import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteObjectsCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";

import { LEAK_CONTENT, PNG_1X1, ROOT_PREFIX, SECRET_CONTENT } from "./fixtures.js";

/**
 * MinIO helpers for integration and e2e tests. MinIO is started by docker-compose.yml
 * (`docker compose up -d --wait` waits for its healthcheck). Every test file creates its own
 * uniquely named bucket and removes it in afterAll.
 */

export const MINIO_ENDPOINT = process.env.MINIO_ENDPOINT ?? `http://127.0.0.1:${process.env.MINIO_PORT ?? "19000"}`;
export const MINIO_ROOT_USER = process.env.MINIO_ROOT_USER ?? "mcp-s3-admin";
export const MINIO_ROOT_PASSWORD = process.env.MINIO_ROOT_PASSWORD ?? "mcp-s3-admin-secret";
export const MINIO_REGION = "us-east-1";

export const PROJECT_DIR = fileURLToPath(new URL("../..", import.meta.url));

export interface Credentials {
  accessKeyId: string;
  secretAccessKey: string;
}

export const ADMIN_CREDENTIALS: Credentials = { accessKeyId: MINIO_ROOT_USER, secretAccessKey: MINIO_ROOT_PASSWORD };

export function minioClient(credentials: Credentials = ADMIN_CREDENTIALS): S3Client {
  return new S3Client({
    region: MINIO_REGION,
    endpoint: MINIO_ENDPOINT,
    forcePathStyle: true,
    credentials,
    maxAttempts: 1,
  });
}

/**
 * Fail fast, with instructions, when MinIO is not running. This is a single readiness probe:
 * waiting for startup is done by `docker compose up --wait` against the container healthcheck.
 */
export async function assertMinioReady(): Promise<void> {
  let status: number | string;
  try {
    const res = await fetch(`${MINIO_ENDPOINT}/minio/health/ready`, { signal: AbortSignal.timeout(5000) });
    status = res.status;
  } catch (err) {
    status = err instanceof Error ? err.message : String(err);
  }
  if (status !== 200) {
    throw new Error(
      `MinIO is not ready at ${MINIO_ENDPOINT} (${String(status)}). ` +
        'Start it with "docker compose up -d --wait" (npm run test:int / test:e2e do this).',
    );
  }
}

/** Lower-case, S3-valid, unique per call. */
export function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
}

export interface SeedObject {
  body: string | Uint8Array;
  contentType: string;
  metadata?: Record<string, string>;
}

/** Standard seed: three objects under the root, two outside it (one is a prefix collision). */
export const STANDARD_SEED: Readonly<Record<string, SeedObject>> = {
  [`${ROOT_PREFIX}a.txt`]: { body: "hello from a\n", contentType: "text/plain", metadata: { owner: "team-a" } },
  [`${ROOT_PREFIX}sub/b.txt`]: { body: "bee\n", contentType: "text/plain" },
  // Stored as octet-stream on purpose: the server must detect PNG from its magic bytes.
  [`${ROOT_PREFIX}img.png`]: { body: PNG_1X1, contentType: "application/octet-stream" },
  "claude-workspace-backup/leak.txt": { body: LEAK_CONTENT, contentType: "text/plain" },
  "outside/secret.txt": { body: SECRET_CONTENT, contentType: "text/plain" },
};

export async function putObject(client: S3Client, bucket: string, key: string, object: SeedObject): Promise<void> {
  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: typeof object.body === "string" ? Buffer.from(object.body, "utf8") : object.body,
      ContentType: object.contentType,
      Metadata: object.metadata,
    }),
  );
}

export async function seedBucket(
  client: S3Client,
  bucket: string,
  objects: Readonly<Record<string, SeedObject>> = STANDARD_SEED,
): Promise<void> {
  await Promise.all(Object.entries(objects).map(([key, object]) => putObject(client, bucket, key, object)));
}

/** Create a unique bucket with the standard seed. */
export async function createSeededBucket(client: S3Client, prefix = "mcp-s3-test"): Promise<string> {
  const bucket = uniqueName(prefix);
  await client.send(new CreateBucketCommand({ Bucket: bucket }));
  await seedBucket(client, bucket);
  return bucket;
}

/** Delete every object in the bucket, then the bucket. */
export async function destroyBucket(client: S3Client, bucket: string): Promise<void> {
  let token: string | undefined;
  do {
    const page = await client.send(new ListObjectsV2Command({ Bucket: bucket, ContinuationToken: token }));
    const keys = (page.Contents ?? []).flatMap((o) => (o.Key === undefined ? [] : [{ Key: o.Key }]));
    if (keys.length > 0) await client.send(new DeleteObjectsCommand({ Bucket: bucket, Delete: { Objects: keys } }));
    token = page.IsTruncated === true ? page.NextContinuationToken : undefined;
  } while (token !== undefined);
  await client.send(new DeleteBucketCommand({ Bucket: bucket }));
}

// --- process helpers ----------------------------------------------------------

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export function run(command: string, args: string[], opts: { input?: string; cwd?: string } = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: opts.cwd ?? PROJECT_DIR, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(opts.input ?? "");
  });
}

/** Run `mc` inside the MinIO container with an alias "local" pointing at the root user. */
async function mc(script: string, input?: string): Promise<string> {
  const full =
    'mc alias set local http://127.0.0.1:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null && ' + script;
  const res = await run("docker", ["compose", "exec", "-T", "minio", "sh", "-c", full], { input });
  if (res.code !== 0) throw new Error(`mc failed (${String(res.code)}): ${res.stderr || res.stdout}`);
  return res.stdout;
}

/**
 * The least-privilege policy from PLAN.md section 3 (read-only variant): ListBucket only for
 * the root prefix, GetObject only under it.
 */
export function rootOnlyPolicy(bucket: string): string {
  return JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ListOnlyUnderRoot",
        Effect: "Allow",
        Action: ["s3:ListBucket"],
        Resource: [`arn:aws:s3:::${bucket}`],
        Condition: { StringLike: { "s3:prefix": [ROOT_PREFIX, `${ROOT_PREFIX}*`] } },
      },
      {
        Sid: "ReadUnderRoot",
        Effect: "Allow",
        Action: ["s3:GetObject"],
        Resource: [`arn:aws:s3:::${bucket}/${ROOT_PREFIX}*`],
      },
    ],
  });
}

export interface RestrictedUser {
  credentials: Credentials;
  cleanup(): Promise<void>;
}

/** Create a MinIO user whose only permissions are rootOnlyPolicy(bucket). */
export async function createRestrictedUser(bucket: string): Promise<RestrictedUser> {
  const name = uniqueName("mcp-s3-user");
  const policy = uniqueName("mcp-s3-policy");
  const secret = randomBytes(18).toString("hex");
  const file = `/tmp/${policy}.json`;
  await mc(
    `cat > ${file} && mc admin user add local ${name} ${secret} >/dev/null && ` +
      `mc admin policy create local ${policy} ${file} >/dev/null && ` +
      `mc admin policy attach local ${policy} --user ${name} >/dev/null && rm -f ${file}`,
    rootOnlyPolicy(bucket),
  );
  return {
    credentials: { accessKeyId: name, secretAccessKey: secret },
    async cleanup() {
      await mc(
        `mc admin policy detach local ${policy} --user ${name} >/dev/null; ` +
          `mc admin user remove local ${name} >/dev/null; mc admin policy remove local ${policy} >/dev/null`,
      );
    },
  };
}
