import {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loadConfig } from "../../src/config.js";
import { toSafeError } from "../../src/errors.js";
import { Storage } from "../../src/storage.js";
import { ROOT_PREFIX, SECRET_CONTENT } from "../helpers/fixtures.js";
import { connectInMemory, ListObjectsResult, onlyText, parseJson } from "../helpers/mcp.js";
import {
  assertMinioReady,
  createRestrictedUser,
  createSeededBucket,
  destroyBucket,
  MINIO_ENDPOINT,
  MINIO_REGION,
  minioClient,
  type RestrictedUser,
} from "../helpers/minio.js";

/**
 * Layer 2 of PLAN.md section 3: the server's own credentials, used directly (without the
 * path jail), get AccessDenied for everything outside the root prefix.
 */

let admin: S3Client;
let bucket = "";
let bucketCreated = false;
let user: RestrictedUser | undefined;
let restricted: S3Client;

beforeAll(async () => {
  await assertMinioReady();
  admin = minioClient();
  bucket = await createSeededBucket(admin, "mcp-s3-iam");
  bucketCreated = true;
  user = await createRestrictedUser(bucket);
  restricted = minioClient(user.credentials);
});

afterAll(async () => {
  await user?.cleanup();
  if (bucketCreated) await destroyBucket(admin, bucket);
});

async function errorOf(promise: Promise<unknown>): Promise<{ name: string; status: number | undefined; code: string }> {
  try {
    await promise;
  } catch (err) {
    if (!(err instanceof Error)) throw err;
    const status = "$metadata" in err ? (err.$metadata as { httpStatusCode?: number }).httpStatusCode : undefined;
    return { name: err.name, status, code: toSafeError(err).code };
  }
  throw new Error("expected the request to be denied, but it succeeded");
}

describe("least-privilege credentials (IAM layer)", () => {
  it("can read and list under the root", async () => {
    const res = await restricted.send(new GetObjectCommand({ Bucket: bucket, Key: `${ROOT_PREFIX}a.txt` }));
    expect(await res.Body?.transformToString()).toBe("hello from a\n");
    const list = await restricted.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: ROOT_PREFIX }));
    expect((list.Contents ?? []).length).toBe(3);
  });

  it.each(["outside/secret.txt", "claude-workspace-backup/leak.txt"])("GetObject %s is AccessDenied", async (key) => {
    const err = await errorOf(restricted.send(new GetObjectCommand({ Bucket: bucket, Key: key })));
    expect(err).toMatchObject({ name: "AccessDenied", status: 403, code: "AccessDenied" });
  });

  it("HeadObject outside the root is denied (403)", async () => {
    const err = await errorOf(restricted.send(new HeadObjectCommand({ Bucket: bucket, Key: "outside/secret.txt" })));
    expect(err.status).toBe(403);
    expect(err.code).toBe("AccessDenied");
  });

  it.each(["", "outside/", "claude-workspace-backup/", "claude-workspace"])("ListObjectsV2 Prefix=%j is AccessDenied", async (prefix) => {
    const err = await errorOf(restricted.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix })));
    expect(err).toMatchObject({ status: 403, code: "AccessDenied" });
  });

  it("cannot write, even under the root (read-only policy)", async () => {
    const err = await errorOf(
      restricted.send(new PutObjectCommand({ Bucket: bucket, Key: `${ROOT_PREFIX}new.txt`, Body: "x" })),
    );
    expect(err).toMatchObject({ status: 403, code: "AccessDenied" });
  });

  it("the server works with these credentials and never exposes outside content", async () => {
    const config = loadConfig({
      S3_BUCKET: bucket,
      S3_ROOT_PREFIX: ROOT_PREFIX,
      AWS_REGION: MINIO_REGION,
      S3_ENDPOINT_URL: MINIO_ENDPOINT,
      S3_FORCE_PATH_STYLE: "true",
    });
    const h = await connectInMemory(config, new Storage(restricted, bucket));
    try {
      const listing = parseJson(await h.call("list_objects", { recursive: true }), ListObjectsResult);
      expect(listing.files.map((f) => f.path).sort()).toEqual(["a.txt", "img.png", "sub/b.txt"]);
      expect(onlyText(await h.call("read_object", { path: "a.txt" }))).toBe("hello from a\n");
      const denied = await h.call("read_object", { path: "../outside/secret.txt" });
      expect(denied.isError).toBe(true);
      expect(JSON.stringify(denied)).not.toContain(SECRET_CONTENT);
    } finally {
      await h.close();
    }
  });
});
