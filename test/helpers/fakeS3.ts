import {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  NoSuchBucket,
  NoSuchKey,
  NotFound,
  S3Client,
  S3ServiceException,
  type GetObjectCommandInput,
  type GetObjectCommandOutput,
  type HeadObjectCommandInput,
  type HeadObjectCommandOutput,
  type ListObjectsV2CommandInput,
  type ListObjectsV2CommandOutput,
} from "@aws-sdk/client-s3";
import { mockClient, type AwsClientStub } from "aws-sdk-client-mock";

/**
 * A small in-memory S3 behind aws-sdk-client-mock. It implements the parts of
 * ListObjectsV2 / HeadObject / GetObject semantics the read tools rely on (prefix,
 * delimiter, MaxKeys, continuation, Range), so tests can assert behaviour instead of
 * hand-wiring every response. All sent commands stay inspectable through `mock`.
 */

export interface FakeObject {
  body: Uint8Array;
  contentType: string | undefined;
  metadata: Record<string, string>;
  lastModified: Date;
  etag: string;
}

export interface PutOptions {
  contentType?: string;
  metadata?: Record<string, string>;
}

const META = { httpStatusCode: 200, requestId: "REQ-FAKE-0001" };

export function accessDenied(bucket: string, key: string): S3ServiceException {
  return new S3ServiceException({
    name: "AccessDenied",
    $fault: "client",
    $metadata: { httpStatusCode: 403, requestId: "REQ-DENIED-0001" },
    message: `User: arn:aws:iam::123456789012:user/mcp-s3 is not authorized to perform: s3:GetObject on resource: "arn:aws:s3:::${bucket}/${key}"`,
  });
}

export function noSuchKey(bucket: string, key: string): NoSuchKey {
  return new NoSuchKey({
    message: `The specified key does not exist: arn:aws:s3:::${bucket}/${key}`,
    $metadata: { httpStatusCode: 404, requestId: "REQ-NOKEY-0001" },
  });
}

export function notFound(): NotFound {
  return new NotFound({ message: "UnknownError", $metadata: { httpStatusCode: 404, requestId: "REQ-404-0001" } });
}

export function noSuchBucket(bucket: string): NoSuchBucket {
  const err = new NoSuchBucket({
    message: `The specified bucket does not exist: ${bucket}`,
    $metadata: { httpStatusCode: 404, requestId: "REQ-NOBUCKET-0001" },
  });
  return Object.assign(err, { BucketName: bucket });
}

export function preconditionFailed(): S3ServiceException {
  return new S3ServiceException({
    name: "PreconditionFailed",
    $fault: "client",
    $metadata: { httpStatusCode: 412 },
    message: "At least one of the pre-conditions you specified did not hold",
  });
}

export function invalidRange(): S3ServiceException {
  return new S3ServiceException({
    name: "InvalidRange",
    $fault: "client",
    $metadata: { httpStatusCode: 416 },
    message: "The requested range is not satisfiable",
  });
}

function parseRange(range: string | undefined, size: number): { start: number; end: number } | undefined {
  if (range === undefined) return undefined;
  const match = /^bytes=(\d+)-(\d*)$/.exec(range);
  if (match?.[1] === undefined) throw new Error(`fake S3: unsupported Range header ${range}`);
  const start = Number(match[1]);
  const end = match[2] === undefined || match[2] === "" ? size - 1 : Math.min(Number(match[2]), size - 1);
  return { start, end };
}

export class FakeS3 {
  readonly bucket: string;
  readonly client: S3Client;
  readonly mock: AwsClientStub<S3Client>;
  readonly objects = new Map<string, FakeObject>();
  /** Keys whose GetObject body was actually read (any transform* method called). */
  readonly bodyReads: string[] = [];
  /** Raw S3 continuation tokens handed out by ListObjectsV2. */
  readonly issuedTokens: string[] = [];

  /** Simulate a misbehaving provider that ignores the Prefix parameter. */
  ignorePrefix = false;
  /** Simulate a provider that ignores the Range header and returns the whole object. */
  ignoreRange = false;
  /** Runs after HeadObject and before GetObject is answered (e.g. to simulate a concurrent write). */
  beforeGet: ((input: GetObjectCommandInput) => void) | undefined;

  private clock = Date.UTC(2026, 0, 2, 3, 4, 5);
  private version = 0;

  constructor(bucket: string) {
    this.bucket = bucket;
    this.client = new S3Client({
      region: "us-east-1",
      credentials: { accessKeyId: "AKIAFAKETEST", secretAccessKey: "fake-secret" },
    });
    this.mock = mockClient(this.client);
    this.mock.on(ListObjectsV2Command).callsFake((input: ListObjectsV2CommandInput) => this.list(input));
    this.mock.on(HeadObjectCommand).callsFake((input: HeadObjectCommandInput) => this.head(input));
    this.mock.on(GetObjectCommand).callsFake((input: GetObjectCommandInput) => this.get(input));
  }

  put(key: string, body: string | Uint8Array, opts: PutOptions = {}): void {
    const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
    this.clock += 1000;
    this.objects.set(key, {
      body: bytes,
      contentType: opts.contentType,
      metadata: opts.metadata ?? {},
      lastModified: new Date(this.clock),
      etag: `"etag-${String(++this.version)}"`,
    });
  }

  /** Inputs of every command sent, in order. */
  sentInputs(): Record<string, unknown>[] {
    return this.mock.calls().map((call) => {
      const command = call.args[0];
      return command.input as Record<string, unknown>;
    });
  }

  restore(): void {
    this.mock.restore();
  }

  private checkBucket(bucket: string | undefined): void {
    if (bucket !== this.bucket) throw noSuchBucket(bucket ?? "");
  }

  private list(input: ListObjectsV2CommandInput): ListObjectsV2CommandOutput {
    this.checkBucket(input.Bucket);
    const prefix = input.Prefix ?? "";
    const maxKeys = input.MaxKeys ?? 1000;
    const startAfter = input.ContinuationToken === undefined ? undefined : this.decodeToken(input.ContinuationToken);

    const keys = [...this.objects.keys()]
      .filter((key) => this.ignorePrefix || key.startsWith(prefix))
      .sort();

    const entries: ({ kind: "object"; key: string } | { kind: "prefix"; prefix: string })[] = [];
    const seenPrefixes = new Set<string>();
    for (const key of keys) {
      if (input.Delimiter !== undefined && key.startsWith(prefix)) {
        const rest = key.slice(prefix.length);
        const idx = rest.indexOf(input.Delimiter);
        if (idx >= 0) {
          const common = prefix + rest.slice(0, idx + input.Delimiter.length);
          if (!seenPrefixes.has(common)) {
            seenPrefixes.add(common);
            entries.push({ kind: "prefix", prefix: common });
          }
          continue;
        }
      }
      entries.push({ kind: "object", key });
    }

    const sortKey = (e: (typeof entries)[number]) => (e.kind === "object" ? e.key : e.prefix);
    const remaining = startAfter === undefined ? entries : entries.filter((e) => sortKey(e) > startAfter);
    const page = remaining.slice(0, maxKeys);
    const truncated = remaining.length > page.length;
    const last = page.at(-1);

    const output: ListObjectsV2CommandOutput = {
      $metadata: META,
      Name: this.bucket,
      Prefix: prefix,
      KeyCount: page.length,
      MaxKeys: maxKeys,
      IsTruncated: truncated,
      Contents: page.flatMap((e) => {
        if (e.kind !== "object") return [];
        const obj = this.objects.get(e.key);
        if (obj === undefined) return [];
        return [{ Key: e.key, Size: obj.body.length, LastModified: obj.lastModified, ETag: obj.etag }];
      }),
      CommonPrefixes: page.flatMap((e) => (e.kind === "prefix" ? [{ Prefix: e.prefix }] : [])),
    };
    if (input.Delimiter !== undefined) output.Delimiter = input.Delimiter;
    if (truncated && last !== undefined) {
      // Like some S3-compatible providers, the raw token embeds the last full key (bucket + root).
      const token = Buffer.from(`${this.bucket}/${sortKey(last)}`, "utf8").toString("base64");
      this.issuedTokens.push(token);
      output.NextContinuationToken = token;
    }
    return output;
  }

  private decodeToken(token: string): string {
    if (!this.issuedTokens.includes(token)) {
      throw new S3ServiceException({
        name: "InvalidArgument",
        $fault: "client",
        $metadata: { httpStatusCode: 400 },
        message: "The continuation token provided is incorrect",
      });
    }
    const decoded = Buffer.from(token, "base64").toString("utf8");
    return decoded.slice(this.bucket.length + 1);
  }

  private head(input: HeadObjectCommandInput): HeadObjectCommandOutput {
    this.checkBucket(input.Bucket);
    const obj = input.Key === undefined ? undefined : this.objects.get(input.Key);
    if (obj === undefined) throw notFound();
    return {
      $metadata: META,
      ContentLength: obj.body.length,
      ContentType: obj.contentType,
      LastModified: obj.lastModified,
      ETag: obj.etag,
      Metadata: obj.metadata,
    };
  }

  private get(input: GetObjectCommandInput): GetObjectCommandOutput {
    this.checkBucket(input.Bucket);
    this.beforeGet?.(input);
    const key = input.Key ?? "";
    const obj = this.objects.get(key);
    if (obj === undefined) throw noSuchKey(this.bucket, key);
    if (input.IfMatch !== undefined && input.IfMatch !== obj.etag) throw preconditionFailed();

    const size = obj.body.length;
    const range = this.ignoreRange ? undefined : parseRange(input.Range, size);
    if (range !== undefined && range.start >= size) throw invalidRange();

    const bytes = range === undefined ? obj.body : obj.body.slice(range.start, range.end + 1);
    const output: GetObjectCommandOutput = {
      $metadata: { ...META, httpStatusCode: range === undefined ? 200 : 206 },
      Body: this.body(key, bytes),
      ContentLength: bytes.length,
      ContentType: obj.contentType,
      ETag: obj.etag,
      LastModified: obj.lastModified,
      Metadata: obj.metadata,
    };
    if (range !== undefined) output.ContentRange = `bytes ${range.start}-${range.end}/${size}`;
    return output;
  }

  private body(key: string, bytes: Uint8Array): GetObjectCommandOutput["Body"] {
    const reads = this.bodyReads;
    const body = {
      transformToByteArray: () => {
        reads.push(key);
        return Promise.resolve(bytes);
      },
      transformToString: (encoding?: string) => {
        reads.push(key);
        return Promise.resolve(Buffer.from(bytes).toString(encoding === "base64" ? "base64" : "utf8"));
      },
      transformToWebStream: () => {
        reads.push(key);
        return new Blob([bytes]).stream();
      },
    };
    return body as unknown as GetObjectCommandOutput["Body"];
  }
}
