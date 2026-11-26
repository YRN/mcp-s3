import { Readable } from "node:stream";

import {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  S3Client,
  type GetObjectCommandOutput,
  type S3ClientConfig,
} from "@aws-sdk/client-s3";

import type { Config } from "./config.js";
import { httpStatusOf } from "./errors.js";
import type { ResolvedKey } from "./paths.js";

/**
 * The only module allowed to talk to S3. Every method takes keys produced by
 * resolveKey() (enforced at compile time by the ResolvedKey brand) and returns raw S3 keys;
 * callers convert them with toRelative() before anything reaches the client.
 */

export interface ListedObject {
  key: string;
  size: number;
  lastModified: Date | undefined;
  etag: string | undefined;
}

export interface ListPage {
  objects: ListedObject[];
  /** CommonPrefixes (only when a delimiter is used), as full keys ending with "/". */
  prefixes: string[];
  /** Opaque S3 continuation token, undefined on the last page. */
  nextContinuationToken: string | undefined;
}

export interface ListOptions {
  /** "/" for a single folder level; omit for a recursive listing. */
  delimiter?: "/";
  maxKeys: number;
  continuationToken?: string | undefined;
  signal?: AbortSignal | undefined;
}

export interface ObjectInfo {
  size: number;
  contentType: string | undefined;
  lastModified: Date | undefined;
  etag: string | undefined;
  metadata: Record<string, string>;
}

export interface ByteRange {
  offset: number;
  /** Number of bytes, at least 1. */
  length: number;
}

export interface GetOptions {
  signal?: AbortSignal | undefined;
  /** Only return the object if its ETag still matches (HTTP If-Match); otherwise S3 answers 412. */
  ifMatch?: string | undefined;
}

export interface ObjectData {
  bytes: Uint8Array;
  contentType: string | undefined;
  /** Total object size taken from Content-Range, when the provider sent it. */
  totalSize: number | undefined;
}

/** The provider's response does not match the request (ignored Range, oversized body, ...). */
export class StorageResponseError extends Error {
  override readonly name = "StorageResponseError";
}

/**
 * Why a GetObject response does not answer the requested byte range, or undefined if it does.
 * See Storage.get() for the rules. The messages are fixed strings (no keys, no bucket).
 */
function rangeProblem(
  res: { ContentRange?: string; ContentLength?: number; $metadata: { httpStatusCode?: number } },
  range: ByteRange,
): string | undefined {
  const tooLong = res.ContentLength !== undefined && res.ContentLength > range.length;
  if (res.ContentRange !== undefined) {
    const contentRange = parseContentRange(res.ContentRange);
    if (contentRange === undefined) return "storage sent a Content-Range header that could not be parsed";
    if (contentRange.start !== range.offset) return "storage sent a Content-Range for a different offset than requested";
    if (tooLong) return "storage announced more bytes (Content-Length) than the requested range";
    return undefined;
  }
  if (httpStatusOf(res) === 206) {
    return tooLong ? "storage announced more bytes (Content-Length) than the requested range" : undefined;
  }
  // No Content-Range and no 206: the provider ignored the Range and sent the object from byte 0.
  // That is the right data for offset 0 (read up to range.length), never for a later offset.
  if (range.offset !== 0) return "storage ignored the Range header (no 206, no Content-Range) for a read at a non-zero offset";
  return undefined;
}

/** Give up on establishing a connection after this long. */
export const S3_CONNECTION_TIMEOUT_MS = 5_000;
/** Give up on a request attempt if the response headers have not arrived after this long. */
export const S3_REQUEST_TIMEOUT_MS = 30_000;
/** Give up on a response whose socket has been idle (e.g. a stalled body) for this long. */
export const S3_SOCKET_TIMEOUT_MS = 30_000;

export function createS3Client(config: Pick<Config, "region" | "endpoint" | "forcePathStyle">): S3Client {
  const clientConfig: S3ClientConfig = {
    region: config.region,
    forcePathStyle: config.forcePathStyle,
    requestHandler: {
      connectionTimeout: S3_CONNECTION_TIMEOUT_MS,
      requestTimeout: S3_REQUEST_TIMEOUT_MS,
      throwOnRequestTimeout: true,
      socketTimeout: S3_SOCKET_TIMEOUT_MS,
    },
  };
  if (config.endpoint !== undefined) clientConfig.endpoint = config.endpoint;
  return new S3Client(clientConfig);
}

interface ContentRange {
  start: number;
  end: number;
  total: number | undefined;
}

/** Parse "bytes <start>-<end>/<total|*>"; undefined if absent or malformed. */
export function parseContentRange(value: string | undefined): ContentRange | undefined {
  if (value === undefined) return undefined;
  const match = /^bytes (\d+)-(\d+)\/(\d+|\*)$/.exec(value.trim());
  if (match?.[1] === undefined || match[2] === undefined || match[3] === undefined) return undefined;
  return { start: Number(match[1]), end: Number(match[2]), total: match[3] === "*" ? undefined : Number(match[3]) };
}

function discardBody(body: GetObjectCommandOutput["Body"]): void {
  if (body instanceof Readable && !body.readableEnded) body.destroy();
}

type Body = NonNullable<GetObjectCommandOutput["Body"]>;

function toChunk(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw new StorageResponseError("unexpected response body chunk");
}

/**
 * Read at most `limit` bytes of a response body, then stop and release the stream.
 * Unlike transformToByteArray(), this never buffers more than `limit` bytes.
 */
async function readAtMost(body: Body, limit: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let filled = 0;
  const take = (chunk: Uint8Array): void => {
    const part = chunk.subarray(0, Math.min(chunk.length, limit - filled));
    chunks.push(part);
    filled += part.length;
  };

  if (body instanceof Readable) {
    // Node.js: the SDK body is an http.IncomingMessage.
    try {
      for await (const value of body as AsyncIterable<unknown>) {
        take(toChunk(value));
        if (filled >= limit) break;
      }
    } finally {
      discardBody(body);
    }
  } else {
    // Other runtimes (and SDK stream mixins without a Node stream): read the web stream.
    const reader = body.transformToWebStream().getReader();
    try {
      while (filled < limit) {
        const result = (await reader.read()) as { done: boolean; value: unknown };
        if (result.done) break;
        take(toChunk(result.value));
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }
  }
  return chunks.length === 1 && chunks[0] !== undefined ? chunks[0] : Buffer.concat(chunks, filled);
}

export class Storage {
  private readonly client: S3Client;
  private readonly bucket: string;

  constructor(client: S3Client, bucket: string) {
    this.client = client;
    this.bucket = bucket;
  }

  /** One page of ListObjectsV2 under `prefix`. */
  async list(prefix: ResolvedKey, opts: ListOptions): Promise<ListPage> {
    const res = await this.client.send(
      new ListObjectsV2Command({
        Bucket: this.bucket,
        Prefix: prefix,
        Delimiter: opts.delimiter,
        MaxKeys: opts.maxKeys,
        ContinuationToken: opts.continuationToken,
      }),
      { abortSignal: opts.signal },
    );

    const objects: ListedObject[] = [];
    for (const item of res.Contents ?? []) {
      if (item.Key === undefined) continue;
      objects.push({ key: item.Key, size: item.Size ?? 0, lastModified: item.LastModified, etag: item.ETag });
    }
    const prefixes: string[] = [];
    for (const item of res.CommonPrefixes ?? []) {
      if (item.Prefix !== undefined) prefixes.push(item.Prefix);
    }
    const nextContinuationToken = res.IsTruncated === false ? undefined : res.NextContinuationToken;
    return { objects, prefixes, nextContinuationToken };
  }

  /** HeadObject. */
  async head(key: ResolvedKey, signal?: AbortSignal): Promise<ObjectInfo> {
    const res = await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }), {
      abortSignal: signal,
    });
    return {
      size: res.ContentLength ?? 0,
      contentType: res.ContentType,
      lastModified: res.LastModified,
      etag: res.ETag,
      metadata: res.Metadata ?? {},
    };
  }

  /**
   * GetObject for an inclusive HTTP byte range. The body is always read with a hard cap of
   * `range.length` bytes and the stream is released afterwards. The response is accepted if:
   * - it has a Content-Range that starts at `range.offset` and does not announce more than
   *   `range.length` bytes (Content-Length), or
   * - it has no Content-Range and status 206, and does not announce more than `range.length`
   *   bytes, or
   * - it has no Content-Range, is not a 206 (the provider ignored the Range and sent the whole
   *   object from byte 0), and `range.offset` is 0. The object may be larger than the range;
   *   only the first `range.length` bytes are read.
   * Anything else destroys the body unread and fails with StorageResponseError. Its message
   * says what was wrong, for the server log only; clients get a generic InternalError.
   */
  async get(key: ResolvedKey, range: ByteRange, opts: GetOptions = {}): Promise<ObjectData> {
    if (!Number.isSafeInteger(range.offset) || range.offset < 0 || !Number.isSafeInteger(range.length) || range.length < 1) {
      throw new RangeError("invalid byte range");
    }
    const res = await this.client.send(
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Range: `bytes=${range.offset}-${range.offset + range.length - 1}`,
        ...(opts.ifMatch === undefined ? {} : { IfMatch: opts.ifMatch }),
      }),
      { abortSignal: opts.signal },
    );

    const body = res.Body;
    const problem = rangeProblem(res, range);
    if (problem !== undefined) {
      discardBody(body);
      throw new StorageResponseError(problem);
    }

    const contentRange = parseContentRange(res.ContentRange);
    const bytes = body === undefined ? new Uint8Array(0) : await readAtMost(body, range.length);
    return { bytes, contentType: res.ContentType, totalSize: contentRange?.total };
  }
}
