import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { startAudit, type AuditDetails } from "../audit.js";
import { S3_MAX_LIST_KEYS, type Config } from "../config.js";
import { errorLogFields, errorResult, httpStatusOf, toSafeError, ToolError } from "../errors.js";
import { compileGlob, GlobError, MAX_GLOB_PATTERN_LENGTH, type GlobMatcher } from "../glob.js";
import { log } from "../logger.js";
import { resolveKey, toRelative, type ResolvedKey } from "../paths.js";
import type { Storage } from "../storage.js";
import { MAX_TOKEN_LENGTH, processTokenKey, TokenCodec, type TokenScope } from "../tokens.js";

export interface ToolContext {
  config: Config;
  storage: Storage;
}

/** Subset of the SDK's RequestHandlerExtra that the handlers use. */
export interface HandlerExtra {
  signal?: AbortSignal | undefined;
  /** Set by safeHandler(): details (e.g. bytes read) that go into the audit line. */
  audit?: AuditDetails | undefined;
}

/** Upper bound on keys scanned by one search_objects call. */
export const SEARCH_SCAN_LIMIT = 10_000;

/**
 * Claude's API rejects image blocks whose base64 data is larger than 5 MB (5,242,880 bytes),
 * which corresponds to 3,932,160 raw bytes. Larger images are answered with a notice.
 */
export const MAX_IMAGE_BASE64_BYTES = 5 * 1024 * 1024;
export const MAX_IMAGE_BYTES = Math.floor(MAX_IMAGE_BASE64_BYTES / 4) * 3;

const MAX_PATH_LENGTH = 1024;

// ---------------------------------------------------------------------------
// Input schemas
// ---------------------------------------------------------------------------

function filePath() {
  return z
    .string()
    .min(1)
    .max(MAX_PATH_LENGTH)
    .describe('File path relative to the workspace root, e.g. "reports/q1.csv". A leading "/" is ignored.');
}

function folderPath() {
  return z
    .string()
    .max(MAX_PATH_LENGTH)
    .default("")
    .describe('Folder path relative to the workspace root, e.g. "reports/" or "reports". Empty string means the root.');
}

export function listObjectsShape(config: Config) {
  return {
    path: folderPath(),
    recursive: z
      .boolean()
      .default(false)
      .describe("If true, list every file under the folder including subfolders. If false, list only direct children and return subfolders in `folders`."),
    max_keys: z
      .number()
      .int()
      .min(1)
      .max(S3_MAX_LIST_KEYS)
      .optional()
      .describe(`Maximum number of entries (folders + files) in this page. Defaults to and is capped at ${config.maxListKeys}.`),
    continuation_token: z
      .string()
      .min(1)
      .max(MAX_TOKEN_LENGTH)
      .optional()
      .describe("Opaque `next_token` from a previous list_objects response, to fetch the next page. Use the same `path` and `recursive` values."),
  };
}

export function getObjectInfoShape() {
  return { path: filePath() };
}

export function readObjectShape(config: Config) {
  return {
    path: filePath(),
    offset: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe("Byte offset to start reading from. To continue a truncated read, pass the offset given in the previous response."),
    length: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(`Maximum number of bytes to read. Defaults to and is capped at ${config.maxReadBytes}.`),
  };
}

export function searchObjectsShape(config: Config) {
  return {
    path: folderPath(),
    pattern: z
      .string()
      .min(1)
      .max(MAX_GLOB_PATTERN_LENGTH)
      .describe(
        'Glob pattern, e.g. "*.csv", "2024/**/*.json", or "*.{csv,tsv}". Supports * (within one folder level), ' +
          "? (one character), ** (any number of folder levels), [abc] / [a-z] / [!abc] (character sets), " +
          "{a,b} (alternatives), and \\ to escape. A pattern without \"/\" matches file names in any subfolder; " +
          'a pattern with "/" matches the path relative to `path`. Matching is case-sensitive. Extglobs like *(...) ' +
          'and a leading "!" are not supported.',
      ),
    max_results: z
      .number()
      .int()
      .min(1)
      .max(S3_MAX_LIST_KEYS)
      .optional()
      .describe(`Maximum number of matching paths to return. Defaults to and is capped at ${config.maxListKeys}.`),
  };
}

type ShapeArgs<Shape extends z.ZodRawShape> = z.infer<z.ZodObject<Shape>>;
export type ListObjectsArgs = ShapeArgs<ReturnType<typeof listObjectsShape>>;
export type GetObjectInfoArgs = ShapeArgs<ReturnType<typeof getObjectInfoShape>>;
export type ReadObjectArgs = ShapeArgs<ReturnType<typeof readObjectShape>>;
export type SearchObjectsArgs = ShapeArgs<ReturnType<typeof searchObjectsShape>>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResult(value: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function textResult(...texts: string[]): CallToolResult {
  return { content: texts.map((text) => ({ type: "text" as const, text })) };
}

/** Relative form of a key that resolveKey() produced; such keys are always under the root. */
function relativeOf(root: string, key: ResolvedKey): string {
  const rel = toRelative(root, key);
  if (rel === null) throw new ToolError("InternalError", "path resolution failed");
  return rel;
}

function requireFileKey(root: string, path: string): ResolvedKey {
  const key = resolveKey(root, path);
  if (key === root) throw new ToolError("InvalidRequest", "path must point to a file, not the workspace root");
  return key;
}

// --- read_object content detection -----------------------------------------

const IMAGE_MIME_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);
const GENERIC_CONTENT_TYPES = new Set(["", "application/octet-stream", "binary/octet-stream"]);
const IMAGE_EXTENSIONS: Readonly<Record<string, string>> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
};

function startsWithBytes(bytes: Uint8Array, signature: readonly number[], at = 0): boolean {
  if (bytes.length < at + signature.length) return false;
  return signature.every((value, i) => bytes[at + i] === value);
}

/** Detect png/jpeg/gif/webp from magic bytes at the start of the file. */
export function sniffImageMime(bytes: Uint8Array): string | undefined {
  if (startsWithBytes(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (startsWithBytes(bytes, [0xff, 0xd8, 0xff])) return "image/jpeg";
  if (startsWithBytes(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) || startsWithBytes(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])) {
    return "image/gif";
  }
  if (startsWithBytes(bytes, [0x52, 0x49, 0x46, 0x46]) && startsWithBytes(bytes, [0x57, 0x45, 0x42, 0x50], 8)) return "image/webp";
  return undefined;
}

/** Image MIME type from the stored Content-Type, or from the file extension if that is generic. */
export function declaredImageMime(contentType: string | undefined, key: string): string | undefined {
  let type = (contentType ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  if (type === "image/jpg") type = "image/jpeg";
  if (IMAGE_MIME_TYPES.has(type)) return type;
  if (!GENERIC_CONTENT_TYPES.has(type)) return undefined;
  const dot = key.lastIndexOf(".");
  if (dot < 0 || dot < key.lastIndexOf("/")) return undefined;
  return IMAGE_EXTENSIONS[key.slice(dot + 1).toLowerCase()];
}

function isContinuationByte(value: number | undefined): boolean {
  return value !== undefined && (value & 0xc0) === 0x80;
}

/**
 * Byte window of `bytes` that contains only whole UTF-8 sequences, for ranged reads that may
 * start or end inside a multi-byte character.
 */
export function utf8Window(bytes: Uint8Array, trimStart: boolean, trimEnd: boolean): { start: number; end: number } {
  let start = 0;
  if (trimStart) {
    while (start < 3 && isContinuationByte(bytes[start])) start++;
  }
  let end = bytes.length;
  if (trimEnd) {
    for (let i = bytes.length - 1; i >= Math.max(start, bytes.length - 4); i--) {
      const value = bytes[i];
      if (value === undefined || isContinuationByte(value)) continue;
      const need = value < 0x80 ? 1 : (value & 0xe0) === 0xc0 ? 2 : (value & 0xf0) === 0xe0 ? 3 : (value & 0xf8) === 0xf0 ? 4 : 1;
      if (i + need > bytes.length) end = i;
      break;
    }
  }
  return { start, end };
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export function createReadHandlers(ctx: ToolContext) {
  const { config, storage } = ctx;
  const root = config.rootPrefix;
  // Stateless encrypted continuation tokens; see tokens.ts.
  const tokens = new TokenCodec(config.tokenKey ?? processTokenKey(), undefined, config.bucket);

  async function listObjects(args: ListObjectsArgs, extra: HandlerExtra = {}): Promise<CallToolResult> {
    const prefix = resolveKey(root, args.path, { dir: true });
    const maxKeys = Math.min(args.max_keys ?? config.maxListKeys, config.maxListKeys);
    const scope: TokenScope = { prefix, recursive: args.recursive };

    let s3Token: string | undefined;
    if (args.continuation_token !== undefined) {
      // Never forward the client's value to S3: only a token we sealed ourselves is used.
      s3Token = tokens.open(args.continuation_token, scope);
      if (s3Token === undefined) {
        throw new ToolError(
          "InvalidRequest",
          "continuation_token is invalid or expired, or was issued for a different path/recursive value; list again without it",
        );
      }
    }

    const page = await storage.list(prefix, {
      ...(args.recursive ? {} : { delimiter: "/" as const }),
      maxKeys,
      continuationToken: s3Token,
      signal: extra.signal,
    });

    const folders = new Set<string>();
    for (const p of page.prefixes) {
      const rel = toRelative(root, p);
      if (rel !== null && p.startsWith(prefix) && p !== prefix) folders.add(rel);
    }

    const files: { path: string; size: number; last_modified: string | null }[] = [];
    for (const obj of page.objects) {
      const rel = toRelative(root, obj.key);
      if (rel === null || !obj.key.startsWith(prefix) || obj.key === prefix) continue;
      if (obj.key.endsWith("/")) {
        // Folder placeholder object (e.g. created by create_folder).
        folders.add(rel);
        continue;
      }
      files.push({ path: rel, size: obj.size, last_modified: obj.lastModified?.toISOString() ?? null });
    }

    let nextToken: string | null = null;
    if (page.nextContinuationToken !== undefined) {
      nextToken = tokens.seal(page.nextContinuationToken, scope);
      if (nextToken.length > MAX_TOKEN_LENGTH) {
        throw new ToolError("InternalError", "listing cannot be paginated (continuation token too large); list a narrower path");
      }
    }
    return jsonResult({ path: relativeOf(root, prefix), folders: [...folders], files, next_token: nextToken });
  }

  async function getObjectInfo(args: GetObjectInfoArgs, extra: HandlerExtra = {}): Promise<CallToolResult> {
    const key = requireFileKey(root, args.path);
    const info = await storage.head(key, extra.signal);
    return jsonResult({
      path: relativeOf(root, key),
      size: info.size,
      content_type: info.contentType ?? null,
      last_modified: info.lastModified?.toISOString() ?? null,
      etag: info.etag ?? null,
      metadata: info.metadata,
    });
  }

  async function readObject(args: ReadObjectArgs, extra: HandlerExtra = {}): Promise<CallToolResult> {
    const key = requireFileKey(root, args.path);
    const rel = relativeOf(root, key);
    const limit = config.maxReadBytes;

    const info = await storage.head(key, extra.signal);
    const size = info.size;
    if (size === 0) return textResult("[empty file: 0 bytes]");
    if (args.offset >= size) {
      throw new ToolError("InvalidRange", `offset ${args.offset} is at or beyond the end of the file (${size} bytes)`);
    }

    const length = Math.min(args.length ?? limit, limit, size - args.offset);
    let data;
    try {
      // If-Match pins the read to the version seen by HEAD, so size and content agree.
      data = await storage.get(key, { offset: args.offset, length }, { signal: extra.signal, ifMatch: info.etag });
    } catch (err) {
      if (err instanceof Error && (err.name === "PreconditionFailed" || httpStatusOf(err) === 412)) {
        throw new ToolError("Conflict", "object changed during read, retry");
      }
      throw err;
    }
    const bytes = data.bytes;
    if (extra.audit !== undefined) extra.audit.bytes = bytes.length;
    const total = data.totalSize ?? size;
    const contentType = data.contentType ?? info.contentType;
    const isWhole = args.offset === 0 && bytes.length >= total;

    // Image content is only returned for bytes that really start with a PNG/JPEG/GIF/WebP
    // signature, with the MIME type taken from the signature (never from Content-Type or
    // the extension): an invalid image block would make the client's API reject the turn.
    const sniffed = args.offset === 0 ? sniffImageMime(bytes) : undefined;
    if (sniffed !== undefined) {
      if (isWhole && bytes.length <= MAX_IMAGE_BYTES) {
        return { content: [{ type: "image", data: Buffer.from(bytes).toString("base64"), mimeType: sniffed }] };
      }
      let reason: string;
      if (total > MAX_IMAGE_BYTES) reason = `images larger than ${MAX_IMAGE_BYTES} bytes (5 MB as base64) cannot be returned`;
      else if (total > limit) reason = `it exceeds the read limit of ${limit} bytes`;
      else reason = "images can only be returned whole; call read_object without offset or length";
      return textResult(`[image ${rel} (${sniffed}, ${total} bytes) cannot be displayed: ${reason}]`);
    }

    const declared = declaredImageMime(contentType, key);
    if (declared !== undefined) {
      if (args.offset > 0) {
        return textResult(
          `[image ${rel} (${declared}, ${total} bytes) cannot be displayed: images can only be returned whole; ` +
            "call read_object without offset or length]",
        );
      }
      return textResult(
        `[binary or corrupt image ${rel} (stored as ${declared}, ${total} bytes): ` +
          "the content is not a valid PNG, JPEG, GIF, or WebP image]",
      );
    }

    const readEnd = args.offset + bytes.length;
    const window = utf8Window(bytes, args.offset > 0, readEnd < total);
    if (window.end <= window.start) {
      throw new ToolError("InvalidRequest", "requested range does not contain a complete UTF-8 character; increase length");
    }

    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(window.start, window.end));
    } catch {
      return textResult(
        `[binary file ${rel} (${contentType ?? "unknown content type"}, ${total} bytes): content cannot be shown as text]`,
      );
    }

    const first = args.offset + window.start;
    const next = args.offset + window.end;
    if (first === 0 && next >= total) return textResult(text);

    let note = `[showing bytes ${first}-${next - 1} of ${total}`;
    note += next < total ? `; to read more, call read_object with offset=${next}]` : "; end of file]";
    return textResult(text, note);
  }

  async function searchObjects(args: SearchObjectsArgs, extra: HandlerExtra = {}): Promise<CallToolResult> {
    const prefix = resolveKey(root, args.path, { dir: true });
    const maxResults = Math.min(args.max_results ?? config.maxListKeys, config.maxListKeys);

    // Compiled before any S3 call, so invalid patterns never reach storage. The matcher has
    // a bounded worst case (see glob.ts); there is no regex backtracking.
    let matcher: GlobMatcher;
    try {
      matcher = compileGlob(args.pattern);
    } catch (err) {
      if (err instanceof GlobError) throw new ToolError("InvalidRequest", `invalid glob pattern: ${err.message}`);
      throw err;
    }

    const matches: string[] = [];
    let scanned = 0;
    let truncated = false;
    let note: string | undefined;
    let token: string | undefined;

    do {
      const page = await storage.list(prefix, { maxKeys: S3_MAX_LIST_KEYS, continuationToken: token, signal: extra.signal });
      for (const obj of page.objects) {
        scanned++;
        const rel = toRelative(root, obj.key);
        if (rel === null || !obj.key.startsWith(prefix) || obj.key.endsWith("/")) continue;
        if (!matcher.matches(obj.key.slice(prefix.length))) continue;
        if (matches.length >= maxResults) {
          truncated = true;
          note = `more than ${maxResults} matches; narrow the pattern or path`;
          break;
        }
        matches.push(rel);
      }
      token = page.nextContinuationToken;
      if (!truncated && token !== undefined && scanned >= SEARCH_SCAN_LIMIT) {
        truncated = true;
        note = `stopped after scanning ${scanned} objects; narrow the path to search further`;
      }
    } while (!truncated && token !== undefined);

    return jsonResult({
      path: relativeOf(root, prefix),
      pattern: args.pattern,
      matches,
      truncated,
      ...(note === undefined ? {} : { note }),
    });
  }

  return { listObjects, getObjectInfo, readObject, searchObjects };
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * The single wrapper every tool handler is registered through. It
 * - turns every failure into an `isError` result with a generic message from errors.ts
 *   (without this, the SDK would copy the raw exception message, which can contain bucket
 *   names or keys, into the response), and
 * - writes exactly one audit line per call (audit.ts).
 */
export function safeHandler<A>(
  tool: string,
  handler: (args: A, extra: HandlerExtra) => Promise<CallToolResult>,
): (args: A, extra: HandlerExtra) => Promise<CallToolResult> {
  return async (args, extra) => {
    const audit = startAudit(tool, args);
    try {
      const result = await handler(args, { signal: extra.signal, audit: audit.details });
      if (result.isError === true) audit.error();
      else audit.ok();
      return result;
    } catch (err) {
      const safe = toSafeError(err);
      if (safe.expected) log.debug(`${tool} rejected`, { code: safe.code });
      else log.warn(`${tool} failed`, { code: safe.code, ...errorLogFields(err) });
      audit.error(safe.code);
      return errorResult(err);
    }
  };
}

/**
 * PLAN.md section 5: read tools never modify anything (readOnlyHint), so they are not
 * destructive and repeating a call has no additional effect (idempotentHint). They only
 * touch the configured bucket and root prefix, not an open world of external entities.
 */
const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

/** Register the read tools and return their names. */
export function registerReadTools(server: McpServer, ctx: ToolContext): string[] {
  const handlers = createReadHandlers(ctx);
  const { config } = ctx;

  server.registerTool(
    "list_objects",
    {
      title: "List objects",
      description:
        "List folders and files under a folder of the workspace. Paths are relative to the workspace root; " +
        "the root itself is the empty string. Results are paginated: pass `next_token` back as `continuation_token`.",
      inputSchema: listObjectsShape(config),
      annotations: READ_ANNOTATIONS,
    },
    safeHandler("list_objects", handlers.listObjects),
  );

  server.registerTool(
    "get_object_info",
    {
      title: "Get object info",
      description: "Get size, content type, last modified time, ETag, and user metadata of a file in the workspace.",
      inputSchema: getObjectInfoShape(),
      annotations: READ_ANNOTATIONS,
    },
    safeHandler("get_object_info", handlers.getObjectInfo),
  );

  server.registerTool(
    "read_object",
    {
      title: "Read object",
      description:
        `Read a file in the workspace. UTF-8 text is returned as text; files whose bytes are a PNG, JPEG, GIF, or ` +
        `WebP image of at most ${MAX_IMAGE_BYTES} bytes are returned whole as image content; ` +
        `other files only as a short "binary" notice. At most ${config.maxReadBytes} bytes are returned per call; ` +
        "for larger files use `offset` (and optionally `length`) to read further parts.",
      inputSchema: readObjectShape(config),
      annotations: READ_ANNOTATIONS,
    },
    safeHandler("read_object", handlers.readObject),
  );

  server.registerTool(
    "search_objects",
    {
      title: "Search objects",
      description:
        "Find files under a folder of the workspace whose path matches a glob pattern (e.g. \"*.csv\"). " +
        "Returns matching paths relative to the workspace root.",
      inputSchema: searchObjectsShape(config),
      annotations: READ_ANNOTATIONS,
    },
    safeHandler("search_objects", handlers.searchObjects),
  );

  return ["list_objects", "get_object_info", "read_object", "search_objects"];
}
