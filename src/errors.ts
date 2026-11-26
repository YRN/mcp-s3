import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { PathOutsideRootError } from "./paths.js";

/** Generic error categories exposed to the client. */
export type ErrorCode =
  | "PathOutsideRoot"
  | "InvalidRequest"
  | "NotFound"
  | "AccessDenied"
  | "InvalidRange"
  | "Conflict"
  | "Throttled"
  | "StorageUnavailable"
  | "Cancelled"
  | "InternalError";

/**
 * Error raised by tool code with a message that is already safe to show to the client.
 * Never put bucket names, the root prefix, or full keys into the message.
 */
export class ToolError extends Error {
  override readonly name = "ToolError";
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface SafeError {
  code: ErrorCode;
  message: string;
  /** True when the error was expected (bad input, missing object, ...) rather than a fault. */
  expected: boolean;
}

/**
 * Known S3 error names (SDK v3 sets `error.name` to the S3 error code). Matching is done by
 * name rather than `instanceof` so that errors from S3-compatible providers and from
 * aws-sdk-client-mock (plain Error with a name) are mapped the same way.
 */
const S3_ERROR_NAMES: ReadonlyMap<string, SafeError> = new Map(Object.entries({
  NoSuchKey: { code: "NotFound", message: "object not found", expected: true },
  NotFound: { code: "NotFound", message: "object not found", expected: true },
  NoSuchVersion: { code: "NotFound", message: "object not found", expected: true },
  AccessDenied: { code: "AccessDenied", message: "access denied", expected: true },
  Forbidden: { code: "AccessDenied", message: "access denied", expected: true },
  AllAccessDisabled: { code: "AccessDenied", message: "access denied", expected: true },
  InvalidAccessKeyId: { code: "AccessDenied", message: "storage credentials were rejected", expected: false },
  SignatureDoesNotMatch: { code: "AccessDenied", message: "storage credentials were rejected", expected: false },
  ExpiredToken: { code: "AccessDenied", message: "storage credentials have expired", expected: false },
  InvalidToken: { code: "AccessDenied", message: "storage credentials were rejected", expected: false },
  NoSuchBucket: { code: "StorageUnavailable", message: "storage is not available", expected: false },
  InvalidRange: { code: "InvalidRange", message: "requested range is not satisfiable", expected: true },
  InvalidObjectState: { code: "InvalidRequest", message: "object is archived and cannot be read", expected: true },
  SlowDown: { code: "Throttled", message: "storage is busy, retry later", expected: true },
  ThrottlingException: { code: "Throttled", message: "storage is busy, retry later", expected: true },
  RequestLimitExceeded: { code: "Throttled", message: "storage is busy, retry later", expected: true },
  ServiceUnavailable: { code: "StorageUnavailable", message: "storage is temporarily unavailable", expected: false },
  InternalError: { code: "StorageUnavailable", message: "storage is temporarily unavailable", expected: false },
  AbortError: { code: "Cancelled", message: "request was cancelled", expected: true },
  CredentialsProviderError: { code: "StorageUnavailable", message: "storage credentials are not configured", expected: false },
  TimeoutError: { code: "StorageUnavailable", message: "storage request timed out", expected: false },
  PreconditionFailed: { code: "Conflict", message: "the object changed during the operation, retry", expected: true },
} satisfies Record<string, SafeError>));

const NETWORK_ERROR_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "EPIPE",
]);

function fromStatus(status: number): SafeError | undefined {
  if (status === 404) return { code: "NotFound", message: "object not found", expected: true };
  if (status === 401 || status === 403) return { code: "AccessDenied", message: "access denied", expected: true };
  if (status === 412) return { code: "Conflict", message: "the object changed during the operation, retry", expected: true };
  if (status === 416) return { code: "InvalidRange", message: "requested range is not satisfiable", expected: true };
  if (status === 429 || status === 503) return { code: "Throttled", message: "storage is busy, retry later", expected: true };
  if (status >= 500) return { code: "StorageUnavailable", message: "storage is temporarily unavailable", expected: false };
  return undefined;
}

/** HTTP status from an AWS SDK error (`$metadata.httpStatusCode`), duck-typed. */
export function httpStatusOf(err: unknown): number | undefined {
  if (typeof err !== "object" || err === null || !("$metadata" in err)) return undefined;
  const metadata = err.$metadata;
  if (typeof metadata !== "object" || metadata === null || !("httpStatusCode" in metadata)) return undefined;
  return typeof metadata.httpStatusCode === "number" ? metadata.httpStatusCode : undefined;
}

function errnoCode(err: Error): string | undefined {
  return "code" in err && typeof err.code === "string" ? err.code : undefined;
}

/**
 * Map any thrown value onto a generic, client-safe error. Original error messages, request
 * IDs, ARNs, bucket names, keys, and stack traces are never copied into the result.
 */
export function toSafeError(err: unknown): SafeError {
  if (err instanceof ToolError) return { code: err.code, message: err.message, expected: true };
  if (err instanceof PathOutsideRootError) {
    return { code: "PathOutsideRoot", message: `path is not allowed (${err.message})`, expected: true };
  }

  if (err instanceof Error) {
    // Map lookup: names such as "constructor" or "__proto__" must not hit Object.prototype.
    const known = S3_ERROR_NAMES.get(err.name);
    if (known !== undefined) return known;

    const status = httpStatusOf(err);
    if (status !== undefined) {
      return fromStatus(status) ?? { code: "InternalError", message: "storage request failed", expected: false };
    }

    const errno = errnoCode(err);
    if (errno !== undefined && NETWORK_ERROR_CODES.has(errno)) {
      return { code: "StorageUnavailable", message: "could not reach storage", expected: false };
    }
  }

  return { code: "InternalError", message: "unexpected error", expected: false };
}

/** Format a client-safe error message, e.g. "NotFound: object not found". */
export function safeErrorMessage(err: unknown): string {
  const safe = toSafeError(err);
  return `${safe.code}: ${safe.message}`;
}

/** Build an MCP tool error result (isError: true) from any thrown value. */
export function errorResult(err: unknown): CallToolResult {
  return { content: [{ type: "text", text: safeErrorMessage(err) }], isError: true };
}

/**
 * Diagnostic fields for stderr logging of unexpected errors. Only the error class name,
 * HTTP status, and errno code are included: no messages (they can contain ARNs, bucket
 * names, or keys) and no stack traces. The one exception is StorageResponseError, whose
 * messages are fixed strings written by storage.ts (they say which check failed).
 */
export function errorLogFields(err: unknown): Record<string, string | number | undefined> {
  if (err instanceof Error) {
    const fields: Record<string, string | number | undefined> = {
      error: err.name,
      status: httpStatusOf(err),
      errno: errnoCode(err),
    };
    if (err.name === "StorageResponseError") fields.detail = err.message;
    return fields;
  }
  return { error: typeof err };
}
