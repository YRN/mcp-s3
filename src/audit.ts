import type { ErrorCode } from "./errors.js";

/**
 * Structured audit log (PLAN.md section 9, Fase 2): exactly one JSON line per tool call,
 * written to stderr (stdout belongs to the MCP stdio protocol). Independent of
 * MCP_S3_LOG_LEVEL.
 *
 * A line contains only: time, tool name, the relative path argument(s) as sent by the client,
 * the result ("ok" / "error"), the generic error code from errors.ts, the number of bytes read
 * (read_object), and the duration. It never contains bucket names, the root prefix, full S3
 * keys, file contents, credentials, tokens, or passwords.
 *
 * Example:
 * {"type":"audit","time":"2026-11-26T10:00:00.000Z","tool":"read_object","path":"a.txt","result":"ok","bytes":12,"duration_ms":8}
 */

/** Path-like tool arguments that are copied into the audit line (all relative to the root). */
export const AUDITED_PATH_ARGS = ["path", "source", "destination"] as const;
type AuditedPathArg = (typeof AUDITED_PATH_ARGS)[number];

/** Upper bound on a path copied into an audit line (input paths are limited to 1024 by schema). */
const MAX_AUDIT_PATH_LENGTH = 1024;

export interface AuditRecord {
  type: "audit";
  /** Start of the call, ISO 8601 UTC. */
  time: string;
  tool: string;
  path?: string;
  source?: string;
  destination?: string;
  result: "ok" | "error";
  /** Generic error code (errors.ts) when result is "error". */
  code?: ErrorCode;
  /** Bytes read from storage, when the tool reads object data. */
  bytes?: number;
  duration_ms: number;
}

/** Filled in by a handler while it runs; the wrapper copies it into the audit line. */
export interface AuditDetails {
  bytes?: number;
}

export type AuditSink = (line: string) => void;

const stderrSink: AuditSink = (line) => {
  console.error(line);
};

let sink: AuditSink = stderrSink;

/** Replace where audit lines go (e.g. capture them in tests). Pass undefined to restore stderr. */
export function setAuditSink(next: AuditSink | undefined): void {
  sink = next ?? stderrSink;
}

/** Relative path arguments of a tool call (only string values of the known argument names). */
export function auditPaths(args: unknown): Partial<Record<AuditedPathArg, string>> {
  const paths: Partial<Record<AuditedPathArg, string>> = {};
  if (typeof args !== "object" || args === null) return paths;
  for (const name of AUDITED_PATH_ARGS) {
    const value: unknown = (args as Record<string, unknown>)[name];
    if (typeof value === "string") paths[name] = value.slice(0, MAX_AUDIT_PATH_LENGTH);
  }
  return paths;
}

export interface AuditCall {
  /** Mutable details the handler can fill in (e.g. bytes read). */
  details: AuditDetails;
  ok(): void;
  /** `code` is omitted when a handler returned an error result instead of throwing. */
  error(code?: ErrorCode): void;
}

/** Start auditing one tool call. Exactly one of ok() / error() must be called when it ends. */
export function startAudit(tool: string, args: unknown, now: () => number = Date.now): AuditCall {
  const started = now();
  const paths = auditPaths(args);
  const details: AuditDetails = {};
  let done = false;

  const finish = (result: "ok" | "error", code?: ErrorCode): void => {
    if (done) return;
    done = true;
    const record: AuditRecord = {
      type: "audit",
      time: new Date(started).toISOString(),
      tool,
      ...paths,
      result,
      ...(code === undefined ? {} : { code }),
      ...(details.bytes === undefined ? {} : { bytes: details.bytes }),
      duration_ms: Math.max(0, now() - started),
    };
    try {
      sink(JSON.stringify(record));
    } catch {
      // Auditing must never break a tool call.
    }
  };

  return {
    details,
    ok: () => {
      finish("ok");
    },
    error: (code) => {
      finish("error", code);
    },
  };
}
