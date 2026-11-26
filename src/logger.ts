import type { LogLevel } from "./config.js";

/**
 * Minimal leveled logger. Everything goes to stderr via console.error because stdout is
 * reserved for the MCP stdio protocol. Callers must never pass credentials, bucket names,
 * the root prefix, or file contents as message or fields.
 */

const ORDER: Record<LogLevel, number> = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };

let threshold = ORDER.INFO;

export function setLogLevel(level: LogLevel): void {
  threshold = ORDER[level];
}

export type LogFields = Readonly<Record<string, string | number | boolean | null | undefined>>;

function write(level: LogLevel, message: string, fields?: LogFields): void {
  if (ORDER[level] < threshold) return;
  const suffix = fields === undefined ? "" : ` ${JSON.stringify(fields)}`;
  console.error(`[mcp-s3] ${level} ${message}${suffix}`);
}

export const log = {
  debug(message: string, fields?: LogFields): void {
    write("DEBUG", message, fields);
  },
  info(message: string, fields?: LogFields): void {
    write("INFO", message, fields);
  },
  warn(message: string, fields?: LogFields): void {
    write("WARN", message, fields);
  },
  error(message: string, fields?: LogFields): void {
    write("ERROR", message, fields);
  },
};
