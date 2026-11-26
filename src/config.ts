import { z } from "zod";

import { hasControlChar, S3_MAX_KEY_BYTES } from "./paths.js";
import { Secret } from "./secret.js";
import { parseTokenKey } from "./tokens.js";

/** S3 limits a single ListObjectsV2 page to 1000 keys. */
export const S3_MAX_LIST_KEYS = 1000;

export const LOG_LEVELS = ["DEBUG", "INFO", "WARN", "ERROR"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export const TRANSPORTS = ["stdio", "http"] as const;
export type Transport = (typeof TRANSPORTS)[number];

/** Startup configuration error. The message is meant for stderr and never echoes env values. */
export class ConfigError extends Error {
  override readonly name = "ConfigError";
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid configuration:\n${issues.map((issue) => `  - ${issue}`).join("\n")}`);
    this.issues = issues;
  }
}

/**
 * Validate S3_ROOT_PREFIX. Returns a problem description, or null when the prefix is valid.
 *
 * Rules (PLAN.md section 3): non-empty, ends with "/", no "." or ".." segment.
 * Additionally rejected because they can never be produced safely by resolveKey():
 * control characters, backslashes, empty segments (leading "/" or "//"), and prefixes
 * that already exceed the S3 key length limit.
 */
export function rootPrefixProblem(value: string): string | null {
  if (value === "") return "S3_ROOT_PREFIX must not be empty (whole-bucket access is not supported)";
  if (!value.isWellFormed() || hasControlChar(value)) return "S3_ROOT_PREFIX must not contain control or invalid characters";
  if (value.includes("\\")) return "S3_ROOT_PREFIX must not contain a backslash";
  if (!value.endsWith("/")) return "S3_ROOT_PREFIX must end with '/' (e.g. claude-workspace/)";

  const segments = value.slice(0, -1).split("/");
  if (segments.some((s) => s === "." || s === "..")) return "S3_ROOT_PREFIX must not contain '.' or '..' segments";
  if (segments.some((s) => s === "")) return "S3_ROOT_PREFIX must not start with '/' or contain empty segments ('//')";
  if (Buffer.byteLength(value, "utf8") >= S3_MAX_KEY_BYTES) return `S3_ROOT_PREFIX must be shorter than ${S3_MAX_KEY_BYTES} bytes`;
  return null;
}

function required(name: string) {
  return z.string({ error: `${name} is required` }).min(1, `${name} must not be empty`);
}

function flag(name: string, defaultValue: boolean) {
  return z
    .stringbool({ error: `${name} must be a boolean (true/false)` })
    .default(defaultValue);
}

function positiveInt(name: string, defaultValue: number, max: number = Number.MAX_SAFE_INTEGER) {
  return z
    .string()
    .regex(/^\d+$/, `${name} must be a positive integer`)
    .transform(Number)
    .pipe(
      z
        .number()
        .int()
        .min(1, `${name} must be at least 1`)
        .max(max, `${name} must be at most ${max}`),
    )
    .default(defaultValue);
}

const EnvSchema = z.object({
  S3_BUCKET: required("S3_BUCKET"),
  S3_ROOT_PREFIX: z.string({ error: "S3_ROOT_PREFIX is required" }).superRefine((value, ctx) => {
    const problem = rootPrefixProblem(value);
    if (problem !== null) ctx.addIssue({ code: "custom", message: problem });
  }),
  AWS_REGION: required("AWS_REGION"),
  S3_ENDPOINT_URL: z
    .url({ protocol: /^https?$/, error: "S3_ENDPOINT_URL must be an http(s) URL" })
    .optional(),
  S3_FORCE_PATH_STYLE: flag("S3_FORCE_PATH_STYLE", false),
  MCP_S3_READ_ONLY: flag("MCP_S3_READ_ONLY", true),
  MCP_S3_ALLOW_DELETE: flag("MCP_S3_ALLOW_DELETE", false),
  MCP_S3_MAX_READ_BYTES: positiveInt("MCP_S3_MAX_READ_BYTES", 1_048_576),
  MCP_S3_MAX_WRITE_BYTES: positiveInt("MCP_S3_MAX_WRITE_BYTES", 5_242_880),
  MCP_S3_MAX_LIST_KEYS: positiveInt("MCP_S3_MAX_LIST_KEYS", 200, S3_MAX_LIST_KEYS),
  MCP_S3_TRANSPORT: z
    .enum(TRANSPORTS, { error: `MCP_S3_TRANSPORT must be one of: ${TRANSPORTS.join(", ")}` })
    .default("stdio"),
  MCP_S3_LOG_LEVEL: z
    .string()
    .transform((value) => value.toUpperCase())
    .pipe(z.enum(LOG_LEVELS, { error: `MCP_S3_LOG_LEVEL must be one of: ${LOG_LEVELS.join(", ")}` }))
    .default("INFO"),
  // Secret: the value is turned into a KeyObject (never serialized or printed) and no issue
  // message ever contains it.
  MCP_S3_TOKEN_KEY: z
    .string()
    .transform((value, ctx) => {
      const key = parseTokenKey(value);
      if (key === null) {
        ctx.addIssue({
          code: "custom",
          message: "MCP_S3_TOKEN_KEY must be exactly 32 bytes encoded as base64 (e.g. the output of `openssl rand -base64 32`)",
        });
        return z.NEVER;
      }
      return key;
    })
    .optional(),
  // Secret: the URL carries the database password, so it is wrapped and never echoed.
  MCP_S3_AUDIT_DATABASE_URL: z
    .url({ protocol: /^postgres(ql)?$/, error: "MCP_S3_AUDIT_DATABASE_URL must be a postgres:// or postgresql:// URL" })
    .transform((value) => new Secret(value))
    .optional(),
}).superRefine((env, ctx) => {
  if (env.MCP_S3_TRANSPORT !== "http") return;
  if (env.MCP_S3_TOKEN_KEY === undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["MCP_S3_TOKEN_KEY"],
      message:
        "MCP_S3_TOKEN_KEY is required when MCP_S3_TRANSPORT=http (continuation tokens and OAuth tokens must survive restarts)",
    });
  }
  // PLAN.md section 9, Fase 3: the remote (HTTP) mode is always read-only.
  if (!env.MCP_S3_READ_ONLY) {
    ctx.addIssue({
      code: "custom",
      path: ["MCP_S3_READ_ONLY"],
      message: "MCP_S3_READ_ONLY=false is not allowed when MCP_S3_TRANSPORT=http (the HTTP mode is always read-only)",
    });
  }
  if (env.MCP_S3_ALLOW_DELETE) {
    ctx.addIssue({
      code: "custom",
      path: ["MCP_S3_ALLOW_DELETE"],
      message: "MCP_S3_ALLOW_DELETE=true is not allowed when MCP_S3_TRANSPORT=http (the HTTP mode is always read-only)",
    });
  }
});

const ConfigSchema = EnvSchema.transform((env) => ({
  bucket: env.S3_BUCKET,
  rootPrefix: env.S3_ROOT_PREFIX,
  region: env.AWS_REGION,
  endpoint: env.S3_ENDPOINT_URL,
  forcePathStyle: env.S3_FORCE_PATH_STYLE,
  readOnly: env.MCP_S3_READ_ONLY,
  allowDelete: env.MCP_S3_ALLOW_DELETE,
  maxReadBytes: env.MCP_S3_MAX_READ_BYTES,
  maxWriteBytes: env.MCP_S3_MAX_WRITE_BYTES,
  maxListKeys: env.MCP_S3_MAX_LIST_KEYS,
  transport: env.MCP_S3_TRANSPORT,
  logLevel: env.MCP_S3_LOG_LEVEL,
  /**
   * AES-256-GCM key for continuation tokens, from MCP_S3_TOKEN_KEY. undefined means "not
   * configured": stdio mode then uses a random key per process (tokens.ts).
   */
  tokenKey: env.MCP_S3_TOKEN_KEY,
  /** PostgreSQL connection URL for the audit log. undefined means audit lines go to stderr only. */
  auditDatabaseUrl: env.MCP_S3_AUDIT_DATABASE_URL,
}));

export type Config = z.infer<typeof ConfigSchema>;

const ENV_NAMES = Object.keys(EnvSchema.shape) as (keyof typeof EnvSchema.shape)[];
const REQUIRED_ENV_NAMES: ReadonlySet<string> = new Set(["S3_BUCKET", "S3_ROOT_PREFIX", "AWS_REGION"]);

/**
 * Parse and validate configuration from environment variables.
 *
 * Empty strings for optional variables are treated as "not set" so they fall back to their
 * defaults; an empty required variable is reported as "must not be empty". Credentials (AWS_PROFILE,
 * AWS_ACCESS_KEY_ID, ...) are intentionally not read here: the AWS SDK default
 * credential provider chain picks them up, and they never enter the Config object.
 *
 * @throws ConfigError when any variable is missing or invalid.
 */
export function loadConfig(env: Readonly<Record<string, string | undefined>> = process.env): Config {
  const input: Record<string, string> = {};
  for (const name of ENV_NAMES) {
    const value = env[name];
    if (value === undefined || (value === "" && !REQUIRED_ENV_NAMES.has(name))) continue;
    input[name] = value;
  }

  const result = ConfigSchema.safeParse(input);
  if (!result.success) {
    const issues = result.error.issues.map((issue) => {
      const name = issue.path.map(String).join(".");
      return issue.message.startsWith(name) || name === "" ? issue.message : `${name}: ${issue.message}`;
    });
    throw new ConfigError(issues);
  }
  return result.data;
}
