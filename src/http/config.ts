import { z } from "zod";

import { ConfigError } from "../config.js";
import { hasControlChar } from "../paths.js";
import { Secret } from "../secret.js";

/**
 * Configuration for MCP_S3_TRANSPORT=http (PLAN.md section 9, Fase 3): bind address, public
 * URL (OAuth issuer), the static admin login, and OAuth client settings. Only read when the
 * HTTP transport is selected; the core variables (and MCP_S3_TOKEN_KEY, read-only mode) are
 * validated by loadConfig() in ../config.ts.
 */

/** OAuth callback of claude.ai custom connectors (the only one in Anthropic's connector docs). */
export const DEFAULT_REDIRECT_URIS: readonly string[] = ["https://claude.ai/api/mcp/auth_callback"];

export const DEFAULT_HTTP_HOST = "127.0.0.1";
export const DEFAULT_HTTP_PORT = 3000;
export const MIN_PASSWORD_LENGTH = 12;
export const MIN_CLIENT_SECRET_LENGTH = 32;
const MAX_CREDENTIAL_LENGTH = 1024;
const MAX_TRUST_PROXY_HOPS = 10;
/** Longest redirect URI accepted (allowlist entries and dynamic registrations). */
export const MAX_REDIRECT_URI_LENGTH = 512;

/** Hostnames treated as loopback in redirect URIs (RFC 8252 section 7.3) and Host headers. */
export const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

export interface StaticClientConfig {
  id: string;
  secret: Secret;
}

export interface HttpConfig {
  /** Bind address. Default 127.0.0.1. */
  host: string;
  port: number;
  /** Public origin of this server, e.g. https://mcp.example.com/ (OAuth issuer). Path is always "/". */
  publicUrl: URL;
  username: Secret;
  password: Secret;
  /** Pre-registered OAuth client (MCP_S3_OAUTH_CLIENT_ID / _SECRET), if configured. */
  staticClient: StaticClientConfig | undefined;
  /** Exact redirect URIs accepted besides loopback ones (dynamic registration and static client). */
  redirectUris: readonly string[];
  /** Whether dynamic client registration (POST /register) is enabled. */
  dynamicRegistration: boolean;
  /** Number of reverse proxy hops whose X-Forwarded-For entry is trusted (Express "trust proxy"). */
  trustProxyHops: number;
}

export function isLoopbackBindHost(host: string): boolean {
  return host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host);
}

/**
 * Validate MCP_S3_PUBLIC_URL. The MCP SDK only accepts an https issuer, or http for
 * localhost / 127.0.0.1. The SDK mounts the OAuth endpoints at absolute paths (/authorize,
 * /token, ...), so a path prefix is not supported.
 */
export function publicUrlProblem(url: URL): string | null {
  const httpLocal = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  if (url.protocol !== "https:" && !httpLocal) {
    return "MCP_S3_PUBLIC_URL must use https (http is only allowed for localhost and 127.0.0.1)";
  }
  if (url.username !== "" || url.password !== "") return "MCP_S3_PUBLIC_URL must not contain credentials";
  if (url.search !== "" || url.hash !== "") return "MCP_S3_PUBLIC_URL must not contain a query or fragment";
  if (url.pathname !== "/") return "MCP_S3_PUBLIC_URL must not contain a path (serve the server at the root of its own host name)";
  return null;
}

/**
 * Whether a redirect URI is a loopback URI (http or https to localhost, 127.0.0.1, or [::1],
 * any port and path). Such URIs are always accepted for dynamic client registration, so that
 * Claude Code and MCP Inspector work locally.
 */
export function isLoopbackRedirectUri(value: string): boolean {
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  return (
    (url.protocol === "http:" || url.protocol === "https:") &&
    LOOPBACK_HOSTNAMES.has(url.hostname) &&
    url.username === "" &&
    url.password === "" &&
    url.hash === ""
  );
}

/** Problem with one MCP_S3_OAUTH_REDIRECT_URIS entry, or null. The value itself is not echoed. */
function redirectUriProblem(value: string): string | null {
  if (value.length > MAX_REDIRECT_URI_LENGTH) return `MCP_S3_OAUTH_REDIRECT_URIS entries must be at most ${MAX_REDIRECT_URI_LENGTH} characters long`;
  if (!URL.canParse(value)) return "MCP_S3_OAUTH_REDIRECT_URIS entries must be absolute URLs";
  const url = new URL(value);
  if (url.protocol !== "https:" && !isLoopbackRedirectUri(value)) {
    return "MCP_S3_OAUTH_REDIRECT_URIS entries must use https (http is only allowed for localhost, 127.0.0.1, and [::1])";
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") {
    return "MCP_S3_OAUTH_REDIRECT_URIS entries must not contain credentials or a fragment";
  }
  if (url.href !== value) {
    return "MCP_S3_OAUTH_REDIRECT_URIS entries must be written in canonical form (e.g. lower-case host, explicit path)";
  }
  return null;
}

function flag(name: string, defaultValue: boolean) {
  return z.stringbool({ error: `${name} must be a boolean (true/false)` }).default(defaultValue);
}

function credential(name: string, minLength: number) {
  return z
    .string({ error: `${name} is required when MCP_S3_TRANSPORT=http` })
    .superRefine((value, ctx) => {
      let problem: string | undefined;
      if (value === "") problem = `${name} must not be empty when MCP_S3_TRANSPORT=http`;
      else if (value.length < minLength) problem = `${name} must be at least ${minLength} characters long`;
      else if (value.length > MAX_CREDENTIAL_LENGTH) problem = `${name} must be at most ${MAX_CREDENTIAL_LENGTH} characters long`;
      else if (!value.isWellFormed() || hasControlChar(value)) problem = `${name} must not contain control characters`;
      if (problem !== undefined) ctx.addIssue({ code: "custom", message: problem });
    });
}

const HttpEnvSchema = z
  .object({
    MCP_S3_HTTP_HOST: z.string().min(1).max(255).default(DEFAULT_HTTP_HOST),
    MCP_S3_HTTP_PORT: z
      .string()
      .regex(/^\d{1,5}$/, "MCP_S3_HTTP_PORT must be a port number (1-65535)")
      .transform(Number)
      .pipe(z.number().int().min(1, "MCP_S3_HTTP_PORT must be a port number (1-65535)").max(65535, "MCP_S3_HTTP_PORT must be a port number (1-65535)"))
      .default(DEFAULT_HTTP_PORT),
    MCP_S3_PUBLIC_URL: z
      .string()
      .refine((value) => URL.canParse(value), "MCP_S3_PUBLIC_URL must be an absolute URL, e.g. https://mcp.example.com")
      .transform((value) => new URL(value))
      .optional(),
    MCP_S3_AUTH_USERNAME: credential("MCP_S3_AUTH_USERNAME", 1),
    MCP_S3_AUTH_PASSWORD: credential("MCP_S3_AUTH_PASSWORD", MIN_PASSWORD_LENGTH),
    MCP_S3_OAUTH_CLIENT_ID: z
      .string()
      .regex(/^[A-Za-z0-9._~-]{1,128}$/, "MCP_S3_OAUTH_CLIENT_ID must be 1-128 characters of A-Z a-z 0-9 . _ ~ -")
      .optional(),
    MCP_S3_OAUTH_CLIENT_SECRET: z
      .string()
      // Unreserved characters only: "+", "%", ":" and the like do not survive the
      // form-urlencoding that client_secret_basic applies before base64 (RFC 6749 2.3.1).
      .regex(/^[A-Za-z0-9._~-]+$/, "MCP_S3_OAUTH_CLIENT_SECRET may only contain A-Z a-z 0-9 . _ ~ - (e.g. openssl rand -hex 32)")
      .min(MIN_CLIENT_SECRET_LENGTH, `MCP_S3_OAUTH_CLIENT_SECRET must be at least ${MIN_CLIENT_SECRET_LENGTH} characters long (e.g. openssl rand -hex 32)`)
      .max(512, "MCP_S3_OAUTH_CLIENT_SECRET must be at most 512 characters long")
      .optional(),
    MCP_S3_OAUTH_REDIRECT_URIS: z
      .string()
      .transform((value) => value.split(",").map((entry) => entry.trim()).filter((entry) => entry !== ""))
      .superRefine((entries, ctx) => {
        if (entries.length === 0) ctx.addIssue({ code: "custom", message: "MCP_S3_OAUTH_REDIRECT_URIS must list at least one URI" });
        for (const entry of entries) {
          const problem = redirectUriProblem(entry);
          if (problem !== null) {
            ctx.addIssue({ code: "custom", message: problem });
            return;
          }
        }
      })
      .optional(),
    MCP_S3_OAUTH_DYNAMIC_REGISTRATION: flag("MCP_S3_OAUTH_DYNAMIC_REGISTRATION", true),
    MCP_S3_TRUST_PROXY: z
      .string()
      .regex(/^\d{1,2}$/, `MCP_S3_TRUST_PROXY must be the number of trusted reverse proxy hops (0-${MAX_TRUST_PROXY_HOPS})`)
      .transform(Number)
      .pipe(z.number().int().min(0).max(MAX_TRUST_PROXY_HOPS, `MCP_S3_TRUST_PROXY must be at most ${MAX_TRUST_PROXY_HOPS}`))
      .default(0),
  })
  .superRefine((env, ctx) => {
    if (env.MCP_S3_PUBLIC_URL !== undefined) {
      const problem = publicUrlProblem(env.MCP_S3_PUBLIC_URL);
      if (problem !== null) ctx.addIssue({ code: "custom", path: ["MCP_S3_PUBLIC_URL"], message: problem });
    } else if (!isLoopbackBindHost(env.MCP_S3_HTTP_HOST)) {
      ctx.addIssue({
        code: "custom",
        path: ["MCP_S3_PUBLIC_URL"],
        message: "MCP_S3_PUBLIC_URL is required when MCP_S3_HTTP_HOST is not a loopback address (e.g. https://mcp.example.com)",
      });
    }
    const hasId = env.MCP_S3_OAUTH_CLIENT_ID !== undefined;
    const hasSecret = env.MCP_S3_OAUTH_CLIENT_SECRET !== undefined;
    if (hasId !== hasSecret) {
      ctx.addIssue({
        code: "custom",
        path: [hasId ? "MCP_S3_OAUTH_CLIENT_SECRET" : "MCP_S3_OAUTH_CLIENT_ID"],
        message: "MCP_S3_OAUTH_CLIENT_ID and MCP_S3_OAUTH_CLIENT_SECRET must be set together",
      });
    }
    if (!env.MCP_S3_OAUTH_DYNAMIC_REGISTRATION && !hasId) {
      ctx.addIssue({
        code: "custom",
        path: ["MCP_S3_OAUTH_DYNAMIC_REGISTRATION"],
        message: "MCP_S3_OAUTH_DYNAMIC_REGISTRATION=false requires MCP_S3_OAUTH_CLIENT_ID and MCP_S3_OAUTH_CLIENT_SECRET (no client could log in)",
      });
    }
  });

const ENV_NAMES = Object.keys(HttpEnvSchema.shape) as (keyof typeof HttpEnvSchema.shape)[];
/** Variables whose empty value means "missing" instead of "use the default". */
const REQUIRED_ENV_NAMES: ReadonlySet<string> = new Set(["MCP_S3_AUTH_USERNAME", "MCP_S3_AUTH_PASSWORD"]);

/**
 * Parse the HTTP-mode variables. Empty optional variables fall back to their defaults.
 * Error messages never contain the values (passwords, secrets, URLs).
 *
 * @throws ConfigError when a variable is missing or invalid.
 */
export function loadHttpConfig(env: Readonly<Record<string, string | undefined>> = process.env): HttpConfig {
  const input: Record<string, string> = {};
  for (const name of ENV_NAMES) {
    const value = env[name];
    if (value === undefined || (value === "" && !REQUIRED_ENV_NAMES.has(name))) continue;
    input[name] = value;
  }

  const result = HttpEnvSchema.safeParse(input);
  if (!result.success) {
    const issues = result.error.issues.map((issue) => {
      const name = issue.path.map(String).join(".");
      return issue.message.startsWith(name) || name === "" ? issue.message : `${name}: ${issue.message}`;
    });
    throw new ConfigError(issues);
  }

  const parsed = result.data;
  const port = parsed.MCP_S3_HTTP_PORT;
  const publicUrl = parsed.MCP_S3_PUBLIC_URL ?? new URL(`http://localhost:${port}`);
  return {
    host: parsed.MCP_S3_HTTP_HOST,
    port,
    publicUrl: new URL(publicUrl.origin),
    username: new Secret(parsed.MCP_S3_AUTH_USERNAME),
    password: new Secret(parsed.MCP_S3_AUTH_PASSWORD),
    staticClient:
      parsed.MCP_S3_OAUTH_CLIENT_ID !== undefined && parsed.MCP_S3_OAUTH_CLIENT_SECRET !== undefined
        ? { id: parsed.MCP_S3_OAUTH_CLIENT_ID, secret: new Secret(parsed.MCP_S3_OAUTH_CLIENT_SECRET) }
        : undefined,
    redirectUris: parsed.MCP_S3_OAUTH_REDIRECT_URIS ?? DEFAULT_REDIRECT_URIS,
    dynamicRegistration: parsed.MCP_S3_OAUTH_DYNAMIC_REGISTRATION,
    trustProxyHops: parsed.MCP_S3_TRUST_PROXY,
  };
}
