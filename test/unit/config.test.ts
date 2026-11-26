import { randomBytes } from "node:crypto";
import { inspect } from "node:util";

import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig, rootPrefixProblem, type Config } from "../../src/config.js";

const BUCKET = "acme-secret-bucket-7f3a";

const BASE: Readonly<Record<string, string>> = {
  S3_BUCKET: BUCKET,
  S3_ROOT_PREFIX: "claude-workspace/",
  AWS_REGION: "us-east-1",
};

function env(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return { ...BASE, ...overrides };
}

function configError(input: Record<string, string | undefined>): ConfigError {
  try {
    loadConfig(input);
  } catch (err) {
    if (err instanceof ConfigError) return err;
    throw new Error(`expected ConfigError, got ${String(err)}`, { cause: err });
  }
  throw new Error("expected loadConfig to throw ConfigError");
}

/** The issue list must name the offending variable. */
function expectIssueFor(err: ConfigError, name: string): void {
  expect(err.issues.length).toBeGreaterThan(0);
  expect(err.issues.some((issue) => issue.includes(name))).toBe(true);
}

describe("loadConfig: required variables", () => {
  it("loads a minimal valid environment", () => {
    const config = loadConfig(env());
    expect(config.bucket).toBe(BUCKET);
    expect(config.rootPrefix).toBe("claude-workspace/");
    expect(config.region).toBe("us-east-1");
  });

  it.each(["S3_BUCKET", "S3_ROOT_PREFIX", "AWS_REGION"])("fails when %s is missing", (name) => {
    const err = configError(env({ [name]: undefined }));
    expect(err).toBeInstanceOf(Error);
    expectIssueFor(err, name);
  });

  it.each(["S3_BUCKET", "S3_ROOT_PREFIX", "AWS_REGION"])("fails when %s is an empty string", (name) => {
    expectIssueFor(configError(env({ [name]: "" })), name);
  });

  it("reports every missing required variable at once", () => {
    const err = configError({});
    for (const name of ["S3_BUCKET", "S3_ROOT_PREFIX", "AWS_REGION"]) expectIssueFor(err, name);
    expect(err.issues.length).toBeGreaterThanOrEqual(3);
  });

  it("issues are plain strings and the message lists them", () => {
    const err = configError({});
    for (const issue of err.issues) {
      expect(typeof issue).toBe("string");
      expect(err.message).toContain(issue);
    }
  });
});

describe("loadConfig: S3_ROOT_PREFIX validation (server must not start)", () => {
  it.each([
    ["empty", ""],
    ["no trailing slash", "claude-workspace"],
    ["no trailing slash, nested", "team/claude-workspace"],
    ["'..' segment", "a/../b/"],
    ["only '..'", "../"],
    ["'..' without slash", ".."],
    ["'.' segment", "./"],
    ["'.' in the middle", "a/./b/"],
    ["'..' at the end", "claude-workspace/../"],
    ["only a slash (whole bucket)", "/"],
    ["leading slash", "/claude-workspace/"],
    ["double slash", "a//b/"],
    ["double slash at end", "claude-workspace//"],
    ["backslash", "a\\b/"],
    ["backslash traversal", "..\\"],
    ["NUL", "claude\x00workspace/"],
    ["newline", "claude\nworkspace/"],
    ["DEL", "claude\x7fworkspace/"],
    ["1024 bytes", `${"a".repeat(1023)}/`],
    ["more than 1024 bytes", `${"a".repeat(2000)}/`],
  ])("rejects %s", (_name, value) => {
    const err = configError(env({ S3_ROOT_PREFIX: value }));
    expectIssueFor(err, "S3_ROOT_PREFIX");
    expect(rootPrefixProblem(value)).not.toBeNull();
  });

  it.each([
    "claude-workspace/",
    "team/claude-workspace/",
    "a/",
    "with space/",
    "ünïcödé/",
    "%2e%2e/",
    "...data/",
    `${"a".repeat(1022)}/`,
  ])("accepts %j", (value) => {
    expect(rootPrefixProblem(value)).toBeNull();
    expect(loadConfig(env({ S3_ROOT_PREFIX: value })).rootPrefix).toBe(value);
  });

  it("does not echo the root prefix or the bucket name in the error (it goes to logs)", () => {
    const err = configError(env({ S3_ROOT_PREFIX: "very-private-prefix-9q" }));
    expect(err.message).not.toContain("very-private-prefix-9q");
    expect(err.message).not.toContain(BUCKET);
    for (const issue of err.issues) {
      expect(issue).not.toContain("very-private-prefix-9q");
      expect(issue).not.toContain(BUCKET);
    }
  });
});

describe("loadConfig: secure defaults", () => {
  const config: Config = loadConfig(env());

  it("is read-only by default", () => {
    expect(config.readOnly).toBe(true);
  });

  it("does not allow delete by default", () => {
    expect(config.allowDelete).toBe(false);
  });

  it("uses the documented limits", () => {
    expect(config.maxReadBytes).toBe(1_048_576);
    expect(config.maxWriteBytes).toBe(5_242_880);
    expect(config.maxListKeys).toBe(200);
  });

  it("uses the documented transport, log level, and path style", () => {
    expect(config.transport).toBe("stdio");
    expect(config.logLevel).toBe("INFO");
    expect(config.forcePathStyle).toBe(false);
    expect(config.endpoint).toBeUndefined();
  });

  it.each([
    "MCP_S3_READ_ONLY",
    "MCP_S3_ALLOW_DELETE",
    "MCP_S3_MAX_READ_BYTES",
    "MCP_S3_MAX_WRITE_BYTES",
    "MCP_S3_MAX_LIST_KEYS",
    "MCP_S3_TRANSPORT",
    "MCP_S3_LOG_LEVEL",
    "S3_ENDPOINT_URL",
    "S3_FORCE_PATH_STYLE",
    "MCP_S3_TOKEN_KEY",
  ])("treats an empty %s as not set", (name) => {
    expect(loadConfig(env({ [name]: "" }))).toEqual(config);
  });

  it("never copies credentials into the config object", () => {
    const loaded = loadConfig(
      env({
        AWS_ACCESS_KEY_ID: "AKIAEXAMPLESECRET123",
        AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        AWS_SESSION_TOKEN: "session-token-example",
        AWS_PROFILE: "mcp-s3-profile-example",
      }),
    );
    const serialised = JSON.stringify(loaded);
    expect(serialised).not.toContain("AKIAEXAMPLESECRET123");
    expect(serialised).not.toContain("wJalrXUtnFEMI");
    expect(serialised).not.toContain("session-token-example");
    expect(serialised).not.toContain("mcp-s3-profile-example");
  });
});

describe("loadConfig: boolean flags (z.stringbool)", () => {
  it.each([
    ["true", true],
    ["TRUE", true],
    ["1", true],
    ["yes", true],
    ["on", true],
    ["false", false],
    ["False", false],
    ["0", false],
    ["no", false],
    ["off", false],
  ])("MCP_S3_READ_ONLY=%j parses as %s", (value, expected) => {
    expect(loadConfig(env({ MCP_S3_READ_ONLY: value })).readOnly).toBe(expected);
    expect(loadConfig(env({ MCP_S3_ALLOW_DELETE: value })).allowDelete).toBe(expected);
    expect(loadConfig(env({ S3_FORCE_PATH_STYLE: value })).forcePathStyle).toBe(expected);
  });

  it.each(["MCP_S3_READ_ONLY", "MCP_S3_ALLOW_DELETE", "S3_FORCE_PATH_STYLE"])(
    "rejects a non-boolean %s instead of falling back to a default",
    (name) => {
      expectIssueFor(configError(env({ [name]: "maybe" })), name);
      expectIssueFor(configError(env({ [name]: "2" })), name);
    },
  );
});

describe("loadConfig: numeric limits", () => {
  it("parses explicit limits", () => {
    const config = loadConfig(
      env({ MCP_S3_MAX_READ_BYTES: "2048", MCP_S3_MAX_WRITE_BYTES: "4096", MCP_S3_MAX_LIST_KEYS: "1000" }),
    );
    expect(config.maxReadBytes).toBe(2048);
    expect(config.maxWriteBytes).toBe(4096);
    expect(config.maxListKeys).toBe(1000);
  });

  it.each(["MCP_S3_MAX_READ_BYTES", "MCP_S3_MAX_WRITE_BYTES", "MCP_S3_MAX_LIST_KEYS"])(
    "rejects invalid values for %s",
    (name) => {
      for (const value of ["0", "-1", "1.5", "abc", "1e3", " 10", "0x10"]) {
        expectIssueFor(configError(env({ [name]: value })), name);
      }
    },
  );

  it("caps MCP_S3_MAX_LIST_KEYS at the S3 page size of 1000", () => {
    expectIssueFor(configError(env({ MCP_S3_MAX_LIST_KEYS: "1001" })), "MCP_S3_MAX_LIST_KEYS");
  });
});

describe("loadConfig: other variables", () => {
  it("accepts an http(s) endpoint", () => {
    expect(loadConfig(env({ S3_ENDPOINT_URL: "http://127.0.0.1:9000" })).endpoint).toBe("http://127.0.0.1:9000");
    expect(loadConfig(env({ S3_ENDPOINT_URL: "https://s3.example.com" })).endpoint).toBe("https://s3.example.com");
  });

  it.each(["not a url", "ftp://example.com", "file:///etc/passwd"])("rejects endpoint %j", (value) => {
    expectIssueFor(configError(env({ S3_ENDPOINT_URL: value })), "S3_ENDPOINT_URL");
  });

  it("accepts the supported transports and rejects others", () => {
    const key = randomBytes(32).toString("base64");
    expect(loadConfig(env({ MCP_S3_TRANSPORT: "http", MCP_S3_TOKEN_KEY: key })).transport).toBe("http");
    expect(loadConfig(env({ MCP_S3_TRANSPORT: "stdio" })).transport).toBe("stdio");
    expectIssueFor(configError(env({ MCP_S3_TRANSPORT: "websocket" })), "MCP_S3_TRANSPORT");
  });

  it("MCP_S3_TRANSPORT=http requires MCP_S3_TOKEN_KEY", () => {
    expectIssueFor(configError(env({ MCP_S3_TRANSPORT: "http" })), "MCP_S3_TOKEN_KEY");
    expectIssueFor(configError(env({ MCP_S3_TRANSPORT: "http", MCP_S3_TOKEN_KEY: "" })), "MCP_S3_TOKEN_KEY");
  });

  it("accepts log levels case-insensitively and rejects unknown levels", () => {
    expect(loadConfig(env({ MCP_S3_LOG_LEVEL: "debug" })).logLevel).toBe("DEBUG");
    expect(loadConfig(env({ MCP_S3_LOG_LEVEL: "Warn" })).logLevel).toBe("WARN");
    expectIssueFor(configError(env({ MCP_S3_LOG_LEVEL: "verbose" })), "MCP_S3_LOG_LEVEL");
  });
});

// ---------------------------------------------------------------------------

const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Same 32 bytes, but with the unused low bits of the last data character set (non-canonical). */
function nonCanonical(canonical: string): string {
  const index = 42; // 32 bytes -> 43 data chars + "="; char 42 carries 4 data bits + 2 unused bits
  const value = B64_ALPHABET.indexOf(canonical.charAt(index));
  return canonical.slice(0, index) + B64_ALPHABET.charAt(value ^ 1) + canonical.slice(index + 1);
}

/** 32 bytes whose base64 contains both "+" and "/", so standard and URL-safe forms differ. */
const KEY_BYTES = Buffer.alloc(32, 0xfb);
const KEY_STANDARD = KEY_BYTES.toString("base64");
const KEY_URLSAFE = KEY_BYTES.toString("base64url");

describe("loadConfig: MCP_S3_TOKEN_KEY", () => {
  it("fixtures are what they claim to be", () => {
    expect(KEY_STANDARD).toMatch(/[+/]/);
    expect(KEY_STANDARD.endsWith("=")).toBe(true);
    expect(KEY_URLSAFE).toMatch(/[-_]/);
    expect(KEY_URLSAFE).not.toContain("=");
    const nc = nonCanonical(KEY_STANDARD);
    expect(nc).not.toBe(KEY_STANDARD);
    expect(Buffer.from(nc, "base64")).toEqual(KEY_BYTES);
  });

  it.each([
    ["standard base64 with padding", KEY_STANDARD],
    ["standard base64 without padding", KEY_STANDARD.replace(/=+$/, "")],
    ["URL-safe base64 without padding", KEY_URLSAFE],
  ])("accepts %s and decodes the same 32-byte key", (_name, value) => {
    const config = loadConfig(env({ MCP_S3_TOKEN_KEY: value }));
    expect(config.tokenKey).toBeDefined();
    expect(config.tokenKey?.symmetricKeySize).toBe(32);
    expect(config.tokenKey?.export()).toEqual(KEY_BYTES);
  });

  it("accepts a random key from `openssl rand -base64 32`-style input", () => {
    const value = randomBytes(32).toString("base64");
    expect(loadConfig(env({ MCP_S3_TOKEN_KEY: value })).tokenKey?.export().toString("base64")).toBe(value);
  });

  it.each([
    ["16 bytes", randomBytes(16).toString("base64")],
    ["48 bytes", randomBytes(48).toString("base64")],
    ["31 bytes", randomBytes(31).toString("base64")],
    ["33 bytes", randomBytes(33).toString("base64")],
    ["64 hex characters (32 bytes as hex)", randomBytes(32).toString("hex")],
    ["not base64", "this is not base64 at all!!"],
    ["base64 with an inner space", `${KEY_STANDARD.slice(0, 20)} ${KEY_STANDARD.slice(20)}`],
    ["mixed standard and URL-safe alphabets", `${KEY_STANDARD.slice(0, 10)}-_${KEY_STANDARD.slice(12)}`],
    ["non-canonical base64 (unused bits set)", nonCanonical(KEY_STANDARD)],
    ["32 bytes with one extra '=' (45 characters, '==')", `${KEY_STANDARD}=`],
    ["too much padding", `${KEY_STANDARD}==`],
  ])("rejects %s without echoing the value", (_name, value) => {
    const err = configError(env({ MCP_S3_TOKEN_KEY: value }));
    expectIssueFor(err, "MCP_S3_TOKEN_KEY");
    expect(err.message).not.toContain(value);
    for (const issue of err.issues) expect(issue).not.toContain(value);
  });

  it("an empty value in stdio mode means no configured key", () => {
    expect(loadConfig(env({ MCP_S3_TOKEN_KEY: "" })).tokenKey).toBeUndefined();
    expect(loadConfig(env()).tokenKey).toBeUndefined();
  });

  it("the key never appears when the config is serialised or inspected", () => {
    const config = loadConfig(env({ MCP_S3_TOKEN_KEY: KEY_STANDARD }));
    for (const rendered of [JSON.stringify(config), inspect(config, { depth: 10 }), inspect(config.tokenKey), JSON.stringify(config.tokenKey)]) {
      expect(rendered).not.toContain(KEY_STANDARD.replace(/=+$/, ""));
      expect(rendered).not.toContain(KEY_URLSAFE);
      expect(rendered).not.toContain(KEY_BYTES.toString("hex"));
    }
  });
});

// ---------------------------------------------------------------------------

describe("loadConfig: the HTTP transport is always read-only (PLAN.md section 9, Fase 3)", () => {
  const HTTP = env({ MCP_S3_TRANSPORT: "http", MCP_S3_TOKEN_KEY: randomBytes(32).toString("base64") });

  it("accepts http with the read-only defaults", () => {
    const config = loadConfig(HTTP);
    expect(config.transport).toBe("http");
    expect(config.readOnly).toBe(true);
    expect(config.allowDelete).toBe(false);
  });

  it("accepts an explicit MCP_S3_READ_ONLY=true and MCP_S3_ALLOW_DELETE=false", () => {
    const config = loadConfig({ ...HTTP, MCP_S3_READ_ONLY: "true", MCP_S3_ALLOW_DELETE: "false" });
    expect(config.readOnly).toBe(true);
    expect(config.allowDelete).toBe(false);
  });

  it("rejects http with MCP_S3_READ_ONLY=false", () => {
    expectIssueFor(configError({ ...HTTP, MCP_S3_READ_ONLY: "false" }), "MCP_S3_READ_ONLY");
  });

  it("rejects http with MCP_S3_ALLOW_DELETE=true", () => {
    expectIssueFor(configError({ ...HTTP, MCP_S3_ALLOW_DELETE: "true" }), "MCP_S3_ALLOW_DELETE");
  });

  it("rejects http with MCP_S3_READ_ONLY=false and MCP_S3_ALLOW_DELETE=true, naming both", () => {
    const err = configError({ ...HTTP, MCP_S3_READ_ONLY: "false", MCP_S3_ALLOW_DELETE: "true" });
    expectIssueFor(err, "MCP_S3_READ_ONLY");
    expectIssueFor(err, "MCP_S3_ALLOW_DELETE");
  });

  it("still allows write mode for stdio", () => {
    const config = loadConfig(env({ MCP_S3_TRANSPORT: "stdio", MCP_S3_READ_ONLY: "false", MCP_S3_ALLOW_DELETE: "true" }));
    expect(config.readOnly).toBe(false);
    expect(config.allowDelete).toBe(true);
  });

  it("does not echo the token key in the error", () => {
    const key = randomBytes(32).toString("base64");
    const err = configError({ ...HTTP, MCP_S3_TOKEN_KEY: key, MCP_S3_READ_ONLY: "false" });
    expect(err.message).not.toContain(key);
  });
});
