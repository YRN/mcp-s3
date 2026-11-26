import { describe, expect, it } from "vitest";

import { ConfigError } from "../../src/config.js";
import {
  DEFAULT_REDIRECT_URIS,
  isLoopbackBindHost,
  isLoopbackRedirectUri,
  loadHttpConfig,
  publicUrlProblem,
  type HttpConfig,
} from "../../src/http/config.js";

const PASSWORD = "correct-horse-battery";
const SECRET_32 = "0123456789abcdef0123456789abcdef";

const BASE: Readonly<Record<string, string>> = {
  MCP_S3_AUTH_USERNAME: "admin",
  MCP_S3_AUTH_PASSWORD: PASSWORD,
};

function env(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return { ...BASE, ...overrides };
}

function load(overrides: Record<string, string | undefined> = {}): HttpConfig {
  return loadHttpConfig(env(overrides));
}

function configError(input: Record<string, string | undefined>): ConfigError {
  try {
    loadHttpConfig(input);
  } catch (err) {
    if (err instanceof ConfigError) return err;
    throw new Error(`expected ConfigError, got ${String(err)}`, { cause: err });
  }
  throw new Error("expected loadHttpConfig to throw ConfigError");
}

function expectIssueFor(overrides: Record<string, string | undefined>, name: string): ConfigError {
  const err = configError(env(overrides));
  expect(err.issues.length).toBeGreaterThan(0);
  expect(err.issues.some((issue) => issue.includes(name)), `${name} in ${JSON.stringify(err.issues)}`).toBe(true);
  return err;
}

describe("loadHttpConfig: defaults", () => {
  it("applies every documented default", () => {
    const config = load();
    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(3000);
    expect(config.publicUrl.href).toBe("http://localhost:3000/");
    expect(config.staticClient).toBeUndefined();
    expect(config.redirectUris).toEqual(["https://claude.ai/api/mcp/auth_callback"]);
    expect(config.redirectUris).toEqual(DEFAULT_REDIRECT_URIS);
    expect(config.dynamicRegistration).toBe(true);
    expect(config.trustProxyHops).toBe(0);
  });

  it("the default public URL follows the port", () => {
    expect(load({ MCP_S3_HTTP_PORT: "8123" }).publicUrl.href).toBe("http://localhost:8123/");
  });

  it("treats empty optional variables as unset", () => {
    const config = load({
      MCP_S3_HTTP_HOST: "",
      MCP_S3_HTTP_PORT: "",
      MCP_S3_PUBLIC_URL: "",
      MCP_S3_OAUTH_CLIENT_ID: "",
      MCP_S3_OAUTH_CLIENT_SECRET: "",
      MCP_S3_OAUTH_REDIRECT_URIS: "",
      MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "",
      MCP_S3_TRUST_PROXY: "",
    });
    expect(config.host).toBe("127.0.0.1");
    expect(config.port).toBe(3000);
    expect(config.staticClient).toBeUndefined();
    expect(config.dynamicRegistration).toBe(true);
    expect(config.trustProxyHops).toBe(0);
  });

  it("wraps the credentials in Secret (not printable)", () => {
    const config = load();
    expect(config.username.reveal()).toBe("admin");
    expect(config.password.reveal()).toBe(PASSWORD);
    expect(JSON.stringify(config)).not.toContain(PASSWORD);
    expect(JSON.stringify(config)).not.toContain("admin");
  });
});

describe("loadHttpConfig: required credentials", () => {
  it("requires MCP_S3_AUTH_USERNAME", () => {
    expectIssueFor({ MCP_S3_AUTH_USERNAME: undefined }, "MCP_S3_AUTH_USERNAME");
    expectIssueFor({ MCP_S3_AUTH_USERNAME: "" }, "MCP_S3_AUTH_USERNAME");
  });

  it("requires MCP_S3_AUTH_PASSWORD", () => {
    expectIssueFor({ MCP_S3_AUTH_PASSWORD: undefined }, "MCP_S3_AUTH_PASSWORD");
    expectIssueFor({ MCP_S3_AUTH_PASSWORD: "" }, "MCP_S3_AUTH_PASSWORD");
  });

  it("reports both when both are missing", () => {
    const err = configError({});
    expect(err.issues.some((i) => i.includes("MCP_S3_AUTH_USERNAME"))).toBe(true);
    expect(err.issues.some((i) => i.includes("MCP_S3_AUTH_PASSWORD"))).toBe(true);
  });

  it("password needs at least 12 characters", () => {
    expectIssueFor({ MCP_S3_AUTH_PASSWORD: "a".repeat(11) }, "MCP_S3_AUTH_PASSWORD");
    expect(load({ MCP_S3_AUTH_PASSWORD: "a".repeat(12) }).password.reveal()).toBe("a".repeat(12));
  });

  it("rejects control characters in the credentials", () => {
    expectIssueFor({ MCP_S3_AUTH_PASSWORD: "a".repeat(11) + "\n" }, "MCP_S3_AUTH_PASSWORD");
    expectIssueFor({ MCP_S3_AUTH_USERNAME: "ad\u0000min" }, "MCP_S3_AUTH_USERNAME");
  });

  it("error messages never contain the password", () => {
    const err = configError(env({ MCP_S3_AUTH_PASSWORD: "short-pw" }));
    expect(err.message).not.toContain("short-pw");
    expect(JSON.stringify(err.issues)).not.toContain("short-pw");
  });
});

describe("loadHttpConfig: HTTP_HOST and HTTP_PORT", () => {
  it("accepts ports 1 to 65535", () => {
    expect(load({ MCP_S3_HTTP_PORT: "1" }).port).toBe(1);
    expect(load({ MCP_S3_HTTP_PORT: "65535" }).port).toBe(65535);
  });

  it.each(["0", "65536", "99999", "-1", "abc", "1.5", " 80", "080a", "123456"])("rejects port %j", (value) => {
    expectIssueFor({ MCP_S3_HTTP_PORT: value }, "MCP_S3_HTTP_PORT");
  });

  it.each(["127.0.0.1", "localhost", "::1", "127.0.0.2"])("loopback host %s needs no public URL", (host) => {
    expect(load({ MCP_S3_HTTP_HOST: host }).host).toBe(host);
  });

  it.each(["0.0.0.0", "::", "192.168.1.5", "mcp.example.com"])("non-loopback host %s requires MCP_S3_PUBLIC_URL", (host) => {
    expectIssueFor({ MCP_S3_HTTP_HOST: host }, "MCP_S3_PUBLIC_URL");
  });

  it("a non-loopback host works with an https public URL", () => {
    const config = load({ MCP_S3_HTTP_HOST: "0.0.0.0", MCP_S3_PUBLIC_URL: "https://mcp.example.com" });
    expect(config.host).toBe("0.0.0.0");
    expect(config.publicUrl.href).toBe("https://mcp.example.com/");
  });
});

describe("loadHttpConfig: MCP_S3_PUBLIC_URL", () => {
  it.each([
    ["https://mcp.example.com", "https://mcp.example.com/"],
    ["https://mcp.example.com/", "https://mcp.example.com/"],
    ["https://mcp.example.com:8443", "https://mcp.example.com:8443/"],
    ["http://localhost:3000", "http://localhost:3000/"],
    ["http://127.0.0.1:4000", "http://127.0.0.1:4000/"],
  ])("accepts %s", (value, href) => {
    expect(load({ MCP_S3_PUBLIC_URL: value }).publicUrl.href).toBe(href);
  });

  it.each([
    ["http://mcp.example.com", "plain http on a public host"],
    ["http://192.168.1.5:3000", "plain http on a LAN address"],
    ["ftp://mcp.example.com", "other scheme"],
    ["https://mcp.example.com/mcp", "path"],
    ["https://mcp.example.com/prefix/", "path prefix"],
    ["https://mcp.example.com/?a=b", "query"],
    ["https://mcp.example.com/#frag", "fragment"],
    ["https://user:pw@mcp.example.com", "credentials"],
    ["not a url", "not a URL"],
    ["mcp.example.com", "no scheme"],
  ])("rejects %s (%s)", (value) => {
    expectIssueFor({ MCP_S3_PUBLIC_URL: value }, "MCP_S3_PUBLIC_URL");
  });

  it("publicUrlProblem agrees", () => {
    expect(publicUrlProblem(new URL("https://a.example"))).toBeNull();
    expect(publicUrlProblem(new URL("http://a.example"))).not.toBeNull();
    expect(publicUrlProblem(new URL("http://localhost:1"))).toBeNull();
    expect(publicUrlProblem(new URL("https://a.example/x"))).not.toBeNull();
  });
});

describe("loadHttpConfig: static OAuth client", () => {
  it("accepts a client id and secret together", () => {
    const config = load({ MCP_S3_OAUTH_CLIENT_ID: "my-client_1.0~x", MCP_S3_OAUTH_CLIENT_SECRET: SECRET_32 });
    expect(config.staticClient?.id).toBe("my-client_1.0~x");
    expect(config.staticClient?.secret.reveal()).toBe(SECRET_32);
    expect(JSON.stringify(config)).not.toContain(SECRET_32);
  });

  it("requires the secret when the id is set, and the id when the secret is set", () => {
    expectIssueFor({ MCP_S3_OAUTH_CLIENT_ID: "client" }, "MCP_S3_OAUTH_CLIENT_SECRET");
    expectIssueFor({ MCP_S3_OAUTH_CLIENT_SECRET: SECRET_32 }, "MCP_S3_OAUTH_CLIENT_ID");
  });

  it("client id: 1-128 characters of [A-Za-z0-9._~-]", () => {
    expect(load({ MCP_S3_OAUTH_CLIENT_ID: "a".repeat(128), MCP_S3_OAUTH_CLIENT_SECRET: SECRET_32 }).staticClient?.id).toHaveLength(128);
    for (const id of ["a".repeat(129), "has space", "slash/x", "colon:x", "ünï", "a@b", "a+b"]) {
      expectIssueFor({ MCP_S3_OAUTH_CLIENT_ID: id, MCP_S3_OAUTH_CLIENT_SECRET: SECRET_32 }, "MCP_S3_OAUTH_CLIENT_ID");
    }
  });

  it("client secret needs at least 32 characters", () => {
    expect(load({ MCP_S3_OAUTH_CLIENT_ID: "c", MCP_S3_OAUTH_CLIENT_SECRET: "x".repeat(32) }).staticClient).toBeDefined();
    const err = expectIssueFor({ MCP_S3_OAUTH_CLIENT_ID: "c", MCP_S3_OAUTH_CLIENT_SECRET: "x".repeat(31) }, "MCP_S3_OAUTH_CLIENT_SECRET");
    expect(err.message).not.toContain("x".repeat(31));
  });

  it("client secret may only contain A-Z a-z 0-9 . _ ~ -", () => {
    for (const secret of [SECRET_32 + " ", SECRET_32 + "é", SECRET_32 + "\n", SECRET_32 + "\u0000", " " + SECRET_32, SECRET_32 + "!", SECRET_32 + ":", SECRET_32 + "%", SECRET_32 + "+", SECRET_32 + "/", SECRET_32 + "\\", SECRET_32 + '"']) {
      expectIssueFor({ MCP_S3_OAUTH_CLIENT_ID: "c", MCP_S3_OAUTH_CLIENT_SECRET: secret }, "MCP_S3_OAUTH_CLIENT_SECRET");
    }
    expect(load({ MCP_S3_OAUTH_CLIENT_ID: "c", MCP_S3_OAUTH_CLIENT_SECRET: "aZ09._~-".repeat(4) }).staticClient).toBeDefined();
  });
});

describe("loadHttpConfig: MCP_S3_OAUTH_REDIRECT_URIS", () => {
  it("replaces the defaults (exact list, trimmed)", () => {
    const config = load({ MCP_S3_OAUTH_REDIRECT_URIS: " https://a.example/cb , https://b.example/cb " });
    expect(config.redirectUris).toEqual(["https://a.example/cb", "https://b.example/cb"]);
  });

  it("accepts loopback http entries", () => {
    expect(load({ MCP_S3_OAUTH_REDIRECT_URIS: "http://localhost:8080/cb" }).redirectUris).toEqual(["http://localhost:8080/cb"]);
  });

  it.each([
    ["http://evil.example/cb", "plain http"],
    ["https://a.example/cb#frag", "fragment"],
    ["https://user:pw@a.example/cb", "credentials"],
    ["a.example/cb", "relative"],
    ["javascript:alert(1)", "scheme"],
    ["https://A.example", "non-canonical (no path, upper case)"],
    ["https://a.example/cb, nonsense", "one bad entry"],
    [",,,", "no entries"],
    [`https://a.example/${"x".repeat(520)}`, "too long"],
  ])("rejects %s (%s)", (value) => {
    expectIssueFor({ MCP_S3_OAUTH_REDIRECT_URIS: value }, "MCP_S3_OAUTH_REDIRECT_URIS");
  });

  it("isLoopbackRedirectUri", () => {
    expect(isLoopbackRedirectUri("http://localhost:1234/cb")).toBe(true);
    expect(isLoopbackRedirectUri("http://127.0.0.1/cb")).toBe(true);
    expect(isLoopbackRedirectUri("http://[::1]:5/cb")).toBe(true);
    expect(isLoopbackRedirectUri("http://localhost.evil.example/cb")).toBe(false);
    expect(isLoopbackRedirectUri("http://127.0.0.1.evil.example/cb")).toBe(false);
    expect(isLoopbackRedirectUri("https://claude.ai/cb")).toBe(false);
    expect(isLoopbackRedirectUri("http://localhost/cb#x")).toBe(false);
    expect(isLoopbackRedirectUri("http://u:p@localhost/cb")).toBe(false);
    expect(isLoopbackRedirectUri("ftp://localhost/cb")).toBe(false);
    expect(isLoopbackRedirectUri("garbage")).toBe(false);
  });

  it("isLoopbackBindHost", () => {
    for (const host of ["127.0.0.1", "127.1.2.3", "localhost", "::1"]) expect(isLoopbackBindHost(host), host).toBe(true);
    for (const host of ["0.0.0.0", "::", "10.0.0.1", "example.com", "127.0.0.1.evil.com", "[::1]"]) expect(isLoopbackBindHost(host), host).toBe(false);
  });
});

describe("loadHttpConfig: MCP_S3_OAUTH_DYNAMIC_REGISTRATION", () => {
  it("false without a static client is rejected (no client could log in)", () => {
    expectIssueFor({ MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "false" }, "MCP_S3_OAUTH_DYNAMIC_REGISTRATION");
  });

  it("false with a static client is accepted", () => {
    const config = load({
      MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "false",
      MCP_S3_OAUTH_CLIENT_ID: "c",
      MCP_S3_OAUTH_CLIENT_SECRET: SECRET_32,
    });
    expect(config.dynamicRegistration).toBe(false);
    expect(config.staticClient?.id).toBe("c");
  });

  it("accepts true explicitly and rejects non-boolean values", () => {
    expect(load({ MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "true" }).dynamicRegistration).toBe(true);
    expectIssueFor({ MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "maybe" }, "MCP_S3_OAUTH_DYNAMIC_REGISTRATION");
  });
});

describe("loadHttpConfig: MCP_S3_TRUST_PROXY", () => {
  it.each(["0", "1", "2", "10"])("accepts %s hops", (value) => {
    expect(load({ MCP_S3_TRUST_PROXY: value }).trustProxyHops).toBe(Number(value));
  });

  it.each(["11", "99", "-1", "abc", "1.5", "true", "100"])("rejects %j", (value) => {
    expectIssueFor({ MCP_S3_TRUST_PROXY: value }, "MCP_S3_TRUST_PROXY");
  });
});

describe("loadHttpConfig: multiple problems", () => {
  it("reports all of them at once", () => {
    const err = configError({
      MCP_S3_AUTH_PASSWORD: "short",
      MCP_S3_HTTP_PORT: "0",
      MCP_S3_TRUST_PROXY: "50",
    });
    expect(err.issues.length).toBeGreaterThanOrEqual(4);
    expect(err.message).toContain("MCP_S3_HTTP_PORT");
    expect(err.message).toContain("MCP_S3_TRUST_PROXY");
  });
});
