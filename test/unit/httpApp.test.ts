import { randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { HTTP_BUCKET, PUBLIC_ORIGIN, quietServer, startApp, type AppOptions, type RunningApp } from "../helpers/httpApp.js";
import { LEAK_CONTENT, SECRET_CONTENT } from "../helpers/fixtures.js";
import {
  ADMIN_PASSWORD,
  ADMIN_USERNAME,
  CLAUDE_REDIRECT,
  LOOPBACK_REDIRECT,
  pkce,
  STATIC_CLIENT_ID,
  STATIC_CLIENT_SECRET,
  str,
  toolText,
} from "../helpers/oauth.js";

const DAY = 24 * 3600;

let restoreQuiet: () => void;
beforeAll(() => {
  restoreQuiet = quietServer();
});
afterAll(() => {
  restoreQuiet();
});

const running: RunningApp[] = [];
async function app(opts: AppOptions = {}): Promise<RunningApp> {
  const a = await startApp(opts);
  running.push(a);
  return a;
}
afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(running.splice(0).map((a) => a.close()));
});

/** Register a public loopback client and return its id. */
async function publicClient(a: RunningApp): Promise<string> {
  const reg = await a.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT], token_endpoint_auth_method: "none" });
  expect(reg.status).toBe(201);
  return str(reg.json.client_id);
}

/** Register a confidential client with the claude.ai callback. */
async function confidentialClient(a: RunningApp): Promise<{ id: string; secret: string }> {
  const reg = await a.oauth.register({ redirect_uris: [CLAUDE_REDIRECT], client_name: "Claude" });
  expect(reg.status).toBe(201);
  return { id: str(reg.json.client_id), secret: str(reg.json.client_secret) };
}

function basicHeader(id: string, secret: string): Record<string, string> {
  return { authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}` };
}

function rawRequest(base: string, path: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, base);
    const req = httpRequest({ host: url.hostname, port: url.port, path: url.pathname, method: "GET", headers }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => (body += chunk));
      res.on("end", () => {
        resolve({ status: res.statusCode ?? 0, body });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------

describe("dynamic client registration", () => {
  it("registers a public loopback client (201, no secret)", async () => {
    const a = await app();
    const reg = await a.oauth.register({
      redirect_uris: [LOOPBACK_REDIRECT],
      token_endpoint_auth_method: "none",
      client_name: "Smoke",
    });
    expect(reg.status).toBe(201);
    expect(typeof reg.json.client_id).toBe("string");
    expect(reg.json).not.toHaveProperty("client_secret");
    expect(reg.json.redirect_uris).toEqual([LOOPBACK_REDIRECT]);
  });

  it("registers a confidential claude.ai client with a secret that does not expire", async () => {
    const a = await app();
    const reg = await a.oauth.register({ redirect_uris: [CLAUDE_REDIRECT], client_name: "Claude" });
    expect(reg.status).toBe(201);
    expect(typeof reg.json.client_secret).toBe("string");
    expect(reg.json.client_secret_expires_at).toBe(0);
  });

  it("the default allowlist has only the claude.ai callback (claude.com is rejected)", async () => {
    const a = await app();
    const reg = await a.oauth.register({ redirect_uris: ["https://claude.com/api/mcp/auth_callback"] });
    expect(reg.status).toBe(400);
    expect(reg.json.error).toBe("invalid_redirect_uri");
  });

  it.each([
    ["https://evil.example/cb"],
    ["http://evil.example/cb"],
    ["https://claude.ai/api/mcp/auth_callback/extra"],
    ["https://claude.ai.evil.example/api/mcp/auth_callback"],
    ["http://localhost.evil.example/cb"],
    ["https://claude.ai/api/mcp/auth_callback#frag"],
  ])("rejects the redirect URI %s with invalid_redirect_uri", async (uri) => {
    const a = await app();
    const reg = await a.oauth.register({ redirect_uris: [uri] });
    expect(reg.status).toBe(400);
    expect(reg.json.error).toBe("invalid_redirect_uri");
  });

  it("rejects a javascript: redirect URI", async () => {
    const a = await app();
    const reg = await a.oauth.register({ redirect_uris: ["javascript:alert(1)"] });
    expect(reg.status).toBe(400);
    expect(["invalid_redirect_uri", "invalid_client_metadata"]).toContain(reg.json.error);
  });

  it("rejects when one of several URIs is not allowed", async () => {
    const a = await app();
    const reg = await a.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT, "https://evil.example/cb"] });
    expect(reg.status).toBe(400);
  });

  it("limits the number of redirect URIs", async () => {
    const a = await app();
    const uris = Array.from({ length: 6 }, (_, i) => `http://localhost:${String(9000 + i)}/cb`);
    expect((await a.oauth.register({ redirect_uris: uris })).status).toBe(400);
  });

  it("rejects unsupported grant types and auth methods", async () => {
    const a = await app();
    expect((await a.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT], grant_types: ["client_credentials"] })).status).toBe(400);
    expect((await a.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT], token_endpoint_auth_method: "private_key_jwt" })).status).toBe(400);
  });

  it("is disabled (404) when MCP_S3_OAUTH_DYNAMIC_REGISTRATION=false, and the metadata has no registration_endpoint", async () => {
    const a = await app({ staticClient: true, env: { MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "false" } });
    const res = await fetch(`${a.base}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: [LOOPBACK_REDIRECT] }),
    });
    expect(res.status).toBe(404);
    const meta = (await (await fetch(`${a.base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    expect(meta).not.toHaveProperty("registration_endpoint");
  });

  it("with DCR disabled a previously issued dynamic client_id is no longer accepted, the static client still works", async () => {
    const key = randomBytes(32).toString("base64");
    const enabled = await app({ tokenKey: key, staticClient: true });
    const dynamicId = await publicClient(enabled);
    const disabled = await app({ tokenKey: key, staticClient: true, env: { MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "false" } });
    const old = await disabled.oauth.authorize(dynamicId, LOOPBACK_REDIRECT, pkce().challenge);
    expect(old.res.status).toBe(400);
    const fixed = await disabled.oauth.authorize(STATIC_CLIENT_ID, CLAUDE_REDIRECT, pkce().challenge);
    expect(fixed.res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------

describe("metadata and plumbing", () => {
  it("serves authorization server metadata for the public origin", async () => {
    const a = await app();
    const res = await fetch(`${a.base}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const meta = (await res.json()) as Record<string, unknown>;
    expect(meta.issuer).toBe(`${PUBLIC_ORIGIN}/`);
    expect(meta.authorization_endpoint).toBe(`${PUBLIC_ORIGIN}/authorize`);
    expect(meta.token_endpoint).toBe(`${PUBLIC_ORIGIN}/token`);
    expect(meta.registration_endpoint).toBe(`${PUBLIC_ORIGIN}/register`);
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
    expect(meta.scopes_supported).toEqual(["read"]);
    expect(meta.response_types_supported).toEqual(["code"]);
  });

  it("serves protected resource metadata at the root and the /mcp path", async () => {
    const a = await app();
    for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
      const res = await fetch(`${a.base}${path}`);
      expect(res.status, path).toBe(200);
      const meta = (await res.json()) as Record<string, unknown>;
      expect(meta.resource, path).toBe(`${PUBLIC_ORIGIN}/mcp`);
      expect(meta.authorization_servers, path).toEqual([`${PUBLIC_ORIGIN}/`]);
    }
  });

  it("/healthz is open and has no details", async () => {
    const a = await app();
    const res = await fetch(`${a.base}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("sets security headers and hides Express", async () => {
    const a = await app();
    const res = await fetch(`${a.base}/healthz`);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("x-powered-by")).toBeNull();
  });

  it("answers unknown paths with a bare 404", async () => {
    const a = await app();
    const res = await fetch(`${a.base}/admin`);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
  });

  it("rejects a foreign Host header (DNS rebinding) with 403", async () => {
    const a = await app();
    const evil = await rawRequest(a.base, "/healthz", { host: "evil.example.com" });
    expect(evil.status).toBe(403);
    const evilPort = await rawRequest(a.base, "/.well-known/oauth-authorization-server", { host: "attacker.test:3000" });
    expect(evilPort.status).toBe(403);
    const ok = await rawRequest(a.base, "/healthz", { host: "localhost:1234" });
    expect(ok.status).toBe(200);
  });

  it("accepts the public host name in the Host header", async () => {
    const a = await app({ origin: "https://mcp.example.com" });
    expect((await rawRequest(a.base, "/healthz", { host: "mcp.example.com" })).status).toBe(200);
    expect((await rawRequest(a.base, "/healthz", { host: "other.example.com" })).status).toBe(403);
  });

  it("the error handler returns generic JSON without a stack trace or parser message", async () => {
    const a = await app();
    const res = await fetch(`${a.base}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"redirect_uris": [',
    });
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).not.toMatch(/SyntaxError|node_modules|\bat\s+\S+\s+\(|stack|Unexpected|JSON\.parse/i);
    expect(text).not.toContain(process.cwd());
    expect(res.headers.get("cache-control")).toBe("no-store");

    const big = await fetch(`${a.base}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `x=${"a".repeat(64 * 1024)}`,
    });
    expect(big.status).toBe(413);
    const bigText = await big.text();
    expect(bigText).not.toMatch(/PayloadTooLarge|node_modules|stack/i);
    expect(JSON.parse(bigText)).toEqual({ error: "invalid_request", error_description: "Malformed request" });
  });
});

// ---------------------------------------------------------------------------

describe("authorize and login page", () => {
  async function dcrClientWithEvilName(a: RunningApp): Promise<string> {
    const reg = await a.oauth.register({
      redirect_uris: ["http://localhost:9999/callback"],
      token_endpoint_auth_method: "none",
      client_name: "<script>alert(1)</script> Smoke\u0007",
    });
    return str(reg.json.client_id);
  }

  it("renders the login page with escaped client name and the security headers", async () => {
    const a = await app();
    const id = await dcrClientWithEvilName(a);
    const page = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(page.res.status).toBe(200);
    expect(page.request).toBeTruthy();
    expect(page.csrf).toBeTruthy();
    expect(page.html).toContain("&lt;script&gt;alert(1)&lt;/script&gt; Smoke");
    expect(page.html).not.toContain("<script>");
    expect(page.html).not.toContain("\u0007");

    const csp = page.res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("form-action 'self' http://localhost:9999");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).not.toContain("unsafe-inline");
    expect(page.res.headers.get("x-frame-options")).toBe("DENY");
    expect(page.res.headers.get("cache-control")).toBe("no-store");
    expect(page.res.headers.get("referrer-policy")).toBe("same-origin");
    expect(page.html).toContain('<meta name="referrer" content="same-origin">');
    expect(page.res.headers.get("content-type")).toMatch(/^text\/html/);
  });

  it("sets an HttpOnly, SameSite=Lax CSRF cookie (Secure only for an https public URL)", async () => {
    const a = await app();
    const id = await publicClient(a);
    const cookie = (await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge)).res.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/^mcp_s3_login_csrf=[A-Za-z0-9_-]{43};/);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
    expect(cookie).toMatch(/Max-Age=\d+/);
    expect(cookie).not.toContain("Secure");

    const https = await app({ origin: "https://mcp.example.com" });
    const id2 = await publicClient(https);
    const cookie2 = (await https.oauth.authorize(id2, LOOPBACK_REDIRECT, pkce().challenge)).res.headers.get("set-cookie") ?? "";
    expect(cookie2).toContain("; Secure");
  });

  it("the page never contains the bucket, the root prefix, or the admin password", async () => {
    const a = await app();
    const id = await publicClient(a);
    const page = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(page.html).not.toContain(HTTP_BUCKET);
    expect(page.html).not.toContain("claude-workspace");
    expect(page.html).not.toContain(ADMIN_PASSWORD);
  });

  it("refuses an unregistered client_id without redirecting", async () => {
    const a = await app();
    const res = await a.oauth.authorize("not-a-client", LOOPBACK_REDIRECT, pkce().challenge);
    expect(res.res.status).toBe(400);
    expect(res.res.headers.get("location")).toBeNull();
    expect(res.request).toBeUndefined();
  });

  it("refuses a redirect URI that is not registered for the client without redirecting", async () => {
    const a = await app();
    const id = await publicClient(a);
    const res = await a.oauth.authorize(id, "https://evil.example/cb", pkce().challenge);
    expect(res.res.status).toBe(400);
    expect(res.res.headers.get("location")).toBeNull();
  });

  it("requires PKCE with S256", async () => {
    const a = await app();
    const id = await publicClient(a);
    const plain = await a.oauth.authorize(id, LOOPBACK_REDIRECT, "x".repeat(43), { code_challenge_method: "plain" });
    expect(plain.res.status).not.toBe(200);
    expect(plain.request).toBeUndefined();
    const noChallenge = await a.oauth.authorize(id, LOOPBACK_REDIRECT, "");
    expect(noChallenge.res.status).not.toBe(200);
    const bogus = await a.oauth.authorize(id, LOOPBACK_REDIRECT, "short");
    expect(bogus.request).toBeUndefined();
  });

  it("answers a resource that is not this server with invalid_target (redirect)", async () => {
    const a = await app();
    const id = await publicClient(a);
    const res = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge, { resource: "https://other.example/mcp" });
    expect(res.res.status).toBe(302);
    const location = new URL(res.res.headers.get("location") ?? "http://invalid/");
    expect(location.origin).toBe("http://localhost:9999");
    expect(location.searchParams.get("error")).toBe("invalid_target");
    expect(location.searchParams.get("state")).toBe('st<>"ate');
  });

  it("accepts the public origin and the /mcp URL (with or without a trailing slash) as resource", async () => {
    const a = await app();
    const id = await publicClient(a);
    for (const resource of [`${PUBLIC_ORIGIN}/mcp`, `${PUBLIC_ORIGIN}/mcp/`, PUBLIC_ORIGIN, `${PUBLIC_ORIGIN}/`]) {
      const res = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge, { resource });
      expect(res.res.status, resource).toBe(200);
    }
  });
});

// ---------------------------------------------------------------------------

describe("POST /login", () => {
  async function page(a: RunningApp) {
    const id = await publicClient(a);
    return { id, form: await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge) };
  }

  it("wrong password: 401 login page, password not reflected, username escaped, no redirect", async () => {
    const a = await app();
    const { form } = await page(a);
    const res = await a.oauth.login(form, '"><b>x</b>', "wrong-password-123");
    const html = await res.text();
    expect(res.status).toBe(401);
    expect(res.headers.get("location")).toBeNull();
    expect(html).toContain("Invalid username or password");
    expect(html).not.toContain("wrong-password-123");
    expect(html).not.toContain("<b>x</b>");
    expect(html).toContain("&lt;b&gt;x&lt;/b&gt;");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    // The form can be submitted again with the same CSRF values.
    expect(hiddenCount(html)).toBe(2);
  });

  it("wrong username with the right password: 401", async () => {
    const a = await app();
    const { form } = await page(a);
    expect((await a.oauth.login(form, "root", ADMIN_PASSWORD)).status).toBe(401);
  });

  it("success: 303 to the redirect URI with code and the original state", async () => {
    const a = await app();
    const { form } = await page(a);
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(res.status).toBe(303);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const location = new URL(res.headers.get("location") ?? "http://invalid/");
    expect(location.origin + location.pathname).toBe(LOOPBACK_REDIRECT);
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe('st<>"ate');
  });

  it("refuses a cross-origin Origin header (403) even with the right password", async () => {
    const a = await app();
    const { form } = await page(a);
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, { origin: "https://evil.example" });
    expect(res.status).toBe(403);
    expect(res.headers.get("location")).toBeNull();
  });

  it.each(["cross-site", "same-site", "none"])("refuses Sec-Fetch-Site: %s (403)", async (value) => {
    const a = await app();
    const { form } = await page(a);
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, { "sec-fetch-site": value });
    expect(res.status).toBe(403);
  });

  it("accepts Sec-Fetch-Site: same-origin", async () => {
    const a = await app();
    const { form } = await page(a);
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, { "sec-fetch-site": "same-origin" });
    expect(res.status).toBe(303);
  });

  it("refuses a request without the CSRF cookie (403)", async () => {
    const a = await app();
    const { form } = await page(a);
    const res = await a.oauth.login({ ...form, cookie: "" }, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(res.status).toBe(403);
  });

  it("refuses a broken CSRF field (403)", async () => {
    const a = await app();
    const { form } = await page(a);
    const csrf = form.csrf ?? "";
    for (const broken of [csrf.slice(0, -2) + "AA", "", "x", csrf + "x"]) {
      expect((await a.oauth.login({ ...form, csrf: broken }, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(403);
    }
  });

  it("refuses a CSRF field and cookie that belong to different pages (403)", async () => {
    const a = await app();
    const id = await publicClient(a);
    const one = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const two = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(one.cookie).not.toBe(two.cookie);
    const res = await a.oauth.login({ request: one.request, csrf: one.csrf, cookie: two.cookie }, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(res.status).toBe(403);
    // CSRF bound to the request: a valid csrf for page one does not authorize page two's request.
    const mixed = await a.oauth.login({ request: two.request, csrf: one.csrf, cookie: one.cookie }, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(mixed.status).toBe(403);
  });

  it("refuses a tampered or missing request field (403)", async () => {
    const a = await app();
    const { form } = await page(a);
    const request = form.request ?? "";
    const tampered = (request.startsWith("A") ? "B" : "A") + request.slice(1);
    expect((await a.oauth.login({ ...form, request: tampered }, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(403);
    expect((await a.oauth.login({ ...form, request: "" }, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(403);
  });

  it("refuses a login request that expired (10 minutes)", async () => {
    const a = await app();
    const { form } = await page(a);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 10 * 60 * 1000 + 1000);
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(res.status).toBe(403);
  });

  it("refuses a form missing fields (403)", async () => {
    const a = await app();
    const res = await fetch(`${a.base}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: a.origin },
      body: new URLSearchParams({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD }),
    });
    expect(res.status).toBe(403);
  });

  it("does not accept GET /login", async () => {
    const a = await app();
    expect((await fetch(`${a.base}/login`)).status).toBe(404);
  });
});

function hiddenCount(html: string): number {
  return (html.match(/<input type="hidden"/g) ?? []).length;
}

// ---------------------------------------------------------------------------

describe("login rate limit", () => {
  async function failures(a: RunningApp, count: number, headers: Record<string, string> = {}): Promise<number[]> {
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const statuses: number[] = [];
    for (let i = 0; i < count; i++) statuses.push((await a.oauth.login(form, ADMIN_USERNAME, "nope-nope-nope", headers)).status);
    return statuses;
  }

  it("the 6th attempt gets 429 with Retry-After, even with the correct password", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) statuses.push((await a.oauth.login(form, ADMIN_USERNAME, "nope-nope-nope")).status);
    expect(statuses).toEqual([401, 401, 401, 401, 401]);

    const limited = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(limited.status).toBe(429);
    const retry = Number(limited.headers.get("retry-after"));
    expect(retry).toBeGreaterThan(0);
    expect(retry).toBeLessThanOrEqual(15 * 60);
    expect(limited.headers.get("location")).toBeNull();
    expect(await limited.text()).not.toContain(ADMIN_PASSWORD);
  });

  it("the block ends after 15 minutes", async () => {
    const a = await app();
    await failures(a, 5);
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect((await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(429);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 15 * 60 * 1000 + 1000);
    const fresh = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect((await a.oauth.login(fresh, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(303);
  });

  it("4 failures then a success does not block", async () => {
    const a = await app();
    expect(await failures(a, 4)).toEqual([401, 401, 401, 401]);
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect((await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(303);
    expect(await failures(a, 4)).toEqual([401, 401, 401, 401]);
  });

  it("ignores X-Forwarded-For when no proxy is trusted (cannot be used to evade the limit)", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    for (let i = 0; i < 5; i++) await a.oauth.login(form, ADMIN_USERNAME, "nope-nope-nope", { "x-forwarded-for": `9.9.9.${String(i)}` });
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, { "x-forwarded-for": "8.8.8.8" });
    expect(res.status).toBe(429);
  });

  it("with MCP_S3_TRUST_PROXY=1 the limit is per forwarded client IP", async () => {
    const a = await app({ env: { MCP_S3_TRUST_PROXY: "1" } });
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    for (let i = 0; i < 5; i++) await a.oauth.login(form, ADMIN_USERNAME, "nope-nope-nope", { "x-forwarded-for": "1.1.1.1" });
    expect((await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, { "x-forwarded-for": "1.1.1.1" })).status).toBe(429);
    expect((await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, { "x-forwarded-for": "2.2.2.2" })).status).toBe(303);
  });

  it("CSRF and origin failures do not count as failed logins", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    for (let i = 0; i < 10; i++) await a.oauth.login({ ...form, cookie: "" }, ADMIN_USERNAME, "nope-nope-nope");
    expect((await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(303);
  });
});

// ---------------------------------------------------------------------------

describe("token endpoint", () => {
  it("rejects a wrong PKCE verifier (invalid_grant), and the code still works afterwards", async () => {
    const a = await app();
    const id = await publicClient(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    const bad = await a.oauth.token({
      grant_type: "authorization_code",
      code,
      code_verifier: pkce().verifier,
      client_id: id,
      redirect_uri: LOOPBACK_REDIRECT,
    });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toBe("invalid_grant");
    const good = await a.oauth.token({ grant_type: "authorization_code", code, code_verifier: k.verifier, client_id: id, redirect_uri: LOOPBACK_REDIRECT });
    expect(good.status).toBe(200);
  });

  it("issues Bearer tokens with scope read and a one hour access token", async () => {
    const a = await app();
    const id = await publicClient(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    const t = await a.oauth.token({
      grant_type: "authorization_code",
      code,
      code_verifier: k.verifier,
      client_id: id,
      redirect_uri: LOOPBACK_REDIRECT,
      resource: a.oauth.resource,
    });
    expect(t.status).toBe(200);
    expect(t.json.token_type).toBe("Bearer");
    expect(t.json.scope).toBe("read");
    expect(t.json.expires_in).toBe(3600);
    expect(typeof t.json.access_token).toBe("string");
    expect(typeof t.json.refresh_token).toBe("string");
    expect(t.headers.get("cache-control")).toBe("no-store");
    expect(t.json.access_token).not.toBe(t.json.refresh_token);
  });

  it("rejects a replayed authorization code", async () => {
    const a = await app();
    const id = await publicClient(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    const params = { grant_type: "authorization_code", code, code_verifier: k.verifier, client_id: id, redirect_uri: LOOPBACK_REDIRECT };
    expect((await a.oauth.token(params)).status).toBe(200);
    const replay = await a.oauth.token(params);
    expect(replay.status).toBe(400);
    expect(replay.json.error).toBe("invalid_grant");
  });

  it("rejects a redirect_uri that differs from the authorization request", async () => {
    const a = await app();
    const reg = await a.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT, "http://localhost:9999/other"], token_endpoint_auth_method: "none" });
    const id = str(reg.json.client_id);
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    const t = await a.oauth.token({ grant_type: "authorization_code", code, code_verifier: k.verifier, client_id: id, redirect_uri: "http://localhost:9999/other" });
    expect(t.status).toBe(400);
    expect(t.json.error).toBe("invalid_grant");
  });

  it("rejects a code presented by another client", async () => {
    const a = await app();
    const id = await publicClient(a);
    const other = await publicClient(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    const t = await a.oauth.token({ grant_type: "authorization_code", code, code_verifier: k.verifier, client_id: other, redirect_uri: LOOPBACK_REDIRECT });
    expect(t.status).toBe(400);
    expect(t.json.error).toBe("invalid_grant");
  });

  it("rejects an authorization code after 2 minutes", async () => {
    const a = await app();
    const id = await publicClient(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 121_000);
    const t = await a.oauth.token({ grant_type: "authorization_code", code, code_verifier: k.verifier, client_id: id, redirect_uri: LOOPBACK_REDIRECT });
    expect(t.status).toBe(400);
  });

  it("rejects a foreign resource at the token endpoint with invalid_target", async () => {
    const a = await app();
    const id = await publicClient(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    const t = await a.oauth.token({
      grant_type: "authorization_code",
      code,
      code_verifier: k.verifier,
      client_id: id,
      redirect_uri: LOOPBACK_REDIRECT,
      resource: "https://other.example/mcp",
    });
    expect(t.status).toBe(400);
    expect(t.json.error).toBe("invalid_target");
  });

  it("rejects garbage codes and unsupported grant types", async () => {
    const a = await app();
    const id = await publicClient(a);
    const garbage = await a.oauth.token({ grant_type: "authorization_code", code: "garbage", code_verifier: pkce().verifier, client_id: id });
    expect(garbage.status).toBe(400);
    const cc = await a.oauth.token({ grant_type: "client_credentials", client_id: id });
    expect(cc.status).toBe(400);
  });

  it("rotates refresh tokens: new one works, the old one is rejected", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t1 = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const r1 = await a.oauth.token({ grant_type: "refresh_token", refresh_token: t1.refresh, client_id: id });
    expect(r1.status).toBe(200);
    expect(r1.json.refresh_token).toBeTruthy();
    expect(r1.json.refresh_token).not.toBe(t1.refresh);
    expect(r1.json.access_token).not.toBe(t1.access);

    const again = await a.oauth.token({ grant_type: "refresh_token", refresh_token: t1.refresh, client_id: id });
    expect(again.status).toBe(400);
    expect(again.json.error).toBe("invalid_grant");

    const r2 = await a.oauth.token({ grant_type: "refresh_token", refresh_token: str(r1.json.refresh_token), client_id: id });
    expect(r2.status).toBe(200);
  });

  it("rejects a refresh token presented by another client", async () => {
    const a = await app();
    const id = await publicClient(a);
    const other = await confidentialClient(a);
    const t1 = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const res = await a.oauth.token({
      grant_type: "refresh_token",
      refresh_token: t1.refresh,
      client_id: other.id,
      client_secret: other.secret,
    });
    expect(res.status).toBe(400);
    expect(res.json.error).toBe("invalid_grant");
    // The owner can still use it: the failed attempt did not burn it.
    expect((await a.oauth.token({ grant_type: "refresh_token", refresh_token: t1.refresh, client_id: id })).status).toBe(200);
  });

  it("a refresh token cannot widen the scope", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t1 = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const res = await a.oauth.token({ grant_type: "refresh_token", refresh_token: t1.refresh, client_id: id, scope: "read write" });
    expect(res.status).toBe(400);
  });

  it("access tokens last one hour", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    expect((await a.oauth.mcp(t.access, "tools/list")).status).toBe(200);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 3599_000);
    expect((await a.oauth.mcp(t.access, "tools/list")).status).toBe(200);
    vi.setSystemTime(Date.now() + 2_000);
    const expired = await a.oauth.mcp(t.access, "tools/list");
    expect(expired.status).toBe(401);
    expect(expired.headers.get("www-authenticate")).toContain("invalid_token");
  });

  it("refresh tokens last 7 days, slide on use, and never outlive 90 days after the login", async () => {
    const a = await app();
    const id = await publicClient(a);
    const refreshWith = (token: string) => a.oauth.token({ grant_type: "refresh_token", refresh_token: token, client_id: id });
    vi.useFakeTimers({ toFake: ["Date"] });

    // Not used for 8 days: gone. Used after 6 days: still valid.
    let start = Date.now();
    let login = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    vi.setSystemTime(start + 8 * DAY * 1000);
    expect((await refreshWith(login.refresh)).status).toBe(400);
    vi.setSystemTime(start);
    start = Date.now();
    login = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    vi.setSystemTime(start + 6 * DAY * 1000);
    expect((await refreshWith(login.refresh)).status).toBe(200);
    vi.setSystemTime(start);

    // Used every 6 days it keeps working until the 90 day cap (day 84 is the 14th refresh).
    const walk = async (): Promise<string> => {
      vi.setSystemTime(start);
      let refresh = login.refresh;
      for (let day = 6; day <= 84; day += 6) {
        vi.setSystemTime(start + day * DAY * 1000);
        const res = await refreshWith(refresh);
        expect(res.status, `day ${String(day)}`).toBe(200);
        refresh = str(res.json.refresh_token);
      }
      return refresh;
    };
    vi.setSystemTime(Date.now());
    start = Date.now();
    login = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const lastRefresh = await walk();

    // The token issued on day 84 is only valid until day 90.
    vi.setSystemTime(start + 91 * DAY * 1000);
    expect((await refreshWith(lastRefresh)).status).toBe(400);

    // Close to the cap (less than the access token lifetime left): access token, no new refresh token.
    start = Date.now();
    login = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const again = await walk();
    vi.setSystemTime(start + 89.99 * DAY * 1000);
    const last = await refreshWith(again);
    expect(last.status).toBe(200);
    expect(last.json.access_token).toBeTruthy();
    expect(last.json).not.toHaveProperty("refresh_token");
  });

  it("revoking an access token makes it 401 and returns 200 to the client", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const rev = await fetch(`${a.base}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: t.access, client_id: id }),
    });
    expect(rev.status).toBe(200);
    const after = await a.oauth.mcp(t.access, "tools/list");
    expect(after.status).toBe(401);
    expect(after.headers.get("www-authenticate")).toContain("invalid_token");
  });

  it("revoking a refresh token makes it unusable", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    await fetch(`${a.base}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: t.refresh, client_id: id }),
    });
    const res = await a.oauth.token({ grant_type: "refresh_token", refresh_token: t.refresh, client_id: id });
    expect(res.status).toBe(400);
  });

  it("another client cannot revoke a token it does not own (still 200, token keeps working)", async () => {
    const a = await app();
    const id = await publicClient(a);
    const other = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const rev = await fetch(`${a.base}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: t.access, client_id: other }),
    });
    expect(rev.status).toBe(200);
    expect((await a.oauth.mcp(t.access, "tools/list")).status).toBe(200);
  });

  it("revoking garbage is accepted (RFC 7009)", async () => {
    const a = await app();
    const id = await publicClient(a);
    const rev = await fetch(`${a.base}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "garbage", client_id: id }),
    });
    expect(rev.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------

describe("confidential clients (dynamic and static)", () => {
  it("a dynamically registered confidential client must present its secret", async () => {
    const a = await app();
    const c = await confidentialClient(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(c.id, CLAUDE_REDIRECT, k.challenge);
    const params = { grant_type: "authorization_code", code, code_verifier: k.verifier, redirect_uri: CLAUDE_REDIRECT };
    // A missing secret is answered by the SDK itself (400 invalid_request).
    const noSecret = await a.oauth.token({ ...params, client_id: c.id });
    expect([400, 401]).toContain(noSecret.status);
    expect(["invalid_request", "invalid_client"]).toContain(noSecret.json.error);
    const wrong = await a.oauth.token({ ...params, client_id: c.id, client_secret: "x".repeat(c.secret.length) });
    expect(wrong.status).toBe(401);
    expect(wrong.json.error).toBe("invalid_client");
    const ok = await a.oauth.token({ ...params, client_id: c.id, client_secret: c.secret });
    expect(ok.status).toBe(200);
  });

  it("client secrets are never reflected in error responses", async () => {
    const a = await app();
    const c = await confidentialClient(a);
    const res = await fetch(`${a.base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: "x", client_id: c.id, client_secret: "reflect-me-please" }),
    });
    expect(await res.text()).not.toContain("reflect-me-please");
  });

  describe("static client", () => {
    async function staticCode(a: RunningApp): Promise<{ code: string; verifier: string }> {
      const k = pkce();
      return { code: await a.oauth.obtainCode(STATIC_CLIENT_ID, CLAUDE_REDIRECT, k.challenge), verifier: k.verifier };
    }

    it("shows the login page for the claude.ai callback and shows the target origin", async () => {
      const a = await app({ staticClient: true });
      const page = await a.oauth.authorize(STATIC_CLIENT_ID, CLAUDE_REDIRECT, pkce().challenge);
      expect(page.res.status).toBe(200);
      expect(page.html).toContain("https://claude.ai");
      expect(page.res.headers.get("content-security-policy")).toContain("form-action 'self' https://claude.ai");
    });

    it("exchanges a code with HTTP Basic authentication", async () => {
      const a = await app({ staticClient: true });
      const { code, verifier } = await staticCode(a);
      const t = await a.oauth.token(
        { grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: CLAUDE_REDIRECT },
        basicHeader(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET),
      );
      expect(t.status).toBe(200);
      expect(t.json.access_token).toBeTruthy();
      expect((await a.oauth.mcp(str(t.json.access_token), "tools/list")).status).toBe(200);
    });

    it("exchanges a code with client_secret_post", async () => {
      const a = await app({ staticClient: true });
      const { code, verifier } = await staticCode(a);
      const t = await a.oauth.token({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        redirect_uri: CLAUDE_REDIRECT,
        client_id: STATIC_CLIENT_ID,
        client_secret: STATIC_CLIENT_SECRET,
      });
      expect(t.status).toBe(200);
    });

    it("refreshes with Basic authentication", async () => {
      const a = await app({ staticClient: true });
      const { code, verifier } = await staticCode(a);
      const first = await a.oauth.token(
        { grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: CLAUDE_REDIRECT },
        basicHeader(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET),
      );
      const refreshed = await a.oauth.token(
        { grant_type: "refresh_token", refresh_token: str(first.json.refresh_token) },
        basicHeader(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET),
      );
      expect(refreshed.status).toBe(200);
    });

    it("a wrong secret gets 401 invalid_client (Basic and post, any length)", async () => {
      const a = await app({ staticClient: true });
      const { code, verifier } = await staticCode(a);
      const base = { grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: CLAUDE_REDIRECT };

      const basic = await a.oauth.token(base, basicHeader(STATIC_CLIENT_ID, "x".repeat(64)));
      expect(basic.status).toBe(401);
      expect(basic.json.error).toBe("invalid_client");
      expect(basic.headers.get("www-authenticate")).toContain("Basic");

      for (const secret of ["short", "", "x".repeat(STATIC_CLIENT_SECRET.length), STATIC_CLIENT_SECRET + "x", STATIC_CLIENT_SECRET.slice(0, -1)]) {
        const post = await a.oauth.token({ ...base, client_id: STATIC_CLIENT_ID, client_secret: secret });
        expect(post.status, JSON.stringify(secret)).toBe(401);
      }
      // Rejections did not burn the code.
      const ok = await a.oauth.token(base, basicHeader(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET));
      expect(ok.status).toBe(200);
    });

    it("a missing secret for the static client is refused", async () => {
      const a = await app({ staticClient: true });
      const { code, verifier } = await staticCode(a);
      const res = await a.oauth.token({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: STATIC_CLIENT_ID, redirect_uri: CLAUDE_REDIRECT });
      expect([400, 401]).toContain(res.status);
      expect(["invalid_request", "invalid_client"]).toContain(res.json.error);
      expect(res.json).not.toHaveProperty("access_token");
    });

    it("refuses two client authentication methods at once, and malformed Basic headers", async () => {
      const a = await app({ staticClient: true });
      const { code, verifier } = await staticCode(a);
      const both = await a.oauth.token(
        { grant_type: "authorization_code", code, code_verifier: verifier, client_secret: STATIC_CLIENT_SECRET },
        basicHeader(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET),
      );
      expect(both.status).toBe(400);
      const mismatch = await a.oauth.token(
        { grant_type: "authorization_code", code, code_verifier: verifier, client_id: "someone-else" },
        basicHeader(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET),
      );
      expect(mismatch.status).toBe(400);
      const malformed = await a.oauth.token({ grant_type: "authorization_code", code, code_verifier: verifier }, { authorization: "Basic !!!" });
      expect(malformed.status).toBe(401);
    });

    it("refuses an unregistered redirect URI (400, no redirect), also loopback", async () => {
      const a = await app({ staticClient: true });
      for (const uri of ["https://evil.example/cb", LOOPBACK_REDIRECT]) {
        const res = await a.oauth.authorize(STATIC_CLIENT_ID, uri, pkce().challenge);
        expect(res.res.status, uri).toBe(400);
        expect(res.res.headers.get("location"), uri).toBeNull();
      }
    });

    it("MCP_S3_OAUTH_REDIRECT_URIS replaces the claude.ai defaults", async () => {
      const a = await app({ staticClient: true, env: { MCP_S3_OAUTH_REDIRECT_URIS: "https://mine.example/cb" } });
      expect((await a.oauth.authorize(STATIC_CLIENT_ID, "https://mine.example/cb", pkce().challenge)).res.status).toBe(200);
      expect((await a.oauth.authorize(STATIC_CLIENT_ID, CLAUDE_REDIRECT, pkce().challenge)).res.status).toBe(400);
      const reg = await a.oauth.register({ redirect_uris: [CLAUDE_REDIRECT] });
      expect(reg.status).toBe(400);
      // Loopback is always accepted for DCR.
      expect((await a.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT] })).status).toBe(201);
    });
  });
});

// ---------------------------------------------------------------------------

describe("/mcp", () => {
  it("without a token: 401 with WWW-Authenticate pointing at the resource metadata", async () => {
    const a = await app();
    const res = await a.oauth.mcp(undefined, "tools/list");
    expect(res.status).toBe(401);
    const www = res.headers.get("www-authenticate") ?? "";
    expect(www).toMatch(/^Bearer /);
    expect(www).toContain(`resource_metadata="${PUBLIC_ORIGIN}/.well-known/oauth-protected-resource/mcp"`);
  });

  it("with garbage or malformed Authorization headers: 401", async () => {
    const a = await app();
    expect((await a.oauth.mcp("garbage", "tools/list")).status).toBe(401);
    const basic = await fetch(`${a.base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Basic YTpi" },
      body: "{}",
    });
    expect(basic.status).toBe(401);
  });

  it("GET and DELETE with a valid token: 405 (stateless server); without a token: 401", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    for (const method of ["GET", "DELETE"]) {
      const res = await fetch(`${a.base}/mcp`, { method, headers: { authorization: `Bearer ${t.access}` } });
      expect(res.status, method).toBe(405);
      expect(res.headers.get("allow")).toContain("POST");
      const noToken = await fetch(`${a.base}/mcp`, { method });
      expect(noToken.status, method).toBe(401);
    }
  });

  it("answers CORS preflight without a token", async () => {
    const a = await app();
    const res = await fetch(`${a.base}/mcp`, { method: "OPTIONS", headers: { origin: "https://claude.ai", "access-control-request-method": "POST" } });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-headers")).toContain("Authorization");
  });

  it("initialize, then tools/list returns only the four read tools with read-only annotations", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const init = await a.oauth.mcp(t.access, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "unit", version: "0" },
    });
    expect(init.status).toBe(200);
    expect((init.json?.result as { serverInfo: { name: string } }).serverInfo.name).toBe("mcp-s3");

    const list = await a.oauth.mcp(t.access, "tools/list", {}, 2);
    expect(list.status).toBe(200);
    const tools = (list.json?.result as { tools: { name: string; annotations: Record<string, unknown> }[] }).tools;
    expect(tools.map((x) => x.name).sort()).toEqual(["get_object_info", "list_objects", "read_object", "search_objects"]);
    for (const tool of tools) {
      expect(tool.annotations).toEqual({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
    }
  });

  it("list_objects (recursive) returns only the root's files with relative paths", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const res = await a.oauth.callTool(t.access, "list_objects", { recursive: true });
    const { text, isError } = toolText(res);
    expect(isError).toBe(false);
    const listing = JSON.parse(text) as { files: { path: string }[] };
    expect(listing.files.map((f) => f.path).sort()).toEqual(["a.txt", "img.png", "sub/b.txt"]);
    for (const needle of ["leak", "claude-workspace", "outside", HTTP_BUCKET]) expect(text).not.toContain(needle);
  });

  it("read_object returns the text; traversal is refused and the secret never appears", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const ok = await a.oauth.callTool(t.access, "read_object", { path: "a.txt" });
    expect(toolText(ok).text).toBe("hello from smoke");

    for (const path of ["../claude-workspace-backup/leak.txt", "../outside/secret.txt", "sub/../../outside/secret.txt"]) {
      const res = await a.oauth.callTool(t.access, "read_object", { path });
      const tt = toolText(res);
      expect(tt.isError, path).toBe(true);
      expect(tt.text, path).toMatch(/PathOutsideRoot/);
      expect(res.text).not.toContain(SECRET_CONTENT);
      expect(res.text).not.toContain(LEAK_CONTENT);
    }
  });

  it("returns images as image content", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const res = await a.oauth.callTool(t.access, "read_object", { path: "img.png" });
    const content = (res.json?.result as { content: { type: string; mimeType?: string }[] }).content;
    expect(content[0]?.type).toBe("image");
    expect(content[0]?.mimeType).toBe("image/png");
  });

  it("there are no write or delete tools to call", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    for (const name of ["write_object", "delete_object", "move_object", "copy_object", "create_folder"]) {
      const res = await a.oauth.callTool(t.access, name, { path: "x.txt", content: "x" });
      expect(toolText(res).isError || res.json?.error !== undefined, name).toBe(true);
    }
    expect(a.fake.objects.has("claude-workspace/x.txt")).toBe(false);
  });

  describe("only access tokens work as bearer tokens", () => {
    it("refresh token, authorization code, and next_token are rejected (401)", async () => {
      const a = await app();
      const id = await publicClient(a);
      const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
      const listing = toolText(await a.oauth.callTool(t.access, "list_objects", { recursive: true, max_keys: 1 }));
      const nextToken = (JSON.parse(listing.text) as { next_token: string | null }).next_token;
      expect(nextToken).toBeTruthy();

      for (const [name, value] of [
        ["refresh token", t.refresh],
        ["authorization code", t.code],
        ["next_token", str(nextToken)],
      ] as const) {
        const res = await a.oauth.mcp(value, "tools/list");
        expect(res.status, name).toBe(401);
      }
      // The access token still works.
      expect((await a.oauth.mcp(t.access, "tools/list")).status).toBe(200);
    });

    it("a login request and a dynamic client_id are rejected as bearer tokens", async () => {
      const a = await app();
      const id = await publicClient(a);
      const page = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
      expect((await a.oauth.mcp(page.request, "tools/list")).status).toBe(401);
      expect((await a.oauth.mcp(id, "tools/list")).status).toBe(401);
    });

    it("an access token is rejected as continuation_token", async () => {
      const a = await app();
      const id = await publicClient(a);
      const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
      const res = await a.oauth.callTool(t.access, "list_objects", { continuation_token: t.access });
      expect(toolText(res).isError).toBe(true);
    });

    it("a real next_token still works as continuation_token", async () => {
      const a = await app();
      const id = await publicClient(a);
      const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
      const first = JSON.parse(toolText(await a.oauth.callTool(t.access, "list_objects", { recursive: true, max_keys: 1 })).text) as {
        files: { path: string }[];
        next_token: string;
      };
      const second = toolText(await a.oauth.callTool(t.access, "list_objects", { recursive: true, max_keys: 1, continuation_token: first.next_token }));
      expect(second.isError).toBe(false);
      expect((JSON.parse(second.text) as { files: { path: string }[] }).files[0]?.path).not.toBe(first.files[0]?.path);
    });
  });
});

// ---------------------------------------------------------------------------

describe("credential and key changes", () => {
  it("changing the admin password invalidates issued access and refresh tokens, but not registered clients", async () => {
    const key = randomBytes(32).toString("base64");
    const before = await app({ tokenKey: key });
    const id = await publicClient(before);
    const t = await before.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    expect((await before.oauth.mcp(t.access, "tools/list")).status).toBe(200);

    const after = await app({ tokenKey: key, env: { MCP_S3_AUTH_PASSWORD: "a-different-password-123" } });
    expect((await after.oauth.mcp(t.access, "tools/list")).status).toBe(401);
    const refresh = await after.oauth.token({ grant_type: "refresh_token", refresh_token: t.refresh, client_id: id });
    expect(refresh.status).toBe(400);
    // The client registration survives; the old password no longer logs in.
    const page = await after.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(page.res.status).toBe(200);
    expect((await after.oauth.login(page, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(401);
    expect((await after.oauth.login(page, ADMIN_USERNAME, "a-different-password-123")).status).toBe(303);
  });

  it("changing the admin username invalidates issued tokens too", async () => {
    const key = randomBytes(32).toString("base64");
    const before = await app({ tokenKey: key });
    const id = await publicClient(before);
    const t = await before.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const after = await app({ tokenKey: key, env: { MCP_S3_AUTH_USERNAME: "root" } });
    expect((await after.oauth.mcp(t.access, "tools/list")).status).toBe(401);
  });

  it("a restart with the same key and credentials keeps tokens and clients valid", async () => {
    const key = randomBytes(32).toString("base64");
    const before = await app({ tokenKey: key });
    const id = await publicClient(before);
    const t = await before.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const after = await app({ tokenKey: key });
    expect((await after.oauth.mcp(t.access, "tools/list")).status).toBe(200);
    expect((await after.oauth.token({ grant_type: "refresh_token", refresh_token: t.refresh, client_id: id })).status).toBe(200);
  });

  it("changing MCP_S3_TOKEN_KEY invalidates dynamic clients and tokens", async () => {
    const before = await app();
    const id = await publicClient(before);
    const t = await before.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const after = await app();
    expect(before.tokenKey).not.toBe(after.tokenKey);
    const page = await after.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(page.res.status).toBe(400);
    expect(page.request).toBeUndefined();
    expect((await after.oauth.mcp(t.access, "tools/list")).status).toBe(401);
  });

  it("a different public URL (issuer) is not needed to keep tokens valid across restarts, but the resource is bound", async () => {
    const key = randomBytes(32).toString("base64");
    const before = await app({ tokenKey: key });
    const id = await publicClient(before);
    const t = await before.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    // Same key and credentials, other origin: the token's resource no longer matches /mcp.
    const moved = await app({ tokenKey: key, origin: "https://mcp.example.com" });
    expect((await moved.oauth.mcp(t.access, "tools/list")).status).toBe(401);
  });
});
