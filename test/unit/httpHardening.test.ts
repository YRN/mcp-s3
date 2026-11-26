import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { quietServer, startApp, type AppOptions, type RunningApp } from "../helpers/httpApp.js";
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

async function publicClient(a: RunningApp, extra: Record<string, unknown> = {}): Promise<string> {
  const reg = await a.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT], token_endpoint_auth_method: "none", ...extra });
  expect(reg.status).toBe(201);
  return str(reg.json.client_id);
}

function basic(id: string, secret: string): Record<string, string> {
  return { authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}` };
}

const WRONG_SECRET = "w".repeat(STATIC_CLIENT_SECRET.length);

// ---------------------------------------------------------------------------

describe("rate limit on failed client authentication (/token, /revoke)", () => {
  async function wrongSecret(a: RunningApp, how: "post" | "basic" | "malformed" = "post"): Promise<number> {
    const params = { grant_type: "authorization_code", code: "x", code_verifier: pkce().verifier };
    if (how === "basic") return (await a.oauth.token(params, basic(STATIC_CLIENT_ID, WRONG_SECRET))).status;
    if (how === "malformed") return (await a.oauth.token(params, { authorization: "Basic !!!" })).status;
    return (await a.oauth.token({ ...params, client_id: STATIC_CLIENT_ID, client_secret: WRONG_SECRET })).status;
  }

  it("10 wrong secrets get 401, the 11th gets 429 with Retry-After and too_many_requests", async () => {
    const a = await app({ staticClient: true });
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) statuses.push(await wrongSecret(a));
    expect(statuses).toEqual(Array<number>(10).fill(401));

    const res = await a.oauth.token({ grant_type: "authorization_code", code: "x", code_verifier: pkce().verifier, client_id: STATIC_CLIENT_ID, client_secret: WRONG_SECRET });
    expect(res.status).toBe(429);
    expect(res.json.error).toBe("too_many_requests");
    const retry = Number(res.headers.get("retry-after"));
    expect(retry).toBeGreaterThan(0);
    expect(retry).toBeLessThanOrEqual(15 * 60);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("the correct secret is also refused while blocked, with Basic and with client_secret_post", async () => {
    const a = await app({ staticClient: true });
    for (let i = 0; i < 10; i++) await wrongSecret(a);
    const k = pkce();
    const base = { grant_type: "authorization_code", code: "x", code_verifier: k.verifier };
    const viaBasic = await a.oauth.token(base, basic(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET));
    expect(viaBasic.status).toBe(429);
    expect(viaBasic.headers.get("retry-after")).toBeTruthy();
    const viaPost = await a.oauth.token({ ...base, client_id: STATIC_CLIENT_ID, client_secret: STATIC_CLIENT_SECRET });
    expect(viaPost.status).toBe(429);
    expect(viaPost.json).not.toHaveProperty("access_token");
  });

  it("9 failures do not block", async () => {
    const a = await app({ staticClient: true });
    for (let i = 0; i < 9; i++) await wrongSecret(a);
    const k = pkce();
    const code = await a.oauth.obtainCode(STATIC_CLIENT_ID, CLAUDE_REDIRECT, k.challenge);
    const ok = await a.oauth.token(
      { grant_type: "authorization_code", code, code_verifier: k.verifier, redirect_uri: CLAUDE_REDIRECT },
      basic(STATIC_CLIENT_ID, STATIC_CLIENT_SECRET),
    );
    expect(ok.status).toBe(200);
  });

  it("public clients without a secret are not affected while the IP is blocked", async () => {
    const a = await app({ staticClient: true });
    const id = await publicClient(a);
    for (let i = 0; i < 10; i++) await wrongSecret(a);
    expect((await wrongSecret(a))).toBe(429);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const refreshed = await a.oauth.token({ grant_type: "refresh_token", refresh_token: t.refresh, client_id: id });
    expect(refreshed.status).toBe(200);
  });

  it("malformed Basic headers count as failures", async () => {
    const a = await app({ staticClient: true });
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) statuses.push(await wrongSecret(a, "malformed"));
    expect(statuses).toEqual(Array<number>(10).fill(401));
    expect(await wrongSecret(a, "malformed")).toBe(429);
    expect(await wrongSecret(a, "basic")).toBe(429);
  });

  it("failures with Basic count too", async () => {
    const a = await app({ staticClient: true });
    for (let i = 0; i < 10; i++) expect(await wrongSecret(a, "basic")).toBe(401);
    expect(await wrongSecret(a, "post")).toBe(429);
  });

  it("/revoke shares the counter with /token and also answers 429", async () => {
    const a = await app({ staticClient: true });
    const revoke = (secret: string) =>
      fetch(`${a.base}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: "x", client_id: STATIC_CLIENT_ID, client_secret: secret }),
      });
    for (let i = 0; i < 5; i++) expect((await revoke(WRONG_SECRET)).status).toBe(401);
    for (let i = 0; i < 5; i++) expect(await wrongSecret(a)).toBe(401);
    const blocked = await revoke(STATIC_CLIENT_SECRET);
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBeTruthy();
    expect(await wrongSecret(a)).toBe(429);
  });

  it("the block ends after 15 minutes", async () => {
    const a = await app({ staticClient: true });
    for (let i = 0; i < 10; i++) await wrongSecret(a);
    expect(await wrongSecret(a)).toBe(429);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 15 * 60 * 1000 + 1000);
    expect(await wrongSecret(a)).toBe(401);
  });

  it("does not use the login counter (and vice versa)", async () => {
    const a = await app({ staticClient: true });
    for (let i = 0; i < 10; i++) await wrongSecret(a);
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect((await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(303);
  });
});

// ---------------------------------------------------------------------------

describe("login page: referrer policy, Origin: null, cookies", () => {
  it("login pages (form, 401, 429) use Referrer-Policy same-origin in header and meta", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(form.res.headers.get("referrer-policy")).toBe("same-origin");
    expect(form.html).toContain('<meta name="referrer" content="same-origin">');

    const wrong = await a.oauth.login(form, ADMIN_USERNAME, "wrong-password-123");
    expect(wrong.status).toBe(401);
    expect(wrong.headers.get("referrer-policy")).toBe("same-origin");

    for (let i = 0; i < 4; i++) await a.oauth.login(form, ADMIN_USERNAME, "wrong-password-123");
    const limited = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("referrer-policy")).toBe("same-origin");
  });

  it("the 303 redirect to the callback uses Referrer-Policy no-referrer", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(res.status).toBe(303);
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("other endpoints keep the global no-referrer policy", async () => {
    const a = await app();
    expect((await fetch(`${a.base}/healthz`)).headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("accepts Origin: null only together with Sec-Fetch-Site: same-origin", async () => {
    const a = await app();
    const id = await publicClient(a);
    const attempt = async (headers: Record<string, string>): Promise<number> => {
      const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
      return (await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, headers)).status;
    };
    expect(await attempt({ origin: "null", "sec-fetch-site": "same-origin" })).toBe(303);
    expect(await attempt({ origin: "null" })).toBe(403);
    expect(await attempt({ origin: "null", "sec-fetch-site": "same-site" })).toBe(403);
    expect(await attempt({ origin: "null", "sec-fetch-site": "cross-site" })).toBe(403);
    expect(await attempt({ origin: "null", "sec-fetch-site": "none" })).toBe(403);
  });

  it("Origin: null with same-origin still needs the CSRF cookie and field", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const headers = { origin: "null", "sec-fetch-site": "same-origin" };
    expect((await a.oauth.login({ ...form, cookie: "" }, ADMIN_USERNAME, ADMIN_PASSWORD, headers)).status).toBe(403);
    expect((await a.oauth.login({ ...form, csrf: "x" }, ADMIN_USERNAME, ADMIN_PASSWORD, headers)).status).toBe(403);
  });

  it("a foreign Origin is still refused even with Sec-Fetch-Site: same-origin", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const res = await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD, { origin: "https://evil.example", "sec-fetch-site": "same-origin" });
    expect(res.status).toBe(403);
  });

  it("uses the __Host- cookie on https public URLs and works end to end", async () => {
    const a = await app({ origin: "https://mcp.example.com" });
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const setCookie = form.res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/^__Host-mcp_s3_login_csrf=[A-Za-z0-9_-]{43}; /);
    expect(setCookie).toContain("; Secure");
    expect(setCookie).toContain("; Path=/");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).not.toMatch(/Domain=/i);
    expect((await a.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD)).status).toBe(303);
  });

  it("on https the unprefixed cookie name is not accepted", async () => {
    const a = await app({ origin: "https://mcp.example.com" });
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    const nonce = form.cookie.split("=")[1] ?? "";
    const res = await a.oauth.login({ ...form, cookie: `mcp_s3_login_csrf=${nonce}` }, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(res.status).toBe(403);
  });

  it("uses the plain cookie name on http", async () => {
    const a = await app();
    const id = await publicClient(a);
    const form = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(form.res.headers.get("set-cookie") ?? "").toMatch(/^mcp_s3_login_csrf=/);
  });

  it("re-sends the cookie with Max-Age=600 on every login view, keeping the nonce", async () => {
    const a = await app();
    const id = await publicClient(a);
    const first = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(first.res.headers.get("set-cookie")).toContain("Max-Age=600");

    const url = new URL("/authorize", a.base);
    const k = pkce();
    for (const [name, value] of Object.entries({
      response_type: "code",
      client_id: id,
      redirect_uri: LOOPBACK_REDIRECT,
      code_challenge: k.challenge,
      code_challenge_method: "S256",
      resource: a.oauth.resource,
    })) url.searchParams.set(name, value);
    const second = await fetch(url, { headers: { cookie: first.cookie }, redirect: "manual" });
    const resent = second.headers.get("set-cookie") ?? "";
    expect(resent).toContain("Max-Age=600");
    expect(resent.split(";")[0]).toBe(first.cookie);
  });
});

// ---------------------------------------------------------------------------

describe("/authorize validation", () => {
  async function errorOf(a: RunningApp, id: string, extra: Record<string, string>, redirect = LOOPBACK_REDIRECT) {
    const res = await a.oauth.authorize(id, redirect, pkce().challenge, extra);
    expect(res.res.status, JSON.stringify(extra)).toBe(302);
    const location = new URL(res.res.headers.get("location") ?? "http://invalid/");
    return { error: location.searchParams.get("error"), location, form: res.request };
  }

  it("redirects an unsupported scope with error=invalid_scope", async () => {
    const a = await app();
    const id = await publicClient(a);
    for (const scope of ["write", "read write", "admin"]) {
      const { error, location, form } = await errorOf(a, id, { scope });
      expect(error, scope).toBe("invalid_scope");
      expect(location.origin).toBe("http://localhost:9999");
      expect(form).toBeUndefined();
    }
  });

  it("accepts scope=read and no scope", async () => {
    const a = await app();
    const id = await publicClient(a);
    expect((await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge, { scope: "read" })).res.status).toBe(200);
    const url = new URL("/authorize", a.base);
    const k = pkce();
    for (const [name, value] of Object.entries({
      response_type: "code",
      client_id: id,
      redirect_uri: LOOPBACK_REDIRECT,
      code_challenge: k.challenge,
      code_challenge_method: "S256",
    })) url.searchParams.set(name, value);
    expect((await fetch(url, { redirect: "manual" })).status).toBe(200);
  });

  it("redirects a resource with a fragment with error=invalid_target", async () => {
    const a = await app();
    const id = await publicClient(a);
    for (const resource of [`${a.origin}/mcp#frag`, `${a.origin}/mcp#`, `${a.origin}#x`]) {
      const { error } = await errorOf(a, id, { resource });
      expect(error, resource).toBe("invalid_target");
    }
  });

  it("redirects a state over 2048 UTF-8 bytes with error=invalid_request (2048 bytes is fine)", async () => {
    const a = await app();
    const id = await publicClient(a);
    // 1100 two-byte characters: 1100 characters but 2200 bytes.
    const { error } = await errorOf(a, id, { state: "é".repeat(1100) });
    expect(error).toBe("invalid_request");
    expect((await errorOf(a, id, { state: "a".repeat(2049) })).error).toBe("invalid_request");
    const fine = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge, { state: "é".repeat(1024) });
    expect(fine.res.status).toBe(200);
    const edge = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge, { state: "a".repeat(2048) });
    expect(edge.res.status).toBe(200);
  });

  it("redirects a state with control characters with error=invalid_request", async () => {
    const a = await app();
    const id = await publicClient(a);
    for (const state of ["a\u0001b", "line\nbreak", "tab\there", "nul\u0000"]) {
      const { error } = await errorOf(a, id, { state });
      expect(error, JSON.stringify(state)).toBe("invalid_request");
    }
  });

  it("redirects a client without the authorization_code grant with error=unauthorized_client", async () => {
    const a = await app();
    const id = await publicClient(a, { grant_types: ["refresh_token"] });
    const { error } = await errorOf(a, id, {});
    expect(error).toBe("unauthorized_client");
  });

  it("a client without grant_types and one with both grants may log in", async () => {
    const a = await app();
    const none = await publicClient(a);
    const both = await publicClient(a, { grant_types: ["authorization_code", "refresh_token"] });
    for (const id of [none, both]) expect((await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge)).res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------

describe("/token grant restrictions", () => {
  it("a client without the refresh_token grant gets no refresh token", async () => {
    const a = await app();
    const id = await publicClient(a, { grant_types: ["authorization_code"] });
    const k = pkce();
    const code = await a.oauth.obtainCode(id, LOOPBACK_REDIRECT, k.challenge);
    const t = await a.oauth.token({ grant_type: "authorization_code", code, code_verifier: k.verifier, client_id: id, redirect_uri: LOOPBACK_REDIRECT });
    expect(t.status).toBe(200);
    expect(t.json.access_token).toBeTruthy();
    expect(t.json).not.toHaveProperty("refresh_token");
  });

  it("a client with both grants still gets one", async () => {
    const a = await app();
    const id = await publicClient(a, { grant_types: ["authorization_code", "refresh_token"] });
    expect((await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT)).refresh).toBeTruthy();
  });

  it("a refresh by a client without the refresh_token grant is rejected with unauthorized_client", async () => {
    const a = await app();
    const owner = await publicClient(a);
    const limited = await publicClient(a, { grant_types: ["authorization_code"] });
    const t = await a.oauth.obtainTokens(owner, LOOPBACK_REDIRECT);
    const res = await a.oauth.token({ grant_type: "refresh_token", refresh_token: t.refresh, client_id: limited });
    expect(res.status).toBe(400);
    expect(res.json.error).toBe("unauthorized_client");
    // The owner's token was not consumed.
    expect((await a.oauth.token({ grant_type: "refresh_token", refresh_token: t.refresh, client_id: owner })).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------

describe("/mcp body errors", () => {
  async function post(a: RunningApp, bearer: string | undefined, body: string, contentType = "application/json") {
    return fetch(`${a.base}/mcp`, {
      method: "POST",
      headers: {
        "content-type": contentType,
        accept: "application/json, text/event-stream",
        ...(bearer === undefined ? {} : { authorization: `Bearer ${bearer}` }),
      },
      body,
    });
  }

  it("malformed JSON without a token is 401 (authentication comes first)", async () => {
    const a = await app();
    const res = await post(a, undefined, '{"jsonrpc": ');
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/^Bearer /);
    const bad = await post(a, "garbage", '{"jsonrpc": ');
    expect(bad.status).toBe(401);
  });

  it("malformed JSON with a token is a 400 JSON-RPC parse error (-32700) without details", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const res = await post(a, t.access, '{"jsonrpc": ');
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null });
    expect(text).not.toMatch(/SyntaxError|Unexpected|node_modules/);
  });

  it("other body errors (too large) are a JSON-RPC invalid request (-32600)", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const big = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { pad: "a".repeat(300_000) } });
    const res = await post(a, t.access, big);
    expect(res.status).toBe(413);
    const body = (await res.json()) as { jsonrpc: string; error: { code: number }; id: null };
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error.code).toBe(-32600);
    expect(body.id).toBeNull();
  });

  it("an unsupported charset is a JSON-RPC invalid request too", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    const res = await post(a, t.access, "{}", "application/json; charset=x-bogus-charset");
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    const body = (await res.json()) as { error: { code: number } };
    expect(body.error.code).toBe(-32600);
  });

  it("a valid call still works after a rejected body", async () => {
    const a = await app();
    const id = await publicClient(a);
    const t = await a.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    await post(a, t.access, "{not json");
    expect(toolText(await a.oauth.callTool(t.access, "get_object_info", { path: "a.txt" })).isError).toBe(false);
  });
});

describe("client names in the login page", () => {
  it("invisible format characters and separators are removed from the shown name", async () => {
    const a = await app();
    const id = await publicClient(a, { client_name: "Safe‮​  App" });
    const page = await a.oauth.authorize(id, LOOPBACK_REDIRECT, pkce().challenge);
    expect(page.res.status).toBe(200);
    expect(page.html).toContain("<strong>SafeApp</strong>");
    for (const ch of ["‮", "​", " ", " "]) expect(page.html).not.toContain(ch);
  });
});
