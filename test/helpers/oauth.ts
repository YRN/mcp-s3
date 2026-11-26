import { createHash, randomBytes } from "node:crypto";

/**
 * Minimal OAuth + MCP-over-HTTP client for tests: dynamic client registration, the login
 * form, token requests, and JSON-RPC calls to /mcp. Plain fetch, no SDK, so the tests see the
 * raw HTTP behaviour of the server.
 */

export const ADMIN_USERNAME = "admin";
export const ADMIN_PASSWORD = "correct-horse-battery";
export const STATIC_CLIENT_ID = "static-client";
export const STATIC_CLIENT_SECRET = "s".repeat(16) + "T".repeat(16) + "0123456789abcdef";
export const LOOPBACK_REDIRECT = "http://localhost:9999/callback";
export const CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

export interface Pkce {
  verifier: string;
  challenge: string;
}

export function pkce(): Pkce {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

export interface AuthorizeResult {
  res: Response;
  html: string;
  /** "name=value" of the CSRF cookie (empty if none was set). */
  cookie: string;
  request: string | undefined;
  csrf: string | undefined;
}

export interface TokenResult {
  status: number;
  json: Record<string, unknown>;
  headers: Headers;
}

export interface McpResult {
  status: number;
  json: Record<string, unknown> | undefined;
  text: string;
  headers: Headers;
}

export function hiddenField(html: string, name: string): string | undefined {
  const match = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
  return match?.[1];
}

export function str(value: unknown): string {
  if (typeof value !== "string") throw new Error(`expected a string, got ${JSON.stringify(value)}`);
  return value;
}

export class OAuthTestClient {
  /** Where requests are sent. */
  readonly base: string;
  /** The server's public origin (issuer, Origin header of the login form, resource URL). */
  readonly origin: string;

  constructor(base: string, origin: string = base) {
    this.base = base;
    this.origin = origin;
  }

  get resource(): string {
    return `${this.origin}/mcp`;
  }

  async register(body: Record<string, unknown>): Promise<{ status: number; json: Record<string, unknown> }> {
    const res = await fetch(`${this.base}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: res.status, json: (await res.json()) as Record<string, unknown> };
  }

  async authorize(
    clientId: string,
    redirectUri: string,
    challenge: string,
    extra: Record<string, string> = {},
  ): Promise<AuthorizeResult> {
    const url = new URL("/authorize", this.base);
    const params: Record<string, string> = {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: 'st<>"ate',
      scope: "read",
      resource: this.resource,
      ...extra,
    };
    for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
    const res = await fetch(url, { redirect: "manual" });
    const html = await res.text();
    return {
      res,
      html,
      cookie: (res.headers.get("set-cookie") ?? "").split(";")[0] ?? "",
      request: hiddenField(html, "request"),
      csrf: hiddenField(html, "csrf"),
    };
  }

  login(
    form: Pick<AuthorizeResult, "request" | "csrf" | "cookie">,
    username: string,
    password: string,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    const body = new URLSearchParams({ request: form.request ?? "", csrf: form.csrf ?? "", username, password });
    return fetch(`${this.base}/login`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(form.cookie === "" ? {} : { cookie: form.cookie }),
        origin: this.origin,
        ...headers,
      },
      body,
    });
  }

  /** authorize + successful login; returns the authorization code. */
  async obtainCode(clientId: string, redirectUri: string, challenge: string): Promise<string> {
    const a = await this.authorize(clientId, redirectUri, challenge);
    const res = await this.login(a, ADMIN_USERNAME, ADMIN_PASSWORD);
    if (res.status !== 303) throw new Error(`login failed with status ${String(res.status)}`);
    const code = new URL(res.headers.get("location") ?? "http://invalid/").searchParams.get("code");
    if (code === null) throw new Error("no code in redirect");
    return code;
  }

  async token(params: Record<string, string>, headers: Record<string, string> = {}): Promise<TokenResult> {
    const res = await fetch(`${this.base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
      body: new URLSearchParams(params),
    });
    return { status: res.status, json: (await res.json()) as Record<string, unknown>, headers: res.headers };
  }

  /** Full authorization code flow for a public client. */
  async obtainTokens(clientId: string, redirectUri: string): Promise<{ access: string; refresh: string; code: string }> {
    const k = pkce();
    const code = await this.obtainCode(clientId, redirectUri, k.challenge);
    const t = await this.token({
      grant_type: "authorization_code",
      code,
      code_verifier: k.verifier,
      client_id: clientId,
      redirect_uri: redirectUri,
      resource: this.resource,
    });
    if (t.status !== 200) throw new Error(`token exchange failed: ${JSON.stringify(t.json)}`);
    return { access: str(t.json.access_token), refresh: str(t.json.refresh_token), code };
  }

  async mcp(bearer: string | undefined, method: string, params: Record<string, unknown> = {}, id = 1): Promise<McpResult> {
    const res = await fetch(`${this.base}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": "2025-06-18",
        ...(bearer === undefined ? {} : { authorization: `Bearer ${bearer}` }),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    const text = await res.text();
    let json: Record<string, unknown> | undefined;
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      json = undefined;
    }
    return { status: res.status, json, text, headers: res.headers };
  }

  callTool(bearer: string, name: string, args: Record<string, unknown> = {}, id = 1): Promise<McpResult> {
    return this.mcp(bearer, "tools/call", { name, arguments: args }, id);
  }
}

/** First text content item of a tools/call JSON-RPC response, plus its isError flag. */
export function toolText(result: McpResult): { text: string; isError: boolean } {
  const payload = result.json?.result as { content?: { type: string; text?: string }[]; isError?: boolean } | undefined;
  const first = payload?.content?.[0];
  return { text: first?.text ?? "", isError: payload?.isError === true };
}
