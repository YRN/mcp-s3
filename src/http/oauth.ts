import { createHash, randomBytes, type KeyObject } from "node:crypto";

import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
  CustomOAuthError,
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
  UnauthorizedClientError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { Response } from "express";
import { z } from "zod";

import { hasControlChar } from "../paths.js";
import type { Secret } from "../secret.js";
import { isLoopbackRedirectUri, MAX_REDIRECT_URI_LENGTH, type HttpConfig } from "./config.js";
import { deriveKey, hmacBase64url, SealedCodec, sha256Base64url } from "./sealed.js";

/**
 * OAuth 2.1 authorization server for the HTTP mode (PLAN.md section 9, Fase 3), plugged into
 * the MCP SDK's mcpAuthRouter / requireBearerAuth.
 *
 * Everything is stateless (sealed with keys derived from MCP_S3_TOKEN_KEY, see sealed.ts), so
 * registered clients and issued tokens survive restarts and work across instances. Only two
 * small in-memory sets exist: authorization codes already exchanged (single use) and revoked
 * token IDs. Both are lost on restart (see the report / README).
 *
 * Tokens are also bound to the admin credentials: the keys for login requests, codes, and
 * tokens are derived with a salt computed from MCP_S3_AUTH_USERNAME and MCP_S3_AUTH_PASSWORD,
 * so changing either one invalidates every issued code and token.
 */

/** The only scope: read-only access to the workspace. */
export const SCOPE_READ = "read";
export const SUPPORTED_SCOPES: readonly string[] = [SCOPE_READ];

export const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
/** Refresh tokens rotate (sliding 7 days), but never beyond this long after the login. */
export const MAX_LOGIN_LIFETIME_SECONDS = 90 * 24 * 60 * 60;
export const AUTHORIZATION_CODE_TTL_SECONDS = 2 * 60;
/** How long a rendered login form stays valid. */
export const LOGIN_REQUEST_TTL_SECONDS = 10 * 60;

export const MAX_REDIRECT_URIS = 5;
export const MAX_CLIENT_NAME_LENGTH = 100;
/** Upper bound on the OAuth `state`, in UTF-8 bytes. */
export const MAX_STATE_LENGTH = 2048;
/** Upper bound on a dynamically registered client_id (it carries the sealed client metadata). */
export const MAX_CLIENT_ID_LENGTH = 6144;
const MAX_TOKEN_LENGTH = 4096;
const MAX_LOGIN_REQUEST_LENGTH = 8192;
/** Upper bound on remembered used codes / revoked token IDs. */
const MAX_TRACKED_IDS = 10_000;

const AUTH_METHODS = ["none", "client_secret_post", "client_secret_basic"] as const;
const GRANT_TYPES: ReadonlySet<string> = new Set(["authorization_code", "refresh_token"]);
const S256_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

// --- keys --------------------------------------------------------------------

export interface OAuthKeys {
  /** Seals dynamically registered client metadata into the client_id. */
  client: KeyObject;
  /** HMAC key deriving a dynamically registered client's secret from its client_id. */
  clientSecret: KeyObject;
  /** Seals the pending authorization request carried by the login form. */
  loginRequest: KeyObject;
  /** HMAC key binding the login form to the CSRF cookie. */
  csrf: KeyObject;
  code: KeyObject;
  access: KeyObject;
  refresh: KeyObject;
}

function lengthPrefixed(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/**
 * Derive all OAuth keys from MCP_S3_TOKEN_KEY. Client keys depend on the token key only, so a
 * password change does not unregister clients; every other key also depends on the admin
 * credentials (through a SHA-256 salt), so a credential change revokes all codes and tokens.
 */
export function deriveOAuthKeys(root: KeyObject, username: Secret, password: Secret): OAuthKeys {
  const clientSalt = Buffer.from("mcp-s3 oauth clients", "utf8");
  const credentialSalt = createHash("sha256")
    .update("mcp-s3 oauth credentials\0", "utf8")
    .update(lengthPrefixed(username.reveal()))
    .update(lengthPrefixed(password.reveal()))
    .digest();
  return {
    client: deriveKey(root, clientSalt, "client-id"),
    clientSecret: deriveKey(root, clientSalt, "client-secret"),
    loginRequest: deriveKey(root, credentialSalt, "login-request"),
    csrf: deriveKey(root, credentialSalt, "login-csrf"),
    code: deriveKey(root, credentialSalt, "authorization-code"),
    access: deriveKey(root, credentialSalt, "access-token"),
    refresh: deriveKey(root, credentialSalt, "refresh-token"),
  };
}

// --- payload schemas -----------------------------------------------------------

const ClientPayload = z.strictObject({
  r: z.array(z.string()).min(1).max(MAX_REDIRECT_URIS),
  m: z.enum(AUTH_METHODS).optional(),
  n: z.string().max(MAX_CLIENT_NAME_LENGTH).optional(),
  g: z.array(z.string()).optional(),
  t: z.array(z.string()).optional(),
  i: z.number().int(),
});

/** Pending authorization request, sealed into the login form. */
export const LoginRequestPayload = z.strictObject({
  /** Client reference: SHA-256 of the client_id. */
  c: z.string(),
  /** Client display name (untrusted, escaped when rendered). */
  n: z.string().max(MAX_CLIENT_NAME_LENGTH).optional(),
  /** Redirect URI, already validated against the client. */
  r: z.string(),
  /** PKCE S256 code challenge. */
  h: z.string(),
  /** OAuth state. */
  s: z.string().max(MAX_STATE_LENGTH).optional(),
  /** Canonical resource (the /mcp URL). */
  a: z.string(),
});
export type LoginRequest = z.infer<typeof LoginRequestPayload>;

const CodePayload = z.strictObject({ j: z.string(), c: z.string(), r: z.string(), h: z.string(), a: z.string() });

const AccessPayload = z.strictObject({ j: z.string(), c: z.string(), a: z.string(), s: z.array(z.string()) });

const RefreshPayload = z.strictObject({
  j: z.string(),
  c: z.string(),
  a: z.string(),
  s: z.array(z.string()),
  /** Login time (epoch seconds), bounds the total lifetime of a rotating refresh token. */
  t: z.number().int(),
});

// --- helpers -----------------------------------------------------------------

/** Reference to a client stored in codes and tokens (the client_id itself can be long). */
export function clientRef(clientId: string): string {
  return sha256Base64url(clientId);
}

/** Invisible format characters (Unicode Cf: bidi overrides, zero-width, ...) and line/paragraph separators. */
const INVISIBLE = /[\p{Cf}\p{Zl}\p{Zp}]/u;

/**
 * Display name for a client: control characters, invisible format characters (Cf, e.g. bidi
 * overrides that could disguise the name), and line/paragraph separators removed, trimmed, at
 * most `max` UTF-16 code units without splitting a surrogate pair. undefined if nothing is left.
 */
export function displayName(value: string | undefined, max = MAX_CLIENT_NAME_LENGTH): string | undefined {
  if (value === undefined) return undefined;
  let out = "";
  for (const ch of value.trim()) {
    if (hasControlChar(ch) || !ch.isWellFormed() || INVISIBLE.test(ch)) continue;
    if (out.length + ch.length > max) break;
    out += ch;
  }
  out = out.trim();
  return out === "" ? undefined : out;
}

/**
 * Whether a client may use a grant type. Clients that registered without grant_types are not
 * restricted (many MCP clients omit the field but still refresh); clients that listed
 * grant_types only get those.
 */
export function allowsGrant(client: OAuthClientInformationFull, grant: "authorization_code" | "refresh_token"): boolean {
  return client.grant_types === undefined || client.grant_types.includes(grant);
}

function newId(): string {
  return randomBytes(16).toString("base64url");
}

/** The resource string without a fragment and without one trailing slash. */
function comparableResource(value: string): string {
  const hash = value.indexOf("#");
  return (hash === -1 ? value : value.slice(0, hash)).replace(/\/$/, "");
}

/** Remembers IDs until their expiry (bounded; the oldest entries are dropped first). */
export class ExpiringIdSet {
  private readonly entries = new Map<string, number>();
  private readonly now: () => number;
  private readonly max: number;

  constructor(now: () => number, max = MAX_TRACKED_IDS) {
    this.now = now;
    this.max = max;
  }

  add(id: string, expiresAt: number): void {
    this.prune();
    this.entries.delete(id);
    this.entries.set(id, expiresAt);
    while (this.entries.size > this.max) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) break;
      this.entries.delete(oldest.value);
    }
  }

  has(id: string): boolean {
    const expiresAt = this.entries.get(id);
    return expiresAt !== undefined && expiresAt > this.nowSeconds();
  }

  private nowSeconds(): number {
    return Math.floor(this.now() / 1000);
  }

  private prune(): void {
    const now = this.nowSeconds();
    for (const [id, expiresAt] of this.entries) {
      if (expiresAt <= now) this.entries.delete(id);
    }
  }
}

// --- clients -----------------------------------------------------------------

/**
 * Registered clients: the optional static client from env, plus dynamically registered
 * clients whose metadata is sealed into their client_id (no storage). A dynamic client's
 * secret is HMAC(client-secret key, client_id), so it can be recomputed on every request.
 */
export class ClientRegistry implements OAuthRegisteredClientsStore {
  private readonly http: HttpConfig;
  private readonly keys: OAuthKeys;
  private readonly codec: SealedCodec<typeof ClientPayload>;
  private readonly now: () => number;
  /** Present only when dynamic client registration is enabled (the SDK checks for it). */
  readonly registerClient?: (
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ) => OAuthClientInformationFull;

  constructor(http: HttpConfig, keys: OAuthKeys, now: () => number = () => Date.now()) {
    this.http = http;
    this.keys = keys;
    this.now = now;
    this.codec = new SealedCodec(keys.client, "client-id", ClientPayload, MAX_CLIENT_ID_LENGTH, now);
    if (http.dynamicRegistration) {
      this.registerClient = (client) => this.register(client);
    }
  }

  /** Whether `uri` may be used as a redirect URI by a dynamically registered client. */
  isAllowedRedirectUri(uri: string): boolean {
    if (uri.length > MAX_REDIRECT_URI_LENGTH) return false;
    return this.http.redirectUris.includes(uri) || isLoopbackRedirectUri(uri);
  }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const fixed = this.http.staticClient;
    if (fixed !== undefined && clientId === fixed.id) {
      return {
        client_id: fixed.id,
        client_secret: fixed.secret.reveal(),
        client_secret_expires_at: 0,
        client_name: "pre-registered client",
        redirect_uris: [...this.http.redirectUris],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      };
    }
    if (!this.http.dynamicRegistration) return undefined;

    const opened = this.codec.open(clientId);
    if (opened === undefined) return undefined;
    const meta = opened.payload;
    // Re-check against the current policy: MCP_S3_OAUTH_REDIRECT_URIS may have changed.
    const redirectUris = meta.r.filter((uri) => this.isAllowedRedirectUri(uri));
    if (redirectUris.length === 0) return undefined;
    return this.clientInfo(clientId, { ...meta, r: redirectUris });
  }

  private clientInfo(clientId: string, meta: z.infer<typeof ClientPayload>): OAuthClientInformationFull {
    const confidential = meta.m !== "none";
    return {
      client_id: clientId,
      client_id_issued_at: meta.i,
      ...(confidential ? { client_secret: hmacBase64url(this.keys.clientSecret, clientId), client_secret_expires_at: 0 } : {}),
      redirect_uris: meta.r,
      ...(meta.m === undefined ? {} : { token_endpoint_auth_method: meta.m }),
      ...(meta.n === undefined ? {} : { client_name: meta.n }),
      ...(meta.g === undefined ? {} : { grant_types: meta.g }),
      ...(meta.t === undefined ? {} : { response_types: meta.t }),
    };
  }

  private register(client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): OAuthClientInformationFull {
    const redirectUris = client.redirect_uris;
    if (redirectUris.length === 0 || redirectUris.length > MAX_REDIRECT_URIS) {
      throw new InvalidClientMetadataError(`redirect_uris must contain 1 to ${MAX_REDIRECT_URIS} URIs`);
    }
    for (const uri of redirectUris) {
      if (!this.isAllowedRedirectUri(uri)) {
        throw new CustomOAuthError(
          "invalid_redirect_uri",
          "redirect_uris must be loopback URIs (http://localhost, http://127.0.0.1) or listed in MCP_S3_OAUTH_REDIRECT_URIS",
        );
      }
    }

    const method = client.token_endpoint_auth_method;
    if (method !== undefined && !(AUTH_METHODS as readonly string[]).includes(method)) {
      throw new InvalidClientMetadataError(`token_endpoint_auth_method must be one of: ${AUTH_METHODS.join(", ")}`);
    }
    if (client.grant_types !== undefined && !client.grant_types.every((g) => GRANT_TYPES.has(g))) {
      throw new InvalidClientMetadataError("grant_types may only contain authorization_code and refresh_token");
    }
    if (client.response_types !== undefined && !client.response_types.every((t) => t === "code")) {
      throw new InvalidClientMetadataError("response_types may only contain code");
    }

    const name = displayName(client.client_name);
    const meta: z.infer<typeof ClientPayload> = {
      r: [...redirectUris],
      ...(method === undefined ? {} : { m: method as (typeof AUTH_METHODS)[number] }),
      ...(name === undefined ? {} : { n: name }),
      ...(client.grant_types === undefined ? {} : { g: [...client.grant_types] }),
      ...(client.response_types === undefined ? {} : { t: [...client.response_types] }),
      i: Math.floor(this.now() / 1000),
    };
    const clientId = this.codec.seal(meta);
    if (clientId.length > MAX_CLIENT_ID_LENGTH) throw new InvalidClientMetadataError("client metadata is too large");
    return this.clientInfo(clientId, meta);
  }
}

// --- provider ----------------------------------------------------------------

/** Shows the login page for a pending authorization request (implemented in login.ts). */
export interface LoginPageRenderer {
  showLogin(res: Response, sealedRequest: string, request: LoginRequest): void;
}

export interface ProviderOptions {
  http: HttpConfig;
  keys: OAuthKeys;
  /** The protected resource, i.e. `${publicUrl}mcp`. */
  resourceUrl: URL;
  now?: () => number;
}

export class S3OAuthProvider implements OAuthServerProvider {
  readonly clientsStore: ClientRegistry;
  readonly resourceUrl: URL;
  private readonly publicUrl: URL;
  private readonly loginRequests: SealedCodec<typeof LoginRequestPayload>;
  private readonly codes: SealedCodec<typeof CodePayload>;
  private readonly accessTokens: SealedCodec<typeof AccessPayload>;
  private readonly refreshTokens: SealedCodec<typeof RefreshPayload>;
  private readonly usedCodes: ExpiringIdSet;
  private readonly revoked: ExpiringIdSet;
  private renderer: LoginPageRenderer | undefined;

  constructor(opts: ProviderOptions) {
    const now = opts.now ?? (() => Date.now());
    this.clientsStore = new ClientRegistry(opts.http, opts.keys, now);
    this.resourceUrl = opts.resourceUrl;
    this.publicUrl = opts.http.publicUrl;
    this.loginRequests = new SealedCodec(opts.keys.loginRequest, "login-request", LoginRequestPayload, MAX_LOGIN_REQUEST_LENGTH, now);
    this.codes = new SealedCodec(opts.keys.code, "authorization-code", CodePayload, MAX_TOKEN_LENGTH, now);
    this.accessTokens = new SealedCodec(opts.keys.access, "access-token", AccessPayload, MAX_TOKEN_LENGTH, now);
    this.refreshTokens = new SealedCodec(opts.keys.refresh, "refresh-token", RefreshPayload, MAX_TOKEN_LENGTH, now);
    this.usedCodes = new ExpiringIdSet(now);
    this.revoked = new ExpiringIdSet(now);
  }

  setLoginPageRenderer(renderer: LoginPageRenderer): void {
    this.renderer = renderer;
  }

  /** Whether a client-supplied RFC 8707 resource designates this server. */
  isOwnResource(resource: URL): boolean {
    // RFC 8707: a resource indicator must not include a fragment.
    if (resource.href.includes("#")) return false;
    const value = comparableResource(resource.href);
    return value === comparableResource(this.resourceUrl.href) || value === comparableResource(this.publicUrl.href);
  }

  // --- authorization endpoint: show the login page ---------------------------

  authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (params.resource !== undefined && !this.isOwnResource(params.resource)) {
      throw new InvalidTargetError("the requested resource is not served by this server");
    }
    if (!S256_CHALLENGE.test(params.codeChallenge)) throw new InvalidRequestError("code_challenge is not a valid S256 challenge");
    if (params.state !== undefined) {
      if (Buffer.byteLength(params.state, "utf8") > MAX_STATE_LENGTH) throw new InvalidRequestError("state is too long");
      if (!params.state.isWellFormed() || hasControlChar(params.state)) throw new InvalidRequestError("state contains invalid characters");
    }
    const scopes = (params.scopes ?? []).filter((scope) => scope !== "");
    const unsupported = scopes.filter((scope) => !SUPPORTED_SCOPES.includes(scope));
    if (unsupported.length > 0) throw new InvalidScopeError(`unsupported scope; supported: ${SUPPORTED_SCOPES.join(" ")}`);
    if (!allowsGrant(client, "authorization_code")) {
      throw new UnauthorizedClientError("client is not registered for the authorization_code grant");
    }
    if (this.renderer === undefined) throw new Error("login page renderer is not configured");

    const name = displayName(client.client_name);
    const request: LoginRequest = {
      c: clientRef(client.client_id),
      ...(name === undefined ? {} : { n: name }),
      r: params.redirectUri,
      h: params.codeChallenge,
      ...(params.state === undefined ? {} : { s: params.state }),
      a: this.resourceUrl.href,
    };
    this.renderer.showLogin(res, this.loginRequests.seal(request, LOGIN_REQUEST_TTL_SECONDS), request);
    return Promise.resolve();
  }

  /** Open a login form's sealed request; undefined if invalid or expired. */
  openLoginRequest(sealed: string): LoginRequest | undefined {
    return this.loginRequests.open(sealed)?.payload;
  }

  /** Issue an authorization code after a successful login. */
  issueAuthorizationCode(request: LoginRequest): string {
    return this.codes.seal({ j: newId(), c: request.c, r: request.r, h: request.h, a: request.a }, AUTHORIZATION_CODE_TTL_SECONDS);
  }

  // --- token endpoint ----------------------------------------------------------

  private openCode(client: OAuthClientInformationFull, code: string) {
    const opened = this.codes.open(code);
    if (opened === undefined || opened.payload.c !== clientRef(client.client_id) || this.usedCodes.has(opened.payload.j)) {
      throw new InvalidGrantError("authorization code is invalid or expired");
    }
    return opened;
  }

  challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    return Promise.resolve(this.openCode(client, authorizationCode).payload.h);
  }

  exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const { payload, expiresAt } = this.openCode(client, authorizationCode);
    if (redirectUri !== undefined && redirectUri !== payload.r) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }
    if (resource !== undefined && !this.isOwnResource(resource)) {
      throw new InvalidTargetError("the requested resource is not served by this server");
    }
    // Single use: remember the code until it would have expired anyway.
    this.usedCodes.add(payload.j, expiresAt ?? this.codes.nowSeconds() + AUTHORIZATION_CODE_TTL_SECONDS);
    return Promise.resolve(
      this.issueTokens(payload.c, payload.a, [...SUPPORTED_SCOPES], this.codes.nowSeconds(), allowsGrant(client, "refresh_token")),
    );
  }

  exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    if (!allowsGrant(client, "refresh_token")) {
      throw new UnauthorizedClientError("client is not registered for the refresh_token grant");
    }
    const opened = this.refreshTokens.open(refreshToken);
    if (opened === undefined || opened.payload.c !== clientRef(client.client_id) || this.revoked.has(opened.payload.j)) {
      throw new InvalidGrantError("refresh token is invalid, expired, or revoked");
    }
    const { payload } = opened;
    if (scopes !== undefined && !scopes.every((scope) => payload.s.includes(scope))) {
      throw new InvalidScopeError("requested scope exceeds the original grant");
    }
    if (resource !== undefined && !this.isOwnResource(resource)) {
      throw new InvalidTargetError("the requested resource is not served by this server");
    }
    // Rotation: the old refresh token stops working (until a restart, see revoked).
    this.revoked.add(payload.j, opened.expiresAt ?? this.refreshTokens.nowSeconds() + REFRESH_TOKEN_TTL_SECONDS);
    const granted = scopes ?? payload.s;
    return Promise.resolve(this.issueTokens(payload.c, payload.a, granted, payload.t, true));
  }

  private issueTokens(client: string, resource: string, scopes: string[], loginTime: number, withRefresh: boolean): OAuthTokens {
    const now = this.accessTokens.nowSeconds();
    const accessToken = this.accessTokens.seal({ j: newId(), c: client, a: resource, s: scopes }, ACCESS_TOKEN_TTL_SECONDS);
    const tokens: OAuthTokens = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      scope: scopes.join(" "),
    };
    const refreshTtl = Math.min(REFRESH_TOKEN_TTL_SECONDS, loginTime + MAX_LOGIN_LIFETIME_SECONDS - now);
    if (withRefresh && refreshTtl > ACCESS_TOKEN_TTL_SECONDS) {
      tokens.refresh_token = this.refreshTokens.seal({ j: newId(), c: client, a: resource, s: scopes, t: loginTime }, refreshTtl);
    }
    return tokens;
  }

  // --- resource server -----------------------------------------------------------

  verifyAccessToken(token: string): Promise<AuthInfo> {
    const opened = this.accessTokens.open(token);
    if (opened === undefined || this.revoked.has(opened.payload.j)) {
      return Promise.reject(new InvalidTokenError("Invalid or expired token"));
    }
    const { payload, expiresAt } = opened;
    return Promise.resolve({
      token,
      clientId: payload.c,
      scopes: payload.s,
      ...(expiresAt === undefined ? {} : { expiresAt }),
      resource: new URL(payload.a),
    });
  }

  revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const ref = clientRef(client.client_id);
    const opened = this.refreshTokens.open(request.token) ?? this.accessTokens.open(request.token);
    if (opened !== undefined && opened.payload.c === ref) {
      this.revoked.add(opened.payload.j, opened.expiresAt ?? this.accessTokens.nowSeconds() + REFRESH_TOKEN_TTL_SECONDS);
    }
    return Promise.resolve();
  }
}
