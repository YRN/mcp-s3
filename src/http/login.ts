import { createHash, createHmac, createSecretKey, randomBytes, timingSafeEqual, type KeyObject } from "node:crypto";

import type { Request, Response } from "express";
import { z } from "zod";

import { log } from "../logger.js";
import type { Secret } from "../secret.js";
import type { HttpConfig } from "./config.js";
import type { LoginPageRenderer, LoginRequest, S3OAuthProvider } from "./oauth.js";
import { FailureRateLimiter } from "./rateLimit.js";
import { constantTimeEqual, hmacBase64url } from "./sealed.js";

/**
 * Login page of the authorization server: one static admin account (MCP_S3_AUTH_USERNAME /
 * MCP_S3_AUTH_PASSWORD), checked with crypto.timingSafeEqual.
 *
 * - Every value shown on the page is HTML-escaped; the password is never echoed.
 * - CSRF: a random nonce in an HttpOnly, SameSite=Lax cookie (prefixed __Host- on https),
 *   bound to the form by HMAC(csrf key, nonce || sealed request); plus Origin /
 *   Sec-Fetch-Site checks on POST.
 * - Brute force: in-memory limit on failed logins per client IP (IPv6 per /64) and in total.
 * - Strict CSP, no framing, no caching. Referrer-Policy same-origin: browsers then send the
 *   real Origin on the same-origin form POST (with no-referrer, Chrome sends "Origin: null"),
 *   and never send a referrer to another origin (e.g. the OAuth callback).
 */

export const LOGIN_PATH = "/login";
/** Base name of the CSRF cookie; on https origins it carries the __Host- prefix. */
export const CSRF_COOKIE = "mcp_s3_login_csrf";
/** Name of the CSRF cookie for an origin (__Host- requires Secure, Path=/, and no Domain). */
export function csrfCookieName(secure: boolean): string {
  return secure ? `__Host-${CSRF_COOKIE}` : CSRF_COOKIE;
}
/** Referrer policy of the login pages (see above). */
export const LOGIN_REFERRER_POLICY = "same-origin";
const CSRF_COOKIE_MAX_AGE_SECONDS = 10 * 60;
const CSRF_NONCE = /^[A-Za-z0-9_-]{43}$/;

/** Failed logins allowed per client IP per window. */
export const LOGIN_MAX_FAILURES_PER_IP = 5;
/** Failed logins allowed from all clients together per window. */
export const LOGIN_MAX_FAILURES_TOTAL = 100;
export const LOGIN_WINDOW_SECONDS = 15 * 60;

const MAX_FIELD_LENGTH = 1024;

// --- HTML --------------------------------------------------------------------

const HTML_ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
};

/** Escape text for use in HTML element content and double- or single-quoted attributes. */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"'`]/g, (ch) => HTML_ESCAPES[ch] ?? ch);
}

const STYLE = [
  "body{font-family:system-ui,-apple-system,sans-serif;background:#f4f4f5;color:#18181b;margin:0}",
  "main{max-width:24rem;margin:4rem auto;background:#fff;padding:2rem;border-radius:.5rem;box-shadow:0 1px 3px rgba(0,0,0,.15)}",
  "h1{font-size:1.25rem;margin-top:0}",
  "label{display:block;margin-top:1rem;font-weight:600}",
  "input{box-sizing:border-box;width:100%;padding:.5rem;margin-top:.25rem;font-size:1rem}",
  "button{margin-top:1.5rem;width:100%;padding:.6rem;font-size:1rem;cursor:pointer}",
  ".error{color:#b91c1c}",
  ".muted{color:#52525b;font-size:.9rem;word-break:break-all}",
].join("");
const STYLE_HASH = `'sha256-${createHash("sha256").update(STYLE, "utf8").digest("base64")}'`;

/** CSP source for the origin a redirect goes to (form-action must allow the post-login redirect). */
function redirectOriginSource(redirectUri: string): string | undefined {
  if (!URL.canParse(redirectUri)) return undefined;
  const url = new URL(redirectUri);
  if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
  // url.origin is scheme://host[:port] with an IDNA/percent-encoded host: no spaces, quotes, or ";".
  return /^https?:\/\/[A-Za-z0-9.\-[\]:]+$/.test(url.origin) ? url.origin : undefined;
}

function setPageHeaders(res: Response, formAction: string): void {
  res.setHeader(
    "Content-Security-Policy",
    `default-src 'none'; style-src ${STYLE_HASH}; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
  );
  res.setHeader("X-Frame-Options", "DENY");
  // Overrides the global no-referrer header for the login pages only.
  res.setHeader("Referrer-Policy", LOGIN_REFERRER_POLICY);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
}

function page(title: string, body: string): string {
  return (
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    `<meta name="referrer" content="${LOGIN_REFERRER_POLICY}">\n` +
    `<title>${escapeHtml(title)}</title>\n<style>${STYLE}</style>\n</head>\n<body>\n<main>\n${body}\n</main>\n</body>\n</html>\n`
  );
}

export interface LoginView {
  sealedRequest: string;
  csrf: string;
  clientName: string | undefined;
  redirectUri: string;
  error?: string | undefined;
  username?: string | undefined;
}

/** The login form. All dynamic values are escaped; there is never a password value. */
export function renderLoginPage(view: LoginView): string {
  const target = URL.canParse(view.redirectUri) ? new URL(view.redirectUri).origin : view.redirectUri;
  const client = view.clientName ?? "An unnamed client";
  const parts = [
    "<h1>Sign in to mcp-s3</h1>",
    `<p><strong>${escapeHtml(client)}</strong> is requesting read-only access to the S3 workspace.</p>`,
    `<p class="muted">After signing in you will be sent to <strong>${escapeHtml(target)}</strong>. ` +
      "Only continue if you started this connection yourself.</p>",
  ];
  if (view.error !== undefined) parts.push(`<p class="error" role="alert">${escapeHtml(view.error)}</p>`);
  parts.push(
    `<form method="post" action="${LOGIN_PATH}">`,
    `<input type="hidden" name="request" value="${escapeHtml(view.sealedRequest)}">`,
    `<input type="hidden" name="csrf" value="${escapeHtml(view.csrf)}">`,
    '<label for="username">Username</label>',
    `<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="${MAX_FIELD_LENGTH}" required autofocus value="${escapeHtml(view.username ?? "")}">`,
    '<label for="password">Password</label>',
    `<input id="password" name="password" type="password" autocomplete="current-password" maxlength="${MAX_FIELD_LENGTH}" required>`,
    '<button type="submit">Sign in</button>',
    "</form>",
  );
  return page("Sign in - mcp-s3", parts.join("\n"));
}

/** A page with a message and no form. */
export function renderMessagePage(title: string, message: string): string {
  return page(`${title} - mcp-s3`, `<h1>${escapeHtml(title)}</h1>\n<p>${escapeHtml(message)}</p>`);
}

// --- credentials -------------------------------------------------------------

/**
 * Compares a username/password pair with the configured admin account in constant time.
 * Both sides are reduced to HMAC-SHA256 digests (random per-process key) before
 * crypto.timingSafeEqual, so inputs of any length are compared without throwing and without
 * timing that depends on the secret's length or content. Both comparisons always run.
 */
export class CredentialChecker {
  private readonly key: KeyObject = createSecretKey(randomBytes(32));
  private readonly username: Buffer;
  private readonly password: Buffer;

  constructor(username: Secret, password: Secret) {
    this.username = this.digest(username.reveal());
    this.password = this.digest(password.reveal());
  }

  private digest(value: string): Buffer {
    return createHmac("sha256", this.key).update(value, "utf8").digest();
  }

  check(username: string, password: string): boolean {
    const userOk = timingSafeEqual(this.digest(username), this.username);
    const passOk = timingSafeEqual(this.digest(password), this.password);
    return userOk && passOk;
  }
}

// --- rate limiting -----------------------------------------------------------

/**
 * Fixed-window limit on failed logins, per client IP (IPv6 per /64, see rateLimitKey) and in
 * total. In memory only (reset on restart). Successful logins clear the IP's counter. The
 * total limit caps distributed guessing at LOGIN_MAX_FAILURES_TOTAL per window; while it is
 * reached, logins from every IP are refused until the window ends (existing tokens keep
 * working).
 */
export class LoginRateLimiter extends FailureRateLimiter {
  constructor(now: () => number = () => Date.now()) {
    super({ perKey: LOGIN_MAX_FAILURES_PER_IP, total: LOGIN_MAX_FAILURES_TOTAL, windowSeconds: LOGIN_WINDOW_SECONDS }, now);
  }
}

// --- controller --------------------------------------------------------------

const LoginForm = z.object({
  request: z.string().min(1).max(8192),
  csrf: z.string().min(1).max(128),
  username: z.string().max(MAX_FIELD_LENGTH),
  password: z.string().max(MAX_FIELD_LENGTH),
});

/** Value of one cookie from a Cookie header (no decoding; our values are base64url). */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (header === undefined) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

export interface LoginControllerOptions {
  http: HttpConfig;
  provider: S3OAuthProvider;
  csrfKey: KeyObject;
  limiter?: LoginRateLimiter;
}

export class LoginController implements LoginPageRenderer {
  private readonly provider: S3OAuthProvider;
  private readonly csrfKey: KeyObject;
  private readonly credentials: CredentialChecker;
  private readonly limiter: LoginRateLimiter;
  private readonly publicOrigin: string;
  private readonly secureCookie: boolean;
  private readonly cookieName: string;

  constructor(opts: LoginControllerOptions) {
    this.provider = opts.provider;
    this.csrfKey = opts.csrfKey;
    this.credentials = new CredentialChecker(opts.http.username, opts.http.password);
    this.limiter = opts.limiter ?? new LoginRateLimiter();
    this.publicOrigin = opts.http.publicUrl.origin;
    this.secureCookie = opts.http.publicUrl.protocol === "https:";
    this.cookieName = csrfCookieName(this.secureCookie);
  }

  private csrfFor(nonce: string, sealedRequest: string): string {
    return hmacBase64url(this.csrfKey, `${nonce}.${sealedRequest}`);
  }

  /** The browser's CSRF nonce (valid existing one, or a new one). */
  private readNonce(req: Request): string | undefined {
    const value = readCookie(req.headers.cookie, this.cookieName);
    return value !== undefined && CSRF_NONCE.test(value) ? value : undefined;
  }

  /**
   * The browser's CSRF nonce, creating one if it has none. The cookie is (re)sent every
   * time, so its Max-Age always covers the form being rendered.
   */
  private ensureNonce(req: Request, res: Response): string {
    const nonce = this.readNonce(req) ?? randomBytes(32).toString("base64url");
    res.setHeader(
      "Set-Cookie",
      `${this.cookieName}=${nonce}; Path=/; Max-Age=${CSRF_COOKIE_MAX_AGE_SECONDS}; HttpOnly; SameSite=Lax${this.secureCookie ? "; Secure" : ""}`,
    );
    return nonce;
  }

  private sendLogin(res: Response, status: number, view: LoginView): void {
    const redirect = redirectOriginSource(view.redirectUri);
    setPageHeaders(res, redirect === undefined ? "'self'" : `'self' ${redirect}`);
    res.status(status).type("html").send(renderLoginPage(view));
  }

  private sendMessage(res: Response, status: number, title: string, message: string): void {
    setPageHeaders(res, "'none'");
    res.status(status).type("html").send(renderMessagePage(title, message));
  }

  /** Called by the provider from GET/POST /authorize once the client and redirect URI are valid. */
  showLogin(res: Response, sealedRequest: string, request: LoginRequest): void {
    const nonce = this.ensureNonce(res.req, res);
    this.sendLogin(res, 200, {
      sealedRequest,
      csrf: this.csrfFor(nonce, sealedRequest),
      clientName: request.n,
      redirectUri: request.r,
    });
  }

  /** POST /login. */
  handlePost(req: Request, res: Response): void {
    const invalid = (): void => {
      this.sendMessage(
        res,
        403,
        "Sign-in form expired",
        "This sign-in form is invalid or has expired. Go back to your application and start the connection again.",
      );
    };

    // Cross-site requests are refused before anything else is looked at. "Origin: null" is
    // what browsers send when a referrer policy of no-referrer applies (e.g. forced by an
    // extension or enterprise policy); it is accepted only together with
    // "Sec-Fetch-Site: same-origin". The CSRF cookie and HMAC below are required either way.
    const fetchSite = req.headers["sec-fetch-site"];
    if (fetchSite !== undefined && fetchSite !== "same-origin") {
      invalid();
      return;
    }
    const origin = req.headers.origin;
    const originOk = origin === undefined || origin === this.publicOrigin || (origin === "null" && fetchSite === "same-origin");
    if (!originOk) {
      invalid();
      return;
    }

    const body: unknown = req.body;
    const form = LoginForm.safeParse(body);
    if (!form.success) {
      invalid();
      return;
    }
    const { request: sealed, csrf, username, password } = form.data;

    const nonce = this.readNonce(req);
    const expected = nonce === undefined ? undefined : this.csrfFor(nonce, sealed);
    if (expected === undefined || !constantTimeEqual(expected, csrf)) {
      invalid();
      return;
    }

    const request = this.provider.openLoginRequest(sealed);
    if (request === undefined) {
      invalid();
      return;
    }

    const ip = req.ip ?? "unknown";
    const wait = this.limiter.retryAfter(ip);
    if (wait > 0) {
      log.warn("login rate limited", { ip });
      res.setHeader("Retry-After", String(wait));
      this.sendMessage(res, 429, "Too many attempts", `Too many failed sign-in attempts. Try again in ${Math.ceil(wait / 60)} minute(s).`);
      return;
    }

    if (!this.credentials.check(username, password)) {
      this.limiter.recordFailure(ip);
      // Never log the attempted username: users sometimes type their password into it.
      log.warn("login failed", { ip });
      this.sendLogin(res, 401, {
        sealedRequest: sealed,
        csrf,
        clientName: request.n,
        redirectUri: request.r,
        error: "Invalid username or password.",
        username,
      });
      return;
    }

    this.limiter.recordSuccess(ip);
    log.info("login succeeded", { ip });
    const target = new URL(request.r);
    target.searchParams.set("code", this.provider.issueAuthorizationCode(request));
    if (request.s !== undefined) target.searchParams.set("state", request.s);
    res.setHeader("Cache-Control", "no-store");
    // The redirect carries the code: no referrer to the callback origin (the page policy
    // same-origin already ensures that; this response header makes it explicit).
    res.setHeader("Referrer-Policy", "no-referrer");
    res.redirect(303, target.href);
  }
}
