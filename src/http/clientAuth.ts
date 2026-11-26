import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { RequestHandler, Response } from "express";

import { log } from "../logger.js";
import { FailureRateLimiter } from "./rateLimit.js";
import { constantTimeEqual } from "./sealed.js";

/**
 * Middleware for the token and revocation endpoints, installed in front of the SDK handlers.
 *
 * 1. Accepts HTTP Basic client authentication (client_secret_basic, RFC 6749 section 2.3.1)
 *    by moving the credentials into the form body, which is where the SDK reads them.
 * 2. Checks the client secret in constant time. The SDK compares secrets with `!==`; a wrong
 *    secret is refused here, so the SDK's comparison only ever runs on the correct secret.
 * 3. Limits failed client authentications per client IP (IPv6 per /64): after
 *    CLIENT_AUTH_MAX_FAILURES_PER_IP failures in CLIENT_AUTH_WINDOW_SECONDS, requests that
 *    carry client credentials get 429 with Retry-After. (The SDK's own rate limit sits behind
 *    this middleware and never sees the refused requests.)
 *
 * Unknown clients and missing credentials are left to the SDK, which answers invalid_client
 * or invalid_request itself.
 */

/** Failed client authentications allowed per client IP per window. */
export const CLIENT_AUTH_MAX_FAILURES_PER_IP = 10;
export const CLIENT_AUTH_WINDOW_SECONDS = 15 * 60;

/** Limiter for failed client authentication at /token and /revoke (per IP, no total limit). */
export function createClientAuthLimiter(now?: () => number): FailureRateLimiter {
  return new FailureRateLimiter({ perKey: CLIENT_AUTH_MAX_FAILURES_PER_IP, windowSeconds: CLIENT_AUTH_WINDOW_SECONDS }, now);
}

interface BasicCredentials {
  id: string;
  secret: string;
}

function formDecode(value: string): string | undefined {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return undefined;
  }
}

/**
 * Parse an `Authorization: Basic` header. undefined: no Basic header; null: malformed.
 * Client ID and secret are form-urlencoded before base64 encoding (RFC 6749 section 2.3.1).
 */
export function parseBasicAuth(header: string | undefined): BasicCredentials | null | undefined {
  if (header === undefined) return undefined;
  const match = /^Basic[ ]+([A-Za-z0-9+/]+={0,2})[ ]*$/i.exec(header);
  if (match === null) return /^Basic(?:\s|$)/i.test(header) ? null : undefined;
  const decoded = Buffer.from(match[1] ?? "", "base64").toString("utf8");
  const colon = decoded.indexOf(":");
  if (colon < 0) return null;
  const id = formDecode(decoded.slice(0, colon));
  const secret = formDecode(decoded.slice(colon + 1));
  if (id === undefined || secret === undefined || id === "") return null;
  return { id, secret };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function refuse(res: Response, status: 400 | 401 | 429, error: string, description: string, basic: boolean): void {
  res.setHeader("Cache-Control", "no-store");
  // Same CORS policy as the SDK's token endpoint, so browser clients can read the error.
  res.setHeader("Access-Control-Allow-Origin", "*");
  if (basic && status === 401) res.setHeader("WWW-Authenticate", 'Basic realm="mcp-s3"');
  res.status(status).json({ error, error_description: description });
}

export function clientAuthPrecheck(
  store: OAuthRegisteredClientsStore,
  limiter: FailureRateLimiter = createClientAuthLimiter(),
): RequestHandler {
  return async (req, res, next) => {
    const raw: unknown = req.body;
    const body: Record<string, unknown> = isRecord(raw) ? raw : {};
    const ip = req.ip ?? "unknown";

    const authorization = req.headers.authorization;
    const carriesSecret = /^Basic(?:\s|$)/i.test(authorization ?? "") || body.client_secret !== undefined;
    if (carriesSecret) {
      const wait = limiter.retryAfter(ip);
      if (wait > 0) {
        log.warn("client authentication rate limited", { ip });
        res.setHeader("Retry-After", String(wait));
        refuse(res, 429, "too_many_requests", "Too many failed client authentication attempts, retry later", false);
        return;
      }
    }

    const basic = parseBasicAuth(authorization);
    if (basic === null) {
      limiter.recordFailure(ip);
      refuse(res, 401, "invalid_client", "Malformed Basic authorization header", true);
      return;
    }
    if (basic !== undefined) {
      if (body.client_secret !== undefined || (body.client_id !== undefined && body.client_id !== basic.id)) {
        refuse(res, 400, "invalid_request", "Use only one client authentication method", true);
        return;
      }
      body.client_id = basic.id;
      body.client_secret = basic.secret;
      req.body = body;
    }

    const clientId = body.client_id;
    const secret = body.client_secret;
    if (typeof clientId === "string" && typeof secret === "string") {
      const client = await store.getClient(clientId);
      if (client?.client_secret !== undefined && !constantTimeEqual(client.client_secret, secret)) {
        limiter.recordFailure(ip);
        log.warn("client authentication failed", { ip });
        refuse(res, 401, "invalid_client", "Client authentication failed", basic !== undefined);
        return;
      }
    }
    next();
  };
}
