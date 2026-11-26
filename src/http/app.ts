import type { Server } from "node:http";

import { metadataHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/metadata.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { OAuthProtectedResourceMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import express, { type ErrorRequestHandler, type Express, type Request, type RequestHandler, type Response } from "express";

import type { Config } from "../config.js";
import { errorLogFields } from "../errors.js";
import { log } from "../logger.js";
import { buildServer, SERVER_NAME } from "../server.js";
import type { Storage } from "../storage.js";
import { clientAuthPrecheck, createClientAuthLimiter } from "./clientAuth.js";
import { LOOPBACK_HOSTNAMES, type HttpConfig } from "./config.js";
import { LOGIN_PATH, LoginController } from "./login.js";
import { deriveOAuthKeys, S3OAuthProvider, SCOPE_READ, SUPPORTED_SCOPES } from "./oauth.js";

/**
 * Streamable HTTP transport with OAuth (PLAN.md section 9, Fase 3).
 *
 * Endpoints:
 *   POST /mcp                                     MCP (stateless; bearer token required)
 *   GET  /.well-known/oauth-protected-resource[/mcp]   protected resource metadata (RFC 9728)
 *   GET  /.well-known/oauth-authorization-server  authorization server metadata (RFC 8414)
 *   GET|POST /authorize, POST /login              authorization + admin login page
 *   POST /token, /register, /revoke               token, dynamic client registration, revocation
 *   GET  /healthz                                 liveness (no details)
 *
 * The MCP endpoint is stateless: each POST gets a fresh McpServer + transport, all sharing one
 * Storage (one S3Client). Nothing session-related is kept in memory, so restarts and multiple
 * instances need no sticky sessions.
 */

export const MCP_PATH = "/mcp";
const FORM_BODY_LIMIT = "16kb";
/** Same limit the SDK's createMcpExpressApp uses (express.json default). */
const MCP_BODY_LIMIT = "100kb";

export interface HttpAppOptions {
  config: Config;
  http: HttpConfig;
  /** Shared by every HTTP request. */
  storage: Storage;
}

/** Host header names accepted (DNS rebinding protection): the public host plus loopback names. */
export function allowedHostnames(http: HttpConfig): string[] {
  return [...new Set([http.publicUrl.hostname, ...LOOPBACK_HOSTNAMES])];
}

const securityHeaders: RequestHandler = (_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
};

/** CORS for /mcp: bearer tokens, no cookies, so any origin may call it with a valid token. */
const mcpCors: RequestHandler = (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version");
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-ID",
    );
    res.setHeader("Access-Control-Max-Age", "600");
    res.status(204).end();
    return;
  }
  next();
};

function statusOf(err: unknown): number | undefined {
  if (typeof err !== "object" || err === null) return undefined;
  const status = "status" in err ? err.status : "statusCode" in err ? err.statusCode : undefined;
  return typeof status === "number" && status >= 400 && status < 600 ? status : undefined;
}

/**
 * Errors from the /mcp JSON body parser (which runs after bearer authentication, so only
 * authenticated requests get here) as JSON-RPC errors: -32700 for malformed JSON, -32600 for
 * other body problems (too large, unsupported charset). Other errors go to errorHandler.
 */
const mcpBodyErrorHandler: ErrorRequestHandler = (err: unknown, _req, res, next) => {
  const type = typeof err === "object" && err !== null && "type" in err ? err.type : undefined;
  if (typeof type !== "string" || !/^(?:entity|charset|encoding)\./.test(type)) {
    next(err);
    return;
  }
  const parseFailed = type === "entity.parse.failed";
  const status = parseFailed ? 400 : (statusOf(err) ?? 400);
  log.debug("MCP request body rejected", { status });
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res
    .status(status)
    .json({ jsonrpc: "2.0", error: parseFailed ? { code: -32700, message: "Parse error" } : { code: -32600, message: "Invalid request body" }, id: null });
};

/** Final error handler: generic JSON, never an error message or stack trace. */
// eslint-disable-next-line @typescript-eslint/no-unused-vars -- Express recognizes error handlers by their four parameters.
const errorHandler: ErrorRequestHandler = (err: unknown, _req, res, _next) => {
  const status = statusOf(err) ?? 500;
  if (status >= 500) log.warn("HTTP request failed", { status, ...errorLogFields(err) });
  else log.debug("HTTP request rejected", { status });
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.setHeader("Cache-Control", "no-store");
  res
    .status(status)
    .json(status >= 500 ? { error: "server_error", error_description: "Internal server error" } : { error: "invalid_request", error_description: "Malformed request" });
};

export function createHttpApp({ config, http, storage }: HttpAppOptions): Express {
  if (config.tokenKey === undefined) throw new Error("MCP_S3_TOKEN_KEY is required for the HTTP transport");
  const resourceUrl = new URL(MCP_PATH, http.publicUrl);
  const keys = deriveOAuthKeys(config.tokenKey, http.username, http.password);
  const provider = new S3OAuthProvider({ http, keys, resourceUrl });
  const login = new LoginController({ http, provider, csrfKey: keys.csrf });
  provider.setLoginPageRenderer(login);

  // Host header validation (DNS rebinding protection) runs first. Bodies are parsed per route:
  // the SDK's OAuth handlers bring their own parsers, /login and /token get a small form
  // parser, and /mcp parses JSON only after authentication.
  const app = express();
  app.use(hostHeaderValidation(allowedHostnames(http)));
  app.disable("x-powered-by");
  app.set("trust proxy", http.trustProxyHops);
  app.use(securityHeaders);

  app.get("/healthz", (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json({ status: "ok" });
  });

  // --- OAuth authorization server --------------------------------------------
  const formParser = express.urlencoded({ extended: false, limit: FORM_BODY_LIMIT, parameterLimit: 20 });
  app.use(["/token", "/revoke"], formParser, clientAuthPrecheck(provider.clientsStore, createClientAuthLimiter()));
  app.post(LOGIN_PATH, formParser, (req, res) => {
    login.handlePost(req, res);
  });
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: http.publicUrl,
      resourceServerUrl: resourceUrl,
      scopesSupported: [...SUPPORTED_SCOPES],
      resourceName: SERVER_NAME,
    }),
  );
  // The SDK serves the path-specific /.well-known/oauth-protected-resource/mcp; clients that
  // only try the root URL get the same document.
  const resourceMetadata: OAuthProtectedResourceMetadata = {
    resource: resourceUrl.href,
    authorization_servers: [http.publicUrl.href],
    scopes_supported: [...SUPPORTED_SCOPES],
    resource_name: SERVER_NAME,
  };
  app.use("/.well-known/oauth-protected-resource", metadataHandler(resourceMetadata));

  // --- MCP endpoint ----------------------------------------------------------
  const bearer = requireBearerAuth({
    verifier: provider,
    requiredScopes: [SCOPE_READ],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl),
    expectedResource: resourceUrl,
  });

  async function handleMcp(req: Request, res: Response): Promise<void> {
    if (req.method !== "POST") {
      // Stateless server: no standalone SSE stream (GET) and no sessions to delete (DELETE).
      res.setHeader("Allow", "POST, OPTIONS");
      res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
      return;
    }
    const { server } = buildServer(config, { storage });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      transport.close().catch(() => undefined);
      server.close().catch(() => undefined);
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      log.warn("MCP request failed", errorLogFields(err));
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      }
    }
  }

  // JSON is parsed only after bearer authentication.
  app.all(MCP_PATH, mcpCors, bearer, express.json({ limit: MCP_BODY_LIMIT }), (req, res) => handleMcp(req, res));
  app.use(MCP_PATH, mcpBodyErrorHandler);

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });
  app.use(errorHandler);
  return app;
}

/** Create the app and listen on MCP_S3_HTTP_HOST:MCP_S3_HTTP_PORT. */
export function startHttpServer(opts: HttpAppOptions): Promise<Server> {
  const app = createHttpApp(opts);
  return new Promise((resolve, reject) => {
    const server = app.listen(opts.http.port, opts.http.host, (err?: Error) => {
      if (err === undefined) resolve(server);
      else reject(err);
    });
  });
}
