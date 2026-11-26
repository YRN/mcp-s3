#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { ConfigError, loadConfig, type Config } from "./config.js";
import { errorLogFields } from "./errors.js";
import { startHttpServer } from "./http/app.js";
import { isLoopbackBindHost, loadHttpConfig, type HttpConfig } from "./http/config.js";
import { log, setLogLevel } from "./logger.js";
import { buildServer, SERVER_VERSION } from "./server.js";
import { createS3Client, Storage } from "./storage.js";

// stdout carries the MCP stdio protocol. Nothing in this process may write to it except the
// transport; every log line goes to stderr.

interface LoadedConfig {
  config: Config;
  /** Present only when MCP_S3_TRANSPORT=http. */
  http: HttpConfig | undefined;
}

/** Load the core config and, for MCP_S3_TRANSPORT=http, the HTTP config; report all problems at once. */
function loadConfigOrExit(): LoadedConfig {
  const issues: string[] = [];
  const collect = (load: () => void): void => {
    try {
      load();
    } catch (err) {
      if (!(err instanceof ConfigError)) {
        console.error("[mcp-s3] Failed to load configuration");
        process.exit(1);
      }
      issues.push(...err.issues);
    }
  };

  let config: Config | undefined;
  let http: HttpConfig | undefined;
  collect(() => {
    config = loadConfig(process.env);
  });
  if ((config?.transport ?? process.env.MCP_S3_TRANSPORT) === "http") {
    collect(() => {
      http = loadHttpConfig(process.env);
    });
  }
  if (config === undefined || issues.length > 0) {
    console.error(`[mcp-s3] ${new ConfigError(issues).message}`);
    process.exit(1);
  }
  return { config, http };
}

async function main(): Promise<void> {
  const { config, http } = loadConfigOrExit();
  setLogLevel(config.logLevel);

  if (config.transport === "http") {
    if (http === undefined) throw new Error("HTTP configuration missing");
    await runHttp(config, http);
    return;
  }
  await runStdio(config);
}

async function runStdio(config: Config): Promise<void> {
  if (config.allowDelete && config.readOnly) {
    log.warn("MCP_S3_ALLOW_DELETE=true has no effect while MCP_S3_READ_ONLY=true");
  }

  const { server, registered, tools } = buildServer(config);
  const transport = new StdioServerTransport();

  let closing = false;
  const shutdown = (reason: string): void => {
    if (closing) return;
    closing = true;
    log.info("shutting down", { reason });
    server
      .close()
      .catch((err: unknown) => {
        log.warn("error while closing", errorLogFields(err));
      })
      .finally(() => process.exit(0));
  };

  process.on("SIGINT", () => {
    shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    shutdown("SIGTERM");
  });
  process.stdin.on("end", () => {
    shutdown("stdin closed");
  });

  await server.connect(transport);

  // Never log the bucket name, root prefix, endpoint, credentials, or the token key.
  log.info("server started", {
    version: SERVER_VERSION,
    transport: config.transport,
    readOnly: config.readOnly,
    readTools: registered.read,
    writeTools: registered.write,
    deleteTools: registered.delete,
    tools: tools.join(","),
    tokenKey: config.tokenKey === undefined ? "random per process" : "MCP_S3_TOKEN_KEY",
  });
}

async function runHttp(config: Config, http: HttpConfig): Promise<void> {
  // One Storage (one S3Client, one connection pool) shared by every HTTP request.
  const storage = new Storage(createS3Client(config), config.bucket);
  const { registered, tools } = buildServer(config, { storage });
  const server = await startHttpServer({ config, http, storage });

  let closing = false;
  const shutdown = (reason: string): void => {
    if (closing) return;
    closing = true;
    log.info("shutting down", { reason });
    server.close(() => process.exit(0));
    server.closeIdleConnections();
    // In-flight requests get a moment to finish, then the process exits regardless.
    setTimeout(() => {
      server.closeAllConnections();
      process.exit(0);
    }, 5_000).unref();
  };
  process.on("SIGINT", () => {
    shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    shutdown("SIGTERM");
  });

  // The public URL is not secret; the bucket, root prefix, credentials, and keys are never logged.
  log.info("server started", {
    version: SERVER_VERSION,
    transport: config.transport,
    listen: `${http.host}:${http.port}`,
    publicUrl: http.publicUrl.origin,
    readOnly: config.readOnly,
    readTools: registered.read,
    writeTools: registered.write,
    deleteTools: registered.delete,
    tools: tools.join(","),
    staticClient: http.staticClient !== undefined,
    dynamicRegistration: http.dynamicRegistration,
    trustProxyHops: http.trustProxyHops,
    tokenKey: "MCP_S3_TOKEN_KEY",
  });

  if (!isLoopbackBindHost(http.host) && http.publicUrl.protocol === "http:") {
    // Allowed because a container must bind 0.0.0.0, but risky on any other host.
    log.warn(
      "MCP_S3_HTTP_HOST is not a loopback address while MCP_S3_PUBLIC_URL uses plain http: the server is reachable " +
        "from the network without TLS (passwords and tokens in clear text), and the Host check accepts loopback names " +
        "such as 'Host: localhost'. Only do this inside a container whose port is published on 127.0.0.1 " +
        "(e.g. docker run -p 127.0.0.1:3000:3000), or behind an HTTPS reverse proxy with an https MCP_S3_PUBLIC_URL.",
      { listen: `${http.host}:${String(http.port)}` },
    );
  }
}

main().catch((err: unknown) => {
  log.error("fatal error", errorLogFields(err));
  process.exit(1);
});
