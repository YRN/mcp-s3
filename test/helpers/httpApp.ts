import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { setAuditSink } from "../../src/audit.js";
import { loadConfig } from "../../src/config.js";
import { createHttpApp } from "../../src/http/app.js";
import { loadHttpConfig } from "../../src/http/config.js";
import { setLogLevel } from "../../src/logger.js";
import { Storage } from "../../src/storage.js";
import { FakeS3 } from "./fakeS3.js";
import { LEAK_CONTENT, PNG_1X1, SECRET_CONTENT } from "./fixtures.js";
import { ADMIN_PASSWORD, ADMIN_USERNAME, OAuthTestClient, STATIC_CLIENT_ID, STATIC_CLIENT_SECRET } from "./oauth.js";

export const HTTP_BUCKET = "acme-secret-bucket-7f3a";
export const HTTP_ROOT = "claude-workspace/";
/** Public origin the app believes in. The test server listens on a random port instead. */
export const PUBLIC_ORIGIN = "http://localhost:3000";

export interface AppOptions {
  /** Extra / overriding MCP_S3_* variables for loadHttpConfig. */
  env?: Record<string, string | undefined>;
  /** Public origin (issuer). Default PUBLIC_ORIGIN. */
  origin?: string;
  /** Base64 MCP_S3_TOKEN_KEY. Default: a fresh random key. */
  tokenKey?: string;
  /** Use a static OAuth client (STATIC_CLIENT_ID / STATIC_CLIENT_SECRET). */
  staticClient?: boolean;
  fake?: FakeS3;
}

export interface RunningApp {
  /** http://127.0.0.1:<port> */
  base: string;
  origin: string;
  oauth: OAuthTestClient;
  fake: FakeS3;
  tokenKey: string;
  close(): Promise<void>;
}

export function seedFake(fake: FakeS3): void {
  fake.put(`${HTTP_ROOT}a.txt`, "hello from smoke", { contentType: "text/plain" });
  fake.put(`${HTTP_ROOT}sub/b.txt`, "bee\n", { contentType: "text/plain" });
  fake.put(`${HTTP_ROOT}img.png`, PNG_1X1, { contentType: "image/png" });
  fake.put("claude-workspace-backup/leak.txt", LEAK_CONTENT, { contentType: "text/plain" });
  fake.put("outside/secret.txt", SECRET_CONTENT, { contentType: "text/plain" });
}

/** Silence server logs and audit lines for the duration of a test file. */
export function quietServer(): () => void {
  setLogLevel("ERROR");
  setAuditSink(() => undefined);
  return () => {
    setLogLevel("INFO");
    setAuditSink(undefined);
  };
}

export async function startApp(opts: AppOptions = {}): Promise<RunningApp> {
  const origin = opts.origin ?? PUBLIC_ORIGIN;
  const tokenKey = opts.tokenKey ?? randomBytes(32).toString("base64");
  const config = loadConfig({
    S3_BUCKET: HTTP_BUCKET,
    S3_ROOT_PREFIX: HTTP_ROOT,
    AWS_REGION: "us-east-1",
    MCP_S3_TRANSPORT: "http",
    MCP_S3_TOKEN_KEY: tokenKey,
  });
  const http = loadHttpConfig({
    MCP_S3_AUTH_USERNAME: ADMIN_USERNAME,
    MCP_S3_AUTH_PASSWORD: ADMIN_PASSWORD,
    MCP_S3_PUBLIC_URL: origin,
    ...(opts.staticClient === true
      ? { MCP_S3_OAUTH_CLIENT_ID: STATIC_CLIENT_ID, MCP_S3_OAUTH_CLIENT_SECRET: STATIC_CLIENT_SECRET }
      : {}),
    ...opts.env,
  });

  const fake = opts.fake ?? new FakeS3(HTTP_BUCKET);
  if (opts.fake === undefined) seedFake(fake);
  const app = createHttpApp({ config, http, storage: new Storage(fake.client, config.bucket) });

  const server: Server = await new Promise((resolve, reject) => {
    const s = app.listen(0, "127.0.0.1", (err?: Error) => {
      if (err === undefined) resolve(s);
      else reject(err);
    });
  });
  const base = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  return {
    base,
    origin,
    oauth: new OAuthTestClient(base, origin),
    fake,
    tokenKey,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => {
          resolve();
        }));
      if (opts.fake === undefined) fake.restore();
    },
  };
}
