import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";

import type { S3Client } from "@aws-sdk/client-s3";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CallToolResultSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { OAuthClientInformationMixed, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { LEAK_CONTENT, ROOT_PREFIX, SECRET_CONTENT } from "../helpers/fixtures.js";
import { expectToolError, ListObjectsResult, onlyText, parseJson } from "../helpers/mcp.js";
import {
  assertMinioReady,
  createSeededBucket,
  destroyBucket,
  MINIO_ENDPOINT,
  MINIO_REGION,
  MINIO_ROOT_PASSWORD,
  MINIO_ROOT_USER,
  minioClient,
  PROJECT_DIR,
} from "../helpers/minio.js";
import {
  ADMIN_PASSWORD,
  ADMIN_USERNAME,
  hiddenField,
  LOOPBACK_REDIRECT,
  OAuthTestClient,
  pkce,
  STATIC_CLIENT_ID,
  STATIC_CLIENT_SECRET,
  toolText,
} from "../helpers/oauth.js";

const SERVER_ENTRY = join(PROJECT_DIR, "dist", "index.js");
const READ_TOOLS = ["get_object_info", "list_objects", "read_object", "search_objects"];
const TOKEN_KEY = randomBytes(32).toString("base64");

let admin: S3Client;
let bucket = "";
let bucketCreated = false;

beforeAll(async () => {
  if (!existsSync(SERVER_ENTRY)) {
    throw new Error(`${SERVER_ENTRY} does not exist; run "npm run build" first (npm run test:e2e does this).`);
  }
  await assertMinioReady();
  admin = minioClient();
  bucket = await createSeededBucket(admin, "mcp-s3-e2e-http");
  bucketCreated = true;
});

afterAll(async () => {
  if (bucketCreated) await destroyBucket(admin, bucket);
});

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      probe.close(() => {
        resolve(port);
      });
    });
  });
}

function serverEnv(overrides: Record<string, string | undefined>): Record<string, string> {
  const merged: Record<string, string | undefined> = {
    ...getDefaultEnvironment(),
    S3_BUCKET: bucket,
    S3_ROOT_PREFIX: ROOT_PREFIX,
    AWS_REGION: MINIO_REGION,
    S3_ENDPOINT_URL: MINIO_ENDPOINT,
    S3_FORCE_PATH_STYLE: "true",
    AWS_ACCESS_KEY_ID: MINIO_ROOT_USER,
    AWS_SECRET_ACCESS_KEY: MINIO_ROOT_PASSWORD,
    AWS_CONFIG_FILE: join(PROJECT_DIR, "test", "e2e", "no-aws-config"),
    AWS_SHARED_CREDENTIALS_FILE: join(PROJECT_DIR, "test", "e2e", "no-aws-credentials"),
    AWS_EC2_METADATA_DISABLED: "true",
    MCP_S3_TRANSPORT: "http",
    MCP_S3_TOKEN_KEY: TOKEN_KEY,
    MCP_S3_AUTH_USERNAME: ADMIN_USERNAME,
    MCP_S3_AUTH_PASSWORD: ADMIN_PASSWORD,
    ...overrides,
  };
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(merged)) if (value !== undefined) env[name] = value;
  return env;
}

interface ServerProcess {
  child: ChildProcessWithoutNullStreams;
  base: string;
  oauth: OAuthTestClient;
  stdout(): string;
  stderr(): string;
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  stop(): Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

function spawnProcess(env: Record<string, string>): Omit<ServerProcess, "base" | "oauth"> {
  const child = spawn(process.execPath, [SERVER_ENTRY], { cwd: PROJECT_DIR, env, stdio: "pipe" });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
  child.stdin.on("error", () => undefined);
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.on("exit", (code, signal) => {
      resolve({ code, signal });
    });
  });
  return {
    child,
    stdout: () => stdout,
    stderr: () => stderr,
    exited,
    stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
      return exited;
    },
  };
}

const servers: ServerProcess[] = [];

/** Start the HTTP server on a random port and wait until it logs "server started". */
async function startServer(overrides: Record<string, string | undefined> = {}): Promise<ServerProcess> {
  const port = await freePort();
  const base = `http://localhost:${String(port)}`;
  const proc = spawnProcess(
    serverEnv({ MCP_S3_HTTP_PORT: String(port), MCP_S3_PUBLIC_URL: base, MCP_S3_HTTP_HOST: "127.0.0.1", ...overrides }),
  );
  const server: ServerProcess = { ...proc, base, oauth: new OAuthTestClient(base) };
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`server did not start in time. stderr: ${proc.stderr()}`));
    }, 20_000);
    const check = setInterval(() => {
      if (proc.stderr().includes("server started")) {
        clearTimeout(timer);
        clearInterval(check);
        resolve();
      }
    }, 25);
    void proc.exited.then(() => {
      clearTimeout(timer);
      clearInterval(check);
      if (!proc.stderr().includes("server started")) reject(new Error(`server exited early. stderr: ${proc.stderr()}`));
    });
  });
  return server;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.stop()));
});

async function expectStartupFailure(overrides: Record<string, string | undefined>, mention: string, secret?: string) {
  const proc = spawnProcess(serverEnv({ MCP_S3_HTTP_PORT: String(await freePort()), ...overrides }));
  const exit = await proc.exited;
  expect(exit.code, `stderr: ${proc.stderr()}`).not.toBe(0);
  expect(exit.code).not.toBeNull();
  expect(proc.stderr()).toContain(mention);
  expect(proc.stderr()).toMatch(/Invalid configuration/);
  expect(proc.stdout()).toBe("");
  if (secret !== undefined) expect(proc.stderr()).not.toContain(secret);
  expect(proc.stderr()).not.toContain(TOKEN_KEY);
  expect(proc.stderr()).not.toContain(bucket);
  expect(proc.stderr()).not.toMatch(/\n\s+at .*\(.*:\d+:\d+\)/); // no stack trace
}

// --- startup behaviour ---------------------------------------------------------

describe("HTTP server: startup", () => {
  it("starts, writes nothing to stdout, and never logs secrets, bucket, or root prefix", async () => {
    const s = await startServer({ MCP_S3_OAUTH_CLIENT_ID: STATIC_CLIENT_ID, MCP_S3_OAUTH_CLIENT_SECRET: STATIC_CLIENT_SECRET });
    // Exercise the server a bit, including a failed login and a tool call.
    const reg = await s.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT], token_endpoint_auth_method: "none" });
    const id = String(reg.json.client_id);
    const form = await s.oauth.authorize(id, LOOPBACK_REDIRECT, "x".repeat(43));
    await s.oauth.login(form, ADMIN_USERNAME, "wrong-password-xyz");
    const t = await s.oauth.obtainTokens(id, LOOPBACK_REDIRECT);
    await s.oauth.callTool(t.access, "read_object", { path: "a.txt" });

    const exit = await s.stop();
    expect(exit.code).toBe(0);
    expect(s.stdout()).toBe("");
    const err = s.stderr();
    expect(err).toContain("server started");
    for (const secret of [ADMIN_PASSWORD, STATIC_CLIENT_SECRET, TOKEN_KEY, MINIO_ROOT_PASSWORD, bucket, ROOT_PREFIX, "wrong-password-xyz", t.access, t.refresh]) {
      expect(err, secret).not.toContain(secret);
    }
    // Audit: one line for the one tool call, relative path only.
    const audit = err.split("\n").filter((line) => line.includes('"type":"audit"'));
    expect(audit).toHaveLength(1);
    expect(JSON.parse(audit[0] ?? "{}")).toMatchObject({ tool: "read_object", path: "a.txt", result: "ok", bytes: 13 });
  });

  it("warns on stderr when binding a non-loopback host while MCP_S3_PUBLIC_URL is plain http", async () => {
    const s = await startServer({ MCP_S3_HTTP_HOST: "0.0.0.0" });
    const exit = await s.stop();
    expect(exit.code).toBe(0);
    expect(s.stderr()).toMatch(/WARN .*MCP_S3_HTTP_HOST is not a loopback address.*plain http/);
    expect(s.stdout()).toBe("");
    for (const secret of [ADMIN_PASSWORD, TOKEN_KEY, bucket, ROOT_PREFIX]) expect(s.stderr()).not.toContain(secret);
  });

  it("does not warn for a loopback bind", async () => {
    const s = await startServer();
    await s.stop();
    expect(s.stderr()).toContain("server started");
    expect(s.stderr()).not.toMatch(/WARN/);
    expect(s.stderr()).not.toContain("not a loopback");
  });

  it("does not warn for a non-loopback bind with an https public URL", async () => {
    const s = await startServer({ MCP_S3_HTTP_HOST: "0.0.0.0", MCP_S3_PUBLIC_URL: "https://mcp.example.com" });
    await s.stop();
    expect(s.stderr()).not.toContain("not a loopback");
  });

  it("SIGTERM shuts down cleanly with exit code 0", async () => {
    const s = await startServer();
    const exit = await s.stop();
    expect(exit.code).toBe(0);
  });

  it("refuses to start with MCP_S3_READ_ONLY=false", async () => {
    await expectStartupFailure({ MCP_S3_READ_ONLY: "false" }, "MCP_S3_READ_ONLY");
  });

  it("refuses to start with MCP_S3_ALLOW_DELETE=true", async () => {
    await expectStartupFailure({ MCP_S3_ALLOW_DELETE: "true" }, "MCP_S3_ALLOW_DELETE");
  });

  it("refuses to start without MCP_S3_TOKEN_KEY", async () => {
    await expectStartupFailure({ MCP_S3_TOKEN_KEY: undefined }, "MCP_S3_TOKEN_KEY");
  });

  it("refuses to start without the admin credentials", async () => {
    await expectStartupFailure({ MCP_S3_AUTH_USERNAME: undefined }, "MCP_S3_AUTH_USERNAME");
    await expectStartupFailure({ MCP_S3_AUTH_PASSWORD: undefined }, "MCP_S3_AUTH_PASSWORD");
  });

  it("refuses a short password without echoing it", async () => {
    await expectStartupFailure({ MCP_S3_AUTH_PASSWORD: "short-pw-1" }, "MCP_S3_AUTH_PASSWORD", "short-pw-1");
  });

  it("refuses a plain http public URL on a public host", async () => {
    await expectStartupFailure({ MCP_S3_PUBLIC_URL: "http://mcp.example.com" }, "MCP_S3_PUBLIC_URL");
  });

  it("refuses a public URL with a path", async () => {
    await expectStartupFailure({ MCP_S3_PUBLIC_URL: "https://mcp.example.com/app" }, "MCP_S3_PUBLIC_URL");
  });

  it("refuses a non-loopback host without MCP_S3_PUBLIC_URL", async () => {
    await expectStartupFailure({ MCP_S3_HTTP_HOST: "0.0.0.0", MCP_S3_PUBLIC_URL: undefined }, "MCP_S3_PUBLIC_URL");
  });

  it("refuses DCR off without a static client", async () => {
    await expectStartupFailure({ MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "false" }, "MCP_S3_OAUTH_DYNAMIC_REGISTRATION");
  });

  it("refuses a client id without a secret and a weak client secret", async () => {
    await expectStartupFailure({ MCP_S3_OAUTH_CLIENT_ID: "c" }, "MCP_S3_OAUTH_CLIENT_SECRET");
    await expectStartupFailure({ MCP_S3_OAUTH_CLIENT_ID: "c", MCP_S3_OAUTH_CLIENT_SECRET: "weak-secret" }, "MCP_S3_OAUTH_CLIENT_SECRET", "weak-secret");
  });

  it("refuses MCP_S3_TRUST_PROXY=11 and a bad port", async () => {
    await expectStartupFailure({ MCP_S3_TRUST_PROXY: "11" }, "MCP_S3_TRUST_PROXY");
    await expectStartupFailure({ MCP_S3_HTTP_PORT: "70000" }, "MCP_S3_HTTP_PORT");
  });

  it("reports several problems at once", async () => {
    const proc = spawnProcess(serverEnv({ MCP_S3_AUTH_PASSWORD: undefined, MCP_S3_READ_ONLY: "false", MCP_S3_TRUST_PROXY: "11" }));
    const exit = await proc.exited;
    expect(exit.code).not.toBe(0);
    for (const name of ["MCP_S3_AUTH_PASSWORD", "MCP_S3_READ_ONLY", "MCP_S3_TRUST_PROXY"]) expect(proc.stderr()).toContain(name);
  });

  it("exits non-zero with a clear message when the port is already in use", async () => {
    const port = await freePort();
    const blocker = createServer();
    await new Promise<void>((resolve) => blocker.listen(port, "127.0.0.1", resolve));
    try {
      const proc = spawnProcess(serverEnv({ MCP_S3_HTTP_PORT: String(port), MCP_S3_PUBLIC_URL: `http://localhost:${String(port)}` }));
      const exit = await proc.exited;
      expect(exit.code).not.toBe(0);
      expect(proc.stderr()).toMatch(/fatal error|EADDRINUSE/i);
      expect(proc.stdout()).toBe("");
      expect(proc.stderr()).not.toContain(ADMIN_PASSWORD);
    } finally {
      await new Promise<void>((resolve) => blocker.close(() => {
        resolve();
      }));
    }
  });
});

// --- endpoints ----------------------------------------------------------------

describe("HTTP server: endpoints", () => {
  it("/mcp without a token: 401 with WWW-Authenticate", async () => {
    const s = await startServer();
    const res = await s.oauth.mcp(undefined, "tools/list");
    expect(res.status).toBe(401);
    const www = res.headers.get("www-authenticate") ?? "";
    expect(www).toMatch(/^Bearer /);
    expect(www).toContain(`resource_metadata="${s.base}/.well-known/oauth-protected-resource/mcp"`);
  });

  it("serves the metadata endpoints (200)", async () => {
    const s = await startServer();
    for (const path of [
      "/.well-known/oauth-authorization-server",
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-protected-resource/mcp",
      "/healthz",
    ]) {
      const res = await fetch(`${s.base}${path}`);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-type"), path).toMatch(/json/);
    }
    const meta = (await (await fetch(`${s.base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    expect(meta.issuer).toBe(`${s.base}/`);
    expect(meta.token_endpoint).toBe(`${s.base}/token`);
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("DCR disabled: /register is 404 and the static client works end to end", async () => {
    const s = await startServer({
      MCP_S3_OAUTH_DYNAMIC_REGISTRATION: "false",
      MCP_S3_OAUTH_CLIENT_ID: STATIC_CLIENT_ID,
      MCP_S3_OAUTH_CLIENT_SECRET: STATIC_CLIENT_SECRET,
    });
    const res = await fetch(`${s.base}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(res.status).toBe(404);
    const redirect = "https://claude.ai/api/mcp/auth_callback";
    const k = pkce();
    const code = await s.oauth.obtainCode(STATIC_CLIENT_ID, redirect, k.challenge);
    const t = await s.oauth.token(
      { grant_type: "authorization_code", code, code_verifier: k.verifier, redirect_uri: redirect },
      { authorization: `Basic ${Buffer.from(`${STATIC_CLIENT_ID}:${STATIC_CLIENT_SECRET}`).toString("base64")}` },
    );
    expect(t.status).toBe(200);
    const list = await s.oauth.mcp(String(t.json.access_token), "tools/list");
    expect(list.status).toBe(200);
  });

  it("only the read tools are exposed over HTTP", async () => {
    const s = await startServer();
    const reg = await s.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT], token_endpoint_auth_method: "none" });
    const t = await s.oauth.obtainTokens(String(reg.json.client_id), LOOPBACK_REDIRECT);
    const res = await s.oauth.mcp(t.access, "tools/list");
    const tools = (res.json?.result as { tools: { name: string }[] }).tools.map((x) => x.name).sort();
    expect(tools).toEqual(READ_TOOLS);
  });
});

// --- full flow with the SDK client ---------------------------------------------

/** In-memory OAuthClientProvider for the SDK client; records where the user would be sent. */
class TestProvider implements OAuthClientProvider {
  authorizationUrl: URL | undefined;
  private info: OAuthClientInformationMixed | undefined;
  private saved: OAuthTokens | undefined;
  private verifier = "";

  get redirectUrl(): string {
    return LOOPBACK_REDIRECT;
  }
  get clientMetadata() {
    return {
      client_name: "mcp-s3 e2e",
      redirect_uris: [LOOPBACK_REDIRECT],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: "read",
    };
  }
  clientInformation(): OAuthClientInformationMixed | undefined {
    return this.info;
  }
  saveClientInformation(info: OAuthClientInformationMixed): void {
    this.info = info;
  }
  tokens(): OAuthTokens | undefined {
    return this.saved;
  }
  saveTokens(tokens: OAuthTokens): void {
    this.saved = tokens;
  }
  redirectToAuthorization(url: URL): void {
    this.authorizationUrl = url;
  }
  saveCodeVerifier(verifier: string): void {
    this.verifier = verifier;
  }
  codeVerifier(): string {
    return this.verifier;
  }
}

function asResult(raw: unknown): CallToolResult {
  return CallToolResultSchema.parse(raw);
}

describe("HTTP server: full OAuth flow with the MCP SDK client", () => {
  it("discovers, registers, logs in, and calls tools through StreamableHTTPClientTransport", async () => {
    const s = await startServer();
    const provider = new TestProvider();

    // 1. Unauthenticated connect: the SDK discovers metadata, registers a client, and asks us to open the browser.
    const first = new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), { authProvider: provider });
    const client1 = new Client({ name: "mcp-s3-e2e-http", version: "0.0.0" });
    await expect(client1.connect(first)).rejects.toThrow();
    const authorizationUrl = provider.authorizationUrl;
    expect(authorizationUrl, "redirectToAuthorization was not called").toBeDefined();
    if (authorizationUrl === undefined) return;
    expect(authorizationUrl.origin).toBe(s.base);
    expect(authorizationUrl.searchParams.get("resource")).toBe(`${s.base}/mcp`);

    // 2. "Browser": open the authorization URL, log in, follow the redirect to get the code.
    const page = await fetch(authorizationUrl, { redirect: "manual" });
    const html = await page.text();
    expect(page.status).toBe(200);
    const form = {
      request: hiddenField(html, "request"),
      csrf: hiddenField(html, "csrf"),
      cookie: (page.headers.get("set-cookie") ?? "").split(";")[0] ?? "",
    };
    const login = await s.oauth.login(form, ADMIN_USERNAME, ADMIN_PASSWORD);
    expect(login.status).toBe(303);
    const callback = new URL(login.headers.get("location") ?? "http://invalid/");
    expect(callback.origin + callback.pathname).toBe(LOOPBACK_REDIRECT);
    expect(callback.searchParams.get("state")).toBe(authorizationUrl.searchParams.get("state"));
    const code = callback.searchParams.get("code") ?? "";
    expect(code).not.toBe("");

    // 3. Back in the client: exchange the code, reconnect with the access token.
    await first.finishAuth(code);
    expect(provider.tokens()?.access_token).toBeTruthy();

    const transport = new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), { authProvider: provider });
    const client = new Client({ name: "mcp-s3-e2e-http", version: "0.0.0" });
    await client.connect(transport);
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((t) => t.name).sort()).toEqual(READ_TOOLS);
      for (const tool of tools.tools) {
        expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });
      }

      const list = parseJson(asResult(await client.callTool({ name: "list_objects", arguments: { recursive: true } })), ListObjectsResult);
      expect(list.files.map((f) => f.path).sort()).toEqual(["a.txt", "img.png", "sub/b.txt"]);
      expect(JSON.stringify(list)).not.toContain(bucket);
      expect(JSON.stringify(list)).not.toContain("claude-workspace");

      const read = asResult(await client.callTool({ name: "read_object", arguments: { path: "a.txt" } }));
      expect(onlyText(read)).toBe("hello from a\n");

      const image = asResult(await client.callTool({ name: "read_object", arguments: { path: "img.png" } }));
      expect(image.content[0]).toMatchObject({ type: "image", mimeType: "image/png" });

      const traversal = asResult(await client.callTool({ name: "read_object", arguments: { path: "../outside/secret.txt" } }));
      expectToolError(traversal, "PathOutsideRoot");
      expect(JSON.stringify(traversal)).not.toContain(SECRET_CONTENT);

      const leak = asResult(await client.callTool({ name: "read_object", arguments: { path: "../claude-workspace-backup/leak.txt" } }));
      expect(leak.isError).toBe(true);
      expect(JSON.stringify(leak)).not.toContain(LEAK_CONTENT);
    } finally {
      await client.close();
    }

    // 4. Refresh through the SDK: the stored refresh token rotates.
    const oldRefresh = provider.tokens()?.refresh_token;
    expect(oldRefresh).toBeTruthy();
    const refreshed = await s.oauth.token({
      grant_type: "refresh_token",
      refresh_token: oldRefresh ?? "",
      client_id: (provider.clientInformation() as { client_id: string }).client_id,
    });
    expect(refreshed.status).toBe(200);
    expect(refreshed.json.refresh_token).not.toBe(oldRefresh);
  });

  it("a token obtained by hand works through StreamableHTTPClientTransport with a bearer header, and a bad token does not", async () => {
    const s = await startServer();
    const reg = await s.oauth.register({ redirect_uris: [LOOPBACK_REDIRECT], token_endpoint_auth_method: "none" });
    const t = await s.oauth.obtainTokens(String(reg.json.client_id), LOOPBACK_REDIRECT);

    const ok = new Client({ name: "mcp-s3-e2e-http", version: "0.0.0" });
    await ok.connect(new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${t.access}` } } }));
    try {
      const result = asResult(await ok.callTool({ name: "get_object_info", arguments: { path: "a.txt" } }));
      expect(toolText({ status: 200, json: { result }, text: "", headers: new Headers() }).isError).toBe(false);
    } finally {
      await ok.close();
    }

    const bad = new Client({ name: "mcp-s3-e2e-http", version: "0.0.0" });
    await expect(
      bad.connect(new StreamableHTTPClientTransport(new URL(`${s.base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${t.refresh}` } } })),
    ).rejects.toThrow();
    await bad.close().catch(() => undefined);
  });
});
