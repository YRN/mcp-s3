import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Readable } from "node:stream";

import type { S3Client } from "@aws-sdk/client-s3";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CallToolResultSchema, JSONRPCMessageSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { LEAK_CONTENT, PNG_1X1, ROOT_PREFIX, SECRET_CONTENT } from "../helpers/fixtures.js";
import {
  expectToolError,
  ListObjectsResult,
  ObjectInfoResult,
  onlyText,
  parseJson,
  SearchObjectsResult,
} from "../helpers/mcp.js";
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

const SERVER_ENTRY = join(PROJECT_DIR, "dist", "index.js");
const READ_TOOLS = ["get_object_info", "list_objects", "read_object", "search_objects"];
const WRITE_OR_DELETE_TOOLS = ["write_object", "create_folder", "copy_object", "delete_object", "move_object"];

let admin: S3Client;
let bucket = "";
let bucketCreated = false;

beforeAll(async () => {
  if (!existsSync(SERVER_ENTRY)) {
    throw new Error(`${SERVER_ENTRY} does not exist; run "npm run build" first (npm run test:e2e does this).`);
  }
  await assertMinioReady();
  admin = minioClient();
  bucket = await createSeededBucket(admin, "mcp-s3-e2e");
  bucketCreated = true;
});

afterAll(async () => {
  if (bucketCreated) await destroyBucket(admin, bucket);
});

/** Environment for the server process. `undefined` removes a variable. */
function serverEnv(overrides: Record<string, string | undefined> = {}): Record<string, string> {
  const merged: Record<string, string | undefined> = {
    ...getDefaultEnvironment(),
    S3_BUCKET: bucket,
    S3_ROOT_PREFIX: ROOT_PREFIX,
    AWS_REGION: MINIO_REGION,
    S3_ENDPOINT_URL: MINIO_ENDPOINT,
    S3_FORCE_PATH_STYLE: "true",
    AWS_ACCESS_KEY_ID: MINIO_ROOT_USER,
    AWS_SECRET_ACCESS_KEY: MINIO_ROOT_PASSWORD,
    // Keep the developer's ~/.aws and instance metadata out of the test.
    AWS_CONFIG_FILE: join(PROJECT_DIR, "test", "e2e", "no-aws-config"),
    AWS_SHARED_CREDENTIALS_FILE: join(PROJECT_DIR, "test", "e2e", "no-aws-credentials"),
    AWS_EC2_METADATA_DISABLED: "true",
    ...overrides,
  };
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(merged)) if (value !== undefined) env[name] = value;
  return env;
}

function collect(stream: Readable | null): () => string {
  let data = "";
  stream?.setEncoding("utf8");
  stream?.on("data", (chunk: string) => (data += chunk));
  return () => data;
}

// --- MCP client over stdio ----------------------------------------------------

interface StdioSession {
  client: Client;
  call(name: string, args?: Record<string, unknown>): Promise<CallToolResult>;
  stderr(): string;
  errors: Error[];
  close(): Promise<void>;
}

const sessions: StdioSession[] = [];

async function connect(overrides: Record<string, string | undefined> = {}): Promise<StdioSession> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: serverEnv(overrides),
    cwd: PROJECT_DIR,
    stderr: "pipe",
  });
  const stderr = collect(transport.stderr as Readable | null);
  const client = new Client({ name: "mcp-s3-e2e", version: "0.0.0" });
  const errors: Error[] = [];
  // Any stdout line that is not a valid JSON-RPC message ends up here.
  client.onerror = (err) => errors.push(err);
  await client.connect(transport);

  const session: StdioSession = {
    client,
    async call(name, args = {}) {
      return CallToolResultSchema.parse(await client.callTool({ name, arguments: args }));
    },
    stderr,
    errors,
    async close() {
      await client.close();
    },
  };
  sessions.push(session);
  return session;
}

afterEach(async () => {
  await Promise.all(sessions.splice(0).map((s) => s.close()));
});

function expectNoLeak(value: unknown): void {
  const serialised = JSON.stringify(value);
  expect(serialised).not.toContain(bucket);
  expect(serialised).not.toContain("claude-workspace");
  expect(serialised).not.toContain(SECRET_CONTENT);
  expect(serialised).not.toContain(LEAK_CONTENT);
}

// --- raw process (for stdout purity, exit codes, signals) --------------------

interface RawProcess {
  child: ChildProcessWithoutNullStreams;
  stdout(): string;
  stderr(): string;
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  request(id: number, method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>>;
  notify(method: string, params?: Record<string, unknown>): void;
}

function spawnServer(overrides: Record<string, string | undefined> = {}): RawProcess {
  const child = spawn(process.execPath, [SERVER_ENTRY], { cwd: PROJECT_DIR, env: serverEnv(overrides), stdio: "pipe" });
  const stderr = collect(child.stderr);
  let stdout = "";
  let buffer = "";
  const waiting = new Map<number, (msg: Record<string, unknown>) => void>();
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
    buffer += chunk;
    let index: number;
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      try {
        const msg = JSON.parse(line) as Record<string, unknown>;
        if (typeof msg.id === "number") waiting.get(msg.id)?.(msg);
      } catch {
        // Invalid lines are reported by the stdout assertions.
      }
    }
  });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.on("exit", (code, signal) => {
      resolve({ code, signal });
    });
  });
  // Ignore EPIPE if the server already exited.
  child.stdin.on("error", () => undefined);

  const send = (msg: Record<string, unknown>) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...msg })}\n`);
  return {
    child,
    stdout: () => stdout,
    stderr,
    exited,
    request(id, method, params = {}) {
      const response = new Promise<Record<string, unknown>>((resolve) => waiting.set(id, resolve));
      send({ id, method, params });
      return response;
    },
    notify(method, params = {}) {
      send({ method, params });
    },
  };
}

const INITIALIZE_PARAMS = {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "mcp-s3-e2e-raw", version: "0.0.0" },
};

async function initialize(proc: RawProcess): Promise<void> {
  const res = await proc.request(1, "initialize", INITIALIZE_PARAMS);
  expect(res.result).toBeDefined();
  proc.notify("notifications/initialized");
}

/** Every stdout line must be a valid JSON-RPC 2.0 message; nothing else may be written. */
function expectOnlyJsonRpc(stdout: string): number {
  expect(stdout === "" || stdout.endsWith("\n")).toBe(true);
  const lines = stdout.split("\n").slice(0, -1);
  for (const line of lines) {
    let parsed: unknown = undefined;
    let isJson = true;
    try {
      parsed = JSON.parse(line);
    } catch {
      isJson = false;
    }
    expect(isJson, `stdout line is not JSON: ${line.slice(0, 200)}`).toBe(true);
    expect(JSONRPCMessageSchema.safeParse(parsed).success, `not a JSON-RPC message: ${line.slice(0, 200)}`).toBe(true);
  }
  return lines.length;
}

// ---------------------------------------------------------------------------

describe("e2e over stdio (node dist/index.js)", () => {
  it("1. default mode lists only the read tools", async () => {
    const s = await connect();
    const { tools } = await s.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(READ_TOOLS);
    for (const name of WRITE_OR_DELETE_TOOLS) expect(tools.some((t) => t.name === name)).toBe(false);
    for (const tool of tools) expect(tool.annotations?.readOnlyHint).toBe(true);
    expectNoLeak(tools);
    expect(s.errors).toEqual([]);
  });

  it("1b. MCP_S3_ALLOW_DELETE=true while read-only still lists only the read tools", async () => {
    const s = await connect({ MCP_S3_ALLOW_DELETE: "true" });
    const { tools } = await s.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(READ_TOOLS);
  });

  it("2. read tools return paths relative to the root", async () => {
    const s = await connect();

    const list = await s.call("list_objects", { recursive: true });
    expect(parseJson(list, ListObjectsResult).files.map((f) => f.path).sort()).toEqual(["a.txt", "img.png", "sub/b.txt"]);

    const top = await s.call("list_objects", {});
    const topBody = parseJson(top, ListObjectsResult);
    expect(topBody.path).toBe("");
    expect(topBody.folders).toEqual(["sub/"]);

    const info = await s.call("get_object_info", { path: "sub/b.txt" });
    expect(parseJson(info, ObjectInfoResult)).toMatchObject({ path: "sub/b.txt", size: 4, content_type: "text/plain" });

    const read = await s.call("read_object", { path: "a.txt" });
    expect(onlyText(read)).toBe("hello from a\n");

    const search = await s.call("search_objects", { pattern: "*.txt" });
    expect(parseJson(search, SearchObjectsResult).matches.sort()).toEqual(["a.txt", "sub/b.txt"]);

    expectNoLeak([list, top, info, read, search]);
    expect(s.errors).toEqual([]);
  });

  it("3. read_object ../outside/secret.txt is an error and does not leak the secret", async () => {
    const s = await connect();
    for (const path of ["../outside/secret.txt", "/../outside/secret.txt", "..\\outside\\secret.txt"]) {
      const result = await s.call("read_object", { path });
      expectToolError(result, "PathOutsideRoot");
      expectNoLeak(result);
    }
    for (const [tool, args] of [
      ["list_objects", { path: "../" }],
      ["search_objects", { path: "../", pattern: "*" }],
      ["get_object_info", { path: "../outside/secret.txt" }],
    ] as const) {
      const result = await s.call(tool, args);
      expectToolError(result, "PathOutsideRoot");
      expectNoLeak(result);
    }
  });

  it("5. read_object on an image returns image content with the right mimeType", async () => {
    const s = await connect();
    const result = await s.call("read_object", { path: "img.png" });
    expect(result.isError).not.toBe(true);
    expect(result.content).toEqual([{ type: "image", data: Buffer.from(PNG_1X1).toString("base64"), mimeType: "image/png" }]);
  });

  it("storage errors reach the client as generic errors and the server keeps running", async () => {
    const s = await connect({ AWS_SECRET_ACCESS_KEY: "definitely-wrong-secret" });
    const result = await s.call("list_objects", {});
    expectToolError(result, "AccessDenied");
    expectNoLeak(result);
    expectToolError(await s.call("read_object", { path: "missing.txt" }), "AccessDenied");
    const { tools } = await s.client.listTools();
    expect(tools).toHaveLength(4);
  });

  it("6. stdout carries only JSON-RPC messages, even with DEBUG logging and errors", async () => {
    const proc = spawnServer({ MCP_S3_LOG_LEVEL: "DEBUG" });
    await initialize(proc);
    let id = 10;
    const calls: [string, Record<string, unknown>][] = [
      ["list_objects", { recursive: true }],
      ["read_object", { path: "a.txt" }],
      ["read_object", { path: "img.png" }],
      ["read_object", { path: "../outside/secret.txt" }],
      ["read_object", { path: "missing.txt" }],
      ["get_object_info", { path: "a.txt" }],
      ["search_objects", { pattern: "*" }],
      ["list_objects", { max_keys: 5000 }],
      ["no_such_tool", {}],
    ];
    const responses = [await proc.request(id++, "tools/list")];
    for (const [name, args] of calls) responses.push(await proc.request(id++, "tools/call", { name, arguments: args }));
    responses.push(await proc.request(id, "no/such/method"));
    proc.child.stdin.end();
    const exit = await proc.exited;

    expect(exit.code).toBe(0);
    expect(responses).toHaveLength(calls.length + 2);
    const lines = expectOnlyJsonRpc(proc.stdout());
    expect(lines).toBe(responses.length + 1); // + initialize response
    // Logging happened, and it went to stderr.
    expect(proc.stderr()).toMatch(/server started/);
    expect(proc.stdout()).not.toMatch(/\[mcp-s3\]/);
  });

  it("logs (stderr) never contain the bucket name, root prefix, or credentials", async () => {
    const proc = spawnServer({ MCP_S3_LOG_LEVEL: "DEBUG" });
    await initialize(proc);
    await proc.request(2, "tools/call", { name: "read_object", arguments: { path: "missing.txt" } });
    await proc.request(3, "tools/call", { name: "read_object", arguments: { path: "../outside/secret.txt" } });
    await proc.request(4, "tools/call", { name: "list_objects", arguments: { recursive: true } });
    proc.child.stdin.end();
    await proc.exited;
    const stderr = proc.stderr();
    expect(stderr.length).toBeGreaterThan(0);
    expect(stderr).not.toContain(bucket);
    expect(stderr).not.toContain("claude-workspace");
    expect(stderr).not.toContain(MINIO_ROOT_PASSWORD);
    expect(stderr).not.toContain(SECRET_CONTENT);
  });

  it.each([
    ["empty", ""],
    ["no trailing slash", "claude-workspace"],
    ["'..' segment", "a/../b/"],
    ["only '../'", "../"],
    ["only '/'", "/"],
    ["leading slash", "/claude-workspace/"],
    ["missing", undefined],
  ])("7. S3_ROOT_PREFIX %s: exits non-zero and writes nothing to stdout", async (_name, prefix) => {
    const proc = spawnServer({ S3_ROOT_PREFIX: prefix });
    proc.child.stdin.end();
    const exit = await proc.exited;
    expect(exit.code).not.toBe(0);
    expect(exit.code).not.toBeNull();
    expect(proc.stdout()).toBe("");
    expect(proc.stderr()).toContain("S3_ROOT_PREFIX");
    expect(proc.stderr()).not.toContain(bucket);
  });

  it.each(["S3_BUCKET", "AWS_REGION"])("missing %s: exits non-zero and writes nothing to stdout", async (name) => {
    const proc = spawnServer({ [name]: undefined });
    proc.child.stdin.end();
    const exit = await proc.exited;
    expect(exit.code).not.toBe(0);
    expect(exit.code).not.toBeNull();
    expect(proc.stdout()).toBe("");
    expect(proc.stderr()).toContain(name);
  });

  it.each(["SIGTERM", "SIGINT"] as const)("%s shuts the server down with exit code 0", async (signal) => {
    const proc = spawnServer();
    await initialize(proc);
    proc.child.kill(signal);
    const exit = await proc.exited;
    expect(exit).toEqual({ code: 0, signal: null });
    expectOnlyJsonRpc(proc.stdout());
  });

  it("closing stdin shuts the server down with exit code 0", async () => {
    const proc = spawnServer();
    await initialize(proc);
    proc.child.stdin.end();
    const exit = await proc.exited;
    expect(exit).toEqual({ code: 0, signal: null });
    expectOnlyJsonRpc(proc.stdout());
  });
});

// ---------------------------------------------------------------------------

describe("e2e: startup log and MCP_S3_TOKEN_KEY", () => {
  const KEY_K = randomBytes(32).toString("base64");
  const KEY_OTHER = randomBytes(32).toString("base64");
  const READ_TOOL_LIST = '"tools":"list_objects,get_object_info,read_object,search_objects"';

  async function startedLog(overrides: Record<string, string | undefined>): Promise<string> {
    const proc = spawnServer(overrides);
    await initialize(proc);
    proc.child.stdin.end();
    const exit = await proc.exited;
    expect(exit.code).toBe(0);
    const line = proc.stderr().split("\n").find((l) => l.includes("server started"));
    if (line === undefined) throw new Error(`no "server started" line in stderr: ${proc.stderr()}`);
    return line;
  }

  it.each([
    [{}],
    [{ MCP_S3_READ_ONLY: "false" }],
    [{ MCP_S3_READ_ONLY: "false", MCP_S3_ALLOW_DELETE: "true" }],
  ])("'server started' lists exactly the registered read tools (%j)", async (overrides: Record<string, string>) => {
    const line = await startedLog(overrides);
    expect(line).toContain(READ_TOOL_LIST);
    expect(line).not.toMatch(/write_object|delete_object|move_object|copy_object|create_folder/);
  });

  it("'server started' never contains the token key, bucket, or root prefix", async () => {
    const line = await startedLog({ MCP_S3_TOKEN_KEY: KEY_K, MCP_S3_LOG_LEVEL: "DEBUG" });
    expect(line).toContain(READ_TOOL_LIST);
    expect(line).not.toContain(KEY_K);
    expect(line).not.toContain(KEY_K.replace(/=+$/, ""));
    expect(line).not.toContain(Buffer.from(KEY_K, "base64").toString("hex"));
    expect(line).not.toContain(bucket);
    expect(line).not.toContain("claude-workspace");
  });

  it("MCP_S3_TRANSPORT=http without MCP_S3_TOKEN_KEY fails to start", async () => {
    for (const key of [undefined, ""]) {
      const proc = spawnServer({ MCP_S3_TRANSPORT: "http", MCP_S3_TOKEN_KEY: key });
      proc.child.stdin.end();
      const exit = await proc.exited;
      expect(exit.code).not.toBe(0);
      expect(exit.code).not.toBeNull();
      expect(proc.stdout()).toBe("");
      expect(proc.stderr()).toContain("MCP_S3_TOKEN_KEY");
    }
  });

  it("an invalid MCP_S3_TOKEN_KEY fails to start without echoing the value", async () => {
    const bad = randomBytes(16).toString("base64");
    const proc = spawnServer({ MCP_S3_TOKEN_KEY: bad });
    proc.child.stdin.end();
    const exit = await proc.exited;
    expect(exit.code).not.toBe(0);
    expect(exit.code).not.toBeNull();
    expect(proc.stdout()).toBe("");
    expect(proc.stderr()).toContain("MCP_S3_TOKEN_KEY");
    expect(proc.stderr()).not.toContain(bad);
  });

  it("a next_token from process A works in process B with the same key; other keys are rejected", async () => {
    const env = { MCP_S3_MAX_LIST_KEYS: "1" };
    const a = await connect({ ...env, MCP_S3_TOKEN_KEY: KEY_K });
    const page1 = parseJson(await a.call("list_objects", { recursive: true }), ListObjectsResult);
    expect(page1.files.map((f) => f.path)).toEqual(["a.txt"]);
    const token = page1.next_token;
    if (token === null) throw new Error("expected a next_token");
    expect(token).not.toContain("claude-workspace");
    await a.close();

    const b = await connect({ ...env, MCP_S3_TOKEN_KEY: KEY_K });
    const page2Result = await b.call("list_objects", { recursive: true, continuation_token: token });
    expectNoLeak(page2Result);
    const page2 = parseJson(page2Result, ListObjectsResult);
    expect(page2.files.map((f) => f.path)).toEqual(["img.png"]);
    if (page2.next_token === null) throw new Error("expected a next_token on page 2");
    const page3 = parseJson(
      await b.call("list_objects", { recursive: true, continuation_token: page2.next_token }),
      ListObjectsResult,
    );
    expect(page3.files.map((f) => f.path)).toEqual(["sub/b.txt"]);
    // MinIO reports IsTruncated=true on the last full page; the next page is empty and final.
    if (page3.next_token !== null) {
      const page4 = parseJson(
        await b.call("list_objects", { recursive: true, continuation_token: page3.next_token }),
        ListObjectsResult,
      );
      expect(page4).toEqual({ path: "", folders: [], files: [], next_token: null });
    }

    const c = await connect({ ...env, MCP_S3_TOKEN_KEY: KEY_OTHER });
    expectToolError(await c.call("list_objects", { recursive: true, continuation_token: token }), "InvalidRequest");

    // Without MCP_S3_TOKEN_KEY every process has its own random key.
    const d = await connect(env);
    expectToolError(await d.call("list_objects", { recursive: true, continuation_token: token }), "InvalidRequest");
  });

  it("without MCP_S3_TOKEN_KEY, tokens work within one process but not in the next", async () => {
    const env = { MCP_S3_MAX_LIST_KEYS: "1" };
    const a = await connect(env);
    const page1 = parseJson(await a.call("list_objects", { recursive: true }), ListObjectsResult);
    const token = page1.next_token;
    if (token === null) throw new Error("expected a next_token");
    const page2 = parseJson(await a.call("list_objects", { recursive: true, continuation_token: token }), ListObjectsResult);
    expect(page2.files.map((f) => f.path)).toEqual(["img.png"]);

    const b = await connect(env);
    expectToolError(await b.call("list_objects", { recursive: true, continuation_token: token }), "InvalidRequest");
  });
});
