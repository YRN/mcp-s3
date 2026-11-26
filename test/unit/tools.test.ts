import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";

import {
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  S3ServiceException,
  type GetObjectCommandOutput,
} from "@aws-sdk/client-s3";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { loadConfig, type Config } from "../../src/config.js";
import { errorResult, safeErrorMessage, toSafeError } from "../../src/errors.js";
import { PathOutsideRootError } from "../../src/paths.js";
import { buildServer, enabledToolGroups } from "../../src/server.js";
import { Storage } from "../../src/storage.js";
import { MAX_TOKEN_LENGTH, TOKEN_TTL_SECONDS } from "../../src/tokens.js";
import { MAX_IMAGE_BYTES, sniffImageMime } from "../../src/tools/read.js";
import { accessDenied, FakeS3, noSuchBucket, noSuchKey, notFound, preconditionFailed } from "../helpers/fakeS3.js";
import { GIF_1X1, JPEG_HEAD, LEAK_CONTENT, PNG_1X1, pngOfSize, SECRET_CONTENT, WEBP_HEAD } from "../helpers/fixtures.js";
import {
  connectInMemory,
  expectOk,
  expectToolError,
  expectValidationError,
  ListObjectsResult,
  nextOffset,
  ObjectInfoResult,
  onlyText,
  parseJson,
  SearchObjectsResult,
  texts,
  type InMemoryHarness,
} from "../helpers/mcp.js";

const BUCKET = "acme-secret-bucket-7f3a";
const ROOT = "claude-workspace/";

const READ_TOOLS = ["get_object_info", "list_objects", "read_object", "search_objects"];
const WRITE_TOOLS = ["write_object", "create_folder", "copy_object"];
const DELETE_TOOLS = ["delete_object", "move_object"];

function makeConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({ S3_BUCKET: BUCKET, S3_ROOT_PREFIX: ROOT, AWS_REGION: "us-east-1", ...overrides });
}

/** Default seed from the task description (same layout as the MinIO integration seed). */
function seed(fake: FakeS3): void {
  fake.put(`${ROOT}a.txt`, "hello from a\n", { contentType: "text/plain", metadata: { owner: "team-a" } });
  fake.put(`${ROOT}sub/b.txt`, "bee\n", { contentType: "text/plain" });
  fake.put(`${ROOT}img.png`, PNG_1X1, { contentType: "image/png" });
  fake.put("claude-workspace-backup/leak.txt", LEAK_CONTENT, { contentType: "text/plain" });
  fake.put("outside/secret.txt", SECRET_CONTENT, { contentType: "text/plain" });
}

let fake: FakeS3 | undefined;
const harnesses: InMemoryHarness[] = [];

async function setup(overrides: Record<string, string> = {}, withSeed = true): Promise<{ fake: FakeS3; h: InMemoryHarness }> {
  fake = new FakeS3(BUCKET);
  if (withSeed) seed(fake);
  return { fake, h: await connectTo(fake, overrides) };
}

/** Another server instance (think: another process) on the same storage. */
async function connectTo(f: FakeS3, overrides: Record<string, string> = {}): Promise<InMemoryHarness> {
  const config = makeConfig(overrides);
  const h = await connectInMemory(config, new Storage(f.client, config.bucket));
  harnesses.push(h);
  return h;
}

afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((h) => h.close()));
  fake?.restore();
  fake = undefined;
});

/** No response may contain the bucket name, the root prefix, or content from outside the root. */
function expectNoLeak(value: unknown): void {
  const serialised = JSON.stringify(value);
  expect(serialised).not.toContain(BUCKET);
  expect(serialised).not.toContain("claude-workspace");
  expect(serialised).not.toContain(SECRET_CONTENT);
  expect(serialised).not.toContain(LEAK_CONTENT);
  expect(serialised).not.toContain("arn:aws");
}

type ReadCommand = typeof ListObjectsV2Command | typeof HeadObjectCommand | typeof GetObjectCommand;

/** Inputs of every sent command of the given type, in order. */
function inputsOf(f: FakeS3, command: ReadCommand): Record<string, unknown>[] {
  return f.mock.calls().flatMap((call) => {
    const sent = call.args[0];
    if (!(sent instanceof command)) return [];
    const input: Record<string, unknown> = { ...sent.input };
    return [input];
  });
}

const listInputs = (f: FakeS3) => inputsOf(f, ListObjectsV2Command);
const headInputs = (f: FakeS3) => inputsOf(f, HeadObjectCommand);
const getInputs = (f: FakeS3) => inputsOf(f, GetObjectCommand);

function rangeLength(range: unknown): number {
  const match = /^bytes=(\d+)-(\d+)$/.exec(String(range));
  if (match?.[1] === undefined || match[2] === undefined) throw new Error(`unexpected Range ${String(range)}`);
  return Number(match[2]) - Number(match[1]) + 1;
}

// ---------------------------------------------------------------------------

describe("tool registration", () => {
  it("default config (read-only) lists exactly the four read tools", async () => {
    const { h } = await setup();
    const { tools } = await h.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(READ_TOOLS);
    for (const name of [...WRITE_TOOLS, ...DELETE_TOOLS]) {
      expect(tools.some((t) => t.name === name)).toBe(false);
    }
  });

  it("read tools are annotated readOnlyHint and not destructive", async () => {
    const { h } = await setup();
    const { tools } = await h.listTools();
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.annotations?.destructiveHint).not.toBe(true);
    }
  });

  it("MCP_S3_ALLOW_DELETE=true has no effect while read-only", async () => {
    const { h } = await setup({ MCP_S3_ALLOW_DELETE: "true" });
    const { tools } = await h.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(READ_TOOLS);
  });

  it("tools/list does not reveal the bucket name or root prefix", async () => {
    const { h } = await setup();
    expectNoLeak(await h.listTools());
  });

  it.each([
    [{ readOnly: true, allowDelete: false }, { read: true, write: false, delete: false }],
    [{ readOnly: true, allowDelete: true }, { read: true, write: false, delete: false }],
    [{ readOnly: false, allowDelete: false }, { read: true, write: true, delete: false }],
    [{ readOnly: false, allowDelete: true }, { read: true, write: true, delete: true }],
  ])("enabledToolGroups(%j) = %j", (input, expected) => {
    expect(enabledToolGroups(input)).toEqual(expected);
  });

  it("enabledToolGroups for the default config enables only read", () => {
    expect(enabledToolGroups(makeConfig())).toEqual({ read: true, write: false, delete: false });
  });
});

// ---------------------------------------------------------------------------

const JAIL_BREAKS: [string, string][] = [
  ["../secret.txt", "relative segment"],
  ["../outside/secret.txt", "relative segment"],
  ["a/../../b", "relative segment"],
  ["sub/../../outside/secret.txt", "relative segment"],
  ["./a.txt", "relative segment"],
  ["..", "relative segment"],
  ["../", "relative segment"],
  ["/../outside/secret.txt", "relative segment"],
  ["../claude-workspace-backup/leak.txt", "relative segment"],
  ["a\\..\\b", "backslash not allowed"],
  ["..\\outside\\secret.txt", "backslash not allowed"],
  ["a//b", "empty segment"],
  ["a\x00b", "invalid character"],
  ["a.txt\x00", "invalid character"],
  ["a\nb", "invalid character"],
  // 17-byte root + 1008 bytes = 1025 bytes (still within the schema's 1024-char limit).
  ["a".repeat(1008), "key too long"],
];

type ToolCall = [tool: string, args: (path: string) => Record<string, unknown>];
const PATH_TOOLS: ToolCall[] = [
  ["list_objects", (path) => ({ path })],
  ["list_objects", (path) => ({ path, recursive: true })],
  ["search_objects", (path) => ({ path, pattern: "*" })],
  ["get_object_info", (path) => ({ path })],
  ["read_object", (path) => ({ path })],
];

describe("path jail through the tools: rejected before any S3 command", () => {
  for (const [tool, args] of PATH_TOOLS) {
    describe(`${tool} ${JSON.stringify(args("<p>"))}`, () => {
      it.each(JAIL_BREAKS)("rejects %j (%s)", async (path, reason) => {
        const { fake: f, h } = await setup();
        const result = await h.call(tool, args(path));
        const text = expectToolError(result, "PathOutsideRoot");
        expect(text).toBe(`PathOutsideRoot: path is not allowed (${reason})`);
        expect(f.mock.calls()).toHaveLength(0);
        expectNoLeak(result);
      });
    });
  }

  it.each(["get_object_info", "read_object"])("%s rejects paths longer than the schema allows, without S3 calls", async (tool) => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call(tool, { path: "a".repeat(5000) }));
    expect(f.mock.calls()).toHaveLength(0);
  });

  it.each(["get_object_info", "read_object"])("%s refuses the workspace root itself, without S3 calls", async (tool) => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call(tool, { path: "" }));
    expectToolError(await h.call(tool, { path: "/" }), "InvalidRequest");
    expect(f.mock.calls()).toHaveLength(0);
  });

  it("read_object ../outside/secret.txt never returns the secret", async () => {
    const { fake: f, h } = await setup();
    const result = await h.call("read_object", { path: "../outside/secret.txt" });
    expectToolError(result, "PathOutsideRoot");
    expect(JSON.stringify(result)).not.toContain(SECRET_CONTENT);
    expect(f.bodyReads).toHaveLength(0);
  });

  it("URL-encoded traversal is treated literally (resolves inside the root)", async () => {
    const { fake: f, h } = await setup();
    const result = await h.call("get_object_info", { path: "%2e%2e/outside/secret.txt" });
    expectToolError(result, "NotFound");
    expect(headInputs(f)).toEqual([{ Bucket: BUCKET, Key: `${ROOT}%2e%2e/outside/secret.txt` }]);
  });
});

// ---------------------------------------------------------------------------

describe("S3 commands use the configured bucket and root-prefixed keys", () => {
  it("list_objects non-recursive uses Delimiter '/'", async () => {
    const { fake: f, h } = await setup();
    expectOk(await h.call("list_objects", {}));
    expect(listInputs(f)).toEqual([{ Bucket: BUCKET, Prefix: ROOT, Delimiter: "/", MaxKeys: 200 }]);
  });

  it("list_objects recursive sends no Delimiter", async () => {
    const { fake: f, h } = await setup();
    expectOk(await h.call("list_objects", { recursive: true }));
    const [input] = listInputs(f);
    expect(input?.Bucket).toBe(BUCKET);
    expect(input?.Prefix).toBe(ROOT);
    expect(input?.Delimiter).toBeUndefined();
  });

  it.each(["sub", "sub/", "/sub", "/sub/"])("list_objects path %j lists the folder claude-workspace/sub/", async (path) => {
    const { fake: f, h } = await setup();
    expectOk(await h.call("list_objects", { path }));
    expect(listInputs(f)[0]?.Prefix).toBe(`${ROOT}sub/`);
  });

  it.each(["sub/b.txt", "/sub/b.txt"])("get_object_info %j sends HeadObject for the root-prefixed key", async (path) => {
    const { fake: f, h } = await setup();
    expectOk(await h.call("get_object_info", { path }));
    expect(headInputs(f)).toEqual([{ Bucket: BUCKET, Key: `${ROOT}sub/b.txt` }]);
  });

  it("read_object sends GetObject with a Range for the root-prefixed key", async () => {
    const { fake: f, h } = await setup();
    expectOk(await h.call("read_object", { path: "a.txt" }));
    // If-Match pins the read to the ETag that HEAD returned.
    const etag = f.objects.get(`${ROOT}a.txt`)?.etag;
    expect(etag).toBe('"etag-1"');
    expect(getInputs(f)).toEqual([{ Bucket: BUCKET, Key: `${ROOT}a.txt`, Range: "bytes=0-12", IfMatch: etag }]);
  });

  it("search_objects lists recursively under the root-prefixed folder", async () => {
    const { fake: f, h } = await setup();
    expectOk(await h.call("search_objects", { path: "sub", pattern: "*.txt" }));
    const inputs = listInputs(f);
    expect(inputs.length).toBeGreaterThan(0);
    for (const input of inputs) {
      expect(input.Bucket).toBe(BUCKET);
      expect(input.Prefix).toBe(`${ROOT}sub/`);
      expect(input.Delimiter).toBeUndefined();
    }
  });

  it("every command of a mixed session targets the bucket and stays under the root", async () => {
    const { fake: f, h } = await setup();
    await h.call("list_objects", {});
    await h.call("list_objects", { path: "sub", recursive: true });
    await h.call("get_object_info", { path: "a.txt" });
    await h.call("read_object", { path: "img.png" });
    await h.call("read_object", { path: "missing.txt" });
    await h.call("search_objects", { pattern: "*.txt" });
    const inputs = f.sentInputs();
    expect(inputs.length).toBeGreaterThanOrEqual(6);
    for (const input of inputs) {
      expect(input.Bucket).toBe(BUCKET);
      const key = input.Key ?? input.Prefix;
      expect(typeof key).toBe("string");
      expect(String(key).startsWith(ROOT)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------

describe("list_objects", () => {
  it("returns direct children with relative paths", async () => {
    const { h } = await setup();
    const result = await h.call("list_objects", {});
    const body = parseJson(result, ListObjectsResult);
    expect(body.path).toBe("");
    expect(body.folders).toEqual(["sub/"]);
    expect(body.files.map((f) => f.path).sort()).toEqual(["a.txt", "img.png"]);
    expect(body.files.find((f) => f.path === "a.txt")?.size).toBe(13);
    for (const file of body.files) expect(new Date(file.last_modified ?? "").toISOString()).toBe(file.last_modified);
    expect(body.next_token).toBeNull();
    expectNoLeak(result);
  });

  it("recursive=true returns every file under the folder", async () => {
    const { h } = await setup();
    const result = await h.call("list_objects", { recursive: true });
    const body = parseJson(result, ListObjectsResult);
    expect(body.files.map((f) => f.path).sort()).toEqual(["a.txt", "img.png", "sub/b.txt"]);
    expectNoLeak(result);
  });

  it("lists a subfolder with paths relative to the root (not to the folder)", async () => {
    const { h } = await setup();
    const body = parseJson(await h.call("list_objects", { path: "sub" }), ListObjectsResult);
    expect(body.path).toBe("sub/");
    expect(body.files.map((f) => f.path)).toEqual(["sub/b.txt"]);
    expect(body.folders).toEqual([]);
  });

  it("an empty or missing folder is an empty listing", async () => {
    const { h } = await setup();
    const body = parseJson(await h.call("list_objects", { path: "nope" }), ListObjectsResult);
    expect(body).toEqual({ path: "nope/", folders: [], files: [], next_token: null });
  });

  it("folder placeholder objects never show up as files", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}sub/`, "");
    f.put(`${ROOT}empty-folder/`, "");
    const root = parseJson(await h.call("list_objects", {}), ListObjectsResult);
    expect(root.folders.sort()).toEqual(["empty-folder/", "sub/"]);

    const recursive = parseJson(await h.call("list_objects", { recursive: true }), ListObjectsResult);
    for (const file of recursive.files) {
      expect(file.path).not.toBe("");
      expect(file.path.endsWith("/")).toBe(false);
    }

    const sub = parseJson(await h.call("list_objects", { path: "sub" }), ListObjectsResult);
    expect(sub.files.map((x) => x.path)).toEqual(["sub/b.txt"]);
    expect(sub.folders).not.toContain("sub/");
  });

  it("drops keys outside the root even if the provider returns them (prefix collision)", async () => {
    const { fake: f, h } = await setup();
    f.ignorePrefix = true;
    for (const recursive of [true, false]) {
      const result = await h.call("list_objects", { recursive });
      const body = parseJson(result, ListObjectsResult);
      const all = [...body.folders, ...body.files.map((x) => x.path)];
      expect(all.length).toBeGreaterThan(0);
      for (const path of all) {
        expect(path).not.toMatch(/leak|secret|backup|outside/);
      }
      expectNoLeak(result);
    }
  });

  it("clamps max_keys to MCP_S3_MAX_LIST_KEYS", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_LIST_KEYS: "3" });
    for (let i = 0; i < 10; i++) f.put(`${ROOT}many/f${String(i)}.txt`, "x");
    const body = parseJson(await h.call("list_objects", { path: "many", max_keys: 999 }), ListObjectsResult);
    expect(body.files.length + body.folders.length).toBeLessThanOrEqual(3);
    expect(body.next_token).not.toBeNull();
    await h.call("list_objects", { path: "many" });
    await h.call("list_objects", { path: "many", max_keys: 2 });
    expect(listInputs(f).map((i) => i.MaxKeys)).toEqual([3, 3, 2]);
  });

  it("clamps max_keys to the default of 200", async () => {
    const { fake: f, h } = await setup();
    await h.call("list_objects", { max_keys: 1000 });
    expect(listInputs(f)[0]?.MaxKeys).toBe(200);
  });

  it.each([0, -1, 1001, 1.5])("rejects max_keys=%j without S3 calls", async (maxKeys) => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call("list_objects", { max_keys: maxKeys }));
    expect(f.mock.calls()).toHaveLength(0);
  });
});

describe("list_objects pagination (next_token)", () => {
  async function paged() {
    const ctx = await setup({ MCP_S3_MAX_LIST_KEYS: "2" });
    for (let i = 0; i < 5; i++) ctx.fake.put(`${ROOT}p/f${String(i)}.txt`, "x");
    return ctx;
  }

  it("walks all pages; next_token is opaque and never the raw S3 token", async () => {
    const { fake: f, h } = await paged();
    const seen: string[] = [];
    let token: string | null = null;
    let pages = 0;
    do {
      const args: Record<string, unknown> = { path: "p", recursive: true };
      if (token !== null) args.continuation_token = token;
      const result = await h.call("list_objects", args);
      expectNoLeak(result);
      const body = parseJson(result, ListObjectsResult);
      seen.push(...body.files.map((x) => x.path));
      token = body.next_token;
      if (token !== null) {
        expect(f.issuedTokens).not.toContain(token);
        for (const raw of f.issuedTokens) expect(token).not.toContain(raw);
      }
      pages++;
    } while (token !== null && pages < 10);

    expect(seen).toEqual(["p/f0.txt", "p/f1.txt", "p/f2.txt", "p/f3.txt", "p/f4.txt"]);
    expect(pages).toBe(3);
    // The real S3 tokens were sent back to S3 on the follow-up requests.
    const sentTokens = listInputs(f).map((i) => i.ContinuationToken);
    expect(sentTokens).toEqual([undefined, ...f.issuedTokens]);
  });

  it("a token cannot be used with a different recursive value", async () => {
    const { fake: f, h } = await paged();
    const first = parseJson(await h.call("list_objects", { path: "p", recursive: true }), ListObjectsResult);
    expect(first.next_token).not.toBeNull();
    const calls = f.mock.calls().length;
    const result = await h.call("list_objects", { path: "p", recursive: false, continuation_token: first.next_token });
    expectToolError(result, "InvalidRequest");
    expect(f.mock.calls()).toHaveLength(calls);
  });

  it("a token cannot be used with a different path", async () => {
    const { fake: f, h } = await paged();
    const first = parseJson(await h.call("list_objects", { path: "p" }), ListObjectsResult);
    expect(first.next_token).not.toBeNull();
    const calls = f.mock.calls().length;
    for (const path of ["", "sub", "p/f0.txt"]) {
      expectToolError(await h.call("list_objects", { path, continuation_token: first.next_token }), "InvalidRequest");
    }
    expect(f.mock.calls()).toHaveLength(calls);
  });

  it("a forged token or a raw S3 token is rejected without S3 calls", async () => {
    const { fake: f, h } = await paged();
    const first = parseJson(await h.call("list_objects", { path: "p" }), ListObjectsResult);
    expect(first.next_token).not.toBeNull();
    const calls = f.mock.calls().length;
    const raw = f.issuedTokens[0] ?? "";
    for (const forged of ["not-a-real-token", raw, Buffer.from(`${BUCKET}/outside/`).toString("base64")]) {
      const result = await h.call("list_objects", { path: "p", continuation_token: forged });
      expectToolError(result, "InvalidRequest");
      expectNoLeak(result);
    }
    expect(f.mock.calls()).toHaveLength(calls);
  });

  it("next_token is null when the listing is complete", async () => {
    const { h } = await paged();
    const body = parseJson(await h.call("list_objects", { path: "p", max_keys: 2 }), ListObjectsResult);
    expect(body.next_token).not.toBeNull();
    const all = parseJson(await h.call("list_objects", { path: "sub" }), ListObjectsResult);
    expect(all.next_token).toBeNull();
  });
});

// ---------------------------------------------------------------------------

describe("get_object_info", () => {
  it("returns size, content type, last modified, etag, and metadata with a relative path", async () => {
    const { fake: f, h } = await setup();
    const result = await h.call("get_object_info", { path: "a.txt" });
    const body = parseJson(result, ObjectInfoResult);
    const stored = f.objects.get(`${ROOT}a.txt`);
    expect(body).toEqual({
      path: "a.txt",
      size: 13,
      content_type: "text/plain",
      last_modified: stored?.lastModified.toISOString(),
      etag: stored?.etag,
      metadata: { owner: "team-a" },
    });
    expectNoLeak(result);
  });

  it("missing object is NotFound", async () => {
    const { h } = await setup();
    const result = await h.call("get_object_info", { path: "missing.txt" });
    expect(expectToolError(result, "NotFound")).toBe("NotFound: object not found");
  });

  it("keys outside the root cannot be reached through a lookalike path", async () => {
    const { fake: f, h } = await setup();
    // "claude-workspace-backup/leak.txt" is outside; this path stays inside the root.
    expectToolError(await h.call("get_object_info", { path: "-backup/leak.txt" }), "NotFound");
    expect(headInputs(f)[0]?.Key).toBe(`${ROOT}-backup/leak.txt`);
  });
});

// ---------------------------------------------------------------------------

describe("read_object: text", () => {
  it("returns a small UTF-8 file as one text item", async () => {
    const { h } = await setup();
    const result = await h.call("read_object", { path: "a.txt" });
    expectOk(result);
    expect(onlyText(result)).toBe("hello from a\n");
    expectNoLeak(result);
  });

  it("an empty file returns the empty-file notice", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}empty.txt`, "");
    expect(onlyText(await h.call("read_object", { path: "empty.txt" }))).toBe("[empty file: 0 bytes]");
  });

  it("missing object is NotFound", async () => {
    const { h } = await setup();
    expectToolError(await h.call("read_object", { path: "missing.txt" }), "NotFound");
  });

  it("truncates at MCP_S3_MAX_READ_BYTES and explains how to continue", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: "16" });
    const content = "0123456789abcdefghijklmnopqrstuvwxyzABCD"; // 40 bytes
    f.put(`${ROOT}long.txt`, content);

    const first = await h.call("read_object", { path: "long.txt" });
    expectOk(first);
    const [chunk, note] = texts(first);
    expect(chunk).toBe(content.slice(0, 16));
    expect(note).toMatch(/bytes 0-15 of 40/);
    expect(note).toMatch(/offset=16/);
    expect(getInputs(f).at(-1)?.Range).toBe("bytes=0-15");

    const second = await h.call("read_object", { path: "long.txt", offset: 16 });
    expect(texts(second)[0]).toBe(content.slice(16, 32));
    expect(nextOffset(second)).toBe(32);
    expect(getInputs(f).at(-1)?.Range).toBe("bytes=16-31");

    const last = await h.call("read_object", { path: "long.txt", offset: 32 });
    expect(texts(last)[0]).toBe(content.slice(32));
    expect(nextOffset(last)).toBeUndefined();
    expect(getInputs(f).at(-1)?.Range).toBe("bytes=32-39");
    expectNoLeak([first, second, last]);
  });

  it("never requests more than 1 MiB by default", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}big.txt`, "x".repeat(3 * 1024 * 1024));
    const result = await h.call("read_object", { path: "big.txt" });
    expectOk(result);
    expect(getInputs(f)).toHaveLength(1);
    expect(getInputs(f)[0]?.Range).toBe("bytes=0-1048575");
    expect(texts(result)[0]).toHaveLength(1_048_576);
    expect(nextOffset(result)).toBe(1_048_576);
    expect(texts(result)[1]).toMatch(/of 3145728/);
  });

  it("honours offset and length", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}abc.txt`, "abcdefghijklmnopqrstuvwxyz");
    const result = await h.call("read_object", { path: "abc.txt", offset: 5, length: 4 });
    expect(texts(result)[0]).toBe("fghi");
    expect(getInputs(f)[0]?.Range).toBe("bytes=5-8");
    expect(nextOffset(result)).toBe(9);
  });

  it("clamps length to MCP_S3_MAX_READ_BYTES", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: "16" });
    f.put(`${ROOT}abc.txt`, "abcdefghijklmnopqrstuvwxyz");
    await h.call("read_object", { path: "abc.txt", length: 1000 });
    await h.call("read_object", { path: "abc.txt", offset: 3, length: 10_000_000 });
    expect(getInputs(f).map((i) => i.Range)).toEqual(["bytes=0-15", "bytes=3-18"]);
  });

  it("clamps the range to the end of the file", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}abc.txt`, "abcdefghijklmnopqrstuvwxyz");
    const result = await h.call("read_object", { path: "abc.txt", offset: 20, length: 100 });
    expect(texts(result)[0]).toBe("uvwxyz");
    expect(getInputs(f)[0]?.Range).toBe("bytes=20-25");
    expect(nextOffset(result)).toBeUndefined();
  });

  it.each([26, 27, 1_000_000])("offset=%i at or past the end is InvalidRange without GetObject", async (offset) => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}abc.txt`, "abcdefghijklmnopqrstuvwxyz");
    const result = await h.call("read_object", { path: "abc.txt", offset });
    expectToolError(result, "InvalidRange");
    expect(getInputs(f)).toHaveLength(0);
    expectNoLeak(result);
  });

  it("offset=size-1 reads the last byte", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}abc.txt`, "abcdefghijklmnopqrstuvwxyz");
    const result = await h.call("read_object", { path: "abc.txt", offset: 25 });
    expect(texts(result)[0]).toBe("z");
    expect(getInputs(f)[0]?.Range).toBe("bytes=25-25");
  });

  it.each([-1, 1.5])("rejects offset=%j without S3 calls", async (offset) => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call("read_object", { path: "a.txt", offset }));
    expect(f.mock.calls()).toHaveLength(0);
  });

  it.each([0, -5])("rejects length=%j without S3 calls", async (length) => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call("read_object", { path: "a.txt", length }));
    expect(f.mock.calls()).toHaveLength(0);
  });

  it("if storage ignores the Range (200, whole object), offset 0 is still capped at MCP_S3_MAX_READ_BYTES", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: "16" });
    const content = "0123456789abcdefghijklmnopqrstuvwxyzABCD"; // 40 bytes
    f.put(`${ROOT}long.txt`, content);
    f.ignoreRange = true;
    const result = await h.call("read_object", { path: "long.txt" });
    expectOk(result);
    expect(texts(result)[0]).toBe(content.slice(0, 16));
    expect(nextOffset(result)).toBe(16);
    expectNoLeak(result);
  });

  it("if storage ignores the Range at offset > 0, it is InternalError and the body is not read", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: "16" });
    f.put(`${ROOT}long.txt`, "SECRET-BODY-".repeat(10));
    f.ignoreRange = true;
    const result = await h.call("read_object", { path: "long.txt", offset: 16 });
    expectToolError(result, "InternalError");
    expect(f.bodyReads).toHaveLength(0);
    expect(JSON.stringify(result)).not.toContain("SECRET-BODY");
    expectNoLeak(result);
  });
});

describe("read_object: UTF-8 multi-byte boundaries", () => {
  const sample = "aé€😀b".repeat(7) + "ü"; // mix of 1, 2, 3, and 4 byte sequences

  async function readAll(h: InMemoryHarness, path: string): Promise<{ chunks: string[]; offsets: number[] }> {
    const chunks: string[] = [];
    const offsets: number[] = [0];
    let offset: number | undefined = 0;
    for (let i = 0; i < 200 && offset !== undefined; i++) {
      const result: CallToolResult = await h.call("read_object", { path, offset });
      expectOk(result);
      chunks.push(texts(result)[0] ?? "");
      offset = nextOffset(result);
      if (offset !== undefined) offsets.push(offset);
    }
    return { chunks, offsets };
  }

  it.each([4, 5, 6, 7, 9, 16])("with a %i-byte limit every chunk is valid text and chunks join to the original", async (limit) => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: String(limit) });
    f.put(`${ROOT}utf8.txt`, sample);
    const bytes = Buffer.from(sample, "utf8");

    const { chunks, offsets } = await readAll(h, "utf8.txt");
    expect(chunks.join("")).toBe(sample);
    for (const chunk of chunks) {
      expect(chunk).not.toContain("�");
      expect(chunk.length).toBeGreaterThan(0);
      expect(Buffer.byteLength(chunk, "utf8")).toBeLessThanOrEqual(limit);
    }
    // Every continuation offset is on a character boundary.
    for (const offset of offsets) {
      expect(bytes.subarray(0, offset).toString("utf8")).not.toContain("�");
    }
    for (const input of getInputs(f)) expect(rangeLength(input.Range)).toBeLessThanOrEqual(limit);
  });

  it("an offset inside a multi-byte character skips to the next whole character", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}e.txt`, "aéb"); // 61 c3 a9 62
    const result = await h.call("read_object", { path: "e.txt", offset: 2 });
    expectOk(result);
    expect(texts(result)[0]).toBe("b");
    expect(texts(result).join("")).not.toContain("�");
  });
});

describe("read_object: binary and images", () => {
  it.each([
    ["PNG", PNG_1X1, "image/png"],
    ["JPEG", JPEG_HEAD, "image/jpeg"],
    ["GIF", GIF_1X1, "image/gif"],
    ["WebP", WEBP_HEAD, "image/webp"],
  ])("detects %s from magic bytes even with Content-Type application/octet-stream", async (_name, bytes, mime) => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}blob`, bytes, { contentType: "application/octet-stream" });
    const result = await h.call("read_object", { path: "blob" });
    expectOk(result);
    expect(result.content).toEqual([{ type: "image", data: Buffer.from(bytes).toString("base64"), mimeType: mime }]);
  });

  it("returns img.png as image content with mimeType image/png", async () => {
    const { h } = await setup();
    const result = await h.call("read_object", { path: "img.png" });
    expect(result.content).toEqual([{ type: "image", data: Buffer.from(PNG_1X1).toString("base64"), mimeType: "image/png" }]);
    expectNoLeak(result);
  });

  it("an image above MCP_S3_MAX_READ_BYTES returns a notice instead of partial image data", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: "64" });
    f.put(`${ROOT}big.png`, pngOfSize(200), { contentType: "image/png" });
    const result = await h.call("read_object", { path: "big.png" });
    expectOk(result);
    expect(result.content.every((item) => item.type === "text")).toBe(true);
    const text = texts(result).join("\n");
    expect(text).toMatch(/image/);
    expect(text).toMatch(/200 bytes/);
    for (const input of getInputs(f)) expect(rangeLength(input.Range)).toBeLessThanOrEqual(64);
    expectNoLeak(result);
  });

  it.each([
    [{ length: 50 }],
    [{ offset: 10 }],
  ])("a partial image read %j returns a notice, never partial image data", async (extra) => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}part.png`, pngOfSize(200), { contentType: "image/png" });
    const result = await h.call("read_object", { path: "part.png", ...extra });
    expectOk(result);
    expect(result.content.every((item) => item.type === "text")).toBe(true);
    expect(texts(result).join("\n")).toMatch(/image/);
  });

  it("a non-image binary file returns a binary notice with the relative path", async () => {
    const { fake: f, h } = await setup();
    const bytes = Uint8Array.from([0x00, 0xff, 0xfe, 0x80, 0x81, 0x00, 0x01, 0xc3, 0x28]);
    f.put(`${ROOT}data/blob.bin`, bytes, { contentType: "application/octet-stream" });
    const result = await h.call("read_object", { path: "data/blob.bin" });
    expectOk(result);
    const text = onlyText(result);
    expect(text.startsWith("[binary file data/blob.bin")).toBe(true);
    expect(text).toContain("9 bytes");
    expect(text).not.toContain(Buffer.from(bytes).toString("base64"));
    expectNoLeak(result);
  });

  it("sniffImageMime recognises signatures and rejects lookalikes", () => {
    expect(sniffImageMime(PNG_1X1)).toBe("image/png");
    expect(sniffImageMime(JPEG_HEAD)).toBe("image/jpeg");
    expect(sniffImageMime(GIF_1X1)).toBe("image/gif");
    expect(sniffImageMime(Buffer.from("GIF87a....."))).toBe("image/gif");
    expect(sniffImageMime(WEBP_HEAD)).toBe("image/webp");
    expect(sniffImageMime(Buffer.from("RIFF\x1a\x00\x00\x00WAVEfmt "))).toBeUndefined();
    expect(sniffImageMime(PNG_1X1.subarray(0, 4))).toBeUndefined();
    expect(sniffImageMime(new Uint8Array(0))).toBeUndefined();
    expect(sniffImageMime(Buffer.from("hello world"))).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------

describe("search_objects", () => {
  it("a pattern without '/' matches file names in every subfolder", async () => {
    const { h } = await setup();
    const result = await h.call("search_objects", { pattern: "*.txt" });
    const body = parseJson(result, SearchObjectsResult);
    expect(body.path).toBe("");
    expect(body.pattern).toBe("*.txt");
    expect(body.matches.sort()).toEqual(["a.txt", "sub/b.txt"]);
    expect(body.truncated).toBe(false);
    expectNoLeak(result);
  });

  it("a pattern with '/' matches the path relative to `path`", async () => {
    const { h } = await setup();
    const body = parseJson(await h.call("search_objects", { pattern: "sub/*.txt" }), SearchObjectsResult);
    expect(body.matches).toEqual(["sub/b.txt"]);
  });

  it("searching a subfolder returns root-relative paths", async () => {
    const { h } = await setup();
    const body = parseJson(await h.call("search_objects", { path: "sub", pattern: "*.txt" }), SearchObjectsResult);
    expect(body.path).toBe("sub/");
    expect(body.matches).toEqual(["sub/b.txt"]);
  });

  it("drops keys outside the root even if the provider returns them (prefix collision)", async () => {
    const { fake: f, h } = await setup();
    f.ignorePrefix = true;
    const result = await h.call("search_objects", { pattern: "*.txt" });
    const body = parseJson(result, SearchObjectsResult);
    expect(body.matches.sort()).toEqual(["a.txt", "sub/b.txt"]);
    expectNoLeak(result);
  });

  it.each(["../outside/*", "../**", "**/../**", "../*-backup/*", "/outside/*"])(
    "pattern %j cannot reach keys outside the root",
    async (pattern) => {
      const { fake: f, h } = await setup();
      f.ignorePrefix = true;
      const result = await h.call("search_objects", { pattern });
      expectOk(result);
      const body = parseJson(result, SearchObjectsResult);
      for (const match of body.matches) expect(match).not.toMatch(/leak|secret/);
      expectNoLeak(result);
      for (const input of listInputs(f)) expect(input.Prefix).toBe(ROOT);
    },
  );

  it("follows S3 pagination to find matches beyond the first page", async () => {
    const { fake: f, h } = await setup();
    for (let i = 0; i < 1200; i++) f.put(`${ROOT}bulk/f${String(i).padStart(4, "0")}.txt`, "x");
    f.put(`${ROOT}bulk/zz-target.csv`, "a,b");
    const body = parseJson(await h.call("search_objects", { path: "bulk", pattern: "*.csv" }), SearchObjectsResult);
    expect(body.matches).toEqual(["bulk/zz-target.csv"]);
    expect(listInputs(f).length).toBeGreaterThanOrEqual(2);
    expect(listInputs(f)[1]?.ContinuationToken).toBe(f.issuedTokens[0]);
  });

  it("clamps max_results to MCP_S3_MAX_LIST_KEYS and reports truncation", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_LIST_KEYS: "3" });
    for (let i = 0; i < 10; i++) f.put(`${ROOT}m/f${String(i)}.log`, "x");
    const body = parseJson(await h.call("search_objects", { pattern: "*.log", max_results: 50 }), SearchObjectsResult);
    expect(body.matches).toHaveLength(3);
    expect(body.truncated).toBe(true);
    expect(typeof body.note).toBe("string");
  });

  it("max_results below the limit is honoured; exact fit is not truncated", async () => {
    const { fake: f, h } = await setup();
    for (let i = 0; i < 4; i++) f.put(`${ROOT}m/f${String(i)}.log`, "x");
    const two = parseJson(await h.call("search_objects", { pattern: "*.log", max_results: 2 }), SearchObjectsResult);
    expect(two.matches).toHaveLength(2);
    expect(two.truncated).toBe(true);
    const four = parseJson(await h.call("search_objects", { pattern: "*.log", max_results: 4 }), SearchObjectsResult);
    expect(four.matches).toHaveLength(4);
    expect(four.truncated).toBe(false);
  });

  it("no matches is an empty list, not an error", async () => {
    const { h } = await setup();
    const body = parseJson(await h.call("search_objects", { pattern: "*.nothing" }), SearchObjectsResult);
    expect(body.matches).toEqual([]);
    expect(body.truncated).toBe(false);
  });

  it.each([0, 1001])("rejects max_results=%i without S3 calls", async (maxResults) => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call("search_objects", { pattern: "*", max_results: maxResults }));
    expect(f.mock.calls()).toHaveLength(0);
  });

  it("rejects an empty pattern without S3 calls", async () => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call("search_objects", { pattern: "" }));
    expect(f.mock.calls()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------

function serviceError(name: string, status: number, message: string): S3ServiceException {
  return new S3ServiceException({
    name,
    $fault: status >= 500 ? "server" : "client",
    $metadata: { httpStatusCode: status, requestId: "REQ-ERR-0001", extendedRequestId: "EXT-ERR-0001" },
    message,
  });
}

const LEAKY = `arn:aws:s3:::${BUCKET}/${ROOT}a.txt RequestId REQ-ERR-0001`;

const ERROR_CASES: [string, () => Error, string][] = [
  ["NoSuchKey", () => noSuchKey(BUCKET, `${ROOT}a.txt`), "NotFound: object not found"],
  ["NotFound", () => notFound(), "NotFound: object not found"],
  ["unknown name with HTTP 404", () => serviceError("UnknownError", 404, LEAKY), "NotFound: object not found"],
  ["AccessDenied", () => accessDenied(BUCKET, `${ROOT}a.txt`), "AccessDenied: access denied"],
  ["Forbidden", () => serviceError("Forbidden", 403, LEAKY), "AccessDenied: access denied"],
  ["unknown name with HTTP 403", () => serviceError("UnknownError", 403, LEAKY), "AccessDenied: access denied"],
];

describe("S3 errors are mapped to generic messages", () => {
  for (const [tool, command] of [
    ["get_object_info", HeadObjectCommand],
    ["read_object", HeadObjectCommand],
  ] as const) {
    it.each(ERROR_CASES)(`${tool}: %s`, async (_name, makeError, expected) => {
      const { fake: f, h } = await setup();
      f.mock.on(command).rejects(makeError());
      const result = await h.call(tool, { path: "a.txt" });
      expect(result.isError).toBe(true);
      expect(onlyText(result)).toBe(expected);
      expectNoLeak(result);
      expect(JSON.stringify(result)).not.toContain("REQ-");
    });
  }

  it.each(ERROR_CASES)("read_object GetObject failure: %s", async (_name, makeError, expected) => {
    const { fake: f, h } = await setup();
    f.mock.on(GetObjectCommand).rejects(makeError());
    const result = await h.call("read_object", { path: "a.txt" });
    expect(onlyText(result)).toBe(expected);
    expectNoLeak(result);
  });

  it.each([
    ["list_objects", {}],
    ["search_objects", { pattern: "*" }],
  ])("%s: ListObjectsV2 AccessDenied", async (tool, args) => {
    const { fake: f, h } = await setup();
    f.mock.on(ListObjectsV2Command).rejects(accessDenied(BUCKET, ROOT));
    const result = await h.call(tool, args);
    expect(onlyText(result)).toBe("AccessDenied: access denied");
    expect(result.isError).toBe(true);
    expectNoLeak(result);
  });

  it.each([
    ["list_objects", {}],
    ["search_objects", { pattern: "*" }],
    ["get_object_info", { path: "a.txt" }],
    ["read_object", { path: "a.txt" }],
  ])(
    "%s: NoSuchBucket becomes StorageUnavailable without the bucket name",
    async (tool, args) => {
      const { fake: f, h } = await setup();
      f.mock.onAnyCommand().rejects(noSuchBucket(BUCKET));
      const result = await h.call(tool, args);
      expectToolError(result, "StorageUnavailable");
      expectNoLeak(result);
    },
  );

  it("an unexpected error never echoes its message", async () => {
    const { fake: f, h } = await setup();
    f.mock.on(HeadObjectCommand).rejects(new Error(`boom ${LEAKY} at /home/user/secret/path`));
    const result = await h.call("get_object_info", { path: "a.txt" });
    expectToolError(result, "InternalError");
    expectNoLeak(result);
    expect(JSON.stringify(result)).not.toContain("boom");
  });

  it("a network error is StorageUnavailable without host details", async () => {
    const { fake: f, h } = await setup();
    const err = Object.assign(new Error(`connect ECONNREFUSED 10.1.2.3:9000 ${BUCKET}.s3.local`), { code: "ECONNREFUSED" });
    f.mock.on(HeadObjectCommand).rejects(err);
    const result = await h.call("get_object_info", { path: "a.txt" });
    expectToolError(result, "StorageUnavailable");
    expectNoLeak(result);
    expect(JSON.stringify(result)).not.toContain("10.1.2.3");
  });

  it("a server error (500) is StorageUnavailable", async () => {
    const { fake: f, h } = await setup();
    f.mock.on(HeadObjectCommand).rejects(serviceError("InternalError", 500, LEAKY));
    const result = await h.call("get_object_info", { path: "a.txt" });
    expectToolError(result, "StorageUnavailable");
    expectNoLeak(result);
  });
});

describe("errors.ts helpers", () => {
  it("PathOutsideRootError keeps only the static reason", () => {
    expect(toSafeError(new PathOutsideRootError("relative segment"))).toMatchObject({
      code: "PathOutsideRoot",
      message: "path is not allowed (relative segment)",
    });
  });

  it("non-Error throwables become InternalError", () => {
    expect(toSafeError(`thrown string ${BUCKET}`)).toMatchObject({ code: "InternalError" });
    expect(toSafeError(undefined)).toMatchObject({ code: "InternalError" });
    expect(JSON.stringify(toSafeError({ bucket: BUCKET }))).not.toContain(BUCKET);
  });

  it("errorResult is an isError result with one text item", () => {
    expect(errorResult(noSuchKey(BUCKET, `${ROOT}x`))).toEqual({
      content: [{ type: "text", text: "NotFound: object not found" }],
      isError: true,
    });
  });
});

describe("errors.ts: error names that exist on Object.prototype", () => {
  it.each(["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf", "isPrototypeOf", "__defineGetter__"])(
    "name %j maps to InternalError: unexpected error",
    (name) => {
      const err = new Error("boom");
      err.name = name;
      expect(safeErrorMessage(err)).toBe("InternalError: unexpected error");
      expect(toSafeError(err).code).toBe("InternalError");
    },
  );

  it("through a tool, a storage error named 'constructor' is a generic InternalError", async () => {
    const { fake: f, h } = await setup();
    const err = new Error(`boom ${LEAKY}`);
    err.name = "constructor";
    f.mock.on(HeadObjectCommand).rejects(err);
    const result = await h.call("get_object_info", { path: "a.txt" });
    expect(onlyText(result)).toBe("InternalError: unexpected error");
    expectNoLeak(result);
  });
});

// ---------------------------------------------------------------------------

describe("buildServer: registered tools", () => {
  it.each([
    [{}],
    [{ MCP_S3_ALLOW_DELETE: "true" }],
    [{ MCP_S3_READ_ONLY: "false" }],
    [{ MCP_S3_READ_ONLY: "false", MCP_S3_ALLOW_DELETE: "true" }],
  ])("with %j only the read tools are registered (write/delete are Phase 2)", async (overrides: Record<string, string>) => {
    const f = (fake = new FakeS3(BUCKET));
    const built = buildServer(makeConfig(overrides), { storage: new Storage(f.client, BUCKET) });
    try {
      expect(built.registered).toEqual({ read: true, write: false, delete: false });
      expect([...built.tools].sort()).toEqual(READ_TOOLS);
    } finally {
      await built.server.close();
    }
    const h = await connectTo(f, overrides);
    const { tools } = await h.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([...built.tools].sort());
  });
});

// ---------------------------------------------------------------------------

describe("read_object: image regressions (MAJOR 2)", () => {
  function expectNoImage(result: CallToolResult): void {
    expectOk(result);
    expect(result.content.length).toBeGreaterThan(0);
    for (const item of result.content) expect(item.type).toBe("text");
  }

  it.each([
    ["Content-Type image/png with text inside", "fake.png", "image/png"],
    ["Content-Type image/jpeg with text inside", "fake.jpg", "image/jpeg"],
    [".png with application/octet-stream and text inside", "notes.png", "application/octet-stream"],
    [".JPG without Content-Type and text inside", "photo.JPG", undefined],
  ])("%s is a 'binary or corrupt image' notice, never image content", async (_name, path, contentType) => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}${path}`, "this is plain text, not an image\n", contentType === undefined ? {} : { contentType });
    const result = await h.call("read_object", { path });
    expectNoImage(result);
    expect(texts(result)[0]?.startsWith(`[binary or corrupt image ${path}`)).toBe(true);
    expectNoLeak(result);
  });

  it("PNG bytes labelled text/plain are returned as image/png", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}pic.txt`, PNG_1X1, { contentType: "text/plain" });
    const result = await h.call("read_object", { path: "pic.txt" });
    expect(result.content).toEqual([{ type: "image", data: Buffer.from(PNG_1X1).toString("base64"), mimeType: "image/png" }]);
  });

  it("JPEG bytes labelled image/png use the mimeType of the actual bytes", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}pic.png`, JPEG_HEAD, { contentType: "image/png" });
    const result = await h.call("read_object", { path: "pic.png" });
    expect(result.content).toEqual([{ type: "image", data: Buffer.from(JPEG_HEAD).toString("base64"), mimeType: "image/jpeg" }]);
  });

  it("the image size limit is 3,932,160 bytes (5 MiB as base64)", () => {
    expect(MAX_IMAGE_BYTES).toBe(3_932_160);
  });

  it("with an 8 MiB read limit, a PNG of 3,932,161 bytes is a notice", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: String(8 * 1024 * 1024) });
    f.put(`${ROOT}huge.png`, pngOfSize(3_932_161), { contentType: "image/png" });
    const result = await h.call("read_object", { path: "huge.png" });
    expectNoImage(result);
    expect(texts(result).join("\n")).toMatch(/3932161 bytes/);
    expect(JSON.stringify(result).length).toBeLessThan(10_000);
  });

  it("with an 8 MiB read limit, a PNG of exactly 3,932,160 bytes is an image of 5,242,880 base64 characters", async () => {
    const { fake: f, h } = await setup({ MCP_S3_MAX_READ_BYTES: String(8 * 1024 * 1024) });
    const bytes = pngOfSize(3_932_160);
    f.put(`${ROOT}max.png`, bytes, { contentType: "image/png" });
    const result = await h.call("read_object", { path: "max.png" });
    expect(result.content).toHaveLength(1);
    const [item] = result.content;
    if (item?.type !== "image") throw new Error(`expected image content, got ${String(item?.type)}`);
    expect(item.mimeType).toBe("image/png");
    expect(item.data).toHaveLength(5_242_880);
    expect(item.data).toBe(Buffer.from(bytes).toString("base64"));
  });

  it.each([
    ["image/png Content-Type", "pic.png", "image/png"],
    [".png with octet-stream", "pic2.png", "application/octet-stream"],
  ])("offset > 0 on an image (%s) is the 'only whole' notice", async (_name, path, contentType) => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}${path}`, pngOfSize(200), { contentType });
    for (const offset of [1, 8, 100]) {
      const result = await h.call("read_object", { path, offset });
      expectNoImage(result);
      expect(texts(result).join("\n")).toMatch(/images can only be returned whole/);
    }
  });

  it("offset > 0 on image bytes without any image hint never returns image content", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}blob`, pngOfSize(200), { contentType: "application/octet-stream" });
    for (const offset of [1, 8, 100]) expectNoImage(await h.call("read_object", { path: "blob", offset }));
  });
});

// ---------------------------------------------------------------------------

describe("read_object: the object must not change between HEAD and GET", () => {
  it("GetObject PreconditionFailed (412) is a Conflict", async () => {
    const { fake: f, h } = await setup();
    f.mock.on(GetObjectCommand).rejects(preconditionFailed());
    expect(onlyText(await h.call("read_object", { path: "a.txt" }))).toBe("Conflict: object changed during read, retry");
  });

  it("an unnamed 412 is a Conflict too", async () => {
    const { fake: f, h } = await setup();
    f.mock.on(GetObjectCommand).rejects(serviceError("UnknownError", 412, LEAKY));
    const result = await h.call("read_object", { path: "a.txt" });
    expect(onlyText(result)).toBe("Conflict: object changed during read, retry");
    expectNoLeak(result);
  });

  it("a write between HEAD and GET is detected through If-Match and its content is not returned", async () => {
    const { fake: f, h } = await setup();
    f.beforeGet = () => {
      f.put(`${ROOT}a.txt`, "REPLACED-CONTENT-THAT-IS-LONGER");
    };
    const result = await h.call("read_object", { path: "a.txt" });
    expect(result.isError).toBe(true);
    expect(onlyText(result)).toBe("Conflict: object changed during read, retry");
    expect(JSON.stringify(result)).not.toContain("REPLACED");
  });
});

describe("read_object: provider responses that do not honour the Range", () => {
  it("206 with a Content-Range for another offset is InternalError and nothing is shown", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}long.txt`, "0123456789abcdefghij");
    let bodyRead = false;
    const body = {
      transformToByteArray: () => {
        bodyRead = true;
        return Promise.resolve(Buffer.from("0123456789"));
      },
      transformToString: () => {
        bodyRead = true;
        return Promise.resolve("0123456789");
      },
      transformToWebStream: () => {
        bodyRead = true;
        return new Blob(["0123456789"]).stream();
      },
    };
    f.mock.on(GetObjectCommand).resolves({
      $metadata: { httpStatusCode: 206 },
      Body: body as unknown as GetObjectCommandOutput["Body"],
      ContentRange: "bytes 0-9/20",
      ContentLength: 10,
    });
    const result = await h.call("read_object", { path: "long.txt", offset: 10 });
    expectToolError(result, "InternalError");
    expect(bodyRead).toBe(false);
    expect(JSON.stringify(result)).not.toContain("0123456789");
    expectNoLeak(result);
  });

  it("200 without Content-Range at offset 0 is accepted for a small object", async () => {
    const { fake: f, h } = await setup();
    f.ignoreRange = true;
    expect(onlyText(await h.call("read_object", { path: "a.txt" }))).toBe("hello from a\n");
  });

  it("200 without Content-Range at offset > 0 is InternalError and the body is not read", async () => {
    const { fake: f, h } = await setup();
    f.ignoreRange = true;
    const result = await h.call("read_object", { path: "a.txt", offset: 6 });
    expectToolError(result, "InternalError");
    expect(f.bodyReads).toHaveLength(0);
    expect(JSON.stringify(result)).not.toContain("hello from a");
  });
});

// ---------------------------------------------------------------------------

describe("list_objects: stateless encrypted continuation tokens", () => {
  const KEY_A = randomBytes(32).toString("base64");
  const KEY_B = randomBytes(32).toString("base64");
  const INVALID_TOKEN_MESSAGE =
    "InvalidRequest: continuation_token is invalid or expired, or was issued for a different path/recursive value; list again without it";

  function pagedFake(): FakeS3 {
    const f = (fake = new FakeS3(BUCKET));
    seed(f);
    for (let i = 0; i < 5; i++) f.put(`${ROOT}p/f${String(i)}.txt`, "x");
    return f;
  }

  async function firstPage(h: InMemoryHarness, args: Record<string, unknown> = { path: "p", recursive: true }): Promise<string> {
    const body = parseJson(await h.call("list_objects", args), ListObjectsResult);
    expect(body.files.map((x) => x.path)).toEqual(["p/f0.txt", "p/f1.txt"]);
    if (body.next_token === null) throw new Error("expected a next_token");
    return body.next_token;
  }

  it("a token from one server works on another server with the same MCP_S3_TOKEN_KEY", async () => {
    const f = pagedFake();
    const a = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_A, MCP_S3_MAX_LIST_KEYS: "2" });
    const b = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_A, MCP_S3_MAX_LIST_KEYS: "2" });
    const token = await firstPage(a);
    const page2 = parseJson(await b.call("list_objects", { path: "p", recursive: true, continuation_token: token }), ListObjectsResult);
    expect(page2.files.map((x) => x.path)).toEqual(["p/f2.txt", "p/f3.txt"]);
    expect(listInputs(f).at(-1)?.ContinuationToken).toBe(f.issuedTokens[0]);
  });

  it("a token is rejected by a server with another key, without any S3 call", async () => {
    const f = pagedFake();
    const a = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_A, MCP_S3_MAX_LIST_KEYS: "2" });
    const b = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_B, MCP_S3_MAX_LIST_KEYS: "2" });
    const token = await firstPage(a);
    const calls = f.mock.calls().length;
    const result = await b.call("list_objects", { path: "p", recursive: true, continuation_token: token });
    expect(onlyText(result)).toBe(INVALID_TOKEN_MESSAGE);
    expect(f.mock.calls()).toHaveLength(calls);
  });

  it("a token is bound to the bucket: same key, other bucket is rejected without S3 calls", async () => {
    const f = pagedFake();
    const a = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_A, MCP_S3_MAX_LIST_KEYS: "2" });
    const b = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_A, MCP_S3_MAX_LIST_KEYS: "2", S3_BUCKET: "other-bucket-9z" });
    const token = await firstPage(a);
    const calls = f.mock.calls().length;
    const result = await b.call("list_objects", { path: "p", recursive: true, continuation_token: token });
    expect(onlyText(result)).toBe(INVALID_TOKEN_MESSAGE);
    expect(f.mock.calls()).toHaveLength(calls);
  });

  it("the token is not the raw S3 token, and decoding it reveals neither the S3 token nor the prefix", async () => {
    const f = pagedFake();
    const h = await connectTo(f, { MCP_S3_MAX_LIST_KEYS: "2" });
    const token = await firstPage(h);
    const raw = f.issuedTokens[0] ?? "";
    expect(raw.length).toBeGreaterThan(0);
    expect(token).not.toContain(raw);
    const decoded = Buffer.from(token, "base64url");
    for (const view of [decoded.toString("utf8"), decoded.toString("latin1")]) {
      expect(view).not.toContain(raw);
      expect(view).not.toContain("claude-workspace");
      expect(view).not.toContain(BUCKET);
    }
  });

  it("every kind of bad token gets the identical message and no S3 call", async () => {
    const f = pagedFake();
    const h = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_A, MCP_S3_MAX_LIST_KEYS: "2" });
    const other = await connectTo(f, { MCP_S3_TOKEN_KEY: KEY_B, MCP_S3_MAX_LIST_KEYS: "2" });
    const token = await firstPage(h);
    const otherToken = await firstPage(other);
    const raw = Buffer.from(token, "base64url");
    const flip = (index: number): string => {
      const copy = Buffer.from(raw);
      copy[index] = (copy[index] ?? 0) ^ 0x01;
      return copy.toString("base64url");
    };

    const variants: [string, Record<string, unknown>][] = [
      ["tampered version", { path: "p", recursive: true, continuation_token: flip(0) }],
      ["tampered iv", { path: "p", recursive: true, continuation_token: flip(5) }],
      ["tampered ciphertext", { path: "p", recursive: true, continuation_token: flip(20) }],
      ["tampered tag", { path: "p", recursive: true, continuation_token: flip(raw.length - 1) }],
      ["other key", { path: "p", recursive: true, continuation_token: otherToken }],
      ["other path", { path: "", recursive: true, continuation_token: token }],
      ["other mode", { path: "p", recursive: false, continuation_token: token }],
      ["raw S3 token", { path: "p", recursive: true, continuation_token: f.issuedTokens[0] }],
      ["garbage", { path: "p", recursive: true, continuation_token: "not-a-real-token" }],
      ["max length garbage", { path: "p", recursive: true, continuation_token: "A".repeat(MAX_TOKEN_LENGTH) }],
    ];
    const calls = f.mock.calls().length;
    for (const [name, args] of variants) {
      const result = await h.call("list_objects", args);
      expect(onlyText(result), name).toBe(INVALID_TOKEN_MESSAGE);
      expect(result.isError, name).toBe(true);
    }
    expect(f.mock.calls()).toHaveLength(calls);
  });

  it("a raw S3 token from the client is never forwarded to ListObjectsV2", async () => {
    const f = pagedFake();
    const h = await connectTo(f, { MCP_S3_MAX_LIST_KEYS: "2" });
    await firstPage(h);
    const raw = f.issuedTokens[0] ?? "";
    expectToolError(await h.call("list_objects", { path: "p", recursive: true, continuation_token: raw }), "InvalidRequest");
    for (const input of listInputs(f)) expect(input.ContinuationToken).not.toBe(raw);
  });

  it(`continuation_token longer than ${MAX_TOKEN_LENGTH} characters is a validation error without S3 calls`, async () => {
    const f = pagedFake();
    const h = await connectTo(f);
    expectValidationError(await h.call("list_objects", { path: "p", continuation_token: "A".repeat(MAX_TOKEN_LENGTH + 1) }));
    expect(f.mock.calls()).toHaveLength(0);
  });

  it("expires after TOKEN_TTL_SECONDS (fake clock)", async () => {
    const t0 = Date.UTC(2026, 10, 26, 12, 0, 0);
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(t0);
      const f = pagedFake();
      const h = await connectTo(f, { MCP_S3_MAX_LIST_KEYS: "2" });
      const token = await firstPage(h);
      const args = { path: "p", recursive: true, continuation_token: token };

      vi.setSystemTime(t0 + (TOKEN_TTL_SECONDS - 1) * 1000);
      const stillValid = parseJson(await h.call("list_objects", args), ListObjectsResult);
      expect(stillValid.files.map((x) => x.path)).toEqual(["p/f2.txt", "p/f3.txt"]);

      vi.setSystemTime(t0 + TOKEN_TTL_SECONDS * 1000);
      const calls = f.mock.calls().length;
      expect(onlyText(await h.call("list_objects", args))).toBe(INVALID_TOKEN_MESSAGE);
      expect(f.mock.calls()).toHaveLength(calls);
    } finally {
      vi.useRealTimers();
    }
  });

  it("pagination works without MCP_S3_TOKEN_KEY (stdio default)", async () => {
    const f = pagedFake();
    const h = await connectTo(f, { MCP_S3_MAX_LIST_KEYS: "2", MCP_S3_TOKEN_KEY: "" });
    const token = await firstPage(h);
    const page2 = parseJson(await h.call("list_objects", { path: "p", recursive: true, continuation_token: token }), ListObjectsResult);
    expect(page2.files.map((x) => x.path)).toEqual(["p/f2.txt", "p/f3.txt"]);
  });
});

// ---------------------------------------------------------------------------

describe("search_objects: glob safety (MAJOR 1)", () => {
  it.each([
    "*(a*)*(a*)*(a*)b",
    "+(x)",
    "!*.txt",
    "[[:alpha:]]",
    "[a",
    "{a,b",
    "a\\",
    "[z-a]",
    "{{{{a}}}}",
    `{${Array.from({ length: 33 }, (_, i) => `x${String(i)}`).join(",")}}`,
    "a".repeat(200),
  ])("rejects %j with 'InvalidRequest: invalid glob pattern: ...' before any S3 call", async (pattern) => {
    const { fake: f, h } = await setup();
    const result = await h.call("search_objects", { pattern });
    const text = expectToolError(result, "InvalidRequest");
    expect(text.startsWith("InvalidRequest: invalid glob pattern: ")).toBe(true);
    expect(f.mock.calls()).toHaveLength(0);
  });

  it("a pattern longer than 256 characters is a schema validation error without S3 calls", async () => {
    const { fake: f, h } = await setup();
    expectValidationError(await h.call("search_objects", { pattern: "*".repeat(257) }));
    expect(f.mock.calls()).toHaveLength(0);
  });

  it("10,000 keys of 1000 characters against *?*?*?*?*?*?*?*?*?*.zip finish in under 1 s", async () => {
    const { fake: f, h } = await setup({}, false);
    const pad = (i: number) => `${String(i).padStart(5, "0")}-`;
    for (let i = 0; i < 9_999; i++) f.put(`${ROOT}e/${pad(i)}${"a".repeat(994)}`, "");
    const target = `zzzzz-${"a".repeat(990)}.zip`;
    f.put(`${ROOT}e/${target}`, "");
    expect(target).toHaveLength(1000);

    const started = performance.now();
    const result = await h.call("search_objects", { path: "e", pattern: "*?*?*?*?*?*?*?*?*?*.zip" });
    const elapsed = performance.now() - started;

    const body = parseJson(result, SearchObjectsResult);
    expect(body.matches).toEqual([`e/${target}`]);
    expect(body.truncated).toBe(false);
    expect(elapsed).toBeLessThan(1000);
  });

  it("CJK worst case: *[188 CJK]{32 alternatives} against 10,000 keys of 333 CJK characters in under 1 s", async () => {
    const CJK_BASE = 0x4e00;
    const CJK_COUNT = 20_992; // U+4E00..U+9FFF
    const cls = Array.from({ length: 188 }, (_, k) => String.fromCodePoint(CJK_BASE + k * 100)).join("");
    const letters = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i < 26 ? 0x61 + i : 0x41 + i - 26)); // a-z, A-F
    const pattern = `*[${cls}]{${letters.join(",")}}`;
    expect(letters).toHaveLength(32);
    expect(pattern).toHaveLength(256);

    const { fake: f, h } = await setup({}, false);
    // Keys cycle through all 20,992 ideographs, so per-character caches cannot help.
    for (let i = 0; i < 9_999; i++) {
      let name = "";
      for (let j = 0; j < 333; j++) name += String.fromCodePoint(CJK_BASE + ((i * 333 + j) % CJK_COUNT));
      f.put(`${ROOT}c/${name}`, "");
    }
    const target = `${"\u9fa5".repeat(331)}${String.fromCodePoint(CJK_BASE)}a`;
    f.put(`${ROOT}c/${target}`, "");
    expect(Buffer.byteLength(`${ROOT}c/${target}`, "utf8")).toBeLessThanOrEqual(1024);

    const started = performance.now();
    const result = await h.call("search_objects", { path: "c", pattern });
    const elapsed = performance.now() - started;

    const body = parseJson(result, SearchObjectsResult);
    expect(body.matches).toEqual([`c/${target}`]);
    expect(body.truncated).toBe(false);
    expect(elapsed).toBeLessThan(1000);
  }, 60_000); // generous timeout so a slow matcher fails on the assertion above, not on the timeout

  it("'**/' does not swallow part of a file name", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}docs/report.csv`, "x");
    f.put(`${ROOT}docs/2024/report.csv`, "x");
    f.put(`${ROOT}docs/old-report.csv`, "x");
    const body = parseJson(await h.call("search_objects", { pattern: "docs/**/report.csv" }), SearchObjectsResult);
    expect(body.matches.sort()).toEqual(["docs/2024/report.csv", "docs/report.csv"]);
  });

  it("supports braces, classes, and case-sensitive matching", async () => {
    const { fake: f, h } = await setup();
    f.put(`${ROOT}t/a.csv`, "x");
    f.put(`${ROOT}t/b.tsv`, "x");
    f.put(`${ROOT}t/C.CSV`, "x");
    const body = parseJson(await h.call("search_objects", { path: "t", pattern: "[!b]*.{csv,tsv}" }), SearchObjectsResult);
    expect(body.matches).toEqual(["t/a.csv"]);
  });
});
