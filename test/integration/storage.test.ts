import type { S3Client } from "@aws-sdk/client-s3";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { loadConfig, type Config } from "../../src/config.js";
import { toSafeError } from "../../src/errors.js";
import { resolveKey } from "../../src/paths.js";
import { Storage } from "../../src/storage.js";
import { LEAK_CONTENT, PNG_1X1, ROOT_PREFIX, SECRET_CONTENT } from "../helpers/fixtures.js";
import {
  connectInMemory,
  expectOk,
  expectToolError,
  ListObjectsResult,
  nextOffset,
  ObjectInfoResult,
  onlyText,
  parseJson,
  SearchObjectsResult,
  texts,
  type InMemoryHarness,
} from "../helpers/mcp.js";
import {
  assertMinioReady,
  createSeededBucket,
  destroyBucket,
  MINIO_ENDPOINT,
  MINIO_REGION,
  minioClient,
  putObject,
  uniqueName,
} from "../helpers/minio.js";

const ROOT = ROOT_PREFIX;
const key = (path: string, dir = false) => resolveKey(ROOT, path, { dir });

let admin: S3Client;
let bucket = "";
let bucketCreated = false;
let storage: Storage;

const LONG_TEXT = "0123456789abcdefghijklmnopqrstuvwxyzABCD"; // 40 bytes
const UTF8_TEXT = "aé€😀b".repeat(9) + "ü";

beforeAll(async () => {
  await assertMinioReady();
  admin = minioClient();
  bucket = await createSeededBucket(admin, "mcp-s3-int");
  bucketCreated = true;
  await putObject(admin, bucket, `${ROOT}long.txt`, { body: LONG_TEXT, contentType: "text/plain" });
  await putObject(admin, bucket, `${ROOT}utf8.txt`, { body: UTF8_TEXT, contentType: "text/plain; charset=utf-8" });
  await putObject(admin, bucket, `${ROOT}empty.txt`, { body: "", contentType: "text/plain" });
  for (let i = 0; i < 5; i++) {
    await putObject(admin, bucket, `${ROOT}pages/f${String(i)}.txt`, { body: `page ${String(i)}`, contentType: "text/plain" });
  }
  storage = new Storage(minioClient(), bucket);
});

afterAll(async () => {
  // Only clean up what beforeAll actually created.
  if (bucketCreated) await destroyBucket(admin, bucket);
});

function expectNoLeak(value: unknown): void {
  const serialised = JSON.stringify(value);
  expect(serialised).not.toContain(bucket);
  expect(serialised).not.toContain("claude-workspace");
  expect(serialised).not.toContain(SECRET_CONTENT);
  expect(serialised).not.toContain(LEAK_CONTENT);
}

async function safeErrorOf(promise: Promise<unknown>): Promise<ReturnType<typeof toSafeError>> {
  try {
    await promise;
  } catch (err) {
    return toSafeError(err);
  }
  throw new Error("expected the storage call to fail");
}

// ---------------------------------------------------------------------------

describe("Storage against MinIO", () => {
  it("lists one folder level with Delimiter '/'", async () => {
    const page = await storage.list(key("", true), { delimiter: "/", maxKeys: 100 });
    expect(page.objects.map((o) => o.key).sort()).toEqual(
      [`${ROOT}a.txt`, `${ROOT}empty.txt`, `${ROOT}img.png`, `${ROOT}long.txt`, `${ROOT}utf8.txt`].sort(),
    );
    expect(page.prefixes.sort()).toEqual([`${ROOT}pages/`, `${ROOT}sub/`]);
    expect(page.nextContinuationToken).toBeUndefined();
  });

  it("recursive list returns only keys under claude-workspace/ (no prefix collision)", async () => {
    const page = await storage.list(key("", true), { maxKeys: 1000 });
    const keys = page.objects.map((o) => o.key);
    expect(keys.length).toBe(11);
    for (const k of keys) expect(k.startsWith(ROOT)).toBe(true);
    expect(keys).not.toContain("claude-workspace-backup/leak.txt");
    expect(keys).not.toContain("outside/secret.txt");
  });

  it("paginates with real continuation tokens", async () => {
    const first = await storage.list(key("pages", true), { maxKeys: 2 });
    expect(first.objects).toHaveLength(2);
    expect(first.nextContinuationToken).toBeDefined();
    const second = await storage.list(key("pages", true), { maxKeys: 2, continuationToken: first.nextContinuationToken });
    expect(second.objects).toHaveLength(2);
    expect(second.objects[0]?.key).not.toBe(first.objects[0]?.key);
  });

  it("head returns size, content type, and metadata", async () => {
    const info = await storage.head(key("a.txt"));
    expect(info.size).toBe(13);
    expect(info.contentType).toBe("text/plain");
    expect(info.metadata).toEqual({ owner: "team-a" });
    expect(info.etag).toMatch(/^".+"$/);
    expect(info.lastModified).toBeInstanceOf(Date);
  });

  it("get reads an exact byte range (HTTP Range)", async () => {
    const data = await storage.get(key("long.txt"), { offset: 10, length: 5 });
    expect(Buffer.from(data.bytes).toString("utf8")).toBe("abcde");
    expect(data.totalSize).toBe(40);
  });

  it("get clamps a range that runs past the end", async () => {
    const data = await storage.get(key("long.txt"), { offset: 36, length: 100 });
    expect(Buffer.from(data.bytes).toString("utf8")).toBe("ABCD");
    expect(data.totalSize).toBe(40);
  });

  it("get with offset past the end maps to InvalidRange", async () => {
    expect((await safeErrorOf(storage.get(key("long.txt"), { offset: 40, length: 1 }))).code).toBe("InvalidRange");
  });

  it("get with If-Match: the current ETag reads, a stale ETag is a Conflict (412)", async () => {
    const info = await storage.head(key("long.txt"));
    const ok = await storage.get(key("long.txt"), { offset: 0, length: 4 }, { ifMatch: info.etag });
    expect(Buffer.from(ok.bytes).toString("utf8")).toBe("0123");
    const stale = await safeErrorOf(storage.get(key("long.txt"), { offset: 0, length: 4 }, { ifMatch: '"0123456789abcdef0123456789abcdef"' }));
    expect(stale.code).toBe("Conflict");
  });

  it("missing keys map to NotFound for head and get", async () => {
    expect((await safeErrorOf(storage.head(key("missing.txt")))).code).toBe("NotFound");
    expect((await safeErrorOf(storage.get(key("missing.txt"), { offset: 0, length: 1 })))).toMatchObject({
      code: "NotFound",
      message: "object not found",
    });
  });

  it("a missing bucket maps to StorageUnavailable", async () => {
    const missing = new Storage(minioClient(), uniqueName("mcp-s3-missing"));
    expect((await safeErrorOf(missing.list(key("", true), { maxKeys: 1 }))).code).toBe("StorageUnavailable");
    expect((await safeErrorOf(missing.head(key("a.txt")))).code).not.toBe("InternalError");
  });

  it("wrong credentials map to AccessDenied", async () => {
    const bad = new Storage(minioClient({ accessKeyId: "nobody", secretAccessKey: "wrong-secret-123" }), bucket);
    expect((await safeErrorOf(bad.list(key("", true), { maxKeys: 1 }))).code).toBe("AccessDenied");
    expect((await safeErrorOf(bad.get(key("a.txt"), { offset: 0, length: 1 }))).code).toBe("AccessDenied");
  });
});

// ---------------------------------------------------------------------------

describe("read tools against MinIO", () => {
  let harness: InMemoryHarness | undefined;

  function config(overrides: Record<string, string> = {}): Config {
    return loadConfig({
      S3_BUCKET: bucket,
      S3_ROOT_PREFIX: ROOT,
      AWS_REGION: MINIO_REGION,
      S3_ENDPOINT_URL: MINIO_ENDPOINT,
      S3_FORCE_PATH_STYLE: "true",
      ...overrides,
    });
  }

  async function connect(overrides: Record<string, string> = {}): Promise<InMemoryHarness> {
    harness = await connectInMemory(config(overrides), storage);
    return harness;
  }

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it("list_objects recursive returns only a.txt-style paths under the root (prefix collision)", async () => {
    const h = await connect();
    const result = await h.call("list_objects", { recursive: true });
    const body = parseJson(result, ListObjectsResult);
    expect(body.files.map((f) => f.path).sort()).toEqual([
      "a.txt",
      "empty.txt",
      "img.png",
      "long.txt",
      "pages/f0.txt",
      "pages/f1.txt",
      "pages/f2.txt",
      "pages/f3.txt",
      "pages/f4.txt",
      "sub/b.txt",
      "utf8.txt",
    ]);
    expectNoLeak(result);
  });

  it("list_objects non-recursive returns folders and direct files", async () => {
    const h = await connect();
    const body = parseJson(await h.call("list_objects", {}), ListObjectsResult);
    expect(body.folders.sort()).toEqual(["pages/", "sub/"]);
    expect(body.files.map((f) => f.path)).toContain("a.txt");
    expect(body.files.map((f) => f.path)).not.toContain("sub/b.txt");
  });

  it("list_objects pages through MinIO with opaque tokens", async () => {
    const h = await connect({ MCP_S3_MAX_LIST_KEYS: "2" });
    const seen: string[] = [];
    let token: string | null = null;
    for (let i = 0; i < 10; i++) {
      const args: Record<string, unknown> = { path: "pages", recursive: true };
      if (token !== null) args.continuation_token = token;
      const result = await h.call("list_objects", args);
      expectNoLeak(result);
      const body = parseJson(result, ListObjectsResult);
      seen.push(...body.files.map((f) => f.path));
      token = body.next_token;
      if (token !== null) expect(Buffer.from(token, "base64").toString("latin1")).not.toContain("claude-workspace");
      if (token === null) break;
    }
    expect(seen).toEqual(["pages/f0.txt", "pages/f1.txt", "pages/f2.txt", "pages/f3.txt", "pages/f4.txt"]);
  });

  it("search_objects never returns keys outside the root", async () => {
    const h = await connect();
    const result = await h.call("search_objects", { pattern: "*.txt" });
    const body = parseJson(result, SearchObjectsResult);
    expect(body.matches).toContain("a.txt");
    expect(body.matches).toContain("sub/b.txt");
    expect(body.matches.some((m) => /leak|secret/.test(m))).toBe(false);
    expectNoLeak(result);
  });

  it("get_object_info returns relative metadata", async () => {
    const h = await connect();
    const result = await h.call("get_object_info", { path: "a.txt" });
    const body = parseJson(result, ObjectInfoResult);
    expect(body).toMatchObject({ path: "a.txt", size: 13, content_type: "text/plain", metadata: { owner: "team-a" } });
    expectNoLeak(result);
  });

  it("read_object reads text, empty files, and missing files", async () => {
    const h = await connect();
    expect(onlyText(await h.call("read_object", { path: "a.txt" }))).toBe("hello from a\n");
    expect(onlyText(await h.call("read_object", { path: "empty.txt" }))).toBe("[empty file: 0 bytes]");
    expectToolError(await h.call("read_object", { path: "missing.txt" }), "NotFound");
  });

  it("read_object uses Range reads to page through a file", async () => {
    const h = await connect({ MCP_S3_MAX_READ_BYTES: "16" });
    const parts: string[] = [];
    let offset: number | undefined = 0;
    for (let i = 0; i < 10 && offset !== undefined; i++) {
      const result = await h.call("read_object", { path: "long.txt", offset });
      expectOk(result);
      parts.push(texts(result)[0] ?? "");
      offset = nextOffset(result);
    }
    expect(parts).toEqual([LONG_TEXT.slice(0, 16), LONG_TEXT.slice(16, 32), LONG_TEXT.slice(32)]);

    const middle = await h.call("read_object", { path: "long.txt", offset: 10, length: 5 });
    expect(texts(middle)[0]).toBe("abcde");
    expectToolError(await h.call("read_object", { path: "long.txt", offset: 40 }), "InvalidRange");
  });

  it("read_object cuts UTF-8 text only at character boundaries", async () => {
    const h = await connect({ MCP_S3_MAX_READ_BYTES: "7" });
    const parts: string[] = [];
    let offset: number | undefined = 0;
    for (let i = 0; i < 100 && offset !== undefined; i++) {
      const result = await h.call("read_object", { path: "utf8.txt", offset });
      expectOk(result);
      const chunk = texts(result)[0] ?? "";
      expect(chunk).not.toContain("�");
      parts.push(chunk);
      offset = nextOffset(result);
    }
    expect(parts.join("")).toBe(UTF8_TEXT);
  });

  it("read_object returns img.png (stored as octet-stream) as image/png", async () => {
    const h = await connect();
    const result = await h.call("read_object", { path: "img.png" });
    expect(result.content).toEqual([{ type: "image", data: Buffer.from(PNG_1X1).toString("base64"), mimeType: "image/png" }]);
  });

  it.each(["../outside/secret.txt", "../claude-workspace-backup/leak.txt", "a/../../outside/secret.txt", "..\\outside\\secret.txt"])(
    "read_object %j is rejected and leaks nothing",
    async (path) => {
      const h = await connect();
      const result = await h.call("read_object", { path });
      expectToolError(result, "PathOutsideRoot");
      expectNoLeak(result);
    },
  );

  it("list_objects and search_objects with path '../' are rejected", async () => {
    const h = await connect();
    for (const [tool, args] of [
      ["list_objects", { path: "../" }],
      ["list_objects", { path: "../", recursive: true }],
      ["search_objects", { path: "../", pattern: "*" }],
    ] as const) {
      const result = await h.call(tool, args);
      expectToolError(result, "PathOutsideRoot");
      expectNoLeak(result);
    }
  });

  it("a nonexistent bucket is StorageUnavailable without the bucket name", async () => {
    const missingBucket = uniqueName("mcp-s3-missing");
    harness = await connectInMemory(config({ S3_BUCKET: missingBucket }), new Storage(minioClient(), missingBucket));
    for (const [tool, args] of [
      ["list_objects", {}],
      ["get_object_info", { path: "a.txt" }],
    ] as const) {
      const result = await harness.call(tool, args);
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result)).not.toContain(missingBucket);
    }
  });
});
