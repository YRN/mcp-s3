import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { auditPaths, setAuditSink, startAudit } from "../../src/audit.js";
import { loadConfig } from "../../src/config.js";
import { Storage } from "../../src/storage.js";
import { FakeS3 } from "../helpers/fakeS3.js";
import { PNG_1X1, SECRET_CONTENT } from "../helpers/fixtures.js";
import { connectInMemory, type InMemoryHarness } from "../helpers/mcp.js";

const BUCKET = "acme-secret-bucket-7f3a";
const ROOT = "claude-workspace/";
const READ_TOOLS = ["get_object_info", "list_objects", "read_object", "search_objects"];

let fake: FakeS3;
let h: InMemoryHarness;
let lines: string[];

beforeEach(async () => {
  lines = [];
  setAuditSink((line) => lines.push(line));
  fake = new FakeS3(BUCKET);
  fake.put(`${ROOT}a.txt`, "hello from a\n", { contentType: "text/plain" });
  fake.put(`${ROOT}sub/b.txt`, "bee\n", { contentType: "text/plain" });
  fake.put(`${ROOT}img.png`, PNG_1X1, { contentType: "image/png" });
  fake.put("outside/secret.txt", SECRET_CONTENT, { contentType: "text/plain" });
  const config = loadConfig({ S3_BUCKET: BUCKET, S3_ROOT_PREFIX: ROOT, AWS_REGION: "us-east-1" });
  h = await connectInMemory(config, new Storage(fake.client, config.bucket));
});

afterEach(async () => {
  await h.close();
  fake.restore();
  setAuditSink(undefined);
});

function parsed(): Record<string, unknown>[] {
  return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
}

function keysOf(record: Record<string, unknown>): string[] {
  return Object.keys(record).sort();
}

describe("audit log: one JSON line per tool call", () => {
  it("writes exactly one line per call, for success and for every kind of failure", async () => {
    await h.call("list_objects", {});
    await h.call("get_object_info", { path: "a.txt" });
    await h.call("read_object", { path: "a.txt" });
    await h.call("search_objects", { pattern: "*.txt" });
    expect(lines).toHaveLength(4);

    await h.call("read_object", { path: "missing.txt" }); // S3 NotFound
    await h.call("read_object", { path: "../outside/secret.txt" }); // path jail
    expect(lines).toHaveLength(6);
    for (const line of lines) {
      expect(line).not.toContain("\n");
      expect(() => {
        JSON.parse(line);
      }).not.toThrow();
    }
  });

  it("does not write a line when the SDK rejects the input before the handler runs", async () => {
    const result = await h.call("read_object", { path: 42 });
    expect(result.isError).toBe(true);
    expect(lines).toHaveLength(0);
  });

  it("has the documented fields for a successful call", async () => {
    await h.call("get_object_info", { path: "a.txt" });
    const [record] = parsed();
    expect(record).toBeDefined();
    if (record === undefined) return;
    expect(keysOf(record)).toEqual(["duration_ms", "path", "result", "time", "tool", "type"]);
    expect(record.type).toBe("audit");
    expect(record.tool).toBe("get_object_info");
    expect(record.path).toBe("a.txt");
    expect(record.result).toBe("ok");
    expect(typeof record.duration_ms).toBe("number");
    expect(record.duration_ms as number).toBeGreaterThanOrEqual(0);
    expect(new Date(record.time as string).toISOString()).toBe(record.time);
  });

  it("adds `bytes` for read_object only", async () => {
    await h.call("list_objects", {});
    await h.call("get_object_info", { path: "a.txt" });
    await h.call("search_objects", { pattern: "*.txt" });
    await h.call("read_object", { path: "a.txt" });
    const records = parsed();
    expect(records).toHaveLength(4);
    for (const record of records) {
      if (record.tool === "read_object") {
        expect(record.bytes).toBe(Buffer.byteLength("hello from a\n"));
        expect(keysOf(record)).toEqual(["bytes", "duration_ms", "path", "result", "time", "tool", "type"]);
      } else {
        expect(record).not.toHaveProperty("bytes");
      }
    }
  });

  it("records bytes of an image read", async () => {
    await h.call("read_object", { path: "img.png" });
    const [record] = parsed();
    expect(record?.bytes).toBe(PNG_1X1.length);
  });

  it("records result=error with a generic code and no bytes for failed calls", async () => {
    await h.call("read_object", { path: "missing.txt" });
    await h.call("read_object", { path: "../outside/secret.txt" });
    const [notFound, jail] = parsed();
    expect(notFound).toMatchObject({ tool: "read_object", path: "missing.txt", result: "error", code: "NotFound" });
    expect(jail).toMatchObject({ tool: "read_object", path: "../outside/secret.txt", result: "error", code: "PathOutsideRoot" });
    expect(notFound).not.toHaveProperty("bytes");
    expect(jail).not.toHaveProperty("bytes");
    for (const record of [notFound, jail]) {
      expect(keysOf(record ?? {})).toEqual(["code", "duration_ms", "path", "result", "time", "tool", "type"]);
    }
  });

  it("never contains the bucket name, the root prefix, an absolute key, or file content", async () => {
    await h.call("list_objects", { path: "sub", recursive: true });
    await h.call("read_object", { path: "a.txt" });
    await h.call("read_object", { path: "img.png" });
    await h.call("read_object", { path: "../outside/secret.txt" });
    await h.call("get_object_info", { path: "nope.txt" });
    await h.call("search_objects", { pattern: "*.txt" });
    expect(lines.length).toBe(6);
    const all = lines.join("\n");
    expect(all).not.toContain(BUCKET);
    expect(all).not.toContain("claude-workspace");
    expect(all).not.toContain("hello from a");
    expect(all).not.toContain(SECRET_CONTENT);
  });

  it("audit sink failures never break the tool call", async () => {
    setAuditSink(() => {
      throw new Error("disk full");
    });
    const result = await h.call("get_object_info", { path: "a.txt" });
    expect(result.isError).not.toBe(true);
  });

  it("without a sink override, lines go to stderr via console.error", async () => {
    setAuditSink(undefined);
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    await h.call("get_object_info", { path: "a.txt" });
    expect(spy).toHaveBeenCalledTimes(1);
    const record = JSON.parse(String(spy.mock.calls[0]?.[0])) as Record<string, unknown>;
    expect(record.tool).toBe("get_object_info");
  });
});

describe("startAudit / auditPaths", () => {
  it("emits at most one line even if ok() and error() are both called", () => {
    const call = startAudit("x", { path: "p" });
    call.ok();
    call.error("NotFound");
    call.ok();
    expect(lines).toHaveLength(1);
  });

  it("uses the injected clock for time and duration", () => {
    let now = Date.UTC(2026, 0, 2, 3, 4, 5);
    const call = startAudit("x", { path: "p" }, () => now);
    now += 250;
    call.ok();
    expect(parsed()[0]).toMatchObject({ time: "2026-01-02T03:04:05.000Z", duration_ms: 250 });
  });

  it("copies only string path/source/destination arguments", () => {
    expect(auditPaths({ path: "a", source: "b", destination: "c", content: "secret", other: "x" })).toEqual({
      path: "a",
      source: "b",
      destination: "c",
    });
    expect(auditPaths({ path: 5 })).toEqual({});
    expect(auditPaths(null)).toEqual({});
    expect(auditPaths("string")).toEqual({});
  });

  it("truncates very long paths", () => {
    expect(auditPaths({ path: "x".repeat(5000) }).path).toHaveLength(1024);
  });
});

describe("tool annotations", () => {
  it("every read tool has exactly readOnlyHint, idempotentHint true and destructiveHint, openWorldHint false", async () => {
    const { tools } = await h.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(READ_TOOLS);
    for (const tool of tools) {
      expect(tool.annotations, tool.name).toMatchObject({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
      expect(Object.keys(tool.annotations ?? {}).sort(), tool.name).toEqual([
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
        "readOnlyHint",
      ]);
    }
  });
});
