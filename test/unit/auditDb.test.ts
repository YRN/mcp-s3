import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setAuditSink, setAuditStore, startAudit, type AuditRecord } from "../../src/audit.js";
import { PostgresAuditStore, type AuditPool } from "../../src/auditDb.js";
import { ConfigError, loadConfig } from "../../src/config.js";

const record: AuditRecord = {
  type: "audit",
  time: "2026-11-26T10:00:00.000Z",
  tool: "read_object",
  path: "a.txt",
  result: "ok",
  bytes: 12,
  duration_ms: 8,
};

class FakePool implements AuditPool {
  readonly queries: { sql: string; values: unknown[] | undefined }[] = [];
  tableExists = false;
  failure: Error | undefined;
  hang = false;
  ended = 0;

  async query(sql: string, values?: unknown[]): Promise<{ rows: unknown[] }> {
    this.queries.push({ sql, values });
    if (this.hang) return new Promise(() => undefined);
    if (this.failure !== undefined) throw this.failure;
    return { rows: sql.includes("to_regclass") ? [{ present: this.tableExists }] : [] };
  }

  end(): Promise<void> {
    this.ended += 1;
    return Promise.resolve();
  }

  matching(text: string) {
    return this.queries.filter((q) => q.sql.includes(text));
  }
}

let pool: FakePool;
let logged: string[];

beforeEach(() => {
  pool = new FakePool();
  logged = [];
  vi.spyOn(console, "error").mockImplementation((line: unknown) => {
    logged.push(String(line));
  });
});

afterEach(() => {
  setAuditStore(undefined);
  setAuditSink(undefined);
});

describe("PostgresAuditStore", () => {
  it("creates the table once and inserts every record with parameters", async () => {
    const store = new PostgresAuditStore(pool);
    store.write(record);
    store.write({ ...record, result: "error", code: "NotFound", bytes: undefined });
    await store.close();

    expect(pool.matching("CREATE TABLE")).toHaveLength(1);
    expect(pool.matching("INSERT INTO").map((q) => q.values)).toEqual([
      [record.time, "read_object", "a.txt", null, null, "ok", null, 12, 8],
      [record.time, "read_object", "a.txt", null, null, "error", "NotFound", null, 8],
    ]);
    expect(pool.ended).toBe(1);
  });

  it("does not run DDL when the table exists", async () => {
    pool.tableExists = true;
    const store = new PostgresAuditStore(pool);
    store.write(record);
    await store.close();
    expect(pool.matching("CREATE")).toHaveLength(0);
    expect(pool.matching("INSERT INTO")).toHaveLength(1);
  });

  it("stores NUL characters in paths as text", async () => {
    const store = new PostgresAuditStore(pool);
    store.write({ ...record, path: "a\u0000b" });
    await store.close();
    expect(pool.matching("INSERT INTO")[0]?.values?.[2]).toBe("a\\u0000b");
  });

  it("never throws or logs driver messages when the database fails, and recovers", async () => {
    const store = new PostgresAuditStore(pool);
    pool.failure = Object.assign(new Error("password authentication failed for user db-user-name"), { code: "28P01" });
    await store.init();
    store.write(record);
    store.write(record);
    await new Promise((resolve) => setImmediate(resolve));

    pool.failure = undefined;
    store.write(record);
    await store.close();

    expect(pool.matching("INSERT INTO")).toHaveLength(1);
    expect(logged.join("\n")).not.toContain("db-user-name");
    // One warning from init(), then one (rate limited) for the two unsaved records.
    expect(logged.filter((line) => line.includes("not saved"))).toHaveLength(1);
    expect(logged).toHaveLength(2);
  });

  it("bounds the number of pending records", async () => {
    pool.hang = true;
    const store = new PostgresAuditStore(pool);
    for (let i = 0; i < 1_001; i += 1) store.write(record);
    expect(logged.filter((line) => line.includes("not saved"))).toHaveLength(1);
    await store.close(10);
  });

  it("gives up after the close timeout when the database hangs", async () => {
    pool.hang = true;
    const store = new PostgresAuditStore(pool);
    store.write(record);
    await store.close(10);
    expect(logged.join("\n")).toContain("did not finish in time");
  });

  it("ends the pool only once and ignores later records", async () => {
    const store = new PostgresAuditStore(pool);
    await Promise.all([store.close(), store.close()]);
    store.write(record);
    expect(pool.ended).toBe(1);
    expect(pool.queries).toHaveLength(0);
  });
});

describe("audit destinations", () => {
  it("writes each call to stderr and to the store", () => {
    const lines: string[] = [];
    const saved: AuditRecord[] = [];
    setAuditSink((line) => lines.push(line));
    setAuditStore({ write: (r) => saved.push(r) });
    startAudit("read_object", { path: "a.txt" }).ok();
    expect(saved).toHaveLength(1);
    expect(lines.map((line) => JSON.parse(line) as unknown)).toEqual(saved);
  });

  it("one failing destination does not affect the other or the caller", () => {
    const saved: AuditRecord[] = [];
    setAuditSink(() => {
      throw new Error("stderr closed");
    });
    setAuditStore({ write: (r) => saved.push(r) });
    startAudit("read_object", {}).ok();
    expect(saved).toHaveLength(1);

    setAuditStore({
      write: () => {
        throw new Error("boom");
      },
    });
    expect(() => {
      startAudit("read_object", {}).ok();
    }).not.toThrow();
  });
});

describe("MCP_S3_AUDIT_DATABASE_URL", () => {
  const base = { S3_BUCKET: "b", S3_ROOT_PREFIX: "root/", AWS_REGION: "us-east-1" };

  it("is optional", () => {
    expect(loadConfig(base).auditDatabaseUrl).toBeUndefined();
    expect(loadConfig({ ...base, MCP_S3_AUDIT_DATABASE_URL: "" }).auditDatabaseUrl).toBeUndefined();
  });

  it.each(["postgres://u:pw-123@db:5432/audit", "postgresql://u:pw-123@db/audit?sslmode=verify-full"])(
    "accepts %s and never serializes it",
    (url) => {
      const config = loadConfig({ ...base, MCP_S3_AUDIT_DATABASE_URL: url });
      expect(config.auditDatabaseUrl?.reveal()).toBe(url);
      expect(JSON.stringify(config)).not.toContain("pw-123");
    },
  );

  it.each(["mysql://u:pw-123@db/audit", "db:pw-123"])("rejects %s without echoing it", (url) => {
    let error: unknown;
    try {
      loadConfig({ ...base, MCP_S3_AUDIT_DATABASE_URL: url });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as Error).message).toContain("MCP_S3_AUDIT_DATABASE_URL");
    expect((error as Error).message).not.toContain("pw-123");
  });
});
