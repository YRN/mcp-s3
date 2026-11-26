import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setAuditSink, setAuditStore, startAudit, type AuditRecord } from "../../src/audit.js";
import { PostgresAuditStore, type AuditDb, type AuditRow } from "../../src/auditDb.js";
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

class FakeDb implements AuditDb {
  readonly rows: AuditRow[] = [];
  pings = 0;
  failure: Error | undefined;
  hang = false;
  disconnected = 0;

  create(row: AuditRow): Promise<unknown> {
    this.rows.push(row);
    if (this.hang) return new Promise(() => undefined);
    if (this.failure !== undefined) return Promise.reject(this.failure);
    return Promise.resolve({ id: 1n });
  }

  ping(): Promise<unknown> {
    this.pings += 1;
    if (this.failure !== undefined) return Promise.reject(this.failure);
    return Promise.resolve([]);
  }

  $disconnect(): Promise<void> {
    this.disconnected += 1;
    return Promise.resolve();
  }
}

let db: FakeDb;
let logged: string[];

beforeEach(() => {
  db = new FakeDb();
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
  it("converts every record to a typed row (Date, BigInt, null)", async () => {
    const store = new PostgresAuditStore(db);
    store.write(record);
    store.write({ ...record, result: "error", code: "NotFound", bytes: undefined, duration_ms: 8.9 });
    await store.close();

    const base = { time: new Date(record.time), tool: "read_object", path: "a.txt", source: null, destination: null };
    expect(db.rows).toEqual([
      { ...base, result: "ok", code: null, bytes: 12n, durationMs: 8n },
      { ...base, result: "error", code: "NotFound", bytes: null, durationMs: 8n },
    ]);
    expect(db.rows[0]?.time).toBeInstanceOf(Date);
    expect(db.disconnected).toBe(1);
  });

  it("passes source and destination", async () => {
    const store = new PostgresAuditStore(db);
    store.write({ ...record, path: undefined, source: "a.txt", destination: "b.txt" });
    await store.close();
    expect(db.rows[0]).toMatchObject({ path: null, source: "a.txt", destination: "b.txt" });
  });

  it("stores NUL characters in paths as text", async () => {
    const store = new PostgresAuditStore(db);
    store.write({ ...record, path: "a\u0000b", source: "s\u0000", destination: "\u0000d" });
    await store.close();
    expect(db.rows[0]).toMatchObject({ path: "a\\u0000b", source: "s\\u0000", destination: "\\u0000d" });
  });

  it("init only pings and never creates anything", async () => {
    const store = new PostgresAuditStore(db);
    await store.init();
    expect(db.pings).toBe(1);
    expect(db.rows).toHaveLength(0);
    expect(logged).toHaveLength(0);
  });

  it("init warns without rejecting or logging driver messages when ping fails", async () => {
    db.failure = Object.assign(new Error("password authentication failed for user db-user-name"), { code: "28P01" });
    const store = new PostgresAuditStore(db);
    await expect(store.init()).resolves.toBeUndefined();
    expect(logged).toHaveLength(1);
    expect(logged[0]).toContain("not ready");
    expect(logged.join("\n")).not.toContain("db-user-name");
  });

  it("never throws or logs driver messages when the database fails, and recovers", async () => {
    const store = new PostgresAuditStore(db);
    db.failure = Object.assign(new Error("password authentication failed for user db-user-name"), { code: "28P01" });
    await store.init();
    expect(() => {
      store.write(record);
      store.write(record);
    }).not.toThrow();
    await new Promise((resolve) => setImmediate(resolve));

    db.failure = undefined;
    store.write(record);
    await store.close();

    expect(db.rows).toHaveLength(3);
    expect(logged.join("\n")).not.toContain("db-user-name");
    // One warning from init(), then one (rate limited) for the two unsaved records.
    expect(logged.filter((line) => line.includes("not saved"))).toHaveLength(1);
    expect(logged).toHaveLength(2);
  });

  it("write returns immediately while the database hangs", () => {
    db.hang = true;
    const store = new PostgresAuditStore(db);
    store.write(record);
    expect(db.rows).toHaveLength(1);
  });

  it("bounds the number of pending records", async () => {
    db.hang = true;
    const store = new PostgresAuditStore(db);
    for (let i = 0; i < 1_001; i += 1) store.write(record);
    expect(db.rows).toHaveLength(1_000);
    expect(logged.filter((line) => line.includes("not saved"))).toHaveLength(1);
    await store.close(10);
  });

  it("gives up after the close timeout when the database hangs", async () => {
    db.hang = true;
    const store = new PostgresAuditStore(db);
    store.write(record);
    await store.close(10);
    expect(logged.join("\n")).toContain("did not finish in time");
  });

  it("does not reject close when disconnect fails, and hides the message", async () => {
    db.$disconnect = () => Promise.reject(new Error("host db.internal refused"));
    const store = new PostgresAuditStore(db);
    await expect(store.close()).resolves.toBeUndefined();
    expect(logged.join("\n")).not.toContain("db.internal");
  });

  it("disconnects only once and ignores later records", async () => {
    const store = new PostgresAuditStore(db);
    await Promise.all([store.close(), store.close()]);
    store.write(record);
    expect(db.disconnected).toBe(1);
    expect(db.rows).toHaveLength(0);
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
