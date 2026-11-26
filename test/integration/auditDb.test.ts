import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AUDIT_TABLE, PostgresAuditStore } from "../../src/auditDb.js";
import { Secret } from "../../src/secret.js";
import { PROJECT_DIR, uniqueName } from "../helpers/minio.js";

/** Needs the postgres service of docker-compose.yml. Every run uses its own database. */
const ADMIN_URL =
  process.env.POSTGRES_URL ??
  `postgresql://mcp_s3:mcp-s3-test-secret@127.0.0.1:${process.env.POSTGRES_PORT ?? "19432"}/mcp_s3`;

const database = uniqueName("audit").replaceAll("-", "_");
const url = Object.assign(new URL(ADMIN_URL), { pathname: `/${database}` }).href;
let admin: pg.Client;
let db: pg.Client;

beforeAll(async () => {
  admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${database}`);
  // The server never creates the table: apply the real migrations to the fresh database.
  await promisify(execFile)("npx", ["prisma", "migrate", "deploy"], {
    cwd: PROJECT_DIR,
    env: { ...process.env, MCP_S3_AUDIT_DATABASE_URL: url },
    timeout: 120_000,
  });
  db = new pg.Client({ connectionString: url });
  await db.connect();
}, 150_000);

afterAll(async () => {
  await db.end();
  await admin.query(`DROP DATABASE ${database} WITH (FORCE)`);
  await admin.end();
});

describe("audit table from migrations", () => {
  it("has a CHECK constraint on result and the time index", async () => {
    const checks = await db.query<{ def: string }>(
      `SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid = $1::regclass AND contype = 'c'`,
      [AUDIT_TABLE],
    );
    expect(checks.rows).toHaveLength(1);
    expect(checks.rows[0]?.def).toMatch(/result.*'ok'.*'error'/s);

    const indexes = await db.query<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes WHERE tablename = $1`,
      [AUDIT_TABLE],
    );
    expect(indexes.rows.map((r) => r.indexname)).toContain("mcp_s3_audit_log_time_idx");

    await expect(
      db.query(`INSERT INTO ${AUDIT_TABLE} (time, tool, result, duration_ms) VALUES (now(), 't', 'maybe', 0)`),
    ).rejects.toMatchObject({ code: "23514" });
  });
});

describe("audit log in PostgreSQL", () => {
  it("saves records from several stores at once", async () => {
    const stores = [1, 2, 3].map(() => PostgresAuditStore.connect(new Secret(url)));
    for (const store of stores) {
      await store.init();
      store.write({
        type: "audit",
        time: "2026-11-26T10:00:00.000Z",
        tool: "read_object",
        path: "x'); DROP TABLE mcp_s3_audit_log; --\u0000",
        result: "error",
        code: "PathOutsideRoot",
        duration_ms: 0,
      });
    }
    await Promise.all(stores.map((store) => store.close()));

    const { rows } = await db.query(
      `SELECT tool, path, code, bytes, duration_ms, time FROM ${AUDIT_TABLE} WHERE tool = 'read_object' AND code = 'PathOutsideRoot'`,
    );
    expect(rows).toHaveLength(3);
    expect(rows[0]).toEqual({
      tool: "read_object",
      path: "x'); DROP TABLE mcp_s3_audit_log; --\\u0000",
      code: "PathOutsideRoot",
      bytes: null,
      duration_ms: "0",
      time: new Date("2026-11-26T10:00:00.000Z"),
    });
  });

  it("saves bytes, source and destination", async () => {
    const store = PostgresAuditStore.connect(new Secret(url));
    store.write({
      type: "audit",
      time: "2026-11-26T11:00:00.000Z",
      tool: "copy_object",
      source: "a.txt",
      destination: "b.txt",
      result: "ok",
      bytes: 42,
      duration_ms: 7,
    });
    await store.close();
    const { rows } = await db.query(`SELECT path, source, destination, bytes, duration_ms FROM ${AUDIT_TABLE} WHERE tool = 'copy_object'`);
    expect(rows).toEqual([{ path: null, source: "a.txt", destination: "b.txt", bytes: "42", duration_ms: "7" }]);
  });

  it("never rejects when the database is unreachable", async () => {
    const bad = Object.assign(new URL(url), { port: "1" }).href;
    const store = PostgresAuditStore.connect(new Secret(bad));
    await expect(store.init()).resolves.toBeUndefined();
    store.write({ type: "audit", time: "2026-11-26T10:00:00.000Z", tool: "t", result: "ok", duration_ms: 1 });
    await expect(store.close()).resolves.toBeUndefined();
  });

  it("the built server saves a tool call and flushes it on shutdown", async () => {
    // Rejected by the path jail, so no S3 request is made.
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("../../dist/index.js", import.meta.url))],
      cwd: PROJECT_DIR,
      env: {
        S3_BUCKET: "unused",
        S3_ROOT_PREFIX: "root/",
        AWS_REGION: "us-east-1",
        MCP_S3_AUDIT_DATABASE_URL: url,
      },
      stderr: "ignore",
    });
    const client = new Client({ name: "mcp-s3-audit-test", version: "0.0.0" });
    await client.connect(transport);
    await client.callTool({ name: "read_object", arguments: { path: "../from-server" } });
    await client.close();

    const { rows } = await db.query(`SELECT result, code FROM ${AUDIT_TABLE} WHERE path = '../from-server'`);
    expect(rows).toEqual([{ result: "error", code: "PathOutsideRoot" }]);
  });
});
