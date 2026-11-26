import { fileURLToPath } from "node:url";

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
  db = new pg.Client({ connectionString: url });
  await db.connect();
});

afterAll(async () => {
  await db.end();
  await admin.query(`DROP DATABASE ${database} WITH (FORCE)`);
  await admin.end();
});

describe("audit log in PostgreSQL", () => {
  it("creates the table when several stores start at once, and saves records", async () => {
    const stores = [1, 2, 3].map(() => PostgresAuditStore.connect(new Secret(url)));
    for (const store of stores) {
      store.write({
        type: "audit",
        time: "2026-11-26T10:00:00.000Z",
        tool: "read_object",
        path: "x'); DROP TABLE mcp_s3_audit; --\u0000",
        result: "error",
        code: "PathOutsideRoot",
        duration_ms: 0,
      });
    }
    await Promise.all(stores.map((store) => store.close()));

    const { rows } = await db.query(`SELECT tool, path, code, bytes, time FROM ${AUDIT_TABLE}`);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toEqual({
      tool: "read_object",
      path: "x'); DROP TABLE mcp_s3_audit; --\\u0000",
      code: "PathOutsideRoot",
      bytes: null,
      time: new Date("2026-11-26T10:00:00.000Z"),
    });
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
