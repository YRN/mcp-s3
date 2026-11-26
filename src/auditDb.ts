import { PrismaPg } from "@prisma/adapter-pg";

import type { AuditRecord, AuditStore } from "./audit.js";
import { errorLogFields } from "./errors.js";
import { PrismaClient } from "./generated/prisma/client.js";
import { log } from "./logger.js";
import type { Secret } from "./secret.js";

/**
 * PostgreSQL store for audit records. Saving is best effort and never delays or fails a tool
 * call: a record that cannot be saved is not retried, because audit.ts has already written the
 * same line to stderr. Error messages from the driver are never logged (errorLogFields), so the
 * connection URL, user, and host stay out of the logs.
 *
 * The table is created by Prisma migrations (prisma/migrations, `prisma migrate deploy`), never by
 * the server. The database user only needs INSERT (and SELECT 1 for the startup check).
 */

export const AUDIT_TABLE = "mcp_s3_audit_log";

/** Records waiting for the database beyond this number are not saved (bounds memory use). */
const MAX_PENDING = 1_000;
const MAX_CONNECTIONS = 4;
const TIMEOUT_MS = 5_000;
const CLOSE_TIMEOUT_MS = 3_000;
/** At most one "could not save" warning per this period. */
const WARN_INTERVAL_MS = 60_000;

/** One row of the audit table, in the shape Prisma expects (see prisma/schema.prisma). */
export interface AuditRow {
  time: Date;
  tool: string;
  path: string | null;
  source: string | null;
  destination: string | null;
  result: "ok" | "error";
  code: string | null;
  bytes: bigint | null;
  durationMs: bigint;
}

/** The part of PrismaClient the store uses (small enough to mock). */
export interface AuditDb {
  create(row: AuditRow): Promise<unknown>;
  /** Connectivity check (SELECT 1). */
  ping(): Promise<unknown>;
  $disconnect(): Promise<void>;
}

/** PostgreSQL text cannot hold NUL, but rejected client paths are audited as sent. */
function text(value: string | undefined): string | null {
  return value === undefined ? null : value.replaceAll("\u0000", "\\u0000");
}

export class PostgresAuditStore implements AuditStore {
  readonly #db: AuditDb;
  readonly #pending = new Set<Promise<void>>();
  #unsaved = 0;
  #lastWarning = Number.NEGATIVE_INFINITY;
  #closing: Promise<void> | undefined;

  constructor(db: AuditDb) {
    this.#db = db;
  }

  static connect(url: Secret): PostgresAuditStore {
    const adapter = new PrismaPg(
      {
        connectionString: url.reveal(),
        max: MAX_CONNECTIONS,
        connectionTimeoutMillis: TIMEOUT_MS,
        query_timeout: TIMEOUT_MS,
        statement_timeout: TIMEOUT_MS,
      },
      {
        // Without a listener, an error on an idle connection (database restart) ends the process.
        onPoolError: (err) => {
          log.warn("audit database connection lost", errorLogFields(err));
        },
      },
    );
    const prisma = new PrismaClient({ adapter, errorFormat: "minimal" });
    return new PostgresAuditStore({
      create: (data) => prisma.auditLog.create({ data, select: { id: true } }),
      ping: () => prisma.$queryRaw`SELECT 1`,
      $disconnect: () => prisma.$disconnect(),
    });
  }

  /** Check the connection early so that a wrong URL shows up at startup. Never rejects. */
  async init(): Promise<void> {
    try {
      await this.#db.ping();
    } catch (err) {
      log.warn("audit database is not ready; audit lines still go to stderr", errorLogFields(err));
    }
  }

  write(record: AuditRecord): void {
    if (this.#closing !== undefined || this.#pending.size >= MAX_PENDING) {
      this.#notSaved();
      return;
    }
    const saving: Promise<void> = this.#insert(record)
      .catch((err: unknown) => {
        this.#notSaved(err);
      })
      .finally(() => this.#pending.delete(saving));
    this.#pending.add(saving);
  }

  /** Wait (bounded) for pending records, then close the connections. Never rejects. */
  close(timeoutMs: number = CLOSE_TIMEOUT_MS): Promise<void> {
    this.#closing ??= this.#close(timeoutMs);
    return this.#closing;
  }

  async #close(timeoutMs: number): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(() => {
        log.warn("audit database did not finish in time", { pending: this.#pending.size });
        resolve();
      }, timeoutMs);
    });
    const drain = async (): Promise<void> => {
      await Promise.allSettled([...this.#pending]);
      await this.#db.$disconnect();
    };
    try {
      await Promise.race([drain(), timeout]);
    } catch (err) {
      log.warn("error while closing the audit database", errorLogFields(err));
    } finally {
      clearTimeout(timer);
    }
  }

  async #insert(record: AuditRecord): Promise<void> {
    await this.#db.create({
      time: new Date(record.time),
      tool: record.tool,
      path: text(record.path),
      source: text(record.source),
      destination: text(record.destination),
      result: record.result,
      code: record.code ?? null,
      bytes: record.bytes === undefined ? null : BigInt(Math.trunc(record.bytes)),
      durationMs: BigInt(Math.trunc(record.duration_ms)),
    });
  }

  #notSaved(err?: unknown): void {
    this.#unsaved += 1;
    const now = Date.now();
    if (now - this.#lastWarning < WARN_INTERVAL_MS) return;
    this.#lastWarning = now;
    log.warn("audit records not saved to the database (they are on stderr)", {
      count: this.#unsaved,
      ...(err === undefined ? {} : errorLogFields(err)),
    });
    this.#unsaved = 0;
  }
}
