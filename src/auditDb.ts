import pg from "pg";

import type { AuditRecord, AuditStore } from "./audit.js";
import { errorLogFields } from "./errors.js";
import { log } from "./logger.js";
import type { Secret } from "./secret.js";

/**
 * PostgreSQL store for audit records. Saving is best effort and never delays or fails a tool
 * call: a record that cannot be saved is not retried, because audit.ts has already written the
 * same line to stderr. Error messages from the driver are never logged (errorLogFields), so the
 * connection URL, user, and host stay out of the logs.
 */

export const AUDIT_TABLE = "mcp_s3_audit";

/** Records waiting for the database beyond this number are not saved (bounds memory use). */
const MAX_PENDING = 1_000;
const MAX_CONNECTIONS = 4;
const TIMEOUT_MS = 5_000;
const CLOSE_TIMEOUT_MS = 3_000;
/** At most one "could not save" warning per this period. */
const WARN_INTERVAL_MS = 60_000;

const TABLE_EXISTS_SQL = `SELECT to_regclass('${AUDIT_TABLE}') IS NOT NULL AS present`;

// Sent as one query, so it runs in one transaction; the advisory lock keeps instances that
// start at the same time from creating the table concurrently.
const CREATE_SQL = `
SELECT pg_advisory_xact_lock(hashtext('${AUDIT_TABLE}'));
CREATE TABLE IF NOT EXISTS ${AUDIT_TABLE} (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  time        timestamptz NOT NULL,
  tool        text NOT NULL,
  path        text,
  source      text,
  destination text,
  result      text NOT NULL CHECK (result IN ('ok', 'error')),
  code        text,
  bytes       bigint,
  duration_ms bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS ${AUDIT_TABLE}_time_idx ON ${AUDIT_TABLE} (time);
`;

const INSERT_SQL = `INSERT INTO ${AUDIT_TABLE}
  (time, tool, path, source, destination, result, code, bytes, duration_ms)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`;

/** The part of pg.Pool the store uses. */
export interface AuditPool {
  query(sql: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
  end(): Promise<void>;
}

/** PostgreSQL text cannot hold NUL, but rejected client paths are audited as sent. */
function text(value: string | undefined): string | null {
  return value === undefined ? null : value.replaceAll("\u0000", "\\u0000");
}

export class PostgresAuditStore implements AuditStore {
  readonly #pool: AuditPool;
  readonly #pending = new Set<Promise<void>>();
  #schema: Promise<void> | undefined;
  #unsaved = 0;
  #lastWarning = Number.NEGATIVE_INFINITY;
  #closing: Promise<void> | undefined;

  constructor(pool: AuditPool) {
    this.#pool = pool;
  }

  static connect(url: Secret): PostgresAuditStore {
    const pool = new pg.Pool({
      connectionString: url.reveal(),
      max: MAX_CONNECTIONS,
      connectionTimeoutMillis: TIMEOUT_MS,
      query_timeout: TIMEOUT_MS,
      statement_timeout: TIMEOUT_MS,
    });
    // Without a listener, an error on an idle connection (database restart) ends the process.
    pool.on("error", (err) => {
      log.warn("audit database connection lost", errorLogFields(err));
    });
    return new PostgresAuditStore(pool);
  }

  /** Create the table early so that a wrong URL shows up at startup. Never rejects. */
  async init(): Promise<void> {
    try {
      await this.#ensureSchema();
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
      await this.#pool.end();
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
    await this.#ensureSchema();
    await this.#pool.query(INSERT_SQL, [
      record.time,
      record.tool,
      text(record.path),
      text(record.source),
      text(record.destination),
      record.result,
      record.code ?? null,
      record.bytes ?? null,
      record.duration_ms,
    ]);
  }

  /** Runs once; after a failure the next caller tries again. */
  #ensureSchema(): Promise<void> {
    this.#schema ??= this.#createSchema().catch((err: unknown) => {
      this.#schema = undefined;
      throw err;
    });
    return this.#schema;
  }

  /** An existing table is left alone, so the database user then only needs INSERT. */
  async #createSchema(): Promise<void> {
    const { rows } = await this.#pool.query(TABLE_EXISTS_SQL);
    if ((rows[0] as { present?: boolean } | undefined)?.present === true) return;
    await this.#pool.query(CREATE_SQL);
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
