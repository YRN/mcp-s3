-- Audit log table. Written by hand from
-- `prisma migrate diff`: id is GENERATED ALWAYS AS IDENTITY (Prisma would emit BIGSERIAL), and the
-- CHECK constraint on "result" cannot be expressed in schema.prisma.
CREATE TABLE "mcp_s3_audit_log" (
    "id" bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    "time" timestamptz NOT NULL,
    "tool" text NOT NULL,
    "path" text,
    "source" text,
    "destination" text,
    "result" text NOT NULL CHECK (result IN ('ok', 'error')),
    "code" text,
    "bytes" bigint,
    "duration_ms" bigint NOT NULL
);

CREATE INDEX "mcp_s3_audit_log_time_idx" ON "mcp_s3_audit_log"("time");
