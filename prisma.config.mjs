// Only the Prisma CLI reads this file (generate, migrate). The server itself gets the URL from
// src/config.ts. process.env is used directly because env() throws when the variable is unset,
// and `prisma generate` (part of the build) must work without a database URL.
// Plain .mjs: eslint.config.js only type-checks files covered by a tsconfig.
import process from "node:process";
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  datasource: { url: process.env.MCP_S3_AUDIT_DATABASE_URL ?? "" },
});
