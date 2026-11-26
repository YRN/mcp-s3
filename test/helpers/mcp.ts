import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";
import { expect } from "vitest";
import { z } from "zod";

import type { Config } from "../../src/config.js";
import { createServer } from "../../src/server.js";
import type { Storage } from "../../src/storage.js";

export interface InMemoryHarness {
  client: Client;
  call(name: string, args?: Record<string, unknown>): Promise<CallToolResult>;
  listTools(): Promise<ListToolsResult>;
  close(): Promise<void>;
}

/** Connect an MCP client to createServer(config, { storage }) over an in-memory transport. */
export async function connectInMemory(config: Config, storage: Storage): Promise<InMemoryHarness> {
  const server = createServer(config, { storage });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "mcp-s3-unit-test", version: "0.0.0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  return {
    client,
    async call(name, args = {}) {
      const raw = await client.callTool({ name, arguments: args });
      return CallToolResultSchema.parse(raw);
    },
    listTools() {
      return client.listTools();
    },
    async close() {
      await client.close();
      await server.close();
    },
  };
}

// --- result helpers ---------------------------------------------------------

export function texts(result: CallToolResult): string[] {
  return result.content.flatMap((item) => (item.type === "text" ? [item.text] : []));
}

/** The single text item of a result; fails if the result has any other shape. */
export function onlyText(result: CallToolResult): string {
  expect(result.content).toHaveLength(1);
  const [item] = result.content;
  if (item?.type !== "text") throw new Error(`expected a text item, got ${JSON.stringify(item)}`);
  return item.text;
}

export function expectToolError(result: CallToolResult, code: string): string {
  expect(result.isError).toBe(true);
  const text = onlyText(result);
  expect(text.startsWith(`${code}:`), `expected "${code}: ..." but got ${JSON.stringify(text)}`).toBe(true);
  return text;
}

/** Input rejected by the SDK's zod validation (before the handler runs). */
export function expectValidationError(result: CallToolResult): void {
  expect(result.isError).toBe(true);
  expect(onlyText(result)).toMatch(/Input validation error/);
}

export function expectOk(result: CallToolResult): void {
  if (result.isError === true) throw new Error(`expected success, got error ${JSON.stringify(result.content)}`);
}

// --- response schemas (the documented contract) -----------------------------

export const ListObjectsResult = z.strictObject({
  path: z.string(),
  folders: z.array(z.string()),
  files: z.array(z.strictObject({ path: z.string(), size: z.number(), last_modified: z.string().nullable() })),
  next_token: z.string().nullable(),
});
export type ListObjectsResult = z.infer<typeof ListObjectsResult>;

export const ObjectInfoResult = z.strictObject({
  path: z.string(),
  size: z.number(),
  content_type: z.string().nullable(),
  last_modified: z.string().nullable(),
  etag: z.string().nullable(),
  metadata: z.record(z.string(), z.string()),
});
export type ObjectInfoResult = z.infer<typeof ObjectInfoResult>;

export const SearchObjectsResult = z.strictObject({
  path: z.string(),
  pattern: z.string(),
  matches: z.array(z.string()),
  truncated: z.boolean(),
  note: z.string().optional(),
});
export type SearchObjectsResult = z.infer<typeof SearchObjectsResult>;

export function parseJson<T>(result: CallToolResult, schema: z.ZodType<T>): T {
  expectOk(result);
  return schema.parse(JSON.parse(onlyText(result)));
}

/** Truncation note of a text read, e.g. "[showing bytes 0-15 of 40; ... offset=16]". */
export function nextOffset(result: CallToolResult): number | undefined {
  const all = texts(result);
  if (all.length < 2) return undefined;
  const match = /offset=(\d+)/.exec(all[all.length - 1] ?? "");
  return match?.[1] === undefined ? undefined : Number(match[1]);
}
