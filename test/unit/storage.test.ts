import { Readable } from "node:stream";

import { GetObjectCommand, type GetObjectCommandOutput } from "@aws-sdk/client-s3";
import { afterEach, describe, expect, it } from "vitest";

import { toSafeError } from "../../src/errors.js";
import { resolveKey } from "../../src/paths.js";
import {
  createS3Client,
  parseContentRange,
  S3_CONNECTION_TIMEOUT_MS,
  S3_REQUEST_TIMEOUT_MS,
  S3_SOCKET_TIMEOUT_MS,
  Storage,
  StorageResponseError,
} from "../../src/storage.js";
import { FakeS3 } from "../helpers/fakeS3.js";

const BUCKET = "acme-secret-bucket-7f3a";
const ROOT = "claude-workspace/";
const KEY = resolveKey(ROOT, "big.bin");

let fake: FakeS3 | undefined;

afterEach(() => {
  fake?.restore();
  fake = undefined;
});

function storageWith(): { f: FakeS3; storage: Storage } {
  fake = new FakeS3(BUCKET);
  return { f: fake, storage: new Storage(fake.client, BUCKET) };
}

/** A Node Readable producing `chunks` chunks of `size` bytes; counts how many were pulled. */
function countingStream(chunks: number, size: number): { stream: Readable; pulled: () => number } {
  let pulled = 0;
  const stream = new Readable({
    read() {
      if (pulled >= chunks) {
        this.push(null);
        return;
      }
      pulled++;
      this.push(Buffer.alloc(size, 0x61));
    },
  });
  return { stream, pulled: () => pulled };
}

/** A web-stream style body (no Node Readable) whose reads are recorded. */
function webBody(bytes: Uint8Array): { body: GetObjectCommandOutput["Body"]; reads: () => number } {
  let reads = 0;
  const body = {
    transformToByteArray: () => {
      reads++;
      return Promise.resolve(bytes);
    },
    transformToString: () => {
      reads++;
      return Promise.resolve(Buffer.from(bytes).toString("utf8"));
    },
    transformToWebStream: () => {
      reads++;
      return new Blob([bytes]).stream();
    },
  };
  return { body: body as unknown as GetObjectCommandOutput["Body"], reads: () => reads };
}

function asBody(stream: Readable): GetObjectCommandOutput["Body"] {
  return stream as unknown as GetObjectCommandOutput["Body"];
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("expected the storage call to fail");
}

describe("parseContentRange", () => {
  it.each([
    ["bytes 0-9/100", { start: 0, end: 9, total: 100 }],
    ["bytes 10-19/*", { start: 10, end: 19, total: undefined }],
    [" bytes 5-5/6 ", { start: 5, end: 5, total: 6 }],
  ])("parses %j", (value, expected) => {
    expect(parseContentRange(value)).toEqual(expected);
  });

  it.each([undefined, "", "bytes */100", "bytes 0-9", "items 0-9/100", "bytes a-b/c", "bytes 0-9/100 extra"])(
    "returns undefined for %j",
    (value) => {
      expect(parseContentRange(value)).toBeUndefined();
    },
  );
});

describe("Storage.get: the provider must honour the Range", () => {
  it("206 with a Content-Range starting at another offset is rejected (InternalError)", async () => {
    const { f, storage } = storageWith();
    const { body, reads } = webBody(Buffer.from("0123456789"));
    f.mock.on(GetObjectCommand).resolves({
      $metadata: { httpStatusCode: 206 },
      Body: body,
      ContentRange: "bytes 0-9/100",
      ContentLength: 10,
    });
    const err = await failure(storage.get(KEY, { offset: 50, length: 10 }));
    expect(err).toBeInstanceOf(StorageResponseError);
    expect(toSafeError(err)).toMatchObject({ code: "InternalError" });
    expect(reads()).toBe(0);
  });

  // A 200 without Content-Range means the provider ignored the Range and sent the object from
  // byte 0. That is still correct data for offset 0 (capped at `length`), never for offset > 0.
  it("200 without Content-Range at offset 0 is accepted", async () => {
    const { f, storage } = storageWith();
    const { body } = webBody(Buffer.from("0123456789"));
    f.mock.on(GetObjectCommand).resolves({ $metadata: { httpStatusCode: 200 }, Body: body, ContentLength: 10 });
    const data = await storage.get(KEY, { offset: 0, length: 10 });
    expect(Buffer.from(data.bytes).toString("utf8")).toBe("0123456789");
  });

  it("200 without Content-Range at offset 0 with a larger object is capped at `length` and the stream released", async () => {
    const { f, storage } = storageWith();
    const { stream, pulled } = countingStream(100, 1024);
    f.mock.on(GetObjectCommand).resolves({ $metadata: { httpStatusCode: 200 }, Body: asBody(stream), ContentLength: 102_400 });
    const data = await storage.get(KEY, { offset: 0, length: 1500 });
    expect(data.bytes.length).toBe(1500);
    expect(stream.destroyed).toBe(true);
    expect(pulled()).toBeLessThan(10);
  });

  it("200 without Content-Range at offset > 0 is rejected and the body is not read", async () => {
    const { f, storage } = storageWith();
    const { body, reads } = webBody(Buffer.from("0123456789"));
    f.mock.on(GetObjectCommand).resolves({ $metadata: { httpStatusCode: 200 }, Body: body, ContentLength: 10 });
    const err = await failure(storage.get(KEY, { offset: 5, length: 5 }));
    expect(toSafeError(err).code).toBe("InternalError");
    expect(reads()).toBe(0);
  });

  it("200 without Content-Range at offset > 0 destroys a Node stream body unread", async () => {
    const { f, storage } = storageWith();
    const { stream, pulled } = countingStream(100, 1024);
    f.mock.on(GetObjectCommand).resolves({ $metadata: { httpStatusCode: 200 }, Body: asBody(stream), ContentLength: 102_400 });
    const err = await failure(storage.get(KEY, { offset: 1024, length: 1024 }));
    expect(toSafeError(err).code).toBe("InternalError");
    expect(stream.destroyed).toBe(true);
    expect(pulled()).toBeLessThanOrEqual(1); // at most the stream's own initial buffering
  });

  it("ContentLength above the requested length is rejected unread", async () => {
    const { f, storage } = storageWith();
    const { stream, pulled } = countingStream(100, 1024);
    f.mock.on(GetObjectCommand).resolves({
      $metadata: { httpStatusCode: 206 },
      Body: asBody(stream),
      ContentRange: "bytes 0-102399/102400",
      ContentLength: 102_400,
    });
    const err = await failure(storage.get(KEY, { offset: 0, length: 1024 }));
    expect(toSafeError(err).code).toBe("InternalError");
    expect(stream.destroyed).toBe(true);
    expect(pulled()).toBeLessThanOrEqual(1);
  });

  it("206 without Content-Range and a longer body is cut to `length` bytes", async () => {
    const { f, storage } = storageWith();
    const { body } = webBody(Buffer.from("abcdefghijklmnopqrstuvwxyz"));
    f.mock.on(GetObjectCommand).resolves({ $metadata: { httpStatusCode: 206 }, Body: body });
    const data = await storage.get(KEY, { offset: 0, length: 5 });
    expect(Buffer.from(data.bytes).toString("utf8")).toBe("abcde");
    expect(data.totalSize).toBeUndefined();
  });

  it("a Node stream body is destroyed once `length` bytes have been read", async () => {
    const { f, storage } = storageWith();
    const { stream, pulled } = countingStream(1000, 1024);
    f.mock.on(GetObjectCommand).resolves({ $metadata: { httpStatusCode: 206 }, Body: asBody(stream) });
    const data = await storage.get(KEY, { offset: 0, length: 1500 });
    expect(data.bytes.length).toBe(1500);
    expect(Buffer.from(data.bytes).every((b) => b === 0x61)).toBe(true);
    expect(stream.destroyed).toBe(true);
    expect(pulled()).toBeLessThan(10); // nowhere near the 1000 available chunks
  });

  it("a matching Content-Range is accepted and gives the total size", async () => {
    const { f, storage } = storageWith();
    const { body } = webBody(Buffer.from("0123456789"));
    f.mock.on(GetObjectCommand).resolves({
      $metadata: { httpStatusCode: 206 },
      Body: body,
      ContentRange: "bytes 50-59/100",
      ContentLength: 10,
    });
    const data = await storage.get(KEY, { offset: 50, length: 10 });
    expect(Buffer.from(data.bytes).toString("utf8")).toBe("0123456789");
    expect(data.totalSize).toBe(100);
  });

  it("a malformed Content-Range is rejected", async () => {
    const { f, storage } = storageWith();
    const { body, reads } = webBody(Buffer.from("0123456789"));
    f.mock.on(GetObjectCommand).resolves({ $metadata: { httpStatusCode: 206 }, Body: body, ContentRange: "bytes garbage" });
    expect(toSafeError(await failure(storage.get(KEY, { offset: 0, length: 10 }))).code).toBe("InternalError");
    expect(reads()).toBe(0);
  });

  it("sends If-Match only when asked to", async () => {
    const { f, storage } = storageWith();
    f.put(KEY, "hello");
    await storage.get(KEY, { offset: 0, length: 5 });
    const etag = f.objects.get(KEY)?.etag;
    await storage.get(KEY, { offset: 0, length: 5 }, { ifMatch: etag });
    const inputs = f.sentInputs();
    expect(inputs[0]).not.toHaveProperty("IfMatch");
    expect(inputs[1]?.IfMatch).toBe(etag);
  });

  it.each([
    [{ offset: -1, length: 1 }],
    [{ offset: 0, length: 0 }],
    [{ offset: 1.5, length: 1 }],
    [{ offset: 0, length: Number.MAX_SAFE_INTEGER + 1 }],
  ])("rejects an invalid range %j without a request", async (range) => {
    const { f, storage } = storageWith();
    await failure(storage.get(KEY, range));
    expect(f.mock.calls()).toHaveLength(0);
  });
});

describe("createS3Client", () => {
  it("configures connection, request, and socket timeouts on the request handler", async () => {
    const client = createS3Client({ region: "us-east-1", forcePathStyle: true, endpoint: "http://127.0.0.1:1" });
    const handler = client.config.requestHandler as unknown as {
      // Internal promise of NodeHttpHandler; its resolved value is what httpHandlerConfigs() returns later.
      configProvider: Promise<Record<string, unknown>>;
    };
    const resolved = await handler.configProvider;
    expect(resolved).toMatchObject({
      connectionTimeout: S3_CONNECTION_TIMEOUT_MS,
      requestTimeout: S3_REQUEST_TIMEOUT_MS,
      socketTimeout: S3_SOCKET_TIMEOUT_MS,
      throwOnRequestTimeout: true,
    });
    expect(S3_CONNECTION_TIMEOUT_MS).toBeGreaterThan(0);
    expect(S3_REQUEST_TIMEOUT_MS).toBeGreaterThan(0);
    expect(S3_SOCKET_TIMEOUT_MS).toBeGreaterThan(0);
    client.destroy();
  });

  it("uses the endpoint and path style from the config", async () => {
    const client = createS3Client({ region: "eu-west-1", forcePathStyle: true, endpoint: "http://127.0.0.1:19000" });
    expect(client.config.forcePathStyle).toBe(true);
    expect(await client.config.region()).toBe("eu-west-1");
    const endpoint = await client.config.endpoint?.();
    expect(endpoint?.hostname).toBe("127.0.0.1");
    client.destroy();
  });
});
