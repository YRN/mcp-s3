import { randomBytes, createSecretKey } from "node:crypto";
import { inspect } from "node:util";

import { describe, expect, it } from "vitest";
import { z } from "zod";

import { parseBasicAuth } from "../../src/http/clientAuth.js";
import { constantTimeEqual, deriveKey, SealedCodec } from "../../src/http/sealed.js";
import { Secret } from "../../src/secret.js";

const basic = (value: string): string => `Basic ${Buffer.from(value, "utf8").toString("base64")}`;

describe("parseBasicAuth", () => {
  it("returns undefined without a Basic header", () => {
    expect(parseBasicAuth(undefined)).toBeUndefined();
    expect(parseBasicAuth("Bearer abc")).toBeUndefined();
    expect(parseBasicAuth("Digest realm=x")).toBeUndefined();
  });

  it("parses id and secret", () => {
    expect(parseBasicAuth(basic("client:secret"))).toEqual({ id: "client", secret: "secret" });
  });

  it("accepts any case of the scheme and extra spaces", () => {
    const b64 = Buffer.from("c:s").toString("base64");
    expect(parseBasicAuth(`basic ${b64}`)).toEqual({ id: "c", secret: "s" });
    expect(parseBasicAuth(`BASIC   ${b64}  `)).toEqual({ id: "c", secret: "s" });
  });

  it("splits at the first colon only (secret may contain colons)", () => {
    expect(parseBasicAuth(basic("id:se:cr:et"))).toEqual({ id: "id", secret: "se:cr:et" });
  });

  it("form-decodes id and secret (RFC 6749 section 2.3.1)", () => {
    expect(parseBasicAuth(basic("my%3Aid:s%40cret%2B1+x"))).toEqual({ id: "my:id", secret: "s@cret+1 x" });
  });

  it("allows an empty secret", () => {
    expect(parseBasicAuth(basic("id:"))).toEqual({ id: "id", secret: "" });
  });

  it("returns null for malformed Basic headers", () => {
    expect(parseBasicAuth("Basic")).toBeNull();
    expect(parseBasicAuth("Basic ")).toBeNull();
    expect(parseBasicAuth("Basic !!!not-base64")).toBeNull();
    expect(parseBasicAuth(basic("no-colon-here"))).toBeNull();
    expect(parseBasicAuth(basic(":secret-without-id"))).toBeNull();
    expect(parseBasicAuth(basic("id%ZZ:secret"))).toBeNull(); // invalid percent-encoding
    expect(parseBasicAuth("Basic a b")).toBeNull();
  });
});

describe("constantTimeEqual", () => {
  it("compares strings of any length without throwing", () => {
    expect(constantTimeEqual("a", "a")).toBe(true);
    expect(constantTimeEqual("", "")).toBe(true);
    expect(constantTimeEqual("a", "b")).toBe(false);
    expect(constantTimeEqual("a", "aa")).toBe(false);
    expect(constantTimeEqual("x".repeat(10_000), "x")).toBe(false);
  });
});

describe("SealedCodec", () => {
  const root = createSecretKey(randomBytes(32));
  const salt = Buffer.from("test salt");
  const Payload = z.strictObject({ a: z.string(), n: z.number() });
  const payload = { a: "hello", n: 7 };

  let nowMs = Date.UTC(2026, 0, 1, 0, 0, 0);
  const clock = (): number => nowMs;
  const make = (label = "kind-a", key = deriveKey(root, salt, label), maxLength = 4096): SealedCodec<typeof Payload> =>
    new SealedCodec(key, label, Payload, maxLength, clock);

  it("round-trips a payload", () => {
    const codec = make();
    const token = codec.seal(payload);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(codec.open(token)?.payload).toEqual(payload);
    expect(codec.open(token)?.expiresAt).toBeUndefined();
  });

  it("produces different tokens for the same payload (random IV)", () => {
    const codec = make();
    expect(codec.seal(payload)).not.toBe(codec.seal(payload));
  });

  it("does not contain the plaintext", () => {
    expect(Buffer.from(make().seal(payload), "base64url").toString("utf8")).not.toContain("hello");
  });

  it("expires: valid until the expiry second, rejected from then on", () => {
    nowMs = Date.UTC(2026, 0, 1, 0, 0, 0);
    const codec = make();
    const token = codec.seal(payload, 60);
    expect(codec.open(token)?.expiresAt).toBe(Math.floor(nowMs / 1000) + 60);
    nowMs += 59_000;
    expect(codec.open(token)).toBeDefined();
    nowMs += 1_000;
    expect(codec.open(token)).toBeUndefined();
    nowMs += 3_600_000;
    expect(codec.open(token)).toBeUndefined();
  });

  it("a token without TTL never expires", () => {
    nowMs = Date.UTC(2026, 0, 1);
    const codec = make();
    const token = codec.seal(payload);
    nowMs += 10 * 365 * 24 * 3600 * 1000;
    expect(codec.open(token)).toBeDefined();
  });

  it("rejects tampered tokens (any single character change)", () => {
    nowMs = Date.UTC(2026, 0, 1);
    const codec = make();
    const token = codec.seal(payload, 600);
    for (let i = 0; i < token.length; i += 1) {
      const swapped = token.charAt(i) === "A" ? "B" : "A";
      const tampered = token.slice(0, i) + swapped + token.slice(i + 1);
      // The last base64url character carries unused bits: changing only those bits decodes identically.
      if (Buffer.from(tampered, "base64url").equals(Buffer.from(token, "base64url"))) continue;
      expect(codec.open(tampered), `char ${String(i)}`).toBeUndefined();
    }
  });

  it("rejects truncated, extended, empty, and non-base64url input", () => {
    const codec = make();
    const token = codec.seal(payload, 600);
    expect(codec.open(token.slice(0, -4))).toBeUndefined();
    expect(codec.open(token + "AAAA")).toBeUndefined();
    expect(codec.open("")).toBeUndefined();
    expect(codec.open("not base64url!")).toBeUndefined();
    expect(codec.open(token + "=")).toBeUndefined();
    expect(codec.open("AAAA")).toBeUndefined();
  });

  it("rejects a wrong version byte", () => {
    const codec = make();
    const raw = Buffer.from(codec.seal(payload), "base64url");
    raw[0] = 2;
    expect(codec.open(raw.toString("base64url"))).toBeUndefined();
  });

  it("rejects tokens opened with a different key", () => {
    const token = make("kind-a").seal(payload);
    const otherRoot = createSecretKey(randomBytes(32));
    const other = new SealedCodec(deriveKey(otherRoot, salt, "kind-a"), "kind-a", Payload, 4096, clock);
    expect(other.open(token)).toBeUndefined();
  });

  it("rejects tokens opened with a different label, even with the same key (AAD binding)", () => {
    const key = deriveKey(root, salt, "kind-a");
    const token = new SealedCodec(key, "kind-a", Payload, 4096, clock).seal(payload);
    expect(new SealedCodec(key, "kind-b", Payload, 4096, clock).open(token)).toBeUndefined();
  });

  it("rejects tokens opened with a key derived for a different label (same label string)", () => {
    const token = make("kind-a").seal(payload);
    const wrongKey = new SealedCodec(deriveKey(root, salt, "kind-b"), "kind-a", Payload, 4096, clock);
    expect(wrongKey.open(token)).toBeUndefined();
  });

  it("rejects tokens opened with a different salt", () => {
    const token = make("kind-a").seal(payload);
    const other = new SealedCodec(deriveKey(root, Buffer.from("other salt"), "kind-a"), "kind-a", Payload, 4096, clock);
    expect(other.open(token)).toBeUndefined();
  });

  it("rejects payloads that do not match the schema", () => {
    const key = deriveKey(root, salt, "kind-a");
    const Loose = z.object({ a: z.string() });
    const token = new SealedCodec(key, "kind-a", Loose, 4096, clock).seal({ a: "x" });
    expect(make("kind-a", key).open(token)).toBeUndefined();
  });

  it("rejects tokens longer than maxLength before decrypting", () => {
    const token = make().seal(payload);
    expect(make("kind-a", undefined, token.length - 1).open(token)).toBeUndefined();
    expect(make("kind-a", undefined, token.length).open(token)).toBeDefined();
  });
});

describe("Secret", () => {
  const value = "hunter2-very-secret";
  const secret = new Secret(value);

  it("reveals the value only through reveal()", () => {
    expect(secret.reveal()).toBe(value);
  });

  it("does not print through JSON.stringify", () => {
    expect(JSON.stringify(secret)).not.toContain(value);
    expect(JSON.stringify({ nested: { secret }, list: [secret] })).not.toContain(value);
    expect(JSON.stringify(secret)).toBe('"[redacted]"');
  });

  it("does not print through String() or template literals", () => {
    expect(String(secret)).not.toContain(value);
    expect([secret].join(",")).toBe("[redacted]");
    expect(String(secret)).toBe("[redacted]");
    expect("x" + String(secret)).not.toContain(value);
  });

  it("does not print through util.inspect, nested or not", () => {
    expect(inspect(secret)).not.toContain(value);
    expect(inspect({ secret, deep: { a: [secret] } }, { depth: 10 })).not.toContain(value);
    expect(inspect(secret, { showHidden: true })).not.toContain(value);
    expect(inspect(secret)).toContain("redacted");
  });

  it("does not expose the value through enumerable keys or Object.entries", () => {
    expect(Object.keys(secret)).toEqual([]);
    expect(JSON.stringify(Object.entries(secret))).not.toContain(value);
    expect(JSON.stringify(Object.assign({}, secret))).not.toContain(value);
  });
});
