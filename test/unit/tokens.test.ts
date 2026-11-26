import { createCipheriv, createSecretKey, randomBytes, type KeyObject } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  MAX_TOKEN_LENGTH,
  parseTokenKey,
  processTokenKey,
  TOKEN_TTL_SECONDS,
  TokenCodec,
  type TokenScope,
} from "../../src/tokens.js";

const RAW_S3_TOKEN = Buffer.from("acme-secret-bucket-7f3a/claude-workspace/p/f1.txt").toString("base64");
const SCOPE: TokenScope = { prefix: "claude-workspace/p/", recursive: true };
/** A fixed clock, aligned to a whole second. */
const T0 = Date.UTC(2026, 10, 26, 12, 0, 0);

function newKey(): KeyObject {
  return createSecretKey(randomBytes(32));
}

function codecAt(key: KeyObject, ms: number): TokenCodec {
  return new TokenCodec(key, () => ms);
}

/** Flip one bit of byte `index` of the decoded token and re-encode it. */
function tamper(token: string, index: number): string {
  const raw = Buffer.from(token, "base64url");
  raw[index] = (raw[index] ?? 0) ^ 0x01;
  return raw.toString("base64url");
}

/**
 * Build a token by hand following the documented wire format
 * base64url(version || iv(12) || ciphertext || tag(16)), AES-256-GCM, AAD = version byte.
 */
function forge(key: KeyObject, plaintext: string, version = 1): string {
  const iv = randomBytes(12);
  const aad = Buffer.from([version]);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([aad, iv, ciphertext, cipher.getAuthTag()]).toString("base64url");
}

describe("TokenCodec: round trip and opacity", () => {
  it("opens what it sealed", () => {
    const codec = new TokenCodec(newKey());
    expect(codec.open(codec.seal(RAW_S3_TOKEN, SCOPE), SCOPE)).toBe(RAW_S3_TOKEN);
  });

  it("a codec with the same key (another process) opens the token", () => {
    const bytes = randomBytes(32);
    const a = new TokenCodec(createSecretKey(bytes));
    const b = new TokenCodec(createSecretKey(Buffer.from(bytes)));
    expect(b.open(a.seal(RAW_S3_TOKEN, SCOPE), SCOPE)).toBe(RAW_S3_TOKEN);
  });

  it("every seal produces a different token (random IV)", () => {
    const codec = new TokenCodec(newKey());
    const tokens = new Set(Array.from({ length: 50 }, () => codec.seal(RAW_S3_TOKEN, SCOPE)));
    expect(tokens.size).toBe(50);
    for (const token of tokens) expect(codec.open(token, SCOPE)).toBe(RAW_S3_TOKEN);
  });

  it("is URL-safe base64 and hides the raw token and the prefix", () => {
    const codec = new TokenCodec(newKey());
    const token = codec.seal(RAW_S3_TOKEN, SCOPE);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    const decoded = Buffer.from(token, "base64url");
    for (const view of [decoded.toString("utf8"), decoded.toString("latin1"), token]) {
      expect(view).not.toContain(RAW_S3_TOKEN);
      expect(view).not.toContain("claude-workspace");
      expect(view).not.toContain("acme-secret-bucket");
    }
    // The raw token itself is base64 of the key; make sure that is not hiding in there either.
    expect(decoded.includes(Buffer.from(RAW_S3_TOKEN, "base64"))).toBe(false);
  });

  it("starts with version byte 1 and has room for iv and tag", () => {
    const token = new TokenCodec(newKey()).seal(RAW_S3_TOKEN, SCOPE);
    const raw = Buffer.from(token, "base64url");
    expect(raw[0]).toBe(1);
    expect(raw.length).toBeGreaterThan(1 + 12 + 16);
  });

  it("handles a long S3 token and a long unicode prefix within MAX_TOKEN_LENGTH", () => {
    const codec = new TokenCodec(newKey());
    const scope: TokenScope = { prefix: `claude-workspace/${"é\"".repeat(330)}/`, recursive: false };
    const s3Token = Buffer.from(`bucket/${"k".repeat(1024)}`).toString("base64");
    const token = codec.seal(s3Token, scope);
    expect(token.length).toBeLessThanOrEqual(MAX_TOKEN_LENGTH);
    expect(codec.open(token, scope)).toBe(s3Token);
  });
});

describe("TokenCodec: tampering", () => {
  const key = newKey();
  const codec = new TokenCodec(key);
  const token = codec.seal(RAW_S3_TOKEN, SCOPE);
  const raw = Buffer.from(token, "base64url");
  const tagStart = raw.length - 16;

  it.each([
    ["version byte", 0],
    ["first iv byte", 1],
    ["last iv byte", 12],
    ["first ciphertext byte", 13],
    ["last ciphertext byte", tagStart - 1],
    ["first tag byte", tagStart],
    ["last tag byte", raw.length - 1],
  ])("flipping the %s (index %i) is rejected", (_name, index) => {
    expect(codec.open(tamper(token, index), SCOPE)).toBeUndefined();
  });

  it("flipping any single bit anywhere is rejected", () => {
    for (let index = 0; index < raw.length; index++) {
      for (let bit = 0; bit < 8; bit++) {
        const copy = Buffer.from(raw);
        copy[index] = (copy[index] ?? 0) ^ (1 << bit);
        expect(codec.open(copy.toString("base64url"), SCOPE), `byte ${index} bit ${bit}`).toBeUndefined();
      }
    }
  });

  it("truncated or extended tokens are rejected", () => {
    expect(codec.open(raw.subarray(0, raw.length - 1).toString("base64url"), SCOPE)).toBeUndefined();
    expect(codec.open(raw.subarray(0, 29).toString("base64url"), SCOPE)).toBeUndefined();
    expect(codec.open(Buffer.concat([raw, Buffer.from([0])]).toString("base64url"), SCOPE)).toBeUndefined();
  });

  it.each([
    ["empty", ""],
    ["standard base64 alphabet", `${token.slice(0, -2)}+/`],
    ["padding", `${token}=`],
    ["whitespace", ` ${token}`],
    ["garbage", "not-a-real-token"],
    ["too long", "A".repeat(MAX_TOKEN_LENGTH + 1)],
  ])("malformed input (%s) is rejected", (_name, value) => {
    expect(codec.open(value, SCOPE)).toBeUndefined();
  });

  it("a token sealed with another key is rejected", () => {
    const other = new TokenCodec(newKey());
    expect(other.open(token, SCOPE)).toBeUndefined();
    expect(codec.open(other.seal(RAW_S3_TOKEN, SCOPE), SCOPE)).toBeUndefined();
  });

  it("a correctly encrypted token with another version byte is rejected", () => {
    const payload = JSON.stringify({ t: RAW_S3_TOKEN, p: SCOPE.prefix, r: true, e: 4_102_444_800 });
    expect(codec.open(forge(key, payload, 1), SCOPE)).toBe(RAW_S3_TOKEN); // sanity: the forge matches the format
    expect(codec.open(forge(key, payload, 2), SCOPE)).toBeUndefined();
    expect(codec.open(forge(key, payload, 0), SCOPE)).toBeUndefined();
  });

  it.each([
    ["not JSON", "t=abc"],
    ["missing field", JSON.stringify({ t: RAW_S3_TOKEN, p: SCOPE.prefix, r: true })],
    ["extra field", JSON.stringify({ t: RAW_S3_TOKEN, p: SCOPE.prefix, r: true, e: 4_102_444_800, x: 1 })],
    ["wrong types", JSON.stringify({ t: RAW_S3_TOKEN, p: SCOPE.prefix, r: "true", e: "4102444800" })],
    ["empty S3 token", JSON.stringify({ t: "", p: SCOPE.prefix, r: true, e: 4_102_444_800 })],
  ])("a correctly encrypted but malformed payload (%s) is rejected", (_name, payload) => {
    expect(codec.open(forge(key, payload), SCOPE)).toBeUndefined();
  });
});

describe("TokenCodec: scope", () => {
  const codec = new TokenCodec(newKey());
  const token = codec.seal(RAW_S3_TOKEN, SCOPE);

  it.each([
    ["another prefix", { prefix: "claude-workspace/", recursive: true }],
    ["a sibling prefix", { prefix: "claude-workspace/q/", recursive: true }],
    ["a sub-prefix", { prefix: "claude-workspace/p/x/", recursive: true }],
    ["the other recursive mode", { prefix: SCOPE.prefix, recursive: false }],
  ])("is rejected for %s", (_name, scope: TokenScope) => {
    expect(codec.open(token, scope)).toBeUndefined();
  });
});

describe("TokenCodec: expiry", () => {
  it(`is valid until TTL-1 s and rejected from exactly TTL (${TOKEN_TTL_SECONDS} s)`, () => {
    expect(TOKEN_TTL_SECONDS).toBe(3600);
    const key = newKey();
    const token = codecAt(key, T0).seal(RAW_S3_TOKEN, SCOPE);
    expect(codecAt(key, T0).open(token, SCOPE)).toBe(RAW_S3_TOKEN);
    expect(codecAt(key, T0 + (TOKEN_TTL_SECONDS - 1) * 1000).open(token, SCOPE)).toBe(RAW_S3_TOKEN);
    expect(codecAt(key, T0 + TOKEN_TTL_SECONDS * 1000 - 1).open(token, SCOPE)).toBe(RAW_S3_TOKEN);
    expect(codecAt(key, T0 + TOKEN_TTL_SECONDS * 1000).open(token, SCOPE)).toBeUndefined();
    expect(codecAt(key, T0 + 10 * TOKEN_TTL_SECONDS * 1000).open(token, SCOPE)).toBeUndefined();
  });

  it("an expired token cannot be revived by tampering with its expiry (it is encrypted)", () => {
    const key = newKey();
    const token = codecAt(key, T0).seal(RAW_S3_TOKEN, SCOPE);
    const later = codecAt(key, T0 + TOKEN_TTL_SECONDS * 1000);
    const raw = Buffer.from(token, "base64url");
    for (let index = 13; index < raw.length - 16; index++) {
      expect(later.open(tamper(token, index), SCOPE)).toBeUndefined();
    }
  });
});

describe("parseTokenKey / processTokenKey", () => {
  it("parses a 32-byte base64 key", () => {
    const bytes = randomBytes(32);
    expect(parseTokenKey(bytes.toString("base64"))?.export()).toEqual(bytes);
    expect(parseTokenKey(bytes.toString("base64url"))?.export()).toEqual(bytes);
  });

  it("rejects a 32-byte key with excess padding (45 characters ending in '==')", () => {
    const canonical = randomBytes(32).toString("base64");
    expect(canonical).toHaveLength(44);
    const padded = `${canonical}=`;
    expect(padded).toHaveLength(45);
    expect(padded.endsWith("==")).toBe(true);
    expect(parseTokenKey(padded)).toBeNull();
    expect(parseTokenKey(canonical)).not.toBeNull();
  });

  it.each(["", "abc", randomBytes(16).toString("base64"), randomBytes(48).toString("base64"), "%%%%"])(
    "rejects %j",
    (value) => {
      expect(parseTokenKey(value)).toBeNull();
    },
  );

  it("the per-process key is stable within the process and 32 bytes long", () => {
    expect(processTokenKey()).toBe(processTokenKey());
    expect(processTokenKey().symmetricKeySize).toBe(32);
  });
});
