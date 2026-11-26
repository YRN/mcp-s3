import { createCipheriv, createDecipheriv, createHash, createSecretKey, randomBytes, type KeyObject } from "node:crypto";

import { z } from "zod";

/**
 * Stateless, encrypted list continuation tokens (PLAN.md section 4, MCP_S3_TOKEN_KEY).
 *
 * Wire format: base64url( version (1 byte) || iv (12 bytes) || ciphertext || tag (16 bytes) )
 * using AES-256-GCM. The additional authenticated data is the version byte followed by
 * SHA-256 of the bucket name, so a token only opens for the bucket that issued it, while the
 * bucket name itself is never part of the token. The plaintext is
 * JSON { t: raw S3 token, p: resolved listing prefix, r: recursive, e: expiry (epoch s) }.
 *
 * The raw S3 token never leaves the server in readable form (some S3-compatible providers
 * embed the full key, including the root prefix, in it), and a token is only accepted for
 * the same prefix and mode that produced it, before it expires.
 */

export const TOKEN_VERSION = 1;
/** Lifetime of a continuation token. */
export const TOKEN_TTL_SECONDS = 60 * 60;
/**
 * Upper bound on the encoded length of a continuation token, checked before decoding.
 * Worst case plaintext: an S3 token (MinIO uses base64 of the full key, up to ~1.4 KB) plus
 * a prefix of up to 1024 UTF-8 bytes (JSON escaping can double quotes), which encodes to
 * roughly 4.7 KB; 8192 leaves headroom without allowing unbounded input.
 */
export const MAX_TOKEN_LENGTH = 8192;
/** Size of an AES-256 key. */
export const TOKEN_KEY_BYTES = 32;

const IV_BYTES = 12;
const TAG_BYTES = 16;
const ALGORITHM = "aes-256-gcm";
const VERSION_HEADER = Buffer.from([TOKEN_VERSION]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const STANDARD_OR_URL_BASE64 = /^(?:[A-Za-z0-9+/]+|[A-Za-z0-9_-]+)={0,2}$/;

const Payload = z.strictObject({
  t: z.string().min(1),
  p: z.string(),
  r: z.boolean(),
  e: z.number().int(),
});

export interface TokenScope {
  /** Resolved listing prefix (full key under the root). */
  prefix: string;
  recursive: boolean;
}

/**
 * Parse a base64 (standard or URL-safe) AES-256 key. Padding is optional, but if present it
 * must be exactly the canonical padding (one "=" for 32 bytes). Returns null when the value
 * is not canonical base64 of exactly 32 bytes. The key is wrapped in a KeyObject, which never
 * serializes or prints its bytes.
 */
export function parseTokenKey(value: string): KeyObject | null {
  if (!STANDARD_OR_URL_BASE64.test(value)) return null;
  const data = value.replace(/=+$/, "");
  const padding = value.length - data.length;
  if (padding !== 0 && padding !== (4 - (data.length % 4)) % 4) return null;
  const bytes = Buffer.from(data, "base64");
  if (bytes.length !== TOKEN_KEY_BYTES) return null;
  // Reject encodings whose unused trailing bits are not zero (non-canonical input).
  const canonical = bytes.toString("base64").replace(/=+$/, "");
  if (canonical !== data.replace(/-/g, "+").replace(/_/g, "/")) return null;
  return createSecretKey(bytes);
}

let processKey: KeyObject | undefined;

/** Random key for this process, used in stdio mode when MCP_S3_TOKEN_KEY is not set. */
export function processTokenKey(): KeyObject {
  processKey ??= createSecretKey(randomBytes(TOKEN_KEY_BYTES));
  return processKey;
}

/** AAD for a token: version byte || SHA-256(bucket name), or just the version byte without a bucket. */
function additionalData(version: Uint8Array, bucket: string | undefined): Buffer {
  if (bucket === undefined) return Buffer.from(version);
  return Buffer.concat([version, createHash("sha256").update(bucket, "utf8").digest()]);
}

export class TokenCodec {
  private readonly key: KeyObject;
  private readonly now: () => number;
  private readonly aad: Buffer;

  /**
   * @param now Clock in milliseconds (defaults to Date.now, so fake timers apply).
   * @param bucket Bucket the tokens belong to. Only its SHA-256 goes into the AAD; a token
   *   sealed for one bucket does not open for another, even with the same key. The server
   *   always passes it; without it the AAD is the version byte alone (unbound tokens).
   */
  constructor(key: KeyObject, now: () => number = () => Date.now(), bucket?: string) {
    this.key = key;
    this.now = now;
    this.aad = additionalData(VERSION_HEADER, bucket);
  }

  /** Encrypt an S3 continuation token bound to `scope`. */
  seal(s3Token: string, scope: TokenScope): string {
    const payload: z.infer<typeof Payload> = {
      t: s3Token,
      p: scope.prefix,
      r: scope.recursive,
      e: Math.floor(this.now() / 1000) + TOKEN_TTL_SECONDS,
    };
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(this.aad);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
    return Buffer.concat([VERSION_HEADER, iv, ciphertext, cipher.getAuthTag()]).toString("base64url");
  }

  /**
   * Decrypt and validate a client-supplied token for `scope`. Returns the raw S3 token, or
   * undefined for every kind of failure (bad encoding, wrong version, failed authentication,
   * malformed payload, expired, other prefix or mode), so callers cannot tell them apart.
   */
  open(token: string, scope: TokenScope): string | undefined {
    if (token.length === 0 || token.length > MAX_TOKEN_LENGTH || !BASE64URL.test(token)) return undefined;
    const raw = Buffer.from(token, "base64url");
    if (raw.length < 1 + IV_BYTES + 1 + TAG_BYTES || raw[0] !== TOKEN_VERSION) return undefined;

    let plaintext: string;
    try {
      const iv = raw.subarray(1, 1 + IV_BYTES);
      const ciphertext = raw.subarray(1 + IV_BYTES, raw.length - TAG_BYTES);
      const tag = raw.subarray(raw.length - TAG_BYTES);
      const decipher = createDecipheriv(ALGORITHM, this.key, iv, { authTagLength: TAG_BYTES });
      // raw[0] === TOKEN_VERSION was checked above, so this.aad covers the version byte.
      decipher.setAAD(this.aad);
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    } catch {
      return undefined;
    }

    let json: unknown;
    try {
      json = JSON.parse(plaintext);
    } catch {
      return undefined;
    }
    const payload = Payload.safeParse(json);
    if (!payload.success) return undefined;

    const { t, p, r, e } = payload.data;
    if (Math.floor(this.now() / 1000) >= e) return undefined;
    if (p !== scope.prefix || r !== scope.recursive) return undefined;
    return t;
  }
}
