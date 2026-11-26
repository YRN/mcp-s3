import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createSecretKey,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

import { z } from "zod";

/**
 * Stateless, encrypted OAuth artifacts (client IDs, login requests, authorization codes,
 * access and refresh tokens), following the pattern of ../tokens.ts.
 *
 * Domain separation from list `next_token`s and between artifact kinds is twofold:
 * - every kind uses its own AES-256-GCM key, derived from MCP_S3_TOKEN_KEY with HKDF-SHA256
 *   and a kind-specific label (next_token uses MCP_S3_TOKEN_KEY directly, so no derived key
 *   equals it), and
 * - the GCM additional authenticated data contains the version byte and the same label.
 * A token of one kind therefore never opens as another kind, or as a next_token.
 *
 * Wire format: base64url( version (1 byte) || iv (12 bytes) || ciphertext || tag (16 bytes) ),
 * plaintext JSON { p: payload, e: expiry in epoch seconds (optional) }.
 */

export const SEALED_VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;
const ALGORITHM = "aes-256-gcm";
const VERSION_HEADER = Buffer.from([SEALED_VERSION]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const HKDF_PREFIX = "mcp-s3 oauth v1 ";

const Envelope = z.strictObject({ p: z.unknown(), e: z.number().int().optional() });

/** Derive a 32-byte key for `label` from the root key (MCP_S3_TOKEN_KEY). */
export function deriveKey(root: KeyObject, salt: Uint8Array, label: string): KeyObject {
  return createSecretKey(Buffer.from(hkdfSync("sha256", root, salt, HKDF_PREFIX + label, KEY_BYTES)));
}

/** base64url(SHA-256(value)): a short, stable, non-reversible reference (e.g. to a client ID). */
export function sha256Base64url(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

/** base64url(HMAC-SHA256(key, value)). */
export function hmacBase64url(key: KeyObject, value: string): string {
  return createHmac("sha256", key).update(value, "utf8").digest("base64url");
}

/**
 * Constant-time string equality. Both values are hashed to 32 bytes first, so neither the
 * comparison time nor an exception depends on where they differ or on their lengths.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const da = createHash("sha256").update(a, "utf8").digest();
  const db = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(da, db);
}

export interface Opened<T> {
  payload: T;
  /** Expiry (epoch seconds), if the artifact has one. */
  expiresAt: number | undefined;
}

export class SealedCodec<S extends z.ZodType> {
  private readonly key: KeyObject;
  private readonly aad: Buffer;
  private readonly schema: S;
  private readonly maxLength: number;
  private readonly now: () => number;

  /**
   * @param key Kind-specific key from deriveKey().
   * @param label Kind label, also bound into the AAD.
   * @param schema Payload schema; payloads that do not match are rejected on open.
   * @param maxLength Upper bound on the encoded length accepted by open().
   * @param now Clock in milliseconds.
   */
  constructor(key: KeyObject, label: string, schema: S, maxLength: number, now: () => number = () => Date.now()) {
    this.key = key;
    this.aad = Buffer.concat([VERSION_HEADER, Buffer.from(HKDF_PREFIX + label, "utf8")]);
    this.schema = schema;
    this.maxLength = maxLength;
    this.now = now;
  }

  nowSeconds(): number {
    return Math.floor(this.now() / 1000);
  }

  /** Encrypt `payload`. With `ttlSeconds`, the artifact expires that many seconds from now. */
  seal(payload: z.infer<S>, ttlSeconds?: number): string {
    const envelope = ttlSeconds === undefined ? { p: payload } : { p: payload, e: this.nowSeconds() + ttlSeconds };
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(this.aad);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(envelope), "utf8"), cipher.final()]);
    return Buffer.concat([VERSION_HEADER, iv, ciphertext, cipher.getAuthTag()]).toString("base64url");
  }

  /**
   * Decrypt and validate. Returns undefined for every kind of failure (encoding, version,
   * authentication, payload shape, expiry), so callers cannot tell them apart.
   */
  open(token: string): Opened<z.infer<S>> | undefined {
    if (token.length === 0 || token.length > this.maxLength || !BASE64URL.test(token)) return undefined;
    const raw = Buffer.from(token, "base64url");
    if (raw.length < 1 + IV_BYTES + 1 + TAG_BYTES || raw[0] !== SEALED_VERSION) return undefined;

    let plaintext: string;
    try {
      const decipher = createDecipheriv(ALGORITHM, this.key, raw.subarray(1, 1 + IV_BYTES), { authTagLength: TAG_BYTES });
      decipher.setAAD(this.aad);
      decipher.setAuthTag(raw.subarray(raw.length - TAG_BYTES));
      plaintext = Buffer.concat([decipher.update(raw.subarray(1 + IV_BYTES, raw.length - TAG_BYTES)), decipher.final()]).toString("utf8");
    } catch {
      return undefined;
    }

    let json: unknown;
    try {
      json = JSON.parse(plaintext);
    } catch {
      return undefined;
    }
    const envelope = Envelope.safeParse(json);
    if (!envelope.success) return undefined;
    const expiresAt = envelope.data.e;
    if (expiresAt !== undefined && this.nowSeconds() >= expiresAt) return undefined;
    const payload = this.schema.safeParse(envelope.data.p);
    if (!payload.success) return undefined;
    return { payload: payload.data, expiresAt };
  }
}
