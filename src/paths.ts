/** S3 limits object keys to 1024 bytes of UTF-8. */
export const S3_MAX_KEY_BYTES = 1024;

declare const resolvedKeyBrand: unique symbol;

/**
 * A full S3 key produced by resolveKey(). It is a plain string at runtime; the brand only
 * exists at compile time so that storage.ts cannot be called with an unchecked key.
 */
export type ResolvedKey = string & { readonly [resolvedKeyBrand]: true };

/**
 * Raised when a user supplied path is rejected by the path jail. The message is a short,
 * static reason that never contains the root prefix, so it is safe to show to the client.
 */
export class PathOutsideRootError extends Error {
  override readonly name = "PathOutsideRootError";
}

export interface ResolveOptions {
  /** Treat the path as a folder: the resulting key ends with "/" (unless it is the root). */
  dir?: boolean;
}

/** True if the string contains a C0 control (including NUL), DEL, or a C1 control. */
export function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

/**
 * Map a path relative to the workspace root onto a full S3 key under `root`.
 * Implements the rules in PLAN.md section 3 (Lapis 1). The input is never URL-decoded.
 *
 * @param root Validated root prefix (non-empty, ends with "/").
 * @param userPath Path supplied by the client, relative to the root.
 * @throws PathOutsideRootError when the path is not allowed.
 */
export function resolveKey(root: string, userPath: string, opts: ResolveOptions = {}): ResolvedKey {
  // Programming error guard: config.ts validates the root before any tool runs.
  if (root === "" || !root.endsWith("/")) throw new Error("resolveKey: invalid root prefix");

  if (!userPath.isWellFormed() || hasControlChar(userPath)) throw new PathOutsideRootError("invalid character");
  if (userPath.includes("\\")) throw new PathOutsideRootError("backslash not allowed");

  const trimmed = userPath.replace(/^\/+/, "");
  const segments = trimmed === "" ? [] : trimmed.split("/");
  const last = segments.length - 1;

  segments.forEach((segment, i) => {
    if (segment === "." || segment === "..") throw new PathOutsideRootError("relative segment");
    // A single trailing "/" (folder) is allowed; empty segments in the middle are not.
    if (segment === "" && i !== last) throw new PathOutsideRootError("empty segment");
  });

  let key = root + segments.filter(Boolean).join("/");
  if (opts.dir && segments.length > 0 && !key.endsWith("/")) key += "/";

  if (!key.startsWith(root)) throw new PathOutsideRootError("outside root");
  if (Buffer.byteLength(key, "utf8") > S3_MAX_KEY_BYTES) throw new PathOutsideRootError("key too long");
  return key as ResolvedKey;
}

/**
 * Convert a full S3 key back to a path relative to `root`.
 * Returns null for keys outside the root; callers must drop those entries.
 */
export function toRelative(root: string, key: string): string | null {
  return key.startsWith(root) ? key.slice(root.length) : null;
}
