/** Shared test fixtures (unit, integration, and e2e). */

export const ROOT_PREFIX = "claude-workspace/";

/** Content of keys outside the root. It must never appear in any tool response. */
export const SECRET_CONTENT = "TOP-SECRET-OUTSIDE-CONTENT";
export const LEAK_CONTENT = "LEAKED-BACKUP-CONTENT";

/** A real 1x1 PNG. */
export const PNG_1X1 = Uint8Array.from(
  Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    "base64",
  ),
);

/** A real 1x1 GIF89a. */
export const GIF_1X1 = Uint8Array.from(
  Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64"),
);

/** Minimal JPEG header bytes (SOI + APP0 JFIF). */
export const JPEG_HEAD = Uint8Array.from([
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0xff, 0xd9,
]);

/** Minimal WebP container header bytes (RIFF....WEBPVP8 ). */
export const WEBP_HEAD = Uint8Array.from([
  0x52, 0x49, 0x46, 0x46, 0x1a, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50, 0x38, 0x20, 0x0e, 0x00, 0x00, 0x00,
  0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x34, 0x25,
]);

/** PNG signature followed by padding, to build an image of arbitrary size. */
export function pngOfSize(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  bytes.set(PNG_1X1.subarray(0, Math.min(size, PNG_1X1.length)));
  return bytes;
}
