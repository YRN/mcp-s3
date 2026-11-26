import { describe, expect, it } from "vitest";

import { PathOutsideRootError, resolveKey, toRelative } from "../../src/paths.js";

const ROOT = "claude-workspace/";
const ROOT_BYTES = Buffer.byteLength(ROOT, "utf8");

function rejection(path: string, opts?: { dir?: boolean }): PathOutsideRootError {
  try {
    resolveKey(ROOT, path, opts);
  } catch (err) {
    if (err instanceof PathOutsideRootError) return err;
    throw new Error(`expected PathOutsideRootError for ${JSON.stringify(path)}, got ${String(err)}`, { cause: err });
  }
  throw new Error(`expected ${JSON.stringify(path)} to be rejected, but it resolved`);
}

describe("resolveKey: PLAN.md section 10 table (ROOT_PREFIX=claude-workspace/)", () => {
  it.each([
    ["", "claude-workspace/"],
    ["reports/q1.csv", "claude-workspace/reports/q1.csv"],
    ["/reports/q1.csv", "claude-workspace/reports/q1.csv"],
    ["%2e%2e/x", "claude-workspace/%2e%2e/x"],
  ])("accepts %j as %j", (input, expected) => {
    expect(resolveKey(ROOT, input)).toBe(expected);
  });

  it.each([
    ["../secret.txt", "relative segment"],
    ["a/../../b", "relative segment"],
    ["./a.txt", "relative segment"],
    ["a\\..\\b", "backslash not allowed"],
    ["a//b", "empty segment"],
    ["a\x00b", "invalid character"],
  ])("rejects %j (%s)", (input, reason) => {
    const err = rejection(input);
    expect(err.message).toBe(reason);
  });

  it("rejects a key longer than 1024 UTF-8 bytes", () => {
    const tooLong = "a".repeat(1024 - ROOT_BYTES + 1);
    expect(rejection(tooLong).message).toBe("key too long");
  });
});

describe("resolveKey: traversal and relative segments", () => {
  it.each([
    "..",
    "../",
    "/..",
    "/../outside/secret.txt",
    "a/..",
    "a/../b",
    ".",
    "./",
    "a/.",
    "a/./b",
    "sub/../../claude-workspace-backup/leak.txt",
    "../claude-workspace-backup/leak.txt",
  ])("rejects %j", (input) => {
    expect(rejection(input).message).toBe("relative segment");
  });

  it.each([
    "a\\b",
    "\\",
    "..\\outside\\secret.txt",
    "a/b\\",
  ])("rejects backslash in %j", (input) => {
    expect(rejection(input).message).toBe("backslash not allowed");
  });

  it.each([
    "a//b",
    "a///b",
    "a//",
    "sub//b.txt",
    "....//x",
  ])("rejects empty segment in %j", (input) => {
    expect(rejection(input).message).toBe("empty segment");
  });

  it("rejects relative segments even with the dir option", () => {
    expect(rejection("../", { dir: true }).message).toBe("relative segment");
    expect(rejection("a/../", { dir: true }).message).toBe("relative segment");
  });
});

describe("resolveKey: control and invalid characters", () => {
  it.each([
    ["NUL", "a\x00b"],
    ["NUL at end", "a.txt\x00"],
    ["tab", "a\tb"],
    ["newline", "a\nb"],
    ["carriage return", "a\rb"],
    ["unit separator 0x1f", "a\x1fb"],
    ["DEL 0x7f", "a\x7fb"],
    ["C1 control 0x85 (NEL)", "a\u0085b"],
    ["C1 control 0x9f", "a\u009fb"],
    ["lone high surrogate", "a\uD800b"],
    ["lone low surrogate", "a\uDC00b"],
  ])("rejects %s", (_name, input) => {
    expect(rejection(input).message).toBe("invalid character");
  });

  it("checks control characters before anything else, even when combined with traversal", () => {
    expect(rejection("../\x00").message).toBe("invalid character");
  });
});

describe("resolveKey: literal handling (no decoding, no normalisation)", () => {
  it.each([
    ["%2E%2E/x", "claude-workspace/%2E%2E/x"],
    ["..%2f..%2fx", "claude-workspace/..%2f..%2fx"],
    ["%2e%2e%2fsecret.txt", "claude-workspace/%2e%2e%2fsecret.txt"],
    ["a%5c..%5cb", "claude-workspace/a%5c..%5cb"],
    ["...", "claude-workspace/..."],
    [".hidden", "claude-workspace/.hidden"],
    ["..foo/bar..", "claude-workspace/..foo/bar.."],
    ["a.b/c..d", "claude-workspace/a.b/c..d"],
  ])("keeps %j literal", (input, expected) => {
    expect(resolveKey(ROOT, input)).toBe(expected);
  });

  it("does not normalise fullwidth dots (U+FF0E) into a traversal", () => {
    expect(resolveKey(ROOT, "．．/x")).toBe("claude-workspace/．．/x");
  });

  it("strips every leading slash, treating absolute paths as relative to the root", () => {
    expect(resolveKey(ROOT, "/")).toBe(ROOT);
    expect(resolveKey(ROOT, "//")).toBe(ROOT);
    expect(resolveKey(ROOT, "///a.txt")).toBe("claude-workspace/a.txt");
    expect(resolveKey(ROOT, "/claude-workspace/a.txt")).toBe("claude-workspace/claude-workspace/a.txt");
  });
});

describe("resolveKey: unicode and spaces", () => {
  it.each([
    ["laporan/ringkasan-é.txt", "claude-workspace/laporan/ringkasan-é.txt"],
    ["日本語/ファイル.txt", "claude-workspace/日本語/ファイル.txt"],
    ["emoji/😀.md", "claude-workspace/emoji/😀.md"],
    ["Ünïcödé/naïve café.txt", "claude-workspace/Ünïcödé/naïve café.txt"],
  ])("accepts unicode path %j", (input, expected) => {
    expect(resolveKey(ROOT, input)).toBe(expected);
  });

  it("keeps NFC and NFD forms distinct (no unicode normalisation)", () => {
    const nfc = "café.txt";
    const nfd = "café.txt";
    expect(resolveKey(ROOT, nfc)).toBe(ROOT + nfc);
    expect(resolveKey(ROOT, nfd)).toBe(ROOT + nfd);
    expect(resolveKey(ROOT, nfc)).not.toBe(resolveKey(ROOT, nfd));
  });

  it.each([
    ["my folder/file name.txt", "claude-workspace/my folder/file name.txt"],
    [" leading.txt", "claude-workspace/ leading.txt"],
    ["trailing.txt ", "claude-workspace/trailing.txt "],
    ["a /b", "claude-workspace/a /b"],
    [" ", "claude-workspace/ "],
  ])("keeps spaces in %j", (input, expected) => {
    expect(resolveKey(ROOT, input)).toBe(expected);
  });

  it("counts multi-byte characters in UTF-8 bytes for the 1024-byte limit", () => {
    // "é" is 2 bytes in UTF-8.
    const budget = 1024 - ROOT_BYTES;
    const okEven = "é".repeat(Math.floor(budget / 2)) + "a".repeat(budget % 2);
    expect(Buffer.byteLength(ROOT + okEven, "utf8")).toBe(1024);
    expect(resolveKey(ROOT, okEven)).toBe(ROOT + okEven);

    const tooLong = "é".repeat(Math.floor(budget / 2) + 1);
    expect(tooLong.length).toBeLessThan(1024);
    expect(rejection(tooLong).message).toBe("key too long");

    // "😀" is 4 bytes in UTF-8 (2 UTF-16 code units).
    const emoji = "😀".repeat(Math.floor(budget / 4) + 1);
    expect(rejection(emoji).message).toBe("key too long");
  });
});

describe("resolveKey: key length boundary", () => {
  it("accepts a key of exactly 1024 bytes", () => {
    const path = "a".repeat(1024 - ROOT_BYTES);
    const key = resolveKey(ROOT, path);
    expect(Buffer.byteLength(key, "utf8")).toBe(1024);
  });

  it("rejects 1025 bytes", () => {
    expect(rejection("a".repeat(1025 - ROOT_BYTES)).message).toBe("key too long");
  });

  it("applies the limit after adding the trailing slash for dir=true", () => {
    const path = "a".repeat(1024 - ROOT_BYTES);
    expect(rejection(path, { dir: true }).message).toBe("key too long");
    expect(resolveKey(ROOT, path.slice(1), { dir: true })).toBe(`${ROOT}${path.slice(1)}/`);
  });
});

describe("resolveKey: trailing slash and the dir option", () => {
  it.each([
    ["reports/", "claude-workspace/reports"],
    ["a/b/", "claude-workspace/a/b"],
  ])("without dir, %j resolves to %j", (input, expected) => {
    expect(resolveKey(ROOT, input)).toBe(expected);
  });

  it.each([
    ["", "claude-workspace/"],
    ["/", "claude-workspace/"],
    ["reports", "claude-workspace/reports/"],
    ["reports/", "claude-workspace/reports/"],
    ["/reports", "claude-workspace/reports/"],
    ["a/b", "claude-workspace/a/b/"],
    ["a/b/", "claude-workspace/a/b/"],
  ])("with dir, %j resolves to %j", (input, expected) => {
    expect(resolveKey(ROOT, input, { dir: true })).toBe(expected);
  });

  it("never produces a double slash for the root with dir=true", () => {
    expect(resolveKey(ROOT, "", { dir: true })).not.toContain("//");
    expect(resolveKey(ROOT, "/", { dir: true })).not.toContain("//");
  });
});

describe("resolveKey: invariants", () => {
  const accepted = [
    "",
    "a.txt",
    "sub/b.txt",
    "/x/y/z",
    "%2e%2e/x",
    "日本語/ファイル.txt",
    "my folder/file name.txt",
    "reports/",
  ];

  it.each(accepted)("result for %j always starts with the root prefix", (input) => {
    expect(resolveKey(ROOT, input).startsWith(ROOT)).toBe(true);
    expect(resolveKey(ROOT, input, { dir: true }).startsWith(ROOT)).toBe(true);
  });

  it("works with a nested root prefix", () => {
    const root = "team/claude-workspace/";
    expect(resolveKey(root, "a.txt")).toBe("team/claude-workspace/a.txt");
    expect(resolveKey(root, "")).toBe(root);
    expect(() => resolveKey(root, "../x")).toThrow(PathOutsideRootError);
  });

  it("rejection messages never contain the root prefix or the input", () => {
    for (const input of ["../secret.txt", "a//b", "a\\b", "a\x00b", "x".repeat(2000)]) {
      const err = rejection(input);
      expect(err).toBeInstanceOf(Error);
      expect(err.message).not.toContain("claude-workspace");
      expect(err.message).not.toContain(input);
    }
  });

  it("refuses to work with an invalid root (programming error, not a jail bypass)", () => {
    expect(() => resolveKey("", "a.txt")).toThrow();
    expect(() => resolveKey("claude-workspace", "a.txt")).toThrow();
  });
});

describe("toRelative", () => {
  it.each([
    ["claude-workspace/a.txt", "a.txt"],
    ["claude-workspace/sub/b.txt", "sub/b.txt"],
    ["claude-workspace/sub/", "sub/"],
    ["claude-workspace/", ""],
    ["claude-workspace/日本語/ファイル.txt", "日本語/ファイル.txt"],
    ["claude-workspace/my folder/file name.txt", "my folder/file name.txt"],
  ])("maps %j to %j", (key, expected) => {
    expect(toRelative(ROOT, key)).toBe(expected);
  });

  it.each([
    "claude-workspace-backup/leak.txt",
    "claude-workspace-backup/",
    "claude-workspace",
    "claude-workspacex/a.txt",
    "outside/secret.txt",
    "xclaude-workspace/a.txt",
    "/claude-workspace/a.txt",
    "CLAUDE-WORKSPACE/a.txt",
    "",
  ])("returns null for %j (outside the root, must be dropped)", (key) => {
    expect(toRelative(ROOT, key)).toBeNull();
  });

  it.each(["a.txt", "sub/b.txt", "%2e%2e/x", "日本語/ファイル.txt", ""])(
    "round-trips resolveKey(%j)",
    (path) => {
      expect(toRelative(ROOT, resolveKey(ROOT, path))).toBe(path);
    },
  );

  it("round-trips folder keys produced with dir=true", () => {
    expect(toRelative(ROOT, resolveKey(ROOT, "sub", { dir: true }))).toBe("sub/");
  });
});
