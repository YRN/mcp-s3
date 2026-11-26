import { performance } from "node:perf_hooks";

import picomatch from "picomatch";
import { describe, expect, it } from "vitest";

import {
  compileGlob,
  expandBraces,
  GlobError,
  MAX_GLOB_ALTERNATIVES,
  MAX_GLOB_PATTERN_LENGTH,
  MAX_GLOB_STATES,
} from "../../src/glob.js";

function matches(pattern: string, path: string): boolean {
  return compileGlob(pattern).matches(path);
}

function globError(pattern: string): GlobError {
  try {
    compileGlob(pattern);
  } catch (err) {
    if (err instanceof GlobError) return err;
    throw new Error(`expected GlobError for ${JSON.stringify(pattern)}, got ${String(err)}`, { cause: err });
  }
  throw new Error(`expected ${JSON.stringify(pattern)} to be rejected`);
}

/** [pattern, path, expected] */
type Case = [string, string, boolean];

describe("glob semantics", () => {
  const cases: Case[] = [
    // A pattern without "/" matches the file name in every subfolder.
    ["*.txt", "a.txt", true],
    ["*.txt", "sub/b.txt", true],
    ["*.txt", "x/y/z/deep.txt", true],
    ["*.txt", "a.txt.bak", false],
    ["*.txt", "txt", false],
    ["*.txt", "sub.txt/file", false],
    // A pattern with "/" matches the whole relative path; "*" stays within one segment.
    ["sub/*.txt", "sub/a.txt", true],
    ["sub/*.txt", "sub/x/a.txt", false],
    ["sub/*.txt", "other/sub/a.txt", false],
    ["*/b.txt", "sub/b.txt", true],
    ["*/b.txt", "a/sub/b.txt", false],
    // "**" as a whole segment spans any number of segments, including zero.
    ["a/**/b", "a/b", true],
    ["a/**/b", "a/x/b", true],
    ["a/**/b", "a/x/y/b", true],
    ["a/**/b", "a/xb", false],
    ["a/**/b", "ab", false],
    ["a/**/b", "b", false],
    ["a/**/b", "x/a/b", false],
    ["**/x", "x", true],
    ["**/x", "a/x", true],
    ["**/x", "a/b/x", true],
    ["**/x", "a/bx", false],
    ["**/x", "bx", false],
    ["**/x", "a/b/cx", false],
    ["a/**/b", "a/x/yb", false],
    ["a/**/b.txt", "a/foob.txt", false],
    ["docs/**/secret", "docs/notsecret", false],
    // Reviewer findings: "**" must never consume part of a segment.
    ["**/report.csv", "myreport.csv", false],
    ["**/report.csv", "a/myreport.csv", false],
    ["**/report.csv", "report.csv", true],
    ["**/report.csv", "a/b/report.csv", true],
    ["**/b", "xb", false],
    ["**/b", "x/b", true],
    ["x/**/y/**/z", "x/qy/z", false],
    ["x/**/y/**/z", "x/y/qz", false],
    ["x/**/y/**/z", "x/y/z", true],
    ["x/**/y/**/z", "x/a/y/b/c/z", true],
    ["a*/**", "aa", false],
    ["a*/**", "aa/x", true],
    // A trailing "/**" also matches the folder name itself, as in picomatch 4.0.7.
    ["reports/**", "reports", true],
    ["a/**", "a", true],
    ["reports/**", "reportsx", false],
    ["reports/**", "reports/x", true],
    ["reports/**", "reports/x/y.csv", true],
    ["a/**", "a/x", true],
    ["a/**", "a/x/y", true],
    ["a/**", "b/x", false],
    ["**/*.csv", "2024/q1/r.csv", true],
    ["**/*.csv", "r.csv", true],
    // Braces.
    ["*.{csv,tsv}", "a.csv", true],
    ["*.{csv,tsv}", "d/a.tsv", true],
    ["*.{csv,tsv}", "a.psv", false],
    ["{a,b}/*.txt", "b/x.txt", true],
    ["{a,b}/*.txt", "c/x.txt", false],
    ["{a,{b,{c,d}}}", "d", true],
    // Character classes.
    ["[!a]*", "b.txt", true],
    ["[!a]*", "a.txt", false],
    ["[!a]*", "x/a.txt", false],
    ["[^a]*", "b.txt", true],
    ["[abc].txt", "b.txt", true],
    ["[abc].txt", "d.txt", false],
    ["[a-c]x", "bx", true],
    ["[a-c]x", "dx", false],
    ["[]]", "]", true],
    ["[]]", "a", false],
    ["[]a]", "a", true],
    // Escapes.
    ["\\*", "*", true],
    ["\\*", "a", false],
    ["\\?", "?", true],
    ["\\?", "a", false],
    ["\\[a]", "[a]", true],
    ["\\{a,b\\}", "{a,b}", true],
    ["\\{a,b\\}", "a", false],
    // Dot-files are matched like any other name.
    ["*", ".env", true],
    ["*.txt", ".hidden.txt", true],
    [".*", ".env", true],
    ["**/*", ".git/config", true],
    // "?" is exactly one character (code point), never "/".
    ["?", "😀", true],
    ["??", "😀", false],
    ["?.txt", "😀.txt", true],
    ["?.txt", "ab.txt", false],
    ["x/a?b", "x/a/b", false],
    ["?", "é", true],
    // Case-sensitive.
    ["*.TXT", "a.txt", false],
    ["*.txt", "A.TXT", false],
    ["A*", "abc", false],
    ["A*", "Abc", true],
    // Unicode literals.
    ["日本語/*.txt", "日本語/ファイル.txt", true],
    ["*😀*", "a😀b", true],
    ["[😀]", "😀", true],
    // Literal text that looks special elsewhere.
    ["a}", "a}", true],
    ["a,b", "a,b", true],
    ["%2e%2e", "%2e%2e", true],
  ];

  it.each(cases)("%j against %j is %s", (pattern, path, expected) => {
    expect(matches(pattern, path)).toBe(expected);
  });

  it("{1..3} is not a numeric range", () => {
    for (const n of ["1", "2", "3"]) expect(matches("{1..3}", n)).toBe(false);
    // Per glob.ts, "{a}" is just "a": a single-option group is its content.
    expect(matches("{1..3}", "1..3")).toBe(true);
  });

  it("character classes never match '/'", () => {
    expect(matches("x/a[!b]c", "x/a/c")).toBe(false);
    expect(matches("x/a[^b]c", "x/a/c")).toBe(false);
  });
});

describe("expandBraces", () => {
  it.each([
    ["a{b,c}d", ["abd", "acd"]],
    ["{a,b}{c,d}", ["ac", "ad", "bc", "bd"]],
    ["{a}", ["a"]],
    ["no braces", ["no braces"]],
    ["[{]x", ["[{]x"]],
    ["\\{a,b\\}", ["\\{a,b\\}"]],
    ["{a,{b,c}}", ["a", "b", "c"]],
  ])("expands %j", (pattern, expected) => {
    expect(expandBraces(pattern)).toEqual(expected);
  });

  it(`allows exactly ${MAX_GLOB_ALTERNATIVES} alternatives`, () => {
    const pattern = `{${Array.from({ length: MAX_GLOB_ALTERNATIVES }, (_, i) => `a${String(i)}`).join(",")}}`;
    expect(expandBraces(pattern)).toHaveLength(MAX_GLOB_ALTERNATIVES);
    expect(() => compileGlob(pattern)).not.toThrow();
  });
});

describe("invalid and unsupported patterns", () => {
  const tooManyAlternatives = `{${Array.from({ length: MAX_GLOB_ALTERNATIVES + 1 }, (_, i) => `a${String(i)}`).join(",")}}`;

  it.each([
    ["extglob *(...)", "*(a*)*(a*)*(a*)b"],
    ["extglob +(...)", "+(x)"],
    ["extglob ?(...)", "?(x)"],
    ["extglob @(...)", "@(x)"],
    ["extglob !(...)", "!(x)"],
    ["negation", "!*.txt"],
    ["POSIX class", "[[:alpha:]]"],
    ["unclosed class", "[a"],
    ["unclosed brace", "{a,b"],
    ["dangling escape", "a\\"],
    ["reversed range", "[z-a]"],
    ["braces nested 4 deep", "{{{{a}}}}"],
    ["33 alternatives", tooManyAlternatives],
    ["6 x 6 = 36 alternatives", "{a,b,c,d,e,f}{1,2,3,4,5,6}"],
    ["empty", ""],
    ["longer than the maximum", "a".repeat(MAX_GLOB_PATTERN_LENGTH + 1)],
  ])("rejects %s", (_name, pattern) => {
    const err = globError(pattern);
    expect(err.message.length).toBeGreaterThan(0);
  });

  it("GlobError messages do not echo the pattern", () => {
    for (const pattern of ["*(secretpattern)", "[secretpattern", "{secretpattern"]) {
      expect(globError(pattern).message).not.toContain("secretpattern");
    }
  });
});

describe(`complexity limit (MAX_GLOB_STATES = ${MAX_GLOB_STATES})`, () => {
  // One NFA state per token plus one accepting state per alternative. glob.ts documents the
  // limit as "more than MAX_GLOB_STATES - 1 characters after brace expansion" being rejected.
  it(`a single literal alternative of ${MAX_GLOB_STATES - 1} characters is accepted`, () => {
    expect(() => compileGlob("a".repeat(MAX_GLOB_STATES - 1))).not.toThrow();
    expect(matches("a".repeat(MAX_GLOB_STATES - 1), "a".repeat(MAX_GLOB_STATES - 1))).toBe(true);
  });

  it(`a single literal alternative of ${MAX_GLOB_STATES} characters is rejected`, () => {
    expect(globError("a".repeat(MAX_GLOB_STATES)).message).toMatch(/too complex/);
  });

  it("states are summed over all alternatives", () => {
    const half = MAX_GLOB_STATES / 2 - 1; // two alternatives of `half` tokens = MAX_GLOB_STATES states
    expect(() => compileGlob(`{${"a".repeat(half)},${"b".repeat(half)}}`)).not.toThrow();
    expect(globError(`{${"a".repeat(half + 1)},${"b".repeat(half)}}`).message).toMatch(/too complex/);
    // Brace expansion multiplies: 32 alternatives of 4 tokens = 160 states.
    expect(globError(`{a,b,c,d,e,f,g,h}{1,2,3,4}xy`).message).toMatch(/too complex/);
  });
});

describe("no catastrophic backtracking (ReDoS)", () => {
  const evil = "*?*?*?*?*?*?*?*?*?*.zip";

  it.each([45, 1000])(`${evil} against a %i-character name finishes quickly`, (length) => {
    const matcher = compileGlob(evil);
    for (const name of ["a".repeat(length), `${"a".repeat(length - 4)}.zap`, `${"a".repeat(length - 4)}.zip`]) {
      const started = performance.now();
      const result = matcher.matches(name);
      const elapsed = performance.now() - started;
      expect(result).toBe(name.endsWith(".zip"));
      expect(elapsed).toBeLessThan(50);
    }
  });

  it.each([
    "*a*a*a*a*a*a*a*a*a*a*b",
    "**/**/**/**/**/**/**/x",
    "{*a*a*a*b,*a*a*a*c,*a*a*a*d}",
    "[a]*[a]*[a]*[a]*[a]*[a]*[a]*[a]*b",
  ])("%s against long adversarial inputs stays fast", (pattern) => {
    const matcher = compileGlob(pattern);
    const inputs = ["a".repeat(1000), "a/".repeat(500), `${"a/".repeat(300)}${"a".repeat(400)}`];
    const started = performance.now();
    for (const input of inputs) matcher.matches(input);
    expect(performance.now() - started).toBeLessThan(150);
  });
});

// ---------------------------------------------------------------------------
// Differential test against picomatch 4.0.7 as the oracle.
// ---------------------------------------------------------------------------

/** mulberry32: small deterministic PRNG so the generated cases are the same on every run. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Pattern pieces for one segment. Deliberately excluded (intended differences, see glob.ts):
 * "[!...]" (picomatch 4.0.7 does not treat it as negation), "." / ".." names, and
 * characters outside the BMP ("?" is one code point here, one UTF-16 unit in picomatch).
 */
const SEGMENT_ATOMS = [
  "a", "b", "x", "y", "z", "ab", "qy", "report", "report.csv", "reports", ".hidden",
  "*", "?", "*.csv", "a*", "*b", "?b", "a?", "*a*", "[ab]", "[a-c]", "[^a]*", "[ab]*",
  "{a,b}", "{report,b}.csv", "a{b,c}", "{x,y}*", "*.{csv,txt}", "a**b", "\\*",
];
const LITERALS = ["a", "b", "x", "y", "z", "report.csv", "reports"];

const PATH_SEGMENTS = [
  "a", "b", "x", "y", "z", "aa", "ab", "ba", "xb", "qy", "qz", "c", "report", "report.csv", "myreport.csv",
  "reports", "notreports", "reportsx", "a.csv", "b.txt", "x.csv", ".hidden", ".csv", "abc", "*", "a-b", "é",
];

function pick<T>(rand: () => number, items: readonly T[]): T {
  const item = items[Math.floor(rand() * items.length)];
  if (item === undefined) throw new Error("empty list");
  return item;
}

function generatePattern(rand: () => number): string {
  const shape = Math.floor(rand() * 8);
  const seg = () => pick(rand, SEGMENT_ATOMS);
  const lit = () => pick(rand, LITERALS);
  switch (shape) {
    case 0:
      return seg(); // single segment: basename rule
    case 1:
      return `**/${lit()}`; // "**/" followed by a literal
    case 2:
      return `**/${seg()}`;
    case 3:
      return `${seg()}/**`; // "/**" at the end
    case 4:
      return `${seg()}/**/${seg()}`; // "**" in the middle
    case 5:
      return `${seg()}/${seg()}`;
    case 6:
      return `${lit()}/**/${lit()}/**/${seg()}`;
    default:
      return `${seg()}/${seg()}/${seg()}`;
  }
}

function generatePath(rand: () => number): string {
  const depth = 1 + Math.floor(rand() * 4);
  return Array.from({ length: depth }, () => pick(rand, PATH_SEGMENTS)).join("/");
}

const PM_OPTIONS = { dot: true, windows: false } as const;

/** picomatch with the server's rule: a pattern without "/" matches the file name only. */
function oracle(pattern: string): (path: string) => boolean {
  const isMatch = picomatch(pattern, PM_OPTIONS);
  if (pattern.includes("/")) return isMatch;
  return (path) => isMatch(path.slice(path.lastIndexOf("/") + 1));
}

describe("differential test against picomatch 4.0.7", () => {
  const rand = prng(0x5eed1234);
  const patterns = [...new Set(Array.from({ length: 700 }, () => generatePattern(rand)))];
  const paths = [...new Set(Array.from({ length: 90 }, () => generatePath(rand)))];
  // Hand-picked paths that end with a pattern literal, so "**" over-matching shows up.
  paths.push("myreport.csv", "a/myreport.csv", "xb", "x/qy/z", "aa", "reports", "x/xb", "a/xb", "a/x/yb");

  it("generates a meaningful amount of cases", () => {
    expect(patterns.length).toBeGreaterThan(300);
    expect(paths.length).toBeGreaterThan(60);
    expect(patterns.length * paths.length).toBeGreaterThan(20_000);
    expect(patterns.some((p) => p.startsWith("**/"))).toBe(true);
    expect(patterns.some((p) => p.endsWith("/**"))).toBe(true);
    expect(patterns.some((p) => p.includes("/**/"))).toBe(true);
  });

  it("agrees with picomatch on every generated pattern/path pair", () => {
    const started = performance.now();
    const mismatches: string[] = [];
    let checked = 0;
    let positives = 0;
    for (const pattern of patterns) {
      const ours = compileGlob(pattern);
      const expected = oracle(pattern);
      for (const path of paths) {
        const want = expected(path);
        const got = ours.matches(path);
        checked++;
        if (want) positives++;
        if (want !== got) mismatches.push(`${JSON.stringify(pattern)} vs ${JSON.stringify(path)}: picomatch ${String(want)}, ours ${String(got)}`);
      }
    }
    const elapsed = performance.now() - started;

    expect(process.env.GLOB_DIFF_ALL === "1" ? mismatches : mismatches.slice(0, 25), `${String(mismatches.length)} mismatches out of ${String(checked)} checks`).toEqual([]);
    expect(checked).toBeGreaterThan(20_000);
    expect(positives).toBeGreaterThan(500); // not just "everything is false"
    expect(elapsed).toBeLessThan(5000);
  });
});
