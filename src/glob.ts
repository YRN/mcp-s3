/**
 * Glob matcher with a bounded worst case (PLAN.md section 2, "Glob").
 *
 * Patterns are compiled into a linear NFA that is simulated with bitsets (Shift-And style),
 * so matching a string costs O(length x words) with words = ceil(states / 32) and states
 * capped at MAX_GLOB_STATES. There is no backtracking, so no input can blow up. The cost per
 * character does not depend on caches: non-ASCII characters are looked up in a map of the
 * pattern's literal characters and with a binary search in each distinct character class.
 *
 * Semantics follow picomatch 4.0.7 with { dot: true } (the library this module replaced),
 * including its rules for where "**" means "any number of folders":
 *   *        any run of characters except "/"
 *   ?        exactly one character except "/"
 *   **       a whole path segment that matches any number of segments: "a/**\/b" matches
 *            "a/b" and "a/x/y/b" (never "a/xb"), "**\/b" matches "b" and "x/b" (never "xb"),
 *            and a trailing "/**" also matches the folder itself ("a/**" matches "a", but
 *            "a*\/**" does not match "aa"). Elsewhere "**" behaves like "*" (picomatch's
 *            context rules, e.g. after "{" or ",", are reproduced exactly).
 *   [...]    one character from a set; ranges "a-z", negation "[!...]" or "[^...]".
 *            A negated set never matches "/".
 *   {a,b}    alternatives, nestable up to MAX_GLOB_BRACE_DEPTH levels and at most
 *            MAX_GLOB_ALTERNATIVES alternatives after expansion.
 *   \x       the character x literally (x must be punctuation or non-ASCII).
 * Matching is case-sensitive and dot-files are matched like any other name. A pattern also
 * matches a path that is exactly equal to the pattern text (as in picomatch).
 *
 * A pattern without "/" is matched against the last path segment (file name); a pattern
 * with "/" is matched against the whole path.
 *
 * Rejected with GlobError (they are regex syntax, not glob syntax, in picomatch): extglobs
 * such as "*(...)" or "+(...)", a leading "!" (negation), POSIX classes like "[[:alpha:]]",
 * unescaped "(", ")", "|", or '"', a "+" right after "]", "{" or "}", escapes of ASCII
 * letters and digits ("\d"), three or more backslashes in a row, ranges inside alternatives
 * ("{a,1..3}"), and control characters. A leading "./" is ignored, as in picomatch.
 *
 * Intended differences from picomatch 4.0.7:
 *   - "." and ".." path segments are matched like any other name (picomatch never matches
 *     them with wildcards).
 *   - "?" and "[...]" match one code point; picomatch matches one UTF-16 code unit, so it
 *     needs "??" for an emoji.
 *   - "[!...]" is a negated set; picomatch 4.0.7 treats "!" there as a literal character.
 *   - A group without a comma is just its content: "{a}" is "a", "{1..3}" is the literal
 *     text "1..3" (picomatch keeps the braces literally or expands a range).
 *   - "[...]" only ever matches one character; picomatch also accepts the literal source
 *     text of a simple set (e.g. "x[ab]y" also matches the path "x[ab]y").
 *   - Paths ending in "/" are out of scope (search_objects skips folder markers); picomatch
 *     lets some patterns match one extra trailing "/".
 */

export const MAX_GLOB_PATTERN_LENGTH = 256;
export const MAX_GLOB_ALTERNATIVES = 32;
export const MAX_GLOB_BRACE_DEPTH = 3;
/** Upper bound on NFA states per compiled matcher (sum over alternatives, +1 each). */
export const MAX_GLOB_STATES = 128;

/** Invalid or unsupported pattern. The message is safe to show to the client. */
export class GlobError extends Error {
  override readonly name = "GlobError";
}

export interface GlobMatcher {
  /** True if `path` (relative, "/"-separated) matches the pattern. */
  matches(path: string): boolean;
}

const SLASH = 0x2f;
const DOT = 0x2e;
const BACKSLASH = 0x5c;

/** Characters that "." does not match in a JavaScript regex (picomatch's "**" excludes them). */
function isLineTerminator(cp: number): boolean {
  return cp === 0x0a || cp === 0x0d || cp === 0x2028 || cp === 0x2029;
}

function isAsciiAlphanumeric(cp: number): boolean {
  return (cp >= 0x30 && cp <= 0x39) || (cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a);
}

function readCodePoint(text: string, index: number): { cp: number; next: number } {
  const cp = text.codePointAt(index) ?? 0;
  return { cp, next: index + (cp > 0xffff ? 2 : 1) };
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

interface CharClass {
  negated: boolean;
  /** Inclusive code point ranges. */
  ranges: [number, number][];
}

interface Span {
  start: number;
  end: number;
}

type Lexeme =
  | (Span & { kind: "char"; cp: number })
  | (Span & { kind: "star" })
  | (Span & { kind: "qmark" })
  | (Span & { kind: "class"; cls: CharClass })
  | (Span & { kind: "open" | "comma" | "close" });

// eslint-disable-next-line no-control-regex -- the point is to find control characters
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;
const EXTGLOB_PREFIXES = new Set(["*", "?", "+", "@", "!"]);

/** Read the escape starting at `index` ("\" followed by one code point). */
function readEscape(text: string, index: number, unclosed: string): { cp: number; next: number } {
  if (index + 1 >= text.length) throw new GlobError(unclosed);
  const { cp, next } = readCodePoint(text, index + 1);
  if (isAsciiAlphanumeric(cp)) {
    throw new GlobError("only punctuation and non-ASCII characters can be escaped with '\\' (no \\d, \\w, ...)");
  }
  if (cp === BACKSLASH && text.charCodeAt(next) === BACKSLASH) {
    throw new GlobError("three or more backslashes in a row are not supported");
  }
  return { cp, next };
}

function parseClass(text: string, start: number): { cls: CharClass; next: number } {
  const unclosed = "unclosed '[' in pattern";
  let i = start + 1;
  let negated = false;
  if (text[i] === "!" || text[i] === "^") {
    negated = true;
    i++;
  }
  const ranges: [number, number][] = [];
  let first = true;
  const member = (): number => {
    if (i >= text.length) throw new GlobError(unclosed);
    if (text[i] === "\\") {
      const { cp, next } = readEscape(text, i, unclosed);
      i = next;
      return cp;
    }
    const { cp, next } = readCodePoint(text, i);
    i = next;
    return cp;
  };
  for (;;) {
    if (i >= text.length) throw new GlobError(unclosed);
    if (text[i] === "]" && !first) return { cls: { negated, ranges }, next: i + 1 };
    if (text.startsWith("[:", i)) throw new GlobError("POSIX character classes like [[:alpha:]] are not supported");
    first = false;
    const lo = member();
    let hi = lo;
    if (text[i] === "-" && i + 1 < text.length && text[i + 1] !== "]") {
      i++;
      hi = member();
      if (hi < lo) throw new GlobError("invalid range in '[...]' (start is after end)");
    }
    ranges.push([lo, hi]);
  }
}

/** Split a pattern into lexemes. Validates everything that does not depend on context. */
function lex(pattern: string): Lexeme[] {
  if (CONTROL_CHARACTERS.test(pattern)) throw new GlobError("control characters are not allowed in patterns");
  if (pattern.startsWith("!")) throw new GlobError("negated patterns (leading '!') are not supported");

  const out: Lexeme[] = [];
  const groups: { comma: boolean; dots: boolean }[] = [];
  const pushChar = (cp: number, start: number, end: number): void => {
    const prev = out[out.length - 1];
    const group = groups[groups.length - 1];
    // Inside braces picomatch turns ".." into a range ("{a..c}"); see the "close" case.
    if (cp === DOT && group !== undefined && prev?.kind === "char" && prev.cp === DOT) group.dots = true;
    out.push({ kind: "char", cp, start, end });
  };

  let i = 0;
  while (i < pattern.length) {
    const start = i;
    const ch = pattern.charAt(i);
    if (EXTGLOB_PREFIXES.has(ch) && pattern[i + 1] === "(") {
      throw new GlobError("extglob patterns like *(...) or +(...) are not supported");
    }
    switch (ch) {
      case "\\": {
        const { cp, next } = readEscape(pattern, i, "pattern ends with an unfinished escape '\\'");
        pushChar(cp, start, next);
        i = next;
        break;
      }
      case "*": {
        while (pattern[i] === "*") i++;
        out.push({ kind: "star", start, end: i });
        break;
      }
      case "?":
        out.push({ kind: "qmark", start, end: ++i });
        break;
      case "[": {
        const { cls, next } = parseClass(pattern, i);
        out.push({ kind: "class", cls, start, end: next });
        i = next;
        break;
      }
      case "{":
        if (groups.length >= MAX_GLOB_BRACE_DEPTH) {
          throw new GlobError(`braces are nested more than ${MAX_GLOB_BRACE_DEPTH} levels deep`);
        }
        groups.push({ comma: false, dots: false });
        out.push({ kind: "open", start, end: ++i });
        break;
      case "}": {
        const group = groups.pop();
        if (group === undefined) {
          pushChar(0x7d, start, ++i); // a stray "}" is literal
        } else {
          if (group.comma && group.dots) throw new GlobError("ranges like {1..3} are not supported inside {a,b} alternatives");
          out.push({ kind: "close", start, end: ++i });
        }
        break;
      }
      case ",": {
        const group = groups[groups.length - 1];
        if (group === undefined) {
          pushChar(0x2c, start, ++i); // a "," outside braces is literal
        } else {
          group.comma = true;
          out.push({ kind: "comma", start, end: ++i });
        }
        break;
      }
      case "(":
      case ")":
        throw new GlobError("parentheses must be escaped as '\\(' and '\\)'; use {a,b} for alternatives");
      case "|":
        throw new GlobError("'|' must be escaped as '\\|'; use {a,b} for alternatives");
      case '"':
        throw new GlobError("double quotes must be escaped as '\\\"'");
      case "+": {
        const prev = out[out.length - 1];
        if (prev?.kind === "class" || prev?.kind === "open" || prev?.kind === "close") {
          throw new GlobError("a '+' right after ']', '{' or '}' must be escaped as '\\+'");
        }
        pushChar(0x2b, start, ++i);
        break;
      }
      default: {
        const { cp, next } = readCodePoint(pattern, i);
        pushChar(cp, start, next);
        i = next;
      }
    }
  }
  if (groups.length > 0) throw new GlobError("unclosed '{' in pattern");
  return out;
}

// ---------------------------------------------------------------------------
// Brace expansion
// ---------------------------------------------------------------------------

type Marker = { kind: "open" } | { kind: "comma" } | { kind: "close" };
type Piece<T> = { kind: "atom"; value: T } | Marker;

function tooManyAlternatives(): GlobError {
  return new GlobError(`braces expand to more than ${MAX_GLOB_ALTERNATIVES} alternatives`);
}

/** Expand {a,b} groups (already validated by lex()) into the list of alternatives. */
function expand<T>(pieces: readonly Piece<T>[]): T[][] {
  let pos = 0;
  const parseSequence = (): T[][] => {
    let results: T[][] = [[]];
    while (pos < pieces.length) {
      const piece = pieces[pos];
      if (piece === undefined || piece.kind === "comma" || piece.kind === "close") break;
      pos++;
      if (piece.kind === "atom") {
        for (const r of results) r.push(piece.value);
        continue;
      }
      const options: T[][] = [];
      for (;;) {
        options.push(...parseSequence());
        if (options.length > MAX_GLOB_ALTERNATIVES) throw tooManyAlternatives();
        const separator = pieces[pos];
        pos++;
        if (separator === undefined) throw new GlobError("unclosed '{' in pattern");
        if (separator.kind === "close") break;
      }
      const product: T[][] = [];
      for (const r of results) {
        for (const option of options) {
          product.push([...r, ...option]);
          if (product.length > MAX_GLOB_ALTERNATIVES) throw tooManyAlternatives();
        }
      }
      results = product;
    }
    return results;
  };
  return parseSequence();
}

function isMarker(lexeme: Lexeme): lexeme is Span & Marker {
  return lexeme.kind === "open" || lexeme.kind === "comma" || lexeme.kind === "close";
}

/**
 * Expand `{a,b}` groups into a list of brace-free alternatives. Escapes and bracket
 * expressions are copied verbatim (braces and commas inside them are literal). A group
 * without a comma is just its content ("{a}" is "a").
 */
export function expandBraces(pattern: string): string[] {
  const pieces = lex(pattern).map((lexeme): Piece<string> =>
    isMarker(lexeme) ? { kind: lexeme.kind } : { kind: "atom", value: pattern.slice(lexeme.start, lexeme.end) },
  );
  return expand(pieces).map((parts) => parts.join(""));
}

// ---------------------------------------------------------------------------
// Tokens (picomatch semantics)
// ---------------------------------------------------------------------------

type Token =
  | { kind: "char"; cp: number }
  | { kind: "any" }
  | { kind: "class"; cls: CharClass }
  /** "*". needsChar: picomatch's "(?=.)", the star may only start before a character that is not a line terminator. */
  | { kind: "star"; needsChar: boolean }
  /** any string, also across "/" (but not across line terminators) */
  | { kind: "globstar" }
  /** "/**" at the end: nothing, or "/" followed by any string */
  | { kind: "trailing" }
  /** "/**\/" in the middle: "/" optionally followed by (any string + "/"); or the end of the input if orEnd */
  | { kind: "middle"; orEnd: boolean }
  /** "**\/" at the start: optionally (any string + "/") */
  | { kind: "leading" };

/** Number of NFA states a token uses (the same as the pattern characters it stands for). */
function stateCount(token: Token): number {
  switch (token.kind) {
    case "trailing":
    case "leading":
      return 2;
    case "middle":
      return 3;
    default:
      return 1;
  }
}

/** picomatch token types that its "**" rules look at. */
type PmType = "bos" | "slash" | "text" | "dot" | "dots" | "star" | "globstar" | "qmark" | "bracket" | "brace" | "comma";

/**
 * Turn lexemes into tokens with the same decisions picomatch's parser makes, before braces
 * are expanded (picomatch compiles braces to regex groups, so its rules see the braces).
 * `simple` is picomatch's shortcut for patterns without "/", brackets, braces, quotes, or a
 * leading "*": no star there needs a following character.
 */
function classify(pattern: string, lexemes: readonly Lexeme[], simple: boolean): Piece<Token>[] {
  const items: Piece<Token>[] = [];
  // prev: type of the previous picomatch token; before: the one before it; slashItem: the
  // previous token is a "/" that is still the last item (not one consumed by "/**\/").
  const pm: { prev: PmType; before: PmType | undefined; slashItem: boolean } = {
    prev: "bos",
    before: undefined,
    slashItem: false,
  };
  let depth = 0;
  // A "**" that stays "any string" only if the next token is "/" or "{", "}", "," inside braces.
  let pendingGlobstar = -1;
  // Where the pattern starts for picomatch: it drops leading "./" (also repeated ones).
  let start = 0;

  const push = (type: PmType, slashItem = false): void => {
    if (pendingGlobstar >= 0) {
      const keeps = type === "slash" || ((type === "brace" || type === "comma") && depth > 0);
      if (!keeps) items[pendingGlobstar] = { kind: "atom", value: { kind: "star", needsChar: false } };
      pendingGlobstar = -1;
    }
    pm.before = pm.prev;
    pm.prev = type;
    pm.slashItem = slashItem;
  };
  const emit = (token: Token): void => {
    items.push({ kind: "atom", value: token });
  };

  for (let n = 0; n < lexemes.length; n++) {
    const lexeme = lexemes[n];
    if (lexeme === undefined) break;
    switch (lexeme.kind) {
      case "open":
        depth++;
        push("brace");
        items.push({ kind: "open" });
        break;
      case "close":
        push("brace");
        depth--;
        items.push({ kind: "close" });
        break;
      case "comma":
        push("comma");
        items.push({ kind: "comma" });
        break;
      case "qmark":
        push("qmark");
        emit({ kind: "any" });
        break;
      case "class":
        push("bracket");
        emit({ kind: "class", cls: lexeme.cls });
        break;
      case "char":
        if (lexeme.cp === SLASH && pm.prev === "dot" && lexeme.start === start + 1 && pattern.startsWith("./", start)) {
          items.pop(); // the "."
          start = lexeme.end;
          pm.prev = "bos";
          pm.before = undefined;
          pm.slashItem = false;
          continue;
        }
        if (lexeme.cp === SLASH) {
          push("slash", true);
        } else if (lexeme.cp === DOT && depth > 0 && pm.prev === "dot") {
          pm.prev = "dots"; // picomatch merges it into the previous token
        } else if (lexeme.cp === DOT) {
          push(depth > 0 || pm.prev === "bos" || pm.prev === "slash" ? "dot" : "text");
        } else {
          push("text");
        }
        emit({ kind: "char", cp: lexeme.cp });
        break;
      case "star": {
        const run = lexeme.end - lexeme.start;
        if (run !== 2) {
          // "*", or "***" and longer (picomatch turns those back into "*").
          const needsChar = run === 1 && !simple && (lexeme.start === start || pm.prev === "slash" || pm.prev === "dot");
          push("star");
          emit({ kind: "star", needsChar });
          break;
        }
        const isStart = pm.prev === "slash" || pm.prev === "bos";
        const isBrace = depth > 0 && (pm.prev === "comma" || pm.prev === "brace");
        if (!isStart && !isBrace) {
          push("star");
          emit({ kind: "star", needsChar: false });
          break;
        }
        // "**/**" is "**": skip repeated "/**" that are followed by "/" or the end.
        let end = lexeme.end;
        while (pattern.startsWith("/**", end) && (end + 3 === pattern.length || pattern[end + 3] === "/")) end += 3;
        while ((lexemes[n + 1]?.start ?? Infinity) < end) n++;
        const isEnd = end === pattern.length;
        const afterStar = pm.before === "star" || pm.before === "globstar";
        const afterSlash = pm.prev === "slash" && pm.slashItem && pm.before !== "bos";

        if (pm.prev === "bos" && isEnd) {
          push("globstar");
          emit({ kind: "globstar" });
        } else if (afterSlash && !afterStar && isEnd) {
          items.pop(); // the "/" is part of the construct
          push("globstar");
          emit({ kind: "trailing" });
        } else if (afterSlash && pattern[end] === "/") {
          items.pop();
          push("globstar");
          emit({ kind: "middle", orEnd: end + 1 < pattern.length });
          n++; // the "/" after "**"
          push("slash");
        } else if (pm.prev === "bos" && pattern[end] === "/") {
          push("globstar");
          emit({ kind: "leading" });
          n++;
          push("slash");
        } else {
          push("globstar");
          emit({ kind: "globstar" });
          pendingGlobstar = items.length - 1;
        }
      }
    }
  }
  return items;
}

/** picomatch's REPLACEMENTS and fast paths (parse.fastpaths), which differ slightly from its parser. */
const FAST_PATH_REPLACEMENTS = new Map([
  ["***", "*"],
  ["**/**", "**"],
  ["**/**/**", "**"],
]);
const FAST_PATH = /^(\*\*\/\*\.\*|\*\*\/\.\*|\*\*\/\*|\*\.\*|\*\/\*|\*\*|\.\*|\*)((?:\.\w+)*)$/;

function fastPathTokens(pattern: string): Piece<Token>[] | undefined {
  const replaced = FAST_PATH_REPLACEMENTS.get(pattern) ?? pattern;
  const match = FAST_PATH.exec(replaced.startsWith("./") ? replaced.slice(2) : replaced);
  if (match === null) return undefined;
  const star = (needsChar: boolean): Token => ({ kind: "star", needsChar });
  const char = (cp: number): Token => ({ kind: "char", cp });
  const bases: Record<string, Token[]> = {
    "*": [star(true)],
    ".*": [char(DOT), star(true)],
    "*.*": [star(false), char(DOT), star(true)],
    "*/*": [star(false), char(SLASH), star(true)],
    "**": [{ kind: "globstar" }],
    "**/*": [{ kind: "leading" }, star(true)],
    "**/*.*": [{ kind: "leading" }, star(false), char(DOT), star(true)],
    "**/.*": [{ kind: "leading" }, char(DOT), star(true)],
  };
  const base = bases[match[1] ?? ""];
  if (base === undefined) return undefined;
  const tokens = [...base];
  for (const ch of match[2] ?? "") tokens.push(char(ch.charCodeAt(0)));
  return tokens.map((value) => ({ kind: "atom", value }));
}

// ---------------------------------------------------------------------------
// Bitset NFA
// ---------------------------------------------------------------------------

type Bits = Int32Array;

function setBit(bits: Bits, state: number): void {
  const word = state >>> 5;
  bits[word] = (bits[word] ?? 0) | (1 << (state & 31));
}

function orInto(target: Bits, source: Bits): void {
  for (let w = 0; w < target.length; w++) target[w] = (target[w] ?? 0) | (source[w] ?? 0);
}

function inRanges(cls: CharClass, cp: number): boolean {
  return cls.ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
}

function classMatches(cls: CharClass, cp: number): boolean {
  // Like picomatch, a negated set never matches "/"; a positive set matches it if listed.
  return cls.negated ? cp !== SLASH && !inRanges(cls, cp) : inRanges(cls, cp);
}

/** A distinct character class with its ranges sorted and merged, for a binary search. */
interface ClassLookup {
  negated: boolean;
  lo: Int32Array;
  hi: Int32Array;
  states: Bits;
}

function classKey(cls: CharClass): string {
  return `${cls.negated ? "!" : ""}${cls.ranges.map(([lo, hi]) => `${String(lo)}-${String(hi)}`).join(",")}`;
}

function mergedRanges(cls: CharClass): { lo: Int32Array; hi: Int32Array } {
  const sorted = [...cls.ranges].sort((a, b) => a[0] - b[0]);
  const lo: number[] = [];
  const hi: number[] = [];
  for (const [l, h] of sorted) {
    const last = hi.length - 1;
    if (last >= 0 && l <= (hi[last] ?? 0) + 1) hi[last] = Math.max(hi[last] ?? 0, h);
    else {
      lo.push(l);
      hi.push(h);
    }
  }
  return { lo: Int32Array.from(lo), hi: Int32Array.from(hi) };
}

function inMergedRanges(lo: Int32Array, hi: Int32Array, cp: number): boolean {
  let left = 0;
  let right = lo.length - 1;
  while (left <= right) {
    const mid = (left + right) >>> 1;
    if (cp < (lo[mid] ?? 0)) right = mid - 1;
    else if (cp > (hi[mid] ?? 0)) left = mid + 1;
    else return true;
  }
  return false;
}

/**
 * Linear NFA for a list of alternatives laid out side by side. Alternative k with tokens
 * owns states base..base+m (m = sum of stateCount), base+m accepts.
 *
 * Per state: an optional single-character test (advance to the next state), self loops
 * ("*" on everything but "/", "**" on everything but line terminators), and forward epsilon
 * edges. "/**\/" is "/" (state s) followed by either the state after the construct (s+3,
 * taken on the same "/") or a loop (s+1) that must end with another "/" (s+2), so the loop
 * can never skip the second "/". A star that needs a following character may only be
 * entered when the next input character exists and is not a line terminator.
 */
class BitsetNfa {
  private readonly words: number;
  private readonly start: Bits;
  private readonly accept: Bits;
  /** epsilon s -> s+1 ("*" and "**" may match nothing) */
  private readonly eps1: Bits;
  /** epsilon s -> s+2 (a trailing "/**" may match nothing) */
  private readonly eps2: Bits;
  /** epsilon s -> s+3 at the end of the input only ("/**\/" may match the end) */
  private readonly endEps3: Bits;
  /** on "/", also s -> s+3 ("/**\/" matching a single "/") */
  private readonly slashSkip3: Bits;
  /** stars that may only be entered before a character that is not a line terminator */
  private readonly notGate: Bits;
  private readonly loopSlash: Bits;
  private readonly loopOther: Bits;
  private readonly loopLineTerminator: Bits;
  /** advance masks for code points 0..127, `words` entries per code point */
  private readonly asciiAdvance: Bits;
  /** "?" states (any non-ASCII character advances them) */
  private readonly anyStates: Bits;
  /** non-ASCII literal characters, deduplicated across alternatives */
  private readonly charStates = new Map<number, Bits>();
  /** distinct character classes, deduplicated across alternatives */
  private readonly classes: ClassLookup[] = [];
  private readonly hasEpsilon: boolean;
  private readonly hasEndEpsilon: boolean;
  private readonly hasSlashSkip: boolean;
  private readonly scratch: Bits;
  private readonly cur: Bits;
  private readonly next: Bits;

  constructor(alternatives: readonly Token[][]) {
    const states = alternatives.reduce((sum, tokens) => sum + tokens.reduce((s, t) => s + stateCount(t), 0) + 1, 0);
    this.words = Math.max(1, Math.ceil(states / 32));
    const make = (): Bits => new Int32Array(this.words);
    this.start = make();
    this.accept = make();
    this.eps1 = make();
    this.eps2 = make();
    this.endEps3 = make();
    this.slashSkip3 = make();
    const gate = make();
    this.loopSlash = make();
    this.loopOther = make();
    this.loopLineTerminator = make();
    this.anyStates = make();
    this.scratch = make();
    this.cur = make();
    this.next = make();

    const charStates = new Map<number, number[]>();
    const classStates = new Map<string, { cls: CharClass; states: number[] }>();
    const addChar = (state: number, cp: number): void => {
      const list = charStates.get(cp);
      if (list === undefined) charStates.set(cp, [state]);
      else list.push(state);
    };
    const addGlobstar = (state: number): void => {
      setBit(this.eps1, state);
      setBit(this.loopOther, state);
      setBit(this.loopSlash, state);
    };

    let base = 0;
    for (const tokens of alternatives) {
      setBit(this.start, base);
      let s = base;
      for (const token of tokens) {
        switch (token.kind) {
          case "char":
            addChar(s, token.cp);
            break;
          case "any":
            setBit(this.anyStates, s);
            break;
          case "class": {
            const key = classKey(token.cls);
            const entry = classStates.get(key);
            if (entry === undefined) classStates.set(key, { cls: token.cls, states: [s] });
            else entry.states.push(s);
            break;
          }
          case "star":
            setBit(this.eps1, s);
            setBit(this.loopOther, s);
            setBit(this.loopLineTerminator, s);
            if (token.needsChar) setBit(gate, s);
            break;
          case "globstar":
            addGlobstar(s);
            break;
          case "trailing":
            addChar(s, SLASH);
            setBit(this.eps2, s);
            addGlobstar(s + 1);
            break;
          case "middle":
            addChar(s, SLASH);
            setBit(this.slashSkip3, s);
            if (token.orEnd) setBit(this.endEps3, s);
            addGlobstar(s + 1);
            addChar(s + 2, SLASH);
            break;
          case "leading":
            // Always the first token: the state after the construct is a start state too.
            addGlobstar(s);
            addChar(s + 1, SLASH);
            setBit(this.start, s + 2);
            break;
        }
        s += stateCount(token);
      }
      setBit(this.accept, s);
      base = s + 1;
    }
    this.notGate = gate.map((w) => ~w);

    // ASCII: one precomputed mask per code point.
    this.asciiAdvance = new Int32Array(128 * this.words);
    const setAscii = (cp: number, state: number): void => {
      const word = cp * this.words + (state >>> 5);
      this.asciiAdvance[word] = (this.asciiAdvance[word] ?? 0) | (1 << (state & 31));
    };
    for (const [cp, list] of charStates) {
      if (cp < 128) {
        for (const state of list) setAscii(cp, state);
      } else {
        const mask = make();
        for (const state of list) setBit(mask, state);
        this.charStates.set(cp, mask);
      }
    }
    for (let cp = 0; cp < 128; cp++) {
      if (cp === SLASH) continue;
      for (let w = 0; w < this.words; w++) {
        const index = cp * this.words + w;
        this.asciiAdvance[index] = (this.asciiAdvance[index] ?? 0) | (this.anyStates[w] ?? 0);
      }
    }
    for (const { cls, states: list } of classStates.values()) {
      for (let cp = 0; cp < 128; cp++) {
        if (classMatches(cls, cp)) for (const state of list) setAscii(cp, state);
      }
      const mask = make();
      for (const state of list) setBit(mask, state);
      this.classes.push({ negated: cls.negated, ...mergedRanges(cls), states: mask });
    }

    this.hasEpsilon = this.eps1.some((w) => w !== 0) || this.eps2.some((w) => w !== 0);
    this.hasEndEpsilon = this.endEps3.some((w) => w !== 0);
    this.hasSlashSkip = this.slashSkip3.some((w) => w !== 0);
  }

  /** Advance mask for a non-ASCII code point (never "/"). Constant work, no cache. */
  private otherMask(cp: number): Bits {
    const mask = this.scratch;
    mask.set(this.anyStates);
    if (this.charStates.size > 0) {
      const exact = this.charStates.get(cp);
      if (exact !== undefined) orInto(mask, exact);
    }
    for (const cls of this.classes) {
      if (inMergedRanges(cls.lo, cls.hi, cp) !== cls.negated) orInto(mask, cls.states);
    }
    return mask;
  }

  /**
   * Add every state reachable through epsilon edges (all edges point forward). `ok`: the
   * next input character exists and is not a line terminator; `atEnd`: no input is left.
   */
  private closure(bits: Bits, ok: boolean, atEnd: boolean): void {
    const words = this.words;
    const eps1 = this.eps1;
    const eps2 = this.eps2;
    const endEps3 = this.endEps3;
    const notGate = this.notGate;
    for (;;) {
      let changed = false;
      let carry1 = 0;
      let carry2 = 0;
      let carry3 = 0;
      for (let w = 0; w < words; w++) {
        const value = bits[w] ?? 0;
        const x1 = value & (eps1[w] ?? 0);
        const x2 = value & (eps2[w] ?? 0);
        const x3 = atEnd ? value & (endEps3[w] ?? 0) : 0;
        let added = (x1 << 1) | carry1 | (x2 << 2) | carry2 | (x3 << 3) | carry3;
        carry1 = x1 >>> 31;
        carry2 = x2 >>> 30;
        carry3 = x3 >>> 29;
        if (!ok) added &= notGate[w] ?? -1;
        const updated = value | added;
        if (updated !== value) {
          bits[w] = updated;
          changed = true;
        }
      }
      if (!changed) return;
    }
  }

  matches(text: string): boolean {
    const n = text.length;
    const words = this.words;
    const notGate = this.notGate;
    let cur = this.cur;
    let next = this.next;

    let nextCp = n > 0 ? (text.codePointAt(0) ?? 0) : -1;
    let ok = n > 0 && !isLineTerminator(nextCp);
    for (let w = 0; w < words; w++) cur[w] = ok ? (this.start[w] ?? 0) : (this.start[w] ?? 0) & (notGate[w] ?? -1);
    this.closure(cur, ok, n === 0);

    let i = 0;
    while (i < n) {
      const cp = nextCp;
      i += cp > 0xffff ? 2 : 1;
      const atEnd = i >= n;
      nextCp = atEnd ? -1 : (text.codePointAt(i) ?? 0);
      ok = !atEnd && !isLineTerminator(nextCp);

      const table = cp < 128 ? this.asciiAdvance : this.otherMask(cp);
      const offset = cp < 128 ? cp * words : 0;
      const loop = cp === SLASH ? this.loopSlash : isLineTerminator(cp) ? this.loopLineTerminator : this.loopOther;
      let carry = 0;
      let alive = 0;
      for (let w = 0; w < words; w++) {
        const value = cur[w] ?? 0;
        const moved = value & (table[offset + w] ?? 0);
        let entered = (moved << 1) | carry;
        carry = moved >>> 31;
        if (!ok) entered &= notGate[w] ?? -1;
        const updated = entered | (value & (loop[w] ?? 0));
        next[w] = updated;
        alive |= updated;
      }
      if (cp === SLASH && this.hasSlashSkip) {
        let carry3 = 0;
        for (let w = 0; w < words; w++) {
          const x = (cur[w] ?? 0) & (this.slashSkip3[w] ?? 0);
          let added = (x << 3) | carry3;
          carry3 = x >>> 29;
          if (!ok) added &= notGate[w] ?? -1;
          next[w] = (next[w] ?? 0) | added;
          alive |= added;
        }
      }
      if (alive === 0) return false;
      if (this.hasEpsilon || (atEnd && this.hasEndEpsilon)) this.closure(next, ok, atEnd);
      const swap = cur;
      cur = next;
      next = swap;
    }

    for (let w = 0; w < words; w++) {
      if (((cur[w] ?? 0) & (this.accept[w] ?? 0)) !== 0) return true;
    }
    return false;
  }
}

/** picomatch's shortcut for patterns that need no parsing (see classify()). */
const NEEDS_FULL_PARSE = /(^[*!]|[/()[\]{}"])/;

/**
 * Compile a glob pattern. Throws GlobError for invalid, unsupported, or too complex
 * patterns. The returned matcher is not reentrant (it reuses internal buffers).
 */
export function compileGlob(pattern: string): GlobMatcher {
  if (pattern.length === 0) throw new GlobError("pattern must not be empty");
  if (pattern.length > MAX_GLOB_PATTERN_LENGTH) {
    throw new GlobError(`pattern must be at most ${MAX_GLOB_PATTERN_LENGTH} characters`);
  }

  const pieces = fastPathTokens(pattern) ?? classify(pattern, lex(pattern), !NEEDS_FULL_PARSE.test(pattern));
  const alternatives = expand(pieces);

  const states = alternatives.reduce((sum, tokens) => sum + tokens.reduce((s, t) => s + stateCount(t), 0) + 1, 0);
  if (states > MAX_GLOB_STATES) {
    throw new GlobError(`pattern is too complex (more than ${MAX_GLOB_STATES - 1} characters after brace expansion)`);
  }

  const nfa = new BitsetNfa(alternatives);
  const byPath = pattern.includes("/");
  return {
    matches(path: string): boolean {
      const subject = byPath ? path : path.slice(path.lastIndexOf("/") + 1);
      if (subject.length === 0) return false;
      return subject === pattern || nfa.matches(subject);
    },
  };
}
