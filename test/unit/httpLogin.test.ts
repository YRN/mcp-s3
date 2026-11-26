import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  CredentialChecker,
  escapeHtml,
  LOGIN_MAX_FAILURES_PER_IP,
  LOGIN_MAX_FAILURES_TOTAL,
  LOGIN_WINDOW_SECONDS,
  LoginRateLimiter,
  readCookie,
  renderLoginPage,
  renderMessagePage,
} from "../../src/http/login.js";
import { Secret } from "../../src/secret.js";

describe("escapeHtml", () => {
  it("escapes & < > \" ' and `", () => {
    expect(escapeHtml("&")).toBe("&amp;");
    expect(escapeHtml("<")).toBe("&lt;");
    expect(escapeHtml(">")).toBe("&gt;");
    expect(escapeHtml('"')).toBe("&quot;");
    expect(escapeHtml("'")).toBe("&#39;");
    expect(escapeHtml("`")).toBe("&#96;");
  });

  it("escapes a script tag and an attribute breakout", () => {
    expect(escapeHtml("<script>alert(1)</script>")).toBe("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(escapeHtml('" onfocus="alert(1)')).toBe("&quot; onfocus=&quot;alert(1)");
    expect(escapeHtml("' onfocus='x")).toBe("&#39; onfocus=&#39;x");
  });

  it("does not double-escape in a way that reopens markup, and escapes ampersands first", () => {
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
    expect(escapeHtml("&amp;")).toBe("&amp;amp;");
  });

  it("leaves safe text, unicode, and the empty string alone", () => {
    expect(escapeHtml("")).toBe("");
    expect(escapeHtml("plain text 123 - _ .")).toBe("plain text 123 - _ .");
    expect(escapeHtml("héllo 日本語 🙂")).toBe("héllo 日本語 🙂");
  });

  it("the output never contains a raw special character", () => {
    const out = escapeHtml("<>&\"'`<>&\"'`");
    expect(out).not.toMatch(/[<>"'`]/);
  });
});

describe("login page rendering", () => {
  const view = {
    sealedRequest: 'abc"><script>1</script>',
    csrf: "csrf-value",
    clientName: "<img src=x onerror=alert(1)>",
    redirectUri: "https://claude.ai/api/mcp/auth_callback",
  };

  it("escapes the client name, the request, and the username; never has a password value", () => {
    const html = renderLoginPage({ ...view, error: "bad <b>", username: '"><script>x</script>' });
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toMatch(/name="password" type="password"/);
    expect(html).not.toMatch(/name="password"[^>]*value=/);
  });

  it("shows the origin of the redirect target, not the whole URL", () => {
    const html = renderLoginPage({ ...view, redirectUri: "https://claude.ai/api/mcp/auth_callback?x=1" });
    expect(html).toContain("https://claude.ai");
    expect(html).not.toContain("auth_callback");
  });

  it("falls back to a neutral name for an unnamed client", () => {
    expect(renderLoginPage({ ...view, clientName: undefined })).toContain("An unnamed client");
  });

  it("renderMessagePage escapes title and message", () => {
    const html = renderMessagePage("<t>", "<m>");
    expect(html).not.toContain("<t>");
    expect(html).not.toContain("<m>");
    expect(html).toContain("&lt;t&gt;");
  });
});

describe("readCookie", () => {
  it("finds a cookie among several", () => {
    expect(readCookie("a=1; b=2;  c=3", "b")).toBe("2");
    expect(readCookie("a=1; b=2", "c")).toBeUndefined();
    expect(readCookie(undefined, "a")).toBeUndefined();
    expect(readCookie("novalue; a=1", "a")).toBe("1");
  });
});

describe("CredentialChecker", () => {
  const checker = new CredentialChecker(new Secret("admin"), new Secret("correct-horse-battery"));

  it("accepts the right pair only", () => {
    expect(checker.check("admin", "correct-horse-battery")).toBe(true);
    expect(checker.check("admin", "wrong-password-123")).toBe(false);
    expect(checker.check("root", "correct-horse-battery")).toBe(false);
    expect(checker.check("root", "wrong")).toBe(false);
  });

  it("is case sensitive and exact (no trimming)", () => {
    expect(checker.check("Admin", "correct-horse-battery")).toBe(false);
    expect(checker.check("admin", "Correct-horse-battery")).toBe(false);
    expect(checker.check("admin ", "correct-horse-battery")).toBe(false);
    expect(checker.check("admin", " correct-horse-battery")).toBe(false);
  });

  it("handles inputs of different length without throwing", () => {
    expect(checker.check("", "")).toBe(false);
    expect(checker.check("a", "c")).toBe(false);
    expect(checker.check("admin", "correct-horse-batter")).toBe(false); // one shorter
    expect(checker.check("admin", "correct-horse-batteryy")).toBe(false); // one longer
    expect(checker.check("x".repeat(100_000), "y".repeat(100_000))).toBe(false);
    expect(checker.check("admin\u0000", "correct-horse-battery")).toBe(false);
  });

  it("handles unicode credentials", () => {
    const uni = new CredentialChecker(new Secret("ädmin"), new Secret("pässwörd-日本語-🙂"));
    expect(uni.check("ädmin", "pässwörd-日本語-🙂")).toBe(true);
    expect(uni.check("admin", "pässwörd-日本語-🙂")).toBe(false);
    expect(uni.check("ädmin", "passwörd-日本語-🙂")).toBe(false);
  });

  it("empty configured values only match empty input", () => {
    const empty = new CredentialChecker(new Secret(""), new Secret(""));
    expect(empty.check("", "")).toBe(true);
    expect(empty.check("a", "")).toBe(false);
  });
});

describe("LoginRateLimiter", () => {
  const START = Date.UTC(2026, 0, 1, 12, 0, 0);

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("uses the documented limits", () => {
    expect(LOGIN_MAX_FAILURES_PER_IP).toBe(5);
    expect(LOGIN_MAX_FAILURES_TOTAL).toBe(100);
    expect(LOGIN_WINDOW_SECONDS).toBe(15 * 60);
  });

  it("allows 4 failures and blocks after the 5th failure of one IP", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 4; i++) {
      expect(limiter.retryAfter("1.1.1.1")).toBe(0);
      limiter.recordFailure("1.1.1.1");
    }
    expect(limiter.retryAfter("1.1.1.1")).toBe(0);
    limiter.recordFailure("1.1.1.1");
    expect(limiter.retryAfter("1.1.1.1")).toBe(15 * 60);
  });

  it("does not block other IPs because of one", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 5; i++) limiter.recordFailure("1.1.1.1");
    expect(limiter.retryAfter("1.1.1.1")).toBeGreaterThan(0);
    expect(limiter.retryAfter("2.2.2.2")).toBe(0);
  });

  it("Retry-After counts down and rounds up to whole seconds", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 5; i++) limiter.recordFailure("1.1.1.1");
    vi.advanceTimersByTime(60_000);
    expect(limiter.retryAfter("1.1.1.1")).toBe(14 * 60);
    vi.advanceTimersByTime(500);
    expect(limiter.retryAfter("1.1.1.1")).toBe(840); // 839.5 s left, rounded up
  });

  it("the block ends exactly when the 15 minute window ends", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 5; i++) limiter.recordFailure("1.1.1.1");
    vi.advanceTimersByTime(15 * 60 * 1000 - 1);
    expect(limiter.retryAfter("1.1.1.1")).toBe(1);
    vi.advanceTimersByTime(1);
    expect(limiter.retryAfter("1.1.1.1")).toBe(0);
  });

  it("starts a fresh window after the old one expired", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 4; i++) limiter.recordFailure("1.1.1.1");
    vi.advanceTimersByTime(15 * 60 * 1000);
    limiter.recordFailure("1.1.1.1"); // counts as the first failure of a new window
    expect(limiter.retryAfter("1.1.1.1")).toBe(0);
    for (let i = 0; i < 3; i++) limiter.recordFailure("1.1.1.1");
    expect(limiter.retryAfter("1.1.1.1")).toBe(0);
    limiter.recordFailure("1.1.1.1");
    expect(limiter.retryAfter("1.1.1.1")).toBeGreaterThan(0);
  });

  it("a success clears the IP's counter", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 4; i++) limiter.recordFailure("1.1.1.1");
    limiter.recordSuccess("1.1.1.1");
    for (let i = 0; i < 4; i++) limiter.recordFailure("1.1.1.1");
    expect(limiter.retryAfter("1.1.1.1")).toBe(0);
  });

  it("blocks every IP once 100 failures happened in total, but not at 99", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 99; i++) limiter.recordFailure(`10.0.0.${String(i)}`);
    expect(limiter.retryAfter("203.0.113.9")).toBe(0);
    limiter.recordFailure("10.0.1.1");
    expect(limiter.retryAfter("203.0.113.9")).toBe(15 * 60);
    expect(limiter.retryAfter("10.0.0.0")).toBe(15 * 60);
  });

  it("the total block outlasts a success of one IP and ends with the window", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 0; i < 100; i++) limiter.recordFailure(`10.0.0.${String(i)}`);
    limiter.recordSuccess("10.0.0.1");
    expect(limiter.retryAfter("10.0.0.1")).toBeGreaterThan(0);
    vi.advanceTimersByTime(15 * 60 * 1000);
    expect(limiter.retryAfter("10.0.0.1")).toBe(0);
    expect(limiter.retryAfter("203.0.113.9")).toBe(0);
  });

  it("accepts an injected clock", () => {
    let now = 1_000_000;
    const limiter = new LoginRateLimiter(() => now);
    for (let i = 0; i < 5; i++) limiter.recordFailure("a");
    expect(limiter.retryAfter("a")).toBe(900);
    now += 900_000;
    expect(limiter.retryAfter("a")).toBe(0);
  });
});
