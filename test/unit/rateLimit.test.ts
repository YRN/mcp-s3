import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LOGIN_MAX_FAILURES_PER_IP, LoginRateLimiter } from "../../src/http/login.js";
import { FailureRateLimiter, rateLimitKey } from "../../src/http/rateLimit.js";
import { displayName } from "../../src/http/oauth.js";

describe("rateLimitKey", () => {
  it("keeps IPv4 addresses", () => {
    expect(rateLimitKey("192.0.2.1")).toBe("192.0.2.1");
    expect(rateLimitKey("10.0.0.255")).toBe("10.0.0.255");
  });

  it.each([
    ["::ffff:192.0.2.1"],
    ["::ffff:c000:201"],
    ["::FFFF:C000:0201"],
    ["0:0:0:0:0:ffff:c000:201"],
    ["0:0:0:0:0:ffff:192.0.2.1"],
    ["[::ffff:192.0.2.1]"],
  ])("maps the IPv4-mapped form %s to its IPv4 address", (address) => {
    expect(rateLimitKey(address)).toBe("192.0.2.1");
  });

  it("maps IPv6 addresses to their /64", () => {
    expect(rateLimitKey("2001:db8:1:2:3:4:5:6")).toBe("2001:db8:1:2::/64");
    expect(rateLimitKey("2001:db8:1:2:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    expect(rateLimitKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(rateLimitKey("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8:0:0::/64");
    expect(rateLimitKey("::1")).toBe("0:0:0:0::/64");
    expect(rateLimitKey("::")).toBe("0:0:0:0::/64");
  });

  it("different /64 prefixes get different keys", () => {
    expect(rateLimitKey("2001:db8:1:2::1")).not.toBe(rateLimitKey("2001:db8:1:3::1"));
    expect(rateLimitKey("2001:db8:1:2::1")).not.toBe(rateLimitKey("2001:db9:1:2::1"));
  });

  it("ignores a zone id and brackets", () => {
    expect(rateLimitKey("fe80::1%eth0")).toBe("fe80:0:0:0::/64");
    expect(rateLimitKey("fe80::1%eth0")).toBe(rateLimitKey("fe80::2%wlan0"));
    expect(rateLimitKey("[2001:db8::1]")).toBe("2001:db8:0:0::/64");
  });

  it("drops a port written next to the address, so each source port shares one key", () => {
    expect(rateLimitKey("192.0.2.1:5678")).toBe("192.0.2.1");
    expect(rateLimitKey("192.0.2.1:5678")).toBe(rateLimitKey("192.0.2.1:443"));
    expect(rateLimitKey("[2001:db8::1]:443")).toBe("2001:db8:0:0::/64");
    expect(rateLimitKey("[::ffff:192.0.2.1]:80")).toBe("192.0.2.1");
    expect(rateLimitKey("1.2.3:80")).toBe("1.2.3:80");
    expect(rateLimitKey("[unknown]:80")).toBe("[unknown]:80");
  });

  it.each(["unknown", "", "not-an-ip", "1.2.3", "1.2.3.4.5", "999.1.1.1", "2001:db8::zzzz", "1:2:3:4:5:6:7:8:9", "[unknown]"])(
    "returns non-IP value %j as is",
    (value) => {
      expect(rateLimitKey(value)).toBe(value);
    },
  );
});

describe("LoginRateLimiter uses rateLimitKey", () => {
  const START = Date.UTC(2026, 0, 1, 12, 0, 0);
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("addresses of one /64 share one counter, other /64s are unaffected", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 1; i <= LOGIN_MAX_FAILURES_PER_IP; i++) limiter.recordFailure(`2001:db8:1:2::${i.toString(16)}`);
    expect(limiter.retryAfter("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBeGreaterThan(0);
    expect(limiter.retryAfter("2001:db8:1:3::1")).toBe(0);
    expect(limiter.retryAfter("192.0.2.1")).toBe(0);
  });

  it("100 distinct addresses from one /64 count as one IP (per-IP limit reached, total far from 100 per window)", () => {
    const limiter = new LoginRateLimiter();
    let blockedAfter = 0;
    for (let i = 0; i < 100; i++) {
      if (limiter.retryAfter(`2001:db8:1:2::${i.toString(16)}`) > 0) break;
      limiter.recordFailure(`2001:db8:1:2::${i.toString(16)}`);
      blockedAfter++;
    }
    expect(blockedAfter).toBe(LOGIN_MAX_FAILURES_PER_IP);
    expect(limiter.retryAfter("2001:db8:1:2::ffff")).toBeGreaterThan(0);
    expect(limiter.retryAfter("203.0.113.9")).toBe(0);
  });

  it("an IPv4 address and its IPv4-mapped forms share one counter", () => {
    const limiter = new LoginRateLimiter();
    limiter.recordFailure("192.0.2.1");
    limiter.recordFailure("::ffff:192.0.2.1");
    limiter.recordFailure("::ffff:c000:201");
    limiter.recordFailure("192.0.2.1");
    expect(limiter.retryAfter("192.0.2.1")).toBe(0);
    limiter.recordFailure("::ffff:192.0.2.1");
    expect(limiter.retryAfter("192.0.2.1")).toBeGreaterThan(0);
    expect(limiter.retryAfter("::ffff:c000:201")).toBeGreaterThan(0);
  });

  it("a success clears the whole /64's counter", () => {
    const limiter = new LoginRateLimiter();
    for (let i = 1; i <= 4; i++) limiter.recordFailure(`2001:db8:1:2::${String(i)}`);
    limiter.recordSuccess("2001:db8:1:2::99");
    limiter.recordFailure("2001:db8:1:2::5");
    expect(limiter.retryAfter("2001:db8:1:2::5")).toBe(0);
  });
});

describe("FailureRateLimiter", () => {
  it("without a total limit only the per-key limit applies", () => {
    let now = 1_000_000;
    const limiter = new FailureRateLimiter({ perKey: 2, windowSeconds: 60 }, () => now);
    for (let i = 0; i < 500; i++) limiter.recordFailure(`10.0.${String(i >> 8)}.${String(i & 255)}`);
    expect(limiter.retryAfter("10.9.9.9")).toBe(0);
    limiter.recordFailure("10.9.9.9");
    limiter.recordFailure("10.9.9.9");
    expect(limiter.retryAfter("10.9.9.9")).toBe(60);
    now += 60_000;
    expect(limiter.retryAfter("10.9.9.9")).toBe(0);
  });

  it("stays bounded under many distinct keys", () => {
    const limiter = new FailureRateLimiter({ perKey: 1, windowSeconds: 60 }, () => 1);
    for (let i = 0; i < 12_000; i++) limiter.recordFailure(`${String(i)}.example`);
    // The newest key is still tracked, the oldest was dropped.
    expect(limiter.retryAfter("11999.example")).toBeGreaterThan(0);
    expect(limiter.retryAfter("0.example")).toBe(0);
  });
});

describe("displayName", () => {
  it("removes control, format (Cf), and line/paragraph separator characters", () => {
    expect(displayName("a‮b")).toBe("ab"); // right-to-left override (Cf)
    expect(displayName("a​b")).toBe("ab"); // zero width space (Cf)
    expect(displayName("a⁦b⁩c")).toBe("abc"); // isolates (Cf)
    expect(displayName("a﻿b")).toBe("ab"); // BOM / zero width no-break space (Cf)
    expect(displayName("a­b")).toBe("ab"); // soft hyphen (Cf)
    expect(displayName("a b")).toBe("ab"); // line separator (Zl)
    expect(displayName("a b")).toBe("ab"); // paragraph separator (Zp)
    expect(displayName("a\u0007b\nc")).toBe("abc");
  });

  it("keeps ordinary text, unicode letters, and emoji", () => {
    expect(displayName("Claude")).toBe("Claude");
    expect(displayName("日本語 クライアント")).toBe("日本語 クライアント");
    expect(displayName("My app 🙂")).toBe("My app 🙂");
  });

  it("returns undefined when nothing visible is left", () => {
    expect(displayName("‮​")).toBeUndefined();
    expect(displayName("   ")).toBeUndefined();
    expect(displayName(undefined)).toBeUndefined();
  });

  it("truncates at 100 UTF-16 units without splitting surrogate pairs", () => {
    expect(displayName("x".repeat(300))).toHaveLength(100);
    const out = displayName("🙂".repeat(100)) ?? "";
    expect(out.length).toBeLessThanOrEqual(100);
    expect(out.isWellFormed()).toBe(true);
  });
});
