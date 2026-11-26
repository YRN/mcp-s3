import { isIPv4, isIPv6 } from "node:net";

/**
 * In-memory, fixed-window limits on failed attempts (logins, client authentication), per
 * client and optionally in total. Reset on restart.
 */

const MAX_TRACKED_KEYS = 10_000;

/** The eight 16-bit groups of an IPv6 address, or undefined if it cannot be parsed. */
function ipv6Groups(address: string): number[] | undefined {
  let value = address;
  const zone = value.indexOf("%");
  if (zone >= 0) value = value.slice(0, zone);

  // Embedded IPv4 in the last 32 bits (e.g. ::ffff:192.0.2.1).
  const lastColon = value.lastIndexOf(":");
  const tail = value.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (!isIPv4(tail)) return undefined;
    const [a = 0, b = 0, c = 0, d = 0] = tail.split(".").map(Number);
    value = `${value.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  const halves = value.split("::");
  if (halves.length > 2) return undefined;
  const parse = (part: string | undefined): number[] =>
    part === undefined || part === "" ? [] : part.split(":").map((group) => Number.parseInt(group, 16));
  const head = parse(halves[0]);
  const rest = parse(halves[1]);
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined;
  const groups = [...head, ...Array<number>(halves.length === 1 ? 0 : missing).fill(0), ...rest];
  return groups.every((group) => Number.isInteger(group) && group >= 0 && group <= 0xffff) ? groups : undefined;
}

/**
 * Key under which a client address is rate limited:
 * - IPv4 and IPv4-mapped IPv6 (::ffff:a.b.c.d): the IPv4 address,
 * - other IPv6: the /64 prefix, because one host usually controls a whole /64,
 * - anything else: the value as is.
 * A port written next to the address (`192.0.2.1:5678`, `[2001:db8::1]:443`), as some proxies do
 * in X-Forwarded-For, is dropped first, so each source port does not get its own counter.
 */
export function rateLimitKey(address: string): string {
  if (isIPv4(address)) return address;
  const v4WithPort = /^([0-9.]+):\d{1,5}$/.exec(address);
  if (v4WithPort?.[1] !== undefined && isIPv4(v4WithPort[1])) return v4WithPort[1];
  const v6WithPort = /^\[([^\]]+)\]:\d{1,5}$/.exec(address);
  const bracketed = v6WithPort?.[1] !== undefined ? `[${v6WithPort[1]}]` : address;
  const bare = bracketed.startsWith("[") && bracketed.endsWith("]") ? bracketed.slice(1, -1) : bracketed;
  if (!isIPv6(bare)) return address;
  const groups = ipv6Groups(bare);
  if (groups === undefined) return address;
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    const high = groups[6] ?? 0;
    const low = groups[7] ?? 0;
    return `${String(high >> 8)}.${String(high & 0xff)}.${String(low >> 8)}.${String(low & 0xff)}`;
  }
  return `${groups.slice(0, 4).map((group) => group.toString(16)).join(":")}::/64`;
}

interface Window {
  count: number;
  resetAt: number;
}

export interface FailureLimits {
  /** Failures allowed per client key per window. */
  perKey: number;
  /** Failures allowed from all clients together per window; undefined for no total limit. */
  total?: number | undefined;
  windowSeconds: number;
}

/**
 * Fixed-window failure counter. Client addresses are mapped with rateLimitKey(). When the
 * per-key table is full, expired entries are dropped first, then the oldest ones (the total
 * limit, if any, still covers them).
 */
export class FailureRateLimiter {
  private readonly perKey = new Map<string, Window>();
  private total: Window = { count: 0, resetAt: 0 };
  private readonly limits: FailureLimits;
  private readonly now: () => number;

  constructor(limits: FailureLimits, now: () => number = () => Date.now()) {
    this.limits = limits;
    this.now = now;
  }

  /** Seconds until `address` may try again, or 0 if it may try now. */
  retryAfter(address: string): number {
    const now = this.now();
    const blockedFor = (window: Window | undefined, max: number | undefined): number =>
      max !== undefined && window !== undefined && window.resetAt > now && window.count >= max
        ? Math.ceil((window.resetAt - now) / 1000)
        : 0;
    return Math.max(
      blockedFor(this.perKey.get(rateLimitKey(address)), this.limits.perKey),
      blockedFor(this.total, this.limits.total),
    );
  }

  recordFailure(address: string): void {
    const now = this.now();
    const resetAt = now + this.limits.windowSeconds * 1000;
    if (this.limits.total !== undefined) {
      if (this.total.resetAt <= now) this.total = { count: 0, resetAt };
      this.total.count++;
    }

    const key = rateLimitKey(address);
    let window = this.perKey.get(key);
    if (window === undefined || window.resetAt <= now) {
      this.prune(now);
      window = { count: 0, resetAt };
      this.perKey.set(key, window);
    }
    window.count++;
  }

  /** Forget the failures of `address` (not of the total). */
  recordSuccess(address: string): void {
    this.perKey.delete(rateLimitKey(address));
  }

  private prune(now: number): void {
    if (this.perKey.size < MAX_TRACKED_KEYS) return;
    for (const [key, window] of this.perKey) {
      if (window.resetAt <= now) this.perKey.delete(key);
    }
    while (this.perKey.size >= MAX_TRACKED_KEYS) {
      const oldest = this.perKey.keys().next();
      if (oldest.done === true) break;
      this.perKey.delete(oldest.value);
    }
  }
}
