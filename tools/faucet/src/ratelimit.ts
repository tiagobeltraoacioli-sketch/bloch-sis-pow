// SPDX-License-Identifier: MIT OR Apache-2.0
// In-memory rate limiting for the faucet: one drip per address per window, plus
// a per-IP request cap. State is process-local (not durable across restarts);
// a production deployment would back this with a shared store. Documented in
// README as a known limitation.

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
}

export class RateLimiter {
  private readonly lastByAddress = new Map<string, number>();
  private readonly ipHits = new Map<string, number[]>();

  constructor(
    private readonly perAddressWindowMs: number,
    private readonly perIpWindowMs: number,
    private readonly perIpMax: number,
  ) {}

  check(address: string, ip: string, now = Date.now()): RateLimitDecision {
    // Per-address cooldown.
    const last = this.lastByAddress.get(address);
    if (last !== undefined) {
      const elapsed = now - last;
      if (elapsed < this.perAddressWindowMs) {
        return {
          allowed: false,
          reason: "this address already received a drip recently",
          retryAfterMs: this.perAddressWindowMs - elapsed,
        };
      }
    }

    // Per-IP sliding window.
    const hits = (this.ipHits.get(ip) ?? []).filter((t) => now - t < this.perIpWindowMs);
    if (hits.length >= this.perIpMax) {
      const oldest = Math.min(...hits);
      return {
        allowed: false,
        reason: "too many requests from this IP",
        retryAfterMs: this.perIpWindowMs - (now - oldest),
      };
    }

    return { allowed: true };
  }

  /** Record a successful drip. Call only after the payment actually went out. */
  record(address: string, ip: string, now = Date.now()): void {
    this.lastByAddress.set(address, now);
    const hits = (this.ipHits.get(ip) ?? []).filter((t) => now - t < this.perIpWindowMs);
    hits.push(now);
    this.ipHits.set(ip, hits);
  }
}
