// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Rate limiting and drain protection for the faucet.
//
// This guards an endpoint that hands out money to anonymous strangers, so it is
// written against a motivated third party rather than against accidental
// double-clicks. Three earlier defects are designed out here, each of which
// made the previous limiter decorative:
//
//   1. CHECK-THEN-ACT WAS NOT ATOMIC. The old code checked the quota, then
//      awaited a payment, then recorded the hit. Every request that arrived
//      inside that await window saw an un-recorded quota and passed. Measured:
//      47 of 100 concurrent requests for ONE address all paid out. The fix is
//      that `reserve()` both decides and records in one synchronous step —
//      Node's single-threaded event loop cannot interleave inside it — and the
//      caller settles the reservation afterwards.
//
//   2. FAILURES WERE FREE. Only successful drips were recorded, so any request
//      that failed downstream cost the caller nothing and the faucet a node
//      round trip and possibly a spawned signer process. Here the per-IP hit is
//      taken at reserve time and is NEVER given back, so the IP budget bounds
//      WORK DONE, not merely money paid. The per-address cooldown is different:
//      it is released on failure, because a user whose drip failed for our
//      reasons must not be locked out for a day.
//
//   3. KEYS WERE NOT NORMALISED. Bloch addresses are checksum-case-insensitive,
//      so one address has ~2^40 spellings, each of which used to open a fresh
//      24 h quota. Every key is lowercased here, and callers are expected to
//      pass the canonical form as well — belt and braces, because this is the
//      cheapest bypass in the whole service.
//
// State is process-local. That is a real limitation with a real consequence —
// a restart clears every cooldown — and it is stated in the README and in the
// operator runbook rather than hidden. It is acceptable only because the coins
// are worthless; it would not be acceptable for anything else.

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
  /** Opaque handle to settle. Present only when `allowed`. */
  ticket?: Reservation;
}

export interface Reservation {
  readonly address: string;
  readonly amountSats: number;
  readonly at: number;
  settled: boolean;
}

/** Normalised limiter key. Addresses are case-insensitive; IPs are not. */
function addrKey(address: string): string {
  return address.trim().toLowerCase();
}

export class RateLimiter {
  /** address -> timestamp of the drip that currently holds the cooldown. */
  private readonly lastByAddress = new Map<string, number>();
  /** ip -> timestamps of requests admitted (successful or not). */
  private readonly ipHits = new Map<string, number[]>();
  /** Rolling ledger of amounts committed or in flight, for the global cap. */
  private spend: Array<{ at: number; sats: number }> = [];

  constructor(
    private readonly perAddressWindowMs: number,
    private readonly perIpWindowMs: number,
    private readonly perIpMax: number,
    /** Rolling ceiling on total satoshis paid out. 0 disables the cap. */
    private readonly globalWindowMs = 86_400_000,
    private readonly globalMaxSats = 0,
  ) {}

  /**
   * Decide and record in one synchronous step. On success the caller MUST
   * settle the returned ticket with `commit()` or `release()`.
   */
  reserve(address: string, ip: string, amountSats: number, now = Date.now()): RateLimitDecision {
    this.prune(now);
    const key = addrKey(address);

    // Per-address cooldown. A reservation in flight occupies this slot exactly
    // as a completed drip does, which is what closes the concurrency race.
    const last = this.lastByAddress.get(key);
    if (last !== undefined && now - last < this.perAddressWindowMs) {
      return {
        allowed: false,
        reason: "this address already received a drip recently",
        retryAfterMs: this.perAddressWindowMs - (now - last),
      };
    }

    // Per-IP sliding window. Taken before the payment and never refunded.
    const hits = this.ipHits.get(ip) ?? [];
    if (hits.length >= this.perIpMax) {
      const oldest = Math.min(...hits);
      return {
        allowed: false,
        reason: "too many requests from this IP",
        retryAfterMs: this.perIpWindowMs - (now - oldest),
      };
    }

    // Global drain ceiling. The per-client limits bound one client; only this
    // bounds the sum of all of them, which is what an attacker with a /64 of
    // IPv6 or a list of addresses actually consumes.
    if (this.globalMaxSats > 0) {
      const committed = this.spend.reduce((a, e) => a + e.sats, 0);
      if (committed + amountSats > this.globalMaxSats) {
        const oldest = this.spend.length ? Math.min(...this.spend.map((e) => e.at)) : now;
        return {
          allowed: false,
          reason: "faucet has reached its rolling payout ceiling; try again later",
          retryAfterMs: Math.max(1000, this.globalWindowMs - (now - oldest)),
        };
      }
    }

    // Admit: take every budget now.
    hits.push(now);
    this.ipHits.set(ip, hits);
    this.lastByAddress.set(key, now);
    const ticket: Reservation = { address: key, amountSats, at: now, settled: false };
    this.spend.push({ at: now, sats: amountSats });
    return { allowed: true, ticket };
  }

  /** The drip went out. The cooldown and the spend both stand. */
  commit(ticket: Reservation): void {
    ticket.settled = true;
  }

  /**
   * The drip did not go out. Give back the address cooldown and the spend, but
   * NOT the per-IP hit — the request still cost the node and the host real
   * work, and refunding it is what made failing requests an unlimited DoS.
   */
  release(ticket: Reservation, now = Date.now()): void {
    if (ticket.settled) return;
    ticket.settled = true;
    if (this.lastByAddress.get(ticket.address) === ticket.at) {
      this.lastByAddress.delete(ticket.address);
    }
    const i = this.spend.findIndex((e) => e.at === ticket.at && e.sats === ticket.amountSats);
    if (i >= 0) this.spend.splice(i, 1);
    void now;
  }

  /** Rolling total actually reserved or paid in the global window. */
  spentSats(now = Date.now()): number {
    this.prune(now);
    return this.spend.reduce((a, e) => a + e.sats, 0);
  }

  /**
   * Drop everything outside its window. Without this the maps grow without
   * bound for the life of the process — `lastByAddress` was never evicted at
   * all, which is a slow memory leak an attacker can drive.
   */
  private prune(now: number): void {
    for (const [k, t] of this.lastByAddress) {
      if (now - t >= this.perAddressWindowMs) this.lastByAddress.delete(k);
    }
    for (const [k, hits] of this.ipHits) {
      const kept = hits.filter((t) => now - t < this.perIpWindowMs);
      if (kept.length === 0) this.ipHits.delete(k);
      else this.ipHits.set(k, kept);
    }
    this.spend = this.spend.filter((e) => now - e.at < this.globalWindowMs);
  }
}
