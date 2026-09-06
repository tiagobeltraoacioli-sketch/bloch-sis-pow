// SPDX-License-Identifier: MIT OR Apache-2.0
// In-memory rate limiting for the faucet: one drip per address per window, plus
// a per-IP request cap. State is process-local (not durable across restarts);
// a production deployment would back this with a shared store. Documented in
// README as a known limitation.
//
// T-3 fix (audit finding): rate limiting used to be TOCTOU. `check()` was a
// pure read, `record()` the only write, and the code called `check()` before
// `await faucet.drip(address)` (which spans several `await` points — an
// external `getutxos` RPC, a spawned signer subprocess, `sendrawtransaction`)
// and `record()` only after. Node's event loop interleaves OTHER requests at
// every one of those `await` points, so N concurrent `POST /api/faucet` for
// the SAME address all observed an empty `lastByAddress` entry, all passed
// `check()`, and all dripped — the funding wallet drained at the rate the
// signer could sign.
//
// The fix is reserve-then-confirm: `reserve()` atomically checks AND records
// a provisional hit in one synchronous call (no `await` inside it, so no
// other request's JS can run between the check and the write — this is what
// actually closes the race, since Node is single-threaded and only yields at
// `await`). `release()` undoes the provisional record if the drip then fails.
// An explicit `inFlight` set additionally rejects a second concurrent request
// for an address that already has one in progress, as an independent,
// easy-to-audit invariant rather than relying solely on the cooldown window
// having a nonzero value.

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
}

export class RateLimiter {
  private readonly lastByAddress = new Map<string, number>();
  private readonly ipHits = new Map<string, number[]>();
  /** T-3 fix: addresses with a reservation not yet released (drip in progress). */
  private readonly inFlight = new Set<string>();

  constructor(
    private readonly perAddressWindowMs: number,
    private readonly perIpWindowMs: number,
    private readonly perIpMax: number,
  ) {}

  /**
   * Read-only advisory check — does NOT reserve anything. Kept for callers
   * that only want to preview a decision (e.g. a status endpoint); the live
   * drip path MUST use {@link reserve} instead, or the TOCTOU this fix closes
   * reopens.
   */
  check(address: string, ip: string, now = Date.now()): RateLimitDecision {
    if (this.inFlight.has(address)) {
      return { allowed: false, reason: "a request for this address is already in flight" };
    }
    return this.evaluate(address, ip, now);
  }

  /**
   * T-3 fix: atomically check AND provisionally record, in one synchronous
   * call. Call this where `check()` used to be called, immediately — before
   * any `await` — so no concurrent request can observe the pre-reservation
   * state. On success, call {@link release} if the drip that follows does
   * NOT go through (so the reservation does not permanently consume the
   * window for a payment that never happened); on failure, {@link release}
   * is a no-op safety net, not required, but harmless if called anyway.
   */
  reserve(address: string, ip: string, now = Date.now()): RateLimitDecision {
    if (this.inFlight.has(address)) {
      return { allowed: false, reason: "a request for this address is already in flight" };
    }
    const decision = this.evaluate(address, ip, now);
    if (!decision.allowed) return decision;

    this.inFlight.add(address);
    this.lastByAddress.set(address, now);
    const hits = this.ipHits.get(ip) ?? [];
    hits.push(now);
    this.ipHits.set(ip, hits);
    return { allowed: true };
  }

  /**
   * Undo a reservation made by {@link reserve} when the drip it was guarding
   * did NOT actually pay out (the address remains eligible; the IP's window
   * does not count a request that never sent funds). Removes exactly the
   * `now` timestamp this reservation added — not a blind "pop the last
   * entry" — so it stays correct even if another request for the same IP
   * reserved (and pushed its own hit) while this one's `await`s were pending.
   */
  release(address: string, ip: string, now: number): void {
    this.inFlight.delete(address);
    if (this.lastByAddress.get(address) === now) {
      this.lastByAddress.delete(address);
    }
    const hits = this.ipHits.get(ip);
    if (hits) {
      const idx = hits.lastIndexOf(now);
      if (idx !== -1) hits.splice(idx, 1);
      if (hits.length === 0) this.ipHits.delete(ip);
    }
  }

  /** Shared decision logic between `check` (read-only) and `reserve` (read+write). */
  private evaluate(address: string, ip: string, now: number): RateLimitDecision {
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
}
