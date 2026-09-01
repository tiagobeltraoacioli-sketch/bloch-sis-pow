// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Rate limiting, in two layers that protect two different things.
//
// ═══════════════════════════════════════════════════════════════════════════
// THE CLIENT LIMIT protects the edge and the other callers. It is fair-share.
// THE UPSTREAM GOVERNOR protects the CHAIN. It is the safety property.
// ═══════════════════════════════════════════════════════════════════════════
//
// Only the second one is load-bearing, and the distinction is the whole point
// of this file.
//
// A client rate limit at a Pages Function is necessarily approximate: there is
// no shared counter, so each isolate holds its own bucket and the effective
// global limit is (per-isolate limit × live isolates). An attacker who can
// spread across isolates — which is what any distributed client does by
// accident — gets a multiple of the nominal rate. If the chain's protection
// depended on that number, the chain would not be protected.
//
// So the chain's protection does not depend on it. The UPSTREAM GOVERNOR caps
// the calls this isolate MAKES, not the calls it RECEIVES:
//
//     however many requests arrive, an isolate performs at most
//     ARCHIVAL_RATE calls/second to the archival plane and at most
//     one fleet call per WITNESS_TTL_MS.
//
// Past that ceiling the edge serves stale cache, and past THAT it refuses. A
// refusal to a caller is a bounded, honest failure; a node whose consensus
// thread is stuck answering an explorer is not. That trade is made here,
// deliberately, and it is why the governor sits between the cache and the
// pool rather than at the front door.
//
// The measured reason it has to exist: an agent's own test starved the nodes
// it was measuring by sweeping every slot on every poll — roughly 3,000 round
// trips — and then reported the fracture it had caused as a finding about the
// chain. The explorer client in `src/lib/g4.ts` does the same shape of thing
// on a smaller scale: `recentBlocks(n)` is n calls per poll and
// `allValidators(64)` is 64.

/**
 * A token bucket.
 *
 * Continuous refill rather than windowed, so a caller cannot get 2x the limit
 * by straddling a window edge — the classic fixed-window defect.
 */
export class Bucket {
  /**
   * @param capacity  burst size
   * @param perSecond sustained refill rate
   * @param now       clock, injectable for tests
   */
  constructor(capacity, perSecond, now) {
    this.capacity = capacity;
    this.perSecond = perSecond;
    this.tokens = capacity;
    this.now = now;
    this.last = now();
  }

  #refill() {
    const t = this.now();
    const dt = Math.max(0, t - this.last) / 1000;
    this.last = t;
    this.tokens = Math.min(this.capacity, this.tokens + dt * this.perSecond);
  }

  /** Take `n` tokens, or return false and take nothing. */
  take(n = 1) {
    this.#refill();
    if (this.tokens < n) return false;
    this.tokens -= n;
    return true;
  }

  /** Milliseconds until `n` tokens would be available. */
  retryAfterMs(n = 1) {
    this.#refill();
    if (this.tokens >= n) return 0;
    return Math.ceil(((n - this.tokens) / this.perSecond) * 1000);
  }

  get remaining() {
    this.#refill();
    return Math.floor(this.tokens);
  }
}

// ─── Client limits ──────────────────────────────────────────────────────────
//
// Two classes, because two requests are not the same size to the chain. A
// `getbalance` is a linear walk of 452,726 committed outputs on the consensus
// thread; a `getblockcount` is a field read. Charging them the same is how a
// polite-looking request rate turns into an impolite load.

/** Sustained calls per second, per client, for cheap methods. */
export const CLIENT_RATE = 8;
/** Burst. One explorer page opening does a handful of calls at once. */
export const CLIENT_BURST = 40;
/** What a full-set walk costs a client, in tokens. */
export const WALK_COST = 8;

// ─── Upstream governor ──────────────────────────────────────────────────────

/**
 * Sustained archival calls per second, per isolate, across ALL clients.
 *
 * ═══ CALIBRATED AGAINST A MEASUREMENT, NOT CHOSEN BY FEEL ═══
 *
 * Measured 2026-09-01 on an isolated Genesis-4 observer carrying the real
 * 452,726-output carryover, localhost so no WAN round trip is in the number,
 * min of fifteen (ms):
 *
 *     getblockcount      0.18      getblockbyslot   0.18
 *     getvalidator       0.18      getvalidatorcount 0.19
 *     getmempoolinfo     0.14      getutxos         4.54
 *     getbalance         9.12
 *
 * and under concurrency, on two cores:
 *
 *     getblockcount x160 -> 35.7 ms wall, 0 failed  (~4,500/s)
 *     getbalance    x64  -> 590.8 ms wall, 0 failed (~108/s)
 *
 * So the budget is set as a fraction of ONE NODE'S CONSENSUS THREAD, which is
 * the resource that actually matters — the RPC is served from it, and a
 * request arriving while a proposal is being signed waits for that signature.
 *
 *   25 calls/s x 2 archivals x 0.2 ms  =  10 ms/s  ~= 1% of the thread
 *   walks, at UPSTREAM_WALK_COST, cap at 5/s x 2 x 9-13 ms
 *                                      =  90-130 ms/s ~= 10% of the thread
 *
 * Ten per cent is the ceiling this layer is willing to be responsible for, and
 * the walks are where it goes. If those numbers move — a bigger output set, a
 * different box — this constant is the line to revisit, and
 * `edge/tests/surface-frozen.test.mjs` fails if the node stops declaring the
 * RPC/consensus coupling the calibration rests on.
 */
export const ARCHIVAL_RATE = 25;
export const ARCHIVAL_BURST = 60;

/**
 * What a full-set walk costs against the UPSTREAM budget.
 *
 * Separate from `WALK_COST`, which prices the same call against the CLIENT's
 * budget. Same asymmetry, two different ledgers: one is about fairness between
 * callers, this one is about the node. `getbalance` is roughly fifty times a
 * head read on the consensus thread and it is charged five, not fifty, because
 * the response is also fifty times more useful — the ceiling above is what
 * bounds it, not the per-call price.
 */
export const UPSTREAM_WALK_COST = 5;

/** Fleet calls. One per witness interval; the burst covers a tiebreak. */
export const FLEET_RATE = 0.05; // one per 20 s
export const FLEET_BURST = 2;

/**
 * Per-isolate state. Module scope on purpose — surviving between requests in
 * the same isolate is the entire mechanism.
 */
const clients = new Map();
let archivalBucket = null;
let fleetBucket = null;

/** Observability: what the isolate has actually spent. */
export const counters = {
  clientRequests: 0,
  clientThrottled: 0,
  archivalCalls: 0,
  archivalRefused: 0,
  fleetCalls: 0,
  cacheHits: 0,
  cacheMisses: 0,
  staleServed: 0,
  coalesced: 0,
};

export function _resetGovernorForTests() {
  clients.clear();
  archivalBucket = null;
  fleetBucket = null;
  for (const k of Object.keys(counters)) counters[k] = 0;
}

/** Bound the client table so a spray of source addresses cannot grow it. */
const MAX_CLIENTS = 5_000;

export function clientBucket(key, now) {
  let b = clients.get(key);
  if (!b) {
    if (clients.size >= MAX_CLIENTS) {
      // Evict the least recently touched. Approximate and cheap; the
      // alternative is an unbounded map, which is a memory bug wearing a
      // rate-limiter costume.
      const oldest = [...clients.entries()].sort((a, b2) => a[1].last - b2[1].last)[0];
      if (oldest) clients.delete(oldest[0]);
    }
    b = new Bucket(CLIENT_BURST, CLIENT_RATE, now);
    clients.set(key, b);
  }
  return b;
}

export function archivalGovernor(now) {
  if (!archivalBucket) archivalBucket = new Bucket(ARCHIVAL_BURST, ARCHIVAL_RATE, now);
  return archivalBucket;
}

export function fleetGovernor(now) {
  if (!fleetBucket) fleetBucket = new Bucket(FLEET_BURST, FLEET_RATE, now);
  return fleetBucket;
}

/**
 * Identify the caller.
 *
 * `CF-Connecting-IP` is set by the edge and cannot be spoofed by a client
 * header, unlike `X-Forwarded-For`. Absent it — local tests, or a runtime that
 * is not Cloudflare — everything shares one bucket, which is the SAFE default:
 * it under-serves rather than under-limits.
 */
export function clientKey(request) {
  const h = request && request.headers;
  return (h && (h.get('cf-connecting-ip') || h.get('x-real-ip'))) || 'anonymous';
}

/** JSON-RPC error codes this layer adds. Stable; branch on these, not on prose. */
export const RATE_LIMITED = -32029;
export const UPSTREAM_BUDGET = -32030;
export const STALE_UPSTREAM = -32011;
export const NO_QUORUM = -32010;

export function rateLimitedError(id, method, retryAfterMs, cost) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: RATE_LIMITED,
      message:
        `Rate limit reached for this client. Nothing is wrong with the chain or ` +
        `with your request — this endpoint is a shared public front for nodes ` +
        `that serve RPC from their consensus thread, so it meters callers ` +
        `rather than passing a burst through. Retry in ` +
        `${Math.ceil(retryAfterMs / 1000)} s, or run your own node and read it ` +
        `directly, which has no limit at all.`,
      data: {
        reason: 'rate_limited',
        method: method || null,
        retry_after_ms: retryAfterMs,
        cost_charged: cost,
        sustained_per_second: CLIENT_RATE,
        burst: CLIENT_BURST,
        walk_cost: WALK_COST,
      },
    },
  };
}

export function upstreamBudgetError(id, method, retryAfterMs) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: UPSTREAM_BUDGET,
      message:
        `This endpoint has reached the number of calls per second it is willing ` +
        `to make to the nodes behind it, and it has no cached answer for this ` +
        `one. This is a deliberate ceiling: a Genesis-4 node answers RPC from ` +
        `the same thread that produces blocks, so an endpoint that forwarded ` +
        `every request would be able to slow the chain down. Nothing is wrong ` +
        `with the chain. Retry in ${Math.ceil(retryAfterMs / 1000)} s.`,
      data: {
        reason: 'upstream_budget_exhausted',
        method: method || null,
        retry_after_ms: retryAfterMs,
        upstream_calls_per_second: ARCHIVAL_RATE,
      },
    },
  };
}
