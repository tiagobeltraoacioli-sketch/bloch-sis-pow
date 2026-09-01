// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The read path. Cache, coalesce, govern, corroborate — in that order.
//
// ═══════════════════════════════════════════════════════════════════════════
// THE ORDER IS THE DESIGN
// ═══════════════════════════════════════════════════════════════════════════
//
//   1. surface       is this a name we answer at all
//   2. client limit  fair share between callers
//   3. cache         answered without touching the chain
//   4. coalesce      fifty tabs arriving on a cold cache are one upstream call
//   5. governor      the ceiling on calls we are willing to make, ever
//   6. archivals     two keyless observers, asked together
//   7. corroborate   they must agree; the fleet witness certifies the lineage
//   8. label         every answer says how well corroborated it is
//
// Steps 3–5 are what make the explorer safe to point at a chain whose RPC has
// no authentication and no rate limit and runs on the consensus thread. Steps
// 6–8 are what make the answers honest. Neither half is optional: a cache in
// front of a single node is fast and wrong, and corroboration without a cache
// is honest and dangerous.
//
// ═══════════════════════════════════════════════════════════════════════════
// WHERE THE CHAIN'S LOAD ACTUALLY COMES FROM, MEASURED
// ═══════════════════════════════════════════════════════════════════════════
//
// Not from the head polls. From the walks and from the fan-out:
//
//   `src/lib/g4.ts` `recentBlocks(fromSlot, n)` — n calls per poll, per tab.
//   `src/lib/g4.ts` `allValidators(64)`          — 64 calls per visit.
//   `getbalance` / `getutxos`                    — one linear pass over the
//       whole committed eUTXO set (452,726 outputs) ON THE CONSENSUS THREAD;
//       the node's own `balance_json` doc comment says so and calls the
//       durable fix a state-layout change.
//
// So the cache classes in `surface.js` are not a performance tweak. The block
// cache turns `recentBlocks` from n calls into (new blocks since last poll)
// calls, which at a 30-second slot is at most one. The validator cache turns
// 64 calls per visit into 64 calls per epoch across all visitors. And the
// `WALK_COST` in `governor.js` prices the two expensive methods so a single
// caller cannot spend the whole isolate's budget on them.

import {
  parsePools,
  attemptOne,
  order,
  markSick,
  markWell,
  canonicalKey,
  ATTEMPT_TIMEOUT_MS,
} from './pool.js';
import {
  methodSpec,
  isBranchSensitive,
  isPinned,
  CacheClass,
  Cost,
  EDGE_SURFACE,
  EDGE_ABSENT,
  edgeMethodNames,
} from './surface.js';
import {
  fleetWitness,
  witnessView,
  observe,
  observeFinalSlot,
  certify,
  salt,
  events as lineageEvents,
  justificationInDoubt,
  loadLineage,
  saveLineage,
  STALE_SLOTS,
  WITNESS_TTL_MS,
} from './lineage.js';
import {
  clientBucket,
  clientKey,
  archivalGovernor,
  fleetGovernor,
  counters,
  rateLimitedError,
  upstreamBudgetError,
  WALK_COST,
  UPSTREAM_WALK_COST,
  NO_QUORUM,
  STALE_UPSTREAM,
} from './governor.js';

/** How long a plane certification is reused. Matches the witness interval. */
export const PLANE_TTL_MS = 20_000;

/** Deterministic JSON, so key order cannot split the cache. */
export function stableStringify(v) {
  if (v === undefined) return 'null';
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  return (
    '{' +
    Object.keys(v)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + stableStringify(v[k]))
      .join(',') +
    '}'
  );
}

/**
 * The cache key, built from what makes the answer immutable.
 *
 * The salt is mixed in for every class EXCEPT `content`. That exception is the
 * point of the class: `getblockbyid(X)` is answered by the block whose hash is
 * X, and no reorg can make X name a different block, so burning the salt must
 * not throw those entries away — they are the only ones we are certain about.
 *
 * `epoch` keys carry the epoch, so an epoch boundary invalidates by
 * construction instead of by hoping a TTL lands in the right place.
 */
export function cacheKeyFor(method, params, spec, ctx) {
  const p = stableStringify(params ?? []);
  if (p.length > 1500) return null; // nothing sane to key on
  const parts = [method, p];
  if (spec.cacheClass !== CacheClass.Content) parts.push(`s${ctx.salt}`);
  if (spec.cacheClass === CacheClass.Epoch) parts.push(`e${ctx.epoch ?? 'unknown'}`);
  return 'https://bloch-explorer.edge/rpc/' + parts.map(encodeURIComponent).join('/');
}

/**
 * How long THIS entry is good for.
 *
 * Read from the entry's own metadata, not from the method's default, because
 * two answers to the same method can have different lifetimes: a
 * `getblockbyslot` for a finalised slot is immutable relative to its lineage
 * and a `getblockbyslot` for the head is not. The write path decides and
 * records; the read path obeys the record. Getting this wrong in the other
 * direction — writing the long TTL and reading the short one — silently threw
 * away every finalised block one slot-time after storing it.
 */
export function effectiveTtl(spec, meta) {
  if (spec.cacheClass === CacheClass.Lineage && meta && meta.finalised === true) {
    return spec.finalTtlMs ?? spec.ttlMs;
  }
  return spec.ttlMs;
}

async function readCache(cache, key, spec, now, allowStale) {
  if (!cache || !key) return null;
  try {
    const res = await cache.match(new Request(key, { method: 'GET' }));
    if (!res) return null;
    const storedAt = Number(res.headers.get('x-edge-stored-at') || 0);
    const ageMs = now - storedAt;
    if (!storedAt || ageMs < 0) return null;
    const body = await res.json();
    const meta = body.meta || {};
    const fresh = ageMs <= effectiveTtl(spec, meta);
    if (!fresh && !allowStale) return null;
    return { result: body.result, meta, ageMs, fresh };
  } catch {
    return null; // caching is an optimisation; never fail a call over it
  }
}

async function writeCache(cache, key, ttlMs, result, meta, now) {
  if (!cache || !key) return;
  try {
    await cache.put(
      new Request(key, { method: 'GET' }),
      new Response(JSON.stringify({ result, meta }), {
        headers: {
          'content-type': 'application/json',
          // The stale window: the entry stays retrievable past its TTL so the
          // governor has something to serve when it refuses a fresh call.
          'cache-control': `max-age=${Math.max(1, Math.round((ttlMs + 300_000) / 1000))}`,
          'x-edge-stored-at': String(now),
        },
      }),
    );
  } catch {
    /* ignore */
  }
}

/** In-flight coalescing, isolate-local, keyed by the cache key. */
const inFlight = new Map();

/** The archival plane's certification, refreshed at most every PLANE_TTL_MS. */
let plane = null;

export function _resetCoreForTests() {
  inFlight.clear();
  plane = null;
}

/** The last known certification, never null, always dated. */
export function planeView(now) {
  if (!plane) return { certified: false, age_ms: null, reason: 'not_probed' };
  return { ...plane.view, age_ms: now - plane.at };
}

/**
 * Ask both archivals one question, concurrently, and group the answers.
 *
 * Both, not one-then-the-other: with a pool of two, asking sequentially and
 * stopping at the first success means never noticing that they disagree, which
 * is the failure the quorum exists to catch. Two calls is the price of the
 * only corroboration a two-node plane can give.
 */
async function askArchivals(rpcReq, urls, opts) {
  const now = opts.now;
  let { order: ordered } = order(urls, now());
  // A pinned read takes the healthiest upstream and ONLY that one. Asking both
  // and then picking a winner would look identical from here and be wrong: for
  // a paginated method the two answers are pages of different sequences, so
  // "they agreed" and "they disagreed" are equally meaningless. `order()` is
  // health-sorted, so this is the best single node we know of.
  if (opts.single) ordered = ordered.slice(0, 1);
  const t = Math.min(ATTEMPT_TIMEOUT_MS, opts.deadline - now() - 250);
  if (t < 500) return { answers: [], attempts: [{ outcome: 'skipped: time budget exhausted' }] };

  const results = await Promise.all(ordered.map((u) => attemptOne(u, rpcReq, t, opts.fetchImpl)));
  const answers = [];
  const attempts = [];
  ordered.forEach((u, i) => {
    const r = results[i];
    counters.archivalCalls += 1;
    if (!r.settled) {
      markSick(u, now());
      attempts.push({ upstream: u, outcome: r.outcome });
      return;
    }
    markWell(u);
    attempts.push({ upstream: u, outcome: 'ok' });
    answers.push({ url: u, value: r.value });
  });
  return { answers, attempts };
}

/**
 * Refresh what we believe about the archival plane: are both archivals on the
 * fleet's lineage, and how far behind are they.
 *
 * This is the piece that lets every OTHER read skip certification entirely. A
 * `getbalance` answer carries no chain context, so certifying it per request
 * would mean a second call per request. Certifying the PLANE on a schedule
 * costs two calls per 20 s and covers every read taken from it — the same
 * trick as the fleet witness, applied one layer down.
 */
export async function refreshPlane(opts, force) {
  const now = opts.now();
  if (!force && plane && now - plane.at < PLANE_TTL_MS) return plane;

  const gov = archivalGovernor(opts.now);
  if (!gov.take(opts.archivals.length)) {
    counters.archivalRefused += 1;
    return plane; // whatever we last knew, dated by planeView
  }

  const { answers } = await askArchivals(
    { jsonrpc: '2.0', id: 1, method: 'getchaininfo', params: [] },
    opts.archivals,
    opts,
  );
  return adoptPlane(answers, opts);
}

/** Fold a set of getchaininfo answers into the plane certification. */
export function adoptPlane(answers, opts) {
  const now = opts.now();
  const wit = opts.witness;
  const chains = answers.map((a) => a.value && a.value.result).filter(Boolean);
  // Certify BEFORE folding these answers into the memo. `observe` writes the
  // root it was given, so folding first would overwrite the very checkpoint an
  // archival is contradicting and then certify against the contradiction — the
  // node would be cleared by the evidence it produced. Order is the whole fix.
  const certs = chains.map((c) => certify(c, wit));
  for (const c of chains) observe(c, 'archival');
  const good = certs.filter((c) => c.ok).length;
  const worst = certs.find((c) => !c.ok) || null;

  const heights = chains.map((c) => Number(c.height)).filter(Number.isFinite);
  const agreed =
    chains.length >= 2 &&
    canonicalKey(headKey(chains[0])) === canonicalKey(headKey(chains[1]));

  plane = {
    at: now,
    chains,
    view: {
      certified: good > 0 && !worst,
      responding: chains.length,
      of: opts.archivals.length,
      agree_on_head: agreed,
      height: heights.length ? Math.max(...heights) : null,
      behind_by_slots: chains.length
        ? Math.max(...chains.map((c) => Number(c.behind_by_slots) || 0))
        : null,
      witness_certified: !!(wit && wit.ok),
      reason: worst ? worst.reason : null,
      detail: worst ? worst.detail || null : null,
    },
  };
  return plane;
}

function headKey(c) {
  return {
    block_id: c.block_id,
    height: c.height,
    finalized: c.finalized,
    justified: c.justified,
  };
}

// ─── Corroboration ──────────────────────────────────────────────────────────

/**
 * The four things this edge can say about an answer, and what each means to
 * someone deciding whether to act on it.
 *
 * `final`          the answer is about a block at or below the finalised
 *                  checkpoint, addressed by content or pinned to a lineage the
 *                  fleet witness confirms. This is the only level that means
 *                  "this cannot change".
 * `corroborated`   both archivals returned the identical answer AND the plane
 *                  they answered from stands on the fleet's lineage. It can
 *                  still be reorganised — it is a claim about the tip.
 * `uncorroborated` served, but something is missing: only one archival
 *                  answered, or the fleet witness is unavailable or stale, or a
 *                  justified checkpoint was rewritten recently. Show it; do not
 *                  settle on it.
 * `node_local`     the question is about the node that was asked, not about the
 *                  chain (`getmempoolinfo`). Corroboration is not merely absent
 *                  here, it is meaningless, and calling it `uncorroborated`
 *                  would invite someone to go looking for the missing witness.
 */
export const Level = {
  Final: 'final',
  Corroborated: 'corroborated',
  Uncorroborated: 'uncorroborated',
  NodeLocal: 'node_local',
};

function corroborationOf(spec, answers, ctx) {
  const now = ctx.now;
  const wit = witnessView(now);
  const pv = planeView(now);

  if (spec.corroboration === 'none') {
    return {
      level: Level.NodeLocal,
      archival_witnesses: answers.length,
      of: ctx.archivalCount,
      note:
        'a node-local reading. Two nodes disagreeing here is normal and is not ' +
        'a fork: the mempool does not converge on this chain.',
      cache_salt: salt(),
      witness: wit,
      plane: pv,
    };
  }
  if (spec.corroboration === 'pinned') {
    return {
      level: Level.Uncorroborated,
      archival_witnesses: answers.length,
      of: ctx.archivalCount,
      pinned_to: ctx.pinnedTo || null,
      note:
        'read from ONE archival on purpose. This method is paginated, and a ' +
        'cursor walked across two nodes that disagree about the head ' +
        'interleaves two registries into a page set that existed on neither. ' +
        'One node answering consistently is worth more here than two nodes ' +
        'agreeing about nothing, so this is uncorroborated by construction ' +
        'rather than by failure.',
      cache_salt: salt(),
      witness: wit,
      plane: pv,
    };
  }
  if (spec.corroboration === 'edge') {
    return {
      level: Level.Corroborated,
      archival_witnesses: 0,
      source: 'edge',
      cache_salt: salt(),
      witness: wit,
      plane: pv,
    };
  }

  const agreed = answers.length >= 2;
  const witnessed = wit.available && wit.age_ms !== null && wit.age_ms < WITNESS_TTL_MS * 3;
  const planeOk = pv.certified === true;
  const doubt = justificationInDoubt(now);

  let level;
  if (ctx.finalised && agreed && witnessed && planeOk && !doubt) level = Level.Final;
  else if (agreed && witnessed && planeOk && !doubt) level = Level.Corroborated;
  else level = Level.Uncorroborated;

  const missing = [];
  if (!agreed) missing.push('only one archival answered');
  if (!witnessed) missing.push(`no fresh fleet witness (${wit.reason || 'stale'})`);
  if (!planeOk) missing.push(`archival plane not certified (${pv.reason || 'not probed'})`);
  if (doubt) missing.push('a justified checkpoint was rewritten recently');

  return {
    level,
    archival_witnesses: answers.length,
    of: ctx.archivalCount,
    fleet_witness: witnessed,
    // The salt rides on every answer so a CLIENT-side cache can be invalidated
    // by the same reorg that invalidates the edge's. A browser holding a map of
    // finalised blocks has exactly the problem this layer solved server-side,
    // and it cannot solve it without being told; see `finalBlocks` in
    // `src/lib/g4.ts`, which used to key on `finalized` alone.
    cache_salt: salt(),
    witness: wit,
    plane: pv,
    missing: missing.length ? missing : undefined,
    reorg_events: lineageEvents().length ? lineageEvents() : undefined,
  };
}

// ─── Finality is re-derived, never served from cache ────────────────────────

/**
 * Replace a cached block's node-relative finality with a freshly derived one.
 *
 * A block's `finality` and `finalized` fields are not properties of the block.
 * They are the answering node's classification of it against that node's own
 * checkpoints at the moment it was asked, and they move. The client-side cache
 * in `src/lib/g4.ts` stores them and is wrong the moment they do.
 *
 * When there is no witness to derive from, the answer is `finalized: null` and
 * `finality: "unknown"` — not `false`, which would be a claim, and not the
 * cached value, which would be a stale claim. A consumer that treats null as
 * "not settled" is behaving correctly; one that treats it as "settled" was
 * always going to be wrong about something.
 */
export function rederiveFinality(result, now) {
  if (!result || typeof result !== 'object' || !('height' in result)) return result;
  const wit = witnessView(now);
  const out = { ...result };
  const h = Number(result.height);
  const fh = wit.available ? Number(wit.finalized_height) : NaN;

  if (Number.isFinite(h) && Number.isFinite(fh)) {
    out.finalized = h <= fh;
    out.finality = out.finalized ? 'finalized' : 'canonical';
    out.finality_source = 'recomputed_from_fleet_witness';
    out.finality_witness_age_ms = wit.age_ms;
  } else {
    out.finalized = null;
    out.finality = 'unknown';
    out.finality_source = 'no_witness';
  }
  if ('finality' in result) out.finality_as_answered = result.finality;
  return out;
}

// ─── The read path ──────────────────────────────────────────────────────────

export function methodNotAllowedError(id, method) {
  const absent = EDGE_ABSENT.find(([n]) => n === method);
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: -32601,
      message: absent
        ? `'${method}' is not served by the explorer edge. ${absent[1]}`
        : `'${method}' is not a method this endpoint answers. This is a READ-ONLY ` +
          `explorer front for Genesis-4; the methods it does answer are listed by ` +
          `'getcapabilities' on this same endpoint.`,
      data: {
        reason: absent ? 'deliberately_absent' : 'method_not_allowed',
        method,
        allowed: edgeMethodNames(),
      },
    },
  };
}

function divergentError(id, method, groups) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: NO_QUORUM,
      message:
        `The two archival nodes behind this endpoint returned different answers ` +
        `for '${method}', so nothing could be corroborated and no single node's ` +
        `answer is being passed off as the chain's. Nothing is wrong with your ` +
        `query. Try again in a moment.`,
      data: {
        reason: 'divergent_archivals',
        method,
        distinct_answers: groups,
        quorum_required: 2,
      },
    },
  };
}

function staleError(id, method, cert) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: STALE_UPSTREAM,
      message:
        `The nodes behind this endpoint are not currently following the chain ` +
        `closely enough to answer '${method}' honestly (${cert.reason}). Serving ` +
        `their answer would show you a view of Genesis-4 that the fleet has moved ` +
        `past, with no sign that it was old. Nothing is wrong with the chain.`,
      data: {
        reason: cert.reason,
        method,
        behind_by_slots: cert.behind_by_slots ?? null,
        behind_by_blocks: cert.behind_by_blocks ?? null,
        detail: cert.detail ?? null,
        tolerance_slots: STALE_SLOTS,
      },
    },
  };
}

function noAnswerError(id, method, attempts) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: -32000,
      message:
        `No archival node answered '${method}'. This is a fault at this endpoint ` +
        `or at the two observer nodes behind it, and it is NOT a statement about ` +
        `Genesis-4: the chain may be finalising normally right now. Retry in a ` +
        `few seconds.`,
      data: { reason: 'no_upstream_answered', method, attempts, chainStatusKnown: false },
    },
  };
}

/** The edge's own capabilities answer. No node is asked. */
export function capabilitiesJson(now) {
  return {
    edge: 'bloch-explorer',
    surface: 'genesis-4-read-only',
    version: '1.0.0',
    methods: EDGE_SURFACE.map((m) => ({
      name: m.name,
      cache_class: m.cacheClass,
      cost: m.cost,
      corroboration: m.corroboration,
      cache_ttl_ms: m.ttlMs,
      alias_of: m.aliasOf ?? null,
      summary: m.summary,
    })),
    absent: EDGE_ABSENT.map(([name, why]) => ({ name, why })),
    corroboration_levels: {
      final: 'at or below the finalised checkpoint, content- or lineage-pinned',
      corroborated: 'both archivals agreed and the fleet witness certifies the lineage',
      uncorroborated: 'served, but a witness or a second archival is missing',
      node_local: 'a property of the node asked, not of the chain',
    },
    limits: {
      client_sustained_per_second: 8,
      client_burst: 40,
      walk_methods_cost: WALK_COST,
      upstream_calls_per_second: 6,
      fleet_witness_interval_ms: WITNESS_TTL_MS,
      stale_tolerance_slots: STALE_SLOTS,
      batch_requests: false,
    },
    honesty: [
      'This endpoint corroborates; it does not validate. It compares answers ' +
        'from independent nodes. It checks no signature and applies no state ' +
        'transition, so two nodes agreeing on a wrong answer is served as ' +
        'corroborated.',
      'Reads come only from keyless archival observers, which cannot propose ' +
        'blocks and therefore cannot invent a branch. Their failure mode is ' +
        'being behind or being down, which is detectable, rather than lying, ' +
        'which would not be.',
      'The fleet is consulted on a schedule, never per request, so public ' +
        'traffic here cannot become load on the validator set.',
      'Run your own node if the answer has to be yours. The guarantee this ' +
        'endpoint gives is bounded by the nodes it can see.',
    ],
    salt: salt(),
    witness: witnessView(now),
    plane: planeView(now),
    reorg_events: lineageEvents(),
  };
}

/**
 * The whole decision path, independent of the Workers runtime.
 *
 * `opts` = { pools:{archivals,fleet}, fetchImpl, cache, waitUntil, now,
 *            clientKey, budgetMs }
 */
export async function handleRead(payload, opts) {
  const now = opts.now;
  const id = payload && payload.id !== undefined ? payload.id : null;
  const method = payload && payload.method;

  if (typeof method !== 'string') {
    return {
      body: { jsonrpc: '2.0', id, error: { code: -32600, message: 'invalid request: missing method' } },
      cacheState: 'bypass',
      status: 400,
    };
  }

  const spec = methodSpec(method);
  if (!spec) {
    return { body: methodNotAllowedError(id, method), cacheState: 'bypass', status: 200 };
  }

  // ── 2. client limit ───────────────────────────────────────────────────────
  counters.clientRequests += 1;
  const cost = spec.cost === Cost.Walk ? WALK_COST : 1;
  const bucket = clientBucket(opts.clientKey || 'anonymous', now);
  if (!bucket.take(cost)) {
    counters.clientThrottled += 1;
    const retry = bucket.retryAfterMs(cost);
    return {
      body: rateLimitedError(id, method, retry, cost),
      cacheState: 'bypass',
      status: 429,
      retryAfterMs: retry,
    };
  }

  await loadLineage(opts.cache);

  // The witness is shared and budget-capped, so this is nearly always free.
  const wit = await fleetWitness({
    fleet: opts.pools.fleet,
    fetchImpl: opts.fetchImpl,
    now,
    budget: fleetGovernor(now),
    counters,
  });

  if (spec.corroboration === 'edge') {
    return {
      body: { jsonrpc: '2.0', id, result: capabilitiesJson(now()) },
      cacheState: 'bypass',
      status: 200,
      // Same shape as every other answer, including the salt, so a client
      // that honours `cache_salt` does not have to special-case this one.
      corroboration: {
        level: Level.Corroborated,
        source: 'edge',
        cache_salt: salt(),
        witness: witnessView(now()),
        plane: planeView(now()),
      },
    };
  }

  const params = payload.params ?? [];
  const rpcReq = { jsonrpc: '2.0', id, method, params };
  const epoch = wit && wit.ok && wit.chain ? Number(wit.chain.epoch) : null;
  const ctx = { salt: salt(), epoch };
  const key = cacheKeyFor(method, params, spec, ctx);

  // ── 3. cache ──────────────────────────────────────────────────────────────
  const hit = await readCache(opts.cache, key, spec, now(), false);
  if (hit) {
    counters.cacheHits += 1;
    return finish(hit.result, hit.meta, {
      id,
      spec,
      cacheState: 'hit',
      ageMs: hit.ageMs,
      now,
      archivalCount: opts.pools.archivals.length,
    });
  }
  counters.cacheMisses += 1;

  // ── 4. coalesce ───────────────────────────────────────────────────────────
  if (key && inFlight.has(key)) {
    counters.coalesced += 1;
    const shared = await inFlight.get(key);
    return { ...shared, cacheState: 'coalesced' };
  }

  const work = (async () => {
    // ── 5. governor ─────────────────────────────────────────────────────────
    const gov = archivalGovernor(now);
    // One token per upstream we are about to call, times what this method costs
    // that upstream. A walk is not the same size as a head read and must not be
    // charged as if it were; see the calibration on ARCHIVAL_RATE.
    const need =
      opts.pools.archivals.length * (spec.cost === Cost.Walk ? UPSTREAM_WALK_COST : 1);
    if (!gov.take(need)) {
      counters.archivalRefused += 1;
      // Prefer a dated stale answer to a refusal, but never silently: the
      // response says `cache: "stale"` and carries its age.
      const stale = await readCache(opts.cache, key, spec, now(), true);
      if (stale) {
        counters.staleServed += 1;
        return finish(stale.result, stale.meta, {
          id,
          spec,
          cacheState: 'stale',
          ageMs: stale.ageMs,
          now,
          archivalCount: opts.pools.archivals.length,
          degraded: 'upstream_budget_exhausted',
        });
      }
      const retry = gov.retryAfterMs(need);
      return {
        body: upstreamBudgetError(id, method, retry),
        cacheState: 'miss',
        status: 429,
        retryAfterMs: retry,
      };
    }

    // ── 6. archivals ────────────────────────────────────────────────────────
    const deadline = now() + (opts.budgetMs || 20_000);
    const { answers, attempts } = await askArchivals(rpcReq, opts.pools.archivals, {
      ...opts,
      witness: wit,
      deadline,
      single: isPinned(method),
    });

    if (!answers.length) {
      return { body: noAnswerError(id, method, attempts), cacheState: 'miss', status: 200 };
    }

    // A getchaininfo answer certifies the plane for free — it IS the probe.
    if (method === 'getchaininfo') {
      adoptPlane(answers, { ...opts, witness: wit, archivals: opts.pools.archivals });
    } else if (isBranchSensitive(method)) {
      await refreshPlane({ ...opts, archivals: opts.pools.archivals, witness: wit }, false);
    }

    // ── 7. corroborate ──────────────────────────────────────────────────────
    const groups = new Map();
    for (const a of answers) {
      const k = canonicalKey(a.value);
      const g = groups.get(k) || { value: a.value, votes: 0 };
      g.votes += 1;
      groups.set(k, g);
    }

    if (isBranchSensitive(method) && groups.size > 1) {
      // They disagree. This is the case the whole layer exists for. Do NOT
      // pick one — a wrong balance served with confidence is worse than an
      // "unavailable" the caller can retry.
      return { body: divergentError(id, method, groups.size), cacheState: 'miss', status: 200 };
    }

    const winner = [...groups.values()][0];
    if (winner.value.error) {
      // An error two nodes agree on is an answer. Do not cache it: the ones
      // that matter here (BLOCK_NOT_FOUND, SLOT_EMPTY) stop being true as the
      // chain advances.
      return { body: { jsonrpc: '2.0', id, ...winner.value }, cacheState: 'bypass', status: 200 };
    }

    // Is the plane fit to be served at all?
    const pv = planeView(now());
    if (
      isBranchSensitive(method) &&
      pv.reason &&
      (pv.reason === 'stale' || pv.reason === 'behind_witness' || pv.reason === 'contradicted_checkpoint')
    ) {
      return {
        body: staleError(id, method, {
          reason: pv.reason,
          behind_by_slots: pv.behind_by_slots,
          detail: pv.detail,
        }),
        cacheState: 'bypass',
        status: 200,
      };
    }

    const result = winner.value.result;
    if (method === 'getchaininfo' || method === 'getblockcount') observe(result, 'archival');

    // R5: a finalised slot whose block id contradicts what we hold.
    let finalised = false;
    if (method === 'getblockbyslot' && result && typeof result === 'object') {
      finalised = result.finalized === true;
      if (finalised) observeFinalSlot(result.slot, result.block_id);
    }
    if (method === 'getblockbyid' && result && typeof result === 'object') {
      finalised = result.finalized === true;
    }

    // ── write-back ──────────────────────────────────────────────────────────
    const meta = {
      answered_by: answers.length,
      fetched_at: now(),
      finalised,
      finality_as_answered: result && result.finality,
    };
    const writeTtl =
      spec.cacheClass === CacheClass.Lineage && finalised ? spec.finalTtlMs : spec.ttlMs;
    const p = writeCache(opts.cache, key, writeTtl, stripFinality(result), meta, now());
    if (opts.waitUntil) opts.waitUntil(p);
    else await p;
    if (opts.waitUntil) opts.waitUntil(saveLineage(opts.cache));

    return finish(stripFinality(result), meta, {
      id,
      spec,
      cacheState: 'miss',
      ageMs: 0,
      now,
      answers,
      archivalCount: opts.pools.archivals.length,
    });
  })();

  if (key) {
    inFlight.set(key, work);
    try {
      return await work;
    } finally {
      inFlight.delete(key);
    }
  }
  return work;
}

/**
 * Remove the node-relative finality fields before storing.
 *
 * They are re-derived on every serve (`rederiveFinality`). Storing them is how
 * a cache comes to assert a finality the chain has withdrawn.
 */
function stripFinality(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return result;
  if (!('finality' in result) && !('finalized' in result)) return result;
  const out = { ...result };
  delete out.finality;
  delete out.finalized;
  return out;
}

function finish(result, meta, o) {
  const now = o.now;
  const t = now();
  const withFinality = rederiveFinality(result, t);
  const corroboration = corroborationOf(
    o.spec,
    o.answers || new Array(meta.answered_by || 0).fill(null),
    {
      now: t,
      finalised: withFinality.finalized === true || meta.finalised === true,
      archivalCount: o.archivalCount,
      pinnedTo: (o.answers && o.answers.length === 1 && o.answers[0] && o.answers[0].url) || null,
    },
  );
  if (o.degraded) corroboration.degraded = o.degraded;
  if (o.cacheState === 'hit' || o.cacheState === 'stale') {
    corroboration.served_from_cache_age_ms = o.ageMs;
  }
  return {
    body: { jsonrpc: '2.0', id: o.id, result: withFinality },
    cacheState: o.cacheState,
    ageMs: o.ageMs,
    status: 200,
    corroboration,
  };
}

/**
 * Everything the read path needs from the Workers runtime.
 *
 * Lives here rather than in a route module so both routes can import it
 * without importing each other's handlers.
 */
export function runtimeFor(context) {
  return {
    fetchImpl: (...a) => fetch(...a),
    cache: typeof caches !== 'undefined' && caches.default ? caches.default : null,
    waitUntil: context && context.waitUntil ? (p) => context.waitUntil(p) : null,
    now: () => Date.now(),
  };
}

/** Everything the runtime front needs to build `opts`. */
export function buildOpts(env, request, runtime) {
  const pools = parsePools(env);
  return {
    pools,
    fetchImpl: runtime.fetchImpl,
    cache: runtime.cache,
    waitUntil: runtime.waitUntil,
    now: runtime.now,
    clientKey: clientKey(request),
    budgetMs: 20_000,
  };
}
