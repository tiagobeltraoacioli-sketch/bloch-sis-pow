// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The fleet witness, the lineage memo, reorg detection, and the cache salt.
//
// ═══════════════════════════════════════════════════════════════════════════
// WHY `finalized` IS NOT A CACHE KEY
// ═══════════════════════════════════════════════════════════════════════════
//
// The obvious design is "a finalised block never changes, so cache it
// forever". On this chain that is false as stated, and it has been measured
// false: nodes have been observed BELOW their own previously finalised
// checkpoint — n01 finalised epoch e651 and later served e160 — because
// `FcStore::head` ratchets downward. Whatever the cause, the consequence for a
// cache is the same: a node saying `finalized: true` at time T is not a
// promise that the same node will say it at time T+1, and it is certainly not
// a promise about the block CONTENT at that slot.
//
// So this file does not treat finality as a latch. It treats it as an
// OBSERVATION about a lineage, records the lineage, and notices when the
// lineage is contradicted.
//
// ═══════════════════════════════════════════════════════════════════════════
// WHAT IS ACTUALLY IMMUTABLE
// ═══════════════════════════════════════════════════════════════════════════
//
// Exactly one thing, and it needs no witness at all: a block addressed by its
// own id. `getblockbyid(X)` cannot come to mean a different block, because X
// is a hash of the block. That is why `getblockbyid` is cached hard and
// `getblockbyslot` is not — "which block sits at slot S" is a fork-choice
// answer and fork choice is exactly what a reorg changes.
//
// Everything else is cached UNDER A SALT. The salt is a small integer mixed
// into every cache key. Burning it (salt + 1) orphans the entire cache in one
// write, which is the only way to invalidate in bulk on a platform whose Cache
// API has no purge-by-prefix. A reorg burns the salt.
//
// ═══════════════════════════════════════════════════════════════════════════
// HOW A REORG IS DETECTED — the five signals, in order of strength
// ═══════════════════════════════════════════════════════════════════════════
//
//  R1  CONTRADICTED CHECKPOINT. We recorded root A for finalized epoch E, and
//      something now reports root B ≠ A for the same E. A finalised checkpoint
//      is supposed to be the one thing that cannot be rewritten, so this is
//      the strongest signal there is and it burns the salt unconditionally.
//      This is the signal that catches the measured descending-finality case:
//      the rewind ends with a DIFFERENT root at an epoch we already have.
//
//  R2  DESCENDING FINALITY. The witness's `finalized.epoch` is lower than the
//      highest finalized epoch we have recorded from that same plane. Legal
//      across a reorg on this chain, and precisely why we cannot latch. Burns
//      the salt: everything keyed on "this is final" was keyed on a claim the
//      chain has withdrawn.
//
//  R3  CONTRADICTED JUSTIFICATION. Same as R1 for the justified checkpoint.
//      Weaker — justification is meant to be reversible — so it does NOT burn
//      the salt; it is reported, and it downgrades corroboration to
//      `uncorroborated` for as long as it stands, because a chain rewriting
//      its justified root is a chain we should not be caching finality claims
//      from.
//
//  R4  RECEDING HEAD. Head height went down while the finalized epoch did not
//      change. An ordinary fork-choice switch. Does NOT burn the salt: nothing
//      above the finalised line is cached under a long TTL anyway, and burning
//      on every reorg of the tip would mean burning several times an hour for
//      no gain.
//
//  R5  CONTRADICTED SLOT. A slot we hold in cache as finalised comes back with
//      a different `block_id`. A direct contradiction of something we are
//      serving. Burns the salt, and is the only signal that can catch a
//      rewrite BELOW the checkpoints both planes report — see the honesty
//      section at the bottom for what that means.
//
// ═══════════════════════════════════════════════════════════════════════════
// WHAT THIS CANNOT DETECT
// ═══════════════════════════════════════════════════════════════════════════
//
//  - A reorg that happens and resolves entirely between two witness polls.
//    The window is WITNESS_TTL_MS and it is stated in every response as
//    `witness_age_ms`, so a caller can decide for itself.
//  - A rewrite the WHOLE observed population agrees on. If both archivals and
//    the witness box report the same new root at an epoch, R1 fires (we have
//    the old root) — but only if this isolate recorded the old root. A cold
//    isolate has no memory and cannot contradict anything.
//  - Anything about correctness. This layer corroborates; it does not
//    validate. It has no signatures, no state transition, and no opinion about
//    whether the majority is right. Two nodes agreeing on a wrong answer is
//    served as `corroborated`, and that is the honest limit of the design.
//  - A body that differs while the head lineage matches. Lineage corroboration
//    certifies WHERE an answer came from, not the bytes of the answer; the
//    bytes are covered separately by requiring two archivals to agree.
//  - R5 only fires on a RE-FETCH, and its own success suppresses it. A
//    finalised slot is cached for a week, so nothing asks about it again until
//    the entry is evicted; the better the cache works, the less often R5 gets
//    the chance to contradict itself. That is a real limit and not a bug to
//    fix by re-asking on a timer — re-asking would put the load back. R1 and
//    R2 are the signals that carry the weight; R5 is the backstop that catches
//    what they cannot see, when it happens to look.

import { attemptOne, order, markSick, markWell, ATTEMPT_TIMEOUT_MS } from './pool.js';

/**
 * How long a fleet witness is reused before another is asked.
 *
 * 20 s is under one slot (30 s), so the witness is never more than about
 * two-thirds of a slot stale, and it caps fleet load at 3 calls/minute per
 * isolate against ONE validator, whatever the public does.
 */
export const WITNESS_TTL_MS = 20_000;

/**
 * How far behind the witness an archival may be and still be served.
 *
 * Four slots — two minutes. Above this the archival is not "a bit behind", it
 * has stopped following, and serving its head as the chain's head is how a
 * reader is shown a two-hour-old balance with no indication that it is old.
 * The node hands us `behind_by_slots` directly, so this needs no arithmetic on
 * wall clocks we do not control.
 */
export const STALE_SLOTS = 4;

/** Epoch→root pairs kept. 64 epochs is about eighteen hours at 32 slots/epoch. */
const MEMO_MAX = 64;

/** Where the salt and the memo persist between isolates. */
const LINEAGE_CACHE_KEY = 'https://bloch-explorer.edge/lineage/v1';

/**
 * Isolate-local mirror of the persisted record.
 *
 * `{ salt, finalized: {epoch: root}, justified: {epoch: root}, maxFinalEpoch,
 *    maxHeight, slots: {slot: block_id}, events: [...] }`
 */
let memo = freshMemo();
let witness = null; // { chain, at, url, ok }
let witnessInFlight = null;

function freshMemo() {
  return {
    salt: 0,
    finalized: Object.create(null),
    justified: Object.create(null),
    maxFinalEpoch: -1,
    maxHeight: -1,
    slots: Object.create(null),
    events: [],
    loaded: false,
  };
}

export function _resetLineageForTests() {
  memo = freshMemo();
  witness = null;
  witnessInFlight = null;
}

/** The current salt. Every cache key is built with it. */
export function salt() {
  return memo.salt;
}

/** The last few reorg events this isolate saw, newest first. */
export function events() {
  return memo.events.slice(0, 8);
}

function record(event) {
  memo.events.unshift({ ...event, at: event.at ?? Date.now() });
  memo.events.length = Math.min(memo.events.length, 16);
}

function trim(map) {
  const keys = Object.keys(map)
    .map(Number)
    .sort((a, b) => b - a);
  for (const k of keys.slice(MEMO_MAX)) delete map[k];
}

/**
 * Fold one observation of a chain head into the memo.
 *
 * `plane` is 'witness' or 'archival' — R2 only fires on the witness plane,
 * because an archival being behind is normal and is handled as staleness, not
 * as a rewind.
 *
 * Returns the list of signals that fired.
 */
export function observe(chain, plane) {
  const signals = [];
  if (!chain) return signals;

  const fin = chain.finalized;
  if (fin && Number.isFinite(Number(fin.epoch)) && typeof fin.root === 'string') {
    const e = Number(fin.epoch);
    const known = memo.finalized[e];
    if (known !== undefined && known !== fin.root) {
      signals.push({
        signal: 'R1',
        kind: 'contradicted_checkpoint',
        epoch: e,
        was: known,
        now: fin.root,
        plane,
      });
    }
    memo.finalized[e] = fin.root;
    trim(memo.finalized);
    if (plane === 'witness') {
      if (memo.maxFinalEpoch >= 0 && e < memo.maxFinalEpoch) {
        signals.push({
          signal: 'R2',
          kind: 'descending_finality',
          epoch: e,
          was: memo.maxFinalEpoch,
          plane,
        });
      }
      if (e > memo.maxFinalEpoch) memo.maxFinalEpoch = e;
    }
  }

  const jus = chain.justified;
  if (jus && Number.isFinite(Number(jus.epoch)) && typeof jus.root === 'string') {
    const e = Number(jus.epoch);
    const known = memo.justified[e];
    if (known !== undefined && known !== jus.root) {
      signals.push({
        signal: 'R3',
        kind: 'contradicted_justification',
        epoch: e,
        was: known,
        now: jus.root,
        plane,
      });
    }
    memo.justified[e] = jus.root;
    trim(memo.justified);
  }

  const h = Number(chain.height);
  if (plane === 'witness' && Number.isFinite(h)) {
    if (memo.maxHeight >= 0 && h < memo.maxHeight) {
      signals.push({ signal: 'R4', kind: 'receding_head', was: memo.maxHeight, now: h, plane });
    }
    if (h > memo.maxHeight) memo.maxHeight = h;
  }

  return applySignals(signals);
}

/**
 * Fold one finalised slot→block_id observation. R5.
 *
 * Only call this for a slot the answering node reported as finalised; an
 * unfinalised slot changing its block is a normal fork-choice switch and
 * recording it would burn the salt several times an hour for nothing.
 */
export function observeFinalSlot(slot, blockId) {
  const s = Number(slot);
  if (!Number.isFinite(s) || typeof blockId !== 'string') return [];
  const known = memo.slots[s];
  const signals = [];
  if (known !== undefined && known !== blockId) {
    signals.push({ signal: 'R5', kind: 'contradicted_slot', slot: s, was: known, now: blockId });
  }
  memo.slots[s] = blockId;
  trim(memo.slots);
  return applySignals(signals);
}

/** R1, R2 and R5 burn the salt. R3 and R4 are reported only. */
const BURNS = new Set(['R1', 'R2', 'R5']);

function applySignals(signals) {
  let burn = false;
  for (const s of signals) {
    record(s);
    if (BURNS.has(s.signal)) burn = true;
  }
  if (burn) {
    memo.salt += 1;
    // Everything we believed about which block is where was believed under the
    // old lineage. Keep the checkpoint roots — they are the evidence — but drop
    // the slot map, or the next contradiction would be measured against a
    // lineage we have already abandoned.
    memo.slots = Object.create(null);
    record({ signal: 'BURN', kind: 'cache_salt_burned', salt: memo.salt });
  }
  return signals;
}

/**
 * True while a justification contradiction (R3) is recent enough that finality
 * claims from this population should not be trusted to hold.
 *
 * One epoch — 16 minutes — because that is the window in which a justified
 * checkpoint would normally have become finalised, and a chain that rewrote it
 * inside that window is a chain whose finality claims are in motion.
 */
export function justificationInDoubt(now) {
  const e = memo.events.find((x) => x.signal === 'R3');
  return !!e && now - e.at < 32 * 30_000;
}

/**
 * Load the persisted salt and memo, once per isolate.
 *
 * The persistence is best effort and racy across isolates: two isolates that
 * burn at the same moment write the same salt rather than two, and an isolate
 * that starts cold has no history and therefore cannot fire R1 or R5 until it
 * has seen an epoch twice. Both failure modes lose DETECTION, never
 * correctness — the worst outcome is a cache entry that lives out its TTL. A
 * design that needed to be exactly right here would need a Durable Object, and
 * that is a real dependency to add for a strictly-better-than-nothing memo.
 */
export async function loadLineage(cache) {
  if (memo.loaded || !cache) return;
  memo.loaded = true;
  try {
    const res = await cache.match(new Request(LINEAGE_CACHE_KEY, { method: 'GET' }));
    if (!res) return;
    const saved = await res.json();
    if (!saved || typeof saved.salt !== 'number') return;
    memo.salt = Math.max(memo.salt, saved.salt);
    Object.assign(memo.finalized, saved.finalized || {});
    Object.assign(memo.justified, saved.justified || {});
    Object.assign(memo.slots, saved.slots || {});
    memo.maxFinalEpoch = Math.max(memo.maxFinalEpoch, Number(saved.maxFinalEpoch ?? -1));
    memo.maxHeight = Math.max(memo.maxHeight, Number(saved.maxHeight ?? -1));
    if (Array.isArray(saved.events)) memo.events = saved.events.concat(memo.events).slice(0, 16);
  } catch {
    /* the memo is an optimisation for detection; never fail a call over it */
  }
}

export async function saveLineage(cache) {
  if (!cache) return;
  try {
    await cache.put(
      new Request(LINEAGE_CACHE_KEY, { method: 'GET' }),
      new Response(
        JSON.stringify({
          salt: memo.salt,
          finalized: memo.finalized,
          justified: memo.justified,
          slots: memo.slots,
          maxFinalEpoch: memo.maxFinalEpoch,
          maxHeight: memo.maxHeight,
          events: memo.events,
        }),
        { headers: { 'content-type': 'application/json', 'cache-control': 'max-age=86400' } },
      ),
    );
  } catch {
    /* ignore */
  }
}

/**
 * The fleet witness: one `getchaininfo` against one validator, shared.
 *
 * Everything about this function is about making its COST a constant:
 *   - one upstream, not a wave;
 *   - reused for WITNESS_TTL_MS;
 *   - concurrent callers share the one in-flight promise;
 *   - a failure is cached too, as `ok: false`, so a down fleet does not turn
 *     every request into a fresh 9-second attempt against a box that is down.
 *
 * `opts` = { fleet, fetchImpl, now, budget }. `budget` is the fleet governor;
 * when it refuses, the previous witness is returned however old it is, marked
 * with its age, and the caller degrades to `uncorroborated` on its own.
 */
export async function fleetWitness(opts) {
  const { fleet, fetchImpl, now } = opts;
  const t = now();
  if (witness && t - witness.at < WITNESS_TTL_MS) return witness;
  if (witnessInFlight) return witnessInFlight;
  if (!fleet.length) return witness || { ok: false, chain: null, at: t, url: null, reason: 'no_fleet_configured' };
  if (opts.budget && !opts.budget.take(1)) {
    return witness || { ok: false, chain: null, at: t, url: null, reason: 'fleet_budget_exhausted' };
  }

  const { order: ordered } = order(fleet, t);
  // Rotate, so one validator does not carry the whole witness load for the
  // lifetime of the isolate.
  const pick = ordered[Math.floor(t / WITNESS_TTL_MS) % ordered.length];

  if (opts.counters) opts.counters.fleetCalls += 1;
  witnessInFlight = (async () => {
    const r = await attemptOne(
      pick,
      { jsonrpc: '2.0', id: 1, method: 'getchaininfo', params: [] },
      ATTEMPT_TIMEOUT_MS,
      fetchImpl,
    );
    const at = now();
    if (r.settled && r.value.result) {
      markWell(pick);
      witness = { ok: true, chain: r.value.result, at, url: pick };
      observe(r.value.result, 'witness');
    } else {
      markSick(pick, at);
      witness = {
        ok: false,
        chain: witness && witness.chain ? witness.chain : null,
        at,
        url: pick,
        reason: r.settled ? 'rpc error' : r.outcome,
        // A carried-over chain is explicitly dated so nothing downstream can
        // mistake it for a fresh reading.
        chainAt: witness ? witness.at : null,
      };
    }
    witnessInFlight = null;
    return witness;
  })();

  return witnessInFlight;
}

/** The witness as callers should read it: never null, always dated. */
export function witnessView(now) {
  if (!witness) return { available: false, age_ms: null, height: null, url: null };
  const chain = witness.chain;
  return {
    available: !!(witness.ok && chain),
    age_ms: now - (witness.ok ? witness.at : witness.chainAt ?? witness.at),
    height: chain ? Number(chain.height) : null,
    slot: chain ? Number(chain.slot) : null,
    finalized_epoch: chain && chain.finalized ? Number(chain.finalized.epoch) : null,
    finalized_root: chain && chain.finalized ? chain.finalized.root : null,
    finalized_height: chain ? Number(chain.finalized_height) : null,
    reason: witness.ok ? null : witness.reason || 'unknown',
  };
}

/**
 * Does the answering archival's own head stand on the witness's lineage?
 *
 * Three questions, in the order that matters:
 *
 *  1. Does it contradict a checkpoint we know? If yes, this is not staleness,
 *     it is a different chain, and it must not be served as corroborated.
 *  2. Is it further behind than STALE_SLOTS? The node tells us directly with
 *     `behind_by_slots`, which is its own gap to wall-clock slot — the field
 *     exists for exactly this question.
 *  3. Is it behind the WITNESS by more than STALE_SLOTS of height? A node can
 *     have a current `behind_by_slots` and still be missing blocks if it is on
 *     a shorter branch.
 */
export function certify(archivalChain, wit, nowSlotTolerance = STALE_SLOTS) {
  if (!archivalChain) return { ok: false, reason: 'no_answer' };

  const fin = archivalChain.finalized;
  if (fin && typeof fin.root === 'string') {
    const known = memo.finalized[Number(fin.epoch)];
    if (known !== undefined && known !== fin.root) {
      return {
        ok: false,
        reason: 'contradicted_checkpoint',
        epoch: Number(fin.epoch),
        detail: `finalized epoch ${fin.epoch} root ${fin.root.slice(0, 12)} contradicts ${String(known).slice(0, 12)}`,
      };
    }
  }

  const behind = Number(archivalChain.behind_by_slots);
  if (Number.isFinite(behind) && behind > nowSlotTolerance) {
    return { ok: false, reason: 'stale', behind_by_slots: behind };
  }

  if (wit && wit.ok && wit.chain) {
    const gap = Number(wit.chain.height) - Number(archivalChain.height);
    if (Number.isFinite(gap) && gap > nowSlotTolerance) {
      return { ok: false, reason: 'behind_witness', behind_by_blocks: gap };
    }
    return { ok: true, witnessed: true };
  }
  return { ok: true, witnessed: false };
}

/** Test seam: install a witness without a network. */
export function _setWitnessForTests(w) {
  witness = w;
  if (w && w.ok && w.chain) observe(w.chain, 'witness');
}
