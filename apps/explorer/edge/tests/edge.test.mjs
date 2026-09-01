// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The read path, verified by VIOLATING it.
//
// Every test below drives the layer into a state it is supposed to refuse, and
// asserts on the refusal. A test that only proves the happy path proves that a
// cache returns cached things; the interesting question is what happens when
// the nodes behind it are wrong, slow, disagreeing, or gone — because that is
// when a public explorer either protects the chain and its readers, or does
// neither loudly.
//
// The measurements the numbers come from are stated at each test.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { handleRead, Level, _resetCoreForTests } from '../core.js';
import { salt, events, _setWitnessForTests, WITNESS_TTL_MS } from '../lineage.js';
import { ARCHIVAL_RATE, ARCHIVAL_BURST, WALK_COST, CLIENT_BURST, counters } from '../governor.js';
import {
  ARCHIVALS,
  FLEET,
  clock,
  fakeCache,
  fakeFetch,
  chainInfo,
  blockAt,
  reset,
  opts,
} from './harness.mjs';

/** Everyone healthy and agreeing. */
function healthy(over = {}) {
  const answer = (method, params) => {
    if (method === 'getchaininfo') return { result: chainInfo(over.chain) };
    if (method === 'getblockcount') return { result: { height: 33_697, slot: 54_592 } };
    if (method === 'getblockbyslot') return { result: blockAt(params[0], over.block) };
    if (method === 'getblockbyid') return { result: blockAt(54_540, over.block) };
    if (method === 'getbalance')
      return { result: { script_hash: params[0], balance_sat: '1000', utxo_count: 1 } };
    if (method === 'getvalidatorcount')
      return { result: { total: 64, active: 64, total_active_stake_sat: '1' } };
    if (method === 'getvalidator') return { result: { index: params[0], state: 'active' } };
    if (method === 'getmempoolinfo') return { result: { size: over.mempool ?? 0, max: 4096 } };
    return { error: { code: -32601, message: 'method not found' } };
  };
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) map[u] = answer;
  return map;
}

const call = (method, params = []) => ({ jsonrpc: '2.0', id: 1, method, params });

// ═══════════════════════════════════════════════════════════════════════════
// 1. THE LOAD THE FLEET SEES
// ═══════════════════════════════════════════════════════════════════════════

test('a hundred head polls cost the chain a bounded, countable number of calls', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const cache = fakeCache();
  const o = opts(f, now, cache);

  // A hundred readers, each from its own address, all polling the head in the
  // same second. This is the explorer's normal traffic shape, and it is
  // deliberately NOT one client hammering — that case is the rate-limit test
  // below, and mixing them would let the client limiter take the credit for a
  // bound the cache is supposed to provide.
  for (let i = 0; i < 100; i++) {
    await handleRead(call('getchaininfo'), { ...o, clientKey: `reader-${i}` });
  }

  // Two archival calls for the first miss, and ONE fleet call for the witness
  // shared by all hundred. Everything else is a cache hit.
  assert.equal(f.archival().length, 2, 'a cold head poll costs exactly one call per archival');
  assert.equal(f.fleet().length, 1, 'a hundred polls cost the validator set exactly one call');
  assert.equal(counters.cacheHits, 99);

  // The same run without this layer — the shape `src/lib/g4.ts` produces today
  // by talking to a passthrough — would be one call per poll.
  assert.ok(f.calls.length < 100 / 20, `${f.calls.length} upstream calls for 100 requests`);
});

test('the fleet is asked once per witness interval however long the traffic lasts', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const o = opts(f, now, fakeCache());

  // Ten minutes of steady polling, one request per second.
  for (let i = 0; i < 600; i++) {
    await handleRead(call('getchaininfo'), o);
    now.advance(1_000);
  }

  const fleetCalls = f.fleet().length;
  const expected = Math.ceil(600_000 / WITNESS_TTL_MS);
  assert.ok(
    fleetCalls <= expected + 1,
    `fleet saw ${fleetCalls} calls in ten minutes; the ceiling is ${expected}`,
  );
  // And it is spread across the fleet rather than landing on one validator.
  assert.ok(new Set(f.fleet().map((c) => c.url)).size > 1, 'the witness must rotate');
});

test('fifty concurrent cold requests are one upstream call, not fifty', async () => {
  reset();
  const now = clock();
  let inflight = 0;
  let peak = 0;
  const base = healthy();
  const slow = {};
  for (const u of Object.keys(base)) {
    slow[u] = (m, p) => {
      inflight += 1;
      peak = Math.max(peak, inflight);
      const r = base[u](m, p);
      inflight -= 1;
      return r;
    };
  }
  const f = fakeFetch(slow);
  const o = opts(f, now, fakeCache());

  await Promise.all(
    Array.from({ length: 50 }, (_, i) =>
      handleRead(call('getchaininfo'), { ...o, clientKey: `reader-${i}` }),
    ),
  );

  assert.equal(f.archival().length, 2, 'coalescing must collapse the cold-cache stampede');
  assert.ok(counters.coalesced >= 48, `only ${counters.coalesced} requests coalesced`);
});

test('a finalised block is fetched once and then never again', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy({ block: { finalized: true, finality: 'finalized' } }));
  const o = opts(f, now, fakeCache());

  await handleRead(call('getblockbyslot', [54_000]), o);
  const after = f.archival().length;

  // A day later. A finalised block is immutable relative to its lineage, so the
  // TTL is a week and the answer must still come from cache.
  now.advance(24 * 3_600_000);
  const again = await handleRead(call('getblockbyslot', [54_000]), o);
  assert.equal(again.cacheState, 'hit');
  assert.equal(f.archival().length, after, 'a finalised block must not be re-fetched');
});

test('an unfinalised block expires quickly — the head is not immutable', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy({ block: { finalized: false } }));
  const o = opts(f, now, fakeCache());

  await handleRead(call('getblockbyslot', [54_592]), o);
  const after = f.archival().length;
  now.advance(10_000); // past the 6 s unfinalised TTL
  const again = await handleRead(call('getblockbyslot', [54_592]), o);
  assert.equal(again.cacheState, 'miss');
  assert.ok(f.archival().length > after, 'an unfinalised block must be re-fetched');
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. VIOLATION: A DELIBERATELY STALE NODE
// ═══════════════════════════════════════════════════════════════════════════

test('a stale archival plane is refused, not served', async () => {
  reset();
  const now = clock();
  // Both archivals are forty slots — twenty minutes — behind the wall clock.
  // This is the exact shape of an isolated node: it answers instantly, its
  // answers are internally consistent, and they are old.
  const stale = chainInfo({ height: 33_000, slot: 54_552, wall_slot: 54_592, behind_by_slots: 40 });
  const map = {};
  for (const u of ARCHIVALS) {
    map[u] = (m, p) => {
      if (m === 'getchaininfo') return { result: stale };
      if (m === 'getbalance')
        return { result: { script_hash: p[0], balance_sat: '999', utxo_count: 1 } };
      return { result: {} };
    };
  }
  for (const u of FLEET) map[u] = () => ({ result: chainInfo() });

  const f = fakeFetch(map);
  const o = opts(f, now, fakeCache());

  const bal = await handleRead(call('getbalance', ['ab'.repeat(32)]), o);
  assert.ok(bal.body.error, 'a balance from a node twenty minutes behind must not be served');
  assert.equal(bal.body.error.code, -32011);
  assert.equal(bal.body.error.data.reason, 'stale');
  assert.equal(bal.body.error.data.behind_by_slots, 40);
  assert.ok(
    /not currently following the chain/.test(bal.body.error.message),
    'the message must say what is wrong in a sentence a person can act on',
  );
});

test('a slightly-behind plane is served but the answer says so', async () => {
  reset();
  const now = clock();
  // Two slots behind: normal. Not an error, but the caller is told.
  const behind = chainInfo({ height: 33_695, behind_by_slots: 2 });
  const map = {};
  for (const u of ARCHIVALS) map[u] = () => ({ result: behind });
  for (const u of FLEET) map[u] = () => ({ result: chainInfo({ height: 33_697 }) });

  const f = fakeFetch(map);
  const out = await handleRead(call('getchaininfo'), opts(f, now, fakeCache()));
  assert.ok(!out.body.error, 'two slots behind is not an error');
  assert.equal(out.corroboration.level, Level.Corroborated);
  assert.equal(out.corroboration.plane.behind_by_slots, 2);
});

test('an archival on a different lineage is refused as a contradiction, not as lag', async () => {
  reset();
  const now = clock();
  // The witness has finalized epoch 1704 at root bb…. The archivals claim a
  // DIFFERENT root at the same epoch. That is not staleness — a finalised
  // checkpoint is the one thing that is not supposed to be rewritable — so the
  // refusal must say so with a different reason.
  _setWitnessForTests({
    ok: true,
    at: now(),
    url: FLEET[0],
    chain: chainInfo({ finalized: { epoch: 1704, root: 'bb'.repeat(32) } }),
  });

  const forked = chainInfo({ finalized: { epoch: 1704, root: '99'.repeat(32) } });
  const map = {};
  for (const u of ARCHIVALS) {
    map[u] = (m, p) =>
      m === 'getchaininfo'
        ? { result: forked }
        : { result: { script_hash: p[0], balance_sat: '5', utxo_count: 1 } };
  }
  for (const u of FLEET) map[u] = () => ({ result: chainInfo() });

  const f = fakeFetch(map);
  const out = await handleRead(call('getbalance', ['cd'.repeat(32)]), opts(f, now, fakeCache()));
  assert.ok(out.body.error);
  assert.equal(out.body.error.data.reason, 'contradicted_checkpoint');
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. VIOLATION: THE TWO ARCHIVALS DISAGREE
// ═══════════════════════════════════════════════════════════════════════════

test('two archivals disagreeing on a balance is refused, never resolved by picking one', async () => {
  reset();
  const now = clock();
  const map = {
    [ARCHIVALS[0]]: (m, p) =>
      m === 'getchaininfo'
        ? { result: chainInfo() }
        : { result: { script_hash: p[0], balance_sat: '1000', utxo_count: 1 } },
    [ARCHIVALS[1]]: (m, p) =>
      m === 'getchaininfo'
        ? { result: chainInfo() }
        : { result: { script_hash: p[0], balance_sat: '0', utxo_count: 0 } },
  };
  for (const u of FLEET) map[u] = () => ({ result: chainInfo() });

  const f = fakeFetch(map);
  const out = await handleRead(call('getbalance', ['ef'.repeat(32)]), opts(f, now, fakeCache()));
  assert.ok(out.body.error, 'a balance two nodes disagree about must not be served');
  assert.equal(out.body.error.code, -32010);
  assert.equal(out.body.error.data.reason, 'divergent_archivals');
});

test('two archivals disagreeing about the MEMPOOL is normal and is served', async () => {
  reset();
  const now = clock();
  // Measured on this chain: one sweep of the fleet in a single minute returned
  // pending counts of 0, 1, 2, 4 and 5. Treating that as a fork would make the
  // mempool endpoint permanently unavailable.
  const map = {
    [ARCHIVALS[0]]: (m) => (m === 'getchaininfo' ? { result: chainInfo() } : { result: { size: 0 } }),
    [ARCHIVALS[1]]: (m) => (m === 'getchaininfo' ? { result: chainInfo() } : { result: { size: 5 } }),
  };
  for (const u of FLEET) map[u] = () => ({ result: chainInfo() });

  const f = fakeFetch(map);
  const out = await handleRead(call('getmempoolinfo'), opts(f, now, fakeCache()));
  assert.ok(!out.body.error, 'disagreement about a node-local number is not a fork');
  assert.equal(out.corroboration.level, Level.NodeLocal);
  assert.ok(/does not converge/.test(out.corroboration.note));
});

test('one archival down degrades to uncorroborated rather than to an error', async () => {
  reset();
  const now = clock();
  const map = { [ARCHIVALS[0]]: healthy()[ARCHIVALS[0]], [ARCHIVALS[1]]: 'timeout' };
  for (const u of FLEET) map[u] = () => ({ result: chainInfo() });

  const f = fakeFetch(map);
  const out = await handleRead(call('getchaininfo'), opts(f, now, fakeCache()));
  assert.ok(!out.body.error, 'one surviving archival is still an answer');
  assert.equal(out.corroboration.level, Level.Uncorroborated);
  assert.ok(out.corroboration.missing.some((m) => /only one archival/.test(m)));
});

test('no fleet witness degrades to uncorroborated, and says which witness is missing', async () => {
  reset();
  const now = clock();
  const map = healthy();
  for (const u of FLEET) map[u] = 'timeout';

  const f = fakeFetch(map);
  const out = await handleRead(call('getchaininfo'), opts(f, now, fakeCache()));
  assert.ok(!out.body.error);
  assert.equal(out.corroboration.level, Level.Uncorroborated);
  assert.ok(out.corroboration.missing.some((m) => /fleet witness/.test(m)));
  assert.equal(out.corroboration.witness.available, false);
});

test('both archivals down is an EDGE fault and says the chain may be fine', async () => {
  reset();
  const now = clock();
  const map = {};
  for (const u of ARCHIVALS) map[u] = 'timeout';
  for (const u of FLEET) map[u] = () => ({ result: chainInfo() });

  const f = fakeFetch(map);
  const out = await handleRead(call('getchaininfo'), opts(f, now, fakeCache()));
  assert.equal(out.body.error.data.reason, 'no_upstream_answered');
  assert.equal(out.body.error.data.chainStatusKnown, false);
  assert.ok(
    /NOT a statement about Genesis-4/.test(out.body.error.message),
    'the old defect was passing a node fault to the public as a chain fault',
  );
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. VIOLATION: PAST THE RATE LIMIT
// ═══════════════════════════════════════════════════════════════════════════

test('a client past its limit gets 429, a Retry-After, and a reason it can branch on', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const o = opts(f, now, fakeCache());

  // The SAME slot every time, so every call after the first is a cache hit and
  // the upstream governor is never touched. What stops this loop can only be
  // the client's own bucket — which is the thing under test. Asking for a
  // different slot each time would hit the upstream ceiling first and the test
  // would pass while proving the wrong bound.
  let throttled = null;
  for (let i = 0; i < CLIENT_BURST + 10; i++) {
    const out = await handleRead(call('getblockbyslot', [50_000]), o);
    if (out.status === 429) {
      throttled = out;
      break;
    }
  }
  assert.ok(throttled, 'a client must eventually be throttled');
  assert.equal(throttled.body.error.code, -32029);
  assert.equal(throttled.body.error.data.reason, 'rate_limited');
  assert.ok(throttled.retryAfterMs > 0, 'a throttle must say when to come back');
  assert.ok(
    /run your own node/.test(throttled.body.error.message),
    'a public limit should tell the caller how to stop being limited',
  );
});

test('a walk costs eight times a head poll, so one caller cannot spend the budget on balances', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const o = opts(f, now, fakeCache());

  let n = 0;
  for (; n < 100; n++) {
    const out = await handleRead(call('getbalance', [`${n}`.padStart(64, '0')]), o);
    if (out.status === 429) break;
  }
  assert.ok(
    n <= Math.ceil(CLIENT_BURST / WALK_COST) + 1,
    `${n} full-set walks were allowed on one burst; the price is ${WALK_COST} tokens each`,
  );
});

test('past the upstream budget the edge serves a DATED stale answer rather than calling out', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const cache = fakeCache();
  const o = opts(f, now, cache);

  // Warm one entry, then let its TTL expire.
  await handleRead(call('getchaininfo'), o);
  now.advance(5_000);

  // Burn the isolate's upstream budget with distinct, uncacheable-by-key calls
  // from many clients, so the client limiter is not what stops us.
  for (let i = 0; i < ARCHIVAL_BURST * 2; i++) {
    await handleRead(call('getblockbyslot', [40_000 + i]), { ...o, clientKey: `c${i}` });
  }

  const out = await handleRead(call('getchaininfo'), { ...o, clientKey: 'someone-else' });
  assert.ok(
    out.cacheState === 'stale' || out.body.error,
    'past the budget the edge must serve stale or refuse — never call out anyway',
  );
  if (out.cacheState === 'stale') {
    assert.ok(out.ageMs >= 5_000, 'a stale answer must carry its age');
    assert.equal(out.corroboration.degraded, 'upstream_budget_exhausted');
  } else {
    assert.equal(out.body.error.code, -32030);
  }
});

test('the upstream ceiling holds no matter how many clients arrive', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const o = opts(f, now, fakeCache());

  // A thousand requests from a thousand different addresses, all distinct
  // slots so nothing can be answered from cache, all inside one second. This
  // is the shape of the incident: a sweep of every slot, all at once.
  await Promise.all(
    Array.from({ length: 1000 }, (_, i) =>
      handleRead(call('getblockbyslot', [10_000 + i]), { ...o, clientKey: `client-${i}` }),
    ),
  );

  const archival = f.archival().length;
  const ceiling = (ARCHIVAL_BURST + ARCHIVAL_RATE) * 2 + 4; // burst + a second of refill, two calls each
  assert.ok(
    archival <= ceiling,
    `1000 requests produced ${archival} upstream calls; the ceiling is ${ceiling}. ` +
      `This is the property the whole layer exists for.`,
  );
  assert.ok(counters.archivalRefused > 0, 'the governor must have refused something');
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. REORGS AND THE CACHE SALT
// ═══════════════════════════════════════════════════════════════════════════

test('R1: a rewritten finalised root burns the cache salt', async () => {
  reset();
  const now = clock();
  let root = 'bb'.repeat(32);
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) {
    map[u] = () => ({ result: chainInfo({ finalized: { epoch: 1704, root } }) });
  }
  const f = fakeFetch(map);
  const cache = fakeCache();
  const o = opts(f, now, cache);

  await handleRead(call('getchaininfo'), o);
  const before = salt();

  // Same epoch, different root. A finalised checkpoint has been rewritten.
  root = '77'.repeat(32);
  now.advance(WITNESS_TTL_MS + 1_000);
  await handleRead(call('getchaininfo'), o);

  assert.ok(salt() > before, 'a contradicted finalised checkpoint must burn the salt');
  assert.ok(events().some((e) => e.signal === 'R1'), 'the event must be recorded and reportable');
  assert.ok(events().some((e) => e.signal === 'BURN'));
});

test('R2: finality descending — measured on this chain — burns the salt', async () => {
  reset();
  const now = clock();
  let finEpoch = 1704;
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) {
    map[u] = () => ({ result: chainInfo({ finalized: { epoch: finEpoch, root: `${finEpoch}`.padStart(64, '0') } }) });
  }
  const f = fakeFetch(map);
  const o = opts(f, now, fakeCache());

  await handleRead(call('getchaininfo'), o);
  const before = salt();

  // n01 finalised e651 and later served e160. `finalized` is not a latch here,
  // which is exactly why it is not a cache key on its own.
  finEpoch = 1600;
  now.advance(WITNESS_TTL_MS + 1_000);
  await handleRead(call('getchaininfo'), o);

  assert.ok(salt() > before, 'descending finality must burn the salt');
  assert.ok(events().some((e) => e.signal === 'R2'));
});

test('a burned salt orphans the cache, and a finalised block survives it', async () => {
  reset();
  const now = clock();
  let root = 'bb'.repeat(32);
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) {
    map[u] = (m, p) => {
      if (m === 'getchaininfo') return { result: chainInfo({ finalized: { epoch: 1704, root } }) };
      if (m === 'getblockbyslot') return { result: blockAt(p[0], { finalized: true, finality: 'finalized' }) };
      if (m === 'getblockbyid') return { result: blockAt(54_000, { finalized: true, finality: 'finalized' }) };
      return { result: {} };
    };
  }
  const f = fakeFetch(map);
  const cache = fakeCache();
  const o = opts(f, now, cache);

  await handleRead(call('getblockbyslot', [54_000]), o);
  await handleRead(call('getblockbyid', ['ab'.repeat(32)]), o);
  f.reset();

  root = '77'.repeat(32);
  now.advance(WITNESS_TTL_MS + 1_000);
  await handleRead(call('getchaininfo'), o);
  f.reset();

  // The slot answer was a fork-choice answer. It must be re-fetched.
  const bySlot = await handleRead(call('getblockbyslot', [54_000]), o);
  assert.equal(bySlot.cacheState, 'miss', 'a lineage-bound answer must not survive a reorg');

  // The block-by-id answer is content-addressed. A reorg cannot make that id
  // name a different block, so throwing it away would be superstition.
  const byId = await handleRead(call('getblockbyid', ['ab'.repeat(32)]), o);
  assert.equal(byId.cacheState, 'hit', 'a content-addressed answer must survive a reorg');
});

test('R5: a finalised slot whose block id changed is caught even with no checkpoint signal', async () => {
  reset();
  const now = clock();
  let bid = '01'.repeat(32);
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) {
    map[u] = (m, p) => {
      if (m === 'getchaininfo') return { result: chainInfo() };
      return { result: blockAt(p[0] ?? 54_000, { finalized: true, finality: 'finalized', block_id: bid }) };
    };
  }
  const f = fakeFetch(map);
  const o = opts(f, now, fakeCache());

  await handleRead(call('getblockbyslot', [54_000]), o);
  const before = salt();

  // The same finalised slot now holds a different block, while both checkpoints
  // look untouched. Nothing but a direct contradiction can catch this.
  bid = '02'.repeat(32);
  now.advance(10 * 24 * 3_600_000); // past even the finalised TTL
  await handleRead(call('getblockbyslot', [54_000]), o);

  assert.ok(salt() > before, 'a contradicted finalised slot must burn the salt');
  assert.ok(events().some((e) => e.signal === 'R5'));
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. FINALITY IS NEVER SERVED FROM CACHE
// ═══════════════════════════════════════════════════════════════════════════

test('a cached block never carries a stale finality claim', async () => {
  reset();
  const now = clock();
  // The node answered "canonical, not finalized" when we fetched it. Later the
  // witness shows the finalised line has moved past that height. The cached
  // block must say `finalized: true` — recomputed — not the stored `false`.
  const map = {};
  let finalizedHeight = 33_000;
  for (const u of [...ARCHIVALS, ...FLEET]) {
    map[u] = (m, p) => {
      if (m === 'getchaininfo') return { result: chainInfo({ finalized_height: finalizedHeight }) };
      return { result: blockAt(p[0] ?? 54_000, { height: 33_100, finalized: false, finality: 'canonical' }) };
    };
  }
  const f = fakeFetch(map);
  const o = opts(f, now, fakeCache());

  // Addressed by id, so the entry lives a week and the six-second head TTL
  // cannot be what makes the second call a miss.
  const first = await handleRead(call('getblockbyid', ['ab'.repeat(32)]), o);
  assert.equal(first.body.result.finalized, false);
  assert.equal(first.body.result.finality_source, 'recomputed_from_fleet_witness');

  finalizedHeight = 33_500; // the chain finalised past it
  now.advance(WITNESS_TTL_MS + 1_000);
  await handleRead(call('getchaininfo'), o);

  const second = await handleRead(call('getblockbyid', ['ab'.repeat(32)]), o);
  assert.equal(second.cacheState, 'hit', 'the block itself is unchanged and comes from cache');
  assert.equal(second.body.result.finalized, true, 'finality must be recomputed, not replayed');
});

test('with no witness a block says finality is unknown, not false', async () => {
  reset();
  const now = clock();
  const map = healthy();
  for (const u of FLEET) map[u] = 'timeout';
  const f = fakeFetch(map);

  const out = await handleRead(call('getblockbyslot', [54_000]), opts(f, now, fakeCache()));
  assert.equal(out.body.result.finalized, null, 'null is an absence; false would be a claim');
  assert.equal(out.body.result.finality, 'unknown');
  assert.equal(out.body.result.finality_source, 'no_witness');
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. THE SURFACE ITSELF
// ═══════════════════════════════════════════════════════════════════════════

test('a Genesis-3 method is refused with the allowed list, not silently forwarded', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const out = await handleRead(call('getsupplydistribution'), opts(f, now, fakeCache()));
  assert.equal(out.body.error.code, -32601);
  assert.ok(out.body.error.data.allowed.includes('getchaininfo'));
  assert.equal(f.archival().length, 0, 'a refused method must cost the chain nothing');
});

test('the write method is refused at the edge and never reaches a node', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const out = await handleRead(call('sendrawtransaction', ['00']), opts(f, now, fakeCache()));
  assert.equal(out.body.error.data.reason, 'deliberately_absent');
  assert.ok(/READ-ONLY/.test(out.body.error.message));
  assert.equal(f.calls.length, 0);
});

test('getcapabilities is answered by the edge because no live node has it', async () => {
  reset();
  const now = clock();
  // Measured 2026-09-01: all nine deployed upstreams answer -32601 to this
  // name, which is frozen into the node's RPC_SURFACE at surface version 4.1.0
  // and exists in no running binary. Forwarding it would return
  // method-not-found for a method this edge does implement.
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) {
    map[u] = (m) =>
      m === 'getchaininfo'
        ? { result: chainInfo() }
        : { error: { code: -32601, message: 'method not found: getcapabilities' } };
  }
  const f = fakeFetch(map);
  const out = await handleRead(call('getcapabilities'), opts(f, now, fakeCache()));
  assert.ok(out.body.result, 'the edge must answer this itself');
  assert.equal(f.ofMethod('getcapabilities').length, 0, 'and must not forward it');
  assert.ok(out.body.result.methods.length >= 12);
  assert.ok(out.body.result.honesty.some((h) => /does not validate/.test(h)));
});

test('the corroboration level is on every answer, cached or not', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const o = opts(f, now, fakeCache());
  for (const m of ['getchaininfo', 'getblockcount', 'getvalidatorcount', 'getmempoolinfo']) {
    const fresh = await handleRead(call(m), o);
    assert.ok(fresh.corroboration && fresh.corroboration.level, `${m}: fresh answer has no level`);
    const cached = await handleRead(call(m), o);
    assert.ok(cached.corroboration && cached.corroboration.level, `${m}: cached answer has no level`);
  }
});

test('an epoch boundary invalidates validator records by construction', async () => {
  reset();
  const now = clock();
  let epoch = 1704;
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) {
    map[u] = (m, p) => {
      if (m === 'getchaininfo') return { result: chainInfo({ epoch }) };
      return { result: { index: p[0], state: 'active', epoch } };
    };
  }
  const f = fakeFetch(map);
  const o = opts(f, now, fakeCache());

  await handleRead(call('getvalidator', [7]), o);
  const before = f.archival().length;
  const same = await handleRead(call('getvalidator', [7]), o);
  assert.equal(same.cacheState, 'hit');

  epoch = 1705;
  now.advance(WITNESS_TTL_MS + 1_000);
  await handleRead(call('getchaininfo'), o);
  const next = await handleRead(call('getvalidator', [7]), o);
  assert.equal(next.cacheState, 'miss', 'an epoch boundary must invalidate, not a TTL');
  assert.ok(f.archival().length > before);
});
