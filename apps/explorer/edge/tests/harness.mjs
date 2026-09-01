// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The test harness: a fake clock, a fake Cache API, a counting fake fetch.
//
// Everything the read path touches is injected, so every test below runs with
// no network and no Workers runtime — which is why they can assert on the
// EXACT number of upstream calls a sequence produces. That number is the
// safety property this layer exists to bound, and a test that could not count
// it would not be testing the thing that matters.

import { _resetPoolForTests } from '../pool.js';
import { _resetLineageForTests, _setWitnessForTests } from '../lineage.js';
import { _resetGovernorForTests, counters } from '../governor.js';
import { _resetCoreForTests } from '../core.js';

export const ARCHIVALS = ['http://arch-a/', 'http://arch-b/'];
export const FLEET = ['http://fleet-1/', 'http://fleet-2/'];

/** A clock you move by hand. */
export function clock(start = 1_700_000_000_000) {
  let t = start;
  const now = () => t;
  now.advance = (ms) => {
    t += ms;
  };
  now.set = (v) => {
    t = v;
  };
  return now;
}

/** A Cache API stand-in. Only match/put, which is all the read path uses. */
export function fakeCache() {
  const store = new Map();
  return {
    store,
    async match(req) {
      const hit = store.get(req.url);
      if (!hit) return undefined;
      return new Response(hit.body, { headers: hit.headers });
    },
    async put(req, res) {
      const headers = {};
      res.headers.forEach((v, k) => {
        headers[k] = v;
      });
      store.set(req.url, { body: await res.text(), headers });
    },
  };
}

/**
 * A fake fetch driven by a per-URL responder.
 *
 * `responders` maps upstream url -> (method, params) => one of
 *   { result }            an answer
 *   { error: {...} }      a JSON-RPC error
 *   'timeout'             an aborted request
 *   'http500'             a bad HTTP status
 *
 * Every call is recorded in `calls`, which is the point.
 */
export function fakeFetch(responders) {
  const calls = [];
  const impl = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, method: body.method, params: body.params });
    const r = responders[url];
    const out = typeof r === 'function' ? r(body.method, body.params) : r;
    if (out === 'timeout') throw Object.assign(new Error('abort'), { name: 'AbortError' });
    if (out === 'http500') return { ok: false, status: 500, text: async () => '' };
    if (out === undefined || out === null) {
      return { ok: true, text: async () => JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'method not found' } }) };
    }
    return { ok: true, text: async () => JSON.stringify({ jsonrpc: '2.0', id: 1, ...out }) };
  };
  impl.calls = calls;
  impl.to = (url) => calls.filter((c) => c.url === url);
  impl.ofMethod = (m) => calls.filter((c) => c.method === m);
  impl.archival = () => calls.filter((c) => ARCHIVALS.includes(c.url));
  impl.fleet = () => calls.filter((c) => FLEET.includes(c.url));
  impl.reset = () => {
    calls.length = 0;
  };
  return impl;
}

/** A plausible getchaininfo result, of the exact shape the live nodes return. */
export function chainInfo(over = {}) {
  const height = over.height ?? 33_697;
  const slot = over.slot ?? 54_592;
  const finEpoch = over.finEpoch ?? 1704;
  return {
    block_id: over.block_id ?? 'ece8aef739ff4df1fcc78efd52e230b87c4fe2edf4979e412621838dcd77a673',
    slot,
    height,
    finalized_height: over.finalized_height ?? height - 65,
    epoch: over.epoch ?? Math.floor(slot / 32),
    slot_in_epoch: slot % 32,
    slots_per_epoch: 32,
    state_root: over.state_root ?? 'd5447f25e17a0cdfbd2ef137d4083a1319ebfa6d966772d809cc2c543d2d81fb',
    justified: over.justified ?? { epoch: finEpoch + 1, root: 'aa'.repeat(32) },
    finalized: over.finalized ?? { epoch: finEpoch, root: 'bb'.repeat(32) },
    previous_justified: { epoch: finEpoch, root: 'bb'.repeat(32) },
    validators: { total: 64, active: 64 },
    total_active_stake_sat: '13453761791667636',
    base_fee_millisat_per_gas: '10',
    next_base_fee_millisat_per_gas: '10',
    mempool: 0,
    blocks_known: height,
    wall_slot: over.wall_slot ?? slot,
    behind_by_slots: over.behind_by_slots ?? 0,
  };
}

/** A block, of the exact shape getblockbyslot returns on the live chain. */
export function blockAt(slot, over = {}) {
  return {
    block_id: over.block_id ?? `${slot}`.padStart(64, '0'),
    version: 2_970_353_669,
    parent: `${slot - 1}`.padStart(64, '0'),
    slot,
    epoch: Math.floor(slot / 32),
    height: over.height ?? slot - 20_895,
    proposer_index: over.proposer_index ?? 4,
    timestamp: 1_788_292_879,
    state_root: 'cc'.repeat(32),
    body_root: 'dd'.repeat(32),
    randao_reveal: 'ee'.repeat(32),
    randao_mix: 'ff'.repeat(32),
    justified_root: 'aa'.repeat(32),
    finalized_root: 'bb'.repeat(32),
    attestation_root: '11'.repeat(32),
    coherence_root: '22'.repeat(32),
    finality: over.finality ?? 'canonical',
    finalized: over.finalized ?? false,
    tx_count: 0,
    attestation_count: 2,
  };
}

/** Reset every module-scoped isolate state between tests. */
export function reset() {
  _resetPoolForTests();
  _resetLineageForTests();
  _resetGovernorForTests();
  _resetCoreForTests();
}

export { counters, _setWitnessForTests };

/** Build the `opts` the read path takes. */
export function opts(fetchImpl, now, cache, over = {}) {
  return {
    pools: { archivals: ARCHIVALS, fleet: FLEET },
    fetchImpl,
    cache,
    waitUntil: null,
    now,
    clientKey: 'test-client',
    budgetMs: 20_000,
    ...over,
  };
}
