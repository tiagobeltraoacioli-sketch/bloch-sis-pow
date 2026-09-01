// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The public REST API, including its own violations.
//
// The two properties worth holding this API to:
//
//  1. NOTHING IS SERVED WITHOUT A CORROBORATION LEVEL. Not a block, not a
//     balance, not a range, not a cached answer. The reason `getchaininfo`
//     through `posternlabs.com/g4rpc` is soft is a good one — a wallet that
//     goes blank when the fleet disagrees is worse than one that shows a
//     dated number — but softness without a label is a number presented as a
//     fact. Here the label is structural.
//
//  2. NO ENDPOINT CAN BE MADE TO FAN OUT WITHOUT BOUND. `/blocks` is the shape
//     that caused the incident; `?limit=5000` must come back clamped, not
//     obeyed.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import { handleApi, MAX_RANGE, MAX_VALIDATORS } from '../api.js';
import { toScriptHash, displayAddress } from '../address.js';
import { addressFromHashHex, sha3_256, bytesToHex } from '../sha3.js';
import { ARCHIVALS, FLEET, clock, fakeCache, fakeFetch, chainInfo, blockAt, reset, opts } from './harness.mjs';

function healthy() {
  const answer = (method, params) => {
    if (method === 'getchaininfo') return { result: chainInfo() };
    if (method === 'getblockbyslot') {
      // Every third slot is empty — a missed proposal, which is normal.
      if (params[0] % 3 === 0) return { error: { code: -32007, message: 'slot empty' } };
      return { result: blockAt(params[0]) };
    }
    if (method === 'getblockbyid') return { result: blockAt(54_540) };
    if (method === 'getbalance')
      return { result: { script_hash: params[0], balance_sat: '1000', utxo_count: 1 } };
    if (method === 'getutxos')
      return { result: { script_hash: params[0], total: 1, returned: 1, truncated: false, utxos: [] } };
    if (method === 'getvalidatorcount')
      return { result: { total: 64, active: 64, total_active_stake_sat: '1' } };
    if (method === 'getvalidator') return { result: { index: params[0], state: 'active' } };
    if (method === 'getmempoolinfo') return { result: { size: 0, max: 4096 } };
    return { error: { code: -32601, message: 'method not found' } };
  };
  const map = {};
  for (const u of [...ARCHIVALS, ...FLEET]) map[u] = answer;
  return map;
}

const qs = (s) => new URLSearchParams(s);

test('every resource carries a corroboration level', async () => {
  reset();
  const now = clock();
  const o = opts(fakeFetch(healthy()), now, fakeCache());
  for (const path of [
    '/api/v1/status',
    '/api/v1/block/54541',
    '/api/v1/validators',
    '/api/v1/validator/3',
    '/api/v1/address/' + 'ab'.repeat(32),
    '/api/v1/mempool',
    '/api/v1/capabilities',
  ]) {
    const out = await handleApi(path, qs(''), o);
    assert.ok(out.body.corroboration, `${path}: no corroboration object`);
    assert.ok(out.body.corroboration.level, `${path}: no corroboration level`);
    assert.ok(out.body.chain, `${path}: no chain stamp`);
  }
});

test('a range is clamped, not obeyed', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const out = await handleApi('/api/v1/blocks', qs('from=54592&limit=5000'), opts(f, now, fakeCache()));
  assert.equal(out.body.requested.limit, MAX_RANGE);
  assert.ok(out.body.data.length <= MAX_RANGE, 'a range must never exceed its own maximum');
  // The incident shape was ~3,000 round trips from one poll. Twenty slots
  // against a two-node pool is at most forty calls, and fewer once warm.
  assert.ok(f.archival().length <= MAX_RANGE * 2 + 2, `${f.archival().length} upstream calls for one range`);
});

test('a range reports the WEAKEST of its items, not the best', async () => {
  reset();
  const now = clock();
  // The fleet is gone, so nothing can be better than uncorroborated. A range
  // that averaged, or took its best member, would hide that.
  const map = healthy();
  for (const u of FLEET) map[u] = 'timeout';
  const out = await handleApi('/api/v1/blocks', qs('from=54592&limit=5'), opts(fakeFetch(map), now, fakeCache()));
  assert.equal(out.body.corroboration.level, 'uncorroborated');
});

test('an empty slot reads as absence, not as an error', async () => {
  reset();
  const now = clock();
  const out = await handleApi('/api/v1/blocks', qs('from=54591&limit=6'), opts(fakeFetch(healthy()), now, fakeCache()));
  const empties = out.body.data.filter((d) => d.empty);
  assert.ok(empties.length > 0, 'a missed proposal must be represented');
  for (const e of empties) {
    assert.equal(e.block, null);
    assert.equal(e.error, null, 'a missed proposal is normal and is not an error');
  }
});

test('the validator list does not fan out by default', async () => {
  reset();
  const now = clock();
  const f = fakeFetch(healthy());
  const out = await handleApi('/api/v1/validators', qs(''), opts(f, now, fakeCache()));
  assert.deepEqual(out.body.data.records, []);
  assert.ok(/not returned by default/.test(out.body.note));
  assert.equal(f.ofMethod('getvalidator').length, 0, 'the default must ask for no records at all');

  const paged = await handleApi('/api/v1/validators', qs('from=0&limit=999'), opts(f, now, fakeCache()));
  assert.equal(paged.body.requested.limit, MAX_VALIDATORS);
});

test('a mistyped address is refused rather than answered with an empty balance', async () => {
  reset();
  const now = clock();
  // A real address with one character changed. Its script hash is perfectly
  // valid and holds nothing, so a proxy that stripped the checksum would answer
  // "0 BLOCH" with total confidence.
  const good = addressFromHashHex('e986db51'.padEnd(40, 'a'));
  const bad = good.slice(0, -1) + (good.slice(-1) === '0' ? '1' : '0');
  const out = await handleApi('/api/v1/address/' + bad, qs(''), opts(fakeFetch(healthy()), now, fakeCache()));
  assert.equal(out.status, 400);
  assert.equal(out.body.error.reason, 'bad_checksum');
  assert.ok(/empty balance for an address that was never yours/.test(out.body.error.detail));

  const ok = await handleApi('/api/v1/address/' + good, qs(''), opts(fakeFetch(healthy()), now, fakeCache()));
  assert.equal(ok.status, 200);
  assert.equal(ok.body.identity.given_as, 'address');
});

test('the three address forms reach the same script hash', async () => {
  const hash = 'e986db51'.padEnd(40, 'a');
  const addr = addressFromHashHex(hash);
  const padded = hash + '0'.repeat(24);
  assert.equal(toScriptHash(addr).scriptHash, padded);
  assert.equal(toScriptHash(hash).scriptHash, padded);
  assert.equal(toScriptHash(padded).scriptHash, padded);
  assert.equal(displayAddress(padded), addr);
  // And a 32-byte script hash that is NOT a padded hash-160 has no address.
  assert.equal(displayAddress('cd'.repeat(32)), null);
});

test('there is no write surface, and the 405 says where to go instead', async () => {
  reset();
  const now = clock();
  const out = await handleApi('/api/v1/sendrawtransaction', qs(''), opts(fakeFetch(healthy()), now, fakeCache()));
  assert.equal(out.status, 404);
  assert.ok(out.body.routes.every((r) => r.startsWith('GET ')));
});

test('an unknown api version is refused by name, not silently routed', async () => {
  reset();
  const now = clock();
  const out = await handleApi('/api/v2/status', qs(''), opts(fakeFetch(healthy()), now, fakeCache()));
  assert.equal(out.status, 404);
  assert.equal(out.body.error.reason, 'unknown_api_version');
});

test('a block cannot be addressed by height, and the refusal explains why', async () => {
  reset();
  const now = clock();
  const out = await handleApi('/api/v1/block/0x1234', qs(''), opts(fakeFetch(healthy()), now, fakeCache()));
  assert.equal(out.status, 400);
  assert.ok(/no block-by-height call/.test(out.body.error.detail));
});

test('a divergent balance is 503 — a retry, not a failure', async () => {
  reset();
  const now = clock();
  const map = {
    [ARCHIVALS[0]]: (m, p) =>
      m === 'getchaininfo' ? { result: chainInfo() } : { result: { script_hash: p[0], balance_sat: '1' } },
    [ARCHIVALS[1]]: (m, p) =>
      m === 'getchaininfo' ? { result: chainInfo() } : { result: { script_hash: p[0], balance_sat: '2' } },
  };
  for (const u of FLEET) map[u] = () => ({ result: chainInfo() });
  const out = await handleApi('/api/v1/address/' + 'ab'.repeat(32), qs(''), opts(fakeFetch(map), now, fakeCache()));
  assert.equal(out.status, 503, 'nodes disagreeing is "come back", not "something broke"');
  assert.equal(out.body.error.data.reason, 'divergent_archivals');
});

test('the mempool endpoint says out loud that it is node-local', async () => {
  reset();
  const now = clock();
  const out = await handleApi('/api/v1/mempool', qs(''), opts(fakeFetch(healthy()), now, fakeCache()));
  assert.equal(out.body.corroboration.level, 'node_local');
  assert.ok(/does not converge/.test(out.body.note));
});

test('SHA3-256 matches FIPS-202 and round-trips an address', () => {
  assert.equal(
    bytesToHex(sha3_256(new Uint8Array(0))),
    'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    'the empty-string vector pins this against FIPS-202 rather than against itself',
  );
  const hash = '00'.repeat(20);
  const addr = addressFromHashHex(hash);
  assert.match(addr, /^bloch1q[0-9a-f]{48}$/);
  assert.equal(toScriptHash(addr).scriptHash, hash + '0'.repeat(24));
  assert.equal(addressFromHashHex('nothex'), null);
});
