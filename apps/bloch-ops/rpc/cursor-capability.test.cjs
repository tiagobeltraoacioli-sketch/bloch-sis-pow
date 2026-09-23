// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { checkCursorCapability } = require('./cursor-capability.cjs');
const scriptHash = 'ab'.repeat(32);
const head = 'cd'.repeat(32);
const txid = '11'.repeat(32);
const txid2 = '22'.repeat(32);
const endpoint = 'http://127.0.0.1:16400/rpc';
const token = '01' + head + scriptHash + txid + '00000000';
const base = { script_hash: scriptHash, total: 2, returned: 1, truncated: true,
  utxos: [{ txid, vout: 0, value_sat: '42', script_hash: scriptHash }] };
function respond(result, id) { return new Response(JSON.stringify({ jsonrpc: '2.0', id, result })); }
function fixture(first, second, build = { features: ['utxo_cursor_v1'] }) {
  const calls = [];
  const fetcher = async (_url, options) => {
    const payload = JSON.parse(options.body);
    calls.push(payload);
    return respond(payload.method === 'getbuildinfo' ? build :
      calls.filter(call => call.method === 'getutxos').length === 1 ? first : second, payload.id);
  };
  return { calls, fetcher };
}
test('requires opt-in and validates arguments before any request', async () => {
  const { calls, fetcher } = fixture(base);
  await assert.rejects(checkCursorCapability({ rpc: endpoint, scriptHash, fetcher }), /opt-in/);
  await assert.rejects(checkCursorCapability({ rpc: endpoint, scriptHash: 'bad', optIn: true, fetcher }), /64-hex/);
  await assert.rejects(checkCursorCapability({ rpc: 'http://example.com/rpc', scriptHash, optIn: true, fetcher }), /HTTPS/);
  assert.equal(calls.length, 0);
});
test('one bounded read detects legacy response without claiming support', async () => {
  const { calls, fetcher } = fixture(base);
  const report = await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher });
  assert.equal(report.status, 'legacy_shape');
  assert.equal(report.request_count, 2);
  assert.deepEqual(calls.map(call => call.method), ['getbuildinfo', 'getutxos']);
  assert.deepEqual(calls[1].params, [scriptHash, 1, null]);
  assert.equal(report.marker_shape_relation, 'advertised_but_legacy');
});
test('empty extended page reports shape only', async () => {
  const { calls, fetcher } = fixture({ ...base, total: 0, returned: 0, truncated: false, utxos: [], at_head: head, at_slot: 23, next_cursor: null });
  const report = await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher });
  assert.equal(report.status, 'cursor_shape_observed');
  assert.equal(calls.length, 2);
  const incomplete = fixture({ ...base, truncated: false, at_head: head, at_slot: 23, next_cursor: null });
  assert.equal((await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher: incomplete.fetcher })).status, 'invalid_response');
});
test('follows exactly one valid next cursor and verifies head and distinct output', async () => {
  const first = { ...base, at_head: head, at_slot: 23, next_cursor: token };
  const second = { ...base, returned: 1, truncated: false, utxos: [{ txid: txid2, vout: 0, value_sat: '5', script_hash: scriptHash }], at_head: head, at_slot: 23, next_cursor: null };
  const { calls, fetcher } = fixture(first, second);
  const report = await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher });
  assert.equal(report.status, 'two_pages_observed');
  assert.equal(report.request_count, 3);
  assert.deepEqual(calls[2].params, [scriptHash, 1, token]);
  assert.equal(report.marker_shape_relation, 'advertised_and_observed');
});
test('rejects malformed cursor fields and repeated output', async () => {
  for (const first of [
    { ...base, at_head: head, at_slot: 23, next_cursor: 'bad' },
    { ...base, at_head: head, at_slot: 23, next_cursor: token.replace(scriptHash, 'ff'.repeat(32)) },
    { ...base, at_head: head, at_slot: 23, next_cursor: null },
    { ...base, total: 1, at_head: head, at_slot: 23, next_cursor: token },
    { ...base, at_head: head, at_slot: '23', next_cursor: token },
  ]) {
    const { fetcher } = fixture(first);
    assert.equal((await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher })).status, 'invalid_response');
  }
  const { fetcher } = fixture({ ...base, at_head: head, at_slot: 23, next_cursor: token },
    { ...base, truncated: false, at_head: head, at_slot: 23, next_cursor: null });
  assert.equal((await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher })).status, 'invalid_response');
  const emptySecond = fixture({ ...base, at_head: head, at_slot: 23, next_cursor: token },
    { ...base, returned: 0, truncated: false, utxos: [], at_head: head, at_slot: 23, next_cursor: null });
  assert.equal((await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher: emptySecond.fetcher })).status, 'invalid_response');
});
test('reports RPC method error as unavailable and stale head separately', async () => {
  const unavailable = async (_url, options) => new Response(JSON.stringify({ jsonrpc: '2.0', id: JSON.parse(options.body).id, error: { code: -32601, message: 'Method not found' } }));
  assert.equal((await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher: unavailable })).status, 'unavailable');
  let n = 0;
  const stale = async (_url, options) => {
    const { id, method } = JSON.parse(options.body);
    if (method === 'getbuildinfo') return respond({ features: ['utxo_cursor_v1'] }, id);
    return ++n === 1 ? respond({ ...base, at_head: head, at_slot: 23, next_cursor: token }, id)
      : new Response(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32020, message: 'head changed' } }));
  };
  assert.equal((await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher: stale })).status, 'stale_head');
});
test('reports absent marker separately from observed cursor shape', async () => {
  const { fetcher, calls } = fixture({ ...base, total: 0, returned: 0, truncated: false, utxos: [], at_head: head, at_slot: 23, next_cursor: null }, undefined, {});
  const report = await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher });
  assert.equal(report.status, 'cursor_shape_observed');
  assert.equal(report.build_marker, 'absent');
  assert.equal(report.marker_shape_relation, 'unadvertised_but_observed');
  assert.equal(calls.length, 2);
});
test('malformed or unavailable build information cannot certify the marker and does not stop shape observation', async () => {
  for (const build of [{ features: 'utxo_cursor_v1' }, { features: Array(65).fill('x') }, { features: [5] }]) {
    const { fetcher } = fixture(base, undefined, build);
    const report = await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher });
    assert.equal(report.build_marker, 'invalid_response');
    assert.equal(report.marker_shape_relation, 'marker_unknown');
    assert.equal(report.status, 'legacy_shape');
  }
  const fetcher = async (_url, options) => {
    const { id, method } = JSON.parse(options.body);
    return method === 'getbuildinfo'
      ? new Response(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } }))
      : respond(base, id);
  };
  const report = await checkCursorCapability({ rpc: endpoint, scriptHash, optIn: true, fetcher });
  assert.equal(report.build_marker, 'unavailable');
  assert.equal(report.status, 'legacy_shape');
  assert.equal(report.request_count, 2);
});
