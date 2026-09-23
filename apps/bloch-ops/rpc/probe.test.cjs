// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { SAFE_METHODS, endpointUrl, runProbe } = require('./probe.cjs');
const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, 'catalog.v1.json'), 'utf8'));
const endpoint = 'http://127.0.0.1:16400/rpc';

function reply(payload, overrides = {}) {
  const spec = catalog.methods.find(m => m.name === payload.method);
  const result = Object.fromEntries(spec.result_fields.map(field => [field, null]));
  Object.assign(result, overrides);
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: payload.id, result }), { status: 200 });
}

test('accepts only HTTPS or loopback HTTP, without URL credentials or query', () => {
  assert.equal(endpointUrl(endpoint), endpoint);
  assert.throws(() => endpointUrl('http://example.org/rpc'), /HTTPS/);
  assert.throws(() => endpointUrl('https://user:pass@example.org/rpc'), /credentials/);
  assert.throws(() => endpointUrl('https://example.org/rpc?token=secret'), /query/);
});

test('observes only catalogued bounded read methods and reports response shapes', async () => {
  const seen = [];
  const fetcher = async (_url, options) => {
    const payload = JSON.parse(options.body);
    seen.push({ http_method: options.method, ...payload });
    return reply(payload, payload.method === 'getchaininfo' ? { height: 10, slot: 12, finalized_height: 8 } : {});
  };
  const report = await runProbe(endpoint, 1000, fetcher);
  assert.equal(report.compatible_shape_count, SAFE_METHODS.length);
  assert.deepEqual(seen.map(row => row.method), SAFE_METHODS);
  assert.ok(seen.every(row => row.http_method === 'POST' && row.jsonrpc === '2.0' && row.params.length === 0));
  assert.equal(report.diagnostics[0].observed.height, 10);
  assert.match(report.identity_note, /not remote attestation/);
});

test('reports RPC errors and missing catalog fields per method', async () => {
  const fetcher = async (_url, options) => {
    const payload = JSON.parse(options.body);
    if (payload.method === 'getbuildinfo') return new Response(JSON.stringify({ jsonrpc: '2.0', id: payload.id, error: { code: -32601, message: 'Method unavailable' } }));
    if (payload.method === 'getblockcount') return new Response(JSON.stringify({ jsonrpc: '2.0', id: payload.id, result: { height: 10 } }));
    return reply(payload);
  };
  const rows = (await runProbe(endpoint, 1000, fetcher)).diagnostics;
  assert.equal(rows.find(row => row.method === 'getbuildinfo').status, 'rpc_error');
  assert.equal(rows.find(row => row.method === 'getblockcount').status, 'schema_drift');
  assert.ok(rows.find(row => row.method === 'getblockcount').missing_fields.includes('slot'));
});

test('rejects a mismatched JSON-RPC id and caps response size', async () => {
  const fetcher = async (_url, options) => {
    const payload = JSON.parse(options.body);
    if (payload.method === 'getchaininfo') return new Response(JSON.stringify({ jsonrpc: '2.0', id: 'wrong', result: {} }));
    if (payload.method === 'getbuildinfo') return new Response('x'.repeat(1024 * 1024 + 1));
    return reply(payload);
  };
  const rows = (await runProbe(endpoint, 1000, fetcher)).diagnostics;
  assert.match(rows[0].error, /mismatched request id/);
  assert.match(rows[1].error, /1 MiB limit/);
});

test('bounds a stalled method and continues probing later methods', async () => {
  const fetcher = async (_url, options) => {
    const payload = JSON.parse(options.body);
    if (payload.method === 'getchaininfo') return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true });
    });
    return reply(payload);
  };
  const rows = (await runProbe(endpoint, 500, fetcher)).diagnostics;
  assert.equal(rows[0].status, 'timeout');
  assert.equal(rows.at(-1).status, 'compatible_shape');
});

const referenceEndpoint = 'https://independent.example/rpc';
const trustedDomain = 'a'.repeat(64);
function comparisonFetcher({ primaryDomain = trustedDomain, referenceDomain = trustedDomain, primaryRoot = 'a'.repeat(64), referenceRoot = 'a'.repeat(64), primaryEpoch = 7, referenceEpoch = 7, referenceUnavailable = false } = {}) {
  const calls = [];
  const fetcher = async (url, options) => {
    const payload = JSON.parse(options.body);
    calls.push({ url, method: payload.method });
    if (referenceUnavailable && url === referenceEndpoint) throw new Error('Reference unavailable');
    if (payload.method === 'getchaininfo') {
      return reply(payload, { finalized: { epoch: url === referenceEndpoint ? referenceEpoch : primaryEpoch,
        root: url === referenceEndpoint ? referenceRoot : primaryRoot } });
    }
    if (payload.method === 'getvalidatoradmission') {
      return reply(payload, { network_domain: url === referenceEndpoint ? referenceDomain : primaryDomain });
    }
    return reply(payload);
  };
  return { fetcher, calls };
}

test('checks trusted domain and same-epoch finalized roots with only two bounded reference reads', async () => {
  const { fetcher, calls } = comparisonFetcher();
  const report = await runProbe(endpoint, 1000, fetcher, { referenceRpc: referenceEndpoint, expectDomain: trustedDomain });
  assert.equal(report.cross_check.status, 'match');
  assert.deepEqual(calls.filter(row => row.url === referenceEndpoint).map(row => row.method), ['getchaininfo', 'getvalidatoradmission']);
  assert.equal(report.reference_diagnostics.length, 2);
  assert.match(report.cross_check.note, /do not establish consensus/);
});

test('fails closed on domain mismatch and same-epoch finalized-root conflict', async () => {
  const { fetcher } = comparisonFetcher({ referenceDomain: 'b'.repeat(64), referenceRoot: 'b'.repeat(64) });
  const report = await runProbe(endpoint, 1000, fetcher, { referenceRpc: referenceEndpoint, expectDomain: trustedDomain });
  assert.equal(report.cross_check.status, 'fail');
  assert.ok(report.cross_check.findings.some(row => row.code === 'reference_domain_mismatch'));
  assert.ok(report.cross_check.findings.some(row => row.code === 'endpoint_domain_conflict'));
  assert.ok(report.cross_check.findings.some(row => row.code === 'same_epoch_finalized_root_conflict'));
});

test('different finalized epochs or unavailable reference remain inconclusive', async () => {
  const differing = comparisonFetcher({ referenceEpoch: 8 });
  const a = await runProbe(endpoint, 1000, differing.fetcher, { referenceRpc: referenceEndpoint });
  assert.equal(a.cross_check.status, 'inconclusive');
  assert.ok(a.cross_check.findings.some(row => row.code === 'different_finalized_epochs'));
  const missing = comparisonFetcher({ referenceUnavailable: true });
  const b = await runProbe(endpoint, 1000, missing.fetcher, { referenceRpc: referenceEndpoint });
  assert.equal(b.cross_check.status, 'inconclusive');
  assert.equal(b.reference_diagnostics[0].status, 'invalid_response');
});

test('rejects duplicate endpoint and invalid expected domain before network calls', async () => {
  const { fetcher, calls } = comparisonFetcher();
  await assert.rejects(runProbe(endpoint, 1000, fetcher, { referenceRpc: endpoint }), /different origin/);
  await assert.rejects(runProbe(endpoint, 1000, fetcher, { referenceRpc: 'http://127.0.0.1:16400/other' }), /different origin/);
  await assert.rejects(runProbe(endpoint, 1000, fetcher, { expectDomain: '  ' }), /64 hexadecimal/);
  assert.equal(calls.length, 0);
});
