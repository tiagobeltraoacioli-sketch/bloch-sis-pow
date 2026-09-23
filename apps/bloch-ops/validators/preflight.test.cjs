'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { evaluate, parseArgs, readEndpoint, writeEvidenceBundle } = require('./preflight.cjs');

const domain = 'a'.repeat(64), root = 'b'.repeat(64), digest = 'c'.repeat(64);
function fixture() {
  return {
    getchaininfo: { block_id: 'd'.repeat(64), slot: 6400, epoch: 200, behind_by_slots: 1, finalized: { epoch: 198, root }, transport: { name: 'libp2p', peers: { devnet: null, libp2p: 4 } } },
    getbuildinfo: { build_version: 'test', source_digest: digest, tree_state: 'clean' },
    getvalidatoradmission: { active: true, epoch: 200, network_domain: domain }
  };
}
function rpcResponse(method, result, options = {}) {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: `preflight-${method}`, result, ...options }), { headers: { 'content-type': 'application/json' } });
}
test('read-only pass still demands manual trust and lifecycle evidence', () => {
  const report = evaluate(fixture(), fixture(), { expectDomain: domain, maxLagSlots: 64 });
  assert.equal(report.summary, 'CHECKS_PASS_MANUAL_REQUIRED');
  assert.equal(report.checks.at(-1).level, 'MANUAL');
  assert.match(report.checks.at(-1).detail, /exit, withdrawal delay and spendable payout/);
});
test('stale or unanchored nodes require review', () => {
  const sample = fixture(); sample.getchaininfo.behind_by_slots = 100; sample.getchaininfo.transport.peers.libp2p = 0;
  const report = evaluate(sample, null, { maxLagSlots: 64 });
  assert.equal(report.summary, 'REVIEW');
  assert.equal(report.checks.find(c => c.title === 'Network domain').level, 'WARN');
});
test('wrong chain domain or conflicting same-epoch finalized root fails', () => {
  const other = fixture(); other.getchaininfo.finalized.root = 'e'.repeat(64);
  const report = evaluate(fixture(), other, { expectDomain: 'f'.repeat(64), maxLagSlots: 64 });
  assert.equal(report.summary, 'FAIL');
  assert.equal(report.checks.find(c => c.title === 'Reference finalized checkpoint').level, 'FAIL');
});
test('different finalized epochs cannot be claimed corroborated', () => {
  const other = fixture(); other.getchaininfo.finalized.epoch = 197;
  const report = evaluate(fixture(), other, { expectDomain: domain, maxLagSlots: 64 });
  assert.equal(report.checks.find(c => c.title === 'Reference finalized checkpoint').level, 'WARN');
});
test('reject remote cleartext and invalid expected domain', () => {
  assert.throws(() => parseArgs(['--rpc', 'http://example.com/rpc']), /HTTPS/);
  assert.throws(() => parseArgs(['--rpc', 'https://example.com/rpc', '--expect-domain', 'short']), /64 hexadecimal/);
  assert.throws(() => parseArgs(['--rpc', 'https://example.com/rpc', '--timeout-ms', '0']), /1000 to 60000/);
  assert.equal(parseArgs(['--rpc', 'https://example.com/rpc', '--timeout-ms', '5000']).timeoutMs, 5000);
});
test('RPC client requests only the three read-only methods', async () => {
  const calls = [];
  const original = global.fetch;
  global.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    calls.push(request.method);
    return rpcResponse(request.method, fixture()[request.method]);
  };
  try {
    const result = await readEndpoint('https://example.com/rpc');
    assert.deepEqual(calls.sort(), ['getbuildinfo', 'getchaininfo', 'getvalidatoradmission']);
    assert.equal(result.getvalidatoradmission.network_domain, domain);
    assert.deepEqual(result.diagnostics.map(item => item.status), ['OK', 'OK', 'OK']);
  } finally { global.fetch = original; }
});
test('method failure is reported while other probes continue and result fails closed', async () => {
  const calls = [];
  const original = global.fetch;
  global.fetch = async (_url, options) => {
    const method = JSON.parse(options.body).method;
    calls.push(method);
    if (method === 'getbuildinfo') throw new DOMException('request aborted', 'AbortError');
    return rpcResponse(method, fixture()[method]);
  };
  try {
    const result = await readEndpoint('https://example.com/rpc', 5000);
    assert.deepEqual(calls, ['getchaininfo', 'getbuildinfo', 'getvalidatoradmission']);
    assert.equal(result.diagnostics[1].detail, 'Timed out after 5000 ms');
    assert.equal(result.getvalidatoradmission.network_domain, domain);
    const report = evaluate(result, null, { expectDomain: domain, maxLagSlots: 2 });
    assert.equal(report.summary, 'FAIL');
    assert.equal(report.checks.find(item => item.title === 'primary getbuildinfo').level, 'FAIL');
    assert.equal(report.checks.at(-1).level, 'MANUAL');
  } finally { global.fetch = original; }
});
test('rejects malformed JSON-RPC envelopes while continuing remaining methods', async () => {
  const original = global.fetch;
  let caseIndex = 0;
  const invalid = [
    { id: 'wrong-id' },
    { jsonrpc: '1.0' },
    { result: [] },
    { result: null },
    { error: null },
    { result: undefined, error: { code: -32603, message: 'secret server diagnostic' } },
    { error: { code: -32603, message: 'secret server diagnostic' } },
    { error: { code: 'not-a-code', message: 'secret server diagnostic' } }
  ];
  try {
    for (caseIndex = 0; caseIndex < invalid.length; caseIndex++) {
      const calls = [];
      global.fetch = async (_url, options) => {
        const method = JSON.parse(options.body).method;
        calls.push(method);
        return rpcResponse(method, fixture()[method], method === 'getchaininfo' ? invalid[caseIndex] : {});
      };
      const result = await readEndpoint('https://example.com/rpc');
      assert.deepEqual(calls, ['getchaininfo', 'getbuildinfo', 'getvalidatoradmission']);
      assert.equal(result.getchaininfo, undefined);
      assert.equal(result.getvalidatoradmission.network_domain, domain);
      assert.equal(result.diagnostics[0].status, 'ERROR');
      if (caseIndex === 5) assert.equal(result.diagnostics[0].detail, 'RPC error -32603');
      assert.doesNotMatch(result.diagnostics[0].detail, /secret/);
      assert.equal(evaluate(result, null, { expectDomain: domain, maxLagSlots: 2 }).summary, 'FAIL');
    }
  } finally { global.fetch = original; }
});
test('bounds streamed RPC responses and omits untrusted bodies and transport errors', async () => {
  const original = global.fetch;
  const secret = 'secret server diagnostic';
  const oversized = JSON.stringify({ jsonrpc: '2.0', id: 'preflight-getchaininfo', result: { data: 'x'.repeat(65536) } });
  const failures = [
    new Response(secret, { status: 503 }),
    new Response(oversized),
    new Response('{ invalid json'),
    new Response('{}', { headers: { 'content-length': '65537' } }),
    new Error(secret)
  ];
  try {
    for (const failure of failures) {
      global.fetch = async (_url, options) => {
        const method = JSON.parse(options.body).method;
        if (method === 'getchaininfo') {
          if (failure instanceof Error) throw failure;
          return failure;
        }
        return rpcResponse(method, fixture()[method]);
      };
      const result = await readEndpoint('https://example.com/rpc');
      assert.equal(result.diagnostics[0].status, 'ERROR');
      assert.doesNotMatch(JSON.stringify(result.diagnostics), /secret/);
      assert.equal(result.diagnostics[1].status, 'OK');
      assert.equal(result.diagnostics[2].status, 'OK');
    }
  } finally { global.fetch = original; }
});
test('failed optional reference probe cannot produce a passing comparison', () => {
  const primary = fixture();
  const reference = fixture();
  delete reference.getchaininfo;
  reference.diagnostics = [{ endpoint: 'reference', method: 'getchaininfo', status: 'ERROR', elapsedMs: 10, detail: 'HTTP 503' }];
  const report = evaluate(primary, reference, { expectDomain: domain, maxLagSlots: 2 });
  assert.equal(report.summary, 'FAIL');
  assert.equal(report.checks.find(item => item.title === 'reference getchaininfo').level, 'FAIL');
});
test('evidence bundle records selected RPC fields, integrity and pending manual gate without unknown fields', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'g4-preflight-'));
  try {
    const sample = fixture();
    sample.getbuildinfo.private_key = 'never-persist-this';
    sample.getchaininfo.unknown_field = 'never-persist-this';
    const report = evaluate(sample, null, { expectDomain: domain, maxLagSlots: 2 });
    const directory = path.join(parent, 'evidence');
    const saved = writeEvidenceBundle(directory, report, sample, null, { expectDomain: domain, maxLagSlots: 2 });
    const body = fs.readFileSync(path.join(directory, 'evidence.json'), 'utf8');
    const bundle = JSON.parse(body);
    assert.equal(saved.checksum, crypto.createHash('sha256').update(body).digest('hex'));
    assert.equal(fs.readFileSync(path.join(directory, 'SHA256SUMS'), 'utf8'), `${saved.checksum}  evidence.json\n`);
    assert.equal(bundle.manualGate.status, 'NOT_VERIFIED');
    assert.equal(bundle.observations.primary.getbuildinfo.source_digest, digest);
    assert.equal(bundle.observations.primary.getchaininfo.finalized.root, root);
    assert.equal(bundle.summary, 'CHECKS_PASS_MANUAL_REQUIRED');
    assert.doesNotMatch(body, /never-persist-this/);
    assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(directory, 'evidence.json')).mode & 0o777, 0o600);
    assert.throws(() => writeEvidenceBundle(directory, report, sample, null, { maxLagSlots: 2 }), /EEXIST/);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});
test('failed probes can be saved but never become passing evidence', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'g4-preflight-'));
  try {
    const sample = fixture();
    delete sample.getbuildinfo;
    sample.diagnostics = [{ endpoint: 'primary', method: 'getbuildinfo', status: 'ERROR', elapsedMs: 12, detail: 'HTTP 503' }];
    const report = evaluate(sample, null, { maxLagSlots: 2 });
    const directory = path.join(parent, 'evidence');
    writeEvidenceBundle(directory, report, sample, null, { maxLagSlots: 2 });
    const bundle = JSON.parse(fs.readFileSync(path.join(directory, 'evidence.json'), 'utf8'));
    assert.equal(bundle.summary, 'FAIL');
    assert.equal(bundle.observations.primary.getbuildinfo, null);
    assert.equal(bundle.manualGate.status, 'NOT_VERIFIED');
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});
