'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { parseArgs, assess, runVerifier, fingerprint, saveEvidence } = require('./checkpoint-verify.cjs');
const digest = 'a'.repeat(64);
const base = ['--binary', '/tmp/bloch-pos', '--envelope', '/tmp/env.bin', '--signer-set', '/tmp/set.bin', '--genesis', '/tmp/mainnet.manifest', '--rpc', '127.0.0.1:16400', '--expect-digest', digest];

test('requires all explicit inputs and rejects URL/credential RPC forms', () => {
  assert.equal(parseArgs(base).rpc, '127.0.0.1:16400');
  assert.throws(() => parseArgs(base.slice(0, -2)), /expect-digest/);
  assert.throws(() => parseArgs([...base, '--rpc', 'example.com:1234']), /repeated/);
  assert.throws(() => parseArgs(base.map(x => x === '127.0.0.1:16400' ? 'https://example.com/rpc' : x)), /host:port/);
  assert.throws(() => parseArgs(base.map(x => x === digest ? 'wrong' : x)), /64 hexadecimal/);
});

test('acceptance remains manual and digest mismatch fails', () => {
  const output = `  WS DIGEST         ${digest}\nFRESHNESS  epoch 10 vs now 11: age 1 of 2016 epochs — FRESH\nVERDICT: ACCEPTED by ws::verify_envelope.\n`;
  const run = { code: 0, stdout: output, stderr: '', stopReason: null };
  assert.equal(assess(run, digest).status, 'CRYPTO_ACCEPTED_MANUAL_REQUIRED');
  assert.equal(assess(run, 'b'.repeat(64)).status, 'FAIL');
  assert.equal(assess({ ...run, code: 1 }, digest).status, 'FAIL');
  assert.equal(assess({ ...run, stdout: output.replace('— FRESH', '— STALE') }, digest).status, 'REVIEW');
  assert.equal(assess({ ...run, stdout: output.replace('— FRESH', '— EXPIRED') }, digest).status, 'FAIL');
});

test('runs only ws-verify flags, bounds output, and saves checksum in new private directory', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bloch-ws-wrap-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const binary = path.join(dir, 'fake-bloch-pos');
  fs.writeFileSync(binary, `#!/bin/sh\nprintf '%s\\n' "$@"\n`, { mode: 0o700 });
  const opts = parseArgs(base.map(x => x === '/tmp/bloch-pos' ? binary : x));
  const run = await runVerifier(opts);
  assert.equal(run.code, 0);
  assert.deepEqual(run.stdout.trim().split('\n'), ['ws-verify', '--envelope', '/tmp/env.bin', '--signer-set', '/tmp/set.bin', '--genesis', '/tmp/mainnet.manifest', '--rpc', '127.0.0.1:16400']);
  assert.equal((await fingerprint(binary, true)).bytes > 0, true);
  const bundle = path.join(dir, 'evidence');
  const report = { status: 'FAIL', diagnostics: { stdout: run.stdout } };
  const sum = saveEvidence(bundle, report);
  const bytes = fs.readFileSync(path.join(bundle, 'checkpoint-verification.json'));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), sum);
  assert.equal(fs.statSync(bundle).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(bundle, 'checkpoint-verification.json')).mode & 0o777, 0o600);
  assert.throws(() => saveEvidence(bundle, report), /EEXIST/);
});

test('caps child output', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bloch-ws-overflow-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const binary = path.join(dir, 'fake-bloch-pos');
  fs.writeFileSync(binary, '#!/bin/sh\nyes X | head -c 100000\n', { mode: 0o700 });
  const result = await runVerifier({ binary, envelope: 'a', signerSet: 'b', genesis: 'c', rpc: '127.0.0.1:1' });
  assert.equal(result.stopReason, 'OUTPUT_LIMIT');
  assert.equal(result.stdout.length + result.stderr.length <= 65536, true);
});
