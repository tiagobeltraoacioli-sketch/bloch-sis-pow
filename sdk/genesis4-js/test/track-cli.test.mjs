// SPDX-License-Identifier: AGPL-3.0-or-later
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const cli = fileURLToPath(new URL('../examples/track-signed.mjs', import.meta.url));
const root = mkdtempSync(join(tmpdir(), 'bloch-track-cli-'));
after(() => rmSync(root, { recursive: true, force: true }));
const rawHex = 'ab'.repeat(128);
const signingRootHex = 'cd'.repeat(32);
const domain = Buffer.from('BLCH4:TXID\0\0\0\0\0\0', 'ascii');
const txid = createHash('sha3-256').update(domain).update(Buffer.from(signingRootHex, 'hex')).digest('hex');
const rawHash = createHash('sha3-256').update(Buffer.from(rawHex, 'hex')).digest('hex');
const mnemonic = 'private mnemonic should never print';
const signed = { txid, rawHex, signingRootHex, rawHash, mnemonic };
const signedPath = join(root, 'signed.json');
writeFileSync(signedPath, JSON.stringify(signed));
const preloader = join(root, 'fetch.mjs');
writeFileSync(preloader, `globalThis.fetch = async (_url, options) => {
  if (!options?.body) return new Response('', { status: 404 });
  const request = JSON.parse(options.body);
  if (request.method !== 'gettxstatus') throw new Error('unexpected method');
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { status: 'pending' } }),
    { status: 200, headers: { 'content-type': 'application/json' } });
};\n`);

function run(...args) {
  return spawnSync(process.execPath, ['--import', preloader, cli, ...args], {
    encoding: 'utf8', env: { ...process.env, BLOCH_RPC_URL: 'https://rpc.example.test/g4rpc',
      BLOCH_EXPLORER_URL: 'https://index.example.test' }, timeout: 10_000,
  });
}

test('tracks stored bytes read-only and compares the previous CLI result', () => {
  const first = run(signedPath);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stderr, '');
  assert.ok(!first.stdout.includes(rawHex));
  assert.ok(!first.stdout.includes(mnemonic));
  const result = JSON.parse(first.stdout);
  assert.equal(result.txid, txid);
  assert.equal(result.observation.kind, 'unresolved');
  assert.equal(result.comparison.status, 'unresolved');
  const previousPath = join(root, 'previous.json');
  writeFileSync(previousPath, first.stdout);
  const second = run(signedPath, previousPath);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(JSON.parse(second.stdout).comparison.status, 'unresolved');
});

test('rejects malformed and mismatched observations without printing secrets', () => {
  for (const previous of [null, {}, { txid, observation: { txid, kind: 'bogus' }, comparison: { txid } },
    { txid: '00'.repeat(32), observation: { txid, kind: 'unresolved' }, comparison: { txid } },
    { txid, observation: { txid, kind: 'unresolved' }, comparison: { txid: 12 } }]) {
    const previousPath = join(root, `bad-${Math.random()}.json`);
    writeFileSync(previousPath, JSON.stringify(previous));
    const child = run(signedPath, previousPath);
    assert.equal(child.status, 1);
    assert.equal(child.stdout, '');
    assert.match(child.stderr, /Previous file must be a track-signed result/);
    assert.ok(!child.stderr.includes(rawHex) && !child.stderr.includes(mnemonic));
  }
});

test('rejects symlinks and oversized input before parsing', () => {
  const link = join(root, 'signed-link.json');
  symlinkSync(signedPath, link);
  const linked = run(link);
  assert.equal(linked.status, 1);
  assert.match(linked.stderr, /regular file/);
  const huge = join(root, 'huge.json');
  writeFileSync(huge, 'x'.repeat(2 * 1024 * 1024 + 1));
  const oversized = run(huge);
  assert.equal(oversized.status, 1);
  assert.match(oversized.stderr, /at most 2 MiB/);
});

test('rejects unsafe endpoint overrides and invalid signed envelope without leaking data', () => {
  const invalid = join(root, 'invalid.json');
  writeFileSync(invalid, JSON.stringify({ ...signed, rawHash: '00'.repeat(32) }));
  const failure = run(invalid);
  assert.equal(failure.status, 1);
  assert.equal(failure.stdout, '');
  assert.ok(!failure.stderr.includes(rawHex) && !failure.stderr.includes(mnemonic));
  const unsafe = spawnSync(process.execPath, [cli, signedPath], {
    encoding: 'utf8', env: { ...process.env, BLOCH_RPC_URL: 'http://rpc.example.test' }, timeout: 10_000,
  });
  assert.equal(unsafe.status, 1);
  assert.match(unsafe.stderr, /BLOCH_RPC_URL must be an HTTPS URL/);
  const query = spawnSync(process.execPath, [cli, signedPath], {
    encoding: 'utf8', env: { ...process.env, BLOCH_RPC_URL: 'https://rpc.example.test/g4rpc?token=secret' }, timeout: 10_000,
  });
  assert.equal(query.status, 1);
  assert.doesNotMatch(query.stderr, /secret/);
});
