// Run through run-anchor-positive-local.mjs, or against a local service using
// PQ_SHIELD_TEST_URL=http://127.0.0.1:<port>.
// Requires local Rust/Cargo. Uses a public test seed, fake regtest addresses,
// and no UTXO, funding, Bitcoin signing, chain publication, or broadcast.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPqShieldClient } from './pq-shield-client.mjs';

const manifest = fileURLToPath(new URL('./anchor-positive-fixture/Cargo.toml', import.meta.url));
const fixture = JSON.parse(execFileSync('cargo', ['run', '--quiet', '--manifest-path', manifest], {
  encoding: 'utf8', timeout: 180_000, maxBuffer: 128 * 1024,
  env: { ...process.env, CARGO_TARGET_DIR: join(tmpdir(), 'pq-shield-anchor-fixture-build') },
}));
const client = createPqShieldClient(process.env.PQ_SHIELD_TEST_URL);
await client.health();

const commitment = await client.anchorCommitment(fixture.fields);
assert.equal(commitment.commitment_bytes_hex, fixture.commitment_bytes_hex,
  'The local API and signer must commit to identical bytes');

// In a real integration, the trusted public key must come from authenticated
// enrollment outside the anchor. This local test provisionally enrolls the
// generated fixture key before inspecting the signed anchor.
const enrolledTestPubkey = fixture.fields.pq_recovery_pubkey;
const valid = await client.verifyAnchor({ ...fixture.fields, signature: fixture.signature }, enrolledTestPubkey);
assert.equal(valid.valid, true, `Valid test signature rejected: ${valid.reason}`);
assert.equal(valid.commitment_bytes_hex, fixture.commitment_bytes_hex);

const tampered = await client.verifyAnchor({
  ...fixture.fields, designated_safe_dest: 'bcrt1qtestattackerdestination', signature: fixture.signature,
}, enrolledTestPubkey);
assert.equal(tampered.valid, false, 'Changed safe destination must invalidate signature');
const changedPolicy = { ...fixture.fields, policy: 'altered-test-policy' };
const changedCommitment = await client.anchorCommitment(changedPolicy);
assert.notEqual(changedCommitment.commitment_bytes_hex, fixture.commitment_bytes_hex,
  'Changed policy must alter commitment bytes');
const tamperedCommitment = await client.verifyAnchor({
  ...changedPolicy, signature: fixture.signature,
}, enrolledTestPubkey);
assert.equal(tamperedCommitment.valid, false, 'Changed commitment must invalidate signature');

assert.notEqual(fixture.other_test_pubkey, enrolledTestPubkey);
const wrongEnrollment = await client.verifyAnchor({
  ...fixture.fields, signature: fixture.signature,
}, fixture.other_test_pubkey);
assert.equal(wrongEnrollment.valid, false, 'Wrong enrolled public key must reject signature');

const serialized = await client.verifyAnchor({ signed_anchor_hex: fixture.signed_anchor_hex }, enrolledTestPubkey);
assert.equal(serialized.valid, true, `Serialized signed anchor rejected: ${serialized.reason}`);

// Exercise the actual HTTP boundary as well as the example client's local
// guard. These placeholders contain no secrets or usable Bitcoin material.
async function expectBadRequest(route, body, pattern) {
  const response = await fetch(new URL(route, process.env.PQ_SHIELD_TEST_URL), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  assert.equal(response.status, 400, `${route} should reject this request`);
  const result = await response.json();
  assert.match(result.error, pattern);
  assert.equal(typeof result.non_custodial, 'string');
}

await expectBadRequest('/anchor/commitment',
  { ...fixture.fields, mnemonic: 'placeholder' }, /secret material/i);
await expectBadRequest('/vault/unvault-tx',
  { vault: { pq_secret: 'placeholder' } }, /secret material/i);
await expectBadRequest('/anchor/verify',
  { signed_anchor_hex: fixture.signed_anchor_hex }, /trusted_pq_pubkey/i);
await expectBadRequest('/anchor/verify',
  { signed_anchor_hex: '00', trusted_pq_pubkey: enrolledTestPubkey }, /signed_anchor_hex.*malformed/i);
await expectBadRequest('/anchor/commitment',
  { ...fixture.fields, recovery_hash: '00' }, /recovery_hash/i);
await expectBadRequest('/anchor/commitment',
  { ...fixture.fields, csv_delay: 65536 }, /expected u16/i);

const maxBodyBytes = 64 * 1024;
for (const route of ['/vault/address', '/vault/unvault-tx', '/vault/branch-a-tx',
  '/vault/clawback-tx', '/anchor/commitment', '/anchor/verify']) {
  const oversized = `{}${' '.repeat(maxBodyBytes - 1)}`;
  assert.equal(Buffer.byteLength(oversized), maxBodyBytes + 1);
  const response = await fetch(new URL(route, process.env.PQ_SHIELD_TEST_URL), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: oversized,
    signal: AbortSignal.timeout(10_000),
  });
  assert.equal(response.status, 413, `${route} must reject a body above 64 KiB`);
}

console.log(JSON.stringify({
  status: 'PASS',
  scope: 'local disposable PQ signer and local reference verifier only',
  checks: ['matching commitment bytes', 'valid signature', 'tampered safe destination rejected',
    'tampered policy commitment rejected', 'wrong enrolled key rejected',
    'serialized signed anchor accepted', 'top-level and nested secret-shaped fields rejected over HTTP',
    'missing trust root rejected over HTTP', 'malformed signed anchor rejected over HTTP',
    'malformed recovery hash rejected over HTTP', 'oversized CSV delay rejected over HTTP',
    'all six JSON routes reject request bodies above 64 KiB with HTTP 413'],
  bitcoin_signing: false, broadcast: false, bloch_consensus_anchor: false,
}, null, 2));
