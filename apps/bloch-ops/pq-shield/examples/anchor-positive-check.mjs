// Run against a locally running Rust pq-shield-api service on 127.0.0.1:8787.
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
const client = createPqShieldClient();
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

const serialized = await client.verifyAnchor({ signed_anchor_hex: fixture.signed_anchor_hex }, enrolledTestPubkey);
assert.equal(serialized.valid, true, `Serialized signed anchor rejected: ${serialized.reason}`);

console.log(JSON.stringify({
  status: 'PASS',
  scope: 'local disposable PQ signer and local reference verifier only',
  checks: ['matching commitment bytes', 'valid signature', 'tampered safe destination rejected',
    'serialized signed anchor accepted'],
  bitcoin_signing: false, broadcast: false, bloch_consensus_anchor: false,
}, null, 2));
