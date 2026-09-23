// Optional integration check against the actual local Rust service.
// Public regtest fixtures, dummy outpoints, invalid test signature: no signing or broadcast.
// Run: node client-routes-check.mjs
import assert from 'node:assert/strict';
import { createPqShieldClient } from './pq-shield-client.mjs';

const client = createPqShieldClient();
const vault = {
  hot_pubkey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  recovery_pubkey: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
  recovery_hash: '5a'.repeat(32), csv_delay: 144,
};
const address = await client.vaultAddress({ network: 'regtest', ...vault });
const trigger_outpoint = { txid: '00'.repeat(32), vout: 0 };

const branch = await client.unsignedBranchA({
  network: 'regtest', vault, trigger_outpoint, trigger_amount_sat: 99_500,
  destination: address.deposit.address, fee_sat: 500,
});
assert.equal(branch.matures_after_blocks, 144);
assert.match(branch.sighashes[0].sign_with, /hot_key/);

const clawback = await client.unsignedClawback({
  network: 'regtest', vault, trigger_outpoint, trigger_amount_sat: 99_500,
  safe_destination: address.deposit.address, fee_sat: 500,
});
assert.equal(clawback.safe_output.amount_sat, 99_000);
assert.match(clawback.sighashes[0].sign_with, /recovery_key/);

const anchor = {
  target_chain: 'bitcoin', btc_vault_address: address.deposit.address,
  recovery_hash: vault.recovery_hash,
  // Public test bytes only. This is not a real enrolled hybrid PQ key.
  pq_recovery_pubkey: '02'.repeat(32),
  designated_safe_dest: address.deposit.address,
  csv_delay: vault.csv_delay, policy: 'client-route-check',
};
const commitment = await client.anchorCommitment(anchor);
assert.ok(commitment.commitment_len > 0);
const verification = await client.verifyAnchor({ ...anchor, signature: '00' }, anchor.pq_recovery_pubkey);
assert.equal(verification.valid, false);

await assert.rejects(client.verifyAnchor({ ...anchor, signature: '00' }, ''), /independently trusted/);
await assert.rejects(client.vaultAddress({ mnemonic: 'test-placeholder' }), /Refusing secret-shaped/);

console.log(JSON.stringify({
  status: 'PASS',
  checked: ['unsignedBranchA', 'unsignedClawback', 'anchorCommitment',
    'verifyAnchor invalid signature', 'missing trust root rejection', 'secret field rejection'],
  note: 'A valid signature requires an independently provisioned client-side PQ signer and enrolled trusted public key.',
}, null, 2));
