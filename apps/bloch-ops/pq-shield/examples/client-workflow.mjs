// Run with Node.js 18+: node client-workflow.mjs
// Keep pq-shield-client.mjs beside this file and start the Rust API on loopback first.
import { createPqShieldClient } from './pq-shield-client.mjs';

const client = createPqShieldClient();
const vault = {
  hot_pubkey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  recovery_pubkey: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
  // Public test hash only. A real vault needs a unique hash from a local signer.
  recovery_hash: '5a'.repeat(32),
  csv_delay: 144,
};

await client.health();
const address = await client.vaultAddress({ network: 'regtest', ...vault });
// Dummy, unfunded outpoint. The unsigned result must never be broadcast.
const unvault = await client.unsignedUnvault({
  network: 'regtest', vault,
  deposit_outpoint: { txid: '00'.repeat(32), vout: 0 },
  deposit_amount_sat: 100_000, fee_sat: 500,
});
if (unvault.trigger_output.address !== address.trigger.address ||
    unvault.trigger_output.amount_sat !== 99_500) {
  throw new Error('Unsigned output did not match the requested vault and amount');
}

console.log(JSON.stringify({
  deposit_address: address.deposit.address,
  trigger_address: address.trigger.address,
  unsigned_unvault_txid: unvault.txid,
  sighash_hex: unvault.sighashes[0].sighash_hex,
  signing: 'NOT PERFORMED',
  broadcast: 'NOT PERFORMED',
}, null, 2));
console.error('Public regtest fixtures only. Validate all artifacts in your signer before real use.');
