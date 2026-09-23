// End-to-end check against the self-hosted PQ Shield reference service.
// All inputs are public regtest fixtures. No keys, funds, signing, or broadcast.
// Start services/pq-shield-api locally, then run: node local-contract-check.mjs

const base = 'http://127.0.0.1:8787';
const vault = {
  hot_pubkey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  recovery_pubkey: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
  recovery_hash: '5a'.repeat(32),
  csv_delay: 144,
};

async function request(route, body) {
  const response = await fetch(`${base}${route}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  return { status: response.status, data: await response.json() };
}

function requireField(condition, message) {
  if (!condition) throw new Error(message);
}

const health = await request('/health');
requireField(health.status === 200 && health.data.service === 'pq-shield-api' && health.data.signs === false,
  'Unexpected health response from the local reference service');

const address = await request('/vault/address', { network: 'regtest', ...vault });
requireField(address.status === 200, `Vault address request failed: ${JSON.stringify(address.data)}`);
requireField(address.data.deposit?.address?.startsWith('bcrt1') &&
  address.data.trigger?.address?.startsWith('bcrt1') &&
  /^[0-9a-f]+$/.test(address.data.deposit?.witness_script_hex ?? ''),
  'Missing regtest deposit/trigger construction artifacts');

// This all-zero outpoint is a fixture, not a funded UTXO. The result is never broadcast.
const unvault = await request('/vault/unvault-tx', {
  network: 'regtest',
  vault,
  deposit_outpoint: { txid: '00'.repeat(32), vout: 0 },
  deposit_amount_sat: 100_000,
  fee_sat: 500,
});
requireField(unvault.status === 200, `Unsigned unvault request failed: ${JSON.stringify(unvault.data)}`);
requireField(/^[0-9a-f]+$/.test(unvault.data.unsigned_tx_hex ?? '') &&
  /^[0-9a-f]{64}$/.test(unvault.data.sighashes?.[0]?.sighash_hex ?? '') &&
  unvault.data.trigger_output?.address === address.data.trigger.address &&
  unvault.data.trigger_output?.amount_sat === 99_500,
  'Unsigned transaction, sighash, or trigger output did not match the vault');

// Send a harmless placeholder under a forbidden field name to check the boundary.
const rejected = await request('/vault/address', {
  network: 'regtest', ...vault, mnemonic: 'test-placeholder-only',
});
requireField(rejected.status === 400 && /secret material/i.test(rejected.data.error ?? ''),
  'The reference service did not reject a secret-shaped field');

console.log(JSON.stringify({
  status: 'PASS',
  scope: 'local reference service, public regtest fixtures only',
  deposit_address: address.data.deposit.address,
  trigger_address: address.data.trigger.address,
  unsigned_unvault_txid: unvault.data.txid,
  trigger_amount_sat: unvault.data.trigger_output.amount_sat,
  secret_field_rejected: true,
}, null, 2));
console.error('No real UTXO, private key, signature, transaction broadcast, or production qualification.');
