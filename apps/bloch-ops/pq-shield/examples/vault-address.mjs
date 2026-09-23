// PQ Shield reference API: public regtest data only.
// Run the Rust service locally first: cd services/pq-shield-api && cargo run
// Then run this file with Node.js 18+: node vault-address.mjs
// The fixed loopback URL cannot send data to a hosted or third-party endpoint.

const response = await fetch('http://127.0.0.1:8787/vault/address', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    network: 'regtest',
    hot_pubkey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    recovery_pubkey: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
    // Demonstration hash only. Derive a unique H(r) in your own signer for a real vault.
    recovery_hash: '5a'.repeat(32),
    csv_delay: 144,
  }),
});

const result = await response.json();
if (!response.ok) {
  throw new Error(`PQ Shield API returned HTTP ${response.status}: ${JSON.stringify(result)}`);
}
if (!result.deposit?.address || !result.trigger?.address) {
  throw new Error('Unexpected address response; review the local API version.');
}
console.log(JSON.stringify(result, null, 2));
console.error('Regtest construction only. No keys were supplied; no transaction was signed or broadcast.');
