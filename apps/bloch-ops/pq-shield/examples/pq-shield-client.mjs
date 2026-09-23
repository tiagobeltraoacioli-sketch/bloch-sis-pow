// Node.js 18+ client for the self-hosted PQ Shield reference service.
// Construction and verification only: this module cannot sign or broadcast.

const HEX = /^(?:[0-9a-f]{2})+$/i;
const HEX32 = /^[0-9a-f]{64}$/i;
const SECRET_FIELD = /secret|seed|priv|mnemonic|wif|preimage|^(?:r|sk)$/i;

function checkPublicInput(value) {
  if (Array.isArray(value)) return value.forEach(checkPublicInput);
  if (value && typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      if (SECRET_FIELD.test(key)) throw new Error(`Refusing secret-shaped field: ${key}`);
      checkPublicInput(nested);
    }
  }
}

function requireShape(ok, route) {
  if (!ok) throw new Error(`Unexpected ${route} response; review the local service version`);
}

function safeAmount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function unsignedShape(data, route, inputAmount, signer) {
  requireShape(data && HEX.test(data.unsigned_tx_hex) && HEX32.test(data.txid) &&
    Array.isArray(data.sighashes) && data.sighashes.length === 1 &&
    data.sighashes[0]?.input_index === 0 &&
    HEX32.test(data.sighashes[0]?.sighash_hex) &&
    data.sighashes[0]?.sighash_type === 'SIGHASH_ALL' &&
    data.sighashes[0]?.sign_with?.startsWith(signer) &&
    HEX.test(data.sighashes[0]?.witness_script_hex) &&
    data.sighashes[0]?.prevout_amount_sat === inputAmount &&
    typeof data.non_custodial === 'string', route);
  return data;
}

export function createPqShieldClient(base = 'http://127.0.0.1:8787') {
  const origin = new URL(base);
  if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' ||
      origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('This example connects to a 127.0.0.1 self-hosted service only');
  }

  async function request(route, body) {
    if (body !== undefined) checkPublicInput(body);
    const response = await fetch(new URL(route, origin), {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(`${route} returned HTTP ${response.status}: ${typeof data?.error === 'string' ? data.error : 'unknown error'}`);
    return data;
  }

  return {
    async health() {
      const data = await request('/health');
      requireShape(data && data.status === 'ok' && data.service === 'pq-shield-api' &&
        data.non_custodial === true && data.signs === false, '/health');
      return data;
    },
    async vaultAddress(fields) {
      const data = await request('/vault/address', fields);
      requireShape(data && data.network === fields.network && data.csv_delay === fields.csv_delay &&
        typeof data.deposit?.address === 'string' &&
        HEX.test(data.deposit?.witness_script_hex) &&
        HEX.test(data.deposit?.script_pubkey_hex) &&
        typeof data.trigger?.address === 'string' &&
        HEX.test(data.trigger?.witness_script_hex) &&
        HEX.test(data.trigger?.script_pubkey_hex) &&
        typeof data.non_custodial === 'string', '/vault/address');
      return data;
    },
    async unsignedUnvault(fields) {
      const data = unsignedShape(await request('/vault/unvault-tx', fields), '/vault/unvault-tx', fields.deposit_amount_sat, 'hot_key');
      requireShape(typeof data.trigger_output?.address === 'string' &&
        data.trigger_output.vout === 0 &&
        safeAmount(data.trigger_output?.amount_sat) &&
        safeAmount(fields.deposit_amount_sat) && safeAmount(fields.fee_sat) &&
        data.trigger_output.amount_sat === fields.deposit_amount_sat - fields.fee_sat, '/vault/unvault-tx');
      return data;
    },
    async unsignedBranchA(fields) {
      const data = unsignedShape(await request('/vault/branch-a-tx', fields), '/vault/branch-a-tx', fields.trigger_amount_sat, 'hot_key');
      requireShape(data.matures_after_blocks === fields.vault.csv_delay, '/vault/branch-a-tx');
      return data;
    },
    async unsignedClawback(fields) {
      const data = unsignedShape(await request('/vault/clawback-tx', fields), '/vault/clawback-tx', fields.trigger_amount_sat, 'recovery_key');
      requireShape(data.safe_output?.address === fields.safe_destination &&
        data.safe_output.vout === 0 && safeAmount(data.safe_output?.amount_sat) &&
        safeAmount(fields.trigger_amount_sat) && safeAmount(fields.fee_sat) &&
        data.safe_output.amount_sat === fields.trigger_amount_sat - fields.fee_sat, '/vault/clawback-tx');
      return data;
    },
    async anchorCommitment(fields) {
      const data = await request('/anchor/commitment', fields);
      requireShape(data && HEX.test(data.commitment_bytes_hex) &&
        data.commitment_bytes_hex.length / 2 === data.commitment_len &&
        HEX32.test(data.bloch_governance_guard_hash) &&
        typeof data.non_custodial === 'string', '/anchor/commitment');
      return data;
    },
    async verifyAnchor(fields, trustedPqPubkey) {
      if (!HEX.test(trustedPqPubkey)) throw new Error('An independently trusted PQ public key is required');
      const data = await request('/anchor/verify', { ...fields, trusted_pq_pubkey: trustedPqPubkey });
      requireShape(data && typeof data.valid === 'boolean' && typeof data.reason === 'string' &&
        data.verified_against_pq_pubkey?.toLowerCase() === trustedPqPubkey.toLowerCase() &&
        HEX.test(data.commitment_bytes_hex), '/anchor/verify');
      return data;
    },
  };
}
