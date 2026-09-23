// SPDX-License-Identifier: AGPL-3.0-or-later
import G4 from './g4.cjs';
import { createCore } from './core.mjs';

const DEFAULT_RPC = 'https://posternlabs.com/g4rpc';
const DEFAULT_EXPLORER = 'https://blochl1.com';
const HASH = /^[0-9a-f]{64}$/i;

function mainnetAddress(value, name) {
  const info = G4.inspectAddress(value);
  if (!info.verified || info.network !== 'mainnet') {
    throw new Error(`${name}: a checksummed Genesis-4 mainnet address is required (${info.message})`);
  }
  return info;
}

async function json(url, options, fetchImpl) {
  const response = await fetchImpl(url, { ...options, redirect: 'error' });
  const body = await response.json();
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}: ${JSON.stringify(body.error ?? body)}`);
  return body;
}

async function rpc(method, params, rpcUrl, fetchImpl) {
  const attempts = method === 'sendrawtransaction' ? 1 : 3;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const body = await json(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    }, fetchImpl);
    if (body.result != null && !body.error) return body.result;
    if (![-32051, -32004, -32053].includes(body.error?.code) || attempt === attempts - 1) {
      throw new Error(`${method}: ${JSON.stringify(body.error ?? 'missing result')}`);
    }
    await new Promise(resolve => setTimeout(resolve, 250 * (attempt + 1)));
  }
}

function assertFits(value) {
  const limits = G4.limits;
  const count = (input, name) => {
    if (!/^(0|[1-9][0-9]*)$/.test(String(input ?? ''))) throw new Error(`Core returned invalid ${name}`);
    return BigInt(input);
  };
  if (count(value.declared_tx_bytes, 'declared_tx_bytes') > BigInt(limits.MAX_BLOCK_TX_BYTES) ||
      count(value.gas, 'gas') > BigInt(limits.BLOCK_GAS_LIMIT)) {
    throw new Error('Signed transaction exceeds Genesis-4 consensus limits');
  }
  if (value.raw_hex && (!/^[0-9a-f]+$/i.test(value.raw_hex) || value.raw_hex.length / 2 > limits.RPC_MAX_RAW_TX_BYTES)) {
    throw new Error('Signed transaction exceeds the RPC byte limit');
  }
}

/** Build a signed Genesis-4 transfer. amount is a decimal BLOCH string. No broadcast occurs. */
export async function createSignedTransaction({
  addressFrom, mnemonic, addressTo, amount, rpcUrl = DEFAULT_RPC, fetchImpl = fetch,
}) {
  const from = mainnetAddress(addressFrom, 'addressFrom');
  mainnetAddress(addressTo, 'addressTo');
  const amountSat = G4.sats.toWire(G4.sats.fromUserBLCH(amount));
  if (typeof mnemonic !== 'string' || !mnemonic.trim()) throw new Error('mnemonic is required');
  const core = createCore();
  try {
    const wallet = core.call('wallet_from_mnemonic', { mnemonic, testnet: false });
    if (String(wallet.address).toLowerCase() !== addressFrom.trim().toLowerCase()) {
      throw new Error('addressFrom does not match the mnemonic');
    }
    const [utxoResult, chainResult] = await Promise.all([
      rpc('getutxos', [from.scriptHash, Number(G4.limits.UTXO_PAGE_MAX)], rpcUrl, fetchImpl),
      rpc('getchaininfo', [], rpcUrl, fetchImpl),
    ]);
    const utxos = G4.parseUtxos(utxoResult);
    const chain = G4.parseChainInfo(chainResult);
    if (!Number.isSafeInteger(chain.epoch) || chain.nextBaseFeeMillisatPerGas == null ||
        chain.slot == null || !Number.isSafeInteger(chainResult.behind_by_slots) || chainResult.behind_by_slots > 2) {
      throw new Error('Current Genesis-4 epoch, next base fee, or fresh chain head is unavailable');
    }
    const args = {
      mnemonic, to: addressTo, testnet: false,
      amount_sats: amountSat,
      base_fee_millisat_per_gas: chain.nextBaseFeeMillisatPerGas.toString(),
      epoch: String(chain.epoch),
      utxos: G4.toSignerUtxos(utxos),
    };
    const preview = core.call('g4_transfer_preview', args);
    assertFits(preview);
    let signed;
    for (let attempt = 0; attempt < 5; attempt++) {
      try { signed = core.call('g4_build_and_sign_transfer', args); break; }
      catch (error) {
        if (!/assumed ceiling|but declares/i.test(String(error.message)) || attempt === 4) throw error;
      }
    }
    assertFits(signed);
    if (!HASH.test(signed.txid_hex) || !HASH.test(signed.signing_root_hex) ||
        signed.txid_hex !== preview.txid_hex || signed.signing_root_hex !== preview.signing_root_hex ||
        signed.amount_sats !== amountSat || !signed.raw_hex) {
      throw new Error('Signed transaction differs from its preview');
    }
    return {
      txid: signed.txid_hex,
      rawHex: signed.raw_hex,
      amountSat,
      feeSat: signed.fee_sats,
      inputCount: signed.input_count,
      outputCount: signed.output_count,
      epoch: chain.epoch,
      baseFeeMillisatPerGas: args.base_fee_millisat_per_gas,
      format: signed.format,
      selectedUtxos: signed.selected_utxos,
      utxosTruncated: utxos.truncated,
    };
  } finally { core.dispose(); }
}

/** Broadcast bytes created above. The returned tx_hash is not the consensus txid. */
export async function broadcastSignedTransaction(signed, { rpcUrl = DEFAULT_RPC, fetchImpl = fetch } = {}) {
  if (!HASH.test(signed?.txid) || !/^[0-9a-f]+$/i.test(signed?.rawHex ?? '') || signed.rawHex.length % 2) {
    throw new Error('A signed transaction with txid and rawHex is required');
  }
  const admission = await rpc('sendrawtransaction', [signed.rawHex], rpcUrl, fetchImpl);
  if (admission?.accepted !== true) {
    throw new Error('sendrawtransaction did not confirm mempool admission; check the txid before building another transfer');
  }
  return { txid: signed.txid, admission };
}

/** Return an indexed canonical receipt with confirmation and finality status. */
export async function getTransaction(txid, { explorerUrl = DEFAULT_EXPLORER, fetchImpl = fetch } = {}) {
  if (!HASH.test(txid)) throw new Error('txid must be 64 hexadecimal characters');
  const base = explorerUrl.replace(/\/$/, '');
  const receipt = await json(`${base}/api/v1/transactions/${txid.toLowerCase()}`, { method: 'GET' }, fetchImpl);
  if (!HASH.test(receipt.txid) || receipt.txid.toLowerCase() !== txid.toLowerCase() ||
      !Array.isArray(receipt.inputs) || !Array.isArray(receipt.outputs) ||
      !Number.isSafeInteger(receipt.height) || !Number.isSafeInteger(receipt.slot) ||
      !Number.isSafeInteger(receipt.confirmations) ||
      !Number.isSafeInteger(receipt.finalized_height) ||
      !['confirmed', 'finalized'].includes(receipt.status) ||
      receipt.finalized !== (receipt.status === 'finalized') ||
      !['corroborated', 'final'].includes(receipt.corroboration)) {
    throw new Error('Indexer returned an incomplete or mismatched transaction receipt');
  }
  return {
    txid: receipt.txid,
    blockId: receipt.block_id,
    height: receipt.height,
    slot: receipt.slot,
    transactionIndex: receipt.index,
    kind: receipt.kind,
    inputs: receipt.inputs,
    outputs: receipt.outputs,
    feeSat: receipt.fee_sat,
    stakeSat: receipt.stake_sat,
    sizeBytes: receipt.size_bytes,
    confirmations: receipt.confirmations,
    status: receipt.status,
    finalized: receipt.finalized,
    finalizedHeight: receipt.finalized_height,
    observedHeadHeight: receipt.observed_head_height,
    observedHeadSlot: receipt.observed_head_slot,
    corroboration: receipt.corroboration,
    source: receipt.source,
    verification: receipt.verification,
  };
}
