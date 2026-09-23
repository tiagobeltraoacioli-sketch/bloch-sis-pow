// SPDX-License-Identifier: AGPL-3.0-or-later
import G4 from './g4.cjs';
import { createCore } from './core.mjs';
import { createHash } from 'node:crypto';

const DEFAULT_RPC = 'https://posternlabs.com/g4rpc';
const DEFAULT_EXPLORER = 'https://blochl1.com';
const HASH = /^[0-9a-f]{64}$/i;
const UINT = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = (1n << 64n) - 1n;
const TXID_DOMAIN = Buffer.from('BLCH4:TXID\0\0\0\0\0\0', 'ascii');

function rawCorrelationHash(rawHex) {
  return createHash('sha3-256').update(Buffer.from(rawHex, 'hex')).digest('hex');
}

function txidFromSigningRoot(rootHex) {
  return createHash('sha3-256').update(TXID_DOMAIN).update(Buffer.from(rootHex, 'hex')).digest('hex');
}

function uint64String(value) {
  return typeof value === 'string' && UINT.test(value) && BigInt(value) <= MAX_U64;
}

function validReceiptEntries(entries, receiptTxid, outputs) {
  if (!Array.isArray(entries)) return false;
  const seen = new Set();
  for (const entry of entries) {
    if (!HASH.test(entry?.txid) || !Number.isSafeInteger(entry.vout) || entry.vout < 0 ||
        !HASH.test(entry.script_hash) || !uint64String(entry.value_sat) ||
        (outputs && entry.txid.toLowerCase() !== receiptTxid.toLowerCase())) return false;
    const outpoint = `${entry.txid.toLowerCase()}:${entry.vout}`;
    if (seen.has(outpoint)) return false;
    seen.add(outpoint);
  }
  return true;
}

function mainnetAddress(value, name) {
  const info = G4.inspectAddress(value);
  if (!info.verified || info.network !== 'mainnet') {
    throw new Error(`${name}: a checksummed Genesis-4 mainnet address is required (${info.message})`);
  }
  return info;
}

/** Create a fresh Genesis-4 mainnet identity in this Node.js process; no RPC call occurs. */
export function createLocalWallet() {
  const core = createCore();
  try {
    const generated = core.call('new_mnemonic', { words: 24 });
    if (typeof generated?.mnemonic !== 'string' || generated.mnemonic.trim().split(/\s+/).length !== 24) {
      throw new Error('Genesis-4 core did not return a 24-word mnemonic');
    }
    const wallet = core.call('wallet_from_mnemonic', { mnemonic: generated.mnemonic, testnet: false });
    mainnetAddress(wallet?.address, 'generated address');
    return { mnemonic: generated.mnemonic, address: wallet.address, network: 'mainnet' };
  } finally { core.dispose(); }
}

/** Recover the Genesis-4 mainnet address for an existing phrase, entirely locally. */
export function deriveLocalAddress({ mnemonic }) {
  if (typeof mnemonic !== 'string' || !mnemonic.trim()) throw new Error('mnemonic is required');
  const core = createCore();
  try {
    const normalized = core.call('normalize_mnemonic', { mnemonic });
    if (typeof normalized?.mnemonic !== 'string' || !normalized.mnemonic) {
      throw new Error('Genesis-4 core did not normalize the mnemonic');
    }
    const wallet = core.call('wallet_from_mnemonic', { mnemonic: normalized.mnemonic, testnet: false });
    mainnetAddress(wallet?.address, 'derived address');
    return { address: wallet.address, network: 'mainnet' };
  } finally { core.dispose(); }
}

async function json(url, options, fetchImpl) {
  const response = await fetchImpl(url, { ...options, redirect: 'error' });
  let body;
  try { body = await response.json(); }
  catch (cause) {
    if (response.ok) throw cause;
    const error = new Error(`${url}: HTTP ${response.status}: non-JSON error response`);
    error.status = response.status;
    throw error;
  }
  if (!response.ok) {
    const error = new Error(`${url}: HTTP ${response.status}: ${JSON.stringify(body.error ?? body)}`);
    error.status = response.status;
    throw error;
  }
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
  if (value.raw_hex && (!/^[0-9a-f]+$/i.test(value.raw_hex) || value.raw_hex.length % 2 ||
      value.raw_hex.length / 2 > limits.RPC_MAX_RAW_TX_BYTES)) {
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
    if (txidFromSigningRoot(signed.signing_root_hex) !== signed.txid_hex) {
      throw new Error('Signed transaction ID differs from its domain-separated signing root');
    }
    return {
      txid: signed.txid_hex,
      rawHex: signed.raw_hex,
      signingRootHex: signed.signing_root_hex,
      rawHash: rawCorrelationHash(signed.raw_hex),
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
  if (!HASH.test(signed?.txid) || !HASH.test(signed?.signingRootHex) || !HASH.test(signed?.rawHash) ||
      !/^[0-9a-f]+$/i.test(signed?.rawHex ?? '') || signed.rawHex.length % 2 ||
      signed.rawHex.length / 2 > G4.limits.RPC_MAX_RAW_TX_BYTES) {
    throw new Error('A complete SDK signed transaction with txid, signingRootHex, rawHash and rawHex is required');
  }
  if (txidFromSigningRoot(signed.signingRootHex) !== signed.txid.toLowerCase() ||
      rawCorrelationHash(signed.rawHex) !== signed.rawHash.toLowerCase()) {
    throw new Error('Signed transaction identity or bytes changed; nothing was submitted');
  }
  const admission = await rpc('sendrawtransaction', [signed.rawHex], rpcUrl, fetchImpl);
  if (admission?.accepted !== true) {
    throw new Error('sendrawtransaction did not confirm mempool admission; check the txid before building another transfer');
  }
  if (admission.tx_hash?.toLowerCase() !== signed.rawHash.toLowerCase() ||
      admission.bytes !== signed.rawHex.length / 2) {
    throw new Error('Node reported admission with mismatched byte count or correlation hash; check the original txid before any retry');
  }
  return { txid: signed.txid, admission };
}

/** Return an indexed canonical receipt with confirmation and finality status. */
export async function getTransaction(txid, { explorerUrl = DEFAULT_EXPLORER, fetchImpl = fetch } = {}) {
  if (!HASH.test(txid)) throw new Error('txid must be 64 hexadecimal characters');
  const base = explorerUrl.replace(/\/$/, '');
  const receipt = await json(`${base}/api/v1/transactions/${txid.toLowerCase()}`, { method: 'GET' }, fetchImpl);
  if (!HASH.test(receipt.txid) || receipt.txid.toLowerCase() !== txid.toLowerCase() ||
      !HASH.test(receipt.block_id) ||
      !validReceiptEntries(receipt.inputs, receipt.txid, false) ||
      !validReceiptEntries(receipt.outputs, receipt.txid, true) ||
      ![receipt.height, receipt.slot, receipt.index, receipt.size_bytes,
        receipt.confirmations, receipt.finalized_height, receipt.observed_head_height,
        receipt.observed_head_slot].every(value => Number.isSafeInteger(value) && value >= 0) ||
      receipt.size_bytes === 0 || receipt.observed_head_height < receipt.height ||
      receipt.observed_head_slot < receipt.slot ||
      receipt.finalized_height > receipt.observed_head_height ||
      receipt.confirmations !== receipt.observed_head_height - receipt.height + 1 ||
      !uint64String(receipt.fee_sat) || !uint64String(receipt.stake_sat) ||
      typeof receipt.kind !== 'string' || !receipt.kind ||
      typeof receipt.source !== 'string' || !receipt.source ||
      typeof receipt.verification !== 'string' || !receipt.verification ||
      !['confirmed', 'finalized'].includes(receipt.status) ||
      receipt.finalized !== (receipt.status === 'finalized') ||
      (receipt.finalized && receipt.finalized_height < receipt.height) ||
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

/** Reconcile an included receipt or report a single node's unresolved observation. */
export async function getTransactionObservation(txid, {
  explorerUrl = DEFAULT_EXPLORER, rpcUrl = DEFAULT_RPC, fetchImpl = fetch,
} = {}) {
  if (!HASH.test(txid)) throw new Error('txid must be 64 hexadecimal characters');
  try {
    const receipt = await getTransaction(txid, { explorerUrl, fetchImpl });
    return { kind: 'included', txid: receipt.txid, receipt };
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  try {
    const result = await rpc('gettxstatus', [txid.toLowerCase()], rpcUrl, fetchImpl);
    const status = result?.status;
    if (!['pending', 'included', 'justified', 'finalized', 'unknown'].includes(status)) {
      throw new Error('gettxstatus returned an invalid node status');
    }
    return {
      kind: 'unresolved', txid: txid.toLowerCase(), nodeStatus: status,
      source: 'single-node gettxstatus',
      note: 'No canonical archival receipt was found. Node status cannot establish deposit credit, finality, absence or failure.',
    };
  } catch (error) {
    return {
      kind: 'unresolved', txid: txid.toLowerCase(), nodeStatus: null,
      source: 'archival 404; node status unavailable',
      note: 'No canonical archival receipt or usable node observation was available. Do not infer transaction failure.',
      observationError: error.message,
    };
  }
}

/** Compare saved observations without deciding an exchange's credit or payout policy. */
export function compareTransactionObservations(previous, current) {
  const valid = item => item && HASH.test(item.txid) &&
    (item.kind === 'unresolved' || (item.kind === 'included' && item.receipt &&
      HASH.test(item.receipt.blockId) && item.receipt.txid?.toLowerCase() === item.txid.toLowerCase() &&
      [item.receipt.height, item.receipt.slot, item.receipt.confirmations,
        item.receipt.observedHeadHeight].every(value => Number.isSafeInteger(value) && value >= 0) &&
      Array.isArray(item.receipt.inputs) && Array.isArray(item.receipt.outputs) &&
      typeof item.receipt.finalized === 'boolean'));
  if (!valid(current) || (previous != null && !valid(previous))) {
    throw new Error('Valid transaction observations are required');
  }
  if (previous && previous.txid.toLowerCase() !== current.txid.toLowerCase()) {
    throw new Error('Cannot compare different transaction IDs');
  }
  const result = (status, requiresReview, detail) => ({
    txid: current.txid.toLowerCase(), status, requiresReview, detail,
  });
  if (current.kind === 'unresolved') {
    return previous?.kind === 'included'
      ? result('receipt_unavailable', true, 'A previously included receipt is unavailable. Check the index and chain independently; do not infer a reorg or failure from this alone.')
      : result('unresolved', true, 'Only a node-local status or no status is available; there is no included archival receipt.');
  }
  if (previous?.kind !== 'included') {
    return result('first_inclusion', true, 'An included receipt is now available. Apply your own amount, destination, confirmation and finality checks.');
  }
  const before = previous.receipt, after = current.receipt;
  if (before.blockId.toLowerCase() !== after.blockId.toLowerCase() ||
      before.height !== after.height || before.slot !== after.slot) {
    return result('block_changed', true, 'The recorded inclusion moved to a different block, height or slot. Review chain history and the stored credit decision.');
  }
  const transfers = receipt => [receipt.inputs, receipt.outputs].map(entries =>
    entries.map(({ txid, vout, value_sat, script_hash }) => [txid, vout, value_sat, script_hash]));
  if (JSON.stringify([transfers(before), before.feeSat, before.stakeSat]) !==
      JSON.stringify([transfers(after), after.feeSat, after.stakeSat])) {
    return result('receipt_changed', true, 'The indexed transaction contents changed for the same txid and block. Review the source records.');
  }
  if (before.finalized && !after.finalized) {
    return result('finality_regressed', true, 'The reported finality flag regressed. Compare independent nodes and checkpoints.');
  }
  if (after.confirmations < before.confirmations || after.observedHeadHeight < before.observedHeadHeight) {
    return result('head_regressed', true, 'The reported head or confirmation count moved backward. Check for stale data or a chain reorganization.');
  }
  return result('consistent', false, 'The stored inclusion and reported progress are consistent across these two observations; this is not independent settlement proof.');
}

/** Match canonical receipt outputs to an expected mainnet address and decimal BLOCH amount. */
export function inspectDepositOutputs({ transaction, addressTo, amount }) {
  const target = mainnetAddress(addressTo, 'addressTo');
  const expectedAmountSat = G4.sats.toWire(G4.sats.fromUserBLCH(amount));
  if (!transaction || !HASH.test(transaction.txid) || !HASH.test(transaction.blockId) ||
      !Array.isArray(transaction.outputs) ||
      !Number.isSafeInteger(transaction.height) || transaction.height < 0 ||
      !Number.isSafeInteger(transaction.slot) || transaction.slot < 0 ||
      !Number.isSafeInteger(transaction.confirmations) || transaction.confirmations < 0 ||
      !['confirmed', 'finalized'].includes(transaction.status) ||
      transaction.finalized !== (transaction.status === 'finalized')) {
    throw new Error('A complete included transaction receipt is required');
  }
  const seen = new Set();
  const matchingOutputs = [];
  for (const output of transaction.outputs) {
    if (!HASH.test(output?.txid) || output.txid.toLowerCase() !== transaction.txid.toLowerCase() ||
        !Number.isSafeInteger(output.vout) || output.vout < 0 ||
        !HASH.test(output.script_hash) ||
        typeof output.value_sat !== 'string' || !/^(0|[1-9][0-9]*)$/.test(output.value_sat) ||
        seen.has(output.vout)) {
      throw new Error('Receipt contains an invalid or duplicate output');
    }
    seen.add(output.vout);
    if (output.script_hash.toLowerCase() === target.scriptHash.toLowerCase()) {
      matchingOutputs.push({ txid: transaction.txid, vout: output.vout, valueSat: output.value_sat });
    }
  }
  const matchedAmountSat = matchingOutputs.reduce((total, output) => total + BigInt(output.valueSat), 0n);
  const expected = BigInt(expectedAmountSat);
  return {
    txid: transaction.txid, blockId: transaction.blockId,
    height: transaction.height, slot: transaction.slot,
    confirmations: transaction.confirmations, finalized: transaction.finalized,
    address: addressTo, scriptHash: target.scriptHash,
    expectedAmountSat, matchedAmountSat: matchedAmountSat.toString(),
    differenceSat: (matchedAmountSat - expected).toString(),
    exactTotal: matchedAmountSat === expected,
    matchingOutputs,
    note: 'Output matching is a receipt inspection, not a deposit credit decision. Apply your own finality, ownership and duplicate-credit policy.',
  };
}
