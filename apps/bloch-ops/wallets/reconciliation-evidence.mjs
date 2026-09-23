import { validIncludedReceipt } from './receipt-validator.mjs';
import { compareReceiptObservations } from './receipt-comparison.mjs';
import { matchDepositOutputs } from './deposit-match.mjs';

const RECEIPT_FIELDS = [
  'txid', 'block_id', 'height', 'slot', 'index', 'kind', 'size_bytes',
  'fee_sat', 'stake_sat', 'confirmations', 'status', 'finalized',
  'finalized_height', 'observed_head_height', 'observed_head_slot',
  'corroboration', 'source', 'verification',
];
const ENTRY_FIELDS = ['txid', 'vout', 'value_sat', 'script_hash'];

function pick(source, fields) {
  return Object.fromEntries(fields.map(field => [field, source[field]]));
}

export function buildReconciliationEvidence(receipt, {
  observedAt,
  previousObservation = null,
  expectedScriptHash = null,
  expectedAmountSat = null,
} = {}) {
  if (!validIncludedReceipt(receipt, receipt?.txid)) {
    throw new Error('A complete included receipt is required');
  }
  if (typeof observedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(observedAt) ||
      !Number.isFinite(Date.parse(observedAt))) {
    throw new Error('A UTC observation timestamp is required');
  }
  if ((expectedScriptHash === null) !== (expectedAmountSat === null)) {
    throw new Error('Deposit comparison requires both script hash and amount');
  }
  const current = { kind: 'included', txid: receipt.txid, receipt };
  const comparison = compareReceiptObservations(previousObservation, current);
  const depositMatch = expectedScriptHash === null ? null :
    matchDepositOutputs(receipt, expectedScriptHash, expectedAmountSat);
  return {
    schema: 'bloch.genesis4.reconciliation-evidence.v1',
    observed_at: observedAt,
    source_url: `https://blochl1.com/api/v1/transactions/${receipt.txid.toLowerCase()}`,
    receipt: {
      ...pick(receipt, RECEIPT_FIELDS),
      inputs: receipt.inputs.map(entry => pick(entry, ENTRY_FIELDS)),
      outputs: receipt.outputs.map(entry => pick(entry, ENTRY_FIELDS)),
    },
    comparison: {
      status: comparison.status,
      requires_review: comparison.requiresReview,
      detail: comparison.detail,
    },
    deposit_match: depositMatch,
    note: 'Public data and local observations only. Recheck source, ownership, block identity, confirmations and finality under your own deposit policy before crediting.',
  };
}
