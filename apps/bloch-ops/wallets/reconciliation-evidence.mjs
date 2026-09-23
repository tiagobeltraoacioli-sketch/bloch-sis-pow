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
const SCHEMA = 'bloch.genesis4.reconciliation-evidence.v2';

function pick(source, fields) {
  return Object.fromEntries(fields.map(field => [field, source[field]]));
}

function snapshotReceipt(receipt) {
  return {
    ...pick(receipt, RECEIPT_FIELDS),
    inputs: receipt.inputs.map(entry => pick(entry, ENTRY_FIELDS)),
    outputs: receipt.outputs.map(entry => pick(entry, ENTRY_FIELDS)),
  };
}

function snapshotObservation(observation) {
  if (observation === null) return null;
  if (observation.kind === 'unresolved') {
    return { kind: 'unresolved', txid: observation.txid };
  }
  return { kind: 'included', txid: observation.txid, receipt: snapshotReceipt(observation.receipt) };
}

function sameJson(left, right) {
  if (left === right) return true;
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object' ||
      Array.isArray(left) !== Array.isArray(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) =>
    key === rightKeys[index] && sameJson(left[key], right[key]));
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
  const previousSnapshot = snapshotObservation(previousObservation);
  const depositMatch = expectedScriptHash === null ? null :
    matchDepositOutputs(receipt, expectedScriptHash, expectedAmountSat);
  return {
    schema: SCHEMA,
    observed_at: observedAt,
    source_url: `https://blochl1.com/api/v1/transactions/${receipt.txid.toLowerCase()}`,
    receipt: snapshotReceipt(receipt),
    previous_observation: previousSnapshot,
    comparison: {
      status: comparison.status,
      requires_review: comparison.requiresReview,
      detail: comparison.detail,
    },
    deposit_match: depositMatch,
    note: 'Public data and local observations only. Recheck source, ownership, block identity, confirmations and finality under your own deposit policy before crediting.',
  };
}

export function verifyReconciliationEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object' || evidence.schema !== SCHEMA) {
    throw new Error('Unsupported reconciliation evidence schema');
  }
  const match = evidence.deposit_match;
  const rebuilt = buildReconciliationEvidence(evidence.receipt, {
    observedAt: evidence.observed_at,
    previousObservation: evidence.previous_observation,
    expectedScriptHash: match === null ? null : match?.scriptHash,
    expectedAmountSat: match === null ? null : match?.expectedAmountSat,
  });
  if (!sameJson(evidence, rebuilt)) {
    throw new Error('Reconciliation evidence does not match its receipt and observations');
  }
  return {
    schema: SCHEMA,
    txid: evidence.receipt.txid,
    observed_at: evidence.observed_at,
    comparison_status: evidence.comparison.status,
    deposit_match: evidence.deposit_match?.exactTotal ?? null,
    structurally_valid: true,
    source_authenticity_verified: false,
    credit_authorized: false,
  };
}
