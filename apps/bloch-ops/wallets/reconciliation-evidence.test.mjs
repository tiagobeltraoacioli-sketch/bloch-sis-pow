import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReconciliationEvidence } from './reconciliation-evidence.mjs';

const txid = 'ab'.repeat(32);
const scriptHash = '02'.repeat(32);
const receipt = {
  txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0,
  kind: 'transfer_v2', size_bytes: 8000, fee_sat: '20', stake_sat: '0',
  inputs: [{ txid: 'ef'.repeat(32), vout: 0, value_sat: '120', script_hash: '01'.repeat(32) }],
  outputs: [{ txid, vout: 0, value_sat: '100', script_hash: scriptHash }],
  confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90,
  observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated',
  source: 'test canonical archive', verification: 'test replay',
};

test('exports only validated public receipt fields and exact matching evidence', () => {
  const supplied = { ...receipt, mnemonic: 'must never be exported',
    outputs: [{ ...receipt.outputs[0], private_key: 'must never be exported' }] };
  const evidence = buildReconciliationEvidence(supplied, {
    observedAt: '2026-09-23T20:00:00.000Z',
    expectedScriptHash: scriptHash,
    expectedAmountSat: '100',
  });
  assert.equal(evidence.schema, 'bloch.genesis4.reconciliation-evidence.v1');
  assert.equal(evidence.receipt.txid, txid);
  assert.equal(evidence.deposit_match.exactTotal, true);
  assert.equal(evidence.deposit_match.outputs[0].vout, 0);
  assert.equal(evidence.comparison.status, 'first_inclusion');
  assert.equal(JSON.stringify(evidence).includes('must never be exported'), false);
});

test('refuses incomplete, contradictory or cross-transaction evidence', () => {
  assert.throws(() => buildReconciliationEvidence({ ...receipt, confirmations: 1 },
    { observedAt: '2026-09-23T20:00:00.000Z' }));
  assert.throws(() => buildReconciliationEvidence(receipt,
    { observedAt: '2026-09-23T20:00:00.000Z', expectedScriptHash: scriptHash }));
  assert.throws(() => buildReconciliationEvidence(receipt, {
    observedAt: '2026-09-23T20:00:00.000Z',
    previousObservation: { kind: 'unresolved', txid: 'ff'.repeat(32) },
  }));
});
