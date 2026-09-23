import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareReceiptObservations } from './receipt-comparison.mjs';

const txid = 'ab'.repeat(32);
const receipt = {
  txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0,
  kind: 'transfer_v2', size_bytes: 8000, fee_sat: '20', stake_sat: '0',
  inputs: [{ txid: 'ef'.repeat(32), vout: 0, value_sat: '120', script_hash: '01'.repeat(32) }],
  outputs: [{ txid, vout: 0, value_sat: '100', script_hash: '02'.repeat(32) }],
  confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90,
  observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated',
  source: 'test archive', verification: 'test replay',
};
const included = value => ({ kind: 'included', txid, receipt: value });

test('first inclusion and stable progress remain observations, not credit approval', () => {
  assert.equal(compareReceiptObservations(null, included(receipt)).status, 'first_inclusion');
  const stable = compareReceiptObservations(included(receipt), included({
    ...receipt, confirmations: 23, observed_head_height: 102,
  }));
  assert.equal(stable.status, 'consistent');
  assert.equal(stable.requiresReview, false);
});

test('missing, moved, altered or regressed receipts require review', () => {
  assert.equal(compareReceiptObservations(included(receipt), { kind: 'unresolved', txid }).status, 'receipt_unavailable');
  assert.equal(compareReceiptObservations(included(receipt), included({ ...receipt, block_id: 'dd'.repeat(32) })).status, 'block_changed');
  assert.equal(compareReceiptObservations(included(receipt), included({
    ...receipt, outputs: [{ ...receipt.outputs[0], value_sat: '99' }],
  })).status, 'receipt_changed');
  assert.equal(compareReceiptObservations(included(receipt), included({
    ...receipt, finalized: false, status: 'confirmed',
  })).status, 'finality_regressed');
  assert.equal(compareReceiptObservations(included(receipt), included({
    ...receipt, confirmations: 21, observed_head_height: 100,
  })).status, 'head_regressed');
});

test('invalid and cross-transaction observations are refused', () => {
  assert.throws(() => compareReceiptObservations(null, included({ ...receipt, outputs: [] , confirmations: 21 })), /Complete/);
  assert.throws(() => compareReceiptObservations(included(receipt), {
    kind: 'unresolved', txid: 'ff'.repeat(32),
  }), /different transaction/);
});
