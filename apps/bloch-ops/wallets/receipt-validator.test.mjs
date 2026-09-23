import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validIncludedReceipt } from './receipt-validator.mjs';

const txid = 'ab'.repeat(32);
const receipt = {
  txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0,
  kind: 'transfer_v2', size_bytes: 8000, fee_sat: '20', stake_sat: '0',
  inputs: [{ txid: 'ef'.repeat(32), vout: 0, value_sat: '120', script_hash: '01'.repeat(32) }],
  outputs: [{ txid, vout: 0, value_sat: '100', script_hash: '02'.repeat(32) }],
  confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90,
  observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated',
  source: 'test canonical archive', verification: 'test replay',
};

test('inspector accepts a complete included receipt', () => {
  assert.equal(validIncludedReceipt(receipt, txid), true);
});

test('inspector refuses contradictory or malformed receipt fields', () => {
  assert.equal(validIncludedReceipt({ ...receipt, outputs: [...receipt.outputs, receipt.outputs[0]] }, txid), false);
  assert.equal(validIncludedReceipt({ ...receipt, inputs: [{ ...receipt.inputs[0], value_sat: '1.5' }] }, txid), false);
  assert.equal(validIncludedReceipt({ ...receipt, outputs: [{ ...receipt.outputs[0], txid: '00'.repeat(32) }] }, txid), false);
  assert.equal(validIncludedReceipt({ ...receipt, confirmations: 21 }, txid), false);
  assert.equal(validIncludedReceipt({ ...receipt, finalized_height: 79 }, txid), false);
});
