import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchDepositOutputs } from './deposit-match.mjs';

const txid = 'ab'.repeat(32), target = '01'.repeat(32);
const receipt = {
  txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0,
  kind: 'transfer_v2', size_bytes: 8000, fee_sat: '20', stake_sat: '0',
  inputs: [{ txid: 'ef'.repeat(32), vout: 0, value_sat: '120', script_hash: '02'.repeat(32) }],
  outputs: [
    { txid, vout: 0, value_sat: '40', script_hash: target },
    { txid, vout: 1, value_sat: '60', script_hash: target },
    { txid, vout: 2, value_sat: '5', script_hash: '03'.repeat(32) },
  ],
  confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90,
  observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated',
  source: 'test archive', verification: 'test replay',
};

test('sums only matching public outputs with exact integer satoshis', () => {
  const result = matchDepositOutputs(receipt, target.toUpperCase(), '100');
  assert.equal(result.exactTotal, true);
  assert.equal(result.matchedAmountSat, '100');
  assert.deepEqual(result.outputs.map(output => output.vout), [0, 1]);
  assert.equal(matchDepositOutputs(receipt, target, '101').differenceSat, '-1');
  assert.equal(matchDepositOutputs(receipt, '04'.repeat(32), '100').exactTotal, false);
});

test('rejects invalid target, money and receipt before matching', () => {
  for (const amount of ['0', '01', '-1', '1.5', '18446744073709551616']) {
    assert.throws(() => matchDepositOutputs(receipt, target, amount), /Expected amount/);
  }
  assert.throws(() => matchDepositOutputs(receipt, 'bad', '100'), /script hash/);
  assert.throws(() => matchDepositOutputs({ ...receipt, outputs: [receipt.outputs[0], receipt.outputs[0]] }, target, '100'), /complete included receipt/);
});
