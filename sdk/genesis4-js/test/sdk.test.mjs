import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCore } from '../core.mjs';
import { createSignedTransaction, getTransaction } from '../index.mjs';

const core = createCore();
const mnemonic = core.call('new_mnemonic', { words: 24 }).mnemonic;
const address = core.call('wallet_from_mnemonic', { mnemonic, testnet: false }).address;
core.dispose();
const txid = 'ab'.repeat(32);
function response(data, status = 200) { return { ok: status === 200, status, async json() { return data; } }; }
const fetchImpl = async (_url, options) => {
  const method = JSON.parse(options.body).method;
  if (method === 'getutxos') return response({ result: { script_hash: '00'.repeat(32), utxos: [{ txid, vout: 0, value_sat: '1000000' }], total: 1, returned: 1, truncated: false } });
  if (method === 'getchaininfo') return response({ result: { height: 100, slot: 120, epoch: 4, next_base_fee_millisat_per_gas: '10', behind_by_slots: 0 } });
  throw new Error(`Unexpected ${method}`);
};

test('high-level SDK produces signed bytes ready for sendrawtransaction', async () => {
  const signed = await createSignedTransaction({ addressFrom: address, mnemonic, addressTo: address, amount: '0.001', fetchImpl });
  assert.match(signed.txid, /^[0-9a-f]{64}$/);
  assert.match(signed.rawHex, /^[0-9a-f]+$/);
  assert.ok(signed.rawHex.length > 1000);
  assert.equal(signed.amountSat, '100000');
  assert.ok(BigInt(signed.feeSat) > 0n);
});

test('mismatched source address is refused before any RPC', async () => {
  const other = createCore();
  const otherMnemonic = other.call('new_mnemonic', { words: 24 }).mnemonic;
  const otherAddress = other.call('wallet_from_mnemonic', { mnemonic: otherMnemonic, testnet: false }).address;
  other.dispose();
  await assert.rejects(createSignedTransaction({ addressFrom: otherAddress, mnemonic, addressTo: address, amount: '1', fetchImpl: () => { throw new Error('RPC called'); } }), /does not match/);
});

test('transaction lookup includes receipt, confirmations, and finality', async () => {
  const lookupFetch = async () => response({ txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0, kind: 'transfer_v2', inputs: [{ value_sat: '120' }], outputs: [{ value_sat: '100' }], fee_sat: '20', stake_sat: '0', size_bytes: 8000, confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90, observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated' });
  const result = await getTransaction(txid, { fetchImpl: lookupFetch });
  assert.equal(result.confirmations, 22);
  assert.equal(result.status, 'finalized');
  assert.equal(result.outputs[0].value_sat, '100');
});
