import { test } from 'node:test';
import assert from 'node:assert/strict';
import G4 from '../g4.cjs';
import { createCore } from '../core.mjs';
import { createLocalWallet, deriveLocalAddress, createSignedTransaction, broadcastSignedTransaction, getTransaction, getTransactionObservation, compareTransactionObservations, inspectDepositOutputs } from '../index.mjs';

const core = createCore();
const mnemonic = core.call('new_mnemonic', { words: 24 }).mnemonic;
const address = core.call('wallet_from_mnemonic', { mnemonic, testnet: false }).address;
core.dispose();
const txid = 'ab'.repeat(32);
function response(data, status = 200) { return { ok: status === 200, status, async json() { return data; } }; }
const fetchImpl = async (_url, options) => {
  const method = JSON.parse(options.body).method;
  if (method === 'getutxos') return response({ result: { script_hash: '00'.repeat(32), utxos: [{ txid, vout: 0, value_sat: '1000000' }], total: 1001, returned: 1, truncated: true } });
  if (method === 'getchaininfo') return response({ result: { height: 100, slot: 120, epoch: 4, next_base_fee_millisat_per_gas: '10', behind_by_slots: 0 } });
  throw new Error(`Unexpected ${method}`);
};

test('local wallet creation and recovery are deterministic across fresh cores', () => {
  const created = createLocalWallet();
  assert.equal(created.network, 'mainnet');
  assert.equal(created.mnemonic.trim().split(/\s+/).length, 24);
  assert.match(created.address, /^bloch1q[0-9a-f]{48}$/);
  assert.deepEqual(deriveLocalAddress({ mnemonic: created.mnemonic }), {
    address: created.address,
    network: 'mainnet',
  });
  assert.deepEqual(deriveLocalAddress({ mnemonic: `  ${created.mnemonic}  ` }), {
    address: created.address,
    network: 'mainnet',
  });
});

test('local wallet recovery rejects empty and invalid phrases without RPC', () => {
  assert.throws(() => deriveLocalAddress({ mnemonic: '' }), /mnemonic is required/);
  assert.throws(() => deriveLocalAddress({ mnemonic: 'not a valid mnemonic' }));
});

test('high-level SDK produces signed bytes ready for sendrawtransaction', async () => {
  const signed = await createSignedTransaction({ addressFrom: address, mnemonic, addressTo: address, amount: '0.001', fetchImpl });
  assert.match(signed.txid, /^[0-9a-f]{64}$/);
  assert.match(signed.rawHex, /^[0-9a-f]+$/);
  assert.ok(signed.rawHex.length > 1000);
  assert.equal(signed.amountSat, '100000');
  assert.ok(BigInt(signed.feeSat) > 0n);
  assert.equal(signed.utxosTruncated, true);
  assert.match(signed.signingRootHex, /^[0-9a-f]{64}$/);
  assert.match(signed.rawHash, /^[0-9a-f]{64}$/);
});

test('broadcast checks local identity and node byte correlation without using tx_hash as txid', async () => {
  const signed = await createSignedTransaction({ addressFrom: address, mnemonic, addressTo: address, amount: '0.001', fetchImpl });
  let calls = 0;
  const submit = async (_url, options) => {
    calls++;
    const request = JSON.parse(options.body);
    assert.equal(request.method, 'sendrawtransaction');
    assert.deepEqual(request.params, [signed.rawHex]);
    return response({ result: { accepted: true, status: 'accepted', bytes: signed.rawHex.length / 2, tx_hash: signed.rawHash } });
  };
  const result = await broadcastSignedTransaction(signed, { fetchImpl: submit });
  assert.equal(result.txid, signed.txid);
  assert.notEqual(result.txid, result.admission.tx_hash);
  assert.equal(calls, 1);
  await assert.rejects(broadcastSignedTransaction({ ...signed, txid: '00'.repeat(32) }, { fetchImpl: submit }), /nothing was submitted/);
  await assert.rejects(broadcastSignedTransaction({ ...signed, rawHex: `00${signed.rawHex.slice(2)}` }, { fetchImpl: submit }), /nothing was submitted/);
  assert.equal(calls, 1);
  await assert.rejects(broadcastSignedTransaction(signed, { fetchImpl: async () => response({ result: {
    accepted: true, bytes: signed.rawHex.length / 2, tx_hash: '00'.repeat(32),
  } }) }), /mismatched byte count or correlation hash/);
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

test('transaction observation preserves the complete included receipt', async () => {
  const receipt = { txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0, kind: 'transfer_v2', inputs: [], outputs: [], fee_sat: '20', stake_sat: '0', size_bytes: 8000, confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90, observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated' };
  const observed = await getTransactionObservation(txid, { fetchImpl: async () => response(receipt) });
  assert.equal(observed.kind, 'included');
  assert.equal(observed.receipt.status, 'finalized');
});

test('archival 404 yields a node-local unresolved status, never a receipt', async () => {
  const calls = [];
  const observed = await getTransactionObservation(txid, { fetchImpl: async (url, options) => {
    calls.push([url, options?.body ? JSON.parse(options.body).method : 'GET']);
    return options?.body ? response({ result: { status: 'pending' } }) : response({ error: 'not indexed' }, 404);
  } });
  assert.equal(observed.kind, 'unresolved');
  assert.equal(observed.nodeStatus, 'pending');
  assert.equal(observed.receipt, undefined);
  assert.deepEqual(calls.map(call => call[1]), ['GET', 'gettxstatus']);
});

test('node failure after archival 404 remains unresolved', async () => {
  const observed = await getTransactionObservation(txid, { fetchImpl: async (_url, options) => {
    if (!options?.body) return response({ error: 'not indexed' }, 404);
    throw new Error('node unavailable');
  } });
  assert.equal(observed.kind, 'unresolved');
  assert.equal(observed.nodeStatus, null);
  assert.match(observed.observationError, /node unavailable/);
});

test('invalid included receipt is rejected without status fallback', async () => {
  let calls = 0;
  await assert.rejects(getTransactionObservation(txid, { fetchImpl: async () => {
    calls++;
    return response({ txid, inputs: [], outputs: [] });
  } }), /incomplete or mismatched/);
  assert.equal(calls, 1);
});

function included(overrides = {}) {
  return { kind: 'included', txid, receipt: {
    txid, blockId: 'cd'.repeat(32), height: 80, slot: 100, inputs: [{ value_sat: '120' }],
    outputs: [{ value_sat: '100' }], feeSat: '20', stakeSat: '0', confirmations: 22,
    observedHeadHeight: 101, finalized: true, ...overrides,
  } };
}

test('observation comparison identifies stable progress and changed blocks', () => {
  assert.equal(compareTransactionObservations(included(), included({ confirmations: 23, observedHeadHeight: 102 })).status, 'consistent');
  assert.equal(compareTransactionObservations(included(), included({ inputs: [{ value_sat: '120', optional_indexer_note: 'new' }] })).status, 'consistent');
  const moved = compareTransactionObservations(included(), included({ blockId: 'ef'.repeat(32), height: 81 }));
  assert.equal(moved.status, 'block_changed');
  assert.equal(moved.requiresReview, true);
});

test('observation comparison flags missing receipts and regressions', () => {
  assert.equal(compareTransactionObservations(included(), { kind: 'unresolved', txid, nodeStatus: 'unknown' }).status, 'receipt_unavailable');
  assert.equal(compareTransactionObservations(included(), included({ finalized: false })).status, 'finality_regressed');
  assert.equal(compareTransactionObservations(included(), included({ confirmations: 20, observedHeadHeight: 99 })).status, 'head_regressed');
  assert.equal(compareTransactionObservations(included(), included({ outputs: [{ value_sat: '99' }] })).status, 'receipt_changed');
  assert.equal(compareTransactionObservations(null, included()).status, 'first_inclusion');
});

test('observation comparison refuses different or malformed records', () => {
  assert.throws(() => compareTransactionObservations(included(), { kind: 'unresolved', txid: 'ef'.repeat(32) }), /different transaction IDs/);
  assert.throws(() => compareTransactionObservations(included(), { kind: 'included', txid }), /Valid transaction observations/);
});

test('deposit output inspection sums exact integer satoshis by mainnet script hash', () => {
  const script_hash = G4.inspectAddress(address).scriptHash;
  const receipt = {
    txid, blockId: 'cd'.repeat(32), height: 80, slot: 100,
    confirmations: 22, status: 'finalized', finalized: true,
    outputs: [
      { txid, vout: 0, value_sat: '100000000', script_hash },
      { txid, vout: 1, value_sat: '25000000', script_hash },
      { txid, vout: 2, value_sat: '50000000', script_hash: 'ef'.repeat(32) },
    ],
  };
  const result = inspectDepositOutputs({ transaction: receipt, addressTo: address, amount: '1.25' });
  assert.equal(result.matchedAmountSat, '125000000');
  assert.equal(result.differenceSat, '0');
  assert.equal(result.exactTotal, true);
  assert.deepEqual(result.matchingOutputs.map(output => output.vout), [0, 1]);
  assert.equal(inspectDepositOutputs({ transaction: receipt, addressTo: address, amount: '1.3' }).differenceSat, '-5000000');
});

test('deposit output inspection rejects malformed or duplicate output records', () => {
  const script_hash = G4.inspectAddress(address).scriptHash;
  const receipt = { txid, blockId: 'cd'.repeat(32), height: 80, slot: 100,
    confirmations: 22, status: 'confirmed', finalized: false,
    outputs: [{ txid, vout: 0, value_sat: '100', script_hash }] };
  const inspect = transaction => inspectDepositOutputs({ transaction, addressTo: address, amount: '0.00000100' });
  assert.throws(() => inspect({ ...receipt, outputs: [...receipt.outputs, receipt.outputs[0]] }), /duplicate output/);
  assert.throws(() => inspect({ ...receipt, outputs: [{ ...receipt.outputs[0], value_sat: '1.25' }] }), /invalid or duplicate output/);
  assert.throws(() => inspect({ ...receipt, outputs: [{ ...receipt.outputs[0], txid: 'ef'.repeat(32) }] }), /invalid or duplicate output/);
  assert.throws(() => inspect({ ...receipt, status: 'pending' }), /complete included/);
  assert.throws(() => inspectDepositOutputs({ transaction: receipt, addressTo: address, amount: 0.1 }));
});
