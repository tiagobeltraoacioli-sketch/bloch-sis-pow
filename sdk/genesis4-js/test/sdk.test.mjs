import { test } from 'node:test';
import assert from 'node:assert/strict';
import G4 from '../g4.cjs';
import { createCore } from '../core.mjs';
import { createLocalWallet, deriveLocalAddress, createSignedTransaction, broadcastSignedTransaction, getTransaction, getTransactionObservation, trackSignedTransaction, compareTransactionObservations, inspectDepositOutputs } from '../index.mjs';

const core = createCore();
const mnemonic = core.call('new_mnemonic', { words: 24 }).mnemonic;
const address = core.call('wallet_from_mnemonic', { mnemonic, testnet: false }).address;
core.dispose();
const txid = 'ab'.repeat(32);
const receiptFixture = {
  txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0,
  kind: 'transfer_v2', size_bytes: 8000, fee_sat: '20', stake_sat: '0',
  inputs: [{ txid: 'ef'.repeat(32), vout: 0, value_sat: '120', script_hash: '01'.repeat(32) }],
  outputs: [{ txid, vout: 0, value_sat: '100', script_hash: '02'.repeat(32) }],
  confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90,
  observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated',
  source: 'test canonical archive', verification: 'test replay',
};
function response(data, status = 200) {
  const body = data && typeof data === 'object' && !Array.isArray(data) &&
    (Object.hasOwn(data, 'result') || Object.hasOwn(data, 'error')) && status === 200
    ? { jsonrpc: '2.0', id: 1, ...data } : data;
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}
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

test('explicit cursor mode enumerates a stable complete UTXO view before signing', async () => {
  const script_hash = G4.inspectAddress(address).scriptHash;
  const head = 'cc'.repeat(32);
  const token = `01${head}${script_hash}${'11'.repeat(32)}00000000`;
  const calls = [];
  const pagedFetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    calls.push(request);
    if (request.method === 'getchaininfo') return response({ result: {
      block_id: head, height: 100, slot: 120, epoch: 4,
      next_base_fee_millisat_per_gas: '10', behind_by_slots: 0,
    } });
    assert.equal(request.method, 'getutxos');
    assert.equal(request.params[0], script_hash);
    const first = request.params[2] === null;
    assert.equal(request.params[2], first ? null : token);
    return response({ result: {
      script_hash, at_head: head, at_slot: 120, total: 2, returned: 1,
      truncated: first, next_cursor: first ? token : null,
      utxos: [{ txid: (first ? '11' : '22').repeat(32), vout: 0,
        value_sat: '1000000', script_hash }],
    } });
  };
  const signed = await createSignedTransaction({
    addressFrom: address, mnemonic, addressTo: address, amount: '0.001',
    utxoMode: 'cursor', fetchImpl: pagedFetch,
  });
  assert.equal(signed.utxosTruncated, false);
  assert.equal(signed.utxoPageCount, 2);
  assert.equal(signed.utxoSourceHead, head);
  assert.deepEqual(calls.map(call => call.method), ['getutxos', 'getutxos', 'getchaininfo']);
});

test('cursor mode fails closed on legacy replies, page conflicts and safety limit', async () => {
  const script_hash = G4.inspectAddress(address).scriptHash;
  const head = 'cc'.repeat(32);
  const token = `01${head}${script_hash}${'11'.repeat(32)}00000000`;
  const page = (txid, truncated, override = {}) => ({
    script_hash, at_head: head, at_slot: 120, total: 2, returned: 1,
    truncated, next_cursor: truncated ? token : null,
    utxos: [{ txid, vout: 0, value_sat: '1000000', script_hash }],
    ...override,
  });
  const callWith = getPage => createSignedTransaction({
    addressFrom: address, mnemonic, addressTo: address, amount: '0.001',
    utxoMode: 'cursor', fetchImpl: async (_url, options) => {
      const request = JSON.parse(options.body);
      if (request.method !== 'getutxos') throw new Error('Signing reached chain read after bad pages');
      return response({ result: getPage(request.params[2]) });
    },
  });
  await assert.rejects(callWith(() => ({ script_hash, total: 1, returned: 1,
    truncated: false, utxos: [{ txid, vout: 0, value_sat: '1000000', script_hash }] })), /cursor protocol/);
  await assert.rejects(callWith(() => page('11'.repeat(32), true, {
    next_cursor: '01'.padEnd(202, '0'),
  })), /does not bind/);
  await assert.rejects(callWith(cursor => cursor === null ? page('11'.repeat(32), true)
    : page('11'.repeat(32), false)), /repeated or reordered/);
  await assert.rejects(callWith(cursor => cursor === null ? page('11'.repeat(32), true)
    : page('22'.repeat(32), false, { at_head: 'dd'.repeat(32) })), /changed head/);
  await assert.rejects(createSignedTransaction({ addressFrom: address, mnemonic, addressTo: address,
    amount: '0.001', utxoMode: 'cursor', maxUtxoPages: 1,
    fetchImpl: async () => response({ result: page('11'.repeat(32), true) }),
  }), /safety limit/);
  await assert.rejects(createSignedTransaction({ addressFrom: address, mnemonic, addressTo: address,
    amount: '0.001', utxoMode: 'cursor',
    fetchImpl: async (_url, options) => {
      const request = JSON.parse(options.body);
      if (request.method === 'getchaininfo') return response({ result: {
        block_id: 'dd'.repeat(32), height: 100, slot: 120, epoch: 4,
        next_base_fee_millisat_per_gas: '10', behind_by_slots: 0,
      } });
      return response({ result: page(txid, false, { total: 1 }) });
    },
  }), /Chain head changed/);
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

test('stored signed transfer can be observed after a timeout without rebroadcast', async () => {
  const signed = await createSignedTransaction({ addressFrom: address, mnemonic, addressTo: address, amount: '0.001', fetchImpl });
  const calls = [];
  const observation = await trackSignedTransaction(signed, { fetchImpl: async (_url, options) => {
    calls.push(options?.body ? JSON.parse(options.body).method : 'GET');
    return options?.body ? response({ result: { status: 'pending' } }) : response({ error: 'not indexed' }, 404);
  } });
  assert.deepEqual(calls, ['GET', 'gettxstatus']);
  assert.equal(observation.txid, signed.txid);
  assert.equal(observation.observation.kind, 'unresolved');
  assert.equal(observation.comparison.status, 'unresolved');
  assert.equal(observation.comparison.requiresReview, true);
  const includedReceipt = {
    ...receiptFixture, txid: signed.txid,
    outputs: receiptFixture.outputs.map(output => ({ ...output, txid: signed.txid })),
  };
  const included = await trackSignedTransaction(signed, {
    previousObservation: observation.observation,
    fetchImpl: async (_url, options) => {
      assert.equal(options?.body, undefined, 'included lookup must not ask node status');
      return response(includedReceipt);
    },
  });
  assert.equal(included.observation.kind, 'included');
  assert.equal(included.comparison.status, 'first_inclusion');
  assert.equal(included.comparison.requiresReview, true);
  await assert.rejects(trackSignedTransaction({ ...signed, rawHex: `00${signed.rawHex.slice(2)}` }, {
    fetchImpl: () => { throw new Error('Network called'); },
  }), /nothing was submitted/);
});

test('mismatched source address is refused before any RPC', async () => {
  const other = createCore();
  const otherMnemonic = other.call('new_mnemonic', { words: 24 }).mnemonic;
  const otherAddress = other.call('wallet_from_mnemonic', { mnemonic: otherMnemonic, testnet: false }).address;
  other.dispose();
  await assert.rejects(createSignedTransaction({ addressFrom: otherAddress, mnemonic, addressTo: address, amount: '1', fetchImpl: () => { throw new Error('RPC called'); } }), /does not match/);
});

test('transaction lookup includes receipt, confirmations, and finality', async () => {
  const lookupFetch = async () => response(receiptFixture);
  const result = await getTransaction(txid, { fetchImpl: lookupFetch });
  assert.equal(result.confirmations, 22);
  assert.equal(result.status, 'finalized');
  assert.equal(result.outputs[0].value_sat, '100');
});

test('transaction observation preserves the complete included receipt', async () => {
  const observed = await getTransactionObservation(txid, { fetchImpl: async () => response(receiptFixture) });
  assert.equal(observed.kind, 'included');
  assert.equal(observed.receipt.status, 'finalized');
});

test('transaction lookup rejects malformed money, outpoints and inconsistent chain metadata', async () => {
  const lookup = data => getTransaction(txid, { fetchImpl: async () => response(data) });
  await assert.rejects(lookup({ ...receiptFixture, outputs: [{ ...receiptFixture.outputs[0], value_sat: '1.5' }] }), /incomplete or mismatched/);
  await assert.rejects(lookup({ ...receiptFixture, outputs: [receiptFixture.outputs[0], receiptFixture.outputs[0]] }), /incomplete or mismatched/);
  await assert.rejects(lookup({ ...receiptFixture, inputs: [{ ...receiptFixture.inputs[0], script_hash: 'bad' }] }), /incomplete or mismatched/);
  await assert.rejects(lookup({ ...receiptFixture, outputs: [{ ...receiptFixture.outputs[0], txid: '00'.repeat(32) }] }), /incomplete or mismatched/);
  await assert.rejects(lookup({ ...receiptFixture, confirmations: 21 }), /incomplete or mismatched/);
  await assert.rejects(lookup({ ...receiptFixture, finalized_height: 79 }), /incomplete or mismatched/);
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
  assert.match(observed.observationError, /network request failed/);
});

test('transport rejects oversized and malformed successful responses without server text', async () => {
  const oversized = new Response('x'.repeat(2 * 1024 * 1024 + 1));
  await assert.rejects(getTransaction(txid, { fetchImpl: async () => oversized }), /response exceeds 2097152 bytes/);
  await assert.rejects(getTransaction(txid, { fetchImpl: async () =>
    new Response('{"secret":"server-payload"') }), error =>
    /invalid JSON response/.test(error.message) && !error.message.includes('server-payload'));
  await assert.rejects(getTransaction(txid, { fetchImpl: async () =>
    new Response('server-payload', { status: 503 }) }), error =>
    error.status === 503 && /HTTP 503/.test(error.message) && !error.message.includes('server-payload'));
  await assert.rejects(getTransaction(txid, { fetchImpl: async () => {
    const error = new Error('Archival transaction: secret transport detail');
    error.status = 404;
    throw error;
  } }), error => error.status === undefined && error.message === 'Archival transaction: network request failed');
});

test('RPC validates id, version and exclusive result/error fields before use', async () => {
  const malformed = [
    { jsonrpc: '2.0', id: 2, result: { status: 'pending' } },
    { jsonrpc: '1.0', id: 1, result: { status: 'pending' } },
    { jsonrpc: '2.0', id: 1, result: { status: 'pending' }, error: null },
    { jsonrpc: '2.0', id: 1 },
  ];
  for (const payload of malformed) {
    const observed = await getTransactionObservation(txid, { fetchImpl: async (_url, options) =>
      options?.body ? response(payload) : response({ error: 'not indexed' }, 404) });
    assert.equal(observed.kind, 'unresolved');
    assert.equal(observed.nodeStatus, null);
    assert.match(observed.observationError, /invalid JSON-RPC response envelope/);
  }
});

test('RPC errors expose stable codes but never a server supplied message', async () => {
  const secret = 'private-upstream-message';
  const observed = await getTransactionObservation(txid, { fetchImpl: async (_url, options) =>
    options?.body ? response({ error: { code: -32603, message: secret } })
      : response({ error: 'not indexed' }, 404) });
  assert.equal(observed.nodeStatus, null);
  assert.match(observed.observationError, /RPC error -32603/);
  assert.ok(!observed.observationError.includes(secret));
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
    txid, blockId: 'cd'.repeat(32), height: 80, slot: 100,
    transactionIndex: 0, kind: 'transfer_v2', sizeBytes: 8000,
    inputs: [{ ...receiptFixture.inputs[0] }], outputs: [{ ...receiptFixture.outputs[0] }],
    feeSat: '20', stakeSat: '0', confirmations: 22,
    observedHeadHeight: 101, observedHeadSlot: 121, finalizedHeight: 90,
    status: 'finalized', finalized: true, corroboration: 'final',
    source: 'test canonical archive', verification: 'test replay', ...overrides,
  } };
}

test('observation comparison identifies stable progress and changed blocks', () => {
  assert.equal(compareTransactionObservations(included(), included({ confirmations: 23, observedHeadHeight: 102, observedHeadSlot: 122 })).status, 'consistent');
  assert.equal(compareTransactionObservations(included(), included({ inputs: [{ ...receiptFixture.inputs[0], optional_indexer_note: 'new' }] })).status, 'consistent');
  const moved = compareTransactionObservations(included(), included({ blockId: 'ef'.repeat(32), height: 81, confirmations: 21 }));
  assert.equal(moved.status, 'block_changed');
  assert.equal(moved.requiresReview, true);
});

test('observation comparison flags missing receipts and regressions', () => {
  assert.equal(compareTransactionObservations(included(), { kind: 'unresolved', txid, nodeStatus: 'unknown' }).status, 'receipt_unavailable');
  assert.equal(compareTransactionObservations(included(), included({ finalized: false, status: 'confirmed' })).status, 'finality_regressed');
  assert.equal(compareTransactionObservations(included(), included({ confirmations: 20, observedHeadHeight: 99 })).status, 'head_regressed');
  assert.equal(compareTransactionObservations(included(), included({ outputs: [{ ...receiptFixture.outputs[0], value_sat: '99' }] })).status, 'receipt_changed');
  assert.equal(compareTransactionObservations(null, included()).status, 'first_inclusion');
});

test('observation comparison refuses different or malformed records', () => {
  assert.throws(() => compareTransactionObservations(included(), { kind: 'unresolved', txid: 'ef'.repeat(32) }), /different transaction IDs/);
  assert.throws(() => compareTransactionObservations(included(), { kind: 'included', txid }), /Valid transaction observations/);
});

test('observation comparison reviews changed metadata and finality or slot regressions', () => {
  for (const change of [{ transactionIndex: 1 }, { kind: 'stake_v2' }, { sizeBytes: 8001 }]) {
    assert.equal(compareTransactionObservations(included(), included(change)).status, 'receipt_changed');
  }
  assert.equal(compareTransactionObservations(included(), included({ finalizedHeight: 89 })).status, 'finality_regressed');
  assert.equal(compareTransactionObservations(included(), included({ corroboration: 'corroborated' })).status, 'finality_regressed');
  assert.equal(compareTransactionObservations(included(), included({ observedHeadSlot: 120 })).status, 'head_regressed');
});

test('observation comparison rejects structurally incomplete included receipts', () => {
  const malformed = [
    { transactionIndex: undefined }, { sizeBytes: 0 }, { finalizedHeight: 102 },
    { observedHeadSlot: 99 }, { confirmations: 21 }, { feeSat: '-1' },
    { outputs: [{ ...receiptFixture.outputs[0], value_sat: '18446744073709551616' }] },
    { outputs: [receiptFixture.outputs[0], receiptFixture.outputs[0]] },
  ];
  for (const change of malformed) {
    assert.throws(() => compareTransactionObservations(included(), included(change)), /Valid transaction observations/);
  }
});

test('deposit output inspection sums exact integer satoshis by mainnet script hash', () => {
  const script_hash = G4.inspectAddress(address).scriptHash;
  const receipt = { ...included().receipt,
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
  const receipt = { ...included().receipt, status: 'confirmed', finalized: false,
    outputs: [{ txid, vout: 0, value_sat: '100', script_hash }] };
  const inspect = transaction => inspectDepositOutputs({ transaction, addressTo: address, amount: '0.00000100' });
  assert.throws(() => inspect({ ...receipt, outputs: [...receipt.outputs, receipt.outputs[0]] }), /duplicate output/);
  assert.throws(() => inspect({ ...receipt, outputs: [{ ...receipt.outputs[0], value_sat: '1.25' }] }), /invalid or duplicate output/);
  assert.throws(() => inspect({ ...receipt, outputs: [{ ...receipt.outputs[0], txid: 'ef'.repeat(32) }] }), /invalid or duplicate output/);
  assert.throws(() => inspect({ ...receipt, outputs: [{ ...receipt.outputs[0], value_sat: '18446744073709551616' }] }), /invalid or duplicate output/);
  assert.throws(() => inspect({ ...receipt, observedHeadHeight: 79 }), /complete included/);
  assert.throws(() => inspect({ ...receipt, finalizedHeight: 102 }), /complete included/);
  assert.throws(() => inspect({ ...receipt, status: 'pending' }), /complete included/);
  assert.throws(() => inspectDepositOutputs({ transaction: receipt, addressTo: address, amount: 0.1 }));
});
