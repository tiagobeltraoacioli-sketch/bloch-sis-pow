// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import G4 from '../g4.cjs';
import { broadcastSignedTransaction, trackSignedTransaction,
  getDepositTransaction, inspectDepositOutputs } from '../index.mjs';
import { createHash } from 'node:crypto';
import { syntheticTransfer } from './synthetic-transfer.mjs';

const hash160 = '12'.repeat(20);
const address = 'bloch1q' + hash160 + G4.checksumForHash160(hash160);
const scriptHash = hash160 + '00'.repeat(12);
const txid = 'ab'.repeat(32);
const receipt = {
  txid, block_id: 'cd'.repeat(32), height: 80, slot: 100, index: 0,
  kind: 'transfer_v2', size_bytes: 8000, fee_sat: '20', stake_sat: '0',
  inputs: [{ txid: 'ef'.repeat(32), vout: 0, value_sat: '120', script_hash: '01'.repeat(32) }],
  outputs: [{ txid, vout: 0, value_sat: '100', script_hash: scriptHash }],
  confirmations: 22, status: 'finalized', finalized: true, finalized_height: 90,
  observed_head_height: 101, observed_head_slot: 121, corroboration: 'corroborated',
  source: 'synthetic offline P2B boundary audit', verification: 'fixture only',
};
const response = (body) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });

test('public checksum fixture maps to the exact padded native L1 script hash', () => {
  const inspected = G4.inspectAddress(address);
  assert.equal(inspected.verified, true);
  assert.equal(inspected.network, 'mainnet');
  assert.equal(inspected.scriptHash, scriptHash);
  assert.equal(G4.inspectAddress(address.slice(0,-1) + (address.at(-1) === '0' ? '1' : '0')).verified, false);
});

test('repeated deposit reads preserve exact outpoints but do not implement a credit ledger', async () => {
  const args = { txid, addressTo: address, amount: '0.00000100', fetchImpl: async () => response(receipt) };
  const first = await getDepositTransaction(args);
  const again = await getDepositTransaction(args);
  assert.deepEqual(first.match.matchingOutputs, again.match.matchingOutputs);
  assert.equal(first.match.exactTotal, true);
  assert.equal(again.match.exactTotal, true);
  assert.match(first.match.note, /duplicate-credit policy/);
  assert.equal(Object.hasOwn(first, 'credited'), false);
});

test('deposit lookup rejects output indexes above the native u32 bound', async () => {
  const forged = { ...receipt, outputs: [{ ...receipt.outputs[0], vout: 4294967296 }] };
  await assert.rejects(getDepositTransaction({ txid, addressTo: address, amount: '0.00000100',
    fetchImpl: async () => response(forged) }));
});

test('offline deposit inspection rejects indexes above the native u32 bound', async () => {
  const parsed = await getDepositTransaction({ txid, addressTo: address, amount: '0.00000100', fetchImpl: async () => response(receipt) });
  parsed.transaction.outputs[0].vout = 4294967296;
  assert.throws(() => inspectDepositOutputs({ transaction: parsed.transaction, addressTo: address, amount: '0.00000100' }));
});

test('receipt inputs and outputs enforce the complete native u32 boundary', async () => {
  for (const field of ['inputs', 'outputs']) {
    for (const vout of [-1, 1.5, 4294967296, Number.MAX_SAFE_INTEGER, '0', null]) {
      const forged = { ...receipt, [field]: [{ ...receipt[field][0], vout }] };
      await assert.rejects(getDepositTransaction({ txid, addressTo: address, amount: '0.00000100',
        fetchImpl: async () => response(forged) }), /incomplete or mismatched/);
      const parsed = await getDepositTransaction({ txid, addressTo: address,
        amount: '0.00000100', fetchImpl: async () => response(receipt) });
      parsed.transaction[field][0].vout = vout;
      assert.throws(() => inspectDepositOutputs({ transaction: parsed.transaction,
        addressTo: address, amount: '0.00000100' }));
    }
    const boundary = { ...receipt, [field]: [{ ...receipt[field][0], vout: 0xffffffff }] };
    const result = await getDepositTransaction({ txid, addressTo: address, amount: '0.00000100',
      fetchImpl: async () => response(boundary) });
    assert.equal(result.match.exactTotal, true);
  }
});

function replaceBytes(envelope, bytes) {
  return { ...envelope, rawHex: bytes.toString('hex'),
    rawHash: createHash('sha3-256').update(bytes).digest('hex') };
}

for (const [epoch, tag] of [[4, 0x01], [800, 0x06]]) {
  test(`transfer tag ${tag} binds a persisted envelope to its decoded spend before any network callback`, async () => {
    const original = await syntheticTransfer({ epoch, inputs: 3, amount: '0.002' });
    const other = await syntheticTransfer({ epoch, inputs: 3, amount: '0.001' });
    assert.equal(parseInt(original.rawHex.slice(0, 2), 16), tag);
    assert.ok(original.inputCount > 1);
    assert.notEqual(original.txid, other.txid);
    let calls = 0;
    const forbidden = async () => { calls++; throw new Error('Unexpected network callback'); };
    const mixed = { ...original, rawHex: other.rawHex, rawHash: other.rawHash };
    for (const envelope of [mixed, { ...other, txid: original.txid, signingRootHex: original.signingRootHex }]) {
      await assert.rejects(broadcastSignedTransaction(envelope, { fetchImpl: forbidden }), /nothing was submitted/);
      await assert.rejects(trackSignedTransaction(envelope, { fetchImpl: forbidden }), /nothing was submitted/);
    }
    const bytes = Buffer.from(original.rawHex, 'hex');
    const hugeCount = Buffer.from(bytes);
    hugeCount.writeUInt32LE(0xffffffff, 1);
    const unknown = Buffer.from(bytes);
    unknown[0] = 0x02;
    const changedSpend = Buffer.from(bytes);
    changedSpend[changedSpend.length - 1] ^= 1; // committed u128 tip
    const malformed = [bytes.subarray(0, 1), bytes.subarray(0, 4),
      bytes.subarray(0, bytes.length - 1), Buffer.concat([bytes, Buffer.from([0])]),
      hugeCount, unknown, changedSpend];
    if (tag === 0x06) {
      const badIndex = Buffer.from(bytes);
      const count = badIndex.readUInt32LE(1);
      let offset = 5;
      for (let i = 0; i < count; i++) {
        offset += 4 + badIndex.readUInt32LE(offset);
        offset += 4 + badIndex.readUInt32LE(offset);
      }
      badIndex.writeUInt32LE(count, offset + 4 + 36);
      malformed.push(badIndex);
    }
    for (const bad of malformed) {
      const envelope = replaceBytes(original, bad);
      await assert.rejects(broadcastSignedTransaction(envelope, { fetchImpl: forbidden }), /nothing was submitted/);
      await assert.rejects(trackSignedTransaction(envelope, { fetchImpl: forbidden }), /nothing was submitted/);
    }
    assert.equal(calls, 0);
    const accepted = await broadcastSignedTransaction(original, { fetchImpl: async (_url, options) => {
      calls++;
      const request = JSON.parse(options.body);
      assert.equal(request.method, 'sendrawtransaction');
      assert.deepEqual(request.params, [original.rawHex]);
      return response({ jsonrpc: '2.0', id: request.id,
        result: { accepted: true, bytes: bytes.length, tx_hash: original.rawHash } });
    } });
    assert.equal(accepted.txid, original.txid);
    assert.equal(calls, 1, 'Only the intact envelope reaches the in-memory callback');
  });
}

test('broadcast and tracking retain validated identity when callers mutate their envelope during I/O', async () => {
  const original = await syntheticTransfer();
  const other = await syntheticTransfer({ amount: '0.002' });
  for (const honestReply of [true, false]) {
    const mutable = { ...original };
    const submission = broadcastSignedTransaction(mutable, { fetchImpl: async (_url, options) => {
      const request = JSON.parse(options.body);
      assert.deepEqual(request.params, [original.rawHex]);
      Object.assign(mutable, other);
      await Promise.resolve();
      const reply = honestReply ? original : other;
      return response({ jsonrpc: '2.0', id: request.id,
        result: { accepted: true, bytes: reply.rawHex.length / 2, tx_hash: reply.rawHash } });
    } });
    if (honestReply) assert.equal((await submission).txid, original.txid);
    else await assert.rejects(submission, /mismatched byte count or correlation hash/);
  }
  const mutable = { ...original };
  const observed = await trackSignedTransaction(mutable, { fetchImpl: async (url, options) => {
    Object.assign(mutable, other);
    await Promise.resolve();
    if (!options?.body) {
      assert.ok(url.endsWith(original.txid));
      return new Response('', { status: 404 });
    }
    const request = JSON.parse(options.body);
    assert.equal(request.method, 'gettxstatus');
    assert.deepEqual(request.params, [original.txid]);
    return response({ jsonrpc: '2.0', id: request.id, result: { status: 'pending' } });
  } });
  assert.equal(observed.txid, original.txid);
  assert.equal(observed.observation.txid, original.txid);
});
