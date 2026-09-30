// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import G4 from '../g4.cjs';
import { broadcastSignedTransaction, trackSignedTransaction } from '../index.mjs';
import { syntheticTransfer } from './synthetic-transfer.mjs';

test('envelope input limits and primitive types fail before transmission', async () => {
  const signed = await syntheticTransfer();
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error('Unexpected callback'); };
  const oversized = '00'.repeat(Number(G4.limits.RPC_MAX_RAW_TX_BYTES) + 1);
  for (const rawHex of ['', 'a', 'ag', oversized]) {
    await assert.rejects(broadcastSignedTransaction({ ...signed, rawHex }, { fetchImpl }));
    await assert.rejects(trackSignedTransaction({ ...signed, rawHex }, { fetchImpl }));
  }
  for (const field of ['txid', 'signingRootHex', 'rawHash', 'rawHex']) {
    const spoof = { ...signed, [field]: { toString: () => signed[field] } };
    await assert.rejects(broadcastSignedTransaction(spoof, { fetchImpl }), /must be strings/);
  }
  assert.equal(calls, 0);
  const emptyBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'sendrawtransaction', params: [''] });
  assert.ok(emptyBody.length + 2 * Number(G4.limits.RPC_MAX_RAW_TX_BYTES) <= 1048576);
});

test('envelope getters are captured once and an ambiguous submission is not retried', async () => {
  const signed = await syntheticTransfer();
  const reads = {};
  const envelope = {};
  for (const field of ['txid', 'signingRootHex', 'rawHash', 'rawHex']) {
    reads[field] = 0;
    Object.defineProperty(envelope, field, { get() {
      reads[field]++;
      if (reads[field] !== 1) throw new Error('Identity reread');
      return signed[field].toUpperCase();
    } });
  }
  let calls = 0;
  await assert.rejects(broadcastSignedTransaction(envelope, { fetchImpl: async (_url, options) => {
    calls++;
    const request = JSON.parse(options.body);
    assert.deepEqual(request.params, [signed.rawHex.toUpperCase()]);
    throw new Error('Synthetic lost reply');
  } }));
  assert.equal(calls, 1);
  assert.deepEqual(Object.values(reads), [1, 1, 1, 1]);
});

// Locate wire fields in actual WASM output, without calculating the SDK root.
function wireOffsets(bytes) {
  let offset = 1;
  const u32 = () => { const value = bytes.readUInt32LE(offset); offset += 4; return value; };
  const fields = [];
  const witnessLengths = [];
  const witness = () => {
    witnessLengths.push(offset); offset += 4 + bytes.readUInt32LE(offset);
    witnessLengths.push(offset); offset += 4 + bytes.readUInt32LE(offset);
  };
  if (bytes[0] === 0x06) {
    const keys = u32();
    for (let i = 0; i < keys; i++) witness();
  }
  const inputs = u32();
  for (let i = 0; i < inputs; i++) {
    fields.push(offset, offset + 32);
    offset += 36;
    if (bytes[0] === 0x01) witness();
    else offset += 4;
  }
  const outputs = u32();
  for (let i = 0; i < outputs; i++) { fields.push(offset, offset + 8); offset += 40; }
  fields.push(offset, offset + 8);
  assert.equal(offset + 24, bytes.length);
  return { fields, witnessLengths };
}

test('every spend field and malformed witness length is rejected before submission or tracking', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error('Unexpected callback'); };
  for (const epoch of [4, 800]) {
    const signed = await syntheticTransfer({ epoch, inputs: 3, amount: '0.002' });
    const original = Buffer.from(signed.rawHex, 'hex');
    const { fields, witnessLengths } = wireOffsets(original);
    for (const [offset, length] of [
      ...fields.map(offset => [offset, false]),
      ...witnessLengths.map(offset => [offset, true]),
    ]) {
      const bytes = Buffer.from(original);
      if (length) bytes.writeUInt32LE(0xffffffff, offset);
      else bytes[offset] ^= 1;
      const changed = { ...signed, rawHex: bytes.toString('hex'),
        rawHash: createHash('sha3-256').update(bytes).digest('hex') };
      await assert.rejects(broadcastSignedTransaction(changed, { fetchImpl }), /nothing was submitted/);
      await assert.rejects(trackSignedTransaction(changed, { fetchImpl }), /nothing was submitted/);
    }
  }
  assert.equal(calls, 0);
});
