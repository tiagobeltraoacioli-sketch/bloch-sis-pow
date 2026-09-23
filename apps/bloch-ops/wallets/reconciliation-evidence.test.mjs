import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildReconciliationEvidence, verifyReconciliationEvidence } from './reconciliation-evidence.mjs';

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
  assert.equal(evidence.schema, 'bloch.genesis4.reconciliation-evidence.v2');
  assert.equal(evidence.receipt.txid, txid);
  assert.equal(evidence.deposit_match.exactTotal, true);
  assert.equal(evidence.deposit_match.outputs[0].vout, 0);
  assert.equal(evidence.comparison.status, 'first_inclusion');
  assert.equal(evidence.previous_observation, null);
  assert.equal(verifyReconciliationEvidence(evidence).structurally_valid, true);
  assert.equal(JSON.stringify(evidence).includes('must never be exported'), false);
});

test('saves the prior public observation and detects changed claims', () => {
  const prior = { kind: 'included', txid, receipt: {
    ...receipt, mnemonic: 'must never be exported',
    confirmations: 21, observed_head_height: 100, observed_head_slot: 120,
  } };
  const evidence = buildReconciliationEvidence(receipt, {
    observedAt: '2026-09-23T20:00:00.000Z', previousObservation: prior,
    expectedScriptHash: scriptHash, expectedAmountSat: '100',
  });
  assert.equal(evidence.comparison.status, 'consistent');
  assert.equal(evidence.previous_observation.receipt.confirmations, 21);
  assert.equal(JSON.stringify(evidence).includes('must never be exported'), false);
  assert.equal(verifyReconciliationEvidence(evidence).comparison_status, 'consistent');
  assert.throws(() => verifyReconciliationEvidence({ ...evidence,
    comparison: { ...evidence.comparison, status: 'finalized' },
  }));
  assert.throws(() => verifyReconciliationEvidence({ ...evidence,
    deposit_match: { ...evidence.deposit_match, matchedAmountSat: '101' },
  }));
  assert.throws(() => verifyReconciliationEvidence({ ...evidence,
    previous_observation: { ...evidence.previous_observation, receipt: {
      ...evidence.previous_observation.receipt, block_id: 'aa'.repeat(32),
    } },
  }));
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

test('offline command verifies a saved file and fails on changed output values', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bloch-evidence-test-'));
  const path = join(dir, 'evidence.json');
  const cli = fileURLToPath(new URL('./verify-evidence.mjs', import.meta.url));
  try {
    const evidence = buildReconciliationEvidence(receipt, {
      observedAt: '2026-09-23T20:00:00.000Z',
      expectedScriptHash: scriptHash, expectedAmountSat: '100',
    });
    writeFileSync(path, JSON.stringify(evidence));
    const accepted = spawnSync(process.execPath, [cli, path], { encoding: 'utf8' });
    assert.equal(accepted.status, 0);
    assert.equal(JSON.parse(accepted.stdout).credit_authorized, false);
    writeFileSync(path, JSON.stringify({ ...evidence, receipt: {
      ...evidence.receipt, outputs: [{ ...evidence.receipt.outputs[0], value_sat: '101' }],
    } }));
    const rejected = spawnSync(process.execPath, [cli, path], { encoding: 'utf8' });
    assert.equal(rejected.status, 1);
    assert.equal(rejected.stdout, '');
  } finally {
    unlinkSync(path);
    rmdirSync(dir);
  }
});
