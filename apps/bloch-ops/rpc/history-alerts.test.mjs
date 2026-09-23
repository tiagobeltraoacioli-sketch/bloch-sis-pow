import assert from 'node:assert/strict';
import test from 'node:test';
import { compareChainObservations } from './history-alerts.mjs';

const sample = (height, finalized_height, slot) => ({ status: 'valid', height, finalized_height, slot });

test('needs two valid gateway observations', () => {
  assert.deepEqual(compareChainObservations(null, sample(12, 8, 20)), { status: 'insufficient', alerts: [] });
  assert.deepEqual(compareChainObservations(sample(12, 8, 20), { status: 'failed' }), { status: 'insufficient', alerts: [] });
});

test('accepts monotonic head and finality progress and same-head finalization', () => {
  assert.deepEqual(compareChainObservations(sample(12, 8, 20), sample(13, 9, 21)), { status: 'consistent', alerts: [] });
  assert.deepEqual(compareChainObservations(sample(12, 8, 20), sample(12, 9, 20)), { status: 'consistent', alerts: [] });
});

test('detects head and finalized height regressions', () => {
  const result = compareChainObservations(sample(12, 8, 20), sample(11, 7, 19));
  assert.equal(result.status, 'review');
  assert.deepEqual(result.alerts.map(alert => alert.code), ['head_regression', 'finality_regression', 'slot_regression']);
});

test('detects contradictory height to slot mapping in both directions', () => {
  assert.deepEqual(compareChainObservations(sample(12, 8, 20), sample(12, 8, 21)).alerts.map(alert => alert.code), ['height_slot_conflict']);
  assert.deepEqual(compareChainObservations(sample(12, 8, 20), sample(13, 8, 20)).alerts.map(alert => alert.code), ['slot_height_conflict']);
});

test('does not infer slot conflicts when either slot is unavailable', () => {
  assert.deepEqual(compareChainObservations(sample(12, 8, null), sample(12, 8, 21)), { status: 'consistent', alerts: [] });
});
