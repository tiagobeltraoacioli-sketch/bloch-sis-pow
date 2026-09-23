// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { compareReports, readReport } = require('./compare-reports.cjs');

const domain = 'a'.repeat(64);
const root = 'b'.repeat(64);
function report(time, { endpoint = 'https://node.example/rpc', networkDomain = domain,
  epoch = 7, finalizedRoot = root, height = 42, chainStatus = 'compatible_shape', domainStatus = 'compatible_shape' } = {}) {
  return {
    schema_version: '1.0.0', observed_at_utc: time, endpoint, reference_endpoint: null,
    diagnostics: [
      { method: 'getchaininfo', status: chainStatus, observed: { finalized: { epoch, root: finalizedRoot }, finalized_height: height } },
      { method: 'getvalidatoradmission', status: domainStatus, observed: { network_domain: networkDomain } },
    ],
  };
}
const earlier = '2026-09-23T10:00:00.000Z';
const later = '2026-09-23T10:05:00.000Z';

test('two ordered reports with stable domain, checkpoint, and finalized height match', () => {
  const result = compareReports(report(earlier), report(later, { epoch: 8, finalizedRoot: 'c'.repeat(64), height: 50 }), domain.toUpperCase());
  assert.equal(result.status, 'match');
  assert.ok(result.findings.some(row => row.code === 'finalized_epoch_advanced'));
  assert.ok(result.findings.some(row => row.code === 'finalized_height_monotonic'));
  assert.equal(JSON.stringify(result).includes('node.example'), false);
});

test('domain changes and conflicts with trusted manifest fail', () => {
  const result = compareReports(report(earlier), report(later, { networkDomain: 'c'.repeat(64) }), domain);
  assert.equal(result.status, 'fail');
  assert.ok(result.findings.some(row => row.code === 'domain_changed'));
  assert.ok(result.findings.some(row => row.code === 'after_domain_mismatch'));
});

test('same-epoch contradictory root and decreasing finality each fail', () => {
  const result = compareReports(report(earlier), report(later, { finalizedRoot: 'c'.repeat(64), height: 41 }));
  assert.equal(result.status, 'fail');
  assert.ok(result.findings.some(row => row.code === 'same_epoch_root_conflict'));
  assert.ok(result.findings.some(row => row.code === 'finalized_height_regressed'));
  const epoch = compareReports(report(earlier), report(later, { epoch: 6 }));
  assert.ok(epoch.findings.some(row => row.code === 'finalized_epoch_regressed'));
});

test('missing observations, unordered clocks, and changed endpoints remain inconclusive', () => {
  const missing = compareReports(report(earlier), report(later, { chainStatus: 'timeout', domainStatus: 'timeout' }));
  assert.equal(missing.status, 'inconclusive');
  assert.ok(missing.findings.some(row => row.code === 'finalized_checkpoint_unavailable'));
  const reversed = compareReports(report(later), report(earlier, { epoch: 6, height: 40 }));
  assert.equal(reversed.status, 'inconclusive');
  assert.equal(reversed.findings.some(row => row.code === 'finalized_epoch_regressed'), false);
  const changed = compareReports(report(earlier), report(later, { endpoint: 'https://other.example/rpc', epoch: 6 }));
  assert.equal(changed.status, 'inconclusive');
  assert.ok(changed.findings.some(row => row.code === 'endpoint_configuration_changed'));
});

test('preserves a failed reference cross-check and treats an unchecked reference as inconclusive', () => {
  const failed = report(later);
  failed.reference_endpoint = 'https://reference.example/rpc';
  failed.cross_check = { status: 'fail' };
  const before = report(earlier);
  before.reference_endpoint = failed.reference_endpoint;
  before.cross_check = { status: 'match' };
  assert.ok(compareReports(before, failed).findings.some(row => row.code === 'after_cross_check_failed'));
  failed.cross_check = { status: 'inconclusive' };
  assert.equal(compareReports(before, failed).status, 'inconclusive');
});

test('rejects malformed report, malformed expected domain, and oversized file', () => {
  assert.throws(() => compareReports({}, report(later)), /probe.cjs JSON report/);
  assert.throws(() => compareReports(report(earlier), report(later), 'wrong'), /64 hexadecimal/);
  assert.throws(() => compareReports(report('yesterday'), report(later)), /invalid UTC/);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bloch-rpc-report-'));
  try {
    const file = path.join(directory, 'large.json');
    fs.writeFileSync(file, ' '.repeat(1024 * 1024 + 1));
    assert.throws(() => readReport(file), /at most 1 MiB/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('CLI returns machine-readable JSON with match, fail, and argument-error exit codes', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bloch-rpc-cli-'));
  try {
    const first = path.join(directory, 'first.json');
    const second = path.join(directory, 'second.json');
    fs.writeFileSync(first, JSON.stringify(report(earlier)));
    fs.writeFileSync(second, JSON.stringify(report(later)));
    const args = [__dirname + '/compare-reports.cjs', '--before', first, '--after', second];
    const good = spawnSync(process.execPath, args, { encoding: 'utf8' });
    assert.equal(good.status, 0);
    assert.equal(JSON.parse(good.stdout).status, 'match');
    fs.writeFileSync(second, JSON.stringify(report(later, { finalizedRoot: 'c'.repeat(64) })));
    const bad = spawnSync(process.execPath, args, { encoding: 'utf8' });
    assert.equal(bad.status, 1);
    assert.equal(JSON.parse(bad.stdout).status, 'fail');
    const invalid = spawnSync(process.execPath, [__dirname + '/compare-reports.cjs'], { encoding: 'utf8' });
    assert.equal(invalid.status, 2);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
