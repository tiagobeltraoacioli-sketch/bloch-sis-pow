// SPDX-License-Identifier: AGPL-3.0-or-later
// Offline comparison of two saved, self-reported RPC probe observations.
'use strict';
const fs = require('node:fs');
const { networkDomain, checkpoint } = require('./probe.cjs');

const MAX_REPORT_BYTES = 1024 * 1024;

function readReport(filename) {
  const stats = fs.statSync(filename);
  if (!stats.isFile() || stats.size > MAX_REPORT_BYTES) throw new Error('Report must be a file of at most 1 MiB');
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}

function observation(report) {
  if (!report || report.schema_version !== '1.0.0' || !Array.isArray(report.diagnostics) ||
      typeof report.endpoint !== 'string' || typeof report.observed_at_utc !== 'string') {
    throw new Error('Expected a probe.cjs JSON report with schema_version 1.0.0');
  }
  const time = Date.parse(report.observed_at_utc);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== report.observed_at_utc) {
    throw new Error('Report has an invalid UTC observation time');
  }
  const row = method => report.diagnostics.find(item => item?.method === method);
  const chain = row('getchaininfo');
  const finalizedHeight = chain?.status === 'compatible_shape' &&
    Number.isSafeInteger(chain.observed?.finalized_height) && chain.observed.finalized_height >= 0
    ? chain.observed.finalized_height : null;
  return {
    time, observed_at_utc: report.observed_at_utc, endpoint: report.endpoint,
    reference_endpoint: report.reference_endpoint ?? null,
    cross_check_status: report.cross_check?.status ?? null,
    network_domain: networkDomain(row('getvalidatoradmission')),
    finalized: checkpoint(chain), finalized_height: finalizedHeight,
  };
}

function compareReports(beforeReport, afterReport, expectedDomain) {
  if (expectedDomain !== undefined && (typeof expectedDomain !== 'string' || !/^[0-9a-fA-F]{64}$/.test(expectedDomain))) {
    throw new Error('Expected domain must be exactly 64 hexadecimal characters');
  }
  const before = observation(beforeReport);
  const after = observation(afterReport);
  const findings = [];
  const add = (status, code) => findings.push({ status, code });
  const timeOrdered = after.time > before.time;
  const sameConfiguration = before.endpoint === after.endpoint && before.reference_endpoint === after.reference_endpoint;
  if (!timeOrdered) add('inconclusive', 'observation_order_unverified');
  if (!sameConfiguration) {
    add('inconclusive', 'endpoint_configuration_changed');
  }
  for (const [label, value] of [['before', before], ['after', after]]) {
    if (value.cross_check_status === 'fail') add('fail', `${label}_cross_check_failed`);
    else if (value.reference_endpoint && value.cross_check_status !== 'match') {
      add('inconclusive', `${label}_cross_check_unverified`);
    }
  }
  const domain = expectedDomain?.toLowerCase();
  for (const [label, value] of [['before', before.network_domain], ['after', after.network_domain]]) {
    if (domain) add(value === null ? 'inconclusive' : value === domain ? 'match' : 'fail',
      value === null ? `${label}_domain_unavailable` : value === domain ? `${label}_domain_matches_expected` : `${label}_domain_mismatch`);
  }
  if (!timeOrdered || !sameConfiguration) add('inconclusive', 'longitudinal_comparison_unavailable');
  else if (before.network_domain === null || after.network_domain === null) add('inconclusive', 'domain_comparison_unavailable');
  else add(before.network_domain === after.network_domain ? 'match' : 'fail',
    before.network_domain === after.network_domain ? 'domain_stable' : 'domain_changed');
  if (!timeOrdered || !sameConfiguration) add('inconclusive', 'finalized_checkpoint_comparison_unavailable');
  else if (before.finalized === null || after.finalized === null) add('inconclusive', 'finalized_checkpoint_unavailable');
  else if (after.finalized.epoch < before.finalized.epoch) add('fail', 'finalized_epoch_regressed');
  else if (after.finalized.epoch === before.finalized.epoch) add(
    before.finalized.root === after.finalized.root ? 'match' : 'fail',
    before.finalized.root === after.finalized.root ? 'same_epoch_root_stable' : 'same_epoch_root_conflict');
  else add('match', 'finalized_epoch_advanced');
  if (!timeOrdered || !sameConfiguration) add('inconclusive', 'finalized_height_comparison_unavailable');
  else if (before.finalized_height === null || after.finalized_height === null) add('inconclusive', 'finalized_height_unavailable');
  else add(after.finalized_height < before.finalized_height ? 'fail' : 'match',
    after.finalized_height < before.finalized_height ? 'finalized_height_regressed' : 'finalized_height_monotonic');
  const status = findings.some(item => item.status === 'fail') ? 'fail'
    : findings.some(item => item.status === 'inconclusive') ? 'inconclusive' : 'match';
  return {
    schema_version: '1.0.0', status,
    before: { observed_at_utc: before.observed_at_utc, network_domain: before.network_domain,
      finalized: before.finalized, finalized_height: before.finalized_height },
    after: { observed_at_utc: after.observed_at_utc, network_domain: after.network_domain,
      finalized: after.finalized, finalized_height: after.finalized_height },
    expected_domain: domain ?? null, findings,
    note: 'Saved reports and their clocks are not authenticated. Matching self-reported values do not prove consensus, endpoint independence, continuous uptime, or settlement finality.',
  };
}

function parseArgs(argv) {
  let before, after, expectDomain;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--before') before = argv[++i];
    else if (argv[i] === '--after') after = argv[++i];
    else if (argv[i] === '--expect-domain') expectDomain = argv[++i];
    else if (argv[i] === '--help') return { help: true };
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  if (!before || !after) throw new Error('Provide --before FILE and --after FILE');
  return { before, after, expectDomain };
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log('Usage: node compare-reports.cjs --before earlier.json --after later.json [--expect-domain 64-HEX]');
    return 0;
  }
  const result = compareReports(readReport(args.before), readReport(args.after), args.expectDomain);
  console.log(JSON.stringify(result, null, 2));
  return result.status === 'match' ? 0 : 1;
}

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (error) { console.error(`RPC report comparison: ${error.message}`); process.exitCode = 2; }
}

module.exports = { MAX_REPORT_BYTES, observation, compareReports, readReport, parseArgs, main };
