#!/usr/bin/env node
// Local, read-only comparison of two operator evidence bundles.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const HEX = /^[a-fA-F0-9]{64}$/;
const MAX_BYTES = 256 * 1024;
const DEFAULT_MAX_AGE_MINUTES = 30;
const MAX_AGE_MINUTES = 1440;
const CLOCK_SKEW_MS = 120 * 1000;

function usage() {
  return 'Usage: node evidence-assess.cjs --preflight DIR --checkpoint DIR --expect-domain 64-HEX --expect-genesis-sha256 64-HEX [--expect-binary-sha256 64-HEX] [--expect-signer-set-sha256 64-HEX] [--max-age-minutes 1..1440] [--json]\nReads only the two local evidence bundles and their SHA256SUMS. Maximum evidence age defaults to 30 minutes; clock skew allowance is 120 seconds. Expected values must come from independently authenticated release material. This comparison never qualifies a validator or opens staking.';
}

function parseArgs(argv) {
  const opts = { json: false };
  const names = { '--preflight': 'preflight', '--checkpoint': 'checkpoint', '--expect-domain': 'expectDomain', '--expect-genesis-sha256': 'expectGenesisSha256', '--expect-binary-sha256': 'expectBinarySha256', '--expect-signer-set-sha256': 'expectSignerSetSha256', '--max-age-minutes': 'maxAgeMinutes' };
  for (let i = 0; i < argv.length; i++) {
    if (['--help', '-h'].includes(argv[i])) { opts.help = true; continue; }
    if (argv[i] === '--json') { opts.json = true; continue; }
    const name = names[argv[i]];
    if (!name || !argv[i + 1] || argv[i + 1].startsWith('--') || opts[name]) throw new Error(`Invalid, repeated or incomplete option: ${argv[i]}`);
    opts[name] = argv[++i];
  }
  if (opts.help) return opts;
  for (const name of ['preflight', 'checkpoint', 'expectDomain', 'expectGenesisSha256']) if (!opts[name]) throw new Error(`${name} is required`);
  for (const name of ['expectDomain', 'expectGenesisSha256', 'expectBinarySha256', 'expectSignerSetSha256']) if (opts[name] !== undefined && !HEX.test(opts[name])) throw new Error(`${name} must be 64 hexadecimal characters`);
  if (opts.maxAgeMinutes === undefined) opts.maxAgeMinutes = DEFAULT_MAX_AGE_MINUTES;
  else if (!/^[0-9]+$/.test(opts.maxAgeMinutes) || !Number.isSafeInteger(Number(opts.maxAgeMinutes)) || Number(opts.maxAgeMinutes) < 1 || Number(opts.maxAgeMinutes) > MAX_AGE_MINUTES) throw new Error(`maxAgeMinutes must be an integer from 1 to ${MAX_AGE_MINUTES}`);
  else opts.maxAgeMinutes = Number(opts.maxAgeMinutes);
  return opts;
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) throw new Error(`${label} must be a canonical UTC timestamp`);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) throw new Error(`${label} must be a valid UTC timestamp`);
  return ms;
}

function readBundle(directory, filename) {
  const dir = fs.lstatSync(directory);
  if (!dir.isDirectory() || dir.isSymbolicLink()) throw new Error(`${filename}: bundle path must be a real directory`);
  const file = path.join(directory, filename);
  const sums = path.join(directory, 'SHA256SUMS');
  for (const target of [file, sums]) {
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_BYTES) throw new Error(`${filename}: files must be regular and at most ${MAX_BYTES} bytes`);
  }
  const body = fs.readFileSync(file);
  const line = fs.readFileSync(sums, 'utf8');
  const match = line.match(new RegExp(`^([a-fA-F0-9]{64})  ${filename.replace('.', '\\.')}\\n$`));
  if (!match || crypto.createHash('sha256').update(body).digest('hex') !== match[1].toLowerCase()) throw new Error(`${filename}: SHA256SUMS mismatch`);
  const value = JSON.parse(body.toString('utf8'));
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error(`${filename}: invalid JSON object`);
  return { value, sha256: match[1].toLowerCase() };
}

function uniqueField(output, label, pattern) {
  const matches = [...output.matchAll(pattern)].map(match => match[1]);
  if (matches.length !== 1) throw new Error(`Checkpoint diagnostics must contain exactly one ${label}`);
  return matches[0];
}

function assess(preflight, checkpoint, expected, nowMs = Date.now()) {
  const checks = [];
  const add = (status, id, detail) => checks.push({ status, id, detail });
  const p = preflight.value, c = checkpoint.value;
  if (p.schema !== 'bloch.genesis4.validator-preflight.evidence.v1' || c.schema !== 'bloch.genesis4.checkpoint-verification.v1') throw new Error('Unsupported evidence schema');
  if (!p.report || !p.observations?.primary || !p.inputs || !c.inputFingerprints || !c.diagnostics || !Array.isArray(c.checks)) throw new Error('Incomplete evidence structure');
  if (p.summary !== p.report.summary || p.manualGate?.status !== 'NOT_VERIFIED' || c.manualGate?.status !== 'NOT_VERIFIED') throw new Error('Inconsistent or missing manual gate / summary');
  const maxAgeMinutes = expected.maxAgeMinutes === undefined ? DEFAULT_MAX_AGE_MINUTES : expected.maxAgeMinutes;
  if (!Number.isSafeInteger(maxAgeMinutes) || maxAgeMinutes < 1 || maxAgeMinutes > MAX_AGE_MINUTES) throw new Error(`maxAgeMinutes must be an integer from 1 to ${MAX_AGE_MINUTES}`);
  if (!Number.isSafeInteger(nowMs)) throw new Error('Assessment clock is invalid');
  const preflightAt = timestamp(p.observedAt, 'Preflight observedAt');
  if (timestamp(p.report.observedAt, 'Preflight report observedAt') !== preflightAt) throw new Error('Preflight report timestamp does not match bundle timestamp');
  const checkpointAt = timestamp(c.observedAt, 'Checkpoint observedAt');
  const maxAgeMs = maxAgeMinutes * 60000;
  for (const [label, at] of [['preflight', preflightAt], ['checkpoint', checkpointAt]]) {
    const age = nowMs - at;
    add(age >= -CLOCK_SKEW_MS && age <= maxAgeMs ? 'PASS' : 'FAIL', `${label}-time`, `${label} observedAt ${new Date(at).toISOString()}; age ${Math.floor(age / 1000)} seconds; maximum ${maxAgeMinutes} minutes, future clock skew allowance 120 seconds.`);
  }
  add(checkpointAt >= preflightAt - CLOCK_SKEW_MS && checkpointAt - preflightAt <= maxAgeMs ? 'PASS' : 'FAIL', 'evidence-sequence', 'Checkpoint must follow preflight within the maximum age; up to 120 seconds of clock skew is allowed.');
  add(p.summary === 'CHECKS_PASS_MANUAL_REQUIRED' && Array.isArray(p.report.checks) && p.report.checks.every(item => ['PASS', 'MANUAL'].includes(item.level)) ? 'PASS' : 'FAIL', 'preflight-status', `Preflight: ${p.summary}`);
  add(c.status === 'CRYPTO_ACCEPTED_MANUAL_REQUIRED' && c.checks.length === 4 && c.checks.every(item => item.status === 'PASS') && c.command?.name === 'ws-verify' && c.command.exitCode === 0 && c.command.stopReason === null && c.freshness === 'FRESH' ? 'PASS' : 'FAIL', 'checkpoint-status', `Checkpoint: ${c.status}`);
  const domain = p.observations.primary.getvalidatoradmission?.network_domain;
  add(HEX.test(domain || '') && HEX.test(p.inputs.expectedNetworkDomain || '') && domain.toLowerCase() === expected.expectDomain.toLowerCase() && p.inputs.expectedNetworkDomain.toLowerCase() === expected.expectDomain.toLowerCase() ? 'PASS' : 'FAIL', 'network-domain', 'Preflight domain and its declared trusted input must match the operator-supplied domain.');
  const genesis = c.inputFingerprints.genesis?.sha256;
  add(HEX.test(genesis || '') && genesis.toLowerCase() === expected.expectGenesisSha256.toLowerCase() ? 'PASS' : 'FAIL', 'genesis-artifact', 'Checkpoint verifier genesis-manifest fingerprint must match the operator-supplied digest.');
  for (const [option, input, id, label] of [
    ['expectBinarySha256', 'binary', 'binary-artifact', 'node binary'],
    ['expectSignerSetSha256', 'signerSet', 'signer-set-artifact', 'signer set']
  ]) {
    if (expected[option] === undefined) continue;
    if (!HEX.test(expected[option])) throw new Error(`${option} must be 64 hexadecimal characters`);
    const recorded = c.inputFingerprints[input]?.sha256;
    add(HEX.test(recorded || '') && recorded.toLowerCase() === expected[option].toLowerCase() ? 'PASS' : 'FAIL', id, `Recorded ${label} fingerprint must match the independently supplied SHA-256.`);
  }
  const stdout = c.diagnostics.stdout;
  if (typeof stdout !== 'string' || Buffer.byteLength(stdout) > 65536) throw new Error('Missing or oversized checkpoint stdout');
  const epochText = uniqueField(stdout, 'checkpoint epoch', /^  epoch\s+([0-9]+)\s*$/gm);
  const root = uniqueField(stdout, 'checkpoint block root', /^  block root\s+([a-fA-F0-9]{64})\s*$/gm);
  const digest = uniqueField(stdout, 'WS digest', /^  WS DIGEST\s+([a-fA-F0-9]{64})\s*$/gm);
  const freshness = [...stdout.matchAll(/^FRESHNESS  epoch ([0-9]+) vs now ([0-9]+):[^\n]*— (FRESH|STALE|EXPIRED)\b/gm)];
  if (freshness.length !== 1) throw new Error('Checkpoint diagnostics must contain exactly one freshness line');
  const cpEpoch = Number(epochText), nowEpoch = Number(freshness[0][2]);
  if (!Number.isSafeInteger(cpEpoch) || !Number.isSafeInteger(nowEpoch)) throw new Error('Checkpoint epoch is outside the safe integer range');
  add(Number(freshness[0][1]) === cpEpoch && freshness[0][3] === 'FRESH' && (stdout.match(/^VERDICT: ACCEPTED by ws::verify_envelope\.$/gm) || []).length === 1 ? 'PASS' : 'FAIL', 'verifier-output', 'Verifier must report a fresh checkpoint at its printed epoch and exactly one accepted verdict.');
  add(HEX.test(c.wsDigest || '') && HEX.test(c.expectedDigest || '') && c.wsDigest.toLowerCase() === digest.toLowerCase() && c.expectedDigest.toLowerCase() === digest.toLowerCase() ? 'PASS' : 'FAIL', 'ws-digest', 'Digest in verifier output, verified value and supplied expected value must agree.');
  const chain = p.observations.primary.getchaininfo || {};
  const finalized = chain.finalized || {};
  const chainEpoch = chain.epoch;
  add(Number.isSafeInteger(chainEpoch) && Math.abs(chainEpoch - nowEpoch) <= 1 ? 'PASS' : 'FAIL', 'observation-epoch', `Preflight head epoch ${chainEpoch}; checkpoint verifier node clock epoch ${nowEpoch}. Maximum drift: one epoch.`);
  if (!Number.isSafeInteger(finalized.epoch) || !HEX.test(finalized.root || '')) add('FAIL', 'finalized-root', 'Preflight finalized checkpoint is absent or malformed.');
  else if (finalized.epoch === cpEpoch) add(finalized.root.toLowerCase() === root.toLowerCase() ? 'PASS' : 'FAIL', 'finalized-root', `Both reports describe epoch ${cpEpoch}; roots must agree.`);
  else if (finalized.epoch < cpEpoch) add('FAIL', 'finalized-root', `Preflight finalized epoch ${finalized.epoch} precedes checkpoint epoch ${cpEpoch}.`);
  else add('MANUAL', 'finalized-root', `Checkpoint epoch ${cpEpoch} is older than preflight finalized epoch ${finalized.epoch}; compare the historical root on an independent archival node.`);
  const reference = p.observations.reference;
  if (p.inputs.referenceQueried && !reference) add('FAIL', 'reference-evidence', 'Preflight declares a reference query but has no reference observations.');
  else if (reference) {
    const refDomain = reference.getvalidatoradmission?.network_domain;
    add(HEX.test(refDomain || '') && refDomain.toLowerCase() === expected.expectDomain.toLowerCase() ? 'PASS' : 'FAIL', 'reference-domain', 'Reference network domain must match the trusted domain.');
    const refFinalized = reference.getchaininfo?.finalized;
    if (refFinalized?.epoch === cpEpoch) add(HEX.test(refFinalized.root || '') && refFinalized.root.toLowerCase() === root.toLowerCase() ? 'PASS' : 'FAIL', 'reference-root', `Reference root at checkpoint epoch ${cpEpoch} must agree.`);
    else add('MANUAL', 'reference-root', 'Reference finality is at another epoch; archival comparison is required.');
  } else add('MANUAL', 'reference-evidence', 'No independent reference node was recorded.');
  const status = checks.some(item => item.status === 'FAIL') ? 'FAIL' : 'REVIEW_MANUAL_REQUIRED';
  return {
    schema: 'bloch.genesis4.validator-evidence-assessment.v1', observedAt: new Date().toISOString(), status,
    inputs: { preflightSha256: preflight.sha256, checkpointSha256: checkpoint.sha256, expectedDomain: expected.expectDomain.toLowerCase(), expectedGenesisSha256: expected.expectGenesisSha256.toLowerCase(), maxAgeMinutes, clockSkewSeconds: CLOCK_SKEW_MS / 1000, ...(expected.expectBinarySha256 === undefined ? {} : { expectedBinarySha256: expected.expectBinarySha256.toLowerCase() }), ...(expected.expectSignerSetSha256 === undefined ? {} : { expectedSignerSetSha256: expected.expectSignerSetSha256.toLowerCase() }) },
    checks, manualGate: { status: 'NOT_VERIFIED', required: ['Authenticate release material, WS digest, signer arrangement and all supplied expected values independently.', 'Compare historical checkpoint root using an independent archival node when epochs differ.', 'Verify deployed binary identity, node independence, exit, withdrawal delay and spendable payout before any bond.'] },
    note: 'SHA256SUMS detects accidental or subsequent bundle changes; it does not authenticate the creator. This local assessment never qualifies staking or delegation.'
  };
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) { console.log(usage()); return 0; }
  const report = assess(readBundle(opts.preflight, 'evidence.json'), readBundle(opts.checkpoint, 'checkpoint-verification.json'), opts);
  if (opts.json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`Validator evidence assessment: ${report.status}`);
    for (const check of report.checks) console.log(`[${check.status}] ${check.id}: ${check.detail}`);
    console.log('Manual gate: NOT_VERIFIED. Review independent publications and the full exit-to-payout lifecycle.');
  }
  return report.status === 'FAIL' ? 2 : 1;
}

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (error) { console.error(`Evidence assessment unavailable: ${error.message}\n${usage()}`); process.exitCode = 2; }
}
module.exports = { parseArgs, readBundle, assess };
