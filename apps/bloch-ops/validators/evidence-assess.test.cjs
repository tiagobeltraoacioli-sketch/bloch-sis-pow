'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { parseArgs, readBundle, assess } = require('./evidence-assess.cjs');

const domain = 'a'.repeat(64), genesis = 'b'.repeat(64), root = 'c'.repeat(64), digest = 'd'.repeat(64), binary = '1'.repeat(64), signerSet = '2'.repeat(64);
const expected = { expectDomain: domain, expectGenesisSha256: genesis };
const preflight = () => ({
  schema: 'bloch.genesis4.validator-preflight.evidence.v1', summary: 'CHECKS_PASS_MANUAL_REQUIRED', report: { summary: 'CHECKS_PASS_MANUAL_REQUIRED', checks: [{ level: 'PASS' }, { level: 'MANUAL' }] },
  inputs: { expectedNetworkDomain: domain, referenceQueried: false }, manualGate: { status: 'NOT_VERIFIED' },
  observations: { primary: { getchaininfo: { epoch: 11, finalized: { epoch: 10, root } }, getvalidatoradmission: { network_domain: domain } }, reference: null }
});
const checkpoint = () => ({
  schema: 'bloch.genesis4.checkpoint-verification.v1', status: 'CRYPTO_ACCEPTED_MANUAL_REQUIRED', checks: [{ status: 'PASS' }, { status: 'PASS' }, { status: 'PASS' }, { status: 'PASS' }],
  command: { name: 'ws-verify', exitCode: 0, stopReason: null }, freshness: 'FRESH', wsDigest: digest, expectedDigest: digest, inputFingerprints: { genesis: { sha256: genesis }, binary: { sha256: binary }, signerSet: { sha256: signerSet } },
  diagnostics: { stdout: `ENVELOPE  local\n  epoch             10\n  block root        ${root}\n  WS DIGEST         ${digest}\nFRESHNESS  epoch 10 vs now 11: age 1 of 2016 epochs — FRESH\nVERDICT: ACCEPTED by ws::verify_envelope.\n` },
  manualGate: { status: 'NOT_VERIFIED' }
});
const wrap = value => ({ value, sha256: 'e'.repeat(64) });

test('same-epoch evidence is consistent yet remains manually gated', () => {
  const result = assess(wrap(preflight()), wrap(checkpoint()), expected);
  assert.equal(result.status, 'REVIEW_MANUAL_REQUIRED');
  assert.equal(result.checks.find(item => item.id === 'finalized-root').status, 'PASS');
  assert.equal(result.manualGate.status, 'NOT_VERIFIED');
});

test('root, domain, genesis and digest contradictions fail closed', () => {
  for (const change of [
    (p, c) => { p.observations.primary.getchaininfo.finalized.root = 'f'.repeat(64); },
    (p, c) => { p.observations.primary.getvalidatoradmission.network_domain = 'f'.repeat(64); },
    (p, c) => { c.inputFingerprints.genesis.sha256 = 'f'.repeat(64); },
    (p, c) => { c.expectedDigest = 'f'.repeat(64); },
    (p, c) => { c.command.exitCode = 1; },
    (p, c) => { p.summary = 'FAIL'; }
  ]) {
    const p = preflight(), c = checkpoint(); change(p, c);
    if (p.summary !== p.report.summary) assert.throws(() => assess(wrap(p), wrap(c), expected), /summary/);
    else assert.equal(assess(wrap(p), wrap(c), expected).status, 'FAIL');
  }
});

test('different finality epochs require archival comparison and older preflight fails', () => {
  const p = preflight(); p.observations.primary.getchaininfo.finalized.epoch = 11;
  assert.equal(assess(wrap(p), wrap(checkpoint()), expected).checks.find(item => item.id === 'finalized-root').status, 'MANUAL');
  p.observations.primary.getchaininfo.finalized.epoch = 9;
  assert.equal(assess(wrap(p), wrap(checkpoint()), expected).status, 'FAIL');
});

test('integrity checksum, format, bounds and symlinks are enforced', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bloch-assess-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const body = Buffer.from(JSON.stringify(preflight()));
  fs.writeFileSync(path.join(dir, 'evidence.json'), body);
  fs.writeFileSync(path.join(dir, 'SHA256SUMS'), `${crypto.createHash('sha256').update(body).digest('hex')}  evidence.json\n`);
  assert.equal(readBundle(dir, 'evidence.json').value.schema, 'bloch.genesis4.validator-preflight.evidence.v1');
  fs.appendFileSync(path.join(dir, 'evidence.json'), '\n');
  assert.throws(() => readBundle(dir, 'evidence.json'), /mismatch/);
  fs.writeFileSync(path.join(dir, 'evidence.json'), Buffer.alloc(256 * 1024 + 1));
  assert.throws(() => readBundle(dir, 'evidence.json'), /at most/);
  fs.rmSync(path.join(dir, 'evidence.json'));
  fs.symlinkSync(path.join(dir, 'SHA256SUMS'), path.join(dir, 'evidence.json'));
  assert.throws(() => readBundle(dir, 'evidence.json'), /regular/);
});

test('both trusted values are mandatory', () => {
  assert.throws(() => parseArgs(['--preflight', 'one', '--checkpoint', 'two']), /expectDomain/);
  assert.equal(parseArgs(['--preflight', 'one', '--checkpoint', 'two', '--expect-domain', domain, '--expect-genesis-sha256', genesis]).checkpoint, 'two');
});

test('optional authenticated binary and signer-set pins match recorded fingerprints and keep manual gate', () => {
  const pinned = { ...expected, expectBinarySha256: binary.toUpperCase(), expectSignerSetSha256: signerSet.toUpperCase() };
  const result = assess(wrap(preflight()), wrap(checkpoint()), pinned);
  assert.equal(result.status, 'REVIEW_MANUAL_REQUIRED');
  assert.equal(result.manualGate.status, 'NOT_VERIFIED');
  assert.equal(result.inputs.expectedBinarySha256, binary);
  assert.equal(result.inputs.expectedSignerSetSha256, signerSet);
  assert.equal(result.checks.find(item => item.id === 'binary-artifact').status, 'PASS');
  assert.equal(result.checks.find(item => item.id === 'signer-set-artifact').status, 'PASS');
  assert.equal(assess(wrap(preflight()), wrap(checkpoint()), expected).checks.some(item => item.id === 'binary-artifact'), false);
});

test('optional pins fail when recorded fingerprint is absent, malformed or different', () => {
  for (const [input, option, pinned] of [['binary', 'expectBinarySha256', binary], ['signerSet', 'expectSignerSetSha256', signerSet]]) {
    for (const value of [undefined, 'not-a-digest', 'f'.repeat(64)]) {
      const c = checkpoint();
      if (value === undefined) delete c.inputFingerprints[input];
      else c.inputFingerprints[input].sha256 = value;
      const result = assess(wrap(preflight()), wrap(c), { ...expected, [option]: pinned });
      assert.equal(result.status, 'FAIL');
      assert.equal(result.checks.find(item => item.id === (input === 'binary' ? 'binary-artifact' : 'signer-set-artifact')).status, 'FAIL');
    }
  }
});

test('optional CLI pins reject malformed and repeated values', () => {
  const base = ['--preflight', 'one', '--checkpoint', 'two', '--expect-domain', domain, '--expect-genesis-sha256', genesis];
  for (const option of ['--expect-binary-sha256', '--expect-signer-set-sha256']) {
    assert.throws(() => parseArgs([...base, option, 'invalid']), /64 hexadecimal/);
    assert.throws(() => parseArgs([...base, option]), /incomplete option/);
    assert.throws(() => parseArgs([...base, option, binary, option, binary]), /repeated/);
  }
  const opts = parseArgs([...base, '--expect-binary-sha256', binary, '--expect-signer-set-sha256', signerSet]);
  assert.equal(opts.expectBinarySha256, binary);
  assert.equal(opts.expectSignerSetSha256, signerSet);
});

test('CLI reads saved bundles and never reports an opening approval', t => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'bloch-assess-cli-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  for (const [directory, filename, value] of [['preflight', 'evidence.json', preflight()], ['checkpoint', 'checkpoint-verification.json', checkpoint()]]) {
    const location = path.join(parent, directory);
    fs.mkdirSync(location);
    const body = Buffer.from(`${JSON.stringify(value)}\n`);
    fs.writeFileSync(path.join(location, filename), body);
    fs.writeFileSync(path.join(location, 'SHA256SUMS'), `${crypto.createHash('sha256').update(body).digest('hex')}  ${filename}\n`);
  }
  const args = [__filename.replace(/\.test\.cjs$/, '.cjs'), '--preflight', path.join(parent, 'preflight'), '--checkpoint', path.join(parent, 'checkpoint'), '--expect-domain', domain, '--expect-genesis-sha256', genesis, '--json'];
  const run = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(run.status, 1);
  assert.equal(JSON.parse(run.stdout).status, 'REVIEW_MANUAL_REQUIRED');
  assert.equal(JSON.parse(run.stdout).manualGate.status, 'NOT_VERIFIED');
});
