#!/usr/bin/env node
// Genesis-4 validator preflight. Read-only JSON-RPC; no wallet or staking calls.
'use strict';

const METHODS = ['getchaininfo', 'getbuildinfo', 'getvalidatoradmission'];
const HEX32 = /^[a-f0-9]{64}$/i;
const MAX_RPC_RESPONSE_BYTES = 64 * 1024;
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function usage() {
  return `Usage: node preflight.cjs --rpc URL [--reference-rpc URL] [--expect-domain 64-HEX] [--max-lag-slots N] [--timeout-ms N] [--evidence-dir NEW_DIRECTORY] [--json]\n\nQueries only ${METHODS.join(', ')}. Each method has a bounded timeout (default 20000 ms). An evidence directory must not already exist; it contains public RPC observations and an explicit pending manual gate. Supply a trusted network domain from independently authenticated release material. The optional reference endpoint is a comparison, not a trust anchor. Exit and withdrawal qualification is always a separate operator gate.`;
}

function parseArgs(argv) {
  const opts = { maxLagSlots: 2, timeoutMs: 20000, json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { opts.help = true; continue; }
    if (arg === '--json') { opts.json = true; continue; }
    const key = { '--rpc': 'rpc', '--reference-rpc': 'referenceRpc', '--expect-domain': 'expectDomain', '--max-lag-slots': 'maxLagSlots', '--timeout-ms': 'timeoutMs', '--evidence-dir': 'evidenceDir' }[arg];
    if (!key || i + 1 >= argv.length) throw new Error(`Invalid or incomplete option: ${arg}`);
    opts[key] = argv[++i];
  }
  if (opts.help) return opts;
  if (!opts.rpc) throw new Error('--rpc is required');
  for (const name of ['rpc', 'referenceRpc']) {
    if (!opts[name]) continue;
    const url = new URL(opts[name]);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw new Error(`${name} must be an HTTP(S) URL without embedded credentials`);
    if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error(`${name} must use HTTPS except on loopback`);
  }
  if (opts.expectDomain && !HEX32.test(opts.expectDomain)) throw new Error('--expect-domain must be 64 hexadecimal characters');
  if (opts.evidenceDir !== undefined && (!opts.evidenceDir.trim() || opts.evidenceDir === '.' || opts.evidenceDir === '..')) throw new Error('--evidence-dir must name a new directory');
  opts.maxLagSlots = Number(opts.maxLagSlots);
  if (!Number.isSafeInteger(opts.maxLagSlots) || opts.maxLagSlots < 0) throw new Error('--max-lag-slots must be a nonnegative integer');
  opts.timeoutMs = Number(opts.timeoutMs);
  if (!Number.isSafeInteger(opts.timeoutMs) || opts.timeoutMs < 1000 || opts.timeoutMs > 60000) throw new Error('--timeout-ms must be an integer from 1000 to 60000');
  return opts;
}

class ProbeError extends Error {}

async function boundedJson(response) {
  const statedLength = Number(response.headers?.get('content-length'));
  if (Number.isFinite(statedLength) && statedLength > MAX_RPC_RESPONSE_BYTES) throw new ProbeError('RPC response exceeds 65536 bytes');
  if (!response.body || typeof response.body.getReader !== 'function') throw new ProbeError('RPC response body unavailable');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RPC_RESPONSE_BYTES) throw new ProbeError('RPC response exceeds 65536 bytes');
      chunks.push(value);
    }
  } finally {
    if (size > MAX_RPC_RESPONSE_BYTES) await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks, size);
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { throw new ProbeError('Invalid JSON-RPC response JSON'); }
}

async function query(endpoint, method, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: `preflight-${method}`, method, params: [] }),
      signal: controller.signal,
      redirect: 'error'
    });
    if (!response.ok) throw new ProbeError(`HTTP ${Number.isInteger(response.status) ? response.status : 'error'}`);
    const envelope = await boundedJson(response);
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) || envelope.jsonrpc !== '2.0' || envelope.id !== `preflight-${method}`) throw new ProbeError('Invalid JSON-RPC envelope');
    if (Object.hasOwn(envelope, 'error')) {
      if (Object.hasOwn(envelope, 'result') || typeof envelope.error !== 'object' || Array.isArray(envelope.error) || !Number.isSafeInteger(envelope.error.code) || typeof envelope.error.message !== 'string') throw new ProbeError('Invalid JSON-RPC error');
      throw new ProbeError(`RPC error ${envelope.error.code}`);
    }
    if (!envelope.result || typeof envelope.result !== 'object' || Array.isArray(envelope.result)) throw new ProbeError('Missing result object');
    return envelope.result;
  } finally { clearTimeout(timer); }
}

async function readEndpoint(endpoint, timeoutMs = 20000, label = 'primary') {
  const values = { diagnostics: [] };
  // A serial probe avoids overloading a small node or gateway with three simultaneous requests.
  for (const method of METHODS) {
    const started = Date.now();
    try {
      values[method] = await query(endpoint, method, timeoutMs);
      values.diagnostics.push({ endpoint: label, method, status: 'OK', elapsedMs: Date.now() - started });
    } catch (error) {
      const detail = error.name === 'AbortError' ? `Timed out after ${timeoutMs} ms` : error instanceof ProbeError ? error.message : 'RPC transport or response read failed';
      values.diagnostics.push({ endpoint: label, method, status: 'ERROR', elapsedMs: Date.now() - started, detail });
    }
  }
  return values;
}

function evaluate(primary, reference, opts) {
  const chain = primary.getchaininfo || {}, build = primary.getbuildinfo || {}, admission = primary.getvalidatoradmission || {};
  const checks = [];
  const add = (level, title, detail) => checks.push({ level, title, detail });
  const diagnostics = [...(primary.diagnostics || []), ...(reference?.diagnostics || [])];
  for (const diagnostic of diagnostics.filter(item => item.status !== 'OK')) add('FAIL', `${diagnostic.endpoint} ${diagnostic.method}`, diagnostic.detail);
  const isUInt = value => Number.isSafeInteger(value) && value >= 0;
  const domain = admission.network_domain;
  const finality = chain.finalized;
  if (!isUInt(chain.slot) || !isUInt(chain.epoch) || !isUInt(chain.behind_by_slots) || !HEX32.test(String(chain.block_id ?? '')) || !finality || !isUInt(finality.epoch) || !HEX32.test(String(finality.root ?? ''))) {
    add('FAIL', 'Chain response', 'Missing or invalid head, lag or finalized checkpoint fields.');
  } else {
    add(chain.behind_by_slots <= opts.maxLagSlots ? 'PASS' : 'WARN', 'Head freshness', `slot ${chain.slot}, epoch ${chain.epoch}, behind ${chain.behind_by_slots} slots; configured maximum ${opts.maxLagSlots}.`);
    add(finality.epoch <= chain.epoch && chain.epoch - finality.epoch <= 4 ? 'PASS' : 'WARN', 'Finality progress', `finalized epoch ${finality.epoch}, root ${finality.root}; head epoch ${chain.epoch}. This is node-reported evidence, not settlement qualification.`);
  }
  const peers = chain.transport?.peers;
  if (!peers || (!isUInt(peers.devnet) && !isUInt(peers.libp2p))) add('WARN', 'Peer connectivity', 'Peer counts were unavailable; check transport and peer connectivity independently.');
  else {
    const count = (isUInt(peers.devnet) ? peers.devnet : 0) + (isUInt(peers.libp2p) ? peers.libp2p : 0);
    add(count > 0 ? 'PASS' : 'WARN', 'Peer connectivity', `${count} reported peers (${chain.transport.name ?? 'unknown'} transport). A peer count does not prove the correct fork.`);
  }
  if (!HEX32.test(String(domain ?? ''))) add('WARN', 'Network domain', 'Admission response did not supply a valid network domain.');
  else if (opts.expectDomain) add(domain.toLowerCase() === opts.expectDomain.toLowerCase() ? 'PASS' : 'FAIL', 'Network domain', `${domain}; compared with operator-supplied trusted domain.`);
  else add('WARN', 'Network domain', `${domain}; no trusted --expect-domain supplied, so chain identity is unverified.`);
  if (!isUInt(admission.epoch) || typeof admission.active !== 'boolean') add('FAIL', 'Validator admission', 'Missing epoch or active flag.');
  else add(admission.epoch === chain.epoch ? 'PASS' : 'WARN', 'Validator admission', `${admission.active ? 'active' : 'inactive'} at epoch ${admission.epoch}; chain epoch ${chain.epoch}. Admission is not exit, payout or delegation qualification.`);
  if (typeof build.source_digest === 'string' && HEX32.test(build.source_digest)) add('PASS', 'Build identity recorded', `version ${build.build_version ?? build.package_version ?? 'unreported'}; source digest ${build.source_digest}; tree ${build.tree_state ?? 'unknown'}. Verify artifact digest separately.`);
  else add('WARN', 'Build identity', 'No valid source digest reported; record the deployed release and binary artifact digest separately.');
  if (reference) {
    const other = reference.getchaininfo || {}, otherAdmission = reference.getvalidatoradmission || {}, otherBuild = reference.getbuildinfo || {};
    if (HEX32.test(String(domain ?? '')) && HEX32.test(String(otherAdmission.network_domain ?? ''))) add(domain.toLowerCase() === otherAdmission.network_domain.toLowerCase() ? 'PASS' : 'FAIL', 'Reference network domain', `primary ${domain}; reference ${otherAdmission.network_domain}.`);
    else add('WARN', 'Reference network domain', 'Could not compare both network domains.');
    if (finality && other.finalized && isUInt(finality.epoch) && isUInt(other.finalized.epoch) && HEX32.test(String(finality.root ?? '')) && HEX32.test(String(other.finalized.root ?? ''))) {
      if (finality.epoch === other.finalized.epoch) add(finality.root.toLowerCase() === other.finalized.root.toLowerCase() ? 'PASS' : 'FAIL', 'Reference finalized checkpoint', `epoch ${finality.epoch}; primary ${finality.root}; reference ${other.finalized.root}.`);
      else add('WARN', 'Reference finalized checkpoint', `Different reported epochs (${finality.epoch} / ${other.finalized.epoch}); roots cannot be compared at the same checkpoint.`);
    } else add('WARN', 'Reference finalized checkpoint', 'One endpoint omitted a valid finalized checkpoint.');
    if (HEX32.test(String(build.source_digest ?? '')) && HEX32.test(String(otherBuild.source_digest ?? ''))) add(build.source_digest.toLowerCase() === otherBuild.source_digest.toLowerCase() ? 'PASS' : 'WARN', 'Reference source digest', `primary ${build.source_digest}; reference ${otherBuild.source_digest}. Different builds need operator review.`);
  }
  add('MANUAL', 'Trust and lifecycle', 'Authenticate the Genesis-4 manifest and signed weak-subjectivity checkpoint out of band. Verify independent node operation, exit, withdrawal delay and spendable payout before any bond. This script does not qualify them.');
  return { observedAt: new Date().toISOString(), diagnostics, checks, summary: checks.some(c => c.level === 'FAIL') ? 'FAIL' : checks.some(c => c.level === 'WARN') ? 'REVIEW' : 'CHECKS_PASS_MANUAL_REQUIRED' };
}

function publicObservation(values) {
  const chain = values.getchaininfo || {};
  const build = values.getbuildinfo || {};
  const admission = values.getvalidatoradmission || {};
  const str = value => typeof value === 'string' ? value.slice(0, 256) : null;
  const uint = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
  const bool = value => typeof value === 'boolean' ? value : null;
  return {
    getchaininfo: values.getchaininfo ? {
      block_id: str(chain.block_id), slot: uint(chain.slot), epoch: uint(chain.epoch), behind_by_slots: uint(chain.behind_by_slots),
      finalized: { epoch: uint(chain.finalized?.epoch), root: str(chain.finalized?.root) },
      transport: { name: str(chain.transport?.name), peers: { devnet: uint(chain.transport?.peers?.devnet), libp2p: uint(chain.transport?.peers?.libp2p) } }
    } : null,
    getbuildinfo: values.getbuildinfo ? { build_version: str(build.build_version), package_version: str(build.package_version), source_digest: str(build.source_digest), tree_state: str(build.tree_state) } : null,
    getvalidatoradmission: values.getvalidatoradmission ? { active: bool(admission.active), epoch: uint(admission.epoch), network_domain: str(admission.network_domain) } : null
  };
}

function writeEvidenceBundle(directory, report, primary, reference, opts) {
  const bundle = {
    schema: 'bloch.genesis4.validator-preflight.evidence.v1',
    observedAt: report.observedAt,
    summary: report.summary,
    inputs: { expectedNetworkDomain: opts.expectDomain || null, maxLagSlots: opts.maxLagSlots, referenceQueried: Boolean(reference) },
    report,
    observations: { primary: publicObservation(primary), reference: reference ? publicObservation(reference) : null },
    manualGate: {
      status: 'NOT_VERIFIED',
      required: [
        'Authenticate the Genesis-4 manifest and network domain through an independent trusted channel.',
        'Authenticate the signed weak-subjectivity checkpoint and verify it against the deployed node.',
        'Verify the release artifact digest, independent node operation, restart and recovery.',
        'Qualify authenticated exit, withdrawal delay and a spendable payout before any bond.'
      ],
      note: 'This read-only bundle is an observation, not admission, staking, delegation or payout approval.'
    }
  };
  const body = `${JSON.stringify(bundle, null, 2)}\n`;
  const checksum = crypto.createHash('sha256').update(body).digest('hex');
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.writeFileSync(path.join(directory, 'evidence.json'), body, { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(path.join(directory, 'SHA256SUMS'), `${checksum}  evidence.json\n`, { flag: 'wx', mode: 0o600 });
  return { directory: path.resolve(directory), checksum };
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) { console.log(usage()); return 0; }
  const primary = await readEndpoint(opts.rpc, opts.timeoutMs, 'primary');
  const reference = opts.referenceRpc ? await readEndpoint(opts.referenceRpc, opts.timeoutMs, 'reference') : null;
  const report = evaluate(primary, reference, opts);
  if (opts.evidenceDir) {
    const saved = writeEvidenceBundle(opts.evidenceDir, report, primary, reference, opts);
    console.error(`Evidence bundle: ${saved.directory} (SHA-256 ${saved.checksum}); manual gate remains NOT_VERIFIED.`);
  }
  if (opts.json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`Genesis-4 validator preflight — ${report.observedAt}\nResult: ${report.summary}\n`);
    for (const diagnostic of report.diagnostics) console.log(`[RPC ${diagnostic.status}] ${diagnostic.endpoint} ${diagnostic.method}: ${diagnostic.elapsedMs} ms${diagnostic.detail ? `; ${diagnostic.detail}` : ''}`);
    console.log('');
    for (const check of report.checks) console.log(`[${check.level}] ${check.title}: ${check.detail}`);
  }
  return report.summary === 'FAIL' ? 2 : report.summary === 'REVIEW' ? 1 : 0;
}

if (require.main === module) main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(error => { console.error(`Preflight unavailable: ${error.message}\n${usage()}`); process.exitCode = 2; });
module.exports = { parseArgs, evaluate, readEndpoint, publicObservation, writeEvidenceBundle };
