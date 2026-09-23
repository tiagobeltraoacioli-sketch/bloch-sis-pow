#!/usr/bin/env node
// Operator-local, read-only wrapper for the installed bloch-pos ws-verify command.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const REQUIRED = ['binary', 'envelope', 'signerSet', 'genesis', 'rpc', 'expectDigest'];
const INPUTS = { '--binary': 'binary', '--envelope': 'envelope', '--signer-set': 'signerSet', '--genesis': 'genesis', '--rpc': 'rpc', '--expect-digest': 'expectDigest', '--evidence-dir': 'evidenceDir' };
const MAX_OUTPUT_BYTES = 65536;
const TIMEOUT_MS = 30000;

function usage() {
  return 'Usage: node checkpoint-verify.cjs --binary /path/to/bloch-pos --envelope /path/to/env.bin --signer-set /path/to/set.bin --genesis /path/to/mainnet.manifest --rpc 127.0.0.1:16400 --expect-digest 64-HEX [--evidence-dir NEW_DIRECTORY] [--json]\nThe digest must come from an independent trusted publication channel. The local binary runs ws-verify only; no artifacts are fetched and no key is requested. The RPC uses the binary\'s plaintext host:port client: prefer your own loopback node.';
}

function parseArgs(argv) {
  const opts = { json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { opts.help = true; continue; }
    if (arg === '--json') { opts.json = true; continue; }
    const key = INPUTS[arg];
    if (!key || i + 1 >= argv.length || argv[i + 1].startsWith('--') || opts[key] !== undefined) throw new Error(`Invalid, repeated or incomplete option: ${arg}`);
    opts[key] = argv[++i];
  }
  if (opts.help) return opts;
  for (const name of REQUIRED) if (!opts[name]) throw new Error(`--${name === 'signerSet' ? 'signer-set' : name === 'expectDigest' ? 'expect-digest' : name} is required`);
  if (!/^[a-fA-F0-9]{64}$/.test(opts.expectDigest)) throw new Error('--expect-digest must be 64 hexadecimal characters');
  // ws_tool::rpc_call uses a direct TCP connection and accepts host:port, not an HTTP URL.
  if (!/^(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\]):[1-9][0-9]{0,4}$/.test(opts.rpc) || Number(opts.rpc.slice(opts.rpc.lastIndexOf(':') + 1)) > 65535) throw new Error('--rpc must be a host:port without credentials or a URL path');
  if (opts.evidenceDir !== undefined && (!opts.evidenceDir.trim() || ['.', '..'].includes(opts.evidenceDir))) throw new Error('--evidence-dir must name a new directory');
  return opts;
}

async function fingerprint(file, executable = false) {
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error(`${executable ? 'Binary' : 'Artifact'} must be a regular file`);
  if (executable && !(stat.mode & 0o111)) throw new Error('Binary is not executable');
  if (!executable && stat.size > 32 * 1024 * 1024) throw new Error('Artifact exceeds 32 MiB limit');
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return { sha256: hash.digest('hex'), bytes: stat.size };
}

async function runVerifier(opts) {
  const args = ['ws-verify', '--envelope', opts.envelope, '--signer-set', opts.signerSet, '--genesis', opts.genesis, '--rpc', opts.rpc];
  return new Promise((resolve, reject) => {
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let stopReason = null;
    const child = spawn(opts.binary, args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env } });
    const timer = setTimeout(() => { stopReason = 'TIMEOUT'; child.kill('SIGKILL'); }, TIMEOUT_MS);
    function add(which, chunk) {
      if (stdout.length + stderr.length + chunk.length > MAX_OUTPUT_BYTES) { stopReason = 'OUTPUT_LIMIT'; child.kill('SIGKILL'); return; }
      if (which === 'stdout') stdout = Buffer.concat([stdout, chunk]); else stderr = Buffer.concat([stderr, chunk]);
    }
    child.stdout.on('data', chunk => add('stdout', chunk));
    child.stderr.on('data', chunk => add('stderr', chunk));
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stopReason, stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') }); });
  });
}

function assess(run, expectedDigest) {
  const match = run.stdout.match(/^\s*WS DIGEST\s+([a-fA-F0-9]{64})\s*$/m);
  const digest = match?.[1]?.toLowerCase() || null;
  const freshness = run.stdout.match(/^FRESHNESS\s+[^\r\n]*?—\s*(FRESH|STALE|EXPIRED)\b/m)?.[1] || 'UNKNOWN';
  const accepted = run.code === 0 && /\bVERDICT: ACCEPTED by ws::verify_envelope\./.test(run.stdout);
  const checks = [
    { id: 'command', status: run.stopReason || (run.code === 0 ? 'PASS' : 'FAIL') },
    { id: 'envelope', status: accepted ? 'PASS' : 'FAIL' },
    { id: 'independent-digest', status: digest && digest === expectedDigest.toLowerCase() ? 'PASS' : 'FAIL' },
    { id: 'freshness', status: freshness === 'FRESH' ? 'PASS' : freshness === 'STALE' ? 'REVIEW' : 'FAIL' }
  ];
  const status = checks.some(c => c.status === 'FAIL' || ['TIMEOUT', 'OUTPUT_LIMIT'].includes(c.status)) ? 'FAIL' : checks.some(c => c.status === 'REVIEW') ? 'REVIEW' : 'CRYPTO_ACCEPTED_MANUAL_REQUIRED';
  return { status, digest, freshness, checks };
}

function saveEvidence(directory, report) {
  const body = `${JSON.stringify(report, null, 2)}\n`;
  fs.mkdirSync(directory, { mode: 0o700 });
  const checksum = crypto.createHash('sha256').update(body).digest('hex');
  fs.writeFileSync(path.join(directory, 'checkpoint-verification.json'), body, { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(path.join(directory, 'SHA256SUMS'), `${checksum}  checkpoint-verification.json\n`, { flag: 'wx', mode: 0o600 });
  return checksum;
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) { console.log(usage()); return 0; }
  const inputs = {};
  for (const name of ['binary', 'envelope', 'signerSet', 'genesis']) inputs[name] = await fingerprint(opts[name], name === 'binary');
  const run = await runVerifier(opts);
  const assessment = assess(run, opts.expectDigest);
  const report = {
    schema: 'bloch.genesis4.checkpoint-verification.v1',
    observedAt: new Date().toISOString(),
    status: assessment.status,
    checks: assessment.checks,
    wsDigest: assessment.digest,
    expectedDigest: opts.expectDigest.toLowerCase(),
    freshness: assessment.freshness,
    inputFingerprints: inputs,
    command: { name: 'ws-verify', rpcTargetRecorded: false, exitCode: run.code, signal: run.signal, stopReason: run.stopReason },
    diagnostics: { stdout: run.stdout, stderr: run.stderr },
    manualGate: { status: 'NOT_VERIFIED', required: ['Authenticate manifest, signer set, digest and installed binary through independent channels.', 'Compare checkpoint roots with independent archivals and review arrangement/freshness.', 'Qualify deployed-release mainnet exit, withdrawal delay and spendable payout before any bond.'] },
    note: 'Acceptance by the operator-supplied binary is a local cryptographic observation, not validator or staking qualification.'
  };
  if (opts.evidenceDir) console.error(`Evidence bundle SHA-256: ${saveEvidence(opts.evidenceDir, report)}; manual gate remains NOT_VERIFIED.`);
  if (opts.json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`Checkpoint verification: ${report.status}\nWS digest: ${report.wsDigest || 'UNAVAILABLE'}\nFreshness: ${report.freshness}`);
    for (const check of report.checks) console.log(`[${check.status}] ${check.id}`);
    console.log('Manual gate: NOT_VERIFIED. Review the complete verifier output and independent publications.');
  }
  return report.status === 'FAIL' ? 2 : report.status === 'REVIEW' ? 1 : 0;
}

if (require.main === module) main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(error => { console.error(`Checkpoint verification unavailable: ${error.message}\n${usage()}`); process.exitCode = 2; });
module.exports = { parseArgs, assess, runVerifier, fingerprint, saveEvidence };
