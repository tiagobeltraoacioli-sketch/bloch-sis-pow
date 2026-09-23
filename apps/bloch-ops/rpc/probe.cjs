// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only, bounded compatibility observations; never a chain identity attestation.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, 'catalog.v1.json'), 'utf8'));

const SAFE_METHODS = Object.freeze([
  'getchaininfo', 'getbuildinfo', 'getblockcount',
  'getvalidatorcount', 'getvalidatoradmission', 'getmempoolinfo',
]);
const MAX_BYTES = 1024 * 1024;

function endpointUrl(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error('RPC endpoint must be an absolute URL'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('RPC endpoint must use HTTPS, or HTTP on loopback');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('RPC endpoint must not contain credentials, query, or fragment');
  }
  return url.href;
}

async function readBounded(response) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Empty HTTP response body');
  let total = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BYTES) throw new Error('Response exceeds 1 MiB limit');
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks, total).toString('utf8');
}

async function probeMethod(endpoint, spec, timeoutMs, fetcher = fetch) {
  const started = performance.now();
  const diagnostic = { method: spec.name, status: 'unavailable', round_trip_ms: null, missing_fields: [] };
  try {
    const response = await fetcher(endpoint, {
      method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/json', 'accept': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: spec.name, method: spec.name, params: [] }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    diagnostic.http_status = response.status;
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = JSON.parse(await readBounded(response));
    if (payload?.jsonrpc !== '2.0' || payload?.id !== spec.name) throw new Error('Invalid JSON-RPC envelope or mismatched request id');
    if (payload.error) {
      diagnostic.status = 'rpc_error';
      diagnostic.error = { code: payload.error.code ?? null, message: String(payload.error.message ?? 'Unknown RPC error') };
      return diagnostic;
    }
    const result = payload.result;
    if (spec.result_kind === 'object' && (!result || typeof result !== 'object' || Array.isArray(result))) {
      throw new Error('Expected an object result');
    }
    diagnostic.missing_fields = spec.result_fields.filter(field => !Object.hasOwn(result, field));
    diagnostic.status = diagnostic.missing_fields.length ? 'schema_drift' : 'compatible_shape';
    if (spec.name === 'getchaininfo') {
      diagnostic.observed = {
        height: result.height ?? null, slot: result.slot ?? null,
        finalized_height: result.finalized_height ?? null,
        finalized: result.finalized && typeof result.finalized === 'object' && !Array.isArray(result.finalized)
          ? { epoch: result.finalized.epoch ?? null, root: result.finalized.root ?? null } : null,
      };
    } else if (spec.name === 'getvalidatoradmission') {
      diagnostic.observed = { network_domain: result.network_domain ?? null, active: result.active ?? null };
    } else if (spec.name === 'getbuildinfo') {
      diagnostic.observed = { source_digest: result.source_digest ?? null, commit: result.commit ?? null };
    }
  } catch (error) {
    diagnostic.status = error?.name === 'TimeoutError' ? 'timeout' : 'invalid_response';
    diagnostic.error = String(error?.message || error);
  } finally {
    diagnostic.round_trip_ms = Math.round(performance.now() - started);
  }
  return diagnostic;
}

function checkpoint(row) {
  const value = row?.status === 'compatible_shape' ? row.observed?.finalized : null;
  return value && Number.isSafeInteger(value.epoch) && value.epoch >= 0 &&
    typeof value.root === 'string' && /^(?:0x)?[0-9a-fA-F]{64}$/.test(value.root)
    ? { epoch: value.epoch, root: value.root.replace(/^0x/i, '').toLowerCase() } : null;
}

function networkDomain(row) {
  const value = row?.status === 'compatible_shape' ? row.observed?.network_domain : null;
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value) ? value.toLowerCase() : null;
}

function crossCheck(primary, reference, expectedDomain, referenceRequested) {
  const findings = [];
  const primaryDomain = networkDomain(primary.find(row => row.method === 'getvalidatoradmission'));
  const referenceDomain = reference && networkDomain(reference.find(row => row.method === 'getvalidatoradmission'));
  const primaryCheckpoint = checkpoint(primary.find(row => row.method === 'getchaininfo'));
  const referenceCheckpoint = reference && checkpoint(reference.find(row => row.method === 'getchaininfo'));
  if (expectedDomain !== undefined) {
    if (!primaryDomain) findings.push({ status: 'inconclusive', code: 'primary_domain_unavailable' });
    else if (primaryDomain !== expectedDomain) findings.push({ status: 'fail', code: 'primary_domain_mismatch' });
    else findings.push({ status: 'match', code: 'primary_domain_matches_expected' });
    if (referenceRequested) {
      if (!referenceDomain) findings.push({ status: 'inconclusive', code: 'reference_domain_unavailable' });
      else if (referenceDomain !== expectedDomain) findings.push({ status: 'fail', code: 'reference_domain_mismatch' });
      else findings.push({ status: 'match', code: 'reference_domain_matches_expected' });
    }
  }
  if (referenceRequested) {
    if (primaryDomain && referenceDomain && primaryDomain !== referenceDomain) {
      findings.push({ status: 'fail', code: 'endpoint_domain_conflict' });
    } else if (primaryDomain && referenceDomain) {
      findings.push({ status: 'match', code: 'endpoint_domains_match' });
    } else if (!expectedDomain && (!primaryDomain || !referenceDomain)) {
      findings.push({ status: 'inconclusive', code: 'endpoint_domain_comparison_unavailable' });
    }
    if (!primaryCheckpoint || !referenceCheckpoint) {
      findings.push({ status: 'inconclusive', code: 'finalized_checkpoint_unavailable' });
    } else if (primaryCheckpoint.epoch === referenceCheckpoint.epoch) {
      findings.push(primaryCheckpoint.root === referenceCheckpoint.root
        ? { status: 'match', code: 'same_epoch_finalized_root_matches' }
        : { status: 'fail', code: 'same_epoch_finalized_root_conflict' });
    } else {
      findings.push({ status: 'inconclusive', code: 'different_finalized_epochs' });
    }
  }
  return {
    status: findings.some(row => row.status === 'fail') ? 'fail'
      : findings.some(row => row.status === 'inconclusive') ? 'inconclusive'
      : findings.length ? 'match' : 'not_requested',
    expected_domain: expectedDomain ?? null,
    primary: { network_domain: primaryDomain, finalized: primaryCheckpoint },
    reference: referenceRequested ? { network_domain: referenceDomain, finalized: referenceCheckpoint } : null,
    findings,
    note: 'Both endpoints self-report these values. Matching replies do not establish consensus, operator independence, or an authenticated checkpoint.',
  };
}

async function runProbe(endpoint, timeoutMs = 12000, fetcher = fetch, options = {}) {
  endpoint = endpointUrl(endpoint);
  const referenceEndpoint = options.referenceRpc === undefined ? null : endpointUrl(options.referenceRpc);
  if (referenceEndpoint && new URL(referenceEndpoint).origin === new URL(endpoint).origin) {
    throw new Error('Reference RPC must use a different origin from the primary endpoint');
  }
  const expectedDomain = options.expectDomain;
  if (expectedDomain !== undefined && (typeof expectedDomain !== 'string' || !/^[0-9a-fA-F]{64}$/.test(expectedDomain))) {
    throw new Error('Expected domain must be exactly 64 hexadecimal characters');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 30000) {
    throw new Error('Timeout must be an integer between 500 and 30000 milliseconds');
  }
  const methods = SAFE_METHODS.map(name => {
    const spec = catalog.methods.find(method => method.name === name);
    if (!spec || spec.params.length) throw new Error(`Unsafe or missing catalog method: ${name}`);
    return spec;
  });
  const diagnostics = [];
  for (const spec of methods) diagnostics.push(await probeMethod(endpoint, spec, timeoutMs, fetcher));
  const referenceDiagnostics = [];
  if (referenceEndpoint) {
    for (const name of ['getchaininfo', 'getvalidatoradmission']) {
      referenceDiagnostics.push(await probeMethod(referenceEndpoint, methods.find(spec => spec.name === name), timeoutMs, fetcher));
    }
  }
  return {
    schema_version: '1.0.0', observed_at_utc: new Date().toISOString(), endpoint,
    catalog_version: catalog.schema_version, catalog_source_commit: catalog.source.checkout_commit,
    diagnostics,
    reference_endpoint: referenceEndpoint,
    reference_diagnostics: referenceEndpoint ? referenceDiagnostics : null,
    cross_check: crossCheck(diagnostics, referenceDiagnostics, expectedDomain?.toLowerCase(), Boolean(referenceEndpoint)),
    compatible_shape_count: diagnostics.filter(d => d.status === 'compatible_shape').length,
    identity_note: 'Responses and network_domain are self-reported by the answering endpoint. A matching source digest is not remote attestation. Compare a trusted network manifest, checkpoint and independent nodes before operational use.',
    scope_note: 'Read-only, no-argument methods only. Shape compatibility does not establish semantic correctness, uptime, chain identity, settlement finality or write-path compatibility.',
  };
}

function parseArgs(argv) {
  let rpc, referenceRpc, expectDomain, timeoutMs = 12000, json = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--rpc') rpc = argv[++i];
    else if (arg === '--reference-rpc') referenceRpc = argv[++i];
    else if (arg === '--expect-domain') expectDomain = argv[++i];
    else if (arg === '--timeout-ms') timeoutMs = Number(argv[++i]);
    else if (arg === '--json') json = true;
    else if (arg === '--help') return { help: true };
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!rpc) throw new Error('Provide --rpc ENDPOINT');
  return { rpc, referenceRpc, expectDomain, timeoutMs, json };
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log('Usage: node probe.cjs --rpc https://host/rpc [--reference-rpc https://other-host/rpc] [--expect-domain 64-HEX] [--timeout-ms 12000] [--json]');
    console.log('HTTP is allowed only on localhost, 127.0.0.1 or [::1]. Read-only requests only.');
    return 0;
  }
  const report = await runProbe(args.rpc, args.timeoutMs, fetch, { referenceRpc: args.referenceRpc, expectDomain: args.expectDomain });
  if (args.json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`RPC compatibility probe: ${report.endpoint}`);
    for (const row of report.diagnostics) {
      console.log(`${row.method}: ${row.status} (${row.round_trip_ms} ms)${row.missing_fields.length ? `; missing ${row.missing_fields.join(', ')}` : ''}${row.error ? `; ${typeof row.error === 'string' ? row.error : row.error.message}` : ''}`);
    }
    if (report.reference_diagnostics) for (const row of report.reference_diagnostics) {
      console.log(`reference ${row.method}: ${row.status} (${row.round_trip_ms} ms)`);
    }
    console.log(`Cross-check: ${report.cross_check.status}; ${report.cross_check.findings.map(row => row.code).join(', ') || 'not requested'}`);
    console.log(report.identity_note);
    console.log(report.scope_note);
  }
  return report.compatible_shape_count === SAFE_METHODS.length &&
    ['match', 'not_requested'].includes(report.cross_check.status) ? 0 : 1;
}

if (require.main === module) main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(error => {
  console.error(`RPC probe: ${error.message}`);
  process.exitCode = 2;
});

module.exports = { SAFE_METHODS, endpointUrl, probeMethod, runProbe, parseArgs, main, crossCheck };
