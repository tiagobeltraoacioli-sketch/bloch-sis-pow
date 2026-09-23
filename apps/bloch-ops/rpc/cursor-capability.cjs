// SPDX-License-Identifier: AGPL-3.0-or-later
// Opt-in, bounded observation of the source-only getutxos cursor extension.
'use strict';
const { endpointUrl } = require('./probe.cjs');

const MAX_BYTES = 128 * 1024;
const HEX32 = /^[0-9a-fA-F]{64}$/;
const AMOUNT = /^(0|[1-9][0-9]*)$/;

function validCount(value) { return Number.isSafeInteger(value) && value >= 0; }
function validHex32(value) { return typeof value === 'string' && HEX32.test(value); }

async function request(endpoint, method, params, id, timeoutMs, fetcher) {
  const response = await fetcher(endpoint, {
    method: 'POST', redirect: 'error',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Empty HTTP response body');
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) throw new Error('Response exceeds 128 KiB limit');
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const payload = JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
  if (payload?.jsonrpc !== '2.0' || payload.id !== id ||
    Object.hasOwn(payload, 'result') === Object.hasOwn(payload, 'error')) {
    throw new Error('Invalid JSON-RPC envelope or mismatched request id');
  }
  if (payload.error) {
    if (!Number.isInteger(payload.error.code) || typeof payload.error.message !== 'string') throw new Error('Invalid JSON-RPC error');
    return { error: { code: payload.error.code, message: payload.error.message.slice(0, 200) } };
  }
  return { result: payload.result };
}

function buildMarker(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Expected object build information');
  if (!Object.hasOwn(result, 'features')) return 'absent';
  if (!Array.isArray(result.features) || result.features.length > 64 ||
    result.features.some(feature => typeof feature !== 'string' || feature.length > 128)) {
    throw new Error('Invalid build feature list');
  }
  return result.features.includes('utxo_cursor_v1') ? 'advertised' : 'absent';
}

function markerShapeRelation(marker, shape) {
  if (marker !== 'advertised' && marker !== 'absent') return 'marker_unknown';
  if (shape !== 'cursor_shape' && shape !== 'legacy_shape') return 'shape_unknown';
  if (marker === 'advertised') return shape === 'cursor_shape' ? 'advertised_and_observed' : 'advertised_but_legacy';
  return shape === 'cursor_shape' ? 'unadvertised_but_observed' : 'unadvertised_and_legacy';
}

function pageShape(result, scriptHash) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Expected object result');
  if (!validHex32(result.script_hash) || result.script_hash.toLowerCase() !== scriptHash) throw new Error('script_hash mismatch');
  if (!validCount(result.total) || !validCount(result.returned) || result.returned > 1 || result.returned > result.total) throw new Error('Invalid total or returned count');
  if (typeof result.truncated !== 'boolean' || !Array.isArray(result.utxos) || result.utxos.length !== result.returned) throw new Error('Invalid truncated or utxos');
  for (const utxo of result.utxos) {
    if (!utxo || typeof utxo !== 'object' || Array.isArray(utxo) || !validHex32(utxo.txid) ||
      !validHex32(utxo.script_hash) || utxo.script_hash.toLowerCase() !== scriptHash ||
      !validCount(utxo.vout) || utxo.vout > 0xffffffff || typeof utxo.value_sat !== 'string' || !AMOUNT.test(utxo.value_sat)) {
      throw new Error('Invalid UTXO entry');
    }
  }
  const extension = ['at_head', 'at_slot', 'next_cursor'];
  if (extension.every(key => !Object.hasOwn(result, key))) return { kind: 'legacy_shape', total: result.total, returned: result.returned };
  if (!extension.every(key => Object.hasOwn(result, key))) throw new Error('Partial cursor extension');
  if (!validHex32(result.at_head) || !validCount(result.at_slot)) throw new Error('Invalid cursor head or slot');
  if (result.truncated !== (result.next_cursor !== null)) throw new Error('truncated and next_cursor disagree');
  if (result.next_cursor !== null) {
    const token = result.next_cursor;
    if (typeof token !== 'string' || !/^01[0-9a-fA-F]{200}$/.test(token)) throw new Error('Invalid version-1 cursor token');
    if (token.slice(2, 66).toLowerCase() !== result.at_head.toLowerCase() ||
      token.slice(66, 130).toLowerCase() !== scriptHash) throw new Error('Cursor head or script hash mismatch');
    if (result.returned !== 1 || result.total <= result.returned ||
      token.slice(130, 194).toLowerCase() !== result.utxos[0].txid.toLowerCase() ||
      parseInt(token.slice(194, 202), 16) !== result.utxos[0].vout) throw new Error('Cursor does not bind to last UTXO');
  }
  return { kind: 'cursor_shape', total: result.total, returned: result.returned,
    at_head: result.at_head.toLowerCase(), at_slot: result.at_slot, next_cursor: result.next_cursor };
}

async function checkCursorCapability({ rpc, scriptHash, optIn = false, timeoutMs = 12000, fetcher = fetch }) {
  if (!optIn) throw new Error('Explicit --probe-cursor opt-in required before any RPC request');
  const endpoint = endpointUrl(rpc);
  if (!validHex32(scriptHash)) throw new Error('Supply a 64-hex --script-hash');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 30000) throw new Error('Timeout must be 500–30000 ms');
  const script = scriptHash.toLowerCase();
  const report = { schema_version: '1.0.0', endpoint, observed_at_utc: new Date().toISOString(),
    method: 'getutxos', script_hash: script, limit: 1, request_count: 0, status: 'inconclusive',
    build_marker: 'unknown', marker_shape_relation: 'shape_unknown',
    note: 'An endpoint observation only. Shape support does not prove complete enumeration, release identity, or mainnet availability.' };
  // The marker is self-reported. Its absence or failure never suppresses the direct shape probe.
  report.request_count++;
  try {
    const build = await request(endpoint, 'getbuildinfo', [], 'cursor-capability-build', timeoutMs, fetcher);
    if (build.error) {
      report.build_marker = 'unavailable';
      report.build_rpc_error = build.error;
    } else report.build_marker = buildMarker(build.result);
  } catch (error) {
    report.build_marker = error?.name === 'TimeoutError' ? 'timeout' : 'invalid_response';
    report.build_error = String(error?.message || error);
  }
  try {
    report.request_count++;
    const first = await request(endpoint, 'getutxos', [script, 1, null], 'cursor-capability-1', timeoutMs, fetcher);
    if (first.error) { report.status = 'unavailable'; report.rpc_error = first.error; return report; }
    const page = pageShape(first.result, script);
    report.marker_shape_relation = markerShapeRelation(report.build_marker, page.kind);
    report.first_page = { total: page.total, returned: page.returned };
    if (page.kind === 'legacy_shape') { report.status = 'legacy_shape'; return report; }
    report.at_head = page.at_head;
    report.at_slot = page.at_slot;
    if (page.next_cursor === null) {
      if (page.total !== page.returned) throw new Error('First cursor page ended before the reported total');
      report.status = 'cursor_shape_observed';
      report.note += ' No next page was available to verify cursor follow-up.';
      return report;
    }
    report.request_count++;
    const second = await request(endpoint, 'getutxos', [script, 1, page.next_cursor], 'cursor-capability-2', timeoutMs, fetcher);
    if (second.error) {
      report.status = second.error.code === -32020 ? 'stale_head' : 'inconclusive';
      report.rpc_error = second.error;
      return report;
    }
    const next = pageShape(second.result, script);
    const firstOutput = first.result.utxos[0];
    const secondOutput = second.result.utxos[0];
    const ordered = secondOutput && (secondOutput.txid.toLowerCase() > firstOutput.txid.toLowerCase() ||
      (secondOutput.txid.toLowerCase() === firstOutput.txid.toLowerCase() && secondOutput.vout > firstOutput.vout));
    if (next.kind !== 'cursor_shape' || next.at_head !== page.at_head || next.at_slot !== page.at_slot ||
      next.total !== page.total || next.returned !== 1 || !ordered) {
      throw new Error('Second page conflicts with first page');
    }
    report.status = 'two_pages_observed';
    report.second_page = { returned: next.returned };
    return report;
  } catch (error) {
    report.status = error?.name === 'TimeoutError' ? 'timeout' : 'invalid_response';
    report.error = String(error?.message || error);
    return report;
  }
}

function parseArgs(argv) {
  const args = { timeoutMs: 12000, optIn: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--rpc') args.rpc = argv[++i];
    else if (arg === '--script-hash') args.scriptHash = argv[++i];
    else if (arg === '--timeout-ms') args.timeoutMs = Number(argv[++i]);
    else if (arg === '--probe-cursor') args.optIn = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--help') return { help: true };
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log('Usage: node cursor-capability.cjs --rpc HTTPS-OR-LOOPBACK-URL --script-hash 64-HEX --probe-cursor [--timeout-ms 12000] [--json]');
    console.log('Sends one getbuildinfo and one getutxos(script_hash, 1, null) request; a third request only if a next_cursor is returned.');
    return 0;
  }
  const report = await checkCursorCapability(args);
  console.log(args.json ? JSON.stringify(report, null, 2) : `${report.status}: ${report.request_count} bounded read request(s); ${report.note}`);
  return ['cursor_shape_observed', 'two_pages_observed'].includes(report.status) ? 0 : 1;
}
if (require.main === module) main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(error => {
  console.error(`Cursor capability: ${error.message}`);
  process.exitCode = 2;
});
module.exports = { checkCursorCapability, pageShape, buildMarker, markerShapeRelation, parseArgs, main };
