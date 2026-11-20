// SPDX-License-Identifier: AGPL-3.0-or-later
// Replay the public fixture against the built WASM through the real
// nw_alloc / nw_call / nw_free ABI (Node >= 20, no dependencies).
//
//   node replay-fixture.mjs <bloch_l2_deposit_wallet_wasm.wasm> <l2-deposit-fixture.json> [signatures-out.json]
//
// Every deterministic reply must equal the recorded one. The fresh `sign`
// result (randomized signature) is written to signatures-out.json so the Rust
// test can verify it with the node's own decoder and hybrid verifier:
//   L2_DEPOSIT_BROWSER_SIGNATURES=signatures-out.json cargo test -p bloch-l2-deposit-wallet-wasm committed_fixture
import { readFileSync, writeFileSync } from 'node:fs';
import { WASI } from 'node:wasi';
import { createHash } from 'node:crypto';

const [wasmPath, fixturePath, outPath] = process.argv.slice(2);
if (!wasmPath || !fixturePath) {
  console.error('usage: node replay-fixture.mjs <wasm> <fixture.json> [signatures-out.json]');
  process.exit(2);
}
const wasmBytes = readFileSync(wasmPath);
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
const module = new WebAssembly.Module(wasmBytes);
const imports = WebAssembly.Module.imports(module).map((i) => `${i.module}.${i.name}`);
const exports = WebAssembly.Module.exports(module).map((e) => e.name);
const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
const instance = new WebAssembly.Instance(module, wasi.getImportObject());
wasi.initialize(instance);
const { memory, nw_alloc, nw_free, nw_call } = instance.exports;

function call(request) {
  const input = new TextEncoder().encode(JSON.stringify(request));
  const ptr = nw_alloc(input.length);
  if (!ptr) throw new Error('nw_alloc refused the request');
  new Uint8Array(memory.buffer, ptr, input.length).set(input);
  const packed = nw_call(ptr, input.length);
  nw_free(ptr, input.length);
  const out = Number(packed >> 32n);
  const len = Number(packed & 0xffffffffn);
  if (!out) throw new Error('nw_call returned no reply');
  const reply = JSON.parse(new TextDecoder().decode(new Uint8Array(memory.buffer, out, len).slice()));
  nw_free(out, len);
  return reply;
}
// Key order is not part of the ABI; compare canonically.
const canonical = (v) =>
  Array.isArray(v) ? v.map(canonical)
  : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]))
  : v;
const same = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));

let failures = 0;
const fresh = [];
fixture.steps.forEach((step, i) => {
  const reply = call(step.request);
  const expected = step.response;
  let ok;
  if (step.request.method === 'sign' && expected.ok) {
    const { transactionHex, ...rest } = reply.result ?? {};
    const { transactionHex: recorded, ...expectedRest } = expected.result;
    ok = reply.ok === true && same(rest, expectedRest)
      && typeof transactionHex === 'string'
      && transactionHex.startsWith(fixture.unsignedTransactionHex)
      && transactionHex.startsWith('14');
    if (ok) fresh.push(reply.result);
  } else {
    ok = same(reply, expected);
  }
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok  ' : 'FAIL'} step ${i} ${step.request.method}${ok ? '' : ` -> ${JSON.stringify(reply).slice(0, 300)}`}`);
});
console.log(`wasm sha256 ${createHash('sha256').update(wasmBytes).digest('hex')} (${wasmBytes.length} bytes)`);
console.log(`imports: ${imports.join(', ')}`);
console.log(`exports: ${exports.join(', ')}`);
if (outPath) writeFileSync(outPath, JSON.stringify(fresh));
console.log(failures ? `${failures} step(s) FAILED` : `all ${fixture.steps.length} steps reproduced`);
process.exit(failures ? 1 : 0);
