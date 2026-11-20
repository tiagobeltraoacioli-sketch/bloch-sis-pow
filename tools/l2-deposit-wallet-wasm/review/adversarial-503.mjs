// SPDX-License-Identifier: AGPL-3.0-or-later
// Independent review 503 (2026-11-20): adversarial run against the BUILT
// signer through the real nw_alloc / nw_call / nw_free ABI, with a host that
// controls WASI `random_get`. Node >= 20, no dependencies, no network.
//
//   node adversarial-503.mjs <wasm> <keys.json> <signed-out.json> <zero-rng-out.json>
//
// keys.json comes from `R503_EXPORT_KEYS=... cargo test --test review_503`
// (public test mnemonic). signed-out.json is judged by the node's own code:
//   R503_SIGNED=signed-out.json R503_ZERO_RNG=zero-rng-out.json \
//     cargo test -p bloch-l2-deposit-wallet-wasm --features state-acceptance --test review_503 -- --nocapture
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomFillSync, randomInt } from 'node:crypto';

const [wasmPath, keysPath, signedOut, zeroOut] = process.argv.slice(2);
if (!wasmPath || !keysPath) {
  console.error('usage: node adversarial-503.mjs <wasm> <keys.json> [signed-out.json] [zero-rng-out.json]');
  process.exit(2);
}
const wasmBytes = readFileSync(wasmPath);
const keys = JSON.parse(readFileSync(keysPath, 'utf8'));
const module = new WebAssembly.Module(wasmBytes);
const DOMAIN = keys.domainHex;
const sha3 = (...parts) => { const h = createHash('sha3-256'); for (const p of parts) h.update(p); return h.digest(); };
const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Buffer.from(s, 'hex');

let passed = 0;
let failed = 0;
const notes = [];
function check(cond, label, detail = '') {
  if (cond) passed += 1;
  else { failed += 1; console.log(`FAIL ${label} ${detail}`); }
}
const note = (s) => { notes.push(s); console.log(`note ${s}`); };

// ── Host ────────────────────────────────────────────────────────────────────
function host(rng = 'os') {
  let memory;
  const stats = { randomCalls: 0, randomBytes: 0 };
  const view = () => new DataView(memory.buffer);
  const wasi = {
    random_get(ptr, len) {
      stats.randomCalls += 1; stats.randomBytes += len;
      if (rng === 'fail') return 29; // EIO
      const target = new Uint8Array(memory.buffer, ptr, len);
      if (rng === 'zero') target.fill(0); else randomFillSync(target);
      return 0;
    },
    environ_sizes_get(count, size) { view().setUint32(count, 0, true); view().setUint32(size, 0, true); return 0; },
    environ_get() { return 0; },
    fd_write(fd, iovs, count, written) {
      let n = 0;
      for (let i = 0; i < count; i += 1) n += view().getUint32(iovs + i * 8 + 4, true);
      view().setUint32(written, n, true);
      return 0;
    },
    proc_exit(code) { throw new Error(`proc_exit ${code}`); },
  };
  const instance = new WebAssembly.Instance(module, { wasi_snapshot_preview1: wasi });
  memory = instance.exports.memory;
  const { nw_alloc, nw_free, nw_call } = instance.exports;
  if (instance.exports._initialize) instance.exports._initialize();
  function raw(bytes) {
    const ptr = nw_alloc(bytes.length);
    if (!ptr) return { allocRefused: true };
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    const packed = nw_call(ptr, bytes.length);
    nw_free(ptr, bytes.length);
    const out = Number(packed >> 32n);
    const len = Number(packed & 0xffffffffn);
    if (!out) return { noReply: true };
    const reply = JSON.parse(Buffer.from(new Uint8Array(memory.buffer, out, len)).toString('utf8'));
    nw_free(out, len);
    return reply;
  }
  const text = (s) => raw(Buffer.from(s, 'utf8'));
  const call = (method, args) => text(JSON.stringify({ method, args }));
  return { instance, memory: () => memory, nw_alloc, nw_free, nw_call, raw, text, call, stats };
}

// ── Independent decoder of wire 0x14 (written from the layout, not the crate) ─
function decode(txHex) {
  const b = unhex(txHex);
  let i = 0;
  const take = (n) => { if (i + n > b.length) throw new Error('truncated'); const s = b.subarray(i, i + n); i += n; return s; };
  const u32 = () => take(4).readUInt32LE(0);
  const u64 = () => take(8).readBigUInt64LE(0);
  const tag = take(1)[0];
  const domain = hex(take(32));
  const pubkey = take(u32());
  const count = u32();
  const inputs = [];
  for (let k = 0; k < count; k += 1) inputs.push({ txidHex: hex(take(32)), vout: u32() });
  const amount = u64();
  const recipient = hex(take(20));
  const changeValue = u64();
  const changeScript = hex(take(32));
  const txBytes = u64();
  const tipLo = u64(); const tipHi = u64();
  const intentEnd = i;
  const sigLen = u32();
  const signature = take(sigLen);
  if (i !== b.length) throw new Error('trailing bytes');
  const intent = b.subarray(0, intentEnd);
  const root = sha3(Buffer.from('BLOCH:L2:DEPOSIT:V1'), intent);
  const txid = hex(sha3(Buffer.from('BLCH4:TXID\0\0\0\0\0\0', 'latin1'), root));
  return { tag, domain, pubkey, inputs, amount, recipient, changeValue, changeScript, txBytes, tip: (tipHi << 64n) | tipLo, sigLen, signature, txid, length: b.length };
}

const released = [];
/// Every released transaction must be exactly the reviewed one.
function judge(label, publicKeyHex, args, review, signed) {
  const tx = decode(signed.transactionHex);
  const owner = hex(sha3(unhex(publicKeyHex)));
  const rows = args.inputs.map((r) => ({ txidHex: r.txidHex, vout: Number(r.vout), valueSat: Number(r.valueSat) }));
  const sorted = [...rows].sort((a, b) => (a.txidHex === b.txidHex ? a.vout - b.vout : a.txidHex < b.txidHex ? -1 : 1));
  const total = rows.reduce((s, r) => s + BigInt(r.valueSat), 0n);
  check(tx.tag === 0x14, `${label}: tag`);
  check(tx.domain === DOMAIN, `${label}: domain`);
  check(hex(tx.pubkey) === publicKeyHex, `${label}: funding key`);
  check(tx.changeScript === owner, `${label}: change script is the owner`, tx.changeScript);
  check(tx.recipient === review.recipientHex && tx.recipient === args.recipientHex.toLowerCase(), `${label}: recipient`);
  check(tx.amount.toString() === review.amountSat && review.amountSat === args.amountSat, `${label}: amount`);
  check(tx.changeValue.toString() === review.changeSat, `${label}: change value`);
  check(tx.txBytes.toString() === review.txBytes && tx.txBytes >= BigInt(tx.length), `${label}: declared size`);
  check(tx.tip.toString() === review.tipMillisatPerGas && review.tipMillisatPerGas === args.tipMillisatPerGas, `${label}: tip`);
  check(JSON.stringify(tx.inputs) === JSON.stringify(sorted.map(({ txidHex, vout }) => ({ txidHex, vout }))), `${label}: inputs`);
  check(total === tx.amount + tx.changeValue + BigInt(review.feeSat), `${label}: conservation`);
  check(total.toString() === review.totalInputSat, `${label}: total`);
  check(tx.txid === signed.txid && tx.txid === review.txid, `${label}: txid (independent sha3)`);
  check(tx.sigLen > 0 && tx.sigLen <= 4593, `${label}: signature bound`, String(tx.sigLen));
  check(signed.feeSat === review.feeSat && signed.changeSat === review.changeSat, `${label}: sign reply echoes review`);
  released.push({ label, publicKeyHex, inputs: rows, review, signed });
  return tx;
}

const V1 = keys.v1.publicKeyHex;
const V2 = keys.v2.publicKeyHex;
const openV1 = { domainHex: DOMAIN, publicKeyHex: V1, mnemonic: keys.mnemonic };
const openV2 = { domainHex: DOMAIN, publicKeyHex: V2, mnemonic: keys.mnemonic };
const base = () => ({
  recipientHex: '97276ae971d27c6aab011da8c62ea3f79653d161',
  amountSat: '1000000000',
  inputs: [
    { txidHex: '34'.repeat(32), vout: 1, valueSat: '900000000' },
    { txidHex: '12'.repeat(32), vout: 0, valueSat: '600000000' },
  ],
  baseFeeMillisatPerGas: '10',
  tipMillisatPerGas: '0',
});
const clone = (v) => JSON.parse(JSON.stringify(v));
const err = (reply, why) => reply && reply.ok === false && (why === undefined || reply.error === why);
const withId = (args, review) => ({ ...clone(args), reviewId: review.reviewId });

// ── 1. Review / sign binding ────────────────────────────────────────────────
{
  const h = host();
  check(err(h.call('review', base()), 'locked'), 'review before open is locked');
  check(err(h.call('sign', { ...base(), reviewId: '00'.repeat(32) }), 'locked'), 'sign before open is locked');
  check(h.call('open_mnemonic', openV1).ok === true, 'open v1');
  check(err(h.call('sign', { ...base(), reviewId: '00'.repeat(32) }), 'review required'), 'sign without review');

  // Control: the reviewed transaction is released, once.
  let r = h.call('review', base());
  check(r.ok === true, 'review ok');
  let s = h.call('sign', withId(base(), r.result));
  check(s.ok === true, 'sign ok');
  judge('control', V1, base(), r.result, s.result);
  check(err(h.call('sign', withId(base(), r.result)), 'review required'), 'review is single-use');

  // Each single-field difference is refused and consumes the review.
  const mutations = [
    ['amount+1', (a) => { a.amountSat = '1000000001'; }],
    ['amount-1', (a) => { a.amountSat = '999999999'; }],
    ['recipient last nibble', (a) => { a.recipientHex = a.recipientHex.slice(0, 39) + '0'; }],
    ['recipient first nibble', (a) => { a.recipientHex = '8' + a.recipientHex.slice(1); }],
    ['input txid', (a) => { a.inputs[0].txidHex = '35'.repeat(32); }],
    ['input vout', (a) => { a.inputs[0].vout = 2; }],
    ['input value +1', (a) => { a.inputs[0].valueSat = '900000001'; }],
    ['input value moved between rows', (a) => { a.inputs[0].valueSat = '900000001'; a.inputs[1].valueSat = '599999999'; }],
    ['base fee', (a) => { a.baseFeeMillisatPerGas = '11'; }],
    ['tip', (a) => { a.tipMillisatPerGas = '1'; }],
    ['extra input', (a) => { a.inputs.push({ txidHex: '56'.repeat(32), vout: 0, valueSat: '1' }); }],
    ['one input fewer', (a) => { a.inputs.pop(); a.amountSat = '100000000'; }],
  ];
  for (const [name, mutate] of mutations) {
    r = h.call('review', base());
    const changed = base(); mutate(changed);
    check(err(h.call('sign', withId(changed, r.result)), 'review changed'), `sign refuses: ${name}`);
    check(err(h.call('sign', withId(base(), r.result)), 'review required'), `refusal consumed the review: ${name}`);
  }
  // "value moved between rows" keeps total, fee and the unsigned bytes equal:
  // only the per-input values in the fingerprint tell them apart.

  // The fingerprint must be the pending one, lowercase, 32 bytes.
  for (const bad of ['11'.repeat(32), null, '11', 5, undefined]) {
    r = h.call('review', base());
    const a = base(); if (bad !== undefined) a.reviewId = bad;
    check(err(h.call('sign', a)), `bad reviewId ${JSON.stringify(bad)}`);
    check(err(h.call('sign', withId(base(), r.result)), 'review required'), 'bad reviewId consumed the review');
  }
  r = h.call('review', base());
  check(err(h.call('sign', { ...base(), reviewId: r.result.reviewId.toUpperCase() })), 'uppercase reviewId refused');

  // cancel, lock, re-open, failed open, garbage call.
  r = h.call('review', base());
  check(h.call('cancel', {}).ok === true, 'cancel');
  check(err(h.call('sign', withId(base(), r.result)), 'review required'), 'cancel invalidates');
  r = h.call('review', base());
  check(h.call('lock', {}).ok === true, 'lock');
  check(err(h.call('sign', withId(base(), r.result)), 'locked'), 'lock invalidates');
  check(h.call('open_mnemonic', openV1).ok === true, 're-open');
  check(err(h.call('sign', withId(base(), r.result)), 'review required'), 're-open does not revive the review');

  // Re-open with ANOTHER key between review and sign.
  const r1 = h.call('review', base());
  check(h.call('open_mnemonic', openV2).ok === true, 'open v2 over v1');
  check(err(h.call('sign', withId(base(), r1.result)), 'review required'), 'v1 review cannot be signed by the v2 session');
  const r2 = h.call('review', base());
  check(r2.ok && r2.result.reviewId !== r1.result.reviewId && r2.result.txid !== r1.result.txid, 'the fingerprint binds the key');
  check(err(h.call('sign', withId(base(), r1.result)), 'review changed'), 'v1 fingerprint refused in the v2 session');
  const r3 = h.call('review', base());
  const s3 = h.call('sign', withId(base(), r3.result));
  check(s3.ok === true, 'v2 sign');
  judge('v2 account', V2, base(), r3.result, s3.result);

  // A failed open drops the session entirely.
  h.call('open_mnemonic', openV1);
  r = h.call('review', base());
  const wrong = V1.slice(0, 200) + (V1[200] === '0' ? '1' : '0') + V1.slice(201);
  check(err(h.call('open_mnemonic', { ...openV1, publicKeyHex: wrong }), 'phrase account mismatch'), 'wrong expected key');
  check(err(h.call('sign', withId(base(), r.result)), 'locked'), 'failed open leaves no session');
  check(err(h.call('open_mnemonic', { ...openV1, domainHex: '00' + DOMAIN.slice(2) }), 'wrong network'), 'wrong domain');
  check(err(h.call('open_mnemonic', { ...openV1, domainHex: DOMAIN.toUpperCase() }), 'wrong network'), 'uppercase domain');
  check(err(h.call('open_keypair', { domainHex: DOMAIN, publicKeyHex: V1, secretKeyHex: keys.v2.secretKeyHex }), 'account mismatch'), 'foreign secret');
  check(err(h.call('open_keypair', { domainHex: DOMAIN, publicKeyHex: V2, secretKeyHex: keys.v1.secretKeyHex }), 'account mismatch'), 'foreign public');

  // Garbage between review and sign.
  h.call('open_mnemonic', openV1);
  for (const garbage of ['{', '[]', 'null', '{"method":"review"}', '{"method":"nope","args":{}}', '{"method":5,"args":{}}', '{"method":"review","args":null}', '{"method":"review","args":[]}']) {
    r = h.call('review', base());
    check(err(h.text(garbage)), `garbage refused: ${garbage}`);
    check(err(h.call('sign', withId(base(), r.result)), 'review required'), `garbage invalidates: ${garbage}`);
  }
  r = h.call('review', base());
  const bogus = h.nw_call(12345, 7);
  check(Number(bogus >> 32n) !== 0, 'bogus buffer answered');
  h.nw_free(Number(bogus >> 32n), Number(bogus & 0xffffffffn));
  check(err(h.call('sign', withId(base(), r.result)), 'review required'), 'bogus buffer invalidates');

  // A newer review replaces the older one.
  const a1 = base(); const a2 = base(); a2.amountSat = '1100000000';
  const ra = h.call('review', a1); const rb = h.call('review', a2);
  check(err(h.call('sign', withId(a1, ra.result)), 'review changed'), 'older review refused');
  check(err(h.call('sign', withId(a2, rb.result)), 'review required'), 'and the newer one was consumed by that attempt');

  // Equivalent spellings of the SAME transaction share one fingerprint.
  const spelled = base();
  spelled.recipientHex = spelled.recipientHex.toUpperCase();
  spelled.inputs.reverse();
  spelled.inputs[0].vout = '0'; spelled.inputs[1].valueSat = 900000000;
  r = h.call('review', base());
  s = h.call('sign', withId(spelled, r.result));
  check(s.ok === true, 'equivalent spelling signs');
  if (s.ok) judge('equivalent spelling', V1, base(), r.result, s.result);

  // Unknown fields: nothing a page adds is silently honoured.
  for (const field of ['confirmed', 'changeScriptHashHex', 'changeAddress', 'ownerHashHex', 'domainHex', 'publicKeyHex', 'digestHex', 'change', 'txBytes', 'signature', '__proto__']) {
    const a = base(); a[field] = field === 'change' ? { scriptHashHex: 'aa'.repeat(32) } : 'aa'.repeat(32);
    check(err(h.text(JSON.stringify({ method: 'review', args: a }).replace('"__proto__"', '"__proto__"')), 'unsupported field') || field === '__proto__', `review refuses field ${field}`);
    r = h.call('review', base());
    const sa = withId(base(), r.result); sa[field] = 'aa'.repeat(32);
    if (field !== '__proto__') check(err(h.call('sign', sa), 'unsupported field'), `sign refuses field ${field}`);
  }
  for (const field of ['changeScriptHashHex', 'address', 'key']) {
    const a = base(); a.inputs[0][field] = 'aa'.repeat(32);
    check(err(h.call('review', a), 'unsupported field'), `input row refuses field ${field}`);
  }
  { const a = base(); a.inputs[0].scriptHashHex = hex(sha3(unhex(V2))); check(err(h.call('review', a), 'funding owner mismatch'), 'foreign scriptHash'); }
  for (const m of ['sign_digest', 'sign_message', 'export', 'export_secret', 'get_secret', 'open', 'debug', 'derive', 'public_key', '']) {
    check(err(h.call(m, {}), 'unsupported method') || err(h.call(m, {})), `no method ${m}`);
  }

  // feeSat / changeSat echoes.
  r = h.call('review', base());
  check(err(h.call('sign', { ...withId(base(), r.result), feeSat: null })), 'feeSat null');
  r = h.call('review', base());
  check(err(h.call('sign', { ...withId(base(), r.result), feeSat: Number(r.result.feeSat) }), 'missing string'), 'feeSat as number');
  r = h.call('review', base());
  check(err(h.call('sign', { ...withId(base(), r.result), changeSat: String(BigInt(r.result.changeSat) + 1n) }), 'review changed'), 'changeSat+1');

  // Duplicate JSON keys (raw text): serde_json keeps the LAST; review and
  // sign parse the same way, and the reply states what was parsed.
  const dup = JSON.stringify({ method: 'review', args: base() }).replace('"amountSat":"1000000000"', '"amountSat":"1000000000","amountSat":"1200000000"');
  r = h.text(dup);
  check(r.ok === true && r.result.amountSat === '1200000000', 'duplicate key: the reply shows the value that was used', JSON.stringify(r).slice(0, 120));
  const dupSign = JSON.stringify({ method: 'sign', args: withId(base(), r.result) }).replace('"amountSat":"1000000000"', '"amountSat":"1200000000","amountSat":"1000000000"');
  check(err(h.text(dupSign), 'review changed'), 'duplicate key in sign: last one judged, refused');
  const dupMethod = `{"method":"review","method":"sign","args":${JSON.stringify(base())}}`;
  check(err(h.text(dupMethod), 'review required'), 'duplicate method: last wins, no review -> refused');

  // Randomised differences (cheap: every one must be refused before signing).
  let refused = 0;
  const N = 400;
  for (let k = 0; k < N; k += 1) {
    r = h.call('review', base());
    const a = withId(base(), r.result);
    const pick = randomInt(8);
    const flip = (s) => { const p = randomInt(s.length); const c = s[p] === 'f' ? '0' : (parseInt(s[p], 16) + 1).toString(16); return s.slice(0, p) + c + s.slice(p + 1); };
    if (pick === 0) a.recipientHex = flip(a.recipientHex);
    else if (pick === 1) a.amountSat = String(1000000000 + (randomInt(2) ? 1 : -1) * (1 + randomInt(400000000)));
    else if (pick === 2) a.inputs[randomInt(2)].txidHex = flip(a.inputs[0].txidHex);
    else if (pick === 3) a.inputs[randomInt(2)].vout = 2 + randomInt(1000);
    else if (pick === 4) a.inputs[randomInt(2)].valueSat = String(700000000 + randomInt(100000000));
    else if (pick === 5) a.baseFeeMillisatPerGas = String(11 + randomInt(1000));
    else if (pick === 6) a.tipMillisatPerGas = String(1 + randomInt(1000)); // above 10: now `tip above base fee`; 1..10: `review changed`
    else a.reviewId = flip(a.reviewId);
    const reply = h.call('sign', a);
    if (err(reply)) refused += 1; else console.log(`FAIL randomised difference signed: ${JSON.stringify(a).slice(0, 300)}`);
  }
  check(refused === N, `randomised differences refused ${refused}/${N}`);
  note(`randomised sign-vs-review differences refused: ${refused}/${N}`);
}

// ── 2. Parsing and arithmetic ───────────────────────────────────────────────
{
  const h = host();
  h.call('open_mnemonic', openV1);
  const rev = (mutate) => { const a = base(); mutate(a); return h.call('review', a); };
  const revRaw = (from, to) => h.text(JSON.stringify({ method: 'review', args: base() }).replace(from, to));
  const table = [];
  const expect = (label, reply, why) => { table.push([label, reply.ok ? 'OK' : reply.error]); check(err(reply, why), `parse: ${label}`, JSON.stringify(reply).slice(0, 160)); };
  for (const [v, why] of [[' 1000000000', 'noncanonical integer'], ['1000000000 ', 'noncanonical integer'], ['1000000000\n', 'noncanonical integer'], ['+1000000000', 'noncanonical integer'], ['-1000000000', 'noncanonical integer'], ['01000000000', 'noncanonical integer'], ['1e9', 'noncanonical integer'], ['1000000000.0', 'noncanonical integer'], ['0x3b9aca00', 'noncanonical integer'], ['1_000_000_000', 'noncanonical integer'], ['', 'noncanonical integer'], ['１０００００００００', 'noncanonical integer'], ['18446744073709551616', 'integer overflow'], ['9'.repeat(39), 'integer overflow'], ['9'.repeat(40), 'noncanonical integer'], ['0', 'amount out of range'], ['999999', 'amount out of range'], ['10000000000000000001', 'amount out of range'], [1000000000, 'missing string'], [true, 'missing string'], [null, 'missing string'], [['1000000000'], 'missing string'], [{}, 'missing string']]) {
    expect(`amountSat=${JSON.stringify(v)}`, rev((a) => { a.amountSat = v; }), why);
  }
  for (const [v, why] of [['9', 'invalid fee'], ['0', 'invalid fee'], [' 10', 'noncanonical integer'], ['010', 'noncanonical integer'], [10, 'missing string'], ['9'.repeat(39), 'integer overflow'], ['340282366920938463463374607431768211455', 'invalid fee']]) {
    expect(`baseFee=${JSON.stringify(v)}`, rev((a) => { a.baseFeeMillisatPerGas = v; }), why);
  }
  for (const [v, why] of [['340282366920938463463374607431768211455', 'tip above ceiling'], ['-1', 'noncanonical integer'], ['00', 'noncanonical integer'], [0, 'missing string']]) {
    expect(`tip=${JSON.stringify(v)}`, rev((a) => { a.tipMillisatPerGas = v; }), why);
  }
  for (const [v, why] of [['0x' + '97276ae971d27c6aab011da8c62ea3f79653d1', 'invalid recipient'], ['0x97276ae971d27c6aab011da8c62ea3f79653d161', 'invalid recipient'], ['97276ae971d27c6aab011da8c62ea3f79653d16', 'invalid recipient'], ['97276ae971d27c6aab011da8c62ea3f79653d1611', 'invalid recipient'], ['zz276ae971d27c6aab011da8c62ea3f79653d161', 'invalid recipient'], [' 7276ae971d27c6aab011da8c62ea3f79653d161', 'invalid recipient'], ['é'.repeat(20), 'invalid recipient'], ['0'.repeat(40), 'zero recipient'], [null, 'missing string'], [0, 'missing string']]) {
    expect(`recipient=${JSON.stringify(v)}`, rev((a) => { a.recipientHex = v; }), why);
  }
  for (const [v, why] of [['34'.repeat(32).toUpperCase().replace(/3/g, 'A'), 'invalid hex'], ['0x' + '34'.repeat(31), 'invalid hex'], ['34'.repeat(31), 'invalid hash'], ['34'.repeat(33), 'invalid hex'], ['3'.repeat(63), 'invalid hex'], ['', 'invalid hash'], [null, 'missing string']]) {
    expect(`txid=${JSON.stringify(v)}`, rev((a) => { a.inputs[0].txidHex = v; }), why);
  }
  for (const [raw, why] of [['-1', 'noncanonical integer'], ['-0', 'noncanonical integer'], ['1.0', 'noncanonical integer'], ['1e0', 'noncanonical integer'], ['1.5', 'noncanonical integer'], ['4294967296', 'integer overflow'], ['18446744073709551616', 'noncanonical integer'], ['"01"', 'noncanonical integer'], ['" 1"', 'noncanonical integer'], ['"4294967296"', 'integer overflow'], ['null', 'missing integer'], ['true', 'missing integer'], ['[1]', 'missing integer']]) {
    expect(`vout=${raw}`, revRaw('"vout":1', `"vout":${raw}`), why);
  }
  for (const [raw, why] of [['0', 'empty input'], ['"0"', 'empty input'], ['-5', 'noncanonical integer'], ['9e8', 'noncanonical integer'], ['900000000.0', 'noncanonical integer'], ['18446744073709551616', 'noncanonical integer'], ['"18446744073709551616"', 'integer overflow'], ['"0900000000"', 'noncanonical integer'], ['null', 'missing integer']]) {
    expect(`valueSat=${raw}`, revRaw('"valueSat":"900000000"', `"valueSat":${raw}`), why);
  }
  // u32::MAX vout and a u64::MAX value are representable and reviewed.
  let r = revRaw('"vout":1', '"vout":4294967295');
  check(r.ok === true, 'vout u32::MAX reviewed');
  r = revRaw('"valueSat":"900000000"', '"valueSat":18446744073709551615');
  check(r.ok === true && r.result.totalInputSat === (18446744073709551615n + 600000000n).toString(), 'u64::MAX input value: total kept in u128', JSON.stringify(r).slice(0, 200));
  table.push(['valueSat=u64::MAX + 600000000', r.ok ? `OK change ${r.result.changeSat}` : r.error]);
  // 128 inputs of u64::MAX: no wrap, a clean refusal.
  const many = (n, value) => Array.from({ length: n }, (_, i) => `{"txidHex":"${'34'.repeat(32)}","vout":${i},"valueSat":${value}}`).join(',');
  r = h.text(`{"method":"review","args":{"recipientHex":"${base().recipientHex}","amountSat":"1000000000","inputs":[${many(128, '18446744073709551615')}],"baseFeeMillisatPerGas":"10","tipMillisatPerGas":"0"}}`);
  expect('128 inputs of u64::MAX', r, 'change overflow');
  // The largest tip the protocol admits: fee does not wrap, inputs cannot pay.
  r = rev((a) => { a.tipMillisatPerGas = '2100000000000000000'; });
  table.push(['tip=MAX_TIP?', r.ok ? 'OK' : r.error]);
  check(err(r), 'huge tip refused somehow');
  // Input bound.
  const rows = (n) => Array.from({ length: n }, (_, i) => ({ txidHex: '34'.repeat(32), vout: i, valueSat: '20000000' }));
  expect('129 inputs', rev((a) => { a.inputs = rows(129); }), 'funding bound');
  expect('0 inputs', rev((a) => { a.inputs = []; }), 'funding bound');
  expect('inputs null', rev((a) => { a.inputs = null; }), 'missing funding');
  expect('inputs object', rev((a) => { a.inputs = { 0: rows(1)[0] }; }), 'missing funding');
  expect('row not an object', rev((a) => { a.inputs = ['x']; }), 'missing args');
  expect('duplicate (1 vs "1")', rev((a) => { a.inputs = [{ txidHex: '34'.repeat(32), vout: 1, valueSat: '900000000' }, { txidHex: '34'.repeat(32), vout: '1', valueSat: '600000000' }]; }), 'duplicate input');
  const full = base(); full.inputs = rows(128);
  r = h.call('review', full);
  check(r.ok === true && r.result.inputCount === 128, '128 inputs reviewed');
  const s = h.call('sign', withId(full, r.result));
  check(s.ok === true, '128 inputs signed');
  if (s.ok) { const tx = judge('128 inputs', V1, full, r.result, s.result); note(`128-input deposit: ${tx.length} bytes encoded, ${tx.txBytes} declared, fee ${r.result.feeSat} sat`); }
  // Minimum amount with exact funding (no change).
  r = h.call('review', base());
  const fee = BigInt(r.result.feeSat);
  const exact = base(); exact.amountSat = (1500000000n - fee).toString();
  r = h.call('review', exact);
  check(r.ok === true && r.result.changeSat === '0', 'exact funding: zero change');
  const se = h.call('sign', withId(exact, r.result));
  if (se.ok) judge('zero change', V1, exact, r.result, se.result);
  const short = base(); short.amountSat = (1500000000n - fee + 1n).toString();
  expect('one satoshi short', h.call('review', short), 'inputs do not cover the amount plus fee');
  console.log('parse table:'); for (const [k, v] of table) console.log(`  ${k} -> ${v}`);
}

// ── 3. The signer's own fee ceilings (R503-1; the first pass had none) ──────
// Second pass (2026-11-20): the request that drained 14.99 BLCH into fee on
// the first artifact must now be refused in `review` and in `sign`.
{
  const h = host();
  h.call('open_mnemonic', openV1);
  const a = base(); a.amountSat = '1000000'; a.tipMillisatPerGas = '1000';
  check(err(h.call('review', a), 'tip above base fee'), 'tip 1000 at base fee 10 is refused');
  a.tipMillisatPerGas = '5217314';
  let r = h.call('review', a);
  check(err(r, 'tip above base fee'), 'R503-1 exact input (tip 5217314) is refused in review', JSON.stringify(r).slice(0, 200));
  note(`fee drain (R503-1 input): review -> ${JSON.stringify(r)}`);
  const honest = { ...a, tipMillisatPerGas: '0' };
  r = h.call('review', honest);
  check(r.ok === true && r.result.feeSat === '2874', 'the same deposit without the tip pays 2874 sat');
  check(err(h.call('sign', withId(a, r.result)), 'tip above base fee'), 'R503-1 exact input is refused in sign after an honest review');
  check(err(h.call('sign', withId(honest, r.result)), 'review required'), 'and that attempt consumed the review');
  // The most the tip rule allows: tip = base fee, the fee doubles.
  const equal = { ...honest, tipMillisatPerGas: '10' };
  r = h.call('review', equal);
  check(r.ok === true && r.result.feeSat === '5748', 'tip = base fee is the maximum: fee doubles', JSON.stringify(r).slice(0, 200));
  if (r.ok) { const s = h.call('sign', withId(equal, r.result)); check(s.ok === true, 'tip = base fee signs'); if (s.ok) judge('tip equal to base fee', V1, equal, r.result, s.result); }
  check(err(h.call('review', { ...honest, tipMillisatPerGas: '11' }), 'tip above base fee'), 'tip = base fee + 1 is refused');
  // The absolute ceiling (0.1 BLCH), whatever prices are reported.
  const under = { ...base(), baseFeeMillisatPerGas: '34805' };
  r = h.call('review', under);
  check(r.ok === true && BigInt(r.result.feeSat) <= 10000000n, 'base fee 34805 (2 inputs) is the last under the ceiling', JSON.stringify(r).slice(0, 200));
  note(`fee ceiling: 2 inputs at base fee 34805 -> feeSat ${r.ok ? r.result.feeSat : r.error}`);
  check(err(h.call('review', { ...base(), baseFeeMillisatPerGas: '34806' }), 'fee above signer ceiling'), 'base fee 34806 is refused by the ceiling');
  check(err(h.call('review', { ...base(), baseFeeMillisatPerGas: '34805', tipMillisatPerGas: '34805' }), 'fee above signer ceiling'), 'an allowed tip cannot pass the ceiling');
  const rich = base(); rich.baseFeeMillisatPerGas = '1000000'; rich.inputs[0].valueSat = '900000000000000';
  check(err(h.call('review', rich), 'fee above signer ceiling'), 'richer inputs do not lift the ceiling');
  // Random prices: nothing is ever reviewed with a fee above 0.1 BLCH or a tip above the base fee.
  let over = 0; let reviewed = 0;
  for (let k = 0; k < 400; k += 1) {
    const q = base();
    const b = 10 + randomInt(k % 2 ? 100000 : 2000000000);
    q.baseFeeMillisatPerGas = String(b);
    q.tipMillisatPerGas = String(randomInt(2) ? randomInt(b * 2) : 0);
    q.inputs[0].valueSat = '900000000000000';
    const x = h.call('review', q);
    if (x.ok) { reviewed += 1; if (BigInt(x.result.feeSat) > 10000000n || BigInt(q.tipMillisatPerGas) > BigInt(b)) over += 1; }
  }
  check(over === 0, `random prices: ${reviewed}/400 reviewed, none above the ceilings`);
  note(`random prices: ${reviewed}/400 reviewed, ${over} above the signer ceilings`);
}

// ── 4. The nw_alloc / nw_free / nw_call boundary ────────────────────────────
{
  const h = host();
  const MAX = 2 * 1024 * 1024;
  check(h.nw_alloc(0) === 0, 'alloc 0 refused');
  check(h.nw_alloc(MAX + 1) === 0, 'alloc MAX+1 refused');
  check(h.nw_alloc(0xffffffff) === 0, 'alloc u32::MAX refused');
  check(h.nw_alloc(-1) === 0, 'alloc -1 refused');
  const req = Buffer.from(JSON.stringify({ method: 'lock', args: {} }));
  const p = h.nw_alloc(req.length);
  new Uint8Array(h.memory().buffer, p, req.length).set(req);
  const reply = (packed) => { const o = Number(packed >> 32n); const l = Number(packed & 0xffffffffn); const t = Buffer.from(new Uint8Array(h.memory().buffer, o, l)).toString(); h.nw_free(o, l); return t; };
  check(reply(h.nw_call(p, req.length - 1)).includes('invalid buffer'), 'wrong length refused');
  check(reply(h.nw_call(p + 1, req.length - 1)).includes('invalid buffer'), 'interior pointer refused');
  check(reply(h.nw_call(0, 0)).includes('invalid buffer'), 'null refused');
  check(reply(h.nw_call(p, 0xffffffff)).includes('invalid buffer'), 'huge length refused');
  h.nw_free(p, req.length + 1); // wrong length: must not free
  check(reply(h.nw_call(p, req.length)).includes('"locked":true'), 'buffer survives a wrong-length free');
  h.nw_free(p, req.length);
  // The allocator may write its free-list links into the block afterwards,
  // so judge the request text, not every byte.
  check(!Buffer.from(h.memory().buffer).includes(req.subarray(8)), 'freed request buffer no longer holds the request text');
  check(reply(h.nw_call(p, req.length)).includes('invalid buffer'), 'use after free refused');
  h.nw_free(p, req.length); h.nw_free(p, req.length); h.nw_free(0, 0); h.nw_free(0xfffffff0, 16);
  // At most four live buffers.
  const live = [1, 2, 3, 4].map(() => h.nw_alloc(64));
  check(live.every((x) => x !== 0) && new Set(live).size === 4, 'four live buffers');
  check(h.nw_alloc(64) === 0, 'fifth buffer refused');
  new Uint8Array(h.memory().buffer, live[0], 64).set(Buffer.from(JSON.stringify({ method: 'lock', args: {} }).padEnd(64, ' ')));
  check(h.nw_call(live[0], 64) === 0n, 'no room for a reply: nw_call returns 0, no trap');
  live.forEach((x) => h.nw_free(x, 64));
  // Total bound: 2 * MAX across live buffers.
  const big1 = h.nw_alloc(MAX); const big2 = h.nw_alloc(MAX); const big3 = h.nw_alloc(1);
  check(big1 !== 0 && big2 !== 0 && big3 === 0, 'total live bytes bounded at 4 MiB');
  h.nw_free(big2, MAX);
  // A full-size request (valid JSON padded with spaces) is parsed.
  const padded = Buffer.alloc(MAX, 0x20); padded.set(req);
  new Uint8Array(h.memory().buffer, big1, MAX).set(padded);
  check(reply(h.nw_call(big1, MAX)).includes('"locked":true'), '2 MiB request parsed');
  // Deep nesting, invalid UTF-8, NUL bytes: refused without a trap.
  for (const [name, body] of [['deep arrays', Buffer.from('['.repeat(MAX))], ['deep objects', Buffer.from('{"a":'.repeat(100000))], ['invalid utf8', Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x3a, 0x31, 0x7d])], ['nul bytes', Buffer.alloc(4096)], ['huge string', Buffer.from(`{"method":"${'a'.repeat(MAX - 40)}","args":{}}`)]]) {
    const b = body.subarray(0, MAX);
    new Uint8Array(h.memory().buffer, big1, MAX).fill(0x20);
    new Uint8Array(h.memory().buffer, big1, b.length).set(b);
    let out; try { out = reply(h.nw_call(big1, MAX)); } catch (e) { out = `TRAP ${e.message}`; }
    check(out.includes('"ok":false'), `hostile request: ${name}`, out.slice(0, 80));
  }
  h.nw_free(big1, MAX);
  check(h.call('open_mnemonic', openV1).ok === true, 'instance still healthy after the boundary abuse');
  note(`memory after boundary abuse: ${h.memory().buffer.byteLength} bytes`);
}

// ── 5. Randomness ───────────────────────────────────────────────────────────
{
  // Zero-filled random_get: what does the scheme do?
  const out = [];
  for (let k = 0; k < 2; k += 1) {
    const h = host('zero');
    check(h.call('open_mnemonic', openV1).ok === true, 'zero rng: open');
    const r = h.call('review', base());
    const s = h.call('sign', withId(base(), r.result));
    check(s.ok === true, 'zero rng: sign');
    if (s.ok) { out.push(s.result.transactionHex); judge(`zero rng ${k}`, V1, base(), r.result, s.result); }
    note(`zero rng instance ${k}: random_get calls ${h.stats.randomCalls}, bytes ${h.stats.randomBytes}`);
  }
  note(`zero rng: two instances produced ${out[0] === out[1] ? 'IDENTICAL' : 'different'} signatures`);
  // Different message, same (zero) randomness: signatures must differ and verify.
  {
    const h = host('zero');
    h.call('open_mnemonic', openV1);
    const a = base(); a.amountSat = '1000000001';
    const r = h.call('review', a);
    const s = h.call('sign', withId(a, r.result));
    if (s.ok) judge('zero rng other message', V1, a, r.result, s.result);
  }
  if (zeroOut) writeFileSync(zeroOut, JSON.stringify(out));
  // Failing random_get: must not sign with made-up entropy.
  const h = host('fail');
  let outcome;
  try { const r = h.call('open_mnemonic', openV1); outcome = `reply ${JSON.stringify(r).slice(0, 120)}`; } catch (e) { outcome = `trap: ${e.message}`; }
  note(`failing random_get at open: ${outcome} (random_get calls ${h.stats.randomCalls})`);
  check(outcome.startsWith('trap') || outcome.includes('"ok":false'), 'failing rng never yields a session');
  let after;
  try { after = JSON.stringify(h.call('review', base())); } catch (e) { after = `trap: ${e.message}`; }
  note(`after the rng failure, review -> ${after.slice(0, 120)}`);
  check(!after.includes('"ok":true'), 'no review after an rng failure');
  // OS rng: how much entropy does one open + sign draw?
  const g = host('os');
  g.call('open_mnemonic', openV1);
  const before = { ...g.stats };
  const r = g.call('review', base());
  const s1 = g.call('sign', withId(base(), r.result));
  const r2 = g.call('review', base());
  const s2 = g.call('sign', withId(base(), r2.result));
  check(s1.ok && s2.ok && s1.result.transactionHex !== s2.result.transactionHex && s1.result.txid === s2.result.txid, 'os rng: two signatures of one deposit differ, one txid');
  note(`os rng: open drew ${before.randomCalls} calls / ${before.randomBytes} bytes; two signs drew ${g.stats.randomCalls - before.randomCalls} calls / ${g.stats.randomBytes - before.randomBytes} bytes`);
}

// ── 6. Secret residue in linear memory after lock ───────────────────────────
function scan(memory, needles) {
  const hay = Buffer.from(memory.buffer);
  return needles.map((needle) => { let n = 0; let at = hay.indexOf(needle); while (at !== -1) { n += 1; at = hay.indexOf(needle, at + 1); } return n; });
}
{
  // Suite envelope (4) | ML-DSA-65 secret key (4032) | Falcon-1024 secret key.
  // The first 32 bytes of the ML-DSA secret key are `rho`, which is public
  // (it also opens the public key), so the scan starts after it.
  const sk = unhex(keys.v1.secretKeyHex);
  const MLDSA_END = 4 + 4032;
  const STEP = 16;
  const offsets = []; for (let o = 4 + 32; o + STEP <= sk.length; o += STEP) offsets.push(o);
  const seed = unhex(keys.v1.seedHex);
  const ranges = (present) => { const out = []; let start = null; let last = null; for (const o of present) { if (start === null) { start = o; } else if (o !== last + STEP) { out.push(`${start}..${last + STEP}`); start = o; } last = o; } if (start !== null) out.push(`${start}..${last + STEP}`); return out; };
  const report = (label, memory) => {
    const counts = scan(memory, offsets.map((o) => sk.subarray(o, o + STEP)));
    const present = offsets.filter((_, i) => counts[i] > 0);
    const mldsa = present.filter((o) => o < MLDSA_END).length * STEP;
    const falcon = present.filter((o) => o >= MLDSA_END).length * STEP;
    const [hexHits] = scan(memory, [Buffer.from(keys.v1.secretKeyHex.slice(200, 264), 'ascii')]);
    const [p1, p2] = scan(memory, [Buffer.from('abandon abandon'), Buffer.from('abandon about')]);
    const [seed32, seedTail] = scan(memory, [seed.subarray(0, 32), seed.subarray(seed.length - 16)]);
    note(`${label}: secret-key bytes found ${present.length * STEP}/${offsets.length * STEP} (ML-DSA part ${mldsa}/${MLDSA_END - 36}, Falcon part ${falcon}/${sk.length - MLDSA_END}; max copies ${Math.max(0, ...counts)}); ranges ${ranges(present).slice(0, 8).join(', ') || 'none'}; secret hex text ${hexHits}; mnemonic text ${p1 + p2}; seed[0..32] ${seed32}, seed tail ${seedTail}`);
    return { bytes: present.length * STEP, hex: hexHits, phrase: p1 + p2, seed: seed32 + seedTail };
  };
  const results = {};
  // Keypair path.
  let h = host();
  h.call('open_keypair', { domainHex: DOMAIN, publicKeyHex: V1, secretKeyHex: keys.v1.secretKeyHex });
  const live = report('keypair session OPEN (scanner sanity)', h.memory());
  check(live.bytes > 0, 'scanner finds the live secret while the session is open');
  h.call('lock', {});
  results.keypairOpenLock = report('keypair: open + LOCK (no signature)', h.memory());
  h = host();
  h.call('open_keypair', { domainHex: DOMAIN, publicKeyHex: V1, secretKeyHex: keys.v1.secretKeyHex });
  let r = h.call('review', base()); h.call('sign', withId(base(), r.result));
  h.call('lock', {});
  results.keypairSignLock = report('keypair: open + sign + LOCK', h.memory());
  // Mnemonic path.
  h = host();
  h.call('open_mnemonic', openV1);
  h.call('lock', {});
  results.mnemonicOpenLock = report('mnemonic: open + LOCK (no signature)', h.memory());
  h = host();
  h.call('open_mnemonic', openV1);
  r = h.call('review', base()); h.call('sign', withId(base(), r.result));
  h.call('lock', {});
  results.mnemonicSignLock = report('mnemonic: open + sign + LOCK', h.memory());
  // Failed opens with a real phrase / key: no session is ever created.
  h = host();
  h.call('open_mnemonic', { ...openV1, publicKeyHex: V2.slice(0, 200) + (V2[200] === '0' ? '1' : '0') + V2.slice(201) });
  results.failedMnemonic = report('mnemonic: FAILED open (wrong expected key)', h.memory());
  h = host();
  h.call('open_keypair', { domainHex: DOMAIN, publicKeyHex: V2, secretKeyHex: keys.v1.secretKeyHex });
  results.failedKeypair = report('keypair: FAILED open (account mismatch)', h.memory());
  h = host();
  h.call('open_mnemonic', { ...openV1, domainHex: '00' + DOMAIN.slice(2) });
  results.wrongNetwork = report('mnemonic: refused open (wrong network)', h.memory());
  note(`residue summary ${JSON.stringify(results)}`);
  // Second pass (R503-2): the signer now wipes freed heap, scrubs the stack
  // after every call and overwrites the seeded RNG slot. Nothing the scanner
  // looks for (16-byte windows of the secret key, the key seed, the seed
  // tail, the secret as hex text, the phrase) may remain after lock or after
  // a refused open.
  for (const [name, found] of Object.entries(results)) {
    check(found.bytes === 0 && found.hex === 0 && found.phrase === 0 && found.seed === 0, `no secret residue: ${name}`, JSON.stringify(found));
  }
}

if (signedOut) writeFileSync(signedOut, JSON.stringify(released));
console.log(`wasm sha256 ${createHash('sha256').update(wasmBytes).digest('hex')} (${wasmBytes.length} bytes)`);
console.log(`released transactions judged in JS: ${released.length}`);
console.log(`checks passed ${passed}, failed ${failed}`);
process.exit(failed ? 1 : 0);
