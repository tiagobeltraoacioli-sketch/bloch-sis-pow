// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The live rig. Not part of `node --test`: it needs a network and a lab node,
// so it is run by hand and its output is the evidence.
//
//   node edge/tests/live-lab.mjs stale     against a deliberately stale node
//   node edge/tests/live-lab.mjs load      with/without, counted, on the lab node
//   node edge/tests/live-lab.mjs limit     driven past both rate limits
//   node edge/tests/live-lab.mjs live      a handful of calls at the real chain
//
// The lab node is an ISOLATED keyless observer on an idle Edgevana box, booted
// from the real Genesis-4 genesis manifest and the real 452,726-output
// carryover, with `--peers 127.0.0.1:1` so it can never reach the fleet. It is
// therefore two useful things at once: a load target that cannot cost the
// chain anything, and a node that is permanently, honestly stale.
//
// Reach it with:
//   ssh -f -N -i ~/.ssh/edgevana_node3 -L 17952:127.0.0.1:17952 ubuntu@<box>

import { handleRead } from '../core.js';
import { counters, _resetGovernorForTests } from '../governor.js';
import { _resetLineageForTests, witnessView } from '../lineage.js';
import { _resetPoolForTests } from '../pool.js';
import { _resetCoreForTests } from '../core.js';
import { DEFAULT_ARCHIVALS, DEFAULT_FLEET } from '../pool.js';

const LAB = process.env.LAB_RPC || 'http://127.0.0.1:17952/';

function reset() {
  _resetPoolForTests();
  _resetLineageForTests();
  _resetGovernorForTests();
  _resetCoreForTests();
}

/** A counting fetch, so the number of upstream calls is a measurement. */
function countingFetch() {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, method: JSON.parse(init.body).method, at: Date.now() });
    return fetch(url, init);
  };
  f.calls = calls;
  f.to = (u) => calls.filter((c) => c.url === u).length;
  return f;
}

/** A cache backed by a Map, standing in for `caches.default`. */
function memCache() {
  const store = new Map();
  return {
    size: () => store.size,
    async match(req) {
      const hit = store.get(req.url);
      return hit ? new Response(hit.body, { headers: hit.headers }) : undefined;
    },
    async put(req, res) {
      const headers = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      store.set(req.url, { body: await res.text(), headers });
    },
  };
}

const opts = (f, cache, pools, clientKey = 'lab') => ({
  pools,
  fetchImpl: f,
  cache,
  waitUntil: null,
  now: () => Date.now(),
  clientKey,
  budgetMs: 20_000,
});

const call = (m, p = []) => ({ jsonrpc: '2.0', id: 1, method: m, params: p });

function hr(title) {
  console.log('\n' + '═'.repeat(74) + '\n' + title + '\n' + '═'.repeat(74));
}

// ─── A: the deliberately stale node ─────────────────────────────────────────

async function stale() {
  hr('A. POINTED AT A DELIBERATELY STALE NODE');
  reset();
  const f = countingFetch();
  const pools = { archivals: [LAB], fleet: DEFAULT_FLEET };

  const raw = await fetch(LAB, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(call('getchaininfo')),
  }).then((r) => r.json());
  console.log(
    `The lab node itself answers, instantly and consistently:\n` +
      `  height ${raw.result.height}  slot ${raw.result.slot}  ` +
      `wall_slot ${raw.result.wall_slot}  behind_by_slots ${raw.result.behind_by_slots}\n` +
      `  (${((raw.result.behind_by_slots * 30) / 86400).toFixed(1)} days behind the chain)\n`,
  );

  for (const [m, p] of [
    ['getchaininfo', []],
    ['getbalance', ['00'.repeat(32)]],
    ['getblockbyslot', [0]],
  ]) {
    const out = await handleRead(call(m, p), opts(f, memCache(), pools));
    if (out.body.error) {
      console.log(`  ${m.padEnd(16)} REFUSED  code ${out.body.error.code}  reason ${out.body.error.data.reason}`);
      console.log(`  ${''.padEnd(16)}          behind_by_slots ${out.body.error.data.behind_by_slots}`);
    } else {
      console.log(
        `  ${m.padEnd(16)} SERVED   level ${out.corroboration.level}` +
          (out.corroboration.missing ? `  missing: ${out.corroboration.missing.join('; ')}` : ''),
      );
    }
  }
  const w = witnessView(Date.now());
  console.log(`\n  fleet witness: available=${w.available} height=${w.height} age=${w.age_ms}ms`);
}

// ─── B: the load, with and without ──────────────────────────────────────────

async function load() {
  hr('B. THE LOAD A REALISTIC EXPLORER SESSION PUTS ON THE NODES');
  const pools = { archivals: [LAB], fleet: [] }; // no fleet: this is a load count, not a chain read

  // WITHOUT the layer: exactly what `src/lib/g4.ts` issues today.
  //   G4Dashboard tick  = getchaininfo + getvalidatorcount + getmempoolinfo + 12 slots
  //   Validators page   = getvalidatorcount + 64 getvalidator
  //   Blocks page       = 25 slots
  const t0 = Date.now();
  let raw = 0;
  const direct = async (m, p = []) => {
    raw += 1;
    await fetch(LAB, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(call(m, p)),
    }).then((r) => r.text());
  };
  const TABS = 10;
  const TICKS = 8; // two minutes of a page left open, at the 15 s poll
  for (let tab = 0; tab < TABS; tab++) {
    for (let t = 0; t < TICKS; t++) {
      await direct('getchaininfo');
      await direct('getvalidatorcount');
      await direct('getmempoolinfo');
      for (let s = 0; s < 12; s++) await direct('getblockbyslot', [54_000 + s]);
    }
  }
  for (let v = 0; v < 64; v++) await direct('getvalidator', [v]);
  const rawMs = Date.now() - t0;

  // WITH the layer: the same user actions, same order, one shared cache.
  reset();
  const f = countingFetch();
  const cache = memCache();
  const t1 = Date.now();
  for (let tab = 0; tab < TABS; tab++) {
    for (let t = 0; t < TICKS; t++) {
      const o = opts(f, cache, pools, `tab-${tab}`);
      await handleRead(call('getchaininfo'), o);
      await handleRead(call('getvalidatorcount'), o);
      await handleRead(call('getmempoolinfo'), o);
      for (let s = 0; s < 12; s++) await handleRead(call('getblockbyslot', [54_000 + s]), o);
    }
  }
  const ov = opts(f, cache, pools, 'validators-page');
  for (let v = 0; v < 64; v++) await handleRead(call('getvalidator', [v]), ov);
  const layerMs = Date.now() - t1;

  console.log(`  ${TABS} tabs x ${TICKS} dashboard ticks, plus one validators page visit\n`);
  console.log(`  WITHOUT the layer : ${String(raw).padStart(5)} upstream calls   ${rawMs} ms`);
  console.log(`  WITH the layer    : ${String(f.calls.length).padStart(5)} upstream calls   ${layerMs} ms`);
  console.log(`  reduction         : ${(raw / Math.max(1, f.calls.length)).toFixed(1)}x`);
  console.log(
    `\n  cache: ${counters.cacheHits} hits / ${counters.cacheMisses} misses, ` +
      `${counters.coalesced} coalesced, ${counters.archivalRefused} refused by the governor`,
  );
  const byMethod = {};
  for (const c of f.calls) byMethod[c.method] = (byMethod[c.method] || 0) + 1;
  console.log(`  upstream calls by method: ${JSON.stringify(byMethod)}`);
}

// ─── C: past the limits ─────────────────────────────────────────────────────

async function limit() {
  hr('C. DRIVEN PAST BOTH LIMITS');
  reset();
  const f = countingFetch();
  const cache = memCache();
  const pools = { archivals: [LAB], fleet: [] };

  console.log('  One client, 60 identical calls (all cache hits after the first):');
  let firstThrottle = null;
  for (let i = 0; i < 60; i++) {
    const out = await handleRead(call('getblockbyslot', [0]), opts(f, cache, pools, 'one-client'));
    if (out.status === 429 && !firstThrottle) {
      firstThrottle = { i, out };
      break;
    }
  }
  if (firstThrottle) {
    const e = firstThrottle.out.body.error;
    console.log(`    throttled on request #${firstThrottle.i + 1}`);
    console.log(`    code ${e.code}  reason ${e.data.reason}  retry_after_ms ${e.data.retry_after_ms}`);
    console.log(`    HTTP status the caller sees: ${firstThrottle.out.status}, Retry-After: ${Math.ceil(firstThrottle.out.retryAfterMs / 1000)}s`);
    console.log(`    message: ${e.message.slice(0, 150)}…`);
  } else {
    console.log('    NOT THROTTLED — the client limiter is not doing its job');
  }

  console.log('\n  Many clients, all-distinct slots, so only the UPSTREAM governor can stop it:');
  reset();
  const f2 = countingFetch();
  const cache2 = memCache();
  let budgetErr = null;
  let served = 0;
  for (let i = 0; i < 200; i++) {
    const out = await handleRead(
      call('getblockbyslot', [1_000 + i]),
      opts(f2, cache2, pools, `client-${i}`),
    );
    if (out.body.error && out.body.error.code === -32030) {
      budgetErr = out;
      break;
    }
    if (!out.body.error) served += 1;
  }
  console.log(
    `    ${served} served, ${f2.calls.length} upstream calls made ` +
      `(the lab node is deliberately stale, so a "served" answer here would be a bug)`,
  );
  if (budgetErr) {
    const e = budgetErr.body.error;
    console.log(`    code ${e.code}  reason ${e.data.reason}  retry_after_ms ${e.data.retry_after_ms}`);
    console.log(`    upstream_calls_per_second advertised: ${e.data.upstream_calls_per_second}`);
    console.log(`    message: ${e.message.slice(0, 160)}…`);
  } else {
    console.log('    the upstream ceiling was never reached in 200 requests');
  }

  console.log('\n  A thousand requests at once, from a thousand addresses:');
  reset();
  const f3 = countingFetch();
  const cache3 = memCache();
  const t = Date.now();
  const outs = await Promise.all(
    Array.from({ length: 1000 }, (_, i) =>
      handleRead(call('getblockbyslot', [5_000 + i]), opts(f3, cache3, pools, `c${i}`)),
    ),
  );
  // Break the outcomes down rather than counting "no error" as success. The
  // lab node is 19 days stale on purpose, so every request the governor DID let
  // through comes back as a -32011 stale refusal — which is the layer working,
  // not failing, and lumping it in with the throttles would hide both.
  const by = {};
  for (const o of outs) {
    // A node error passes through verbatim and carries no `data` — the node's
    // own errors are not this layer's errors and are not reshaped.
    const e = o.body.error;
    const k = e ? `refused ${(e.data && e.data.reason) || `node ${e.code}`}` : 'served';
    by[k] = (by[k] || 0) + 1;
  }
  console.log(`    outcomes: ${JSON.stringify(by)}`);
  console.log(
    `    ${f3.calls.length} upstream calls for 1000 requests in ${Date.now() - t} ms`,
  );
  console.log(
    `    the node saw ${((f3.calls.length / 1000) * 100).toFixed(1)}% of the request rate; ` +
      `a passthrough would have shown it 100%`,
  );
}

// ─── D: against the real chain, gently ──────────────────────────────────────

async function live() {
  hr('D. AGAINST THE LIVE CHAIN (a handful of calls, read only)');
  reset();
  const f = countingFetch();
  const cache = memCache();
  const pools = { archivals: DEFAULT_ARCHIVALS, fleet: DEFAULT_FLEET };

  for (const [m, p] of [
    ['getchaininfo', []],
    ['getblockcount', []],
    ['getvalidatorcount', []],
    ['getmempoolinfo', []],
    ['getcapabilities', []],
  ]) {
    const o = opts(f, cache, pools, 'live-probe');
    const out = await handleRead(call(m, p), o);
    const c = out.corroboration || {};
    console.log(
      `  ${m.padEnd(18)} ${out.body.error ? 'ERROR ' + out.body.error.data.reason : 'ok'}  ` +
        `level=${c.level}  witnesses=${c.archival_witnesses ?? '-'}/${c.of ?? '-'}  ` +
        `fleet_witness=${c.fleet_witness ?? '-'}  cache=${out.cacheState}`,
    );
    if (c.missing) console.log(`  ${''.padEnd(18)} missing: ${c.missing.join('; ')}`);
  }
  const head = await handleRead(call('getchaininfo'), opts(f, cache, pools, 'live-probe-2'));
  console.log(`\n  head: height ${head.body.result.height} slot ${head.body.result.slot} ` +
    `finalized_height ${head.body.result.finalized_height} (second call: ${head.cacheState})`);
  console.log(`  total upstream calls for six requests: ${f.calls.length}`);
  console.log(`    archival: ${f.calls.filter((c) => DEFAULT_ARCHIVALS.includes(c.url)).length}`);
  console.log(`    fleet   : ${f.calls.filter((c) => DEFAULT_FLEET.includes(c.url)).length}`);
}

const mode = process.argv[2] || 'stale';
const run = { stale, load, limit, live };
if (!run[mode]) {
  console.error(`usage: node live-lab.mjs [${Object.keys(run).join('|')}]`);
  process.exit(2);
}
await run[mode]();
