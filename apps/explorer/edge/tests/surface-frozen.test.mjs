// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The edge namespace, frozen in both directions, against the node's own source.
//
// ═══════════════════════════════════════════════════════════════════════════
// WHY THIS TEST EXISTS
// ═══════════════════════════════════════════════════════════════════════════
//
// `functions/rpc.js` shipped a Genesis-3 allowlist — `gethashrate`,
// `getsupplydistribution`, `getdifficultyhistory` — for three weeks after
// Genesis-3 stopped at height 39,918 and Genesis-4 replaced it. The file's own
// comment said so ("NOTE (Genesis-4): the allowlist below is the Genesis-3
// surface … at the V4 relaunch it must be rebuilt"). A comment noticed; nothing
// failed.
//
// The node solved the same problem for Rust callers with
// `the_rpc_method_namespace_is_frozen`, which reads its own dispatcher's source
// and asserts a written-out golden list in both directions. This is that test,
// extended across the language boundary, and it is the reason the edge cannot
// drift again:
//
//   → every method the EDGE exposes must exist in the node's RPC_SURFACE;
//   → every method the NODE serves must be either exposed by the edge or
//     listed in EDGE_ABSENT with a written reason;
//   → the edge's own list is a golden list, written out, so changing the public
//     surface of a public endpoint is a diff a reviewer has to approve.
//
// It reads `crates/bloch-pos-node/src/rpc.rs` directly. Not a copy, not a
// generated JSON: a copy is a second thing to keep in sync, which is the defect.

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { EDGE_SURFACE, EDGE_ABSENT, edgeMethodNames, methodSpec, CacheClass, Cost } from '../surface.js';

const here = dirname(fileURLToPath(import.meta.url));
const RPC_RS = resolve(here, '../../../../crates/bloch-pos-node/src/rpc.rs');
const SOURCE = readFileSync(RPC_RS, 'utf8');

/** Names out of `pub const RPC_SURFACE: &[Method] = &[ … ]`. */
function nodeSurfaceNames() {
  const start = SOURCE.indexOf('pub const RPC_SURFACE: &[Method] = &[');
  assert.notEqual(start, -1, 'RPC_SURFACE must exist in rpc.rs — has the table moved or been renamed?');
  const end = SOURCE.indexOf('\n];', start);
  assert.notEqual(end, -1, 'RPC_SURFACE must close at `\\n];`');
  const body = SOURCE.slice(start, end);
  return [...body.matchAll(/name:\s*"([a-z_]+)"/g)].map((m) => m[1]);
}

/**
 * Names the dispatcher actually accepts, read out of `pub fn route`.
 *
 * Deliberately the same extraction the Rust test does, including collecting
 * every literal left of `=>` so an aliased arm (`"getutxos" | "listunspent"`)
 * contributes both names. If the Rust extractor and this one disagree about
 * what the dispatcher says, one of them is wrong and the divergence is the
 * finding.
 */
function dispatchArmNames() {
  const afterFn = SOURCE.split('pub fn route(')[1];
  assert.ok(afterFn, 'route() must exist');
  const body = afterFn.split('Ok(match method {')[1];
  assert.ok(body, 'route() must dispatch with `Ok(match method {`');
  const end = body.indexOf('\n    })\n}');
  assert.notEqual(end, -1, "route()'s match must close at `    })`");

  const names = [];
  for (const line of body.slice(0, end).split('\n')) {
    if (!line.startsWith('        ')) continue;
    const rest = line.slice(8);
    if (!rest.startsWith('"')) continue;
    const head = rest.includes('=>') ? rest.slice(0, rest.indexOf('=>')) : rest;
    for (const m of head.matchAll(/"([^"]*)"/g)) names.push(m[1]);
  }
  return names;
}

test('the edge method namespace is frozen', () => {
  // The golden list, written out. NOT derived from EDGE_SURFACE — deriving it
  // would make an accidental edit invisible, which is the whole point of a
  // golden list. Changing the public surface of a public endpoint is a diff
  // somebody has to approve.
  const golden = [
    'getbalance',
    'getblockbyid',
    'getblockbyslot',
    'getblockcount',
    'getcapabilities',
    'getchaininfo',
    'getmempoolinfo',
    'getstakedistribution',
    'getsupply',
    'gettxout',
    'getutxos',
    'getvalidator',
    'getvalidatorcount',
    'getvalidators',
    'listunspent',
  ];

  assert.deepEqual(
    edgeMethodNames(),
    golden,
    'EDGE_SURFACE changed. This is a PUBLIC endpoint: adding or removing a method ' +
      'here changes what posternlabs.com and blochprotocol.io promise callers. ' +
      'Update the golden list in the same commit.',
  );

  const sorted = [...golden].sort();
  assert.deepEqual(sorted, golden, 'the golden list must be sorted');
  assert.equal(new Set(golden).size, golden.length, 'the golden list must be free of duplicates');
});

test('every edge method exists in the node RPC_SURFACE', () => {
  const nodeNames = new Set(nodeSurfaceNames());
  assert.ok(nodeNames.size >= 10, `RPC_SURFACE parse found only ${nodeNames.size} names — the extractor has stopped seeing the table`);
  for (const name of edgeMethodNames()) {
    assert.ok(
      nodeNames.has(name),
      `the edge exposes '${name}' and the node does not serve it. This is the ` +
        `Genesis-3 defect exactly: an allowlist naming methods that answer -32601. ` +
        `Either wire it into the node or drop it from EDGE_SURFACE.`,
    );
  }
});

test('every edge method is actually dispatched by the node', () => {
  // RPC_SURFACE being right is not enough — the node's own test proves the
  // table and the dispatcher agree, but this edge is built against the
  // DISPATCHER, and reading it directly means this test still fails correctly
  // if the node's own freeze is ever weakened.
  const arms = new Set(dispatchArmNames());
  assert.ok(arms.size >= 10, `the arm extractor found only ${arms.size} names: ${[...arms]}`);
  for (const name of edgeMethodNames()) {
    if (name === 'getcapabilities') continue; // answered at the edge; see below
    assert.ok(arms.has(name), `'${name}' is exposed by the edge and not dispatched by route()`);
  }
});

test('every node method is either exposed or absent for a written reason', () => {
  const exposed = new Set(edgeMethodNames());
  const absent = new Map(EDGE_ABSENT);
  for (const name of nodeSurfaceNames()) {
    if (exposed.has(name)) continue;
    assert.ok(
      absent.has(name),
      `the node serves '${name}' and the edge neither exposes it nor says why not. ` +
        `Silence is how an allowlist becomes a list nobody can review: add it to ` +
        `EDGE_SURFACE, or to EDGE_ABSENT with the reason.`,
    );
    assert.ok(
      absent.get(name).length > 40,
      `'${name}' is in EDGE_ABSENT with a reason too short to be one`,
    );
  }
});

test('nothing in EDGE_ABSENT is also exposed', () => {
  const exposed = new Set(edgeMethodNames());
  for (const [name] of EDGE_ABSENT) {
    assert.ok(!exposed.has(name), `'${name}' is both exposed and documented as absent`);
  }
});

test('the write method is absent, and stays absent', () => {
  // Pinned separately from the loop above because it is the one exclusion that
  // is a security property rather than a tidiness one. An explorer that can
  // broadcast is an explorer that can lose a transaction behind a cache.
  const absent = new Map(EDGE_ABSENT);
  assert.ok(absent.has('sendrawtransaction'), 'the explorer edge must not expose a write method');
  assert.equal(methodSpec('sendrawtransaction'), null);
});

test('every exposed method declares a cache class, a cost and a corroboration level', () => {
  const classes = new Set(Object.values(CacheClass));
  const costs = new Set(Object.values(Cost));
  for (const m of EDGE_SURFACE) {
    assert.ok(classes.has(m.cacheClass), `${m.name}: unknown cache class ${m.cacheClass}`);
    assert.ok(costs.has(m.cost), `${m.name}: unknown cost ${m.cost}`);
    assert.ok(
      ['quorum', 'lineage', 'none', 'edge', 'pinned'].includes(m.corroboration),
      `${m.name}: unknown corroboration level ${m.corroboration}`,
    );
    assert.ok(Number.isFinite(m.ttlMs) && m.ttlMs > 0, `${m.name}: needs a positive ttlMs`);
    assert.ok(m.summary && m.summary.length > 20, `${m.name}: needs a real summary`);
  }
});

test('the two full-set walks are priced as walks', () => {
  // `balance_json` and `utxos_json` in rpc.rs are a linear pass over the whole
  // committed output set on the consensus thread. If either is ever classed
  // Cheap, the governor stops protecting the thing it exists to protect.
  for (const name of ['getbalance', 'getutxos', 'listunspent']) {
    assert.equal(methodSpec(name).cost, Cost.Walk, `${name} must be priced as a full-set walk`);
  }
  assert.equal(methodSpec('getblockcount').cost, Cost.Cheap);
});

test('the node source still says its RPC has no authentication', () => {
  // The single fact this whole layer is built on. If the node ever grows auth
  // or a rate limit, this test failing is the prompt to revisit the design
  // rather than to keep a workaround that has stopped being necessary.
  assert.ok(
    SOURCE.includes('## Authentication: there is none'),
    'rpc.rs no longer declares that it has no authentication — re-read the design ' +
      'assumptions in edge/pool.js and edge/governor.js before adjusting this test',
  );
  assert.ok(
    SOURCE.includes('No API key, no rate limit, no per-method authorisation'),
    'the no-rate-limit statement has moved or changed',
  );
});

test('the node still serves RPC from the consensus thread', () => {
  assert.ok(
    SOURCE.includes('The engine services RPC between slot duties'),
    'the RPC/consensus coupling statement has moved; the governor rates are chosen ' +
      'against it and should be rechecked',
  );
});

test('mempool is declared node-local, matching the node own words', () => {
  assert.equal(methodSpec('getmempoolinfo').cacheClass, CacheClass.NodeLocal);
  assert.equal(methodSpec('getmempoolinfo').corroboration, 'none');
  assert.ok(
    SOURCE.includes('node-local, not consensus'),
    "rpc.rs no longer calls getmempoolinfo node-local; the edge's `node_local` " +
      'corroboration level is derived from that claim',
  );
});
