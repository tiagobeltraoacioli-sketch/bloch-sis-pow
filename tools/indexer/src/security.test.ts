// SPDX-License-Identifier: MIT OR Apache-2.0
// node:test regression suite for the T-1/T-2/T-7/T-8 audit findings.
//
// Run: `tsc && node --test dist/security.test.js` (see package.json "test:node").
// Separate from `selftest.ts` (the existing hand-rolled offline scenario
// runner) — this file uses the standard `node:test` runner per the audit's
// own instruction, and is scoped to these specific regressions rather than
// the full reorg scenario `selftest.ts` already covers.

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { JsonStore } from "./store.js";
import { createReadApi } from "./api.js";
import type { IndexerConfig } from "./config.js";
import type { Tx } from "./rpc.js";
import { parseJsonExactIntegers, assertJsonSourceAccessAvailable } from "./sats.js";

function idAddress(spk: string): string {
  // Identity "address encoder" for tests that don't care about the real
  // bloch1... checksum scheme — mirrors selftest.ts's own convention.
  return `addr:${spk}`;
}

function tmpFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "bloch-indexer-test-"));
  return join(dir, "state.json");
}

function coinbaseTx(txid: string, outSpk: string, value: bigint): Tx {
  return {
    txid,
    coinbase: true,
    inputs: [],
    outputs: [{ index: 0, script_pubkey: outSpk, value }],
  };
}

// ── T-1: prototype-pollution-shaped addresses ──────────────────────────────

test("T-1: __proto__ and friends never resolve to an inherited property", () => {
  const store = JsonStore.ephemeral(idAddress);
  store.applyBlock(1, "h1", [coinbaseTx("t1", "spk-real-address", 100n)]);

  for (const poison of ["__proto__", "constructor", "toString", "valueOf", "hasOwnProperty"]) {
    // Before the fix: `store.state.history[poison] ?? []` resolved to the
    // inherited `Object.prototype` member (a function), which is NOT
    // nullish, so `?? []` never fired and callers got a function where an
    // array was expected.
    const history = store.getHistory(poison);
    assert.ok(Array.isArray(history), `getHistory(${poison}) must return an array, got ${typeof history}`);
    assert.equal(history.length, 0);

    const balance = store.getBalance(poison);
    assert.equal(typeof balance, "bigint", `getBalance(${poison}) must return a bigint, got ${typeof balance}`);
    assert.equal(balance, 0n);

    const utxos = store.getUtxosForAddress(poison);
    assert.ok(Array.isArray(utxos));
    assert.equal(utxos.length, 0);
  }

  // A real address is unaffected by any of the above.
  assert.equal(store.getBalance("addr:spk-real-address"), 100n);
});

test("T-1: GET /address/__proto__/history over the real HTTP API does not crash the process and returns a clean response", async () => {
  const store = JsonStore.ephemeral(idAddress);
  const cfg = { network: "testnet" } as IndexerConfig;
  const server = createReadApi(cfg, store);

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("expected an AddressInfo");
  const base = `http://127.0.0.1:${addr.port}`;

  try {
    // This is the exact PoC path from the finding. Before the fix: an
    // uncaught TypeError ("h.map is not a function") inside the
    // `createServer` callback — an uncaught exception in a Node http
    // handler terminates the process by default.
    const res = await fetch(`${base}/address/__proto__/history`);
    // Either outcome is acceptable PROVIDED IT IS A CLEAN HTTP RESPONSE:
    // parseAddress(:400) rejects "__proto__" outright since it fails the
    // bloch1.../bloch1t... prefix check, which is what actually fires here.
    assert.ok(res.status === 400 || res.status === 200, `unexpected status ${res.status}`);
    const body = (await res.json()) as Record<string, unknown>;
    assert.ok(body !== null && typeof body === "object");

    // The server must still be alive and answering ordinary requests —
    // the real regression check: the process did not exit.
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
  } finally {
    server.close();
  }
});

test("T-1: /address/constructor/balance also rejects cleanly (not just __proto__)", async () => {
  const store = JsonStore.ephemeral(idAddress);
  const cfg = { network: "testnet" } as IndexerConfig;
  const server = createReadApi(cfg, store);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("expected an AddressInfo");
  try {
    const res = await fetch(`http://127.0.0.1:${addr.port}/address/constructor/balance`);
    assert.equal(res.status, 400);
    const body = (await res.json()) as { balanceSats?: unknown };
    // Before the fix this could read back the STRINGIFIED native function
    // (`Object.prototype.constructor`) as "balanceSats" — never a function,
    // stringified or otherwise, must appear here.
    assert.equal(body.balanceSats, undefined);
  } finally {
    server.close();
  }
});

// ── T-2: applyBlock atomicity ───────────────────────────────────────────────

test("T-2: a non-P2PKH-shaped output does not abort the block or corrupt the store", () => {
  const store = JsonStore.ephemeral(idAddress);
  // Two outputs: one ordinary, one that the (real) address encoder would
  // reject — simulated here via idAddress accepting anything, so instead we
  // exercise the actual failure path with a throwing encoder passed
  // directly to a second, dedicated store.
  const throwing = (spk: string): string => {
    if (spk === "bad-spk") throw new Error("hash must be 20 bytes, got 7");
    return idAddress(spk);
  };
  const store2 = JsonStore.ephemeral(throwing);

  const tx: Tx = {
    txid: "tx1",
    coinbase: true,
    inputs: [],
    outputs: [
      { index: 0, script_pubkey: "good-spk", value: 100n },
      { index: 1, script_pubkey: "bad-spk", value: 50n }, // triggers the throwing encoder
    ],
  };

  // Before the fix: this would throw mid-application, leaving spent UTXOs
  // deleted / balances bumped for output 0 but NEVER setting
  // chain[height]/undo[height] — so the block was neither committed nor
  // rollback-able, and a naive retry would re-apply from scratch, DOUBLE
  // crediting output 0 forever.
  assert.doesNotThrow(() => store2.applyBlock(1, "hash1", [tx]));

  // The block is FULLY committed in one shot — chain + undo both present.
  assert.equal(store2.getChainHashAt(1), "hash1");
  assert.equal(store2.getTip()?.height, 1);

  // Both outputs are indexed — the "bad" one under a synthetic address
  // rather than being dropped or aborting the block.
  assert.equal(store2.getBalance(idAddress("good-spk")), 100n);
  assert.equal(store2.getBalance("unknown:bad-spk"), 50n);

  // Re-applying the same height is refused outright (the existing guard),
  // which is what actually prevents the double-credit now that the block
  // commits atomically: there is no "partially applied, retry from
  // scratch" state left behind for a poller to stumble into.
  assert.throws(() => store2.applyBlock(1, "hash1", [tx]), /already indexed/);
  assert.equal(store2.getBalance(idAddress("good-spk")), 100n, "must not have doubled");
});

test("T-2: rollback of a block containing a synthetic-address output is exact", () => {
  const throwing = (spk: string): string => {
    if (spk === "bad-spk") throw new Error("bad shape");
    return idAddress(spk);
  };
  const store = JsonStore.ephemeral(throwing);
  store.applyBlock(1, "h1", [coinbaseTx("t1", "good-spk", 10n)]);
  store.applyBlock(2, "h2", [
    {
      txid: "t2",
      coinbase: true,
      inputs: [],
      outputs: [{ index: 0, script_pubkey: "bad-spk", value: 25n }],
    },
  ]);
  assert.equal(store.getBalance("unknown:bad-spk"), 25n);

  store.rollbackTo(1);
  assert.equal(store.getBalance("unknown:bad-spk"), 0n, "rollback must exactly reverse the synthetic-address credit");
  assert.equal(store.getUtxosForAddress("unknown:bad-spk").length, 0);
});

// ── T-7: atomic persist + indexOk ───────────────────────────────────────────

test("T-7: a corrupt state file is reported via indexOk(), not silently presented as healthy", () => {
  const file = tmpFile();
  writeFileSync(file, "{ not valid json ]]]");
  const store = JsonStore.open(file, idAddress);
  assert.equal(store.indexOk(), false);
  rmSync(file, { force: true });
});

test("T-7: a fresh (never-written) path is a healthy empty index, not a degraded one", () => {
  const file = tmpFile();
  const store = JsonStore.open(file, idAddress);
  assert.equal(store.indexOk(), true);
});

test("T-7: persist() writes via a temp file + rename, leaving no partial file behind", () => {
  const file = tmpFile();
  const store = JsonStore.open(file, idAddress);
  store.applyBlock(1, "h1", [coinbaseTx("t1", "spk", 42n)]);
  store.persist();

  // No leftover .tmp file after a successful persist — the rename replaced
  // the live path in one atomic step.
  assert.equal(existsSync(`${file}.tmp`), false);
  assert.equal(existsSync(file), true);

  const reloaded = JsonStore.open(file, idAddress);
  assert.equal(reloaded.indexOk(), true);
  assert.equal(reloaded.getBalance(idAddress("spk")), 42n);
  rmSync(file, { force: true });
});

// ── T-8: secondary utxo index stays correct ─────────────────────────────────

test("T-8: getUtxosForAddress via the secondary index matches a from-scratch scan", () => {
  const store = JsonStore.ephemeral(idAddress);
  store.applyBlock(1, "h1", [
    {
      txid: "t1",
      coinbase: true,
      inputs: [],
      outputs: [
        { index: 0, script_pubkey: "alice", value: 5n },
        { index: 1, script_pubkey: "bob", value: 7n },
        { index: 2, script_pubkey: "alice", value: 3n },
      ],
    },
  ]);
  const aliceUtxos = store.getUtxosForAddress(idAddress("alice"));
  assert.equal(aliceUtxos.length, 2);
  assert.equal(
    aliceUtxos.reduce((sum, u) => sum + u.utxo.value, 0n),
    8n,
  );
  assert.equal(store.getUtxosForAddress(idAddress("bob")).length, 1);
  assert.equal(store.getUtxosForAddress(idAddress("carol")).length, 0);

  // Spend one of alice's two UTXOs; the index must track the removal.
  store.applyBlock(2, "h2", [
    {
      txid: "t2",
      coinbase: false,
      inputs: [{ prev_txid: "t1", prev_index: 0 }],
      outputs: [],
    },
  ]);
  assert.equal(store.getUtxosForAddress(idAddress("alice")).length, 1);
  assert.equal(store.getUtxosForAddress(idAddress("alice"))[0]?.utxo.value, 3n);
});

// ── T-6: key-filtered exact-integer reviver + startup probe ────────────────

test("T-6: an oversized integer under a recognized amount key is preserved exactly", () => {
  const parsed = parseJsonExactIntegers('{"satoshis":354617540000000001,"value":9007199254740993}') as {
    satoshis: unknown;
    value: unknown;
  };
  assert.equal(typeof parsed.satoshis, "string", "satoshis must survive as a string, not a rounded number");
  assert.equal(parsed.satoshis, "354617540000000001");
  assert.equal(typeof parsed.value, "string");
  assert.equal(parsed.value, "9007199254740993");
});

test("T-6: an oversized integer under an UNRECOGNIZED key is left as a (rounded) number, never retyped", () => {
  // Before the fix, the reviver had no key filter and rewrote every oversized
  // integer anywhere in the document — including `height`, which
  // `getBlockByHeight` (rpc.ts) types as `number`. Retyping it to a string
  // silently would be a worse bug than the double-rounding it also carries:
  // a lying type, not just an imprecise value.
  const parsed = parseJsonExactIntegers('{"height":99999999999999999999}') as { height: unknown };
  assert.equal(typeof parsed.height, "number", "an unlisted key must stay a number, never silently retyped");
});

test("T-6: an address-keyed legacy balance entry is treated as an amount (dynamic key, not a literal name)", () => {
  // StoreState.balances is Record<address, satoshis> — the JSON key for each
  // entry IS the address, so a fixed literal-name allowlist alone would miss
  // exactly the largest, highest-value amounts in a legacy state file.
  const addr = "bloch1t" + "0".repeat(41);
  const parsed = parseJsonExactIntegers(`{"balances":{"${addr}":354617540000000001}}`) as {
    balances: Record<string, unknown>;
  };
  assert.equal(typeof parsed.balances[addr], "string");
  assert.equal(parsed.balances[addr], "354617540000000001");
});

test("T-6: an oversized number that is NOT a plain integer literal (already a string, or a float) is untouched", () => {
  const parsed = parseJsonExactIntegers('{"satoshis":"354617540000000001","value":1.5}') as {
    satoshis: unknown;
    value: unknown;
  };
  assert.equal(parsed.satoshis, "354617540000000001");
  assert.equal(parsed.value, 1.5);
});

test("T-6: assertJsonSourceAccessAvailable does not throw on this test runtime (node >= 21 required by package.json)", () => {
  assert.doesNotThrow(() => assertJsonSourceAccessAvailable());
});

// LG-07: pages bind the immutable revision and never materialize all UTXOs.
import { encodeAddress } from "./address.js";
import { MAX_API_RESPONSE_BYTES } from "./api.js";
import { MAX_RPC_RESPONSE_BYTES, readBoundedResponse } from "./rpc.js";
import { statSync, readFileSync, readdirSync } from "node:fs";

test("LG-07: bounded pages cover every entry and reject stale/cross-endpoint cursors", async () => {
  const spk = "11".repeat(20);
  const address = encodeAddress(spk, "testnet");
  const store = JsonStore.ephemeral((script) => encodeAddress(script, "testnet"));
  store.applyBlock(0, "h0", Array.from({ length: 523 }, (_, index) => coinbaseTx(index.toString(16).padStart(64, "0"), spk, 1n)));
  store.getUtxosForAddress = () => { throw new Error("API must not read the entire UTXO list"); };
  const server = createReadApi({ network: "testnet" } as IndexerConfig, store);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const endpoint = server.address();
  if (!endpoint || typeof endpoint === "string") throw new Error("missing listener");
  const base = `http://127.0.0.1:${endpoint.port}/address/${address}`;
  try {
    for (const kind of ["utxos", "history"]) {
      let cursor: string | null = null;
      const seen = new Set<string>();
      do {
        const response = await fetch(`${base}/${kind}?limit=37${cursor ? `&cursor=${cursor}` : ""}`);
        assert.equal(response.status, 200);
        const text = await response.text();
        assert.ok(Buffer.byteLength(text) <= MAX_API_RESPONSE_BYTES);
        const page = JSON.parse(text) as { [key: string]: unknown; nextCursor: string | null };
        const items = page[kind] as Array<{ txid: string }>;
        assert.ok(items.length <= 37);
        for (const item of items) { assert.ok(!seen.has(item.txid)); seen.add(item.txid); }
        cursor = page.nextCursor;
      } while (cursor !== null);
      assert.equal(seen.size, 523);
    }
    const first = await (await fetch(`${base}/utxos`)).json() as { utxos: unknown[]; nextCursor: string };
    assert.equal(first.utxos.length, 100);
    assert.equal((await fetch(`${base}/history?cursor=${first.nextCursor}`)).status, 400);
    for (const query of ["limit=0", "limit=501", "limit=-1", "limit=1.5", "limit=1&limit=2", "cursor=null", "offset=99"]) {
      assert.equal((await fetch(`${base}/utxos?${query}`)).status, 400, query);
    }
    const balance = await (await fetch(`${base}/balance`)).json() as { utxoCount: number };
    assert.equal(balance.utxoCount, 523);
    store.applyBlock(1, "h1", [coinbaseTx("ff".repeat(32), spk, 1n)]);
    assert.equal((await fetch(`${base}/utxos?cursor=${first.nextCursor}`)).status, 409);
    store.rollbackTo(0);
    assert.equal((await fetch(`${base}/utxos?cursor=${first.nextCursor}`)).status, 409, "returning to the same tip must not revive stale cursors");
    const capitalized = address.slice(0, 7) + address.slice(7).toUpperCase();
    const alternate = await (await fetch(base.replace(address, capitalized) + "/balance")).json() as { utxoCount: number };
    assert.equal(alternate.utxoCount, 523);
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
});

test("LG-07: API limits oversized fields and request URLs", async () => {
  const spk = "22".repeat(20);
  const address = encodeAddress(spk, "testnet");
  const store = JsonStore.ephemeral((script) => encodeAddress(script, "testnet"));
  store.applyBlock(0, "h0", [coinbaseTx("a".repeat(16_384), spk, 1n)]);
  const server = createReadApi({ network: "testnet" } as IndexerConfig, store);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const endpoint = server.address();
  if (!endpoint || typeof endpoint === "string") throw new Error("missing listener");
  const base = `http://127.0.0.1:${endpoint.port}`;
  try {
    const response = await fetch(`${base}/address/${address}/history`);
    assert.equal(response.status, 503);
    assert.ok(Buffer.byteLength(await response.text()) < MAX_API_RESPONSE_BYTES);
    assert.equal((await fetch(`${base}/${"a".repeat(2050)}`)).status, 414);
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
});

test("LG-07: upstream response limits apply to streamed and declared sizes", async () => {
  const oversized = Buffer.alloc(MAX_RPC_RESPONSE_BYTES + 1, 32);
  await assert.rejects(readBoundedResponse(new Response(oversized), "test"), /exceeds 8 MiB/);
  await assert.rejects(readBoundedResponse(new Response("{}", { headers: { "content-length": String(MAX_RPC_RESPONSE_BYTES + 1) } }), "test"), /exceeds 8 MiB/);
  assert.equal(await readBoundedResponse(new Response("{\"ok\":true}"), "test"), '{"ok":true}');
});

test("LG-07: unchanged snapshots are not rewritten and corrupt snapshots are preserved", () => {
  const file = tmpFile();
  try {
    const store = JsonStore.open(file, idAddress);
    store.applyBlock(0, "h0", [coinbaseTx("t1", "spk", 42n)]);
    store.persist();
    const first = statSync(file);
    store.persist();
    assert.equal(statSync(file).ino, first.ino, "no rename/rewrite during an unchanged poll");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(join(file, "..")), ["state.json"]);
    const restored = JsonStore.open(file, idAddress);
    assert.equal(restored.getUtxoCount(idAddress("spk")), 1);
    assert.notEqual(restored.getSnapshotId(), store.getSnapshotId(), "restart invalidates pagination cursors");
    writeFileSync(file, "{broken");
    const corrupt = JsonStore.open(file, idAddress);
    assert.throws(() => corrupt.persist(), /unreadable/);
    assert.equal(readFileSync(file, "utf8"), "{broken");
  } finally { rmSync(join(file, ".."), { recursive: true, force: true }); }
});

test("LG-07: corrupt snapshots cannot produce authoritative empty balance responses", async () => {
  const file = tmpFile();
  writeFileSync(file, "{broken");
  const store = JsonStore.open(file, idAddress);
  const server = createReadApi({ network: "testnet" } as IndexerConfig, store);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const endpoint = server.address();
  if (!endpoint || typeof endpoint === "string") throw new Error("missing listener");
  try {
    const address = encodeAddress("33".repeat(20), "testnet");
    const response = await fetch(`http://127.0.0.1:${endpoint.port}/address/${address}/balance`);
    assert.equal(response.status, 503);
    assert.equal((await response.json() as { balanceSats?: string }).balanceSats, undefined);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(join(file, ".."), { recursive: true, force: true });
  }
});

import { serializeState } from "./store.js";

function spendTx(txid: string, previous: string, destination: string, value: bigint): Tx {
  return { txid, coinbase: false, inputs: [{ prev_txid: previous, prev_index: 0 }],
    outputs: [{ index: 0, script_pubkey: destination, value }] };
}

test("index accuracy: chained same-block spends and persisted undo restore the exact funded UTXO", () => {
  const file = tmpFile();
  try {
    const store = JsonStore.open(file, idAddress);
    store.applyBlock(0, "h0", [coinbaseTx("funding", "alice", 100n)]);
    const beforeUtxos = { ...store.state.utxos };
    const beforeBalances = { ...store.state.balances };
    const beforeHistory = structuredClone({ ...store.state.history });
    store.applyBlock(1, "h1", [
      spendTx("first", "funding", "bob", 90n),
      spendTx("second", "first", "carol", 80n),
      spendTx("third", "second", "dave", 70n),
    ]);
    assert.equal(store.getUtxo("funding", 0), undefined);
    assert.equal(store.getUtxo("first", 0), undefined);
    assert.equal(store.getUtxo("second", 0), undefined);
    assert.equal(store.getUtxo("third", 0)?.value, 70n);
    for (const address of ["alice", "bob", "carol"]) {
      assert.equal(store.getBalance(idAddress(address)), 0n);
      assert.equal(store.getUtxoCount(idAddress(address)), 0);
    }
    assert.deepEqual(store.getHistory(idAddress("bob")).map((entry) => entry.direction), ["in", "out"]);
    assert.deepEqual(store.state.undo[1]?.spent.map((entry) => entry.key), ["funding:0"]);
    store.persist();
    const loaded = JsonStore.open(file, idAddress);
    loaded.rollbackTo(0);
    assert.deepEqual({ ...loaded.state.utxos }, beforeUtxos);
    assert.deepEqual({ ...loaded.state.balances }, beforeBalances);
    assert.deepEqual({ ...loaded.state.history }, beforeHistory);
    assert.equal(loaded.getUtxoCount(idAddress("alice")), 1);
    for (const address of ["bob", "carol", "dave"]) assert.equal(loaded.getUtxoCount(idAddress(address)), 0);
    assert.deepEqual(loaded.getTip(), { height: 0, hash: "h0" });
  } finally { rmSync(join(file, ".."), { recursive: true, force: true }); }
});

test("index accuracy: duplicate spends and outpoint collisions reject atomically", () => {
  const attempts: Tx[][] = [
    [spendTx("a", "funding", "bob", 90n), spendTx("b", "funding", "carol", 90n)],
    [{ ...spendTx("a", "funding", "bob", 90n), inputs: [
      { prev_txid: "funding", prev_index: 0 }, { prev_txid: "funding", prev_index: 0 },
    ] }],
    [spendTx("a", "funding", "bob", 90n), spendTx("b", "a", "carol", 80n), spendTx("c", "a", "dave", 80n)],
    [coinbaseTx("collision", "bob", 1n), coinbaseTx("collision", "carol", 1n)],
    [coinbaseTx("funding", "bob", 100n)],
    [spendTx("child", "later", "bob", 1n), coinbaseTx("later", "carol", 1n)],
  ];
  for (const transactions of attempts) {
    const store = JsonStore.ephemeral(idAddress);
    store.applyBlock(0, "h0", [coinbaseTx("funding", "alice", 100n)]);
    const before = JSON.stringify(serializeState(store.state));
    const revision = store.getSnapshotId();
    assert.throws(() => store.applyBlock(1, "h1", transactions), /duplicate|before creation/);
    assert.equal(JSON.stringify(serializeState(store.state)), before);
    assert.equal(store.getSnapshotId(), revision);
    assert.equal(store.getUtxoCount(idAddress("alice")), 1);
    assert.equal(store.getUtxoCount(idAddress("bob")), 0);
    // A failed block must not prevent a subsequent valid retry at its height.
    store.applyBlock(1, "valid-h1", [spendTx("valid", "funding", "bob", 90n)]);
    assert.equal(store.getBalance(idAddress("bob")), 90n);
    store.rollbackTo(0);
    assert.equal(store.getBalance(idAddress("alice")), 100n);
  }
});

import { deserializeState } from "./store.js";
import { Indexer } from "./indexer.js";
import { RpcClient } from "./rpc.js";

test("snapshot validation: malformed shapes and counters cannot freeze revision/persistence", () => {
  const store = JsonStore.ephemeral(idAddress);
  store.applyBlock(0, "h0", [coinbaseTx("funding", "alice", 10n)]);
  const valid = serializeState(store.state) as Record<string, unknown>;
  for (const bad of [null, {}, [],
    { ...valid, blocksApplied: "garbage" }, { ...valid, blocksRolledBack: -1 },
    { ...valid, reorgsHandled: 0.5 }, { ...valid, blocksApplied: Number.MAX_SAFE_INTEGER + 1 },
    { ...valid, indexedTip: { height: 0, hash: "wrong" } },
    { ...valid, indexedTip: null }, { ...valid, chain: [] },
  ]) {
    assert.throws(() => deserializeState(bad));
  }
  assert.deepEqual(deserializeState(valid), store.state);
});

test("snapshot roundtrip: prototype-shaped own keys preserve balances, history and undo", () => {
  const store = JsonStore.ephemeral(() => "__proto__");
  store.applyBlock(0, "h0", [coinbaseTx("funding", "unused", 10n)]);
  const loaded = deserializeState(JSON.parse(JSON.stringify(serializeState(store.state))));
  assert.equal(loaded.balances["__proto__"], 10n);
  assert.equal(loaded.history["__proto__"]?.length, 1);
  assert.equal(loaded.undo[0]?.deltas["__proto__"], 10n);
  assert.deepEqual(loaded, store.state);
});

test("rollback preflight: a missing undo record leaves all higher blocks unchanged", () => {
  const store = JsonStore.ephemeral(idAddress);
  for (let height = 0; height < 3; height++) store.applyBlock(height, `h${height}`, [coinbaseTx(`t${height}`, "alice", 10n)]);
  delete store.state.undo[1];
  const before = JSON.stringify(serializeState(store.state));
  const revision = store.getSnapshotId();
  assert.throws(() => store.rollbackTo(0), /no undo record/);
  assert.equal(JSON.stringify(serializeState(store.state)), before);
  assert.equal(store.getSnapshotId(), revision);
});

test("sync refuses an RPC block whose height differs from the requested position", async () => {
  const store = JsonStore.ephemeral(idAddress);
  const rpc = new RpcClient({ async call(method) {
    assert.equal(method, "getblockbyheight");
    return { hash: "wrong", height: 9, parents: [], transactions: [] };
  } });
  await assert.rejects(new Indexer(rpc, store).syncOnce(), /requested height 0/);
  assert.equal(store.getTip(), null);
  assert.equal(store.state.blocksApplied, 0);
});
