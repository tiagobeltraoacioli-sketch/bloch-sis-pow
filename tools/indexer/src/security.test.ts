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
