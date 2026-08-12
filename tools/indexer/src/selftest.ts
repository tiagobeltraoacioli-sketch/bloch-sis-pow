// SPDX-License-Identifier: MIT OR Apache-2.0
// Offline self-test for the reorg-safe indexer. Drives the scripted stub chain
// through a reorg and asserts that address balances, UTXOs, and history are
// correct AFTER rollback + re-apply — i.e. no state from the orphaned blocks
// leaks through. Exits non-zero on failure. Run: npm run selftest
//
// It also covers the satoshi encoding (docs/specs/BLOCH-SATOSHI-ENCODING.md):
// amounts are `bigint` in memory, decimal strings on the wire, on disk, and out
// of the read API — with a balance 39x past Number.MAX_SAFE_INTEGER carried
// through index -> persist -> reload -> API -> reorg.
//
// This is NOT a test against a live network; it exercises the rollback logic in
// isolation against a deterministic fixture chain.

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";

import { RpcClient } from "./rpc.js";
import { JsonStore } from "./store.js";
import { Indexer } from "./indexer.js";
import { createReadApi } from "./api.js";
import { encodeAddress } from "./address.js";
import { parseSats, formatSats, MAX_SATS, parseJsonExactIntegers } from "./sats.js";
import { buildScenario, buildLargeValueScenario, actorScript, LARGEST_CARRYOVER_SAT } from "./stubchain.js";

let failed = false;

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error("FAIL:", msg);
    failed = true;
    process.exitCode = 1;
    return;
  }
  console.log("ok:", msg);
}

function assertThrows(fn: () => unknown, msg: string): void {
  try {
    fn();
  } catch {
    console.log("ok:", msg);
    return;
  }
  console.error("FAIL (did not throw):", msg);
  failed = true;
  process.exitCode = 1;
}

async function reorgSuite(): Promise<void> {
  console.log("\n── reorg suite (chain A -> chain B) ───────────────────────────");
  const { transport, doReorg } = buildScenario();
  const rpc = new RpcClient(transport);
  const store = JsonStore.ephemeral((spk) => encodeAddress(spk, "testnet"));
  const indexer = new Indexer(rpc, store, (m) => console.log("   [idx]", m));

  const addr = (name: string) => encodeAddress(actorScript(name), "testnet");
  const A = { miner: addr("miner"), alice: addr("alice"), bob: addr("bob"), carol: addr("carol"), dave: addr("dave") };

  // ── Phase 1: index chain A (heights 0..4) ────────────────────────────────
  const r1 = await indexer.syncOnce();
  assert(r1.tipHeight === 4, `indexed chain A up to tip height 4 (got ${r1.tipHeight})`);
  assert(!r1.reorgDetected, "no reorg on first sync");

  // Balances after chain A:
  //   miner: 20 (h1 change) + 50 (h4 coinbase) = 70  (cb0 50 spent in h1)
  //   alice: 20 (h2 change)                          (h1 30 spent in h2)
  //   bob:   5  (h3 change)                          (h2 10 spent in h3)
  //   carol: 5                                        (h3)
  //   dave:  0
  // (h0's coinbase arrives from the stub as a LEGACY bare JSON number, so these
  // balances also prove the dual-tolerant reader, spec rule 5.)
  assert(store.getBalance(A.miner) === 70n, `chainA miner balance 70 (got ${store.getBalance(A.miner)})`);
  assert(store.getBalance(A.alice) === 20n, `chainA alice balance 20 (got ${store.getBalance(A.alice)})`);
  assert(store.getBalance(A.bob) === 5n, `chainA bob balance 5 (got ${store.getBalance(A.bob)})`);
  assert(store.getBalance(A.carol) === 5n, `chainA carol balance 5 (got ${store.getBalance(A.carol)})`);
  assert(store.getBalance(A.dave) === 0n, `chainA dave balance 0 (got ${store.getBalance(A.dave)})`);
  assert(store.getHistory(A.carol).length === 1, "chainA carol has 1 history entry");
  assert(
    typeof store.getBalance(A.miner) === "bigint" && typeof store.getHistory(A.carol)[0]?.amountSats === "bigint",
    "balances and history amounts are bigint, not number",
  );

  // ── Phase 2: reorg replaces heights 3..4, then sync again ────────────────
  doReorg();
  const r2 = await indexer.syncOnce();
  assert(r2.reorgDetected, "reorg detected on second sync");
  assert(r2.forkHeight === 2, `fork point at height 2 (got ${r2.forkHeight})`);
  assert(r2.rolledBack === 2, `rolled back 2 blocks (got ${r2.rolledBack})`);
  assert(r2.applied === 2, `re-applied 2 blocks (got ${r2.applied})`);
  assert(r2.tipHeight === 4, `tip back to height 4 (got ${r2.tipHeight})`);

  // Balances after chain B:
  //   miner: 20 (h1 change) + 50 (h4' coinbase) = 70
  //   alice: 20
  //   bob:   2  (h3' change)
  //   carol: 0  (her UTXO was orphaned!)
  //   dave:  8  (h3')
  assert(store.getBalance(A.miner) === 70n, `chainB miner balance 70 (got ${store.getBalance(A.miner)})`);
  assert(store.getBalance(A.alice) === 20n, `chainB alice balance 20 (got ${store.getBalance(A.alice)})`);
  assert(store.getBalance(A.bob) === 2n, `chainB bob balance 2 (got ${store.getBalance(A.bob)})`);
  assert(store.getBalance(A.carol) === 0n, `chainB carol balance 0 — orphaned UTXO gone (got ${store.getBalance(A.carol)})`);
  assert(store.getBalance(A.dave) === 8n, `chainB dave balance 8 (got ${store.getBalance(A.dave)})`);

  // The KEY assertion the roadmap calls out: no stale history from the orphaned
  // block. Carol must have zero history entries now.
  assert(store.getHistory(A.carol).length === 0, "carol has NO stale history after reorg");
  assert(store.getHistory(A.dave).length === 1, "dave has exactly 1 history entry after reorg");
  assert(store.getUtxosForAddress(A.carol).length === 0, "carol has no live UTXOs after reorg");

  // Idempotency: a third sync with no chain change must be a no-op.
  const r3 = await indexer.syncOnce();
  assert(!r3.reorgDetected && r3.applied === 0 && r3.rolledBack === 0, "third sync is a clean no-op");
}

// ── The satoshi-encoding suite: the point of the bigint migration ─────────────
//
// Pinned, measured on node v22.16.0:
//   $ node -e 'console.log(JSON.stringify(JSON.parse(`{"v":354617540000000001}`)))'
//   {"v":354617540000000000}      # 1 satoshi gone, silently
//   $ node -e 'console.log(JSON.stringify(JSON.parse(`{"v":"354617540000000001"}`)))'
//   {"v":"354617540000000001"}    # string form: byte-identical
async function largeValueSuite(): Promise<void> {
  console.log("\n── large-value suite (balance past Number.MAX_SAFE_INTEGER) ───");

  const WHALE_TOTAL = LARGEST_CARRYOVER_SAT + 1n; // 354,617,540,000,000,001
  assert(
    LARGEST_CARRYOVER_SAT > BigInt(Number.MAX_SAFE_INTEGER) * 39n,
    `fixture is >39x Number.MAX_SAFE_INTEGER (${LARGEST_CARRYOVER_SAT} vs ${Number.MAX_SAFE_INTEGER})`,
  );
  // Why the +1: as doubles the sum simply does not move. This is the assertion
  // the old `number`-typed store could not pass.
  assert(
    Number(LARGEST_CARRYOVER_SAT) + 1 === Number(LARGEST_CARRYOVER_SAT),
    "as doubles, 354617540000000000 + 1 === 354617540000000000 (the corruption this test pins)",
  );

  const dir = mkdtempSync(join(tmpdir(), "bloch-indexer-selftest-"));
  const dataFile = join(dir, "state.json");
  try {
    const { transport, whaleScript, doReorg } = buildLargeValueScenario();
    const rpc = new RpcClient(transport);
    const store = JsonStore.open(dataFile, (spk) => encodeAddress(spk, "testnet"));
    const indexer = new Indexer(rpc, store, (m) => console.log("   [idx]", m));
    const whale = encodeAddress(whaleScript, "testnet");

    // Index: h0 pays the whale 354,617,540,000,000,000; h1 pays 1 more.
    const r1 = await indexer.syncOnce();
    assert(r1.tipHeight === 1, `indexed both large-value blocks (tip ${r1.tipHeight})`);
    assert(
      store.getBalance(whale) === WHALE_TOTAL,
      `whale balance is exactly ${WHALE_TOTAL} (got ${store.getBalance(whale)})`,
    );
    const utxos = store.getUtxosForAddress(whale);
    assert(
      utxos.length === 2 && utxos.some((u) => u.utxo.value === LARGEST_CARRYOVER_SAT),
      `whale UTXO carries ${LARGEST_CARRYOVER_SAT} exactly`,
    );

    // Persisted by indexer.syncOnce(): the file must hold decimal STRINGS, and
    // JSON.stringify must not have thrown on a bigint.
    const onDisk = readFileSync(dataFile, "utf8");
    assert(
      onDisk.includes(`"${WHALE_TOTAL}"`),
      `state file stores the balance as a decimal string "${WHALE_TOTAL}"`,
    );
    assert(
      !new RegExp(`[^"]${LARGEST_CARRYOVER_SAT}`).test(onDisk),
      "state file contains no bare numeric satoshi literal",
    );

    // Reload from disk: exact round-trip.
    const reloaded = JsonStore.open(dataFile, (spk) => encodeAddress(spk, "testnet"));
    assert(
      reloaded.getBalance(whale) === WHALE_TOTAL,
      `balance survives persist -> reload exactly (got ${reloaded.getBalance(whale)})`,
    );
    assert(
      reloaded.getHistory(whale).reduce((a, e) => a + (e.direction === "in" ? e.amountSats : -e.amountSats), 0n) ===
        WHALE_TOTAL,
      "history amounts survive reload exactly",
    );

    // Read API: amounts out as decimal strings, never JSON numbers.
    const server = createReadApi(
      { network: "testnet" } as never,
      reloaded,
    );
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const body = await (await fetch(`http://127.0.0.1:${port}/address/${whale}/balance`)).text();
    server.close();
    assert(
      body.includes(`"balanceSats":"${WHALE_TOTAL}"`),
      `API emits balanceSats as a decimal string (body: ${body})`,
    );
    assert(!body.includes(`"balanceSats":${WHALE_TOTAL}`), "API does not emit balanceSats as a JSON number");
    // And a JavaScript consumer reading that body gets the exact digits back.
    const roundTripped = (parseJsonExactIntegers(body) as { balanceSats: string }).balanceSats;
    assert(BigInt(roundTripped) === WHALE_TOTAL, "API body survives a JavaScript JSON round-trip byte for byte");

    // Reorg the whole thing away: balance must return to 0, not to a residue.
    doReorg();
    const r2 = await indexer.syncOnce();
    assert(r2.reorgDetected && r2.forkHeight === -1, `whole chain replaced (fork ${r2.forkHeight})`);
    assert(store.getBalance(whale) === 0n, `whale balance back to 0 after reorg (got ${store.getBalance(whale)})`);
    assert(store.getUtxosForAddress(whale).length === 0, "whale has no live UTXOs after reorg");
    assert(store.getHistory(whale).length === 0, "whale has no stale history after reorg");
    assert(
      JsonStore.open(dataFile, (spk) => encodeAddress(spk, "testnet")).getBalance(whale) === 0n,
      "post-reorg zero balance also survives persist -> reload",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function encodingSuite(): void {
  console.log("\n── parseSats / legacy-tolerance suite ─────────────────────────");

  assert(parseSats("354617540000000001") === 354617540000000001n, "parses the canonical decimal-string form exactly");
  assert(parseSats(0) === 0n && parseSats("0") === 0n, "parses zero in both forms");
  assert(parseSats(4200000000) === 4_200_000_000n, "parses the legacy bare-number form (below 2^53)");
  assert(parseSats(MAX_SATS) === MAX_SATS, "accepts an amount at the supply cap (10^19)");
  assert(formatSats(MAX_SATS) === "10000000000000000000", "formats the supply cap as a decimal string");

  assertThrows(() => parseSats("-1"), "rejects a negative amount");
  assertThrows(() => parseSats(-1), "rejects a negative legacy number");
  assertThrows(() => parseSats(MAX_SATS + 1n), "rejects an amount above the supply cap");
  assertThrows(() => parseSats("10000000000000000001"), "rejects an above-cap decimal string");
  assertThrows(() => parseSats("0x10"), "rejects hex");
  assertThrows(() => parseSats("007"), "rejects leading zeros");
  assertThrows(() => parseSats("1.5"), "rejects a decimal point");
  assertThrows(() => parseSats(1.5), "rejects a non-integer number");
  assertThrows(() => parseSats(undefined), "rejects a missing amount");
  // A legacy number past 2^53 has already lost its digits — refuse it loudly
  // rather than launder a wrong value into a confident-looking bigint.
  assertThrows(() => parseSats(354617540000000001), "rejects a legacy number above Number.MAX_SAFE_INTEGER");

  // Fixed vector (spec test obligation 5): the numeric form corrupts, the string
  // form does not, and parseJsonExactIntegers recovers the raw digits.
  const numericForm = JSON.stringify(JSON.parse(`{"v":354617540000000001}`));
  assert(numericForm === `{"v":354617540000000000}`, `numeric JSON form loses 1 sat (got ${numericForm})`);
  const stringForm = JSON.stringify(JSON.parse(`{"v":"354617540000000001"}`));
  assert(stringForm === `{"v":"354617540000000001"}`, `string JSON form is byte-identical (got ${stringForm})`);
  const recovered = parseJsonExactIntegers(`{"v":354617540000000001}`) as { v: unknown };
  assert(
    parseSats(recovered.v) === 354617540000000001n,
    `raw-source reader recovers the exact digits of a legacy oversized literal (got ${String(recovered.v)})`,
  );
  const smallLiteral = parseJsonExactIntegers(`{"height":8500,"v":50}`) as { height: unknown; v: unknown };
  assert(
    typeof smallLiteral.height === "number" && smallLiteral.height === 8500 && typeof smallLiteral.v === "number",
    "raw-source reader leaves safe integers (heights, small amounts) as numbers",
  );
}

function legacyStateFileSuite(): void {
  console.log("\n── legacy on-disk state suite ─────────────────────────────────");
  const dir = mkdtempSync(join(tmpdir(), "bloch-indexer-legacy-"));
  const file = join(dir, "old-state.json");
  try {
    // Exactly the shape the pre-bigint build wrote: every amount a JSON number,
    // including one past 2^53 that a plain JSON.parse would round.
    const legacy = `{
      "indexedTip": {"height": 2, "hash": "aa"},
      "reorgsHandled": 0, "blocksApplied": 3, "blocksRolledBack": 0,
      "chain": {"0":"a0","1":"a1","2":"aa"},
      "utxos": {"t0:0": {"address":"bloch1tsmall","value":4200000000,"height":1},
                "t1:0": {"address":"bloch1twhale","value":354617540000000000,"height":2}},
      "balances": {"bloch1tsmall": 4200000000, "bloch1twhale": 354617540000000000},
      "history": {"bloch1twhale": [{"txid":"t1","height":2,"direction":"in","amountSats":354617540000000000}]},
      "undo": {"2": {"height":2,"hash":"aa","created":["t1:0"],"spent":[],
                     "deltas":{"bloch1twhale":354617540000000000}}}
    }`;
    writeFileSync(file, legacy);

    const store = JsonStore.open(file, (spk) => spk);
    assert(
      store.getBalance("bloch1twhale") === 354_617_540_000_000_000n,
      `legacy numeric state file loads exactly (got ${store.getBalance("bloch1twhale")})`,
    );
    assert(store.getBalance("bloch1tsmall") === 4_200_000_000n, "legacy small balance loads exactly");
    assert(store.getTip()?.height === 2 && store.getChainHashAt(2) === "aa", "legacy tip/chain survive the load");
    assert(
      store.getUtxo("t1", 0)?.value === 354_617_540_000_000_000n,
      "legacy UTXO value loads as an exact bigint",
    );

    // And re-persisting migrates it to the string form.
    store.persist();
    const migrated = readFileSync(file, "utf8");
    assert(
      migrated.includes(`"354617540000000000"`) && !migrated.includes(`:354617540000000000`),
      "re-persisting migrates the file to decimal strings",
    );
    const reloaded = JsonStore.open(file, (spk) => spk);
    assert(
      reloaded.getBalance("bloch1twhale") === 354_617_540_000_000_000n,
      "migrated file reloads exactly",
    );
    assert(
      reloaded.state.undo[2]?.deltas["bloch1twhale"] === 354_617_540_000_000_000n,
      "undo deltas survive the migration (rollback would otherwise be wrong)",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function run(): Promise<void> {
  await reorgSuite();
  encodingSuite();
  legacyStateFileSuite();
  await largeValueSuite();

  if (failed) {
    console.error("\nSELF-TEST FAILED (see FAIL lines above).");
    process.exit(1);
  }
  console.log("\nAll self-tests passed (offline, scripted chain, no network).");
}

run().catch((e) => {
  console.error("selftest crashed:", e);
  process.exit(1);
});
