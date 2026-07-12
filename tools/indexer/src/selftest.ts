// SPDX-License-Identifier: MIT OR Apache-2.0
// Offline self-test for the reorg-safe indexer. Drives the scripted stub chain
// through a reorg and asserts that address balances, UTXOs, and history are
// correct AFTER rollback + re-apply — i.e. no state from the orphaned blocks
// leaks through. Exits non-zero on failure. Run: npm run selftest
//
// This is NOT a test against a live network; it exercises the rollback logic in
// isolation against a deterministic fixture chain.

import { RpcClient } from "./rpc.js";
import { JsonStore } from "./store.js";
import { Indexer } from "./indexer.js";
import { encodeAddress } from "./address.js";
import { buildScenario, actorScript } from "./stubchain.js";

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error("FAIL:", msg);
    process.exit(1);
  }
  console.log("ok:", msg);
}

async function run(): Promise<void> {
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
  assert(store.getBalance(A.miner) === 70, `chainA miner balance 70 (got ${store.getBalance(A.miner)})`);
  assert(store.getBalance(A.alice) === 20, `chainA alice balance 20 (got ${store.getBalance(A.alice)})`);
  assert(store.getBalance(A.bob) === 5, `chainA bob balance 5 (got ${store.getBalance(A.bob)})`);
  assert(store.getBalance(A.carol) === 5, `chainA carol balance 5 (got ${store.getBalance(A.carol)})`);
  assert(store.getBalance(A.dave) === 0, `chainA dave balance 0 (got ${store.getBalance(A.dave)})`);
  assert(store.getHistory(A.carol).length === 1, "chainA carol has 1 history entry");

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
  assert(store.getBalance(A.miner) === 70, `chainB miner balance 70 (got ${store.getBalance(A.miner)})`);
  assert(store.getBalance(A.alice) === 20, `chainB alice balance 20 (got ${store.getBalance(A.alice)})`);
  assert(store.getBalance(A.bob) === 2, `chainB bob balance 2 (got ${store.getBalance(A.bob)})`);
  assert(store.getBalance(A.carol) === 0, `chainB carol balance 0 — orphaned UTXO gone (got ${store.getBalance(A.carol)})`);
  assert(store.getBalance(A.dave) === 8, `chainB dave balance 8 (got ${store.getBalance(A.dave)})`);

  // The KEY assertion the roadmap calls out: no stale history from the orphaned
  // block. Carol must have zero history entries now.
  assert(store.getHistory(A.carol).length === 0, "carol has NO stale history after reorg");
  assert(store.getHistory(A.dave).length === 1, "dave has exactly 1 history entry after reorg");
  assert(store.getUtxosForAddress(A.carol).length === 0, "carol has no live UTXOs after reorg");

  // Idempotency: a third sync with no chain change must be a no-op.
  const r3 = await indexer.syncOnce();
  assert(!r3.reorgDetected && r3.applied === 0 && r3.rolledBack === 0, "third sync is a clean no-op");

  console.log("\nAll reorg self-tests passed (offline, scripted chain, no network).");
}

run().catch((e) => {
  console.error("selftest crashed:", e);
  process.exit(1);
});
