<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Coordinated Upgrade — GHOSTDAG Reachability Fix

**Status: SCAFFOLD / UNAUDITED — review before any wide deployment.**
Branch: `fix/ghostdag-reachability` (commit `2b7a28c`).

## Why (the incident this fixes)

At high DAG height the current node's `classify_mergeset` is
`O(|mergeset| × |blue_set| × bounded-BFS)`: `past_blue_set` walks the selected
chain to `k*100 = 1000` hops and `is_ancestor` is a bounded BFS, both of which
**saturate at ~397k** (the `past_blue_set hit depth bound` WARN). Per-block
validation crawls to ~15 s/block (~4 blocks/min). Consequence: a node that
falls behind **cannot integrate the backlog into its selected chain** — it
freezes with `syncing: true` forever, and the network **fails to converge**
(nodes stuck at different heights; observed 2026-07-16: nodes at 397044 / 393904
/ 392398 while the canonical tip advanced to ~398237 on another node).

The fix adds an **O(1) reachability index** (interval labeling + future-covering
set, Kaspa-style) and **incremental blue-coloring inherited from the selected
parent** (the "Fast" path), so backlogs process quickly and nodes converge.

## Token / history preservation (guarantee)

The fix ships behind an activation-height gate, **DEFAULT DISABLED**
(`CORRECTED_COLORING_ACTIVATION_HEIGHT = u64::MAX` in `src/consensus/mod.rs`).
Historical blocks are loaded verbatim from disk and **NEVER recomputed** → every
already-mined block and balance is preserved byte-identically. When enabled,
only blocks **at/above** the activation height use the Fast coloring; everything
below stays Legacy. There is no retroactive recompute and no reorg of history.

## Step 0 — decide the case with the replay harness (REQUIRED first)

The Fast path computes the *correct* (unbounded) GHOSTDAG coloring. That is
byte-identical to Legacy on **narrow** DAGs but **diverges on wide anticones**
(the bounded Legacy BFS under-counts). Run the read-only replay against a real
snapshot to find out which case the live chain is in:

```sh
BLOCH_SNAPSHOT=/path/to/a/node/data-dir \
  cargo test --release --test ghostdag_replay_snapshot -- --ignored --nocapture
```

- **Case A — DROP-IN** (replay reports Legacy == Fast on every block): the chain
  is narrow; Fast is a pure speedup with identical results → **no fork, no
  coordination on a height needed.** Each operator can enable Fast (set the
  activation height to `0` or any height ≤ current tip) and restart, independently.
- **Case B — GATED** (replay reports a divergence at some height): Fast would
  change results → a **consensus change**. It MUST go behind a coordinated
  activation height (Step 1B). Baking it in silently would fork the network.

## Step 1 — set the activation height

Edit `src/consensus/mod.rs`:

- **Case A (drop-in):** `pub const CORRECTED_COLORING_ACTIVATION_HEIGHT: u64 = 0;`
  (Fast everywhere; identical results, just faster.)
- **Case B (gated):** ALL operators set the **same**
  `CORRECTED_COLORING_ACTIVATION_HEIGHT = H`, where **H > current tip + buffer**
  (choose a round number several hours of blocks above the tip so every operator
  has time to upgrade). Below `H`: Legacy (byte-identical, no fork). At/above
  `H`: Fast (converged). **Any node not upgraded by height `H` forks off the
  network** — comms + a confirmed upgrade window are mandatory in Case B.

## Step 2 — build and restart (per node)

```sh
cd ~/bloch
git fetch && git checkout fix/ghostdag-reachability   # or the merged release tag
# apply the chosen CORRECTED_COLORING_ACTIVATION_HEIGHT (Step 1)
cargo build --release
sudo systemctl restart bloch-node
```

Verify: `bloch-cli dag` (chain_length climbing), `bloch-cli peers`
(`syncing` clears once caught up). The data-dir/volume is untouched — mined
history is preserved.

## Rollback

Fully safe: check out the previous (alpha3) binary and restart. The gate is
default-disabled, so the un-upgraded binary is byte-identical Legacy — no fork,
no data change. In Case B, roll back *before* height `H` if aborting.

## Notes

- This is a **performance/convergence** fix, not a coin/consensus-reward change.
  The gas/coin/token semantics are untouched.
- Independent verification: two operators running the replay against the same
  snapshot must get the same Case A/B verdict (the harness is deterministic).
- The reachability index is a **cache** (own column family, never part of the
  integrity chain); it rebuilds deterministically on restart and cannot corrupt
  the DAG.
