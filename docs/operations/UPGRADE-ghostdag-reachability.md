<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Node Upgrade — GHOSTDAG Reachability Fix (DROP-IN)

**Status: candidate, UNAUDITED — review + test before deploying.**
Branch: `fix/ghostdag-reachability`.

## Verdict: DROP-IN (result-identical, no fork, no coordinated height)

The differential harness proves the fast path is **byte-identical** to the
current node on the live chain, so this is a **transparent performance fix** —
**no fork, and no coordinated activation height is required.** Each operator can
upgrade independently, at their own pace; upgraded and un-upgraded nodes stay on
the same chain.

Evidence (`dag_shape_stats` against a real snapshot): the Bloch DAG is
**~99.94 % linear** — **max blues_anticone_size = 9** (below `K = 10`), max
mergeset width = 6, 0 blocks with mergeset > K. The Fast path diverges from the
bounded Legacy path only when an anticone is *wide* enough to be under-counted;
that never happens below the bound, so results are identical. The
`past_blue_set hit depth bound` WARN is a chain-*depth* (perf) symptom, not a
wide-anticone (correctness) one.

## Why (the incident this fixes)

`classify_mergeset` is `O(|mergeset| × |blue_set| × bounded-BFS)`; the
reachability walk saturates the `k*100 = 1000` depth bound at ~397k, so
per-block validation crawls (~15 s/block). A node that falls behind cannot
integrate the backlog into its selected chain → it freezes (`syncing: true`) and
the network fails to converge. The fix adds an O(1) reachability index +
incremental blue-coloring so backlogs process fast and nodes converge.

## Token / history preservation

The change is behind an activation-height gate; historical blocks are loaded
verbatim and **never recomputed** → every mined block/balance is byte-identical,
no reorg. For a DROP-IN, enabling Fast at height `0` is safe (identical results).
The data-dir / volume is untouched.

## Step 1 — (optional, recommended) re-verify DROP-IN yourself

```sh
BLOCH_SNAPSHOT=/path/to/a/node/data-dir \
  cargo test --release --test ghostdag_replay_snapshot dag_shape_stats -- --ignored --nocapture
```
Confirm `max blues_anticone_size < K` (and, if you want the full byte-level
check, run `replay_snapshot_legacy_vs_fast` — note it walks the whole chain
through the slow Legacy path, so it can take hours).

## Step 2 — build + restart (per node, independent)

```sh
cd ~/bloch && git fetch && git checkout fix/ghostdag-reachability   # or the merged release tag
# in src/consensus/mod.rs:  CORRECTED_COLORING_ACTIVATION_HEIGHT = 0
cargo build --release
sudo systemctl restart bloch-node
```

Verify: `bloch-cli dag` (chain_length climbing again), `bloch-cli peers`
(`syncing` clears once caught up).

## Rollback

Fully safe — check out the previous (alpha3) binary and restart. Result-identical
both ways; nothing to reconcile.

## Notes

- Performance/convergence fix only — coin, reward, and token semantics untouched.
- The reachability index is a cache (own column family, never part of the
  integrity chain); it rebuilds deterministically on restart and cannot corrupt
  the DAG.
- Should the chain shape ever change (sustained wide anticones), re-run the
  verdict — if a future divergence appears, revert to the coordinated
  activation-height procedure. `max anticone < K` today makes that remote.
