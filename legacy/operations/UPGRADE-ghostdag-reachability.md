<!-- SPDX-License-Identifier: MIT -->
# Node Upgrade — GHOSTDAG Reachability Fix (durable index + coordinated activation)

**Status: candidate, UNAUDITED — review + test before deploying.**
Branches: `fix/ghostdag-reachability` (index + Fast mode) →
`feat/reachability-durable` (durable CF + rebuild migration + activation shape).
Canonical ADR: `legacy/BLOCH-UPGRADE-REACHABILITY.md`.

## Verdict: COORDINATED SOFT-FORK (not a per-node DROP-IN)

> **This supersedes the earlier "DROP-IN, no coordination, enable at height 0"
> verdict, which is RETRACTED.** The chain actually froze (see mechanism below),
> which is only possible if a bounded ancestry walk bit on real history. Where a
> bound bit, the corrected `Fast` coloring differs from `Legacy` on **new**
> blocks, so mixing upgraded and un-upgraded nodes would fork. Adopting `Fast`
> is therefore a coordinated activation at a **future height**, owned by the
> operator/network — not a transparent per-node speedup.

Shipped default is **OFF**: `CORRECTED_COLORING_ACTIVATION_HEIGHT = u64::MAX`.
Deploying this branch changes **zero** live behavior until a height is set.

### Why the old "narrow DAG ⇒ DROP-IN" argument does not hold
`max blues_anticone_size = 9 < K` measures anticone **width**. The two buggy
walks are bounded by chain **depth** (`past_blue_set` at `K*100 = 1000` selected
hops; `is_ancestor` at `1024`). A deep, narrow chain still truncates the blue-set
seed. Width statistics cannot rule out a depth-cap divergence — only the replay
harness against the real datadir can.

## Mechanism (the incident this fixes) — CORRECTED

`classify_mergeset` seeds the blue set with a `K*100`-bounded `past_blue_set`
walk. Past the cap it `warn!`s and drops blue ancestors → the seed is incomplete.
The corrected causal chain (note: the DAA does **not** read the blue set):

```
bounded blue set  →  divergent blue_work/blue_score
  →  divergent selected_parent (argmax blue_work)
    →  divergent SELECTED-PARENT timestamp
      →  divergent ASERT expected_bits  (src/pow/mod.rs:77 next_bits, a function
         of anchor + selected-parent timestamp + height ONLY)
        →  "invalid difficulty" rejection at height ~394630
          →  selected chain freezes at blue_score 395897  (syncing: true)
```

Earlier text called this a "wrong window into the DAA." That is imprecise: the
DAA is a **victim** of the divergent selected parent, not a consumer of the blue
set. The fix — exact classification → correct selected_parent → matching bits —
is unchanged.

## Token / history preservation

Historical blocks are loaded verbatim from `CF_DAG` and **never recomputed**
(`load_persisted` / `load_persisted_validated`), regardless of coloring mode. So
every mined block/balance is byte-identical and there is no history reorg.
Enabling `Fast` affects only **new** blocks' classification — which is exactly
why activation must be network-coordinated (a live fork between mixed nodes, not
a history reorg).

## The durable reachability index (new)

- New column family `CF_REACHABILITY` (+ `reachability/meta/version` and
  `reachability/meta/root` in `CF_META`). A **non-consensus cache**: never part
  of the integrity chain; rebuildable.
- Written **atomically with `CF_DAG`** in the same `WriteBatch`
  (`put_dag_with_integrity_and_reach`), in the same deferred post-UTXO window, so
  a crash leaves it all-or-nothing consistent. Refused reorgs roll it back with
  `remove_block`.
- On boot (only when the index is maintained): load from the CF if the version
  matches and coverage is complete; otherwise **rebuild** from `CF_DAG` by
  replaying the same `add_block` path in topological order. A random-sample
  self-check against the brute-force oracle gates acceptance. No peer resync.

## Step 1 — build + deploy OFF (safe on every node, independent)

```sh
cd ~/bloch && git fetch && git checkout feat/reachability-durable
# Leave CORRECTED_COLORING_ACTIVATION_HEIGHT = u64::MAX (default, OFF).
cargo build --release
sudo systemctl restart bloch-node
```
This is safe to roll out node-by-node: with the gate OFF the node is byte-for-byte
`Legacy` and `CF_REACHABILITY` stays untouched.

Optional dev/test check on a **throwaway** datadir (node-local, NOT activation):
```sh
BLOCH_GHOSTDAG_COLORING=fast cargo run --release -- <node args>   # exercises Fast + durable index
```

## Step 2 — prove the divergence set against the real datadir (read-only)

```sh
BLOCH_SNAPSHOT=/path/to/a/node/data-dir \
  cargo test --release --test ghostdag_replay_snapshot \
    replay_snapshot_legacy_vs_fast -- --ignored --nocapture
```
Read-only (never writes the snapshot). Reports the lowest diverging height, a
decision-flip vs metadata-only breakdown, and whether `Fast` advances past
`blue_score 395897` where `Legacy` stalled. Also available: `dag_shape_stats`.

## Step 3 — coordinated activation (founder / network, the only live change)

1. Choose a **future** height `H` > current tip at upgrade time.
2. Set `CORRECTED_COLORING_ACTIVATION_HEIGHT = H` and rebuild.
3. Ensure ALL mining/validating nodes deploy the same `H` **before** the tip
   reaches it. Below `H`: `Legacy`. At/above `H`: `Fast`.
4. Setting `H` ≤ current tip is FORBIDDEN (would recolor mined blocks).

Verify: `bloch-cli dag` (chain_length climbing again past the stall),
`bloch-cli peers` (`syncing` clears once caught up).

## Rollback

- Gate OFF: fully safe — revert the binary; `CF_REACHABILITY` is inert.
- After activation: a coordinated down-grade (all nodes revert `H`), subject to
  the same fork caveat as any soft-fork reversal.

## Notes

- The reachability index is a cache (own column family, never in the integrity
  chain); it rebuilds deterministically on restart and cannot corrupt the DAG.
- No existing test's expected values changed by making `Fast` exact — the
  `identical_*` differential tests still assert `Legacy == Fast` and pass, because
  those shapes never hit a cap in a result-affecting way. Any future expectation
  change from exact classification is the OLD value being the bug; flag it for
  founder review.
