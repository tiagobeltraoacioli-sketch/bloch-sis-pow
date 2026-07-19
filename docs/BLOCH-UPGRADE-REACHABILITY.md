<!-- SPDX-License-Identifier: MIT -->
# BLOCH Upgrade — Durable Interval-Reachability + Exact GHOSTDAG Coloring

**Status: candidate, UNAUDITED — review + test before any coordinated activation.**
Branch: `feat/reachability-durable` (builds on `fix/ghostdag-reachability`).
Live default: **OFF** (`CORRECTED_COLORING_ACTIVATION_HEIGHT = u64::MAX`).

This is the canonical ADR for replacing the two bounded (silently-approximating)
GHOSTDAG ancestry walks with an exact interval-reachability index, and for making
that index **durable** so it survives restarts. It supersedes the "DROP-IN /
no-coordination" verdict in the earlier operations runbook (see the correction in
§4 and `docs/operations/UPGRADE-ghostdag-reachability.md`).

---

## 1. The two silent-approximation walks (the bug)

Consensus classification (`src/consensus/mod.rs`) answered DAG questions with two
**bounded** walks that silently clamp and under-count on deep DAGs:

1. `past_blue_set` (`:1119`) seeds a block's blue set by walking the
   selected-parent chain, capped at `K*100 = 1000` hops, then `warn!` + `break`.
   Beyond the cap it **drops** blue ancestors → the seed blue set (and the
   `blues_anticone_sizes` map derived from it) is incomplete.
2. `is_ancestor` (`:291`) answers DAG-ancestry with a backwards BFS capped at
   `MAX_REACHABILITY_DEPTH = 1024` (plus a `depth_limit*10` visited cap). When the
   height-difference exceeds the cap it can return a **false negative**.

Both are consensus-divergence vectors: two nodes that hit the cap differently
compute different colorings for the same block.

The exact replacement already exists: `src/consensus/reachability.rs` — an
interval-labeling + future-covering-set (FCS) index giving `is_chain_ancestor`
O(1) and `is_dag_ancestor` O(log n), validated against a brute-force oracle. The
`Fast` coloring mode routes all anticone tests through it, and (this branch) also
seeds the blue set through the **unbounded** `past_blue_set_unbounded`, so **no
silent-approximation walk remains reachable once `Fast` is active.**

---

## 2. The incident mechanism — CORRECTED

The earlier runbook described the stall as a "wrong window into the DAA." That is
**imprecise** and is corrected here.

The difficulty/DAA (`expected_bits`) is computed by `src/pow/mod.rs:77 next_bits`
= **ASERT-Lattice**, anchored, a function ONLY of:

> `(anchor, SELECTED-PARENT timestamp, height)`.

It does **not** consume the blue set. So the blue set never feeds the DAA
directly. The real causal chain is one hop longer, through the selected parent:

```
bounded blue set (past_blue_set / is_ancestor cap under-counts)
    → divergent blue_work / blue_score on affected blocks
        → divergent selected_parent (argmax blue_work; ties by blue_score, hash)
            → divergent SELECTED-PARENT timestamp
                → divergent ASERT expected_bits  (pow::next_bits)
                    → "invalid difficulty" rejection at height ~394630
                        → virtual/selected chain freezes at blue_score 395897
                            → node reports syncing:true, network fails to converge
```

The fix is unchanged in spirit: **exact classification → correct
`selected_parent` → matching `expected_bits` → the block validates.** Only the
mechanism text ("wrong window into the DAA") needed correcting: the DAA is a
victim of the divergent selected parent, not a direct consumer of the blue set.

---

## 3. What this branch delivers

### 3.1 Exact `Fast` coloring (no reachable approximation)
`classify_mergeset_fast` now seeds from `past_blue_set_unbounded` (no `K*100`
cap) and tests anticones through the interval index (no `is_ancestor` cap). On
any DAG where neither cap bit, this is **byte-identical** to `Legacy`; where a cap
bit, it returns the complete (oracle-correct) answer.

### 3.2 Durable reachability index (new column family)
- `CF_REACHABILITY`: key = 32-byte block hash, value = a deterministic per-block
  record (`interval` 2×u64, `remaining` 2×u64, `tree_parent`, `children`, `fcs`).
- Version tag `reachability/meta/version` and `reachability/meta/root` in
  `CF_META`. Version bump ⇒ rebuild on boot.
- **Atomic coupling:** each insert's reachability delta (which can span many
  blocks when a reindex reshuffles a subtree — not just the new block) is written
  in the **same `WriteBatch`** as `CF_DAG` + `CF_DAG_INTEGRITY`
  (`Storage::put_dag_with_integrity_and_reach`), wired into the SAME deferred
  post-UTXO write window as the DAG (`main.rs` accept path + mining loop). A
  crash leaves the index all-or-nothing consistent with the block set. Refused
  reorgs roll the index back alongside `remove_block` (`remove_leaf` tombstones).
- **Non-consensus:** the index is a rebuildable cache. It is NEVER hashed into the
  integrity chain and can be discarded/rebuilt without affecting any balance.

### 3.3 Boot: load-or-rebuild migration
On boot, when the index is maintained (Fast / armed):
- If `CF_REACHABILITY` carries the matching version and covers every `CF_DAG`
  block → load it directly (no O(chain) recompute).
- Else rebuild by replaying the **same** `reach.add_block` code path in Kahn
  topological order (`rebuild_reachability_from_store`) — no separate bulk
  algorithm — then persist the fresh snapshot.
- Either way, a random-sample self-check against the brute-force oracle
  (`reach_self_check_sample`) runs before the index colors any new block; a
  loaded index that fails is rebuilt once. **No peer resync.**

### 3.4 Activation shape — OFF by default (Phase 3)
- `CORRECTED_COLORING_ACTIVATION_HEIGHT` stays `u64::MAX` =
  `TBD_COORDINATED_RELEASE`. Nothing on the live chain changes from this branch.
- A dev/test env override `BLOCH_GHOSTDAG_COLORING=fast`
  (`GhostDAG::with_default_k_env`) exercises `Fast` on a **throwaway** datadir.
  It is node-local — NOT a network activation, and cannot substitute for setting
  the height.
- Historical blocks are loaded verbatim from `CF_DAG` and never recomputed, so
  every already-mined block/balance is preserved unconditionally regardless of
  the coloring mode.

---

## 4. Fork status — CORRECTION to the earlier "DROP-IN" verdict

The earlier operations runbook concluded **DROP-IN — no fork, enable at height
`0`.** That conclusion is **retracted here as unsafe** for one reason: the chain
actually stalled (§2), which is only possible if a bounded walk **did** bite on
real history. Where a cap bit, `Legacy` and the exact `Fast` classification
differ on **new** blocks, so two nodes running different coloring would fork.
Adopting `Fast` is therefore a **consensus change requiring coordination**, not a
transparent per-node speedup.

- Enabling `Fast` does NOT recompute stored history (loaded verbatim), so it is
  not a history reorg. The risk is purely a **live fork** between upgraded and
  un-upgraded nodes on newly-mined blocks.
- Whether `Fast == Legacy` on the specific real history is an **empirical**
  question the operator settles by running the replay harness against the real
  (stalled) datadir — see §5. On a truly narrow chain they may still be
  identical; the stall is evidence they are not.

The DAG-shape statistic in the old runbook (`max blues_anticone_size = 9 < K`)
measures **anticone width**, which the depth caps do not depend on. The caps are a
chain-**depth** phenomenon: a deep selected chain (> 1000 hops) truncates the blue
set even when every anticone is narrow. So "narrow ⇒ DROP-IN" does not follow.

---

## 5. Operator procedure for a coordinated activation (the remaining step)

This is the ONLY step that changes live behavior, and it is owned by the
operator/network, not by this branch:

1. **Prove the divergence set.** Against the real (stalled) datadir, read-only:
   ```sh
   BLOCH_SNAPSHOT=/path/to/data-dir \
     cargo test --release --test ghostdag_replay_snapshot \
       replay_snapshot_legacy_vs_fast -- --ignored --nocapture
   ```
   It reports: lowest diverging height, a decision-flip vs metadata-only
   breakdown, and whether `Fast` advances past `blue_score 395897` where `Legacy`
   stalled. Divergence is expected here (that is the bug); the point is to bound
   it.
2. **Pick a future height** `H` strictly greater than the current tip at the
   coordinated upgrade moment. Set `CORRECTED_COLORING_ACTIVATION_HEIGHT = H`.
   Setting `H` at or below the tip is FORBIDDEN (it would recolor mined blocks).
3. **Coordinate.** All mining/validating nodes deploy the same `H` before the tip
   reaches it. Below `H` every node stays on `Legacy`; at/above `H` every node
   uses `Fast`. This is a **soft-fork-style coordinated activation.**
4. On boot the durable index loads or rebuilds and self-checks before `H`, so
   `Fast` classification is ready when the tip crosses `H`.

Until step 2 is taken, the shipped binary is byte-for-byte `Legacy` on the live
chain.

---

## 6. Test evidence (this branch)

- `cargo test -p bloch --test ghostdag_differential` — `Legacy == Fast`
  byte-identical on linear/merging/wide/random shapes (the caps did not bite);
  `index_matches_oracle_all_shapes` (index == unbounded oracle);
  `offline_proof_fast_exact_where_legacy_undercounts` — deep merging DAG (depth
  ≈ 400 > cap 300) where the `past_blue_set` cap bites: **147/601 blocks diverge,
  Fast == oracle throughout, Fast's blue set is a strict superset of Legacy's at
  every divergence (Legacy under-counts, never the reverse).**
- `cargo test -p bloch --test reachability_persistence` — atomic write, reload,
  from-CF_DAG rebuild migration, reload==rebuild equivalence; each self-checks
  against the oracle.
- `cargo test -p bloch --lib reachability` — encode/decode round-trip + delta
  drain reconstructs the full index.
- `ghostdag_replay_snapshot` (ignored) — the operator's real-datadir harness.

**No existing test's expected values changed** as a result of making `Fast`
exact: every `identical_*` differential test still asserts `Legacy == Fast` and
still passes, because none of those shapes hit a cap in a result-affecting way.
If a future test's expectation changes because classification became exact, treat
the OLD expectation as the bug and flag it explicitly for founder review.

---

## 7. Rollback

Fully safe while the gate is OFF: revert the binary; `CF_REACHABILITY` is an
inert cache. After a coordinated activation, rollback is a coordinated
down-grade (all nodes revert `H`) and is subject to the same fork caveat as any
soft-fork reversal.
