//! Bloch-SIS Protocol — Reorg detection & execution (Sprint U.3).
//!
//! Pure functions that compute *what* a reorg looks like (`compute_reorg_plan`)
//! and *perform* one against storage + mempool (`execute_reorg`). This module
//! is deliberately disconnected from `accept_block` in main.rs — Sprint U.4 is
//! responsible for wiring these primitives into the node event loop.
//!
//! # Rationale for splitting U.3 / U.4
//!
//! `accept_block` is large (1100+ lines) and couples DAG insertion, storage
//! mutations, mempool updates, node-state locks, and RPC-visible metrics.
//! Introducing a reorg path inside it safely requires an end-to-end test
//! harness, which is U.4's scope. U.3 delivers the pieces that harness will
//! drive, with their own unit tests against mock DAG data and small fixture
//! blocks so the algorithms can be validated in isolation.
//!
//! # Audit reference
//!
//! Finding **C-1** — `accept_block` is forward-only, so a fork with higher
//! blue work silently leaves the UTXO state inconsistent. U.1 persisted undo
//! data; U.2 added `rollback_block`; U.3 adds reorg planning and execution;
//! U.4 will integrate and test end-to-end.

use std::collections::HashSet;

use crate::consensus::{BlockHash, GhostDAG};
use crate::core::{Block, Transaction, UndoData, UndoEntry};
use crate::mempool::Mempool;
use crate::storage::Storage;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// The steps needed to move the selected chain tip from one block to another.
///
/// `to_rollback` is ordered *tip-first*: the first element is the current
/// tip, the last element is the child of the LCA. Rolling back in this order
/// undoes each block's mutations cleanly because each `rollback_block` call
/// is self-contained (reads UndoData, replays in reverse).
///
/// `to_apply` is ordered *LCA-first*: the first element is the child of the
/// LCA on the new chain, the last element is the new tip. Applying in this
/// order mirrors how `accept_block` builds state forward.
///
/// Note: the LCA block itself appears in neither vector — it is the common
/// root that stays in place throughout the reorg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorgPlan {
    pub lca:         BlockHash,
    pub to_rollback: Vec<BlockHash>,
    pub to_apply:    Vec<BlockHash>,
}

/// Statistics returned by `execute_reorg`. Fed into logs / metrics by the
/// U.4 caller. All counts reflect successful operations only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReorgOutcome {
    pub rolled_back:    usize,
    pub applied:        usize,
    pub txs_reinjected: usize,
    pub txs_discarded:  usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// LCA computation
// ─────────────────────────────────────────────────────────────────────────────

/// Walk the selected-parent chain from `start` up to genesis, collecting
/// every hash we visit. Used by `find_lca` to mark A's ancestors so we can
/// scan B's ancestors for the first intersection.
///
/// The walk terminates at genesis (selected_parent = None) or when a
/// referenced selected_parent is absent from the DAG — the latter should
/// never happen on a consistent store but we don't panic on it.
fn collect_selected_ancestors(
    dag: &GhostDAG,
    start: &BlockHash,
) -> HashSet<BlockHash> {
    let mut out = HashSet::new();
    let mut cur = Some(*start);
    while let Some(h) = cur {
        if !out.insert(h) {
            // Cycle (shouldn't happen on a DAG) — break to avoid infinite loop.
            break;
        }
        cur = match dag.get_block_data(&h) {
            Some(data) => data.selected_parent,
            None       => None,
        };
    }
    out
}

/// Find the lowest common ancestor of two blocks along their selected-parent
/// chains. Returns None if the two chains never intersect — this indicates
/// either a corrupted DAG or blocks from incompatible genesis, and the
/// caller should refuse to reorg.
///
/// Runtime: O(depth_a + depth_b). For within-finality-window reorgs
/// (depth ≤ CHECKPOINT_DEPTH = 1000) this is trivially fast.
pub fn find_lca(
    dag: &GhostDAG,
    a: &BlockHash,
    b: &BlockHash,
) -> Option<BlockHash> {
    if a == b { return Some(*a); }

    let a_ancestors = collect_selected_ancestors(dag, a);

    // Walk B's chain; first hit in A's ancestor set is the LCA.
    let mut cur = Some(*b);
    while let Some(h) = cur {
        if a_ancestors.contains(&h) {
            return Some(h);
        }
        cur = dag.get_block_data(&h).and_then(|d| d.selected_parent);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Plan computation
// ─────────────────────────────────────────────────────────────────────────────

/// Build the path from `start` along selected_parent, EXCLUSIVE of `stop`.
/// Returns tip-first ordering: path[0] == start.
///
/// Returns None if `stop` is not reachable from `start` via selected_parent
/// (caller should have verified via find_lca first; this is defensive).
fn selected_path_to(
    dag: &GhostDAG,
    start: &BlockHash,
    stop: &BlockHash,
) -> Option<Vec<BlockHash>> {
    let mut path = Vec::new();
    let mut cur = Some(*start);
    while let Some(h) = cur {
        if h == *stop { return Some(path); }
        path.push(h);
        cur = dag.get_block_data(&h).and_then(|d| d.selected_parent);
    }
    None  // walked to genesis without hitting stop
}

/// Compute the rollback + apply sequence needed to move the selected chain
/// tip from `old_tip` to `new_tip`.
///
/// Returns `None` — meaning no reorg is needed / possible — in these cases:
///
///   * `old_tip == new_tip`: trivially a no-op.
///   * `old_tip` is an ancestor of `new_tip`: this is a forward extension,
///     not a reorg. Caller should use the normal accept_block path.
///   * `new_tip` is an ancestor of `old_tip`: this would be going backwards
///     and shouldn't be a valid state transition; we refuse.
///   * The two chains share no common ancestor: DAG corruption or
///     cross-genesis blocks.
///
/// A returned plan has both `to_rollback` and `to_apply` non-empty.
pub fn compute_reorg_plan(
    dag: &GhostDAG,
    old_tip: &BlockHash,
    new_tip: &BlockHash,
) -> Option<ReorgPlan> {
    if old_tip == new_tip { return None; }

    let lca = find_lca(dag, old_tip, new_tip)?;

    // Forward extension case: the "old tip" IS the LCA, meaning new_tip is
    // a descendant. That's just a chain extension, not a reorg.
    if lca == *old_tip { return None; }

    // Backward case: new_tip is an ancestor of old_tip. Refuse.
    if lca == *new_tip { return None; }

    // Build the two paths. Each excludes the LCA itself — the LCA stays in
    // place, its state is untouched by the reorg.
    let to_rollback = selected_path_to(dag, old_tip, &lca)?;
    let to_apply_reversed = selected_path_to(dag, new_tip, &lca)?;

    // to_apply_reversed is tip-first; we need LCA-first so the caller can
    // replay mutations in natural forward order.
    let mut to_apply = to_apply_reversed;
    to_apply.reverse();

    // Defensive: both paths must be non-empty by construction (we excluded
    // equal-tip and ancestor cases above) but assert rather than silently
    // emit a malformed plan.
    if to_rollback.is_empty() || to_apply.is_empty() {
        return None;
    }

    Some(ReorgPlan { lca, to_rollback, to_apply })
}

// ─────────────────────────────────────────────────────────────────────────────
// Block UTXO mutation (forward apply)
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a block's UTXO / tx_index / coinbase_info mutations forward,
/// capturing UndoData so the block can later be rolled back.
///
/// Mirrors the mutation loop of `accept_block` in main.rs deliberately —
/// same ordering (put_tx_index → put_utxo per output → put_coinbase_info OR
/// capture-and-delete per input) so the UndoData captured here is shaped
/// identically to what `accept_block` produces for forward accepts. This
/// symmetry is load-bearing: `rollback_block` (U.2) works on either.
///
/// Intended for use when a block was accepted and its UndoData was later
/// pruned (shouldn't normally happen within finality window) OR when reorg
/// re-applies a block from the new chain.
///
/// # Errors
///
/// Returns Err only if `put_undo_data` fails. Individual UTXO writes use
/// `let _ =` to stay best-effort consistent with accept_block's semantics
/// (errors there are logged but don't abort the block).
pub fn apply_block_utxo_mutations(
    store: &Storage,
    block: &Block,
) -> Result<(), String> {
    let block_hash = block.block_hash();
    let mut undo = UndoData::new(block_hash, block.height);

    for tx in &block.transactions {
        let txid = tx.txid();

        let _ = store.put_tx_index(&txid, &block_hash, block.height);
        undo.tx_index_keys.push(txid);

        for (j, out) in tx.outputs.iter().enumerate() {
            let _ = store.put_utxo(&txid, j as u32, out);
            undo.created_utxo_keys.push((txid, j as u32));
        }

        if tx.is_coinbase() {
            let _ = store.put_coinbase_info(&txid, block.height);
            undo.coinbase_txids.push(txid);
        } else {
            for inp in &tx.inputs {
                // Capture BEFORE delete so rollback can restore the pre-spend output.
                if let Ok(Some(output)) = store.get_utxo(&inp.prev_txid, inp.prev_index) {
                    undo.spent_utxos.push(UndoEntry {
                        prev_txid:  inp.prev_txid,
                        prev_index: inp.prev_index,
                        output,
                    });
                }
                let _ = store.delete_utxo(&inp.prev_txid, inp.prev_index);
            }
        }
    }

    store.put_undo_data(&block_hash, &undo)
        .map_err(|e| format!("apply_block_utxo_mutations: put_undo_data failed: {}", e))
}

/// SECURITY (audit H1): re-validate a fork block's transactions against the
/// *incrementally-reorged* UTXO state before applying it during a reorg.
///
/// Signatures are state-independent and were already verified at accept time,
/// so we re-check only the rules that differ between the accept-time
/// (main-chain) view and the fork's own context: input existence, no
/// double-spend, value conservation, and coinbase maturity. Without this, a
/// fork-loser block that spends an output which only ever existed on the main
/// chain — or that double-spends — would be applied unvalidated and mint coins
/// from nothing when the fork wins.
fn validate_fork_block_state(store: &Storage, block: &Block) -> Result<(), String> {
    use std::collections::{HashMap, HashSet};
    // Outputs created earlier in THIS block (outpoint -> value) so a later tx
    // can spend an earlier one; coinbase outputs are tracked separately because
    // they are immature to spend within the same block.
    let mut created: HashMap<([u8; 32], u32), u64> = HashMap::new();
    let mut created_coinbase: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut spent: HashSet<([u8; 32], u32)> = HashSet::new();

    for tx in &block.transactions {
        let txid = tx.txid();
        if !tx.is_coinbase() {
            let mut in_sum: u64 = 0;
            for inp in &tx.inputs {
                let op = (inp.prev_txid, inp.prev_index);
                if !spent.insert(op) {
                    return Err(format!("double-spend of {}:{} within fork block",
                        hex::encode(&op.0[..4]), op.1));
                }
                let val = if let Some(v) = created.get(&op) {
                    if created_coinbase.contains(&op) {
                        return Err(format!("spends immature same-block coinbase {}:{}",
                            hex::encode(&op.0[..4]), op.1));
                    }
                    *v
                } else {
                    match store.get_utxo(&inp.prev_txid, inp.prev_index) {
                        Ok(Some(out)) => out.value,
                        _ => return Err(format!("input {}:{} absent from reorged UTXO set",
                            hex::encode(&op.0[..4]), op.1)),
                    }
                };
                in_sum = in_sum.saturating_add(val);
            }
            let out_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
            if in_sum < out_sum {
                return Err(format!("value violation: inputs {} < outputs {}", in_sum, out_sum));
            }
            crate::core::check_coinbase_maturity(tx, block.height, |t| {
                store.get_coinbase_height(t).ok().flatten()
            })?;
        }
        for (j, out) in tx.outputs.iter().enumerate() {
            let op = (txid, j as u32);
            created.insert(op, out.value);
            if tx.is_coinbase() { created_coinbase.insert(op); }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mempool reinject (with validation)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute a transaction's fee by looking up each input's prev output in
/// the CURRENT UTXO set. Also returns whether every input resolved —
/// a tx with missing inputs is invalid in the post-reorg state and must
/// not be reinjected.
///
/// Returns `(fee, all_inputs_present)`.
fn compute_fee_and_validate(
    store: &Storage,
    tx: &Transaction,
) -> (u64, bool) {
    let mut input_sum: u64 = 0;
    for inp in &tx.inputs {
        match store.get_utxo(&inp.prev_txid, inp.prev_index) {
            Ok(Some(out)) => input_sum = input_sum.saturating_add(out.value),
            _             => return (0, false),
        }
    }
    let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let fee = input_sum.saturating_sub(output_sum);
    (fee, true)
}

/// Attempt to reinject one tx into the mempool, validating against the
/// current UTXO set. Returns true if reinjected, false if discarded.
///
/// Reasons for discarding:
///   * Any input UTXO missing from the current set (the new chain spent it
///     elsewhere, or it was created by a rolled-back block that the new
///     chain doesn't include).
///   * Tx already present in mempool (shouldn't happen but defensive —
///     without this we'd double-count a reinject).
///   * mempool.add rejects (e.g. oversized, malformed, output overflow —
///     these are checks `accept_block` didn't make at acceptance time).
fn try_reinject(
    store: &Storage,
    mempool: &Mempool,
    tx: &Transaction,
) -> bool {
    if mempool.contains(&tx.txid()) { return false; }

    let (fee, valid) = compute_fee_and_validate(store, tx);
    if !valid { return false; }

    mempool.add(tx.clone(), fee).is_ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a reorg plan against storage + mempool.
///
/// # Phases
///
/// 1. **Rollback** each block in `plan.to_rollback` (tip-first). For each
///    rolled-back block, collect non-coinbase txs as reinject candidates.
/// 2. **Apply** each block in `plan.to_apply` (LCA-first). Each apply
///    captures fresh UndoData so the new chain is also reorg-capable.
/// 3. **Reinject** candidate txs into the mempool, validating each against
///    the now-current UTXO set. Invalid ones are counted as discarded.
///
/// # Preconditions
///
/// * Every hash in `plan.to_rollback` has a persisted block body and undo
///   record (post-U.1 accepts always do; pre-U.1 blocks within the reorg
///   window should never exist in practice).
/// * Every hash in `plan.to_apply` has a persisted block body whose UTXO
///   mutations have NOT been applied yet. (This is true for blocks that
///   were inserted into the DAG as non-selected tips.)
///
/// # Failure mode
///
/// A rollback error aborts the reorg immediately — storage may be in a
/// half-rolled-back state, which is worse than where we started. Callers
/// should treat this as unrecoverable and shut down / alert. The forward
/// apply errors log and continue (best-effort), matching accept_block.
///
/// # Caller concerns (NOT handled here)
///
/// * Updating `selected_chain_tip` / `current_bits` / `finalized_height`
///   meta keys — that's U.4's plumbing.
/// * Locking the DAG / node_state — U.4 coordinates higher-level locks.
/// * RPC event emission — U.4 emits reorg events post-hoc from the outcome.
pub fn execute_reorg(
    store: &Storage,
    mempool: &Mempool,
    plan: &ReorgPlan,
) -> Result<ReorgOutcome, String> {
    // Sprint FF observability: record every attempt and surface the fork
    // depth before we start mutating. A failure below leaves storage in a
    // partial state, so the failures counter is the one to alert on.
    crate::metrics::inc_reorg_attempt();
    crate::metrics::set_fork_depth(plan.to_rollback.len() as i64);
    let result = execute_reorg_inner(store, mempool, plan);
    if result.is_err() {
        crate::metrics::inc_reorg_failure();
    }
    result
}

fn execute_reorg_inner(
    store: &Storage,
    mempool: &Mempool,
    plan: &ReorgPlan,
) -> Result<ReorgOutcome, String> {
    let mut candidate_txs: Vec<Transaction> = Vec::new();

    // Phase 1: Rollback old chain (tip-toward-LCA). Keep the block bodies so
    // the original chain can be restored if a fork block fails re-validation.
    let mut rolled_back_blocks: Vec<Block> = Vec::new();
    for hash in &plan.to_rollback {
        // Capture the block's non-coinbase txs BEFORE rollback mutates state
        // (though get_block reads CF_BLOCKS, which rollback never touches —
        // order is correct either way, we read first for clarity).
        let block = store.get_block(hash)
            .map_err(|e| format!("execute_reorg: get_block on rollback target failed: {}", e))?
            .ok_or_else(|| format!("execute_reorg: block body missing for rollback target"))?;

        for tx in &block.transactions {
            if !tx.is_coinbase() {
                candidate_txs.push(tx.clone());
            }
        }

        store.rollback_block(hash)
            .map_err(|e| format!(
                "execute_reorg: rollback failed at h={} (reorg aborted, storage in partial state): {}",
                block.height, e
            ))?;
        // Shielded-state undo (Sprint U.4 live-wiring). AUDIT CORRECTION: a bare
        // LIFO pop is NOT safe here. `apply_block_self` currently runs for EVERY
        // accepted block (incl. side/losing forks, at main.rs), so the undo stack
        // is in ARRIVAL order, not selected-chain order. Correct U.4 wiring:
        //  (a) shielded state must mutate ONLY on selected-chain connect/disconnect
        //      — move the accept-path `apply_block_self` into the connect
        //      transition so the undo stack IS the selected chain;
        //  (b) here, call `shielded.write().disconnect_block_self(hash)` per
        //      rolled-back block (tip-first). It is now identity-keyed and returns
        //      `ReorgOrderMismatch` rather than undo the wrong block;
        //  (c) Phase 2 calls `apply_block_self(fork_hash, &b.shielded_transactions)`
        //      per applied fork block, and RE-ADMITS dropped shielded txs to the
        //      shielded mempool (currently lost — liveness).
        // Mechanism + exact-reversal/order-guard tests: `coherence::ShieldedEngine`.
        // Whole path is LATENT today (RejectAll makes shielded txs never apply).
        rolled_back_blocks.push(block);
    }

    // Phase 2: Validate THEN apply new chain (LCA-toward-tip). Each fork block
    // is re-validated against the incrementally-reorged UTXO state (audit H1).
    // If any block is invalid, abort and restore the original chain so a
    // rejected reorg never leaves a corrupted / coins-from-nothing UTXO set.
    let mut applied: Vec<[u8; 32]> = Vec::new();
    for hash in &plan.to_apply {
        let block = store.get_block(hash)
            .map_err(|e| format!("execute_reorg: get_block on apply target failed: {}", e))?
            .ok_or_else(|| format!("execute_reorg: block body missing for apply target"))?;

        if let Err(reason) = validate_fork_block_state(store, &block) {
            log::error!(
                "execute_reorg: fork block h={} failed re-validation ({}); aborting reorg, restoring original chain",
                block.height, reason
            );
            // Undo what we applied (tip-first), then re-apply the original
            // chain (LCA-first = reverse of the tip-first rollback order).
            for h in applied.iter().rev() { let _ = store.rollback_block(h); }
            for b in rolled_back_blocks.iter().rev() { let _ = apply_block_utxo_mutations(store, b); }
            return Err(format!("reorg aborted: fork block h={} invalid: {}", block.height, reason));
        }

        apply_block_utxo_mutations(store, &block)
            .map_err(|e| format!("execute_reorg: apply_block_utxo_mutations failed at h={}: {}", block.height, e))?;
        applied.push(*hash);
    }

    // Phase 3: Reinject valid, validate-rejected txs into mempool.
    // UTXO set now reflects the new chain; any tx whose inputs survive is
    // still spendable.
    let mut txs_reinjected = 0;
    let mut txs_discarded  = 0;
    for tx in candidate_txs {
        if try_reinject(store, mempool, &tx) {
            txs_reinjected += 1;
        } else {
            txs_discarded  += 1;
        }
    }

    Ok(ReorgOutcome {
        rolled_back:    plan.to_rollback.len(),
        applied:        plan.to_apply.len(),
        txs_reinjected,
        txs_discarded,
    })
}
