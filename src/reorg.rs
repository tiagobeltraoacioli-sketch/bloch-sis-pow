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

use std::collections::{HashMap, HashSet};

use crate::consensus::{BlockHash, GhostDAG};
use crate::core::{Block, Transaction, TxOutput, UndoData, UndoEntry};
use crate::mempool::Mempool;
use crate::storage::Storage;

// ─────────────────────────────────────────────────────────────────────────────
// Reorg depth cap (security hardening)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum reorg depth — the number of selected-chain blocks `execute_reorg`
/// may roll back in one plan. Anchored to the finality window
/// (`core::CHECKPOINT_DEPTH`): `accept_block` already refuses blocks at or
/// below the finalized height, so any plan deeper than this window indicates
/// either a bug in plan computation or an attack attempt to unwind history.
/// Such plans are refused with [`ERR_REORG_DEPTH`] before ANY storage access.
#[cfg(not(test))]
pub const MAX_REORG_DEPTH: u64 = crate::core::CHECKPOINT_DEPTH;

/// Test builds use a tiny cap so the accept-path depth-cap regression
/// (`refused_deep_reorg_must_not_poison_dag_selected_tip` in src/main.rs)
/// can drive whole real chains through `accept_block` in milliseconds
/// instead of building 1000-block fixtures. All depth-cap unit tests in
/// this file are written against the symbolic constant, so they hold at
/// any value. Production (non-test) builds are unchanged: the cap stays
/// anchored to the finality window, and integration tests in tests/ link
/// the library crate compiled WITHOUT `cfg(test)`, so they too see the
/// production value.
#[cfg(test)]
pub const MAX_REORG_DEPTH: u64 = 4;

/// Distinct, machine-matchable error marker for a refused too-deep reorg.
/// Callers (and tests) can distinguish "refused by policy" from "failed
/// mid-execution" by matching on this substring.
pub const ERR_REORG_DEPTH: &str = "reorg depth exceeds maximum";

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

// ─────────────────────────────────────────────────────────────────────────────
// Atomic reorg batch (crash-consistency hardening)
// ─────────────────────────────────────────────────────────────────────────────
//
// SECURITY: `execute_reorg` previously mutated storage in place, block by
// block (rollback_block / apply_block_utxo_mutations). A crash — or a
// mid-reorg error such as a missing undo record — left the chain state
// half-applied: some blocks rolled back, others not, with no recovery marker.
// `ReorgBatch` stages EVERY chain-switch mutation into a single RocksDB
// `WriteBatch` and commits it with one `db.write()` call, which RocksDB
// guarantees is atomic. Any error before the commit simply drops the batch:
// storage is byte-identical to the pre-reorg state.
//
// Because staged writes are not visible to reads until commit, the batch
// keeps an in-memory overlay for the two column families the reorg logic
// reads back during staging (UTXO set + coinbase index). Reads go
// overlay-first, then fall through to the committed DB — this is what lets
// `validate_fork_block_state` (audit H1) see the *incrementally-reorged*
// state while nothing has hit disk yet.
//
// Key/value layouts and CF names below MIRROR src/storage/mod.rs exactly
// (utxo_key / addr_utxo_key / put_tx_index / put_coinbase_info /
// put_undo_data and the CF_* constants — those are private to the storage
// module, so they are replicated here byte-for-byte). The
// `reorg_batch_column_families_exist` unit test guards against CF renames;
// `reorg.rs` staging drifting from `storage.rs` layouts would be caught by
// the state-equality integration tests (tests/reorg_hardening.rs).

const CF_UTXO:            &str = "utxo";
const CF_ADDR_UTXO:       &str = "addr_utxo";
const CF_COINBASE:        &str = "coinbase";
const CF_TX_INDEX:        &str = "tx_index";
const CF_UNDO:            &str = "undo";
const CF_ADDR_TX_HISTORY: &str = "addr_tx_history";

/// UTXO key: `[txid][4B index LE]` — mirrors `storage::utxo_key`.
fn utxo_key(txid: &[u8; 32], index: u32) -> Vec<u8> {
    let mut k = txid.to_vec();
    k.extend_from_slice(&index.to_le_bytes());
    k
}

/// Address-index key: `[script_pubkey][txid][4B index LE]` — mirrors
/// `storage::addr_utxo_key` (which receives the full script_pubkey).
fn addr_utxo_key(script_pubkey: &[u8], txid: &[u8; 32], index: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(script_pubkey.len() + 36);
    k.extend_from_slice(script_pubkey);
    k.extend_from_slice(txid);
    k.extend_from_slice(&index.to_le_bytes());
    k
}

/// bincode encoding identical to the storage module's private `encode`.
fn bc_encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e| format!("reorg batch: encode failed: {}", e))
}

/// All chain-switch mutations staged for one atomic commit, with an overlay
/// so staged UTXO / coinbase state is readable before the commit.
struct ReorgBatch<'a> {
    store: &'a Storage,
    batch: rocksdb::WriteBatch,
    /// utxo_key → Some(output) if staged-created/restored, None if staged-deleted.
    utxo_overlay: HashMap<Vec<u8>, Option<TxOutput>>,
    /// coinbase txid → Some(height) if staged-put, None if staged-deleted.
    coinbase_overlay: HashMap<[u8; 32], Option<u64>>,
}

impl<'a> ReorgBatch<'a> {
    fn new(store: &'a Storage) -> Self {
        ReorgBatch {
            store,
            batch: rocksdb::WriteBatch::default(),
            utxo_overlay: HashMap::new(),
            coinbase_overlay: HashMap::new(),
        }
    }

    fn cf(&self, name: &str) -> Result<&'a rocksdb::ColumnFamily, String> {
        self.store.db().cf_handle(name)
            .ok_or_else(|| format!("reorg batch: missing column family '{}'", name))
    }

    /// Overlay-aware UTXO read: staged state wins, otherwise committed DB.
    fn get_utxo(&self, txid: &[u8; 32], index: u32) -> Result<Option<TxOutput>, String> {
        if let Some(staged) = self.utxo_overlay.get(&utxo_key(txid, index)) {
            return Ok(staged.clone());
        }
        self.store.get_utxo(txid, index)
            .map_err(|e| format!("reorg batch: get_utxo failed: {}", e))
    }

    /// Overlay-aware coinbase-height read.
    fn get_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, String> {
        if let Some(staged) = self.coinbase_overlay.get(txid) {
            return Ok(*staged);
        }
        self.store.get_coinbase_height(txid)
            .map_err(|e| format!("reorg batch: get_coinbase_height failed: {}", e))
    }

    /// Mirrors `Storage::put_utxo` (CF_UTXO row + CF_ADDR_UTXO index row).
    fn put_utxo(&mut self, txid: &[u8; 32], index: u32, output: &TxOutput) -> Result<(), String> {
        let key = utxo_key(txid, index);
        let cf_u = self.cf(CF_UTXO)?;
        self.batch.put_cf(cf_u, &key, &bc_encode(output)?);
        if output.script_pubkey.len() >= 20 {
            let cf_ai = self.cf(CF_ADDR_UTXO)?;
            self.batch.put_cf(cf_ai, &addr_utxo_key(&output.script_pubkey, txid, index), b"");
        }
        self.utxo_overlay.insert(key, Some(output.clone()));
        Ok(())
    }

    /// Mirrors `Storage::delete_utxo`, but resolves the output for the
    /// address-index cleanup through the OVERLAY — a UTXO restored earlier in
    /// this same batch is not on disk yet.
    fn delete_utxo(&mut self, txid: &[u8; 32], index: u32) -> Result<(), String> {
        if let Some(output) = self.get_utxo(txid, index)? {
            if output.script_pubkey.len() >= 20 {
                let cf_ai = self.cf(CF_ADDR_UTXO)?;
                self.batch.delete_cf(cf_ai, &addr_utxo_key(&output.script_pubkey, txid, index));
            }
        }
        let key = utxo_key(txid, index);
        let cf_u = self.cf(CF_UTXO)?;
        self.batch.delete_cf(cf_u, &key);
        self.utxo_overlay.insert(key, None);
        Ok(())
    }

    /// Mirrors `Storage::put_coinbase_info` (txid → height LE).
    fn put_coinbase_info(&mut self, txid: &[u8; 32], height: u64) -> Result<(), String> {
        let cf = self.cf(CF_COINBASE)?;
        self.batch.put_cf(cf, txid, &height.to_le_bytes());
        self.coinbase_overlay.insert(*txid, Some(height));
        Ok(())
    }

    fn delete_coinbase_info(&mut self, txid: &[u8; 32]) -> Result<(), String> {
        let cf = self.cf(CF_COINBASE)?;
        self.batch.delete_cf(cf, txid);
        self.coinbase_overlay.insert(*txid, None);
        Ok(())
    }

    /// Mirrors `Storage::put_tx_index` (txid → [32B block_hash][8B height LE]).
    fn put_tx_index(&mut self, txid: &[u8; 32], block_hash: &[u8; 32], height: u64) -> Result<(), String> {
        let cf = self.cf(CF_TX_INDEX)?;
        let mut val = Vec::with_capacity(40);
        val.extend_from_slice(block_hash);
        val.extend_from_slice(&height.to_le_bytes());
        self.batch.put_cf(cf, txid, &val);
        Ok(())
    }

    fn delete_tx_index(&mut self, txid: &[u8; 32]) -> Result<(), String> {
        let cf = self.cf(CF_TX_INDEX)?;
        self.batch.delete_cf(cf, txid);
        Ok(())
    }

    /// Mirrors `Storage::put_undo_data`.
    fn put_undo_data(&mut self, block_hash: &[u8; 32], data: &UndoData) -> Result<(), String> {
        let encoded = bc_encode(data)?;
        let cf = self.cf(CF_UNDO)?;
        self.batch.put_cf(cf, block_hash, &encoded);
        Ok(())
    }

    fn delete_undo_data(&mut self, block_hash: &[u8; 32]) -> Result<(), String> {
        let cf = self.cf(CF_UNDO)?;
        self.batch.delete_cf(cf, block_hash);
        Ok(())
    }

    /// Stage deletion of one addr_tx_history row (key precomputed by the
    /// caller via `storage::indexer::make_key`).
    fn delete_addr_history_key(&mut self, key: &[u8]) -> Result<(), String> {
        let cf = self.cf(CF_ADDR_TX_HISTORY)?;
        self.batch.delete_cf(cf, key);
        Ok(())
    }

    /// Commit every staged mutation atomically. Consumes the batch; RocksDB
    /// applies a WriteBatch all-or-nothing.
    fn commit(self) -> Result<(), String> {
        self.store.db().write(self.batch)
            .map_err(|e| format!("reorg batch: atomic commit failed: {}", e))
    }
}

/// Stage the full rollback of one block into the batch — the batched twin of
/// `Storage::rollback_block` (U.2), preserving its exact mutation set and
/// ordering: addr_tx_history unindex, restore spent UTXOs, delete created
/// UTXOs, delete coinbase infos, delete tx_index rows, delete the undo record.
fn rollback_block_batched(
    batch: &mut ReorgBatch,
    block: &Block,
    block_hash: &BlockHash,
) -> Result<(), String> {
    let undo = batch.store.get_undo_data(block_hash)
        .map_err(|e| format!("rollback: get_undo_data failed: {}", e))?
        .ok_or_else(|| format!(
            "rollback: no undo data for block {}..",
            hex::encode(&block_hash[..4]),
        ))?;

    // Spent-output lookup from UndoData — same rationale as
    // `Storage::unindex_tx_addresses` (deterministic accept-time capture).
    let mut spent_lookup: HashMap<([u8; 32], u32), TxOutput> =
        HashMap::with_capacity(undo.spent_utxos.len());
    for entry in &undo.spent_utxos {
        spent_lookup.insert((entry.prev_txid, entry.prev_index), entry.output.clone());
    }

    // 1. Un-index addr_tx_history. Key computation mirrors
    //    `Storage::unindex_tx_addresses` byte-for-byte (20-byte script prefix
    //    as address hash; bit-31 marker for input entries). Best-effort
    //    semantics preserved: unresolvable addresses are skipped.
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        for (vout_idx, output) in tx.outputs.iter().enumerate() {
            if output.script_pubkey.len() >= 20 {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&output.script_pubkey[..20]);
                let key = crate::storage::indexer::make_key(
                    &addr, block.height, tx_idx as u32, vout_idx as u32,
                );
                batch.delete_addr_history_key(&key)?;
            }
        }
        if !tx.is_coinbase() {
            for (vin_idx, input) in tx.inputs.iter().enumerate() {
                if let Some(prev_output) = spent_lookup.get(&(input.prev_txid, input.prev_index)) {
                    if prev_output.script_pubkey.len() >= 20 {
                        let mut addr = [0u8; 20];
                        addr.copy_from_slice(&prev_output.script_pubkey[..20]);
                        let key = crate::storage::indexer::make_key(
                            &addr, block.height, tx_idx as u32, 0x8000_0000 | vin_idx as u32,
                        );
                        batch.delete_addr_history_key(&key)?;
                    }
                }
            }
        }
    }

    // 2. Restore spent UTXOs (also restages the CF_ADDR_UTXO row).
    for entry in &undo.spent_utxos {
        batch.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output)?;
    }

    // 3. Delete created UTXOs (also cleans the CF_ADDR_UTXO row).
    for (txid, idx) in &undo.created_utxo_keys {
        batch.delete_utxo(txid, *idx)?;
    }

    // 4. Delete coinbase-info rows.
    for txid in &undo.coinbase_txids {
        batch.delete_coinbase_info(txid)?;
    }

    // 5. Delete tx_index rows.
    for txid in &undo.tx_index_keys {
        batch.delete_tx_index(txid)?;
    }

    // 6. Delete the undo record itself.
    batch.delete_undo_data(block_hash)?;

    Ok(())
}

/// Stage the forward application of one fork block — the batched twin of
/// `apply_block_utxo_mutations`, identical mutation set and ordering so the
/// staged UndoData is byte-compatible with what the direct path produces.
fn apply_block_utxo_mutations_batched(
    batch: &mut ReorgBatch,
    block: &Block,
) -> Result<(), String> {
    let block_hash = block.block_hash();
    let mut undo = UndoData::new(block_hash, block.height);

    for tx in &block.transactions {
        let txid = tx.txid();

        batch.put_tx_index(&txid, &block_hash, block.height)?;
        undo.tx_index_keys.push(txid);

        for (j, out) in tx.outputs.iter().enumerate() {
            batch.put_utxo(&txid, j as u32, out)?;
            undo.created_utxo_keys.push((txid, j as u32));
        }

        if tx.is_coinbase() {
            batch.put_coinbase_info(&txid, block.height)?;
            undo.coinbase_txids.push(txid);
        } else {
            for inp in &tx.inputs {
                // Capture BEFORE delete (through the overlay — the pre-spend
                // output may have been staged by an earlier fork block).
                if let Ok(Some(output)) = batch.get_utxo(&inp.prev_txid, inp.prev_index) {
                    undo.spent_utxos.push(UndoEntry {
                        prev_txid:  inp.prev_txid,
                        prev_index: inp.prev_index,
                        output,
                    });
                }
                batch.delete_utxo(&inp.prev_txid, inp.prev_index)?;
            }
        }
    }

    batch.put_undo_data(&block_hash, &undo)
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
///
/// Reads go through the [`ReorgBatch`] overlay so the "incrementally-reorged"
/// state is visible even though nothing has been committed to disk yet.
fn validate_fork_block_state(batch: &ReorgBatch, block: &Block) -> Result<(), String> {
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
                    match batch.get_utxo(&inp.prev_txid, inp.prev_index) {
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
                batch.get_coinbase_height(t).ok().flatten()
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
/// All chain-switch storage mutations (phases 1 + 2) are staged into a single
/// RocksDB `WriteBatch` and committed atomically. Any error before the commit
/// — a plan deeper than [`MAX_REORG_DEPTH`], a missing block body or undo
/// record, or a fork block failing H1 re-validation — drops the batch, so
/// storage stays byte-identical to the pre-reorg state. A crash mid-reorg
/// likewise leaves either the complete old state (commit not reached) or the
/// complete new state (commit durable); half-applied chain state is no
/// longer reachable. Mempool reinject (phase 3) runs only after the commit.
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
    // depth before doing any work. Failures (including refused-by-depth-cap
    // plans) increment the failures counter — that is the one to alert on.
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
    // ── Depth cap (security hardening) ────────────────────────────────────
    // Refuse over-deep plans BEFORE any storage access. Reorg depth = number
    // of established selected-chain blocks the plan unwinds. Distinct error
    // marker so callers can tell policy refusal from execution failure.
    let depth = plan.to_rollback.len() as u64;
    if depth > MAX_REORG_DEPTH {
        return Err(format!(
            "{}: plan rolls back {} blocks > cap {} (finality window); refused with no storage mutation",
            ERR_REORG_DEPTH, depth, MAX_REORG_DEPTH,
        ));
    }

    let mut candidate_txs: Vec<Transaction> = Vec::new();

    // All phase-1/phase-2 mutations are STAGED here and committed atomically
    // after the whole plan has validated. Any early return drops the batch —
    // storage untouched.
    let mut batch = ReorgBatch::new(store);

    // Phase 1: Stage rollback of the old chain (tip-toward-LCA).
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

        rollback_block_batched(&mut batch, &block, hash)
            .map_err(|e| format!(
                "execute_reorg: rollback failed at h={} (reorg aborted, no storage mutation committed): {}",
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
        //
        // DECISION (U.4 close-out): this shielded selected-chain-order wiring is
        // DEFERRED to the SP1-verifier track, on purpose. It is only end-to-end
        // exercisable once `RejectAll` is lifted (real shielded txs applying), so
        // landing it now would merge consensus-path code that cannot be tested for
        // zero present effect. It lands WITH the SP1 verifier, as one coherent,
        // reviewable, fully-testable change. The UTXO half of U.4 (above) is
        // complete and hardened — see tests/reorg_hardening.rs (audit-H1 restore,
        // byte-exact A→B→A symmetry, shielded order-guard) + tests/sprint_u4_reorg_e2e.rs.
    }

    // Phase 2: Validate THEN stage the new chain (LCA-toward-tip). Each fork
    // block is re-validated against the incrementally-reorged UTXO state via
    // the batch overlay (audit H1). If any block is invalid, drop the batch —
    // no explicit restore pass is needed because nothing was committed, so a
    // rejected reorg can never leave a corrupted / coins-from-nothing UTXO set.
    for hash in &plan.to_apply {
        let block = store.get_block(hash)
            .map_err(|e| format!("execute_reorg: get_block on apply target failed: {}", e))?
            .ok_or_else(|| format!("execute_reorg: block body missing for apply target"))?;

        if let Err(reason) = validate_fork_block_state(&batch, &block) {
            log::error!(
                "execute_reorg: fork block h={} failed re-validation ({}); aborting reorg (atomic batch dropped, storage untouched)",
                block.height, reason
            );
            return Err(format!("reorg aborted: fork block h={} invalid: {}", block.height, reason));
        }

        apply_block_utxo_mutations_batched(&mut batch, &block)
            .map_err(|e| format!("execute_reorg: batched apply failed at h={}: {}", block.height, e))?;
    }

    // ── Atomic commit: the entire chain switch lands in one db.write() ────
    batch.commit()?;

    // Phase 3: Reinject valid, validate-rejected txs into mempool.
    // UTXO set now reflects the new chain (the batch above is committed);
    // any tx whose inputs survive is still spendable.
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

// ─────────────────────────────────────────────────────────────────────────────
// Regression tests — depth cap + atomic batch.
//
// Broader reorg behavior (plans, H1 abort-restore, byte-exact symmetry) is
// covered by tests/sprint_u3_reorg.rs, tests/reorg_hardening.rs and
// tests/sprint_u4_reorg_e2e.rs, which now exercise the batch path end to end.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod reorg_hardening_unit_tests {
    use super::*;
    use crate::core::{BlockHeader, TxInput};
    use tempfile::TempDir;

    fn mk_storage() -> (TempDir, Storage) {
        let tmp = TempDir::new().unwrap();
        let s = Storage::open(tmp.path()).unwrap();
        (tmp, s)
    }

    fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
        TxOutput { value, script_pubkey: vec![addr_byte; 20] }
    }

    fn mk_block_at(height: u64, nonce_tag: u64, txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version:     1,
                parents:     vec![],
                merkle_root: crate::core::MerkleRoot::ZERO,
                timestamp:   1_700_000_000 + height,
                bits:        0x1d00ffff,
                nonce:       nonce_tag,
            },
            transactions: txs,
            blue_score: height,
            height,
            pow_solution: Vec::new(),
            shielded_transactions: Vec::new(),
        }
    }

    fn mk_coinbase(addr_byte: u8, value: u64, height: u64, tag: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0u8; 32],
                prev_index: 0xffff_ffff,
                script_sig: format!("cb:{}:{}:{}", height, addr_byte, tag).into_bytes(),
                sequence:   0xffff_ffff,
            }],
            outputs: vec![mk_output(addr_byte, value)],
            locktime: 0,
        }
    }

    fn mk_spend_tx(prev_txid: [u8; 32], prev_index: u32, to_addr: u8, value: u64, tag: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_index,
                script_sig: vec![0xde, 0xad, 0xbe, tag],
                sequence:   0xffff_ffff,
            }],
            outputs: vec![mk_output(to_addr, value)],
            locktime: 0,
        }
    }

    fn hash_of(i: u64) -> BlockHash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        h[31] = 0xFD; // avoid colliding with real fixture hashes
        h
    }

    /// The CF names ReorgBatch stages into must exist in the live schema —
    /// guards the mirrored constants against renames in src/storage/mod.rs.
    #[test]
    fn reorg_batch_column_families_exist() {
        let (_tmp, store) = mk_storage();
        for name in [CF_UTXO, CF_ADDR_UTXO, CF_COINBASE, CF_TX_INDEX, CF_UNDO, CF_ADDR_TX_HISTORY] {
            assert!(
                store.db().cf_handle(name).is_some(),
                "column family '{}' missing — reorg batch constants must mirror src/storage/mod.rs",
                name,
            );
        }
    }

    /// Depth cap regression: a plan rolling back MAX_REORG_DEPTH + 1 blocks
    /// must be refused with the DISTINCT cap error before any storage access.
    /// Without the cap, execute_reorg instead walks the plan and fails with a
    /// generic "block body missing" error — so this assertion fails.
    #[test]
    fn reorg_depth_cap_refuses_plan_beyond_max_depth() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();

        let plan = ReorgPlan {
            lca:         [0u8; 32],
            to_rollback: (0..=MAX_REORG_DEPTH).map(hash_of).collect(), // cap + 1 entries
            to_apply:    vec![[0xEE; 32]],
        };
        let err = execute_reorg(&store, &mempool, &plan).unwrap_err();
        assert!(
            err.contains(ERR_REORG_DEPTH),
            "too-deep reorg must be refused with the distinct cap error, got: {}", err,
        );
    }

    /// Boundary: a plan at EXACTLY the cap passes the gate (it then fails for
    /// a different reason — the fixture blocks don't exist — proving the cap
    /// does not over-refuse at the boundary).
    #[test]
    fn reorg_depth_cap_allows_plan_at_exact_cap() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();

        let plan = ReorgPlan {
            lca:         [0u8; 32],
            to_rollback: (0..MAX_REORG_DEPTH).map(hash_of).collect(), // exactly cap
            to_apply:    vec![[0xEE; 32]],
        };
        let err = execute_reorg(&store, &mempool, &plan).unwrap_err();
        assert!(
            !err.contains(ERR_REORG_DEPTH),
            "plan at exactly the cap must not be refused by the depth cap: {}", err,
        );
        assert!(
            err.contains("block body missing"),
            "at-cap plan must proceed past the gate and fail on the missing fixture blocks: {}", err,
        );
    }

    /// Atomic-batch regression (crash-consistency): a reorg that fails MIDWAY
    /// through rollback (second rollback target has no undo record, e.g.
    /// pruned) must leave storage byte-identical to the pre-reorg state.
    ///
    /// Before the batch conversion, execute_reorg committed each
    /// rollback_block individually: the FIRST target (A2) was already rolled
    /// back on disk when the second (A1) failed, leaving a half-applied chain
    /// state — A2's coinbase UTXO deleted and its undo record gone. Both
    /// assertions below fail on that code.
    #[test]
    fn reorg_atomic_batch_no_partial_state_on_mid_rollback_failure() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();

        // Established chain: A1 (h=1) ← A2 (h=2), both applied with undo data.
        let a1 = mk_block_at(1, 0x0A01, vec![mk_coinbase(0xA1, 100, 1, 1)]);
        let a2 = mk_block_at(2, 0x0A02, vec![mk_coinbase(0xA2, 100, 2, 2)]);
        let (a1h, a2h) = (a1.block_hash(), a2.block_hash());
        store.put_block(&a1).unwrap();
        apply_block_utxo_mutations(&store, &a1).unwrap();
        store.put_block(&a2).unwrap();
        apply_block_utxo_mutations(&store, &a2).unwrap();

        // Simulate a pruned/lost undo record for A1 — the SECOND rollback
        // target in tip-first order, so the failure hits mid-plan.
        store.delete_undo_data(&a1h).unwrap();

        // Fork target (content irrelevant; rollback fails before apply).
        let b1 = mk_block_at(1, 0x0B01, vec![mk_coinbase(0xB1, 100, 1, 3)]);
        let b1h = b1.block_hash();
        store.put_block(&b1).unwrap();

        let plan = ReorgPlan {
            lca:         [0u8; 32],
            to_rollback: vec![a2h, a1h], // tip-first
            to_apply:    vec![b1h],
        };

        let cb_a2_txid = a2.transactions[0].txid();
        let err = execute_reorg(&store, &mempool, &plan).unwrap_err();
        assert!(err.contains("no undo data"), "failure must be the missing undo record: {}", err);

        // Atomicity: A2's rollback was STAGED before the failure but must not
        // have reached disk — all-or-nothing.
        assert!(
            store.get_utxo(&cb_a2_txid, 0).unwrap().is_some(),
            "A2's coinbase UTXO must survive an aborted reorg (no partial rollback)",
        );
        assert!(
            store.get_undo_data(&a2h).unwrap().is_some(),
            "A2's undo record must survive an aborted reorg (no partial rollback)",
        );
        assert!(
            store.get_coinbase_height(&cb_a2_txid).unwrap().is_some(),
            "A2's coinbase-info row must survive an aborted reorg",
        );
        // And nothing of the fork leaked in.
        assert!(store.get_utxo(&b1.transactions[0].txid(), 0).unwrap().is_none());
    }

    /// Atomic-batch success path: after a committed reorg, ALL reorg keys are
    /// applied — old chain fully rolled back, every fork block fully applied
    /// (UTXOs, coinbase index, tx index, fresh undo records) — including a
    /// fork block that spends an output created by the PRECEDING fork block,
    /// which is only visible through the batch overlay while staging.
    #[test]
    fn reorg_atomic_batch_applies_all_keys_on_success() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();

        // Seed a spendable outpoint U that exists independently of both forks.
        let u_txid = [0x55u8; 32];
        store.put_utxo(&u_txid, 0, &mk_output(0x99, 100)).unwrap();

        // Established chain: A1 applied.
        let a1 = mk_block_at(1, 0x0A01, vec![mk_coinbase(0xA1, 100, 1, 1)]);
        let a1h = a1.block_hash();
        store.put_block(&a1).unwrap();
        apply_block_utxo_mutations(&store, &a1).unwrap();

        // Fork: B1 = [cb_b1, tx1: U(100) → X(90)], B2 = [cb_b2, tx2: X(90) → Y(80)].
        let cb_b1 = mk_coinbase(0xB1, 100, 1, 2);
        let tx1   = mk_spend_tx(u_txid, 0, 0xB2, 90, 1);
        let x_txid = tx1.txid();
        let b1 = mk_block_at(1, 0x0B01, vec![cb_b1.clone(), tx1]);

        let cb_b2 = mk_coinbase(0xB3, 100, 2, 3);
        let tx2   = mk_spend_tx(x_txid, 0, 0xB4, 80, 2);
        let y_txid = tx2.txid();
        let b2 = mk_block_at(2, 0x0B02, vec![cb_b2.clone(), tx2.clone()]);

        let (b1h, b2h) = (b1.block_hash(), b2.block_hash());
        store.put_block(&b1).unwrap();
        store.put_block(&b2).unwrap();

        let plan = ReorgPlan {
            lca:         [0u8; 32],
            to_rollback: vec![a1h],
            to_apply:    vec![b1h, b2h],
        };
        let outcome = execute_reorg(&store, &mempool, &plan).expect("reorg must succeed");
        assert_eq!(outcome.rolled_back, 1);
        assert_eq!(outcome.applied, 2);

        // Old chain fully rolled back.
        let cb_a1_txid = a1.transactions[0].txid();
        assert!(store.get_utxo(&cb_a1_txid, 0).unwrap().is_none(), "A1 coinbase UTXO removed");
        assert!(store.get_undo_data(&a1h).unwrap().is_none(),      "A1 undo record removed");
        assert!(store.get_coinbase_height(&cb_a1_txid).unwrap().is_none(), "A1 coinbase info removed");

        // New chain fully applied.
        assert!(store.get_utxo(&cb_b1.txid(), 0).unwrap().is_some(), "B1 coinbase UTXO present");
        assert!(store.get_utxo(&cb_b2.txid(), 0).unwrap().is_some(), "B2 coinbase UTXO present");
        assert!(store.get_utxo(&u_txid, 0).unwrap().is_none(),       "U spent by B1");
        assert!(store.get_utxo(&x_txid, 0).unwrap().is_none(),       "X spent by B2 (intra-fork chain)");
        assert!(store.get_utxo(&y_txid, 0).unwrap().is_some(),       "Y (B2 output) present");
        assert!(store.get_undo_data(&b1h).unwrap().is_some(),        "B1 reorg-capable (undo present)");
        assert!(store.get_undo_data(&b2h).unwrap().is_some(),        "B2 reorg-capable (undo present)");
        assert_eq!(
            store.get_tx_location(&tx2.txid()).unwrap().map(|(h, _)| h),
            Some(b2h),
            "tx index points at the fork block",
        );
    }
}
