//! Bloch-SIS Protocol — Mempool
//!
//! FIX #5: In-memory transaction pool with basic validation.
//! Accepts transactions, deduplicates, evicts by fee rate.
//! Sprint N-min: per-tx size cap, intra-mempool double-spend detection.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock;
use crate::core::Transaction;

const MAX_MEMPOOL_SIZE: usize = 50_000;

/// P0 memory bound (roadmap §3.4 / §1.4): total serialized bytes the mempool
/// will hold. The count cap alone allowed 50_000 × 400 KiB ≈ 20 GB worst case;
/// this caps actual memory. 300 MiB is a conservative default — it must be
/// tuned against real block sizes and load-tested (not yet done). Eviction
/// enforces BOTH this and MAX_MEMPOOL_SIZE.
const MAX_MEMPOOL_BYTES: usize = 300 * 1024 * 1024;

/// SECURITY (audit L2): minimum relay fee rate in satoshis per serialized byte.
/// Rejects free / dust-rate transactions that would otherwise let an actor with
/// spendable UTXOs flood the mempool and skew fee-estimation RPCs.
pub const MIN_RELAY_FEE_RATE: u64 = 1;
/// Fixed-point scale so fee-rate (fee/size) comparisons don't truncate to 0.
const FEE_RATE_SCALE: u128 = 1_000_000;

/// Sprint N-min: max serialized bytes per tx accepted into mempool.
/// 400 KB accommodates legitimate consolidation (~120 ML-DSA-65 inputs)
/// while rejecting pathological transactions that could exhaust memory.
/// Transport layer (libp2p gossipsub) caps at 4 MB; this is a tighter
/// application-level bound.
pub const MAX_TX_SIZE: usize = 400 * 1024;

#[derive(Clone)]
pub struct MempoolEntry {
    pub tx:         Transaction,
    pub fee:        u64,
    pub added_at:   u64,
}

pub struct Mempool {
    txs: RwLock<HashMap<[u8; 32], MempoolEntry>>,
    /// Sprint N-min: maps each spent outpoint to the txid that spends it.
    /// Used for O(1) intra-mempool double-spend detection.
    /// Invariant: for every (outpoint, spender_txid) entry, txs contains
    /// an entry with key spender_txid whose inputs include outpoint.
    spent: RwLock<HashMap<([u8; 32], u32), [u8; 32]>>,
    /// P0: running sum of `tx.actual_size()` for every entry in `txs`. Kept in
    /// sync under the `txs` write lock (only mutated while that lock is held),
    /// so reads are consistent with the map. Used to enforce MAX_MEMPOOL_BYTES
    /// in O(1) without rescanning the pool for its total size.
    total_bytes: AtomicUsize,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            txs:   RwLock::new(HashMap::new()),
            spent: RwLock::new(HashMap::new()),
            total_bytes: AtomicUsize::new(0),
        }
    }

    /// Add a transaction to the mempool.
    /// Returns Ok(txid) or Err if duplicate, conflicting, oversized, or full.
    ///
    /// Sprint N-min additions over v0.5.6:
    ///   - Rejects tx with serialized size > MAX_TX_SIZE (400 KB)
    ///   - Rejects tx whose inputs conflict with txs already in mempool
    ///   - Maintains the spent-outpoint index alongside the tx map
    pub fn add(&self, tx: Transaction, fee: u64) -> Result<[u8; 32], MempoolError> {
        let txid = tx.txid();

        // Structural checks (cheap, before taking write lock on spent).
        if tx.inputs.is_empty()  { crate::metrics::inc_tx_rejected("invalid"); return Err(MempoolError::Invalid("no inputs".into())); }
        if tx.outputs.is_empty() { crate::metrics::inc_tx_rejected("invalid"); return Err(MempoolError::Invalid("no outputs".into())); }
        if tx.is_coinbase()      { crate::metrics::inc_tx_rejected("invalid"); return Err(MempoolError::Invalid("coinbase not allowed".into())); }

        // Sprint N-min: size cap.
        let size = tx.actual_size();
        if size > MAX_TX_SIZE {
            crate::metrics::inc_tx_rejected("oversized");
            return Err(MempoolError::Oversized { size, max: MAX_TX_SIZE });
        }

        // SECURITY (audit L2): enforce a minimum relay fee rate (sat/byte).
        if fee < (size as u64).saturating_mul(MIN_RELAY_FEE_RATE) {
            crate::metrics::inc_tx_rejected("low_fee");
            return Err(MempoolError::Invalid(format!(
                "fee {} below minimum relay rate ({} sat/byte for {} bytes)",
                fee, MIN_RELAY_FEE_RATE, size
            )));
        }

        // Overflow check on outputs.
        let _total_out: u64 = tx.outputs.iter()
            .map(|o| o.value)
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or_else(|| {
                crate::metrics::inc_tx_rejected("overflow");
                MempoolError::Invalid("output overflow".into())
            })?;

        // Take both write locks in a consistent order (txs first, then spent)
        // to prevent any future codepath from deadlocking.
        let mut pool  = self.txs.write();
        let mut spent = self.spent.write();

        if pool.contains_key(&txid) {
            crate::metrics::inc_tx_rejected("duplicate");
            return Err(MempoolError::Duplicate);
        }

        // Sprint N-min: intra-mempool double-spend detection.
        // If any input of the new tx is already claimed by a mempool tx,
        // reject the new tx (no RBF in v0.5.7 — first-seen wins).
        for inp in &tx.inputs {
            let op = (inp.prev_txid, inp.prev_index);
            if let Some(existing_txid) = spent.get(&op) {
                crate::metrics::inc_tx_rejected("conflict");
                return Err(MempoolError::Conflict {
                    outpoint_txid: inp.prev_txid,
                    outpoint_idx:  inp.prev_index,
                    existing_spender: *existing_txid,
                });
            }
        }

        // Evict the lowest fee-RATE tx(s) until BOTH bounds admit the new tx
        // (audit L2: rank by fee/byte, not absolute fee, so a single large
        // low-rate tx can't out-rank many small higher-rate ones):
        //   - count bound: pool.len() < MAX_MEMPOOL_SIZE
        //   - byte  bound: total_bytes + size <= MAX_MEMPOOL_BYTES  (P0)
        //
        // NOTE (roadmap §3.4 / P1 #10): eviction still does an O(n) min-scan per
        // evicted tx because `txs` is a HashMap with no fee-rate index. The byte
        // bound below caps *memory*; the fee-rate-ordered BTreeMap index that
        // makes eviction O(log n) is deferred to P1 and is NOT load-tested here.
        // Under a small-high-rate-tx flood this loop can evict several entries
        // per insert — bounded, but its cost needs load testing to confirm.
        let mut cur_bytes = self.total_bytes.load(Ordering::Relaxed);
        let new_rate = (fee as u128 * FEE_RATE_SCALE) / (size.max(1) as u128);
        while pool.len() >= MAX_MEMPOOL_SIZE
            || cur_bytes.saturating_add(size) > MAX_MEMPOOL_BYTES
        {
            let lowest = pool.iter()
                .map(|(k, e)| (*k, (e.fee as u128 * FEE_RATE_SCALE) / (e.tx.actual_size().max(1) as u128)))
                .min_by_key(|(_, r)| *r);
            match lowest {
                Some((k, low_rate)) if new_rate > low_rate => {
                    // Also drop its spent-set entries before eviction.
                    if let Some(evicted) = pool.remove(&k) {
                        cur_bytes = cur_bytes.saturating_sub(evicted.tx.actual_size());
                        for inp in &evicted.tx.inputs {
                            spent.remove(&(inp.prev_txid, inp.prev_index));
                        }
                    }
                }
                // Either the pool is empty (only possible when the new tx alone
                // exceeds the byte cap) or the new tx does not out-rank the
                // cheapest resident: reject rather than evict a better tx.
                _ => {
                    crate::metrics::inc_tx_rejected("full");
                    return Err(MempoolError::Full);
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Insert into both maps atomically (we hold both write locks).
        for inp in &tx.inputs {
            spent.insert((inp.prev_txid, inp.prev_index), txid);
        }
        pool.insert(txid, MempoolEntry { tx, fee, added_at: now });
        self.total_bytes.store(cur_bytes.saturating_add(size), Ordering::Relaxed);
        crate::metrics::inc_tx_accepted();
        Ok(txid)
    }

    pub fn remove(&self, txid: &[u8; 32]) -> bool {
        let mut pool  = self.txs.write();
        let mut spent = self.spent.write();
        if let Some(entry) = pool.remove(txid) {
            self.total_bytes.fetch_sub(entry.tx.actual_size(), Ordering::Relaxed);
            for inp in &entry.tx.inputs {
                spent.remove(&(inp.prev_txid, inp.prev_index));
            }
            true
        } else {
            false
        }
    }

    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.txs.read().contains_key(txid)
    }

    pub fn size(&self) -> usize {
        self.txs.read().len()
    }

    /// Return up to `limit` txs sorted by fee (highest first) for block template
    pub fn get_for_block(&self, limit: usize) -> Vec<Transaction> {
        let pool = self.txs.read();
        let mut entries: Vec<&MempoolEntry> = pool.values().collect();
        entries.sort_by(|a, b| b.fee.cmp(&a.fee));
        entries.iter().take(limit).map(|e| e.tx.clone()).collect()
    }

    /// List all txids in the mempool
    pub fn txids(&self) -> Vec<[u8; 32]> {
        self.txs.read().keys().cloned().collect()
    }

    /// List all entries with metadata (for RPC verbose mempool)
    pub fn entries(&self) -> Vec<([u8; 32], u64, u64)> {
        self.txs.read().iter().map(|(k, e)| (*k, e.fee, e.added_at)).collect()
    }

    /// Median fee across all mempool entries (for fee estimation)
    pub fn median_fee(&self) -> u64 {
        let pool = self.txs.read();
        if pool.is_empty() { return 1000; } // default 1000 sats
        let mut fees: Vec<u64> = pool.values().map(|e| e.fee).collect();
        fees.sort();
        fees[fees.len() / 2]
    }

    /// Remove all txs whose inputs are now spent (after block confirmation)
    pub fn remove_confirmed(&self, txids: &[[u8; 32]]) {
        let set: HashSet<[u8; 32]> = txids.iter().cloned().collect();
        let mut pool  = self.txs.write();
        let mut spent = self.spent.write();
        // Sprint N-min: collect outpoints to drop from spent before removing
        // the tx entries themselves.
        for txid in &set {
            if let Some(entry) = pool.get(txid) {
                self.total_bytes.fetch_sub(entry.tx.actual_size(), Ordering::Relaxed);
                for inp in &entry.tx.inputs {
                    spent.remove(&(inp.prev_txid, inp.prev_index));
                }
            }
        }
        pool.retain(|k, _| !set.contains(k));
    }

    /// P0: total serialized bytes currently held (for the byte-cap metric /
    /// diagnostics). O(1) — reads the running counter.
    pub fn size_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }
}

// ── Sprint A additions ──────────────────────────────────────────

impl Mempool {
    /// Sprint A: Get a full Transaction by txid.
    pub fn get_tx(&self, txid: &[u8; 32]) -> Option<Transaction> {
        self.txs.read().get(txid).map(|e| e.tx.clone())
    }

    /// Sprint A: Get full mempool entry (tx + fee + timestamp) by txid.
    pub fn get_entry(&self, txid: &[u8; 32]) -> Option<MempoolEntry> {
        self.txs.read().get(txid).cloned()
    }

    /// Sprint A: Scan mempool for txs that spend from or pay to the
    /// given address. Returns Vec of AddressTxInfo sorted newest first.
    pub fn txs_affecting_address(
        &self,
        addr_hash: &[u8; 20],
        utxo_lookup: Option<&dyn Fn(&[u8; 32], u32) -> Option<crate::core::TxOutput>>,
    ) -> Vec<AddressTxInfo> {
        let pool = self.txs.read();
        let mut results = Vec::new();

        for (txid, entry) in pool.iter() {
            let incoming: u64 = entry.tx.outputs.iter()
                .filter(|o| o.script_pubkey.as_slice() == addr_hash.as_slice())
                .map(|o| o.value)
                .sum();

            let outgoing: u64 = if let Some(lookup) = utxo_lookup {
                entry.tx.inputs.iter()
                    .filter_map(|inp| {
                        let utxo = lookup(&inp.prev_txid, inp.prev_index)?;
                        if utxo.script_pubkey.as_slice() == addr_hash.as_slice() {
                            Some(utxo.value)
                        } else {
                            None
                        }
                    })
                    .sum()
            } else {
                0
            };

            if incoming > 0 || outgoing > 0 {
                results.push(AddressTxInfo {
                    txid:     *txid,
                    tx:       entry.tx.clone(),
                    incoming,
                    outgoing,
                    fee:      entry.fee,
                    added_at: entry.added_at,
                });
            }
        }

        results.sort_by(|a, b| b.added_at.cmp(&a.added_at));
        results
    }

    /// Sprint A: Compute pending balance changes for an address.
    /// Returns (incoming_sats, outgoing_sats).
    pub fn pending_balance_for(
        &self,
        addr_hash: &[u8; 20],
        utxo_lookup: Option<&dyn Fn(&[u8; 32], u32) -> Option<crate::core::TxOutput>>,
    ) -> (u64, u64) {
        let txs = self.txs_affecting_address(addr_hash, utxo_lookup);
        let incoming: u64 = txs.iter().map(|t| t.incoming).sum();
        let outgoing: u64 = txs.iter().map(|t| t.outgoing).sum();
        (incoming, outgoing)
    }
}

/// Sprint A: Info about a mempool tx affecting a specific address.
#[derive(Clone, Debug)]
pub struct AddressTxInfo {
    pub txid:     [u8; 32],
    pub tx:       Transaction,
    pub incoming: u64,
    pub outgoing: u64,
    pub fee:      u64,
    pub added_at: u64,
}

impl Default for Mempool {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("duplicate transaction")]
    Duplicate,
    #[error("mempool full")]
    Full,
    #[error("invalid transaction: {0}")]
    Invalid(String),
    /// Sprint N-min: new tx conflicts with a tx already in the mempool
    /// (both spend the same UTXO). First-seen wins; the new tx is rejected.
    #[error("conflicts with mempool tx {}: outpoint {}:{} already spent", hex::encode(existing_spender), hex::encode(outpoint_txid), outpoint_idx)]
    Conflict {
        outpoint_txid:    [u8; 32],
        outpoint_idx:     u32,
        existing_spender: [u8; 32],
    },
    /// Sprint N-min: transaction serialized size exceeds MAX_TX_SIZE.
    #[error("transaction too large: {size} bytes (max {max})")]
    Oversized { size: usize, max: usize },
}
