//! Bloch-SIS Protocol — Mempool
//!
//! FIX #5: In-memory transaction pool with basic validation.
//! Accepts transactions, deduplicates, evicts by fee rate.
//! Sprint N-min: per-tx size cap, intra-mempool double-spend detection.

use std::collections::{BTreeMap, HashMap, HashSet};
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

/// P1 (roadmap §3): fixed-point fee-RATE key, `(fee * FEE_RATE_SCALE) / size`,
/// as an `Ord` newtype over `u128`. Ordering is ascending, so the lowest-rate
/// (eviction-target) tx is `btree.iter().next()` and the highest-rate
/// (block-template head) is `btree.iter().next_back()`. This is the SAME
/// fixed-point rate the eviction loop already computed at the O(n) min-scan —
/// no new ranking semantics, only a different data structure.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct FeeRateKey(u128);

#[inline]
fn fee_rate_key(fee: u64, size: usize) -> FeeRateKey {
    FeeRateKey((fee as u128 * FEE_RATE_SCALE) / (size.max(1) as u128))
}

/// Behavior-neutral time seam (roadmap §4 DST prerequisite). Production reads
/// the wall clock (`SystemClock`), so node behavior is unchanged; the DST
/// harness can inject a deterministic clock via `Mempool::with_clock`. This
/// replaces the direct `SystemTime::now()` call that stamped `added_at`.
pub trait Clock: Send + Sync {
    /// Current time as Unix seconds.
    fn now_secs(&self) -> u64;
}

/// Real-wall-clock `Clock` used by `Mempool::new()`. Behavior-identical to the
/// pre-seam `SystemTime::now()` call.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

pub struct Mempool {
    txs: RwLock<HashMap<[u8; 32], MempoolEntry>>,
    /// Sprint N-min: maps each spent outpoint to the txid that spends it.
    /// Used for O(1) intra-mempool double-spend detection.
    /// Invariant: for every (outpoint, spender_txid) entry, txs contains
    /// an entry with key spender_txid whose inputs include outpoint.
    spent: RwLock<HashMap<([u8; 32], u32), [u8; 32]>>,
    /// P1 (roadmap §3): fee-rate ordered secondary index over `txs`. Maps each
    /// `FeeRateKey` to the set of txids at that rate (the `HashSet` absorbs rate
    /// collisions). Makes eviction O(log n) (peek lowest key) instead of an
    /// O(n) min-scan, and gives `get_for_block` a fee-rate ordering consistent
    /// with eviction.
    ///
    /// INVARIANT: the multiset of txids across all `rate_index` sets is exactly
    /// the key set of `txs`, and each txid's key is `fee_rate_key(entry.fee,
    /// entry.tx.actual_size())`. Mutated only on the same paths that mutate
    /// `txs` (add / eviction / remove / remove_confirmed), always while the
    /// `txs` write lock is held first — the lock-order doc-comment above stays
    /// valid (txs → spent → rate_index).
    rate_index: RwLock<BTreeMap<FeeRateKey, HashSet<[u8; 32]>>>,
    /// P0: running sum of `tx.actual_size()` for every entry in `txs`. Kept in
    /// sync under the `txs` write lock (only mutated while that lock is held),
    /// so reads are consistent with the map. Used to enforce MAX_MEMPOOL_BYTES
    /// in O(1) without rescanning the pool for its total size.
    total_bytes: AtomicUsize,
    /// P1 time seam (behavior-neutral): stamps `added_at`. Defaults to
    /// `SystemClock`.
    clock: Box<dyn Clock>,
}

impl Mempool {
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock))
    }

    /// Construct a mempool with an injected clock (DST / deterministic tests).
    /// Behavior is identical to `new()` when passed a `SystemClock`.
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            txs:   RwLock::new(HashMap::new()),
            spent: RwLock::new(HashMap::new()),
            rate_index: RwLock::new(BTreeMap::new()),
            total_bytes: AtomicUsize::new(0),
            clock,
        }
    }

    /// Insert a txid into the fee-rate index. Caller MUST hold the `txs` write
    /// lock (index mutation is serialized behind it).
    fn index_insert(idx: &mut BTreeMap<FeeRateKey, HashSet<[u8; 32]>>, key: FeeRateKey, txid: [u8; 32]) {
        idx.entry(key).or_default().insert(txid);
    }

    /// Remove a txid from the fee-rate index, dropping the bucket if it empties.
    /// Caller MUST hold the `txs` write lock.
    fn index_remove(idx: &mut BTreeMap<FeeRateKey, HashSet<[u8; 32]>>, key: FeeRateKey, txid: &[u8; 32]) {
        if let Some(set) = idx.get_mut(&key) {
            set.remove(txid);
            if set.is_empty() {
                idx.remove(&key);
            }
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
        // P1 (roadmap §2): additive instrumentation span. No behavior change —
        // fields are recorded; the reject-reason events below mirror
        // `inc_tx_rejected(reason)` and the eviction event surfaces the §3
        // eviction cost this insert paid. Inert unless a tracing subscriber is
        // installed (subscriber init lives in main.rs, which this dev does not
        // own — see report).
        let _span = tracing::debug_span!("mempool.add", fee).entered();
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

        // Take the write locks in a consistent order (txs → spent → rate_index)
        // to prevent any future codepath from deadlocking. The rate_index is
        // mutated only under the txs write lock, exactly like total_bytes.
        let mut pool  = self.txs.write();
        let mut spent = self.spent.write();
        let mut rate_index = self.rate_index.write();

        if pool.contains_key(&txid) {
            crate::metrics::inc_tx_rejected("duplicate");
            tracing::debug!(reason = "duplicate", "mempool tx rejected");
            return Err(MempoolError::Duplicate);
        }

        // Sprint N-min: intra-mempool double-spend detection.
        // If any input of the new tx is already claimed by a mempool tx,
        // reject the new tx (no RBF in v0.5.7 — first-seen wins).
        for inp in &tx.inputs {
            let op = (inp.prev_txid, inp.prev_index);
            if let Some(existing_txid) = spent.get(&op) {
                crate::metrics::inc_tx_rejected("conflict");
                tracing::debug!(reason = "conflict", "mempool tx rejected");
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
        // P1 (roadmap §3): the O(n) min-scan is GONE. The lowest-fee-rate
        // resident is `rate_index.iter().next()` (O(log n) peek + O(1) set
        // removal). The comparison semantics are unchanged: the SAME fixed-point
        // `FeeRateKey` the old scan computed, so a small-high-rate-tx flood no
        // longer scans up to 50k entries per accepted tx.
        let mut cur_bytes = self.total_bytes.load(Ordering::Relaxed);
        let new_key = fee_rate_key(fee, size);
        let mut evictions: u32 = 0;
        while pool.len() >= MAX_MEMPOOL_SIZE
            || cur_bytes.saturating_add(size) > MAX_MEMPOOL_BYTES
        {
            // Lowest fee-rate resident: first btree bucket, any member.
            let lowest = rate_index.iter().next()
                .and_then(|(k, set)| set.iter().next().map(|txid| (*k, *txid)));
            match lowest {
                Some((low_key, victim)) if new_key > low_key => {
                    // Drop the victim from txs, spent, total_bytes, and the index
                    // in one step so the three-way invariant never drifts.
                    Self::index_remove(&mut rate_index, low_key, &victim);
                    if let Some(evicted) = pool.remove(&victim) {
                        cur_bytes = cur_bytes.saturating_sub(evicted.tx.actual_size());
                        for inp in &evicted.tx.inputs {
                            spent.remove(&(inp.prev_txid, inp.prev_index));
                        }
                    }
                    evictions += 1;
                }
                // Either the pool is empty (only possible when the new tx alone
                // exceeds the byte cap) or the new tx does not out-rank the
                // cheapest resident: reject rather than evict a better tx.
                _ => {
                    crate::metrics::inc_tx_rejected("full");
                    tracing::debug!(reason = "full", evictions, "mempool tx rejected");
                    return Err(MempoolError::Full);
                }
            }
        }

        let now = self.clock.now_secs();

        // Insert into txs, spent, and rate_index atomically (all write locks held).
        for inp in &tx.inputs {
            spent.insert((inp.prev_txid, inp.prev_index), txid);
        }
        Self::index_insert(&mut rate_index, new_key, txid);
        pool.insert(txid, MempoolEntry { tx, fee, added_at: now });
        self.total_bytes.store(cur_bytes.saturating_add(size), Ordering::Relaxed);
        crate::metrics::inc_tx_accepted();
        tracing::debug!(size, evictions, "mempool tx accepted");
        Ok(txid)
    }

    pub fn remove(&self, txid: &[u8; 32]) -> bool {
        let mut pool  = self.txs.write();
        let mut spent = self.spent.write();
        let mut rate_index = self.rate_index.write();
        if let Some(entry) = pool.remove(txid) {
            self.total_bytes.fetch_sub(entry.tx.actual_size(), Ordering::Relaxed);
            let key = fee_rate_key(entry.fee, entry.tx.actual_size());
            Self::index_remove(&mut rate_index, key, txid);
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

    /// Return up to `limit` txs for a block template, HIGHEST FEE-RATE first.
    ///
    /// BEHAVIOR CHANGE (P1 / roadmap §3, audit L2) — flagged for the
    /// consensus/mining owner: this previously sorted by ABSOLUTE fee
    /// (`b.fee.cmp(&a.fee)`), which disagreed with eviction (which ranks by
    /// fee/byte). Selection now reads the same `rate_index` ordering as
    /// eviction — highest fee-RATE first (`rate_index.iter().rev()`) — so
    /// templates and eviction agree. Block *validity* is unchanged; only which
    /// txs land in a template (and their order) changes. Ties within a rate
    /// bucket are unordered (HashSet iteration).
    pub fn get_for_block(&self, limit: usize) -> Vec<Transaction> {
        let pool = self.txs.read();
        let rate_index = self.rate_index.read();
        let mut out = Vec::with_capacity(limit.min(pool.len()));
        'outer: for (_key, set) in rate_index.iter().rev() {
            for txid in set {
                if let Some(e) = pool.get(txid) {
                    out.push(e.tx.clone());
                    if out.len() >= limit {
                        break 'outer;
                    }
                }
            }
        }
        out
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
        let mut rate_index = self.rate_index.write();
        // Sprint N-min: collect outpoints to drop from spent before removing
        // the tx entries themselves. P1: also drop the fee-rate index entry so
        // the index never drifts from `txs`.
        for txid in &set {
            if let Some(entry) = pool.get(txid) {
                self.total_bytes.fetch_sub(entry.tx.actual_size(), Ordering::Relaxed);
                let key = fee_rate_key(entry.fee, entry.tx.actual_size());
                Self::index_remove(&mut rate_index, key, txid);
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

    /// P1 (roadmap §3): assert the three-way `txs` ↔ `spent` ↔ `rate_index`
    /// invariant. Returns `Err(reason)` on the first drift found; `Ok(())` if
    /// consistent. This is the property the `mempool_ops` fuzz target and the
    /// `tests/mempool_index_prop.rs` proptest assert never breaks. Not a
    /// hot-path method — it takes read locks and walks the maps.
    ///
    /// Checks:
    ///   1. index multiset == txs key set, each at its `fee_rate_key`.
    ///   2. every `spent` entry points at a live tx that claims that outpoint.
    ///   3. `total_bytes` == Σ actual_size (bounded by MAX_MEMPOOL_BYTES).
    ///   4. `size()` <= MAX_MEMPOOL_SIZE.
    pub fn debug_check_invariants(&self) -> Result<(), String> {
        let pool = self.txs.read();
        let spent = self.spent.read();
        let rate_index = self.rate_index.read();

        // 4. count bound.
        if pool.len() > MAX_MEMPOOL_SIZE {
            return Err(format!("size {} > MAX_MEMPOOL_SIZE {}", pool.len(), MAX_MEMPOOL_SIZE));
        }

        // 1. index ↔ txs. Count index members and check each maps to a live tx
        //    whose fee-rate key matches the bucket it sits in.
        let mut indexed = 0usize;
        for (key, set) in rate_index.iter() {
            if set.is_empty() {
                return Err("rate_index has an empty bucket (should be pruned)".into());
            }
            for txid in set {
                indexed += 1;
                match pool.get(txid) {
                    None => return Err(format!("rate_index txid {} absent from txs", hex::encode(txid))),
                    Some(e) => {
                        let expect = fee_rate_key(e.fee, e.tx.actual_size());
                        if expect != *key {
                            return Err(format!(
                                "rate_index txid {} filed under {:?} but its key is {:?}",
                                hex::encode(txid), key, expect
                            ));
                        }
                    }
                }
            }
        }
        if indexed != pool.len() {
            return Err(format!("rate_index has {} members but txs has {}", indexed, pool.len()));
        }

        // 2. spent ↔ txs.
        for ((prev_txid, prev_index), spender) in spent.iter() {
            match pool.get(spender) {
                None => return Err(format!("spent points at absent tx {}", hex::encode(spender))),
                Some(e) => {
                    let claims = e.tx.inputs.iter()
                        .any(|inp| inp.prev_txid == *prev_txid && inp.prev_index == *prev_index);
                    if !claims {
                        return Err(format!(
                            "spent outpoint {}:{} attributed to {} which does not claim it",
                            hex::encode(prev_txid), prev_index, hex::encode(spender)
                        ));
                    }
                }
            }
        }

        // 3. byte counter.
        let sum: usize = pool.values().map(|e| e.tx.actual_size()).sum();
        let counted = self.total_bytes.load(Ordering::Relaxed);
        if sum != counted {
            return Err(format!("total_bytes {} != Σ actual_size {}", counted, sum));
        }
        if counted > MAX_MEMPOOL_BYTES {
            return Err(format!("total_bytes {} > MAX_MEMPOOL_BYTES {}", counted, MAX_MEMPOOL_BYTES));
        }

        Ok(())
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
