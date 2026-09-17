// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-entry bookkeeping for the engine's mempool (audit EN-02 / EN-04,
//! 2026-09-16).
//!
//! `Engine::on_transaction` used to answer "how many entries does this
//! source already hold?" by re-hashing the first-input pubkey of EVERY
//! mempool entry on EVERY arrival (`tx_source_hash` over ~3.75 KB of hybrid
//! key, ~10 µs each — ~40 ms of consensus-thread CPU per 120-byte frame at
//! `MEMPOOL_MAX`, EN-04), and it had no notion of how many BYTES the pool
//! held at all (EN-02). This index computes each entry's source hash, byte
//! length and txid ONCE, at insertion, and keeps the two aggregates the door
//! consults — a per-source count and a byte total — so both questions are
//! O(log n).
//!
//! # Why it self-reconciles
//!
//! The mempool is mutated on more paths than the door: included (the
//! applied-block arm), refused by the proposer's drop loop, swept, expired,
//! evicted for a better fee, and retained by the validator-lifecycle
//! revalidation in `engine/validator_lifecycle.rs`. Every path in `engine.rs`
//! updates this index explicitly; the lifecycle path (a `retain` over the
//! map) and the tests that fill `mempool` directly do not. Rather than turn
//! every such site into a leak, [`MempoolIndex::reconcile`] rebuilds the
//! difference against the map itself — dropping keys the pool no longer
//! holds, indexing keys it holds but this never saw — and the engine runs it
//! wherever `mempool_admitted_at` is already reconciled (`evict_stale_mempool`,
//! once per applied block) and lazily at the door when the lengths disagree.
//! The steady-state cost is one length comparison per arrival; the
//! out-of-sync cost is one hash per entry this index has never seen, paid
//! once.

use std::collections::BTreeMap;

use bloch_pos_committee::transition::PosTransaction;
use sha3::{Digest, Sha3_256};

/// What the door needs to know about one live entry without decoding it
/// again: its source (for `MEMPOOL_MAX_PER_SOURCE`), its wire length (for
/// `MEMPOOL_MAX_BYTES`) and, for the transfer shapes that create outputs, its
/// txid (so a chained spend can find its pending parent — see
/// `Engine::pending_output_script`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryMeta {
    source: Option<[u8; 32]>,
    bytes: usize,
    txid: Option<[u8; 32]>,
}

/// The index. See the module doc for what it is for and why it reconciles.
#[derive(Debug, Default)]
pub(super) struct MempoolIndex {
    entries: BTreeMap<Vec<u8>, EntryMeta>,
    /// Live entries per source hash. An absent key means zero; a key is
    /// removed the moment its count reaches zero, so `len()` of this map is
    /// "distinct sources pending", not a leak of every source ever seen.
    by_source: BTreeMap<[u8; 32], usize>,
    /// txid → mempool key, for the transfer shapes that create outputs.
    by_txid: BTreeMap<[u8; 32], Vec<u8>>,
    /// Sum of `bytes` over `entries`.
    bytes: usize,
}

impl MempoolIndex {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Index `key` → `tx`. Idempotent: an already-indexed key is left alone,
    /// so a caller that cannot know whether the entry was seen (reconcile)
    /// may call this freely without double-counting.
    pub(super) fn insert(&mut self, key: &[u8], tx: &PosTransaction) {
        if self.entries.contains_key(key) {
            return;
        }
        let meta = EntryMeta {
            source: super::tx_source_hash(tx),
            bytes: key.len(),
            txid: match tx {
                PosTransaction::Transfer { .. } | PosTransaction::TransferV2 { .. } => {
                    Some(tx.txid())
                }
                _ => None,
            },
        };
        if let Some(source) = meta.source {
            let n = self.by_source.entry(source).or_insert(0);
            *n = n.saturating_add(1);
        }
        if let Some(txid) = meta.txid {
            self.by_txid.insert(txid, key.to_vec());
        }
        self.bytes = self.bytes.saturating_add(meta.bytes);
        self.entries.insert(key.to_vec(), meta);
    }

    /// Forget `key`. A key this index never held is a no-op, for the same
    /// reason `insert` is idempotent.
    pub(super) fn remove(&mut self, key: &[u8]) {
        let Some(meta) = self.entries.remove(key) else { return };
        if let Some(source) = meta.source {
            if let Some(n) = self.by_source.get_mut(&source) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.by_source.remove(&source);
                }
            }
        }
        if let Some(txid) = meta.txid {
            // Only if it still points at THIS key: two distinct encodings can
            // share a txid (the witness is outside it), and the survivor must
            // keep its parent lookup.
            if self.by_txid.get(&txid).is_some_and(|k| k.as_slice() == key) {
                self.by_txid.remove(&txid);
            }
        }
        self.bytes = self.bytes.saturating_sub(meta.bytes);
    }

    /// Bring this index into agreement with `mempool`: drop what the pool no
    /// longer holds, index what it holds that this never saw.
    pub(super) fn reconcile(&mut self, mempool: &BTreeMap<Vec<u8>, PosTransaction>) {
        let gone: Vec<Vec<u8>> = self
            .entries
            .keys()
            .filter(|k| !mempool.contains_key(k.as_slice()))
            .cloned()
            .collect();
        for key in gone {
            self.remove(&key);
        }
        if self.entries.len() == mempool.len() {
            return; // same keys on both sides, nothing to add
        }
        for (key, tx) in mempool {
            self.insert(key, tx); // idempotent for the ones already indexed
        }
    }

    /// Entries indexed. Equal to `mempool.len()` whenever the two agree.
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Wire bytes held, summed over the indexed entries.
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Live entries whose source is `source`.
    pub(super) fn from_source(&self, source: &[u8; 32]) -> usize {
        self.by_source.get(source).copied().unwrap_or(0)
    }

    /// The mempool key of the pending transfer whose txid is `txid`, if any.
    pub(super) fn key_of_txid(&self, txid: &[u8; 32]) -> Option<&Vec<u8>> {
        self.by_txid.get(txid)
    }

    /// The aggregates recomputed from scratch over `mempool`, for tests that
    /// assert the incremental bookkeeping never drifts from the truth.
    #[cfg(test)]
    pub(super) fn recount(
        mempool: &BTreeMap<Vec<u8>, PosTransaction>,
    ) -> (BTreeMap<[u8; 32], usize>, usize) {
        let mut by_source = BTreeMap::new();
        let mut bytes = 0usize;
        for (key, tx) in mempool {
            if let Some(source) = super::tx_source_hash(tx) {
                *by_source.entry(source).or_insert(0usize) += 1;
            }
            bytes += key.len();
        }
        (by_source, bytes)
    }

    /// The incremental per-source table, for the same assertion.
    #[cfg(test)]
    pub(super) fn by_source(&self) -> &BTreeMap<[u8; 32], usize> {
        &self.by_source
    }
}

/// Does `key_hash` — SHA3-256 of a spender's public key — open an output
/// locked by `script_hash`?
///
/// A node-local mirror of the consensus predicate `transition::owns`
/// (bloch-pos-committee, private to that crate), byte for byte: the native
/// form (all 32 bytes equal) and the Genesis-3 carried form (last 12 bytes
/// zero, first 20 equal — `SHA3-256(pubkey)[..20]` written into
/// `script_hash[0..20]`). Mirrored rather than imported because the
/// consensus crate is frozen and does not export it; the test
/// `owns_output_mirrors_the_consensus_predicate` pins the three vectors the
/// consensus crate's own tests pin. Used only by the mempool door (audit
/// EN-02, 2026-09-16) to refuse a transfer consensus would refuse as
/// `ScriptMismatch` — a policy check that can only ever agree with the
/// transition, never overrule it.
pub(super) fn owns_output(key_hash: &[u8; 32], script_hash: &[u8; 32]) -> bool {
    if key_hash == script_hash {
        return true;
    }
    script_hash[20..] == [0u8; 12] && key_hash[..20] == script_hash[..20]
}

/// SHA3-256 of a hybrid public key — the script-hash convention every
/// ownership site in this codebase uses (`tx_source_hash`, `rpc.rs`'s
/// `validator_json`, the transition's `apply_transfer`).
pub(super) fn key_hash(pubkey: &[u8]) -> [u8; 32] {
    Sha3_256::digest(pubkey).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::transition::{TransferInput, TransferOutput};

    fn transfer(pubkey: u8, n: u8) -> PosTransaction {
        PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid: [n; 32],
                vout: 0,
                pubkey: vec![pubkey; 4],
                signature: vec![n],
            }],
            outputs: vec![TransferOutput { value: 1_000, script_hash: [n; 32] }],
            tx_bytes: 0,
            tip_millisat_per_gas: u128::from(n),
        }
    }

    /// Same vectors as the consensus crate's own `owns` tests: the native
    /// form, the carried form, another key against both, and a carried
    /// script whose padding is not all zero.
    #[test]
    fn owns_output_mirrors_the_consensus_predicate() {
        let full: [u8; 32] = key_hash(b"the holder");
        let mut carried = [0u8; 32];
        carried[..20].copy_from_slice(&full[..20]);
        assert!(owns_output(&full, &full), "native: identical hashes open");
        assert!(owns_output(&full, &carried), "carried: the same key, truncated, opens");
        let theirs: [u8; 32] = key_hash(b"someone else");
        assert!(!owns_output(&theirs, &full));
        assert!(!owns_output(&theirs, &carried), "a carried output is not a free-for-all");
        let mut almost = carried;
        almost[31] = 1;
        assert!(!owns_output(&full, &almost), "non-zero padding is a native script, compared whole");
    }

    /// The incremental aggregates equal a recount at every step, including
    /// after a `reconcile` against a map that was mutated behind the index.
    #[test]
    fn aggregates_never_drift_from_a_recount() {
        let mut pool: BTreeMap<Vec<u8>, PosTransaction> = BTreeMap::new();
        let mut idx = MempoolIndex::new();
        let check = |idx: &MempoolIndex, pool: &BTreeMap<Vec<u8>, PosTransaction>| {
            let (by_source, bytes) = MempoolIndex::recount(pool);
            assert_eq!(idx.by_source(), &by_source, "per-source table drifted");
            assert_eq!(idx.bytes(), bytes, "byte total drifted");
            assert_eq!(idx.len(), pool.len(), "entry count drifted");
        };
        for n in 0..6u8 {
            let tx = transfer(n % 2, n);
            let key = tx.canonical_bytes();
            idx.insert(&key, &tx);
            pool.insert(key, tx);
            check(&idx, &pool);
        }
        // Explicit removal.
        let key = transfer(1, 3).canonical_bytes();
        pool.remove(&key);
        idx.remove(&key);
        check(&idx, &pool);
        // Removed behind the index (the lifecycle `retain`), then reconciled.
        pool.retain(|_, tx| matches!(tx, PosTransaction::Transfer { inputs, .. } if inputs[0].pubkey[0] == 0));
        idx.reconcile(&pool);
        check(&idx, &pool);
        // Inserted behind the index (a test filling the map), then reconciled.
        let tx = transfer(1, 9);
        pool.insert(tx.canonical_bytes(), tx);
        idx.reconcile(&pool);
        check(&idx, &pool);
        // Double insert and double remove are no-ops, not double counts.
        let (key, tx) = pool.iter().next().map(|(k, t)| (k.clone(), t.clone())).unwrap();
        idx.insert(&key, &tx);
        check(&idx, &pool);
        pool.remove(&key);
        idx.remove(&key);
        idx.remove(&key);
        check(&idx, &pool);
    }

    /// The txid lookup follows the entry in and out.
    #[test]
    fn a_pending_transfer_is_found_by_txid_until_it_leaves() {
        let mut idx = MempoolIndex::new();
        let tx = transfer(0, 1);
        let key = tx.canonical_bytes();
        assert!(idx.key_of_txid(&tx.txid()).is_none());
        idx.insert(&key, &tx);
        assert_eq!(idx.key_of_txid(&tx.txid()), Some(&key));
        idx.remove(&key);
        assert!(idx.key_of_txid(&tx.txid()).is_none());
    }
}
