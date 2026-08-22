// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SVM state tree (spec §4.1) and the account store that feeds it.
//!
//! ## Why this is a COPY of the consensus SMT, not a reuse
//!
//! The spec's preference order was "export and reuse `state_root::Smt`; only
//! if that drags frozen surfaces, copy it". Verified 2026-08-21: the
//! consensus `Smt` is `pub` (state_root.rs:423), but **every SHA3 invocation
//! in that module hard-codes `DS_STATE`** (state_root.rs:212,
//! `h.update(DS_STATE)`) — the leaf/node/empty constants included. Reuse
//! would therefore commit SVM leaves under the consensus separator, which
//! §4.1 forbids ("an SVM leaf must never be presentable as a consensus leaf
//! in a proof"), and parameterising the separator *there* means editing the
//! frozen consensus crate — exactly the line this front must not cross. So
//! the fallback applies: this file copies the construction **exactly** —
//! fixed depth 256, no path compaction, MSB-first bit order, the same five
//! preimage markers, `BTreeMap` canonicalisation — parameterised by the
//! 16-byte domain separator, and a permanent dev-only cross-KAT
//! (`copy_matches_consensus_smt_forever` below) instantiates the copy with
//! `DS_STATE` and compares roots against `state_root::Smt` on randomized
//! vectors. The compact-SMT soundness bugs state_root.rs documents do not
//! get less dangerous the second time; neither does silent drift between two
//! copies of the same construction.
//!
//! ## What is deliberately NOT copied
//!
//! - The singleton memo (state_root.rs:380-420). That cache is a measured
//!   answer to a 452k-leaf carryover set; v0 SVM account counts are
//!   thousands (spec §4.2-3), where a full fold of cached leaves is well
//!   under a millisecond. Copying a cache without its justifying measurement
//!   is how caches metastasize. When measurement says otherwise, the
//!   incremental tree lands WITH its "incremental == cold-recomputed"
//!   property test (spec §4.2-3), not before.
//! - Inclusion proofs. Proof generation/verification arrives with the
//!   consensus wiring (§9), which is X1-round work; a proof format shipped
//!   before anything verifies it is a frozen surface nobody audited.
//!
//! ## The leaf cache (spec §4.2-1)
//!
//! Per-account leaf caching is in-spec from day one, on the exact precedent
//! of `build_state_tree_with_eutxo_leaves` (state_root.rs:1234): a leaf is a
//! pure function of one account, the fold recomputes the ROOT from leaves
//! every time, and no cached root ever outlives its leaves. [`SvmState`]
//! keeps `(tree_key, value_hash)` per account, maintained in the ONE
//! mutation choke point ([`SvmState::set_account`]) so cache and accounts
//! cannot drift apart — and the §8-8 test proves cold == cached anyway.

use crate::account::Account;
use crate::params::DS_SVM_STATE;
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

/// Tree depth in bits — identical to state_root.rs:91 and for the same
/// reason: keys are SHA3-256 outputs, every leaf sits at full depth, and a
/// fixed-depth tree has exactly one shape per key set.
pub const TREE_DEPTH: usize = 256;

// The five preimage markers, byte-for-byte the state_root.rs set
// (state_root.rs:100-120). Same values on purpose: the *separator* is what
// keeps the two trees apart, and using the same marker bytes is what lets
// the cross-KAT compare constructions directly.
const MARK_LEAF: u8 = 0x00;
const MARK_NODE: u8 = 0x01;
const MARK_EMPTY: u8 = 0x02;
const MARK_KEY: u8 = 0x03;
const MARK_VALUE: u8 = 0x04;

/// Component tag for account leaves under [`DS_SVM_STATE`]'s key derivation.
/// The SVM tree currently commits one component; the tag exists anyway
/// because the consensus tree's history shows components accrete, and tags
/// are append-only from the first one (state_root.rs:126-140).
const TAG_SVM_ACCOUNT: u8 = 0x01;

/// A sparse Merkle tree with the state_root.rs construction, parameterised
/// by domain separator.
///
/// Same posture as the original (state_root.rs:410-423): a plain owned value
/// with `&mut self` insertion, no interior mutability, no memoized root —
/// [`Smt::root`] recomputes from the leaves every time, so it cannot
/// disagree with them. Leaves live in a `BTreeMap`, which iterates in key
/// order regardless of insertion order: same leaves ⇒ same root, full stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Smt {
    ds: [u8; 16],
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
}

impl Smt {
    /// An empty tree committing under `ds`. The domain separator is fixed at
    /// construction — a tree that could change separator mid-life would let
    /// one leaf set commit under two identities.
    pub fn with_domain(ds: [u8; 16]) -> Self {
        Smt { ds, leaves: BTreeMap::new() }
    }

    /// An empty tree under the production SVM separator.
    pub fn new_svm() -> Self {
        Smt::with_domain(DS_SVM_STATE)
    }

    /// Insert or update the value hash at `key`. Last write wins; both are
    /// deterministic functions of the final map contents, never of the call
    /// sequence (state_root.rs:437).
    pub fn insert(&mut self, key: [u8; 32], value_hash: [u8; 32]) {
        self.leaves.insert(key, value_hash);
    }

    /// Remove the leaf at `key` (account deletion, spec §4.2-2: delete
    /// refunds the bond and the entry leaves the tree).
    pub fn remove(&mut self, key: &[u8; 32]) {
        self.leaves.remove(key);
    }

    /// Number of committed leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree commits nothing.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The committed root — pure recomputation from the leaves
    /// (state_root.rs:455 and its §5.5 argument).
    pub fn root(&self) -> [u8; 32] {
        let empty = self.empty_hashes();
        let leaves: Vec<([u8; 32], [u8; 32])> =
            self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        self.subtree_root(&leaves, 0, &empty)
    }

    fn sha3(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(self.ds);
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    fn leaf_hash(&self, key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
        self.sha3(&[&[MARK_LEAF], key, value_hash])
    }

    fn node_hash(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        self.sha3(&[&[MARK_NODE], left, right])
    }

    /// `empty[d]` = root of an all-empty subtree topped at depth `d`
    /// (state_root.rs:230-243). Recomputed per call, like the original: a
    /// `OnceLock` is global mutable state and §5.5 bans the pattern.
    fn empty_hashes(&self) -> Vec<[u8; 32]> {
        let mut empty = vec![[0u8; 32]; TREE_DEPTH + 1];
        empty[TREE_DEPTH] = self.sha3(&[&[MARK_EMPTY]]);
        for d in (0..TREE_DEPTH).rev() {
            empty[d] = self.node_hash(&empty[d + 1], &empty[d + 1]);
        }
        empty
    }

    /// state_root.rs:260-283, verbatim construction: sorted keys + MSB-first
    /// branching means one `partition_point` per level and a recursion shape
    /// that is a function of the key set alone.
    fn subtree_root(
        &self,
        leaves: &[([u8; 32], [u8; 32])],
        depth: usize,
        empty: &[[u8; 32]],
    ) -> [u8; 32] {
        if leaves.is_empty() {
            return empty[depth];
        }
        if depth == TREE_DEPTH {
            debug_assert_eq!(leaves.len(), 1);
            let (key, value_hash) = &leaves[0];
            return self.leaf_hash(key, value_hash);
        }
        if leaves.len() == 1 {
            // The singleton fast path (state_root.rs:295-320) minus its
            // memo — same arithmetic in the same order, so the same value.
            let (key, value_hash) = &leaves[0];
            let mut h = self.leaf_hash(key, value_hash);
            let mut d = TREE_DEPTH;
            while d > depth {
                d -= 1;
                h = if bit(key, d) == 0 {
                    self.node_hash(&h, &empty[d + 1])
                } else {
                    self.node_hash(&empty[d + 1], &h)
                };
            }
            return h;
        }
        let split = leaves.partition_point(|(k, _)| bit(k, depth) == 0);
        let left = self.subtree_root(&leaves[..split], depth + 1, empty);
        let right = self.subtree_root(&leaves[split..], depth + 1, empty);
        self.node_hash(&left, &right)
    }
}

/// Bit `d` of `key`, most-significant first (state_root.rs:246-249): MSB-first
/// matches lexicographic byte order, which is what lets the fold split a
/// sorted slice with `partition_point`.
fn bit(key: &[u8; 32], d: usize) -> u8 {
    (key[d / 8] >> (7 - (d % 8))) & 1
}

/// Tree key of an account (spec §4.1):
/// `SHA3(DS_SVM_STATE ‖ MARK_KEY ‖ TAG_SVM_ACCOUNT ‖ address)`.
pub fn account_tree_key(address: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_SVM_STATE);
    h.update([MARK_KEY]);
    h.update([TAG_SVM_ACCOUNT]);
    h.update(address);
    h.finalize().into()
}

/// Leaf value of an account (spec §4.1):
/// `SHA3(DS_SVM_STATE ‖ MARK_VALUE ‖ canonical_serialization(account))`.
pub fn account_value_hash(account: &Account) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_SVM_STATE);
    h.update([MARK_VALUE]);
    h.update(account.to_canonical_bytes());
    h.finalize().into()
}

/// The hash of "no account here" — the tree's own empty-slot constant under
/// [`DS_SVM_STATE`] (`SHA3(DS ‖ MARK_EMPTY)`), reused by the layer-2 readonly
/// check for declared-but-absent accounts. A *defined* constant rather than
/// all-zeros, for the state_root.rs:113 reason: "empty" must be a value the
/// hash function produced, not a magic number an unrelated computation could
/// accidentally emit.
pub fn absent_account_hash() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_SVM_STATE);
    h.update([MARK_EMPTY]);
    h.finalize().into()
}

/// Canonical existence hash of an optional account: the leaf value for
/// present, [`absent_account_hash`] for absent. This is what the §6.4 layer-2
/// readonly-integrity check compares — existence itself is part of "did the
/// bytes drift", or deleting a readonly account would pass the check.
pub fn existence_hash(account: Option<&Account>) -> [u8; 32] {
    match account {
        Some(a) => account_value_hash(a),
        None => absent_account_hash(),
    }
}

/// The SVM account store: the accounts plus their cached leaves.
///
/// The two maps are maintained together in [`SvmState::set_account`] — the
/// single mutation choke point — so the §4.2-1 discipline ("what is cached is
/// re-derivable per-entry data, and no cached root outlives its leaves")
/// holds structurally: there IS no cached root, and a leaf is overwritten in
/// the same statement that overwrites its account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SvmState {
    accounts: BTreeMap<[u8; 32], Account>,
    /// address → (tree_key, value_hash); every entry a pure function of the
    /// corresponding `accounts` entry.
    leaves: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
}

impl SvmState {
    /// Empty state.
    pub fn new() -> Self {
        SvmState::default()
    }

    /// Genesis-style manifest funding (spec §9.2: "v0 development and tests
    /// fund accounts from a genesis-style manifest only" — the value bridge
    /// from the eUTXO plane needs a founder-visible conservation ruling that
    /// has not happened). TRUSTED input: manifests are not validated against
    /// the bond floor, because genesis registration of programs (balance 0,
    /// executable) is exactly the case the runtime's commit-time bond check
    /// never sees (programs are never merged as writable — §6.2 immutable).
    pub fn from_manifest(entries: impl IntoIterator<Item = ([u8; 32], Account)>) -> Self {
        let mut s = SvmState::new();
        for (addr, acct) in entries {
            s.set_account(addr, Some(acct));
        }
        s
    }

    /// The account at `address`, if any.
    pub fn get(&self, address: &[u8; 32]) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Number of live accounts.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Whether no accounts exist.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Iterate accounts in canonical (address) order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &Account)> {
        self.accounts.iter()
    }

    /// THE mutation choke point: set (`Some`) or delete (`None`) the account
    /// at `address`, and its cached leaf, in one place. Every commit in
    /// scheduler.rs lands here; nothing else in the crate writes either map.
    pub fn set_account(&mut self, address: [u8; 32], account: Option<Account>) {
        match account {
            Some(a) => {
                let leaf = (account_tree_key(&address), account_value_hash(&a));
                self.accounts.insert(address, a);
                self.leaves.insert(address, leaf);
            }
            None => {
                self.accounts.remove(&address);
                self.leaves.remove(&address);
            }
        }
    }

    /// The committed SVM root from the **cached** leaves (spec §4.2-1). This
    /// is the production path. Until the X1 round freezes `TAG_SVM_ROOT`,
    /// every KAT pins THIS root and never the outer consensus `state_root`
    /// (spec §4.1) — so this front cannot leak churn into anyone else's KATs.
    pub fn svm_root(&self) -> [u8; 32] {
        let mut t = Smt::new_svm();
        for (_, (k, v)) in self.leaves.iter() {
            t.insert(*k, *v);
        }
        t.root()
    }

    /// The same root recomputed **cold** — leaves re-derived from the
    /// accounts, ignoring the cache. This is the §8-8 control: public (not
    /// `cfg(test)`) because "recompute from scratch and compare" is exactly
    /// what an auditor or a doubting node operator should be able to run.
    pub fn svm_root_cold(&self) -> [u8; 32] {
        let mut t = Smt::new_svm();
        for (addr, a) in self.accounts.iter() {
            t.insert(account_tree_key(addr), account_value_hash(a));
        }
        t.root()
    }

    /// Total balance across all accounts, in u128 (the interfaces.rs
    /// arithmetic contract: entries are u64, SUMS are u128). Used by the
    /// block-level conservation test.
    pub fn total_balance(&self) -> u128 {
        self.accounts.values().map(|a| u128::from(a.balance_sat)).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cheap deterministic byte generator for test vectors: SHA3 in counter
    /// mode. Not a production RNG — a pinned sequence, so every run of the
    /// cross-KAT tests the same vectors (the "proptest entropy is not a pin"
    /// argument from the front plan).
    fn det_bytes32(seed: u64, i: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"bloch-svm-test-vectors");
        h.update(seed.to_le_bytes());
        h.update(i.to_le_bytes());
        h.finalize().into()
    }

    /// THE cross-KAT (spec §4.1 fallback obligation): the copied construction
    /// instantiated with the consensus separator must produce byte-identical
    /// roots to `state_root::Smt` — empty, singleton, and many-leaf shapes,
    /// randomized keys — forever. If either side ever changes construction,
    /// this goes red before any auditor has to find the drift.
    #[test]
    fn copy_matches_consensus_smt_forever() {
        use bloch_pos_committee::state_root::Smt as ConsensusSmt;
        // The consensus separator, spelled here rather than imported: the
        // POINT is to pin our copy against the frozen crate's behaviour, and
        // committee params.rs:184 defines DS_STATE = b"BLCH4:STATE\0\0\0\0\0".
        let ds_state: [u8; 16] = *b"BLCH4:STATE\0\0\0\0\0";

        for n in [0usize, 1, 2, 3, 7, 33, 100] {
            let mut ours = Smt::with_domain(ds_state);
            let mut theirs = ConsensusSmt::new();
            for i in 0..n {
                let k = det_bytes32(1, i as u64);
                let v = det_bytes32(2, i as u64);
                ours.insert(k, v);
                theirs.insert(k, v);
            }
            assert_eq!(ours.root(), theirs.root(), "construction drift at n={n}");
        }
    }

    /// And the negative control of the cross-KAT: under the SVM separator the
    /// same leaves produce a DIFFERENT root than under the consensus
    /// separator — the whole reason the copy exists (§4.1: "an SVM leaf must
    /// never be presentable as a consensus leaf").
    #[test]
    fn svm_domain_separates_from_consensus_domain() {
        let k = det_bytes32(3, 0);
        let v = det_bytes32(4, 0);
        let mut svm = Smt::new_svm();
        svm.insert(k, v);
        let mut cons = Smt::with_domain(*b"BLCH4:STATE\0\0\0\0\0");
        cons.insert(k, v);
        assert_ne!(svm.root(), cons.root());
        // Empty roots differ too — even "nothing" is domain-separated.
        assert_ne!(Smt::new_svm().root(), Smt::with_domain(*b"BLCH4:STATE\0\0\0\0\0").root());
    }

    /// §8-8: cold full rebuild == cached-leaf rebuild, through create /
    /// update / delete churn. This is the test that dies if `set_account`
    /// ever stops maintaining the leaf cache (mutation roster item h).
    #[test]
    fn cold_rebuild_equals_cached_rebuild() {
        let mut s = SvmState::new();
        for i in 0..40u64 {
            let addr = det_bytes32(5, i);
            s.set_account(addr, Some(Account::wallet(i * 1_000)));
        }
        assert_eq!(s.svm_root(), s.svm_root_cold(), "after creates");
        // Update half of them.
        for i in 0..20u64 {
            let addr = det_bytes32(5, i);
            let mut a = s.get(&addr).unwrap().clone();
            a.balance_sat += 1;
            a.data = vec![i as u8; 3];
            s.set_account(addr, Some(a));
        }
        assert_eq!(s.svm_root(), s.svm_root_cold(), "after updates");
        // Delete a third.
        for i in 0..13u64 {
            let addr = det_bytes32(5, i);
            s.set_account(addr, None);
        }
        assert_eq!(s.svm_root(), s.svm_root_cold(), "after deletes");
        assert_eq!(s.len(), 27);
    }

    /// §8-8 inherited iteration-order test (state_root.rs idiom): the same
    /// accounts inserted in shuffled orders produce the same root — the
    /// in-memory-layout variant of the `expected_bits` failure, pinned dead.
    #[test]
    fn insertion_order_cannot_matter() {
        let entries: Vec<([u8; 32], Account)> = (0..25u64)
            .map(|i| (det_bytes32(6, i), Account::wallet(i)))
            .collect();
        let forward = SvmState::from_manifest(entries.clone());
        let mut reversed_entries = entries.clone();
        reversed_entries.reverse();
        let reversed = SvmState::from_manifest(reversed_entries);
        // A deterministic interleave as the third order.
        let mut interleaved_entries = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            if i % 2 == 0 {
                interleaved_entries.push(e.clone());
            }
        }
        for (i, e) in entries.iter().enumerate() {
            if i % 2 == 1 {
                interleaved_entries.push(e.clone());
            }
        }
        let interleaved = SvmState::from_manifest(interleaved_entries);
        assert_eq!(forward.svm_root(), reversed.svm_root());
        assert_eq!(forward.svm_root(), interleaved.svm_root());
    }

    /// Delete really restores the prior root — the leaf leaves the tree
    /// rather than committing a tombstone (spec §4.2-2: the entry-count cost
    /// stops when the entry goes).
    #[test]
    fn delete_restores_prior_root() {
        let mut s = SvmState::new();
        let a1 = det_bytes32(7, 1);
        let a2 = det_bytes32(7, 2);
        s.set_account(a1, Some(Account::wallet(5)));
        let root_one = s.svm_root();
        s.set_account(a2, Some(Account::wallet(9)));
        assert_ne!(s.svm_root(), root_one);
        s.set_account(a2, None);
        assert_eq!(s.svm_root(), root_one);
    }

    /// The empty root is defined and pinned (a chain must be able to commit
    /// "no SVM state yet" unambiguously — and §9-1 says below the activation
    /// epoch `TAG_SVM_ROOT` commits exactly this constant, so its stability
    /// matters beyond aesthetics).
    #[test]
    fn empty_root_is_pinned() {
        let r = SvmState::new().svm_root();
        assert_eq!(r, Smt::new_svm().root());
        assert_eq!(
            hex::encode(r),
            // Pinned on first computation (2026-08-22); any construction or
            // separator change moves this and must be a visible review event.
            "6ee8f625fe15248233c9428d28bcb077ff04afe7487b8528df62b4d99b928606"
        );
    }
}
