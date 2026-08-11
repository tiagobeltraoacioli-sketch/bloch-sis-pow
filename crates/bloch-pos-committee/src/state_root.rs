// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SHA3-256 sparse Merkle tree that commits the consensus state (§5.5).
//!
//! `state_root` commits, in one tree:
//!
//! - the eUTXO set,
//! - the validator registry (pubkeys, stake, activation/exit epochs, slashed
//!   flag),
//! - the current and previous epoch attestation participation records,
//! - the randao mix history for the last 2 epochs,
//! - the taint set root (§4.1),
//! - the Coherence shielded-pool state: the accumulator root and the
//!   nullifier-set root (§6.6.2). Finality means nothing if the shielded
//!   ledger is not part of what gets finalized.
//!
//! ## The rule this module is shaped by
//!
//! §5.5, hard rule: every consensus-relevant value used to validate block *B*
//! must be derivable from *B.parent*'s **committed** state, never from
//! node-local mutable state. That rule exists because `expected_bits` was read
//! from a node-local mutable variable and split the mainnet on 2026-08-08 —
//! identical binaries, divergent local state, frozen followers.
//!
//! The API makes the rule structural rather than aspirational:
//!
//! - [`state_root`] is a pure function of a [`ConsensusState`] the caller
//!   passes in. There is no constructor that reads a database, a clock, or a
//!   config file.
//! - There is **no interior mutability and no cache anywhere in this module**
//!   — not even a memoized root or a lazily-initialized table of empty-subtree
//!   hashes. A cache is exactly the kind of node-local mutable state §5.5
//!   bans; recomputing instead costs a few hundred SHA3 calls and buys the
//!   property that two nodes given the same bytes cannot possibly disagree.
//! - Insertion order cannot matter: a key's position in the tree is fixed by
//!   the key itself, and the builder canonicalises through a `BTreeMap`. Two
//!   nodes that hold the same state but iterated it in different orders — the
//!   in-memory-layout variant of the `expected_bits` failure — produce the
//!   same root. This is tested, because it is the property that prevents a
//!   chain split.

use crate::params::DS_STATE;
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

/// Tree depth in bits. Keys are SHA3-256 outputs, so every leaf sits at the
/// full 256-bit depth; there is no variable-depth compaction. Compact SMTs are
/// smaller but their proofs depend on subtle "extension node" rules that have
/// produced real-world soundness bugs; a fixed-depth tree has exactly one
/// shape per key set, which is the property consensus needs most.
pub const TREE_DEPTH: usize = 256;

// -- Hash-preimage markers ---------------------------------------------------
//
// Every SHA3 invocation in this module starts with DS_STATE (16 bytes) and
// then one marker byte, so the five preimage shapes below can never collide
// with each other, and none of them can collide with any other protocol hash
// (§6.1). Without the leaf/node split, an attacker could present an internal
// node as a leaf (or vice versa) and forge proofs — the classic Merkle
// second-preimage trick.

/// Leaf node: `SHA3(DS_STATE ‖ 0x00 ‖ key ‖ value_hash)`. The key is bound
/// into the leaf so a proof for key K cannot be replayed for key K'.
const MARK_LEAF: u8 = 0x00;
/// Internal node: `SHA3(DS_STATE ‖ 0x01 ‖ left ‖ right)`.
const MARK_NODE: u8 = 0x01;
/// The empty leaf slot: `SHA3(DS_STATE ‖ 0x02)`. A *defined* constant rather
/// than all-zeros, so "empty" is a value the hash function produced and not a
/// magic number an unrelated computation could accidentally emit.
const MARK_EMPTY: u8 = 0x02;
/// Key derivation: `SHA3(DS_STATE ‖ 0x03 ‖ component_tag ‖ entry_key_bytes)`.
const MARK_KEY: u8 = 0x03;
/// Value hashing: `SHA3(DS_STATE ‖ 0x04 ‖ canonical_serialization)`.
const MARK_VALUE: u8 = 0x04;

// -- Component tags ----------------------------------------------------------
//
// One byte per state component, mixed into key derivation so entries from
// different components can never occupy the same leaf even if their natural
// keys coincide (e.g. validator index 5 vs. participation record for
// validator 5).

const TAG_EUTXO: u8 = 0x01;
const TAG_VALIDATOR: u8 = 0x02;
const TAG_PARTICIPATION_CURRENT: u8 = 0x03;
const TAG_PARTICIPATION_PREVIOUS: u8 = 0x04;
const TAG_RANDAO: u8 = 0x05;
const TAG_TAINT_ROOT: u8 = 0x06;
const TAG_COHERENCE_ACCUMULATOR: u8 = 0x07;
const TAG_COHERENCE_NULLIFIERS: u8 = 0x08;

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_STATE);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn leaf_hash(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    sha3(&[&[MARK_LEAF], key, value_hash])
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha3(&[&[MARK_NODE], left, right])
}

/// Hashes of the all-empty subtree at every depth. `empty[d]` is the root of
/// an empty subtree whose top sits at depth `d`; `empty[TREE_DEPTH]` is the
/// empty leaf slot.
///
/// Recomputed on every call on purpose. These are pure constants and the
/// obvious move is a `OnceLock` — but that is global mutable state, and §5.5
/// bans the *pattern*, not just the instances that have already bitten us.
/// 256 SHA3 calls are noise next to the tree walk itself.
fn empty_hashes() -> Vec<[u8; 32]> {
    let mut empty = vec![[0u8; 32]; TREE_DEPTH + 1];
    empty[TREE_DEPTH] = sha3(&[&[MARK_EMPTY]]);
    for d in (0..TREE_DEPTH).rev() {
        empty[d] = node_hash(&empty[d + 1], &empty[d + 1]);
    }
    empty
}

/// Bit `d` of `key`, most-significant first — bit 0 is the top branch of the
/// tree. MSB-first matches lexicographic byte order, which is what lets the
/// root computation split a *sorted* key slice with `partition_point`.
fn bit(key: &[u8; 32], d: usize) -> u8 {
    (key[d / 8] >> (7 - (d % 8))) & 1
}

/// Root of the subtree at `depth` containing exactly the (sorted) `leaves`.
///
/// Because keys are sorted lexicographically and branching is MSB-first, all
/// keys whose next bit is 0 form a prefix of the slice — one `partition_point`
/// per level, no allocation, and the recursion shape is a function of the key
/// set alone. That is the whole determinism argument: the same set of leaves
/// has exactly one root, no matter who computes it or in what order the
/// entries arrived.
fn subtree_root(leaves: &[([u8; 32], [u8; 32])], depth: usize, empty: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty[depth];
    }
    if depth == TREE_DEPTH {
        // Keys are unique 256-bit values, so a slice that survives 256 splits
        // holds exactly one entry.
        debug_assert_eq!(leaves.len(), 1);
        let (key, value_hash) = &leaves[0];
        return leaf_hash(key, value_hash);
    }
    let split = leaves.partition_point(|(k, _)| bit(k, depth) == 0);
    let left = subtree_root(&leaves[..split], depth + 1, empty);
    let right = subtree_root(&leaves[split..], depth + 1, empty);
    node_hash(&left, &right)
}

/// A Merkle inclusion proof: the sibling hash at every depth, ordered from the
/// root (depth 0) down to the leaf's sibling (depth 255).
///
/// Fixed length — a variable-length proof format would reintroduce the
/// compact-tree ambiguity this module deliberately avoids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    /// `siblings[d]` is the hash of the subtree that is *not* on the key's
    /// path at depth `d + 1`.
    pub siblings: Vec<[u8; 32]>,
}

/// The sparse Merkle tree over the committed consensus state.
///
/// This is a plain owned value with `&mut self` insertion — deliberate, and
/// different from interior mutability: the caller sees every mutation in the
/// type system, nothing mutates behind a `&self`, and there is no hidden
/// root cache to go stale. [`Smt::root`] recomputes from the leaves every
/// time, so it cannot disagree with the leaves.
///
/// Leaves live in a `BTreeMap`, which iterates in key order regardless of
/// insertion order. Together with the key-determined tree shape this gives
/// the §5.5 property: same state ⇒ same root, full stop.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Smt {
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
}

impl Smt {
    /// An empty tree. Its root is defined (see [`Smt::root`]) — a chain must
    /// be able to commit "no state yet" unambiguously at genesis.
    pub fn new() -> Self {
        Self { leaves: BTreeMap::new() }
    }

    /// Insert or update the value hash at `key`. Last write wins; updating a
    /// key to the same value is a no-op on the root. Both are deterministic
    /// functions of the final map contents, never of the call sequence.
    pub fn insert(&mut self, key: [u8; 32], value_hash: [u8; 32]) {
        self.leaves.insert(key, value_hash);
    }

    /// Number of committed leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree commits nothing.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The committed root. Pure recomputation from the leaves — no memoized
    /// value exists to be stale (§5.5: a cached root that survived a code
    /// path that forgot to invalidate it is exactly how `expected_bits`
    /// diverged).
    pub fn root(&self) -> [u8; 32] {
        let empty = empty_hashes();
        // BTreeMap iteration is already key-sorted, which subtree_root needs.
        let leaves: Vec<([u8; 32], [u8; 32])> =
            self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        subtree_root(&leaves, 0, &empty)
    }

    /// Inclusion proof for `key`, or `None` if the key is not committed.
    ///
    /// The proof is generated by the same split walk as [`Smt::root`], so it
    /// cannot structurally disagree with the root — there is one definition
    /// of the tree shape, not two.
    pub fn prove(&self, key: &[u8; 32]) -> Option<InclusionProof> {
        if !self.leaves.contains_key(key) {
            return None;
        }
        let empty = empty_hashes();
        let all: Vec<([u8; 32], [u8; 32])> =
            self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut slice: &[([u8; 32], [u8; 32])] = &all;
        for d in 0..TREE_DEPTH {
            let split = slice.partition_point(|(k, _)| bit(k, d) == 0);
            if bit(key, d) == 0 {
                siblings.push(subtree_root(&slice[split..], d + 1, &empty));
                slice = &slice[..split];
            } else {
                siblings.push(subtree_root(&slice[..split], d + 1, &empty));
                slice = &slice[split..];
            }
        }
        debug_assert_eq!(slice.len(), 1);
        Some(InclusionProof { siblings })
    }
}

/// Verify that `value_hash` is committed at `key` under `root`.
///
/// A free function taking everything by argument — a verifier must not need a
/// tree, a database, or any local state to check a proof (§5.5). This is what
/// a light client or the in-circuit verifier runs.
pub fn verify_inclusion(
    root: &[u8; 32],
    key: &[u8; 32],
    value_hash: &[u8; 32],
    proof: &InclusionProof,
) -> bool {
    if proof.siblings.len() != TREE_DEPTH {
        // Reject malformed proofs outright instead of folding whatever is
        // there: a shorter proof must never be able to verify against an
        // interior node.
        return false;
    }
    let mut h = leaf_hash(key, value_hash);
    for d in (0..TREE_DEPTH).rev() {
        let sib = &proof.siblings[d];
        h = if bit(key, d) == 0 { node_hash(&h, sib) } else { node_hash(sib, &h) };
    }
    h == *root
}

// -- Committed state components ---------------------------------------------
//
// Serialization here is canonical by construction: fixed field order, fixed
// little-endian widths, explicit length prefix on the one variable-length
// field. There is no serde and no derive-based format — a format that can
// change when a dependency changes is a consensus break waiting for a
// version bump.

/// One unspent eUTXO, as committed in state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EutxoEntry {
    /// Transaction id (a `block_id`-style SHA3 digest under §5.4 rules).
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Value in satoshis. A single output fits u64; **sums** of values must
    /// use u128 — see [`total_utxo_value`].
    pub value: u64,
    /// SHA3-256 of the locking script / eUTXO datum.
    pub script_hash: [u8; 32],
}

impl EutxoEntry {
    fn entry_key(&self) -> Vec<u8> {
        let mut k = Vec::with_capacity(36);
        k.extend_from_slice(&self.txid);
        k.extend_from_slice(&self.vout.to_le_bytes());
        k
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(76);
        s.extend_from_slice(&self.txid);
        s.extend_from_slice(&self.vout.to_le_bytes());
        s.extend_from_slice(&self.value.to_le_bytes());
        s.extend_from_slice(&self.script_hash);
        s
    }
}

/// One validator registry record, as committed in state (§5.5 list item 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRecord {
    /// Index into the registry; the key of this record.
    pub index: u32,
    /// The full hybrid ML-DSA-65 ‖ Falcon-1024 public key (≈ 3,745 B). The
    /// whole key is committed, not a hash of it: the registry *is* the
    /// authoritative key store, and committing a hash would leave the actual
    /// key bytes living in uncommitted local storage — the §5.5 failure shape.
    pub pubkey: Vec<u8>,
    /// Bonded stake in satoshis. Sums of stake must use u128 — see
    /// [`total_effective_stake`].
    pub stake: u64,
    /// Epoch the validator becomes active.
    pub activation_epoch: u64,
    /// Epoch the validator exits; `u64::MAX` means "no exit scheduled".
    pub exit_epoch: u64,
    /// Whether the validator has been slashed. Encoded strictly as 0x00/0x01.
    pub slashed: bool,
}

impl ValidatorRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.index.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(64 + self.pubkey.len());
        s.extend_from_slice(&self.index.to_le_bytes());
        // Length prefix: without it, (pubkey ‖ stake) and a one-byte-longer
        // pubkey with a shifted stake could serialize identically.
        s.extend_from_slice(&(self.pubkey.len() as u32).to_le_bytes());
        s.extend_from_slice(&self.pubkey);
        s.extend_from_slice(&self.stake.to_le_bytes());
        s.extend_from_slice(&self.activation_epoch.to_le_bytes());
        s.extend_from_slice(&self.exit_epoch.to_le_bytes());
        s.push(self.slashed as u8);
        s
    }
}

/// One validator's attestation participation in an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParticipationRecord {
    /// Index into the validator registry.
    pub validator_index: u32,
    /// Whether an attestation from this validator was included this epoch.
    pub attested: bool,
}

impl ParticipationRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.validator_index.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(5);
        s.extend_from_slice(&self.validator_index.to_le_bytes());
        s.push(self.attested as u8);
        s
    }
}

/// The randao mix for one epoch. State commits the last 2 (§5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandaoMix {
    pub epoch: u64,
    pub mix: [u8; 32],
}

impl RandaoMix {
    fn entry_key(&self) -> Vec<u8> {
        self.epoch.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(40);
        s.extend_from_slice(&self.epoch.to_le_bytes());
        s.extend_from_slice(&self.mix);
        s
    }
}

/// Everything `state_root` commits, passed **by argument** — this struct is
/// the §5.5 rule made into a type. A block validator builds it from the
/// parent block's committed state and from nothing else; there is no way to
/// compute a root from "whatever the node currently has in RAM" because no
/// such entry point exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusState<'a> {
    /// The eUTXO set. Order is irrelevant; duplicates by (txid, vout) resolve
    /// last-wins, deterministically.
    pub eutxos: &'a [EutxoEntry],
    /// The validator registry.
    pub validators: &'a [ValidatorRecord],
    /// Attestation participation for the current epoch.
    pub current_participation: &'a [ParticipationRecord],
    /// Attestation participation for the previous epoch.
    pub previous_participation: &'a [ParticipationRecord],
    /// Randao mix history — the last 2 epochs.
    pub randao_mixes: &'a [RandaoMix],
    /// Root of the taint set (§4.1), maintained by its own module.
    pub taint_root: [u8; 32],
    /// Coherence shielded pool: SHAKE-256 accumulator root (§6.6.2).
    pub coherence_accumulator_root: [u8; 32],
    /// Coherence shielded pool: nullifier-set root (§6.6.2).
    pub coherence_nullifier_root: [u8; 32],
}

fn derive_key(component_tag: u8, entry_key: &[u8]) -> [u8; 32] {
    sha3(&[&[MARK_KEY], &[component_tag], entry_key])
}

fn hash_value(serialized: &[u8]) -> [u8; 32] {
    sha3(&[&[MARK_VALUE], serialized])
}

/// Build the full state SMT from a [`ConsensusState`].
///
/// Exposed (rather than only [`state_root`]) so callers can generate
/// inclusion proofs against the same tree the root came from.
pub fn build_state_tree(state: &ConsensusState<'_>) -> Smt {
    let mut smt = Smt::new();
    for e in state.eutxos {
        smt.insert(derive_key(TAG_EUTXO, &e.entry_key()), hash_value(&e.serialize()));
    }
    for v in state.validators {
        smt.insert(derive_key(TAG_VALIDATOR, &v.entry_key()), hash_value(&v.serialize()));
    }
    for p in state.current_participation {
        smt.insert(
            derive_key(TAG_PARTICIPATION_CURRENT, &p.entry_key()),
            hash_value(&p.serialize()),
        );
    }
    for p in state.previous_participation {
        smt.insert(
            derive_key(TAG_PARTICIPATION_PREVIOUS, &p.entry_key()),
            hash_value(&p.serialize()),
        );
    }
    for r in state.randao_mixes {
        smt.insert(derive_key(TAG_RANDAO, &r.entry_key()), hash_value(&r.serialize()));
    }
    // The three foreign roots are committed as single leaves under their own
    // tags. They are roots of trees other modules own; committing them here
    // is what makes shielded-pool reorganisation impossible after finality
    // (§6.6.2) without re-hashing every nullifier into this tree.
    smt.insert(derive_key(TAG_TAINT_ROOT, &[]), hash_value(&state.taint_root));
    smt.insert(
        derive_key(TAG_COHERENCE_ACCUMULATOR, &[]),
        hash_value(&state.coherence_accumulator_root),
    );
    smt.insert(
        derive_key(TAG_COHERENCE_NULLIFIERS, &[]),
        hash_value(&state.coherence_nullifier_root),
    );
    smt
}

/// The state root committed in `BlockHeaderV4.state_root` (§5.3, §5.5) — a
/// pure function of the passed-in state.
pub fn state_root(state: &ConsensusState<'_>) -> [u8; 32] {
    build_state_tree(state).root()
}

/// Sum of all committed eUTXO values, in u128.
///
/// Why u128: one output fits u64 (21e9 BLCH × 1e8 sat < 2^64), but a *sum*
/// over an adversarially-chosen set does not — and a silent wrap here is not
/// a bug, it is a consensus split, the same class of failure `sample()`
/// guards its cumulative-stake array against.
pub fn total_utxo_value(eutxos: &[EutxoEntry]) -> u128 {
    eutxos.iter().map(|e| e.value as u128).sum()
}

/// Sum of all bonded stake, in u128. Same overflow argument as
/// [`total_utxo_value`].
pub fn total_effective_stake(validators: &[ValidatorRecord]) -> u128 {
    validators.iter().map(|v| v.stake as u128).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        // Spread test keys through the whole key space via the real
        // derivation, so tests exercise realistic (deep, divergent) paths.
        derive_key(0xEE, &[n])
    }

    fn val(n: u8) -> [u8; 32] {
        hash_value(&[n])
    }

    #[test]
    fn empty_tree_has_a_defined_stable_nonzero_root() {
        let a = Smt::new().root();
        let b = Smt::new().root();
        assert_eq!(a, b, "empty root must be a constant of the protocol");
        assert_ne!(a, [0u8; 32], "empty root must be a hash output, not a magic zero");
    }

    #[test]
    fn insertion_order_does_not_change_the_root() {
        // THE §5.5 property. If this test can fail, the chain can split on
        // nothing more than two nodes iterating their storage differently.
        let entries: Vec<([u8; 32], [u8; 32])> = (0..32u8).map(|i| (key(i), val(i))).collect();

        let mut forward = Smt::new();
        for (k, v) in &entries {
            forward.insert(*k, *v);
        }
        let mut reverse = Smt::new();
        for (k, v) in entries.iter().rev() {
            reverse.insert(*k, *v);
        }
        // A deterministic shuffle (stride 7 is coprime with 32, so it visits
        // every entry) — no rand dependency in a consensus crate.
        let mut strided = Smt::new();
        let mut i = 0usize;
        for _ in 0..entries.len() {
            let (k, v) = &entries[i];
            strided.insert(*k, *v);
            i = (i + 7) % entries.len();
        }

        assert_eq!(forward.root(), reverse.root());
        assert_eq!(forward.root(), strided.root());
    }

    #[test]
    fn update_is_last_wins_and_deterministic() {
        let mut a = Smt::new();
        a.insert(key(1), val(1));
        a.insert(key(1), val(2)); // overwrite

        let mut b = Smt::new();
        b.insert(key(1), val(2)); // direct

        assert_eq!(a.root(), b.root(), "an updated key must equal a directly-inserted one");
        assert_eq!(a.len(), 1);

        let mut c = Smt::new();
        c.insert(key(1), val(1));
        assert_ne!(a.root(), c.root(), "the pre-update root must differ");
    }

    #[test]
    fn inclusion_proof_verifies() {
        let mut smt = Smt::new();
        for i in 0..16u8 {
            smt.insert(key(i), val(i));
        }
        let root = smt.root();
        for i in 0..16u8 {
            let proof = smt.prove(&key(i)).expect("committed key must be provable");
            assert_eq!(proof.siblings.len(), TREE_DEPTH);
            assert!(
                verify_inclusion(&root, &key(i), &val(i), &proof),
                "valid proof must verify for key {i}"
            );
        }
    }

    #[test]
    fn proof_for_absent_key_is_none() {
        let mut smt = Smt::new();
        smt.insert(key(1), val(1));
        assert!(smt.prove(&key(2)).is_none());
    }

    #[test]
    fn tampered_proofs_fail() {
        let mut smt = Smt::new();
        for i in 0..8u8 {
            smt.insert(key(i), val(i));
        }
        let root = smt.root();
        let proof = smt.prove(&key(3)).unwrap();

        // Baseline sanity.
        assert!(verify_inclusion(&root, &key(3), &val(3), &proof));

        // Flip one bit in one sibling.
        let mut bad = proof.clone();
        bad.siblings[100][0] ^= 0x01;
        assert!(!verify_inclusion(&root, &key(3), &val(3), &bad));

        // Wrong value under a genuine proof.
        assert!(!verify_inclusion(&root, &key(3), &val(4), &proof));

        // Proof replayed for a different (also committed) key — the key is
        // bound into the leaf hash precisely so this fails.
        assert!(!verify_inclusion(&root, &key(4), &val(3), &proof));

        // Wrong root.
        let mut other = smt.clone();
        other.insert(key(200), val(200));
        assert!(!verify_inclusion(&other.root(), &key(3), &val(3), &proof));

        // Truncated proof must be rejected outright, not folded partially.
        let mut short = proof.clone();
        short.siblings.pop();
        assert!(!verify_inclusion(&root, &key(3), &val(3), &short));
    }

    // -- full consensus-state commitment -------------------------------------

    /// Owned backing storage for a [`ConsensusState`] fixture: eUTXOs,
    /// validators, current/previous participation, randao mixes.
    type Fx = (
        Vec<EutxoEntry>,
        Vec<ValidatorRecord>,
        Vec<ParticipationRecord>,
        Vec<ParticipationRecord>,
        Vec<RandaoMix>,
    );

    fn fixture() -> Fx {
        let eutxos: Vec<EutxoEntry> = (0..10u8)
            .map(|i| EutxoEntry {
                txid: key(i),
                vout: i as u32,
                value: 840_000_000_000 + i as u64,
                script_hash: val(i),
            })
            .collect();
        let validators: Vec<ValidatorRecord> = (0..4u8)
            .map(|i| ValidatorRecord {
                index: i as u32,
                // Real hybrid keys are ≈ 3,745 B; a smaller stand-in is fine
                // because only the serialization path matters here.
                pubkey: vec![i; 64],
                stake: 100_000_000_000 * (i as u64 + 1),
                activation_epoch: 1,
                exit_epoch: u64::MAX,
                slashed: false,
            })
            .collect();
        let current: Vec<ParticipationRecord> = (0..4u32)
            .map(|i| ParticipationRecord { validator_index: i, attested: i % 2 == 0 })
            .collect();
        let previous: Vec<ParticipationRecord> = (0..4u32)
            .map(|i| ParticipationRecord { validator_index: i, attested: true })
            .collect();
        let randao =
            vec![RandaoMix { epoch: 41, mix: val(41) }, RandaoMix { epoch: 42, mix: val(42) }];
        (eutxos, validators, current, previous, randao)
    }

    fn state(f: &Fx) -> ConsensusState<'_> {
        ConsensusState {
            eutxos: &f.0,
            validators: &f.1,
            current_participation: &f.2,
            previous_participation: &f.3,
            randao_mixes: &f.4,
            taint_root: val(101),
            coherence_accumulator_root: val(102),
            coherence_nullifier_root: val(103),
        }
    }

    #[test]
    fn state_root_is_independent_of_component_iteration_order() {
        // Same state, reversed storage-iteration order — the in-memory-layout
        // variant of the 2026-08-08 failure. Must commit identically.
        let f = fixture();
        let root_a = state_root(&state(&f));

        let mut g = f.clone();
        g.0.reverse();
        g.1.reverse();
        g.2.reverse();
        g.3.reverse();
        g.4.reverse();
        let root_b = state_root(&state(&g));

        assert_eq!(root_a, root_b);
    }

    #[test]
    fn every_component_field_is_load_bearing() {
        // Mutate one field of one entry of each component and assert the root
        // moves. If any field were dropped from serialization, that field
        // would be un-finalized state — mutable without detection, which is
        // the §6.6.2 asymmetry for whatever it governs.
        let f = fixture();
        let base = state_root(&state(&f));
        let mut roots = vec![base];

        macro_rules! mutated {
            ($m:expr) => {{
                let mut g = f.clone();
                #[allow(clippy::redundant_closure_call)]
                ($m)(&mut g);
                let r = state_root(&state(&g));
                assert_ne!(r, base, "mutation must change the state root");
                roots.push(r);
            }};
        }

        mutated!(|g: &mut Fx| g.0[3].value += 1);
        mutated!(|g: &mut Fx| g.0[3].vout += 1);
        mutated!(|g: &mut Fx| g.0[3].script_hash[0] ^= 1);
        mutated!(|g: &mut Fx| g.0[3].txid[31] ^= 1);
        mutated!(|g: &mut Fx| g.0.pop().map(|_| ()).unwrap()); // removal
        mutated!(|g: &mut Fx| g.1[2].stake += 1);
        mutated!(|g: &mut Fx| g.1[2].pubkey[0] ^= 1);
        mutated!(|g: &mut Fx| g.1[2].activation_epoch += 1);
        mutated!(|g: &mut Fx| g.1[2].exit_epoch = 999);
        mutated!(|g: &mut Fx| g.1[2].slashed = true);
        mutated!(|g: &mut Fx| g.2[1].attested = !g.2[1].attested);
        mutated!(|g: &mut Fx| g.3[1].attested = !g.3[1].attested);
        mutated!(|g: &mut Fx| g.4[0].mix[5] ^= 1);
        mutated!(|g: &mut Fx| g.4[0].epoch += 2);

        // Singleton roots.
        for i in 0..3 {
            let f2 = f.clone();
            let mut s = state(&f2);
            match i {
                0 => s.taint_root[0] ^= 1,
                1 => s.coherence_accumulator_root[0] ^= 1,
                _ => s.coherence_nullifier_root[0] ^= 1,
            }
            let r = state_root(&s);
            assert_ne!(r, base);
            roots.push(r);
        }

        // All mutations must also differ pairwise — two different states
        // committing to the same root would be a commitment collision.
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(roots[i], roots[j], "distinct states {i} and {j} share a root");
            }
        }
    }

    #[test]
    fn current_and_previous_participation_do_not_alias() {
        // Identical records under the two epoch tags must land on different
        // leaves — otherwise "attested last epoch" and "attested this epoch"
        // would be the same committed fact.
        let f = fixture();
        let base = state_root(&state(&f));

        let mut g = f.clone();
        std::mem::swap(&mut g.2, &mut g.3);
        // current (even indices attested) and previous (all attested) differ,
        // so swapping them must move the root.
        assert_ne!(state_root(&state(&g)), base);
    }

    #[test]
    fn state_entries_are_provable_against_the_state_root() {
        let f = fixture();
        let s = state(&f);
        let tree = build_state_tree(&s);
        let root = tree.root();
        assert_eq!(root, state_root(&s), "tree and root entry points must agree");

        let v = &f.1[2];
        let k = derive_key(TAG_VALIDATOR, &v.entry_key());
        let vh = hash_value(&v.serialize());
        let proof = tree.prove(&k).expect("committed validator must be provable");
        assert!(verify_inclusion(&root, &k, &vh, &proof));

        // A different stake for the same validator must not verify under the
        // same proof — this is what lets a light client trust a claimed stake.
        let mut forged = v.clone();
        forged.stake += 1;
        assert!(!verify_inclusion(&root, &k, &hash_value(&forged.serialize()), &proof));
    }

    #[test]
    fn balance_sums_use_u128_and_survive_u64_overflow() {
        // Three near-max u64 outputs: their sum overflows u64 by construction
        // but must be exact in u128.
        let eutxos: Vec<EutxoEntry> = (0..3u8)
            .map(|i| EutxoEntry {
                txid: key(i),
                vout: 0,
                value: u64::MAX - 1,
                script_hash: val(i),
            })
            .collect();
        let expected = 3u128 * (u64::MAX as u128 - 1);
        assert_eq!(total_utxo_value(&eutxos), expected);

        let validators: Vec<ValidatorRecord> = (0..3u8)
            .map(|i| ValidatorRecord {
                index: i as u32,
                pubkey: vec![0; 8],
                stake: u64::MAX,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                slashed: false,
            })
            .collect();
        assert_eq!(total_effective_stake(&validators), 3u128 * u64::MAX as u128);
    }
}
