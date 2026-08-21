// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SHA3-256 sparse Merkle tree that commits the consensus state (§5.5).
//!
//! `state_root` commits, in one tree:
//!
//! - the eUTXO set,
//! - the validator registry (pubkeys, stake, activation/exit/withdrawable
//!   epochs, slashed flag, RANDAO chain head and position, withdrawal
//!   credentials),
//! - the current and previous epoch attestation participation records,
//! - the randao mix history for the last 2 epochs,
//! - the justification/finality bookkeeping: the engine's full checkpoint
//!   history, the current/previous-justified and finalized checkpoints, the
//!   inactivity-leak ledger and the epoch clock,
//! - the epoch-boundary votes pending the next finality tally,
//! - the LMD-GHOST bookkeeping: latest message per validator and the
//!   equivocator bar,
//! - the staking queues: the deposit history and the delegation history,
//! - fee rewards accrued to proposers, pending the epoch boundary,
//! - the L1 fee-market leaf: the price this block charged and the usage the
//!   next block's controller reads ([`TAG_BASE_FEE`], 2026-08-12),
//! - the per-delegator ledgers: cumulative slashing losses and cumulative fee
//!   rewards ([`TAG_DELEGATOR_SLASH_LOSS`], [`TAG_DELEGATOR_FEE_REWARD`]),
//! - the taint set root (§4.1),
//! - the cumulative issued supply — the hard-cap invariant's counter
//!   ([`TAG_ISSUED_SUPPLY`], 2026-08-12),
//! - the Coherence shielded-pool state: the accumulator root and the
//!   nullifier-set root (§6.6.2). Finality means nothing if the shielded
//!   ledger is not part of what gets finalized.
//!
//! The list is closed, and each extension carries the same argument. The
//! 2026-08-12 fee-market pair is the latest: `TAG_BASE_FEE` because the next
//! block's price is *derived from* it — a price kept in node-local execution
//! bookkeeping is `expected_bits` with a different name — and
//! `TAG_DELEGATOR_FEE_REWARD` because a withdrawal pays it out, so two nodes
//! disagreeing on it would pay different amounts for the same exit. Both
//! clear the cannot-be-reconstructed bar; both are recorded here and in
//! `BLOCH-L1-FEE-MARKET.md` §4.4/§6.1 rather than smuggled.
//!
//! It was first extended on 2026-08-11, and the reason is
//! the reason the list exists at all: §5.5's hard rule ("every
//! consensus-relevant value comes from the parent's *committed* state") is
//! senior to the freeze that closed the list, and the transition demonstrably
//! read the bookkeeping components above — finality roots at step 6, the
//! RANDAO chain position at step 5, the queues and pending fees at every
//! boundary — while the root did not bind them. Uncommitted
//! consensus-relevant state is the `expected_bits` shape: a node that syncs
//! by state root cannot reconstruct it, and two nodes that disagree in it
//! validate differently while their roots claim agreement. The extension was
//! recorded as a visible spec change (migration doc §5.5, interfaces
//! §Boundary 7), not smuggled; "we need more state" without the
//! cannot-be-reconstructed argument remains insufficient grounds to touch
//! the list.
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
// Added by the 2026-08-11 extension (see module docs). Tags are append-only:
// reusing or renumbering one would silently re-key every leaf of the
// component it named.
const TAG_FINALITY: u8 = 0x09;
const TAG_PENDING_VOTE: u8 = 0x0A;
const TAG_FC_MESSAGE: u8 = 0x0B;
const TAG_FC_EQUIVOCATOR: u8 = 0x0C;
const TAG_DEPOSIT_QUEUE: u8 = 0x0D;
const TAG_DELEGATION: u8 = 0x0E;
const TAG_PENDING_FEE: u8 = 0x0F;

/// The L1 EVM execution commitment (`docs/specs/BLOCH-L1-EVM-STATE-MODEL.md`).
/// One singleton leaf, same posture as the taint and Coherence roots: the EVM
/// state lives in its own commitment structure (a keccak-256 MPT, carried from
/// the execution layer) and only its digest enters this tree. Per-account EVM
/// state is deliberately NOT expanded into SMT leaves — see the spec, §2.
///
/// Numbered 0x10 and not 0x09: it was authored against 0x09 on the same day the
/// S5.5 bookkeeping extension claimed 0x09-0x0F, and the two never saw each
/// other. Renumbering is free now and never again — tags are append-only
/// because reusing one silently re-keys every leaf of the component it named.
const TAG_EVM_COMMITMENT: u8 = 0x10;

// Slashing (§7.3), added 2026-08-12. The slash's *effects* on the registry (the
// `slashed` flag, the reduced bond) were already committed through the
// validator component; what was not, and had to be, is the bookkeeping that
// decides whether a slash may happen at all — above all the applied-evidence
// set, which is the entire anti-replay defence. A node that state-synced
// without it could be handed the same evidence twice and would slash twice, or
// could refuse to slash because its neighbour's set said otherwise: two nodes,
// same headers, different verdicts. The §5.5 failure shape exactly.
//
// `ejected` is NOT here on purpose — see `slashing::SlashingState::ejected_ids`.
const TAG_SLASH_APPLIED: u8 = 0x11;
const TAG_SLASH_WINDOW: u8 = 0x12;
const TAG_DELEGATOR_SLASH_LOSS: u8 = 0x13;

/// Cumulative issued supply in satoshis (2026-08-12): one singleton leaf, a
/// `u128` serialized as 16 LE bytes. This is the counter the hard-cap
/// consensus invariant reads (`tokenomics_v4::TOTAL_SUPPLY_SAT`; the
/// transition refuses any block whose committed issuance exceeds it —
/// `TransitionError::SupplyCapExceeded`).
///
/// Why it must be committed and cannot be derived: the amount actually minted
/// per epoch depends on participation (a validator whose attestation never
/// landed forfeits its slice — never minted) and on per-account truncation in
/// `rewards::distribute`, so "how much has been issued" is a function of the
/// whole chain history, not of the epoch number. Uncommitted, it is the §5.5
/// failure shape verbatim: a state-synced node cannot reconstruct it, and two
/// nodes that disagree in it enforce the cap differently while their roots
/// claim agreement. Passes the module docs' cannot-be-reconstructed bar for
/// extending the closed list; recorded as a visible revision in the migration
/// doc §5.5 (same precedent as the slashing tags above) — not smuggled.
const TAG_ISSUED_SUPPLY: u8 = 0x14;

/// The L1 fee-market price leaf (2026-08-12): one singleton, holding the base
/// fee this block's transactions were priced at plus the block's measured
/// usage on both controller axes — exactly the §4.4 triple the fee-market
/// spec defines (`BLOCH-L1-FEE-MARKET.md`; the spec drafted it as "tag 0x09"
/// before the S5.5 extension claimed 0x09–0x0F — tags are append-only, so it
/// lands here).
///
/// Why it must be committed: the next block's base fee is **derived from**
/// this leaf by `fee_market::next_base_fee`. Read from node-local execution
/// bookkeeping instead, it is `expected_bits` verbatim — an uncommitted
/// retarget input, the exact shape of the 2026-08-08 consensus split. (The
/// EVM segment's own pair inside [`EvmCommitment`] is carried from the
/// execution layer and prices the EVM segment; this leaf is the L1 market's,
/// computed by the transition itself.)
const TAG_BASE_FEE: u8 = 0x15;

/// Cumulative fee rewards credited to one delegator account (2026-08-12),
/// the earning mirror of [`TAG_DELEGATOR_SLASH_LOSS`]: the epoch boundary
/// routes each producer's fee share through the stake-origin + commission
/// split (`fee_market::distribute_producer_fees`), and the delegators' side
/// settles here rather than into the operator's bond. Same replay argument as
/// the loss ledger — editing delegation records would reshuffle warm-up
/// history — and same §5.5 argument: a withdrawal pays this out, so a node
/// that disagreed on it would pay a different amount for the same exit.
const TAG_DELEGATOR_FEE_REWARD: u8 = 0x16;


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
    if leaves.len() == 1 {
        // A subtree holding exactly one leaf folds that leaf against the empty
        // constant at every remaining level. Doing it here rather than by
        // recursing is the same arithmetic in the same order — see
        // `singleton_subtree_root` for why it is also the same value.
        let (key, value_hash) = &leaves[0];
        return singleton_subtree_root(key, value_hash, depth, empty);
    }
    let split = leaves.partition_point(|(k, _)| bit(k, depth) == 0);
    let left = subtree_root(&leaves[..split], depth + 1, empty);
    let right = subtree_root(&leaves[split..], depth + 1, empty);
    node_hash(&left, &right)
}

/// Root of the subtree at `depth` that holds `key` as its only leaf.
///
/// Identical, hash for hash, to what [`subtree_root`] computes by recursing:
/// at each level the leaf sits on the side its key bit selects and the other
/// side is the empty constant one level down. The loop exists because the
/// recursion costs `TREE_DEPTH - depth` calls per leaf, and with a real
/// carryover set that is the whole cost of a root.
///
/// **Why this is memoized and [`Smt::root`] is not.** The module's rule is
/// that no cached root may outlive the leaves it was computed from — a stale
/// root is how `expected_bits` split consensus, and that rule stands. This
/// cache does not weaken it: the key is the *entire input* `(key, value_hash,
/// depth)` of a pure function, so a hit returns what a recomputation would
/// return. There is no state to invalidate, and therefore no invalidation to
/// forget. A leaf whose value changes hashes to a different `value_hash` and
/// so lands on a different cache entry; a leaf whose neighbours change is
/// looked up at a different `depth`.
fn singleton_subtree_root(
    key: &[u8; 32],
    value_hash: &[u8; 32],
    depth: usize,
    empty: &[[u8; 32]],
) -> [u8; 32] {
    debug_assert!(depth <= TREE_DEPTH);
    if let Some(hit) = memo_get(&(*key, *value_hash, depth)) {
        return hit;
    }
    let mut h = leaf_hash(key, value_hash);
    let mut d = TREE_DEPTH;
    while d > depth {
        d -= 1;
        h = if bit(key, d) == 0 { node_hash(&h, &empty[d + 1]) } else { node_hash(&empty[d + 1], &h) };
    }
    memo_put((*key, *value_hash, depth), h);
    h
}

/// Look a singleton up, promoting a hit from the previous generation.
///
/// Promotion is what makes the two generations worth having: an entry still in
/// use is copied back into `hot` the first time it is read after a rotation, so
/// the live working set survives every rotation from then on. Without it, a
/// rotation would demote the whole set and the generation after would drop it.
fn memo_get(key: &SingletonKey) -> Option<[u8; 32]> {
    SINGLETON_MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if let Some(hit) = m.hot.get(key).copied() {
            return Some(hit);
        }
        let hit = m.cold.get(key).copied()?;
        m.hot.insert(*key, hit);
        Some(hit)
    })
}

#[cfg(test)]
fn memo_generation_sizes() -> (usize, usize) {
    SINGLETON_MEMO.with(|m| {
        let m = m.borrow();
        (m.hot.len(), m.cold.len())
    })
}

fn memo_put(key: SingletonKey, value: [u8; 32]) {
    SINGLETON_MEMO.with(|m| {
        let mut m = m.borrow_mut();
        m.hot.insert(key, value);
        if m.hot.len() >= SINGLETON_MEMO_GENERATION {
            // Rotate, never clear. The old `hot` becomes `cold` and is still
            // readable; only the generation before it is dropped.
            m.cold = std::mem::take(&mut m.hot);
        }
    });
}

/// Entries one generation of the singleton memo holds before it rotates.
///
/// Sized above a full carryover-scale leaf set (~4.5e5) so the live set fits
/// in one generation with room to spare, at roughly 100 bytes per entry. Two
/// generations are held, so the memory bound is twice this.
///
/// **Why two generations and not one bounded map.** This used to be a single
/// map that called `clear()` on reaching its limit. Correct — every entry is
/// recomputable — but the cost of being right that way is a cliff: measured at
/// Genesis-4's carryover size, a state root with a warm memo takes 1.2s and
/// the same root with a cold one takes **51 seconds**. A wholesale clear
/// therefore did not cost "a few misses", it cost a 40x block, at an
/// unpredictable moment, on whichever node happened to fill first. Rotating
/// drops at most the generation before last, and anything still in use is
/// promoted back on its first read (see [`memo_get`]), so the working set is
/// never dropped while it is working.
const SINGLETON_MEMO_GENERATION: usize = 600_000;

type SingletonKey = ([u8; 32], [u8; 32], usize);

/// Two generations of the singleton memo. Contents never affect a result —
/// every entry is a pure function of its key — so rotation is a performance
/// decision end to end, with no consensus surface.
#[derive(Default)]
struct SingletonMemo {
    hot: std::collections::HashMap<SingletonKey, [u8; 32]>,
    cold: std::collections::HashMap<SingletonKey, [u8; 32]>,
}

thread_local! {
    /// Per-thread so the hot consensus loop never contends on a lock. Purity
    /// makes duplication across threads a memory question, never a
    /// correctness one: every thread that computes an entry computes the
    /// same bytes.
    static SINGLETON_MEMO: std::cell::RefCell<SingletonMemo> =
        std::cell::RefCell::new(SingletonMemo::default());
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
    /// Head of the validator's SHAKE-256 RANDAO chain (§6.3), **as advanced**:
    /// every accepted block moves its proposer's head one link down. The
    /// transition reads it to judge the next reveal (step 5), which is
    /// exactly the §5.5 test for "must be committed" — before the 2026-08-11
    /// extension it mutated per block in local state only.
    pub randao_commitment: [u8; 32],
    /// How far down the chain the head is — the other half of the committed
    /// [`crate::beacon::RevealState`] pair.
    pub reveals_used: u32,
    /// Epoch the bonded stake becomes withdrawable; `u64::MAX` until an exit
    /// schedules it. Uncommitted, a node could release stake early without
    /// any root disagreeing.
    pub withdrawable_epoch: u64,
    /// Where the stake returns on withdrawal. Opaque bytes (the address
    /// format is the node's, per the interfaces open point) — opaque is fine,
    /// uncommitted is not: a swapped destination must move the root.
    pub withdrawal_credentials: Vec<u8>,
    /// Commission the operator charges on its delegators' rewards, in basis
    /// points (2026-08-12). Committed because the epoch boundary *pays with
    /// it*: it decides the operator/delegator split of both issuance and fees
    /// (`rewards::distribute`, `fee_market::distribute_producer_fees`). Read
    /// from anywhere but committed state, two nodes would compound different
    /// bonds from the same block — the §5.5 shape applied to revenue.
    pub commission_bps: u128,
}

impl ValidatorRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.index.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s =
            Vec::with_capacity(120 + self.pubkey.len() + self.withdrawal_credentials.len());
        s.extend_from_slice(&self.index.to_le_bytes());
        // Length prefix: without it, (pubkey ‖ stake) and a one-byte-longer
        // pubkey with a shifted stake could serialize identically.
        s.extend_from_slice(&(self.pubkey.len() as u32).to_le_bytes());
        s.extend_from_slice(&self.pubkey);
        s.extend_from_slice(&self.stake.to_le_bytes());
        s.extend_from_slice(&self.activation_epoch.to_le_bytes());
        s.extend_from_slice(&self.exit_epoch.to_le_bytes());
        s.push(self.slashed as u8);
        s.extend_from_slice(&self.randao_commitment);
        s.extend_from_slice(&self.reveals_used.to_le_bytes());
        s.extend_from_slice(&self.withdrawable_epoch.to_le_bytes());
        // Second variable-length field, second length prefix — same
        // no-ambiguity argument as the pubkey's.
        s.extend_from_slice(&(self.withdrawal_credentials.len() as u32).to_le_bytes());
        s.extend_from_slice(&self.withdrawal_credentials);
        // Appended last, after the final variable-length field: appending is
        // the only edit to a committed serialization that cannot re-key an
        // existing prefix by accident.
        s.extend_from_slice(&self.commission_bps.to_le_bytes());
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

// -- 2026-08-11 components (module docs: the one extension) ------------------

/// One checkpoint as committed — epoch plus the root of its epoch's first
/// block. The root is raw bytes, not a `BlockId`, for the same reason the
/// finality module's own `Checkpoint` is: it is a value to compare, never an
/// identity to mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub epoch: u64,
    pub root: [u8; 32],
}

impl CheckpointRecord {
    fn write_into(&self, s: &mut Vec<u8>) {
        s.extend_from_slice(&self.epoch.to_le_bytes());
        s.extend_from_slice(&self.root);
    }
}

/// Cumulative inactivity leak charged to one validator, in satoshis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeakRecord {
    pub validator: u32,
    pub leaked_sat: u64,
}

/// The justification/finality bookkeeping, committed as one leaf under
/// [`TAG_FINALITY`]. This is the full fold state of the finality engine plus
/// the previous-justified checkpoint the frozen `FinalityView` carries — the
/// values step 6 of the transition compares headers against, and the values
/// surround-vote slashing is judged by. A single leaf (not per-checkpoint
/// leaves) because the engine's state is only ever read and replaced whole;
/// nothing proves one historical justification in isolation today. Splitting
/// it later is a visible re-keying, not a silent one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityRecord {
    /// Every justified checkpoint the engine holds, any order — serialization
    /// sorts by epoch, so the committed bytes are a function of the set.
    pub justified: Vec<CheckpointRecord>,
    /// Highest justified checkpoint.
    pub current_justified: CheckpointRecord,
    /// Justified checkpoint as of the previous epoch (Casper's second round).
    pub previous_justified: CheckpointRecord,
    /// Highest finalized checkpoint.
    pub finalized: CheckpointRecord,
    /// Inactivity-leak ledger, any order — serialization sorts by validator.
    pub leaked: Vec<LeakRecord>,
    /// Next epoch the engine will accept — the "dense, in-order" clock.
    pub next_epoch: u64,
}

impl FinalityRecord {
    fn serialize(&self) -> Vec<u8> {
        // Canonicalise here, not in the builder: the committed bytes must be
        // a function of the *content*, whichever order a caller assembled the
        // vectors in (rule: insertion order cannot matter).
        let mut justified = self.justified.clone();
        justified.sort_by_key(|c| c.epoch);
        let mut leaked = self.leaked.clone();
        leaked.sort_by_key(|l| l.validator);

        let mut s = Vec::with_capacity(48 + 40 * justified.len() + 12 * leaked.len() + 128);
        // Count prefixes keep the two variable-length lists unambiguous.
        s.extend_from_slice(&(justified.len() as u64).to_le_bytes());
        for c in &justified {
            c.write_into(&mut s);
        }
        self.current_justified.write_into(&mut s);
        self.previous_justified.write_into(&mut s);
        self.finalized.write_into(&mut s);
        s.extend_from_slice(&(leaked.len() as u64).to_le_bytes());
        for l in &leaked {
            s.extend_from_slice(&l.validator.to_le_bytes());
            s.extend_from_slice(&l.leaked_sat.to_le_bytes());
        }
        s.extend_from_slice(&self.next_epoch.to_le_bytes());
        s
    }
}

/// One epoch-boundary vote awaiting the finality tally, committed per entry
/// under [`TAG_PENDING_VOTE`]. Keyed by `(validator, signing_root)` — exactly
/// the transition's accumulation key, so the committed set is the set, not
/// the arrival order. The signing root is computed by the attestation module
/// and passed in opaque; this module never re-derives it (one derivation
/// path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingVoteRecord {
    pub validator: u32,
    pub signing_root: [u8; 32],
    pub slot: u64,
    pub head: [u8; 32],
    pub source_epoch: u64,
    pub source_root: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
}

impl PendingVoteRecord {
    fn entry_key(&self) -> Vec<u8> {
        let mut k = Vec::with_capacity(36);
        k.extend_from_slice(&self.validator.to_le_bytes());
        k.extend_from_slice(&self.signing_root);
        k
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(156);
        s.extend_from_slice(&self.validator.to_le_bytes());
        s.extend_from_slice(&self.signing_root);
        s.extend_from_slice(&self.slot.to_le_bytes());
        s.extend_from_slice(&self.head);
        s.extend_from_slice(&self.source_epoch.to_le_bytes());
        s.extend_from_slice(&self.source_root);
        s.extend_from_slice(&self.target_epoch.to_le_bytes());
        s.extend_from_slice(&self.target_root);
        s
    }
}

/// One validator's LMD-GHOST latest message, committed per entry under
/// [`TAG_FC_MESSAGE`]. Fork choice does not validate blocks, but the message
/// map lives in the committed state and feeds every weight computation; left
/// uncommitted it would be a per-node opinion two roots could silently
/// disagree on, and a state-synced node could not rebuild it at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FcMessageRecord {
    pub validator: u32,
    pub slot: u64,
    pub root: [u8; 32],
}

impl FcMessageRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.validator.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(44);
        s.extend_from_slice(&self.validator.to_le_bytes());
        s.extend_from_slice(&self.slot.to_le_bytes());
        s.extend_from_slice(&self.root);
        s
    }
}

/// One validator barred from fork-choice weight for equivocating, committed
/// per entry under [`TAG_FC_EQUIVOCATOR`]. A separate component from the
/// messages (not a marker byte on them) because the two sets are disjoint by
/// invariant, and if that invariant ever broke the root should commit the
/// contradiction rather than let last-write-wins hide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FcEquivocatorRecord {
    pub validator: u32,
}

impl FcEquivocatorRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.validator.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        self.validator.to_le_bytes().to_vec()
    }
}

/// One deposit in the permanent activation queue, committed per entry under
/// [`TAG_DEPOSIT_QUEUE`]. Keyed by pubkey hash — unique by the
/// one-deposit-per-key rule — so the committed queue is order-free; the
/// activation fold sorts by (epoch, pubkey hash) itself and never by
/// position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositQueueRecord {
    pub pubkey_hash: [u8; 32],
    pub deposit_epoch: u64,
    pub amount_sat: u128,
}

impl DepositQueueRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.pubkey_hash.to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(56);
        s.extend_from_slice(&self.pubkey_hash);
        s.extend_from_slice(&self.deposit_epoch.to_le_bytes());
        s.extend_from_slice(&self.amount_sat.to_le_bytes());
        s
    }
}

/// One delegation in the permanent history, committed per entry under
/// [`TAG_DELEGATION`]. Keyed by **position** in the history, unlike the
/// deposit queue: two byte-identical delegations (same delegator, validator,
/// amount, epoch) are two bonds, so content cannot key them — and position
/// is chain order, fixed by the blocks that carried the entries, not by any
/// node's arrival order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegationRecord {
    /// Position in the committed history (append order across the chain).
    pub position: u64,
    pub delegator: u32,
    pub validator: u32,
    pub amount_sat: u128,
    pub requested_epoch: u64,
    /// Epoch deactivation was requested, if any. Encoded 0x00, or 0x01 ‖
    /// epoch — so `None` and `Some(0)` cannot collide.
    pub deactivate_epoch: Option<u64>,
    /// False when the §4.1 taint oracle refused the coins: the record is
    /// committed precisely so the refusal is an auditable consensus fact.
    pub eligible: bool,
}

impl DelegationRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.position.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(60);
        s.extend_from_slice(&self.position.to_le_bytes());
        s.extend_from_slice(&self.delegator.to_le_bytes());
        s.extend_from_slice(&self.validator.to_le_bytes());
        s.extend_from_slice(&self.amount_sat.to_le_bytes());
        s.extend_from_slice(&self.requested_epoch.to_le_bytes());
        match self.deactivate_epoch {
            None => s.push(0x00),
            Some(e) => {
                s.push(0x01);
                s.extend_from_slice(&e.to_le_bytes());
            }
        }
        s.push(self.eligible as u8);
        s
    }
}

/// Fee rewards accrued to one proposer during the open epoch, waiting to
/// compound at the boundary; committed per entry under [`TAG_PENDING_FEE`].
/// Uncommitted, a boundary would pay validators amounts no root ever agreed
/// on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingFeeRecord {
    pub validator: u32,
    pub amount_sat: u128,
}

impl PendingFeeRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.validator.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(20);
        s.extend_from_slice(&self.validator.to_le_bytes());
        s.extend_from_slice(&self.amount_sat.to_le_bytes());
        s
    }
}

/// The committed output of the L1 EVM execution layer for one block
/// (`docs/specs/BLOCH-L1-EVM-STATE-MODEL.md` §2–§3).
///
/// **Carried, never recomputed here** — the same rule as the Coherence roots:
/// this crate cannot run the EVM (transactions are opaque bytes to it, §1.2 of
/// the migration design), so the execution layer computes these values and the
/// transition carries them into the committed state. The two roots are
/// keccak-256 Merkle-Patricia roots, not SHA3-SMT roots, on purpose: keccak is
/// what every EVM proof consumer (`eth_getProof`, MPT light clients) speaks,
/// keccak-256 is a hash (Grover-only quantum exposure, same margin as the rest
/// of the SHA-3 family), and re-rooting an incrementally-maintained foreign
/// structure inside this tree is exactly what the Coherence precedent rejects.
///
/// `gas_used` and `base_fee_per_gas` are committed for the §5.5 reason: the
/// next block's base fee is *derived from* the parent's committed pair. A base
/// fee read from node-local execution bookkeeping instead of committed state
/// would be `expected_bits` all over again — an uncommitted retarget input,
/// the exact shape of the 2026-08-08 consensus split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmCommitment {
    /// keccak-256 MPT root of the EVM account trie (address → nonce, balance,
    /// code hash, storage root) after executing this block's EVM segment.
    pub account_root: [u8; 32],
    /// keccak-256 MPT root over this block's EVM receipts.
    pub receipts_root: [u8; 32],
    /// EVM gas consumed by this block's EVM segment.
    pub gas_used: u64,
    /// Base fee, in satoshi per gas, that this block's EVM transactions were
    /// charged. Input to the next block's base-fee derivation.
    pub base_fee_per_gas: u64,
}

impl EvmCommitment {
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(80);
        s.extend_from_slice(&self.account_root);
        s.extend_from_slice(&self.receipts_root);
        s.extend_from_slice(&self.gas_used.to_le_bytes());
        s.extend_from_slice(&self.base_fee_per_gas.to_le_bytes());
        s
    }
}

/// One spent piece of slashing evidence, committed so the same pair can never
/// be applied twice ([`TAG_SLASH_APPLIED`]).
///
/// The id is the whole record: the component is a set, and set membership is
/// the only fact it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedEvidenceRecord {
    pub id: [u8; 32],
}

impl AppliedEvidenceRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.id.to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        self.id.to_vec()
    }
}

/// Stake slashed in one epoch, inside the correlation window
/// ([`TAG_SLASH_WINDOW`]). Uncommitted, two nodes would price the *next*
/// correlated offence differently and disagree on the resulting bond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashWindowRecord {
    pub epoch: u64,
    pub slashed_sat: u128,
}

impl SlashWindowRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.epoch.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(24);
        s.extend_from_slice(&self.epoch.to_le_bytes());
        s.extend_from_slice(&self.slashed_sat.to_le_bytes());
        s
    }
}

/// Cumulative slashing loss charged to one delegator account
/// ([`TAG_DELEGATOR_SLASH_LOSS`]).
///
/// A separate ledger rather than an edit to the delegation records, because
/// the delegation registry replays its warm-up history from those records and
/// editing an amount would retroactively reshuffle every later admission under
/// the shared churn budget. Committed because a withdrawal nets it out: a node
/// that disagreed on the loss would pay a different amount for the same exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatorLossRecord {
    pub delegator: u32,
    pub loss_sat: u128,
}

impl DelegatorLossRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.delegator.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(20);
        s.extend_from_slice(&self.delegator.to_le_bytes());
        s.extend_from_slice(&self.loss_sat.to_le_bytes());
        s
    }
}

/// The committed L1 fee-market state ([`TAG_BASE_FEE`]): the base fee this
/// block's transactions were charged, in millisatoshi per gas
/// (`fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS` at genesis), and the block's
/// own usage on the two controller axes. The **next** block's price is
/// `fee_market::next_base_fee(base_fee_millisat_per_gas, BlockUsage {
/// gas_used, tx_bytes })` — derived from this leaf and from nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseFeeRecord {
    /// Price charged in this block, millisatoshi per gas.
    pub base_fee_millisat_per_gas: u128,
    /// Gas consumed by this block's transactions (≤ `BLOCK_GAS_LIMIT`).
    pub gas_used: u64,
    /// Transaction payload bytes of this block (≤ `MAX_BLOCK_TX_BYTES`).
    pub tx_bytes: u64,
}

impl BaseFeeRecord {
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(32);
        s.extend_from_slice(&self.base_fee_millisat_per_gas.to_le_bytes());
        s.extend_from_slice(&self.gas_used.to_le_bytes());
        s.extend_from_slice(&self.tx_bytes.to_le_bytes());
        s
    }
}

/// Cumulative fee rewards settled to one delegator account
/// ([`TAG_DELEGATOR_FEE_REWARD`]) — the earning mirror of
/// [`DelegatorLossRecord`], for the same reason: the delegation registry
/// replays its history from the committed delegation records, so crediting a
/// record's amount would retroactively reshuffle every later admission. The
/// reward is committed here instead, and the withdrawal surface pays it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatorFeeRecord {
    pub delegator: u32,
    pub reward_sat: u128,
}

impl DelegatorFeeRecord {
    fn entry_key(&self) -> Vec<u8> {
        self.delegator.to_le_bytes().to_vec()
    }
    fn serialize(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(20);
        s.extend_from_slice(&self.delegator.to_le_bytes());
        s.extend_from_slice(&self.reward_sat.to_le_bytes());
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
    /// Justification/finality bookkeeping (single leaf).
    pub finality: &'a FinalityRecord,
    /// Epoch-boundary votes pending the next finality tally.
    pub pending_votes: &'a [PendingVoteRecord],
    /// LMD-GHOST latest message per validator.
    pub fc_messages: &'a [FcMessageRecord],
    /// Validators barred from fork-choice weight.
    pub fc_equivocators: &'a [FcEquivocatorRecord],
    /// The permanent deposit/activation queue.
    pub deposit_queue: &'a [DepositQueueRecord],
    /// The permanent delegation history, positionally keyed.
    pub delegations: &'a [DelegationRecord],
    /// Fee rewards pending the epoch boundary.
    pub pending_fees: &'a [PendingFeeRecord],
    /// Root of the taint set (§4.1), maintained by its own module.
    pub taint_root: [u8; 32],
    /// Coherence shielded pool: SHAKE-256 accumulator root (§6.6.2).
    pub coherence_accumulator_root: [u8; 32],
    /// Coherence shielded pool: nullifier-set root (§6.6.2).
    pub coherence_nullifier_root: [u8; 32],
    /// L1 EVM execution commitment, carried from the execution layer
    /// (`BLOCH-L1-EVM-STATE-MODEL.md`).
    pub evm: EvmCommitment,
    /// Cumulative issued supply, in satoshis ([`TAG_ISSUED_SUPPLY`]). Gross
    /// and monotone: burns (base-fee burn, slashing residue, inactivity leak)
    /// never decrement it — they only widen the gap below the cap, and the
    /// cap invariant is one-sided.
    pub issued_sat: u128,
    /// Spent slashing evidence — the anti-replay set (§7.3).
    pub applied_evidence: &'a [AppliedEvidenceRecord],
    /// Per-epoch slashed stake inside the correlation window (§7.3).
    pub slash_window: &'a [SlashWindowRecord],
    /// Cumulative slashing losses per delegator account (§7.3).
    pub delegator_slash_losses: &'a [DelegatorLossRecord],
    /// The L1 fee-market price and this block's usage ([`TAG_BASE_FEE`]).
    pub base_fee: BaseFeeRecord,
    /// Cumulative fee rewards per delegator account
    /// ([`TAG_DELEGATOR_FEE_REWARD`]).
    pub delegator_fee_rewards: &'a [DelegatorFeeRecord],
}

/// How many **closed** epoch boundaries the committed beacon history retains,
/// on top of the running mix for the open epoch (§5.5).
///
/// Two, because `seed_for_epoch(E)` reads the boundary closed at `E-1` and the
/// look-ahead needs the one before it; anything shorter makes a committee
/// underivable from committed state, which is the §5.5 failure by another road.
pub const RANDAO_BOUNDARIES_RETAINED: u64 = 2;

/// **The** definition of which RANDAO mixes the state root commits.
///
/// It is a function because it used to be two rules. `transition` committed the
/// retained boundaries *plus* the running mix (three entries from epoch 2 on);
/// `derive` committed `{epoch-1, epoch}` (two). Same block, same parent, two
/// different leaf sets, therefore two different state roots — the crate's
/// founding rule ("one derivation path") is enforced for block identity by
/// `header::single_derivation_path` and was, until now, not enforced at all for
/// the state root. Found independently by two agents on 2026-08-12, from
/// opposite ends: one auditing which fields were committed, one running a real
/// devnet and finding `produce.rs` unusable by the node.
///
/// `transition`'s rule won: it retains strictly more, it is the one the node
/// runs, and committing the running mix is what binds each block's RANDAO
/// reveal into the root its header pins.
///
/// `history` is the closed boundaries in any order; `(epoch, running)` is the
/// open epoch's accumulating mix. Output is sorted by epoch with one entry per
/// epoch — a `history` that already carries `epoch` is overridden by `running`,
/// because the open epoch's live value is the one that was revealed to.
///
/// Pinned by `tests/one_state_root.rs`.
pub fn randao_window(history: &[RandaoMix], epoch: u64, running: [u8; 32]) -> Vec<RandaoMix> {
    let keep_from = epoch.saturating_sub(RANDAO_BOUNDARIES_RETAINED);
    let mut by_epoch: std::collections::BTreeMap<u64, [u8; 32]> = history
        .iter()
        .filter(|m| m.epoch >= keep_from && m.epoch < epoch)
        .map(|m| (m.epoch, m.mix))
        .collect();
    by_epoch.insert(epoch, running);
    by_epoch.into_iter().map(|(epoch, mix)| RandaoMix { epoch, mix }).collect()
}

fn derive_key(component_tag: u8, entry_key: &[u8]) -> [u8; 32] {
    sha3(&[&[MARK_KEY], &[component_tag], entry_key])
}

fn hash_value(serialized: &[u8]) -> [u8; 32] {
    sha3(&[&[MARK_VALUE], serialized])
}

/// The Merkle leaf one eUTXO contributes: its tree key, and the hash of its
/// serialization.
///
/// The **single definition** of that pair. A caller that keeps eUTXO leaves
/// incrementally (see `CommittedState`'s eUTXO set) and this module computing
/// them from scratch must produce identical bytes or the two would commit
/// different roots for the same state — so neither is allowed its own copy of
/// this expression.
pub fn eutxo_leaf(e: &EutxoEntry) -> ([u8; 32], [u8; 32]) {
    (derive_key(TAG_EUTXO, &e.entry_key()), hash_value(&e.serialize()))
}

/// Build the full state SMT from a [`ConsensusState`].
///
/// Exposed (rather than only [`state_root`]) so callers can generate
/// inclusion proofs against the same tree the root came from.
pub fn build_state_tree(state: &ConsensusState<'_>) -> Smt {
    let leaves: BTreeMap<[u8; 32], [u8; 32]> = state.eutxos.iter().map(eutxo_leaf).collect();
    build_state_tree_inner(state, &leaves)
}

/// [`build_state_tree`] with the eUTXO leaves handed in already computed.
///
/// Why this exists: `build_state_tree` re-serializes and re-hashes **every**
/// eUTXO on every call, and a block calls it at least once. At Genesis-4's
/// carryover size that is 452,726 entries — around 900,000 SHA3 hashes plus a
/// full `BTreeMap` rebuild, per block. A `perf` profile of a replaying
/// validator on 2026-08-21 put 50.7% of its CPU in the keccak permutation and
/// another 9.2% in `Smt::insert`, for a state where all but a handful of those
/// entries were byte-for-byte identical to the previous block.
///
/// The leaves a caller passes here must come from [`eutxo_leaf`] — that is why
/// it is public. This function is not a cache and holds no state: it recomputes
/// the tree, and therefore the root, from whatever leaves it is given, every
/// time. The §5.5 rule ("no cached root may outlive the leaves it was computed
/// from") is untouched; what is cached upstream is the *leaves*, each of which
/// is a pure function of one entry.
///
/// `state.eutxos` is IGNORED here — `eutxo_leaves` replaces it. Pass an empty
/// slice so a reader cannot mistake one for the other.
pub fn build_state_tree_with_eutxo_leaves(
    state: &ConsensusState<'_>,
    eutxo_leaves: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Smt {
    build_state_tree_inner(state, eutxo_leaves)
}

/// [`build_state_tree`] and [`build_state_tree_with_eutxo_leaves`] are the same
/// tree; only where the eUTXO leaves come from differs. Written once so the two
/// entry points cannot drift into committing different shapes.
fn build_state_tree_inner(
    state: &ConsensusState<'_>,
    eutxo_leaves: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Smt {
    let mut smt = Smt::new();
    for (key, value_hash) in eutxo_leaves {
        smt.insert(*key, *value_hash);
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
    // The finality bookkeeping is one leaf (see FinalityRecord docs).
    smt.insert(derive_key(TAG_FINALITY, &[]), hash_value(&state.finality.serialize()));
    for v in state.pending_votes {
        smt.insert(derive_key(TAG_PENDING_VOTE, &v.entry_key()), hash_value(&v.serialize()));
    }
    for m in state.fc_messages {
        smt.insert(derive_key(TAG_FC_MESSAGE, &m.entry_key()), hash_value(&m.serialize()));
    }
    for e in state.fc_equivocators {
        smt.insert(derive_key(TAG_FC_EQUIVOCATOR, &e.entry_key()), hash_value(&e.serialize()));
    }
    for d in state.deposit_queue {
        smt.insert(derive_key(TAG_DEPOSIT_QUEUE, &d.entry_key()), hash_value(&d.serialize()));
    }
    for d in state.delegations {
        smt.insert(derive_key(TAG_DELEGATION, &d.entry_key()), hash_value(&d.serialize()));
    }
    for f in state.pending_fees {
        smt.insert(derive_key(TAG_PENDING_FEE, &f.entry_key()), hash_value(&f.serialize()));
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
    // The EVM commitment is the fourth carried foreign component — a single
    // structured leaf, not per-account leaves. Expanding accounts here would
    // commit the same state twice (once in the keccak MPT, once in this SMT)
    // and make every EVM write cost a 256-level SHA3 path on top of its MPT
    // path; the spec (§2) opens the closed list by exactly one leaf and no
    // more.
    smt.insert(derive_key(TAG_EVM_COMMITMENT, &[]), hash_value(&state.evm.serialize()));
    // The issued-supply counter (2026-08-12): a fifth singleton, fixed-width
    // 16-byte LE — the value the hard-cap invariant is checked against.
    smt.insert(
        derive_key(TAG_ISSUED_SUPPLY, &[]),
        hash_value(&state.issued_sat.to_le_bytes()),
    );
    for e in state.applied_evidence {
        smt.insert(derive_key(TAG_SLASH_APPLIED, &e.entry_key()), hash_value(&e.serialize()));
    }
    for w in state.slash_window {
        smt.insert(derive_key(TAG_SLASH_WINDOW, &w.entry_key()), hash_value(&w.serialize()));
    }
    for d in state.delegator_slash_losses {
        smt.insert(
            derive_key(TAG_DELEGATOR_SLASH_LOSS, &d.entry_key()),
            hash_value(&d.serialize()),
        );
    }
    // The fee-market leaf (2026-08-12): the price the next block derives its
    // own from. A sixth singleton, fixed-width serialization.
    smt.insert(derive_key(TAG_BASE_FEE, &[]), hash_value(&state.base_fee.serialize()));
    for d in state.delegator_fee_rewards {
        smt.insert(
            derive_key(TAG_DELEGATOR_FEE_REWARD, &d.entry_key()),
            hash_value(&d.serialize()),
        );
    }
    smt
}

/// The state root committed in `BlockHeaderV4.state_root` (§5.3, §5.5) — a
/// pure function of the passed-in state.
pub fn state_root(state: &ConsensusState<'_>) -> [u8; 32] {
    build_state_tree(state).root()
}

/// [`state_root`] over a state whose eUTXO leaves the caller already holds.
///
/// Same root, same rules; see [`build_state_tree_with_eutxo_leaves`] for why
/// the leaves are worth keeping and why keeping them is not a cached root.
pub fn state_root_with_eutxo_leaves(
    state: &ConsensusState<'_>,
    eutxo_leaves: &BTreeMap<[u8; 32], [u8; 32]>,
) -> [u8; 32] {
    build_state_tree_with_eutxo_leaves(state, eutxo_leaves).root()
}

/// Sum of all committed eUTXO values, in u128.
///
/// Why u128: one output fits u64 (100e9 BLCH × 1e8 sat = 10^19, 54% of
/// `u64::MAX` — it fits, with 1.84x headroom and no more), but a *sum* of even
/// two large outputs does not — and a silent wrap here is not
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

    /// Reference walk: recurses one level at a time all the way to
    /// `TREE_DEPTH`, with no shortcut and no memo. This is what
    /// `subtree_root` did before the singleton fold was hoisted out, and it
    /// is the definition the root must keep matching.
    fn reference_subtree_root(
        leaves: &[([u8; 32], [u8; 32])],
        depth: usize,
        empty: &[[u8; 32]],
    ) -> [u8; 32] {
        if leaves.is_empty() {
            return empty[depth];
        }
        if depth == TREE_DEPTH {
            let (key, value_hash) = &leaves[0];
            return leaf_hash(key, value_hash);
        }
        let split = leaves.partition_point(|(k, _)| bit(k, depth) == 0);
        let left = reference_subtree_root(&leaves[..split], depth + 1, empty);
        let right = reference_subtree_root(&leaves[split..], depth + 1, empty);
        node_hash(&left, &right)
    }

    /// Not an assertion about wall-clock, which varies by machine — it
    /// prints, and exists so the carryover-scale cost is measurable in the
    /// tree that ships. Run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn carryover_scale_root_cost() {
        let n = 452_726u32;
        let mut smt = Smt::new();
        for i in 0..n {
            smt.insert(derive_key(TAG_EUTXO, &i.to_le_bytes()), hash_value(&i.to_le_bytes()));
        }
        let t0 = std::time::Instant::now();
        let a = smt.root();
        let cold = t0.elapsed();
        let t1 = std::time::Instant::now();
        let b = smt.root();
        let warm = t1.elapsed();
        assert_eq!(a, b);
        println!("  folhas: {n}");
        println!("  1a raiz (memo frio) : {cold:.2?}");
        println!("  2a raiz (memo quente): {warm:.2?}");
    }

    #[test]
    fn memoized_singleton_fold_matches_the_full_recursion() {
        // Keys are spread by the real derivation, so leaves become singletons
        // at realistic (shallow, uneven) depths — the case the shortcut is
        // for. Several sizes, because the singleton depth depends on how many
        // neighbours share a prefix.
        for n in [1u32, 2, 3, 17, 64, 500] {
            let mut smt = Smt::new();
            let mut leaves: Vec<([u8; 32], [u8; 32])> = Vec::new();
            for i in 0..n {
                let k = derive_key(TAG_EUTXO, &i.to_le_bytes());
                let v = hash_value(&i.to_le_bytes());
                smt.insert(k, v);
                leaves.push((k, v));
            }
            leaves.sort_by(|a, b| a.0.cmp(&b.0));
            let want = reference_subtree_root(&leaves, 0, &empty_hashes());
            assert_eq!(smt.root(), want, "memoized root diverged from the full recursion at n={n}");
        }
    }

    #[test]
    fn memo_survives_a_value_change_at_the_same_key() {
        // The memo is keyed by the whole input, so re-inserting a different
        // value under a key already cached must move the root. This is the
        // failure a root cache would have: same key, stale answer.
        let k = derive_key(TAG_EUTXO, b"k");
        let mut smt = Smt::new();
        smt.insert(k, hash_value(b"before"));
        let before = smt.root();
        smt.insert(k, hash_value(b"after"));
        let after = smt.root();
        assert_ne!(before, after, "a changed leaf value must change the root");
        smt.insert(k, hash_value(b"before"));
        assert_eq!(smt.root(), before, "restoring the value must restore the root");
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

    /// Owned backing storage for a [`ConsensusState`] fixture — every
    /// component non-empty, so a dropped `build_state_tree` loop would fail
    /// the load-bearing test rather than commit an empty component silently.
    #[derive(Clone)]
    struct Fx {
        eutxos: Vec<EutxoEntry>,
        validators: Vec<ValidatorRecord>,
        current: Vec<ParticipationRecord>,
        previous: Vec<ParticipationRecord>,
        randao: Vec<RandaoMix>,
        finality: FinalityRecord,
        pending_votes: Vec<PendingVoteRecord>,
        fc_messages: Vec<FcMessageRecord>,
        fc_equivocators: Vec<FcEquivocatorRecord>,
        deposit_queue: Vec<DepositQueueRecord>,
        delegations: Vec<DelegationRecord>,
        pending_fees: Vec<PendingFeeRecord>,
        evm: EvmCommitment,
        applied: Vec<AppliedEvidenceRecord>,
        window: Vec<SlashWindowRecord>,
        losses: Vec<DelegatorLossRecord>,
        base_fee: BaseFeeRecord,
        fee_rewards: Vec<DelegatorFeeRecord>,
    }

    fn fixture() -> Fx {
        // Distinct non-zero values in all four EVM fields on purpose: with
        // zeros, a serialization that aliased two of them would still produce
        // equal roots and the aliasing test below would pass vacuously.
        // Slashing bookkeeping, non-empty: a component whose fixture is empty
        // is a component the coverage test cannot distinguish from an absent
        // one. `validator: 1` deliberately collides with a registry key and an
        // fc-message key — the component tag is what keeps the three apart.
        let applied = vec![
            AppliedEvidenceRecord { id: key(0xA1) },
            AppliedEvidenceRecord { id: key(0xA2) },
        ];
        let window = vec![
            SlashWindowRecord { epoch: 7, slashed_sat: 5_000_000_000 },
            SlashWindowRecord { epoch: 8, slashed_sat: 1 },
        ];
        let losses = vec![
            DelegatorLossRecord { delegator: 1, loss_sat: 42 },
            DelegatorLossRecord { delegator: 9, loss_sat: 1_000 },
        ];
        let evm = EvmCommitment {
            account_root: key(0xE0),
            receipts_root: key(0xE1),
            gas_used: 21_000,
            base_fee_per_gas: 7,
        };
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
                randao_commitment: val(0x40 + i),
                reveals_used: i as u32,
                withdrawable_epoch: u64::MAX,
                withdrawal_credentials: vec![0xC0 + i; 20],
                commission_bps: 500 * i as u128,
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
        let finality = FinalityRecord {
            justified: vec![
                CheckpointRecord { epoch: 40, root: val(0x50) },
                CheckpointRecord { epoch: 42, root: val(0x52) },
            ],
            current_justified: CheckpointRecord { epoch: 42, root: val(0x52) },
            previous_justified: CheckpointRecord { epoch: 40, root: val(0x50) },
            finalized: CheckpointRecord { epoch: 40, root: val(0x50) },
            leaked: vec![LeakRecord { validator: 3, leaked_sat: 77 }],
            next_epoch: 43,
        };
        let pending_votes: Vec<PendingVoteRecord> = (0..3u32)
            .map(|i| PendingVoteRecord {
                validator: i,
                signing_root: val(0x60 + i as u8),
                slot: 43 * 32 + i as u64,
                head: val(0x70 + i as u8),
                source_epoch: 42,
                source_root: val(0x52),
                target_epoch: 43,
                target_root: val(0x71),
            })
            .collect();
        let fc_messages = vec![
            FcMessageRecord { validator: 0, slot: 1370, root: val(0x70) },
            FcMessageRecord { validator: 1, slot: 1371, root: val(0x71) },
        ];
        let fc_equivocators = vec![FcEquivocatorRecord { validator: 2 }];
        let deposit_queue = vec![DepositQueueRecord {
            pubkey_hash: val(0x80),
            deposit_epoch: 41,
            amount_sat: 200_000 * 100_000_000,
        }];
        let delegations = vec![
            DelegationRecord {
                position: 0,
                delegator: 900,
                validator: 1,
                amount_sat: 1_000 * 100_000_000,
                requested_epoch: 42,
                deactivate_epoch: None,
                eligible: true,
            },
            DelegationRecord {
                position: 1,
                delegator: 900,
                validator: 1,
                amount_sat: 1_000 * 100_000_000,
                requested_epoch: 42,
                deactivate_epoch: Some(50),
                eligible: false,
            },
        ];
        let pending_fees = vec![PendingFeeRecord { validator: 1, amount_sat: 1_234 }];
        // Fee-market leaf: three distinct non-zero values so an aliasing or
        // dropped field cannot hide behind zeros (the EVM-fixture argument).
        let base_fee = BaseFeeRecord {
            base_fee_millisat_per_gas: 12,
            gas_used: 3_000_000,
            tx_bytes: 65_536,
        };
        // Delegator 1 deliberately collides with a slash-loss key: the
        // component tag is what keeps earning and losing apart.
        let fee_rewards = vec![
            DelegatorFeeRecord { delegator: 1, reward_sat: 55 },
            DelegatorFeeRecord { delegator: 900, reward_sat: 4_321 },
        ];
        Fx {
            eutxos,
            validators,
            current,
            previous,
            randao,
            finality,
            pending_votes,
            fc_messages,
            fc_equivocators,
            deposit_queue,
            delegations,
            pending_fees,
            evm,
            applied,
            window,
            losses,
            base_fee,
            fee_rewards,
        }
    }

    /// Supplying the eUTXO leaves must commit exactly the root that computing
    /// them from the entries commits. If these two ever disagree, a node on one
    /// path and a node on the other split the chain — which is the whole risk
    /// this optimisation takes on, so it is the thing to pin.
    #[test]
    fn supplied_eutxo_leaves_commit_the_same_root() {
        let f = fixture();
        assert!(!f.eutxos.is_empty(), "control: a fixture with no outputs would prove nothing");

        let from_entries = state_root(&state(&f));
        let leaves: BTreeMap<[u8; 32], [u8; 32]> = f.eutxos.iter().map(eutxo_leaf).collect();
        let mut view = state(&f);
        view.eutxos = &[];
        let from_leaves = state_root_with_eutxo_leaves(&view, &leaves);

        assert_eq!(
            from_entries, from_leaves,
            "the same eUTXO set committed two different roots depending on the path"
        );

        // Control: the balances genuinely reach the root, so the equality above
        // is not two paths agreeing on a state they both ignored — the bug this
        // component actually shipped with once.
        let empty: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
        assert_ne!(
            from_entries,
            state_root_with_eutxo_leaves(&view, &empty),
            "dropping every output left the root unchanged: the eUTXO component is not committed"
        );
    }

    /// What the two paths cost at Genesis-4's real carryover size.
    ///
    /// `#[ignore]` because it allocates a 452,726-entry set and is a
    /// measurement, not an assertion. Run it deliberately:
    ///
    /// ```text
    /// cargo test -p bloch-pos-committee --release supplied_leaves_cost -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn supplied_leaves_cost_at_carryover_scale() {
        const N: u32 = 452_726;
        let f = fixture();
        let eutxos: Vec<EutxoEntry> = (0..N)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[..4].copy_from_slice(&i.to_le_bytes());
                EutxoEntry { txid, vout: 0, value: 1_000 + i as u64, script_hash: [7u8; 32] }
            })
            .collect();

        let mut view = state(&f);
        let leaves: BTreeMap<[u8; 32], [u8; 32]> = eutxos.iter().map(eutxo_leaf).collect();

        // Warm BOTH paths before timing either. The singleton memo is
        // thread-local and persists across calls, so a cold first run and a
        // warm second one is not a comparison of the two paths — it is a
        // comparison of a cold cache with a warm one, which would flatter this
        // patch by a wide margin. In production the memo is warm for both.
        view.eutxos = &eutxos;
        let a = state_root(&view);
        view.eutxos = &[];
        let b = state_root_with_eutxo_leaves(&view, &leaves);

        view.eutxos = &eutxos;
        let t0 = std::time::Instant::now();
        let a2 = state_root(&view);
        let from_entries = t0.elapsed();

        view.eutxos = &[];
        let t1 = std::time::Instant::now();
        let b2 = state_root_with_eutxo_leaves(&view, &leaves);
        let from_leaves = t1.elapsed();
        assert_eq!(a, a2);
        assert_eq!(b, b2);

        // Third measurement: what a state root costs immediately AFTER the memo
        // rotates. Under the old wholesale `clear()` this was the cold cost —
        // the 51s cliff. With rotation the live set is still in the demoted
        // generation and is promoted back on first read, so it should land
        // near the warm number, not the cold one.
        for i in 0..(SINGLETON_MEMO_GENERATION as u64) {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_le_bytes());
            k[9] = 0xFF; // junk namespace, cannot collide with a real leaf
            memo_put((k, k, 0), k);
        }
        let t2 = std::time::Instant::now();
        let c = state_root_with_eutxo_leaves(&view, &leaves);
        let after_rotation = t2.elapsed();
        assert_eq!(b, c);

        assert_eq!(a, b, "the measurement is only meaningful if both paths agree");
        println!("  entries ({N} eUTXOs): {from_entries:?}");
        println!("  kept leaves:          {from_leaves:?}");
        println!("  kept leaves, just after a memo rotation: {after_rotation:?}");
        println!(
            "  saved per state root: {:.1}%",
            100.0 * (1.0 - from_leaves.as_secs_f64() / from_entries.as_secs_f64())
        );
    }

    /// Filling the memo must demote the previous generation, not delete it.
    ///
    /// The old code called `clear()`, so an entry written just before the
    /// limit was gone the moment the limit was reached. That is what turned a
    /// 1.2s state root into a 51s one at an unpredictable moment. Here the
    /// entry survives, and reading it moves it back into the live generation.
    #[test]
    fn the_memo_rotates_instead_of_clearing() {
        let key = |i: u64| {
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&i.to_le_bytes());
            (a, a, 0usize)
        };
        let val = |i: u64| {
            let mut a = [0u8; 32];
            a[0] = 0xA5;
            a[1..9].copy_from_slice(&i.to_le_bytes());
            a
        };

        let early = key(0);
        memo_put(early, val(0));
        assert_eq!(memo_get(&early), Some(val(0)), "control: it was not even stored");

        // Push past one generation, which must rotate exactly once.
        for i in 1..=(SINGLETON_MEMO_GENERATION as u64) {
            memo_put(key(i), val(i));
        }

        let (hot, cold) = memo_generation_sizes();
        assert!(hot < SINGLETON_MEMO_GENERATION, "the live generation did not rotate");
        assert!(cold >= SINGLETON_MEMO_GENERATION - 1, "the demoted generation was dropped");
        assert!(
            hot + cold <= 2 * SINGLETON_MEMO_GENERATION,
            "two generations must stay inside the memory bound"
        );

        // The point of the change: an entry written before the rotation is
        // still a hit. Under `clear()` this returned None.
        assert_eq!(
            memo_get(&early),
            Some(val(0)),
            "rotation dropped an entry that was still in use"
        );

        // And reading it promoted it back, so the next rotation cannot drop it.
        let (hot_after, _) = memo_generation_sizes();
        assert_eq!(hot_after, hot + 1, "a hit on the demoted generation must promote");

        // Control: a key never written is still a miss, so the assertions above
        // are not passing because the memo returns something for anything.
        assert_eq!(memo_get(&key(u64::MAX)), None, "control: unknown key must miss");
    }

    fn state(f: &Fx) -> ConsensusState<'_> {
        ConsensusState {
            eutxos: &f.eutxos,
            validators: &f.validators,
            current_participation: &f.current,
            previous_participation: &f.previous,
            randao_mixes: &f.randao,
            finality: &f.finality,
            pending_votes: &f.pending_votes,
            fc_messages: &f.fc_messages,
            fc_equivocators: &f.fc_equivocators,
            deposit_queue: &f.deposit_queue,
            delegations: &f.delegations,
            pending_fees: &f.pending_fees,
            taint_root: val(101),
            coherence_accumulator_root: val(102),
            coherence_nullifier_root: val(103),
            evm: f.evm,
            // Non-zero and asymmetric on purpose, like the EVM fields: a
            // serialization that dropped or aliased the counter must move the
            // root in the coverage test below.
            issued_sat: crate::tokenomics_v4::GENESIS_ISSUED_SAT + 12_345,
            applied_evidence: &f.applied,
            slash_window: &f.window,
            delegator_slash_losses: &f.losses,
            base_fee: f.base_fee,
            delegator_fee_rewards: &f.fee_rewards,
        }
    }

    #[test]
    fn state_root_is_independent_of_component_iteration_order() {
        // Same state, reversed storage-iteration order — the in-memory-layout
        // variant of the 2026-08-08 failure. Must commit identically.
        let f = fixture();
        let root_a = state_root(&state(&f));

        let mut g = f.clone();
        g.eutxos.reverse();
        g.validators.reverse();
        g.current.reverse();
        g.previous.reverse();
        g.randao.reverse();
        // The single-leaf finality record canonicalises its internal lists.
        g.finality.justified.reverse();
        g.finality.leaked.reverse();
        g.pending_votes.reverse();
        g.fc_messages.reverse();
        g.fc_equivocators.reverse();
        g.deposit_queue.reverse();
        g.delegations.reverse();
        g.pending_fees.reverse();
        g.fee_rewards.reverse();
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

        mutated!(|g: &mut Fx| g.eutxos[3].value += 1);
        mutated!(|g: &mut Fx| g.eutxos[3].vout += 1);
        mutated!(|g: &mut Fx| g.eutxos[3].script_hash[0] ^= 1);
        mutated!(|g: &mut Fx| g.eutxos[3].txid[31] ^= 1);
        mutated!(|g: &mut Fx| g.eutxos.pop().map(|_| ()).unwrap()); // removal
        mutated!(|g: &mut Fx| g.validators[2].stake += 1);
        mutated!(|g: &mut Fx| g.validators[2].pubkey[0] ^= 1);
        mutated!(|g: &mut Fx| g.validators[2].activation_epoch += 1);
        mutated!(|g: &mut Fx| g.validators[2].exit_epoch = 999);
        mutated!(|g: &mut Fx| g.validators[2].slashed = true);
        mutated!(|g: &mut Fx| g.validators[2].randao_commitment[0] ^= 1);
        mutated!(|g: &mut Fx| g.validators[2].reveals_used += 1);
        mutated!(|g: &mut Fx| g.validators[2].withdrawable_epoch = 1_000);
        mutated!(|g: &mut Fx| g.validators[2].withdrawal_credentials[0] ^= 1);
        mutated!(|g: &mut Fx| g.current[1].attested = !g.current[1].attested);
        mutated!(|g: &mut Fx| g.previous[1].attested = !g.previous[1].attested);
        mutated!(|g: &mut Fx| g.randao[0].mix[5] ^= 1);
        mutated!(|g: &mut Fx| g.randao[0].epoch += 2);
        // Finality bookkeeping — every field of the single leaf.
        mutated!(|g: &mut Fx| g.finality.justified[0].epoch += 1);
        mutated!(|g: &mut Fx| g.finality.justified[0].root[0] ^= 1);
        mutated!(|g: &mut Fx| g.finality.justified.pop().map(|_| ()).unwrap());
        mutated!(|g: &mut Fx| g.finality.current_justified.root[0] ^= 1);
        mutated!(|g: &mut Fx| g.finality.previous_justified.epoch += 1);
        mutated!(|g: &mut Fx| g.finality.finalized.root[0] ^= 1);
        mutated!(|g: &mut Fx| g.finality.leaked[0].leaked_sat += 1);
        mutated!(|g: &mut Fx| g.finality.leaked[0].validator += 1);
        mutated!(|g: &mut Fx| g.finality.leaked.push(LeakRecord { validator: 9, leaked_sat: 1 }));
        mutated!(|g: &mut Fx| g.finality.next_epoch += 1);
        // Pending epoch-boundary votes.
        mutated!(|g: &mut Fx| g.pending_votes[1].validator += 10);
        mutated!(|g: &mut Fx| g.pending_votes[1].signing_root[0] ^= 1);
        mutated!(|g: &mut Fx| g.pending_votes[1].slot += 1);
        mutated!(|g: &mut Fx| g.pending_votes[1].head[0] ^= 1);
        mutated!(|g: &mut Fx| g.pending_votes[1].source_epoch += 1);
        mutated!(|g: &mut Fx| g.pending_votes[1].source_root[0] ^= 1);
        mutated!(|g: &mut Fx| g.pending_votes[1].target_epoch += 1);
        mutated!(|g: &mut Fx| g.pending_votes[1].target_root[0] ^= 1);
        mutated!(|g: &mut Fx| g.pending_votes.pop().map(|_| ()).unwrap());
        // Fork-choice bookkeeping.
        mutated!(|g: &mut Fx| g.fc_messages[0].slot += 1);
        mutated!(|g: &mut Fx| g.fc_messages[0].root[0] ^= 1);
        mutated!(|g: &mut Fx| g.fc_messages.pop().map(|_| ()).unwrap());
        mutated!(|g: &mut Fx| g.fc_equivocators[0].validator += 1);
        mutated!(|g: &mut Fx| g.fc_equivocators.pop().map(|_| ()).unwrap());
        // Staking queues.
        mutated!(|g: &mut Fx| g.deposit_queue[0].pubkey_hash[0] ^= 1);
        mutated!(|g: &mut Fx| g.deposit_queue[0].deposit_epoch += 1);
        mutated!(|g: &mut Fx| g.deposit_queue[0].amount_sat += 1);
        mutated!(|g: &mut Fx| g.deposit_queue.pop().map(|_| ()).unwrap());
        mutated!(|g: &mut Fx| g.delegations[0].position += 5);
        mutated!(|g: &mut Fx| g.delegations[0].delegator += 1);
        mutated!(|g: &mut Fx| g.delegations[0].validator += 1);
        mutated!(|g: &mut Fx| g.delegations[0].amount_sat += 1);
        mutated!(|g: &mut Fx| g.delegations[0].requested_epoch += 1);
        // Option encoding: None, Some(0) and Some(50) must all be distinct.
        mutated!(|g: &mut Fx| g.delegations[0].deactivate_epoch = Some(0));
        mutated!(|g: &mut Fx| g.delegations[1].deactivate_epoch = None);
        mutated!(|g: &mut Fx| g.delegations[1].deactivate_epoch = Some(51));
        mutated!(|g: &mut Fx| g.delegations[0].eligible = false);
        mutated!(|g: &mut Fx| g.delegations.pop().map(|_| ()).unwrap());
        // Pending fees.
        mutated!(|g: &mut Fx| g.pending_fees[0].validator += 1);
        mutated!(|g: &mut Fx| g.pending_fees[0].amount_sat += 1);
        mutated!(|g: &mut Fx| g.pending_fees.pop().map(|_| ()).unwrap());
        // Fee-market bookkeeping (2026-08-12): the price leaf every next
        // block's base fee is derived from, and the delegator earning ledger.
        mutated!(|g: &mut Fx| g.base_fee.base_fee_millisat_per_gas += 1);
        mutated!(|g: &mut Fx| g.base_fee.gas_used += 1);
        mutated!(|g: &mut Fx| g.base_fee.tx_bytes += 1);
        mutated!(|g: &mut Fx| g.fee_rewards[0].delegator += 1);
        mutated!(|g: &mut Fx| g.fee_rewards[0].reward_sat += 1);
        mutated!(|g: &mut Fx| g.fee_rewards.pop().map(|_| ()).unwrap());

        // Singleton roots and the issued-supply counter.
        for i in 0..4 {
            let f2 = f.clone();
            let mut s = state(&f2);
            match i {
                0 => s.taint_root[0] ^= 1,
                1 => s.coherence_accumulator_root[0] ^= 1,
                2 => s.coherence_nullifier_root[0] ^= 1,
                // One satoshi of issuance must move the root — this is the
                // leaf the hard-cap invariant reads, and an uncommitted or
                // truncated counter is the §5.5 failure for the cap itself.
                _ => s.issued_sat += 1,
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
        std::mem::swap(&mut g.current, &mut g.previous);
        // current (even indices attested) and previous (all attested) differ,
        // so swapping them must move the root.
        assert_ne!(state_root(&state(&g)), base);
    }

    #[test]
    fn evm_commitment_fields_do_not_alias() {
        // account_root/receipts_root are both 32 bytes and gas_used/
        // base_fee_per_gas are both u64, adjacent in the serialization — a
        // combine that were commutative or misaligned would let two different
        // execution outcomes commit identically.
        let f = fixture();
        let base = state_root(&state(&f));

        let mut swapped_roots = state(&f);
        std::mem::swap(
            &mut swapped_roots.evm.account_root,
            &mut swapped_roots.evm.receipts_root,
        );
        assert_ne!(state_root(&swapped_roots), base);

        let mut swapped_u64s = state(&f);
        std::mem::swap(
            &mut swapped_u64s.evm.gas_used,
            &mut swapped_u64s.evm.base_fee_per_gas,
        );
        assert_ne!(state_root(&swapped_u64s), base);
    }

    #[test]
    fn same_natural_key_under_different_components_does_not_alias() {
        // Validator index 1 appears as a registry key, an fc-message key and
        // a pending-fee key in the fixture. The component tag is what keeps
        // those three leaves apart; this pins that removing one of them
        // changes the root even though the other two remain — i.e. they are
        // three leaves, not one.
        let f = fixture();
        let base = state_root(&state(&f));

        let mut g = f.clone();
        g.fc_messages.retain(|m| m.validator != 1);
        let without_msg = state_root(&state(&g));
        assert_ne!(without_msg, base);

        let mut h = f.clone();
        h.pending_fees.retain(|p| p.validator != 1);
        let without_fee = state_root(&state(&h));
        assert_ne!(without_fee, base);
        assert_ne!(without_fee, without_msg);

        // Delegator 1 also appears in BOTH per-delegator ledgers — a slash
        // loss and a fee reward. Earning and losing must be two leaves.
        let mut k = f.clone();
        k.fee_rewards.retain(|r| r.delegator != 1);
        let without_reward = state_root(&state(&k));
        assert_ne!(without_reward, base);
        let mut l = f.clone();
        l.losses.retain(|r| r.delegator != 1);
        let without_loss = state_root(&state(&l));
        assert_ne!(without_loss, base);
        assert_ne!(without_reward, without_loss);
    }

    #[test]
    fn state_entries_are_provable_against_the_state_root() {
        let f = fixture();
        let s = state(&f);
        let tree = build_state_tree(&s);
        let root = tree.root();
        assert_eq!(root, state_root(&s), "tree and root entry points must agree");

        let v = &f.validators[2];
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
                randao_commitment: [0; 32],
                reveals_used: 0,
                withdrawable_epoch: u64::MAX,
                withdrawal_credentials: Vec::new(),
                commission_bps: 0,
            })
            .collect();
        assert_eq!(total_effective_stake(&validators), 3u128 * u64::MAX as u128);
    }
}
