//! Coherence shielded-pool primitives — the lean, portable core.
//!
//! Single source of truth shared by the node (`bloch::coherence` re-exports
//! this), the SP1 guest prover (`crates/coherence-prover`), and the mobile
//! wallet. Implements the C1-frozen formats (`docs/specs/COHERENCE-C1.md`):
//! SHAKE-256 note commitments, hash-derived nullifiers, a SHAKE-256 incremental
//! Merkle accumulator, and `check_spend` — the exact statement the ZK circuit
//! proves. No node/std-heavy dependencies, so it compiles for the zkVM target.

use serde::{Serialize, Deserialize};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

pub const TREE_DEPTH: usize = 32;

const DOM_CM: &[u8] = b"bloch:coherence:cm:v1";
const DOM_NF: &[u8] = b"bloch:coherence:nf:v1";
const DOM_MT: &[u8] = b"bloch:coherence:mt:v1";

/// SHAKE-256 squeezed to 32 bytes over the concatenation of `parts`.
fn shake256_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    for p in parts { h.update(p); }
    let mut xof = h.finalize_xof();
    let mut out = [0u8; 32];
    xof.read(&mut out);
    out
}

// ── Notes ────────────────────────────────────────────────────────────────────

/// A shielded note (private).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub v: u64,
    pub pk_d: [u8; 32],
    pub rho: [u8; 32],
    pub psi: [u8; 32],
}

impl Note {
    /// cm = SHAKE256(DOM_CM ‖ v ‖ pk_d ‖ rho ‖ psi).
    pub fn commitment(&self) -> [u8; 32] {
        shake256_32(&[DOM_CM, &self.v.to_le_bytes(), &self.pk_d, &self.rho, &self.psi])
    }
    /// Nullifier at `position` under nullifier key `nk`.
    pub fn nullifier(&self, nk: &[u8; 32], position: u64) -> [u8; 32] {
        shake256_32(&[DOM_NF, nk, &self.rho, &position.to_le_bytes()])
    }
}

fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_MT, left, right])
}

// ── Nullifier set (sparse Merkle tree, SHAKE-256) — C1.1 ─────────────────────
//
// C1 froze "the global nullifier set" as consensus state but never defined its
// commitment; the set lived as a bare `HashSet` with no canonical root (finding
// F9 of `BLOCH-COHERENCE-UNDER-POS.md`). Under PoS that gap becomes load
// bearing: `state_root` must commit the set, so the set needs a root, and the
// root must be a function of the *set* rather than of anyone's insertion order.
//
// Ratified in `docs/specs/COHERENCE-C1.1.md`. This is an addition to C1, not a
// change to it: nothing C1 froze moves.

/// Domain tag for the nullifier-set tree. Distinct from `DOM_MT` so a node of
/// this tree can never be reinterpreted as a node of the commitment tree.
const DOM_NFSET: &[u8] = b"bloch:coherence:nfset:v1";

/// Depth of the nullifier-set tree: one level per bit of a nullifier.
///
/// The nullifier IS the key, so the tree spans the whole 256-bit keyspace and
/// membership is positional — there is no ordering to agree on and no leaf
/// index to assign. That is the difference from [`CommitmentTree`], where a
/// note's *position* is consensus (it is bound into the nullifier, §1.3) and
/// therefore insertion order is too.
pub const NFSET_DEPTH: usize = 256;

/// The leaf stored at an occupied key. Any fixed non-empty value works; this
/// one is domain-separated so it cannot collide with a hash of anything else.
fn nfset_present() -> [u8; 32] {
    shake256_32(&[DOM_NFSET, b"present"])
}

fn nfset_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_NFSET, left, right])
}

/// `empty[d]` = root of an all-empty subtree of height `d`.
fn nfset_empty_roots() -> [[u8; 32]; NFSET_DEPTH + 1] {
    let mut e = [[0u8; 32]; NFSET_DEPTH + 1];
    e[0] = shake256_32(&[DOM_NFSET, b"empty-leaf"]);
    for d in 1..=NFSET_DEPTH {
        e[d] = nfset_parent(&e[d - 1], &e[d - 1]);
    }
    e
}

/// Bit `d` of `key`, MSB first — the direction taken at depth `d` walking down
/// from the root.
fn nfset_bit(key: &[u8; 32], d: usize) -> bool {
    (key[d / 8] >> (7 - (d % 8))) & 1 == 1
}

/// The spent-nullifier set and its canonical root.
///
/// A **sparse** Merkle tree keyed by the nullifier itself. Two properties are
/// the reason for choosing it over the cheaper running hash `H(prev ‖ nf)`:
///
/// 1. **The root is a function of the set.** A running hash makes insertion
///    order consensus, so two honest nodes that applied the same blocks in a
///    different order — or that undid and redid a reorg — would commit
///    different roots for identical state.
/// 2. **Non-membership is provable.** What a spend verifier actually needs is
///    "`nf` is *not* in the set as of this anchor", and a hash chain cannot
///    show that. [`NullifierSet::non_membership_proof`] returns the sibling
///    path; [`verify_non_membership`] checks it against a root, so a light
///    client or a pruning proof (§6.6.4) can be convinced without the set.
///
/// Insert-only in normal operation (§6.6.1); [`NullifierSet::remove`] exists
/// solely for reorg undo, driven by the block's recorded nullifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierSet {
    /// Sorted for determinism: the root is computed by descending this slice,
    /// so the traversal — and therefore the hashing — is a function of the set.
    keys: Vec<[u8; 32]>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from any iterator; duplicates collapse, order is irrelevant.
    pub fn from_iter<I: IntoIterator<Item = [u8; 32]>>(it: I) -> Self {
        let mut keys: Vec<[u8; 32]> = it.into_iter().collect();
        keys.sort_unstable();
        keys.dedup();
        Self { keys }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn contains(&self, nf: &[u8; 32]) -> bool {
        self.keys.binary_search(nf).is_ok()
    }

    /// Insert `nf`. Returns false if it was already spent — which is the
    /// double-spend check itself, so callers must not ignore it.
    pub fn insert(&mut self, nf: [u8; 32]) -> bool {
        match self.keys.binary_search(&nf) {
            Ok(_) => false,
            Err(i) => {
                self.keys.insert(i, nf);
                true
            }
        }
    }

    /// Remove `nf` — **reorg undo only**. The set is monotone in normal
    /// operation; removing a nullifier that was not undone by a disconnected
    /// block would resurrect a spent note.
    pub fn remove(&mut self, nf: &[u8; 32]) -> bool {
        match self.keys.binary_search(nf) {
            Ok(i) => {
                self.keys.remove(i);
                true
            }
            Err(_) => false,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.keys.iter()
    }

    /// The canonical root of the set.
    ///
    /// Computed by descending only where keys exist: an all-empty subtree
    /// short-circuits to its precomputed root, so the cost is bounded by the
    /// occupied paths rather than by the 2^256 keyspace.
    pub fn root(&self) -> [u8; 32] {
        let empty = nfset_empty_roots();
        Self::subtree_root(&self.keys, 0, &empty)
    }

    /// Root of the subtree at depth `d` spanning exactly `keys` (a contiguous,
    /// sorted slice of the keys that live under it).
    fn subtree_root(keys: &[[u8; 32]], d: usize, empty: &[[u8; 32]; NFSET_DEPTH + 1]) -> [u8; 32] {
        if keys.is_empty() {
            return empty[NFSET_DEPTH - d];
        }
        if d == NFSET_DEPTH {
            // A leaf: every key that reached here is the same key, since all
            // 256 bits have been consumed.
            return nfset_present();
        }
        // Sorted keys with a common prefix split on bit `d` into a zero-run
        // then a one-run, so the split point is a partition, not a filter.
        let split = keys.partition_point(|k| !nfset_bit(k, d));
        let l = Self::subtree_root(&keys[..split], d + 1, empty);
        let r = Self::subtree_root(&keys[split..], d + 1, empty);
        nfset_parent(&l, &r)
    }

    /// Sibling path proving `nf` is **absent**, root-to-leaf order reversed to
    /// leaf-to-root (index `d` is the sibling met at depth `NFSET_DEPTH-1-d`
    /// on the way up), matching [`verify_non_membership`].
    ///
    /// Returns `None` if `nf` is present — a caller asking for a proof of a
    /// spent nullifier has a bug, and a proof-shaped `None` is easier to
    /// notice than an unusable proof.
    pub fn non_membership_proof(&self, nf: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        if self.contains(nf) {
            return None;
        }
        let empty = nfset_empty_roots();
        let mut path = Vec::with_capacity(NFSET_DEPTH);
        let mut keys: &[[u8; 32]] = &self.keys;
        for d in 0..NFSET_DEPTH {
            let split = keys.partition_point(|k| !nfset_bit(k, d));
            let (mine, sibling) = if nfset_bit(nf, d) {
                (&keys[split..], &keys[..split])
            } else {
                (&keys[..split], &keys[split..])
            };
            path.push(Self::subtree_root(sibling, d + 1, &empty));
            keys = mine;
        }
        path.reverse();
        Some(path)
    }
}

/// Check a non-membership proof: walking the empty leaf up through `path` under
/// `nf`'s bits must reproduce `root`.
pub fn verify_non_membership(nf: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if path.len() != NFSET_DEPTH {
        return false;
    }
    let empty = nfset_empty_roots();
    let mut node = empty[0];
    for (i, sibling) in path.iter().enumerate() {
        // `path` is leaf-to-root, so entry `i` is the sibling at depth
        // `NFSET_DEPTH - 1 - i`.
        let d = NFSET_DEPTH - 1 - i;
        node = if nfset_bit(nf, d) {
            nfset_parent(sibling, &node)
        } else {
            nfset_parent(&node, sibling)
        };
    }
    node == *root
}

// ── Nullifier set, persistent form (Arc-shared SMT-256) — same root ──────────
//
// [`NullifierSet`] is the ratified definition (C1.1) and stays the reference:
// a sorted `Vec` whose `root()` descends the whole set. That shape is exactly
// wrong for a set that lives inside a consensus state which is **cloned once
// per block** (`compute_post_state` starts from `pre.clone()`): the clone is
// O(n) memcpy, the insert is O(n) `Vec::insert`, and the root is O(n·depth)
// hashing — replay goes quadratic in the pool's lifetime.
//
// `NullifierSmt` is the same set under the same commitment — bit-identical
// roots, pinned by test against `NullifierSet` — held as a persistent tree of
// immutable `Arc` nodes, the pattern `bloch-pos-committee::state_root::Smt`
// already uses for the eUTXO component: clone is O(1) (two pointer bumps),
// insert rebuilds only the touched path (≈2·256 SHAKE-256 calls, constant in
// the set size), and `root()` reads the cached top hash. Structural sharing is
// safe for exactly the reason it is safe in `state_root::Smt`: nodes are
// immutable, every node's hash is computed in its constructor from the very
// children it is built with, and a mutation rebuilds the root path instead of
// editing it — there is no invalidation step, so none can be forgotten.
//
// There is deliberately **no `remove`**: Genesis-4 reorgs are replay-of-state
// (the engine refolds from a kept pre-state clone), never undo, so the
// insert-only monotonicity of §6.6.1 holds with no exception here.

/// One immutable node of the persistent nullifier tree.
///
/// `Leaf` is a **maximal singleton**: the unique key below this point, with
/// the subtree's hash (the present-leaf folded up through empty siblings)
/// computed for the depth the node sits at. Both constructors below keep that
/// canonical form — a `Split` always has ≥ 2 keys under it — so two trees
/// holding the same set are structurally identical whatever order built them.
#[derive(Debug)]
enum NfsNode {
    Leaf {
        key: [u8; 32],
        hash: [u8; 32],
    },
    Split {
        left: Option<std::sync::Arc<NfsNode>>,
        right: Option<std::sync::Arc<NfsNode>>,
        hash: [u8; 32],
    },
}

impl NfsNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            NfsNode::Leaf { hash, .. } | NfsNode::Split { hash, .. } => *hash,
        }
    }
}

/// Hash of a singleton subtree rooted at depth `d` holding exactly `key`:
/// the present-leaf marker folded up through empty siblings along the key's
/// bits. Identical to what [`NullifierSet::subtree_root`] computes for a
/// one-key slice at the same depth.
fn nfset_singleton_hash(key: &[u8; 32], d: usize, empty: &[[u8; 32]]) -> [u8; 32] {
    let mut h = nfset_present();
    for lvl in (d..NFSET_DEPTH).rev() {
        let sibling = &empty[NFSET_DEPTH - 1 - lvl];
        h = if nfset_bit(key, lvl) {
            nfset_parent(sibling, &h)
        } else {
            nfset_parent(&h, sibling)
        };
    }
    h
}

/// Hash of an optional child sitting at depth `child_depth`.
fn nfs_child_hash(child: &Option<std::sync::Arc<NfsNode>>, child_depth: usize, empty: &[[u8; 32]]) -> [u8; 32] {
    match child {
        Some(n) => n.hash(),
        None => empty[NFSET_DEPTH - child_depth],
    }
}

fn nfs_leaf(key: [u8; 32], d: usize, empty: &[[u8; 32]]) -> std::sync::Arc<NfsNode> {
    std::sync::Arc::new(NfsNode::Leaf { key, hash: nfset_singleton_hash(&key, d, empty) })
}

fn nfs_split(
    left: Option<std::sync::Arc<NfsNode>>,
    right: Option<std::sync::Arc<NfsNode>>,
    d: usize,
    empty: &[[u8; 32]],
) -> std::sync::Arc<NfsNode> {
    let hash = nfset_parent(
        &nfs_child_hash(&left, d + 1, empty),
        &nfs_child_hash(&right, d + 1, empty),
    );
    std::sync::Arc::new(NfsNode::Split { left, right, hash })
}

/// Split node at depth `d` holding exactly the two distinct keys `a` and `b`.
fn nfs_split_pair(a: [u8; 32], b: [u8; 32], d: usize, empty: &[[u8; 32]]) -> std::sync::Arc<NfsNode> {
    debug_assert_ne!(a, b);
    let ab = nfset_bit(&a, d);
    if ab == nfset_bit(&b, d) {
        let child = nfs_split_pair(a, b, d + 1, empty);
        let (l, r) = if ab { (None, Some(child)) } else { (Some(child), None) };
        nfs_split(l, r, d, empty)
    } else {
        let (lo, hi) = if ab { (b, a) } else { (a, b) };
        nfs_split(
            Some(nfs_leaf(lo, d + 1, empty)),
            Some(nfs_leaf(hi, d + 1, empty)),
            d,
            empty,
        )
    }
}

/// The spent-nullifier set as a persistent, structurally-shared SMT-256.
///
/// Commits to **exactly the same root** as [`NullifierSet`] over the same set
/// (pinned by test); differs only in cost shape — see the module comment
/// above. `Clone` is O(1); use this form wherever the set lives inside a
/// state that is cloned per block.
#[derive(Clone)]
pub struct NullifierSmt {
    top: Option<std::sync::Arc<NfsNode>>,
    len: u64,
    /// `empty[h]` = root of an all-empty subtree of height `h`. Shared across
    /// clones (same posture as `state_root::Smt`): a per-instance immutable
    /// table, never global mutable state.
    empty: std::sync::Arc<Vec<[u8; 32]>>,
}

impl Default for NullifierSmt {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NullifierSmt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The tree is 256 levels deep; a derived Debug would print it all.
        f.debug_struct("NullifierSmt")
            .field("len", &self.len)
            .field("root", &self.root())
            .finish()
    }
}

/// Equality is root equality: the root is a collision-resistant commitment to
/// the set, and both construction paths (incremental insert and bulk build)
/// produce the same canonical structure anyway. Comparing hashes keeps the
/// check O(1) instead of a 256-deep structural walk.
impl PartialEq for NullifierSmt {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.root() == other.root()
    }
}
impl Eq for NullifierSmt {}

impl NullifierSmt {
    pub fn new() -> Self {
        Self { top: None, len: 0, empty: std::sync::Arc::new(nfset_empty_roots().to_vec()) }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains(&self, nf: &[u8; 32]) -> bool {
        let mut node = self.top.as_ref();
        let mut d = 0usize;
        while let Some(n) = node {
            match &**n {
                NfsNode::Leaf { key, .. } => return key == nf,
                NfsNode::Split { left, right, .. } => {
                    node = if nfset_bit(nf, d) { right.as_ref() } else { left.as_ref() };
                    d += 1;
                }
            }
        }
        false
    }

    /// Insert `nf`. Returns false if it was already spent — the double-spend
    /// check itself, same contract as [`NullifierSet::insert`].
    pub fn insert(&mut self, nf: [u8; 32]) -> bool {
        if self.contains(&nf) {
            return false;
        }
        let empty = std::sync::Arc::clone(&self.empty);
        self.top = Some(Self::insert_rec(self.top.as_ref(), &nf, 0, &empty));
        self.len += 1;
        true
    }

    /// Rebuild the path from depth `d` down to where `nf` lands; every node
    /// off the path is shared, not copied. `nf` is known absent (checked by
    /// the caller), so a `Leaf` met here always splits.
    fn insert_rec(
        node: Option<&std::sync::Arc<NfsNode>>,
        nf: &[u8; 32],
        d: usize,
        empty: &[[u8; 32]],
    ) -> std::sync::Arc<NfsNode> {
        match node {
            None => nfs_leaf(*nf, d, empty),
            Some(n) => match &**n {
                NfsNode::Leaf { key, .. } => nfs_split_pair(*key, *nf, d, empty),
                NfsNode::Split { left, right, .. } => {
                    if nfset_bit(nf, d) {
                        let new_right = Self::insert_rec(right.as_ref(), nf, d + 1, empty);
                        nfs_split(left.clone(), Some(new_right), d, empty)
                    } else {
                        let new_left = Self::insert_rec(left.as_ref(), nf, d + 1, empty);
                        nfs_split(Some(new_left), right.clone(), d, empty)
                    }
                }
            },
        }
    }

    /// The canonical root — [`NullifierSet::root`] of the same set, read from
    /// the cached top hash in O(1).
    pub fn root(&self) -> [u8; 32] {
        match &self.top {
            Some(n) => n.hash(),
            None => self.empty[NFSET_DEPTH],
        }
    }

    /// Every key, ascending (an in-order walk of an MSB-first tree is sorted
    /// order). This is the canonical serialization order.
    pub fn keys_sorted(&self) -> Vec<[u8; 32]> {
        fn walk(node: &Option<std::sync::Arc<NfsNode>>, out: &mut Vec<[u8; 32]>) {
            if let Some(n) = node {
                match &**n {
                    NfsNode::Leaf { key, .. } => out.push(*key),
                    NfsNode::Split { left, right, .. } => {
                        walk(left, out);
                        walk(right, out);
                    }
                }
            }
        }
        let mut out = Vec::with_capacity(self.len as usize);
        walk(&self.top, &mut out);
        out
    }

    /// Bulk build from strictly-ascending unique keys — the deserialization
    /// path. One singleton fold per key (the same total hashing as one
    /// [`NullifierSet::root`] pass), against ~2× that for repeated `insert`.
    /// Rejects unsorted or duplicated input rather than canonicalising it:
    /// the caller is decoding a serialized state, and bytes that are not the
    /// canonical encoding are corruption, not a formatting choice.
    pub fn from_sorted_unique(keys: &[[u8; 32]]) -> Result<Self, &'static str> {
        if keys.windows(2).any(|w| w[0] >= w[1]) {
            return Err("nullifier keys not strictly ascending");
        }
        let empty = std::sync::Arc::new(nfset_empty_roots().to_vec());
        fn build(
            keys: &[[u8; 32]],
            d: usize,
            empty: &[[u8; 32]],
        ) -> Option<std::sync::Arc<NfsNode>> {
            match keys.len() {
                0 => None,
                1 => Some(nfs_leaf(keys[0], d, empty)),
                _ => {
                    let split = keys.partition_point(|k| !nfset_bit(k, d));
                    let l = build(&keys[..split], d + 1, empty);
                    let r = build(&keys[split..], d + 1, empty);
                    Some(nfs_split(l, r, d, empty))
                }
            }
        }
        let top = build(keys, 0, &empty);
        Ok(Self { top, len: keys.len() as u64, empty })
    }
}

// ── Commitment tree (incremental, fixed depth, SHAKE-256) ─────────────────────

/// Append-only Merkle accumulator of note commitments; the root is the anchor.
#[derive(Debug, Clone, Default)]
pub struct CommitmentTree {
    leaves: Vec<[u8; 32]>,
}

impl CommitmentTree {
    pub fn new() -> Self { Self { leaves: Vec::new() } }

    pub fn append(&mut self, cm: [u8; 32]) -> u64 {
        let pos = self.leaves.len() as u64;
        self.leaves.push(cm);
        pos
    }

    /// Number of appended leaves (commitments).
    pub fn len(&self) -> usize { self.leaves.len() }
    pub fn is_empty(&self) -> bool { self.leaves.is_empty() }

    /// Drop leaves back to the first `n` (reorg undo). The root recomputes from
    /// the remaining leaves; truncating to a prior length restores the exact
    /// earlier root (append-only tree over a `Vec`).
    pub fn truncate(&mut self, n: usize) { self.leaves.truncate(n); }

    fn empty_roots() -> [[u8; 32]; TREE_DEPTH + 1] {
        let mut e = [[0u8; 32]; TREE_DEPTH + 1];
        e[0] = shake256_32(&[DOM_MT, b"empty-leaf"]);
        for d in 1..=TREE_DEPTH {
            e[d] = merkle_parent(&e[d - 1], &e[d - 1]);
        }
        e
    }

    pub fn root(&self) -> [u8; 32] {
        let empty = Self::empty_roots();
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        for d in 0..TREE_DEPTH {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() { level[i + 1] } else { empty[d] };
                next.push(merkle_parent(&l, &r));
                i += 2;
            }
            if next.is_empty() { next.push(empty[d + 1]); }
            level = next;
        }
        level[0]
    }

    pub fn path(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        if index as usize >= self.leaves.len() { return None; }
        let empty = Self::empty_roots();
        let mut idx = index as usize;
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut path = Vec::with_capacity(TREE_DEPTH);
        for d in 0..TREE_DEPTH {
            let sib = idx ^ 1;
            let s = if sib < level.len() { level[sib] } else { empty[d] };
            path.push(s);
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let l = level[i];
                let r = if i + 1 < level.len() { level[i + 1] } else { empty[d] };
                next.push(merkle_parent(&l, &r));
                i += 2;
            }
            if next.is_empty() { next.push(empty[d + 1]); }
            level = next;
            idx /= 2;
        }
        Some(path)
    }
}

/// Verify a Merkle path: fold `leaf` up with `path` and compare to `root`.
pub fn verify_path(leaf: &[u8; 32], index: u64, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if path.len() != TREE_DEPTH { return false; }
    let mut cur = *leaf;
    let mut idx = index;
    for sib in path {
        cur = if idx & 1 == 0 { merkle_parent(&cur, sib) } else { merkle_parent(sib, &cur) };
        idx >>= 1;
    }
    &cur == root
}

// ── Commitment accumulator, frontier form (what consensus state holds) ───────

/// The commitment accumulator reduced to what appending needs: the **frontier**
/// (one partial root per set bit of the leaf count) plus the leaf count.
///
/// Commits to **exactly the same root** as a [`CommitmentTree`] holding the
/// same leaves in the same order (pinned by test). The difference is what is
/// stored: `CommitmentTree` keeps the full leaf vector — a witness service for
/// wallets, reconstructible from block bodies, therefore a node-side index —
/// while consensus state needs only what the next append and the next root
/// require. Leaf order is consensus (the nullifier binds `LE64(position)`,
/// §1.3), and it is exactly the append order this struct advances.
///
/// Fixed size (≈1 KB), so cloning it inside a per-block state clone is a
/// memcpy, not an O(pool) copy. `append` is O(TREE_DEPTH) hashing worst case,
/// amortised 2 hashes; `root()` is O(TREE_DEPTH) hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    leaf_count: u64,
    /// `slots[d]` is meaningful iff bit `d` of `leaf_count` is set (slot
    /// `TREE_DEPTH` iff the tree is exactly full); every other slot is
    /// **zeroed**, kept canonical by `append` so that derived equality and
    /// byte serialization are functions of the accumulated leaves alone.
    slots: [[u8; 32]; TREE_DEPTH + 1],
}

impl Default for Frontier {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontier {
    pub fn new() -> Self {
        Self { leaf_count: 0, slots: [[0u8; 32]; TREE_DEPTH + 1] }
    }

    /// Number of leaves accumulated. The next leaf's position — the value the
    /// nullifier binds — is exactly this.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// Append `cm`, returning its position. Same contract as
    /// [`CommitmentTree::append`]; panics if the tree is full (2^32 leaves) —
    /// deterministic across all nodes, and a full pool is a protocol-level
    /// event, not a condition to paper over locally.
    pub fn append(&mut self, cm: [u8; 32]) -> u64 {
        assert!(self.leaf_count < 1u64 << TREE_DEPTH, "commitment accumulator full (2^32 leaves)");
        let pos = self.leaf_count;
        let mut cur = cm;
        let mut d = 0usize;
        // Carry: each completed left subtree combines and its slot zeroes,
        // exactly the binary increment of `leaf_count`.
        while (self.leaf_count >> d) & 1 == 1 {
            cur = merkle_parent(&self.slots[d], &cur);
            self.slots[d] = [0u8; 32];
            d += 1;
        }
        self.slots[d] = cur;
        self.leaf_count += 1;
        pos
    }

    /// The accumulator root — [`CommitmentTree::root`] of the same leaves.
    pub fn root(&self) -> [u8; 32] {
        if self.leaf_count == 1u64 << TREE_DEPTH {
            return self.slots[TREE_DEPTH];
        }
        let empty = CommitmentTree::empty_roots();
        let mut cur = empty[0];
        for d in 0..TREE_DEPTH {
            cur = if (self.leaf_count >> d) & 1 == 1 {
                merkle_parent(&self.slots[d], &cur)
            } else {
                merkle_parent(&cur, &empty[d])
            };
        }
        cur
    }

    /// The raw slots, for canonical serialization. Unset slots are zero — an
    /// invariant `append` maintains and [`Frontier::from_parts`] enforces.
    pub fn slots(&self) -> &[[u8; 32]; TREE_DEPTH + 1] {
        &self.slots
    }

    /// Rebuild from serialized parts, refusing non-canonical bytes: a slot
    /// whose count bit is clear must be zero, or two encodings of the same
    /// accumulator would exist (and derived equality would lie).
    pub fn from_parts(
        leaf_count: u64,
        slots: [[u8; 32]; TREE_DEPTH + 1],
    ) -> Result<Self, &'static str> {
        if leaf_count > 1u64 << TREE_DEPTH {
            return Err("frontier leaf count exceeds 2^32");
        }
        for (d, slot) in slots.iter().enumerate() {
            let bit_set = (leaf_count >> d) & 1 == 1;
            if !bit_set && slot != &[0u8; 32] {
                return Err("frontier slot set where the leaf-count bit is clear");
            }
        }
        Ok(Self { leaf_count, slots })
    }
}

// ── Spend statement (the SP1 guest logic; proved in ZK) ───────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendPublic {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub out_commitments: Vec<[u8; 32]>,
    pub fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendInput {
    pub note: Note,
    pub position: u64,
    pub path: Vec<[u8; 32]>,
    pub nk: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendWitness {
    pub inputs: Vec<SpendInput>,
    pub outputs: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendError {
    Membership(usize),
    Nullifier(usize),
    OutputCommitment(usize),
    /// public.nullifiers.len() != witness.inputs.len().
    NullifierCountMismatch { public: usize, witness: usize },
    /// public.out_commitments.len() != witness.outputs.len().
    OutputCountMismatch { public: usize, witness: usize },
    Overflow,
    Unbalanced { inputs: u128, outputs: u128, fee: u64 },
}

/// The EXACT statement the ZK circuit proves (runs on the PRIVATE witness).
pub fn check_spend(public: &SpendPublic, w: &SpendWitness) -> Result<(), SpendError> {
    // Bind the public vectors to the witness EXACTLY (C2 fix). Without these
    // binds a prover could append extra public out_commitments beyond the
    // witness outputs — commitments the balance check never sees — and mint
    // unbacked notes into the tree (shielded counterfeiting); likewise the
    // nullifier count must match the spent inputs one-for-one.
    if public.out_commitments.len() != w.outputs.len() {
        return Err(SpendError::OutputCountMismatch {
            public: public.out_commitments.len(),
            witness: w.outputs.len(),
        });
    }
    if public.nullifiers.len() != w.inputs.len() {
        return Err(SpendError::NullifierCountMismatch {
            public: public.nullifiers.len(),
            witness: w.inputs.len(),
        });
    }
    let mut in_sum: u128 = 0;
    for (i, inp) in w.inputs.iter().enumerate() {
        let cm = inp.note.commitment();
        if !verify_path(&cm, inp.position, &inp.path, &public.anchor) {
            return Err(SpendError::Membership(i));
        }
        let nf = inp.note.nullifier(&inp.nk, inp.position);
        if public.nullifiers.get(i) != Some(&nf) {
            return Err(SpendError::Nullifier(i));
        }
        in_sum = in_sum.checked_add(inp.note.v as u128).ok_or(SpendError::Overflow)?;
    }
    let mut out_sum: u128 = 0;
    for (i, out) in w.outputs.iter().enumerate() {
        if public.out_commitments.get(i) != Some(&out.commitment()) {
            return Err(SpendError::OutputCommitment(i));
        }
        out_sum = out_sum.checked_add(out.v as u128).ok_or(SpendError::Overflow)?;
    }
    if in_sum != out_sum + public.fee as u128 {
        return Err(SpendError::Unbalanced { inputs: in_sum, outputs: out_sum, fee: public.fee });
    }
    Ok(())
}

// ── Shielded transaction (wire type) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedTx {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub outputs: Vec<[u8; 32]>,
    pub fee: u64,
    pub proof: Vec<u8>,
    pub binding_sig: Vec<u8>,
}

impl ShieldedTx {
    pub fn public(&self) -> SpendPublic {
        SpendPublic {
            anchor: self.anchor,
            nullifiers: self.nullifiers.clone(),
            out_commitments: self.outputs.clone(),
            fee: self.fee,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(v: u64, tag: u8) -> Note {
        Note { v, pk_d: [tag; 32], rho: [tag ^ 0x11; 32], psi: [tag ^ 0x22; 32] }
    }

    #[test]
    fn commitment_and_nullifier_are_deterministic_and_distinct() {
        let n = note(100, 1);
        assert_eq!(n.commitment(), n.commitment());
        assert_ne!(n.commitment(), n.nullifier(&[9; 32], 0));
        assert_ne!(n.nullifier(&[9; 32], 0), n.nullifier(&[9; 32], 1));
    }

    #[test]
    fn merkle_membership_roundtrips() {
        let mut t = CommitmentTree::new();
        let cms: Vec<_> = (0..5u8).map(|i| note(i as u64, i).commitment()).collect();
        for cm in &cms { t.append(*cm); }
        let root = t.root();
        for (i, cm) in cms.iter().enumerate() {
            let path = t.path(i as u64).unwrap();
            assert!(verify_path(cm, i as u64, &path, &root));
        }
        assert!(!verify_path(&[0xAB; 32], 0, &t.path(0).unwrap(), &root));
    }

    #[test]
    fn check_spend_accepts_valid_and_rejects_inflation_and_forgery() {
        let mut t = CommitmentTree::new();
        let inp = note(1000, 7);
        let pos = t.append(inp.commitment());
        let anchor = t.root();
        let path = t.path(pos).unwrap();
        let nk = [3u8; 32];

        let out = note(900, 8);
        let public = SpendPublic {
            anchor, nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![out.commitment()], fee: 100,
        };
        let w = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path: path.clone(), nk }],
            outputs: vec![out],
        };
        assert_eq!(check_spend(&public, &w), Ok(()));

        // inflation
        let big = note(5000, 8);
        let pub2 = SpendPublic {
            anchor, nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![big.commitment()], fee: 0,
        };
        let w2 = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path: path.clone(), nk }],
            outputs: vec![big],
        };
        assert!(matches!(check_spend(&pub2, &w2), Err(SpendError::Unbalanced { .. })));

        // forged membership
        let bad = SpendPublic { anchor: [0xCD; 32], ..public.clone() };
        assert!(matches!(check_spend(&bad, &w), Err(SpendError::Membership(0))));
    }

    /// C2 regression: the public vectors must be bound to the witness lengths.
    /// Extra public out_commitments (unseen by the balance check) were the
    /// counterfeiting vector: a proof over N witness outputs would also attest
    /// to an N+1-th unbacked commitment entering the tree.
    #[test]
    fn check_spend_binds_public_counts_to_witness() {
        let mut t = CommitmentTree::new();
        let inp = note(1000, 7);
        let pos = t.append(inp.commitment());
        let anchor = t.root();
        let path = t.path(pos).unwrap();
        let nk = [3u8; 32];
        let out = note(900, 8);

        let honest = SpendPublic {
            anchor,
            nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![out.commitment()],
            fee: 100,
        };
        let w = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path, nk }],
            outputs: vec![out.clone()],
        };

        // (c) honest spend with matching lengths still verifies.
        assert_eq!(check_spend(&honest, &w), Ok(()));

        // (a) N witness outputs but N+1 public out_commitments must fail:
        // the smuggled commitment would mint an unbacked 1M-value note.
        let smuggled = note(1_000_000, 9);
        let mut inflated = honest.clone();
        inflated.out_commitments.push(smuggled.commitment());
        assert_eq!(
            check_spend(&inflated, &w),
            Err(SpendError::OutputCountMismatch { public: 2, witness: 1 })
        );

        // (b) N witness inputs but fewer public nullifiers must fail with the
        // distinct count-mismatch error (an input spent without publishing its
        // nullifier could be double-spent).
        let mut missing_nf = honest.clone();
        missing_nf.nullifiers.clear();
        assert_eq!(
            check_spend(&missing_nf, &w),
            Err(SpendError::NullifierCountMismatch { public: 0, witness: 1 })
        );

        // Extra public nullifiers beyond the witness inputs must also fail:
        // unproven nullifiers would burn notes the witness never opened.
        let mut extra_nf = honest.clone();
        extra_nf.nullifiers.push([0xEE; 32]);
        assert_eq!(
            check_spend(&extra_nf, &w),
            Err(SpendError::NullifierCountMismatch { public: 2, witness: 1 })
        );
    }
}

#[cfg(test)]
mod nfset_tests {
    use super::*;

    fn nf(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k[31] = b ^ 0xFF;
        k
    }

    /// The root is a function of the SET. This is the property a running hash
    /// `H(prev ‖ nf)` cannot have, and the reason it was rejected: insertion
    /// order would become consensus, so two nodes that applied the same blocks
    /// in a different order — or undid and redid a reorg — would commit
    /// different roots for identical state.
    #[test]
    fn root_depends_on_the_set_not_the_order() {
        let a = NullifierSet::from_iter([nf(1), nf(2), nf(3)]);
        let b = NullifierSet::from_iter([nf(3), nf(1), nf(2)]);
        let c = NullifierSet::from_iter([nf(2), nf(2), nf(1), nf(3), nf(3)]);
        assert_eq!(a.root(), b.root());
        assert_eq!(a.root(), c.root(), "duplicates must collapse");

        let mut d = NullifierSet::new();
        for k in [nf(3), nf(1), nf(2)] {
            assert!(d.insert(k));
        }
        assert_eq!(a.root(), d.root(), "incremental inserts must agree with a bulk build");
    }

    /// Every distinct set commits distinctly, including the empty one — which
    /// must not be the zero root, or "no pool" and "an unset field" would be
    /// indistinguishable in the state tree.
    #[test]
    fn distinct_sets_commit_distinctly() {
        let empty = NullifierSet::new().root();
        assert_ne!(empty, [0u8; 32]);
        let one = NullifierSet::from_iter([nf(1)]).root();
        let two = NullifierSet::from_iter([nf(1), nf(2)]).root();
        assert_ne!(empty, one);
        assert_ne!(one, two);
    }

    /// Insert reports the double-spend. The return value IS the check.
    #[test]
    fn reinserting_a_spent_nullifier_is_refused() {
        let mut s = NullifierSet::new();
        assert!(s.insert(nf(7)));
        assert!(!s.insert(nf(7)));
        assert_eq!(s.len(), 1);
    }

    /// Reorg undo restores the exact earlier root — the property that makes a
    /// disconnect safe. Without it a reorg would leave the chain committing a
    /// root no honest node could reproduce.
    #[test]
    fn removing_an_undone_nullifier_restores_the_earlier_root() {
        let mut s = NullifierSet::from_iter([nf(1), nf(2)]);
        let before = s.root();
        assert!(s.insert(nf(9)));
        assert_ne!(s.root(), before);
        assert!(s.remove(&nf(9)));
        assert_eq!(s.root(), before);
    }

    /// Non-membership verifies against the root, and stops verifying the
    /// moment the nullifier is spent — which is the whole point: a spend
    /// verifier proves `nf ∉ set` at the anchor.
    #[test]
    fn non_membership_proves_absence_and_only_absence() {
        let mut s = NullifierSet::from_iter([nf(1), nf(2), nf(3)]);
        let root = s.root();
        let absent = nf(42);

        let proof = s.non_membership_proof(&absent).expect("absent key has a proof");
        assert_eq!(proof.len(), NFSET_DEPTH);
        assert!(verify_non_membership(&absent, &proof, &root));

        // The security-relevant negative: the proof must NOT verify for a key
        // that IS in the set. (It *will* verify for other absent keys whose
        // path meets the same siblings — in a sparse tree an all-empty path
        // proves the whole region empty, so one proof legitimately covers many
        // absent keys. That is a property of the structure, not a weakness:
        // what a verifier concludes is "this key is absent", which is true for
        // every key the proof covers.)
        assert!(!verify_non_membership(&nf(1), &proof, &root), "a spent key verified as absent");
        // Nor against a different root.
        let other = NullifierSet::from_iter([nf(1)]).root();
        assert!(!verify_non_membership(&absent, &proof, &other));

        // Once spent, there is no proof of absence and the old one dies.
        s.insert(absent);
        assert!(s.non_membership_proof(&absent).is_none());
        assert!(!verify_non_membership(&absent, &proof, &s.root()));
    }

    /// A tampered path is rejected. Without this the verifier could be
    /// accepting any 256 hashes of the right length.
    #[test]
    fn tampered_paths_are_rejected() {
        let s = NullifierSet::from_iter([nf(1), nf(2)]);
        let root = s.root();
        let absent = nf(200);
        let good = s.non_membership_proof(&absent).unwrap();

        for i in [0usize, 1, NFSET_DEPTH / 2, NFSET_DEPTH - 1] {
            let mut bad = good.clone();
            bad[i][0] ^= 1;
            assert!(!verify_non_membership(&absent, &bad, &root), "tamper at {i} accepted");
        }
        let mut short = good.clone();
        short.pop();
        assert!(!verify_non_membership(&absent, &short, &root));
    }

    /// The nullifier-set tree and the commitment tree must never share a node
    /// value for the same inputs — different domain tags, checked rather than
    /// assumed.
    #[test]
    fn nfset_domain_is_separate_from_the_commitment_tree() {
        let l = nf(1);
        let r = nf(2);
        assert_ne!(nfset_parent(&l, &r), merkle_parent(&l, &r));
        assert_ne!(NullifierSet::new().root(), CommitmentTree::new().root());
    }
}

#[cfg(test)]
mod persistent_state_tests {
    use super::*;

    /// Deterministic pseudo-random 32-byte keys (SHAKE of a counter), so the
    /// equivalence claims below are exercised over keys that actually spread
    /// across the tree instead of clustering in one subtree.
    fn prk(i: u64) -> [u8; 32] {
        shake256_32(&[b"coherence-test-key", &i.to_le_bytes()])
    }

    fn unhex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// The two empty roots are pinned as constants because the live Genesis-4
    /// chain committed `[0u8; 32]` sentinels instead of them: an empty pool
    /// and the genesis sentinel are DIFFERENT values, and any code that
    /// equates them must fail a test, not a mainnet. The flag-day bridge from
    /// sentinel to real root is a separate, deliberate change (DEV-10).
    #[test]
    fn empty_roots_are_pinned_and_are_not_zero() {
        let acc = unhex32("cd640768299853bb27e3dfa62faed4b9c2e9348d8ac2f81dd03ecc96ae5b3ff1");
        let nfs = unhex32("d5fdc9dcde0d309db399649a21cd95e45e117e369c13cca70b8e87f2849f7930");
        assert_eq!(CommitmentTree::new().root(), acc);
        assert_eq!(Frontier::new().root(), acc);
        assert_eq!(NullifierSet::new().root(), nfs);
        assert_eq!(NullifierSmt::new().root(), nfs);
        assert_ne!(acc, [0u8; 32], "empty accumulator root must not equal the genesis sentinel");
        assert_ne!(nfs, [0u8; 32], "empty nullifier root must not equal the genesis sentinel");
        assert_ne!(acc, nfs);
    }

    /// The frontier is the same accumulator as the full-leaf-vector tree:
    /// identical roots and positions at every step, across lengths that cover
    /// every carry shape up to several complete subtrees.
    #[test]
    fn frontier_matches_commitment_tree_at_every_length() {
        let mut tree = CommitmentTree::new();
        let mut frontier = Frontier::new();
        assert_eq!(tree.root(), frontier.root());
        for i in 0..130u64 {
            let cm = prk(i);
            let p1 = tree.append(cm);
            let p2 = frontier.append(cm);
            assert_eq!(p1, p2, "positions diverge at leaf {i}");
            assert_eq!(frontier.leaf_count(), tree.len() as u64);
            assert_eq!(tree.root(), frontier.root(), "roots diverge after leaf {i}");
        }
    }

    /// Frontier serialization round-trips through its parts, and the
    /// non-canonical encodings (a stale slot where the count bit is clear)
    /// are refused rather than accepted-and-unequal.
    #[test]
    fn frontier_parts_round_trip_and_reject_non_canonical() {
        let mut f = Frontier::new();
        for i in 0..37u64 {
            f.append(prk(i));
        }
        let rebuilt = Frontier::from_parts(f.leaf_count(), *f.slots()).unwrap();
        assert_eq!(f, rebuilt);
        assert_eq!(f.root(), rebuilt.root());

        // 37 = 0b100101: bit 1 is clear, so slot 1 must be zero.
        let mut bad = *f.slots();
        bad[1] = [0xAA; 32];
        assert!(Frontier::from_parts(37, bad).is_err());
        assert!(Frontier::from_parts((1u64 << TREE_DEPTH) + 1, *f.slots()).is_err());
    }

    /// The persistent SMT commits to exactly the NullifierSet root at every
    /// step, via both construction paths, and agrees on membership.
    #[test]
    fn nullifier_smt_matches_nullifier_set_at_every_step() {
        let mut reference = NullifierSet::new();
        let mut persistent = NullifierSmt::new();
        assert_eq!(reference.root(), persistent.root());
        let keys: Vec<[u8; 32]> = (0..96u64).map(prk).collect();
        for (i, k) in keys.iter().enumerate() {
            assert!(persistent.insert(*k));
            assert!(reference.insert(*k));
            assert_eq!(reference.root(), persistent.root(), "roots diverge after insert {i}");
            assert!(!persistent.insert(*k), "re-insert must report the double spend");
            assert!(persistent.contains(k));
        }
        assert!(!persistent.contains(&prk(1_000_000)));
        assert_eq!(persistent.len(), 96);

        // Bulk build from the canonical serialization order agrees with the
        // incrementally built tree — and with the reference.
        let sorted = persistent.keys_sorted();
        assert!(sorted.windows(2).all(|w| w[0] < w[1]), "keys_sorted must be strictly ascending");
        let bulk = NullifierSmt::from_sorted_unique(&sorted).unwrap();
        assert_eq!(bulk, persistent);
        assert_eq!(bulk.root(), reference.root());

        // Non-canonical input is refused.
        let mut unsorted = sorted.clone();
        unsorted.swap(0, 1);
        assert!(NullifierSmt::from_sorted_unique(&unsorted).is_err());
        let mut dup = sorted.clone();
        dup[1] = dup[0];
        assert!(NullifierSmt::from_sorted_unique(&dup).is_err());
    }

    /// Clone is structural sharing: after cloning, mutating one side must not
    /// move the other side's root — and both sides stay internally correct.
    #[test]
    fn nullifier_smt_clone_shares_and_diverges_safely() {
        let mut a = NullifierSmt::new();
        for i in 0..40u64 {
            a.insert(prk(i));
        }
        let frozen = a.clone();
        let frozen_root = frozen.root();
        a.insert(prk(999));
        assert_ne!(a.root(), frozen_root, "insert must move the mutated tree's root");
        assert_eq!(frozen.root(), frozen_root, "the clone must be immune to later inserts");
        assert_eq!(
            frozen.root(),
            NullifierSet::from_iter((0..40u64).map(prk)).root(),
            "the frozen clone still commits the original set"
        );
    }
}
