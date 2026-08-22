//! # `state` — committed, non-per-UTXO module state as a single 32-byte root
//!
//! This module is the reference design for the **hard Ustav problem**: an Ustav
//! token's modules need state that is *not* naturally per-UTXO — a **registry**
//! (`key -> value`), a bounded **holder-set** (`max_holders`), a **dividend
//! snapshot** (balances frozen at a point), and **allow/deny lists**. An eUTXO
//! datum can only carry a small, fixed blob; it cannot carry an unbounded map.
//!
//! The answer, the same one Cardano/Ergo-style chains use, is a **cryptographic
//! commitment**: keep the big map off-datum, and carry a single **32-byte root**
//! in the datum (as a [`crate::Val::Bytes`]). A validator asserts the root against
//! `ctx`; anyone can prove a specific key's membership *or* non-membership from
//! `root + key + (value?) + path` alone, without the whole map.
//!
//! ## What this provides
//! - A canonical **sparse Merkle tree** (SMT), fixed depth 256, keyed by the
//!   SHAKE-256 hash of the key. Domain-separated tags (`KEY`/`LEAF`/`NODE`) and a
//!   precomputed empty-subtree ladder. Same map ⇒ identical root, regardless of
//!   insertion order.
//! - **Membership** proofs (a key maps to a value) *and* **non-membership** proofs
//!   (a key's slot is empty), both verifiable from the root alone.
//! - Four typed wrappers over the SMT: [`Registry`], [`HolderSet`] (deterministic
//!   `max_holders` bound via checked arithmetic), [`Snapshot`] (frozen balances +
//!   floor-division dividend math), and [`MembershipList`] + [`gate_allows`]
//!   (allow/deny gating).
//! - [`root_as_val`] / [`val_as_root`]: move a root in and out of a [`crate::Val`]
//!   so an on-chain validator can assert `datum_root == ctx_root`.
//!
//! ## Hashing discipline — matches the VM's `Op::Shake256`
//! Roots computed here MUST equal roots a validator could recompute on-chain, so
//! this module reuses lib.rs's exact hashing primitive: `sha3::Shake256`, absorb,
//! `finalize_xof`, read **32 bytes**. The only additions are 1-byte **domain tags**
//! and length prefixes so the leaf/node/key hash spaces never collide.
//!
//! ## Honest limits
//! Reference / foundation, **unaudited, not consensus-wired**. Deterministic by
//! construction: no I/O, no clock, no float, canonical `BTreeMap` ordering, checked
//! integer arithmetic for every count and bound. Proof size is the full depth (256
//! siblings) — correct and simple, not size-optimized; a production build would
//! compress default siblings. Designed ≠ audited ≠ booted.

use std::collections::BTreeMap;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::Val;

/// A 32-byte digest — a leaf hash, an internal node hash, or a tree root.
pub type Hash = [u8; 32];

/// Fixed tree depth: the key hash is 256 bits, so every key occupies a unique
/// leaf slot at depth 256. Non-membership is "this slot is the empty leaf".
pub const TREE_DEPTH: usize = 256;

/// The size of a root, in bytes — it fits in a [`crate::Val::Bytes`].
pub const ROOT_BYTES: usize = 32;

/// The empty-leaf sentinel: an absent key's slot hashes to this. A present leaf is
/// a domain-tagged SHAKE-256 digest, which is never all-zero in practice, so the
/// two spaces do not collide.
pub const EMPTY_LEAF: Hash = [0u8; 32];

// Domain-separation tags. Distinct first bytes keep the key-hash, leaf-hash and
// node-hash pre-images in disjoint spaces (no cross-space second-preimages).
const KEY_TAG: u8 = 0x02;
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

/// Gas to charge per SHAKE-256 invocation — mirrors lib.rs `gas_cost(Op::Shake256)`
/// so an integrator can price state proofs on the same schedule as the VM.
pub const SHAKE256_GAS: u64 = 60;

/// Reference gas to **verify** one proof: one key hash + `TREE_DEPTH` node hashes
/// (the leaf hash is folded into the first node hash). Membership adds one leaf
/// hash. This is advisory — the caller meters it against its own budget.
pub const fn verify_gas() -> u64 {
    SHAKE256_GAS * (TREE_DEPTH as u64 + 2)
}

// ── core hashing (identical discipline to lib.rs Op::Shake256) ──────────────────

/// SHAKE-256 XOF over the concatenation of `parts`, read to exactly 32 bytes.
fn shake32(parts: &[&[u8]]) -> Hash {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut r = h.finalize_xof();
    let mut out = [0u8; 32];
    r.read(&mut out);
    out
}

/// The 256-bit **path** of a key: `SHAKE-256(KEY_TAG ‖ key)`. Determines the leaf
/// slot; independent of the value.
pub fn key_hash(key: &[u8]) -> Hash {
    shake32(&[&[KEY_TAG], key])
}

/// The leaf hash for a present `(key, value)`: binds the value to its key slot and
/// length-prefixes the value for injectivity.
fn leaf_hash(kh: &Hash, value: &[u8]) -> Hash {
    let len = (value.len() as u64).to_le_bytes();
    shake32(&[&[LEAF_TAG], kh, &len, value])
}

/// The internal node hash of an ordered `(left, right)` child pair.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    shake32(&[&[NODE_TAG], left, right])
}

/// Bit `depth` of a hash, most-significant-first (`depth 0` = MSB of byte 0).
fn bit_at(h: &Hash, depth: usize) -> u8 {
    let byte = depth / 8;
    let shift = 7 - (depth % 8);
    (h[byte] >> shift) & 1
}

/// The empty-subtree ladder: `empty[256]` is the empty leaf; `empty[d]` is the hash
/// of a fully-empty subtree rooted at depth `d`. An empty tree's root is `empty[0]`.
///
/// Computed once per process (`OnceLock`): the ladder is 256 chained SHAKE-256
/// calls, and the pre-refactor code recomputed it on EVERY `root()`/`prove()` call —
/// measurable, pure waste, since the ladder is a compile-time-constant-in-spirit
/// value the code cannot yet make a `const` (SHAKE-256 is not const-evaluable).
fn empty_hashes() -> &'static [Hash; TREE_DEPTH + 1] {
    static LADDER: std::sync::OnceLock<[Hash; TREE_DEPTH + 1]> = std::sync::OnceLock::new();
    LADDER.get_or_init(|| {
        let mut e = [[0u8; 32]; TREE_DEPTH + 1];
        e[TREE_DEPTH] = EMPTY_LEAF;
        let mut d = TREE_DEPTH;
        while d > 0 {
            d -= 1;
            e[d] = node_hash(&e[d + 1], &e[d + 1]);
        }
        e
    })
}

/// The path **prefix** identifying the subtree a key's path passes through at
/// `depth`: bits `[0, depth)` of the key hash kept, bits `[depth, 256)` zeroed.
/// `(depth, prefix)` is the canonical name of an internal node — stable across
/// mutations, which is what makes it usable as a cache key (unlike the
/// entry-slice ranges the pre-refactor recursion was shaped around).
fn prefix_at(kh: &Hash, depth: usize) -> Hash {
    let mut p = [0u8; 32];
    let full = depth / 8;
    p[..full].copy_from_slice(&kh[..full]);
    if depth % 8 != 0 {
        p[full] = kh[full] & (0xffu8 << (8 - depth % 8));
    }
    p
}

/// `prefix` with bit `depth` set — the name of the right child of node
/// `(depth, prefix)`. (The left child is `(depth + 1, prefix)` unchanged.)
fn set_bit(mut prefix: Hash, depth: usize) -> Hash {
    prefix[depth / 8] |= 1u8 << (7 - depth % 8);
    prefix
}

/// Upper bound (inclusive) of the key-hash range covered by node `(depth, prefix)`:
/// bits `[depth, 256)` set to 1. Lower bound is `prefix` itself.
fn range_hi(mut prefix: Hash, depth: usize) -> Hash {
    let full = depth / 8;
    if depth % 8 != 0 {
        prefix[full] |= 0xffu8 >> (depth % 8);
        for b in &mut prefix[full + 1..] {
            *b = 0xff;
        }
    } else {
        for b in &mut prefix[full..] {
            *b = 0xff;
        }
    }
    prefix
}

/// Fold a single leaf up an otherwise-empty subtree from `TREE_DEPTH` to `depth`:
/// the hash of a subtree at `depth` that contains exactly the one entry `(kh, leaf)`.
/// `O(TREE_DEPTH - depth)` node hashes, no recursion, no cache required — this is
/// the closed form the incremental engine uses for every single-entry subtree, so
/// the node cache only ever holds one entry per *occupied* node-with-siblings
/// instead of one per spine level (memory `O(n)`, not `O(n · 256)`).
fn spine_hash(kh: &Hash, leaf: &Hash, depth: usize, empty: &[Hash; TREE_DEPTH + 1]) -> Hash {
    let mut cur = *leaf;
    let mut d = TREE_DEPTH;
    while d > depth {
        d -= 1;
        cur = if bit_at(kh, d) == 0 {
            node_hash(&cur, &empty[d + 1])
        } else {
            node_hash(&empty[d + 1], &cur)
        };
    }
    cur
}

// ── the sparse Merkle tree ──────────────────────────────────────────────────────

/// A canonical, deterministic sparse Merkle tree over `key -> value` byte maps.
///
/// Determinism: the backing stores are `BTreeMap`s (canonical ordering) and the root
/// is a pure function of the *set* of entries — two trees with the same entries have
/// the same root no matter the insertion order (proved in tests, and byte-pinned
/// against the pre-refactor implementation in `tests/euvm_pinned_roots.rs`).
///
/// ## Incremental engine (refactor of the original recompute-everything design)
///
/// The pre-refactor `root()` rebuilt the whole tree on every call: it re-hashed
/// every key and leaf (`entries()`), then recursed every occupied path down all 256
/// levels — `O(n · 256)` SHAKE-256 calls *per `root()` call*, and the `Registry` /
/// `HolderSet` wrappers call `root()` after every mutation, making a build of n
/// entries quadratic. This engine keeps the identical hash discipline (same
/// `KEY`/`LEAF`/`NODE` tags, same ladder, same canonical entry order — the roots are
/// byte-identical, see the KATs) but maintains state incrementally:
///
/// - `entries`: `key_hash -> leaf_hash`, the canonical sorted entry set. Leaf hashes
///   are computed once per mutation, not once per `root()` call.
/// - `cache`: memoized internal-node hashes keyed by the stable node name
///   `(depth, prefix)`. A mutation of key `k` invalidates exactly the 256 nodes on
///   `k`'s path (a node's hash can only change if its subtree contains the mutated
///   leaf, and those are precisely the nodes whose prefix prefixes `key_hash(k)`).
/// - `root_hash`: recomputed eagerly at the end of every mutation by re-walking the
///   invalidated path with memo hits everywhere else — `O(256)` hashes per mutation
///   amortized — so `root()` is a field read and needs no interior mutability
///   (`&self` stays `Sync`, and `Eq`/`Clone` semantics stay value-like).
///
/// The cache is a `BTreeMap` (not `HashMap`) deliberately: this crate's determinism
/// story is "no allocation- or iteration-order-dependent behaviour anywhere", and a
/// BTreeMap keeps even the debug representation canonical. Persistence of the node
/// cache / entry set to disk is deliberately NOT provided here — see
/// docs/specs/BLOCH-EUVM-GAP-MAP.md ("what remains open") for the backing-store
/// seam this design leaves.
#[derive(Clone, Debug, Default)]
pub struct SparseMerkleTree {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    /// `key_hash -> leaf_hash`, kept in canonical (big-endian hash) order.
    entries: BTreeMap<Hash, Hash>,
    /// Memoized internal-node hashes by stable node name `(depth, prefix)`.
    /// Holds only branching nodes and single-entry subtree TOPS (spine interiors
    /// are recomputed by `spine_hash`'s closed form) — `O(n)` entries total.
    cache: BTreeMap<(u16, Hash), Hash>,
    /// The current root, maintained eagerly by `recompute_root` on every mutation.
    /// `None` iff the tree is empty (the empty root is the ladder head, which is
    /// not representable as a "computed" value at `Default`-construction time
    /// because the ladder is lazily initialized).
    root_hash: Option<Hash>,
}

/// Semantic equality: two trees are equal iff they commit to the same `key -> value`
/// map. The node cache is mutation-history-dependent (a memo, not state) and MUST
/// NOT participate — a derived `PartialEq` would call two semantically identical
/// trees unequal just because they were built in different orders.
impl PartialEq for SparseMerkleTree {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}
impl Eq for SparseMerkleTree {}

/// A membership / non-membership proof for a single key, verifiable from a root.
///
/// `value = Some(_)` is a **membership** proof (the key maps to this value);
/// `value = None` is a **non-membership** proof (the key's slot is the empty leaf).
/// `siblings` holds one hash per depth, indexed `0..TREE_DEPTH`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub siblings: Vec<Hash>,
}

impl Proof {
    /// True iff this is a membership proof (the key was present).
    pub fn is_membership(&self) -> bool {
        self.value.is_some()
    }
}

impl SparseMerkleTree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite `key -> value`; returns the previous value if any.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
        let kh = key_hash(key);
        self.entries.insert(kh, leaf_hash(&kh, value));
        let prev = self.map.insert(key.to_vec(), value.to_vec());
        self.invalidate_path(&kh);
        self.recompute_root();
        prev
    }

    /// Remove `key`; returns the removed value if any.
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let prev = self.map.remove(key);
        if prev.is_some() {
            let kh = key_hash(key);
            self.entries.remove(&kh);
            self.invalidate_path(&kh);
            self.recompute_root();
        }
        prev
    }

    /// The value bound to `key`, if present.
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.map.get(key)
    }

    /// Whether `key` is present.
    pub fn contains(&self, key: &[u8]) -> bool {
        self.map.contains_key(key)
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drop the memoized hash of every node on `kh`'s path — exactly the set of
    /// nodes whose subtree contains the mutated leaf, hence exactly the set whose
    /// hash may have changed. Nodes off the path keep their (still-correct) memos.
    fn invalidate_path(&mut self, kh: &Hash) {
        for d in 0..TREE_DEPTH {
            self.cache.remove(&(d as u16, prefix_at(kh, d)));
        }
    }

    /// The hash of node `(depth, prefix)`, memoizing every branching node and
    /// single-entry subtree top it computes. Recursion depth is bounded by
    /// `TREE_DEPTH`; with warm memos a post-mutation recompute only descends the
    /// invalidated path (`O(TREE_DEPTH)` work), everything else is a memo hit.
    fn node(&mut self, depth: usize, prefix: Hash, empty: &[Hash; TREE_DEPTH + 1]) -> Hash {
        let hi = range_hi(prefix, depth);
        let mut in_range = self.entries.range(prefix..=hi);
        let (first_kh, first_leaf) = match in_range.next() {
            None => return empty[depth],
            Some((k, l)) => (*k, *l),
        };
        if depth == TREE_DEPTH {
            // 256-bit unique key hashes: exactly one entry can land on a full path.
            return first_leaf;
        }
        if let Some(h) = self.cache.get(&(depth as u16, prefix)) {
            return *h;
        }
        let single = in_range.next().is_none();
        let h = if single {
            spine_hash(&first_kh, &first_leaf, depth, empty)
        } else {
            let left = self.node(depth + 1, prefix, empty);
            let right = self.node(depth + 1, set_bit(prefix, depth), empty);
            node_hash(&left, &right)
        };
        self.cache.insert((depth as u16, prefix), h);
        h
    }

    /// Recompute and store the root after a mutation (memo hits off the path).
    fn recompute_root(&mut self) {
        if self.entries.is_empty() {
            self.root_hash = None;
            return;
        }
        let empty = *empty_hashes();
        let r = self.node(0, [0u8; 32], &empty);
        self.root_hash = Some(r);
    }

    /// Read-only node hash for proof generation: ladder for empty, memo hit where
    /// available, closed-form spine for single-entry subtrees, and a (rare — only
    /// reachable if the memo was never built, which `recompute_root` prevents)
    /// recursive recompute as the correctness backstop.
    fn node_readonly(&self, depth: usize, prefix: Hash, empty: &[Hash; TREE_DEPTH + 1]) -> Hash {
        let hi = range_hi(prefix, depth);
        let mut in_range = self.entries.range(prefix..=hi);
        let (first_kh, first_leaf) = match in_range.next() {
            None => return empty[depth],
            Some((k, l)) => (*k, *l),
        };
        if depth == TREE_DEPTH {
            return first_leaf;
        }
        if let Some(h) = self.cache.get(&(depth as u16, prefix)) {
            return *h;
        }
        if in_range.next().is_none() {
            return spine_hash(&first_kh, &first_leaf, depth, empty);
        }
        let left = self.node_readonly(depth + 1, prefix, empty);
        let right = self.node_readonly(depth + 1, set_bit(prefix, depth), empty);
        node_hash(&left, &right)
    }

    /// The 32-byte root committing to the whole map. Pure function of the entry set
    /// (byte-identical to the pre-refactor full recomputation — pinned by KATs).
    /// `O(1)`: mutations maintain it eagerly.
    pub fn root(&self) -> Hash {
        match self.root_hash {
            Some(r) => r,
            None => empty_hashes()[0],
        }
    }

    /// A proof for `key`: membership if present, non-membership otherwise.
    /// Walks the key's path once, reading each off-path sibling from the memo /
    /// ladder / spine closed form — `O(TREE_DEPTH)` after any mutation, instead of
    /// the pre-refactor full-tree recursion per call.
    pub fn prove(&self, key: &[u8]) -> Proof {
        let empty = empty_hashes();
        let target = key_hash(key);
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut prefix = [0u8; 32];
        for d in 0..TREE_DEPTH {
            if bit_at(&target, d) == 0 {
                // going left: sibling is the right child
                siblings.push(self.node_readonly(d + 1, set_bit(prefix, d), empty));
            } else {
                // going right: sibling is the left child; extend own prefix
                siblings.push(self.node_readonly(d + 1, prefix, empty));
                prefix = set_bit(prefix, d);
            }
        }
        Proof {
            key: key.to_vec(),
            value: self.map.get(key).cloned(),
            siblings,
        }
    }
}

/// Verify a membership / non-membership `proof` against `root`, from the proof
/// alone — no access to the tree. Recomputes the key's path and folds the leaf up
/// through the siblings; accepts iff it reproduces `root`.
///
/// Soundness (proved in tests): tampering with the leaf value, any sibling, or the
/// membership/non-membership flag changes the recomputed root and fails.
pub fn verify(root: &Hash, proof: &Proof) -> bool {
    if proof.siblings.len() != TREE_DEPTH {
        return false;
    }
    let kh = key_hash(&proof.key);
    let mut cur = match &proof.value {
        Some(v) => leaf_hash(&kh, v),
        None => EMPTY_LEAF,
    };
    let mut depth = TREE_DEPTH;
    while depth > 0 {
        depth -= 1;
        let sib = &proof.siblings[depth];
        cur = if bit_at(&kh, depth) == 0 {
            node_hash(&cur, sib)
        } else {
            node_hash(sib, &cur)
        };
    }
    &cur == root
}

// ── Val bridge (so a validator can assert a root against ctx) ────────────────────

// ── compressed proofs (audit finding #3: 8 KiB per proof, uncompressed) ─────────

/// A **compressed** membership / non-membership proof.
///
/// A [`Proof`] carries 256 sibling hashes = 8 KiB, regardless of how many keys the
/// tree actually holds — the size the reuse audit flags
/// (docs/specs/BLOCH-L1-EVM-REUSE-AUDIT.md §7.1, finding 3: "Proofs are
/// uncompressed: 256 × 32 B = 8 KiB each, with no empty-ladder run compression").
///
/// In a real tree that is almost all padding. A tree with `n` entries has roughly
/// `log2(n)` levels where the sibling is a genuine subtree; every level below that
/// has an *empty* sibling, and an empty sibling at depth `d` is not data — it is
/// `empty_hashes()[d + 1]`, a value the verifier recomputes from nothing. So the
/// proof only needs to say **which** levels are non-empty and supply those hashes.
///
/// Encoding: a 256-bit `present` bitmap (32 B, MSB-first, bit `d` = "level `d`'s
/// sibling is non-empty") plus the non-empty hashes in depth order. A single-entry
/// tree's proof goes from 8192 B to 32 B.
///
/// This is a **transport format only**. It is a new structure sitting beside
/// [`Proof`]; nothing about roots, [`verify`], or the existing proof format changes,
/// because those are committed identities (see `tests/euvm_pinned_roots.rs`).
/// [`compress`]/[`expand`] round-trip byte-for-byte, proved in
/// `tests/euvm_compressed_proofs.rs`, including the adversarial case of a *genuine*
/// subtree hash that happens to equal an empty-ladder value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedProof {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    /// Bit `d` (MSB-first over 32 bytes) set ⇔ `siblings[d] != empty_hashes()[d + 1]`.
    pub present: [u8; 32],
    /// The non-empty siblings, in ascending depth order. Length == popcount(present).
    pub nodes: Vec<Hash>,
}

impl CompressedProof {
    /// True iff this is a membership proof (the key was present).
    pub fn is_membership(&self) -> bool {
        self.value.is_some()
    }
    /// Serialized size in bytes of the witness part (bitmap + nodes) — what the
    /// compression actually buys, comparable against `TREE_DEPTH * 32` = 8192.
    pub fn witness_bytes(&self) -> usize {
        32 + self.nodes.len() * 32
    }
}

/// Compress a [`Proof`] by dropping every sibling that equals the empty-subtree
/// ladder value for its depth (the verifier regenerates those).
///
/// Returns `None` for a structurally invalid proof (wrong sibling count) rather than
/// producing a compressed form that could never expand — fail-closed, matching
/// [`verify`]'s own length check.
pub fn compress(proof: &Proof) -> Option<CompressedProof> {
    if proof.siblings.len() != TREE_DEPTH {
        return None;
    }
    let empty = empty_hashes();
    let mut present = [0u8; 32];
    let mut nodes = Vec::new();
    for (d, sib) in proof.siblings.iter().enumerate() {
        // A sibling at depth `d` is the hash of a subtree rooted at depth `d + 1`.
        if *sib != empty[d + 1] {
            present[d / 8] |= 1u8 << (7 - d % 8);
            nodes.push(*sib);
        }
    }
    Some(CompressedProof {
        key: proof.key.clone(),
        value: proof.value.clone(),
        present,
        nodes,
    })
}

/// Expand a [`CompressedProof`] back into a full [`Proof`].
///
/// Returns `None` if the bitmap's popcount does not match `nodes.len()` — i.e. the
/// witness is internally inconsistent. That check is what stops a truncated or padded
/// `nodes` vector from silently expanding into a *different but well-formed* proof:
/// without it, a short `nodes` list would shift every later sibling up a level and
/// yield a proof that fails [`verify`] for a confusing reason instead of being
/// refused here for the real one.
pub fn expand(c: &CompressedProof) -> Option<Proof> {
    let empty = empty_hashes();
    let popcount: usize = c.present.iter().map(|b| b.count_ones() as usize).sum();
    if popcount != c.nodes.len() {
        return None;
    }
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    let mut next = 0usize;
    for d in 0..TREE_DEPTH {
        let set = (c.present[d / 8] >> (7 - d % 8)) & 1 == 1;
        if set {
            siblings.push(c.nodes[next]);
            next += 1;
        } else {
            siblings.push(empty[d + 1]);
        }
    }
    Some(Proof {
        key: c.key.clone(),
        value: c.value.clone(),
        siblings,
    })
}

/// Verify a compressed proof against `root`: expand, then run the *unchanged*
/// [`verify`]. Deliberately not a second folding implementation — a second copy of
/// the fold is a second place for the two to drift, and the existing one is the
/// pinned, byte-tested path.
pub fn verify_compressed(root: &Hash, c: &CompressedProof) -> bool {
    match expand(c) {
        Some(p) => verify(root, &p),
        None => false,
    }
}

/// Move a root into a VM value, so a datum can carry it and a validator can compare
/// it against a `ctx` field with the existing `Op::Eq` / `Op::Verify` opcodes.
pub fn root_as_val(root: &Hash) -> Val {
    Val::Bytes(root.to_vec())
}

/// Read a root back out of a VM value; `None` if it is not exactly 32 bytes.
pub fn val_as_root(v: &Val) -> Option<Hash> {
    match v {
        Val::Bytes(b) => b.as_slice().try_into().ok(),
        Val::Int(_) => None,
    }
}

// ── (a) Registry: key -> value, add/update yields a new root ─────────────────────

/// A registry: an arbitrary `key -> value` byte map committed to a single root.
/// `set`/`remove` return the new root so a contract's datum can advance in lockstep.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    tree: SparseMerkleTree,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add or update `key -> value`; returns the new root.
    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Hash {
        self.tree.insert(key, value);
        self.tree.root()
    }
    /// Remove `key`; returns the new root.
    pub fn remove(&mut self, key: &[u8]) -> Hash {
        self.tree.remove(key);
        self.tree.root()
    }
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.tree.get(key)
    }
    pub fn len(&self) -> usize {
        self.tree.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
    pub fn root(&self) -> Hash {
        self.tree.root()
    }
    pub fn prove(&self, key: &[u8]) -> Proof {
        self.tree.prove(key)
    }
}

/// Errors from the bounded / arithmetic state structures. Everything that could
/// overflow a count uses checked arithmetic and surfaces here rather than wrapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateError {
    /// Inserting a new holder would exceed `max`.
    HolderLimitExceeded { max: u64, attempted: u64 },
    /// A count or sum overflowed its integer type.
    CountOverflow,
}

// ── (b) HolderSet: a deterministic max_holders bound ─────────────────────────────

/// A holder-set with a hard, deterministic **`max_holders`** cap — the classic
/// security-token constraint (e.g. a jurisdiction's investor limit). Stores
/// `holder_id -> balance`; the cap is enforced with checked arithmetic on *new*
/// insertions only (updating an existing holder never trips it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderSet {
    tree: SparseMerkleTree,
    max_holders: u64,
}

impl HolderSet {
    /// A new holder-set that will admit at most `max_holders` distinct holders.
    pub fn new(max_holders: u64) -> Self {
        Self {
            tree: SparseMerkleTree::new(),
            max_holders,
        }
    }

    /// Set `holder`'s balance. New holders count against `max_holders`; if admitting
    /// one would exceed the cap, returns `HolderLimitExceeded` and the set is left
    /// unchanged. Returns the new root on success.
    pub fn set_balance(&mut self, holder: &[u8], balance: u64) -> Result<Hash, StateError> {
        if !self.tree.contains(holder) {
            let current = self.tree.len() as u64;
            let attempted = current.checked_add(1).ok_or(StateError::CountOverflow)?;
            if attempted > self.max_holders {
                return Err(StateError::HolderLimitExceeded {
                    max: self.max_holders,
                    attempted,
                });
            }
        }
        self.tree.insert(holder, &balance.to_le_bytes());
        Ok(self.tree.root())
    }

    /// Remove `holder` (freeing a slot); returns the new root.
    pub fn remove(&mut self, holder: &[u8]) -> Hash {
        self.tree.remove(holder);
        self.tree.root()
    }

    /// `holder`'s balance, if present.
    pub fn balance_of(&self, holder: &[u8]) -> Option<u64> {
        self.tree.get(holder).and_then(|b| decode_u64(b))
    }

    /// Whether `holder` is in the set.
    pub fn contains(&self, holder: &[u8]) -> bool {
        self.tree.contains(holder)
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
    pub fn max_holders(&self) -> u64 {
        self.max_holders
    }
    pub fn root(&self) -> Hash {
        self.tree.root()
    }
    pub fn prove(&self, holder: &[u8]) -> Proof {
        self.tree.prove(holder)
    }
}

/// Decode a little-endian `u64` balance leaf; `None` unless exactly 8 bytes.
pub fn decode_u64(b: &[u8]) -> Option<u64> {
    b.try_into().ok().map(u64::from_le_bytes)
}

// ── (c) Snapshot: freeze balances for dividend math ──────────────────────────────

/// An immutable **snapshot** of balances frozen at a point in time — the basis for a
/// dividend / airdrop distribution. Its root commits to the exact balance set, so a
/// distribution contract can prove each holder's share against a fixed commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    tree: SparseMerkleTree,
    total: u128,
}

impl Snapshot {
    /// Freeze a balance map. `total` (the supply denominator for pro-rata math) is a
    /// checked sum of all balances; overflow surfaces as `CountOverflow`.
    pub fn freeze(balances: &BTreeMap<Vec<u8>, u64>) -> Result<Self, StateError> {
        let mut tree = SparseMerkleTree::new();
        let mut total: u128 = 0;
        for (holder, bal) in balances {
            total = total
                .checked_add(*bal as u128)
                .ok_or(StateError::CountOverflow)?;
            tree.insert(holder, &bal.to_le_bytes());
        }
        Ok(Self { tree, total })
    }

    /// The frozen total supply (the pro-rata denominator).
    pub fn total_supply(&self) -> u128 {
        self.total
    }

    /// `holder`'s frozen balance, if present.
    pub fn balance_of(&self, holder: &[u8]) -> Option<u64> {
        self.tree.get(holder).and_then(|b| decode_u64(b))
    }

    /// The pro-rata dividend for `holder` from a `pool`: `floor(balance * pool /
    /// total)`. Deterministic floor division, checked multiply. `None` if the holder
    /// is absent or the total is zero. (Any floor remainder — "dust" — is left to the
    /// caller's rounding policy; this returns only the exact per-holder floor.)
    pub fn dividend_share(&self, holder: &[u8], pool: u128) -> Option<u128> {
        if self.total == 0 {
            return None;
        }
        let bal = self.balance_of(holder)? as u128;
        let numerator = bal.checked_mul(pool)?;
        Some(numerator / self.total)
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }
    pub fn prove(&self, holder: &[u8]) -> Proof {
        self.tree.prove(holder)
    }
    pub fn len(&self) -> usize {
        self.tree.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
}

// ── (d) AllowList / DenyList: a membership gate ──────────────────────────────────

/// A membership set (members carry an empty value). Backs both an allow-list and a
/// deny-list — the difference is only how [`gate_allows`] reads a proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MembershipList {
    tree: SparseMerkleTree,
}

impl MembershipList {
    pub fn new() -> Self {
        Self::default()
    }
    /// Add `id` to the set; returns the new root.
    pub fn add(&mut self, id: &[u8]) -> Hash {
        self.tree.insert(id, &[]);
        self.tree.root()
    }
    /// Remove `id`; returns the new root.
    pub fn remove(&mut self, id: &[u8]) -> Hash {
        self.tree.remove(id);
        self.tree.root()
    }
    pub fn contains(&self, id: &[u8]) -> bool {
        self.tree.contains(id)
    }
    pub fn len(&self) -> usize {
        self.tree.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
    pub fn root(&self) -> Hash {
        self.tree.root()
    }
    pub fn prove(&self, id: &[u8]) -> Proof {
        self.tree.prove(id)
    }
}

/// Which way a membership list gates: an allow-list permits *members*; a deny-list
/// permits *non-members*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Allow,
    Deny,
}

/// Decide whether `proof` (against `root`) grants passage under `gate`. The proof
/// must *both* verify against the committed root *and* carry the right membership
/// polarity — so neither a forged proof nor a valid-but-wrong-polarity proof passes.
///
/// - `Allow`: pass iff a **valid membership** proof (the id is on the allow-list).
/// - `Deny`:  pass iff a **valid non-membership** proof (the id is not deny-listed).
pub fn gate_allows(gate: Gate, root: &Hash, proof: &Proof) -> bool {
    if !verify(root, proof) {
        return false;
    }
    match gate {
        Gate::Allow => proof.is_membership(),
        Gate::Deny => !proof.is_membership(),
    }
}

/// Why an identity-bound gate refused. Distinguishing the reasons matters: a
/// `KeyMismatch` is an *attack signature* (someone relayed a proof that is not
/// about them), while `ProofInvalid` / `WrongPolarity` are ordinary failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    /// The proof does not verify against the committed root at all.
    ProofInvalid,
    /// The proof verifies and is about the right identity, but has the wrong
    /// membership polarity for this gate (allow-listed check on a non-member, or a
    /// deny-listed party proving membership).
    WrongPolarity,
    /// **The bypass this API exists to close.** The proof is valid but its `key` is
    /// not the identity the caller authenticated — i.e. a relayed/borrowed proof.
    KeyMismatch,
}

/// **Identity-bound gating — the fix for the relay/fabrication bypass.**
///
/// [`gate_allows`] answers only "is this proof internally consistent with the root,
/// with the right polarity". It never binds `proof.key` to *who is transacting*, and
/// two integration tests pin the consequences as working attacks:
/// `tests/audit_stateproof.rs::allow_gate_kyc_bypass_by_relaying_a_members_proof`
/// (a non-member replays a member's public proof and passes a KYC allow-gate) and
/// `::deny_gate_is_bypassable_with_a_made_up_identity` (a sanctioned party proves
/// non-membership of a key it invented on the spot, and the sanctions list is inert).
///
/// Both attacks have the same shape: the proof is about SOMEONE ELSE'S key, or about
/// no one's. This function closes both by requiring the caller to pass the identity
/// it **already authenticated by other means** (`authenticated_id`) and refusing
/// unless `proof.key` is exactly that identity. The key check is done FIRST, before
/// the cryptographic verification, so a relayed proof is rejected as `KeyMismatch`
/// rather than being reported as a polarity problem — the caller can log the
/// difference.
///
/// ## What "authenticated" must mean (the caller's obligation, unchanged)
/// This function cannot authenticate anyone; it has no signature, no key, no host.
/// `authenticated_id` MUST be an identity the caller established itself — in a
/// validator program that is the redeemer pubkey that just passed [`crate::Op::VerifySig`]
/// (the VM's host callback [`crate::SigVerifier`], lib.rs), not a self-declared field
/// from the spender. Passing an attacker-supplied `authenticated_id` reintroduces the
/// bypass one level up; there is no way for this crate to prevent that, which is
/// exactly why the binding is an explicit parameter instead of a hidden default.
///
/// [`gate_allows`] is deliberately left in place and unchanged: it is the correct
/// primitive when the identity binding genuinely happens elsewhere, downstream
/// consumers exist, and the two bypass tests must keep passing as documentation of
/// what the unbound API does and does not promise.
pub fn gate_allows_bound(
    gate: Gate,
    root: &Hash,
    proof: &Proof,
    authenticated_id: &[u8],
) -> Result<(), GateError> {
    // Identity binding FIRST. Constant-time comparison is not required: `proof.key`
    // and `authenticated_id` are both public data (an id on a public list and an id
    // the caller already authenticated), so there is no secret to leak by timing.
    if proof.key.as_slice() != authenticated_id {
        return Err(GateError::KeyMismatch);
    }
    if !verify(root, proof) {
        return Err(GateError::ProofInvalid);
    }
    let polarity_ok = match gate {
        Gate::Allow => proof.is_membership(),
        Gate::Deny => !proof.is_membership(),
    };
    if polarity_ok {
        Ok(())
    } else {
        Err(GateError::WrongPolarity)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run, Ctx, Op, SigVerifier};

    /// A no-op verifier — none of the state tests exercise signatures.
    struct NoSig;
    impl SigVerifier for NoSig {
        fn verify(&self, _m: &[u8], _p: &[u8], _s: &[u8]) -> bool {
            false
        }
    }

    // ── SMT core: empty root, membership, non-membership ──

    #[test]
    fn empty_tree_root_is_empty_ladder() {
        let t = SparseMerkleTree::new();
        assert_eq!(t.root(), empty_hashes()[0]);
        // A non-membership proof for any key verifies against the empty root.
        let p = t.prove(b"nobody");
        assert!(!p.is_membership());
        assert!(verify(&t.root(), &p));
    }

    #[test]
    fn membership_and_nonmembership_verify() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        t.insert(b"bob", b"200");
        let root = t.root();

        // membership: alice -> 100 proves against the root
        let pa = t.prove(b"alice");
        assert!(pa.is_membership());
        assert_eq!(pa.value.as_deref(), Some(&b"100"[..]));
        assert!(verify(&root, &pa));

        // non-membership: carol is absent, its slot is empty
        let pc = t.prove(b"carol");
        assert!(!pc.is_membership());
        assert!(verify(&root, &pc));
    }

    // ── determinism: same map, any insertion order ⇒ identical root ──

    #[test]
    fn determinism_insertion_order_independent() {
        let mut a = SparseMerkleTree::new();
        for (k, v) in [
            (&b"k1"[..], &b"v1"[..]),
            (b"k2", b"v2"),
            (b"k3", b"v3"),
            (b"k4", b"v4"),
        ] {
            a.insert(k, v);
        }
        // reverse order + an insert-then-overwrite detour → same final map
        let mut b = SparseMerkleTree::new();
        b.insert(b"k4", b"v4");
        b.insert(b"k2", b"WRONG");
        b.insert(b"k3", b"v3");
        b.insert(b"k1", b"v1");
        b.insert(b"k2", b"v2"); // corrected
        assert_eq!(a.root(), b.root());

        // recomputing is stable
        assert_eq!(a.root(), a.root());
    }

    #[test]
    fn different_value_changes_root() {
        let mut a = SparseMerkleTree::new();
        a.insert(b"k", b"v");
        let mut b = a.clone();
        b.insert(b"k", b"w");
        assert_ne!(a.root(), b.root());
    }

    // ── proof soundness: tampered leaf / path / polarity all fail ──

    #[test]
    fn tampered_value_fails() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        t.insert(b"bob", b"200");
        let root = t.root();
        let mut p = t.prove(b"alice");
        assert!(verify(&root, &p));
        p.value = Some(b"999".to_vec()); // forge a bigger balance
        assert!(!verify(&root, &p));
    }

    #[test]
    fn tampered_sibling_fails() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        t.insert(b"bob", b"200");
        let root = t.root();
        let mut p = t.prove(b"bob");
        assert!(verify(&root, &p));
        p.siblings[TREE_DEPTH - 1][0] ^= 0xff; // flip a sibling near the leaf
        assert!(!verify(&root, &p));
    }

    #[test]
    fn forged_membership_of_absent_key_fails() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        let root = t.root();
        // take carol's (valid, non-membership) proof and claim it's a membership
        let mut p = t.prove(b"carol");
        assert!(verify(&root, &p));
        p.value = Some(b"1".to_vec());
        assert!(!verify(&root, &p)); // cannot fabricate membership from a root
    }

    #[test]
    fn wrong_length_proof_rejected() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"1");
        let root = t.root();
        let mut p = t.prove(b"alice");
        p.siblings.truncate(TREE_DEPTH - 1);
        assert!(!verify(&root, &p));
    }

    // ── (a) Registry ──

    #[test]
    fn registry_add_update_new_root() {
        let mut r = Registry::new();
        let r0 = r.root();
        let r1 = r.set(b"symbol", b"USTAV");
        assert_ne!(r0, r1);
        let r2 = r.set(b"decimals", b"6");
        assert_ne!(r1, r2);
        // update an existing key → yet another root
        let r3 = r.set(b"symbol", b"USTV");
        assert_ne!(r2, r3);
        assert_eq!(r.get(b"symbol").map(|v| v.as_slice()), Some(&b"USTV"[..]));
        // membership proof against the live root
        assert!(verify(&r.root(), &r.prove(b"decimals")));
        // removing yields a fresh root and a non-membership proof
        let r4 = r.remove(b"decimals");
        assert_ne!(r3, r4);
        let p = r.prove(b"decimals");
        assert!(!p.is_membership());
        assert!(verify(&r.root(), &p));
    }

    // ── (b) HolderSet: deterministic max_holders bound ──

    #[test]
    fn holderset_enforces_max_holders() {
        let mut hs = HolderSet::new(2);
        assert!(hs.set_balance(b"h1", 10).is_ok());
        assert!(hs.set_balance(b"h2", 20).is_ok());
        // third distinct holder is rejected — deterministically
        assert_eq!(
            hs.set_balance(b"h3", 30),
            Err(StateError::HolderLimitExceeded {
                max: 2,
                attempted: 3
            })
        );
        // the set is unchanged after the rejected insert
        assert_eq!(hs.len(), 2);
        assert!(!hs.contains(b"h3"));
        // updating an EXISTING holder never trips the cap
        assert!(hs.set_balance(b"h1", 99).is_ok());
        assert_eq!(hs.balance_of(b"h1"), Some(99));
        // freeing a slot lets a new holder in
        hs.remove(b"h2");
        assert!(hs.set_balance(b"h3", 30).is_ok());
        assert_eq!(hs.len(), 2);
    }

    // ── (c) Snapshot + dividend math ──

    #[test]
    fn snapshot_dividends_are_pro_rata_floor() {
        let mut balances = BTreeMap::new();
        balances.insert(b"a".to_vec(), 100u64);
        balances.insert(b"b".to_vec(), 300u64);
        balances.insert(b"c".to_vec(), 600u64); // total = 1000
        let snap = Snapshot::freeze(&balances).unwrap();
        assert_eq!(snap.total_supply(), 1000);

        // pool of 1_000_000 → shares 100k / 300k / 600k
        assert_eq!(snap.dividend_share(b"a", 1_000_000), Some(100_000));
        assert_eq!(snap.dividend_share(b"b", 1_000_000), Some(300_000));
        assert_eq!(snap.dividend_share(b"c", 1_000_000), Some(600_000));

        // floor division: pool 999 → a gets floor(100*999/1000)=99
        assert_eq!(snap.dividend_share(b"a", 999), Some(99));

        // absent holder → None; the snapshot root is a stable commitment
        assert_eq!(snap.dividend_share(b"z", 1000), None);
        assert!(verify(&snap.root(), &snap.prove(b"a")));
        assert!(!snap.prove(b"z").is_membership());
    }

    #[test]
    fn snapshot_is_frozen_independent_of_later_state() {
        let mut balances = BTreeMap::new();
        balances.insert(b"a".to_vec(), 100u64);
        balances.insert(b"b".to_vec(), 100u64);
        let snap = Snapshot::freeze(&balances).unwrap();
        let root_before = snap.root();
        // The snapshot owns its data; nothing external can mutate it.
        balances.insert(b"a".to_vec(), 999);
        assert_eq!(snap.root(), root_before);
        assert_eq!(snap.balance_of(b"a"), Some(100));
    }

    // ── (d) AllowList / DenyList gate ──

    #[test]
    fn allowlist_gate() {
        let mut allow = MembershipList::new();
        allow.add(b"kyc:alice");
        allow.add(b"kyc:bob");
        let root = allow.root();

        // member passes an allow-gate
        assert!(gate_allows(Gate::Allow, &root, &allow.prove(b"kyc:alice")));
        // non-member fails an allow-gate (valid non-membership proof, wrong polarity)
        let pmallory = allow.prove(b"kyc:mallory");
        assert!(verify(&root, &pmallory));
        assert!(!gate_allows(Gate::Allow, &root, &pmallory));
    }

    #[test]
    fn denylist_gate() {
        let mut deny = MembershipList::new();
        deny.add(b"sanctioned:x");
        let root = deny.root();

        // a clean id passes a deny-gate (proven NOT on the list)
        assert!(gate_allows(Gate::Deny, &root, &deny.prove(b"clean:y")));
        // a listed id fails a deny-gate
        assert!(!gate_allows(Gate::Deny, &root, &deny.prove(b"sanctioned:x")));
    }

    #[test]
    fn gate_rejects_proof_from_wrong_root() {
        let mut a = MembershipList::new();
        a.add(b"id1");
        let mut b = MembershipList::new();
        b.add(b"id1");
        b.add(b"id2");
        // a proof built from b does not pass against a's root
        let p = b.prove(b"id2");
        assert!(!gate_allows(Gate::Allow, &a.root(), &p));
    }

    // ── the payoff: a root lives in Val::Bytes and a validator asserts it ──

    #[test]
    fn root_fits_in_val_and_validator_asserts_it() {
        let mut reg = Registry::new();
        reg.set(b"symbol", b"USTAV");
        let root = reg.root();

        // round-trip through Val::Bytes
        let v = root_as_val(&root);
        assert_eq!(val_as_root(&v), Some(root));

        // A validator program: assert that ctx.fields[0] (the committed root the tx
        // presents) equals the datum root the contract carries. datum is seeded as the
        // bottom of the stack by run(); the tx supplies the "current" root via ctx.
        let program = vec![Op::CtxField(0), Op::Eq];
        let ctx = Ctx {
            fields: vec![root_as_val(&root)],
            ..Default::default()
        };
        let noop = NoSig;
        let mut gas = 1000;
        // datum == committed root → validator returns true
        assert_eq!(
            run(&program, vec![root_as_val(&root)], &ctx, &noop, &mut gas),
            Ok(true)
        );

        // a stale/forged root in the datum → validator returns false
        let mut wrong = root;
        wrong[0] ^= 0x01;
        let mut gas2 = 1000;
        assert_eq!(
            run(
                &program,
                vec![root_as_val(&wrong)],
                &ctx,
                &noop,
                &mut gas2
            ),
            Ok(false)
        );
    }

    #[test]
    fn val_as_root_rejects_non_32_bytes() {
        assert_eq!(val_as_root(&Val::Bytes(vec![0u8; 31])), None);
        assert_eq!(val_as_root(&Val::Int(5)), None);
        assert_eq!(val_as_root(&Val::Bytes(vec![7u8; 32])), Some([7u8; 32]));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ADVERSARIAL + PROPERTY TESTS (appended by an independent reviewer pass).
    // Existing tests and module logic above are unchanged.
    // ═══════════════════════════════════════════════════════════════════════════

    // ── determinism: same input ⇒ same output ──

    #[test]
    fn prove_is_deterministic_across_repeated_calls_and_build_order() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        t.insert(b"bob", b"200");
        t.insert(b"carol", b"300");
        let p1 = t.prove(b"bob");
        let p2 = t.prove(b"bob");
        assert_eq!(p1, p2);

        // an independently-built tree with the same entries (different insertion
        // order) produces a byte-for-byte identical proof, not just an identical root
        let mut u = SparseMerkleTree::new();
        u.insert(b"carol", b"300");
        u.insert(b"alice", b"100");
        u.insert(b"bob", b"200");
        assert_eq!(t.prove(b"bob"), u.prove(b"bob"));
    }

    #[test]
    fn verify_is_a_pure_function_of_its_inputs() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"x", b"1");
        let root = t.root();
        let p = t.prove(b"x");
        for _ in 0..5 {
            assert!(verify(&root, &p));
        }
    }

    #[test]
    fn verify_gas_matches_its_own_formula_and_is_stable() {
        assert_eq!(verify_gas(), SHAKE256_GAS * (TREE_DEPTH as u64 + 2));
        assert_eq!(verify_gas(), 15_480);
        assert_eq!(verify_gas(), verify_gas()); // const fn: no hidden state, ever
    }

    #[test]
    fn shake256_gas_tracks_the_vm_s_own_gas_schedule() {
        // `SHAKE256_GAS` exists so an integrator can price proof verification on the
        // same schedule as the real VM. Pin it against the VM's actual, private
        // `gas_cost` — reachable here because `state` is a child module of the crate
        // root that defines it — so schedule drift in lib.rs breaks this test instead
        // of silently mispricing every `verify_gas()` estimate.
        assert_eq!(SHAKE256_GAS, crate::gas_cost(&crate::Op::Shake256));
    }

    // ── adversarial: proof tampering beyond the two cases already covered ──

    #[test]
    fn tampered_root_level_sibling_fails() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        t.insert(b"bob", b"200");
        let root = t.root();
        let mut p = t.prove(b"alice");
        assert!(verify(&root, &p));
        p.siblings[0][0] ^= 0xff; // the sibling closest to the root, not the leaf
        assert!(!verify(&root, &p));
    }

    #[test]
    fn membership_proof_cannot_be_downgraded_to_nonmembership() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        let root = t.root();
        let mut p = t.prove(b"alice");
        assert!(p.is_membership());
        p.value = None; // claim alice's slot is empty
        assert!(!verify(&root, &p));
    }

    #[test]
    fn nonmembership_proof_cannot_be_repointed_to_an_actual_member() {
        // The security-critical direction of a key-repointing attack: take a
        // genuine non-membership proof (for an absent key) and retarget its `key`
        // field to a key that IS actually present, keeping the same siblings and
        // `value: None`. This must NOT verify — otherwise a relayed proof could
        // falsely certify a real member as absent.
        //
        // (The converse — repointing to a *different but still absent* key — is
        // NOT guaranteed to fail: with few populated leaves, many distinct absent
        // keys that first diverge from the same real leaf at the same bit-depth
        // share byte-identical non-membership witnesses, which is expected/sound
        // SMT behaviour, not a soundness gap, since every such key genuinely is
        // absent.)
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        t.insert(b"bob", b"200");
        let root = t.root();
        let mut p = t.prove(b"nobody"); // absent
        assert!(verify(&root, &p));
        p.key = b"alice".to_vec(); // alice is a real member
        assert!(!verify(&root, &p));
    }

    #[test]
    fn proof_with_too_many_siblings_is_rejected() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"1");
        let root = t.root();
        let mut p = t.prove(b"alice");
        p.siblings.push(EMPTY_LEAF); // one too many
        assert!(!verify(&root, &p));
    }

    #[test]
    fn empty_proof_siblings_is_rejected() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"1");
        let root = t.root();
        let p = Proof {
            key: b"alice".to_vec(),
            value: Some(b"1".to_vec()),
            siblings: vec![],
        };
        assert!(!verify(&root, &p));
    }

    // ── fail-closed / no-panic on edge-case input ──

    #[test]
    fn empty_key_and_empty_value_round_trip_without_panicking() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"", b"");
        t.insert(b"nonempty", b"v");
        let root = t.root();
        assert!(t.contains(b""));
        let p = t.prove(b"");
        assert!(p.is_membership());
        assert_eq!(p.value.as_deref(), Some(&b""[..]));
        assert!(verify(&root, &p));
    }

    #[test]
    fn large_value_does_not_panic_and_still_verifies() {
        let mut t = SparseMerkleTree::new();
        let big = vec![0xabu8; 10_000];
        t.insert(b"whale", &big);
        let root = t.root();
        let p = t.prove(b"whale");
        assert_eq!(p.value.as_deref(), Some(&big[..]));
        assert!(verify(&root, &p));
    }

    #[test]
    fn removing_an_absent_key_is_a_deterministic_no_op() {
        let mut t = SparseMerkleTree::new();
        t.insert(b"alice", b"100");
        let root_before = t.root();
        assert_eq!(t.remove(b"never-was-here"), None);
        assert_eq!(t.root(), root_before);

        let mut reg = Registry::new();
        reg.set(b"k", b"v");
        let r0 = reg.root();
        assert_eq!(reg.remove(b"absent"), r0);
    }

    #[test]
    fn decode_u64_rejects_wrong_length_and_round_trips_exact_length() {
        assert_eq!(decode_u64(&[]), None);
        assert_eq!(decode_u64(&[1, 2, 3]), None);
        assert_eq!(decode_u64(&[0u8; 9]), None);
        assert_eq!(decode_u64(&42u64.to_le_bytes()), Some(42));
    }

    #[test]
    fn val_as_root_rejects_boundary_lengths() {
        assert_eq!(val_as_root(&Val::Bytes(vec![])), None);
        assert_eq!(val_as_root(&Val::Bytes(vec![0u8; 1])), None);
        assert_eq!(val_as_root(&Val::Bytes(vec![0u8; 33])), None);
        assert_eq!(val_as_root(&Val::Bytes(vec![0u8; 64])), None);
    }

    // ── (b) HolderSet: bound invariant under a scripted sequence, plus a zero cap ──

    #[test]
    fn holderset_len_never_exceeds_max_holders_across_a_scripted_sequence() {
        let mut hs = HolderSet::new(3);
        let ops: &[(&[u8], u64)] = &[
            (b"h1", 10),
            (b"h2", 20),
            (b"h3", 30),
            (b"h4", 40), // must be rejected: would be a 4th holder over a cap of 3
            (b"h1", 11),
            (b"h2", 21),
        ];
        for (id, bal) in ops {
            let _ = hs.set_balance(id, *bal); // Ok or Err, either way the invariant holds
            assert!(hs.len() as u64 <= hs.max_holders());
        }
        assert_eq!(hs.len(), 3);
        assert!(!hs.contains(b"h4"));

        // freeing a slot and refilling it re-checks the invariant at every step
        hs.remove(b"h3");
        assert!(hs.len() as u64 <= hs.max_holders());
        assert!(hs.set_balance(b"h4", 40).is_ok());
        assert_eq!(hs.len(), 3);
    }

    #[test]
    fn holderset_zero_cap_rejects_every_new_holder_but_never_panics() {
        let mut hs = HolderSet::new(0);
        assert_eq!(
            hs.set_balance(b"h1", 1),
            Err(StateError::HolderLimitExceeded {
                max: 0,
                attempted: 1
            })
        );
        assert!(hs.is_empty());
        assert_eq!(hs.root(), empty_hashes()[0]);
    }

    // ── (c) Snapshot: value conservation of the dividend split, and the empty case ──

    #[test]
    fn snapshot_dividend_shares_never_exceed_the_pool_dust_bounded_by_holder_count() {
        let mut balances = BTreeMap::new();
        balances.insert(b"a".to_vec(), 7u64);
        balances.insert(b"b".to_vec(), 11u64);
        balances.insert(b"c".to_vec(), 13u64); // total = 31: does not divide evenly
        let snap = Snapshot::freeze(&balances).unwrap();
        let pool: u128 = 1_000_003;
        let sum: u128 = balances
            .keys()
            .map(|h| snap.dividend_share(h, pool).unwrap())
            .sum();
        assert!(sum <= pool); // never over-distribute the pool
        assert!(pool - sum < balances.len() as u128); // floor rounding loses < 1/holder
    }

    #[test]
    fn snapshot_of_empty_map_has_zero_total_and_does_not_panic() {
        let snap = Snapshot::freeze(&BTreeMap::new()).unwrap();
        assert_eq!(snap.total_supply(), 0);
        assert_eq!(snap.root(), empty_hashes()[0]);
        assert_eq!(snap.dividend_share(b"anyone", 100), None); // total==0 guard
    }

    // ── (d) gate_allows: pins an integration hazard worth flagging explicitly ──

    #[test]
    fn gate_allows_does_not_bind_the_proof_s_key_to_a_caller_s_claimed_identity() {
        // `verify`/`gate_allows` only check that a proof is internally consistent
        // with the root — NOT that `proof.key` equals whatever identity the
        // integrator meant to authorize. So relaying *any* valid member's proof
        // satisfies an `Allow` gate, regardless of who is actually transacting.
        // This pins the current (documented) contract as a deliberate flag: an
        // integrator wiring this into a validator MUST separately assert
        // `proof.key == expected_id` (e.g. the signer/redeemer's id) — gate_allows
        // alone does not perform that binding.
        let mut allow = MembershipList::new();
        allow.add(b"alice");
        let root = allow.root();
        let alices_proof = allow.prove(b"alice");

        // "bob" relays alice's proof and the gate alone cannot tell the difference
        assert!(gate_allows(Gate::Allow, &root, &alices_proof));

        // the only defense is the integrator explicitly checking the identity:
        let claimed_caller: &[u8] = b"bob";
        assert_ne!(alices_proof.key, claimed_caller);
    }
}
