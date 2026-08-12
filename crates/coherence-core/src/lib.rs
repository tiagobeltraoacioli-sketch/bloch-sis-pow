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
