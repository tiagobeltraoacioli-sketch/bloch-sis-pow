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
    /// **OPEN ITEM — no scheme, no sighash domain.** This field predates the
    /// value bridge and has never had a defined signer, key, or message. In
    /// Sapling the binding signature exists because balance lives in
    /// homomorphic Pedersen value commitments; here commitments are SHAKE-256
    /// hashes with no homomorphism, so that role is impossible — balance is
    /// enforced *inside* the proved statement instead. The transplant-binding
    /// role (a proof must not be movable onto a different transaction) is
    /// filled for the bridge by committing a transaction digest into the
    /// public inputs (see [`UnshieldPublic::transparent_digest`]). What
    /// remains undecided for THIS field: define an envelope-malleability
    /// signature (scheme + sighash domain) or delete the field at wire
    /// freeze. Until that decision, verifiers MUST ignore it and producers
    /// MUST leave it empty.
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

// ═════════════════════════════════════════════════════════════════════════════
// Value bridge (F10): shield / unshield — transparent ↔ shielded
// ═════════════════════════════════════════════════════════════════════════════
//
// C1 froze a HERMETIC pool: `check_spend` enforces Σin = Σout + fee over notes
// only, so value could neither enter the pool nor leave it beyond the public
// fee (finding F10 of `BLOCH-COHERENCE-UNDER-POS.md`). The types below are the
// doors: `ShieldTx` (transparent → shielded) and `UnshieldTx` (shielded →
// transparent). `check_spend` itself is untouched — it is the C1-frozen
// statement and the pinned SP1 guest proves exactly it.
//
// ── WIRE FORMAT: **NOT FROZEN** ──────────────────────────────────────────────
// The measured proof does not fit the block
// (`docs/audit/COHERENCE-PROOF-SIZE-2026-08-29.md`: core 2.66 MiB, compressed
// 1.21 MiB, vs `MAX_BLOCK_TX_BYTES_V2` = 512 KiB). Whether the block cap rises
// or the proof moves off-body (data availability) is an OPEN architecture
// decision. Consequences drawn here:
//   * proof carriage sits behind [`ProofCarrier`] + [`ProofFetch`] — both
//     outcomes fit without touching statements or transaction logic;
//   * the serde derives on these types are plumbing for tests and prototypes
//     ONLY. No canonical byte layout is defined and nothing here is a
//     C1-ratified encoding. Do not pin hashes of these encodings.
//
// ── TAINT IS DEAD ────────────────────────────────────────────────────────────
// §3.2 rule 2, §3.3 and §3.5 of `BLOCH-COHERENCE-UNDER-POS.md` (the taint gate
// on shielding and its activation ordering) are orphaned: the Genesis-4 taint
// set dissolved (see `bloch-pos-committee/src/tokenomics_v4.rs` and
// `interfaces.rs` — "`Tainted` variants are never produced"). `ShieldTx`
// therefore carries NO taint rule. What survives is §3.4 — a stake deposit may
// spend only transparent inputs — and it is already enforced in
// `bloch-pos-committee::staking::validate_deposit`
// (`DepositReject::ShieldedInput`). Unshield outputs are ordinary fresh
// transparent outputs, born untainted, and therefore deposit-eligible; the
// positive test pinning that lives in
// `bloch-pos-committee/tests/committee.rs::unshield_output_funds_a_valid_deposit`.

/// Domain tag for proof-blob commitments ([`ProofCarrier::commitment`]).
const DOM_PROOF: &[u8] = b"bloch:coherence:proofcm:v1";
/// Domain tag for the unshield transparent-outputs digest.
const DOM_TOUT: &[u8] = b"bloch:coherence:unshield-touts:v1";

/// `SHAKE256(DOM_PROOF ‖ bytes)` — the consensus identity of a proof blob.
///
/// This is the indirection the open block-size decision hangs on: whatever a
/// transaction merkle-binds, gossips, or fetches, the 32-byte commitment is
/// the stable name of the proof in BOTH architecture outcomes.
pub fn proof_commitment(bytes: &[u8]) -> [u8; 32] {
    shake256_32(&[DOM_PROOF, bytes])
}

/// Where a transaction's proof bytes live. **The** indirection for the open
/// architecture decision:
///
/// * **Outcome A — the block cap rises**: producers use
///   [`ProofCarrier::Inline`]; [`ProofCarrier::resolve`] returns the bytes
///   with no fetch. Nothing else changes.
/// * **Outcome B — the proof leaves the block body** (data availability):
///   producers use [`ProofCarrier::Detached`]; the body carries only the
///   32-byte commitment + length, and validators resolve the bytes through a
///   [`ProofFetch`] implementation (mempool sidecar, DA layer, …). `resolve`
///   re-hashes what was fetched, so a fetch layer can never substitute a
///   different proof than the one the transaction committed to.
///
/// Statements, transaction logic, and the pool-value ratchet are identical in
/// both outcomes; only the `ProofFetch` implementation differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofCarrier {
    /// Proof travels in the transaction body.
    Inline(Vec<u8>),
    /// Proof lives off-body; the transaction carries its commitment and size.
    Detached { commitment: [u8; 32], len: u64 },
}

/// Supplies detached proof bytes by commitment. Implemented by the node
/// (mempool sidecar store, DA layer client); [`NoDetachedProofs`] is the
/// fail-closed default for contexts where only inline proofs are acceptable.
pub trait ProofFetch {
    fn fetch(&self, commitment: &[u8; 32]) -> Option<Vec<u8>>;
}

/// Resolves nothing: any [`ProofCarrier::Detached`] fails with `NotFound`.
pub struct NoDetachedProofs;

impl ProofFetch for NoDetachedProofs {
    fn fetch(&self, _commitment: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofUnavailable {
    /// The fetch layer has no bytes for this commitment. Fail-closed: a
    /// transaction whose proof cannot be resolved is unverifiable, not valid.
    NotFound { commitment: [u8; 32] },
    /// Fetched bytes have the wrong length for the declared blob.
    LengthMismatch { expected: u64, got: u64 },
    /// Fetched bytes hash to a different commitment — a substituted proof.
    CommitmentMismatch { expected: [u8; 32], got: [u8; 32] },
}

impl ProofCarrier {
    /// The consensus identity of the proof, independent of carriage.
    pub fn commitment(&self) -> [u8; 32] {
        match self {
            ProofCarrier::Inline(bytes) => proof_commitment(bytes),
            ProofCarrier::Detached { commitment, .. } => *commitment,
        }
    }

    /// Declared byte length (what fee/weight accounting charges for).
    pub fn len(&self) -> u64 {
        match self {
            ProofCarrier::Inline(bytes) => bytes.len() as u64,
            ProofCarrier::Detached { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Produce the actual proof bytes, verifying that what came back is the
    /// blob this transaction committed to.
    pub fn resolve(&self, fetch: &dyn ProofFetch) -> Result<Vec<u8>, ProofUnavailable> {
        match self {
            ProofCarrier::Inline(bytes) => Ok(bytes.clone()),
            ProofCarrier::Detached { commitment, len } => {
                let bytes = fetch
                    .fetch(commitment)
                    .ok_or(ProofUnavailable::NotFound { commitment: *commitment })?;
                if bytes.len() as u64 != *len {
                    return Err(ProofUnavailable::LengthMismatch {
                        expected: *len,
                        got: bytes.len() as u64,
                    });
                }
                let got = proof_commitment(&bytes);
                if got != *commitment {
                    return Err(ProofUnavailable::CommitmentMismatch {
                        expected: *commitment,
                        got,
                    });
                }
                Ok(bytes)
            }
        }
    }
}

// ── Bridge-facing transparent views ──────────────────────────────────────────

/// Note ciphertext, format owned by DEV-2 (ML-KEM-768 note encryption).
/// Opaque here on purpose: this crate binds *counts* (one ciphertext per
/// commitment, [`BridgeShapeError::CiphertextCountMismatch`]) and nothing
/// about the interior. Replace the interior with DEV-2's struct when that
/// lands; the newtype keeps every call site compiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCiphertext(pub Vec<u8>);

/// Minimal view of a spent transparent output (eUTXO outpoint). This crate
/// stays lean — the node resolves these against its ledger and performs the
/// full eUTXO validation (existence, hybrid signatures, transparent balance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentOutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// A fresh transparent output created by an unshield. `script_hash` follows
/// the Genesis-4 addressing (32-byte script hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentOutput {
    pub value_sat: u64,
    pub script_hash: [u8; 32],
}

/// `SHAKE256(DOM_TOUT ‖ count ‖ (value ‖ script_hash)*)` — the digest of the
/// transparent side of an unshield, committed into [`UnshieldPublic`] so the
/// proof is bound to *these* destinations. Without it, a valid unshield proof
/// could be replayed with the transparent outputs swapped to an attacker's
/// script — the classic proof-transplant. Length-prefixed and fixed-width, so
/// the encoding is injective.
pub fn transparent_outputs_digest(outputs: &[TransparentOutput]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(DOM_TOUT);
    h.update(&(outputs.len() as u64).to_le_bytes());
    for o in outputs {
        h.update(&o.value_sat.to_le_bytes());
        h.update(&o.script_hash);
    }
    let mut xof = h.finalize_xof();
    let mut out = [0u8; 32];
    xof.read(&mut out);
    out
}

// ── Shield statement (proved in ZK; strictly smaller than spend) ─────────────

/// Public inputs of the shield proof. No anchor and no nullifiers — a shield
/// spends no note, so its statement is strictly smaller than `check_spend`:
/// only "each committed note opens to some value and the values total exactly
/// the public `value_shielded`".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldPublic {
    /// Total value entering the pool, PUBLIC — as in any t→z design. How it
    /// splits into notes stays inside the proof.
    pub value_shielded: u64,
    pub out_commitments: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldWitness {
    pub outputs: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldError {
    /// public.out_commitments.len() != witness.outputs.len(). Same
    /// counterfeiting vector as the C2 bind on `check_spend`: an extra public
    /// commitment the balance never sees would mint an unbacked note.
    OutputCountMismatch { public: usize, witness: usize },
    OutputCommitment(usize),
    Overflow,
    Unbalanced { outputs: u128, value_shielded: u64 },
}

/// The EXACT statement the shield proof must attest (runs on the PRIVATE
/// witness): every public commitment opens to a witness note, and the note
/// values total exactly the public `value_shielded`. Backing invariant: the
/// pool's implicit balance grows by precisely what the transparent side paid
/// in.
pub fn check_shield(public: &ShieldPublic, w: &ShieldWitness) -> Result<(), ShieldError> {
    if public.out_commitments.len() != w.outputs.len() {
        return Err(ShieldError::OutputCountMismatch {
            public: public.out_commitments.len(),
            witness: w.outputs.len(),
        });
    }
    let mut out_sum: u128 = 0;
    for (i, out) in w.outputs.iter().enumerate() {
        if public.out_commitments.get(i) != Some(&out.commitment()) {
            return Err(ShieldError::OutputCommitment(i));
        }
        out_sum = out_sum.checked_add(out.v as u128).ok_or(ShieldError::Overflow)?;
    }
    if out_sum != public.value_shielded as u128 {
        return Err(ShieldError::Unbalanced { outputs: out_sum, value_shielded: public.value_shielded });
    }
    Ok(())
}

// ── Unshield statement (proved in ZK; `check_spend` + one public term) ───────

/// Public inputs of the unshield proof: exactly [`SpendPublic`] plus the
/// public `value_unshielded` and the binding digest of the transparent side.
///
/// **This is a revision of the frozen C1 spend statement**, not a reuse of
/// it: a new guest proves [`check_unshield`], which means a new ELF and a new
/// pinned verifying key alongside the spend one. `check_spend` and its pinned
/// guest are untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldPublic {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// Shielded change staying in the pool.
    pub change_commitments: Vec<[u8; 32]>,
    /// Total value leaving the pool, PUBLIC.
    pub value_unshielded: u64,
    /// Paid from the pool, like `SpendPublic::fee`.
    pub fee: u64,
    /// [`transparent_outputs_digest`] of the transaction's transparent
    /// outputs. Not recomputable from the witness — the statement simply
    /// commits it, and the VERIFIER recomputes it from the transaction
    /// ([`UnshieldTx::public`] builds it from the tx's own outputs, so the
    /// bind holds by construction). This term is what makes an unshield proof
    /// non-transplantable onto different destinations.
    pub transparent_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshieldWitness {
    pub inputs: Vec<SpendInput>,
    pub change_outputs: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnshieldError {
    Membership(usize),
    Nullifier(usize),
    /// The same nullifier appears twice among the public nullifiers — i.e.
    /// the same note is spent twice INSIDE one transaction, doubling
    /// `in_sum`. Application-level `NullifierSet::insert` would also catch
    /// it, but this is the statement where a soundness reviewer looks first,
    /// so the statement rejects it itself. (`check_spend` relies on the
    /// application layer for this case; flagged, not changed — it is frozen.)
    DuplicateNullifier(usize),
    ChangeCommitment(usize),
    NullifierCountMismatch { public: usize, witness: usize },
    ChangeCountMismatch { public: usize, witness: usize },
    Overflow,
    Unbalanced { inputs: u128, change: u128, value_unshielded: u64, fee: u64 },
}

/// The EXACT statement the unshield proof must attest: `check_spend`'s
/// membership/nullifier/opening checks over the pool side, with the balance
/// extended by one public term:
///
/// ```text
/// Σ inputs = Σ change + value_unshielded + fee
/// ```
///
/// This is the soundness-critical statement of the whole bridge: a break here
/// MINTS transparent supply and pierces the 100 B hard cap. The defense
/// outside the proof system is [`PoolValue`] — see its docs.
pub fn check_unshield(public: &UnshieldPublic, w: &UnshieldWitness) -> Result<(), UnshieldError> {
    if public.change_commitments.len() != w.change_outputs.len() {
        return Err(UnshieldError::ChangeCountMismatch {
            public: public.change_commitments.len(),
            witness: w.change_outputs.len(),
        });
    }
    if public.nullifiers.len() != w.inputs.len() {
        return Err(UnshieldError::NullifierCountMismatch {
            public: public.nullifiers.len(),
            witness: w.inputs.len(),
        });
    }
    let mut in_sum: u128 = 0;
    for (i, inp) in w.inputs.iter().enumerate() {
        let cm = inp.note.commitment();
        if !verify_path(&cm, inp.position, &inp.path, &public.anchor) {
            return Err(UnshieldError::Membership(i));
        }
        let nf = inp.note.nullifier(&inp.nk, inp.position);
        if public.nullifiers.get(i) != Some(&nf) {
            return Err(UnshieldError::Nullifier(i));
        }
        if public.nullifiers[..i].contains(&nf) {
            return Err(UnshieldError::DuplicateNullifier(i));
        }
        in_sum = in_sum.checked_add(inp.note.v as u128).ok_or(UnshieldError::Overflow)?;
    }
    let mut change_sum: u128 = 0;
    for (i, out) in w.change_outputs.iter().enumerate() {
        if public.change_commitments.get(i) != Some(&out.commitment()) {
            return Err(UnshieldError::ChangeCommitment(i));
        }
        change_sum = change_sum.checked_add(out.v as u128).ok_or(UnshieldError::Overflow)?;
    }
    // u64 + u64 fits u128; the change_sum add is the only one that can carry.
    let owed = change_sum
        .checked_add(public.value_unshielded as u128 + public.fee as u128)
        .ok_or(UnshieldError::Overflow)?;
    if in_sum != owed {
        return Err(UnshieldError::Unbalanced {
            inputs: in_sum,
            change: change_sum,
            value_unshielded: public.value_unshielded,
            fee: public.fee,
        });
    }
    Ok(())
}

// ── Bridge transaction types (wire format NOT frozen — see section header) ──

/// Structural validity of a bridge transaction — the cheap checks every node
/// runs before touching a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeShapeError {
    /// One ciphertext per commitment, or the recipient cannot ever decrypt
    /// the note — a burned note that still counts toward the pool.
    CiphertextCountMismatch { commitments: usize, ciphertexts: usize },
    /// A shield must spend at least one transparent input.
    NoTransparentInputs,
    /// An unshield must spend at least one note.
    NoNullifiers,
    /// An unshield must create at least one transparent output.
    NoTransparentOutputs,
    /// A zero-value bridge crossing is spam by construction.
    ZeroValue,
    /// Σ transparent output values must equal the public `value_unshielded`
    /// exactly — this equality is what welds the proved pool-side balance to
    /// the transparent ledger. It is a NODE-side check (the statement cannot
    /// see the transparent outputs; it sees only their digest).
    TransparentSumMismatch { outputs_sum: u128, value_unshielded: u64 },
}

/// `shield_tx` — transparent → shielded (spec §3.2, taint rule dropped).
///
/// Node-side validity (outside this crate):
/// 1. eUTXO: inputs exist, hybrid signatures verify, and
///    `Σ inputs = value_shielded + fee + transparent change`. The input
///    signatures MUST cover the entire transaction — `value_shielded`, the
///    commitment list, the ciphertexts and the proof commitment included —
///    which is why `ShieldTx` carries no `binding_sig`: the transparent
///    signer is the binder.
/// 2. [`ShieldTx::check_shape`].
/// 3. The proof (resolved via [`ProofCarrier::resolve`]) verifies
///    [`check_shield`] against [`ShieldTx::public`].
/// 4. State: append `outputs` to the commitment tree; credit
///    [`PoolValue::apply_shield`]. No anchor, no nullifiers — a shield spends
///    no note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldTx {
    pub transparent_inputs: Vec<TransparentOutPoint>,
    /// PUBLIC total entering the pool.
    pub value_shielded: u64,
    /// Fee, paid on the transparent side (from the inputs), NOT from the pool.
    pub fee: u64,
    /// Note commitments entering the tree.
    pub outputs: Vec<[u8; 32]>,
    /// One per output (DEV-2 format).
    pub output_ciphertexts: Vec<NoteCiphertext>,
    pub proof: ProofCarrier,
}

impl ShieldTx {
    pub fn public(&self) -> ShieldPublic {
        ShieldPublic { value_shielded: self.value_shielded, out_commitments: self.outputs.clone() }
    }

    pub fn check_shape(&self) -> Result<(), BridgeShapeError> {
        if self.transparent_inputs.is_empty() {
            return Err(BridgeShapeError::NoTransparentInputs);
        }
        if self.value_shielded == 0 {
            return Err(BridgeShapeError::ZeroValue);
        }
        if self.outputs.len() != self.output_ciphertexts.len() {
            return Err(BridgeShapeError::CiphertextCountMismatch {
                commitments: self.outputs.len(),
                ciphertexts: self.output_ciphertexts.len(),
            });
        }
        Ok(())
    }
}

/// `unshield_tx` — shielded → transparent.
///
/// Node-side validity (outside this crate):
/// 1. [`UnshieldTx::check_shape`] — including the transparent-sum weld.
/// 2. `anchor` is a known commitment-tree root; every nullifier is absent
///    from the [`NullifierSet`] (then inserted on application).
/// 3. The proof (resolved via [`ProofCarrier::resolve`]) verifies
///    [`check_unshield`] against [`UnshieldTx::public`] — whose
///    `transparent_digest` is recomputed from THIS transaction's outputs, so
///    a proof bound to other destinations cannot verify here.
/// 4. State: insert nullifiers, append `change_commitments`, create the
///    transparent outputs as fresh eUTXO entries, and debit
///    [`PoolValue::apply_unshield`] — the ratchet runs even when the proof
///    verified.
///
/// The created outputs are ordinary transparent outputs: born untainted
/// (there is no taint set) and deposit-eligible under §3.4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldTx {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// Shielded change staying in the pool.
    pub change_commitments: Vec<[u8; 32]>,
    /// One per change commitment (DEV-2 format).
    pub change_ciphertexts: Vec<NoteCiphertext>,
    /// PUBLIC total leaving the pool. Must equal Σ `transparent_outputs`
    /// values exactly ([`UnshieldTx::check_shape`]).
    pub value_unshielded: u64,
    /// Paid from the pool.
    pub fee: u64,
    pub transparent_outputs: Vec<TransparentOutput>,
    pub proof: ProofCarrier,
    /// **OPEN ITEM** — same pendency as [`ShieldedTx::binding_sig`]: no
    /// scheme, no sighash domain. The anti-transplant role is filled by
    /// `transparent_digest` inside the proved statement; whether this field
    /// gains an envelope-malleability signature or is deleted is a
    /// wire-freeze decision. Until then: producers leave it empty, verifiers
    /// ignore it.
    pub binding_sig: Vec<u8>,
}

impl UnshieldTx {
    /// The public inputs this transaction demands of its proof. The digest is
    /// derived from the transaction's OWN transparent outputs — binding by
    /// construction: change the destinations and the proof no longer speaks
    /// for this transaction.
    pub fn public(&self) -> UnshieldPublic {
        UnshieldPublic {
            anchor: self.anchor,
            nullifiers: self.nullifiers.clone(),
            change_commitments: self.change_commitments.clone(),
            value_unshielded: self.value_unshielded,
            fee: self.fee,
            transparent_digest: transparent_outputs_digest(&self.transparent_outputs),
        }
    }

    pub fn check_shape(&self) -> Result<(), BridgeShapeError> {
        if self.nullifiers.is_empty() {
            return Err(BridgeShapeError::NoNullifiers);
        }
        if self.transparent_outputs.is_empty() {
            return Err(BridgeShapeError::NoTransparentOutputs);
        }
        if self.value_unshielded == 0 {
            return Err(BridgeShapeError::ZeroValue);
        }
        if self.change_commitments.len() != self.change_ciphertexts.len() {
            return Err(BridgeShapeError::CiphertextCountMismatch {
                commitments: self.change_commitments.len(),
                ciphertexts: self.change_ciphertexts.len(),
            });
        }
        let mut sum: u128 = 0;
        for o in &self.transparent_outputs {
            sum += o.value_sat as u128; // u128 sum of u64s cannot overflow at any real count
        }
        if sum != self.value_unshielded as u128 {
            return Err(BridgeShapeError::TransparentSumMismatch {
                outputs_sum: sum,
                value_unshielded: self.value_unshielded,
            });
        }
        Ok(())
    }
}

// ── Pool-value ratchet (interface for DEV-8) ─────────────────────────────────

/// The pool's transparent backing, in satoshis — **the defense that lives
/// OUTSIDE the proof system.**
///
/// A soundness failure in the unshield proof mints transparent supply and
/// pierces the 100 B hard cap. This counter caps the blast radius: the chain
/// can never pay out more transparent value than has ever entered the pool,
/// no matter what a proof claims. [`PoolValueError::WouldMint`] is the alarm
/// — a transaction that trips it is invalid even if its proof verified.
///
/// Interface contract with DEV-8 (the supply ratchet):
/// * DEV-8 owns WHERE this commits — it must live in the consensus-committed
///   state (`state_root`), never node-local (§5.5), or two honest nodes could
///   disagree on whether an unshield is covered.
/// * This type owns the ARITHMETIC: all mutations are checked, deltas are the
///   three `apply_*` calls (one per shielded tx kind), and each has an exact
///   inverse `undo_*` for reorg disconnects.
/// * Monotone invariant for the ratchet proper:
///   `Σ apply_unshield amounts ≤ Σ apply_shield amounts` at every block —
///   which is exactly "this counter never underflows".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolValue {
    sat: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolValueError {
    Overflow,
    /// The pool does not hold what this operation withdraws. On an unshield
    /// this is the counterfeit alarm; on an `undo_*` it means state
    /// corruption (an undo that was never applied).
    WouldMint { pool: u128, requested: u128 },
}

impl PoolValue {
    pub const ZERO: PoolValue = PoolValue { sat: 0 };

    pub fn from_sat(sat: u128) -> Self {
        Self { sat }
    }

    pub fn sat(&self) -> u128 {
        self.sat
    }

    /// Shield applied: `value_shielded` enters the pool. (The shield fee is
    /// paid transparently and never touches the pool.)
    pub fn apply_shield(&mut self, value_shielded: u64) -> Result<(), PoolValueError> {
        self.sat = self.sat.checked_add(value_shielded as u128).ok_or(PoolValueError::Overflow)?;
        Ok(())
    }

    /// Shielded spend applied: only the public fee leaves the pool.
    pub fn apply_spend(&mut self, fee: u64) -> Result<(), PoolValueError> {
        self.debit(fee as u128)
    }

    /// Unshield applied: `value_unshielded + fee` leaves the pool.
    pub fn apply_unshield(&mut self, value_unshielded: u64, fee: u64) -> Result<(), PoolValueError> {
        self.debit(value_unshielded as u128 + fee as u128)
    }

    /// Reorg disconnect of a shield.
    pub fn undo_shield(&mut self, value_shielded: u64) -> Result<(), PoolValueError> {
        self.debit(value_shielded as u128)
    }

    /// Reorg disconnect of a shielded spend.
    pub fn undo_spend(&mut self, fee: u64) -> Result<(), PoolValueError> {
        self.sat = self.sat.checked_add(fee as u128).ok_or(PoolValueError::Overflow)?;
        Ok(())
    }

    /// Reorg disconnect of an unshield.
    pub fn undo_unshield(&mut self, value_unshielded: u64, fee: u64) -> Result<(), PoolValueError> {
        self.sat = self
            .sat
            .checked_add(value_unshielded as u128 + fee as u128)
            .ok_or(PoolValueError::Overflow)?;
        Ok(())
    }

    fn debit(&mut self, amount: u128) -> Result<(), PoolValueError> {
        if amount > self.sat {
            return Err(PoolValueError::WouldMint { pool: self.sat, requested: amount });
        }
        self.sat -= amount;
        Ok(())
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
mod bridge_tests {
    use super::*;

    fn note(v: u64, tag: u8) -> Note {
        Note { v, pk_d: [tag; 32], rho: [tag ^ 0x11; 32], psi: [tag ^ 0x22; 32] }
    }

    fn ct() -> NoteCiphertext {
        NoteCiphertext(vec![0u8; 8])
    }

    // ── check_shield ────────────────────────────────────────────────────────

    #[test]
    fn shield_accepts_exact_backing_and_hides_the_split() {
        // 1000 in, split 700/300 — the split is witness-only; the statement
        // sees the commitments and the public total.
        let a = note(700, 1);
        let b = note(300, 2);
        let public = ShieldPublic {
            value_shielded: 1000,
            out_commitments: vec![a.commitment(), b.commitment()],
        };
        let w = ShieldWitness { outputs: vec![a, b] };
        assert_eq!(check_shield(&public, &w), Ok(()));
    }

    /// The counterfeiting vector, shield edition: notes totalling MORE than
    /// the public value_shielded would mint unbacked pool value.
    #[test]
    fn shield_rejects_notes_exceeding_the_public_value() {
        let a = note(700, 1);
        let b = note(400, 2); // 1100 committed, 1000 declared
        let public = ShieldPublic {
            value_shielded: 1000,
            out_commitments: vec![a.commitment(), b.commitment()],
        };
        let w = ShieldWitness { outputs: vec![a, b] };
        assert_eq!(
            check_shield(&public, &w),
            Err(ShieldError::Unbalanced { outputs: 1100, value_shielded: 1000 })
        );
    }

    /// And the burn direction: declaring more than the notes carry would
    /// desync the pool's implicit balance from its notes.
    #[test]
    fn shield_rejects_public_value_exceeding_the_notes() {
        let a = note(500, 1);
        let public = ShieldPublic { value_shielded: 1000, out_commitments: vec![a.commitment()] };
        let w = ShieldWitness { outputs: vec![a] };
        assert!(matches!(check_shield(&public, &w), Err(ShieldError::Unbalanced { .. })));
    }

    /// C2-bind, shield edition: an extra public commitment the balance check
    /// never sees must fail on count, not slip through.
    #[test]
    fn shield_binds_public_count_to_witness() {
        let a = note(1000, 1);
        let smuggled = note(1_000_000, 9);
        let public = ShieldPublic {
            value_shielded: 1000,
            out_commitments: vec![a.commitment(), smuggled.commitment()],
        };
        let w = ShieldWitness { outputs: vec![a] };
        assert_eq!(
            check_shield(&public, &w),
            Err(ShieldError::OutputCountMismatch { public: 2, witness: 1 })
        );
    }

    #[test]
    fn shield_rejects_wrong_commitment_and_u64_scale_imbalance() {
        let a = note(1000, 1);
        let public = ShieldPublic { value_shielded: 1000, out_commitments: vec![[0xAB; 32]] };
        let w = ShieldWitness { outputs: vec![a] };
        assert_eq!(check_shield(&public, &w), Err(ShieldError::OutputCommitment(0)));

        // At u64::MAX scale the u128 accumulator must neither wrap nor agree:
        // two max-value notes cannot be declared as a small public total.
        let m1 = note(u64::MAX, 1);
        let m2 = note(u64::MAX, 2);
        let public = ShieldPublic {
            value_shielded: 1000,
            out_commitments: vec![m1.commitment(), m2.commitment()],
        };
        let w = ShieldWitness { outputs: vec![m1, m2] };
        assert!(matches!(check_shield(&public, &w), Err(ShieldError::Unbalanced { .. })));
    }

    // ── check_unshield ──────────────────────────────────────────────────────

    /// One funded tree, reused across the unshield tests.
    fn funded(v: u64) -> (CommitmentTree, Note, u64, Vec<[u8; 32]>, [u8; 32], [u8; 32]) {
        let mut t = CommitmentTree::new();
        let n = note(v, 7);
        let pos = t.append(n.commitment());
        let anchor = t.root();
        let path = t.path(pos).unwrap();
        let nk = [3u8; 32];
        (t, n, pos, path, anchor, nk)
    }

    fn valid_unshield() -> (UnshieldPublic, UnshieldWitness) {
        // 1000 in = 300 change + 600 out + 100 fee
        let (_t, inp, pos, path, anchor, nk) = funded(1000);
        let change = note(300, 8);
        let public = UnshieldPublic {
            anchor,
            nullifiers: vec![inp.nullifier(&nk, pos)],
            change_commitments: vec![change.commitment()],
            value_unshielded: 600,
            fee: 100,
            transparent_digest: transparent_outputs_digest(&[TransparentOutput {
                value_sat: 600,
                script_hash: [0x51; 32],
            }]),
        };
        let w = UnshieldWitness {
            inputs: vec![SpendInput { note: inp, position: pos, path, nk }],
            change_outputs: vec![change],
        };
        (public, w)
    }

    #[test]
    fn unshield_accepts_a_balanced_exit() {
        let (public, w) = valid_unshield();
        assert_eq!(check_unshield(&public, &w), Ok(()));
    }

    /// THE mint vector: claiming more public value_unshielded than the notes
    /// fund. A soundness break here counterfeits transparent supply, so the
    /// statement-level rejection is the first of the two defenses (the
    /// PoolValue ratchet is the second).
    #[test]
    fn unshield_rejects_minting_more_than_the_inputs_fund() {
        let (mut public, w) = valid_unshield();
        public.value_unshielded = 601; // one sat over
        assert_eq!(
            check_unshield(&public, &w),
            Err(UnshieldError::Unbalanced {
                inputs: 1000,
                change: 300,
                value_unshielded: 601,
                fee: 100
            })
        );
    }

    #[test]
    fn unshield_rejects_forged_membership_and_wrong_nullifier() {
        let (public, w) = valid_unshield();

        let forged = UnshieldPublic { anchor: [0xCD; 32], ..public.clone() };
        assert_eq!(check_unshield(&forged, &w), Err(UnshieldError::Membership(0)));

        let mut wrong_nf = public.clone();
        wrong_nf.nullifiers[0] = [0xEE; 32];
        assert_eq!(check_unshield(&wrong_nf, &w), Err(UnshieldError::Nullifier(0)));
    }

    /// C2-binds, unshield edition: public vectors bound to witness lengths in
    /// both directions.
    #[test]
    fn unshield_binds_public_counts_to_witness() {
        let (public, w) = valid_unshield();

        let mut smuggled_change = public.clone();
        smuggled_change.change_commitments.push(note(1_000_000, 9).commitment());
        assert_eq!(
            check_unshield(&smuggled_change, &w),
            Err(UnshieldError::ChangeCountMismatch { public: 2, witness: 1 })
        );

        let mut missing_nf = public.clone();
        missing_nf.nullifiers.clear();
        assert_eq!(
            check_unshield(&missing_nf, &w),
            Err(UnshieldError::NullifierCountMismatch { public: 0, witness: 1 })
        );

        let mut extra_nf = public.clone();
        extra_nf.nullifiers.push([0xEE; 32]);
        assert_eq!(
            check_unshield(&extra_nf, &w),
            Err(UnshieldError::NullifierCountMismatch { public: 2, witness: 1 })
        );
    }

    /// Spending the same note twice in ONE transaction doubles in_sum — the
    /// intra-tx double-spend the NullifierSet only catches at application.
    /// The unshield statement rejects it itself.
    #[test]
    fn unshield_rejects_intra_tx_double_spend() {
        let (_t, inp, pos, path, anchor, nk) = funded(1000);
        let nf = inp.nullifier(&nk, pos);
        let change = note(300, 8);
        let public = UnshieldPublic {
            anchor,
            nullifiers: vec![nf, nf],
            change_commitments: vec![change.commitment()],
            value_unshielded: 1600, // 2×1000 − 300 − 100: balanced IF the dup counted
            fee: 100,
            transparent_digest: [0u8; 32],
        };
        let dup = SpendInput { note: inp.clone(), position: pos, path: path.clone(), nk };
        let w = UnshieldWitness { inputs: vec![dup.clone(), dup], change_outputs: vec![change] };
        assert_eq!(check_unshield(&public, &w), Err(UnshieldError::DuplicateNullifier(1)));
    }

    /// The anti-transplant bind: the same shielded material pointed at a
    /// different transparent destination yields DIFFERENT public inputs, so a
    /// proof committed to one set of publics cannot speak for the other.
    #[test]
    fn unshield_public_binds_the_transparent_destinations() {
        let tx = UnshieldTx {
            anchor: [1; 32],
            nullifiers: vec![[2; 32]],
            change_commitments: vec![],
            change_ciphertexts: vec![],
            value_unshielded: 600,
            fee: 100,
            transparent_outputs: vec![TransparentOutput {
                value_sat: 600,
                script_hash: [0x51; 32],
            }],
            proof: ProofCarrier::Inline(vec![]),
            binding_sig: vec![],
        };
        let mut hijacked = tx.clone();
        hijacked.transparent_outputs[0].script_hash = [0x66; 32]; // attacker's script

        assert_ne!(tx.public(), hijacked.public());
        assert_ne!(tx.public().transparent_digest, hijacked.public().transparent_digest);

        // Same value split differently must also re-bind.
        let mut resplit = tx.clone();
        resplit.transparent_outputs = vec![
            TransparentOutput { value_sat: 300, script_hash: [0x51; 32] },
            TransparentOutput { value_sat: 300, script_hash: [0x51; 32] },
        ];
        assert_ne!(tx.public().transparent_digest, resplit.public().transparent_digest);
    }

    // ── shapes: the transparent weld and the ciphertext count ───────────────

    #[test]
    fn unshield_shape_welds_outputs_to_the_public_value() {
        let mut tx = UnshieldTx {
            anchor: [1; 32],
            nullifiers: vec![[2; 32]],
            change_commitments: vec![[3; 32]],
            change_ciphertexts: vec![ct()],
            value_unshielded: 600,
            fee: 100,
            transparent_outputs: vec![TransparentOutput {
                value_sat: 600,
                script_hash: [0x51; 32],
            }],
            proof: ProofCarrier::Inline(vec![]),
            binding_sig: vec![],
        };
        assert_eq!(tx.check_shape(), Ok(()));

        // Output sum drifting from the proved public value is the weld break:
        // the pool would be debited 600 while the ledger credits 700.
        tx.transparent_outputs[0].value_sat = 700;
        assert_eq!(
            tx.check_shape(),
            Err(BridgeShapeError::TransparentSumMismatch {
                outputs_sum: 700,
                value_unshielded: 600
            })
        );

        tx.transparent_outputs.clear();
        assert_eq!(tx.check_shape(), Err(BridgeShapeError::NoTransparentOutputs));

        tx.transparent_outputs = vec![TransparentOutput { value_sat: 0, script_hash: [0x51; 32] }];
        tx.value_unshielded = 0;
        assert_eq!(tx.check_shape(), Err(BridgeShapeError::ZeroValue));
    }

    #[test]
    fn shield_shape_requires_inputs_value_and_ciphertext_parity() {
        let mut tx = ShieldTx {
            transparent_inputs: vec![TransparentOutPoint { txid: [9; 32], vout: 0 }],
            value_shielded: 1000,
            fee: 10,
            outputs: vec![[1; 32], [2; 32]],
            output_ciphertexts: vec![ct(), ct()],
            proof: ProofCarrier::Inline(vec![]),
        };
        assert_eq!(tx.check_shape(), Ok(()));

        tx.output_ciphertexts.pop();
        assert_eq!(
            tx.check_shape(),
            Err(BridgeShapeError::CiphertextCountMismatch { commitments: 2, ciphertexts: 1 })
        );
        tx.output_ciphertexts.push(ct());

        tx.transparent_inputs.clear();
        assert_eq!(tx.check_shape(), Err(BridgeShapeError::NoTransparentInputs));
        tx.transparent_inputs.push(TransparentOutPoint { txid: [9; 32], vout: 0 });

        tx.value_shielded = 0;
        assert_eq!(tx.check_shape(), Err(BridgeShapeError::ZeroValue));
    }

    // ── proof carriage indirection ──────────────────────────────────────────

    struct MapFetch(std::collections::HashMap<[u8; 32], Vec<u8>>);
    impl ProofFetch for MapFetch {
        fn fetch(&self, commitment: &[u8; 32]) -> Option<Vec<u8>> {
            self.0.get(commitment).cloned()
        }
    }

    #[test]
    fn proof_carrier_serves_both_architecture_outcomes() {
        let bytes = vec![0xAA; 128];
        let cm = proof_commitment(&bytes);

        // Outcome A: inline. Resolution is trivial and needs no fetch layer.
        let inline = ProofCarrier::Inline(bytes.clone());
        assert_eq!(inline.commitment(), cm);
        assert_eq!(inline.resolve(&NoDetachedProofs).unwrap(), bytes);

        // Outcome B: detached, resolved through a store.
        let detached = ProofCarrier::Detached { commitment: cm, len: 128 };
        assert_eq!(detached.commitment(), cm, "same identity in both carriages");
        let store = MapFetch([(cm, bytes.clone())].into_iter().collect());
        assert_eq!(detached.resolve(&store).unwrap(), bytes);
    }

    #[test]
    fn detached_proofs_fail_closed() {
        let bytes = vec![0xAA; 128];
        let cm = proof_commitment(&bytes);
        let carrier = ProofCarrier::Detached { commitment: cm, len: 128 };

        // Absent → unverifiable, never valid.
        assert_eq!(
            carrier.resolve(&NoDetachedProofs),
            Err(ProofUnavailable::NotFound { commitment: cm })
        );

        // A substituted proof of the right length is caught by re-hashing.
        let mut forged = bytes.clone();
        forged[0] ^= 1;
        let bad_store = MapFetch([(cm, forged.clone())].into_iter().collect());
        assert_eq!(
            carrier.resolve(&bad_store),
            Err(ProofUnavailable::CommitmentMismatch {
                expected: cm,
                got: proof_commitment(&forged)
            })
        );

        // Wrong length is rejected before hashing.
        let short = ProofCarrier::Detached { commitment: cm, len: 64 };
        let store = MapFetch([(cm, bytes)].into_iter().collect());
        assert_eq!(
            short.resolve(&store),
            Err(ProofUnavailable::LengthMismatch { expected: 64, got: 128 })
        );
    }

    // ── the pool-value ratchet ──────────────────────────────────────────────

    /// The defense outside the proof system: even a "verified" unshield can
    /// never withdraw more than the pool has ever received.
    #[test]
    fn ratchet_caps_withdrawals_at_lifetime_deposits() {
        let mut pool = PoolValue::ZERO;
        pool.apply_shield(1000).unwrap();
        pool.apply_spend(100).unwrap(); // a shielded spend's fee leaves too
        assert_eq!(pool.sat(), 900);

        // The counterfeit scenario: a soundness break produced a proof for
        // 900 out + 1 fee. The proof verified; the ratchet still says no.
        assert_eq!(
            pool.apply_unshield(900, 1),
            Err(PoolValueError::WouldMint { pool: 900, requested: 901 })
        );
        // And a rejected operation must not have moved the counter.
        assert_eq!(pool.sat(), 900);

        // The exact remaining backing can leave.
        pool.apply_unshield(850, 50).unwrap();
        assert_eq!(pool.sat(), 0);
    }

    #[test]
    fn ratchet_undo_is_exact_inverse_and_detects_corruption() {
        let mut pool = PoolValue::from_sat(500);
        let snapshot = pool;

        pool.apply_shield(300).unwrap();
        pool.apply_unshield(100, 10).unwrap();
        pool.apply_spend(5).unwrap();
        // Disconnect in reverse order, as a reorg would.
        pool.undo_spend(5).unwrap();
        pool.undo_unshield(100, 10).unwrap();
        pool.undo_shield(300).unwrap();
        assert_eq!(pool, snapshot, "reorg undo must restore the exact backing");

        // Undoing a shield that was never applied is state corruption, and it
        // reports as the mint alarm rather than wrapping.
        let mut broken = PoolValue::ZERO;
        assert_eq!(broken.undo_shield(1), Err(PoolValueError::WouldMint { pool: 0, requested: 1 }));
    }

    // ── end-to-end: shield feeds the tree, unshield drains it ───────────────

    /// The full bridge round-trip at the statement level: transparent value
    /// enters via check_shield, the minted notes are real tree citizens that
    /// check_unshield can spend back out, and the ratchet books every leg.
    #[test]
    fn bridge_round_trip_conserves_value() {
        let mut pool = PoolValue::ZERO;
        let mut tree = CommitmentTree::new();

        // Shield 1000 into two notes.
        let a = note(700, 1);
        let b = note(300, 2);
        let shield_pub = ShieldPublic {
            value_shielded: 1000,
            out_commitments: vec![a.commitment(), b.commitment()],
        };
        assert_eq!(
            check_shield(&shield_pub, &ShieldWitness { outputs: vec![a.clone(), b.clone()] }),
            Ok(())
        );
        let pa = tree.append(a.commitment());
        let pb = tree.append(b.commitment());
        pool.apply_shield(1000).unwrap();

        // Unshield note `a` (700): 500 out, 150 change, 50 fee.
        let anchor = tree.root();
        let nk = [3u8; 32];
        let change = note(150, 4);
        let public = UnshieldPublic {
            anchor,
            nullifiers: vec![a.nullifier(&nk, pa)],
            change_commitments: vec![change.commitment()],
            value_unshielded: 500,
            fee: 50,
            transparent_digest: transparent_outputs_digest(&[TransparentOutput {
                value_sat: 500,
                script_hash: [0x51; 32],
            }]),
        };
        let w = UnshieldWitness {
            inputs: vec![SpendInput { note: a, position: pa, path: tree.path(pa).unwrap(), nk }],
            change_outputs: vec![change],
        };
        assert_eq!(check_unshield(&public, &w), Ok(()));
        pool.apply_unshield(500, 50).unwrap();

        // The books close: 1000 in − 550 out = 450 backing, which is exactly
        // note b (300, untouched at pb) + the 150 change note.
        assert_eq!(pool.sat(), 450);
        let _ = pb;
    }
}
