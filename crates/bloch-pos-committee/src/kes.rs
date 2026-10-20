//! Forward-secure validator keys ("Proof of Context and Time"): a key-evolving
//! signature scheme (KES, as in Cardano's Ouroboros) over the hybrid
//! ML-DSA-65 ‖ Falcon-1024 suite, ported from GnB `core::kes`.
//!
//! A validator registers once, with its static key, the Merkle root over
//! `2^depth` leaf keys, one per KES period (wire 0x17, from
//! [`crate::params::KES_REGISTRATION_EPOCH`]). From
//! [`crate::params::KES_ACTIVATION_EPOCH`] on, every proposal and every vote
//! must be signed by the leaf of the period of its epoch (the target epoch for
//! a vote). Leaf `i` derives from `seed_i`, and `seed_{i+1} = H(seed_i)`, so a
//! signer that has evolved to period `p` holds only `seed_p`: it can sign `p`
//! and later, nothing earlier. Keys that leak, are sold or are retired after
//! the fact cannot re-sign the past, which closes long-range attacks on FFG
//! finality without recurring weak-subjectivity checkpoints: one pin of the
//! activation checkpoint covers the history signed before it.
//!
//! ```text
//! seed_{i+1} = SHA3("BLOCH-KES-v1/step" ‖ seed_i)
//! leaf_i     = hybrid keypair from SHA3("BLOCH-KES-v1/leaf" ‖ seed_i)
//! L_i        = SHA3("BLOCH-KES-v1/pk" ‖ pk_i)
//! node       = SHA3("BLOCH-KES-v1/node" ‖ left ‖ right)
//! message    = SHA3("BLOCH-KES-v2/sign" ‖ domain ‖ u32 validator ‖ u8 depth ‖ root ‖ u64 period ‖ signing root)
//! signature  = "KES1" ‖ u32 leaf ‖ u32 len ‖ pk ‖ u32 len ‖ sig ‖ u8 depth ‖ depth × 32-byte siblings
//! ```
//!
//! The leaf signs [`leaf_message`], never the bare consensus root (audit p8a):
//! the Merkle path alone proves only that the key is SOME leaf of SOME tree.
//! On the mainnet line the binding is in force from the first KES signature.
//!
//! # Per-key start period and rotation (HF3, docs/KES-MAINNET-READINESS.md §3)
//!
//! The devnet lineage indexed leaves by the network-wide period since
//! activation, so every tree of one depth expired in the same epoch and a key
//! could never be renewed (readiness blockers B1/B2). On this line:
//!
//! * Each key carries its own `start_period` ([`KesPublic::start_period`]):
//!   leaf `i` signs global period `start_period + i`
//!   ([`KesPublic::leaf_index`]). A registration before enforcement starts at
//!   period 0; one included in period `p` after it starts at `p + 1`.
//! * `KesRotate` ([`ROTATE_TAG`]) replaces a key without a human in the loop:
//!   it is signed by the leaf of the CURRENT period `p` of the key in force
//!   over [`rotate_signing_root`] (bound through [`leaf_message`]), is valid
//!   only in a block of period `p`, and makes the new tree the key from
//!   `p + 1` (start period `p + 1`). The static key cannot rotate: a static
//!   key stolen later could otherwise rotate on a long-range fork.
//! * The state keeps, per validator, a [`KesEntry`]: the key in force and at
//!   most one pending successor. [`KesEntry::in_force`] resolves the key for
//!   a period lazily, so no epoch-boundary hook mutates state; the successor
//!   is promoted (and the old key dropped) when the next rotation is applied.
//!
//! This crate only hashes and checks paths; the leaf signature goes through
//! the caller's [`SignatureVerifier`] like every other consensus signature.
//! Key generation and evolution live in the node (`bloch-pos-node::kes_key`).

use crate::attestation::{KeyLookup, SignatureVerifier};
use sha3::{Digest, Sha3_256};

const DS_STEP: &[u8] = b"BLOCH-KES-v1/step";
const DS_LEAF: &[u8] = b"BLOCH-KES-v1/leaf";
const DS_PK: &[u8] = b"BLOCH-KES-v1/pk";
const DS_NODE: &[u8] = b"BLOCH-KES-v1/node";
const DS_REGISTER: &[u8] = b"BLOCH-KES-v1/register";
const DS_SIGN: &[u8] = b"BLOCH-KES-v2/sign";
const DS_AUTHORITY: &[u8] = b"BLOCH-KES-v1/authority";
const DS_ROTATE: &[u8] = b"BLOCH-KES-v1/rotate";

/// Transaction tag of `PosTransaction::KesRegister`. Free on the mainnet line
/// (highest 0x16, the L2 range 0x12-0x16) and the same byte devnet4 used.
pub const REGISTER_TAG: u8 = 0x17;

/// Transaction tag of `PosTransaction::KesRotate`: 0x1B, as ruled by the HF3
/// tag allocation (`codex/hf3-tags-20261020` e0bfbfff, `wire_alloc::tx::
/// KES_ROTATE`; 0x18-0x1A belong to the PQ migration).
pub const ROTATE_TAG: u8 = 0x1B;

/// Wire prefix of a KES signature; a legacy hybrid signature starts with the
/// suite envelope `B1 0C 01 00`, so the two never parse as each other.
pub const SIGNATURE_MAGIC: [u8; 4] = *b"KES1";
/// Shallowest and deepest trees accepted at registration.
pub const MIN_DEPTH: u8 = 1;
pub const MAX_DEPTH: u8 = 16;
/// Leaf key and signature bounds: the hybrid suite's envelope sizes
/// (3,749-byte key; at most 4,593-byte signature, `transition::funded`).
pub const MAX_LEAF_PK_LEN: usize = 3_749;
pub const MAX_LEAF_SIG_LEN: usize = 4_593;
/// Largest encoded KES signature: magic, period, two length prefixes, key,
/// signature, depth byte and a full path.
pub const MAX_SIGNATURE_LEN: usize = 4 + 4 + 4 + MAX_LEAF_PK_LEN + 4 + MAX_LEAF_SIG_LEN + 1 + 32 * MAX_DEPTH as usize;

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Sha3_256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

/// `seed_{i+1}` from `seed_i` (one-way).
pub fn step(seed: &[u8; 32]) -> [u8; 32] {
    h(&[DS_STEP, seed])
}

/// The deterministic keygen seed of leaf `i`, from `seed_i`.
pub fn leaf_seed(seed: &[u8; 32]) -> [u8; 32] {
    h(&[DS_LEAF, seed])
}

/// Merkle leaf of a leaf public key.
pub fn leaf_hash(pk: &[u8]) -> [u8; 32] {
    h(&[DS_PK, pk])
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    h(&[DS_NODE, l, r])
}

/// Root over a power-of-two number of leaf hashes.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
    }
    level.first().copied().unwrap_or([0; 32])
}

/// Sibling hashes from leaf `index` up to the root.
pub fn auth_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    let mut level = leaves.to_vec();
    let mut i = index;
    while level.len() > 1 {
        path.push(level[i ^ 1]);
        level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
        i >>= 1;
    }
    path
}

/// A validator's registered forward-secure key: tree depth, Merkle root and
/// the global period its leaf 0 signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KesPublic {
    pub depth: u8,
    pub root: [u8; 32],
    /// The global KES period of leaf 0 (per key, fixed when the key is
    /// committed; readiness blocker B1).
    pub start_period: u64,
}

impl KesPublic {
    /// A tree whose leaf 0 signs global period `start_period`.
    pub fn new(depth: u8, root: [u8; 32], start_period: u64) -> Self {
        KesPublic { depth, root, start_period }
    }

    /// Number of leaves (periods) in the tree.
    pub fn periods(&self) -> u64 {
        1u64 << self.depth.min(MAX_DEPTH)
    }

    /// The leaf that signs global KES period `period`: `period −
    /// start_period`, or `None` before the key starts or once the tree is
    /// exhausted (expired).
    pub fn leaf_index(&self, period: u64) -> Option<u64> {
        if !(MIN_DEPTH..=MAX_DEPTH).contains(&self.depth) {
            return None;
        }
        period.checked_sub(self.start_period).filter(|&leaf| leaf < self.periods())
    }

    /// The first global period this key can no longer sign.
    pub fn end_period(&self) -> u64 {
        self.start_period.saturating_add(self.periods())
    }

    /// Periods left to sign at global period `period`, counting `period`
    /// itself (0 once expired; the full lifetime before the start).
    pub fn remaining_periods(&self, period: u64) -> u64 {
        self.end_period().saturating_sub(period.max(self.start_period))
    }

    /// Same tree (depth and root), whatever the start period.
    pub fn same_tree(&self, other: &KesPublic) -> bool {
        self.depth == other.depth && self.root == other.root
    }

    /// The bytes the state commits for this key:
    /// `depth ‖ root ‖ u64 LE start_period`.
    pub fn committed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(self.depth);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.start_period.to_le_bytes());
        out
    }
}

/// A validator's KES state: the key in force and at most one rotated-in
/// successor, which takes over at its own `start_period`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KesEntry {
    pub current: KesPublic,
    pub next: Option<KesPublic>,
}

impl From<KesPublic> for KesEntry {
    fn from(current: KesPublic) -> Self {
        KesEntry { current, next: None }
    }
}

impl KesEntry {
    /// The key that signs global period `period`: the successor from its
    /// start period on, the current key before. Leaf bounds are the key's
    /// own ([`KesPublic::leaf_index`]).
    pub fn in_force(&self, period: u64) -> KesPublic {
        match self.next {
            Some(next) if period >= next.start_period => next,
            _ => self.current,
        }
    }

    /// The same entry with a successor that is already in force at `period`
    /// promoted (the replaced key is dropped). Pure; the transition applies it
    /// before a rotation, so the state never holds more than two keys.
    pub fn settled(&self, period: u64) -> KesEntry {
        match self.next {
            Some(next) if period >= next.start_period => KesEntry { current: next, next: None },
            _ => *self,
        }
    }

    /// The rotation waiting for a later period than `period`, if any.
    pub fn pending_at(&self, period: u64) -> Option<KesPublic> {
        self.next.filter(|next| next.start_period > period)
    }

    /// The state-root value (component 0x22): the current key's
    /// [`KesPublic::committed_bytes`], then the successor's if there is one.
    pub fn committed_bytes(&self) -> Vec<u8> {
        let mut out = self.current.committed_bytes();
        if let Some(next) = self.next {
            out.extend_from_slice(&next.committed_bytes());
        }
        out
    }
}

/// A signature by the leaf of period `index`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KesSignature {
    pub index: u32,
    pub leaf_pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub path: Vec<[u8; 32]>,
}

impl KesSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17 + self.leaf_pk.len() + self.sig.len() + 32 * self.path.len());
        out.extend_from_slice(&SIGNATURE_MAGIC);
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&(self.leaf_pk.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.leaf_pk);
        out.extend_from_slice(&(self.sig.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.sig);
        out.push(self.path.len() as u8);
        for n in &self.path {
            out.extend_from_slice(n);
        }
        out
    }

    /// Strict inverse of [`Self::encode`]: bounded fields, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_SIGNATURE_LEN || !bytes.starts_with(&SIGNATURE_MAGIC) {
            return None;
        }
        let mut at = SIGNATURE_MAGIC.len();
        let mut take = |n: usize| -> Option<&[u8]> {
            let end = at.checked_add(n)?;
            let out = bytes.get(at..end)?;
            at = end;
            Some(out)
        };
        let u32_at = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
        let index = u32_at(take(4)?);
        let pk_len = u32_at(take(4)?) as usize;
        if pk_len > MAX_LEAF_PK_LEN {
            return None;
        }
        let leaf_pk = take(pk_len)?.to_vec();
        let sig_len = u32_at(take(4)?) as usize;
        if sig_len > MAX_LEAF_SIG_LEN {
            return None;
        }
        let sig = take(sig_len)?.to_vec();
        let depth = take(1)?[0];
        if depth > MAX_DEPTH {
            return None;
        }
        let mut path = Vec::with_capacity(depth as usize);
        for _ in 0..depth {
            path.push(take(32)?.try_into().unwrap());
        }
        (at == bytes.len()).then_some(KesSignature { index, leaf_pk, sig, path })
    }
}

/// Verify `signature` (encoded) as `public`'s leaf signature over `message`
/// for global period `period`: the leaf index must be the one
/// [`KesPublic::leaf_index`] assigns, the path as deep as the tree, the leaf
/// key must hash up the path to the registered root, and the leaf signature
/// must verify. `message` is already [`leaf_message`].
pub fn verify<V: SignatureVerifier + ?Sized>(
    verifier: &V,
    public: &KesPublic,
    period: u64,
    message: &[u8; 32],
    signature: &[u8],
) -> bool {
    let Some(leaf) = public.leaf_index(period) else { return false };
    let Some(s) = KesSignature::decode(signature) else { return false };
    if u64::from(s.index) != leaf || s.path.len() != public.depth as usize {
        return false;
    }
    let mut node = leaf_hash(&s.leaf_pk);
    let mut i = leaf;
    for sib in &s.path {
        node = if i & 1 == 0 { node_hash(&node, sib) } else { node_hash(sib, &node) };
        i >>= 1;
    }
    node == public.root && verifier.verify_kes_leaf(&s.leaf_pk, message, &s.sig)
}

/// The signing root a validator's static key signs to register `public`.
/// Bound to the network (manifest domain) and the validator index, so a
/// registration cannot be replayed onto another network or validator.
pub fn register_signing_root(network_domain: &[u8; 32], validator: u32, public: &KesPublic) -> [u8; 32] {
    h(&[DS_REGISTER, network_domain, &validator.to_le_bytes(), &[public.depth], &public.root])
}

/// The root the CURRENT leaf of `validator`'s key in force signs (through
/// [`leaf_message`]) to rotate to `new_depth ‖ new_root` in global period
/// `period`. Bound to the network, validator, period and new tree; a
/// distinct domain from every consensus root and from registration.
pub fn rotate_signing_root(network_domain: &[u8; 32], validator: u32, period: u64, new_depth: u8, new_root: &[u8; 32]) -> [u8; 32] {
    h(&[DS_ROTATE, network_domain, &validator.to_le_bytes(), &period.to_le_bytes(), &[new_depth], new_root])
}

/// What a KES leaf signs: the consensus signing root under the network
/// domain, the validator index, the registered tree (depth ‖ root) and the
/// global period. The Merkle path alone proves only that the leaf key is SOME
/// leaf of SOME tree; this makes the leaf's signature say whose tree, which
/// period and which network, so it cannot be claimed by a validator that
/// registered the same root or copied the leaf key, moved to another period
/// of a tree that repeats a leaf, or replayed on another network where the
/// same tree was registered (audit p8a).
pub fn bound_signing_root(
    network_domain: &[u8; 32],
    validator: u32,
    public: &KesPublic,
    period: u64,
    signing_root: &[u8; 32],
) -> [u8; 32] {
    h(&[DS_SIGN, network_domain, &validator.to_le_bytes(), &[public.depth], &public.root, &period.to_le_bytes(), signing_root])
}

/// The 32 bytes a KES leaf signs for a consensus message by `validator` under
/// `public` in global `period`: [`bound_signing_root`]. `None` (refuse) when
/// no network domain is known, so a lookup that cannot name the network fails
/// closed. The node signer and every verifier go through this one function.
pub fn leaf_message(
    network_domain: Option<[u8; 32]>,
    validator: u32,
    public: &KesPublic,
    period: u64,
    signing_root: &[u8; 32],
) -> Option<[u8; 32]> {
    network_domain.map(|domain| bound_signing_root(&domain, validator, public, period, signing_root))
}

/// Which key authenticates `validator`'s consensus signature for `epoch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningMode {
    /// The registered static key: before the compiled gate, before KES binds
    /// on chain (`kes_enforced_from`), or — after it binds — for a validator
    /// that never registered a KES key (static-key fallback, review F-2).
    Static,
    /// The KES leaf of this global period under the key in force.
    Kes(u64),
    /// Past the gate, through a lookup that cannot say whether KES binds:
    /// nothing verifies.
    FailClosed,
}

/// Has KES enforcement bound (compiled gate reached and committed bind
/// epoch passed) at `epoch` according to `keys`?
pub fn is_bound(keys: &dyn KeyLookup, epoch: u64) -> bool {
    crate::params::kes_period(epoch).is_some() && matches!(keys.kes_enforced_from(), Some(Some(bound)) if epoch >= bound)
}

/// The signing mode for `validator` in `epoch` (see [`SigningMode`]).
pub fn signing_mode(keys: &dyn KeyLookup, validator: u32, epoch: u64) -> SigningMode {
    let Some(period) = crate::params::kes_period(epoch) else {
        return SigningMode::Static;
    };
    match keys.kes_enforced_from() {
        None => return SigningMode::FailClosed,
        Some(None) => return SigningMode::Static,
        Some(Some(bound)) if epoch < bound => return SigningMode::Static,
        Some(Some(_)) => {}
    }
    match keys.kes_public(validator, period) {
        Some(_) => SigningMode::Kes(period),
        None => SigningMode::Static,
    }
}

/// Verify a validator's consensus signature (a proposal or a vote) for
/// `epoch` against `keys`, under [`signing_mode`]. Its signature is exactly
/// that of `slashing::verify_offender_signature` on the HF2 slashing line
/// (`keys, verifier, validator, message_epoch, signing_root, signature ->
/// Option<bool>`): the integration routes that function here so consensus
/// and the node's evidence pre-check resolve the same per-epoch key.
///
/// Fault attribution: a KES root (and every rotation) is registered by a
/// transaction after genesis, so the key in force is BRANCH-DEPENDENT. A
/// KES signature that fails here proves misbehaviour only against a KES
/// entry both peers share; a relay must treat such a failure as "ignore",
/// not as a peer fault, unless the validator's entry
/// (`CommittedState::kes_roots`) is identical in this node's finalized
/// state. Static-key failures keep their existing attribution.
///
/// Rules: the static hybrid key,
/// exactly as before, until KES binds (and for never-registered validators
/// after); the leaf of `epoch`'s period under the key in force, over
/// [`leaf_message`], for a registered validator once it binds. `None` when
/// `keys` does not know the validator at all. A registered key that has
/// expired signs nothing (rescue: re-register, `check_kes_register`).
pub fn verify_validator(
    keys: &dyn KeyLookup,
    verifier: &dyn SignatureVerifier,
    validator: u32,
    epoch: u64,
    signing_root: &[u8; 32],
    signature: &[u8],
) -> Option<bool> {
    let period = match signing_mode(keys, validator, epoch) {
        SigningMode::Static => None,
        SigningMode::Kes(period) => Some(period),
        SigningMode::FailClosed => {
            keys.pubkey(validator)?;
            return Some(false);
        }
    };
    verify_validator_in(keys, verifier, validator, period, signing_root, signature)
}

/// [`verify_validator`] with the period given: `None` is the static key,
/// `Some(p)` the KES leaf of global period `p`. For callers (and tests) that
/// hold the period already; consensus uses [`verify_validator`].
pub fn verify_validator_in(
    keys: &dyn KeyLookup,
    verifier: &dyn SignatureVerifier,
    validator: u32,
    period: Option<u64>,
    signing_root: &[u8; 32],
    signature: &[u8],
) -> Option<bool> {
    let static_key = keys.pubkey(validator)?;
    let Some(period) = period else {
        return Some(verifier.verify_with_key(static_key, signing_root, signature));
    };
    let Some(public) = keys.kes_public(validator, period) else {
        return Some(false);
    };
    let Some(message) = leaf_message(keys.kes_network_domain(), validator, &public, period, signing_root) else {
        return Some(false);
    };
    Some(verifier.verify_kes(&public, period, &message, signature))
}

/// A fingerprint of everything [`verify_validator`] authenticates `validator`
/// against for `epoch`, for caches that remember "this exact message already
/// verified under this exact authority" (gossip pending tokens, block
/// admission proofs). Before enforcement it is `SHA3(static key)`, byte for
/// byte the fingerprint those caches always used; from it on it also commits
/// to the KES key (or its absence), the network domain and the period, so a
/// registration or a domain change can never reuse a stale verdict. `None`
/// when `keys` does not know the validator.
pub fn authority_fingerprint(keys: &dyn KeyLookup, validator: u32, epoch: u64) -> Option<[u8; 32]> {
    let static_key = keys.pubkey(validator)?;
    let static_hash = h(&[static_key]);
    let period = match signing_mode(keys, validator, epoch) {
        // After KES binds, a never-registered validator's static key is a
        // fallback authority: tagged, so no verdict cached under the plain
        // pre-enforcement form is reused across the bind.
        SigningMode::Static if is_bound(keys, epoch) => return Some(h(&[DS_AUTHORITY, &static_hash, b"static-fallback"])),
        SigningMode::Static => return Some(static_hash),
        SigningMode::FailClosed => return Some(h(&[DS_AUTHORITY, &static_hash, b"fail-closed"])),
        SigningMode::Kes(period) => period,
    };
    let kes = keys.kes_public(validator, period).map(|k| k.committed_bytes()).unwrap_or_default();
    let domain = keys.kes_network_domain();
    Some(h(&[
        DS_AUTHORITY,
        &static_hash,
        &(kes.len() as u32).to_le_bytes(),
        &kes,
        &[u8::from(domain.is_some())],
        &domain.unwrap_or([0; 32]),
        &period.to_le_bytes(),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Binds a "signature" to (key, root) without real cryptography.
    struct ToyVerifier;
    impl SignatureVerifier for ToyVerifier {
        fn verify_with_key(&self, pubkey: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
            signature == h(&[pubkey, root])
        }
    }

    fn toy_tree(depth: u8, seed0: [u8; 32]) -> (Vec<Vec<u8>>, Vec<[u8; 32]>) {
        let mut seed = seed0;
        let mut pks = Vec::new();
        for _ in 0..(1u32 << depth) {
            pks.push(leaf_seed(&seed).to_vec());
            seed = step(&seed);
        }
        let leaves = pks.iter().map(|pk| leaf_hash(pk)).collect();
        (pks, leaves)
    }

    fn toy_sign(pks: &[Vec<u8>], leaves: &[[u8; 32]], period: usize, root: &[u8; 32]) -> Vec<u8> {
        KesSignature {
            index: period as u32,
            leaf_pk: pks[period].clone(),
            sig: h(&[&pks[period], root]).to_vec(),
            path: auth_path(leaves, period),
        }
        .encode()
    }

    #[test]
    fn every_period_verifies_only_for_itself() {
        let (pks, leaves) = toy_tree(3, [7; 32]);
        let public = KesPublic::new(3, merkle_root(&leaves), 0);
        let root = [9u8; 32];
        for p in 0..8usize {
            let sig = toy_sign(&pks, &leaves, p, &root);
            assert!(verify(&ToyVerifier, &public, p as u64, &root, &sig), "period {p}");
            assert!(!verify(&ToyVerifier, &public, (p as u64 + 1) % 8, &root, &sig), "wrong period");
            assert!(!verify(&ToyVerifier, &public, p as u64, &[8; 32], &sig), "wrong message");
        }
        assert!(!verify(&ToyVerifier, &public, 8, &root, &toy_sign(&pks, &leaves, 0, &root)), "beyond the tree");
    }

    #[test]
    fn tampering_and_foreign_keys_fail() {
        let (pks, leaves) = toy_tree(3, [7; 32]);
        let public = KesPublic::new(3, merkle_root(&leaves), 0);
        let root = [9u8; 32];
        let good = KesSignature::decode(&toy_sign(&pks, &leaves, 2, &root)).unwrap();
        let mut bad = good.clone();
        bad.path[1][0] ^= 1;
        assert!(!verify(&ToyVerifier, &public, 2, &root, &bad.encode()), "tampered path");
        let mut short = good.clone();
        short.path.pop();
        assert!(!verify(&ToyVerifier, &public, 2, &root, &short.encode()), "short path");
        let (other_pks, other_leaves) = toy_tree(3, [8; 32]);
        let foreign = toy_sign(&other_pks, &other_leaves, 2, &root);
        assert!(!verify(&ToyVerifier, &public, 2, &root, &foreign), "another tree");
        assert!(!verify(&ToyVerifier, &KesPublic::new(2, public.root, 0), 2, &root, &good.encode()));
    }

    #[test]
    fn decoding_is_strict() {
        let (pks, leaves) = toy_tree(2, [1; 32]);
        let sig = toy_sign(&pks, &leaves, 1, &[0; 32]);
        assert_eq!(KesSignature::decode(&sig).unwrap().encode(), sig);
        let mut trailing = sig.clone();
        trailing.push(0);
        assert!(KesSignature::decode(&trailing).is_none());
        assert!(KesSignature::decode(&sig[..sig.len() - 1]).is_none());
        assert!(KesSignature::decode(&[0xB1, 0x0C, 0x01, 0x00]).is_none(), "a legacy envelope is not KES");
    }

    #[test]
    fn evolving_the_seed_cannot_reach_back() {
        // seed_{i+1} = H(seed_i): leaf i's seed is not a function of seed_{i+1}.
        let s0 = [3u8; 32];
        let s1 = step(&s0);
        assert_ne!(leaf_seed(&s0), leaf_seed(&s1));
        assert_eq!(step(&s1), step(&step(&s0)));
    }

    #[test]
    fn the_bound_root_commits_to_every_field() {
        let k = KesPublic::new(10, [5; 32], 0);
        let base = bound_signing_root(&[1; 32], 3, &k, 7, &[9; 32]);
        assert_ne!(base, bound_signing_root(&[2; 32], 3, &k, 7, &[9; 32]), "network");
        assert_ne!(base, bound_signing_root(&[1; 32], 4, &k, 7, &[9; 32]), "validator");
        assert_ne!(base, bound_signing_root(&[1; 32], 3, &KesPublic::new(11, [5; 32], 0), 7, &[9; 32]), "depth");
        assert_ne!(base, bound_signing_root(&[1; 32], 3, &KesPublic::new(10, [6; 32], 0), 7, &[9; 32]), "root");
        assert_ne!(base, bound_signing_root(&[1; 32], 3, &k, 8, &[9; 32]), "period");
        assert_ne!(base, bound_signing_root(&[1; 32], 3, &k, 7, &[8; 32]), "message");
        assert_ne!(base, register_signing_root(&[1; 32], 3, &k), "never a registration message");
    }

    #[test]
    fn leaf_index_is_the_period_inside_the_tree_and_nothing_outside() {
        let k = KesPublic::new(2, [0; 32], 0);
        assert_eq!((0..4).map(|p| k.leaf_index(p)).collect::<Vec<_>>(), vec![Some(0), Some(1), Some(2), Some(3)]);
        assert_eq!(k.leaf_index(4), None, "an exhausted tree signs nothing");
        assert_eq!(KesPublic::new(0, [0; 32], 0).leaf_index(0), None);
        assert_eq!(KesPublic::new(MAX_DEPTH + 1, [0; 32], 0).leaf_index(0), None);
        assert_eq!(k.committed_bytes(), [&[2u8][..], &[0u8; 32][..], &0u64.to_le_bytes()[..]].concat());
    }

    #[test]
    fn a_per_key_start_period_shifts_the_leaves_and_the_expiry() {
        // Blocker B1: two keys of the same depth expire at different periods
        // when they start at different periods.
        let a = KesPublic::new(2, [1; 32], 0);
        let b = KesPublic::new(2, [1; 32], 10);
        assert_eq!(b.leaf_index(9), None, "before its start a key signs nothing");
        assert_eq!((10..14).map(|p| b.leaf_index(p)).collect::<Vec<_>>(), vec![Some(0), Some(1), Some(2), Some(3)]);
        assert_eq!(b.leaf_index(14), None);
        assert_eq!((a.end_period(), b.end_period()), (4, 14));
        assert_eq!((b.remaining_periods(0), b.remaining_periods(10), b.remaining_periods(13), b.remaining_periods(14)), (4, 4, 1, 0));
        assert!(a.same_tree(&b));
        assert_ne!(a.committed_bytes(), b.committed_bytes(), "the start period is committed");
        assert_eq!(KesPublic::new(16, [0; 32], u64::MAX - 3).leaf_index(u64::MAX), Some(3), "no overflow at the top");
        assert_eq!(KesPublic::new(16, [0; 32], u64::MAX - 3).end_period(), u64::MAX);
    }

    #[test]
    fn a_kes_entry_hands_over_at_the_successors_start_and_settles_lazily() {
        let current = KesPublic::new(3, [1; 32], 0);
        let next = KesPublic::new(3, [2; 32], 6);
        let entry = KesEntry { current, next: Some(next) };
        assert_eq!(entry.in_force(5), current);
        assert_eq!(entry.in_force(6), next);
        assert_eq!(entry.pending_at(5), Some(next));
        assert_eq!(entry.pending_at(6), None);
        assert_eq!(entry.settled(5), entry, "nothing to promote yet");
        assert_eq!(entry.settled(6), KesEntry::from(next), "promoted, old key dropped");
        assert_eq!(
            entry.committed_bytes(),
            [current.committed_bytes(), next.committed_bytes()].concat()
        );
        assert_eq!(KesEntry::from(current).committed_bytes(), current.committed_bytes());
    }

    #[test]
    fn the_rotation_root_binds_every_field_and_is_its_own_domain() {
        let base = rotate_signing_root(&[1; 32], 3, 7, 12, &[5; 32]);
        assert_ne!(base, rotate_signing_root(&[2; 32], 3, 7, 12, &[5; 32]), "network");
        assert_ne!(base, rotate_signing_root(&[1; 32], 4, 7, 12, &[5; 32]), "validator");
        assert_ne!(base, rotate_signing_root(&[1; 32], 3, 8, 12, &[5; 32]), "period");
        assert_ne!(base, rotate_signing_root(&[1; 32], 3, 7, 11, &[5; 32]), "depth");
        assert_ne!(base, rotate_signing_root(&[1; 32], 3, 7, 12, &[6; 32]), "root");
        let k = KesPublic::new(12, [5; 32], 0);
        assert_ne!(base, register_signing_root(&[1; 32], 3, &k), "never a registration message");
        assert_ne!(base, bound_signing_root(&[1; 32], 3, &k, 7, &[5; 32]), "never a leaf message");
    }

    #[test]
    fn without_a_network_domain_there_is_no_message_to_sign() {
        let k = KesPublic::new(3, [4; 32], 0);
        assert_eq!(leaf_message(None, 1, &k, 0, &[9; 32]), None);
        assert_eq!(leaf_message(Some([1; 32]), 1, &k, 0, &[9; 32]), Some(bound_signing_root(&[1; 32], 1, &k, 0, &[9; 32])));
        assert_ne!(leaf_message(Some([1; 32]), 1, &k, 0, &[9; 32]), Some([9; 32]), "never the bare root");
    }

    #[test]
    fn registration_root_binds_network_validator_and_key() {
        let k = KesPublic::new(10, [5; 32], 0);
        let base = register_signing_root(&[1; 32], 3, &k);
        assert_ne!(base, register_signing_root(&[2; 32], 3, &k));
        assert_ne!(base, register_signing_root(&[1; 32], 4, &k));
        assert_ne!(base, register_signing_root(&[1; 32], 3, &KesPublic::new(11, [5; 32], 0)));
    }
}
