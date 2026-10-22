// SPDX-License-Identifier: AGPL-3.0-or-later

//! Self-contained finality certificates for Bloch Genesis-4.
//!
//! A certificate proves that checkpoint `(E, R)` is finalized, to a party
//! that runs no node and trusts only one earlier finalized block id (its
//! *anchor*). It carries:
//!
//! 1. **Two supermajority links**, exactly the Casper-FFG shape the chain
//!    finalizes on (`finality.rs`, `EPOCHS_PER_CHECKPOINT = 1`): the
//!    justifying link `S → E` (votes whose target is `(E, R)`) and the
//!    finalizing link `E → E+1` (votes whose source is `(E, R)`). Every vote
//!    is listed with its own `slot`, `head` and full hybrid
//!    ML-DSA-65 ‖ Falcon-1024 signature over the unchanged consensus
//!    `AttestationData::signing_root`. Hybrid signatures do not aggregate, so
//!    the votes are listed, not aggregated.
//! 2. **The validator set they are counted against, bound to a trusted
//!    state root.** The whole validator registry, as committed under
//!    `TAG_VALIDATOR` in the state root of a *set-source block*, with one
//!    sparse-Merkle inclusion proof per record and an absence proof for every
//!    index gap and for `max_index + 1` — so the serving node can neither
//!    invent a key, change a stake, nor *omit* a member to shrink the
//!    denominator. The set-source block must hash to a root the verifier
//!    already trusts (its anchor, or the checkpoint of a certificate it has
//!    already verified): that is the chain-of-certificates trust model.
//! 3. **The checkpoint header** (its hash IS `R`, its `state_root` makes `R`
//!    usable as the next set source) and an optional **ancestry** — parent-
//!    linked headers from `R` down to any block the client cares about, which
//!    is thereby finalized.
//!
//! ## Weight rule (deliberately stricter than the chain's)
//!
//! A vote weighs the validator's committed own bond (`ValidatorRecord::stake`
//! of the set-source state). The denominator is the bond of every record
//! active at the link's target epoch (`activation_epoch <= t < exit_epoch`),
//! slashed or not; slashed validators' votes count zero. The test is
//! `3·signed >= 2·total` in u128. This ignores the inactivity leak (which only
//! *shrinks* the chain's denominator) and delegated stake (not provable from
//! the registry leaf alone), so a passing certificate always means two thirds
//! of committed bonded stake signed both links — the accountable-safety
//! premise — while a chain that finalized *only* thanks to a leak-shrunk
//! denominator yields a certificate this verifier refuses. That is the safe
//! direction for an exchange.

use bloch_pos_committee::attestation::AttestationData;
use bloch_pos_committee::header::{BlockHeaderV4, BlockId};
use bloch_pos_committee::state_root::{
    empty_subtree_hashes, leaf_value_hash, validator_leaf_key, verify_absence, verify_inclusion,
    InclusionProof, ValidatorRecord, TREE_DEPTH,
};
use bloch_pos_committee::{epoch_of, SLOTS_PER_EPOCH};
use std::collections::BTreeSet;

/// Wire magic + version. Bumped on any format change.
pub const MAGIC: &[u8; 8] = b"BLOCHFC1";
pub const VERSION: u16 = 1;

/// Parser bounds (anti-exhaustion, not policy).
pub const MAX_RECORDS: usize = 1 << 16;
pub const MAX_VOTES_PER_LINK: usize = 1 << 16;
pub const MAX_SIG_BYTES: usize = 16 * 1024;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_ANCESTRY: usize = 4096;
/// Default for [`TrustAnchors::max_hop_epochs`]: how far (in epochs) a
/// certificate's target may sit past its set-source block. A registry drifts
/// (activations, exits) with distance; the weak-subjectivity reasoning is
/// the same as checkpoint sync's.
pub const DEFAULT_MAX_HOP_EPOCHS: u64 = 256;

// ─── Compressed SMT proof ──────────────────────────────────────────────────

/// An [`InclusionProof`] with empty-subtree siblings elided: a 256-bit map
/// (bit `d` set ⇒ sibling `d` is present) and the present siblings in depth
/// order. Re-expanded against the public empty constants before checking, so
/// compression cannot change what verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressedProof {
    pub bitmap: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl CompressedProof {
    pub fn compress(p: &InclusionProof, empty: &[[u8; 32]]) -> Self {
        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        for (d, s) in p.siblings.iter().enumerate() {
            if *s != empty[d + 1] {
                bitmap[d / 8] |= 0x80 >> (d % 8);
                siblings.push(*s);
            }
        }
        CompressedProof { bitmap, siblings }
    }

    pub fn expand(&self, empty: &[[u8; 32]]) -> Option<InclusionProof> {
        let mut out = Vec::with_capacity(TREE_DEPTH);
        let mut it = self.siblings.iter();
        for d in 0..TREE_DEPTH {
            if self.bitmap[d / 8] & (0x80 >> (d % 8)) != 0 {
                out.push(*it.next()?);
            } else {
                out.push(empty[d + 1]);
            }
        }
        if it.next().is_some() {
            return None;
        }
        Some(InclusionProof { siblings: out })
    }

    fn encoded_len(&self) -> usize {
        32 + 32 * self.siblings.len()
    }
}

// ─── Certificate ───────────────────────────────────────────────────────────

/// One signed vote inside a link. `source`/`target` are the link's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub validator: u32,
    pub slot: u64,
    pub head: [u8; 32],
    pub signature: Vec<u8>,
}

/// A supermajority link `source → target` and the votes that make it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub source_epoch: u64,
    pub source_root: [u8; 32],
    pub target_epoch: u64,
    pub target_root: [u8; 32],
    /// Ascending by validator, one vote per validator.
    pub votes: Vec<Vote>,
}

impl Link {
    pub fn data(&self, v: &Vote) -> AttestationData {
        AttestationData {
            slot: v.slot,
            head: v.head,
            source_epoch: self.source_epoch,
            source_root: self.source_root,
            target_epoch: self.target_epoch,
            target_root: self.target_root,
        }
    }
}

/// The registry of a set-source block, proven against its `state_root`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryProof {
    /// The set-source block header. Its id must be trusted by the verifier.
    pub header: BlockHeaderV4,
    /// `ValidatorRecord` canonical bytes + inclusion proof, ascending index.
    pub records: Vec<(Vec<u8>, CompressedProof)>,
    /// Absence proofs: every gap below the highest index, then `max + 1`.
    pub absent: Vec<(u32, CompressedProof)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// Header of the checkpoint block; `id() == links[0].target_root`.
    pub checkpoint_header: BlockHeaderV4,
    pub registry: RegistryProof,
    /// `[justifying S→E, finalizing E→E+1]`.
    pub links: [Link; 2],
    /// Headers from the checkpoint's parent downward (each the previous one's
    /// parent). Empty when no ancestry was requested.
    pub ancestry: Vec<BlockHeaderV4>,
}

impl Certificate {
    pub fn epoch(&self) -> u64 {
        self.links[0].target_epoch
    }
    pub fn root(&self) -> [u8; 32] {
        self.links[0].target_root
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(self.encoded_len_hint());
        o.extend_from_slice(MAGIC);
        o.extend_from_slice(&VERSION.to_le_bytes());
        o.extend_from_slice(&self.checkpoint_header.canonical_serialize());
        o.extend_from_slice(&self.registry.header.canonical_serialize());
        o.extend_from_slice(&(self.registry.records.len() as u32).to_le_bytes());
        for (bytes, p) in &self.registry.records {
            o.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            o.extend_from_slice(bytes);
            put_proof(&mut o, p);
        }
        o.extend_from_slice(&(self.registry.absent.len() as u32).to_le_bytes());
        for (i, p) in &self.registry.absent {
            o.extend_from_slice(&i.to_le_bytes());
            put_proof(&mut o, p);
        }
        for l in &self.links {
            o.extend_from_slice(&l.source_epoch.to_le_bytes());
            o.extend_from_slice(&l.source_root);
            o.extend_from_slice(&l.target_epoch.to_le_bytes());
            o.extend_from_slice(&l.target_root);
            o.extend_from_slice(&(l.votes.len() as u32).to_le_bytes());
            for v in &l.votes {
                o.extend_from_slice(&v.validator.to_le_bytes());
                o.extend_from_slice(&v.slot.to_le_bytes());
                o.extend_from_slice(&v.head);
                o.extend_from_slice(&(v.signature.len() as u32).to_le_bytes());
                o.extend_from_slice(&v.signature);
            }
        }
        o.extend_from_slice(&(self.ancestry.len() as u32).to_le_bytes());
        for h in &self.ancestry {
            o.extend_from_slice(&h.canonical_serialize());
        }
        o
    }

    fn encoded_len_hint(&self) -> usize {
        let regs: usize = self.registry.records.iter().map(|(b, p)| 4 + b.len() + p.encoded_len()).sum();
        let abs: usize = self.registry.absent.iter().map(|(_, p)| 4 + p.encoded_len()).sum();
        let votes: usize =
            self.links.iter().flat_map(|l| l.votes.iter()).map(|v| 48 + v.signature.len()).sum();
        10 + 2 * 304 + 8 + regs + abs + 2 * 84 + votes + 4 + 304 * self.ancestry.len()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Refusal> {
        let mut r = Rd(b);
        if r.take(8)? != MAGIC {
            return Err(Refusal::Malformed("magic"));
        }
        if r.u16()? != VERSION {
            return Err(Refusal::Malformed("version"));
        }
        let checkpoint_header = r.header()?;
        let set_header = r.header()?;
        let n = r.count(MAX_RECORDS)?;
        let mut records = Vec::with_capacity(n);
        for _ in 0..n {
            let len = r.count(MAX_RECORD_BYTES)?;
            let bytes = r.take(len)?.to_vec();
            records.push((bytes, r.proof()?));
        }
        let n = r.count(MAX_RECORDS + 1)?;
        let mut absent = Vec::with_capacity(n);
        for _ in 0..n {
            let i = r.u32()?;
            absent.push((i, r.proof()?));
        }
        let mut link = || -> Result<Link, Refusal> {
            let source_epoch = r.u64()?;
            let source_root = r.a32()?;
            let target_epoch = r.u64()?;
            let target_root = r.a32()?;
            let n = r.count(MAX_VOTES_PER_LINK)?;
            let mut votes = Vec::with_capacity(n);
            for _ in 0..n {
                let validator = r.u32()?;
                let slot = r.u64()?;
                let head = r.a32()?;
                let sl = r.count(MAX_SIG_BYTES)?;
                let signature = r.take(sl)?.to_vec();
                votes.push(Vote { validator, slot, head, signature });
            }
            Ok(Link { source_epoch, source_root, target_epoch, target_root, votes })
        };
        let l0 = link()?;
        let l1 = link()?;
        let n = r.count(MAX_ANCESTRY)?;
        let mut ancestry = Vec::with_capacity(n);
        for _ in 0..n {
            ancestry.push(r.header()?);
        }
        if !r.0.is_empty() {
            return Err(Refusal::Malformed("trailing bytes"));
        }
        Ok(Certificate {
            checkpoint_header,
            registry: RegistryProof { header: set_header, records, absent },
            links: [l0, l1],
            ancestry,
        })
    }
}

fn put_proof(o: &mut Vec<u8>, p: &CompressedProof) {
    o.extend_from_slice(&p.bitmap);
    // Sibling count is implied by the bitmap's popcount.
    for s in &p.siblings {
        o.extend_from_slice(s);
    }
}

struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        if self.0.len() < n {
            return Err(Refusal::Malformed("truncated"));
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn u16(&mut self) -> Result<u16, Refusal> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| Refusal::Malformed("u16"))?))
    }
    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| Refusal::Malformed("u32"))?))
    }
    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| Refusal::Malformed("u64"))?))
    }
    fn a32(&mut self) -> Result<[u8; 32], Refusal> {
        self.take(32)?.try_into().map_err(|_| Refusal::Malformed("a32"))
    }
    fn count(&mut self, max: usize) -> Result<usize, Refusal> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(Refusal::Malformed("count over bound"));
        }
        Ok(n)
    }
    fn header(&mut self) -> Result<BlockHeaderV4, Refusal> {
        BlockHeaderV4::canonical_deserialize(self.take(BlockHeaderV4::ENCODED_LEN)?)
            .map_err(|_| Refusal::Malformed("header"))
    }
    fn proof(&mut self) -> Result<CompressedProof, Refusal> {
        let bitmap = self.a32()?;
        let n: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
        let mut siblings = Vec::with_capacity(n as usize);
        for _ in 0..n {
            siblings.push(self.a32()?);
        }
        Ok(CompressedProof { bitmap, siblings })
    }
}

// ─── Verification ──────────────────────────────────────────────────────────

/// Signature check, injected so the library can be used without the PQ
/// stack (and so tests can count calls). Must check BOTH hybrid halves.
pub trait SigCheck {
    fn verify(&self, pubkey: &[u8], signing_root: &[u8; 32], signature: &[u8]) -> bool;
}

/// The production check: `bloch_crypto::crypto::verify`, the exact entry
/// point the node's consensus `HybridVerifier::verify_with_key` calls.
#[cfg(feature = "hybrid")]
pub struct HybridSigCheck;

#[cfg(feature = "hybrid")]
impl SigCheck for HybridSigCheck {
    fn verify(&self, pubkey: &[u8], signing_root: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::verify(pubkey, signing_root, signature)
    }
}

/// What the verifier trusts: block ids of finalized blocks (a weak-
/// subjectivity anchor, or checkpoints of certificates already verified).
#[derive(Clone, Debug)]
pub struct TrustAnchors {
    pub roots: BTreeSet<[u8; 32]>,
    pub max_hop_epochs: u64,
}

impl TrustAnchors {
    pub fn new(roots: impl IntoIterator<Item = [u8; 32]>) -> Self {
        TrustAnchors { roots: roots.into_iter().collect(), max_hop_epochs: DEFAULT_MAX_HOP_EPOCHS }
    }
}

/// Why a certificate was refused. One cause per variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed(&'static str),
    /// The set-source block is not one the verifier trusts (wrong set /
    /// foreign chain).
    UntrustedSetSource { root: [u8; 32] },
    /// The set source is not strictly before the certified epoch, or too far
    /// behind it.
    SetSourceDistance { source_epoch: u64, target_epoch: u64 },
    /// A registry record does not verify against the set-source state root.
    RegistryProof { index: u32 },
    /// Records are not strictly ascending, or an index gap / the end of the
    /// registry is not proven absent (a member could have been omitted).
    RegistryIncomplete { index: u32 },
    /// The checkpoint header does not hash to the certified root (foreign
    /// root), or the links are not `S→E`, `E→E+1`.
    CheckpointMismatch,
    LinkShape(&'static str),
    DuplicateOrUnsortedVote { link: usize, validator: u32 },
    UnknownValidator { link: usize, validator: u32 },
    /// The vote's slot is not in the target epoch.
    VoteOutsideEpoch { link: usize, validator: u32 },
    BadSignature { link: usize, validator: u32 },
    InsufficientStake { link: usize, signed: u128, total: u128 },
    AncestryBroken { at: usize },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// What a verified certificate establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub epoch: u64,
    pub root: [u8; 32],
    pub checkpoint_slot: u64,
    pub checkpoint_state_root: [u8; 32],
    pub set_source_root: [u8; 32],
    /// `(signed, total)` committed bond per link.
    pub stake: [(u128, u128); 2],
    pub votes: [usize; 2],
    /// The lowest block of the ancestry (finalized by implication).
    pub ancestry_tip: Option<(u64, [u8; 32])>,
}

fn id(h: &BlockHeaderV4) -> [u8; 32] {
    *BlockId::of(h).as_bytes()
}

/// Verify `cert` under `anchors`. Pure: no clock, no I/O, no global state.
pub fn verify(cert: &Certificate, anchors: &TrustAnchors, sigs: &dyn SigCheck) -> Result<Verified, Refusal> {
    let [l0, l1] = &cert.links;
    let e = l0.target_epoch;

    // 1. Shape: S→E then E→E+1, and the checkpoint header IS (E, R).
    if l0.source_epoch >= e {
        return Err(Refusal::LinkShape("justifying link source not before target"));
    }
    if l1.source_epoch != e || l1.source_root != l0.target_root {
        return Err(Refusal::LinkShape("finalizing link does not start at the checkpoint"));
    }
    if e.checked_add(1) != Some(l1.target_epoch) {
        return Err(Refusal::LinkShape("finalizing link is not consecutive"));
    }
    if id(&cert.checkpoint_header) != l0.target_root {
        return Err(Refusal::CheckpointMismatch);
    }
    // The checkpoint of epoch E is the last block strictly before E's first slot.
    let first_e = e.checked_mul(SLOTS_PER_EPOCH).ok_or(Refusal::LinkShape("epoch overflow"))?;
    if cert.checkpoint_header.slot >= first_e {
        return Err(Refusal::CheckpointMismatch);
    }

    // 2. Set source: trusted, before E, within the hop bound.
    let src = &cert.registry.header;
    let src_root = id(src);
    if !anchors.roots.contains(&src_root) {
        return Err(Refusal::UntrustedSetSource { root: src_root });
    }
    let src_epoch = epoch_of(src.slot);
    if src.slot >= first_e || e - src_epoch > anchors.max_hop_epochs {
        return Err(Refusal::SetSourceDistance { source_epoch: src_epoch, target_epoch: e });
    }

    // 3. The registry, complete, against the set source's state root.
    let empty = empty_subtree_hashes();
    let mut registry: Vec<ValidatorRecord> = Vec::with_capacity(cert.registry.records.len());
    for (bytes, cp) in &cert.registry.records {
        let rec = ValidatorRecord::from_canonical_bytes(bytes).ok_or(Refusal::Malformed("record"))?;
        if let Some(prev) = registry.last() {
            if rec.index <= prev.index {
                return Err(Refusal::RegistryIncomplete { index: rec.index });
            }
        }
        let proof = cp.expand(&empty).ok_or(Refusal::RegistryProof { index: rec.index })?;
        if !verify_inclusion(&src.state_root, &validator_leaf_key(rec.index), &leaf_value_hash(bytes), &proof) {
            return Err(Refusal::RegistryProof { index: rec.index });
        }
        registry.push(rec);
    }
    // Every index in [0, max] not listed, then max+1, must be proven absent,
    // in ascending order and nothing else.
    let mut expected_absent: Vec<u32> = Vec::new();
    let mut next = 0u32;
    for r in &registry {
        while next < r.index {
            expected_absent.push(next);
            next += 1;
        }
        next = r.index.checked_add(1).ok_or(Refusal::Malformed("index overflow"))?;
    }
    expected_absent.push(next);
    if expected_absent.len() != cert.registry.absent.len() {
        let missing = expected_absent
            .iter()
            .find(|i| !cert.registry.absent.iter().any(|(a, _)| a == *i))
            .copied()
            .unwrap_or(next);
        return Err(Refusal::RegistryIncomplete { index: missing });
    }
    for (want, (got, cp)) in expected_absent.iter().zip(&cert.registry.absent) {
        if want != got {
            return Err(Refusal::RegistryIncomplete { index: *want });
        }
        let proof = cp.expand(&empty).ok_or(Refusal::RegistryIncomplete { index: *got })?;
        if !verify_absence(&src.state_root, &validator_leaf_key(*got), &proof) {
            return Err(Refusal::RegistryIncomplete { index: *got });
        }
    }

    // 4. Each link: unique sorted voters, active at the target, in-epoch,
    //    valid hybrid signature; then 3·signed ≥ 2·total.
    let mut stake = [(0u128, 0u128); 2];
    for (li, link) in cert.links.iter().enumerate() {
        let t = link.target_epoch;
        let active = |r: &ValidatorRecord| r.activation_epoch <= t && t < r.exit_epoch;
        let total: u128 = registry.iter().filter(|r| active(r)).map(|r| r.stake as u128).sum();
        let mut signed: u128 = 0;
        let mut last: Option<u32> = None;
        for v in &link.votes {
            if last.is_some_and(|p| v.validator <= p) {
                return Err(Refusal::DuplicateOrUnsortedVote { link: li, validator: v.validator });
            }
            last = Some(v.validator);
            let rec = registry
                .binary_search_by_key(&v.validator, |r| r.index)
                .ok()
                .map(|p| &registry[p])
                .filter(|r| active(r))
                .ok_or(Refusal::UnknownValidator { link: li, validator: v.validator })?;
            if epoch_of(v.slot) != t {
                return Err(Refusal::VoteOutsideEpoch { link: li, validator: v.validator });
            }
            if !sigs.verify(&rec.pubkey, &link.data(v).signing_root(), &v.signature) {
                return Err(Refusal::BadSignature { link: li, validator: v.validator });
            }
            if !rec.slashed {
                signed += rec.stake as u128;
            }
        }
        if total == 0 || signed * 3 < total * 2 {
            return Err(Refusal::InsufficientStake { link: li, signed, total });
        }
        stake[li] = (signed, total);
    }

    // 5. Ancestry: each header is the previous one's parent.
    let mut parent = cert.checkpoint_header.parent;
    let mut tip = None;
    for (i, h) in cert.ancestry.iter().enumerate() {
        let hid = id(h);
        if hid != parent {
            return Err(Refusal::AncestryBroken { at: i });
        }
        parent = h.parent;
        tip = Some((h.slot, hid));
    }

    Ok(Verified {
        epoch: e,
        root: l0.target_root,
        checkpoint_slot: cert.checkpoint_header.slot,
        checkpoint_state_root: cert.checkpoint_header.state_root,
        set_source_root: src_root,
        stake,
        votes: [l0.votes.len(), l1.votes.len()],
        ancestry_tip: tip,
    })
}

/// Verify a sequence; each verified checkpoint becomes trusted for the next
/// (the chain-of-certificates mode an L2 follower or exchange runs).
pub fn verify_chain(
    certs: &[Certificate],
    anchors: &mut TrustAnchors,
    sigs: &dyn SigCheck,
) -> Result<Vec<Verified>, (usize, Refusal)> {
    let mut out = Vec::with_capacity(certs.len());
    for (i, c) in certs.iter().enumerate() {
        let v = verify(c, anchors, sigs).map_err(|e| (i, e))?;
        anchors.roots.insert(v.root);
        out.push(v);
    }
    Ok(out)
}

// ─── Builder helpers (used by the node's RPC) ──────────────────────────────

/// Prove the whole registry of `state` against `header.state_root`. Returns
/// `None` if the state's tree does not commit to that root (wrong pairing).
pub fn registry_proof(
    state: &bloch_pos_committee::transition::CommittedState,
    header: BlockHeaderV4,
) -> Option<RegistryProof> {
    let tree = state.state_tree();
    if tree.root() != header.state_root {
        return None;
    }
    let empty = empty_subtree_hashes();
    let mut records = Vec::new();
    let mut absent = Vec::new();
    let mut next = 0u32;
    for rec in state.committed_validator_records() {
        while next < rec.index {
            let p = tree.prove_absence(&validator_leaf_key(next))?;
            absent.push((next, CompressedProof::compress(&p, &empty)));
            next += 1;
        }
        let p = tree.prove(&validator_leaf_key(rec.index))?;
        records.push((rec.canonical_bytes(), CompressedProof::compress(&p, &empty)));
        next = rec.index.checked_add(1)?;
    }
    let p = tree.prove_absence(&validator_leaf_key(next))?;
    absent.push((next, CompressedProof::compress(&p, &empty)));
    Some(RegistryProof { header, records, absent })
}

/// Encoded size breakdown, for reporting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SizeReport {
    pub total: usize,
    pub registry: usize,
    pub votes: [usize; 2],
    pub ancestry: usize,
}

pub fn size_report(c: &Certificate) -> SizeReport {
    let registry = 304
        + 8
        + c.registry.records.iter().map(|(b, p)| 4 + b.len() + p.encoded_len()).sum::<usize>()
        + c.registry.absent.iter().map(|(_, p)| 4 + p.encoded_len()).sum::<usize>();
    let votes = [0, 1].map(|i| {
        84 + c.links[i].votes.iter().map(|v| 48 + v.signature.len()).sum::<usize>()
    });
    SizeReport { total: c.encode().len(), registry, votes, ancestry: 4 + 304 * c.ancestry.len() }
}

/// Lower-case hex helpers (the CLI and RPC speak hex).
pub fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes().chunks(2).map(|p| Some(v(p[0])? << 4 | v(p[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::state_root::Smt;

    #[test]
    fn compressed_proof_roundtrips_and_absence_verifies() {
        let mut t = Smt::new();
        for i in 0..50u32 {
            if i == 7 {
                continue;
            }
            t.insert(validator_leaf_key(i), leaf_value_hash(&i.to_le_bytes()));
        }
        let empty = empty_subtree_hashes();
        let root = t.root();
        let p = t.prove(&validator_leaf_key(3)).unwrap();
        let c = CompressedProof::compress(&p, &empty);
        assert!(c.siblings.len() < 20);
        assert_eq!(c.expand(&empty).unwrap(), p);
        assert!(verify_inclusion(&root, &validator_leaf_key(3), &leaf_value_hash(&3u32.to_le_bytes()), &p));
        for gap in [7u32, 50, 1000] {
            let a = t.prove_absence(&validator_leaf_key(gap)).unwrap();
            assert!(verify_absence(&root, &validator_leaf_key(gap), &a), "gap {gap}");
            assert!(!verify_absence(&root, &validator_leaf_key(3), &a));
        }
        assert!(t.prove_absence(&validator_leaf_key(3)).is_none());
        // A present key's inclusion siblings must not pass as absence.
        assert!(!verify_absence(&root, &validator_leaf_key(3), &p));
        // Empty tree: everything absent.
        let e = Smt::new();
        let a = e.prove_absence(&validator_leaf_key(0)).unwrap();
        assert!(verify_absence(&e.root(), &validator_leaf_key(0), &a));
    }
}
