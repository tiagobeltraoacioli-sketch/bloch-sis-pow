// SPDX-License-Identifier: AGPL-3.0-or-later

//! `getlcproof` / `BLCLMP01` (`BLCLMP02` with a second bind proof): a finality certificate plus the state proofs
//! needed to judge it under every consensus signature and weight rule, from
//! one trusted block id. RPC and tool layer only: this reads committed state
//! and signed votes, and nothing here feeds a consensus input.
//!
//! The certificate alone ([`crate::verify`], format `BLOCHFC1`) checks each
//! vote against the static key under the v1 form. That stops working in two
//! steps, both of which this module handles:
//!
//! * from `params::SIG_CANONICAL_ACTIVATION_EPOCH` (HF2) votes use the bound v2
//!   form. Votes here go through `PolicyVerifier::consensus`, the call the
//!   transition makes;
//! * from the KES bind (`params::KES_ACTIVATION_EPOCH` or later) a registered
//!   validator signs with a KES leaf, and its key lives in component 0x22.
//!   [`KesProofs`] proves the bind epoch and each voter's entry or absence.
//!
//! [`FinalitySetProof`] adds the finality leaf (0x09) so that, from HF1, votes
//! are weighed by the frozen finality set the chain itself uses. It is mandatory
//! from a set source in the gate epoch on, so a bare certificate stops verifying
//! there. See `docs/specs/BLOCH-RPC-V4.md`
//! section 4.5b and `docs/LC-MAINNET-PATH.md` on the light-client branch, whose
//! `ffg` module is the origin of this rule and shares this wire format.

use crate::state::{decode_kes_entry, prove_absent, prove_leaf, FinalityLeaf, FrozenSet};
use crate::{Certificate, CompressedProof, RegistryProof};
use bloch_pos_committee::attestation::{KeyLookup, PolicyVerifier, SignatureVerifier};
use bloch_pos_committee::header::{BlockHeaderV4, BlockId};
use bloch_pos_committee::kes::{self, KesEntry, KesPublic};
use bloch_pos_committee::state_root::{
    empty_subtree_hashes, finality_leaf_key, kes_enforced_leaf_key, kes_leaf_key, leaf_value_hash, validator_leaf_key,
    Smt, ValidatorRecord,
};
use bloch_pos_committee::{epoch_of, params, SLOTS_PER_EPOCH};
use std::collections::{BTreeMap, BTreeSet};

/// Genesis-4 mainnet network domain (`getvalidatoradmission.network_domain`,
/// `CommittedState::admission_network_domain`): every KES leaf signature
/// commits to it (`kes::leaf_message`). Read from two public RPCs on
/// 2026-10-30; a light client pins it with its anchor.
pub const MAINNET_NETWORK_DOMAIN: [u8; 32] = [
    0xf4, 0x7d, 0x3e, 0x49, 0x8f, 0xf9, 0x78, 0xe3, 0x44, 0x71, 0xda, 0xff, 0xf5, 0xf9, 0x4f, 0xe1, 0x39, 0xfc, 0x3f,
    0xf4, 0x89, 0xb1, 0xa0, 0x0f, 0x46, 0x9c, 0x03, 0x02, 0x58, 0x31, 0x19, 0x66,
];

/// The KES extension: the bind-epoch leaf and one entry (or absence) per
/// voter, all against the set-source state root, and optionally the
/// bind-epoch leaf of the checkpoint's own state.
///
/// Freshness (security review round 2, CRY-2 / FC-5). The set source may be
/// up to `max_hop_epochs` older than the target, and an absence proven in an
/// old state says nothing about a later one:
///
/// * The bind is decided at the boundary into some epoch `n` and governs
///   from `n + KES_BIND_DELAY_EPOCHS`; the leaf is in every state from `n`
///   on. So "no bind" in a state of epoch `s` proves "static keys" only for
///   targets `t <= s + KES_BIND_DELAY_EPOCHS`. A later target is refused.
/// * A voter proven to have no entry may be judged by its static key past
///   the bind only if the set source is itself bound and in the target's
///   KES period: a first registration in a bound state starts in the period
///   after its inclusion, whereas one made before the bind signs from the
///   bind on, so an older absence cannot exclude it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KesProofs {
    /// Against the set-source state root. `Some(epoch)`: the committed bind
    /// epoch; `None`: proven absent.
    pub enforced: (Option<u64>, CompressedProof),
    /// The same leaf (or its absence) against the checkpoint header's state
    /// root, for the finalizing link only, and only when the set source
    /// proves the bind absent. The set source of a checkpoint cannot speak
    /// for the finalizing link's target (two epochs past the newest state a
    /// set source can be), so without this no step could be taken while the
    /// chain has not bound, nor across the bind. It is used after the
    /// justifying link has passed its quorum under the set source's proof,
    /// which is what backs the checkpoint's state root.
    pub enforced_at_checkpoint: Option<(Option<u64>, CompressedProof)>,
    /// `(validator, Some(entry bytes) | None, proof)`, ascending validator.
    pub entries: Vec<(u32, Option<Vec<u8>>, CompressedProof)>,
}

/// The frozen-finality-set extension: the finality leaf and its proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalitySetProof {
    pub leaf: Vec<u8>,
    pub proof: CompressedProof,
}

/// Everything one finality step needs.
#[derive(Clone, Debug)]
pub struct MainnetProof {
    pub cert: Certificate,
    pub finality_set: Option<FinalitySetProof>,
    pub kes: Option<KesProofs>,
}

/// What the light client is configured with, once.
#[derive(Clone, Debug)]
pub struct Config {
    pub network_domain: [u8; 32],
    /// Bound on (target epoch − set-source epoch): the registry / frozen set
    /// of the set source must be recent (weak subjectivity, as checkpoint
    /// sync). `crate::DEFAULT_MAX_HOP_EPOCHS` = 256.
    pub max_hop_epochs: u64,
}

impl Config {
    pub fn mainnet() -> Self {
        Config { network_domain: MAINNET_NETWORK_DOMAIN, max_hop_epochs: crate::DEFAULT_MAX_HOP_EPOCHS }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weights {
    /// Own bond of the set-source registry (pre-HF1 rule).
    Bond,
    /// The frozen finality set of the set source (HF1).
    Frozen { with_pending: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Shape(&'static str),
    UntrustedSetSource,
    SetSourceDistance,
    Registry(u32),
    RegistryIncomplete(u32),
    FinalitySet(&'static str),
    Kes(&'static str),
    DuplicateOrUnsortedVote(u32),
    UnknownValidator(u32),
    VoteOutsideEpoch(u32),
    BadSignature(u32),
    InsufficientWeight { link: usize, signed: u128, total: u128 },
    AncestryBroken(usize),
}

/// A checkpoint the light client now trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub epoch: u64,
    pub root: [u8; 32],
    pub checkpoint_header: BlockHeaderV4,
    pub set_source_root: [u8; 32],
    pub weights: Weights,
    /// `(signed, total)` for each link (and each set, for `Frozen` the
    /// smaller margin of current/pending is reported).
    pub stake: [(u128, u128); 2],
    pub votes: [usize; 2],
    pub kes_votes: usize,
    /// The lowest header of the ancestry (finalized by implication).
    pub ancestry_tip: Option<BlockHeaderV4>,
}

/// What a link knows about the KES bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bind {
    /// The committed bind epoch.
    At(u64),
    /// Proven absent in a state of this epoch.
    AbsentIn(u64),
}

/// May a voter proven to have no KES entry in a set-source state of epoch
/// `src_epoch` be judged by its static key at `target`, given that KES binds
/// from `bound_from <= target`? Only if that state is itself bound (a first
/// registration made in a bound state starts in the period after its
/// inclusion; one made before the bind signs from the bind on) and in the
/// target's KES period.
fn static_fallback_is_fresh(bound_from: u64, src_epoch: u64, target: u64) -> bool {
    src_epoch >= bound_from && params::kes_period(target) == params::kes_period(src_epoch)
}

fn id(h: &BlockHeaderV4) -> [u8; 32] {
    *BlockId::of(h).as_bytes()
}

/// Validator keys proven against one state root: static keys from registry
/// records, KES entries and the bind epoch from component 0x22.
pub struct ProvenKeys<'a> {
    pub records: &'a BTreeMap<u32, ValidatorRecord>,
    pub kes: BTreeMap<u32, KesEntry>,
    /// Validators proven to have no KES entry.
    pub kes_absent: BTreeSet<u32>,
    /// `None` when no KES proofs were given (fails closed past the gate).
    pub enforced: Option<Option<u64>>,
    pub network_domain: [u8; 32],
}

impl KeyLookup for ProvenKeys<'_> {
    fn pubkey(&self, validator: u32) -> Option<&[u8]> {
        self.records.get(&validator).map(|r| r.pubkey.as_slice())
    }
    fn kes_public(&self, validator: u32, period: u64) -> Option<KesPublic> {
        self.kes.get(&validator).and_then(|e| e.resolve(period))
    }
    fn kes_network_domain(&self) -> Option<[u8; 32]> {
        Some(self.network_domain)
    }
    fn kes_enforced_from(&self) -> Option<Option<u64>> {
        self.enforced
    }
}

/// Verify one finality step under `trusted` block ids (the anchor and every
/// checkpoint verified before). Pure: no clock, no I/O.
pub fn verify(
    p: &MainnetProof,
    trusted: &BTreeSet<[u8; 32]>,
    cfg: &Config,
    sigs: &dyn SignatureVerifier,
) -> Result<Verified, Refusal> {
    let cert = &p.cert;
    let [l0, l1] = &cert.links;
    let e = l0.target_epoch;

    // 1. Shape: S→E then E→E+1; the checkpoint header IS (E, R).
    if l0.source_epoch >= e {
        return Err(Refusal::Shape("justifying link source not before target"));
    }
    if l1.source_epoch != e || l1.source_root != l0.target_root || e.checked_add(1) != Some(l1.target_epoch) {
        return Err(Refusal::Shape("finalizing link is not (E,R) -> E+1"));
    }
    if id(&cert.checkpoint_header) != l0.target_root {
        return Err(Refusal::Shape("checkpoint header is not the target root"));
    }
    let first_e = e.checked_mul(SLOTS_PER_EPOCH).ok_or(Refusal::Shape("epoch overflow"))?;
    if cert.checkpoint_header.slot >= first_e {
        return Err(Refusal::Shape("checkpoint block not before its epoch"));
    }

    // 2. Set source: trusted, before E, within the hop bound.
    let src = &cert.registry.header;
    if !trusted.contains(&id(src)) {
        return Err(Refusal::UntrustedSetSource);
    }
    if src.slot >= first_e || e - epoch_of(src.slot) > cfg.max_hop_epochs {
        return Err(Refusal::SetSourceDistance);
    }
    let root = src.state_root;

    // 3. Weights. No choice of rule: bond and frozen weights disagree in both
    //    directions, so a prover free to omit the leaf could pick the rule that
    //    accepts. From the gate epoch on the leaf is mandatory. An epoch's fold
    //    runs at its closing boundary, so a set source in the gate epoch commits
    //    no set yet: only there may a proven leaf without a set mean bond.
    let src_epoch = epoch_of(src.slot);
    let gate = params::HF1_FROZEN_FINALITY_SET_EPOCH;
    let frozen: Option<(FrozenSet, Option<FrozenSet>)> = match &p.finality_set {
        None if src_epoch >= gate => {
            return Err(Refusal::FinalitySet("finality leaf required from the frozen-set gate"));
        }
        None => None,
        Some(fp) => {
            if !prove_leaf(&root, &finality_leaf_key(), &fp.leaf, &fp.proof) {
                return Err(Refusal::FinalitySet("leaf not committed"));
            }
            let leaf = FinalityLeaf::decode(&fp.leaf).ok_or(Refusal::FinalitySet("malformed leaf"))?;
            match leaf.finality_set {
                Some(set) => Some((set.current, set.pending)),
                None if src_epoch <= gate => None,
                None => return Err(Refusal::FinalitySet("no frozen set in this state")),
            }
        }
    };

    // 4. Registry records against the set-source root. The bond rule needs
    //    the registry complete (no member omitted to shrink the
    //    denominator); with the frozen set the denominator is committed and
    //    a record only supplies a voter's key.
    let mut records: BTreeMap<u32, ValidatorRecord> = BTreeMap::new();
    let mut last: Option<u32> = None;
    for (bytes, cp) in &cert.registry.records {
        let rec = ValidatorRecord::from_canonical_bytes(bytes).ok_or(Refusal::Registry(u32::MAX))?;
        if last.is_some_and(|l| rec.index <= l) {
            return Err(Refusal::RegistryIncomplete(rec.index));
        }
        last = Some(rec.index);
        if !prove_leaf(&root, &validator_leaf_key(rec.index), bytes, cp) {
            return Err(Refusal::Registry(rec.index));
        }
        records.insert(rec.index, rec);
    }
    if frozen.is_none() {
        let mut expected = Vec::new();
        let mut next = 0u32;
        for i in records.keys() {
            while next < *i {
                expected.push(next);
                next += 1;
            }
            next = i.checked_add(1).ok_or(Refusal::RegistryIncomplete(*i))?;
        }
        expected.push(next);
        if expected.len() != cert.registry.absent.len() {
            return Err(Refusal::RegistryIncomplete(next));
        }
        for (want, (got, cp)) in expected.iter().zip(&cert.registry.absent) {
            if want != got || !prove_absent(&root, &validator_leaf_key(*got), cp) {
                return Err(Refusal::RegistryIncomplete(*want));
            }
        }
    }

    // 5. KES keys (required for targets at or past the KES gate). `binds`
    //    is what each link is judged under.
    let mut binds: [Option<Bind>; 2] = [None, None];
    let mut keys = ProvenKeys {
        records: &records,
        kes: BTreeMap::new(),
        kes_absent: BTreeSet::new(),
        enforced: None,
        network_domain: cfg.network_domain,
    };
    match &p.kes {
        None => {
            if params::kes_period(l1.target_epoch).is_some() {
                return Err(Refusal::Kes("KES proofs required past the KES gate"));
            }
        }
        Some(kp) => {
            let (enforced, ep) = &kp.enforced;
            // Against the set-source root only. (A bind proven solely by the
            // checkpoint's own state used to be accepted here; that state is
            // backed by nothing until the justifying link has been judged,
            // and the justifying link was then judged under it.)
            let ok = match enforced {
                Some(epoch) => prove_leaf(&root, &kes_enforced_leaf_key(), &epoch.to_le_bytes(), ep),
                None => prove_absent(&root, &kes_enforced_leaf_key(), ep),
            };
            if !ok {
                return Err(Refusal::Kes("bind epoch not proven"));
            }
            binds[0] = Some(match enforced {
                Some(epoch) => Bind::At(*epoch),
                None => Bind::AbsentIn(src_epoch),
            });
            binds[1] = binds[0];
            // The finalizing link may take the bind from the checkpoint's
            // own state root, when the set source does not commit one. Step
            // 6 reads it only after the justifying link passed its quorum.
            if let Some((at_checkpoint, cp)) = &kp.enforced_at_checkpoint {
                if enforced.is_some() {
                    return Err(Refusal::Kes("checkpoint bind proof beside a bind at the set source"));
                }
                let cp_root = cert.checkpoint_header.state_root;
                let ok = match at_checkpoint {
                    Some(epoch) => prove_leaf(&cp_root, &kes_enforced_leaf_key(), &epoch.to_le_bytes(), cp),
                    None => prove_absent(&cp_root, &kes_enforced_leaf_key(), cp),
                };
                if !ok {
                    return Err(Refusal::Kes("checkpoint bind epoch not proven"));
                }
                binds[1] = Some(match at_checkpoint {
                    Some(epoch) => Bind::At(*epoch),
                    None => Bind::AbsentIn(epoch_of(cert.checkpoint_header.slot)),
                });
            }
            let mut last = None;
            for (v, bytes, cp) in &kp.entries {
                if last.is_some_and(|l| *v <= l) {
                    return Err(Refusal::Kes("entries not ascending"));
                }
                last = Some(*v);
                match bytes {
                    Some(b) => {
                        if !prove_leaf(&root, &kes_leaf_key(*v), b, cp) {
                            return Err(Refusal::Kes("entry not committed"));
                        }
                        keys.kes.insert(*v, decode_kes_entry(b).ok_or(Refusal::Kes("malformed entry"))?);
                    }
                    None => {
                        if !prove_absent(&root, &kes_leaf_key(*v), cp) {
                            return Err(Refusal::Kes("absence not proven"));
                        }
                        keys.kes_absent.insert(*v);
                    }
                }
            }
        }
    }

    // 6. Links.
    let mut stake = [(0u128, 0u128); 2];
    let mut kes_votes = 0usize;
    for (li, link) in cert.links.iter().enumerate() {
        let t = link.target_epoch;
        let active = |r: &ValidatorRecord| r.activation_epoch <= t && t < r.exit_epoch;
        // An absence proves "static keys" only for the epochs a bind decided
        // right after that state could not reach yet.
        if let (Some(_), Some(Bind::AbsentIn(at))) = (params::kes_period(t), binds[li]) {
            if t > at.saturating_add(params::KES_BIND_DELAY_EPOCHS) {
                return Err(Refusal::Kes("bind absence too old for this target"));
            }
        }
        keys.enforced = binds[li].map(|bind| match bind {
            Bind::At(epoch) => Some(epoch),
            Bind::AbsentIn(_) => None,
        });
        let bound_from = match binds[li] {
            Some(Bind::At(b)) if params::kes_period(t).is_some() && t >= b => Some(b),
            _ => None,
        };
        let kes_on = bound_from.is_some();
        // Whether "no KES entry at the set source" still holds at `t`.
        let absence_is_fresh = bound_from.is_some_and(|b| static_fallback_is_fresh(b, src_epoch, t));
        let mut signers: Vec<u32> = Vec::with_capacity(link.votes.len());
        let mut last: Option<u32> = None;
        for v in &link.votes {
            if last.is_some_and(|l| v.validator <= l) {
                return Err(Refusal::DuplicateOrUnsortedVote(v.validator));
            }
            last = Some(v.validator);
            let rec = records.get(&v.validator).filter(|r| active(r)).ok_or(Refusal::UnknownValidator(v.validator))?;
            if epoch_of(v.slot) != t {
                return Err(Refusal::VoteOutsideEpoch(v.validator));
            }
            // Past the bind, a validator must be proven KES-registered or
            // proven unregistered (static fallback); an unproven one is refused.
            if kes_on && !keys.kes.contains_key(&v.validator) && !keys.kes_absent.contains(&v.validator) {
                return Err(Refusal::Kes("voter's KES entry not proven"));
            }
            if kes_on && keys.kes_absent.contains(&v.validator) && !absence_is_fresh {
                return Err(Refusal::Kes("voter absence too old"));
            }
            let verifier = PolicyVerifier::consensus(sigs, epoch_of(v.slot));
            let data = link.data(v);
            if kes::verify_validator(&keys, &verifier, v.validator, t, &data.signing_root(), &v.signature) != Some(true) {
                return Err(Refusal::BadSignature(v.validator));
            }
            if kes_on && keys.kes.contains_key(&v.validator) {
                kes_votes += 1;
            }
            if !rec.slashed {
                signers.push(v.validator);
            }
        }
        let tally = |weight: &dyn Fn(u32) -> u128, total: u128| -> Result<(u128, u128), Refusal> {
            let signed: u128 = signers.iter().map(|v| weight(*v)).sum();
            if total == 0 || signed * 3 < total * 2 {
                return Err(Refusal::InsufficientWeight { link: li, signed, total });
            }
            Ok((signed, total))
        };
        stake[li] = match &frozen {
            None => {
                let total: u128 = records.values().filter(|r| active(r)).map(|r| r.stake as u128).sum();
                tally(&|v| records[&v].stake as u128, total)?
            }
            Some((current, pending)) => {
                let c = tally(&|v| current.weight(v) as u128, current.total())?;
                match pending {
                    None => c,
                    Some(p) => {
                        let q = tally(&|v| p.weight(v) as u128, p.total())?;
                        // Report the tighter margin.
                        if q.0 * c.1 < c.0 * q.1 { q } else { c }
                    }
                }
            }
        };
    }

    // 7. Ancestry: each header the previous one's parent.
    let mut parent = cert.checkpoint_header.parent;
    let mut tip = None;
    for (i, h) in cert.ancestry.iter().enumerate() {
        if id(h) != parent {
            return Err(Refusal::AncestryBroken(i));
        }
        parent = h.parent;
        tip = Some(*h);
    }

    Ok(Verified {
        epoch: e,
        root: l0.target_root,
        checkpoint_header: cert.checkpoint_header,
        set_source_root: id(src),
        weights: match &frozen {
            None => Weights::Bond,
            Some((_, pending)) => Weights::Frozen { with_pending: pending.is_some() },
        },
        stake,
        votes: [l0.votes.len(), l1.votes.len()],
        kes_votes,
        ancestry_tip: tip,
    })
}

/// One step of a client that walks the chain: [`verify`], then the verified
/// checkpoint becomes the ONLY trusted block id, and it must be newer than
/// the checkpoint the client stood on (`after_epoch`, `None` for an anchor
/// whose epoch the caller does not track).
///
/// Every caller that keeps a trusted set across steps goes through this
/// (security review round 2, CRY-2 / FC-5). A set that only grows keeps old
/// roots usable as set sources for ever, and the older the set source the
/// less its state says about the keys in force at the target; a client that
/// has verified epoch `E` has no use for a set source before it. On a
/// refusal `trusted` is unchanged.
pub fn verify_next(
    p: &MainnetProof,
    trusted: &mut BTreeSet<[u8; 32]>,
    after_epoch: Option<u64>,
    cfg: &Config,
    sigs: &dyn SignatureVerifier,
) -> Result<Verified, Refusal> {
    let v = verify(p, trusted, cfg, sigs)?;
    if after_epoch.is_some_and(|newest| v.epoch <= newest) {
        return Err(Refusal::Shape("target not after the trusted checkpoint"));
    }
    trusted.clear();
    trusted.insert(v.root);
    Ok(v)
}

/// Chain-of-certificates: each verified checkpoint is the trusted one for
/// the next ([`verify_next`]). On return `trusted` holds only the newest
/// verified root.
pub fn verify_chain(
    proofs: &[MainnetProof],
    trusted: &mut BTreeSet<[u8; 32]>,
    cfg: &Config,
    sigs: &dyn SignatureVerifier,
) -> Result<Vec<Verified>, (usize, Refusal)> {
    let mut out: Vec<Verified> = Vec::with_capacity(proofs.len());
    for (i, p) in proofs.iter().enumerate() {
        let after = out.last().map(|v| v.epoch);
        let v = verify_next(p, trusted, after, cfg, sigs).map_err(|e| (i, e))?;
        out.push(v);
    }
    Ok(out)
}

// ─── Wire format of a step proof (host → guest, RPC) ───────────────────────

/// Magic + version of [`MainnetProof::encode`] for a proof without
/// [`KesProofs::enforced_at_checkpoint`]: the format every released verifier
/// reads, byte for byte what it was.
pub const PROOF_MAGIC: &[u8; 8] = b"BLCLMP01";
/// Magic + version of a proof that carries
/// [`KesProofs::enforced_at_checkpoint`], appended after the KES entries.
/// One proof has one encoding: `02` always carries the second proof, `01`
/// never does.
pub const PROOF_MAGIC_V2: &[u8; 8] = b"BLCLMP02";

fn put_proof(o: &mut Vec<u8>, p: &CompressedProof) {
    o.extend_from_slice(&p.bitmap);
    o.extend_from_slice(&(p.siblings.len() as u16).to_le_bytes());
    for s in &p.siblings {
        o.extend_from_slice(s);
    }
}

fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_le_bytes());
    o.extend_from_slice(b);
}

struct Rd<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.b.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn proof(&mut self) -> Option<CompressedProof> {
        let bitmap: [u8; 32] = self.take(32)?.try_into().ok()?;
        let n = self.u16()? as usize;
        if n > 256 {
            return None;
        }
        let mut siblings = Vec::with_capacity(n);
        for _ in 0..n {
            siblings.push(self.take(32)?.try_into().ok()?);
        }
        Some(CompressedProof { bitmap, siblings })
    }
}

impl MainnetProof {
    pub fn encode(&self) -> Vec<u8> {
        let second = self.kes.as_ref().and_then(|k| k.enforced_at_checkpoint.as_ref());
        let mut o = if second.is_some() { PROOF_MAGIC_V2.to_vec() } else { PROOF_MAGIC.to_vec() };
        put_bytes(&mut o, &self.cert.encode());
        match &self.finality_set {
            None => o.push(0),
            Some(fs) => {
                o.push(1);
                put_bytes(&mut o, &fs.leaf);
                put_proof(&mut o, &fs.proof);
            }
        }
        match &self.kes {
            None => o.push(0),
            Some(k) => {
                o.push(1);
                match k.enforced.0 {
                    None => o.push(0),
                    Some(e) => {
                        o.push(1);
                        o.extend_from_slice(&e.to_le_bytes());
                    }
                }
                put_proof(&mut o, &k.enforced.1);
                o.extend_from_slice(&(k.entries.len() as u32).to_le_bytes());
                for (v, bytes, p) in &k.entries {
                    o.extend_from_slice(&v.to_le_bytes());
                    match bytes {
                        None => o.push(0),
                        Some(b) => {
                            o.push(1);
                            put_bytes(&mut o, b);
                        }
                    }
                    put_proof(&mut o, p);
                }
                if let Some((at_checkpoint, p)) = &k.enforced_at_checkpoint {
                    match at_checkpoint {
                        None => o.push(0),
                        Some(e) => {
                            o.push(1);
                            o.extend_from_slice(&e.to_le_bytes());
                        }
                    }
                    put_proof(&mut o, p);
                }
            }
        }
        o
    }

    /// Strict inverse of [`Self::encode`].
    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Rd { b, at: 0 };
        let v2 = match r.take(8)? {
            m if m == PROOF_MAGIC => false,
            m if m == PROOF_MAGIC_V2 => true,
            _ => return None,
        };
        let cert = Certificate::decode(r.bytes()?).ok()?;
        let finality_set = match r.u8()? {
            0 => None,
            1 => Some(FinalitySetProof { leaf: r.bytes()?.to_vec(), proof: r.proof()? }),
            _ => return None,
        };
        let kes = match r.u8()? {
            0 => None,
            1 => {
                let enforced = match r.u8()? {
                    0 => None,
                    1 => Some(r.u64()?),
                    _ => return None,
                };
                let ep = r.proof()?;
                let n = r.u32()? as usize;
                if n > crate::MAX_VOTES_PER_LINK {
                    return None;
                }
                let mut entries = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    let v = r.u32()?;
                    let bytes = match r.u8()? {
                        0 => None,
                        1 => Some(r.bytes()?.to_vec()),
                        _ => return None,
                    };
                    entries.push((v, bytes, r.proof()?));
                }
                let enforced_at_checkpoint = if v2 {
                    let at_checkpoint = match r.u8()? {
                        0 => None,
                        1 => Some(r.u64()?),
                        _ => return None,
                    };
                    Some((at_checkpoint, r.proof()?))
                } else {
                    None
                };
                Some(KesProofs { enforced: (enforced, ep), enforced_at_checkpoint, entries })
            }
            _ => return None,
        };
        // `02` exists only to carry the second proof.
        if v2 && kes.is_none() {
            return None;
        }
        (r.at == b.len()).then_some(MainnetProof { cert, finality_set, kes })
    }
}

// ─── Builder helpers (used by the node's RPC) ──────────────────────────────

/// The extensions of one checkpoint, proven once per epoch by the node next to
/// the registry proof, and narrowed to the voters of a certificate on request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckpointExtensions {
    /// `None` below the HF1 frozen-set gate.
    pub finality_set: Option<FinalitySetProof>,
    /// `None` before KES registration opens.
    pub kes: Option<KesProofs>,
}

impl KesProofs {
    /// Attach the checkpoint's own bind proof (`checkpoint`: the extensions
    /// proven for the checkpoint block) when [`verify`] needs it: the set
    /// source proves the bind absent and the finalizing link's target
    /// `finalizing_target` is at or past the KES gate. Otherwise the proof
    /// is left as it is, and keeps the `BLCLMP01` encoding.
    pub fn with_checkpoint_bind(mut self, checkpoint: Option<&KesProofs>, finalizing_target: u64) -> Self {
        if self.enforced.0.is_none() && params::kes_period(finalizing_target).is_some() {
            if let Some(cp) = checkpoint {
                self.enforced_at_checkpoint = Some(cp.enforced.clone());
            }
        }
        self
    }
}

impl CheckpointExtensions {
    /// Everything a proof for `voters` needs: only those voters' KES entries.
    pub fn for_voters(&self, voters: &BTreeSet<u32>) -> Self {
        let mut out = self.clone();
        if let Some(k) = out.kes.as_mut() {
            k.entries.retain(|(v, _, _)| voters.contains(v));
        }
        out
    }
}

/// [`crate::registry_proof`] plus the extensions, from one tree build: the
/// tree is the expensive part, and every proof must come from the tree whose
/// root the header commits. `None` on a state that does not commit to the
/// header's root.
pub fn checkpoint_proofs(
    state: &bloch_pos_committee::transition::CommittedState,
    header: BlockHeaderV4,
) -> Option<(RegistryProof, CheckpointExtensions)> {
    let tree = state.state_tree();
    let registry = crate::registry_proof_in(&tree, state, header)?;
    let finality_set = finality_set_proof(&tree, state, epoch_of(header.slot));
    let kes = kes_proofs(&tree, state, epoch_of(header.slot));
    Some((registry, CheckpointExtensions { finality_set, kes }))
}

fn compress(p: &bloch_pos_committee::state_root::InclusionProof) -> CompressedProof {
    CompressedProof::compress(p, &empty_subtree_hashes())
}

fn finality_set_proof(
    tree: &Smt,
    state: &bloch_pos_committee::transition::CommittedState,
    epoch: u64,
) -> Option<FinalitySetProof> {
    let record = state.committed_finality_record();
    // Pre-gate blocks need no leaf; a block of the gate epoch serves its leaf
    // even without a set, because `verify` requires it there.
    if record.finality_set.is_none() && epoch < params::HF1_FROZEN_FINALITY_SET_EPOCH {
        return None;
    }
    let leaf = record.committed_bytes();
    let key = finality_leaf_key();
    // The tree is the authority: bytes it does not commit are never served.
    if tree.get(&key) != Some(leaf_value_hash(&leaf)) {
        return None;
    }
    Some(FinalitySetProof { leaf, proof: compress(&tree.prove(&key)?) })
}

fn kes_proofs(
    tree: &Smt,
    state: &bloch_pos_committee::transition::CommittedState,
    epoch: u64,
) -> Option<KesProofs> {
    if !params::kes_registration_open(epoch) {
        return None;
    }
    let bind = kes_enforced_leaf_key();
    let enforced = match state.kes_enforced_from() {
        Some(e) => {
            if tree.get(&bind) != Some(leaf_value_hash(&e.to_le_bytes())) {
                return None;
            }
            (Some(e), compress(&tree.prove(&bind)?))
        }
        None => (None, compress(&tree.prove_absence(&bind)?)),
    };
    let roots = state.kes_roots();
    let mut entries = Vec::new();
    for rec in state.committed_validator_records() {
        let key = kes_leaf_key(rec.index);
        match roots.get(&rec.index) {
            Some(entry) => {
                let bytes = entry.committed_bytes();
                if tree.get(&key) != Some(leaf_value_hash(&bytes)) {
                    return None;
                }
                entries.push((rec.index, Some(bytes), compress(&tree.prove(&key)?)));
            }
            None => entries.push((rec.index, None, compress(&tree.prove_absence(&key)?))),
        }
    }
    Some(KesProofs { enforced, enforced_at_checkpoint: None, entries })
}

/// Drop votes the set source cannot judge. A validator activated after the
/// set source, or already exited at the link's target, weighs nothing under
/// that set, yet [`verify`] refuses a certificate that lists it; the chain
/// counted the vote under its own later roster, so the node may hold one.
pub fn retain_provable_votes(cert: &mut Certificate) {
    let records: BTreeMap<u32, ValidatorRecord> = cert
        .registry
        .records
        .iter()
        .filter_map(|(b, _)| ValidatorRecord::from_canonical_bytes(b).map(|r| (r.index, r)))
        .collect();
    for link in cert.links.iter_mut() {
        let t = link.target_epoch;
        link.votes.retain(|v| {
            records.get(&v.validator).is_some_and(|r| r.activation_epoch <= t && t < r.exit_epoch)
        });
    }
}

/// Drop static votes [`verify`] would refuse as `voter absence too old`: on
/// a link that KES binds, the votes of validators `kes` proves to have no
/// entry, when the set source is not bound or not in the target's KES period
/// (the bind is read as [`verify`] reads it: the checkpoint's proof for the
/// finalizing link when there is one). The chain counted those votes under
/// its own, later, state; this set source cannot vouch for them, and one of
/// them makes the whole proof refused. Whether the quorum holds without
/// them is for [`verify`] to say.
pub fn retain_fresh_static_votes(cert: &mut Certificate, kes: &KesProofs) {
    let src_epoch = epoch_of(cert.registry.header.slot);
    let absent: BTreeSet<u32> = kes.entries.iter().filter(|(_, bytes, _)| bytes.is_none()).map(|(v, _, _)| *v).collect();
    for (li, link) in cert.links.iter_mut().enumerate() {
        let t = link.target_epoch;
        let bind = match (&kes.enforced_at_checkpoint, li) {
            (Some((at_checkpoint, _)), 1) if kes.enforced.0.is_none() => *at_checkpoint,
            _ => kes.enforced.0,
        };
        let Some(b) = bind.filter(|b| params::kes_period(t).is_some() && t >= *b) else { continue };
        if !static_fallback_is_fresh(b, src_epoch, t) {
            link.votes.retain(|v| !absent.contains(&v.validator));
        }
    }
}

// ─── The production signature check ────────────────────────────────────────

/// The node's `HybridVerifier` for consensus messages: the same `bloch_crypto`
/// call behind each trait method it overrides (`bloch-pos-node/src/keys.rs`).
#[cfg(feature = "hybrid")]
pub struct HybridConsensusVerifier;

#[cfg(feature = "hybrid")]
impl SignatureVerifier for HybridConsensusVerifier {
    fn verify_with_key(&self, pubkey: &[u8], signing_root: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::verify(pubkey, signing_root, signature)
    }

    fn verify_with_key_under(
        &self,
        policy: bloch_pos_committee::SignaturePolicy,
        pubkey: &[u8],
        signing_root: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        use bloch_crypto::crypto::SignaturePolicy as C;
        use bloch_pos_committee::SignaturePolicy as P;
        let policy = match policy {
            P::Compatible => C::Compatible,
            P::CompatiblePinned => C::CompatiblePinned,
            P::CanonicalUnbound => C::CanonicalUnbound,
            P::Bound => C::Bound,
        };
        bloch_crypto::crypto::verify_with_policy(policy, pubkey, signing_root, signature)
    }

    /// KES leaves are always in the bound form.
    fn verify_kes_leaf(&self, leaf_pk: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        bloch_crypto::crypto::verify_bound(leaf_pk, message, signature)
    }
}
