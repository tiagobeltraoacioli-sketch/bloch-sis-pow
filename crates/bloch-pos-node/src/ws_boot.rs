// SPDX-License-Identifier: AGPL-3.0-or-later

//! Weak-subjectivity boot wiring — the node-side consumer of
//! `bloch_pos_committee::ws` (BLOCH-WEAK-SUBJECTIVITY.md §4).
//!
//! The pure crate decides; this module supplies what the decision functions
//! declare as inputs and acts on what they return. Nothing here re-derives a
//! rule that `ws.rs` already states: the window, the anti-rollback order, the
//! four boot states, the never-reorg cross-check and the genesis anchor are
//! all called, not copied.
//!
//! ## What is wired, at boot, in order
//!
//! 1. **`ws_latest`** (§4.1): the highest-epoch checkpoint this node has ever
//!    verified, persisted as `ws_latest.bin` (the 154 canonical bytes) in the
//!    data dir. When none exists the **genesis anchor is the first
//!    checkpoint** ([`ws::genesis_anchor`]): trusting it is trusting the
//!    genesis manifest, the same trust every node of the network already
//!    makes to exist at all — which is exactly why a fresh devnet still boots
//!    with no flags.
//! 2. **`--ws-checkpoint <file>`**: a [`CheckpointEnvelope`] loaded from disk
//!    and verified m-of-n under the real hybrid suite
//!    ([`ws::verify_envelope`] through [`WsHybridVerifier`] →
//!    `bloch_crypto`). This devnet build bakes no Phase A signer keys, so the
//!    arrangement comes from `--ws-signer-set <file>`; a release build will
//!    hard-code the §6 sets and the flag becomes an override.
//! 3. **Anti-rollback** ([`ws::accept`]): an envelope older than `ws_latest`
//!    is logged and ignored; the same epoch with a different digest is
//!    [`Acceptance::Conflict`] and refuses the boot loudly — a stolen old
//!    quorum signature must not refresh a node backward, and an equivocal
//!    publication must never be silently overwritten.
//! 4. **Cross-check** ([`ws::cross_check`]): a published checkpoint NEVER
//!    reorganizes a node that has finality of its own. A conflict is a
//!    screaming alarm and the node keeps its database; only the newcomer and
//!    the long-offline can be moved by the signers.
//! 5. **The four boot states** ([`ws::boot_decision`], §4.2): `Resume` /
//!    `ResumeStaleWarn` proceed (the latter warns), `RequireCheckpoint` and
//!    `RefuseStale` refuse to sync unless a sufficiently fresh anchor exists —
//!    and the refusal is the mechanism working, so the error message says so
//!    and tells the operator where a checkpoint comes from.
//!
//! After boot the engine enforces the anchor forward: when its own finality
//! first reaches the anchor's epoch it compares roots ([`ws::cross_check`]
//! again, from live state). A node that had no finality of its own at boot
//! treats a mismatch as fatal — a fresh node must never keep following a
//! chain that contradicts its trust anchor; a node that booted on its own
//! finality treats it as the WS_CONFLICT alarm, never a reorg.
//!
//! ## Honestly not wired (devnet stage)
//!
//! Checkpoint-sync state download (§4.3.2) does not exist — this node syncs
//! by replaying full blocks from genesis, so a non-genesis anchor is a
//! *floor and cross-check*, not a sync starting point. Consequently the
//! `RefuseStale` recovery can only establish "checkpoint descends from local
//! history" against blocks it already has; a fresh checkpoint beyond the
//! local head halts for the operator instead of header-syncing forward, and
//! `--ws-accept-reorg` is not implemented.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use bloch_pos_committee::staking::{HybridKeyVerifier, HYBRID_PK_BYTES};
use bloch_pos_committee::ws::{
    self, Acceptance, BootDecision, CheckpointEnvelope, CrossCheck, Reconciliation, Signer,
    SignerSet, WeakSubjectivityCheckpoint,
};

use crate::codec::{DecodeErr, Reader};

/// A policy refusal requires operator action, not an automatic restart loop.
/// Keep this separate from ordinary permissions and transient filesystem errors.
#[derive(Debug)]
pub struct BootRefused(String);

impl std::fmt::Display for BootRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.0.fmt(f) }
}
impl std::error::Error for BootRefused {}

pub fn boot_refused(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, BootRefused(message.into()))
}

pub fn is_non_retryable(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|cause| cause.is::<BootRefused>())
}

// ---------------------------------------------------------------------------
// The hybrid verifier the envelope check runs under
// ---------------------------------------------------------------------------

/// The real ML-DSA-65 ‖ Falcon-1024 verifier for checkpoint envelopes.
///
/// `ws::verify_envelope` receives the halves pre-split at the fixed points
/// (the AND-composition lives in `staking::verify_hybrid`, called — not
/// copied); each half goes to its own primitive in `bloch_crypto`. Distinct
/// from [`crate::keys::HybridVerifier`], which serves the consensus signature
/// checks — checkpoint signers are not validators. (Both are key-based now:
/// `HybridVerifier` lost its index table on 2026-09-02, when the consensus
/// call sites started resolving keys from the committed registry.)
pub struct WsHybridVerifier;

impl HybridKeyVerifier for WsHybridVerifier {
    fn verify_mldsa65(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify_mldsa65_raw(pubkey, signing_root, sig)
    }
    fn verify_falcon1024(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        bloch_crypto::crypto::falcon::verify(pubkey, signing_root, sig)
    }
}

/// Devnet network id, derived from the genesis-manifest digest: each devnet
/// is its own network, so a checkpoint from one can never verify on another
/// (`WrongNetwork`/`WrongGenesisRoot` by construction). The mainnet manifest
/// format — a superset that does not exist yet — will carry an explicit,
/// published network id instead.
pub fn network_id_of(genesis_digest: &[u8; 32]) -> u32 {
    // Destructuring a fixed-size array: no length check, nothing to fail.
    let [b0, b1, b2, b3, ..] = *genesis_digest;
    u32::from_le_bytes([b0, b1, b2, b3])
}

// ---------------------------------------------------------------------------
// File forms. The checkpoint's canonical 154 bytes are the committee crate's;
// everything here only frames them (same division of labor as codec.rs).
// ---------------------------------------------------------------------------

const WS_ENVELOPE_MAGIC: &[u8; 8] = b"BPOSWSE1";
const WS_SIGNER_SET_MAGIC: &[u8; 8] = b"BPOSWSS1";
const WS_PARTIAL_MAGIC: &[u8; 8] = b"BPOSWSP1";
/// `signer_index` is a u8 in the envelope, so no artifact can carry more.
const MAX_SIGNERS: usize = 256;

/// Decode the canonical checkpoint bytes. The committee crate's
/// `canonical_serialize` is the single authority on the layout; this decoder
/// proves itself against it on every call by re-serializing and comparing —
/// a drift between the two cannot silently mint a second byte layout.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<WeakSubjectivityCheckpoint, DecodeErr> {
    if bytes.len() != ws::WS_CHECKPOINT_BYTES {
        return Err(DecodeErr("checkpoint: wrong length"));
    }
    let mut r = Reader::new(bytes);
    let cp = WeakSubjectivityCheckpoint {
        version: r.u16()?,
        network_id: r.u32()?,
        genesis_root: r.h32()?,
        epoch: r.u64()?,
        block_root: r.h32()?,
        state_root: r.h32()?,
        validator_set_root: r.h32()?,
        issued_at: r.u64()?,
        signer_set_id: r.u32()?,
    };
    r.finish()?;
    if cp.canonical_serialize() != bytes {
        return Err(DecodeErr("checkpoint: decoder disagrees with canonical_serialize"));
    }
    Ok(cp)
}

/// Encode a distribution envelope: magic ‖ canonical checkpoint ‖ signature
/// list. This is the node's file framing of the spec's `wscheckpoint-*.bin`
/// artifact family; the digest signers sign is over the canonical bytes only.
/// Not called on the node's boot path — the *publication* side (the signing
/// ceremony of §6, `ws_tool`) writes these files and the boot path only
/// reads them. Living next to its decoder, with the round-trip tests below,
/// is what keeps the two from drifting into two formats.
pub fn encode_envelope_file(env: &CheckpointEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WS_ENVELOPE_MAGIC);
    out.extend_from_slice(&env.checkpoint.canonical_serialize());
    out.extend_from_slice(&(env.signatures.len() as u32).to_le_bytes());
    for (index, sig) in &env.signatures {
        out.push(*index);
        crate::codec::put_bytes(&mut out, sig);
    }
    out
}

pub fn decode_envelope_file(bytes: &[u8]) -> Result<CheckpointEnvelope, DecodeErr> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != WS_ENVELOPE_MAGIC {
        return Err(DecodeErr("not a checkpoint envelope file"));
    }
    let checkpoint = decode_checkpoint(r.take(ws::WS_CHECKPOINT_BYTES)?)?;
    let n = r.u32()? as usize;
    if n > MAX_SIGNERS {
        return Err(DecodeErr("envelope: signature count over cap"));
    }
    let mut signatures = Vec::with_capacity(n);
    for _ in 0..n {
        let index = r.take(1)?[0];
        signatures.push((index, r.bytes()?));
    }
    r.finish()?;
    Ok(CheckpointEnvelope { checkpoint, signatures })
}

/// Encode one signer's partial signature — the file a signer hands back, and
/// the only thing that has to leave their machine.
///
/// The framing exists to carry the `ws_digest` the signature was made over;
/// see [`PartialSignature`] for why that matters. It does NOT carry the
/// checkpoint: a partial is a statement about a digest, and the coordinator
/// must already hold the 154 bytes it refers to.
pub fn encode_partial_file(p: &PartialSignature) -> Vec<u8> {
    // Capacity hint only: saturation costs at most a reallocation.
    let mut out = Vec::with_capacity(p.signature.len().saturating_add(8 + 32 + 1 + 4));
    out.extend_from_slice(WS_PARTIAL_MAGIC);
    out.extend_from_slice(&p.digest);
    out.push(p.signer_index);
    crate::codec::put_bytes(&mut out, &p.signature);
    out
}

pub fn decode_partial_file(bytes: &[u8]) -> Result<PartialSignature, DecodeErr> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != WS_PARTIAL_MAGIC {
        return Err(DecodeErr("not a checkpoint partial-signature file"));
    }
    let digest = r.h32()?;
    let signer_index = r.take(1)?[0];
    let signature = r.bytes()?;
    r.finish()?;
    Ok(PartialSignature { signer_index, digest, signature })
}

/// Encode a signer arrangement (written by the ceremony side, `ws_tool`;
/// a release build will additionally hard-code the §6 arrangements next to
/// its pinned genesis, and this file form then becomes a test fixture).
/// Pubkeys are the RAW hybrid halves (`HYBRID_PK_BYTES`), the form
/// `ws::Signer` carries — not the 4-byte suite envelope.
pub fn encode_signer_set_file(set: &SignerSet) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WS_SIGNER_SET_MAGIC);
    out.extend_from_slice(&set.id.to_le_bytes());
    out.extend_from_slice(&(set.threshold as u32).to_le_bytes());
    out.extend_from_slice(&(set.min_external as u32).to_le_bytes());
    out.extend_from_slice(&set.adopted_epoch.to_le_bytes());
    out.extend_from_slice(&(set.signers.len() as u32).to_le_bytes());
    for s in &set.signers {
        out.push(u8::from(s.external));
        out.extend_from_slice(&s.pubkey);
    }
    out
}

pub fn decode_signer_set_file(bytes: &[u8]) -> Result<SignerSet, DecodeErr> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != WS_SIGNER_SET_MAGIC {
        return Err(DecodeErr("not a signer-set file"));
    }
    let id = r.u32()?;
    let threshold = r.u32()? as usize;
    let min_external = r.u32()? as usize;
    let adopted_epoch = r.u64()?;
    let n = r.u32()? as usize;
    if n > MAX_SIGNERS {
        return Err(DecodeErr("signer set: count over cap"));
    }
    let mut signers = Vec::with_capacity(n);
    for _ in 0..n {
        let external = match r.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(DecodeErr("signer set: external flag not 0/1")),
        };
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(r.take(HYBRID_PK_BYTES)?);
        signers.push(Signer { pubkey, external });
    }
    r.finish()?;
    if threshold == 0 || threshold > signers.len() || min_external > threshold {
        return Err(DecodeErr("signer set: incoherent quorum shape"));
    }

    // Refuse malformed arrangements at the file boundary.
    //
    // Validate locally for actionable file diagnostics. The committee's
    // standalone verifier also enforces basic shape and distinct keys, so
    // callers constructing SignerSet directly cannot bypass these rules.
    //
    // 1. ONE KEY IN TWO SLOTS. The quorum counts distinct signer *indices*,
    //    so public-key uniqueness is checked separately. Without it, an
    //    arrangement seating one key twice is a 1-of-n
    //    wearing an m-of-n's clothes: its single holder signs once, lists the
    //    byte-identical signature at both indices, the indices differ, and
    //    every rule passes. Seat the duplicate once `internal` and once
    //    `external` and `min_external` falls in the same stroke — the rule
    //    §6.1 leans on to make two founder-adjacent keys not a quorum.
    // (`DecodeErr` carries a `&'static str`, so the offending slot numbers
    // cannot go in the message; `duplicate_key_slots` is public so a caller
    // that wants to name them — `ws_tool` does — can ask.)
    if duplicate_key_slots(&signers).is_some() {
        return Err(DecodeErr(
            "signer set: two slots hold the SAME public key, which makes the quorum a 1-of-n \
             that its single holder can satisfy alone",
        ));
    }
    // 2. THE ARRANGEMENT CLOCK. `adopted_epoch` is the field that decides
    //    whether §6.3's dead-man's switch exists, it arrives from this file,
    //    and until now nothing looked at it. A value far enough in the future
    //    pushes `review_deadline()` and `hard_stop()` past every epoch the
    //    chain will reach (10^12 is ~30 million years of 16-minute epochs) and
    //    `u64::MAX` saturates the additions outright — in every such case the
    //    refusal and the warning are unreachable comparisons. Refusing a set
    //    whose window contains no epoch at or after its own adoption is the
    //    clock-free way to say it; `arrangement_window` carries the reasoning.
    //    The decoder catches the arithmetic half — a value so large that
    //    `review_deadline()` and `hard_stop()` are CLAMPED rather than
    //    computed, at which point the §6.3 comparisons cannot move at all.
    //    The other half, a value that is merely absurd (10^12 epochs is ~30
    //    million years and clamps nothing), needs an epoch to compare
    //    against and is enforced by `arrangement_window` in `boot` below.
    if adopted_epoch
        > u64::MAX - (ws::WS_ARRANGEMENT_REVIEW_EPOCHS + ws::WS_ARRANGEMENT_GRACE_EPOCHS)
    {
        return Err(DecodeErr(
            "signer set: adopted_epoch saturates the §6.3 review clock, so the dead-man's \
             switch could never fire",
        ));
    }
    Ok(SignerSet { id, signers, threshold, min_external, adopted_epoch })
}

// ---------------------------------------------------------------------------
// The publication side: partial signatures and their combination
// ---------------------------------------------------------------------------
//
// These live HERE and not in `bloch_pos_committee::ws` on purpose. `ws.rs` is
// byte-identical between the release tag, the fleet commit and every branch
// that carries the ceremony tool, and the consuming half of the mechanism
// already ships in the binary validators run. Putting the ceremony's own
// logic in the frozen consensus crate would make the ceremony depend on a
// change to that crate — a rollout question the ceremony does not otherwise
// have. Nothing below is on any acceptance path: `combine` builds an envelope,
// `ws::verify_envelope` remains the sole judge of whether one is good.

/// One signer's contribution: a hybrid signature over a checkpoint's
/// `ws_digest`, plus the digest it was made over and the slot it was made for.
///
/// Carrying the digest is what makes the ceremony **asynchronous**, which is
/// the point of a 2-of-3: each signer sees the 154 bytes, recomputes the
/// digest themselves, signs, and hands this back. No signer needs any other
/// signer to be online, and no coordinator can attach a signature made over
/// one checkpoint to a different one — [`combine`] compares this field against
/// the digest of the checkpoint it is building and refuses on mismatch.
///
/// Without the binding the same mistake still fails, but as
/// `EnvelopeReject::BadSignature`, which reads like a corrupt file or the
/// wrong key. The difference is attribution: `DigestMismatch` names the person
/// to call, while the signers are still reachable.
///
/// `signature` is the RAW hybrid body — `ML-DSA-65 ‖ Falcon-1024`, split at
/// `staking::MLDSA65_SIG_BYTES` — the form `CheckpointEnvelope::signatures`
/// carries, not a suite-enveloped object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature {
    pub signer_index: u8,
    pub digest: [u8; 32],
    pub signature: Vec<u8>,
}

/// Why partial signatures could not be combined into an envelope.
///
/// A near-mirror of `ws::EnvelopeReject` by design: every structural rule
/// `ws::verify_envelope` enforces at a stranger's boot is enforced here at the
/// ceremony, so a quorum that would be refused in the field is refused on the
/// coordinator's machine instead. The one rule this cannot check is the
/// cryptography; `ws_tool::envelope` runs the real `ws::verify_envelope` over
/// the combined result before writing it, and
/// `combine_agrees_with_verify_envelope` pins the correspondence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CombineReject {
    WrongVersion { got: u16 },
    WrongSignerSet { got: u32, expected: u32 },
    ReservedSignerSet,
    /// The checkpoint's epoch is outside the arrangement's §6.3 validity
    /// window `[adopted_epoch, hard_stop()]`. See [`arrangement_window`].
    OutsideArrangementWindow { adopted_epoch: u64, hard_stop_epoch: u64 },
    UnknownSignerIndex { index: u8 },
    /// The same signer contributed twice. One key is one signature: counting
    /// it twice turns an m-of-n into an (m-1)-of-n.
    DuplicateSigner { index: u8 },
    /// A partial was made over a different checkpoint than the one being
    /// assembled. The signature may be perfectly valid; it says nothing about
    /// this epoch, this root, or this chain.
    DigestMismatch { index: u8 },
    QuorumNotReached { got: usize, need: usize },
    ExternalQuorumNotReached { got: usize, need: usize },
}

/// Which §6 phase's numbers this arrangement matches, if any.
///
/// The signer-set file carries the quorum RULE and reaches a node over an
/// unauthenticated channel, so its shape is POLICY, not operator input: the
/// only arrangements a node (or the ceremony tooling, which must refuse
/// whatever a node would refuse) accepts are the two
/// BLOCH-WEAK-SUBJECTIVITY.md §6 describes — Phase A 2-of-3 with one external
/// signer, Phase B 3-of-5 with two. `None` means neither matches and the
/// caller must fail closed.
pub fn shape_policy_of(set: &SignerSet) -> Option<(usize, usize, usize)> {
    if set.matches_policy(
        ws::WS_PHASE_A_THRESHOLD,
        ws::WS_PHASE_A_SIGNERS,
        ws::WS_PHASE_A_MIN_EXTERNAL,
    ) {
        Some((ws::WS_PHASE_A_THRESHOLD, ws::WS_PHASE_A_SIGNERS, ws::WS_PHASE_A_MIN_EXTERNAL))
    } else if set.matches_policy(
        ws::WS_PHASE_B_THRESHOLD,
        ws::WS_PHASE_B_SIGNERS,
        ws::WS_PHASE_B_MIN_EXTERNAL,
    ) {
        Some((ws::WS_PHASE_B_THRESHOLD, ws::WS_PHASE_B_SIGNERS, ws::WS_PHASE_B_MIN_EXTERNAL))
    } else {
        None
    }
}

/// The refusal text for a set `shape_policy_of` matched to neither phase —
/// one wording for the boot gate and the ceremony tool, so an operator sees
/// the same sentence at `ws-verify` time as a stranger's node prints at boot.
pub fn shape_policy_refusal(set: &SignerSet, origin: &str) -> String {
    format!(
        "signer set {origin} REFUSED: its shape ({}-of-{}, >= {} external) is neither \
         Phase A ({}-of-{}, >= {} external) nor Phase B ({}-of-{}, >= {} external); a \
         weak-subjectivity root of trust with any other arrangement is not accepted by \
         this node",
        set.threshold,
        set.signers.len(),
        set.min_external,
        ws::WS_PHASE_A_THRESHOLD,
        ws::WS_PHASE_A_SIGNERS,
        ws::WS_PHASE_A_MIN_EXTERNAL,
        ws::WS_PHASE_B_THRESHOLD,
        ws::WS_PHASE_B_SIGNERS,
        ws::WS_PHASE_B_MIN_EXTERNAL,
    )
}

/// The epochs an arrangement may attest: `[adopted_epoch, hard_stop()]`.
///
/// The upper bound is `ws::SignerSet::hard_stop` — §6.3's dead-man's switch,
/// which `ws::verify_envelope` already enforces. The **lower** bound is the
/// half that does not exist upstream, and without it the upper one is not a
/// bound at all:
///
/// `review_deadline()` and `hard_stop()` are `adopted_epoch` plus a fixed
/// 41,040 epochs. `adopted_epoch` arrives from an operator-supplied file with
/// nothing checking it, so setting it to any large number pushes both
/// deadlines past every epoch the chain will ever reach — 10^12 is already
/// about 30 million years of 16-minute epochs, and `u64::MAX` saturates the
/// additions outright so that even the arithmetic stops moving. In every such
/// case `cp.epoch > set.hard_stop()` is simply never true: the refusal and the
/// twelve-month review warning both become unreachable comparisons, for the
/// life of the arrangement, and nothing about the resulting envelope looks any
/// different from a correct one.
///
/// Requiring `cp.epoch >= adopted_epoch` closes it without a clock: an
/// arrangement may not attest an epoch from before it existed. The pair then
/// bounds every arrangement to a 41,040-epoch window wherever `adopted_epoch`
/// is put, so the switch is real for every value of the field rather than only
/// for plausible ones. It is compatible with §6.4 rotation, where the
/// incoming arrangement signs from its adoption epoch forward and the outgoing
/// one covers the overlap.
pub fn arrangement_window(set: &SignerSet, epoch: u64) -> Result<(), (u64, u64)> {
    if epoch < set.adopted_epoch || epoch > set.hard_stop() {
        return Err((set.adopted_epoch, set.hard_stop()));
    }
    Ok(())
}

/// Assemble collected partial signatures into a `CheckpointEnvelope`.
///
/// Pure: no clock, no filesystem, no cryptography. It orders the signatures by
/// `signer_index` so that the same partials in any collection order produce
/// **byte-identical** envelope framing — a coordinator who receives the
/// auditor's file first must not publish a different artifact than one who
/// receives it last, or the cross-channel digest comparison the whole
/// mechanism rests on would be comparing two different things.
///
/// It never drops a partial to make a quorum fit: `ws::verify_envelope`
/// requires *every listed* signature to verify, so silently discarding a bad
/// one here would move the failure to a stranger's boot.
pub fn combine(
    cp: &WeakSubjectivityCheckpoint,
    set: &SignerSet,
    partials: &[PartialSignature],
) -> Result<CheckpointEnvelope, CombineReject> {
    if cp.version != ws::WS_FORMAT_VERSION {
        return Err(CombineReject::WrongVersion { got: cp.version });
    }
    if cp.signer_set_id == ws::WS_GENESIS_SIGNER_SET_ID || set.id == ws::WS_GENESIS_SIGNER_SET_ID
        || is_unsigned_anchor_id(cp.signer_set_id) || is_unsigned_anchor_id(set.id) {
        return Err(CombineReject::ReservedSignerSet);
    }
    if cp.signer_set_id != set.id {
        return Err(CombineReject::WrongSignerSet { got: cp.signer_set_id, expected: set.id });
    }
    if let Err((adopted_epoch, hard_stop_epoch)) = arrangement_window(set, cp.epoch) {
        return Err(CombineReject::OutsideArrangementWindow { adopted_epoch, hard_stop_epoch });
    }

    let digest = cp.ws_digest();
    let mut seen = [false; 256];
    for p in partials {
        let i = p.signer_index;
        if (i as usize) >= set.signers.len() {
            return Err(CombineReject::UnknownSignerIndex { index: i });
        }
        if seen[i as usize] {
            return Err(CombineReject::DuplicateSigner { index: i });
        }
        seen[i as usize] = true;
        if p.digest != digest {
            return Err(CombineReject::DigestMismatch { index: i });
        }
    }
    if partials.len() < set.threshold {
        return Err(CombineReject::QuorumNotReached {
            got: partials.len(),
            need: set.threshold,
        });
    }
    let external = partials
        .iter()
        .filter(|p| set.signers[p.signer_index as usize].external)
        .count();
    if external < set.min_external {
        return Err(CombineReject::ExternalQuorumNotReached {
            got: external,
            need: set.min_external,
        });
    }

    let mut signatures: Vec<(u8, Vec<u8>)> =
        partials.iter().map(|p| (p.signer_index, p.signature.clone())).collect();
    signatures.sort_by_key(|(i, _)| *i);
    Ok(CheckpointEnvelope { checkpoint: *cp, signatures })
}

/// The first pair of slots holding byte-identical public keys, if any.
///
/// `n(n-1)/2` comparisons of `HYBRID_PK_BYTES` bytes — 3 memcmps for the §6.1
/// Phase A shape, 10 for Phase B. Deliberately not short-circuited on
/// `external`: two slots holding the same key are unsound whatever their
/// subset flags say; the internal/external pairing is merely the worst case,
/// because it defeats `min_external` as well as `threshold`.
pub fn duplicate_key_slots(signers: &[Signer]) -> Option<(u8, u8)> {
    for i in 0..signers.len() {
        // `i + 1` cannot overflow (i < len), but the ratchet wants the proof
        // in the type: saturating_add is identical on every reachable value.
        for j in i.saturating_add(1)..signers.len() {
            if signers[i].pubkey == signers[j].pubkey {
                return Some((i as u8, j as u8));
            }
        }
    }
    None
}

/// SHA3-256 of a signer-set file — the arrangement's fingerprint.
///
/// `--ws-signer-set` is an unauthenticated download, exactly like the envelope
/// it accompanies, and it carries the quorum rule itself. Comparing this
/// fingerprint across independent channels is the only thing that makes the
/// arrangement as checkable as the checkpoint.
pub fn signer_set_fingerprint(bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    Sha3_256::digest(bytes).into()
}

// ---------------------------------------------------------------------------
// ws_latest persistence (§4.1)
// ---------------------------------------------------------------------------

const WS_LATEST_FILE: &str = "ws_latest.bin";

/// Load the stored `ws_latest`, refusing a file that belongs to another
/// network — the same §3.1 refusal-not-migration rule the meta marker
/// applies.
pub fn load_latest(
    dir: &Path,
    network_id: u32,
    genesis_root: &[u8; 32],
) -> io::Result<Option<WeakSubjectivityCheckpoint>> {
    let path = dir.join(WS_LATEST_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let bad = boot_refused;
    let cp = decode_checkpoint(&bytes)
        .map_err(|e| bad(format!("{}: {e}", path.display())))?;
    if cp.network_id != network_id || &cp.genesis_root != genesis_root {
        return Err(bad(format!(
            "{} belongs to a different network; refusing. Verify the data directory and checkpoint trust configuration before recovery",
            path.display()
        )));
    }
    Ok(Some(cp))
}

/// Persist `ws_latest` (write-to-temp + fsync + rename + fsync(dir), like the
/// block-log rewrite and the slashing-protection watermark).
///
/// The directory fsync is not optional (audit round 3, M-6): `ws_latest` is
/// what the next boot refuses to rewind below. A rename that a crash can undo
/// would let the node come back trusting an older checkpoint than the one it
/// had already announced, which is the weak-subjectivity window re-opening by
/// itself.
pub fn save_latest(dir: &Path, cp: &WeakSubjectivityCheckpoint) -> io::Result<()> {
    use std::io::Write;
    let tmp = dir.join("ws_latest.bin.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&cp.canonical_serialize())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(WS_LATEST_FILE))?;
    crate::store::fsync_dir(dir)
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

/// Reserved `signer_set_id` of an operator-trusted checkpoint: the Ethereum
/// model, where no one signs anything and the operator who boots a fresh
/// node decides which finalized root is real (Prysm/Teku
/// `--weak-subjectivity-checkpoint`, Lighthouse `--checkpoint-sync-url`).
/// No arrangement may claim this id, so such a checkpoint can never be
/// mistaken for, or combined into, a signed envelope.
pub const WS_OPERATOR_TRUSTED_SIGNER_SET_ID: u32 = u32::MAX;

/// Reserved `signer_set_id` of a **release-baked** checkpoint: a finalized
/// (epoch, block, state) compiled into the node release itself, exactly as
/// the genesis anchor is. Its trust is the release binary's trust — the same
/// trust every operator already places in the code that enforces the window
/// — so it adds no key, no ceremony and no new root of trust. Like the
/// operator-trusted id, no arrangement may claim it and it is never signed.
pub const WS_RELEASE_SIGNER_SET_ID: u32 = u32::MAX - 1;

/// The ids that name an unsigned anchor and can never appear in a signed
/// arrangement or envelope.
pub const fn is_unsigned_anchor_id(id: u32) -> bool {
    id == WS_OPERATOR_TRUSTED_SIGNER_SET_ID || id == WS_RELEASE_SIGNER_SET_ID
}

/// True when this binary was built with the `ws-auto-checkpoint` prototype
/// feature: the unsigned operator-trusted inputs (`--checkpoint-sync-url`,
/// `--ws-trusted-checkpoint`, `--ws-trusted-root`) are accepted. Never in a
/// release yet (owner decision, round 11).
pub const AUTO_CHECKPOINT_ENABLED: bool = cfg!(feature = "ws-auto-checkpoint");

/// True when this binary was built with `ws-release-anchor` (implied by
/// `ws-auto-checkpoint`): the release-baked checkpoint is compiled in, a
/// restart part-way through a checkpoint sync resumes, and the same-fact rule
/// applies. Without it the node behaves exactly as fa980367: no release
/// anchor, and a restart mid-sync still halts with `ERR_WS_STALE`.
pub const RELEASE_ANCHOR_ENABLED: bool = cfg!(feature = "ws-release-anchor");

/// Decode the release-baked checkpoint file. An EMPTY file means "this
/// release bakes no checkpoint" (the state of every build until a release
/// engineer mints one with `ws-checkpoint --release-anchor`).
pub fn decode_release_anchor(bytes: &[u8]) -> Result<Option<WeakSubjectivityCheckpoint>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let cp = decode_checkpoint(bytes).map_err(|e| format!("release-baked checkpoint: {e}"))?;
    if cp.version != ws::WS_FORMAT_VERSION {
        return Err(format!("release-baked checkpoint: unsupported version {}", cp.version));
    }
    if cp.signer_set_id != WS_RELEASE_SIGNER_SET_ID {
        return Err(format!(
            "release-baked checkpoint carries signer-set id {}, not the reserved release id {WS_RELEASE_SIGNER_SET_ID}; \
             mint it with `bloch-pos ws-checkpoint --release-anchor`",
            cp.signer_set_id
        ));
    }
    if cp.epoch == 0 {
        return Err("release-baked checkpoint at epoch 0 duplicates the genesis anchor".into());
    }
    if cp.validator_set_root != [0; 32] {
        return Err("release-baked checkpoint has a nonzero validator_set_root this node cannot derive".into());
    }
    Ok(Some(cp))
}

/// Workspace-relative path of the file `compiled_release_anchor` compiles in.
/// It must lie inside the source-digest scope (build_source_digest.rs), so
/// that a binary's reported source digest also binds the anchor it bakes.
pub const RELEASE_ANCHOR_SOURCE: &str = "crates/bloch-pos-node/src/ws_release_anchor.rs";

/// Decode the hex text of `src/ws_release_anchor.rs` (empty: no anchor).
#[cfg_attr(not(feature = "ws-release-anchor"), allow(dead_code))]
pub fn decode_release_anchor_hex(text: &str) -> Result<Option<WeakSubjectivityCheckpoint>, String> {
    let bytes = crate::codec::unhex(text.trim()).map_err(|e| format!("release-baked checkpoint hex: {e}"))?;
    decode_release_anchor(&bytes)
}

/// The checkpoint compiled into this binary, if any. Only builds with the
/// `ws-release-anchor` feature read `src/ws_release_anchor.rs`.
pub fn compiled_release_anchor() -> Result<Option<WeakSubjectivityCheckpoint>, String> {
    #[cfg(feature = "ws-release-anchor")]
    {
        decode_release_anchor_hex(crate::ws_release_anchor::RELEASE_ANCHOR_HEX)
    }
    #[cfg(not(feature = "ws-release-anchor"))]
    {
        Ok(None)
    }
}

/// Where an unsigned, operator-trusted checkpoint comes from.
#[derive(Debug, Clone)]
pub enum TrustedSource {
    /// `--ws-trusted-checkpoint <file>`: the artifact `ws-checkpoint
    /// --operator-trusted` derives from several RPC endpoints.
    File(PathBuf),
    /// `--checkpoint-sync-url`: fetched at boot from the operator's nodes
    /// ([`crate::ws_tool::fetch_trusted_checkpoint`]).
    Fetched(WeakSubjectivityCheckpoint),
}

/// An unsigned checkpoint the operator vouches for. `block_root`, when given
/// (`--ws-trusted-root`), is the root the operator compared through a SECOND,
/// independent channel (an explorer, another operator); the checkpoint must
/// name exactly it. Optional, as Ethereum's `--wss-checkpoint` is.
#[derive(Debug, Clone)]
pub struct TrustedCheckpoint {
    pub source: TrustedSource,
    pub block_root: Option<[u8; 32]>,
}

/// CLI-supplied weak-subjectivity inputs.
#[derive(Default)]
pub struct WsConfig {
    pub checkpoint: Option<PathBuf>,
    pub signer_set: Option<PathBuf>,
    /// Independently obtained SHA3-256 of the complete BPOSWSS1 file bytes.
    pub signer_set_sha3: Option<[u8; 32]>,
    /// `--ws-trusted-checkpoint` [+ `--ws-trusted-root`]: the unsigned path.
    pub trusted: Option<TrustedCheckpoint>,
    /// `--checkpoint-sync-url <host:port>[,...]`: the friction-free unsigned
    /// path. Consulted ONLY when this node lacks fresh finality of its own
    /// (a new node, or one offline for weeks); a running node never needs it.
    pub checkpoint_sync: Vec<String>,
    /// `--ws-trusted-root` given together with `--checkpoint-sync-url`.
    pub checkpoint_sync_pin: Option<[u8; 32]>,
    /// Release-baked checkpoint ([`WS_RELEASE_SIGNER_SET_ID`]), consulted on
    /// every boot before any operator input. `None` unless the binary was
    /// built with `ws-release-anchor` AND `src/ws_release_anchor.rs` is set.
    pub release_anchor: Option<WeakSubjectivityCheckpoint>,
    /// Restart-during-checkpoint-sync fix (agent 181's ERR_WS_STALE finding):
    /// a node whose own finality is beyond the window but BEHIND a fresh,
    /// already-verified anchor keeps syncing under that anchor as a hard
    /// anchor, exactly as it did before the restart. Off unless built with
    /// `ws-release-anchor`.
    pub resume_sync_under_anchor: bool,
}

impl WsConfig {
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut checkpoint = None;
        let mut signer_set = None;
        let mut pin = None;
        let mut trusted_file = None;
        let mut trusted_root = None;
        let mut sync_urls = None;
        let mut index = 0;
        while index < args.len() {
            if args[index] == "--" {
                if args[index + 1..].iter().any(|arg| matches!(arg.as_str(),
                    "--ws-checkpoint" | "--ws-signer-set" | "--ws-signer-set-sha3"
                    | "--ws-trusted-checkpoint" | "--ws-trusted-root" | "--checkpoint-sync-url")) {
                    return Err("weak-subjectivity options must appear before `--`".into());
                }
                break;
            }
            let destination = match args[index].as_str() {
                "--ws-checkpoint" => Some((&mut checkpoint, "--ws-checkpoint")),
                "--ws-signer-set" => Some((&mut signer_set, "--ws-signer-set")),
                "--ws-signer-set-sha3" => Some((&mut pin, "--ws-signer-set-sha3")),
                "--ws-trusted-checkpoint" => Some((&mut trusted_file, "--ws-trusted-checkpoint")),
                "--ws-trusted-root" => Some((&mut trusted_root, "--ws-trusted-root")),
                "--checkpoint-sync-url" => Some((&mut sync_urls, "--checkpoint-sync-url")),
                _ => None,
            };
            if let Some((slot, name)) = destination {
                if slot.is_some() {
                    return Err(format!("{name} must be supplied only once"));
                }
                let value = args.get(index + 1)
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| format!("{name} requires a value"))?;
                *slot = Some(value.clone());
                index += 2;
                continue;
            }
            index += 1;
        }
        let supplied = [checkpoint.is_some(), signer_set.is_some(), pin.is_some()];
        if supplied.iter().any(|present| *present) && !supplied.iter().all(|present| *present) {
            return Err("--ws-checkpoint, --ws-signer-set and --ws-signer-set-sha3 must be supplied together".into());
        }
        let signer_set_sha3 = pin.map(|value| {
            let bytes = crate::codec::unhex(&value).map_err(|error| format!("--ws-signer-set-sha3: {error}"))?;
            bytes.try_into().map_err(|_| "--ws-signer-set-sha3 requires exactly 32 bytes (64 hex characters)".to_string())
        }).transpose()?;
        let mut checkpoint_sync = Vec::new();
        for url in sync_urls.as_deref().unwrap_or("").split(',').map(str::trim).filter(|url| !url.is_empty()) {
            if url.starts_with("https://") {
                return Err("--checkpoint-sync-url takes a node RPC as host:port (plain HTTP); https is not supported".into());
            }
            checkpoint_sync.push(url.trim_start_matches("http://").trim_end_matches('/').to_string());
        }
        let block_root: Option<[u8; 32]> = trusted_root.map(|root| {
            let bytes = crate::codec::unhex(&root).map_err(|error| format!("--ws-trusted-root: {error}"))?;
            bytes.try_into().map_err(|_| "--ws-trusted-root requires exactly 32 bytes (64 hex characters)".to_string())
        }).transpose()?;
        let sources = usize::from(checkpoint.is_some()) + usize::from(trusted_file.is_some())
            + usize::from(!checkpoint_sync.is_empty());
        if sources > 1 {
            return Err("--ws-checkpoint, --ws-trusted-checkpoint and --checkpoint-sync-url are alternatives; supply one".into());
        }
        if block_root.is_some() && trusted_file.is_none() && checkpoint_sync.is_empty() {
            return Err("--ws-trusted-root compares a checkpoint: supply it with --checkpoint-sync-url or --ws-trusted-checkpoint".into());
        }
        if !AUTO_CHECKPOINT_ENABLED && (trusted_file.is_some() || block_root.is_some() || !checkpoint_sync.is_empty()) {
            return Err("--checkpoint-sync-url, --ws-trusted-checkpoint and --ws-trusted-root are a prototype \
                        (cargo feature `ws-auto-checkpoint`) and are not enabled in this build".into());
        }
        let checkpoint_sync_pin = if checkpoint_sync.is_empty() { None } else { block_root };
        let trusted = trusted_file.map(|path| TrustedCheckpoint { source: TrustedSource::File(PathBuf::from(path)), block_root });
        Ok(Self {
            checkpoint: checkpoint.map(PathBuf::from),
            signer_set: signer_set.map(PathBuf::from),
            signer_set_sha3,
            trusted,
            checkpoint_sync,
            checkpoint_sync_pin,
            release_anchor: compiled_release_anchor()?,
            resume_sync_under_anchor: RELEASE_ANCHOR_ENABLED,
        })
    }
}

/// What the engine carries out of a successful boot: the anchor it must
/// enforce once its own finality reaches `anchor_epoch`.
#[derive(Debug)]
pub struct WsOutcome {
    /// Full authenticated artifact, retained for validation as synchronization progresses.
    pub checkpoint: WeakSubjectivityCheckpoint,
    pub anchor_epoch: u64,
    pub anchor_root: [u8; 32],
    /// True when the node had no finality of its own at boot: the anchor is
    /// then its ONLY defense, and a later contradiction is fatal. False for a
    /// node that booted on its own finality — there a contradiction is the
    /// WS_CONFLICT alarm, never a reorg and never an exit.
    pub anchor_is_hard: bool,
    /// Prominent messages the engine prints (collected so tests can assert
    /// on them instead of scraping stderr).
    pub warnings: Vec<String>,
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn window_days() -> u64 {
    ws::WS_PERIOD_EPOCHS / ws::EPOCHS_PER_DAY
}

/// Compare only against locally replay-validated canonical state. Missing local
/// evidence is not a successful validation and must never manufacture trust.
fn check_local_state(
    checkpoint: &WeakSubjectivityCheckpoint,
    genesis_anchor: &WeakSubjectivityCheckpoint,
    local_state_root: &impl Fn(&[u8; 32]) -> Option<[u8; 32]>,
    warnings: &mut Vec<String>,
) -> io::Result<()> {
    // The reserved release anchor records the manifest-derived genesis state.
    // Published checkpoints instead use the named block's header field, as the
    // RPC/tool always did, including a genesis boundary after missed slots.
    // Legacy genesis headers carry zero; bound manifests carry a pre-state
    // commitment. Neither is interchangeable with the reserved anchor's root.
    let root = if checkpoint.signer_set_id == ws::WS_GENESIS_SIGNER_SET_ID
        && checkpoint.epoch == 0 && checkpoint.block_root == genesis_anchor.block_root {
        Some(genesis_anchor.state_root)
    } else {
        local_state_root(&checkpoint.block_root)
    };
    if let Some(root) = root {
        if root != checkpoint.state_root {
            return Err(boot_refused(format!(
                "WS_STATE_CONFLICT: checkpoint epoch {} state root {} differs from locally validated block {} state root {}",
                checkpoint.epoch, hex32(&checkpoint.state_root), hex32(&checkpoint.block_root), hex32(&root)
            )));
        }
    } else {
        warnings.push(format!("checkpoint epoch {} state root has no local canonical block evidence yet; it is not locally validated", checkpoint.epoch));
    }
    if checkpoint.validator_set_root != [0; 32] {
        warnings.push(format!("WARNING: checkpoint epoch {} has a nonzero validator_set_root that this node cannot independently derive; this field is not validated", checkpoint.epoch));
    }
    // Zero is the existing published format's unavailable-root sentinel, not
    // a validator registry commitment. Preserve that historical encoding.
    Ok(())
}

/// [`ws::accept`], except that two checkpoints naming the SAME finalized
/// block and state at one epoch are one fact, not an equivocation, even when
/// their digests differ because one is operator-trusted and the other signed
/// (or issued at another time). Different roots stay a loud conflict.
fn same_fact_accept(stored: &WeakSubjectivityCheckpoint, incoming: &WeakSubjectivityCheckpoint) -> Acceptance {
    match ws::accept(Some(stored), incoming) {
        Acceptance::Conflict
            if incoming.block_root == stored.block_root && incoming.state_root == stored.state_root =>
        {
            Acceptance::Ignore
        }
        other => other,
    }
}

/// Load and check an operator-trusted checkpoint. Nothing here is a
/// signature: the trust is the operator's, exactly as on Ethereum. What the
/// node still enforces is everything it CAN check by itself — the network,
/// the genesis, the format, agreement with the root the operator compared
/// independently, and agreement with any block it has already validated.
/// Freshness, own-finality cross-check and anti-rollback run afterwards on
/// the same path as a signed envelope.
fn trusted_checkpoint(
    trusted: &TrustedCheckpoint,
    network_id: u32,
    genesis_root: &[u8; 32],
    genesis_anchor: &WeakSubjectivityCheckpoint,
    local_state_root: &impl Fn(&[u8; 32]) -> Option<[u8; 32]>,
    warnings: &mut Vec<String>,
) -> io::Result<WeakSubjectivityCheckpoint> {
    let bad = boot_refused;
    let (cp, origin) = match &trusted.source {
        TrustedSource::File(path) => {
            let cp = decode_checkpoint(&fs::read(path)?)
                .map_err(|e| bad(format!("{}: {e}", path.display())))?;
            (cp, path.display().to_string())
        }
        TrustedSource::Fetched(cp) => (*cp, "--checkpoint-sync-url".to_string()),
    };
    if cp.version != ws::WS_FORMAT_VERSION {
        return Err(bad(format!("{origin}: unsupported checkpoint version {}", cp.version)));
    }
    if cp.network_id != network_id || &cp.genesis_root != genesis_root {
        return Err(bad(format!("{origin}: checkpoint belongs to a different network; refusing")));
    }
    if cp.signer_set_id != WS_OPERATOR_TRUSTED_SIGNER_SET_ID {
        return Err(bad(format!(
            "{origin}: not an operator-trusted checkpoint (signer-set id {}); derive one with \
             `bloch-pos ws-checkpoint --operator-trusted`, or pass a signed envelope with --ws-checkpoint",
            cp.signer_set_id
        )));
    }
    if cp.epoch == 0 {
        return Err(bad("an operator-trusted checkpoint at epoch 0 is the genesis anchor, which every node already has".into()));
    }
    match trusted.block_root {
        Some(expected) if expected != cp.block_root => {
            return Err(bad(format!(
                "operator-trusted checkpoint from {origin} names block {} at epoch {}, but --ws-trusted-root is {}; \
                 the two channels disagree, so neither is trusted. Investigate before booting",
                hex32(&cp.block_root), cp.epoch, hex32(&expected)
            )));
        }
        Some(_) => {}
        None => warnings.push(format!(
            "no --ws-trusted-root given: compare block {} (epoch {}) with the explorer or another operator",
            hex32(&cp.block_root), cp.epoch
        )),
    }
    check_local_state(&cp, genesis_anchor, local_state_root, warnings)?;
    warnings.push(format!(
        "operator-trusted checkpoint: epoch {} block {} from {origin} (no signatures; the operator vouched for this root)",
        cp.epoch, hex32(&cp.block_root)
    ));
    Ok(cp)
}

/// Admit the release-baked checkpoint, if it applies to this network. The
/// order of checks is the signed envelope's: identity, local evidence,
/// own-finality cross-check (a contradiction is the `WS_CONFLICT` alarm and
/// is not admitted — a release can never reorganize a running node), then
/// anti-rollback with the same-fact rule.
#[allow(clippy::too_many_arguments)]
fn admit_release_anchor(
    release: &WeakSubjectivityCheckpoint,
    data_dir: &Path,
    network_id: u32,
    genesis_root: &[u8; 32],
    genesis_anchor: &WeakSubjectivityCheckpoint,
    has_local_finality: bool,
    local_root_at: &impl Fn(u64) -> Option<[u8; 32]>,
    local_state_root: &impl Fn(&[u8; 32]) -> Option<[u8; 32]>,
    anchor: &mut WeakSubjectivityCheckpoint,
    warnings: &mut Vec<String>,
) -> io::Result<Result<(), String>> {
    if release.signer_set_id != WS_RELEASE_SIGNER_SET_ID {
        return Err(boot_refused("release-baked checkpoint does not carry the reserved release id; refusing"));
    }
    if release.network_id != network_id || &release.genesis_root != genesis_root {
        // A mainnet release run against a devnet manifest: not this chain's
        // fact, so it is neither an anchor nor an error.
        warnings.push(format!(
            "release-baked checkpoint (epoch {}) is for network {:#010x}, not this one; ignored",
            release.epoch, release.network_id
        ));
        return Ok(Ok(()));
    }
    check_local_state(release, genesis_anchor, local_state_root, warnings)?;
    if has_local_finality {
        if let CrossCheck::Conflict { local_root, published_root } = ws::cross_check(local_root_at(release.epoch), release) {
            warnings.push(format!(
                "WS_CONFLICT: the release-baked checkpoint contradicts this node's OWN finality at epoch {}.\n  \
                 local finalized root: {}\n  release root:         {}\n\
                 Own finality stands: NOT reorganizing, NOT adopting the release anchor. Either this \
                 node is on a forged branch or the release was built against a wrong chain; alert the operator.",
                release.epoch, hex32(&local_root), hex32(&published_root)
            ));
            return Ok(Ok(()));
        }
    }
    match same_fact_accept(anchor, release) {
        Acceptance::Store => {
            save_latest(data_dir, release)?;
            *anchor = *release;
            warnings.push(format!(
                "release-baked checkpoint adopted: epoch {} block {} (trust = this release binary; no signatures)",
                release.epoch, hex32(&release.block_root)
            ));
        }
        Acceptance::Ignore => warnings.push(format!(
            "release-baked checkpoint epoch {} is not newer than stored ws_latest (epoch {}); ignored",
            release.epoch, anchor.epoch
        )),
        Acceptance::Conflict => {
            return Ok(Err(format!(
                "WS_CONFLICT (release-baked checkpoint): this release names block {} at epoch {}, but the \
                 stored ws_latest names block {} at the same epoch. Refusing to start; compare both roots \
                 with operators you trust before choosing.",
                hex32(&release.block_root), release.epoch, hex32(&anchor.block_root)
            )));
        }
    }
    Ok(Ok(()))
}

/// The whole boot sequence described in the module docs. `local_root_at`
/// returns this node's own finalized checkpoint root at an epoch (`None` if
/// its finality has not reached it); `is_canonical` answers whether a block
/// root is on the node's replayed canonical chain.
#[allow(clippy::too_many_arguments)]
pub fn boot(
    cfg: &WsConfig,
    data_dir: &Path,
    network_id: u32,
    genesis_root: &[u8; 32],
    genesis_anchor: &WeakSubjectivityCheckpoint,
    wall_epoch: u64,
    has_local_finality: bool,
    local_finalized: (u64, [u8; 32]),
    local_root_at: impl Fn(u64) -> Option<[u8; 32]>,
    is_canonical: impl Fn(&[u8; 32]) -> bool,
    local_state_root: impl Fn(&[u8; 32]) -> Option<[u8; 32]>,
) -> io::Result<Result<WsOutcome, String>> {
    let mut warnings = Vec::new();
    if cfg.signer_set_sha3.is_some() && (cfg.checkpoint.is_none() || cfg.signer_set.is_none()) {
        return Err(boot_refused("--ws-signer-set-sha3 requires both --ws-checkpoint and --ws-signer-set; a pin cannot authenticate an absent arrangement or a cached checkpoint by itself"));
    }

    // 1. ws_latest, with the genesis anchor as the first checkpoint when no
    //    other has ever been verified (§4.1 precedence, source 3).
    let mut anchor = match load_latest(data_dir, network_id, genesis_root)? {
        Some(cp) => cp,
        None => {
            save_latest(data_dir, genesis_anchor)?;
            *genesis_anchor
        }
    };

    check_local_state(&anchor, genesis_anchor, &local_state_root, &mut warnings)?;

    // 1b. Release-baked checkpoint (`ws-release-anchor`): the
    //     same trust as the genesis anchor — the release binary — at a recent
    //     epoch. It goes through every rule a signed envelope goes through
    //     except the signature check, because there is nothing to sign: the
    //     bytes are part of the code that enforces the window.
    if let Some(release) = &cfg.release_anchor {
        if let Err(message) = admit_release_anchor(
            release, data_dir, network_id, genesis_root, genesis_anchor, has_local_finality,
            &local_root_at, &local_state_root, &mut anchor, &mut warnings,
        )? {
            return Ok(Err(message));
        }
    }

    // 2. Operator-supplied envelope (§4.1 precedence, source 1), or the
    //    unsigned operator-trusted checkpoint (the Ethereum model).
    let incoming: Option<WeakSubjectivityCheckpoint> = if let Some(path) = &cfg.checkpoint {
        let bad = boot_refused;
        let env = decode_envelope_file(&fs::read(path)?)
            .map_err(|e| bad(format!("{}: {e}", path.display())))?;
        let Some(set_path) = &cfg.signer_set else {
            return Err(bad(
                "--ws-checkpoint given but no signer arrangement is known: this devnet \
                 build bakes no Phase A keys, so pass --ws-signer-set <file> (release \
                 builds will carry the arrangement of BLOCH-WEAK-SUBJECTIVITY.md §6)"
                    .into(),
            ));
        };
        let set_bytes = fs::read(set_path)?;
        let Some(expected) = cfg.signer_set_sha3 else {
            return Err(bad(
                "--ws-checkpoint REFUSED without --ws-signer-set-sha3: the V1 checkpoint digest binds only the arrangement id, so accepting an unpinned file would let one download substitute its keys, quorum and review clock together with the envelope".into(),
            ));
        };
        let actual = signer_set_fingerprint(&set_bytes);
        if actual != expected {
            return Err(bad(format!("signer arrangement fingerprint mismatch: expected {}, read {}; refusing substituted keys/quorum/review clock", hex32(&expected), hex32(&actual))));
        }
        let set = decode_signer_set_file(&set_bytes)
            .map_err(|e| bad(format!("{}: {e}", set_path.display())))?;
        // The arrangement is an unauthenticated download, exactly like the
        // envelope — and it is the file that carries the quorum RULE. Its
        // fingerprint is printed so it can be compared across channels the
        // way the ws digest is: an attacker who can substitute this file does
        // not need to forge a signature.
        warnings.push(format!(
            "ws signer arrangement {} fingerprint (SHA3-256 of {}): {}",
            set.id,
            set_path.display(),
            hex32(&signer_set_fingerprint(&set_bytes)),
        ));
        // NEW-2 (audit round 3): the signer set's SHAPE is policy, not
        // operator input. A set file that is not one of the two published
        // arrangements (BLOCH-WEAK-SUBJECTIVITY.md §6: Phase A 2-of-3 with one
        // external signer, Phase B 3-of-5 with two) is refused before any
        // signature is checked — otherwise an operator-supplied 1-of-1 set
        // would make a single key the root of trust for every node that
        // trusts this file. Fail closed: neither shape matches → refusal
        // naming both. (The ceremony branch shipped this as a warning; the
        // audited gate on main is a refusal, and the refusal wins — a node
        // never boots from an arrangement §6 does not describe.)
        let Some((threshold, signers, min_external)) = shape_policy_of(&set) else {
            return Err(bad(shape_policy_refusal(&set, &set_path.display().to_string())));
        };
        if is_unsigned_anchor_id(env.checkpoint.signer_set_id) || is_unsigned_anchor_id(set.id) {
            return Err(bad(format!(
                "checkpoint envelope {} REFUSED: signer-set ids {WS_RELEASE_SIGNER_SET_ID} and {WS_OPERATOR_TRUSTED_SIGNER_SET_ID} are reserved for \
                 release-baked and operator-trusted checkpoints, which are never signed (use --ws-trusted-checkpoint)",
                path.display()
            )));
        }
        let ok = ws::verify_envelope_with_shape_policy(
            &env,
            &set,
            network_id,
            genesis_root,
            &WsHybridVerifier,
            threshold,
            signers,
            min_external,
        )
        .map_err(|e| {
            bad(format!(
                "checkpoint envelope {} REFUSED: {e:?} (ws digest {})",
                path.display(),
                hex32(&env.checkpoint.ws_digest())
            ))
        })?;
        // The §6.3 window's missing LOWER bound. `ws::verify_envelope`
        // enforces `cp.epoch <= set.hard_stop()`, and `hard_stop()` is
        // `adopted_epoch` plus a fixed 41,040 epochs — so an `adopted_epoch`
        // large enough (10^12 is ~30 million years of 16-minute epochs) puts
        // the hard stop past every epoch the chain will ever reach and the
        // refusal becomes a comparison that can never be true. Nothing
        // validates that field: it arrives in the operator's `--ws-signer-set`
        // file, and there is no flag to check it at. Requiring the checkpoint
        // to be at or after the arrangement's own adoption closes it without a
        // clock, and it belongs HERE — this is the sole production caller of
        // envelope verification, so the rule covers every node without
        // editing the frozen committee crate. See `arrangement_window`.
        if let Err((adopted, hard)) = arrangement_window(&set, env.checkpoint.epoch) {
            return Err(bad(format!(
                "checkpoint envelope {} REFUSED: epoch {} is outside arrangement {}'s §6.3 \
                 validity window [{adopted}, {hard}].\n  An arrangement may not attest an \
                 epoch from before it was adopted. If the checkpoint epoch looks right, the \
                 arrangement's adopted_epoch is wrong — and an adopted_epoch in the future \
                 is exactly how the dead-man's switch gets pushed past every epoch this \
                 chain will reach, silently and permanently.\n  ws digest {}",
                path.display(),
                env.checkpoint.epoch,
                set.id,
                hex32(&env.checkpoint.ws_digest()),
            )));
        }
        if ok.arrangement_past_review {
            warnings.push(format!(
                "WARNING: signer arrangement {} is past its 12-month review deadline \
                 (inside grace). The review ADR is overdue — §6.3.",
                set.id
            ));
        }
        let cp = env.checkpoint;
        check_local_state(&cp, genesis_anchor, &local_state_root, &mut warnings)?;
        Some(cp)
    } else if let Some(trusted) = &cfg.trusted {
        Some(trusted_checkpoint(trusted, network_id, genesis_root, genesis_anchor, &local_state_root, &mut warnings)?)
    } else {
        None
    };

    let mut published: Option<WeakSubjectivityCheckpoint> = None;
    if let Some(cp) = incoming {
        // 4 (order matters): the cross-check against OWN finality comes
        // before admission. A published checkpoint that contradicts what this
        // node itself finalized is an alarm and is NOT admitted as an anchor;
        // it can never reorganize us (§5's structural limit).
        if has_local_finality {
            match ws::cross_check(local_root_at(cp.epoch), &cp) {
                CrossCheck::Consistent => {
                    warnings.push(format!(
                        "ws checkpoint at epoch {} is consistent with own finality",
                        cp.epoch
                    ));
                    published = Some(cp);
                }
                CrossCheck::AheadOfLocal => published = Some(cp),
                CrossCheck::Conflict { local_root, published_root } => {
                    warnings.push(format!(
                        "########################################################\n\
                         WS_CONFLICT: the published checkpoint contradicts this \
                         node's OWN finality at epoch {}.\n  local finalized root: {}\n  \
                         published root:       {}\nA checkpoint can never override a \
                         running node's finality — NOT reorganizing, KEEPING this \
                         database. Alert the operator and the publication channels: \
                         either the signers published a false checkpoint or this node \
                         is on a forged branch.\n\
                         ########################################################",
                        cp.epoch,
                        hex32(&local_root),
                        hex32(&published_root),
                    ));
                }
            }
        } else {
            published = Some(cp);
        }

        // 3. Anti-rollback against the stored ws_latest (§4.1).
        if let Some(cp) = published {
            // The same-fact rule comes with the release anchor: a default build
            // keeps fa980367's anti-rollback exactly (a re-mint with another
            // issued_at is WS_CONFLICT even when the roots agree).
            let decision = if RELEASE_ANCHOR_ENABLED { same_fact_accept(&anchor, &cp) } else { ws::accept(Some(&anchor), &cp) };
            match decision {
                Acceptance::Store => {
                    save_latest(data_dir, &cp)?;
                    anchor = cp;
                }
                Acceptance::Ignore => warnings.push(format!(
                    "ws checkpoint at epoch {} is not newer than stored ws_latest \
                     (epoch {}); logged and ignored (anti-rollback, §4.1)",
                    cp.epoch, anchor.epoch
                )),
                Acceptance::Conflict => {
                    return Ok(Err(format!(
                        "WS_CONFLICT (equivocal checkpoint): the supplied checkpoint \
                         carries the same epoch {} as the stored ws_latest but a \
                         different digest.\n  stored digest:   {}\n  incoming digest: {}\n\
                         Two validly-signed checkpoints for one epoch mean a \
                         quietly-replaced publication or an equivocal quorum — never a \
                         silent overwrite. Refusing to start; verify the digest across \
                         independent publication channels before trusting either \
                         artifact.",
                        cp.epoch,
                        hex32(&anchor.ws_digest()),
                        hex32(&cp.ws_digest()),
                    )));
                }
            }
        }
    }

    // 5. The four boot states (§4.2).
    let (fin_epoch, fin_root) = local_finalized;
    let age = wall_epoch.saturating_sub(fin_epoch);
    let anchor_age = wall_epoch.saturating_sub(anchor.epoch);
    let mut hard_anchor = !has_local_finality;
    let gate: Result<(), String> = match ws::boot_decision(has_local_finality, age) {
        BootDecision::Resume => Ok(()),
        BootDecision::ResumeStaleWarn => {
            warnings.push(format!(
                "WARNING: this node's finalized knowledge is {age} epochs old — inside \
                 the weak-subjectivity window ({} epochs) but past the freshness \
                 threshold ({}). Resuming from own finality, but fetch a fresh \
                 checkpoint ({}) before following any peer that offers a \
                 competing finalized branch.",
                ws::WS_PERIOD_EPOCHS,
                ws::WS_FRESH_EPOCHS,
                if AUTO_CHECKPOINT_ENABLED { "--ws-trusted-checkpoint or --ws-checkpoint" } else { "--ws-checkpoint" },
            ));
            Ok(())
        }
        BootDecision::RequireCheckpoint => {
            if anchor_age < ws::WS_PERIOD_EPOCHS {
                let which = if anchor.signer_set_id == ws::WS_GENESIS_SIGNER_SET_ID {
                    "the genesis anchor".to_string()
                } else {
                    format!("checkpoint epoch {}", anchor.epoch)
                };
                warnings.push(format!(
                    "fresh node: syncing under {which} (age {anchor_age} of {} epochs)",
                    ws::WS_PERIOD_EPOCHS
                ));
                Ok(())
            } else {
                Err(require_checkpoint_message(&anchor, anchor_age))
            }
        }
        BootDecision::RefuseStale => {
            if anchor_age < ws::WS_PERIOD_EPOCHS {
                // Recovery (§4.2): a fresh verified checkpoint exists. Descent
                // can only be established against blocks this node already
                // has — header-sync-forward does not exist at this milestone.
                let descends = is_canonical(&anchor.block_root);
                // Agent 181's finding: a node restarted part-way through a
                // checkpoint sync has some own finality, all of it older than
                // the window, and has not replayed up to the anchor block yet,
                // so `descends` is false and the old rule halted it. The
                // anchor is fresh, verified and AHEAD of everything this node
                // finalized: the node is in exactly the state it was in before
                // the restart, so it continues under the anchor as a HARD
                // anchor (a contradiction when its finality reaches the
                // anchor epoch exits 78, as for a fresh node). Nothing is
                // discarded, so no evidence disappears.
                let syncing_under_anchor = cfg.resume_sync_under_anchor
                    && anchor.signer_set_id != ws::WS_GENESIS_SIGNER_SET_ID
                    && anchor.epoch > fin_epoch;
                if !descends && syncing_under_anchor {
                    hard_anchor = true;
                    warnings.push(format!(
                        "resuming a checkpoint sync: own finality (epoch {fin_epoch}) is {age} epochs old, \
                         behind the verified anchor at epoch {}; continuing under that anchor as the only \
                         defense (hard), as before the restart",
                        anchor.epoch
                    ));
                    Ok(())
                } else { match ws::reconcile(&anchor, fin_root, descends) {
                    Reconciliation::ContinueForward => {
                        warnings.push(format!(
                            "own finality is {age} epochs old (beyond the {}-epoch \
                             window) but a fresh checkpoint at epoch {} descends from \
                             local history: continuing forward under it.",
                            ws::WS_PERIOD_EPOCHS,
                            anchor.epoch
                        ));
                        Ok(())
                    }
                    Reconciliation::HaltForOperator {
                        local_finalized_root,
                        checkpoint_root,
                    } => Err(format!(
                        "ERR_WS_STALE recovery halted: the fresh checkpoint does not \
                         verifiably descend from this node's finalized head, and the \
                         node will NOT silently discard its database — whichever side \
                         is wrong, that is how evidence disappears.\n  \
                         local finalized root: {}\n  checkpoint root:      {}\n\
                         Either local history was forged while the node was away, or \
                         the published checkpoint is wrong (or, at this devnet stage, \
                         the checkpoint is simply beyond the local head and \
                         header-sync-forward is not implemented). Resuming requires an \
                         explicit operator decision: compare both roots against \
                         operators you trust, then move the data dir aside by hand. \
                         (--ws-accept-reorg is not implemented yet.)",
                        hex32(&local_finalized_root),
                        hex32(&checkpoint_root),
                    )),
                } }
            } else {
                Err(format!(
                    "ERR_WS_STALE: this node's own finalized knowledge is {age} epochs \
                     old — at or beyond the weak-subjectivity window of {} epochs \
                     (≈ {} days at the mainnet slot cadence). Every validator that \
                     signed this database's finality markers may already have \
                     withdrawn, and could sign a conflicting continuation for free; \
                     the local markers are no longer a defense, so no peer can be \
                     safely followed. This refusal is the mechanism working, not a \
                     fault. Recover by obtaining a recent {} OUT OF BAND \
                     (see below) and restarting with it.\n\n{}",
                    ws::WS_PERIOD_EPOCHS,
                    window_days(),
                    if AUTO_CHECKPOINT_ENABLED { "checkpoint (operator-trusted or signed)" } else { "signed checkpoint" },
                    where_checkpoints_come_from(),
                ))
            }
        }
    };

    Ok(match gate {
        Ok(()) => Ok(WsOutcome {
            checkpoint: anchor,
            anchor_epoch: anchor.epoch,
            anchor_root: anchor.block_root,
            anchor_is_hard: hard_anchor,
            warnings,
        }),
        Err(msg) => Err(msg),
    })
}

fn require_checkpoint_message(anchor: &WeakSubjectivityCheckpoint, anchor_age: u64) -> String {
    let which = if anchor.signer_set_id == ws::WS_GENESIS_SIGNER_SET_ID {
        "the genesis anchor".to_string()
    } else {
        format!("a checkpoint at epoch {}", anchor.epoch)
    };
    format!(
        "ERR_WS_REQUIRE_CHECKPOINT: refusing to sync — and this is the mechanism \
         working, not a fault.\n\n\
         This node has no finalized history of its own, and its only trust anchor \
         ({which}) is {anchor_age} epochs old — at or beyond the weak-subjectivity \
         window of {} epochs (≈ {} days at the mainnet slot cadence). Under proof of \
         stake, validators who exited and withdrew long ago can sign a complete forged \
         history at zero cost; beyond the window, nothing inside the protocol lets a \
         syncing node tell that forgery from the chain the network actually lived. A \
         recent checkpoint obtained OUT OF BAND is the only sound way in.\n\n{}",
        ws::WS_PERIOD_EPOCHS,
        window_days(),
        where_checkpoints_come_from(),
    )
}

fn where_checkpoints_come_from() -> String {
    let unsigned = if AUTO_CHECKPOINT_ENABLED { UNSIGNED_SOURCES } else { "" };
    format!("{unsigned}{SIGNED_SOURCE}")
}

const UNSIGNED_SOURCES: &str =
    "Easiest (checkpoint sync, the Ethereum model — no files, no signatures):\n  \
     restart with --checkpoint-sync-url <host:port>,<host:port> naming RPCs of nodes \
     you trust (your own, or other operators'). Every endpoint must agree. Then compare \
     the printed block root with the explorer; add --ws-trusted-root <root> to pin it.\n\n\
     Operator-trusted checkpoint file (offline variant):\n  \
     1. Derive it from nodes you trust — your own, or other operators' — with \
     `bloch-pos ws-checkpoint --operator-trusted --genesis <manifest> --rpc <a>,<b>,<c> \
     --epoch <recent finalized epoch> --out <prefix>`; every endpoint must agree.\n  \
     2. Compare the printed block root against a SECOND, independent channel (the \
     explorer, another operator) — TWO independent channels at least.\n  \
     3. Restart with --ws-trusted-checkpoint <prefix>.bin --ws-trusted-root <block root>.\n\n";

const SIGNED_SOURCE: &str =
    "Signed checkpoint (BLOCH-WEAK-SUBJECTIVITY.md §2.3, §4.1):\n  \
     1. Fetch the latest signed checkpoint envelope from a channel you trust: the \
     Foundation site, the GitHub/GitLab release pages, the explorer front page, or \
     the announcement channel.\n  \
     2. Compare its 64-hex ws digest across AT LEAST TWO independent channels — \
     agreement across independent operators is the evidence, not the artifact's \
     say-so.\n  \
     3. Obtain the signer-arrangement SHA3-256 fingerprint through an independent \
     trusted channel, then restart with all three inputs: --ws-checkpoint <file> \
     --ws-signer-set <file> --ws-signer-set-sha3 <independently-verified-hex32>.";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::ws::{
        WS_FORMAT_VERSION, WS_PERIOD_EPOCHS, WS_PHASE_A_MIN_EXTERNAL, WS_PHASE_A_SIGNERS,
        WS_PHASE_A_THRESHOLD,
    };

    #[test]
    fn audit_only_typed_ws_policy_refusals_disable_automatic_restart() {
        let refusal = boot_refused("fresh checkpoint required");
        assert!(is_non_retryable(&refusal));
        assert_eq!(refusal.to_string(), "fresh checkpoint required");
        assert!(!is_non_retryable(&io::Error::new(io::ErrorKind::PermissionDenied, "file permission denied")));
        assert!(!is_non_retryable(&io::Error::new(io::ErrorKind::Other, "fresh checkpoint required")));
    }

    const NET: u32 = 0xD3_00_00_01;
    const GEN: [u8; 32] = [0x61; 32];

    fn checkpoint(epoch: u64) -> WeakSubjectivityCheckpoint {
        WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: NET,
            genesis_root: GEN,
            epoch,
            block_root: [0x22; 32],
            state_root: [0x33; 32],
            validator_set_root: [0x44; 32],
            issued_at: 1_800_000_000,
            signer_set_id: 1,
        }
    }

    fn genesis_anchor() -> WeakSubjectivityCheckpoint {
        ws::genesis_anchor(NET, GEN, [0x33; 32], [0u8; 32], 1_800_000_000)
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bloch-ws-boot-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn no_flags() -> WsConfig {
        WsConfig { checkpoint: None, signer_set: None, signer_set_sha3: None, trusted: None, ..WsConfig::default() }
    }

    // -- codecs -------------------------------------------------------------

    #[test]
    fn checkpoint_bytes_round_trip_and_reject_junk() {
        let cp = checkpoint(512);
        let bytes = cp.canonical_serialize();
        assert_eq!(decode_checkpoint(&bytes).unwrap(), cp);
        // Wrong length fails.
        assert!(decode_checkpoint(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(decode_checkpoint(&longer).is_err());
    }

    #[test]
    fn envelope_file_round_trips_and_rejects_trailing() {
        let env = CheckpointEnvelope {
            checkpoint: checkpoint(256),
            signatures: vec![(0, vec![0xAB; 100]), (2, vec![0xCD; 200])],
        };
        let bytes = encode_envelope_file(&env);
        let back = decode_envelope_file(&bytes).unwrap();
        assert_eq!(back.checkpoint, env.checkpoint);
        assert_eq!(back.signatures, env.signatures);
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(decode_envelope_file(&junk).is_err(), "encode(x) ‖ junk must not decode");
    }

    #[test]
    fn signer_set_file_round_trips() {
        let set = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: [1; HYBRID_PK_BYTES], external: false },
                Signer { pubkey: [2; HYBRID_PK_BYTES], external: true },
            ],
            threshold: 2,
            min_external: 1,
            adopted_epoch: 7,
        };
        let bytes = encode_signer_set_file(&set);
        let back = decode_signer_set_file(&bytes).unwrap();
        assert_eq!(back.id, set.id);
        assert_eq!(back.threshold, set.threshold);
        assert_eq!(back.min_external, set.min_external);
        assert_eq!(back.adopted_epoch, set.adopted_epoch);
        assert_eq!(back.signers.len(), 2);
        assert_eq!(back.signers[1].pubkey, set.signers[1].pubkey);
        assert!(back.signers[1].external);
        // An incoherent quorum shape is refused at decode, not at verify.
        let mut bad = set;
        bad.threshold = 3; // > signers.len()
        assert!(decode_signer_set_file(&encode_signer_set_file(&bad)).is_err());
    }

    // -- the real hybrid suite, end to end ----------------------------------

    /// Strip the 4-byte suite envelope bloch-crypto wraps around keys and
    /// signatures, asserting the suite is the hybrid one.
    fn strip(bytes: &[u8]) -> Vec<u8> {
        let (suite, body) = bloch_crypto::crypto::split_envelope(bytes).expect("enveloped");
        assert_eq!(suite, bloch_crypto::crypto::SUITE_MLDSA65_FALCON1024);
        body.to_vec()
    }

    /// A Phase-A-shaped 2-of-3 envelope signed by REAL ML-DSA-65 ‖
    /// Falcon-1024 keys verifies through the node's `WsHybridVerifier`, and
    /// the m-of-n rules hold under it: quorum without the external signer
    // ── the publication side: partials, combination, and its refusals ──────
    //
    // A signer whose output the verifier accepts is only half the test. Each
    // test below states a thing the ceremony must REFUSE, and each has a
    // recorded violation run: delete the check it names and exactly this test
    // goes red. See docs/CHECKPOINT-RUNBOOK.md §7.

    fn a_set(min_external: usize, adopted_epoch: u64) -> SignerSet {
        SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: [10u8; HYBRID_PK_BYTES], external: false },
                Signer { pubkey: [11u8; HYBRID_PK_BYTES], external: false },
                Signer { pubkey: [12u8; HYBRID_PK_BYTES], external: true },
            ],
            threshold: WS_PHASE_A_THRESHOLD,
            min_external,
            adopted_epoch,
        }
    }

    fn a_partial(cp: &WeakSubjectivityCheckpoint, index: u8) -> PartialSignature {
        PartialSignature {
            signer_index: index,
            digest: cp.ws_digest(),
            signature: vec![7u8; 4600],
        }
    }

    /// The round trip the ceremony exists to make possible: two signers who
    /// never met produce partials over the same digest and a coordinator
    /// combines them into an envelope with the expected shape.
    #[test]
    fn combined_partials_produce_the_expected_envelope() {
        let cp = checkpoint(1536);
        let set = a_set(WS_PHASE_A_MIN_EXTERNAL, 0);
        let env = combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 2)]).expect("combine");
        assert_eq!(env.checkpoint, cp);
        assert_eq!(env.signatures.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 2]);
    }

    /// Collection order must not change the artifact. Two honest coordinators
    /// who received the auditor's file at different times have to announce the
    /// same 64 hex characters, or the cross-channel comparison the mechanism
    /// rests on is comparing two different things.
    ///
    /// VIOLATION: delete `signatures.sort_by_key` in `combine` → red.
    #[test]
    fn combination_is_order_independent() {
        let cp = checkpoint(1536);
        let set = a_set(WS_PHASE_A_MIN_EXTERNAL, 0);
        let a = combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 2)]).unwrap();
        let b = combine(&cp, &set, &[a_partial(&cp, 2), a_partial(&cp, 0)]).unwrap();
        assert_eq!(a.signatures, b.signatures);
        assert_eq!(encode_envelope_file(&a), encode_envelope_file(&b));
    }

    /// A signature over a DIFFERENT root is not a signature about this
    /// checkpoint. The partial may be cryptographically perfect; it attests
    /// something else, and the coordinator finds that out — with the signer
    /// named — rather than a stranger finding it out as `BadSignature`.
    ///
    /// VIOLATION: delete the `p.digest != digest` check → red.
    #[test]
    fn combine_refuses_a_partial_over_a_different_root() {
        let cp = checkpoint(1536);
        let mut other = cp;
        other.block_root = [0xEE; 32];
        assert_ne!(cp.ws_digest(), other.ws_digest());
        assert_eq!(
            combine(&cp, &a_set(WS_PHASE_A_MIN_EXTERNAL, 0), &[a_partial(&cp, 0), a_partial(&other, 2)]).err().unwrap(),
            CombineReject::DigestMismatch { index: 2 }
        );
    }

    /// The same, for the epoch: last ceremony's signature cannot be recycled
    /// into this one. The 256-epoch cadence is exactly what makes this
    /// tempting.
    ///
    /// VIOLATION: delete the `p.digest != digest` check → red.
    #[test]
    fn combine_refuses_a_partial_for_a_different_epoch() {
        let cp = checkpoint(1536);
        let previous = checkpoint(1280);
        assert_eq!(
            combine(&cp, &a_set(WS_PHASE_A_MIN_EXTERNAL, 0), &[a_partial(&previous, 0), a_partial(&cp, 2)]).err().unwrap(),
            CombineReject::DigestMismatch { index: 0 }
        );
    }

    /// Both halves of the policy, refused at the ceremony rather than at a
    /// user's boot: too few signatures, and enough signatures without the
    /// external witness.
    ///
    /// VIOLATION: delete either count check in `combine` → red.
    #[test]
    fn combine_refuses_a_quorum_that_violates_the_policy() {
        let cp = checkpoint(1536);
        let set = a_set(WS_PHASE_A_MIN_EXTERNAL, 0);
        assert_eq!(
            combine(&cp, &set, &[a_partial(&cp, 2)]).err().unwrap(),
            CombineReject::QuorumNotReached { got: 1, need: WS_PHASE_A_THRESHOLD }
        );
        assert_eq!(
            combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 1)]).err().unwrap(),
            CombineReject::ExternalQuorumNotReached { got: 0, need: WS_PHASE_A_MIN_EXTERNAL }
        );
        assert_eq!(
            combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 7)]).err().unwrap(),
            CombineReject::UnknownSignerIndex { index: 7 }
        );
    }

    /// One key submitted twice is one signature. Counting it twice turns the
    /// 2-of-3 into a 1-of-3 — and if the duplicated key is the external one,
    /// into a quorum with no Foundation participation at all.
    ///
    /// VIOLATION: delete the `seen[...]` check in `combine` → red.
    #[test]
    fn combine_refuses_the_same_signer_counted_twice() {
        let cp = checkpoint(1536);
        let set = a_set(WS_PHASE_A_MIN_EXTERNAL, 0);
        assert_eq!(
            combine(&cp, &set, &[a_partial(&cp, 2), a_partial(&cp, 2)]).err().unwrap(),
            CombineReject::DuplicateSigner { index: 2 }
        );
        assert_eq!(
            combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 0)]).err().unwrap(),
            CombineReject::DuplicateSigner { index: 0 }
        );
    }

    /// The correspondence that keeps the ceremony side from drifting from the
    /// acceptance side: over every subset of a Phase A arrangement, `combine`
    /// succeeds exactly when `ws::verify_envelope` accepts the envelope it
    /// would have built. A rule added to one and not the other fails this.
    #[test]
    fn combine_agrees_with_verify_envelope() {
        let cp = checkpoint(1536);
        let set = a_set(WS_PHASE_A_MIN_EXTERNAL, 0);
        // A verifier that accepts any non-empty signature, so the only thing
        // separating the two sides is the counting rules.
        struct Yes;
        impl bloch_pos_committee::staking::HybridKeyVerifier for Yes {
            fn verify_mldsa65(&self, _p: &[u8], _r: &[u8; 32], s: &[u8]) -> bool {
                !s.is_empty()
            }
            fn verify_falcon1024(&self, _p: &[u8], _r: &[u8; 32], s: &[u8]) -> bool {
                !s.is_empty()
            }
        }
        for mask in 0u8..8 {
            let indices: Vec<u8> = (0u8..3).filter(|i| mask >> i & 1 == 1).collect();
            let partials: Vec<PartialSignature> =
                indices.iter().map(|i| a_partial(&cp, *i)).collect();
            let combined = combine(&cp, &set, &partials).is_ok();
            let verified = ws::verify_envelope(
                &CheckpointEnvelope {
                    checkpoint: cp,
                    signatures: indices.iter().map(|i| (*i, vec![7u8; 4600])).collect(),
                },
                &set,
                NET,
                &GEN,
                &Yes,
            )
            .is_ok();
            assert_eq!(combined, verified, "disagreement on signer subset {indices:?}");
        }
    }

    // ── the `adopted_epoch` hazard ─────────────────────────────────────────

    /// The defect, demonstrated with the real accessors rather than asserted
    /// from prose: `adopted_epoch` arrives from an operator file, and any
    /// large value makes §6.3's dead-man's switch unreachable. `u64::MAX`
    /// saturates the additions outright; 10^12 does not saturate anything and
    /// is just as fatal, because 10^12 epochs is ~30 million years.
    #[test]
    fn a_large_adopted_epoch_makes_the_dead_man_switch_unreachable() {
        for adopted in [10u64.pow(12), u64::MAX] {
            let set = a_set(WS_PHASE_A_MIN_EXTERNAL, adopted);
            // Every epoch the chain can reach is below the hard stop, so
            // `cp.epoch > set.hard_stop()` — the §6.3 refusal — is a
            // comparison that can never be true, and the 12-month review
            // warning never prints either.
            let plausible = 1_000_000u64; // ~30 years of 16-minute epochs
            assert!(plausible <= set.hard_stop(), "the refusal is unreachable");
            assert!(plausible <= set.review_deadline(), "the warning is unreachable too");
        }
        // And nothing in the frozen crate objects: verify_envelope judges the
        // hard stop the arrangement states, so it accepts.
        let set = a_set(WS_PHASE_A_MIN_EXTERNAL, u64::MAX);
        assert_eq!(set.hard_stop(), u64::MAX);
    }

    /// The bound, and where it has to live: there is no `--adopted-epoch`
    /// flag on the release lineage, so the field cannot be validated at a
    /// flag. It reaches production through exactly one path —
    /// `decode_signer_set_file` reading the operator's `--ws-signer-set`
    /// file, whose result is the only `SignerSet` `ws::verify_envelope` is
    /// ever called with. `arrangement_window` adds the missing LOWER bound:
    /// an arrangement may not attest an epoch from before it existed, which
    /// makes `[adopted_epoch, hard_stop()]` a real 41,040-epoch window
    /// wherever `adopted_epoch` is put.
    ///
    /// VIOLATION: delete the `epoch < set.adopted_epoch` clause in
    /// `arrangement_window` → red.
    #[test]
    fn the_arrangement_window_bounds_every_adopted_epoch() {
        let span = ws::WS_ARRANGEMENT_REVIEW_EPOCHS + ws::WS_ARRANGEMENT_GRACE_EPOCHS;

        // A sane arrangement: the window is exactly the review + grace span,
        // inclusive at both ends and refusing one past either.
        let set = a_set(WS_PHASE_A_MIN_EXTERNAL, 1_000);
        assert!(arrangement_window(&set, 1_000).is_ok(), "the adoption epoch itself");
        assert!(arrangement_window(&set, 1_000 + span).is_ok(), "the hard stop itself");
        assert!(arrangement_window(&set, 999).is_err(), "one epoch before adoption");
        assert!(arrangement_window(&set, 1_000 + span + 1).is_err(), "one past the hard stop");

        // The hazard: with adopted_epoch enormous, the upper bound is useless
        // and the LOWER one is what refuses every epoch the chain can reach.
        for adopted in [10u64.pow(12), u64::MAX] {
            let set = a_set(WS_PHASE_A_MIN_EXTERNAL, adopted);
            assert!(arrangement_window(&set, 1_536).is_err(), "adopted={adopted}");
            let cp = checkpoint(1536);
            assert_eq!(
                combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 2)]).err().unwrap(),
                CombineReject::OutsideArrangementWindow {
                    adopted_epoch: adopted,
                    hard_stop_epoch: set.hard_stop(),
                }
            );
        }
    }

    /// The same bound at the decoder, which is the gate that matters: it
    /// covers every `SignerSet` any node will ever judge, including files this
    /// toolchain did not write. Forged by byte surgery, exactly as an attacker
    /// with the published arrangement would do it.
    ///
    /// VIOLATION: delete the `hard_stop() < adopted_epoch` check in
    /// `decode_signer_set_file` → red.
    #[test]
    fn the_decoder_refuses_an_overflowing_arrangement_clock() {
        let bytes = encode_signer_set_file(&a_set(WS_PHASE_A_MIN_EXTERNAL, 1_000));
        decode_signer_set_file(&bytes).expect("a sane arrangement decodes");

        // adopted_epoch sits at offset 8 (magic) + 4 (id) + 4 (threshold)
        // + 4 (min_external) = 20.
        let mut forged = bytes.clone();
        forged[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            decode_signer_set_file(&forged).is_err(),
            "an arrangement whose clock saturates must not reach the boot path"
        );

        // The boundary is exactly the clamp and no wider: the largest
        // non-saturating value still decodes. No legitimate arrangement is
        // anywhere near it, which is why the check can be unconditional.
        let span = ws::WS_ARRANGEMENT_REVIEW_EPOCHS + ws::WS_ARRANGEMENT_GRACE_EPOCHS;
        let mut edge = bytes.clone();
        edge[20..28].copy_from_slice(&(u64::MAX - span).to_le_bytes());
        decode_signer_set_file(&edge).expect("the largest non-saturating value still decodes");
        let mut over = bytes;
        over[20..28].copy_from_slice(&(u64::MAX - span + 1).to_le_bytes());
        assert!(decode_signer_set_file(&over).is_err(), "one past the clamp boundary");
    }

    /// One key in two slots: the arrangement that is a 1-of-3 wearing a
    /// 2-of-3's clothes. `ws::verify_envelope` counts distinct INDICES, never
    /// distinct KEYS, so its holder signs once, lists the identical signature
    /// at both indices, and every counting rule passes. Proven against the
    /// real verifier, then refused at the decoder — the one place that covers
    /// every node without touching the frozen crate.
    ///
    /// VIOLATION: delete the `duplicate_key_slots` check in
    /// `decode_signer_set_file` → red.
    #[test]
    fn one_key_in_two_slots_is_a_forgeable_quorum_and_the_decoder_refuses_it() {
        let cp = checkpoint(1536);
        let digest = cp.ws_digest();
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(&strip(&pk));
        let (other_pk, _) = bloch_crypto::crypto::generate_keypair();
        let mut other = [0u8; HYBRID_PK_BYTES];
        other.copy_from_slice(&strip(&other_pk));

        let bad = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey, external: false },
                Signer { pubkey: other, external: false },
                Signer { pubkey, external: true }, // the SAME key, external slot
            ],
            threshold: WS_PHASE_A_THRESHOLD,
            min_external: WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        // One holder must not satisfy the quorum by occupying two indices.
        let one = strip(&bloch_crypto::crypto::sign(&sk, &digest).expect("sign"));
        let forged = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, one.clone()), (2, one)],
        };
        assert_eq!(
            ws::verify_envelope(&forged, &bad, NET, &GEN, &WsHybridVerifier),
            Err(ws::EnvelopeReject::DuplicateSignerKey { first: 0, second: 2 }),
        );
        // File decoding independently rejects the same duplicated key.
        assert!(!bad.matches_policy(
            WS_PHASE_A_THRESHOLD,
            WS_PHASE_A_SIGNERS,
            WS_PHASE_A_MIN_EXTERNAL,
        ) || duplicate_key_slots(&bad.signers).is_some());
        assert_eq!(duplicate_key_slots(&bad.signers), Some((0, 2)));
        assert!(
            decode_signer_set_file(&encode_signer_set_file(&bad)).is_err(),
            "a duplicate-key arrangement must not reach the boot path"
        );

        // Violating the guard: a SOUND arrangement of the same shape must
        // still decode, or the check would refuse correct ceremonies.
        let sound = SignerSet {
            signers: vec![
                Signer { pubkey, external: false },
                Signer { pubkey: other, external: false },
                Signer { pubkey: [9u8; HYBRID_PK_BYTES], external: true },
            ],
            ..bad
        };
        decode_signer_set_file(&encode_signer_set_file(&sound)).expect("sound arrangement decodes");
    }

    /// `min_external = 0` is accepted by the decoder and by
    /// `ws::verify_envelope`, so "every valid quorum contains the auditor" is
    /// a property of the ARRANGEMENT FILE, not of the code. The file arrives
    /// over the same unauthenticated channel as the envelope. This is the
    /// single most important caveat of the whole mechanism, so it is pinned as
    /// a test rather than left in prose.
    #[test]
    fn the_external_minimum_is_only_as_good_as_the_arrangement_file() {
        let cp = checkpoint(1536);
        let doctored = a_set(0, 0); // min_external = 0, everything else Phase A
        // The shape gate passes it...
        decode_signer_set_file(&encode_signer_set_file(&doctored))
            .expect("min_external = 0 is a coherent shape");
        // ...and a founder-only quorum then combines and would verify.
        assert!(combine(&cp, &doctored, &[a_partial(&cp, 0), a_partial(&cp, 1)]).is_ok());
        // What catches it is `matches_policy`, which no acceptance path calls.
        assert!(!doctored.matches_policy(
            WS_PHASE_A_THRESHOLD,
            WS_PHASE_A_SIGNERS,
            WS_PHASE_A_MIN_EXTERNAL,
        ));
        // The correct arrangement does match, so the check discriminates.
        assert!(a_set(WS_PHASE_A_MIN_EXTERNAL, 0).matches_policy(
            WS_PHASE_A_THRESHOLD,
            WS_PHASE_A_SIGNERS,
            WS_PHASE_A_MIN_EXTERNAL,
        ));
    }

    /// Re-minting the same epoch is a node-halting event, and the runbook has
    /// to say so in the operator's terms.
    ///
    /// `issued_at` is documented as informational — `verify_envelope` never
    /// reads it — but it IS inside `canonical_serialize`, so two mints of one
    /// epoch at different wall-clock times are two different digests. `accept`
    /// keys on the epoch: same epoch, different digest is
    /// `Acceptance::Conflict`, and `boot` turns a Conflict into a refusal to
    /// start. So publishing an interim checkpoint for epoch E and a corrected
    /// one later at the same E bricks the boot of every node that stored the
    /// first — with two perfectly valid quorums.
    #[test]
    fn re_minting_one_epoch_halts_every_node_that_saw_the_first() {
        let first = checkpoint(1536);
        let mut second = first;
        second.issued_at += 1; // one second later; nothing else changed

        assert_ne!(first.ws_digest(), second.ws_digest(), "issued_at is inside the digest");
        assert_eq!(first.epoch, second.epoch);
        assert_eq!(first.block_root, second.block_root, "they attest the SAME history");
        assert_eq!(ws::accept(Some(&first), &second), ws::Acceptance::Conflict);

        // The escape is to publish at a HIGHER epoch, never to re-mint the
        // same one: a later epoch is `Store` and supersedes cleanly.
        let next = checkpoint(1536 + ws::WS_PUBLICATION_INTERVAL_EPOCHS);
        assert_eq!(ws::accept(Some(&first), &next), ws::Acceptance::Store);
        // And re-delivering the IDENTICAL artifact is a harmless no-op, which
        // is why byte-identical re-mints are safe and near-identical are not.
        assert_eq!(ws::accept(Some(&first), &first), ws::Acceptance::Ignore);
    }

    /// fails, and one tampered signature rejects the whole envelope.
    #[test]
    fn real_hybrid_phase_a_envelope_verifies() {
        let cp = checkpoint(256);
        let digest = cp.ws_digest();

        let mut signers = Vec::new();
        let mut secrets = Vec::new();
        for _ in 0..3 {
            let (pk, sk) = bloch_crypto::crypto::generate_keypair();
            let raw = strip(&pk);
            let mut pubkey = [0u8; HYBRID_PK_BYTES];
            pubkey.copy_from_slice(&raw);
            signers.push(pubkey);
            secrets.push(sk);
        }
        let set = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: signers[0], external: false },
                Signer { pubkey: signers[1], external: false },
                Signer { pubkey: signers[2], external: true },
            ],
            threshold: WS_PHASE_A_THRESHOLD,
            min_external: WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        assert!(set.matches_policy(
            WS_PHASE_A_THRESHOLD,
            WS_PHASE_A_SIGNERS,
            WS_PHASE_A_MIN_EXTERNAL
        ));

        let sig_of = |i: usize| -> Vec<u8> {
            strip(&bloch_crypto::crypto::sign(&secrets[i], &digest).expect("sign"))
        };

        // Internal 0 + external 2: valid quorum.
        let env = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, sig_of(0)), (2, sig_of(2))],
        };
        ws::verify_envelope(&env, &set, NET, &GEN, &WsHybridVerifier).expect("must verify");

        // Round-trip the artifact through its file form and verify again —
        // the path the --ws-checkpoint flag exercises.
        let back = decode_envelope_file(&encode_envelope_file(&env)).unwrap();
        ws::verify_envelope(&back, &set, NET, &GEN, &WsHybridVerifier)
            .expect("file round-trip must still verify");

        // Two internal keys: m reached, external minimum not (§2.2 rule 4).
        let env_internal = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, sig_of(0)), (1, sig_of(1))],
        };
        assert!(matches!(
            ws::verify_envelope(&env_internal, &set, NET, &GEN, &WsHybridVerifier),
            Err(ws::EnvelopeReject::ExternalQuorumNotReached { .. })
        ));

        // One flipped bit in the external signature rejects the envelope.
        let mut tampered = sig_of(2);
        tampered[0] ^= 1;
        let env_bad = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, sig_of(0)), (2, tampered)],
        };
        assert!(matches!(
            ws::verify_envelope(&env_bad, &set, NET, &GEN, &WsHybridVerifier),
            Err(ws::EnvelopeReject::BadSignature { index: 2 })
        ));
    }

    // -- boot orchestration -------------------------------------------------

    #[test]
    fn audit_arrangement_pin_configuration_is_explicit_and_fail_closed() {
        let args = |values: &[&str]| values.iter().map(|value| value.to_string()).collect::<Vec<_>>();
        assert!(WsConfig::from_args(&args(&["--ws-signer-set-sha3"])).is_err());
        assert!(WsConfig::from_args(&args(&["--ws-signer-set-sha3", "abcd"])).is_err());
        let pin = "11".repeat(32);
        assert!(WsConfig::from_args(&args(&["--ws-signer-set-sha3", &pin, "--ws-signer-set-sha3", &pin])).is_err());
        for incomplete in [
            vec!["--ws-checkpoint", "checkpoint.bin"],
            vec!["--ws-signer-set", "set.bin"],
            vec!["--ws-signer-set-sha3", pin.as_str()],
            vec!["--ws-checkpoint", "checkpoint.bin", "--ws-signer-set", "set.bin"],
        ] {
            assert!(WsConfig::from_args(&args(&incomplete)).is_err());
        }
        assert!(WsConfig::from_args(&args(&["--ws-checkpoint", "--ws-signer-set", "set.bin"])).is_err());
        assert!(WsConfig::from_args(&args(&["--ws-checkpoint", "a", "--ws-checkpoint", "b",
            "--ws-signer-set", "set.bin", "--ws-signer-set-sha3", &pin])).is_err());
        assert!(WsConfig::from_args(&args(&["--", "--ws-checkpoint", "checkpoint.bin",
            "--ws-signer-set", "set.bin", "--ws-signer-set-sha3", &pin])).is_err());
        let config = WsConfig::from_args(&args(&["--ws-checkpoint", "checkpoint.bin",
            "--ws-signer-set", "set.bin", "--ws-signer-set-sha3", &pin])).unwrap();
        assert_eq!(config.checkpoint, Some(PathBuf::from("checkpoint.bin")));
        assert_eq!(config.signer_set, Some(PathBuf::from("set.bin")));
        assert_eq!(config.signer_set_sha3, Some([0x11; 32]));

        // Keep a second line of defense for programmatic callers that bypass
        // the CLI parser: a pin alone must not initialize ws_latest.
        let invalid = WsConfig {
            checkpoint: None,
            signer_set: None,
            signer_set_sha3: Some([0x11; 32]),
            trusted: None,
            ..WsConfig::default()
        };
        let dir = tmpdir("pin-missing-artifacts");
        let error = boot(&invalid, &dir, NET, &GEN, &genesis_anchor(), 0, false,
            (0, GEN), |_| None, |_| false, |_| None).err().unwrap();
        assert!(is_non_retryable(&error));
        assert!(!dir.join(WS_LATEST_FILE).exists(), "misconfigured pin must not silently initialize trust");
    }

    #[test]
    fn audit_arrangement_pin_refuses_review_clock_substitution_before_adoption() {
        let dir = tmpdir("pinned-arrangement");
        let mut checkpoint = checkpoint(64);
        checkpoint.signer_set_id = 3;
        let (set, signatures) = phase_a_set_and_signatures(3, &checkpoint.ws_digest());
        let envelope = CheckpointEnvelope { checkpoint, signatures };
        let original = encode_signer_set_file(&set);
        let mut changed = set.clone();
        changed.adopted_epoch = 1;
        // This is precisely the legacy gap: the old checkpoint signature does
        // not authenticate a changed arrangement review clock.
        ws::verify_envelope(&envelope, &changed, NET, &GEN, &WsHybridVerifier).unwrap();
        let arrangement_path = dir.join("arrangement.bin");
        let checkpoint_path = dir.join("checkpoint.bin");
        fs::write(&arrangement_path, encode_signer_set_file(&changed)).unwrap();
        fs::write(&checkpoint_path, encode_envelope_file(&envelope)).unwrap();
        let config = WsConfig { checkpoint: Some(checkpoint_path), signer_set: Some(arrangement_path.clone()),
            signer_set_sha3: Some(signer_set_fingerprint(&original)), trusted: None, ..WsConfig::default() };
        let error = boot(&config, &dir, NET, &GEN, &genesis_anchor(), 70, false,
            (0, GEN), |_| None, |_| false, |_| None).err().unwrap();
        assert!(is_non_retryable(&error));
        assert!(error.to_string().contains("fingerprint mismatch"));
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
        fs::write(&arrangement_path, original).unwrap();
        let outcome = boot(&config, &dir, NET, &GEN, &genesis_anchor(), 70, false,
            (0, GEN), |_| None, |_| false, |_| None).unwrap().unwrap();
        assert_eq!(outcome.checkpoint, checkpoint);
        assert!(!outcome.warnings.iter().any(|warning| warning.contains("not pinned")));
    }

    #[test]
    fn audit_genesis_boundary_preserves_published_header_root_convention() {
        let anchor = genesis_anchor();
        for header_root in [[0; 32], [0x77; 32]] {
            let local = |root: &[u8; 32]| if *root == GEN { Some(header_root) } else { None };
            let mut warnings = Vec::new();
            check_local_state(&anchor, &anchor, &local, &mut warnings).unwrap();
            let mut published = anchor;
            published.epoch = 1;
            published.signer_set_id = 3;
            published.state_root = header_root;
            check_local_state(&published, &anchor, &local, &mut warnings).unwrap();
            published.state_root = [0x99; 32];
            assert!(check_local_state(&published, &anchor, &local, &mut warnings).is_err());
            let mut corrupt_anchor = anchor;
            corrupt_anchor.state_root = header_root;
            assert!(check_local_state(&corrupt_anchor, &anchor, &local, &mut warnings).is_err());
        }
    }

    #[test]
    fn audit_checkpoint_state_is_checked_before_admission_and_on_restart() {
        let dir = tmpdir("local-state");
        let mut cp = checkpoint(64);
        cp.signer_set_id = 3;
        cp.validator_set_root = [0; 32]; // Published legacy sentinel remains valid.
        let (set, signatures) = phase_a_set_and_signatures(3, &cp.ws_digest());
        let envelope = dir.join("checkpoint.bin");
        let arrangement = dir.join("arrangement.bin");
        fs::write(&envelope, encode_envelope_file(&CheckpointEnvelope { checkpoint: cp, signatures })).unwrap();
        fs::write(&arrangement, encode_signer_set_file(&set)).unwrap();
        let unpinned = WsConfig { checkpoint: Some(envelope.clone()), signer_set: Some(arrangement.clone()), signer_set_sha3: None, trusted: None, ..WsConfig::default() };
        let error = boot(&unpinned, &dir, NET, &GEN, &genesis_anchor(), 70, true,
            (64, cp.block_root), |_| Some(cp.block_root), |_| true, |_| None).err().unwrap();
        assert!(is_non_retryable(&error));
        assert!(error.to_string().contains("REFUSED without --ws-signer-set-sha3"));
        let cfg = pinned_config(envelope, arrangement);
        let local = |root: &[u8; 32]| if *root == cp.block_root { Some([0xee; 32]) } else { None };
        let error = boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), 70, true,
            (64, cp.block_root), |_| Some(cp.block_root), |_| true, local).err().unwrap();
        assert!(is_non_retryable(&error));
        assert!(error.to_string().contains("WS_STATE_CONFLICT"));
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());

        boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), 70, true,
            (64, cp.block_root), |_| Some(cp.block_root), |_| true,
            |root| if *root == cp.block_root { Some(cp.state_root) } else { None }).unwrap().unwrap();
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), cp);
        let error = boot(&no_flags(), &dir, NET, &GEN, &genesis_anchor(), 70, true,
            (64, cp.block_root), |_| Some(cp.block_root), |_| true, local).err().unwrap();
        assert!(is_non_retryable(&error));
        assert!(error.to_string().contains("WS_STATE_CONFLICT"));
    }

    #[test]
    fn audit_malformed_ws_artifacts_are_typed_but_raw_io_errors_are_not() {
        let dir = tmpdir("operator-errors");
        let path = dir.join("checkpoint.bin");
        let config = WsConfig { checkpoint: Some(path.clone()), signer_set: None, signer_set_sha3: None, trusted: None, ..WsConfig::default() };
        let attempt = || boot(&config, &dir, NET, &GEN, &genesis_anchor(), 0, false, (0, GEN), |_| None, |_| false, |_| None);
        let missing = attempt().err().unwrap();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        assert!(!is_non_retryable(&missing));
        fs::write(&path, b"malformed").unwrap();
        assert!(is_non_retryable(&attempt().err().unwrap()));
        fs::write(&path, encode_envelope_file(&CheckpointEnvelope { checkpoint: checkpoint(0), signatures: vec![] })).unwrap();
        let absent_arrangement = attempt().err().unwrap();
        assert!(is_non_retryable(&absent_arrangement));
        assert!(absent_arrangement.to_string().contains("no signer arrangement"));
        fs::write(dir.join(WS_LATEST_FILE), b"malformed").unwrap();
        assert!(is_non_retryable(&load_latest(&dir, NET, &GEN).unwrap_err()));
    }

    #[test]
    fn fresh_node_boots_under_fresh_genesis_anchor_and_persists_it() {
        let dir = tmpdir("fresh");
        let out = boot(
            &no_flags(),
            &dir,
            NET,
            &GEN,
            &genesis_anchor(),
            0, // wall epoch: launch day
            false,
            (0, GEN),
            |_| None,
            |_| false, |_| None,
        )
        .unwrap()
        .expect("fresh node inside the trust-once window must sync");
        assert_eq!(out.anchor_epoch, 0);
        assert_eq!(out.anchor_root, GEN);
        assert!(out.anchor_is_hard);
        // Item 5: the genesis anchor became the first stored checkpoint.
        let stored = load_latest(&dir, NET, &GEN).unwrap().expect("persisted");
        assert_eq!(stored, genesis_anchor());
    }

    #[test]
    fn fresh_node_with_stale_anchor_refuses_and_says_where_to_get_one() {
        let dir = tmpdir("stale-fresh");
        let refusal = boot(
            &no_flags(),
            &dir,
            NET,
            &GEN,
            &genesis_anchor(),
            WS_PERIOD_EPOCHS, // the chain outgrew the trust-once window
            false,
            (0, GEN),
            |_| None,
            |_| false, |_| None,
        )
        .unwrap()
        .expect_err("a fresh node with only a stale anchor must not sync");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"));
        assert!(refusal.contains("--ws-checkpoint"));
        assert!(refusal.contains("TWO independent channels"));
        assert!(refusal.contains("not a fault"));
    }

    #[test]
    fn own_finality_resumes_and_warns_when_stale_inside_window() {
        let dir = tmpdir("resume");
        // Fresh: age 0.
        let out = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            10, true, (10, [0x55; 32]), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect("fresh own finality resumes");
        assert!(!out.anchor_is_hard);

        // Stale but inside the window: resumes with a prominent warning.
        let out = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            ws::WS_FRESH_EPOCHS + 5, true, (5, [0x55; 32]), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect("inside the window still resumes");
        assert!(out.warnings.iter().any(|w| w.contains("WARNING")));
    }

    #[test]
    fn beyond_window_refuses_without_a_fresh_checkpoint() {
        let dir = tmpdir("refuse-stale");
        let refusal = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            WS_PERIOD_EPOCHS + 7, true, (7, [0x55; 32]), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect_err("beyond the window with no checkpoint must refuse");
        assert!(refusal.contains("ERR_WS_STALE"));
        assert!(refusal.contains("--ws-checkpoint"));
    }

    #[test]
    fn anti_rollback_ignores_older_and_refuses_equivocal() {
        let dir = tmpdir("rollback");
        // Seed ws_latest at epoch 512.
        save_latest(&dir, &checkpoint(512)).unwrap();

        // Older incoming (epoch 256) via the pure rule the boot path calls.
        assert_eq!(
            ws::accept(Some(&checkpoint(512)), &checkpoint(256)),
            Acceptance::Ignore
        );
        // Same epoch, different digest: Conflict — and boot turns that into a
        // refusal (exercised end-to-end in ws_conflict_refuses_boot below).
        let mut equivocal = checkpoint(512);
        equivocal.block_root = [0xEE; 32];
        assert_eq!(ws::accept(Some(&checkpoint(512)), &equivocal), Acceptance::Conflict);

        // The stored artifact survives untouched.
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), checkpoint(512));
    }

    /// End-to-end: a validly-signed envelope for the SAME epoch as the stored
    /// ws_latest but a different digest refuses the boot loudly.
    /// The arrangement-window gate WHERE IT ACTUALLY RUNS.
    ///
    /// `the_arrangement_window_bounds_every_adopted_epoch` proves the
    /// predicate; this proves `boot` calls it. Without a test at this level
    /// the wiring could be deleted and every other test would stay green —
    /// which is the whole failure mode this gate exists to prevent, since the
    /// `adopted_epoch` it guards is itself a field nothing used to look at.
    ///
    /// The envelope here is signed by a real hybrid key over the real digest
    /// and `ws::verify_envelope` ACCEPTS it: the arrangement claims adoption
    /// at epoch 10^12, which no chain reaches, so the §6.3 hard stop is a
    /// comparison that can never fire. Nothing upstream objects. This gate is
    /// the only thing between that arrangement and a booting node.
    ///
    /// VIOLATION: delete the `arrangement_window` block in `boot` → red.
    #[test]
    fn boot_refuses_an_arrangement_adopted_after_the_checkpoint() {
        let dir = tmpdir("window");
        // A Phase-A-SHAPED arrangement, so the NEW-2 shape gate passes it and
        // the refusal under test is attributable to the window and nothing
        // else. (The original fixture was a 1-of-1; that shape is now refused
        // earlier, by the shape gate — see
        // `a_signer_set_outside_the_published_shapes_is_refused`.)
        let far = 10u64.pow(12);
        let mut signers = Vec::new();
        let mut secrets = Vec::new();
        for external in [true, false, false] {
            let (pk, sk) = bloch_crypto::crypto::generate_keypair();
            let raw = strip(&pk);
            let mut pubkey = [0u8; HYBRID_PK_BYTES];
            pubkey.copy_from_slice(&raw);
            signers.push(Signer { pubkey, external });
            secrets.push(sk);
        }
        let set = SignerSet {
            id: 9,
            signers,
            threshold: ws::WS_PHASE_A_THRESHOLD,
            min_external: ws::WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: far,
        };
        // The clock does not saturate, so the decoder admits it...
        let set_bytes = encode_signer_set_file(&set);
        decode_signer_set_file(&set_bytes).expect("10^12 saturates nothing; the decoder admits it");

        let mut cp = checkpoint(256);
        cp.signer_set_id = 9;
        let signatures = (0..2u8)
            .map(|i| {
                (i, strip(&bloch_crypto::crypto::sign(&secrets[i as usize], &cp.ws_digest()).unwrap()))
            })
            .collect();
        let env = CheckpointEnvelope { checkpoint: cp, signatures };
        // ...and the frozen verifier accepts the envelope outright, because
        // `cp.epoch > hard_stop()` is false and always will be.
        ws::verify_envelope(&env, &set, NET, &GEN, &WsHybridVerifier)
            .expect("verify_envelope has no lower bound to apply");

        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, &set_bytes).unwrap();

        let cfg = pinned_config(env_path, set_path);
        let err = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            300, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .expect_err("boot must refuse an arrangement adopted after the checkpoint");
        assert!(is_non_retryable(&err));
        let msg = err.to_string();
        assert!(msg.contains("outside arrangement"), "{msg}");
        assert!(msg.contains(&far.to_string()), "the message must name the adoption epoch: {msg}");

        // Violating the guard: the SAME envelope under an arrangement adopted
        // at a sane epoch must boot, so the refusal is attributable to
        // adopted_epoch and to nothing else about this envelope.
        let sane = SignerSet { adopted_epoch: 0, ..set };
        fs::write(dir.join("set-ok.bin"), encode_signer_set_file(&sane)).unwrap();
        let cfg = pinned_config(dir.join("env.bin"), dir.join("set-ok.bin"));
        boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            300, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .expect("io")
        .expect("a sanely-adopted arrangement must still boot");
    }

    #[test]
    fn ws_conflict_refuses_boot() {
        let dir = tmpdir("conflict");
        // The stored latest is the genesis anchor (epoch 0); craft an
        // equivocal "epoch 0" checkpoint signed by a real 1-of-1 arrangement.
        save_latest(&dir, &genesis_anchor()).unwrap();

        let mut cp = checkpoint(0);
        cp.signer_set_id = 9;
        let (set, signatures) = phase_a_set_and_signatures(9, &cp.ws_digest());
        let env = CheckpointEnvelope { checkpoint: cp, signatures };
        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(&set)).unwrap();

        let cfg = pinned_config(env_path, set_path);
        let refusal = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            1, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect_err("an equivocal same-epoch checkpoint must refuse the boot");
        assert!(refusal.contains("WS_CONFLICT"));
        assert!(refusal.contains("equivocal"));
        // The stored artifact was not overwritten.
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    /// A Phase A signer set (2-of-3, one external) plus two signatures over
    /// `digest` — signer 0 (external) and signer 1 — the minimum that clears
    /// both the threshold and `min_external`. NEW-2 made the set's shape
    /// policy: a 1-of-1 fixture no longer boots (see
    /// `a_signer_set_outside_the_published_shapes_is_refused`).
    fn phase_a_set_and_signatures(id: u32, digest: &[u8; 32]) -> (SignerSet, Vec<(u8, Vec<u8>)>) {
        let mut signers = Vec::new();
        let mut secrets = Vec::new();
        for external in [true, false, false] {
            let (pk, sk) = bloch_crypto::crypto::generate_keypair();
            let raw = strip(&pk);
            let mut pubkey = [0u8; HYBRID_PK_BYTES];
            pubkey.copy_from_slice(&raw);
            signers.push(Signer { pubkey, external });
            secrets.push(sk);
        }
        let set = SignerSet {
            id,
            signers,
            threshold: ws::WS_PHASE_A_THRESHOLD,
            min_external: ws::WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        let sigs = (0..2u8)
            .map(|i| {
                (i, strip(&bloch_crypto::crypto::sign(&secrets[i as usize], digest).unwrap()))
            })
            .collect();
        (set, sigs)
    }

    fn pinned_config(checkpoint: PathBuf, signer_set: PathBuf) -> WsConfig {
        let bytes = fs::read(&signer_set).unwrap();
        WsConfig {
            checkpoint: Some(checkpoint),
            signer_set: Some(signer_set),
            signer_set_sha3: Some(signer_set_fingerprint(&bytes)),
            trusted: None,
            ..WsConfig::default()
        }
    }

    /// A published checkpoint that contradicts OWN finality raises the alarm,
    /// is not admitted as the anchor, and never blocks the node from
    /// resuming on its own finality — the §5 structural limit.
    #[test]
    fn published_checkpoint_never_overrides_own_finality() {
        let dir = tmpdir("cross-check");
        let mut cp = checkpoint(64);
        cp.signer_set_id = 3;
        let (set, signatures) = phase_a_set_and_signatures(3, &cp.ws_digest());
        let env = CheckpointEnvelope { checkpoint: cp, signatures };
        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(&set)).unwrap();
        let cfg = pinned_config(env_path, set_path);

        // The node's own finalized root at epoch 64 differs from cp's.
        let own_root = [0x99; 32];
        let out = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            70, true, (70, own_root),
            move |e| if e <= 70 { Some(own_root) } else { None },
            |_| false, |_| None,
        )
        .unwrap()
        .expect("a conflicting published checkpoint must not stop a fresh node's resume");
        assert!(out.warnings.iter().any(|w| w.contains("WS_CONFLICT")));
        assert!(out.warnings.iter().any(|w| w.contains("NOT reorganizing")));
        // Not admitted: the anchor is still the genesis anchor.
        assert_eq!(out.anchor_epoch, 0);
        assert!(!out.anchor_is_hard);
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    /// **NEW-2 regression.** A signer set whose shape is not one of the two
    /// published arrangements — here the 1-of-1 fixture the tests above used
    /// to boot with — is refused BEFORE any signature is checked, naming both
    /// accepted shapes. Revert the shape check in `boot` and this test fails:
    /// the envelope verifies under its single key and the boot proceeds.
    #[test]
    fn a_signer_set_outside_the_published_shapes_is_refused() {
        let dir = tmpdir("shape-policy");
        save_latest(&dir, &genesis_anchor()).unwrap();
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let raw = strip(&pk);
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(&raw);
        let set = SignerSet {
            id: 11,
            signers: vec![Signer { pubkey, external: true }],
            threshold: 1,
            min_external: 1,
            adopted_epoch: 0,
        };
        let mut cp = checkpoint(64);
        cp.signer_set_id = 11;
        let env = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, strip(&bloch_crypto::crypto::sign(&sk, &cp.ws_digest()).unwrap()))],
        };
        // Control: the envelope itself is valid under its own set — so the
        // refusal below is the shape rule and nothing else.
        ws::verify_envelope(&env, &set, NET, &GEN, &WsHybridVerifier).expect("control: verifies");
        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(&set)).unwrap();
        let cfg = pinned_config(env_path, set_path);
        let err = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            1, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .err()
        .expect("a 1-of-1 signer set must not become a root of trust");
        assert!(is_non_retryable(&err));
        let msg = err.to_string();
        assert!(msg.contains("REFUSED") && msg.contains("Phase A") && msg.contains("Phase B"), "{msg}");
        // Nothing was adopted.
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    // -- owner runbook evidence (docs/WS-CHECKPOINT-OWNER-RUNBOOK.md) -------
    //
    // These pin the mainnet numbers the owner runbook relies on: the window
    // around a checkpoint at epoch 7168, the restart-during-sync halt, and the
    // difference between re-signing (safe) and re-minting (halts nodes).

    fn owner_set_and_secrets(id: u32) -> (SignerSet, Vec<Vec<u8>>) {
        let mut signers = Vec::new();
        let mut secrets = Vec::new();
        for external in [true, true, true] {
            let (pk, sk) = bloch_crypto::crypto::generate_keypair();
            let mut pubkey = [0u8; HYBRID_PK_BYTES];
            pubkey.copy_from_slice(&strip(&pk));
            signers.push(Signer { pubkey, external });
            secrets.push(sk.to_vec());
        }
        let set = SignerSet {
            id,
            signers,
            threshold: ws::WS_PHASE_A_THRESHOLD,
            min_external: ws::WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        (set, secrets)
    }

    fn owner_envelope(cp: WeakSubjectivityCheckpoint, secrets: &[Vec<u8>], who: &[u8]) -> CheckpointEnvelope {
        let signatures = who
            .iter()
            .map(|i| (*i, strip(&bloch_crypto::crypto::sign(&secrets[*i as usize], &cp.ws_digest()).unwrap())))
            .collect();
        CheckpointEnvelope { checkpoint: cp, signatures }
    }

    fn write_artifacts(dir: &Path, tag: &str, env: &CheckpointEnvelope, set: &SignerSet) -> WsConfig {
        let env_path = dir.join(format!("{tag}-env.bin"));
        let set_path = dir.join(format!("{tag}-set.bin"));
        fs::write(&env_path, encode_envelope_file(env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(set)).unwrap();
        pinned_config(env_path, set_path)
    }

    /// Mainnet today: a wiped node holding only the genesis anchor refuses
    /// (agent 106's ERR_WS_REQUIRE_CHECKPOINT); an epoch-7168 envelope admits
    /// it and is persisted, after which restarts need no flags until wall
    /// epoch 9183 inclusive; from 9184 a node without finality refuses again.
    #[test]
    fn owner_runbook_window_for_an_epoch_7168_checkpoint() {
        let dir = tmpdir("owner-7168");
        let wall = 7290;
        let refusal = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            wall, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect_err("the genesis anchor is 7290 epochs old");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"), "{refusal}");

        let (set, secrets) = owner_set_and_secrets(1);
        let env = owner_envelope(checkpoint(7168), &secrets, &[0, 1]);
        let cfg = write_artifacts(&dir, "e7168", &env, &set);
        let ok = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            wall, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect("a fresh 2-of-3 envelope admits a wiped node");
        assert_eq!(ok.anchor_epoch, 7168);
        assert!(ok.anchor_is_hard);
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), checkpoint(7168));

        let last_ok = 7168 + WS_PERIOD_EPOCHS - 1;
        assert_eq!(last_ok, 9183);
        boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            last_ok, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect("the stored ws_latest still admits a fresh boot at 9183");
        let refusal = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            last_ok + 1, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect_err("at 9184 the 7168 checkpoint has aged out");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"), "{refusal}");
        assert!(refusal.contains("checkpoint at epoch 7168"), "{refusal}");
    }

    /// A node syncing from genesis under a checkpoint has its OWN finality
    /// after the first finalized epochs. If it restarts while that finality
    /// is still 2016 or more epochs behind the wall clock and before it holds
    /// the checkpoint block, the boot halts for the operator (ERR_WS_STALE
    /// recovery halted, exit 78). Inside the window it resumes with a
    /// warning, and once the checkpoint block is canonical it continues.
    #[test]
    fn owner_runbook_restart_during_sync_before_the_checkpoint_block_halts() {
        let dir = tmpdir("owner-midsync");
        save_latest(&dir, &checkpoint(7168)).unwrap();
        let wall = 7290;
        let halted = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            wall, true, (3000, [0x55; 32]), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect_err("own finality 4290 epochs old, checkpoint block not yet local");
        assert!(halted.contains("ERR_WS_STALE recovery halted"), "{halted}");

        let resumed = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            wall, true, (wall - WS_PERIOD_EPOCHS + 1, [0x55; 32]), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect("own finality inside the window resumes");
        assert!(resumed.warnings.iter().any(|w| w.contains("WARNING")), "{:?}", resumed.warnings);

        boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            wall, true, (3000, [0x55; 32]), |_| None, |_| true, |_| None,
        )
        .unwrap()
        .expect("a checkpoint block already on the local chain continues forward");

        let wiped = tmpdir("owner-midsync-wiped");
        save_latest(&wiped, &checkpoint(7168)).unwrap();
        boot(
            &no_flags(), &wiped, NET, &GEN, &genesis_anchor(),
            wall, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect("chain files removed, ws_latest.bin kept: starts again as a fresh node");
    }

    /// Signatures are randomised, so two signing sessions over the SAME
    /// checkpoint bytes give different envelopes; both verify and the second
    /// is a no-op. Minting the same epoch again with another issued_at gives
    /// a different digest and refuses the boot of every node that stored the
    /// first.
    #[test]
    fn owner_runbook_resigning_is_safe_reminting_is_not() {
        let dir = tmpdir("owner-resign");
        let (set, secrets) = owner_set_and_secrets(1);
        let cp = checkpoint(7168);
        let first = owner_envelope(cp, &secrets, &[0, 1]);
        let second = owner_envelope(cp, &secrets, &[0, 2]);
        let again = owner_envelope(cp, &secrets, &[0, 1]);
        assert_ne!(first.signatures[0].1, again.signatures[0].1, "signatures are randomised");
        for env in [&first, &second, &again] {
            ws::verify_envelope(env, &set, NET, &GEN, &WsHybridVerifier).expect("each verifies");
        }
        let wall = 7290;
        let cfg = write_artifacts(&dir, "first", &first, &set);
        boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), wall, false, (0, GEN), |_| None, |_| false, |_| None)
            .unwrap()
            .expect("first envelope admitted");
        let cfg = write_artifacts(&dir, "second", &second, &set);
        let ok = boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), wall, false, (0, GEN), |_| None, |_| false, |_| None)
            .unwrap()
            .expect("a re-signed envelope of the same bytes is a no-op");
        assert!(ok.warnings.iter().any(|w| w.contains("not newer")), "{:?}", ok.warnings);

        let mut reminted = cp;
        reminted.issued_at += 1;
        assert_ne!(reminted.ws_digest(), cp.ws_digest());
        let env = owner_envelope(reminted, &secrets, &[0, 1]);
        let cfg = write_artifacts(&dir, "reminted", &env, &set);
        let attempt = boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), wall, false, (0, GEN), |_| None, |_| false, |_| None)
            .unwrap();
        if RELEASE_ANCHOR_ENABLED {
            // Same-fact rule: same block and state, so one fact.
            attempt.expect("same roots at one epoch are not an equivocation under ws-release-anchor");
        } else {
            let refusal = attempt.expect_err("a re-mint of a stored epoch refuses the boot");
            assert!(refusal.contains("WS_CONFLICT"), "{refusal}");
        }
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), cp);
    }

    // ── operator-trusted (unsigned) checkpoints: the Ethereum model ────────

    fn trusted_cp(epoch: u64) -> WeakSubjectivityCheckpoint {
        WeakSubjectivityCheckpoint {
            validator_set_root: [0; 32],
            signer_set_id: WS_OPERATOR_TRUSTED_SIGNER_SET_ID,
            ..checkpoint(epoch)
        }
    }

    fn trusted_config(dir: &Path, cp: &WeakSubjectivityCheckpoint, root: [u8; 32]) -> WsConfig {
        let path = dir.join("trusted.bin");
        fs::write(&path, cp.canonical_serialize()).unwrap();
        WsConfig { trusted: Some(TrustedCheckpoint { source: TrustedSource::File(path), block_root: Some(root) }), ..WsConfig::default() }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[cfg(feature = "ws-auto-checkpoint")]
    #[test]
    fn trusted_flags_parse_and_sources_are_alternatives() {
        let root = "22".repeat(32);
        let cfg = WsConfig::from_args(&args(&["--ws-trusted-checkpoint", "cp.bin", "--ws-trusted-root", &root])).unwrap();
        let trusted = cfg.trusted.expect("parsed");
        assert!(matches!(&trusted.source, TrustedSource::File(p) if *p == PathBuf::from("cp.bin")));
        assert_eq!(trusted.block_root, Some([0x22; 32]));
        // The comparison root is optional, as Ethereum's --wss-checkpoint is.
        let cfg = WsConfig::from_args(&args(&["--ws-trusted-checkpoint", "cp.bin"])).unwrap();
        assert_eq!(cfg.trusted.expect("parsed").block_root, None);
        // ...but a root alone compares nothing.
        assert!(WsConfig::from_args(&args(&["--ws-trusted-root", &root])).is_err());
        assert!(WsConfig::from_args(&args(&["--ws-trusted-checkpoint", "cp.bin", "--ws-trusted-root", "22"])).is_err());

        let cfg = WsConfig::from_args(&args(&["--checkpoint-sync-url", "http://10.0.0.1:8080/, 10.0.0.2:8080",
            "--ws-trusted-root", &root])).unwrap();
        assert_eq!(cfg.checkpoint_sync, vec!["10.0.0.1:8080".to_string(), "10.0.0.2:8080".to_string()]);
        assert_eq!(cfg.checkpoint_sync_pin, Some([0x22; 32]));
        assert!(cfg.trusted.is_none(), "filled only at boot, and only when needed");
        assert!(WsConfig::from_args(&args(&["--checkpoint-sync-url", "https://rpc.example"])).is_err());

        let both = args(&["--ws-trusted-checkpoint", "cp.bin", "--ws-trusted-root", &root,
            "--ws-checkpoint", "e", "--ws-signer-set", "s", "--ws-signer-set-sha3", &root]);
        assert!(WsConfig::from_args(&both).err().unwrap().contains("alternatives"));
        let both = args(&["--ws-trusted-checkpoint", "cp.bin", "--checkpoint-sync-url", "a:1"]);
        assert!(WsConfig::from_args(&both).err().unwrap().contains("alternatives"));
    }

    /// --checkpoint-sync-url hands boot an in-memory checkpoint; no file, no pin.
    #[test]
    fn fetched_checkpoint_boots_a_fresh_node_without_any_file() {
        let dir = tmpdir("trusted-fetched");
        let cp = trusted_cp(5000);
        let cfg = WsConfig {
            trusted: Some(TrustedCheckpoint { source: TrustedSource::Fetched(cp), block_root: None }),
            ..WsConfig::default()
        };
        let out = boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), 5010, false, (0, GEN), |_| None, |_| false, |_| None)
            .unwrap()
            .expect("fetched checkpoint anchors the sync");
        assert_eq!(out.anchor_epoch, 5000);
        assert!(out.warnings.iter().any(|w| w.contains("no --ws-trusted-root")));
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), cp);
    }

    /// The point of the feature: past the trust-once window a fresh node
    /// boots with no signature from anyone, under the root its operator chose.
    #[test]
    fn fresh_node_boots_under_an_operator_trusted_checkpoint() {
        let dir = tmpdir("trusted-fresh");
        let cp = trusted_cp(5000);
        let out = boot(
            &trusted_config(&dir, &cp, cp.block_root), &dir, NET, &GEN, &genesis_anchor(),
            5010, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect("a fresh operator-trusted checkpoint must let a fresh node sync");
        assert_eq!(out.anchor_epoch, 5000);
        assert_eq!(out.anchor_root, cp.block_root);
        assert!(out.anchor_is_hard, "with no own finality the anchor is the only defense");
        assert!(out.warnings.iter().any(|w| w.contains("operator-trusted")));
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), cp);
    }

    #[test]
    fn trusted_checkpoint_refuses_a_root_the_operator_did_not_compare() {
        let dir = tmpdir("trusted-root-mismatch");
        let cp = trusted_cp(5000);
        let error = boot(
            &trusted_config(&dir, &cp, [0x99; 32]), &dir, NET, &GEN, &genesis_anchor(),
            5010, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .err()
        .expect("disagreeing channels must refuse");
        assert!(is_non_retryable(&error));
        assert!(error.to_string().contains("disagree"));
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    #[test]
    fn trusted_checkpoint_refuses_signed_ids_other_networks_and_epoch_zero() {
        let dir = tmpdir("trusted-shape");
        let attempt = |cp: WeakSubjectivityCheckpoint| boot(
            &trusted_config(&dir, &cp, cp.block_root), &dir, NET, &GEN, &genesis_anchor(),
            5010, false, (0, GEN), |_| None, |_| false, |_| None,
        );
        let signed_id = WeakSubjectivityCheckpoint { signer_set_id: 1, ..trusted_cp(5000) };
        assert!(attempt(signed_id).err().unwrap().to_string().contains("not an operator-trusted"));
        let other_net = WeakSubjectivityCheckpoint { network_id: NET + 1, ..trusted_cp(5000) };
        assert!(attempt(other_net).err().unwrap().to_string().contains("different network"));
        assert!(attempt(trusted_cp(0)).is_err());
    }

    /// Unsigned does not mean unbounded: a stale root still cannot sync.
    #[test]
    fn stale_trusted_checkpoint_still_refuses() {
        let dir = tmpdir("trusted-stale");
        let cp = trusted_cp(100);
        let refusal = boot(
            &trusted_config(&dir, &cp, cp.block_root), &dir, NET, &GEN, &genesis_anchor(),
            100 + WS_PERIOD_EPOCHS, false, (0, GEN), |_| None, |_| false, |_| None,
        )
        .unwrap()
        .expect_err("a checkpoint at or beyond the window must not anchor a sync");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"));
        // Only prototype builds point operators at the unsigned flags.
        assert_eq!(refusal.contains("--ws-trusted-checkpoint"), AUTO_CHECKPOINT_ENABLED);
    }

    /// The operator's word moves a newcomer, never a running node.
    #[test]
    fn trusted_checkpoint_never_overrides_own_finality() {
        let dir = tmpdir("trusted-vs-own");
        let cp = trusted_cp(64);
        let out = boot(
            &trusted_config(&dir, &cp, cp.block_root), &dir, NET, &GEN, &genesis_anchor(),
            70, true, (66, [0x55; 32]), |_| Some([0x55; 32]), |_| true, |_| None,
        )
        .unwrap()
        .expect("own finality resumes");
        assert!(out.warnings.iter().any(|w| w.contains("WS_CONFLICT")));
        assert_eq!(out.anchor_epoch, 0, "a contradicting checkpoint is not admitted");
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    /// A signed and an operator-trusted checkpoint of the same block are one
    /// fact; different blocks at one epoch stay an equivocation.
    #[cfg(feature = "ws-auto-checkpoint")]
    #[test]
    fn same_epoch_same_roots_is_not_an_equivocation() {
        let signed = checkpoint(512);
        let trusted = WeakSubjectivityCheckpoint { issued_at: 1, ..trusted_cp(512) };
        assert_ne!(signed.ws_digest(), trusted.ws_digest());
        assert!(matches!(same_fact_accept(&signed, &trusted), Acceptance::Ignore));
        let forked = WeakSubjectivityCheckpoint { block_root: [0x77; 32], ..trusted };
        assert!(matches!(same_fact_accept(&signed, &forked), Acceptance::Conflict));
    }

    #[test]
    fn the_operator_trusted_id_can_never_be_combined_into_an_envelope() {
        let cp = trusted_cp(1536);
        let set = SignerSet { id: WS_OPERATOR_TRUSTED_SIGNER_SET_ID, ..a_set(WS_PHASE_A_MIN_EXTERNAL, 0) };
        assert!(matches!(
            combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 2)]),
            Err(CombineReject::ReservedSignerSet)
        ));
    }

    // ── agent 208: release-baked anchor and restart-during-sync (prototype) ──

    fn release_cp(epoch: u64) -> WeakSubjectivityCheckpoint {
        WeakSubjectivityCheckpoint {
            validator_set_root: [0; 32],
            signer_set_id: WS_RELEASE_SIGNER_SET_ID,
            ..checkpoint(epoch)
        }
    }

    fn release_config(cp: WeakSubjectivityCheckpoint) -> WsConfig {
        WsConfig { release_anchor: Some(cp), ..WsConfig::default() }
    }

    #[test]
    fn default_build_is_inert() {
        assert_eq!(AUTO_CHECKPOINT_ENABLED, cfg!(feature = "ws-auto-checkpoint"));
        let parsed = WsConfig::from_args(&args(&["--data-dir", "x"])).unwrap();
        assert_eq!(RELEASE_ANCHOR_ENABLED, cfg!(feature = "ws-release-anchor"));
        assert!(RELEASE_ANCHOR_ENABLED || !AUTO_CHECKPOINT_ENABLED, "ws-auto-checkpoint implies ws-release-anchor");
        assert_eq!(parsed.resume_sync_under_anchor, RELEASE_ANCHOR_ENABLED);
        // Only a ws-release-anchor build compiles the anchor in.
        if !RELEASE_ANCHOR_ENABLED {
            assert!(parsed.release_anchor.is_none());
            assert!(compiled_release_anchor().unwrap().is_none());
        }
        assert_eq!(parsed.release_anchor, compiled_release_anchor().unwrap());
        if !AUTO_CHECKPOINT_ENABLED {
            for flags in [
                vec!["--checkpoint-sync-url", "127.0.0.1:1"],
                vec!["--ws-trusted-checkpoint", "cp.bin"],
            ] {
                let error = WsConfig::from_args(&args(&flags)).err().expect("refused without the feature");
                assert!(error.contains("not enabled in this build"), "{error}");
            }
        }
    }

    #[test]
    fn release_anchor_file_decoding() {
        assert_eq!(decode_release_anchor(&[]).unwrap(), None);
        let cp = release_cp(7168);
        assert_eq!(decode_release_anchor(&cp.canonical_serialize()).unwrap(), Some(cp));
        let signed = WeakSubjectivityCheckpoint { validator_set_root: [0; 32], ..checkpoint(7168) };
        assert!(decode_release_anchor(&signed.canonical_serialize()).unwrap_err().contains("reserved release id"));
        let trusted = WeakSubjectivityCheckpoint { signer_set_id: WS_OPERATOR_TRUSTED_SIGNER_SET_ID, ..cp };
        assert!(decode_release_anchor(&trusted.canonical_serialize()).is_err());
        assert!(decode_release_anchor(&release_cp(0).canonical_serialize()).is_err());
        let nonzero = WeakSubjectivityCheckpoint { validator_set_root: [1; 32], ..cp };
        assert!(decode_release_anchor(&nonzero.canonical_serialize()).is_err());
        assert!(decode_release_anchor(&cp.canonical_serialize()[..100]).is_err());
    }

    /// The headline: a wiped mainnet node at wall epoch 7290 boots with no
    /// flag and no signature because its release bakes epoch 7168.
    #[test]
    fn release_anchor_boots_a_fresh_node_with_no_flags() {
        let dir = tmpdir("release-fresh");
        let wall = 7290;
        let out = boot(&release_config(release_cp(7168)), &dir, NET, &GEN, &genesis_anchor(), wall, false,
            (0, GEN), |_| None, |_| false, |_| None).unwrap().expect("release anchor admits a fresh node");
        assert_eq!(out.anchor_epoch, 7168);
        assert!(out.anchor_is_hard);
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), release_cp(7168));
        assert!(out.warnings.iter().any(|w| w.contains("release-baked checkpoint adopted")), "{:?}", out.warnings);
        // The window is unchanged: a release older than 2016 epochs is refused
        // like any other stale anchor, and the message still says where to go.
        let old = tmpdir("release-stale");
        let refusal = boot(&release_config(release_cp(7168)), &old, NET, &GEN, &genesis_anchor(),
            7168 + WS_PERIOD_EPOCHS, false, (0, GEN), |_| None, |_| false, |_| None)
            .unwrap().expect_err("an aged release anchor does not stretch the window");
        assert!(refusal.contains("ERR_WS_REQUIRE_CHECKPOINT"), "{refusal}");
    }

    #[test]
    fn release_anchor_for_another_network_is_ignored_not_fatal() {
        let dir = tmpdir("release-other-net");
        let foreign = WeakSubjectivityCheckpoint { network_id: NET ^ 1, ..release_cp(64) };
        let out = boot(&release_config(foreign), &dir, NET, &GEN, &genesis_anchor(), 70, false,
            (0, GEN), |_| None, |_| false, |_| None).unwrap().expect("young devnet boots on genesis");
        assert_eq!(out.anchor_epoch, 0);
        assert!(out.warnings.iter().any(|w| w.contains("not this one; ignored")), "{:?}", out.warnings);
    }

    /// A release can never move a running node: a contradiction with own
    /// finality is the WS_CONFLICT alarm, the anchor is not adopted, and the
    /// node keeps its own finality.
    #[test]
    fn release_anchor_never_overrides_own_finality() {
        let dir = tmpdir("release-conflict");
        let out = boot(&release_config(release_cp(7168)), &dir, NET, &GEN, &genesis_anchor(), 7290, true,
            (7280, [0x77; 32]), |_| Some([0x99; 32]), |_| true, |_| None).unwrap().expect("own finality resumes");
        assert!(!out.anchor_is_hard);
        assert_ne!(out.anchor_epoch, 7168);
        assert!(out.warnings.iter().any(|w| w.contains("WS_CONFLICT")), "{:?}", out.warnings);
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    /// The release anchor, a signed envelope and an operator-trusted file for
    /// the same block are one fact. A different block at the same epoch is a
    /// loud refusal. An older release never rolls a newer stored anchor back.
    #[test]
    fn release_anchor_same_fact_conflict_and_anti_rollback() {
        let dir = tmpdir("release-same-fact");
        save_latest(&dir, &checkpoint(7168)).unwrap();
        boot(&release_config(release_cp(7168)), &dir, NET, &GEN, &genesis_anchor(), 7290, false,
            (0, GEN), |_| None, |_| false, |_| None).unwrap().expect("same block and state: one fact");
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), checkpoint(7168));

        let other = WeakSubjectivityCheckpoint { block_root: [0x23; 32], ..release_cp(7168) };
        let refusal = boot(&release_config(other), &dir, NET, &GEN, &genesis_anchor(), 7290, false,
            (0, GEN), |_| None, |_| false, |_| None).unwrap().expect_err("same epoch, other block");
        assert!(refusal.contains("WS_CONFLICT (release-baked checkpoint)"), "{refusal}");

        let newer = tmpdir("release-rollback");
        save_latest(&newer, &checkpoint(7424)).unwrap();
        let out = boot(&release_config(release_cp(7168)), &newer, NET, &GEN, &genesis_anchor(), 7500, false,
            (0, GEN), |_| None, |_| false, |_| None).unwrap().expect("stored newer anchor stands");
        assert_eq!(out.anchor_epoch, 7424);
        assert!(out.warnings.iter().any(|w| w.contains("not newer")), "{:?}", out.warnings);
    }

    /// No arrangement, partial or envelope may use the reserved release id.
    #[test]
    fn the_release_id_can_never_be_signed() {
        let cp = release_cp(1536);
        let set = SignerSet { id: WS_RELEASE_SIGNER_SET_ID, ..a_set(WS_PHASE_A_MIN_EXTERNAL, 0) };
        assert!(matches!(combine(&cp, &set, &[a_partial(&cp, 0), a_partial(&cp, 2)]),
            Err(CombineReject::ReservedSignerSet)));
        let dir = tmpdir("release-id-envelope");
        let (owner_set, secrets) = owner_set_and_secrets(WS_RELEASE_SIGNER_SET_ID);
        let env = owner_envelope(cp, &secrets, &[0, 1]);
        let cfg = write_artifacts(&dir, "reserved", &env, &owner_set);
        let error = boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), 1600, false,
            (0, GEN), |_| None, |_| false, |_| None).expect_err("reserved id refused");
        assert!(error.to_string().contains("reserved"), "{error}");
    }

    /// Agent 181's finding, fixed behind the prototype switch: the same
    /// restart that halts today (own finality 4290 epochs old, checkpoint
    /// block not yet local) resumes under the stored anchor, as a HARD anchor.
    #[test]
    fn restart_during_checkpoint_sync_resumes_under_the_anchor() {
        let dir = tmpdir("resume-midsync");
        save_latest(&dir, &checkpoint(7168)).unwrap();
        let wall = 7290;
        let on = WsConfig { resume_sync_under_anchor: true, ..WsConfig::default() };
        let out = boot(&on, &dir, NET, &GEN, &genesis_anchor(), wall, true,
            (3000, [0x55; 32]), |_| None, |_| false, |_| None).unwrap().expect("resumes under the anchor");
        assert_eq!(out.anchor_epoch, 7168);
        assert!(out.anchor_is_hard, "the anchor stays the only defense");
        assert!(out.warnings.iter().any(|w| w.contains("resuming a checkpoint sync")), "{:?}", out.warnings);

        // Switch off: today's behaviour is unchanged.
        let halted = boot(&no_flags(), &dir, NET, &GEN, &genesis_anchor(), wall, true,
            (3000, [0x55; 32]), |_| None, |_| false, |_| None).unwrap().expect_err("still halts when off");
        assert!(halted.contains("ERR_WS_STALE recovery halted"), "{halted}");

        // Not widened: an anchor that is itself past the window still refuses,
        // and so does a stale node whose only anchor is the genesis anchor.
        let refused = boot(&on, &dir, NET, &GEN, &genesis_anchor(), 7168 + WS_PERIOD_EPOCHS, true,
            (3000, [0x55; 32]), |_| None, |_| false, |_| None).unwrap().expect_err("aged anchor");
        assert!(refused.contains("ERR_WS_STALE"), "{refused}");
        let genesis_only = tmpdir("resume-genesis-only");
        let refused = boot(&on, &genesis_only, NET, &GEN, &genesis_anchor(), wall, true,
            (3000, [0x55; 32]), |_| None, |_| false, |_| None).unwrap().expect_err("genesis anchor is stale");
        assert!(refused.contains("ERR_WS_STALE"), "{refused}");

        // Why `anchor.epoch > fin_epoch` always holds on this branch: it is
        // reached only with age >= WS_PERIOD and anchor_age < WS_PERIOD, so
        // the anchor is strictly newer than own finality. A stored anchor at
        // or below own finality never needs this rule.
    }

    /// The whole non-recurring path: release anchor on a wiped node, a
    /// restart mid-sync, then the node's own finality takes over.
    #[test]
    fn release_anchor_and_resume_together() {
        let dir = tmpdir("release-and-resume");
        let mut cfg = release_config(release_cp(7168));
        cfg.resume_sync_under_anchor = true;
        boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), 7290, false, (0, GEN), |_| None, |_| false, |_| None)
            .unwrap().expect("fresh boot");
        let out = boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), 7300, true, (2500, [0x55; 32]),
            |_| None, |_| false, |_| None).unwrap().expect("restart mid-sync");
        assert!(out.anchor_is_hard);
        let caught_up = boot(&cfg, &dir, NET, &GEN, &genesis_anchor(), 7400, true, (7398, [0x22; 32]),
            |e| (e == 7168).then_some([0x22; 32]), |_| true, |_| None).unwrap().expect("synced");
        assert!(!caught_up.anchor_is_hard);
        assert!(caught_up.warnings.iter().any(|w| w.contains("not newer")), "{:?}", caught_up.warnings);
    }

    // ── agent 242 review ─────────────────────────────────────────────────────

    /// R242: a build without the unsigned operator flags must not point an
    /// operator at them (feature-off output equals fa980367's guidance).
    #[test]
    fn builds_without_operator_flags_never_name_them() {
        let dir = tmpdir("a242-stale-warn-text");
        let out = boot(&no_flags(), &dir, NET, &GEN, &genesis_anchor(), 2000, true,
            (2000 - bloch_pos_committee::ws::WS_FRESH_EPOCHS, [0x55; 32]), |_| None, |_| true, |_| None).unwrap().expect("resume, stale warn");
        let text = out.warnings.join("\n");
        assert!(text.contains("freshness"), "{text}");
        let stale = boot(&no_flags(), &dir, NET, &GEN, &genesis_anchor(), 3000 + WS_PERIOD_EPOCHS, true,
            (3000, [0x55; 32]), |_| None, |_| true, |_| None).unwrap().expect_err("ERR_WS_STALE");
        assert!(stale.contains("ERR_WS_STALE"), "{stale}");
        for message in [&text, &stale] {
            assert_eq!(message.contains("--ws-trusted-checkpoint"), AUTO_CHECKPOINT_ENABLED, "{message}");
        }
        assert_eq!(stale.contains("operator-trusted"), AUTO_CHECKPOINT_ENABLED, "{stale}");
        if !AUTO_CHECKPOINT_ENABLED {
            assert!(!text.contains("operator-trusted"), "{text}");
        }
    }

    /// R242: a release can be rolled back to fa980367. That binary's boot
    /// reads ws_latest without looking at the signer-set id, so a stored
    /// release anchor keeps working there (this default build runs the same
    /// code path) and is never a refusal.
    #[test]
    fn a_stored_release_anchor_boots_a_default_build() {
        let dir = tmpdir("a242-rollback");
        save_latest(&dir, &release_cp(7168)).unwrap();
        let out = boot(&no_flags(), &dir, NET, &GEN, &genesis_anchor(), 7300, false,
            (0, GEN), |_| None, |_| false, |_| None).unwrap().expect("fresh node under the stored release anchor");
        assert_eq!(out.anchor_epoch, 7168);
        assert!(out.anchor_is_hard);
        let out = boot(&no_flags(), &dir, NET, &GEN, &genesis_anchor(), 7300, true,
            (7298, [0x22; 32]), |e| (e == 7168).then_some([0x22; 32]), |_| true, |_| None).unwrap().expect("synced node");
        assert!(!out.anchor_is_hard);
    }

    /// Mainnet genesis block id (genesis/mainnet.manifest; network 1228832244).
    const MAINNET_GENESIS_ROOT_HEX: &str = "9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415";

    /// R242: the anchor a ws-release-anchor build compiles is exactly the
    /// file named by RELEASE_ANCHOR_SOURCE (which the source digest hashes),
    /// and a baked anchor is the mainnet chain's.
    #[test]
    fn the_compiled_anchor_is_the_hashed_file_and_names_mainnet() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = fs::read_to_string(root.join(RELEASE_ANCHOR_SOURCE)).expect("anchor source file");
        let start = text.find("RELEASE_ANCHOR_HEX: &str = \"").expect("hex constant") + "RELEASE_ANCHOR_HEX: &str = \"".len();
        let hex = &text[start..start + text[start..].find('"').expect("closing quote")];
        let on_disk = decode_release_anchor_hex(hex).expect("valid anchor file");
        if RELEASE_ANCHOR_ENABLED {
            assert_eq!(compiled_release_anchor().unwrap(), on_disk);
        }
        if let Some(cp) = on_disk {
            assert_eq!(cp.network_id, 1_228_832_244, "a release bakes the mainnet anchor only");
            assert_eq!(hex32(&cp.genesis_root), MAINNET_GENESIS_ROOT_HEX);
            assert_eq!(cp.signer_set_id, WS_RELEASE_SIGNER_SET_ID);
        }
    }

    /// R242: a ws-release-anchor build without ws-auto-checkpoint refuses the
    /// unsigned operator inputs (owner decision: unit-tested only).
    #[test]
    fn the_release_configuration_refuses_operator_inputs() {
        for flags in [
            vec!["--checkpoint-sync-url", "127.0.0.1:1"],
            vec!["--ws-trusted-checkpoint", "cp.bin"],
            vec!["--ws-trusted-checkpoint", "cp.bin", "--ws-trusted-root", &"22".repeat(32)],
        ] {
            let parsed = WsConfig::from_args(&args(&flags));
            assert_eq!(parsed.is_ok(), AUTO_CHECKPOINT_ENABLED, "{flags:?}");
        }
    }
}
