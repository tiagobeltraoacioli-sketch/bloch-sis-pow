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

// ---------------------------------------------------------------------------
// The hybrid verifier the envelope check runs under
// ---------------------------------------------------------------------------

/// The real ML-DSA-65 ‖ Falcon-1024 verifier for checkpoint envelopes.
///
/// `ws::verify_envelope` receives the halves pre-split at the fixed points
/// (the AND-composition lives in `staking::verify_hybrid`, called — not
/// copied); each half goes to its own primitive in `bloch_crypto`. Distinct
/// from [`crate::keys::HybridVerifier`], which is keyed by validator index
/// against the genesis registry — checkpoint signers are not validators.
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
    u32::from_le_bytes(genesis_digest[..4].try_into().unwrap())
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
    let mut out = Vec::with_capacity(8 + 32 + 1 + 4 + p.signature.len());
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

    // Two refusals that belong HERE and nowhere else.
    //
    // This decoder is the only path by which a `SignerSet` reaches production:
    // `ws::verify_envelope`'s single non-test caller is `boot` below, and the
    // set it judges always comes from this function reading the operator's
    // `--ws-signer-set` file. So a rule enforced here covers 100% of what any
    // node will ever accept, while changing nothing in the frozen committee
    // crate — no consensus edit, no rollout, and artifacts still verify under
    // the binary the fleet already runs. (A future release that hard-codes the
    // §6 arrangements next to its pinned genesis would bypass this decoder;
    // that release must carry both checks with the keys it bakes in.)
    //
    // 1. ONE KEY IN TWO SLOTS. The quorum counts distinct signer *indices*,
    //    never distinct *keys* — `ws::verify_envelope`'s `DuplicateSigner`
    //    compares indices, and nothing anywhere compares two slots' pubkey
    //    bytes. An arrangement seating one key twice is therefore a 1-of-n
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
    if cp.signer_set_id == ws::WS_GENESIS_SIGNER_SET_ID || set.id == ws::WS_GENESIS_SIGNER_SET_ID {
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
        for j in (i + 1)..signers.len() {
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
    let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
    let cp = decode_checkpoint(&bytes)
        .map_err(|e| bad(format!("{}: {e}", path.display())))?;
    if cp.network_id != network_id || &cp.genesis_root != genesis_root {
        return Err(bad(format!(
            "{} belongs to a different network; refusing (delete it yourself if that is \
             really what you want)",
            path.display()
        )));
    }
    Ok(Some(cp))
}

/// Persist `ws_latest` (write-to-temp + rename, like the block-log rewrite).
pub fn save_latest(dir: &Path, cp: &WeakSubjectivityCheckpoint) -> io::Result<()> {
    let tmp = dir.join("ws_latest.bin.tmp");
    fs::write(&tmp, cp.canonical_serialize())?;
    fs::rename(&tmp, dir.join(WS_LATEST_FILE))
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

/// CLI-supplied weak-subjectivity inputs.
pub struct WsConfig {
    pub checkpoint: Option<PathBuf>,
    pub signer_set: Option<PathBuf>,
}

/// What the engine carries out of a successful boot: the anchor it must
/// enforce once its own finality reaches `anchor_epoch`.
#[derive(Debug)]
pub struct WsOutcome {
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
) -> io::Result<Result<WsOutcome, String>> {
    let mut warnings = Vec::new();

    // 1. ws_latest, with the genesis anchor as the first checkpoint when no
    //    other has ever been verified (§4.1 precedence, source 3).
    let mut anchor = match load_latest(data_dir, network_id, genesis_root)? {
        Some(cp) => cp,
        None => {
            save_latest(data_dir, genesis_anchor)?;
            *genesis_anchor
        }
    };

    // 2. Operator-supplied envelope (§4.1 precedence, source 1).
    let mut published: Option<WeakSubjectivityCheckpoint> = None;
    if let Some(path) = &cfg.checkpoint {
        let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
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
        let set = decode_signer_set_file(&set_bytes)
            .map_err(|e| bad(format!("{}: {e}", set_path.display())))?;

        // The arrangement is an unauthenticated download, exactly like the
        // envelope — and it is the file that carries the quorum RULE. A node
        // handed a doctored one (`min_external` set to 0, say) will happily
        // accept a founder-only quorum and report nothing unusual, because
        // `verify_envelope` enforces the numbers this file states, not §6's.
        // `matches_policy` is what compares them against §6, and until now it
        // was called only from tests. Two lines follow: the arrangement's
        // fingerprint, so it can be compared across channels the way the ws
        // digest is, and — when the shape is not one §6 describes — a warning
        // that says exactly what was weakened.
        warnings.push(format!(
            "ws signer arrangement {} fingerprint (SHA3-256 of {}): {}",
            set.id,
            set_path.display(),
            hex32(&signer_set_fingerprint(&set_bytes)),
        ));
        let phase_a = set.matches_policy(
            ws::WS_PHASE_A_THRESHOLD,
            ws::WS_PHASE_A_SIGNERS,
            ws::WS_PHASE_A_MIN_EXTERNAL,
        );
        let phase_b = set.matches_policy(
            ws::WS_PHASE_B_THRESHOLD,
            ws::WS_PHASE_B_SIGNERS,
            ws::WS_PHASE_B_MIN_EXTERNAL,
        );
        if !phase_a && !phase_b {
            warnings.push(format!(
                "!!!! ARRANGEMENT DOES NOT MATCH ANY §6 POLICY: {} is {}-of-{} with \
                 min_external {}. Phase A is 2-of-3 with at least 1 external; Phase B is \
                 3-of-5 with at least 2. This node will enforce the numbers THIS FILE \
                 states, not the ones §6 states — the quorum rule travels in the \
                 arrangement, and the arrangement arrived over an unauthenticated \
                 channel.{} Compare the fingerprint above against an independent \
                 publication channel before trusting the anchor.",
                set_path.display(),
                set.threshold,
                set.signers.len(),
                set.min_external,
                if set.min_external == 0 {
                    " min_external is ZERO, so a quorum of founder-adjacent keys alone \
                     satisfies it and there is no outside witness at all."
                } else {
                    ""
                },
            ));
        }
        let ok = ws::verify_envelope(&env, &set, network_id, genesis_root, &WsHybridVerifier)
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
        // `verify_envelope`, so the rule covers every node without editing the
        // frozen committee crate. See `arrangement_window`.
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
            match ws::accept(Some(&anchor), &cp) {
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
    let gate: Result<(), String> = match ws::boot_decision(has_local_finality, age) {
        BootDecision::Resume => Ok(()),
        BootDecision::ResumeStaleWarn => {
            warnings.push(format!(
                "WARNING: this node's finalized knowledge is {age} epochs old — inside \
                 the weak-subjectivity window ({} epochs) but past the freshness \
                 threshold ({}). Resuming from own finality, but fetch a fresh \
                 checkpoint (--ws-checkpoint) before following any peer that offers a \
                 competing finalized branch.",
                ws::WS_PERIOD_EPOCHS,
                ws::WS_FRESH_EPOCHS,
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
                match ws::reconcile(&anchor, fin_root, descends) {
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
                }
            } else {
                Err(format!(
                    "ERR_WS_STALE: this node's own finalized knowledge is {age} epochs \
                     old — at or beyond the weak-subjectivity window of {} epochs \
                     (≈ {} days at the mainnet slot cadence). Every validator that \
                     signed this database's finality markers may already have \
                     withdrawn, and could sign a conflicting continuation for free; \
                     the local markers are no longer a defense, so no peer can be \
                     safely followed. This refusal is the mechanism working, not a \
                     fault. Recover by obtaining a recent signed checkpoint OUT OF \
                     BAND (see below) and restarting with --ws-checkpoint <file>.\n\n{}",
                    ws::WS_PERIOD_EPOCHS,
                    window_days(),
                    where_checkpoints_come_from(),
                ))
            }
        }
    };

    Ok(match gate {
        Ok(()) => Ok(WsOutcome {
            anchor_epoch: anchor.epoch,
            anchor_root: anchor.block_root,
            anchor_is_hard: !has_local_finality,
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
    "To obtain a checkpoint (BLOCH-WEAK-SUBJECTIVITY.md §2.3, §4.1):\n  \
     1. Fetch the latest signed checkpoint envelope from a channel you trust: the \
     Foundation site, the GitHub/GitLab release pages, the explorer front page, or \
     the announcement channel.\n  \
     2. Compare its 64-hex ws digest across AT LEAST TWO independent channels — \
     agreement across independent operators is the evidence, not the artifact's \
     say-so.\n  \
     3. Restart with:  --ws-checkpoint <file>   (on devnet builds also \
     --ws-signer-set <file>, since no signer arrangement is baked in)."
        .to_string()
}

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
        WsConfig { checkpoint: None, signer_set: None }
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
        // ONE holder, ONE signature, listed at two indices: the frozen
        // verifier ACCEPTS. This is the finding, not a hypothetical.
        let one = strip(&bloch_crypto::crypto::sign(&sk, &digest).expect("sign"));
        let forged = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, one.clone()), (2, one)],
        };
        ws::verify_envelope(&forged, &bad, NET, &GEN, &WsHybridVerifier).expect(
            "the quorum counts distinct INDICES, not distinct KEYS — if this now fails, \
             ws::verify_envelope was hardened and this test should be inverted",
        );
        // `matches_policy` does see it — but nothing on the acceptance path
        // calls `matches_policy`, which is exactly why the decoder must.
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
            |_| false,
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
            |_| false,
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
            10, true, (10, [0x55; 32]), |_| None, |_| false,
        )
        .unwrap()
        .expect("fresh own finality resumes");
        assert!(!out.anchor_is_hard);

        // Stale but inside the window: resumes with a prominent warning.
        let out = boot(
            &no_flags(), &dir, NET, &GEN, &genesis_anchor(),
            ws::WS_FRESH_EPOCHS + 5, true, (5, [0x55; 32]), |_| None, |_| false,
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
            WS_PERIOD_EPOCHS + 7, true, (7, [0x55; 32]), |_| None, |_| false,
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
    #[test]
    fn ws_conflict_refuses_boot() {
        let dir = tmpdir("conflict");
        // The stored latest is the genesis anchor (epoch 0); craft an
        // equivocal "epoch 0" checkpoint signed by a real 1-of-1 arrangement.
        save_latest(&dir, &genesis_anchor()).unwrap();

        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let raw = strip(&pk);
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(&raw);
        let set = SignerSet {
            id: 9,
            signers: vec![Signer { pubkey, external: true }],
            threshold: 1,
            min_external: 1,
            adopted_epoch: 0,
        };
        let mut cp = checkpoint(0);
        cp.signer_set_id = 9;
        let env = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, strip(&bloch_crypto::crypto::sign(&sk, &cp.ws_digest()).unwrap()))],
        };
        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(&set)).unwrap();

        let cfg = WsConfig { checkpoint: Some(env_path), signer_set: Some(set_path) };
        let refusal = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            1, false, (0, GEN), |_| None, |_| false,
        )
        .unwrap()
        .expect_err("an equivocal same-epoch checkpoint must refuse the boot");
        assert!(refusal.contains("WS_CONFLICT"));
        assert!(refusal.contains("equivocal"));
        // The stored artifact was not overwritten.
        assert_eq!(load_latest(&dir, NET, &GEN).unwrap().unwrap(), genesis_anchor());
    }

    /// A published checkpoint that contradicts OWN finality raises the alarm,
    /// is not admitted as the anchor, and never blocks the node from
    /// resuming on its own finality — the §5 structural limit.
    #[test]
    fn published_checkpoint_never_overrides_own_finality() {
        let dir = tmpdir("cross-check");
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let raw = strip(&pk);
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(&raw);
        let set = SignerSet {
            id: 3,
            signers: vec![Signer { pubkey, external: true }],
            threshold: 1,
            min_external: 1,
            adopted_epoch: 0,
        };
        let mut cp = checkpoint(64);
        cp.signer_set_id = 3;
        let env = CheckpointEnvelope {
            checkpoint: cp,
            signatures: vec![(0, strip(&bloch_crypto::crypto::sign(&sk, &cp.ws_digest()).unwrap()))],
        };
        let env_path = dir.join("env.bin");
        let set_path = dir.join("set.bin");
        fs::write(&env_path, encode_envelope_file(&env)).unwrap();
        fs::write(&set_path, encode_signer_set_file(&set)).unwrap();
        let cfg = WsConfig { checkpoint: Some(env_path), signer_set: Some(set_path) };

        // The node's own finalized root at epoch 64 differs from cp's.
        let own_root = [0x99; 32];
        let out = boot(
            &cfg, &dir, NET, &GEN, &genesis_anchor(),
            70, true, (70, own_root),
            move |e| if e <= 70 { Some(own_root) } else { None },
            |_| false,
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
}
