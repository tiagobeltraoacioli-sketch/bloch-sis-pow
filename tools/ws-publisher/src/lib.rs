// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recurring publication pipeline for weak-subjectivity checkpoints.
//!
//! `ws.rs` (crates/bloch-pos-committee) defines the artifact, the digest,
//! the quorum rule and the cadence; `ws_boot.rs` (crates/bloch-pos-node)
//! defines the file framing the node reads. This crate is the *other* side
//! of both: the machinery that produces those files on the cadence the
//! constants promise. Four stations, three trust levels:
//!
//! 1. **stage** — runs UNATTENDED on a timer next to a trusted node. Touches
//!    no keys. Computes the due publication epoch from the node's finalized
//!    epoch, invokes the payload producer, validates the payload against the
//!    committee crate's canonical layout, and writes a signing request.
//! 2. **sign** — runs ATTENDED, once per keyholder, on the keyholder's own
//!    machine. The only station that reads a secret key. The pipeline never
//!    schedules it; a human does.
//! 3. **seal** — assembles the m-of-n envelope from the staged payload and
//!    the collected signatures, and refuses to write anything the node's own
//!    `ws::verify_envelope` would not accept.
//! 4. **verify** — the third-party station: given nothing but a checkpoint
//!    file, a signer-set file and the chain identity pins, reproduce the
//!    exact accept/reject judgement a node makes at boot. This subcommand IS
//!    the verification instruction for exchanges, in executable form.
//!
//! ## What is deliberately not here
//!
//! - No canonical byte layout: [`decode_checkpoint`] proves itself against
//!   `WeakSubjectivityCheckpoint::canonical_serialize` on every call, the
//!   same discipline as `ws_boot::decode_checkpoint`.
//! - No quorum arithmetic: sealing and verifying call `ws::verify_envelope`.
//! - No unattended signing. `stage` produces a request; producing a
//!   signature requires a human with a key, by design.

use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

use bloch_pos_committee::staking::{HybridKeyVerifier, HYBRID_PK_BYTES};
use bloch_pos_committee::ws::{
    self, CheckpointEnvelope, EnvelopeReject, Signer, SignerSet, WeakSubjectivityCheckpoint,
    WS_CHECKPOINT_BYTES, WS_FORMAT_VERSION, WS_FRESH_EPOCHS, WS_GENESIS_SIGNER_SET_ID,
    WS_PERIOD_EPOCHS, WS_PUBLICATION_INTERVAL_EPOCHS,
};

// ---------------------------------------------------------------------------
// The real verifier
// ---------------------------------------------------------------------------

/// The real ML-DSA-65 ‖ Falcon-1024 verifier — the same two calls the node's
/// `ws_boot::WsHybridVerifier` makes (crates/bloch-pos-node/src/ws_boot.rs).
/// Kept call-for-call identical so an envelope this tool seals is accepted or
/// refused by the node for the same reason it was here.
pub struct RealHybridVerifier;

impl HybridKeyVerifier for RealHybridVerifier {
    fn verify_mldsa65(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        bloch_crypto::crypto::verify_mldsa65_raw(pubkey, signing_root, sig)
    }
    fn verify_falcon1024(&self, pubkey: &[u8], signing_root: &[u8; 32], sig: &[u8]) -> bool {
        bloch_crypto::crypto::falcon::verify(pubkey, signing_root, sig)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PipeErr {
    Io(io::Error),
    Decode(&'static str),
    /// A validation the pipeline refuses to proceed past. The string is the
    /// full operator-facing explanation — a refused stage/seal must be
    /// attributable from its message alone, the `EnvelopeReject` rule.
    Refuse(String),
}

impl fmt::Display for PipeErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipeErr::Io(e) => write!(f, "io: {e}"),
            PipeErr::Decode(m) => write!(f, "decode: {m}"),
            PipeErr::Refuse(m) => write!(f, "refused: {m}"),
        }
    }
}

impl From<io::Error> for PipeErr {
    fn from(e: io::Error) -> Self {
        PipeErr::Io(e)
    }
}

fn refuse(msg: impl Into<String>) -> PipeErr {
    PipeErr::Refuse(msg.into())
}

// ---------------------------------------------------------------------------
// File framing — same magics and layout as ws_boot.rs, proven by round-trip
// ---------------------------------------------------------------------------
//
// The node's encoder/decoder live in a binary crate and cannot be imported.
// The framing is restated here — magic ‖ canonical checkpoint ‖ u32 count ‖
// (u8 index ‖ u32 len ‖ sig)* — and pinned two ways: the checkpoint decode
// proves itself against `canonical_serialize` on every call, and the tests
// below round-trip byte-identical vectors. If ws_boot.rs ever changes its
// framing these magics stop matching and the node refuses the file loudly
// ("not a checkpoint envelope file"), which is the failure mode we want:
// noisy at boot, never a silently different artifact.

const WS_ENVELOPE_MAGIC: &[u8; 8] = b"BPOSWSE1";
const WS_SIGNER_SET_MAGIC: &[u8; 8] = b"BPOSWSS1";
/// `signer_index` is a u8 in the envelope, so no artifact can carry more.
const MAX_SIGNERS: usize = 256;
/// Cap on one signature field, mirroring the node codec's field cap: a
/// hybrid signature is ~4.6 KB, so 64 KB is generous and still refuses a
/// corrupt length prefix before it allocates anything interesting.
const MAX_SIG_LEN: usize = 64 * 1024;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], PipeErr> {
        if self.bytes.len() - self.at < n {
            return Err(PipeErr::Decode("truncated"));
        }
        let out = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16, PipeErr> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, PipeErr> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, PipeErr> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn h32(&mut self) -> Result<[u8; 32], PipeErr> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn finish(self) -> Result<(), PipeErr> {
        if self.at != self.bytes.len() {
            return Err(PipeErr::Decode("trailing bytes"));
        }
        Ok(())
    }
}

/// Decode the canonical 154 checkpoint bytes. The committee crate's
/// `canonical_serialize` is the single authority on the layout; this decoder
/// proves itself against it on every call by re-serializing and comparing,
/// so a drift between the two cannot silently mint a second byte layout.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<WeakSubjectivityCheckpoint, PipeErr> {
    if bytes.len() != WS_CHECKPOINT_BYTES {
        return Err(PipeErr::Decode("checkpoint: wrong length"));
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
        return Err(PipeErr::Decode("checkpoint: decoder disagrees with canonical_serialize"));
    }
    Ok(cp)
}

/// Encode the distribution envelope — the `wscheckpoint-<epoch>.bin` the
/// node's `--ws-checkpoint` flag reads.
pub fn encode_envelope_file(env: &CheckpointEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WS_ENVELOPE_MAGIC);
    out.extend_from_slice(&env.checkpoint.canonical_serialize());
    out.extend_from_slice(&(env.signatures.len() as u32).to_le_bytes());
    for (index, sig) in &env.signatures {
        out.push(*index);
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
    }
    out
}

pub fn decode_envelope_file(bytes: &[u8]) -> Result<CheckpointEnvelope, PipeErr> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != WS_ENVELOPE_MAGIC {
        return Err(PipeErr::Decode("not a checkpoint envelope file"));
    }
    let checkpoint = decode_checkpoint(r.take(WS_CHECKPOINT_BYTES)?)?;
    let n = r.u32()? as usize;
    if n > MAX_SIGNERS {
        return Err(PipeErr::Decode("envelope: signature count over cap"));
    }
    let mut signatures = Vec::with_capacity(n);
    for _ in 0..n {
        let index = r.take(1)?[0];
        let len = r.u32()? as usize;
        if len > MAX_SIG_LEN {
            return Err(PipeErr::Decode("envelope: signature length over cap"));
        }
        signatures.push((index, r.take(len)?.to_vec()));
    }
    r.finish()?;
    Ok(CheckpointEnvelope { checkpoint, signatures })
}

/// Encode a signer arrangement file (`BPOSWSS1`). The publication side
/// writes this once per arrangement; the node reads it via
/// `--ws-signer-set` on devnet builds (a release hard-codes the keys).
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

pub fn decode_signer_set_file(bytes: &[u8]) -> Result<SignerSet, PipeErr> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != WS_SIGNER_SET_MAGIC {
        return Err(PipeErr::Decode("not a signer-set file"));
    }
    let id = r.u32()?;
    let threshold = r.u32()? as usize;
    let min_external = r.u32()? as usize;
    let adopted_epoch = r.u64()?;
    let n = r.u32()? as usize;
    if n > MAX_SIGNERS {
        return Err(PipeErr::Decode("signer set: count over cap"));
    }
    let mut signers = Vec::with_capacity(n);
    for _ in 0..n {
        let external = match r.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(PipeErr::Decode("signer set: external flag not 0/1")),
        };
        let mut pubkey = [0u8; HYBRID_PK_BYTES];
        pubkey.copy_from_slice(r.take(HYBRID_PK_BYTES)?);
        signers.push(Signer { pubkey, external });
    }
    r.finish()?;
    if threshold == 0 || threshold > signers.len() || min_external > threshold {
        return Err(PipeErr::Decode("signer set: incoherent quorum shape"));
    }
    Ok(SignerSet { id, signers, threshold, min_external, adopted_epoch })
}

// ---------------------------------------------------------------------------
// Cadence arithmetic
// ---------------------------------------------------------------------------

/// The publication epoch currently owed: the latest finalized epoch that is
/// a multiple of [`WS_PUBLICATION_INTERVAL_EPOCHS`], or `None` before the
/// first interval completes. Epoch 0 is never owed — its anchor is the
/// genesis block itself (`WS_GENESIS_SIGNER_SET_ID`), not an envelope.
///
/// When the pipeline has been down across several intervals this yields only
/// the LATEST due epoch — the spec's rule ("a checkpoint for the latest
/// finalized epoch that is a multiple of 256"): back-filling missed epochs
/// would spend signing ceremonies on artifacts nobody should boot from.
pub fn due_epoch(finalized_epoch: u64) -> Option<u64> {
    let due = finalized_epoch - finalized_epoch % WS_PUBLICATION_INTERVAL_EPOCHS;
    (due > 0).then_some(due)
}

/// Freshness of a checkpoint of epoch `cp_epoch` at wall-clock epoch `now`,
/// judged by the same two thresholds the node's boot decision uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Within [`WS_FRESH_EPOCHS`].
    Fresh { age: u64 },
    /// Past the soft threshold, inside the hard one: usable, warn.
    Stale { age: u64 },
    /// At or past [`WS_PERIOD_EPOCHS`]: a node must not boot from this.
    Expired { age: u64 },
}

pub fn freshness(cp_epoch: u64, wall_epoch: u64) -> Freshness {
    let age = wall_epoch.saturating_sub(cp_epoch);
    if age < WS_FRESH_EPOCHS {
        Freshness::Fresh { age }
    } else if age < WS_PERIOD_EPOCHS {
        Freshness::Stale { age }
    } else {
        Freshness::Expired { age }
    }
}

// ---------------------------------------------------------------------------
// The publication directory
// ---------------------------------------------------------------------------

/// Filesystem layout the stations share. Everything under `publish/` is
/// PUBLIC by design; everything else is working state. No station ever
/// writes a secret under this root — signing happens on keyholder machines,
/// and only detached signatures come back.
///
/// ```text
/// <root>/
///   staging/<epoch>/
///     wscheckpoint-<epoch>.payload.bin   the unsigned canonical 154 bytes
///     wscheckpoint-<epoch>.payload.json  human-readable view + ws_digest
///     SIGNING-REQUEST.txt                what each keyholder receives
///   signatures/<epoch>/
///     sig-<index>.bin                    detached hybrid signatures, one per
///                                        keyholder, dropped in by humans
///   publish/<epoch>/
///     wscheckpoint-<epoch>.bin           the sealed envelope   (PUBLIC)
///     wscheckpoint-<epoch>.json          the announcement view (PUBLIC)
///     ws-signer-set-<id>.bin             the arrangement       (PUBLIC)
///   publish/latest.json                  well-known index      (PUBLIC)
///   LATEST                               newest sealed epoch (anti-rollback)
/// ```
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Layout { root: root.into() }
    }
    pub fn staging_dir(&self, epoch: u64) -> PathBuf {
        self.root.join("staging").join(epoch.to_string())
    }
    pub fn payload_bin(&self, epoch: u64) -> PathBuf {
        self.staging_dir(epoch).join(format!("wscheckpoint-{epoch}.payload.bin"))
    }
    pub fn payload_json(&self, epoch: u64) -> PathBuf {
        self.staging_dir(epoch).join(format!("wscheckpoint-{epoch}.payload.json"))
    }
    pub fn signing_request(&self, epoch: u64) -> PathBuf {
        self.staging_dir(epoch).join("SIGNING-REQUEST.txt")
    }
    pub fn signatures_dir(&self, epoch: u64) -> PathBuf {
        self.root.join("signatures").join(epoch.to_string())
    }
    pub fn publish_dir(&self, epoch: u64) -> PathBuf {
        self.root.join("publish").join(epoch.to_string())
    }
    pub fn envelope_bin(&self, epoch: u64) -> PathBuf {
        self.publish_dir(epoch).join(format!("wscheckpoint-{epoch}.bin"))
    }
    pub fn envelope_json(&self, epoch: u64) -> PathBuf {
        self.publish_dir(epoch).join(format!("wscheckpoint-{epoch}.json"))
    }
    pub fn latest_index(&self) -> PathBuf {
        self.root.join("publish").join("latest.json")
    }
    pub fn latest_marker(&self) -> PathBuf {
        self.root.join("LATEST")
    }

    /// Newest sealed epoch, or `None` before the first seal. The marker is
    /// the pipeline's anti-rollback floor, the publication-side analogue of
    /// the node's `ws_latest` rule (§4.1): no station ever stages or seals
    /// an epoch at or below it.
    pub fn latest_sealed(&self) -> Result<Option<u64>, PipeErr> {
        match fs::read_to_string(self.latest_marker()) {
            Ok(s) => s
                .trim()
                .parse::<u64>()
                .map(Some)
                .map_err(|_| refuse(format!("LATEST marker is not an epoch number: {s:?}"))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Chain identity pins
// ---------------------------------------------------------------------------

/// The chain a checkpoint must belong to. Supplied by the operator (stage,
/// seal) or the third party (verify) — never taken from the artifact under
/// judgement, which is the entire point of a pin.
#[derive(Clone, Copy)]
pub struct ChainPins {
    pub network_id: u32,
    pub genesis_root: [u8; 32],
}

// ---------------------------------------------------------------------------
// Station 1: stage
// ---------------------------------------------------------------------------

pub struct StageRequest<'a> {
    pub layout: &'a Layout,
    /// The node's current finalized epoch (from `getchaininfo`).
    pub finalized_epoch: u64,
    /// The node's current finalized root, if the caller has it. Only usable
    /// as a cross-check when the due epoch IS the finalized epoch.
    pub finalized_root: Option<[u8; 32]>,
    pub pins: ChainPins,
    /// Off-cadence override for the spec's event-driven publications (§3:
    /// mass slashing, >5% stake exit, announced ceremony downtime). `None`
    /// means the ordinary cadence.
    pub epoch_override: Option<u64>,
}

pub enum StageOutcome {
    /// Nothing owed yet (first interval not complete).
    NothingDue,
    /// The due epoch is already sealed and published.
    AlreadyPublished { epoch: u64 },
    /// The due epoch is already staged with an identical payload; the
    /// signing ceremony is the outstanding step.
    AlreadyStaged { epoch: u64, digest: [u8; 32] },
    /// Newly staged: the signing request now exists.
    Staged { epoch: u64, digest: [u8; 32] },
}

/// Validate a producer's payload and stage it for signing. `payload` is the
/// unsigned canonical checkpoint from the payload producer (the checkpoint
/// tool); this station re-derives nothing about the chain — it checks that
/// what the producer handed over is exactly the artifact the cadence owes,
/// and refuses everything else.
pub fn stage(req: &StageRequest, payload: &[u8]) -> Result<StageOutcome, PipeErr> {
    let target = match req.epoch_override {
        Some(e) => e,
        None => match due_epoch(req.finalized_epoch) {
            Some(e) => e,
            None => return Ok(StageOutcome::NothingDue),
        },
    };
    if target > req.finalized_epoch {
        return Err(refuse(format!(
            "epoch {target} is not finalized yet (finalized epoch is {}): a checkpoint \
             may only attest a FINALIZED epoch boundary",
            req.finalized_epoch
        )));
    }
    if req.epoch_override.is_none() && !ws::is_publication_epoch(target) {
        // Unreachable by construction of due_epoch; kept as a belt against
        // future edits to the arithmetic above.
        return Err(refuse(format!("epoch {target} is not a publication epoch")));
    }

    // Anti-rollback: never stage at or below what is already sealed.
    if let Some(latest) = req.layout.latest_sealed()? {
        if target <= latest {
            return Ok(StageOutcome::AlreadyPublished { epoch: latest });
        }
    }
    if req.layout.envelope_bin(target).exists() {
        return Ok(StageOutcome::AlreadyPublished { epoch: target });
    }

    // The payload, judged against the committee crate's layout and the pins.
    let cp = decode_checkpoint(payload)?;
    if cp.version != WS_FORMAT_VERSION {
        return Err(refuse(format!(
            "payload version {} but this pipeline speaks {WS_FORMAT_VERSION}",
            cp.version
        )));
    }
    if cp.epoch != target {
        return Err(refuse(format!(
            "payload attests epoch {} but the due epoch is {target}: the producer and \
             the stager disagree about what is owed",
            cp.epoch
        )));
    }
    if cp.network_id != req.pins.network_id {
        return Err(refuse(format!(
            "payload network_id {:#010x} but the pinned network is {:#010x}",
            cp.network_id, req.pins.network_id
        )));
    }
    if cp.genesis_root != req.pins.genesis_root {
        return Err(refuse(
            "payload genesis_root does not match the pinned genesis — wrong chain".to_string(),
        ));
    }
    if cp.signer_set_id == WS_GENESIS_SIGNER_SET_ID {
        return Err(refuse(
            "payload claims the reserved genesis signer-set id 0; no envelope may".to_string(),
        ));
    }
    if let Some(root) = req.finalized_root {
        if cp.epoch == req.finalized_epoch && cp.block_root != root {
            return Err(refuse(format!(
                "payload block_root {} disagrees with the node's finalized root {} at the \
                 same epoch — the producer is reading a different chain",
                hex::encode(cp.block_root),
                hex::encode(root)
            )));
        }
    }

    let digest = cp.ws_digest();

    // Idempotence with teeth: re-staging the same epoch must be a no-op if
    // and only if the bytes are identical. A DIFFERENT payload for an
    // already-staged epoch is the one situation this station must never
    // paper over — signatures may already exist over the staged digest.
    let bin = req.layout.payload_bin(target);
    if bin.exists() {
        let existing = fs::read(&bin)?;
        if existing == payload {
            return Ok(StageOutcome::AlreadyStaged { epoch: target, digest });
        }
        return Err(refuse(format!(
            "epoch {target} is already staged with DIFFERENT payload bytes \
             (staged digest {}, offered digest {}). Refusing to replace: keyholders may \
             have signed the staged digest. If the staged payload is wrong, delete \
             {} by hand and re-run — that deletion is the human acknowledgement.",
            hex::encode(decode_checkpoint(&existing)?.ws_digest()),
            hex::encode(digest),
            req.layout.staging_dir(target).display()
        )));
    }

    fs::create_dir_all(req.layout.staging_dir(target))?;
    fs::create_dir_all(req.layout.signatures_dir(target))?;
    fs::write(&bin, payload)?;
    fs::write(req.layout.payload_json(target), payload_json(&cp, &digest))?;
    fs::write(req.layout.signing_request(target), signing_request_text(&cp, &digest))?;
    Ok(StageOutcome::Staged { epoch: target, digest })
}

// ---------------------------------------------------------------------------
// Station 2: sign (attended; the only station that reads a secret key)
// ---------------------------------------------------------------------------

/// Sign a staged payload's `ws_digest` with one keyholder's hybrid secret
/// key and return the detached signature body (suite envelope stripped —
/// the raw ML-DSA-65 ‖ Falcon-1024 bytes `CheckpointEnvelope` carries).
///
/// When the signer's public key is supplied, the signature is verified
/// against it before being returned — a keyholder discovering they signed
/// with the wrong key at seal time would burn a ceremony round-trip.
pub fn sign_payload(
    payload: &[u8],
    secret_key: &[u8],
    expect_pubkey: Option<&[u8; HYBRID_PK_BYTES]>,
) -> Result<Vec<u8>, PipeErr> {
    let cp = decode_checkpoint(payload)?;
    let digest = cp.ws_digest();
    let enveloped = bloch_crypto::crypto::sign(secret_key, &digest)
        .map_err(|e| refuse(format!("signing failed: {e:?}")))?;
    let (suite, body) = bloch_crypto::crypto::split_envelope(&enveloped)
        .ok_or(PipeErr::Decode("signature missing suite envelope"))?;
    if suite != bloch_crypto::crypto::SUITE_MLDSA65_FALCON1024 {
        return Err(refuse(format!(
            "secret key produced suite {suite:#06x}, not the hybrid ML-DSA-65 ‖ Falcon-1024 \
             suite — checkpoint signers use the same suite as everything else"
        )));
    }
    let body = body.to_vec();
    if let Some(pk) = expect_pubkey {
        if !verify_one_signature(&cp, pk, &body) {
            return Err(refuse(
                "the produced signature does not verify under the signer's published \
                 public key — wrong secret key for this signer index"
                    .to_string(),
            ));
        }
    }
    Ok(body)
}

/// Verify one detached signature over a checkpoint's digest under one
/// public key, going through `ws::verify_envelope` with a synthetic
/// 1-of-1 arrangement so the AND-composition of the hybrid is the committee
/// crate's, never restated here.
fn verify_one_signature(
    cp: &WeakSubjectivityCheckpoint,
    pubkey: &[u8; HYBRID_PK_BYTES],
    sig: &[u8],
) -> bool {
    let set = SignerSet {
        id: cp.signer_set_id,
        signers: vec![Signer { pubkey: *pubkey, external: false }],
        threshold: 1,
        min_external: 0,
        adopted_epoch: cp.epoch, // review clock irrelevant for a probe set
    };
    let env = CheckpointEnvelope { checkpoint: *cp, signatures: vec![(0, sig.to_vec())] };
    ws::verify_envelope(&env, &set, cp.network_id, &cp.genesis_root, &RealHybridVerifier).is_ok()
}

// ---------------------------------------------------------------------------
// Station 3: seal
// ---------------------------------------------------------------------------

pub struct SealOutcome {
    pub epoch: u64,
    pub digest: [u8; 32],
    pub envelope_path: PathBuf,
    pub signature_count: usize,
    /// `ws::verify_envelope` said the arrangement is past its 12-month
    /// review deadline (inside grace). Sealing proceeds; the operator must
    /// surface the overdue review.
    pub arrangement_past_review: bool,
}

/// Assemble the envelope for a staged epoch from collected signatures and
/// verify it exactly as a booting node would; only a verifying envelope is
/// written. The signatures are `(signer_index, detached signature)` pairs —
/// collected from `signatures/<epoch>/sig-<index>.bin` by the CLI, or passed
/// explicitly.
pub fn seal(
    layout: &Layout,
    epoch: u64,
    set: &SignerSet,
    set_file_bytes: &[u8],
    signatures: Vec<(u8, Vec<u8>)>,
    pins: &ChainPins,
) -> Result<SealOutcome, PipeErr> {
    let payload = fs::read(layout.payload_bin(epoch)).map_err(|e| {
        refuse(format!(
            "no staged payload for epoch {epoch} ({e}); run `stage` first — seal never \
             constructs a payload"
        ))
    })?;
    let cp = decode_checkpoint(&payload)?;

    if let Some(latest) = layout.latest_sealed()? {
        if epoch <= latest {
            return Err(refuse(format!(
                "epoch {epoch} is at or below the newest sealed epoch {latest}: the \
                 anti-rollback rule (§4.1) applies to the publisher too"
            )));
        }
    }

    let env = CheckpointEnvelope { checkpoint: cp, signatures };
    let ok = ws::verify_envelope(&env, set, pins.network_id, &pins.genesis_root, &RealHybridVerifier)
        .map_err(|e| refuse(format!("the assembled envelope does not verify: {}", reject_text(&e))))?;

    let digest = cp.ws_digest();
    let bytes = encode_envelope_file(&env);
    // Round-trip before anything is written: what lands on disk must decode
    // to the exact envelope that just verified.
    let back = decode_envelope_file(&bytes)?;
    if back.checkpoint != cp || back.signatures != env.signatures {
        return Err(PipeErr::Decode("envelope file round-trip disagreement"));
    }

    let dir = layout.publish_dir(epoch);
    fs::create_dir_all(&dir)?;
    let envelope_path = layout.envelope_bin(epoch);
    fs::write(&envelope_path, &bytes)?;
    fs::write(layout.envelope_json(epoch), envelope_json(&env, &digest))?;
    fs::write(dir.join(format!("ws-signer-set-{}.bin", set.id)), set_file_bytes)?;
    fs::write(layout.latest_index(), latest_index_json(&cp, &digest, set.id))?;
    fs::write(layout.latest_marker(), format!("{epoch}\n"))?;

    Ok(SealOutcome {
        epoch,
        digest,
        envelope_path,
        signature_count: env.signatures.len(),
        arrangement_past_review: ok.arrangement_past_review,
    })
}

// ---------------------------------------------------------------------------
// Station 4: verify (the third-party station)
// ---------------------------------------------------------------------------

pub struct VerifyReport {
    pub checkpoint: WeakSubjectivityCheckpoint,
    pub digest: [u8; 32],
    pub signature_count: usize,
    pub external_count: usize,
    pub threshold: usize,
    pub min_external: usize,
    pub arrangement_past_review: bool,
    pub freshness: Option<Freshness>,
}

/// The exchange-side judgement: given an envelope file, a signer-set file,
/// and the chain pins obtained out of band, reproduce the node's boot-time
/// accept/reject. `wall_epoch` (when known) adds the freshness verdict.
pub fn verify_files(
    envelope_bytes: &[u8],
    signer_set_bytes: &[u8],
    pins: &ChainPins,
    wall_epoch: Option<u64>,
) -> Result<VerifyReport, PipeErr> {
    let env = decode_envelope_file(envelope_bytes)?;
    let set = decode_signer_set_file(signer_set_bytes)?;
    let ok = ws::verify_envelope(&env, &set, pins.network_id, &pins.genesis_root, &RealHybridVerifier)
        .map_err(|e| refuse(reject_text(&e)))?;
    let external_count = env
        .signatures
        .iter()
        .filter(|(i, _)| set.signers[*i as usize].external)
        .count();
    Ok(VerifyReport {
        checkpoint: env.checkpoint,
        digest: env.checkpoint.ws_digest(),
        signature_count: env.signatures.len(),
        external_count,
        threshold: set.threshold,
        min_external: set.min_external,
        arrangement_past_review: ok.arrangement_past_review,
        freshness: wall_epoch.map(|w| freshness(env.checkpoint.epoch, w)),
    })
}

fn reject_text(e: &EnvelopeReject) -> String {
    use EnvelopeReject::*;
    match e {
        WrongVersion { got } => format!("format version {got} is not one this tool speaks"),
        WrongNetwork { got, expected } => format!(
            "network_id {got:#010x} but expected {expected:#010x} — an artifact from a \
             different network (testnet replay?)"
        ),
        WrongGenesisRoot => "genesis_root mismatch — an artifact from a different chain".into(),
        WrongSignerSet { got, expected } => {
            format!("envelope names signer set {got} but the supplied arrangement is {expected}")
        }
        ReservedSignerSet => "signer set id 0 is reserved for the genesis anchor".into(),
        ArrangementExpired { hard_stop_epoch } => format!(
            "the signer arrangement is past review + grace (hard stop epoch \
             {hard_stop_epoch}) — refused until governance renews it (dead-man's switch)"
        ),
        UnknownSignerIndex { index } => format!("signature from unknown signer index {index}"),
        DuplicateSigner { index } => format!("signer index {index} listed twice"),
        QuorumNotReached { got, need } => format!("{got} signatures, quorum needs {need}"),
        ExternalQuorumNotReached { got, need } => format!(
            "{got} external signatures, minimum is {need} — a founder-adjacent-only quorum \
             must not verify"
        ),
        BadSignature { index } => format!("signature from signer index {index} does not verify"),
    }
}

// ---------------------------------------------------------------------------
// Renderings — views of the artifact, never the artifact
// ---------------------------------------------------------------------------

fn hex32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

/// The `.json` view of an unsigned payload (spec §2.3: the JSON is a view;
/// the binary is the artifact).
pub fn payload_json(cp: &WeakSubjectivityCheckpoint, digest: &[u8; 32]) -> String {
    format!(
        "{{\n  \"format\": \"bloch-ws-checkpoint-payload\",\n  \"version\": {},\n  \
         \"network_id\": {},\n  \"genesis_root\": \"{}\",\n  \"epoch\": {},\n  \
         \"block_root\": \"{}\",\n  \"state_root\": \"{}\",\n  \
         \"validator_set_root\": \"{}\",\n  \"issued_at\": {},\n  \
         \"signer_set_id\": {},\n  \"ws_digest\": \"{}\"\n}}\n",
        cp.version,
        cp.network_id,
        hex32(&cp.genesis_root),
        cp.epoch,
        hex32(&cp.block_root),
        hex32(&cp.state_root),
        hex32(&cp.validator_set_root),
        cp.issued_at,
        cp.signer_set_id,
        hex::encode(digest),
    )
}

/// The `.json` view of a sealed envelope — what announcements quote. Carries
/// the digest and the signer indices, not the signature bytes: the binary is
/// the artifact, and an announcement that pasted 9 KB of hex would train
/// readers to skim past exactly the 64 characters that matter.
pub fn envelope_json(env: &CheckpointEnvelope, digest: &[u8; 32]) -> String {
    let cp = &env.checkpoint;
    let signers: Vec<String> = env.signatures.iter().map(|(i, _)| i.to_string()).collect();
    format!(
        "{{\n  \"format\": \"bloch-ws-checkpoint\",\n  \"version\": {},\n  \
         \"network_id\": {},\n  \"genesis_root\": \"{}\",\n  \"epoch\": {},\n  \
         \"block_root\": \"{}\",\n  \"state_root\": \"{}\",\n  \
         \"validator_set_root\": \"{}\",\n  \"issued_at\": {},\n  \
         \"signer_set_id\": {},\n  \"ws_digest\": \"{}\",\n  \
         \"signer_indices\": [{}]\n}}\n",
        cp.version,
        cp.network_id,
        hex32(&cp.genesis_root),
        cp.epoch,
        hex32(&cp.block_root),
        hex32(&cp.state_root),
        hex32(&cp.validator_set_root),
        cp.issued_at,
        cp.signer_set_id,
        hex::encode(digest),
        signers.join(", "),
    )
}

/// The well-known `publish/latest.json` index a mirror serves at a stable
/// URL. Everything in it is re-verifiable from the named file; the index
/// itself carries no authority (an attacker controlling the mirror can lie
/// here, and the lie is caught by verifying the file it points to).
pub fn latest_index_json(cp: &WeakSubjectivityCheckpoint, digest: &[u8; 32], set_id: u32) -> String {
    format!(
        "{{\n  \"format\": \"bloch-ws-latest\",\n  \"epoch\": {},\n  \
         \"checkpoint_file\": \"{}/wscheckpoint-{}.bin\",\n  \
         \"signer_set_file\": \"{}/ws-signer-set-{}.bin\",\n  \
         \"ws_digest\": \"{}\"\n}}\n",
        cp.epoch,
        cp.epoch,
        cp.epoch,
        cp.epoch,
        set_id,
        hex::encode(digest),
    )
}

/// The signing request a keyholder receives. Self-contained on purpose: the
/// payload hex is 308 characters, so the keyholder can recompute the digest
/// on an offline machine from this text alone and compare before signing.
pub fn signing_request_text(cp: &WeakSubjectivityCheckpoint, digest: &[u8; 32]) -> String {
    format!(
        "BLOCH WEAK-SUBJECTIVITY CHECKPOINT — SIGNING REQUEST\n\
         =====================================================\n\n\
         Epoch:              {}\n\
         Network id:         {:#010x}\n\
         Genesis root:       {}\n\
         Block root:         {}\n\
         State root:         {}\n\
         Validator set root: {}\n\
         Issued at (unix):   {}\n\
         Signer set id:      {}\n\n\
         DIGEST TO SIGN (SHA3-256 over the domain-separated canonical bytes):\n\n\
         \x20   {}\n\n\
         Canonical payload ({} bytes, hex):\n\n\
         \x20   {}\n\n\
         Before signing, independently recompute the digest from the payload\n\
         hex above: SHA3-256( \"BLCH4:WSCKPT\\0\\0\\0\\0\" || payload ). It must\n\
         equal the digest printed here, and the epoch/roots must match what\n\
         your own node reports for this finalized epoch. Then, on your own\n\
         machine:\n\n\
         \x20   bloch-ws-publisher sign \\\n\
         \x20       --payload wscheckpoint-{}.payload.bin \\\n\
         \x20       --secret-key <your keyfile> \\\n\
         \x20       --signer-set <arrangement file> --signer-index <your index> \\\n\
         \x20       --out sig-<your index>.bin\n\n\
         Return ONLY the sig-<index>.bin file. Never the key, never a shell\n\
         transcript. Signing is the human step of this pipeline by design —\n\
         nothing schedules it, and no station other than `sign` reads a key.\n",
        cp.epoch,
        cp.network_id,
        hex32(&cp.genesis_root),
        hex32(&cp.block_root),
        hex32(&cp.state_root),
        hex32(&cp.validator_set_root),
        cp.issued_at,
        cp.signer_set_id,
        hex::encode(digest),
        WS_CHECKPOINT_BYTES,
        hex::encode(cp.canonical_serialize()),
        cp.epoch,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ws-publisher-test-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const NET: u32 = 0x0400_0007;
    const GEN: [u8; 32] = [0xAB; 32];

    fn pins() -> ChainPins {
        ChainPins { network_id: NET, genesis_root: GEN }
    }

    fn cp(epoch: u64) -> WeakSubjectivityCheckpoint {
        WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: NET,
            genesis_root: GEN,
            epoch,
            block_root: [0x11; 32],
            state_root: [0x22; 32],
            validator_set_root: [0x33; 32],
            issued_at: 1_756_500_000,
            signer_set_id: 1,
        }
    }

    // -- cadence ------------------------------------------------------------

    #[test]
    fn due_epoch_matches_the_committee_cadence() {
        assert_eq!(due_epoch(0), None);
        assert_eq!(due_epoch(WS_PUBLICATION_INTERVAL_EPOCHS - 1), None);
        assert_eq!(due_epoch(WS_PUBLICATION_INTERVAL_EPOCHS), Some(WS_PUBLICATION_INTERVAL_EPOCHS));
        assert_eq!(
            due_epoch(3 * WS_PUBLICATION_INTERVAL_EPOCHS + 17),
            Some(3 * WS_PUBLICATION_INTERVAL_EPOCHS)
        );
        // Everything due_epoch yields is a publication epoch by ws.rs's own rule.
        for f in [256, 300, 511, 512, 10_000] {
            if let Some(e) = due_epoch(f) {
                assert!(ws::is_publication_epoch(e));
            }
        }
    }

    #[test]
    fn freshness_thresholds_are_the_committee_crates() {
        assert!(matches!(freshness(1000, 1000), Freshness::Fresh { age: 0 }));
        assert!(matches!(
            freshness(0, WS_FRESH_EPOCHS),
            Freshness::Stale { .. }
        ));
        assert!(matches!(
            freshness(0, WS_PERIOD_EPOCHS),
            Freshness::Expired { .. }
        ));
        assert!(matches!(
            freshness(0, WS_PERIOD_EPOCHS - 1),
            Freshness::Stale { .. }
        ));
    }

    // -- framing ------------------------------------------------------------

    #[test]
    fn checkpoint_decode_proves_itself_against_canonical_serialize() {
        let c = cp(512);
        let bytes = c.canonical_serialize();
        assert_eq!(decode_checkpoint(&bytes).unwrap(), c);
        assert!(decode_checkpoint(&bytes[..WS_CHECKPOINT_BYTES - 1]).is_err());
    }

    #[test]
    fn envelope_and_signer_set_files_round_trip() {
        let env = CheckpointEnvelope {
            checkpoint: cp(512),
            signatures: vec![(0, vec![7u8; 4000]), (2, vec![9u8; 4100])],
        };
        let back = decode_envelope_file(&encode_envelope_file(&env)).unwrap();
        assert_eq!(back.checkpoint, env.checkpoint);
        assert_eq!(back.signatures, env.signatures);

        let set = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: [1u8; HYBRID_PK_BYTES], external: false },
                Signer { pubkey: [2u8; HYBRID_PK_BYTES], external: true },
            ],
            threshold: 2,
            min_external: 1,
            adopted_epoch: 0,
        };
        let back = decode_signer_set_file(&encode_signer_set_file(&set)).unwrap();
        assert_eq!(back.id, set.id);
        assert_eq!(back.threshold, set.threshold);
        assert_eq!(back.min_external, set.min_external);
        assert_eq!(back.signers.len(), 2);
        assert!(back.signers[1].external);
    }

    // -- staging ------------------------------------------------------------

    #[test]
    fn stage_is_idempotent_and_refuses_a_changed_payload() {
        let layout = Layout::new(tmpdir("stage"));
        let c = cp(512);
        let payload = c.canonical_serialize();
        let req = StageRequest {
            layout: &layout,
            finalized_epoch: 600,
            finalized_root: None,
            pins: pins(),
            epoch_override: None,
        };
        match stage(&req, &payload).unwrap() {
            StageOutcome::Staged { epoch, digest } => {
                assert_eq!(epoch, 512);
                assert_eq!(digest, c.ws_digest());
            }
            _ => panic!("expected Staged"),
        }
        assert!(layout.payload_bin(512).exists());
        assert!(layout.signing_request(512).exists());

        // Same bytes again: no-op.
        assert!(matches!(
            stage(&req, &payload).unwrap(),
            StageOutcome::AlreadyStaged { epoch: 512, .. }
        ));

        // Different bytes for the same epoch: hard refusal.
        let mut other = c;
        other.block_root = [0x99; 32];
        assert!(matches!(
            stage(&req, &other.canonical_serialize()),
            Err(PipeErr::Refuse(_))
        ));
    }

    #[test]
    fn stage_refuses_wrong_epoch_network_and_unfinalized() {
        let layout = Layout::new(tmpdir("stage-refuse"));
        let base = StageRequest {
            layout: &layout,
            finalized_epoch: 600,
            finalized_root: None,
            pins: pins(),
            epoch_override: None,
        };
        // Producer built epoch 256 while 512 is due.
        assert!(matches!(stage(&base, &cp(256).canonical_serialize()), Err(PipeErr::Refuse(_))));
        // Wrong network.
        let mut wrong = cp(512);
        wrong.network_id = NET + 1;
        assert!(matches!(stage(&base, &wrong.canonical_serialize()), Err(PipeErr::Refuse(_))));
        // Reserved signer-set id.
        let mut reserved = cp(512);
        reserved.signer_set_id = WS_GENESIS_SIGNER_SET_ID;
        assert!(matches!(stage(&base, &reserved.canonical_serialize()), Err(PipeErr::Refuse(_))));
        // Override beyond finality.
        let over = StageRequest { epoch_override: Some(700), ..base };
        assert!(matches!(stage(&over, &cp(700).canonical_serialize()), Err(PipeErr::Refuse(_))));
        // Nothing due before the first interval.
        let early = StageRequest {
            layout: &layout,
            finalized_epoch: 100,
            finalized_root: None,
            pins: pins(),
            epoch_override: None,
        };
        assert!(matches!(stage(&early, &[]).unwrap(), StageOutcome::NothingDue));
    }

    #[test]
    fn stage_cross_checks_the_finalized_root_when_epochs_match() {
        let layout = Layout::new(tmpdir("stage-root"));
        let c = cp(512);
        let req = StageRequest {
            layout: &layout,
            finalized_epoch: 512,
            finalized_root: Some([0xEE; 32]), // disagrees with cp's 0x11
            pins: pins(),
            epoch_override: None,
        };
        assert!(matches!(stage(&req, &c.canonical_serialize()), Err(PipeErr::Refuse(_))));
    }

    // -- the full pipeline under the real hybrid suite ----------------------

    fn strip(bytes: &[u8]) -> Vec<u8> {
        let (suite, body) = bloch_crypto::crypto::split_envelope(bytes).expect("enveloped");
        assert_eq!(suite, bloch_crypto::crypto::SUITE_MLDSA65_FALCON1024);
        body.to_vec()
    }

    #[test]
    fn stage_sign_seal_verify_end_to_end() {
        let layout = Layout::new(tmpdir("e2e"));
        let c = cp(512);
        let payload = c.canonical_serialize();

        // Three real keyholders: Phase A shape (2-of-3, one external).
        let mut pks = Vec::new();
        let mut sks = Vec::new();
        for _ in 0..3 {
            let (pk, sk) = bloch_crypto::crypto::generate_keypair();
            let mut fixed = [0u8; HYBRID_PK_BYTES];
            fixed.copy_from_slice(&strip(&pk));
            pks.push(fixed);
            sks.push(sk);
        }
        let set = SignerSet {
            id: 1,
            signers: vec![
                Signer { pubkey: pks[0], external: false },
                Signer { pubkey: pks[1], external: false },
                Signer { pubkey: pks[2], external: true },
            ],
            threshold: ws::WS_PHASE_A_THRESHOLD,
            min_external: ws::WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        assert!(set.matches_policy(
            ws::WS_PHASE_A_THRESHOLD,
            ws::WS_PHASE_A_SIGNERS,
            ws::WS_PHASE_A_MIN_EXTERNAL
        ));
        let set_bytes = encode_signer_set_file(&set);

        // Station 1.
        let req = StageRequest {
            layout: &layout,
            finalized_epoch: 512,
            finalized_root: Some(c.block_root),
            pins: pins(),
            epoch_override: None,
        };
        assert!(matches!(stage(&req, &payload).unwrap(), StageOutcome::Staged { .. }));

        // Station 2 — two keyholders, one internal + the external.
        let sig0 = sign_payload(&payload, &sks[0], Some(&pks[0])).unwrap();
        let sig2 = sign_payload(&payload, &sks[2], Some(&pks[2])).unwrap();
        // Wrong-key detection: signer 0's key against signer 2's pubkey.
        assert!(sign_payload(&payload, &sks[0], Some(&pks[2])).is_err());

        // Station 3 — internal-only quorum must refuse (rule 4)...
        let sig1 = sign_payload(&payload, &sks[1], Some(&pks[1])).unwrap();
        assert!(seal(
            &layout,
            512,
            &set,
            &set_bytes,
            vec![(0, sig0.clone()), (1, sig1)],
            &pins()
        )
        .is_err());
        // ...and the valid quorum seals.
        let sealed = seal(
            &layout,
            512,
            &set,
            &set_bytes,
            vec![(0, sig0), (2, sig2)],
            &pins(),
        )
        .unwrap();
        assert_eq!(sealed.epoch, 512);
        assert_eq!(sealed.signature_count, 2);
        assert_eq!(layout.latest_sealed().unwrap(), Some(512));
        assert!(layout.latest_index().exists());

        // Station 4 — the third party verifies the published file.
        let env_bytes = fs::read(&sealed.envelope_path).unwrap();
        let report = verify_files(&env_bytes, &set_bytes, &pins(), Some(600)).unwrap();
        assert_eq!(report.checkpoint, c);
        assert_eq!(report.digest, c.ws_digest());
        assert_eq!(report.external_count, 1);
        assert!(matches!(report.freshness, Some(Freshness::Fresh { .. })));

        // A flipped byte anywhere in the envelope is caught.
        let mut tampered = env_bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 1;
        assert!(verify_files(&tampered, &set_bytes, &pins(), None).is_err());

        // Wrong pins are caught (testnet replay).
        let wrong = ChainPins { network_id: NET + 1, genesis_root: GEN };
        assert!(verify_files(&env_bytes, &set_bytes, &wrong, None).is_err());

        // Anti-rollback: staging or sealing 256 after 512 is refused/absorbed.
        let older = StageRequest {
            layout: &layout,
            finalized_epoch: 512,
            finalized_root: None,
            pins: pins(),
            epoch_override: Some(256),
        };
        assert!(matches!(
            stage(&older, &cp(256).canonical_serialize()).unwrap(),
            StageOutcome::AlreadyPublished { epoch: 512 }
        ));
    }
}
