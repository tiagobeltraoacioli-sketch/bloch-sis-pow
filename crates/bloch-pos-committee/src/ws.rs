// SPDX-License-Identifier: AGPL-3.0-or-later

//! Weak subjectivity — checkpoint format, verification, and the fresh-sync
//! rules (`BLOCH-WEAK-SUBJECTIVITY.md`, corrected 2026-08-11).
//!
//! ## The problem this module answers
//!
//! Under PoW a fresh node needs nothing but the genesis: forging a heavier
//! history costs as much as living the real one. Under PoS that property does
//! not exist. Once a validator's stake has cleared withdrawal
//! ([`crate::staking::validate_withdrawal`]) its key can sign anything,
//! forever, at zero cost — so a quorum of *exited* validators can manufacture
//! a complete alternative history whose every signature verifies. A fresh
//! node cannot distinguish the two from inside the protocol; the difference
//! is which history the network actually lived through, and that is social
//! information. The answer (Buterin, 2014) is a **weak-subjectivity
//! checkpoint**: a recent finalized (epoch, root) obtained out of band, which
//! the node adopts as a floor it will never revert below.
//!
//! ## The window, re-derived — and why the spec's first number was wrong
//!
//! The original spec set the period equal to
//! [`crate::staking::WITHDRAWAL_DELAY_EPOCHS`] and called that conservative
//! because "exit churn is rate-limited". Re-doing the arithmetic against this
//! crate falsifies both halves:
//!
//! 1. **Validator exits are not rate-limited at all.** The churn budget
//!    ([`crate::delegation::WARMUP_RATE_BPS`], 25 bps since 2026-08-11)
//!    applies to *delegation* warm-up and cool-down. Nothing in
//!    [`crate::staking`] meters exits — the entire self-bonded set can exit
//!    in one epoch. There is no churn credit to decline; on the path that
//!    matters there is nothing to take.
//! 2. **The bound was not conservative — it was 31 epochs too long.** A
//!    validator keeps duties for [`crate::staking::EXIT_DELAY_EPOCHS`] epochs
//!    after its exit is included
//!    ([`crate::staking::ValidatorRecord::assigned_duties_at`]), so a member
//!    of the committee that finalized epoch `F` may have exited as early as
//!    `F − (EXIT_DELAY_EPOCHS − 1)` and becomes withdrawable — unslashable —
//!    at `F + WITHDRAWAL_DELAY_EPOCHS − EXIT_DELAY_EPOCHS + 1`. With the
//!    period at the full withdrawal delay, a node still trusted its own
//!    finality for ~8 hours during which every signer of it could already be
//!    gone. [`WS_PERIOD_EPOCHS`] is therefore **derived** as
//!    `WITHDRAWAL_DELAY_EPOCHS − EXIT_DELAY_EPOCHS`, leaving one epoch of
//!    margin below the earliest possible full withdrawal; the test
//!    `old_window_had_an_unslashable_hole` pins the defect the old constant
//!    had, using the real staking functions.
//!
//! What the 900 → 25 bps churn change *did* alter is a different clock, and
//! it moved in the favorable direction: delegated **collateral** behind a
//! validator's weight drains at the churn rate and becomes spendable after
//! [`crate::delegation::COOLDOWN_EPOCHS`] — about 5 days for two thirds of
//! delegated stake at 25 bps, versus about half a day at 900. That erosion
//! still completes well inside the weak-subjectivity window (the test
//! `delegated_collateral_erodes_inside_the_window` measures it), which means
//! the window's hard guarantee is narrower than it sounds: it guarantees the
//! *validator keys* that finalized the anchor are still slashable, but what
//! they have at risk may by then be only their self-bonds, not the delegated
//! weight they carried. Signing a forged history inside the window is then
//! cheap, not free. Whether the delegation cool-down should scale toward the
//! withdrawal delay is a consensus-parameter question for the founder,
//! flagged here and in the spec — not decided in code.
//!
//! ## Who is trusted, said plainly
//!
//! A checkpoint is a trust anchor, not a proof (the phrasing is
//! `bloch-snapshot-utxo.rs`'s, and it is the house rule). Whoever syncs from
//! scratch trusts the signer arrangement of §6 of the spec: in Phase A, the
//! Foundation, Postern Labs, and one external auditor — founder-adjacent
//! trust with one outside witness, and it must never be described as
//! decentralised. A validly signed checkpoint that attests a forged history —
//! collusion, coercion, or wholesale key theft — is **undetectable from
//! inside the protocol**; the defenses are the independence of the signers,
//! the multiplicity of publication channels, the running network's refusal to
//! follow, and the annual review. A node with no one to trust — no flag, no
//! release-baked checkpoint it believes, no operator decision — and a
//! database that is empty or older than [`WS_PERIOD_EPOCHS`] has exactly one
//! sound behavior, and this module returns it:
//! [`BootDecision::RequireCheckpoint`] / [`BootDecision::RefuseStale`]. It
//! does not sync. That is not a failure mode to engineer around; it is the
//! honest meaning of "weak subjectivity".
//!
//! The one structural limit on the signers' power, enforced here: a
//! checkpoint can never override a running node's own finality. A node whose
//! knowledge is fresh treats a published checkpoint as a cross-check
//! ([`cross_check`]); a conflict raises an alarm, never a reorg. The signers
//! can deceive only the newcomer and the long-offline; they cannot move the
//! network.
//!
//! ## Interaction with the Genesis-3 halt and the signed snapshot
//!
//! The Genesis-3 chain halts at its terminal height; Genesis-4 launches
//! months later from the founder-signed balance snapshot, whose digest is
//! embedded in the Genesis-4 genesis block (`BLOCH-TOKENOMICS-V4.md` §3.1,
//! §3.2.2 — after the halt *the signed artifact is canonical, not the
//! chain*). Three consequences for this module:
//!
//! - **The genesis block is the first weak-subjectivity anchor.**
//!   [`genesis_anchor`] renders it as a checkpoint at epoch 0 under the
//!   reserved [`WS_GENESIS_SIGNER_SET_ID`]. It carries no Foundation
//!   envelope: trusting it *is* trusting the release binary plus the
//!   published snapshot digest, the same trust every Genesis-4 node makes to
//!   exist at all. During the first [`WS_PERIOD_EPOCHS`] after launch a fresh
//!   node therefore needs nothing beyond the genesis — the PoW-like
//!   trust-once window — and Foundation checkpoints only become load-bearing
//!   once the chain outgrows it.
//! - **The dead period needs no checkpoint** because there is no chain to
//!   sync and nothing for a forged continuation to attach to; the artifact,
//!   not any chain, is what Genesis-4 will be built from.
//! - **History below the genesis anchor is Genesis-3 history.** It is
//!   backfill — a service, not consensus — and it authenticates against the
//!   snapshot digest the genesis embeds, never against PoW accumulated after
//!   the halt (which stopped being evidence the day mining stopped).
//!
//! ## What consumes this module
//!
//! The node's boot path: [`boot_decision`] → obtain/verify an envelope
//! ([`verify_envelope`]) → anti-rollback against the stored checkpoint
//! ([`accept`]) → reconcile against local history ([`reconcile`]) → anchor
//! fork choice and finality ([`anchor`], which hands
//! [`crate::finality::FinalityState`] its trusted root). State download then
//! verifies every piece against `state_root` / `validator_set_root` — the
//! trust is the 32 bytes of the root, never the peer that served the data.

use crate::finality;
use crate::params::{DS_WSCKPT, SLOTS_PER_EPOCH, SLOT_DURATION_SECS};
use crate::staking::{self, HybridKeyVerifier, HYBRID_PK_BYTES};
use sha3::{Digest, Sha3_256};

// ---------------------------------------------------------------------------
// The window and cadence
// ---------------------------------------------------------------------------

/// Hard threshold: the oldest a node's own finalized knowledge may be while
/// still serving as its subjectivity anchor. **Derived, not chosen**:
/// the withdrawal delay minus the exit delay, because a committee member of
/// epoch `F` may have exited up to `EXIT_DELAY_EPOCHS − 1` epochs before `F`
/// while still carrying duties, and is unslashable once its withdrawal
/// clears. See the module docs for why the spec's original value (the full
/// withdrawal delay) had the sign of its error backwards.
pub const WS_PERIOD_EPOCHS: u64 =
    staking::WITHDRAWAL_DELAY_EPOCHS - staking::EXIT_DELAY_EPOCHS;

/// Soft threshold — half the period. Staleness is surfaced while ~11 days of
/// margin remain, instead of being discovered at the cliff edge.
pub const WS_FRESH_EPOCHS: u64 = WS_PERIOD_EPOCHS / 2;

/// The Foundation publishes a checkpoint at every finalized epoch that is a
/// multiple of this. Against [`WS_PERIOD_EPOCHS`] this leaves a ~7.8× margin:
/// **six** consecutive signing ceremonies can fail before the newest
/// published checkpoint ages past the hard threshold (the seventh miss is the
/// liveness event). The spec originally said seven, computed against the
/// uncorrected window; `publication_cadence_margin` pins the corrected count.
pub const WS_PUBLICATION_INTERVAL_EPOCHS: u64 = 256;

/// Wall-clock epochs per day, from the slot geometry. Used only for the
/// arrangement-review deadlines, which the spec states in months.
pub const EPOCHS_PER_DAY: u64 = 86_400 / (SLOT_DURATION_SECS * SLOTS_PER_EPOCH);

/// Review cadence of the signer arrangement (§6.3): 12 months. Past this,
/// envelopes still verify but carry a warning — the review ADR is due.
pub const WS_ARRANGEMENT_REVIEW_EPOCHS: u64 = 365 * EPOCHS_PER_DAY;

/// Grace beyond the review deadline (§6.3): ~3 months. Past review + grace
/// the arrangement's envelopes are refused — the dead-man's switch that keeps
/// a skipped review from quietly becoming permanent. Fresh sync degrades
/// until governance acts; running nodes are unaffected.
pub const WS_ARRANGEMENT_GRACE_EPOCHS: u64 = 91 * EPOCHS_PER_DAY;

/// Is `epoch` one the Foundation owes a checkpoint for?
pub const fn is_publication_epoch(epoch: u64) -> bool {
    epoch % WS_PUBLICATION_INTERVAL_EPOCHS == 0
}

/// Estimate the current epoch from wall-clock time. This is the one place
/// the subjectivity machinery reads a clock, and it is an *input*, supplied
/// by the caller: a node whose clock can be set backward can be convinced it
/// is fresh when it is stale (the standard NTP caveat, shared with every
/// slots-based chain — the runbook owes authenticated time sources).
/// The "refuse to start if the clock disagrees grossly with peer time"
/// defense §1 calls for is implemented node-side in
/// `bloch-pos-node/src/time_check.rs` (2026-08-31): boot compares the local
/// clock against the median of the dialed peers' reported time and refuses
/// beyond half an epoch of skew.
pub const fn wallclock_epoch(genesis_unix: u64, now_unix: u64) -> u64 {
    now_unix.saturating_sub(genesis_unix) / (SLOT_DURATION_SECS * SLOTS_PER_EPOCH)
}

// ---------------------------------------------------------------------------
// Checkpoint format (§2.1)
// ---------------------------------------------------------------------------

/// Format version this module encodes and accepts.
pub const WS_FORMAT_VERSION: u16 = 1;

/// Canonical serialization length: every field fixed-width, declared order,
/// little-endian integers, no framing, no options — injective by
/// construction, the same discipline as `BlockHeaderV4`.
pub const WS_CHECKPOINT_BYTES: usize = 2  // version
    + 4   // network_id
    + 32  // genesis_root
    + 8   // epoch
    + 32  // block_root
    + 32  // state_root
    + 32  // validator_set_root
    + 8   // issued_at
    + 4; // signer_set_id

/// The signed object: a finalized epoch boundary, bound to one chain.
///
/// There is deliberately **no expiry field**: freshness is a consumer-side
/// rule computed from `epoch` against [`WS_PERIOD_EPOCHS`]. Baking a second
/// notion of freshness into the artifact would create two clocks that can
/// disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeakSubjectivityCheckpoint {
    /// Format version, [`WS_FORMAT_VERSION`].
    pub version: u16,
    /// Genesis-4 network id — a testnet checkpoint must be unusable on
    /// mainnet by construction, not by operator care.
    pub network_id: u32,
    /// Identity of the Genesis-4 genesis block (which itself embeds the
    /// signed Genesis-3 snapshot digest — §3.2.2 of the tokenomics spec).
    pub genesis_root: [u8; 32],
    /// The finalized epoch this checkpoint attests.
    pub epoch: u64,
    /// Identity of the finalized epoch-boundary block. Raw bytes, not a
    /// `BlockId`, for the same reason `finality::Checkpoint::root` is: a
    /// value that arrives from outside is compared against an identity this
    /// node derives itself, never minted into one.
    pub block_root: [u8; 32],
    /// `BlockHeaderV4.state_root` of that block — what checkpoint-sync state
    /// download verifies against.
    pub state_root: [u8; 32],
    /// SMT root of the validator registry at that state, included so the
    /// registry can be verified directly, without first rebuilding the full
    /// state tree.
    pub validator_set_root: [u8; 32],
    /// Unix seconds at signing. Informational — verification never reads it,
    /// because an artifact checked at boot must not depend on the verifying
    /// machine's clock agreeing with the signing ceremony's.
    pub issued_at: u64,
    /// Which signer arrangement produced this (§6.4);
    /// [`WS_GENESIS_SIGNER_SET_ID`] is reserved for the genesis anchor.
    pub signer_set_id: u32,
}

impl WeakSubjectivityCheckpoint {
    /// Canonical bytes — the thing that is hashed and signed. Fields in
    /// declared order, integers little-endian, nothing optional.
    pub fn canonical_serialize(&self) -> [u8; WS_CHECKPOINT_BYTES] {
        let mut out = [0u8; WS_CHECKPOINT_BYTES];
        let mut at = 0usize;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&self.version.to_le_bytes());
        put(&self.network_id.to_le_bytes());
        put(&self.genesis_root);
        put(&self.epoch.to_le_bytes());
        put(&self.block_root);
        put(&self.state_root);
        put(&self.validator_set_root);
        put(&self.issued_at.to_le_bytes());
        put(&self.signer_set_id.to_le_bytes());
        out
    }

    /// `SHA3-256(DS_WSCKPT ‖ canonical bytes)` — the digest signers sign and
    /// announcements quote. 64 hex characters: it fits in a chat message or a
    /// phone call, which is exactly the out-of-band property the mechanism
    /// needs.
    pub fn ws_digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_WSCKPT);
        h.update(self.canonical_serialize());
        h.finalize().into()
    }

    /// Render this checkpoint as the trust root for
    /// [`crate::finality::FinalityState`] — justified and finalized by
    /// definition, the floor fork choice never reverts below.
    pub fn as_finality_checkpoint(&self) -> finality::Checkpoint {
        finality::Checkpoint { epoch: self.epoch, root: self.block_root }
    }
}

/// Start finality from a verified checkpoint. Thin by design: the anchor is
/// `FinalityState::new`'s documented purpose, and this function exists so the
/// sync path has one named place where "the checkpoint becomes the floor"
/// happens.
pub fn anchor(cp: &WeakSubjectivityCheckpoint) -> finality::FinalityState {
    finality::FinalityState::new(cp.as_finality_checkpoint())
}

// ---------------------------------------------------------------------------
// Signer sets (§6)
// ---------------------------------------------------------------------------

/// Phase A (launch): 2-of-3, at least one external — the Foundation, Postern
/// Labs, and the external audit firm. Founder-adjacent trust with one outside
/// witness; strictly better than a single key, and not decentralised.
pub const WS_PHASE_A_THRESHOLD: usize = 2;
/// Phase A signer count.
pub const WS_PHASE_A_SIGNERS: usize = 3;
/// Phase A minimum valid signatures from the external subset.
pub const WS_PHASE_A_MIN_EXTERNAL: usize = 1;

/// Phase B (by the first review): 3-of-5, at least two external. The
/// Foundation and Postern together cannot produce a quorum.
pub const WS_PHASE_B_THRESHOLD: usize = 3;
/// Phase B signer count.
pub const WS_PHASE_B_SIGNERS: usize = 5;
/// Phase B minimum valid signatures from the external subset.
pub const WS_PHASE_B_MIN_EXTERNAL: usize = 2;

/// Reserved `signer_set_id` of the genesis anchor. No envelope exists for it:
/// the genesis block is release-baked and its trust is the signed Genesis-3
/// snapshot whose digest it embeds, not a Foundation quorum.
pub const WS_GENESIS_SIGNER_SET_ID: u32 = 0;

/// One keyholder in an arrangement: an ordinary hybrid keypair — the same
/// suite as everything else, no threshold ceremony, no DKG, no new primitive.
#[derive(Clone)]
pub struct Signer {
    /// ML-DSA-65 ‖ Falcon-1024 public key.
    pub pubkey: [u8; HYBRID_PK_BYTES],
    /// True for signers outside the founding cluster (§6.1's subset column).
    /// This flag is *verification* data — rule 4 makes the external minimum a
    /// client-enforced invariant, not a signing-ceremony hope.
    pub external: bool,
}

/// A signer arrangement as hard-coded in the client release: keys, quorum
/// rule, and its review clock. `signer_index` in envelopes indexes into
/// `signers`.
#[derive(Clone)]
pub struct SignerSet {
    /// Arrangement id, matched against `checkpoint.signer_set_id`. Must not
    /// be [`WS_GENESIS_SIGNER_SET_ID`].
    pub id: u32,
    pub signers: Vec<Signer>,
    /// Minimum valid signatures.
    pub threshold: usize,
    /// Minimum valid signatures from signers flagged `external`.
    pub min_external: usize,
    /// Epoch the arrangement was adopted — the review clock's zero.
    pub adopted_epoch: u64,
}

impl SignerSet {
    /// Epoch after which envelopes from this arrangement warn (review due).
    pub fn review_deadline(&self) -> u64 {
        self.adopted_epoch.saturating_add(WS_ARRANGEMENT_REVIEW_EPOCHS)
    }

    /// Epoch after which envelopes from this arrangement are refused — the
    /// §6.3 dead-man's switch.
    pub fn hard_stop(&self) -> u64 {
        self.review_deadline().saturating_add(WS_ARRANGEMENT_GRACE_EPOCHS)
    }

    /// Does the set's shape satisfy an (m, n, min-external) policy, including
    /// having enough externally-flagged keys for the external minimum to be
    /// satisfiable at all? A set that *cannot* meet its own external minimum
    /// would make every envelope unverifiable — better caught at
    /// release-build time than at a user's boot.
    pub fn matches_policy(&self, threshold: usize, n: usize, min_external: usize) -> bool {
        self.threshold == threshold
            && self.signers.len() == n
            && self.min_external == min_external
            && self.signers.iter().filter(|s| s.external).count() >= min_external
            && self.threshold <= self.signers.len()
            && self.min_external <= self.threshold
    }
}

// ---------------------------------------------------------------------------
// Envelope and verification (§2.2)
// ---------------------------------------------------------------------------

/// The distributed artifact: the checkpoint plus a plain list of independent
/// hybrid signatures over its digest. No threshold lattice signature exists
/// production-ready, and none is needed for something verified once at boot.
#[derive(Clone)]
pub struct CheckpointEnvelope {
    pub checkpoint: WeakSubjectivityCheckpoint,
    /// `(signer_index, hybrid signature over ws_digest)`.
    pub signatures: Vec<(u8, Vec<u8>)>,
}

/// Why an envelope was rejected. Explicit variants because a refused boot
/// must be attributable from its error message alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeReject {
    /// Format version this client does not speak.
    WrongVersion { got: u16 },
    /// Cross-chain / testnet replay: network id mismatch.
    WrongNetwork { got: u32, expected: u32 },
    /// Cross-chain replay: genesis root mismatch.
    WrongGenesisRoot,
    /// The envelope names a different arrangement than the one supplied.
    WrongSignerSet { got: u32, expected: u32 },
    /// The genesis id is reserved — no envelope may claim it.
    ReservedSignerSet,
    /// Arrangement past review + grace (§6.3): refused until governance acts.
    ArrangementExpired { hard_stop_epoch: u64 },
    /// A signer index outside the set.
    UnknownSignerIndex { index: u8 },
    /// The same signer listed twice — a duplicated key must not count twice
    /// toward the quorum.
    DuplicateSigner { index: u8 },
    /// Fewer signatures than the threshold, before any verification runs.
    QuorumNotReached { got: usize, need: usize },
    /// Fewer external signatures than the minimum — a quorum consisting only
    /// of founder-adjacent keys must not verify (rule 4).
    ExternalQuorumNotReached { got: usize, need: usize },
    /// A listed signature failed either half of the hybrid. Every listed
    /// signature must verify — a mixture of valid and junk signatures is
    /// malformed, not "enough valid ones".
    BadSignature { index: u8 },
}

/// What a successful verification reports beyond "valid".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeOk {
    /// The arrangement is past its 12-month review deadline (but inside
    /// grace). Accept, warn loudly: the review ADR is overdue.
    pub arrangement_past_review: bool,
}

/// Verify an envelope against the arrangement and the chain identity the
/// caller expects. All rules of §2.2 (order: cheapest first — the hybrid
/// verification is by far the most expensive step and runs last):
///
/// 1. every listed `signer_index` exists and none repeats,
/// 2. every listed signature verifies over `ws_digest` under BOTH halves
///    (the AND-composition is [`crate::staking`]'s, called — not copied),
/// 3. at least `set.threshold` signatures,
/// 4. at least `set.min_external` from externally-flagged signers.
pub fn verify_envelope(
    env: &CheckpointEnvelope,
    set: &SignerSet,
    expected_network_id: u32,
    expected_genesis_root: &[u8; 32],
    verifier: &dyn HybridKeyVerifier,
) -> Result<EnvelopeOk, EnvelopeReject> {
    let cp = &env.checkpoint;
    if cp.version != WS_FORMAT_VERSION {
        return Err(EnvelopeReject::WrongVersion { got: cp.version });
    }
    if cp.network_id != expected_network_id {
        return Err(EnvelopeReject::WrongNetwork {
            got: cp.network_id,
            expected: expected_network_id,
        });
    }
    if &cp.genesis_root != expected_genesis_root {
        return Err(EnvelopeReject::WrongGenesisRoot);
    }
    if cp.signer_set_id == WS_GENESIS_SIGNER_SET_ID || set.id == WS_GENESIS_SIGNER_SET_ID {
        return Err(EnvelopeReject::ReservedSignerSet);
    }
    if cp.signer_set_id != set.id {
        return Err(EnvelopeReject::WrongSignerSet { got: cp.signer_set_id, expected: set.id });
    }
    // The dead-man's switch is judged against the checkpoint's own epoch, not
    // wall clock: the artifact must verify identically on every machine.
    if cp.epoch > set.hard_stop() {
        return Err(EnvelopeReject::ArrangementExpired { hard_stop_epoch: set.hard_stop() });
    }

    // Index validity and uniqueness before any signature math.
    let mut seen = [false; 256];
    for (index, _) in &env.signatures {
        if (*index as usize) >= set.signers.len() {
            return Err(EnvelopeReject::UnknownSignerIndex { index: *index });
        }
        if seen[*index as usize] {
            return Err(EnvelopeReject::DuplicateSigner { index: *index });
        }
        seen[*index as usize] = true;
    }

    // Count checks before verification: rejecting an under-quorum envelope
    // must not cost a single hybrid verification (~7.3M instructions each).
    if env.signatures.len() < set.threshold {
        return Err(EnvelopeReject::QuorumNotReached {
            got: env.signatures.len(),
            need: set.threshold,
        });
    }
    let external_listed = env
        .signatures
        .iter()
        .filter(|(i, _)| set.signers[*i as usize].external)
        .count();
    if external_listed < set.min_external {
        return Err(EnvelopeReject::ExternalQuorumNotReached {
            got: external_listed,
            need: set.min_external,
        });
    }

    let digest = cp.ws_digest();
    for (index, sig) in &env.signatures {
        let signer = &set.signers[*index as usize];
        if !staking::verify_hybrid(&signer.pubkey, &digest, sig, verifier) {
            return Err(EnvelopeReject::BadSignature { index: *index });
        }
    }

    Ok(EnvelopeOk { arrangement_past_review: cp.epoch > set.review_deadline() })
}

// ---------------------------------------------------------------------------
// Storage rule (§4.1): anti-rollback
// ---------------------------------------------------------------------------

/// What to do with a validly-signed envelope relative to the highest-epoch
/// checkpoint the node has ever verified (`ws_latest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    /// Newer than anything stored — persist as the new `ws_latest`.
    Store,
    /// Older than, or identical to, the stored checkpoint — log and ignore.
    /// Without this rule, a stolen *old* quorum signature could "refresh" a
    /// node backward into an attacker's window.
    Ignore,
    /// Same epoch, different digest: two validly-signed checkpoints for one
    /// epoch is a loud alarm (a quietly-replaced publication or an equivocal
    /// quorum), never a silent overwrite.
    Conflict,
}

/// Anti-rollback decision. Pure — persistence belongs to the node.
pub fn accept(
    stored: Option<&WeakSubjectivityCheckpoint>,
    incoming: &WeakSubjectivityCheckpoint,
) -> Acceptance {
    match stored {
        None => Acceptance::Store,
        Some(s) if incoming.epoch > s.epoch => Acceptance::Store,
        Some(s) if incoming.epoch < s.epoch => Acceptance::Ignore,
        Some(s) if incoming.ws_digest() == s.ws_digest() => Acceptance::Ignore,
        Some(_) => Acceptance::Conflict,
    }
}

// ---------------------------------------------------------------------------
// Boot decision (§4.2)
// ---------------------------------------------------------------------------

/// The four boot states. `age` is (wall-clock epoch estimate) − (the node's
/// own latest finalized epoch); the caller computes it with
/// [`wallclock_epoch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootDecision {
    /// Empty database: a checkpoint is **required** (flag or release-baked).
    /// No checkpoint → refuse to sync, saying why in these terms. A fresh
    /// node with no one to trust does not get a chain; it gets this variant.
    RequireCheckpoint,
    /// Fresh knowledge: resume from own finalized head — own finality *is*
    /// the subjectivity anchor. A published checkpoint is a cross-check
    /// ([`cross_check`]), never a requirement.
    Resume,
    /// Stale but inside the window: resume, warn prominently, and fetch a
    /// fresh checkpoint before following any peer offering a competing
    /// finalized branch.
    ResumeStaleWarn,
    /// At or beyond the window (`ERR_WS_STALE`): refuse to follow any peer.
    /// Every validator that signed this node's finality markers may already
    /// have withdrawn; a checkpoint stops being optional and becomes the only
    /// sound way back in. A long-offline node with no one to trust stays
    /// here — that is the honest cost of the mechanism, not a bug.
    RefuseStale,
}

/// Decide the boot state from local knowledge alone.
pub fn boot_decision(has_local_finality: bool, age_epochs: u64) -> BootDecision {
    if !has_local_finality {
        BootDecision::RequireCheckpoint
    } else if age_epochs < WS_FRESH_EPOCHS {
        BootDecision::Resume
    } else if age_epochs < WS_PERIOD_EPOCHS {
        BootDecision::ResumeStaleWarn
    } else {
        BootDecision::RefuseStale
    }
}

// ---------------------------------------------------------------------------
// Reconciliation (§4.2 recovery) and the running-node cross-check (§5)
// ---------------------------------------------------------------------------

/// Recovery from [`BootDecision::RefuseStale`], after a fresh envelope
/// verified: reconcile it against local history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    /// The checkpoint descends from the node's own finalized head: keep the
    /// database, sync forward, verifying each epoch's justification along
    /// the way. The common case — the node was simply away.
    ContinueForward,
    /// Not a descendant: either local history was forged while the node was
    /// away, or the published checkpoint is wrong. The node MUST NOT
    /// auto-wipe — whichever side is wrong, silently discarding a database
    /// is how evidence disappears. Halt with both roots printed; resuming
    /// requires an explicit operator decision (`--ws-accept-reorg <root>`).
    HaltForOperator { local_finalized_root: [u8; 32], checkpoint_root: [u8; 32] },
}

/// `checkpoint_descends_local` is established by the caller syncing headers
/// from its local finalized head to the checkpoint and verifying each epoch's
/// justification — ancestry is chain knowledge this crate does not hold.
pub fn reconcile(
    cp: &WeakSubjectivityCheckpoint,
    local_finalized_root: [u8; 32],
    checkpoint_descends_local: bool,
) -> Reconciliation {
    if checkpoint_descends_local || cp.block_root == local_finalized_root {
        Reconciliation::ContinueForward
    } else {
        Reconciliation::HaltForOperator { local_finalized_root, checkpoint_root: cp.block_root }
    }
}

/// A running node's view of a published checkpoint. The checkpoint can never
/// override own finality — the structural limit on the signers' blast
/// radius: they can deceive the newcomer; they cannot move the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossCheck {
    /// The published root matches what this node finalized at that epoch.
    Consistent,
    /// The checkpoint attests an epoch beyond this node's finality — nothing
    /// to compare yet; the node will get there by ordinary sync.
    AheadOfLocal,
    /// `WS_CONFLICT`: the published checkpoint contradicts this node's own
    /// finality. Alarm and operator alert — never a reorg.
    Conflict { local_root: [u8; 32], published_root: [u8; 32] },
}

/// Compare a published checkpoint against the node's own finalized root at
/// the same epoch (`None` if the node has not finalized that epoch).
pub fn cross_check(
    local_root_at_epoch: Option<[u8; 32]>,
    published: &WeakSubjectivityCheckpoint,
) -> CrossCheck {
    match local_root_at_epoch {
        None => CrossCheck::AheadOfLocal,
        Some(root) if root == published.block_root => CrossCheck::Consistent,
        Some(root) => CrossCheck::Conflict { local_root: root, published_root: published.block_root },
    }
}

// ---------------------------------------------------------------------------
// The genesis anchor (Genesis-3 snapshot interaction)
// ---------------------------------------------------------------------------

/// Render the Genesis-4 genesis block as the first weak-subjectivity anchor:
/// epoch 0, under the reserved signer-set id, with no envelope. Its trust is
/// the founder-signed Genesis-3 snapshot whose digest the genesis block
/// embeds — the trust every Genesis-4 node already makes to exist at all
/// (the tokenomics spec's rule: after the halt, the signed artifact is
/// canonical, not the chain). Recurrence is what distinguishes PoS here: PoW
/// asks for this trust once; this design re-asks every fresh-syncing node
/// for a *recent* anchor, forever, and the genesis is merely the first.
pub fn genesis_anchor(
    network_id: u32,
    genesis_root: [u8; 32],
    state_root: [u8; 32],
    validator_set_root: [u8; 32],
    issued_at: u64,
) -> WeakSubjectivityCheckpoint {
    WeakSubjectivityCheckpoint {
        version: WS_FORMAT_VERSION,
        network_id,
        genesis_root,
        epoch: 0,
        block_root: genesis_root,
        state_root,
        validator_set_root,
        issued_at,
        signer_set_id: WS_GENESIS_SIGNER_SET_ID,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::{Delegation, Registry, COOLDOWN_EPOCHS, MIN_CHURN_SAT, WARMUP_RATE_BPS};
    use crate::params::{DS_ATTEST, DS_BLOCK, DS_DEPOSIT, DS_EXIT, DS_PROPOSE};
    use crate::staking::{
        validate_withdrawal, ValidatorRecord, WithdrawReject, EXIT_DELAY_EPOCHS,
        FALCON1024_PK_BYTES, MLDSA65_PK_BYTES, MLDSA65_SIG_BYTES, WITHDRAWAL_DELAY_EPOCHS,
    };

    // -- the window arithmetic, executable ---------------------------------

    /// The correction that motivated this module: with the period at the full
    /// withdrawal delay (the spec's original number), a committee member of
    /// epoch F who exited at F − (EXIT_DELAY − 1) — still carrying duties at
    /// F — can withdraw while a node's trust in F is still inside the old
    /// window. The real staking functions demonstrate the hole.
    #[test]
    fn old_window_had_an_unslashable_hole() {
        let f = 10_000u64; // the epoch the node's anchor was finalized
        let exit_epoch = f - (EXIT_DELAY_EPOCHS - 1);
        let mut rec = record();
        rec.exit_epoch = Some(exit_epoch);

        // The validator was still assigned duties at F — it could be in the
        // committee whose signatures the node's anchor rests on.
        assert!(rec.assigned_duties_at(f), "exited validator still serves at F");

        // Old rule: trust own finality while age < WITHDRAWAL_DELAY_EPOCHS,
        // i.e. through age WITHDRAWAL_DELAY_EPOCHS − 1. At that age the
        // signer's withdrawal has already cleared: the hole.
        let last_trusted_old = f + WITHDRAWAL_DELAY_EPOCHS - 1;
        assert!(
            validate_withdrawal(&rec, last_trusted_old).is_ok(),
            "inside the old window the committee can already be unslashable"
        );
    }

    /// The corrected constant closes the hole with margin: at the first age
    /// the node refuses (`age == WS_PERIOD_EPOCHS`), the earliest-exiting
    /// committee member of the anchor epoch is still one epoch short of
    /// withdrawal.
    #[test]
    fn corrected_window_leaves_no_gap() {
        let f = 10_000u64;
        let exit_epoch = f - (EXIT_DELAY_EPOCHS - 1);
        let mut rec = record();
        rec.exit_epoch = Some(exit_epoch);
        assert!(rec.assigned_duties_at(f));

        // Last age the corrected rule still trusts: WS_PERIOD_EPOCHS − 1.
        assert_eq!(
            validate_withdrawal(&rec, f + WS_PERIOD_EPOCHS - 1),
            Err(WithdrawReject::DelayNotElapsed)
        );
        // Even at the refusal boundary itself the stake is still bonded —
        // one epoch of margin below the earliest possible withdrawal.
        assert_eq!(
            validate_withdrawal(&rec, f + WS_PERIOD_EPOCHS),
            Err(WithdrawReject::DelayNotElapsed)
        );
        // Derivation sanity: the period plus the duty overlap never exceeds
        // the withdrawal delay.
        assert!(WS_PERIOD_EPOCHS + EXIT_DELAY_EPOCHS <= WITHDRAWAL_DELAY_EPOCHS);
        assert!(WS_FRESH_EPOCHS < WS_PERIOD_EPOCHS);
    }

    /// The honest caveat the 25 bps churn change re-prices: delegated
    /// collateral behind finality weight drains and becomes spendable well
    /// inside the weak-subjectivity window. The window guarantees the
    /// validator *keys* are still slashable — not that what they have at
    /// risk still matches the weight they carried. Measured, not asserted
    /// from prose: two thirds of an all-delegated set drains in ~439 epochs
    /// at 25 bps (ln 3 / −ln(1 − 0.0025)), plus the delegation cool-down —
    /// under a quarter of the window.
    #[test]
    fn delegated_collateral_erodes_inside_the_window() {
        // Large enough that the churn floor is negligible until well past
        // the one-third mark (floor binds only below MIN_CHURN/rate of the
        // total).
        let initial: u128 = 1_000_000_000 * crate::tokenomics_v4::SAT_PER_BLOCH;
        let per = initial / 10;
        let delegations: Vec<Delegation> = (0..10)
            .map(|i| Delegation {
                delegator: i,
                validator: i,
                amount_sat: per,
                requested_epoch: 0,
                deactivate_epoch: Some(1),
                eligible: true,
            })
            .collect();
        assert!(initial * WARMUP_RATE_BPS / 10_000 > MIN_CHURN_SAT, "floor must not dominate");

        let mut drained_at = None;
        for e in 1..=600u64 {
            let reg = Registry::resolve(&delegations, e);
            if reg.total_active() * 3 <= initial {
                drained_at = Some(e);
                break;
            }
        }
        let e = drained_at.expect("two thirds must drain within 600 epochs at 25 bps");
        // Geometric decay at 25 bps/epoch: ln 3 / −ln(0.9975) ≈ 439.
        assert!((420..=460).contains(&e), "expected ~439 epochs, got {e}");
        // The erosion — drain plus cool-down — completes in a fraction of
        // the window. This is the deterrent-decay caveat, in numbers.
        assert!(e + COOLDOWN_EPOCHS < WS_PERIOD_EPOCHS / 4);
    }

    /// Publication cadence vs the corrected window: six consecutive missed
    /// ceremonies are survivable, the seventh is a liveness event. (The spec
    /// originally said seven, computed against the uncorrected window.)
    #[test]
    fn publication_cadence_margin() {
        assert!(7 * WS_PUBLICATION_INTERVAL_EPOCHS < WS_PERIOD_EPOCHS);
        assert!(8 * WS_PUBLICATION_INTERVAL_EPOCHS >= WS_PERIOD_EPOCHS);
        assert!(is_publication_epoch(0));
        assert!(is_publication_epoch(WS_PUBLICATION_INTERVAL_EPOCHS * 3));
        assert!(!is_publication_epoch(WS_PUBLICATION_INTERVAL_EPOCHS + 1));
    }

    // -- format ------------------------------------------------------------

    fn checkpoint() -> WeakSubjectivityCheckpoint {
        WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: 0x0004_0001,
            genesis_root: [0x61; 32],
            epoch: WS_PUBLICATION_INTERVAL_EPOCHS * 4,
            block_root: [0x22; 32],
            state_root: [0x33; 32],
            validator_set_root: [0x44; 32],
            issued_at: 1_800_000_000,
            signer_set_id: 1,
        }
    }

    #[test]
    fn canonical_bytes_are_fixed_length() {
        let cp = checkpoint();
        assert_eq!(cp.canonical_serialize().len(), WS_CHECKPOINT_BYTES);
        // The spec quotes 154 B for the offline-signing path; pin it so a
        // field change cannot silently invalidate the ceremony runbook.
        assert_eq!(WS_CHECKPOINT_BYTES, 154);
    }

    #[test]
    fn digest_binds_every_field() {
        let base = checkpoint();
        let mut variants = vec![base];
        macro_rules! mutate {
            ($($field:ident => $e:expr),*) => {$(
                let mut m = base;
                m.$field = $e;
                variants.push(m);
            )*}
        }
        mutate!(
            version => WS_FORMAT_VERSION + 1,
            network_id => base.network_id + 1,
            genesis_root => [0xEE; 32],
            epoch => base.epoch + 1,
            block_root => [0xEE; 32],
            state_root => [0xEE; 32],
            validator_set_root => [0xEE; 32],
            issued_at => base.issued_at + 1,
            signer_set_id => base.signer_set_id + 1
        );
        let digests: Vec<[u8; 32]> = variants.iter().map(|c| c.ws_digest()).collect();
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(digests[i], digests[j], "fields {i} vs {j} did not bind");
            }
        }
    }

    #[test]
    fn domain_tag_shape_and_uniqueness() {
        assert_eq!(DS_WSCKPT.len(), 16);
        assert!(DS_WSCKPT.starts_with(b"BLCH4:WSCKPT"));
        assert!(DS_WSCKPT[12..].iter().all(|&b| b == 0), "zero-padded to 16");
        for other in [DS_BLOCK, DS_ATTEST, DS_DEPOSIT, DS_EXIT, DS_PROPOSE] {
            assert_ne!(DS_WSCKPT, other);
        }
    }

    // -- envelope verification (§2.2 KAT set) ------------------------------

    /// Accepts iff both halves are non-empty and the pubkey's first byte is
    /// not the poison marker — lets a test fail exactly one signer.
    struct MarkerVerifier {
        poison: u8,
    }
    impl HybridKeyVerifier for MarkerVerifier {
        fn verify_mldsa65(&self, pubkey: &[u8], _root: &[u8; 32], sig: &[u8]) -> bool {
            assert_eq!(pubkey.len(), MLDSA65_PK_BYTES);
            assert_eq!(sig.len(), MLDSA65_SIG_BYTES);
            pubkey[0] != self.poison
        }
        fn verify_falcon1024(&self, pubkey: &[u8], _root: &[u8; 32], sig: &[u8]) -> bool {
            assert_eq!(pubkey.len(), FALCON1024_PK_BYTES);
            !sig.is_empty()
        }
    }

    fn accept_all() -> MarkerVerifier {
        MarkerVerifier { poison: 0xFF }
    }

    fn signer(id: u8, external: bool) -> Signer {
        Signer { pubkey: [id; HYBRID_PK_BYTES], external }
    }

    /// Phase A shape: internal 0, internal 1, external 2.
    fn phase_a_set() -> SignerSet {
        let set = SignerSet {
            id: 1,
            signers: vec![signer(10, false), signer(11, false), signer(12, true)],
            threshold: WS_PHASE_A_THRESHOLD,
            min_external: WS_PHASE_A_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        assert!(set.matches_policy(WS_PHASE_A_THRESHOLD, WS_PHASE_A_SIGNERS, WS_PHASE_A_MIN_EXTERNAL));
        set
    }

    fn sig() -> Vec<u8> {
        vec![0u8; MLDSA65_SIG_BYTES + 1280]
    }

    fn envelope(indices: &[u8]) -> CheckpointEnvelope {
        CheckpointEnvelope {
            checkpoint: checkpoint(),
            signatures: indices.iter().map(|i| (*i, sig())).collect(),
        }
    }

    const NET: u32 = 0x0004_0001;
    const GEN: [u8; 32] = [0x61; 32];

    #[test]
    fn valid_phase_a_envelope_verifies() {
        // Internal 0 + external 2: quorum of 2 with 1 external.
        let ok = verify_envelope(&envelope(&[0, 2]), &phase_a_set(), NET, &GEN, &accept_all())
            .expect("must verify");
        assert!(!ok.arrangement_past_review);
    }

    #[test]
    fn quorum_without_external_fails() {
        // Both internal keys: m reached, external minimum not — the rule
        // that keeps the m-of-n from being the Foundation with extra steps.
        assert_eq!(
            verify_envelope(&envelope(&[0, 1]), &phase_a_set(), NET, &GEN, &accept_all()),
            Err(EnvelopeReject::ExternalQuorumNotReached { got: 0, need: WS_PHASE_A_MIN_EXTERNAL })
        );
    }

    #[test]
    fn under_quorum_fails_before_any_verification() {
        // Poison every key: if verification ran, it would report
        // BadSignature. The count check must fire first.
        let poison_all = MarkerVerifier { poison: 12 };
        assert_eq!(
            verify_envelope(&envelope(&[2]), &phase_a_set(), NET, &GEN, &poison_all),
            Err(EnvelopeReject::QuorumNotReached { got: 1, need: WS_PHASE_A_THRESHOLD })
        );
    }

    #[test]
    fn duplicate_signer_index_fails() {
        assert_eq!(
            verify_envelope(&envelope(&[2, 2]), &phase_a_set(), NET, &GEN, &accept_all()),
            Err(EnvelopeReject::DuplicateSigner { index: 2 })
        );
    }

    #[test]
    fn unknown_signer_index_fails() {
        assert_eq!(
            verify_envelope(&envelope(&[0, 7]), &phase_a_set(), NET, &GEN, &accept_all()),
            Err(EnvelopeReject::UnknownSignerIndex { index: 7 })
        );
    }

    #[test]
    fn one_bad_signature_rejects_the_envelope() {
        // Signer 2's key starts with byte 12; poisoning it fails the ML-DSA
        // half. A mixture of valid and junk is malformed, not "enough".
        let poison_external = MarkerVerifier { poison: 12 };
        assert_eq!(
            verify_envelope(&envelope(&[0, 2]), &phase_a_set(), NET, &GEN, &poison_external),
            Err(EnvelopeReject::BadSignature { index: 2 })
        );
    }

    #[test]
    fn wrong_network_and_wrong_genesis_replays_fail() {
        assert_eq!(
            verify_envelope(&envelope(&[0, 2]), &phase_a_set(), NET + 1, &GEN, &accept_all()),
            Err(EnvelopeReject::WrongNetwork { got: NET, expected: NET + 1 })
        );
        assert_eq!(
            verify_envelope(&envelope(&[0, 2]), &phase_a_set(), NET, &[0xEE; 32], &accept_all()),
            Err(EnvelopeReject::WrongGenesisRoot)
        );
    }

    #[test]
    fn genesis_signer_set_id_is_reserved() {
        let mut env = envelope(&[0, 2]);
        env.checkpoint.signer_set_id = WS_GENESIS_SIGNER_SET_ID;
        assert_eq!(
            verify_envelope(&env, &phase_a_set(), NET, &GEN, &accept_all()),
            Err(EnvelopeReject::ReservedSignerSet)
        );
    }

    #[test]
    fn arrangement_review_warns_then_refuses() {
        let set = phase_a_set();
        // Past review, inside grace: verifies with the warning bit set.
        let mut env = envelope(&[0, 2]);
        env.checkpoint.epoch = set.review_deadline() + 1;
        let ok = verify_envelope(&env, &set, NET, &GEN, &accept_all()).expect("inside grace");
        assert!(ok.arrangement_past_review);
        // Past review + grace: refused — the dead-man's switch.
        env.checkpoint.epoch = set.hard_stop() + 1;
        assert_eq!(
            verify_envelope(&env, &set, NET, &GEN, &accept_all()),
            Err(EnvelopeReject::ArrangementExpired { hard_stop_epoch: set.hard_stop() })
        );
    }

    #[test]
    fn phase_b_needs_two_externals() {
        let set = SignerSet {
            id: 2,
            signers: vec![
                signer(20, false),
                signer(21, false),
                signer(22, true),
                signer(23, true),
                signer(24, true),
            ],
            threshold: WS_PHASE_B_THRESHOLD,
            min_external: WS_PHASE_B_MIN_EXTERNAL,
            adopted_epoch: 0,
        };
        assert!(set.matches_policy(WS_PHASE_B_THRESHOLD, WS_PHASE_B_SIGNERS, WS_PHASE_B_MIN_EXTERNAL));
        let mut env = envelope(&[0, 1, 2]);
        env.checkpoint.signer_set_id = 2;
        // Foundation + Postern + one external: only one external — fails.
        // The two internal keys cannot produce a quorum even with a third.
        assert_eq!(
            verify_envelope(&env, &set, NET, &GEN, &accept_all()),
            Err(EnvelopeReject::ExternalQuorumNotReached { got: 1, need: WS_PHASE_B_MIN_EXTERNAL })
        );
        let mut env = envelope(&[0, 2, 3]);
        env.checkpoint.signer_set_id = 2;
        assert!(verify_envelope(&env, &set, NET, &GEN, &accept_all()).is_ok());
    }

    #[test]
    fn fully_signed_envelope_travels_as_a_small_file() {
        // Phase B, all five signatures at the realistic hybrid size: the
        // artifact stays under the 25 KB the spec promises for distribution.
        let bytes = WS_CHECKPOINT_BYTES
            + 5 * (1 + MLDSA65_SIG_BYTES + 1280);
        assert!(bytes < 25 * 1024);
    }

    // -- storage rule, boot, reconciliation --------------------------------

    #[test]
    fn anti_rollback_ignores_older_and_flags_equivocal() {
        let newer = checkpoint();
        let mut older = checkpoint();
        older.epoch -= WS_PUBLICATION_INTERVAL_EPOCHS;

        assert_eq!(accept(None, &older), Acceptance::Store);
        assert_eq!(accept(Some(&older), &newer), Acceptance::Store);
        // A stolen old quorum signature must not refresh a node backward.
        assert_eq!(accept(Some(&newer), &older), Acceptance::Ignore);
        // Re-delivery of the identical artifact is a no-op.
        assert_eq!(accept(Some(&newer), &newer), Acceptance::Ignore);
        // Same epoch, different digest: loud, never silent.
        let mut equivocal = newer;
        equivocal.block_root = [0xEE; 32];
        assert_eq!(accept(Some(&newer), &equivocal), Acceptance::Conflict);
    }

    #[test]
    fn boot_decision_at_the_three_boundaries() {
        assert_eq!(boot_decision(false, 0), BootDecision::RequireCheckpoint);
        // An empty database is a fresh node regardless of any age estimate.
        assert_eq!(boot_decision(false, u64::MAX), BootDecision::RequireCheckpoint);

        assert_eq!(boot_decision(true, 0), BootDecision::Resume);
        assert_eq!(boot_decision(true, WS_FRESH_EPOCHS - 1), BootDecision::Resume);
        assert_eq!(boot_decision(true, WS_FRESH_EPOCHS), BootDecision::ResumeStaleWarn);
        assert_eq!(boot_decision(true, WS_PERIOD_EPOCHS - 1), BootDecision::ResumeStaleWarn);
        // At the period the node's own markers stop being a defense.
        assert_eq!(boot_decision(true, WS_PERIOD_EPOCHS), BootDecision::RefuseStale);
        assert_eq!(boot_decision(true, u64::MAX), BootDecision::RefuseStale);
    }

    #[test]
    fn reconcile_keeps_history_or_halts_for_the_operator() {
        let cp = checkpoint();
        let local = [0x55; 32];
        assert_eq!(reconcile(&cp, local, true), Reconciliation::ContinueForward);
        // Checkpoint exactly at the local head: trivially consistent.
        assert_eq!(reconcile(&cp, cp.block_root, false), Reconciliation::ContinueForward);
        // Divergent: never auto-wipe — evidence must survive.
        assert_eq!(
            reconcile(&cp, local, false),
            Reconciliation::HaltForOperator {
                local_finalized_root: local,
                checkpoint_root: cp.block_root
            }
        );
    }

    #[test]
    fn published_checkpoint_never_overrides_own_finality() {
        let cp = checkpoint();
        assert_eq!(cross_check(Some(cp.block_root), &cp), CrossCheck::Consistent);
        assert_eq!(cross_check(None, &cp), CrossCheck::AheadOfLocal);
        assert_eq!(
            cross_check(Some([0x55; 32]), &cp),
            CrossCheck::Conflict { local_root: [0x55; 32], published_root: cp.block_root }
        );
    }

    // -- genesis anchor and the finality floor -----------------------------

    #[test]
    fn genesis_anchor_is_the_first_trust_root() {
        let g = genesis_anchor(NET, GEN, [0x33; 32], [0x44; 32], 1_800_000_000);
        assert_eq!(g.epoch, 0);
        assert_eq!(g.block_root, GEN);
        assert_eq!(g.signer_set_id, WS_GENESIS_SIGNER_SET_ID);
        assert!(is_publication_epoch(g.epoch));

        // Anchoring hands finality its floor: justified and finalized by
        // definition, next epoch expected is 1.
        let st = anchor(&g);
        assert_eq!(st.finalized(), g.as_finality_checkpoint());
        assert_eq!(st.current_justified(), g.as_finality_checkpoint());
        assert_eq!(st.next_epoch(), 1);
    }

    #[test]
    fn anchoring_a_later_checkpoint_sets_the_floor_there() {
        let cp = checkpoint();
        let st = anchor(&cp);
        assert_eq!(st.finalized().epoch, cp.epoch);
        assert_eq!(st.finalized().root, cp.block_root);
        assert_eq!(st.next_epoch(), cp.epoch + 1);
    }

    #[test]
    fn wallclock_epoch_is_saturating_and_slot_derived() {
        let genesis = 1_800_000_000u64;
        let epoch_secs = SLOT_DURATION_SECS * SLOTS_PER_EPOCH;
        assert_eq!(wallclock_epoch(genesis, genesis), 0);
        assert_eq!(wallclock_epoch(genesis, genesis + epoch_secs - 1), 0);
        assert_eq!(wallclock_epoch(genesis, genesis + epoch_secs), 1);
        // A clock behind genesis reads epoch 0, not a wrapped huge number.
        assert_eq!(wallclock_epoch(genesis, genesis - 10), 0);
    }

    // -- helpers -----------------------------------------------------------

    fn record() -> ValidatorRecord {
        ValidatorRecord {
            pubkey: [7u8; HYBRID_PK_BYTES],
            amount_sat: crate::staking::MIN_DEPOSIT_SAT,
            activation_epoch: 0,
            exit_epoch: None,
            withdrawal_addr: [2u8; 32],
            withdrawn: false,
        }
    }
}
