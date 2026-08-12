// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Frozen consensus interfaces — the Phase-1 contract between workstreams
//!
//! > **PROSE PARTIALLY SUPERSEDED — 2026-08-11 (PMO ruling; signatures
//! > unaffected).** The trait and type signatures below remain frozen exactly
//! > as reviewed. The surrounding prose, however, was written against
//! > premises that changed AFTER the freeze:
//! >
//! > - **the sampled committee (128 per epoch + 8 per slot)** — replaced by
//! >   partitioning the active set (finding F1; see `committees.rs`). One
//! >   attestation now does both jobs: it carries its slot's fork-choice
//! >   weight AND accumulates toward the epoch's justification. Where prose
//! >   below says only "epoch committee" votes feed [`FinalityGadget`] or
//! >   that a "slot subcommittee" feeds fork choice only, read: every
//! >   attestation is an epoch-committee vote, and every attestation feeds
//! >   LMD-GHOST.
//! > - **the 100 B supply** — reverted to 21 B, the V2 nominal. The `u128`
//! >   arithmetic contract survives (the danger was always the products, not
//! >   the totals); the "54% of `u64::MAX`" premise does not.
//! > - **the taint machinery** — dissolved: the carryover crosses as one
//! >   undifferentiated set. [`StateRoots::taint_root`] is retained as a
//! >   reserved, all-zero slot (removing it would re-open the freeze);
//! >   `Tainted` variants are never produced.
//! > - **the hybrid PoW phase** — erased: Genesis-3 halts at height 80,000
//! >   and Genesis-4 launches from a snapshot.
//!
//! §9.2 of the migration design: *"Interfaces between the three [developers]
//! are frozen at the end of Phase 1 as Rust traits with no implementations;
//! every later phase codes against them."* This module is that freeze. Each
//! trait is one boundary between workstreams; each is documented with who
//! implements it, who consumes it, and which spec section governs it. The
//! companion prose is `docs/specs/BLOCH-POS-INTERFACES.md`.
//!
//! ## The purity contract — binding on every implementation
//!
//! Every method here is a **pure function of its explicit arguments**. `&self`
//! exists so implementations can be handed around as trait objects and may
//! carry only configuration fixed at genesis (chain id, genesis time, frozen
//! constants) — never a clock, a cache, a database handle, or anything mutable.
//! Everything a consensus rule needs from chain state arrives through a
//! [`StateReader`] obtained from the **parent block's committed state**, and
//! through nothing else.
//!
//! This is not a style preference. §5.5 of the design exists because
//! `expected_bits` was derived from node-local mutable state instead of from
//! ancestry, and nodes running identical binaries split consensus at retarget
//! heights on 2026-08-08. A trait method that could be satisfied by reading
//! local state would re-open that bug class at the interface level, where no
//! reviewer of any single implementation would see it. A4's standing checklist
//! item — "does this read local mutable state?" — applies to implementations
//! of every trait in this module, and it is a merge blocker.
//!
//! ## The arithmetic contract
//!
//! Every stake, balance, reward or penalty in these signatures is **`u128`
//! satoshis**. Under Tokenomics V4 the supply is 10^19 sat — 54% of
//! `u64::MAX` — so the sum of two large balances overflows `u64`, silently in
//! release builds, and a silently wrapped consensus value is a chain split
//! (`BLOCH-TOKENOMICS-V4.md` §8.1). Individual amounts would mostly fit; the
//! interface still carries `u128` end-to-end so that no implementation is ever
//! one refactor away from an accumulator in the wrong width. The compile-time
//! assertion pinning this reasoning lives in [`crate::tokenomics_v4`].
//!
//! ## Change control
//!
//! These traits are frozen. Changing a signature after Phase 1 means every
//! workstream re-reviews its call sites, so a change requires the two-reviewer
//! rule of §9.4 (one other DEV plus A4) **and** a PMO-recorded reason. Adding
//! a variant to a `#[non_exhaustive]` error enum is the one sanctioned cheap
//! extension point.

use crate::attestation::{Attestation, AttestationData};
use crate::sample::Validator;

// ─── Identity and checkpoint types ──────────────────────────────────────────

/// The one and only block identifier (§5.4):
/// `SHA3-256(DS_BLOCK ‖ canonical_serialize(header))`.
///
/// A newtype rather than a bare `[u8; 32]` on purpose. The historical
/// `pow_hash` / `block_hash` split — two hashes both usable as "the" block key
/// — caused the DAG-keying defect that stalled tip selection on the live
/// chain. Genesis-4 forbids the pattern at the type level: there is no second
/// identifier type, and the only legitimate producer of a `BlockId` is
/// [`StateCommitment::block_id`]. A2 owns the property test asserting no code
/// path derives one from anything else.
/// **Re-export, not a declaration.** This module used to declare its own
/// `pub struct BlockId(pub [u8; 32])` while `header.rs` declared an opaque one
/// with a single constructor. Two identity types in one consensus crate is the
/// very defect the paragraph above warns about, reproduced by the parallel
/// workstreams that wrote the two files — caught by `single_derivation_path`
/// at integration, 2026-08-11. There is now exactly one.
pub use crate::header::BlockId;

/// An (epoch, block) pair — the unit justification and finality operate on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: u64,
    /// Root of the epoch's first block, as attested.
    ///
    /// Raw bytes and not a [`BlockId`] on purpose: a checkpoint root arrives
    /// from an attestation on the wire, so it is a value to be *compared*
    /// against an id this node derived itself (`BlockId::of(...).as_bytes()`),
    /// never an identity to be minted from untrusted bytes. Typing it as
    /// `BlockId` would force a `[u8; 32] -> BlockId` conversion into existence
    /// and reopen exactly what the opaque type closes.
    pub root: [u8; 32],
}

/// The finality bookkeeping carried in committed state.
///
/// `previous_justified` is not an optimisation: Casper-style two-round
/// finality decides "finalized" by relating the *current* justification to the
/// one before it, and surround-vote slashing is judged against the same
/// history. Dropping it would make both rules unstatable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalityState {
    pub previous_justified: Checkpoint,
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
}

// ─── Header and envelope (§5.3) ─────────────────────────────────────────────

/// **Re-export, not a declaration.** The header was declared twice — here as
/// the frozen contract and in `header.rs` with the canonical 304-byte
/// serialisation. The two disagreed on field types (`BlockId` vs `[u8; 32]`),
/// so "the header" had no single encoding, which is the same hazard as having
/// two block ids. `header.rs` wins because identity is derived from its bytes.
pub use crate::header::BlockHeaderV4;


/// Header plus the proposer's signature — the signature lives here, in the
/// envelope, **not** in the header (§5.3): a 4.6 KB in-header signature would
/// ride along every header-sync and light-client path, so the signed object is
/// kept at 248 B and only full validation pays for the hybrid verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalEnvelope {
    pub header: BlockHeaderV4,
    /// Hybrid ML-DSA-65 ‖ Falcon-1024, ≈ 4,589 B, opaque here — this crate
    /// never links the PQ stack (same reasoning as
    /// [`crate::attestation::SignatureVerifier`]).
    pub proposer_sig: Vec<u8>,
}

// ─── Staking lifecycle types (§7) ───────────────────────────────────────────

/// A transparent-ledger output reference. Deposits may only spend transparent
/// outputs (§6.6.3), so this is the only shape of input the staking boundary
/// ever names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UtxoRef {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// One validator as the registry commits it. This is the record behind the
/// sampling-facing [`Validator`] view, which carries only index and effective
/// stake.
///
/// Epoch fields use `u64::MAX` as "not scheduled" rather than `Option` so the
/// record has one fixed-width committed encoding — an `Option` would put a
/// serialisation choice inside consensus state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRecord {
    pub index: u32,
    /// Suite-tagged hybrid public key, 3,745 B. One key serves identity,
    /// proposal and attestation — there is no second algorithm to split roles
    /// across (§6.2).
    pub pubkey: Vec<u8>,
    /// Bonded stake in satoshis. `u128` per the arithmetic contract.
    pub staked_sat: u128,
    /// Head of the validator's SHAKE-256 hash chain (§6.3).
    pub randao_commitment: [u8; 32],
    /// Where the stake returns on withdrawal. Opaque bytes: the address format
    /// belongs to the node's transaction layer, which this standalone crate
    /// deliberately does not depend on. Freezing a width here would be
    /// guessing; the node's format is authoritative (open point recorded in
    /// `BLOCH-POS-INTERFACES.md`).
    pub withdrawal_credentials: Vec<u8>,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    pub withdrawable_epoch: u64,
    pub slashed: bool,
}

/// The `DEPOSIT` transaction payload (§7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositTx {
    /// `u128` even though the spec sketch says `u64`: the arithmetic contract
    /// wins, and the rest of this crate (delegation, rewards) already carries
    /// amounts as `u128`.
    pub amount_sat: u128,
    /// Suite-tagged hybrid public key, 3,745 B.
    pub validator_pubkey: Vec<u8>,
    /// `c_0`, the top of the SHAKE-256 reveal chain (§6.3).
    pub randao_commitment: [u8; 32],
    /// Opaque — see [`ValidatorRecord::withdrawal_credentials`].
    pub withdrawal_credentials: Vec<u8>,
    /// Hybrid signature over [`StakingLifecycle::deposit_signing_root`]. Both
    /// halves must verify — possession of one lattice key must not vouch for
    /// the other.
    pub proof_of_possession: Vec<u8>,
    /// The transparent outputs being bonded. Listed here because eligibility
    /// (§4.1 taint, §6.6.3 transparency) is judged per input, not per amount.
    pub inputs: Vec<UtxoRef>,
}

/// The voluntary-exit message (§7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitTx {
    pub validator: u32,
    /// Epoch the exit is requested for. Signed, so a captured exit message
    /// cannot be replayed in a later epoch to force an unplanned exit.
    pub epoch: u64,
    /// Hybrid signature over [`StakingLifecycle::exit_signing_root`].
    pub signature: Vec<u8>,
}

// ─── Slashing types (§7.3) ──────────────────────────────────────────────────

/// The slashable offences. Closed enum on purpose: an offence class is a
/// consensus rule, and adding one is a hard fork, not an enum extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offence {
    /// Two distinct signed headers for the same slot by the same proposer.
    ProposerEquivocation,
    /// Two distinct attestations with the same target epoch (§7.3).
    DoubleVote,
    /// One attestation's source/target span strictly surrounds the other's.
    SurroundVote,
}

/// Evidence as it travels in a transaction: the two conflicting signed
/// messages, carried whole so every node re-verifies both signatures rather
/// than trusting the reporter.
///
/// This is the wire/transaction shape; the state machine that judges it is
/// [`crate::slashing::SlashingState`], reached through the transition's
/// `PosTransaction::SlashingEvidence` variant. (Deriving `PartialEq` was
/// added when the wiring landed — a derive, not a signature change, so it is
/// inside the freeze.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingEvidence {
    ProposerEquivocation {
        first: ProposalEnvelope,
        second: ProposalEnvelope,
    },
    AttestationOffence {
        first: Attestation,
        second: Attestation,
    },
}

// ─── Rejection reasons ──────────────────────────────────────────────────────
//
// Distinct variants for the same reason `attestation::RejectReason` has them:
// a bare "invalid" makes a divergence impossible to debug from logs. All are
// `#[non_exhaustive]` — adding a variant is the one cheap extension the
// change-control rule allows.

/// Why a block proposal was rejected before state transition.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalReject {
    /// Header's `proposer_index` is not the validator drawn for the slot.
    NotScheduledProposer,
    /// Hybrid signature failed (either half).
    BadSignature,
    /// `randao_reveal` is not the preimage of the proposer's current
    /// commitment.
    BadRandaoReveal,
    /// `version` is not the Genesis-4 block version.
    WrongVersion,
}

/// Why applying a block to the parent state failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    Proposal(ProposalReject),
    /// An attestation in the body failed validation; index into the body list.
    Attestation(u32),
    /// A transaction failed validation; index into the body list.
    Transaction(u32),
    /// Header `state_root` does not match the transition's computed root.
    StateRootMismatch,
    /// Header slot does not advance past the parent's.
    NonMonotonicSlot,
    /// Header's justified/finalized roots contradict the parent state's
    /// finality — a block may never un-finalize anything (§6.6.2 makes the
    /// same demand of the shielded pool via `coherence_root`).
    FinalityRegression,
    // ── Variants below were added by the transition/produce seam via the one
    // sanctioned cheap extension point (`#[non_exhaustive]`, see module docs).
    // Each is a distinct header-commitment failure that would otherwise hide
    // inside a neighbouring variant and be undebuggable from logs.
    /// Header `parent` is not the id of the block whose committed state was
    /// supplied for validation.
    ///
    /// `apply_block` is defined as parent-state x block -> child-state, so a
    /// block naming a different parent must be a deterministic reject:
    /// silently applying it to the wrong state is the block-identity failure
    /// shape (the `pow_hash`/`block_hash` DAG-keying defect) moved one layer up.
    WrongParent,
    /// Header `body_root` does not match the Merkle root over the body's
    /// transactions.
    BodyRootMismatch,
    /// Header `attestation_root` does not match the root over the attestation
    /// quorum the body carries.
    AttestationRootMismatch,
    /// Header `coherence_root` is not the §6.6.2 mirror binding of the
    /// parent's **committed** accumulator and nullifier-set roots
    /// (`derive::expected_coherence` — derived from parent state, which
    /// carries the pool's roots unchanged; the pool itself is never
    /// re-rooted, §6.6.1).
    CoherenceRootMismatch,
}

/// Why a deposit was rejected (§7.1, §4.1, §6.6.3).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositReject {
    BelowMinimum,
    /// Above the per-validator stake cap in force at inclusion.
    AboveValidatorCap,
    /// An input is in the taint set — premine, treasury, or a descendant.
    TaintedInput,
    /// An input is a shielded output. Stake must be attributable, so a bond
    /// always traces to transparent coins (§6.6.3).
    ShieldedInput,
    /// Proof of possession failed (either half of the hybrid).
    BadProofOfPossession,
    /// Key is not tagged `SUITE_MLDSA65_FALCON1024`.
    WrongSuite,
    /// The pubkey is already registered — a second deposit is a top-up path
    /// decision, not a fresh validator, and the interface refuses the
    /// ambiguity.
    PubkeyAlreadyRegistered,
}

/// Why a voluntary exit was rejected (§7.2).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReject {
    BadSignature,
    /// Validator is not active at the exit epoch.
    NotActive,
    /// An exit is already scheduled.
    AlreadyExiting,
    /// Slashed validators are ejected on the slashing path; they do not also
    /// get the voluntary path.
    Slashed,
}

/// Why slashing evidence was rejected (§7.3).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceReject {
    /// The two messages do not constitute any [`Offence`].
    NotSlashable,
    /// A signature on either message failed.
    BadSignature,
    /// The offender is already slashed — evidence is not double-countable.
    AlreadySlashed,
}

/// What the eligibility oracle says about one deposit input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositInputStatus {
    /// Transparent and untainted: may back a bond.
    Eligible,
    /// Transparent but in the taint set (§4.1).
    Tainted,
    /// A shielded output (§6.6.3).
    Shielded,
    /// Not found. Distinct from `Tainted` because "unknown" must fail closed
    /// for deposits but should not be logged or slashed as an offence.
    Unknown,
}

// ─── Injected capability traits ─────────────────────────────────────────────

/// Signature verification by raw public key, for messages from parties not yet
/// in the registry (deposits) or being judged against a committed key
/// (evidence). The registry-index flavour is
/// [`crate::attestation::SignatureVerifier`]; both exist so this crate never
/// links the PQ stack and the verifier (C FFI today, pure-Rust in-circuit
/// tomorrow — `spikes/prover-cost/`) stays a caller decision.
pub trait KeyVerifier {
    /// Verify `signature` over `signing_root` under the suite-tagged hybrid
    /// `pubkey`. Must verify **both** halves — AND, not OR (§6.2).
    fn verify(&self, pubkey: &[u8], signing_root: &[u8; 32], signature: &[u8]) -> bool;
}

/// The taint / transparency oracle (§4.1, §6.6.3) — DEV-3's taint tracking
/// behind one question.
///
/// Purity note: implementations answer from the taint-set state committed at
/// the parent block (its root is in [`StateRoots::taint_root`]), not from any
/// live index. Two nodes at the same parent must give byte-identical answers.
pub trait StakeEligibility {
    fn deposit_input_status(&self, input: &UtxoRef) -> DepositInputStatus;
}

/// Read access to one block's **committed** state — the only door consensus
/// rules may reach through for chain data (§5.5).
///
/// Implemented by DEV-1's state object; consumed by everything. The methods
/// are the closed list of what any consensus rule is allowed to need. If a
/// rule wants a value this trait does not expose, the value must first become
/// committed state (and appear under [`StateRoots`]) — that pressure is
/// intentional, and it is the §5.5 rule expressed as an API.
pub trait StateReader {
    /// Slot of the block whose post-state this is.
    fn slot(&self) -> u64;

    /// The committed state root — the value that must equal
    /// [`BlockHeaderV4::state_root`] of the block that produced this state.
    fn state_root(&self) -> [u8; 32];

    /// Active validator set for sampling: capped effective stakes, taint
    /// already zeroed (§4.1), exactly what [`crate::sample::sample`] takes.
    fn active_validators(&self) -> Vec<Validator>;

    /// Full record for one validator, or `None` if the index was never
    /// registered.
    fn validator_record(&self, index: u32) -> Option<ValidatorRecord>;

    /// Sum of active effective stake, in satoshis. `u128`: this is precisely
    /// the accumulator the arithmetic contract exists for.
    fn total_active_stake_sat(&self) -> u128;

    /// Accumulated beacon output as of this state.
    fn randao_mix(&self) -> [u8; 32];

    /// Beacon mix at an earlier epoch boundary. Committed state keeps the
    /// last 2 epochs (§5.5); older epochs return `None`.
    ///
    /// Two is exactly `committees::MIN_SEED_LOOKAHEAD_EPOCHS + 1`, and it is a
    /// floor, not a convenience: while epoch `N` is processed, duties for `N`
    /// need the mix at the close of `N − 2` and duties for `N + 1` need the
    /// close of `N − 1` (finding F6). Retention below that bound makes the
    /// look-ahead uncomputable; shortening it is a consensus change.
    fn randao_mix_at(&self, epoch: u64) -> Option<[u8; 32]>;

    /// Justification/finality bookkeeping as of this state.
    fn finality(&self) -> FinalityState;
}

// ─── Boundary 1: block production (proposer duties) ─────────────────────────

/// Who may propose, and what a valid proposal is.
///
/// Implemented by DEV-1 (using this crate's sampling); consumed by DEV-3
/// (gossip admission, RPC) and by [`SlashingRules`] (equivocation evidence
/// re-validates proposals). Spec: §5.3, §6.3, §6.4.
///
/// Sortition is **public** by deliberate choice — no standardised PQ VRF
/// exists, and hashing a non-unique ML-DSA or Falcon signature would hand the
/// proposer a grinding lever (§6.4). Every node can therefore compute the
/// schedule; the DoS consequences are an operational matter (sentry nodes),
/// not this interface's.
pub trait ProposerDuties {
    /// The validator drawn to propose at `slot`, or `None` when no validator
    /// is eligible (an empty young network — the caller decides whether an
    /// empty slot is acceptable, as with committee sampling).
    ///
    /// `beacon_mix` is the mix committed at the epoch boundary that scheduled
    /// this slot, read from the parent chain's [`StateReader::randao_mix_at`]
    /// — never from the proposing node's own view of "now".
    fn proposer(&self, beacon_mix: &[u8; 32], slot: u64, validators: &[Validator])
        -> Option<u32>;

    /// Domain-separated signing root the proposer signs:
    /// `SHA3-256(DS_PROPOSE ‖ canonical header)`. Distinct from the block id's
    /// `DS_BLOCK` domain so a signature can never be mistaken for an
    /// identifier or vice versa (see [`crate::params::DS_PROPOSE`]).
    fn proposal_signing_root(&self, header: &BlockHeaderV4) -> [u8; 32];

    /// Full proposal check: scheduled proposer, version, reveal, signature.
    ///
    /// `randao_commitment` is the proposer's current chain head as committed
    /// in the parent state. Signature verification comes last — it costs a
    /// 4.6 KB hybrid verify, and everything before it is a cheap rejection
    /// (the same DoS ordering [`crate::attestation::validate`] uses).
    fn validate_proposal(
        &self,
        envelope: &ProposalEnvelope,
        expected_proposer: u32,
        proposer_pubkey: &[u8],
        randao_commitment: &[u8; 32],
        keys: &dyn KeyVerifier,
    ) -> Result<(), ProposalReject>;
}

// ─── Boundary 2: state transition ───────────────────────────────────────────

/// The state transition function: parent state × block → child state.
///
/// Implemented by DEV-1; consumed by DEV-3 (sync, RPC) and by every test
/// harness A2/A3 build. Spec: §5.5.
///
/// The associated types are the two things this standalone crate deliberately
/// does not define: the concrete state object and the node's transaction
/// format. Everything else in the signature is nailed down.
pub trait StateTransition {
    /// The committed-state object. Bounded by [`StateReader`] so the output
    /// of one transition is, by construction, a legal input to the next —
    /// there is no other way to thread state between blocks.
    type State: StateReader;

    /// The node's transaction type. Opaque here; the eUTXO format is out of
    /// scope for the migration (§1.2) and out of reach for this crate.
    type Transaction;

    /// Apply one block. Pure: the child state is a function of `pre` and the
    /// block contents, and two nodes applying the same block to the same
    /// parent state must produce bit-identical `state_root`s. Failure returns
    /// the *first* error in validation order — error order is consensus-
    /// visible (it decides which reject a node reports), so it is part of the
    /// frozen contract, not an implementation detail.
    fn apply_block(
        &self,
        pre: &Self::State,
        envelope: &ProposalEnvelope,
        attestations: &[Attestation],
        transactions: &[Self::Transaction],
    ) -> Result<Self::State, TransitionError>;

    /// Epoch-boundary processing: reward distribution, activation/exit queue
    /// movement, finality bookkeeping roll-over, beacon history rotation.
    ///
    /// Split from [`Self::apply_block`] because it runs even when the boundary
    /// slot is empty — a skipped slot must not skip the epoch's accounting,
    /// or a withheld proposal becomes a lever over everyone's rewards.
    fn process_epoch(&self, pre: &Self::State) -> Result<Self::State, TransitionError>;
}

// ─── Boundary 3: randomness beacon (§6.3) ───────────────────────────────────

/// The hash-based commit-reveal beacon.
///
/// Implemented by DEV-2; consumed by DEV-1 (proposal validation mixes the
/// reveal) and by this crate's sampling (the mix seeds sortition).
///
/// Uniqueness comes from preimage binding, not from signatures — there is
/// exactly one valid reveal per commitment, which is the property no lattice
/// signature can offer (§6.4). The residual influence is withholding: one bit
/// per skipped slot, paid for with the forfeited proposer reward.
pub trait RandomnessBeacon {
    /// Does `reveal` open `commitment`, i.e. `SHAKE-256(reveal) ==
    /// commitment`?
    fn verify_reveal(&self, commitment: &[u8; 32], reveal: &[u8; 32]) -> bool;

    /// Fold a verified reveal into the accumulated mix:
    /// `SHA3-256(DS_RANDAO ‖ prev_mix ‖ reveal)`.
    fn mix(&self, prev_mix: &[u8; 32], reveal: &[u8; 32]) -> [u8; 32];

    /// Length of the commitment hash chain a registration buys
    /// (`RANDAO_CHAIN_LENGTH`, proposed 8,192). A constant behind a method so
    /// consumers cannot compile the number in and drift from the
    /// implementation.
    fn chain_length(&self) -> u64;

    /// Has the validator consumed its chain? Exhaustion is reachable in
    /// normal operation (§6.3), so it must be a checked state, not a panic;
    /// an exhausted validator proposes nothing until it re-commits.
    fn is_exhausted(&self, reveals_used: u64) -> bool;

    /// Signing root for the re-commit message that installs a fresh chain
    /// head. Fixed-width fields under `DS_RANDAO`; the input length differs
    /// from the mixing preimage, so the two uses cannot collide.
    fn recommit_signing_root(&self, validator: u32, new_commitment: &[u8; 32]) -> [u8; 32];
}

// ─── Boundary 4: justification and finality ─────────────────────────────────

/// The Casper-style two-round finality rule over epoch-boundary votes.
///
/// Implemented by DEV-1 on top of this crate's committee draw and
/// [`crate::forkchoice`]; consumed by DEV-3 (sync from finalized checkpoint,
/// RPC) and by the L2, whose anchor moves from PoW depth to finalized
/// checkpoints. Spec: §5.1, §6.5.2.
///
/// Only the **epoch committee's** votes count here. The per-slot subcommittee
/// exists solely to give LMD-GHOST weight between boundaries; letting its
/// eight votes touch justification would shrink the finality quorum from 128
/// signatures to whatever eight validators say.
pub trait FinalityGadget {
    /// The quorum test: does `stake_for` reach ≥ 2/3 of `total_active`?
    /// One definition, used everywhere — a rounding disagreement in the
    /// quorum boundary is a consensus split, so no caller reimplements this.
    fn is_supermajority(&self, stake_for_sat: u128, total_active_sat: u128) -> bool;

    /// Advance justification/finality with one epoch's tallied target vote.
    ///
    /// `stake_on_target` is the summed effective stake of epoch-committee
    /// members whose attestation named `target` (tallied by the caller from
    /// validated attestations — this method judges, it does not count).
    /// Returns the new bookkeeping; when the vote does not justify, the
    /// return equals `prev` rolled forward.
    fn process_epoch_votes(
        &self,
        prev: &FinalityState,
        source: Checkpoint,
        target: Checkpoint,
        stake_on_target_sat: u128,
        total_active_sat: u128,
    ) -> FinalityState;

    /// Per-epoch inactivity penalty for a non-participating validator once
    /// finality has stalled (§5.1: quadratic after 4 epochs). Exists so a
    /// stalled committee bleeds until the remaining live stake is a
    /// supermajority again — the recovery path from a dead validator set.
    /// Zero while finality is current.
    fn inactivity_penalty_sat(
        &self,
        epochs_since_finality: u64,
        effective_stake_sat: u128,
    ) -> u128;
}

// ─── Boundary 5: staking lifecycle (§7) ─────────────────────────────────────

/// Deposit, activation, exit, withdrawal — the validator lifecycle.
///
/// Implemented by DEV-3; consumed by DEV-1's transition (deposits and exits
/// arrive inside blocks) and by the wallet/RPC surface. Spec: §7.1–7.2, §4.1,
/// §6.6.3.
///
/// Delegation (warm-up budgets, the fixed-point stake cap) stays concrete in
/// [`crate::delegation`] — it is already implemented and tested, and a trait
/// wrapping an existing single implementation would be indirection without a
/// boundary.
pub trait StakingLifecycle {
    /// Signing root of the deposit's proof of possession:
    /// `SHA3-256(DS_DEPOSIT ‖ fields)` (§7.1). The PoP is what stops a
    /// deposit from registering someone *else's* public key — rejected keys
    /// still burn the depositor's own coins otherwise.
    fn deposit_signing_root(&self, tx: &DepositTx) -> [u8; 32];

    /// Full deposit check: bounds, suite tag, input eligibility, PoP.
    ///
    /// `max_stake_sat` is the per-validator cap **in force at the parent
    /// state** — the cap is 1% of a moving total (§4.1) resolved by
    /// [`crate::delegation::Registry::cap_sat`], so it arrives as an explicit
    /// input rather than being recomputed from hidden state.
    /// `existing` is the registry record already holding this pubkey, if any.
    fn validate_deposit(
        &self,
        tx: &DepositTx,
        max_stake_sat: u128,
        existing: Option<&ValidatorRecord>,
        eligibility: &dyn StakeEligibility,
        keys: &dyn KeyVerifier,
    ) -> Result<(), DepositReject>;

    /// Epoch at which a deposit accepted at `deposit_epoch` activates, given
    /// how many validators are queued ahead of it. Encodes both
    /// `ACTIVATION_DELAY_EPOCHS` and the `MAX_ACTIVATIONS_PER_EPOCH` throttle
    /// (§4.1.4) — the queue is what stops an actor from materialising a
    /// majority in one epoch.
    fn activation_epoch(&self, deposit_epoch: u64, queue_ahead: u64) -> u64;

    /// Signing root of a voluntary exit, under `DS_SLASH`'s sibling domain
    /// (see [`crate::params::DS_SLASH`]): `SHA3-256(DS_SLASH ‖ fields)`.
    fn exit_signing_root(&self, exit: &ExitTx) -> [u8; 32];

    /// Validate a voluntary exit against the committed record.
    fn validate_exit(
        &self,
        exit: &ExitTx,
        record: &ValidatorRecord,
        current_epoch: u64,
        keys: &dyn KeyVerifier,
    ) -> Result<(), ExitReject>;

    /// Epoch at which a validator requesting exit at `request_epoch` stops
    /// being assigned duties (`EXIT_DELAY_EPOCHS`).
    fn exit_epoch(&self, request_epoch: u64) -> u64;

    /// Epoch at which an exited validator's stake becomes spendable
    /// (`WITHDRAWAL_DELAY_EPOCHS` after exit). The long delay **is** the
    /// weak-subjectivity margin (§7.2): it must exceed the window in which an
    /// exited validator could sign a conflicting history at no cost, because
    /// its stake must still be reachable by slashing throughout that window.
    fn withdrawable_epoch(&self, exit_epoch: u64) -> u64;

    /// Satoshis spendable to the withdrawal credentials at `current_epoch`:
    /// zero before [`Self::withdrawable_epoch`], the bonded stake net of
    /// slashing after it.
    fn withdrawable_sat(&self, record: &ValidatorRecord, current_epoch: u64) -> u128;
}

// ─── Boundary 6: slashing (§7.3) ────────────────────────────────────────────

/// Offence classification, evidence validation, and penalty arithmetic.
///
/// Implemented by DEV-3; consumed by DEV-1's transition (evidence arrives in
/// blocks) and by A4's adversarial review, which treats this trait as the
/// complete statement of what is slashable.
///
/// Classification is separated from evidence validation on purpose: the pure
/// predicates over [`AttestationData`] (already on the struct —
/// `surrounds`, `is_double_vote`) answer "would this pair be an offence?",
/// while [`Self::validate_evidence`] answers "is this transaction proof of
/// it?" — the second requires both signatures to verify, or forged evidence
/// could eject an honest validator.
pub trait SlashingRules {
    /// Classify a pair of attestations, `None` if the pair is innocent.
    fn classify_attestations(&self, a: &AttestationData, b: &AttestationData)
        -> Option<Offence>;

    /// Classify a pair of headers as proposer equivocation: same slot, same
    /// proposer, different block id. `None` otherwise (including the
    /// identical-header case — republishing your own block is not an
    /// offence).
    fn classify_proposals(&self, a: &BlockHeaderV4, b: &BlockHeaderV4) -> Option<Offence>;

    /// Validate an evidence transaction end-to-end: both messages signed by
    /// `offender`'s committed key, pair actually slashable, offender not
    /// already slashed. Returns the offence being punished.
    fn validate_evidence(
        &self,
        evidence: &SlashingEvidence,
        offender: &ValidatorRecord,
        keys: &dyn KeyVerifier,
    ) -> Result<Offence, EvidenceReject>;

    /// Penalty in satoshis. Takes the correlation context (§7.3): stake
    /// slashed in the same window scales the penalty up, because without
    /// amplification an entity running a thousand validators is punished no
    /// more per coin than one unlucky solo operator — and correlated failure
    /// is exactly the signature of an attack.
    fn penalty_sat(
        &self,
        offence: Offence,
        offender_stake_sat: u128,
        correlated_slashed_sat: u128,
        total_active_sat: u128,
    ) -> u128;

    /// Whistleblower reward paid to the including proposer, as a function of
    /// the penalty (§7.3: 1/32). A method, not a constant, so the split can
    /// only be defined in one place.
    fn whistleblower_reward_sat(&self, penalty_sat: u128) -> u128;
}

// ─── Boundary 7: state commitment (§5.4, §5.5) ──────────────────────────────

/// Every root in [`StateRoots`] is the commitment to one component the §5.5
/// rule requires to be committed. The list is closed: a consensus rule that
/// needs a value not represented here must first add its component — visibly,
/// in a spec change — rather than reading it from anywhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRoots {
    /// eUTXO set.
    pub utxo_root: [u8; 32],
    /// Validator registry ([`ValidatorRecord`]s).
    pub registry_root: [u8; 32],
    /// Current + previous epoch attestation participation.
    pub participation_root: [u8; 32],
    /// Beacon mix history, last 2 epochs.
    pub randao_history_root: [u8; 32],
    /// The §4.1 taint set.
    pub taint_root: [u8; 32],
    /// Coherence SHAKE-256 accumulator root — **carried, never recomputed**:
    /// the accumulator is C1-frozen and incremental, and resetting or
    /// re-rooting it at the transition would force re-shielding and
    /// retroactively de-anonymise the pool (§6.6.1).
    pub coherence_accumulator_root: [u8; 32],
    /// Coherence nullifier-set root. Monotone forever, same continuity rule.
    pub coherence_nullifier_root: [u8; 32],
}

/// The hashing boundary: block identity, body root, attestation root, state
/// root. Implemented by DEV-2 (owner of §6.1 domain separation); consumed by
/// everyone — these four functions are the only place consensus bytes become
/// digests.
///
/// A1's KATs pin every method here; no output of these functions may change
/// without a new vector file, because each one *is* a consensus constant in
/// function form.
pub trait StateCommitment {
    /// The block identifier: `SHA3-256(DS_BLOCK ‖ canonical header)` (§5.4).
    /// The single constructor of [`BlockId`] in spirit — A2's property test
    /// holds every other derivation to be a defect.
    fn block_id(&self, header: &BlockHeaderV4) -> BlockId;

    /// Merkle root over the block's transaction ids under `DS_BODY`.
    fn body_root(&self, tx_ids: &[[u8; 32]]) -> [u8; 32];

    /// Root over the attestation quorum carried in the body — what
    /// [`BlockHeaderV4::attestation_root`] must equal. Attestations are a
    /// separate tree from transactions so a finalized epoch's signatures can
    /// be pruned (§6.5.1) without disturbing the transaction commitment.
    fn attestation_root(&self, attestations: &[Attestation]) -> [u8; 32];

    /// The committed state root over all components, under `DS_STATE` —
    /// what [`BlockHeaderV4::state_root`] must equal.
    fn state_root(&self, roots: &StateRoots) -> [u8; 32];
}
