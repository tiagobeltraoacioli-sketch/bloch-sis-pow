// SPDX-License-Identifier: AGPL-3.0-or-later

//! # bloch-pos-committee
//!
//! > **PROSE PARTIALLY SUPERSEDED — 2026-08-11 (PMO ruling; APIs unaffected).**
//! > The description below was written against the **sampled** committee
//! > design (128 per epoch + 8 per slot), which finding F1 replaced with a
//! > **partition** of the active set — see `committees.rs`, which is the
//! > current design and its own rationale. Under the partition, every active
//! > validator serves in exactly one slot committee per epoch, and one
//! > attestation does both jobs: its slot's fork-choice weight and its
//! > epoch's justification vote. The sampled draw ([`slot_subcommittee`],
//! > [`epoch_committee`], `sample::*`) remains in-tree as the record of the
//! > analysis and for the sortition machinery it shares with the proposer
//! > draw; it is not the committee mechanism the node composes.
//!
//! The committee layer of the Proof-of-Stake migration design
//! (`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md`, §6.5.2):
//!
//! - a **per-slot subcommittee** (8 validators) whose only job is to give
//!   LMD-GHOST its fork-choice weight between epoch boundaries;
//! - an **epoch committee** (128 validators) that votes once per epoch for
//!   justification and finality.
//!
//! ## Why the split exists
//!
//! The hybrid ML-DSA-65 ‖ Falcon-1024 signature is ≈ 4,589 B and costs a
//! measured 7,274,849 RV32IM instructions to verify in-circuit
//! (`spikes/prover-cost/RESULTS.md`). Having a full committee attest every slot
//! — the Ethereum shape — would cost 308.7 GB of signatures per year and
//! 15.5 M proving cycles per second. Moving the full vote to the epoch boundary
//! cuts both by 32×, but epoch-only voting leaves nothing weighting the fork
//! choice *inside* an epoch, which makes short reorgs cheap. The small per-slot
//! sample buys that weight back for 1/8 the per-slot cost.
//!
//! ## Status
//!
//! **UNAUDITED. Not wired into the node.** This crate is not a member of the
//! node workspace and is not a path-dependency of `bloch`, so the node's build
//! and validation path are untouched — the same posture
//! `crates/coherence-prover` takes. Activation, when it comes, is a
//! height-gated flag day like `STATE_ROOT_ACTIVATION_HEIGHT`.
//!
//! ## The rule this crate is written to obey
//!
//! Every consensus-relevant value must be derivable from the parent block's
//! committed state, never from node-local mutable state (§5.5 of the design —
//! the rule that exists because `expected_bits` was read from mutable local
//! state and split consensus on 2026-08-08). Accordingly, [`sample::sample`]
//! takes the beacon mix, the index, and the validator set as arguments; there
//! is no cached set, no clock, and no interior mutability anywhere in the
//! sampling or fork-choice path.

// ────────────────────────────────────────────────────────────────────────────
// Consensus invariants that survive `--release`
// ────────────────────────────────────────────────────────────────────────────

/// An internal consensus invariant, checked in **every** profile.
///
/// # Why this is not a `debug_assert!`
///
/// The workspace `[profile.release]` sets `overflow-checks = true` and does
/// **not** set `debug-assertions`, so it defaults to `false`: every
/// `debug_assert!` in this crate is compiled out of the binary mainnet runs.
/// The roster-split defect of 2026-08-21 had exactly one guard — a
/// `debug_assert_eq!` in `transition::close_epoch` — and that guard was not in
/// the binary. It found nothing, because it was not there.
///
/// # Why a panic is the right outcome
///
/// A panic in the consensus path **halts this node** instead of letting it
/// diverge silently. On a coordinated 64-validator fleet a halted node is
/// diagnosable in minutes and recoverable by restart; a diverged node poisons
/// finality for everyone and is precisely what produced the defect this macro
/// was written for. Loud and stopped beats quiet and wrong.
///
/// # The rule for using it
///
/// **Only for conditions that can fire on an internal code bug and on nothing
/// else** — both sides derived from already-validated committed state, never
/// from attacker-supplied input. A `consensus_invariant!` reachable from
/// untrusted input is a remotely triggerable halt, i.e. a DoS. Every call site
/// must state, in a comment, why its condition is internal. If you cannot
/// write that comment, the check belongs in the block-validation path
/// returning `Err`, not here.
///
/// Deliberately a dedicated macro rather than `assert!` so the checks are
/// greppable (`rg consensus_invariant`) and their intent is explicit, and
/// rather than `debug-assertions = true` on the whole release profile, which
/// would turn on every `debug_assert!` in every dependency, change
/// performance, and give a blast radius nobody has measured.
macro_rules! consensus_invariant {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            panic!(
                "CONSENSUS INVARIANT VIOLATED (this node is halting rather than diverging): {}",
                format_args!($($arg)+)
            );
        }
    };
}
pub(crate) use consensus_invariant;

pub mod attestation;
pub mod beacon;
pub mod committees;
pub mod delegation;
pub mod fee_market;
pub mod genesis_cohort;
pub mod finality;
pub mod forkchoice;
pub mod gossip;
pub mod header;
pub mod interfaces;
pub mod params;
// The integrator-facing consensus-parameter change schedule: every epoch
// gate in this crate as data, derived from the constants themselves, with a
// tripwire test that fails the build if a new gate is added without a feed
// entry. Served over RPC as `getconsensusschedule` by `bloch-pos-node`.
pub mod params_feed;
// Instrumentation only, and compiled out unless `perf-timing` is on — see
// the module docs. No consensus rule reads it.
pub mod perf;
// The relaunch proof harness (scenarios 1-4 + their mutations). Test-only:
// the module carries a mutation switch that flips committee membership back
// to the pre-fix behaviour, and that switch must not be able to exist in a
// shipped binary. Entry point: `scripts/prova-relanca.sh`.
#[cfg(test)]
mod prova;
pub mod produce;
pub mod tokenomics_v4;
pub mod rewards;
pub mod sample;
pub mod staking;
pub mod state_root;
pub mod schedule;
pub mod slashing;
pub mod derive;
pub mod transition;
pub mod ws;

pub use attestation::{Attestation, AttestationData, RejectReason, SignatureVerifier};
pub use beacon::{mix_in, process_reveal, BeaconError, RandaoChain, RevealState};
pub use forkchoice::{BlockTree, LatestMessage, Store};
pub use gossip::{
    AttestationPool, BlockLookup, CommitteeLookup, GossipDecision, IgnoreReason,
    ATTESTATION_WINDOW_SLOTS, MAX_EQUIVOCATIONS_PER_DUTY, MAX_PENDING_ATTESTATIONS,
};
pub use params::{COMMITTEE_SIZE, RANDAO_CHAIN_LENGTH, SLOTS_PER_EPOCH, SLOT_SUBCOMMITTEE_SIZE};
pub use sample::{is_selected, sample, Role, Validator};
pub use schedule::{epoch_schedule, proposer, EpochSchedule};
pub use slashing::{
    EvidenceError, SlashableOffense, SlashingEvidence, SlashingOutcome, SlashingState,
};
pub use staking::{
    resolve_activations, validate_deposit, validate_exit, validate_withdrawal, DepositInput,
    DepositReject, DepositTx, ExitReject, ExitTx, HybridKeyVerifier, QueuedDeposit, WithdrawReject,
};
pub use state_root::{
    build_state_tree, state_root, verify_inclusion, BaseFeeRecord, CheckpointRecord,
    ConsensusState, DelegationRecord, DelegatorFeeRecord, DepositQueueRecord, EutxoEntry,
    FcEquivocatorRecord, FcMessageRecord, FinalityRecord, InclusionProof, LeakRecord,
    ParticipationRecord, PendingFeeRecord, PendingVoteRecord, RandaoMix, Smt,
};
pub use header::{BlockEnvelope, BlockHeaderV4, BlockId, Body, DecodeError, VERSION_G4};
pub use interfaces::{
    FinalityGadget, ProposerDuties, RandomnessBeacon, SlashingRules, StakingLifecycle,
    StateCommitment, StateReader, StateTransition,
};
pub use fee_market::{
    charge, distribute_producer_fees, fee_parts_sat, intrinsic_gas, next_base_fee,
    split_delegator_fees, BlockUsage, TxCharge, TxClass, BLOCK_GAS_LIMIT, MAX_BLOCK_TX_BYTES,
    MIN_BASE_FEE_MILLISAT_PER_GAS,
};
pub use finality::{EpochOutcome, EpochVotes, FinalityError};
pub use produce::{produce, ProduceError, ProducerRandao, ProposerSigner};
// `validate_block` used to be re-exported here. It was a second, uncalled
// block validator; the node runs `transition::Transition::apply_block`, and
// two validation stacks with divergent error orders is the condition that
// produced this week's defects. Deleted 2026-08-12 — the comparison of the two
// checklists is in `derive.rs` where the function stood. The derivations it
// composed are still `pub` in `derive` and still shared with `produce`.
pub use derive::{ChainState, ParentState, RandaoRejection};
pub use transition::{CommittedState, GenesisValidator, PosTransaction, Transition};
pub use ws::{
    accept, anchor, boot_decision, cross_check, genesis_anchor, reconcile, verify_envelope,
    Acceptance, BootDecision, CheckpointEnvelope, CrossCheck, EnvelopeOk, EnvelopeReject,
    Reconciliation, Signer, SignerSet, WeakSubjectivityCheckpoint, WS_FRESH_EPOCHS,
    WS_PERIOD_EPOCHS, WS_PUBLICATION_INTERVAL_EPOCHS,
};

// ── Names that exist in two modules — NOT re-exported flat ──────────────────
//
// Three names collided when the parallel workstreams were integrated, and each
// collision is a real design question, not a namespacing accident. Flattening
// either side would pick a winner silently, so callers must qualify:
//
//   `interfaces::Checkpoint`       vs `finality::Checkpoint`
//   `interfaces::FinalityState`    vs `finality::FinalityState`
//   `staking::ValidatorRecord`     vs `state_root::ValidatorRecord`
//   `interfaces::SlashingEvidence` vs `slashing::SlashingEvidence`
//
// The fourth pair is deliberate layering, not drift: `interfaces::` is the
// frozen wire/transaction enum (header pair OR attestation pair — what rides
// in `PosTransaction::SlashingEvidence` and what every node re-verifies), and
// `slashing::` is the attestation-pair struct the state machine and gossip
// capture path use. The single conversion between them is the `From` impl in
// slashing.rs; the flat re-export carries `slashing::`'s because gossip
// consumers see that one.
//
// (`BlockId` and `BlockHeaderV4` were on this list too. They are not any more:
// two block-identity types in one consensus crate is the `pow_hash` /
// `block_hash` defect rebuilt from scratch, so `interfaces` now re-exports
// `header`'s rather than declaring twins. Deciding that was not optional.)
//
// The first two are the same concept declared twice: the PMO froze them as part
// of the `FinalityGadget` boundary while the gadget author wrote concrete ones.
// The third is genuinely two different records that happen to share a name —
// staking's is the lifecycle record (activation/exit epochs, withdrawal
// address), state_root's is what gets committed into the SMT. They may want
// different names rather than one merged type.
//
// The last two are frozen-contract vs concrete again, with one deliberate
// asymmetry: the *concrete* `header::` pair is what the flat re-export carries.
// `interfaces::BlockId` is a transparent `pub [u8; 32]` tuple — anyone could
// mint one from raw bytes, which is exactly the second-derivation-path defect
// §5.4 forbids — while `header::BlockId` is opaque with `BlockId::of` as its
// single constructor, and A2's source-scan property test enforces that.
// Exporting the permissive type flat would hand every downstream caller the
// forgeable one by default. The frozen trait signatures still name their own
// `interfaces::` types, qualified.
//
// Resolving these is an integration decision, deliberately left visible.

/// Draw the per-slot fork-choice subcommittee.
pub fn slot_subcommittee(beacon_mix: &[u8; 32], slot: u64, validators: &[Validator]) -> Vec<u32> {
    sample(beacon_mix, slot, Role::SlotSubcommittee, validators, SLOT_SUBCOMMITTEE_SIZE)
}

/// Draw the epoch finality committee.
pub fn epoch_committee(beacon_mix: &[u8; 32], epoch: u64, validators: &[Validator]) -> Vec<u32> {
    sample(beacon_mix, epoch, Role::EpochCommittee, validators, COMMITTEE_SIZE)
}

/// Epoch containing `slot`.
pub const fn epoch_of(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

/// Is `slot` the last slot of its epoch — the one carrying the full committee's
/// finality vote?
pub const fn is_epoch_boundary(slot: u64) -> bool {
    (slot + 1) % SLOTS_PER_EPOCH == 0
}
