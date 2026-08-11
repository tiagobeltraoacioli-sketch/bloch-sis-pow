// SPDX-License-Identifier: MIT OR Apache-2.0

//! # bloch-pos-committee
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

pub mod attestation;
pub mod beacon;
pub mod committees;
pub mod delegation;
pub mod finality;
pub mod forkchoice;
pub mod interfaces;
pub mod params;
pub mod tokenomics_v4;
pub mod rewards;
pub mod sample;
pub mod staking;
pub mod state_root;
pub mod schedule;
pub mod slashing;

pub use attestation::{Attestation, AttestationData, RejectReason, SignatureVerifier};
pub use beacon::{mix_in, process_reveal, BeaconError, RandaoChain, RevealState};
pub use forkchoice::{BlockTree, LatestMessage, Store};
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
    build_state_tree, state_root, verify_inclusion, ConsensusState, EutxoEntry, InclusionProof,
    ParticipationRecord, RandaoMix, Smt,
};
pub use interfaces::{
    BlockHeaderV4, BlockId, FinalityGadget, ProposerDuties, RandomnessBeacon, SlashingRules,
    StakingLifecycle, StateCommitment, StateReader, StateTransition,
};
pub use finality::{EpochOutcome, EpochVotes, FinalityError};

// ── Names that exist in two modules — NOT re-exported flat ──────────────────
//
// Three names collided when the parallel workstreams were integrated, and each
// collision is a real design question, not a namespacing accident. Flattening
// either side would pick a winner silently, so callers must qualify:
//
//   `interfaces::Checkpoint`     vs `finality::Checkpoint`
//   `interfaces::FinalityState`  vs `finality::FinalityState`
//   `staking::ValidatorRecord`   vs `state_root::ValidatorRecord`
//
// The first two are the same concept declared twice: the PMO froze them as part
// of the `FinalityGadget` boundary while the gadget author wrote concrete ones.
// The third is genuinely two different records that happen to share a name —
// staking's is the lifecycle record (activation/exit epochs, withdrawal
// address), state_root's is what gets committed into the SMT. They may want
// different names rather than one merged type.
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
