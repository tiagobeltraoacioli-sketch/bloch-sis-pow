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
//! **THIS IS THE LIVE CHAIN'S CONSENSUS.** `crates/bloch-pos-node` — the
//! `bloch-pos` binary the Genesis-4 fleet runs — is a direct path-dependency
//! of this crate, and both are members of the root workspace. Genesis-4 has
//! been producing, attesting, justifying and finalizing blocks under these
//! rules since 21:31:19 UTC on 2026-08-13, when Genesis-3 (proof of work)
//! stopped permanently at height 39,918. There is no activation height and no
//! flag day pending: the rules here are in force from slot 0.
//!
//! **UNAUDITED by any third party.** Nothing in here has been through an
//! external security review. The tests in `tests/` and the in-module tests are
//! the only evidence.
//!
//! **The live security question is concentration, not consensus math.** All 64
//! Genesis-4 validators are operated by a single entity; 93.94% of the
//! carryover sits at one address ([`tokenomics_v4::LARGEST_CARRYOVER_ADDRESS_BLOCH`]),
//! and carried balances are stakeable, so if that balance stakes the Nakamoto
//! coefficient is 1. One operator can halt the chain and one holder can
//! outvote every other. [`genesis_cohort`] tapers a cap against exactly this,
//! and reports [`genesis_cohort::CapStatus::Deferred`] while there is not yet
//! enough independent stake for the rule to bind.
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
pub mod fee_market;
pub mod genesis_cohort;
pub mod finality;
pub mod forkchoice;
pub mod gossip;
pub mod header;
pub mod interfaces;
pub mod params;
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
