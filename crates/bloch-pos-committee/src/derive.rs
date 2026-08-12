// SPDX-License-Identifier: AGPL-3.0-or-later

//! The **shared derivation functions** producer and validator must both use.
//!
//! ## The one rule that shapes this file
//!
//! Every `expected` value a validator checks a header field against is
//! computed by a `pub` function in this module, and [`crate::produce`] stamps
//! the header by calling **those same functions**. There is deliberately no
//! value that the producer derives one way and the validator re-derives
//! another: producer/validator divergence *inside a single node* is exactly
//! what stopped this mainnet for 50 minutes at h28080 — the producer stamped a
//! value, the same binary's validation path derived a different one, and the
//! node rejected its own blocks. A reimplementation "that does the same thing"
//! is the defect; sharing the function is the fix. (Same failure family as the
//! 2026-08-08 `expected_bits` split, §5.5 of the migration design.)
//!
//! ## What this seam covers — derivations only, since 2026-08-12
//!
//! This module used to carry a `validate_block` as well: a second, complete,
//! uncalled block validator with its own frozen error order. It is gone, and
//! the comparison that justified deleting it is written out where it stood
//! (search "deleted 2026-08-12"). Validation happens in exactly one place now,
//! [`crate::transition::Transition::apply_block`], which is the seam the node
//! binds.
//!
//! What remains here is the set of `pub` **derivation** functions: the seed,
//! the active set, the proposer draw, the RANDAO fold, the finality
//! carry-over, the Coherence binding, the two body Merkle roots, the
//! attestation-inclusion predicate and the post-state root. Those are shared
//! on purpose — [`crate::produce`] stamps a header with them and `transition`
//! checks against them. Transactions are opaque bytes to this crate (§1.2);
//! they are committed by `body_root` and carried through the state root
//! untouched.
//!
//! ## Purity
//!
//! Everything below is a pure function of a [`ParentState`] — the parent
//! block's header and committed components — and the block being judged. No
//! clocks, no caches, no interior mutability (§5.5).

use crate::attestation::{validate as validate_attestation, Attestation, SignatureVerifier};
use crate::beacon::{process_reveal, BeaconError, RevealState};
use crate::header::BlockHeaderV4;
use crate::params::DS_BODY;
use crate::sample::Validator;
use crate::schedule;
use crate::state_root::{
    ConsensusState, DelegationRecord, DepositQueueRecord, EutxoEntry, EvmCommitment, FcEquivocatorRecord, FcMessageRecord, FinalityRecord, ParticipationRecord, PendingFeeRecord, PendingVoteRecord, RandaoMix, ValidatorRecord, state_root,
};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

// ────────────────────────────────────────────────────────────────────────────
// Committed state as this seam models it
// ────────────────────────────────────────────────────────────────────────────

/// The committed consensus-state components of one block, owned.
///
/// This is the owned mirror of [`crate::state_root::ConsensusState`] (which
/// borrows), so a parent state can be held, cloned, and turned into a child
/// state by [`post_chain_state`]. The eUTXO set and the registry pass through
/// this seam unchanged — updating them is transaction execution and lifecycle
/// processing, DEV-1's transition — but they are *carried* here because the
/// state root commits all components, and a root computed over a subset would
/// not be the root the header must carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainState {
    /// The eUTXO set (carried through this seam unchanged).
    pub eutxos: Vec<EutxoEntry>,
    /// The validator registry as committed (the SMT flavour of the record).
    pub registry: Vec<ValidatorRecord>,
    /// Attestation participation, current epoch.
    pub current_participation: Vec<ParticipationRecord>,
    /// Attestation participation, previous epoch.
    pub previous_participation: Vec<ParticipationRecord>,
    /// Beacon mix history: the accumulated mix as of the last processed block
    /// of each of the last two epochs (§5.5 keeps exactly 2).
    pub randao_mixes: Vec<RandaoMix>,
    /// Justification/finality bookkeeping (§5.5, 2026-08-11 extension).
    /// Carried through this seam unchanged — advancing it is epoch
    /// processing, the transition's job — but carried, because the state root
    /// commits all components and a root over a subset is not the root the
    /// header must carry.
    pub finality: FinalityRecord,
    /// Epoch-boundary votes pending the finality tally. Carried unchanged;
    /// accumulating them is the transition's job.
    pub pending_votes: Vec<PendingVoteRecord>,
    /// LMD-GHOST latest messages. Carried unchanged.
    pub fc_messages: Vec<FcMessageRecord>,
    /// Fork-choice equivocator bar. Carried unchanged.
    pub fc_equivocators: Vec<FcEquivocatorRecord>,
    /// The permanent deposit queue. Carried unchanged (deposits are
    /// transactions, and transactions are opaque at this seam).
    pub deposit_queue: Vec<DepositQueueRecord>,
    /// The permanent delegation history. Carried unchanged, same reason.
    pub delegations: Vec<DelegationRecord>,
    /// Fee rewards pending the epoch boundary. Carried unchanged, same
    /// reason.
    pub pending_fees: Vec<PendingFeeRecord>,
    /// Taint-set root (§4.1), carried.
    pub taint_root: [u8; 32],
    /// Coherence accumulator root (§6.6.2), carried — never recomputed.
    pub coherence_accumulator_root: [u8; 32],
    /// Coherence nullifier-set root (§6.6.2), carried.
    pub coherence_nullifier_root: [u8; 32],
    /// L1 EVM execution commitment (`BLOCH-L1-EVM-STATE-MODEL.md`), carried —
    /// updating it is EVM execution, which happens in the node's transition,
    /// not in this seam.
    pub evm: EvmCommitment,
    /// Cumulative issued supply (`TAG_ISSUED_SUPPLY`, 2026-08-12). Carried
    /// unchanged: issuance happens at epoch boundaries, which are the
    /// transition's job, never this seam's.
    pub issued_sat: u128,
    /// Slashing bookkeeping (§7.3), carried through this seam unchanged —
    /// evidence is executed by the transition, never here.
    pub applied_evidence: Vec<crate::state_root::AppliedEvidenceRecord>,
    pub slash_window: Vec<crate::state_root::SlashWindowRecord>,
    pub delegator_slash_losses: Vec<crate::state_root::DelegatorLossRecord>,
    /// L1 fee-market leaf (2026-08-12), carried unchanged: charging
    /// transactions and moving the price are transaction execution, which this
    /// seam does not do — but the leaf is carried, because the state root
    /// commits all components and a root over a subset is not the root the
    /// header must carry.
    pub base_fee: crate::state_root::BaseFeeRecord,
    /// Delegator fee-reward ledger, carried unchanged: it is filled at the
    /// epoch boundary, which is the transition's job.
    pub delegator_fee_rewards: Vec<crate::state_root::DelegatorFeeRecord>,
}

impl ChainState {
    /// The committed state root over all components — the value
    /// `BlockHeaderV4::state_root` must equal. Delegates to the one SMT
    /// implementation in [`crate::state_root`]; there is no second tree.
    pub fn root(&self) -> [u8; 32] {
        state_root(&ConsensusState {
            eutxos: &self.eutxos,
            validators: &self.registry,
            current_participation: &self.current_participation,
            previous_participation: &self.previous_participation,
            randao_mixes: &self.randao_mixes,
            finality: &self.finality,
            pending_votes: &self.pending_votes,
            fc_messages: &self.fc_messages,
            fc_equivocators: &self.fc_equivocators,
            deposit_queue: &self.deposit_queue,
            delegations: &self.delegations,
            pending_fees: &self.pending_fees,
            applied_evidence: &self.applied_evidence,
            slash_window: &self.slash_window,
            delegator_slash_losses: &self.delegator_slash_losses,
            base_fee: self.base_fee,
            delegator_fee_rewards: &self.delegator_fee_rewards,
            taint_root: self.taint_root,
            coherence_accumulator_root: self.coherence_accumulator_root,
            coherence_nullifier_root: self.coherence_nullifier_root,
            evm: self.evm,
            issued_sat: self.issued_sat,
        })
    }
}

/// Everything block production and block validation may know: the parent
/// block's header and the state committed at it. Nothing else exists as far as
/// this module is concerned — no clock, no mempool view, no node-local state
/// (§5.5). Producer and validator are handed the *same* `ParentState`, which
/// is what makes "derive it the same way" checkable rather than aspirational.
pub struct ParentState<'a> {
    /// The parent block's header. Supplies the parent id, the parent slot,
    /// the accumulated beacon mix, and the finality/coherence roots to carry.
    pub header: &'a BlockHeaderV4,
    /// The consensus-state components committed at the parent.
    pub chain: &'a ChainState,
    /// Per-validator committed RANDAO chain heads, sorted by validator index.
    ///
    /// The registry record grew its `randao_commitment`/`reveals_used`
    /// columns on 2026-08-11 and the transition commits them into the SMT.
    /// This seam still reads chain heads from this side list and carries the
    /// registry's columns *unchanged* through [`post_chain_state`] — meaning
    /// its root and the transition's root for the same block differ until the
    /// seam is folded into the transition (the pre-existing integration step,
    /// flagged in the module docs, not widened here). Each stack remains
    /// internally consistent: its producer and its validator use the same
    /// derivation.
    pub reveal_states: &'a [(u32, RevealState)],
}

impl ParentState<'_> {
    /// Committed RANDAO chain head for one validator.
    pub fn reveal_state_of(&self, validator: u32) -> Option<&RevealState> {
        self.reveal_states
            .binary_search_by_key(&validator, |(i, _)| *i)
            .ok()
            .map(|at| &self.reveal_states[at].1)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Shared derivations — the producer stamps what these return, the validator
// checks against what these return. One definition each.
// ────────────────────────────────────────────────────────────────────────────

/// The active validator set at `epoch`, in sampling form.
///
/// One definition of "active": activated at or before `epoch`, not yet exited,
/// not slashed. The producer choosing its schedule and the validator checking
/// it must agree on this set or they disagree on everything downstream.
pub fn active_validators(registry: &[ValidatorRecord], epoch: u64) -> Vec<Validator> {
    registry
        .iter()
        .filter(|v| v.activation_epoch <= epoch && epoch < v.exit_epoch && !v.slashed)
        .map(|v| Validator { index: v.index, effective_stake: v.stake })
        .collect()
}

/// The beacon mix that seeds sortition for `slot`'s epoch: the mix as of the
/// close of the *previous* epoch, read from the parent's committed history —
/// never from anyone's live accumulator (§6.3: the schedule of epoch E is
/// fixed when E-1 closes, which is what bounds the grinding window).
///
/// Epoch 0 is seeded by the zero mix — a genesis constant, the same
/// convention the beacon's own tests use for "no reveals yet". `None` means
/// the parent's committed history does not cover the required epoch, in which
/// case no schedule exists and no block can be validly produced or accepted.
pub fn sortition_seed(parent: &ParentState<'_>, slot: u64) -> Option<[u8; 32]> {
    let epoch = crate::epoch_of(slot);
    if epoch == 0 {
        return Some([0u8; 32]);
    }
    parent.chain.randao_mixes.iter().find(|m| m.epoch == epoch - 1).map(|m| m.mix)
}

/// The validator scheduled to propose at `slot`, per the parent's committed
/// state. Composes [`sortition_seed`], [`active_validators`] and the one
/// proposer draw in [`crate::schedule::proposer`] — this is a composition,
/// not a reimplementation, so it *cannot* disagree with the schedule module.
pub fn scheduled_proposer(parent: &ParentState<'_>, slot: u64) -> Option<u32> {
    let seed = sortition_seed(parent, slot)?;
    let active = active_validators(&parent.chain.registry, crate::epoch_of(slot));
    schedule::proposer(&seed, slot, &active)
}

/// Why a reveal cannot advance the beacon from this parent state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandaoRejection {
    /// The proposer has no committed RANDAO chain head in the parent state.
    UnknownValidatorChain,
    /// The reveal fails against the committed head (or the chain is spent).
    Beacon(BeaconError),
}

/// Verify `reveal` for `proposer` against the parent's committed chain head
/// and fold it into the parent's accumulated mix. Returns the advanced
/// per-validator state and the new global mix — the exact pair the child
/// block commits (`randao_reveal` is checked by, `randao_mix` must equal,
/// this function's output).
///
/// One call into [`crate::beacon::process_reveal`], with the previous mix
/// pinned to the **parent header's** committed `randao_mix`. Pinning the
/// input here (instead of letting each caller pick "the current mix") is the
/// point: the h28080 stall was a producer and a validator in the same binary
/// feeding the same function different inputs.
pub fn randao_transition(
    parent: &ParentState<'_>,
    proposer: u32,
    reveal: &[u8; 32],
) -> Result<(RevealState, [u8; 32]), RandaoRejection> {
    let committed = parent.reveal_state_of(proposer).ok_or(RandaoRejection::UnknownValidatorChain)?;
    process_reveal(committed, &parent.header.randao_mix, reveal).map_err(RandaoRejection::Beacon)
}

/// The justified/finalized roots the child header must carry: the parent
/// state's, unchanged. Advancing justification is epoch processing
/// ([`crate::interfaces::StateTransition::process_epoch`], DEV-1); at this
/// seam any deviation — regression *or* unauthorized advance — is rejected,
/// because a block must never claim finality the transition did not compute.
pub fn expected_finality(parent: &ParentState<'_>) -> ([u8; 32], [u8; 32]) {
    (parent.header.justified_root, parent.header.finalized_root)
}

/// The §6.6.2 header mirror: `SHA3-256(DS_COHERENCE ‖ accumulator_root ‖
/// nullifier_root)` — the one encoding of the two committed Coherence roots
/// that `BlockHeaderV4.coherence_root` carries.
///
/// This binds the header field to the same two values `state_root` commits as
/// SMT leaves (`TAG_COHERENCE_ACCUMULATOR` / `TAG_COHERENCE_NULLIFIERS`), so
/// the mirror can never drift from the committed state. It does **not**
/// re-root the pool: the accumulator root is an input, computed once by the
/// C1-frozen SHAKE-256 tree in `coherence-core` and carried as a value —
/// §6.6.1's no-re-rooting rule is about that tree, not about how the header
/// encodes its root.
///
/// The genesis ceremony (`tools/genesis4-ceremony`) stamps the genesis header
/// with this same function over the carried pool's roots, which is what makes
/// "carried verbatim" a chain anchored in a checkable commitment instead of an
/// arbitrary constant.
pub fn coherence_binding(accumulator_root: &[u8; 32], nullifier_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(crate::params::DS_COHERENCE);
    h.update(accumulator_root);
    h.update(nullifier_root);
    h.finalize().into()
}

// `nullifier_set_root` used to live here. It is gone, and its absence is the
// point: the nullifier-set root is a **Coherence** object, and this crate's
// posture toward Coherence is carried-never-recomputed (§6.6.1). Computing it
// here — under a `BLCH4:` tag, with SHA3-256, in the consensus crate — was the
// PoS layer reaching into the shielded pool's business, and it produced an
// interim commitment that would have had to change before the ceremony,
// changing the genesis identity with it.
//
// The ratified definition is `coherence_core::NullifierSet` (a SHAKE-256
// sparse Merkle tree under `bloch:coherence:nfset:v1`, with non-membership
// proofs), specified in `docs/specs/COHERENCE-C1.1.md`. Whoever supplies
// `coherence_nullifier_root` — the genesis ceremony, and later the node's
// Coherence engine — computes it there, with the same code the SP1 guest runs.


/// The coherence root the child header must carry: the [`coherence_binding`]
/// of the **parent's committed** accumulator and nullifier-set roots.
///
/// Derived from `parent.chain`, not copied from `parent.header`: a value that
/// is only ever copied forward is anchored in nothing but the genesis stamp,
/// and validates nothing (the §5.5 "no value the validator cannot re-derive
/// from committed state" rule). Because shielded-transaction application is
/// inert at this seam — [`post_chain_state`] carries both roots unchanged —
/// the parent's committed roots ARE the child's post-state roots, so this is
/// simultaneously "carried, never re-rooted" (§6.6.1) and re-derivable.
///
/// When DEV-3 wires shielded application, [`post_chain_state`] starts
/// updating the two roots and this function must take the block's shielded
/// transactions and derive from the *post* state. Change the signature when
/// that happens — both the producer ([`crate::produce`]) and the validator
/// call this one function, so the compiler will hold them together through
/// the change (the h28080 lesson, applied forward).
pub fn expected_coherence(parent: &ParentState<'_>) -> [u8; 32] {
    coherence_binding(
        &parent.chain.coherence_accumulator_root,
        &parent.chain.coherence_nullifier_root,
    )
}

// ── Body commitments (DS_BODY domain, §6.1) ─────────────────────────────────
//
// Two Merkle trees, one domain tag, disjoint preimages: every hash starts
// with DS_BODY, then a marker byte (leaf/node/empty), then the tree kind
// (transactions vs attestations). Marker separation is what kills the classic
// "internal node presented as a leaf" second-preimage trick; kind separation
// is what keeps a transaction commitment from ever aliasing an attestation
// commitment. Attestations get their own tree (not a shared one) so a
// finalized epoch's signatures can be pruned without disturbing the
// transaction commitment (§6.5.1).

const MARK_LEAF: u8 = 0x00;
const MARK_NODE: u8 = 0x01;
const MARK_EMPTY: u8 = 0x02;
const KIND_TX: u8 = 0x01;
const KIND_ATTESTATION: u8 = 0x02;

fn body_sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DS_BODY);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Binary Merkle root with odd nodes promoted unchanged.
///
/// Promotion (instead of Bitcoin-style duplication of the last node) cannot
/// introduce ambiguity here because leaves and internal nodes live in
/// disjoint marked preimages — a promoted leaf can never be re-read as the
/// node of some other tree. Duplication, by contrast, is exactly what made
/// two distinct transaction lists share a root in CVE-2012-2459.
fn merkle_root(kind: u8, mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() {
        // A *defined* empty-tree value, not all-zeros: "no transactions" must
        // be a hash output the domain produced, not a magic constant another
        // computation could accidentally emit.
        return body_sha3(&[&[MARK_EMPTY], &[kind]]);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(body_sha3(&[&[MARK_NODE], &[kind], &pair[0], &pair[1]]));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// Merkle root committing the block's transactions — what
/// `BlockHeaderV4::body_root` must equal. Transactions are opaque bytes to
/// this crate; each leaf length-prefixes its bytes so `[b"ab", b"c"]` and
/// `[b"a", b"bc"]` cannot commit identically.
pub fn body_root(transactions: &[Vec<u8>]) -> [u8; 32] {
    let leaves = transactions
        .iter()
        .map(|tx| {
            body_sha3(&[&[MARK_LEAF], &[KIND_TX], &(tx.len() as u64).to_le_bytes(), tx])
        })
        .collect();
    merkle_root(KIND_TX, leaves)
}

/// Canonical encoding of one attestation for the quorum commitment: the
/// signed data (fixed widths, declaration order), the validator index, and
/// the length-prefixed signature. The signature *is* committed — an
/// attestation in a block is evidence, and evidence whose signature could be
/// swapped without moving the root would not be evidence.
fn attestation_leaf(att: &Attestation) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(128 + att.signature.len());
    bytes.extend_from_slice(&att.data.slot.to_le_bytes());
    bytes.extend_from_slice(&att.data.head);
    bytes.extend_from_slice(&att.data.source_epoch.to_le_bytes());
    bytes.extend_from_slice(&att.data.source_root);
    bytes.extend_from_slice(&att.data.target_epoch.to_le_bytes());
    bytes.extend_from_slice(&att.data.target_root);
    bytes.extend_from_slice(&att.validator.to_le_bytes());
    bytes.extend_from_slice(&(att.signature.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&att.signature);
    body_sha3(&[&[MARK_LEAF], &[KIND_ATTESTATION], &bytes])
}

/// Root over the attestation quorum carried in the body — what
/// `BlockHeaderV4::attestation_root` must equal.
pub fn attestation_root(attestations: &[Attestation]) -> [u8; 32] {
    merkle_root(KIND_ATTESTATION, attestations.iter().map(attestation_leaf).collect())
}

/// May `att` be included in a block at `block_slot` built on `parent`?
///
/// One definition, used twice: the producer *filters* its collected
/// attestations with this exact predicate, and the validator *rejects* the
/// block if any included attestation fails it. If the two sides used
/// different predicates, the producer would routinely assemble blocks its own
/// node refuses — the h28080 shape again, one layer up.
///
/// The committee is drawn from the same parent-committed seed and active set
/// as everything else; inclusion is restricted to attestations from the
/// block's own epoch because the parent's committed mix history is what makes
/// older committees derivable, and it keeps exactly two epochs — an
/// attestation this rule excludes is one whose committee a fresh node could
/// not re-derive from the parent state alone (§5.5 fails closed).
///
/// **KNOWN DIVERGENCE, recorded 2026-08-12, not fixed here.** "One definition,
/// used twice" is true of this function's two callers, but this function and
/// [`crate::transition`]'s step 8 do not draw the same committee: this one
/// calls [`crate::slot_subcommittee`] (the sampled 8-validator draw), the
/// transition calls [`crate::committees::committee_for_slot`] (the F1
/// partition). The partition is the current design and the sampled draw is
/// superseded — see the lib.rs banner — so a producer filtering with this
/// predicate can drop attestations its own validator would have accepted, and
/// keep ones it would refuse. It was masked while `derive::validate_block`
/// existed, because that validator used this same superseded rule and so
/// agreed with the producer perfectly while both disagreed with the node.
/// Deleting the parallel validator is what exposed it. Fixing it is a change
/// to `produce.rs`'s filter, on a seam this task did not open.
pub fn validate_included_attestation(
    parent: &ParentState<'_>,
    block_slot: u64,
    att: &Attestation,
    verifier: &dyn SignatureVerifier,
) -> Result<(), crate::attestation::RejectReason> {
    use crate::attestation::RejectReason;
    if crate::epoch_of(att.data.slot) != crate::epoch_of(block_slot) {
        // Cross-epoch inclusion: committee not derivable at this seam.
        return Err(RejectReason::NotInCommittee);
    }
    let seed = sortition_seed(parent, att.data.slot).ok_or(RejectReason::NotInCommittee)?;
    let active = active_validators(&parent.chain.registry, crate::epoch_of(block_slot));
    let committee = crate::slot_subcommittee(&seed, att.data.slot, &active);
    validate_attestation(att, &committee, block_slot, verifier)
}

/// The child block's committed consensus state: the parent's components with
/// this seam's updates applied — beacon history advanced with `new_mix`,
/// participation credited for the included quorum, everything else carried.
///
/// Deterministic by construction: participation is rebuilt through a
/// `BTreeMap`, and the mix history is keyed by epoch, so two nodes (or the
/// producer and validator inside one node) applying the same block to the
/// same parent produce byte-identical components — and therefore, through
/// [`ChainState::root`], bit-identical state roots.
pub fn post_chain_state(
    parent: &ParentState<'_>,
    block_slot: u64,
    new_mix: [u8; 32],
    attestations: &[Attestation],
) -> ChainState {
    let mut post = parent.chain.clone();
    let epoch = crate::epoch_of(block_slot);

    // Beacon history. This seam used to apply its OWN retention rule here, one
    // entry shorter than `transition`'s, so the two produced different state
    // roots for the same block. There is one rule now and it lives in
    // `state_root::randao_window`; the divergence and why transition's rule won
    // are documented there.
    post.randao_mixes = crate::state_root::randao_window(&post.randao_mixes, epoch, new_mix);

    // Participation: credit every validator whose attestation this block
    // carries. Rebuilt via BTreeMap so duplicate records or append order can
    // never influence the committed result. `attested` is monotone within an
    // epoch — an included attestation cannot be un-included.
    let mut credited: BTreeMap<u32, bool> = post
        .current_participation
        .iter()
        .map(|p| (p.validator_index, p.attested))
        .collect();
    for att in attestations {
        credited.insert(att.validator, true);
    }
    post.current_participation = credited
        .into_iter()
        .map(|(validator_index, attested)| ParticipationRecord { validator_index, attested })
        .collect();

    post
}

/// The state root the child header must carry. Composition of
/// [`post_chain_state`] and [`ChainState::root`] — exposed as one function so
/// the producer cannot even *accidentally* root a differently-built state.
pub fn post_state_root(
    parent: &ParentState<'_>,
    block_slot: u64,
    new_mix: [u8; 32],
    attestations: &[Attestation],
) -> [u8; 32] {
    post_chain_state(parent, block_slot, new_mix, attestations).root()
}

// ────────────────────────────────────────────────────────────────────────────
// The validator that used to live here — deleted 2026-08-12
// ────────────────────────────────────────────────────────────────────────────
//
// `validate_block(parent, envelope, verifier) -> Result<(), TransitionError>`
// stood here: a complete second block validator, with its own frozen error
// order, **and no caller**. The node runs `transition::Transition::apply_block`
// (`bloch-pos-node/src/engine.rs` binds that seam explicitly). Nothing outside
// this crate's own tests ever called this one.
//
// Two validation stacks with divergent error orders is precisely the condition
// that produced this week's defects: two block-identity functions, two state
// -root derivations (`state_root::randao_window` exists because of it), and a
// header that committed to nothing — that last one *because* the three
// commitment checks lived only here, in the stack nobody ran, so the stack that
// did run accepted any `body_root` at all for 178 green tests. A rule that
// exists twice is a rule that is enforced once and believed twice.
//
// THE COMPARISON, so the deletion is not a deletion of coverage. Left column:
// what `validate_block` checked. Right: where `transition` checks it.
//
//   parent linkage      → step 2, `header.parent != pre.head`. Same rule; the
//                         transition compares against an id IT derived rather
//                         than against a header field, which is stricter.
//   slot monotonicity   → step 1, plus a rule this seam had no way to state:
//                         a block in an epoch already processed past is also
//                         `NonMonotonicSlot`.
//   scheduled proposer  → step 4, via `schedule::proposer` off the same seed.
//   version             → step 3.
//   RANDAO reveal + mix → step 5, via `beacon::process_reveal`, and it ADVANCES
//                         the committed chain head, which this seam could not.
//   attestations        → step 8. Different committee rule, and the transition's
//                         is the current one: `committees::committee_for_slot`
//                         (the F1 partition) against this seam's
//                         `slot_subcommittee` (the superseded sampled draw —
//                         see the lib.rs banner). Plus a same-epoch bound.
//   attestation_root    → step 3b, same `attestation_root` function.
//   body_root           → step 3b, same `body_root` function.
//   finality carry-over → step 6, against the committed finality ENGINE rather
//                         than against the parent header's copied field.
//   coherence_root      → step 3b, same `coherence_binding`.
//   state_root          → step 12, over the state the transition actually
//                         computed (registry, finality, fees and all), not over
//                         a state whose components this seam carried unchanged.
//   proposer signature  → step 7, moved EARLIER on purpose: one hybrid verify
//                         before N attestation verifies is the cheap-first
//                         order the transition's docs freeze.
//
// Nothing was checked here and only here. What WAS only here was two negative
// tests — `WrongVersion` and proposer `BadSignature` had no regression test in
// the transition, only in `produce.rs`'s tamper table against this function.
// Those are migrated to `transition::tests` (`wrong_version_rejected`,
// `bad_proposer_signature_rejected`); deleting a checker while dropping the
// tests that prove the check exists is how a check becomes a comment.
//
// Everything ABOVE this comment stays: `active_validators`, `sortition_seed`,
// `scheduled_proposer`, `randao_transition`, `expected_finality`,
// `coherence_binding`, `expected_coherence`, `body_root`, `attestation_root`,
// `validate_included_attestation`, `post_chain_state`, `post_state_root`. They
// are the shared derivations — `produce.rs` stamps with them and `transition`
// checks with them, and that sharing is the anti-h28080 invariant itself. Only
// the parallel validator died.

#[cfg(test)]
mod coherence_tests {
    use super::*;
    use crate::header::VERSION_G4;
    use crate::state_root::{CheckpointRecord, EvmCommitment, FinalityRecord, RandaoMix};

    fn chain(acc: [u8; 32], nf: [u8; 32]) -> ChainState {
        ChainState {
            eutxos: Vec::new(),
            registry: Vec::new(),
            current_participation: Vec::new(),
            previous_participation: Vec::new(),
            randao_mixes: vec![RandaoMix { epoch: 0, mix: [0u8; 32] }],
            // The bookkeeping components the S5.5 extension added. Empty here
            // on purpose: this fixture exercises the Coherence binding only,
            // and listing them explicitly (rather than `..Default::default()`)
            // means the next component added breaks this line and gets looked
            // at, instead of silently defaulting to empty inside a test that
            // claims to cover the state.
            finality: FinalityRecord {
                justified: Vec::new(),
                current_justified: CheckpointRecord { epoch: 0, root: [0u8; 32] },
                previous_justified: CheckpointRecord { epoch: 0, root: [0u8; 32] },
                finalized: CheckpointRecord { epoch: 0, root: [0u8; 32] },
                leaked: Vec::new(),
                next_epoch: 0,
            },
            pending_votes: Vec::new(),
            fc_messages: Vec::new(),
            fc_equivocators: Vec::new(),
            deposit_queue: Vec::new(),
            delegations: Vec::new(),
            pending_fees: Vec::new(),
            taint_root: [0u8; 32],
            coherence_accumulator_root: acc,
            coherence_nullifier_root: nf,
            // Empty EVM segment: no accounts, no receipts, no gas. Written out
            // rather than defaulted so the next carried component breaks this
            // line and gets looked at.
            applied_evidence: Vec::new(),
            slash_window: Vec::new(),
            delegator_slash_losses: Vec::new(),
            // Genesis-shaped fee market: the price floor, no usage behind it.
            // Written out rather than defaulted, same break-this-line reason.
            base_fee: crate::state_root::BaseFeeRecord {
                base_fee_millisat_per_gas:
                    crate::fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                gas_used: 0,
                tx_bytes: 0,
            },
            delegator_fee_rewards: Vec::new(),
            evm: EvmCommitment {
                account_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                base_fee_per_gas: 0,
            },
            // Genesis-shaped, written out for the same break-this-line reason.
            issued_sat: crate::tokenomics_v4::GENESIS_ISSUED_SAT,
        }
    }

    fn header_with_coherence(coherence_root: [u8; 32]) -> BlockHeaderV4 {
        BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0u8; 32],
            state_root: [0u8; 32],
            body_root: [0u8; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0u8; 32],
            randao_mix: [0u8; 32],
            justified_root: [0u8; 32],
            finalized_root: [0u8; 32],
            attestation_root: [0u8; 32],
            coherence_root,
        }
    }

    /// The mirror is a function of the two roots and nothing else, and it is
    /// injective over each input (no zero-absorption: an all-zero root pair
    /// still produces a real digest — "empty pool" is a hash output, never
    /// the magic constant `[0u8; 32]` the old genesis stamped).
    #[test]
    fn binding_depends_on_both_roots_and_is_never_zero() {
        let a = coherence_binding(&[1u8; 32], &[2u8; 32]);
        assert_eq!(a, coherence_binding(&[1u8; 32], &[2u8; 32]));
        assert_ne!(a, coherence_binding(&[3u8; 32], &[2u8; 32]));
        assert_ne!(a, coherence_binding(&[1u8; 32], &[4u8; 32]));
        // Swapping the operands must not commute — acc and nf are different
        // objects and the binding must tell them apart.
        assert_ne!(
            coherence_binding(&[1u8; 32], &[2u8; 32]),
            coherence_binding(&[2u8; 32], &[1u8; 32])
        );
        assert_ne!(coherence_binding(&[0u8; 32], &[0u8; 32]), [0u8; 32]);
    }

    /// The child's coherence_root derives from the parent's **committed
    /// state**, not from the parent's header field: a stale or corrupt header
    /// value does not propagate. This is the difference between "carried" and
    /// "validated" — the value the chain finalizes is re-derivable by every
    /// node from state it can check.
    #[test]
    fn expected_coherence_derives_from_committed_state_not_the_parent_header() {
        let chain = chain([0x12; 32], [0x13; 32]);
        let honest = header_with_coherence(coherence_binding(&[0x12; 32], &[0x13; 32]));
        let stale = header_with_coherence([0x08; 32]); // arbitrary junk stamp
        let expected = coherence_binding(&[0x12; 32], &[0x13; 32]);
        for header in [&honest, &stale] {
            let parent = ParentState { header, chain: &chain, reveal_states: &[] };
            assert_eq!(expected_coherence(&parent), expected);
        }
    }

    /// Carriage invariant while shielded application is inert: whatever block
    /// is applied, [`post_chain_state`] leaves both Coherence roots untouched
    /// — so `expected_coherence` over the parent equals the binding of the
    /// child's post-state roots, and the mirror stays consistent block after
    /// block. The day this test fails is the day shielded application was
    /// wired in — at which point `expected_coherence` must move to the post
    /// state (see its doc).
    #[test]
    fn post_chain_state_carries_both_coherence_roots_unchanged() {
        let parent_chain = chain([0xAA; 32], [0xBB; 32]);
        let header = header_with_coherence(coherence_binding(&[0xAA; 32], &[0xBB; 32]));
        let parent = ParentState { header: &header, chain: &parent_chain, reveal_states: &[] };
        let post = post_chain_state(&parent, 1, [0xCC; 32], &[]);
        assert_eq!(post.coherence_accumulator_root, [0xAA; 32]);
        assert_eq!(post.coherence_nullifier_root, [0xBB; 32]);
        assert_eq!(
            expected_coherence(&parent),
            coherence_binding(&post.coherence_accumulator_root, &post.coherence_nullifier_root),
        );
    }

}
