// SPDX-License-Identifier: MIT OR Apache-2.0

//! The state transition function — the composition layer (§5.5, Boundary 2).
//!
//! Every module in this crate states one rule; until now nothing composed
//! them. This module implements [`StateTransition`]: parent state × block →
//! child state, calling into `schedule`, `beacon`, `committees`,
//! `attestation`, `forkchoice`, `rewards` and `state_root` for `apply_block`,
//! and into `finality`, `staking`, `delegation` and `genesis_cohort` for
//! `process_epoch`. No consensus rule is *defined* here; this module only
//! decides in what order the existing rules run and what state they read.
//!
//! ## The three rules this module is written against
//!
//! 1. **Every consensus value comes from the parent's committed state** —
//!    never from node-local mutable state. [`CommittedState`] is a plain value
//!    with no clock, no cache and no interior mutability; `apply_block` takes
//!    it by `&` and returns a new one. Even the state root is recomputed from
//!    the leaves on every call (the same posture as [`crate::state_root::Smt`])
//!    because a memoized root that survives one forgotten invalidation is
//!    exactly how `expected_bits` split the mainnet on 2026-08-08.
//! 2. **No function may depend on input arrival order.** Everything
//!    accumulated across blocks lives in `BTreeMap`/`BTreeSet` keyed by data,
//!    not in insertion-ordered `Vec`s: pending finality votes are keyed by
//!    `(validator, signing_root)`, fork-choice messages by validator, so the
//!    same set of attestations produces the same committed state no matter
//!    which block, or which position in a block, carried each one. Blocks
//!    themselves apply in chain order — enforced by the parent/slot checks —
//!    so delivery order cannot reach the state at all.
//! 3. **A cap measured against a total it reduces is wrong.** The cohort cap
//!    uses the closed form in [`crate::genesis_cohort::apply_cohort_cap`];
//!    the per-validator delegation cap uses the fixed-point iteration in
//!    [`crate::delegation::Registry::cap_sat`]. This module *calls* those and
//!    never re-derives either denominator.
//!
//! ## Frozen error order (consensus-visible, per the `StateTransition` docs)
//!
//! Cheapest first, so spam is rejected before any hybrid verify runs:
//!
//! 1. `NonMonotonicSlot` — slot must advance, and must not land in an epoch
//!    the caller already processed past.
//! 2. `WrongParent` — header `parent` vs the pre-state's head id.
//! 3. `Proposal(WrongVersion)`.
//! 4. `Proposal(NotScheduledProposer)` — the `schedule` draw (a hash, no sig).
//! 5. `Proposal(BadRandaoReveal)` — preimage check + mix consistency (two
//!    hashes).
//! 6. `FinalityRegression` — header finality roots vs parent-committed
//!    finality (a comparison).
//! 7. `Proposal(BadSignature)` — the proposer's hybrid signature: one
//!    expensive verify, placed before the N attestation verifies.
//! 8. `Attestation(i)` — in body order; membership (cheap) is checked before
//!    each signature inside [`crate::attestation::validate`].
//! 9. `Transaction(i)` — in body order; all checks here are cheap state
//!    lookups.
//! 10. `StateRootMismatch` — last, because the root only exists once the
//!     whole transition has run.
//!
//! ## Double-apply is a reject, not a no-op — decided here
//!
//! Applying a block to its own post-state fails with `NonMonotonicSlot`.
//! `apply_block` is *parent* state × block → child state; the post-state of B
//! is not B's parent, so accepting the call and returning the input unchanged
//! would silently mask a caller wiring bug — the same class of defect as the
//! `pow_hash`/`block_hash` double-keying that stalled tip selection. The
//! idempotence that actually matters — the same block applied to the same
//! *parent* state twice yields bit-identical children — holds because the
//! function is pure, and is pinned by test.
//!
//! ## What is honestly not committed yet (flagged, not hidden)
//!
//! [`crate::state_root::ConsensusState`] — the frozen §5.5 component list —
//! commits the registry, participation, beacon mix history and the carried
//! roots. The following consensus-relevant fields of [`CommittedState`] do
//! **not** yet appear under a `StateRoots` component and therefore are not
//! bound by the header's `state_root`: the finality bookkeeping, per-validator
//! RANDAO chain positions (`reveals_used`), the deposit/delegation queues,
//! pending fee rewards, and fork-choice latest messages. Extending the closed
//! component list is a visible spec change (interfaces §Boundary 7) that needs
//! the two-reviewer rule; recorded in `BLOCH-POS-INTERFACES.md` as an open
//! point rather than smuggled in here as an eighth leaf.
//!
//! Similarly, [`block_id`] and [`proposal_signing_root`] below implement the
//! §5.4/§6.1 formulas (`SHA3-256(DS_BLOCK ‖ canonical header)`,
//! `SHA3-256(DS_PROPOSE ‖ canonical header)`) directly, because DEV-2's
//! `StateCommitment`/`ProposerDuties` implementations have not landed. When
//! they do, A1's KATs must pin that these agree byte-for-byte, and these
//! free functions become delegating shims.

use crate::attestation::{self, Attestation, AttestationData, SignatureVerifier};
use crate::beacon::{self, RevealState};
use crate::committees;
use crate::delegation::{self, Delegation};
use crate::finality;
use crate::forkchoice::{LatestMessage, Store};
use crate::genesis_cohort;
use crate::interfaces::{
    BlockHeaderV4, BlockId, Checkpoint, FinalityState as FinalityView, ProposalEnvelope,
    ProposalReject, StateReader, StateTransition, TransitionError, ValidatorRecord,
};
use crate::params::{DS_BLOCK, DS_PROPOSE, SLOTS_PER_EPOCH};
use crate::rewards::{self, StakeAccount};
use crate::sample::Validator;
use crate::schedule;
use crate::staking::{self, QueuedDeposit};
use crate::state_root::{
    ConsensusState, ParticipationRecord, RandaoMix, ValidatorRecord as CommittedValidatorRecord,
};
use crate::tokenomics_v4;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// The Genesis-4 block version (§5.3): `0xB10C_0005`.
pub const BLOCK_VERSION_V4: u32 = 0xB10C_0005;

// ─── Hashing shims (see module docs: interim until DEV-2's impls land) ──────

/// Canonical header serialization: fields in declaration order, fixed
/// little-endian widths, no length prefixes needed because every field is
/// fixed-width — the same "no two headers share bytes" argument
/// `AttestationData::signing_root` makes.
fn canonical_header_bytes(h: &BlockHeaderV4) -> Vec<u8> {
    let mut b = Vec::with_capacity(304);
    b.extend_from_slice(&h.version.to_le_bytes());
    b.extend_from_slice(&h.parent.0);
    b.extend_from_slice(&h.state_root);
    b.extend_from_slice(&h.body_root);
    b.extend_from_slice(&h.slot.to_le_bytes());
    b.extend_from_slice(&h.proposer_index.to_le_bytes());
    b.extend_from_slice(&h.randao_reveal);
    b.extend_from_slice(&h.randao_mix);
    b.extend_from_slice(&h.justified_root.0);
    b.extend_from_slice(&h.finalized_root.0);
    b.extend_from_slice(&h.attestation_root);
    b.extend_from_slice(&h.coherence_root);
    b
}

/// §5.4: `SHA3-256(DS_BLOCK ‖ canonical header)` — the one block identifier.
pub fn block_id(h: &BlockHeaderV4) -> BlockId {
    let mut d = Sha3_256::new();
    d.update(DS_BLOCK);
    d.update(canonical_header_bytes(h));
    BlockId(d.finalize().into())
}

/// The proposer's signing root, under its own domain (`DS_PROPOSE`), distinct
/// from the identity domain so a signature can never double as an identifier.
pub fn proposal_signing_root(h: &BlockHeaderV4) -> [u8; 32] {
    let mut d = Sha3_256::new();
    d.update(DS_PROPOSE);
    d.update(canonical_header_bytes(h));
    d.finalize().into()
}

// ─── Transactions ───────────────────────────────────────────────────────────

/// The transaction shapes this transition interprets. The eUTXO format is out
/// of the migration's scope (§1.2), so value transfers are opaque here — only
/// their fees are consensus inputs to this layer. Deposits, exits and
/// delegations are the staking-lifecycle messages whose *state-dependent*
/// rules this transition owns; their cryptographic admission checks (proof of
/// possession, taint/transparency of inputs, hybrid signatures) run at the
/// mempool boundary against DEV-3's `StakingLifecycle`/`StakeEligibility`
/// implementations, which `apply_block`'s frozen signature deliberately does
/// not receive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PosTransaction {
    /// An opaque value transfer. Consensus here needs only the fees.
    Transfer { base_fee_sat: u128, priority_fee_sat: u128 },
    /// Register a validator (§7.1). PoP/taint already checked at admission.
    Deposit {
        /// Suite-tagged hybrid public key (opaque bytes, per the interfaces).
        pubkey: Vec<u8>,
        amount_sat: u128,
        /// `c_0`, head of the SHAKE-256 reveal chain (§6.3).
        randao_commitment: [u8; 32],
        withdrawal_credentials: Vec<u8>,
    },
    /// Voluntary exit (§7.2). Signature already checked at admission.
    Exit { validator: u32 },
    /// Bond delegated stake behind an operator.
    Delegate {
        delegator: u32,
        validator: u32,
        amount_sat: u128,
        /// Resolved by the taint oracle at admission (§4.1): an ineligible
        /// delegation is recorded but never contributes stake — the record
        /// exists so the ineligibility is itself a committed, auditable fact.
        eligible: bool,
    },
}

// ─── The committed state ────────────────────────────────────────────────────

/// One validator of the launch set, as published in the genesis block.
#[derive(Clone, Debug)]
pub struct GenesisValidator {
    pub index: u32,
    pub pubkey: Vec<u8>,
    pub staked_sat: u128,
    pub randao_commitment: [u8; 32],
    pub withdrawal_credentials: Vec<u8>,
}

/// The committed post-state of one block — [`StateTransition::State`].
///
/// A plain value: `Clone` + `PartialEq`, no interior mutability, no handles.
/// Everything a consensus rule may read arrives through this struct, and the
/// struct is only ever produced by [`CommittedState::genesis`] or by the
/// transition itself — there is no constructor that reads a database.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedState {
    /// Slot of the block whose post-state this is.
    slot: u64,
    /// Epoch whose accounting context is current. Blocks may only apply in
    /// this epoch; `close_epoch` advances it — over empty boundary slots too.
    epoch: u64,
    /// Id of the block that produced this state (genesis block at genesis).
    head: BlockId,
    /// The validator registry, keyed by index. `BTreeMap` everywhere in this
    /// struct: iteration order must be a function of the data, never of a
    /// hasher seed or insertion history (rule 2).
    validators: BTreeMap<u32, ValidatorRecord>,
    /// RANDAO chain position per validator. The chain *head* lives in the
    /// registry record (`randao_commitment`); this is how far down it is.
    reveals_used: BTreeMap<u32, u32>,
    /// The accumulated beacon mix as of this state.
    randao_mix: [u8; 32],
    /// Mix as fixed at the close of each epoch, last 2 retained (§5.5). The
    /// mix at the close of epoch E seeds epoch E+1's sortition and partition.
    boundary_mixes: BTreeMap<u64, [u8; 32]>,
    /// The mix that seeds epoch 0 — fixed at genesis, before any validator
    /// could have influenced it.
    genesis_mix: [u8; 32],
    /// The genesis cohort (sorted): the founder-operated launch set whose
    /// combined weight [`genesis_cohort::apply_cohort_cap`] tapers to 1/3.
    genesis_cohort: Vec<u32>,
    /// The justification/finality fold (finality.rs). Kept whole so this
    /// state remains bit-identical to a from-scratch replay of the votes.
    finality_engine: finality::FinalityState,
    /// Justified checkpoint as of the *previous* epoch — required by the
    /// frozen [`FinalityView`] (surround-vote slashing is judged against it).
    previous_justified: Checkpoint,
    /// Epoch-boundary votes accumulated during the current epoch, keyed by
    /// `(validator, signing_root)` so the set — not the arrival order — is
    /// what gets committed (rule 2). The finality engine is the sole judge of
    /// what these votes mean; this map only collects them.
    pending_votes: BTreeMap<(u32, [u8; 32]), AttestationData>,
    /// LMD-GHOST latest message per validator, as accepted by
    /// [`Store::observe`] — the single definition of accept/equivocate.
    latest_messages: BTreeMap<u32, (u64, [u8; 32])>,
    /// Validators barred from fork-choice weight for equivocating. Monotone.
    fc_equivocators: BTreeSet<u32>,
    /// Attestation inclusion per validator, current epoch. Feeds rewards
    /// (credits) and the committed participation component.
    current_participation: BTreeMap<u32, bool>,
    /// Same, previous epoch.
    previous_participation: BTreeMap<u32, bool>,
    /// Every deposit ever included, in [`QueuedDeposit`] form. Kept forever
    /// on purpose: [`staking::resolve_activations`] replays the queue from
    /// epoch zero, so removing an activated entry would shift every later
    /// admission — history is the input, not a cache to prune.
    deposit_history: Vec<QueuedDeposit>,
    /// Pubkey hash → registry index, so a second deposit of the same key is a
    /// deterministic reject (the `PubkeyAlreadyRegistered` rationale).
    pubkey_index: BTreeMap<[u8; 32], u32>,
    /// Every delegation ever included. Same replay argument as the deposit
    /// history: [`delegation::Registry::resolve`] is a fold over all of it.
    delegations: Vec<Delegation>,
    /// Fee rewards accrued to proposers during the current epoch, compounded
    /// into their bond only at the epoch boundary — so effective stake, and
    /// with it every committee and schedule, is frozen for the epoch's whole
    /// duration. Mid-epoch compounding would let a fee-heavy block reshuffle
    /// the committees that are supposed to be judging it.
    pending_fee_rewards: BTreeMap<u32, u128>,
    /// Carried roots (§6.6.2): never recomputed by this transition.
    taint_root: [u8; 32],
    coherence_accumulator_root: [u8; 32],
    coherence_nullifier_root: [u8; 32],
}

impl CommittedState {
    /// The state committed by the genesis block. Its checkpoint is justified
    /// and finalized by definition — finality needs a root of trust.
    #[allow(clippy::too_many_arguments)]
    pub fn genesis(
        genesis_block: BlockId,
        genesis_mix: [u8; 32],
        validators: &[GenesisValidator],
        cohort: &[u32],
        taint_root: [u8; 32],
        coherence_accumulator_root: [u8; 32],
        coherence_nullifier_root: [u8; 32],
    ) -> Self {
        let mut registry = BTreeMap::new();
        let mut reveals_used = BTreeMap::new();
        let mut pubkey_index = BTreeMap::new();
        for v in validators {
            registry.insert(
                v.index,
                ValidatorRecord {
                    index: v.index,
                    pubkey: v.pubkey.clone(),
                    staked_sat: v.staked_sat,
                    randao_commitment: v.randao_commitment,
                    withdrawal_credentials: v.withdrawal_credentials.clone(),
                    activation_epoch: 0,
                    exit_epoch: u64::MAX,
                    withdrawable_epoch: u64::MAX,
                    slashed: false,
                },
            );
            reveals_used.insert(v.index, 0);
            pubkey_index.insert(Sha3_256::digest(&v.pubkey).into(), v.index);
        }
        let mut cohort_sorted = cohort.to_vec();
        // Canonicalise: apply_cohort_cap binary-searches this list, and a
        // caller-ordered list would make membership a function of memory
        // layout (rule 2).
        cohort_sorted.sort_unstable();
        cohort_sorted.dedup();

        let genesis_cp = Checkpoint { epoch: 0, root: genesis_block };
        let mut st = CommittedState {
            slot: 0,
            epoch: 0,
            head: genesis_block,
            validators: registry,
            reveals_used,
            randao_mix: genesis_mix,
            boundary_mixes: BTreeMap::new(),
            genesis_mix,
            genesis_cohort: cohort_sorted,
            finality_engine: finality::FinalityState::new(finality::Checkpoint {
                epoch: 0,
                root: genesis_block.0,
            }),
            previous_justified: genesis_cp,
            pending_votes: BTreeMap::new(),
            latest_messages: BTreeMap::new(),
            fc_equivocators: BTreeSet::new(),
            current_participation: BTreeMap::new(),
            previous_participation: BTreeMap::new(),
            deposit_history: Vec::new(),
            pubkey_index,
            delegations: Vec::new(),
            pending_fee_rewards: BTreeMap::new(),
            taint_root,
            coherence_accumulator_root,
            coherence_nullifier_root,
        };
        // Seed epoch 0's participation for the launch roster, so the
        // committed participation component is well-defined from block one.
        for v in st.duty_roster_at(0) {
            st.current_participation.insert(v.index, false);
        }
        st
    }

    /// Id of the block that produced this state.
    pub fn head(&self) -> BlockId {
        self.head
    }

    // ── Derivations from committed state (rule 1: no other source exists) ──

    /// The beacon mix that seeds sortition and partition for `epoch`: the mix
    /// fixed at the close of epoch `epoch - 1` (§6.3), so the schedule is
    /// knowable exactly one epoch ahead and no earlier.
    fn seed_for_epoch(&self, epoch: u64) -> [u8; 32] {
        if epoch == 0 {
            return self.genesis_mix;
        }
        match self.boundary_mixes.get(&(epoch - 1)) {
            Some(m) => *m,
            // Unreachable by the retention invariant (the current epoch's
            // seed is always among the last 2 boundaries), but a consensus
            // function is not allowed to panic on any input, so the total
            // fallback is the genesis mix rather than an unwrap.
            None => self.genesis_mix,
        }
    }

    /// The duty roster for `epoch`: active registry records plus activated
    /// delegated stake, with the genesis-cohort cap applied last.
    ///
    /// Derived on demand, never cached: everything it reads is committed and
    /// frozen for the epoch (stake mutations happen only at boundaries, new
    /// delegations request from the *next* epoch), so recomputation cannot
    /// disagree with itself — and a cached roster is exactly the §5.5 pattern
    /// this crate bans.
    fn duty_roster_at(&self, epoch: u64) -> Vec<Validator> {
        // Delegated stake resolved by the delegation module's own fold; its
        // per-validator cap uses the fixed-point form (rule 3 — the cap is
        // measured against the capped total, not the total it reduces).
        let reg = delegation::Registry::resolve(&self.delegations, epoch);
        let delegated = reg.validators(); // sorted by index

        let mut roster: Vec<Validator> = Vec::new();
        for (idx, rec) in &self.validators {
            if rec.slashed || rec.activation_epoch > epoch || epoch >= rec.exit_epoch {
                continue;
            }
            let own = sat_u64(rec.staked_sat);
            let del = delegated
                .binary_search_by_key(idx, |v| v.index)
                .map(|p| delegated[p].effective_stake)
                .unwrap_or(0);
            roster.push(Validator { index: *idx, effective_stake: own.saturating_add(del) });
        }
        // The cohort cap's closed form (`s/(1-s) · others`) lives in
        // genesis_cohort.rs; this call is the whole integration.
        genesis_cohort::apply_cohort_cap(&roster, &self.genesis_cohort, epoch)
    }

    fn duty_roster(&self) -> Vec<Validator> {
        self.duty_roster_at(self.epoch)
    }

    /// The frozen finality view over the engine's state.
    fn finality_view(&self) -> FinalityView {
        let j = self.finality_engine.current_justified();
        let f = self.finality_engine.finalized();
        FinalityView {
            previous_justified: self.previous_justified,
            justified: Checkpoint { epoch: j.epoch, root: BlockId(j.root) },
            finalized: Checkpoint { epoch: f.epoch, root: BlockId(f.root) },
        }
    }

    /// Recompute the committed state root from the frozen §5.5 components.
    /// Pure recomputation on every call — no memoized value can go stale.
    fn compute_root(&self) -> [u8; 32] {
        let validators: Vec<CommittedValidatorRecord> = self
            .validators
            .values()
            .map(|r| CommittedValidatorRecord {
                index: r.index,
                pubkey: r.pubkey.clone(),
                // The committed record carries u64; the registry carries u128
                // per the arithmetic contract. Saturation is unreachable
                // (supply < 2^64 per bond) and exists only so the narrowing
                // cannot wrap.
                stake: sat_u64(r.staked_sat),
                activation_epoch: r.activation_epoch,
                exit_epoch: r.exit_epoch,
                slashed: r.slashed,
            })
            .collect();
        let current: Vec<ParticipationRecord> = self
            .current_participation
            .iter()
            .map(|(v, a)| ParticipationRecord { validator_index: *v, attested: *a })
            .collect();
        let previous: Vec<ParticipationRecord> = self
            .previous_participation
            .iter()
            .map(|(v, a)| ParticipationRecord { validator_index: *v, attested: *a })
            .collect();
        // Boundary mixes (last 2) plus the running mix keyed by the current
        // epoch: committing the running value is what binds each block's
        // RANDAO reveal into the state root the header pins.
        let mut mixes: Vec<RandaoMix> = self
            .boundary_mixes
            .iter()
            .map(|(e, m)| RandaoMix { epoch: *e, mix: *m })
            .collect();
        mixes.push(RandaoMix { epoch: self.epoch, mix: self.randao_mix });

        crate::state_root::state_root(&ConsensusState {
            // The eUTXO set is owned by the node's transaction layer, which
            // this standalone crate cannot see (transactions are opaque);
            // the node's implementation supplies it here.
            eutxos: &[],
            validators: &validators,
            current_participation: &current,
            previous_participation: &previous,
            randao_mixes: &mixes,
            taint_root: self.taint_root,
            coherence_accumulator_root: self.coherence_accumulator_root,
            coherence_nullifier_root: self.coherence_nullifier_root,
        })
    }

    // ── Fork-choice accumulation ────────────────────────────────────────────

    /// Fold this block's attestations into the LMD-GHOST latest messages.
    ///
    /// A fresh [`Store`] is rebuilt from committed state and the block's
    /// votes are fed through [`Store::observe`] — the *single* definition of
    /// which message wins and what counts as equivocation. This method only
    /// mirrors observe's accepted outcomes back into committed form; it never
    /// re-decides them. Rebuilding per block instead of holding a live Store
    /// is deliberate: a long-lived store on the node is exactly the mutable
    /// local state rule 1 bans from the transition.
    fn accumulate_forkchoice(&mut self, roster: &[Validator], attestations: &[Attestation]) {
        let mut store = Store::new();
        for v in roster {
            store.set_stake(v.index, v.effective_stake);
        }
        // Committed messages first: one per validator, so cross-validator
        // iteration order cannot matter.
        for (v, (slot, root)) in &self.latest_messages {
            store.observe(*v, LatestMessage { slot: *slot, root: *root });
        }
        for att in attestations {
            if self.fc_equivocators.contains(&att.validator) {
                // Store::observe would refuse these too if the store lived
                // across blocks; since it is rebuilt, the committed bar is
                // re-applied here. Equivocators stay excluded forever.
                continue;
            }
            let msg = LatestMessage { slot: att.data.slot, root: att.data.head };
            if store.observe(att.validator, msg) {
                self.latest_messages.insert(att.validator, (msg.slot, msg.root));
            }
        }
        // Whatever observe classified as equivocation is barred and its
        // weight removed — both halves of the pair, so arrival order cannot
        // decide the outcome (the forkchoice.rs 2026-08-11 finding).
        let newly: Vec<u32> = store.equivocators().copied().collect();
        for e in newly {
            self.fc_equivocators.insert(e);
            self.latest_messages.remove(&e);
        }
    }

    // ── Transactions ────────────────────────────────────────────────────────

    /// Apply one transaction's state-dependent rules. Returns the
    /// `(base_fee, priority_fee)` it contributes. `total_active_sat` is the
    /// epoch's active stake, passed in because the per-validator cap is a
    /// fraction of *committed* active stake (rule 1), not something this
    /// method may re-derive from a moving intermediate.
    fn apply_transaction(
        &mut self,
        tx: &PosTransaction,
        total_active_sat: u128,
    ) -> Result<(u128, u128), ()> {
        match tx {
            PosTransaction::Transfer { base_fee_sat, priority_fee_sat } => {
                Ok((*base_fee_sat, *priority_fee_sat))
            }
            PosTransaction::Deposit {
                pubkey,
                amount_sat,
                randao_commitment,
                withdrawal_credentials,
            } => {
                let pubkey_hash: [u8; 32] = Sha3_256::digest(pubkey).into();
                // A second deposit of a registered key is a top-up path
                // decision the interface refuses to make implicitly.
                if self.pubkey_index.contains_key(&pubkey_hash) {
                    return Err(());
                }
                if *amount_sat < staking::MIN_DEPOSIT_SAT {
                    return Err(());
                }
                // Per-validator cap: 1% of committed active stake, floored at
                // the minimum deposit — a naive 1% cap at genesis (active
                // stake ≈ 0) would deadlock the bootstrap (staking.rs docs).
                let cap = (total_active_sat * delegation::MAX_VALIDATOR_STAKE_BPS / 10_000)
                    .max(staking::MIN_DEPOSIT_SAT);
                if *amount_sat > cap {
                    return Err(());
                }
                // Next free index: a deterministic function of the registry,
                // never of anything local.
                let index = self.validators.keys().next_back().map_or(0, |k| k + 1);
                self.validators.insert(
                    index,
                    ValidatorRecord {
                        index,
                        pubkey: pubkey.clone(),
                        staked_sat: *amount_sat,
                        randao_commitment: *randao_commitment,
                        withdrawal_credentials: withdrawal_credentials.clone(),
                        // Not scheduled until the activation queue admits it.
                        activation_epoch: u64::MAX,
                        exit_epoch: u64::MAX,
                        withdrawable_epoch: u64::MAX,
                        slashed: false,
                    },
                );
                self.reveals_used.insert(index, 0);
                self.pubkey_index.insert(pubkey_hash, index);
                self.deposit_history.push(QueuedDeposit {
                    pubkey_hash,
                    deposit_epoch: self.epoch,
                    amount_sat: *amount_sat,
                });
                Ok((0, 0))
            }
            PosTransaction::Exit { validator } => {
                let Some(rec) = self.validators.get_mut(validator) else {
                    return Err(());
                };
                // Active, not already exiting, not slashed (slashing has its
                // own ejection path and must not share the voluntary one).
                if rec.slashed
                    || rec.activation_epoch > self.epoch
                    || rec.exit_epoch != u64::MAX
                {
                    return Err(());
                }
                // Duties stop EXIT_DELAY_EPOCHS after the request — an exit
                // must not dodge already-assigned duties — and the stake
                // stays slashable through the weak-subjectivity margin.
                let exit_epoch = self.epoch.saturating_add(staking::EXIT_DELAY_EPOCHS);
                rec.exit_epoch = exit_epoch;
                rec.withdrawable_epoch =
                    exit_epoch.saturating_add(staking::WITHDRAWAL_DELAY_EPOCHS);
                Ok((0, 0))
            }
            PosTransaction::Delegate { delegator, validator, amount_sat, eligible } => {
                let Some(rec) = self.validators.get(validator) else {
                    return Err(());
                };
                if rec.slashed || rec.exit_epoch != u64::MAX {
                    return Err(());
                }
                if *amount_sat < delegation::MIN_DELEGATION_SAT {
                    return Err(());
                }
                self.delegations.push(Delegation {
                    delegator: *delegator,
                    validator: *validator,
                    amount_sat: *amount_sat,
                    // A delegation included during epoch E requests from
                    // E+1: the stake backing epoch E's committees was fixed
                    // before E started, and nothing included *during* E may
                    // change it (the same principle as ACTIVATION_DELAY).
                    requested_epoch: self.epoch + 1,
                    deactivate_epoch: None,
                    eligible: *eligible,
                });
                Ok((0, 0))
            }
        }
    }

    // ── Epoch boundary ──────────────────────────────────────────────────────

    /// Close the current epoch E and open E+1. Infallible and pure — it runs
    /// whether or not the boundary slot carried a block, because a withheld
    /// proposal must not become a lever over everyone's rewards or over the
    /// finality clock (the engine's leak ticks on empty epochs too).
    fn close_epoch(&self) -> CommittedState {
        let mut st = self.clone();
        let closing = st.epoch;
        let roster = st.duty_roster_at(closing);

        // 1. Justification and finality (finality.rs). Epoch 0's checkpoint
        //    is the genesis root of trust — already justified and finalized —
        //    so the engine's dense history starts at epoch 1.
        if closing >= 1 {
            let votes: Vec<(u32, AttestationData)> =
                st.pending_votes.iter().map(|((v, _), d)| (*v, *d)).collect();
            // Roll the frozen view's previous_justified before the engine
            // moves: it is "the justified checkpoint as of the last epoch",
            // exactly what surround-vote slashing judges against.
            let old = st.finality_engine.current_justified();
            st.previous_justified = Checkpoint { epoch: old.epoch, root: BlockId(old.root) };
            // Out-of-order is unreachable: this is the only call site and it
            // feeds epochs densely by construction. A total no-op on Err
            // beats a panic in a consensus path.
            let _ = st.finality_engine.process_epoch(&finality::EpochVotes {
                epoch: closing,
                committee: &roster,
                attestations: &votes,
            });
        }

        // 2. Rewards for the closed epoch (rewards.rs). Issuance follows the
        //    recommended decay curve, summed over the epoch's actual slots so
        //    year edges land exactly where tokenomics_v4 puts them. Credits
        //    are attestation inclusion: a validator whose vote never landed
        //    earns nothing this epoch, forfeiting its slice (its delegators'
        //    exposure to that is what makes delegation a real choice).
        let first_slot = closing * SLOTS_PER_EPOCH;
        let mut epoch_issuance: u128 = 0;
        for s in first_slot..first_slot + SLOTS_PER_EPOCH {
            epoch_issuance += tokenomics_v4::validator_reward_decay_sat(s);
        }
        let total_stake: u128 = roster.iter().map(|v| v.effective_stake as u128).sum();
        if total_stake > 0 {
            for v in &roster {
                let attested = *st.current_participation.get(&v.index).unwrap_or(&false);
                // Stake basis is the CAPPED effective stake: stake above the
                // per-validator or cohort cap carries no weight and earns
                // nothing — the caps would be decorative otherwise. The
                // operator/delegator split of this payout happens where
                // per-delegator accounts exist (DEV-3's wallet surface);
                // consensus commits only the total, into the bond.
                let payout = rewards::distribute(
                    &StakeAccount {
                        self_stake: v.effective_stake as u128,
                        delegated_stake: 0,
                        commission_bps: 0,
                        credits: u64::from(attested),
                        max_credits: 1,
                    },
                    epoch_issuance,
                    total_stake,
                );
                if payout.operator > 0 {
                    if let Some(rec) = st.validators.get_mut(&v.index) {
                        rec.staked_sat += payout.operator;
                    }
                }
            }
        }
        // Fee rewards accrued during the epoch compound now, not per block —
        // see the field docs: effective stake is frozen within an epoch.
        let fees = std::mem::take(&mut st.pending_fee_rewards);
        for (idx, amount) in fees {
            if let Some(rec) = st.validators.get_mut(&idx) {
                rec.staked_sat += amount;
            }
        }

        // 3. Fix the boundary mix that seeds epoch E+1, and retain exactly
        //    the last 2 boundaries (§5.5).
        st.boundary_mixes.insert(closing, st.randao_mix);
        let keep_from = closing.saturating_sub(1);
        st.boundary_mixes.retain(|e, _| *e >= keep_from);

        // 4. Activation queue (staking.rs). Resolved by replaying the full
        //    committed history — the rule is stated once, in
        //    resolve_activations, and this is its only call site here.
        let next_epoch = closing + 1;
        for (pubkey_hash, activation_epoch) in
            staking::resolve_activations(&st.deposit_history, next_epoch)
        {
            if activation_epoch == next_epoch {
                if let Some(idx) = st.pubkey_index.get(&pubkey_hash) {
                    if let Some(rec) = st.validators.get_mut(idx) {
                        rec.activation_epoch = next_epoch;
                    }
                }
            }
        }
        // Exits need no active step: the roster filter
        // (activation ≤ e < exit) retires them at their recorded epoch.

        // 5. Open E+1. The cohort cap for the new epoch is applied inside
        //    duty_roster_at (genesis_cohort.rs closed form — rule 3).
        st.epoch = next_epoch;
        st.pending_votes.clear();
        let roster_next = st.duty_roster_at(next_epoch);
        st.previous_participation = std::mem::take(&mut st.current_participation);
        for v in &roster_next {
            st.current_participation.insert(v.index, false);
        }

        // 6. The next epoch's committee partition. Derived, not stored — a
        //    stored partition is a cache (§5.5) — but computed once here to
        //    pin, at the boundary, that it is fully determined by committed
        //    state and covers every eligible validator exactly once.
        let partition =
            committees::epoch_committees(&st.seed_for_epoch(next_epoch), next_epoch, &roster_next);
        debug_assert_eq!(
            partition.iter().map(Vec::len).sum::<usize>(),
            roster_next.iter().filter(|v| v.effective_stake > 0).count(),
            "epoch partition must cover the eligible set exactly once"
        );

        st
    }
}

/// Narrow a `u128` stake to the `u64` the sampling layer carries. Saturating,
/// never wrapping: unreachable at the V4 supply scale for a single bond, and
/// present only so a refactor cannot introduce a silent wrap.
fn sat_u64(x: u128) -> u64 {
    if x > u64::MAX as u128 {
        u64::MAX
    } else {
        x as u64
    }
}

impl StateReader for CommittedState {
    fn slot(&self) -> u64 {
        self.slot
    }

    fn state_root(&self) -> [u8; 32] {
        self.compute_root()
    }

    fn active_validators(&self) -> Vec<Validator> {
        self.duty_roster()
    }

    fn validator_record(&self, index: u32) -> Option<ValidatorRecord> {
        self.validators.get(&index).cloned()
    }

    fn total_active_stake_sat(&self) -> u128 {
        self.duty_roster().iter().map(|v| v.effective_stake as u128).sum()
    }

    fn randao_mix(&self) -> [u8; 32] {
        self.randao_mix
    }

    fn randao_mix_at(&self, epoch: u64) -> Option<[u8; 32]> {
        self.boundary_mixes.get(&epoch).copied()
    }

    fn finality(&self) -> FinalityView {
        self.finality_view()
    }
}

// ─── The transition ─────────────────────────────────────────────────────────

/// The state transition function. Carries only genesis-fixed configuration —
/// the injected signature verifier — per the interfaces' purity contract:
/// no clock, no cache, no handle to anything mutable.
pub struct Transition<V: SignatureVerifier> {
    verifier: V,
}

impl<V: SignatureVerifier> Transition<V> {
    pub fn new(verifier: V) -> Self {
        Transition { verifier }
    }

    /// Run the whole transition *except* the final root comparison, returning
    /// the would-be child state. This is the proposer's API: a block builder
    /// needs exactly this state to fill `state_root` (and `randao_mix`) in
    /// the header it is about to sign. `apply_block` is this plus the check.
    pub fn compute_post_state(
        &self,
        pre: &CommittedState,
        envelope: &ProposalEnvelope,
        attestations: &[Attestation],
        transactions: &[PosTransaction],
    ) -> Result<CommittedState, TransitionError> {
        let header = &envelope.header;

        // 1. Slot must advance (double-apply of a block to its own
        //    post-state lands here — a reject by decision, see module docs).
        if header.slot <= pre.slot {
            return Err(TransitionError::NonMonotonicSlot);
        }
        let block_epoch = crate::epoch_of(header.slot);
        // A block in an epoch the caller already processed past is the same
        // defect: time ran backwards relative to the accounting.
        if block_epoch < pre.epoch {
            return Err(TransitionError::NonMonotonicSlot);
        }
        // 2. The block must extend exactly the state it is applied to.
        if header.parent != pre.head {
            return Err(TransitionError::WrongParent);
        }
        // 3. Version.
        if header.version != BLOCK_VERSION_V4 {
            return Err(TransitionError::Proposal(ProposalReject::WrongVersion));
        }

        // Roll epoch accounting over any empty boundary slots the chain
        // skipped. Identical to the caller invoking process_epoch itself —
        // close_epoch is the single definition of the boundary — so explicit
        // and implicit epoch processing cannot diverge.
        let mut st = pre.clone();
        while st.epoch < block_epoch {
            st = st.close_epoch();
        }

        let roster = st.duty_roster();
        let seed = st.seed_for_epoch(st.epoch);

        // 4. The proposer must be the validator drawn for this slot
        //    (schedule.rs) — a hash away, checked before any signature.
        match schedule::proposer(&seed, header.slot, &roster) {
            Some(p) if p == header.proposer_index => {}
            _ => return Err(TransitionError::Proposal(ProposalReject::NotScheduledProposer)),
        }

        // 5. RANDAO (beacon.rs): the reveal must open the proposer's
        //    committed chain head, and the header's mix must be exactly the
        //    fold of that reveal into the parent mix — the header may not
        //    carry a mix the reveal does not produce.
        let proposer_rec = match st.validators.get(&header.proposer_index) {
            Some(r) => r.clone(),
            // Unreachable: the roster only drew registered validators. Total
            // anyway — a consensus path must not panic on any input.
            None => return Err(TransitionError::Proposal(ProposalReject::NotScheduledProposer)),
        };
        let reveal_state = RevealState {
            commitment: proposer_rec.randao_commitment,
            reveals_used: *st.reveals_used.get(&header.proposer_index).unwrap_or(&0),
        };
        let (next_reveal_state, next_mix) =
            match beacon::process_reveal(&reveal_state, &st.randao_mix, &header.randao_reveal) {
                Ok(ok) => ok,
                Err(_) => return Err(TransitionError::Proposal(ProposalReject::BadRandaoReveal)),
            };
        if header.randao_mix != next_mix {
            return Err(TransitionError::Proposal(ProposalReject::BadRandaoReveal));
        }
        if let Some(rec) = st.validators.get_mut(&header.proposer_index) {
            rec.randao_commitment = next_reveal_state.commitment;
        }
        st.reveals_used.insert(header.proposer_index, next_reveal_state.reveals_used);
        st.randao_mix = next_mix;

        // 6. Finality consistency: the header must carry exactly the
        //    parent-committed justified/finalized roots. Exact equality is
        //    the only rule with no room for interpretation — anything looser
        //    would let a proposer carry stale finality, and a block may never
        //    un-finalize anything.
        let fin = st.finality_view();
        if header.justified_root != fin.justified.root
            || header.finalized_root != fin.finalized.root
        {
            return Err(TransitionError::FinalityRegression);
        }

        // 7. The proposer's signature — one hybrid verify, after every cheap
        //    check and before the N attestation verifies.
        if !self.verifier.verify(
            header.proposer_index,
            &proposal_signing_root(header),
            &envelope.proposer_sig,
        ) {
            return Err(TransitionError::Proposal(ProposalReject::BadSignature));
        }

        // 8. Attestations, against the slot committee (committees.rs +
        //    attestation.rs). Only current-epoch slots are decidable from
        //    retained state (the 2-epoch mix window), so only they are
        //    admissible; membership is checked before each signature inside
        //    attestation::validate (its DoS ordering, not re-decided here).
        for (i, att) in attestations.iter().enumerate() {
            let reject = TransitionError::Attestation(i as u32);
            if crate::epoch_of(att.data.slot) != st.epoch {
                return Err(reject);
            }
            let committee = committees::committee_for_slot(&seed, att.data.slot, &roster);
            if attestation::validate(att, &committee, header.slot, &self.verifier).is_err() {
                return Err(reject);
            }
            // A validated, included attestation is participation — the fact
            // rewards and the committed participation component both read.
            st.current_participation.insert(att.validator, true);
            // Collected for the epoch's finality tally. Keyed by content, so
            // the committed set is independent of inclusion order (rule 2);
            // the finality engine is the sole judge of what the votes mean.
            st.pending_votes.insert((att.validator, att.data.signing_root()), att.data);
        }

        // 9. Fork-choice weight accumulation (forkchoice.rs).
        st.accumulate_forkchoice(&roster, attestations);

        // 10. Transactions — cheap state-dependent rules only (see
        //     PosTransaction docs for where the crypto checks live).
        let total_active: u128 = roster.iter().map(|v| v.effective_stake as u128).sum();
        let mut base_fees: u128 = 0;
        let mut priority_fees: u128 = 0;
        for (i, tx) in transactions.iter().enumerate() {
            match st.apply_transaction(tx, total_active) {
                Ok((b, p)) => {
                    base_fees += b;
                    priority_fees += p;
                }
                Err(()) => return Err(TransitionError::Transaction(i as u32)),
            }
        }

        // 11. Rewards (rewards.rs): the block's fee split. The producer's
        //     share accrues and compounds at the epoch boundary; the burned
        //     share is burned by never being credited to anyone.
        let split = rewards::split_fees_at(base_fees, priority_fees, header.slot);
        if split.to_producer > 0 {
            *st.pending_fee_rewards.entry(header.proposer_index).or_insert(0) +=
                split.to_producer;
        }

        st.slot = header.slot;
        st.head = block_id(header);
        Ok(st)
    }
}

impl<V: SignatureVerifier> StateTransition for Transition<V> {
    type State = CommittedState;
    type Transaction = PosTransaction;

    fn apply_block(
        &self,
        pre: &Self::State,
        envelope: &ProposalEnvelope,
        attestations: &[Attestation],
        transactions: &[Self::Transaction],
    ) -> Result<Self::State, TransitionError> {
        let post = self.compute_post_state(pre, envelope, attestations, transactions)?;
        // 12. The root, last: it only exists once the whole transition ran,
        //     and it binds the header to the child state bit-for-bit.
        if post.compute_root() != envelope.header.state_root {
            return Err(TransitionError::StateRootMismatch);
        }
        Ok(post)
    }

    fn process_epoch(&self, pre: &Self::State) -> Result<Self::State, TransitionError> {
        // Infallible by construction: the boundary must be processable even
        // when the slot was empty, or a withheld proposal becomes a lever
        // over everyone's accounting.
        Ok(pre.close_epoch())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::RandaoChain;

    /// Accept-everything verifier: these tests exercise the transition's
    /// composition and ordering, not the PQ stack (which this crate never
    /// links — the same reasoning as attestation.rs).
    struct OkVerifier;
    impl SignatureVerifier for OkVerifier {
        fn verify(&self, _v: u32, _root: &[u8; 32], _sig: &[u8]) -> bool {
            true
        }
    }

    fn sat(bloch: u128) -> u128 {
        bloch * tokenomics_v4::SAT_PER_BLOCH
    }

    fn setup(n: u32) -> (Transition<OkVerifier>, CommittedState, Vec<RandaoChain>) {
        let mut chains = Vec::new();
        let mut vals = Vec::new();
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            seed[1] = 0x5A;
            let chain = RandaoChain::generate(seed);
            vals.push(GenesisValidator {
                index: i,
                pubkey: vec![i as u8; 8],
                staked_sat: sat(200_000),
                randao_commitment: chain.commitment(),
                withdrawal_credentials: vec![i as u8; 4],
            });
            chains.push(chain);
        }
        let st = CommittedState::genesis(
            BlockId([0x60; 32]),
            [0x07; 32],
            &vals,
            &[],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
        );
        (Transition::new(OkVerifier), st, chains)
    }

    /// Build a valid block at `slot` on top of `pre`, consuming the drawn
    /// proposer's next reveal — the same walk a real validator client does.
    fn build_block(
        t: &Transition<OkVerifier>,
        pre: &CommittedState,
        slot: u64,
        atts: &[Attestation],
        txs: &[PosTransaction],
        chains: &mut [RandaoChain],
    ) -> ProposalEnvelope {
        // The builder's context is the parent state rolled over any epoch
        // boundaries the block crosses — exactly what apply_block will do.
        let mut ctx = pre.clone();
        while ctx.epoch < crate::epoch_of(slot) {
            ctx = ctx.close_epoch();
        }
        let roster = ctx.duty_roster();
        let seed = ctx.seed_for_epoch(ctx.epoch);
        let p = schedule::proposer(&seed, slot, &roster).expect("no eligible proposer");
        let reveal = chains[p as usize].next_reveal().expect("chain spent");
        let mix = beacon::mix_in(&ctx.randao_mix, &reveal);
        let fin = ctx.finality_view();
        let mut header = BlockHeaderV4 {
            version: BLOCK_VERSION_V4,
            parent: pre.head,
            state_root: [0u8; 32],
            body_root: [0u8; 32],
            slot,
            proposer_index: p,
            randao_reveal: reveal,
            randao_mix: mix,
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: [0u8; 32],
            coherence_root: [0u8; 32],
        };
        let probe = ProposalEnvelope { header, proposer_sig: vec![0u8; 8] };
        let post = t
            .compute_post_state(pre, &probe, atts, txs)
            .expect("builder produced an untransitionable block");
        header.state_root = post.state_root();
        ProposalEnvelope { header, proposer_sig: vec![0u8; 8] }
    }

    /// One attestation from `v` for `slot`, voting `target_root` as both head
    /// and target, sourcing the state's current justified checkpoint.
    fn attest(st: &CommittedState, v: u32, slot: u64, target_root: [u8; 32]) -> Attestation {
        let fin = st.finality_view();
        Attestation {
            data: AttestationData {
                slot,
                head: target_root,
                source_epoch: fin.justified.epoch,
                source_root: fin.justified.root.0,
                target_epoch: crate::epoch_of(slot),
                target_root,
            },
            validator: v,
            signature: vec![0u8; 8],
        }
    }

    /// Every validator's attestation for its own partition slot in the
    /// state's current epoch, targeting `target_root`.
    fn full_epoch_attestations(st: &CommittedState, target_root: [u8; 32]) -> Vec<Attestation> {
        let roster = st.duty_roster();
        let seed = st.seed_for_epoch(st.epoch);
        let partition = committees::epoch_committees(&seed, st.epoch, &roster);
        let first = st.epoch * SLOTS_PER_EPOCH;
        let mut out = Vec::new();
        for (i, committee) in partition.iter().enumerate() {
            for member in committee {
                out.push(attest(st, *member, first + i as u64, target_root));
            }
        }
        out
    }

    // ── the required test list ──────────────────────────────────────────────

    #[test]
    fn valid_block_applies() {
        let (t, g, mut chains) = setup(4);
        let b1 = build_block(&t, &g, 1, &[], &[], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[]).expect("valid block rejected");

        assert_eq!(s1.slot(), 1);
        assert_eq!(s1.head(), block_id(&b1.header));
        assert_ne!(s1.randao_mix(), g.randao_mix(), "the reveal must move the mix");
        assert_eq!(s1.state_root(), b1.header.state_root);
        // The proposer's chain advanced exactly one step in committed state.
        assert_eq!(*s1.reveals_used.get(&b1.header.proposer_index).unwrap(), 1);
        // And a second block chains on the first.
        let b2 = build_block(&t, &s1, 2, &[], &[], &mut chains);
        let s2 = t.apply_block(&s1, &b2, &[], &[]).expect("second block rejected");
        assert_eq!(s2.slot(), 2);
    }

    #[test]
    fn wrong_proposer_rejected() {
        let (t, g, mut chains) = setup(4);
        let roster = g.duty_roster();
        let seed = g.seed_for_epoch(0);
        let designated = schedule::proposer(&seed, 1, &roster).unwrap();
        let wrong = (designated + 1) % 4;
        let reveal = chains[wrong as usize].next_reveal().unwrap();
        let fin = g.finality_view();
        let header = BlockHeaderV4 {
            version: BLOCK_VERSION_V4,
            parent: g.head,
            state_root: [0u8; 32],
            body_root: [0u8; 32],
            slot: 1,
            proposer_index: wrong,
            randao_reveal: reveal,
            randao_mix: beacon::mix_in(&g.randao_mix, &reveal),
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: [0u8; 32],
            coherence_root: [0u8; 32],
        };
        let env = ProposalEnvelope { header, proposer_sig: vec![0u8; 8] };
        assert_eq!(
            t.apply_block(&g, &env, &[], &[]),
            Err(TransitionError::Proposal(ProposalReject::NotScheduledProposer)),
        );
    }

    #[test]
    fn bad_randao_reveal_rejected() {
        let (t, g, mut chains) = setup(4);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        // A forged reveal: not the committed preimage.
        b.header.randao_reveal = [0x99; 32];
        b.header.randao_mix = beacon::mix_in(&g.randao_mix, &b.header.randao_reveal);
        assert_eq!(
            t.apply_block(&g, &b, &[], &[]),
            Err(TransitionError::Proposal(ProposalReject::BadRandaoReveal)),
        );
    }

    #[test]
    fn correct_reveal_but_wrong_mix_field_rejected() {
        let (t, g, mut chains) = setup(4);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        // The reveal opens the commitment, but the header lies about the
        // resulting mix — the header may not carry a mix the reveal does not
        // produce.
        b.header.randao_mix[0] ^= 1;
        assert_eq!(
            t.apply_block(&g, &b, &[], &[]),
            Err(TransitionError::Proposal(ProposalReject::BadRandaoReveal)),
        );
    }

    #[test]
    fn non_member_attestation_rejected() {
        let (t, g, mut chains) = setup(8);
        // Move into epoch 1 so attestations are expressible (an epoch-0
        // target cannot satisfy source < target — genesis is already final).
        let b1 = build_block(&t, &g, 32, &[], &[], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[]).unwrap();

        // Find a slot whose committee excludes some validator, and have that
        // outsider attest it.
        let roster = s1.duty_roster();
        let seed = s1.seed_for_epoch(1);
        let partition = committees::epoch_committees(&seed, 1, &roster);
        let (slot_idx, committee) = partition
            .iter()
            .enumerate()
            .find(|(_, c)| !c.is_empty())
            .expect("some slot must have a committee");
        let outsider = (0..8).find(|v| !committee.contains(v)).expect("8 > committee size");
        let att = attest(&s1, outsider, 32 + slot_idx as u64, s1.head().0);

        let b2 = {
            // Build the block by hand: the builder helper would refuse a
            // block that cannot transition.
            let roster = s1.duty_roster();
            let p = schedule::proposer(&seed, 63, &roster).unwrap();
            let reveal = chains[p as usize].next_reveal().unwrap();
            let fin = s1.finality_view();
            let header = BlockHeaderV4 {
                version: BLOCK_VERSION_V4,
                parent: s1.head,
                state_root: [0u8; 32],
                body_root: [0u8; 32],
                slot: 63,
                proposer_index: p,
                randao_reveal: reveal,
                randao_mix: beacon::mix_in(&s1.randao_mix, &reveal),
                justified_root: fin.justified.root,
                finalized_root: fin.finalized.root,
                attestation_root: [0u8; 32],
                coherence_root: [0u8; 32],
            };
            ProposalEnvelope { header, proposer_sig: vec![0u8; 8] }
        };
        assert_eq!(
            t.apply_block(&s1, &b2, std::slice::from_ref(&att), &[]),
            Err(TransitionError::Attestation(0)),
        );
    }

    #[test]
    fn state_root_mismatch_rejected() {
        let (t, g, mut chains) = setup(4);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        b.header.state_root[0] ^= 1;
        assert_eq!(t.apply_block(&g, &b, &[], &[]), Err(TransitionError::StateRootMismatch));
    }

    #[test]
    fn finality_regression_rejected() {
        let (t, g, mut chains) = setup(4);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        b.header.finalized_root = BlockId([0xEE; 32]);
        assert_eq!(t.apply_block(&g, &b, &[], &[]), Err(TransitionError::FinalityRegression));
    }

    #[test]
    fn wrong_parent_rejected() {
        let (t, g, mut chains) = setup(4);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        b.header.parent = BlockId([0xFF; 32]);
        assert_eq!(t.apply_block(&g, &b, &[], &[]), Err(TransitionError::WrongParent));
    }

    #[test]
    fn double_apply_is_rejected_and_reapply_to_parent_is_deterministic() {
        let (t, g, mut chains) = setup(4);
        let b = build_block(&t, &g, 1, &[], &[], &mut chains);
        let s1 = t.apply_block(&g, &b, &[], &[]).unwrap();

        // DECISION (module docs): applying a block to its own post-state is a
        // reject, not a no-op — the post-state of B is not B's parent, and a
        // silent no-op would mask the caller's wiring bug.
        assert_eq!(t.apply_block(&s1, &b, &[], &[]), Err(TransitionError::NonMonotonicSlot));

        // The idempotence that matters: the same (parent, block) pair yields
        // a bit-identical child every time — the function is pure.
        let s1_again = t.apply_block(&g, &b, &[], &[]).unwrap();
        assert_eq!(s1, s1_again);
        assert_eq!(s1.state_root(), s1_again.state_root());
    }

    #[test]
    fn justification_and_finality_advance_across_epochs() {
        let (t, g, mut chains) = setup(8);

        // Epoch 1's checkpoint: its first block.
        let b1 = build_block(&t, &g, 32, &[], &[], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[]).unwrap();
        let cp1 = s1.head();

        // Every validator votes its partition slot, targeting cp1; the
        // epoch's last block carries the whole quorum.
        let atts1 = full_epoch_attestations(&s1, cp1.0);
        let b2 = build_block(&t, &s1, 63, &atts1, &[], &mut chains);
        let s2 = t.apply_block(&s1, &b2, &atts1, &[]).unwrap();
        // Everyone's participation is recorded.
        assert!(s2.current_participation.values().all(|a| *a));

        // Crossing into epoch 2 closes epoch 1: 8/8 stake ≥ 2/3 justifies.
        let b3 = build_block(&t, &s2, 64, &[], &[], &mut chains);
        let s3 = t.apply_block(&s2, &b3, &[], &[]).unwrap();
        assert_eq!(s3.finality().justified, Checkpoint { epoch: 1, root: cp1 });
        assert_eq!(s3.finality().finalized.epoch, 0, "one justification finalizes nothing yet");
        let cp2 = s3.head();

        // Epoch 2 votes source cp1 → target cp2; closing epoch 2 makes the
        // link consecutive, finalizing cp1.
        let atts2 = full_epoch_attestations(&s3, cp2.0);
        let b4 = build_block(&t, &s3, 95, &atts2, &[], &mut chains);
        let s4 = t.apply_block(&s3, &b4, &atts2, &[]).unwrap();
        let b5 = build_block(&t, &s4, 96, &[], &[], &mut chains);
        let s5 = t.apply_block(&s4, &b5, &[], &[]).unwrap();

        let fin = s5.finality();
        assert_eq!(fin.justified, Checkpoint { epoch: 2, root: cp2 });
        assert_eq!(fin.finalized, Checkpoint { epoch: 1, root: cp1 });
        assert_eq!(fin.previous_justified, Checkpoint { epoch: 1, root: cp1 });
    }

    #[test]
    fn replay_is_delivery_order_independent() {
        let (t, g, mut chains) = setup(8);

        // A chain with real content: a deposit, a delegation, and a full
        // attestation quorum.
        let deposit = PosTransaction::Deposit {
            pubkey: vec![0xAB; 8],
            amount_sat: staking::MIN_DEPOSIT_SAT,
            randao_commitment: [0xCD; 32],
            withdrawal_credentials: vec![0xEF; 4],
        };
        let delegate = PosTransaction::Delegate {
            delegator: 900,
            validator: 0,
            amount_sat: delegation::MIN_DELEGATION_SAT,
            eligible: true,
        };
        let b1 = build_block(&t, &g, 33, &[], &[deposit.clone()], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[deposit.clone()]).unwrap();
        let b2 = build_block(&t, &s1, 34, &[], &[delegate.clone()], &mut chains);
        let s2 = t.apply_block(&s1, &b2, &[], &[delegate.clone()]).unwrap();
        let atts = full_epoch_attestations(&s2, s1.head().0);
        let b3 = build_block(&t, &s2, 63, &atts, &[], &mut chains);
        let final_a = t.apply_block(&s2, &b3, &atts, &[]).unwrap();

        // Out-of-order delivery: a later block cannot apply early — the
        // parent check refuses it, so delivery order never reaches state.
        assert_eq!(
            t.apply_block(&g, &b2, &[], &[delegate.clone()]),
            Err(TransitionError::WrongParent),
        );

        // The caller buffers and replays in chain order: identical end state.
        let r1 = t.apply_block(&g, &b1, &[], &[deposit]).unwrap();
        let r2 = t.apply_block(&r1, &b2, &[], &[delegate]).unwrap();
        let final_b = t.apply_block(&r2, &b3, &atts, &[]).unwrap();
        assert_eq!(final_a, final_b);
        assert_eq!(final_a.state_root(), final_b.state_root());

        // And the attestation order *within* the carrier block is
        // immaterial: reversed list, same committed state (rule 2).
        let mut reversed = atts.clone();
        reversed.reverse();
        let final_c = t.apply_block(&r2, &b3, &reversed, &[]).unwrap();
        assert_eq!(final_a, final_c);
    }

    #[test]
    fn explicit_and_implicit_epoch_processing_agree() {
        let (t, g, mut chains) = setup(4);
        // A block two epochs ahead of genesis, over nothing but empty slots.
        let b = build_block(&t, &g, 2 * SLOTS_PER_EPOCH + 3, &[], &[], &mut chains);

        // Path A: the caller processed both empty boundaries explicitly.
        let e1 = t.process_epoch(&g).unwrap();
        let e2 = t.process_epoch(&e1).unwrap();
        assert_eq!(e2.epoch, 2);
        let s_explicit = t.apply_block(&e2, &b, &[], &[]).unwrap();

        // Path B: apply_block rolls the boundaries itself.
        let s_implicit = t.apply_block(&g, &b, &[], &[]).unwrap();

        assert_eq!(s_explicit, s_implicit);
    }

    #[test]
    fn epoch_processes_even_with_no_blocks_at_all() {
        let (t, g, _) = setup(4);
        // No block ever arrives; the boundary must still process — the
        // finality clock (and eventually the inactivity leak) ticks on empty
        // epochs too.
        let mut st = g;
        for _ in 0..6 {
            st = t.process_epoch(&st).unwrap();
        }
        assert_eq!(st.epoch, 6);
        // Boundary mixes retained: exactly the last 2.
        assert!(st.randao_mix_at(4).is_some());
        assert!(st.randao_mix_at(5).is_some());
        assert!(st.randao_mix_at(3).is_none());
    }

    #[test]
    fn deposit_queues_and_activates_through_the_epoch_pipeline() {
        let (t, g, mut chains) = setup(4);
        let deposit = PosTransaction::Deposit {
            pubkey: vec![0xAA; 8],
            amount_sat: staking::MIN_DEPOSIT_SAT,
            randao_commitment: [0xBB; 32],
            withdrawal_credentials: vec![0xCC; 4],
        };
        // Included during epoch 1.
        let b = build_block(&t, &g, 33, &[], std::slice::from_ref(&deposit), &mut chains);
        let mut st = t.apply_block(&g, &b, &[], std::slice::from_ref(&deposit)).unwrap();

        let new_index = 4u32;
        let rec = st.validator_record(new_index).expect("deposit must register a record");
        assert_eq!(rec.activation_epoch, u64::MAX, "not scheduled until the queue admits it");
        assert!(
            !st.active_validators().iter().any(|v| v.index == new_index),
            "a queued validator has no duties"
        );

        // Walk the boundaries to the activation epoch: deposit at epoch 1 →
        // eligible at 1 + ACTIVATION_DELAY_EPOCHS.
        let expected = 1 + staking::ACTIVATION_DELAY_EPOCHS;
        while st.epoch < expected {
            st = t.process_epoch(&st).unwrap();
        }
        let rec = st.validator_record(new_index).unwrap();
        assert_eq!(rec.activation_epoch, expected);
        assert!(
            st.active_validators().iter().any(|v| v.index == new_index),
            "activated validator must appear in the roster"
        );

        // A second deposit of the same pubkey is a deterministic reject.
        let dup = PosTransaction::Deposit {
            pubkey: vec![0xAA; 8],
            amount_sat: staking::MIN_DEPOSIT_SAT,
            randao_commitment: [0xDD; 32],
            withdrawal_credentials: vec![0xEE; 4],
        };
        let mut probe = st.clone();
        assert_eq!(probe.apply_transaction(&dup, 0), Err(()));
    }

    #[test]
    fn exit_schedules_duty_stop_and_withdrawal_delay() {
        let (t, g, mut chains) = setup(4);
        let exit = PosTransaction::Exit { validator: 0 };
        let b = build_block(&t, &g, 1, &[], std::slice::from_ref(&exit), &mut chains);
        let st = t.apply_block(&g, &b, &[], std::slice::from_ref(&exit)).unwrap();

        let rec = st.validator_record(0).unwrap();
        assert_eq!(rec.exit_epoch, staking::EXIT_DELAY_EPOCHS, "duties stop only after the delay");
        assert_eq!(
            rec.withdrawable_epoch,
            staking::EXIT_DELAY_EPOCHS + staking::WITHDRAWAL_DELAY_EPOCHS,
            "the weak-subjectivity margin counts from the exit epoch"
        );
        // Still on duty this epoch — an exit is not a same-epoch escape.
        assert!(st.active_validators().iter().any(|v| v.index == 0));
        // A second exit is rejected: the withdrawal clock must never reset.
        let mut probe = st.clone();
        assert_eq!(probe.apply_transaction(&exit, 0), Err(()));
    }

    #[test]
    fn fees_split_and_compound_only_at_the_boundary() {
        let (t, g, mut chains) = setup(4);
        let tx = PosTransaction::Transfer { base_fee_sat: 1_000, priority_fee_sat: 500 };
        let b = build_block(&t, &g, 1, &[], std::slice::from_ref(&tx), &mut chains);
        let s1 = t.apply_block(&g, &b, &[], std::slice::from_ref(&tx)).unwrap();
        let p = b.header.proposer_index;

        // During the epoch the fee accrues but the bond — and with it every
        // committee — is untouched.
        let before = s1.validator_record(p).unwrap().staked_sat;
        assert_eq!(before, sat(200_000));
        // Emission-era split: half the base fee burns, priority is whole.
        assert_eq!(*s1.pending_fee_rewards.get(&p).unwrap(), 1_000);

        // Nobody attested this epoch, so issuance is fully forfeited and the
        // boundary compounds exactly the fee share.
        let s2 = t.process_epoch(&s1).unwrap();
        assert_eq!(s2.validator_record(p).unwrap().staked_sat, sat(200_000) + 1_000);
        assert!(s2.pending_fee_rewards.is_empty());
    }

    #[test]
    fn genesis_cohort_cap_binds_at_the_floor() {
        // Direct roster check: one whale in the cohort, two outsiders. At
        // the one-year floor the closed form allows the cohort exactly half
        // of what everyone else holds (s/(1-s)·O at s = 1/3).
        let mut vals = Vec::new();
        let mut cohort_val = GenesisValidator {
            index: 0,
            pubkey: vec![0; 8],
            staked_sat: sat(9_000_000),
            randao_commitment: [0; 32],
            withdrawal_credentials: vec![0; 4],
        };
        vals.push(cohort_val.clone());
        for i in 1..3u32 {
            cohort_val.index = i;
            cohort_val.staked_sat = sat(1_000_000);
            cohort_val.pubkey = vec![i as u8; 8];
            vals.push(cohort_val.clone());
        }
        let st = CommittedState::genesis(
            BlockId([1; 32]),
            [2; 32],
            &vals,
            &[0],
            [0; 32],
            [0; 32],
            [0; 32],
        );
        let roster = st.duty_roster_at(genesis_cohort::COHORT_TAPER_EPOCHS);
        let cohort_stake =
            roster.iter().find(|v| v.index == 0).unwrap().effective_stake as u128;
        let others: u128 = roster
            .iter()
            .filter(|v| v.index != 0)
            .map(|v| v.effective_stake as u128)
            .sum();
        assert!(cohort_stake > 0, "the cap scales, it does not confiscate");
        assert!(
            cohort_stake <= others * genesis_cohort::COHORT_CAP_FLOOR_BPS
                / (10_000 - genesis_cohort::COHORT_CAP_FLOOR_BPS),
            "cohort must sit at or under the closed-form cap"
        );
        // And the share of the post-cap total is at most one third — the
        // point of the whole rule: the founder cannot stall finality alone.
        assert!(cohort_stake * 3 <= (cohort_stake + others) + 3, "≤ 1/3 of the capped total");
    }
}
