// SPDX-License-Identifier: AGPL-3.0-or-later

//! The state transition function — the composition layer (§5.5, Boundary 2).
//!
//! Every module in this crate states one rule; until now nothing composed
//! them. This module implements [`StateTransition`]: parent state × block →
//! child state, calling into `schedule`, `beacon`, `committees`,
//! `attestation`, `forkchoice`, `rewards`, `slashing` and `state_root` for
//! `apply_block`, and into `finality`, `staking`, `delegation` and
//! `genesis_cohort` for `process_epoch`. No consensus rule is *defined* here; this module only
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
//! ## The commitment covers the whole committed state (closed 2026-08-11)
//!
//! An earlier revision of this module honestly flagged a gap: the finality
//! bookkeeping, per-validator RANDAO chain positions (`reveals_used`), the
//! deposit/delegation queues, pending fee rewards and fork-choice latest
//! messages lived in [`CommittedState`] but not under the header's
//! `state_root`. That gap is now closed by the visible §5.5 component-list
//! extension (see [`crate::state_root`] module docs and interfaces
//! §Boundary 7): every one of those fields is committed, and
//! [`CommittedState::compute_root`] below is the single place the mapping
//! from state to components is defined.
//!
//! **One gap reopened in the same wave, and closed on 2026-08-12.** Slashing
//! was wired into the transition concurrently with the extension above, so its
//! state fell outside it. The slash's *effects* on the registry were committed,
//! so a state-synced node saw the outcome — but not the replay-protection set,
//! which is what stops the same evidence being applied twice, nor the
//! correlation window that prices the next offence. Two nodes could hold the
//! same headers and reach different verdicts on the same evidence. It is now
//! three components: `TAG_SLASH_APPLIED`, `TAG_SLASH_WINDOW` and
//! `TAG_DELEGATOR_SLASH_LOSS`.
//!
//! The `ejected` set stayed out, on purpose and with a test: it is exactly
//! `{v : registry[v].slashed}`, and the registry is already committed, so a
//! second leaf would commit one fact twice and let the copies drift. See
//! `tests::ejected_set_is_exactly_the_slashed_registry`.
//!
//! What remains **outside** the root by design stays outside for a stated
//! reason, not by omission — each entry carries the reconstruction argument
//! §5.5 demands:
//!
//! - `slot` and `head`: bound by the block header itself. `head` *cannot* be
//!   committed without circularity — it is the id of the very header that
//!   carries this root — and `slot` only changes when `head` does, so the
//!   header binds both. A state-synced node reads them from the header it
//!   trusted to get the root.
//! - `epoch`: committed, indirectly but bindingly — the running mix is a
//!   randao-history leaf whose entry key *is* the current epoch, so two
//!   states that differ only in epoch produce different roots (pinned by
//!   test).
//! - `genesis_mix` and `genesis_cohort`: genesis constants, immutable after
//!   the genesis block, part of chain identity exactly like the genesis id.
//!   The §5.5 failure shape requires *mutable* local state; a node that
//!   disagrees on these is on a different chain, not a diverged one.
//! - `pubkey_index`: a pure index over the committed registry
//!   (`SHA3-256(pubkey) → index`), reconstructible from the registry leaves
//!   alone.
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
    BlockId, Checkpoint, FinalityState as FinalityView, ProposalEnvelope,
    ProposalReject, SlashingEvidence, StateReader, StateTransition, TransitionError,
    ValidatorRecord,
};
use crate::params::SLOTS_PER_EPOCH;
use crate::rewards::{self, StakeAccount};
use crate::sample::Validator;
use crate::schedule;
use crate::slashing;
use crate::staking::{self, QueuedDeposit};
use crate::fee_market;
use crate::state_root::{
    AppliedEvidenceRecord, BaseFeeRecord, CheckpointRecord, ConsensusState, DelegatorFeeRecord, DelegatorLossRecord, SlashWindowRecord, DelegationRecord, DepositQueueRecord, EvmCommitment, FcEquivocatorRecord, FcMessageRecord, FinalityRecord, LeakRecord, ParticipationRecord, PendingFeeRecord, PendingVoteRecord, RandaoMix, ValidatorRecord as CommittedValidatorRecord,
};
use crate::tokenomics_v4;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// The Genesis-4 block version (§5.3), re-exported so this module's readers
/// see the same constant the header encoder stamps.
pub use crate::header::VERSION_G4 as BLOCK_VERSION_V4;

// ─── Header identity: DELEGATED, never re-derived here ─────────────────────
//
// This module carried its own `canonical_header_bytes` / `block_id` /
// `proposal_signing_root` as an interim shim while `header.rs` was written in
// parallel. Both landed, and for a while the crate had two byte layouts for
// one header and two ways to derive one id — a self-inflicted instance of the
// exact `pow_hash`/`block_hash` split that stalled the live chain. The shim is
// gone: identity comes from `BlockId::of` and the signing root from
// `BlockHeaderV4::proposal_signing_root`, and there is no second copy to drift.

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
    /// An opaque value transfer, priced by the L1 fee market: **gas × price**,
    /// where the gas is derived (class + size, `fee_market::intrinsic_gas`)
    /// and the price is the base fee this block's committed state fixes.
    ///
    /// This variant used to read `Transfer { base_fee_sat, priority_fee_sat }`
    /// — a transaction that declared, in satoshis, what it felt like paying.
    /// That is not a placeholder for a fee market, it is the absence of one:
    /// nothing constrained the number, so a proposer could include a transfer
    /// claiming any fee at all and compound it into its own bond. Changing the
    /// variant changes `canonical_bytes`, therefore `body_root`, therefore the
    /// block id — a consensus change, pinned by
    /// `tests::transfer_encoding_is_gas_priced_not_declared`.
    Transfer {
        /// eUTXO inputs, each costing one hybrid verification. The class term
        /// of the gas charge; nothing else about the transfer is consensus at
        /// this layer (§1.2 — the value format stays out of scope).
        inputs: u32,
        /// Payload bytes this transaction makes every node carry and store.
        /// The dominant gas term for PQ-signed traffic, and the quantity the
        /// block's byte cap is measured against.
        tx_bytes: u64,
        /// The sender's tip, in millisatoshi per gas. The **only** user-set
        /// price in the system: the base fee is the protocol's.
        tip_millisat_per_gas: u128,
    },
    /// Register a validator (§7.1). PoP/taint already checked at admission.
    Deposit {
        /// Suite-tagged hybrid public key (opaque bytes, per the interfaces).
        pubkey: Vec<u8>,
        amount_sat: u128,
        /// `c_0`, head of the SHAKE-256 reveal chain (§6.3).
        randao_commitment: [u8; 32],
        withdrawal_credentials: Vec<u8>,
        /// Commission this operator will charge on its delegators' rewards,
        /// in basis points. Declared at registration and committed with the
        /// record, so a delegator picking an operator is picking a rate that
        /// consensus agrees on — not one an operator asserts off-chain.
        /// Uncapped by consensus, per `rewards::MAX_COMMISSION_BPS`'s
        /// rationale: a cap is evaded by a front-end, a visible rate is
        /// priced by delegators.
        commission_bps: u128,
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
    /// A §7.3 evidence transaction: two conflicting signed messages proving
    /// one validator equivocated (a header pair or an attestation pair —
    /// [`crate::interfaces::SlashingEvidence`] is the frozen wire shape).
    ///
    /// Carried whole and **re-verified by every node** in
    /// [`slashing::SlashingState::process`]/`process_proposer` — the reporter
    /// is never trusted, so forged evidence cannot eject an honest validator
    /// and a replayed pair (either order) is a deterministic reject. Unlike
    /// every other transaction, its admission checks run *inside* the
    /// transition, not at the mempool boundary: whether evidence is fresh is
    /// a question about committed state (the applied-set), which only the
    /// transition holds.
    ///
    /// The offence itself may be arbitrarily old: evidence stays prosecutable
    /// for as long as the offender's stake is reachable, which is exactly
    /// what the withdrawal delay (the weak-subjectivity margin, §7.2) exists
    /// to guarantee. No committee-membership check is imposed on the two
    /// messages, deliberately — old epochs' committees are no longer
    /// derivable from retained state (2-epoch mix window), and a signed
    /// conflict is hostile whether or not the signer was on duty.
    SlashingEvidence(SlashingEvidence),
}

impl PosTransaction {
    /// The canonical wire encoding of a consensus transaction — the bytes the
    /// header's `body_root` is a Merkle root over.
    ///
    /// # Why this had to exist
    ///
    /// `derive::body_root` takes `&[Vec<u8>]` and has always been able to
    /// compute a body root; the transition, which holds typed
    /// `PosTransaction`s, had no way to produce those bytes. So the stack the
    /// node actually runs **never checked `body_root` at all** — a header
    /// could carry any value in that field and be accepted. What that costs is
    /// not that arbitrary transactions execute (the `state_root` check at the
    /// end catches a body that changes state differently), it is that the
    /// header stops committing to the body: one `BlockId` could name two
    /// different bodies, one valid and one garbage. An attacker gossips the
    /// honest header with a mangled body, every node rejects the pair, and any
    /// node that remembers rejections by block id then refuses the honest body
    /// too. Identity that does not cover the payload is the same defect family
    /// as `pow_hash`/`block_hash`, one layer down.
    ///
    /// # Scope, stated honestly
    ///
    /// The eUTXO value-transfer format is out of the migration's scope (§1.2),
    /// so [`PosTransaction::Transfer`] is opaque *here* by design: consensus
    /// at this layer needs its **fee-market inputs** — the class term
    /// (`inputs`), the size term (`tx_bytes`) and the tip — and those are what
    /// is encoded. It does not encode a fee: the fee is derived, from these
    /// and from the committed base fee. When the real transfer format lands it
    /// must supply its own canonical bytes and this arm becomes a delegation
    /// to them — the discriminant tag makes that a widening rather than a
    /// re-keying, because no other variant's encoding shifts.
    ///
    /// # Rules the encoding obeys
    ///
    /// One-byte discriminant first, then fixed-width little-endian fields in
    /// declaration order, with every variable-length field length-prefixed.
    /// Together those give injectivity: no two distinct transactions share an
    /// encoding, which is what makes the Merkle root over them meaningful. The
    /// nested signed messages inside slashing evidence are folded in through
    /// the roots they were *signed over* (`proposal_signing_root`,
    /// `AttestationData::signing_root`) plus their signatures, rather than
    /// re-serialised here — a second encoding of a header is exactly the kind
    /// of duplicate derivation this crate exists to refuse.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let put = |b: &mut Vec<u8>, bytes: &[u8]| {
            b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            b.extend_from_slice(bytes);
        };
        match self {
            PosTransaction::Transfer { inputs, tx_bytes, tip_millisat_per_gas } => {
                b.push(0x01);
                b.extend_from_slice(&inputs.to_le_bytes());
                b.extend_from_slice(&tx_bytes.to_le_bytes());
                b.extend_from_slice(&tip_millisat_per_gas.to_le_bytes());
            }
            PosTransaction::Deposit {
                pubkey,
                amount_sat,
                randao_commitment,
                withdrawal_credentials,
                commission_bps,
            } => {
                b.push(0x02);
                put(&mut b, pubkey);
                b.extend_from_slice(&amount_sat.to_le_bytes());
                b.extend_from_slice(randao_commitment);
                put(&mut b, withdrawal_credentials);
                b.extend_from_slice(&commission_bps.to_le_bytes());
            }
            PosTransaction::Exit { validator } => {
                b.push(0x03);
                b.extend_from_slice(&validator.to_le_bytes());
            }
            PosTransaction::Delegate { delegator, validator, amount_sat, eligible } => {
                b.push(0x04);
                b.extend_from_slice(&delegator.to_le_bytes());
                b.extend_from_slice(&validator.to_le_bytes());
                b.extend_from_slice(&amount_sat.to_le_bytes());
                b.push(u8::from(*eligible));
            }
            PosTransaction::SlashingEvidence(ev) => {
                b.push(0x05);
                match ev {
                    crate::interfaces::SlashingEvidence::ProposerEquivocation { first, second } => {
                        b.push(0x01);
                        for env in [first, second] {
                            b.extend_from_slice(&env.header.proposal_signing_root());
                            put(&mut b, &env.proposer_sig);
                        }
                    }
                    crate::interfaces::SlashingEvidence::AttestationOffence { first, second } => {
                        b.push(0x02);
                        for att in [first, second] {
                            b.extend_from_slice(&att.validator.to_le_bytes());
                            b.extend_from_slice(&att.data.signing_root());
                            put(&mut b, &att.signature);
                        }
                    }
                }
            }
        }
        b
    }

    /// Inverse of [`canonical_bytes`](Self::canonical_bytes) for the four
    /// user-submittable variants.
    ///
    /// A block body carries transactions as opaque bytes and `body_root`
    /// commits to exactly those bytes, so a node that receives a block must
    /// recover the same values the proposer encoded or it computes a different
    /// post-state from the same block. That makes this function consensus, not
    /// convenience: it has to be the exact inverse, and
    /// `tests::canonical_bytes_round_trips` pins it against the encoder rather
    /// than against a hand-written expectation.
    ///
    /// # Why `SlashingEvidence` is not decodable, and is not an oversight
    ///
    /// The evidence arm deliberately folds its nested messages in through the
    /// roots they were *signed over* plus their signatures — it never
    /// re-serialises the header or the attestation. A signing root is a hash;
    /// nothing recovers the envelope from it. So evidence encoded this way is
    /// one-way by construction, and this returns
    /// [`TxDecodeError::EvidenceNotDecodable`] for tag `0x05` instead of
    /// pretending otherwise.
    ///
    /// The consequence is worth stating plainly, because it bounds what the
    /// slashing pipeline can be built on: evidence cannot reach a verifier
    /// through `body.transactions`, since the verifier would have only hashes
    /// to re-verify against. Evidence needs its own wire shape carrying the
    /// two envelopes whole. Until that exists, the §7.3 path is unreachable
    /// from the network however complete `slashing.rs` is.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TxDecodeError> {
        let mut r = TxReader { b: bytes, i: 0 };
        let tag = r.u8()?;
        let tx = match tag {
            0x01 => PosTransaction::Transfer {
                inputs: r.u32()?,
                tx_bytes: r.u64()?,
                tip_millisat_per_gas: r.u128()?,
            },
            0x02 => PosTransaction::Deposit {
                pubkey: r.bytes()?,
                amount_sat: r.u128()?,
                randao_commitment: r.h32()?,
                withdrawal_credentials: r.bytes()?,
                commission_bps: r.u128()?,
            },
            0x03 => PosTransaction::Exit { validator: r.u32()? },
            0x04 => PosTransaction::Delegate {
                delegator: r.u32()?,
                validator: r.u32()?,
                amount_sat: r.u128()?,
                eligible: match r.u8()? {
                    0 => false,
                    1 => true,
                    // Injectivity cuts both ways: if `true` had two encodings
                    // the same transaction would have two body roots.
                    other => return Err(TxDecodeError::NotCanonical(other)),
                },
            },
            0x05 => return Err(TxDecodeError::EvidenceNotDecodable),
            other => return Err(TxDecodeError::UnknownTag(other)),
        };
        // Trailing bytes would mean two encodings decode to one transaction,
        // which breaks the injectivity `body_root` depends on.
        if r.i != r.b.len() {
            return Err(TxDecodeError::TrailingBytes);
        }
        Ok(tx)
    }
}

/// Why a transaction's canonical bytes could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDecodeError {
    /// Ran out of input mid-field.
    Truncated,
    /// Discriminant this build does not know.
    UnknownTag(u8),
    /// Tag `0x05`: one-way by construction — see
    /// [`PosTransaction::from_canonical_bytes`].
    EvidenceNotDecodable,
    /// A field carried a value with more than one encoding (e.g. a bool that
    /// is neither 0 nor 1).
    NotCanonical(u8),
    /// Decoded a whole transaction and input remained.
    TrailingBytes,
}

impl core::fmt::Display for TxDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TxDecodeError::Truncated => write!(f, "transaction truncated"),
            TxDecodeError::UnknownTag(t) => write!(f, "unknown transaction tag {t:#04x}"),
            TxDecodeError::EvidenceNotDecodable => write!(
                f,
                "slashing evidence is encoded one-way (signing roots, not envelopes) \
                 and cannot be recovered from a block body"
            ),
            TxDecodeError::NotCanonical(v) => write!(f, "non-canonical field value {v}"),
            TxDecodeError::TrailingBytes => write!(f, "trailing bytes after transaction"),
        }
    }
}

/// Little-endian reader mirroring the encoder's field order and widths.
struct TxReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> TxReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxDecodeError> {
        let end = self.i.checked_add(n).ok_or(TxDecodeError::Truncated)?;
        let s = self.b.get(self.i..end).ok_or(TxDecodeError::Truncated)?;
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, TxDecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, TxDecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, TxDecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> Result<u128, TxDecodeError> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn h32(&mut self) -> Result<[u8; 32], TxDecodeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, TxDecodeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
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
    /// Commission charged on delegators' rewards, in basis points. Published
    /// in the genesis block like every other registry column, so a delegator
    /// choosing an operator at launch is choosing a committed rate.
    pub commission_bps: u128,
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
    /// frozen [`FinalityView`] (Casper's two-round rule relates the current
    /// justification to this one). Honest scope note: the wired surround-vote
    /// slashing does NOT read it — the Casper surround predicate
    /// (`s1 < s2 ∧ t2 < t1`, `AttestationData::surrounds`) is a property of
    /// the evidence pair alone, decidable with no history at all, which is
    /// what lets old offences stay prosecutable after the epoch's context is
    /// gone. This field is the finality bookkeeping, not a slashing input.
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
    /// The slashing state machine (§7.3, slashing.rs): applied-evidence ids
    /// (anti-replay), ejected validators, and the per-epoch slashed-stake
    /// window that prices correlation amplification. Consensus state, derived
    /// exclusively from evidence transactions in blocks — never from gossip,
    /// which only *captures* candidate pairs (gossip.rs).
    slashing: slashing::SlashingState,
    /// Cumulative slashing losses per delegator account, in satoshis.
    ///
    /// A separate ledger, NOT a mutation of the delegation records: the
    /// delegation registry replays its warm-up history from the committed
    /// records ([`delegation::Registry::resolve`]), so editing a record's
    /// amount would retroactively reshuffle every later admission under the
    /// shared churn budget. The loss is committed here instead, and the
    /// node's withdrawal surface nets it out
    /// (`delegator_slash_loss_sat`). The delegated stake itself stops
    /// counting the moment the operator is slashed, because the duty roster
    /// skips slashed validators entirely.
    delegator_slash_losses: BTreeMap<u32, u128>,
    /// Cumulative **fee** rewards settled to each delegator account, in
    /// satoshis — the earning mirror of [`Self::delegator_slash_losses`], and
    /// a ledger for exactly the same reason: crediting a delegation record's
    /// amount would retroactively reshuffle every later warm-up admission
    /// under the shared churn budget ([`delegation::Registry::resolve`] folds
    /// the records from epoch zero). Filled at the epoch boundary by
    /// [`fee_market::distribute_producer_fees`] plus
    /// [`fee_market::split_delegator_fees`]; committed under
    /// `TAG_DELEGATOR_FEE_REWARD`; read by the wallet surface
    /// ([`Self::delegator_fee_reward_sat`]).
    delegator_fee_rewards: BTreeMap<u32, u128>,
    /// The L1 fee market's price, in millisatoshi per gas, that **this**
    /// block's transactions were charged (spec §4.4). Committed, because the
    /// next block's price is derived from it and from the usage below by
    /// [`fee_market::next_base_fee`] — a price read from node-local
    /// bookkeeping is `expected_bits` with a different name.
    base_fee_millisat_per_gas: u128,
    /// Gas this block's transactions consumed, and the payload bytes they
    /// carried: the controller's two axes, and the two quantities the
    /// per-block caps are checked against. Zero on a state produced by
    /// `close_epoch` alone — a boundary is not a block and moves no price.
    block_gas_used: u64,
    block_tx_bytes: u64,
    /// Carried roots (§6.6.2): never recomputed by this transition.
    taint_root: [u8; 32],
    coherence_accumulator_root: [u8; 32],
    coherence_nullifier_root: [u8; 32],
    /// L1 EVM execution commitment, carried (`BLOCH-L1-EVM-STATE-MODEL.md`).
    /// The node's execution layer computes it; this transition only commits
    /// it, exactly like the Coherence roots above.
    evm: EvmCommitment,
    /// Cumulative issued supply in satoshis — the hard-cap invariant's
    /// counter (2026-08-12), committed under `TAG_ISSUED_SUPPLY`.
    ///
    /// Seeded at genesis with `tokenomics_v4::GENESIS_ISSUED_SAT` (everything
    /// but the validator emission exists from slot 0) and advanced only at
    /// epoch boundaries, by the satoshis `close_epoch` actually credits —
    /// which is less than the curve when validators miss attestations
    /// (forfeited slices are never minted) or when `rewards::distribute`
    /// truncates. That data-dependence is why the counter is committed
    /// instead of derived from the epoch number: underivable-from-headers is
    /// the §5.5 bar for state-root membership.
    ///
    /// Gross and monotone: fees move existing coins, whistleblower rewards
    /// come out of slashed bonds, and burns never decrement the counter —
    /// they widen the gap below the cap, and the invariant is one-sided
    /// (`issued_sat <= TOTAL_SUPPLY_SAT`, enforced in `compute_post_state`).
    issued_sat: u128,
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
        evm: EvmCommitment,
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
                    commission_bps: v.commission_bps,
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

        let genesis_cp = Checkpoint { epoch: 0, root: *genesis_block.as_bytes() };
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
                root: *genesis_block.as_bytes(),
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
            slashing: slashing::SlashingState::new(),
            delegator_slash_losses: BTreeMap::new(),
            delegator_fee_rewards: BTreeMap::new(),
            // Genesis opens at the price floor, with no usage behind it: the
            // first block's price is `next_base_fee(floor, {0, 0})`, which
            // clamps back to the floor. A market that opened above its floor
            // would be charging for congestion that never happened.
            base_fee_millisat_per_gas: fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            block_gas_used: 0,
            block_tx_bytes: 0,
            taint_root,
            coherence_accumulator_root,
            coherence_nullifier_root,
            evm,
            issued_sat: tokenomics_v4::GENESIS_ISSUED_SAT,
        };
        // Seed epoch 0's participation for the launch roster, so the
        // committed participation component is well-defined from block one.
        for v in st.duty_roster_at(0) {
            st.current_participation.insert(v.index, false);
        }
        st
    }

    /// Id of the block that produced this state.
    /// Exactly the value a block's header must carry in `coherence_root`.
    ///
    /// An accessor and not two public fields on purpose: the header field is a
    /// *binding* over both pool roots, and exposing the roots separately would
    /// let a caller compose them — in the wrong order, or with one of them
    /// stale — which is the composition the binding exists to make impossible.
    /// The producer stamps this and the validator checks against it, so there
    /// is one expression of the rule and both sides evaluate it.
    pub fn coherence_root(&self) -> [u8; 32] {
        crate::derive::coherence_binding(
            &self.coherence_accumulator_root,
            &self.coherence_nullifier_root,
        )
    }

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
            justified: Checkpoint { epoch: j.epoch, root: j.root },
            finalized: Checkpoint { epoch: f.epoch, root: f.root },
        }
    }

    /// Recompute the committed state root from the §5.5 components. Pure
    /// recomputation on every call — no memoized value can go stale. This is
    /// the one place [`CommittedState`] fields map to committed components;
    /// a field added to the struct but not to this function is exactly the
    /// gap the 2026-08-11 extension closed, and the field-coverage test at
    /// the bottom of this file exists to make that regression loud.
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
                // The RANDAO chain pair (head, position) is committed as
                // advanced — step 5 of the transition reads it back from
                // exactly here.
                randao_commitment: r.randao_commitment,
                reveals_used: *self.reveals_used.get(&r.index).unwrap_or(&0),
                withdrawable_epoch: r.withdrawable_epoch,
                withdrawal_credentials: r.withdrawal_credentials.clone(),
                commission_bps: r.commission_bps,
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
        // Which mixes are committed is decided in ONE place — see
        // `state_root::randao_window` for why that is worth a function.
        let boundaries: Vec<RandaoMix> = self
            .boundary_mixes
            .iter()
            .map(|(e, m)| RandaoMix { epoch: *e, mix: *m })
            .collect();
        let mixes = crate::state_root::randao_window(&boundaries, self.epoch, self.randao_mix);

        // Finality bookkeeping: the engine's full fold state plus the frozen
        // view's previous-justified checkpoint, in one leaf.
        let cp = |c: finality::Checkpoint| CheckpointRecord { epoch: c.epoch, root: c.root };
        let finality_record = FinalityRecord {
            justified: self.finality_engine.justified_checkpoints().map(cp).collect(),
            current_justified: cp(self.finality_engine.current_justified()),
            previous_justified: CheckpointRecord {
                epoch: self.previous_justified.epoch,
                root: self.previous_justified.root,
            },
            finalized: cp(self.finality_engine.finalized()),
            leaked: self
                .finality_engine
                .leaked_stakes()
                .map(|(validator, leaked_sat)| LeakRecord { validator, leaked_sat })
                .collect(),
            next_epoch: self.finality_engine.next_epoch(),
        };
        // The signing root travels from the accumulation key into the leaf
        // key untouched — computed once, in attestation.rs, never re-derived.
        let pending_votes: Vec<PendingVoteRecord> = self
            .pending_votes
            .iter()
            .map(|((validator, signing_root), d)| PendingVoteRecord {
                validator: *validator,
                signing_root: *signing_root,
                slot: d.slot,
                head: d.head,
                source_epoch: d.source_epoch,
                source_root: d.source_root,
                target_epoch: d.target_epoch,
                target_root: d.target_root,
            })
            .collect();
        let fc_messages: Vec<FcMessageRecord> = self
            .latest_messages
            .iter()
            .map(|(validator, (slot, root))| FcMessageRecord {
                validator: *validator,
                slot: *slot,
                root: *root,
            })
            .collect();
        let fc_equivocators: Vec<FcEquivocatorRecord> = self
            .fc_equivocators
            .iter()
            .map(|validator| FcEquivocatorRecord { validator: *validator })
            .collect();
        let deposit_queue: Vec<DepositQueueRecord> = self
            .deposit_history
            .iter()
            .map(|d| DepositQueueRecord {
                pubkey_hash: d.pubkey_hash,
                deposit_epoch: d.deposit_epoch,
                amount_sat: d.amount_sat,
            })
            .collect();
        // Positionally keyed: the history's append order is chain order (see
        // DelegationRecord docs for why content cannot key duplicates).
        let delegations: Vec<DelegationRecord> = self
            .delegations
            .iter()
            .enumerate()
            .map(|(position, d)| DelegationRecord {
                position: position as u64,
                delegator: d.delegator,
                validator: d.validator,
                amount_sat: d.amount_sat,
                requested_epoch: d.requested_epoch,
                deactivate_epoch: d.deactivate_epoch,
                eligible: d.eligible,
            })
            .collect();
        let pending_fees: Vec<PendingFeeRecord> = self
            .pending_fee_rewards
            .iter()
            .map(|(validator, amount_sat)| PendingFeeRecord {
                validator: *validator,
                amount_sat: *amount_sat,
            })
            .collect();

        // Slashing bookkeeping (§7.3). Built from the state machine's own
        // accessors so there is one reading of what it holds.
        let applied_evidence: Vec<AppliedEvidenceRecord> =
            self.slashing.applied_ids().map(|id| AppliedEvidenceRecord { id: *id }).collect();
        let slash_window: Vec<SlashWindowRecord> = self
            .slashing
            .window_entries()
            .map(|(epoch, slashed_sat)| SlashWindowRecord { epoch, slashed_sat })
            .collect();
        let delegator_losses: Vec<DelegatorLossRecord> = self
            .delegator_slash_losses
            .iter()
            .map(|(delegator, loss_sat)| DelegatorLossRecord {
                delegator: *delegator,
                loss_sat: *loss_sat,
            })
            .collect();
        let delegator_fee_rewards: Vec<DelegatorFeeRecord> = self
            .delegator_fee_rewards
            .iter()
            .map(|(delegator, reward_sat)| DelegatorFeeRecord {
                delegator: *delegator,
                reward_sat: *reward_sat,
            })
            .collect();

        crate::state_root::state_root(&ConsensusState {
            // The eUTXO set is owned by the node's transaction layer, which
            // this standalone crate cannot see (transactions are opaque);
            // the node's implementation supplies it here.
            eutxos: &[],
            validators: &validators,
            current_participation: &current,
            previous_participation: &previous,
            randao_mixes: &mixes,
            finality: &finality_record,
            pending_votes: &pending_votes,
            fc_messages: &fc_messages,
            fc_equivocators: &fc_equivocators,
            deposit_queue: &deposit_queue,
            delegations: &delegations,
            pending_fees: &pending_fees,
            applied_evidence: &applied_evidence,
            slash_window: &slash_window,
            delegator_slash_losses: &delegator_losses,
            base_fee: BaseFeeRecord {
                base_fee_millisat_per_gas: self.base_fee_millisat_per_gas,
                gas_used: self.block_gas_used,
                tx_bytes: self.block_tx_bytes,
            },
            delegator_fee_rewards: &delegator_fee_rewards,
            taint_root: self.taint_root,
            coherence_accumulator_root: self.coherence_accumulator_root,
            coherence_nullifier_root: self.coherence_nullifier_root,
            evm: self.evm,
            issued_sat: self.issued_sat,
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

    /// Apply one transaction's state-dependent rules. Returns what it owes the
    /// block ([`fee_market::TxCharge`] — gas, bytes and the two settled fee
    /// parts). `total_active_sat` is the epoch's active stake, passed in
    /// because the per-validator cap is a fraction of *committed* active stake
    /// (rule 1), not something this method may re-derive from a moving
    /// intermediate; `base_fee_millisat_per_gas` is this block's price, passed
    /// in for the same reason — it is derived once, from the parent's
    /// committed leaf, and every transaction in the block settles at it.
    ///
    /// Staking messages charge nothing at this layer: their own fee handling
    /// belongs with the transfer format that carries them (§1.2), and inventing
    /// a charge here would be inventing a price nobody specified.
    fn apply_transaction(
        &mut self,
        tx: &PosTransaction,
        total_active_sat: u128,
        base_fee_millisat_per_gas: u128,
    ) -> Result<fee_market::TxCharge, ()> {
        let free = fee_market::TxCharge {
            gas: 0,
            tx_bytes: 0,
            base_fee_sat: 0,
            priority_fee_sat: 0,
        };
        match tx {
            PosTransaction::Transfer { inputs, tx_bytes, tip_millisat_per_gas } => {
                Ok(fee_market::charge(
                    fee_market::TxClass::Eutxo { inputs: *inputs },
                    *tx_bytes,
                    base_fee_millisat_per_gas,
                    *tip_millisat_per_gas,
                ))
            }
            PosTransaction::Deposit {
                pubkey,
                amount_sat,
                randao_commitment,
                withdrawal_credentials,
                commission_bps,
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
                        commission_bps: *commission_bps,
                    },
                );
                self.reveals_used.insert(index, 0);
                self.pubkey_index.insert(pubkey_hash, index);
                self.deposit_history.push(QueuedDeposit {
                    pubkey_hash,
                    deposit_epoch: self.epoch,
                    amount_sat: *amount_sat,
                });
                Ok(free)
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
                Ok(free)
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
                Ok(free)
            }
            // Evidence needs the injected signature verifier, which lives on
            // the Transition, not on the state — compute_post_state routes it
            // to `apply_slashing_evidence` before this method is reached.
            // Reaching this arm means a caller bypassed that seam; refusing
            // beats silently accepting unverified evidence.
            PosTransaction::SlashingEvidence(_) => Err(()),
        }
    }

    /// Verify and execute one §7.3 evidence transaction against this state.
    ///
    /// The verdict — structure, anti-replay, not-already-slashed, both
    /// signatures — belongs to [`slashing::SlashingState`] (the single
    /// definition, its unit tests pin every branch). What belongs *here* is
    /// the consequence, because only this struct holds the accounts:
    ///
    /// - the operator's own bond absorbs its share of the penalty and the
    ///   record is marked `slashed` — duties stop immediately (the duty
    ///   roster filters on the flag) and the residue stays locked through
    ///   the weak-subjectivity margin, never *shortening* an
    ///   already-scheduled lock;
    /// - each delegator's pro-rata loss is committed to the
    ///   [`Self::delegator_slash_losses`] ledger (delegation.rs rule 3:
    ///   exposure is what makes delegation a security signal). Bonded is
    ///   slashable in every lifecycle state except withdrawn — a delegation
    ///   still warming up or draining is still bonded coins; one past
    ///   cool-down is not reachable and is masked out;
    /// - the whistleblower's 1/32 accrues to the including proposer through
    ///   [`Self::pending_fee_rewards`], compounding at the epoch boundary
    ///   like every other in-epoch reward (effective stake stays frozen
    ///   within the epoch). The rest of the penalty is burned by never being
    ///   credited to anyone — the same burn-by-omission as the base fee.
    fn apply_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
        including_proposer: u32,
        total_active_sat: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), ()> {
        let offender = match evidence {
            SlashingEvidence::AttestationOffence { first, .. } => first.validator,
            SlashingEvidence::ProposerEquivocation { first, .. } => first.header.proposer_index,
        };
        // No record, nothing to slash: evidence against an index that never
        // registered proves nothing about this chain.
        let Some(offender_rec) = self.validators.get(&offender) else {
            return Err(());
        };
        let own_bond_sat = offender_rec.staked_sat;

        // The exposure view apply_slash prices against: index 0 is a
        // synthetic record for the operator's own bond (so operator and
        // delegators are priced by the same arithmetic, in one call), the
        // rest mirrors the committed delegation list in order, with
        // withdrawn (post-cool-down) delegations masked ineligible — their
        // coins have left the bond and are no longer reachable.
        let registry = delegation::Registry::resolve(&self.delegations, self.epoch);
        let mut exposure: Vec<Delegation> = Vec::with_capacity(self.delegations.len() + 1);
        exposure.push(Delegation {
            delegator: offender,
            validator: offender,
            amount_sat: own_bond_sat,
            requested_epoch: 0,
            deactivate_epoch: None,
            eligible: true,
        });
        for d in &self.delegations {
            let mut view = *d;
            if registry.state_of(d) == delegation::StakeState::Inactive {
                view.eligible = false;
            }
            exposure.push(view);
        }

        let outcome = match evidence {
            SlashingEvidence::AttestationOffence { first, second } => {
                let pair = slashing::SlashingEvidence {
                    first: first.clone(),
                    second: second.clone(),
                };
                self.slashing.process(
                    &pair,
                    self.epoch,
                    &exposure,
                    total_active_sat,
                    including_proposer,
                    verifier,
                )
            }
            SlashingEvidence::ProposerEquivocation { first, second } => {
                self.slashing.process_proposer(
                    first,
                    second,
                    self.epoch,
                    &exposure,
                    total_active_sat,
                    including_proposer,
                    verifier,
                )
            }
        }
        .map_err(|_| ())?;

        let epoch = self.epoch;
        if let Some(rec) = self.validators.get_mut(&offender) {
            rec.slashed = true;
            rec.staked_sat = rec.staked_sat.saturating_sub(outcome.delegation_losses_sat[0]);
            // Ejection: duties stop now. min(), because a validator already
            // exiting must not have its exit pushed later by the slash.
            if epoch < rec.exit_epoch {
                rec.exit_epoch = epoch;
            }
            // The residue stays reachable through the weak-subjectivity
            // margin, and a slash never *shortens* a scheduled lock
            // (`u64::MAX` means no lock was scheduled at all).
            let lock = epoch.saturating_add(staking::WITHDRAWAL_DELAY_EPOCHS);
            rec.withdrawable_epoch = if rec.withdrawable_epoch == u64::MAX {
                lock
            } else {
                rec.withdrawable_epoch.max(lock)
            };
        }
        for (d, loss) in self
            .delegations
            .iter()
            .zip(outcome.delegation_losses_sat.iter().skip(1))
        {
            if *loss > 0 {
                *self.delegator_slash_losses.entry(d.delegator).or_insert(0) += *loss;
            }
        }
        if outcome.whistleblower_reward_sat > 0 {
            *self
                .pending_fee_rewards
                .entry(including_proposer)
                .or_insert(0) += outcome.whistleblower_reward_sat;
        }
        Ok(())
    }

    /// Total slashing loss committed against one delegator account, in
    /// satoshis. The number a wallet subtracts from the delegator's bonded
    /// amounts at withdrawal — a delegator who chose a slashed operator finds
    /// its loss here, not in a mutated delegation record.
    pub fn delegator_slash_loss_sat(&self, delegator: u32) -> u128 {
        self.delegator_slash_losses.get(&delegator).copied().unwrap_or(0)
    }

    /// Total fee reward settled to one delegator account, in satoshis — the
    /// earning half of the pair above, and the number a wallet adds to the
    /// delegator's withdrawable balance. Non-zero in both eras, which is the
    /// whole point of routing fees through the commission split.
    pub fn delegator_fee_reward_sat(&self, delegator: u32) -> u128 {
        self.delegator_fee_rewards.get(&delegator).copied().unwrap_or(0)
    }

    /// The price this state's block charged, in millisatoshi per gas. The
    /// **next** block's price is [`Self::next_base_fee`] — never this value
    /// carried forward, and never a node-local number.
    pub fn base_fee_millisat_per_gas(&self) -> u128 {
        self.base_fee_millisat_per_gas
    }

    /// The price the child block must charge: the EIP-1559 controller applied
    /// to this state's committed price and usage.
    ///
    /// One definition, two callers — the producer prices its mempool with it
    /// and the validator charges every included transaction with it. A second
    /// expression of this rule anywhere is h28080 with a fee attached.
    pub fn next_base_fee(&self) -> u128 {
        fee_market::next_base_fee(
            self.base_fee_millisat_per_gas,
            fee_market::BlockUsage {
                gas_used: self.block_gas_used,
                tx_bytes: self.block_tx_bytes,
            },
        )
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
            // the anchor of Casper's two-round finality rule. (Not a slashing
            // input — see the field docs: the surround predicate is pairwise.)
            let old = st.finality_engine.current_justified();
            st.previous_justified = Checkpoint { epoch: old.epoch, root: old.root };
            // The votes go through `votes_from_partition`, not straight into
            // `EpochVotes`, so the partition filter has exactly ONE definition
            // in the crate. It is redundant here — step 8 of `compute_post_state`
            // already refuses any attestation whose author is not in
            // `committee_for_slot` for its own slot, off the same seed — and
            // that redundancy is the point: G1 was written, tested and sealed
            // as "corrected" while the filter sat unwired, because the caller
            // was trusted to have done it. The assertion below is what makes
            // the trust checkable instead of assumed: if the two ever disagree,
            // a test build says so, rather than the quorum denominator quietly
            // shifting under a rule nobody re-read.
            //
            // `active_set` is the whole duty roster, not the slot committee:
            // the union of an epoch's committees IS the active set, so the
            // quorum denominator is total active stake (F1).
            let mut accepted = Vec::new();
            let epoch_votes = finality::votes_from_partition(
                closing,
                &roster,
                &votes,
                &st.seed_for_epoch(closing),
                &mut accepted,
            );
            debug_assert_eq!(
                epoch_votes.attestations.len(),
                votes.len(),
                "boundary partition dropped votes that the inclusion check at step 8 admitted - \
                 the two filters have diverged"
            );
            // Out-of-order is unreachable: this is the only call site and it
            // feeds epochs densely by construction. A total no-op on Err
            // beats a panic in a consensus path.
            let _ = st.finality_engine.process_epoch(&epoch_votes);
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
        // The hard cap, applied at the source (2026-08-12): issuance is
        // clamped to the remaining headroom, so emission STOPS at the cap
        // instead of crossing it. The clamp never binds under the shipped
        // curve — the 40-year decay sum is the allocation minus a pinned dust
        // (`tokenomics_v4::EMISSION_DUST_SAT`) — but the cap must not depend
        // on the curve staying that way: with the clamp, no curve edit can
        // mint past `TOTAL_SUPPLY_SAT` without also getting past the
        // `SupplyCapExceeded` check in `compute_post_state`, which reads the
        // committed counter, not the curve.
        let headroom = tokenomics_v4::TOTAL_SUPPLY_SAT.saturating_sub(st.issued_sat);
        let epoch_issuance = if epoch_issuance > headroom { headroom } else { epoch_issuance };
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
                        // The committed counter advances by what was MINTED,
                        // not by what the curve offered: forfeited slices and
                        // distribute()'s truncation dust never become coins,
                        // and a counter that overstated real issuance would
                        // hit the cap early — wrong in the direction that
                        // punishes honest validators. Bounded by
                        // `epoch_issuance <= headroom`, so it cannot pass the
                        // cap (pinned by `emission_stops_at_the_cap`).
                        st.issued_sat += payout.operator;
                    }
                }
            }
        }
        // Fee rewards accrued during the epoch compound now, not per block —
        // see the field docs: effective stake is frozen within an epoch — and
        // they compound **through the delegation split**, not raw into the
        // operator's bond.
        //
        // WHY THE SPLIT IS NOT OPTIONAL (spec §6.1). `rewards::distribute`
        // above pays delegators out of `epoch_issuance`, which
        // `tokenomics_v4` sets to zero after `EMISSION_SLOTS` — the exact
        // moment fees become validators' entire revenue. Crediting
        // `FeeSplit::to_producer` raw to the proposer's record (what this step
        // did until 2026-08-12) therefore put delegator revenue at exactly
        // zero at the fee-only boundary, and delegation — the mechanism that
        // lets stake exist without running hardware — would have died forty
        // years into an immutable schedule. Routing fees through the same
        // stake-origin + commission arithmetic keeps it alive in both eras.
        //
        // The delegators' side settles into the committed
        // `delegator_fee_rewards` ledger rather than into the delegation
        // records, for the reason those records exist: the registry replays
        // its warm-up history from them, so editing an amount would
        // retroactively reshuffle every later admission under the churn
        // budget. Truncation dust from the pro-rata pass goes to the operator
        // — some account must hold it, and the operator is the one whose
        // block earned the fee.
        let fee_registry = delegation::Registry::resolve(&st.delegations, closing);
        let fees = std::mem::take(&mut st.pending_fee_rewards);
        for (idx, amount) in fees {
            let Some(rec) = st.validators.get(&idx) else { continue };
            let acct = StakeAccount {
                // The bond as of the epoch's END, read from `self` — the
                // pre-boundary state — not from `st`, which the issuance loop
                // above has already credited. A fee earned during epoch E must
                // be split by the stake position that held during E; splitting
                // it by a bond that E's own issuance just inflated would make
                // the operator's share depend on the order of two steps at the
                // same boundary, which is exactly the kind of ordering
                // dependence rule 2 exists to keep out of committed state.
                self_stake: self.validators.get(&idx).map_or(rec.staked_sat, |r| r.staked_sat),
                delegated_stake: fee_registry.stake_of(idx),
                commission_bps: rec.commission_bps,
                // Not scaled by credits: producing the block IS the
                // performance, and there is nothing further to forfeit
                // (fee_market::distribute_producer_fees' own rule).
                credits: 1,
                max_credits: 1,
            };
            let payout = fee_market::distribute_producer_fees(&acct, amount);
            // Per-delegator shares, pro-rata by the satoshis each account had
            // ACTUALLY activated — the same measure that gave the operator its
            // consensus weight. Aggregated per account first, so a delegator
            // holding two bonds behind one operator is one payee and the
            // iteration order is a function of the data (rule 2).
            let mut by_account: BTreeMap<u32, u128> = BTreeMap::new();
            for d in &st.delegations {
                if d.validator != idx {
                    continue;
                }
                let activated = fee_registry.activated_sat(d);
                if activated > 0 {
                    *by_account.entry(d.delegator).or_insert(0) += activated;
                }
            }
            let stakes: Vec<(u32, u128)> = by_account.into_iter().collect();
            let (shares, dust) = fee_market::split_delegator_fees(&stakes, payout.delegators);
            for (delegator, reward) in shares {
                if reward > 0 {
                    *st.delegator_fee_rewards.entry(delegator).or_insert(0) += reward;
                }
            }
            if let Some(rec) = st.validators.get_mut(&idx) {
                rec.staked_sat += payout.operator + dust;
            }
        }

        // 3. Fix the boundary mix that seeds epoch E+1, and retain exactly
        //    the last 2 boundaries (§5.5).
        st.boundary_mixes.insert(closing, st.randao_mix);
        let keep_from = closing.saturating_sub(crate::state_root::RANDAO_BOUNDARIES_RETAINED - 1);
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
        // Compare bytes against an id THIS node derived, never mint an id from
        // the header's untrusted `parent` field (S5.4).
        if &header.parent != pre.head.as_bytes() {
            return Err(TransitionError::WrongParent);
        }
        // 3. Version.
        if header.version != BLOCK_VERSION_V4 {
            return Err(TransitionError::Proposal(ProposalReject::WrongVersion));
        }

        // 3b. THE HEADER MUST COMMIT TO WHAT IT CARRIES.
        //
        // These three checks were absent from this stack entirely. They existed
        // only in `derive::validate_block`, a parallel validator with no caller
        // — so the code the node actually runs accepted any `body_root`,
        // `attestation_root` or `coherence_root` whatsoever. Found at
        // integration on 2026-08-12 while unifying the two stacks.
        //
        // What was at stake is subtler than "arbitrary transactions execute":
        // step 12's `state_root` check does catch a body that changes state
        // differently. What was lost is that the header stopped *committing to*
        // the body, so one `BlockId` could name two different bodies. Gossip
        // the honest header with a mangled body and every node rejects the
        // pair; a node that caches rejections by block id then refuses the
        // honest body too. Identity that does not cover the payload is the
        // `pow_hash`/`block_hash` defect family one layer down.
        //
        // They sit here — after the two integer comparisons, before the
        // sortition draw and long before the hybrid verify — because they are
        // hashes over data already in hand, and the frozen error order is
        // cheap-to-expensive. The functions are `derive`'s: one derivation
        // path means the producer stamps and the validator checks by calling
        // the same code, which is the whole anti-h28080 invariant `produce.rs`
        // is built on.
        let tx_bytes: Vec<Vec<u8>> =
            transactions.iter().map(PosTransaction::canonical_bytes).collect();
        if header.body_root != crate::derive::body_root(&tx_bytes) {
            return Err(TransitionError::BodyRootMismatch);
        }
        if header.attestation_root != crate::derive::attestation_root(attestations) {
            return Err(TransitionError::AttestationRootMismatch);
        }
        // Carried, never recomputed (§6.6.1): the pool is inert under PoS, so
        // the header must reproduce the binding over the state the PARENT
        // committed. Deriving it — rather than copying the parent's header
        // field — is what makes it a check instead of a tautology.
        if header.coherence_root != pre.coherence_root() {
            return Err(TransitionError::CoherenceRootMismatch);
        }

        // Roll epoch accounting over any empty boundary slots the chain
        // skipped. Identical to the caller invoking process_epoch itself —
        // close_epoch is the single definition of the boundary — so explicit
        // and implicit epoch processing cannot diverge.
        let mut st = pre.clone();
        while st.epoch < block_epoch {
            st = st.close_epoch();
        }

        // 3c. THE HARD CAP IS A CONSENSUS INVARIANT (founder decision,
        // 2026-08-12): a block whose committed cumulative issuance exceeds
        // `TOTAL_SUPPLY_SAT` is invalid, on every node, with its own error.
        // After the boundary roll and before anything expensive — it is one
        // integer comparison. `close_epoch` clamps issuance to the remaining
        // headroom, so this cannot fire on a state this transition produced;
        // what it refuses is a PRE-state that already claims issuance beyond
        // the cap (a forged snapshot, a corrupted state-sync payload, a
        // foreign chain's state). Building on such a state would propagate
        // the violation under an honest node's signature — refusing is the
        // whole point of making the cap an invariant instead of a property
        // the curve happens to have. The counter is committed
        // (`TAG_ISSUED_SUPPLY`), so two nodes cannot disagree about how much
        // has been issued while their roots agree — the §5.5 rule, applied
        // to the cap itself.
        if st.issued_sat > tokenomics_v4::TOTAL_SUPPLY_SAT {
            return Err(TransitionError::SupplyCapExceeded);
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
            &header.proposal_signing_root(),
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

        // 10. Transactions — cheap state-dependent rules, except slashing
        //     evidence, which is routed here because it needs the injected
        //     verifier (two hybrid verifies per evidence; evidence is rare
        //     and a proposer including garbage evidence forfeits the whole
        //     block, so the cost is not a spam surface). Invalid evidence is
        //     a block reject, not a skip: every node re-judges it, so a
        //     proposer cannot smuggle a no-op past nodes that judge harder.
        // The block's price, derived from the PARENT's committed fee-market
        // leaf and from nothing else (spec §4.4). Fixed before the first
        // transaction is charged, so every transaction in a block settles at
        // one price — and the producer computes it with the very same call
        // (`CommittedState::next_base_fee`) when it prices its mempool.
        //
        // `pre`, not `st`: the roll to `st` only crosses empty epoch
        // boundaries, and a boundary is not a block — it moves no price. Both
        // read the same fields here, and reading the pre-state is what says
        // so.
        let base_fee = pre.next_base_fee();

        let total_active: u128 = roster.iter().map(|v| v.effective_stake as u128).sum();
        let mut base_fees: u128 = 0;
        let mut priority_fees: u128 = 0;
        let mut block_gas: u64 = 0;
        let mut block_bytes: u64 = 0;
        for (i, tx) in transactions.iter().enumerate() {
            let applied = match tx {
                PosTransaction::SlashingEvidence(ev) => st
                    .apply_slashing_evidence(
                        ev,
                        header.proposer_index,
                        total_active,
                        &self.verifier,
                    )
                    .map(|()| fee_market::TxCharge {
                        gas: 0,
                        tx_bytes: 0,
                        base_fee_sat: 0,
                        priority_fee_sat: 0,
                    }),
                _ => st.apply_transaction(tx, total_active, base_fee),
            };
            match applied {
                Ok(charge) => {
                    base_fees += charge.base_fee_sat;
                    priority_fees += charge.priority_fee_sat;
                    block_gas = block_gas.saturating_add(charge.gas);
                    block_bytes = block_bytes.saturating_add(charge.tx_bytes);
                }
                Err(()) => return Err(TransitionError::Transaction(i as u32)),
            }
        }

        // 10b. THE TWO PER-BLOCK CAPS (fee-market spec §5). A block exceeding
        //      either is invalid, and each has its own error because "the
        //      block was too big" and "the block was too expensive" are
        //      different facts about a proposer's behaviour. They are checked
        //      after the transactions are charged, because the charge is what
        //      produces the two totals — and before the reward step, so an
        //      over-cap block never pays anyone.
        //
        //      Neither total is taken from the header: a self-declared size is
        //      not a cap, it is a request. Both are summed from the body the
        //      header already commits to (step 3b), which is what makes the
        //      caps checkable rather than advisory.
        if block_gas > fee_market::BLOCK_GAS_LIMIT {
            return Err(TransitionError::BlockGasLimitExceeded);
        }
        if block_bytes > fee_market::MAX_BLOCK_TX_BYTES {
            return Err(TransitionError::BlockByteLimitExceeded);
        }

        // 11. Rewards (rewards.rs): the block's fee split. The producer's
        //     share accrues and compounds at the epoch boundary — where it now
        //     goes through the operator/delegator commission split, see
        //     `close_epoch` — and the burned share is burned by never being
        //     credited to anyone.
        let split = rewards::split_fees_at(base_fees, priority_fees, header.slot);
        if split.to_producer > 0 {
            *st.pending_fee_rewards.entry(header.proposer_index).or_insert(0) +=
                split.to_producer;
        }

        // The fee-market leaf this block commits: the price it charged and the
        // usage the next block's controller reads.
        st.base_fee_millisat_per_gas = base_fee;
        st.block_gas_used = block_gas;
        st.block_tx_bytes = block_bytes;

        st.slot = header.slot;
        st.head = BlockId::of(header);
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
mod tx_codec_tests {
    use super::*;

    /// One of each decodable variant, with values chosen so a field-order or
    /// width mistake cannot pass: every integer differs, and the two
    /// length-prefixed byte fields have different lengths so swapping them
    /// changes the result.
    fn samples() -> Vec<PosTransaction> {
        vec![
            PosTransaction::Transfer {
                inputs: 7,
                tx_bytes: 1_234_567,
                tip_millisat_per_gas: 987_654_321_000,
            },
            PosTransaction::Deposit {
                pubkey: vec![0xAB; 3745],
                amount_sat: 25_000 * 100_000_000,
                randao_commitment: [0x5C; 32],
                withdrawal_credentials: vec![0xCD; 32],
                commission_bps: 1_250,
            },
            PosTransaction::Exit { validator: 63 },
            PosTransaction::Delegate {
                delegator: 11,
                validator: 42,
                amount_sat: 1_000 * 100_000_000,
                eligible: true,
            },
            PosTransaction::Delegate {
                delegator: 0,
                validator: 0,
                amount_sat: 0,
                eligible: false,
            },
        ]
    }

    #[test]
    fn canonical_bytes_round_trips() {
        for tx in samples() {
            let bytes = tx.canonical_bytes();
            let back = PosTransaction::from_canonical_bytes(&bytes)
                .expect("a transaction this crate encoded must decode");
            assert_eq!(
                back.canonical_bytes(),
                bytes,
                "re-encoding the decoded value must reproduce the same bytes, \
                 or body_root disagrees between proposer and verifier"
            );
        }
    }

    #[test]
    fn evidence_is_one_way_and_says_so() {
        // Not a limitation to route around: the encoder folds nested messages
        // in as signing roots, and a hash does not invert.
        let mut b = vec![0x05, 0x01];
        b.extend_from_slice(&[0u8; 32]);
        b.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            PosTransaction::from_canonical_bytes(&b),
            Err(TxDecodeError::EvidenceNotDecodable)
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        // Two encodings decoding to one transaction would break the
        // injectivity body_root leans on.
        let mut b = PosTransaction::Exit { validator: 5 }.canonical_bytes();
        b.push(0x00);
        assert_eq!(PosTransaction::from_canonical_bytes(&b), Err(TxDecodeError::TrailingBytes));
    }

    #[test]
    fn truncation_is_refused_not_defaulted() {
        let full = samples()[1].canonical_bytes();
        for cut in [0, 1, 5, full.len() - 1] {
            assert_eq!(
                PosTransaction::from_canonical_bytes(&full[..cut]),
                Err(TxDecodeError::Truncated),
                "a short read must fail, never zero-fill"
            );
        }
    }

    #[test]
    fn non_canonical_bool_is_refused() {
        let mut b = PosTransaction::Delegate {
            delegator: 1,
            validator: 2,
            amount_sat: 3,
            eligible: true,
        }
        .canonical_bytes();
        *b.last_mut().unwrap() = 2;
        assert_eq!(PosTransaction::from_canonical_bytes(&b), Err(TxDecodeError::NotCanonical(2)));
    }

    #[test]
    fn unknown_tag_is_refused() {
        assert_eq!(
            PosTransaction::from_canonical_bytes(&[0xFF]),
            Err(TxDecodeError::UnknownTag(0xFF))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::BlockHeaderV4;

    /// The genesis id, derived rather than invented.
    ///
    /// The tests used to write `BlockId([0x60; 32])`. That is no longer
    /// expressible, and correctly so: genesis is a block, so its id is
    /// `BlockId::of` over its header like every other block's. A literal id
    /// would have been the one place in the crate where an identity came from
    /// somewhere other than the bytes it names.
    fn genesis_block_id() -> BlockId {
        BlockId::of(&BlockHeaderV4 {
            version: BLOCK_VERSION_V4,
            parent: [0u8; 32],
            state_root: [0u8; 32],
            body_root: [0u8; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0u8; 32],
            randao_mix: [0x07; 32],
            justified_root: [0u8; 32],
            finalized_root: [0u8; 32],
            attestation_root: [0u8; 32],
            coherence_root: [0x33; 32],
        })
    }
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

    /// Rejects exactly the marker byte-string `b"forged"`, accepts anything
    /// else — enough to make one signature of an evidence pair verifiably
    /// bad while every other signature in the block still passes.
    struct MarkerVerifier;
    impl SignatureVerifier for MarkerVerifier {
        fn verify(&self, _v: u32, _root: &[u8; 32], sig: &[u8]) -> bool {
            sig != b"forged"
        }
    }

    fn setup(n: u32) -> (Transition<OkVerifier>, CommittedState, Vec<RandaoChain>) {
        setup_with(n, OkVerifier)
    }

    fn setup_with<V: SignatureVerifier>(
        n: u32,
        verifier: V,
    ) -> (Transition<V>, CommittedState, Vec<RandaoChain>) {
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
                // A real, non-zero rate: with 0% commission the operator and
                // delegator halves of the fee split are indistinguishable, and
                // every commission assertion would pass vacuously.
                commission_bps: 500,
            });
            chains.push(chain);
        }
        let st = CommittedState::genesis(
            genesis_block_id(),
            [0x07; 32],
            &vals,
            &[],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            EvmCommitment {
                account_root: [0x44; 32],
                receipts_root: [0x55; 32],
                gas_used: 0,
                base_fee_per_gas: 1,
            },
        );
        (Transition::new(verifier), st, chains)
    }

    /// Build a valid block at `slot` on top of `pre`, consuming the drawn
    /// proposer's next reveal — the same walk a real validator client does.
    fn build_block<V: SignatureVerifier>(
        t: &Transition<V>,
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
            parent: *pre.head.as_bytes(),
            state_root: [0u8; 32],
            // The commitment fields are STAMPED, from the same functions the
            // validator checks with — the producer discipline of `produce.rs`.
            // They used to be zeros here, and every test passed, which is
            // precisely how nobody noticed the validator never checked them.
            body_root: crate::derive::body_root(
                &txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>(),
            ),
            slot,
            proposer_index: p,
            randao_reveal: reveal,
            randao_mix: mix,
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: crate::derive::attestation_root(atts),
            coherence_root: pre.coherence_root(),
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
                source_root: fin.justified.root,
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
        assert_eq!(s1.head(), BlockId::of(&b1.header));
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
            parent: *g.head.as_bytes(),
            state_root: [0u8; 32],
            body_root: crate::derive::body_root(&[]),
            slot: 1,
            proposer_index: wrong,
            randao_reveal: reveal,
            randao_mix: beacon::mix_in(&g.randao_mix, &reveal),
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            // Stamped for an empty body, not zeroed: the commitment checks run
            // before the proposer draw, so a zeroed header would die at step 3b
            // and this test would pass without ever reaching what it is about.
            attestation_root: crate::derive::attestation_root(&[]),
            coherence_root: crate::derive::coherence_binding(
                &g.coherence_accumulator_root,
                &g.coherence_nullifier_root,
            ),
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
        let att = attest(&s1, outsider, 32 + slot_idx as u64, *s1.head().as_bytes());

        let b2 = {
            // Build the block by hand: the builder helper would refuse a
            // block that cannot transition.
            let roster = s1.duty_roster();
            let p = schedule::proposer(&seed, 63, &roster).unwrap();
            let reveal = chains[p as usize].next_reveal().unwrap();
            let fin = s1.finality_view();
            let header = BlockHeaderV4 {
                version: BLOCK_VERSION_V4,
                parent: *s1.head.as_bytes(),
                state_root: [0u8; 32],
                body_root: crate::derive::body_root(&[]),
                slot: 63,
                proposer_index: p,
                randao_reveal: reveal,
                randao_mix: beacon::mix_in(&s1.randao_mix, &reveal),
                justified_root: fin.justified.root,
                finalized_root: fin.finalized.root,
                // The block DOES carry the non-member attestation, so it must
                // commit to it — otherwise the reject would be the commitment
                // check, not the membership check this test is named for.
                attestation_root: crate::derive::attestation_root(std::slice::from_ref(&att)),
                coherence_root: crate::derive::coherence_binding(
                    &s1.coherence_accumulator_root,
                    &s1.coherence_nullifier_root,
                ),
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
        b.header.finalized_root = [0xEE; 32];
        assert_eq!(t.apply_block(&g, &b, &[], &[]), Err(TransitionError::FinalityRegression));
    }

    #[test]
    fn wrong_parent_rejected() {
        let (t, g, mut chains) = setup(4);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        b.header.parent = [0xFF; 32];
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
        let atts1 = full_epoch_attestations(&s1, *cp1.as_bytes());
        let b2 = build_block(&t, &s1, 63, &atts1, &[], &mut chains);
        let s2 = t.apply_block(&s1, &b2, &atts1, &[]).unwrap();
        // Everyone's participation is recorded.
        assert!(s2.current_participation.values().all(|a| *a));

        // Crossing into epoch 2 closes epoch 1: 8/8 stake ≥ 2/3 justifies.
        let b3 = build_block(&t, &s2, 64, &[], &[], &mut chains);
        let s3 = t.apply_block(&s2, &b3, &[], &[]).unwrap();
        assert_eq!(s3.finality().justified, Checkpoint { epoch: 1, root: *cp1.as_bytes() });
        assert_eq!(s3.finality().finalized.epoch, 0, "one justification finalizes nothing yet");
        let cp2 = s3.head();

        // Epoch 2 votes source cp1 → target cp2; closing epoch 2 makes the
        // link consecutive, finalizing cp1.
        let atts2 = full_epoch_attestations(&s3, *cp2.as_bytes());
        let b4 = build_block(&t, &s3, 95, &atts2, &[], &mut chains);
        let s4 = t.apply_block(&s3, &b4, &atts2, &[]).unwrap();
        let b5 = build_block(&t, &s4, 96, &[], &[], &mut chains);
        let s5 = t.apply_block(&s4, &b5, &[], &[]).unwrap();

        let fin = s5.finality();
        assert_eq!(fin.justified, Checkpoint { epoch: 2, root: *cp2.as_bytes() });
        assert_eq!(fin.finalized, Checkpoint { epoch: 1, root: *cp1.as_bytes() });
        assert_eq!(fin.previous_justified, Checkpoint { epoch: 1, root: *cp1.as_bytes() });
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
            commission_bps: 500,
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
        let atts = full_epoch_attestations(&s2, *s1.head().as_bytes());
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

        // And the attestation order *within* the carrier block is immaterial
        // to the resulting STATE (rule 2), even though it is not immaterial to
        // the block: since step 3b the header commits to the ordered list, so a
        // reversed list is a different block and needs its own header. That is
        // the correct split — the body is an ordered structure and its root
        // says so, while the state must remain a function of the *set*. The
        // reversal is carried through the builder rather than dropped, because
        // it is exactly the property A2 found violated once (`Store::observe`
        // kept the first message while its comment claimed order-independence).
        let mut reversed = atts.clone();
        reversed.reverse();
        // Re-stamp b3 for the reversed list rather than building afresh: a new
        // build would consume the proposer's next reveal, and the whole point
        // is to hold everything except the ordering constant.
        let mut b3_rev = b3.clone();
        b3_rev.header.attestation_root = crate::derive::attestation_root(&reversed);
        b3_rev.header.state_root =
            t.compute_post_state(&r2, &b3_rev, &reversed, &[]).unwrap().state_root();
        let final_c = t.apply_block(&r2, &b3_rev, &reversed, &[]).unwrap();
        assert_eq!(
            final_a.state_root(),
            final_c.state_root(),
            "attestation order inside the body leaked into committed state"
        );
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
            commission_bps: 500,
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
            commission_bps: 500,
        };
        let mut probe = st.clone();
        assert_eq!(probe.apply_transaction(&dup, 0, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS), Err(()));
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
        assert_eq!(probe.apply_transaction(&exit, 0, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS), Err(()));
    }

    /// One transfer, charged by the fee market rather than by its own say-so,
    /// accruing in-epoch and compounding at the boundary.
    ///
    /// The numbers here used to be the ones the transaction declared
    /// (`base_fee_sat: 1_000`). They are now *derived*, which is the change:
    /// gas comes from the class and the size, the price comes from committed
    /// state, and the transaction contributes only a tip. Every figure below is
    /// recomputed from the fee-market functions rather than written as a
    /// literal — a hard-coded 860 would pass for a while and then silently pin
    /// a constant nobody meant to freeze.
    #[test]
    fn fees_are_charged_by_the_market_and_compound_only_at_the_boundary() {
        let (t, g, mut chains) = setup(4);
        let tx = PosTransaction::Transfer { inputs: 1, tx_bytes: 512, tip_millisat_per_gas: 5 };
        let b = build_block(&t, &g, 1, &[], std::slice::from_ref(&tx), &mut chains);
        let s1 = t.apply_block(&g, &b, &[], std::slice::from_ref(&tx)).unwrap();
        let p = b.header.proposer_index;

        // What the market says this transaction owes, at the price the parent
        // state fixed for this block.
        let price = g.next_base_fee();
        assert_eq!(price, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS, "an empty chain sits at the floor");
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 1 },
            512,
            price,
            5,
        );
        let expected = rewards::split_fees_at(charge.base_fee_sat, charge.priority_fee_sat, 1);
        assert!(expected.burned > 0, "era 1 must burn half the base fee");

        // During the epoch the fee accrues but the bond — and with it every
        // committee — is untouched.
        assert_eq!(s1.validator_record(p).unwrap().staked_sat, sat(200_000));
        assert_eq!(*s1.pending_fee_rewards.get(&p).unwrap(), expected.to_producer);

        // The block's committed usage is what the controller will read.
        assert_eq!(s1.block_gas_used, charge.gas);
        assert_eq!(s1.block_tx_bytes, 512);
        assert_eq!(s1.base_fee_millisat_per_gas, price);

        // Nobody attested this epoch, so issuance is fully forfeited and the
        // boundary compounds exactly the fee share. No delegators here, so the
        // split hands the operator everything.
        let s2 = t.process_epoch(&s1).unwrap();
        assert_eq!(
            s2.validator_record(p).unwrap().staked_sat,
            sat(200_000) + expected.to_producer
        );
        assert!(s2.pending_fee_rewards.is_empty());
    }

    /// **The fee market is wired, and a transaction cannot name its own fee.**
    ///
    /// Two transfers identical in everything the market prices (class, size,
    /// tip) must pay identically, and a bigger transaction must pay more —
    /// which is only expressible because the fee is a function of the
    /// transaction's *shape*, not a number it carries. Before this wave a
    /// transfer declared `base_fee_sat` outright, so a proposer could include
    /// one claiming any figure and compound it into its own bond.
    #[test]
    fn a_transaction_cannot_declare_its_own_fee() {
        let (t, g, mut chains) = setup(4);
        let small = PosTransaction::Transfer { inputs: 1, tx_bytes: 256, tip_millisat_per_gas: 0 };
        let large = PosTransaction::Transfer { inputs: 4, tx_bytes: 4_096, tip_millisat_per_gas: 0 };

        let b_small = build_block(&t, &g, 1, &[], std::slice::from_ref(&small), &mut chains);
        let s_small = t.apply_block(&g, &b_small, &[], std::slice::from_ref(&small)).unwrap();

        let (t2, g2, mut chains2) = setup(4);
        let b_large = build_block(&t2, &g2, 1, &[], std::slice::from_ref(&large), &mut chains2);
        let s_large = t2.apply_block(&g2, &b_large, &[], std::slice::from_ref(&large)).unwrap();

        let paid = |s: &CommittedState| -> u128 {
            s.pending_fee_rewards.values().sum()
        };
        assert!(paid(&s_small) > 0, "the price floor must make every transaction cost something");
        assert!(
            paid(&s_large) > paid(&s_small),
            "four hybrid verifies and 16x the bytes must not cost the same as one and 256 B"
        );
        // And the gas the block committed is exactly the intrinsic charge — no
        // transaction-supplied number enters it.
        assert_eq!(
            s_large.block_gas_used,
            fee_market::intrinsic_gas(fee_market::TxClass::Eutxo { inputs: 4 }, 4_096)
        );
    }

    /// The base fee is derived from the parent's committed leaf, by the one
    /// controller, and a congested block raises the price for the next one.
    #[test]
    fn the_base_fee_moves_with_committed_usage_only() {
        let (t, g, mut chains) = setup(4);
        // A block at the byte target: the controller's neutral point on the
        // byte axis, but well under target on gas — so the max-utilisation
        // rule prices the byte axis and leaves the floor alone (it cannot
        // fall below it anyway).
        let tx = PosTransaction::Transfer { inputs: 1, tx_bytes: 8_192, tip_millisat_per_gas: 0 };
        let b1 = build_block(&t, &g, 1, &[], std::slice::from_ref(&tx), &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], std::slice::from_ref(&tx)).unwrap();

        // The next block's price is the controller over what s1 committed —
        // and nothing else. Same function, same inputs, same answer.
        assert_eq!(
            s1.next_base_fee(),
            fee_market::next_base_fee(
                s1.base_fee_millisat_per_gas(),
                fee_market::BlockUsage { gas_used: s1.block_gas_used, tx_bytes: s1.block_tx_bytes },
            )
        );

        // Empty epoch boundaries move no price: a boundary is not a block.
        let rolled = t.process_epoch(&s1).unwrap();
        assert_eq!(rolled.base_fee_millisat_per_gas(), s1.base_fee_millisat_per_gas());
        assert_eq!(rolled.next_base_fee(), s1.next_base_fee());

        // A congested state raises it: forced through the committed leaf, so
        // this exercises the transition's own derivation, not the controller
        // in isolation.
        let mut congested = s1.clone();
        congested.block_gas_used = fee_market::BLOCK_GAS_LIMIT;
        congested.block_tx_bytes = fee_market::MAX_BLOCK_TX_BYTES;
        assert!(congested.next_base_fee() > congested.base_fee_millisat_per_gas());
    }

    /// The two per-block caps (fee-market spec §5) reject with their own
    /// errors. Without this the caps would be constants nothing enforces —
    /// which is what they were until 2026-08-12.
    #[test]
    fn the_two_block_caps_are_enforced() {
        // Bytes bind first for signature-heavy traffic, so the byte cap is
        // reachable with a transaction the gas cap still admits.
        let (t, g, mut chains) = setup(4);
        let fat = PosTransaction::Transfer {
            inputs: 1,
            tx_bytes: fee_market::MAX_BLOCK_TX_BYTES + 1,
            tip_millisat_per_gas: 0,
        };
        let env = probe_env(&g, 1, std::slice::from_ref(&fat), &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&fat)).unwrap_err(),
            TransitionError::BlockByteLimitExceeded,
        );

        // The gas cap needs the verify term, not the byte term: many inputs,
        // few bytes — which is exactly the shape the byte cap cannot see.
        let (t2, g2, mut chains2) = setup(4);
        let inputs = (fee_market::BLOCK_GAS_LIMIT / fee_market::HYBRID_VERIFY_GAS + 1) as u32;
        let heavy = PosTransaction::Transfer { inputs, tx_bytes: 128, tip_millisat_per_gas: 0 };
        let env2 = probe_env(&g2, 1, std::slice::from_ref(&heavy), &mut chains2);
        assert_eq!(
            t2.compute_post_state(&g2, &env2, &[], std::slice::from_ref(&heavy)).unwrap_err(),
            TransitionError::BlockGasLimitExceeded,
        );

        // And a block at exactly the byte cap is VALID — an off-by-one here
        // would make the cap unreachable and the byte axis dead.
        let (t3, g3, mut chains3) = setup(4);
        let at_cap = PosTransaction::Transfer {
            inputs: 1,
            tx_bytes: fee_market::MAX_BLOCK_TX_BYTES,
            tip_millisat_per_gas: 0,
        };
        let b = build_block(&t3, &g3, 1, &[], std::slice::from_ref(&at_cap), &mut chains3);
        assert!(t3.apply_block(&g3, &b, &[], std::slice::from_ref(&at_cap)).is_ok());
    }

    /// **The year-40 test, at the transition rather than in the arithmetic.**
    ///
    /// A block whose producer has delegators must credit those delegators from
    /// its fee revenue — in both eras, but the era that matters is the one
    /// where `epoch_issuance` is zero, because that is where crediting the fee
    /// raw to the operator (what step 11 did until 2026-08-12) would have put
    /// delegator revenue at exactly zero at the moment fees became everything.
    #[test]
    fn producer_fees_reach_delegators_through_the_commission_split() {
        let (t, g, mut chains) = setup(4);
        // A delegation behind validator 0, bonded during epoch 0 so it is
        // warming up (partially activated under the churn budget) by epoch 1 —
        // the epoch whose boundary settles the fee. Requested during E means
        // it can only count from E+1, which is why the fee block cannot be in
        // epoch 0.
        let operator = 0u32;
        let delegate = PosTransaction::Delegate {
            delegator: 900,
            validator: operator,
            // Large next to a 200,000-BLOCH self-bond, so the delegator's
            // stake-weighted share survives the pro-rata truncation.
            amount_sat: sat(600_000),
            eligible: true,
        };
        let b1 = build_block(&t, &g, 1, &[], std::slice::from_ref(&delegate), &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], std::slice::from_ref(&delegate)).unwrap();

        // Find a slot in epoch 1 that the operator itself proposes: the fee
        // accrues to the block's producer, so the producer must be the account
        // the delegation sits behind. Derived from the rolled state, not
        // guessed — the epoch-1 roster already counts the warming delegation.
        let ctx = t.process_epoch(&s1).unwrap();
        let roster = ctx.duty_roster();
        let seed = ctx.seed_for_epoch(1);
        assert!(
            delegation::Registry::resolve(&ctx.delegations, 1).stake_of(operator) > 0,
            "fixture premise: the delegation must be contributing stake by epoch 1"
        );
        let slot = (SLOTS_PER_EPOCH..2 * SLOTS_PER_EPOCH)
            .find(|s| schedule::proposer(&seed, *s, &roster) == Some(operator))
            .expect("the operator must lead some slot of the epoch");

        // A fee-paying transfer in the operator's block, with a fat tip so the
        // producer's share sits well above the pro-rata truncation floor.
        let tx = PosTransaction::Transfer {
            inputs: 2,
            tx_bytes: 9_216,
            tip_millisat_per_gas: 4_000,
        };
        let b2 = build_block(&t, &s1, slot, &[], std::slice::from_ref(&tx), &mut chains);
        assert_eq!(b2.header.proposer_index, operator);
        let s2 = t.apply_block(&s1, &b2, &[], std::slice::from_ref(&tx)).unwrap();
        let accrued = *s2.pending_fee_rewards.get(&operator).unwrap();
        assert!(accrued > 0);
        let bond_before = s2.validator_record(operator).unwrap().staked_sat;

        // The boundary settles it — through the split.
        let st = t.process_epoch(&s2).unwrap();
        let to_delegator = st.delegator_fee_reward_sat(900);
        assert!(
            to_delegator > 0,
            "delegators earned nothing from producer fees — the split is not wired"
        );
        assert_eq!(st.delegator_fee_reward_sat(901), 0, "other accounts untouched");

        // Conservation, and the exact arithmetic: the same `fee_market` call
        // the transition made, over the same committed inputs.
        let registry = delegation::Registry::resolve(&st.delegations, 1);
        let payout = fee_market::distribute_producer_fees(
            &StakeAccount {
                self_stake: bond_before,
                delegated_stake: registry.stake_of(operator),
                commission_bps: 500,
                credits: 1,
                max_credits: 1,
            },
            accrued,
        );
        assert_eq!(payout.operator + payout.delegators, accrued, "the fee must not leak");
        assert_eq!(to_delegator, payout.delegators, "delegators got something other than their share");
        // Nobody attested epoch 1, so issuance is fully forfeited and the bond
        // moved by exactly the operator's fee side.
        assert_eq!(
            st.validator_record(operator).unwrap().staked_sat,
            bond_before + payout.operator,
        );
        assert!(st.pending_fee_rewards.is_empty());

        // Commission is load-bearing, not decorative: at 0% the delegator's
        // share is strictly larger, on the same inputs.
        let uncharged = fee_market::distribute_producer_fees(
            &StakeAccount { commission_bps: 0, ..StakeAccount {
                self_stake: bond_before,
                delegated_stake: registry.stake_of(operator),
                commission_bps: 0,
                credits: 1,
                max_credits: 1,
            } },
            accrued,
        );
        assert!(uncharged.delegators > payout.delegators, "commission changed nothing");
    }

    // ── the checks migrated out of the deleted `derive::validate_block` ─────
    //
    // These two had NO negative test in this module. Their only regression
    // coverage lived in `produce.rs`'s tamper table against
    // `derive::validate_block` — a validator with no caller. Deleting that
    // validator without moving these would have deleted the proof that the
    // checks exist, which is how a check becomes a comment.

    #[test]
    fn wrong_version_rejected() {
        let (t, g, mut chains) = setup(4);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        // The Genesis-3 tag: the version this chain is migrating away from,
        // not an arbitrary number.
        b.header.version = 0xB10C_0004;
        assert_eq!(
            t.apply_block(&g, &b, &[], &[]),
            Err(TransitionError::Proposal(ProposalReject::WrongVersion)),
        );
    }

    #[test]
    fn bad_proposer_signature_rejected() {
        // MarkerVerifier rejects exactly `b"forged"`, so the block dies on the
        // proposer signature and on nothing else.
        let (t, g, mut chains) = setup_with(4, MarkerVerifier);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        // Control: the honest signature passes this verifier.
        assert!(t.apply_block(&g, &b, &[], &[]).is_ok());
        b.proposer_sig = b"forged".to_vec();
        assert_eq!(
            t.apply_block(&g, &b, &[], &[]),
            Err(TransitionError::Proposal(ProposalReject::BadSignature)),
        );
    }

    /// The `Transfer` encoding is gas-priced, and the change is a **consensus**
    /// change: `canonical_bytes` is what `body_root` is a Merkle root over, so
    /// re-shaping the variant re-keys the block id of every block carrying one.
    ///
    /// Pinned two ways: the discriminant and width are fixed (a silent shift
    /// would re-key transfers against a deployed chain), and no declared-fee
    /// field survives — the encoding carries the market's *inputs*, and the fee
    /// is derived from them plus committed state.
    #[test]
    fn transfer_encoding_is_gas_priced_not_declared() {
        let tx = PosTransaction::Transfer { inputs: 3, tx_bytes: 1_024, tip_millisat_per_gas: 7 };
        let bytes = tx.canonical_bytes();
        // 1 discriminant + u32 inputs + u64 bytes + u128 tip.
        assert_eq!(bytes.len(), 1 + 4 + 8 + 16);
        assert_eq!(bytes[0], 0x01, "the Transfer discriminant is frozen");
        assert_eq!(&bytes[1..5], &3u32.to_le_bytes());
        assert_eq!(&bytes[5..13], &1_024u64.to_le_bytes());
        assert_eq!(&bytes[13..], &7u128.to_le_bytes());

        // Injectivity over each field: two transfers differing anywhere commit
        // to different bodies, therefore different block ids.
        let vary = |inputs, tx_bytes, tip| {
            crate::derive::body_root(&[PosTransaction::Transfer {
                inputs,
                tx_bytes,
                tip_millisat_per_gas: tip,
            }
            .canonical_bytes()])
        };
        let base = vary(3, 1_024, 7);
        assert_ne!(base, vary(4, 1_024, 7));
        assert_ne!(base, vary(3, 1_025, 7));
        assert_ne!(base, vary(3, 1_024, 8));
    }

    // ── slashing through the transition (§7.3) ──────────────────────────────

    /// A double vote by `v`: two attestations, same target epoch, different
    /// heads. Signatures are the OkVerifier/MarkerVerifier-passing kind.
    fn double_vote_evidence(v: u32) -> SlashingEvidence {
        let data = |head: u8| AttestationData {
            slot: 32,
            head: [head; 32],
            source_epoch: 0,
            source_root: [1; 32],
            target_epoch: 1,
            target_root: [head; 32],
        };
        SlashingEvidence::AttestationOffence {
            first: Attestation { data: data(0xAA), validator: v, signature: vec![0u8; 8] },
            second: Attestation { data: data(0xBB), validator: v, signature: vec![0u8; 8] },
        }
    }

    /// A syntactically valid envelope for `slot` on `pre` (right proposer,
    /// reveal, mix, finality roots) with a zero state root — for tests that
    /// need `compute_post_state` to reach the transaction step and fail
    /// there, where `build_block` would refuse to assemble the block at all.
    /// A header for `slot` carrying no `state_root` — for tests that expect a
    /// rejection *before* step 12 and so never need the post-state.
    ///
    /// It takes `txs` because the header commits to the body (step 3b): a probe
    /// stamped for an empty body and then handed a transaction is now a
    /// `BodyRootMismatch`, which is the check doing its job. That also means one
    /// probe cannot serve two different tx lists — a caller comparing two bodies
    /// needs a probe per body, which is the honest shape.
    fn probe_env(
        pre: &CommittedState,
        slot: u64,
        txs: &[PosTransaction],
        chains: &mut [RandaoChain],
    ) -> ProposalEnvelope {
        let roster = pre.duty_roster();
        let seed = pre.seed_for_epoch(pre.epoch);
        let p = schedule::proposer(&seed, slot, &roster).unwrap();
        let reveal = chains[p as usize].next_reveal().unwrap();
        let fin = pre.finality_view();
        let header = BlockHeaderV4 {
            version: BLOCK_VERSION_V4,
            parent: *pre.head.as_bytes(),
            state_root: [0u8; 32],
            body_root: crate::derive::body_root(
                &txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>(),
            ),
            slot,
            proposer_index: p,
            randao_reveal: reveal,
            randao_mix: beacon::mix_in(&pre.randao_mix, &reveal),
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: crate::derive::attestation_root(&[]),
            coherence_root: pre.coherence_root(),
        };
        ProposalEnvelope { header, proposer_sig: vec![0u8; 8] }
    }

    #[test]
    fn evidence_transaction_slashes_operator_and_delegators_and_pays_whistleblower() {
        let (t, g, mut chains) = setup(4);
        let seed = g.seed_for_epoch(0);
        // Pick an offender that is NOT the proposer of the evidence-carrying
        // block, so the whistleblower's account is cleanly separable.
        let p2 = schedule::proposer(&seed, 2, &g.duty_roster()).unwrap();
        let offender = (p2 + 1) % 4;

        // Block 1: a delegator bonds behind the future offender.
        let delegate = PosTransaction::Delegate {
            delegator: 900,
            validator: offender,
            amount_sat: delegation::MIN_DELEGATION_SAT,
            eligible: true,
        };
        let b1 = build_block(&t, &g, 1, &[], std::slice::from_ref(&delegate), &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], std::slice::from_ref(&delegate)).unwrap();

        // Block 2 carries the evidence transaction.
        let ev = PosTransaction::SlashingEvidence(double_vote_evidence(offender));
        let b2 = build_block(&t, &s1, 2, &[], std::slice::from_ref(&ev), &mut chains);
        let s2 = t.apply_block(&s1, &b2, &[], std::slice::from_ref(&ev)).unwrap();
        assert_eq!(p2, b2.header.proposer_index, "test premise: whistleblower is p2");

        // Operator: 5% of the bond burned, record marked, ejected now, stake
        // locked through the weak-subjectivity margin.
        let own_loss = sat(200_000) * slashing::SLASH_PROPOSER_EQUIV_BPS / 10_000;
        let rec = s2.validator_record(offender).unwrap();
        assert!(rec.slashed);
        assert_eq!(rec.staked_sat, sat(200_000) - own_loss);
        assert_eq!(rec.exit_epoch, 0, "duties stop in the epoch of the slash");
        assert_eq!(rec.withdrawable_epoch, staking::WITHDRAWAL_DELAY_EPOCHS);
        assert!(
            !s2.active_validators().iter().any(|v| v.index == offender),
            "a slashed validator must leave the duty roster at once"
        );

        // Delegator: pro-rata loss (delegation.rs rule 3), committed to the
        // ledger a wallet reads — still exposed even though the delegation
        // was warming up, because bonded is slashable.
        let del_loss = delegation::MIN_DELEGATION_SAT * slashing::SLASH_PROPOSER_EQUIV_BPS / 10_000;
        assert_eq!(s2.delegator_slash_loss_sat(900), del_loss);
        assert_eq!(s2.delegator_slash_loss_sat(901), 0, "other accounts untouched");

        // Whistleblower: 1/32 of the total, accrued in-epoch...
        let whistle = (own_loss + del_loss) / slashing::WHISTLEBLOWER_QUOTIENT;
        assert_eq!(*s2.pending_fee_rewards.get(&p2).unwrap(), whistle);
        assert_eq!(s2.validator_record(p2).unwrap().staked_sat, sat(200_000));
        // ...and compounded into the bond only at the boundary (nobody
        // attested, so issuance contributes nothing here).
        let s3 = t.process_epoch(&s2).unwrap();
        assert_eq!(s3.validator_record(p2).unwrap().staked_sat, sat(200_000) + whistle);
        assert!(s3.pending_fee_rewards.is_empty());
    }

    #[test]
    fn proposer_equivocation_evidence_slashes_through_the_transition() {
        let (t, g, mut chains) = setup(4);
        let p1 = schedule::proposer(&g.seed_for_epoch(0), 1, &g.duty_roster()).unwrap();
        let offender = (p1 + 1) % 4;

        // Two distinct headers signed for the same slot — the offence the
        // produce.rs single-use reveal fence exists to prevent by accident.
        let equivocate = |distinguisher: u8| ProposalEnvelope {
            header: BlockHeaderV4 {
                version: BLOCK_VERSION_V4,
                parent: [distinguisher; 32],
                state_root: [0; 32],
                body_root: [0; 32],
                slot: 77,
                proposer_index: offender,
                randao_reveal: [1; 32],
                randao_mix: [2; 32],
                justified_root: [3; 32],
                finalized_root: [4; 32],
                attestation_root: [5; 32],
                coherence_root: [6; 32],
            },
            proposer_sig: vec![0u8; 8],
        };
        let ev = PosTransaction::SlashingEvidence(SlashingEvidence::ProposerEquivocation {
            first: equivocate(0xAA),
            second: equivocate(0xBB),
        });
        let b1 = build_block(&t, &g, 1, &[], std::slice::from_ref(&ev), &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], std::slice::from_ref(&ev)).unwrap();

        let rec = s1.validator_record(offender).unwrap();
        assert!(rec.slashed);
        assert_eq!(
            rec.staked_sat,
            sat(200_000) - sat(200_000) * slashing::SLASH_PROPOSER_EQUIV_BPS / 10_000,
        );
        assert!(!s1.active_validators().iter().any(|v| v.index == offender));
    }

    #[test]
    fn forged_evidence_rejects_the_block_and_slashes_nobody() {
        // MarkerVerifier: every ordinary signature passes, `b"forged"` fails —
        // so the block dies on exactly the evidence signature and nothing else.
        let (t, g, mut chains) = setup_with(4, MarkerVerifier);

        let forged = {
            let SlashingEvidence::AttestationOffence { first, mut second } =
                double_vote_evidence(2)
            else {
                unreachable!()
            };
            second.signature = b"forged".to_vec();
            PosTransaction::SlashingEvidence(SlashingEvidence::AttestationOffence {
                first,
                second,
            })
        };
        // A probe per body: the header commits to what it carries, so the
        // forged and honest bodies are different blocks. Each probe needs its
        // own RANDAO chains — a probe consumes a reveal, and a second probe off
        // the same chains would reveal the *next* link and die on
        // `BadRandaoReveal` instead of reaching the evidence. `setup_with` is
        // deterministic, so the two runs are the same chain from the same seed:
        // same slot, same parent state, same proposer draw. Only the body
        // differs, which is the comparison this test is making.
        let (_, _, mut chains_forged) = setup_with(4, MarkerVerifier);
        let env = probe_env(&g, 1, std::slice::from_ref(&forged), &mut chains_forged);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&forged)).unwrap_err(),
            TransitionError::Transaction(0),
        );

        // Same pair, honestly signed, same block context: applies and cuts —
        // proving the reject above was the forgery and only the forgery.
        let honest = PosTransaction::SlashingEvidence(double_vote_evidence(2));
        let env = probe_env(&g, 1, std::slice::from_ref(&honest), &mut chains);
        let post = t
            .compute_post_state(&g, &env, &[], std::slice::from_ref(&honest))
            .unwrap();
        assert!(post.validator_record(2).unwrap().slashed);
    }

    #[test]
    fn innocent_pair_evidence_rejects_the_block() {
        let (t, g, mut chains) = setup(4);
        // Different target epochs, no surround: honest voting across epochs.
        let data = |source_epoch: u64, target_epoch: u64| AttestationData {
            slot: target_epoch * 32,
            head: [7; 32],
            source_epoch,
            source_root: [1; 32],
            target_epoch,
            target_root: [7; 32],
        };
        let innocent = PosTransaction::SlashingEvidence(SlashingEvidence::AttestationOffence {
            first: Attestation { data: data(1, 2), validator: 2, signature: vec![0u8; 8] },
            second: Attestation { data: data(2, 3), validator: 2, signature: vec![0u8; 8] },
        });
        let env = probe_env(&g, 1, std::slice::from_ref(&innocent), &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&innocent)).unwrap_err(),
            TransitionError::Transaction(0),
        );
    }

    #[test]
    fn evidence_against_an_unregistered_index_rejects_the_block() {
        let (t, g, mut chains) = setup(4);
        let ev = PosTransaction::SlashingEvidence(double_vote_evidence(99));
        let env = probe_env(&g, 1, std::slice::from_ref(&ev), &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&ev)).unwrap_err(),
            TransitionError::Transaction(0),
        );
    }

    #[test]
    fn replayed_evidence_rejects_the_second_block_even_swapped() {
        let (t, g, mut chains) = setup(4);
        let p1 = schedule::proposer(&g.seed_for_epoch(0), 1, &g.duty_roster()).unwrap();
        let offender = (p1 + 1) % 4;
        let ev = PosTransaction::SlashingEvidence(double_vote_evidence(offender));
        let b1 = build_block(&t, &g, 1, &[], std::slice::from_ref(&ev), &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], std::slice::from_ref(&ev)).unwrap();

        // The same evidence in a later block: dead on arrival.
        let env2 = probe_env(&s1, 2, std::slice::from_ref(&ev), &mut chains);
        assert_eq!(
            t.compute_post_state(&s1, &env2, &[], std::slice::from_ref(&ev)).unwrap_err(),
            TransitionError::Transaction(0),
        );
        // Swapping the pair does not mint fresh evidence. Different bytes, so
        // a different body, so its own probe.
        let swapped = {
            let SlashingEvidence::AttestationOffence { first, second } =
                double_vote_evidence(offender)
            else {
                unreachable!()
            };
            PosTransaction::SlashingEvidence(SlashingEvidence::AttestationOffence {
                first: second,
                second: first,
            })
        };
        let (_, _, mut chains_swapped) = setup(4);
        let env3 = probe_env(&s1, 2, std::slice::from_ref(&swapped), &mut chains_swapped);
        assert_eq!(
            t.compute_post_state(&s1, &env3, &[], std::slice::from_ref(&swapped)).unwrap_err(),
            TransitionError::Transaction(0),
        );
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
            commission_bps: 0,
        };
        vals.push(cohort_val.clone());
        for i in 1..3u32 {
            cohort_val.index = i;
            cohort_val.staked_sat = sat(1_000_000);
            cohort_val.pubkey = vec![i as u8; 8];
            vals.push(cohort_val.clone());
        }
        let st = CommittedState::genesis(
            genesis_block_id(),
            [2; 32],
            &vals,
            &[0],
            [0; 32],
            [0; 32],
            [0; 32],
            EvmCommitment {
                account_root: [0; 32],
                receipts_root: [0; 32],
                gas_used: 0,
                base_fee_per_gas: 1,
            },
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

    // ── the 2026-08-11 commitment-gap closure ───────────────────────────────

    /// A state in which every bookkeeping component is non-empty: a deposit,
    /// a delegation, a fee-paying transfer and a full attestation quorum have
    /// all been applied, and one equivocator is barred. This is the fixture
    /// the two tests below share — a state where the pre-extension root would
    /// have been blind to most of what follows.
    fn state_with_live_bookkeeping() -> (Transition<OkVerifier>, CommittedState, Vec<Attestation>)
    {
        let (t, g, mut chains) = setup(8);
        let deposit = PosTransaction::Deposit {
            pubkey: vec![0xAB; 8],
            amount_sat: staking::MIN_DEPOSIT_SAT,
            randao_commitment: [0xCD; 32],
            withdrawal_credentials: vec![0xEF; 4],
            commission_bps: 500,
        };
        let delegate = PosTransaction::Delegate {
            delegator: 900,
            validator: 0,
            amount_sat: delegation::MIN_DELEGATION_SAT,
            eligible: true,
        };
        let fee = PosTransaction::Transfer { inputs: 1, tx_bytes: 512, tip_millisat_per_gas: 5 };
        let slot1 = SLOTS_PER_EPOCH + 1;
        let b1 =
            build_block(&t, &g, slot1, &[], &[deposit.clone(), fee.clone()], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[deposit, fee]).unwrap();
        let b2 =
            build_block(&t, &s1, slot1 + 1, &[], std::slice::from_ref(&delegate), &mut chains);
        let s2 = t.apply_block(&s1, &b2, &[], &[delegate]).unwrap();
        let atts = full_epoch_attestations(&s2, *s1.head().as_bytes());
        let b3 = build_block(&t, &s2, slot1 + 7, &atts, &[], &mut chains);
        let mut st = t.apply_block(&s2, &b3, &atts, &[]).unwrap();
        // One barred equivocator, so that component is non-empty too. (The
        // committed bar is monotone; inserting here models a prior verdict.)
        st.fc_equivocators.insert(7);
        st.latest_messages.remove(&7);

        // The fixture must actually be live, or the coverage below is voided.
        assert!(!st.pending_votes.is_empty());
        assert!(!st.latest_messages.is_empty());
        assert!(!st.fc_equivocators.is_empty());
        assert!(!st.deposit_history.is_empty());
        assert!(!st.delegations.is_empty());
        assert!(!st.pending_fee_rewards.is_empty());
        assert!(!st.boundary_mixes.is_empty());
        (t, st, atts)
    }

    /// Every consensus-relevant `CommittedState` field moves the root; every
    /// deliberately-uncommitted field does not, and says why. This test is
    /// the inventory from the 2026-08-11 gap closure, executable: if someone
    /// adds a field to `CommittedState` and forgets `compute_root`, the
    /// matching mutation added here (per the module docs) is what will catch
    /// the next gap — and if they forget the mutation too, the reviewer has
    /// this list to diff against the struct.
    #[test]
    fn every_committed_state_field_is_bound_by_the_root() {
        let (_t, st, _) = state_with_live_bookkeeping();
        let base = st.compute_root();

        let mut moved = vec![base];
        macro_rules! must_move {
            ($what:expr, $m:expr) => {{
                let mut g = st.clone();
                #[allow(clippy::redundant_closure_call)]
                ($m)(&mut g);
                let r = g.compute_root();
                assert_ne!(r, base, "{} must be bound by the state root", $what);
                moved.push(r);
            }};
        }

        // The epoch clock (committed via the running-mix entry key).
        must_move!("epoch", |g: &mut CommittedState| g.epoch += 1);
        // Registry columns, including the 2026-08-11 additions.
        must_move!("validator stake", |g: &mut CommittedState| {
            g.validators.get_mut(&0).unwrap().staked_sat += 1
        });
        must_move!("validator randao_commitment", |g: &mut CommittedState| {
            g.validators.get_mut(&0).unwrap().randao_commitment[0] ^= 1
        });
        must_move!("validator withdrawable_epoch", |g: &mut CommittedState| {
            g.validators.get_mut(&0).unwrap().withdrawable_epoch = 99
        });
        must_move!("validator withdrawal_credentials", |g: &mut CommittedState| {
            g.validators.get_mut(&0).unwrap().withdrawal_credentials.push(0x01)
        });
        must_move!("reveals_used", |g: &mut CommittedState| {
            *g.reveals_used.get_mut(&0).unwrap() += 1
        });
        // Beacon state.
        must_move!("randao_mix", |g: &mut CommittedState| g.randao_mix[0] ^= 1);
        must_move!("boundary_mixes", |g: &mut CommittedState| {
            for (_, m) in g.boundary_mixes.iter_mut() {
                m[0] ^= 1;
            }
        });
        // Finality bookkeeping.
        must_move!("finality_engine", |g: &mut CommittedState| {
            g.finality_engine = finality::FinalityState::new(finality::Checkpoint {
                epoch: 0,
                root: [0xEE; 32],
            })
        });
        must_move!("previous_justified", |g: &mut CommittedState| {
            g.previous_justified.epoch += 1
        });
        must_move!("pending_votes (removal)", |g: &mut CommittedState| {
            let k = *g.pending_votes.keys().next().unwrap();
            g.pending_votes.remove(&k);
        });
        // Fork-choice bookkeeping.
        must_move!("latest_messages", |g: &mut CommittedState| {
            for (_, (slot, _)) in g.latest_messages.iter_mut() {
                *slot += 1;
            }
        });
        must_move!("fc_equivocators", |g: &mut CommittedState| {
            g.fc_equivocators.insert(6);
        });
        // Staking queues and fees.
        must_move!("deposit_history", |g: &mut CommittedState| {
            g.deposit_history[0].amount_sat += 1
        });
        must_move!("delegations", |g: &mut CommittedState| {
            g.delegations[0].amount_sat += 1
        });
        must_move!("pending_fee_rewards", |g: &mut CommittedState| {
            for (_, amount) in g.pending_fee_rewards.iter_mut() {
                *amount += 1;
            }
        });
        // Participation.
        must_move!("current_participation", |g: &mut CommittedState| {
            let k = *g.current_participation.keys().next().unwrap();
            let v = g.current_participation[&k];
            g.current_participation.insert(k, !v);
        });
        must_move!("previous_participation", |g: &mut CommittedState| {
            g.previous_participation.insert(999, true);
        });
        // Slashing bookkeeping (§7.3). The registry effects of a slash were
        // already covered above; these are the three components that decide
        // whether a slash may happen at all, and they went uncommitted until
        // 2026-08-12.
        must_move!("slashing applied-evidence set", |g: &mut CommittedState| {
            g.slashing.poke_for_test(Some([0x5A; 32]), None)
        });
        must_move!("slashing correlation window", |g: &mut CommittedState| {
            g.slashing.poke_for_test(None, Some((3, 1_000)))
        });
        must_move!("delegator_slash_losses", |g: &mut CommittedState| {
            g.delegator_slash_losses.insert(4, 777);
        });
        // Validator commission — it decides how a boundary splits BOTH revenue
        // streams, so a node that disagreed on it would compound a different
        // bond from the same block.
        must_move!("validator commission_bps", |g: &mut CommittedState| {
            g.validators.get_mut(&0).unwrap().commission_bps += 1
        });
        // Fee market (2026-08-12): the price leaf the next block's controller
        // reads, and the delegator earning ledger.
        must_move!("base_fee_millisat_per_gas", |g: &mut CommittedState| {
            g.base_fee_millisat_per_gas += 1
        });
        must_move!("block_gas_used", |g: &mut CommittedState| g.block_gas_used += 1);
        must_move!("block_tx_bytes", |g: &mut CommittedState| g.block_tx_bytes += 1);
        must_move!("delegator_fee_rewards", |g: &mut CommittedState| {
            g.delegator_fee_rewards.insert(4, 888);
        });
        // Carried roots.
        must_move!("taint_root", |g: &mut CommittedState| g.taint_root[0] ^= 1);
        must_move!("coherence_accumulator_root", |g: &mut CommittedState| {
            g.coherence_accumulator_root[0] ^= 1
        });
        must_move!("coherence_nullifier_root", |g: &mut CommittedState| {
            g.coherence_nullifier_root[0] ^= 1
        });

        // Distinct mutations must commit distinctly — a collision would mean
        // two different states share a root.
        for i in 0..moved.len() {
            for j in (i + 1)..moved.len() {
                assert_ne!(moved[i], moved[j], "states {i} and {j} share a root");
            }
        }

        // ── Deliberately NOT committed — each with its reconstruction
        //    argument (module docs), pinned so a future change is a decision,
        //    not an accident. ─────────────────────────────────────────────
        // `slot`: bound by the header that carries the root; it cannot change
        // without `head` changing.
        let mut g = st.clone();
        g.slot += 1;
        assert_eq!(g.compute_root(), base, "slot is header-bound, not root-bound");
        // `genesis_mix` / `genesis_cohort`: genesis constants — chain
        // identity, immutable after genesis, like the genesis block id.
        let mut g = st.clone();
        g.genesis_mix[0] ^= 1;
        assert_eq!(g.compute_root(), base, "genesis_mix is chain identity");
        let mut g = st.clone();
        g.genesis_cohort.push(3);
        assert_eq!(g.compute_root(), base, "genesis_cohort is chain identity");
        // `pubkey_index`: a derived index over the committed registry.
        let mut g = st.clone();
        g.pubkey_index.clear();
        assert_eq!(g.compute_root(), base, "pubkey_index is derived from the registry");
    }

    /// Two nodes that reach the same state over different paths — buffered
    /// out-of-order delivery, reversed attestation order inside the carrier
    /// block, and explicit vs implicit epoch processing — commit the SAME
    /// root, at a point where every bookkeeping component of the 2026-08-11
    /// extension is non-empty. This is the §5.5 property re-proven over the
    /// extended component list: before the extension this test would have
    /// passed vacuously, because the root could not see most of the state it
    /// now binds.
    #[test]
    fn convergent_paths_commit_identical_roots_with_bookkeeping_live() {
        let (t, g, mut chains) = setup(8);
        let deposit = PosTransaction::Deposit {
            pubkey: vec![0xAB; 8],
            amount_sat: staking::MIN_DEPOSIT_SAT,
            randao_commitment: [0xCD; 32],
            withdrawal_credentials: vec![0xEF; 4],
            commission_bps: 500,
        };
        let delegate = PosTransaction::Delegate {
            delegator: 900,
            validator: 0,
            amount_sat: delegation::MIN_DELEGATION_SAT,
            eligible: true,
        };
        let fee = PosTransaction::Transfer { inputs: 1, tx_bytes: 512, tip_millisat_per_gas: 5 };
        let slot1 = SLOTS_PER_EPOCH + 1;
        let b1 =
            build_block(&t, &g, slot1, &[], &[deposit.clone(), fee.clone()], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[deposit.clone(), fee.clone()]).unwrap();
        let b2 =
            build_block(&t, &s1, slot1 + 1, &[], std::slice::from_ref(&delegate), &mut chains);
        let s2 = t.apply_block(&s1, &b2, &[], std::slice::from_ref(&delegate)).unwrap();
        let atts = full_epoch_attestations(&s2, *s1.head().as_bytes());
        let b3 = build_block(&t, &s2, slot1 + 7, &atts, &[], &mut chains);

        // Node A: chain order, implicit epoch rollover inside apply_block.
        let a = t.apply_block(&s2, &b3, &atts, &[]).unwrap();

        // Node B: processed the empty genesis-epoch boundary EXPLICITLY, then
        // applied the same blocks with b3's attestations delivered reversed.
        let e1 = t.process_epoch(&g).unwrap();
        let r1 = t.apply_block(&e1, &b1, &[], &[deposit, fee]).unwrap();
        let r2 = t.apply_block(&r1, &b2, &[], &[delegate]).unwrap();
        let mut reversed = atts.clone();
        reversed.reverse();
        // Since step 3b the header commits to the ordered attestation list, so
        // the reversed delivery is a different block and needs its own root.
        // Re-stamped rather than rebuilt so everything except the ordering is
        // held constant — the claim under test is that ordering does not reach
        // committed state, not that two different blocks agree.
        let mut b3_rev = b3.clone();
        b3_rev.header.attestation_root = crate::derive::attestation_root(&reversed);
        b3_rev.header.state_root =
            t.compute_post_state(&r2, &b3_rev, &reversed, &[]).unwrap().state_root();
        let b = t.apply_block(&r2, &b3_rev, &reversed, &[]).unwrap();

        // Mid-epoch, with every extended component live — not after a
        // boundary flushed the interesting state away.
        assert!(!a.pending_votes.is_empty(), "fixture must exercise pending votes");
        assert!(!a.latest_messages.is_empty(), "fixture must exercise fork-choice messages");
        assert!(!a.deposit_history.is_empty(), "fixture must exercise the deposit queue");
        assert!(!a.delegations.is_empty(), "fixture must exercise delegations");
        assert!(!a.pending_fee_rewards.is_empty(), "fixture must exercise pending fees");

        // The COMMITTED state must be identical; `head` legitimately is not,
        // because re-stamping the attestation root made b3_rev a different
        // block with a different id. That is the distinction the extension
        // draws on purpose: `head` is bound by the header, never by the root
        // (committing it would be circular), so two blocks that commit the same
        // state can differ in identity. Comparing whole `CommittedState`s here
        // would be comparing that identity too, and would fail for a reason
        // that has nothing to do with the property under test.
        assert_eq!(
            a.state_root(),
            b.state_root(),
            "same chain, different paths: the committed roots must be identical"
        );
        assert_eq!(a.epoch, b.epoch);
        assert_eq!(a.validators, b.validators);
        assert_eq!(a.pending_votes, b.pending_votes);
        assert_eq!(a.latest_messages, b.latest_messages);
        assert_eq!(a.pending_fee_rewards, b.pending_fee_rewards);

        // And the roots keep agreeing across the boundary that consumes the
        // pending components (votes tallied, fees compounded).
        let a4 = t.process_epoch(&a).unwrap();
        let b4 = t.process_epoch(&b).unwrap();
        assert_eq!(a4.state_root(), b4.state_root());
    }

    /// **The regression test for step 3b.** Each of the three header
    /// commitments must reject on its own, with its own error.
    ///
    /// Without this, the checks could be silently deleted and every other test
    /// would still pass — which is exactly the state the crate was in until
    /// 2026-08-12, when the stack the node runs checked none of them and 178
    /// green tests said nothing about it. A check with no negative test is a
    /// comment.
    #[test]
    fn header_must_commit_to_body_attestations_and_coherence() {
        let (t, g, mut chains) = setup(4);
        let deposit = PosTransaction::Exit { validator: 3 };
        let good = build_block(&t, &g, 1, &[], std::slice::from_ref(&deposit), &mut chains);
        // Control: it applies.
        assert!(t.apply_block(&g, &good, &[], std::slice::from_ref(&deposit)).is_ok());

        // A body the header does not name.
        let mut b = good.clone();
        b.header.body_root = [0xAB; 32];
        assert_eq!(
            t.compute_post_state(&g, &b, &[], std::slice::from_ref(&deposit)).unwrap_err(),
            TransitionError::BodyRootMismatch,
        );
        // ...and the reverse direction: header untouched, body swapped. This is
        // the case that matters, because it is the one an attacker controls.
        let other = PosTransaction::Exit { validator: 2 };
        assert_eq!(
            t.compute_post_state(&g, &good, &[], std::slice::from_ref(&other)).unwrap_err(),
            TransitionError::BodyRootMismatch,
        );

        let mut b = good.clone();
        b.header.attestation_root = [0xCD; 32];
        assert_eq!(
            t.compute_post_state(&g, &b, &[], std::slice::from_ref(&deposit)).unwrap_err(),
            TransitionError::AttestationRootMismatch,
        );

        let mut b = good.clone();
        b.header.coherence_root = [0xEF; 32];
        assert_eq!(
            t.compute_post_state(&g, &b, &[], std::slice::from_ref(&deposit)).unwrap_err(),
            TransitionError::CoherenceRootMismatch,
        );

        // The Coherence mirror is a real binding, not a copy of the parent's
        // header field: a state whose pool roots differ must demand a different
        // header value, even though the pool is inert.
        let mut moved = g.clone();
        moved.coherence_accumulator_root = [0x77; 32];
        assert_ne!(
            crate::derive::coherence_binding(
                &moved.coherence_accumulator_root,
                &moved.coherence_nullifier_root,
            ),
            good.header.coherence_root,
            "the coherence binding ignored the accumulator root"
        );
    }


    /// The `ejected` set is **not** a committed component, and this is why it
    /// does not need to be: it is exactly `{v : registry[v].slashed}`.
    ///
    /// Without this test the omission is an assertion in a comment. With it,
    /// the day the two stop agreeing — a code path that ejects without marking
    /// the record, or removes a record — is the day this fails, and the choice
    /// gets re-made deliberately instead of becoming a silent hole in
    /// state-sync. (Committing both would be worse: two copies of one fact,
    /// free to drift, in the structure whose whole purpose is that they cannot.)
    #[test]
    fn ejected_set_is_exactly_the_slashed_registry() {
        let (t, g, mut chains) = setup(4);
        let seed = g.seed_for_epoch(0);
        let p1 = schedule::proposer(&seed, 1, &g.duty_roster()).unwrap();
        let offender = (p1 + 1) % 4;

        // Before: both empty.
        assert_eq!(g.slashing.ejected_ids().count(), 0);
        assert!(!g.validators.values().any(|r| r.slashed));

        let ev = PosTransaction::SlashingEvidence(double_vote_evidence(offender));
        let b1 = build_block(&t, &g, 1, &[], std::slice::from_ref(&ev), &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], std::slice::from_ref(&ev)).unwrap();

        let ejected: BTreeSet<u32> = s1.slashing.ejected_ids().copied().collect();
        let slashed: BTreeSet<u32> =
            s1.validators.values().filter(|r| r.slashed).map(|r| r.index).collect();
        assert!(!ejected.is_empty(), "the fixture must actually slash someone");
        assert_eq!(ejected, slashed, "ejected and the slashed registry disagree");

        // And the state root moves, because the registry side of the fact is
        // committed — so a state-synced node sees the ejection even though the
        // set itself is not a leaf.
        assert_ne!(s1.compute_root(), g.compute_root());
    }

    // ── The hard cap as a consensus invariant (2026-08-12) ──────────────────

    /// A pre-state whose committed issuance exceeds the cap is refused — with
    /// its own error, before any signature work. This is the case the check
    /// exists for: the transition's own arithmetic clamps at the cap, so an
    /// over-cap state can only arrive from outside (a forged snapshot, a
    /// corrupted sync), and an honest node must refuse to extend it rather
    /// than launder it under a valid block.
    #[test]
    fn block_on_a_state_beyond_the_cap_is_rejected() {
        let (t, g, mut chains) = setup(4);
        // The block itself is honest — built against the honest state...
        let b1 = build_block(&t, &g, 1, &[], &[], &mut chains);
        // ...but the state it is applied to claims one satoshi too many.
        let mut over = g.clone();
        over.issued_sat = tokenomics_v4::TOTAL_SUPPLY_SAT + 1;
        assert_eq!(
            t.compute_post_state(&over, &b1, &[], &[]).unwrap_err(),
            TransitionError::SupplyCapExceeded,
        );
    }

    /// Exactly at the cap is VALID: the invariant is `issued <= cap`, and a
    /// chain that has emitted its entire supply keeps producing (fee-only)
    /// blocks forever. An off-by-one here would halt the chain at the exact
    /// moment the emission schedule completes.
    #[test]
    fn block_exactly_at_the_cap_is_accepted() {
        let (t, g, mut chains) = setup(4);
        let mut at_cap = g.clone();
        at_cap.issued_sat = tokenomics_v4::TOTAL_SUPPLY_SAT;
        let b1 = build_block(&t, &at_cap, 1, &[], &[], &mut chains);
        let s1 = t.apply_block(&at_cap, &b1, &[], &[]).expect("at-cap block rejected");
        assert_eq!(s1.issued_sat, tokenomics_v4::TOTAL_SUPPLY_SAT, "no issuance may follow");
    }

    /// Emission stops at the cap: an epoch boundary crossed with zero
    /// headroom credits nothing, and a boundary crossed with less headroom
    /// than the curve offers credits at most the headroom. Fees still flow —
    /// the cap ends issuance, not the chain.
    #[test]
    fn emission_stops_at_the_cap() {
        // Epoch 1, not 0: an epoch-0 attestation cannot exist (source epoch 0
        // is not < target epoch 0), and without attestations nobody earns, so
        // the assertion would be vacuous.
        let slot_last = 2 * SLOTS_PER_EPOCH - 1;

        // Zero headroom: the boundary must mint nothing at all.
        let (t, g, mut chains) = setup(4);
        let mut at_cap = t.process_epoch(&g).unwrap();
        at_cap.issued_sat = tokenomics_v4::TOTAL_SUPPLY_SAT;
        // Full participation, so every validator WOULD earn if headroom allowed.
        let atts = full_epoch_attestations(&at_cap, *at_cap.head.as_bytes());
        let b = build_block(&t, &at_cap, slot_last, &atts, &[], &mut chains);
        let s = t.apply_block(&at_cap, &b, &atts, &[]).unwrap();
        let bonded_before: u128 = at_cap.validators.values().map(|r| r.staked_sat).sum();
        let rolled = t.process_epoch(&s).unwrap();
        let bonded_after: u128 = rolled.validators.values().map(|r| r.staked_sat).sum();
        assert_eq!(bonded_after, bonded_before, "issuance was minted past the cap");
        assert_eq!(rolled.issued_sat, tokenomics_v4::TOTAL_SUPPLY_SAT);

        // Partial headroom: the boundary credits at most the headroom, never
        // the full curve amount, and lands at the cap or under it.
        let (t2, g2, mut chains2) = setup(4);
        let headroom: u128 = 1_000; // far below the epoch's curve issuance
        let mut near_cap = t2.process_epoch(&g2).unwrap();
        near_cap.issued_sat = tokenomics_v4::TOTAL_SUPPLY_SAT - headroom;
        let atts2 = full_epoch_attestations(&near_cap, *near_cap.head.as_bytes());
        let b2 = build_block(&t2, &near_cap, slot_last, &atts2, &[], &mut chains2);
        let s2 = t2.apply_block(&near_cap, &b2, &atts2, &[]).unwrap();
        let rolled2 = t2.process_epoch(&s2).unwrap();
        assert!(
            rolled2.issued_sat <= tokenomics_v4::TOTAL_SUPPLY_SAT,
            "the boundary crossed the cap: {}",
            rolled2.issued_sat
        );
        assert!(
            rolled2.issued_sat > near_cap.issued_sat,
            "with headroom left, the boundary must still mint"
        );
        // And the next block on that chain is still valid: the cap ends
        // issuance, not the chain.
        let b3 = build_block(&t2, &rolled2, slot_last + 2, &[], &[], &mut chains2);
        assert!(t2.apply_block(&rolled2, &b3, &[], &[]).is_ok(), "chain must outlive emission");
    }

    /// No path in this crate can raise the cap. What a test CAN prove, it
    /// proves; what only the type system proves, it names:
    ///
    /// - `TOTAL_SUPPLY_SAT` is a `const` — there is no setter, no config
    ///   field, no genesis parameter that feeds it; the reference below is a
    ///   compile-time constant expression, which is the proof.
    /// - The transaction enum is matched EXHAUSTIVELY here with no wildcard
    ///   arm, so adding a variant (the only in-protocol road to a mint or a
    ///   cap change) fails this test's compilation and forces a human through
    ///   this comment.
    /// - Issuance is monotone and cap-bounded across boundaries (checked).
    ///
    /// Honest limit, stated as in the spec: this pins that no mechanism
    /// INSIDE the protocol changes the cap. A hard fork adopted by every
    /// operator can change any rule — the claim "impossible to alter" would
    /// be false, and this test does not make it.
    #[test]
    fn no_in_protocol_path_can_raise_the_cap() {
        // Const, pinned by value: 100 B BLCH at 8 decimals.
        const CAP: u128 = tokenomics_v4::TOTAL_SUPPLY_SAT;
        assert_eq!(CAP, 10_000_000_000_000_000_000);

        // Exhaustive match, no `_` arm: every transaction the protocol can
        // carry is enumerated, and none of them is a mint or a cap edit —
        // Transfer moves existing coins and pays fees from them, Deposit and
        // Delegate bond existing coins, Exit unbonds them, evidence burns.
        let witness = PosTransaction::Exit { validator: 0 };
        match &witness {
            PosTransaction::Transfer { .. } => {}
            PosTransaction::Deposit { .. } => {}
            PosTransaction::Exit { .. } => {}
            PosTransaction::Delegate { .. } => {}
            PosTransaction::SlashingEvidence(_) => {}
        }

        // Monotone under blocks and boundaries, and never above the cap.
        // Epoch 1, because epoch-0 attestations cannot exist (source 0 is not
        // < target 0) and unattested validators earn nothing.
        let (t, g, mut chains) = setup(4);
        assert_eq!(g.issued_sat, tokenomics_v4::GENESIS_ISSUED_SAT);
        let e1 = t.process_epoch(&g).unwrap();
        assert_eq!(e1.issued_sat, g.issued_sat, "epoch 0 had no attesters, so no issuance");
        let atts = full_epoch_attestations(&e1, *e1.head.as_bytes());
        let b = build_block(&t, &e1, 2 * SLOTS_PER_EPOCH - 1, &atts, &[], &mut chains);
        let s = t.apply_block(&e1, &b, &atts, &[]).unwrap();
        assert_eq!(s.issued_sat, e1.issued_sat, "a block mid-epoch must not issue");
        let rolled = t.process_epoch(&s).unwrap();
        assert!(rolled.issued_sat >= s.issued_sat, "issuance regressed");
        assert!(rolled.issued_sat <= CAP);
        // The boundary with full participation actually minted something —
        // otherwise the monotonicity above was checked vacuously.
        assert!(rolled.issued_sat > s.issued_sat, "fixture minted nothing");
    }
}
