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
//! 9. `Transaction(i)` / `Transfer(i, reason)` — in body order. The staking
//!    arms are cheap state lookups. A transfer runs its own frozen
//!    cheapest-first order *within* the transaction (structure, size floor,
//!    set membership, script hashes, conservation, then the hybrid
//!    verifications last) — see [`CommittedState::apply_transfer`] — and
//!    reports which rule it broke, because those rules decide who may move
//!    coins and a bare index is not enough to debug a divergence over one.
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
    ProposalReject, SlashingEvidence, StateReader, StateTransition, TransferReject,
    TransitionError, ValidatorRecord,
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

/// One spent output, with the witness that authorises spending it.
///
/// The outpoint (`txid`, `vout`) names *which* coin; the witness proves the
/// spender may move it. Both halves are carried in the same struct because a
/// spend that reached consensus without its witness would be a spend nobody
/// authorised, and there is no state in which one is meaningful without the
/// other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferInput {
    /// Id of the transaction that created the output being spent.
    pub txid: [u8; 32],
    /// Index of that output within its creating transaction.
    pub vout: u32,
    /// The hybrid public key whose SHA3-256 the output's `script_hash`
    /// commits to. Carried in the witness, not in the state: the set stores
    /// the *hash* of the key, so a ≈3.7 KB key only ever hits the wire when
    /// the coin actually moves.
    pub pubkey: Vec<u8>,
    /// Hybrid signature over the transfer's signing root
    /// ([`PosTransaction::spend_signing_root`]).
    pub signature: Vec<u8>,
}

/// One witness-table entry of a [`PosTransaction::TransferV2`]: a public key
/// and ONE hybrid signature over the transfer's signing root.
///
/// The V1 shape carries this pair inside every input. But a transfer has one
/// signing root ([`PosTransaction::spend_signing_root`]), so N inputs owned
/// by one key carry N copies of a 3,749 B key and N 4,775 B proofs of the
/// same statement — measured 2026-08-21, that caps a 262,144 B block at ~30
/// inputs and costs 30 × 145 µs of verification to establish what one
/// verification establishes. V2 lifts the pair into a per-owner table;
/// inputs point into it by index. Same key, same root, same check — the
/// security cost of revealing the key once instead of N times is zero,
/// because the N copies were byte-identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessKey {
    /// The hybrid public key whose SHA3-256 the spent outputs' `script_hash`
    /// commits to — the same key a V1 input carries, carried once.
    pub pubkey: Vec<u8>,
    /// Hybrid signature over [`PosTransaction::spend_signing_root`]. One per
    /// owner, not one per input: the root already covers every spend point,
    /// so one signature authorises all of this owner's inputs.
    pub signature: Vec<u8>,
}

/// One spent output of a [`PosTransaction::TransferV2`]: the outpoint, plus
/// the index of the witness-table entry that authorises it — 40 bytes
/// against V1's 8,560.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferInputV2 {
    /// Id of the transaction that created the output being spent.
    pub txid: [u8; 32],
    /// Index of that output within its creating transaction.
    pub vout: u32,
    /// Index into the transfer's witness table ([`WitnessKey`]). Witness
    /// data, outside the signing root — same argument as the pubkey itself:
    /// consensus checks it against the committed `script_hash`, so a third
    /// party re-pointing it either changes nothing (same key) or fails
    /// [`TransferReject::ScriptMismatch`]/[`TransferReject::WitnessKeyUnused`].
    pub key_index: u32,
}

/// Rewrite a [`PosTransaction::TransferV2`] witness table into the one order
/// consensus accepts — ascending by pubkey bytes — remapping every input's
/// `key_index` through the same permutation. **The builder-side contract**
/// for [`TransferReject::WitnessTableNotCanonical`]: a wallet assembles its
/// table in any convenient order, calls this once, and the result is the
/// canonical encoding.
///
/// Pure re-indexing, and provably signature-neutral: the table and the
/// `key_index` fields sit outside [`PosTransaction::spend_signing_root`], so
/// this changes neither the root, nor the txid, nor any signature's
/// validity; and the charge is untouched because the class term of the fee
/// is `keys.len()`, invariant under permutation. The one thing it changes is
/// `canonical_bytes` — onto the unique encoding all nodes admit.
///
/// Degenerate inputs are passed through, not repaired: duplicate pubkeys
/// stay adjacent duplicates (still [`TransferReject::DuplicateWitnessKey`] —
/// the stable sort cannot merge them because which signature survives would
/// be this function's invention), and a `key_index` already past the table
/// is left as it is (still [`TransferReject::BadKeyIndex`]). Canonical form
/// is about ORDER; the other table disciplines keep their own rejects.
pub fn canonicalize_witness_table(keys: &mut Vec<WitnessKey>, inputs: &mut [TransferInputV2]) {
    // Sort a permutation, not the table: the table entries are ~8.5 KB each
    // (hybrid key + signature) and the remap needs old→new positions anyway.
    let mut order: Vec<u32> = (0..keys.len() as u32).collect();
    order.sort_by(|a, b| keys[*a as usize].pubkey.cmp(&keys[*b as usize].pubkey));
    let mut new_index = vec![0u32; keys.len()];
    for (new, old) in order.iter().enumerate() {
        new_index[*old as usize] = new as u32;
    }
    let mut sorted: Vec<WitnessKey> =
        order.iter().map(|old| keys[*old as usize].clone()).collect();
    core::mem::swap(keys, &mut sorted);
    for i in inputs.iter_mut() {
        if let Some(n) = new_index.get(i.key_index as usize) {
            i.key_index = *n;
        }
    }
}

/// One created output: an amount, and the commitment to who may spend it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferOutput {
    /// Value in satoshis. `u64` per output, exactly as the committed
    /// [`crate::state_root::EutxoEntry`] holds it; **sums are `u128`**, which
    /// is the whole reason a 100-billion-BLCH supply at 8 decimals is
    /// representable without the totals wrapping.
    pub value: u64,
    /// SHA3-256 of the locking script — here, of the spender's public key.
    pub script_hash: [u8; 32],
}

/// The transaction shapes this transition interprets. Value transfers move
/// real coins out of the committed unspent set and into new outputs; deposits,
/// exits and delegations are the staking-lifecycle messages whose
/// *state-dependent* rules this transition owns; their remaining cryptographic
/// admission checks (proof of possession, taint/transparency of inputs) run at
/// the mempool boundary against DEV-3's `StakingLifecycle`/`StakeEligibility`
/// implementations, which `apply_block`'s frozen signature deliberately does
/// not receive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PosTransaction {
    /// A value transfer against the committed eUTXO set, priced by the L1 fee
    /// market: **gas × price**, where the gas is derived (class + size,
    /// `fee_market::intrinsic_gas`) and the price is the base fee this block's
    /// committed state fixes.
    ///
    /// # Two revisions, and what each closed
    ///
    /// It first read `Transfer { base_fee_sat, priority_fee_sat }` — a
    /// transaction that declared, in satoshis, what it felt like paying. That
    /// is not a placeholder for a fee market, it is the absence of one:
    /// nothing constrained the number, so a proposer could include a transfer
    /// claiming any fee at all and compound it into its own bond.
    ///
    /// It then read `Transfer { inputs: u32, tx_bytes, tip }` — three gas
    /// terms with **no sender, no recipient and no amount**. The committed
    /// state carried the 452,133-output opening ledger and the state root
    /// committed to it, but no transaction could take a satoshi out of it: the
    /// chain had balances and no payments. This revision is what makes the
    /// ledger move, and it is where the authorisation rule lives — an output
    /// is spendable by whoever produces the key its `script_hash` commits to,
    /// and by nobody else.
    ///
    /// Each revision changes `canonical_bytes`, therefore `body_root`,
    /// therefore the block id of every block carrying a transfer. That is a
    /// consensus change and is pinned by
    /// `tests::transfer_encoding_carries_value_not_only_gas`.
    Transfer {
        /// The outputs being spent, each with its own witness — and each
        /// costing one hybrid verification, which is the class term of the gas
        /// charge. The count is **derived from this list**: an input count a
        /// transaction merely asserted would let it buy N verifications'
        /// worth of node CPU at the price of one.
        inputs: Vec<TransferInput>,
        /// The outputs being created. Their keys are `(txid, vout)` where the
        /// txid is [`PosTransaction::txid`] — derived, never carried, so a
        /// transaction cannot name the location it writes to.
        outputs: Vec<TransferOutput>,
        /// Payload bytes this transaction makes every node carry and store.
        /// The dominant gas term for PQ-signed traffic, and the quantity the
        /// block's byte cap is measured against.
        ///
        /// Declared rather than derived, so a transfer can pay for the
        /// off-chain weight it imposes; but consensus refuses a declaration
        /// **below** the transaction's own canonical length
        /// ([`TransferReject::UnderdeclaredSize`]), because the alternative is
        /// a witness-heavy transaction that pays for none of its witnesses and
        /// counts for nothing against the block's byte cap.
        tx_bytes: u64,
        /// The sender's tip, in millisatoshi per gas. The **only** user-set
        /// price in the system: the base fee is the protocol's.
        tip_millisat_per_gas: u128,
    },
    /// A value transfer with the witnesses deduplicated per owner (wire tag
    /// `0x06`) — INERT until
    /// [`crate::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`].
    ///
    /// Semantically identical to [`Self::Transfer`]: the same outputs move
    /// under the same authorisation rule, and the signing root — therefore
    /// the txid, therefore every created outpoint — is **byte-identical**
    /// between the two encodings of one logical transfer (the root covers
    /// spend points, outputs, `tx_bytes` and tip; witnesses and indices are
    /// outside it in both formats, see [`Self::spend_signing_root`]). A
    /// wallet signature is valid under either encoding; only the wire shape
    /// and the admission checks differ.
    ///
    /// What differs: each owner's (pubkey, signature) pair appears once, in
    /// `keys`, and each 40-byte input points at its entry. Two table
    /// disciplines are consensus, not lint — no duplicate keys
    /// ([`TransferReject::DuplicateWitnessKey`]) and no unreferenced entries
    /// ([`TransferReject::WitnessKeyUnused`]) — because the table is witness
    /// (unsigned), and without them a relay could re-shape the unsigned
    /// bytes inside the declared `tx_bytes` while the signatures stayed
    /// valid. With them, every witness byte is checked against something
    /// committed, exactly as in V1.
    TransferV2 {
        /// The witness table: one entry per owner, each verified once over
        /// the signing root. The verify-gas class term is `keys.len()` —
        /// the verifications a node actually runs (gas buys node CPU).
        keys: Vec<WitnessKey>,
        /// The outputs being spent, each naming its witness by index.
        inputs: Vec<TransferInputV2>,
        /// The outputs being created — identical to [`Self::Transfer`].
        outputs: Vec<TransferOutput>,
        /// Declared payload bytes — identical rules to [`Self::Transfer`],
        /// floored at this encoding's own canonical length.
        tx_bytes: u64,
        /// The sender's tip, in millisatoshi per gas — identical to
        /// [`Self::Transfer`].
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
    /// Register a validator by **spending real coins** — the funded
    /// replacement for [`PosTransaction::Deposit`], consensus-valid only from
    /// [`crate::params::FUNDED_STAKE_ACTIVATION_EPOCH`] (2026-08-21).
    ///
    /// # What this closes
    ///
    /// The legacy `Deposit` names an `amount_sat`, spends no output and
    /// carries no signature; the only thing refusing it on the live chain is
    /// `admissible()` in the node — a mempool refusal its own comment calls
    /// "not a consensus rule". A modified proposer could mint stake from
    /// nothing and every unmodified node would accept the block. This variant
    /// makes the bond cost coins: the inputs are spent under exactly the
    /// transfer path's rules, and the equality
    ///
    /// ```text
    /// Σ inputs  ==  amount_sat + Σ change + fee
    /// ```
    ///
    /// is enforced with the transfer's own [`TransferReject::ValueNotConserved`]
    /// — what leaves the eUTXO set is exactly what enters the bond plus the
    /// fee, and `issued_sat` is never touched.
    ///
    /// # Two signature domains, two signers, deliberately
    ///
    /// - **`DS_SPEND`**, signed by the owners of the coins over
    ///   [`PosTransaction::spend_signing_root`]: authorises the spend and —
    ///   because the root covers the whole registration payload including the
    ///   PoP — endorses exactly which validator the coins bond. Reused
    ///   verbatim from `Transfer` ([`TransferInput`], same root construction):
    ///   two ways to authorise a spend would be two surfaces to get one of
    ///   them wrong.
    /// - **`DS_DEPOSIT`**, signed by the validator key over
    ///   [`crate::staking::DepositTx::signing_root`]: proves possession of
    ///   BOTH halves of the hybrid key (anti rogue-key). It deliberately does
    ///   NOT cover the inputs, so the hot validator key can never authorise
    ///   coin movement — compromise of it must not reach the principal.
    ///
    /// # Capacity, with the numbers (measured 2026-08-21)
    ///
    /// A PQ witness is 3,749 B of enveloped pubkey + 4,775 B of hybrid
    /// signature per input, and the PoP is another 4,775 B signature beside a
    /// second copy of the 3,749 B key. A single-input, single-change funded
    /// deposit encodes to ≈17.3 KB, so the 262,144-byte block cap admits
    /// **15 deposits per block** (each extra input costs ≈8.6 KB more; two
    /// inputs each → 10 per block). Gas does not bind first: two hybrid
    /// verifications (2 × 72,748) plus ≈17.3 KB at 16 gas/byte is ≈427K gas,
    /// so 15 deposits are ≈6.4M of the 60M limit. And the useful ceiling is
    /// smaller than either cap: [`crate::staking::MAX_ACTIVATIONS_PER_EPOCH`]
    /// admits 4 validators per epoch — the queue, not the block, is the
    /// bottleneck, by design.
    FundedDeposit {
        /// The outputs funding the bond, each with its own witness — same
        /// type, same rules, same gas class as a transfer's inputs.
        inputs: Vec<TransferInput>,
        /// Change back to the depositor. Keyed by this transaction's derived
        /// txid, like transfer outputs.
        change: Vec<TransferOutput>,
        /// Suite-tagged hybrid public key. Consensus pins the suite to
        /// `SUITE_MLDSA65_FALCON1024` ([`crate::staking::is_wire_hybrid_pubkey`]):
        /// the ML-DSA-only escape hatch must not enter the registry.
        pubkey: Vec<u8>,
        /// The bond, in satoshis — the amount the conservation equality moves
        /// from the eUTXO set into the registry.
        amount_sat: u128,
        /// `c_0`, head of the SHAKE-256 reveal chain (§6.3).
        randao_commitment: [u8; 32],
        /// Where the bond withdraws to — must be the 32-byte script-hash
        /// form, fixed here and never by a later message ([`crate::staking::Address`]).
        withdrawal_credentials: Vec<u8>,
        /// Operator commission in basis points, committed with the record and
        /// covered by BOTH signing roots (see `DS_DEPOSIT` above).
        commission_bps: u128,
        /// Hybrid signature by the validator key over the `DS_DEPOSIT` root.
        /// Covered by the `DS_SPEND` root (it is computed first — no
        /// circularity), so mutating it in transit breaks the input
        /// signatures instead of producing a mangled-body DoS.
        proof_of_possession: Vec<u8>,
        /// Declared payload size — same rules, same
        /// [`TransferReject::UnderdeclaredSize`] floor as a transfer.
        tx_bytes: u64,
        /// The depositor's tip; the base fee is the protocol's.
        tip_millisat_per_gas: u128,
    },
    /// Voluntary exit, **signed** — the funded replacement for
    /// [`PosTransaction::Exit`], consensus-valid only from the flag day.
    ///
    /// The legacy `Exit` is unauthenticated: anyone could retire any
    /// validator irreversibly (the roster-emptying attack `admissible()`
    /// documents). This one verifies a hybrid signature by the registered
    /// key over [`crate::staking::ExitTx::signing_root`] (`DS_EXIT`), which
    /// binds the epoch so a captured exit cannot be replayed from the future;
    /// state effects are identical to the legacy arm (duties stop after
    /// [`crate::staking::EXIT_DELAY_EPOCHS`], stake withdrawable after
    /// [`crate::staking::WITHDRAWAL_DELAY_EPOCHS`] more). It settles no fee —
    /// a locked bond reaches no spendable coin to pay one with — but its
    /// bytes and gas still count against both block caps, so it cannot stuff
    /// blocks for free; it is bounded at one per validator per lifetime by
    /// the exit rules themselves.
    SignedExit {
        validator: u32,
        /// Epoch the exit is intended for; signed, must not be in the future
        /// of the including block's epoch.
        epoch: u64,
        /// Hybrid signature over the `DS_EXIT` root, verified against the
        /// REGISTERED pubkey — never one carried in the message.
        signature: Vec<u8>,
    },
    /// Pay out a withdrawable bond as a spendable output — permissionless and
    /// unsigned, because every term is already fixed by committed state: the
    /// destination was pinned at registration (`withdrawal_credentials`), the
    /// clock by the exit, and the amount by the record. After the delay, this
    /// transfer is the only thing that can happen to those coins, so a
    /// signature would authorise nothing (the `validate_withdrawal`
    /// rationale in `staking.rs`).
    ///
    /// # THE WRITE-OFF RULE (founder decision, 2026-08-22)
    ///
    /// The payout is `staked_sat − unbacked_principal`
    /// ([`CommittedState::withdrawable_sat`]), and the remainder is **written
    /// off, never emitted**: it is added to the committed `written_off_sat`
    /// counter and the bond is zeroed. A genesis bond's 25,000-BLOCH
    /// principal was never issued and never funded, so it never becomes
    /// spendable coin — only the post-genesis accrual does. A bond funded by
    /// [`Self::FundedDeposit`] has no unbacked principal at all, so it pays in
    /// full: THAT asymmetry is the rule.
    ///
    /// # The floor, and why the write-off is not just the principal
    ///
    /// `unbacked_principal` is `min(principal, low_water)`, where the low
    /// water is the smallest the bond has ever been
    /// ([`CommittedState::stake_low_water_sat`]). Without the floor the rule
    /// charges a pre-gate slash TWICE — once when the penalty burned phantom
    /// principal, again when the withdrawal subtracts the whole principal
    /// anyway — and the second charge lands on genuinely emitted rewards.
    /// Measured: principal 25,000, slash −5,000, rewards +10,000 pays 5,000
    /// without the floor and 10,000 with it, and 10,000 is the emitted coin
    /// actually in the bond.
    ///
    /// # Derived, not materialised, and that is deliberate
    ///
    /// Everything the rule reads — the deposit history, the genesis
    /// principals, the low-water marks — is already-committed state, so the
    /// quantity is recomputed on every call and the state root grows no
    /// column for it. The rejected alternative materialised it once, on the
    /// boundary that crosses the flag day; that version pays the FULL
    /// principal of every genesis bond as spendable coin if the founder ever
    /// arms an epoch the chain has already passed, because the crossing
    /// condition never fires.
    ///
    /// A bond slashed by a binary older than the low-water recorder has no
    /// floor to read and is REFUSED rather than guessed at
    /// ([`CommittedState::is_write_off_indeterminate`]): every available
    /// default is wrong in one direction, and a refusal is the only choice
    /// that is reversible.
    ///
    /// `issued_sat` is untouched in both directions — a withdrawal moves
    /// existing value, it never issues. It settles NO fee: a fee would have to
    /// come out of the payout, which would make exactly the bonds that pay
    /// zero (fully slashed, or pure write-off) unclosable and their write-off
    /// permanently unrecorded. Its bytes and gas still count against both
    /// block caps, so it is not free block space; and it is bounded at one per
    /// validator for the lifetime of the chain by its own single-shot rule.
    ///
    /// A second withdrawal finds the record empty and is refused — which is
    /// also what keeps this variant's constant canonical bytes (tag + index,
    /// hence one txid per validator forever) from ever colliding on an output
    /// key. If re-bonding of an index is ever allowed, that derivation must
    /// change first.
    Withdraw { validator: u32 },
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
    /// The digest each input's signature is taken over: everything the
    /// transfer commits to **except the witnesses**.
    ///
    /// # Why the witnesses are excluded, and it is not a weakening
    ///
    /// A signature is produced over this root and then stored inside the
    /// transaction. If the root covered the witnesses, it would have to cover
    /// the signature being produced over it — no signer could ever compute the
    /// value to sign. Excluding them is the only construction that terminates,
    /// and it is the standard one (Bitcoin's sighash, Ethereum's RLP-minus-VRS).
    ///
    /// What that leaves unsigned is exactly the witness bytes, and every use
    /// consensus makes of them is checked against something that *is* signed:
    /// the pubkey against the output's committed `script_hash`, the signature
    /// against this root. A third party may substitute neither without failing
    /// one of those two checks.
    ///
    /// # What it covers, and why each field is in it
    ///
    /// - **the spend points** — otherwise a signature authorising the movement
    ///   of one coin would authorise the movement of any coin;
    /// - **the outputs, in order** — otherwise the destination and the amount
    ///   could be rewritten in flight, which is the entire attack;
    /// - **`tx_bytes` and the tip** — both set the fee, and the fee is the
    ///   difference between what the inputs carry and what the outputs
    ///   receive. An unsigned fee term is an unsigned deduction from the
    ///   sender's own money.
    ///
    /// Lengths are prefixed and every field is fixed-width, so no two distinct
    /// transfers share a preimage: a signature is a statement about one
    /// transfer and cannot be reinterpreted as a statement about another.
    ///
    /// Non-transfer variants have no spend to authorise; this returns their
    /// domain-tagged canonical bytes so the function is total, and nothing in
    /// the transition asks them for one.
    pub fn spend_signing_root(&self) -> [u8; 32] {
        // ONE preimage layout for both transfer encodings, by construction:
        // V1 and V2 feed the same helper the same (spend points, outputs,
        // tx_bytes, tip), so the roots — and with them the txids and every
        // wallet signature — cannot drift between the formats. Two hand-
        // rolled copies of this fold would be the `pow_hash`/`block_hash`
        // duplicate-derivation defect at the signature layer. The V2 witness
        // table and the per-input `key_index` stay OUTSIDE the root for the
        // same documented reason the V1 witnesses do: they are witness data,
        // and a root that covered the signatures could never be signed.
        fn fold_spend(
            h: &mut Sha3_256,
            spends: &mut dyn Iterator<Item = ([u8; 32], u32)>,
            n_spends: u32,
            outputs: &[TransferOutput],
            tx_bytes: u64,
            tip: u128,
        ) {
            h.update(n_spends.to_le_bytes());
            for (txid, vout) in spends {
                h.update(txid);
                h.update(vout.to_le_bytes());
            }
            h.update((outputs.len() as u32).to_le_bytes());
            for o in outputs {
                h.update(o.value.to_le_bytes());
                h.update(o.script_hash);
            }
            h.update(tx_bytes.to_le_bytes());
            h.update(tip.to_le_bytes());
        }

        let mut h = Sha3_256::new();
        h.update(crate::params::DS_SPEND);
        match self {
            PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } => {
                fold_spend(
                    &mut h,
                    &mut inputs.iter().map(|i| (i.txid, i.vout)),
                    inputs.len() as u32,
                    outputs,
                    *tx_bytes,
                    *tip_millisat_per_gas,
                );
            }
            PosTransaction::TransferV2 { inputs, outputs, tx_bytes, tip_millisat_per_gas, .. } => {
                fold_spend(
                    &mut h,
                    &mut inputs.iter().map(|i| (i.txid, i.vout)),
                    inputs.len() as u32,
                    outputs,
                    *tx_bytes,
                    *tip_millisat_per_gas,
                );
            }
            PosTransaction::FundedDeposit {
                inputs,
                change,
                pubkey,
                amount_sat,
                randao_commitment,
                withdrawal_credentials,
                commission_bps,
                proof_of_possession,
                tx_bytes,
                tip_millisat_per_gas,
            } => {
                // The variant tag leads, unlike the Transfer arm (whose
                // layout is frozen — re-keying it re-keys every txid on the
                // chain). Cross-variant injectivity under the shared DS_SPEND
                // domain then rests on: (1) this stream begins 0x07 (the
                // variant's wire tag) while a Transfer stream begins with a
                // 4-byte input count, (2) the
                // structural lengths differ (this stream carries a
                // length-prefixed 3,749 B key and a 4,775 B PoP mid-stream),
                // and (3) a byte-identical pair would additionally need BOTH
                // interpretations to be well-formed and applicable against
                // the same committed set under the same keys. A signature
                // over one shape is a statement about that shape only.
                h.update([0x07u8]);
                // Witness-free, exactly like the Transfer arm: spend points
                // without their pubkeys/signatures — the root a signature is
                // computed over cannot cover the signature being produced.
                h.update((inputs.len() as u32).to_le_bytes());
                for i in inputs {
                    h.update(i.txid);
                    h.update(i.vout.to_le_bytes());
                }
                h.update((change.len() as u32).to_le_bytes());
                for o in change {
                    h.update(o.value.to_le_bytes());
                    h.update(o.script_hash);
                }
                // The registration payload IS covered — including the PoP.
                // The PoP is computed over the DS_DEPOSIT root first, so
                // there is no circularity; covering it here means a PoP
                // mutated in transit breaks the input signatures (a
                // deterministic reject) instead of producing a second body
                // for the same txid — the mangled-body DoS family step 3b of
                // compute_post_state exists to refuse.
                h.update((pubkey.len() as u32).to_le_bytes());
                h.update(pubkey);
                h.update(amount_sat.to_le_bytes());
                h.update(randao_commitment);
                h.update((withdrawal_credentials.len() as u32).to_le_bytes());
                h.update(withdrawal_credentials);
                h.update(commission_bps.to_le_bytes());
                h.update((proof_of_possession.len() as u32).to_le_bytes());
                h.update(proof_of_possession);
                // The fee terms, for the same reason as the Transfer arm: an
                // unsigned fee term is an unsigned deduction from the
                // depositor's own money.
                h.update(tx_bytes.to_le_bytes());
                h.update(tip_millisat_per_gas.to_le_bytes());
            }
            other => h.update(other.canonical_bytes()),
        }
        h.finalize().into()
    }

    /// This transaction's id: `SHA3-256(DS_TXID ‖ spend_signing_root)`.
    ///
    /// Taken over the **witness-free** root, so the id — and with it the key
    /// of every output the transfer creates — is fixed the moment the sender
    /// decides what to send, and cannot be moved afterwards by anyone
    /// re-encoding the signatures. A txid over the full encoding would let a
    /// relay change where a payment lands in the set, breaking any transaction
    /// already built to spend it; that is transaction malleability, and it is
    /// designed out here rather than patched later.
    ///
    /// Distinct outputs cannot collide: the root covers the spend points, an
    /// outpoint is consumed at most once, and a transfer with no inputs is
    /// refused ([`TransferReject::NoInputs`]) — so no two applicable transfers
    /// can share a preimage.
    pub fn txid(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(crate::params::DS_TXID);
        h.update(self.spend_signing_root());
        h.finalize().into()
    }

    /// The `DS_DEPOSIT` root a [`PosTransaction::FundedDeposit`]'s proof of
    /// possession must be signed over — [`crate::staking::DepositTx::signing_root`]
    /// applied to this transaction's registration fields.
    ///
    /// One derivation path, two callers: the transition verifies the PoP with
    /// it (`apply_funded_deposit`), and the node's mempool pre-verifies with
    /// the same call (`admissible` in `bloch-pos-node/src/engine.rs`) so the
    /// producer's `ProbeVerifier` cannot be fed a garbage PoP that costs an
    /// honest proposer its own block — the slot-69 class. A second expression
    /// of this root anywhere would be the duplicate-derivation habit this
    /// crate refuses.
    ///
    /// `None` for every other variant, and for a `FundedDeposit` whose
    /// pubkey is not the enveloped hybrid form or whose credentials are not
    /// 32 bytes — the same shapes the transition refuses as `StakingRule`
    /// before it ever asks for this root.
    pub fn funded_deposit_pop_signing_root(&self) -> Option<[u8; 32]> {
        let PosTransaction::FundedDeposit {
            pubkey,
            amount_sat,
            randao_commitment,
            withdrawal_credentials,
            commission_bps,
            ..
        } = self
        else {
            return None;
        };
        if !staking::is_wire_hybrid_pubkey(pubkey) {
            return None;
        }
        // The reference DepositTx carries the RAW hybrid key (the registry
        // and the wire carry it enveloped); the suite id comes from the
        // envelope it was checked against above.
        let raw: [u8; staking::HYBRID_PK_BYTES] =
            pubkey[staking::WIRE_SUITE_HEADER_BYTES..].try_into().ok()?;
        let addr: staking::Address = withdrawal_credentials.as_slice().try_into().ok()?;
        Some(
            staking::DepositTx {
                suite: staking::SUITE_MLDSA65_FALCON1024,
                amount_sat: *amount_sat,
                validator_pubkey: raw,
                randao_commitment: *randao_commitment,
                withdrawal_addr: addr,
                commission_bps: *commission_bps,
                // The root cannot cover the signature computed over it; the
                // field is unread by signing_root and empty by construction.
                proof_of_possession: Vec::new(),
            }
            .signing_root(),
        )
    }

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
    /// [`PosTransaction::Transfer`] now encodes the transfer itself — spend
    /// points with their witnesses, created outputs, and the two fee-market
    /// terms. It still does not encode a *fee*: the fee is derived, from the
    /// class and size here plus the committed base fee, and is whatever the
    /// inputs exceed the outputs by. It also does not encode a txid: that is
    /// derived ([`PosTransaction::txid`]), because a transaction that named
    /// its own id could name one already in the set.
    ///
    /// What stays out of scope is the general eUTXO *script* format (§1.2).
    /// The locking condition committed by `script_hash` is fixed here at
    /// "SHA3-256 of the spender's public key" — a pay-to-pubkey-hash and
    /// nothing more. Datums, validators and multi-party scripts are a later
    /// widening, and one that must not silently re-key: when they land they
    /// need their own discriminant, not an extra optional field on this one.
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
            PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } => {
                b.push(0x01);
                // Counts are length prefixes like every other variable-length
                // field here, so a truncated list cannot decode as a shorter
                // valid one.
                b.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
                for i in inputs {
                    b.extend_from_slice(&i.txid);
                    b.extend_from_slice(&i.vout.to_le_bytes());
                    put(&mut b, &i.pubkey);
                    put(&mut b, &i.signature);
                }
                b.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
                for o in outputs {
                    b.extend_from_slice(&o.value.to_le_bytes());
                    b.extend_from_slice(&o.script_hash);
                }
                b.extend_from_slice(&tx_bytes.to_le_bytes());
                b.extend_from_slice(&tip_millisat_per_gas.to_le_bytes());
            }
            PosTransaction::TransferV2 { keys, inputs, outputs, tx_bytes, tip_millisat_per_gas } => {
                // 0x06: the deduplicated-witness transfer. Table first, then
                // the 40-byte inputs that index into it — same encoding rules
                // as every other tag (fixed-width LE, every variable-length
                // field length-prefixed), same injectivity argument.
                b.push(0x06);
                b.extend_from_slice(&(keys.len() as u32).to_le_bytes());
                for k in keys {
                    put(&mut b, &k.pubkey);
                    put(&mut b, &k.signature);
                }
                b.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
                for i in inputs {
                    b.extend_from_slice(&i.txid);
                    b.extend_from_slice(&i.vout.to_le_bytes());
                    b.extend_from_slice(&i.key_index.to_le_bytes());
                }
                b.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
                for o in outputs {
                    b.extend_from_slice(&o.value.to_le_bytes());
                    b.extend_from_slice(&o.script_hash);
                }
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
            PosTransaction::FundedDeposit {
                inputs,
                change,
                pubkey,
                amount_sat,
                randao_commitment,
                withdrawal_credentials,
                commission_bps,
                proof_of_possession,
                tx_bytes,
                tip_millisat_per_gas,
            } => {
                // 0x07, not 0x06: the deduplicated transfer owns 0x06 (frozen
                // by test, armed for epoch 800). One byte with two live
                // meanings on the wire is the 2026-08-08 fork class.
                b.push(0x07);
                b.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
                for i in inputs {
                    b.extend_from_slice(&i.txid);
                    b.extend_from_slice(&i.vout.to_le_bytes());
                    put(&mut b, &i.pubkey);
                    put(&mut b, &i.signature);
                }
                b.extend_from_slice(&(change.len() as u32).to_le_bytes());
                for o in change {
                    b.extend_from_slice(&o.value.to_le_bytes());
                    b.extend_from_slice(&o.script_hash);
                }
                put(&mut b, pubkey);
                b.extend_from_slice(&amount_sat.to_le_bytes());
                b.extend_from_slice(randao_commitment);
                put(&mut b, withdrawal_credentials);
                b.extend_from_slice(&commission_bps.to_le_bytes());
                put(&mut b, proof_of_possession);
                b.extend_from_slice(&tx_bytes.to_le_bytes());
                b.extend_from_slice(&tip_millisat_per_gas.to_le_bytes());
            }
            PosTransaction::SignedExit { validator, epoch, signature } => {
                b.push(0x08);
                b.extend_from_slice(&validator.to_le_bytes());
                b.extend_from_slice(&epoch.to_le_bytes());
                put(&mut b, signature);
            }
            PosTransaction::Withdraw { validator } => {
                b.push(0x09);
                b.extend_from_slice(&validator.to_le_bytes());
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
            0x01 => {
                // Counts are read from untrusted bytes, so nothing is
                // preallocated from them: a 4-billion-input header on a 40-byte
                // payload must cost one failed read, not a 4-billion-element
                // reservation. Each push is backed by bytes that were actually
                // delivered, and a short list dies on `Truncated`.
                let n_in = r.u32()?;
                let mut inputs = Vec::new();
                for _ in 0..n_in {
                    inputs.push(TransferInput {
                        txid: r.h32()?,
                        vout: r.u32()?,
                        pubkey: r.bytes()?,
                        signature: r.bytes()?,
                    });
                }
                let n_out = r.u32()?;
                let mut outputs = Vec::new();
                for _ in 0..n_out {
                    outputs.push(TransferOutput { value: r.u64()?, script_hash: r.h32()? });
                }
                PosTransaction::Transfer {
                    inputs,
                    outputs,
                    tx_bytes: r.u64()?,
                    tip_millisat_per_gas: r.u128()?,
                }
            }
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
            0x06 => {
                // Purely structural, like tag 0x01: counts come from untrusted
                // bytes, so nothing is preallocated from them, and every push
                // is backed by bytes actually delivered. Whether the format is
                // ACTIVE is not this function's question — the flag-day gate
                // lives in the transition (`FormatNotActive`), against the
                // committed epoch; a decoder that answered it would be a
                // second copy of a consensus rule, free to drift.
                let n_keys = r.u32()?;
                let mut keys = Vec::new();
                for _ in 0..n_keys {
                    keys.push(WitnessKey { pubkey: r.bytes()?, signature: r.bytes()? });
                }
                let n_in = r.u32()?;
                let mut inputs = Vec::new();
                for _ in 0..n_in {
                    inputs.push(TransferInputV2 {
                        txid: r.h32()?,
                        vout: r.u32()?,
                        key_index: r.u32()?,
                    });
                }
                let n_out = r.u32()?;
                let mut outputs = Vec::new();
                for _ in 0..n_out {
                    outputs.push(TransferOutput { value: r.u64()?, script_hash: r.h32()? });
                }
                PosTransaction::TransferV2 {
                    keys,
                    inputs,
                    outputs,
                    tx_bytes: r.u64()?,
                    tip_millisat_per_gas: r.u128()?,
                }
            }
            // The funded staking shapes (tags 0x07–0x09; flag day:
            // `params::FUNDED_STAKE_ACTIVATION_EPOCH`). 0x06 was already
            // spoken for — the deduplicated transfer above, frozen by test
            // and armed for its own flag day — so the funded shapes take the
            // next free tags; one byte, two live meanings is the 2026-08-08
            // fork class at the decode layer. Note what is NOT here: no gate
            // check. Decodability is permanent for every tag this build has
            // ever known — historical blocks must re-decode on every replay —
            // and validity is a transition rule (`apply_transaction`'s epoch
            // dispatch), never a decode rule. The legacy tags 0x02–0x04 above
            // stay decodable forever for the same reason, even after the gate
            // makes them invalid in new block bodies.
            0x07 => {
                // Same no-preallocation posture as the Transfer arm: counts
                // are untrusted bytes.
                let n_in = r.u32()?;
                let mut inputs = Vec::new();
                for _ in 0..n_in {
                    inputs.push(TransferInput {
                        txid: r.h32()?,
                        vout: r.u32()?,
                        pubkey: r.bytes()?,
                        signature: r.bytes()?,
                    });
                }
                let n_change = r.u32()?;
                let mut change = Vec::new();
                for _ in 0..n_change {
                    change.push(TransferOutput { value: r.u64()?, script_hash: r.h32()? });
                }
                PosTransaction::FundedDeposit {
                    inputs,
                    change,
                    pubkey: r.bytes()?,
                    amount_sat: r.u128()?,
                    randao_commitment: r.h32()?,
                    withdrawal_credentials: r.bytes()?,
                    commission_bps: r.u128()?,
                    proof_of_possession: r.bytes()?,
                    tx_bytes: r.u64()?,
                    tip_millisat_per_gas: r.u128()?,
                }
            }
            0x08 => PosTransaction::SignedExit {
                validator: r.u32()?,
                epoch: r.u64()?,
                signature: r.bytes()?,
            },
            0x09 => PosTransaction::Withdraw { validator: r.u32()? },
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

/// Why one transaction in a block body was refused by the transition.
///
/// A named reason rather than `()`, because the transfer rules decide who may
/// move coins and a bare unit told an operator nothing about *which* rule a
/// diverging node applied differently. The staking arms keep a single reason:
/// their detailed rejects (`DepositReject`, `ExitReject`) belong to the
/// admission boundary that owns those checks, and inventing a second, subtly
/// different taxonomy here is the duplicate-derivation habit this crate
/// refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxReject {
    /// A value transfer broke one of the eUTXO rules.
    Transfer(TransferReject),
    /// A deposit, exit or delegation failed its state-dependent rule.
    StakingRule,
    /// Slashing evidence reached the plain transaction seam instead of
    /// `apply_slashing_evidence`, which is the only path that verifies it.
    MisroutedEvidence,
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

/// The principal of one genesis registration: 25,000 BLOCH, in satoshis.
///
/// This is the amount [`CommittedState::unbacked_principal_sat`] writes off
/// for a validator that has NO deposit-history entry — i.e. one seeded by
/// [`CommittedState::genesis`], whose bond destroyed no eUTXO coins and
/// advanced no `issued_sat` (founder decision, 2026-08-21: "a bond is
/// withdrawable only to the extent it was funded"). The live chain's 64
/// genesis bonds are each exactly this value, pinned against the published
/// manifest by `the_genesis_bond_principal_is_outside_the_issued_supply`
/// (`bloch-pos-node/src/genesis.rs`), which also asserts THIS constant equals
/// the manifest's per-validator stake — so the write-off cannot drift from
/// the artefact it was measured against.
///
/// Numerically equal to [`staking::MIN_DEPOSIT_SAT`] today, and deliberately
/// NOT defined as it: the minimum deposit is a policy knob that may move;
/// the genesis principal is a historical fact that may not.
pub const GENESIS_UNFUNDED_PRINCIPAL_SAT: u128 = 25_000 * tokenomics_v4::SAT_PER_BLOCH;

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
    /// The bond each genesis validator was REGISTERED with, by index — the
    /// principal that was never emitted (no eUTXO was destroyed for it and
    /// `genesis_issued_sat` never counted it; the manifest pins this at
    /// 25,000 BLOCH x 64 on mainnet). Uncommitted, like [`Self::genesis_mix`]
    /// and [`Self::genesis_cohort`]: a pure function of the genesis manifest,
    /// identical on every node that replays the same genesis, and immutable
    /// forever after. Read by [`Self::unbacked_principal_sat`] on every call
    /// — it is one of the three committed inputs (with the deposit history
    /// and [`Self::stake_low_water`]) the write-off is derived from, which is
    /// why the rule needs no column of its own in the state root.
    genesis_principal_sat: BTreeMap<u32, u128>,
    /// Cumulative unissued principal written off at withdrawals, committed
    /// under `TAG_WRITTEN_OFF` once non-zero. Monotone; audit surface only.
    written_off_sat: u128,
    /// THE LOW-WATER MARK of every bond a slash has ever reduced — committed
    /// under `TAG_STAKE_LOW_WATER` (state_root.rs, 2026-08-22), and written
    /// UNGATED, from the rebuild.
    ///
    /// The write-off owed at withdrawal is `U(t) = min(P, min_{s<=t}
    /// staked(s))`, and THIS map is the `min` term —
    /// [`Self::unbacked_principal_sat`] reads it on every call. Without it
    /// the rule substitutes `min(P, staked_now)`. That substitution is a
    /// CONFISCATION, not a
    /// rounding: a bond whose principal was 25,000, that a pre-gate slash cut
    /// to 20,000 and that later rewards rebuilt to 30,000, has 10,000
    /// satoshis of genuinely emitted coin inside it — and `min(25,000,
    /// 30,000)` classifies 25,000 as phantom and pays 5,000. The missing
    /// 5,000 is exactly what the pre-gate slash already burned, taken twice.
    ///
    /// So the recorder cannot be gated: the gate needs to READ a history the
    /// gate itself would be too late to WRITE. Shipping it ungated is safe
    /// without a second flag day only because of a measurement, not because
    /// of a comment — 64 of 64 live validators carry no applied slash
    /// (2026-08-22), so this map is empty everywhere, and an empty map
    /// contributes no leaves and cannot move a root.
    ///
    /// **A zero entry is real and is kept.** Absent means "never slashed";
    /// present-and-zero means "slashed to nothing". A bond slashed to zero
    /// that lost its entry would read as never-slashed and be paid out — and
    /// the absent/present distinction is also what defines the indeterminate
    /// class ([`Self::is_write_off_indeterminate`]).
    stake_low_water: BTreeMap<u32, u128>,
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
    ///
    /// **What one-sided does NOT protect (2026-08-22, stated so nobody ever
    /// assumes otherwise):** the cap check only fires if THIS COUNTER
    /// advances past the cap. Spendable coin created without touching the
    /// counter sails through it — paying out the 1,600,000 BLOCH of
    /// never-emitted genesis bond principal would have raised no alarm here,
    /// which is exactly the hole the funded-staking write-off closes. The
    /// check also does not tie the eUTXO set's total to this counter, and it
    /// does not see burns. Against phantom-principal escape the protections
    /// are the `apply_withdraw` payout arithmetic (`staked - unbacked`), the
    /// whistleblower cap, and the conservation tests — never this invariant.
    issued_sat: u128,
    /// The unspent-output set, keyed by `(txid, vout)` so iteration order is a
    /// function of the data and never of insertion history (rule 2).
    ///
    /// # Why this is here now
    ///
    /// `compute_root` used to pass `eutxos: &[]` under a comment saying the
    /// node's transaction layer owned the set and "supplies it here". No seam
    /// existed for it to be supplied through, and nothing ever supplied
    /// anything — so the balance component of the state root was committed
    /// empty on every block since genesis. Genesis-4 had a `TAG_EUTXO` slot in
    /// its schema and no balances in it: a chain where nobody holds anything,
    /// including the 452,133 outputs the Genesis-3 snapshot carries.
    ///
    /// The set lives in the state because the state root commits to it. What
    /// stays out of this crate is the general script format; what an output is
    /// worth and who may move it are consensus, and consensus is what this
    /// struct is.
    ///
    /// **It moves now** (2026-08-13). The gap this doc used to record — genesis
    /// seeds the set and nothing ever spends from it, because
    /// `PosTransaction::Transfer` carried three gas terms with no sender,
    /// recipient or amount — is closed: [`CommittedState::apply_transfer`]
    /// consumes inputs and creates outputs under the authorisation and
    /// conservation rules stated there. Genesis-4 no longer has balances that
    /// nobody can spend.
    ///
    /// # The gap, and the flag day that closes it (2026-08-21)
    ///
    /// **Bonding is not funded from this set — until
    /// `params::FUNDED_STAKE_ACTIVATION_EPOCH`.** The legacy
    /// `PosTransaction::Deposit` and `Delegate` name an `amount_sat` and
    /// spend no output; `Exit` and the withdrawal delay return no output
    /// either. So the pre-gate chain holds two pools — this one and the
    /// registry's bonded stake — and coins do not travel between them: a
    /// deposit creates bonded stake without destroying spendable coins, and
    /// fee rewards compound into bonds that this set never funded.
    ///
    /// From the gate epoch on, the wire closes it: `FundedDeposit` spends
    /// outputs from this set into the bond under an exact conservation
    /// equality, `Withdraw` pays the bond's FUNDED portion back into this set
    /// (the unfunded genesis/legacy principal is written off at withdrawal —
    /// founder decision, see `unbacked_principal_sat`), and the legacy
    /// discriminants become consensus-invalid in block bodies.
    ///
    /// Pre-gate, conservation therefore holds **within** the transfer path
    /// (the fee is exactly what leaves the set, pinned by test) and **not**
    /// across the two pools. Until the gate is armed, no single

    /// number in this state is "the supply".
    eutxos: EutxoSet,
}

/// The committed eUTXO set, and the Merkle leaves it contributes to the state
/// root, in one value.
///
/// **Why one type and not two fields.** Keeping the leaves is what makes the
/// state root cheap — see
/// [`crate::state_root::build_state_tree_with_eutxo_leaves`] for the
/// measurement. But a leaf map that can be updated independently of the
/// entries is a cache that can go stale, and a stale leaf is a wrong state
/// root, which is a consensus split — the exact failure the §5.5 rule exists
/// to prevent. So the two are never separately reachable: `insert` and
/// `remove` are the only mutators, each updates both halves, and no caller can
/// touch one without the other. Drift is not guarded against here; it is
/// unrepresentable.
///
/// The leaf itself comes from [`crate::state_root::eutxo_leaf`], the single
/// definition shared with the from-scratch path, so a kept leaf and a
/// recomputed one cannot disagree by construction.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EutxoSet {
    entries: BTreeMap<([u8; 32], u32), crate::state_root::EutxoEntry>,
    /// `entry key -> value hash`, one per entry, always exactly in step.
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
}

impl EutxoSet {
    fn insert(&mut self, entry: crate::state_root::EutxoEntry) {
        let (key, value_hash) = crate::state_root::eutxo_leaf(&entry);
        self.leaves.insert(key, value_hash);
        self.entries.insert((entry.txid, entry.vout), entry);
    }

    fn remove(&mut self, outpoint: &([u8; 32], u32)) {
        if let Some(entry) = self.entries.remove(outpoint) {
            let (key, _) = crate::state_root::eutxo_leaf(&entry);
            self.leaves.remove(&key);
        }
    }

    fn get(&self, outpoint: &([u8; 32], u32)) -> Option<&crate::state_root::EutxoEntry> {
        self.entries.get(outpoint)
    }

    fn contains_key(&self, outpoint: &([u8; 32], u32)) -> bool {
        self.entries.contains_key(outpoint)
    }

    fn values(&self) -> impl Iterator<Item = &crate::state_root::EutxoEntry> {
        self.entries.values()
    }

    /// Only tests count the set; the consensus paths iterate it.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// The leaves this set contributes, ready for
    /// [`crate::state_root::state_root_with_eutxo_leaves`].
    ///
    /// Debug builds re-derive every leaf here and compare. The type makes
    /// drift unrepresentable, so this can only fire if someone adds a third
    /// mutator and forgets the leaf half — which is exactly the edit that
    /// would otherwise ship a wrong state root and split the chain. Every test
    /// in this crate computes a state root, so every test runs this check.
    ///
    /// It is O(set) and re-hashes everything, i.e. it costs exactly what this
    /// patch exists to avoid — deliberately, and `debug_assert` only. A node
    /// built without optimisations was already unusable at this state size;
    /// this makes it more so, and buys the invariant in every test run.
    fn leaves(&self) -> &BTreeMap<[u8; 32], [u8; 32]> {
        debug_assert_eq!(
            self.leaves.len(),
            self.entries.len(),
            "kept eUTXO leaves drifted from the entries: a mutator updated one half only"
        );
        debug_assert!(
            self.entries.values().all(|e| {
                let (key, value_hash) = crate::state_root::eutxo_leaf(e);
                self.leaves.get(&key) == Some(&value_hash)
            }),
            "a kept eUTXO leaf disagrees with the entry it was derived from"
        );
        &self.leaves
    }
}

impl FromIterator<crate::state_root::EutxoEntry> for EutxoSet {
    fn from_iter<I: IntoIterator<Item = crate::state_root::EutxoEntry>>(iter: I) -> Self {
        let mut set = EutxoSet::default();
        for e in iter {
            set.insert(e);
        }
        set
    }
}

/// Does `key_hash` — SHA3-256 of a spender's public key — open an output
/// locked by `script_hash`?
///
/// Two forms, because the chain opens with balances minted under a different
/// convention and they have to be spendable by the people who hold them.
///
/// **Native.** All 32 bytes equal. This is the pay-to-pubkey-hash the format
/// is specified as, and every output a Genesis-4 transaction creates uses it.
///
/// **Carried.** The last 12 bytes are zero and the first 20 match. A
/// Genesis-3 address is `SHA3-256(pubkey)[..20]` — the *same hash of the same
/// key*, truncated — so the carryover writes those 20 bytes into
/// `script_hash[0..20]` and zeroes the rest. The holder proves ownership
/// identically; only the comparison length differs.
///
/// # Why this function has to exist
///
/// Without it the entire opening ledger is frozen. A carried output could
/// only be opened by a key whose SHA3-256 both matched the old 20 bytes AND
/// ended in twelve zero bytes — 2^96 of work for the zeros alone. That is not
/// a difficulty, it is an impossibility: 57,146,400,000 BLOCH, every carried
/// balance and every vested allocation, unspendable forever, on a chain whose
/// state root committed to them correctly the whole time.
///
/// # What it costs, stated
///
/// A carried output is protected by 160 bits of preimage resistance rather
/// than 256. That is exactly the security those coins had on Genesis-3, and
/// what Bitcoin gives its own outputs, so nothing is weakened by carrying
/// them across — but the two tiers are real and the weaker one is the older
/// one. It applies ONLY to outputs whose last 12 bytes are zero; native
/// outputs keep the full 32-byte check.
///
/// A native output could in principle hash to something ending in twelve zero
/// bytes and become checkable under both arms. The probability is 2^-96 per
/// key, and both arms demand the same key, so it changes nothing about who
/// can spend it.
fn owns(key_hash: &[u8; 32], script_hash: &[u8; 32]) -> bool {
    if key_hash == script_hash {
        return true;
    }
    script_hash[20..] == [0u8; 12] && key_hash[..20] == script_hash[..20]
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
        // The balances this chain opens with: the Genesis-3 carryover plus the
        // vested allocation outputs. Empty on a devnet, where nobody holds
        // anything. Passed explicitly rather than defaulted, so a network that
        // SHOULD carry balances cannot be launched without someone deciding to
        // pass none — the failure mode that left `eutxos: &[]` in the root for
        // the whole of Genesis-4's development.
        opening_balances: &[crate::state_root::EutxoEntry],
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
        // Every genesis bond is unfunded by construction — the registry is
        // seeded with `staked_sat` and no eUTXO is destroyed for any of it —
        // so the registered amount IS the never-emitted principal, whatever
        // the manifest set it to (25,000 BLOCH on mainnet, arbitrary on a
        // devnet). Recorded per index, uncommitted, for the one-time
        // materialization at the funded-staking activation boundary.
        let genesis_principal_sat: BTreeMap<u32, u128> =
            validators.iter().map(|v| (v.index, v.staked_sat)).collect();
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
            genesis_principal_sat,
            written_off_sat: 0,
            stake_low_water: BTreeMap::new(),
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
            eutxos: opening_balances.iter().cloned().collect(),
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

    /// The duty roster as **consensus weight**: [`Self::duty_roster_at`] with
    /// each validator's accrued inactivity leak subtracted, once
    /// [`crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH`] binds.
    ///
    /// This is the roster the proposer draw and the committee partition must
    /// read. `duty_roster_at` deliberately is not: it still feeds
    /// `finality::process_epoch`, which subtracts the leak itself, and the
    /// reward split, where absence is already priced as forfeited credits.
    /// Leaking in both places would charge it twice.
    ///
    /// The leak is applied AFTER the cohort cap, matching the order finality
    /// already uses — it receives `duty_roster_at`'s post-cap output and
    /// subtracts from that. Same order, same numbers: this roster equals the
    /// quorum weights validator for validator, which is the point. One
    /// definition of what a leak is worth, two call paths reading it.
    ///
    /// A validator whose leak has reached its stake lands on zero and drops
    /// out of `eligible` in both `sample` and `epoch_committees` — it stops
    /// being drawn to propose and stops holding a committee seat, which is
    /// exactly the liveness the leak was supposed to buy back.
    fn consensus_roster_at(&self, epoch: u64) -> Vec<Validator> {
        let roster = self.duty_roster_at(epoch);
        if epoch < crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH {
            return roster;
        }
        with_leak_applied(roster, |index| self.finality_engine.leaked_of(index))
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
        // The eUTXO component comes in as leaves the set already holds, not as
        // a cloned vector of entries to re-serialize and re-hash. `&[]` below
        // is not "no balances" — it is the field this path does not read; the
        // balances arrive through `self.eutxos.leaves()` on the call itself.
        // (It genuinely WAS `&[]` once, under a comment saying the node
        // supplied it, and nothing did: every block from genesis committed an
        // empty balance component. Hence the emphasis.)
        let stake_low_water: Vec<crate::state_root::StakeLowWaterRecord> = self
            .stake_low_water
            .iter()
            .map(|(validator, low_water_sat)| crate::state_root::StakeLowWaterRecord {
                validator: *validator,
                low_water_sat: *low_water_sat,
            })
            .collect();
        // NOTE (2026-08-23): the state root commits `stake_low_water` and
        // `written_off_sat` and DELIBERATELY commits no column for the
        // unbacked principal itself, nor for the indeterminate class. Both
        // are pure functions of state already committed here — the deposit
        // queue/history, the genesis principals and the low-water marks — so
        // a leaf for either would be a second encoding of a fact the root
        // already fixes, and two encodings of one fact are two places for it
        // to drift. `stake_low_water` and `written_off_sat` are different:
        // one is history no other field records, the other is a monotone
        // accumulator. Divergence is still caught either way — a wrong payout
        // moves `eutxos` and `written_off_sat`, both of which ARE committed.
        crate::state_root::state_root_with_eutxo_leaves(&ConsensusState {
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
            written_off_sat: self.written_off_sat,
            stake_low_water: &stake_low_water,
        }, self.eutxos.leaves())
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
    /// The LEGACY staking messages charge nothing at this layer: their own
    /// fee handling belongs with the transfer format that carries them
    /// (§1.2), and inventing a charge here would be inventing a price nobody
    /// specified. The FUNDED staking messages (valid from the flag day) do
    /// pay: a funded deposit is priced like a transfer plus one hybrid
    /// verification for its PoP, a withdrawal's fee comes out of its payout,
    /// and a signed exit settles zero but still counts its real bytes and gas
    /// against both block caps so it cannot stuff blocks for free.
    ///
    /// `verifier` is threaded in because a transfer's authorisation is a
    /// signature check, and the only thing that may decide whether an output
    /// moves is whether its owner said so.
    /// Test-only convenience: [`Self::apply_transaction_gated`] at the real
    /// flag day. `#[cfg(test)]` because after the boundary was threaded
    /// through `compute_post_state_gated` this became the SECOND production
    /// reader of `params::FUNDED_STAKE_ACTIVATION_EPOCH`, and two readers of
    /// a flag day is one too many — keeping it compiled into the node would
    /// leave a path where the frontier could drift out of step with the
    /// block path's. The remaining production readers are
    /// `compute_post_state` and `close_epoch`, one per layer.
    #[cfg(test)]
    fn apply_transaction(
        &mut self,
        tx: &PosTransaction,
        total_active_sat: u128,
        base_fee_millisat_per_gas: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, TxReject> {
        self.apply_transaction_gated(
            tx,
            total_active_sat,
            base_fee_millisat_per_gas,
            verifier,
            crate::params::FUNDED_STAKE_ACTIVATION_EPOCH,
        )
    }

    /// [`Self::apply_transaction`] with the funded-stake flag-day epoch
    /// explicit — the testable inner form (the `with_leak_applied` idiom):
    /// the shipped constant stays inert under its tripwire while tests
    /// exercise BOTH sides of the gate by passing an epoch of their own.
    ///
    /// # The transition rule of the flag day (2026-08-21)
    ///
    /// `self.epoch` here is the block's post-boundary epoch —
    /// `compute_post_state` rolls the boundary before any transaction
    /// applies — so the dispatch below is a rule about the epoch of
    /// INCLUSION:
    ///
    /// - from the gate epoch on, the legacy `Deposit` / `Exit` / `Delegate`
    ///   discriminants are **consensus-invalid in a block body**. It is THIS
    ///   refusal — every node rejecting the block — that closes the
    ///   modified-proposer mint, not the mempool's `admissible()`, which a
    ///   modified proposer never consults;
    /// - before the gate epoch, the funded shapes are invalid instead, which
    ///   with the shipped `u64::MAX` gate makes them inert by construction:
    ///   no state root can change until the constant is lowered and the
    ///   fleet rebuilt together (rule 1; `funded_stake_gate_ships_inert`).
    ///
    /// Post-gate delegation is deliberately a GAP, stated rather than hidden:
    /// the legacy `Delegate` becomes invalid and no funded replacement ships
    /// in this wave, so NEW delegations are impossible from the gate until a
    /// funded delegate lands (its principal will follow the same "withdrawable
    /// only to the extent funded" rule). Existing delegations keep their
    /// weight — the registry fold over `delegations` is untouched.
    ///
    /// That the gate reads the COMMITTED epoch and not a node clock is not
    /// self-evident from the other gate tests: every one of them passes a
    /// SATURATED gate (0 or `u64::MAX`), at which `x >= gate` is constant for
    /// every `x` and the comparison is blind to which `x` it read. Pinned
    /// instead by `probe_gate_reads_the_block_epoch_not_a_clock`, which parks
    /// the gate at 5 with the committed epoch at 2 while any wall clock reads
    /// far above it. The standing reason is the 2026-08-08 `expected_bits`
    /// fork: a consensus rule that reads node-local state forks the fleet by
    /// construction.
    fn apply_transaction_gated(
        &mut self,
        tx: &PosTransaction,
        total_active_sat: u128,
        base_fee_millisat_per_gas: u128,
        verifier: &dyn SignatureVerifier,
        funded_stake_gate_epoch: u64,
    ) -> Result<fee_market::TxCharge, TxReject> {
        let funded_era = self.epoch >= funded_stake_gate_epoch;
        let free = fee_market::TxCharge {
            gas: 0,
            tx_bytes: 0,
            base_fee_sat: 0,
            priority_fee_sat: 0,
        };
        match tx {
            PosTransaction::Transfer { .. } => self
                .apply_transfer(tx, base_fee_millisat_per_gas, verifier)
                .map_err(TxReject::Transfer),
            PosTransaction::TransferV2 { .. } => {
                // THE FLAG-DAY GATE, FIRST — before any other look at the
                // transaction. Read from `self.epoch`, which is COMMITTED
                // state already rolled to the block's epoch by `close_epoch`
                // (compute_post_state's boundary walk), never from anything
                // node-local — the 2026-08-08 `expected_bits` fork is the
                // standing reason. Pre-activation, this reject and the old
                // binary's `UnknownTag(0x06)` decode failure are two roads to
                // the same verdict on the same block, which is what keeps a
                // mixed fleet on one chain until the flag day.
                if self.epoch < crate::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH {
                    return Err(TxReject::Transfer(TransferReject::FormatNotActive));
                }
                self.apply_transfer_v2(tx, base_fee_millisat_per_gas, verifier)
                    .map_err(TxReject::Transfer)
            }
            PosTransaction::Deposit {
                pubkey,
                amount_sat,
                randao_commitment,
                withdrawal_credentials,
                commission_bps,
            } => {
                // Flag day: an unfunded deposit — no inputs, no signature,
                // stake from nothing — is consensus-invalid from the gate on.
                // THIS refusal, not the mempool's (engine.rs `admissible`),
                // is what closes the modified-proposer path that could mint
                // stake from nothing. Gate read from `self.epoch`: committed
                // state already rolled to the block's own epoch by
                // `compute_post_state`'s boundary walk, never anything
                // node-local (the 2026-08-08 rule).
                if funded_era {
                    return Err(TxReject::StakingRule);
                }
                let pubkey_hash: [u8; 32] = Sha3_256::digest(pubkey).into();
                // A second deposit of a registered key is a top-up path
                // decision the interface refuses to make implicitly.
                if self.pubkey_index.contains_key(&pubkey_hash) {
                    return Err(TxReject::StakingRule);
                }
                if *amount_sat < staking::MIN_DEPOSIT_SAT {
                    return Err(TxReject::StakingRule);
                }
                // Per-validator cap: 1% of committed active stake, floored at
                // the minimum deposit — a naive 1% cap at genesis (active
                // stake ≈ 0) would deadlock the bootstrap (staking.rs docs).
                let cap = (total_active_sat * delegation::MAX_VALIDATOR_STAKE_BPS / 10_000)
                    .max(staking::MIN_DEPOSIT_SAT);
                if *amount_sat > cap {
                    return Err(TxReject::StakingRule);
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
                // Flag day: the unauthenticated exit is consensus-invalid
                // from the gate on — [`PosTransaction::SignedExit`] replaces
                // it. An exit anyone can submit for any validator is an
                // irreversible griefing lever. Same gate discipline as the
                // Deposit arm.
                if funded_era {
                    return Err(TxReject::StakingRule);
                }
                let Some(rec) = self.validators.get_mut(validator) else {
                    return Err(TxReject::StakingRule);
                };
                // Active, not already exiting, not slashed (slashing has its
                // own ejection path and must not share the voluntary one).
                if rec.slashed
                    || rec.activation_epoch > self.epoch
                    || rec.exit_epoch != u64::MAX
                {
                    return Err(TxReject::StakingRule);
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
                // Flag day: the unfunded delegation is consensus-invalid from
                // the gate on — a legacy delegation names an amount and
                // destroys no coin, the same phantom the write-off exists to
                // contain. NO funded replacement ships in this wave; see the
                // dispatch docs above for the stated gap.
                if funded_era {
                    return Err(TxReject::StakingRule);
                }
                let Some(rec) = self.validators.get(validator) else {
                    return Err(TxReject::StakingRule);
                };
                if rec.slashed || rec.exit_epoch != u64::MAX {
                    return Err(TxReject::StakingRule);
                }
                if *amount_sat < delegation::MIN_DELEGATION_SAT {
                    return Err(TxReject::StakingRule);
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
            PosTransaction::FundedDeposit { .. } => {
                // Inert until the flag day: with the shipped u64::MAX gate
                // this reject is unconditional, so no pre-gate block body can
                // carry a funded deposit and no pre-gate root can move.
                if !funded_era {
                    return Err(TxReject::StakingRule);
                }
                self.apply_funded_deposit(
                    tx,
                    total_active_sat,
                    base_fee_millisat_per_gas,
                    verifier,
                )
            }
            PosTransaction::SignedExit { validator, epoch, signature } => {
                if !funded_era {
                    return Err(TxReject::StakingRule);
                }
                // State rules first (cheap lookups), signature last — the
                // same rules and the same order as `staking::validate_exit`,
                // the reference this arm follows: registered, active, not
                // slashed (slashing has its own ejection path and must not
                // share the voluntary one), not already exiting (the
                // withdrawal clock must never reset), and the signed epoch
                // must not be ahead of the including block's (a pre-signed
                // future exit would decouple the clock from inclusion time).
                let Some(rec) = self.validators.get(validator) else {
                    return Err(TxReject::StakingRule);
                };
                if rec.slashed
                    || rec.activation_epoch > self.epoch
                    || rec.exit_epoch != u64::MAX
                    || *epoch > self.epoch
                {
                    return Err(TxReject::StakingRule);
                }
                // One definition of the DS_EXIT root: `staking::ExitTx` —
                // over the hash of the REGISTERED pubkey, so the message
                // cannot substitute a key of its own. Verified through the
                // injected verifier like every other suite-enveloped
                // signature in the transition (the transfer path's
                // `verify_with_key`).
                let root = staking::ExitTx {
                    pubkey_hash: Sha3_256::digest(&rec.pubkey).into(),
                    epoch: *epoch,
                    // Unread by signing_root — a root cannot cover the
                    // signature computed over it.
                    signature: Vec::new(),
                }
                .signing_root();
                if !verifier.verify_with_key(&rec.pubkey, &root, signature) {
                    return Err(TxReject::StakingRule);
                }
                // Effects identical to the legacy arm: duties stop after the
                // exit delay, the stake stays slashable through the
                // weak-subjectivity margin.
                let exit_epoch = self.epoch.saturating_add(staking::EXIT_DELAY_EPOCHS);
                let Some(rec) = self.validators.get_mut(validator) else {
                    // Unreachable — checked above. Total anyway: a consensus
                    // path must not panic on any input.
                    return Err(TxReject::StakingRule);
                };
                rec.exit_epoch = exit_epoch;
                rec.withdrawable_epoch =
                    exit_epoch.saturating_add(staking::WITHDRAWAL_DELAY_EPOCHS);
                // Settles no fee — a locked bond reaches no spendable coin —
                // but the REAL bytes and gas count against both block caps:
                // a message that consumed block space for free would be a
                // stuffing vector outside the fee market's budget. One per
                // validator per lifetime (exit_epoch never resets), so this
                // is not an unpriced spam surface either.
                let len = tx.canonical_bytes().len() as u64;
                Ok(fee_market::TxCharge {
                    gas: fee_market::intrinsic_gas(
                        // One hybrid verification, priced as such.
                        fee_market::TxClass::Eutxo { inputs: 1 },
                        len,
                    ),
                    tx_bytes: len,
                    base_fee_sat: 0,
                    priority_fee_sat: 0,
                })
            }
            PosTransaction::Withdraw { validator } => {
                if !funded_era {
                    return Err(TxReject::StakingRule);
                }
                // THE INDETERMINATE CLASS, first and before every other rule
                // so no branch below can reach a mutation on this bond. A
                // validator lands here only by having been slashed before the
                // low-water recorder existed, which makes `min(P, min staked)`
                // uncomputable. Every available default errs: the current
                // stake or 0 as the floor releases never-emitted principal as
                // spendable coin; the registered principal confiscates
                // emitted coin. Refusing is the only choice that is wrong in
                // neither direction, and it is REVERSIBLE — a stuck bond can
                // be released by a rule written later, with the history in
                // hand; a payout cannot be unpaid. Deterministic and
                // replay-safe: the predicate reads only committed state, so
                // every node refuses the same withdrawal forever.
                if self.is_write_off_indeterminate(*validator) {
                    return Err(TxReject::StakingRule);
                }
                let Some(rec) = self.validators.get(validator) else {
                    return Err(TxReject::StakingRule);
                };
                // `withdrawable_epoch` is u64::MAX until an exit (or a
                // slash) schedules it, so this one comparison is also the
                // "must have exited" rule — the `staking::validate_withdrawal`
                // reference states the split rejects.
                if self.epoch < rec.withdrawable_epoch {
                    return Err(TxReject::StakingRule);
                }
                // The credential must already be the 32-byte script-hash
                // form. The genesis credentials are (founder H160 ‖ 12 zero
                // bytes), which is exactly the CARRIED form `owns()` opens —
                // pinned against the manifest by the genesis.rs test.
                let Ok(script_hash) = <[u8; 32]>::try_from(rec.withdrawal_credentials.as_slice())
                else {
                    return Err(TxReject::StakingRule);
                };
                // THE WRITE-OFF ARITHMETIC. `unbacked` is the never-emitted
                // principal FLOORED by the smallest the bond has ever been
                // (see `unbacked_principal_sat`); `min` again here over
                // `staked_sat` is belt over the same invariant, so even a
                // state produced by a future refactor that broke the floor
                // cannot underflow the payout.
                let staked_before = rec.staked_sat;
                let unbacked =
                    self.unbacked_principal_sat(*validator, funded_stake_gate_epoch)
                        .min(staked_before);
                let payout = staked_before - unbacked;
                // Nothing left: this bond was already withdrawn. A
                // deterministic reject, so a replayed Withdraw can never
                // create a second output or double-count the write-off.
                if staked_before == 0 {
                    return Err(TxReject::StakingRule);
                }
                // Explicit narrowing, NOT `sat_u64`: a saturated payout would
                // pay less than the bond gave up and silently break the
                // conservation equality below. Unreachable at the V4 supply
                // (TOTAL_SUPPLY_SAT = 1e19 < u64::MAX), refused rather than
                // assumed away.
                let Ok(payout_u64) = u64::try_from(payout) else {
                    return Err(TxReject::StakingRule);
                };
                // Withdraw's canonical bytes are constant per validator, so
                // its txid is too; the single-shot rule above is what keeps
                // this from colliding with its own earlier output. Refuse the
                // collision anyway, like the transfer path does.
                let txid = tx.txid();
                if payout > 0 && self.eutxos.contains_key(&(txid, 0)) {
                    return Err(TxReject::Transfer(TransferReject::OutputExists));
                }
                // PRICED, but fee-free. The bytes and the gas count against
                // BOTH block caps — a message that consumed block space for
                // free would be a stuffing vector outside the fee market's
                // budget — while the settled fee is zero, exactly as
                // `SignedExit` above. A fee would have to come out of the
                // payout, and that would make precisely the bonds that pay
                // ZERO (fully slashed, or pure write-off) unclosable and
                // their write-off permanently unrecorded. An audit counter
                // that cannot account for the worst bonds is not an audit
                // counter. Not a spam surface either: one per validator per
                // lifetime, five canonical bytes.
                let len = tx.canonical_bytes().len() as u64;
                let charge = fee_market::TxCharge {
                    gas: fee_market::intrinsic_gas(
                        // No witness to verify: the payout is fully
                        // determined by committed state (see the variant
                        // docs).
                        fee_market::TxClass::Eutxo { inputs: 0 },
                        len,
                    ),
                    tx_bytes: len,
                    base_fee_sat: 0,
                    priority_fee_sat: 0,
                };
                // ── Apply. Conservation, the equality this arm enforces:
                //    staked_before − staked_after == payout + written_off
                // The bond is emptied; the eUTXO set gains exactly `payout`;
                // the unemitted remainder leaves as an audit entry, never as
                // coin. `issued_sat` is untouched — a withdrawal moves
                // existing value, it never issues (verifiable over RPC via
                // `issued_supply_sat`).
                if payout > 0 {
                    self.eutxos.insert(crate::state_root::EutxoEntry {
                        txid,
                        vout: 0,
                        value: payout_u64,
                        script_hash,
                    });
                }
                if let Some(rec) = self.validators.get_mut(validator) {
                    rec.staked_sat = 0;
                }
                // The bond's `stake_low_water` entry is deliberately NOT
                // removed. It is history, not a balance: the record is
                // terminal after this, no rule reads the entry again, and
                // adding a second write site to the map — for a cleanup
                // nothing needs — would buy state-size savings at the cost of
                // another place the write-off's history can be lost.
                self.written_off_sat += unbacked;
                Ok(charge)
            }
            // Evidence needs the injected signature verifier, which lives on
            // the Transition, not on the state — compute_post_state routes it
            // to `apply_slashing_evidence` before this method is reached.
            // Reaching this arm means a caller bypassed that seam; refusing
            // beats silently accepting unverified evidence.
            PosTransaction::SlashingEvidence(_) => Err(TxReject::MisroutedEvidence),
        }
    }

    /// Authorise, price and apply one value transfer against the committed
    /// unspent set.
    ///
    /// This is the function that moves the ledger, and every line of it is
    /// load-bearing. Three properties have to hold together, and none of them
    /// implies the others:
    ///
    /// 1. **Only the owner spends.** Each input supplies a public key and a
    ///    signature. The key must hash to the `script_hash` the *committed*
    ///    output carries, and the signature must verify over the transfer's
    ///    signing root. Checking only the hash would let anyone who can read
    ///    the chain replay a key; checking only the signature would let anyone
    ///    sign with a key of their own choosing.
    /// 2. **Value is conserved.** `sum(inputs) == sum(outputs) + fee`, with the
    ///    fee coming from the fee market — never from the transaction. A
    ///    transfer that declares its own fee is the absence of a fee market
    ///    (see the `fee_market::charge` rationale, and the two revisions
    ///    recorded on [`PosTransaction::Transfer`]); a transfer whose outputs
    ///    exceed its inputs is a mint outside the emission schedule, which is
    ///    the one thing the 100-billion cap exists to make impossible.
    /// 3. **Each output is spent at most once.** Enforced by removing inputs
    ///    from the set as they are consumed, so a second spend — in this
    ///    transaction or in any later one in the same block — finds nothing to
    ///    spend and is refused.
    ///
    /// # The check order is consensus, and it is cheapest-first
    ///
    /// Structure, then set membership, then the script hashes, then
    /// conservation, and only then the hybrid signatures — the one expensive
    /// operation, deliberately last, exactly as
    /// [`crate::attestation::validate`] puts committee membership before its
    /// verification. An attacker spamming unfundable or malformed transfers
    /// gets rejected on arithmetic, not on ≈7.3 M instructions per input.
    ///
    /// Because every check runs before any mutation, a refused transfer leaves
    /// the state untouched — the caller rejects the whole block, but this
    /// function is not what makes that safe.
    fn apply_transfer(
        &mut self,
        tx: &PosTransaction,
        base_fee_millisat_per_gas: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, TransferReject> {
        let PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } = tx
        else {
            // Unreachable: the only caller matches the variant first. A
            // consensus function does not panic on any input.
            return Err(TransferReject::NoInputs);
        };

        // ── Structure ───────────────────────────────────────────────────────
        if inputs.is_empty() {
            return Err(TransferReject::NoInputs);
        }
        // The declared size must cover the transaction's own bytes: it is what
        // the market charges and what the block's byte cap counts, and the
        // witnesses are the bulk of a PQ-signed transfer.
        if *tx_bytes < tx.canonical_bytes().len() as u64 {
            return Err(TransferReject::UnderdeclaredSize);
        }

        // ── The spend points, and the set ───────────────────────────────────
        //
        // Collected before anything is consumed, so the duplicate check sees
        // the transaction whole. A `BTreeSet` keyed by outpoint: order-free,
        // like every other accumulation in this crate (rule 2).
        let mut seen: BTreeSet<([u8; 32], u32)> = BTreeSet::new();
        let mut spent_value: u128 = 0;
        for i in inputs {
            let key = (i.txid, i.vout);
            if !seen.insert(key) {
                return Err(TransferReject::DuplicateInput);
            }
            let Some(entry) = self.eutxos.get(&key) else {
                return Err(TransferReject::UnknownInput);
            };
            // The key the output committed to, checked before the signature —
            // one hash against one hybrid verification.
            let key_hash: [u8; 32] = Sha3_256::digest(&i.pubkey).into();
            if !owns(&key_hash, &entry.script_hash) {
                return Err(TransferReject::ScriptMismatch);
            }
            spent_value += entry.value as u128;
        }

        // ── The price, derived ──────────────────────────────────────────────
        //
        // The class term is the *actual* input count, not a number the
        // transaction asserts: gas buys node CPU, and one hybrid verification
        // per input is what this function is about to spend.
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: inputs.len() as u32 },
            *tx_bytes,
            base_fee_millisat_per_gas,
            *tip_millisat_per_gas,
        );

        // ── Conservation ────────────────────────────────────────────────────
        //
        // u128 throughout: each value is u64, but a sum of them is not, and
        // the fee is priced in u128 already. Equality, not `>=` — a transfer
        // that overpays has simply misdeclared its outputs, and silently
        // sweeping the remainder to the proposer would be a fee nobody set.
        let created: u128 = outputs.iter().map(|o| o.value as u128).sum();
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        if spent_value != created + fee {
            return Err(TransferReject::ValueNotConserved);
        }

        // ── The output keys ─────────────────────────────────────────────────
        //
        // Derived from the witness-free root, so the transaction cannot choose
        // where it writes. A collision with a live output would destroy that
        // output's value; it needs a SHA3-256 collision to happen, and is
        // refused rather than assumed away.
        let txid = tx.txid();
        for vout in 0..outputs.len() as u32 {
            if self.eutxos.contains_key(&(txid, vout)) {
                return Err(TransferReject::OutputExists);
            }
        }

        // ── Authorisation: the expensive check, last ────────────────────────
        //
        // One signing root for the whole transfer, so N inputs cost N
        // verifications and not N roots. The root excludes the witnesses (see
        // `spend_signing_root`), which is what lets a signature exist at all.
        let signing_root = tx.spend_signing_root();
        for i in inputs {
            if !verifier.verify_with_key(&i.pubkey, &signing_root, &i.signature) {
                return Err(TransferReject::BadSignature);
            }
        }

        // ── Apply ───────────────────────────────────────────────────────────
        //
        // Nothing above may fail from here, so the set never sees a half-applied
        // transfer.
        for i in inputs {
            self.eutxos.remove(&(i.txid, i.vout));
        }
        for (vout, o) in outputs.iter().enumerate() {
            let vout = vout as u32;
            self.eutxos.insert(crate::state_root::EutxoEntry {
                txid,
                vout,
                value: o.value,
                script_hash: o.script_hash,
            });
        }
        Ok(charge)
    }

    /// [`Self::apply_transfer`] for the deduplicated-witness format
    /// ([`PosTransaction::TransferV2`]) — the same three load-bearing
    /// properties (only the owner spends, value is conserved, each output is
    /// spent at most once), plus the two table disciplines that make a
    /// deduplicated witness as tamper-evident as an inlined one.
    ///
    /// **The caller holds the flag-day gate.** This function is the
    /// post-activation semantics and assumes the epoch check already ran
    /// (`apply_transaction`); tests exercise it directly at this seam, the
    /// same pattern as `with_leak_applied`.
    ///
    /// # Frozen check order, cheapest first (consensus, like V1's)
    ///
    /// Structure (no inputs, size floor), table discipline (strict pubkey
    /// order, which subsumes duplicate keys),
    /// per-input set membership + index bounds + script hashes, table
    /// coverage (unused entries), the price, conservation, output-key
    /// collisions, and only then the hybrid verifications — **one per table
    /// entry, not per input**. The k owner-key hashes are computed once
    /// (k hashes, not n), which with the one-verify-per-owner rule is the
    /// entire performance point: a 30-input single-owner consolidation runs
    /// 1 hybrid verification (145 µs measured) instead of 30, and the class
    /// term of the gas charge is `keys.len()` because that is the CPU the
    /// node actually spends (the "gas buys node CPU" rationale in
    /// [`fee_market::TxClass`]).
    ///
    /// # Why the ATTACK this format invites is dead on arrival
    ///
    /// Deduplication must not let one owner's key authorise another owner's
    /// coin: a transfer spending A's and B's outputs with a table of only
    /// A's key (both inputs pointing at it, signed perfectly by A) fails
    /// [`TransferReject::ScriptMismatch`] on B's input — `owns` compares the
    /// indexed key's hash against **each spent output's committed
    /// `script_hash`**, per input, before any signature is even looked at.
    /// The table changed where a key LIVES, never what it must match.
    fn apply_transfer_v2(
        &mut self,
        tx: &PosTransaction,
        base_fee_millisat_per_gas: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, TransferReject> {
        let PosTransaction::TransferV2 { keys, inputs, outputs, tx_bytes, tip_millisat_per_gas } =
            tx
        else {
            // Unreachable: the only caller matches the variant first. A
            // consensus function does not panic on any input.
            return Err(TransferReject::NoInputs);
        };

        // ── Structure ───────────────────────────────────────────────────────
        if inputs.is_empty() {
            return Err(TransferReject::NoInputs);
        }
        // Same floor as V1, against THIS encoding's own length — the table is
        // most of a real transfer's bytes and must be paid for and counted.
        if *tx_bytes < tx.canonical_bytes().len() as u64 {
            return Err(TransferReject::UnderdeclaredSize);
        }

        // ── Table discipline: strictly ascending by pubkey bytes ────────────
        //
        // One pass replaces the order-free `BTreeSet` dedup this arm shipped
        // with: `keys` must be STRICTLY increasing by pubkey bytes. Strict
        // order subsumes the duplicate check (a sorted table can only carry a
        // duplicate adjacently), so nothing the old pass refused is admitted;
        // adjacent equality keeps its old name (`DuplicateWitnessKey`), an
        // inversion is the new `WitnessTableNotCanonical`. The discrimination
        // matters: equality and disorder are different wallet bugs, and this
        // enum exists so an operator can read a divergence off a log.
        //
        // Why the ORDER is consensus and not lint: the table and every
        // `key_index` sit OUTSIDE `spend_signing_root` (its fold covers spend
        // points, outputs, tx_bytes, tip — witnesses deliberately excluded,
        // see the doc on that function), while the node's mempool is keyed by
        // `canonical_bytes`, not txid (bloch-pos-node/src/engine.rs:800,
        // `on_transaction`). Order-free tables therefore give one txid many
        // valid encodings: a relay permutes `keys`, remaps the `key_index`es,
        // and a byte-keyed mempool holds the permuted twin as a DISTINCT
        // entry of the SAME transfer — churn, and wallet confusion, the exact
        // malleability class segwit closed. With one canonical order the
        // encoding of a valid transfer is unique given its signature set, so
        // every byte-keyed structure downstream (mempool key, gossip frame,
        // block packing by encoded length, post-apply removal by body bytes)
        // is correct without being touched.
        //
        // Why there is NO new activation constant: this function is reachable
        // only through the `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` gate in
        // `apply_transaction`, so the order rule activates on the SAME flag
        // day as the format itself. A second constant would be a second flag
        // day for one format — a partition waiting to happen.
        for pair in keys.windows(2) {
            match pair[0].pubkey.cmp(&pair[1].pubkey) {
                core::cmp::Ordering::Equal => {
                    return Err(TransferReject::DuplicateWitnessKey);
                }
                core::cmp::Ordering::Greater => {
                    return Err(TransferReject::WitnessTableNotCanonical);
                }
                core::cmp::Ordering::Less => {}
            }
        }
        // The owner-key hashes, computed ONCE — k hashes, not n. Whether each
        // key OPENS anything is decided per input below, against the spent
        // output's committed `script_hash`; this is only the digest.
        let key_hashes: Vec<[u8; 32]> =
            keys.iter().map(|k| Sha3_256::digest(&k.pubkey).into()).collect();
        let mut key_used = vec![false; keys.len()];

        // ── The spend points, and the set ───────────────────────────────────
        let mut seen: BTreeSet<([u8; 32], u32)> = BTreeSet::new();
        let mut spent_value: u128 = 0;
        for i in inputs {
            let key = (i.txid, i.vout);
            if !seen.insert(key) {
                return Err(TransferReject::DuplicateInput);
            }
            let Some(entry) = self.eutxos.get(&key) else {
                return Err(TransferReject::UnknownInput);
            };
            let Some(key_hash) = key_hashes.get(i.key_index as usize) else {
                return Err(TransferReject::BadKeyIndex);
            };
            // THE control that makes deduplication safe: the indexed key must
            // hash to what THIS output committed to. A's key on B's coin dies
            // here, before any signature — same placement as V1's check, one
            // (precomputed) hash against one hybrid verification.
            if !owns(key_hash, &entry.script_hash) {
                return Err(TransferReject::ScriptMismatch);
            }
            key_used[i.key_index as usize] = true;
            spent_value += entry.value as u128;
        }
        // ── Table discipline: every entry referenced ────────────────────────
        //
        // With the per-input check above this restores V1's property that
        // every witness byte is checked against something committed; an
        // unreferenced entry would be relay-stuffable padding inside the
        // declared tx_bytes.
        if key_used.iter().any(|used| !used) {
            return Err(TransferReject::WitnessKeyUnused);
        }

        // ── The price, derived ──────────────────────────────────────────────
        //
        // The class term is the TABLE length: gas buys node CPU, and one
        // hybrid verification per table entry is what this function is about
        // to spend — `keys.len()` verifications, not `inputs.len()`. Both
        // counts are derived from the lists, never asserted.
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: keys.len() as u32 },
            *tx_bytes,
            base_fee_millisat_per_gas,
            *tip_millisat_per_gas,
        );

        // ── Conservation ────────────────────────────────────────────────────
        //
        // Identical rule to V1: u128 sums, strict equality.
        let created: u128 = outputs.iter().map(|o| o.value as u128).sum();
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        if spent_value != created + fee {
            return Err(TransferReject::ValueNotConserved);
        }

        // ── The output keys ─────────────────────────────────────────────────
        //
        // The txid comes off the witness-free root, which is byte-identical
        // to the V1 root for the same logical transfer — deliberately, so
        // wallet signatures survive re-encoding (see `spend_signing_root`).
        let txid = tx.txid();
        for vout in 0..outputs.len() as u32 {
            if self.eutxos.contains_key(&(txid, vout)) {
                return Err(TransferReject::OutputExists);
            }
        }

        // ── Authorisation: the expensive check, last — ONCE PER OWNER ───────
        //
        // The whole point of the format: the signing root covers every spend
        // point, so one signature per key authorises all of that key's
        // inputs. k verifications instead of n; each is the SAME check a V1
        // input would get.
        let signing_root = tx.spend_signing_root();
        for k in keys {
            if !verifier.verify_with_key(&k.pubkey, &signing_root, &k.signature) {
                return Err(TransferReject::BadSignature);
            }
        }

        // ── Apply ───────────────────────────────────────────────────────────
        //
        // Nothing above may fail from here — identical to V1, so a refused
        // transfer leaves the state untouched.
        for i in inputs {
            self.eutxos.remove(&(i.txid, i.vout));
        }
        for (vout, o) in outputs.iter().enumerate() {
            let vout = vout as u32;
            self.eutxos.insert(crate::state_root::EutxoEntry {
                txid,
                vout,
                value: o.value,
                script_hash: o.script_hash,
            });
        }
        Ok(charge)
    }

    /// Authorise, price and apply one funded deposit: spend real coins under
    /// the transfer path's rules, register the validator under the staking
    /// rules, and enforce that the two sides meet in an exact equality.
    ///
    /// Only reachable from the funded era (`apply_transaction_gated` refuses
    /// the variant before the flag day), so nothing here runs on the live
    /// chain until the gate is armed.
    ///
    /// # The check order is consensus, cheapest-first, and frozen
    ///
    /// 1. structure (non-empty inputs, size floor) — transfer rules, transfer
    ///    rejects;
    /// 2. registration statics (suite-pinned pubkey shape, 32-byte
    ///    credential, unregistered key, minimum, cap) — `StakingRule`, all
    ///    integer/byte comparisons;
    /// 3. spend points against the committed set (duplicates, existence,
    ///    ownership hash) — transfer rejects;
    /// 4. price and conservation — arithmetic;
    /// 5. change-output keys;
    /// 6. the hybrid verifications, LAST: the input signatures over the
    ///    `DS_SPEND` root, then the PoP over the `DS_DEPOSIT` root. Spam is
    ///    rejected on arithmetic, never at ≈7.3M instructions per signature.
    ///
    /// Every check runs before any mutation, so a refused deposit leaves the
    /// state untouched — the same posture as [`Self::apply_transfer`].
    ///
    /// # Conservation (the equality, stated once and enforced below)
    ///
    /// ```text
    /// Σ inputs  ==  amount_sat + Σ change + fee
    /// ```
    ///
    /// What leaves the eUTXO set is exactly the bond plus the change plus the
    /// fee; the bond enters the registry at exactly `amount_sat`; and
    /// `issued_sat` is never touched — a funded deposit moves existing coins,
    /// it never issues. Same reject, same spirit as the transfer's
    /// [`TransferReject::ValueNotConserved`]: equality, not `>=`, because an
    /// overpaying deposit has misdeclared itself and a silent sweep to the
    /// proposer would be a fee nobody set.
    fn apply_funded_deposit(
        &mut self,
        tx: &PosTransaction,
        total_active_sat: u128,
        base_fee_millisat_per_gas: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, TxReject> {
        let PosTransaction::FundedDeposit {
            inputs,
            change,
            pubkey,
            amount_sat,
            randao_commitment,
            withdrawal_credentials,
            commission_bps,
            proof_of_possession,
            tx_bytes,
            tip_millisat_per_gas,
        } = tx
        else {
            // Unreachable: the only caller matches the variant first. A
            // consensus function does not panic on any input.
            return Err(TxReject::Transfer(TransferReject::NoInputs));
        };

        // ── 1. Structure: the transfer rules, verbatim ─────────────────────
        // A deposit that spends nothing is the legacy mint this variant
        // exists to replace; refused with the transfer's own reason.
        if inputs.is_empty() {
            return Err(TxReject::Transfer(TransferReject::NoInputs));
        }
        if *tx_bytes < tx.canonical_bytes().len() as u64 {
            return Err(TxReject::Transfer(TransferReject::UnderdeclaredSize));
        }

        // ── 2. Registration statics ────────────────────────────────────────
        // Suite pinned by consensus: only the enveloped hybrid form may
        // register (staking.rs rationale — the ML-DSA-only escape hatch must
        // not enter the registry through this door).
        if !staking::is_wire_hybrid_pubkey(pubkey) {
            return Err(TxReject::StakingRule);
        }
        // The credential must be the 32-byte script-hash form NOW, not at
        // withdrawal: a malformed credential discovered 2,048 epochs later
        // would strand the bond forever.
        if withdrawal_credentials.len() != 32 {
            return Err(TxReject::StakingRule);
        }
        let pubkey_hash: [u8; 32] = Sha3_256::digest(pubkey).into();
        // Same three rules, same order, same rationales as the legacy arm:
        // no re-registration, the minimum bond, the 1%-of-active-stake cap
        // floored at the minimum (the genesis-bootstrap argument in
        // staking.rs).
        if self.pubkey_index.contains_key(&pubkey_hash) {
            return Err(TxReject::StakingRule);
        }
        if *amount_sat < staking::MIN_DEPOSIT_SAT {
            return Err(TxReject::StakingRule);
        }
        let cap = (total_active_sat * delegation::MAX_VALIDATOR_STAKE_BPS / 10_000)
            .max(staking::MIN_DEPOSIT_SAT);
        if *amount_sat > cap {
            return Err(TxReject::StakingRule);
        }

        // ── 3. The spend points, against the committed set ─────────────────
        // Identical mechanics to apply_transfer: whole-transaction duplicate
        // check, existence, then the ownership hash — one hash before one
        // hybrid verification.
        let mut seen: BTreeSet<([u8; 32], u32)> = BTreeSet::new();
        let mut spent_value: u128 = 0;
        for i in inputs {
            let key = (i.txid, i.vout);
            if !seen.insert(key) {
                return Err(TxReject::Transfer(TransferReject::DuplicateInput));
            }
            let Some(entry) = self.eutxos.get(&key) else {
                return Err(TxReject::Transfer(TransferReject::UnknownInput));
            };
            let key_hash: [u8; 32] = Sha3_256::digest(&i.pubkey).into();
            if !owns(&key_hash, &entry.script_hash) {
                return Err(TxReject::Transfer(TransferReject::ScriptMismatch));
            }
            spent_value += entry.value as u128;
        }

        // ── 4. The price, derived — and the PoP is in the class term ───────
        // `inputs + 1`: the PoP costs the node exactly one more hybrid
        // verification, priced identically to an input's. Charging it through
        // the class keeps ONE pricing function (`fee_market::charge`) instead
        // of a bespoke gas formula for this variant.
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: inputs.len() as u32 + 1 },
            *tx_bytes,
            base_fee_millisat_per_gas,
            *tip_millisat_per_gas,
        );

        // ── Conservation ───────────────────────────────────────────────────
        // The equality from the doc above. u128 throughout, like the
        // transfer.
        let returned: u128 = change.iter().map(|o| o.value as u128).sum();
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        if spent_value != *amount_sat + returned + fee {
            return Err(TxReject::Transfer(TransferReject::ValueNotConserved));
        }

        // ── 5. The change-output keys ──────────────────────────────────────
        let txid = tx.txid();
        for vout in 0..change.len() as u32 {
            if self.eutxos.contains_key(&(txid, vout)) {
                return Err(TxReject::Transfer(TransferReject::OutputExists));
            }
        }

        // ── 6. Authorisation, the expensive checks last ────────────────────
        // The coin owners' signatures over the witness-free DS_SPEND root
        // (which covers the registration payload AND the PoP — see
        // spend_signing_root), through the same verifier seam as the
        // transfer.
        let signing_root = tx.spend_signing_root();
        for i in inputs {
            if !verifier.verify_with_key(&i.pubkey, &signing_root, &i.signature) {
                return Err(TxReject::Transfer(TransferReject::BadSignature));
            }
        }
        // The validator key's proof of possession over the DS_DEPOSIT root —
        // a REGISTRATION rule (anti rogue-key), hence `StakingRule` and not a
        // transfer reject: the coins' movement was already authorised above,
        // this decides whether the registry may admit the key. `None` is
        // unreachable here (shape checked at step 2), refused totally anyway.
        let Some(pop_root) = tx.funded_deposit_pop_signing_root() else {
            return Err(TxReject::StakingRule);
        };
        if !verifier.verify_with_key(pubkey, &pop_root, proof_of_possession) {
            return Err(TxReject::StakingRule);
        }

        // ── Apply. Nothing below may fail. ─────────────────────────────────
        for i in inputs {
            self.eutxos.remove(&(i.txid, i.vout));
        }
        for (vout, o) in change.iter().enumerate() {
            self.eutxos.insert(crate::state_root::EutxoEntry {
                txid,
                vout: vout as u32,
                value: o.value,
                script_hash: o.script_hash,
            });
        }
        // Registration — field for field what the legacy arm wrote, so the
        // activation queue, the roster filters and the epoch pipeline treat a
        // funded validator identically to every earlier one. The
        // deposit-history entry's epoch is >= the gate by construction (this
        // arm only runs in the funded era), which is exactly what marks this
        // bond as FUNDED for `unbacked_principal_sat`: nothing is written off
        // at its withdrawal.
        let index = self.validators.keys().next_back().map_or(0, |k| k + 1);
        self.validators.insert(
            index,
            ValidatorRecord {
                index,
                pubkey: pubkey.clone(),
                staked_sat: *amount_sat,
                randao_commitment: *randao_commitment,
                withdrawal_credentials: withdrawal_credentials.clone(),
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
        Ok(charge)
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
        // Read the offender's backed share BEFORE the slash consumes it: the
        // whistleblower cap below is a function of what was coin-backed at the
        // moment of the offence, and one line further down that number is gone.
        let backed_before_slash = self.withdrawable_sat(offender);
        if let Some(rec) = self.validators.get_mut(&offender) {
            rec.slashed = true;
            rec.staked_sat = rec.staked_sat.saturating_sub(outcome.delegation_losses_sat[0]);
            // THE LOW-WATER RECORDER (2026-08-22), UNGATED — the only site
            // that writes `stake_low_water`, sitting on the only site that
            // reduces `staked_sat`. `min` over the bond's whole history:
            // rewards raise `staked_sat` and must NOT raise this, or the
            // write-off would re-classify earned coin as phantom (the field
            // docs work the number).
            //
            // Zero is stored, never elided: absent means "never slashed", and
            // a bond slashed to nothing must not be able to impersonate one.
            //
            // HONEST SCOPE OF THE `min` INSIDE [`Self::fold_low_water`]:
            // `slashing::process` ejects a validator on its first offence and
            // refuses every later evidence against it (`EvidenceError::
            // AlreadySlashed`), and this is the only site that reduces
            // `staked_sat`. So on today's rules the fold runs AT MOST ONCE
            // per validator, and `min` is indistinguishable from a plain
            // assignment by any reachable sequence of blocks — a mutation to
            // assignment survives the whole consensus suite, and saying it
            // does is worth more than a test that pretends otherwise. The
            // `min` is there for the second stake-reduction site that does
            // not exist yet (partial slashing, a leak that bites principal),
            // and it is pinned where it CAN be pinned: `fold_low_water` is a
            // pure function with its own unit test that feeds it a second
            // reduction directly.
            let staked_after = rec.staked_sat;
            let folded =
                Self::fold_low_water(self.stake_low_water.get(&offender).copied(), staked_after);
            self.stake_low_water.insert(offender, folded);
            // NOTE: the mark above IS the write-off's maintenance fold. The
            // rejected design carried a second, parallel `unbacked` map and
            // folded `unbacked = min(unbacked, staked_sat)` here as well;
            // deriving the write-off per call from this mark makes that
            // duplicate unnecessary, and removes the failure mode where a
            // future stake-reduction site updates one fold and forgets the
            // other. Direction is still the decision it always was: the
            // penalty consumes the bond's REAL value (emitted rewards) first
            // and only starts burning unissued principal once nothing real is
            // left, because the reverse order would make slashing free for
            // the genesis cohort.
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
        // The whistleblower reward may not exceed the BACKED share the slash
        // actually consumed.
        //
        // Unbounded, it is a hole straight through the founder's rule that a
        // genesis bond's principal never becomes spendable. The reward is a
        // thirty-second of what was slashed and lands in `pending_fee_rewards`,
        // which is accrual — and accrual IS withdrawable. So slashing an
        // unbacked genesis bond converted principal that `issued_sat` never
        // counted into withdrawable coins in somebody else's bond, with
        // `issued_sat` never moving. A validator willing to be slashed (or a
        // proposer colluding with one) could run that in a loop and mint past
        // the supply cap. Found by the adversarial front as A7, against
        // production code, before the gate ever armed.
        //
        // The cap is deliberately conservative: it counts only the backed
        // share consumed from the OFFENDER'S OWN bond, not from delegated
        // principal, because delegated backing is a surface this change does
        // not settle. Under-paying a whistleblower is the safe direction —
        // it destroys value that was never coins, which is what unbacked
        // principal is. Over-paying creates coins, which is the whole defect.
        //
        // `backed_before_slash` is `withdrawable_sat`, i.e. `staked_sat`
        // minus the FLOORED unbacked principal, read before the penalty
        // applies. The floor matters here for the same reason it matters at
        // withdrawal: without it a bond that a pre-gate slash cut and later
        // rewards rebuilt would read a backed share smaller than the emitted
        // coin actually in it, and the reporter would be under-paid twice
        // over.
        //
        // Gated, and this is not optional: with the flag day closed
        // `unbacked_principal_sat` treats every bond as unbacked, so applying
        // the cap unconditionally would zero every whistleblower reward on the
        // live chain today — a consensus change outside its own flag day,
        // which rule 1 forbids and which would fork the fleet on the next
        // slash.
        let reward = capped_whistleblower_reward(
            outcome.whistleblower_reward_sat,
            outcome.delegation_losses_sat[0],
            backed_before_slash,
            self.epoch >= crate::params::FUNDED_STAKE_ACTIVATION_EPOCH,
        );
        if reward > 0 {
            *self
                .pending_fee_rewards
                .entry(including_proposer)
                .or_insert(0) += reward;
        }
        Ok(())
    }


    /// The low-water fold: the smallest a bond has ever been, given whatever
    /// floor was already recorded and the stake left after the reduction that
    /// is happening now. `None` — no floor yet — means this reduction IS the
    /// history, so the post-reduction stake is the floor.
    ///
    /// Pure, and separate from its call site, because the `min` cannot be
    /// exercised from a block today: a validator is ejected on its first
    /// offence and no second slash is admissible, so the recorder runs once
    /// per validator and `min` collapses to assignment on every reachable
    /// path. Feeding a second reduction to this function directly is the only
    /// way to make that branch fail when it is broken, and its unit test does
    /// exactly that.
    fn fold_low_water(existing: Option<u128>, staked_after: u128) -> u128 {
        match existing {
            Some(floor) => floor.min(staked_after),
            None => staked_after,
        }
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

    /// One unspent output, by outpoint — the lookup a wallet needs to build a
    /// spend, and the one a mempool needs to price it.
    ///
    /// Read-only on purpose. The set is mutated in exactly one place
    /// ([`Self::apply_transfer`]), under the authorisation and conservation
    /// rules; a `&mut` accessor would be a second way to move coins, with no
    /// rules attached.
    pub fn utxo(&self, txid: &[u8; 32], vout: u32) -> Option<&crate::state_root::EutxoEntry> {
        self.eutxos.get(&(*txid, vout))
    }

    /// Every unspent output, in outpoint order (the order the state root
    /// commits them in).
    pub fn utxos(&self) -> impl Iterator<Item = &crate::state_root::EutxoEntry> {
        self.eutxos.values()
    }

    /// Total value in the unspent set, in satoshis.
    ///
    /// `u128`, because the set holds a 100-billion-BLCH supply at 8 decimals
    /// and a `u64` sum of `u64` values would wrap somewhere inside it — the
    /// same reason [`crate::state_root::total_utxo_value`] exists.
    pub fn total_unspent_sat(&self) -> u128 {
        self.eutxos.values().map(|e| e.value as u128).sum()
    }

    /// The price this state's block charged, in millisatoshi per gas. The
    /// **next** block's price is [`Self::next_base_fee`] — never this value
    /// carried forward, and never a node-local number.
    pub fn base_fee_millisat_per_gas(&self) -> u128 {
        self.base_fee_millisat_per_gas
    }

    // ── Read surface for the node's RPC layer ───────────────────────────────
    //
    // Added 2026-08-13 for `bloch-pos-node`'s JSON-RPC module. All three are
    // *read-only projections of already-committed state*: they compute nothing
    // a consensus rule does not already compute, and no transition behaviour
    // changes. They exist because the fields they read are private — which is
    // correct, since a mutable handle to the eUTXO set outside the transition
    // is exactly the node-local mutable consensus state rule 2 forbids — and a
    // query surface still has to be able to answer "what does this address
    // hold". Borrowed (`&`) rather than cloned so a query cannot be mistaken
    // for a state the caller may edit.

    /// Number of validators in the committed registry — **every** record, not
    /// just the active ones. [`StateReader::active_validators`] answers the
    /// other question; a query surface needs both, because "3 of 10 active" and
    /// "3 of 3 active" are different networks and one number cannot say which.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Every unspent output, in `(txid, vout)` order.
    ///
    /// Order is the map's, so it is a function of the data and not of insertion
    /// history (rule 2) — which is what makes a paginated query stable across
    /// two calls to two different nodes on the same state.
    pub fn eutxos(&self) -> impl Iterator<Item = &crate::state_root::EutxoEntry> + '_ {
        self.eutxos.values()
    }

    /// Sum of the values of every output locked to `script_hash`, in satoshis.
    ///
    /// `u128` and not `u64`: a single output fits u64 (the cap is 54.21% of
    /// `u64::MAX`) but a *sum* of two large ones wraps, and this is a sum. That
    /// is the arithmetic contract, and a balance query is precisely where
    /// ignoring it would be invisible until the one address that overflows.
    pub fn balance_sat(&self, script_hash: &[u8; 32]) -> u128 {
        self.eutxos
            .values()
            .filter(|e| &e.script_hash == script_hash)
            .map(|e| u128::from(e.value))
            .sum()
    }

    /// The committed cumulative-issuance counter, in satoshis — the number the
    /// hard cap is enforced against (`SupplyCapExceeded` reads this exact
    /// field in `compute_post_state`).
    ///
    /// Read-only projection under the same contract as the block above: the
    /// field stays private because only the transition may advance it, but a
    /// supply cap nobody can observe over RPC is a promise rather than a
    /// check. Added 2026-08-21 as a prerequisite of the funded-staking flag
    /// day (`params::FUNDED_STAKE_ACTIVATION_EPOCH`): the post-activation
    /// runbook has to verify that a deposit-and-withdraw pair leaves this
    /// counter unchanged — bond moves are moves of existing coins, never
    /// issuance — and that verification is impossible if the counter never
    /// leaves the node. `TOTAL_SUPPLY_SAT - issued_sat()` is the emission
    /// headroom the boundary clamp works from.
    pub fn issued_sat(&self) -> u128 {
        self.issued_sat
    }

    /// How much of validator `index`'s bond was never funded by eUTXO coins
    /// — the portion the founder's decision writes off at withdrawal ("a bond
    /// is withdrawable only to the extent it was funded").
    ///
    /// # The principal: which class the bond is in
    ///
    /// - **no deposit-history entry** → the record was seeded by
    ///   [`CommittedState::genesis`]: its principal destroyed no coins and
    ///   was counted in no issuance ([`GENESIS_UNFUNDED_PRINCIPAL_SAT`],
    ///   manifest-pinned) → the whole principal is phantom;
    /// - **deposited before the gate** → a legacy unfunded
    ///   [`PosTransaction::Deposit`] minted the whole `amount_sat` from
    ///   nothing → phantom too. This covers the modified-proposer case:
    ///   consensus applied legacy deposits even while the mempool refused
    ///   them, so keying the write-off on the genesis cohort alone would
    ///   leave any such principal withdrawable;
    /// - **deposited at or past the gate** → a [`PosTransaction::FundedDeposit`]
    ///   destroyed real coins for it → nothing to write off.
    ///
    /// # The floor: how much of that principal is still THERE
    ///
    /// The answer is `min(principal, low_water)`, where the low water is the
    /// smallest the bond has ever been ([`Self::stake_low_water_sat`],
    /// recorded by `apply_slashing_evidence`) and falls back to the current
    /// `staked_sat` for a bond no slash has ever touched — for which the two
    /// are identical, so every validator on the live chain reads the number
    /// it would read without this term.
    ///
    /// The floor is not decoration; without it the rule CONFISCATES EMITTED
    /// COIN. A slash burns phantom principal first, so subtracting the whole
    /// principal at withdrawal charges that burn a second time, and the
    /// second charge lands on rewards the operator really earned. MEASURED
    /// against the unfloored version: principal 25,000 BLOCH, slash −5,000,
    /// rewards +10,000 pays 5,000 unfloored and 10,000 floored, and 10,000 is
    /// exactly the emitted coin in the bond
    /// (`slash_below_principal_then_reaccumulate_pays_exactly_the_emitted_excess`).
    ///
    /// # Derived per call, never materialised
    ///
    /// Everything above is already-committed state, so this adds NO column to
    /// the state root and no root moves while the gate is closed (rule 1 of
    /// the flag day). The rejected alternative computed the same quantity
    /// ONCE, on the boundary that crosses the gate, and stored it: that
    /// version writes off NOTHING — paying every genesis bond's full
    /// principal as spendable coin — if the founder ever arms an epoch the
    /// chain has already passed, because the crossing condition
    /// `closing < gate && next >= gate` never fires. A per-call derivation
    /// has no boundary to miss.
    ///
    /// The history lookup is sound because a pubkey deposits at most once
    /// (`pubkey_index` makes a second deposit a deterministic reject) and the
    /// history is kept forever (see the `deposit_history` field docs).
    fn unbacked_principal_sat(&self, index: u32, funded_stake_gate_epoch: u64) -> u128 {
        let Some(rec) = self.validators.get(&index) else {
            return 0;
        };
        let pubkey_hash: [u8; 32] = Sha3_256::digest(&rec.pubkey).into();
        let principal = match self
            .deposit_history
            .iter()
            .find(|d| d.pubkey_hash == pubkey_hash)
        {
            None => GENESIS_UNFUNDED_PRINCIPAL_SAT,
            Some(d) if d.deposit_epoch < funded_stake_gate_epoch => d.amount_sat,
            Some(_) => 0,
        };
        let floor = self
            .stake_low_water
            .get(&index)
            .copied()
            .unwrap_or(rec.staked_sat);
        principal.min(floor)
    }

    /// Is the write-off for `validator` UNCOMPUTABLE?
    ///
    /// True exactly when the bond was slashed but carries no low-water mark:
    /// it was slashed by a binary older than the recorder, so `min(principal,
    /// min staked)` cannot be evaluated and every available default is wrong
    /// in one direction. [`PosTransaction::Withdraw`] refuses these rather
    /// than guessing (see that variant's docs).
    ///
    /// A PREDICATE over committed state, not a stored set, and that is sound
    /// only because a bond cannot be slashed twice: a validator is ejected on
    /// its first offence and no second slash is admissible, so a record that
    /// is `slashed` with no mark today can never acquire one later and change
    /// class. If a second slash ever becomes reachable, this must become a
    /// stored set recorded at the first slash, or a bond could silently leave
    /// the refuse class with a floor that saw only its second penalty.
    pub fn is_write_off_indeterminate(&self, validator: u32) -> bool {
        self.validators
            .get(&validator)
            .is_some_and(|r| r.slashed && !self.stake_low_water.contains_key(&validator))
    }

    /// How many bonds are in the indeterminate class — the number the
    /// post-activation runbook watches, and zero on the live chain today
    /// (nothing has ever been slashed).
    pub fn write_off_indeterminate_count(&self) -> usize {
        self.validators
            .keys()
            .filter(|v| self.is_write_off_indeterminate(**v))
            .count()
    }

    /// The recorded low-water mark of one bond, in satoshis, or `None` if no
    /// slash has ever reduced it. `Some(0)` and `None` are DIFFERENT facts:
    /// the first is a bond slashed to nothing, the second a bond never
    /// slashed — the difference is what defines the indeterminate class.
    pub fn stake_low_water_sat(&self, validator: u32) -> Option<u128> {
        self.stake_low_water.get(&validator).copied()
    }

    /// Cumulative unissued principal written off at withdrawals, in
    /// satoshis — the audit counter the post-activation runbook checks
    /// (1,600,000 BLOCH once all 64 genesis bonds are withdrawn). Read-only
    /// projection, same contract as [`Self::issued_sat`]: only the transition
    /// writes the underlying field.
    pub fn written_off_sat(&self) -> u128 {
        self.written_off_sat
    }

    /// The satoshis validator `index` could withdraw today's rules permitting
    /// — bonded stake minus the unbacked principal, saturating at zero.
    ///
    /// This is the amount [`PosTransaction::Withdraw`] pays, the ceiling the
    /// whistleblower cap in `apply_slashing_evidence` reads, and the number
    /// the RPC's validator surface reports: one definition for all three.
    /// Saturating: the floor keeps `unbacked <= staked_sat` on every
    /// reachable path, and a plain subtraction would turn any future break of
    /// that into a debug panic on a consensus read path or a wrapped
    /// near-`u128::MAX` "withdrawable" in release.
    pub fn withdrawable_sat(&self, index: u32) -> u128 {
        self.withdrawable_sat_gated(index, crate::params::FUNDED_STAKE_ACTIVATION_EPOCH)
    }

    /// [`Self::withdrawable_sat`] with the gate epoch explicit — the testable
    /// inner form, same idiom as `with_leak_applied`: the tripwire keeps the
    /// shipped constant inert, and tests exercise both sides of the gate here
    /// without arming anything.
    fn withdrawable_sat_gated(&self, index: u32, funded_stake_gate_epoch: u64) -> u128 {
        self.validators.get(&index).map_or(0, |r| {
            r.staked_sat
                .saturating_sub(self.unbacked_principal_sat(index, funded_stake_gate_epoch))
        })
    }

    /// The price the child block must charge: the EIP-1559 controller applied
    /// to this state's committed price and usage.
    ///
    /// One definition, two callers — the producer prices its mempool with it
    /// and the validator charges every included transaction with it. A second
    /// expression of this rule anywhere is h28080 with a fee attached.
    pub fn next_base_fee(&self) -> u128 {
        self.next_base_fee_at(self.epoch)
    }

    /// The price this state charges for a block in `epoch`.
    ///
    /// The epoch is explicit because the EIP-1559 byte target is flag-day
    /// gated and this state's own `epoch` is the WRONG one to use at the
    /// boundary: `compute_post_state` prices from `pre`, which has not rolled
    /// yet, so on the first block of the activation epoch `pre.epoch` is still
    /// the old era. The consensus caller passes the epoch derived from the
    /// block's header slot; [`Self::next_base_fee`] keeps the convenient form
    /// for the producer and the RPC, where this state IS the one being priced.
    pub fn next_base_fee_at(&self, epoch: u64) -> u128 {
        fee_market::next_base_fee(
            self.base_fee_millisat_per_gas,
            fee_market::BlockUsage {
                gas_used: self.block_gas_used,
                tx_bytes: self.block_tx_bytes,
            },
            epoch,
        )
    }

    // ── Epoch boundary ──────────────────────────────────────────────────────

    /// Close the current epoch E and open E+1. Infallible and pure — it runs
    /// whether or not the boundary slot carried a block, because a withheld
    /// proposal must not become a lever over everyone's rewards or over the
    /// finality clock (the engine's leak ticks on empty epochs too).
    /// # It takes no flag-day parameter, and that is the point
    ///
    /// A rejected design materialized the write-off here, on the ONE boundary
    /// that crosses `FUNDED_STAKE_ACTIVATION_EPOCH`, which forced a `gate`
    /// parameter through this function and every caller. The write-off is
    /// derived per call instead (`unbacked_principal_sat`), so the boundary
    /// carries no flag-day rule at all — and the class of bug that motivated
    /// the change cannot exist here: a boundary condition that never fires
    /// (the founder arming an epoch the chain has already passed) is a
    /// silent, total failure of the rule, while a derivation has nothing to
    /// miss.
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
        let roster_next = st.consensus_roster_at(next_epoch);
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

        // 7. NO funded-staking activation boundary. The write-off is
        //    DERIVED per call from committed state
        //    (`unbacked_principal_sat`), not materialized here, and the
        //    difference is not stylistic. A one-shot boundary fires only when
        //    `closing < gate && next >= gate`; if the founder arms an epoch
        //    the chain has already passed — an ordinary operational outcome,
        //    since arming means agreeing an epoch and rebuilding a fleet —
        //    that condition never holds again, the map stays empty, and every
        //    genesis bond withdraws its full never-emitted principal as
        //    spendable coin. All 1,600,000 BLOCH of it, silently, in the
        //    exact opposite direction from the decision. A derivation has no
        //    boundary to miss
        //    (`arming_the_gate_at_an_epoch_already_passed_still_writes_off`).

        st
    }
}

/// The whistleblower reward, capped at the backed share the slash consumed.
///
/// Pure and gate-explicit for the same reason `withdrawable_sat_gated` is: the
/// shipped constant is `u64::MAX`, so a test that went through the caller could
/// only ever exercise the pre-gate side. Both sides are reachable here without
/// arming anything.
///
/// `funded_era == false` returns the raw reward unchanged — the pre-gate rule,
/// byte for byte.
fn capped_whistleblower_reward(
    raw_reward_sat: u128,
    operator_loss_sat: u128,
    backed_before_slash_sat: u128,
    funded_era: bool,
) -> u128 {
    if !funded_era {
        return raw_reward_sat;
    }
    raw_reward_sat.min(operator_loss_sat.min(backed_before_slash_sat))
}

/// `roster` with each validator's accrued inactivity leak subtracted.
///
/// Split out of [`CommittedState::consensus_roster_at`] so the arithmetic is
/// testable without standing up a finality engine and starving it for the
/// four-plus epochs it takes a leak to start accruing. Saturating: a leak that
/// has reached the stake lands on zero and never wraps into a giant weight,
/// which is the one way this could turn a dead validator into a dominant one.
fn with_leak_applied(roster: Vec<Validator>, leaked_of: impl Fn(u32) -> u64) -> Vec<Validator> {
    roster
        .into_iter()
        .map(|v| Validator {
            index: v.index,
            effective_stake: v.effective_stake.saturating_sub(leaked_of(v.index)),
        })
        .collect()
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
        // The node-side duty computations (attest, judge, propose) read this,
        // so it carries the leak for the same reason step 4 does: the schedule
        // a node acts on must be the schedule every other node validates it
        // against.
        self.consensus_roster_at(self.epoch)
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
        self.compute_post_state_gated(
            pre,
            envelope,
            attestations,
            transactions,
            crate::params::FUNDED_STAKE_ACTIVATION_EPOCH,
        )
    }

    /// [`Self::compute_post_state`] with the funded-staking flag day passed
    /// in, threading it to the ONE place that reads it: every transaction,
    /// through `apply_transaction_gated`. The epoch-boundary walk takes no
    /// flag-day parameter — see `close_epoch` for why the write-off is
    /// derived rather than materialized there.
    ///
    /// Same standing as the other two `_gated` seams — a testing seam, not a
    /// policy knob. It exists because the funded discriminants are
    /// consensus-invalid while the constant is `u64::MAX`, so a test that
    /// only calls the seam methods directly never proves the BLOCK path
    /// accepts them, and until 2026-08-22 no test did. Production reaches
    /// this through `compute_post_state`, whose single argument is the
    /// constant.
    pub fn compute_post_state_gated(
        &self,
        pre: &CommittedState,
        envelope: &ProposalEnvelope,
        attestations: &[Attestation],
        transactions: &[PosTransaction],
        funded_stake_activation_epoch: u64,
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
        //
        // AND WHAT THIS CHECK DOES **NOT** PROTECT (2026-08-22): it is
        // one-sided — it fires only when the committed counter advances past
        // the cap. It does not detect spendable value created WITHOUT
        // advancing `issued_sat` (a withdrawal paying out the never-emitted
        // genesis bond principal would pass it clean — that hole is closed
        // by `apply_withdraw`'s write-off arithmetic, not here), it does not
        // reconcile the eUTXO total against the counter, and it does not see
        // burns. Anyone auditing the funded-staking flag day: the protection
        // for that front is `payout = staked_sat - unbacked_principal` plus the
        // conservation tests, and this check contributes nothing to it.
        if st.issued_sat > tokenomics_v4::TOTAL_SUPPLY_SAT {
            return Err(TransitionError::SupplyCapExceeded);
        }

        // Consensus weight, not raw stake: the proposer draw below and the
        // committee check at step 8 must both read the leak-adjusted roster,
        // or an absent validator keeps its slot and its seat forever.
        let roster = st.consensus_roster_at(st.epoch);
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
        let base_fee = pre.next_base_fee_at(block_epoch);

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
                    })
                    .map_err(|()| TxReject::StakingRule),
                _ => st.apply_transaction_gated(
                    tx,
                    total_active,
                    base_fee,
                    &self.verifier,
                    funded_stake_activation_epoch,
                ),
            };
            match applied {
                Ok(charge) => {
                    base_fees += charge.base_fee_sat;
                    priority_fees += charge.priority_fee_sat;
                    block_gas = block_gas.saturating_add(charge.gas);
                    block_bytes = block_bytes.saturating_add(charge.tx_bytes);
                }
                // The transfer rules keep their reason; everything else stays
                // on the frozen `Transaction(i)` variant it always used.
                Err(TxReject::Transfer(why)) => {
                    return Err(TransitionError::Transfer(i as u32, why))
                }
                Err(_) => return Err(TransitionError::Transaction(i as u32)),
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
        if block_bytes > fee_market::max_block_tx_bytes(block_epoch) {
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

impl<V: SignatureVerifier> Transition<V> {
    /// [`StateTransition::apply_block`] with the funded-staking flag day
    /// passed in — the full block path (header commitments, proposer draw,
    /// RANDAO, attestations, transactions, state-root check), differing from
    /// production only in where the boundary sits. The seam the conservation
    /// test drives, so the deposit/exit/withdraw cycle it asserts over is the
    /// one a real block would produce and not a hand-called method.
    pub fn apply_block_gated(
        &self,
        pre: &CommittedState,
        envelope: &ProposalEnvelope,
        attestations: &[Attestation],
        transactions: &[PosTransaction],
        funded_stake_activation_epoch: u64,
    ) -> Result<CommittedState, TransitionError> {
        let post = self.compute_post_state_gated(
            pre,
            envelope,
            attestations,
            transactions,
            funded_stake_activation_epoch,
        )?;
        if post.compute_root() != envelope.header.state_root {
            return Err(TransitionError::StateRootMismatch);
        }
        Ok(post)
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
            // Two inputs with DIFFERENT witness lengths and two outputs with
            // different values: a field-order, width or count mistake in
            // either list changes the bytes, and swapping the pubkey and
            // signature of an input changes them too.
            PosTransaction::Transfer {
                inputs: vec![
                    TransferInput {
                        txid: [0x11; 32],
                        vout: 7,
                        pubkey: vec![0xA1; 3745],
                        signature: vec![0xB2; 4589],
                    },
                    TransferInput {
                        txid: [0x22; 32],
                        vout: 0,
                        pubkey: vec![0xC3; 17],
                        signature: vec![0xD4; 5],
                    },
                ],
                outputs: vec![
                    TransferOutput { value: 1, script_hash: [0xE5; 32] },
                    TransferOutput { value: u64::MAX, script_hash: [0xF6; 32] },
                ],
                tx_bytes: 1_234_567,
                tip_millisat_per_gas: 987_654_321_000,
            },
            // The empty-list edges, which the count prefixes must survive.
            PosTransaction::Transfer {
                inputs: vec![TransferInput {
                    txid: [0u8; 32],
                    vout: u32::MAX,
                    pubkey: Vec::new(),
                    signature: Vec::new(),
                }],
                outputs: Vec::new(),
                tx_bytes: 0,
                tip_millisat_per_gas: 0,
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
            // Appended AFTER the originals: `truncation_is_refused_not_defaulted`
            // indexes samples()[1], and V2 joining the corpus must not silently
            // repoint what that test sweeps.
            PosTransaction::TransferV2 {
                keys: vec![
                    WitnessKey { pubkey: vec![0xA1; 37], signature: vec![0xB2; 53] },
                    // Zero-length halves: the length prefixes must carry them.
                    WitnessKey { pubkey: Vec::new(), signature: Vec::new() },
                ],
                inputs: vec![
                    TransferInputV2 { txid: [0x11; 32], vout: 0, key_index: 0 },
                    TransferInputV2 { txid: [0x22; 32], vout: u32::MAX, key_index: 1 },
                    // An index past the table DECODES — whether it is valid is
                    // the transition's question (BadKeyIndex), not the codec's.
                    TransferInputV2 { txid: [0x33; 32], vout: 7, key_index: u32::MAX },
                ],
                outputs: vec![TransferOutput { value: u64::MAX, script_hash: [0xC3; 32] }],
                tx_bytes: 262_144,
                tip_millisat_per_gas: 987_654_321_000,
            },
            // The empty-table/empty-output edges.
            PosTransaction::TransferV2 {
                keys: Vec::new(),
                inputs: vec![TransferInputV2 { txid: [0u8; 32], vout: 0, key_index: 0 }],
                outputs: Vec::new(),
                tx_bytes: 0,
                tip_millisat_per_gas: 0,
            },
            // The funded staking shapes (0x07–0x09). Same value discipline as
            // the transfer samples above: every integer differs and the four
            // length-prefixed byte fields have four different lengths, so a
            // swapped pair or a shifted width cannot round-trip.
            PosTransaction::FundedDeposit {
                inputs: vec![TransferInput {
                    txid: [0x31; 32],
                    vout: 9,
                    pubkey: vec![0xA7; 3749],
                    signature: vec![0xB8; 4775],
                }],
                change: vec![TransferOutput { value: 77, script_hash: [0xC9; 32] }],
                pubkey: vec![0xDA; 3749],
                amount_sat: 25_000 * 100_000_000,
                randao_commitment: [0xEB; 32],
                withdrawal_credentials: vec![0xFC; 32],
                commission_bps: 750,
                proof_of_possession: vec![0x1D; 4775],
                tx_bytes: 17_300,
                tip_millisat_per_gas: 12,
            },
            // And its empty-list edges.
            PosTransaction::FundedDeposit {
                inputs: Vec::new(),
                change: Vec::new(),
                pubkey: Vec::new(),
                amount_sat: 0,
                randao_commitment: [0u8; 32],
                withdrawal_credentials: Vec::new(),
                commission_bps: 0,
                proof_of_possession: Vec::new(),
                tx_bytes: 0,
                tip_millisat_per_gas: 0,
            },
            PosTransaction::SignedExit {
                validator: 21,
                epoch: 4_096,
                signature: vec![0x2E; 4775],
            },
            PosTransaction::Withdraw { validator: 63 },
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

    /// The funded shapes obey the same three codec laws as everything else —
    /// asserted against a full-size sample so the cuts land inside real
    /// fields, not only inside the header.
    #[test]
    fn funded_shapes_refuse_truncation_and_trailing_bytes() {
        for tx in &samples()[8..] {
            let full = tx.canonical_bytes();
            for cut in [1, full.len() / 2, full.len() - 1] {
                if cut < full.len() {
                    assert_eq!(
                        PosTransaction::from_canonical_bytes(&full[..cut]),
                        Err(TxDecodeError::Truncated),
                        "a short read of tag {:#04x} must fail, never zero-fill",
                        full[0],
                    );
                }
            }
            let mut long = full.clone();
            long.push(0x00);
            assert_eq!(
                PosTransaction::from_canonical_bytes(&long),
                Err(TxDecodeError::TrailingBytes),
                "two encodings must not decode to one tag-{:#04x} transaction",
                full[0],
            );
        }
        // Control for the slice above: samples()[8..] really are the funded
        // shapes (the two TransferV2 samples sit at 6..8), or the loop
        // asserted over nothing.
        assert!(matches!(samples()[8], PosTransaction::FundedDeposit { .. }));
        assert!(matches!(samples()[11], PosTransaction::Withdraw { .. }));
    }

    /// The funded wire tags, frozen — the exact counterpart of the V2 pin in
    /// `transfer_v2_codec_survives_the_truncation_sweep`. 0x06 is the
    /// deduplicated transfer's and is re-pinned here as the CONTROL: the a7
    /// integration re-tagged the funded shapes to 0x07–0x09 precisely
    /// because 0x06 was already spoken for, and one byte carrying two live
    /// meanings on the wire is the 2026-08-08 fork class. Any change to any
    /// of these four bytes is a flag-day event, not an edit.
    #[test]
    fn the_funded_wire_tags_are_frozen() {
        let s = samples();
        assert!(matches!(s[6], PosTransaction::TransferV2 { .. }));
        assert_eq!(s[6].canonical_bytes()[0], 0x06, "TransferV2 keeps 0x06 (control)");
        assert!(matches!(s[8], PosTransaction::FundedDeposit { .. }));
        assert_eq!(s[8].canonical_bytes()[0], 0x07, "FundedDeposit is frozen at 0x07");
        assert!(matches!(s[10], PosTransaction::SignedExit { .. }));
        assert_eq!(s[10].canonical_bytes()[0], 0x08, "SignedExit is frozen at 0x08");
        assert!(matches!(s[11], PosTransaction::Withdraw { .. }));
        assert_eq!(s[11].canonical_bytes()[0], 0x09, "Withdraw is frozen at 0x09");
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

    /// The 0x06 codec under the full adversarial sweep: every strict prefix
    /// dies on `Truncated` (never zero-fills), and one extra byte dies on
    /// `TrailingBytes` — with the round-trip through the SAME sample as the
    /// control that the encoding is decodable at all, so the sweep is not
    /// vacuously failing on garbage.
    #[test]
    fn transfer_v2_codec_survives_the_truncation_sweep() {
        let tx = samples()
            .into_iter()
            .find(|t| matches!(t, PosTransaction::TransferV2 { keys, .. } if !keys.is_empty()))
            .expect("the corpus must carry a non-trivial V2 sample");
        let full = tx.canonical_bytes();
        assert_eq!(full[0], 0x06, "the V2 wire tag is frozen");

        // Control: the whole encoding decodes and re-encodes identically
        // (also covered by `canonical_bytes_round_trips` over the corpus).
        let back = PosTransaction::from_canonical_bytes(&full).unwrap();
        assert_eq!(back.canonical_bytes(), full);

        for cut in 0..full.len() {
            assert_eq!(
                PosTransaction::from_canonical_bytes(&full[..cut]),
                Err(TxDecodeError::Truncated),
                "a {cut}-byte prefix must fail, never zero-fill",
            );
        }
        let mut trailing = full.clone();
        trailing.push(0x00);
        assert_eq!(
            PosTransaction::from_canonical_bytes(&trailing),
            Err(TxDecodeError::TrailingBytes),
        );
    }

    /// The capacity claim in the `FundedDeposit` docs, pinned so it cannot go
    /// stale: with the measured PQ witness (3,749 B enveloped pubkey, 4,775 B
    /// hybrid signature — the first `samples()` funded deposit carries
    /// exactly those), a single-input, single-change funded deposit is
    /// ≈17.3 KB and the 262,144-byte block cap fits **15** of them. And the
    /// byte cap binds FIRST: fifteen deposits' gas — two hybrid verifies each
    /// (inputs + PoP) plus their bytes — stays far inside the gas limit, the
    /// same bytes-bind-first shape as the transfer analysis in fee_market.rs.
    #[test]
    fn fifteen_single_input_funded_deposits_fit_a_block() {
        let sample = &samples()[8];
        assert!(matches!(sample, PosTransaction::FundedDeposit { .. }));
        let len = sample.canonical_bytes().len() as u64;
        assert_eq!(len, 17_273, "the size the capacity docs quote");
        assert_eq!(
            fee_market::MAX_BLOCK_TX_BYTES / len,
            15,
            "the per-block deposit count in the FundedDeposit docs went stale"
        );
        let gas_each =
            fee_market::intrinsic_gas(fee_market::TxClass::Eutxo { inputs: 2 }, len);
        assert!(
            gas_each * 15 < fee_market::BLOCK_GAS_LIMIT / 4,
            "gas must not be the binding cap for funded deposits"
        );
        // Re-measured for the epoch-800 512 KiB cap (BLOCK_BYTES_V2): the
        // funded-stake gate can only arm at or after that flag day, so the
        // capacity that matters operationally is THIS one — 30 per block,
        // and the byte cap still binds first.
        assert_eq!(
            fee_market::MAX_BLOCK_TX_BYTES_V2 / len,
            30,
            "the post-epoch-800 per-block deposit count"
        );
        assert!(
            gas_each * 30 < fee_market::BLOCK_GAS_LIMIT / 2,
            "gas must not become the binding cap under the doubled byte cap"
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
        fn verify_with_key(&self, _pk: &[u8], _root: &[u8; 32], _sig: &[u8]) -> bool {
            true
        }
    }

    fn sat(bloch: u128) -> u128 {
        bloch * tokenomics_v4::SAT_PER_BLOCH
    }

    // ── A verifier that actually binds a signature to a key and a message ───
    //
    // `OkVerifier` says yes to everything, which is right for tests about
    // composition and ordering and *fatal* for tests about who may spend a
    // coin: under it, every signature test passes with the signature check
    // deleted. The transfer tests below therefore run against `ToyVerifier`,
    // whose `verify_with_key` accepts exactly one byte-string per (key,
    // message) pair.
    //
    // It is not cryptography and does not pretend to be — it is a function
    // with the one property the rules under test depend on: a signature is
    // valid for one key over one root and for nothing else. That is enough to
    // fail an implementation that checks the wrong root (say, one that
    // included the witnesses, or omitted the outputs), that passes the wrong
    // key, or that skips the check.
    //
    // The registry form (`verify`, used for proposer and attestation
    // signatures) stays permissive, so a transfer test dies on the transfer
    // and never on block plumbing.
    fn toy_sign(pubkey: &[u8], root: &[u8; 32]) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(b"toy-spend-signature");
        h.update((pubkey.len() as u32).to_le_bytes());
        h.update(pubkey);
        h.update(root);
        h.finalize().to_vec()
    }

    struct ToyVerifier;
    impl SignatureVerifier for ToyVerifier {
        fn verify(&self, _v: u32, _root: &[u8; 32], _sig: &[u8]) -> bool {
            true
        }
        fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            sig == toy_sign(pk, root).as_slice()
        }
    }

    /// A spender's "key". Length varies with the tag so two owners never share
    /// a script hash by accident.
    fn owner_key(tag: u8) -> Vec<u8> {
        vec![tag; 8 + tag as usize % 5]
    }

    /// The commitment an output carries to its owner: `SHA3-256(pubkey)`.
    fn script_of(pubkey: &[u8]) -> [u8; 32] {
        Sha3_256::digest(pubkey).into()
    }

    /// One opening-balance output: `value` satoshis locked to `owner`.
    fn opening(tag: u8, vout: u32, value: u64, owner: &[u8]) -> crate::state_root::EutxoEntry {
        crate::state_root::EutxoEntry {
            txid: [tag; 32],
            vout,
            value,
            script_hash: script_of(owner),
        }
    }

    /// Sign every input of a transfer under `owner`'s key.
    ///
    /// Separate from construction so a test that edits a signed field can put
    /// the signatures back. Without it, a test meaning to break conservation
    /// would break the signature as well and pass for the wrong reason — which
    /// is the failure mode that makes a negative test worthless.
    fn resign(tx: &mut PosTransaction, owner: &[u8]) {
        let root = tx.spend_signing_root();
        if let PosTransaction::Transfer { inputs, .. } = tx {
            for i in inputs.iter_mut() {
                i.signature = toy_sign(owner, &root);
            }
        }
    }

    /// A conserving transfer that spends `entries` whole and pays the
    /// remainder, after the market's fee, to `to_script`.
    ///
    /// The fee is computed with the **same** `fee_market::charge` call the
    /// transition makes, at the price the caller passes — never a literal. A
    /// fixture that hard-coded the fee would stop conserving the moment any
    /// gas constant moved, and the test would report a conservation bug that
    /// was really a stale number.
    ///
    /// `tx_bytes` is raised to the encoding's own length if the caller asked
    /// for less, so a test aiming at some other rule cannot trip the size
    /// floor by accident.
    fn transfer_spending(
        entries: &[crate::state_root::EutxoEntry],
        owner: &[u8],
        to_script: [u8; 32],
        tx_bytes: u64,
        tip: u128,
        price: u128,
    ) -> PosTransaction {
        let inputs: Vec<TransferInput> = entries
            .iter()
            .map(|e| TransferInput {
                txid: e.txid,
                vout: e.vout,
                pubkey: owner.to_vec(),
                // A placeholder of the right LENGTH: the real signature goes
                // in below, and the encoding's size must not change under it.
                signature: vec![0u8; 32],
            })
            .collect();
        let spent: u128 = entries.iter().map(|e| e.value as u128).sum();

        // Size first: the charge depends on tx_bytes, so the floor has to be
        // resolved before the fee, and the encoding's length does not depend
        // on the VALUE of tx_bytes (it is a fixed-width field).
        let probe = PosTransaction::Transfer {
            inputs: inputs.clone(),
            outputs: vec![TransferOutput { value: 0, script_hash: to_script }],
            tx_bytes,
            tip_millisat_per_gas: tip,
        };
        let tx_bytes = tx_bytes.max(probe.canonical_bytes().len() as u64);

        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: inputs.len() as u32 },
            tx_bytes,
            price,
            tip,
        );
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        assert!(spent >= fee, "fixture underfunded: {spent} sat cannot pay a {fee} sat fee");
        let change = (spent - fee) as u64;

        let mut tx = PosTransaction::Transfer {
            inputs,
            outputs: vec![TransferOutput { value: change, script_hash: to_script }],
            tx_bytes,
            tip_millisat_per_gas: tip,
        };
        resign(&mut tx, owner);
        tx
    }

    /// [`resign`] for the V2 shape: sign once **per witness-table entry**,
    /// each under its own key — the construct/sign split the repo requires so
    /// a negative test cannot pass on a stale signature.
    fn resign_v2(tx: &mut PosTransaction) {
        let root = tx.spend_signing_root();
        if let PosTransaction::TransferV2 { keys, .. } = tx {
            for k in keys.iter_mut() {
                k.signature = toy_sign(&k.pubkey.clone(), &root);
            }
        }
    }

    /// A conserving `TransferV2` with an explicit witness table and an
    /// explicit key assignment per input — explicit, because the discipline
    /// tests need to build tables the honest constructor never would
    /// (duplicates, unreferenced entries, wrong indices).
    ///
    /// The fee comes from the **same** `fee_market::charge` call the
    /// transition makes, with the class term `keys.len()` — the table length,
    /// exactly as `apply_transfer_v2` derives it. Same size-floor handling as
    /// [`transfer_spending`].
    fn transfer_v2_raw(
        entries: &[crate::state_root::EutxoEntry],
        keys: &[&[u8]],
        key_of: &[u32],
        to_script: [u8; 32],
        tx_bytes: u64,
        tip: u128,
        price: u128,
    ) -> PosTransaction {
        assert_eq!(entries.len(), key_of.len(), "fixture: one key index per input");
        let table: Vec<WitnessKey> = keys
            .iter()
            .map(|k| WitnessKey {
                pubkey: k.to_vec(),
                // Right LENGTH, wrong bytes: the real signature goes in below.
                signature: vec![0u8; 32],
            })
            .collect();
        let inputs: Vec<TransferInputV2> = entries
            .iter()
            .zip(key_of)
            .map(|(e, ki)| TransferInputV2 { txid: e.txid, vout: e.vout, key_index: *ki })
            .collect();
        let spent: u128 = entries.iter().map(|e| e.value as u128).sum();

        let probe = PosTransaction::TransferV2 {
            keys: table.clone(),
            inputs: inputs.clone(),
            outputs: vec![TransferOutput { value: 0, script_hash: to_script }],
            tx_bytes,
            tip_millisat_per_gas: tip,
        };
        let tx_bytes = tx_bytes.max(probe.canonical_bytes().len() as u64);

        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: table.len() as u32 },
            tx_bytes,
            price,
            tip,
        );
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        assert!(spent >= fee, "fixture underfunded: {spent} sat cannot pay a {fee} sat fee");
        let change = (spent - fee) as u64;

        let mut tx = PosTransaction::TransferV2 {
            keys: table,
            inputs,
            outputs: vec![TransferOutput { value: change, script_hash: to_script }],
            tx_bytes,
            tip_millisat_per_gas: tip,
        };
        resign_v2(&mut tx);
        tx
    }

    /// The V2 re-encoding of a signed V1 transfer: the witness of each
    /// input's first occurrence moves into the table — the SAME pubkey and
    /// the SAME signature bytes, deduplicated, nothing re-signed — and the
    /// table is then put into the one consensus order by
    /// [`canonicalize_witness_table`] (first-occurrence order would be
    /// [`TransferReject::WitnessTableNotCanonical`] whenever the V1 inputs
    /// happen to reveal keys out of byte order). This is the operation a
    /// relay or wallet performs after the flag day, and the equivalence
    /// tests are about proving it changes no verified fact.
    fn v2_twin_of(v1: &PosTransaction) -> PosTransaction {
        let PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } = v1
        else {
            panic!("v2_twin_of takes a V1 transfer");
        };
        let mut keys: Vec<WitnessKey> = Vec::new();
        let mut v2_inputs = Vec::new();
        for i in inputs {
            let idx = match keys.iter().position(|k| k.pubkey == i.pubkey) {
                Some(idx) => idx,
                None => {
                    keys.push(WitnessKey {
                        pubkey: i.pubkey.clone(),
                        signature: i.signature.clone(),
                    });
                    keys.len() - 1
                }
            };
            v2_inputs.push(TransferInputV2 {
                txid: i.txid,
                vout: i.vout,
                key_index: idx as u32,
            });
        }
        canonicalize_witness_table(&mut keys, &mut v2_inputs);
        PosTransaction::TransferV2 {
            keys,
            inputs: v2_inputs,
            outputs: outputs.clone(),
            tx_bytes: *tx_bytes,
            tip_millisat_per_gas: *tip_millisat_per_gas,
        }
    }

    /// Rejects exactly the marker byte-string `b"forged"`, accepts anything
    /// else — enough to make one signature of an evidence pair verifiably
    /// bad while every other signature in the block still passes.
    struct MarkerVerifier;
    impl SignatureVerifier for MarkerVerifier {
        fn verify(&self, _v: u32, _root: &[u8; 32], sig: &[u8]) -> bool {
            sig != b"forged"
        }
        fn verify_with_key(&self, _pk: &[u8], _root: &[u8; 32], sig: &[u8]) -> bool {
            sig != b"forged"
        }
    }

    fn setup(n: u32) -> (Transition<OkVerifier>, CommittedState, Vec<RandaoChain>) {
        setup_with(n, OkVerifier, &[])
    }

    /// `setup`, plus an opening ledger — the fixture every transfer test needs,
    /// because a transfer can only move coins that already exist. Paired with
    /// [`ToyVerifier`] so spend authorisation is actually checked.
    fn setup_funded(
        n: u32,
        opening_balances: &[crate::state_root::EutxoEntry],
    ) -> (Transition<ToyVerifier>, CommittedState, Vec<RandaoChain>) {
        setup_with(n, ToyVerifier, opening_balances)
    }

    fn setup_with<V: SignatureVerifier>(
        n: u32,
        verifier: V,
        opening_balances: &[crate::state_root::EutxoEntry],
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
            opening_balances,
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

    /// [`build_block`] with the funded-staking flag day passed in — the
    /// producer half of `apply_block_gated`. Both halves must roll the
    /// boundary with the SAME gate or the builder stamps a state root the
    /// validator will not reproduce, which is exactly the divergence the
    /// gated pair exists to make testable.
    fn build_block_gated<V: SignatureVerifier>(
        t: &Transition<V>,
        pre: &CommittedState,
        slot: u64,
        atts: &[Attestation],
        txs: &[PosTransaction],
        chains: &mut [RandaoChain],
        gate: u64,
    ) -> ProposalEnvelope {
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
            .compute_post_state_gated(pre, &probe, atts, txs, gate)
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
        assert_eq!(
            probe.apply_transaction(
                &dup,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &OkVerifier
            ),
            Err(TxReject::StakingRule)
        );
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
        assert_eq!(
            probe.apply_transaction(
                &exit,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &OkVerifier
            ),
            Err(TxReject::StakingRule)
        );
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
        let owner = owner_key(0x31);
        let coin = opening(0x71, 0, 100_000_000, &owner);
        let (t, g, mut chains) = setup_funded(4, &[coin.clone()]);
        let tx = transfer_spending(
            std::slice::from_ref(&coin),
            &owner,
            script_of(&owner_key(0x32)),
            512,
            5,
            g.next_base_fee(),
        );
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
        let owner = owner_key(0x33);
        let to = script_of(&owner_key(0x34));
        // Four funded coins: one for the small transfer, four for the large —
        // the input count is now the REAL list length, so "four verifies" has
        // to mean four outputs actually being spent.
        let coins: Vec<_> =
            (0..4u32).map(|i| opening(0x72, i, 100_000_000, &owner)).collect();

        let (t, g, mut chains) = setup_funded(4, &coins);
        let small = transfer_spending(&coins[..1], &owner, to, 256, 0, g.next_base_fee());
        let b_small = build_block(&t, &g, 1, &[], std::slice::from_ref(&small), &mut chains);
        let s_small = t.apply_block(&g, &b_small, &[], std::slice::from_ref(&small)).unwrap();

        let (t2, g2, mut chains2) = setup_funded(4, &coins);
        let large = transfer_spending(&coins, &owner, to, 4_096, 0, g2.next_base_fee());
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
        let owner = owner_key(0x35);
        let coin = opening(0x73, 0, 100_000_000, &owner);
        let (t, g, mut chains) = setup_funded(4, &[coin.clone()]);
        // A block at the byte target: the controller's neutral point on the
        // byte axis, but well under target on gas — so the max-utilisation
        // rule prices the byte axis and leaves the floor alone (it cannot
        // fall below it anyway).
        let tx = transfer_spending(
            std::slice::from_ref(&coin),
            &owner,
            script_of(&owner_key(0x36)),
            8_192,
            0,
            g.next_base_fee(),
        );
        let b1 = build_block(&t, &g, 1, &[], std::slice::from_ref(&tx), &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], std::slice::from_ref(&tx)).unwrap();

        // The next block's price is the controller over what s1 committed —
        // and nothing else. Same function, same inputs, same answer.
        assert_eq!(
            s1.next_base_fee(),
            fee_market::next_base_fee(
                s1.base_fee_millisat_per_gas(),
                fee_market::BlockUsage { gas_used: s1.block_gas_used, tx_bytes: s1.block_tx_bytes },
                s1.epoch,
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
    ///
    /// # What the size floor changed here, stated rather than hidden
    ///
    /// The gas half used to be built as "many inputs, few bytes" — a transfer
    /// asserting thousands of inputs while declaring 128 bytes. That shape is
    /// no longer expressible, and its disappearance is the point of
    /// [`TransferReject::UnderdeclaredSize`]: an input now carries a real
    /// witness, and a transaction may not declare a size below its own
    /// encoding. With that floor in place, `inputs × HYBRID_VERIFY_GAS` cannot
    /// outrun the byte cap for the eUTXO class — bytes bind first, exactly as
    /// `fee_market`'s own `bytes_bind_before_gas` says they do.
    ///
    /// So the gas cap is reached the only way it still can be: by
    /// **over**-declaring size, which is allowed (you pay for what you
    /// declare). The gas check runs before the byte check in the frozen order,
    /// which is what makes it observable. Honest consequence: for today's
    /// transaction set the gas cap is a backstop for a class that does not
    /// exist yet (`TxClass::Shielded`, `EvmPq`) rather than a live constraint
    /// on transfers — and a backstop that is never exercised is precisely the
    /// kind of check that rots, which is why it is still tested.
    /// A2: the byte cap must come from the BLOCK's own epoch, not from a
    /// constant and not from node-local state.
    ///
    /// Without this test the whole flag day is unpinned: reverting the gate at
    /// `compute_post_state` to the raw `MAX_BLOCK_TX_BYTES` survives every
    /// other test in this crate, and that revert is exactly the shape of the
    /// 2026-08-08 `expected_bits` fork — a rule read from somewhere other than
    /// the block being judged. It is not hypothetical: that revert reached
    /// this branch once, and this test is what caught it.
    #[test]
    fn the_block_cap_gate_reads_the_epoch_from_the_blocks_own_header() {
        const ACT: u64 = crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH;
        let Some(first_v2_slot) = ACT.checked_mul(crate::params::SLOTS_PER_EPOCH) else {
            // Inert: no header slot can name the V2 era at all, which IS the
            // transition-level statement of inertness. Nothing to exercise.
            return;
        };

        // A payload over the V1 cap and under the V2 cap. The ONLY thing that
        // can decide it is which era the block is in.
        let over_v1 = fee_market::MAX_BLOCK_TX_BYTES + 1;
        assert!(over_v1 <= fee_market::MAX_BLOCK_TX_BYTES_V2);

        let owner = owner_key(0x41);
        let to = script_of(&owner_key(0x42));

        // In the V2 era it is accepted.
        let c1 = opening(0x81, 0, 21_000_000_000_000_000, &owner);
        let (t, g, mut chains) = setup_funded(4, std::slice::from_ref(&c1));
        let fat = transfer_spending(
            std::slice::from_ref(&c1), &owner, to, over_v1, 0, g.next_base_fee(),
        );
        let b = build_block(&t, &g, first_v2_slot, &[], std::slice::from_ref(&fat), &mut chains);
        assert!(
            t.apply_block(&g, &b, &[], std::slice::from_ref(&fat)).is_ok(),
            "a block over the V1 cap must be VALID once the flag day has passed"
        );

        // THE CONTROL: the same payload, same size, in the V1 era — refused.
        // Only the era differs between the two halves, so the verdict is about
        // the era and nothing else.
        let c2 = opening(0x82, 0, 21_000_000_000_000_000, &owner);
        let (t2, g2, mut chains2) = setup_funded(4, std::slice::from_ref(&c2));
        let fat2 = transfer_spending(
            std::slice::from_ref(&c2), &owner, to, over_v1, 0, g2.next_base_fee(),
        );
        let env2 = probe_env(&g2, 1, std::slice::from_ref(&fat2), &mut chains2);
        assert_eq!(
            t2.compute_post_state(&g2, &env2, &[], std::slice::from_ref(&fat2)).unwrap_err(),
            TransitionError::BlockByteLimitExceeded,
            "the same block one epoch earlier must still be over the cap"
        );
    }

    /// A2, the other half: the price the boundary block CHARGES must come
    /// from the block's epoch, not from the parent state's.
    ///
    /// `compute_post_state` prices from `pre`, which has not rolled yet, so on
    /// the first block of the activation epoch `pre.epoch` is still the old
    /// era. Pricing from it would charge that block against a 131,072 target
    /// under a 524,288 cap — a legal half-full block read as congested. This
    /// asserts on the price the post state COMMITS, because asserting on the
    /// two helper methods instead leaves the wiring free: reverting the call
    /// to `pre.next_base_fee()` survives a test that only compares helpers.
    #[test]
    fn the_boundary_blocks_price_comes_from_the_block_epoch_not_the_parent() {
        const ACT: u64 = crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH;
        let Some(first_v2_slot) = ACT.checked_mul(crate::params::SLOTS_PER_EPOCH) else {
            return;
        };

        let owner = owner_key(0x43);
        let to = script_of(&owner_key(0x44));
        let c = opening(0x83, 0, 21_000_000_000_000_000, &owner);
        let (t, g, mut chains) = setup_funded(4, std::slice::from_ref(&c));

        // The parent: the last block of the old era, saturating the V1 cap.
        // 256 KiB is twice the old target and exactly the new one, so it is
        // the single payload that prices differently in the two eras.
        let saturating = transfer_spending(
            std::slice::from_ref(&c), &owner, to,
            fee_market::MAX_BLOCK_TX_BYTES, 0, g.next_base_fee(),
        );
        let b1 = build_block(
            &t, &g, first_v2_slot - 1, &[], std::slice::from_ref(&saturating), &mut chains,
        );
        let s1 = t
            .apply_block(&g, &b1, &[], std::slice::from_ref(&saturating))
            .expect("a block at exactly the V1 cap is valid in the old era");
        assert_eq!(s1.epoch, ACT - 1, "parent must sit one epoch below the flag day");
        assert_eq!(s1.block_tx_bytes, fee_market::MAX_BLOCK_TX_BYTES);

        // The two candidate prices really differ — otherwise this proves
        // nothing. `next_base_fee()` is the old-era answer, because s1's own
        // epoch is the old era; that is exactly the value the wiring must NOT
        // use for a block in the new one.
        let old_era_price = s1.next_base_fee();
        let new_era_price = s1.next_base_fee_at(ACT);
        assert!(old_era_price > s1.base_fee_millisat_per_gas(), "old era: congested");
        assert_eq!(new_era_price, s1.base_fee_millisat_per_gas(), "new era: at target");
        assert_ne!(old_era_price, new_era_price);

        // The boundary block itself. What it COMMITS is the price it charged.
        let b2 = build_block(&t, &s1, first_v2_slot, &[], &[], &mut chains);
        let s2 = t.apply_block(&s1, &b2, &[], &[]).expect("boundary block must apply");
        assert_eq!(
            s2.base_fee_millisat_per_gas(),
            new_era_price,
            "the boundary block must be priced against the epoch it lives in"
        );
    }

    #[test]
    fn the_two_block_caps_are_enforced() {
        let owner = owner_key(0x37);
        let to = script_of(&owner_key(0x38));
        // Funded well above any fee these blocks can charge: the caps are what
        // must reject them, not an unfundable transfer.
        let coin = |tag: u8| opening(tag, 0, 21_000_000_000_000_000, &owner);

        // Bytes bind first for signature-heavy traffic, so the byte cap is
        // reachable with a transaction the gas cap still admits.
        let c1 = coin(0x74);
        let (t, g, mut chains) = setup_funded(4, &[c1.clone()]);
        let fat = transfer_spending(
            std::slice::from_ref(&c1),
            &owner,
            to,
            fee_market::MAX_BLOCK_TX_BYTES + 1,
            0,
            g.next_base_fee(),
        );
        let env = probe_env(&g, 1, std::slice::from_ref(&fat), &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&fat)).unwrap_err(),
            TransitionError::BlockByteLimitExceeded,
        );

        // The gas cap: a declared size whose byte term alone exceeds the gas
        // limit. Derived from the constants, so a change to either moves this
        // with it.
        let c2 = coin(0x75);
        let (t2, g2, mut chains2) = setup_funded(4, &[c2.clone()]);
        let over_gas = fee_market::BLOCK_GAS_LIMIT / fee_market::GAS_PER_BYTE + 1;
        let heavy = transfer_spending(
            std::slice::from_ref(&c2),
            &owner,
            to,
            over_gas,
            0,
            g2.next_base_fee(),
        );
        let env2 = probe_env(&g2, 1, std::slice::from_ref(&heavy), &mut chains2);
        assert_eq!(
            t2.compute_post_state(&g2, &env2, &[], std::slice::from_ref(&heavy)).unwrap_err(),
            TransitionError::BlockGasLimitExceeded,
        );

        // And a block at exactly the byte cap is VALID — an off-by-one here
        // would make the cap unreachable and the byte axis dead.
        let c3 = coin(0x76);
        let (t3, g3, mut chains3) = setup_funded(4, &[c3.clone()]);
        let at_cap = transfer_spending(
            std::slice::from_ref(&c3),
            &owner,
            to,
            fee_market::MAX_BLOCK_TX_BYTES,
            0,
            g3.next_base_fee(),
        );
        let b = build_block(&t3, &g3, 1, &[], std::slice::from_ref(&at_cap), &mut chains3);
        assert!(t3.apply_block(&g3, &b, &[], std::slice::from_ref(&at_cap)).is_ok());
    }

    /// The shape the gas half of the test above can no longer take: a transfer
    /// that claims many inputs while declaring almost no bytes.
    ///
    /// Pinned as its own test because it is a **security** property, not a
    /// test-construction detail. Without the size floor, one block could carry
    /// thousands of ≈8.4 KB witnesses (a hybrid key plus a hybrid signature
    /// per input) while contributing ~nothing to the byte cap the whole gossip
    /// budget rests on — every node made to download and store tens of
    /// megabytes for the price of a few hundred bytes.
    #[test]
    fn a_transfer_cannot_declare_fewer_bytes_than_it_carries() {
        let owner = owner_key(0x39);
        let coins: Vec<_> = (0..8u32).map(|i| opening(0x77, i, 1_000_000, &owner)).collect();
        let (_t, g, _chains) = setup_funded(4, &coins);

        let mut tx = transfer_spending(
            &coins,
            &owner,
            script_of(&owner_key(0x3A)),
            0, // asks for zero; the helper raises it to the encoding's length
            0,
            g.next_base_fee(),
        );
        let PosTransaction::Transfer { tx_bytes, .. } = &tx else { unreachable!() };
        let honest = *tx_bytes;
        assert!(honest > 128, "fixture premise: real witnesses cost real bytes");

        // One byte short of honest is already refused — and the signatures are
        // restored, so the reject is the size rule and not a stale witness.
        if let PosTransaction::Transfer { tx_bytes, .. } = &mut tx {
            *tx_bytes = honest - 1;
        }
        resign(&mut tx, &owner);
        let mut probe = g.clone();
        assert_eq!(
            probe.apply_transfer(&tx, g.next_base_fee(), &ToyVerifier),
            Err(TransferReject::UnderdeclaredSize),
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // The transfer moves value — the rules that decide who owns what
    // ────────────────────────────────────────────────────────────────────────
    //
    // Until this wave `Transfer` carried `{ inputs: u32, tx_bytes, tip }`:
    // three gas terms and no sender, recipient or amount. The committed state
    // held the opening ledger and the state root committed to it, and no
    // transaction could take a satoshi out of it. These tests are the proof
    // that it can now, and — far more important — the proof of everything that
    // still cannot happen.
    //
    // Each negative test below was run against a deliberately sabotaged
    // implementation and observed to FAIL; a negative test that passes with
    // its rule deleted proves nothing at all. The sabotage results are
    // recorded on each test.

    /// **Value moves, and it moves exactly where it was sent.**
    ///
    /// The set loses the spent outputs and gains the created ones, the
    /// amounts are what the transaction said, the new outputs are locked to
    /// the recipient, and the difference between what went in and what came
    /// out is the fee — not a satoshi more or less.
    ///
    /// Sabotage: skipping the removal loop leaves the spent coin in the set
    /// (`the spent output is still in the set`); skipping the insert loop
    /// drops the payment (`the recipient was not paid`).
    #[test]
    fn a_transfer_moves_value_and_the_root_follows() {
        let alice = owner_key(0x50);
        let bob_script = script_of(&owner_key(0x51));
        let coin_a = opening(0x80, 0, 60_000_000, &alice);
        let coin_b = opening(0x80, 1, 40_000_000, &alice);
        let (t, g, mut chains) = setup_funded(4, &[coin_a.clone(), coin_b.clone()]);

        let price = g.next_base_fee();
        let tx = transfer_spending(&[coin_a.clone(), coin_b.clone()], &alice, bob_script, 512, 2, price);
        let PosTransaction::Transfer { outputs, .. } = &tx else { unreachable!() };
        let paid = outputs[0].value;
        let txid = tx.txid();

        let b = build_block(&t, &g, 1, &[], std::slice::from_ref(&tx), &mut chains);
        let s1 = t.apply_block(&g, &b, &[], std::slice::from_ref(&tx)).unwrap();

        // The inputs are gone.
        assert!(
            !s1.eutxos.contains_key(&(coin_a.txid, coin_a.vout)),
            "the spent output is still in the set"
        );
        assert!(!s1.eutxos.contains_key(&(coin_b.txid, coin_b.vout)));
        // The output exists, at the derived key, with the right value and the
        // recipient's lock.
        let created = s1.eutxos.get(&(txid, 0)).expect("the recipient was not paid");
        assert_eq!(created.value, paid);
        assert_eq!(created.script_hash, bob_script);
        assert_eq!(created.txid, txid, "the entry must key itself consistently");
        assert_eq!(created.vout, 0);
        assert_eq!(s1.eutxos.len(), 1, "two spent, one created");

        // Conservation, checked from the outside: what left the set minus what
        // entered it is exactly the fee the block charged.
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 2 },
            512,
            price,
            2,
        );
        let before: u128 = (coin_a.value as u128) + (coin_b.value as u128);
        let after: u128 = s1.eutxos.values().map(|e| e.value as u128).sum();
        assert_eq!(
            before - after,
            charge.base_fee_sat + charge.priority_fee_sat,
            "the coins that left the set are not the fee that was charged"
        );

        // And the ledger is under the state root. Isolated: the post-state with
        // its unspent set put back must root differently, so this cannot pass
        // on the strength of some other field having moved.
        let mut reverted = s1.clone();
        reverted.eutxos = g.eutxos.clone();
        assert_ne!(
            s1.compute_root(),
            reverted.compute_root(),
            "the unspent set is not bound by the state root"
        );
    }

    /// **Conservation.** A transfer whose outputs plus fee do not equal its
    /// inputs is refused, and refused with a reason of its own.
    ///
    /// Both directions matter and both are checked. Paying out more than was
    /// spent is a mint outside the emission schedule — the one thing the
    /// 100-billion cap exists to make impossible. Paying out less is not
    /// generosity: the surplus would vanish from the accounted supply with
    /// nothing recording it, and "value quietly disappeared" is how a ledger
    /// stops being auditable.
    ///
    /// Sabotage: replacing the equality with `spent_value >= created + fee`
    /// makes the underpaying half pass; deleting the check entirely makes both
    /// halves pass and the overpay case actually MINTS — the post-state's
    /// unspent total rises above the opening balance.
    #[test]
    fn a_transfer_that_does_not_conserve_value_is_refused() {
        let alice = owner_key(0x52);
        let to = script_of(&owner_key(0x53));
        let coin = opening(0x81, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();

        let honest = transfer_spending(std::slice::from_ref(&coin), &alice, to, 512, 1, price);
        // Control: the honest transfer is accepted, so the two mutants below
        // fail on the amount and on nothing else.
        assert!(g.clone().apply_transfer(&honest, price, &ToyVerifier).is_ok());

        for delta in [1i64, -1] {
            let mut bad = honest.clone();
            if let PosTransaction::Transfer { outputs, .. } = &mut bad {
                outputs[0].value = outputs[0].value.wrapping_add_signed(delta);
            }
            // Re-signed: the output value is inside the signing root, so an
            // edited transfer carries a stale signature. Without this the test
            // would pass on `BadSignature` and never reach conservation.
            resign(&mut bad, &alice);
            assert_eq!(
                g.clone().apply_transfer(&bad, price, &ToyVerifier),
                Err(TransferReject::ValueNotConserved),
                "an output {delta} satoshi off must be refused",
            );
        }

        // And through the block seam, so the named reason survives to the
        // caller rather than being flattened into `Transaction(i)`.
        let mut mint = honest.clone();
        if let PosTransaction::Transfer { outputs, .. } = &mut mint {
            outputs[0].value += 1_000_000;
        }
        resign(&mut mint, &alice);
        let (t, g2, mut chains) = setup_funded(4, &[coin]);
        let env = probe_env(&g2, 1, std::slice::from_ref(&mint), &mut chains);
        assert_eq!(
            t.compute_post_state(&g2, &env, &[], std::slice::from_ref(&mint)).unwrap_err(),
            TransitionError::Transfer(0, TransferReject::ValueNotConserved),
        );
    }

    /// **Double spend.** The same output spent twice in one block is refused —
    /// whether the two spends are two transactions or two inputs of one.
    ///
    /// The in-block case is the one that matters: a node that only checked the
    /// *parent* state's unspent set would accept both, because both look
    /// fundable against the state the block started from. The set has to be
    /// consumed as the block is applied, which is what makes the second spend
    /// find nothing.
    ///
    /// Sabotage: moving the removal out of `apply_transfer` and into a pass
    /// after the block's transactions are all applied makes the two-transaction
    /// half pass — and the block then spends 50,000,000 satoshis twice while
    /// paying out both times. Deleting the `seen` set makes the one-transaction
    /// half pass, with the same doubling inside a single transfer.
    #[test]
    fn spending_one_output_twice_in_a_block_is_refused() {
        let alice = owner_key(0x54);
        let to = script_of(&owner_key(0x55));
        let coin = opening(0x82, 0, 50_000_000, &alice);

        // (a) Two transactions, same outpoint. They cannot be byte-identical
        //     or the mempool/body would hold one — the tip differs, which
        //     changes the signing root and so the txid too. Two genuinely
        //     distinct transactions, both spending the same coin.
        let (t, g, mut chains) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();
        let first = transfer_spending(std::slice::from_ref(&coin), &alice, to, 512, 1, price);
        let second = transfer_spending(std::slice::from_ref(&coin), &alice, to, 512, 2, price);
        assert_ne!(first, second, "fixture premise: two distinct transactions");
        let both = [first.clone(), second];
        let env = probe_env(&g, 1, &both, &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], &both).unwrap_err(),
            TransitionError::Transfer(1, TransferReject::UnknownInput),
            "the second spend must find the coin already gone",
        );
        // The first one alone is fine — so the reject above is the double
        // spend, not something wrong with the transaction itself. A fresh
        // fixture, because `probe_env` already consumed the proposer's reveal
        // and a RANDAO chain position is spendable exactly once.
        let (t1, g1, mut chains1) = setup_funded(4, &[coin.clone()]);
        let solo = build_block(&t1, &g1, 1, &[], std::slice::from_ref(&first), &mut chains1);
        assert!(t1.apply_block(&g1, &solo, &[], std::slice::from_ref(&first)).is_ok());

        // (b) One transaction naming the same outpoint twice. Caught by its
        //     own rule: the set would silently deduplicate it, and the
        //     transfer would appear to spend 100,000,000 satoshis of a
        //     50,000,000-satoshi coin.
        let (_t2, g2, _c2) = setup_funded(4, &[coin.clone()]);
        let doubled = transfer_spending(&[coin.clone(), coin.clone()], &alice, to, 512, 1, price);
        assert_eq!(
            g2.clone().apply_transfer(&doubled, price, &ToyVerifier),
            Err(TransferReject::DuplicateInput),
        );
    }

    /// **An input that does not exist is refused** — and so is one that exists
    /// but is not the one being claimed.
    ///
    /// Without this a transfer could conjure its own funding: name any
    /// outpoint, pay yourself the amount, and the only thing standing between
    /// an attacker and arbitrary coins would be the fee.
    ///
    /// Sabotage: replacing the `get` with a default 0-value entry turns the
    /// reject into `ValueNotConserved`, and this assertion fails on the
    /// reason — which is the point of naming the reasons.
    #[test]
    fn an_input_that_is_not_in_the_set_is_refused() {
        let alice = owner_key(0x56);
        let to = script_of(&owner_key(0x57));
        let real = opening(0x83, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[real.clone()]);
        let price = g.next_base_fee();

        // A txid nobody ever created. Correctly signed and internally
        // conserving, so the only thing wrong with it is that the coin it
        // spends does not exist.
        let ghost = crate::state_root::EutxoEntry { txid: [0xEE; 32], ..real.clone() };
        let tx = transfer_spending(std::slice::from_ref(&ghost), &alice, to, 512, 1, price);
        assert_eq!(
            g.clone().apply_transfer(&tx, price, &ToyVerifier),
            Err(TransferReject::UnknownInput),
        );

        // The right txid, the wrong index: an off-by-one in the outpoint key
        // would make these two the same output.
        let wrong_vout = crate::state_root::EutxoEntry { vout: 1, ..real.clone() };
        let tx2 =
            transfer_spending(std::slice::from_ref(&wrong_vout), &alice, to, 512, 1, price);
        assert_eq!(
            g.clone().apply_transfer(&tx2, price, &ToyVerifier),
            Err(TransferReject::UnknownInput),
        );

        // Control: the real outpoint is spendable, so the two rejects are
        // about the outpoint and not about the fixture.
        let good = transfer_spending(std::slice::from_ref(&real), &alice, to, 512, 1, price);
        assert!(g.clone().apply_transfer(&good, price, &ToyVerifier).is_ok());
    }

    /// **The test that stops anyone spending anyone else's coins.**
    ///
    /// Three ways to fail authorisation, because they are three different
    /// mistakes and only one of them is caught by a naive implementation:
    ///
    /// 1. the right key, a signature that is not over this transfer — a
    ///    signature lifted from another transaction, which is what "the root
    ///    must cover the payment" is for;
    /// 2. an attacker's own key, with a perfectly valid signature under it —
    ///    valid crypto, wrong owner. Caught by the `script_hash` check, and by
    ///    nothing else; an implementation that only verified the signature
    ///    would hand the coin over;
    /// 3. the victim's key with the attacker's signature — the ordinary forgery.
    ///
    /// Sabotage: deleting the `verify_with_key` call makes (1) and (3) pass;
    /// deleting the `script_hash` comparison makes (2) pass, and the attacker
    /// walks off with a coin they never owned. Both were observed.
    #[test]
    fn a_transfer_with_a_bad_signature_is_refused() {
        let alice = owner_key(0x58);
        let mallory = owner_key(0x59);
        let to = script_of(&owner_key(0x5A));
        let coin = opening(0x84, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();

        let honest = transfer_spending(std::slice::from_ref(&coin), &alice, to, 512, 1, price);
        assert!(
            g.clone().apply_transfer(&honest, price, &ToyVerifier).is_ok(),
            "control: the owner's own signature must be accepted"
        );

        // (1) Alice's key, but a signature over a DIFFERENT transfer. The
        //     bytes are a real signature; they just say something else.
        let other = transfer_spending(std::slice::from_ref(&coin), &alice, to, 512, 9, price);
        let stolen_sig = match &other {
            PosTransaction::Transfer { inputs, .. } => inputs[0].signature.clone(),
            _ => unreachable!(),
        };
        let mut replayed = honest.clone();
        if let PosTransaction::Transfer { inputs, .. } = &mut replayed {
            inputs[0].signature = stolen_sig;
        }
        assert_eq!(
            g.clone().apply_transfer(&replayed, price, &ToyVerifier),
            Err(TransferReject::BadSignature),
            "a signature over another transfer must not authorise this one",
        );

        // (2) Mallory signs, with her own key, flawlessly — over exactly this
        //     transfer. The signature verifies; the key is not the one the
        //     output committed to.
        let mut impersonated = honest.clone();
        if let PosTransaction::Transfer { inputs, .. } = &mut impersonated {
            inputs[0].pubkey = mallory.clone();
        }
        resign(&mut impersonated, &mallory);
        assert!(
            ToyVerifier.verify_with_key(
                &mallory,
                &impersonated.spend_signing_root(),
                match &impersonated {
                    PosTransaction::Transfer { inputs, .. } => &inputs[0].signature,
                    _ => unreachable!(),
                },
            ),
            "fixture premise: Mallory's signature really is valid under Mallory's key"
        );
        assert_eq!(
            g.clone().apply_transfer(&impersonated, price, &ToyVerifier),
            Err(TransferReject::ScriptMismatch),
            "a valid signature under the wrong key must not move Alice's coin",
        );

        // (3) Alice's key, Mallory's signature: the plain forgery.
        let root = honest.spend_signing_root();
        let mut forged = honest.clone();
        if let PosTransaction::Transfer { inputs, .. } = &mut forged {
            inputs[0].signature = toy_sign(&mallory, &root);
        }
        assert_eq!(
            g.clone().apply_transfer(&forged, price, &ToyVerifier),
            Err(TransferReject::BadSignature),
        );

        // Nothing above moved a satoshi: every reject left the set untouched.
        let mut probe = g.clone();
        for bad in [&replayed, &impersonated, &forged] {
            let _ = probe.apply_transfer(bad, price, &ToyVerifier);
        }
        assert_eq!(probe.eutxos, g.eutxos, "a refused transfer must not touch the set");
    }

    /// **A signed transfer in flight cannot be redirected, re-priced, or
    /// re-pointed at a different coin.**
    ///
    /// The end-to-end statement of what the signing root is for. Anyone who
    /// handles a transfer between the sender and the block — a peer, a relay,
    /// the proposer itself — sees the whole transaction and could rewrite any
    /// field in it. Each rewrite below is one they would want to make, and each
    /// must invalidate the signature that was already produced.
    ///
    /// Sabotage: dropping the outputs from the signing-root preimage makes the
    /// *recipient* and *amount* cases pass — a proposer could then reroute
    /// every payment in its own block to itself, with the sender's genuine
    /// signature still attached.
    #[test]
    fn a_signed_transfer_cannot_be_rewritten_in_flight() {
        let alice = owner_key(0x5B);
        let bob = script_of(&owner_key(0x5C));
        let mallory_script = script_of(&owner_key(0x5D));
        let coin = opening(0x85, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();
        let signed = transfer_spending(std::slice::from_ref(&coin), &alice, bob, 512, 1, price);
        assert!(g.clone().apply_transfer(&signed, price, &ToyVerifier).is_ok());

        // Each tamper keeps the signature Alice actually produced.
        let mut tampered: Vec<(&str, PosTransaction)> = Vec::new();
        let mut edit = signed.clone();
        if let PosTransaction::Transfer { outputs, .. } = &mut edit {
            outputs[0].script_hash = mallory_script;
        }
        tampered.push(("the payment redirected to another recipient", edit));
        let mut edit = signed.clone();
        if let PosTransaction::Transfer { outputs, .. } = &mut edit {
            outputs[0].value -= 1;
        }
        tampered.push(("the amount reduced", edit));
        let mut edit = signed.clone();
        if let PosTransaction::Transfer { tip_millisat_per_gas, .. } = &mut edit {
            *tip_millisat_per_gas += 1;
        }
        tampered.push(("the tip raised out of the sender's own coins", edit));
        let mut edit = signed.clone();
        if let PosTransaction::Transfer { tx_bytes, .. } = &mut edit {
            *tx_bytes += 1;
        }
        tampered.push(("the declared size inflated", edit));

        for (what, tx) in &tampered {
            let got = g.clone().apply_transfer(tx, price, &ToyVerifier);
            assert!(
                matches!(
                    got,
                    Err(TransferReject::BadSignature) | Err(TransferReject::ValueNotConserved)
                ),
                "{what} was accepted: {got:?}",
            );
        }

        // And the one rewrite that is NOT about the money: a tampered witness.
        // The transaction still means the same payment, so it is still refused
        // — by the signature, not by the id, which has not moved.
        let mut witness = signed.clone();
        if let PosTransaction::Transfer { inputs, .. } = &mut witness {
            inputs[0].signature[0] ^= 0xFF;
        }
        assert_eq!(witness.txid(), signed.txid(), "a witness edit must not re-key the payment");
        assert_eq!(
            g.clone().apply_transfer(&witness, price, &ToyVerifier),
            Err(TransferReject::BadSignature),
        );
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
        let spender = owner_key(0x3B);
        let coins: Vec<_> =
            (0..2u32).map(|i| opening(0x78, i, 100_000_000, &spender)).collect();
        let (t, g, mut chains) = setup_funded(4, &coins);
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
        // Priced at the block's own base fee — `s1`'s child, not genesis's.
        let tx = transfer_spending(
            &coins,
            &spender,
            script_of(&owner_key(0x3C)),
            9_216,
            4_000,
            s1.next_base_fee(),
        );
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
        let (t, g, mut chains) = setup_with(4, MarkerVerifier, &[]);
        let mut b = build_block(&t, &g, 1, &[], &[], &mut chains);
        // Control: the honest signature passes this verifier.
        assert!(t.apply_block(&g, &b, &[], &[]).is_ok());
        b.proposer_sig = b"forged".to_vec();
        assert_eq!(
            t.apply_block(&g, &b, &[], &[]),
            Err(TransitionError::Proposal(ProposalReject::BadSignature)),
        );
    }

    /// The `Transfer` encoding carries the transfer, and the change is a
    /// **consensus** change: `canonical_bytes` is what `body_root` is a Merkle
    /// root over, so re-shaping the variant re-keys the block id of every block
    /// carrying one.
    ///
    /// Pinned three ways: the discriminant and the field layout are fixed (a
    /// silent shift would re-key transfers against a deployed chain); no
    /// declared-fee field survives, because the fee is what the inputs exceed
    /// the outputs by; and the encoding is injective over **every** field of
    /// **every** input and output, which is what makes the body root a
    /// commitment to the payment rather than to a summary of it.
    #[test]
    fn transfer_encoding_carries_value_not_only_gas() {
        let input = |txid: u8, vout: u32| TransferInput {
            txid: [txid; 32],
            vout,
            pubkey: vec![0xA0; 3],
            signature: vec![0xB0; 2],
        };
        let out = |value: u64, sh: u8| TransferOutput { value, script_hash: [sh; 32] };
        let tx = PosTransaction::Transfer {
            inputs: vec![input(0x10, 3)],
            outputs: vec![out(1_000, 0xC0)],
            tx_bytes: 1_024,
            tip_millisat_per_gas: 7,
        };
        let bytes = tx.canonical_bytes();

        // Layout, field by field: tag, input count, the input (outpoint +
        // length-prefixed witnesses), output count, the output, size, tip.
        assert_eq!(bytes[0], 0x01, "the Transfer discriminant is frozen");
        assert_eq!(&bytes[1..5], &1u32.to_le_bytes(), "input count");
        assert_eq!(&bytes[5..37], &[0x10u8; 32], "txid");
        assert_eq!(&bytes[37..41], &3u32.to_le_bytes(), "vout");
        assert_eq!(&bytes[41..45], &3u32.to_le_bytes(), "pubkey length prefix");
        assert_eq!(&bytes[45..48], &[0xA0u8; 3], "pubkey");
        assert_eq!(&bytes[48..52], &2u32.to_le_bytes(), "signature length prefix");
        assert_eq!(&bytes[52..54], &[0xB0u8; 2], "signature");
        assert_eq!(&bytes[54..58], &1u32.to_le_bytes(), "output count");
        assert_eq!(&bytes[58..66], &1_000u64.to_le_bytes(), "output value");
        assert_eq!(&bytes[66..98], &[0xC0u8; 32], "output script hash");
        assert_eq!(&bytes[98..106], &1_024u64.to_le_bytes(), "tx_bytes");
        assert_eq!(&bytes[106..122], &7u128.to_le_bytes(), "tip");
        assert_eq!(bytes.len(), 122, "no trailing field");

        // Injectivity: mutate one field at a time and the body root must move.
        // Every field, including the witnesses — the body root commits to what
        // was gossiped, even though the SIGNING root deliberately does not.
        let root = |t: &PosTransaction| crate::derive::body_root(&[t.canonical_bytes()]);
        let base = root(&tx);
        let mutants = [
            PosTransaction::Transfer {
                inputs: vec![input(0x11, 3)],
                outputs: vec![out(1_000, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![input(0x10, 4)],
                outputs: vec![out(1_000, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![input(0x10, 3), input(0x12, 0)],
                outputs: vec![out(1_000, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![TransferInput {
                    pubkey: vec![0xA1; 3],
                    ..input(0x10, 3)
                }],
                outputs: vec![out(1_000, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![TransferInput {
                    signature: vec![0xB1; 2],
                    ..input(0x10, 3)
                }],
                outputs: vec![out(1_000, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![input(0x10, 3)],
                outputs: vec![out(1_001, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![input(0x10, 3)],
                outputs: vec![out(1_000, 0xC1)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![input(0x10, 3)],
                outputs: vec![out(1_000, 0xC0), out(0, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![input(0x10, 3)],
                outputs: vec![out(1_000, 0xC0)],
                tx_bytes: 1_025,
                tip_millisat_per_gas: 7,
            },
            PosTransaction::Transfer {
                inputs: vec![input(0x10, 3)],
                outputs: vec![out(1_000, 0xC0)],
                tx_bytes: 1_024,
                tip_millisat_per_gas: 8,
            },
        ];
        for (i, m) in mutants.iter().enumerate() {
            assert_ne!(base, root(m), "mutant {i} shares a body root with the original");
        }

        // Output ORDER is committed too: outputs are positionally keyed by
        // vout, so swapping two of them sends the money to different places.
        let a = PosTransaction::Transfer {
            inputs: vec![input(0x10, 3)],
            outputs: vec![out(1, 0xC0), out(2, 0xC1)],
            tx_bytes: 1_024,
            tip_millisat_per_gas: 7,
        };
        let b = PosTransaction::Transfer {
            inputs: vec![input(0x10, 3)],
            outputs: vec![out(2, 0xC1), out(1, 0xC0)],
            tx_bytes: 1_024,
            tip_millisat_per_gas: 7,
        };
        assert_ne!(root(&a), root(&b), "output order must be committed");
        assert_ne!(a.txid(), b.txid(), "output order must change the txid");
    }

    /// The signing root covers everything a spender is agreeing to, and
    /// **nothing** that a third party can change without invalidating the
    /// transfer.
    ///
    /// The two halves are equally load-bearing. If the root did not move with
    /// the outputs, a relay could redirect the money and the signature would
    /// still verify — the entire attack. If it moved with the witnesses, no
    /// signature could ever be computed, because the value to sign would
    /// depend on the signature.
    #[test]
    fn the_signing_root_covers_the_payment_and_excludes_the_witnesses() {
        let base = PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid: [0x40; 32],
                vout: 1,
                pubkey: vec![0xAA; 4],
                signature: vec![0xBB; 4],
            }],
            outputs: vec![TransferOutput { value: 500, script_hash: [0xCC; 32] }],
            tx_bytes: 700,
            tip_millisat_per_gas: 3,
        };
        let r0 = base.spend_signing_root();

        // Witness-only edits: same root, same txid — this is what "the id is
        // not malleable" means, in one assertion.
        let mut witness_edit = base.clone();
        if let PosTransaction::Transfer { inputs, .. } = &mut witness_edit {
            inputs[0].pubkey = vec![0x01; 3745];
            inputs[0].signature = vec![0x02; 4589];
        }
        assert_eq!(witness_edit.spend_signing_root(), r0, "witnesses are outside the root");
        assert_eq!(witness_edit.txid(), base.txid(), "witnesses must not move the txid");
        assert_ne!(
            witness_edit.canonical_bytes(),
            base.canonical_bytes(),
            "fixture premise: the two really are different transactions on the wire"
        );

        // Everything else moves it. Each of these is a way to steal or
        // repurpose an authorisation if it were left unsigned.
        let mut moved = vec![r0];
        let mut check = |label: &str, t: PosTransaction| {
            let r = t.spend_signing_root();
            assert_ne!(r, r0, "{label} must be covered by the signing root");
            moved.push(r);
        };
        check("the outpoint txid", {
            let mut t = base.clone();
            if let PosTransaction::Transfer { inputs, .. } = &mut t {
                inputs[0].txid = [0x41; 32];
            }
            t
        });
        check("the outpoint index", {
            let mut t = base.clone();
            if let PosTransaction::Transfer { inputs, .. } = &mut t {
                inputs[0].vout = 2;
            }
            t
        });
        check("the output value", {
            let mut t = base.clone();
            if let PosTransaction::Transfer { outputs, .. } = &mut t {
                outputs[0].value = 501;
            }
            t
        });
        check("the recipient", {
            let mut t = base.clone();
            if let PosTransaction::Transfer { outputs, .. } = &mut t {
                outputs[0].script_hash = [0xCD; 32];
            }
            t
        });
        check("the declared size", {
            let mut t = base.clone();
            if let PosTransaction::Transfer { tx_bytes, .. } = &mut t {
                *tx_bytes = 701;
            }
            t
        });
        check("the tip", {
            let mut t = base.clone();
            if let PosTransaction::Transfer { tip_millisat_per_gas, .. } = &mut t {
                *tip_millisat_per_gas = 4;
            }
            t
        });
        let unique: BTreeSet<[u8; 32]> = moved.iter().copied().collect();
        assert_eq!(unique.len(), moved.len(), "two distinct transfers share a signing root");

        // The txid is a domain-separated hash OF the signing root, not the
        // root itself: a value that identifies a transaction must never be a
        // value a key was asked to sign.
        assert_ne!(base.txid(), r0);
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

    /// The whistleblower reward may not turn unbacked principal into coins.
    ///
    /// Slashing an unbacked genesis bond used to credit a thirty-second of the
    /// loss into `pending_fee_rewards` regardless — and accrual is withdrawable
    /// under the founder's rule, while `issued_sat` never moved. A validator
    /// willing to be slashed could run that in a loop and mint past the supply
    /// cap. Found as A7 by the adversarial front, against production code,
    /// before the gate ever armed.
    #[test]
    fn the_whistleblower_reward_cannot_exceed_the_backed_share() {
        let raw = 1_000u128; // a thirty-second of 32,000
        let loss = 32_000u128;

        // Pre-gate: unchanged, byte for byte. This half is load-bearing — the
        // cap must not alter the live chain outside its own flag day, and
        // `unbacked_principal_sat` treats EVERY bond as unbacked while the
        // gate is closed, so an ungated cap would zero every reward today.
        assert_eq!(capped_whistleblower_reward(raw, loss, 0, false), raw);

        // Post-gate, fully unbacked offender: nothing backed was consumed, so
        // nothing may be paid. This is the hole.
        assert_eq!(capped_whistleblower_reward(raw, loss, 0, true), 0);

        // Post-gate, partially backed: the cap bites at what was backed.
        assert_eq!(capped_whistleblower_reward(raw, loss, 400, true), 400);

        // Control: a fully backed offender pays the full reward. Without this
        // half the assertions above would pass just as well against a cap that
        // always returned zero, which would break slashing rather than fix it.
        assert_eq!(capped_whistleblower_reward(raw, loss, loss, true), raw);

        // Control: the operator's own loss also bounds it — a reward larger
        // than what left the offender's bond would be minting from the other
        // direction.
        assert_eq!(capped_whistleblower_reward(raw, 300, u128::MAX, true), 300);
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
        let (t, g, mut chains) = setup_with(4, MarkerVerifier, &[]);

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
        let (_, _, mut chains_forged) = setup_with(4, MarkerVerifier, &[]);
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
            // Devnet/test genesis: nobody holds anything.
            &[],
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
    fn state_with_live_bookkeeping() -> (Transition<ToyVerifier>, CommittedState, Vec<Attestation>)
    {
        // Funded, and the transfer below actually spends: the unspent set is
        // one of the components the root must bind, and a fixture where it sat
        // empty (or untouched since genesis) would exercise that leaf
        // vacuously.
        let spender = owner_key(0x3D);
        let coin = opening(0x79, 0, 100_000_000, &spender);
        let (t, g, mut chains) = setup_funded(8, &[coin.clone()]);
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
        let fee = transfer_spending(
            std::slice::from_ref(&coin),
            &spender,
            script_of(&owner_key(0x3E)),
            512,
            5,
            g.next_base_fee(),
        );
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
        let spender = owner_key(0x3F);
        let coin = opening(0x7A, 0, 100_000_000, &spender);
        let (t, g, mut chains) = setup_funded(8, &[coin.clone()]);
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
        let fee = transfer_spending(
            std::slice::from_ref(&coin),
            &spender,
            script_of(&owner_key(0x40)),
            512,
            5,
            g.next_base_fee(),
        );
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
        // The funded shapes (2026-08-21) keep the property BY equality:
        // FundedDeposit destroys exactly what it bonds (ValueNotConserved
        // otherwise), Withdraw creates exactly what the bond gives up minus
        // the fee — and only the FUNDED portion at that — and SignedExit
        // moves no value at all. Whoever adds a variant here must argue the
        // same, in this comment, before the compiler lets the test build.
        let witness = PosTransaction::Exit { validator: 0 };
        match &witness {
            PosTransaction::Transfer { .. } => {}
            // The deduplicated encoding of the same movement: conserves under
            // the same strict-equality rule, mints nothing.
            PosTransaction::TransferV2 { .. } => {}
            PosTransaction::Deposit { .. } => {}
            PosTransaction::Exit { .. } => {}
            PosTransaction::Delegate { .. } => {}
            // The funded-staking trio (tags 0x07-0x09). FundedDeposit
            // DESTROYS committed outputs to create the bond (conservation
            // enforced with the transfer path's own ValueNotConserved);
            // SignedExit only schedules epochs. Withdraw is the one place
            // bonded value becomes spendable coin, and its arithmetic is the
            // write-off rule: it pays `staked_sat - unbacked_principal`, i.e.
            // only value that entered the bond as destroyed coins (the funded
            // principal) or as counted issuance / fee rewards — never the
            // unissued genesis principal, which leaves as `written_off_sat`,
            // and never a satoshi of new issuance (`issued_sat` untouched;
            // pinned by the conservation tests below).
            PosTransaction::FundedDeposit { .. } => {}
            PosTransaction::SignedExit { .. } => {}
            PosTransaction::Withdraw { .. } => {}
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

    // ── The inactivity leak must reach the schedule, not only the quorum ────

    /// The shipped default has to stay inert.
    ///
    /// Lowering this constant changes proposer selection and committee
    /// membership on the next epoch, so a node still on the old value computes
    /// a different schedule and forks. This test is a tripwire, not a property:
    /// it is meant to fail the moment someone sets a real epoch, so that the
    /// change is made together with a coordinated rebuild rather than shipped
    /// quietly inside an unrelated release.
    #[test]
    fn leaked_roster_ships_inert() {
        assert_eq!(
            crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH,
            u64::MAX,
            "binding the leaked roster is a flag day: set the epoch and roll the fleet together"
        );
    }

    /// Same tripwire for the funded-staking gate. The founder's decision on
    /// the 1,600,000 BLOCH of unissued genesis bond principal is now
    /// RECORDED (write-off at withdrawal — see the constant's docs in
    /// `params.rs`) and the wire plus the rules ship in this binary, inert.
    /// What remains before this constant may move is purely operational: the
    /// whole fleet rebuilt onto a binary carrying the new discriminants, as a
    /// verified fact rather than a hope — the first post-gate block changes
    /// block-body decoding, so a node on the old binary rejects it as a
    /// decode error rather than as a rule. This test is what makes lowering
    /// the constant a deliberate, visible act instead of a quiet edit inside
    /// an unrelated release.
    #[test]
    fn funded_stake_gate_ships_inert() {
        assert_eq!(
            crate::params::FUNDED_STAKE_ACTIVATION_EPOCH,
            u64::MAX,
            "funding the bonds is a flag day: the write-off decision is already implemented \
             behind it, so what gates arming it is the fleet rebuild — set the epoch and roll \
             the fleet together"
        );
    }

    /// Before the flag day, nothing moves — even with a leak on the books.
    #[test]
    fn consensus_roster_matches_duty_roster_before_the_flag_day() {
        let (_t, g, _c) = setup(4);
        assert_eq!(
            g.consensus_roster_at(g.epoch),
            g.duty_roster_at(g.epoch),
            "the gate is closed, so these must be the same roster"
        );
    }

    /// A fully-leaked validator stops being drawn to propose and stops holding
    /// a committee seat — the liveness the leak is supposed to buy back.
    ///
    /// The control half is what makes this worth running: the same validator,
    /// on the same seed, with the leak NOT applied, both proposes and sits on
    /// a committee. Without that half the assertions below would pass just as
    /// well against a roster that had lost the validator for some unrelated
    /// reason, which is the failure mode that makes a negative test worthless.
    #[test]
    fn a_fully_leaked_validator_leaves_the_schedule() {
        let (_t, g, _c) = setup(4);
        let absent = 1u32;
        let unleaked = g.duty_roster_at(0);
        let seed = g.seed_for_epoch(0);

        // Control: with raw stake the absent validator is scheduled like anyone
        // else. If this ever stops holding, the test below proves nothing.
        let drawn_before: Vec<u32> =
            (0..256).filter_map(|s| schedule::proposer(&seed, s, &unleaked)).collect();
        assert!(
            drawn_before.contains(&absent),
            "control failed: the absent validator was never drawn even unleaked,              so the assertions below would be vacuous"
        );
        assert!(
            crate::committees::epoch_committees(&seed, 0, &unleaked)
                .iter()
                .any(|c| c.contains(&absent)),
            "control failed: the absent validator held no seat even unleaked"
        );

        // Leak it to the floor. Saturating: the leak exceeds the stake here on
        // purpose, because a real leak keeps accruing past it.
        let stake_of_absent =
            unleaked.iter().find(|v| v.index == absent).unwrap().effective_stake;
        let leaked = with_leak_applied(unleaked.clone(), |i| {
            if i == absent {
                stake_of_absent.saturating_mul(2)
            } else {
                0
            }
        });

        assert_eq!(
            leaked.iter().find(|v| v.index == absent).unwrap().effective_stake,
            0,
            "a leak past the stake must land on zero, never wrap"
        );
        for v in &leaked {
            if v.index != absent {
                assert_eq!(
                    v.effective_stake,
                    unleaked.iter().find(|u| u.index == v.index).unwrap().effective_stake,
                    "a validator that never leaked must keep its exact weight"
                );
            }
        }

        assert!(
            !(0..256)
                .filter_map(|s| schedule::proposer(&seed, s, &leaked))
                .any(|p| p == absent),
            "a fully-leaked validator must never win a proposer draw"
        );
        assert!(
            !crate::committees::epoch_committees(&seed, 0, &leaked)
                .iter()
                .any(|c| c.contains(&absent)),
            "a fully-leaked validator must hold no committee seat"
        );

        // And the slots it used to take are not lost — they go to the live set,
        // which is the entire point: empty slots become produced slots.
        assert!(
            (0..256).filter_map(|s| schedule::proposer(&seed, s, &leaked)).count() == 256,
            "every slot must still draw a proposer from the surviving validators"
        );
    }

    // ── TransferV2: deduplicated witnesses behind their own flag day ────────
    //
    // The tests below call `apply_transfer_v2` directly — the unit seam
    // BELOW the flag-day gate, the same pattern as testing
    // `with_leak_applied` directly — because the gate is `u64::MAX` and the
    // block path correctly refuses everything. The gate itself is tested
    // end-to-end through `compute_post_state`.

    /// Arming this format is a flag day. Once armed, the thing that must hold
    /// is not "still inert" — it is that the epoch is in the FUTURE relative
    /// to nothing this test can see, and that it moves together with the block
    /// cap. So the tripwire checks the pairing (see
    /// `raising_the_block_cap_is_a_flag_day`) and this test checks the only
    /// property left that is checkable here: an armed epoch must be a real
    /// one, and the fleet must be rebuilt before the chain reaches it.
    #[test]
    fn transfer_v2_activation_is_paired_with_the_block_cap() {
        assert_eq!(
            crate::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
            crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH,
            "both consensus switches must activate at the SAME epoch: a fleet \
             running two different rule sets is a partition"
        );
    }

    /// Before the flag day a block carrying a V2 transfer is refused with
    /// `FormatNotActive` — and the CONTROL is the same logical transfer,
    /// re-encoded as V1, accepted in the same position of the same-slot block
    /// and actually moving the coins. Together they prove the reject is about
    /// the format and nothing else in the block or the transfer.
    #[test]
    fn transfer_v2_is_refused_before_the_flag_day_and_its_v1_twin_applies() {
        let alice = owner_key(0x60);
        let to = script_of(&owner_key(0x61));
        let coin = opening(0x86, 0, 50_000_000, &alice);

        let (t, g, mut chains) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();
        // One logical transfer, two encodings. 512 declared bytes covers both
        // canonical lengths (toy keys), and `tx_bytes` is inside the shared
        // signing root, so the two encodings commit to the same declaration.
        let v1 = transfer_spending(std::slice::from_ref(&coin), &alice, to, 512, 1, price);
        let v2 = v2_twin_of(&v1);
        // Premise of "same logical transfer", checked, not assumed.
        assert_eq!(v1.txid(), v2.txid());

        // The V2 encoding, in an otherwise-valid block: refused at the gate,
        // with the transfer's index and the format reason.
        let env = probe_env(&g, 1, std::slice::from_ref(&v2), &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&v2)).unwrap_err(),
            TransitionError::Transfer(0, TransferReject::FormatNotActive),
        );

        // Control: the V1 twin, same slot, fresh fixture (probe_env consumed
        // the proposer's reveal) — accepted, and the coin actually moves.
        let (t1, g1, mut chains1) = setup_funded(4, &[coin.clone()]);
        let b = build_block(&t1, &g1, 1, &[], std::slice::from_ref(&v1), &mut chains1);
        let s = t1.apply_block(&g1, &b, &[], std::slice::from_ref(&v1)).unwrap();
        assert!(s.utxo(&coin.txid, 0).is_none(), "the spent coin must leave the set");
        assert!(s.utxo(&v1.txid(), 0).is_some(), "the payment must land in the set");
    }

    /// **Equivalence at the byte level (item test a).** Re-encoding a signed
    /// V1 transfer as V2 moves the SAME signature bytes into the table; the
    /// signing root and txid are bit-identical, the two apply paths produce
    /// bit-identical unspent sets and identical charges, and corrupting the
    /// deduplicated signature fails exactly as corrupting the inlined one
    /// does. One input on purpose: with one input the class terms coincide
    /// (k = n = 1), so the same outputs conserve under both charges — the
    /// deliberate multi-input pricing difference is pinned separately by
    /// `v2_charges_the_verifies_it_runs`.
    #[test]
    fn v2_verifies_exactly_the_v1_signatures() {
        let alice = owner_key(0x62);
        let to = script_of(&owner_key(0x63));
        let coin = opening(0x87, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();

        let v1 = transfer_spending(std::slice::from_ref(&coin), &alice, to, 512, 1, price);
        let v2 = v2_twin_of(&v1);

        // The commitment surface is identical: root, and therefore txid and
        // therefore every created outpoint. This is what makes a wallet
        // signature valid under either encoding.
        assert_eq!(v1.spend_signing_root(), v2.spend_signing_root());
        assert_eq!(v1.txid(), v2.txid());
        // And the wire encodings are NOT identical — different tags, so the
        // equality above is a property of the root construction, not of the
        // twins being the same bytes.
        assert_ne!(v1.canonical_bytes(), v2.canonical_bytes());

        // Same pre-state, both paths: bit-identical unspent sets and charges.
        let mut a = g.clone();
        let charge_v1 = a.apply_transfer(&v1, price, &ToyVerifier).unwrap();
        let mut b = g.clone();
        let charge_v2 = b.apply_transfer_v2(&v2, price, &ToyVerifier).unwrap();
        assert_eq!(charge_v1, charge_v2, "one input, one verification: same charge");
        assert_eq!(a.eutxos, b.eutxos, "the two encodings must move the ledger identically");

        // Control: one corrupted signature byte in the TABLE fails the V2
        // exactly as the same corruption inline fails the V1 — the check
        // did not get weaker by being run once.
        let mut bad_v2 = v2.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad_v2 {
            keys[0].signature[0] ^= 1;
        }
        assert_eq!(
            g.clone().apply_transfer_v2(&bad_v2, price, &ToyVerifier),
            Err(TransferReject::BadSignature),
        );
        let mut bad_v1 = v1.clone();
        if let PosTransaction::Transfer { inputs, .. } = &mut bad_v1 {
            inputs[0].signature[0] ^= 1;
        }
        assert_eq!(
            g.clone().apply_transfer(&bad_v1, price, &ToyVerifier),
            Err(TransferReject::BadSignature),
        );
    }

    /// **THE control of the item (test c): a deduplicated key must not
    /// authorise another owner's coin.** The obvious attack on witness
    /// deduplication: put only A's key in the table, point B's input at it,
    /// have A sign perfectly. `owns` fails on B's input — the indexed key's
    /// hash does not match B's committed `script_hash` — BEFORE any
    /// signature is looked at, so not even a flawless signature from A can
    /// reach B's coin.
    ///
    /// The control half in the same test: the SAME two spend points with an
    /// honest table ([A, B], each input naming its own key, each entry
    /// signed by its owner) applies and moves both coins — so the reject
    /// above was the key reuse, not some other defect in the fixture.
    #[test]
    fn dedup_key_cannot_authorise_another_owners_input() {
        let alice = owner_key(0x64);
        let bob = owner_key(0x65);
        let to = script_of(&owner_key(0x66));
        let coin_a = opening(0x88, 0, 50_000_000, &alice);
        let coin_b = opening(0x89, 0, 50_000_000, &bob);
        let (_t, g, _c) = setup_funded(4, &[coin_a.clone(), coin_b.clone()]);
        let price = g.next_base_fee();

        // The attack: internally consistent, correctly signed by A, and
        // conserving under its own (k = 1) charge — everything about it is
        // valid except whose coin the second input is.
        let attack = transfer_v2_raw(
            &[coin_a.clone(), coin_b.clone()],
            &[&alice],
            &[0, 0],
            to,
            512,
            1,
            price,
        );
        assert_eq!(
            g.clone().apply_transfer_v2(&attack, price, &ToyVerifier),
            Err(TransferReject::ScriptMismatch),
            "A's key on B's coin must die on the script hash, before any verify",
        );

        // Control: same spend points, honest table — applies, and both coins
        // move to the payment.
        let honest = transfer_v2_raw(
            &[coin_a.clone(), coin_b.clone()],
            &[&alice, &bob],
            &[0, 1],
            to,
            512,
            1,
            price,
        );
        let mut post = g.clone();
        assert!(
            post.apply_transfer_v2(&honest, price, &ToyVerifier).is_ok(),
            "the honest two-owner transfer must apply — otherwise the attack \
             assertion above proves nothing about key reuse",
        );
        assert!(post.utxo(&coin_a.txid, 0).is_none());
        assert!(post.utxo(&coin_b.txid, 0).is_none());
        assert!(post.utxo(&honest.txid(), 0).is_some());
    }

    /// A `key_index` past the table is refused as such. The index is witness
    /// data outside the signing root — pinned here by the root not moving
    /// under the mutation — so the still-valid signature must not save it.
    #[test]
    fn a_key_index_past_the_table_is_refused() {
        let alice = owner_key(0x67);
        let to = script_of(&owner_key(0x68));
        let coin = opening(0x8A, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();

        let honest = transfer_v2_raw(std::slice::from_ref(&coin), &[&alice], &[0], to, 512, 1, price);
        // Control first: the same transfer with the index in range applies.
        assert!(g.clone().apply_transfer_v2(&honest, price, &ToyVerifier).is_ok());

        let mut bad = honest.clone();
        if let PosTransaction::TransferV2 { inputs, .. } = &mut bad {
            inputs[0].key_index = 1;
        }
        // NOT re-signed, deliberately: the index is outside the root, so the
        // signature is still valid — the reject below is the bounds check
        // and nothing else.
        assert_eq!(bad.spend_signing_root(), honest.spend_signing_root());
        assert_eq!(
            g.clone().apply_transfer_v2(&bad, price, &ToyVerifier),
            Err(TransferReject::BadKeyIndex),
        );
    }

    /// Two table entries with one key are refused; the deduplicated form of
    /// the same transfer (one entry, both inputs pointing at it) is the
    /// control and applies. Without this rule the table bytes are malleable:
    /// the entries are witness, so a relay could split one entry into N
    /// without touching any signed byte.
    #[test]
    fn a_duplicate_witness_key_is_refused() {
        let alice = owner_key(0x69);
        let to = script_of(&owner_key(0x6A));
        let c1 = opening(0x8B, 0, 50_000_000, &alice);
        let c2 = opening(0x8C, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[c1.clone(), c2.clone()]);
        let price = g.next_base_fee();

        let dup = transfer_v2_raw(
            &[c1.clone(), c2.clone()],
            &[&alice, &alice],
            &[0, 1],
            to,
            512,
            1,
            price,
        );
        assert_eq!(
            g.clone().apply_transfer_v2(&dup, price, &ToyVerifier),
            Err(TransferReject::DuplicateWitnessKey),
        );

        // Control: the deduplicated table over the same spend points applies.
        let deduped =
            transfer_v2_raw(&[c1.clone(), c2.clone()], &[&alice], &[0, 0], to, 512, 1, price);
        assert!(g.clone().apply_transfer_v2(&deduped, price, &ToyVerifier).is_ok());
    }

    /// A table entry no input references is refused; drop the entry and the
    /// same transfer applies (the control). The unused entry is correctly
    /// signed by its own key — what is wrong with it is exactly that nothing
    /// committed ever checks it, which is the relay-padding hole the rule
    /// closes.
    #[test]
    fn an_unreferenced_witness_key_is_refused() {
        let alice = owner_key(0x6B);
        let bob = owner_key(0x6C);
        let to = script_of(&owner_key(0x6D));
        let coin = opening(0x8D, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[coin.clone()]);
        let price = g.next_base_fee();

        let padded =
            transfer_v2_raw(std::slice::from_ref(&coin), &[&alice, &bob], &[0], to, 512, 1, price);
        assert_eq!(
            g.clone().apply_transfer_v2(&padded, price, &ToyVerifier),
            Err(TransferReject::WitnessKeyUnused),
        );

        // Control: same transfer without the free rider.
        let lean = transfer_v2_raw(std::slice::from_ref(&coin), &[&alice], &[0], to, 512, 1, price);
        assert!(g.clone().apply_transfer_v2(&lean, price, &ToyVerifier).is_ok());
    }

    /// The class term of the V2 charge is the TABLE length — the hybrid
    /// verifications the node actually runs — not the input count. Two
    /// same-owner inputs are charged one verification's gas, and the control
    /// is the same quantity priced at two: strictly more, so the assertion
    /// cannot pass vacuously.
    #[test]
    fn v2_charges_the_verifies_it_runs() {
        let alice = owner_key(0x6E);
        let to = script_of(&owner_key(0x6F));
        let c1 = opening(0x8E, 0, 50_000_000, &alice);
        let c2 = opening(0x8F, 0, 50_000_000, &alice);
        let (_t, g, _c) = setup_funded(4, &[c1.clone(), c2.clone()]);
        let price = g.next_base_fee();

        let tx = transfer_v2_raw(&[c1, c2], &[&alice], &[0, 0], to, 512, 1, price);
        let PosTransaction::TransferV2 { tx_bytes, .. } = &tx else { unreachable!() };
        let declared = *tx_bytes;

        let charge = g.clone().apply_transfer_v2(&tx, price, &ToyVerifier).unwrap();
        let one_verify = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 1 },
            declared,
            price,
            1,
        );
        let two_verifies = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 2 },
            declared,
            price,
            1,
        );
        assert_eq!(charge, one_verify, "two inputs, one owner: gas for ONE verification");
        assert!(
            two_verifies.gas > one_verify.gas,
            "control: per-input pricing must actually differ, or the equality \
             above says nothing"
        );
    }

    /// **The permuted-twin refusal — why the table order is consensus.** The
    /// table and the `key_index`es are outside the signing root, so a relay
    /// can swap two entries and re-point the indices without touching one
    /// signed byte: same root, same txid, DIFFERENT `canonical_bytes` — and
    /// the mempool is keyed by `canonical_bytes` (engine.rs:800), so before
    /// this rule the twin would sit next to the original as a distinct entry
    /// of the same transfer. The test pins all three facts (root equal, txid
    /// equal, bytes distinct) and then the refusal; the CONTROL is the same
    /// spend points, same signatures, canonical order — applies and moves
    /// both coins. Last, the twin is repaired by
    /// [`canonicalize_witness_table`] alone — no re-sign — back to the exact
    /// canonical bytes: order was the only thing wrong with it.
    #[test]
    fn a_permuted_witness_table_is_refused_and_shares_the_txid() {
        // Two owners with an EXPLICIT byte order, so "permuted" is a fact
        // established by the fixture, not by owner_key's internals.
        let a = owner_key(0x70);
        let b = owner_key(0x71);
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let to = script_of(&owner_key(0x72));
        let coin_lo = opening(0x90, 0, 50_000_000, &lo);
        let coin_hi = opening(0x91, 0, 50_000_000, &hi);
        let (_t, g, _c) = setup_funded(4, &[coin_lo.clone(), coin_hi.clone()]);
        let price = g.next_base_fee();

        let canonical = transfer_v2_raw(
            &[coin_lo.clone(), coin_hi.clone()],
            &[&lo, &hi],
            &[0, 1],
            to,
            512,
            1,
            price,
        );

        // The relay's move, exactly: swap the entries, re-point the indices,
        // re-sign NOTHING.
        let mut permuted = canonical.clone();
        if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut permuted {
            keys.swap(0, 1);
            for i in inputs.iter_mut() {
                i.key_index ^= 1;
            }
        }
        // The mempool facts this rule exists for: one txid, two encodings.
        assert_eq!(permuted.spend_signing_root(), canonical.spend_signing_root());
        assert_eq!(permuted.txid(), canonical.txid());
        assert_ne!(
            permuted.canonical_bytes(),
            canonical.canonical_bytes(),
            "premise: the twin must be a DISTINCT encoding, or nothing below \
             says anything about malleability"
        );

        assert_eq!(
            g.clone().apply_transfer_v2(&permuted, price, &ToyVerifier),
            Err(TransferReject::WitnessTableNotCanonical),
        );

        // Control: canonical order, same signatures — applies, coins move.
        let mut post = g.clone();
        assert!(
            post.apply_transfer_v2(&canonical, price, &ToyVerifier).is_ok(),
            "the canonical form must apply — otherwise the refusal above \
             proves nothing about order"
        );
        assert!(post.utxo(&coin_lo.txid, 0).is_none());
        assert!(post.utxo(&coin_hi.txid, 0).is_none());
        assert!(post.utxo(&canonical.txid(), 0).is_some());

        // Repairable without the owners: canonicalization alone restores the
        // exact canonical bytes.
        if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut permuted {
            canonicalize_witness_table(keys, inputs);
        }
        assert_eq!(permuted.canonical_bytes(), canonical.canonical_bytes());
    }

    /// **Discrimination between the two table faults.** Adjacent equality is
    /// the DUPLICATE and must keep its name — `DuplicateWitnessKey` — while
    /// an inversion is `WitnessTableNotCanonical`; a non-adjacent duplicate
    /// necessarily contains an inversion and now surfaces as the latter.
    /// The names matter for the same reason `TransferReject` is not one
    /// opaque variant (interfaces.rs): the two rejects are different wallet
    /// bugs read off a log. The control half is the same two spend points
    /// under the deduplicated, ordered table, applying.
    #[test]
    fn duplicate_and_disorder_are_discriminated() {
        let a = owner_key(0x73);
        let b = owner_key(0x74);
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let to = script_of(&owner_key(0x75));
        let c1 = opening(0x92, 0, 50_000_000, &lo);
        let c2 = opening(0x93, 0, 50_000_000, &lo);
        let c3 = opening(0x94, 0, 50_000_000, &hi);
        let (_t, g, _c) = setup_funded(4, &[c1.clone(), c2.clone(), c3.clone()]);
        let price = g.next_base_fee();

        // Adjacent equality: the duplicate, under its own name.
        let dup = transfer_v2_raw(&[c1.clone(), c2.clone()], &[&lo, &lo], &[0, 1], to, 512, 1, price);
        assert_eq!(
            g.clone().apply_transfer_v2(&dup, price, &ToyVerifier),
            Err(TransferReject::DuplicateWitnessKey),
            "equality must NOT be misread as an order fault"
        );

        // Non-adjacent duplicate [lo, hi, lo]: the duplicate is not adjacent,
        // but hi > lo IS an inversion — refused as the order fault.
        let split = transfer_v2_raw(
            &[c1.clone(), c3.clone(), c2.clone()],
            &[&lo, &hi, &lo],
            &[0, 1, 2],
            to,
            512,
            1,
            price,
        );
        assert_eq!(
            g.clone().apply_transfer_v2(&split, price, &ToyVerifier),
            Err(TransferReject::WitnessTableNotCanonical),
        );

        // Control: deduplicated AND ordered, same three coins — applies.
        let clean = transfer_v2_raw(
            &[c1.clone(), c2.clone(), c3.clone()],
            &[&lo, &hi],
            &[0, 0, 1],
            to,
            512,
            1,
            price,
        );
        assert!(g.clone().apply_transfer_v2(&clean, price, &ToyVerifier).is_ok());
    }

    /// **Uniqueness of the canonical encoding, and charge invariance.** For
    /// any consensus-valid V2, `canonical_bytes` of a permuted twin fed
    /// through [`canonicalize_witness_table`] equals the bytes of the
    /// transfer BUILT in order — bit for bit, txid preserved, and the charge
    /// is unchanged because the class term is `keys.len()`, invariant under
    /// permutation. Three keys, rotated (not swapped), so the remap is a
    /// real permutation and not its own inverse — an index remap bug that a
    /// symmetric swap would hide (e.g. mapping new→old instead of old→new)
    /// breaks a rotation.
    #[test]
    fn canonicalization_restores_the_unique_encoding() {
        let mut ks = [owner_key(0x76), owner_key(0x77), owner_key(0x78)];
        ks.sort();
        let to = script_of(&owner_key(0x79));
        let coins: Vec<_> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| opening(0x95 + i as u8, 0, 50_000_000, k))
            .collect();
        let (_t, g, _c) = setup_funded(4, &coins);
        let price = g.next_base_fee();

        let canonical = transfer_v2_raw(
            &coins,
            &[&ks[0], &ks[1], &ks[2]],
            &[0, 1, 2],
            to,
            1024,
            1,
            price,
        );

        // Rotate: old table index j lands at (j + 2) % 3, and every input's
        // key_index moves with it, so ownership is preserved.
        let mut permuted = canonical.clone();
        if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut permuted {
            keys.rotate_left(1);
            for i in inputs.iter_mut() {
                i.key_index = (i.key_index + 2) % 3;
            }
        }
        // Premise: a genuinely distinct encoding of the same transfer.
        assert_ne!(permuted.canonical_bytes(), canonical.canonical_bytes());
        assert_eq!(permuted.txid(), canonical.txid());

        if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut permuted {
            canonicalize_witness_table(keys, inputs);
        }
        // The whole transaction, equal — bytes, and therefore every field
        // the charge derives from (keys.len(), tx_bytes, tip).
        assert_eq!(permuted, canonical);

        // And it is the encoding consensus admits, with the same charge and
        // the same post-state as the built-ordered original.
        let mut s1 = g.clone();
        let charge1 = s1.apply_transfer_v2(&canonical, price, &ToyVerifier).unwrap();
        let mut s2 = g.clone();
        let charge2 = s2.apply_transfer_v2(&permuted, price, &ToyVerifier).unwrap();
        assert_eq!(charge1, charge2);
        assert_eq!(s1.eutxos, s2.eutxos);
    }

    /// **Tripwire: the order rule has NO flag day of its own.** There is no
    /// new activation constant to pin, and that absence is the design: the
    /// check lives inside `apply_transfer_v2`, reachable only through the
    /// `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` gate in `apply_transaction`
    /// — so pre-activation, a permuted V2 in a block dies at the GATE
    /// (`FormatNotActive`), never at the order rule. The control at the
    /// post-activation seam: the SAME transaction, applied directly, IS
    /// refused by the order rule — proving the rule exists and sits strictly
    /// behind the gate, i.e. it activates on the dedup flag day and no
    /// other. Companion to `transfer_v2_activation_is_paired_with_the_block_cap`.
    #[test]
    fn the_order_rule_activates_on_the_dedup_flag_day_not_its_own() {
        let a = owner_key(0x7A);
        let b = owner_key(0x7B);
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let to = script_of(&owner_key(0x7C));
        let coin_lo = opening(0x98, 0, 50_000_000, &lo);
        let coin_hi = opening(0x99, 0, 50_000_000, &hi);
        let (t, g, mut chains) = setup_funded(4, &[coin_lo.clone(), coin_hi.clone()]);
        let price = g.next_base_fee();

        let canonical = transfer_v2_raw(
            &[coin_lo.clone(), coin_hi.clone()],
            &[&lo, &hi],
            &[0, 1],
            to,
            512,
            1,
            price,
        );
        let mut permuted = canonical.clone();
        if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut permuted {
            keys.swap(0, 1);
            for i in inputs.iter_mut() {
                i.key_index ^= 1;
            }
        }

        // Block path, pre-flag-day: the gate speaks, not the order rule.
        let env = probe_env(&g, 1, std::slice::from_ref(&permuted), &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&permuted)).unwrap_err(),
            TransitionError::Transfer(0, TransferReject::FormatNotActive),
        );

        // Post-activation seam: the same bytes die on the order rule.
        assert_eq!(
            g.clone().apply_transfer_v2(&permuted, price, &ToyVerifier),
            Err(TransferReject::WitnessTableNotCanonical),
        );
    }
    // ── Funded staking: the eUTXO-backed bond lifecycle (flag day) ──────────

    /// A validator pubkey shaped the way consensus demands: the `B1 0C`
    /// envelope, the 0x0001 hybrid suite id, and exactly
    /// [`staking::HYBRID_PK_BYTES`] of body.
    fn wire_validator_key(tag: u8) -> Vec<u8> {
        let mut v = vec![0xB1, 0x0C, 0x01, 0x00];
        v.extend(std::iter::repeat(tag).take(staking::HYBRID_PK_BYTES));
        v
    }

    /// A conserving funded deposit bonding `amount_sat` out of `entries`,
    /// change back to the owner, toy-signed. The fee is computed with the
    /// SAME `fee_market::charge` call the transition makes (class
    /// `inputs + 1` — the PoP), so the fixture keeps conserving when a gas
    /// constant moves. PoP is produced BEFORE the input signatures because
    /// the spend root covers it — the same ordering a real wallet must use.
    fn funded_deposit_spending(
        entries: &[crate::state_root::EutxoEntry],
        owner: &[u8],
        amount_sat: u128,
        val_key_tag: u8,
        price: u128,
    ) -> PosTransaction {
        let inputs: Vec<TransferInput> = entries
            .iter()
            .map(|e| TransferInput {
                txid: e.txid,
                vout: e.vout,
                pubkey: owner.to_vec(),
                // Right length: toy signatures are 32 B, so the encoding's
                // size — and with it the fee — is fixed before signing.
                signature: vec![0u8; 32],
            })
            .collect();
        let spent: u128 = entries.iter().map(|e| e.value as u128).sum();
        let mut tx = PosTransaction::FundedDeposit {
            inputs,
            change: vec![TransferOutput { value: 0, script_hash: script_of(owner) }],
            pubkey: wire_validator_key(val_key_tag),
            amount_sat,
            randao_commitment: [0xAB; 32],
            withdrawal_credentials: vec![0xCD; 32],
            commission_bps: 500,
            proof_of_possession: vec![0u8; 32],
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        };
        let len = tx.canonical_bytes().len() as u64;
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: entries.len() as u32 + 1 },
            len,
            price,
            0,
        );
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        assert!(
            spent >= amount_sat + fee,
            "fixture underfunded: {spent} sat cannot bond {amount_sat} and pay {fee}"
        );
        let change_value = (spent - amount_sat - fee) as u64;
        if let PosTransaction::FundedDeposit { tx_bytes, change, .. } = &mut tx {
            *tx_bytes = len;
            change[0].value = change_value;
        }
        resign_funded(&mut tx, owner);
        tx
    }

    /// Re-sign a funded deposit after a test edited it: fresh PoP over the
    /// DS_DEPOSIT root, then fresh input signatures over the DS_SPEND root
    /// that covers that PoP. Same rationale as [`resign`]: a test that means
    /// to break conservation must not break the signatures as well and pass
    /// for the wrong reason.
    fn resign_funded(tx: &mut PosTransaction, owner: &[u8]) {
        let pop_root = tx
            .funded_deposit_pop_signing_root()
            .expect("fixture must keep the well-formed pubkey/credential shape");
        if let PosTransaction::FundedDeposit { proof_of_possession, pubkey, .. } = tx {
            *proof_of_possession = toy_sign(pubkey, &pop_root);
        }
        let root = tx.spend_signing_root();
        if let PosTransaction::FundedDeposit { inputs, .. } = tx {
            for i in inputs.iter_mut() {
                i.signature = toy_sign(owner, &root);
            }
        }
    }

    /// The spend root binds the registration payload and the fee terms, and
    /// deliberately does NOT bind the witnesses — the mirror of
    /// `deposit_signing_root_binds_every_field` (staking.rs) for the funded
    /// wire shape. The witness half is the control: without it, "every edit
    /// moves the root" would also pass for a root over the full encoding,
    /// which is precisely the malleable-txid construction this root exists
    /// to rule out.
    #[test]
    fn funded_deposit_spend_root_binds_everything_but_the_witnesses() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let base = funded_deposit_spending(
            &[entry],
            &owner,
            staking::MIN_DEPOSIT_SAT,
            0x77,
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
        );
        let root = base.spend_signing_root();

        // Every signed field moves the root.
        let mut edits: Vec<PosTransaction> = Vec::new();
        for k in 0..8 {
            let mut e = base.clone();
            if let PosTransaction::FundedDeposit {
                inputs,
                change,
                pubkey,
                amount_sat,
                randao_commitment,
                withdrawal_credentials,
                commission_bps,
                proof_of_possession,
                tx_bytes,
                tip_millisat_per_gas,
            } = &mut e
            {
                match k {
                    0 => inputs[0].vout ^= 1,
                    1 => change[0].value ^= 1,
                    2 => pubkey[4] ^= 1,
                    3 => *amount_sat ^= 1,
                    4 => randao_commitment[0] ^= 1,
                    5 => withdrawal_credentials[0] ^= 1,
                    6 => *commission_bps ^= 1,
                    7 => {
                        proof_of_possession[0] ^= 1;
                        *tx_bytes ^= 1;
                        *tip_millisat_per_gas ^= 1;
                    }
                    _ => unreachable!(),
                }
            }
            edits.push(e);
        }
        for (k, e) in edits.iter().enumerate() {
            assert_ne!(
                e.spend_signing_root(),
                root,
                "edit {k} did not move the spend root — that field is unsigned"
            );
        }

        // Control: the witnesses do NOT move it (the root must be computable
        // before the signatures exist), and the txid stays put with them.
        let mut w = base.clone();
        if let PosTransaction::FundedDeposit { inputs, .. } = &mut w {
            inputs[0].pubkey = owner_key(9);
            inputs[0].signature = vec![0xFF; 64];
        }
        assert_eq!(w.spend_signing_root(), root, "a witness edit must not move the root");
        assert_eq!(w.txid(), base.txid(), "re-encoded witnesses must not move the txid");
    }

    /// Rule 1 of the flag day: with the shipped `u64::MAX` gate, none of the
    /// funded shapes can touch state — and the refusal leaves the state
    /// byte-identical. The control half applies THE SAME transaction through
    /// the gated inner form with the gate at epoch 0 and it lands, which
    /// proves the refusal above is the gate and not some other rule.
    #[test]
    fn funded_shapes_are_consensus_invalid_before_the_flag_day() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let deposit = funded_deposit_spending(&[entry], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price);

        for tx in [
            deposit.clone(),
            PosTransaction::SignedExit { validator: 0, epoch: 0, signature: vec![1] },
            PosTransaction::Withdraw { validator: 0 },
        ] {
            let mut st = g.clone();
            assert_eq!(
                // The REAL dispatch, real constant: this is the arm
                // compute_post_state runs for every block on the live chain.
                st.apply_transaction(&tx, 0, price, &ToyVerifier),
                Err(TxReject::StakingRule),
                "a funded shape must be consensus-invalid while the gate is closed"
            );
            assert_eq!(st, g, "a refused transaction must leave the state untouched");
        }

        // Control: same deposit, gate armed at epoch 0 — it applies.
        let mut st = g.clone();
        st.apply_transaction_gated(&deposit, 0, price, &ToyVerifier, 0)
            .expect("the identical transaction must apply once the gate is open");
        assert_ne!(st, g, "the control half must actually change state");
    }

    /// The other side of the flag day: from the gate epoch on, the legacy
    /// unfunded discriminants are consensus-invalid in block bodies — THE
    /// refusal that closes the modified-proposer mint. Control: the same
    /// messages under the shipped (closed) gate still apply, which is also
    /// what keeps every pre-gate block replayable.
    #[test]
    fn legacy_staking_shapes_become_invalid_at_the_flag_day() {
        let (_t, g, _c) = setup(4);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let legacy = [
            PosTransaction::Deposit {
                pubkey: vec![0xAA; 8],
                amount_sat: staking::MIN_DEPOSIT_SAT,
                randao_commitment: [0xBB; 32],
                withdrawal_credentials: vec![0xCC; 4],
                commission_bps: 500,
            },
            PosTransaction::Exit { validator: 0 },
            PosTransaction::Delegate {
                delegator: 9,
                validator: 0,
                amount_sat: delegation::MIN_DELEGATION_SAT,
                eligible: true,
            },
        ];
        for tx in &legacy {
            // Control first: pre-gate (the shipped constant) they apply.
            let mut st = g.clone();
            st.apply_transaction(tx, 0, price, &OkVerifier)
                .expect("control failed: the legacy shape must still apply pre-gate");
            // Post-gate they are invalid, and the state stays untouched.
            let mut st = g.clone();
            assert_eq!(
                st.apply_transaction_gated(tx, 0, price, &OkVerifier, 0),
                Err(TxReject::StakingRule),
                "a legacy staking shape must be consensus-invalid past the gate"
            );
            assert_eq!(st, g);
        }
    }

    /// The deposit half of the conservation contract:
    /// `Σ inputs == amount + Σ change + fee`, enforced exactly — and the bond
    /// that appears in the registry is backed satoshi-for-satoshi by coins
    /// that left the committed set, with `issued_sat` untouched.
    #[test]
    fn funded_deposit_moves_coins_into_the_bond_and_conserves_value() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;
        let tx = funded_deposit_spending(&[entry], &owner, amount, 0x77, price);

        let pool_before: u128 = g.eutxos.values().map(|e| e.value as u128).sum();
        let mut st = g.clone();
        let charge = st
            .apply_transaction_gated(&tx, 0, price, &ToyVerifier, 0)
            .expect("a conserving, honestly signed deposit must apply");
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        assert!(fee > 0, "fixture vacuous: a zero fee cannot distinguish the equality");

        // The equality, measured on the committed set: exactly amount + fee
        // left it (the change came back).
        let pool_after: u128 = st.eutxos.values().map(|e| e.value as u128).sum();
        assert_eq!(pool_before - pool_after, amount + fee);
        // The bond holds exactly the amount, queued like any legacy deposit.
        let rec = st.validators.get(&4).expect("the deposit must register index 4");
        assert_eq!(rec.staked_sat, amount);
        assert_eq!(rec.activation_epoch, u64::MAX, "queued, not scheduled");
        assert_eq!(rec.withdrawal_credentials, vec![0xCD; 32]);
        // The change output landed under the derived txid.
        assert!(st.eutxos.contains_key(&(tx.txid(), 0)));
        // A bond move is a move: nothing was issued.
        assert_eq!(st.issued_sat, g.issued_sat, "a funded deposit must not touch issuance");
        // Its history entry is stamped with the including epoch, which (>= the
        // gate by construction) is what marks the bond FUNDED for withdrawal.
        assert_eq!(st.deposit_history.last().unwrap().amount_sat, amount);
        assert_eq!(st.deposit_history.last().unwrap().deposit_epoch, 0);
        assert_eq!(st.withdrawable_sat_gated(4, 0), amount, "a funded bond is fully withdrawable");

        // The negative half: one satoshi of imbalance, signatures HONESTLY
        // re-produced over the edited content, and the equality itself
        // refuses.
        let mut off = tx.clone();
        if let PosTransaction::FundedDeposit { change, .. } = &mut off {
            change[0].value += 1;
        }
        resign_funded(&mut off, &owner);
        let mut st2 = g.clone();
        assert_eq!(
            st2.apply_transaction_gated(&off, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::ValueNotConserved)),
            "one satoshi out of balance must be refused by conservation, not by a signature"
        );
        assert_eq!(st2, g);

        // And the funded validator walks the SAME activation pipeline as
        // every legacy one: eligible after the delay, admitted by the queue.
        let mut walked = st.clone();
        while walked.epoch < staking::ACTIVATION_DELAY_EPOCHS + 1 {
            walked = t.process_epoch(&walked).unwrap();
        }
        assert_eq!(
            walked.validators.get(&4).unwrap().activation_epoch,
            staking::ACTIVATION_DELAY_EPOCHS,
            "a funded deposit activates through the unchanged epoch pipeline"
        );
    }

    /// Signature and registration negatives, each with its passing twin in
    /// the test above (the honestly-signed deposit that applied).
    #[test]
    fn funded_deposit_signature_and_registration_negatives() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let good = funded_deposit_spending(&[entry], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price);

        // Control, restated locally: the honest twin applies.
        let mut st = g.clone();
        st.apply_transaction_gated(&good, 0, price, &ToyVerifier, 0).expect("control");

        // A corrupted input signature: refused by the transfer's own rule.
        let mut bad_sig = good.clone();
        if let PosTransaction::FundedDeposit { inputs, .. } = &mut bad_sig {
            bad_sig_flip(&mut inputs[0].signature);
        }
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&bad_sig, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::BadSignature)),
        );

        // A thief's key: hashes to the wrong script, refused before any
        // verification runs — even though the thief signed honestly with the
        // key it presented.
        let thief = owner_key(13); // same length as owner_key(3), so the size floor stays satisfied
        let mut stolen = good.clone();
        if let PosTransaction::FundedDeposit { inputs, .. } = &mut stolen {
            inputs[0].pubkey = thief.clone();
        }
        resign_funded(&mut stolen, &thief);
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&stolen, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::ScriptMismatch)),
        );

        // A garbage PoP the owners signed over: the coins' movement is
        // authorised, the REGISTRATION is what refuses — the rogue-key door.
        let mut rogue = good.clone();
        if let PosTransaction::FundedDeposit { proof_of_possession, .. } = &mut rogue {
            *proof_of_possession = vec![0xEE; 32];
        }
        // Re-sign the INPUTS only (over the root covering the garbage PoP);
        // deliberately not resign_funded, which would fix the PoP too.
        let root = rogue.spend_signing_root();
        if let PosTransaction::FundedDeposit { inputs, .. } = &mut rogue {
            for i in inputs.iter_mut() {
                i.signature = toy_sign(&owner, &root);
            }
        }
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&rogue, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "a deposit whose PoP does not verify must not register"
        );

        // The ML-DSA-only escape hatch, smuggled in the envelope: refused as
        // a registration rule before any signature is checked.
        let mut half_suite = good.clone();
        if let PosTransaction::FundedDeposit { pubkey, .. } = &mut half_suite {
            pubkey[2] = 0x02;
        }
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&half_suite, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "only the hybrid suite may enter the registry"
        );
    }

    /// One flipped byte that keeps the length — split out so the borrow on
    /// the enum field ends before the assertion.
    fn bad_sig_flip(sig: &mut [u8]) {
        sig[0] ^= 0xFF;
    }

    /// The founder decision, end to end: a genesis bond withdraws ONLY its
    /// post-genesis accrual; the 25,000-BLOCH principal leaves as
    /// `written_off_sat`, never as coin. The control half is a validator with
    /// the SAME numbers whose bond IS funded (a deposit-history entry at a
    /// post-gate epoch): it withdraws principal plus accrual. Without the
    /// control, the assertions on validator 0 would pass just as well against
    /// a Withdraw that short-paid everyone.
    #[test]
    fn genesis_withdrawal_pays_only_the_post_genesis_accrual() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let accrual = sat(7);

        let mut st = g.clone();
        for v in [0u32, 1] {
            let rec = st.validators.get_mut(&v).unwrap();
            // A genesis-shaped position: unfunded principal plus accrued
            // rewards, exited and past the weak-subjectivity margin.
            rec.staked_sat = GENESIS_UNFUNDED_PRINCIPAL_SAT + accrual;
            rec.exit_epoch = 0;
            rec.withdrawable_epoch = 0;
            rec.withdrawal_credentials = vec![0xE0 + v as u8; 32];
        }
        // Validator 1 is the funded twin: its history says real coins backed
        // the whole principal (deposit_epoch 0 >= gate 0 ⇒ funded).
        let funded_hash: [u8; 32] =
            Sha3_256::digest(&st.validators.get(&1).unwrap().pubkey).into();
        st.deposit_history.push(QueuedDeposit {
            pubkey_hash: funded_hash,
            deposit_epoch: 0,
            amount_sat: GENESIS_UNFUNDED_PRINCIPAL_SAT + accrual,
        });

        let issued_before = st.issued_sat;

        // The genesis bond: payout = accrual, write-off = the principal.
        let wd0 = PosTransaction::Withdraw { validator: 0 };
        let charge = st
            .apply_transaction_gated(&wd0, 0, price, &ToyVerifier, 0)
            .expect("an exited genesis bond with accrual must withdraw");
        assert_eq!(
            charge.base_fee_sat + charge.priority_fee_sat,
            0,
            "a withdrawal settles no fee — see the variant docs"
        );
        assert!(
            charge.gas > 0 && charge.tx_bytes > 0,
            "but its bytes and gas are priced against both block caps"
        );
        let out = st.eutxos.get(&(wd0.txid(), 0)).expect("the withdrawal must create an output");
        assert_eq!(out.value as u128, accrual, "only the accrual becomes coin");
        assert_eq!(out.script_hash, [0xE0; 32], "paid to the registered credential");
        assert_eq!(
            st.validators.get(&0).unwrap().staked_sat,
            0,
            "the record is closed, not left holding a residue"
        );
        assert_eq!(
            st.written_off_sat,
            GENESIS_UNFUNDED_PRINCIPAL_SAT,
            "the unfunded principal leaves as an audit entry, never as coin"
        );

        // The funded twin: SAME numbers, whole bond pays, nothing written off.
        let written_off_after_genesis = st.written_off_sat;
        let wd1 = PosTransaction::Withdraw { validator: 1 };
        st.apply_transaction_gated(&wd1, 0, price, &ToyVerifier, 0)
            .expect("control: the funded twin must withdraw");
        let out = st.eutxos.get(&(wd1.txid(), 0)).expect("control output");
        assert_eq!(
            out.value as u128,
            GENESIS_UNFUNDED_PRINCIPAL_SAT + accrual,
            "control: a funded bond withdraws principal AND accrual"
        );
        assert_eq!(st.validators.get(&1).unwrap().staked_sat, 0);
        assert_eq!(
            st.written_off_sat, written_off_after_genesis,
            "control: a funded bond writes nothing off"
        );
        // The gap between the two payouts IS the write-off.
        assert_eq!(
            (GENESIS_UNFUNDED_PRINCIPAL_SAT + accrual) - accrual,
            GENESIS_UNFUNDED_PRINCIPAL_SAT,
        );

        // Conservation phase of the runbook: two withdrawals, zero issuance.
        assert_eq!(st.issued_sat, issued_before, "a withdrawal moves value, never issues it");

        // Single-shot: both closed records refuse a replay.
        for wd in [&wd0, &wd1] {
            let before = st.clone();
            assert_eq!(
                st.apply_transaction_gated(wd, 0, price, &ToyVerifier, 0),
                Err(TxReject::StakingRule),
                "a second withdrawal must be a deterministic reject"
            );
            assert_eq!(st, before);
        }
    }

    /// The clock and the eligibility rejects around Withdraw, each with the
    /// twin that passes one epoch (or one fact) later.
    #[test]
    fn withdrawal_respects_the_weak_subjectivity_clock() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let wd = PosTransaction::Withdraw { validator: 0 };

        // Never exited: withdrawable_epoch is u64::MAX, refused.
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "a bonded validator that never exited must not withdraw"
        );

        // Exited but one epoch inside the margin: still refused; at the
        // boundary epoch itself: pays. The two halves share every other fact.
        let mut st = g.clone();
        {
            let rec = st.validators.get_mut(&0).unwrap();
            rec.staked_sat = GENESIS_UNFUNDED_PRINCIPAL_SAT + sat(7);
            rec.exit_epoch = 0;
            rec.withdrawable_epoch = 1;
            rec.withdrawal_credentials = vec![0xE7; 32];
        }
        assert_eq!(
            st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "the weak-subjectivity margin must hold to the epoch"
        );
        st.epoch = 1;
        st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0)
            .expect("control: at the boundary the same withdrawal pays");
    }

    /// SignedExit: the signature decides, the roster consequences follow the
    /// legacy arm exactly, and a replayed or future-dated message is refused.
    #[test]
    fn signed_exit_requires_the_registered_keys_signature() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let rec_pubkey = g.validators.get(&0).unwrap().pubkey.clone();
        let root = staking::ExitTx {
            pubkey_hash: Sha3_256::digest(&rec_pubkey).into(),
            epoch: 0,
            signature: Vec::new(),
        }
        .signing_root();

        // Control: signed by the registered key, the exit lands with the
        // legacy arm's exact schedule.
        let good = PosTransaction::SignedExit {
            validator: 0,
            epoch: 0,
            signature: toy_sign(&rec_pubkey, &root),
        };
        let mut st = g.clone();
        let charge = st.apply_transaction_gated(&good, 0, price, &ToyVerifier, 0).expect("control");
        assert_eq!(st.validators.get(&0).unwrap().exit_epoch, staking::EXIT_DELAY_EPOCHS);
        assert_eq!(
            st.validators.get(&0).unwrap().withdrawable_epoch,
            staking::EXIT_DELAY_EPOCHS + staking::WITHDRAWAL_DELAY_EPOCHS
        );
        // Free of fee, but not free of the caps: real bytes, real gas.
        assert_eq!(charge.base_fee_sat + charge.priority_fee_sat, 0);
        assert_eq!(charge.tx_bytes, good.canonical_bytes().len() as u64);
        assert!(charge.gas > 0);
        // A second exit must not reset the clock — same rule as legacy.
        assert_eq!(
            st.apply_transaction_gated(&good, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule)
        );

        // A signature by anyone else is refused, state untouched.
        let forged = PosTransaction::SignedExit {
            validator: 0,
            epoch: 0,
            signature: toy_sign(&owner_key(9), &root),
        };
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&forged, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "an exit not signed by the validator's own key must be refused"
        );
        assert_eq!(st, g);

        // A future-dated exit is refused even correctly signed — the clock
        // must not be decoupled from inclusion time.
        let future_root = staking::ExitTx {
            pubkey_hash: Sha3_256::digest(&rec_pubkey).into(),
            epoch: 5,
            signature: Vec::new(),
        }
        .signing_root();
        let future = PosTransaction::SignedExit {
            validator: 0,
            epoch: 5,
            signature: toy_sign(&rec_pubkey, &future_root),
        };
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&future, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "a pre-signed future exit must be refused at inclusion"
        );
    }

    /// The public accessor under the SHIPPED gate: every genesis bond reads
    /// its stake minus the manifest principal, and the number is exactly what
    /// the RPC surface reports. (The armed-gate arithmetic is covered by the
    /// withdrawal tests above through the gated form.)
    #[test]
    fn withdrawable_sat_writes_off_the_genesis_principal_under_the_shipped_gate() {
        let (_t, g, _c) = setup(4);
        // Fixture bonds are 200,000 BLOCH; the write-off is 25,000.
        assert_eq!(g.withdrawable_sat(0), sat(200_000) - GENESIS_UNFUNDED_PRINCIPAL_SAT);
        // An unknown index reads zero rather than panicking.
        assert_eq!(g.withdrawable_sat(999), 0);
    }

    /// THE attack the write-off invites, refused by name: relabel a genesis
    /// bond as funded by re-depositing under its registered pubkey, so the
    /// history lookup finds a post-gate entry and the 25,000-BLOCH write-off
    /// evaporates. It dies at registration — `pubkey_index` makes a second
    /// deposit of a registered key a deterministic reject — and the pinned
    /// half is that the write-off DID NOT MOVE. The control twin is the
    /// byte-for-byte same deposit under a fresh key: it registers, and its
    /// bond is fully withdrawable (unbacked = 0), proving the reject was
    /// about the key reuse and nothing else in the transaction.
    #[test]
    fn a_genesis_bond_cannot_be_relabelled_funded_by_reusing_its_pubkey() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;

        // Give validator 0 the wire-form key a real manifest would carry —
        // registry AND derived index together, exactly as `genesis` seeds
        // them — so the attack reaches the pubkey rule instead of dying on
        // the fixture's 8-byte toy key at the suite-shape check.
        let mut st = g.clone();
        let wire = wire_validator_key(0x77);
        let old_hash: [u8; 32] = Sha3_256::digest(&st.validators.get(&0).unwrap().pubkey).into();
        st.pubkey_index.remove(&old_hash);
        st.validators.get_mut(&0).unwrap().pubkey = wire.clone();
        st.pubkey_index.insert(Sha3_256::digest(&wire).into(), 0);

        // The write-off, before: no history entry, so the full genesis
        // principal is unbacked.
        let unbacked_before = st.validators.get(&0).unwrap().staked_sat
            - st.withdrawable_sat_gated(0, 0);
        assert_eq!(unbacked_before, GENESIS_UNFUNDED_PRINCIPAL_SAT);

        // The attack: a conserving, honestly signed funded deposit whose
        // validator key is the genesis validator's registered key (same tag
        // 0x77 ⇒ same wire bytes).
        let attack =
            funded_deposit_spending(&[entry.clone()], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price);
        let before = st.clone();
        assert_eq!(
            st.apply_transaction_gated(&attack, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "a second deposit of a registered key must be a deterministic reject"
        );
        assert_eq!(st, before, "a refused deposit must leave the state untouched");
        // The pinned half: the write-off did not move — no history entry was
        // created, so the genesis principal is exactly as unbacked as before.
        assert_eq!(
            st.validators.get(&0).unwrap().staked_sat - st.withdrawable_sat_gated(0, 0),
            GENESIS_UNFUNDED_PRINCIPAL_SAT,
            "the attack must not shrink the unbacked principal"
        );

        // Control twin: the same deposit under a FRESH key registers, and
        // its bond carries no write-off at all.
        let honest =
            funded_deposit_spending(&[entry], &owner, staking::MIN_DEPOSIT_SAT, 0x78, price);
        st.apply_transaction_gated(&honest, 0, price, &ToyVerifier, 0)
            .expect("control: the fresh-key twin must register");
        assert_eq!(
            st.withdrawable_sat_gated(4, 0),
            staking::MIN_DEPOSIT_SAT,
            "control: a funded bond is fully withdrawable — unbacked = 0"
        );
    }

    /// The full funded life cycle against one ledger: deposit → signed exit
    /// → withdrawal, with conservation asserted at every hop. The invariant
    /// is `eUTXO pool + bonded stake`, which may fall ONLY by the two fees
    /// (the exit is deliberately fee-settled at zero), and `issued_sat`,
    /// which may not move at all — coin enters the stake by leaving the
    /// eUTXO set and re-enters the eUTXO set by leaving the stake, and no
    /// hop may create or destroy a satoshi outside the fee split.
    #[test]
    fn funded_round_trip_conserves_value_and_never_issues() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;

        let pool = |st: &CommittedState| -> u128 {
            st.eutxos.values().map(|e| e.value as u128).sum()
        };
        let bonded = |st: &CommittedState| -> u128 {
            st.validators.values().map(|r| r.staked_sat).sum()
        };

        let mut st = g.clone();
        let (pool0, bonded0, issued0) = (pool(&st), bonded(&st), st.issued_sat);

        // ── Deposit: coin leaves the set, the bond gains exactly `amount`.
        let dep = funded_deposit_spending(&[entry], &owner, amount, 0x77, price);
        let charge = st
            .apply_transaction_gated(&dep, 0, price, &ToyVerifier, 0)
            .expect("the deposit must apply");
        let fee_d = charge.base_fee_sat + charge.priority_fee_sat;
        assert!(fee_d > 0, "fixture vacuous with a zero deposit fee");
        assert_eq!(pool(&st), pool0 - amount - fee_d);
        assert_eq!(bonded(&st), bonded0 + amount);

        // ── Signed exit: schedules the clocks, moves NO value.
        // Activation is hand-rolled here — the queue's own pipeline is
        // proven in `funded_deposit_moves_coins_into_the_bond_...`.
        st.validators.get_mut(&4).unwrap().activation_epoch = 0;
        let rec_pubkey = st.validators.get(&4).unwrap().pubkey.clone();
        let root = staking::ExitTx {
            pubkey_hash: Sha3_256::digest(&rec_pubkey).into(),
            epoch: 0,
            signature: Vec::new(),
        }
        .signing_root();
        let exit = PosTransaction::SignedExit {
            validator: 4,
            epoch: 0,
            signature: toy_sign(&rec_pubkey, &root),
        };
        let (pool1, bonded1) = (pool(&st), bonded(&st));
        let charge = st
            .apply_transaction_gated(&exit, 0, price, &ToyVerifier, 0)
            .expect("the signed exit must apply");
        assert_eq!(charge.base_fee_sat + charge.priority_fee_sat, 0, "an exit settles no fee");
        assert_eq!(pool(&st), pool1, "an exit moves no coin");
        assert_eq!(bonded(&st), bonded1, "an exit unbonds nothing by itself");

        // ── Withdrawal, at the scheduled epoch: the whole funded bond comes
        // back as one output. It settles NO fee — see the `Withdraw` variant
        // docs: a fee floor would make a zero-payout bond unclosable and its
        // write-off unrecordable — but its bytes and gas are still charged
        // against both block caps.
        let wd_epoch = st.validators.get(&4).unwrap().withdrawable_epoch;
        assert_eq!(
            wd_epoch,
            staking::EXIT_DELAY_EPOCHS + staking::WITHDRAWAL_DELAY_EPOCHS,
            "the two delays compose"
        );
        st.epoch = wd_epoch;
        let wd = PosTransaction::Withdraw { validator: 4 };
        let charge = st
            .apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0)
            .expect("the withdrawal must pay");
        assert_eq!(
            charge.base_fee_sat + charge.priority_fee_sat,
            0,
            "a withdrawal settles no fee"
        );
        assert!(
            charge.gas > 0 && charge.tx_bytes > 0,
            "but it is priced against both block caps — free block space is a stuffing vector"
        );
        let out = st.eutxos.get(&(wd.txid(), 0)).expect("the payout output");
        assert_eq!(out.value as u128, amount, "a funded bond withdraws in full");
        assert_eq!(out.script_hash, [0xCD; 32], "paid to the registered credential");
        assert_eq!(
            st.written_off_sat, 0,
            "a bond funded with real coins writes nothing off"
        );

        // ── The ledger, end to end: the DEPOSIT fee is the only leak, and
        // nothing was issued anywhere in the cycle.
        assert_eq!(bonded(&st), bonded0, "the bond came all the way back out");
        assert_eq!(pool(&st), pool0 - fee_d);
        assert_eq!(
            pool(&st) + bonded(&st),
            pool0 + bonded0 - fee_d,
            "conservation: the cycle leaks exactly the deposit's fee"
        );
        assert_eq!(st.issued_sat, issued0, "no hop of the cycle may issue");
    }


    /// The write-off is DERIVED from `deposit_history`, not stored: a funded
    /// bond is funded because its history entry says so, and the field docs
    /// promise the history is kept forever. This test makes that coupling
    /// executable — erase a funded validator's entry and the derivation
    /// silently reclassifies the bond as genesis-class, 25,000 BLOCH written
    /// off. Any future pruning of the history must confront this test by
    /// name; "the history is the input, not a cache to prune" is load-bearing
    /// for coins now, not only for activation order.
    #[test]
    fn the_write_off_derivation_depends_on_history_immortality() {
        let owner = owner_key(3);
        // Bond ABOVE the genesis principal so the reclassified number is
        // distinguishable from zero (MIN_DEPOSIT_SAT is exactly the genesis
        // bond size, so a minimum bond would read 0 either way).
        let amount = staking::MIN_DEPOSIT_SAT + sat(1_000);
        let entry = opening(0x51, 0, amount as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        assert!(amount > GENESIS_UNFUNDED_PRINCIPAL_SAT);

        let mut st = g.clone();
        let dep = funded_deposit_spending(&[entry], &owner, amount, 0x77, price);
        // Enough committed active stake that the 1% per-validator cap clears
        // the above-minimum bond — the cap itself is another test's subject.
        let active = sat(3_000_000);
        st.apply_transaction_gated(&dep, active, price, &ToyVerifier, 0).expect("deposit");
        assert_eq!(st.withdrawable_sat_gated(4, 0), amount, "control: funded, no write-off");

        // The hypothetical prune — exactly what the field docs forbid.
        let hash = st.deposit_history.last().unwrap().pubkey_hash;
        st.deposit_history.retain(|d| d.pubkey_hash != hash);
        assert_eq!(
            st.withdrawable_sat_gated(4, 0),
            amount - GENESIS_UNFUNDED_PRINCIPAL_SAT,
            "with its history gone the same bond silently loses the genesis write-off"
        );
    }

    /// The saturation in `withdrawable_sat_gated` is a consensus claim, not
    /// decoration: slashing consumes the withdrawable accrual BEFORE the
    /// notional principal, so a genesis bond slashed below 25,000 BLOCH must
    /// read zero — a plain subtraction would underflow (a debug panic on a
    /// consensus read path, a wrapped near-u128::MAX "withdrawable" in
    /// release). This test exists because the 2026-08-22 mutation run proved
    /// the rest of the suite survives that exact substitution.
    #[test]
    fn a_bond_slashed_below_its_unbacked_principal_reads_zero_not_underflow() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let mut st = g.clone();
        // A slash that ate through the accrual and into the principal.
        st.validators.get_mut(&0).unwrap().staked_sat = GENESIS_UNFUNDED_PRINCIPAL_SAT - sat(1);
        assert_eq!(st.withdrawable_sat_gated(0, 0), 0, "saturates at zero, never wraps");
        // The SHIPPED gate derives the same unbacked principal for a
        // history-less record, so the public accessor must saturate too.
        assert_eq!(st.withdrawable_sat(0), 0);
        // Control: one satoshi above the principal reads exactly one satoshi,
        // so the zero above is saturation and not some unrelated short-circuit.
        st.validators.get_mut(&0).unwrap().staked_sat = GENESIS_UNFUNDED_PRINCIPAL_SAT + 1;
        assert_eq!(st.withdrawable_sat_gated(0, 0), 1);
    }

    // ── The write-off's HISTORY: the low-water mark ─────────────────────────

    /// A double vote by `v` under a distinguishing `tag`, so a second offence
    /// by the same validator is a DIFFERENT evidence id and is not refused by
    /// the applied-evidence dedup. Without this, "slash twice" tests silently
    /// become "slash once".
    fn double_vote_evidence_tagged(v: u32, tag: u8) -> SlashingEvidence {
        let data = |head: u8| AttestationData {
            slot: 32,
            head: [head; 32],
            source_epoch: 0,
            source_root: [tag; 32],
            target_epoch: 1,
            target_root: [head; 32],
        };
        SlashingEvidence::AttestationOffence {
            first: Attestation { data: data(0xAA), validator: v, signature: vec![0u8; 8] },
            second: Attestation { data: data(0xBB), validator: v, signature: vec![0u8; 8] },
        }
    }

    /// THE RECORDER. A slash — and only a slash — writes a bond's low-water
    /// mark, and untouched validators keep `None`. "Absent" and "recorded"
    /// have to stay distinguishable, because the indeterminate class is
    /// defined by exactly that difference.
    #[test]
    fn a_slash_records_the_bonds_low_water_mark_and_nothing_else_moves_it() {
        let (_t, g, _c) = setup(4);
        let offender = 3u32;
        let total_active: u128 = 4 * sat(200_000);

        assert_eq!(
            g.stake_low_water_sat(offender),
            None,
            "control failed: a fresh bond must have no recorded floor"
        );

        let mut st = g.clone();
        st.apply_slashing_evidence(
            &double_vote_evidence_tagged(offender, 0x01),
            0,
            total_active,
            &OkVerifier,
        )
        .unwrap();

        let floor = st.stake_low_water_sat(offender).expect("the slash must record a floor");
        assert_eq!(
            floor,
            st.validators.get(&offender).unwrap().staked_sat,
            "the floor is the stake left AFTER the penalty"
        );
        for other in [0u32, 1, 2] {
            assert_eq!(
                st.stake_low_water_sat(other),
                None,
                "an untouched bond must keep None, not Some(stake)"
            );
        }

        // A reward boundary raises `staked_sat`; the mark must hold.
        let after = st.close_epoch();
        assert_eq!(
            after.stake_low_water_sat(offender),
            Some(floor),
            "rewards must not lift a recorded floor"
        );
    }

    /// The `min` in [`CommittedState::fold_low_water`] cannot be reached from
    /// a block today — a validator is ejected on its first offence, so the
    /// recorder runs once per bond and `min` collapses to assignment on every
    /// reachable path. Feeding a second reduction to the pure function
    /// directly is the only way to make that branch fail when it is broken.
    #[test]
    fn the_low_water_fold_keeps_the_minimum_across_repeated_reductions() {
        // No floor yet: this reduction IS the history.
        assert_eq!(CommittedState::fold_low_water(None, sat(90)), sat(90));
        // A deeper reduction lowers it.
        assert_eq!(CommittedState::fold_low_water(Some(sat(90)), sat(40)), sat(40));
        // A shallower one does NOT lift it — the branch that is unreachable
        // from a block and is exactly what a broken `min` would get wrong.
        assert_eq!(CommittedState::fold_low_water(Some(sat(40)), sat(70)), sat(40));
        // Zero is a real floor, distinct from "no floor".
        assert_eq!(CommittedState::fold_low_water(Some(sat(40)), 0), 0);
    }

    /// THE MEASUREMENT THAT CHOSE THE FLOOR (2026-08-23). A genesis bond is
    /// slashed BELOW nothing in particular, then earns real rewards on top.
    /// The emitted coin in that bond is exactly the post-slash accrual, and
    /// that is what the withdrawal must pay.
    ///
    /// Without the `stake_low_water` floor the rule subtracts the WHOLE
    /// registered principal anyway, which charges the slash's burn a second
    /// time — and the second charge lands on rewards the operator really
    /// earned. Measured on the unfloored code: principal 25,000, slash
    /// −5,000, rewards +10,000 paid 5,000 where 10,000 was owed. This test is
    /// the executable form of that measurement; it fails by exactly the burn
    /// if the floor is removed.
    #[test]
    fn slash_below_principal_then_reaccumulate_pays_exactly_the_emitted_excess() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let p = GENESIS_UNFUNDED_PRINCIPAL_SAT;
        let burn = sat(5_000);
        let reward = sat(10_000);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;

        let mut st = g.clone();
        {
            let rec = st.validators.get_mut(&0).unwrap();
            // The bond starts at exactly its (all-phantom) principal.
            rec.staked_sat = p;
        }
        // A slash cuts into the phantom principal and records the floor.
        st.stake_low_water.insert(0, p - burn);
        {
            let rec = st.validators.get_mut(&0).unwrap();
            // Then REAL, emitted rewards rebuild the bond above the floor.
            rec.staked_sat = p - burn + reward;
            rec.exit_epoch = 0;
            rec.withdrawable_epoch = 0;
            rec.withdrawal_credentials = vec![0xE0; 32];
        }

        assert_eq!(
            st.withdrawable_sat_gated(0, 0),
            reward,
            "the floored write-off must pay exactly the emitted excess"
        );
        // The control that names the bug: unfloored, the same bond reads
        // `reward - burn`, i.e. the burn charged twice.
        assert_eq!(
            (p - burn + reward) - p,
            reward - burn,
            "control: this is what the unfloored rule would have paid"
        );

        let issued_before = st.issued_sat;
        let wd = PosTransaction::Withdraw { validator: 0 };
        st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0)
            .expect("the slashed-then-regrown bond must withdraw");
        let out = st.eutxos.get(&(wd.txid(), 0)).expect("the payout output");
        assert_eq!(out.value as u128, reward, "only the emitted excess becomes coin");
        assert_eq!(st.validators.get(&0).unwrap().staked_sat, 0, "the bond is closed");
        assert_eq!(
            st.written_off_sat,
            p - burn,
            "the write-off is the phantom principal the slash did NOT already burn"
        );
        assert_eq!(st.issued_sat, issued_before, "a withdrawal never issues");
    }

    /// A bond slashed to or below its phantom principal pays ZERO — and the
    /// withdrawal is still VALID: it records the write-off and closes the
    /// record without creating an output. That is what the fee-free pricing
    /// buys; a fee floor would leave exactly these bonds unclosable and their
    /// write-off permanently unrecorded.
    #[test]
    fn a_bond_slashed_to_its_floor_withdraws_zero_and_still_closes() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let floor = sat(3_000);
        let mut st = g.clone();
        st.stake_low_water.insert(0, floor);
        {
            let rec = st.validators.get_mut(&0).unwrap();
            rec.staked_sat = floor;
            rec.exit_epoch = 0;
            rec.withdrawable_epoch = 0;
            rec.withdrawal_credentials = vec![0xE0; 32];
        }
        assert!(floor < GENESIS_UNFUNDED_PRINCIPAL_SAT, "fixture must be below the principal");
        assert_eq!(st.withdrawable_sat_gated(0, 0), 0, "nothing emitted survives");

        let wd = PosTransaction::Withdraw { validator: 0 };
        let charge = st
            .apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0)
            .expect("a zero-payout withdrawal is still a valid withdrawal");
        assert_eq!(charge.base_fee_sat + charge.priority_fee_sat, 0, "settles no fee");
        assert!(charge.gas > 0 && charge.tx_bytes > 0, "but is priced against both caps");
        assert!(
            !st.eutxos.contains_key(&(wd.txid(), 0)),
            "the eUTXO set holds no zero-value entries"
        );
        assert_eq!(st.validators.get(&0).unwrap().staked_sat, 0, "the record is closed");
        assert_eq!(st.written_off_sat, floor, "the whole surviving bond was phantom");

        // Single-shot: the closed record refuses a replay.
        let before = st.clone();
        assert_eq!(
            st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "a second withdrawal must be a deterministic reject"
        );
        assert_eq!(st, before);
    }

    /// THE INDETERMINATE CLASS. A bond slashed by a binary older than the
    /// low-water recorder has no floor to read, so `min(principal, min
    /// staked)` is uncomputable and every available default is wrong in one
    /// direction. The withdrawal is REFUSED rather than guessed at, and the
    /// refusal is deterministic (it reads only committed state) and
    /// reversible (a stuck bond can be released by a later rule; a payout
    /// cannot be unpaid).
    ///
    /// Control half: the SAME bond with a recorded floor withdraws normally,
    /// so the refusal is about the missing history and nothing else.
    #[test]
    fn a_slash_with_no_recorded_floor_refuses_the_withdrawal_instead_of_guessing() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let mut st = g.clone();
        {
            let rec = st.validators.get_mut(&0).unwrap();
            rec.slashed = true; // slashed by a pre-recorder binary
            rec.staked_sat = sat(190_000);
            rec.exit_epoch = 0;
            rec.withdrawable_epoch = 0;
            rec.withdrawal_credentials = vec![0xE0; 32];
        }
        assert!(st.is_write_off_indeterminate(0), "slashed with no mark IS indeterminate");
        assert_eq!(st.write_off_indeterminate_count(), 1);

        let wd = PosTransaction::Withdraw { validator: 0 };
        let before = st.clone();
        assert_eq!(
            st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "an uncomputable write-off must refuse, not guess"
        );
        assert_eq!(st, before, "a refused withdrawal must leave the state untouched");

        // Control: give it the history it was missing and it pays.
        st.stake_low_water.insert(0, sat(190_000));
        assert!(!st.is_write_off_indeterminate(0));
        assert_eq!(st.write_off_indeterminate_count(), 0);
        st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0)
            .expect("control: with a recorded floor the same bond withdraws");

        // And a never-slashed bond is never in the class, mark or no mark.
        assert!(!g.is_write_off_indeterminate(1));
        assert_eq!(g.write_off_indeterminate_count(), 0);
    }

    /// WHY DERIVED AND NOT MATERIALISED. The founder arms the flag day at an
    /// epoch the chain has ALREADY PASSED — an ordinary operational outcome
    /// (agree an epoch, rebuild the fleet, miss it while the rebuild runs).
    ///
    /// A rule that computes the write-off ONCE, on the boundary where
    /// `closing < gate && next >= gate`, never fires in that case: the map
    /// stays empty, every genesis bond reads `unbacked = 0`, and all
    /// 1,600,000 BLOCH of never-emitted principal pays out as spendable coin
    /// — the exact opposite of the decision, and silent. A per-call
    /// derivation has no boundary to miss, which is what this test pins.
    #[test]
    fn arming_the_gate_at_an_epoch_already_passed_still_writes_off() {
        let (_t, g, _c) = setup_funded(4, &[]);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let mut st = g.clone();
        // The chain is at epoch 9; the gate is armed at 3, long behind it.
        // No boundary between 2 and 3 will ever be walked again.
        st.epoch = 9;
        const GATE_ALREADY_PASSED: u64 = 3;
        {
            let rec = st.validators.get_mut(&0).unwrap();
            rec.staked_sat = GENESIS_UNFUNDED_PRINCIPAL_SAT + sat(7);
            rec.exit_epoch = 4;
            rec.withdrawable_epoch = 5;
            rec.withdrawal_credentials = vec![0xE0; 32];
        }
        let wd = PosTransaction::Withdraw { validator: 0 };
        st.apply_transaction_gated(&wd, 0, price, &ToyVerifier, GATE_ALREADY_PASSED)
            .expect("the funded era is open at epoch 9 with the gate at 3");
        let out = st.eutxos.get(&(wd.txid(), 0)).expect("the payout output");
        assert_eq!(
            out.value as u128,
            sat(7),
            "only the accrual — the principal must still be written off"
        );
        assert_eq!(
            st.written_off_sat,
            GENESIS_UNFUNDED_PRINCIPAL_SAT,
            "the write-off happened even though no boundary crossed the gate"
        );
    }

    /// EVERY FUNDED SHAPE IS PRICED AGAINST BOTH BLOCK CAPS.
    ///
    /// The rejected wire shape charged all three funded discriminants `free`
    /// — `gas: 0, tx_bytes: 0` — which is not a fee policy but a hole: a
    /// funded deposit is ~4 KB of PQ witness on this fixture and tens of KB
    /// with real hybrid keys, and a transaction that reports zero bytes and
    /// zero gas consumes block space that neither the byte cap nor the gas
    /// cap can see. On a chain already producing blocks with 0-1
    /// attestations, free bandwidth is the cheapest denial of service there
    /// is.
    ///
    /// So: `gas > 0` and `tx_bytes > 0` for all three, always. The SETTLED
    /// FEE is a separate question and the answers differ on purpose — the
    /// deposit pays one (it moves the depositor's own coin and is repeatable),
    /// the exit and the withdrawal settle none (a locked bond reaches no
    /// spendable coin, and a fee out of a payout would make a zero-payout
    /// bond unclosable), and both are bounded at one per validator per
    /// lifetime.
    ///
    /// The control that makes this non-vacuous: the three LEGACY shapes are
    /// still `free`, which is the pre-existing behaviour this change did not
    /// touch. If a future edit priced them, the live chain's roots would move
    /// outside a flag day.
    #[test]
    fn the_funded_shapes_are_priced_against_both_block_caps() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;

        // 0x07 — the deposit: priced AND fee-settling.
        let dep = funded_deposit_spending(&[entry], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price);
        let mut st = g.clone();
        let c = st
            .apply_transaction_gated(&dep, 0, price, &ToyVerifier, 0)
            .expect("the deposit must apply");
        assert!(c.gas > 0, "0x07 must charge gas");
        assert!(c.tx_bytes >= dep.canonical_bytes().len() as u64, "0x07 must charge its bytes");
        assert!(c.base_fee_sat > 0, "0x07 settles a fee out of the depositor's own coin");

        // 0x08 — the signed exit: priced, fee-free.
        st.validators.get_mut(&4).unwrap().activation_epoch = 0;
        let pk = st.validators.get(&4).unwrap().pubkey.clone();
        let root = staking::ExitTx {
            pubkey_hash: Sha3_256::digest(&pk).into(),
            epoch: 0,
            signature: Vec::new(),
        }
        .signing_root();
        let exit =
            PosTransaction::SignedExit { validator: 4, epoch: 0, signature: toy_sign(&pk, &root) };
        let c = st
            .apply_transaction_gated(&exit, 0, price, &ToyVerifier, 0)
            .expect("the exit must apply");
        assert!(c.gas > 0, "0x08 must charge gas");
        assert_eq!(c.tx_bytes, exit.canonical_bytes().len() as u64, "0x08 must charge its bytes");
        assert_eq!(c.base_fee_sat + c.priority_fee_sat, 0, "0x08 settles no fee");

        // 0x09 — the withdrawal: priced, fee-free.
        st.epoch = st.validators.get(&4).unwrap().withdrawable_epoch;
        let wd = PosTransaction::Withdraw { validator: 4 };
        let c = st
            .apply_transaction_gated(&wd, 0, price, &ToyVerifier, 0)
            .expect("the withdrawal must apply");
        assert!(c.gas > 0, "0x09 must charge gas");
        assert_eq!(c.tx_bytes, wd.canonical_bytes().len() as u64, "0x09 must charge its bytes");
        assert_eq!(c.base_fee_sat + c.priority_fee_sat, 0, "0x09 settles no fee");

        // Control: the legacy shapes stay free, pre-gate, unchanged.
        let legacy = PosTransaction::Exit { validator: 0 };
        let mut pre = g.clone();
        let c = pre
            .apply_transaction_gated(&legacy, 0, price, &ToyVerifier, u64::MAX)
            .expect("control: the legacy exit still applies before the gate");
        assert_eq!((c.gas, c.tx_bytes), (0, 0), "control: legacy shapes are still free");
    }

    /// THE BLOCK PATH, ACCEPT SIDE — the three funded discriminants carried
    /// inside real blocks: header commitments, body root and state-root check
    /// included, not called as seam methods.
    ///
    /// Every other funded-staking test in this file drives
    /// `apply_transaction_gated` directly. That leaves a gap the 2026-08-22
    /// mutation run named in a different context: a rule can be intact and
    /// green at the seam while the path a node actually runs never reaches
    /// it, or reaches it with different arguments. Here the deposit, the exit
    /// and the withdrawal each ride inside a block that `apply_block_gated`
    /// validates end to end.
    ///
    /// # The argument that differs, and the trap it sets
    ///
    /// A block prices its transactions at `pre.next_base_fee_at(epoch)` — the
    /// EIP-1559 controller's output for THAT block — not at whatever price a
    /// test hands the seam. A funded deposit's change output is computed from
    /// the fee, so a fixture built at a different price is off by the
    /// difference and dies on `ValueNotConserved`, one layer below anything
    /// this test means to assert. Hence `price` below. MEASURED on this
    /// fixture (2026-08-23): the two prices are BOTH 10 millisat/gas on a
    /// fresh chain and the mismatch does not bite here — which is precisely
    /// why the fixture takes the block's price explicitly rather than relying
    /// on that coincidence, since the first transaction to move the
    /// controller off its floor would break every test that assumed it.
    ///
    /// # A failure this test does NOT explain
    ///
    /// An earlier draft of this file, built on the rejected `DepositFunded`
    /// wire shape, saw the seam accept a deposit that the builder then
    /// refused with `Transaction(0)`. That is the producer/validator
    /// disagreement class, and it deserves a root cause. This test's shape is
    /// the same experiment on the wire format that shipped, and it PASSES —
    /// so whatever it was did not survive into this shape, and it is not the
    /// price mismatch above (measured: identical prices, and the
    /// deliberately mis-priced fixture is accepted). No root cause was
    /// established; the code that exhibited it is not in this tree. Recorded
    /// here rather than dropped, because "it went away when we changed
    /// something else" is how a producer/validator split gets rediscovered
    /// in production.
    ///
    /// Asserted here is the fee-independent half: registration, the funded
    /// bond's zero write-off, the payout's value and destination,
    /// `issued_sat` unmoved and `written_off_sat` still zero. The exact
    /// satoshi identity across the cycle needs the per-transaction charges
    /// (the deposit pays a fee, part of which the block burns) and is
    /// asserted at the seam by
    /// `funded_round_trip_conserves_value_and_never_issues`, which can see
    /// them. `issued_sat` unchanged is the WEAK half and is labelled as such:
    /// no staking path writes that counter outside the reward boundary.
    #[test]
    fn the_block_path_accepts_the_funded_lifecycle() {
        const GATE: u64 = 1;
        let owner = owner_key(3);
        let coin = opening(0x21, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (t, g, mut chains) = setup_funded(4, std::slice::from_ref(&coin));

        // ── Block 0: an EMPTY block in epoch 1, so the gate is behind us.
        let slot0 = SLOTS_PER_EPOCH;
        let b0 = build_block_gated(&t, &g, slot0, &[], &[], &mut chains, GATE);
        let g = t.apply_block_gated(&g, &b0, &[], &[], GATE).expect("empty block");
        assert_eq!(g.epoch, 1, "control failed: the gate was not crossed");
        let issued_start = g.issued_sat;

        // ── Block 1: the funded deposit, priced at the price THIS BLOCK will
        //    charge — see the doc above.
        let slot1 = slot0 + 1;
        let price = g.next_base_fee_at(crate::epoch_of(slot1));
        let deposit =
            funded_deposit_spending(&[coin], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price);
        let b1 = build_block_gated(
            &t,
            &g,
            slot1,
            &[],
            std::slice::from_ref(&deposit),
            &mut chains,
            GATE,
        );
        let s1 = t
            .apply_block_gated(&g, &b1, &[], std::slice::from_ref(&deposit), GATE)
            .expect("a funded deposit must be acceptable in a real block after the gate");
        assert_eq!(s1.validator_count(), 5, "the block registered the funded validator");
        assert_eq!(
            s1.unbacked_principal_sat(4, GATE),
            0,
            "a funded bond is born with nothing to write off"
        );
        assert_eq!(s1.issued_sat, issued_start, "control (weak half): deposit is not emission");

        // ── Block 2: the exit, signed by the validator's own key. The
        //    activation clock is not what this test is about, so the record
        //    is made exit-eligible first — everything else runs through the
        //    block path.
        let mut s1 = s1;
        s1.validators.get_mut(&4).unwrap().activation_epoch = 0;
        let rec_pubkey = s1.validators.get(&4).unwrap().pubkey.clone();
        let exit_root = staking::ExitTx {
            pubkey_hash: Sha3_256::digest(&rec_pubkey).into(),
            epoch: s1.epoch,
            signature: Vec::new(),
        }
        .signing_root();
        let exit = PosTransaction::SignedExit {
            validator: 4,
            epoch: s1.epoch,
            signature: toy_sign(&rec_pubkey, &exit_root),
        };
        let b2 = build_block_gated(
            &t,
            &s1,
            slot1 + 1,
            &[],
            std::slice::from_ref(&exit),
            &mut chains,
            GATE,
        );
        let s2 = t
            .apply_block_gated(&s1, &b2, &[], std::slice::from_ref(&exit), GATE)
            .expect("a signed exit must be acceptable in a real block after the gate");
        let withdrawable_at = s2.validators.get(&4).unwrap().withdrawable_epoch;
        assert!(withdrawable_at > s2.epoch, "control failed: the exit scheduled no delay");

        // ── Block 3: the withdrawal, at the first slot the lock allows.
        let slot3 = withdrawable_at * SLOTS_PER_EPOCH;
        let withdraw = PosTransaction::Withdraw { validator: 4 };
        let b3 = build_block_gated(
            &t,
            &s2,
            slot3,
            &[],
            std::slice::from_ref(&withdraw),
            &mut chains,
            GATE,
        );
        let s3 = t
            .apply_block_gated(&s2, &b3, &[], std::slice::from_ref(&withdraw), GATE)
            .expect("a withdrawal must be acceptable in a real block after the gate");

        // The payout is REAL and exact — a cycle that paid nothing would
        // satisfy every zero-delta assertion just as well.
        let out = s3
            .eutxos
            .get(&(withdraw.txid(), 0))
            .expect("the funded bond must come back out");
        assert_eq!(out.value as u128, staking::MIN_DEPOSIT_SAT, "the whole funded bond");
        assert_eq!(out.script_hash, [0xCD; 32], "paid to the registered credential");
        assert_eq!(s3.validators.get(&4).unwrap().staked_sat, 0, "the record is closed");
        assert_eq!(s3.written_off_sat, 0, "a funded bond writes nothing off");
        assert_eq!(s3.issued_sat, issued_start, "control (weak half): no emission anywhere");
    }

    /// PROBE (epoch-discipline front, 2026-08-22): the gate must read the
    /// BLOCK'S committed epoch, not any clock the node happens to own.
    ///
    /// Every existing gate test passes a SATURATED gate — 0 or `u64::MAX` —
    /// at which `x >= gate` is constant for every possible `x`. That makes
    /// them blind to WHICH `x` is read. This one puts the gate in the MIDDLE
    /// and parks `self.epoch` BELOW it while any wall clock is far above it,
    /// so the two epoch sources disagree and only the committed one gives the
    /// stated answer.
    #[test]
    fn probe_gate_reads_the_block_epoch_not_a_clock() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let deposit =
            funded_deposit_spending(&[entry], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price);
        const GATE: u64 = 5;

        // NEGATIVE: committed epoch 2 < gate 5 -> refused. A machine clock
        // reports an epoch in the millions, which is >= 5, so a clock-reading
        // gate would ACCEPT here.
        let mut pre = g.clone();
        pre.epoch = 2;
        let mut st = pre.clone();
        assert_eq!(
            st.apply_transaction_gated(&deposit, 0, price, &ToyVerifier, GATE),
            Err(TxReject::StakingRule),
            "pre-gate BLOCK epoch must refuse the funded shape, whatever the node clock says"
        );
        assert_eq!(st, pre, "a refused transaction must leave the state untouched");

        // CONTROL: same gate, same transaction, committed epoch 7 >= 5 -> lands.
        let mut post = g.clone();
        post.epoch = 7;
        post.apply_transaction_gated(&deposit, 0, price, &ToyVerifier, GATE)
            .expect("control: post-gate block epoch must accept the same transaction");
    }


    // ── THE PROOF: a deposit may not create stake without destroying coin ───
    //
    // Dev 3, 2026-08-23. The tests below exist so that the funding property
    // is LOAD-BEARING: each one dies if the step that destroys the coin is
    // removed while the step that credits the bond survives. They are the
    // authorisation to open the deposit door — the door `admissible()` holds
    // shut today with "bonding is not yet funded from the UTXO set".
    //
    // Two entry paths, deliberately, because the 2026-08-22 mutation run
    // proved a validation can be left intact and green while its CALL is
    // deleted: `the_real_block_path_...` runs the production entry
    // (`compute_post_state`, what every node runs on every block) and
    // `the_shipped_dispatch_is_the_gated_one` pins that the seam the other
    // tests use IS the shipped dispatch.

    /// Totals, before and after, on BOTH sides of the ledger.
    ///
    /// The existing conservation test measures the eUTXO pool. This one
    /// measures the pool AND the registry AND their sum, so the mutation
    /// class it refuses is the specific one this whole front exists to
    /// prevent: crediting the bond while not spending the inputs. Delete the
    /// `self.eutxos.remove` loop and assertion 1 dies; credit the bond twice
    /// and assertion 2 dies; do both and assertion 3 dies. The registry-wide
    /// sum is what makes 2 catch a double credit — a per-record assertion
    /// would not.
    #[test]
    fn a_funded_deposit_destroys_exactly_the_coin_it_bonds() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;
        let tx = funded_deposit_spending(&[entry], &owner, amount, 0x77, price);

        let pool = |s: &CommittedState| -> u128 {
            s.eutxos.values().map(|e| e.value as u128).sum()
        };
        let bonded = |s: &CommittedState| -> u128 {
            s.validators.values().map(|v| v.staked_sat).sum()
        };
        let (pool0, bonded0) = (pool(&g), bonded(&g));
        assert!(pool0 > 0 && bonded0 > 0, "fixture vacuous: both pools must start non-empty");

        let mut st = g.clone();
        let charge = st
            .apply_transaction_gated(&tx, 0, price, &ToyVerifier, 0)
            .expect("a conserving, honestly signed deposit must apply");
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        assert!(fee > 0, "fixture vacuous: a zero fee cannot distinguish the equality");

        // 1. The spendable side lost exactly the bond plus the fee.
        assert_eq!(
            pool(&st),
            pool0 - amount - fee,
            "the eUTXO set must lose exactly amount + fee — if it did not, \
             the bond was created without destroying coin"
        );
        // 2. The bonded side gained exactly the bond, measured across the
        //    WHOLE registry so a second credit anywhere is caught.
        assert_eq!(
            bonded(&st),
            bonded0 + amount,
            "the registry must gain exactly the amount, once"
        );
        // 3. The two pools together lost only the fee. This is the invariant
        //    a reviewer can read in one line: coin moved, none appeared.
        assert_eq!(
            pool(&st) + bonded(&st),
            pool0 + bonded0 - fee,
            "value must be conserved across the pool/registry boundary, burning only the fee"
        );
        // 4. Nothing was issued: the emission schedule is untouched.
        assert_eq!(st.issued_sat, g.issued_sat, "a funded deposit must not issue");
        // 5. The named outpoints are actually GONE — not merely accounted for.
        let PosTransaction::FundedDeposit { inputs, .. } = &tx else { unreachable!() };
        for i in inputs {
            assert!(
                !st.eutxos.contains_key(&(i.txid, i.vout)),
                "a funded input must leave the unspent set"
            );
        }
    }

    /// No double-spend into stake: one output funds one bond, ever.
    ///
    /// Both shapes of the attack — the same outpoint twice in ONE deposit
    /// (`DuplicateInput`, caught before the set is consulted) and the same
    /// outpoint in two SEQUENTIAL deposits (`UnknownInput`, because the first
    /// removed it). Control: each rejected deposit's honest twin applied.
    #[test]
    fn one_output_cannot_fund_two_deposits() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;

        // Two distinct deposits (different validator keys, hence different
        // txids) reaching for the SAME coin.
        let first = funded_deposit_spending(&[entry.clone()], &owner, amount, 0x77, price);
        let second = funded_deposit_spending(&[entry.clone()], &owner, amount, 0x78, price);
        assert_ne!(first.txid(), second.txid(), "fixture: the two deposits must differ");

        let mut st = g.clone();
        st.apply_transaction_gated(&first, 0, price, &ToyVerifier, 0)
            .expect("control: the first deposit must apply");
        let after_first = st.clone();
        assert_eq!(
            st.apply_transaction_gated(&second, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::UnknownInput)),
            "the same coin must not fund a second bond"
        );
        assert_eq!(st, after_first, "a refused deposit must leave the state untouched");
        assert_eq!(st.validators.len(), 5, "exactly one bond may exist for one coin");

        // The same outpoint named twice inside ONE deposit. Its inputs sum to
        // twice the coin's value, which is precisely the mint this refuses.
        let doubled = funded_deposit_spending(
            &[entry.clone(), entry],
            &owner,
            amount,
            0x79,
            price,
        );
        let mut st2 = g.clone();
        assert_eq!(
            st2.apply_transaction_gated(&doubled, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::DuplicateInput)),
            "one deposit must not spend the same outpoint twice"
        );
        assert_eq!(st2, g);
    }

    /// The input must EXIST and be UNSPENT — a deposit cannot name coin into
    /// being. Two halves: an outpoint that never existed, and one this very
    /// state already spent through the ordinary transfer path.
    #[test]
    fn a_deposit_naming_an_unknown_or_already_spent_output_is_refused() {
        let owner = owner_key(3);
        let real = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        // Same value, same owner, never in the committed set.
        let ghost = opening(0x9E, 7, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&real));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;
        assert!(!g.eutxos.contains_key(&(ghost.txid, ghost.vout)), "fixture: the ghost is unspent-set-absent");

        // (a) Never existed.
        let phantom = funded_deposit_spending(&[ghost], &owner, amount, 0x77, price);
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&phantom, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::UnknownInput)),
            "a deposit naming an outpoint that never existed must be refused"
        );
        assert_eq!(st, g);

        // Control: the identical deposit shape over the REAL coin applies, so
        // the refusal above is the existence rule and not the fixture.
        let honest = funded_deposit_spending(
            std::slice::from_ref(&real),
            &owner,
            amount,
            0x77,
            price,
        );
        let mut ctl = g.clone();
        ctl.apply_transaction_gated(&honest, 0, price, &ToyVerifier, 0)
            .expect("control: the same deposit over a real coin must apply");

        // (b) Already spent — by a plain transfer, through the shipped
        //     dispatch, so the two paths share one unspent set.
        let mut st2 = g.clone();
        let sweep = transfer_spending(
            std::slice::from_ref(&real),
            &owner,
            script_of(&owner_key(13)),
            0,
            0,
            price,
        );
        st2.apply_transaction(&sweep, 0, price, &ToyVerifier)
            .expect("control: the transfer that spends the coin must apply");
        let after_sweep = st2.clone();
        assert_eq!(
            st2.apply_transaction_gated(&honest, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::UnknownInput)),
            "a deposit naming an already-spent output must be refused"
        );
        assert_eq!(st2, after_sweep);
    }

    /// Stake from nothing, in its subtlest form: the inputs are real, present
    /// and honestly signed — there are just not enough of them for the bond
    /// being claimed. Strict equality is what refuses, so a one-satoshi
    /// overclaim dies exactly like a gross one.
    ///
    /// The `active` stake handed in is large enough that the 1%-of-active cap
    /// is not what rejects these (it is checked BEFORE conservation); the
    /// control proves the cap is clear.
    #[test]
    fn a_deposit_may_not_bond_more_than_its_inputs_destroy() {
        let owner = owner_key(3);
        let value = staking::MIN_DEPOSIT_SAT as u64 + 1_000_000;
        let entry = opening(0x51, 0, value, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;
        // 1% of this clears both `amount` and `amount + 1`, so the cap cannot
        // be the reason anything below is refused.
        let active = sat(3_000_000);
        let good = funded_deposit_spending(
            std::slice::from_ref(&entry),
            &owner,
            amount,
            0x77,
            price,
        );

        // Control: the honest twin applies at this `active`.
        let mut ctl = g.clone();
        ctl.apply_transaction_gated(&good, active, price, &ToyVerifier, 0)
            .expect("control: the conserving deposit must apply under the same cap");

        // (a) One satoshi of stake that no input backs. Signatures HONESTLY
        //     re-produced over the edited content, so conservation — not a
        //     signature — is what must refuse.
        let mut over_by_one = good.clone();
        if let PosTransaction::FundedDeposit { amount_sat, .. } = &mut over_by_one {
            *amount_sat += 1;
        }
        resign_funded(&mut over_by_one, &owner);
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&over_by_one, active, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::ValueNotConserved)),
            "one satoshi of unbacked stake must be refused by conservation"
        );
        assert_eq!(st, g, "a refused deposit must leave the state untouched");

        // (b) The whole input claimed as bond, leaving nothing for the fee —
        //     inputs present, insufficient, and every witness honest.
        let mut whole_input = good.clone();
        if let PosTransaction::FundedDeposit { amount_sat, change, .. } = &mut whole_input {
            *amount_sat = value as u128;
            change[0].value = 0;
        }
        resign_funded(&mut whole_input, &owner);
        let mut st2 = g.clone();
        assert_eq!(
            st2.apply_transaction_gated(&whole_input, active, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::ValueNotConserved)),
            "a bond that leaves the fee unfunded must be refused"
        );
        assert_eq!(st2, g);
    }

    /// Where the remainder goes when the inputs exceed the bond: into a
    /// DECLARED change output, or the deposit is refused. It is never
    /// silently burned — the failure mode that would quietly cost a depositor
    /// the difference between its coin and its bond.
    #[test]
    fn the_remainder_is_declared_change_and_never_a_silent_burn() {
        let owner = owner_key(3);
        let surplus: u64 = 1_000_000;
        let value = staking::MIN_DEPOSIT_SAT as u64 + surplus;
        let entry = opening(0x51, 0, value, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;
        let good = funded_deposit_spending(
            std::slice::from_ref(&entry),
            &owner,
            amount,
            0x77,
            price,
        );

        let mut st = g.clone();
        let charge = st
            .apply_transaction_gated(&good, 0, price, &ToyVerifier, 0)
            .expect("the deposit with change must apply");
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        assert!(fee > 0 && (fee as u64) < surplus, "fixture vacuous: the fee must fit inside the surplus");

        // The change exists, under the derived txid, for exactly the
        // remainder, and it is spendable by the depositor.
        let out = st
            .eutxos
            .get(&(good.txid(), 0))
            .expect("the surplus must come back as a change output");
        assert_eq!(
            out.value as u128,
            value as u128 - amount - fee,
            "change must be exactly inputs − bond − fee"
        );
        assert_eq!(out.script_hash, script_of(&owner), "change must return to the depositor");

        // Drop the change entirely: the surplus would have to vanish, and the
        // equality refuses instead of burning it.
        let mut burned = good.clone();
        if let PosTransaction::FundedDeposit { change, .. } = &mut burned {
            change.clear();
        }
        resign_funded(&mut burned, &owner);
        let mut st2 = g.clone();
        assert_eq!(
            st2.apply_transaction_gated(&burned, 0, price, &ToyVerifier, 0),
            Err(TxReject::Transfer(TransferReject::ValueNotConserved)),
            "an undeclared surplus must be refused, never silently burned"
        );
        assert_eq!(st2, g);

        // And change to a THIRD party is allowed — it is the coin owners'
        // own signed instruction (the DS_SPEND root covers the outputs), not
        // a hole. Pinned so the rule is stated rather than assumed.
        let stranger = script_of(&owner_key(13));
        let mut elsewhere = good.clone();
        if let PosTransaction::FundedDeposit { change, .. } = &mut elsewhere {
            change[0].script_hash = stranger;
        }
        resign_funded(&mut elsewhere, &owner);
        let mut st3 = g.clone();
        st3.apply_transaction_gated(&elsewhere, 0, price, &ToyVerifier, 0)
            .expect("change may be paid anywhere the signed transaction says");
        assert_eq!(st3.eutxos.get(&(elsewhere.txid(), 0)).unwrap().script_hash, stranger);
    }

    /// THE CALL-SITE TEST, consensus half: the funded deposit is judged
    /// through `compute_post_state` — the entry every node runs on every
    /// block — and not by reaching into the arm.
    ///
    /// Under the shipped `u64::MAX` gate the verdict is a BLOCK REJECT, which
    /// is what makes the whole front inert: no pre-gate block body can carry
    /// a funded deposit. Delete the `if !funded_era` guard from the
    /// `FundedDeposit` arm and this test goes red — the deposit applies
    /// through the real path — while every seam test above stays green.
    ///
    /// The control runs a LEGACY `Deposit` through the same harness and it
    /// applies, which proves the harness reaches the dispatch at all: without
    /// it, "the block was rejected" would also be satisfied by a broken
    /// envelope.
    #[test]
    fn the_real_block_path_refuses_a_funded_deposit_today() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (t, g, mut chains) = setup_funded(4, std::slice::from_ref(&entry));
        let price = g.next_base_fee();
        let dep = funded_deposit_spending(&[entry], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price);

        let env = probe_env(&g, 1, std::slice::from_ref(&dep), &mut chains);
        assert_eq!(
            t.compute_post_state(&g, &env, &[], std::slice::from_ref(&dep)).unwrap_err(),
            TransitionError::Transaction(0),
            "a funded deposit in a block body must be a block reject while the gate is shut"
        );

        // Control: the legacy shape, same harness, applies pre-gate — so the
        // rejection above is the gate and not the plumbing.
        let (t2, g2, mut chains2) = setup(4);
        let legacy = PosTransaction::Deposit {
            pubkey: vec![0xAA; 8],
            amount_sat: staking::MIN_DEPOSIT_SAT,
            randao_commitment: [0xBB; 32],
            withdrawal_credentials: vec![0xCC; 4],
            commission_bps: 500,
        };
        let b = build_block(&t2, &g2, 1, &[], std::slice::from_ref(&legacy), &mut chains2);
        let post = t2
            .apply_block(&g2, &b, &[], std::slice::from_ref(&legacy))
            .expect("control: the legacy deposit must still apply through the real path");
        assert_eq!(post.validators.len(), 5, "control: the legacy deposit registered");
    }

    /// THE CALL-SITE TEST, seam half: `apply_transaction` — the function
    /// `compute_post_state` actually calls — IS `apply_transaction_gated` at
    /// the shipped constant, verdict and post-state alike.
    ///
    /// Every funded test above (and every one that shipped with the a7 merge)
    /// exercises the gated inner form. That is only evidence about production
    /// if the outer form delegates to it with the SHIPPED epoch. Repoint the
    /// delegation at a different epoch — the one edit that would silently arm
    /// the whole front — and this test goes red on the funded rows while the
    /// direct-seam tests stay green.
    #[test]
    fn the_shipped_dispatch_is_the_gated_one_at_the_shipped_constant() {
        let owner = owner_key(3);
        let entry = opening(0x51, 0, staking::MIN_DEPOSIT_SAT as u64 + 1_000_000, &owner);
        let (_t, g, _c) = setup_funded(4, std::slice::from_ref(&entry));
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let corpus = [
            funded_deposit_spending(&[entry], &owner, staking::MIN_DEPOSIT_SAT, 0x77, price),
            PosTransaction::SignedExit { validator: 0, epoch: 0, signature: vec![1, 2, 3] },
            PosTransaction::Withdraw { validator: 0 },
            PosTransaction::Deposit {
                pubkey: vec![0xAA; 8],
                amount_sat: staking::MIN_DEPOSIT_SAT,
                randao_commitment: [0xBB; 32],
                withdrawal_credentials: vec![0xCC; 4],
                commission_bps: 500,
            },
            PosTransaction::Exit { validator: 0 },
            PosTransaction::Delegate {
                delegator: 9,
                validator: 0,
                amount_sat: delegation::MIN_DELEGATION_SAT,
                eligible: true,
            },
        ];
        for (i, tx) in corpus.iter().enumerate() {
            let mut a = g.clone();
            let mut b = g.clone();
            let ra = a.apply_transaction(tx, 0, price, &ToyVerifier);
            let rb = b.apply_transaction_gated(
                tx,
                0,
                price,
                &ToyVerifier,
                crate::params::FUNDED_STAKE_ACTIVATION_EPOCH,
            );
            assert_eq!(ra, rb, "corpus row {i}: the shipped dispatch diverged from the gated one");
            assert_eq!(a, b, "corpus row {i}: the two forms produced different states");
        }
        // The tripwire the rows above depend on: the shipped gate is still
        // shut. If a flag day lowers it, this assertion is the one that must
        // be confronted — and the funded rows re-derived — rather than the
        // suite quietly changing meaning.
        assert_eq!(
            crate::params::FUNDED_STAKE_ACTIVATION_EPOCH,
            u64::MAX,
            "the funded-stake gate is armed: re-derive this file's expectations deliberately"
        );
    }

    /// Proof of possession is what stops a funded deposit from bonding real
    /// coin to a validator key its payer does not hold — and, because
    /// `pubkey_index` refuses a second registration of the same key FOREVER,
    /// it is also what stops a stranger paying `MIN_DEPOSIT_SAT` to lock a
    /// validator out of its own identity permanently.
    ///
    /// Three properties, each with its control:
    ///  (a) a deposit whose PoP does not verify does not register — and the
    ///      key it named stays free for whoever actually holds it;
    ///  (b) the ML-DSA-only escape hatch cannot enter the registry;
    ///  (c) the lock-out being prevented is REAL: a second registration of an
    ///      already-registered key is refused, so had (a) landed the key
    ///      would have been dead.
    ///
    /// The toy verifier cannot model "cannot produce a signature" (it is a
    /// pure function of key and root), so this half uses a PoP that verifies
    /// under NO key. The "signed by the wrong holder" form needs real
    /// asymmetry and lives at the node's door
    /// (`a_funded_deposit_cannot_bond_coin_to_a_key_the_spender_does_not_hold`).
    #[test]
    fn possession_keeps_a_validator_key_from_being_squatted() {
        let owner = owner_key(3);
        let value = staking::MIN_DEPOSIT_SAT as u64 + 1_000_000;
        let first_coin = opening(0x51, 0, value, &owner);
        let second_coin = opening(0x52, 0, value, &owner);
        let (_t, g, _c) = setup_funded(4, &[first_coin.clone(), second_coin.clone()]);
        let price = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let amount = staking::MIN_DEPOSIT_SAT;

        // The validator key at stake, and the deposit its true holder would
        // send (the fixture's PoP verifies).
        let honest = funded_deposit_spending(
            std::slice::from_ref(&first_coin),
            &owner,
            amount,
            0x77,
            price,
        );
        let PosTransaction::FundedDeposit { pubkey: victim_key, .. } = &honest else {
            unreachable!()
        };
        let victim_hash: [u8; 32] = Sha3_256::digest(victim_key).into();

        // (a) The squat: real coin, real spend authorisation, a PoP nobody
        //     can have produced. The inputs are re-signed OVER the garbage
        //     PoP (not `resign_funded`, which would repair it), so the coins'
        //     movement is authorised and only the registration rule can be
        //     what refuses.
        let mut squat = honest.clone();
        if let PosTransaction::FundedDeposit { proof_of_possession, .. } = &mut squat {
            *proof_of_possession = vec![0xEE; 32];
        }
        let root = squat.spend_signing_root();
        if let PosTransaction::FundedDeposit { inputs, .. } = &mut squat {
            for i in inputs.iter_mut() {
                i.signature = toy_sign(&owner, &root);
            }
        }
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction_gated(&squat, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "a deposit that cannot prove possession must not register"
        );
        assert_eq!(st, g, "a refused squat must not move state — not even the coin");
        assert!(
            !st.pubkey_index.contains_key(&victim_hash),
            "the squatted key must be left unregistered"
        );

        // ...and the key is still there for the validator that holds it.
        st.apply_transaction_gated(&honest, 0, price, &ToyVerifier, 0)
            .expect("the true holder must still be able to register its own key");
        assert!(st.pubkey_index.contains_key(&victim_hash));

        // (c) The lock-out is real: the SAME key, a different coin, a
        //     perfectly valid PoP — and it is refused forever. This is what
        //     the squat in (a) would have bought for MIN_DEPOSIT_SAT.
        let again = funded_deposit_spending(
            std::slice::from_ref(&second_coin),
            &owner,
            amount,
            0x77,
            price,
        );
        let before = st.clone();
        assert_eq!(
            st.apply_transaction_gated(&again, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "a registered key may never be registered twice — which is why (a) matters"
        );
        assert_eq!(st, before);

        // (b) The ML-DSA-only escape hatch, smuggled in the envelope, cannot
        //     enter the registry. Deliberately NOT re-signed: the suite check
        //     runs before any signature work, so a repaired witness would
        //     prove nothing extra, and `funded_deposit_pop_signing_root`
        //     returns `None` for this shape anyway.
        let mut half_suite = honest.clone();
        if let PosTransaction::FundedDeposit { pubkey, .. } = &mut half_suite {
            pubkey[2] = 0x02;
        }
        assert!(
            half_suite.funded_deposit_pop_signing_root().is_none(),
            "a non-hybrid key must have no PoP root to verify against"
        );
        let mut st2 = g.clone();
        assert_eq!(
            st2.apply_transaction_gated(&half_suite, 0, price, &ToyVerifier, 0),
            Err(TxReject::StakingRule),
            "only the enveloped hybrid suite may enter the registry"
        );
        assert_eq!(st2, g);
    }
}

#[cfg(test)]
mod carried_ownership_tests {
    use super::*;

    fn h(bytes: &[u8]) -> [u8; 32] {
        Sha3_256::digest(bytes).into()
    }

    /// A carried output — 20 bytes of the Genesis-3 hash, 12 zeros — must be
    /// openable by the key that owned it there. Without this the entire
    /// opening ledger is frozen.
    #[test]
    fn a_carried_output_opens_for_its_genesis3_owner() {
        let pubkey = b"a hybrid public key stands in here";
        let full = h(pubkey);
        let mut carried = [0u8; 32];
        carried[..20].copy_from_slice(&full[..20]);
        assert!(owns(&full, &carried), "the holder of the same key must be able to spend");
    }

    #[test]
    fn a_native_output_still_needs_all_32_bytes() {
        let pubkey = b"a hybrid public key stands in here";
        let full = h(pubkey);
        assert!(owns(&full, &full));
        let mut off_by_one_late = full;
        off_by_one_late[31] ^= 1; // differs only past byte 20
        assert!(
            !owns(&full, &off_by_one_late),
            "a native output must not fall back to the 20-byte comparison"
        );
    }

    #[test]
    fn a_different_key_opens_neither_form() {
        let mine = h(b"my key");
        let theirs = h(b"someone else's key");
        let mut carried = [0u8; 32];
        carried[..20].copy_from_slice(&mine[..20]);
        assert!(!owns(&theirs, &carried), "a carried output is not a free-for-all");
        assert!(!owns(&theirs, &mine));
    }

    /// The relaxed arm is gated on the twelve zero bytes and nothing else. A
    /// script_hash with any non-zero tail gets the full check, so the weaker
    /// tier cannot be entered by an output that did not come from the
    /// carryover.
    #[test]
    fn the_relaxed_arm_needs_the_zero_tail() {
        let mine = h(b"my key");
        let mut almost = [0u8; 32];
        almost[..20].copy_from_slice(&mine[..20]);
        almost[31] = 1; // one byte of tail set
        assert!(!owns(&mine, &almost));
    }
}
