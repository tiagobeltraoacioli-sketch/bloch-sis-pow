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
//! `EpochAdvanceTooLarge` was appended to this order, not inserted into it: it
//! sits between the header-commitment checks and the epoch boundary walk it
//! bounds, which is the first point at which the walk's cost is about to be
//! paid. Every block that was a reject before the rule existed still returns
//! the error it returned before.
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
use crate::attestation::KeyLookup as _;
use crate::slashing;
use crate::staking::{self, QueuedDeposit};
use crate::fee_market;
use crate::state_root::{
    AppliedEvidenceRecord, BaseFeeRecord, CheckpointRecord, ConsensusState, DelegatorFeeRecord, DelegatorLossRecord, SlashWindowRecord, DelegationRecord, DepositQueueRecord, EvmCommitment, FcEquivocatorRecord, FcMessageRecord, FinalityRecord, LeakRecord, ParticipationRecord, PendingFeeRecord, PendingVoteRecord, RandaoMix, ValidatorRecord as CommittedValidatorRecord,
};
use crate::tokenomics_v4;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// Register a validator (§7.1).
    ///
    /// **The proof of possession is checked HERE, by the transition, not at
    /// admission.** The comment that used to sit on this line said the
    /// opposite ("PoP/taint already checked at admission") and it was false in
    /// both halves: `bloch-pos-node`'s `admissible` refuses every deposit
    /// outright, so nothing was checking anything, and admission is mempool
    /// policy in any case — a rule one producer can lift for the whole network
    /// is not a rule. The taint set is separately retired (§4.1 was rewritten;
    /// see `staking::DepositInput::tainted`).
    ///
    /// This matters more than it did: since the committee-signature path was
    /// changed to read the key the **state root commits**
    /// (`attestation::KeyLookup`), the `pubkey` below is not a hint — it is
    /// the exact bytes every node will verify this validator's blocks and
    /// attestations against, permanently (nothing deletes a registry record,
    /// and no production path rewrites its key). So the deposit must prove
    /// the key is a real hybrid key its depositor can sign under; otherwise it
    /// mints a committee seat nobody can ever fill, which is the same "dead
    /// weight subtracted from finality" the key-lookup fix exists to end.
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
        /// Hybrid signature over
        /// [`staking::wire_deposit_pop_root`] of every field above, proving
        /// the depositor holds the secret half of `pubkey`.
        ///
        /// It covers `commission_bps` and the withdrawal credentials as well
        /// as the key: a proof that left them out would let any relay rewrite
        /// where the stake returns to, or what the operator charges its
        /// delegators, without breaking the proof.
        ///
        /// Appended at the END of wire tag `0x02`, which is why the field can
        /// exist at all — see the encoder for why that is consensus-neutral
        /// while `params::DEPOSIT_ACTIVATION_EPOCH` is `u64::MAX`.
        proof_of_possession: Vec<u8>,
    },
    /// Voluntary exit (§7.2) — **UNAUTHENTICATED**, and retired at
    /// [`crate::params::EXIT_AUTH_ACTIVATION_EPOCH`] in favour of
    /// [`Self::ExitV2`].
    ///
    /// The doc line this replaces read "Signature already checked at
    /// admission." No signature exists to check: the message is a registry
    /// index and nothing else, the arm in `apply_transaction` never touches a
    /// verifier, and `bloch-pos-node`'s `admissible` refuses the message
    /// outright *because* of that — which is mempool policy, not consensus, so
    /// a modified proposer can still put one in a block today.
    ///
    /// Below the flag day this arm behaves exactly as it always has (it is the
    /// control); at and above it, it is invalid.
    Exit { validator: u32 },
    /// Authenticated voluntary exit (§7.2) — consensus-INVALID until
    /// [`crate::params::EXIT_AUTH_ACTIVATION_EPOCH`], which is `u64::MAX`.
    ///
    /// What it adds over [`Self::Exit`], and both are necessary:
    ///
    /// 1. **A hybrid signature verified IN CONSENSUS** against the pubkey the
    ///    registry committed at registration — never a key carried in the
    ///    message — over [`crate::staking::ExitTx::signing_root`] (`DS_EXIT`
    ///    domain, one definition, shared with the reference validator). The
    ///    signed `epoch` must EQUAL the inclusion epoch, so a captured exit
    ///    message cannot be replayed at a time its signer never chose.
    /// 2. **A per-epoch churn cap** ([`crate::staking::MAX_EXITS_PER_EPOCH`]).
    ///    Authentication alone still lets one operator holding many keys
    ///    retire the roster in a single block; see that constant's docs.
    ///
    /// # The wire byte is claimed but NOT DECODED
    ///
    /// `canonical_bytes` writes `0x08`. The decoder has **no `0x08` arm** and
    /// deliberately keeps returning [`TxDecodeError::UnknownTag`]: that byte
    /// is CONTESTED across live lineages — `SignedExit`, `Withdraw` and
    /// `ExitV2` all claim it (`tests/wire_tag_registry.rs`, and the two
    /// meanings are semantically incompatible, so whichever lands second
    /// splits the chain at decode). Assigning it is the founder's, and the
    /// registry test refuses contested bytes until they are assigned.
    ///
    /// So this variant is, today, encode-and-apply only: the rules are
    /// written, compiled, tested and wired into the production dispatcher,
    /// and nothing on the wire can reach them. Closing that last gap is a
    /// one-line decoder arm plus a `Contested` → `Released` edit, and both
    /// wait on the same ruling.
    ExitV2 {
        /// SHA3-256 of the exiting validator's **registered** pubkey. The
        /// index is resolved from this through `pubkey_index`, so the message
        /// names an identity rather than a position.
        pubkey_hash: [u8; 32],
        /// Epoch the exit was signed for; must equal the inclusion epoch.
        epoch: u64,
        /// Hybrid signature (both halves) over the `DS_EXIT` signing root.
        signature: Vec<u8>,
    },
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
                proof_of_possession,
            } => {
                b.push(0x02);
                put(&mut b, pubkey);
                b.extend_from_slice(&amount_sat.to_le_bytes());
                b.extend_from_slice(randao_commitment);
                put(&mut b, withdrawal_credentials);
                b.extend_from_slice(&commission_bps.to_le_bytes());
                // APPENDED, and appending to a wire tag is normally a fork.
                // It is not one here, and the reason is specific rather than
                // hopeful: `DEPOSIT_ACTIVATION_EPOCH` is `u64::MAX`, so the
                // transition refuses tag 0x02 at EVERY epoch before it looks
                // at any field. A block carrying a deposit is therefore
                // invalid on the old binary (which now reads trailing bytes it
                // cannot place) and invalid on the new one (which now reads a
                // truncated body on the old encoding) and invalid on both by
                // the gate regardless — three roads to the same verdict on the
                // same block. A block carrying NO deposit is byte-identical
                // under both encoders. The moment that gate is armed this
                // becomes a real format change needing its own flag day, which
                // is one more thing the founder is deciding when arming it.
                put(&mut b, proof_of_possession);
            }
            PosTransaction::Exit { validator } => {
                b.push(0x03);
                b.extend_from_slice(&validator.to_le_bytes());
            }
            PosTransaction::ExitV2 { pubkey_hash, epoch, signature } => {
                // 0x08. Same encoding rules as every other tag: fixed-width
                // LE for the scalars, length-prefixed for the one
                // variable-length field, so no two byte strings decode to one
                // transaction. See the variant's docs for why the DECODER
                // does not answer this byte yet.
                b.push(0x08);
                b.extend_from_slice(pubkey_hash);
                b.extend_from_slice(&epoch.to_le_bytes());
                put(&mut b, signature);
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
                // Whether the PoP is VALID is not this function's question —
                // the same division tag 0x06 states: the decoder reads shape,
                // the transition judges rules.
                proof_of_possession: r.bytes()?,
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
            // NO `0x08` ARM, ON PURPOSE. `PosTransaction::ExitV2` ENCODES to
            // 0x08 (`canonical_bytes`), and this decoder still answers
            // `UnknownTag(0x08)`. The byte is contested across live lineages
            // — `SignedExit`, `Withdraw` and `ExitV2` each claim it, and the
            // first two are semantically incompatible with the third, so
            // whichever landed second would split the chain at decode. The
            // assignment is the founder's; `tests/wire_tag_registry.rs`
            // refuses contested bytes until it is made, and adding an arm here
            // is what would make that test go red. Until then no wire byte can
            // reach the ExitV2 rules, which is the honest state of this
            // feature and not an oversight.
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
    /// A `Deposit` or `Delegate` arrived below
    /// [`crate::params::DEPOSIT_ACTIVATION_EPOCH`]. Unfunded bonding is not a
    /// rule this chain has ever activated: both messages create consensus
    /// weight without spending an eUTXO input, and the gate is what makes the
    /// refusal a property of the CHAIN rather than of whichever node happened
    /// to hold the transaction. Its own variant, not `StakingRule`, because
    /// "the flag day has not arrived" and "the amount was below the minimum"
    /// are different facts and a test that cannot tell them apart is not
    /// testing the gate. Both still surface as the frozen
    /// `TransitionError::Transaction(i)`; no error code changes.
    StakingNotActive,
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

thread_local! {
    /// How many times [`CommittedState::compute_root`] has run **on this
    /// thread**.
    ///
    /// **Observability only.** No consensus rule reads it, nothing branches on
    /// it, and it is never committed — it exists so a test can assert *how
    /// many* state roots one slot costs, which is a claim timing cannot make
    /// honestly on a loaded box.
    ///
    /// Per-thread and not a process-wide atomic for two reasons: the consensus
    /// engine is one thread by construction (that is this node's whole
    /// design), and `cargo test` runs each test on its own thread — a shared
    /// counter would make the assertion a race against every other test in the
    /// binary. A thread-local bump on a path that already hashes an entire
    /// state tree is not measurable.
    static ROOT_COMPUTATION_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The calling thread's [`ROOT_COMPUTATION_COUNT`]. Observability only.
pub fn root_computations() -> u64 {
    ROOT_COMPUTATION_COUNT.with(|c| c.get())
}

thread_local! {
    /// How many times the copy-on-write eUTXO map was **deeply copied** on
    /// this thread — the O(n) event [`EutxoSet`]'s `Arc` exists to make rare.
    ///
    /// **Observability only.** No consensus rule reads it, nothing branches
    /// on it, and it is never committed — it exists so a test can assert *how
    /// many* full-map copies an epoch roll or a block costs, which is the
    /// claim that decides whether a node far behind the wall clock can catch
    /// up at all (2026-08-31: `close_epoch`'s clone of a 452,726-entry map,
    /// once per rolled epoch per arriving attestation, was the whole stall).
    /// Timing cannot make that claim honestly on a loaded box; a count can.
    ///
    /// Per-thread for the same two reasons as [`ROOT_COMPUTATION_COUNT`]: the
    /// consensus engine is one thread by construction, and a process-wide
    /// atomic would make test assertions a race against every other test in
    /// the binary.
    static EUTXO_MAP_DEEP_COPIES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The calling thread's [`EUTXO_MAP_DEEP_COPIES`]. Observability only.
pub fn eutxo_map_deep_copies() -> u64 {
    EUTXO_MAP_DEEP_COPIES.with(|c| c.get())
}

// ────────────────────────────────────────────────────────────────────────────
// The boundary-partition divergence detector (unconditional, NON-FATAL)
// ────────────────────────────────────────────────────────────────────────────

/// Times the epoch-boundary tally dropped attestations that the inclusion
/// check at step 8 had already admitted, since this process started.
///
/// **Present in the release binary.** No `cfg`, no `debug_assert!`. The
/// workspace `[profile.release]` sets `overflow-checks` and not
/// `debug-assertions`, so the `debug_assert_eq!` that was the only guard on
/// the 2026-08-21 roster split was absent from every binary mainnet ran — the
/// defect was invisible in production for the whole time it was live. This
/// counter is the thing that makes it visible.
///
/// Process-wide rather than thread-local, following
/// [`crate::forkchoice::FORKCHOICE_STEPS`]: an operator scraping a node wants
/// one number for the process, and the tests that read it assert it *moved*
/// rather than an exact value, so a concurrent test cannot race them.
#[doc(hidden)]
pub static BOUNDARY_VOTE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Record and report one boundary-partition divergence. **Never panics, never
/// touches consensus state, and never changes the returned post-state.**
///
/// # Why this is a detector and not a `consensus_invariant!`
///
/// A panic here would halt the node, which is the right trade for a condition
/// that can only fire on an internal code bug — and this one cannot make that
/// claim. `apply_slashing_evidence` sets `slashed = true` and
/// `exit_epoch = epoch` MID-EPOCH, and `duty_roster_at` filters on exactly
/// that predicate, so the roster's index set legitimately shrinks between two
/// blocks of one epoch. Votes admitted against the wider partition are then
/// tallied against the narrower one and dropped, by the rule as written.
/// Anyone who can get valid equivocation evidence included can cause it, so an
/// unconditional panic at this site would be a remotely triggerable halt of
/// every node that applied the same block. See
/// `mid_epoch_slashing_changes_the_roster_index_set_within_one_epoch`.
///
/// So the requirement behind the guard — *production must be able to SEE this,
/// which today it cannot* — is met without the fatality: an unconditional,
/// loud, structured, rate-limited line on stderr plus a counter. The
/// `debug_assert_eq!` at the call site stays, because in a test build the
/// condition IS a bug and should stop the run.
///
/// Rate-limited by power-of-two backoff rather than by a clock: this crate has
/// no time source and must not acquire one (§5.5), and a replaying node can
/// close thousands of epochs in seconds. The first eight are printed, then
/// every doubling, so a live divergence is never silent and a backfill can
/// never drown the log.
#[cold]
fn report_boundary_vote_drop(closing: u64, admitted: usize, tallied: usize) {
    let n = BOUNDARY_VOTE_DROPS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= 8 || n.is_power_of_two() {
        eprintln!(
            "BLOCH-CONSENSUS-DIVERGENCE boundary_partition_dropped_votes \
             epoch={closing} admitted={admitted} tallied={tallied} dropped={} occurrences={n} \
             note=the inclusion check at step 8 and the boundary tally partitioned different \
             rosters; expected only after a mid-epoch slashing, a bug otherwise",
            admitted.saturating_sub(tallied)
        );
    }
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
    ///
    /// This is also the **authoritative key store** for consensus signature
    /// checks — see the `impl KeyLookup` below and
    /// [`crate::attestation::KeyLookup`] for which state answers where.
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
    /// # The gap that is still open, named rather than left to be discovered
    ///
    /// **Bonding is not funded from this set.** `PosTransaction::Deposit` and
    /// `Delegate` name an `amount_sat` and spend no output; `Exit` and the
    /// withdrawal delay return no output either. So the chain holds two pools
    /// — this one and the registry's bonded stake — and coins do not travel
    /// between them: a deposit creates bonded stake without destroying
    /// spendable coins, and fee rewards compound into bonds that this set
    /// never funded.
    ///
    /// Conservation therefore holds **within** the transfer path (the fee is
    /// exactly what leaves the set, pinned by test) and **not** across the two
    /// pools. Closing it means giving deposits and withdrawals eUTXO inputs
    /// and outputs, which is a change to the staking messages' wire shape and
    /// to their admission rules, not to this field.
    ///
    /// **What changed on 2026-09-03.** This doc used to end "no single number
    /// in this state is the supply". There is one now:
    /// [`CommittedState::accounted_supply_sat`] sums both pools and every
    /// ledger beside them, and `compute_post_state` refuses any block that
    /// grows it by more than the block was entitled to mint. That does not
    /// close the gap above — deposits still bond coins the eUTXO set never
    /// funded, which is why the rule carries an explicit `unfunded_bonded`
    /// term — but it does mean the gap can no longer *widen* unobserved, and
    /// when deposits are finally funded from this set the term goes to zero
    /// and the rule tightens to an equality with no edit.
    eutxos: EutxoSet,
}

/// The committed registry answering "what key is validator `i` registered
/// under?", for whichever `CommittedState` the caller chose.
///
/// Implemented on the map rather than on `CommittedState` deliberately: the
/// borrow a caller needs is of `self.validators` alone, so that a transition
/// step can hold this immutable borrow while mutating *other* fields of the
/// same state (participation, pending votes, the slashing machine). An impl on
/// the whole state would borrow all of it and force a clone of the key — 3,745
/// bytes per attestation, on the hot path.
impl crate::attestation::KeyLookup for BTreeMap<u32, ValidatorRecord> {
    fn pubkey(&self, validator: u32) -> Option<&[u8]> {
        self.get(&validator).map(|r| r.pubkey.as_slice())
    }
}

/// The same registry reached through the whole state, for callers that hold an
/// immutable `CommittedState` (the node's gossip path holds an
/// `Arc<CommittedState>` from `rolled_to`) and therefore have no borrow
/// conflict to avoid.
///
/// Both impls exist on purpose. Inside the transition the map form is required:
/// a step must hold this borrow while mutating participation and pending votes
/// on the same state, and an impl over the whole state would borrow all of it.
impl crate::attestation::KeyLookup for CommittedState {
    fn pubkey(&self, validator: u32) -> Option<&[u8]> {
        self.validators.pubkey(validator)
    }
}

/// The committed eUTXO set, and the Merkle subtree it contributes to the
/// state root, in one value.
///
/// **Why one type and not two fields.** Keeping the leaves is what makes the
/// state root cheap — see
/// [`crate::state_root::build_state_tree_with_eutxo_tree`] for the
/// measurement. But a leaf store that can be updated independently of the
/// entries is a cache that can go stale, and a stale leaf is a wrong state
/// root, which is a consensus split — the exact failure the §5.5 rule exists
/// to prevent. So the two are never separately reachable: `insert` and
/// `remove` are the only mutators, each updates both halves, and no caller can
/// touch one without the other. Drift is not guarded against here; it is
/// unrepresentable.
///
/// **Why a tree and not a leaf map.** The map still had to be walked into a
/// tree once per block, and that walk — not the leaf derivation — was the
/// cost: at carryover scale it hashed every internal node of a 452,726-leaf
/// tree to commit a block that moved eight of them. Holding the tree makes
/// the walk incremental, because [`crate::state_root::Smt`] rebuilds only the
/// path to a changed leaf and shares the rest.
///
/// The leaf itself comes from [`crate::state_root::eutxo_leaf`], the single
/// definition shared with the from-scratch path, so a kept leaf and a
/// recomputed one cannot disagree by construction.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EutxoSet {
    /// Behind an `Arc`, and that is a **liveness** decision, not a style one
    /// (2026-08-31). `CommittedState` is cloned in two places that never
    /// touch this map: `close_epoch` (via `Transition::process_epoch`) and
    /// `compute_post_state`'s `pre.clone()`. A node `E` epochs behind the
    /// wall clock re-derives `rolled_to(wall_epoch)` after every applied
    /// block — the memo is generation-keyed and an applied block moves the
    /// generation — so it paid `E` full copies of this map (452,726 entries,
    /// ~60 MB, tens of ms each) *per block* while catching up. The break-even
    /// was near a 6–10 epoch gap; a cold start (~1,550 epochs) held
    /// `E × 60 MB` transiently and was unconditionally fatal. Sharing the map
    /// makes those clones a refcount bump, exactly as the `Smt` beside it
    /// already shares its nodes.
    ///
    /// Mutation goes through [`EutxoSet::entries_mut`] — `Arc::make_mut`, so
    /// a *shared* map is copied in full once, on first write, and a writer
    /// can never be observed by the states it was cloned from. The copy this
    /// buys back is the one `pre.clone()` used to pay unconditionally: it now
    /// happens only for a block that actually moves the ledger, and
    /// [`EUTXO_MAP_DEEP_COPIES`] counts every occurrence so tests can pin
    /// "an epoch roll copies nothing" as an assertion rather than a timing.
    ///
    /// **Not a consensus change.** The entries, their `BTreeMap` iteration
    /// order, the leaves and the root are bit-identical to the unshared
    /// representation; only *when the allocator copies* moved.
    entries: std::sync::Arc<BTreeMap<([u8; 32], u32), crate::state_root::EutxoEntry>>,
    /// The subtree of `entry key -> value hash` leaves, one per entry, always
    /// exactly in step.
    tree: crate::state_root::Smt,
    /// Running sum of every entry's `value`, in satoshis — the eUTXO half of
    /// [`CommittedState::accounted_supply_sat`].
    ///
    /// **Why it is kept and not summed on demand.** The conservation invariant
    /// runs on every block and needs this total twice (pre-state and
    /// post-state). Summing costs a walk of 452,726 entries each time, which
    /// is the exact O(set) per-block cost the incremental `tree` beside it
    /// exists to have removed — adding it back under a different name would
    /// undo that work.
    ///
    /// **Why it cannot drift.** It is maintained by `insert` and `remove`,
    /// the same two mutators that maintain `tree`, and by the bulk
    /// `FromIterator`; no third path can touch the entries. `total_sat()`
    /// re-sums under `debug_assert`, so every test in this crate checks the
    /// kept total against the entries it claims to summarise — the same
    /// discipline `tree()` applies to the leaves.
    ///
    /// `u128`, not `u64`: a single output fits `u64`, sums of them do not
    /// (`state_root::total_utxo_value` carries the same note).
    total_sat: u128,
}

impl EutxoSet {
    /// The single mutable path to the entries map — copy-on-write.
    ///
    /// If the map is shared (any other `CommittedState` clone still holds
    /// it), `Arc::make_mut` copies it in full first; the counter records that
    /// this happened, because "how many full copies" is the load-bearing
    /// claim of the whole representation (see the field docs). Both mutators
    /// go through here so no third path can copy — or worse, fail to
    /// unshare — without being counted.
    fn entries_mut(&mut self) -> &mut BTreeMap<([u8; 32], u32), crate::state_root::EutxoEntry> {
        if std::sync::Arc::get_mut(&mut self.entries).is_none() {
            EUTXO_MAP_DEEP_COPIES.with(|c| c.set(c.get() + 1));
        }
        std::sync::Arc::make_mut(&mut self.entries)
    }

    fn insert(&mut self, entry: crate::state_root::EutxoEntry) {
        let (key, value_hash) = crate::state_root::eutxo_leaf(&entry);
        self.tree.insert(key, value_hash);
        let value = u128::from(entry.value);
        let replaced = self.entries_mut().insert((entry.txid, entry.vout), entry);
        // An overwrite REPLACES a value, it does not add one. Nothing in the
        // transition writes the same outpoint twice today (a txid commits to
        // its inputs, so a second creation of the same outpoint would need a
        // collision), but a total that assumed so would be wrong exactly when
        // that assumption broke, and silently.
        if let Some(old) = replaced {
            self.total_sat -= u128::from(old.value);
        }
        self.total_sat += value;
    }

    fn remove(&mut self, outpoint: &([u8; 32], u32)) {
        // The containment probe runs on the shared map so removing an absent
        // outpoint stays what it always was — a no-op — instead of becoming
        // the one full-map copy this type exists to avoid.
        if !self.entries.contains_key(outpoint) {
            return;
        }
        if let Some(entry) = self.entries_mut().remove(outpoint) {
            let (key, _) = crate::state_root::eutxo_leaf(&entry);
            self.tree.remove(&key);
            self.total_sat -= u128::from(entry.value);
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

    /// Satoshis held by the set: the kept total, checked against a full
    /// re-sum in debug builds for the reason `tree()` re-derives its leaves.
    ///
    /// **The re-sum is a debug-build cost, and it is not free.** The doc on
    /// the field says the kept total exists to avoid an O(set) walk per
    /// block; that is true of a shipped binary, where `debug_assert` compiles
    /// to nothing, and false of `cargo test`, where this walks all entries on
    /// every call and the conservation check calls it twice per block. Stated
    /// rather than removed because the trade is the right way round: the
    /// failure it catches is a kept total that silently disagrees with the
    /// ledger it summarises, which would make the conservation invariant
    /// report on a number no longer connected to the coins — a guard passing
    /// for the wrong reason, which is worse than a slow test. Test fixtures
    /// hold hundreds of entries, not the 452,726 the field doc cites; the
    /// mainnet-scale walk happens only in the benches that opt into that
    /// size.
    fn total_sat(&self) -> u128 {
        debug_assert_eq!(
            self.total_sat,
            self.entries.values().map(|e| u128::from(e.value)).sum::<u128>(),
            "the kept eUTXO total drifted from the entries: a mutator updated one half only"
        );
        self.total_sat
    }

    /// Only tests count the set; the consensus paths iterate it.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// The subtree this set contributes, ready for
    /// [`crate::state_root::state_root_with_eutxo_tree`].
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
    fn tree(&self) -> &crate::state_root::Smt {
        debug_assert_eq!(
            self.tree.len(),
            self.entries.len(),
            "the kept eUTXO subtree drifted from the entries: a mutator updated one half only"
        );
        debug_assert!(
            self.entries.values().all(|e| {
                let (key, value_hash) = crate::state_root::eutxo_leaf(e);
                self.tree.get(&key) == Some(value_hash)
            }),
            "a kept eUTXO leaf disagrees with the entry it was derived from"
        );
        &self.tree
    }
}

impl FromIterator<crate::state_root::EutxoEntry> for EutxoSet {
    /// Builds the subtree in **bulk**, not by repeated insertion.
    ///
    /// This matters and is not a micro-optimisation. Inserting one leaf at a
    /// time costs each leaf its own 256-level singleton fold *and* re-folds
    /// whichever neighbour it pushes down, so a from-scratch load pays the
    /// fold about twice per entry; the bulk walk pays it exactly once, which
    /// is what the flat recursion used to do. At Genesis-4's carryover size
    /// (452,726 outputs) the difference is 150 s against 67 s — i.e. the
    /// one-off cost of opening the chain, which this patch must not make
    /// worse while making the per-block cost small.
    fn from_iter<I: IntoIterator<Item = crate::state_root::EutxoEntry>>(iter: I) -> Self {
        let entries: BTreeMap<([u8; 32], u32), crate::state_root::EutxoEntry> =
            iter.into_iter().map(|e| ((e.txid, e.vout), e)).collect();
        // Same leaf derivation as `insert`, from the same single definition,
        // so a bulk-built set and an incrementally-built one hold identical
        // leaves — and therefore commit an identical root.
        let leaves: BTreeMap<[u8; 32], [u8; 32]> =
            entries.values().map(crate::state_root::eutxo_leaf).collect();
        let total_sat = entries.values().map(|e| u128::from(e.value)).sum();
        EutxoSet {
            entries: std::sync::Arc::new(entries),
            tree: crate::state_root::Smt::from_leaf_map(&leaves),
            total_sat,
        }
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
            eutxos: opening_balances.iter().cloned().collect(),
        };
        // Seed epoch 0's participation for the launch roster, so the
        // committed participation component is well-defined from block one.
        for v in st.duty_roster_at(0) {
            st.current_participation.insert(v.index, false);
        }

        // ── GENESIS CONSERVATION, ENFORCED ──────────────────────────────
        //
        // The opening leg of the supply invariant, and the one the block rule
        // structurally cannot see. `compute_post_state`'s check is a DELTA —
        // it judges how holdings move against how issuance moves — so a
        // constant offset baked in at slot 0 cancels on every block forever.
        // Genesis-4 mainnet put 1,600,000 BLOCH through exactly that blind
        // spot: this function bonds every `GenesisValidator::staked_sat` into
        // a live, earning, slashable record while seeding `issued_sat` from
        // `GENESIS_ISSUED_SAT`, which counts the carryover and the allocation
        // buckets and not the bonds.
        //
        // Until 2026-09-04 nothing checked that at all, here or anywhere on an
        // exit path: `Manifest::check_bonds_are_funded` existed and its single
        // caller printed a warning. A warning is not a check — it is a check
        // whose failure is a decision nobody made.
        //
        // ONE-SIDED, for the same reason the block rule is: burns are real and
        // uncounted, and a devnet issues nothing while bonding play money, so
        // an opening that holds LESS than it issued is ordinary and must pass.
        // What is refused is holding MORE, beyond the one historical offset
        // this chain is already committed to.
        //
        // A PANIC, and deliberately. This is called once, at node start, from
        // `Manifest::genesis_state`, before any block exists; there is no
        // consensus path to halt and no peer that can trigger it. A node whose
        // own genesis mints coins from nothing has no correct behaviour
        // available other than refusing to start — continuing would put an
        // honest signature on an inflated ledger, which is the outcome the
        // whole invariant exists to prevent.
        let accounted = st.accounted_supply_sat();
        let ceiling = st
            .issued_sat
            .saturating_add(tokenomics_v4::GENESIS_UNFUNDED_BONDED_CEILING_SAT);
        assert!(
            accounted <= ceiling,
            "genesis mints from nothing: slot 0 holds {accounted} sat \
             (eUTXO opening balances + {} sat bonded to {} validators) against \
             {} sat issued, which is {} sat past the {} sat recorded Genesis-4 \
             cohort offset. See tokenomics_v4::GENESIS_UNFUNDED_BONDED_CEILING_SAT: \
             that ceiling records committed history and is not a budget to spend.",
            st.validators.values().map(|r| r.staked_sat).sum::<u128>(),
            st.validators.len(),
            st.issued_sat,
            accounted.saturating_sub(ceiling),
            tokenomics_v4::GENESIS_UNFUNDED_BONDED_CEILING_SAT,
        );

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
    ///
    /// # The look-ahead
    ///
    /// `back = 1 + `[`crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS`] **only at
    /// and above [`crate::params::ANCESTRY_SEED_ACTIVATION_EPOCH`]**, which is
    /// `u64::MAX`. Below it — that is, for every epoch any chain can reach —
    /// this function computes `back = 1`, the original pre-F6 rule, exactly as
    /// the `GATED.` note in the body says. Until 2026-09-02 this doc said the
    /// look-ahead was unconditional and pointed at the constant as removed. It
    /// was deleted on 2026-08-24 and restored; see its doc block for why the
    /// coordinated-relaunch premise was wrong. **F6 is not closed in the
    /// shipped binary**; arming that constant is what closes it.
    ///
    /// `back = 2` is what closes finding F6: at `back = 1` the seed for epoch
    /// `E` is the mix at the close of `E − 1`, so the trailing proposers of
    /// `E − 1` can re-sort `E`'s partition by withholding a reveal — they see
    /// the schedule their own reveal produces before they have to publish it.
    ///
    /// **The retention already covers it.** While epoch `E` is open the last
    /// closed epoch is `E − 1`, and `close_epoch` keeps
    /// [`crate::state_root::RANDAO_BOUNDARIES_RETAINED`]` = 2` boundaries —
    /// `{E − 2, E − 1}`. `back = 2` reads `E − 2`, which is retained. So this
    /// needs NO change to the retention window, and therefore none to the
    /// state root (`state_root::randao_window` folds exactly those retained
    /// boundaries into the tree). The two other callers are covered too: the
    /// close-epoch vote partition asks for `closing` before step 3 inserts,
    /// when `{closing − 2, closing − 1}` is retained, and the next-epoch
    /// partition asks for `closing + 1` after it, when `{closing − 1,
    /// closing}` is.
    pub fn seed_for_epoch(&self, epoch: u64) -> [u8; 32] {
        // In a shipped binary this is exactly
        // `1 + committees::MIN_SEED_LOOKAHEAD_EPOCHS`. In a test build it is
        // the same value unless a test has reverted the look-ahead on this
        // thread (`params::rehearsal::with_lookahead_zero`), which is how the
        // anti-partition tests are shown to go red against the pre-fix rule
        // without editing a line of source.
        //
        // GATED. Below `ANCESTRY_SEED_ACTIVATION_EPOCH` this is the ORIGINAL
        // rule, `back = 1`, because the existing chain's blocks were produced
        // and validated under it and boot is a replay of that log through this
        // same function. Changing it unconditionally does not cause a
        // disagreement, it stops the node: `ingest` rejects and returns, and
        // the node parks silently at an old height. See the constant's docs.
        #[cfg(test)]
        let gate_open = crate::params::rehearsal::gates_are_forced_open();
        #[cfg(not(test))]
        let gate_open = false;
        let lookahead = if !gate_open && epoch < crate::params::ANCESTRY_SEED_ACTIVATION_EPOCH {
            0
        } else {
            #[cfg(test)]
            {
                crate::params::rehearsal::effective_lookahead()
            }
            #[cfg(not(test))]
            {
                crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS
            }
        };
        let back = 1 + lookahead;
        let Some(src) = epoch.checked_sub(back) else {
            return Self::rehearsal_mutate(self.genesis_mix);
        };
        Self::rehearsal_mutate(match self.boundary_mixes.get(&src) {
            Some(m) => *m,
            // Unreachable by the retention invariant (the current epoch's
            // seed is always among the last 2 boundaries), but a consensus
            // function is not allowed to panic on any input, so the total
            // fallback is the genesis mix rather than an unwrap.
            None => self.genesis_mix,
        })
    }

    /// The A/B comparator's tripwire: a planted one-bit difference the
    /// rehearsal turns on to prove the comparator goes red when the halves
    /// really do disagree. Identity in any build that is not a test build.
    #[inline]
    fn rehearsal_mutate(seed: [u8; 32]) -> [u8; 32] {
        #[allow(unused_mut)]
        let mut seed = seed;
        #[cfg(test)]
        if crate::params::rehearsal::MUTATE_SEED.with(std::cell::Cell::get) {
            seed[0] ^= 0x01;
        }
        seed
    }


    /// The duty roster for `epoch`: active registry records plus activated
    /// delegated stake, with the genesis-cohort cap applied last.
    ///
    /// Derived on demand, never cached: everything it reads is committed and
    /// frozen for the epoch (stake mutations happen only at boundaries, new
    /// delegations request from the *next* epoch), so recomputation cannot
    /// disagree with itself — and a cached roster is exactly the §5.5 pattern
    /// this crate bans.
    ///
    /// # This function owns the membership predicate
    ///
    /// Since `committees::epoch_committees` stopped filtering on stake
    /// (2026-08-24), **the index set this function returns IS committee
    /// membership.** The predicate is `!slashed && activation_epoch <= epoch
    /// && epoch < exit_epoch` — the same three clauses
    /// `derive::active_validators` applies to the registry, which is what lets
    /// four independent roster producers agree on one partition. Anything
    /// added to it here — in particular any stake threshold — silently
    /// un-agrees them, because `derive` has neither delegation, nor the cohort
    /// cap, nor the leak to compare against. Stake belongs in the
    /// `effective_stake` field, which decides weight; not in the filter, which
    /// decides membership.
    ///
    /// # Caveat: the index set is NOT frozen for the epoch
    ///
    /// The stake is, but the membership is not: `apply_slashing_evidence` sets
    /// `slashed` mid-epoch, so a validator can leave this roster between two
    /// blocks of the same epoch and re-sort the partition under votes already
    /// admitted. See the comment on the `debug_assert_eq!` in `close_epoch`.
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
    /// out of `eligible` in `sample` — it stops being drawn to propose, and
    /// its empty slots go to the live set, which is the liveness the leak was
    /// supposed to buy back.
    ///
    /// It does **not** stop holding a committee seat, and that is deliberate
    /// since 2026-08-24. `committees::epoch_committees` no longer filters on
    /// stake: membership is a pure function of (seed, epoch, index set), so
    /// this roster and [`Self::duty_roster_at`] — which differ only in stake,
    /// never in index set — partition identically, and the inclusion check at
    /// step 8 can no longer disagree with the boundary tally about who was in
    /// which committee. The seat a fully-leaked validator keeps is inert: it
    /// carries zero weight into both the quorum numerator and denominator.
    /// Read `epoch_committees`' docs before changing either roster.
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
        ROOT_COMPUTATION_COUNT.with(|c| c.set(c.get().wrapping_add(1)));
        // Instrumentation only; compiled out without `perf-timing`.
        let _perf = crate::perf::span(crate::perf::Phase::StateRoot);
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

        // The eUTXO component comes in as the subtree the set already holds,
        // not as a cloned vector of entries to re-serialize, re-hash and
        // re-walk into a tree — cloning it shares every leaf this block did
        // not touch. `&[]` below
        // is not "no balances" — it is the field this path does not read; the
        // balances arrive through `self.eutxos.tree()` on the call itself.
        // (It genuinely WAS `&[]` once, under a comment saying the node
        // supplied it, and nothing did: every block from genesis committed an
        // empty balance component. Hence the emphasis.)
        crate::state_root::state_root_with_eutxo_tree(&ConsensusState {
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
        }, self.eutxos.tree())
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
    ///
    /// `verifier` is threaded in because a transfer's authorisation is a
    /// signature check, and the only thing that may decide whether an output
    /// moves is whether its owner said so.
    /// Is unfunded bonding (`Deposit`, `Delegate`) active in `epoch`?
    ///
    /// `epoch` is the caller's `self.epoch`, which `compute_post_state` has
    /// already rolled to the judged block's own `epoch_of(header.slot)`. It is
    /// committed state, never a clock — see the constant's docs for the full
    /// divergence argument and for why arming the constant is not how deposits
    /// open.
    fn unfunded_bonding_active(epoch: u64) -> bool {
        #[cfg(test)]
        let forced = crate::params::rehearsal::bonding_gate_forced_open();
        #[cfg(not(test))]
        let forced = false;
        forced || epoch >= crate::params::DEPOSIT_ACTIVATION_EPOCH
    }

    /// Is the AUTHENTICATED exit rule active in `epoch`?
    ///
    /// One reader for one gate, so the three sites it governs — legacy `Exit`
    /// becoming invalid, `ExitV2` becoming valid, and the
    /// [`staking::MAX_EXITS_PER_EPOCH`] churn cap starting to bind — can never
    /// drift apart into a chain where the old message is dead and the new one
    /// is not yet alive. `epoch` is the caller's `self.epoch`: committed
    /// state, rolled to the judged block's own `epoch_of(header.slot)`, never
    /// a clock.
    fn exit_auth_active(epoch: u64) -> bool {
        #[cfg(test)]
        let forced = crate::params::rehearsal::exit_auth_gate_forced_open();
        #[cfg(not(test))]
        let forced = false;
        forced || epoch >= crate::params::EXIT_AUTH_ACTIVATION_EPOCH
    }

    fn apply_transaction(
        &mut self,
        tx: &PosTransaction,
        total_active_sat: u128,
        base_fee_millisat_per_gas: u128,
        verifier: &dyn SignatureVerifier,
    ) -> Result<fee_market::TxCharge, TxReject> {
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
                proof_of_possession,
            } => {
                // THE FLAG-DAY GATE, FIRST — before the registry is even
                // consulted, for the same reason the TransferV2 arm above puts
                // its gate first. Read from `self.epoch`: COMMITTED state,
                // rolled to this block's epoch by compute_post_state's boundary
                // walk, never node-local. `DEPOSIT_ACTIVATION_EPOCH` is
                // `u64::MAX`, so this refuses at EVERY epoch — which is the
                // point. Until this existed the only thing standing between a
                // block and stake minted from nothing was
                // `bloch-pos-node`'s `admissible`, mempool policy that one
                // producer could lift for the whole network.
                if !Self::unfunded_bonding_active(self.epoch) {
                    return Err(TxReject::StakingNotActive);
                }
                let pubkey_hash: [u8; 32] = Sha3_256::digest(pubkey).into();
                // A second deposit of a registered key is a top-up path
                // decision the interface refuses to make implicitly.
                if self.pubkey_index.contains_key(&pubkey_hash) {
                    return Err(TxReject::StakingRule);
                }
                // Per-validator cap: 1% of committed active stake, floored at
                // the minimum deposit — a naive 1% cap at genesis (active
                // stake ≈ 0) would deadlock the bootstrap (staking.rs docs).
                // DERIVED here, ENFORCED there: only this scope can see the
                // committed active stake (§5.5 forbids taking it from
                // anything node-local), and only `staking` may say what the
                // bound means.
                let cap = (total_active_sat * delegation::MAX_VALIDATOR_STAKE_BPS / 10_000)
                    .max(staking::MIN_DEPOSIT_SAT);
                // THE DEPOSIT RULES, all of them, in ONE call to the ONE
                // function that owns them (`staking::validate_wire_deposit`,
                // whose shape half is `staking::deposit_shape` — the same
                // function the §7.1 `validate_deposit` path calls). Nothing
                // above this line inspects `pubkey.len()` or the amount, and
                // that is deliberate: this arm used to restate the bounds
                // inline while the callee restated the geometry, so one
                // consensus rule had two derivations and two places to drift.
                // Cheapest-first survives the move — `deposit_shape` runs
                // inside the callee before the ~4.6 KB hybrid verification,
                // the most expensive check in the arm.
                //
                // This is the check whose absence let a deposit register a key
                // nobody holds: a rogue-key registration lifted from someone
                // else's public bytes takes a committee seat that can never be
                // filled by anyone, and its stake still counts against the
                // quorum everybody else has to reach. Since the committee path
                // was changed to verify signatures against the key the STATE
                // ROOT commits (`attestation::KeyLookup`), that is the key
                // written right below — permanently, because no production
                // path removes a registry record or rewrites its key.
                //
                // Detailed rejects collapse to `StakingRule` deliberately, per
                // this enum's own doc: `DepositReject` is the admission
                // boundary's taxonomy, and a second one here would be the same
                // duplicate-derivation habit in the error space.
                if staking::validate_wire_deposit(
                    pubkey,
                    *amount_sat,
                    randao_commitment,
                    withdrawal_credentials,
                    *commission_bps,
                    proof_of_possession,
                    cap,
                    verifier,
                )
                .is_err()
                {
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
                // THE FLAG-DAY GATE, FIRST — same discipline as the Deposit
                // and TransferV2 arms, and read from `self.epoch`: COMMITTED
                // state, rolled to this block's epoch by compute_post_state's
                // boundary walk, never node-local. At and above
                // EXIT_AUTH_ACTIVATION_EPOCH the unauthenticated message is
                // dead and `ExitV2` is the only voluntary exit; the constant
                // is `u64::MAX`, so today this never fires and everything
                // below is byte-for-byte the behaviour that shipped.
                if Self::exit_auth_active(self.epoch) {
                    return Err(TxReject::StakingNotActive);
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
            PosTransaction::ExitV2 { pubkey_hash, epoch, signature } => {
                // The gate first, before the registry is consulted and long
                // before a hybrid verification is paid for.
                if !Self::exit_auth_active(self.epoch) {
                    return Err(TxReject::StakingNotActive);
                }
                self.apply_exit_v2(pubkey_hash, *epoch, signature, verifier).map(|()| free)
            }
            PosTransaction::Delegate { delegator, validator, amount_sat, eligible } => {
                // Same gate, same constant, and it must be the same constant:
                // a delegation adds to `effective_stake` through
                // `consensus_roster_at` and requests from `self.epoch + 1`, so
                // it reaches consensus weight FASTER than a deposit, which
                // waits out ACTIVATION_DELAY_EPOCHS. Closing the slow door
                // alone would be a fix that reads like one and is not.
                if !Self::unfunded_bonding_active(self.epoch) {
                    return Err(TxReject::StakingNotActive);
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
            // Evidence needs the injected signature verifier, which lives on
            // the Transition, not on the state — compute_post_state routes it
            // to `apply_slashing_evidence` before this method is reached.
            // Reaching this arm means a caller bypassed that seam; refusing
            // beats silently accepting unverified evidence.
            PosTransaction::SlashingEvidence(_) => Err(TxReject::MisroutedEvidence),
        }
    }

    /// How many voluntary exits have already been included in the epoch this
    /// state is open on — the input to the [`staking::MAX_EXITS_PER_EPOCH`]
    /// churn budget.
    ///
    /// # Derived from the committed registry, never counted into a new field
    ///
    /// Both exit arms set `exit_epoch = self.epoch + EXIT_DELAY_EPOCHS`, so
    /// "was this exit included during epoch E" is already written down in
    /// state: it is exactly the records whose `exit_epoch` equals
    /// `E + EXIT_DELAY_EPOCHS`. Counting them is a pure function of committed
    /// data, which buys three things a counter field would not:
    ///
    /// - **no state-root change.** A new `CommittedState` field that the root
    ///   commits to would re-key leaves on replay and split a mixed fleet
    ///   *before* the flag day, which is the one thing the gate exists to
    ///   prevent. A field the root did NOT commit to would be worse: consensus
    ///   reading uncommitted state is the shape of the 2026-08-08
    ///   `expected_bits` fork.
    /// - **no reset to get wrong.** There is no epoch-boundary bookkeeping to
    ///   forget in `close_epoch`; the window moves because `self.epoch` moved.
    /// - **agreement by construction.** Two nodes with the same registry
    ///   compute the same number, in any order, from any replay path.
    ///
    /// Slashing does NOT consume this budget: `apply_slashing_evidence` sets
    /// `exit_epoch = self.epoch` (no delay), which cannot equal
    /// `self.epoch + EXIT_DELAY_EPOCHS` while `EXIT_DELAY_EPOCHS` is non-zero.
    /// A forced ejection is not a voluntary exit and must not be able to
    /// exhaust the voluntary budget — nor to be blocked by it.
    fn voluntary_exits_this_epoch(&self) -> usize {
        let marker = self.epoch.saturating_add(staking::EXIT_DELAY_EPOCHS);
        // The `!= u64::MAX` half is not redundant. `u64::MAX` is the registry's
        // sentinel for "never exited", and `saturating_add` makes the marker
        // equal that sentinel once `self.epoch` is within EXIT_DELAY_EPOCHS of
        // the top — at which point a bare equality would count every ACTIVE
        // validator as having exited this epoch and wedge the budget shut
        // forever. Unreachable arithmetic, guarded anyway: an epoch counter is
        // exactly the kind of thing that is unreachable until it is not, and
        // the guard costs one comparison on a 64-entry map.
        self.validators
            .values()
            .filter(|r| r.exit_epoch != u64::MAX && r.exit_epoch == marker)
            .count()
    }

    /// Apply an authenticated voluntary exit. Seam below
    /// [`crate::params::EXIT_AUTH_ACTIVATION_EPOCH`]; the caller holds the
    /// gate, this function holds the rules.
    ///
    /// # Where this runs — the whole chain, written down
    ///
    /// `Transition::apply_block` → `compute_post_state` step 10 → the
    /// transaction loop's `_ => st.apply_transaction(..)` → the `ExitV2` arm →
    /// here. There is no second dispatcher and no parallel validator: step 10
    /// names only `SlashingEvidence` and routes everything else through
    /// `apply_transaction`, so this is the ONE path a block's transactions
    /// take on every node. `exit_v2_transitions_through_apply_block_and_is_inert_below_the_gate`
    /// drives a real signed block down it rather than asserting it here, for
    /// the reason `derive::validate_block` exists as a warning: a rule
    /// exercised only at its own seam can be correct and unreachable at once.
    ///
    /// And it is reachable in exactly the sense that matters and no further.
    /// **Nothing on the fleet executes this today**, and nothing can: the gate
    /// is `u64::MAX`, so the caller refuses before this function is entered,
    /// and the wire byte is unassigned so no gossiped message could carry an
    /// `ExitV2` even if it were open. Arming is the founder's, and it has an
    /// unmet precondition. What is claimed here is narrower and checkable:
    /// spec-correct, composed with the real handler, and tested under a
    /// rehearsal gate, so that WHEN it is armed it is right.
    ///
    /// Check order is cheapest-first, the discipline the whole crate keeps:
    /// epoch equality, identity resolution, lifecycle, the churn budget, and
    /// only then the one hybrid verification (~145 µs). An attacker spamming
    /// exits for validators that are already exiting, or exits past the
    /// epoch's budget, pays arithmetic and a `BTreeMap` lookup — never a
    /// signature check.
    ///
    /// Every check runs before any mutation, so a refused exit leaves the
    /// state untouched.
    fn apply_exit_v2(
        &mut self,
        pubkey_hash: &[u8; 32],
        epoch: u64,
        signature: &[u8],
        verifier: &dyn SignatureVerifier,
    ) -> Result<(), TxReject> {
        // Equality, not `<=`: `staking::validate_exit` refuses only FUTURE
        // epochs because it is the reference validator and does not know when
        // inclusion happens. Consensus does, so it can be stricter, and must
        // be — a message signed for epoch E and included at E+900 would start
        // the withdrawal clock at a time the signer never agreed to, and would
        // make a captured exit permanently replayable.
        if epoch != self.epoch {
            return Err(TxReject::StakingRule);
        }
        // Identity, not position: the message names a key hash, and the
        // registry resolves it. `pubkey_index` is injective and permanent
        // (indices are never reused, records are never removed), so this
        // cannot resolve to a different validator on a different node.
        let Some(index) = self.pubkey_index.get(pubkey_hash).copied() else {
            return Err(TxReject::StakingRule);
        };
        let Some(rec) = self.validators.get(&index) else {
            return Err(TxReject::StakingRule);
        };
        // Same lifecycle rules as the legacy arm — active, not already
        // exiting, not slashed. Slashing owns its own ejection path and must
        // not share the voluntary one, or a slashed validator could reset its
        // withdrawal clock.
        if rec.slashed || rec.activation_epoch > self.epoch || rec.exit_epoch != u64::MAX {
            return Err(TxReject::StakingRule);
        }
        // THE CHURN BUDGET. Deliberately before the signature: it is the rule
        // that survives every key being genuine, so it must also be the rule
        // an attacker cannot make expensive to enforce.
        if self.voluntary_exits_this_epoch() >= staking::MAX_EXITS_PER_EPOCH {
            return Err(TxReject::StakingRule);
        }
        // THE AUTHORISATION, LAST. Against `rec.pubkey` — the key the registry
        // committed at registration — and over the shared `DS_EXIT` root, so
        // this crate has exactly one definition of what an exit signature
        // covers. A key carried in the message would authorise nothing: the
        // signer would be choosing their own public key.
        let root = staking::ExitTx {
            pubkey_hash: *pubkey_hash,
            epoch,
            signature: Vec::new(),
        }
        .signing_root();
        if !verifier.verify_with_key(&rec.pubkey, &root, signature) {
            return Err(TxReject::StakingRule);
        }
        // Mutation only after every check has passed.
        let Some(rec) = self.validators.get_mut(&index) else {
            return Err(TxReject::StakingRule);
        };
        let exit_epoch = self.epoch.saturating_add(staking::EXIT_DELAY_EPOCHS);
        rec.exit_epoch = exit_epoch;
        rec.withdrawable_epoch = exit_epoch.saturating_add(staking::WITHDRAWAL_DELAY_EPOCHS);
        Ok(())
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
                // `&self.validators` beside `&mut self.slashing`: disjoint
                // fields, so borrowck allows it, and the offender's key comes
                // from the same pre-state registry that everything else in
                // this block is judged against.
                //
                // Slashing is the site where the old index table failed most
                // quietly. A deposit-added validator was not merely unable to
                // vote — it was UNSLASHABLE: evidence against it hit
                // `pubkeys.get(index) == None`, returned false, and was
                // rejected as `BadSignature`. It could equivocate for free.
                // A record is never removed from the registry (exit and
                // slashing set fields, they do not delete), so evidence
                // against an exited or already-slashed validator still
                // resolves its key here.
                self.slashing.process(
                    &pair,
                    self.epoch,
                    &exposure,
                    total_active_sat,
                    including_proposer,
                    verifier,
                    &self.validators,
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
                    &self.validators,
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

    /// Cumulative issuance this state commits to, in satoshis
    /// (`state_root::TAG_ISSUED_SUPPLY`). The numerator of the hard cap and
    /// the right-hand side of the conservation invariant below.
    pub fn issued_sat(&self) -> u128 {
        self.issued_sat
    }

    /// **Every satoshi this state says someone holds**, in satoshis: the sum
    /// of every place a coin can sit in committed state.
    ///
    /// Six terms, and the list is exhaustive by construction — a coin that
    /// sat anywhere else could not be committed, because the state root has no
    /// other value-bearing component (`state_root`'s tag list). Five are
    /// places a coin sits:
    ///
    /// 1. the unspent-output set (`TAG_EUTXO`) — spendable coins;
    /// 2. bonded stake, `ValidatorRecord::staked_sat` summed over the whole
    ///    registry, exited and slashed records included (an exited bond is
    ///    still a bond until a withdrawal path pays it out, and there is no
    ///    such path yet — see `staking::apply_exit`);
    /// 3. delegated stake (`TAG_DELEGATION`) — bonded by someone who is not
    ///    the operator, and just as real;
    /// 4. fee rewards accrued during the open epoch and not yet compounded
    ///    (`TAG_PENDING_FEE`) — coins that have left the eUTXO set and have
    ///    not yet reached a bond, i.e. exactly the in-flight case an
    ///    invariant that skipped it would misread as a mint;
    /// 5. the delegator fee ledger (`TAG_DELEGATOR_FEE_REWARD`) — the
    ///    delegators' settled share, which lives in a ledger rather than in
    ///    their delegation records for the reason those docs give.
    ///
    /// and **minus** the sixth term, which is a debit and not a holding:
    ///
    /// 6. `delegator_slash_losses` (`TAG_DELEGATOR_SLASH_LOSS`) — satoshis a
    ///    slash destroyed out of delegated bonds.
    ///
    /// # Why the slash ledger is subtracted, and why getting this wrong was a
    /// # hole in the invariant rather than a rounding note
    ///
    /// `apply_slash` computes each delegation's pro-rata loss and **does not
    /// mutate the delegation record** (`delegation::apply_slash` returns a
    /// vector; the operator's own bond is debited from `staked_sat`, the
    /// delegators' side is only recorded here). So term 3 above keeps
    /// reporting the delegators' pre-slash `amount_sat` forever, and the burn
    /// is invisible to a total that stops at five terms.
    ///
    /// That is not a cosmetic understatement of a burn. The whistleblower is
    /// paid `total_slashed / 32` where `total_slashed` covers the operator's
    /// bond **and** every delegated bond behind it
    /// (`slashing::WHISTLEBLOWER_QUOTIENT`), and that payment lands in
    /// `pending_fee_rewards`, which term 4 *does* count. Five terms therefore
    /// move by `whistleblower − operator_loss` on a slash, which is
    /// **positive** whenever the operator's own bond is under 1/32 of the
    /// stake behind it — a heavily-delegated validator, i.e. exactly the
    /// shape delegation exists to produce. The invariant would then refuse an
    /// honest block: a false red in a consensus path, which is a halt.
    ///
    /// Subtracting the ledger makes both sides right at once. The delta over
    /// a slash becomes `−(operator_loss + delegator_losses) + total/32`,
    /// which is `−31/32` of the penalty: negative, so the burn is seen, and
    /// safely inside `<=`, so no honest block is refused.
    ///
    /// `saturating_sub` on the aggregate: the ledger is bounded by the bonds
    /// it was computed from (a validator is slashed at most once —
    /// `SlashingState::ejected` and `rec.slashed` both refuse a second), so
    /// it cannot exceed term 3. Saturating rather than asserting because a
    /// consensus path must not panic, and a saturated total can only make the
    /// left-hand side smaller, which is the direction that refuses nothing.
    ///
    /// # What this number is not
    ///
    /// It is not equal to [`Self::issued_sat`], and on Genesis-4 mainnet it
    /// never was. Two standing reasons, both named rather than left to be
    /// discovered:
    ///
    /// - **Burns are one-way and uncounted.** The base-fee share and the
    ///   uncredited part of a slashing penalty are burned *by omission* —
    ///   nobody is credited and no counter decrements (`issued_sat` is gross
    ///   and monotone by design). So this total drifts BELOW issuance, by the
    ///   amount ever burned, and that is correct.
    /// - **The genesis cohort's bonds were never issued.** The mainnet
    ///   manifest funds 64 validators with 25,000 BLOCH each — 1,600,000
    ///   BLOCH — while `Manifest::genesis_issued_sat` sums only the carryover
    ///   and the five allocation buckets. That stake was minted from nothing
    ///   at slot 0, so this total opens ABOVE `GENESIS_ISSUED_SAT` by exactly
    ///   that much. It cannot be corrected in place: `issued_sat` is committed
    ///   state, and rewriting a live chain's genesis is a relaunch, not a
    ///   patch.
    ///
    ///   What IS closed is the way it happened. `Manifest::check_supply` does
    ///   **not** count validator bonds and never did — it sums the carryover
    ///   and the allocations, because it has to mean exactly what the
    ///   `issued_sat` counter means or it would be checking a different
    ///   quantity from the one the chain commits. The bonds are counted by
    ///   `Manifest::check_bonds_are_funded`, which since 2026-09-04 is a hard
    ///   error on the `genesis-mainnet` exit path rather than a printed
    ///   warning, and by the assertion in `CommittedState::genesis` itself, so
    ///   no future genesis can bond MORE outside its issuance than
    ///   `tokenomics_v4::GENESIS_UNFUNDED_BONDED_CEILING_SAT` — the frozen
    ///   record of what this chain already did. (Until 2026-09-04 this
    ///   paragraph claimed `check_supply` counted the bonds. It did not, and
    ///   the claim is corrected rather than deleted because the correction is
    ///   the point: the check that closes this lives under another name.)
    ///
    ///   The way it could have GROWN is the invariant below.
    ///
    /// Both are why the invariant is a **delta** rule and a one-sided one, not
    /// an equality against a constant: a fixed offset present in both the pre
    /// and the post state cancels, and burns can only move the total the safe
    /// way.
    pub fn accounted_supply_sat(&self) -> u128 {
        let held = self.eutxos.total_sat()
            + self.validators.values().map(|r| r.staked_sat).sum::<u128>()
            + self.delegations.iter().map(|d| d.amount_sat).sum::<u128>()
            + self.pending_fee_rewards.values().sum::<u128>()
            + self.delegator_fee_rewards.values().sum::<u128>();
        let burned = self.delegator_slash_losses.values().sum::<u128>();
        held.saturating_sub(burned)
    }

    /// How far this state's holdings sit above its issuance counter, in
    /// satoshis: `accounted_supply_sat() - issued_sat()`, signed.
    ///
    /// **The genesis leg of the invariant, made visible instead of assumed.**
    /// The conservation rule in `compute_post_state` is a *delta* — it judges
    /// how the two numbers move relative to each other — so a constant offset
    /// present at slot 0 cancels on every block and is never observed. That
    /// is the right rule (see [`Self::accounted_supply_sat`]) and it leaves
    /// the opening itself unjudged, which is precisely where Genesis-4's
    /// 1,600,000 BLOCH went: `CommittedState::genesis` bonds the launch
    /// cohort's `staked_sat` while seeding `issued_sat` from
    /// `tokenomics_v4::GENESIS_ISSUED_SAT`, which sums the carryover and the
    /// allocation buckets and not the bonds.
    ///
    /// So this returns a positive number at genesis, and that is a fact about
    /// a live chain rather than a bug to be fixed here: `issued_sat` is
    /// committed state, and rewriting a running chain's slot 0 is a relaunch.
    /// What this accessor buys is that the offset is *named, readable and
    /// pinned by test* (`the_genesis_supply_gap_is_exactly_the_cohorts_bonds`)
    /// rather than an unexplained constant discovered later by someone
    /// wondering why two supply figures disagree.
    ///
    /// Signed, because it goes negative in ordinary operation: burns are
    /// one-way and uncounted, so a chain that has run for a while holds less
    /// than it has issued. `i128` cannot overflow on the difference — both
    /// terms are bounded by `TOTAL_SUPPLY_SAT`, 54% of `u64::MAX`.
    pub fn supply_gap_sat(&self) -> i128 {
        self.accounted_supply_sat() as i128 - self.issued_sat as i128
    }

    /// Does `post` hold no more than `pre` plus what the transition between
    /// them was entitled to create? The supply-conservation invariant, as one
    /// predicate.
    ///
    ///   `accounted(post) <= accounted(pre) + minted + unfunded_bonded`
    ///
    /// where `minted` is the rise in the committed issuance counter and
    /// `unfunded_bonded` is what the block bonded without spending an output
    /// (`Deposit`/`Delegate`; zero on every block a chain can currently
    /// produce — `params::DEPOSIT_ACTIVATION_EPOCH` is `u64::MAX`).
    ///
    /// A predicate and not four lines inline in `compute_post_state` for one
    /// reason: the failing side has to be testable. The passing side is
    /// exercised by every block in this crate's suite, but a guard nobody has
    /// ever seen refuse anything is a guard nobody knows is wired up — and
    /// the states that would trip this one (a bond credited without advancing
    /// `issued_sat`) cannot be reached through the transition, only
    /// constructed. See `an_inflated_bond_is_refused_as_unconserved_supply`.
    ///
    /// `saturating_add` on the allowance: an overflow there would wrap the
    /// ceiling to a small number and refuse honest blocks, so it saturates
    /// upward. It cannot lose a violation — the terms are all bounded by
    /// `TOTAL_SUPPLY_SAT`, which is 54% of `u64::MAX` and nowhere near
    /// `u128`.
    fn supply_conserved(pre: &Self, post: &Self, unfunded_bonded: u128) -> bool {
        let minted = post.issued_sat.saturating_sub(pre.issued_sat);
        let allowed = pre
            .accounted_supply_sat()
            .saturating_add(minted)
            .saturating_add(unfunded_bonded);
        post.accounted_supply_sat() <= allowed
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
    fn close_epoch(&self) -> CommittedState {
        // Instrumentation only; compiled out without `perf-timing`.
        let _perf = crate::perf::span(crate::perf::Phase::EpochBoundary);
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
            //
            // The PARTITION is drawn from `consensus_roster_at` — the roster
            // step 8 admitted these votes against — while the DENOMINATOR base
            // stays the unleaked `roster`, because `process_epoch` subtracts
            // the leak itself and would otherwise charge it twice. Below
            // `LEAKED_ROSTER_ACTIVATION_EPOCH` the two are the same value, so
            // this changes nothing about the chain as it stands; above it, it
            // is what keeps the boundary tally reading the same committee the
            // block did.
            let mut accepted = Vec::new();
            let partition_set = st.consensus_roster_at(closing);
            let epoch_votes = finality::votes_from_partition(
                closing,
                &roster,
                &partition_set,
                &votes,
                &st.seed_for_epoch(closing),
                &mut accepted,
            );
            // DELIBERATELY STILL A `debug_assert!`, and this is the one place
            // in the crate where that is a decision rather than an omission.
            //
            // The brief for the 2026-08-24 roster unification asked for this to
            // become a `consensus_invariant!` so it would survive into the
            // release binary. It must not, because **untrusted input can drive
            // it**, and an unconditional panic here would therefore be a
            // remotely triggerable halt:
            //
            //   `apply_slashing_evidence` sets `rec.slashed = true` and
            //   `rec.exit_epoch = epoch` the moment a valid `SlashingEvidence`
            //   transaction is applied — mid-epoch. `duty_roster_at` filters on
            //   exactly that predicate, so the roster's INDEX SET shrinks
            //   between one block of the epoch and the next. Step 8 of every
            //   later block then partitions a 63-member set while the votes
            //   already in `pending_votes` were admitted against the 64-member
            //   one, and this boundary tally partitions the 63-member set too.
            //   A Fisher-Yates over a different length is a different
            //   permutation everywhere, so those earlier votes are dropped here
            //   — legitimately, by the rule as written — and the counts differ.
            //   Anyone who can get valid equivocation evidence included can
            //   cause it.
            //
            // Removing the `effective_stake > 0` filter from
            // `epoch_committees` closed the LEAK half of this divergence (the
            // two rosters now carry the same index set whatever the leak does).
            // It does not close the SLASHING half, which is a membership change
            // in committed state, not a stake change — fixing that means
            // freezing the epoch's roster at its first slot, which is a
            // consensus rule change and needs its own flag day and rollout.
            // Until that lands, this stays a test-build guard, and the
            // divergence is pinned by
            // `mid_epoch_slashing_changes_the_roster_index_set_within_one_epoch`.
            // The unconditional half of the guard: present in the release
            // binary, never fatal. See `report_boundary_vote_drop` for why
            // fatal is wrong here and what would have to change to make it
            // right. Runs BEFORE the debug_assert so a test build records the
            // occurrence before it stops.
            if epoch_votes.attestations.len() != votes.len() {
                report_boundary_vote_drop(closing, votes.len(), epoch_votes.attestations.len());
            }
            debug_assert_eq!(
                epoch_votes.attestations.len(),
                votes.len(),
                "boundary partition dropped votes that the inclusion check at step 8 admitted - \
                 the two filters have diverged (or a mid-epoch slash moved the roster)"
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
                        if !mutation_mints_from_nothing() {
                            st.issued_sat += payout.operator;
                        }
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
        // UNCONDITIONAL, not a `debug_assert!` — see `crate::consensus_invariant`
        // for why the release profile compiles those out and why halting beats
        // diverging.
        //
        // Why this condition is internal and cannot be driven by untrusted
        // input: both sides come from ONE value, `roster_next`, which is
        // derived from already-validated committed state. Nothing a block, a
        // transaction or a peer can carry appears on either side — the only way
        // they can differ is if `epoch_committees` stops covering its input
        // exactly once, which is a code bug in this crate.
        //
        // IDENTITY, NOT CARDINALITY, and that distinction is the whole value of
        // this guard. It compared seat COUNT against roster LENGTH until
        // 2026-08-24, and in that form it was a tautology in the shipped binary:
        // both sides reduce to `roster_next.len()`, and no input can separate
        // them. The concrete input that walks straight through the counting
        // version is one character in the shuffle —
        //
        //     committees.rs:  eligible.swap(i, j)  ->  eligible[i] = eligible[j]
        //
        // which DUPLICATES one index and LOSES another while the length stays
        // exactly right. A real partition bug, invisible to a seat count.
        // Comparing the sorted index vectors catches it, and costs one sort of
        // a list that is already tiny.
        let mut seated: Vec<u32> = partition.iter().flatten().copied().collect();
        seated.sort_unstable();
        let mut expected: Vec<u32> = roster_next.iter().map(|v| v.index).collect();
        expected.sort_unstable();
        consensus_invariant!(
            seated == expected,
            "epoch partition must seat every validator exactly once: {} seats over {} \
             validators, and the index sets differ",
            seated.len(),
            expected.len()
        );

        st
    }
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
        // KEEPING the zeroed record is load-bearing, not incidental. Committee
        // membership is a function of (seed, epoch, index set), so the leaked
        // and unleaked rosters partition identically only while they carry the
        // SAME index set. Dropping the record here re-opens the 2026-08-24
        // roster split from the other side, and the committee-level tests would
        // not see it, because they build both rosters as fixtures rather than
        // through these call sites. Pinned by
        // `the_two_call_sites_agree_on_the_index_set_with_a_real_leak`.
        .filter(|v| !mutation_leak_drops_zeroed() || v.effective_stake > 0)
        .collect()
}

/// **MUTATION SWITCH.** `true` makes `close_epoch` credit the epoch's reward
/// into the operator's bond **without advancing `issued_sat`** — a mint from
/// nothing, planted on the production path.
///
/// It is the mutation the supply-conservation invariant exists for, and the
/// only one that distinguishes it from the hard cap beside it: the counter
/// stays below `TOTAL_SUPPLY_SAT` forever, so `SupplyCapExceeded` never
/// fires, while the ledger grows every epoch. Pinned by
/// `an_inflated_bond_is_refused_as_unconserved_supply`.
///
/// Constant `false` in every build that is not a test build, so the branch
/// folds away and the switch cannot exist in a shipped binary.
#[inline]
fn mutation_mints_from_nothing() -> bool {
    #[cfg(test)]
    {
        return crate::params::rehearsal::mint_from_nothing();
    }
    #[cfg(not(test))]
    false
}

/// **MUTATION SWITCH.** `true` makes [`with_leak_applied`] drop a fully-leaked
/// validator instead of keeping it at zero — the defect, from the other door.
///
/// Constant `false` in every build that is not a test build, so the branch
/// folds away and the switch cannot exist in a shipped binary.
#[inline]
fn mutation_leak_drops_zeroed() -> bool {
    #[cfg(test)]
    {
        return crate::params::rehearsal::LEAK_DROPS_ZEROED
            .load(std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(not(test))]
    false
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

        // 3d. THE BOUNDARY WALK BELOW MUST HAVE A CEILING.
        //
        // Its trip count is `block_epoch`, which is `epoch_of(header.slot)`,
        // which is an untrusted u64 that arrived over gossip. `u64::MAX`
        // divided by 32 slots is ~5.76e17, and every turn clones the whole
        // eUTXO set: unbounded, one packet costs every node that judges it its
        // remaining uptime. `params::MAX_EPOCH_ADVANCE` is that ceiling — a
        // plain bound, live at every epoch, with no flag day and nothing to
        // arm. `block_epoch >= pre.epoch` is already guaranteed by the check
        // above; `saturating_sub` says so rather than relying on it.
        //
        // Checked BEFORE the state clone (the clone is the expensive part) and
        // before the walk it bounds. It is deliberately here and not up beside
        // step 1, so that every block that was already a reject keeps
        // returning the SAME error it returned before this rule existed.
        if block_epoch.saturating_sub(pre.epoch) > crate::params::MAX_EPOCH_ADVANCE {
            return Err(TransitionError::EpochAdvanceTooLarge);
        }

        // Roll epoch accounting over any empty boundary slots the chain
        // skipped. Identical to the caller invoking process_epoch itself —
        // close_epoch is the single definition of the boundary — so explicit
        // and implicit epoch processing cannot diverge. Bounded by 3d above.
        let mut st = {
            // Instrumentation only; compiled out without `perf-timing`.
            let _perf = crate::perf::span(crate::perf::Phase::StateClone);
            pre.clone()
        };
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
        //
        //    The key comes from `st.validators` — the registry of the BLOCK'S
        //    PRE-STATE, which is the parent's post-state. Not this node's
        //    head, not `rolled_to`, not a table built at boot from the genesis
        //    manifest (which is what this used to read, and why a
        //    deposit-added validator could not propose). That choice is what
        //    keeps `apply_block` a pure function of (parent state, block):
        //    every node judging this block resolves the same bytes, because
        //    they all hold the same parent state. Deriving a consensus verdict
        //    from node-local state instead is the 2026-08-08 `expected_bits`
        //    fork, and this is the same shape of decision.
        //
        //    Note the proposer signing root covers `canonical_serialize()` of
        //    the header, which includes `proposer_index` — so a proposer
        //    signature is bound to its index and cannot be replayed under
        //    another. (Attestation signing roots are NOT so bound; see the
        //    note in step 8.)
        let Some(proposer_key) = st.validators.pubkey(header.proposer_index) else {
            return Err(TransitionError::Proposal(ProposalReject::UnknownProposer));
        };
        if !self.verifier.verify_with_key(
            proposer_key,
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
        //
        //    Keys come from `st.validators`, the same pre-state registry that
        //    produced `roster` and therefore `committee`. Membership and key
        //    MUST come from one state: an attestation is authorised by the
        //    pair (this index is in the committee, this key is registered at
        //    that index), and splitting the pair across two states is how a
        //    seat drawn from one view gets filled by a key from another.
        //
        //    This matters more here than for the proposer, because
        //    `AttestationData::signing_root()` does NOT cover the validator
        //    index — it covers only the vote (slot, head, source, target). The
        //    binding of vote to voter is done entirely by which key this
        //    lookup returns. It is sound because the registry makes index→key
        //    injective and permanent (indices are never reused, pubkeys never
        //    mutated, records never removed, and the Deposit handler rejects a
        //    pubkey already registered), so no two indices can ever hold the
        //    same key and no index can ever change hands.
        for (i, att) in attestations.iter().enumerate() {
            let reject = TransitionError::Attestation(i as u32);
            if crate::epoch_of(att.data.slot) != st.epoch {
                return Err(reject);
            }
            let committee = committees::committee_for_slot(&seed, att.data.slot, &roster);
            if attestation::validate(att, &committee, header.slot, &self.verifier, &st.validators)
                .is_err()
            {
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
        // Satoshis this block bonds without spending an output. See the
        // conservation check at step 11b.
        let mut unfunded_bonded: u128 = 0;
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
                _ => st.apply_transaction(tx, total_active, base_fee, &self.verifier),
            };
            match applied {
                Ok(charge) => {
                    base_fees += charge.base_fee_sat;
                    priority_fees += charge.priority_fee_sat;
                    block_gas = block_gas.saturating_add(charge.gas);
                    block_bytes = block_bytes.saturating_add(charge.tx_bytes);
                    // Bonding that funds itself from nothing, measured where
                    // it happens. `Deposit` and `Delegate` name an
                    // `amount_sat` and spend no output, so an admitted one
                    // raises the accounted total with no issuance behind it —
                    // the conservation check below would otherwise have to
                    // refuse the very messages the deposit rehearsal exists to
                    // exercise. Naming the quantity is the honest form: it is
                    // the supply gap the block created, it is zero on every
                    // block any chain can currently produce (both arms are
                    // refused while `DEPOSIT_ACTIVATION_EPOCH` is `u64::MAX`),
                    // and when deposits are finally funded from the eUTXO set
                    // this term goes to zero permanently and the invariant
                    // tightens to an equality with no edit here.
                    match tx {
                        PosTransaction::Deposit { amount_sat, .. }
                        | PosTransaction::Delegate { amount_sat, .. } => {
                            unfunded_bonded = unfunded_bonded.saturating_add(*amount_sat);
                        }
                        _ => {}
                    }
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

        // 11b. SUPPLY CONSERVATION — the invariant that says nothing minted
        //      from nothing (2026-09-03). The hard cap at step 3c watches the
        //      issuance COUNTER; this watches whether the counter and the
        //      LEDGER agree, and they are different questions: a bug that
        //      credited a bond without advancing `issued_sat` passes the cap
        //      forever while inflating the supply on every block.
        //
        //      The rule, in one line: what committed state holds may grow by
        //      at most what this transition minted, plus what it bonded
        //      without funding.
        //
        //        accounted(post) <= accounted(pre) + minted + unfunded_bonded
        //
        //      `pre`, not the epoch-rolled `st` snapshot, on both sides — the
        //      boundary roll is part of what is being judged, so an issuance
        //      step inside `close_epoch` must be covered by this check and not
        //      hidden behind its own starting point.
        //
        //      Why each term is exactly what it is, and why `<=`, is on
        //      `TransitionError::SupplyNotConserved` and on
        //      `accounted_supply_sat`; the short form is that burns are
        //      one-way and uncounted (so the total may legitimately fall
        //      behind issuance), and that `unfunded_bonded` is zero on every
        //      block any chain can currently produce because
        //      `DEPOSIT_ACTIVATION_EPOCH` refuses both arms at every epoch.
        //
        //      Costs one subtraction and two small map walks per block: the
        //      eUTXO half is the total `EutxoSet` keeps incrementally, so this
        //      does NOT reintroduce the O(452,726) per-block walk the kept
        //      subtree exists to have removed.
        //
        //      NOT GATED, and this is deliberate. A flag day exists to stop a
        //      mixed fleet disagreeing about a block one binary accepts and
        //      another rejects; here there is no such block, because no
        //      reachable transaction can make the left side exceed the right.
        //      An old binary and a new one return the same verdict on every
        //      block either can build — which is the property a flag day buys,
        //      already held.
        if !CommittedState::supply_conserved(pre, &st, unfunded_bonded) {
            return Err(TransitionError::SupplyNotConserved);
        }

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

    /// # Why this carries no `SupplyNotConserved` return, when step 11b does
    ///
    /// Asked and decided on 2026-09-04, because the shape invites the
    /// opposite answer: this is the epoch roll, the roll is where issuance
    /// happens, and it returns a `Result` that never uses its error arm.
    ///
    /// **The block path already judges every boundary that reaches committed
    /// state.** `compute_post_state` does not call this function; it rolls
    /// the boundary itself — `while st.epoch < block_epoch { st =
    /// st.close_epoch() }` — and then runs step 11b against `pre`, the state
    /// from *before* the roll. That is deliberate and documented at 11b: the
    /// boundary is inside what is judged, not behind its own starting point.
    /// So the same `close_epoch` call, on the path where its output becomes
    /// consensus, is already covered.
    ///
    /// **This function's output never becomes committed state.** Its only
    /// production caller is `engine::Engine::rolled_to`, the memoized DUTY
    /// VIEW: the roster, seed and finality view a node derives to judge an
    /// arriving attestation. Nothing writes the result back — the engine's
    /// state is advanced by `apply_block` and nothing else — so an inflated
    /// projection here could mis-derive a committee, never mint a satoshi.
    /// Pinned by `the_boundary_roll_is_judged_on_the_block_path`.
    ///
    /// **And returning `Err` would be a regression, not a hardening.** Both
    /// engine call sites are `.expect("process_epoch is infallible")`, so an
    /// error arm here is a panic, on a path taken once per arriving
    /// attestation. Trading a mis-derived duty view for a crashed node is the
    /// wrong direction, and it would break the property the original comment
    /// names: the boundary must be processable even when the slot was empty,
    /// or a withheld proposal becomes a lever over everyone's accounting.
    ///
    /// What is added instead is a `debug_assert`, which costs nothing in a
    /// shipped binary and makes every test in both crates check the roll it
    /// just performed. That is the honest split: the consensus statement is
    /// made where consensus reads it, and the projection is checked where a
    /// developer would see it.
    fn process_epoch(&self, pre: &Self::State) -> Result<Self::State, TransitionError> {
        // Infallible by construction: the boundary must be processable even
        // when the slot was empty, or a withheld proposal becomes a lever
        // over everyone's accounting.
        let post = pre.close_epoch();
        debug_assert!(
            CommittedState::supply_conserved(pre, &post, 0),
            "an epoch boundary minted from nothing: holdings rose from {} to {} sat              while issuance rose from {} to {}. A boundary bonds only what it              issues, so this is close_epoch crediting a reward without advancing              issued_sat — the defect `mint_from_nothing` injects, reached for real.",
            pre.accounted_supply_sat(),
            post.accounted_supply_sat(),
            pre.issued_sat,
            post.issued_sat,
        );
        Ok(post)
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
                proof_of_possession: vec![0xEF; 4_589],
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
        ]
    }

    /// `ExitV2` ENCODES to `0x08` and this tree DOES NOT DECODE `0x08`.
    ///
    /// Both halves are deliberate and both are pinned here, because "the
    /// decoder happens not to know this byte yet" and "the decoder must not
    /// know this byte yet" look identical in a diff. `0x08` is contested
    /// across live lineages (`SignedExit`, `Withdraw`, `ExitV2` — see
    /// `tests/wire_tag_registry.rs`); two of those meanings are incompatible,
    /// so whichever landed second would split the chain at decode. The byte is
    /// the founder's to assign, and until it is assigned an authenticated exit
    /// cannot travel on the wire at all.
    ///
    /// Deliberately NOT in `samples()`: `canonical_bytes_round_trips` requires
    /// every sample to decode, which is exactly what this one must not do.
    #[test]
    fn exit_v2_encodes_to_an_unassigned_byte_it_cannot_decode() {
        let tx = PosTransaction::ExitV2 {
            pubkey_hash: [0xAB; 32],
            epoch: 7,
            signature: vec![0xCD; 96],
        };
        let bytes = tx.canonical_bytes();
        assert_eq!(bytes[0], 0x08, "the encoder claims 0x08");
        assert_eq!(
            PosTransaction::from_canonical_bytes(&bytes),
            Err(TxDecodeError::UnknownTag(0x08)),
            "0x08 is CONTESTED: adding a decoder arm before the founder assigns \
             the byte is what splits the chain, and is what this pins against",
        );
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
    pub(super) struct OkVerifier;
    impl SignatureVerifier for OkVerifier {
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
        fn verify_with_key(&self, _pk: &[u8], _root: &[u8; 32], sig: &[u8]) -> bool {
            sig != b"forged"
        }
    }

    // ── The deterministic chain comparator, and its tripwire ───────────────
    //
    // Real `build_block` (the producer's own walk), real `apply_block` (every
    // validation step, including the proposer draw at step 4 and the committee
    // filter at step 8), real `close_epoch`, real state roots. What is
    // replaced is the DRIVER: slots are stepped by a `for`, the RANDAO chains
    // come from fixed seeds, and nothing reads a clock. A run is a pure
    // function of (validator count, mutation flag), so machine load can change
    // how LONG a run takes and not what it produces — which is what makes a
    // bit-for-bit chain comparison meaningful on a box under load.

    /// Kept, but no longer load-bearing: `MUTATE_SEED` is now a THREAD-LOCAL
    /// (`params::rehearsal`), so a mutation cannot reach any test but the one
    /// that set it. It used to be a process global, and this mutex was the
    /// only guard — which serialised the two A/B tests against each other and
    /// left the crate's other ~260 tests reading a corrupted consensus seed
    /// whenever the tripwire held the flag up. Removing the mutex is safe;
    /// it is left in place so the two A/B runs stay serialised against each
    /// other for timing stability, and because deleting a lock is a separate
    /// change from the one that made it unnecessary.
    static AB_HOOKS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Everything one node believed after one slot. Eight fields; `assert_eq!`
    /// on the struct is what makes "all eight are compared" true by
    /// construction instead of by a checklist that can fall out of date.
    #[derive(PartialEq, Eq, Debug, Clone)]
    struct AbRecord {
        slot: u64,
        epoch: u64,
        head: [u8; 32],
        state_root: [u8; 32],
        seed: [u8; 32],
        randao_mix: [u8; 32],
        proposer: Option<u32>,
        partition: Vec<Vec<u32>>,
    }

    fn ab_run(mutate: bool, slots: u64, n: u32) -> Vec<AbRecord> {
        crate::params::rehearsal::MUTATE_SEED.with(|c| c.set(mutate));

        let (t, g, mut chains) = setup(n);
        let mut st = g;
        let mut out = Vec::new();
        for slot in 1..=slots {
            let b = build_block(&t, &st, slot, &[], &[], &mut chains);
            st = t
                .apply_block(&st, &b, &[], &[])
                .expect("the producer and the validator must agree within one run");
            let epoch = st.epoch;
            let seed = st.seed_for_epoch(epoch);
            let roster = st.duty_roster();
            out.push(AbRecord {
                slot,
                epoch,
                head: *st.head.as_bytes(),
                state_root: st.state_root(),
                seed,
                randao_mix: st.randao_mix,
                proposer: schedule::proposer(&seed, slot, &roster),
                partition: crate::committees::epoch_committees(&seed, epoch, &roster),
            });
        }
        crate::params::rehearsal::MUTATE_SEED.with(|c| c.set(false));
        out
    }

    /// Compare two runs by LOGICAL SLOT NUMBER, never by position in a
    /// sequence of blocks. Returns (content differences, fields compared).
    fn ab_diff(a: &[AbRecord], b: &[AbRecord]) -> (usize, usize) {
        let (mut d, mut fields) = (0usize, 0usize);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.slot, y.slot, "the comparator lost slot alignment");
            fields += 8;
            if x != y {
                d += 1;
            }
        }
        (d, fields)
    }

    /// The `back` arithmetic in `seed_for_epoch` and the boundary epoch
    /// `committees::seed_epoch` names are the same arithmetic. If either side
    /// is edited alone, this fails.
    #[test]
    fn the_lookahead_matches_the_committee_crates_seed_epoch() {
        let back = 1 + crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS;
        for e in 0u64..4_000 {
            assert_eq!(
                e.checked_sub(back),
                crate::committees::seed_epoch(e),
                "epoch {e}: the transition's boundary epoch and the committee crate's disagree"
            );
        }
    }

    /// **The retention claim, tested rather than argued.**
    ///
    /// The whole "no state-root change" argument rests on
    /// `RANDAO_BOUNDARIES_RETAINED = 2` already holding `E − 2` while `E` is
    /// open. If that were false the rule would silently fall back to the
    /// genesis mix — reachable arithmetic, not an unreachable branch.
    #[test]
    fn the_rule_reads_a_boundary_the_state_still_retains() {
        // The rules under test ship INERT behind their flag days; open them for
        // this thread so this is not dead code. See params::rehearsal.
        let _gates = crate::params::rehearsal::gates_open_guard();
        // `seed_for_epoch` goes through `rehearsal_mutate`, which reads the
        // process-global `MUTATE_SEED`; `randao_mix_at` does not. So this test
        // is a READER of that global and must be excluded from the A/B
        // rehearsal, or it compares a mutated seed against an unmutated mix and
        // fails by exactly one bit of byte 0. Observed 2026-08-24: left[0]=144,
        // right[0]=145. Pre-existing race, made visible by adding tests that
        // changed the harness's interleaving. Flipping a global is only safe
        // if every reader takes the same lock.
        let _g = AB_HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let (t, g, mut chains) = setup(8);
        let mut st = g;
        let mut checked = 0;
        for slot in 1..=(crate::SLOTS_PER_EPOCH * 4) {
            let b = build_block(&t, &st, slot, &[], &[], &mut chains);
            st = t.apply_block(&st, &b, &[], &[]).expect("block rejected");
            let e = st.epoch;
            if e >= 2 {
                let src = e - (1 + crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS);
                assert!(
                    st.randao_mix_at(src).is_some(),
                    "epoch {e} is open and boundary {src} — the seed the rule needs — has \
                     already been evicted; the look-ahead WOULD need a retention change and \
                     therefore a state-root change"
                );
                assert_eq!(
                    st.seed_for_epoch(e),
                    st.randao_mix_at(src).unwrap(),
                    "the seed did not come from the retained boundary it claims"
                );
                checked += 1;
            }
        }
        assert!(checked > 64, "only {checked} slots reached the rule");
    }

    /// The driver is deterministic: same inputs, same chain, bit for bit.
    /// Without this the mutation below would be meaningless — a comparator
    /// that reddens at everything would pass it.
    #[test]
    fn two_identical_runs_produce_an_identical_chain() {
        let _g = AB_HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let slots = crate::SLOTS_PER_EPOCH * 2;
        let a = ab_run(false, slots, 8);
        let b = ab_run(false, slots, 8);
        let (d, fields) = ab_diff(&a, &b);
        println!("DETERMINISM: {slots} slots, {fields} fields compared, {d} differences");
        assert_eq!(d, 0, "the driver is not deterministic; no comparison below means anything");
    }

    /// **The comparator's tripwire.** Plant a one-bit difference in the seed
    /// and require the comparator to go red. A comparator that cannot see a
    /// planted difference is not comparing anything — which is how a whole
    /// suite was once found passing empty.
    #[test]
    fn the_comparator_bites_a_planted_difference() {
        let _g = AB_HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let slots = crate::SLOTS_PER_EPOCH * 2;
        let clean = ab_run(false, slots, 8);
        let mutated = ab_run(true, slots, 8);
        let (d, fields) = ab_diff(&clean, &mutated);
        println!(
            "MUTATION: {fields} fields compared, {d} differences (0 would mean the \
             comparator is blind)"
        );
        assert!(d > 0, "the comparator did not see a one-bit seed difference");
    }

    /// `pub(super)` so the sibling `epoch_advance_bound` module can build the
    /// same fixture rather than a second one that could drift from it.
    pub(super) fn setup(n: u32) -> (Transition<OkVerifier>, CommittedState, Vec<RandaoChain>) {
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

    /// A distinguishable output for the copy-on-write tests.
    fn cow_coin(i: u32) -> crate::state_root::EutxoEntry {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&i.to_le_bytes());
        crate::state_root::EutxoEntry {
            txid,
            vout: 0,
            value: 1_000 + i as u64,
            script_hash: [7u8; 32],
        }
    }

    /// **The catch-up fix's load-bearing claim, as a count.** Rolling a state
    /// across epoch boundaries — what `rolled_to(wall_epoch)` does once per
    /// applied block on a node that is behind — must copy the eUTXO map ZERO
    /// times, because `close_epoch` never writes to the ledger. Before the
    /// `Arc` (2026-08-31) it copied the full map once per epoch crossed,
    /// which at carryover scale (452,726 entries, ~60 MB) made a gap of ~15
    /// epochs a stall and a cold start (~1,550 epochs) fatal.
    ///
    /// The `ptr_eq` half is what makes this a sharing test and not an
    /// equality test: fifty rolls end on the *same allocation* the genesis
    /// state holds, so the memory a roll of N epochs pins is N × (the small
    /// per-epoch fields), never N × the ledger.
    #[test]
    fn an_epoch_roll_deep_copies_no_eutxo_maps() {
        let balances: Vec<_> = (0..512).map(cow_coin).collect();
        let (_t, st, _chains) = setup_funded(8, &balances);
        let before = eutxo_map_deep_copies();
        let mut cur = st.clone();
        for _ in 0..50 {
            cur = cur.close_epoch();
        }
        assert_eq!(
            eutxo_map_deep_copies() - before,
            0,
            "an epoch roll wrote to the ledger, or a clone stopped sharing it — \
             either way a catching-up node is back to one full-map copy per epoch per block"
        );
        assert_eq!(cur.eutxos, st.eutxos, "a boundary must not move the ledger");
        assert!(
            std::sync::Arc::ptr_eq(&cur.eutxos.entries, &st.eutxos.entries),
            "the rolled state re-allocated an identical ledger instead of sharing it"
        );
    }

    /// The other half of copy-on-write: a write to a *shared* map copies it
    /// exactly once, unshares it, and is invisible to every other holder —
    /// and a no-op write (removing an absent outpoint) copies nothing.
    #[test]
    fn a_ledger_write_copies_the_shared_map_once_and_disturbs_no_sharer() {
        let balances: Vec<_> = (0..8).map(cow_coin).collect();
        let (_t, st, _chains) = setup_funded(4, &balances);
        let root_before = st.state_root();

        let mut writer = st.clone();
        let before = eutxo_map_deep_copies();
        writer.eutxos.remove(&(balances[0].txid, balances[0].vout));
        assert_eq!(
            eutxo_map_deep_copies() - before,
            1,
            "the first write to a shared map must pay exactly one full copy"
        );
        writer.eutxos.remove(&(balances[1].txid, balances[1].vout));
        assert_eq!(
            eutxo_map_deep_copies() - before,
            1,
            "the map was unshared by the first write; the second must not copy again"
        );

        // The sharer still holds both spent outputs, and its root stands.
        assert!(st.eutxos.get(&(balances[0].txid, balances[0].vout)).is_some());
        assert!(st.eutxos.get(&(balances[1].txid, balances[1].vout)).is_some());
        assert_eq!(st.state_root(), root_before, "a writer's edit leaked into its sharer");
        assert_ne!(writer.state_root(), root_before, "control: the writes must move the writer");

        // Removing an outpoint that is not there is a no-op, not a copy.
        let mut reader = st.clone();
        let before = eutxo_map_deep_copies();
        reader.eutxos.remove(&([0xEE; 32], 7));
        assert_eq!(
            eutxo_map_deep_copies() - before,
            0,
            "a no-op remove on a shared map must not pay the full-map copy"
        );
        assert!(
            std::sync::Arc::ptr_eq(&reader.eutxos.entries, &st.eutxos.entries),
            "a no-op remove must leave the map shared"
        );
    }

    /// What a block-level state root costs at Genesis-4's real carryover
    /// size, and what the `pre.clone()` in `apply_block` costs beside it.
    ///
    /// `#[ignore]`: it builds a 452,726-output ledger and is a measurement,
    /// not an assertion. Run it deliberately, in release:
    ///
    /// ```text
    /// cargo test --release -p bloch-pos-committee --lib \
    ///     carryover_scale_block_cost -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn carryover_scale_block_cost() {
        const N: u32 = 452_726;
        let balances: Vec<crate::state_root::EutxoEntry> = (0..N)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[..4].copy_from_slice(&i.to_le_bytes());
                crate::state_root::EutxoEntry {
                    txid,
                    vout: 0,
                    value: 1_000 + i as u64,
                    script_hash: [7u8; 32],
                }
            })
            .collect();

        let t0 = std::time::Instant::now();
        let (_t, mut st, _chains) = setup_funded(8, &balances);
        let genesis_build = t0.elapsed();

        // Warm first: the singleton memo is thread-local and persists, so a
        // cold first call would be a comparison of caches, not of paths.
        let warm = st.state_root();

        let t1 = std::time::Instant::now();
        let again = st.state_root();
        let unchanged = t1.elapsed();
        assert_eq!(warm, again);

        // Four spends and four creations — the shape of an ordinary block.
        let t2 = std::time::Instant::now();
        for i in 0..4u32 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&(i * 7919).to_le_bytes());
            st.eutxos.remove(&(txid, 0));
        }
        for i in 0..4u32 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&(N + i).to_le_bytes());
            st.eutxos.insert(crate::state_root::EutxoEntry {
                txid,
                vout: 0,
                value: 42,
                script_hash: [9u8; 32],
            });
        }
        let edit = t2.elapsed();
        let t3 = std::time::Instant::now();
        let moved = st.state_root();
        let after_edit = t3.elapsed();
        assert_ne!(warm, moved, "control: the edit must move the root");

        let t4 = std::time::Instant::now();
        let cloned = st.clone();
        let pre_clone = t4.elapsed();
        assert_eq!(cloned.state_root(), moved);

        println!("  outputs                          : {N}");
        println!("  genesis build (one-off)          : {genesis_build:.4?}");
        println!("  state_root(), nothing changed    : {unchanged:.4?}");
        println!("  8-output edit                    : {edit:.4?}");
        println!("  state_root() after the 8 edits   : {after_edit:.4?}");
        println!("  pre.clone() of the whole state   : {pre_clone:.4?}");
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
        // The proposer signature is now SIGNED, not stubbed with eight zero
        // bytes. It has to be: the proposer check resolves the proposer's key
        // from the registry and calls `verify_with_key`, so a verifier double
        // that binds signature→key (`ToyVerifier`) rejects a stub.
        //
        // This is strictly more coverage than before, not a workaround. Under
        // the old index-keyed `verify`, `ToyVerifier` answered `true` for any
        // proposer signature whatsoever, so every block these tests built
        // carried a proposer signature nothing ever checked. Signing it here
        // means the builder now exercises the real binding: sign with the key
        // the PARENT STATE has registered for the drawn proposer, over that
        // header's own signing root.
        //
        // Signed twice because the signing root covers `state_root`: the probe
        // header (root still zero) and the final header are different messages.
        let sign_for = |h: &BlockHeaderV4| -> Vec<u8> {
            match crate::attestation::KeyLookup::pubkey(pre, p) {
                Some(pk) => toy_sign(pk, &h.proposal_signing_root()),
                // A fixture whose registry has no such index: leave the stub
                // and let the transition reject it, which is the honest
                // outcome rather than a silently-passing block.
                None => vec![0u8; 8],
            }
        };
        let probe = ProposalEnvelope { header, proposer_sig: sign_for(&header) };
        let post = t
            .compute_post_state(pre, &probe, atts, txs)
            .expect("builder produced an untransitionable block");
        header.state_root = post.state_root();
        let proposer_sig = sign_for(&header);
        ProposalEnvelope { header, proposer_sig }
    }

    /// One attestation from `v` for `slot`, voting `target_root` as both head
    /// and target, sourcing the state's current justified checkpoint.
    fn attest(st: &CommittedState, v: u32, slot: u64, target_root: [u8; 32]) -> Attestation {
        let fin = st.finality_view();
        let att = Attestation {
            data: AttestationData {
                slot,
                head: target_root,
                source_epoch: fin.justified.epoch,
                source_root: fin.justified.root,
                target_epoch: crate::epoch_of(slot),
                target_root,
            },
            validator: v,
            // Signed with the key the registry holds for `v`. Under the old
            // index-keyed verify, `ToyVerifier` accepted any attestation
            // signature at all, so these fixtures asserted on attestations
            // nothing verified. Now the signature has to be real, which is
            // more coverage, not less.
            signature: Vec::new(),
        };
        let sig = match crate::attestation::KeyLookup::pubkey(st, v) {
            Some(pk) => toy_sign(pk, &att.data.signing_root()),
            None => vec![0u8; 8],
        };
        Attestation { signature: sig, ..att }
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

    // ── B6: the supply-conservation invariant, shown refusing ────────────
    //
    // The three tests below were NAMED in doc comments before any of them
    // existed. That is the failure this block closes: a doc that cites a test
    // is read as evidence the property is checked, and a reader has no way to
    // tell a citation from a claim. Each name now resolves to a test that can
    // fail.

    /// **The decisive one.** With the mutation OFF the epoch boundary applies;
    /// with it ON the very same block is refused `SupplyNotConserved`.
    ///
    /// # Why an A/B and not a hand-built bad state
    ///
    /// The states that violate this invariant cannot be reached through the
    /// transition — that is the argument on `supply_conserved`, and it is
    /// true. The temptation is therefore to construct one by hand: mutate a
    /// `staked_sat` field, call the predicate, watch it return false. That
    /// would test the predicate and prove nothing about the guard, because it
    /// never goes near `compute_post_state` and cannot tell a wired-up check
    /// from a dead one.
    ///
    /// `mint_from_nothing` instead plants the defect on the PRODUCTION path,
    /// inside `close_epoch`, where a real bug would live: the reward is
    /// credited into the bond and `issued_sat` is simply not advanced. Every
    /// other rule in the transition still passes — the block is well-formed,
    /// the proposer is drawn correctly, the attestations verify, and crucially
    /// the HARD CAP at step 3c is still satisfied, because the counter it
    /// reads is the one the defect leaves alone. So this is exactly the class
    /// of bug the cap cannot see, and the only thing standing between it and
    /// an inflating chain is step 11b.
    ///
    /// The boundary is slot 64 (epoch 1 → 2) with a full attestation quorum
    /// behind it, because that is where `close_epoch` actually mints: rewards
    /// need participation, and an empty boundary would credit nothing and
    /// leave the mutation with nothing to steal.
    #[test]
    fn an_inflated_bond_is_refused_as_unconserved_supply() {
        let _ab = AB_HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let (t, g, mut chains) = setup(8);

        // Epoch 1's checkpoint, then a full quorum recorded against it — the
        // epoch-boundary shape from `justification_and_finality_advance_across_epochs`.
        let b1 = build_block(&t, &g, 32, &[], &[], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[]).unwrap();
        let atts1 = full_epoch_attestations(&s1, *s1.head().as_bytes());
        let b2 = build_block(&t, &s1, 63, &atts1, &[], &mut chains);
        let s2 = t.apply_block(&s1, &b2, &atts1, &[]).unwrap();
        assert!(
            s2.current_participation.values().all(|a| *a),
            "the boundary must have participation behind it, or it mints nothing \
             and the mutation has nothing to steal"
        );

        // The block that crosses into epoch 2 and therefore closes epoch 1.
        let b3 = build_block(&t, &s2, 64, &[], &[], &mut chains);

        // ── A: clean. The boundary applies and mints. ─────────────────────
        let s3 = t
            .apply_block(&s2, &b3, &[], &[])
            .expect("the honest boundary must apply — a guard that refuses this is a halt");
        let minted = s3.issued_sat() - s2.issued_sat();
        assert!(
            minted > 0,
            "the boundary issued nothing, so the A/B compares two states that \
             differ in no coins and the test would pass vacuously"
        );
        // Holdings rose by exactly what issuance rose by: conservation is not
        // merely satisfied at `<=`, it is TIGHT across an honest boundary.
        assert_eq!(
            s3.accounted_supply_sat() - s2.accounted_supply_sat(),
            minted,
            "an honest epoch boundary must move holdings and issuance by the same \
             satoshis — if these can differ, the invariant has slack a defect fits in"
        );

        // ── B: mutated. The decisive assertion. ───────────────────────────
        //
        // `compute_post_state`, NOT `apply_block`, and that is the whole
        // point of this leg. `apply_block` compares the committed root at
        // step 12, so under the mutation it would refuse this block either
        // way — with `StateRootMismatch`, because the header commits a root
        // the defective transition no longer produces. That is a real second
        // line of defence and it proves nothing here: it only catches a node
        // whose defect DISAGREES with the block's author. A bug ships to the
        // whole fleet at once, author included, and then every root matches.
        //
        // `compute_post_state` contains no state-root comparison at all, so
        // `SupplyNotConserved` coming out of it can only have come from step
        // 11b. Delete that check and this assertion returns `Ok`.
        let refused = {
            let _mint = crate::params::rehearsal::mint_from_nothing_guard();
            t.compute_post_state(&s2, &b3, &[], &[])
        };
        assert_eq!(
            refused.err(),
            Some(TransitionError::SupplyNotConserved),
            "close_epoch credited a reward without advancing issued_sat and the \
             transition produced a post-state anyway: step 11b is not wired up"
        );

        // ── C: a defective PRODUCER cannot even build the block ───────────
        //
        // The strongest form of the same fact, and it is worth stating because
        // it is stronger than the invariant was designed for. `build_block`
        // runs the real transition to stamp its `state_root`, so on a fleet
        // that shipped this defect the proposer's own arithmetic refuses the
        // boundary before anyone else sees it. The inflated chain is not
        // rejected downstream; it is never authored.
        let author_refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _mint = crate::params::rehearsal::mint_from_nothing_guard();
            let (tm, gm, mut chm) = setup(8);
            let m1 = build_block(&tm, &gm, 32, &[], &[], &mut chm);
            let sm1 = tm
                .apply_block(&gm, &m1, &[], &[])
                .expect("epoch 0 closes with no participation, so it mints nothing to steal");
            let matts = full_epoch_attestations(&sm1, *sm1.head().as_bytes());
            let m2 = build_block(&tm, &sm1, 63, &matts, &[], &mut chm);
            let sm2 = tm.apply_block(&sm1, &m2, &matts, &[]).unwrap();
            // The boundary block. Building it runs the transition, which
            // refuses — so this panics rather than returning.
            build_block(&tm, &sm2, 64, &[], &[], &mut chm)
        }));
        assert!(
            author_refused.is_err(),
            "a producer carrying the defect built an inflated boundary block \
             and committed a root for it"
        );

        // The mutation is invisible to the hard cap, which is the whole point:
        // had it fired instead, this test would be passing for the wrong
        // reason and `SupplyNotConserved` would still be unreachable.
        assert!(
            s3.issued_sat() < tokenomics_v4::TOTAL_SUPPLY_SAT,
            "the fixture must sit far below the cap, so `SupplyCapExceeded` \
             cannot be what refused the mutated block"
        );

        // And the switch restored itself: the guard is scoped, so the next
        // block on this thread is honest again.
        assert!(!crate::params::rehearsal::mint_from_nothing());
        t.apply_block(&s2, &b3, &[], &[])
            .expect("the mutation leaked past its guard");
    }

    /// The genesis offset is EXACTLY the launch cohort's bonds — the number
    /// `supply_gap_sat` exists to name, pinned so it cannot drift into an
    /// unexplained constant.
    ///
    /// # Why the fixture funds the opening ledger to the last satoshi
    ///
    /// `setup` alone would not do. Its genesis seeds `issued_sat` with
    /// `GENESIS_ISSUED_SAT` — a mainnet-scale figure — while its eUTXO set is
    /// empty, so `supply_gap_sat()` comes out hugely NEGATIVE and the equality
    /// this test is named for is simply false there. That is not a defect in
    /// the accessor; it is a devnet, which issues nothing and bonds play
    /// money.
    ///
    /// So the fixture reproduces the mainnet SHAPE: an opening ledger holding
    /// exactly `GENESIS_ISSUED_SAT` (the carryover plus the allocation buckets,
    /// as one output — their composition is `Manifest`'s business and tested
    /// there), and eight validators bonded on top of it. Then, and only then,
    /// the gap is the bonds and nothing else, which is the claim.
    #[test]
    fn the_genesis_supply_gap_is_exactly_the_cohorts_bonds() {
        // One output standing in for the whole funded opening. `u64` is not a
        // limit here: `GENESIS_ISSUED_SAT` is below `TOTAL_SUPPLY_SAT`, which
        // is 54% of `u64::MAX`.
        let funded = crate::state_root::EutxoEntry {
            txid: [0xA1; 32],
            vout: 0,
            value: u64::try_from(tokenomics_v4::GENESIS_ISSUED_SAT)
                .expect("GENESIS_ISSUED_SAT is below u64::MAX by construction"),
            script_hash: [0xB2; 32],
        };
        let (_t, g, _chains) = setup_funded(8, &[funded.clone()]);

        // `setup_with` bonds `sat(200_000)` per validator. Derived from the
        // fixture rather than retyped, so changing the fixture cannot leave
        // this test asserting a number the state no longer holds.
        let bonds: u128 = g.validators.values().map(|r| r.staked_sat).sum();
        assert_eq!(bonds, sat(200_000) * 8);

        assert_eq!(
            g.issued_sat(),
            tokenomics_v4::GENESIS_ISSUED_SAT,
            "genesis must seed the counter from the constant, or the gap below \
             measures something other than the cohort",
        );
        assert_eq!(
            g.accounted_supply_sat(),
            tokenomics_v4::GENESIS_ISSUED_SAT + bonds,
            "slot 0 holds the funded opening plus the bonds, and nothing else",
        );

        // The claim in the name.
        assert_eq!(
            g.supply_gap_sat(),
            bonds as i128,
            "the genesis supply gap is the launch cohort's bonds, exactly — if \
             this drifts, `supply_gap_sat` has become an unexplained constant",
        );

        // The gap is what it is because the bonds are outside issuance. Take
        // the cohort away and the opening balances to zero — which is what
        // makes the sentence "the gap IS the bonds" mean something.
        let (_t2, g2, _c2) = setup_funded(0, &[funded]);
        assert_eq!(
            g2.supply_gap_sat(),
            0,
            "with no cohort bonded, a funded opening must balance exactly",
        );

        // And the offset the fixture reproduces is the one the chain committed
        // to: eight fixture validators at 200,000 BLOCH is the same 1,600,000
        // BLOCH the mainnet cohort holds at 64 × 25,000, which is the figure
        // frozen as the ceiling both genesis checks refuse to exceed.
        assert_eq!(
            bonds,
            tokenomics_v4::GENESIS_UNFUNDED_BONDED_CEILING_SAT,
            "the fixture no longer reproduces the committed Genesis-4 offset",
        );
    }

    /// `process_epoch` carries no conservation error arm, and this is the test
    /// that makes that a decision rather than an omission. See the doc on
    /// `Transition::process_epoch`.
    ///
    /// Two halves, and both are needed:
    ///
    /// 1. **The block path judges the boundary.** `compute_post_state` rolls
    ///    the epoch itself and checks against the PRE-roll state, so the same
    ///    `close_epoch` that `process_epoch` would call is already covered
    ///    where it counts. The mutated boundary is refused by a block —
    ///    proved above and re-stated here against the identical slot.
    /// 2. **`process_epoch`'s output is a projection.** It is the duty view
    ///    (`engine::rolled_to`), never committed state. So even the mutated
    ///    roll, which this asserts really does inflate the ledger, cannot mint
    ///    a satoshi — it can only mis-derive a roster, and the `debug_assert`
    ///    in `process_epoch` is what makes that visible to a developer.
    #[test]
    fn the_boundary_roll_is_judged_on_the_block_path() {
        let _ab = AB_HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let (t, g, mut chains) = setup(8);
        let b1 = build_block(&t, &g, 32, &[], &[], &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &[]).unwrap();
        let atts1 = full_epoch_attestations(&s1, *s1.head().as_bytes());
        let b2 = build_block(&t, &s1, 63, &atts1, &[], &mut chains);
        let s2 = t.apply_block(&s1, &b2, &atts1, &[]).unwrap();

        // The honest roll conserves, and `process_epoch` agrees with the
        // boundary a block would perform.
        let rolled = t.process_epoch(&s2).expect("process_epoch is infallible");
        assert!(
            CommittedState::supply_conserved(&s2, &rolled, 0),
            "an honest epoch roll must conserve, or the debug_assert inside \
             process_epoch fires on every node in a debug build"
        );
        assert_eq!(rolled.epoch, s2.epoch + 1);

        // The mutated roll really does inflate — stated, so the second half is
        // not vacuous. `close_epoch` directly, because `process_epoch`'s own
        // debug_assert would (correctly) fire on this state.
        let inflated = {
            let _mint = crate::params::rehearsal::mint_from_nothing_guard();
            s2.close_epoch()
        };
        assert!(
            inflated.accounted_supply_sat() > s2.accounted_supply_sat(),
            "the mutation credited nothing, so the rest of this test is vacuous"
        );
        assert_eq!(
            inflated.issued_sat(),
            s2.issued_sat(),
            "the mutation must leave the counter alone — that is what makes it \
             invisible to the hard cap"
        );
        assert!(
            !CommittedState::supply_conserved(&s2, &inflated, 0),
            "the inflated roll must not be conserved, or the predicate is blind"
        );

        // And the same inflation, routed through a BLOCK, is refused by
        // consensus. This is the half that matters: the projection above is
        // never committed, and every boundary that IS committed arrives this
        // way.
        //
        // `compute_post_state` rather than `apply_block`, for the reason leg B
        // of `an_inflated_bond_is_refused_as_unconserved_supply` gives: the
        // root check would refuse this block too, and refusing for the wrong
        // reason would let this test pass with step 11b deleted.
        let b3 = build_block(&t, &s2, 64, &[], &[], &mut chains);
        let refused = {
            let _mint = crate::params::rehearsal::mint_from_nothing_guard();
            t.compute_post_state(&s2, &b3, &[], &[])
        };
        assert_eq!(
            refused.err(),
            Some(TransitionError::SupplyNotConserved),
            "the boundary that `process_epoch` only projects is judged, for real, \
             on the path where its output becomes consensus"
        );
    }

    #[test]
    fn replay_is_delivery_order_independent() {
        // Pre-gate fixture: this test bonds through the legacy unfunded
        // `Deposit`/`Delegate` path, which `DEPOSIT_ACTIVATION_EPOCH` now
        // refuses at every epoch. The switch says so out loud rather than the
        // constant being weakened to keep an old fixture green.
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let (t, g, mut chains) = setup(8);

        // A chain with real content: a deposit, a delegation, and a full
        // attestation quorum.
        let deposit =
            toy_deposit(vec![0xAB; staking::HYBRID_PK_BYTES], [0xCD; 32], vec![0xEF; 4], 500);
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
        // Re-stamping the header means RE-SIGNING it. The proposer signature
        // covers `canonical_serialize()` of the whole header, so mutating
        // `attestation_root` (and then `state_root`) invalidates the
        // signature carried over from `b3`. Under the old index-keyed verify
        // this went unnoticed, because the double accepted ANY proposer
        // signature; now the key comes from the registry and the signature
        // is really checked.
        let resign_header = |env: &mut ProposalEnvelope, st: &CommittedState| {
            if let Some(pk) =
                crate::attestation::KeyLookup::pubkey(st, env.header.proposer_index)
            {
                env.proposer_sig = toy_sign(pk, &env.header.proposal_signing_root());
            }
        };
        resign_header(&mut b3_rev, &r2);
        b3_rev.header.state_root =
            t.compute_post_state(&r2, &b3_rev, &reversed, &[]).unwrap().state_root();
        resign_header(&mut b3_rev, &r2);
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
        // Pre-gate fixture: this test bonds through the legacy unfunded
        // `Deposit`/`Delegate` path, which `DEPOSIT_ACTIVATION_EPOCH` now
        // refuses at every epoch. The switch says so out loud rather than the
        // constant being weakened to keep an old fixture green.
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let (t, g, mut chains) = setup(4);
        let deposit =
            toy_deposit(vec![0xAA; staking::HYBRID_PK_BYTES], [0xBB; 32], vec![0xCC; 4], 500);
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
        let dup =
            toy_deposit(vec![0xAA; staking::HYBRID_PK_BYTES], [0xDD; 32], vec![0xEE; 4], 500);
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

    // -- The key a deposit commits is the key that must be able to sign ------
    //
    // These verify by VIOLATING, against `ToyVerifier` (a signature is valid
    // for one key over one root and for nothing else) rather than
    // `OkVerifier`, because under an accept-everything verifier every one of
    // them passes with the proof-of-possession check deleted.
    //
    // The rule they cover exists because of the key-lookup change: consensus
    // now verifies a validator's blocks and attestations against the pubkey
    // the STATE ROOT commits, so the bytes this arm writes are the bytes every
    // node will judge that validator by, permanently. A record is never
    // removed and its key is never rewritten, so a key nobody can sign under
    // is a committee seat nobody can ever fill — stake that counts toward the
    // quorum everyone else has to reach and never answers.

    /// A wire deposit carrying a proof of possession that really verifies
    /// under [`ToyVerifier`].
    ///
    /// Every deposit fixture in this module goes through here. A placeholder
    /// proof is no longer a harmless filler: the transition refuses a deposit
    /// that cannot prove it holds the key it is registering, so a fixture with
    /// invented signature bytes does not register a validator and every
    /// assertion downstream of it collapses.
    fn toy_deposit(
        pubkey: Vec<u8>,
        randao_commitment: [u8; 32],
        withdrawal_credentials: Vec<u8>,
        commission_bps: u128,
    ) -> PosTransaction {
        let amount_sat = staking::MIN_DEPOSIT_SAT;
        let root = staking::wire_deposit_pop_root(
            &pubkey,
            amount_sat,
            &randao_commitment,
            &withdrawal_credentials,
            commission_bps,
        );
        let proof_of_possession = toy_sign(&pubkey, &root);
        PosTransaction::Deposit {
            pubkey,
            amount_sat,
            randao_commitment,
            withdrawal_credentials,
            commission_bps,
            proof_of_possession,
        }
    }

    /// The fixture the key tests below vary: one deposit, signed under `key`,
    /// with the other fields held constant.
    fn signed_deposit(key: Vec<u8>, commission_bps: u128) -> PosTransaction {
        toy_deposit(key, [0xB1; 32], vec![0xC0; 32], commission_bps)
    }

    fn hybrid_shaped_key(tag: u8) -> Vec<u8> {
        vec![tag; staking::HYBRID_PK_BYTES]
    }

    /// The whole point, end to end through the production seam: a deposit
    /// proves possession, the transition commits the key into the registry,
    /// and the newcomer's GENUINE attestation then verifies against that
    /// registry — the state-root-committed key — and is accepted.
    ///
    /// Sabotage check: point `attestation::validate` at a registry without the
    /// newcomer and the last assertion becomes `UnknownValidator`; sign the
    /// attestation under any other key and it becomes `BadSignature`. Both are
    /// the failure this whole change exists to end.
    #[test]
    fn a_deposited_validators_genuine_signature_is_accepted_not_badsignature() {
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let (_t, g, _chains) = setup(4);
        let key = hybrid_shaped_key(0x9E);
        let deposit = signed_deposit(key.clone(), 500);

        let mut st = g;
        st.apply_transaction(
            &deposit,
            0,
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            &ToyVerifier,
        )
        .expect("a deposit proving possession of a well-shaped key must be accepted");

        // The registry — what the state root commits — now holds exactly the
        // deposited bytes at the newcomer's index.
        let newcomer = 4u32;
        assert_eq!(
            crate::attestation::KeyLookup::pubkey(&st, newcomer),
            Some(key.as_slice()),
            "the committed registry must hold the deposited key"
        );

        // Its genuine vote, signed with the key it deposited, judged by the
        // same registry.
        let data = crate::attestation::AttestationData {
            slot: 294,
            head: [0xAA; 32],
            source_epoch: 1,
            source_root: [1u8; 32],
            target_epoch: 2,
            target_root: [2u8; 32],
        };
        let att = crate::attestation::Attestation {
            data,
            validator: newcomer,
            signature: toy_sign(&key, &data.signing_root()),
        };
        assert_eq!(
            crate::attestation::validate(&att, &[newcomer], 294, &ToyVerifier, &st),
            Ok(()),
            "a deposit-added validator's genuine signature must not be BadSignature"
        );
    }

    /// A key nobody holds cannot be registered. The attacker copies somebody
    /// else's public bytes and submits them as its own validator key; without
    /// the proof of possession this succeeded, and the seat it minted could
    /// never be filled by anyone — including the validator whose key was
    /// copied, whose own deposit would then be refused as a duplicate.
    #[test]
    fn a_rogue_key_registration_is_refused() {
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let (_t, g, _chains) = setup(4);
        let victim = hybrid_shaped_key(0x11);
        let attacker = hybrid_shaped_key(0x22);
        // Attacker holds its OWN key, and signs with it — over the victim's
        // key it is trying to register.
        let mut rogue = signed_deposit(victim, 500);
        if let PosTransaction::Deposit { proof_of_possession, .. } = &mut rogue {
            let root = [0u8; 32];
            *proof_of_possession = toy_sign(&attacker, &root);
        }
        let mut st = g;
        assert_eq!(
            st.apply_transaction(
                &rogue,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier
            ),
            Err(TxReject::StakingRule),
            "a key whose secret half the depositor does not hold must not reach the registry"
        );
        assert!(
            st.validator_record(4).is_none(),
            "the refused deposit must leave no record behind"
        );
    }

    /// Bytes that are not a hybrid key at all. Refused on SHAPE, before any
    /// verification runs — every signature checked against them would fail
    /// forever, and the record could never be repaired.
    #[test]
    fn a_key_that_is_not_the_suites_shape_is_refused() {
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let (_t, g, _chains) = setup(4);
        for len in [0usize, 8, staking::HYBRID_PK_BYTES - 1, staking::HYBRID_PK_BYTES + 1] {
            let deposit = signed_deposit(vec![0x33; len], 500);
            let mut st = g.clone();
            assert_eq!(
                st.apply_transaction(
                    &deposit,
                    0,
                    fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                    &ToyVerifier
                ),
                Err(TxReject::StakingRule),
                "a {len}-byte pubkey is not a SUITE_MLDSA65_FALCON1024 key"
            );
        }
    }

    /// The proof covers the commission and the withdrawal credentials, not
    /// just the key. A relay that rewrites either — where the stake returns
    /// to, or what the operator keeps from its delegators — must invalidate
    /// the proof. A root that covered only the pubkey would leave both fields
    /// free for anyone on the path to change.
    #[test]
    fn the_proof_binds_every_field_of_the_deposit() {
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let (_t, g, _chains) = setup(4);
        let key = hybrid_shaped_key(0x44);

        // Control: untouched, it applies.
        let honest = signed_deposit(key.clone(), 500);
        let mut st = g.clone();
        assert!(st
            .apply_transaction(&honest, 0, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS, &ToyVerifier)
            .is_ok());

        // Commission rewritten in flight, proof left alone.
        let mut tampered = signed_deposit(key.clone(), 500);
        if let PosTransaction::Deposit { commission_bps, .. } = &mut tampered {
            *commission_bps = 10_000;
        }
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction(
                &tampered,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier
            ),
            Err(TxReject::StakingRule),
            "rewriting the commission must break the proof"
        );

        // Withdrawal credentials rewritten: where the principal returns to.
        let mut tampered = signed_deposit(key, 500);
        if let PosTransaction::Deposit { withdrawal_credentials, .. } = &mut tampered {
            *withdrawal_credentials = vec![0xEE; 32];
        }
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction(
                &tampered,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier
            ),
            Err(TxReject::StakingRule),
            "rewriting the withdrawal credentials must break the proof"
        );
    }

    /// A wire deposit for an arbitrary amount, proved under [`ToyVerifier`].
    /// `toy_deposit` fixes the amount at the minimum; the bound tests need to
    /// move it while keeping the proof genuine, so that a rejection can only
    /// be about the amount.
    fn signed_deposit_of(key: Vec<u8>, amount_sat: u128) -> PosTransaction {
        let randao_commitment = [0xB1; 32];
        let withdrawal_credentials = vec![0xC0; 32];
        let commission_bps = 500u128;
        let root = staking::wire_deposit_pop_root(
            &key,
            amount_sat,
            &randao_commitment,
            &withdrawal_credentials,
            commission_bps,
        );
        let proof_of_possession = toy_sign(&key, &root);
        PosTransaction::Deposit {
            pubkey: key,
            amount_sat,
            randao_commitment,
            withdrawal_credentials,
            commission_bps,
            proof_of_possession,
        }
    }

    /// The arm states no deposit rule of its own any more — it derives the cap
    /// from committed state and hands everything to
    /// `staking::validate_wire_deposit`, whose shape half is
    /// `staking::deposit_shape`. This is the test that says the delegation is
    /// real: the bounds are still enforced HERE, through the owner, with the
    /// arm holding no copy of them.
    ///
    /// Sabotage: drop the `deposit_shape` call inside `validate_wire_deposit`
    /// and both rejections below become `Ok`, because each deposit's proof of
    /// possession is genuine — the only thing wrong with them is the amount.
    ///
    /// `total_active_sat` is 0 here, so the 1%-of-active-stake cap floors at
    /// `MIN_DEPOSIT_SAT` (the genesis-bootstrap floor `staking` documents) and
    /// the floor and the cap coincide — which makes one fixture able to probe
    /// both edges.
    #[test]
    fn the_arm_still_bounds_the_amount_through_the_owner() {
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let (_t, g, _chains) = setup(4);
        let cap = staking::MIN_DEPOSIT_SAT; // total_active_sat = 0 → the floor

        // Below the minimum.
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction(
                &signed_deposit_of(hybrid_shaped_key(0x71), staking::MIN_DEPOSIT_SAT - 1),
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier
            ),
            Err(TxReject::StakingRule),
            "an under-minimum deposit must still be refused"
        );
        assert!(st.validator_record(4).is_none(), "a refused deposit leaves no record");

        // Above the per-validator cap.
        let mut st = g.clone();
        assert_eq!(
            st.apply_transaction(
                &signed_deposit_of(hybrid_shaped_key(0x72), cap + 1),
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier
            ),
            Err(TxReject::StakingRule),
            "an over-cap deposit must still be refused"
        );
        assert!(st.validator_record(4).is_none(), "a refused deposit leaves no record");

        // The control: the fixture is live, so the two refusals above are
        // about the amount and not about the fixture being broken.
        let mut st = g;
        assert!(st
            .apply_transaction(
                &signed_deposit_of(hybrid_shaped_key(0x73), cap),
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier
            )
            .is_ok());
        assert!(st.validator_record(4).is_some(), "an in-bounds proved deposit must register");
    }

    /// The same refusal one level up, through `apply_block` — the seam a real
    /// node judges blocks at, not the per-transaction call. Reconciles B1's
    /// block-level shape test with the proof-of-possession form: the deposit
    /// here is genuinely proved, so the block is refused for the key's
    /// GEOMETRY and nothing else. B1's own copy of this fixture was the same
    /// assertions without the proof, so it is subsumed rather than kept —
    /// two fixtures for one rule is two places for it to drift.
    ///
    /// `DEPOSIT_ACTIVATION_EPOCH` refuses this encoding at every epoch, so on
    /// its own it makes every other deposit rule unreachable — and unreachable
    /// rules rot. Forcing the gate OPEN for the whole body removes the gate as
    /// an explanation. Why that matters beyond tidiness: before this call site
    /// existed, the only thing between an opened gate and a registry full of
    /// arbitrary bytes was `bloch-pos-node`'s mempool, and `keys.rs` had to
    /// document that "a registry key may be arbitrary bytes" and fail closed
    /// on them. The registry is now shape-checked by consensus, so opening the
    /// gate alone can no longer admit a key no signature could ever verify
    /// under.
    ///
    /// The block is assembled BY HAND rather than through `build_block`, which
    /// requires a transitionable body — the point of this fixture is a body
    /// that is not one. It reuses a real header for the slot (real proposer,
    /// real reveal, real mix) and re-roots and re-signs it over the malformed
    /// body, so the only thing wrong with the block is the deposit.
    #[test]
    fn a_malformed_deposit_key_in_a_block_is_refused_even_with_the_gate_open() {
        let _open = crate::params::rehearsal::bonding_gate_open_guard();
        let (t, g, mut chains) = setup_with(4, ToyVerifier, &[]);

        let well_formed = signed_deposit_of(hybrid_shaped_key(0x6A), staking::MIN_DEPOSIT_SAT);
        // Same deposit in every respect but the key geometry — and proved just
        // as genuinely, so the proof cannot be what refuses it.
        let malformed =
            signed_deposit_of(vec![0x6A; staking::HYBRID_PK_BYTES - 1], staking::MIN_DEPOSIT_SAT);

        // The fixture is live: with the gate open the well-formed one really
        // does register. Without this the refusal below could come from
        // anything at all.
        let good_block =
            build_block(&t, &g, 33, &[], std::slice::from_ref(&well_formed), &mut chains);
        let applied = t
            .apply_block(&g, &good_block, &[], std::slice::from_ref(&well_formed))
            .expect("the well-formed proved deposit must apply with the gate open");
        assert_eq!(applied.validator_count(), 5, "fixture must actually register a validator");

        // Re-root and re-sign that same header over the malformed body.
        let mut header = good_block.header;
        header.body_root = crate::derive::body_root(&[malformed.canonical_bytes()]);
        let proposer_sig = match crate::attestation::KeyLookup::pubkey(&g, header.proposer_index) {
            Some(pk) => toy_sign(pk, &header.proposal_signing_root()),
            None => unreachable!("the drawn proposer is in the genesis registry"),
        };
        let bad_block = ProposalEnvelope { header, proposer_sig };

        assert_eq!(
            t.apply_block(&g, &bad_block, &[], std::slice::from_ref(&malformed)),
            Err(TransitionError::Transaction(0)),
            "a malformed deposit key must be refused by the transition, at index 0",
        );

        // And the reason is the shape rule, not the flag day — the gate is
        // open for this whole test, so `StakingNotActive` is not available.
        let mut probe = g.clone();
        assert_eq!(
            probe.apply_transaction(
                &malformed,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            ),
            Err(TxReject::StakingRule),
        );
        assert_eq!(probe.validator_count(), 4, "a refused deposit must leave no trace");
    }

    /// The gate still comes FIRST. Adding checks to this arm must not have
    /// created a road into it: with the flag day inert (the fleet's real
    /// configuration), a perfectly-proved deposit is still refused, and
    /// refused as `StakingNotActive` — not as a key problem.
    #[test]
    fn the_flag_day_still_refuses_a_perfectly_proved_deposit() {
        let (_t, g, _chains) = setup(4);
        let deposit = signed_deposit(hybrid_shaped_key(0x55), 500);
        let mut st = g;
        assert_eq!(
            st.apply_transaction(
                &deposit,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier
            ),
            Err(TxReject::StakingNotActive),
        );
    }

    // -- DEPOSIT_ACTIVATION_EPOCH -------------------------------------------

    /// THE GATE IS A CONSENSUS RULE, AND THIS PROVES IT IS NOT THE MEMPOOL'S.
    ///
    /// At the pristine tree (`g4-node-20260901`) this test's fixture applied
    /// clean: `apply_block` returned a state with a fifth validator record
    /// holding `MIN_DEPOSIT_SAT` against no input spent. The only thing
    /// refusing a deposit was `bloch-pos-node`'s `admissible`, and that crate
    /// is not in this test's dependency graph — there is no mempool here to
    /// blame, which is the whole reason the test lives in the committee crate.
    ///
    /// The block is BUILT with the gate forced open, so the header carries a
    /// real `state_root` and `body_root` over a body that really contains the
    /// deposit — exactly the block a patched producer would gossip. It is then
    /// JUDGED with the gate shut, by the code every honest node runs. The
    /// refusal that comes back is `compute_post_state`'s.
    #[test]
    fn a_deposit_in_a_block_is_refused_by_consensus_not_by_the_mempool() {
        let (t, g, mut chains) = setup(4);
        let deposit =
            toy_deposit(vec![0x5A; staking::HYBRID_PK_BYTES], [0x5B; 32], vec![0x5C; 4], 500);

        // Built by a producer whose gate is open: a well-formed block, every
        // root correct, carrying stake minted from nothing.
        let (b, applied_open) = {
            let _open = crate::params::rehearsal::bonding_gate_open_guard();
            let b = build_block(&t, &g, 33, &[], std::slice::from_ref(&deposit), &mut chains);
            let st = t
                .apply_block(&g, &b, &[], std::slice::from_ref(&deposit))
                .expect("with the gate open this is the pre-gate behaviour");
            (b, st)
        };
        // The fixture is live: with the gate open the deposit really does what
        // the finding says it does. Without this the test below could pass
        // against a block that was never applicable for some other reason.
        assert_eq!(applied_open.validator_count(), 5, "fixture must actually mint a validator");

        // Judged by a node running the shipped rules. Same block, same body.
        assert_eq!(
            t.apply_block(&g, &b, &[], std::slice::from_ref(&deposit)),
            Err(TransitionError::Transaction(0)),
            "consensus must refuse the deposit, at index 0, on the frozen variant",
        );

        // And the reason is the flag day, not the minimum, not a duplicate
        // pubkey, not the per-validator cap.
        let mut probe = g.clone();
        assert_eq!(
            probe.apply_transaction(
                &deposit,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &OkVerifier,
            ),
            Err(TxReject::StakingNotActive),
        );
        assert_eq!(probe.validator_count(), 4, "a refused deposit must leave no trace");
    }

    /// The faster door. A delegation reaches `effective_stake` at `epoch + 1`
    /// with no activation queue in front of it, so it must be shut by the same
    /// constant or the deposit gate is decoration.
    #[test]
    fn a_delegation_in_a_block_is_refused_by_consensus_too() {
        let (t, g, mut chains) = setup(4);
        let delegate = PosTransaction::Delegate {
            delegator: 900,
            validator: 0,
            amount_sat: delegation::MIN_DELEGATION_SAT,
            eligible: true,
        };
        let b = {
            let _open = crate::params::rehearsal::bonding_gate_open_guard();
            let b = build_block(&t, &g, 33, &[], std::slice::from_ref(&delegate), &mut chains);
            let st = t.apply_block(&g, &b, &[], std::slice::from_ref(&delegate)).unwrap();
            assert!(!st.delegations.is_empty(), "fixture must actually bond");
            b
        };
        assert_eq!(
            t.apply_block(&g, &b, &[], std::slice::from_ref(&delegate)),
            Err(TransitionError::Transaction(0)),
        );
    }

    /// The gate reads the epoch of the BLOCK, and the same body flips verdict
    /// on nothing but that number.
    ///
    /// This is the divergence property stated as a test: `unfunded_bonding_active`
    /// is a function of one `u64` that `compute_post_state` derives as
    /// `epoch_of(header.slot)` and from nothing else. There is no node identity,
    /// no clock and no mutable local in its argument list, so two honest nodes
    /// handed the same header cannot disagree — which is precisely what the
    /// 2026-08-08 `expected_bits` rule could not say about itself.
    #[test]
    fn the_gate_is_a_function_of_the_block_epoch_alone() {
        // Below the flag day: refused, at every epoch a chain can reach.
        for e in [0u64, 1, 1_766, 100_000, u64::MAX - 1] {
            assert!(!CommittedState::unfunded_bonding_active(e), "epoch {e} must be below");
        }
        // At and above it: allowed. Reached only by moving the constant, which
        // `deposit_gate_is_inert` forbids — the arm is covered, not open.
        assert!(CommittedState::unfunded_bonding_active(
            crate::params::DEPOSIT_ACTIVATION_EPOCH
        ));
    }

    /// TRIPWIRE. `DEPOSIT_ACTIVATION_EPOCH` must stay `u64::MAX`.
    ///
    /// Not a style rule. The encoding this constant gates is the
    /// UNAUTHENTICATED one: `Deposit` spends no input and carries no signature,
    /// `Delegate` likewise. Moving this number to a reachable epoch does not
    /// open deposits safely — it makes stake minted from nothing a
    /// consensus-VALID transaction on every node at once, which is strictly
    /// worse than the pre-gate tree, where at least the mempool refused it.
    ///
    /// Deposits open by a funded, authenticated message that spends transparent
    /// eUTXO inputs and proves possession of the key — the shape
    /// `staking::validate_deposit` already describes and no encoder emits. That
    /// message needs a wire tag the founder has not assigned, and it will bring
    /// its own activation constant. This one is a permanent closure.
    ///
    /// Whoever arms it has to delete this test first, and read this while doing
    /// so.
    #[test]
    fn deposit_gate_is_inert() {
        assert_eq!(
            crate::params::DEPOSIT_ACTIVATION_EPOCH,
            u64::MAX,
            "arming this reopens unfunded bonding on all nodes; read the test docs",
        );
    }

    // -- EXIT_AUTH_ACTIVATION_EPOCH -----------------------------------------

    /// TRIPWIRE. `EXIT_AUTH_ACTIVATION_EPOCH` must stay `u64::MAX`.
    ///
    /// Arming it retires the legacy `Exit` message on every node — and puts
    /// nothing in its place, because `ExitV2`'s wire byte (`0x08`) is still
    /// contested and this tree's decoder refuses it. Voluntary exit would stop
    /// existing rather than become authenticated. Whoever arms it has to
    /// delete this test first, and read this while doing so.
    #[test]
    fn exit_auth_gate_is_inert() {
        assert_eq!(
            crate::params::EXIT_AUTH_ACTIVATION_EPOCH,
            u64::MAX,
            "arming this retires legacy Exit while ExitV2 is still undecodable; read the docs",
        );
    }

    /// The unauthenticated message is STILL VALID today. This is the control
    /// half of the flag day and it is an assertion about the network as it
    /// runs, not a wish: below the gate `Exit` applies exactly as it always
    /// did, so a fleet that is mid-rollout cannot disagree about a block.
    #[test]
    fn below_the_gate_the_legacy_exit_still_applies_and_exit_v2_does_not() {
        let (_t, g, _c) = setup(4);

        let mut probe = g.clone();
        assert!(
            probe
                .apply_transaction(
                    &PosTransaction::Exit { validator: 0 },
                    0,
                    fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                    &OkVerifier,
                )
                .is_ok(),
            "the control must not move: legacy Exit applies below the flag day",
        );

        let exit = signed_exit(0, 0);
        let mut probe = g.clone();
        assert_eq!(
            probe.apply_transaction(
                &exit,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            ),
            Err(TxReject::StakingNotActive),
            "a perfectly signed ExitV2 is still consensus-INVALID below the flag day",
        );
    }

    /// Build the signed exit a validator would actually send, under
    /// [`ToyVerifier`]'s one-key-one-root rule.
    fn signed_exit(validator: u8, epoch: u64) -> PosTransaction {
        let pk = vec![validator; 8];
        let pubkey_hash: [u8; 32] = Sha3_256::digest(&pk).into();
        let root = staking::ExitTx { pubkey_hash, epoch, signature: Vec::new() }.signing_root();
        PosTransaction::ExitV2 { pubkey_hash, epoch, signature: toy_sign(&pk, &root) }
    }

    /// THE AUTHENTICATION, above the gate. `ToyVerifier`, never `OkVerifier`:
    /// the whole point of `ExitV2` over the legacy message is that a signature
    /// is checked, and a verifier that accepts everything would pass this test
    /// on an implementation that skipped the check entirely.
    #[test]
    fn exit_v2_requires_the_registered_validators_own_signature() {
        let _guard = crate::params::rehearsal::exit_auth_gate_open_guard();
        let (_t, g, _c) = setup(4);

        // The genuine article applies.
        let mut probe = g.clone();
        assert!(
            probe
                .apply_transaction(
                    &signed_exit(1, 0),
                    0,
                    fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                    &ToyVerifier,
                )
                .is_ok(),
            "a correctly signed exit for a registered validator must apply",
        );
        assert_eq!(
            probe.validator_record(1).unwrap().exit_epoch,
            staking::EXIT_DELAY_EPOCHS,
            "the authenticated path schedules the same duty stop as the legacy one",
        );

        // Validator 2's own key, over validator 1's message: the signature is
        // real, it just does not authorise THIS exit.
        let PosTransaction::ExitV2 { pubkey_hash, epoch, .. } = signed_exit(1, 0) else {
            unreachable!()
        };
        let wrong_signer = PosTransaction::ExitV2 {
            pubkey_hash,
            epoch,
            signature: toy_sign(
                &vec![2u8; 8],
                &staking::ExitTx { pubkey_hash, epoch, signature: Vec::new() }.signing_root(),
            ),
        };
        let mut probe = g.clone();
        assert_eq!(
            probe.apply_transaction(
                &wrong_signer,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            ),
            Err(TxReject::StakingRule),
            "one validator must not be able to retire another",
        );

        // No signature at all — the exact shape the legacy message has, and
        // the exact shape that used to work.
        let unsigned = PosTransaction::ExitV2 { pubkey_hash, epoch, signature: Vec::new() };
        let mut probe = g.clone();
        assert_eq!(
            probe.apply_transaction(
                &unsigned,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            ),
            Err(TxReject::StakingRule),
            "an exit with no signature authorises nothing",
        );
    }

    /// A captured exit must not be replayable at a time its signer never
    /// chose: the signed epoch has to EQUAL the inclusion epoch, in both
    /// directions.
    #[test]
    fn exit_v2_binds_the_signed_epoch_to_the_inclusion_epoch() {
        let _guard = crate::params::rehearsal::exit_auth_gate_open_guard();
        let (_t, g, _c) = setup(4);
        for signed_for in [1u64, 7] {
            let mut probe = g.clone();
            assert_eq!(
                probe.apply_transaction(
                    &signed_exit(1, signed_for),
                    0,
                    fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                    &ToyVerifier,
                ),
                Err(TxReject::StakingRule),
                "an exit signed for epoch {signed_for} must not apply in epoch 0",
            );
        }
    }

    /// THE CHURN CAP — the rule that survives every signature being genuine.
    ///
    /// Four validators, all correctly signed, all in one epoch, against a
    /// budget of [`staking::MAX_EXITS_PER_EPOCH`]: the first
    /// `MAX_EXITS_PER_EPOCH` apply and every one after that is refused, so the
    /// 64-validator roster cannot retire in a block even when the keys are all
    /// under one roof — which at Genesis-4 they are.
    #[test]
    fn exit_v2_admits_at_most_max_exits_per_epoch() {
        let _guard = crate::params::rehearsal::exit_auth_gate_open_guard();
        let n = staking::MAX_EXITS_PER_EPOCH as u32 + 2;
        let (_t, g, _c) = setup(n);
        let mut st = g.clone();

        let mut applied = 0usize;
        for v in 0..n {
            let r = st.apply_transaction(
                &signed_exit(v as u8, 0),
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            );
            if r.is_ok() {
                applied += 1;
            } else {
                assert_eq!(
                    r, Err(TxReject::StakingRule),
                    "past the budget an exit is refused, not applied differently",
                );
            }
        }
        assert_eq!(
            applied,
            staking::MAX_EXITS_PER_EPOCH,
            "exactly the churn budget may be spent in one epoch",
        );

        // The budget is a property of the EPOCH, not of the state object: the
        // same window reopens once the epoch moves, and the already-exited
        // records do not keep consuming it.
        let mut next = st.clone();
        next.epoch += 1;
        assert_eq!(
            next.voluntary_exits_this_epoch(),
            0,
            "last epoch's exits must not spend this epoch's budget",
        );
        assert!(
            next.apply_transaction(
                &signed_exit((n - 1) as u8, 1),
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            )
            .is_ok(),
            "a fresh epoch restores the budget",
        );
    }

    /// The budget counts VOLUNTARY exits only. A slashing ejection sets
    /// `exit_epoch = self.epoch` (no delay), so it can neither exhaust the
    /// voluntary budget nor be blocked by it — otherwise an attacker could
    /// buy immunity from ejection by spending the epoch's exits, or a wave of
    /// ejections could freeze honest exits.
    #[test]
    fn a_slashing_ejection_does_not_spend_the_exit_budget() {
        let _guard = crate::params::rehearsal::exit_auth_gate_open_guard();
        let (_t, g, _c) = setup(4);
        let mut st = g.clone();
        // The shape slashing writes, applied directly: same epoch, no delay.
        st.validators.get_mut(&3).unwrap().slashed = true;
        st.validators.get_mut(&3).unwrap().exit_epoch = st.epoch;
        assert_eq!(
            st.voluntary_exits_this_epoch(),
            0,
            "an ejection is not a voluntary exit and must not consume the budget",
        );
    }

    // -- B4 HARDENING: the production apply path, end to end ----------------

    /// `build_block`, minus the "and this block transitions" assertion.
    ///
    /// The header is stamped by the same `derive` functions the validator
    /// checks with and signed over a `state_root` of zeros. Every check
    /// `compute_post_state` makes *before* step 10 — slot, parent, version,
    /// body/attestation/coherence roots, the sortition draw, the RANDAO
    /// reveal, the proposer signature — therefore still passes, and the block
    /// reaches the transaction arms and reports the transaction's own error.
    /// The bogus root is never the verdict, because step 12 runs after step
    /// 10.
    ///
    /// `build_block` cannot serve here: it calls `compute_post_state` and
    /// `expect`s success, which is precisely what a test about a body
    /// consensus refuses must not require. Without this helper the only way
    /// to reach a rejecting transaction arm through the real handler is to
    /// build the block under a gate you then close — which works for the
    /// flag-day tests, and does not work for a body that is invalid on BOTH
    /// sides of the gate (an exhausted churn budget, a replayed exit).
    fn stamped_block_unproven_root(
        pre: &CommittedState,
        slot: u64,
        txs: &[PosTransaction],
        chains: &mut [RandaoChain],
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
            randao_mix: mix,
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: crate::derive::attestation_root(&[]),
            coherence_root: pre.coherence_root(),
        };
        let proposer_sig = match crate::attestation::KeyLookup::pubkey(pre, p) {
            Some(pk) => toy_sign(pk, &header.proposal_signing_root()),
            None => vec![0u8; 8],
        };
        ProposalEnvelope { header, proposer_sig }
    }

    /// **THE WIRING, PROVEN AT THE REAL BLOCK HANDLER** — and proven inert.
    ///
    /// Every other test in this section calls `apply_transaction` directly,
    /// which is the seam, not the path. A rule that is only ever exercised at
    /// its seam can be perfectly correct and still unreachable: the dispatcher
    /// in `compute_post_state` step 10 routes `SlashingEvidence` by name and
    /// everything else through `_ => apply_transaction`, and "everything else"
    /// is an assumption until something drives a real block through it.
    ///
    /// So this drives one. `ToyVerifier`, never `OkVerifier`: the signature
    /// has to be checked by the code under test, not waved through by the
    /// fixture. Both halves are asserted, because each alone is misleading:
    ///
    /// - with the rehearsal gate OPEN the exit transitions end to end through
    ///   `apply_block` — body root, proposer signature, state root and all —
    ///   and the registry record it wrote is visible in the post-state, so the
    ///   handler reached `apply_exit_v2` rather than skipping an unknown
    ///   variant;
    /// - with the gate CLOSED — the configuration every node on the fleet runs
    ///   today, `EXIT_AUTH_ACTIVATION_EPOCH` being `u64::MAX` — the SAME block
    ///   with the SAME body is invalid at the transaction.
    ///
    /// That second assertion is the honest statement of this feature's status:
    /// spec-correct, composed with the real handler, and switched off. It is
    /// not "wired to production" in the sense of executing on the fleet, and
    /// it cannot be until the founder arms the constant — which is out of
    /// scope here and has its own unmet precondition (the wire byte).
    #[test]
    fn exit_v2_transitions_through_apply_block_and_is_inert_below_the_gate() {
        let (t, g, mut chains) = setup_funded(8, &[]);
        let exit = signed_exit(1, 0);

        let (b, applied_open) = {
            let _open = crate::params::rehearsal::exit_auth_gate_open_guard();
            let b = build_block(&t, &g, 1, &[], std::slice::from_ref(&exit), &mut chains);
            let st = t
                .apply_block(&g, &b, &[], std::slice::from_ref(&exit))
                .expect("with the gate open an authenticated exit must transition end to end");
            (b, st)
        };

        let rec = applied_open.validator_record(1).expect("validator 1 must still exist");
        assert_eq!(
            rec.exit_epoch,
            staking::EXIT_DELAY_EPOCHS,
            "the block handler did not reach apply_exit_v2: no exit was scheduled",
        );
        assert_eq!(
            rec.withdrawable_epoch,
            staking::EXIT_DELAY_EPOCHS.saturating_add(staking::WITHDRAWAL_DELAY_EPOCHS),
            "the withdrawal clock must start from the exit's inclusion, not from zero",
        );
        assert_eq!(
            applied_open.validator_record(0).unwrap().exit_epoch,
            u64::MAX,
            "an exit must retire the validator it names and no other",
        );

        assert_eq!(
            t.apply_block(&g, &b, &[], std::slice::from_ref(&exit)),
            Err(TransitionError::Transaction(0)),
            "GATED INERT: on the rules this tree ships, that block is refused at the \
             transaction by every node",
        );
    }

    /// **THE CHURN CAP IS A PROPERTY OF THE EPOCH, ENFORCED BY THE BLOCK
    /// HANDLER** — not of one block, and not of the mempool.
    ///
    /// This is the finding that matters most about a churn budget, and the one
    /// a seam-level test cannot see. `bloch-pos-node`'s `admissible` is relay
    /// policy: one modified producer lifts it for the whole network, which is
    /// exactly the argument that put the authentication in consensus in the
    /// first place. And a cap enforced per BLOCK would be no cap at all —
    /// there are `SLOTS_PER_EPOCH` blocks in an epoch, so a 64-validator
    /// roster would still empty inside one epoch, four at a time.
    ///
    /// So: spend the whole budget in block one, then put one more correctly
    /// signed exit in block two of the SAME epoch, and the second block is
    /// invalid. The budget survives across blocks because it is derived from
    /// the committed registry (`voluntary_exits_this_epoch`) rather than from
    /// a per-block counter — which is also why no replay path, no reordering
    /// and no restart can reset it mid-epoch.
    #[test]
    fn the_churn_cap_binds_across_blocks_within_one_epoch() {
        let _open = crate::params::rehearsal::exit_auth_gate_open_guard();
        let n = staking::MAX_EXITS_PER_EPOCH as u32 + 2;
        let (t, g, mut chains) = setup_funded(n + 4, &[]);

        // Block one spends the epoch's whole budget, in one body.
        let full: Vec<PosTransaction> =
            (0..staking::MAX_EXITS_PER_EPOCH as u32).map(|v| signed_exit(v as u8, 0)).collect();
        let b1 = build_block(&t, &g, 1, &[], &full, &mut chains);
        let s1 = t.apply_block(&g, &b1, &[], &full).expect("the budget itself must fit in a block");
        assert_eq!(
            s1.voluntary_exits_this_epoch(),
            staking::MAX_EXITS_PER_EPOCH,
            "fixture must actually spend the budget, or the next assertion is vacuous",
        );
        assert_eq!(
            crate::epoch_of(1),
            crate::epoch_of(2),
            "both blocks must sit in ONE epoch or this test proves nothing",
        );

        // Block two, same epoch, one more genuine exit by a validator that has
        // not exited and whose signature is its own.
        let over = vec![signed_exit(staking::MAX_EXITS_PER_EPOCH as u8, 0)];
        let b2 = stamped_block_unproven_root(&s1, 2, &over, &mut chains);
        assert_eq!(
            t.apply_block(&s1, &b2, &[], &over),
            Err(TransitionError::Transaction(0)),
            "a second block in the same epoch must not be able to re-open the churn budget",
        );

        // And the refusal is the budget, not the signature or the lifecycle:
        // the same message applies the moment the epoch — and only the epoch —
        // moves on.
        let mut next = s1.clone();
        next.epoch += 1;
        assert_eq!(
            next.voluntary_exits_this_epoch(),
            0,
            "last epoch's exits must not spend this epoch's budget",
        );
        assert!(
            next.apply_transaction(
                &signed_exit(staking::MAX_EXITS_PER_EPOCH as u8, 1),
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            )
            .is_ok(),
            "the refusal above must have been the budget and nothing else",
        );
    }

    /// **REPLAY, THE ONE THAT MATTERS: an old signed exit re-submitted
    /// later.**
    ///
    /// The existing epoch-binding test only refuses exits signed for the
    /// FUTURE, which is also all `staking::validate_exit` refuses (`epoch >
    /// current_epoch`) — it is the reference validator and cannot know when
    /// inclusion happens. Consensus can, and a past-signed exit is the
    /// dangerous direction: an exit message is public the moment it is
    /// gossiped, so under a `<=` rule anyone who ever signed one exit has
    /// signed a permanent, unrevocable retirement that any future proposer can
    /// cash at any time — and with `WITHDRAWAL_DELAY_EPOCHS` = 2,048 the
    /// victim's bond is locked from whenever that happens to be.
    ///
    /// Equality is what closes it, and this pins equality in the direction the
    /// weaker rule would have allowed, through the real block handler.
    #[test]
    fn an_old_signed_exit_cannot_be_replayed_in_a_later_epoch() {
        let _open = crate::params::rehearsal::exit_auth_gate_open_guard();
        let (t, g, mut chains) = setup_funded(8, &[]);

        // Captured in epoch 0, exactly as it would have been gossiped.
        let captured = signed_exit(1, 0);

        // Time passes. The state rolls to a later epoch by the boundary walk,
        // not by a test poking a field.
        let mut later = g.clone();
        for _ in 0..3 {
            later = later.close_epoch();
        }
        assert_eq!(later.epoch, 3, "fixture must actually advance the epoch");

        // Directly at the seam: refused.
        let mut probe = later.clone();
        assert_eq!(
            probe.apply_transaction(
                &captured,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            ),
            Err(TxReject::StakingRule),
            "a signature from epoch 0 must not authorise a retirement in epoch 3",
        );
        assert_eq!(
            probe.validator_record(1).unwrap().exit_epoch,
            u64::MAX,
            "a refused replay must leave no trace on the record",
        );

        // And through the real block handler, which is where a proposer would
        // actually try it.
        let body = vec![captured];
        let slot = 3 * crate::SLOTS_PER_EPOCH + 1;
        let b = stamped_block_unproven_root(&later, slot, &body, &mut chains);
        assert_eq!(
            t.apply_block(&later, &b, &[], &body),
            Err(TransitionError::Transaction(0)),
            "a block replaying a stale exit must be invalid, not merely unrelayed",
        );

        // The validator can still leave — by signing for the epoch it is
        // actually in. The rule refuses stale AUTHORISATION, never the exit.
        let mut fresh = later.clone();
        assert!(
            fresh
                .apply_transaction(
                    &signed_exit(1, 3),
                    0,
                    fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                    &ToyVerifier,
                )
                .is_ok(),
            "binding the epoch must not make voluntary exit impossible",
        );
    }

    /// The other replay: the same message, in the epoch it was signed for,
    /// submitted twice.
    ///
    /// Epoch equality cannot catch this one — the epoch is right. What catches
    /// it is the `exit_epoch != u64::MAX` lifecycle check, and it has to,
    /// because a second application would re-stamp `withdrawable_epoch` and
    /// move a withdrawal clock that must never move once started. It also
    /// keeps one validator from spending the whole epoch's churn budget by
    /// resubmitting its own exit.
    #[test]
    fn an_applied_exit_cannot_be_replayed_in_its_own_epoch() {
        let _open = crate::params::rehearsal::exit_auth_gate_open_guard();
        let (_t, g, _c) = setup(4);
        let mut st = g.clone();
        let exit = signed_exit(1, 0);

        assert!(
            st.apply_transaction(
                &exit,
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            )
            .is_ok(),
            "the first application must succeed or the replay proves nothing",
        );
        let after_first = st.validator_record(1).unwrap();

        for _ in 0..3 {
            assert_eq!(
                st.apply_transaction(
                    &exit,
                    0,
                    fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                    &ToyVerifier,
                ),
                Err(TxReject::StakingRule),
                "the identical message must not apply twice",
            );
        }
        assert_eq!(
            st.validator_record(1).unwrap(),
            after_first,
            "a refused replay must not move the withdrawal clock",
        );
        assert_eq!(
            st.voluntary_exits_this_epoch(),
            1,
            "one validator's resubmissions must not eat the epoch's churn budget",
        );
    }

    /// **THE OTHER HALF OF THE FLAG DAY.** Above the gate the unauthenticated
    /// `Exit` is INVALID — and that is not tidiness, it is the churn cap's
    /// load-bearing precondition.
    ///
    /// Legacy `Exit` carries no signature and its arm never consults a
    /// verifier. If it stayed valid past the flag day, both new rules would be
    /// decoration: anyone could retire anyone with tag `0x03` and never touch
    /// `apply_exit_v2` at all. The two arms therefore have to flip on ONE
    /// reader (`exit_auth_active`) — one gate, opposite directions, no epoch
    /// in which both are live and none in which neither is.
    #[test]
    fn above_the_gate_the_legacy_exit_is_invalid_so_it_cannot_bypass_the_new_rules() {
        let _open = crate::params::rehearsal::exit_auth_gate_open_guard();
        let (t, g, mut chains) = setup_funded(8, &[]);

        let legacy = vec![PosTransaction::Exit { validator: 1 }];
        let mut probe = g.clone();
        assert_eq!(
            probe.apply_transaction(
                &legacy[0],
                0,
                fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
                &ToyVerifier,
            ),
            Err(TxReject::StakingNotActive),
            "past the flag day the unauthenticated message must be dead",
        );
        assert_eq!(
            probe.validator_record(1).unwrap().exit_epoch,
            u64::MAX,
            "a refused legacy exit must leave no trace",
        );

        let b = stamped_block_unproven_root(&g, 1, &legacy, &mut chains);
        assert_eq!(
            t.apply_block(&g, &b, &[], &legacy),
            Err(TransitionError::Transaction(0)),
            "and the block handler must refuse it too, or the cap is bypassable by tag 0x03",
        );

        // Neither can it be laundered through the budget: an epoch whose
        // budget is untouched still refuses it.
        assert_eq!(g.voluntary_exits_this_epoch(), 0);
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
        // Pre-gate fixture: this test bonds through the legacy unfunded
        // `Deposit`/`Delegate` path, which `DEPOSIT_ACTIVATION_EPOCH` now
        // refuses at every epoch. The switch says so out loud rather than the
        // constant being weakened to keep an old fixture green.
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
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
        // Signed, for the same reason `build_block` signs: the proposer check
        // resolves the key from the registry, so a stub no longer passes a
        // key-binding verifier double.
        let proposer_sig = match crate::attestation::KeyLookup::pubkey(pre, p) {
            Some(pk) => toy_sign(pk, &header.proposal_signing_root()),
            None => vec![0u8; 8],
        };
        ProposalEnvelope { header, proposer_sig }
    }

    #[test]
    fn evidence_transaction_slashes_operator_and_delegators_and_pays_whistleblower() {
        // Pre-gate fixture: this test bonds through the legacy unfunded
        // `Deposit`/`Delegate` path, which `DEPOSIT_ACTIVATION_EPOCH` now
        // refuses at every epoch. The switch says so out loud rather than the
        // constant being weakened to keep an old fixture green.
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
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
        // Pre-gate fixture: this test bonds through the legacy unfunded
        // `Deposit`/`Delegate` path, which `DEPOSIT_ACTIVATION_EPOCH` now
        // refuses at every epoch. The switch says so out loud rather than the
        // constant being weakened to keep an old fixture green.
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        // Funded, and the transfer below actually spends: the unspent set is
        // one of the components the root must bind, and a fixture where it sat
        // empty (or untouched since genesis) would exercise that leaf
        // vacuously.
        let spender = owner_key(0x3D);
        let coin = opening(0x79, 0, 100_000_000, &spender);
        let (t, g, mut chains) = setup_funded(8, &[coin.clone()]);
        let deposit =
            toy_deposit(vec![0xAB; staking::HYBRID_PK_BYTES], [0xCD; 32], vec![0xEF; 4], 500);
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
        // Pre-gate fixture: this test bonds through the legacy unfunded
        // `Deposit`/`Delegate` path, which `DEPOSIT_ACTIVATION_EPOCH` now
        // refuses at every epoch. The switch says so out loud rather than the
        // constant being weakened to keep an old fixture green.
        let _bonding = crate::params::rehearsal::bonding_gate_open_guard();
        let spender = owner_key(0x3F);
        let coin = opening(0x7A, 0, 100_000_000, &spender);
        let (t, g, mut chains) = setup_funded(8, &[coin.clone()]);
        let deposit =
            toy_deposit(vec![0xAB; staking::HYBRID_PK_BYTES], [0xCD; 32], vec![0xEF; 4], 500);
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
        // Re-stamping the header means RE-SIGNING it: the proposer signature
        // covers the whole header, so mutating `attestation_root` (and then
        // `state_root`) invalidates the signature carried over from `b3`.
        // The old index-keyed verify accepted any proposer signature, so this
        // block was never actually signature-checked.
        let resign_header = |env: &mut ProposalEnvelope, st: &CommittedState| {
            if let Some(pk) =
                crate::attestation::KeyLookup::pubkey(st, env.header.proposer_index)
            {
                env.proposer_sig = toy_sign(pk, &env.header.proposal_signing_root());
            }
        };
        resign_header(&mut b3_rev, &r2);
        b3_rev.header.state_root =
            t.compute_post_state(&r2, &b3_rev, &reversed, &[]).unwrap().state_root();
        resign_header(&mut b3_rev, &r2);
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
        // carry is enumerated, and none of them edits the cap.
        //
        // Read that as written: NONE OF THEM EDITS THE CAP. It is not the
        // same claim as "none of them mints", and this comment used to make
        // the stronger one by asserting that Deposit and Delegate bond
        // EXISTING coins. They do not. The live `Deposit` handler consumes no
        // eUTXO input — it hashes the pubkey, checks the bounds, inserts a
        // `ValidatorRecord` and writes `staked_sat` from nothing — which the
        // crate states plainly at `transition.rs`'s eUTXO-set doc: bonding is
        // not funded from that set, and `Deposit`/`Delegate` spend no output.
        // This test never checked the bonding claim, so it passed while the
        // claim was false; the exhaustive match below proves only that the
        // variant SET cannot grow without a human reading this comment.
        // The supply consequence is tracked separately and is not pinned here.
        let witness = PosTransaction::Exit { validator: 0 };
        match &witness {
            PosTransaction::Transfer { .. } => {}
            // The deduplicated encoding of the same movement: conserves under
            // the same strict-equality rule, mints nothing.
            PosTransaction::TransferV2 { .. } => {}
            PosTransaction::Deposit { .. } => {}
            PosTransaction::Exit { .. } => {}
            // The authenticated exit schedules epochs on a record — an
            // `exit_epoch` and a `withdrawable_epoch` — and moves no satoshi
            // in either direction, so it cannot touch the cap either. What it
            // adds over the legacy message is a signature check and a churn
            // budget, neither of which is arithmetic on supply.
            PosTransaction::ExitV2 { .. } => {}
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

    // ── The inactivity leak must reach the schedule, not only the quorum ────

    /// The shipped default has to stay inert.
    ///
    /// Until the constant was armed this test pinned `u64::MAX` (inert).
    /// Arming flips its job, not its nature: it is still a tripwire — now
    /// against a SECOND silent change of the epoch, which would be a new flag
    /// day needing its own fleet rollout, announcement and runbook. The value
    /// here must equal the one recorded in `docs/LEAKED-ROSTER-FLAG-DAY.md`
    /// and in the release notes of the armed build.
    #[test]
    fn leaked_roster_armed_epoch_matches_the_runbook() {
        assert_eq!(
            crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH,
            1400,
            "the armed epoch must match docs/LEAKED-ROSTER-FLAG-DAY.md; changing it again is a new flag day"
        );
    }

    /// **The epoch-partition invariant, exercised on the REAL condition.**
    ///
    /// The existing guard test greps the source to prove the check is
    /// unconditional, then fires `consensus_invariant!(1 + 1 == 3)` — so it
    /// proves the macro panics, never that this invariant can. This one drives
    /// the actual condition with the input that separates identity from
    /// cardinality: `eligible[i] = eligible[j]` in the shuffle, which duplicates
    /// one index and loses another while the length stays exactly right.
    ///
    /// In its pre-2026-08-24 counting form the guard was GREEN on this input —
    /// a real partition bug walked through it. That is why the comparison is
    /// now on sorted index vectors.
    #[test]
    fn the_partition_invariant_catches_a_duplicated_index() {
        use std::sync::atomic::Ordering::Relaxed;
        let _h = crate::params::rehearsal::HOOK.lock().unwrap_or_else(|e| e.into_inner());

        // Control: unmutated, a boundary closes without tripping the guard.
        crate::params::rehearsal::PARTITION_DUPLICATES_AN_INDEX.store(false, Relaxed);
        let (_t, st, _c) = setup(8);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| st.clone().close_epoch()))
                .is_ok(),
            "control failed: the boundary panics even unmutated, so the mutation below \
             would prove nothing"
        );

        // Cardinality is NOT enough: with the mutation on, the seat count still
        // equals the roster length. This is the assertion the old guard made.
        crate::params::rehearsal::PARTITION_DUPLICATES_AN_INDEX.store(true, Relaxed);
        let (_t2, st2, _c2) = setup(8);
        let seed = st2.seed_for_epoch(st2.epoch + 1);
        let roster = st2.consensus_roster_at(st2.epoch + 1);
        let partition = committees::epoch_committees(&seed, st2.epoch + 1, &roster);
        assert_eq!(
            partition.iter().map(Vec::len).sum::<usize>(),
            roster.len(),
            "the mutation is supposed to preserve the SEAT COUNT — if it does not, it is \
             not reproducing the bug this guard was weak to"
        );
        let mut seated: Vec<u32> = partition.iter().flatten().copied().collect();
        seated.sort_unstable();
        let mut expected: Vec<u32> = roster.iter().map(|v| v.index).collect();
        expected.sort_unstable();
        assert_ne!(
            seated, expected,
            "the mutation did not actually duplicate an index, so the guard below is \
             not being tested on the input it exists for"
        );

        // And the shipped guard goes red on it.
        let red =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| st2.clone().close_epoch()));
        crate::params::rehearsal::PARTITION_DUPLICATES_AN_INDEX.store(false, Relaxed);
        assert!(
            red.is_err(),
            "THE PARTITION INVARIANT IS BACK TO COUNTING SEATS: an index was duplicated and \
             another lost, the length stayed right, and the guard passed. That is a real \
             partition bug shipping undetected."
        );
    }

    /// The two flag days added for the preserve-history relaunch must stay
    /// INERT until they are armed deliberately, and when armed they must match
    /// the runbook that is versioned beside them.
    ///
    /// Same idiom, and the same job, as
    /// `leaked_roster_armed_epoch_matches_the_runbook`: a tripwire against a
    /// SILENT change of a consensus flag day. Arming either of these in an
    /// epoch that is already in the PAST fails silently — the rule simply
    /// applies to everything — which is how 1,600,000 BLCH once escaped a
    /// write-off that never fired.
    #[test]
    fn the_replay_compatibility_gates_are_inert_until_armed() {
        for (name, value) in [
            ("ANCESTRY_SEED_ACTIVATION_EPOCH", crate::params::ANCESTRY_SEED_ACTIVATION_EPOCH),
            ("LEAK_RECOVERY_ACTIVATION_EPOCH", crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH),
        ] {
            assert_eq!(
                value,
                u64::MAX,
                "{name} has been armed. That is a deliberate act and it needs three things \
                 before this assertion may be updated: (1) the epoch must be STRICTLY IN THE \
                 FUTURE at tag time — an epoch already past arms silently and applies the rule \
                 to the whole history; (2) it must fall AFTER the rollout completes, since all \
                 64 validators stop and restart together; (3) the value must match the runbook \
                 versioned in docs/. Update this test in the same commit that arms it."
            );
        }
    }

    /// Below its flag day, `seed_for_epoch` must be the ORIGINAL rule, mix of
    /// `epoch − 1`. This is what lets the corrected binary replay the existing
    /// log at all: the seed decides the partition, the partition decides which
    /// attestations are admitted, and that is committed in the state root.
    ///
    /// The break is at epoch 1, not epoch 2 — `seed_epoch(1)` is `None` under
    /// the corrected rule, so it takes the genesis mix while the original takes
    /// `boundary_mixes[0]`, the close of epoch 0, which is not the genesis mix
    /// once epoch 0 has produced a block.
    #[test]
    fn below_its_flag_day_the_seed_is_the_original_rule() {
        let (_t, mut g, _c) = setup(4);
        // A boundary mix for epoch 0 that is NOT the genesis mix, which is the
        // only case that can tell the two rules apart at epoch 1.
        g.boundary_mixes.insert(0, [0xA5u8; 32]);
        assert_ne!(g.genesis_mix, [0xA5u8; 32], "fixture must distinguish the two rules");

        assert_eq!(
            g.seed_for_epoch(1),
            [0xA5u8; 32],
            "epoch 1 below the flag day must read boundary_mixes[0] — the ORIGINAL rule. \
             Reading the genesis mix here is the corrected rule leaking into history, and it \
             stops every node's boot replay at epoch 1"
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

    /// **The call-site test.** The two rosters `transition.rs` actually holds
    /// must agree on their INDEX SET, with a leak that was accrued by the real
    /// fold rather than fabricated.
    ///
    /// Why this exists on top of the committee-level tests: those build the
    /// leaked and unleaked rosters as FIXTURES shaped like what
    /// `with_leak_applied` produces, and so they prove `epoch_committees` is
    /// leak-invariant — the core claim — but not that these two call sites feed
    /// it the same index set. Make `with_leak_applied` drop the zeroed record
    /// and every one of those tests stays green while the split is back. This
    /// one goes red, which is the whole point of writing it.
    ///
    /// The leak here is REAL: it is accrued by driving `process_epoch` over
    /// epochs in which nobody attests, which is the only way a leak comes into
    /// existence anywhere in this system. Fabricating the accumulator would
    /// have made the fixture prove itself.
    #[test]
    fn the_two_call_sites_agree_on_the_index_set_with_a_real_leak() {
        let _h = crate::params::rehearsal::HOOK.lock().unwrap_or_else(|e| e.into_inner());
        crate::params::rehearsal::LEAK_DROPS_ZEROED
            .store(false, std::sync::atomic::Ordering::Relaxed);

        let (_t, mut g, _c) = setup(8);
        let seed = g.seed_for_epoch(0);

        // Accrue a real leak: epoch after epoch in which nobody attests. The
        // engine's own rule decides when the bite starts and how big it is.
        let mut zeroed = None;
        for epoch in 1..400u64 {
            let roster = g.duty_roster_at(0);
            let mut accepted = Vec::new();
            let votes = finality::votes_from_partition(epoch, &roster, &roster, &[], &seed, &mut accepted);
            if g.finality_engine.process_epoch(&votes).is_err() {
                break;
            }
            if let Some(v) = roster
                .iter()
                .find(|v| g.finality_engine.leaked_of(v.index) >= v.effective_stake)
            {
                zeroed = Some(v.index);
                break;
            }
        }
        let zeroed = zeroed.expect(
            "the fold never drove anybody to zero, so this test would be vacuous -              the leak rule or its threshold changed",
        );

        // Open the gate. Below it `consensus_roster_at` short-circuits to the
        // unleaked roster and the comparison below could not fail either way.
        let epoch = crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH;
        g.epoch = epoch;

        let duty = g.duty_roster_at(epoch);
        let consensus = g.consensus_roster_at(epoch);

        // Non-vacuity, both halves: the gate is really open, and somebody is
        // really at zero on the consensus side.
        assert_ne!(
            consensus, duty,
            "control failed: the two rosters are identical value-for-value, so the \
             leak never reached consensus_roster_at and the assertion below is vacuous"
        );
        assert_eq!(
            consensus.iter().find(|v| v.index == zeroed).map(|v| v.effective_stake),
            Some(0),
            "control failed: the fully-leaked validator is not at zero on the consensus side"
        );

        let duty_set: Vec<u32> = duty.iter().map(|v| v.index).collect();
        let consensus_set: Vec<u32> = consensus.iter().map(|v| v.index).collect();
        assert_eq!(
            consensus_set, duty_set,
            "THE ROSTER SPLIT IS BACK: consensus_roster_at and duty_roster_at no longer \
             carry the same index set, so epoch_committees will shuffle lists of different \
             length and the boundary tally will drop votes step 8 admitted"
        );

        // And the consequence the index set exists to buy: identical partitions.
        assert_eq!(
            crate::committees::epoch_committees(&seed, epoch, &consensus),
            crate::committees::epoch_committees(&seed, epoch, &duty),
            "same index set but different partitions - epoch_committees read stake again"
        );
    }

    /// **MUTATION.** Put the split back through `with_leak_applied` and watch
    /// the call-site test go red:
    ///
    /// ```text
    /// cargo test -p bloch-pos-committee --lib \
    ///   transition::tests::rehearsal_dropping_the_leaked_record_reopens_the_split \
    ///   -- --nocapture
    /// ```
    #[test]
    fn rehearsal_dropping_the_leaked_record_reopens_the_split() {
        use std::sync::atomic::Ordering::Relaxed;
        let _h = crate::params::rehearsal::HOOK.lock().unwrap_or_else(|e| e.into_inner());

        // Control: mutation off, the pinning assertion holds. Without this a
        // panic below could be coming from anywhere.
        crate::params::rehearsal::LEAK_DROPS_ZEROED.store(false, Relaxed);
        assert!(
            std::panic::catch_unwind(call_site_index_sets_agree).is_ok(),
            "control failed: the call-site assertion does not hold even unmutated"
        );

        crate::params::rehearsal::LEAK_DROPS_ZEROED.store(true, Relaxed);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // the failure IS the result
        let red = std::panic::catch_unwind(call_site_index_sets_agree);
        std::panic::set_hook(prev);
        crate::params::rehearsal::LEAK_DROPS_ZEROED.store(false, Relaxed);

        let msg = red
            .err()
            .map(|e| {
                e.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default()
            })
            .expect(
                "MUTATION DID NOT GO RED: with_leak_applied was made to drop the fully-leaked \
                 record and the two call sites still agreed on the index set. Either the \
                 switch is no longer wired into with_leak_applied, or the assertion is vacuous.",
            );
        println!("MUTATION WENT RED, as it must. First failure:\n  {msg}");
    }

    /// The body of the call-site assertion, factored out so the mutation test
    /// can run the identical code under `catch_unwind`.
    fn call_site_index_sets_agree() {
        let (_t, mut g, _c) = setup(8);
        let seed = g.seed_for_epoch(0);
        let mut zeroed = None;
        for epoch in 1..400u64 {
            let roster = g.duty_roster_at(0);
            let mut accepted = Vec::new();
            let votes = finality::votes_from_partition(epoch, &roster, &roster, &[], &seed, &mut accepted);
            if g.finality_engine.process_epoch(&votes).is_err() {
                break;
            }
            if let Some(v) = roster
                .iter()
                .find(|v| g.finality_engine.leaked_of(v.index) >= v.effective_stake)
            {
                zeroed = Some(v.index);
                break;
            }
        }
        assert!(zeroed.is_some(), "the fold never drove anybody to zero");
        let epoch = crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH;
        g.epoch = epoch;
        let duty: Vec<u32> = g.duty_roster_at(epoch).iter().map(|v| v.index).collect();
        let consensus: Vec<u32> =
            g.consensus_roster_at(epoch).iter().map(|v| v.index).collect();
        assert_eq!(
            consensus, duty,
            "THE ROSTER SPLIT IS BACK: the two call sites carry different index sets"
        );
    }

    /// A fully-leaked validator stops being drawn to propose — the liveness the
    /// leak is supposed to buy back — while **keeping its committee seat**.
    ///
    /// The second half was the opposite assertion until 2026-08-24, and the
    /// change is the point of the roster unification: committee membership is
    /// now a pure function of (seed, epoch, index set), so the leaked and
    /// unleaked rosters partition identically and the inclusion check at step 8
    /// can no longer disagree with the boundary tally about who sits where. The
    /// seat that stays is inert — zero weight in both the quorum numerator and
    /// the denominator — so nothing about finality is bought back by evicting
    /// it, whereas evicting it cost the chain every attestation in the epoch.
    /// See `committees::epoch_committees`' docs.
    ///
    /// The control half is what makes this worth running: the same validator,
    /// on the same seed, with the leak NOT applied, both proposes and sits on
    /// a committee. Without that half the assertions below would pass just as
    /// well against a roster that had lost the validator for some unrelated
    /// reason, which is the failure mode that makes a negative test worthless.
    #[test]
    fn a_fully_leaked_validator_leaves_the_schedule() {
        // Holds a roster with a zero-stake member, so it must be excluded from
        // `RESTORE_ZERO_STAKE_FILTER` (see `committees::tests`).
        let _h = crate::params::rehearsal::HOOK.lock().unwrap_or_else(|e| e.into_inner());
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
        // The seat SURVIVES the leak, and the partition is bit-identical to the
        // unleaked one. This is the assertion the 2026-08-21 defect needed and
        // did not have.
        let leaked_partition = crate::committees::epoch_committees(&seed, 0, &leaked);
        assert!(
            leaked_partition.iter().any(|c| c.contains(&absent)),
            "a fully-leaked validator must keep its (inert) committee seat — evicting it is \
             what made the two rosters partition differently"
        );
        assert_eq!(
            leaked_partition,
            crate::committees::epoch_committees(&seed, 0, &unleaked),
            "the leaked and unleaked rosters must partition identically"
        );

        // And the slots it used to take are not lost — they go to the live set,
        // which is the entire point: empty slots become produced slots.
        assert!(
            (0..256).filter_map(|s| schedule::proposer(&seed, s, &leaked)).count() == 256,
            "every slot must still draw a proposer from the surviving validators"
        );
    }

    /// The boundary-divergence DETECTOR fires, and it is in the release
    /// binary.
    ///
    /// Drives the real `close_epoch` over a real mid-epoch slash: votes are
    /// admitted against the 8-member partition, validator 3 is then removed
    /// from the roster exactly the way `apply_slashing_evidence` removes it,
    /// and the boundary tallies against the 7-member partition. The counter
    /// must move. The `debug_assert_eq!` beside it must ALSO still fire in a
    /// test build, so the close is run under `catch_unwind` — a test build is
    /// supposed to stop on this, production is supposed to log it and carry on.
    #[test]
    fn the_boundary_divergence_detector_fires_on_a_mid_epoch_slash() {
        use std::panic::AssertUnwindSafe;
        use std::sync::atomic::Ordering::Relaxed;
        let _h = crate::params::rehearsal::HOOK.lock().unwrap_or_else(|e| e.into_inner());

        let (_t, g, _c) = setup(8);
        let mut st = g.clone();
        st.epoch = 1;

        // Exactly what step 8 would have admitted: every member of the epoch's
        // partition, voting in its own slot, off the real seed and the real
        // roster.
        let seed = st.seed_for_epoch(1);
        let roster = st.duty_roster_at(1);
        let partition = committees::epoch_committees(&seed, 1, &roster);
        for (i, members) in partition.iter().enumerate() {
            for v in members {
                let d = AttestationData {
                    slot: SLOTS_PER_EPOCH + i as u64,
                    head: [0x11; 32],
                    source_epoch: 0,
                    source_root: *g.head.as_bytes(),
                    target_epoch: 1,
                    target_root: [0x11; 32],
                };
                st.pending_votes.insert((*v, d.signing_root()), d);
            }
        }
        assert_eq!(st.pending_votes.len(), 8, "fixture must actually carry votes");

        // The mid-epoch slash, written the way apply_slashing_evidence writes
        // it — the unit seam, so the test does not need valid PQ evidence.
        {
            let rec = st.validators.get_mut(&3).unwrap();
            rec.slashed = true;
            rec.exit_epoch = 1;
        }

        let before = BOUNDARY_VOTE_DROPS.load(Relaxed);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let closed = std::panic::catch_unwind(AssertUnwindSafe(|| st.close_epoch()));
        std::panic::set_hook(prev);

        assert!(
            BOUNDARY_VOTE_DROPS.load(Relaxed) > before,
            "the boundary dropped votes and the unconditional detector did not count it — \
             production would be blind to this again"
        );
        assert!(
            closed.is_err(),
            "the debug_assert beside the detector must still stop a TEST build; if it stopped \
             firing, a test run can no longer tell this apart from a healthy boundary"
        );

        // And the detector really is unconditional at the call site.
        //
        // Comments are stripped before the window is judged. Without that, the
        // explanatory comment directly above the call — which necessarily says
        // the words "debug_assert", because explaining why this is NOT one is
        // its entire job — trips the assertion. That is how this test failed
        // the first time it was ever run: a false red, on prose.
        let src = include_str!("transition.rs");
        let at = src.find("report_boundary_vote_drop(closing,").expect("the call site moved");
        let code: String = src[at.saturating_sub(600)..at]
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("#[cfg(") && !code.contains("debug_assert"),
            "the detector call has grown a cfg gate or moved inside a debug_assert; it is a \
             release-profile check or it is nothing. Code before the call site:\n{code}"
        );
    }

    /// The partition-coverage guard must be in the **release** binary.
    ///
    /// The workspace `[profile.release]` sets `overflow-checks = true` and does
    /// not set `debug-assertions`, so it defaults to `false` and every
    /// `debug_assert!` is compiled out of the binary mainnet runs — which is
    /// why the one guard on the 2026-08-21 roster split found nothing. This
    /// pins the replacement: the coverage check goes through
    /// `consensus_invariant!`, that macro is gated on no `cfg` at all, and it
    /// really does panic. Source-scanned rather than taken on faith, because
    /// the failure mode is a guard that exists in the tree and not in the
    /// binary, which no ordinary test can tell apart.
    #[test]
    fn the_partition_coverage_guard_survives_into_a_release_build() {
        let src = include_str!("transition.rs");
        // The guard's message changed on 2026-08-24 when it stopped comparing
        // seat COUNT (a tautology no input could fail) and started comparing
        // sorted index vectors. This test only proves the guard is
        // UNCONDITIONAL; that its condition can actually fail is proved by
        // `the_partition_invariant_catches_a_duplicated_index`, which drives the
        // real condition instead of a planted `1 + 1 == 3`.
        let needle = "epoch partition must seat every validator exactly once";
        let at = src.find(needle).expect("the coverage guard's message moved");
        let window = &src[at.saturating_sub(500)..at];
        assert!(
            window.contains("consensus_invariant!("),
            "the coverage guard is no longer a consensus_invariant! — if it went back to \
             debug_assert! it is absent from every release build"
        );

        // The macro itself must not be gated on anything.
        let lib = include_str!("lib.rs");
        let body = lib
            .split("macro_rules! consensus_invariant")
            .nth(1)
            .expect("the macro moved out of lib.rs")
            .split("\npub(crate) use")
            .next()
            .unwrap();
        assert!(
            !body.contains("cfg!") && !body.contains("#[cfg") && !body.contains("debug_assert"),
            "consensus_invariant! has grown a cfg gate; it is a release-profile check or it \
             is nothing"
        );

        // And it fires. Caught, so the suite stays green while proving it.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let fired = std::panic::catch_unwind(|| {
            consensus_invariant!(1 + 1 == 3, "planted violation, {} != {}", 2, 3);
        });
        std::panic::set_hook(prev);
        assert!(fired.is_err(), "consensus_invariant! did not panic on a false condition");
    }

    /// **The divergence the roster unification does NOT close, pinned so it is
    /// not mistaken for closed.**
    ///
    /// Removing the `effective_stake > 0` filter from `epoch_committees` makes
    /// the partition invariant under *stake* changes, which is what the leak
    /// is. It cannot make it invariant under *membership* changes, and
    /// `apply_slashing_evidence` performs one MID-EPOCH: it sets
    /// `slashed = true` and `exit_epoch = epoch` the moment valid evidence is
    /// applied, and `duty_roster_at` filters on exactly that.
    ///
    /// So within one epoch the roster's INDEX SET can shrink between two
    /// blocks. Attestations admitted by step 8 against the 64-member partition
    /// are then tallied at the boundary against the 63-member one, which is a
    /// different Fisher-Yates permutation everywhere — the same mechanism as
    /// the leak defect, from a different cause, and reachable by anyone who can
    /// get valid equivocation evidence included.
    ///
    /// This is why the guard in `close_epoch` is deliberately still a
    /// `debug_assert!` and NOT a `consensus_invariant!`: an unconditional panic
    /// there would be a remotely triggerable halt. Closing it properly means
    /// freezing the epoch's roster at its first slot — a consensus rule change
    /// with its own flag day, out of scope for the 2026-08-24 unification.
    #[test]
    fn mid_epoch_slashing_changes_the_roster_index_set_within_one_epoch() {
        // Same reason as above: the control half builds a fully-leaked roster.
        let _h = crate::params::rehearsal::HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let (_t, g, _c) = setup(8);
        let seed = g.seed_for_epoch(g.epoch);
        let before = g.duty_roster_at(g.epoch);
        assert_eq!(before.len(), 8);

        // Exactly what `apply_slashing_evidence` writes, minus the evidence
        // plumbing — the unit seam, the same pattern `with_leak_applied` is
        // tested at.
        let mut after_state = g.clone();
        {
            let rec = after_state.validators.get_mut(&3).unwrap();
            rec.slashed = true;
            rec.exit_epoch = after_state.epoch;
        }
        let after = after_state.duty_roster_at(after_state.epoch);

        assert_eq!(after.len(), 7, "a slash must remove the record from the duty roster");
        assert!(!after.iter().any(|v| v.index == 3));

        // Control: the leak, which changes only stake, does NOT move the
        // partition. If this half ever fails, the unification has regressed and
        // the assertion below is measuring the wrong thing.
        let leaked = with_leak_applied(before.clone(), |i| if i == 3 { u64::MAX } else { 0 });
        assert_eq!(
            committees::epoch_committees(&seed, g.epoch, &leaked),
            committees::epoch_committees(&seed, g.epoch, &before),
            "control: a pure stake change must not move the partition"
        );

        // The membership change, however, does.
        let p_before = committees::epoch_committees(&seed, g.epoch, &before);
        let p_after = committees::epoch_committees(&seed, g.epoch, &after);
        assert_ne!(
            p_before, p_after,
            "if a mid-epoch slash stopped re-sorting the partition, this residual is closed \
             and the debug_assert in close_epoch can be promoted to consensus_invariant!"
        );
        let moved = p_before
            .iter()
            .zip(p_after.iter())
            .map(|(a, b)| a.iter().filter(|v| **v != 3 && b.binary_search(*v).is_err()).count())
            .sum::<usize>();
        println!(
            "MID-EPOCH SLASH: one validator removed from an 8-member roster moved {moved} of \
             the remaining 7 into a different slot. Stake changes are invariant; membership \
             changes are not."
        );
    }

    // ── TransferV2: deduplicated witnesses behind their own flag day ────────
    //
    // The tests below call `apply_transfer_v2` directly — the unit seam
    // BELOW the flag-day gate, the same pattern as testing
    // `with_leak_applied` directly. This banner used to justify that by
    // saying the gate was still at its inert maximum value so the block path
    // refused everything; that stopped being true when
    // `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` was bound, and the chain is
    // long past it. The unit seam is still the right place to test the apply
    // rules in isolation — it just is not because the format is unreachable.
    // The gate itself is tested end-to-end through `compute_post_state`.

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

    // ── The seed: what the look-ahead buys, and what the ANCHOR buys ────────
    //
    // Two different fixes live in this tree and they are not the same fix.
    //
    // * The F6 LOOK-AHEAD moves which boundary the seed reads, from the close
    //   of `E-1` to the close of `E-2`. It is a rule change, and the reader
    //   is still anchored to the reading node's own head.
    // * The ANCHOR (`Engine::seed_for_attestation`) changes where the seed is
    //   read FROM: the attestation's own branch, walked back through
    //   consensus-checked `header.randao_mix` fields, instead of this node's
    //   head rolled speculatively forward.
    //
    // The look-ahead widens a window. The anchor removes the node's head from
    // the derivation altogether. `lag_tolerance_measured_in_slots_and_epochs`
    // prices the first; `the_anchor_never_disagrees_at_any_lag` prices the
    // second. Everything here runs through the REAL readers on real states
    // from the real transition — a library function nobody calls proves
    // nothing about a live chain, which is how mainnet split with the F6
    // property test already green.
    mod seed_lookahead {
        use super::*;
        use crate::header::BlockHeaderV4 as Hdr;

        /// A block at every slot from 1 to `slots`, minus `skipped`, with each
        /// epoch's full attestation quorum carried by its last slot.
        ///
        /// The quorum is not decoration: without it nothing justifies, the
        /// inactivity leak arms after a few epochs, and `consensus_roster_at`
        /// starts moving stake. A roster that drifts would repartition the
        /// committee for a reason that is not the seed, and every measurement
        /// below would be reading the leak instead of the thing under test.
        struct Chain {
            /// Head state after each slot; `states[0]` is genesis. A skipped
            /// slot repeats its predecessor, so the index is the slot number.
            states: Vec<CommittedState>,
            /// Every block header this chain produced, by block id — the
            /// node's `blocks` map, which is what the anchor walks.
            headers: BTreeMap<[u8; 32], Hdr>,
            /// Block id produced at each slot, where one was.
            root_at: BTreeMap<u64, [u8; 32]>,
            genesis_root: [u8; 32],
            genesis_mix: [u8; 32],
        }

        fn chain(n: u32, slots: u64, skipped: &[u64]) -> Chain {
            let (t, g, mut chains) = setup(n);
            let genesis_root = *g.head.as_bytes();
            let genesis_mix = g.genesis_mix;
            let mut states = Vec::with_capacity(slots as usize + 1);
            let mut headers = BTreeMap::new();
            let mut root_at = BTreeMap::new();
            let mut st = g.clone();
            states.push(g);
            let mut epoch_first_root = [0u8; 32];
            for slot in 1..=slots {
                if skipped.contains(&slot) {
                    states.push(st.clone());
                    continue;
                }
                let epoch = crate::epoch_of(slot);
                let last_of_epoch = slot % SLOTS_PER_EPOCH == SLOTS_PER_EPOCH - 1;
                // Epoch 0 has no attestations to carry: source 0 is not < target 0.
                let atts = if last_of_epoch && epoch >= 1 {
                    full_epoch_attestations(&st, epoch_first_root)
                } else {
                    Vec::new()
                };
                let b = build_block(&t, &st, slot, &atts, &[], &mut chains);
                st = t
                    .apply_block(&st, &b, &atts, &[])
                    .expect("the fixture's own block must transition");
                let id = *st.head.as_bytes();
                headers.insert(id, b.header);
                root_at.insert(slot, id);
                if slot % SLOTS_PER_EPOCH == 0 {
                    epoch_first_root = id;
                }
                states.push(st.clone());
            }
            Chain { states, headers, root_at, genesis_root, genesis_mix }
        }

        impl Chain {
            /// The blocks a node whose head is at `head_slot` holds. The
            /// anchor reads this map and nothing else — which is the whole
            /// point of it.
            fn blocks_up_to(&self, head_slot: u64) -> BTreeMap<[u8; 32], Hdr> {
                self.root_at
                    .iter()
                    .filter(|(s, _)| **s <= head_slot)
                    .filter_map(|(_, id)| self.headers.get(id).map(|h| (*id, *h)))
                    .collect()
            }

            /// The checkpoint root of `epoch`: the latest block strictly
            /// BEFORE the epoch's first slot — the convention `target_root`
            /// carries, and therefore what an attestation for `epoch` anchors
            /// to.
            fn checkpoint_root(&self, epoch: u64) -> [u8; 32] {
                let first = epoch * SLOTS_PER_EPOCH;
                self.root_at
                    .range(..first)
                    .next_back()
                    .map(|(_, id)| *id)
                    .unwrap_or(self.genesis_root)
            }
        }

        /// `Engine::ancestral_boundary_mix`, reproduced against a plain header
        /// map: walk selected-parent from `from` to the last block strictly
        /// below the first slot of `epoch` and take its `randao_mix`.
        ///
        /// `None` = the branch is unreachable from what this node holds. The
        /// node must Ignore, never Reject — a node that cannot reach the
        /// branch is not in a position to claim anybody is out of committee.
        fn ancestral_boundary_mix(
            blocks: &BTreeMap<[u8; 32], Hdr>,
            genesis_root: [u8; 32],
            genesis_mix: [u8; 32],
            from: &[u8; 32],
            epoch: u64,
        ) -> Option<[u8; 32]> {
            let first = epoch * SLOTS_PER_EPOCH;
            let mut cur = *from;
            for _ in 0..=blocks.len() {
                if cur == genesis_root {
                    return Some(genesis_mix);
                }
                let h = blocks.get(&cur)?;
                if h.slot < first {
                    return Some(h.randao_mix);
                }
                cur = h.parent;
            }
            None
        }

        /// `Engine::seed_for_attestation`, reproduced.
        fn seed_for_attestation(
            c: &Chain,
            blocks: &BTreeMap<[u8; 32], Hdr>,
            target_root: &[u8; 32],
            epoch: u64,
        ) -> Option<[u8; 32]> {
            match epoch.checked_sub(committees::MIN_SEED_LOOKAHEAD_EPOCHS) {
                None => Some(c.genesis_mix),
                Some(src) => {
                    ancestral_boundary_mix(blocks, c.genesis_root, c.genesis_mix, target_root, src)
                }
            }
        }

        /// `Engine::rolled_to`, in this crate's terms: the head state rolled
        /// forward through `process_epoch` until its open epoch is `epoch`.
        /// Byte for byte the loop the node runs — `process_epoch` is
        /// `close_epoch` and nothing else.
        fn rolled_to(st: &CommittedState, epoch: u64) -> CommittedState {
            let mut cur = st.clone();
            while cur.epoch < epoch {
                cur = cur.close_epoch();
            }
            cur
        }

        /// The seed an ALREADY-ROLLED state yields for `epoch` under an
        /// arbitrary look-ahead. Look-ahead 1 is the shipped rule; 0 is the
        /// pre-fix rule, kept so one run can price both without recompiling.
        /// Pinned against the production reader in
        /// `the_model_of_the_reader_matches_the_reader` — without that pin
        /// every number this module prints is fiction.
        fn seed_of_rolled(rolled: &CommittedState, epoch: u64, lookahead: u64) -> [u8; 32] {
            match epoch.checked_sub(lookahead + 1) {
                None => rolled.genesis_mix,
                Some(e) => rolled.boundary_mixes.get(&e).copied().unwrap_or(rolled.genesis_mix),
            }
        }

        fn seed_from_head(st: &CommittedState, epoch: u64, lookahead: u64) -> [u8; 32] {
            seed_of_rolled(&rolled_to(st, epoch), epoch, lookahead)
        }

        fn committees_of(st: &CommittedState, epoch: u64, lookahead: u64) -> Vec<Vec<u32>> {
            let rolled = rolled_to(st, epoch);
            let roster = rolled.consensus_roster_at(epoch);
            let seed = seed_of_rolled(&rolled, epoch, lookahead);
            committees::epoch_committees(&seed, epoch, &roster)
        }

        fn hex8(b: &[u8; 32]) -> String {
            b[..4].iter().map(|x| format!("{x:02x}")).collect()
        }

        // ── control: the model equals the shipped reader ────────────────────

        #[test]
        fn the_model_of_the_reader_matches_the_reader() {
        // The rules under test ship INERT behind their flag days; open them for
        // this thread so this is not dead code. See params::rehearsal.
        let _gates = crate::params::rehearsal::gates_open_guard();
            let c = chain(8, 5 * SLOTS_PER_EPOCH + 3, &[]);
            for target in 0..=6u64 {
                for head in [0u64, 31, 64, 95, 128, 160, 163] {
                    let st = &c.states[head as usize];
                    if st.epoch > target {
                        continue;
                    }
                    let rolled = rolled_to(st, target);
                    assert_eq!(
                        seed_of_rolled(&rolled, target, committees::MIN_SEED_LOOKAHEAD_EPOCHS),
                        rolled.seed_for_epoch(target),
                        "the module's model of seed_for_epoch has drifted from the reader \
                         (target {target}, head slot {head})"
                    );
                }
            }
        }

        // ── THE ANCHOR ─────────────────────────────────────────────────────

        /// **The property that distinguishes the anchor from the look-ahead:
        /// at NO lag does an anchored node derive a WRONG committee.** It
        /// either derives the right one or reports the branch unreachable —
        /// and unreachable means Ignore, never Reject.
        ///
        /// That is the whole disease. The old reader answered an honest vote
        /// from a validator that really was in the committee with a peer
        /// penalty, because it judged the vote against a committee derived
        /// from how much of the chain the JUDGE had downloaded. A node cannot
        /// be wrong about someone else's duty by being behind if its own head
        /// is not an input.
        ///
        /// The control is the third column: the head-anchored rule must be
        /// shown to actually DISAGREE at some lag, or the comparison is
        /// vacuous and this test proves nothing about the anchor.
        #[test]
        fn the_anchor_never_disagrees_at_any_lag() {
        // The rules under test ship INERT behind their flag days; open them for
        // this thread so this is not dead code. See params::rehearsal.
        let _gates = crate::params::rehearsal::gates_open_guard();
            const TARGET: u64 = 5;
            let lead_slot = TARGET * SLOTS_PER_EPOCH + 3;
            let c = chain(8, lead_slot, &[]);
            let leader = &c.states[lead_slot as usize];
            assert_eq!(leader.epoch, TARGET);

            // What an attestation for epoch TARGET carries: the checkpoint
            // root of TARGET, which is the last block below its first slot.
            let target_root = c.checkpoint_root(TARGET);
            assert_eq!(
                c.root_at.get(&(TARGET * SLOTS_PER_EPOCH - 1)),
                Some(&target_root),
                "control: with a dense chain the checkpoint of TARGET is the last block of \
                 TARGET-1"
            );

            // Truth: the seed the TRANSITION will use when that attestation is
            // validated inside a block on this branch. The anchor and the
            // head-anchored reader at the SHIPPED look-ahead are both measured
            // against it.
            let truth = leader.seed_for_epoch(TARGET);
            // The pre-fix rule is measured against ITS OWN caught-up answer,
            // not against `truth`. Measuring it against `truth` would answer
            // "does look-ahead 0 differ from look-ahead 1", which is a
            // question about the rule change and not about lag, and would mark
            // a perfectly self-consistent base node WRONG at zero lag.
            let truth0 = seed_from_head(leader, TARGET, 0);

            eprintln!(
                "\nANCHOR-LAG target epoch {TARGET}, leader head slot {lead_slot}, attestation \
                 target_root {} (slot {})",
                hex8(&target_root),
                TARGET * SLOTS_PER_EPOCH - 1
            );
            eprintln!(
                "  {:>9} {:>5} {:>4} | {:^12} | {:^12} | {:^12}",
                "head slot", "epoch", "lag", "ANCHOR", "HEAD la=1", "HEAD la=0"
            );
            eprintln!(
                "  (each column is compared against a CAUGHT-UP node running the same rule, so                  a WRONG is lag doing the damage and not the rule change.)"
            );

            let mut rows: Vec<u64> = vec![lead_slot];
            for h in (0..=TARGET).rev() {
                let last = h * SLOTS_PER_EPOCH + SLOTS_PER_EPOCH - 1;
                if last <= lead_slot {
                    rows.push(last);
                }
                rows.push(h * SLOTS_PER_EPOCH);
            }
            rows.sort_unstable();
            rows.dedup();
            rows.reverse();

            let mut anchor_wrong = 0usize;
            let mut anchor_unjudgeable = 0usize;
            let mut head1_wrong = 0usize;
            let mut head0_wrong = 0usize;
            for &head in &rows {
                let st = &c.states[head as usize];
                let blocks = c.blocks_up_to(head);
                let a = seed_for_attestation(&c, &blocks, &target_root, TARGET);
                let h1 = seed_from_head(st, TARGET, 1);
                let h0 = seed_from_head(st, TARGET, 0);
                let a_verdict = match a {
                    None => {
                        anchor_unjudgeable += 1;
                        "UNJUDGEABLE"
                    }
                    Some(s) if s == truth => "AGREE",
                    Some(_) => {
                        anchor_wrong += 1;
                        "WRONG"
                    }
                };
                if h1 != truth {
                    head1_wrong += 1;
                }
                if h0 != truth0 {
                    head0_wrong += 1;
                }
                eprintln!(
                    "  {:>9} {:>5} {:>4} | {:^12} | {:^12} | {:^12}",
                    head,
                    st.epoch,
                    TARGET as i64 - st.epoch as i64,
                    a_verdict,
                    if h1 == truth { "AGREE" } else { "WRONG" },
                    if h0 == truth0 { "AGREE" } else { "WRONG" },
                );
            }
            eprintln!(
                "\nANCHOR-LAG SUMMARY over {} head positions: anchor WRONG {anchor_wrong}, \
                 anchor UNJUDGEABLE {anchor_unjudgeable}; head-anchored WRONG {head1_wrong} at \
                 look-ahead 1 and {head0_wrong} at look-ahead 0.\n\
                 WRONG is a false NotInCommittee Reject and a peer penalty. UNJUDGEABLE is an \
                 Ignore and costs the peer nothing.\n",
                rows.len()
            );

            // THE PROPERTY.
            assert_eq!(
                anchor_wrong, 0,
                "the anchor must never derive a committee that differs from the transition's; \
                 {anchor_wrong} of {} head positions did",
                rows.len()
            );
            // CONTROL — without a head-anchored failure somewhere, the
            // property above is satisfied by a rule that does nothing.
            assert!(
                head1_wrong > 0,
                "control: the head-anchored reader must be shown to actually get the committee \
                 WRONG at some lag, or this test is not comparing anything"
            );
            assert!(
                head0_wrong >= head1_wrong,
                "control: the pre-fix look-ahead must be at least as wrong as the fixed one"
            );
        }

        /// The seam the anchor lives or dies on, and which nothing else pins:
        /// **the mix the anchor reads out of a block HEADER must be the mix
        /// `close_epoch` writes into `boundary_mixes`.**
        ///
        /// `judge` (gossip admission) reads the first; step 8 of
        /// `compute_post_state` (block inclusion) reads the second. If they
        /// can differ, a node relays attestations it will then refuse to
        /// build on, and the anchor has replaced one split with another.
        ///
        /// Checked on a chain with EMPTY EPOCHS in it, because that is where
        /// the two definitions could come apart: the anchor walks to the last
        /// block below the boundary, which for an empty epoch sits one or
        /// more epochs further back, while `close_epoch` still writes an
        /// entry for the empty epoch.
        #[test]
        fn the_anchors_header_mix_is_the_transitions_boundary_mix() {
        // The rules under test ship INERT behind their flag days; open them for
        // this thread so this is not dead code. See params::rehearsal.
        let _gates = crate::params::rehearsal::gates_open_guard();
            // Epoch 3 (slots 96..=127) is left ENTIRELY empty.
            let empty: Vec<u64> = (3 * SLOTS_PER_EPOCH..4 * SLOTS_PER_EPOCH).collect();
            let last = 6 * SLOTS_PER_EPOCH;
            let c = chain(8, last, &empty);
            let head = &c.states[last as usize];
            assert_eq!(head.epoch, 6);
            assert!(
                c.root_at.range(3 * SLOTS_PER_EPOCH..4 * SLOTS_PER_EPOCH).next().is_none(),
                "control: epoch 3 must really be empty, or the hard case is untested"
            );

            let blocks = c.blocks_up_to(last);
            for epoch in 2..=6u64 {
                let target_root = c.checkpoint_root(epoch);
                let anchored = seed_for_attestation(&c, &blocks, &target_root, epoch)
                    .expect("the whole chain is held, so nothing is unjudgeable");
                // The transition's own answer, from a state on that branch
                // whose open epoch is `epoch`.
                let on_branch = rolled_to(&c.states[(epoch * SLOTS_PER_EPOCH) as usize], epoch);
                let transitional = on_branch.seed_for_epoch(epoch);
                eprintln!(
                    "ANCHOR-SEAM epoch {epoch}: anchor {} vs transition {}",
                    hex8(&anchored),
                    hex8(&transitional)
                );
                assert_eq!(
                    anchored, transitional,
                    "epoch {epoch}: the gossip judge and the block-inclusion check must derive \
                     the SAME seed, or a node relays what it will then refuse to build on"
                );
            }
        }

        // ── What the LOOK-AHEAD buys, measured rather than estimated ────────

        /// `rolled_to(T)` closes every epoch from the node's own open epoch to
        /// `T-1`, and each `close_epoch` writes
        /// `boundary_mixes[closing] = st.randao_mix` — the mix frozen at that
        /// node's head. So a rolled entry for epoch `e` is the TRUE close of
        /// `e` if and only if the node holds every block of `e`. Let `C` be
        /// the last epoch the node holds COMPLETE. The seed for `T` reads the
        /// boundary at `T - 1 - lookahead`, so a head-anchored node agrees
        /// with a caught-up one iff
        ///
        ///     T - 1 - lookahead <= C
        ///
        /// One epoch of block history per unit of look-ahead, and nothing
        /// else. The test prints the boundary rather than asserting a guess.
        #[test]
        fn lag_tolerance_measured_in_slots_and_epochs() {
            const TARGET: u64 = 5;
            let lead_slot = TARGET * SLOTS_PER_EPOCH + 3;
            let c = chain(8, lead_slot, &[]);
            let states = &c.states;
            let leader = &states[lead_slot as usize];
            assert_eq!(leader.epoch, TARGET, "the leader must be inside the target epoch");

            // ── The SECOND fabrication channel, measured before anything else
            //
            // `rolled_to` does not only fabricate boundary mixes. Every
            // `close_epoch` it runs also PAYS REWARDS, so a node rolling from
            // an old head invents stake the chain never issued and its
            // `consensus_roster_at` differs from a caught-up node's by more
            // than the seed. Neither the look-ahead NOR the anchor closes
            // this: `judge` still takes its roster from `rolled_to`.
            let lead_roster = rolled_to(leader, TARGET).consensus_roster_at(TARGET);
            let stale_roster = rolled_to(&states[0], TARGET).consensus_roster_at(TARGET);
            eprintln!(
                "\nROSTER-CHANNEL: rolling from genesis vs from the leader's head gives {} \
                 rosters for epoch {TARGET} (leader stake {:?}, rolled-from-genesis stake \
                 {:?}). Uniform genesis stakes hide the consequence; a live roster does not. \
                 This channel is NOT what the seed fix closes.",
                if lead_roster != stale_roster { "DIFFERENT" } else { "identical" },
                lead_roster.first().map(|v| v.effective_stake),
                stale_roster.first().map(|v| v.effective_stake),
            );
            assert_ne!(
                lead_roster, stale_roster,
                "if the roster no longer drifts under rolling, the warning above is stale — \
                 check whether close_epoch still pays rewards"
            );

            eprintln!(
                "\nSEED-LAG target epoch {TARGET}, leader head slot {lead_slot}. `own` = each \
                 node's own rolled roster (what it really judges with); `shared` = the leader's \
                 roster, which isolates the seed."
            );
            eprintln!(
                "  {:>9} {:>5} {:>4} | {:^34} | {:^34}",
                "head slot", "epoch", "lag", "LOOK-AHEAD 1 (fixed)", "LOOK-AHEAD 0 (base)"
            );

            let mut rows: Vec<u64> = Vec::new();
            for h in (0..=TARGET).rev() {
                let last = h * SLOTS_PER_EPOCH + SLOTS_PER_EPOCH - 1;
                if last <= lead_slot {
                    rows.push(last);
                }
                rows.push(h * SLOTS_PER_EPOCH);
            }
            rows.sort_unstable();
            rows.reverse();

            let comm_with = |st: &CommittedState, lookahead: u64, roster: &[Validator]| {
                committees::epoch_committees(
                    &seed_from_head(st, TARGET, lookahead),
                    TARGET,
                    roster,
                )
            };
            let lead_seed1 = seed_from_head(leader, TARGET, 1);
            let lead_seed0 = seed_from_head(leader, TARGET, 0);
            let lead_own1 = committees_of(leader, TARGET, 1);
            let lead_own0 = committees_of(leader, TARGET, 0);
            let lead_sh1 = comm_with(leader, 1, &lead_roster);
            let lead_sh0 = comm_with(leader, 0, &lead_roster);

            for &head in rows.iter() {
                let st = &states[head as usize];
                let s1 = seed_from_head(st, TARGET, 1);
                let s0 = seed_from_head(st, TARGET, 0);
                let own1 = committees_of(st, TARGET, 1);
                let own0 = committees_of(st, TARGET, 0);
                let sh1 = comm_with(st, 1, &lead_roster);
                let sh0 = comm_with(st, 0, &lead_roster);
                let d = |a: &Vec<Vec<u32>>, b: &Vec<Vec<u32>>| {
                    a.iter().zip(b).filter(|(x, y)| x != y).count()
                };
                eprintln!(
                    "  {:>9} {:>5} {:>4} | {} {:<7} own {:>2}/32 shared {:>2}/32 | \
                     {} {:<7} own {:>2}/32 shared {:>2}/32",
                    head,
                    st.epoch,
                    TARGET as i64 - st.epoch as i64,
                    hex8(&s1),
                    if s1 == lead_seed1 { "AGREE" } else { "DIVERGE" },
                    d(&own1, &lead_own1),
                    d(&sh1, &lead_sh1),
                    hex8(&s0),
                    if s0 == lead_seed0 { "AGREE" } else { "DIVERGE" },
                    d(&own0, &lead_own0),
                    d(&sh0, &lead_sh0),
                );
                // On a shared roster the seed is the ONLY input left, so seed
                // agreement and committee agreement must coincide. If they
                // ever came apart the table would be reporting something
                // other than the seed.
                assert_eq!(
                    s1 == lead_seed1,
                    sh1 == lead_sh1,
                    "head slot {head}, look-ahead 1: seed and shared-roster committee disagree \
                     about whether they agree"
                );
                assert_eq!(
                    s0 == lead_seed0,
                    sh0 == lead_sh0,
                    "head slot {head}, look-ahead 0: seed and shared-roster committee disagree \
                     about whether they agree"
                );
            }

            // The exact boundary, swept slot by slot rather than estimated.
            let floor = |lookahead: u64| -> u64 {
                let lead_seed = seed_from_head(leader, TARGET, lookahead);
                let mut lowest = lead_slot;
                for head in (0..=lead_slot).rev() {
                    if seed_from_head(&states[head as usize], TARGET, lookahead) == lead_seed {
                        lowest = head;
                    } else {
                        break;
                    }
                }
                lowest
            };
            let f1 = floor(1);
            let f0 = floor(0);
            eprintln!(
                "\nSEED-LAG BOUNDARY (leader head slot {lead_slot}, target epoch {TARGET}):\n  \
                 look-ahead 1 (fixed): agrees down to head slot {f1} -> tolerates {} slots of \
                 lag\n  \
                 look-ahead 0 (base) : agrees down to head slot {f0} -> tolerates {} slots of \
                 lag\n  \
                 GAIN: {} slots = {} epoch of block history = {} minutes at 30 s/slot, on top \
                 of the {} minutes the base rule already had.\n",
                lead_slot - f1,
                lead_slot - f0,
                f0 - f1,
                (f0 - f1) / SLOTS_PER_EPOCH,
                (f0 - f1) * 30 / 60,
                (lead_slot - f0) * 30 / 60,
            );

            assert!(
                f1 < f0,
                "the look-ahead must tolerate MORE lag than the base rule; measured fixed floor \
                 {f1} vs base floor {f0}"
            );
            assert!(f1 > 0, "a fix that tolerates unbounded lag is not this fix");
            assert_eq!(
                f0 - f1,
                SLOTS_PER_EPOCH,
                "one unit of look-ahead must buy exactly one epoch of block history, no more"
            );
            assert_eq!(
                f0,
                (TARGET - 1) * SLOTS_PER_EPOCH + SLOTS_PER_EPOCH - 1,
                "the base rule's floor must be the LAST SLOT of epoch TARGET-1: it needs that \
                 epoch complete and nothing more"
            );
            assert_eq!(
                f1,
                (TARGET - 2) * SLOTS_PER_EPOCH + SLOTS_PER_EPOCH - 1,
                "the fixed rule's floor must be the LAST SLOT of epoch TARGET-2"
            );
        }

        // ── The anti-partition property, and the mutation that must kill it ─

        /// Two states share history to the close of `E-2`, then diverge
        /// through the whole of `E-1` — one chain produces every slot, the
        /// other withholds three. They must still partition `E` identically,
        /// or every cross-branch attestation is `NotInCommittee` and fork
        /// choice can never weigh the two branches against each other.
        ///
        /// **This test is run BOTH WAYS in one execution**, which is the only
        /// form of mutation evidence that survives being read by a third
        /// party: with the shipped look-ahead the seeds must MATCH, and with
        /// the look-ahead reverted to zero on this thread
        /// (`params::rehearsal::with_lookahead_zero`) they must DIFFER. A
        /// green run therefore proves both that the rule holds and that the
        /// test can tell when it does not. If the mutated half ever starts
        /// matching, this test fails and says so — it cannot rot into a
        /// tautology.
        #[test]
        fn nothing_in_the_previous_epoch_can_move_an_epochs_seed() {
        // The rules under test ship INERT behind their flag days; open them for
        // this thread so this is not dead code. See params::rehearsal.
        let _gates = crate::params::rehearsal::gates_open_guard();
            const E: u64 = 4;
            let head_slot = E * SLOTS_PER_EPOCH;
            // Withheld slots, all inside E-1 (epoch 3 = slots 96..=127).
            let withheld = [101u64, 109, 118];
            for w in withheld {
                assert_eq!(crate::epoch_of(w), E - 1, "the divergence must live in E-1");
            }

            let ca = chain(8, head_slot, &[]);
            let cb = chain(8, head_slot, &withheld);
            let a = &ca.states[head_slot as usize];
            let b = &cb.states[head_slot as usize];
            assert_eq!(a.epoch, E);
            assert_eq!(b.epoch, E);

            // Control 1 — the history really is shared to the close of E-2.
            assert_eq!(
                a.boundary_mixes.get(&(E - 2)),
                b.boundary_mixes.get(&(E - 2)),
                "control: the two branches must agree on the close of E-2, or they never shared \
                 the history this property is about"
            );
            // Control 2 — E-1 really did diverge. Without this the property
            // is satisfied by two identical chains, which is no test at all.
            assert_ne!(
                a.boundary_mixes.get(&(E - 1)),
                b.boundary_mixes.get(&(E - 1)),
                "control: withholding three slots of E-1 must move the close of E-1, or the \
                 property below is vacuous"
            );
            assert_ne!(
                a.head.as_bytes(),
                b.head.as_bytes(),
                "control: the two branches must be different chains"
            );

            // THE PROPERTY, through the shipped reader.
            let seed_a = a.seed_for_epoch(E);
            let seed_b = b.seed_for_epoch(E);
            eprintln!(
                "SEED-IMMUNITY epoch {E}: close(E-2) {} == {} ; close(E-1) {} != {} ; \
                 seed(E) {} vs {}",
                hex8(a.boundary_mixes.get(&(E - 2)).unwrap()),
                hex8(b.boundary_mixes.get(&(E - 2)).unwrap()),
                hex8(a.boundary_mixes.get(&(E - 1)).unwrap()),
                hex8(b.boundary_mixes.get(&(E - 1)).unwrap()),
                hex8(&seed_a),
                hex8(&seed_b),
            );
            assert_eq!(
                seed_a, seed_b,
                "SEED-IMMUNITY: two chains sharing history to the close of epoch {} must derive \
                 the SAME seed for epoch {E}. They do not, so something that happened during \
                 epoch {} moved it — that is the partition.",
                E - 2,
                E - 1,
            );

            // The consequence on the wire: the roster is partitioned
            // identically, slot for slot.
            let roster = a.consensus_roster_at(E);
            assert_eq!(roster, b.consensus_roster_at(E), "control: same roster on both branches");
            let first = E * SLOTS_PER_EPOCH;
            for s in first..first + SLOTS_PER_EPOCH {
                assert_eq!(
                    committees::committee_for_slot(&seed_a, s, &roster),
                    committees::committee_for_slot(&seed_b, s, &roster),
                    "SEED-IMMUNITY: slot {s} of epoch {E} is judged against a different \
                     committee on the two branches"
                );
            }

            // ── THE MUTATION, in-tree and in the same run ───────────────────
            //
            // Revert the look-ahead to zero on this thread and the SAME
            // states must now yield DIFFERENT seeds, because the reader is
            // back to the close of E-1 — the boundary control 2 just proved
            // diverged. A mutation that does not change the outcome is not a
            // mutation, and the test says so in those words.
            let (mut_a, mut_b) = crate::params::rehearsal::with_lookahead_zero(|| {
                (a.seed_for_epoch(E), b.seed_for_epoch(E))
            });
            eprintln!(
                "SEED-IMMUNITY MUTANT (look-ahead 0): seed(E) {} vs {} — must DIFFER",
                hex8(&mut_a),
                hex8(&mut_b)
            );
            assert_ne!(
                mut_a, mut_b,
                "the mutation did not bite: with the look-ahead reverted to zero the reader \
                 must take the close of epoch {}, which the two branches disagree about. If \
                 these still match, the assertion above is not measuring the seed and this \
                 test is worthless.",
                E - 1,
            );
            // And the mutant must actually differ from the shipped answer on
            // at least one branch, or the two rules are indistinguishable
            // here and the fixture is too weak.
            assert!(
                mut_a != seed_a || mut_b != seed_b,
                "the mutant seed equals the shipped seed on both branches: this fixture cannot \
                 tell the two rules apart"
            );
            // The switch must be off again — a leaked mutation would silently
            // corrupt every test that runs after this one on this thread.
            assert_eq!(
                a.seed_for_epoch(E),
                seed_a,
                "with_lookahead_zero leaked: the rule is still mutated after it returned"
            );
        }

        /// Pins the SHIPPED READER against the two candidate boundaries on a
        /// state where they differ, and names which one it took.
        ///
        /// `assert_eq!(MIN_SEED_LOOKAHEAD_EPOCHS, 1)` — which is what
        /// `tests/committee.rs` does — compares a constant with its own
        /// literal and cannot fail for any reason a reader would care about.
        /// This one runs both ways in one execution, like the test above.
        #[test]
        fn the_shipped_reader_takes_the_older_boundary_not_the_newer() {
        // The rules under test ship INERT behind their flag days; open them for
        // this thread so this is not dead code. See params::rehearsal.
        let _gates = crate::params::rehearsal::gates_open_guard();
            let c = chain(8, 4 * SLOTS_PER_EPOCH + 1, &[]);
            let st = &c.states[(4 * SLOTS_PER_EPOCH + 1) as usize];
            assert_eq!(st.epoch, 4);
            let older = *st.boundary_mixes.get(&2).expect("retention holds {E-2, E-1}");
            let newer = *st.boundary_mixes.get(&3).expect("retention holds {E-2, E-1}");
            assert_ne!(older, newer, "control: the two candidates must differ");

            let seed = st.seed_for_epoch(4);
            assert_eq!(
                seed, older,
                "CommittedState::seed_for_epoch must read the close of E-2 (the F6 look-ahead). \
                 It read {}, and the close of E-1 is {} — a reader that took the newer boundary \
                 has reverted the fix.",
                hex8(&seed),
                hex8(&newer),
            );

            // The mutant must take the newer one. If it does not, this test
            // cannot distinguish the two rules and proves nothing.
            let mutant = crate::params::rehearsal::with_lookahead_zero(|| st.seed_for_epoch(4));
            assert_eq!(
                mutant, newer,
                "with the look-ahead reverted the reader must take the close of E-1; it took {}",
                hex8(&mutant)
            );
        }

        // ── What the fix does to the chain itself ──────────────────────────

        /// `seed_for_epoch` feeds `schedule::proposer` as well as the
        /// partition, so a binary with the look-ahead builds a DIFFERENT
        /// chain from the same genesis than one without. This finds the first
        /// slot at which it does.
        ///
        /// Both rules are evaluated on the SAME states, which is the only way
        /// to ask "where do they first disagree" — past that slot the two
        /// binaries are on different chains and nothing is comparable.
        ///
        /// The answer is EPOCH 1, not epoch 2, and the reason is worth
        /// stating because it is easy to get wrong: `seed_epoch(1)` is `None`
        /// under the look-ahead so the fixed rule takes the genesis mix,
        /// while the base rule takes `boundary_mixes[0]` — the close of epoch
        /// 0, which is NOT the genesis mix once epoch 0 has produced a single
        /// block. Only epoch 0 is common ground.
        #[test]
        fn the_two_rules_first_draw_a_different_proposer_at() {
            let last = 4 * SLOTS_PER_EPOCH;
            let c = chain(8, last, &[]);
            let mut first_diff: Option<(u64, u32, u32)> = None;
            let mut per_epoch: BTreeMap<u64, usize> = BTreeMap::new();
            for slot in 1..=last {
                let epoch = crate::epoch_of(slot);
                let ctx = rolled_to(&c.states[(slot - 1) as usize], epoch);
                let roster = ctx.duty_roster();
                let p1 = schedule::proposer(&seed_of_rolled(&ctx, epoch, 1), slot, &roster)
                    .expect("eligible proposer");
                let p0 = schedule::proposer(&seed_of_rolled(&ctx, epoch, 0), slot, &roster)
                    .expect("eligible proposer");
                if p1 != p0 {
                    *per_epoch.entry(epoch).or_insert(0) += 1;
                    if first_diff.is_none() {
                        first_diff = Some((slot, p1, p0));
                    }
                }
            }
            let (slot, p1, p0) = first_diff.expect("the two rules must differ somewhere");
            eprintln!(
                "PROPOSER-DIVERGENCE: first differing slot {slot} (epoch {}), fixed draws {p1}, \
                 base draws {p0}; differing slots per epoch {per_epoch:?}",
                crate::epoch_of(slot)
            );
            assert_eq!(
                per_epoch.get(&0),
                None,
                "epoch 0 must be identical under both rules: seed_epoch(0) is None either way, \
                 so both fall back to the genesis mix"
            );
            assert_eq!(
                crate::epoch_of(slot),
                1,
                "the two rules must first diverge in epoch 1 — epoch 1 is NOT common ground, \
                 because the base rule seeds it from the close of epoch 0 while the look-ahead \
                 seeds it from the genesis mix"
            );
        }
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

/// The consensus half of the untrusted-`header.slot` bound (finding
/// C1-slot-bound).
///
/// `compute_post_state` walks `while st.epoch < block_epoch { st.close_epoch()
/// }`, and `block_epoch` is `epoch_of(header.slot)` over a `u64` that arrived
/// off the wire. These pin the ceiling that stops that walk from being a
/// free denial of service, and — the half that matters more — pin that the
/// ceiling is far enough away that no honest block can reach it.
#[cfg(test)]
mod epoch_advance_bound {
    use super::tests::setup;
    use super::*;
    use crate::header::BlockHeaderV4;
    use crate::params::MAX_EPOCH_ADVANCE;

    /// A header that satisfies every check the transition runs BEFORE the
    /// boundary walk — parent, version, and the three commitments — so the
    /// only thing left that can refuse it is the walk's own ceiling. Nothing
    /// downstream of the walk needs to be right, because nothing downstream
    /// of the walk should ever be reached.
    fn header_at_slot(pre: &CommittedState, slot: u64) -> ProposalEnvelope {
        let fin = pre.finality_view();
        ProposalEnvelope {
            header: BlockHeaderV4 {
                version: BLOCK_VERSION_V4,
                parent: *pre.head.as_bytes(),
                state_root: [0u8; 32],
                body_root: crate::derive::body_root(&[]),
                slot,
                proposer_index: 0,
                randao_reveal: [0u8; 32],
                randao_mix: [0u8; 32],
                justified_root: fin.justified.root,
                finalized_root: fin.finalized.root,
                attestation_root: crate::derive::attestation_root(&[]),
                coherence_root: crate::derive::coherence_binding(
                    &pre.coherence_accumulator_root,
                    &pre.coherence_nullifier_root,
                ),
            },
            proposer_sig: vec![0u8; 8],
        }
    }

    /// **The finding.** `header.slot` is an untrusted `u64`; before the bound,
    /// `u64::MAX` here meant ~5.76e17 `close_epoch` turns — one gossiped
    /// packet, every node judging it frozen for longer than the universe has
    /// run. It must come back as a decision, and it must come back fast.
    ///
    /// Delete the `MAX_EPOCH_ADVANCE` check in `compute_post_state` and this
    /// test does not fail with a wrong error — it never returns at all, which
    /// is precisely the defect.
    #[test]
    fn a_header_naming_the_end_of_time_is_refused_not_walked() {
        let (t, g, _chains) = setup(4);
        let b = header_at_slot(&g, u64::MAX);
        assert_eq!(
            t.compute_post_state(&g, &b, &[], &[]).err(),
            Some(TransitionError::EpochAdvanceTooLarge),
            "an unbounded epoch walk is a free denial of service",
        );
    }

    /// The bound is on the gap to the PARENT, not on the absolute epoch — so
    /// it must fire on the first epoch past the ceiling and not one before.
    /// The pair is what makes this a bound rather than a constant: the second
    /// half proves the rule is not simply refusing everything.
    #[test]
    fn the_ceiling_is_exact_and_the_epoch_below_it_still_transitions() {
        let (t, g, _chains) = setup(4);
        assert_eq!(g.epoch, 0, "the fixture starts at epoch 0");

        // Exactly at the ceiling: this rule must NOT be the one that answers.
        let at = header_at_slot(&g, MAX_EPOCH_ADVANCE * SLOTS_PER_EPOCH);
        assert_ne!(
            t.compute_post_state(&g, &at, &[], &[]).err(),
            Some(TransitionError::EpochAdvanceTooLarge),
            "a gap of exactly MAX_EPOCH_ADVANCE is inside the bound",
        );

        // One epoch past it: this rule, and no other.
        let over = header_at_slot(&g, (MAX_EPOCH_ADVANCE + 1) * SLOTS_PER_EPOCH);
        assert_eq!(
            t.compute_post_state(&g, &over, &[], &[]).err(),
            Some(TransitionError::EpochAdvanceTooLarge),
        );
    }

    /// **Replay safety, as an assertion rather than a paragraph.** The bound
    /// may not be adopted quietly unless it is unreachable by honest history,
    /// and honest history's gaps are inter-block gaps of a few epochs. Pinning
    /// the headroom here means anyone who later lowers the constant toward the
    /// real world has to argue with a test instead of with a comment.
    #[test]
    fn the_bound_sits_orders_of_magnitude_above_any_gap_this_chain_has_made() {
        // ~200 slots was the worst vão measured through the 2026-08/09 stalls.
        let worst_observed_gap_epochs = 200 / SLOTS_PER_EPOCH + 1;
        assert!(
            MAX_EPOCH_ADVANCE >= worst_observed_gap_epochs * 100,
            "MAX_EPOCH_ADVANCE ({MAX_EPOCH_ADVANCE}) must keep two orders of magnitude over \
             the worst gap this chain has produced ({worst_observed_gap_epochs} epochs), or a \
             stall stops being a delay and becomes a hard fork",
        );
        // And it must still be a bound: anything near u64::MAX is not one.
        assert!(MAX_EPOCH_ADVANCE < 1 << 20, "a ceiling that large is not a ceiling");
    }
}
