// SPDX-License-Identifier: AGPL-3.0-or-later

//! Consensus constants for the committee layer.
//!
//! Values come from §5.1 and §6.5.2 of the migration design, which in turn come
//! from the measured in-circuit cost of the hybrid signature
//! (`spikes/prover-cost/RESULTS.md`): 7,274,849 RV32IM instructions per
//! ML-DSA-65 ‖ Falcon-1024 verification, and a 4,589-byte signature.
//!
//! Nothing here is active. There is no activation height in this crate because
//! the crate is not wired into the node; when it is, activation follows the
//! height-gated flag-day idiom used by `STATE_ROOT_ACTIVATION_HEIGHT`.

/// Full committee, voting once at each epoch boundary for justification and
/// finality. At 4,589 B per signature this is ≈ 588 KB in the epoch-boundary
/// block and ≈ 19.3 GB/year.
pub const COMMITTEE_SIZE: usize = 128;

/// Per-slot sample, voting only to give LMD-GHOST its fork-choice weight.
///
/// Why this exists at all: epoch-only voting would leave no attestation weight
/// between epoch boundaries, so intra-epoch ordering would rest on slot number
/// and the proposer signature alone, and short reorgs would be cheap. Ethereum
/// avoids this by slicing the validator set into one committee per slot; the
/// measured cost of a 4.6 KB signature makes that too expensive here, so the
/// design keeps a small sample instead.
pub const SLOT_SUBCOMMITTEE_SIZE: usize = 8;

/// Slots per epoch (§5.1).
pub const SLOTS_PER_EPOCH: u64 = 32;

/// Seconds per slot (§5.1) — identical to today's PoW block target, so the
/// transition adds no new propagation pressure.
pub const SLOT_DURATION_SECS: u64 = 30;

/// Upper bound on weighted draws before the deterministic fallback in
/// [`crate::sample::sample`] fills the remaining seats in index order.
///
/// Reached only when stake is so concentrated that rejection keeps hitting the
/// same few validators — which is exactly the distribution the G1–G4 gates
/// exist to prevent from ever reaching mainnet.
pub const MAX_DRAWS_PER_SLOT: usize = 4096;

/// Length of the RANDAO hash chain committed at registration (§6.3, Appendix
/// A). A validator's commitment supports exactly this many reveals — one per
/// slot it actually proposes — before a re-commit transaction is required.
///
/// At one reveal per proposed slot, 8,192 reveals is years of proposing for
/// any validator in a set of realistic size, so re-commits are rare; but the
/// exhaustion path must still exist and be enforced, because a chain that
/// silently accepted reveal 8,193 would be accepting a value with no
/// registered commitment behind it.
pub const RANDAO_CHAIN_LENGTH: u32 = 8_192;
/// Epochs of non-finality tolerated before the inactivity leak switches on
/// (§5.1: "quadratic after 4 epochs of non-finality"). Below this, a stall is
/// treated as transient — leaking on every hiccup would punish ordinary
/// network jitter; above it, the set is presumed partitioned or abandoned and
/// liveness is bought back by shrinking the absent stake.
pub const INACTIVITY_LEAK_THRESHOLD_EPOCHS: u64 = 4;

/// Divisor of the per-epoch inactivity bite: an absent validator loses
/// `stake * t / QUOTIENT` in the t-th epoch beyond the threshold, so the
/// cumulative loss grows quadratically. 64 is sized for recovery in tens of
/// epochs (≈ hours at 16 min/epoch), not days: with a 40%-absent set, the
/// live 60% regains a 2/3 supermajority after ~6 leak epochs. Like every
/// §5.1 value this is a Phase-1 proposal needing a KAT and a devnet sweep.
pub const INACTIVITY_LEAK_QUOTIENT: u128 = 64;

/// Flag-day epoch at which the inactivity leak starts reaching the **duty
/// roster**, and not only the quorum denominator.
///
/// `u64::MAX` means INERT: every node ships the code and none of it changes a
/// single committee or proposer draw until this constant is lowered and the
/// fleet is rebuilt together. Same idiom as `STATE_ROOT_ACTIVATION_HEIGHT` —
/// a consensus rule arrives by flag day, never by whoever restarts first.
///
/// # The defect this closes
///
/// The chain carried two disagreeing stake views. `finality::process_epoch`
/// subtracts each validator's accrued leak before it measures the quorum, so
/// the denominator shrinks to the set that is actually voting and finality
/// heals itself. `CommittedState::duty_roster_at` never subtracted it — and
/// the proposer draw (`schedule::proposer` → `sample`, weighted by
/// `effective_stake`) and the committee partition (`committees::
/// epoch_committees`, which admits every validator with `effective_stake > 0`)
/// both read *that* roster. A validator the finality layer had already written
/// off kept winning proposer draws and kept holding committee seats.
///
/// The asymmetry is the whole bug: **finality recovers on its own and block
/// production never does.** Nothing feeds the leak back into the schedule, so
/// a slot drawn for an absent validator stays empty for as long as the chain
/// runs.
///
/// Measured on Genesis-4 mainnet, 2026-08-21: seven live validators held
/// 6.19% of unleaked stake; blocks arrived every 19.2 slots against the 16.2
/// that `1 / 0.0619` predicts — ~94% of slots drawn for validators that
/// counted for nothing and produced nothing. `SLOT_DURATION_SECS` is 30, so
/// the chain ran at roughly ten minutes a block while finalising every epoch.
///
/// # Choosing the epoch
///
/// Proposer selection and committee membership both change the moment this
/// binds, so a node still on the old value computes a different schedule and
/// forks. Set it far enough ahead that every validator is rebuilt first, and
/// treat "the fleet is on the new binary" as a precondition, not a hope.
pub const LEAKED_ROSTER_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag-day epoch at which the deduplicated transfer format (`TransferV2`,
/// wire tag `0x06`) becomes acceptable in blocks.
///
/// **ARMED at epoch 800, and epoch 800 is behind the chain** (mainnet was in
/// epoch 815 on 2026-08-21). The paragraph that used to stand here said
/// "`u64::MAX` means INERT" and described a gate that had already fired — the
/// doc was written for the disarmed value and never revisited when the value
/// changed, which is precisely the drift `HISTORICAL_FLAG_DAYS`' tripwire now
/// refuses. A node built from this source applies the V2 rules from its next
/// block; a node still on a pre-arming binary rejects those bodies as
/// `UnknownTag(0x06)`. That is a live partition risk for as long as any
/// unrebuilt node remains, not a future one. Same idiom as
/// `LEAKED_ROSTER_ACTIVATION_EPOCH` — a consensus rule arrives by flag day,
/// never by whoever restarts first. The V1 format (tag `0x01`) stays valid
/// forever; this gate only *adds* an encoding, it retires nothing.
///
/// # The defect this closes
///
/// A V1 transfer carries one full witness per input: txid 32 + vout 4 +
/// pubkey 3,749 + signature 4,775 = 8,560 B, so `MAX_BLOCK_TX_BYTES`
/// (262,144) fits ~30 inputs per block. A consolidation's inputs are almost
/// always one owner's, and there is ONE signing root per transfer
/// ([`crate::transition::PosTransaction::spend_signing_root`]) — so those 30
/// witnesses are 30 copies of the same key carrying 30 proofs of the same
/// statement, 30 hybrid verifications (145 µs each, measured 2026-08-21) to
/// establish what one establishes. V2 carries a witness table with one
/// (pubkey, signature) entry per owner and 40-byte inputs (txid + vout +
/// key_index): a 30-input single-owner consolidation drops from ~256,800 B
/// to ~9,700 B, ~6,300 inputs fit in a block, and verification is one hybrid
/// check per owner. That matters because the dominant per-block cost is the
/// state root, LINEAR in the UTXO set size (51 s cold / 0.59 s warm over
/// today's 452,726-entry carryover) — consolidation is how the set shrinks,
/// and this format is what makes consolidation cheap.
///
/// # Why a mixed fleet agrees before the flag day
///
/// A pre-activation block carrying `0x06` is rejected by BOTH binaries, for
/// different proximate reasons and the same verdict: the old binary fails to
/// decode the body (`TxDecodeError::UnknownTag(0x06)`), the new one decodes
/// it and refuses it at the gate
/// ([`crate::interfaces::TransferReject::FormatNotActive`]). Either way the
/// block is invalid everywhere, so no honest proposer produces one and no
/// fork opens. AFTER activation the two binaries diverge — the old one still
/// rejects what the new one accepts — so "the fleet is on the new binary" is
/// a precondition of lowering this, not a hope. The gate reads the COMMITTED
/// epoch (`CommittedState::epoch`, already rolled to the block's epoch),
/// never node-local state — the 2026-08-08 `expected_bits` fork is the
/// standing reason.
pub const TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH: u64 = 800;

/// Flag day for the 512 KiB block payload cap
/// ([`crate::fee_market::MAX_BLOCK_TX_BYTES_V2`]).
///
/// From this epoch a block may carry 524,288 payload bytes instead of
/// 262,144, and the EIP-1559 byte target moves with it — the two are one
/// switch, never two. Splitting them would price a half-full block as
/// congested: the controller reads utilisation as `tx_bytes / target`, so a
/// doubled cap over an undoubled target makes 300 KiB — well under the new
/// cap — read as 2.3x over target and push the base fee up on a block that is
/// not scarce at all.
///
/// **ARMED at epoch 800**, paired with the constant above (pinned by
/// `transfer_v2_activation_is_paired_with_the_block_cap`) and, like it, behind
/// the chain — the "u64::MAX until the founder sets it" this paragraph used to
/// open with described the disarmed value and outlived it. Below the flag day
/// every node computes the old cap and the old target, so a mixed fleet
/// reaches one verdict on every block; at and above it they diverge on both,
/// so **the fleet must be rebuilt before this constant is ever lowered**. Same idiom as
/// [`LEAKED_ROSTER_ACTIVATION_EPOCH`], and the gate reads the epoch derived
/// from the block's own header slot — never node-local state, which is what
/// the 2026-08-08 `expected_bits` fork cost us.
pub const BLOCK_BYTES_V2_ACTIVATION_EPOCH: u64 = 800;
/// Flag-day epoch at which staking becomes **funded from the eUTXO set**:
/// deposits spend real outputs, exits are signed, and a withdrawal returns
/// the bond as a spendable output.
///
/// `u64::MAX` means INERT: every node ships this constant and nothing reads
/// it into a consensus rule until it is lowered and the fleet is rebuilt
/// together — the same idiom as [`LEAKED_ROSTER_ACTIVATION_EPOCH`] directly
/// above, and for the same reason: the change it gates alters what a block
/// may carry, so a node on the old value forks at the gate, not before it.
///
/// # The defect this gate closes
///
/// The chain holds two pools of value that never touch. `PosTransaction::
/// Deposit` and `Delegate` name an `amount_sat` and spend no output — Deposit
/// does not even carry a signature — and `Exit` plus the withdrawal delay
/// return no output, so bonded stake is created without destroying spendable
/// coins and can never become spendable coins again (the `eutxos` field docs
/// in `transition.rs` state the gap in full: "Bonding is not funded from this
/// set"). What stands between the live chain and a free 25,000-BLOCH bond
/// today is `admissible()` in `bloch-pos-node/src/engine.rs` — a MEMPOOL
/// refusal, explicitly "a node-side refusal, not a consensus rule: a block
/// that already carries a deposit still applies it". A proposer running
/// modified software can mint stake from nothing and every unmodified node
/// will accept the block. The validator set is currently protected by
/// operator agreement; this flag day replaces that agreement with a rule.
///
/// # What binds at the gate
///
/// From the first epoch `>=` this constant:
///
/// - funded staking messages (deposit variants that consume eUTXO inputs
///   under the transfer path's equality conservation, a signed exit, and a
///   withdrawal that pays the registered credential) become consensus-valid;
/// - the legacy unfunded `Deposit` / `Delegate` / `Exit` discriminants become
///   consensus-INVALID in block bodies — and it is that refusal, not the
///   mempool's, that closes the modified-proposer path;
/// - the 64 genesis registrations are grandfathered where they stand: the
///   state root is bit-identical across the gate slot itself, so nothing
///   changes outside the gate (rule 2).
///
/// # Why the wire change is not shipped next to this constant yet
///
/// The mainnet manifest bonds 25,000 BLOCH for each of its 64 validators —
/// 1,600,000 BLOCH of principal that `Manifest::genesis_issued_sat()`
/// (`bloch-pos-node/src/genesis.rs`) never counted: genesis issuance is
/// carryover plus allocations only, and `CommittedState::genesis` seeds the
/// registry bonds with no eUTXO counterpart and no `issued_sat` contribution.
/// All 64 withdrawal credentials are one address — the founder's carried
/// H160, zero-padded to 32 bytes (pinned by test against the published
/// manifest). Whether that principal is (1) recognised as retroactive
/// emission (`issued_sat += 160e12` once, at the first boundary past the
/// gate, shrinking future emission by 0.0037%), (2) re-backed by burning an
/// equal amount of the founder's liquid coins, or (3) written off so a
/// genesis withdrawal returns only the post-genesis accrual, is an economic
/// decision that belongs to the founder. Shipping withdrawal code before that
/// decision is made would hard-code one of the three by accident — so the
/// gate is reserved here, inert, and the wire shapes follow the decision.
/// (The post-genesis accrual itself is clean either way: epoch emission
/// advances `issued_sat` when it credits a bond, and fee rewards are backed
/// by coins the transfer path already destroyed.)
///
/// # Choosing the epoch
///
/// New discriminants change block-body decoding, so a node on the old binary
/// rejects the first post-gate block as a decode error rather than a rule.
/// Same precondition as the constant above: every validator rebuilt first,
/// "the fleet is on the new binary" as a fact, not a hope.
///
/// # An epoch already behind the chain does NOT brick the fleet
///
/// Written here because the opposite was believed, and believing it makes the
/// mistake easy: "a gate in the past just fails to fire, so the failure
/// direction is a stopped fleet" reads as safe, and would have been recorded
/// next to this constant as the reason a short rebuild window is tolerable. It
/// is not what the code does. There is no boot-time check anywhere in this
/// crate that a flag day is still ahead of the chain; every gate is a plain
/// `epoch < FLAG_DAY` against the block being judged. Set below the chain's
/// current epoch, this gate is simply LIVE on the next block, silently, on
/// rebuilt nodes only.
///
/// For this constant specifically, the write-off line the founder picks
/// decides the size of the damage, and both directions are unsafe:
///
/// - a materialisation keyed to CROSSING the boundary (`closing < gate &&
///   next >= gate`) never crosses a gate already behind the chain, so the map
///   of unbacked principal stays empty and a genesis withdrawal pays the full
///   registered bond — 25,000 BLOCH x 64 = **1,600,000 BLOCH** that
///   `Manifest::genesis_issued_sat()` never counted as issued;
/// - a rule keyed to "deposited at or after the gate" retroactively
///   reclassifies deposits that already happened as funded, making legacy
///   bonds withdrawable.
///
/// So the number that matters when arming this is not "how long before the
/// fleet bricks" — nothing bricks — but **how many epochs the fleet has to
/// finish rebuilding before the chain reaches the epoch**, and an epoch
/// already behind the chain has zero. `HISTORICAL_FLAG_DAYS` and the tripwire
/// test beside it are what make arming this a deliberate act rather than a
/// one-character edit; see their docs for the per-gate consequences.
pub const FUNDED_STAKE_ACTIVATION_EPOCH: u64 = u64::MAX;

// ── The flag-day seam ───────────────────────────────────────────────────────

/// Every flag-day epoch this crate gates a consensus rule on, in one value.
///
/// # Why this type exists at all
///
/// The four constants above are what mainnet runs. This struct is what TESTS
/// run, and the difference is the whole point.
///
/// A gate is a comparison, `epoch < FLAG_DAY`. Two things decide its verdict:
/// the flag day, and **where the epoch came from**. The second is the one that
/// forks chains — reading it from a machine clock, a config file, or any other
/// node-local source is the 2026-08-08 `expected_bits` defect exactly, where
/// nodes running byte-identical binaries disagreed because the rule was
/// derived from mutable local state instead of from the block under judgement.
/// So every gate in this crate must read the epoch of the BLOCK BEING JUDGED,
/// and something must be able to catch it if one stops.
///
/// Nothing could, for the gates shipped at `u64::MAX`. A test can only observe
/// where a comparison read its left operand if the comparison's answer can
/// CHANGE with that operand — and `x < u64::MAX` is true for every `x` a
/// `u64` can hold, so a disarmed gate returns the same verdict whether it read
/// the block's epoch, the wall clock, or a random number. Measured on this
/// branch, 2026-08-22: replacing `epoch` with a wall-clock epoch inside
/// `CommittedState::consensus_roster_at` — the `LEAKED_ROSTER_ACTIVATION_EPOCH`
/// gate, shipped disarmed — leaves the crate at **393 passing, 0 failing**.
/// The same substitution at the `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` gate,
/// which is ARMED at 800, kills two tests immediately. Same rule, same code
/// shape, same discipline in the comments; the armed one is protected and the
/// disarmed one is not, and nothing about the source distinguishes them.
///
/// **A rule that survives its own deactivation is not protected.** This type
/// is how a disarmed gate gets tested anyway: the consensus path takes its
/// flag days as a VALUE rather than reading the constants, production passes
/// [`FlagDays::MAINNET`] and nothing else does, and a test passes a flag day
/// in the middle of a range it can put the state on both sides of.
///
/// # The test convention this type is useless without
///
/// A seam alone does not kill the mutation — it only makes killing it
/// possible. A test that threads a flag day of `0` or `u64::MAX` through this
/// struct is exactly as blind as one that read the constant, because both
/// comparisons are constant-valued again. The convention, and
/// `gate_source_probe` below is its worked example:
///
/// 1. pick a flag day in the MIDDLE of the representable range — never `0`,
///    never `u64::MAX`, and never a value the wall clock could plausibly
///    equal (a wall-clock epoch at 30 s slots and 32 slots/epoch is ~1.86e6
///    today and rises; the tests here use values under 100);
/// 2. exercise the state at `GATE - 1` and at `GATE`, and assert the verdicts
///    DIFFER. The negative half without the control half proves nothing: a
///    gate that refuses everything passes the negative half.
///
/// Then, and only then, substituting any other epoch source for the block's
/// own flips one of the two halves.
///
/// # The fields are private, and that is the enforcement
///
/// "Production passes `MAINNET` and nothing else" is the entire safety
/// argument for adding a parameter to a consensus function, and a comment
/// saying so is not an argument — mutating the production call site to pass
/// `FlagDays { leaked_roster: 900, ..MAINNET }` compiled and passed the whole
/// suite when these fields were public (MUT-14, 2026-08-22). It had to: any
/// flag day past the epochs a test fixture can reach behaves exactly like
/// `u64::MAX`, so no behavioural test can distinguish one wrong future epoch
/// from the disarmed value. The defence cannot be a test; it has to be the
/// type. With the fields private to this module and the only constructors
/// being [`FlagDays::MAINNET`] and a `#[cfg(test)]` builder, a non-test caller
/// has no way to name any other value, and that mutation stops compiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagDays {
    /// See [`TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`].
    transfer_witness_dedup: u64,
    /// See [`BLOCK_BYTES_V2_ACTIVATION_EPOCH`].
    block_bytes_v2: u64,
    /// See [`LEAKED_ROSTER_ACTIVATION_EPOCH`].
    leaked_roster: u64,
    /// See [`FUNDED_STAKE_ACTIVATION_EPOCH`].
    funded_stake: u64,
}

impl FlagDays {
    /// The flag days mainnet runs, and — outside `#[cfg(test)]` — the only
    /// `FlagDays` any caller can name. Every public entry point in
    /// `transition` passes this and nothing else, so the `_gated` forms are a
    /// test seam and never a second configuration surface. A node that could
    /// be handed a different `FlagDays` at runtime would have re-created, in a
    /// nicer type, the very thing this seam exists to make impossible: a
    /// consensus rule that depends on something other than the block.
    pub const MAINNET: FlagDays = FlagDays {
        transfer_witness_dedup: TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
        block_bytes_v2: BLOCK_BYTES_V2_ACTIVATION_EPOCH,
        leaked_roster: LEAKED_ROSTER_ACTIVATION_EPOCH,
        funded_stake: FUNDED_STAKE_ACTIVATION_EPOCH,
    };

    /// The four flag days as a list, for the invariants that must hold of
    /// every one of them without naming any.
    pub const fn all(&self) -> [u64; 4] {
        [self.transfer_witness_dedup, self.block_bytes_v2, self.leaked_roster, self.funded_stake]
    }

    /// See [`TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`].
    pub const fn transfer_witness_dedup(&self) -> u64 {
        self.transfer_witness_dedup
    }
    /// See [`BLOCK_BYTES_V2_ACTIVATION_EPOCH`].
    pub const fn block_bytes_v2(&self) -> u64 {
        self.block_bytes_v2
    }
    /// See [`LEAKED_ROSTER_ACTIVATION_EPOCH`].
    pub const fn leaked_roster(&self) -> u64 {
        self.leaked_roster
    }
    /// See [`FUNDED_STAKE_ACTIVATION_EPOCH`].
    pub const fn funded_stake(&self) -> u64 {
        self.funded_stake
    }

    /// `MAINNET` with the transfer-format flag day and the block-byte flag day
    /// both moved to `gate`.
    ///
    /// The two move together because consensus requires it
    /// (`transfer_v2_activation_is_paired_with_the_block_cap`): a fixture that
    /// armed one and not the other would exercise a state mainnet cannot be
    /// in — a 512 KiB cap priced against a 128 KiB target, or the reverse.
    #[cfg(test)]
    pub(crate) const fn with_transfer_pair(gate: u64) -> FlagDays {
        FlagDays { transfer_witness_dedup: gate, block_bytes_v2: gate, ..FlagDays::MAINNET }
    }

    /// `MAINNET` with the leak flag day moved to `gate`.
    #[cfg(test)]
    pub(crate) const fn with_leaked_roster(gate: u64) -> FlagDays {
        FlagDays { leaked_roster: gate, ..FlagDays::MAINNET }
    }
}

/// Flag days that mainnet has ALREADY CROSSED, frozen as history.
///
/// `armed_flag_days_are_disarmed_or_deliberate` refuses any armed flag day
/// that is not in this list. Arming a new one therefore costs a deliberate
/// edit here, next to the rule below, instead of a one-character change to a
/// constant that nothing checks.
///
/// # A FLAG DAY IN THE PAST DOES NOT BRICK THE FLEET. IT CHANGES CONSENSUS RETROACTIVELY.
///
/// This is written out because the opposite was believed, and the opposite is
/// the dangerous belief: "a gate already in the past just fails to activate,
/// so the worst case is a stopped fleet" reads as a safe direction and would
/// have been recorded here as one. It is not the behaviour. Every gate in this
/// crate is a plain `epoch < FLAG_DAY` comparison against the epoch of the
/// block being judged, with no boot-time check that the epoch has not already
/// passed. Ship a flag day below the chain's current epoch and the new rule is
/// live on the NEXT block, with no boundary crossing, no announcement and no
/// error — while every node still on the old binary applies the old rule to
/// the same block. That is a silent partition, not a halt, and the direction
/// of the damage depends entirely on which rule was gated:
///
/// - `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` in the past: `0x06` bodies
///   become valid immediately on rebuilt nodes and stay `UnknownTag(0x06)`
///   decode failures on the rest. The two halves of the fleet disagree about
///   whether a block exists.
/// - `BLOCK_BYTES_V2_ACTIVATION_EPOCH` in the past: rebuilt nodes accept
///   512 KiB blocks the rest reject, and both halves also price every block
///   differently, because the byte target moves with the cap.
/// - `LEAKED_ROSTER_ACTIVATION_EPOCH` in the past: proposer draw and committee
///   partition change for the same seed, so the two halves disagree about who
///   was even allowed to propose. This is the worst of the four: it forks
///   without any transaction having to be unusual.
/// - `FUNDED_STAKE_ACTIVATION_EPOCH` in the past: whatever the funded-staking
///   line ends up materialising at the gate crossing is materialised late or
///   not at all, and any rule keyed to "deposited after the gate" retroactively
///   reclassifies deposits that already happened. Sized on the fs-writeoff line
///   at 25,000 BLOCH x 64 genesis bonds = **1,600,000 BLOCH** paid out against
///   principal that `Manifest::genesis_issued_sat()` never counted as issued.
///
/// The window that matters is therefore not "how long until the fleet bricks"
/// — nothing bricks — but **how long the fleet has to finish rebuilding before
/// the chain reaches the epoch**, and a flag day already behind the chain has
/// a window of zero.
pub const HISTORICAL_FLAG_DAYS: [u64; 1] = [800];

/// Domain separation tags (§6.1). Fixed 16 bytes, right-padded with zeros, so
/// no tag can be a prefix of another.
pub const DS_SORTITION: [u8; 16] = *b"BLCH4:SORTIT\0\0\0\0";
/// Attestation signing root domain.
pub const DS_ATTEST: [u8; 16] = *b"BLCH4:ATTEST\0\0\0\0";
/// Block identity (§5.4). The one and only block identifier is
/// `SHA3-256(DS_BLOCK ‖ canonical header)` — the tag is what guarantees a block
/// id can never collide with any other domain's digest of the same bytes.
pub const DS_BLOCK: [u8; 16] = *b"BLCH4:BLOCK\0\0\0\0\0";
/// Transaction Merkle tree (`body_root`).
pub const DS_BODY: [u8; 16] = *b"BLCH4:BODY\0\0\0\0\0\0";
/// State SMT nodes (`state_root`).
pub const DS_STATE: [u8; 16] = *b"BLCH4:STATE\0\0\0\0\0";
/// Beacon mixing (§6.3): `mix' = SHA3-256(DS_RANDAO ‖ mix ‖ reveal)`.
pub const DS_RANDAO: [u8; 16] = *b"BLCH4:RANDAO\0\0\0\0";
/// Deposit message signing root (§7.1 proof of possession).
pub const DS_DEPOSIT: [u8; 16] = *b"BLCH4:DEPOSIT\0\0\0";
/// The signing root an eUTXO spend authorisation covers: the domain under
/// which an output's owner authorises *this* transfer and no other.
///
/// Its own tag, and not `DS_BODY` or `DS_TXID`, for the reason every tag in
/// this table exists: a spend authorisation must not be replayable as any
/// other signed message, and a digest that identifies a transaction must not
/// double as the digest a key signed. The preimage covers the spend points,
/// the outputs, the declared size and the tip — everything except the
/// witnesses, which cannot be inside a root they are produced over.
pub const DS_SPEND: [u8; 16] = *b"BLCH4:SPEND\0\0\0\0\0";
/// Transaction identity: `txid = SHA3-256(DS_TXID ‖ spend signing root)`.
///
/// Derived from the witness-free signing root, so a transaction's id — and
/// therefore the keys of every output it creates — cannot be changed by
/// anyone re-encoding its signatures. A txid taken over the full encoding
/// would make an unrelated party able to re-key a payment already in flight,
/// which is the malleability class that made Bitcoin's chained-transaction
/// wallets unsafe before segwit.
pub const DS_TXID: [u8; 16] = *b"BLCH4:TXID\0\0\0\0\0\0";
/// Slashing evidence and voluntary-exit signing roots (§7.2, §7.3).
pub const DS_SLASH: [u8; 16] = *b"BLCH4:SLASH\0\0\0\0\0";
/// Proposer signature domain over the header.
///
/// **Not in the §6.1 table** — the spec assigns a tag to block identity but
/// none to the proposer's signature, leaving the signature to cover the same
/// domain-tagged bytes as the id. Signing the id would work, but a signature
/// domain that is also an identifier domain invites exactly the cross-protocol
/// replay games domain separation exists to end, so this crate freezes a
/// distinct tag and the spec table needs the row added (flagged in
/// `BLOCH-POS-INTERFACES.md`).
pub const DS_PROPOSE: [u8; 16] = *b"BLCH4:PROPOSE\0\0\0";
/// Deposit proof-of-possession domain (§6.1, §7.1). A PoP bound to its own
/// domain cannot be replayed as an attestation or a block signature — the tag
/// is what makes a signature mean one thing only.
/// Voluntary-exit signing domain (§7.2). Not in the §6.1 table by name, but
/// the exit is "a hybrid-signed message" and every signed message gets its own
/// tag; all tags are fixed 16 bytes, so no tag can prefix another.
pub const DS_EXIT: [u8; 16] = *b"BLCH4:EXIT\0\0\0\0\0\0";
/// Weak-subjectivity checkpoint digest domain
/// (`BLOCH-WEAK-SUBJECTIVITY.md` §2.1). The checkpoint is signed and verified
/// out of band, at boot — its digest must live in its own domain so a signed
/// checkpoint can never be replayed as any in-protocol message, nor vice versa.
pub const DS_WSCKPT: [u8; 16] = *b"BLCH4:WSCKPT\0\0\0\0";
/// Header `coherence_root` mirror binding (§6.6.2):
/// `coherence_root = SHA3-256(DS_COHERENCE ‖ accumulator_root ‖ nullifier_root)`.
///
/// This tags the header *encoding* of the two Coherence roots, not anything
/// inside the pool: the accumulator itself stays SHAKE-256 under the C1-frozen
/// `bloch:coherence:*:v1` domains (`crates/coherence-core`), untouched by the
/// BLCH4 sweep — §6.6 says the migration brings the rest of the chain to where
/// Coherence already is, and this tag is on the "rest of the chain" side of
/// that line.
pub const DS_COHERENCE: [u8; 16] = *b"BLCH4:COHERE\0\0\0\0";
/// State SMT node domain (§6.1) — every hash in [`crate::state_root`] starts
/// with this tag so a state-tree node can never collide with a block id, a
/// transaction Merkle node, or any other SHA3 use in the protocol.
/// Slashing-evidence identity domain (anti-replay key, §7.3).

/// Role tags, mixed into the sortition seed so the per-slot subcommittee is not
/// a predictable subset of the epoch committee.
pub(crate) const ROLE_SLOT: u8 = 0x01;
pub(crate) const ROLE_EPOCH: u8 = 0x02;

#[cfg(test)]
mod flag_day_tripwire {
    use super::{FlagDays, HISTORICAL_FLAG_DAYS};

    /// THE TRIPWIRE. Every flag day mainnet ships is either disarmed
    /// (`u64::MAX`) or listed in [`HISTORICAL_FLAG_DAYS`] as one the chain has
    /// already crossed.
    ///
    /// Lowering a constant to an epoch — any epoch — now fails the build until
    /// someone also writes that epoch down here, and the doc on
    /// `HISTORICAL_FLAG_DAYS` is what they have to read to do it. That is the
    /// entire mechanism: a flag day cannot be armed by a one-character edit
    /// that no test looks at, which is how `flagday/epoch-800` came to claim
    /// an arming its code never performed.
    ///
    /// It deliberately does NOT assert "the epoch is in the future". Nothing
    /// in this crate knows what epoch the chain is on — that is a fact about a
    /// running network, not about the code — and a test that hard-coded one
    /// would be stale the day after it was written. The floor that a real
    /// arming needs (chain epoch at arming time, plus a fleet-rebuild window
    /// in epochs) is a founder input; see the note in the task log. What this
    /// test buys is that the input is REQUIRED before an arming compiles,
    /// rather than optional after it ships.
    #[test]
    fn armed_flag_days_are_disarmed_or_deliberate() {
        for (i, day) in FlagDays::MAINNET.all().into_iter().enumerate() {
            assert!(
                day == u64::MAX || HISTORICAL_FLAG_DAYS.contains(&day),
                "flag day #{i} is armed at epoch {day}, which is not a crossed flag day. \
                 Arming a gate is a fleet-wide, un-rollback-able act: add {day} to \
                 HISTORICAL_FLAG_DAYS only once the fleet is rebuilt AND the epoch is \
                 ahead of the chain - a flag day already behind the chain does not brick \
                 the fleet, it silently partitions it (see HISTORICAL_FLAG_DAYS docs)."
            );
        }
    }

    /// `MAINNET` is the constants and nothing else. Pinned because the whole
    /// safety argument for the `_gated` seam is "production passes exactly
    /// this value": a `MAINNET` that drifted from the constants would make the
    /// seam a second configuration surface instead of a test hook.
    #[test]
    fn mainnet_flag_days_are_the_shipped_constants() {
        let f = FlagDays::MAINNET;
        assert_eq!(f.transfer_witness_dedup(), super::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH);
        assert_eq!(f.block_bytes_v2(), super::BLOCK_BYTES_V2_ACTIVATION_EPOCH);
        assert_eq!(f.leaked_roster(), super::LEAKED_ROSTER_ACTIVATION_EPOCH);
        assert_eq!(f.funded_stake(), super::FUNDED_STAKE_ACTIVATION_EPOCH);
        assert_eq!(f.all().len(), 4, "a new flag day must join all() or the tripwire skips it");
    }
}
