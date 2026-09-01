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

/// Divisor of the per-epoch **recovery** of the inactivity leak, once finality
/// is healthy again: `leaked -= max(leaked / QUOTIENT, 1)` on every epoch that
/// is *not* leaking. This is the whole answer to "the relaunch inherits a
/// collapsed denominator".
///
/// # Why the accumulator had to become recoverable
///
/// Before this constant, `FinalityState::leaked` had **exactly one write
/// path** — `+= bite` — with no decay, no reset and no removal anywhere in the
/// crate. The quorum denominator subtracts that accumulator, so the
/// denominator shrank monotonically and never came back: once enough stake had
/// leaked, a handful of nodes — one, even — held two thirds of what remained
/// and finalized entirely alone. That is the ratchet behind the 2026-08-24
/// incident, where three nodes finalized epoch 986 under three different roots
/// and no amount of arriving blocks could reunify them.
///
/// # Why it lives HERE and not in a migration
///
/// `CommittedState` has no constructor that reads a database
/// (`transition.rs`, struct docs) and the node's storage is an **append-only
/// block log**: restart means replaying every block through the same
/// `Transition` (`bloch-pos-node/src/store.rs` module docs). So the leak is
/// not a value sitting in storage that an operator can edit before the
/// relaunch — it is re-derived from the block log on every boot. A one-shot
/// storage migration has nothing to migrate, and zeroing "at load" would make
/// a node disagree with its own replay, which is the `expected_bits` defect
/// class this repo has already paid for twice. The only place the accumulator
/// can be changed deterministically on 64 machines is inside the fold, which
/// is where this is.
///
/// # The rate, and the sawtooth it buys
///
/// 16 means a healthy epoch returns 1/16 of the outstanding leak, so the
/// accumulator halves about every 11 epochs and drains completely in a bounded
/// number (the `max(·, 1)` floor guarantees termination). It is deliberately
/// SLOWER than accrual: recovery must not instantly undo the very leak that
/// bought the recovery. It does not remove that tension — a validator set that
/// is permanently short of a supermajority will oscillate between leaking and
/// recovering rather than stalling forever, and the honest fix for stake that
/// is never coming back is EJECTION from the registry, not a perpetual leak.
/// That is a validator-set change and deliberately not in this fold.
pub const INACTIVITY_LEAK_RECOVERY_QUOTIENT: u64 = 16;

/// The quorum denominator may never fall below this fraction of the
/// **unleaked** active stake: `MIN_QUORUM_DENOMINATOR_NUM /
/// MIN_QUORUM_DENOMINATOR_DEN`. One half.
///
/// `process_epoch` already guarded `total_active == 0`. It had no guard for
/// "total_active is small", and small is where the damage is: at 6.25% of the
/// original stake a 4-of-64 partition reaches two thirds of what is left and
/// justifies its own branch (`finality::tests::
/// a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator`
/// measures it: epoch 25, after 92.2% of network stake has leaked).
///
/// # What the floor is worth, exactly
///
/// Write `p` for the present fraction of the ORIGINAL active stake. Once the
/// absent stake has fully leaked, the 2/3 test is `3p ≥ 2·max(p, 1/2)`, which
/// for `p < 1/2` is `3p ≥ 1`, i.e. **`p ≥ 1/3`**. So:
///
/// - a set holding **at least a third** of the original stake can still be
///   rescued by the leak — which is the entire reason the leak exists, and the
///   §5.1 recovery property is unchanged (pinned by
///   `inactivity_leak_recovers_finality`, whose 60/40 stall still recovers on
///   the same epoch it always did);
/// - a set holding **less than a third** can never justify, no matter how long
///   it waits. The 2026-08-24 partitions were 4 of 64.
///
/// # The residual, stated rather than glossed
///
/// A floor of one half admits at most three pairwise-disjoint sets of exactly
/// one third each, so it bounds the divergence from "any handful of nodes" to
/// "at most three ways" — it does not make the justified root unique. Full
/// uniqueness needs a minimum recovering fraction strictly above one half,
/// i.e. a floor above 3/4, at the price of never recovering from an outage of
/// more than half the stake. Which of those two the chain wants is a founder
/// decision about safety versus liveness, not an implementation detail, and
/// it is one constant away.
pub const MIN_QUORUM_DENOMINATOR_NUM: u128 = 1;
/// Denominator of [`MIN_QUORUM_DENOMINATOR_NUM`].
pub const MIN_QUORUM_DENOMINATOR_DEN: u128 = 2;

// The owner's decision on this pair, and the residual he accepted with it, are
// pinned in `tests::the_quorum_floor_is_the_one_the_owner_chose`.

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
/// epoch_committees`) both read *that* roster. A validator the finality layer
/// had already written off kept winning proposer draws and kept holding
/// committee seats.
///
/// **Corrected 2026-08-24, and this is what makes the flag day safe to keep
/// armed.** `epoch_committees` used to admit "every validator with
/// `effective_stake > 0`", and that filter ran *before* the shuffle — so the
/// leaked and unleaked rosters partitioned differently the moment the leak
/// zeroed anybody, and the boundary tally dropped attestations the block had
/// admitted. The filter is gone: committee MEMBERSHIP is now a pure function
/// of (seed, epoch, index set) and stake decides WEIGHT only, so what this
/// flag day changes is the proposer draw and the quorum weights — never the
/// partition. See `committees::epoch_committees`'s docs for the full
/// reasoning.
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
///
/// The choice procedure, the fleet-rollout order, the readiness predicate and
/// the post-activation observables live in `docs/LEAKED-ROSTER-FLAG-DAY.md`.
/// The armed value below was produced by that runbook; the tripwire test in
/// `transition.rs` pins it, so it cannot drift without failing the suite.
///
/// ARMED 2026-08-24 at epoch 1400 — 2026-08-29 10:51:19 UTC. Rehearsed first on
/// a two-node devnet WITH the control the repo's testing rule requires: the
/// armed and inert halves produced an identical 143 blocks before the
/// boundary, neither forked, and only the armed half's slot occupancy moved
/// after it (68.1% -> 72.8%).
///
/// # Where 1400 actually comes from — it is NOT the runbook's formula
///
/// An earlier version of this comment said the armed value "was produced by
/// that runbook". **That was false**, and it is corrected here rather than
/// quietly dropped, because a comment that misstates the provenance of a
/// consensus flag day is the same category of defect this file keeps paying
/// for.
///
/// The runbook's formula is `E = round_up_100(epoch_at_tag + 900)`. Armed at
/// epoch 909, that gives **1900**; the runbook's own worked example gives 1600;
/// the runbook never mentions 1400 anywhere. The armed value is 500 epochs —
/// 5.6 days — below the formula.
///
/// It was chosen deliberately by the integration coordinator, and this is the
/// reasoning that should have been written down beside it at the time. The
/// runbook's 900 decomposes as 270 rollout (12 boxes x ~6 h of replay) + 90
/// soak + 180 decision + ~360 contingency. **The rollout term is obsolete**:
/// with replay down to ~7 minutes, rolling the fleet is about an hour — roughly
/// 4 epochs, not 270. So the real requirement is on the order of 274 epochs and
/// 1400 leaves 491 of margin, close to double.
///
/// **Do not "fix" the constant to match the formula.** Changing it is a flag
/// day across 64 nodes; the margin is sufficient on the argument above. Fix the
/// runbook instead: its rollout term must be derived from measured replay cost,
/// not held fixed at days.
///
/// Note what the tripwire can and cannot do. It compares this constant against
/// a literal `1400` in the test source — a copy of itself. That catches a
/// SILENT change of the epoch. It cannot catch the epoch having been wrong from
/// the start, which is exactly what happened here and why this note exists.
pub const LEAKED_ROSTER_ACTIVATION_EPOCH: u64 = 1400;

/// Flag-day epoch at which the deduplicated transfer format (`TransferV2`,
/// wire tag `0x06`) becomes acceptable in blocks.
///
/// `u64::MAX` means INERT: every node ships the decoder and the apply path
/// and none of it changes what a block may carry until this constant is
/// lowered and the fleet is rebuilt together. Same idiom as
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

/// Flag day for consensus vesting locks — SHIPS INERT (`u64::MAX`), and the
/// decision to arm it is not this constant's to make.
///
/// # What activates
///
/// At the epoch boundary that OPENS this epoch, `close_epoch` runs the
/// one-time seeding ([`crate::vesting`]): each genesis allocation outpoint
/// that is **still unspent** is replaced, in committed state, by tranche
/// outputs whose `unlock_epoch`s follow the tokenomics_v4 vesting curves
/// (founder 2y cliff + 8y linear; team 18m + 36m; VC 12m + 24m; marketing
/// 25% TGE + 24m; liquidity is liquid by design and is not seeded). From
/// that block on, both transfer arms refuse to spend an output before its
/// `unlock_epoch` ([`crate::interfaces::TransferReject::VestingLocked`]).
///
/// # Why this is a fork point (and the enforcement is not)
///
/// The lock field serializes into an entry's leaf only when nonzero
/// (`EutxoEntry::serialize`), so merely shipping this code moves no root and
/// the spend check is vacuously true pre-activation — no entry can carry a
/// nonzero lock before the seeding runs. The SEEDING is the discontinuity:
/// it rewrites outpoints, so the state root at the boundary differs from
/// what an old binary computes. "The fleet is on the new binary" is a
/// precondition of lowering this, exactly as for
/// [`TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`] above.
///
/// # The go/no-go precondition, and its measured answer
///
/// Seeding can only lock what is still there. The runbook precondition
/// (rpc.rs, `TxOut`) is that the allocation outpoints are unspent when the
/// rule arms. **Measured 2026-08-31 against three fleet nodes (consistent
/// head, slot 51,184, epoch 1,599): all five allocation outpoints are
/// already SPENT** — `gettxout` answers `unspent: false` for every one, and
/// the founder script's balance stands at ~37.94B BLOCH against the ~56.05B
/// it opened with. Arming this flag day on the current chain therefore seeds
/// nothing and locks nothing; the honest uses left are (a) a future genesis
/// whose manifest carries real `unlock_epoch`s, and (b) a negotiated
/// re-commitment in which the buckets are first RETURNED to fresh outpoints
/// whose txids are pinned here before arming. Neither is a unilateral code
/// change, which is why the constant ships at `u64::MAX`.
pub const VESTING_LOCK_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for the withdrawal transaction (tag `0x08`,
/// [`crate::transition::PosTransaction::Withdraw`]) — the path that turns an
/// exited validator's bonded stake back into spendable eUTXO coins — and,
/// with it, the two slashing-side rules it depends on:
///
/// - a slash schedules the residue's lock at `slash_epoch +
///   `[`crate::slashing::CORRELATION_WINDOW_EPOCHS`] (4,096) instead of
///   `slash_epoch + `[`crate::staking::WITHDRAWAL_DELAY_EPOCHS`] (2,048), so
///   a proven offender's residue stays reachable for the full window in which
///   correlated offences amplify;
/// - a slashed residue is re-priced at the withdrawal itself: the payout is
///   reduced by the correlation amplification visible in the trailing window
///   at the door (`3 × slashed_share`, the same arithmetic
///   `slashing::penalty_bps` runs at evidence time), and the reduction is
///   burned. See the `Withdraw` arm of `apply_transaction` for the full rule
///   and its stated limits.
///
/// `u64::MAX` until the founder sets it: below this epoch the transaction is
/// INERT — the old binary fails to decode tag `0x08`
/// (`TxDecodeError::UnknownTag`), the new one decodes it and refuses it at
/// the gate, so a pre-activation block carrying one is invalid on BOTH
/// binaries for different proximate reasons and the same verdict, exactly the
/// [`TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`] idiom. The gate reads the
/// COMMITTED epoch (`CommittedState::epoch`, already rolled to the block's
/// epoch), never node-local state — the 2026-08-08 `expected_bits` fork is
/// the standing reason.
///
/// # Preconditions of ever lowering this, in order of severity
///
/// 1. **Deposits must debit the eUTXO set first — PARTLY ANSWERED, and the
///    remaining half is the blocker.** The unfunded `Deposit` (tag `0x02`)
///    that named an `amount_sat` and spent no output is now
///    consensus-rejected at EVERY epoch, and the funded successor
///    (`DepositV2`, tag `0x07`, behind
///    [`FUNDED_STAKING_ACTIVATION_EPOCH`]) destroys real coins into the
///    bond under strict conservation. So the money printer this precondition
///    named — deposit → exit → withdraw while the deposit costs nothing — is
///    closed for NEW bonds. What is NOT closed: the **genesis** bonds, which
///    no transaction ever funded, and reward compounding, which grows bonds
///    the eUTXO set never funded. Withdrawals must not arm until those two
///    are accounted (precondition 2), and arming them BEFORE
///    `FUNDED_STAKING_ACTIVATION_EPOCH` would reopen the printer outright.
/// 2. **The genesis bonds must be accounted inside issued supply.** The
///    withdrawal pays committed bonds out as eUTXO value without touching
///    `issued_sat` (the bond's value is treated as already issued — reward
///    compounding incremented the counter when it entered the bond, and a
///    funded deposit's coins were issued before they were bonded). Whether
///    the launch validators' `staked_sat` was inside `GENESIS_ISSUED_SAT`
///    is a genesis-ceremony fact that must be audited before the first
///    genesis-cohort withdrawal, or the supply-cap invariant tracks a
///    number the spendable set quietly exceeds.
/// 3. **The fleet must be rebuilt before this is lowered** — after
///    activation the old binary still rejects what the new one accepts, so
///    "everyone runs the new binary" is a precondition, not a hope.
pub const WITHDRAWAL_ACTIVATION_EPOCH: u64 = u64::MAX;

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
/// `u64::MAX` until the founder sets it. Below it every node computes the old
/// cap and the old target, so a mixed fleet reaches one verdict on every
/// block; at and above it they diverge on both, so **the fleet must be
/// rebuilt before this constant is ever lowered**. Same idiom as
/// [`LEAKED_ROSTER_ACTIVATION_EPOCH`], and the gate reads the epoch derived
/// from the block's own header slot — never node-local state, which is what
/// the 2026-08-08 `expected_bits` fork cost us.
pub const BLOCK_BYTES_V2_ACTIVATION_EPOCH: u64 = 800;

// ── The F6 seed look-ahead is GATED, not unconditional ─────────────────────
//
// A previous version of this comment declared the look-ahead "UNCONDITIONAL —
// there is no flag day", recording the 2026-08-24 decision to delete
// `ANCESTRY_SEED_ACTIVATION_EPOCH`. That decision was reversed and the gate
// was restored, because the premise ("a coordinated relaunch has no live
// network to split") was wrong: boot is a REPLAY of the block log, and a
// binary running the new rule against a log produced under the old one parks
// silently at epoch 1. The comment outlived the reversal by 230 lines, which
// is exactly the defect class a stale consensus comment is.
//
// The rule as shipped: below [`ANCESTRY_SEED_ACTIVATION_EPOCH`] the seed for
// epoch `E` is the mix at the close of `E − 1` (the original rule, the one
// the existing chain's blocks carry); at and above it, the close of
// `E − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`. The full reasoning — what F6 closes,
// why the retention window already covers `E − 2`, and why the gate exists —
// lives on the constant itself (below) and on
// [`crate::transition::CommittedState::seed_for_epoch`]. The look-ahead in
// force at any epoch is answered by exactly one function,
// [`seed_lookahead_at`], and every production reader must go through it.

/// Test-only rehearsal hook. `cfg(test)`, so it cannot exist in a shipped
/// binary. Flips one bit of every seed, so the deterministic chain comparator
/// can be shown to go red on a planted difference — a comparator that cannot
/// see one is not comparing anything.
#[cfg(test)]
pub mod rehearsal {
    use std::cell::Cell;

    /// A mutation switch that is **thread-local**, wearing the `AtomicBool`
    /// interface so call sites do not have to change.
    ///
    /// Every switch here was a process-global `AtomicBool` guarded by [`HOOK`]
    /// — a mutex the two tests flipping a switch take and the other ~260 tests
    /// in the crate do NOT, while `cargo test` runs them in parallel on
    /// separate threads. A switch read from inside a consensus function
    /// (`epoch_committees`, `with_leak_applied`, `seed_for_epoch`) therefore
    /// mutated the rule under every test running beside it. That produces false
    /// REDS and false GREENS, so a green suite was a property of the thread
    /// scheduler.
    ///
    /// Thread-local makes the leak impossible by construction rather than by
    /// discipline. `MUTATE_SEED` was converted first; this covers the rest,
    /// including `RESTORE_ZERO_STAKE_FILTER` — the switch the ONLY proof of the
    /// roster unification depends on, and therefore the switch the decision to
    /// keep epoch 1400 armed on 64 production nodes rests on.
    pub struct TlFlag(pub &'static std::thread::LocalKey<Cell<bool>>);

    impl TlFlag {
        pub fn store(&self, v: bool, _order: std::sync::atomic::Ordering) {
            self.0.with(|c| c.set(v));
        }
        pub fn load(&self, _order: std::sync::atomic::Ordering) -> bool {
            self.0.with(|c| c.get())
        }
    }

    /// Restores the pre-2026-08-24 `effective_stake > 0` filter that ran
    /// *before* the Fisher-Yates shuffle in `committees::epoch_committees` —
    /// i.e. puts the roster-split defect back, so the tests that pin the fix
    /// can be shown to go red. Read only through
    /// `committees::mutation_restores_zero_stake_filter`.
    thread_local! {
        static RESTORE_ZERO_STAKE_FILTER_TL: Cell<bool> = const { Cell::new(false) };
    }
    /// Thread-local; see [`TlFlag`] for why this is not an `AtomicBool`.
    pub static RESTORE_ZERO_STAKE_FILTER: TlFlag = TlFlag(&RESTORE_ZERO_STAKE_FILTER_TL);

    /// Makes `transition::with_leak_applied` REMOVE a validator whose leak has
    /// eaten its whole stake, instead of keeping it at `effective_stake = 0`.
    ///
    /// This is the defect coming back through the other door. The 2026-08-24
    /// fix removed the `effective_stake > 0` filter from `epoch_committees`, so
    /// membership is a function of (seed, epoch, index set) and the two rosters
    /// partition identically **as long as they carry the same index set**. If
    /// `with_leak_applied` ever drops the zeroed record, `consensus_roster_at`
    /// and `duty_roster_at` stop agreeing on that set, and the split is back —
    /// with the committee-level tests still green, because those build both
    /// rosters as fixtures rather than through the call sites.
    ///
    /// Read only through `transition::mutation_leak_drops_zeroed`.
    thread_local! {
        static LEAK_DROPS_ZEROED_TL: Cell<bool> = const { Cell::new(false) };
    }
    /// Thread-local; see [`TlFlag`] for why this is not an `AtomicBool`.
    pub static LEAK_DROPS_ZEROED: TlFlag = TlFlag(&LEAK_DROPS_ZEROED_TL);

    thread_local! {
        static PARTITION_DUPLICATES_AN_INDEX_TL: Cell<bool> = const { Cell::new(false) };
    }
    /// Makes the Fisher-Yates step in `committees::epoch_committees` do
    /// `eligible[i] = eligible[j]` instead of `eligible.swap(i, j)` —
    /// DUPLICATING one validator index and LOSING another while the list length
    /// stays exactly right.
    ///
    /// It exists to give the epoch-partition `consensus_invariant!` an input
    /// that can actually make it fail. In its pre-2026-08-24 counting form
    /// (seat count vs roster length) this mutation walks straight through: both
    /// sides still reduce to the same number. Comparing sorted index vectors
    /// catches it. Thread-local; see [`TlFlag`].
    pub static PARTITION_DUPLICATES_AN_INDEX: TlFlag = TlFlag(&PARTITION_DUPLICATES_AN_INDEX_TL);

    thread_local! {
        static GATES_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::ANCESTRY_SEED_ACTIVATION_EPOCH`],
    /// [`super::LEAK_RECOVERY_ACTIVATION_EPOCH`] and
    /// [`super::WITHDRAWAL_ACTIVATION_EPOCH`] as if they had already bound.
    ///
    /// The two flag days ship INERT (`u64::MAX`), which is correct — the fleet
    /// must replay its existing log under the OLD rules — but it means no epoch
    /// a test can construct ever reaches them. Without this, every test of the
    /// post-flag-day behaviour would be dead code, and the only tests left
    /// would be the ones asserting inertness. Both sides need cover.
    ///
    /// Default is CLOSED, deliberately: an unadorned `cargo test` exercises the
    /// configuration the fleet actually runs. Tests of the new rules opt in.
    pub fn gates_are_forced_open() -> bool {
        GATES_OPEN_TL.with(|c| c.get())
    }

    /// Opens both gates for this thread until the returned guard drops —
    /// including on the unwind path, so a failing assertion cannot leave the
    /// rules mutated for the rest of the thread.
    #[cfg(test)]
    pub fn gates_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                GATES_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = GATES_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static ARMED_AT_TL: Cell<Option<u64>> = const { Cell::new(None) };
    }

    /// Test-only: the epoch both gates behave as ARMED AT on this thread, if a
    /// test has set one. `None` in every other circumstance, including all
    /// shipped builds — the production gate readers consult this only under
    /// `cfg(test)`.
    ///
    /// This exists because [`gates_are_forced_open`] can only model the two
    /// endpoints — gate closed everywhere (`u64::MAX`) or open everywhere
    /// (epoch 0) — and neither endpoint contains the flag day itself. The
    /// property the live chain's safety rests on is the SEAM: a binary armed
    /// at epoch `A` must be bit-identical to the inert one for every epoch
    /// below `A`, and must apply the new rule from `A` exactly. Without a way
    /// to place `A` inside a test's reachable range, that property is dead
    /// code until it fires on mainnet — which is the one place it must never
    /// fire first.
    pub fn armed_activation_epoch() -> Option<u64> {
        ARMED_AT_TL.with(Cell::get)
    }

    /// Arms both gates at `epoch` for this thread until the returned guard
    /// drops — including on the unwind path, so a failing assertion cannot
    /// leave the gates armed for the rest of the thread.
    ///
    /// Precedence: [`gates_open_guard`] (open everywhere) wins over this if
    /// both are set, mirroring the reader in [`super::ancestry_seed_gate_epoch`].
    #[cfg(test)]
    pub fn gates_armed_at_guard(epoch: u64) -> impl Drop {
        struct Restore(Option<u64>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ARMED_AT_TL.with(|c| c.set(self.0));
            }
        }
        let prev = ARMED_AT_TL.with(|c| c.replace(Some(epoch)));
        Restore(prev)
    }

    thread_local! {
        static DEPOSIT_FUNDING_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::FUNDED_STAKING_ACTIVATION_EPOCH`] as if it
    /// had already bound for the funded `DepositV2` arm (tag `0x07`). The
    /// legacy unfunded `Deposit` is consensus-rejected at EVERY epoch and no
    /// longer waits for this gate — the guard opens only the successor.
    ///
    /// Its own flag, NOT folded into [`gates_are_forced_open`]: that guard
    /// documents itself as covering the seed and leak-recovery gates, and the
    /// tests that open it exercise finality arithmetic that has nothing to do
    /// with deposits — one shared switch would silently retire the unfunded
    /// deposit under every one of them, reddening (or worse, greening)
    /// assertions written against the pre-flag-day rules. Default is CLOSED,
    /// so an unadorned `cargo test` exercises the configuration the fleet
    /// actually runs; tests of the funded format opt in. Thread-local — see
    /// [`TlFlag`] for why nothing here may be a process global.
    pub fn deposit_funding_forced_open() -> bool {
        DEPOSIT_FUNDING_OPEN_TL.with(|c| c.get())
    }

    /// Opens the deposit-funding gate for this thread until the returned
    /// guard drops — including on the unwind path, so a failing assertion
    /// cannot leave the rule mutated for the rest of the thread.
    #[cfg(test)]
    pub fn deposit_funding_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                DEPOSIT_FUNDING_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = DEPOSIT_FUNDING_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    /// Serializes every test that flips a switch in this module. The switches
    /// are process-global and `cargo test` runs test functions on threads, so
    /// without this a mutation test would silently corrupt an unrelated one.
    pub static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    thread_local! {
        /// Plant a one-bit difference in every seed, so the A/B chain
        /// comparator can be shown to go red on a difference that is really
        /// there.
        ///
        /// **Thread-local, and it must stay that way.** This was an
        /// `AtomicBool` — a PROCESS global — guarded by an `AB_HOOKS` mutex
        /// that only the two A/B tests take. That mutex serialises those two
        /// against each other and does nothing for the other ~260 tests in
        /// this crate, every one of which reads `seed_for_epoch` and none of
        /// which take it. So while the comparator's tripwire held the flag
        /// up, any test running beside it computed a corrupted consensus
        /// seed. Observed 2026-08-24: a full `cargo test -p
        /// bloch-pos-committee` failed with
        /// `the_rule_reads_a_boundary_the_state_still_retains ... block
        /// rejected: Proposal(NotScheduledProposer)` — a test with no
        /// connection to the mutation, reddened by it.
        ///
        /// That is worse than a flaky test. A mutation switch that leaks into
        /// unrelated tests produces false REDs, which get "fixed", and false
        /// GREENs wherever the planted difference happens to land somewhere
        /// the assertions do not look. Thread-local makes the leak
        /// impossible: `cargo test` gives each test its own thread, so a
        /// mutation cannot escape the test that set it.
        pub static MUTATE_SEED: Cell<bool> = const { Cell::new(false) };

        /// Test-only mutation of the **rule itself**: force the seed
        /// look-ahead back to ZERO — the pre-fix arithmetic, in which epoch
        /// `E` is seeded by the close of `E − 1`.
        ///
        /// `MUTATE_SEED` above flips a bit of the seed's VALUE, which shows a
        /// comparator can see a difference. It cannot show that a reader
        /// which reverted to `E − 1` gets caught, because a bit-flip and a
        /// reverted look-ahead are not the same mutation. This one reverts
        /// the look-ahead, so the anti-partition tests can be run both ways
        /// by a third party with nothing but `cargo test` — no source edit,
        /// no script, no narration.
        ///
        /// Thread-local, not an atomic, and deliberately: `cargo test` runs
        /// tests in parallel on separate threads and `seed_for_epoch` is on
        /// almost every path in the crate. A process-global switch would flip
        /// the consensus rule under every test running beside it. Set it with
        /// [`with_lookahead_zero`], which restores it on the way out.
        pub static LOOKAHEAD_ZERO: Cell<bool> = const { Cell::new(false) };
    }

    /// Run `f` with the seed look-ahead forced to zero on this thread, then
    /// restore it — including on the unwind path, so a failing assertion
    /// inside `f` cannot leave the rule mutated for the rest of the thread.
    #[cfg(test)]
    pub fn with_lookahead_zero<R>(f: impl FnOnce() -> R) -> R {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                LOOKAHEAD_ZERO.with(|c| c.set(false));
            }
        }
        LOOKAHEAD_ZERO.with(|c| c.set(true));
        let _r = Restore;
        f()
    }

    thread_local! {
        /// Test-only override of [`super::FUNDED_STAKING_ACTIVATION_EPOCH`].
        ///
        /// The shipped constant is `u64::MAX` — correctly INERT, since the
        /// funded staking format does not exist — which means no epoch a test
        /// can construct ever reaches it. Without an override, every test of
        /// the post-activation path (`apply_deposit` accepting a valid funded
        /// deposit) would be dead code, and the boundary itself — reject at
        /// `activation − 1`, accept at `activation` — untestable from either
        /// side. Same argument as [`gates_are_forced_open`], but carrying an
        /// EPOCH rather than a bool, so the numeric boundary is exercised
        /// through the same `<` the fleet runs, not a bypass of it.
        ///
        /// Thread-local for the reasons documented on [`TlFlag`] and
        /// [`MUTATE_SEED`]: a process-global override would rewrite the
        /// consensus rule under every test running beside the one that set it.
        static FUNDED_STAKING_ACTIVATION_TL: Cell<Option<u64>> = const { Cell::new(None) };
    }

    /// Run `f` with the funded-staking flag day set to `epoch` on this
    /// thread, then restore the shipped constant — including on the unwind
    /// path, so a failing assertion cannot leave the rule mutated for the
    /// rest of the thread.
    #[cfg(test)]
    pub fn with_funded_staking_activation_at<R>(epoch: u64, f: impl FnOnce() -> R) -> R {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                FUNDED_STAKING_ACTIVATION_TL.with(|c| c.set(None));
            }
        }
        FUNDED_STAKING_ACTIVATION_TL.with(|c| c.set(Some(epoch)));
        let _r = Restore;
        f()
    }

    /// The funded-staking flag day this build's readers must use: the shipped
    /// constant, unless a test has moved it on this thread.
    #[cfg(test)]
    pub fn effective_funded_staking_activation() -> u64 {
        FUNDED_STAKING_ACTIVATION_TL
            .with(Cell::get)
            .unwrap_or(super::FUNDED_STAKING_ACTIVATION_EPOCH)
    }

    thread_local! {
        /// Test-only override of [`super::SIGNED_EXIT_ACTIVATION_EPOCH`] —
        /// the exit twin of [`FUNDED_STAKING_ACTIVATION_TL`], carried
        /// separately because the two flag days are separate constants and a
        /// test must be able to move one while proving the other did not
        /// follow.
        static SIGNED_EXIT_ACTIVATION_TL: Cell<Option<u64>> = const { Cell::new(None) };
    }

    /// Run `f` with the signed-exit flag day set to `epoch` on this thread,
    /// then restore the shipped constant — including on the unwind path.
    #[cfg(test)]
    pub fn with_signed_exit_activation_at<R>(epoch: u64, f: impl FnOnce() -> R) -> R {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                SIGNED_EXIT_ACTIVATION_TL.with(|c| c.set(None));
            }
        }
        SIGNED_EXIT_ACTIVATION_TL.with(|c| c.set(Some(epoch)));
        let _r = Restore;
        f()
    }

    /// The signed-exit flag day this build's readers must use: the shipped
    /// constant, unless a test has moved it on this thread.
    #[cfg(test)]
    pub fn effective_signed_exit_activation() -> u64 {
        SIGNED_EXIT_ACTIVATION_TL
            .with(Cell::get)
            .unwrap_or(super::SIGNED_EXIT_ACTIVATION_EPOCH)
    }

    /// The look-ahead this build's readers must use: the shipped constant,
    /// unless a test has mutated the rule on this thread.
    #[cfg(test)]
    pub fn effective_lookahead() -> u64 {
        if LOOKAHEAD_ZERO.with(Cell::get) {
            0
        } else {
            crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS
        }
    }
}

/// Flag day for the **seed look-ahead** (`CommittedState::seed_for_epoch`).
///
/// Below this epoch the seed for `E` is the mix at the close of `E − 1` — the
/// original rule, which the existing chain's blocks were produced and validated
/// under. From it, the seed is the close of `E − 1 − `[`crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS`].
///
/// # Why this gate exists, and why it was briefly deleted
///
/// It was removed on 2026-08-24 on the integration coordinator's instruction,
/// under the premise that a coordinated stop — all 64 validators halted and
/// restarted together — makes a flag day unnecessary, because there is no live
/// network for a gradual rollout to split.
///
/// **The premise was wrong, and the reason is worth keeping.** Persistence here
/// is an append-only BLOCK LOG (`store.rs`), and boot is a REPLAY of that log
/// through the same transition that accepted the blocks live. The transition
/// re-validates the state root (`StateRootMismatch`), and the seed decides the
/// committee partition, which decides which attestations are admitted, which
/// changes the root. So a node running the new rule against the old log does
/// not merely disagree at the boundary — it stops. `Engine::ingest` rejects and
/// returns, so the node ends up silently parked at an old height with a
/// truncated chain, and cannot follow the live network either. No panic, no
/// alarm.
///
/// The break is at **epoch 1**, not epoch 2: `seed_epoch(1)` is `None`, so the
/// corrected rule takes the genesis mix while the base takes `boundary_mixes[0]`
/// — the close of epoch 0, which is not the genesis mix once epoch 0 has
/// produced a block. First divergent proposer slot is 32; only epoch 0 is
/// common ground. Without this gate the new binary stops near the start of the
/// chain.
///
/// `u64::MAX` means INERT. Fill at tag time, and it must be **strictly in the
/// future** and **after the rollout completes** — arming an epoch already in the
/// past is the failure mode that let 1,600,000 BLCH escape a write-off that
/// never fired, and it fails SILENTLY. The gate reads the epoch derived from the
/// BLOCK, never a local clock: reading node-local mutable state is what caused
/// the 2026-08-08 `expected_bits` consensus split.
pub const ANCESTRY_SEED_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for **inactivity-leak recovery and the quorum-denominator floor**
/// ([`INACTIVITY_LEAK_RECOVERY_QUOTIENT`], [`MIN_QUORUM_DENOMINATOR_NUM`]).
///
/// Same reason as [`ANCESTRY_SEED_ACTIVATION_EPOCH`], one layer along: the leak
/// accumulator is committed into the state root (`state_root.rs`, `leaked:
/// Vec<LeakRecord>`), and the floor changes which checkpoints justify, which is
/// committed too. A node folding the log under new leak rules computes a root
/// the historical headers do not carry.
///
/// An empty accumulator serializes as a zero length, byte-identical to a chain
/// that never leaked, so blocks before the first bite replay unchanged and the
/// break point is the first epoch boundary that accrues one.
///
/// `u64::MAX` means INERT. Same arming rules as above.
pub const LEAK_RECOVERY_ACTIVATION_EPOCH: u64 = u64::MAX;

/// The epoch [`ANCESTRY_SEED_ACTIVATION_EPOCH`]'s readers actually compare
/// against in THIS build.
///
/// In a shipped binary this **is** the constant — `#[inline]`, no state, the
/// comparison folds at compile time. In a test build the rehearsal hooks may
/// move it on the current thread only: [`rehearsal::gates_open_guard`] forces
/// it to 0 (armed everywhere), [`rehearsal::gates_armed_at_guard`] places it
/// at a chosen epoch so the SEAM — inert below, armed at and above — is
/// reachable by a test. Every production read of the gate goes through here;
/// a second reader comparing the raw constant would silently not take the
/// rehearsal, which is how the engine's copy of the look-ahead drifted from
/// the transition's in the first place.
#[inline]
pub fn ancestry_seed_gate_epoch() -> u64 {
    #[cfg(test)]
    {
        if rehearsal::gates_are_forced_open() {
            return 0;
        }
        if let Some(e) = rehearsal::armed_activation_epoch() {
            return e;
        }
    }
    ANCESTRY_SEED_ACTIVATION_EPOCH
}

/// The epoch [`LEAK_RECOVERY_ACTIVATION_EPOCH`]'s readers actually compare
/// against in THIS build. Same contract as [`ancestry_seed_gate_epoch`].
#[inline]
pub fn leak_recovery_gate_epoch() -> u64 {
    #[cfg(test)]
    {
        if rehearsal::gates_are_forced_open() {
            return 0;
        }
        if let Some(e) = rehearsal::armed_activation_epoch() {
            return e;
        }
    }
    LEAK_RECOVERY_ACTIVATION_EPOCH
}

/// The seed look-ahead in force at `epoch` — **the one spelling of the F6
/// rule**, consulted by [`crate::transition::CommittedState::seed_for_epoch`]
/// and by the node's attestation-judging path
/// (`bloch-pos-node/src/engine.rs::seed_for_attestation`).
///
/// Below [`ANCESTRY_SEED_ACTIVATION_EPOCH`] it is 0: the seed for `E` is the
/// close of `E − 1`, the original rule the existing chain's blocks were
/// produced and validated under. At and above the gate it is
/// [`crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS`].
///
/// # Why this must be the only spelling
///
/// The node's gossip judge carried its own copy of this arithmetic. It was
/// written in the window when the gate had been deleted (2026-08-24) and the
/// look-ahead was unconditional; when the gate was restored in the committee
/// crate, the copy was not re-gated. Result, live on mainnet until this
/// function unified them: the transition admitted attestations under the
/// close-of-`E − 1` committees (gate closed) while the gossip judge derived
/// the close-of-`E − 2` committees (gate ignored) — so honest attestations
/// arriving over gossip were answered `Reject(NotInCommittee)` and never
/// reached a proposer's pool, and quorum leaned on validators large enough to
/// include their own votes in their own blocks. Two spellings of one
/// consensus-adjacent rule is the `expected_bits` defect class; this function
/// is the fix's shape: one authority, everyone calls it.
#[inline]
pub fn seed_lookahead_at(epoch: u64) -> u64 {
    if epoch < ancestry_seed_gate_epoch() {
        return 0;
    }
    #[cfg(test)]
    {
        crate::params::rehearsal::effective_lookahead()
    }
    #[cfg(not(test))]
    {
        crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS
    }
}

/// Flag day for **eUTXO-funded staking** — the ONE constant for the feature:
/// the epoch at which the funded deposit wire format
/// ([`crate::transition::PosTransaction::DepositV2`], tag `0x07` — coins
/// actually spent into the bond, proof of possession carried and checked,
/// applied by `CommittedState::apply_deposit_v2` with the field rules taken
/// from [`crate::staking::validate_deposit_fields`]) becomes acceptable in
/// blocks, and at which the funded delegation path
/// ([`crate::transition::CommittedState::apply_delegation`]) opens with it.
/// An earlier integration draft carried a second constant
/// (`DEPOSIT_FUNDING_ACTIVATION_EPOCH`) for the same feature; two gates for
/// one switch is how the two halves drift apart, so it was unified here.
///
/// # What is and is not gated on this constant
///
/// Below it, `DepositV2` refuses (`TransferReject::FormatNotActive` — the
/// same two-roads verdict as `TransferV2`: the old binary fails to decode
/// tag `0x07`, the new one refuses at the gate, so a mixed fleet stays on
/// one chain until the flag day) and `apply_delegation` refuses
/// (`TxReject::StakingNotActive`). AFTER activation the binaries diverge in
/// both directions, so the fleet must be rebuilt before this is lowered. The
/// legacy unfunded encodings — wire tags `0x02` (`Deposit`) and `0x04`
/// (`Delegate`) — are NOT what activates here: they name an `amount_sat`,
/// carry no signature and spend no output, so they are consensus-rejected at
/// EVERY epoch (see the two arms in `apply_transaction`). This constant names
/// the epoch at which their funded successors, whose wire format is owned by
/// the funded-format work stream, start being applied.
///
/// # The acceptance change the rejection itself is
///
/// Until 2026-08-31 the refusal of unfunded staking messages lived only at
/// the mempool door (`bloch-pos-node/src/engine.rs::admissible`), and its own
/// comment said so: "a node-side refusal, not a consensus rule: a block that
/// already carries a deposit still applies it." The consequence was that any
/// CURRENT COMMITTEE MEMBER could include a `Deposit` in its own block and
/// mint bonded stake — no key possession proven, no coins spent. Bounded
/// (outsiders cannot propose, and minted stake has no withdrawal path back to
/// coins), but it was consensus-weight inflation available to insiders.
///
/// Moving the refusal into `apply_transaction` closes that path, and it is a
/// TIGHTENING of what a node accepts: a binary from before this change
/// applies a deposit-carrying block, a binary from after rejects it
/// (`TransitionError::Transaction`). The two diverge on exactly the blocks
/// only a malicious insider can produce — which is the point — so the fleet
/// must be rebuilt together, per the flag-day runbook. **Replay precondition,
/// checked before rollout, not assumed:** no block in the live log may carry
/// tag `0x02` or `0x04`. The mempool has refused both since Genesis-4 launch
/// (2026-08-13) and only committee members propose, so the log should be
/// clean — but if an insider ever exercised the gap, an upgraded node will
/// stop at that block, and the rejection would instead need its own armed
/// activation epoch.
///
/// `u64::MAX` means INERT: funded staking does not exist yet, so nothing may
/// activate it. Arm it only when (1) the funded wire format is landed and the
/// fleet rebuilt, (2) the epoch is STRICTLY in the future at tag time — an
/// epoch already past arms silently, the failure mode that once let 1,600,000
/// BLCH escape a write-off — and (3) the value matches the runbook. The gate
/// reads the COMMITTED epoch (`CommittedState::epoch`, rolled by
/// `close_epoch`), never node-local state — the 2026-08-08 `expected_bits`
/// fork is the standing reason.
pub const FUNDED_STAKING_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for **signed voluntary exits** — the epoch at which an exit that
/// carries a hybrid signature over its own signing root
/// ([`crate::staking::ExitTx`], judged by [`crate::staking::validate_exit`]
/// through [`crate::transition::CommittedState::apply_exit`]) becomes
/// acceptable in blocks.
///
/// # Why exits have their own constant
///
/// Separate from [`FUNDED_STAKING_ACTIVATION_EPOCH`] because the two formats
/// have independent lives: a signed exit needs nothing from the eUTXO set —
/// only the signature §7.2 always specified — so it can (and should) activate
/// without waiting for the funded deposit machinery, while a funded deposit
/// has no dependency on exits. The three rejections below land together; the
/// three activations need not.
///
/// # What this closes
///
/// The wire `Exit` (tag `0x03`) is literally `Exit { validator: u32 }` — an
/// index, nothing else. Its arm in `apply_transaction` checked registry state
/// and never touched a verifier, while its doc comment claimed "Signature
/// already checked at admission" — false the same way the deposit comment
/// was: admission is node-local, and a proposer building its own block never
/// consults it. One hostile proposal slot could therefore carry `Exit` for
/// EVERY active index; every node would apply them, duties would stop
/// `EXIT_DELAY_EPOCHS` (32) later, and an exit is irrevocable
/// (`exit_epoch != u64::MAX` is refused) — the roster empties, every bond
/// locks for the 2,048-epoch withdrawal delay, and the attacker's own
/// relative weight rises. Combined with the unfunded-deposit mint this was
/// "exit everyone else, mint yourself a majority". As with the deposit, the
/// consensus arm now rejects tag `0x03` at EVERY epoch — no flag day reopens
/// an unauthenticated encoding — and this constant gates only the signed
/// successor. Same fleet-rebuild discipline and the same replay precondition
/// as above: the live log must be checked for tag `0x03` blocks before
/// rollout.
///
/// # The carrier this gate arms (wire tag `0x09`)
///
/// Until 2026-08-31 this constant gated a path **no bytes could reach**:
/// `apply_exit` was complete and tested and `validate_exit` verified the
/// hybrid signature properly, and no `PosTransaction` variant carried a
/// [`crate::staking::ExitTx`] — every call site was a doc comment or a test.
/// The consequence was not academic. `Withdraw` requires `exit_epoch` to be
/// set, and the only production writer of that field was the
/// slashing/ejection path, so a validator could join Genesis-4 and leave only
/// by being punished. The carrier is
/// [`crate::transition::PosTransaction::ExitV2`], tag `0x09`, which encodes
/// the WHOLE envelope (committed-pubkey hash, epoch, hybrid signature) — not
/// a signing root, the mistake that left tag `0x05` one-way and §7.3
/// unreachable from a block body.
///
/// # An exit-side rate limit does NOT exist, and this gate does not add one
///
/// Stated here because arming is where it becomes real. Nothing meters
/// voluntary exits: the churn budget ([`crate::delegation::WARMUP_RATE_BPS`],
/// [`crate::delegation::MIN_CHURN_SAT`]) governs DELEGATION warm-up and
/// cool-down, and `crate::staking` has no exit queue at all — the whole
/// self-bonded set can exit in one epoch, and
/// [`crate::ws`]'s module docs already record that as a measured fact rather
/// than an assumption. [`crate::staking::EXIT_DELAY_EPOCHS`] delays when
/// duties STOP; it does not bound how many may request. Arming this gate
/// therefore makes a mass simultaneous exit expressible on the wire for the
/// first time, and the exposure is to LIVENESS (the roster, and with it the
/// quorum denominator, can empty as fast as blocks can carry signatures), not
/// to the supply cap. Whether that needs a churn limit — and if so, whether
/// it belongs beside the activation throttle
/// ([`crate::staking::MAX_ACTIVATIONS_PER_EPOCH`]) — is a consensus-parameter
/// decision for the founder, flagged here, deliberately NOT invented in code.
///
/// `u64::MAX` means INERT. Same arming rules as
/// [`FUNDED_STAKING_ACTIVATION_EPOCH`], including the strictly-in-the-future
/// requirement and reading only the committed epoch. One further precondition
/// of its own: the exit-rate question above must have an answer before the
/// day, because after it the answer is a hard fork rather than a constant.
pub const SIGNED_EXIT_ACTIVATION_EPOCH: u64 = u64::MAX;

// ── The ordering the three staking gates may never be armed out of ─────────
//
// Checked at COMPILE TIME, because the failure mode is an edit to a constant
// weeks from now — a runbook line and a doc paragraph are exactly what got
// skipped the last time a flag day was armed wrong. All three constants are
// `u64::MAX` today, so both assertions hold trivially; they exist to make the
// ARMING order a build error rather than a fleet incident.
//
// Carried from the sibling integration pass (2026-08-31), which arrived at
// the same two invariants independently.
const _: () = assert!(
    WITHDRAWAL_ACTIVATION_EPOCH >= FUNDED_STAKING_ACTIVATION_EPOCH,
    "WITHDRAWAL_ACTIVATION_EPOCH must not precede FUNDED_STAKING_ACTIVATION_EPOCH: \
     paying out bonds while deposits are still unfunded turns deposit → exit → \
     withdraw into a mint"
);
const _: () = assert!(
    WITHDRAWAL_ACTIVATION_EPOCH >= SIGNED_EXIT_ACTIVATION_EPOCH,
    "WITHDRAWAL_ACTIVATION_EPOCH must not precede SIGNED_EXIT_ACTIVATION_EPOCH: \
     a withdrawal consumes an EXITED record, and after the 2026-08-31 closure the \
     signed exit is the only thing that can exit one — arming the payout first \
     ships a door with no road to it"
);

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
/// The signing root a funded deposit's INPUT witnesses cover
/// (`PosTransaction::DepositV2`): the domain under which a coin's owner
/// authorises destroying that coin into *this* validator bond and nothing
/// else.
///
/// Its own tag, and not [`DS_SPEND`], because the two preimages carry
/// different structures behind the same fold style: under one tag, a
/// signature over a deposit could — for some adversarially chosen field
/// values — parse as a signature over a transfer, and a coin authorised into
/// a bond would instead move to an attacker's output. Distinct tags make the
/// cross-reading impossible by construction instead of improbable by
/// arithmetic. And it is not [`DS_DEPOSIT`] either: that tag is the
/// VALIDATOR key's proof-of-possession domain (§7.1), signed by a different
/// key over a different statement ("I possess this key"), and a root that
/// served both would let one signature answer for the other.
///
/// The preimage covers the spend points, every §7.1 registration field
/// (pubkey, amount, RANDAO commitment, withdrawal address, commission), the
/// change outputs, the declared size and the tip — everything except the
/// witnesses and the PoP, which are signatures and cannot live inside a root
/// they are produced over. Both are still checked against committed material:
/// each witness against the spent output's `script_hash` and this root, the
/// PoP against the pubkey and the §7.1 root, whose every field is inside
/// *this* root and therefore inside the txid.
pub const DS_DEPOSIT_FUND: [u8; 16] = *b"BLCH4:DEPFUND\0\0\0";
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
