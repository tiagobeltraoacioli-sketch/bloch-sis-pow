// SPDX-License-Identifier: AGPL-3.0-or-later

//! Consensus constants for the committee layer.
//!
//! Values come from §5.1 and §6.5.2 of the migration design, which in turn come
//! from the measured in-circuit cost of the hybrid signature
//! (`spikes/prover-cost/RESULTS.md`): 7,274,849 RV32IM instructions per
//! ML-DSA-65 ‖ Falcon-1024 verification, and a 4,589-byte signature.
//!
//! These are LIVE consensus constants, and several of the activation heights
//! below are bound, not inert: `LEAKED_ROSTER_ACTIVATION_EPOCH` (1400),
//! `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` (800) and
//! `BLOCK_BYTES_V2_ACTIVATION_EPOCH` (800) are all epochs the chain is past.
//! `ANCESTRY_SEED_ACTIVATION_EPOCH` and `LEAK_RECOVERY_ACTIVATION_EPOCH` are
//! the ones still at `u64::MAX`.
//!
//! Until 2026-09-02 this header said nothing here was active and that the
//! crate held no activation height at all because it was not wired into the
//! node. All three clauses were false: the crate is a path-dependency of
//! `bloch-pos-node`, and this file has five activation constants, three of
//! them bound.

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
/// **This paragraph is the CORRECT account of that incident, and it is now
/// reproduced rather than asserted** — see
/// `prova::tests::s0_three_partitions_finalize_three_different_roots_at_the_same_epoch`
/// and `docs/post-mortems/2026-08-24-finality-divergence.md`. Two things the
/// next post-mortem must not repeat. First, the *other* finding of 2026-08-24
/// — the pre-shuffle roster filter in `epoch_committees`, proven by
/// `prova.rs` scenarios 1 to 4 — is a real defect but was **inert at epoch
/// 986**, gated behind [`LEAKED_ROSTER_ACTIVATION_EPOCH`] = 1400; it did not
/// cause this and has been miscited as its cause. Second, the epoch number and
/// the count of three in the sentence above are single-sourced to this comment,
/// written the same evening; the *mechanism* is now measured, the *specific
/// numbers* are still recollection.
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
/// **This flag day is ARMED, and bound long ago.** It is currently `1400`,
/// which the chain passed on 2026-08-29; the leak reaches the duty roster on
/// every block since. It is not a sentinel and has not been one since
/// 2026-08-24 — see "ARMED" below for the arming record and the provenance of
/// the number.
///
/// A `u64::MAX` here WOULD mean inert: every node ships the code and none of
/// it changes a single committee or proposer draw until the constant is
/// lowered and the fleet is rebuilt together. That is the idiom, shared with
/// `STATE_ROOT_ACTIVATION_HEIGHT` — a consensus rule arrives by flag day,
/// never by whoever restarts first — and it is the state this constant was in
/// before it was armed, not the state it is in now. The opening paragraph
/// asserted the inert state in the present tense for eight days after arming;
/// `scripts/check-comment-constants.py` now fails the build on that shape.
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
/// **This flag day is BOUND.** It is currently `800`, an epoch the chain is
/// long past, so `TransferV2` is acceptable in blocks today and the paragraphs
/// below describing the gate as pending describe history, not the live rule.
/// The V1 format (tag `0x01`) stays valid forever; this gate only *adds* an
/// encoding, it retires nothing.
///
/// A `u64::MAX` here WOULD mean inert: every node ships the decoder and the
/// apply path and none of it changes what a block may carry until the
/// constant is lowered and the fleet is rebuilt together. That is the idiom,
/// shared with `LEAKED_ROSTER_ACTIVATION_EPOCH` — a consensus rule arrives by
/// flag day, never by whoever restarts first — and it is the state this
/// constant was in before it was bound, not the state it is in now.
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
/// **This flag day is BOUND.** It is currently `800`, an epoch the chain is
/// long past, so the 512 KiB cap and the moved byte target are the live rule
/// and the two paragraphs above describe a switch that has already happened.
/// Until 2026-09-02 this paragraph described the constant as an unset
/// sentinel awaiting the founder, while the constant beside it read `800`.
///
/// Below the epoch every node computes the old cap and the old target, so a
/// mixed fleet reaches one verdict on every block; at and above it they
/// diverge on both, which is why rebuilding the fleet is a PRECONDITION of
/// lowering this constant and not a follow-up. Same idiom as
/// [`LEAKED_ROSTER_ACTIVATION_EPOCH`], and the gate reads the epoch derived
/// from the block's own header slot — never node-local state, which is what
/// the 2026-08-08 `expected_bits` fork cost us.
pub const BLOCK_BYTES_V2_ACTIVATION_EPOCH: u64 = 800;

/// **Superseded — read [`ANCESTRY_SEED_ACTIVATION_EPOCH`] below instead.**
///
/// This heading used to declare the F6 seed look-ahead unconditional and the
/// gate gone. The gate was deleted on 2026-08-24 and then RESTORED, for the
/// reason its own doc block records: boot is a replay of an append-only block
/// log, so a node running the corrected rule against the old log does not
/// disagree at a boundary, it stops. The constant exists, it is `u64::MAX`,
/// and therefore the SHIPPED rule is still `back = 1` — the pre-F6 rule — for
/// every epoch any chain can reach. The paragraphs below describe the deletion
/// and are kept as the record of it, not as a description of today.
///
/// `CommittedState::seed_for_epoch` seeds epoch `E` from the mix at the close
/// of `E − 1 − `[`crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS`], always. It
/// was written behind an inert `ANCESTRY_SEED_ACTIVATION_EPOCH` gate first,
/// and the gate was REMOVED on the founder's instruction (2026-08-24): the
/// relaunch is a coordinated convergence — one storage state installed on all
/// 64 validators, all restarted together — so there is no live network for a
/// gradual rollout to split, which is the only thing the gate bought. Deleting
/// it also deletes the way it could go wrong: an activation epoch armed in the
/// past, which is how 1,600,000 BLCH once escaped a write-off that never
/// fired.
///
/// **What this means for anyone reading later.** The rule is now implicit in
/// the binary rather than dated in a constant, so "which seed rule does this
/// chain run" is answered by the release, not by the state. Any FUTURE change
/// to `seed_for_epoch` on a live network needs a gate again — this note is not
/// a precedent for changing consensus without one.
///
/// # What the look-ahead closes
///
/// F6, proposer grinding: at `back = 1` the seed for `E` is the mix at the
/// close of `E − 1`, so the trailing proposers of `E − 1` see the partition
/// their own reveal produces before they must publish it, and can re-sort `E`
/// by withholding.
///
/// It also removes the sub-epoch-lag case of the duty-view ANCHOR defect,
/// because the `E − 2` mix is frozen before `E − 1` begins. It is a mitigation
/// of that defect, not a fix; the fix is anchoring the duty view to the
/// ancestry of the thing being judged (`bloch-pos-node/src/engine.rs`).
///
/// # It costs nothing at the seam
///
/// `close_epoch` retains [`crate::state_root::RANDAO_BOUNDARIES_RETAINED`]` =
/// 2` boundaries, so while `E` is open the state holds `{E − 2, E − 1}`. The
/// rule reads `E − 2`, already there. No retention change, and therefore no
/// state-root change — `state_root::randao_window` folds exactly the retained
/// boundaries into the tree. Pinned by
/// `the_rule_reads_a_boundary_the_state_still_retains`.

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

    /// Test-only: treat [`super::ANCESTRY_SEED_ACTIVATION_EPOCH`] and
    /// [`super::LEAK_RECOVERY_ACTIVATION_EPOCH`] as if they had already bound.
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
