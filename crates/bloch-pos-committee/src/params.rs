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
//! `LEAK_RECOVERY_ACTIVATION_EPOCH` is armed at 2700 (2026-09-06);
//! `ANCESTRY_SEED_ACTIVATION_EPOCH`, `DEPOSIT_ACTIVATION_EPOCH`,
//! `EXIT_AUTH_ACTIVATION_EPOCH`, `FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH`,
//! `SLASHING_EVIDENCE_ACTIVATION_EPOCH`, `DUST_RULE_ACTIVATION_EPOCH`,
//! `RANDAO_RECOMMIT_ACTIVATION_EPOCH` and `TX_BYTES_BOUND_ACTIVATION_EPOCH`
//! are the ones still at `u64::MAX`.
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

/// Hard ceiling on attestations a single block body may carry.
///
/// # Why a block-level bound exists at all
///
/// Step 8 of `Transition::apply_block` runs a per-attestation loop. Before
/// 2026-09-04 nothing bounded the length of that loop from inside consensus:
/// the only cap was `bloch_pos_node::codec::decode_envelope`'s wire limit, a
/// number written in the *node's* decoder and therefore absent from every
/// other way a body reaches the transition (RPC, replay of a locally built
/// body, the producer's own `compute_post_state` probe, a future codec). A
/// consensus rule that only holds because one particular decoder happens to
/// enforce it is not a consensus rule.
///
/// # Why exactly 4,096 and not something tighter
///
/// 4,096 is **the same number the wire decoder already enforced**, chosen for
/// that reason and no other. It makes this constant provably a no-op for
/// every block that has ever crossed the network — no historical body can
/// violate a bound its own decoder already applied — so binding it needs no
/// flag day and can create no fork. That is the whole of the safety argument.
///
/// It is emphatically *not* the tight bound. An honest body can hold at most
/// one attestation per (validator, vote) pair in the current epoch, so with
/// today's 64-validator set the honest ceiling is nearer 64 than 4,096. A cap
/// in that region would be a genuine tightening — it could reject a body an
/// older producer might build — and tightening a live consensus rule is a
/// flag day and the founder's call, not a dev's. See the note beside the
/// check in `transition.rs` step 8.
///
/// The DoS this constant was written for is **not** closed by this constant.
/// It is closed by hoisting the epoch partition out of the loop (same file,
/// same step): the cost of a body went from `n` shuffles of the whole active
/// set to one. This bound is the backstop behind that fix, not the fix.
pub const MAX_ATTESTATIONS_PER_BLOCK: usize = 4_096;

/// Seconds per slot (§5.1) — identical to today's PoW block target, so the
/// transition adds no new propagation pressure.
pub const SLOT_DURATION_SECS: u64 = 30;

/// The most epochs one block may advance the epoch accounting past its
/// parent's, before [`crate::interfaces::TransitionError::EpochAdvanceTooLarge`].
///
/// # Why a bound has to exist at all
///
/// `compute_post_state` rolls the accounting over every epoch the chain
/// skipped: `while st.epoch < block_epoch { st = st.close_epoch() }`. The loop
/// is correct — `close_epoch` is the single definition of the boundary, so
/// implicit and explicit epoch processing cannot diverge — but its trip count
/// is `epoch_of(header.slot)` and `header.slot` is an untrusted `u64` that
/// arrives off the wire. `u64::MAX / SLOTS_PER_EPOCH` is ~5.76e17, and each
/// turn clones the whole eUTXO set. Unbounded, one packet costs every node
/// that judges it its remaining uptime.
///
/// **This is a plain bound, NOT an armed activation.** There is no flag-day
/// constant here, nothing set to `u64::MAX` waiting to be switched on, and no
/// epoch at which the behaviour changes: the check is live at every epoch on
/// any node running this crate.
///
/// # Why 4,096, and what it costs
///
/// The gap this measures is not "how old is the chain" — it is the distance
/// between ONE block and its PARENT, since `pre.epoch` is always
/// `epoch_of(parent.slot)`. So the number is a ceiling on how long the whole
/// network may be dark and still resume on the same chain: 4,096 x 32 slots x
/// 30s = **45.5 days** of total halt.
///
/// Against that, the largest gaps this chain has actually produced are three
/// orders of magnitude smaller — tens to ~200 slots of vão (under 7 epochs)
/// through the 2026-08/09 stalls, and the whole of Genesis-4 to date is under
/// 2,000 epochs old. Replay safety therefore holds by construction and not by
/// hope: no block in committed history advances the epoch by more than a
/// handful, so every historical block replays through this gate unchanged.
///
/// The honest cost, named rather than buried: if the network really did halt
/// for 46 days, the block that tried to restart it would be invalid under this
/// rule and the chain would need a coordinated fork to resume. That is the
/// trade — a bounded DoS in exchange for a liveness ceiling — and it is the
/// reason the value is 4,096 rather than the ~10 that history alone would
/// justify. Raising or lowering it is a consensus change and a founder call.
///
/// # This is the backstop, not the first line
///
/// `bloch-pos-node`'s `Engine::ingest` refuses a gossiped block whose slot is
/// more than `2 x SLOTS_PER_EPOCH` past that node's own wall clock, which caps
/// the walk at two turns on every path a stranger can reach. That rule is
/// local (a node may hold it or not without forking); this one is consensus,
/// and it is what still holds when the block arrives some other way — a
/// crafted store, a sync response, a future transport, a node that drops the
/// local rule.
pub const MAX_EPOCH_ADVANCE: u64 = 4_096;

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

    thread_local! {
        static BONDING_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    thread_local! {
        static MINT_FROM_NOTHING_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// **MUTATION SWITCH — injects a mint from nothing.** `true` makes
    /// `transition::CommittedState::close_epoch` credit the epoch's validator
    /// reward into the operator's bond *without* advancing the committed
    /// `issued_sat` counter.
    ///
    /// This is the one defect the hard cap cannot see and the whole point of
    /// the supply-conservation invariant: the counter stays honest forever
    /// while the ledger grows on every epoch boundary, so
    /// `SupplyCapExceeded` never fires and the supply inflates without limit.
    ///
    /// It exists so the invariant can be shown to REFUSE something. A guard
    /// that has only ever been observed passing is a guard nobody knows is
    /// wired up — the same argument `PARTITION_DUPLICATES_AN_INDEX` above
    /// makes for the epoch partition. Read only through
    /// `transition::mutation_mints_from_nothing`, `cfg(test)` on both sides,
    /// so the branch folds away and the switch cannot exist in a shipped
    /// binary.
    pub fn mint_from_nothing() -> bool {
        MINT_FROM_NOTHING_TL.with(|c| c.get())
    }

    /// Injects the mint above for this thread until the guard drops,
    /// including on unwind — a failing assertion must not leave the rest of
    /// the thread minting coins from nothing.
    pub fn mint_from_nothing_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                MINT_FROM_NOTHING_TL.with(|c| c.set(self.0));
            }
        }
        let prev = MINT_FROM_NOTHING_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    /// Test-only: treat [`super::DEPOSIT_ACTIVATION_EPOCH`] as already bound.
    ///
    /// Its own switch, NOT folded into `GATES_OPEN`, and the reason is that the
    /// two mean opposite things. `GATES_OPEN` turns the NEW rule on for gates
    /// whose inert value is the old behaviour; this one turns the OLD (unfunded
    /// bonding) behaviour BACK ON for a gate whose inert value is the refusal.
    /// A test that wanted a post-ancestry-seed roster and got a chain where
    /// stake mints from nothing would be a fixture lying about the network it
    /// models.
    ///
    /// It exists because the only two things a test can do with a permanently
    /// closed gate are assert it is closed and build the fixture that proves
    /// the refusal comes from consensus rather than from the mempool. The
    /// second needs a block that CARRIES a deposit, and a producer cannot
    /// stamp a `state_root` over a transition that refuses the transaction —
    /// so the block is built with this open and judged with it shut.
    ///
    /// Default is CLOSED: an unadorned `cargo test` runs the fleet's rules.
    pub fn bonding_gate_forced_open() -> bool {
        BONDING_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the unfunded-bonding gate for this thread until the guard drops,
    /// including on unwind, so a failing assertion cannot leave stake minting
    /// from nothing for the rest of the thread.
    pub fn bonding_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                BONDING_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = BONDING_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static EXIT_AUTH_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::EXIT_AUTH_ACTIVATION_EPOCH`] as already bound.
    ///
    /// Its own switch for the same reason `BONDING_GATE_OPEN` is: this gate's
    /// inert value selects a REFUSAL of the new format and the *survival* of
    /// the old unauthenticated one, so folding it into `GATES_OPEN` would
    /// silently retire legacy `Exit` inside every test that only wanted a
    /// post-ancestry-seed roster.
    ///
    /// Default CLOSED, deliberately: an unadorned `cargo test` exercises the
    /// configuration the fleet actually runs today, in which `ExitV2` is
    /// invalid at every epoch and legacy `Exit` still applies. Tests of the
    /// post-flag-day rules — the signature check and the churn cap — opt in.
    pub fn exit_auth_gate_forced_open() -> bool {
        EXIT_AUTH_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the authenticated-exit gate for this thread until the guard
    /// drops, including on unwind, so a failing assertion cannot leave the
    /// exit rules mutated for the rest of the thread.
    pub fn exit_auth_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                EXIT_AUTH_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = EXIT_AUTH_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static SLASHING_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::SLASHING_EVIDENCE_ACTIVATION_EPOCH`] as
    /// already bound.
    ///
    /// Its own switch for the same reason `EXIT_AUTH_GATE_OPEN` is: this
    /// gate's inert value selects a REFUSAL of the evidence transaction, so
    /// folding it into `GATES_OPEN` would silently start slashing inside every
    /// test that only wanted a post-ancestry-seed roster.
    ///
    /// Default CLOSED, deliberately: an unadorned `cargo test` exercises the
    /// configuration the fleet actually runs today, in which a block carrying
    /// tag `0x05` is refused at the transition at every reachable epoch.
    /// Tests of the post-flag-day rules — evidence slashes, forged evidence
    /// rejects the block — opt in with the guard below.
    pub fn slashing_gate_forced_open() -> bool {
        SLASHING_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the slashing-evidence gate for this thread until the guard
    /// drops, including on unwind, so a failing assertion cannot leave the
    /// slashing rules mutated for the rest of the thread.
    pub fn slashing_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                SLASHING_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = SLASHING_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static DUST_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::DUST_RULE_ACTIVATION_EPOCH`] as already
    /// bound. Its own switch, not folded into `GATES_OPEN`, for the
    /// `exit_auth_gate_forced_open` reason: this gate's inert value keeps
    /// dust outputs VALID (the fleet's configuration today), so an
    /// unadorned `cargo test` must exercise exactly that, and tests of the
    /// post-flag-day refusals opt in.
    pub fn dust_gate_forced_open() -> bool {
        DUST_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the dust gate for this thread until the guard drops, including
    /// on unwind, so a failing assertion cannot leave the transfer rules
    /// mutated for the rest of the thread.
    pub fn dust_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                DUST_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = DUST_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static TX_BYTES_BOUND_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::TX_BYTES_BOUND_ACTIVATION_EPOCH`] as already
    /// bound.
    ///
    /// Its own switch for the `BONDING_GATE_OPEN` reason: the gate's inert
    /// value keeps the OLD permissive rule (over-declaring `tx_bytes` is
    /// legal), so folding it into `GATES_OPEN` would silently tighten transfer
    /// validity inside every test that only wanted the post-ancestry-seed
    /// roster. Default CLOSED: an unadorned `cargo test` runs the fleet's
    /// rules; tests of the declared-size ceiling opt in.
    pub fn tx_bytes_bound_forced_open() -> bool {
        TX_BYTES_BOUND_OPEN_TL.with(|c| c.get())
    }

    /// Opens the declared-size-ceiling gate for this thread until the guard
    /// drops, including on unwind, so a failing assertion cannot leave
    /// transfer validity tightened for the rest of the thread.
    pub fn tx_bytes_bound_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                TX_BYTES_BOUND_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = TX_BYTES_BOUND_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
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
    thread_local! {
        static FEE_STAKE_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH`] as
    /// already bound.
    ///
    /// Its own switch, NOT folded into `GATES_OPEN`, for the same reason the
    /// deposit and exit gates have theirs: the leak-era tests that open
    /// `GATES_OPEN` pin roots and balances computed under the compounding
    /// rule, and silently decoupling fee crediting inside them would turn
    /// every one into a fixture lying about the chain it models. Tests of the
    /// post-flag-day fee rules opt in here and nowhere else.
    ///
    /// Default CLOSED: an unadorned `cargo test` runs the fleet's rules.
    pub fn fee_stake_gate_forced_open() -> bool {
        FEE_STAKE_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the fee-to-stake decoupling gate for this thread until the guard
    /// drops, including on unwind, so a failing assertion cannot leave the
    /// fee rules mutated for the rest of the thread.
    pub fn fee_stake_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FEE_STAKE_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = FEE_STAKE_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

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
        static RANDAO_RECOMMIT_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::RANDAO_RECOMMIT_ACTIVATION_EPOCH`] as
    /// already bound.
    ///
    /// Its own switch, NOT folded into `GATES_OPEN`, for the same reason
    /// `EXIT_AUTH_GATE_OPEN` has its own: this gate's inert value selects a
    /// REFUSAL (a re-commit is consensus-invalid at every epoch), and a test
    /// that only wanted the post-ancestry-seed roster must not silently gain
    /// a chain where exhausted validators resurrect themselves.
    ///
    /// Default CLOSED, deliberately: an unadorned `cargo test` exercises the
    /// configuration the fleet runs today, in which every RANDAO chain is
    /// terminal. Tests of the post-flag-day rules — the signature check, the
    /// exhaustion precondition, the epoch binding — opt in.
    pub fn randao_recommit_gate_forced_open() -> bool {
        RANDAO_RECOMMIT_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the re-commit gate for this thread until the guard drops,
    /// including on unwind, so a failing assertion cannot leave the beacon
    /// rules mutated for the rest of the thread.
    pub fn randao_recommit_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                RANDAO_RECOMMIT_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = RANDAO_RECOMMIT_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static ATTESTATION_DEDUP_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::ATTESTATION_DEDUP_ACTIVATION_EPOCH`] as
    /// already bound.
    ///
    /// Its own switch, NOT folded into `GATES_OPEN`, for the same reason the
    /// dust and tx-bytes gates have theirs: this gate's inert value selects
    /// the OLD (duplicate-tolerant) rule, so folding it into `GATES_OPEN`
    /// would silently tighten body validity inside every test that only
    /// wanted the post-ancestry-seed roster. Default CLOSED: an unadorned
    /// `cargo test` runs the fleet's rules; tests of the tightened rule opt
    /// in.
    pub fn attestation_dedup_gate_forced_open() -> bool {
        ATTESTATION_DEDUP_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the attestation-dedup gate for this thread until the guard
    /// drops, including on unwind, so a failing assertion cannot leave body
    /// validity tightened for the rest of the thread.
    pub fn attestation_dedup_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                ATTESTATION_DEDUP_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = ATTESTATION_DEDUP_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static REWARDS_V2_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::REWARDS_V2_ACTIVATION_EPOCH`] as already
    /// bound.
    ///
    /// Its own switch, NOT folded into `GATES_OPEN`, for the same reason the
    /// fee-stake-decouple gate has one: the leak-era tests that open
    /// `GATES_OPEN` pin issuance figures computed under the OLD reward rules,
    /// and silently switching the credit/basis/delegator-split rules inside
    /// them would turn every one into a fixture lying about the chain it
    /// models. Default CLOSED: an unadorned `cargo test` runs the fleet's
    /// rules; tests of rewards v2 opt in here and nowhere else.
    pub fn rewards_v2_gate_forced_open() -> bool {
        REWARDS_V2_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the rewards-v2 gate for this thread until the guard drops,
    /// including on unwind, so a failing assertion cannot leave the reward
    /// rules mutated for the rest of the thread.
    pub fn rewards_v2_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                REWARDS_V2_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = REWARDS_V2_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static STAKING_TX_METERING_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::STAKING_TX_METERING_ACTIVATION_EPOCH`] as
    /// already bound.
    ///
    /// Its own switch for the `dust_gate_forced_open` reason: the gate's
    /// inert value keeps staking transactions FREE and
    /// `MAX_TRANSACTIONS_PER_BLOCK` unconsulted (today's fleet configuration),
    /// so an unadorned `cargo test` must exercise exactly that, and tests of
    /// the post-flag-day metering opt in.
    pub fn staking_tx_metering_gate_forced_open() -> bool {
        STAKING_TX_METERING_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the staking-tx-metering gate for this thread until the guard
    /// drops, including on unwind, so a failing assertion cannot leave the
    /// fee rules mutated for the rest of the thread.
    pub fn staking_tx_metering_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                STAKING_TX_METERING_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = STAKING_TX_METERING_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static FC_HORIZON_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat
    /// [`super::FORKCHOICE_EQUIVOCATION_HORIZON_ACTIVATION_EPOCH`] as already
    /// bound (external audit 2026-09-07, O01).
    ///
    /// Its own switch for the `dust_gate_forced_open` reason: the inert
    /// value keeps today's one-message fork-choice fold — the fleet's
    /// configuration, and the four-of-six miss it carries — so an unadorned
    /// `cargo test` must exercise exactly that, and tests of the retained
    /// horizon opt in here and nowhere else.
    pub fn forkchoice_equivocation_horizon_gate_forced_open() -> bool {
        FC_HORIZON_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the fork-choice horizon gate for this thread until the guard
    /// drops, including on unwind, so a failing assertion cannot leave the
    /// fork-choice fold mutated for the rest of the thread.
    pub fn forkchoice_equivocation_horizon_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FC_HORIZON_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = FC_HORIZON_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static WITHDRAWAL_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::WITHDRAWAL_ACTIVATION_EPOCH`] as already
    /// bound.
    ///
    /// Kept for symmetry with every other gate even though — see that
    /// constant's docs — nothing reads this switch today: there is no
    /// `Withdraw` transaction to un-refuse, only the orphaned predicate
    /// [`crate::transition::CommittedState::withdrawal_active`], forcing
    /// which open changes no observable behaviour anywhere in this crate
    /// yet. Not folded into `GATES_OPEN`, matching every other gate's own
    /// switch, so that the day this IS wired the same isolation applies
    /// without a second decision.
    pub fn withdrawal_gate_forced_open() -> bool {
        WITHDRAWAL_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the withdrawal gate for this thread until the guard drops,
    /// including on unwind, so a failing assertion cannot leave the
    /// withdrawal rules mutated for the rest of the thread.
    pub fn withdrawal_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                WITHDRAWAL_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = WITHDRAWAL_GATE_OPEN_TL.with(|c| c.replace(true));
        Restore(prev)
    }

    thread_local! {
        static SIGHASH_NETWORK_BINDING_GATE_OPEN_TL: Cell<bool> = const { Cell::new(false) };
    }

    /// Test-only: treat [`super::SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH`]
    /// as already bound.
    ///
    /// Its own switch, NOT folded into `GATES_OPEN`: this gate's inert value
    /// keeps every existing KAT root computed under the OLD, unbound
    /// `DS_SPEND` fold, so folding it into `GATES_OPEN` would silently change
    /// every signing root pinned by every OTHER test in the crate that
    /// spends anything. Default CLOSED: an unadorned `cargo test` runs the
    /// fleet's rules; tests of the network-bound fold opt in.
    pub fn sighash_network_binding_gate_forced_open() -> bool {
        SIGHASH_NETWORK_BINDING_GATE_OPEN_TL.with(|c| c.get())
    }

    /// Opens the sighash-network-binding gate for this thread until the
    /// guard drops, including on unwind, so a failing assertion cannot leave
    /// the signing-root fold mutated for the rest of the thread.
    pub fn sighash_network_binding_gate_open_guard() -> impl Drop {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                SIGHASH_NETWORK_BINDING_GATE_OPEN_TL.with(|c| c.set(self.0));
            }
        }
        let prev = SIGHASH_NETWORK_BINDING_GATE_OPEN_TL.with(|c| c.replace(true));
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
/// **ARMED at epoch 2700** (founder decision, 2026-09-06; ≈2026-09-12 wall
/// clock at 90 epochs/day from epoch ~2070). Below 2700 the shipped arithmetic
/// is unchanged — the unfloored, leak-adjusted denominator of the 2026-08-24
/// incident. At and after 2700 the denominator floor and the leak recovery are
/// in force.
///
/// DEPLOYMENT DEADLINE: every validator must run a binary carrying this value
/// BEFORE epoch 2700. A fleet split across old/new binaries at that boundary
/// diverges — this is a flag day, and the coordinated rebuild is the
/// operational half of the decision.
pub const LEAK_RECOVERY_ACTIVATION_EPOCH: u64 = 2_700;

/// Flag day for **unfunded bonding**: the epoch at and after which the legacy
/// `Deposit` and `Delegate` messages are valid. Below it they are refused by
/// CONSENSUS, on every node, with [`crate::transition::TxReject::StakingNotActive`].
///
/// # What it closes, and why a node-side check was not enough
///
/// `bloch-pos-node`'s `admissible` has refused both messages at the mempool
/// door since 2026-08-13, and its own comment says what that is worth: "this is
/// a node-side refusal, not a consensus rule: a block that already carries a
/// deposit still applies it." It is MEMPOOL POLICY. One producer that lifts it
/// — a patched binary, a `--` flag, a fork of the node crate — lifts it for the
/// entire network, because every other node runs `apply_transaction`, and
/// `apply_transaction` applied both messages unconditionally. Sixty-four
/// validators judging the block would each have accepted it.
///
/// Both messages mint consensus weight without spending an output. `Deposit`
/// registers a `ValidatorRecord` holding `amount_sat` (>= `MIN_DEPOSIT_SAT`,
/// 25,000 BLCH) against no input and no signature. `Delegate` is the same shape
/// one layer along and lands FASTER: `consensus_roster_at` adds resolved
/// delegated stake into `effective_stake` (transition.rs, `roster.push`), and a
/// delegation requests from `self.epoch + 1` rather than waiting out
/// `ACTIVATION_DELAY_EPOCHS`. They are one rule — bonding is not funded from
/// the eUTXO set — so they share one constant, and arming for one without the
/// other would reopen the hole through the faster door.
///
/// # Where the epoch comes from
///
/// `self.epoch` inside `apply_transaction`, which `compute_post_state` has
/// already rolled to `crate::epoch_of(header.slot)` — the boundary walk `while
/// st.epoch < block_epoch { st.close_epoch() }`, and `close_epoch` advances by
/// exactly one. So at the gate, `self.epoch` IS the epoch of the block being
/// judged, a pure function of a header field that the block id commits to
/// (`DS_BLOCK` over the canonical header). It is not a wall clock, not a
/// `current_bits`-style mutable local, and not the node's own head. Two honest
/// nodes handed the same block read the same number. This is deliberately the
/// same shape as the `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` gate that sits
/// four lines above it, and deliberately NOT the shape of the 2026-08-08
/// `expected_bits` split, where the verdict came from state each node mutated
/// on its own accepted-block path and identical binaries diverged.
///
/// # Replay safety
///
/// Refusing below the flag day rewrites history only if history contains one.
/// It does not: measured 2026-09-02 against the two keyless archivals
/// 139.180.166.5 and 139.180.173.231, which agreed byte-for-byte at height
/// 35,628 / epoch 1,766 (`state_root`
/// 71e71e6a5a0843af78d4bd2a63b0e4192a62f5108741ac3ed76797d57f063fa7) on
/// `validators.total == 64`. `validator_count` is `validators.len()` — EVERY
/// record, including one queued at `activation_epoch == u64::MAX` — and the
/// genesis cohort is 64. No `Deposit` has ever been applied on the canonical
/// chain, so every historical block replays through this gate unchanged and
/// the fleet can adopt it without a coordinated flag day. (`Delegate` leaves no
/// registry trace, so its absence is argued, not measured: nothing on this
/// chain has ever had an incentive to delegate to a founder-held validator, and
/// a delegation would have moved `effective_stake` in `total_active_stake_sat`,
/// which is uniform across the 64 at 142,582,277.37013640 BLCH.)
///
/// # `u64::MAX` means INERT — and here inert means the rule is FULLY LIVE
///
/// Unlike [`ANCESTRY_SEED_ACTIVATION_EPOCH`], whose inert value selects the OLD
/// behaviour, this constant's inert value selects the REFUSAL. Set to
/// `u64::MAX`, no epoch ever reaches it and both messages are invalid in
/// consensus at every epoch, today, on any node running this crate. The gate is
/// not waiting to be armed to do its work; it is doing it.
///
/// # ARMING THIS CONSTANT IS NOT HOW DEPOSITS OPEN
///
/// Read that twice. The encoding this gate governs is the UNAUTHENTICATED one.
/// Moving this number to a real epoch does not make deposits safe; it makes
/// stake-minted-from-nothing a consensus-VALID transaction on all 64 nodes,
/// which is strictly worse than today, where at least the mempool refuses it.
/// The recommendation of the commit that introduced this gate is that this
/// number never move.
///
/// Deposits open by a different route: a funded, authenticated message that
/// spends transparent eUTXO inputs and carries a proof of possession — the form
/// `staking::validate_deposit` and `DepositTx` already describe and nothing
/// encodes. That form needs a wire tag, the tag space above the released range
/// is contested across live lineages, and the registry that resolves it is the
/// founder's to assign. When it lands it brings its OWN activation constant.
/// This one stays `u64::MAX` and the legacy arm stays refused, permanently.
///
/// `deposit_gate_is_inert` pins the value, so arming it means deleting a test
/// that says all of the above out loud.
pub const DEPOSIT_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for the **authenticated voluntary exit** (§7.2) and the per-epoch
/// exit churn cap. `u64::MAX` = INERT: no epoch reaches it, so on every node
/// running this crate today the rule below is written down and does nothing.
///
/// # The hole it closes
///
/// [`crate::transition::PosTransaction::Exit`] (wire tag `0x03`) carries a
/// registry index and NOTHING ELSE. Its arm in the transition consults the
/// registry and never touches a verifier, so *anyone* can retire *any*
/// validator, and an exit cannot be revoked (`exit_epoch != u64::MAX` is a
/// refusal). Sixty-four such messages retire the whole roster and lock every
/// bond for [`crate::staking::WITHDRAWAL_DELAY_EPOCHS`] = 2,048 epochs. The
/// node's mempool has refused the message since 2026-08-13
/// (`bloch-pos-node`'s `admissible`), but mempool policy is one producer's
/// choice to lift; consensus is what makes it everyone's.
///
/// # What the gate switches, in both directions, at one epoch
///
/// - **at and above**: legacy `Exit` (`0x03`) becomes consensus-INVALID, and
///   [`crate::transition::PosTransaction::ExitV2`] — hybrid signature verified
///   against the *registered* pubkey, signed epoch bound to the inclusion
///   epoch — becomes the only voluntary exit;
/// - **at and above**: at most [`crate::staking::MAX_EXITS_PER_EPOCH`]
///   voluntary exits may be included per epoch, the churn budget that stops a
///   roster-wide retirement from being one block's work even when every
///   signature is genuine (the mirror of `MAX_ACTIVATIONS_PER_EPOCH`, and for
///   the same reason: a committee that can empty instantly can be emptied
///   instantly);
/// - **below**: every arm behaves EXACTLY as it does today, byte for byte.
///   That is what lets a mixed fleet reach one verdict on every block until
///   the day, and it is why the arms below the gate must not be "improved"
///   while they are the control.
///
/// The gate reads `CommittedState::epoch` — committed state rolled to the
/// block's own header slot by `compute_post_state`'s boundary walk, never
/// node-local. The 2026-08-08 `expected_bits` fork is the standing reason.
///
/// # ARMING THIS IS A FOUNDER DECISION, AND IT HAS A PRECONDITION
///
/// Two, actually. (1) The whole fleet must already be running a binary that
/// carries this rule, because the first post-gate block changes the verdict on
/// legacy `Exit` — a node without the rule accepts what a node with it
/// refuses. (2) `ExitV2` has **no decoder arm**: wire byte `0x08` is
/// CONTESTED across live lineages (`SignedExit`, `Withdraw`, `ExitV2` all
/// claim it — see `tests/wire_tag_registry.rs`), and this tree refuses to
/// decode it until the founder rules on the byte. Arming this constant
/// without that ruling retires the legacy message and puts nothing in its
/// place: voluntary exit would simply stop existing.
///
/// `exit_auth_gate_is_inert` pins the value.
pub const EXIT_AUTH_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for the **fee-to-stake decoupling** (finding C-R2-2, 2026-09-05).
///
/// Three rules bind together once an epoch reaches this constant; below it,
/// every one of them is byte-identical to the chain as it stands:
///
/// 1. **Producer fee accrual is capped per block** at
///    [`crate::rewards::MAX_BLOCK_FEE_TO_PRODUCER_SAT`]; the excess is burned
///    by omission, the same one-way door the base-fee burn already uses.
/// 2. **The operator's boundary fee share stops compounding into the bond.**
///    `close_epoch` credits it (plus the pro-rata dust) to the committed
///    `validator_fee_rewards` withdrawable ledger — the operator mirror of
///    `delegator_fee_rewards` — instead of adding it to
///    `ValidatorRecord::staked_sat`. Consensus weight can then grow only
///    through the deposit path, which checks the per-validator cap at
///    admission; fees buy income, not weight. Before this gate, a proposer
///    converts liquid coin into bonded stake at 100% via tips, with no cap —
///    which is the C-R2-2 finding.
/// 3. **The per-validator stake cap applies to own+delegated stake** in
///    `duty_roster_at`, via [`crate::delegation::combined_cap_sat`] — the
///    same `MAX_VALIDATOR_STAKE_BPS` fixed point the delegation registry
///    already runs, but over the combined position, floored at the equal
///    share so a roster of uniformly large bonds cannot cap itself to zero.
///
/// All three change either committed state evolution or consensus weight, so
/// they cannot ship enabled on a mixed fleet: this constant stays `u64::MAX`
/// until the founder names the epoch, exactly like
/// [`ANCESTRY_SEED_ACTIVATION_EPOCH`]. The new `validator_fee_rewards` state
/// component contributes zero SMT leaves while empty, and its only writer is
/// behind this gate, so pre-gate roots are unchanged by the code carrying it.
///
/// `fee_stake_gate_is_inert` pins the value.
pub const FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for the **slashing-evidence transaction** (§7.3), wire tag `0x05`.
/// `u64::MAX` = INERT: no epoch reaches it, so on every node running this
/// crate today a block that carries tag `0x05` is refused by the transition
/// (`TxReject::EvidenceNotActive`) at every reachable epoch — exactly the
/// verdict an older binary reaches at its decoder, so a mixed fleet agrees on
/// every block until the day.
///
/// # The hole it exists to close (F-02, Round 2)
///
/// §7.3's slashing rules (`slashing.rs`) and the transition's
/// `apply_slashing_evidence` were complete and mutation-tested, and
/// unreachable: the tag-`0x05` encoder used to fold the two conflicting
/// messages in as the *signing roots* they were signed over — hashes, which
/// do not invert — so the decoder answered `EvidenceNotDecodable`
/// unconditionally and no ingress path (block body, gossip, RPC) could carry
/// a proof of equivocation to a verifier. Equivocation therefore had no
/// economic cost, and the Casper security argument did not hold on the live
/// chain. The wire format now carries both envelopes whole (the header or
/// attestation plus its signature, re-verified by every node), so evidence
/// decodes — and THIS constant is what keeps the change inert until the
/// founder schedules it.
///
/// # What the gate switches at one epoch
///
/// - **below** (every epoch today): a block carrying a `SlashingEvidence`
///   transaction is consensus-INVALID (`EvidenceNotActive`), and the node's
///   mempool refuses to admit or relay one (`admissible`);
/// - **at and above**: the evidence transaction becomes valid where the pair
///   proves an offence, and `apply_slashing_evidence` burns the offender's
///   stake, ejects it from the roster and pays the whistleblower's 1/32 —
///   the rules that have been in the tree, tested, since Genesis-4 launch.
///
/// The gate reads the block's own epoch as rolled by `compute_post_state`'s
/// boundary walk — committed state, never a clock. The 2026-08-08
/// `expected_bits` fork is the standing reason.
///
/// # ARMING THIS IS A FOUNDER DECISION, AND IT HAS A PRECONDITION
///
/// The whole fleet must already run a binary whose decoder understands the
/// evidence wire format: below the gate old and new binaries agree (both
/// refuse the block, one at decode and one at the transition), but the first
/// post-gate block that carries evidence is accepted only by nodes that can
/// decode it. Same rollout discipline as `LEAKED_ROSTER_ACTIVATION_EPOCH`.
///
/// `slashing_evidence_gate_is_inert` pins the value.
pub const SLASHING_EVIDENCE_ACTIVATION_EPOCH: u64 = u64::MAX;

/// **Flag day for the transfer dust rule — SHIPS INERT (`u64::MAX`).**
///
/// H-R7-3: the transfer arms accept zero-value outputs, outputs of any
/// value down to 1 sat, and any number of outputs the byte/gas ceilings
/// permit. Every output becomes a PERMANENT `EutxoEntry` (~76 bytes of
/// state each) that every node holds in memory and replays at boot, priced
/// only by the one-time fee on its bytes (~6.4 sat per output at the
/// floor) — unbounded state growth for negligible cost.
///
/// From this epoch the transition refuses, in both transfer formats:
/// - any output below [`MIN_TRANSFER_OUTPUT_SAT`] (zero included) —
///   [`crate::interfaces::TransferReject::DustOutput`];
/// - more than [`MAX_TRANSFER_OUTPUTS`] outputs in one transaction —
///   [`crate::interfaces::TransferReject::TooManyOutputs`].
///
/// Why a flag day at all: both refusals change the verdict on bodies that
/// are VALID today. The historical log may already carry such outputs, and
/// a mixed fleet where only some nodes refuse them is a fork on the first
/// dust transfer after the rollout — the same reasoning as every other
/// gate in this file. The mempool half of the rule
/// (`bloch-pos-node/src/engine.rs`, `admissible`) is node-local policy and
/// is already live ungated: it stops NEW dust propagating without changing
/// any block's validity.
///
/// ARMING THIS (and the two values below) IS A FOUNDER DECISION.
/// `dust_rule_is_inert` pins the inert value.
pub const DUST_RULE_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Minimum value of a single transfer output once
/// [`DUST_RULE_ACTIVATION_EPOCH`] binds — outputs below it (zero included)
/// are refused. 1,000 sat (10 µBLCH at 8 decimals): well above the ~6.4 sat
/// byte-fee of creating the entry, so an output must carry at least two
/// orders of magnitude more value than the fee its creation paid, and small
/// real payments remain untouched. Value subject to the same founder
/// decision that arms the gate.
pub const MIN_TRANSFER_OUTPUT_SAT: u64 = 1_000;

/// Maximum number of outputs one transfer may create once
/// [`DUST_RULE_ACTIVATION_EPOCH`] binds. The byte ceiling already bounds
/// the count indirectly (~6,500 forty-byte outputs in a 262,144-byte
/// block); this bounds what ONE fee-paying transaction may add to the
/// permanent set, so state growth is priced per transaction and not only
/// per block. 256 is far above any observed honest fan-out (the wallet
/// writes 2). Value subject to the same founder decision that arms the
/// gate.
pub const MAX_TRANSFER_OUTPUTS: usize = 256;

/// Flag day for the RANDAO **re-commit** transaction
/// ([`crate::transition::PosTransaction::RandaoRecommit`]) — INERT at
/// `u64::MAX`. **Do not arm without the founder's ruling.**
///
/// # Why this exists: every RANDAO chain is terminal today
///
/// A registration buys exactly [`RANDAO_CHAIN_LENGTH`] = 8,192 reveals
/// (§6.3). One reveal is consumed per **proposed** slot, and when the chain
/// bottoms out at the seed, [`crate::beacon::RevealState::is_exhausted`]
/// makes every further reveal a deterministic reject — the validator can
/// never propose again. `beacon.rs` has said since §6.3 step 4 that the way
/// back is "a re-commit transaction carrying a fresh `c_0`", and
/// [`crate::beacon::RevealState::recommit`] has existed for exactly that —
/// but until this gate landed **no consensus path called it**: no wire tag,
/// no `apply_transaction` arm, nothing. Chains were terminal, and at the
/// launch roster's proposal cadence the first validators exhaust around
/// **2027-02-11** (finding H-R7-1). After the last chain spends, the fleet
/// stops proposing entirely.
///
/// # What arming it enables
///
/// At and above this epoch, `RandaoRecommit` applies: a validator whose
/// chain is EXHAUSTED may install a fresh `c_0`, authorised by a hybrid
/// signature verified in consensus against the pubkey the registry committed
/// at registration (never a key carried in the message), over
/// [`crate::beacon::recommit_signing_root`] — which binds the inclusion
/// epoch, so a captured re-commit cannot be replayed at a later exhaustion.
/// Below this epoch the arm refuses before reading any field, exactly like
/// the `Deposit`/`ExitV2` gates, so today's fleet behaviour is unchanged
/// byte for byte.
///
/// # Arming has the same unmet precondition as `EXIT_AUTH_ACTIVATION_EPOCH`
///
/// The transaction's wire byte (`0x0A`) is claimed encode-side only: the
/// decoder deliberately refuses it until the founder assigns the byte
/// (`tests/wire_tag_registry.rs`). Arming this constant without that
/// assignment activates rules nothing on the wire can reach. Both decisions
/// — the byte and the flag day — are the founder's, and both have a hard
/// deadline: they must be armed, with the fleet rebuilt, **before the first
/// chain exhausts (~2027-02-11)**, or proposal liveness starts decaying
/// validator by validator.
///
/// `randao_recommit_gate_is_inert` pins the value.
pub const RANDAO_RECOMMIT_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for the **declared-size ceiling** on transfers (audit H-R7-2,
/// 2026-09-05): at and above this epoch, a `Transfer`/`TransferV2` whose
/// declared `tx_bytes` exceeds its own canonical encoding by more than
/// [`crate::fee_market::TX_BYTES_DECLARE_SLACK`] is consensus-invalid
/// (`TransferReject::OverdeclaredSize`). Below it, every block is judged
/// byte for byte as today: declaring more than you carry stays legal, you
/// simply pay for it.
///
/// # The defect this closes
///
/// `tx_bytes` is a number the sender writes, bounded below by the encoding
/// (`UnderdeclaredSize`) and above only by `MAX_TX_GAS` — which a full
/// block's worth of bytes clears by construction. The block byte cap
/// (step 10b) sums the DECLARED sizes, while the proposer used to pack by
/// WIRE length, so one small, fully-paid transfer declaring
/// `MAX_BLOCK_TX_BYTES_V2` made every selection carrying it over-cap: the
/// probe loop then popped and BARRED the innocent tail one transaction at a
/// time (`REJECTION_TTL_SLOTS` each) — up to a block's worth of honest
/// transactions censored per slot, for about an hour, per ~85 k-sat
/// transaction. The node side (packing by declared size, refusing gross
/// over-declaration at the mempool door) shipped live because it is policy;
/// THIS gate is the consensus half that stops an adversarial *proposer* from
/// building such a block on purpose.
///
/// The gate reads `CommittedState::epoch` — committed state rolled to the
/// judged block's own `epoch_of(header.slot)`, never a clock. The 2026-08-08
/// `expected_bits` fork is the standing reason.
///
/// # ARMING THIS IS A FOUNDER DECISION
///
/// It is a flag day: the first post-gate block changes the verdict on a
/// transaction shape the old rules accept, so the whole fleet must run a
/// binary carrying this rule before any epoch is named. Ships INERT at
/// `u64::MAX`; `tx_bytes_bound_gate_is_inert` pins the value.
pub const TX_BYTES_BOUND_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for refusing a **duplicate** `(validator, signing_root)`
/// attestation pair within one block body (audit R3 M-2, 2026-09-06).
/// `u64::MAX` = INERT: no epoch reaches it, so on every node running this
/// crate today a body carrying the same pair twice is accepted exactly as it
/// always has been — the second copy simply overwrites the same
/// `pending_votes` entry and the same participation bit the first wrote,
/// which is idempotent, not illegal.
///
/// # The defect this closes, and why it needed a gate at all
///
/// Commit `02fdbd5` (§ step 8 of `Transition::apply_block`) added a
/// consensus-level refusal of a duplicate pair, ungated, alongside the
/// (correctly ungated) hoist of the epoch partition out of the
/// per-attestation loop and the (correctly ungated)
/// [`MAX_ATTESTATIONS_PER_BLOCK`] cap. The cap is provably a no-op on every
/// historical block (see that constant's docs: it equals the wire decoder's
/// own pre-existing bound). **The duplicate refusal carries no such proof.**
/// It rejects a BODY SHAPE — two identical `(validator, signing_root)`
/// entries — that nothing before `02fdbd5` ever forbade in consensus; the
/// argument for its safety rests entirely on "the reference producer's
/// mempool is keyed so it cannot build one", which is a fact about ONE
/// implementation's admission policy, not a consensus rule, and not
/// something this crate can verify against the actual historical block log
/// the way the cap's argument can be checked against the decoder's own
/// constant. A hand-built body, a different producer, or a future codec
/// change could carry a duplicate that an un-gated rule newly rejects,
/// forking a mixed fleet exactly the way every other gate in this file
/// exists to prevent.
///
/// # What the gate switches at one epoch
///
/// - **below** (every epoch today): a body carrying the same `(validator,
///   signing_root)` pair twice is accepted, byte for byte as before
///   `02fdbd5` — the second copy is idempotent, not rejected;
/// - **at and above**: [`crate::interfaces::TransitionError::DuplicateAttestation`]
///   refuses the block, exactly as `02fdbd5` shipped it.
///
/// The gate reads `CommittedState::epoch` — committed state rolled to the
/// judged block's own `epoch_of(header.slot)`, never a clock. The 2026-08-08
/// `expected_bits` fork is the standing reason.
///
/// # ARMING THIS IS A FOUNDER DECISION
///
/// It is a flag day like every other tightening in this file: the whole
/// fleet must run a binary carrying this rule before any epoch is named.
/// Ships INERT at `u64::MAX`; `attestation_dedup_gate_is_inert` pins the
/// value.
pub const ATTESTATION_DEDUP_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for **rewards v2** (audit R1 M1 + M3 + M4, R7 M5, 2026-09-06):
/// one constant, four rules that all change committed state and therefore
/// cannot ship enabled on a mixed fleet. `u64::MAX` = INERT: below it every
/// rule is byte-for-byte the chain as it stands today.
///
/// 1. **Participation credit is scoped to what can actually justify (R1
///    M1).** Below the gate `process_epoch`'s only epoch check on an
///    attestation is `epoch_of(att.data.slot) == st.epoch`; nothing requires
///    `att.data.target_epoch == st.epoch` or `att.data.source_epoch` to name
///    the CURRENT justified checkpoint, and a validator with two DISTINCT
///    signing roots in the epoch (an in-block equivocator, caught by
///    [`SLASHING_EVIDENCE_ACTIVATION_EPOCH`] once THAT arms, not by the
///    reward pass) still earns full credit for whichever landed last. At and
///    above the gate, `close_epoch`'s credit loop additionally requires the
///    target/source binding and withholds credit from a two-signing-root
///    validator.
/// 2. **Issuance basis reads the LEAK-ADJUSTED roster (R1 M3).** Below the
///    gate the issuance loop prices every validator's share off
///    `duty_roster_at` — the same roster [`LEAKED_ROSTER_ACTIVATION_EPOCH`]
///    deliberately does NOT touch, because `consensus_roster_at` (leaked) is
///    reserved for the proposer draw and the committee partition. That
///    reservation is right for WEIGHT but wrong for INCOME: it means the
///    leak costs a validator its committee seat's weight and its proposer
///    slots but not one satoshi of issuance, so a fully-leaked, absent
///    validator earns exactly as much as a fully-present one. At and above
///    the gate, the issuance loop's stake basis is `consensus_roster_at`
///    instead — the same roster the proposer draw already reads, so a
///    leaked validator's income shrinks with its weight.
/// 3. **Delegators earn their pro-rata share of issuance (R1 M4).** Below the
///    gate `close_epoch` calls `rewards::distribute` with `delegated_stake:
///    0, commission_bps: 0` hard-coded, so `Payout::delegators` is always
///    zero and 100% of issuance compounds into the operator's own bond —
///    correct arithmetic fed a wrong question. At and above the gate the
///    call carries the REAL delegated stake (activated satoshis,
///    [`crate::delegation::Registry::activated_sat`]) and the operator's
///    commission, and `Payout::delegators` settles into a new committed
///    ledger, [`crate::transition::CommittedState::delegator_issuance_rewards`]
///    — the issuance mirror of the fee path's `delegator_fee_rewards`,
///    contributing ZERO SMT leaves while empty (every writer is behind this
///    gate) and reachable through its own fresh state-root tag,
///    `state_root::TAG_DELEGATOR_ISSUANCE_REWARD`, which does not alias any
///    tag `0x00..=0x17` already assigned.
/// 4. **Block production earns a measurable slice of the epoch's credit (R7
///    M5).** Below the gate a validator's credit is 1 bit — did its vote
///    land — regardless of whether it produced every block it was
///    scheduled for; `beacon.rs`'s "withholding is priced at the cost of the
///    forfeited proposer reward" argument does not hold on THIS chain,
///    because there is no separate proposer reward to forfeit. At and above
///    the gate, a validator's `max_credits` also counts the epoch's slots it
///    was SCHEDULED to propose (`schedule::proposer` over the closing
///    epoch's own seed and roster — the same draw `apply_block`'s step 7
///    already re-derives to check the header, so this adds no new trust
///    input) and its `credits` counts how many of those it actually
///    produced, so a withheld proposal forfeits a real, measurable slice of
///    that epoch's issuance rather than nothing.
///
/// # Why one constant for four rules
///
/// All four touch the same loop (`close_epoch`'s issuance pass) and the same
/// committed quantities (`current_participation`, `issued_sat`,
/// `ValidatorRecord::staked_sat`); arming them independently would let a
/// fleet run some combination no one designed or tested, and — per the same
/// argument [`EXIT_AUTH_ACTIVATION_EPOCH`] and `DEPOSIT_ACTIVATION_EPOCH`
/// give for their own pairing — every rule that changes issuance is one
/// mixed-fleet fork waiting for one flag day, not several.
///
/// `rewards_v2_gate_is_inert` pins the value.
pub const REWARDS_V2_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for the **fork-choice equivocation retention horizon** (external
/// audit 2026-09-07, O01 — "general order-independence claim is too
/// strong"): `u64::MAX` = INERT, below it the transition keeps a bounded
/// per-validator vote history and judges same-slot equivocation against it.
///
/// # The gap
///
/// [`crate::forkchoice::Store::observe`] compares an incoming vote against
/// ONE retained message per validator — the latest. For votes A = (slot 1,
/// head x), B = (slot 1, head y) and C = (slot 2, head z) from one
/// validator, (A, B) is an equivocation; but if C is observed between them
/// the second old vote is dismissed as merely stale (`prev.slot >=
/// msg.slot`) and the pair is never seen. Of the six arrival orders, ABC and
/// BAC bar the validator; ACB, BCA, CAB and CBA keep C and miss it.
/// `CommittedState::accumulate_forkchoice` rebuilds a `Store` every block
/// from the committed `latest_messages` — one per validator — plus the
/// block's votes, so the committed `fc_equivocators` set (a state-root
/// component) is, in general, a function of the ORDER blocks carried the
/// votes in, not only of which votes exist. The `observe` doc comment
/// claimed the opposite; it is corrected in the same change.
///
/// Today the transition's own admission rules leave that gap unreachable
/// through `apply_block`: step 8 admits only votes of the block's own epoch
/// (`epoch_of(att.data.slot) == st.epoch`) and `committees::epoch_committees`
/// PARTITIONS the roster, seating each validator in exactly one slot per
/// epoch — so a validator has no includable second slot to move its latest
/// message past. That is an invariant of two OTHER modules, not a property
/// of the fork-choice fold, and O01 is right that the fold must not lean on
/// it: the node's own fork choice (`bloch-pos-node/src/engine.rs`) feeds the
/// same `Store` blocks in root order and pool votes in arrival order, where
/// the miss is live today (node-local weight, not committed state).
///
/// # What arming changes
///
/// From this epoch, `accumulate_forkchoice` additionally:
/// 1. retains, per validator, every admitted vote of the most recent
///    [`FORKCHOICE_EQUIVOCATION_HORIZON_SLOTS`] slots in the committed
///    `fc_recent_votes` component (`state_root::TAG_FC_RECENT_VOTE`, one
///    leaf per (validator, slot));
/// 2. bars a validator whose vote names a slot it already has a retained
///    vote for with a DIFFERENT root — regardless of whether a later-slot
///    message has since become its latest — dropping its weight and its
///    history, so the barred set is a function of which votes exist;
/// 3. prunes the history to the horizon below the block's slot, so the
///    component holds at most `validators × horizon` entries.
///
/// Weight semantics are untouched: the latest message still decides weight,
/// exactly as `Store::observe` computes it, and `observe` itself is not
/// changed. Below the gate nothing writes `fc_recent_votes`, so it commits
/// ZERO leaves and every pre-gate root is byte-identical to the chain as it
/// stands — pinned against roots computed on the tree BEFORE this change by
/// `state_root::tests::pre_activation_root_is_byte_identical_with_the_recent_vote_component_present`
/// and `transition::tests::fc_horizon_pre_activation_committed_root_is_the_golden_root`.
///
/// Why a flag day: rule 2 changes a committed component (`fc_equivocators`)
/// on bodies that apply today and rule 1 adds leaves; a mixed fleet forks on
/// the first block after the rollout either way.
///
/// ARMING THIS IS A FOUNDER DECISION.
/// `forkchoice_equivocation_horizon_gate_is_inert` pins the inert value.
pub const FORKCHOICE_EQUIVOCATION_HORIZON_ACTIVATION_EPOCH: u64 = u64::MAX;

/// How many slots of per-validator vote history the committed
/// `fc_recent_votes` component retains once
/// [`FORKCHOICE_EQUIVOCATION_HORIZON_ACTIVATION_EPOCH`] binds: after the
/// block at slot `S` is applied, exactly the slots `S - HORIZON + 1 ..= S`
/// survive (saturating at the chain's first slots).
///
/// One epoch, and one epoch is exactly enough. A vote is includable in the
/// block at slot `S` only if `epoch_of(vote.slot) == epoch_of(S)`
/// (transition.rs step 8) and `vote.slot <= S` (`attestation::validate`,
/// `FutureSlot`), i.e. `vote.slot ∈ [epoch_start(S), S]`; and
/// `S - epoch_start(S) <= SLOTS_PER_EPOCH - 1` for every `S`. So for any
/// block `S'` that could carry a vote for slot `s` — same epoch as `s`,
/// `S' >= s` — `s >= S' - (SLOTS_PER_EPOCH - 1)`, and `s` survives the prune
/// at `S'`. A same-slot conflict can therefore only ever be admitted while
/// the first vote is still retained, which is what makes the detection
/// complete for every includable vote; `fc_horizon_covers_every_includable_slot`
/// walks the claim over the first five epochs, and also shows the bound is
/// tight (an includable slot sits exactly on the floor), so nothing shorter
/// is complete. Anything longer retains votes no block can conflict with
/// any more — the two-epoch figure the finding floats would double the
/// bound for zero detections. If step 8 is ever widened to admit
/// previous-epoch votes (the `previous_participation` window is the obvious
/// temptation), this must grow to `2 * SLOTS_PER_EPOCH` in the same change,
/// and that test is what goes red.
pub const FORKCHOICE_EQUIVOCATION_HORIZON_SLOTS: u64 = SLOTS_PER_EPOCH;

/// Flag day for **staking-transaction metering** (audit R7 M1, 2026-09-06):
/// `u64::MAX` = INERT, below it every staking variant (`Deposit`, `Exit`,
/// `Delegate`, `ExitV2`, `RandaoRecommit`, `SlashingEvidence`) is charged
/// `fee_market::TxCharge { gas: 0, tx_bytes: 0, .. }` exactly as today, and
/// no transaction-COUNT cap exists to consult (see "Not yet closed by this
/// gate" below).
///
/// # The hole this closes
///
/// A body made entirely of staking transactions consumes zero of the block
/// gas cap and zero of the block byte cap — real bytes (the wire decoder's
/// own per-body limit is the only bound today) and real state (a `Deposit`
/// inserts a 3,749-byte pubkey; every variant grows `pending_votes`-adjacent
/// or registry-adjacent maps this crate must serialize into the state root
/// on every later block) priced at nothing. Combined with
/// [`MAX_EPOCH_ADVANCE`]'s docs on the wire decoder being the only bound on
/// body length, a producer that ignores mempool policy (which already
/// refuses most of these — see e.g. [`DEPOSIT_ACTIVATION_EPOCH`]'s docs on
/// `admissible`) could build a body of thousands of these transactions for
/// free.
///
/// # What the gate switches at one epoch
///
/// - **below**: unmetered, byte for byte the chain as it stands;
/// - **at and above**: each staking variant (including `SlashingEvidence`)
///   is charged `fee_market::intrinsic_gas` — flat overhead plus its own
///   `canonical_bytes().len()` plus one `HYBRID_VERIFY_GAS` term per hybrid
///   signature the arm actually verifies (reusing `TxClass::Eutxo{ inputs }`
///   for the shape, since `fee_market` has no dedicated staking class and
///   the cost SHAPE — flat + bytes + N verifications — is identical) — at
///   the block's base fee like a transfer's gas component (no priority
///   fee: nothing here names a tip, and none of these messages spend an
///   eUTXO input to draw one from). Both existing per-block caps
///   (`BlockGasLimitExceeded`, `BlockByteLimitExceeded`) already sum every
///   transaction's charge (step 10b), so making this charge non-zero is
///   what makes them bind on a staking-only body; no new cap is needed for
///   that half.
///
/// **Not yet closed by this gate**: a consensus `MAX_TRANSACTIONS_PER_BLOCK`
/// bound on transaction COUNT (of any kind), independent of the two byte/gas
/// caps. That needs a new `TransitionError` variant, and `TransitionError`
/// is defined in `interfaces.rs`, outside this pass's ownership; the
/// metering half above is complete and gated, the count half is not — flagged
/// here rather than silently dropped.
///
/// The gate reads `CommittedState::epoch` — committed state rolled to the
/// judged block's own `epoch_of(header.slot)`, never a clock. The 2026-08-08
/// `expected_bits` fork is the standing reason.
///
/// # ARMING THIS IS A FOUNDER DECISION
///
/// It is a flag day: the first post-gate block changes the verdict (a body
/// the old rules accepted may now hit `BlockGasLimitExceeded` or
/// `BlockByteLimitExceeded` on staking bytes alone) on a body the old rules
/// accept, so the whole fleet must run a binary carrying this rule before
/// any epoch is named. Ships INERT at `u64::MAX`;
/// `staking_tx_metering_gate_is_inert` pins the value.
pub const STAKING_TX_METERING_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for the **withdrawal transaction** (audit R7 M4, 2026-09-06).
/// `u64::MAX` = INERT, and — unusually for this file — INERT is ALL this
/// constant is today: there is no `PosTransaction::Withdraw` variant and no
/// call site reads this gate. Recorded here rather than left undone.
///
/// # The hole this closes, and it is still open
///
/// `Exit`/`ExitV2` set `withdrawable_epoch`, that field is committed and
/// hashed into the state root, and nothing has ever read it: every genesis
/// bond (1,600,000 BLCH) and the entire validator emission this chain will
/// ever mint (42.85% of total supply, minted directly into `staked_sat`,
/// never into an eUTXO output) is permanently illiquid until a withdrawal
/// path exists.
///
/// # Why this pass ships the gate but not the transaction, in two parts
///
/// 1. **The wire byte.** `PosTransaction`'s variant space is frozen by an
///    EXHAUSTIVE match with no wildcard arm in the unowned
///    `tests/wire_tag_registry.rs` (`frozen_variant_space`) — by design: its
///    own doc comment records having verified that adding ANY new
///    `PosTransaction` variant, under any name or byte, stops that file
///    compiling with `error[E0004]`. `Withdraw` is additionally already a
///    three-way live-branch naming collision in that file's own sweep
///    (claimed at `0x07`, `0x08`, and `0x09` by different unmerged tips) —
///    a second, independent reason the byte is the founder's to assign, not
///    this pass's to guess around.
/// 2. **The record itself has no field for it.** The type `CommittedState`
///    actually stores per validator is `crate::interfaces::ValidatorRecord`
///    (`activation_epoch`, `exit_epoch`, `withdrawable_epoch`,
///    `staked_sat`, `withdrawal_credentials`, …) — and `interfaces.rs` is
///    outside this pass's ownership. It has no `withdrawn` flag, so even
///    with a byte in hand, marking a withdrawal PAID (so it cannot be
///    replayed) would need a field this pass cannot add to the struct
///    consensus actually reads.
///
/// [`crate::staking::validate_withdrawal`] and its own
/// `crate::staking::ValidatorRecord` (a self-contained, fully-tested
/// predicate — exited, past `withdrawable_epoch`, not already withdrawn —
/// returning `(withdrawal_addr, amount_sat)`) exist as ready-made logic for
/// whoever lands both of the above: they operate on staking.rs's OWN record
/// shape, not on `interfaces::ValidatorRecord`, precisely because this pass
/// cannot commit a `withdrawn` bit to the real one. Wiring them in means
/// resolving (1) and (2) first, in a pass that owns `interfaces.rs` and
/// `tests/wire_tag_registry.rs`.
///
/// # ARMING THIS IS A FOUNDER DECISION, AND IT HAS A PRECONDITION
///
/// This constant gates NOTHING today (see above) — arming it changes no
/// behaviour on its own. Ships INERT at `u64::MAX`; `withdrawal_gate_is_inert`
/// pins the value, and `the_withdrawal_gate_is_a_function_of_the_block_epoch_alone`
/// pins the (currently orphaned) predicate against regressing before the
/// day it is actually wired to a transaction arm.
pub const WITHDRAWAL_ACTIVATION_EPOCH: u64 = u64::MAX;

/// Flag day for **network-bound transfer signing** (audit A2-3 / R7 M2,
/// 2026-09-06): `u64::MAX` = INERT, below it `DS_SPEND`'s preimage is
/// unchanged and every signing root this crate has ever computed replays
/// identically.
///
/// # The hole this closes
///
/// `DS_SPEND` is a PROTOCOL-VERSION tag, identical on every network built
/// from this crate — no chain id, no genesis root, no nonce. A2 §3 argued
/// cross-chain replay of ordinary transfers is blocked in practice because
/// `parent`/`state_root`/`head` diverge across chains, but that argument
/// does not reach a CARRYOVER outpoint: `Manifest::allocation_outputs`
/// derives allocation txids as a pure function of the manifest, so any two
/// networks opened from the same Genesis-3 snapshot share hundreds of
/// thousands of IDENTICAL outpoints with identical `script_hash`es, and a
/// transfer signed on one is byte-for-byte valid on the other for as long as
/// the outpoint is unspent on both — the classic ETH/ETC replay shape,
/// reachable by any contentious fork, testnet, or re-launch from the same
/// carryover artifact.
///
/// # What the gate switches at one epoch
///
/// - **below**: `spend_signing_root`'s fold is unchanged — the same
///   `(n_spends, spend points, outputs, tx_bytes, tip)` preimage under
///   `DS_SPEND`, byte for byte;
/// - **at and above**: the fold additionally covers a network-binding value
///   (see [`crate::transition::PosTransaction::network_binding`]) under a NEW, distinct
///   16-byte tag, `DS_SPEND2` (`b"BLCH4:SPEND2\0\0\0\0"` — not a prefix of
///   `DS_SPEND` and not prefixed by it, since both are exactly 16 bytes with
///   different content), so a signature becomes a statement about one
///   transfer on ONE chain. V1 and V2 share the fold (one function, both
///   callers), so `txid` — derived from the witness-free signing root —
///   stays witness-free in both formats.
///
/// The gate reads `CommittedState::epoch` — committed state rolled to the
/// judged block's own `epoch_of(header.slot)`, never a clock. The 2026-08-08
/// `expected_bits` fork is the standing reason.
///
/// # ARMING THIS IS A FOUNDER DECISION, AND IT MUST BE ANNOUNCED
///
/// Unlike every other gate in this file, arming this one does not merely
/// change which NEW transactions are valid — it changes the signing root of
/// every UNSPENT output as of the flag day, invalidating any pre-signed
/// transaction nobody has broadcast yet. It is a flag day in the same
/// mixed-fleet sense as the others (the whole fleet must run a binary
/// carrying the new fold first), plus a wallet-facing announcement the
/// others do not need. Ships INERT at `u64::MAX`;
/// `sighash_network_binding_gate_is_inert` pins the value.
pub const SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH: u64 = u64::MAX;

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
/// The network-bound spend signing root domain (audit A2-3 / R7 M2), used
/// once [`SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH`] binds instead of
/// [`DS_SPEND`] — its own tag, not a suffix or a reuse of `DS_SPEND`'s bytes,
/// because a fold under one domain must never collide with a fold under
/// another even when one is a strict superset of the other's preimage
/// fields (the same reasoning `DS_SPEND` itself documents). 16 bytes, and
/// distinct from every other tag in this table at the twelfth byte
/// (`'2'` vs `DS_SPEND`'s trailing `\0`), so neither can ever be mistaken
/// for the other.
pub const DS_SPEND2: [u8; 16] = *b"BLCH4:SPEND2\0\0\0\0";
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

/// Independent flag day for funded validator admission (wire 0x0B).
/// Deliberately unarmed pending a coordinated consensus release. This never
/// enables the unfunded legacy Deposit/Delegate formats. No runtime override.
pub const FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH: u64 = u64::MAX;

pub fn funded_validator_admission_active(epoch: u64) -> bool {
    #[cfg(test)]
    if funded_admission_rehearsal::enabled() { return true; }
    FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH != u64::MAX
        && epoch.checked_sub(FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH).is_some()
}

#[cfg(test)]
pub(crate) mod funded_admission_rehearsal {
    use std::cell::Cell;
    thread_local! { static ENABLED: Cell<bool> = const { Cell::new(false) }; }
    pub fn enabled() -> bool { ENABLED.with(Cell::get) }
    pub fn run<T>(f: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore { fn drop(&mut self) { ENABLED.with(|v| v.set(self.0)); } }
        let _restore = Restore(ENABLED.with(|v| v.replace(true)));
        f()
    }
}
