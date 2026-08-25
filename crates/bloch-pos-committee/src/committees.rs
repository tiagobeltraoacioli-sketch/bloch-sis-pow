// SPDX-License-Identifier: AGPL-3.0-or-later

//! Epoch committees — the active set **partitioned**, not sampled.
//!
//! # The bug this replaces
//!
//! The first design sampled 128 validators to vote at the epoch boundary. The
//! adversarial review (finding F1) showed the quorum denominator had no
//! coherent reading, and that both candidates fail:
//!
//! - **Denominator = network stake.** A 128-validator sample cannot hold two
//!   thirds of the network's stake once the network has more than ~192
//!   validators — and gate G4 *requires* at least 200. Finality would be
//!   structurally unreachable and the inactivity leak would fire forever.
//! - **Denominator = committee stake.** A 128-member sample has enough variance
//!   that an adversary holding ~30% of network stake exceeds one third of the
//!   committee in roughly one epoch in five, and can stall finality well below
//!   the nominal threshold.
//!
//! # The fix
//!
//! Partition instead of sampling: shuffle the active set deterministically and
//! cut it into [`SLOTS_PER_EPOCH`] committees, one per slot. Every active
//! validator lands in exactly one committee and votes exactly once per epoch,
//! so the union of an epoch's committees **is** the active set. The quorum
//! denominator is then total active stake with no ambiguity and no sampling
//! variance — the same property Ethereum gets, and for the same reason.
//!
//! This also removes finding F2. Under independent per-slot draws a validator
//! was routinely selected in several slots of one epoch, emitting several
//! attestations with the same `target_epoch` — which
//! [`crate::attestation::AttestationData::is_double_vote`] correctly flags as a
//! slashable double vote. Honest validators slashed themselves. Under a
//! partition each validator attests once per epoch, so two attestations sharing
//! a target epoch really are equivocation.
//!
//! # What it costs
//!
//! Per epoch the network carries one hybrid signature per active validator
//! (≈ 4,589 B), against 384 under the sampled design. **Partitioning is cheaper
//! below 384 validators** — which is where gate G4 puts the launch — and more
//! expensive above it. That is the honest trade: correctness now, and a scaling
//! ceiling at roughly 4,096 validators (128 per slot, ≈ 574 KB/slot) where
//! sub-sampling would have to return and F1 with it. Aggregation would lift the
//! ceiling, and the measured in-circuit cost (`spikes/prover-cost/RESULTS.md`)
//! says that is research, not engineering.
//!
//! # Which mix seeds which epoch
//!
//! The partition for epoch `N` is seeded by the mix fixed at the close of
//! epoch `N − 1 − `[`MIN_SEED_LOOKAHEAD_EPOCHS`] — see the constant's docs for
//! the attack this closes (finding F6: trailing-slot withholding re-sorting
//! the next epoch's partition) and the residual it does not.

use crate::params::{DS_SORTITION, SLOTS_PER_EPOCH};
use crate::sample::Validator;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Role tag for the epoch partition. Distinct from the sortition roles so the
/// partition can never coincide with a proposer draw.
const ROLE_PARTITION: u8 = 0x03;

// ────────────────────────────────────────────────────────────────────────────
// Seed look-ahead (finding F6)
// ────────────────────────────────────────────────────────────────────────────

/// Seed look-ahead, in epochs (adversarial review, finding F6).
///
/// The partition for epoch `N` is seeded by the beacon mix as fixed at the
/// **close of epoch `N − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`** — with a look-ahead
/// of one, the close of epoch `N − 2`. Ethereum's `MIN_SEED_LOOKAHEAD` is the
/// same device at the same value, for the same reason.
///
/// **What it closes.** Without the look-ahead, epoch `N` was seeded by the mix
/// at the close of epoch `N − 1`, so whoever proposed the last `t` slots of
/// `N − 1` could choose reveal-or-withhold per slot, grind `2^t` candidate
/// mixes, and pick the one whose epoch-`N` partition placed the most of their
/// own validators where they wanted them — re-sorting the body that decides
/// finality, not just one proposer slot. With the look-ahead, the seed for
/// epoch `N` is already fixed before epoch `N − 1` begins: **no slot the
/// adversary proposes in `N − 1` can influence `N`'s partition at all.**
///
/// **What it does not close — stated so nobody reads more into it.** The
/// last-revealer bias is displaced, not eliminated: the trailing proposers of
/// epoch `E` still bias the partition of epoch `E + 1 + MIN_SEED_LOOKAHEAD_EPOCHS`
/// by the standard one bit per withheld slot (§6.3), at the price of the
/// forfeited proposer rewards. That residual is inherent to RANDAO and is the
/// same one Ethereum accepts. Raising the look-ahead does not shrink it; it
/// only moves the target epoch further out.
///
/// **What it costs.** Duties become computable earlier: the schedule for epoch
/// `N` is public from the close of `N − 2`, widening the F7 DoS warning window
/// from one epoch to two (~32 min). That trade is deliberate — grinding the
/// finality partition is strictly worse than a longer warning for a DoS
/// surface that is public by design anyway (§6.4).
pub const MIN_SEED_LOOKAHEAD_EPOCHS: u64 = 1;

/// The epoch whose **closing** mix seeds `epoch`'s partition:
/// `epoch − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`.
///
/// `None` for the first `MIN_SEED_LOOKAHEAD_EPOCHS + 1` epochs, which have no
/// usable boundary behind them and are seeded by the genesis mix instead
/// (see [`seed_mix`]). Those early epochs still partition differently from
/// each other because the epoch number is folded into the XOF seed.
pub const fn seed_epoch(epoch: u64) -> Option<u64> {
    epoch.checked_sub(MIN_SEED_LOOKAHEAD_EPOCHS + 1)
}

/// Select the mix that seeds `epoch`'s partition out of committed beacon
/// history.
///
/// `boundary_mixes[e]` must be the accumulated mix at the **close** of epoch
/// `e` — i.e. after the reveal of `e`'s last non-skipped slot was folded in.
/// This slice-from-genesis shape is the reference form; a node only ever needs
/// the last `MIN_SEED_LOOKAHEAD_EPOCHS + 1` boundary mixes at once (that is
/// exactly the two-epoch retention `StateReader::randao_mix_at` commits to).
///
/// Returns `None` when the needed boundary mix is missing from the slice.
/// Missing history is a caller bug and must fail loudly: silently falling
/// back to a newer mix would reintroduce F6 in the fallback path.
pub fn seed_mix(
    genesis_mix: &[u8; 32],
    boundary_mixes: &[[u8; 32]],
    epoch: u64,
) -> Option<[u8; 32]> {
    match seed_epoch(epoch) {
        None => Some(*genesis_mix),
        Some(e) => boundary_mixes.get(e as usize).copied(),
    }
}

/// [`epoch_committees`] with the F6 look-ahead applied — the safe entry point.
///
/// Callers that already hold the correct seed (because the beacon layer
/// selected it) may call [`epoch_committees`] directly; every other caller
/// should go through here so the mix-to-epoch binding is decided in exactly
/// one place. `None` propagates [`seed_mix`]'s missing-history failure.
pub fn seeded_epoch_committees(
    genesis_mix: &[u8; 32],
    boundary_mixes: &[[u8; 32]],
    epoch: u64,
    validators: &[Validator],
) -> Option<Vec<Vec<u32>>> {
    let mix = seed_mix(genesis_mix, boundary_mixes, epoch)?;
    Some(epoch_committees(&mix, epoch, validators))
}

/// Mutation switch for the roster-split regression. `cfg(test)`, so it cannot
/// exist in a shipped binary — same idiom as
/// [`crate::params::rehearsal::MUTATE_SEED`] and
/// `finality`'s `IGNORE_LEAK_IN_DENOMINATOR`.
///
/// `true` restores the pre-2026-08-24 `effective_stake > 0` filter *before* the
/// shuffle, i.e. it puts the defect back. A regression test that cannot be made
/// to fail is not testing anything, so
/// `tests::rehearsal_restoring_the_filter_reopens_the_roster_split` flips this
/// and proves the pinning assertion goes red.
///
/// Constant `false` in every build that is not a test build, so the branch in
/// [`epoch_committees`] folds away.
#[inline]
fn mutation_restores_zero_stake_filter() -> bool {
    #[cfg(test)]
    {
        return crate::params::rehearsal::RESTORE_ZERO_STAKE_FILTER
            .load(std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(not(test))]
    false
}

/// Partition the active set into one committee per slot of `epoch`.
///
/// `beacon_mix` must be the seed selected by [`seed_mix`] — the mix at the
/// close of epoch `epoch − 1 − MIN_SEED_LOOKAHEAD_EPOCHS`, not the current
/// mix. Passing a later mix reintroduces finding F6: the trailing proposers
/// of the previous epoch regain the power to re-sort this epoch's partition
/// by withholding reveals. [`seeded_epoch_committees`] does the selection.
///
/// Returns `SLOTS_PER_EPOCH` committees, each sorted ascending, together
/// covering every eligible validator exactly once. Committee `i` serves slot
/// `i` of the epoch: its members carry that slot's fork-choice weight, and
/// their votes accumulate toward the epoch's justification.
///
/// # Membership is a pure function of the index set — stake decides WEIGHT only
///
/// Every validator in `validators` gets a seat. There is **no stake filter**
/// here, and the absence is load-bearing rather than an oversight: it is what
/// makes the partition *leak-invariant*, so no call path can change the
/// committees by holding a different variant of the same roster.
///
/// Until 2026-08-24 this function filtered `effective_stake > 0` **before** the
/// Fisher-Yates shuffle. A shuffle's XOF draws are length-dependent, so a list
/// of 64 and a list of 63 are not "the same permutation minus one element" —
/// they are entirely different permutations. `transition.rs` holds two rosters
/// for one epoch (`consensus_roster_at`, leak-applied, and `duty_roster_at`,
/// not), and `with_leak_applied` uses `saturating_sub`, which *keeps* a
/// fully-leaked validator at `effective_stake = 0` rather than dropping it. So
/// the moment the inactivity leak zeroed anybody, the two rosters reached this
/// function at different lengths, the inclusion check at step 8 of
/// `compute_post_state` and the boundary tally in `close_epoch` partitioned
/// differently, and attestations the block had *admitted* were dropped at the
/// tally. Measured: 63 of 64 honest validators voting the same root, the
/// boundary keeping 4 of them (6.3%), justification `None`. Pinned by
/// `finality::tests::a_single_fully_leaked_validator_makes_the_two_rosters_partition_differently`.
///
/// Why the filter was removed rather than the leaked validator dropped on both
/// paths — the four reasons, in the order that decided it:
///
/// 1. **The filter had no other live effect.** `duty_roster_at`
///    (transition.rs) already excludes slashed, pre-activation and exited
///    records; they never reach this function. Dropping leaked-to-zero
///    validators was the filter's *only* remaining behaviour — i.e. it existed
///    only to cause this bug.
/// 2. **Leak-invariance by construction.** The leaked and unleaked rosters
///    carry the same index set and differ only in stake. With no filter, the
///    permutation cannot see the difference, so the two call paths cannot
///    diverge no matter which variant each one happens to hold.
/// 3. **The alternative touches quorum arithmetic.** Dropping the zeroed
///    validator on both paths would require the finality path to apply the
///    leak too — but `finality::process_epoch` re-subtracts its own `leaked`
///    map from whatever roster it is handed, so feeding it a leak-applied
///    roster double-charges the quorum denominator. More risk, less coverage,
///    in the exact arithmetic that decides finality.
/// 4. **It fixes the class, not the instance.** `derive::active_validators`
///    is a fourth roster producer: registry stake only, no delegation, no
///    cohort cap, no leak, and no zero-stake filter. No amount of leak
///    bookkeeping can make it agree with `transition.rs`, because it has no
///    leak information at all. With the filter gone, all four producers
///    compute the same membership predicate — `activation_epoch <= epoch
///    && epoch < exit_epoch && !slashed` — and therefore the same partition.
///
/// That last point is not theoretical. A FIFTH divergent view was measured on
/// 2026-08-24: an 8.27% weight asymmetry between the stake table
/// `forkchoice_head` feeds LMD-GHOST (the node's OWN head state) and the
/// `staked_sat` that `close_epoch` inflates for validators that attested on the
/// branch that node happened to apply. It is real, it is out of scope here, and
/// it is the same shape as this defect: a consensus quantity derived from a
/// node-local view of which roster is the roster. Every producer this crate can
/// make agree by construction, it should — which is the argument for making
/// membership a function of the index set and nothing else.
///
/// **A zero-weight member holds an INERT seat.** Quorum is stake-weighted over
/// the whole active set (`finality`'s `total_active`), so a zero-stake member
/// contributes 0 to the numerator and 0 to the denominator. The liveness the
/// inactivity leak buys back comes from the shrinking denominator and from
/// proposer selection (`schedule::sample` is stake-weighted and still never
/// draws a zero-stake validator) — never from committee membership. Being in a
/// committee is permission to be counted, not weight.
///
/// **The residual, stated rather than filtered.** A validator with genuinely
/// zero stake — not merely leaked to zero — would now take an inert seat. Every
/// runtime path that can create a validator record forbids that state:
/// `staking::validate_deposit` and the `Deposit` handler both reject below
/// `MIN_DEPOSIT_SAT` (25,000 BLCH); `staked_sat` thereafter only ever grows,
/// except in `apply_slashing_evidence`, which sets `slashed = true` in the same
/// statement and so removes the record from every roster; and
/// `genesis_cohort::apply_cohort_cap` cannot scale a member to zero, because
/// `s_i * cap / S` needs `s_i * cap < S`, and with `s_i >= MIN_DEPOSIT_SAT`
/// (2.5e12 sat) and `cap >= MIN_DEPOSIT_SAT / 2` (the deferral floor) the
/// numerator is >= 3.1e24 while `S` is bounded by the whole V4 supply, 1e19.
/// The one remaining producer is a hand-written genesis config, which does not
/// check `staked_sat` — an operator error, not an attacker-reachable state, and
/// its whole effect is one inert zero-weight seat. It is deliberately NOT
/// filtered here: a stake predicate in this function is what the four producers
/// cannot share, which is finding 4 above rebuilt.
///
/// Sizes differ by at most one. Members are assigned by count, not by stake,
/// which is safe because `MAX_VALIDATOR_STAKE` already caps any single
/// validator at 1% of active stake: no committee can be dominated by one member
/// unless the cap itself has been defeated.
pub fn epoch_committees(
    beacon_mix: &[u8; 32],
    epoch: u64,
    validators: &[Validator],
) -> Vec<Vec<u32>> {
    let n_slots = SLOTS_PER_EPOCH as usize;

    // Canonicalise before anything else. The order the caller happened to hold
    // the registry in must never reach the result — the same rule the sampler
    // learned the hard way.
    let mut eligible: Vec<u32> = validators
        .iter()
        // NO STAKE FILTER — see the "Membership is a pure function of the
        // index set" section above. The only thing that reads stake in this
        // function is the mutation hook above, and that is `cfg(test)`.
        .filter(|v| !mutation_restores_zero_stake_filter() || v.effective_stake > 0)
        .map(|v| v.index)
        .collect();
    eligible.sort_unstable();
    eligible.dedup();

    if eligible.is_empty() {
        return vec![Vec::new(); n_slots];
    }

    let mut xof = {
        let mut h = Shake256::default();
        h.update(&DS_SORTITION);
        h.update(beacon_mix);
        h.update(&epoch.to_le_bytes());
        h.update(&[ROLE_PARTITION]);
        h.finalize_xof()
    };

    // Fisher-Yates over the canonical order. Each draw is reduced by rejection
    // rather than by `%`: a modulo would bias low indices toward the tail of the
    // shuffle, which is a bias in committee membership, not a rounding detail.
    let len = eligible.len();
    for i in (1..len).rev() {
        let bound = (i + 1) as u128;
        let limit = (u128::MAX / bound) * bound;
        let j = loop {
            let mut buf = [0u8; 16];
            xof.read(&mut buf);
            let v = u128::from_le_bytes(buf);
            if v < limit {
                break (v % bound) as usize;
            }
            // A rejected draw still consumes XOF output, keeping the stream
            // position a deterministic function of the inputs.
        };
        // The mutation switch that gives the epoch-partition invariant a real
        // input: duplicate one index, lose another, keep the length. `false` in
        // every build that is not a test build, so this folds away.
        #[cfg(test)]
        if crate::params::rehearsal::PARTITION_DUPLICATES_AN_INDEX
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            eligible[i] = eligible[j];
            continue;
        }
        eligible.swap(i, j);
    }

    // Cut into contiguous chunks. Sizes differ by at most one, and the larger
    // chunks go to the earliest slots — an arbitrary choice, but identical on
    // every node, which is the only property that matters.
    let base = len / n_slots;
    let extra = len % n_slots;
    let mut out = Vec::with_capacity(n_slots);
    let mut pos = 0usize;
    for slot in 0..n_slots {
        let take = base + usize::from(slot < extra);
        let mut c: Vec<u32> = eligible[pos..pos + take].to_vec();
        pos += take;
        c.sort_unstable();
        out.push(c);
    }
    out
}

/// The committee serving `slot` within its epoch.
///
/// Same seed contract as [`epoch_committees`]: `beacon_mix` is the F6-selected
/// seed for the slot's epoch, not the current mix.
pub fn committee_for_slot(
    beacon_mix: &[u8; 32],
    slot: u64,
    validators: &[Validator],
) -> Vec<u32> {
    let epoch = slot / SLOTS_PER_EPOCH;
    let idx = (slot % SLOTS_PER_EPOCH) as usize;
    epoch_committees(beacon_mix, epoch, validators)
        .into_iter()
        .nth(idx)
        .unwrap_or_default()
}

/// Total active stake — **the quorum denominator**, stated once so it cannot be
/// read two ways.
///
/// Justification requires attesting stake `w` with `3·w ≥ 2·total_active_stake`,
/// where the total is over the whole active set, not over any committee. That is
/// only a coherent rule because the epoch's committees partition the active set:
/// every validator gets exactly one chance to contribute, so the denominator is
/// reachable by construction.
pub fn total_active_stake(validators: &[Validator]) -> u128 {
    validators.iter().map(|v| v.effective_stake as u128).sum()
}

/// Does `stake_for` meet the two-thirds threshold of `total_active_stake`?
///
/// Integer form `3·w ≥ 2·total` — never floating point, and never
/// `w >= total * 2 / 3`, whose truncation admits a quorum one satoshi short.
/// Rounding here is consensus.
pub fn is_supermajority(stake_for: u128, total_active_stake: u128) -> bool {
    total_active_stake > 0 && stake_for.saturating_mul(3) >= total_active_stake.saturating_mul(2)
}

// ────────────────────────────────────────────────────────────────────────────
// The roster unification, pinned
// ────────────────────────────────────────────────────────────────────────────
//
// These are unit tests, not integration tests in `tests/committee.rs`, for one
// reason: the mutation switch is `#[cfg(test)]`, and `#[cfg(test)]` items do
// not exist in the library an integration test links against. A mutation that
// can be reached from `tests/` is a mutation that exists in a shipped binary.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::rehearsal::{HOOK, RESTORE_ZERO_STAKE_FILTER};
    use std::sync::atomic::Ordering::Relaxed;

    const STAKE: u64 = 32_000 * 100_000_000;

    fn set(n: u32) -> Vec<Validator> {
        (0..n).map(|index| Validator { index, effective_stake: STAKE }).collect()
    }

    /// `transition::with_leak_applied`'s exact shape: `saturating_sub`, so a
    /// fully-leaked validator STAYS in the list at `effective_stake = 0`.
    fn with_leak(roster: &[Validator], zeroed: &[u32]) -> Vec<Validator> {
        roster
            .iter()
            .map(|v| Validator {
                index: v.index,
                effective_stake: if zeroed.contains(&v.index) {
                    v.effective_stake.saturating_sub(v.effective_stake.saturating_mul(2))
                } else {
                    v.effective_stake
                },
            })
            .collect()
    }

    /// The assertion the fix exists to make true, factored out so the mutation
    /// test below can run *this exact body* with the defect restored and show
    /// it panic. A regression test that cannot be made to fail is not testing
    /// anything.
    fn assert_the_two_rosters_partition_identically() {
        let seed = [0x5Au8; 32];
        for epoch in [0u64, 1, 7, 1_400] {
            // `duty_roster_at`-shaped: no leak, 64 validators, all funded.
            let duty = set(64);
            // `consensus_roster_at`-shaped: the same 64 indices, with the
            // inactivity leak having eaten one validator's whole stake.
            let consensus = with_leak(&duty, &[7]);
            assert_eq!(
                consensus.len(),
                duty.len(),
                "the leak must not drop the record — if it did, this test is not \
                 exercising the shape transition.rs actually produces"
            );
            assert_eq!(
                consensus.iter().find(|v| v.index == 7).unwrap().effective_stake,
                0,
                "fixture must actually zero somebody"
            );

            let boundary = epoch_committees(&seed, epoch, &duty);
            let step8 = epoch_committees(&seed, epoch, &consensus);
            assert_eq!(
                step8, boundary,
                "epoch {epoch}: the leaked and unleaked rosters must partition \
                 identically — membership is (seed, epoch, index set), stake is weight"
            );
            // And the zeroed validator keeps an inert seat rather than vanishing.
            assert!(
                step8.iter().any(|c| c.contains(&7)),
                "epoch {epoch}: the fully-leaked validator must keep its (zero-weight) seat"
            );
            assert_eq!(
                step8.iter().map(Vec::len).sum::<usize>(),
                64,
                "epoch {epoch}: the partition must still cover the whole roster once"
            );
        }
    }

    /// The two call paths in `transition.rs` — step 8's `consensus_roster_at`
    /// and `close_epoch`'s `duty_roster_at` — must produce IDENTICAL
    /// committees, with and without a fully-leaked validator present.
    ///
    /// Asserted against the real production function, not a reimplementation.
    #[test]
    fn the_two_rosters_partition_identically_with_and_without_a_leaked_validator() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        assert_the_two_rosters_partition_identically();
    }

    /// **MUTATION TEST.** Restore the pre-2026-08-24 `effective_stake > 0`
    /// filter before the shuffle — the defect — and the assertion above must go
    /// red. Run it and watch it happen:
    ///
    /// ```text
    /// cargo test -p bloch-pos-committee --lib \
    ///   committees::tests::rehearsal_restoring_the_filter_reopens_the_roster_split \
    ///   -- --nocapture
    /// ```
    ///
    /// The panic is caught rather than allowed to fail the run, so the suite
    /// stays green while still proving the pinning assertion is load-bearing.
    /// The switch is `#[cfg(test)]`, so it cannot exist in a shipped binary.
    #[test]
    fn rehearsal_restoring_the_filter_reopens_the_roster_split() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());

        // Control first: with the mutation OFF the assertion passes. Without
        // this half, a panic below could be coming from anywhere.
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        assert_the_two_rosters_partition_identically();

        RESTORE_ZERO_STAKE_FILTER.store(true, Relaxed);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // the failure is the result, not noise
        let red = std::panic::catch_unwind(assert_the_two_rosters_partition_identically);
        std::panic::set_hook(prev);
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);

        let msg = red
            .err()
            .map(|e| {
                e.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default()
            })
            .expect(
                "MUTATION DID NOT GO RED: the zero-stake filter was restored and the two \
                 rosters still partitioned identically. Either the mutation switch is not \
                 wired into epoch_committees any more, or the assertion is vacuous.",
            );
        println!("MUTATION WENT RED, as it must. First failure:\n  {msg}");

        // And the measurement, so the size of the defect is on the record and
        // not just its existence.
        RESTORE_ZERO_STAKE_FILTER.store(true, Relaxed);
        let duty = set(64);
        let consensus = with_leak(&duty, &[7]);
        let seed = [0x5Au8; 32];
        let step8 = epoch_committees(&seed, 1, &consensus);
        let boundary = epoch_committees(&seed, 1, &duty);
        let admitted: usize = step8.iter().map(Vec::len).sum();
        let agreeing: usize = step8
            .iter()
            .zip(boundary.iter())
            .map(|(a, b)| a.iter().filter(|v| b.binary_search(*v).is_ok()).count())
            .sum();
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        println!(
            "WITH THE DEFECT RESTORED: of {admitted} attestations step 8 would admit, the \
             boundary partition still seats {agreeing} in the same slot ({:.1}%). One \
             validator at zero stake was enough.",
            agreeing as f64 / admitted as f64 * 100.0
        );
        assert!(
            agreeing * 3 < admitted,
            "the restored defect kept {agreeing} of {admitted} in place — if most survive, \
             this mutation is not reproducing the mechanism it names"
        );
    }

    /// Property: for a random index set and a random leak pattern, **membership
    /// is invariant under any stake change that does not change the index
    /// set.** Only the weights may move.
    ///
    /// Deterministic LCG rather than a random source: a property test in a
    /// consensus crate that cannot be replayed from its seed is a flake
    /// generator.
    #[test]
    fn membership_is_invariant_under_any_stake_change() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);

        let mut rng: u64 = 0x2026_0824_DEAD_BEEF;
        let mut next = move || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            rng >> 11
        };

        for case in 0..200u32 {
            // A random index set — sparse indices, not 0..n, so the test also
            // covers the case where the index is not the position.
            let n = 1 + (next() % 96) as usize;
            let mut idx: Vec<u32> = Vec::with_capacity(n);
            let mut cursor = 0u32;
            for _ in 0..n {
                cursor = cursor.wrapping_add(1 + (next() % 5) as u32);
                idx.push(cursor);
            }

            let base: Vec<Validator> = idx
                .iter()
                .map(|&index| Validator { index, effective_stake: 1 + (next() % 1_000_000) as u64 })
                .collect();
            // Arbitrary stake perturbation over the SAME index set: some
            // validators fully leaked to zero, others rescaled.
            let perturbed: Vec<Validator> = base
                .iter()
                .map(|v| Validator {
                    index: v.index,
                    effective_stake: match next() % 3 {
                        0 => 0,
                        1 => v.effective_stake.saturating_mul(1 + (next() % 64)),
                        _ => v.effective_stake / (1 + (next() % 8)),
                    },
                })
                .collect();
            let epoch = next() % 4_096;
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&next().to_le_bytes());
            assert_eq!(
                epoch_committees(&seed, epoch, &base),
                epoch_committees(&seed, epoch, &perturbed),
                "case {case}: membership moved under a pure stake change (n={n}, epoch={epoch})"
            );
        }
        // The all-zero end of the range is not left to the generator — at
        // n up to 96 it would fire in maybe half of runs, which is a flake,
        // not coverage. It has its own test below.
    }

    /// The degenerate end of the same rule: an all-zero-stake roster is still
    /// seated. It used to collapse to 32 empty committees, which is how a
    /// stake filter turns "everyone is broke" into "the epoch has no
    /// committees at all".
    #[test]
    fn an_all_zero_stake_roster_is_still_partitioned() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        let zeroed: Vec<Validator> =
            (0..40u32).map(|index| Validator { index, effective_stake: 0 }).collect();
        let cs = epoch_committees(&[0x11u8; 32], 3, &zeroed);
        assert_eq!(cs.iter().map(Vec::len).sum::<usize>(), 40);
        // Weight, however, is still zero — the seats are inert.
        assert_eq!(total_active_stake(&zeroed), 0);
        assert!(!is_supermajority(0, total_active_stake(&zeroed)));
        // An genuinely empty set is still 32 empty committees, unchanged.
        let empty = epoch_committees(&[0x11u8; 32], 3, &[]);
        assert!(empty.iter().all(Vec::is_empty));
        assert_eq!(empty.len(), SLOTS_PER_EPOCH as usize);
    }
}
