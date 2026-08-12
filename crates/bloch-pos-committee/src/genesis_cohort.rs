// SPDX-License-Identifier: AGPL-3.0-or-later

//! The genesis validator cohort and its declining cap.
//!
//! # What this enforces
//!
//! The chain launches with a validator set the founder funds and operates —
//! there is no other option, since a fresh genesis has no PoW to seed it and
//! deposits need blocks that need validators (tokenomics §3.3). That is a
//! centralised start, by construction.
//!
//! The founder's commitment is that it does not stay that way: **within one
//! year the founder's consensus weight falls below one third**. This module is
//! that commitment expressed as a consensus rule rather than a promise.
//!
//! # Why one third, specifically
//!
//! It is not a round number chosen for looking modest. One third is exactly the
//! share that can stall a two-thirds quorum — the threshold at which a single
//! actor stops being able to *prevent* finality. Above it, the founder can
//! freeze the chain unilaterally; below it, the founder cannot. The rule says,
//! in one number: after year one, the founder cannot halt Bloch alone.
//!
//! (Note what it does **not** say. One third is the *liveness* threshold, not
//! the *safety* one — that is two thirds. Falling under a third stops the
//! founder stalling finality; it never stopped anyone from finalising a bad
//! state, which needs 2/3 and is out of reach either way.)
//!
//! # How it is enforced, and where enforcement stops
//!
//! The cohort is a **fixed set published in the genesis block**. It can only
//! shrink — validators leave it by exiting, and nothing can be added. So the
//! set is auditable by anyone, forever, with no list-writing power retained by
//! anybody: unlike a taint list, this one is written once, in public, and only
//! against the founder's own validators.
//!
//! Their **combined** effective stake is capped, and the cap declines linearly
//! from the whole set at genesis to one third at one year, then holds. Stake
//! above the cap earns nothing and carries no weight; it is not confiscated.
//!
//! **Where this stops working, stated plainly:** the cap binds the genesis
//! cohort. Nothing prevents the founder from funding *new* validators after
//! genesis under addresses that are not in the cohort, and no on-chain rule can
//! see beneficial ownership behind them. Past the cohort, the one-third figure
//! is a commitment that has to be verified externally — by the Foundation's
//! reporting rule (`BLOCH-ENTITY-STRUCTURE.md` §5.1) and by whoever is
//! watching. The enforceable part is real and bounded; claiming more would be
//! claiming that consensus can see through an address, and it cannot.

use crate::params::SLOTS_PER_EPOCH;
use crate::sample::Validator;
use crate::tokenomics_v4::SLOTS_PER_YEAR;

/// Epochs in a year at 30 s slots and 32-slot epochs.
pub const EPOCHS_PER_YEAR: u64 = SLOTS_PER_YEAR / SLOTS_PER_EPOCH;

/// Where the cap starts: the cohort is the whole validator set at genesis.
pub const COHORT_CAP_START_BPS: u128 = 10_000;

/// Where it lands, and stays: one third, the finality-stall threshold.
pub const COHORT_CAP_FLOOR_BPS: u128 = 3_333;

/// Epochs over which the cap declines from start to floor — one year.
pub const COHORT_TAPER_EPOCHS: u64 = EPOCHS_PER_YEAR;

/// The cap on the cohort's combined weight at `epoch`, in basis points of total
/// active stake.
///
/// Linear taper, not a cliff. A step from 100% to 33% on a single epoch
/// boundary would eject two thirds of the chain's consensus weight in sixteen
/// minutes — the chain would stop the moment the rule bit. Tapering makes the
/// constraint continuous, so independent stake has a whole year of steadily
/// rising room rather than one deadline, and the founder can see the pressure
/// building rather than hitting a wall.
pub const fn cohort_cap_bps(epoch: u64) -> u128 {
    if epoch >= COHORT_TAPER_EPOCHS {
        return COHORT_CAP_FLOOR_BPS;
    }
    let span = COHORT_CAP_START_BPS - COHORT_CAP_FLOOR_BPS;
    COHORT_CAP_START_BPS - span * epoch as u128 / COHORT_TAPER_EPOCHS as u128
}

/// Apply the cohort cap to a validator set.
///
/// `cohort` is the genesis set, sorted ascending. Returns the set with cohort
/// members scaled down proportionally if their combined stake exceeds the cap
/// for `epoch`. Non-cohort validators are untouched.
///
/// Scaling is **pro-rata across the cohort**, not truncation of whichever
/// members happen to be largest: the cohort is one economic actor, so which of
/// its own validators absorbs the reduction is meaningless, and a rule that
/// picked would invite the founder to shuffle stake between them to choose.
/// Why the cap is deferred, when it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapStatus {
    /// Genesis window: the cohort is still the whole set by design.
    NotTapering,
    /// Enforced. The cohort was scaled to this many satoshis, or was already under.
    Enforced { cap_sat: u128 },
    /// **Not enforced**, because there is not yet enough independent stake for
    /// the rule to mean anything. See [`apply_cohort_cap`].
    Deferred { independent_sat: u128 },
}

/// The minimum independent stake at which the one-third rule is meaningful:
/// one validator's worth. Below this there is no one for the cohort to be
/// one third *of*.
pub const CAP_MEANINGFUL_AT_SAT: u128 = crate::staking::MIN_DEPOSIT_SAT;

/// Status of the cap at `epoch`, without applying it.
pub fn cap_status(validators: &[Validator], cohort: &[u32], epoch: u64) -> CapStatus {
    let bps = cohort_cap_bps(epoch);
    if bps >= 10_000 {
        return CapStatus::NotTapering;
    }
    let total: u128 = validators.iter().map(|v| v.effective_stake as u128).sum();
    let cohort_stake: u128 = validators
        .iter()
        .filter(|v| cohort.binary_search(&v.index).is_ok())
        .map(|v| v.effective_stake as u128)
        .sum();
    let others = total - cohort_stake;
    if others < CAP_MEANINGFUL_AT_SAT {
        return CapStatus::Deferred { independent_sat: others };
    }
    CapStatus::Enforced { cap_sat: others * bps / (10_000 - bps) }
}

pub fn apply_cohort_cap(validators: &[Validator], cohort: &[u32], epoch: u64) -> Vec<Validator> {
    let total: u128 = validators.iter().map(|v| v.effective_stake as u128).sum();
    if total == 0 {
        return validators.to_vec();
    }
    let cohort_stake: u128 = validators
        .iter()
        .filter(|v| cohort.binary_search(&v.index).is_ok())
        .map(|v| v.effective_stake as u128)
        .sum();

    // DEFERRAL, and it is load-bearing. The closed form below is a share of
    // NON-COHORT stake, so with none of it the cap is zero and the whole cohort
    // — which at a cold launch is the entire validator set — drops to zero
    // effective stake and the chain stops.
    //
    // That is not hypothetical: integer truncation makes the taper bite at
    // **epoch 5, about 1.3 hours after genesis**, where `10_000 - bps == 1` and
    // the cap is `9999 x O`. With `O == 0` it is 0. A rule written to
    // decentralise the chain would have killed it on day one — found by
    // adversarial review, 2026-08-11.
    //
    // The deeper point is that the cap cannot manufacture decentralisation out
    // of nothing. If no independent stake ever arrives, the honest options are
    // to halt or to let the cohort keep its weight; halting silently is the
    // worse one, because it hides the fact that nobody showed up. So the cap
    // defers, and `cap_status` reports *why* — the shortfall becomes visible
    // instead of becoming an outage.
    match cap_status(validators, cohort, epoch) {
        CapStatus::NotTapering | CapStatus::Deferred { .. } => return validators.to_vec(),
        CapStatus::Enforced { .. } => {}
    }
    let bps = cohort_cap_bps(epoch);

    // The cap is a share of the stake ACTIVE AFTER capping, so it cannot be
    // taken as a fraction of the pre-cap total: scaling the cohort down also
    // shrinks the total, and the share lands far above target. Capping a
    // cohort at "1/3 of the pre-cap total" left it holding 77% — the same
    // self-referential mistake the per-validator cap in `delegation.rs` had,
    // caught by test both times.
    //
    // Solved in closed form rather than by iteration: for a target share `s`
    // over non-cohort stake `O`, the admissible cohort weight is
    // `s/(1-s) · O`. At one third that is exactly `O/2` — the cohort may hold
    // half of what everyone else holds, which is what "one third of the whole"
    // means once you account for the cohort being part of the whole.
    let others = total - cohort_stake;
    let cap = others * bps / (10_000 - bps);
    if cohort_stake <= cap {
        return validators.to_vec();
    }

    validators
        .iter()
        .map(|v| {
            if cohort.binary_search(&v.index).is_ok() {
                // Truncating division keeps the cohort at or under the cap,
                // never over — the direction that matters for a cap.
                let scaled = v.effective_stake as u128 * cap / cohort_stake;
                Validator { index: v.index, effective_stake: scaled as u64 }
            } else {
                *v
            }
        })
        .collect()
}

/// Does the cohort meet its commitment at `epoch`?
///
/// Reporting, not consensus: [`apply_cohort_cap`] already makes the answer
/// true by construction inside consensus. This is for the operator dashboard
/// and the gate reporting, where the question is whether the *underlying*
/// position has come down — not whether the cap is masking one that has not.
pub fn cohort_share_bps(validators: &[Validator], cohort: &[u32]) -> u128 {
    let total: u128 = validators.iter().map(|v| v.effective_stake as u128).sum();
    if total == 0 {
        return 0;
    }
    let cohort_stake: u128 = validators
        .iter()
        .filter(|v| cohort.binary_search(&v.index).is_ok())
        .map(|v| v.effective_stake as u128)
        .sum();
    cohort_stake * 10_000 / total
}
