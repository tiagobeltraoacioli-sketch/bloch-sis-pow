// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stake delegation — the subsystem the Solana revenue model requires.
//!
//! Commission is meaningless without delegated stake, and rewards paid pro-rata
//! to all stake only make sense if stake can sit behind an operator without
//! running one. This module supplies that: delegate, deactivate, withdraw, and
//! the rules that stop delegation from becoming a way to reconfigure consensus
//! quickly or to hide concentration.
//!
//! ## Four rules that are not obvious, and why each exists
//!
//! 1. **Warm-up is rate-limited.** At most [`WARMUP_RATE_BPS`] of active stake
//!    may activate in one epoch (Solana uses the same device at 9%). Without
//!    it, an actor holding idle coins could move the entire validator set in a
//!    single epoch — the committee is stake-weighted, so instant activation is
//!    instant control. Cool-down is limited the same way, so the set cannot be
//!    emptied at speed either.
//! 2. **Delegated stake counts toward the per-validator cap.** §4.1 caps a
//!    validator at 1% of active stake; delegation must not be a way around it.
//!    Stake above the cap earns nothing, which pushes delegators to spread out
//!    rather than pile onto the largest operator.
//! 3. **Delegators are exposed to slashing.** Pro-rata with the operator. If
//!    they were not, delegation would be a free option: all of the yield, none
//!    of the risk, and no reason to care who you delegate to.
//! 4. **Ineligible stake delegates to nothing — and in Genesis-4 nothing is
//!    ineligible by origin.** The `eligible` bit is the fail-closed door the
//!    retired §4.1 taint set used to feed. That set is empty: the carryover —
//!    the founder's balance included — delegates like any other liquid coin,
//!    because a carried-over balance that is liquid is also stakeable
//!    (founder decision, 2026-08-11). The door stays because the transition
//!    state machine carries the bit and the fail-closed direction must stay
//!    testable, not because anything may set it false by provenance.
//!
//! ## Honest note on decentralisation
//!
//! Delegation cuts both ways. It removes the 100,000 BLCH barrier to
//! participation — the minimum delegation is 10 BLCH — but it also lets a large
//! operator accumulate other people's stake, and it lets one holder spread a
//! position across many validators while keeping economic control. The
//! concentration metrics in this module ([`Registry::top_share_bps`],
//! [`Registry::nakamoto_coefficient`]) measure the *operator* view, which is
//! what consensus sees. They cannot see beneficial ownership behind several
//! delegators, and no on-chain metric can.

use crate::sample::Validator;
use crate::tokenomics_v4::SAT_PER_BLOCH;

/// Most of the active stake that may activate — or deactivate — in one epoch.
///
/// **0.25%.** This was 900 bps (9%) until 2026-08-11, taken from Solana's
/// warm-up rate. The numeral was ported and the clock was not: a Solana epoch
/// is ~48 hours, a Bloch epoch is 16 minutes, so the same percentage ran ~180x
/// faster in wall-clock time. Zero to the one-third finality-stall threshold
/// took `ln(1.5)/ln(1.09) = 4.7` epochs — **75 minutes**. No human process
/// reacts to a public queue in 75 minutes, so the limit defended nothing.
///
/// A churn limit is denominated in wall-clock time, not epochs: what it buys
/// is the interval during which a takeover-in-progress is visible in the
/// activation queue, measured against how long detection and response take. At
/// 25 bps that interval is `ln(1.5)/ln(1.0025) = 162` epochs, **~43 hours** —
/// about two working days of a publicly visible hostile queue.
///
/// 25 is the knee of the curve, not a sacred number; `BLOCH-POS-STAKE-CHURN.md`
/// has the full dial (100 bps -> 11 h, 50 -> 22 h, 10 -> 4.5 d, 5 -> Solana's
/// actual wall-clock rate). Past roughly a day each further halving buys less
/// security — the real barrier has shifted to acquiring the coins — while the
/// liveness bill below keeps growing linearly.
///
/// **What this costs, stated plainly.** The budget is shared with cool-down,
/// so every cost is symmetric. Honest onboarding slows ~36x (a participant
/// bringing 10% of the active set: 18 min -> ~11 h). Doubling the active set
/// goes from ~2 hours to **~3.1 days**, which for a young network hungry for
/// stake is the largest real cost. And exit is equally slow: after a slashing
/// scare or a key-compromise disclosure, a third of the set now takes ~43
/// hours to drain instead of ~1 hour, staying bonded and slashable that whole
/// time. Lowering the rate extends honest exposure exactly as much as it
/// delays an attacker — that symmetry is the F3 lesson (emptying the set fast
/// is as dangerous as filling it fast), not an oversight.
///
/// **What no rate limit buys.** Nothing here stops an attacker who has the
/// coins. Beneficial ownership is invisible on-chain: the 1% per-validator cap
/// is bypassed by splitting, and the operator-view metrics cannot see one
/// owner behind many delegators. The rate buys visibility time, and only that.
///
/// Phase 2, flagged and deliberately not sized: an absolute cap
/// (`clamp(total * 25bps, MIN, MAX)`) so attack time grows with the network as
/// it does on Ethereum, instead of staying at 43 hours forever. Sizing `MAX`
/// needs real staking data.
pub const WARMUP_RATE_BPS: u128 = 25;

/// Minimum a delegator may bond. Far below the validator minimum: the point of
/// delegation is that staking should not require running a node.
pub const MIN_DELEGATION_SAT: u128 = 10 * SAT_PER_BLOCH;

/// The floor under the per-epoch churn budget: one validator's minimum
/// deposit. See the floor rationale at the budget computation in
/// [`Registry::resolve`] — it exists to guarantee a drain terminates, and it
/// is sized so a young network can still onboard at a usable rate.
pub const MIN_CHURN_SAT: u128 = crate::staking::MIN_DEPOSIT_SAT;

/// Per-validator cap as a share of total active stake (§4.1: 1%).
pub const MAX_VALIDATOR_STAKE_BPS: u128 = 100;

/// Rounds of fixed-point iteration used to resolve the cap. Bounded so the
/// result is identical on every node regardless of how fast it converges.
pub const CAP_FIXPOINT_ROUNDS: u32 = 32;

/// Epochs between requesting deactivation and the stake becoming withdrawable.
pub const COOLDOWN_EPOCHS: u64 = 32;

/// One delegation record, as committed in state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delegation {
    /// Who bonded the coins.
    pub delegator: u32,
    /// Operator the stake sits behind.
    pub validator: u32,
    pub amount_sat: u128,
    /// Epoch the delegation was requested.
    pub requested_epoch: u64,
    /// Epoch deactivation was requested, if any.
    pub deactivate_epoch: Option<u64>,
    /// Fail-closed eligibility bit; when false the delegation is recorded but
    /// never contributes stake. **Always `true` by origin in Genesis-4**: the
    /// §4.1 taint set that used to drive it is retired and empty, and a
    /// carried-over balance that is liquid is also stakeable — the founder's
    /// included (founder decision, 2026-08-11). No oracle may derive `false`
    /// from where a coin came from.
    pub eligible: bool,
}

impl Delegation {
    /// Deterministic queue order: request epoch, validator, delegator, amount.
    ///
    /// Never by position in the input slice — that was a real consensus bug in
    /// the sampling path, where the committee depended on how the caller
    /// happened to lay the registry out in memory.
    ///
    /// `amount_sat` is part of the key, and leaving it out was the same bug in
    /// a second place. Nothing forbids one delegator bonding to one validator
    /// twice in one epoch, so without the amount those two records tie; a
    /// stable sort then preserves *caller order*, and under the warm-up budget
    /// a tie decides which record is admitted first. Two nodes holding the
    /// identical delegation set but iterating it differently resolved to
    /// different registries — found by property test, 2026-08-11.
    ///
    /// Records identical in all four components are interchangeable: admitting
    /// either yields the same stake, so a residual tie cannot change the
    /// result.
    fn queue_key(&self) -> (u64, u32, u32, u128) {
        (self.requested_epoch, self.validator, self.delegator, self.amount_sat)
    }
}

/// Lifecycle position of a delegation at a given epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakeState {
    /// Queued, waiting for warm-up budget.
    Activating,
    /// Counted in consensus and earning.
    Active,
    /// Deactivation requested; still slashable, no longer earning.
    Deactivating,
    /// Withdrawable.
    Inactive,
}

/// The resolved view of all delegations at one epoch.
///
/// Built by a single deterministic pass from the full delegation list, so two
/// nodes with identical state always agree. Nothing here reads a clock, a
/// cache, or anything mutable.
pub struct Registry {
    epoch: u64,
    /// (validator, active stake) sorted by validator index.
    stakes: Vec<(u32, u128)>,
    total_active: u128,
    /// Queue keys of the delegations actually admitted at this epoch, sorted.
    ///
    /// Needed because "is this delegation active?" is a question about the
    /// record, not about its validator. Answering it from the validator's
    /// aggregate stake reported a queued delegation as `Active` whenever some
    /// *other* delegation to the same validator had already been admitted —
    /// found by property test, 2026-08-11.
    admitted: Vec<(u64, u32, u32, u128)>,
    /// Queue key -> satoshis of that delegation actually activated, sorted.
    ///
    /// Partial activation means a delegation can contribute stake without being
    /// fully admitted, so "is it active?" and "how much of it is active?" are
    /// different questions and both have callers: consensus wants the stake, a
    /// wallet wants to tell its user that 500 of their 1,000 BLCH are earning.
    activated: Vec<((u64, u32, u32, u128), u128)>,
}

impl Registry {
    /// Resolve the registry at `epoch`.
    ///
    /// Walks epochs from zero admitting delegations under the warm-up budget.
    /// The walk is O(epochs × delegations); this is a reference implementation
    /// and a production node would carry the activation epoch in committed
    /// state rather than recomputing it. What matters here is that the rule is
    /// stated once, unambiguously.
    pub fn resolve(delegations: &[Delegation], epoch: u64) -> Registry {
        let mut queue: Vec<&Delegation> =
            delegations.iter().filter(|d| d.eligible && d.amount_sat >= MIN_DELEGATION_SAT).collect();
        queue.sort_by_key(|d| d.queue_key());

        let mut active: Vec<(u32, u128)> = Vec::new();
        let mut total_active: u128 = 0;
        // How much of each queued delegation is currently active. Partial
        // activation is the whole point — see the loop below.
        let mut activated: Vec<u128> = vec![0; queue.len()];

        for e in 0..=epoch {
            // Genesis is unlimited: the rate limit exists to stop new stake
            // from overwhelming an *existing* set, and at epoch 0 there is no
            // set to protect. Every later epoch is rate-limited against the
            // stake active at the start of that epoch.
            let budget = if e == 0 {
                u128::MAX
            } else {
                // FLOOR, and it is load-bearing. The rate is a fraction of the
                // stake that is *currently* active, so during a drain the
                // budget shrinks with the thing it is draining: the tail decays
                // geometrically and never reaches zero. A mass exit would leave
                // a dust remainder bonded forever — caught by
                // `deactivation_drains_gradually_and_completes`, which ran 200
                // epochs and still found 937,812 sat stuck.
                //
                // Any positive floor guarantees termination. The floor is one
                // VALIDATOR's worth of stake, not one delegation's: at 25 bps
                // the proportional budget only exceeds 100,000 BLCH once the
                // active set passes 40M BLCH, so on a young network a 10-BLCH
                // floor would be the binding constraint and would strangle
                // onboarding — 10 BLCH per 16 minutes is not a network, it is
                // a queue. (Ethereum's floor is the same idea at a different
                // unit: 4 validators per epoch.)
                //
                // It was `MIN_DELEGATION_SAT` while the rate was 900 bps, where
                // the floor almost never bound. Lowering the rate 36x is what
                // makes the floor load-bearing, so the two move together.
                let rate = total_active * WARMUP_RATE_BPS / 10_000;
                if rate > MIN_CHURN_SAT { rate } else { MIN_CHURN_SAT }
            };

            // PARTIAL ACTIVATION. A delegation larger than the epoch's budget
            // activates in slices across several epochs instead of waiting for
            // a budget that will never come.
            //
            // The previous rule let the head of the queue through whole,
            // whatever its size, to avoid deadlocking on any delegation bigger
            // than 9% of active stake — which on a young network is most of
            // them. That bought liveness by selling the cap: a single large
            // delegation activated entirely in one epoch, which is exactly the
            // "instant activation is instant control" the limit exists to stop
            // (adversarial review, finding F3, 2026-08-11).
            //
            // Slicing gives both. The queue always drains, and the 9% ceiling
            // holds absolutely, in both directions. It is also what Solana and
            // Ethereum do, for the same reason.
            let mut used: u128 = 0;
            for (i, d) in queue.iter().enumerate() {
                if d.requested_epoch > e || d.deactivate_epoch.is_some_and(|de| de <= e) {
                    continue;
                }
                let remaining = d.amount_sat - activated[i];
                if remaining == 0 || used >= budget {
                    continue;
                }
                let take = remaining.min(budget - used);
                used += take;
                activated[i] += take;
                total_active += take;
                match active.binary_search_by_key(&d.validator, |(v, _)| *v) {
                    Ok(pos) => active[pos].1 += take,
                    Err(pos) => active.insert(pos, (d.validator, take)),
                }
            }

            // Cool-down, sliced the same way and against the same budget.
            let mut released: u128 = 0;
            for (i, d) in queue.iter().enumerate() {
                let Some(de) = d.deactivate_epoch else { continue };
                if de > e || activated[i] == 0 || released >= budget {
                    continue;
                }
                let give = activated[i].min(budget - released);
                released += give;
                activated[i] -= give;
                total_active -= give;
                if let Ok(pos) = active.binary_search_by_key(&d.validator, |(v, _)| *v) {
                    active[pos].1 -= give;
                    if active[pos].1 == 0 {
                        active.remove(pos);
                    }
                }
            }
        }

        // A delegation counts as admitted only once it is FULLY activated;
        // a partially activated one is still warming up.
        let mut admitted_keys: Vec<(u64, u32, u32, u128)> = queue
            .iter()
            .enumerate()
            .filter(|(i, d)| activated[*i] == d.amount_sat)
            .map(|(_, d)| d.queue_key())
            .collect();
        admitted_keys.sort_unstable();

        let mut activated_map: Vec<((u64, u32, u32, u128), u128)> = queue
            .iter()
            .enumerate()
            .filter(|(i, _)| activated[*i] > 0)
            .map(|(i, d)| (d.queue_key(), activated[i]))
            .collect();
        activated_map.sort_unstable();

        Registry {
            epoch,
            stakes: active,
            total_active,
            admitted: admitted_keys,
            activated: activated_map,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Total active stake before the per-validator cap is applied.
    pub fn total_active(&self) -> u128 {
        self.total_active
    }

    /// Per-validator cap in satoshis: [`MAX_VALIDATOR_STAKE_BPS`] of total
    /// **capped** active stake, resolved by fixed-point iteration.
    ///
    /// The obvious implementation measures the cap against the *uncapped*
    /// total, and it is much weaker than "1%" sounds — precisely when it
    /// matters most. With one operator holding 90% of raw stake among a hundred
    /// operators, a cap of 1%-of-uncapped leaves it 9.99M against 1M for
    /// everyone else: still ten times any peer, 9.2% of effective weight, and
    /// present in over half of all committees. The cap's strength degrades
    /// exactly as concentration rises.
    ///
    /// Iterating to a fixed point instead clamps that same operator to 1.0% —
    /// level with a normal validator, a ninefold improvement. The iteration is
    /// safe to specify: clamping can only lower the total, which can only lower
    /// the cap, so the sequence is monotonically decreasing and bounded below,
    /// and integer arithmetic reaches a fixed point in finitely many rounds.
    /// The round bound is fixed at [`CAP_FIXPOINT_ROUNDS`] and the value after
    /// the bound is used as-is, so every node stops at the same number
    /// regardless of convergence speed.
    pub fn cap_sat(&self) -> u128 {
        if self.total_active == 0 {
            return 0;
        }
        let mut cap = self.total_active * MAX_VALIDATOR_STAKE_BPS / 10_000;
        let mut round = 0;
        while round < CAP_FIXPOINT_ROUNDS {
            let capped_total: u128 =
                self.stakes.iter().map(|(_, s)| if *s > cap { cap } else { *s }).sum();
            let next = capped_total * MAX_VALIDATOR_STAKE_BPS / 10_000;
            if next == cap {
                break;
            }
            cap = next;
            round += 1;
        }
        cap
    }

    /// The validator set as consensus sees it, capped, ready for sampling.
    ///
    /// `effective_stake` saturates to `u64` because [`Validator`] carries a
    /// `u64`; with a 1% cap on a 100 B supply the ceiling is ~10^17 sat, an
    /// order of magnitude inside `u64`, so the saturation is unreachable in
    /// practice and present only so the conversion cannot wrap.
    pub fn validators(&self) -> Vec<Validator> {
        let cap = self.cap_sat();
        self.stakes
            .iter()
            .map(|(v, s)| {
                let capped = if cap > 0 && *s > cap { cap } else { *s };
                Validator {
                    index: *v,
                    effective_stake: if capped > u64::MAX as u128 {
                        u64::MAX
                    } else {
                        capped as u64
                    },
                }
            })
            .collect()
    }

    /// Uncapped active stake behind one operator.
    pub fn stake_of(&self, validator: u32) -> u128 {
        self.stakes
            .binary_search_by_key(&validator, |(v, _)| *v)
            .map(|p| self.stakes[p].1)
            .unwrap_or(0)
    }

    /// Largest operator's share of active stake, in basis points — gate G2
    /// (must stay under 2,500).
    pub fn top_share_bps(&self) -> u128 {
        if self.total_active == 0 {
            return 0;
        }
        self.stakes.iter().map(|(_, s)| *s).max().unwrap_or(0) * 10_000 / self.total_active
    }

    /// Smallest number of operators that together exceed one third of active
    /// stake — gate G3 (must be at least 7).
    ///
    /// One third, not one half: a third is the threshold that breaks a
    /// two-thirds quorum, so it is the number at which finality can be stalled.
    /// Quoting the halving threshold would flatter the figure.
    pub fn nakamoto_coefficient(&self) -> usize {
        if self.total_active == 0 {
            return 0;
        }
        let mut sorted: Vec<u128> = self.stakes.iter().map(|(_, s)| *s).collect();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let threshold = self.total_active / 3;
        let mut acc: u128 = 0;
        for (i, s) in sorted.iter().enumerate() {
            acc += *s;
            if acc > threshold {
                return i + 1;
            }
        }
        sorted.len()
    }

    /// Satoshis of `d` currently counted as active stake.
    ///
    /// Between zero and `d.amount_sat`: partial while warming up or draining.
    /// The sum of this over every delegation equals [`Registry::total_active`],
    /// which the sum of fully-admitted amounts does not — a delegation halfway
    /// through warm-up contributes stake while still reporting `Activating`.
    pub fn activated_sat(&self, d: &Delegation) -> u128 {
        self.activated
            .binary_search_by_key(&d.queue_key(), |(k, _)| *k)
            .map(|i| self.activated[i].1)
            .unwrap_or(0)
    }

    /// Lifecycle position of one delegation at this epoch.
    pub fn state_of(&self, d: &Delegation) -> StakeState {
        if !d.eligible || d.amount_sat < MIN_DELEGATION_SAT {
            return StakeState::Inactive;
        }
        match d.deactivate_epoch {
            Some(de) if self.epoch >= de + COOLDOWN_EPOCHS => StakeState::Inactive,
            Some(de) if self.epoch >= de => StakeState::Deactivating,
            _ => {
                // Ask about THIS record, not about its validator. Reading the
                // validator's aggregate stake reported a delegation still in
                // the warm-up queue as Active whenever any other delegation to
                // the same validator had been admitted — so the sum of the
                // records reported Active exceeded total_active().
                if self.admitted.binary_search(&d.queue_key()).is_ok() {
                    StakeState::Active
                } else {
                    StakeState::Activating
                }
            }
        }
    }
}

/// Apply a slashing penalty across an operator and everyone delegated to it.
///
/// Pro-rata, so a delegator's loss is proportional to what it staked. Returns
/// the amount each delegation loses, in the order given.
///
/// Delegators being exposed is the point: without it, delegation is all yield
/// and no risk, nobody has any reason to care whether their operator is
/// well-run, and the whole mechanism stops being a security signal.
pub fn apply_slash(
    delegations: &[Delegation],
    validator: u32,
    penalty_bps: u128,
) -> Vec<u128> {
    delegations
        .iter()
        .map(|d| {
            if d.validator == validator && d.eligible {
                d.amount_sat * penalty_bps.min(10_000) / 10_000
            } else {
                0
            }
        })
        .collect()
}
