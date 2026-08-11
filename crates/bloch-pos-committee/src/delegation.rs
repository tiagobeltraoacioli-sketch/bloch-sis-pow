// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! 4. **Tainted stake delegates to nothing.** The §4.1 ineligibility rules
//!    follow the coins, not the account. Delegation is otherwise a laundering
//!    route: tainted coins delegate, earn, and vote by proxy.
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
/// 9%, matching Solana's warm-up/cool-down rate.
pub const WARMUP_RATE_BPS: u128 = 900;

/// Minimum a delegator may bond. Far below the validator minimum: the point of
/// delegation is that staking should not require running a node.
pub const MIN_DELEGATION_SAT: u128 = 10 * SAT_PER_BLOCH;

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
    /// False when the coins are tainted under §4.1 — the delegation is recorded
    /// but never contributes stake.
    pub eligible: bool,
}

impl Delegation {
    /// Deterministic queue order: by request epoch, then validator, then
    /// delegator. Never by position in the input slice — that was a real
    /// consensus bug in the sampling path, where the committee depended on how
    /// the caller happened to lay the registry out in memory.
    fn queue_key(&self) -> (u64, u32, u32) {
        (self.requested_epoch, self.validator, self.delegator)
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
        let mut admitted = vec![false; queue.len()];

        for e in 0..=epoch {
            // Genesis is unlimited: the rate limit exists to stop new stake
            // from overwhelming an *existing* set, and at epoch 0 there is no
            // set to protect. Every later epoch is rate-limited against the
            // stake active at the start of that epoch.
            let budget = if e == 0 {
                u128::MAX
            } else {
                total_active * WARMUP_RATE_BPS / 10_000
            };

            // Head-of-queue always progresses, even when the delegation alone
            // exceeds the epoch's budget. Without this the queue deadlocks
            // forever on any single delegation larger than 9% of active stake
            // — and on a small network that is most of them. Admitting one
            // oversized entry per epoch bounds the disruption to one record
            // per epoch while guaranteeing liveness.
            let mut used: u128 = 0;
            let mut any_admitted = false;

            for (i, d) in queue.iter().enumerate() {
                if admitted[i] || d.requested_epoch > e {
                    continue;
                }
                if used + d.amount_sat > budget && any_admitted {
                    continue; // waits for a later epoch; queue order is stable
                }
                used = used.saturating_add(d.amount_sat);
                any_admitted = true;
                admitted[i] = true;
                total_active += d.amount_sat;
                match active.binary_search_by_key(&d.validator, |(v, _)| *v) {
                    Ok(pos) => active[pos].1 += d.amount_sat,
                    Err(pos) => active.insert(pos, (d.validator, d.amount_sat)),
                }
            }

            // Cool-down, rate-limited and liveness-guaranteed the same way.
            let mut released: u128 = 0;
            let mut any_released = false;
            for (i, d) in queue.iter().enumerate() {
                if !admitted[i] {
                    continue;
                }
                let Some(de) = d.deactivate_epoch else { continue };
                if de > e {
                    continue;
                }
                if released + d.amount_sat > budget && any_released {
                    continue;
                }
                released = released.saturating_add(d.amount_sat);
                any_released = true;
                admitted[i] = false;
                total_active -= d.amount_sat;
                if let Ok(pos) = active.binary_search_by_key(&d.validator, |(v, _)| *v) {
                    active[pos].1 -= d.amount_sat;
                    if active[pos].1 == 0 {
                        active.remove(pos);
                    }
                }
            }
        }

        Registry { epoch, stakes: active, total_active }
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

    /// Lifecycle position of one delegation at this epoch.
    pub fn state_of(&self, d: &Delegation) -> StakeState {
        if !d.eligible || d.amount_sat < MIN_DELEGATION_SAT {
            return StakeState::Inactive;
        }
        match d.deactivate_epoch {
            Some(de) if self.epoch >= de + COOLDOWN_EPOCHS => StakeState::Inactive,
            Some(de) if self.epoch >= de => StakeState::Deactivating,
            _ => {
                if self.stake_of(d.validator) > 0 && d.requested_epoch <= self.epoch {
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
