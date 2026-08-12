// SPDX-License-Identifier: AGPL-3.0-or-later

//! Validator revenue, modelled on Solana.
//!
//! Solana's validator economics have three parts, and the first one carries a
//! structural requirement that is easy to miss:
//!
//! 1. **Inflation rewards go to stake, not to block producers.** Every staked
//!    coin earns its pro-rata share of the epoch's issuance, whether or not its
//!    validator happened to lead a slot. Producing blocks is not how you get
//!    paid; *being staked behind a validator that performs* is. The validator
//!    takes a **commission** (single-digit percent in practice, 0–100% legal)
//!    off the rewards of the stake delegated to it.
//! 2. **Base fees are split** — half burned, half to the block producer.
//! 3. **Priority fees go entirely to the block producer** (Solana moved from a
//!    50/50 burn to 100% with SIMD-0096).
//!
//! The structural requirement is **delegation**. Commission is meaningless
//! without delegated stake, and pro-rata-to-all-stake rewards only make sense
//! if stake can sit behind an operator without running one. That is a genuine
//! addition to the PoS design, which until now had validators depositing
//! directly with a 100,000 BLCH minimum — see §7 of this crate's notes and the
//! open question in the tokenomics spec.
//!
//! This differs from the migration design's earlier sketch (§7.4: "7/8 to
//! attesters, 1/8 to proposer"), which is the Ethereum shape. Both are
//! defensible; they are not compatible, and this module implements the Solana
//! one.

use crate::tokenomics_v4::SAT_PER_BLOCH;

/// Basis points denominator.
pub const BPS: u128 = 10_000;

// ── Fee split ───────────────────────────────────────────────────────────────

/// Share of the **base fee** that is burned. Solana burns half.
pub const BASE_FEE_BURN_BPS: u128 = 5_000;

/// Share of the **priority fee** that goes to the block producer. Solana routes
/// all of it since SIMD-0096; before that it was a 50/50 burn like the base fee.
pub const PRIORITY_FEE_PRODUCER_BPS: u128 = 10_000;

/// How a block's fees split between the producer and the burn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSplit {
    pub to_producer: u128,
    pub burned: u128,
}

/// Split base and priority fees for a block at `slot`.
///
/// **Two eras, by founder decision.**
///
/// - *During emission* (`slot < EMISSION_SLOTS`): Solana's split — half the base
///   fee burned, priority fees entirely to the producer. The burn is the
///   deflationary counterweight that gives the hard cap its meaning while new
///   supply is still arriving.
/// - *After emission*: **no burn at all**, 100% of every fee to the producer.
///   Once issuance stops, fees are the entire security budget, and burning part
///   of the only remaining revenue would shrink the validator set for no gain.
///
/// The switch happens at exactly the slot emission stops, so there is never a
/// window where both issuance and a burn apply, nor one where neither does.
pub const fn split_fees_at(base_fee: u128, priority_fee: u128, slot: u64) -> FeeSplit {
    if slot >= crate::tokenomics_v4::EMISSION_SLOTS {
        return FeeSplit { to_producer: base_fee + priority_fee, burned: 0 };
    }
    let base_burn = base_fee * BASE_FEE_BURN_BPS / BPS;
    let prio_producer = priority_fee * PRIORITY_FEE_PRODUCER_BPS / BPS;
    FeeSplit {
        to_producer: (base_fee - base_burn) + prio_producer,
        burned: base_burn + (priority_fee - prio_producer),
    }
}

/// The emission-era split. Kept as a named entry point because most callers are
/// reasoning about the live chain, not the year-40 end state.
pub const fn split_fees(base_fee: u128, priority_fee: u128) -> FeeSplit {
    split_fees_at(base_fee, priority_fee, 0)
}

// ── Commission ──────────────────────────────────────────────────────────────

/// Commission is uncapped by consensus (Solana allows 0–100%), because a cap is
/// trivially evaded by an operator running its own delegation front-end, and an
/// uncapped-but-visible rate lets delegators price it. Wallets and explorers
/// are expected to surface it prominently.
pub const MAX_COMMISSION_BPS: u128 = 10_000;

/// One validator's stake position for reward purposes.
#[derive(Clone, Copy, Debug)]
pub struct StakeAccount {
    /// Stake the operator itself bonded.
    pub self_stake: u128,
    /// Stake delegated to this operator by others.
    pub delegated_stake: u128,
    /// Commission the operator charges on delegators' rewards, in bps.
    pub commission_bps: u128,
    /// Attestation credits earned this epoch, over the maximum attainable.
    /// Solana scales rewards by vote credits: an offline validator earns
    /// nothing and its delegators earn nothing, which is what makes delegation
    /// a real choice rather than a free ride.
    pub credits: u64,
    pub max_credits: u64,
}

/// What an epoch's issuance pays out to one validator and its delegators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payout {
    /// To the operator: rewards on its own stake, plus commission on delegators'.
    pub operator: u128,
    /// To delegators, after commission.
    pub delegators: u128,
    /// Not paid out — the share forfeited by missed attestations.
    pub forfeited: u128,
}

/// Distribute one validator's slice of epoch issuance.
///
/// `epoch_issuance` is the whole epoch's validator emission; `total_stake` is
/// the network's active stake. The validator's gross share is pro-rata by
/// stake, scaled by the fraction of attestation credits it actually earned.
///
/// All arithmetic is `u128`: `epoch_issuance * stake` multiplies two values
/// that can each approach 10^19 — the product overflows `u64` by twenty orders
/// of magnitude, and this is precisely the expression that looks harmless.
pub fn distribute(acct: &StakeAccount, epoch_issuance: u128, total_stake: u128) -> Payout {
    let stake = acct.self_stake + acct.delegated_stake;
    if total_stake == 0 || stake == 0 || acct.max_credits == 0 {
        return Payout { operator: 0, delegators: 0, forfeited: 0 };
    }
    let gross = epoch_issuance * stake / total_stake;
    let earned = gross * acct.credits.min(acct.max_credits) as u128 / acct.max_credits as u128;
    let forfeited = gross - earned;

    // Split by stake origin first, then take commission only from the
    // delegated side. Charging commission on the operator's own stake would be
    // the operator paying itself, which inflates the advertised rate.
    let delegator_gross = earned * acct.delegated_stake / stake;
    let operator_gross = earned - delegator_gross;
    let commission = delegator_gross * acct.commission_bps.min(MAX_COMMISSION_BPS) / BPS;

    Payout {
        operator: operator_gross + commission,
        delegators: delegator_gross - commission,
        forfeited,
    }
}

/// Nominal annual yield for a staker, in basis points, ignoring fees and
/// commission: `issuance_year / total_staked`.
///
/// The figure a delegator actually compares. It is **higher than the inflation
/// rate** whenever less than all supply is staked — with roughly two thirds
/// staked, as on Solana, a 5.45% inflation is about an 8% nominal yield, and
/// the real yield net of dilution is what is left after the 5.45%.
pub fn nominal_yield_bps(annual_issuance_sat: u128, total_staked_sat: u128) -> u128 {
    if total_staked_sat == 0 {
        return 0;
    }
    annual_issuance_sat * BPS / total_staked_sat
}

/// Minimum delegation, so dust delegations cannot bloat the reward pass.
/// Far below the validator minimum: the point of delegation is that staking
/// should not require 100,000 BLCH.
pub const MIN_DELEGATION_SAT: u128 = 10 * SAT_PER_BLOCH;
