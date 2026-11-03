// SPDX-License-Identifier: AGPL-3.0-or-later
//! # L2 protocol fee on L1 (candidate, inert)
//!
//! From [`crate::params::L2_REVENUE_EPOCH`] (shipped `u64::MAX`), L1 charges
//! one protocol fee per crossing of the native L2 bridge:
//!
//! - **Deposit (0x14).** The depositor's inputs pay `fee_sat(amount_sat)` on
//!   top of `amount_sat`, the change and the ordinary eUTXO fee. The inbox
//!   record, and so the L2 mint, stays exactly `amount_sat`: no L2 rule, guest,
//!   configuration or vkey changes.
//! - **Withdrawal claim (0x16).** The release output pays `sats - fee_sat(sats)`
//!   to the L1 recipient; the escrow still drops by exactly `sats` (the outbox
//!   leaf is unchanged). The relayer still pays only the eUTXO fee.
//!
//! In both cases the fee is a new spendable output at [`TREASURY_VOUT`] locked
//! to the compiled [`TREASURY_SCRIPT_HASH`]. It stays in the accounted supply;
//! nothing is burned and no key, setter or recurring signature exists. The rate,
//! floor and cap are compiled constants (a change is a new fork).
//!
//! The level is the middle of public comparables (report 233): 5 bps per
//! crossing, the same rate as the bUSDC vault fee (report 197), with a floor
//! that prices the inbox record and a cap for very large crossings.

/// Fee rate on a deposit, in basis points of `amount_sat`.
pub const DEPOSIT_FEE_BPS: u64 = 5;
/// Fee rate on a withdrawal claim, in basis points of `sats`.
pub const CLAIM_FEE_BPS: u64 = 5;
/// Smallest fee per crossing: 0.00005 BLCH (5 bps of 0.1 BLCH).
pub const FEE_FLOOR_SAT: u64 = 5_000;
/// Largest fee per crossing: 1 BLCH (reached at 2,000 BLCH).
pub const FEE_CAP_SAT: u64 = 100_000_000;
/// Hard ceiling on either rate. A typo above it does not compile.
pub const MAX_FEE_BPS: u64 = 30;
/// Output index of the fee. Deposits use 0 (change) and 1 (the escrow
/// record, never a spendable output); claims use 0 (release) and 1 (change).
pub const TREASURY_VOUT: u32 = 2;

/// The protocol treasury's L1 script hash. **TBD-owner**: `None` until the
/// owner names it. While it is `None` the gate cannot be armed
/// (`hard_forks::l2_revenue_may_arm`, compile-time).
/// Alias of `params::PROTOCOL_TREASURY_SCRIPT_HASH`, shared with the
/// forced-inclusion surcharge.
pub const TREASURY_SCRIPT_HASH: Option<[u8; 32]> = crate::params::PROTOCOL_TREASURY_SCRIPT_HASH;

const BPS_DENOMINATOR: u64 = 10_000;

/// `clamp(floor(amount * bps / 10_000), FEE_FLOOR_SAT, FEE_CAP_SAT)`.
pub const fn fee_sat(amount: u64, bps: u64) -> u64 {
    // u128: amount * bps cannot overflow.
    let raw = (amount as u128 * bps as u128 / BPS_DENOMINATOR as u128) as u64;
    if raw < FEE_FLOOR_SAT {
        FEE_FLOOR_SAT
    } else if raw > FEE_CAP_SAT {
        FEE_CAP_SAT
    } else {
        raw
    }
}

pub const fn deposit_fee_sat(amount_sat: u64) -> u64 {
    fee_sat(amount_sat, DEPOSIT_FEE_BPS)
}

pub const fn claim_fee_sat(sats: u64) -> u64 {
    fee_sat(sats, CLAIM_FEE_BPS)
}

/// What the L1 recipient of a claim of `sats` receives with the fee active.
pub const fn claim_net_sat(sats: u64) -> u64 {
    sats - claim_fee_sat(sats)
}

/// The fee rule is in force in `epoch` and has a treasury. With no treasury
/// it is never in force, even when a test forces the gate open, so a forced
/// test exercises the rule only through [`treasury`].
pub(crate) fn active(epoch: u64) -> bool {
    crate::params::l2_revenue_active(epoch) && treasury().is_some()
}

/// The deposit fee a block in `epoch` charges on `amount_sat` (0 before the
/// gate). For the offline CLI; consensus reads the state's epoch.
pub fn deposit_fee_at_epoch(epoch: u64, amount_sat: u64) -> u64 {
    if active(epoch) { deposit_fee_sat(amount_sat) } else { 0 }
}

/// The claim fee a block in `epoch` takes from a release of `sats` (0 before
/// the gate).
pub fn claim_fee_at_epoch(epoch: u64, sats: u64) -> u64 {
    if active(epoch) { claim_fee_sat(sats) } else { 0 }
}

/// What a tool must ask for: `--epoch` is needed only once the gate is armed.
pub const fn gate_armed() -> bool {
    crate::params::L2_REVENUE_EPOCH != u64::MAX
}

#[cfg(not(test))]
pub(crate) fn treasury() -> Option<[u8; 32]> {
    TREASURY_SCRIPT_HASH
}

/// Tests set a stand-in treasury; release builds read only the constant.
#[cfg(test)]
pub(crate) fn treasury() -> Option<[u8; 32]> {
    test_treasury::get().or(TREASURY_SCRIPT_HASH)
}

#[cfg(test)]
pub(crate) mod test_treasury {
    use std::cell::Cell;
    thread_local! { static VALUE: Cell<Option<[u8; 32]>> = const { Cell::new(None) }; }
    pub fn get() -> Option<[u8; 32]> { VALUE.with(Cell::get) }
    pub fn set(value: [u8; 32]) -> impl Drop {
        struct Restore(Option<[u8; 32]>);
        impl Drop for Restore { fn drop(&mut self) { VALUE.with(|v| v.set(self.0)); } }
        Restore(VALUE.with(|v| v.replace(Some(value))))
    }
}

// The rates stay under the hard ceiling and the floor under the cap.
const _: () = assert!(DEPOSIT_FEE_BPS <= MAX_FEE_BPS && CLAIM_FEE_BPS <= MAX_FEE_BPS);
const _: () = assert!(FEE_FLOOR_SAT <= FEE_CAP_SAT);
// The smallest claim (the smallest deposit, which is also the L2's minimum
// withdrawal) always pays a positive release.
const _: () = assert!(FEE_FLOOR_SAT < crate::transition::l2_deposit::MIN_L2_DEPOSIT_SAT);
const _: () = assert!(claim_net_sat(crate::transition::l2_deposit::MIN_L2_DEPOSIT_SAT) > 0);
// The treasury output never collides with the outputs these transactions
// already create.
const _: () = assert!(TREASURY_VOUT != crate::transition::l2_deposit::ESCROW_VOUT);
const _: () = assert!(
    TREASURY_VOUT != crate::transition::l2_claim::RELEASE_VOUT
        && TREASURY_VOUT != crate::transition::l2_claim::CHANGE_VOUT
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transition::l2_deposit::{MAX_L2_DEPOSIT_SAT, MIN_L2_DEPOSIT_SAT};

    const BLCH: u64 = 100_000_000;

    #[test]
    fn the_fee_is_five_bps_between_the_floor_and_the_cap() {
        assert_eq!(deposit_fee_sat(MIN_L2_DEPOSIT_SAT), FEE_FLOOR_SAT, "0.01 BLCH pays the floor");
        assert_eq!(deposit_fee_sat(BLCH / 10), 5_000, "0.1 BLCH: 5 bps equals the floor");
        assert_eq!(deposit_fee_sat(BLCH), 50_000, "1 BLCH pays 0.0005 BLCH");
        assert_eq!(deposit_fee_sat(100 * BLCH), 5_000_000, "100 BLCH pays 0.05 BLCH");
        assert_eq!(deposit_fee_sat(2_000 * BLCH), FEE_CAP_SAT, "the cap is reached at 2,000 BLCH");
        assert_eq!(deposit_fee_sat(10_000 * BLCH), FEE_CAP_SAT);
        assert_eq!(deposit_fee_sat(MAX_L2_DEPOSIT_SAT), FEE_CAP_SAT, "no overflow at the largest record");
        assert_eq!(claim_fee_sat(BLCH), 50_000);
        assert_eq!(claim_net_sat(BLCH), BLCH - 50_000);
    }

    #[test]
    fn the_fee_never_exceeds_its_rate_above_the_floor_and_the_release_stays_positive() {
        let mut amount = MIN_L2_DEPOSIT_SAT;
        while amount < 20_000 * BLCH {
            let fee = claim_fee_sat(amount);
            assert!(fee >= FEE_FLOOR_SAT && fee <= FEE_CAP_SAT);
            if fee > FEE_FLOOR_SAT {
                assert!(u128::from(fee) * 10_000 <= u128::from(amount) * u128::from(CLAIM_FEE_BPS));
            }
            assert!(claim_net_sat(amount) > 0 && claim_net_sat(amount) + fee == amount);
            amount = amount * 3 / 2 + 7;
        }
    }

    #[test]
    fn the_rule_ships_inert_with_no_treasury() {
        assert_eq!(crate::params::L2_REVENUE_EPOCH, u64::MAX);
        assert_eq!(TREASURY_SCRIPT_HASH, None, "TBD-owner");
        for epoch in [0, 7_360, 8_620, 10_000, u64::MAX - 1] {
            assert!(!active(epoch), "{epoch}");
        }
        // A forced gate without a treasury is still off.
        let _gate = crate::params::l2_revenue_test::open();
        assert!(!active(0));
        let _treasury = test_treasury::set([0x7e; 32]);
        assert!(active(0));
    }
}
