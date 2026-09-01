// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every fee figure the explorer's Fees & Mempool page renders, recomputed
//! here from `fee_market` itself.
//!
//! The page is a claim about this chain's arithmetic, and the published
//! integrator formula was wrong once already (it took the byte term from V2
//! and the verification term from V1 — see
//! `BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` §6.2). So no number reaches the
//! page by being typed twice: each one is asserted here against the module
//! that consensus actually calls, and the page's own JS re-derives them from
//! the same formula rather than hard-coding results.

use bloch_pos_committee::fee_market::*;
use bloch_pos_committee::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH;

/// The epoch the live chain is in (observed 2026-09-01, archival
/// 139.180.166.5:8080, `getchaininfo` → epoch 1704). Any epoch past the
/// flag-day works; this one is the one the page describes.
const LIVE_EPOCH: u64 = 1_704;

#[test]
fn the_page_is_describing_the_post_flag_day_era() {
    assert_eq!(BLOCK_BYTES_V2_ACTIVATION_EPOCH, 800);
    assert!(LIVE_EPOCH >= BLOCK_BYTES_V2_ACTIVATION_EPOCH);
    assert_eq!(max_block_tx_bytes(LIVE_EPOCH), 524_288);
    assert_eq!(block_tx_bytes_target(LIVE_EPOCH), 262_144);
    // ...and what it says the pre-800 era was.
    assert_eq!(max_block_tx_bytes(799), 262_144);
    assert_eq!(block_tx_bytes_target(799), 131_072);
}

#[test]
fn the_gas_formula_the_page_prints() {
    // gas = 5,000 + tx_bytes x 16 + 72,748 x owner_keys
    assert_eq!(TX_FLAT_GAS, 5_000);
    assert_eq!(GAS_PER_BYTE, 16);
    assert_eq!(HYBRID_VERIFY_GAS, 72_748);

    // The page's calculator is exactly `intrinsic_gas` for the eUTXO class,
    // where the class term is the OWNER-KEY count under V2.
    for keys in [1u32, 2, 7, 62] {
        for bytes in [8_689u64, 20_000, 262_144, 524_288] {
            let mine = 5_000 + bytes * 16 + 72_748 * keys as u64;
            assert_eq!(
                intrinsic_gas(TxClass::Eutxo { inputs: keys }, bytes),
                mine,
                "explorer formula diverged at {keys} keys / {bytes} bytes"
            );
        }
    }
}

#[test]
fn the_worked_example_the_page_shows() {
    // One input, one owner, two outputs: ~8,689 encoded bytes. The byte count
    // is an ILLUSTRATION and the page says so — Falcon-1024 signatures are
    // variable length, so no constant is a correct size. What is pinned here
    // is the arithmetic applied to it.
    let gas = intrinsic_gas(TxClass::Eutxo { inputs: 1 }, 8_689);
    assert_eq!(gas, 216_772);

    // At the floor price, with no tip.
    let c = charge(TxClass::Eutxo { inputs: 1 }, 8_689, MIN_BASE_FEE_MILLISAT_PER_GAS, 0);
    assert_eq!(c.gas, 216_772);
    assert_eq!(c.base_fee_sat, 2_168); // ceil(216_772 * 10 / 1000)
    assert_eq!(c.priority_fee_sat, 0);
    // 2,168 sat = 0.00002168 BLCH — the module's "order of a thousand
    // satoshis (10^-5 BLCH)" claim, made concrete.
}

#[test]
fn base_and_tip_round_up_separately_and_the_difference_is_real() {
    // The trap the integration book flags: folding the two prices together
    // and dividing once can be one satoshi short, and one satoshi short is a
    // hard rejection under strict equality.
    //
    // The example is FOUND, not asserted from memory — the first draft of
    // this test hard-coded a transfer where the two methods happen to agree,
    // and `fee_parts_sat` caught it. That is the same class of error as the
    // published formula this whole file exists to guard against.
    let fold = |gas: u64, base: u128, tip: u128| -> u128 {
        (gas as u128 * (base + tip)).div_ceil(MILLISAT_PER_SAT)
    };

    // 1. Folding is NEVER larger than settling separately — so the wallet bug
    //    always underpays, never over. Swept over the whole realistic size
    //    range at the live price.
    let mut gap_seen = None;
    for bytes in 8_000u64..30_000 {
        let gas = intrinsic_gas(TxClass::Eutxo { inputs: 1 }, bytes);
        for tip in [1u128, 2, 3, 5, 10] {
            let (b, t) = fee_parts_sat(gas, MIN_BASE_FEE_MILLISAT_PER_GAS, tip);
            let separate = b + t;
            let folded = fold(gas, MIN_BASE_FEE_MILLISAT_PER_GAS, tip);
            assert!(folded <= separate, "folding overpaid at {bytes} B, tip {tip}");
            assert!(separate - folded <= 1, "the gap is at most one satoshi");
            if separate - folded == 1 && gap_seen.is_none() {
                gap_seen = Some((bytes, tip, gas, separate, folded));
            }
        }
    }

    // 2. The gap is real and reachable, and this is the case the page cites.
    let (bytes, tip, gas, separate, folded) = gap_seen.expect("no one-satoshi case found");
    assert_eq!((bytes, tip), (8_000, 2));
    assert_eq!(gas, 205_748);
    assert_eq!(separate, 2_470);
    assert_eq!(folded, 2_469);

    // And the parts themselves, since the page prints them.
    let (b, t) = fee_parts_sat(gas, 10, 2);
    assert_eq!((b, t), (2_058, 412)); // ceil(2057.48), ceil(411.496)
}

#[test]
fn the_floor_is_absorbing_which_is_why_the_chart_is_flat() {
    // THE claim the page's fee history rests on. An empty block — which is
    // what 32,455 of 33,647 blocks have been — asks the controller for a
    // downward step, and from the floor that step cannot land anywhere.
    let empty = BlockUsage { gas_used: 0, tx_bytes: 0 };
    let mut price = MIN_BASE_FEE_MILLISAT_PER_GAS;
    assert_eq!(price, 10);
    for _ in 0..10_000 {
        price = next_base_fee(price, empty, LIVE_EPOCH);
        assert_eq!(price, 10, "the floor let go");
    }

    // And not only from the floor: any under-target block walks DOWN to the
    // floor and stops. Start high, run empty blocks, land on 10 and stay.
    let mut p = 1_000_000u128;
    for _ in 0..2_000 {
        p = next_base_fee(p, empty, LIVE_EPOCH);
    }
    assert_eq!(p, MIN_BASE_FEE_MILLISAT_PER_GAS);
}

#[test]
fn what_it_would_actually_take_to_lift_the_price() {
    // The page states the threshold rather than drawing a scary chart: the
    // price only moves up when a block exceeds a target, and at the floor the
    // first step is +1 msat/gas (the "congested block must always move the
    // price" floor-at-1 rule).
    let target_bytes = block_tx_bytes_target(LIVE_EPOCH);
    assert_eq!(target_bytes, 262_144);

    // Exactly at target: unchanged.
    let at = BlockUsage { gas_used: 0, tx_bytes: target_bytes };
    assert_eq!(next_base_fee(10, at, LIVE_EPOCH), 10);

    // One byte over: the delta truncates to 0 and is floored to 1.
    let over_one = BlockUsage { gas_used: 0, tx_bytes: target_bytes + 1 };
    assert_eq!(next_base_fee(10, over_one, LIVE_EPOCH), 11);

    // A payload-saturated block (the cap, = 2x target) is the biggest single
    // step there is: +1/8.
    let full = BlockUsage { gas_used: 0, tx_bytes: max_block_tx_bytes(LIVE_EPOCH) };
    assert_eq!(next_base_fee(8_000, full, LIVE_EPOCH), 9_000);

    // Roughly how many typical transfers that is. ~8,689 B each.
    assert_eq!(target_bytes / 8_689, 30);
    assert_eq!(max_block_tx_bytes(LIVE_EPOCH) / 8_689, 60);
}

#[test]
fn staleness_is_bounded_at_one_eighth_per_block_in_both_directions() {
    // The page's "why you must rebuild, not resubmit" number.
    let full = BlockUsage { gas_used: BLOCK_GAS_LIMIT, tx_bytes: 0 };
    let empty = BlockUsage { gas_used: 0, tx_bytes: 0 };

    // Fastest rise: x9/8 per block, compounding.
    let mut up = 8_000u128;
    for _ in 0..3 {
        up = next_base_fee(up, full, LIVE_EPOCH);
    }
    assert_eq!(up, 11_390); // 8000 * (9/8)^3 = 11,390.625, integer-truncated
    // Fastest fall: x7/8 per block.
    let mut down = 8_000u128;
    for _ in 0..3 {
        down = next_base_fee(down, empty, LIVE_EPOCH);
    }
    assert_eq!(down, 5_360); // 8000 -> 7000 -> 6125 -> 5360, each step truncating

    // A quote one block stale is off by at most 12.5%; the whole point is
    // that under strict equality "at most 12.5% off" is still a rejection.
    assert!(next_base_fee(8_000, full, LIVE_EPOCH) == 9_000);
}

#[test]
fn a_skipped_slot_does_not_move_the_price() {
    // Why the page charts PRICE PER BLOCK and not per slot: no block, no
    // controller update. Nothing here to call — the absence of a call IS the
    // rule — so this pins the shape the page relies on: the controller is a
    // pure function of the parent's committed usage, never of a clock.
    let p = 12_345u128;
    let u = BlockUsage { gas_used: 1, tx_bytes: 1 };
    assert_eq!(next_base_fee(p, u, LIVE_EPOCH), next_base_fee(p, u, LIVE_EPOCH));
}

#[test]
fn the_caps_the_page_prints_as_planning_limits() {
    assert_eq!(BLOCK_GAS_LIMIT, 60_000_000);
    assert_eq!(BLOCK_GAS_TARGET, 30_000_000);
    assert_eq!(MIN_BASE_FEE_MILLISAT_PER_GAS, 10);
    assert_eq!(BASE_FEE_CHANGE_DENOMINATOR, 8);
    assert_eq!(MILLISAT_PER_SAT, 1_000);

    // The distinct-owner ceiling the book quotes (~62), and the fact that
    // bytes bind before gas for a payload-saturated block.
    let saturated_gas = intrinsic_gas(TxClass::Eutxo { inputs: 62 }, 524_288);
    assert!(saturated_gas < BLOCK_GAS_LIMIT, "bytes must bind before gas");
    assert_eq!(saturated_gas, 5_000 + 524_288 * 16 + 72_748 * 62);
}
