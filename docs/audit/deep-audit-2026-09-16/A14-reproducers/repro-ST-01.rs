// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ST-01 reproduction — independent second review.
//
// Drop-in integration test for `crates/bloch-pos-committee/tests/` (same
// idioms as `tests/committee.rs`, public API only). NOT placed in the
// repository and NOT run by the reviewer (build lock held).
//
// Claim under test: the genesis-cohort cap fixes the NON-cohort side's share
// of consensus weight by calendar alone, so a single validator holding the
// minimum bond (25,000 BLCH) that is outside the cohort
//   (a) holds ~6% of consensus weight and issuance today (epoch ~3,065),
//   (b) can stall finality alone from ~month 6,
//   (c) is a 2/3 finality supermajority BY ITSELF from epoch 32,872
//       (2027-08-13) onward, in the real finality engine, with zero cohort
//       votes, and
//   (d) once at the floor, a SILENT outsider stalls finality permanently:
//       the inactivity leak cannot rescue the cohort because the
//       MIN_QUORUM_DENOMINATOR floor (1/2 of the unleaked total, live since
//       epoch 2700) is measured against a total the cap keeps the cohort
//       strictly under a third of.
//
// Code under test: genesis_cohort.rs:111-127 (cap_status, CAP_MEANINGFUL_AT_SAT),
// :175-193 (closed form + pro-rata scale); committees.rs:551 (is_supermajority);
// finality.rs process_epoch (floor + tally); transition.rs:2532 (cap applied
// unconditionally in duty_roster_at), :4834 (that roster feeds finality),
// :5032 (that roster is the issuance basis).

use bloch_pos_committee::attestation::AttestationData;
use bloch_pos_committee::committees::{is_supermajority, total_active_stake};
use bloch_pos_committee::finality::{Checkpoint, EpochVotes, FinalityState};
use bloch_pos_committee::genesis_cohort::{
    apply_cohort_cap, cap_status, cohort_cap_bps, cohort_share_bps, CapStatus,
    CAP_MEANINGFUL_AT_SAT, COHORT_TAPER_EPOCHS, EPOCHS_PER_YEAR,
};
use bloch_pos_committee::params::{
    LEAK_RECOVERY_ACTIVATION_EPOCH, MIN_QUORUM_DENOMINATOR_DEN, MIN_QUORUM_DENOMINATOR_NUM,
};
use bloch_pos_committee::staking::MIN_DEPOSIT_SAT;
use bloch_pos_committee::Validator;

/// The live cohort: 64 validators (main.rs:1046 puts EVERY genesis validator
/// in the cohort). Each bond is 25,000 BLCH at genesis plus ~1 month of
/// compounded issuance; the exact figure does not matter — the cap is a
/// multiple of the OUTSIDER's stake, not of the cohort's.
const COHORT_N: u32 = 64;
const COHORT_MEMBER_STAKE_SAT: u64 = 6_000_000 * 100_000_000; // ~6M BLCH each (~384M total)
const OUTSIDER: u32 = 64; // first index a FundedDeposit would take (funded.rs: last + 1)

fn cohort_indices() -> Vec<u32> {
    (0..COHORT_N).collect()
}

/// 64-member cohort plus ONE outsider holding exactly the minimum bond.
fn roster_with_one_min_bond_outsider() -> Vec<Validator> {
    let mut vs: Vec<Validator> = (0..COHORT_N)
        .map(|i| Validator { index: i, effective_stake: COHORT_MEMBER_STAKE_SAT })
        .collect();
    vs.push(Validator { index: OUTSIDER, effective_stake: MIN_DEPOSIT_SAT as u64 });
    vs
}

fn split(capped: &[Validator]) -> (u128, u128, u128) {
    let total = total_active_stake(capped);
    let outsider = capped.iter().find(|v| v.index == OUTSIDER).unwrap().effective_stake as u128;
    let cohort = total - outsider;
    (total, cohort, outsider)
}

// ── (a) today: one minimum bond is ~6% of the chain, against ~384M BLCH ──────

#[test]
fn st01_a_today_one_min_bond_outsider_holds_six_percent_of_consensus_and_issuance() {
    let epoch = 3_065; // mainnet, 2026-09-16
    let vs = roster_with_one_min_bond_outsider();
    let cohort = cohort_indices();

    // Exactly one minimum bond is enough to switch the cap ON (`others <
    // CAP_MEANINGFUL_AT_SAT` is the deferral test; equality enforces).
    assert_eq!(CAP_MEANINGFUL_AT_SAT, MIN_DEPOSIT_SAT);
    assert!(matches!(cap_status(&vs, &cohort, epoch), CapStatus::Enforced { .. }));

    let capped = apply_cohort_cap(&vs, &cohort, epoch);
    let (total, cohort_w, outsider_w) = split(&capped);

    // bps(3065) = 10000 - 6667*3065/32872 = 9379 → cap = 25k * 9379/621 ≈ 377,576 BLCH.
    assert_eq!(cohort_cap_bps(epoch), 9_379);
    assert!(cohort_w < 380_000 * 100_000_000, "cohort scaled to {cohort_w} sat");
    assert!(cohort_w > 375_000 * 100_000_000);

    // The outsider's share is 1 - bps/10000 ≈ 6.2%, WHATEVER its absolute size.
    let outsider_bps = outsider_w * 10_000 / total;
    assert!(outsider_bps >= 600, "outsider holds {outsider_bps} bps for a 25k bond");
    // The cohort's ~384M BLCH raw position was cut ~1000x by a 25k bond.
    assert!(COHORT_N as u128 * COHORT_MEMBER_STAKE_SAT as u128 / cohort_w > 1_000);
}

// ── (b) month 6+: the outsider alone denies the cohort a supermajority ───────

#[test]
fn st01_b_from_month_six_the_outsider_alone_can_deny_the_cohort_a_quorum() {
    let vs = roster_with_one_min_bond_outsider();
    let cohort = cohort_indices();

    // At exactly half a year the rounding still (barely) lets the cohort through.
    let at_half = apply_cohort_cap(&vs, &cohort, EPOCHS_PER_YEAR / 2);
    let (t, c, _) = split(&at_half);
    assert!(is_supermajority(c, t), "epoch {} is the last epoch the cohort suffices", EPOCHS_PER_YEAR / 2);

    // One epoch later, and for every epoch after, it does not.
    for e in [EPOCHS_PER_YEAR / 2 + 1, EPOCHS_PER_YEAR * 3 / 4, EPOCHS_PER_YEAR, EPOCHS_PER_YEAR * 5] {
        let capped = apply_cohort_cap(&vs, &cohort, e);
        let (t, c, _) = split(&capped);
        assert!(!is_supermajority(c, t), "epoch {e}: the 64-validator cohort still reaches 2/3 without the outsider");
    }
}

// ── (c) month 12+: the outsider IS a supermajority, by itself ────────────────

#[test]
fn st01_c_from_the_taper_floor_a_single_min_bond_outsider_is_a_supermajority_alone() {
    let vs = roster_with_one_min_bond_outsider();
    let cohort = cohort_indices();
    let capped = apply_cohort_cap(&vs, &cohort, COHORT_TAPER_EPOCHS);
    let (total, cohort_w, outsider_w) = split(&capped);

    // cap = 2.5e12 * 3333 / 6667 = 1,249,887,505,624 sat (< outsider/2), then
    // pro-rata truncation per member; the cohort lands at or below that.
    assert!(cohort_w <= MIN_DEPOSIT_SAT * 3_333 / 6_667);
    assert!(cohort_w * 2 < outsider_w, "cap is strictly under half the outsider's bond");

    // The single outsider satisfies the finality quorum rule on its own.
    assert!(is_supermajority(outsider_w, total), "3*{outsider_w} >= 2*{total} must hold");
    // Which the existing tests never assert: they only pin the cohort side.
    assert!(cohort_share_bps(&capped, &cohort) < 3_334);
    // And, because issuance is pro-rata over this same capped roster
    // (transition.rs:5032), the outsider draws >= 2/3 of every epoch's issuance.
    assert!(outsider_w * 3 >= total * 2);
}

// ── (c') the real finality engine justifies and finalizes on the outsider's
//         vote ALONE, with zero cohort votes ──────────────────────────────────

#[test]
fn st01_c_the_finality_engine_finalizes_on_the_outsiders_vote_alone() {
    let vs = roster_with_one_min_bond_outsider();
    let cohort = cohort_indices();
    let capped = apply_cohort_cap(&vs, &cohort, COHORT_TAPER_EPOCHS);

    // Start the engine at the taper floor (>= LEAK_RECOVERY_ACTIVATION_EPOCH,
    // so the denominator floor is live, as on mainnet since epoch 2700).
    assert!(COHORT_TAPER_EPOCHS >= LEAK_RECOVERY_ACTIVATION_EPOCH);
    let genesis = Checkpoint { epoch: COHORT_TAPER_EPOCHS, root: [0; 32] };
    let mut fs = FinalityState::new(genesis);

    let vote = |source: Checkpoint, target_epoch: u64, root: [u8; 32]| AttestationData {
        slot: target_epoch * 32,
        head: root,
        source_epoch: source.epoch,
        source_root: source.root,
        target_epoch,
        target_root: root,
    };

    // Epoch T+1: only the outsider votes. Justified.
    let e1 = COHORT_TAPER_EPOCHS + 1;
    let a1 = [(OUTSIDER, vote(fs.current_justified(), e1, [1; 32]))];
    let out1 = fs
        .process_epoch(&EpochVotes { epoch: e1, active_set: &capped, attestations: &a1 })
        .unwrap();
    assert_eq!(out1.justified, Some(Checkpoint { epoch: e1, root: [1; 32] }),
        "one 25k-BLCH outsider justified a checkpoint against 64 silent cohort validators");

    // Epoch T+2: again only the outsider. T+1 is FINALIZED.
    let e2 = e1 + 1;
    let a2 = [(OUTSIDER, vote(fs.current_justified(), e2, [2; 32]))];
    let out2 = fs
        .process_epoch(&EpochVotes { epoch: e2, active_set: &capped, attestations: &a2 })
        .unwrap();
    assert_eq!(out2.finalized, Some(Checkpoint { epoch: e1, root: [1; 32] }),
        "one outsider finalized a checkpoint alone — safety is in one operator's hands");
    assert_eq!(fs.finalized().epoch, e1);
}

// ── (d) a SILENT outsider at the floor stalls finality forever: the leak
//        cannot rescue a cohort the cap pins strictly under one third ──────────

#[test]
fn st01_d_a_silent_outsider_at_the_floor_stalls_finality_permanently_despite_the_leak() {
    let vs = roster_with_one_min_bond_outsider();
    let cohort = cohort_indices();
    let capped = apply_cohort_cap(&vs, &cohort, COHORT_TAPER_EPOCHS);
    let (total, cohort_w, outsider_w) = split(&capped);

    // The arithmetic: floor = unleaked_total * 1/2 (params.rs:260-262).
    // The cohort can justify only if 3*C >= 2*floor = C + O, i.e. 2C >= O —
    // and the cap makes 2C < O (test c). So no amount of leaking helps.
    let floor = total * MIN_QUORUM_DENOMINATOR_NUM / MIN_QUORUM_DENOMINATOR_DEN;
    assert!(!is_supermajority(cohort_w, floor), "3*{cohort_w} < 2*{floor}");

    let genesis = Checkpoint { epoch: COHORT_TAPER_EPOCHS, root: [0; 32] };
    let mut fs = FinalityState::new(genesis);
    // 400 epochs (~3.5 days): all 64 cohort validators vote perfectly every
    // epoch on one chain; the outsider never votes.
    for k in 1..=400u64 {
        let e = COHORT_TAPER_EPOCHS + k;
        let src = fs.current_justified();
        let root = [k as u8; 32];
        let votes: Vec<(u32, AttestationData)> = (0..COHORT_N)
            .map(|i| (i, AttestationData {
                slot: e * 32,
                head: root,
                source_epoch: src.epoch,
                source_root: src.root,
                target_epoch: e,
                target_root: root,
            }))
            .collect();
        let out = fs
            .process_epoch(&EpochVotes { epoch: e, active_set: &capped, attestations: &votes })
            .unwrap();
        assert_eq!(out.justified, None, "epoch {e}: the cohort justified without the outsider");
    }
    // The leak DID run to completion on the outsider — and it changed nothing.
    assert_eq!(fs.leaked_of(OUTSIDER) as u128, outsider_w, "outsider fully leaked");
    assert_eq!(fs.finalized().epoch, COHORT_TAPER_EPOCHS, "no finality in 400 epochs");
    assert_eq!(fs.current_justified().epoch, COHORT_TAPER_EPOCHS);
}

// ── control: before the floor the leak DOES rescue (stall is temporary) ─────

#[test]
fn st01_control_before_month_twelve_the_leak_ends_an_outsider_stall_in_hours() {
    // Month 9: cohort share = 50% (> 1/3), so once the outsider has leaked
    // to <= C/2 the cohort clears 2/3 of the leak-adjusted total.
    let epoch = EPOCHS_PER_YEAR * 3 / 4;
    let vs = roster_with_one_min_bond_outsider();
    let cohort = cohort_indices();
    let capped = apply_cohort_cap(&vs, &cohort, epoch);

    let mut fs = FinalityState::new(Checkpoint { epoch, root: [0; 32] });
    let mut first_justified = None;
    for k in 1..=60u64 {
        let e = epoch + k;
        let src = fs.current_justified();
        let root = [k as u8; 32];
        let votes: Vec<(u32, AttestationData)> = (0..COHORT_N)
            .map(|i| (i, AttestationData {
                slot: e * 32, head: root, source_epoch: src.epoch, source_root: src.root,
                target_epoch: e, target_root: root,
            }))
            .collect();
        let out = fs
            .process_epoch(&EpochVotes { epoch: e, active_set: &capped, attestations: &votes })
            .unwrap();
        if out.justified.is_some() && first_justified.is_none() {
            first_justified = Some(k);
        }
    }
    let k = first_justified.expect("before the floor the leak must eventually rescue the cohort");
    assert!(k > 4, "the stall lasts past the 4-epoch leak threshold");
    assert!(k < 40, "but ends within hours (got {k} epochs)");
}
