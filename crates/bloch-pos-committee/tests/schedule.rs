// SPDX-License-Identifier: AGPL-3.0-or-later

//! Properties the slot/epoch scheduler must hold for consensus not to split.

use bloch_pos_committee::schedule::{
    epoch_at, epoch_start, first_slot_of_epoch, last_slot_of_epoch, slot_at, slot_start,
    GENESIS_SLOT,
};
use bloch_pos_committee::*;

const MIX: [u8; 32] = [7u8; 32];
const GENESIS_TIME: u64 = 1_754_870_400; // arbitrary but fixed; nothing may depend on "now"

/// Distinct per-validator stakes so draws are genuinely weighted, not uniform.
fn weighted_set(n: u32) -> Vec<Validator> {
    (0..n)
        .map(|index| Validator { index, effective_stake: 100_000 + 977 * (index as u64 % 53) })
        .collect()
}

// ── slot ↔ epoch ↔ time arithmetic ──────────────────────────────────────────

#[test]
fn genesis_instant_is_slot_zero_and_pre_genesis_is_nothing() {
    assert_eq!(slot_at(GENESIS_TIME, GENESIS_TIME), Some(GENESIS_SLOT));
    // One second earlier must NOT round into slot 0: "slot -1" does not exist.
    assert_eq!(slot_at(GENESIS_TIME, GENESIS_TIME - 1), None);
    assert_eq!(epoch_at(GENESIS_TIME, GENESIS_TIME - 1), None);
}

#[test]
fn slot_window_edges_are_exact() {
    // The last second of slot 0 and the first second of slot 1.
    assert_eq!(slot_at(GENESIS_TIME, GENESIS_TIME + 29), Some(0));
    assert_eq!(slot_at(GENESIS_TIME, GENESIS_TIME + 30), Some(1));
    // Same shape at an arbitrary later boundary.
    let start = slot_start(GENESIS_TIME, 12_345).unwrap();
    assert_eq!(slot_at(GENESIS_TIME, start - 1), Some(12_344));
    assert_eq!(slot_at(GENESIS_TIME, start), Some(12_345));
    assert_eq!(slot_at(GENESIS_TIME, start + 29), Some(12_345));
    assert_eq!(slot_at(GENESIS_TIME, start + 30), Some(12_346));
}

#[test]
fn slot_time_round_trips_both_ways() {
    // The largest representable slot depends on genesis_time, not just on
    // u64::MAX / SLOT_DURATION: the window start must also fit in u64.
    let max_slot = (u64::MAX - GENESIS_TIME) / 30;
    for slot in [0u64, 1, 31, 32, 33, 1_000_000, max_slot] {
        let t = slot_start(GENESIS_TIME, slot).unwrap();
        assert_eq!(slot_at(GENESIS_TIME, t), Some(slot), "slot {slot} round trip");
    }
    assert_eq!(slot_start(GENESIS_TIME, max_slot + 1), None);
    // And time → slot → time recovers the window start.
    let t = GENESIS_TIME + 12_345 * 30 + 17; // mid-window
    let slot = slot_at(GENESIS_TIME, t).unwrap();
    assert_eq!(slot_start(GENESIS_TIME, slot), Some(GENESIS_TIME + 12_345 * 30));
}

#[test]
fn slot_epoch_round_trips_both_ways() {
    for epoch in [0u64, 1, 2, 1000, u64::MAX / SLOTS_PER_EPOCH - 1] {
        let first = first_slot_of_epoch(epoch).unwrap();
        let last = last_slot_of_epoch(epoch).unwrap();
        assert_eq!(last - first + 1, SLOTS_PER_EPOCH);
        assert_eq!(epoch_of(first), epoch);
        assert_eq!(epoch_of(last), epoch);
        // The boundary slot of the epoch is its last slot, and the next slot
        // belongs to the next epoch.
        assert!(is_epoch_boundary(last));
        assert_eq!(epoch_of(last + 1), epoch + 1);
    }
}

#[test]
fn epoch_time_arithmetic_is_consistent_with_slot_time() {
    for epoch in [0u64, 1, 7, 9999] {
        let via_epoch = epoch_start(GENESIS_TIME, epoch).unwrap();
        let via_slot = slot_start(GENESIS_TIME, first_slot_of_epoch(epoch).unwrap()).unwrap();
        assert_eq!(via_epoch, via_slot);
        assert_eq!(epoch_at(GENESIS_TIME, via_epoch), Some(epoch));
        // One second earlier falls in the previous epoch — or before genesis.
        let expected_prev = if epoch > 0 { Some(epoch - 1) } else { None };
        assert_eq!(epoch_at(GENESIS_TIME, via_epoch - 1), expected_prev);
    }
}

#[test]
fn overflow_returns_none_instead_of_panicking() {
    // These inputs are unreachable in practice; what matters is that a
    // consensus function is total — a panic here is a remote crash button.
    assert_eq!(slot_start(u64::MAX, 1), None);
    assert_eq!(slot_start(0, u64::MAX), None);
    assert_eq!(first_slot_of_epoch(u64::MAX), None);
    assert_eq!(last_slot_of_epoch(u64::MAX / SLOTS_PER_EPOCH + 1), None);
    assert_eq!(epoch_start(u64::MAX, u64::MAX), None);
    assert_eq!(epoch_schedule(&MIX, u64::MAX, &weighted_set(10)), None);
}

// ── proposer designation ────────────────────────────────────────────────────

#[test]
fn schedule_is_deterministic() {
    let vs = weighted_set(300);
    let a = epoch_schedule(&MIX, 42, &vs).unwrap();
    let b = epoch_schedule(&MIX, 42, &vs).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.proposers.len() as u64, SLOTS_PER_EPOCH);
    assert!(a.proposers.iter().all(|p| p.is_some()));
}

#[test]
fn validator_order_does_not_change_the_schedule() {
    // Two nodes may hold the registry in different memory order; the roster
    // must be a function of the set, not of the slice layout.
    let vs = weighted_set(300);
    let mut reversed = vs.clone();
    reversed.reverse();
    let mut rotated = vs.clone();
    rotated.rotate_left(113);
    let canonical = epoch_schedule(&MIX, 42, &vs).unwrap();
    assert_eq!(canonical, epoch_schedule(&MIX, 42, &reversed).unwrap());
    assert_eq!(canonical, epoch_schedule(&MIX, 42, &rotated).unwrap());
}

#[test]
fn schedule_changes_with_the_beacon_mix() {
    let vs = weighted_set(300);
    let other_mix = [8u8; 32];
    assert_ne!(
        epoch_schedule(&MIX, 42, &vs).unwrap(),
        epoch_schedule(&other_mix, 42, &vs).unwrap(),
    );
}

#[test]
fn schedule_changes_with_the_epoch() {
    // Same mix, different epoch → different slot numbers seed the draws, so
    // the roster must differ (this is what makes a stale schedule useless).
    let vs = weighted_set(300);
    let a = epoch_schedule(&MIX, 42, &vs).unwrap();
    let b = epoch_schedule(&MIX, 43, &vs).unwrap();
    assert_ne!(a.proposers, b.proposers);
}

#[test]
fn empty_and_zero_stake_sets_do_not_break() {
    assert_eq!(proposer(&MIX, 5, &[]), None);
    let sched = epoch_schedule(&MIX, 0, &[]).unwrap();
    assert!(sched.proposers.iter().all(|p| p.is_none()));
    // All-zero stake is the same as empty: nobody is eligible.
    let zeroed: Vec<Validator> =
        (0..50).map(|index| Validator { index, effective_stake: 0 }).collect();
    let sched = epoch_schedule(&MIX, 0, &zeroed).unwrap();
    assert!(sched.proposers.iter().all(|p| p.is_none()));
}

#[test]
fn zero_stake_validators_never_propose() {
    // One eligible validator among dead weight: it must get every slot.
    let mut vs: Vec<Validator> =
        (0..50).map(|index| Validator { index, effective_stake: 0 }).collect();
    vs[37].effective_stake = 100_000;
    let sched = epoch_schedule(&MIX, 3, &vs).unwrap();
    assert!(sched.proposers.iter().all(|p| *p == Some(37)));
}

#[test]
fn proposer_is_a_member_of_its_own_slot_subcommittee() {
    // Pinned property (module docs): the k=1 proposer draw shares its XOF
    // prefix with the k=8 subcommittee draw, so the proposer always carries
    // fork-choice weight in its own slot. If a refactor of `sample` ever
    // breaks this, it must be a conscious decision, not an accident.
    let vs = weighted_set(300);
    for slot in 0..256u64 {
        let p = proposer(&MIX, slot, &vs).unwrap();
        let sub = slot_subcommittee(&MIX, slot, &vs);
        assert!(sub.binary_search(&p).is_ok(), "slot {slot}: proposer {p} not in {sub:?}");
    }
}

#[test]
fn schedule_lookup_by_absolute_slot() {
    let vs = weighted_set(300);
    let epoch = 42u64;
    let sched = epoch_schedule(&MIX, epoch, &vs).unwrap();
    let first = first_slot_of_epoch(epoch).unwrap();
    for i in 0..SLOTS_PER_EPOCH {
        let slot = first + i;
        // The roster agrees with the per-slot function — one definition of
        // the draw, two access paths.
        assert_eq!(sched.proposer_at(slot), proposer(&MIX, slot, &vs));
    }
    // Slots outside the epoch never yield an authoritative-looking index.
    assert_eq!(sched.proposer_at(first - 1), None);
    assert_eq!(sched.proposer_at(first + SLOTS_PER_EPOCH), None);
}

#[test]
fn weighted_draw_favours_stake_over_an_epoch_horizon() {
    // Not a statistical test of `sample` (tests/committee.rs owns that) — a
    // sanity check that proposer designation actually flows through the
    // stake-weighted path: a validator with ~100x the stake of each of the
    // others should be drawn far more often than 1/N over many epochs.
    let mut vs = weighted_set(100);
    vs[7].effective_stake = 10_000_000;
    let mut hits = 0u32;
    let mut slots = 0u32;
    for epoch in 0..64u64 {
        let sched = epoch_schedule(&MIX, epoch, &vs).unwrap();
        hits += sched.proposers.iter().filter(|p| **p == Some(7)).count() as u32;
        slots += SLOTS_PER_EPOCH as u32;
    }
    // Fair share by stake is ~50%; uniform would be 1%. Anything above 10%
    // proves the weighting is live without being brittle to the fixed seed.
    assert!(hits * 10 > slots, "validator 7 proposed {hits}/{slots} slots");
}
