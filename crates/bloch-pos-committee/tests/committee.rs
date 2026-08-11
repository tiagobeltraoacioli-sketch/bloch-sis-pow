// SPDX-License-Identifier: MIT OR Apache-2.0

//! Properties the committee layer must hold for consensus not to split.

use bloch_pos_committee::*;
use std::collections::HashMap;

fn uniform_set(n: u32, stake: u64) -> Vec<Validator> {
    (0..n).map(|index| Validator { index, effective_stake: stake }).collect()
}

const MIX: [u8; 32] = [7u8; 32];

// ── determinism ─────────────────────────────────────────────────────────────

#[test]
fn same_inputs_give_same_committee() {
    let vs = uniform_set(500, 100_000);
    let a = slot_subcommittee(&MIX, 1234, &vs);
    let b = slot_subcommittee(&MIX, 1234, &vs);
    assert_eq!(a, b);
    assert_eq!(a.len(), SLOT_SUBCOMMITTEE_SIZE);
}

#[test]
fn output_is_sorted_and_distinct() {
    let vs = uniform_set(500, 100_000);
    for slot in 0..64u64 {
        let c = slot_subcommittee(&MIX, slot, &vs);
        assert!(c.windows(2).all(|w| w[0] < w[1]), "slot {slot}: nao ordenado ou com repetido");
    }
}

#[test]
fn validator_order_does_not_change_the_draw() {
    // Two nodes may hold the registry in different order in memory. The
    // committee must not depend on that.
    let vs = uniform_set(300, 100_000);
    let mut reversed = vs.clone();
    reversed.reverse();
    assert_eq!(slot_subcommittee(&MIX, 99, &vs), slot_subcommittee(&MIX, 99, &reversed));
}

#[test]
fn different_slots_give_different_committees() {
    let vs = uniform_set(500, 100_000);
    let a = slot_subcommittee(&MIX, 1, &vs);
    let b = slot_subcommittee(&MIX, 2, &vs);
    assert_ne!(a, b);
}

#[test]
fn different_beacon_mix_gives_different_committee() {
    let vs = uniform_set(500, 100_000);
    let other = [8u8; 32];
    assert_ne!(slot_subcommittee(&MIX, 1, &vs), slot_subcommittee(&other, 1, &vs));
}

#[test]
fn slot_and_epoch_roles_are_separated() {
    // If the role tag were missing, the slot subcommittee for index i would be
    // a prefix of the epoch committee for index i — the per-slot sample would
    // leak the finality committee a whole epoch early.
    let vs = uniform_set(500, 100_000);
    let s = sample(&MIX, 5, Role::SlotSubcommittee, &vs, 8);
    let e = sample(&MIX, 5, Role::EpochCommittee, &vs, 8);
    assert_ne!(s, e);
}

// ── stake weighting ─────────────────────────────────────────────────────────

#[test]
fn zero_stake_is_never_selected() {
    let mut vs = uniform_set(100, 100_000);
    for v in vs.iter_mut().take(50) {
        v.effective_stake = 0; // ineligible: tainted, exited or slashed
    }
    for slot in 0..300u64 {
        for picked in slot_subcommittee(&MIX, slot, &vs) {
            assert!(picked >= 50, "slot {slot}: validador sem stake foi sorteado ({picked})");
        }
    }
}

#[test]
fn selection_is_proportional_to_stake() {
    // One validator with 10× the stake of each of the other 99.
    let mut vs = uniform_set(100, 100_000);
    vs[0].effective_stake = 1_000_000;
    let total_weight = 1_000_000f64 + 99.0 * 100_000.0;
    let expected_share = 1_000_000f64 / total_weight;

    let rounds = 4000u64;
    let mut hits = 0u32;
    for slot in 0..rounds {
        if slot_subcommittee(&MIX, slot, &vs).contains(&0) {
            hits += 1;
        }
    }
    // Probability of appearing in a draw of 8 without replacement is higher
    // than a single-draw share; assert it lands in a sane band around it
    // rather than pinning an exact figure.
    let observed = hits as f64 / rounds as f64;
    let lower = expected_share * 8.0 * 0.6;
    let upper = expected_share * 8.0 * 1.4;
    assert!(
        observed > lower && observed < upper,
        "share observada {observed:.4} fora da banda [{lower:.4}, {upper:.4}]"
    );
}

#[test]
fn draw_is_not_biased_toward_low_indices() {
    // Catches the classic `% total` modulo bias: with uniform stake, every
    // validator should appear about equally often.
    let n = 64u32;
    let vs = uniform_set(n, 100_000);
    let rounds = 6000u64;
    let mut counts = vec![0u32; n as usize];
    for slot in 0..rounds {
        for picked in slot_subcommittee(&MIX, slot, &vs) {
            counts[picked as usize] += 1;
        }
    }
    let expected = (rounds as f64 * SLOT_SUBCOMMITTEE_SIZE as f64) / n as f64;
    let first_half: u32 = counts[..32].iter().sum();
    let second_half: u32 = counts[32..].iter().sum();
    let skew = (first_half as f64 - second_half as f64).abs()
        / (first_half + second_half) as f64;
    assert!(skew < 0.05, "assimetria entre metades = {skew:.4}");
    for (i, c) in counts.iter().enumerate() {
        let dev = (*c as f64 - expected).abs() / expected;
        assert!(dev < 0.25, "validador {i}: desvio {dev:.3} da media");
    }
}

// ── degenerate sets ─────────────────────────────────────────────────────────

#[test]
fn fewer_validators_than_seats_returns_all() {
    let vs = uniform_set(3, 100_000);
    assert_eq!(slot_subcommittee(&MIX, 1, &vs), vec![0, 1, 2]);
}

#[test]
fn empty_set_returns_empty() {
    assert!(slot_subcommittee(&MIX, 1, &[]).is_empty());
    assert!(slot_subcommittee(&MIX, 1, &uniform_set(10, 0)).is_empty());
}

#[test]
fn extreme_concentration_still_terminates_and_fills() {
    // One validator with essentially all the stake — the distribution the
    // G1–G4 gates exist to prevent. Rejection sampling would keep hitting the
    // whale; the fallback must fill the remaining seats deterministically.
    let mut vs = uniform_set(50, 1);
    vs[0].effective_stake = u64::MAX / 4;
    let a = slot_subcommittee(&MIX, 1, &vs);
    let b = slot_subcommittee(&MIX, 1, &vs);
    assert_eq!(a.len(), SLOT_SUBCOMMITTEE_SIZE);
    assert_eq!(a, b, "o fallback tem de ser deterministico");
    assert!(a.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn is_selected_agrees_with_sample() {
    let vs = uniform_set(200, 100_000);
    for slot in 0..20u64 {
        let c = slot_subcommittee(&MIX, slot, &vs);
        for v in 0..200u32 {
            let expected = c.contains(&v);
            let got = is_selected(&MIX, slot, Role::SlotSubcommittee, &vs, SLOT_SUBCOMMITTEE_SIZE, v);
            assert_eq!(expected, got, "slot {slot}, validador {v}");
        }
    }
}

// ── epoch helpers ───────────────────────────────────────────────────────────

#[test]
fn epoch_boundaries_are_the_last_slot_of_each_epoch() {
    assert_eq!(epoch_of(0), 0);
    assert_eq!(epoch_of(31), 0);
    assert_eq!(epoch_of(32), 1);
    assert!(is_epoch_boundary(31));
    assert!(is_epoch_boundary(63));
    assert!(!is_epoch_boundary(0));
    assert!(!is_epoch_boundary(32));
}

#[test]
fn epoch_committee_is_larger_than_the_slot_sample() {
    let vs = uniform_set(500, 100_000);
    assert_eq!(epoch_committee(&MIX, 3, &vs).len(), COMMITTEE_SIZE);
    assert_eq!(slot_subcommittee(&MIX, 3, &vs).len(), SLOT_SUBCOMMITTEE_SIZE);
}

// ── attestation ─────────────────────────────────────────────────────────────

struct AlwaysValid;
impl SignatureVerifier for AlwaysValid {
    fn verify(&self, _v: u32, _r: &[u8; 32], _s: &[u8]) -> bool { true }
}
struct AlwaysInvalid;
impl SignatureVerifier for AlwaysInvalid {
    fn verify(&self, _v: u32, _r: &[u8; 32], _s: &[u8]) -> bool { false }
}

fn att(slot: u64, head: u8, validator: u32) -> Attestation {
    Attestation {
        data: AttestationData {
            slot,
            head: [head; 32],
            source_epoch: 1,
            source_root: [1u8; 32],
            target_epoch: 2,
            target_root: [2u8; 32],
        },
        validator,
        signature: vec![0u8; 4589],
    }
}

#[test]
fn signing_root_changes_with_every_field() {
    let base = att(10, 0xAA, 1).data;
    let mut fields = Vec::new();
    let mut d = base; d.slot += 1; fields.push(d);
    let mut d = base; d.head = [0xBB; 32]; fields.push(d);
    let mut d = base; d.source_epoch += 1; fields.push(d);
    let mut d = base; d.source_root = [9u8; 32]; fields.push(d);
    let mut d = base; d.target_epoch += 1; fields.push(d);
    let mut d = base; d.target_root = [9u8; 32]; fields.push(d);
    for f in fields {
        assert_ne!(base.signing_root(), f.signing_root());
    }
}

#[test]
fn non_member_is_rejected_before_signature_check() {
    // Verifier says everything is valid; membership must still reject.
    let committee = vec![1u32, 2, 3];
    let a = att(5, 0xAA, 99);
    assert_eq!(
        bloch_pos_committee::attestation::validate(&a, &committee, 5, &AlwaysValid),
        Err(RejectReason::NotInCommittee)
    );
}

#[test]
fn bad_signature_is_rejected() {
    let committee = vec![1u32, 2, 3];
    let a = att(5, 0xAA, 2);
    assert_eq!(
        bloch_pos_committee::attestation::validate(&a, &committee, 5, &AlwaysInvalid),
        Err(RejectReason::BadSignature)
    );
}

#[test]
fn future_slot_and_bad_checkpoints_are_rejected() {
    let committee = vec![2u32];
    let a = att(9, 0xAA, 2);
    assert_eq!(
        bloch_pos_committee::attestation::validate(&a, &committee, 5, &AlwaysValid),
        Err(RejectReason::FutureSlot)
    );
    let mut b = att(5, 0xAA, 2);
    b.data.source_epoch = 5;
    b.data.target_epoch = 5;
    assert_eq!(
        bloch_pos_committee::attestation::validate(&b, &committee, 5, &AlwaysValid),
        Err(RejectReason::NonMonotonicCheckpoints)
    );
}

#[test]
fn valid_attestation_passes() {
    let committee = vec![1u32, 2, 3];
    assert!(bloch_pos_committee::attestation::validate(
        &att(5, 0xAA, 2), &committee, 5, &AlwaysValid).is_ok());
}

#[test]
fn slashable_patterns_are_detected() {
    let a = AttestationData {
        slot: 1, head: [1; 32],
        source_epoch: 1, source_root: [1; 32],
        target_epoch: 6, target_root: [6; 32],
    };
    let b = AttestationData { source_epoch: 2, target_epoch: 5, ..a };
    assert!(a.surrounds(&b));
    assert!(!b.surrounds(&a));

    let c = AttestationData { head: [9; 32], ..a };
    assert!(a.is_double_vote(&c));
    assert!(!a.is_double_vote(&a));
}

// ── fork choice ─────────────────────────────────────────────────────────────

fn root(b: u8) -> [u8; 32] { [b; 32] }

/// genesis → a → b, and genesis → c  (a fork)
fn tree() -> (HashMap<[u8; 32], [u8; 32]>, HashMap<[u8; 32], Vec<[u8; 32]>>) {
    let mut parents = HashMap::new();
    parents.insert(root(1), root(0));
    parents.insert(root(2), root(1));
    parents.insert(root(3), root(0));
    let mut children = HashMap::new();
    children.insert(root(0), vec![root(1), root(3)]);
    children.insert(root(1), vec![root(2)]);
    (parents, children)
}

#[test]
fn weight_follows_the_heavier_branch() {
    let (parents, children) = tree();
    let t = BlockTree { parents: &parents };
    let mut s = Store::new();
    for v in 0..3u32 { s.set_stake(v, 100); }
    s.observe(0, LatestMessage { slot: 1, root: root(2) });
    s.observe(1, LatestMessage { slot: 1, root: root(2) });
    s.observe(2, LatestMessage { slot: 1, root: root(3) });

    assert_eq!(s.weight(&t, &root(1)), 200);
    assert_eq!(s.weight(&t, &root(3)), 100);
    assert_eq!(s.head(&t, root(0), &children), root(2));
}

#[test]
fn only_the_latest_message_counts() {
    let (parents, children) = tree();
    let t = BlockTree { parents: &parents };
    let mut s = Store::new();
    s.set_stake(0, 100);
    s.observe(0, LatestMessage { slot: 1, root: root(3) });
    s.observe(0, LatestMessage { slot: 2, root: root(2) });
    assert_eq!(s.weight(&t, &root(3)), 0);
    assert_eq!(s.weight(&t, &root(1)), 100);
    assert_eq!(s.head(&t, root(0), &children), root(2));
}

#[test]
fn stale_message_cannot_move_the_head_back() {
    let (parents, _) = tree();
    let t = BlockTree { parents: &parents };
    let mut s = Store::new();
    s.set_stake(0, 100);
    assert!(s.observe(0, LatestMessage { slot: 5, root: root(2) }));
    assert!(!s.observe(0, LatestMessage { slot: 4, root: root(3) }));
    assert_eq!(s.weight(&t, &root(3)), 0);
}

#[test]
fn equivocation_in_one_slot_drops_the_validator_entirely() {
    // This test used to assert the opposite — that each node keeps whichever
    // message it saw first — and it passed, because both nodes ended up with
    // *some* weight. What it never checked was whether they agreed on the HEAD,
    // and they did not: keeping the first-seen message makes the head a function
    // of gossip arrival order, which is the exact divergence fork choice exists
    // to prevent. Found by property test, 2026-08-11.
    let (parents, children) = tree();
    let t = BlockTree { parents: &parents };
    let mut a = Store::new();
    let mut b = Store::new();
    a.set_stake(0, 100);
    b.set_stake(0, 100);
    a.set_stake(1, 10);
    b.set_stake(1, 10);
    // An honest validator, so the head is defined after the equivocator is gone.
    a.observe(1, LatestMessage { slot: 3, root: root(2) });
    b.observe(1, LatestMessage { slot: 3, root: root(2) });

    // Validator 0 equivocates; the two nodes see the pair in opposite orders.
    a.observe(0, LatestMessage { slot: 3, root: root(2) });
    a.observe(0, LatestMessage { slot: 3, root: root(3) });
    b.observe(0, LatestMessage { slot: 3, root: root(3) });
    b.observe(0, LatestMessage { slot: 3, root: root(2) });

    // The equivocator contributes nothing, on both nodes.
    assert_eq!(a.weight(&t, &root(0)), 10);
    assert_eq!(b.weight(&t, &root(0)), 10);
    assert_eq!(a.equivocators().count(), 1);
    assert_eq!(b.equivocators().count(), 1);

    // And — the property the old test never asserted — they agree on the head.
    assert_eq!(a.head(&t, root(0), &children), b.head(&t, root(0), &children));

    // A late message from a barred validator stays barred.
    assert!(!a.observe(0, LatestMessage { slot: 9, root: root(3) }));
    assert_eq!(a.weight(&t, &root(0)), 10);
}

#[test]
fn head_ties_break_deterministically() {
    let (parents, children) = tree();
    let t = BlockTree { parents: &parents };
    let mut s = Store::new();
    for v in 0..2u32 { s.set_stake(v, 100); }
    s.observe(0, LatestMessage { slot: 1, root: root(1) });
    s.observe(1, LatestMessage { slot: 1, root: root(3) });
    // Equal weight on both branches → larger root wins, on every node.
    assert_eq!(s.head(&t, root(0), &children), root(3));
}

#[test]
fn cyclic_parent_map_does_not_hang() {
    let mut parents = HashMap::new();
    parents.insert(root(1), root(2));
    parents.insert(root(2), root(1)); // corrupt: cycle
    let t = BlockTree { parents: &parents };
    let mut s = Store::new();
    s.set_stake(0, 100);
    s.observe(0, LatestMessage { slot: 1, root: root(1) });
    assert_eq!(s.weight(&t, &root(9)), 0);
}

#[test]
fn subcommittee_actually_carries_intra_epoch_weight() {
    // The point of §6.5.2: between epoch boundaries, weight comes from the
    // per-slot samples. Eight validators voting each slot must be enough to
    // separate two competing branches.
    let (parents, children) = tree();
    let t = BlockTree { parents: &parents };
    let vs = uniform_set(500, 100_000);
    let mut s = Store::new();
    for v in &vs { s.set_stake(v.index, v.effective_stake); }

    // Slots 0..4 of one epoch: each slot's subcommittee votes for branch `2`.
    let mut voted = 0;
    for slot in 0..5u64 {
        for v in slot_subcommittee(&MIX, slot, &vs) {
            if s.observe(v, LatestMessage { slot, root: root(2) }) { voted += 1; }
        }
    }
    assert!(voted >= SLOT_SUBCOMMITTEE_SIZE, "poucos votos acumulados: {voted}");
    assert!(s.weight(&t, &root(1)) > 0);
    assert_eq!(s.head(&t, root(0), &children), root(2));
}

// ── tokenomics V4 ───────────────────────────────────────────────────────────

use bloch_pos_committee::tokenomics_v4 as tk;

#[test]
fn allocations_sum_to_total_supply() {
    let sum = tk::FOUNDER_BLOCH + tk::VC_BLOCH + tk::TEAM_BLOCH + tk::MARKETING_BLOCH
        + tk::LIQUIDITY_BLOCH + tk::HOLDER_CARRYOVER_CAP_BLOCH + tk::VALIDATOR_EMISSION_BLOCH;
    assert_eq!(sum, tk::TOTAL_SUPPLY_BLOCH);
    assert_eq!(tk::VALIDATOR_EMISSION_BLOCH, 53_700_000_000);
}

#[test]
fn founder_is_fully_locked_through_the_cliff() {
    assert_eq!(tk::founder_vested_sat(0), 0);
    assert_eq!(tk::founder_vested_sat(tk::FOUNDER_CLIFF_SLOTS - 1), 0);
    // First slot after the cliff releases essentially nothing — linear, no jump.
    assert_eq!(tk::founder_vested_sat(tk::FOUNDER_CLIFF_SLOTS), 0);
}

#[test]
fn founder_vesting_is_linear_and_completes_exactly() {
    let total = tk::FOUNDER_BLOCH * tk::SAT_PER_BLOCH;
    let mid = tk::FOUNDER_CLIFF_SLOTS + tk::FOUNDER_VESTING_SLOTS / 2;
    let half = tk::founder_vested_sat(mid);
    let err = (half as i128 - (total / 2) as i128).abs();
    assert!(err < 1_000_000, "meio do vesting deveria ser ~metade, erro {err}");
    // Exact at the end: no dust may be stranded, or supply accounting breaks.
    assert_eq!(tk::founder_vested_sat(tk::FOUNDER_VESTING_END_SLOT), total);
    assert_eq!(tk::founder_vested_sat(u64::MAX), total);
}

#[test]
fn founder_vesting_never_decreases() {
    let step = tk::SLOTS_PER_YEAR / 12;
    let mut prev = 0u128;
    let mut slot = 0u64;
    while slot < tk::FOUNDER_VESTING_END_SLOT + step {
        let v = tk::founder_vested_sat(slot);
        assert!(v >= prev, "vesting regrediu no slot {slot}");
        prev = v;
        slot += step;
    }
}

#[test]
fn validator_emission_stops_after_forty_years() {
    for f in [tk::validator_reward_flat_sat as fn(u64) -> u128, tk::validator_reward_halving_sat] {
        assert!(f(0) > 0);
        assert!(f(tk::EMISSION_SLOTS - 1) > 0);
        assert_eq!(f(tk::EMISSION_SLOTS), 0);
        assert_eq!(f(u64::MAX), 0);
    }
}

#[test]
fn neither_curve_exceeds_the_allocation() {
    let alloc = tk::VALIDATOR_EMISSION_BLOCH * tk::SAT_PER_BLOCH;
    for emitted in [
        tk::validator_emitted_flat_by(tk::EMISSION_SLOTS),
        tk::validator_emitted_halving_by(tk::EMISSION_SLOTS),
    ] {
        assert!(emitted <= alloc, "emitiu {emitted} > alocado {alloc}");
        // Truncation may strand a little dust; it must never mint.
        assert!(alloc - emitted < tk::EMISSION_SLOTS as u128);
    }
    assert_eq!(tk::validator_emitted_flat_by(u64::MAX),
               tk::validator_emitted_flat_by(tk::EMISSION_SLOTS));
    assert_eq!(tk::validator_emitted_halving_by(u64::MAX),
               tk::validator_emitted_halving_by(tk::EMISSION_SLOTS));
}

#[test]
fn flat_curve_matches_the_spec_average() {
    assert_eq!(tk::validator_reward_flat_sat(0) / tk::SAT_PER_BLOCH, 1_276);
}

#[test]
fn halving_curve_halves_every_four_years() {
    let r0 = tk::validator_reward_halving_sat(0);
    assert_eq!(r0 / tk::SAT_PER_BLOCH, 6_387);
    assert_eq!(tk::validator_reward_halving_sat(tk::HALVING_PERIOD_SLOTS), r0 / 2);
    assert_eq!(tk::validator_reward_halving_sat(2 * tk::HALVING_PERIOD_SLOTS), r0 / 4);
    // Front-loading is the whole point: half the allocation inside four years.
    let first_era = tk::validator_emitted_halving_by(tk::HALVING_PERIOD_SLOTS);
    let alloc = tk::VALIDATOR_EMISSION_BLOCH * tk::SAT_PER_BLOCH;
    let share = first_era * 100 / alloc;
    assert!(share >= 49 && share <= 51, "primeiro era emitiu {share}%");
}

#[test]
fn halving_beats_flat_on_early_validator_share() {
    // The measured reason to prefer front-loading: at two years the halving
    // curve has put far more stake in validator hands than the flat curve.
    let two_years = 2 * tk::SLOTS_PER_YEAR;
    let h = tk::validator_emitted_halving_by(two_years);
    let f = tk::validator_emitted_flat_by(two_years);
    assert!(h > f * 4, "halving {h} deveria superar flat {f} com folga");
}

// ── vesting ─────────────────────────────────────────────────────────────────

#[test]
fn cliffs_are_staggered_to_avoid_a_cliff_wall() {
    // Founder 24 mo, team 18 mo, VC 12 mo — three distinct months.
    let m = tk::MONTH_SLOTS;
    assert_eq!(tk::VC_CLIFF_SLOTS / m, 12);
    assert_eq!(tk::TEAM_CLIFF_SLOTS / m, 18);
    assert_eq!(tk::FOUNDER_CLIFF_SLOTS / m, 24);
    let mut cliffs = [tk::VC_CLIFF_SLOTS, tk::TEAM_CLIFF_SLOTS, tk::FOUNDER_CLIFF_SLOTS];
    cliffs.sort();
    assert!(cliffs.windows(2).all(|w| w[1] - w[0] >= 6 * m), "cliffs a menos de 6 meses");
}

#[test]
fn locked_buckets_release_nothing_at_genesis() {
    assert_eq!(tk::vc_vested_sat(0), 0);
    assert_eq!(tk::team_vested_sat(0), 0);
    assert_eq!(tk::founder_vested_sat(0), 0);
}

#[test]
fn each_bucket_vests_fully_and_never_over() {
    let cases: [(fn(u64) -> u128, u128); 3] = [
        (tk::vc_vested_sat, tk::VC_BLOCH),
        (tk::team_vested_sat, tk::TEAM_BLOCH),
        (tk::marketing_vested_sat, tk::MARKETING_BLOCH),
    ];
    for (f, total) in cases {
        let want = total * tk::SAT_PER_BLOCH;
        assert_eq!(f(u64::MAX), want);
        assert!(f(10 * tk::SLOTS_PER_YEAR) <= want);
    }
}

#[test]
fn marketing_releases_a_quarter_at_genesis() {
    let total = tk::MARKETING_BLOCH * tk::SAT_PER_BLOCH;
    assert_eq!(tk::marketing_vested_sat(0), total / 4);
    assert_eq!(tk::marketing_vested_sat(tk::MARKETING_VESTING_SLOTS), total);
}

#[test]
fn liquidity_is_fully_liquid_at_genesis() {
    let total = tk::LIQUIDITY_BLOCH * tk::SAT_PER_BLOCH;
    assert_eq!(tk::liquidity_vested_sat(0), total);
}

#[test]
fn insider_unlock_is_monotonic_and_capped() {
    let cap = (tk::FOUNDER_BLOCH + tk::TEAM_BLOCH + tk::VC_BLOCH + tk::MARKETING_BLOCH)
        * tk::SAT_PER_BLOCH;
    let step = tk::MONTH_SLOTS;
    let mut prev = 0u128;
    let mut slot = 0u64;
    while slot < 13 * tk::SLOTS_PER_YEAR {
        let v = tk::insider_unlocked_sat(slot);
        assert!(v >= prev, "insider unlock regrediu no slot {slot}");
        assert!(v <= cap);
        prev = v;
        slot += step;
    }
    assert_eq!(tk::insider_unlocked_sat(u64::MAX), cap);
}

#[test]
fn nothing_but_liquidity_marketing_and_holders_circulates_at_genesis() {
    // The strongest property of the V4 schedule: at genesis no insider bucket
    // except a quarter of marketing has any spendable stake at all.
    let sat = tk::SAT_PER_BLOCH;
    let circulating_insiders = tk::insider_unlocked_sat(0);
    assert_eq!(circulating_insiders, tk::MARKETING_BLOCH * sat / 4);
    assert_eq!(tk::founder_vested_sat(0), 0);
}

#[test]
fn carryover_below_cap_is_untouched() {
    let sat = tk::SAT_PER_BLOCH;
    // Measured floor: 181,104,000 BLCH across four non-founder addresses.
    let total = 181_104_000 * sat;
    assert_eq!(tk::scaled_carryover_sat(177_063_600 * sat, total), 177_063_600 * sat);
    assert_eq!(tk::scaled_carryover_sat(411_600 * sat, total), 411_600 * sat);
}

#[test]
fn carryover_over_cap_scales_pro_rata() {
    let sat = tk::SAT_PER_BLOCH;
    let total = 600_000_000 * sat; // twice the cap
    // Every holder keeps exactly half.
    assert_eq!(tk::scaled_carryover_sat(400_000_000 * sat, total), 200_000_000 * sat);
    assert_eq!(tk::scaled_carryover_sat(2 * sat, total), sat);
    // And the scaled total lands on the cap, not near it.
    let a = tk::scaled_carryover_sat(400_000_000 * sat, total);
    let b = tk::scaled_carryover_sat(200_000_000 * sat, total);
    assert_eq!(a + b, tk::HOLDER_CARRYOVER_CAP_BLOCH * sat);
}

#[test]
fn carryover_scaling_does_not_overflow_at_full_supply() {
    // balance × cap is the product of two ~1e19 values: it overflows u64 by
    // twenty orders of magnitude. This must stay in u128 and stay exact.
    let sat = tk::SAT_PER_BLOCH;
    let huge = tk::TOTAL_SUPPLY_BLOCH * sat;
    let out = tk::scaled_carryover_sat(huge, huge);
    assert_eq!(out, tk::HOLDER_CARRYOVER_CAP_BLOCH * sat);
}

#[test]
fn total_supply_is_over_half_of_u64_max() {
    // The documented reason every quantity is u128 (§8.1). If this ever fails,
    // the u128 choice should be revisited deliberately.
    assert!(tk::TOTAL_SUPPLY_SAT > (u64::MAX as u128) / 2);
    assert!(tk::TOTAL_SUPPLY_SAT < u64::MAX as u128);
}

#[test]
fn decay_curve_meets_the_inflation_target() {
    // Founder requirement: annual inflation under 7% of total supply.
    let y1 = tk::annual_inflation_bps(0);
    assert!(y1 < 700, "ano 1 = {}bps, acima do teto de 700", y1);
    assert_eq!(y1, 545); // 5.45%
    assert!(tk::annual_inflation_bps(4) < y1);
    assert!(tk::annual_inflation_bps(9) < tk::annual_inflation_bps(4));
    assert_eq!(tk::annual_inflation_bps(9), 211); // 2.11% no ano 10
}

#[test]
fn decay_curve_declines_ten_percent_a_year() {
    let y0 = tk::validator_reward_decay_sat(0);
    let y1 = tk::validator_reward_decay_sat(tk::SLOTS_PER_YEAR);
    let ratio = y1 * 1000 / y0;
    assert!((899..=901).contains(&ratio), "razao anual = {ratio}/1000");
    assert_eq!(y0 / tk::SAT_PER_BLOCH, 5_181);
}

#[test]
fn decay_curve_emits_the_allocation_exactly() {
    let alloc = tk::VALIDATOR_EMISSION_BLOCH * tk::SAT_PER_BLOCH;
    let emitted = tk::validator_emitted_decay_by(tk::EMISSION_SLOTS);
    // Under the cap, never over: truncation may strand dust, never mint.
    assert!(emitted <= alloc, "emitiu {emitted} > alocado {alloc}");
    let residual = alloc - emitted;
    assert_eq!(residual, 67_200, "residuo mudou: {residual} sat");
    assert!(residual < tk::SAT_PER_BLOCH, "residuo passou de 1 BLCH");
    assert_eq!(tk::validator_emitted_decay_by(u64::MAX), emitted);
    assert_eq!(tk::validator_reward_decay_sat(tk::EMISSION_SLOTS), 0);
}

#[test]
fn decay_front_loads_enough_to_outpace_insider_unlocks() {
    // The decentralisation constraint: by month 24 validators must hold more
    // than any single insider bucket has unlocked by then.
    let m24 = 2 * tk::SLOTS_PER_YEAR;
    let validators = tk::validator_emitted_decay_by(m24);
    let biggest_insider = tk::vc_vested_sat(m24); // VC cliffs first
    assert!(validators > biggest_insider * 2,
        "validadores {validators} vs maior insider {biggest_insider}");
}

// ── receita do validador (modelo Solana) ────────────────────────────────────

use bloch_pos_committee::rewards::{self, StakeAccount};

fn acct(self_s: u128, deleg: u128, comm: u128) -> StakeAccount {
    StakeAccount { self_stake: self_s, delegated_stake: deleg,
                   commission_bps: comm, credits: 100, max_credits: 100 }
}

#[test]
fn base_fee_burns_half_priority_fee_does_not() {
    let s = rewards::split_fees(1_000, 4_000);
    assert_eq!(s.burned, 500);
    assert_eq!(s.to_producer, 500 + 4_000);
    assert_eq!(s.burned + s.to_producer, 5_000, "fee sumiu ou foi criada");
}

#[test]
fn burn_stops_when_emission_ends() {
    let last = tk::EMISSION_SLOTS - 1;
    let first_after = tk::EMISSION_SLOTS;
    let during = rewards::split_fees_at(1_000, 4_000, last);
    let after = rewards::split_fees_at(1_000, 4_000, first_after);
    assert_eq!(during.burned, 500);
    assert_eq!(after.burned, 0);
    assert_eq!(after.to_producer, 5_000, "pos-emissao o validador leva tudo");
    // No window with both issuance and no burn, or neither.
    assert!(tk::validator_reward_decay_sat(last) > 0);
    assert_eq!(tk::validator_reward_decay_sat(first_after), 0);
}

#[test]
fn fee_split_conserves_value_in_both_eras() {
    for slot in [0u64, 1, tk::EMISSION_SLOTS - 1, tk::EMISSION_SLOTS, u64::MAX] {
        for (b, p) in [(0u128, 0u128), (1, 0), (0, 1), (7, 13), (999_999, 1)] {
            let s = rewards::split_fees_at(b, p, slot);
            assert_eq!(s.burned + s.to_producer, b + p, "slot={slot} base={b} prio={p}");
        }
    }
}

#[test]
fn fee_split_conserves_value_for_arbitrary_inputs() {
    for (b, p) in [(0, 0), (1, 0), (0, 1), (7, 13), (999_999, 1), (u64::MAX as u128, 0)] {
        let s = rewards::split_fees(b, p);
        assert_eq!(s.burned + s.to_producer, b + p, "base={b} prio={p}");
    }
}

#[test]
fn rewards_are_pro_rata_to_stake_not_to_block_production() {
    // The Solana property: a validator that never leads still earns on its
    // stake. Two validators, same stake, same credits, same payout.
    let issuance = 1_000_000u128;
    let total = 1_000u128;
    let a = rewards::distribute(&acct(500, 0, 0), issuance, total);
    let b = rewards::distribute(&acct(500, 0, 0), issuance, total);
    assert_eq!(a.operator, b.operator);
    assert_eq!(a.operator, issuance / 2);
}

#[test]
fn commission_is_charged_only_on_delegated_stake() {
    // 10% commission, half the stake delegated.
    let p = rewards::distribute(&acct(500, 500, 1_000), 1_000_000, 1_000);
    assert_eq!(p.delegators + p.operator, 1_000_000);
    // Delegators' gross is 500_000; commission takes 10% = 50_000.
    assert_eq!(p.delegators, 450_000);
    assert_eq!(p.operator, 500_000 + 50_000);
}

#[test]
fn zero_commission_gives_delegators_everything_they_earned() {
    let p = rewards::distribute(&acct(0, 1_000, 0), 1_000_000, 1_000);
    assert_eq!(p.delegators, 1_000_000);
    assert_eq!(p.operator, 0);
}

#[test]
fn full_commission_is_allowed_and_takes_all_delegator_rewards() {
    // Legal, and the reason wallets must display the rate.
    let p = rewards::distribute(&acct(0, 1_000, 10_000), 1_000_000, 1_000);
    assert_eq!(p.delegators, 0);
    assert_eq!(p.operator, 1_000_000);
}

#[test]
fn missed_attestations_forfeit_rewards_for_operator_and_delegators() {
    let mut a = acct(500, 500, 0);
    a.credits = 50; // half the epoch missed
    let p = rewards::distribute(&a, 1_000_000, 1_000);
    assert_eq!(p.forfeited, 500_000);
    assert_eq!(p.operator + p.delegators, 500_000);
}

#[test]
fn offline_validator_earns_nothing_and_neither_do_its_delegators() {
    let mut a = acct(500, 500, 0);
    a.credits = 0;
    let p = rewards::distribute(&a, 1_000_000, 1_000);
    assert_eq!(p.operator, 0);
    assert_eq!(p.delegators, 0);
    assert_eq!(p.forfeited, 1_000_000);
}

#[test]
fn distribute_never_pays_more_than_the_stake_share() {
    let issuance = 5_000_000u128;
    let total = 10_000u128;
    for (s, d, c) in [(1u128, 0u128, 0u128), (0, 1, 10_000), (3_000, 7_000, 750), (10_000, 0, 0)] {
        let p = rewards::distribute(&acct(s, d, c), issuance, total);
        let share = issuance * (s + d) / total;
        assert!(p.operator + p.delegators + p.forfeited <= share + 1,
            "pagou acima da fatia: {s}/{d}/{c}");
    }
}

#[test]
fn degenerate_inputs_pay_nothing_instead_of_panicking() {
    let p = rewards::distribute(&acct(0, 0, 0), 1_000_000, 1_000);
    assert_eq!((p.operator, p.delegators, p.forfeited), (0, 0, 0));
    let p = rewards::distribute(&acct(100, 0, 0), 1_000_000, 0);
    assert_eq!((p.operator, p.delegators), (0, 0));
    let mut a = acct(100, 0, 0);
    a.max_credits = 0;
    assert_eq!(rewards::distribute(&a, 1_000_000, 1_000).operator, 0);
}

#[test]
fn distribution_does_not_overflow_at_full_supply_scale() {
    // issuance × stake is the product of two ~1e19 values.
    let sat = tk::SAT_PER_BLOCH;
    let total = tk::TOTAL_SUPPLY_BLOCH * sat;
    let issuance = 5_450_564_151 * sat;
    let p = rewards::distribute(&acct(total / 2, total / 2, 500), issuance, total);
    assert_eq!(p.operator + p.delegators, issuance);
}

#[test]
fn nominal_yield_exceeds_inflation_when_not_all_supply_is_staked() {
    let sat = tk::SAT_PER_BLOCH;
    let issuance = 5_450_564_151 * sat;                    // ano 1
    let staked = tk::TOTAL_SUPPLY_BLOCH * sat * 2 / 3;     // dois tercos, como Solana
    let y = rewards::nominal_yield_bps(issuance, staked);
    assert!(y > 545, "yield {y}bps deveria superar a inflacao de 545bps");
    assert_eq!(y, 817); // 8,17%
}

// ── delegacao ───────────────────────────────────────────────────────────────

use bloch_pos_committee::delegation::{self, Delegation, Registry, StakeState};

fn deleg(delegator: u32, validator: u32, bloch: u128, epoch: u64) -> Delegation {
    Delegation {
        delegator, validator,
        amount_sat: bloch * tk::SAT_PER_BLOCH,
        requested_epoch: epoch, deactivate_epoch: None, eligible: true,
    }
}

#[test]
fn delegation_activates_and_counts_as_validator_stake() {
    let ds = vec![deleg(1, 10, 1_000_000, 0), deleg(2, 10, 500_000, 0)];
    let r = Registry::resolve(&ds, 5);
    assert_eq!(r.stake_of(10), 1_500_000 * tk::SAT_PER_BLOCH);
    assert_eq!(r.validators().len(), 1);
}

#[test]
fn dust_and_tainted_delegations_never_count() {
    let mut small = deleg(1, 10, 1, 0);
    small.amount_sat = delegation::MIN_DELEGATION_SAT - 1;
    let mut tainted = deleg(2, 10, 1_000_000, 0);
    tainted.eligible = false; // §4.1: coins carry the ineligibility
    let r = Registry::resolve(&[small, tainted], 10);
    assert_eq!(r.stake_of(10), 0);
    assert_eq!(r.total_active(), 0);
    assert_eq!(r.state_of(&tainted), StakeState::Inactive);
}

#[test]
fn warmup_is_rate_limited_so_stake_cannot_seize_the_set_in_one_epoch() {
    // A large incumbent, then a whale that tries to activate everything at once.
    let mut ds = vec![deleg(1, 10, 100_000_000, 0)];
    for i in 0..20u32 {
        ds.push(deleg(100 + i, 20, 10_000_000, 1));
    }
    let e1 = Registry::resolve(&ds, 1);
    let e40 = Registry::resolve(&ds, 40);
    assert!(e1.stake_of(20) < e40.stake_of(20),
        "a baleia entrou inteira numa epoca so: {} vs {}", e1.stake_of(20), e40.stake_of(20));
    // And eventually it all lands.
    assert_eq!(e40.stake_of(20), 200_000_000 * tk::SAT_PER_BLOCH);
}

#[test]
fn registry_is_independent_of_input_order() {
    // The consensus bug found in the sampling path: output must depend on the
    // set, never on how the caller ordered it.
    let ds = vec![deleg(1, 10, 1_000, 0), deleg(2, 20, 2_000, 0), deleg(3, 30, 3_000, 1)];
    let mut rev = ds.clone();
    rev.reverse();
    let a = Registry::resolve(&ds, 6);
    let b = Registry::resolve(&rev, 6);
    assert_eq!(a.validators(), b.validators());
    assert_eq!(a.total_active(), b.total_active());
}

#[test]
fn validators_come_out_sorted_and_capped() {
    // One operator with 90% of stake must be clamped to the 1% cap.
    let mut ds = vec![deleg(1, 50, 900_000_000, 0)];
    for i in 0..99u32 {
        ds.push(deleg(200 + i, i, 1_000_000, 0));
    }
    let r = Registry::resolve(&ds, 200);
    let vs = r.validators();
    assert!(vs.windows(2).all(|w| w[0].index < w[1].index), "saida nao ordenada");
    let whale = vs.iter().find(|v| v.index == 50).unwrap();
    assert_eq!(whale.effective_stake as u128, r.cap_sat());
    assert!(r.stake_of(50) > r.cap_sat(), "o teste nao esta exercitando o teto");
    // Fixed point: the cap lands level with a normal validator, not 10x above.
    let normal = vs.iter().find(|v| v.index == 0).unwrap().effective_stake as u128;
    assert!(whale.effective_stake as u128 <= normal * 11 / 10,
        "teto deixou a baleia em {} contra {normal} de um validador normal",
        whale.effective_stake);
}

#[test]
fn cap_pushes_the_sampler_away_from_the_whale() {
    // The cap has to actually change who gets drawn, not merely exist.
    let mut ds = vec![deleg(1, 50, 900_000_000, 0)];
    for i in 0..99u32 {
        ds.push(deleg(200 + i, i, 1_000_000, 0));
    }
    let vs = Registry::resolve(&ds, 200).validators();
    let mut whale_draws = 0;
    for slot in 0..500u64 {
        if slot_subcommittee(&MIX, slot, &vs).contains(&50) {
            whale_draws += 1;
        }
    }
    // Uncapped, an operator holding 90% of raw stake would be in essentially
    // every committee. The fixed-point cap levels it with a normal validator,
    // so it should appear at roughly the same rate as anyone else: 8 seats out
    // of 100 operators is ~8% of committees.
    assert!(whale_draws < 100, "baleia sorteada em {whale_draws}/500 comites");
}

#[test]
fn deactivation_removes_stake_after_the_request() {
    let mut d = deleg(1, 10, 1_000_000, 0);
    d.deactivate_epoch = Some(5);
    let before = Registry::resolve(&[d], 4);
    let after = Registry::resolve(&[d], 6);
    assert!(before.stake_of(10) > 0);
    assert_eq!(after.stake_of(10), 0);
    assert_eq!(before.state_of(&d), StakeState::Active);
}

#[test]
fn stake_is_withdrawable_only_after_the_cooldown() {
    let mut d = deleg(1, 10, 1_000_000, 0);
    d.deactivate_epoch = Some(5);
    let mid = Registry::resolve(&[d], 5 + delegation::COOLDOWN_EPOCHS - 1);
    let done = Registry::resolve(&[d], 5 + delegation::COOLDOWN_EPOCHS);
    assert_eq!(mid.state_of(&d), StakeState::Deactivating);
    assert_eq!(done.state_of(&d), StakeState::Inactive);
}

#[test]
fn slashing_hits_delegators_pro_rata_with_the_operator() {
    let ds = vec![
        deleg(1, 10, 1_000, 0),   // operator's own
        deleg(2, 10, 3_000, 0),   // delegator
        deleg(3, 99, 5_000, 0),   // different validator, untouched
    ];
    let losses = delegation::apply_slash(&ds, 10, 500); // 5%
    assert_eq!(losses[0], 50 * tk::SAT_PER_BLOCH);
    assert_eq!(losses[1], 150 * tk::SAT_PER_BLOCH);
    assert_eq!(losses[2], 0);
    // Proportional: the delegator staked 3× and loses 3×.
    assert_eq!(losses[1], losses[0] * 3);
}

#[test]
fn concentration_metrics_track_the_gates() {
    // Ten equal operators: top share 10%, and it takes 4 to pass one third.
    let ds: Vec<Delegation> = (0..10u32).map(|i| deleg(i, i, 1_000_000, 0)).collect();
    let r = Registry::resolve(&ds, 200);
    assert_eq!(r.top_share_bps(), 1_000);
    assert_eq!(r.nakamoto_coefficient(), 4);

    // One operator at half: G2 (<2500 bps) and G3 (>=7) both fail.
    let mut ds2 = vec![deleg(99, 99, 9_000_000, 0)];
    ds2.extend((0..9u32).map(|i| deleg(i, i, 1_000_000, 0)));
    let r2 = Registry::resolve(&ds2, 400);
    assert!(r2.top_share_bps() > 2_500, "G2 deveria falhar");
    assert_eq!(r2.nakamoto_coefficient(), 1, "G3 deveria falhar");
}

#[test]
fn empty_registry_does_not_divide_by_zero() {
    let r = Registry::resolve(&[], 10);
    assert_eq!(r.total_active(), 0);
    assert_eq!(r.cap_sat(), 0);
    assert_eq!(r.top_share_bps(), 0);
    assert_eq!(r.nakamoto_coefficient(), 0);
    assert!(r.validators().is_empty());
    assert!(slot_subcommittee(&MIX, 1, &r.validators()).is_empty());
}

// ── particao de epoca (correcao do F1) ──────────────────────────────────────

use bloch_pos_committee::committees::{
    committee_for_slot, epoch_committees, is_supermajority, total_active_stake,
};

#[test]
fn every_validator_serves_exactly_once_per_epoch() {
    // A propriedade que conserta o F1: a uniao dos comites de uma epoca E o
    // conjunto ativo, entao o denominador do quorum e alcancavel por
    // construcao. Amostrar 128 nunca alcanca 2/3 do stake da rede.
    let vs = uniform_set(500, 100_000);
    let cs = epoch_committees(&MIX, 7, &vs);
    assert_eq!(cs.len(), SLOTS_PER_EPOCH as usize);

    let mut all: Vec<u32> = cs.iter().flatten().copied().collect();
    all.sort_unstable();
    let mut expected: Vec<u32> = (0..500u32).collect();
    expected.sort_unstable();
    assert_eq!(all, expected, "a uniao dos comites deve ser o conjunto ativo");

    let mut dedup = all.clone();
    dedup.dedup();
    assert_eq!(dedup.len(), all.len(), "nenhum validador em dois comites");
}

#[test]
fn partition_fixes_the_self_slashing_hazard() {
    // F2: com sorteios independentes por slot, um validador honesto aparecia em
    // varios slots da mesma epoca e emitia varias atestacoes com o mesmo
    // target_epoch — que is_double_vote marca como ofensa. Sob particao ele
    // atesta uma vez so, entao duas atestacoes com o mesmo alvo sao mesmo
    // equivocacao.
    let vs = uniform_set(300, 100_000);
    for epoch in 0..8u64 {
        let cs = epoch_committees(&MIX, epoch, &vs);
        for v in 0..300u32 {
            let n = cs.iter().filter(|c| c.contains(&v)).count();
            assert_eq!(n, 1, "validador {v} servindo {n} vezes na epoca {epoch}");
        }
    }
}

#[test]
fn partition_is_independent_of_input_order() {
    let vs = uniform_set(400, 100_000);
    let mut rev = vs.clone();
    rev.reverse();
    assert_eq!(epoch_committees(&MIX, 3, &vs), epoch_committees(&MIX, 3, &rev));
}

#[test]
fn partition_is_deterministic_and_moves_with_its_inputs() {
    let vs = uniform_set(400, 100_000);
    assert_eq!(epoch_committees(&MIX, 3, &vs), epoch_committees(&MIX, 3, &vs));
    assert_ne!(epoch_committees(&MIX, 3, &vs), epoch_committees(&MIX, 4, &vs));
    assert_ne!(epoch_committees(&MIX, 3, &vs), epoch_committees(&[9u8; 32], 3, &vs));
}

#[test]
fn committee_sizes_differ_by_at_most_one() {
    for n in [200u32, 384, 500, 1000] {
        let vs = uniform_set(n, 100_000);
        let cs = epoch_committees(&MIX, 1, &vs);
        let lo = cs.iter().map(|c| c.len()).min().unwrap();
        let hi = cs.iter().map(|c| c.len()).max().unwrap();
        assert!(hi - lo <= 1, "n={n}: tamanhos de {lo} a {hi}");
        assert_eq!(cs.iter().map(|c| c.len()).sum::<usize>(), n as usize);
    }
}

#[test]
fn ineligible_validators_are_never_assigned() {
    let mut vs = uniform_set(100, 100_000);
    for v in vs.iter_mut().take(40) {
        v.effective_stake = 0;
    }
    let cs = epoch_committees(&MIX, 1, &vs);
    let all: Vec<u32> = cs.iter().flatten().copied().collect();
    assert_eq!(all.len(), 60);
    assert!(all.iter().all(|v| *v >= 40));
}

#[test]
fn fewer_validators_than_slots_leaves_empty_committees() {
    let vs = uniform_set(5, 100_000);
    let cs = epoch_committees(&MIX, 1, &vs);
    assert_eq!(cs.iter().filter(|c| !c.is_empty()).count(), 5);
    assert_eq!(cs.iter().flatten().count(), 5);
    // Conjunto vazio nao quebra e nao inventa membro.
    let empty = epoch_committees(&MIX, 1, &[]);
    assert_eq!(empty.len(), SLOTS_PER_EPOCH as usize);
    assert!(empty.iter().all(|c| c.is_empty()));
}

#[test]
fn committee_for_slot_selects_the_right_slice() {
    let vs = uniform_set(200, 100_000);
    let cs = epoch_committees(&MIX, 2, &vs);
    for i in 0..SLOTS_PER_EPOCH {
        let slot = 2 * SLOTS_PER_EPOCH + i;
        assert_eq!(committee_for_slot(&MIX, slot, &vs), cs[i as usize]);
    }
}

#[test]
fn quorum_is_exact_at_two_thirds_and_reachable() {
    // Aritmetica inteira: 2/3 exato justifica, um satoshi abaixo nao.
    assert!(is_supermajority(2, 3));
    assert!(!is_supermajority(1, 3));
    assert!(is_supermajority(67, 100));
    assert!(!is_supermajority(66, 100));
    assert!(!is_supermajority(0, 0), "conjunto vazio nao auto-justifica");
    assert!(is_supermajority(u128::MAX, u128::MAX), "sem overflow no topo");

    // E o ponto do F1: o denominador e alcancavel, porque a uniao dos comites
    // e o conjunto ativo.
    let vs = uniform_set(300, 100_000);
    let total = total_active_stake(&vs);
    let cs = epoch_committees(&MIX, 1, &vs);
    let reachable: u128 = cs.iter().flatten().count() as u128 * 100_000;
    assert_eq!(reachable, total);
    assert!(is_supermajority(reachable, total));
}
