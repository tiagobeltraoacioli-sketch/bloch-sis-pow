// SPDX-License-Identifier: AGPL-3.0-or-later

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
/// Every index resolves to the same placeholder key. These tests are about
/// window, dedup, membership and ordering — not about key binding — and
/// their verifier doubles ignore the key bytes. The cases that DO care
/// about resolution use `NoKeys` / a real registry instead.
struct AnyKey;
impl crate::attestation::KeyLookup for AnyKey {
fn pubkey(&self, _v: u32) -> Option<&[u8]> {
Some(b"placeholder-key")
}
}

impl SignatureVerifier for AlwaysValid {
    fn verify_with_key(&self, _pk: &[u8], _root: &[u8; 32], _sig: &[u8]) -> bool { true }
}
struct AlwaysInvalid;
impl SignatureVerifier for AlwaysInvalid {
    fn verify_with_key(&self, _pk: &[u8], _r: &[u8; 32], _s: &[u8]) -> bool { false }
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
        bloch_pos_committee::attestation::validate(&a, &committee, 5, &AlwaysValid, &AnyKey),
        Err(RejectReason::NotInCommittee)
    );
}

#[test]
fn bad_signature_is_rejected() {
    let committee = vec![1u32, 2, 3];
    let a = att(5, 0xAA, 2);
    assert_eq!(
        bloch_pos_committee::attestation::validate(&a, &committee, 5, &AlwaysInvalid, &AnyKey),
        Err(RejectReason::BadSignature)
    );
}

#[test]
fn future_slot_and_bad_checkpoints_are_rejected() {
    let committee = vec![2u32];
    let a = att(9, 0xAA, 2);
    assert_eq!(
        bloch_pos_committee::attestation::validate(&a, &committee, 5, &AlwaysValid, &AnyKey),
        Err(RejectReason::FutureSlot)
    );
    let mut b = att(5, 0xAA, 2);
    b.data.source_epoch = 5;
    b.data.target_epoch = 5;
    assert_eq!(
        bloch_pos_committee::attestation::validate(&b, &committee, 5, &AlwaysValid, &AnyKey),
        Err(RejectReason::NonMonotonicCheckpoints)
    );
}

#[test]
fn valid_attestation_passes() {
    let committee = vec![1u32, 2, 3];
    assert!(bloch_pos_committee::attestation::validate(
        &att(5, 0xAA, 2), &committee, 5, &AlwaysValid, &AnyKey).is_ok());
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
fn the_carryover_is_one_set_with_no_founder_line() {
    // O carryover inteiro atravessa, o saldo do fundador junto: foi minerado na
    // mesma cadeia sob as mesmas regras. Some com isso o conjunto de taint (nao
    // ha classe de moeda a marcar) e o teto de holders (existia para limitar o
    // que legados recebiam ENQUANTO o fundador era excluido).
    // Sob o split de 2026-08-12 (x100/21): 3.773.884.800 BLCH da G3.
    assert_eq!(tk::CARRYOVER_TOTAL_BLOCH, 18_146_400_000);
    assert_eq!(tk::HOLDER_CARRYOVER_CAP_BLOCH, 0, "o teto foi aposentado");
    // Renomear nao move saldo, e o split nao move razao: o maior endereco
    // continua com ~94% do carryover (3.546.175.400 BLCH da G3, escalado).
    assert_eq!(tk::LARGEST_CARRYOVER_ADDRESS_BLOCH, 17_046_829_380);
    let share = tk::LARGEST_CARRYOVER_ADDRESS_BLOCH * 10_000 / tk::CARRYOVER_TOTAL_BLOCH;
    assert_eq!(share, 9394, "93,94% do carryover num endereco so");
}

#[test]
fn allocations_sum_to_total_supply() {
    let sum = tk::CARRYOVER_TOTAL_BLOCH + tk::FOUNDER_BLOCH + tk::VC_BLOCH
        + tk::TEAM_BLOCH + tk::MARKETING_BLOCH + tk::LIQUIDITY_BLOCH
        + tk::VALIDATOR_EMISSION_BLOCH;
    assert_eq!(sum, tk::TOTAL_SUPPLY_BLOCH);
    assert_eq!(tk::VALIDATOR_EMISSION_BLOCH, 42_853_600_000);
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
    assert_eq!(tk::validator_reward_flat_sat(0) / tk::SAT_PER_BLOCH, 1_018);
}

#[test]
fn halving_curve_halves_every_four_years() {
    let r0 = tk::validator_reward_halving_sat(0);
    assert_eq!(r0 / tk::SAT_PER_BLOCH, 5_097);
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
    // 24 meses desde a decisao do founder de 2026-08-21 (era 120, dez anos).
    // O comentario acima ja dizia 24: era do rascunho que a decisao de 11/08
    // tinha revertido, e ficou dessincronizado do valor fixado aqui.
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
fn total_supply_headroom_is_pinned_honestly() {
    // The documented reason every quantity is u128 (§8.1), re-pinned for the
    // 2026-08-12 split: 100 bi = 54,21% de u64::MAX. Um saldo unico cabe em
    // u64 (com 1,84x de folga, e so), a soma de DOIS saldos grandes estoura —
    // toda soma de satoshis e u128, e as asserts de compilacao em
    // tokenomics_v4 pinam as duas direcoes. E o int64 do SDK Go NAO comporta
    // o total — quebra conhecida e aceita na decisao do split, nao um
    // acidente a descobrir depois.
    assert!(tk::TOTAL_SUPPLY_SAT <= u64::MAX as u128, "um saldo tem de caber em u64");
    assert!(tk::TOTAL_SUPPLY_SAT * 2 > u64::MAX as u128, "saiu da zona de wrap: reavalie");
    assert!(tk::TOTAL_SUPPLY_SAT > i64::MAX as u128, "int64 do Go voltou a caber: atualize docs");
    // A folga exata, para o dossie: u64::MAX / supply_sat = 1 (inteiro), ou
    // seja, menos de 2x — nunca some dois saldos em u64.
    assert_eq!((u64::MAX as u128) / tk::TOTAL_SUPPLY_SAT, 1);
}

#[test]
fn decay_curve_meets_the_inflation_target() {
    // Founder requirement: annual inflation under 7% of total supply.
    let y1 = tk::annual_inflation_bps(0);
    assert!(y1 < 700, "ano 1 = {}bps, acima do teto de 700", y1);
    assert_eq!(y1, 434); // 4,34% (truncado)
    assert!(tk::annual_inflation_bps(4) < y1);
    assert!(tk::annual_inflation_bps(9) < tk::annual_inflation_bps(4));
    assert_eq!(tk::annual_inflation_bps(9), 168);
}

#[test]
fn the_split_left_the_inflation_schedule_untouched() {
    // A prova de que o split de 2026-08-12 e puro tambem no TEMPO, nao so nas
    // alocacoes: a inflacao anual em bps e IDENTICA a do cronograma de 21 bi
    // em todos os 40 anos (verificado fora de banda; os dez primeiros ficam
    // pinados aqui por valor). Se um recalculo futuro de INITIAL_ANNUAL_SAT
    // mover um unico ano em um unico bps, isto acusa.
    let pinned: [(u64, u128); 10] = [
        (0, 434), (1, 391), (2, 352), (3, 317), (4, 285),
        (5, 256), (6, 231), (7, 208), (8, 187), (9, 168),
    ];
    for (year, bps) in pinned {
        assert_eq!(tk::annual_inflation_bps(year), bps, "ano {year} saiu do cronograma");
    }
    // E a meta do fundador vale em todos os anos, nao so no pico.
    for year in 0..40 {
        assert!(tk::annual_inflation_bps(year) < 700, "ano {year} acima de 7%");
    }
}

#[test]
fn decay_curve_declines_ten_percent_a_year() {
    let y0 = tk::validator_reward_decay_sat(0);
    let y1 = tk::validator_reward_decay_sat(tk::SLOTS_PER_YEAR);
    let ratio = y1 * 1000 / y0;
    assert!((899..=901).contains(&ratio), "razao anual = {ratio}/1000");
    assert_eq!(y0 / tk::SAT_PER_BLOCH, 4_134);
}

#[test]
fn decay_curve_emits_the_allocation_exactly() {
    let alloc = tk::VALIDATOR_EMISSION_BLOCH * tk::SAT_PER_BLOCH;
    let emitted = tk::validator_emitted_decay_by(tk::EMISSION_SLOTS);
    // Under the cap, never over: truncation may strand dust, never mint.
    assert!(emitted <= alloc, "emitiu {emitted} > alocado {alloc}");
    let residual = alloc - emitted;
    // O residuo e IRREDUTIVEL (a soma de 40 anos e multipla de SLOTS_PER_YEAR
    // e a alocacao nao e) — a afirmacao antiga de "residuo zero" era
    // impossivel e foi corrigida em tokenomics_v4. Pinado por constante E por
    // valor, para o dossie.
    assert_eq!(residual, tk::EMISSION_DUST_SAT, "residuo mudou: {residual} sat");
    assert_eq!(tk::EMISSION_DUST_SAT, 855_280);
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

    // A margem e uma RAZAO, e o split de 2026-08-12 nao move razao nenhuma:
    // validadores lideram o maior balde de insider por ~1,7x no mes 24, o
    // mesmo que no supply de 21 bi. (A margem encolhera na volta para 21 bi
    // porque a ALOCACAO relativa mudou naquela revisao; o split nao muda.)
    assert!(validators > biggest_insider,
        "validadores {validators} atras do maior insider {biggest_insider}");
    let ratio = validators * 100 / biggest_insider;
    assert!((160..=185).contains(&ratio), "margem mudou: {ratio}/100");
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
    let issuance = 4_367_467_018 * sat; // ano 1 sob o split
    let p = rewards::distribute(&acct(total / 2, total / 2, 500), issuance, total);
    assert_eq!(p.operator + p.delegators, issuance);
}

#[test]
fn nominal_yield_exceeds_inflation_when_not_all_supply_is_staked() {
    let sat = tk::SAT_PER_BLOCH;
    let issuance = 4_367_467_018 * sat;                    // ano 1 (436 bps)
    let staked = tk::TOTAL_SUPPLY_BLOCH * sat * 2 / 3;     // dois tercos, como Solana
    let y = rewards::nominal_yield_bps(issuance, staked);
    assert!(y > 436, "yield {y}bps deveria superar a inflacao de 436bps");
    assert!((645..=665).contains(&y), "yield {y}bps");
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

/// Fixa a decisao do fundador de 2026-08-11: **saldo de carryover que e
/// liquido e tambem stakeavel.** O maior endereco do carryover — o do fundador
/// — entra inteiro como delegacao e vira stake ativo; nada no caminho de
/// admissao pergunta de onde a moeda veio (eligible=true e o UNICO valor que o
/// conjunto de taint vazio pode produzir para uma moeda carregada). Reverter a
/// decisao exige reintroduzir um criterio de origem, e este teste e onde essa
/// reintroducao quebra primeiro.
#[test]
fn carryover_liquid_balance_delegates_as_stake() {
    let founder = deleg(0, 1, tk::LARGEST_CARRYOVER_ADDRESS_BLOCH, 0);
    let others =
        deleg(2, 3, tk::CARRYOVER_TOTAL_BLOCH - tk::LARGEST_CARRYOVER_ADDRESS_BLOCH, 0);
    let r = Registry::resolve(&[founder, others], 0);
    // O carryover inteiro pode estar em stake — nenhum sat e recusado.
    assert_eq!(r.total_active(), tk::CARRYOVER_TOTAL_BLOCH * tk::SAT_PER_BLOCH);
    assert_eq!(r.state_of(&founder), StakeState::Active);
    // O que a decisao custa, medido em vez de narrado: com o carryover todo em
    // stake, o maior operador detem ~94% do stake ativo — G2 (< 2.500 bps)
    // vermelho e coeficiente de Nakamoto 1 ate as moedas mudarem de mao. A
    // conta completa esta em BLOCH-TOKENOMICS-V4.md §4A.1 e §11 da migracao.
    assert!(r.top_share_bps() > 9_000);
    assert_eq!(r.nakamoto_coefficient(), 1);
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

/// Epocas para o conjunto ativo crescer por um fator, na taxa de warm-up
/// vigente. Os testes de churn derivam o horizonte daqui em vez de fixar um
/// numero: a taxa e um parametro de consenso que ja mudou uma vez (900 -> 25
/// bps, 2026-08-11) e um horizonte fixo teria virado um teste que passa por
/// motivo errado.
fn epochs_to_grow_by(factor: f64) -> u64 {
    let r = delegation::WARMUP_RATE_BPS as f64 / 10_000.0;
    (factor.ln() / (1.0 + r).ln()).ceil() as u64
}

#[test]
fn warmup_is_rate_limited_so_stake_cannot_seize_the_set_in_one_epoch() {
    // A large incumbent, then a whale that tries to activate everything at once.
    let mut ds = vec![deleg(1, 10, 100_000_000, 0)];
    for i in 0..20u32 {
        ds.push(deleg(100 + i, 20, 10_000_000, 1));
    }
    // Horizonte DERIVADO da constante, nao um numero magico: o conjunto
    // precisa triplicar (100M incumbente -> 300M), o que a taxa de warm-up
    // leva `ln(3)/ln(1+r)` epocas. Um 40 fixo aqui era so o valor que passava
    // com 900 bps e escondia que o teste dependia da taxa.
    let horizon = epochs_to_grow_by(3.0) + 8;
    let e1 = Registry::resolve(&ds, 1);
    let done = Registry::resolve(&ds, horizon);
    assert!(e1.stake_of(20) < done.stake_of(20),
        "a baleia entrou inteira numa epoca so: {} vs {}", e1.stake_of(20), done.stake_of(20));
    // And eventually it all lands.
    assert_eq!(done.stake_of(20), 200_000_000 * tk::SAT_PER_BLOCH);
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
fn deactivation_drains_gradually_and_completes() {
    // Antes da correcao do F3 a saida era instantanea: um registro saia inteiro
    // numa epoca so. Agora o cool-down e fatiado pelo mesmo orcamento de 9% do
    // warm-up, entao a saida drena e o teto vale nos DOIS sentidos — esvaziar o
    // conjunto rapido era tao perigoso quanto enche-lo.
    // 10M BLCH: bem acima do piso de churn de 500k BLCH/epoca (2026-08-12),
    // para que a drenagem leve varias epocas e a monotonicidade seja visivel.
    let mut d = deleg(1, 10, 10_000_000, 0);
    d.deactivate_epoch = Some(5);
    let at = |e: u64| Registry::resolve(&[d], e).stake_of(10);

    let before = at(4);
    assert!(before > 0, "ativa antes do pedido de saida");
    assert_eq!(Registry::resolve(&[d], 4).state_of(&d), StakeState::Active);

    // Drena de forma monotona, sem sumir de uma vez.
    let after_one = at(6);
    let after_two = at(7);
    assert!(after_one < before, "nao comecou a drenar");
    assert!(after_two < after_one, "drenagem parou no meio");
    assert!(after_one > 0, "saiu tudo numa epoca so — o teto foi contornado");

    // E termina.
    assert_eq!(at(200), 0, "a saida nunca completou");
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
    committee_for_slot, epoch_committees, is_supermajority, seed_epoch, seed_mix,
    seeded_epoch_committees, total_active_stake, MIN_SEED_LOOKAHEAD_EPOCHS,
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

/// Zero-stake validators DO get a seat — an inert one.
///
/// Inverted 2026-08-24. This test used to assert the opposite: that
/// `epoch_committees` dropped every validator with `effective_stake == 0`. That
/// filter ran *before* the Fisher-Yates shuffle, so a roster of 64 and the same
/// roster with one validator leaked to zero produced entirely different
/// permutations — and `transition.rs` holds both variants for one epoch (step 8
/// reads the leak-applied roster, the boundary tally reads the unleaked one).
/// The result was that attestations a block had admitted were dropped at the
/// boundary and nothing finalized.
///
/// Membership is now a pure function of (seed, epoch, index set); stake decides
/// WEIGHT only, and a zero-weight member contributes 0 to both sides of the
/// quorum. Ineligibility — slashed, exited, not yet activated — is applied at
/// the roster level in `transition::duty_roster_at`, which is the one predicate
/// all four roster producers share. See `committees::epoch_committees`' docs.
#[test]
fn zero_stake_validators_hold_an_inert_seat_rather_than_being_dropped() {
    let mut vs = uniform_set(100, 100_000);
    for v in vs.iter_mut().take(40) {
        v.effective_stake = 0;
    }
    let cs = epoch_committees(&MIX, 1, &vs);
    let all: Vec<u32> = cs.iter().flatten().copied().collect();
    assert_eq!(all.len(), 100, "every validator in the index set gets exactly one seat");
    assert!((0..40).all(|i| all.contains(&i)), "the zero-stake validators must be seated");

    // The seats are inert: identical partition to one where those 40 carry
    // stake, so no call path can move the committees by changing stake.
    let funded = uniform_set(100, 100_000);
    assert_eq!(
        epoch_committees(&MIX, 1, &funded),
        cs,
        "the partition must be invariant under a pure stake change"
    );
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

// ── beacon seed look-ahead (F6 fix) ─────────────────────────────────────────

/// Fold one deterministic pseudo-reveal per slot of `epoch` into `mix`,
/// skipping the last `withheld_tail` slots — the adversary's only move (§6.3:
/// reveal or withhold; a third outcome is a SHAKE-256 preimage attack, pinned
/// by the beacon's own tests).
fn close_of_epoch(mix: [u8; 32], epoch: u64, withheld_tail: u64) -> [u8; 32] {
    let mut m = mix;
    for s in 0..SLOTS_PER_EPOCH - withheld_tail {
        let mut r = [0u8; 32];
        r[..8].copy_from_slice(&(epoch * SLOTS_PER_EPOCH + s).to_le_bytes());
        m = mix_in(&m, &r);
    }
    m
}

#[test]
fn seed_epoch_arithmetic_and_missing_history() {
    // The constant is consensus: moving it re-times every duty on the chain.
    assert_eq!(MIN_SEED_LOOKAHEAD_EPOCHS, 1);
    // Epochs with no usable boundary behind them fall back to the genesis mix.
    assert_eq!(seed_epoch(0), None);
    assert_eq!(seed_epoch(1), None);
    // From then on: epoch N is seeded by the close of N − 2.
    assert_eq!(seed_epoch(2), Some(0));
    assert_eq!(seed_epoch(7), Some(5));

    let genesis = [1u8; 32];
    let closes = [[2u8; 32]]; // history holds only the close of epoch 0
    assert_eq!(seed_mix(&genesis, &closes, 0), Some(genesis));
    assert_eq!(seed_mix(&genesis, &closes, 1), Some(genesis));
    assert_eq!(seed_mix(&genesis, &closes, 2), Some(closes[0]));
    // Missing history must fail loudly, never fall back to a newer mix —
    // a silent fallback would be F6 reintroduced in the error path.
    assert_eq!(seed_mix(&genesis, &closes, 3), None);
    let vs = uniform_set(100, 100_000);
    assert!(seeded_epoch_committees(&genesis, &closes, 3, &vs).is_none());

    // Epochs 0 and 1 share the genesis mix but still partition differently,
    // because the epoch number is folded into the XOF seed.
    assert_ne!(epoch_committees(&genesis, 0, &vs), epoch_committees(&genesis, 1, &vs));
}

#[test]
fn withholding_in_the_tail_of_an_epoch_cannot_resort_the_next_epochs_partition() {
    // The F6 attack: the proposers of the last t slots of epoch 3 choose
    // reveal-or-withhold, grinding 2^t candidate mixes, trying to re-sort the
    // partition of epoch 4 — the body whose votes justify and finalize.
    //
    // Two beacon histories, identical through the close of epoch 2, diverging
    // only in epoch 3's tail: honest reveals everything, the adversary
    // withholds the last 4 slots.
    let genesis = [0u8; 32];
    let vs = uniform_set(300, 100_000);

    let mut closes_honest: Vec<[u8; 32]> = Vec::new();
    let mut closes_withheld: Vec<[u8; 32]> = Vec::new();
    let mut mh = genesis;
    let mut mw = genesis;
    for e in 0..=4u64 {
        mh = close_of_epoch(mh, e, 0);
        mw = close_of_epoch(mw, e, if e == 3 { 4 } else { 0 });
        closes_honest.push(mh);
        closes_withheld.push(mw);
    }
    assert_eq!(closes_honest[2], closes_withheld[2], "histories must agree before the attack");
    assert_ne!(closes_honest[3], closes_withheld[3], "withholding must actually move the mix");

    // THE PROPERTY: epoch 4's partition is identical in both histories. Its
    // seed is the close of epoch 2 (look-ahead of 1), fixed before any of the
    // adversary's epoch-3 slots existed.
    let honest = seeded_epoch_committees(&genesis, &closes_honest, 4, &vs).unwrap();
    let withheld = seeded_epoch_committees(&genesis, &closes_withheld, 4, &vs).unwrap();
    assert_eq!(honest, withheld, "tail withholding re-sorted the next epoch — F6 is back");

    // And the proposer roster for epoch 4 is equally immune: same seed rule.
    let sh = epoch_schedule(&seed_mix(&genesis, &closes_honest, 4).unwrap(), 4, &vs).unwrap();
    let sw = epoch_schedule(&seed_mix(&genesis, &closes_withheld, 4).unwrap(), 4, &vs).unwrap();
    assert_eq!(sh, sw, "tail withholding re-sorted the proposer schedule");

    // Teeth: under the pre-F6 rule (seed = close of epoch 3), the same
    // withholding WOULD have re-sorted epoch 4. If this ever fails, the test
    // above is vacuous and must be rewritten.
    assert_ne!(
        epoch_committees(&closes_honest[3], 4, &vs),
        epoch_committees(&closes_withheld[3], 4, &vs),
        "counterfactual lost its teeth: the old rule no longer differs"
    );

    // Honest residual, stated as a test: the bias is displaced, not erased.
    // Epoch 5 is seeded by the close of epoch 3, so the withholding does move
    // THAT partition — one bit per withheld slot, an epoch later, exactly the
    // residual §6.3 prices in and Ethereum accepts under MIN_SEED_LOOKAHEAD.
    let h5 = seeded_epoch_committees(&genesis, &closes_honest, 5, &vs).unwrap();
    let w5 = seeded_epoch_committees(&genesis, &closes_withheld, 5, &vs).unwrap();
    assert_ne!(h5, w5, "the residual vanished — something other than look-ahead changed");
}

#[test]
fn warmup_cap_holds_even_for_an_oversized_delegation() {
    // F3: a escapatoria de liveness anterior admitia a cabeca da fila INTEIRA,
    // qualquer que fosse o tamanho — entao uma delegacao grande ativava de uma
    // vez e contornava o teto por epoca. Com fatiamento, ela entra em pedacos.
    // 1 bi BLCH de base: o orcamento proporcional (25 bps = 2,5M) fica acima
    // do piso de 500k BLCH, entao o teste exercita a TAXA, nao o piso.
    let incumbent = deleg(1, 10, 1_000_000_000, 0);
    let whale = deleg(2, 20, 5_000_000_000, 1); // 5x o incumbente
    let ds = vec![incumbent, whale];

    let base = Registry::resolve(&ds, 0).total_active();
    let e1 = Registry::resolve(&ds, 1);
    let entered = e1.total_active() - base;
    // Teto lido da constante, nao restatado: um `9 / 100` aqui sobrevive a
    // mudanca da taxa e passa a testar um limite que nao existe mais. O piso
    // entra pelo mesmo motivo — o orcamento real e max(taxa, piso).
    let cap = (base * delegation::WARMUP_RATE_BPS / 10_000).max(delegation::MIN_CHURN_SAT);
    assert!(entered <= cap + 1, "entrou {entered}, teto era {cap} — F3 de volta");
    assert!(entered > 0, "nada entrou: deadlock, que e o bug que a escapatoria consertava");

    // Parcialmente ativa nao conta como admitida.
    assert_eq!(e1.state_of(&whale), StakeState::Activating);

    // E eventualmente entra inteira: 1 bi -> 6 bi, seis vezes o conjunto.
    let done = Registry::resolve(&ds, epochs_to_grow_by(6.0) + 8);
    assert_eq!(done.stake_of(20), 5_000_000_000 * tk::SAT_PER_BLOCH);
    assert_eq!(done.state_of(&whale), StakeState::Active);
}

#[test]
fn genesis_is_still_unlimited_so_the_chain_can_start() {
    // A excecao do genesis continua: no epoch 0 nao existe conjunto a proteger,
    // e sem ela nada nunca ativa (orcamento de 9% de zero e zero).
    let ds: Vec<Delegation> = (0..10u32).map(|i| deleg(i, i, 1_000_000, 0)).collect();
    let r = Registry::resolve(&ds, 0);
    assert_eq!(r.total_active(), 10_000_000 * tk::SAT_PER_BLOCH);
    assert_eq!(r.validators().len(), 10);
}

#[test]
fn each_foundation_bucket_is_pinned() {
    let sat = tk::SAT_PER_BLOCH;
    assert_eq!(tk::VC_BLOCH, 10_000_000_000);
    assert_eq!(tk::TEAM_BLOCH, 10_000_000_000);
    assert_eq!(tk::MARKETING_BLOCH, 4_000_000_000);
    assert_eq!(tk::LIQUIDITY_BLOCH, 5_000_000_000);
    assert_eq!(tk::FOUNDATION_HELD_BLOCH, 29_000_000_000);
    assert_eq!(tk::FOUNDATION_HELD_BLOCH * 100 / tk::TOTAL_SUPPLY_BLOCH, 29);

    // Liquido no genesis: so liquidez inteira e o quarto do marketing.
    assert_eq!(tk::vc_vested_sat(0), 0, "VC nao pode ter nada liquido no genesis");
    assert_eq!(tk::team_vested_sat(0), 0, "time nao pode ter nada liquido no genesis");
    assert_eq!(tk::marketing_vested_sat(0), 1_000_000_000 * sat);
    assert_eq!(tk::liquidity_vested_sat(0), 5_000_000_000 * sat);
    assert_eq!(tk::FOUNDATION_LIQUID_AT_GENESIS_BLOCH, 6_000_000_000);

    // Cada balde veste por inteiro, no prazo dele.
    let y = tk::SLOTS_PER_YEAR;
    assert_eq!(tk::vc_vested_sat(3 * y), tk::VC_BLOCH * sat, "VC no ano 3");
    assert_eq!(tk::team_vested_sat(5 * y), tk::TEAM_BLOCH * sat, "time no ano 4,5");
    assert_eq!(tk::marketing_vested_sat(2 * y), tk::MARKETING_BLOCH * sat);
}

#[test]
fn two_holders_account_for_the_entire_genesis_float() {
    // O numero do 7B: a fundacao fica com exatamente 25% do circulante no slot
    // 0 e o carryover com os outros 75%. Nenhum dos dois consegue mudar isso
    // se comportando diferente — so emissao e stake independente diluem.
    let f = tk::FOUNDATION_LIQUID_AT_GENESIS_BLOCH;
    let c = tk::CARRYOVER_TOTAL_BLOCH;
    let circulating = f + c;
    assert_eq!(circulating, 24_146_400_000);
    assert_eq!(f * 1000 / circulating, 248, "fundacao = 24,8% do circulante");
    assert_eq!(c * 1000 / circulating, 751, "carryover = 75,1% (truncado)");
}

// ── coorte de genesis e o teto declinante ───────────────────────────────────

use bloch_pos_committee::genesis_cohort::{
    apply_cohort_cap, cohort_cap_bps, cohort_share_bps, COHORT_CAP_FLOOR_BPS, EPOCHS_PER_YEAR,
};

#[test]
fn the_cap_reaches_one_third_at_one_year_and_holds() {
    assert_eq!(cohort_cap_bps(0), 10_000, "no genesis a coorte E o conjunto");
    let half = cohort_cap_bps(EPOCHS_PER_YEAR / 2);
    assert!((6_600..=6_700).contains(&half), "meio do ano: {half}bps");
    assert_eq!(cohort_cap_bps(EPOCHS_PER_YEAR), COHORT_CAP_FLOOR_BPS);
    assert_eq!(cohort_cap_bps(EPOCHS_PER_YEAR * 10), COHORT_CAP_FLOOR_BPS, "nao volta a subir");
    // Monotonicamente decrescente — pressao continua, nao um degrau.
    let mut prev = u128::MAX;
    for e in (0..EPOCHS_PER_YEAR).step_by((EPOCHS_PER_YEAR / 40) as usize) {
        let c = cohort_cap_bps(e);
        assert!(c <= prev, "teto subiu na epoca {e}");
        prev = c;
    }
}

#[test]
fn a_founder_holding_everything_is_capped_to_a_third_after_a_year() {
    // A coorte com 90% do stake, um ano depois.
    // Escala realista: o teto so vale quando ha pelo menos um deposito minimo
    // (100.000 BLCH) de stake independente — abaixo disso ele defere, porque
    // nao ha de quem a coorte seja um terco.
    let mut vs: Vec<Validator> = (0..64u32)
        .map(|i| Validator { index: i, effective_stake: 900_000_000_000_000 })
        .collect();
    vs.extend((100..110u32).map(|i| Validator { index: i, effective_stake: 7_000_000_000_000 }));
    let cohort: Vec<u32> = (0..64u32).collect();

    assert!(cohort_share_bps(&vs, &cohort) > 9_000, "o teste nao esta exercitando o teto");

    let capped = apply_cohort_cap(&vs, &cohort, EPOCHS_PER_YEAR);
    let share = cohort_share_bps(&capped, &cohort);
    assert!(share <= COHORT_CAP_FLOOR_BPS + 1, "coorte ficou em {share}bps, acima de 1/3");

    // E abaixo de 1/3 e exatamente o ponto em que ela deixa de poder travar
    // um quorum de 2/3.
    let total: u128 = capped.iter().map(|v| v.effective_stake as u128).sum();
    let coh: u128 = capped.iter().filter(|v| v.index < 64).map(|v| v.effective_stake as u128).sum();
    assert!(coh * 3 <= total, "a coorte ainda consegue travar a finalidade");
}

#[test]
fn at_genesis_nothing_is_capped_because_the_cohort_is_everything() {
    let vs: Vec<Validator> = (0..64u32)
        .map(|i| Validator { index: i, effective_stake: 1_000_000 })
        .collect();
    let cohort: Vec<u32> = (0..64u32).collect();
    assert_eq!(apply_cohort_cap(&vs, &cohort, 0), vs, "o genesis nao pode ser capado");
}

#[test]
fn non_cohort_validators_are_never_touched() {
    let vs = vec![
        Validator { index: 1, effective_stake: 900_000_000_000_000 },  // coorte
        Validator { index: 50, effective_stake: 100_000_000_000_000 }, // independente
    ];
    let capped = apply_cohort_cap(&vs, &[1], EPOCHS_PER_YEAR);
    assert_eq!(capped[1].effective_stake, 100_000_000_000_000, "stake independente foi mexido");
    assert!(capped[0].effective_stake < 900_000_000_000_000, "a coorte nao foi capada");
}

#[test]
fn the_cap_scales_the_cohort_pro_rata() {
    // Qual validador da coorte absorve a reducao nao pode importar: a coorte e
    // um ator economico so, e escolher convidaria a embaralhar stake entre eles.
    let vs = vec![
        Validator { index: 1, effective_stake: 600_000_000_000_000 },
        Validator { index: 2, effective_stake: 300_000_000_000_000 },
        Validator { index: 50, effective_stake: 100_000_000_000_000 },
    ];
    let capped = apply_cohort_cap(&vs, &[1, 2], EPOCHS_PER_YEAR);
    // 2:1 antes, 2:1 depois.
    assert_eq!(capped[0].effective_stake / capped[1].effective_stake, 2);
    assert!(capped[0].effective_stake < 600_000_000_000_000);
}

#[test]
fn a_cohort_already_under_the_cap_is_left_alone() {
    let vs = vec![
        Validator { index: 1, effective_stake: 100_000_000_000_000 },
        Validator { index: 50, effective_stake: 900_000_000_000_000 },
    ];
    assert_eq!(apply_cohort_cap(&vs, &[1], EPOCHS_PER_YEAR), vs);
}

#[test]
fn the_cap_does_not_halt_a_cold_launch() {
    // G2, achado por revisao adversarial: com truncagem inteira o taper morde
    // na EPOCA 5 — ~1,3 h depois do genesis — e ali (10000-bps)==1, entao o teto
    // e 9999*O. Sem stake independente, O=0, o teto e 0, e a coorte inteira
    // (que num lancamento frio E a rede) ia a zero. A regra de descentralizacao
    // mataria a cadeia no primeiro dia.
    use bloch_pos_committee::genesis_cohort::{cap_status, CapStatus};
    let vs: Vec<Validator> = (0..64u32)
        .map(|i| Validator { index: i, effective_stake: 1_000_000_000_000 })
        .collect();
    let cohort: Vec<u32> = (0..64u32).collect();

    for e in [5u64, 10, 100, EPOCHS_PER_YEAR, EPOCHS_PER_YEAR * 5] {
        let out = apply_cohort_cap(&vs, &cohort, e);
        let total: u128 = out.iter().map(|v| v.effective_stake as u128).sum();
        assert!(total > 0, "epoca {e}: a coorte foi zerada e a cadeia para");
        assert_eq!(out, vs, "epoca {e}: nao deveria capar sem stake independente");
        assert!(matches!(cap_status(&vs, &cohort, e),
                         CapStatus::Deferred { .. } | CapStatus::NotTapering));
    }
}

#[test]
fn the_cap_engages_once_independent_stake_arrives() {
    use bloch_pos_committee::genesis_cohort::{cap_status, CapStatus};
    let mut vs: Vec<Validator> = (0..64u32)
        .map(|i| Validator { index: i, effective_stake: 1_000_000_000_000 })
        .collect();
    let cohort: Vec<u32> = (0..64u32).collect();

    // Um deposito independente acima do minimo: a regra passa a valer.
    vs.push(Validator { index: 999, effective_stake: 20_000_000_000_000 });
    let st = cap_status(&vs, &cohort, EPOCHS_PER_YEAR);
    assert!(matches!(st, CapStatus::Enforced { .. }), "deveria valer: {st:?}");

    let out = apply_cohort_cap(&vs, &cohort, EPOCHS_PER_YEAR);
    let share = cohort_share_bps(&out, &cohort);
    assert!(share <= COHORT_CAP_FLOOR_BPS + 1, "coorte em {share}bps");
    assert!(out.iter().map(|v| v.effective_stake as u128).sum::<u128>() > 0);
}

#[test]
fn the_f1_attack_no_longer_works() {
    // F1: com comite AMOSTRADO de 128 e quorum sobre o stake DO COMITE, um
    // adversario com ~30% do stake da rede passa de 1/3 do comite por variancia
    // amostral em cerca de uma epoca a cada cinco, e trava a finalidade.
    //
    // Sob particao isso deixa de existir por construcao: a uniao dos comites da
    // epoca E o conjunto ativo, entao o denominador e o stake total da rede e a
    // fatia do adversario no denominador e exatamente a fatia dele na rede —
    // sem variancia para explorar.
    use bloch_pos_committee::committees::{epoch_committees, total_active_stake};

    let mut vs: Vec<Validator> = (0..300u32)
        .map(|i| Validator { index: i, effective_stake: 100_000 })
        .collect();
    // Adversario com ~30% do stake espalhado em 128 registros.
    for i in 0..128u32 {
        vs.push(Validator { index: 1000 + i, effective_stake: 100_000 });
    }
    let adversary: std::collections::HashSet<u32> = (1000..1128).collect();
    let total = total_active_stake(&vs);

    // Sob particao, a fatia do adversario no DENOMINADOR e estavel em toda
    // epoca — nao ha sorteio de onde ele possa sair melhor.
    let adv_stake: u128 = vs.iter()
        .filter(|v| adversary.contains(&v.index))
        .map(|v| v.effective_stake as u128).sum();
    let share = adv_stake * 10_000 / total;

    for epoch in 0..40u64 {
        let cs = epoch_committees(&MIX, epoch, &vs);
        // Toda epoca: uniao == conjunto ativo, entao o denominador nao varia.
        let seats: usize = cs.iter().map(|c| c.len()).sum();
        assert_eq!(seats, vs.len(), "epoca {epoch}: a uniao deixou de ser o conjunto");
        let adv_seats: usize = cs.iter().flatten().filter(|v| adversary.contains(v)).count();
        assert_eq!(adv_seats, 128, "epoca {epoch}: assentos do adversario variaram");
    }

    // E a fatia dele fica abaixo de 1/3, entao ele nao trava nada — em NENHUMA
    // epoca, nao "na maioria delas".
    assert!(share < 3_333, "adversario com {share}bps do denominador");
}

#[test]
fn out_of_slot_attestations_are_dropped_not_counted_absent() {
    // O wiring so vale se ele conferir o comite DO SLOT, nao "algum comite da
    // epoca". Um voto do slot errado seria voto em todo slot alcancavel, que e
    // exatamente o risco de duplo voto que a particao existe para remover.
    use bloch_pos_committee::committees::epoch_committees;
    use bloch_pos_committee::finality::votes_from_partition;

    let vs: Vec<Validator> = (0..200u32)
        .map(|i| Validator { index: i, effective_stake: 100_000 })
        .collect();
    let epoch = 3u64;
    let cs = epoch_committees(&MIX, epoch, &vs);

    // Um validador do comite do slot 0, votando pelo slot 0 (valido) e pelo
    // slot 1 (invalido — nao e o comite dele).
    let v = cs[0][0];
    let base = AttestationData {
        slot: epoch * SLOTS_PER_EPOCH,
        head: [1u8; 32],
        source_epoch: epoch - 1, source_root: [2u8; 32],
        target_epoch: epoch, target_root: [3u8; 32],
    };
    let wrong = AttestationData { slot: base.slot + 1, ..base };
    let atts = vec![(v, base), (v, wrong)];

    let mut buf = Vec::new();
    let out = votes_from_partition(epoch, &vs, &vs, &atts, &MIX, &mut buf);
    assert_eq!(out.attestations.len(), 1, "voto de slot alheio foi aceito");
    assert_eq!(out.attestations[0].1.slot, base.slot);
    // E o denominador continua sendo o conjunto ativo INTEIRO.
    assert_eq!(out.active_set.len(), 200);
}

// ── The verifier reads the registry (2026-09-02) ────────────────────────────
//
// These are the "verify by violating" cases for the change that made consensus
// signature checks resolve keys from the committed validator registry instead
// of from a table built once at boot from the genesis manifest.
//
// The defect being closed: a validator added by an on-chain deposit registered,
// activated, entered the roster and was drawn for a committee, and then its
// GENUINE signature was rejected as `BadSignature`, because the boot-time table
// had no entry past the genesis set. Its committee seats could never be filled,
// so a deposit landing before the fix silently subtracted from finality.
//
// The verifier double below binds a signature to a KEY (not to an index),
// which is what the real hybrid suite does. That is the whole point: the index
// must stop being an input to "is this signature valid".

/// `sig == SHA3-ish(key ‖ root)`, a stand-in for the hybrid suite. Pure: this
/// crate deliberately carries no PQ dependency.
fn key_sign(pubkey: &[u8], root: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pubkey.len() + 32);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(root);
    out
}

struct KeyBound;
impl SignatureVerifier for KeyBound {
    fn verify_with_key(&self, pubkey: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        sig == key_sign(pubkey, root).as_slice()
    }
}

/// A registry: index → key. Lookup by the index FIELD, as production does.
struct KeyRegistry(Vec<(u32, Vec<u8>)>);
impl attestation::KeyLookup for KeyRegistry {
    fn pubkey(&self, validator: u32) -> Option<&[u8]> {
        self.0.iter().find(|(i, _)| *i == validator).map(|(_, k)| k.as_slice())
    }
}

fn key_of(index: u32) -> Vec<u8> {
    format!("validator-{index}-key").into_bytes()
}

/// Indices 0..=7 are the "genesis set"; index 8 is the validator a deposit
/// added afterwards — exactly the case the boot-time table could not serve.
fn registry_with_newcomer() -> KeyRegistry {
    KeyRegistry((0..=8u32).map(|i| (i, key_of(i))).collect())
}

fn signed_att(validator: u32, key: &[u8]) -> Attestation {
    let data = AttestationData {
        slot: 294,
        head: [0xAA; 32],
        source_epoch: 1,
        source_root: [1u8; 32],
        target_epoch: 2,
        target_root: [2u8; 32],
    };
    let sig = key_sign(key, &data.signing_root());
    Attestation { data, validator, signature: sig }
}

#[test]
fn deposit_added_validator_now_verifies() {
    // The exact failing case from the report: newcomer at index 8, drawn for
    // slot 294, committee = [8] — a committee consisting ENTIRELY of the
    // validator whose votes could never be counted.
    let committee = vec![8u32];
    let att = signed_att(8, &key_of(8));
    assert_eq!(
        attestation::validate(&att, &committee, 294, &KeyBound, &registry_with_newcomer()),
        Ok(()),
        "a deposit-added validator's genuine signature must be accepted"
    );
}

#[test]
fn genuinely_bad_signature_is_still_rejected() {
    let committee = vec![8u32];
    let mut att = signed_att(8, &key_of(8));
    att.signature = b"not the signature".to_vec();
    assert_eq!(
        attestation::validate(&att, &committee, 294, &KeyBound, &registry_with_newcomer()),
        Err(attestation::RejectReason::BadSignature),
    );
}

#[test]
fn key_not_in_the_registry_is_rejected() {
    // A signature that is perfectly well-formed under a key the registry does
    // not hold at that index. This is the case that matters most: the fix must
    // not degrade into "any signature by any key passes". The signer holds a
    // real keypair and signs correctly — it is simply not the key registered
    // at index 8.
    let committee = vec![8u32];
    let stranger = b"a key that was never registered".to_vec();
    let att = signed_att(8, &stranger);
    assert_eq!(
        attestation::validate(&att, &committee, 294, &KeyBound, &registry_with_newcomer()),
        Err(attestation::RejectReason::BadSignature),
        "a genuine signature under an unregistered key must not authorise an index"
    );
}

#[test]
fn index_outside_the_registry_is_rejected() {
    // Index 9 is in the committee this node drew but absent from the registry.
    // Distinct from BadSignature on purpose: it says the registry does not know
    // the index, which is a statement about state, not about the bytes.
    let committee = vec![9u32];
    let att = signed_att(9, &key_of(9));
    assert_eq!(
        attestation::validate(&att, &committee, 294, &KeyBound, &registry_with_newcomer()),
        Err(attestation::RejectReason::UnknownValidator),
    );
}

#[test]
fn one_validators_signature_does_not_authorise_another_index() {
    // `AttestationData::signing_root()` does NOT cover the validator index —
    // it covers only the vote. So the ONLY thing binding a vote to a voter is
    // which key the registry returns for that index. Validator 3 signs; the
    // attestation is presented as validator 4's. It must fail, and it fails
    // because index 4 resolves to a different key.
    //
    // This is why the registry's index→key map being injective and permanent
    // (indices never reused, pubkeys never mutated, records never removed,
    // duplicate pubkeys refused at deposit) is load-bearing, not incidental.
    let committee = vec![3u32, 4u32];
    let mut att = signed_att(3, &key_of(3));
    att.validator = 4;
    assert_eq!(
        attestation::validate(&att, &committee, 294, &KeyBound, &registry_with_newcomer()),
        Err(attestation::RejectReason::BadSignature),
    );
}

#[test]
fn membership_is_still_checked_before_the_registry_is_touched() {
    // The DoS ordering must survive the change: a non-member is rejected on
    // the cheap binary search, never reaching the registry probe. Proven by a
    // lookup that panics if consulted.
    struct Exploding;
    impl attestation::KeyLookup for Exploding {
        fn pubkey(&self, _v: u32) -> Option<&[u8]> {
            panic!("registry consulted before the committee membership check");
        }
    }
    let committee = vec![1u32, 2u32];
    let att = signed_att(7, &key_of(7));
    assert_eq!(
        attestation::validate(&att, &committee, 294, &KeyBound, &Exploding),
        Err(attestation::RejectReason::NotInCommittee),
    );
}

#[test]
fn registry_lookup_equals_the_old_index_table_over_the_genesis_set() {
    // THE INERTNESS PROOF, in its pure form.
    //
    // The deleted code did `pubkeys.get(index)` over a `Vec<Vec<u8>>` built
    // from the genesis manifest in index order. While the registry still
    // equals the genesis set — which is the live chain's state today: 64
    // registered, 64 active, every activation_epoch 0, no deposit ever — the
    // two lookups must return identical bytes for every index, and both must
    // answer None past the end. If that holds, the change is observationally
    // inert and can ship and soak ahead of the deposit flag day rather than
    // being bundled with it.
    let genesis_set: Vec<Vec<u8>> = (0..64u32).map(key_of).collect();
    let old_table = |i: u32| genesis_set.get(i as usize).map(|k| k.as_slice());

    let registry = KeyRegistry((0..64u32).map(|i| (i, key_of(i))).collect());
    let new_lookup = |i: u32| attestation::KeyLookup::pubkey(&registry, i);

    for i in 0..64u32 {
        assert_eq!(old_table(i), new_lookup(i), "index {i} resolves differently");
        assert!(new_lookup(i).is_some());
    }
    // And both agree about absence, which is the half that decides whether a
    // node that has not yet applied a deposit behaves like the old one.
    for i in 64..80u32 {
        assert_eq!(old_table(i), None);
        assert_eq!(new_lookup(i), None);
    }
}
