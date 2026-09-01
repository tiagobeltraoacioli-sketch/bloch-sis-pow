// SPDX-License-Identifier: AGPL-3.0-or-later
//! INDEPENDENT reproduction probe for the claim that `Store::observe` is
//! "a function of the message set, never of arrival order".
//!
//! Written from the source, not copied from the reported witness, and it
//! searches ALL permutations rather than asserting one hand-picked pair.

use std::collections::HashMap;

use bloch_pos_committee::forkchoice::{BlockTree, LatestMessage, Store};

fn r(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Fold `msgs` (validator, message) in the given order and return
/// (head, equivocator count, voter count).
fn fold(order: &[(u32, LatestMessage)]) -> ([u8; 32], usize, usize) {
    let genesis = r(0);
    let mut parents = HashMap::new();
    let mut children = HashMap::new();
    let mut kids = Vec::new();
    for n in 1..=3u8 {
        parents.insert(r(n), genesis);
        kids.push(r(n));
    }
    children.insert(genesis, kids);
    let tree = BlockTree { parents: &parents };

    let mut s = Store::new();
    s.set_stake(0, 100);
    s.set_stake(1, 1);
    for (v, m) in order {
        s.observe(*v, *m);
    }
    (
        s.head(&tree, genesis, &children),
        s.equivocators().count(),
        s.voters(),
    )
}

fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut p in permutations(&rest) {
            p.insert(0, head.clone());
            out.push(p);
        }
    }
    out
}

/// THE FINDING. Same three messages, every arrival order, more than one head.
#[test]
fn fold_of_an_equivocating_pair_plus_a_later_vote_is_order_dependent() {
    let msgs = vec![
        (0u32, LatestMessage { slot: 5, root: r(1) }), // pair half A
        (0u32, LatestMessage { slot: 5, root: r(2) }), // pair half B
        (0u32, LatestMessage { slot: 7, root: r(3) }), // strictly later vote
        (1u32, LatestMessage { slot: 6, root: r(1) }), // tie-breaker, honest
    ];

    let mut heads: Vec<[u8; 32]> = Vec::new();
    let mut barred: Vec<usize> = Vec::new();
    for p in permutations(&msgs) {
        let (h, eq, _) = fold(&p);
        if !heads.contains(&h) {
            heads.push(h);
        }
        if !barred.contains(&eq) {
            barred.push(eq);
        }
    }
    heads.sort();
    barred.sort();

    assert!(
        heads.len() > 1,
        "observe is documented as set-determined; it produced ONE head over all \
         24 permutations, so the reported finding did not reproduce"
    );
    assert_eq!(
        heads,
        vec![r(1), r(3)],
        "expected exactly the two heads: A (equivocator barred) and C (bar masked)"
    );
    assert_eq!(
        barred,
        vec![0, 1],
        "the equivocation bar itself is order-dependent: it fires in some orders \
         and not others, from the identical message set"
    );
}

/// The masking rule stated directly, with no fork choice in the way: a vote at
/// a HIGHER slot swallows both halves of a lower-slot equivocating pair.
#[test]
fn a_higher_slot_vote_masks_a_lower_slot_equivocating_pair() {
    let a = LatestMessage { slot: 5, root: r(1) };
    let b = LatestMessage { slot: 5, root: r(2) };
    let later = LatestMessage { slot: 7, root: r(3) };

    let mut pair_first = Store::new();
    pair_first.observe(0, a);
    pair_first.observe(0, b);
    assert_eq!(pair_first.equivocators().count(), 1);
    // The bar is permanent, so the later honest vote is refused too.
    assert!(!pair_first.observe(0, later));
    assert_eq!(pair_first.voters(), 0);

    let later_first = {
        let mut s = Store::new();
        assert!(s.observe(0, later));
        // `prev.slot >= msg.slot` swallows BOTH halves before the equivocation
        // arm is ever reached, because the equivocation arm tests only
        // `prev.slot == msg.slot`.
        assert!(!s.observe(0, a));
        assert!(!s.observe(0, b));
        s
    };
    assert_eq!(
        later_first.equivocators().count(),
        0,
        "the pair is invisible once a later vote is stored"
    );
    assert_eq!(later_first.voters(), 1, "the validator keeps full weight");
}

/// GUARD CHECK, by deliberate violation: confirm the two orders really do
/// exercise the SAME message multiset, so the asymmetry is not an artefact of
/// the probe feeding different inputs to the two sides.
#[test]
fn the_two_orders_carry_the_identical_message_multiset() {
    let msgs = vec![
        (0u32, LatestMessage { slot: 5, root: r(1) }),
        (0u32, LatestMessage { slot: 5, root: r(2) }),
        (0u32, LatestMessage { slot: 7, root: r(3) }),
    ];
    for p in permutations(&msgs) {
        let mut key: Vec<(u32, u64, [u8; 32])> =
            p.iter().map(|(v, m)| (*v, m.slot, m.root)).collect();
        key.sort();
        let mut base: Vec<(u32, u64, [u8; 32])> =
            msgs.iter().map(|(v, m)| (*v, m.slot, m.root)).collect();
        base.sort();
        assert_eq!(key, base, "permutation changed the multiset — probe is invalid");
    }
}

/// GUARD CHECK, by deliberate violation: with NO later vote the fold IS
/// order-independent. If this test failed, the finding would be much broader
/// than reported (plain equivocation would be order-dependent too) and the
/// probe above would not isolate the masking rule.
#[test]
fn a_bare_equivocating_pair_is_order_independent() {
    let a = LatestMessage { slot: 5, root: r(1) };
    let b = LatestMessage { slot: 5, root: r(2) };
    let ab = fold(&[(0, a), (0, b), (1, LatestMessage { slot: 6, root: r(1) })]);
    let ba = fold(&[(0, b), (0, a), (1, LatestMessage { slot: 6, root: r(1) })]);
    assert_eq!(ab, ba, "the 2026-08-11 fix does hold for a bare pair");
    assert_eq!(ab.1, 1, "and it does bar the validator");
}

/// GUARD CHECK, by deliberate violation: a later vote from a DIFFERENT
/// validator must not mask anything. Confirms the masking is per-validator and
/// the probe's asymmetry comes from the `latest` entry, not from the store.
#[test]
fn a_later_vote_from_another_validator_masks_nothing() {
    let mut s = Store::new();
    s.observe(1, LatestMessage { slot: 9, root: r(3) });
    s.observe(0, LatestMessage { slot: 5, root: r(1) });
    s.observe(0, LatestMessage { slot: 5, root: r(2) });
    assert_eq!(s.equivocators().count(), 1);
}

// ─── The candidate fix, and the fork-safety argument as a test ──────────────

fn fold_with(order: &[(u32, LatestMessage)], fixed: bool) -> ([u8; 32], usize, usize) {
    let genesis = r(0);
    let mut parents = HashMap::new();
    let mut children = HashMap::new();
    let mut kids = Vec::new();
    for n in 1..=4u8 {
        parents.insert(r(n), genesis);
        kids.push(r(n));
    }
    children.insert(genesis, kids);
    let tree = BlockTree { parents: &parents };

    let mut s = if fixed { Store::new_set_determined() } else { Store::new() };
    s.set_stake(0, 100);
    s.set_stake(1, 1);
    s.set_stake(2, 7);
    for (v, m) in order {
        s.observe(*v, *m);
    }
    (s.head(&tree, genesis, &children), s.equivocators().count(), s.voters())
}

/// The fix, against the same witness: ONE head over all 24 orders.
#[test]
fn the_set_determined_fold_gives_one_head_where_the_legacy_fold_gives_two() {
    let msgs = vec![
        (0u32, LatestMessage { slot: 5, root: r(1) }),
        (0u32, LatestMessage { slot: 5, root: r(2) }),
        (0u32, LatestMessage { slot: 7, root: r(3) }),
        (1u32, LatestMessage { slot: 6, root: r(1) }),
    ];
    let mut legacy = Vec::new();
    let mut fixed = Vec::new();
    for p in permutations(&msgs) {
        let l = fold_with(&p, false);
        let f = fold_with(&p, true);
        if !legacy.contains(&l) { legacy.push(l); }
        if !fixed.contains(&f) { fixed.push(f); }
    }
    assert_eq!(legacy.len(), 2, "control: the legacy fold is order-dependent here");
    assert_eq!(
        fixed.len(),
        1,
        "the fix must collapse all 24 orders to one outcome; got {fixed:?}"
    );
    // And it settles on the honest answer: the equivocator is barred and loses
    // its weight, so the tie-breaker's block wins.
    assert_eq!(fixed[0].1, 1, "equivocator barred in every order");
    assert_eq!(fixed[0].0, r(1), "head is the honest validator's block");
}

/// Tiny xorshift — a seeded generator, so a failure is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// THE FORK-SAFETY ARGUMENT, as evidence rather than as prose.
///
/// Over randomised message sets that contain NO equivocation, the legacy fold
/// and the set-determined fold agree on the head, on the voter set and on the
/// equivocator set — in every arrival order. That is what makes the flag day
/// a no-op for every chain that has never carried a masked equivocating pair,
/// and it is the only reason an un-upgraded node and an upgraded one can sit
/// on the same chain before the constant binds.
#[test]
fn both_folds_agree_on_every_non_equivocating_set() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    for case in 0..4000u32 {
        // Build a set with at most one root per (validator, slot): the
        // definition of "no equivocation".
        let mut chosen: Vec<(u32, u64, [u8; 32])> = Vec::new();
        let n = 1 + rng.below(7) as usize;
        for _ in 0..n {
            let v = rng.below(3) as u32;
            let slot = 1 + rng.below(5);
            let root = r(1 + rng.below(4) as u8);
            if let Some(e) = chosen.iter().find(|(cv, cs, _)| *cv == v && *cs == slot) {
                // Reuse the root already fixed for this (validator, slot) —
                // a duplicate broadcast, not an offence.
                chosen.push((v, slot, e.2));
            } else {
                chosen.push((v, slot, root));
            }
        }
        let msgs: Vec<(u32, LatestMessage)> = chosen
            .iter()
            .map(|(v, slot, root)| (*v, LatestMessage { slot: *slot, root: *root }))
            .collect();

        // Shuffle a few arrival orders and demand both folds agree on all of
        // them, and with each other.
        let mut legacy_ref = None;
        for _ in 0..6 {
            let mut order = msgs.clone();
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i as u64 + 1) as usize);
            }
            let l = fold_with(&order, false);
            let f = fold_with(&order, true);
            assert_eq!(
                l, f,
                "case {case}: the two folds disagree on a set with no \
                 equivocation — the flag day would NOT be a no-op. set={chosen:?}"
            );
            match legacy_ref {
                None => legacy_ref = Some(l),
                Some(prev) => assert_eq!(
                    prev, l,
                    "case {case}: even the legacy fold is order-dependent on a \
                     non-equivocating set — the finding is broader than reported"
                ),
            }
        }
    }
}

/// And over sets that DO contain equivocation, the fixed fold is
/// order-independent while the legacy one is not. States the finding as a
/// population rather than as one hand-picked triple, and reports the rate.
#[test]
fn the_fix_is_order_independent_on_equivocating_sets_and_the_legacy_fold_is_not() {
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    let mut legacy_split = 0u32;
    let mut fixed_split = 0u32;
    let total = 3000u32;
    for _ in 0..total {
        // Force at least one equivocating pair.
        let v = rng.below(2) as u32;
        let s0 = 1 + rng.below(4);
        let mut msgs = vec![
            (v, LatestMessage { slot: s0, root: r(1) }),
            (v, LatestMessage { slot: s0, root: r(2) }),
        ];
        for _ in 0..(1 + rng.below(4)) {
            msgs.push((
                rng.below(3) as u32,
                LatestMessage { slot: 1 + rng.below(8), root: r(1 + rng.below(4) as u8) },
            ));
        }
        let mut l_seen: Vec<([u8; 32], usize, usize)> = Vec::new();
        let mut f_seen: Vec<([u8; 32], usize, usize)> = Vec::new();
        for _ in 0..8 {
            let mut order = msgs.clone();
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i as u64 + 1) as usize);
            }
            let l = fold_with(&order, false);
            let f = fold_with(&order, true);
            if !l_seen.contains(&l) { l_seen.push(l); }
            if !f_seen.contains(&f) { f_seen.push(f); }
        }
        if l_seen.len() > 1 { legacy_split += 1; }
        if f_seen.len() > 1 { fixed_split += 1; }
    }
    assert_eq!(
        fixed_split, 0,
        "the set-determined fold split on {fixed_split}/{total} equivocating sets"
    );
    assert!(
        legacy_split > 0,
        "the legacy fold never split — the probe is not generating the pattern"
    );
    eprintln!(
        "legacy fold produced order-dependent outcomes on {legacy_split}/{total} \
         randomised sets containing an equivocating pair \
         ({:.1}%)",
        100.0 * legacy_split as f64 / total as f64
    );
}

/// **The fix's honest limit.** It makes ONE fold set-determined. It does not
/// make the committed chain-wide accumulation complete.
///
/// `transition::accumulate_forkchoice` builds a fresh `Store` per block, seeded
/// from committed `latest_messages` — which holds ONE message per validator,
/// not a per-slot history. So `seen` starts empty at every block, and an
/// equivocating pair whose halves land in different blocks with a later vote
/// committed between them is still invisible, before and after the flag day.
///
/// Closing that would mean committing per-slot history to the state root: a
/// layout change, not a fold change. Recorded here so the gap is not
/// rediscovered as a regression.
#[test]
fn the_fix_does_not_close_masking_split_across_two_folds() {
    let a = LatestMessage { slot: 5, root: r(1) };
    let b = LatestMessage { slot: 5, root: r(2) };
    let later = LatestMessage { slot: 40, root: r(3) };

    // Fold 1 (block N): half A only. Committed latest = (5, A).
    let mut f1 = Store::new_set_determined();
    assert!(f1.observe(0, a));

    // Fold 2 (block N+1): re-seeded from committed state, then the later vote.
    let mut f2 = Store::new_set_determined();
    assert!(f2.observe(0, a));
    assert!(f2.observe(0, later));

    // Fold 3 (block N+2): re-seeded from committed (40, C); half B arrives.
    let mut f3 = Store::new_set_determined();
    assert!(f3.observe(0, later));
    assert!(!f3.observe(0, b));
    assert_eq!(
        f3.equivocators().count(),
        0,
        "if this ever becomes 1 the fix grew a memory it was not given"
    );
}
