// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the warm-up walk behind `Registry::resolve` (security review
//! ST-1).
//!
//! The walk was rewritten to skip the epochs and entries in which nothing
//! can move, and its last result is memoised. Both are meant to be
//! invisible: `Registry::resolve` must return, for every input, exactly what
//! it returned before. So the previous implementation is kept here verbatim
//! as [`resolve_reference`], and the tests compare the two on randomized
//! histories, in the house style of `tests/properties.rs`: a fixed-seed
//! splitmix64 generator, std only, reproducible without capturing a seed.
//!
//! The pruning check of
//! `params::FUNDED_DELEGATION_BOUND_ACTIVATION_EPOCH` is tested at the end.

use super::*;

/// `Registry::resolve` exactly as it stood at commit 776efe8d, before ST-1:
/// two passes over the whole queue for every epoch since genesis. Verbatim,
/// comments included, except for the name and the `Arc::new` around the two
/// result vectors (the field type changed; the values did not).
fn resolve_reference(delegations: &[Delegation], epoch: u64) -> Registry {
    let mut queue: Vec<&Delegation> =
        delegations.iter().filter(|d| d.eligible && d.amount_sat >= MIN_DELEGATION_SAT).collect();
    // R1 M5 (perf, ungated, behaviour-identical): with nothing eligible
    // to admit, every one of the `epoch + 1` iterations below finds no
    // `d` to activate or deactivate — the loop is `for e in 0..=epoch`
    // over a `queue` it never indexes into productively, so its ONLY
    // effect on an empty queue is burning CPU. Skipping it changes
    // nothing about the RESULT (every field below is what the loop
    // would have produced from an empty `queue` and `activated`), only
    // the cost: at today's epoch (~2,000+) this call site is walked from
    // `duty_roster_at` on every block, and `self.delegations` is
    // provably empty on the live chain today (`DEPOSIT_ACTIVATION_EPOCH`
    // is `u64::MAX`, so `Delegate` — the only writer — has never
    // applied; see that constant's docs).
    if queue.is_empty() {
        return Registry {
            epoch,
            stakes: Vec::new(),
            total_active: 0,
            admitted: Arc::new(Vec::new()),
            activated: Arc::new(Vec::new()),
        };
    }
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
            // Any positive floor guarantees termination. The floor is a
            // wall-clock quantity, not one delegation's worth: at 25 bps
            // the proportional budget only exceeds 500,000 BLCH once the
            // active set passes 200M BLCH, so on a young network a 10-BLCH
            // floor would be the binding constraint and would strangle
            // onboarding — 10 BLCH per 16 minutes is not a network, it is
            // a queue. (Ethereum's floor is the same idea at a different
            // unit: 4 validators per epoch.)
            //
            // It was `MIN_DELEGATION_SAT` while the rate was 900 bps, where
            // the floor almost never bound. Lowering the rate 36x is what
            // makes the floor load-bearing, so the two move together — and
            // the 2026-08-12 split moved the floor x5 so its wall-clock
            // value stayed put (see MIN_CHURN_SAT).
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
        admitted: Arc::new(admitted_keys),
        activated: Arc::new(activated_map),
    }
}

// ── Deterministic PRNG (splitmix64): std only, fixed seed, reproducible ─────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, n)` by widening multiply; test-grade.
    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        ((self.next_u64() as u128 * n as u128) >> 64) as u64
    }
}

const BLCH: u128 = SAT_PER_BLOCH;

/// How many shapes [`random_history`] knows.
const SHAPES: u64 = 5;

/// A random delegation history of one of five shapes, each aimed at a
/// different part of the walk.
fn random_history(rng: &mut Rng, shape: u64, n: usize) -> Vec<Delegation> {
    (0..n as u32)
        .map(|k| {
            let unique = 1_000 + k;
            let (requested_epoch, amount_sat, validator, delegator) = match shape {
                // Everything in the first few epochs, amounts on both sides
                // of the minimum and of the churn floor, colliding accounts.
                0 => (
                    rng.below(6),
                    rng.below(2 * MIN_CHURN_SAT as u64) as u128,
                    rng.below(4) as u32,
                    rng.below(6) as u32,
                ),
                // A sparse history: bursts separated by long idle gaps.
                1 => (
                    rng.below(8) * 97 + rng.below(3),
                    (10 + rng.below(3_000_000)) as u128 * BLCH,
                    rng.below(9) as u32,
                    unique,
                ),
                // Whales: active stake passes 200M BLCH, so the proportional
                // rate replaces the floor and backlogs last hundreds of
                // epochs.
                2 => (
                    rng.below(40),
                    (1 + rng.below(400)) as u128 * 1_000_000 * BLCH,
                    rng.below(5) as u32,
                    unique,
                ),
                // A swarm of minimum-size positions, the cheap-position
                // pattern of the finding.
                3 => (
                    rng.below(12) * 30,
                    MIN_DELEGATION_SAT + rng.below(3) as u128,
                    rng.below(3) as u32,
                    unique,
                ),
                // Records that tie on the whole queue key and differ only in
                // their deactivation epoch.
                _ => (
                    rng.below(3),
                    [MIN_DELEGATION_SAT, MIN_CHURN_SAT, 3 * MIN_CHURN_SAT][rng.below(3) as usize],
                    rng.below(2) as u32,
                    rng.below(2) as u32,
                ),
            };
            // Withdrawals: a position that was deactivated stays in the list
            // for ever. Before, at and after its own request epoch; one
            // epoch later; a few epochs later; hundreds of epochs later.
            let deactivate_epoch = match rng.below(8) {
                0 | 1 | 2 => None,
                3 => Some(requested_epoch.saturating_sub(rng.below(3))),
                4 => Some(requested_epoch + 1),
                5 => Some(requested_epoch + rng.below(8)),
                6 => Some(requested_epoch + rng.below(60)),
                _ => Some(requested_epoch + rng.below(400)),
            };
            Delegation {
                delegator,
                validator,
                amount_sat: if rng.below(12) == 0 { MIN_DELEGATION_SAT - 1 } else { amount_sat },
                requested_epoch,
                deactivate_epoch,
                eligible: rng.below(8) != 0,
            }
        })
        .collect()
}

/// The last epoch at which a record of `ds` is requested or deactivated.
fn last_event(ds: &[Delegation]) -> u64 {
    ds.iter()
        .flat_map(|d| [Some(d.requested_epoch), d.deactivate_epoch])
        .flatten()
        .max()
        .unwrap_or(0)
}

/// Everything a caller can observe of a registry, record by record: what
/// the roster, the reward split, slashing, commission updates and
/// withdrawals read.
fn assert_same_view(new: &Registry, old: &Registry, ds: &[Delegation], context: &str) {
    assert_eq!(new, old, "{context}: registries differ");
    assert_eq!(new.epoch(), old.epoch(), "{context}");
    assert_eq!(new.total_active(), old.total_active(), "{context}");
    assert_eq!(new.cap_sat(), old.cap_sat(), "{context}");
    assert_eq!(new.validators(), old.validators(), "{context}");
    let cap = 500_000_000 * BLCH;
    assert_eq!(
        new.validators_with_absolute_cap(cap),
        old.validators_with_absolute_cap(cap),
        "{context}"
    );
    assert_eq!(new.top_share_bps(), old.top_share_bps(), "{context}");
    assert_eq!(new.nakamoto_coefficient(), old.nakamoto_coefficient(), "{context}");
    // The slashing exposure view, built the way
    // `CommittedState::apply_slashing_evidence` builds it.
    let exposure = |r: &Registry| -> Vec<Delegation> {
        ds.iter()
            .map(|d| {
                let mut view = *d;
                if r.state_of(d) == StakeState::Inactive {
                    view.eligible = false;
                }
                view.amount_sat = r.activated_sat(d);
                view
            })
            .collect()
    };
    let (new_exposure, old_exposure) = (exposure(new), exposure(old));
    assert_eq!(new_exposure, old_exposure, "{context}: slashing exposure differs");
    for d in ds {
        assert_eq!(new.state_of(d), old.state_of(d), "{context}");
        assert_eq!(new.activated_sat(d), old.activated_sat(d), "{context}");
        assert_eq!(new.stake_of(d.validator), old.stake_of(d.validator), "{context}");
        assert_eq!(
            apply_slash(&new_exposure, d.validator, 3_300),
            apply_slash(&old_exposure, d.validator, 3_300),
            "{context}: slashing losses differ"
        );
    }
}

// ═══ 1. THE WALK RETURNS WHAT THE OLD ONE RETURNED ══════════════════════════

/// Random histories of every shape, resolved at a random epoch before,
/// inside and long after the last event. Both the bare walk and the memoised
/// entry point must return the reference value.
#[test]
fn fold_matches_the_reference_on_random_histories() {
    let mut rng = Rng::new(0xB10C_5701);
    let mut moved = 0u32;
    let mut backlog = 0u32;
    for trial in 0..1_600u32 {
        let shape = rng.below(SHAPES);
        let n = match rng.below(4) {
            0 => rng.below(3) as usize,
            1 => rng.below(12) as usize,
            _ => 1 + rng.below(40) as usize,
        };
        let ds = random_history(&mut rng, shape, n);
        let tail = [0, 3, 40, 700][rng.below(4) as usize];
        let epoch = rng.below(last_event(&ds) + 2 + tail);

        let old = resolve_reference(&ds, epoch);
        let context = format!("trial {trial}, shape {shape}, {n} records, epoch {epoch}");
        assert_same_view(&Registry::resolve_uncached(&ds, epoch), &old, &ds, &context);
        assert_same_view(&Registry::resolve(&ds, epoch), &old, &ds, &context);

        moved += u32::from(old.total_active() > 0);
        // A record still warming up or draining at the queried epoch: the
        // rate limit was binding when the walk stopped.
        backlog += u32::from(ds.iter().any(|d| {
            let held = old.activated_sat(d);
            d.eligible && d.amount_sat >= MIN_DELEGATION_SAT && held > 0 && held < d.amount_sat
        }));
    }
    // The generator must actually reach the interesting states.
    assert!(moved > 800, "only {moved} trials had active stake");
    assert!(backlog > 150, "only {backlog} trials stopped inside a rate-limited backlog");
}

/// One history, every epoch: an off-by-one at a request epoch, at a
/// deactivation epoch, at the first idle epoch or at the last busy one
/// cannot hide behind a randomly chosen query epoch.
#[test]
fn fold_matches_the_reference_at_every_epoch_of_a_history() {
    let mut rng = Rng::new(0xB10C_5702);
    for trial in 0..20u32 {
        let shape = trial as u64 % SHAPES;
        let n = 4 + rng.below(24) as usize;
        let ds = random_history(&mut rng, shape, n);
        let horizon = (last_event(&ds) + 60).min(480);
        for epoch in 0..=horizon {
            assert_eq!(
                Registry::resolve_uncached(&ds, epoch),
                resolve_reference(&ds, epoch),
                "trial {trial}, shape {shape}, epoch {epoch}"
            );
        }
    }
}

/// The finding's own scenario at today's scale: positions created during
/// the funded-delegation era and resolved thousands of idle epochs later.
#[test]
fn fold_matches_the_reference_across_a_long_idle_history() {
    let mut rng = Rng::new(0xB10C_5703);
    for trial in 0..6u32 {
        let ds: Vec<Delegation> = (0..40u32)
            .map(|k| {
                let requested_epoch = 4_670 + rng.below(2_700);
                Delegation {
                    delegator: k,
                    validator: rng.below(7) as u32,
                    amount_sat: if k % 9 == 0 {
                        (1 + rng.below(30)) as u128 * 1_000_000 * BLCH
                    } else {
                        MIN_DELEGATION_SAT + rng.below(500) as u128 * BLCH
                    },
                    requested_epoch,
                    deactivate_epoch: (rng.below(3) == 0)
                        .then(|| requested_epoch + 1 + rng.below(300)),
                    eligible: true,
                }
            })
            .collect();
        for epoch in [4_669, 4_670, 5_000, 7_399, 7_400] {
            let context = format!("trial {trial}, epoch {epoch}");
            assert_same_view(
                &Registry::resolve_uncached(&ds, epoch),
                &resolve_reference(&ds, epoch),
                &ds,
                &context,
            );
        }
    }
}

/// The result does not depend on the order the caller holds the list in —
/// the property `tests/properties.rs` pins for the public entry point,
/// repeated here against the reference so a memo hit cannot stand in for it.
#[test]
fn fold_matches_the_reference_whatever_the_input_order() {
    let mut rng = Rng::new(0xB10C_5704);
    for trial in 0..200u32 {
        // Unique queue keys: with ties the reference itself follows caller
        // order (see `Delegation::queue_key`).
        let shape = 1 + rng.below(3);
        let n = 1 + rng.below(30) as usize;
        let mut ds = random_history(&mut rng, shape, n);
        let epoch = rng.below(last_event(&ds) + 50);
        let canonical = resolve_reference(&ds, epoch);
        for i in (1..ds.len()).rev() {
            ds.swap(i, rng.below(i as u64 + 1) as usize);
        }
        assert_eq!(Registry::resolve_uncached(&ds, epoch), canonical, "trial {trial}");
        assert_eq!(Registry::resolve(&ds, epoch), canonical, "trial {trial}");
    }
}

// ═══ 2. THE MEMO NEVER ANSWERS FOR ANOTHER INPUT ════════════════════════════

/// A hit is the value a fresh computation returns, and it is a hit: the
/// walk runs once for any number of calls with one input.
#[test]
fn memo_hit_is_identical_to_a_fresh_computation() {
    let mut rng = Rng::new(0xB10C_5705);
    let ds = random_history(&mut rng, 1, 30);
    let epoch = last_event(&ds) + 5;
    let fresh = Registry::resolve_uncached(&ds, epoch);

    let before = resolve_recomputations();
    let first = Registry::resolve(&ds, epoch);
    assert_eq!(resolve_recomputations(), before + 1, "the first call computes");
    for _ in 0..8 {
        assert_eq!(Registry::resolve(&ds, epoch), fresh);
    }
    assert_eq!(resolve_recomputations(), before + 1, "identical calls must not recompute");
    assert_eq!(first, fresh);
}

/// Every way an input can differ is a miss that recomputes: another epoch,
/// one field of one record, one record more or fewer, another order. Each
/// answer is checked against the reference, so a memo that keyed on less
/// than its whole input would return a stale registry here.
#[test]
fn memo_misses_on_any_change_of_input() {
    let mut rng = Rng::new(0xB10C_5706);
    for trial in 0..60u32 {
        let shape = rng.below(SHAPES);
        let n = 2 + rng.below(20) as usize;
        let base = random_history(&mut rng, shape, n);
        let epoch = rng.below(last_event(&base) + 30);
        assert_eq!(Registry::resolve(&base, epoch), resolve_reference(&base, epoch));

        let mut variants: Vec<(Vec<Delegation>, u64)> = vec![
            (base.clone(), epoch + 1),
            (base.clone(), epoch.saturating_sub(1)),
            (base[1..].to_vec(), epoch),
            (base.iter().rev().copied().collect(), epoch),
        ];
        let pick = rng.below(base.len() as u64) as usize;
        let edits: [fn(&mut Delegation); 7] = [
            |d| d.amount_sat += 1,
            |d| d.validator += 1,
            |d| d.delegator += 1,
            |d| d.requested_epoch += 1,
            |d| d.eligible = !d.eligible,
            |d| d.deactivate_epoch = Some(d.deactivate_epoch.map_or(0, |e| e + 1)),
            |d| d.deactivate_epoch = None,
        ];
        for edit in edits {
            let mut changed = base.clone();
            edit(&mut changed[pick]);
            variants.push((changed, epoch));
        }
        let mut grown = base.clone();
        grown.push(Delegation {
            delegator: 9_999,
            validator: 0,
            amount_sat: MIN_CHURN_SAT,
            requested_epoch: epoch,
            deactivate_epoch: None,
            eligible: true,
        });
        variants.push((grown, epoch));

        for (index, (ds, at)) in variants.iter().enumerate() {
            // Re-prime with the base input so each variant meets a memo
            // holding a neighbouring, different input.
            let _ = Registry::resolve(&base, epoch);
            assert_eq!(
                Registry::resolve(ds, *at),
                resolve_reference(ds, *at),
                "trial {trial}, variant {index}"
            );
        }
    }
}

/// The memo is per thread and holds nothing another thread can observe.
#[test]
fn memo_is_local_to_the_calling_thread() {
    let mut rng = Rng::new(0xB10C_5707);
    let ds = random_history(&mut rng, 2, 12);
    let epoch = 90;
    let here = Registry::resolve(&ds, epoch);
    let before = resolve_recomputations();
    let there = std::thread::spawn({
        let ds = ds.clone();
        move || {
            let started = resolve_recomputations();
            let registry = Registry::resolve(&ds, epoch);
            (registry, resolve_recomputations() - started)
        }
    })
    .join()
    .unwrap();
    assert_eq!(there.0, here);
    assert_eq!(there.1, 1, "a new thread starts with an empty memo");
    assert_eq!(resolve_recomputations(), before, "and leaves this thread's alone");
}

// ═══ 3. MEASUREMENT ═════════════════════════════════════════════════════════

/// Before/after cost of one resolve at epoch 7,400 (not asserted on time).
///
/// ```sh
/// cargo test --release -p bloch-pos-committee --lib \
///     delegation::tests::measure_resolver -- --ignored --nocapture
/// ```
#[test]
#[ignore = "measurement, minutes in a debug build: run in release with --nocapture"]
fn measure_resolver_before_and_after_at_epoch_7400() {
    use std::time::Instant;
    const EPOCH: u64 = 7_400;
    let best_of = |runs: u32, f: &dyn Fn() -> Registry| {
        (0..runs)
            .map(|_| {
                let t = Instant::now();
                std::hint::black_box(f());
                t.elapsed()
            })
            .min()
            .unwrap()
    };
    println!("resolve at epoch {EPOCH}; positions | before | after (walk) | after (memo hit)");
    for (label, whales) in [("minimum-size positions", 0u32), ("same, behind a 300M BLCH backlog", 30)] {
        println!("-- {label}");
        for n in [1_000u32, 10_000, 100_000] {
            let mut rng = Rng::new(0xB10C_57FF ^ u64::from(n));
            // Created across the funded-delegation era (live since epoch
            // 4,669), over 139 validators; half were deactivated again, the
            // create-and-recover pattern of the finding.
            let mut ds: Vec<Delegation> = (0..n)
                .map(|k| {
                    let requested_epoch = 4_670 + rng.below(EPOCH - 4_670);
                    Delegation {
                        delegator: k,
                        validator: rng.below(139) as u32,
                        amount_sat: MIN_DELEGATION_SAT,
                        requested_epoch,
                        deactivate_epoch: (k % 2 == 0).then(|| requested_epoch + 1 + rng.below(100)),
                        eligible: true,
                    }
                })
                .collect();
            // Thirty 10M BLCH positions requested 300 epochs ago: still
            // warming up at the queried epoch.
            ds.extend((0..whales).map(|k| Delegation {
                delegator: n + k,
                validator: k,
                amount_sat: 10_000_000 * BLCH,
                requested_epoch: EPOCH - 300,
                deactivate_epoch: None,
                eligible: true,
            }));
            let before = best_of(if n >= 100_000 { 1 } else { 3 }, &|| resolve_reference(&ds, EPOCH));
            let after = best_of(5, &|| Registry::resolve_uncached(&ds, EPOCH));
            let _ = Registry::resolve(&ds, EPOCH);
            let hit = best_of(5, &|| Registry::resolve(&ds, EPOCH));
            assert_eq!(Registry::resolve(&ds, EPOCH), resolve_reference(&ds, EPOCH));
            println!("{n:>9} | {before:>12.3?} | {after:>12.3?} | {hit:>12.3?}");
        }
    }
}

// ═══ 4. PRUNING (FUNDED_DELEGATION_BOUND_ACTIVATION_EPOCH) ══════════════════

fn position(delegator: u32, amount_blch: u128, requested_epoch: u64) -> Delegation {
    Delegation {
        delegator,
        validator: delegator % 3,
        amount_sat: amount_blch * BLCH,
        requested_epoch,
        deactivate_epoch: None,
        eligible: true,
    }
}

/// `ds` with the given positions overwritten by the tombstone.
fn pruned(ds: &[Delegation], positions: &[usize]) -> Vec<Delegation> {
    let mut out = ds.to_vec();
    for p in positions {
        out[*p] = Delegation::PRUNED;
    }
    out
}

#[test]
fn the_tombstone_is_outside_the_fold_and_unlike_any_admissible_record() {
    assert!(Delegation::PRUNED.is_pruned());
    assert!(!Delegation::PRUNED.eligible);
    assert!(Delegation::PRUNED.amount_sat < MIN_DELEGATION_SAT);
    assert!(!position(0, 10, 0).is_pruned());
    let ds = [position(1, 1_000, 2), Delegation::PRUNED, position(2, 2_000, 3)];
    let live = [ds[0], ds[2]];
    for epoch in [0, 2, 3, 50] {
        assert_eq!(Registry::resolve_uncached(&ds, epoch), Registry::resolve_uncached(&live, epoch));
        assert_eq!(Registry::resolve_uncached(&ds, epoch).state_of(&ds[1]), StakeState::Inactive);
        assert_eq!(Registry::resolve_uncached(&ds, epoch).activated_sat(&ds[1]), 0);
    }
}

#[test]
fn pruning_a_position_that_drained_before_an_idle_epoch_is_neutral() {
    let mut gone = position(1, 2_000_000, 1);
    gone.deactivate_epoch = Some(20);
    let ds = [gone, position(2, 3_000_000, 2), position(3, 10, 5)];
    // 2M BLCH drain at the 500,000 BLCH floor: four epochs from epoch 20.
    assert!(Registry::resolve_uncached(&ds, 22).activated_sat(&gone) > 0);
    assert!(!pruning_is_outcome_neutral(&ds, &[0], 22), "still draining");
    assert_eq!(Registry::resolve_uncached(&ds, 24).activated_sat(&gone), 0);
    assert!(pruning_is_outcome_neutral(&ds, &[0], 24));
    assert_eq!(
        Registry::resolve_uncached(&pruned(&ds, &[0]), 24),
        Registry::resolve_uncached(&ds, 24)
    );
}

/// The case that makes the check necessary. The removed record once stood
/// ahead of a large one in the queue; without it the large one would have
/// warmed up sooner, so while the large one is still warming up a replay
/// without the record gives it more stake than the chain agreed on.
#[test]
fn pruning_is_refused_while_the_record_still_shapes_a_backlog() {
    let mut gone = position(1, 5_000_000, 1);
    gone.deactivate_epoch = Some(2);
    let behind = position(2, 40_000_000, 1);
    let ds = [gone, behind];
    let at = 40;
    let with = Registry::resolve_uncached(&ds, at);
    let without = Registry::resolve_uncached(&pruned(&ds, &[0]), at);
    assert_eq!(with.activated_sat(&gone), 0, "the record itself has drained");
    assert!(with.activated_sat(&behind) < behind.amount_sat, "the backlog is still open");
    assert_ne!(with.activated_sat(&behind), without.activated_sat(&behind));
    assert!(!pruning_is_outcome_neutral(&ds, &[0], at));

    // Once the backlog has closed in both replays, nothing remembers it.
    let later = 200;
    assert_eq!(Registry::resolve_uncached(&ds, later).activated_sat(&behind), behind.amount_sat);
    assert!(pruning_is_outcome_neutral(&ds, &[0], later));
}

/// Totals are not enough. Here the removed record leaves the total and both
/// validators' stakes exactly as they were at the queried epoch, and still
/// moves stake between two records that stay: one of them is draining, so
/// the split decides what the following epochs release.
#[test]
fn pruning_is_refused_when_only_the_split_between_other_records_moves() {
    let record = |delegator, validator, amount_blch: u128, requested_epoch, deactivate_epoch| Delegation {
        delegator,
        validator,
        amount_sat: amount_blch * BLCH,
        requested_epoch,
        deactivate_epoch,
        eligible: true,
    };
    let ds = [
        record(0, 0, 200_000, 1, Some(3)),
        record(1, 0, 500_000, 3, None),
        record(2, 1, 1_100_000, 2, Some(5)),
        record(3, 0, 900_000, 0, Some(3)),
        record(4, 1, 1_000_000, 1, Some(4)),
    ];
    let at = 5;
    let with = Registry::resolve_uncached(&ds, at);
    let without = Registry::resolve_uncached(&pruned(&ds, &[0]), at);
    assert_eq!(with.activated_sat(&ds[0]), 0);
    assert_eq!(with.total_active(), without.total_active());
    assert_eq!(with.validators(), without.validators());
    assert_ne!(with.activated_sat(&ds[2]), without.activated_sat(&ds[2]));
    assert_ne!(with.activated_sat(&ds[4]), without.activated_sat(&ds[4]));
    assert!(!pruning_is_outcome_neutral(&ds, &[0], at));
}

#[test]
fn pruning_is_refused_for_a_record_that_is_not_drained_or_not_in_the_list() {
    let mut cooling = position(1, 1_000, 1);
    cooling.deactivate_epoch = Some(9);
    let mut leaving_later = position(4, 1_000, 60);
    leaving_later.deactivate_epoch = Some(70);
    let ds = [cooling, position(2, 1_000, 1), position(3, 1_000, 60), leaving_later];
    assert!(!pruning_is_outcome_neutral(&ds, &[1], 50), "never deactivated");
    assert!(!pruning_is_outcome_neutral(&ds, &[0], 8), "deactivation still ahead");
    // Nothing activated yet is not the same as drained: these two have not
    // reached their request epoch and would take budget later, whether or
    // not a deactivation is already recorded for a later epoch.
    assert_eq!(Registry::resolve_uncached(&ds, 50).activated_sat(&ds[2]), 0);
    assert!(!pruning_is_outcome_neutral(&ds, &[2], 50), "not requested yet");
    assert!(!pruning_is_outcome_neutral(&ds, &[3], 50), "requested and deactivated later");
    assert!(!pruning_is_outcome_neutral(&ds, &[4], 50), "no such position");
    assert!(pruning_is_outcome_neutral(&ds, &[0], 50));
    assert!(pruning_is_outcome_neutral(&ds, &[], 50));
}

/// The property the transition relies on: whenever the check passes, the
/// pruned list and the full list resolve to the same registry at that epoch
/// and at every later one, whatever the chain appends or deactivates
/// afterwards.
#[test]
fn a_neutral_pruning_stays_invisible_under_any_later_history() {
    let mut rng = Rng::new(0xB10C_5708);
    let (mut neutral, mut refused) = (0u32, 0u32);
    for trial in 0..500u32 {
        let shape = 1 + rng.below(3);
        let n = 2 + rng.below(30) as usize;
        let ds = random_history(&mut rng, shape, n);
        let at = rng.below(last_event(&ds) + 200);
        let now = resolve_reference(&ds, at);
        // Candidates as the transition picks them: deactivated, fully
        // drained, in the fold. A random subset of those.
        let positions: Vec<usize> = (0..ds.len())
            .filter(|i| {
                let d = &ds[*i];
                d.eligible
                    && d.amount_sat >= MIN_DELEGATION_SAT
                    && d.deactivate_epoch.is_some_and(|de| de <= at)
                    && now.activated_sat(d) == 0
                    && rng.below(3) != 0
            })
            .collect();
        if positions.is_empty() {
            continue;
        }
        if !pruning_is_outcome_neutral(&ds, &positions, at) {
            refused += 1;
            continue;
        }
        neutral += 1;

        // What the chain may do afterwards: append delegations requested
        // after `at`, and deactivate live ones after `at`.
        let mut full = ds.clone();
        for d in full.iter_mut() {
            if d.deactivate_epoch.is_none() && rng.below(3) == 0 {
                d.deactivate_epoch = Some(at + 1 + rng.below(40));
            }
        }
        for k in 0..rng.below(6) as u32 {
            let mut d = random_history(&mut rng, shape, 1)[0];
            d.delegator = 50_000 + k;
            d.requested_epoch = at + 1 + rng.below(30);
            d.deactivate_epoch = (rng.below(2) == 0).then(|| d.requested_epoch + rng.below(50));
            full.push(d);
        }
        let cut = pruned(&full, &positions);
        for epoch in (at..at + 120).chain([at + 400, at + 3_000]) {
            assert_eq!(
                Registry::resolve_uncached(&cut, epoch),
                Registry::resolve_uncached(&full, epoch),
                "trial {trial}, pruned at {at}, epoch {epoch}"
            );
        }
        assert_eq!(Registry::resolve_uncached(&cut, at + 7), resolve_reference(&full, at + 7));
    }
    assert!(neutral > 100, "only {neutral} neutral prunings exercised");
    assert!(refused > 5, "only {refused} refusals exercised");
}
