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

// ═══ 5. GROWTH CAP (FUNDED_DELEGATION_GROWTH_CAP_ACTIVATION_EPOCH) ══════════

/// The capped rule stated the slow way: every entry visited twice in every
/// epoch since genesis, the activation pass against the capped budget from
/// `rule.gate` on, the release pass against the budget it always had.
/// Written independently of `fold_queue` and of
/// `WarmupRule::activation_budget`.
fn capped_reference(delegations: &[Delegation], epoch: u64, rule: &WarmupRule) -> Vec<u128> {
    let mut order: Vec<usize> = (0..delegations.len())
        .filter(|i| delegations[*i].eligible && delegations[*i].amount_sat >= MIN_DELEGATION_SAT)
        .collect();
    order.sort_by_key(|i| delegations[*i].queue_key());
    let mut activated = vec![0u128; delegations.len()];
    let mut total_active = 0u128;
    for e in 0..=epoch {
        let release = if e == 0 {
            u128::MAX
        } else {
            (total_active * WARMUP_RATE_BPS / 10_000).max(MIN_CHURN_SAT)
        };
        let warm = match rule.gate {
            Some(gate) if e >= gate && e != 0 => {
                (total_active / rule.div).max(rule.floor_sat).min(release)
            }
            _ => release,
        };
        let mut used = 0u128;
        for &i in &order {
            let d = &delegations[i];
            if d.requested_epoch > e || d.deactivate_epoch.is_some_and(|de| de <= e) {
                continue;
            }
            let take = (d.amount_sat - activated[i]).min(warm - used);
            used += take;
            activated[i] += take;
            total_active += take;
        }
        let mut released = 0u128;
        for &i in &order {
            let d = &delegations[i];
            if !d.deactivate_epoch.is_some_and(|de| de <= e) {
                continue;
            }
            let give = activated[i].min(release - released);
            released += give;
            activated[i] -= give;
            total_active -= give;
        }
    }
    activated
}

fn middle_rule(gate: u64) -> WarmupRule {
    WarmupRule { gate: Some(gate), div: GROWTH_CAP_WARMUP_DIV, floor_sat: GROWTH_CAP_WARMUP_FLOOR_SAT }
}

/// The inert rule is the old rule, and a gate that has not been reached is
/// the inert rule: on random histories the walk returns the pre-ST-1
/// reference value in both cases.
#[test]
fn an_inert_or_future_growth_cap_changes_nothing() {
    assert_eq!(WarmupRule::consensus(), WarmupRule::LEGACY);
    let mut rng = Rng::new(0x6A0B_CA90);
    for trial in 0..600u32 {
        let shape = rng.below(SHAPES);
        let n = 1 + rng.below(30) as usize;
        let ds = random_history(&mut rng, shape, n);
        let epoch = rng.below(last_event(&ds) + 60);
        let old = resolve_reference(&ds, epoch);
        let context = format!("trial {trial}, shape {shape}, epoch {epoch}");
        assert_same_view(&Registry::resolve_with_rule(&ds, epoch, &WarmupRule::LEGACY), &old, &ds, &context);
        // A gate strictly above the resolved epoch, down to the very next one.
        for gate in [epoch + 1, epoch + 1 + rng.below(500), u64::MAX] {
            assert_same_view(&Registry::resolve_with_rule(&ds, epoch, &middle_rule(gate)), &old, &ds, &context);
        }
        // Constants that are not below today's are no cap at all.
        let loose = WarmupRule { gate: Some(rng.below(epoch + 1)), div: 400, floor_sat: MIN_CHURN_SAT };
        assert_same_view(&Registry::resolve_with_rule(&ds, epoch, &loose), &old, &ds, &context);
        let looser = WarmupRule { gate: Some(0), div: 1, floor_sat: u128::MAX };
        assert_same_view(&Registry::resolve_with_rule(&ds, epoch, &looser), &old, &ds, &context);
    }
}

/// The skipping walk against the two-passes-per-epoch statement of the
/// capped rule, with gates before, inside and after the history and with
/// several parameter choices.
#[test]
fn capped_fold_matches_a_naive_capped_walk() {
    let mut rng = Rng::new(0x6A0B_CA91);
    let mut capped_runs = 0u32;
    let mut compared_records = 0u32;
    for trial in 0..1_200u32 {
        let shape = rng.below(SHAPES);
        let n = 1 + rng.below(30) as usize;
        let ds = random_history(&mut rng, shape, n);
        let horizon = [3, 60, 900][rng.below(3) as usize];
        let epoch = rng.below(last_event(&ds) + horizon);
        let rule = WarmupRule {
            gate: Some(rng.below(epoch + 3)),
            div: [400, 768, 1_536, 7][rng.below(4) as usize],
            floor_sat: [MIN_CHURN_SAT, MIN_CHURN_SAT / 2, MIN_CHURN_SAT / 4, 1][rng.below(4) as usize],
        };
        let registry = Registry::resolve_with_rule(&ds, epoch, &rule);
        let want = capped_reference(&ds, epoch, &rule);
        let in_fold = |d: &Delegation| d.eligible && d.amount_sat >= MIN_DELEGATION_SAT;
        let mut total = 0u128;
        let mut compared = 0u32;
        for (d, expected) in ds.iter().zip(want.iter()) {
            total += *expected;
            // Records that tie on the whole queue key are interchangeable
            // (which of them takes a slice first is not observable), so the
            // per-record amount is compared only where the key is unique;
            // the sum below covers the rest.
            let twins = ds.iter().filter(|o| in_fold(o) && o.queue_key() == d.queue_key()).count();
            if in_fold(d) && twins == 1 {
                assert_eq!(registry.activated_sat(d), *expected, "trial {trial}, epoch {epoch}, {rule:?}");
                compared += 1;
            }
        }
        compared_records += compared;
        assert_eq!(registry.total_active(), total, "trial {trial}, epoch {epoch}, {rule:?}");
        capped_runs += u32::from(registry != Registry::resolve_with_rule(&ds, epoch, &WarmupRule::LEGACY));
    }
    assert!(capped_runs > 100, "only {capped_runs} histories were changed by the cap");
    assert!(compared_records > 5_000, "only {compared_records} records compared one by one");
}

/// The gate epoch itself is the first capped epoch; the epoch before it is
/// the last with today's budget.
#[test]
fn the_cap_binds_exactly_at_its_gate_epoch() {
    const GATE: u64 = 10;
    let whale = position(1, 100_000_000, 5);
    let at = |epoch| Registry::resolve_with_rule(&[whale], epoch, &middle_rule(GATE)).total_active();
    // Epochs 5..=9: 500,000 BLCH each.
    assert_eq!(at(GATE - 1), 5 * MIN_CHURN_SAT);
    assert_eq!(at(GATE - 1), Registry::resolve_with_rule(&[whale], GATE - 1, &WarmupRule::LEGACY).total_active());
    // Epoch 10 on: the floor, 250,000 BLCH each.
    assert_eq!(at(GATE), 5 * MIN_CHURN_SAT + GROWTH_CAP_WARMUP_FLOOR_SAT);
    assert_eq!(at(GATE + 7), 5 * MIN_CHURN_SAT + 8 * GROWTH_CAP_WARMUP_FLOOR_SAT);
}

/// The proportional term replaces the floor exactly when
/// `active / DIV` exceeds it, and the capped budget never exceeds today's.
#[test]
fn the_capped_budget_at_its_limits() {
    let rule = middle_rule(1);
    let crossover = GROWTH_CAP_WARMUP_DIV * GROWTH_CAP_WARMUP_FLOOR_SAT;
    assert_eq!(crossover, 192_000_000 * BLCH);
    let legacy = |active| epoch_budget(1, active);
    // At and below the crossover the floor binds; one divisor above it the
    // proportional term is one satoshi larger.
    for active in [0, 1, crossover - 1, crossover, crossover + GROWTH_CAP_WARMUP_DIV - 1] {
        assert_eq!(rule.activation_budget(1, active, legacy(active)), GROWTH_CAP_WARMUP_FLOOR_SAT);
    }
    assert_eq!(
        rule.activation_budget(1, crossover + GROWTH_CAP_WARMUP_DIV, legacy(crossover + GROWTH_CAP_WARMUP_DIV)),
        GROWTH_CAP_WARMUP_FLOOR_SAT + 1
    );
    // Never above today's budget, for any amount of active stake up to the
    // whole supply and for any constants.
    let supply = crate::tokenomics_v4::TOTAL_SUPPLY_SAT;
    for active in [0, BLCH, crossover, 10 * crossover, supply] {
        for (div, floor_sat) in [(768, GROWTH_CAP_WARMUP_FLOOR_SAT), (1, 0), (1, u128::MAX), (u128::MAX, 0)] {
            let rule = WarmupRule { gate: Some(1), div, floor_sat };
            assert!(rule.activation_budget(1, active, legacy(active)) <= legacy(active));
        }
    }
    // Below the gate and at genesis: today's budget, untouched.
    assert_eq!(middle_rule(5).activation_budget(4, crossover, legacy(crossover)), legacy(crossover));
    assert_eq!(middle_rule(0).activation_budget(0, 0, u128::MAX), u128::MAX);
    // A zero floor still drains a queue only through the proportional term;
    // the shipped floor is positive, so a queue always moves.
    assert!(GROWTH_CAP_WARMUP_FLOOR_SAT >= MIN_DELEGATION_SAT);
}

/// Release is not capped: stake that is leaving drains at exactly today's
/// speed, whether or not the cap is armed and whatever is queued to enter.
#[test]
fn the_cap_never_slows_release() {
    const GATE: u64 = 3;
    // 40M BLCH active from genesis, deactivated after the gate, with 300M
    // BLCH queued behind it trying to enter.
    let mut leaving = position(1, 40_000_000, 0);
    leaving.deactivate_epoch = Some(GATE + 2);
    let entering = position(2, 300_000_000, GATE + 1);
    let alone = [leaving];
    let crowded = [leaving, entering];
    let mut drained_at = None;
    for epoch in 0..200 {
        let legacy = Registry::resolve_with_rule(&alone, epoch, &WarmupRule::LEGACY).activated_sat(&leaving);
        for ds in [&alone[..], &crowded[..]] {
            for rule in [middle_rule(GATE), WarmupRule { gate: Some(GATE), div: 1_536, floor_sat: 1 }] {
                assert_eq!(Registry::resolve_with_rule(ds, epoch, &rule).activated_sat(&leaving), legacy, "epoch {epoch}");
            }
        }
        if legacy == 0 && drained_at.is_none() {
            drained_at = Some(epoch);
        }
    }
    // 40M at 500,000 BLCH per epoch: 80 epochs from the deactivation epoch.
    assert_eq!(drained_at, Some(GATE + 2 + 79));

    // A position that never got any budget leaves at once: nothing to drain.
    let mut stuck = position(3, 1_000, GATE + 1);
    stuck.requested_epoch = GATE + 2;
    stuck.deactivate_epoch = Some(GATE + 4);
    let ds = [entering, stuck];
    for epoch in GATE + 4..GATE + 50 {
        let r = Registry::resolve_with_rule(&ds, epoch, &middle_rule(GATE));
        assert_eq!(r.activated_sat(&stuck), 0);
        assert_eq!(
            r.state_of(&stuck),
            if epoch >= GATE + 4 + COOLDOWN_EPOCHS { StakeState::Inactive } else { StakeState::Deactivating }
        );
    }
}

// ── The three options, computed on the real walk ────────────────────────────

/// Honest weight the options are compared at: the epoch-6090 figure quoted
/// on `params::HF2_GROWTH_CAP_EPOCH`.
const MODEL_WEIGHT: u128 = 204_660_000 * BLCH;
const EPOCHS_PER_DAY: f64 = 90.0;

/// Epochs from the attacker's request until its ACTIVE stake first reaches
/// one third and two thirds of the total, `(to_third, to_two_thirds)`.
/// The request is made in the epoch before `START` and takes its first slice
/// at `START`, as a `FundedDelegate` does on the real transition, so the
/// counts are the ones `transition::funded_delegation::tests::growth_cap_*`
/// measure through real epoch boundaries.
///
/// `honest_delegated` of the honest weight is delegated stake (active since
/// genesis); the rest is own stake. The attacker delegates far more than it
/// needs, to validators it controls. With `own_path` it also activates own
/// stake as fast as the HF2 cap allows: `staking::growth_budget_sat(W)` per
/// `GROWTH_WINDOW_EPOCHS`, an upper bound on what FIFO admission lets
/// through. The delegated side is the real walk under `rule`.
fn epochs_to_thresholds(rule: WarmupRule, honest_delegated: u128, own_path: bool) -> (u64, u64) {
    const START: u64 = 100;
    let mut ds = Vec::new();
    if honest_delegated > 0 {
        ds.push(Delegation {
            delegator: 0, validator: 0, amount_sat: honest_delegated,
            requested_epoch: 0, deactivate_epoch: None, eligible: true,
        });
    }
    // Four validators' worth of the 500M BLCH per-validator ceiling.
    for k in 1..=4u32 {
        ds.push(Delegation {
            delegator: k, validator: k, amount_sat: 500_000_000 * BLCH,
            requested_epoch: START, deactivate_epoch: None, eligible: true,
        });
    }
    let rule = WarmupRule { gate: rule.gate.map(|_| START), ..rule };
    let mut own = 0u128;
    let (mut third, mut two_thirds) = (None, None);
    // Coarse steps, then the exact epoch: the walk is monotone here.
    let attacker_at = |epoch: u64, own: u128| {
        Registry::resolve_with_rule(&ds, epoch, &rule).total_active() - honest_delegated + own
    };
    let mut epoch = START;
    while two_thirds.is_none() {
        epoch += 1;
        assert!(epoch < START + 20_000);
        if own_path && (epoch - START) % crate::staking::GROWTH_WINDOW_EPOCHS == 0 {
            let w = MODEL_WEIGHT + attacker_at(epoch - 1, own);
            own += crate::staking::growth_budget_sat(w);
        }
        let attacker = attacker_at(epoch, own);
        if third.is_none() && 2 * attacker >= MODEL_WEIGHT {
            third = Some(epoch - START + 1);
        }
        if attacker >= 2 * MODEL_WEIGHT {
            two_thirds = Some(epoch - START + 1);
        }
    }
    (third.unwrap(), two_thirds.unwrap())
}

/// Epochs for one honest delegation of `amount` to be fully active when the
/// queue is otherwise empty and little delegated stake is active.
fn epochs_to_warm_up(rule: WarmupRule, amount: u128) -> u64 {
    const START: u64 = 100;
    let d = Delegation {
        delegator: 1, validator: 1, amount_sat: amount,
        requested_epoch: START, deactivate_epoch: None, eligible: true,
    };
    let rule = WarmupRule { gate: rule.gate.map(|_| START), ..rule };
    (START..).find(|e| Registry::resolve_with_rule(&[d], *e, &rule).activated_sat(&d) == amount).unwrap() - START + 1
}

const OPTIONS: [(&str, WarmupRule); 3] = [
    ("permissive (today)", WarmupRule { gate: None, div: 400, floor_sat: 500_000 * BLCH }),
    ("middle (shipped)", WarmupRule { gate: Some(0), div: 768, floor_sat: 250_000 * BLCH }),
    ("strict", WarmupRule { gate: Some(0), div: 1_536, floor_sat: 125_000 * BLCH }),
];

/// The table of the report and of the spec, computed, with the figures the
/// documentation quotes pinned so they cannot drift from the code.
#[test]
fn growth_cap_options_table() {
    assert_eq!((OPTIONS[1].1.div, OPTIONS[1].1.floor_sat), (GROWTH_CAP_WARMUP_DIV, GROWTH_CAP_WARMUP_FLOOR_SAT));
    let days = |epochs: u64| epochs as f64 / EPOCHS_PER_DAY;
    let mut rows = Vec::new();
    println!("honest weight {} BLCH; epochs (days)", MODEL_WEIGHT / BLCH);
    println!("option | delegated share of honest weight | path | to 1/3 | to 2/3");
    for (name, rule) in OPTIONS {
        let mut row = Vec::new();
        for (label, honest_delegated) in [("0%", 0), ("100%", MODEL_WEIGHT)] {
            for own_path in [false, true] {
                let (third, two_thirds) = epochs_to_thresholds(rule, honest_delegated, own_path);
                println!(
                    "{name} | {label} | {} | {third} ({:.1} d) | {two_thirds} ({:.1} d)",
                    if own_path { "delegation + own stake" } else { "delegation only" },
                    days(third), days(two_thirds),
                );
                row.push((third, two_thirds));
            }
        }
        let waits: Vec<u64> = [10, 100_000, 1_000_000, 10_000_000]
            .iter().map(|blch| epochs_to_warm_up(rule, blch * BLCH)).collect();
        println!("{name} | warm-up of 10 / 100k / 1M / 10M BLCH on an empty queue: {waits:?} epochs");
        rows.push((row, waits));
    }
    // [option][0: none delegated, delegation only; 1: none, both paths;
    //          2: all delegated, delegation only; 3: all, both paths]
    let at = |option: usize, case: usize| rows[option].0[case];
    // Today: the figures on `HF2_GROWTH_CAP_EPOCH` (7.6 and about 5 days).
    assert_eq!(at(0, 0), (205, 687));
    assert_eq!(at(0, 2), (163, 440));
    // Shipped: one third takes twice as long as today, two thirds about
    // twice; strict doubles again.
    assert_eq!(at(1, 0), (410, 1_350));
    assert_eq!(at(2, 0), (819, 2_700));
    // Every option is ordered in every case.
    for case in 0..4 {
        assert!(at(0, case).0 < at(1, case).0 && at(1, case).0 < at(2, case).0);
        assert!(at(0, case).1 < at(1, case).1 && at(1, case).1 < at(2, case).1);
    }
    // Effect on a delegator: waiting time only.
    assert_eq!(rows[0].1, vec![1, 1, 2, 20]);
    assert_eq!(rows[1].1, vec![1, 1, 4, 40]);
    assert_eq!(rows[2].1, vec![1, 1, 8, 80]);
}

/// The pruning check of `FUNDED_DELEGATION_BOUND_ACTIVATION_EPOCH` reads the
/// same rule as the resolver, so the two gates compose: with the growth cap
/// armed before, at or after the pruning epoch, a pruning the check accepts
/// is still invisible at that epoch and at every later one, and the pruned
/// list still resolves to the two-passes-per-epoch statement of the capped
/// rule.
#[test]
fn a_neutral_pruning_stays_invisible_under_the_growth_cap() {
    let mut rng = Rng::new(0x6A0B_CA92);
    let (mut neutral, mut refused, mut capped) = (0u32, 0u32, 0u32);
    for trial in 0..500u32 {
        let shape = 1 + rng.below(3);
        let n = 2 + rng.below(30) as usize;
        let ds = random_history(&mut rng, shape, n);
        let at = rng.below(last_event(&ds) + 200);
        let gate = rng.below(at + 40);
        let _cap = crate::params::funded_delegation_growth_cap_rehearsal::open_at(gate);
        let rule = WarmupRule::consensus();
        assert_eq!(rule, middle_rule(gate));
        let now = Registry::resolve_uncached(&ds, at);
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
                "trial {trial}, pruned at {at}, gate {gate}, epoch {epoch}"
            );
        }
        let want: u128 = capped_reference(&full, at + 7, &rule).iter().sum();
        assert_eq!(Registry::resolve_uncached(&cut, at + 7).total_active(), want, "trial {trial}");
        capped += u32::from(
            Registry::resolve_uncached(&full, at + 60) != Registry::resolve_with_rule(&full, at + 60, &WarmupRule::LEGACY),
        );
    }
    assert!(neutral > 100, "only {neutral} neutral prunings exercised");
    assert!(refused > 5, "only {refused} refusals exercised");
    assert!(capped > 20, "only {capped} of the histories were changed by the cap");
}
