// SPDX-License-Identifier: AGPL-3.0-or-later

//! R1 M5 (perf, ungated, behaviour-identical): `delegation::Registry::resolve`
//! and `staking::resolve_activations` now short-circuit when nothing is
//! eligible to admit, instead of walking `0..=epoch` — Θ(epoch) work for a
//! result that was always going to be empty. The change is a pure
//! optimisation: NOTHING about the shipped consensus rule moves, so this
//! file exists to prove the fast path and the original algorithm agree, not
//! to test the rule itself (that is `tests/properties.rs`'s job, a file this
//! crate does not own the right to edit in this worktree, hence a NEW file).
//!
//! `bloch-pos-committee` carries no `proptest` dev-dependency (unlike
//! `bloch-crypto` and `bloch-sis-pow` elsewhere in this workspace, and unlike
//! this crate's OWN `tests/properties.rs`, whose banner calls itself a
//! "property test" file while using a hand-rolled deterministic RNG rather
//! than the `proptest` crate) — and `--offline` builds cannot fetch a new
//! one. This file follows the existing house style instead: a small,
//! seeded, dependency-free linear-congruential generator driving many random
//! trials, which is what "property test" already means in this crate.

use bloch_pos_committee::delegation::{
    Delegation, Registry, MIN_CHURN_SAT, MIN_DELEGATION_SAT, WARMUP_RATE_BPS,
};
use bloch_pos_committee::staking::{
    resolve_activations, QueuedDeposit, ACTIVATION_DELAY_EPOCHS, MAX_ACTIVATIONS_PER_EPOCH,
};

/// Same shape as `tests/properties.rs`'s `Rng`: a tiny, seeded,
/// dependency-free generator, deterministic across runs so a failure is
/// reproducible without capturing a seed out of band.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
    fn below_u128(&mut self, bound: u128) -> u128 {
        if bound == 0 {
            0
        } else {
            (self.next_u64() as u128) % bound
        }
    }
    fn bool_with_odds(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
}

// ── delegation::Registry::resolve ───────────────────────────────────────────

/// The pre-R1-M5 algorithm, unconditionally — no empty-queue short-circuit.
/// A deliberate, independent re-derivation (not a call into the crate's own
/// `resolve`) so this file is actually checking the fast path against a
/// SEPARATE statement of the rule, not against itself. Reads the real
/// exported constants (`MIN_DELEGATION_SAT`, `WARMUP_RATE_BPS`,
/// `MIN_CHURN_SAT`) rather than mirroring their values, so this reference
/// cannot drift from the crate's own numbers.
fn resolve_reference(delegations: &[Delegation], epoch: u64) -> (u128, Vec<(u32, u128)>) {
    let mut queue: Vec<&Delegation> = delegations
        .iter()
        .filter(|d| d.eligible && d.amount_sat >= MIN_DELEGATION_SAT)
        .collect();
    queue.sort_by_key(|d| (d.requested_epoch, d.validator, d.delegator, d.amount_sat));

    let mut active: Vec<(u32, u128)> = Vec::new();
    let mut total_active: u128 = 0;
    let mut activated: Vec<u128> = vec![0; queue.len()];

    for e in 0..=epoch {
        let budget = if e == 0 {
            u128::MAX
        } else {
            let rate = total_active * WARMUP_RATE_BPS / 10_000;
            if rate > MIN_CHURN_SAT {
                rate
            } else {
                MIN_CHURN_SAT
            }
        };

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

    (total_active, active)
}

fn random_delegation(rng: &mut Rng) -> Delegation {
    let requested_epoch = rng.below(6);
    Delegation {
        delegator: rng.below(6) as u32,
        validator: rng.below(4) as u32,
        // Spans both sides of `MIN_DELEGATION_SAT` and both sides of
        // `MIN_CHURN_SAT`, so warm-up slicing is actually exercised.
        amount_sat: rng.below_u128(2 * MIN_CHURN_SAT),
        requested_epoch,
        deactivate_epoch: if rng.bool_with_odds(3) {
            Some(requested_epoch + rng.below(8))
        } else {
            None
        },
        eligible: !rng.bool_with_odds(4), // ~75% eligible
    }
}

/// The property: `Registry::resolve`'s two headline outputs — total active
/// stake and the per-validator stake vector — match the reference on random
/// inputs, EMPTY ones included (the case the short-circuit actually changes
/// the code path for) and non-empty ones (the case it must not touch at
/// all). Reverting the short-circuit cannot turn this red — it would only
/// prove the reference matches itself — so this test's job is the inverse
/// one: catching the short-circuit if it EVER stops being a no-op, e.g. a
/// future edit that changes what an all-ineligible or all-empty queue
/// resolves to without updating both paths.
#[test]
fn resolve_matches_the_unoptimised_reference_including_the_empty_queue_case() {
    let mut rng = Rng::new(0xB10C_05A1);
    for trial in 0..500 {
        // Bias toward small/empty inputs early, since that is the path the
        // fix actually changes; widen later so the non-empty path (which
        // must be untouched) gets real coverage too.
        let n = if trial < 100 { rng.below(2) as usize } else { rng.below(10) as usize };
        let dels: Vec<Delegation> = (0..n).map(|_| random_delegation(&mut rng)).collect();
        let epoch = rng.below(10);

        let fast = Registry::resolve(&dels, epoch);
        let (ref_total, ref_active) = resolve_reference(&dels, epoch);

        assert_eq!(
            fast.total_active(),
            ref_total,
            "trial {trial}: total_active diverged for {n} delegations at epoch {epoch}"
        );
        let mut fast_stakes: Vec<(u32, u128)> =
            ref_active.iter().map(|(v, _)| (*v, fast.stake_of(*v))).collect();
        fast_stakes.sort_unstable();
        let mut ref_sorted = ref_active.clone();
        ref_sorted.sort_unstable();
        assert_eq!(
            fast_stakes, ref_sorted,
            "trial {trial}: per-validator stake diverged for {n} delegations at epoch {epoch}"
        );
    }
}

/// The specific case the fix targets, isolated: a wholly empty delegation
/// list at a large epoch must resolve instantly to nothing active — and, by
/// the reference above, that is exactly what the O(epoch) walk would have
/// produced too.
#[test]
fn resolve_on_an_empty_queue_matches_the_reference_at_a_large_epoch() {
    let dels: Vec<Delegation> = Vec::new();
    let epoch = 5_000;
    let fast = Registry::resolve(&dels, epoch);
    let (ref_total, ref_active) = resolve_reference(&dels, epoch);
    assert_eq!(fast.total_active(), 0);
    assert_eq!(ref_total, 0);
    assert!(ref_active.is_empty());
    assert!(fast.validators().is_empty());
}

// ── staking::resolve_activations ────────────────────────────────────────────

/// The pre-R1-M5 algorithm for the staking queue, unconditionally. Reads the
/// real exported constants (`ACTIVATION_DELAY_EPOCHS`,
/// `MAX_ACTIVATIONS_PER_EPOCH`) rather than mirroring their values.
fn resolve_activations_reference(deposits: &[QueuedDeposit], epoch: u64) -> Vec<([u8; 32], u64)> {
    let mut queue: Vec<&QueuedDeposit> = deposits.iter().collect();
    queue.sort_by_key(|d| (d.deposit_epoch, d.pubkey_hash));

    let mut activated: Vec<([u8; 32], u64)> = Vec::new();
    let mut done = vec![false; queue.len()];

    for e in 0..=epoch {
        let mut admitted_this_epoch = 0usize;
        for (i, d) in queue.iter().enumerate() {
            if admitted_this_epoch == MAX_ACTIVATIONS_PER_EPOCH {
                break;
            }
            if done[i] || d.deposit_epoch.saturating_add(ACTIVATION_DELAY_EPOCHS) > e {
                continue;
            }
            done[i] = true;
            admitted_this_epoch += 1;
            activated.push((d.pubkey_hash, e));
        }
    }
    activated
}

fn random_deposit(rng: &mut Rng) -> QueuedDeposit {
    let mut hash = [0u8; 32];
    for b in hash.iter_mut() {
        *b = rng.below(256) as u8;
    }
    QueuedDeposit {
        pubkey_hash: hash,
        deposit_epoch: rng.below(6),
        amount_sat: rng.below_u128(1_000_000_000_000),
    }
}

#[test]
fn resolve_activations_matches_the_unoptimised_reference_including_the_empty_queue_case() {
    let mut rng = Rng::new(0xB10C_05A2);
    for trial in 0..500 {
        let n = if trial < 100 { rng.below(2) as usize } else { rng.below(10) as usize };
        let deposits: Vec<QueuedDeposit> = (0..n).map(|_| random_deposit(&mut rng)).collect();
        let epoch = rng.below(10);

        let fast = resolve_activations(&deposits, epoch);
        let reference = resolve_activations_reference(&deposits, epoch);
        assert_eq!(
            fast, reference,
            "trial {trial}: resolve_activations diverged for {n} deposits at epoch {epoch}"
        );
    }
}

#[test]
fn resolve_activations_on_an_empty_queue_matches_the_reference_at_a_large_epoch() {
    let deposits: Vec<QueuedDeposit> = Vec::new();
    let epoch = 5_000;
    assert_eq!(resolve_activations(&deposits, epoch), Vec::new());
    assert_eq!(resolve_activations_reference(&deposits, epoch), Vec::new());
}
