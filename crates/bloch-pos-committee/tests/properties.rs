// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property tests (A2 deliverable, §12 of the migration design).
//!
//! Two properties dominate this file because each maps to a consensus bug this
//! chain has actually suffered:
//!
//! 1. **Order independence.** Every consensus function must give the same
//!    result no matter how its input happens to be ordered. The cumulative
//!    stake array in `sample` was once built in slice order, so two nodes with
//!    identical state drew different committees.
//! 2. **No local state (§5.5).** Calling the same function twice with the same
//!    inputs gives the same result, never depending on an earlier call.
//!    `expected_bits` read node-local mutable state and split mainnet on
//!    2026-08-08.
//!
//! Plus: value conservation in `split_fees`/`distribute`, vesting
//! monotonicity, emission never exceeding its allocation, and no accumulator
//! overflow at the V4 supply scale (10^19 sat = 54% of `u64::MAX`).
//!
//! All randomness comes from a fixed-seed splitmix64 generator implemented
//! below: the suite is exactly reproducible, uses only std, and adds no
//! dependency.
//!
//! Tests prefixed `probe_` assert properties the production code is SUPPOSED
//! to hold but (at the time of writing) does not. They are left failing on
//! purpose — A2's job is to find, not to fix. Each probe's comment states the
//! finding precisely.

use bloch_pos_committee::delegation::{self, Delegation, Registry, StakeState};
use bloch_pos_committee::rewards::{self, StakeAccount};
use bloch_pos_committee::tokenomics_v4 as tk;
use bloch_pos_committee::*;
use std::collections::HashMap;

// ── Deterministic PRNG (splitmix64) — std only, fixed seed, reproducible ────

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

    /// Uniform in `[0, n)` by widening multiply — no modulo, test-grade.
    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        ((self.next_u64() as u128 * n as u128) >> 64) as u64
    }

    /// Fisher–Yates.
    fn shuffle<T>(&mut self, xs: &mut [T]) {
        for i in (1..xs.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            xs.swap(i, j);
        }
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        out
    }
}

// ── Generators ──────────────────────────────────────────────────────────────

/// Random validator set with unique indices; ~10% carry zero stake
/// (tainted/exited under §4.1) so the eligibility filter is always exercised.
fn random_validators(rng: &mut Rng, n: usize) -> Vec<Validator> {
    (0..n as u32)
        .map(|index| Validator {
            index,
            effective_stake: if rng.below(10) == 0 { 0 } else { 1 + rng.below(1_000_000_000_000) },
        })
        .collect()
}

/// Random delegation list with **unique** `(requested_epoch, validator,
/// delegator)` queue keys — the well-formed-state case. The duplicate-key case
/// is a separate probe.
fn random_delegations(rng: &mut Rng, n: usize) -> Vec<Delegation> {
    (0..n as u32)
        .map(|i| {
            let requested_epoch = rng.below(8);
            let mut d = Delegation {
                delegator: 1_000 + i, // unique per record → unique queue key
                validator: rng.below(15) as u32,
                amount_sat: (10 + rng.below(1_000_000)) as u128 * tk::SAT_PER_BLOCH,
                requested_epoch,
                deactivate_epoch: None,
                eligible: rng.below(8) != 0, // ~12% tainted
            };
            if rng.below(5) == 0 {
                d.deactivate_epoch = Some(requested_epoch + rng.below(20));
            }
            if rng.below(12) == 0 {
                d.amount_sat = delegation::MIN_DELEGATION_SAT - 1; // dust
            }
            d
        })
        .collect()
}

fn registry_fingerprint(r: &Registry) -> (Vec<Validator>, u128, u128, u128, usize) {
    (r.validators(), r.total_active(), r.cap_sat(), r.top_share_bps(), r.nakamoto_coefficient())
}

// ═══ 1. ORDER INDEPENDENCE ══════════════════════════════════════════════════

#[test]
fn sample_is_independent_of_validator_order() {
    // The bug this crate already had: the cumulative stake array was built in
    // slice order, so two nodes holding the same set in different memory order
    // drew different committees. Random sets, random shuffles, both roles.
    let mut rng = Rng::new(0xB10C_0001);
    for _ in 0..40 {
        let n = 9 + rng.below(292) as usize;
        let vs = random_validators(&mut rng, n);
        let mix = rng.bytes32();
        let index = rng.next_u64();
        for (role, k) in [(Role::SlotSubcommittee, SLOT_SUBCOMMITTEE_SIZE), (Role::EpochCommittee, COMMITTEE_SIZE)] {
            let canonical = sample(&mix, index, role, &vs, k);

            // Structural sanity while we are here: sorted, distinct, only
            // eligible members, exactly k seats when k are fillable.
            assert!(canonical.windows(2).all(|w| w[0] < w[1]), "not sorted/distinct");
            let eligible = vs.iter().filter(|v| v.effective_stake > 0).count();
            assert_eq!(canonical.len(), k.min(eligible));
            for picked in &canonical {
                let v = vs.iter().find(|v| v.index == *picked).unwrap();
                assert!(v.effective_stake > 0, "zero-stake validator drawn");
            }

            for _ in 0..3 {
                let mut shuffled = vs.clone();
                rng.shuffle(&mut shuffled);
                assert_eq!(
                    sample(&mix, index, role, &shuffled, k),
                    canonical,
                    "committee depends on registry memory order (n={n}, role={role:?})"
                );
            }
        }
    }
}

#[test]
fn is_selected_agrees_with_sample_on_random_sets() {
    // Membership has exactly one definition. A predicate that disagreed with
    // the full draw in any corner case would be a consensus split.
    let mut rng = Rng::new(0xB10C_0002);
    for _ in 0..15 {
        let n = 5 + rng.below(120) as usize;
        let vs = random_validators(&mut rng, n);
        let mix = rng.bytes32();
        let index = rng.next_u64();
        let committee = sample(&mix, index, Role::SlotSubcommittee, &vs, SLOT_SUBCOMMITTEE_SIZE);
        for v in &vs {
            assert_eq!(
                committee.contains(&v.index),
                is_selected(&mix, index, Role::SlotSubcommittee, &vs, SLOT_SUBCOMMITTEE_SIZE, v.index)
            );
        }
    }
}

#[test]
fn registry_resolve_is_independent_of_delegation_order() {
    // Same shape of bug as the sampling one: the resolved registry must be a
    // function of the delegation *set*, never of the order the caller stored
    // it in. Well-formed state: unique queue keys.
    let mut rng = Rng::new(0xB10C_0003);
    for _ in 0..25 {
        let n = 4 + rng.below(40) as usize;
        let ds = random_delegations(&mut rng, n);
        for epoch in [0u64, 3, 9, 25, 60] {
            let canonical = registry_fingerprint(&Registry::resolve(&ds, epoch));
            for _ in 0..3 {
                let mut shuffled = ds.clone();
                rng.shuffle(&mut shuffled);
                assert_eq!(
                    registry_fingerprint(&Registry::resolve(&shuffled, epoch)),
                    canonical,
                    "registry depends on delegation input order (epoch {epoch})"
                );
            }
        }
    }
}

/// Random block tree: block 0 is genesis, every later block picks a random
/// earlier parent. Returns (parents, children).
fn random_tree(
    rng: &mut Rng,
    n_blocks: u64,
) -> (HashMap<[u8; 32], [u8; 32]>, HashMap<[u8; 32], Vec<[u8; 32]>>) {
    let root = |b: u64| -> [u8; 32] {
        let mut r = [0u8; 32];
        r[..8].copy_from_slice(&b.to_le_bytes());
        r
    };
    let mut parents = HashMap::new();
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    for b in 1..n_blocks {
        let p = rng.below(b);
        parents.insert(root(b), root(p));
        children.entry(root(p)).or_default().push(root(b));
    }
    (parents, children)
}

#[test]
fn forkchoice_is_independent_of_arrival_order_without_equivocation() {
    // One message per (validator, slot), distinct slots per validator — the
    // honest case. Head and every weight must not depend on gossip arrival
    // order, stake registration order, or the order of a block's child list.
    let mut rng = Rng::new(0xB10C_0004);
    for _ in 0..20 {
        let n_blocks = 3 + rng.below(38);
        let (parents, children) = random_tree(&mut rng, n_blocks);
        let roots: Vec<[u8; 32]> = (0..n_blocks)
            .map(|b| {
                let mut r = [0u8; 32];
                r[..8].copy_from_slice(&b.to_le_bytes());
                r
            })
            .collect();
        let genesis = roots[0];

        let n_validators = 2 + rng.below(28) as u32;
        let stakes: Vec<(u32, u64)> =
            (0..n_validators).map(|v| (v, 1 + rng.below(1_000_000))).collect();

        // Distinct slots per validator so the latest-message rule is total.
        let mut messages: Vec<(u32, LatestMessage)> = Vec::new();
        for v in 0..n_validators {
            let mut slots: Vec<u64> = (1..=10).collect();
            rng.shuffle(&mut slots);
            for &slot in slots.iter().take(1 + rng.below(3) as usize) {
                let target = roots[rng.below(n_blocks) as usize];
                messages.push((v, LatestMessage { slot, root: target }));
            }
        }

        let build = |rng: &mut Rng| -> Store {
            let mut s = Store::new();
            let mut st = stakes.clone();
            rng.shuffle(&mut st);
            for (v, stake) in st {
                s.set_stake(v, stake);
            }
            let mut ms = messages.clone();
            rng.shuffle(&mut ms);
            for (v, m) in ms {
                s.observe(v, m);
            }
            s
        };

        let a = build(&mut rng);
        let b = build(&mut rng);
        let tree = BlockTree { parents: &parents };

        for r in &roots {
            assert_eq!(a.weight(&tree, r), b.weight(&tree, r), "weight depends on arrival order");
        }

        let mut shuffled_children = children.clone();
        for kids in shuffled_children.values_mut() {
            rng.shuffle(kids);
        }
        assert_eq!(
            a.head(&tree, genesis, &children),
            b.head(&tree, genesis, &shuffled_children),
            "head depends on arrival or child-list order"
        );
    }
}

#[test]
fn reward_distribution_is_independent_of_account_order() {
    // Payouts are per-account and the epoch totals are sums; both must be
    // invariant under permutation of the account list.
    let mut rng = Rng::new(0xB10C_0005);
    for _ in 0..20 {
        let accounts: Vec<StakeAccount> = (0..1 + rng.below(30))
            .map(|_| {
                let max_credits = 1 + rng.below(1_000);
                StakeAccount {
                    self_stake: rng.below(1_000_000_000) as u128,
                    delegated_stake: rng.below(1_000_000_000) as u128,
                    commission_bps: rng.below(10_001) as u128,
                    credits: rng.below(max_credits + 1),
                    max_credits,
                }
            })
            .collect();
        let total_stake: u128 =
            accounts.iter().map(|a| a.self_stake + a.delegated_stake).sum::<u128>().max(1);
        let issuance = 1 + rng.below(u64::MAX) as u128;

        let payouts: Vec<rewards::Payout> =
            accounts.iter().map(|a| rewards::distribute(a, issuance, total_stake)).collect();
        let total: u128 = payouts.iter().map(|p| p.operator + p.delegators + p.forfeited).sum();

        let mut order: Vec<usize> = (0..accounts.len()).collect();
        rng.shuffle(&mut order);
        let mut shuffled_total = 0u128;
        for i in order {
            let p = rewards::distribute(&accounts[i], issuance, total_stake);
            assert_eq!(p, payouts[i], "payout depends on evaluation order");
            shuffled_total += p.operator + p.delegators + p.forfeited;
        }
        assert_eq!(shuffled_total, total);
        assert!(total <= issuance, "epoch paid out more than it issued");
    }
}

#[test]
fn slash_losses_follow_records_not_positions() {
    // apply_slash returns losses in input order by contract; the loss charged
    // to a given *record* must not change when the list is permuted.
    let mut rng = Rng::new(0xB10C_0006);
    for _ in 0..20 {
        let n = 3 + rng.below(30) as usize;
        let ds = random_delegations(&mut rng, n);
        let validator = rng.below(15) as u32;
        let penalty = rng.below(12_000) as u128; // beyond 10_000 exercises the clamp
        let losses = delegation::apply_slash(&ds, validator, penalty);

        let mut order: Vec<usize> = (0..ds.len()).collect();
        rng.shuffle(&mut order);
        let shuffled: Vec<Delegation> = order.iter().map(|&i| ds[i]).collect();
        let shuffled_losses = delegation::apply_slash(&shuffled, validator, penalty);
        for (pos, &orig) in order.iter().enumerate() {
            assert_eq!(shuffled_losses[pos], losses[orig], "loss moved with position, not record");
        }
    }
}

// ═══ 2. NO LOCAL STATE (§5.5) ═══════════════════════════════════════════════

#[test]
fn sample_has_no_hidden_state_across_interleaved_calls() {
    // Same inputs → same output, regardless of what was computed in between.
    // This is the property whose absence (`expected_bits` reading a mutable
    // local) split mainnet on 2026-08-08.
    let mut rng = Rng::new(0xB10C_0007);
    let vs = random_validators(&mut rng, 200);
    let cases: Vec<([u8; 32], u64, usize)> = (0..40)
        .map(|_| (rng.bytes32(), rng.next_u64(), if rng.below(2) == 0 { 8 } else { 128 }))
        .collect();
    let first: Vec<Vec<u32>> =
        cases.iter().map(|(m, i, k)| sample(m, *i, Role::SlotSubcommittee, &vs, *k)).collect();

    let mut order: Vec<usize> = (0..cases.len()).collect();
    rng.shuffle(&mut order);
    for idx in order {
        // Decoy call with unrelated inputs: if any hidden state existed, this
        // is what would perturb it.
        let decoy_mix = rng.bytes32();
        let _ = sample(&decoy_mix, rng.next_u64(), Role::EpochCommittee, &vs, 64);

        let (m, i, k) = &cases[idx];
        assert_eq!(
            sample(m, *i, Role::SlotSubcommittee, &vs, *k),
            first[idx],
            "sample result changed between calls with identical inputs"
        );
    }
}

#[test]
fn registry_resolution_is_repeatable() {
    let mut rng = Rng::new(0xB10C_0008);
    for _ in 0..10 {
        let ds = random_delegations(&mut rng, 25);
        let decoys = random_delegations(&mut rng, 25);
        let epoch = rng.below(64);
        let first = registry_fingerprint(&Registry::resolve(&ds, epoch));
        let _ = Registry::resolve(&decoys, epoch + 1); // unrelated work in between
        assert_eq!(registry_fingerprint(&Registry::resolve(&ds, epoch)), first);
    }
}

#[test]
fn forkchoice_queries_do_not_mutate_the_store() {
    // weight() and head() are reads; asking twice must answer the same, and
    // asking about one root must not change the answer for another.
    let mut rng = Rng::new(0xB10C_0009);
    let (parents, children) = random_tree(&mut rng, 30);
    let tree = BlockTree { parents: &parents };
    let mut store = Store::new();
    for v in 0..20u32 {
        store.set_stake(v, 1 + rng.below(1_000_000));
        let mut r = [0u8; 32];
        r[..8].copy_from_slice(&rng.below(30).to_le_bytes());
        store.observe(v, LatestMessage { slot: 1 + rng.below(10), root: r });
    }
    let genesis = {
        let mut r = [0u8; 32];
        r[..8].copy_from_slice(&0u64.to_le_bytes());
        r
    };
    let head1 = store.head(&tree, genesis, &children);
    for b in 0..30u64 {
        let mut r = [0u8; 32];
        r[..8].copy_from_slice(&b.to_le_bytes());
        let w1 = store.weight(&tree, &r);
        let w2 = store.weight(&tree, &r);
        assert_eq!(w1, w2);
    }
    assert_eq!(store.head(&tree, genesis, &children), head1);
}

#[test]
fn signing_root_and_validate_are_pure_and_field_sensitive() {
    struct AlwaysValid;
    impl SignatureVerifier for AlwaysValid {
        fn verify(&self, _v: u32, _r: &[u8; 32], _s: &[u8]) -> bool {
            true
        }
    }
    let mut rng = Rng::new(0xB10C_000A);
    for _ in 0..100 {
        let a = AttestationData {
            slot: rng.next_u64() >> 1,
            head: rng.bytes32(),
            source_epoch: rng.below(1_000),
            source_root: rng.bytes32(),
            target_epoch: 1_000 + rng.below(1_000),
            target_root: rng.bytes32(),
        };
        let b = AttestationData { slot: a.slot.wrapping_add(1 + rng.below(100)), ..a };
        // Purity: same data, same root, every time.
        assert_eq!(a.signing_root(), a.signing_root());
        // Sensitivity: distinct data, distinct root.
        assert_ne!(a.signing_root(), b.signing_root());

        let att = Attestation { data: a, validator: 3, signature: vec![0u8; 8] };
        let committee = vec![1u32, 3, 5];
        let r1 = attestation::validate(&att, &committee, a.slot, &AlwaysValid);
        let r2 = attestation::validate(&att, &committee, a.slot, &AlwaysValid);
        assert_eq!(r1, r2, "validate is not repeatable");
    }
}

#[test]
fn tokenomics_functions_are_pure_at_random_slots() {
    // Const fns cannot hold state, but the property is cheap insurance against
    // a future refactor introducing a cache — the exact way §5.5 was violated.
    let mut rng = Rng::new(0xB10C_000B);
    let fns: [fn(u64) -> u128; 9] = [
        tk::founder_vested_sat,
        tk::vc_vested_sat,
        tk::team_vested_sat,
        tk::marketing_vested_sat,
        tk::liquidity_vested_sat,
        tk::insider_unlocked_sat,
        tk::validator_reward_flat_sat,
        tk::validator_reward_halving_sat,
        tk::validator_reward_decay_sat,
    ];
    for _ in 0..50 {
        let slot = rng.below(tk::EMISSION_SLOTS + tk::SLOTS_PER_YEAR);
        for f in fns {
            let first = f(slot);
            let _ = f(rng.below(tk::EMISSION_SLOTS)); // interleave
            assert_eq!(f(slot), first);
        }
        let (b, p) = (rng.below(u64::MAX) as u128, rng.below(u64::MAX) as u128);
        assert_eq!(rewards::split_fees_at(b, p, slot), rewards::split_fees_at(b, p, slot));
    }
}

// ═══ 3. VALUE CONSERVATION ══════════════════════════════════════════════════

#[test]
fn fee_split_conserves_value_in_all_eras() {
    // burned + to_producer == base + priority: nothing minted, nothing lost,
    // in the emission era, at the boundary, and in the fee-only era.
    let mut rng = Rng::new(0xB10C_000C);
    for _ in 0..200 {
        let base = rng.below(u64::MAX) as u128;
        let prio = rng.below(u64::MAX) as u128;
        let slot = match rng.below(5) {
            0 => tk::EMISSION_SLOTS - 1,
            1 => tk::EMISSION_SLOTS,
            2 => u64::MAX,
            _ => rng.next_u64(),
        };
        let s = rewards::split_fees_at(base, prio, slot);
        assert_eq!(s.burned + s.to_producer, base + prio, "slot={slot} base={base} prio={prio}");
    }
}

#[test]
fn distribute_conserves_the_stake_share_exactly() {
    // operator + delegators + forfeited must equal the account's gross slice
    // (issuance × stake / total) to the satoshi — commission and credit
    // scaling move value around, never create or destroy it.
    //
    // Inputs are bounded by the documented domain (issuance and stake both at
    // most the 10^19-sat total supply). OBSERVATION for the report, not a
    // failure: outside that domain the u128 product `epoch_issuance * stake`
    // at rewards.rs:133 overflows — at the supply cap it reaches ~10^38,
    // only 3.4× under u128::MAX, so the headroom is real but thin, and
    // nothing in `distribute` checks the domain.
    let mut rng = Rng::new(0xB10C_000D);
    let half_supply = (tk::TOTAL_SUPPLY_SAT / 2) as u64;
    for _ in 0..300 {
        let self_stake = rng.below(half_supply) as u128;
        let delegated = rng.below(half_supply) as u128;
        let stake = self_stake + delegated;
        let total_stake =
            (stake + rng.below(u64::MAX) as u128).min(tk::TOTAL_SUPPLY_SAT).max(stake);
        let max_credits = 1 + rng.below(10_000);
        let acct = StakeAccount {
            self_stake,
            delegated_stake: delegated,
            commission_bps: rng.below(15_000) as u128, // above 10_000 exercises the clamp
            credits: rng.below(max_credits + 2),       // above max exercises the clamp
            max_credits,
        };
        let issuance = rng.below(u64::MAX) as u128;
        let p = rewards::distribute(&acct, issuance, total_stake);
        if total_stake == 0 || stake == 0 {
            assert_eq!((p.operator, p.delegators, p.forfeited), (0, 0, 0));
        } else {
            let gross = issuance * stake / total_stake;
            assert_eq!(
                p.operator + p.delegators + p.forfeited,
                gross,
                "value created or destroyed: {acct:?}"
            );
        }
    }
}

#[test]
fn slash_never_exceeds_the_bonded_amount() {
    let mut rng = Rng::new(0xB10C_000E);
    for _ in 0..50 {
        let ds = random_delegations(&mut rng, 20);
        let validator = rng.below(15) as u32;
        let penalty = rng.below(50_000) as u128; // far beyond 100%, must clamp
        let losses = delegation::apply_slash(&ds, validator, penalty);
        assert_eq!(losses.len(), ds.len());
        for (d, loss) in ds.iter().zip(&losses) {
            assert!(*loss <= d.amount_sat, "slashed more than was bonded");
            if d.validator != validator || !d.eligible {
                assert_eq!(*loss, 0, "slash hit an unrelated or ineligible record");
            } else if penalty >= 10_000 {
                assert_eq!(*loss, d.amount_sat, "100% penalty must take everything");
            }
        }
    }
}

// ═══ 4. VESTING MONOTONICITY ════════════════════════════════════════════════

#[test]
fn all_vesting_schedules_are_monotonic_and_capped() {
    // A vesting function that ever regresses would let "unlocked" balance
    // become locked again — supply accounting breaks either way.
    let mut rng = Rng::new(0xB10C_000F);
    let cases: [(fn(u64) -> u128, u128, &str); 6] = [
        (tk::founder_vested_sat, tk::FOUNDER_BLOCH, "founder"),
        (tk::vc_vested_sat, tk::VC_BLOCH, "vc"),
        (tk::team_vested_sat, tk::TEAM_BLOCH, "team"),
        (tk::marketing_vested_sat, tk::MARKETING_BLOCH, "marketing"),
        (tk::liquidity_vested_sat, tk::LIQUIDITY_BLOCH, "liquidity"),
        (
            tk::insider_unlocked_sat,
            tk::FOUNDER_BLOCH + tk::TEAM_BLOCH + tk::VC_BLOCH + tk::MARKETING_BLOCH,
            "insider",
        ),
    ];
    let horizon = tk::FOUNDER_VESTING_END_SLOT + tk::SLOTS_PER_YEAR;
    for _ in 0..400 {
        let a = rng.below(horizon);
        let b = a + rng.below(horizon); // a <= b
        for (f, total_bloch, name) in cases {
            let (va, vb) = (f(a), f(b));
            assert!(va <= vb, "{name} vesting regressed between slots {a} and {b}");
            assert!(vb <= total_bloch * tk::SAT_PER_BLOCH, "{name} vested above its bucket");
        }
    }
    // Exact completion, no stranded dust.
    for (f, total_bloch, name) in cases {
        assert_eq!(f(u64::MAX), total_bloch * tk::SAT_PER_BLOCH, "{name} did not complete");
    }
}

// ═══ 5. EMISSION BOUNDS ═════════════════════════════════════════════════════

#[test]
fn emission_accumulators_are_monotonic_and_never_exceed_the_allocation() {
    let mut rng = Rng::new(0xB10C_0010);
    let alloc = tk::VALIDATOR_EMISSION_BLOCH * tk::SAT_PER_BLOCH;
    let curves: [(fn(u64) -> u128, &str); 3] = [
        (tk::validator_emitted_flat_by, "flat"),
        (tk::validator_emitted_halving_by, "halving"),
        (tk::validator_emitted_decay_by, "decay"),
    ];
    let horizon = tk::EMISSION_SLOTS + 2 * tk::SLOTS_PER_YEAR;
    for _ in 0..200 {
        let a = rng.below(horizon);
        let b = a + rng.below(horizon);
        for (f, name) in curves {
            let (ea, eb) = (f(a), f(b));
            assert!(ea <= eb, "{name} emission accumulator regressed ({a} → {b})");
            assert!(eb <= alloc, "{name} emitted beyond the validator allocation at slot {b}");
        }
    }
    for (f, name) in curves {
        assert_eq!(f(u64::MAX), f(tk::EMISSION_SLOTS), "{name} kept emitting after year 40");
    }
}

#[test]
fn emission_increment_matches_the_per_slot_reward() {
    // The accumulator and the per-slot reward are two derivations of the same
    // schedule; §5.4's "exactly one derivation" rule means they must agree at
    // every slot, including era and year boundaries.
    let mut rng = Rng::new(0xB10C_0011);
    let pairs: [(fn(u64) -> u128, fn(u64) -> u128, &str); 3] = [
        (tk::validator_emitted_flat_by, tk::validator_reward_flat_sat, "flat"),
        (tk::validator_emitted_halving_by, tk::validator_reward_halving_sat, "halving"),
        (tk::validator_emitted_decay_by, tk::validator_reward_decay_sat, "decay"),
    ];
    let mut slots: Vec<u64> = (0..150).map(|_| rng.below(tk::EMISSION_SLOTS)).collect();
    // Deliberately include every kind of boundary.
    slots.extend([
        0,
        tk::HALVING_PERIOD_SLOTS - 1,
        tk::HALVING_PERIOD_SLOTS,
        tk::SLOTS_PER_YEAR - 1,
        tk::SLOTS_PER_YEAR,
        tk::EMISSION_SLOTS - 1,
    ]);
    for s in slots {
        for (emitted_by, reward, name) in pairs {
            assert_eq!(
                emitted_by(s + 1) - emitted_by(s),
                reward(s),
                "{name}: accumulator increment disagrees with the reward at slot {s}"
            );
        }
    }
}

#[test]
fn unlocked_supply_never_exceeds_total_supply() {
    // At any slot, everything that can possibly be liquid — insider unlocks,
    // liquidity, the carryover cap, and validator emission under any curve —
    // must stay at or under the 100 B hard cap.
    let mut rng = Rng::new(0xB10C_0012);
    let carry = tk::CARRYOVER_TOTAL_BLOCH * tk::SAT_PER_BLOCH;
    let curves: [fn(u64) -> u128; 3] = [
        tk::validator_emitted_flat_by,
        tk::validator_emitted_halving_by,
        tk::validator_emitted_decay_by,
    ];
    for _ in 0..200 {
        let slot = rng.below(tk::EMISSION_SLOTS + 2 * tk::SLOTS_PER_YEAR);
        for emitted in curves {
            let liquid =
                tk::insider_unlocked_sat(slot) + tk::liquidity_vested_sat(slot) + carry + emitted(slot);
            assert!(liquid <= tk::TOTAL_SUPPLY_SAT, "supply exceeded at slot {slot}");
        }
    }
}

// ═══ 6. NO OVERFLOW AT THE V4 SUPPLY SCALE ══════════════════════════════════
//
// 100 B BLCH at 8 decimals is 10^19 sat — 54% of u64::MAX. Any u64 accumulator
// over more than one large balance wraps. These run in debug (overflow-checked)
// builds, so a wrap is a panic, not a silent wrong answer.

#[test]
fn sampling_survives_stake_totals_beyond_u64() {
    // 200 validators × (u64::MAX / 100) sums to ~2× u64::MAX: the cumulative
    // stake array must be wider than u64 or this panics/wraps.
    let vs: Vec<Validator> = (0..200)
        .map(|index| Validator { index, effective_stake: u64::MAX / 100 })
        .collect();
    let mix = [0xA5u8; 32];
    for index in 0..10u64 {
        let c = sample(&mix, index, Role::EpochCommittee, &vs, COMMITTEE_SIZE);
        assert_eq!(c.len(), COMMITTEE_SIZE);
        assert!(c.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(c, sample(&mix, index, Role::EpochCommittee, &vs, COMMITTEE_SIZE));
    }
}

#[test]
fn registry_survives_the_full_supply_delegated() {
    // The entire supply bonded across 150 delegations: resolution, the cap
    // fixpoint, and the concentration metrics must all stay exact. At the
    // 100 B split the TOTAL itself is 54% of u64::MAX — one more reason,
    // besides the products, that the arithmetic is u128.
    let per = tk::TOTAL_SUPPLY_BLOCH / 150; // BLCH each
    let ds: Vec<Delegation> = (0..150u32)
        .map(|i| Delegation {
            delegator: i,
            validator: i,
            amount_sat: per * tk::SAT_PER_BLOCH,
            requested_epoch: 0,
            deactivate_epoch: None,
            eligible: true,
        })
        .collect();
    let r = Registry::resolve(&ds, 0);
    assert_eq!(r.total_active(), per * tk::SAT_PER_BLOCH * 150);
    assert_eq!(
        r.total_active() / tk::SAT_PER_BLOCH,
        tk::TOTAL_SUPPLY_BLOCH / 150 * 150,
        "test is not at supply scale"
    );
    let vs = r.validators();
    assert_eq!(vs.len(), 150);
    for v in &vs {
        assert!((v.effective_stake as u128) <= r.cap_sat().max(per * tk::SAT_PER_BLOCH));
    }
    // And the committee still draws from it without overflow.
    let c = sample(&[0x5Au8; 32], 7, Role::EpochCommittee, &vs, COMMITTEE_SIZE);
    assert_eq!(c.len(), COMMITTEE_SIZE);
    let _ = (r.top_share_bps(), r.nakamoto_coefficient());
}

#[test]
fn forkchoice_weight_survives_maximum_stakes() {
    // 300 validators at u64::MAX each voting the same root: the weight
    // accumulator must be u128.
    let mut parents = HashMap::new();
    let child = [1u8; 32];
    let genesis = [0u8; 32];
    parents.insert(child, genesis);
    let tree = BlockTree { parents: &parents };
    let mut s = Store::new();
    for v in 0..300u32 {
        s.set_stake(v, u64::MAX);
        s.observe(v, LatestMessage { slot: 1, root: child });
    }
    assert_eq!(s.weight(&tree, &genesis), 300u128 * u64::MAX as u128);
}

#[test]
fn distribution_survives_full_supply_scale_inputs() {
    let mut rng = Rng::new(0xB10C_0013);
    let total = tk::TOTAL_SUPPLY_SAT;
    for _ in 0..50 {
        let stake = 1 + rng.below(u64::MAX) as u128; // up to ~total supply
        let self_stake = stake / (1 + rng.below(10) as u128);
        let max_credits = 1 + rng.below(1_000);
        let acct = StakeAccount {
            self_stake,
            delegated_stake: stake - self_stake,
            commission_bps: rng.below(10_001) as u128,
            credits: rng.below(max_credits + 1),
            max_credits,
        };
        let issuance = tk::INITIAL_ANNUAL_SAT; // year-1 issuance, ~4.37e17 sat
        let p = rewards::distribute(&acct, issuance, total);
        assert_eq!(p.operator + p.delegators + p.forfeited, issuance * stake / total);
    }
}

// ═══ 7. PROBES — properties the current code DOES NOT hold ══════════════════
//
// Each probe asserts a property consensus needs; the assertion is expected to
// fail against the current implementation. Left failing on purpose: A2 finds,
// A2 does not fix. The probe comment is the finding.

#[test]
fn probe_sample_rejects_duplicate_registry_indices() {
    // FINDING: `sample` assumes validator indices are unique but never checks.
    // With two registry entries sharing an index (a malformed state no layer
    // enforces against), both entries occupy adjacent slots in the cumulative
    // array and BOTH can be drawn — the returned committee then contains the
    // same validator index twice, giving one validator two seats' weight while
    // the committee has one fewer distinct member. `sort_unstable_by_key` on
    // the duplicate key is also unspecified about their relative order.
    let mut vs: Vec<Validator> = (0..20)
        .map(|index| Validator { index, effective_stake: 1_000 })
        .collect();
    // Duplicate index 7 with dominant stake so both entries are drawn quickly.
    vs.push(Validator { index: 7, effective_stake: 1_000_000 });
    vs[7].effective_stake = 1_000_000;
    let mix = [0x33u8; 32];
    for slot in 0..50u64 {
        let c = sample(&mix, slot, Role::SlotSubcommittee, &vs, SLOT_SUBCOMMITTEE_SIZE);
        assert!(
            c.windows(2).all(|w| w[0] < w[1]),
            "slot {slot}: committee contains a duplicate index: {c:?}"
        );
    }
}

#[test]
fn probe_registry_resolve_is_order_independent_with_duplicate_queue_keys() {
    // FINDING: `Delegation::queue_key` is (requested_epoch, validator,
    // delegator) — it omits amount. Two records sharing that triple (e.g. the
    // same delegator bonding twice to the same validator in one epoch, which
    // no rule forbids) compare equal, so their relative order after the stable
    // sort is the CALLER'S INPUT ORDER. Under a tight warm-up budget the two
    // orders admit different records first, and two nodes holding the same
    // delegation set in different order resolve different registries — the
    // exact §5.5 failure shape this crate exists to prevent.
    let base = Delegation {
        delegator: 1,
        validator: 20,
        amount_sat: 100 * tk::SAT_PER_BLOCH,
        requested_epoch: 0,
        deactivate_epoch: None,
        eligible: true,
    };
    let big = Delegation {
        delegator: 5,
        validator: 10,
        amount_sat: 2_000 * tk::SAT_PER_BLOCH,
        requested_epoch: 1,
        deactivate_epoch: None,
        eligible: true,
    };
    let small = Delegation { amount_sat: 10 * tk::SAT_PER_BLOCH, ..big }; // same queue key

    let a = Registry::resolve(&[base, big, small], 1);
    let b = Registry::resolve(&[base, small, big], 1);
    assert_eq!(
        a.stake_of(10),
        b.stake_of(10),
        "same delegation set, different input order, different registry"
    );
}

#[test]
fn probe_forkchoice_head_is_order_independent_under_equivocation() {
    // FINDING: `Store::observe` keeps the FIRST message seen for a given slot
    // (`prev.slot >= msg.slot` → ignored). The code comment claims this
    // "makes head selection independent of gossip arrival order", but it does
    // the opposite: when a validator equivocates (two heads, one slot), each
    // node keeps whichever message reached it first, so two honest nodes hold
    // different latest-message sets and can compute DIFFERENT HEADS from the
    // same received messages. Ethereum-shape fixes discard both equivocating
    // messages (and slash); first-seen is inherently arrival-order-dependent.
    let genesis = [0u8; 32];
    let a_block = [1u8; 32];
    let b_block = [2u8; 32];
    let mut parents = HashMap::new();
    parents.insert(a_block, genesis);
    parents.insert(b_block, genesis);
    let mut children = HashMap::new();
    children.insert(genesis, vec![a_block, b_block]);
    let tree = BlockTree { parents: &parents };

    let msg_a = LatestMessage { slot: 3, root: a_block };
    let msg_b = LatestMessage { slot: 3, root: b_block };

    let mut node1 = Store::new();
    node1.set_stake(0, 100);
    node1.observe(0, msg_a);
    node1.observe(0, msg_b);

    let mut node2 = Store::new();
    node2.set_stake(0, 100);
    node2.observe(0, msg_b);
    node2.observe(0, msg_a);

    assert_eq!(
        node1.head(&tree, genesis, &children),
        node2.head(&tree, genesis, &children),
        "two nodes saw the same two messages in different order and chose different heads"
    );
}

#[test]
fn probe_state_of_agrees_with_the_admitted_registry() {
    // FINDING: `Registry::state_of` decides Active by `stake_of(validator) > 0
    // && requested_epoch <= epoch` — it looks at the VALIDATOR's stake, not at
    // whether THIS delegation was admitted. A delegation still queued behind
    // the warm-up budget is reported Active as soon as any other delegation to
    // the same validator is active. Summing the amounts of delegations
    // reported Active then disagrees with `total_active()` — a wallet or
    // explorer built on this API would display stake as earning while the
    // consensus registry has not admitted it. (The mirror case exists on
    // cool-down: a budget-delayed release is reported Deactivating while its
    // stake is still counted.)
    let seed = Delegation {
        delegator: 1,
        validator: 20,
        amount_sat: 100 * tk::SAT_PER_BLOCH,
        requested_epoch: 0,
        deactivate_epoch: None,
        eligible: true,
    };
    // Two large delegations to the same validator in epoch 1; the 9% budget
    // admits only the head of the queue, the other waits.
    let first = Delegation {
        delegator: 2,
        validator: 10,
        amount_sat: 1_000 * tk::SAT_PER_BLOCH,
        requested_epoch: 1,
        deactivate_epoch: None,
        eligible: true,
    };
    let queued = Delegation { delegator: 3, ..first };

    let ds = [seed, first, queued];
    let r = Registry::resolve(&ds, 1);

    // A invariante original somava o amount INTEIRO de toda delegacao reportada
    // Active. Ela pegou o bug real de state_of, e depois quebrou por um motivo
    // diferente: com ativacao parcial (correcao do F3) uma delegacao contribui
    // stake enquanto ainda reporta Activating, entao "soma dos Active" nunca
    // igualaria o total. A invariante certa e sobre a PORCAO ativada.
    let activated_sum: u128 = ds.iter().map(|d| r.activated_sat(d)).sum();
    assert_eq!(
        activated_sum,
        r.total_active(),
        "a soma das porcoes ativadas tem de ser exatamente o stake ativo"
    );

    // E o que a sonda existia para pegar continua fixado: nenhuma delegacao
    // pode ser reportada Active sem estar integralmente ativada.
    for d in ds.iter() {
        if r.state_of(d) == StakeState::Active {
            assert_eq!(
                r.activated_sat(d),
                d.amount_sat,
                "state_of reportou Active uma delegacao que nao esta inteira"
            );
        }
    }
}

// ═══ Epoch arithmetic ═══════════════════════════════════════════════════════

#[test]
fn epoch_boundary_is_exactly_where_the_epoch_increments() {
    let mut rng = Rng::new(0xB10C_0014);
    for _ in 0..200 {
        let slot = rng.below(u64::MAX - 1);
        assert_eq!(
            is_epoch_boundary(slot),
            epoch_of(slot + 1) == epoch_of(slot) + 1,
            "boundary flag disagrees with epoch_of at slot {slot}"
        );
    }
}
