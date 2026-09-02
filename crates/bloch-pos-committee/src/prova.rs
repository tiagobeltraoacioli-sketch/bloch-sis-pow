// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The relaunch proof harness** — scenarios 1 to 4 of the Genesis-4
//! relaunch, each with a mutation switch that flips the code back to the
//! broken behaviour and makes a named test go RED.
//!
//! Run it with `scripts/prova-relanca.sh`. That script is the documented
//! command; everything below is what it executes.
//!
//! # Why this file exists
//!
//! Nine commits on this project say "proven by mutation" and left no script,
//! no CI target and no recorded output. A proof nobody can re-run is a claim.
//! Every scenario here is a `#[test]`, every mutation is an `AtomicBool` under
//! `#[cfg(test)]` — the [`crate::params::rehearsal::MUTATE_SEED`] idiom, so
//! the mutation cannot exist in a shipped binary — and each one has a named
//! partner test that asserts the mutation BITES.
//!
//! # WHICH DEFECT THIS FILE IS ABOUT — read this before citing it
//!
//! This file covers **two different failures**, and they were confused with
//! each other for a week. The settled account of both is
//! `docs/post-mortems/2026-08-24-finality-divergence.md`; cite that, not this
//! header.
//!
//! - **Scenario 0 is the 2026-08-24 incident**: the quorum DENOMINATOR is
//!   leak-adjusted with no floor, so a node that can hear only a handful of
//!   the fleet shrinks its own denominator until that handful is two thirds of
//!   it, and finalizes alone. Three partitions did it at once, on one epoch,
//!   under three roots. This is **live in every shipped binary today**, because
//!   [`crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH`] is `u64::MAX`.
//! - **Scenarios 1 to 4 are the roster split**, described below. It is a real
//!   defect, it was fixed on 2026-08-24, and it was **provably inert at the
//!   time of the incident** — mainnet was at ~epoch 986 and the rule that
//!   exposes it does not bind until epoch 1400. It did not cause the
//!   divergence, and it must stop being cited as if it had.
//!
//! # The roster split (scenarios 1–4), in one paragraph
//!
//! [`crate::committees::epoch_committees`] **used to** filter
//! `effective_stake > 0` **before** its Fisher-Yates shuffle. A shuffle is
//! length-dependent, so a 64-element list and a 63-element list produce
//! entirely different permutations — not the same permutation with one element
//! missing. `transition::with_leak_applied` zeroes a fully-leaked validator's
//! stake but keeps it in the roster, so the leak-applied roster (which
//! `compute_post_state` step 8 uses to admit attestations into a block)
//! partitioned differently from the unleaked roster (which `close_epoch` uses
//! to tally the boundary). Honest attestations admitted by the block were
//! dropped at the tally.
//!
//! **The filter is gone** (`b0300409`, 2026-08-24 19:50). It survives only
//! behind [`crate::params::rehearsal::RESTORE_ZERO_STAKE_FILTER`], a
//! `cfg(test)` thread-local, which is what [`partition_step8`]'s broken arm
//! now sets. Between 2026-08-24 and 2026-09-01 it did not set it, both arms of
//! that function computed the same partition, and five tests failed while
//! announcing that this analysis was refuted. They were not refuting it; they
//! were reporting that they could no longer reach the code they exercise.
//! [`crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH`] is now ARMED and bound, so
//! reintroducing the filter today would split the live fleet.
//!
//! # The contract scenarios 1–4 measure against
//!
//! Dev A's fix removes the pre-shuffle filter, making committee membership a
//! pure function of `(seed, epoch, index set)` — **leak-invariant by
//! construction**. Until that lands, [`partition_step8`] models the fixed
//! behaviour by calling the *real* [`crate::committees::epoch_committees`]
//! with the roster's stakes normalised to 1. That is not an approximation:
//! `effective_stake` is read in exactly one place in that function, the
//! filter, so normalising the stakes and deleting the filter produce the same
//! eligible set and therefore the same shuffle, byte for byte. The fidelity is
//! itself asserted, in [`tests::the_model_of_the_fix_is_the_production_shuffle`].
//!
//! # What is real and what is modelled
//!
//! Real, called directly: [`crate::committees::epoch_committees`],
//! [`crate::finality::votes_from_partition`],
//! [`crate::finality::FinalityState::process_epoch`],
//! [`crate::finality::FinalityState::relaunch`]. Every leak balance in every
//! scenario is accrued by driving real epochs through `process_epoch`; none is
//! hand-stuffed.
//!
//! Modelled, because the production function is private to `transition.rs` and
//! belongs to Dev A: the leak subtraction ([`with_leak_applied_mirror`]) and
//! the slot placement of an attestation. Both are pinned to the production
//! source by [`tests::the_leak_mirror_is_the_production_arithmetic`], which
//! fails if `transition.rs` drifts.

use crate::attestation::AttestationData;
use crate::committees;
use crate::finality::{Checkpoint, FinalityState, votes_from_partition};
use crate::params::SLOTS_PER_EPOCH;
use crate::sample::Validator;
use std::sync::atomic::Ordering::Relaxed;

// ────────────────────────────── the mutation ────────────────────────────────

/// The mutation switch. `#[cfg(test)]` by virtue of the whole module being
/// test-only, exactly like [`crate::params::rehearsal`]: it cannot exist in a
/// shipped binary.
///
/// ON  = the PRE-FIX behaviour: step 8 partitions the leak-applied roster,
///       whose eligible set is shorter, so it shuffles differently.
/// OFF = the contract: membership is a function of the index set alone.
pub mod mutation {
    use std::sync::atomic::AtomicBool;
    /// Restore the pre-shuffle stake filter to step 8's roster.
    pub static PRE_FIX_FILTER: AtomicBool = AtomicBool::new(false);
}

/// Serialises every test that touches the process-global switch. Cargo runs
/// tests in parallel; a process global read by two scenarios at once would
/// make the whole harness report noise.
static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ──────────────────────────── the two partitions ────────────────────────────

/// The partition **step 8 admits attestations against**, under whichever
/// behaviour the mutation switch selects.
///
/// `consensus_roster` is the leak-applied roster — the one
/// `CommittedState::consensus_roster_at` returns once the flag day binds.
pub fn partition_step8(seed: &[u8; 32], epoch: u64, consensus_roster: &[Validator]) -> Vec<Vec<u32>> {
    if mutation::PRE_FIX_FILTER.load(Relaxed) {
        // BROKEN. Dev A's fix HAS landed (2026-08-24): `epoch_committees` no
        // longer contains an `effective_stake > 0` filter at all, so simply
        // calling it on a leak-applied roster no longer reproduces anything.
        // The pre-fix behaviour now has to be asked for, through the switch
        // production actually reads.
        //
        // ── WHY THIS LINE EXISTS (2026-09-01) ───────────────────────────────
        // It used to say only `return committees::epoch_committees(...)`, with
        // the comment "this is not a re-implementation of the broken code, it
        // IS the broken code: today's production function, called on today's
        // production input". That was true when it was written and stopped
        // being true the moment the filter was deleted. From then on BOTH arms
        // of this function computed the identical partition, the mutation was
        // a no-op, and five tests failed while their own messages announced
        // that the analysis was "refuted" — a static reference pointing at code
        // that had moved. See `docs/post-mortems/2026-08-24-finality-divergence.md`.
        let _g = pre_fix_filter_guard();
        return committees::epoch_committees(seed, epoch, consensus_roster);
    }
    // THE CONTRACT, and since 2026-08-24 also the production behaviour. Same
    // production function, stakes normalised so that even if the pre-shuffle
    // filter were restored it could not remove anyone — which is what deleting
    // the filter does. Membership = f(seed, epoch, index set).
    let by_index: Vec<Validator> = consensus_roster
        .iter()
        .map(|v| Validator { index: v.index, effective_stake: 1 })
        .collect();
    committees::epoch_committees(seed, epoch, &by_index)
}

/// Turn the production pre-shuffle filter back on for this thread, and off
/// again when the guard drops — including on an unwind, so a failing assertion
/// inside a scenario cannot leave the consensus rule mutated for the rest of
/// the thread.
///
/// [`crate::params::rehearsal::RESTORE_ZERO_STAKE_FILTER`] is the switch
/// `committees::mutation_restores_zero_stake_filter` reads, and it is
/// thread-local for the reason that module documents at length. `HOOK` still
/// serialises the scenarios because [`mutation::PRE_FIX_FILTER`] itself is a
/// process global.
fn pre_fix_filter_guard() -> impl Drop {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::params::rehearsal::RESTORE_ZERO_STAKE_FILTER.store(false, Relaxed);
        }
    }
    crate::params::rehearsal::RESTORE_ZERO_STAKE_FILTER.store(true, Relaxed);
    Restore
}

/// The partition the **epoch boundary** tallies against. Unconditional: this
/// is `close_epoch`'s call, on the unleaked duty roster, and neither the
/// defect nor the fix changes it. Present so both sides of the comparison are
/// visible in one file.
pub fn partition_boundary(seed: &[u8; 32], epoch: u64, duty_roster: &[Validator]) -> Vec<Vec<u32>> {
    committees::epoch_committees(seed, epoch, duty_roster)
}

/// Mirror of `transition::with_leak_applied` (private to Dev A's file).
/// Pinned to the production source by
/// [`tests::the_leak_mirror_is_the_production_arithmetic`].
pub fn with_leak_applied_mirror(roster: &[Validator], st: &FinalityState) -> Vec<Validator> {
    roster
        .iter()
        .map(|v| Validator {
            index: v.index,
            effective_stake: v.effective_stake.saturating_sub(st.leaked_of(v.index)),
        })
        .collect()
}

// ───────────────────────────────── fixtures ─────────────────────────────────

/// 64 validators — the live fleet size.
const N: u32 = 64;
/// One validator's stake. Round, so printed percentages are readable.
const STAKE: u64 = 1_000_000_000;
const SEED: [u8; 32] = [0x5A; 32];
const G: [u8; 32] = [0xAA; 32];

fn genesis() -> Checkpoint {
    Checkpoint { epoch: 0, root: G }
}

fn root(n: u8) -> [u8; 32] {
    [n; 32]
}

fn duty_roster() -> Vec<Validator> {
    (0..N).map(|index| Validator { index, effective_stake: STAKE }).collect()
}

fn att(v: u32, slot: u64, epoch: u64, target: [u8; 32], src: Checkpoint) -> (u32, AttestationData) {
    (
        v,
        AttestationData {
            slot,
            head: target,
            source_epoch: src.epoch,
            source_root: src.root,
            target_epoch: epoch,
            target_root: target,
        },
    )
}

/// Epochs of unbroken non-finality needed to drain an absent validator to
/// **exactly** zero.
///
/// The bite is `remaining · t / INACTIVITY_LEAK_QUOTIENT` with
/// `t = since_finality − INACTIVITY_LEAK_THRESHOLD_EPOCHS`, so at `t = 64` the
/// bite is the whole remainder. 70 epochs clears it with margin, and
/// [`build_stalled_ledger`] asserts the zero was actually reached rather than
/// assuming this arithmetic.
const STALL_EPOCHS: u64 = 70;

/// Drive a real stall and return the resulting state, plus the set of
/// validators the leak took to exactly zero.
///
/// `live` votes every epoch and is spared; everyone else is absent and bleeds.
/// The live vote is **split across two roots** so no root ever reaches two
/// thirds: the stall does not self-heal, the leak keeps running, and the
/// absent really do reach zero. Nothing here is hand-stuffed — every satoshi
/// of leak in this harness came out of `process_epoch`.
fn build_stalled_ledger(live: &[u32]) -> (FinalityState, Vec<u32>) {
    let roster = duty_roster();
    let mut st = FinalityState::new(genesis());
    for e in 1..=STALL_EPOCHS {
        let src = st.current_justified();
        let atts: Vec<(u32, AttestationData)> = live
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let target = if i % 2 == 0 { root(1) } else { root(2) };
                att(*v, e * SLOTS_PER_EPOCH, e, target, src)
            })
            .collect();
        let out = st
            .process_epoch(&crate::finality::EpochVotes {
                epoch: e,
                active_set: &roster,
                attestations: &atts,
            })
            .expect("dense, in-order epochs");
        assert!(
            out.justified.is_none(),
            "epoch {e} justified; the fixture was supposed to stall, and a healed stall \
             stops the leak before the ledger is full"
        );
    }
    let zeros: Vec<u32> = (0..N).filter(|v| st.leaked_of(*v) >= STAKE).collect();
    assert!(
        !zeros.is_empty(),
        "{STALL_EPOCHS} epochs of stall drained nobody to zero. Only a validator at EXACTLY \
         zero changes the eligible-set LENGTH, so without one there is no defect to measure \
         and every scenario below would pass vacuously."
    );
    (st, zeros)
}

/// One node's view for one epoch: the roster it derives, and the partition
/// step 8 admits against.
struct NodeView {
    step8: Vec<Vec<u32>>,
}

fn view_of(st: &FinalityState, epoch: u64) -> NodeView {
    let duty = duty_roster();
    let consensus = with_leak_applied_mirror(&duty, st);
    NodeView { step8: partition_step8(&SEED, epoch, &consensus) }
}

/// How many validators the leak has taken to exactly zero on this node.
/// The only quantity that changes a partition: a validator merely *reduced*
/// by the leak still holds its seat.
fn zero_count(st: &FinalityState) -> usize {
    (0..N).filter(|v| st.leaked_of(*v) >= STAKE).count()
}

/// The slot a validator attests in, under a given view. `None` for a validator
/// the view gives no seat — which, before the fix, is every validator the leak
/// took to zero.
fn slot_of(view: &NodeView, v: u32, epoch: u64) -> Option<u64> {
    view.step8
        .iter()
        .position(|c| c.binary_search(&v).is_ok())
        .map(|i| epoch * SLOTS_PER_EPOCH + i as u64)
}

/// One epoch on one node, end to end through the production path.
///
/// `stream` is the honest gossip: every validator's single attestation, placed
/// at the slot **its own node's view** assigned. This node admits from that
/// stream whatever matches its own step-8 partition (that is
/// `compute_post_state` step 8), then tallies the survivors at the boundary
/// with the real [`votes_from_partition`] against the unleaked duty roster
/// (that is `close_epoch`), then folds them with the real `process_epoch`.
///
/// Returns `(justified root, attestations admitted, attestations that survived
/// the boundary)`.
fn run_epoch(
    st: &mut FinalityState,
    epoch: u64,
    stream: &[(u32, AttestationData)],
) -> (Option<[u8; 32]>, usize, usize) {
    let view = view_of(st, epoch);
    let duty = duty_roster();

    // ── step 8: admit only attestations in this node's own partition ──
    let admitted: Vec<(u32, AttestationData)> = stream
        .iter()
        .filter(|(v, d)| {
            let idx = (d.slot % SLOTS_PER_EPOCH) as usize;
            view.step8.get(idx).is_some_and(|c| c.binary_search(v).is_ok())
        })
        .copied()
        .collect();

    // ── close_epoch: tally against the UNLEAKED duty roster ──
    let mut accepted = Vec::new();
    let ev = votes_from_partition(epoch, &duty, &duty, &admitted, &SEED, &mut accepted);
    let survived = ev.attestations.len();
    let out = st.process_epoch(&ev).expect("dense, in-order epochs");
    (out.justified.map(|c| c.root), admitted.len(), survived)
}

/// The honest gossip stream for one epoch: all 64 validators vote for the same
/// root, each at the slot its own node assigned it. Validators are split
/// between the two node views — which is what a real network is.
fn honest_stream(
    epoch: u64,
    target: [u8; 32],
    src: Checkpoint,
    left: &NodeView,
    right: &NodeView,
) -> Vec<(u32, AttestationData)> {
    (0..N)
        .filter_map(|v| {
            let view = if v % 2 == 0 { left } else { right };
            slot_of(view, v, epoch).map(|slot| att(v, slot, epoch, target, src))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════════════════ fidelity of the model ══════════════════════════

    /// **The model of the fix is the production shuffle.**
    ///
    /// If every validator has stake, the pre-shuffle filter removes nobody, so
    /// the contract and today's production function must agree *bit for bit*.
    /// This is what makes [`partition_step8`] a model of the fix rather than a
    /// convenient invention — and it is also scenario 3's core claim: on a
    /// healthy network the fix is a no-op.
    #[test]
    fn the_model_of_the_fix_is_the_production_shuffle() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        mutation::PRE_FIX_FILTER.store(false, Relaxed);
        let healthy = duty_roster();
        for epoch in 0..8u64 {
            assert_eq!(
                partition_step8(&SEED, epoch, &healthy),
                committees::epoch_committees(&SEED, epoch, &healthy),
                "epoch {epoch}: the contract and production disagree on a roster with no \
                 zero stake. Then the model is not the production shuffle and nothing \
                 below measures the real function."
            );
        }
        println!("FIDELITY: on a healthy roster the contract IS the production partition, 8/8 epochs");
    }

    /// The leak arithmetic this file mirrors is still the arithmetic
    /// `transition.rs` ships. Source-level, because a mirror that silently
    /// drifts from its original is worse than no mirror.
    #[test]
    fn the_leak_mirror_is_the_production_arithmetic() {
        let src = include_str!("transition.rs");
        assert!(
            src.contains("effective_stake: v.effective_stake.saturating_sub(leaked_of(v.index))"),
            "`with_leak_applied` changed shape; `with_leak_applied_mirror` in prova.rs must be \
             re-derived before any scenario in this file is believed"
        );
        assert!(
            src.contains("if epoch < crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH"),
            "the flag-day gate moved; this harness models the POST-flag-day roster and its \
             relevance depends on that gate still being the thing that arms it"
        );
    }

    // ════════════ SCENARIO 0 — the 2026-08-24 incident, reproduced ═══════════

    /// The three partitions of the incident, and how many epochs they are
    /// driven for. 4-of-64 is the size recorded in
    /// [`crate::params::MIN_QUORUM_DENOMINATOR_NUM`]'s docs ("The 2026-08-24
    /// partitions were 4 of 64"); 120 epochs is the horizon
    /// `finality::tests::run_partition_inner` uses for the same scenario.
    const INCIDENT_PARTITIONS: [&[u32]; 3] = [&[0, 1, 2, 3], &[4, 5, 6, 7], &[8, 9, 10, 11]];
    const INCIDENT_HORIZON: u64 = 120;

    /// A root that is a function of (partition, epoch), so two partitions
    /// never accidentally agree and every epoch has its own checkpoint — which
    /// is what lets consecutive justification finalize.
    fn incident_root(tag: u8, epoch: u64) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = 0xE0 | tag;
        r[1..9].copy_from_slice(&epoch.to_le_bytes());
        r
    }

    /// Drive ONE node that can hear only `heard`, for `INCIDENT_HORIZON`
    /// epochs, and report the first epoch it FINALIZED and what it finalized.
    ///
    /// The node's registry is the full 64-validator roster — every node had
    /// the same registry; that is not what the partition changed. What the
    /// partition changed is the attestation set that reached it. Everything
    /// here goes through the real [`FinalityState::process_epoch`]; no leak
    /// balance and no denominator is hand-stuffed.
    fn drive_partitioned_node(heard: &[u32], tag: u8) -> (Option<u64>, Option<Checkpoint>, f64) {
        let roster = duty_roster();
        let mut st = FinalityState::new(genesis());
        for e in 1..=INCIDENT_HORIZON {
            let src = st.current_justified();
            let target = incident_root(tag, e);
            let atts: Vec<(u32, AttestationData)> = heard
                .iter()
                .map(|v| att(*v, e * SLOTS_PER_EPOCH, e, target, src))
                .collect();
            let out = st
                .process_epoch(&crate::finality::EpochVotes {
                    epoch: e,
                    active_set: &roster,
                    attestations: &atts,
                })
                .expect("dense, in-order epochs");
            if let Some(cp) = out.finalized {
                let destroyed: u128 = (0..N).map(|v| st.leaked_of(v) as u128).sum();
                let total = N as u128 * STAKE as u128;
                return (Some(e), Some(cp), destroyed as f64 / total as f64 * 100.0);
            }
        }
        (None, None, 0.0)
    }

    /// **THE INCIDENT: three nodes finalize the same epoch on three different
    /// roots — with no bug in the finality code and no disagreement about any
    /// rule.**
    ///
    /// This is the scenario the rest of this file was believed to explain and
    /// does not. The mechanism is not the committee partition; it is the
    /// **quorum denominator**. `process_epoch` measures the two-thirds test
    /// against the LEAK-ADJUSTED total. A node that can hear only four of the
    /// sixty-four counts the other sixty as absent, absent stake leaks, and the
    /// leak is subtracted from the very total the quorum is measured against.
    /// The denominator walks down until it fits inside the minority the node
    /// can still hear, and that minority justifies — then finalizes — its own
    /// branch. Three disjoint partitions do this three times, independently, at
    /// the same epoch, on three different roots.
    ///
    /// Nothing in this test touches a mutation switch. **It runs the arithmetic
    /// a shipped binary runs today**, because
    /// [`crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH`] is `u64::MAX`, so
    /// `process_epoch` takes the unfloored `leak_adjusted` branch on every
    /// epoch a real chain can reach. The floor and the leak recovery that
    /// landed on 2026-08-25 are correct and are NOT in force. That is the
    /// finding, and it is why this test is not decorated as a historical
    /// curiosity: it is a description of the code the fleet is running.
    ///
    /// The companion below shows the floor stops it, so this is not a test
    /// that merely cannot fail.
    #[test]
    fn s0_three_partitions_finalize_three_different_roots_at_the_same_epoch() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());

        let outcomes: Vec<(Option<u64>, Option<Checkpoint>, f64)> = INCIDENT_PARTITIONS
            .iter()
            .enumerate()
            .map(|(i, heard)| drive_partitioned_node(heard, i as u8))
            .collect();

        let mut finalized = Vec::new();
        for (i, (epoch, cp, destroyed)) in outcomes.iter().enumerate() {
            let epoch = epoch.unwrap_or_else(|| {
                panic!(
                    "partition {i} ({:?}) never finalized in {INCIDENT_HORIZON} epochs. Then \
                     the leak-adjusted denominator is not the mechanism of the 2026-08-24 \
                     divergence and this account is wrong.",
                    INCIDENT_PARTITIONS[i]
                )
            });
            finalized.push((epoch, cp.expect("finalized epoch carries a checkpoint"), *destroyed));
        }

        // All three at the SAME epoch. The partitions are the same size and
        // see the same schedule, so anything else would mean the outcome
        // depends on something other than the denominator.
        let e0 = finalized[0].0;
        for (i, (e, _, _)) in finalized.iter().enumerate() {
            assert_eq!(
                *e, e0,
                "partition {i} finalized at epoch {e}, partition 0 at {e0}. Three symmetric \
                 partitions must reach the false quorum together, or the mechanism is not \
                 the one this test names."
            );
        }

        // Three DIFFERENT roots. This is the safety violation.
        let roots: Vec<[u8; 32]> = finalized.iter().map(|(_, cp, _)| cp.root).collect();
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "partitions {i} and {j} finalized the same root; then this fixture is \
                     not reproducing a divergence at all"
                );
            }
        }
        // ...and all three are checkpoints for one and the same epoch.
        let ce = finalized[0].1.epoch;
        for (i, (_, cp, _)) in finalized.iter().enumerate() {
            assert_eq!(
                cp.epoch, ce,
                "partition {i} finalized checkpoint epoch {}, partition 0 finalized {ce}. \
                 The incident is three roots for ONE epoch; different epochs would be a \
                 different, and much less serious, fact.",
                cp.epoch
            );
        }

        // The quorum was false: 4 of 64 is 6.25%, nowhere near two thirds of
        // an intact denominator. If it justified before the leak threshold it
        // did so without the leak, and the mechanism is not what is claimed.
        assert!(
            e0 > crate::params::INACTIVITY_LEAK_THRESHOLD_EPOCHS,
            "a partition finalized at epoch {e0}, at or before the leak threshold — 4/64 \
             cannot reach 2/3 of an unshrunken denominator, so the fixture is wrong"
        );

        println!(
            "INCIDENT (s0): 3 disjoint partitions of 4 of 64 validators (6.25% each) EACH \
             finalized checkpoint epoch {ce} at epoch {e0}, on 3 DIFFERENT roots \
             ({:02x?}, {:02x?}, {:02x?}), after the leak destroyed {:.1}% of network stake. \
             No mutation switch was touched: this is the arithmetic a shipped binary runs, \
             because LEAK_RECOVERY_ACTIVATION_EPOCH is u64::MAX.",
            &roots[0][..2],
            &roots[1][..2],
            &roots[2][..2],
            finalized[0].2
        );
    }

    /// **The cure, and the proof that scenario 0 can be stopped.**
    ///
    /// A test that reproduces a failure is worth nothing unless something makes
    /// it stop. Open the two flag-day gates
    /// ([`crate::params::rehearsal::gates_open_guard`], `cfg(test)`) so the
    /// denominator floor and the leak recovery are in force, and run the
    /// IDENTICAL three partitions. None of them may finalize, ever: with the
    /// floor at one half, a set must hold at least a third of the original
    /// stake to be rescued by the leak, and 6.25% is not a third.
    ///
    /// This is also the exact measurement of what arming
    /// [`crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH`] would buy. Arming it
    /// is the founder's decision and is NOT taken here.
    #[test]
    fn s0_cure_the_denominator_floor_stops_all_three_partitions() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let _gates = crate::params::rehearsal::gates_open_guard();

        for (i, heard) in INCIDENT_PARTITIONS.iter().enumerate() {
            let (epoch, cp, _) = drive_partitioned_node(heard, i as u8);
            assert_eq!(
                epoch, None,
                "MUTATION DID NOT BITE: with the denominator floor in force, partition {i} \
                 ({heard:?}) still finalized {cp:?} at epoch {epoch:?}. Either the gate is \
                 not wired or scenario 0 was passing for some other reason."
            );
        }
        println!(
            "CURE (s0): with the floor at {}/{} of the unleaked total in force, all 3 \
             partitions of 4 of 64 failed to finalize in {INCIDENT_HORIZON} epochs. The \
             floor is GATED INERT in production (LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX); \
             arming it is the founder's decision.",
            crate::params::MIN_QUORUM_DENOMINATOR_NUM,
            crate::params::MIN_QUORUM_DENOMINATOR_DEN
        );
    }

    /// **The ratchet is live: the shipped default IS the incident arithmetic.**
    ///
    /// Scenario 0 above proves it behaviourally. This states it as a fact about
    /// the constant, so that the day somebody arms the flag day, exactly one
    /// test tells them that scenario 0 has changed meaning.
    ///
    /// It does NOT assert that the gate should be armed. It asserts that while
    /// it reads `u64::MAX`, no epoch any chain can reach takes the floored
    /// branch — which is the difference between "the fix landed" and "the fix
    /// is in force", and the difference the audit could not settle.
    #[test]
    fn the_quorum_floor_is_shipped_but_not_in_force() {
        assert_eq!(
            crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH,
            u64::MAX,
            "LEAK_RECOVERY_ACTIVATION_EPOCH has been armed. The denominator floor and the \
             leak recovery are now in force from that epoch, so \
             `s0_three_partitions_finalize_three_different_roots_at_the_same_epoch` no \
             longer describes what a shipped binary does after it. Re-read both scenario 0 \
             tests, and re-read the settlement guarantee in \
             docs/post-mortems/2026-08-24-finality-divergence.md before telling an \
             integrator anything about finality."
        );
        println!(
            "RATCHET: LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX. The floor \
             ({}/{}) and the leak recovery are compiled in and UNREACHABLE; every epoch a \
             real chain can reach takes the unfloored, leak-adjusted denominator — the \
             arithmetic of 2026-08-24.",
            crate::params::MIN_QUORUM_DENOMINATOR_NUM,
            crate::params::MIN_QUORUM_DENOMINATOR_DEN
        );
    }

    // ═══════════════════ SCENARIO 1 — the disease reproduced ═════════════════

    /// **Two nodes, different leak ledgers, and a chain that stops finalizing
    /// for good.**
    ///
    /// Both nodes replay a real stall, but they heard different attestation
    /// subsets — the 2026-08-09 gossip-queue drop, which is why the incident
    /// happened at all. Their ledgers therefore take different validators to
    /// zero. Under the pre-fix filter, a different ZERO-SET means a different
    /// eligible-set LENGTH-and-content, hence a different Fisher-Yates
    /// permutation, hence they admit different attestations from the same
    /// honest gossip and tally different quorums.
    ///
    /// The sharp form of the finding: **two nodes diverge if and only if their
    /// sets of fully-leaked validators differ.** A validator merely *reduced*
    /// by the leak changes no partition; a validator at exactly zero changes
    /// every one of them.
    ///
    /// **And it does not come back.** Not in the way this test first claimed:
    /// its original assertion was that the two ledgers drift further apart
    /// forever, and the harness refuted that on the first run (gap
    /// `2000000000 -> 0`). The leak floors at zero, so a deep enough stall
    /// pins every absent validator on both nodes at exactly zero and the two
    /// ledgers become identical again — they reconverge by destroying
    /// everything they disagreed about.
    ///
    /// What does not come back is the chain. No finality means more leak, more
    /// leak means more validators at zero, none ever returns, and the
    /// leak-adjusted denominator walks to zero — at which point no quorum is
    /// reachable on any input. The correction is recorded here rather than
    /// quietly edited away, because the wrong version of this assertion would
    /// have passed a relaunch on a claim the code does not support.
    #[test]
    fn s1_disease_two_nodes_diverge_and_the_chain_never_finalizes_again() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        mutation::PRE_FIX_FILTER.store(true, Relaxed); // the CURRENT behaviour
        let r = drive_two_nodes();
        mutation::PRE_FIX_FILTER.store(false, Relaxed);

        assert_ne!(
            r.zeros_left, r.zeros_right,
            "the two nodes ended the stall with identical zero-sets; then there is nothing \
             for the length-dependent shuffle to disagree about and this scenario is vacuous"
        );
        assert_ne!(
            r.step8_left, r.step8_right,
            "different zero-sets produced the SAME step-8 partition — the length-dependent \
             shuffle is not the mechanism and this analysis is wrong"
        );
        assert!(
            r.agreed_epochs == 0,
            "the two nodes agreed on a justified root in {} of {} epochs; under the pre-fix \
             filter they must never agree",
            r.agreed_epochs,
            r.epochs
        );
        assert!(
            r.left_justified == 0 && r.right_justified == 0,
            "a node justified anyway (L={}, R={}) — with 100% honest participation the \
             boundary was supposed to drop the votes",
            r.left_justified,
            r.right_justified
        );
        // THE RATCHET. Measured, and NOT the quantity this test first asserted.
        //
        // The first version of this test asserted that the two nodes' leak
        // LEDGERS drift further apart forever. That is false, and the harness
        // said so on the first run: `gap 2000000000 -> 0`. The leak has a
        // floor at zero, so once a stall is deep enough every absent validator
        // on both nodes is pinned at exactly zero and the two ledgers become
        // IDENTICAL again. The ledgers reconverge — by destroying everything
        // they disagreed about.
        //
        // What does not come back is the CHAIN. Each epoch of non-finality
        // takes more validators to zero, none ever returns (there is no decay
        // and no reset), and once the zero-set reaches the whole fleet the
        // leak-adjusted denominator is zero and no quorum is reachable on any
        // input, forever. That is the absorbing state, and it is what "does
        // not come back" has to mean.
        assert!(
            r.zeros_end > r.zeros_start,
            "the zero-set did not grow ({} -> {}); then non-finality is not consuming the \
             fleet and the absorbing state is unproven",
            r.zeros_start,
            r.zeros_end
        );
        // How much of the fleet the stall has eaten. Reported rather than
        // pinned to an exact count: a validator whose vote happens to survive
        // the mismatched partition is spared that epoch, so the exact terminal
        // count is a property of the shuffle, not of the finding.
        assert!(
            r.destroyed_end * 10 > (N as u128 * STAKE as u128) * 9,
            "the stall destroyed only {} of {} satoshis; the fleet is not being consumed \
             and the absorbing state is unproven",
            r.destroyed_end,
            N as u128 * STAKE as u128
        );
        println!(
            "DISEASE: 2 nodes, zero-sets differing by {} validators, {} epochs of 100% honest \
             participation. Justified: L={} R={}, AGREED on {}. Boundary kept {:.1}% of \
             admitted votes. Fully-leaked validators {} -> {} of {}; {} satoshis destroyed \
             ({:.0}% of the fleet). The denominator is now ZERO: no quorum is reachable on \
             any input, and nothing gives the stake back.",
            r.zero_set_symmetric_difference,
            r.epochs,
            r.left_justified,
            r.right_justified,
            r.agreed_epochs,
            r.survival_pct,
            r.zeros_start,
            r.zeros_end,
            N,
            r.destroyed_end,
            r.destroyed_end as f64 / (N as u128 * STAKE as u128) as f64 * 100.0
        );
        println!(
            "DISEASE (correction): the two leak LEDGERS reconverged, gap {} -> {}. They agree \
             again because every validator they disagreed about is pinned at zero. Ledger \
             convergence here is the symptom of total loss, not recovery.",
            r.gap_start, r.gap_end
        );
    }

    // ═════════════════════════ SCENARIO 2 — the cure ═════════════════════════

    /// **The same two nodes, the same divergent ledgers, convergence.**
    ///
    /// Nothing about the starting state changes — the ledgers are built by the
    /// identical fixture, from the identical stall. Only the partition rule
    /// changes. Under the contract, membership does not read stake, so two
    /// nodes whose ledgers disagree still derive the *same* partition, admit
    /// the same attestations, and justify the same root.
    #[test]
    fn s2_cure_the_same_divergent_nodes_converge_from_the_same_state() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        mutation::PRE_FIX_FILTER.store(false, Relaxed); // the contract
        let r = drive_two_nodes();

        assert_ne!(
            r.zeros_left, r.zeros_right,
            "the fixture stopped producing divergent ledgers; the cure would then be \
             proven against a state that never had the disease"
        );
        assert_eq!(
            r.step8_left, r.step8_right,
            "two nodes with different leak ledgers derived DIFFERENT partitions under the \
             contract. Membership is still reading stake; the fix is not leak-invariant."
        );
        assert_eq!(
            r.agreed_epochs, r.epochs,
            "the nodes agreed on only {} of {} epochs",
            r.agreed_epochs, r.epochs
        );
        assert!(
            r.left_justified == r.epochs && r.right_justified == r.epochs,
            "100% honest participation did not justify every epoch (L={}, R={} of {})",
            r.left_justified,
            r.right_justified,
            r.epochs
        );
        assert_eq!(
            r.survival_pct, 100.0,
            "the boundary dropped honest votes ({:.1}% survived) even under the contract",
            r.survival_pct
        );
        assert_eq!(
            r.gap_end, r.gap_start,
            "finality resumed but the leak gap still moved, {} -> {}",
            r.gap_start, r.gap_end
        );
        // The counterpart of scenario 1's absorbing state: under the contract
        // the fleet stops being consumed. Not one further validator is taken
        // to zero, because finality resumed on the first epoch.
        assert_eq!(
            r.zeros_end, r.zeros_start,
            "the cure restored finality but still took {} more validators to zero",
            r.zeros_end - r.zeros_start
        );
        assert!(
            r.zeros_end < N as usize,
            "the whole fleet is at zero even under the contract; the cure recovered nothing"
        );
        println!(
            "CURE: the SAME two divergent ledgers (zero-sets differing by {} validators) \
             now derive an IDENTICAL partition, keep {:.1}% of admitted votes, and justify \
             the same root in {}/{} epochs. Fully-leaked validators froze at {} of {} \
             (scenario 1 reached {}). The leak gap froze at {}.",
            r.zero_set_symmetric_difference,
            r.survival_pct,
            r.agreed_epochs,
            r.epochs,
            r.zeros_end,
            N,
            N,
            r.gap_end
        );
    }

    /// **The mutation for scenario 2.** Restore the pre-shuffle filter and the
    /// cure must fail. This is the same switch scenario 1 turns on
    /// deliberately: scenario 1 *is* scenario 2's mutation, which is why it is
    /// stated as its own scenario and asserted here as a negative.
    #[test]
    fn s2_mutation_restoring_the_pre_fix_filter_breaks_the_cure() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        mutation::PRE_FIX_FILTER.store(true, Relaxed);
        let r = drive_two_nodes();
        mutation::PRE_FIX_FILTER.store(false, Relaxed);
        assert_ne!(
            r.step8_left, r.step8_right,
            "MUTATION DID NOT BITE: with the pre-shuffle filter restored the two nodes still \
             derived the same partition. Either the switch is not wired or the cure was \
             passing for some other reason."
        );
        assert_eq!(
            r.agreed_epochs, 0,
            "MUTATION DID NOT BITE: the nodes still agreed on {} of {} epochs with the \
             filter restored",
            r.agreed_epochs,
            r.epochs
        );
        println!(
            "MUTATION (s2): filter restored -> partitions differ, {}/{} epochs agreed, \
             {:.1}% of votes survived the boundary",
            r.agreed_epochs, r.epochs, r.survival_pct
        );
    }

    // ═══════════════ SCENARIO 3 — healthy network is untouched ═══════════════

    /// **On a healthy network the fix is a no-op, epoch for epoch.**
    ///
    /// This is the regression that protects the relaunch: 64 validators, no
    /// leak, nobody at zero. Every partition, every admitted set, every
    /// justified root and every leak ledger must be identical under the
    /// current code and under the contract.
    #[test]
    fn s3_healthy_network_is_identical_under_the_fix() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let (a, fields_a) = healthy_run(true); // pre-fix
        let (b, fields_b) = healthy_run(false); // contract
        assert_eq!(fields_a, fields_b);
        assert!(fields_a > 0, "the comparator compared nothing");
        assert_eq!(
            a, b,
            "the fix changed a healthy chain. It must be a no-op where nobody is at zero \
             stake, or the relaunch is a hard fork nobody planned."
        );
        println!(
            "HEALTHY NO-OP: {} fields over {} epochs identical under the pre-fix filter and \
             under the contract",
            fields_a,
            HEALTHY_EPOCHS
        );
    }

    /// **The comparator's tripwire.** A comparator that cannot go red is not
    /// comparing anything — this suite has already been found passing empty
    /// once. Plant the defect's own precondition (one validator at exactly
    /// zero stake) and require the same comparison to break.
    ///
    /// This is deliberately the *cheap* tripwire. The chain-level one already
    /// exists and is stronger: `transition.rs`'s
    /// `the_comparator_bites_a_planted_difference` runs the real `build_block`
    /// / `apply_block` / `close_epoch` driver and flips one bit of every seed
    /// through [`crate::params::rehearsal::MUTATE_SEED`].
    /// `scripts/prova-relanca.sh` runs both.
    #[test]
    fn s3_mutation_the_comparator_bites_one_zero_stake_validator() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let mut planted = duty_roster();
        planted[7].effective_stake = 0;
        let mut differences = 0usize;
        for epoch in 0..HEALTHY_EPOCHS {
            mutation::PRE_FIX_FILTER.store(true, Relaxed);
            let pre = partition_step8(&SEED, epoch, &planted);
            mutation::PRE_FIX_FILTER.store(false, Relaxed);
            let post = partition_step8(&SEED, epoch, &planted);
            if pre != post {
                differences += 1;
            }
        }
        assert_eq!(
            differences, HEALTHY_EPOCHS as usize,
            "the comparator saw a difference in only {differences} of {HEALTHY_EPOCHS} epochs \
             after planting a zero-stake validator; it is blind to the defect it exists to catch"
        );
        println!(
            "MUTATION (s3): one validator at zero stake changes the partition in \
             {differences}/{HEALTHY_EPOCHS} epochs — the comparator sees the defect"
        );
    }

    // ═══════════ SCENARIO 4 — a state that already carries a leak ════════════

    /// **With an accrued leak balance on the books.**
    ///
    /// A clean devnet cannot prove this, because a clean devnet has no leak.
    /// The starting state here is built by driving [`STALL_EPOCHS`] real
    /// epochs of non-finality through `process_epoch`, so the ledger is
    /// genuine: 30 validators at exactly zero, 34 intact.
    ///
    /// Three things are asserted, in the order they matter:
    ///
    /// 1. **Pre-fix, the quorum denominator is unreachable.** Every surviving
    ///    validator votes honestly for one root and the boundary still refuses
    ///    to justify, because the votes were placed in the wrong partition.
    /// 2. **Post-fix, it is exactly the live stake.** The same ledger, the
    ///    same votes: the denominator is the leak-adjusted total, the
    ///    numerator is all of it, and it justifies.
    /// 3. **After the relaunch reset, it is the full fleet.** The ledger is
    ///    empty, so the denominator returns to 64 x STAKE — the number a
    ///    relaunched chain must price its quorum against, and the number it
    ///    would NOT have got had the balance been inherited.
    #[test]
    fn s4_accrued_leak_plus_the_reset_restore_the_quorum_denominator() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let live: Vec<u32> = (0..34).collect();
        let (stalled, zeros) = build_stalled_ledger(&live);
        let duty = duty_roster();
        let leaked_roster = with_leak_applied_mirror(&duty, &stalled);
        let alive = (N as usize) - zeros.len();
        assert_eq!(zeros.len(), 30, "fixture drift: expected 30 validators drained to zero");

        // The denominator process_epoch will use, from the real ledger.
        let denom_carried: u128 =
            duty.iter().map(|v| v.effective_stake.saturating_sub(stalled.leaked_of(v.index)) as u128).sum();
        assert_eq!(
            denom_carried,
            alive as u128 * STAKE as u128,
            "the carried denominator is not the live stake; the fixture is not what it claims"
        );

        // (1) pre-fix.
        mutation::PRE_FIX_FILTER.store(true, Relaxed);
        let broken = one_epoch_from(&stalled, &leaked_roster);
        // (2) post-fix, from the IDENTICAL state.
        mutation::PRE_FIX_FILTER.store(false, Relaxed);
        let fixed = one_epoch_from(&stalled, &leaked_roster);

        assert_eq!(
            broken.justified, None,
            "pre-fix, {alive} honest validators holding 100% of live stake justified anyway \
             — then the roster split does not block finality and this finding is refuted"
        );
        assert_eq!(
            fixed.justified,
            Some(root(9)),
            "post-fix, {alive} validators holding 100% of the {denom_carried}-satoshi \
             denominator did NOT justify (survived {} of {} votes)",
            fixed.survived,
            fixed.admitted
        );
        assert_eq!(
            fixed.survived, fixed.admitted,
            "post-fix the boundary still dropped {} of {} honest votes",
            fixed.admitted - fixed.survived,
            fixed.admitted
        );

        // (3) the relaunch reset.
        let relaunched = FinalityState::relaunch(genesis());
        assert_eq!(relaunched.leaked_total(), 0);
        let denom_relaunched: u128 = duty
            .iter()
            .map(|v| v.effective_stake.saturating_sub(relaunched.leaked_of(v.index)) as u128)
            .sum();
        assert_eq!(
            denom_relaunched,
            N as u128 * STAKE as u128,
            "the relaunched chain did not price its quorum against the full fleet"
        );
        assert!(
            denom_relaunched > denom_carried,
            "the reset did not change the denominator; then the fixture never carried a leak"
        );
        println!(
            "ACCRUED LEAK: ledger holds {} satoshis across {} fully-leaked validators. \
             Pre-fix: {}/{} votes survived, justified=NONE. Post-fix: {}/{} survived, \
             JUSTIFIED against a denominator of {} ({} live validators). After the relaunch \
             reset the denominator is {} ({} validators) — {:.1}% more quorum weight than \
             an inherited ledger would have allowed.",
            stalled.leaked_total(),
            zeros.len(),
            broken.survived,
            broken.admitted,
            fixed.survived,
            fixed.admitted,
            denom_carried,
            alive,
            denom_relaunched,
            N,
            (denom_relaunched as f64 / denom_carried as f64 - 1.0) * 100.0
        );
    }

    /// **The mutation for scenario 4.** With the filter restored, the accrued
    /// ledger must once again destroy the quorum.
    #[test]
    fn s4_mutation_the_pre_fix_filter_destroys_the_quorum_again() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let live: Vec<u32> = (0..34).collect();
        let (stalled, _) = build_stalled_ledger(&live);
        let leaked_roster = with_leak_applied_mirror(&duty_roster(), &stalled);
        mutation::PRE_FIX_FILTER.store(true, Relaxed);
        let r = one_epoch_from(&stalled, &leaked_roster);
        mutation::PRE_FIX_FILTER.store(false, Relaxed);
        assert_eq!(
            r.justified, None,
            "MUTATION DID NOT BITE: with the pre-shuffle filter restored, an accrued ledger \
             still justified. Scenario 4 is then passing for some other reason."
        );
        assert!(
            r.survived * 3 < r.admitted,
            "MUTATION DID NOT BITE: the boundary still kept {} of {} votes",
            r.survived,
            r.admitted
        );
        println!(
            "MUTATION (s4): filter restored -> boundary kept {} of {} honest votes, \
             justified=NONE",
            r.survived, r.admitted
        );
    }

    // ══════════════════ LANDED — the contract, on production ═════════════════

    /// **The contract, asserted of the production function directly.**
    ///
    /// Everything above measures the contract through [`partition_step8`].
    /// This one asserts it of the *production* function: with one validator at
    /// zero stake, `epoch_committees` must still partition the full index set.
    ///
    /// It was `#[ignore]`d as `pending_dev_a_…` on the grounds that it was
    /// "RED on this branch by construction — the filter is still there".
    /// **The filter is not still there.** It was removed from
    /// `committees::epoch_committees` on 2026-08-24 and survives only behind
    /// `params::rehearsal::RESTORE_ZERO_STAKE_FILTER`, a `cfg(test)`
    /// thread-local. The `#[ignore]` outlived its reason by a week, and while
    /// it stood, the one assertion that could have detected that the rest of
    /// this file had gone stale was the one assertion never run.
    #[test]
    fn production_membership_is_leak_invariant() {
        let healthy = duty_roster();
        let mut leaked = healthy.clone();
        leaked[7].effective_stake = 0;
        for epoch in 0..4u64 {
            assert_eq!(
                committees::epoch_committees(&SEED, epoch, &leaked),
                committees::epoch_committees(&SEED, epoch, &healthy),
                "epoch {epoch}: committee membership still moves when one validator's stake \
                 goes to zero. Membership must be a function of (seed, epoch, index set)."
            );
        }
    }

    // ───────────────────────────── the drivers ──────────────────────────────

    /// Epochs of honest participation after the stall.
    const DIVERGENCE_EPOCHS: u64 = 6;
    /// Epochs compared by the healthy-network regression.
    const HEALTHY_EPOCHS: u64 = 8;

    struct TwoNodes {
        epochs: u64,
        agreed_epochs: u64,
        left_justified: u64,
        right_justified: u64,
        zeros_left: Vec<u32>,
        zeros_right: Vec<u32>,
        zero_set_symmetric_difference: usize,
        step8_left: Vec<Vec<u32>>,
        step8_right: Vec<Vec<u32>>,
        survival_pct: f64,
        gap_start: u128,
        gap_end: u128,
        zeros_start: usize,
        zeros_end: usize,
        destroyed_end: u128,
    }

    /// Build two nodes whose ledgers diverged during one stall, then give them
    /// [`DIVERGENCE_EPOCHS`] of perfect honest participation and see whether
    /// they come back.
    ///
    /// The two ledgers differ exactly the way the 2026-08-09 flood made them
    /// differ: each node heard one validator the other did not.
    fn drive_two_nodes() -> TwoNodes {
        // Node L heard validator 62; node R heard 63 instead.
        let live_l: Vec<u32> = (0..33).chain(std::iter::once(62)).collect();
        let live_r: Vec<u32> = (0..33).chain(std::iter::once(63)).collect();
        let (mut st_l, zeros_left) = build_stalled_ledger(&live_l);
        let (mut st_r, zeros_right) = build_stalled_ledger(&live_r);

        let gap_start = leak_gap(&st_l, &st_r);
        let zeros_start = zero_count(&st_l);
        let first = STALL_EPOCHS + 1;
        let view_l = view_of(&st_l, first);
        let view_r = view_of(&st_r, first);
        let step8_left = view_l.step8.clone();
        let step8_right = view_r.step8.clone();

        let (mut agreed, mut lj, mut rj) = (0u64, 0u64, 0u64);
        let (mut admitted_total, mut survived_total) = (0usize, 0usize);
        for e in first..first + DIVERGENCE_EPOCHS {
            let target = root((e % 200) as u8 + 20);
            // Each node's own view places its own validators' attestations.
            let vl = view_of(&st_l, e);
            let vr = view_of(&st_r, e);
            // The source must be each node's own highest justified checkpoint;
            // a vote linking from anything else is not a valid vote.
            let stream_l = honest_stream(e, target, st_l.current_justified(), &vl, &vr);
            let stream_r = honest_stream(e, target, st_r.current_justified(), &vl, &vr);
            let (jl, al, sl) = run_epoch(&mut st_l, e, &stream_l);
            let (jr, ar, sr) = run_epoch(&mut st_r, e, &stream_r);
            admitted_total += al + ar;
            survived_total += sl + sr;
            if jl.is_some() {
                lj += 1;
            }
            if jr.is_some() {
                rj += 1;
            }
            if jl.is_some() && jl == jr {
                agreed += 1;
            }
        }

        let sym: std::collections::BTreeSet<u32> = zeros_left
            .iter()
            .chain(zeros_right.iter())
            .filter(|v| !(zeros_left.contains(v) && zeros_right.contains(v)))
            .copied()
            .collect();

        TwoNodes {
            epochs: DIVERGENCE_EPOCHS,
            agreed_epochs: agreed,
            left_justified: lj,
            right_justified: rj,
            zeros_left,
            zeros_right,
            zero_set_symmetric_difference: sym.len(),
            step8_left,
            step8_right,
            survival_pct: if admitted_total == 0 {
                0.0
            } else {
                survived_total as f64 / admitted_total as f64 * 100.0
            },
            gap_start,
            gap_end: leak_gap(&st_l, &st_r),
            zeros_start,
            zeros_end: zero_count(&st_l),
            destroyed_end: st_l.leaked_total(),
        }
    }

    fn leak_gap(a: &FinalityState, b: &FinalityState) -> u128 {
        (0..N)
            .map(|v| {
                let (x, y) = (a.leaked_of(v) as i128, b.leaked_of(v) as i128);
                (x - y).unsigned_abs()
            })
            .sum()
    }

    struct OneEpoch {
        justified: Option<[u8; 32]>,
        admitted: usize,
        survived: usize,
    }

    /// One epoch driven from a given state, with every validator that holds a
    /// step-8 seat voting honestly for the same root.
    fn one_epoch_from(base: &FinalityState, leaked_roster: &[Validator]) -> OneEpoch {
        let mut st = base.clone();
        let epoch = st.next_epoch();
        let duty = duty_roster();
        let step8 = partition_step8(&SEED, epoch, leaked_roster);
        let src = st.current_justified();
        let target = root(9);

        let stream: Vec<(u32, AttestationData)> = step8
            .iter()
            .enumerate()
            .flat_map(|(i, members)| {
                members.iter().map(move |v| {
                    att(*v, epoch * SLOTS_PER_EPOCH + i as u64, epoch, target, src)
                })
            })
            .collect();

        let mut accepted = Vec::new();
        let ev = votes_from_partition(epoch, &duty, &duty, &stream, &SEED, &mut accepted);
        let survived = ev.attestations.len();
        let out = st.process_epoch(&ev).expect("dense, in-order epochs");
        OneEpoch { justified: out.justified.map(|c| c.root), admitted: stream.len(), survived }
    }

    /// Everything one node believed for one epoch on a healthy network.
    /// Compared as a struct so "every field is compared" is true by
    /// construction rather than by a checklist.
    #[derive(PartialEq, Eq, Debug)]
    struct HealthyRecord {
        epoch: u64,
        step8: Vec<Vec<u32>>,
        boundary: Vec<Vec<u32>>,
        justified: Option<[u8; 32]>,
        admitted: usize,
        survived: usize,
        leaked_total: u128,
    }

    /// Drive a healthy chain — 64 validators, nobody at zero — and record it.
    /// Returns the records and the number of fields compared.
    fn healthy_run(pre_fix: bool) -> (Vec<HealthyRecord>, usize) {
        mutation::PRE_FIX_FILTER.store(pre_fix, Relaxed);
        let duty = duty_roster();
        let mut st = FinalityState::new(genesis());
        let mut out = Vec::new();
        for epoch in 1..=HEALTHY_EPOCHS {
            let leaked_roster = with_leak_applied_mirror(&duty, &st);
            let step8 = partition_step8(&SEED, epoch, &leaked_roster);
            let boundary = partition_boundary(&SEED, epoch, &duty);
            let src = st.current_justified();
            let target = root(epoch as u8);
            let stream: Vec<(u32, AttestationData)> = step8
                .iter()
                .enumerate()
                .flat_map(|(i, members)| {
                    members.iter().map(move |v| {
                        att(*v, epoch * SLOTS_PER_EPOCH + i as u64, epoch, target, src)
                    })
                })
                .collect();
            let mut accepted = Vec::new();
            let ev = votes_from_partition(epoch, &duty, &duty, &stream, &SEED, &mut accepted);
            let survived = ev.attestations.len();
            let res = st.process_epoch(&ev).expect("dense, in-order epochs");
            out.push(HealthyRecord {
                epoch,
                step8,
                boundary,
                justified: res.justified.map(|c| c.root),
                admitted: stream.len(),
                survived,
                leaked_total: st.leaked_total(),
            });
        }
        mutation::PRE_FIX_FILTER.store(false, Relaxed);
        let fields = out.len() * 7;
        (out, fields)
    }
}
