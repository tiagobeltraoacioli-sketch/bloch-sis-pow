// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HF1 security review (2026-10-20), frozen finality set
// (`params::NATIVE_FINALITY_SET_ACTIVATION_EPOCH`, p1a / hf1-core 2037d077).
// Findings summarized in docs/HARD-FORKS-1-2-3-INTEGRATION.md (HF1 review).
//
// Every `#[ignore]` test here asserts the property the review asks for and
// FAILS on 2037d077. Run them with
//
//     cargo test -p bloch-pos-committee --lib hf1_review -- --ignored --nocapture
//
// The non-ignored tests pin behaviour the review VERIFIED (they pass).

use super::*;
use crate::params::native_finality_set_test as gate;
use crate::params::NATIVE_FINALITY_SET_PRUNE_AFTER_EPOCHS as PRUNE;

const G: Checkpoint = Checkpoint { epoch: 0, root: [0xAA; 32] };

fn roster(stakes: &[u64]) -> Vec<Validator> {
    stakes.iter().enumerate().map(|(i, s)| Validator { index: i as u32, effective_stake: *s }).collect()
}

fn branch_root(marker: u8, epoch: u64) -> [u8; 32] {
    let mut out = [marker; 32];
    out[..8].copy_from_slice(&epoch.to_le_bytes());
    out
}

/// Every voter votes this branch's checkpoint of `epoch`, sourcing the
/// branch's own current justified checkpoint (an honest validator).
fn step(st: &mut FinalityState, set: &[Validator], voters: &[u32], epoch: u64, marker: u8) -> EpochOutcome {
    let target = branch_root(marker, epoch);
    let src = st.current_justified();
    let atts: Vec<(u32, AttestationData)> = voters
        .iter()
        .map(|v| {
            (*v, AttestationData {
                slot: epoch * crate::params::SLOTS_PER_EPOCH,
                head: target,
                source_epoch: src.epoch,
                source_root: src.root,
                target_epoch: epoch,
                target_root: target,
            })
        })
        .collect();
    st.process_epoch(&EpochVotes { epoch, active_set: set, attestations: &atts }).unwrap()
}

// ── F1: one mainnet host holds more than a third of the finality weight ──

/// Post-cap duty-roster weights per HOST, summed from
/// a duty-roster snapshot (getvalidators at epoch 6016,
/// placement of 2026-10-14; branch codex/bloch-p7b-model-20261019). One
/// aggregate validator per host: the quorum and the (proportional) leak are
/// the same as for the host's validators individually, up to rounding.
const FLEET: [(&str, u64); 6] = [
    ("H1", 2_709_799_500_222_430),
    ("H2", 2_342_333_817_849_529),
    ("H3", 7_095_696_886_847_240),
    ("H4", 3_584_232_045_867_593),
    ("H5", 1_963_368_303_795_402),
    ("X externals", 2_320_570_718_336_547),
];

/// First epoch (after the outage starts at epoch 6) at which a checkpoint
/// after the outage finalizes, within `horizon` epochs; mainnet rules (quorum
/// floor + leak recovery, ETH-paced leak).
fn first_finality_after_outage(offline: &[usize], frozen: bool, horizon: u64) -> Option<u64> {
    let _floor = crate::params::rehearsal::gates_open_guard();
    let _pace = crate::params::eth_paced_leak_rehearsal::open();
    let _g = frozen.then(gate::open);
    let stakes: Vec<u64> = FLEET.iter().map(|(_, s)| *s).collect();
    let set = roster(&stakes);
    let all: Vec<u32> = (0..FLEET.len() as u32).collect();
    let live: Vec<u32> = all.iter().copied().filter(|i| !offline.contains(&(*i as usize))).collect();
    let mut st = FinalityState::new(G);
    for e in 1..=5 {
        step(&mut st, &set, &all, e, 0x01);
    }
    for e in 6..6 + horizon {
        if step(&mut st, &set, &live, e, 0x01).finalized.is_some_and(|c| c.epoch >= 6) {
            return Some(e - 6);
        }
    }
    None
}

/// Quantification table (prints; asserts only what it measured).
#[test]
fn f1_mainnet_fleet_outage_table() {
    let scenarios: &[&[usize]] = &[&[0], &[1], &[2], &[3], &[4], &[2, 5], &[0, 3, 5], &[0, 1, 5], &[3, 4, 5]];
    for off in scenarios {
        let names: Vec<&str> = off.iter().map(|i| FLEET[*i].0).collect();
        let legacy = first_finality_after_outage(off, false, 3_000);
        let frozen = first_finality_after_outage(off, true, 3_000);
        eprintln!("offline {names:?}: legacy resumes after {legacy:?} epochs, frozen set after {frozen:?}");
        if frozen.is_none() {
            assert!(legacy.is_some(), "the leak rescues every scenario of this table today");
        }
    }
    // The headline: H3 alone.
    assert_eq!(first_finality_after_outage(&[2], true, 3_000), None);
    let legacy = first_finality_after_outage(&[2], false, 3_000).unwrap();
    assert!((600..=800).contains(&legacy), "H3 down: today the leak resumes finality after {legacy} epochs");
}

/// F1 property: no single-host outage halts finality on the mainnet fleet.
/// FAILS: H3 holds 35.45% of the post-cap weight; with the frozen set and H3
/// offline, finality never resumes until H3 returns (or a recovery release).
#[test]
#[ignore = "HF1 review F1: fails on 2037d077 (single host H3 > 1/3 of the frozen set)"]
fn f1_no_single_host_outage_halts_finality_under_the_frozen_set() {
    for host in 0..5usize {
        assert!(
            first_finality_after_outage(&[host], true, 3_000).is_some(),
            "{} offline halts finality for 3000 epochs (~33 days) under the frozen set",
            FLEET[host].0
        );
    }
}

// ── F2: validators that LEAVE the roster stay in the frozen set ──────────

/// F2 property: if every validator that still exists votes, finality
/// continues. FAILS: 40% of the set exits (voluntary exit, slashing exit at
/// e+1, or any `exit_epoch`) in one epoch; the remaining 60% vote unanimously,
/// yet the frozen set still counts the departed stake in its denominator,
/// and since only a finalized handoff can remove it, finality is dead for
/// good. The legacy rule (denominator = current roster) finalizes at once.
#[test]
#[ignore = "HF1 review F2: fails on 2037d077 (exited stake is permanent absence)"]
fn f2_finality_survives_the_exit_of_a_third_when_everyone_left_votes() {
    let full = roster(&[100; 10]);
    let remaining: Vec<Validator> = full.iter().copied().filter(|v| v.index >= 4).collect();
    let all: Vec<u32> = (0..10).collect();
    let left: Vec<u32> = (4..10).collect();
    let run = |frozen: bool| -> Option<u64> {
        let _g = frozen.then(gate::open);
        let mut st = FinalityState::new(G);
        for e in 1..=5 {
            step(&mut st, &full, &all, e, 0x01);
        }
        for e in 6..=6 + 3 * PRUNE {
            if step(&mut st, &remaining, &left, e, 0x01).finalized.is_some_and(|c| c.epoch >= 6) {
                return Some(e);
            }
        }
        None
    };
    assert_eq!(run(false), Some(7), "legacy: unanimous remaining roster finalizes at once");
    assert!(run(true).is_some(), "frozen set: 100% of the existing roster votes and finality never resumes");
}

// ── F3: the recovery epoch re-forms the set per branch ──────────────────

/// F3 property: a coordinated recovery epoch must not let both sides of a
/// split finalize. FAILS: `open_finality_set` re-forms `current` from each
/// branch's OWN `last_seen`, so each side prunes the other and both finalize
/// conflicting checkpoints, the exact defect the frozen set exists to stop.
/// The release that names the epoch is the same binary on both sides.
#[test]
#[ignore = "HF1 review F3: fails on 2037d077 (recovery re-forms the set per branch)"]
fn f3_a_recovery_epoch_finalizes_at_most_one_side_of_a_split() {
    let set = roster(&[100; 10]);
    let all: Vec<u32> = (0..10).collect();
    let split = 6u64;
    let r = split + PRUNE + 10;
    let _g = gate::open();
    let _r = gate::recovery(&[r]);
    let mut common = FinalityState::new(G);
    for e in 1..=split {
        step(&mut common, &set, &all, e, 0x01);
    }
    let sides: [(Vec<u32>, u8); 2] = [((0..6).collect(), 0xA0), ((6..10).collect(), 0xB0)];
    let mut finalized_sides = 0;
    for (voters, marker) in &sides {
        let mut st = common.clone();
        let mut fin = false;
        for e in split + 1..=r + 5 {
            if step(&mut st, &set, voters, e, *marker).finalized.is_some_and(|c| c.epoch > split) {
                fin = true;
            }
        }
        eprintln!("side {marker:#x}: finalized post-split = {fin}, set total = {}", st.finality_set().unwrap().current.total());
        finalized_sides += usize::from(fin);
    }
    assert!(finalized_sides <= 1, "{finalized_sides} sides finalized conflicting checkpoints after the recovery epoch");
}

/// F3b: a recovery epoch earlier than PRUNE epochs after the absentees'
/// last vote re-forms the SAME set and does nothing. Passes (pins the
/// operational constraint: recovery >= last vote + 90 epochs = 24 h).
#[test]
fn f3b_recovery_before_the_prune_horizon_is_a_no_op() {
    let set = roster(&[100; 10]);
    let all: Vec<u32> = (0..10).collect();
    let live: Vec<u32> = (0..6).collect();
    // Last vote of the absentees: epoch 5. Pruned only at r >= 5 + PRUNE.
    let r = 5 + PRUNE - 1;
    let _g = gate::open();
    let _r = gate::recovery(&[r]);
    let mut st = FinalityState::new(G);
    for e in 1..=5 {
        step(&mut st, &set, &all, e, 0x01);
    }
    let mut fin = false;
    for e in 6..=r + 20 {
        fin |= step(&mut st, &set, &live, e, 0x01).finalized.is_some_and(|c| c.epoch > 5);
    }
    assert!(!fin);
    assert_eq!(st.finality_set().unwrap().current.total(), 1_000);
    // One epoch later the same recovery prunes them and finality resumes.
    let _r = gate::recovery(&[r + 1]);
    let mut st2 = FinalityState::new(G);
    for e in 1..=5 {
        step(&mut st2, &set, &all, e, 0x01);
    }
    let mut first = None;
    for e in 6..=r + 20 {
        if first.is_none() && step(&mut st2, &set, &live, e, 0x01).finalized.is_some_and(|c| c.epoch > 5) {
            first = Some(e);
        }
    }
    assert_eq!(first, Some(r + 2));
}

// ── Verified: accountable safety survives pruning (no finding) ──────────

/// A long split where side A (>= 2/3) finalizes and prunes side B, then some
/// A voters defect to B. B's quorum (2/3 of the unpruned set) can only be met
/// with >= 1/3 of the original set made of validators that already voted on
/// A after the split; their B votes source B's older justified checkpoint
/// and target a later epoch, so they SURROUND their own A votes. The test
/// checks the arithmetic premise: B cannot reach 2/3 of C0 without at least
/// one third of C0 coming from A's post-split voters.
#[test]
fn verified_pruning_keeps_one_third_accountable_via_surround_votes() {
    let set = roster(&[100; 9]);
    let all: Vec<u32> = (0..9).collect();
    let _g = gate::open();
    let mut common = FinalityState::new(G);
    for e in 1..=3 {
        step(&mut common, &set, &all, e, 0x01);
    }
    // Phase 1: A = 0..=5 (600/900 = 2/3), B = 7,8; validator 6 silent.
    let mut a = common.clone();
    let mut b = common.clone();
    let a_voters: Vec<u32> = (0..=5).collect();
    for e in 4..=4 + PRUNE + 5 {
        step(&mut a, &set, &a_voters, e, 0xA0);
        step(&mut b, &set, &[7, 8], e, 0xB0);
    }
    assert_eq!(a.finality_set().unwrap().current.total(), 600, "A pruned 6, 7, 8");
    assert_eq!(b.finality_set().unwrap().current.total(), 900, "B never finalized: C0");
    // B's quorum needs 600 of C0; outside A's post-split voters there is 300.
    let outside_a: u128 = [6u32, 7, 8].iter().map(|v| b.finality_set().unwrap().current.members[v] as u128).sum();
    assert!(3 * (600 - outside_a) >= 900, "B needs >= 1/3 of C0 from A's voters (surround-slashable)");
}
