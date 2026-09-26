// SPDX-License-Identifier: AGPL-3.0-or-later
//
// INF-02 — "One credential class controls the majority of validator keys".
//
// Independent-reviewer reproduction. This file is an integration test in the
// idiom of crates/bloch-pos-committee/tests/*.rs (public API only, std only).
// It is NOT in the repository; to run it, copy it to
//   crates/bloch-pos-committee/tests/repro_inf_02.rs
// and run `cargo test -p bloch-pos-committee --test repro_inf_02`.
//
// What it proves, with the exact mainnet numbers:
//
//   genesis/mainnet.manifest (decoded by verify/decode_manifest.py):
//     64 validators, every stake_sat == 2_500_000_000_000 (25,000 BLCH),
//     cohort == all 64 indices, total 160_000_000_000_000 sat.
//   crates/bloch-pos-committee/src/finality.rs:478  3·w ≥ 2·total  (2/3 rule)
//   crates/bloch-pos-committee/src/params.rs:1293   DEPOSIT gate inert → no
//     independent stake → genesis_cohort::cap_status == Deferred (100% weight)
//   crates/bloch-pos-committee/src/params.rs:1425   SLASHING_EVIDENCE inert →
//     transition.rs:3089 refuses every evidence tx → equivocation is unpunished
//
// The credential concentration itself (one SSH key / one Fly token reaching
// 49–65 hosts) is an operational fact stated in deploy/SSH-ROLE-SEPARATION.md
// and deploy/FLAG-DAY-EPOCH-800.md and cannot be unit-tested; what CAN be
// tested is the consensus consequence of holding those 49 keys, which is
// what the three tests below pin.

use bloch_pos_committee::attestation::AttestationData;
use bloch_pos_committee::finality::{Checkpoint, EpochVotes, FinalityState};
use bloch_pos_committee::genesis_cohort::{cap_status, CapStatus};
use bloch_pos_committee::params::{
    DEPOSIT_ACTIVATION_EPOCH, LEAK_RECOVERY_ACTIVATION_EPOCH, SLASHING_EVIDENCE_ACTIVATION_EPOCH,
    SLOTS_PER_EPOCH,
};
use bloch_pos_committee::sample::Validator;

/// Exact per-validator stake in genesis/mainnet.manifest.
const MAINNET_STAKE_SAT: u64 = 2_500_000_000_000;
const N: u32 = 64;
/// Validators reachable through the Fly account alone (FLAG-DAY-EPOCH-800.md:60-64).
const FLY: u32 = 49;
/// Mainnet is at ≈ epoch 3,065; start the gadget from a checkpoint past every
/// armed gate so the arithmetic is the one the live binary runs today.
const START_EPOCH: u64 = 3_064;

fn mainnet_set() -> Vec<Validator> {
    (0..N).map(|i| Validator { index: i, effective_stake: MAINNET_STAKE_SAT }).collect()
}

fn root(tag: u8, epoch: u64) -> [u8; 32] {
    let mut r = [tag; 32];
    r[0] = epoch as u8;
    r[1] = (epoch >> 8) as u8;
    r
}

fn vote(v: u32, epoch: u64, target: [u8; 32], source: Checkpoint) -> (u32, AttestationData) {
    (
        v,
        AttestationData {
            slot: epoch * SLOTS_PER_EPOCH,
            head: target,
            source_epoch: source.epoch,
            source_root: source.root,
            target_epoch: epoch,
            target_root: target,
        },
    )
}

fn start() -> Checkpoint {
    Checkpoint { epoch: START_EPOCH, root: [0xAA; 32] }
}

/// The live gates this reproduction depends on. If any of these flips, the
/// reasoning in the finding changes and this test must be re-read.
#[test]
fn the_gates_this_finding_assumes_are_still_in_that_state() {
    assert_eq!(DEPOSIT_ACTIVATION_EPOCH, u64::MAX, "deposits inert: cohort stays 100% of stake");
    assert_eq!(SLASHING_EVIDENCE_ACTIVATION_EPOCH, u64::MAX, "slashing inert: no penalty");
    assert!(START_EPOCH >= LEAK_RECOVERY_ACTIVATION_EPOCH, "test runs past the armed floor");

    // No independent stake exists, so the founder-cohort cap is DEFERRED and
    // every one of the 64 keys keeps its full weight (genesis_cohort.rs:118-128).
    let cohort: Vec<u32> = (0..N).collect();
    match cap_status(&mainnet_set(), &cohort, START_EPOCH) {
        CapStatus::Deferred { independent_sat } => assert_eq!(independent_sat, 0),
        other => panic!("cohort cap is not deferred on the live set: {other:?}"),
    }
}

/// 49 stolen keys justify and finalize on their own. The 15 remaining honest
/// validators vote for a different root every epoch and it never matters.
#[test]
fn forty_nine_of_sixty_four_finalize_alone_over_the_honest_fifteen() {
    let set = mainnet_set();
    let mut st = FinalityState::new(start());
    let mut source = start();

    for k in 1..=2u64 {
        let e = START_EPOCH + k;
        let attacker_root = root(0xE0, e);
        let honest_root = root(0x11, e);
        let mut atts: Vec<(u32, AttestationData)> = Vec::new();
        for v in 0..FLY {
            atts.push(vote(v, e, attacker_root, source));
        }
        for v in FLY..N {
            atts.push(vote(v, e, honest_root, source));
        }
        let out = st
            .process_epoch(&EpochVotes { epoch: e, active_set: &set, attestations: &atts })
            .unwrap();
        assert!(out.equivocators.is_empty());
        assert_eq!(
            out.justified,
            Some(Checkpoint { epoch: e, root: attacker_root }),
            "49/64 = 76.6% ≥ 2/3: the stolen keys justify their own root at epoch {e}"
        );
        assert!(!st.is_justified(&Checkpoint { epoch: e, root: honest_root }));
        if k == 2 {
            assert_eq!(
                out.finalized,
                Some(Checkpoint { epoch: e - 1, root: root(0xE0, e - 1) }),
                "consecutive justification finalizes the attacker's checkpoint"
            );
        }
        source = Checkpoint { epoch: e, root: attacker_root };
    }
    assert_eq!(st.finalized().epoch, START_EPOCH + 1);
}

/// The same 49 keys, signing twice per epoch, finalize TWO conflicting
/// checkpoints — one per audience. A single node that sees both signatures
/// discards the equivocator (finality.rs `no_two_conflicting_checkpoints_in_
/// one_epoch`), so the attacker delivers each set to one audience only; on the
/// devnet transport that is a direct TCP frame with no relay of accepted
/// attestations (net.rs module docs, engine.rs:3817 report is a no-op on
/// devnet). With SLASHING_EVIDENCE inert nothing punishes the double vote.
#[test]
fn the_same_forty_nine_keys_finalize_two_conflicting_checkpoints_for_two_audiences() {
    let set = mainnet_set();
    let mut audience_a = FinalityState::new(start());
    let mut audience_b = FinalityState::new(start());
    let mut src_a = start();
    let mut src_b = start();

    for k in 1..=2u64 {
        let e = START_EPOCH + k;
        let x = root(0xA0, e);
        let y = root(0xB0, e);
        let atts_a: Vec<_> = (0..FLY).map(|v| vote(v, e, x, src_a)).collect();
        let atts_b: Vec<_> = (0..FLY).map(|v| vote(v, e, y, src_b)).collect();
        let out_a = audience_a
            .process_epoch(&EpochVotes { epoch: e, active_set: &set, attestations: &atts_a })
            .unwrap();
        let out_b = audience_b
            .process_epoch(&EpochVotes { epoch: e, active_set: &set, attestations: &atts_b })
            .unwrap();
        assert_eq!(out_a.justified, Some(Checkpoint { epoch: e, root: x }));
        assert_eq!(out_b.justified, Some(Checkpoint { epoch: e, root: y }));
        src_a = Checkpoint { epoch: e, root: x };
        src_b = Checkpoint { epoch: e, root: y };
    }
    let fa = audience_a.finalized();
    let fb = audience_b.finalized();
    assert_eq!(fa.epoch, START_EPOCH + 1);
    assert_eq!(fb.epoch, START_EPOCH + 1);
    assert_ne!(fa.root, fb.root, "one epoch, two finalized roots: a consensus split");

    // And the control: an audience that sees BOTH sets bars every one of the
    // 49 and justifies nothing — which is exactly why per-audience delivery
    // is the attacker's move, not a limitation.
    let mut both = FinalityState::new(start());
    let e = START_EPOCH + 1;
    let mut atts: Vec<_> = (0..FLY).map(|v| vote(v, e, root(0xA0, e), start())).collect();
    atts.extend((0..FLY).map(|v| vote(v, e, root(0xB0, e), start())));
    let out = both
        .process_epoch(&EpochVotes { epoch: e, active_set: &set, attestations: &atts })
        .unwrap();
    assert_eq!(out.justified, None);
    assert_eq!(out.equivocators.len(), FLY as usize);
}

/// The honest remainder (15/64 = 23.4%) can never justify anything, even with
/// the armed epoch-2700 denominator floor: the floor is half the unleaked
/// total, and 3·0.234 < 2·0.5. So once the 49 stolen keys go silent or go
/// rogue, the honest fleet has no recovery path through consensus.
#[test]
fn the_honest_fifteen_can_never_justify_even_after_the_leak() {
    let set = mainnet_set();
    let mut st = FinalityState::new(start());
    for k in 1..=200u64 {
        let e = START_EPOCH + k;
        let r = root(0x11, e);
        let atts: Vec<_> = (FLY..N).map(|v| vote(v, e, r, start())).collect();
        let out = st
            .process_epoch(&EpochVotes { epoch: e, active_set: &set, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, None, "15/64 justified at epoch {e}; the floor is wrong");
    }
    assert_eq!(st.finalized(), start());
    assert_eq!(st.current_justified(), start());
}
