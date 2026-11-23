// AUDIT-L1L2-20261123 L1X-01: behind
// `params::L2_ATTESTED_RELEASE_LANE_ACTIVATION_EPOCH` attested claims draw on
// their own lane of the release window. The three proofs of concept of the
// finding, with the gate armed, no longer freeze anybody. Inert as shipped.
use crate::l2_settlement::withdrawal::ReleaseRules;

type FixLeaves = Vec<([u8; 32], u64)>;

fn fix_tree(leaves: &[([u8; 32], u64)]) -> Vec<[u8; 32]> {
    leaves.iter().enumerate().map(|(i, (r, sats))| wd::leaf(700771, i as u64, r, *sats)).collect()
}

/// Mainnet limits + a 3-of-5 attestor set installed at the boundary; `escrow`
/// sats escrowed; one withdrawal record over `leaves` at native height 1,
/// matured for LARGE claims (2 880 blocks) and finalized.
fn fix_claims(escrow: u64, leaves: &[([u8; 32], u64)]) -> CommittedState {
    let (base, mut policy, mut chains) = funded_running_without_l2();
    policy.attestor_set = wd::attestor_set_hash(3, &mainnet_attestors());
    let mut pre = {
        let _gate = crate::params::l2_settlement_rehearsal::open();
        let _policy = crate::l2_settlement::activation_rehearsal::set(Activation { policy, asynchronous: mn::ASYNCHRONOUS, limits: mn::LIMITS });
        apply(&base, crate::params::SLOTS_PER_EPOCH, &[], &mut chains).unwrap()
    };
    let tree = fix_tree(leaves);
    let l2 = pre.l2_settlement.as_mut().unwrap();
    l2.append_deposit(crate::l2_settlement::InboxRecord { height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: escrow, recipient: [0x42; 20] })
        .unwrap();
    l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&tree), count: tree.len() as u64, height: 1 });
    while l2.height() + 1 < 1 + mn::LIMITS.large_delay_blocks {
        l2.advance_height().unwrap();
    }
    finalize_all(&mut pre);
    pre
}

/// The claim transaction of leaf `index`, attested 3-of-5 or not, judged by
/// the real claim path at the state's epoch.
fn fix_verdict(pre: &CommittedState, leaves: &FixLeaves, index: u64, attested: bool) -> Result<(), TxReject> {
    let attestation = attested.then(|| attest5(leaves, &[0, 1, 2]));
    try_claim(pre, &claim_of(pre, leaves, index, attestation)).map(|_| ())
}

/// Pay leaf `index` on `pre` under the rules of its epoch.
fn fix_pay(pre: &mut CommittedState, leaves: &FixLeaves, index: u64, attested: bool) {
    let rules = ReleaseRules::at(pre.epoch);
    let (recipient, sats) = leaves[index as usize];
    let proof = wd::proof(&fix_tree(leaves), index).unwrap();
    pre.l2_settlement.as_mut().unwrap().release_withdrawal_under(700771, index, &recipient, sats, &proof, attested, rules).expect("paid");
}

fn fix_to_next_window(pre: &mut CommittedState) {
    let l2 = pre.l2_settlement.as_mut().unwrap();
    let next = l2.height() + 1;
    for _ in 0..mn::LIMITS.release_window_blocks - next % mn::LIMITS.release_window_blocks {
        l2.advance_height().unwrap();
    }
}

const FIX_RATE_LIMITED: Result<(), TxReject> = Err(TxReject::L2WithdrawClaim(ClaimReject::RateLimited));
const DUST: u64 = 1_000_000;

#[test]
fn l1x01_the_attested_lane_gate_is_inert() {
    assert_eq!(crate::params::L2_ATTESTED_RELEASE_LANE_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::l2_attested_release_lane_active(u64::MAX - 1));
    assert_eq!(ReleaseRules::at(u64::MAX - 1), ReleaseRules::default());
}

/// Part (a): a dust claim landed first in the window froze every attested
/// withdrawal above the cap. Behind the gate the attested claim is paid
/// after it, and nothing of the lane exists in the state while inert.
#[test]
fn l1x01_a_dust_claim_no_longer_freezes_an_attested_withdrawal() {
    let leaves: FixLeaves = vec![([1; 32], 500 * BLCH), ([9; 32], DUST)];
    let mut pre = fix_claims(1_000 * BLCH, &leaves);
    fix_pay(&mut pre, &leaves, 1, false);
    assert_eq!(fix_verdict(&pre, &leaves, 0, true), FIX_RATE_LIMITED, "as shipped: frozen for the window");
    assert_eq!(*pre.l2_settlement().unwrap().attested_release(), wd::ReleaseWindow::default());
    assert!(!pre.l2_settlement().unwrap().committed_bytes().windows(34).any(|w| w == b"BLOCH:NATIVE:L2:ATTESTED-RELEASE:1"));

    let _gate = crate::params::l2_attested_release_lane_rehearsal::open();
    assert_eq!(fix_verdict(&pre, &leaves, 0, true), Ok(()));
    let open_before = pre.l2_settlement().unwrap().release_window();
    fix_pay(&mut pre, &leaves, 0, true);
    let l2 = pre.l2_settlement().unwrap();
    assert_eq!(l2.release_window(), open_before, "the ordinary window did not move");
    assert_eq!(l2.attested_release().released, u128::from(500 * BLCH));
    assert_eq!(l2.attested_release().cap, u128::from((1_000 * BLCH - DUST) / 2), "half of the escrow at the lane's first claim");
    assert!(l2.committed_bytes().windows(34).any(|w| w == b"BLOCH:NATIVE:L2:ATTESTED-RELEASE:1"));
    assert!(l2.escrow_conserved());
}

/// Part (b): one unattested claim just under the threshold still uses the
/// whole ordinary cap (that is the rate limit), but a small claimant now has
/// a way out that the big claim cannot close: the attested lane.
#[test]
fn l1x01_b_a_starved_small_claim_is_payable_with_an_attestation() {
    let leaves: FixLeaves = vec![([9; 32], 100 * BLCH - 1), ([2; 32], BLCH), ([3; 32], DUST)];
    let mut pre = fix_claims(1_000 * BLCH, &leaves);
    let _gate = crate::params::l2_attested_release_lane_rehearsal::open();
    fix_pay(&mut pre, &leaves, 0, false);
    assert_eq!(pre.l2_settlement().unwrap().release_window().remaining(), 1);
    for index in [1, 2] {
        assert_eq!(fix_verdict(&pre, &leaves, index, false), FIX_RATE_LIMITED, "the ordinary cap is spent");
        assert_eq!(fix_verdict(&pre, &leaves, index, true), Ok(()), "the attested lane is not");
    }
}

/// Part (c): with the EXE-4 gate armed one attested claim 1 sat over the cap
/// closed the window for everyone, 0.01 BLCH included. Behind the lane gate
/// it closes nothing: the victim's attested claim and the small unattested
/// claim are both paid after it.
#[test]
fn l1x01_c_one_over_cap_attested_claim_no_longer_closes_the_window() {
    let over_cap = 100 * BLCH + 1;
    let leaves: FixLeaves = vec![([1; 32], 400 * BLCH), ([9; 32], over_cap), ([3; 32], DUST)];
    let mut exe4 = fix_claims(1_000 * BLCH, &leaves);
    {
        let _exe4 = crate::params::l2_release_exemption_rehearsal::open();
        fix_pay(&mut exe4, &leaves, 1, true);
        assert_eq!(fix_verdict(&exe4, &leaves, 0, true), FIX_RATE_LIMITED, "EXE-4 alone: closed");
        assert_eq!(fix_verdict(&exe4, &leaves, 2, false), FIX_RATE_LIMITED, "even 0.01 BLCH");
    }
    for with_exe4 in [false, true] {
        let _exe4 = with_exe4.then(crate::params::l2_release_exemption_rehearsal::open);
        let _gate = crate::params::l2_attested_release_lane_rehearsal::open();
        let mut pre = fix_claims(1_000 * BLCH, &leaves);
        fix_pay(&mut pre, &leaves, 1, true);
        assert_eq!(fix_verdict(&pre, &leaves, 0, true), Ok(()));
        assert_eq!(fix_verdict(&pre, &leaves, 2, false), Ok(()));
        fix_pay(&mut pre, &leaves, 0, true);
        fix_pay(&mut pre, &leaves, 2, false);
        assert!(pre.l2_settlement().unwrap().escrow_conserved());
    }
}

/// The lane is still a rate limit: it admits attested claims while it has
/// released no more than half the escrow, the claim that crosses the budget
/// is paid in full and closes it, and it reopens with the next window. An
/// unattested claim is never admitted by the lane.
#[test]
fn l1x01_the_attested_lane_is_bounded_per_window() {
    let leaves: FixLeaves =
        vec![([1; 32], 300 * BLCH), ([2; 32], 250 * BLCH), ([3; 32], 150 * BLCH), ([4; 32], 120 * BLCH), ([5; 32], DUST)];
    let mut pre = fix_claims(1_000 * BLCH, &leaves);
    let _gate = crate::params::l2_attested_release_lane_rehearsal::open();
    assert_eq!(fix_verdict(&pre, &leaves, 3, false).map_err(|_| ()), Err(()), "a large claim still needs its attestation");
    fix_pay(&mut pre, &leaves, 0, true); // 300 of a 500 budget
    fix_pay(&mut pre, &leaves, 1, true); // 550: crosses the budget, paid in full
    assert_eq!(fix_verdict(&pre, &leaves, 2, true), FIX_RATE_LIMITED, "the lane is closed for this window");
    assert_eq!(fix_verdict(&pre, &leaves, 4, true), FIX_RATE_LIMITED, "for any attested amount");
    assert_eq!(fix_verdict(&pre, &leaves, 4, false), Ok(()), "the ordinary window is independent");
    fix_to_next_window(&mut pre);
    assert_eq!(fix_verdict(&pre, &leaves, 2, true), Ok(()), "a new window, a new budget");
    fix_pay(&mut pre, &leaves, 2, true);
    let l2 = pre.l2_settlement().unwrap();
    assert_eq!(l2.attested_release().cap, u128::from(225 * BLCH), "half of the 450 BLCH left in escrow");
    assert!(l2.escrow_conserved());

    #[cfg(feature = "local-state-cache")]
    {
        let (restored, bytes, _) = local_cache_round_trip(&pre);
        assert!(bytes.windows(16).any(|w| w == b"BPOSST01:L2AR:v1"));
        assert_eq!(restored.l2_settlement().unwrap().attested_release(), pre.l2_settlement().unwrap().attested_release());
    }
}
