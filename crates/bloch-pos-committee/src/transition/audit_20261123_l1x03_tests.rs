// AUDIT-L1L2-20261123 L1X-03, the L1 half: behind
// `params::L2_CUMULATIVE_DEPOSIT_CAP_ACTIVATION_EPOCH` a deposit that would
// take the lifetime deposit total above the L2 cumulative mint cap is
// refused on L1. Inert as shipped.
use crate::transition::l2_deposit::MAX_L2_DEPOSIT_SAT;

/// An activated L2 whose lifetime deposits are `room` sats below the cap,
/// all of it withdrawn again (escrow 0): the state the finding reaches by
/// cycling value through the bridge.
fn fix_nearly_capped(room: u64) -> CommittedState {
    let (mut opened, _) = activated_fixture(true, [0; 32]);
    let l2 = opened.l2_settlement.as_mut().unwrap();
    let limits = *l2.limits();
    let sats = MAX_L2_DEPOSIT_SAT - room;
    let height = l2.height() + 1;
    l2.append_deposit(crate::l2_settlement::InboxRecord { height, tx_index: 0, txid: [1; 32], vout: 1, sats, recipient: [0x42; 20] })
        .unwrap();
    let tree = vec![wd::leaf(700771, 0, &[7; 32], sats)];
    l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&tree), count: 1, height });
    for _ in 0..limits.large_delay_blocks.max(limits.release_window_blocks) + 1 {
        l2.advance_height().unwrap();
    }
    l2.release_withdrawal(700771, 0, &[7; 32], sats, &wd::proof(&tree, 0).unwrap(), false, false).unwrap();
    assert_eq!((l2.escrow_sat(), l2.cumulative_deposited_sat()), (0, u128::from(sats)));
    assert_eq!(l2.cumulative_deposited_sat(), l2.deposited_sat(), "the O(1) total equals the inbox sum");
    opened
}

#[test]
fn l1x03_the_cumulative_cap_gate_is_inert() {
    assert_eq!(crate::params::L2_CUMULATIVE_DEPOSIT_CAP_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::l2_cumulative_deposit_cap_active(u64::MAX - 1));
    // The L1 constant is the L2 `ChainSpec::max_l1_sats` (the L1 total supply).
    assert_eq!(u128::from(MAX_L2_DEPOSIT_SAT), crate::tokenomics_v4::TOTAL_SUPPLY_SAT);
}

/// The finding's poison record: with 5 BLCH of room left, a deposit of
/// 5 BLCH + 1 sat is admitted as shipped and refused behind the gate, in the
/// preflight and in the transition; exactly up to the cap is admitted.
#[test]
fn l1x03_the_deposit_past_the_mint_cap_is_refused_only_behind_the_gate() {
    let room = 5 * BLCH;
    let pre = fix_nearly_capped(room);
    let within = deposit_tx(&pre, room);
    let beyond = deposit_tx(&pre, room + 1);
    let base_fee = pre.next_base_fee();
    assert_eq!(pre.l2_deposit_refusal_at(&within, base_fee), None);
    assert_eq!(pre.l2_deposit_refusal_at(&beyond, base_fee), None, "as shipped the L1 has no cumulative bound");
    let _gate = crate::params::l2_cumulative_deposit_cap_rehearsal::open();
    assert_eq!(pre.l2_deposit_refusal_at(&within, base_fee), None);
    assert_eq!(pre.l2_deposit_refusal_at(&beyond, base_fee), Some(L2DepositReject::Inbox));
    let mut state = pre.clone();
    assert_eq!(
        state.apply_transaction(&PosTransaction::L2Deposit(beyond), 0, base_fee, &ToyVerifier).map(|_| ()),
        Err(TxReject::L2Deposit(L2DepositReject::Inbox))
    );
    assert_eq!(state, pre, "a refused deposit changes nothing");
    state.apply_transaction(&PosTransaction::L2Deposit(within), 0, base_fee, &ToyVerifier).expect("up to the cap");
    let l2 = state.l2_settlement().unwrap();
    assert_eq!(l2.cumulative_deposited_sat(), u128::from(MAX_L2_DEPOSIT_SAT));
    assert!(l2.escrow_conserved());
    // At the cap even the minimum deposit is refused; the L2 keeps settling.
    let dust = deposit_tx(&state, crate::transition::l2_deposit::MIN_L2_DEPOSIT_SAT);
    assert_eq!(state.l2_deposit_refusal_at(&dust, state.next_base_fee()), Some(L2DepositReject::Inbox));
}
