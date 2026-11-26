// AUDIT-L1L2-20261123 L1X-02: behind
// `params::L2_DEPOSIT_INFLOW_BOUND_ACTIVATION_EPOCH` a block carries at most
// MAX_DEPOSITS_PER_BLOCK L2 deposits and no deposit joins a full backlog;
// with the gate inert (as shipped) nothing changes.
use crate::l2_settlement::{MAX_DEPOSITS_PER_BLOCK, MAX_INBOX_PER_SETTLEMENT, MAX_PENDING_DEPOSITS};
use crate::transition::l2_deposit::L2DepositReject;

#[test]
fn l1x02_the_deposit_inflow_gate_is_inert() {
    assert_eq!(crate::params::L2_DEPOSIT_INFLOW_BOUND_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::l2_deposit_inflow_bound_active(u64::MAX - 1));
}

#[test]
fn l1x02_deposits_per_block_are_capped_only_behind_the_gate() {
    let (opened, mut chains) = funded_l2(8);
    let block = build_block(&Transition::new(ProofDouble), &opened, crate::params::SLOTS_PER_EPOCH + 1, &[], &[], &mut chains);
    let over: Vec<PosTransaction> = (0..MAX_DEPOSITS_PER_BLOCK as u32 + 1).map(|i| min_deposit(&opened, i)).collect();
    let at_cap = &over[..MAX_DEPOSITS_PER_BLOCK];
    // Inert (as shipped): any number that fits the block.
    let inert = body_verdict(&opened, &block, &over).expect("no cap while the gate is inert");
    assert_eq!(inert.l2_settlement().unwrap().inbox().len(), MAX_DEPOSITS_PER_BLOCK + 1);
    // Armed: the cap, exactly.
    let _gate = crate::params::l2_deposit_inflow_bound_rehearsal::open();
    assert_eq!(body_verdict(&opened, &block, &over).map(|_| ()), Err(TransitionError::BlockGasLimitExceeded));
    let capped = body_verdict(&opened, &block, at_cap).expect("up to the cap");
    assert_eq!(capped.l2_settlement().unwrap().inbox().len(), MAX_DEPOSITS_PER_BLOCK);
    // Other transactions are not counted: two deposits beside a DA batch.
    let mut mixed = at_cap.to_vec();
    mixed.push(PosTransaction::L2DataAvailability(da_tx(&opened, coin(7), 2 * BLCH, 1, batch(&[&[1]]))));
    assert!(body_verdict(&opened, &block, &mixed).is_ok());
}

/// The finding's flood, with the gate armed: the block-full of minimum
/// deposits of the proof of concept is invalid, and at the capped rate the
/// inflow of one proof time does not exceed what one settlement consumes.
#[test]
fn l1x02_the_flood_of_the_proof_of_concept_is_refused_behind_the_gate() {
    let (opened, mut chains) = funded_l2(40);
    let block = build_block(&Transition::new(ProofDouble), &opened, crate::params::SLOTS_PER_EPOCH + 1, &[], &[], &mut chains);
    let flood: Vec<PosTransaction> = (0..30).map(|i| min_deposit(&opened, i)).collect();
    assert_eq!(body_verdict(&opened, &block, &flood).expect("valid today").l2_settlement().unwrap().inbox().len(), 30);
    let _gate = crate::params::l2_deposit_inflow_bound_rehearsal::open();
    assert_eq!(body_verdict(&opened, &block, &flood).map(|_| ()), Err(TransitionError::BlockGasLimitExceeded));
    assert!(MAX_DEPOSITS_PER_BLOCK as u64 * crate::l2_settlement::DEPOSIT_DRAIN_BLOCKS <= MAX_INBOX_PER_SETTLEMENT);
}

/// Whatever the prover's speed, the backlog stops at MAX_PENDING_DEPOSITS:
/// the next deposit is refused (preflight and transition alike, nothing
/// escrowed) until a settlement consumes records.
#[test]
fn l1x02_no_deposit_joins_a_full_backlog_behind_the_gate() {
    let (opened, _) = funded_l2(4);
    let mut full = opened.clone();
    let l2 = full.l2_settlement.as_mut().unwrap();
    let height = l2.height() + 1;
    for i in 0..MAX_PENDING_DEPOSITS as u32 {
        let mut txid = [0x55; 32];
        txid[..4].copy_from_slice(&i.to_be_bytes());
        l2.append_deposit(crate::l2_settlement::InboxRecord { height, tx_index: i, txid, vout: 1, sats: 1_000_000, recipient: [0x42; 20] })
            .unwrap();
    }
    assert!(l2.deposit_backlog_full());
    let mut room = full.clone();
    room.l2_settlement.as_mut().unwrap().mark_consumed_for_test(1);
    let PosTransaction::L2Deposit(tx) = min_deposit(&full, 0) else { unreachable!() };
    let base_fee = full.next_base_fee();
    // Inert: admitted.
    assert_eq!(full.l2_deposit_refusal_at(&tx, base_fee), None);
    let _gate = crate::params::l2_deposit_inflow_bound_rehearsal::open();
    assert_eq!(full.l2_deposit_refusal_at(&tx, base_fee), Some(L2DepositReject::Inbox));
    let mut state = full.clone();
    assert_eq!(
        state.apply_transaction(&PosTransaction::L2Deposit(tx.clone()), 0, base_fee, &ToyVerifier).map(|_| ()),
        Err(TxReject::L2Deposit(L2DepositReject::Inbox))
    );
    assert_eq!(state, full, "a refused deposit changes nothing");
    // One record consumed: one place again.
    assert_eq!(room.l2_deposit_refusal_at(&tx, base_fee), None);
    room.apply_transaction(&PosTransaction::L2Deposit(tx), 0, base_fee, &ToyVerifier).expect("room for one");
    let l2 = room.l2_settlement().unwrap();
    assert!(l2.deposit_backlog_full() && l2.escrow_conserved());
}
