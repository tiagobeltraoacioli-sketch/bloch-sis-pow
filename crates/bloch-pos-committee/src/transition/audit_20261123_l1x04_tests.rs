// AUDIT-L1L2-20261123 L1X-04, the L1 part: behind
// `params::L2_DA_SETTLER_SLOT_ACTIVATION_EPOCH`, on an L2 with a settler set,
// data-availability batches from other keys leave one of the four places of
// a block to the registered settler. Inert as shipped.

/// `n` distinct batches for L2 block 1, each funded by its own coin of the
/// depositor key.
fn da_batches(pre: &CommittedState, n: u32) -> Vec<PosTransaction> {
    (0..n).map(|i| PosTransaction::L2DataAvailability(da_tx(pre, coin(i), 2 * BLCH, 1, batch(&[&[i as u8 + 1]])))).collect()
}

#[test]
fn l1x04_the_da_slot_gate_is_inert() {
    assert_eq!(crate::params::L2_DA_SETTLER_SLOT_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::l2_da_settler_slot_active(u64::MAX - 1));
}

/// The finding's block: four junk batches from a key that has nothing to do
/// with the L2. Valid as shipped, and valid behind the gate while no settler
/// set exists; with a set, the fourth place is the settler's.
#[test]
fn l1x04_other_keys_leave_one_da_place_to_the_settler_behind_the_gate() {
    use crate::l2_settlement::da::{MAX_PER_BLOCK, RESERVED_FOR_SETTLER};
    // The junk sender is the depositor key; the settler is another key.
    let (pre, mut chains) = settler_fixture_with(8, Some(vec![settler_key(1)]));
    let block = template(&pre, &mut chains);
    let junk = da_batches(&pre, MAX_PER_BLOCK as u32);
    let inert = body_verdict(&pre, &block, &junk).expect("four junk batches are a valid block as shipped");
    assert_eq!(inert.l2_settlement().unwrap().data_availability().len(), MAX_PER_BLOCK);

    let (no_set, mut plain_chains) = settler_fixture_with(8, None);
    let plain_block = template(&no_set, &mut plain_chains);
    let plain_junk = da_batches(&no_set, MAX_PER_BLOCK as u32);
    let _gate = crate::params::l2_da_settler_slot_rehearsal::open();
    assert!(body_verdict(&no_set, &plain_block, &plain_junk).is_ok(), "without a settler set the rule does not bind");
    assert_eq!(body_verdict(&pre, &block, &junk).map(|_| ()), Err(TransitionError::BlockGasLimitExceeded));
    let shared = &junk[..MAX_PER_BLOCK - RESERVED_FOR_SETTLER];
    let post = body_verdict(&pre, &block, shared).expect("the other keys' share");
    assert_eq!(post.l2_settlement().unwrap().data_availability().len(), MAX_PER_BLOCK - RESERVED_FOR_SETTLER);
}

/// The settler's own batches are not limited by the reservation: with the
/// depositor key registered as the settler, the same four batches are valid.
#[test]
fn l1x04_the_settlers_batches_take_any_place() {
    use crate::l2_settlement::da::MAX_PER_BLOCK;
    let (pre, mut chains) = settler_fixture_with(8, Some(vec![settler_key(1), depositor()]));
    let block = template(&pre, &mut chains);
    let own = da_batches(&pre, MAX_PER_BLOCK as u32);
    let _gate = crate::params::l2_da_settler_slot_rehearsal::open();
    let post = body_verdict(&pre, &block, &own).expect("the settler may use every place");
    assert_eq!(post.l2_settlement().unwrap().data_availability().len(), MAX_PER_BLOCK);
    // Five is still too many for anyone.
    let five = da_batches(&pre, MAX_PER_BLOCK as u32 + 1);
    assert_eq!(body_verdict(&pre, &block, &five).map(|_| ()), Err(TransitionError::BlockGasLimitExceeded));
}
