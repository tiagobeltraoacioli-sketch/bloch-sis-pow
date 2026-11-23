// AUDIT-L1L2-20261123 L1S-02, the L2 side effect of
// `params::FEE_CONTROLLER_PAID_USAGE_ACTIVATION_EPOCH`: a settlement is free
// and takes its whole block. Inert it reads as a full block (+12.5%, EXE-5);
// behind the gate the settlement block is neutral, neither +12.5% nor the
// -12.5% an empty block would give.
#[test]
fn l1s02_a_settlement_block_is_neutral_behind_the_paid_usage_gate() {
    let (mut opened, mut chains) = funded_l2(1);
    // A price well above the floor, held by a parent exactly at target.
    opened.base_fee_millisat_per_gas = 1_000_000;
    opened.block_gas_used = fee_market::BLOCK_GAS_TARGET;
    opened.block_tx_bytes = 0;
    let price = opened.next_base_fee();
    assert_eq!(price, 1_000_000);
    let slot = crate::params::SLOTS_PER_EPOCH + 1;
    let anchored = apply(&opened, slot, &[], &mut chains).unwrap();
    let anchored_price = anchored.next_base_fee();
    let empty = crate::l2_settlement::expected_body_commitment(&[]);
    let tx = PosTransaction::L2SettlementAsync(Box::new(settlement(&anchored, empty)));

    let block = build_block(&Transition::new(ProofDouble), &anchored, slot + 1, &[], std::slice::from_ref(&tx), &mut chains);
    let inert = body_verdict(&anchored, &block, std::slice::from_ref(&tx)).expect("settlement");
    assert_eq!(inert.block_gas_used, fee_market::BLOCK_GAS_LIMIT);
    assert!(inert.next_base_fee() > anchored_price, "as shipped a settlement block raises the price");

    let _fix = crate::params::fee_controller_paid_usage_rehearsal::open();
    let armed = body_verdict(&anchored, &block, std::slice::from_ref(&tx)).expect("settlement");
    assert_eq!(armed.l2_settlement().unwrap().settled_number(), 1);
    assert_eq!(armed.next_base_fee(), anchored_price, "behind the gate it is neutral");
}
