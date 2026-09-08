// SPDX-License-Identifier: AGPL-3.0-or-later
// Diagnostic for VAD-03 in VALIDATOR-ADMISSION-REVIEW-2026-09-08.md.
// Appended to engine/validator_admission_tests.rs only in a disposable copy.
// Success reproduces the documented gap; it is not a security pass.
#[test]
fn audit_unfunded_signed_deposit_reaches_mempool() {
    let (mut engine, _dir, funding, joining, mut tx) = fixture();
    tx.inputs[0].txid = [0xfa; 32];
    assert!(engine.state.utxo(&tx.inputs[0].txid, tx.inputs[0].vout).is_none());
    tx.tip_millisat_per_gas = 100;
    authorize(&mut tx, &funding, &joining);
    tx.verify_authorizations(&HybridVerifier::new()).unwrap();
    let wire = PosTransaction::FundedDeposit(tx);
    let canonical = wire.canonical_bytes();
    assert!(engine.on_transaction(wire).is_ok(), "audit reproducer: unfunded admission");
    assert!(engine.mempool.contains_key(&canonical));
    engine.wall_slot = 1;
    engine.propose(1);
    assert!(!engine.mempool.contains_key(&canonical), "consensus must remove the unfunded transaction");
    assert!(engine.is_rejected(&canonical, 1).is_some());
    assert_eq!(engine.state.validator_index_by_pubkey(&joining.pubkey), None);
}
