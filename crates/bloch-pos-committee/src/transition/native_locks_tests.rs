// Canonical locks reject otherwise valid ordinary spends atomically.
fn lock(state: &mut CommittedState, point: ([u8; 32], u32)) {
    let mut native = native_dex::NativeState::empty([0x91; 32]).unwrap();
    native.test_lock_base(point);
    state.native_state = Some(native);
}

#[test]
fn native_locks_reject_mixed_transfers_in_either_order() {
    let owner = owner_key(0x31);
    let coins = [
        opening(0x71, 0, 1_000_000_000, &owner),
        opening(0x72, 0, 1_000_000_000, &owner),
    ];
    for reverse in [false, true] {
        let entries = if reverse {
            vec![coins[1].clone(), coins[0].clone()]
        } else {
            coins.to_vec()
        };
        for v2 in [false, true] {
            let (_, mut state, _) = setup_funded(4, &coins);
            let price = state.next_base_fee();
            let tx = if v2 {
                transfer_v2_raw(
                    &entries,
                    &[&owner],
                    &[0, 0],
                    script_of(&owner),
                    256,
                    0,
                    price,
                )
            } else {
                transfer_spending(&entries, &owner, script_of(&owner), 256, 0, price)
            };
            // Control proves conservation and signatures really pass absent the lock.
            let mut control = state.clone();
            if v2 {
                control.apply_transfer_v2(&tx, price, &ToyVerifier).unwrap();
            } else {
                control.apply_transfer(&tx, price, &ToyVerifier).unwrap();
            }
            let accounted = state.accounted_supply_sat();
            lock(&mut state, (coins[1].txid, coins[1].vout));
            assert_eq!(
                state.accounted_supply_sat(),
                accounted,
                "metadata must not double-count custody"
            );
            let before = state.clone();
            let root = state.compute_root();
            let result = if v2 {
                state.apply_transfer_v2(&tx, price, &ToyVerifier)
            } else {
                state.apply_transfer(&tx, price, &ToyVerifier)
            };
            assert_eq!(result, Err(TransferReject::LockedNativeReserve));
            assert_eq!(state, before);
            assert_eq!(state.compute_root(), root);
            let ordinary = if v2 {
                transfer_v2_raw(
                    &coins[..1],
                    &[&owner],
                    &[0],
                    script_of(&owner),
                    256,
                    0,
                    price,
                )
            } else {
                transfer_spending(&coins[..1], &owner, script_of(&owner), 256, 0, price)
            };
            if v2 {
                state
                    .apply_transfer_v2(&ordinary, price, &ToyVerifier)
                    .unwrap();
            } else {
                state
                    .apply_transfer(&ordinary, price, &ToyVerifier)
                    .unwrap();
            }
            assert_eq!(state.native_state, before.native_state);
            assert!(state.utxo(&coins[1].txid, coins[1].vout).is_some());
        }
    }
}

#[test]
fn native_locks_reject_mixed_validator_funding() {
    use super::funded_admission as f;
    crate::params::funded_admission_rehearsal::run(|| {
        let mut tx = f::deposit(20);
        tx.inputs.push(FundingInput {
            txid: [21; 32],
            vout: 0,
        });
        f::authorize(&mut tx);
        let (_, mut state, _) = f::fixture(&[tx.clone()]);
        let mut first = state.utxo(&[20; 32], 0).unwrap().clone();
        first.value -= 100_000;
        state.eutxos.insert(first.clone());
        let second = crate::state_root::EutxoEntry {
            txid: [21; 32],
            vout: 0,
            value: 100_000,
            script_hash: first.script_hash,
        };
        state.eutxos.insert(second.clone());
        let mut control = state.clone();
        f::apply(&mut control, &tx).unwrap();
        for point in [(first.txid, 0), (second.txid, 0)] {
            let mut locked = state.clone();
            lock(&mut locked, point);
            let before = locked.clone();
            assert_eq!(
                f::apply(&mut locked, &tx),
                Err(TxReject::FundedDeposit(
                    FundedDepositReject::LockedNativeReserve
                ))
            );
            assert_eq!(locked, before);
            assert_eq!(locked.compute_root(), before.compute_root());
        }
    });
}

#[test]
fn native_locks_reject_joint_context_in_ordinary_planner() {
    let owner = owner_key(0x31);
    let coins = [
        opening(0x71, 0, 1_000_000_000, &owner),
        opening(0x72, 0, 1_000_000_000, &owner),
    ];
    let (_, mut state, _) = setup_funded(4, &coins);
    let price = state.next_base_fee();
    let tx = transfer_v2_raw(&coins, &[&owner], &[0, 0], script_of(&owner), 256, 0, price);
    let charge = state
        .clone()
        .apply_transfer_v2(&tx, price, &ToyVerifier)
        .unwrap();
    lock(&mut state, (coins[1].txid, 0));
    let before = state.clone();
    let context = JointTransferContext {
        envelope_bytes: tx.canonical_bytes().len() as u64,
        output_txid: tx.txid(),
        charge,
        authorization: tx.spend_signing_root(),
        reserve: None,
    };
    let result = state.plan_transfer_v2_with_context(&tx, price, &ToyVerifier, Some(context));
    assert!(matches!(result, Err(TransferReject::LockedNativeReserve)));
    drop(result);
    assert_eq!(state, before);
}
