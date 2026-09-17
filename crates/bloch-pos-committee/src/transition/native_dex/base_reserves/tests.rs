use super::super::tests::{fixture, key, signature, BoundVerifier, COIN, DOMAIN};
use super::*;
use crate::transition::{TransferReject, WitnessKey};

fn sign(request: &mut Request) {
    let digest = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&digest, &keys[0].pubkey);
    }
}
fn price(state: &State, request: &mut Request, funding: u64, deposit: u64) {
    let len = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = len;
    }
    let charge = state.quote_base_reserve(request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[1].value =
            funding - deposit - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    sign(request);
}
fn create(state: &State, funding: OutPoint, seed: u8, amount: u64) -> Request {
    let id = reserve_id(&DOMAIN, &[seed; 32], &key(1)).unwrap();
    let mut request = Request {
        action: Action::Create {
            seed: [seed; 32],
            amount,
        },
        valid_until: 100,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: key(1),
                signature: vec![0; 32],
            }],
            inputs: vec![TransferInputV2 {
                txid: funding.0,
                vout: funding.1,
                key_index: 0,
            }],
            outputs: vec![
                TransferOutput {
                    value: amount,
                    script_hash: reserve_script(&DOMAIN, &id),
                },
                TransferOutput {
                    value: 0,
                    script_hash: Sha3_256::digest(key(1)).into(),
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 1,
        },
    };
    price(
        state,
        &mut request,
        state.base.utxo(&funding.0, funding.1).unwrap().value,
        amount,
    );
    request
}
fn continuation(state: &State, record: &Record, funding: OutPoint) -> Request {
    let mut request = Request {
        action: Action::Continue {
            reserve: record.id,
            revision: record.revision,
        },
        valid_until: 100,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: record.owner.clone(),
                signature: vec![0; 32],
            }],
            inputs: vec![
                TransferInputV2 {
                    txid: record.outpoint.0,
                    vout: record.outpoint.1,
                    key_index: RESERVE_KEY_INDEX,
                },
                TransferInputV2 {
                    txid: funding.0,
                    vout: funding.1,
                    key_index: 0,
                },
            ],
            outputs: vec![
                TransferOutput {
                    value: record.amount,
                    script_hash: reserve_script(&DOMAIN, &record.id),
                },
                TransferOutput {
                    value: 0,
                    script_hash: Sha3_256::digest(&record.owner).into(),
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 1,
        },
    };
    price(
        state,
        &mut request,
        state.base.utxo(&funding.0, funding.1).unwrap().value,
        0,
    );
    request
}
fn funded() -> (State, Receipt) {
    let (mut state, _) = fixture();
    let request = create(&state, ([8; 32], 0), 9, 10_000_000);
    let receipt = state
        .execute_base_reserve(&request, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    (state, receipt)
}
fn conserved(state: &State) {
    let coins: u128 = state
        .base
        .utxos()
        .map(|entry| u128::from(entry.value))
        .sum();
    let fees = state.fee_escrow();
    assert_eq!(coins + fees.0 + fees.1, u128::from(COIN));
}

#[test]
fn funding_locks_real_blch_and_never_changes_native_supply_or_state() {
    let (mut state, _) = fixture();
    let native_root = state.native.state_root();
    let request = create(&state, ([8; 32], 0), 9, 10_000_000);
    let receipt = state
        .execute_base_reserve(&request, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert!(state.base.utxo(&[8; 32], 0).is_none());
    assert_eq!(
        state.base.utxo(&receipt.blch_txid, 0).unwrap().value,
        10_000_000
    );
    assert!(state.base_is_locked(&receipt.reserve.outpoint));
    assert!(state
        .spendable_base_output(&receipt.reserve.outpoint)
        .is_none());
    assert!(state
        .spendable_base_output(&(receipt.blch_txid, 1))
        .is_some());
    assert_eq!(state.native.state_root(), native_root);
    conserved(&state);
}

#[test]
fn repeated_same_value_continuations_pay_from_separate_inputs_and_restore() {
    let (mut state, mut receipt) = funded();
    let native_root = state.native.state_root();
    for revision in 1..=3 {
        let old = receipt.reserve.clone();
        let funding = (receipt.blch_txid, 1);
        let old_funding = state.base.utxo(&funding.0, 1).unwrap().value;
        let request = continuation(&state, &old, funding);
        receipt = state
            .execute_base_reserve(&request, 3, &BoundVerifier, &BoundVerifier)
            .unwrap();
        assert_eq!(receipt.reserve.revision, revision);
        assert_eq!(receipt.reserve.amount, old.amount);
        assert!(state.base.utxo(&old.outpoint.0, old.outpoint.1).is_none());
        assert!(!state.base_is_locked(&old.outpoint));
        assert!(state.base_is_locked(&receipt.reserve.outpoint));
        assert_eq!(
            old_funding as u128 - state.base.utxo(&receipt.blch_txid, 1).unwrap().value as u128,
            receipt.charge.base_fee_sat + receipt.charge.priority_fee_sat
        );
        conserved(&state);
    }
    assert_eq!(state.native.state_root(), native_root);
    let restored = State::restore(state.snapshot(), state.state_root(), &BoundVerifier).unwrap();
    assert_eq!(restored.state_root(), state.state_root());
    assert_eq!(
        restored.base_reserve(&receipt.reserve.id),
        Some(&receipt.reserve)
    );
    assert!(restored
        .spendable_base_output(&receipt.reserve.outpoint)
        .is_none());
}

#[test]
fn ordinary_base_planner_has_no_reserve_authority_even_with_valid_owner_signature() {
    let (state, receipt) = funded();
    let mut request = continuation(&state, &receipt.reserve, (receipt.blch_txid, 1));
    let mut base = state.base.clone();
    assert!(matches!(
        base.plan_transfer_v2(&request.blch, base.next_base_fee(), &BoundVerifier),
        Err(TransferReject::BadKeyIndex)
    ));
    if let PosTransaction::TransferV2 { inputs, .. } = &mut request.blch {
        inputs[0].key_index = 0;
    }
    sign(&mut request);
    assert!(matches!(
        base.plan_transfer_v2(&request.blch, base.next_base_fee(), &BoundVerifier),
        Err(TransferReject::ScriptMismatch)
    ));
    assert_eq!(base, state.base);
}

#[test]
fn ordinary_joint_dispatch_refuses_locked_base_before_any_native_commit() {
    let (mut state, receipt) = funded();
    let (_, mut joint) = fixture();
    joint.blch = continuation(&state, &receipt.reserve, (receipt.blch_txid, 1)).blch;
    let before = state.state_root();
    assert!(matches!(
        state.execute(&joint, 3, &BoundVerifier, &BoundVerifier),
        Err(Error::LockedReserve)
    ));
    assert_eq!(state.state_root(), before);
}

#[test]
fn reserve_cannot_pay_fees_or_change_beneficiary() {
    let (mut state, receipt) = funded();
    for change_owner in [false, true] {
        let mut request = continuation(&state, &receipt.reserve, (receipt.blch_txid, 1));
        if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
            if change_owner {
                outputs[0].script_hash = Sha3_256::digest(key(1)).into();
            } else {
                outputs[0].value -= 1;
                outputs[1].value += 1;
            }
        }
        sign(&mut request);
        let before = state.state_root();
        assert!(matches!(
            state.execute_base_reserve(&request, 3, &BoundVerifier, &BoundVerifier),
            Err(Error::InvalidReserve)
        ));
        assert_eq!(state.state_root(), before);
    }
}

#[test]
fn reserve_only_and_duplicate_reserve_inputs_fail_without_mutation() {
    let (mut state, receipt) = funded();
    for duplicate in [false, true] {
        let mut request = continuation(&state, &receipt.reserve, (receipt.blch_txid, 1));
        if let PosTransaction::TransferV2 { inputs, .. } = &mut request.blch {
            if duplicate {
                inputs.push(inputs[0].clone());
            } else {
                inputs.pop();
            }
        }
        let length = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
            *tx_bytes = length;
        }
        sign(&mut request);
        let before = state.state_root();
        assert!(state
            .execute_base_reserve(&request, 3, &BoundVerifier, &BoundVerifier)
            .is_err());
        assert_eq!(state.state_root(), before);
    }
}

#[test]
fn forged_signature_wrong_owner_and_expiry_leave_locks_and_fees_unchanged() {
    let (mut state, receipt) = funded();
    let original = continuation(&state, &receipt.reserve, (receipt.blch_txid, 1));
    for kind in 0..4 {
        let mut request = original.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
            if kind == 0 {
                keys[0].signature[0] ^= 1;
            }
            if kind == 1 {
                keys[0].pubkey = key(2);
            }
        }
        if kind == 3 {
            let wrong_domain = request.authorization(&[43; 32]).unwrap();
            if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
                keys[0].signature = signature(&wrong_domain, &keys[0].pubkey);
            }
        }
        let before = state.state_root();
        assert!(state
            .execute_base_reserve(
                &request,
                if kind == 2 { 101 } else { 3 },
                &BoundVerifier,
                &BoundVerifier
            )
            .is_err());
        assert_eq!(state.state_root(), before);
    }
}

#[test]
fn replay_and_stale_revision_do_not_consume_new_fee_funding() {
    let (mut state, receipt) = funded();
    let request = continuation(&state, &receipt.reserve, (receipt.blch_txid, 1));
    let next = state
        .execute_base_reserve(&request, 3, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let before = state.state_root();
    assert!(matches!(
        state.execute_base_reserve(&request, 3, &BoundVerifier, &BoundVerifier),
        Err(Error::StaleReserve)
    ));
    let mut stale = continuation(&state, &next.reserve, (next.blch_txid, 1));
    if let Action::Continue { revision, .. } = &mut stale.action {
        *revision = 0;
    }
    sign(&mut stale);
    assert!(matches!(
        state.execute_base_reserve(&stale, 3, &BoundVerifier, &BoundVerifier),
        Err(Error::StaleReserve)
    ));
    assert_eq!(state.state_root(), before);
}

#[test]
fn snapshot_authentication_detects_omitted_forged_and_duplicated_reserves() {
    let (state, _) = funded();
    for kind in 0..7 {
        let mut snapshot = state.snapshot();
        match kind {
            0 => snapshot.base_reserves.clear(),
            1 => snapshot.base_reserves[0].amount += 1,
            2 => snapshot.base_reserves[0].owner = key(2),
            3 => snapshot.base_reserves[0].outpoint.0 = [255; 32],
            4 => snapshot
                .base_reserves
                .push(snapshot.base_reserves[0].clone()),
            5 => snapshot.base_reserves[0].revision += 1,
            _ => snapshot.version = 1,
        }
        assert!(
            State::restore(snapshot, state.state_root(), &BoundVerifier).is_err(),
            "tamper {kind}"
        );
    }
}

#[test]
fn a_different_reserve_cannot_be_used_as_fee_funding() {
    let (mut state, first) = funded();
    let request = create(&state, (first.blch_txid, 1), 10, 1_000_000);
    let second = state
        .execute_base_reserve(&request, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let request = continuation(&state, &first.reserve, second.reserve.outpoint);
    let before = state.state_root();
    assert!(matches!(
        state.execute_base_reserve(&request, 3, &BoundVerifier, &BoundVerifier),
        Err(Error::LockedReserve)
    ));
    assert_eq!(state.state_root(), before);
}

#[test]
fn bounded_reserve_count_and_duplicate_creation_fail_closed() {
    let (mut state, _) = fixture();
    let mut funding = ([8; 32], 0);
    for seed in 1..=MAX_RESERVES as u8 {
        let request = create(&state, funding, seed, 5000);
        let receipt = state
            .execute_base_reserve(&request, 2, &BoundVerifier, &BoundVerifier)
            .unwrap();
        funding = (receipt.blch_txid, 1);
    }
    let before = state.state_root();
    for seed in [1, MAX_RESERVES as u8 + 1] {
        let request = create(&state, funding, seed, 5000);
        assert!(state
            .execute_base_reserve(&request, 2, &BoundVerifier, &BoundVerifier)
            .is_err());
        assert_eq!(state.state_root(), before);
    }
    conserved(&state);
}

#[test]
fn output_collision_and_fee_overflow_do_not_partially_commit_custody() {
    let (mut state, _) = fixture();
    let request = create(&state, ([8; 32], 0), 9, 10_000_000);
    let txid = request.output_txid(&DOMAIN).unwrap();
    state.base.eutxos.insert(EutxoEntry {
        txid,
        vout: 0,
        value: 1,
        script_hash: Sha3_256::digest(key(1)).into(),
    });
    let before = state.state_root();
    assert!(matches!(
        state.execute_base_reserve(&request, 2, &BoundVerifier, &BoundVerifier),
        Err(Error::Base(TransferReject::OutputExists))
    ));
    assert_eq!(state.state_root(), before);
    assert!(state.base_reserves.is_empty());

    let (mut state, receipt) = funded();
    let request = continuation(&state, &receipt.reserve, (receipt.blch_txid, 1));
    state.base_fees = u128::MAX;
    let before = state.state_root();
    assert!(matches!(
        state.execute_base_reserve(&request, 3, &BoundVerifier, &BoundVerifier),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(state.state_root(), before);
    assert!(state.base_is_locked(&receipt.reserve.outpoint));
}
