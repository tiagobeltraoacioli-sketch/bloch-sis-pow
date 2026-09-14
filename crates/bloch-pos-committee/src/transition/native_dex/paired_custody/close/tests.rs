use super::super::super::tests::{key, signature, BoundVerifier, DOMAIN};
use super::super::tests::setup;
use super::*;
use crate::transition::{TransferInputV2, TransferOutput};
fn funded_close() -> (State, CloseRequest) {
    let (mut state, create) = setup();
    let receipt = state
        .execute_paired_custody(&create, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let mut close = CloseRequest {
        reserve: receipt.reserve.id,
        creation_authorization: receipt.authorization,
        blch: create.blch,
        native: create.native,
        valid_until: 100,
        native_gas: 100_000,
    };
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut close.blch
    {
        *inputs = vec![
            TransferInputV2 {
                txid: receipt.blch_txid,
                vout: 0,
                key_index: RESERVE_KEY_INDEX,
            },
            TransferInputV2 {
                txid: receipt.blch_txid,
                vout: 1,
                key_index: 0,
            },
        ];
        *outputs = vec![
            TransferOutput {
                value: receipt.reserve.amount,
                script_hash: Sha3_256::digest(key(1)).into(),
            },
            TransferOutput {
                value: 1,
                script_hash: Sha3_256::digest(key(1)).into(),
            },
        ];
    }
    close.native.transaction.inputs = vec![receipt.native.outputs[0]];
    close.native.transaction.outputs.truncate(1);
    price(&state, &mut close);
    sign(&mut close);
    (state, close)
}
fn price(state: &State, r: &mut CloseRequest) {
    let len = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = len;
    }
    let fee = state.quote_paired_close(r).unwrap();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut r.blch
    {
        let p = &inputs[1];
        outputs[1].value = state.base.utxo(&p.txid, p.vout).unwrap().value
            - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
}
fn sign(r: &mut CloseRequest) {
    let auth = r.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = signature(&auth, &key(1));
    }
    r.native.witnesses.owners[0] = signature(&auth, &key(1));
}
#[test]
fn close_missing_fee_duplicate_reserve_output_collision_and_fee_overflow_rollback() {
    let (state, request) = funded_close();
    for variant in 0..4 {
        let mut state = state.clone();
        let mut r = request.clone();
        match variant {
            0 => {
                if let PosTransaction::TransferV2 { inputs, .. } = &mut r.blch {
                    inputs.pop();
                }
            }
            1 => {
                if let PosTransaction::TransferV2 { inputs, .. } = &mut r.blch {
                    inputs.push(inputs[0].clone());
                }
            }
            2 => {
                state.base.eutxos.insert(crate::state_root::EutxoEntry {
                    txid: r.output_txid(&DOMAIN).unwrap(),
                    vout: 0,
                    value: 1,
                    script_hash: [7; 32],
                });
            }
            _ => state.base_fees = u128::MAX,
        }
        let len = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
            *tx_bytes = len;
        }
        sign(&mut r);
        let root = state.state_root();
        let native = state.native().snapshot();
        assert!(state
            .execute_paired_close(&r, 1, &BoundVerifier, &BoundVerifier)
            .is_err());
        assert_eq!(state.state_root(), root);
        assert_eq!(state.native().snapshot(), native);
    }
}
#[test]
fn owned_native_view_and_snapshot_authenticate_paired_locks_and_reject_v2() {
    let (state, _) = funded_close();
    let view = state.native().snapshot();
    let root = state.native().state_root();
    let mut changed = state.clone();
    changed.paired_reserves.values_mut().next().unwrap().amount += 1;
    assert_ne!(changed.native().snapshot(), view);
    assert_ne!(changed.native().state_root(), root);
    let mut snapshot = state.snapshot();
    snapshot.version = 2;
    assert!(State::restore(snapshot, state.state_root(), &BoundVerifier).is_err());
    let mut snapshot = state.snapshot();
    snapshot.paired_reserves[0].outpoint.index = 1;
    assert!(State::restore(snapshot, state.state_root(), &BoundVerifier).is_err());
}
#[test]
fn closed_identifier_recreation_cannot_replay_previous_close_authorization() {
    let (mut state, close) = funded_close();
    let old = state.paired_reserves[&close.reserve].clone();
    let seed = state.base_reserves[&close.reserve].seed;
    let closed = state
        .execute_paired_close(&close, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let (_, mut create) = setup();
    create.seed = seed;
    create.native.transaction.inputs = vec![
        closed.native.outputs[0],
        OutPoint {
            transaction: old.outpoint.transaction,
            index: 1,
        },
    ];
    create.native.transaction.inputs.sort();
    create.native.witnesses.owners = vec![vec![0; 32]; 2];
    if let PosTransaction::TransferV2 { inputs, .. } = &mut create.blch {
        *inputs = vec![TransferInputV2 {
            txid: closed.blch_txid,
            vout: 1,
            key_index: 0,
        }];
    }
    let len = create.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut create.blch {
        *tx_bytes = len;
    }
    let fee = state.quote_paired_custody(&create).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut create.blch {
        outputs[1].value = state.base.utxo(&closed.blch_txid, 1).unwrap().value
            - create.blch_amount
            - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
    let auth = create.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut create.blch {
        keys[0].signature = signature(&auth, &key(1));
    }
    create.native.witnesses.owners = vec![signature(&auth, &key(1)); 2];
    let recreated = state
        .execute_paired_custody(&create, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(recreated.reserve.id, close.reserve);
    assert_ne!(recreated.authorization, close.creation_authorization);
    let root = state.state_root();
    assert!(state
        .execute_paired_close(&close, 1, &BoundVerifier, &BoundVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
}
