use super::super::tests::{fixture, key, signature, BoundVerifier, COIN, DOMAIN};
use super::*;
use crate::transition::{TransferOutput, WitnessKey};

pub(super) fn setup() -> (State, Request) {
    let (state, joint) = fixture();
    let mut native = state.native().clone();
    let mut envelope = joint.native;
    let hash = envelope.transaction.signing_hash(&DOMAIN).unwrap();
    envelope.witnesses.owners[0] = signature(&hash, &key(3));
    let receipt = native
        .apply(
            &envelope.transaction,
            &envelope.witnesses,
            1,
            &BoundVerifier,
            1_000_000,
        )
        .unwrap();
    envelope.transaction.inputs = receipt.outputs;
    envelope.transaction.outputs = vec![
        bloch_euvm::ustav::Output {
            owner: key(1),
            amount: 60,
        },
        bloch_euvm::ustav::Output {
            owner: key(1),
            amount: 40,
        },
    ];
    let base = state.base().clone();
    let state = State::from_parts(
        base.clone(),
        native.clone(),
        base.compute_root(),
        native.state_root(),
    )
    .unwrap();
    let seed = [44; 32];
    let id = reserve_id(&DOMAIN, &seed, &key(1)).unwrap();
    let mut request = Request {
        blch: joint.blch,
        native: envelope,
        seed,
        blch_amount: 1_000_000,
        native_amount: 60,
        valid_until: 100,
        native_gas: 100_000,
    };
    if let PosTransaction::TransferV2 { keys, outputs, .. } = &mut request.blch {
        *keys = vec![WitnessKey {
            pubkey: key(1),
            signature: vec![0; 32],
        }];
        *outputs = vec![
            TransferOutput {
                value: request.blch_amount,
                script_hash: reserve_script(&DOMAIN, &id),
            },
            TransferOutput {
                value: 1,
                script_hash: Sha3_256::digest(key(1)).into(),
            },
        ];
    }
    price(&state, &mut request);
    sign(&mut request);
    (state, request)
}
fn price(state: &State, r: &mut Request) {
    let len = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = len;
    }
    let fee = state.quote_paired_custody(r).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut r.blch {
        outputs[1].value = COIN - r.blch_amount - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
}
fn sign(r: &mut Request) {
    let hash = r.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = signature(&hash, &key(1));
    }
    r.native.witnesses.owners[0] = signature(&hash, &key(1));
}
#[test]
fn native_planner_requires_explicit_custody_consent_and_dropped_plan_is_atomic() {
    let (state, r) = setup();
    let mut native = state.native().clone();
    let tx = &r.native.transaction;
    let hash = tx.signing_hash(&DOMAIN).unwrap();
    let record = custody::Record {
        id: [55; 32],
        authorization: [66; 32],
        asset: tx.asset,
        owner: key(1),
        amount: 60,
        outpoint: OutPoint {
            transaction: hash,
            index: 0,
        },
    };
    let mut w = r.native.witnesses.clone();
    w.owners[0] = signature(&hash, &key(1));
    let root = native.state_root();
    assert!(native
        .plan_custody(record.clone(), tx, &w, 1, &BoundVerifier, 100_000)
        .is_err());
    assert_eq!(native.state_root(), root);
    let auth = custody::signing_hash(&record, &hash, &DOMAIN).unwrap();
    w.owners[0] = signature(&auth, &key(1));
    drop(
        native
            .plan_custody(record.clone(), tx, &w, 1, &BoundVerifier, 100_000)
            .unwrap(),
    );
    assert_eq!(native.state_root(), root);
    let mut forged = record.clone();
    forged.authorization[0] ^= 1;
    assert!(native
        .plan_custody(forged, tx, &w, 1, &BoundVerifier, 100_000)
        .is_err());
    assert_eq!(native.state_root(), root);
    native
        .plan_custody(record.clone(), tx, &w, 1, &BoundVerifier, 100_000)
        .unwrap()
        .commit();
    assert!(native.is_locked(&record.outpoint));
    assert!(native.spendable_output(&record.outpoint).is_none());
    let restored =
        PoolLedger::restore(native.snapshot(), native.state_root(), &BoundVerifier).unwrap();
    assert!(restored.is_locked(&record.outpoint));
    assert!(State::from_parts(
        state.base().clone(),
        restored,
        state.base().compute_root(),
        native.state_root()
    )
    .is_err());
}
#[test]
fn paired_creation_replay_and_tampered_snapshots_fail_closed() {
    let (mut state, r) = setup();
    let result = state
        .execute_paired_custody(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let root = state.state_root();
    assert!(state
        .execute_paired_custody(&r, 1, &BoundVerifier, &BoundVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    let snapshot = state.snapshot();
    for variant in 0..7 {
        let mut bad = snapshot.clone();
        match variant {
            0 => bad.native.custody.clear(),
            1 => bad.native.custody[0].authorization[0] ^= 1,
            2 => bad.native.custody[0].owner = key(2),
            3 => bad.native.custody[0].amount += 1,
            4 => bad.native.custody.push(bad.native.custody[0].clone()),
            5 => bad.base_reserves.clear(),
            _ => bad.base_reserves[0].revision += 1,
        }
        assert!(State::restore(bad, root, &BoundVerifier).is_err());
    }
    let restored = State::restore(snapshot, root, &BoundVerifier).unwrap();
    assert_eq!(
        restored.paired_custody(&result.reserve.id).unwrap().amount,
        60
    );
}
#[test]
fn paired_continuation_and_joint_native_spend_cannot_escape_locks() {
    let (mut state, r) = setup();
    let receipt = state
        .execute_paired_custody(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let root = state.state_root();
    let mut continuation = base_reserves::Request {
        action: base_reserves::Action::Continue {
            reserve: receipt.reserve.id,
            revision: 0,
        },
        valid_until: 100,
        blch: r.blch.clone(),
    };
    let len = continuation.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut continuation.blch {
        *tx_bytes = len;
    }
    assert!(matches!(
        state.execute_base_reserve(&continuation, 1, &BoundVerifier, &BoundVerifier),
        Err(Error::LockedReserve)
    ));
    assert_eq!(state.state_root(), root);
    let mut native = state.native().clone();
    let mut tx = r.native.transaction.clone();
    tx.inputs = vec![receipt.native.outputs[0]];
    tx.outputs.truncate(1);
    let hash = tx.signing_hash(&DOMAIN).unwrap();
    let mut w = r.native.witnesses.clone();
    w.owners[0] = signature(&hash, &key(1));
    assert!(matches!(
        native.apply(&tx, &w, 1, &BoundVerifier, 100_000),
        Err(PoolError::LockedInput)
    ));
    assert!(matches!(
        native.plan_transfer(&tx, &w, 1, &BoundVerifier, 100_000),
        Err(PoolError::LockedInput)
    ));
}
#[test]
fn expired_wrong_domain_fee_overflow_and_exhausted_gas_leave_both_sides_unchanged() {
    let (state, r) = setup();
    for variant in 0..4 {
        let mut state = state.clone();
        let mut r = r.clone();
        match variant {
            0 => r.valid_until = 0,
            1 => r.native.domain = [99; 32],
            2 => state.base_fees = u128::MAX,
            _ => r.native_gas = 1,
        }
        let root = state.state_root();
        assert!(state
            .execute_paired_custody(&r, 1, &BoundVerifier, &BoundVerifier)
            .is_err());
        assert_eq!(state.state_root(), root);
    }
}
#[test]
fn signing_and_encoding_reject_oversized_base_shape_before_copying() {
    let (_, mut r) = setup();
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = vec![0; MAX_BASE_WITNESS_BYTES + 1];
    }
    assert!(matches!(
        r.canonical_bytes(&DOMAIN),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        r.authorization(&DOMAIN),
        Err(Error::ResourceLimit)
    ));
}
