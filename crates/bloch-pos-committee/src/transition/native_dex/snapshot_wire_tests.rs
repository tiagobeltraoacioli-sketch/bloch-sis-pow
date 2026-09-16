use super::super::tests::{fixture, BoundVerifier, DOMAIN};
use super::super::tests::{key, signature};
use super::*;

fn populated() -> (CommittedState, NativeState) {
    let (state, _) = fixture();
    let (base, pinned) = state.into_parts();
    (base, pinned.state)
}

#[test]
fn replay_bound_restore_cannot_bootstrap_or_change_canonical_state() {
    struct ReplayVerifier;
    impl crate::SignatureVerifier for ReplayVerifier {
        fn verify_with_key(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            signature(root, key) == sig
        }
        fn valid_native_key(&self, key: &[u8]) -> bool {
            key.len() == 32 && key[0] != 0
        }
        fn verify_native_signature(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            signature(root, key) == sig
        }
    }
    let (mut base, native) = populated();
    let bytes = native.encode_snapshot().unwrap();
    assert_eq!(base.native_component_snapshot_bytes().unwrap(), None);
    assert!(base
        .with_restored_native_component(&bytes, &ReplayVerifier)
        .is_err());
    base.native_state = Some(native);
    let before = base.compute_root();
    let restored = base
        .with_restored_native_component(&bytes, &ReplayVerifier)
        .unwrap();
    assert_eq!(restored.compute_root(), before);
    assert_eq!(
        restored.native_component_snapshot_bytes().unwrap(),
        Some(bytes.clone())
    );
    let mut corrupt = bytes;
    corrupt[10] ^= 1;
    assert!(base
        .with_restored_native_component(&corrupt, &ReplayVerifier)
        .is_err());
    assert_eq!(base.compute_root(), before);
}

#[test]
fn deterministic_populated_roundtrip_preserves_native_commitment() {
    let (base, native) = populated();
    let bytes = native.encode_snapshot().unwrap();
    assert_eq!(bytes, native.clone().encode_snapshot().unwrap());
    assert_eq!(bytes, native.encode_snapshot_bounded(bytes.len()).unwrap());
    assert_eq!(
        native.encode_snapshot_bounded(bytes.len() - 1),
        Err(SnapshotError::ResourceLimit)
    );
    let restored =
        NativeState::restore_snapshot(&bytes, &base, native.commitment(), &BoundVerifier).unwrap();
    assert_eq!(native, restored);
    assert_eq!(bytes, restored.encode_snapshot().unwrap());
}

#[test]
fn malformed_transport_and_wrong_context_are_rejected_without_mutation() {
    let (base, native) = populated();
    let bytes = native.encode_snapshot().unwrap();
    let original = base.compute_root();
    for cut in 0..bytes.len() {
        assert!(NativeState::restore_snapshot(
            &bytes[..cut],
            &base,
            native.commitment(),
            &BoundVerifier
        )
        .is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        NativeState::restore_snapshot(&trailing, &base, native.commitment(), &BoundVerifier),
        Err(SnapshotError::InvalidEncoding)
    );
    let mut wrong_version = bytes.clone();
    wrong_version[8] = 2;
    assert_eq!(
        NativeState::restore_snapshot(&wrong_version, &base, native.commitment(), &BoundVerifier),
        Err(SnapshotError::InvalidEncoding)
    );
    assert_eq!(
        NativeState::restore_snapshot(&bytes, &base, [99; 32], &BoundVerifier),
        Err(SnapshotError::CommitmentMismatch)
    );
    let mut wrong_domain = base.clone();
    wrong_domain.admission_network_domain = Some([77; 32]);
    assert_eq!(
        NativeState::restore_snapshot(&bytes, &wrong_domain, native.commitment(), &BoundVerifier),
        Err(SnapshotError::WrongDomain)
    );
    assert_eq!(base.compute_root(), original);
}

#[test]
fn bounded_reader_refuses_forged_counts_before_allocating() {
    let encoded = u32::MAX.to_le_bytes();
    let mut reader = Reader {
        bytes: &encoded,
        offset: 0,
        allocations: 0,
    };
    assert!(Vec::<n::TokenSnapshot>::read(&mut reader).is_err());
    assert_eq!(reader.allocations, 0);
    let mut budget = MAX_DECODED_COLLECTION_BYTES - 1;
    assert_eq!(
        charge::<u64>(&mut budget, 1),
        Err(SnapshotError::ResourceLimit)
    );
    let overlarge = vec![0; MAX_SNAPSHOT_BYTES + 1];
    let (base, native) = populated();
    assert_eq!(
        NativeState::restore_snapshot(&overlarge, &base, native.commitment(), &BoundVerifier),
        Err(SnapshotError::ResourceLimit)
    );
}

#[test]
fn invalid_native_supply_and_duplicate_output_records_are_rejected() {
    let (base, native) = populated();
    let bytes = native.encode_snapshot().unwrap();
    for duplicate in [false, true] {
        let mut reader = Reader {
            bytes: &bytes,
            offset: 10,
            allocations: 0,
        };
        let mut payload = Payload::read(&mut reader).unwrap();
        if duplicate {
            let output = payload.native.gateway.native.outputs[0].clone();
            payload.native.gateway.native.outputs.push(output);
        } else {
            payload.native.gateway.native.tokens[0].1.supply += 1;
        }
        let mut writer = Writer::new(MAX_SNAPSHOT_BYTES);
        MAGIC.write(&mut writer).unwrap();
        1u16.write(&mut writer).unwrap();
        payload.write(&mut writer).unwrap();
        assert_eq!(
            NativeState::restore_snapshot(
                &writer.bytes,
                &base,
                native.commitment(),
                &BoundVerifier
            ),
            Err(SnapshotError::InvalidState)
        );
    }
}

#[test]
fn canonical_transport_rejects_rehearsal_fee_escrow() {
    let (_, mut native) = populated();
    native.base_fees = 1;
    assert_eq!(
        native.encode_snapshot(),
        Err(SnapshotError::NonCanonicalFees)
    );
    native.base_fees = 0;
    native.priority_fees = 1;
    assert_eq!(
        native.encode_snapshot(),
        Err(SnapshotError::NonCanonicalFees)
    );
    assert!(NativeState::empty(DOMAIN)
        .unwrap()
        .encode_snapshot()
        .is_ok());
}

#[test]
fn populated_custody_indexes_are_reconstructed_and_checked_against_base() {
    let (mut state, request) = super::super::initial_liquidity::tests::funded();
    state
        .execute_initial_liquidity(&request, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    // Test-only canonical fixture: production has no populated-state import.
    state.base_fees = 0;
    state.priority_fees = 0;
    let (base, pinned) = state.into_parts();
    let native = pinned.state;
    assert!(!native.base_locks.is_empty());
    assert!(!native.reserve_pools.is_empty());
    let bytes = native.encode_snapshot().unwrap();
    let restored =
        NativeState::restore_snapshot(&bytes, &base, native.commitment(), &BoundVerifier).unwrap();
    assert_eq!(restored, native);
    let (unrelated_base, _) = populated();
    assert!(NativeState::restore_snapshot(
        &bytes,
        &unrelated_base,
        native.commitment(),
        &BoundVerifier
    )
    .is_err());
    let mut corrupt = native.clone();
    corrupt.base_locks.clear();
    assert_eq!(
        NativeState::restore_snapshot(&bytes, &base, corrupt.commitment(), &BoundVerifier),
        Err(SnapshotError::CommitmentMismatch)
    );
}

#[test]
fn gateway_import_and_release_history_survive_restore_and_refuse_replay() {
    let gas = 100_000_000;
    let (base, _) = populated();
    let mut ledger = p::PoolLedger::new(DOMAIN);
    let registration = n::Registration {
        charter: m::TokenCharter {
            token_name: b"Snapshot bridge".to_vec(),
            modules: vec![m::ModuleKind::Supply(m::SupplyConfig {
                cap: 1_000_000,
                issuer_pubkey: key(1),
            })],
        },
        nonce: [1; 32],
        initial_kyc_root: None,
    };
    let sig = signature(&registration.signing_hash(&DOMAIN).unwrap(), &key(1));
    let asset = ledger
        .register(registration, &sig, &BoundVerifier, gas)
        .unwrap();
    let config = g::RouteConfig {
        route: g::Route {
            source_domain: [7; 32],
            native_domain: DOMAIN,
            native_asset: asset,
            token: [8; 20],
            vault: [9; 20],
            decimals: 6,
            cap: 1_000_000,
            vault_code_hash: [10; 32],
        },
        committee: vec![key(2), key(3)],
        threshold: 2,
    };
    let approvals = |message: &[u8]| vec![signature(message, &key(2)), signature(message, &key(3))];
    let message = config.signing_hash();
    ledger
        .enable(
            config.clone(),
            &signature(&message, &key(1)),
            &approvals(&message),
            &BoundVerifier,
            gas,
        )
        .unwrap();
    let import = g::ImportRequest {
        deposit: g::Deposit {
            route: config.route.id(),
            nonce: 1,
            sender: [11; 20],
            amount: 100,
            pq_recipient_hash: g::recipient_hash(&key(12)),
        },
        source_transaction: [13; 32],
        source_block: [14; 32],
        event_index: 0,
        valid_until: 100,
        transaction: n::Transaction {
            asset,
            inputs: vec![],
            outputs: vec![n::Output {
                owner: key(12),
                amount: 100,
            }],
            delta: 100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
    };
    let message = import.signing_hash(&DOMAIN).unwrap();
    let witness = n::Witnesses {
        owners: vec![],
        modules: vec![vec![bloch_euvm::Val::Bytes(signature(&message, &key(1)))]],
        eligibility: vec![],
    };
    let receipt = ledger
        .import(
            &import,
            &witness,
            &approvals(&message),
            1,
            &BoundVerifier,
            gas,
        )
        .unwrap();
    let withdraw = g::WithdrawalRequest {
        route: config.route.id(),
        nonce: 0,
        recipient: [15; 20],
        transaction: n::Transaction {
            asset,
            inputs: receipt.outputs,
            outputs: vec![],
            delta: -100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
    };
    let message = withdraw.signing_hash(&DOMAIN).unwrap();
    let burn = n::Witnesses {
        owners: vec![signature(&message, &key(12))],
        modules: vec![vec![bloch_euvm::Val::Bytes(signature(&message, &key(1)))]],
        eligibility: vec![],
    };
    ledger
        .withdraw(
            &withdraw,
            &burn,
            &approvals(&message),
            2,
            &BoundVerifier,
            gas,
        )
        .unwrap();
    let root = ledger.state_root();
    let state = State::from_parts(base.clone(), ledger, base.compute_root(), root).unwrap();
    let (_, pinned) = state.into_parts();
    let native = pinned.state;
    let mut restored = NativeState::restore_snapshot(
        &native.encode_snapshot().unwrap(),
        &base,
        native.commitment(),
        &BoundVerifier,
    )
    .unwrap();
    assert_eq!(restored, native);
    assert_eq!(
        restored
            .native
            .gateway()
            .route(&config.route.id())
            .unwrap()
            .burned,
        100
    );
    assert_eq!(
        restored
            .native
            .gateway()
            .release_record(&config.route.id(), 0)
            .unwrap()
            .recipient,
        [15; 20]
    );
    let message = import.signing_hash(&DOMAIN).unwrap();
    assert!(restored
        .native
        .import(
            &import,
            &witness,
            &approvals(&message),
            3,
            &BoundVerifier,
            gas
        )
        .is_err());
    assert_eq!(restored.commitment(), native.commitment());
}
