use super::super::tests::{fixture, key, signature, BoundVerifier, COIN, DOMAIN};
use super::*;
use crate::transition::PosTransaction;
use bloch_euvm::ustav::gateway as g;
use bloch_euvm::ustav::gateway::pools as p;
use bloch_euvm::{modules as m, ustav as n, Val};
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
const GAS: u64 = 1_000_000;
const PRICE: u128 = 200;
pub(in crate::transition) fn fixture_import() -> (CommittedState, gateway::Request) {
    let (original, template) = fixture();
    let (base, _) = original.into_parts();
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
        .register(registration, &sig, &BoundVerifier, GAS)
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
            GAS,
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

    let root = ledger.state_root();
    let state = State::from_parts(base.clone(), ledger, base.compute_root(), root).unwrap();
    let mut request = gateway::Request {
        blch: template.blch,
        gateway: g::wire::Envelope {
            domain: DOMAIN,
            operation: Operation::Import(import),
            witnesses: n::Witnesses {
                owners: vec![],
                modules: vec![vec![Val::Bytes(vec![0; 32])]],
                eligibility: vec![],
            },
            approvals: vec![vec![0; 32], vec![0; 32]],
        },
        valid_until: 100,
        native_gas: 100_000,
    };
    price_sign(&state, &mut request, COIN);
    let (mut base, pinned) = state.into_parts();
    base.native_state = Some(pinned.state);
    (base, request)
}
fn price_sign(state: &State, request: &mut gateway::Request, balance: u64) {
    let len = request.canonical_bytes(&DOMAIN).unwrap().len() as u64 + OUTER_BYTES;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = len;
    }
    let charge = state
        .quote_gateway_with_context(request, PRICE, OUTER_BYTES)
        .unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[0].value = balance - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    sign(request);
}
fn sign(request: &mut gateway::Request) {
    let message = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&message, &keys[0].pubkey);
    }
    request.gateway.witnesses.modules[0] = vec![Val::Bytes(signature(&message, &key(1)))];
    request.gateway.approvals = vec![signature(&message, &key(2)), signature(&message, &key(3))];
    if !request.gateway.witnesses.owners.is_empty() {
        request.gateway.witnesses.owners = vec![signature(&message, &key(12))];
    }
}
fn apply(
    base: &mut CommittedState,
    request: &gateway::Request,
    slot: u64,
    import: bool,
) -> Result<TxCharge, Error> {
    apply_gateway(
        base,
        &request.canonical_bytes(&DOMAIN).unwrap(),
        slot,
        PRICE,
        &BoundVerifier,
        &BoundVerifier,
        import,
    )
}
#[test]
fn canonical_import_binds_price_outer_frame_and_replays_atomically() {
    let (mut base, request) = fixture_import();
    let before = base.clone();
    let charge = apply(&mut base, &request, 1, true).unwrap();
    assert_eq!(
        charge.tx_bytes,
        request.canonical_bytes(&DOMAIN).unwrap().len() as u64 + OUTER_BYTES
    );
    let component = base.native_state.as_ref().unwrap();
    assert_eq!((component.base_fees, component.priority_fees), (0, 0));
    assert_ne!(base.compute_root(), before.compute_root());
    let after = base.clone();
    assert!(apply(&mut base, &request, 1, true).is_err());
    assert_eq!(base, after);
    let restored = after
        .with_restored_native_component(
            &after.native_component_snapshot_bytes().unwrap().unwrap(),
            &ReplayVerifier,
        )
        .unwrap();
    assert_eq!(restored, after);
    let mut fork = before;
    apply(&mut fork, &request, 1, true).unwrap();
    assert_eq!(fork, after);
}
#[test]
fn malformed_expired_wrong_tag_and_forged_quorum_preserve_state() {
    let (base, request) = fixture_import();
    for case in 0..5 {
        let mut attempt = base.clone();
        let mut bad = request.clone();
        match case {
            0 => {
                bad.gateway.approvals[1][0] ^= 1;
            }
            1 => {
                bad.gateway.witnesses.modules[0] = vec![Val::Bytes(vec![0; 32])];
            }
            2 => {}
            3 => {}
            _ => {
                if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut bad.blch {
                    *tx_bytes -= OUTER_BYTES;
                }
                sign(&mut bad);
            }
        }
        assert!(apply(
            &mut attempt,
            &bad,
            if case == 2 { 101 } else { 1 },
            case != 3
        )
        .is_err());
        assert_eq!(attempt, base);
    }
    let mut attempt = base.clone();
    assert!(apply_import(
        &mut attempt,
        &[0; 8],
        1,
        PRICE,
        &BoundVerifier,
        &BoundVerifier
    )
    .is_err());
    assert_eq!(attempt, base);
}

#[test]
fn canonical_withdrawal_burns_once_and_preserves_release_across_restart() {
    let (mut base, mut request) = fixture_import();
    apply(&mut base, &request, 1, true).unwrap();
    let imported = base.clone();
    let minted = base
        .native_state
        .as_ref()
        .unwrap()
        .native
        .gateway()
        .native()
        .snapshot()
        .outputs[0]
        .0
        .clone();
    let Operation::Import(import) = request.gateway.operation.clone() else {
        unreachable!()
    };
    let sponsor_txid = request.output_txid(&DOMAIN).unwrap();
    let balance = base.utxo(&sponsor_txid, 0).unwrap().value;
    if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut request.blch {
        keys[0].pubkey = key(3);
        inputs[0].txid = sponsor_txid;
    }
    request.gateway.operation = Operation::Withdraw(g::WithdrawalRequest {
        route: import.deposit.route,
        nonce: 0,
        recipient: [15; 20],
        transaction: n::Transaction {
            asset: import.transaction.asset,
            inputs: vec![minted],
            outputs: vec![],
            delta: -100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
    });
    request.gateway.witnesses.owners = vec![vec![0; 32]];
    let native = base.native_state.as_ref().unwrap();
    let mut projection = base.clone();
    projection.native_state = None;
    let state = State::from_parts(
        projection.clone(),
        native.native.clone(),
        projection.compute_root(),
        native.native.state_root(),
    )
    .unwrap();
    price_sign(&state, &mut request, balance);
    assert!(apply(&mut base, &request, 2, true).is_err());
    assert_eq!(base, imported);
    apply(&mut base, &request, 2, false).unwrap();
    let native = base.native_state.as_ref().unwrap();
    assert_eq!(
        native
            .native
            .gateway()
            .route(&import.deposit.route)
            .unwrap()
            .burned,
        100
    );
    assert_eq!(
        native
            .native
            .gateway()
            .release_record(&import.deposit.route, 0)
            .unwrap()
            .recipient,
        [15; 20]
    );
    let after = base.clone();
    assert!(apply(&mut base, &request, 2, false).is_err());
    assert_eq!(base, after);
    let bytes = base.native_component_snapshot_bytes().unwrap().unwrap();
    let mut restored = base
        .with_restored_native_component(&bytes, &ReplayVerifier)
        .unwrap();
    assert_eq!(restored, base);
    assert!(apply(&mut restored, &request, 2, false).is_err());
    assert_eq!(restored, base);
}

pub(in crate::transition) fn funded_import(price: u128) -> (CommittedState, gateway::Request) {
    let (mut base, mut request) = fixture_import();
    let native = base.native_state.as_ref().unwrap();
    let mut projection = base.clone();
    projection.native_state = None;
    let state = State::from_parts(
        projection.clone(),
        native.native.clone(),
        projection.compute_root(),
        native.native.state_root(),
    )
    .unwrap();
    let charge = state
        .quote_gateway_with_context(&request, price, OUTER_BYTES)
        .unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[0].value = COIN - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    sign(&mut request);
    base.native_state = Some(native.clone());
    (base, request)
}

pub(in crate::transition) fn withdrawal_for(
    base: &CommittedState,
    mut request: gateway::Request,
    price: u128,
) -> gateway::Request {
    let minted = base
        .native_state
        .as_ref()
        .unwrap()
        .native
        .gateway()
        .native()
        .snapshot()
        .outputs[0]
        .0
        .clone();
    let Operation::Import(import) = request.gateway.operation.clone() else {
        unreachable!()
    };
    let sponsor_txid = request.output_txid(&DOMAIN).unwrap();
    let balance = base.utxo(&sponsor_txid, 0).unwrap().value;
    if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut request.blch {
        keys[0].pubkey = key(3);
        inputs[0].txid = sponsor_txid;
    }
    request.gateway.operation = Operation::Withdraw(g::WithdrawalRequest {
        route: import.deposit.route,
        nonce: 0,
        recipient: [15; 20],
        transaction: n::Transaction {
            asset: import.transaction.asset,
            inputs: vec![minted],
            outputs: vec![],
            delta: -100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
    });
    request.gateway.witnesses.owners = vec![vec![0; 32]];
    let native = base.native_state.as_ref().unwrap();
    let mut projection = base.clone();
    projection.native_state = None;
    let state = State::from_parts(
        projection.clone(),
        native.native.clone(),
        projection.compute_root(),
        native.native.state_root(),
    )
    .unwrap();
    price_sign(&state, &mut request, balance);

    let charge = state
        .quote_gateway_with_context(&request, price, OUTER_BYTES)
        .unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[0].value = balance - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    sign(&mut request);
    request
}
