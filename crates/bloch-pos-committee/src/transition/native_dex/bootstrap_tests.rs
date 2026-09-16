use super::super::{
    tests::{key, signature, BoundVerifier, COIN, DOMAIN},
    NativeState,
};
use super::*;
use crate::interfaces::StateReader;
pub(in crate::transition) fn fixture(fee: u128) -> (CommittedState, Request) {
    let (state, old) = super::super::tests::fixture();
    let (mut base, _) = state.into_parts();
    base.native_state = Some(NativeState::empty(DOMAIN).unwrap());
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"Bootstrap".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: key(2),
            })],
        },
        nonce: [7; 32],
        initial_kyc_root: None,
    };
    let asset = registration.asset_id(&DOMAIN).unwrap();
    let mut request = Request {
        domain: DOMAIN,
        blch: old.blch,
        registration,
        route: RouteConfig {
            route: Route {
                source_domain: [9; 32],
                native_domain: DOMAIN,
                native_asset: asset,
                token: [3; 20],
                vault: [4; 20],
                decimals: 6,
                cap: 1000,
                vault_code_hash: [5; 32],
            },
            committee: vec![key(4), key(5)],
            threshold: 2,
        },
        valid_until: 10000,
        native_gas: 100_000,
        issuer_signature: vec![0; 32],
        approvals: vec![vec![0; 32]; 2],
    };
    let size = request.canonical_bytes().unwrap().len() as u64 + 5;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = size;
    }
    let charge = request.quote(fee).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[0].value = COIN - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    sign(&mut request);
    (base, request)
}
fn sign(request: &mut Request) {
    let hash = request.authorization().unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&hash, &key(1));
    }
    request.issuer_signature = signature(&hash, &key(2));
    request.approvals = vec![signature(&hash, &key(4)), signature(&hash, &key(5))];
}
pub(in crate::transition) fn assert_registered(base: &CommittedState, r: &Request) {
    let ledger = base.native_state.as_ref().unwrap().native.gateway();
    assert_eq!(ledger.native().supply(&r.route.route.native_asset), Some(0));
    assert_eq!(
        ledger.native().next_mint_nonce(&r.route.route.native_asset),
        Some(0)
    );
    assert!(ledger.route(&r.route.route.id()).is_some());
}
fn apply(base: &mut CommittedState, r: &Request) -> Result<fee_market::TxCharge, Error> {
    apply_bootstrap(
        base,
        &r.canonical_bytes()?,
        1,
        fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
        &BoundVerifier,
        &BoundVerifier,
    )
}
#[test]
fn bootstrap_atomic_zero_supply_and_replay_refusal() {
    let (mut base, r) = fixture(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS);
    apply(&mut base, &r).unwrap();
    assert_registered(&base, &r);
    let root = base.state_root();
    assert!(apply(&mut base, &r).is_err());
    assert_eq!(base.state_root(), root);
}
#[test]
fn bootstrap_every_authority_and_route_mutation_rejected_atomically() {
    let (base, r) = fixture(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS);
    for n in 0..6 {
        let mut bad = r.clone();
        match n {
            0 => bad.issuer_signature[0] ^= 1,
            1 => bad.approvals[0][0] ^= 1,
            2 => {
                if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
                    keys[0].signature[0] ^= 1
                }
            }
            3 => bad.route.route.vault[0] ^= 1,
            4 => bad.valid_until = 0,
            _ => bad.native_gas = 2,
        };
        let mut staged = base.clone();
        assert!(apply(&mut staged, &bad).is_err(), "case {n}");
        assert_eq!(staged.state_root(), base.state_root());
        assert_eq!(staged.native_state, base.native_state);
    }
}
#[test]
fn bootstrap_codec_rejects_truncation_trailing_and_oversize() {
    let (_, r) = fixture(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS);
    let bytes = r.canonical_bytes().unwrap();
    assert_eq!(decode(&bytes).unwrap().canonical_bytes().unwrap(), bytes);
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(decode(&bad).is_err());
    assert!(decode(&vec![0; MAX_BYTES + 1]).is_err());
}

#[test]
fn bootstrap_signed_invalid_route_and_insufficient_budget_are_atomic() {
    let (base, request) = fixture(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS);
    for case in 0..4 {
        let mut bad = request.clone();
        match case {
            0 => bad.route.route.decimals = 18,
            1 => bad.route.route.source_domain = DOMAIN,
            2 => bad.route.route.cap = 1001,
            _ => bad.native_gas = 2,
        }
        sign(&mut bad);
        let mut staged = base.clone();
        assert!(apply(&mut staged, &bad).is_err());
        assert_eq!(staged.state_root(), base.state_root());
        assert_eq!(staged.native_state, base.native_state);
    }
}
