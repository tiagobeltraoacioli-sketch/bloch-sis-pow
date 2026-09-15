use super::super::{
    initial_liquidity,
    pool_wire::Request,
    tests::{BoundVerifier, DOMAIN},
    PosTransaction,
};
use super::*;

fn sequence() -> (State, Vec<Vec<u8>>, State) {
    let (state, first) = initial_liquidity::tests::swap_fixture();
    let mut direct = state.clone();
    let receipt = direct
        .execute_blch_swap(&first, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let second = initial_liquidity::tests::swap_request(
        &direct,
        first.quote.pool,
        (receipt.blch_txid, 1),
        Some(receipt.native.outputs[1]),
        3,
        first.blch.clone(),
    );
    direct
        .execute_blch_swap(&second, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let frames = vec![
        pool_wire::encode(&Request::Swap(first), &DOMAIN).unwrap(),
        pool_wire::encode(&Request::Swap(second), &DOMAIN).unwrap(),
    ];
    (state, frames, direct)
}

struct NoCrypto;
impl SignatureVerifier for NoCrypto {
    fn verify_with_key(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> bool {
        panic!("preflight must precede crypto")
    }
}
impl Verifier for NoCrypto {
    fn valid_pq_key(&self, _: &[u8]) -> bool {
        panic!("preflight must precede key admission")
    }
    fn verify_pq(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
        panic!("preflight must precede crypto")
    }
}

#[test]
fn dependent_swaps_simulate_without_mutation_and_commit_together() {
    let (mut state, frames, direct) = sequence();
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    let root = state.state_root();
    let fees = state.fee_escrow();
    let preview = simulate(&state, &root, 1, &refs, &BoundVerifier, &BoundVerifier).unwrap();
    assert_eq!(state.state_root(), root);
    assert_eq!(state.fee_escrow(), fees);
    assert_eq!(preview.post_root, direct.state_root());
    assert_eq!(preview.receipts.len(), 2);
    assert_eq!(
        preview.wire_bytes,
        frames.iter().map(|f| f.len() as u64).sum()
    );
    let applied = apply(&mut state, &root, 1, &refs, &BoundVerifier, &BoundVerifier).unwrap();
    assert_eq!(applied.commitment, preview.commitment);
    assert_eq!(applied.charge, preview.charge);
    assert_eq!(state.state_root(), direct.state_root());
    assert_eq!(
        state.fee_escrow(),
        (
            fees.0 + applied.charge.base_fee_sat,
            fees.1 + applied.charge.priority_fee_sat
        )
    );
    assert!(matches!(
        apply(&mut state, &root, 1, &refs, &NoCrypto, &NoCrypto),
        Err(Error::WrongParent)
    ));
    let post = state.state_root();
    assert!(apply(&mut state, &post, 1, &refs, &BoundVerifier, &BoundVerifier).is_err());
    assert_eq!(state.state_root(), post);
}

#[test]
fn later_bad_signature_duplicate_or_order_rolls_back_every_operation() {
    let (mut state, frames, _) = sequence();
    let root = state.state_root();
    let fees = state.fee_escrow();
    let mut bad = pool_wire::decode(&frames[1], &DOMAIN).unwrap();
    if let Request::Swap(r) = &mut bad {
        if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
            keys[0].signature[0] ^= 1;
        }
    }
    let bad = pool_wire::encode(&bad, &DOMAIN).unwrap();
    for (refs, index) in [
        (vec![frames[0].as_slice(), bad.as_slice()], 1),
        (vec![frames[0].as_slice(), frames[0].as_slice()], 1),
        (vec![frames[1].as_slice(), frames[0].as_slice()], 0),
    ] {
        assert!(
            matches!(apply(&mut state, &root, 1, &refs, &BoundVerifier, &BoundVerifier), Err(Error::Operation { index: i, .. }) if i == index)
        );
        assert_eq!(state.state_root(), root);
        assert_eq!(state.fee_escrow(), fees);
    }
}

#[test]
fn count_wire_size_and_malformed_later_frame_reject_before_crypto() {
    let (mut state, frames, _) = sequence();
    let root = state.state_root();
    assert!(matches!(
        apply(&mut state, &root, 1, &[], &NoCrypto, &NoCrypto),
        Err(Error::Empty)
    ));
    assert!(matches!(
        apply(
            &mut state,
            &root,
            1,
            &vec![frames[0].as_slice(); MAX_OPERATIONS + 1],
            &NoCrypto,
            &NoCrypto
        ),
        Err(Error::TooManyOperations)
    ));
    let large = vec![0; MAX_BYTES as usize + 1];
    assert!(matches!(
        apply(&mut state, &root, 1, &[&large], &NoCrypto, &NoCrypto),
        Err(Error::BytesLimit)
    ));
    assert!(matches!(
        apply(
            &mut state,
            &root,
            1,
            &[&frames[0], &frames[1][..20]],
            &NoCrypto,
            &NoCrypto
        ),
        Err(Error::Operation { index: 1, .. })
    ));
    assert_eq!(state.state_root(), root);
}

#[test]
fn aggregate_declared_bytes_and_gas_are_capped_before_crypto() {
    let (mut state, mut initial) = initial_liquidity::tests::funded();
    let length = initial.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut initial.blch {
        *tx_bytes = length + fee_market::TX_BYTES_DECLARE_SLACK;
    }
    let frame = pool_wire::encode(&Request::Initialize(initial), &DOMAIN).unwrap();
    let charge = pool_wire::quote_encoded(&state, &frame).unwrap();
    let count = (MAX_BYTES / charge.tx_bytes + 1) as usize;
    assert!(count <= MAX_OPERATIONS && count * frame.len() <= MAX_BYTES as usize);
    let root = state.state_root();
    assert!(matches!(
        apply(
            &mut state,
            &root,
            1,
            &vec![frame.as_slice(); count],
            &NoCrypto,
            &NoCrypto
        ),
        Err(Error::BytesLimit)
    ));
    assert_eq!(state.state_root(), root);
    let (mut state, mut swap) = initial_liquidity::tests::swap_fixture();
    swap.native_gas = MAX_GAS / (2 * super::super::NATIVE_GAS_MULTIPLIER) + 1;
    let frame = pool_wire::encode(&Request::Swap(swap), &DOMAIN).unwrap();
    let charge = pool_wire::quote_encoded(&state, &frame).unwrap();
    assert!(charge.gas <= MAX_GAS && charge.gas * 2 > MAX_GAS);
    let root = state.state_root();
    assert!(matches!(
        apply(
            &mut state,
            &root,
            1,
            &[&frame, &frame],
            &NoCrypto,
            &NoCrypto
        ),
        Err(Error::GasLimit)
    ));
    assert_eq!(state.state_root(), root);
}

#[test]
fn restored_parent_reexecutes_identically_and_preview_cannot_bypass_freshness() {
    let (mut state, frames, direct) = sequence();
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    let root = state.state_root();
    let snapshot = state.snapshot();
    let a = simulate(&state, &root, 1, &refs, &BoundVerifier, &BoundVerifier).unwrap();
    let b = simulate(&state, &root, 2, &refs, &BoundVerifier, &BoundVerifier).unwrap();
    assert_ne!(a.commitment, b.commitment);
    assert!(apply(
        &mut state,
        &root,
        101,
        &refs,
        &BoundVerifier,
        &BoundVerifier
    )
    .is_err());
    assert_eq!(state.state_root(), root);
    apply(&mut state, &root, 1, &refs, &BoundVerifier, &BoundVerifier).unwrap();
    let mut restored = State::restore(snapshot, root, &BoundVerifier).unwrap();
    let replay = apply(
        &mut restored,
        &root,
        1,
        &refs,
        &BoundVerifier,
        &BoundVerifier,
    )
    .unwrap();
    assert_eq!(a.commitment, replay.commitment);
    assert_eq!(restored.state_root(), direct.state_root());
    assert_eq!(restored.native().snapshot(), state.native().snapshot());
    assert_eq!(restored.base(), state.base());
}
