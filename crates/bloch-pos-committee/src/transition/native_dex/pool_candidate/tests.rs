use super::super::{
    pool_batch::tests::{sequence, NoCrypto},
    pool_wire,
    tests::{BoundVerifier, DOMAIN},
    PosTransaction,
};
use super::*;

fn fixture() -> (State, Vec<u8>, State) {
    let (state, frames, direct) = sequence();
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    let bytes = build(&state, 1, &refs, &BoundVerifier, &BoundVerifier).unwrap();
    (state, bytes, direct)
}

#[test]
fn exchange_reexecutes_identically_without_mutating_producer_and_rejects_replay() {
    let (mut state, bytes, direct) = fixture();
    let root = state.state_root();
    let (expected, frames) = decode(&bytes, &DOMAIN, 1).unwrap();
    assert_eq!(expected.parent, root);
    assert_eq!(expected.post, direct.state_root());
    assert_eq!(
        build(&state, 1, &frames, &BoundVerifier, &BoundVerifier).unwrap(),
        bytes
    );
    assert_eq!(state.state_root(), root);
    let receipt = apply(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).unwrap();
    assert_eq!(receipt.post_root, direct.state_root());
    assert_eq!(state.base(), direct.base());
    assert_eq!(state.native().snapshot(), direct.native().snapshot());
    assert_eq!(state.fee_escrow(), direct.fee_escrow());
    assert!(matches!(
        apply(&mut state, &bytes, 1, &NoCrypto, &NoCrypto),
        Err(Error::Batch(pool_batch::Error::WrongParent))
    ));
    assert_eq!(state.state_root(), direct.state_root());
}

#[test]
fn forged_post_state_rejects_before_installing_any_operation() {
    let (mut state, mut bytes, _) = fixture();
    let root = state.state_root();
    let fees = state.fee_escrow();
    bytes[82] ^= 1; // post-state root starts after domain, parent and height
    assert!(decode(&bytes, &DOMAIN, 1).is_ok());
    assert!(matches!(
        apply(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier),
        Err(Error::Batch(pool_batch::Error::PostStateMismatch))
    ));
    assert_eq!(state.state_root(), root);
    assert_eq!(state.fee_escrow(), fees);
}

#[test]
fn every_prefix_trailing_data_and_host_context_mismatch_fail_before_crypto() {
    let (mut state, bytes, _) = fixture();
    let root = state.state_root();
    for end in 0..bytes.len() {
        assert!(
            apply(&mut state, &bytes[..end], 1, &NoCrypto, &NoCrypto).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        apply(&mut state, &trailing, 1, &NoCrypto, &NoCrypto),
        Err(Error::Wire(wire::Error::TrailingBytes))
    ));
    assert!(matches!(
        apply(&mut state, &bytes, 2, &NoCrypto, &NoCrypto),
        Err(Error::WrongHeight)
    ));
    for (offset, value) in [
        (0, b"UNKNOWN!".to_vec()),
        (8, 2u16.to_le_bytes().to_vec()),
        (10, vec![0; 32]),
        (146, 0u16.to_le_bytes().to_vec()),
        (146, u16::MAX.to_le_bytes().to_vec()),
        (148, u64::MAX.to_le_bytes().to_vec()),
    ] {
        let mut bad = bytes.clone();
        bad[offset..offset + value.len()].copy_from_slice(&value);
        assert!(apply(&mut state, &bad, 1, &NoCrypto, &NoCrypto).is_err());
    }
    assert!(matches!(
        decode(&bytes, &[99; 32], 1),
        Err(Error::Wire(wire::Error::WrongDomain))
    ));
    assert!(matches!(
        apply(
            &mut state,
            &vec![0; MAX_ENCODED_BYTES + 1],
            1,
            &NoCrypto,
            &NoCrypto
        ),
        Err(Error::Wire(wire::Error::TooLarge))
    ));
    assert_eq!(state.state_root(), root);
}

#[test]
fn altered_body_or_announced_commitment_fails_before_crypto() {
    let (mut state, bytes, _) = fixture();
    let root = state.state_root();
    for offset in [114, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(matches!(
            apply(&mut state, &bad, 1, &NoCrypto, &NoCrypto),
            Err(Error::CommitmentMismatch)
        ));
        assert_eq!(state.state_root(), root);
    }
}

struct PermissiveProducer;
impl SignatureVerifier for PermissiveProducer {
    fn verify_with_key(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> bool {
        true
    }
}
#[test]
fn permissive_producer_result_is_not_authority_and_snapshot_replay_is_deterministic() {
    let (mut state, frames, _) = sequence();
    let root = state.state_root();
    let snapshot = state.snapshot();
    let mut request = pool_wire::decode(&frames[0], &DOMAIN).unwrap();
    if let pool_wire::Request::Swap(r) = &mut request {
        if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
            keys[0].signature[0] ^= 1;
        }
    }
    let forged = pool_wire::encode(&request, &DOMAIN).unwrap();
    let dishonest = build(&state, 1, &[&forged], &PermissiveProducer, &BoundVerifier).unwrap();
    assert!(matches!(
        apply(&mut state, &dishonest, 1, &BoundVerifier, &BoundVerifier),
        Err(Error::Batch(pool_batch::Error::Operation { index: 0, .. }))
    ));
    assert_eq!(state.state_root(), root);
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    let bytes = build(&state, 1, &refs, &BoundVerifier, &BoundVerifier).unwrap();
    let first = apply(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).unwrap();
    let mut restored = State::restore(snapshot, root, &BoundVerifier).unwrap();
    let replay = apply(&mut restored, &bytes, 1, &BoundVerifier, &BoundVerifier).unwrap();
    assert_eq!(first.post_root, replay.post_root);
    assert_eq!(first.commitment, replay.commitment);
    assert_eq!(first.charge, replay.charge);
}
