use super::super::tests::{BoundVerifier, DOMAIN};
use super::*;

fn fixtures() -> Vec<(State, Request)> {
    let (a, ar) = paired_custody::tests::setup();
    let (b, br) = initial_liquidity::tests::funded();
    let (c, cr) = add_liquidity::tests::fixture();
    let (d, dr) = initial_liquidity::tests::swap_fixture();
    let (e, er) = initial_liquidity::tests::remove_fixture();
    let (f, fr) = paired_custody::funded_close();
    vec![
        (a, Request::CreatePair(ar)),
        (b, Request::Initialize(br)),
        (c, Request::Add(cr)),
        (d, Request::Swap(dr)),
        (e, Request::Remove(er)),
        (f, Request::ClosePair(fr)),
    ]
}

#[test]
fn all_operations_preserve_direct_execution_fees_and_replay_protection() {
    for (mut state, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        assert_eq!(
            encode(&decode(&bytes, &DOMAIN).unwrap(), &DOMAIN).unwrap(),
            bytes
        );
        let charge = quote_encoded(&state, &bytes).unwrap();
        assert_eq!(charge.tx_bytes, bytes.len() as u64);
        let mut direct = state.clone();
        let fee = match &r {
            Request::CreatePair(r) => {
                direct
                    .execute_paired_custody(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Initialize(r) => {
                direct
                    .execute_initial_liquidity(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Add(r) => {
                direct
                    .execute_blch_add(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Swap(r) => {
                direct
                    .execute_blch_swap(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Remove(r) => {
                direct
                    .execute_blch_remove(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::ClosePair(r) => {
                direct
                    .execute_paired_close(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
        };
        assert_eq!(charge.gas, fee.gas);
        assert_eq!(charge.base_fee_sat, fee.base_fee_sat);
        apply_encoded(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).unwrap();
        assert_eq!(state.state_root(), direct.state_root());
        assert_eq!(state.fee_escrow(), direct.fee_escrow());
        let root = state.state_root();
        assert!(apply_encoded(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn every_truncated_prefix_and_trailing_byte_rejects_atomically() {
    for (mut state, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        let root = state.state_root();
        for end in 0..bytes.len() {
            assert!(
                apply_encoded(&mut state, &bytes[..end], 1, &BoundVerifier, &BoundVerifier)
                    .is_err(),
                "prefix {end}"
            );
            assert_eq!(state.state_root(), root);
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode(&trailing, &DOMAIN),
            Err(Error::TrailingBytes)
        ));
    }
}

#[test]
fn hostile_headers_domains_and_lengths_are_bounded() {
    for (_, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        let length_offset = if matches!(r, Request::Initialize(_)) {
            124
        } else {
            58
        };
        for (offset, data) in [
            (0, b"UNKNOWN!".to_vec()),
            (8, 0u16.to_le_bytes().to_vec()),
            (10, vec![0; 32]),
            (length_offset, u64::MAX.to_le_bytes().to_vec()),
            (length_offset + 9, u32::MAX.to_le_bytes().to_vec()),
            (length_offset + 13, u32::MAX.to_le_bytes().to_vec()),
        ] {
            let mut bad = bytes.clone();
            bad[offset..offset + data.len()].copy_from_slice(&data);
            assert!(decode(&bad, &DOMAIN).is_err());
        }
        assert!(matches!(decode(&bytes, &[99; 32]), Err(Error::WrongDomain)));
        if length_offset == 58 {
            let base_len = u64::from_le_bytes(bytes[58..66].try_into().unwrap()) as usize;
            let native_offset = 66 + base_len;
            let mut bad = bytes.clone();
            bad[native_offset..native_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(matches!(decode(&bad, &DOMAIN), Err(Error::TooLarge)));
            let mut bad = bytes.clone();
            bad[native_offset + 8 + 11] ^= 1;
            assert!(decode(&bad, &DOMAIN).is_err());
            if matches!(r, Request::Remove(_)) {
                let native_len =
                    u64::from_le_bytes(bytes[native_offset..native_offset + 8].try_into().unwrap())
                        as usize;
                let owner_offset = native_offset + 8 + native_len + 32;
                for length in [0, MAX_BASE_WITNESS_BYTES as u64 + 1, u64::MAX] {
                    let mut bad = bytes.clone();
                    bad[owner_offset..owner_offset + 8].copy_from_slice(&length.to_le_bytes());
                    assert!(decode(&bad, &DOMAIN).is_err());
                }
                let mut old = bytes.clone();
                old[8..10].copy_from_slice(&1u16.to_le_bytes());
                assert!(matches!(decode(&old, &DOMAIN), Err(Error::InvalidVersion)));
            }
        }
    }
}

#[test]
fn canonical_intent_tampering_and_expiry_never_change_state() {
    for (mut state, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        let root = state.state_root();
        assert!(apply_encoded(&mut state, &bytes, 101, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
        let offset = if matches!(r, Request::Initialize(_)) {
            106
        } else {
            42
        };
        let mut tampered = bytes.clone();
        tampered[offset] ^= 1;
        assert!(decode(&tampered, &DOMAIN).is_ok());
        assert!(apply_encoded(&mut state, &tampered, 1, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn creation_frame_stays_compatible_with_existing_transport() {
    let (_, request) = paired_custody::tests::setup();
    let old = paired_custody::wire::encode(&request, &DOMAIN).unwrap();
    assert_eq!(encode(&Request::CreatePair(request), &DOMAIN).unwrap(), old);
    assert!(matches!(decode(&old, &DOMAIN), Ok(Request::CreatePair(_))));
}

#[test]
fn unsigned_intents_can_decode_but_cannot_execute() {
    for (mut state, mut request) in fixtures() {
        let blch = match &mut request {
            Request::CreatePair(r) => &mut r.blch,
            Request::Initialize(r) => &mut r.blch,
            Request::Add(r) => &mut r.blch,
            Request::Swap(r) => &mut r.blch,
            Request::Remove(r) => &mut r.blch,
            Request::ClosePair(r) => &mut r.blch,
        };
        let PosTransaction::TransferV2 { keys, .. } = blch else {
            panic!("fixture must use TransferV2");
        };
        keys[0].signature.clear();
        let bytes = encode(&request, &DOMAIN).unwrap();
        assert!(decode(&bytes, &DOMAIN).is_ok());
        let root = state.state_root();
        assert!(apply_encoded(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
}
