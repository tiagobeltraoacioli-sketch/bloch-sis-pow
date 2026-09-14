use super::super::super::tests::{BoundVerifier, DOMAIN};
use super::super::tests::setup;
use super::*;

#[test]
fn roundtrip_and_encoded_execution_match_direct_state_fees_and_locks() {
    let (mut direct, request) = setup();
    let mut encoded = direct.clone();
    let bytes = encode(&request, &DOMAIN).unwrap();
    let decoded = decode(&bytes, &DOMAIN).unwrap();
    assert_eq!(encode(&decoded, &DOMAIN).unwrap(), bytes);
    assert_eq!(
        decoded.authorization(&DOMAIN).unwrap(),
        request.authorization(&DOMAIN).unwrap()
    );
    let a = direct
        .execute_paired_custody(&request, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let b = apply_encoded(&mut encoded, &bytes, 1, &BoundVerifier, &BoundVerifier).unwrap();
    assert_eq!(a.authorization, b.authorization);
    assert_eq!(a.reserve, b.reserve);
    assert_eq!(a.charge.gas, b.charge.gas);
    assert_eq!(a.charge.tx_bytes, b.charge.tx_bytes);
    assert_eq!(direct.state_root(), encoded.state_root());
    assert_eq!(direct.fee_escrow(), encoded.fee_escrow());
    assert!(encoded.base_is_locked(&b.reserve.outpoint));
    assert!(encoded.native().is_locked(&b.native.outputs[0]));
    let root = encoded.state_root();
    assert!(apply_encoded(&mut encoded, &bytes, 1, &BoundVerifier, &BoundVerifier).is_err());
    assert_eq!(encoded.state_root(), root);
}
#[test]
fn every_truncation_and_trailing_data_is_rejected_without_mutation() {
    let (mut state, r) = setup();
    let bytes = encode(&r, &DOMAIN).unwrap();
    let root = state.state_root();
    for end in 0..bytes.len() {
        assert!(
            apply_encoded(&mut state, &bytes[..end], 1, &BoundVerifier, &BoundVerifier).is_err(),
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
#[test]
fn header_domain_section_and_key_limits_fail_before_allocating_declared_tables() {
    let (_, r) = setup();
    let bytes = encode(&r, &DOMAIN).unwrap();
    for (offset, data) in [
        (0, b"BLCHNATV".to_vec()),
        (8, 2u16.to_le_bytes().to_vec()),
        (10, vec![0; 32]),
        (58, u64::MAX.to_le_bytes().to_vec()),
        (67, u32::MAX.to_le_bytes().to_vec()),
        (67, 2u32.to_le_bytes().to_vec()),
        (67, 0u32.to_le_bytes().to_vec()),
    ] {
        let mut bad = bytes.clone();
        bad[offset..offset + data.len()].copy_from_slice(&data);
        assert!(decode(&bad, &DOMAIN).is_err());
    }
    assert!(matches!(decode(&bytes, &[99; 32]), Err(Error::WrongDomain)));
    let base_len = u64::from_le_bytes(bytes[58..66].try_into().unwrap()) as usize;
    let mut bad = bytes.clone();
    bad[66 + base_len..74 + base_len].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(decode(&bad, &DOMAIN), Err(Error::TooLarge)));
    // One key occupies count + public-key length/bytes + signature length/bytes.
    let mut pos = 71;
    let key_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + key_len;
    let sig_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + sig_len;
    let inputs = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + inputs * 40;
    let mut bad = bytes.clone();
    bad[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(decode(&bad, &DOMAIN), Err(Error::TooLarge)));
}
#[test]
fn canonical_tail_tampering_and_invalid_native_signature_never_publish_half_state() {
    let (state, r) = setup();
    let bytes = encode(&r, &DOMAIN).unwrap();
    for offset in [bytes.len() - 48, bytes.len() - 16, bytes.len() - 8] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(decode(&bad, &DOMAIN).is_ok()); // well-formed intent, unauthorized change
        let mut staged = state.clone();
        let root = staged.state_root();
        assert!(apply_encoded(&mut staged, &bad, 1, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(staged.state_root(), root);
    }
    let mut bad = r.clone();
    bad.native.witnesses.owners[0][0] ^= 1;
    let mut staged = state.clone();
    let root = staged.state_root();
    assert!(apply_encoded(
        &mut staged,
        &encode(&bad, &DOMAIN).unwrap(),
        1,
        &BoundVerifier,
        &BoundVerifier
    )
    .is_err());
    assert_eq!(staged.state_root(), root);
}
