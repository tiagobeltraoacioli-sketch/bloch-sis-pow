// SPDX-License-Identifier: AGPL-3.0-or-later
use bloch_l2_proof::{policy_commitment, verify};
const VALUES: &[u8] = include_bytes!("fixtures/source-contract.values");
const PROOF: &[u8] = include_bytes!("fixtures/source-contract.proof");
fn key() -> [u8; 32] {
    // Independently retained guest key, never extracted from submitted proof data.
    [
        0x00, 0xf4, 0x7f, 0xd9, 0x03, 0xd6, 0x85, 0xe8, 0x5c, 0xec, 0x17, 0xba, 0x02, 0x7d, 0x9b,
        0xdb, 0xab, 0x3f, 0x51, 0xc2, 0xee, 0x5f, 0x92, 0xc0, 0x78, 0xb5, 0xe0, 0x3c, 0xa6, 0xc3,
        0xa4, 0x1a,
    ]
}
#[test]
fn native_rehearsal_uses_the_same_pinned_program_and_real_verifier() {
    let values = include_bytes!("fixtures/native-empty.values");
    let proof = include_bytes!("fixtures/native-empty.proof");
    assert!(verify(&policy_commitment(), &key(), values, proof));
    // Neither another real statement nor another real proof is interchangeable.
    assert!(!verify(&policy_commitment(), &key(), VALUES, proof));
    assert!(!verify(&policy_commitment(), &key(), values, PROOF));
}
#[test]
fn real_groth16_is_verified_and_every_transport_byte_is_bound() {
    assert!(verify(&policy_commitment(), &key(), VALUES, PROOF));
    for i in 0..PROOF.len() {
        let mut changed = PROOF.to_vec();
        changed[i] ^= 1;
        assert!(
            !verify(&policy_commitment(), &key(), VALUES, &changed),
            "byte {i}"
        );
    }
}
#[test]
fn real_proof_does_not_authenticate_changed_values_policy_or_guest() {
    for i in 0..VALUES.len() {
        let mut changed = VALUES.to_vec();
        changed[i] ^= 1;
        assert!(
            !verify(&policy_commitment(), &key(), &changed, PROOF),
            "byte {i}"
        );
    }
    assert!(!verify(&[9; 32], &key(), VALUES, PROOF));
    assert!(!verify(&policy_commitment(), &[9; 32], VALUES, PROOF));
    for length in 0..PROOF.len() {
        assert!(!verify(
            &policy_commitment(),
            &key(),
            VALUES,
            &PROOF[..length]
        ));
    }
    assert!(!verify(
        &policy_commitment(),
        &key(),
        VALUES,
        &[PROOF, &[0]].concat()
    ));
}
