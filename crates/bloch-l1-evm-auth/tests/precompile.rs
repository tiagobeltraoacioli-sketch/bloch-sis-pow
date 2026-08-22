// SPDX-License-Identifier: AGPL-3.0-or-later
//! §8 — the hybrid-verify precompile.

mod common;

use bloch_l1_evm_auth::precompile::{pq_verify, PQ_VERIFY_ADDRESS, PQ_VERIFY_BASE_GAS};
use bloch_l1_evm_auth::root::{call_message, signing_root};
use bloch_l1_evm_auth::{wrap_envelope, GAS_PER_BYTE, SUITE_MLDSA65_ONLY};
use common::{abi_encode, first_use_tx, Key, MockVerifier, CHAIN_ID};

const V: MockVerifier = MockVerifier;

fn truth(out: &bloch_l1_evm_auth::PrecompileOutput) -> bool {
    let mut expect_true = [0u8; 32];
    expect_true[31] = 1;
    if out.output == expect_true {
        true
    } else {
        assert_eq!(out.output, [0u8; 32], "output must be exactly 0 or 1");
        false
    }
}

fn expected_gas(input_len: usize) -> u64 {
    PQ_VERIFY_BASE_GAS + input_len as u64 * GAS_PER_BYTE
}

#[test]
fn the_address_is_the_one_the_spec_reserved() {
    let mut want = [0u8; 20];
    want[19] = 0xff;
    assert_eq!(PQ_VERIFY_ADDRESS, want);
}

#[test]
fn a_valid_triple_verifies() {
    let key = Key::new(61);
    let msg32 = [0x77u8; 32];
    let sig = key.sign(&call_message(CHAIN_ID, &msg32));
    let input = abi_encode(&key.enveloped, &msg32, &sig);
    let out = pq_verify(&input, CHAIN_ID, &V);
    assert!(truth(&out));
    assert_eq!(out.gas, expected_gas(input.len()));
}

#[test]
fn a_signature_over_the_bare_digest_does_not_verify() {
    // THE hole DS_EVM_CALL closes. Without the tag, a contract could hand a
    // user 32 bytes that happen to be a transaction's signing root; the
    // "message signature" would then move that user's funds.
    let key = Key::new(62);
    let tx = first_use_tx(&key);
    let root = signing_root(&tx).unwrap();

    // NEGATIVE: signed over the raw 32 bytes.
    let bare = key.sign(&root);
    let input = abi_encode(&key.enveloped, &root, &bare);
    assert!(!truth(&pq_verify(&input, CHAIN_ID, &V)));

    // CONTROL: signed over SHA3(DS_EVM_CALL ‖ chain_id ‖ msg32).
    let proper = key.sign(&call_message(CHAIN_ID, &root));
    let input = abi_encode(&key.enveloped, &root, &proper);
    assert!(truth(&pq_verify(&input, CHAIN_ID, &V)));
}

#[test]
fn the_chain_id_is_bound() {
    let key = Key::new(63);
    let msg32 = [0x12u8; 32];
    let sig = key.sign(&call_message(CHAIN_ID, &msg32));
    let input = abi_encode(&key.enveloped, &msg32, &sig);

    assert!(truth(&pq_verify(&input, CHAIN_ID, &V)));
    assert!(!truth(&pq_verify(&input, CHAIN_ID + 1, &V)));
}

#[test]
fn both_halves_must_verify() {
    let key = Key::new(64);
    let msg32 = [0x21u8; 32];
    let message = call_message(CHAIN_ID, &msg32);

    // NEGATIVE: garbage ML-DSA half.
    let mut body = vec![0u8; bloch_l1_evm_auth::MLDSA65_SIG_BYTES];
    body.extend_from_slice(&key.falcon_sig(&message));
    let input = abi_encode(
        &key.enveloped,
        &msg32,
        &wrap_envelope(bloch_l1_evm_auth::SUITE_MLDSA65_FALCON1024, &body),
    );
    assert!(!truth(&pq_verify(&input, CHAIN_ID, &V)));

    // NEGATIVE: garbage Falcon half.
    let mut body = key.mldsa_sig(&message);
    body.extend_from_slice(&vec![0u8; common::FALCON_SIG_BYTES]);
    let input = abi_encode(
        &key.enveloped,
        &msg32,
        &wrap_envelope(bloch_l1_evm_auth::SUITE_MLDSA65_FALCON1024, &body),
    );
    assert!(!truth(&pq_verify(&input, CHAIN_ID, &V)));

    // CONTROL.
    let input = abi_encode(&key.enveloped, &msg32, &key.sign(&message));
    assert!(truth(&pq_verify(&input, CHAIN_ID, &V)));
}

#[test]
fn the_escape_hatch_and_the_legacy_blob_are_rejected_here_too() {
    let key = Key::new(65);
    let msg32 = [0x31u8; 32];
    let message = call_message(CHAIN_ID, &msg32);

    // NEGATIVE: 0x0002 envelope.
    let input = abi_encode(
        &wrap_envelope(SUITE_MLDSA65_ONLY, &key.body),
        &msg32,
        &wrap_envelope(SUITE_MLDSA65_ONLY, &key.sign_body(&message)),
    );
    assert!(!truth(&pq_verify(&input, CHAIN_ID, &V)));

    // NEGATIVE: un-enveloped bodies.
    let input = abi_encode(&key.body, &msg32, &key.sign_body(&message));
    assert!(!truth(&pq_verify(&input, CHAIN_ID, &V)));

    // CONTROL.
    let input = abi_encode(&key.enveloped, &msg32, &key.sign(&message));
    assert!(truth(&pq_verify(&input, CHAIN_ID, &V)));
}

#[test]
fn malformed_input_returns_false_and_is_charged_in_full() {
    // A cheap failure path is a DoS invitation: an attacker who can make an
    // invalid input cost less than a valid one has found a free way to make
    // every node work.
    let key = Key::new(66);
    let msg32 = [0x41u8; 32];
    let valid = abi_encode(&key.enveloped, &msg32, &key.sign(&call_message(CHAIN_ID, &msg32)));

    let mut malformed: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8; 31],
        vec![0u8; 95],
        vec![0u8; 96],
        vec![0xff; 200],
    ];
    // Non-canonical head offset.
    let mut bad_off = valid.clone();
    bad_off[31] = 0x80;
    malformed.push(bad_off);
    // Second offset not immediately after the first tail.
    let mut bad_off2 = valid.clone();
    bad_off2[95] = bad_off2[95].wrapping_add(32);
    malformed.push(bad_off2);
    // Oversized declared length.
    let mut huge = valid.clone();
    huge[96 + 24..96 + 32].copy_from_slice(&u64::MAX.to_be_bytes());
    malformed.push(huge);
    // Non-zero trailing padding on the last tail.
    let mut dirty = valid.clone();
    *dirty.last_mut().unwrap() = 1;
    malformed.push(dirty);
    // Trailing bytes past the encoding.
    let mut extended = valid.clone();
    extended.extend_from_slice(&[0u8; 32]);
    malformed.push(extended);
    // A high word that does not fit a usize.
    let mut wide = valid.clone();
    wide[0] = 1;
    malformed.push(wide);

    for input in &malformed {
        let out = pq_verify(input, CHAIN_ID, &V);
        assert!(!truth(&out), "malformed input verified");
        assert_eq!(
            out.gas,
            expected_gas(input.len()),
            "malformed input must cost exactly what well-formed input of the same size costs"
        );
    }

    // CONTROL: the well-formed input, same formula.
    let out = pq_verify(&valid, CHAIN_ID, &V);
    assert!(truth(&out));
    assert_eq!(out.gas, expected_gas(valid.len()));
}

#[test]
fn gas_scales_with_the_input_and_never_overflows() {
    for len in [0usize, 1, 96, 4_096, 65_536] {
        let out = pq_verify(&vec![0u8; len], CHAIN_ID, &V);
        assert_eq!(out.gas, expected_gas(len));
    }
    // Saturating, not wrapping, at absurd sizes — the charge is monotone in
    // the input length and can never be cheaper for being larger.
    let a = pq_verify(&vec![0u8; 1_000], CHAIN_ID, &V).gas;
    let b = pq_verify(&vec![0u8; 2_000], CHAIN_ID, &V).gas;
    assert!(b > a);
}

#[test]
fn arbitrary_input_never_panics() {
    let mut state: u64 = 0xDEADBEEFCAFEBABE;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..3_000 {
        let len = (next() % 300) as usize;
        let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
        let out = pq_verify(&buf, CHAIN_ID, &V);
        assert_eq!(out.gas, expected_gas(buf.len()));
    }
}
