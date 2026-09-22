// SPDX-License-Identifier: AGPL-3.0-or-later
//! Official round-3 submission verification data, not crate-generated expectations.
use bloch_crypto::crypto;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("vectors/falcon1024-round3.json");

fn cases() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)), "b4cbb8c7df88e6eb5e75ed8669c1b95777a4e07cf5b0691fb3ce37818498fbd6");
    let cases: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(cases.as_array().unwrap().iter().map(|case| case["count"].as_u64().unwrap()).collect::<Vec<_>>(), vec![0, 1, 99]);
    cases.as_array().unwrap().iter().map(|case| {
        let pk = hex::decode(case["pk"].as_str().unwrap()).unwrap();
        let message = hex::decode(case["msg"].as_str().unwrap()).unwrap();
        let signed = hex::decode(case["sm"].as_str().unwrap()).unwrap();
        assert_eq!(message.len() as u64, case["mlen"].as_u64().unwrap());
        assert_eq!(signed.len() as u64, case["smlen"].as_u64().unwrap());
        // Official nist.c: u16BE signature length || nonce40 || message ||
        // 0x2a || compressed polynomial. PQClean detached format puts 0x3a
        // first, then nonce40 and the exact same compressed polynomial.
        let signature_len = usize::from(u16::from_be_bytes([signed[0], signed[1]]));
        assert_eq!(signed.len(), 2 + 40 + message.len() + signature_len);
        assert_eq!(&signed[42..42 + message.len()], message.as_slice());
        let encoded = &signed[42 + message.len()..];
        assert_eq!(encoded[0], 0x2a);
        let mut signature = vec![0x3a];
        signature.extend_from_slice(&signed[2..42]);
        signature.extend_from_slice(&encoded[1..]);
        (pk, message, signature)
    }).collect()
}

#[test]
fn official_falcon_vectors_verify_and_mutations_fail() {
    for (pk, message, signature) in cases() {
        assert!(crypto::falcon::verify(&pk, &message, &signature));
        let mut wrong_message = message.clone(); wrong_message[0] ^= 1;
        assert!(!crypto::falcon::verify(&pk, &wrong_message, &signature));
        let mut wrong_nonce = signature.clone(); wrong_nonce[1] ^= 1;
        assert!(!crypto::falcon::verify(&pk, &message, &wrong_nonce));
        let mut wrong_key = pk.clone(); wrong_key[1] ^= 1;
        assert!(!crypto::falcon::verify(&wrong_key, &message, &signature));
        assert!(!crypto::falcon::verify(&pk, &message, &signature[..signature.len() - 1]));
    }
}

#[test]
fn hybrid_wrapper_requires_official_falcon_half_and_fresh_mldsa_half() {
    let (mldsa_pk, mldsa_sk) = mldsa65::keypair();
    for (falcon_pk, message, falcon_signature) in cases() {
        // Only the Falcon half is an official KAT. The fresh ML-DSA half
        // exercises the production hybrid combiner and is not a standards KAT.
        let mldsa_signature = mldsa65::detached_sign(&message, &mldsa_sk);
        let mut pk = vec![0xb1, 0x0c, 0x01, 0x00];
        pk.extend_from_slice(mldsa_pk.as_bytes());
        pk.extend_from_slice(&falcon_pk);
        let mut signature = vec![0xb1, 0x0c, 0x01, 0x00];
        signature.extend_from_slice(mldsa_signature.as_bytes());
        signature.extend_from_slice(&falcon_signature);
        assert!(crypto::verify(&pk, &message, &signature));
        let mut bad_mldsa = signature.clone(); bad_mldsa[crypto::SUITE_HEADER_LEN] ^= 1;
        assert!(!crypto::verify(&pk, &message, &bad_mldsa));
        let mut bad_falcon = signature;
        bad_falcon[crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1] ^= 1;
        assert!(!crypto::verify(&pk, &message, &bad_falcon));
    }
}
