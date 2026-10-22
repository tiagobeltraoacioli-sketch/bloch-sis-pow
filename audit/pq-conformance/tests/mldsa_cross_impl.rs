//! P9e: byte-exact FIPS 204 KATs via an independent implementation (fips204,
//! IntegrityChain) used as an oracle, then cross-checked against Bloch's
//! production ML-DSA-65 (PQClean via pqcrypto-mldsa =0.1.2).
//!
//! Chain of evidence:
//!  1. fips204 reproduces ACVP keyGen (25/25) and deterministic + hedged
//!     sigGen (external/pure) byte-for-byte -> fips204 is a valid FIPS 204 oracle.
//!  2. Bloch's production signer (`crypto::sign`, suites 0x0001 and 0x0002)
//!     emits ML-DSA halves that fips204 verifies under the empty context, i.e.
//!     the production signer is FIPS 204 *final* pure-mode (M' = 0 || 0 || M),
//!     not round-3 Dilithium and not HashML-DSA.
//!  3. fips204 signatures over random messages verify under Bloch's verifier.
use fips204::ml_dsa_65 as oracle;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use serde_json::Value;

const FIXTURE: &[u8] = include_bytes!("../../../crates/bloch-crypto/tests/vectors/acvp-fips204-mldsa65-full.json");

fn b(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap_or("")).unwrap()
}
fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}

#[test]
fn oracle_reproduces_acvp_keygen_and_siggen_byte_exact() {
    let v: Value = serde_json::from_slice(FIXTURE).unwrap();
    for case in v["keyGen"].as_array().unwrap() {
        let (pk, sk) = oracle::KG::keygen_from_seed(&arr(&b(case, "seed")));
        assert_eq!(pk.into_bytes().to_vec(), b(case, "pk"), "keyGen pk tcId {}", case["tcId"]);
        assert_eq!(sk.into_bytes().to_vec(), b(case, "sk"), "keyGen sk tcId {}", case["tcId"]);
    }
    let mut n = 0;
    for case in v["sigGen"].as_array().unwrap() {
        let sk = oracle::PrivateKey::try_from_bytes(arr(&b(case, "sk"))).unwrap();
        let rnd: [u8; 32] = if case["deterministic"].as_bool().unwrap() { [0u8; 32] } else { arr(&b(case, "rnd")) };
        let sig = sk.try_sign_with_seed(&rnd, &b(case, "message"), &b(case, "context")).unwrap();
        assert_eq!(sig.to_vec(), b(case, "signature"), "sigGen tcId {}", case["tcId"]);
        n += 1;
    }
    assert_eq!(n, 30);
}

#[test]
fn production_signer_is_fips204_final_pure_mode_per_oracle() {
    for (i, seed) in [[0x11u8; 32], [0x5Au8; 32], [0xC3u8; 32]].iter().enumerate() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(seed).unwrap();
        let msg = format!("p9e production signer conformance {i}");
        let sig = bloch_crypto::crypto::sign(&sk, msg.as_bytes()).unwrap();
        // Enveloped suite 0x0001: 4-byte header, then mldsa(1952) || falcon.
        let mpk: [u8; 1952] = arr(&pk[4..4 + 1952]);
        let msig: [u8; 3309] = arr(&sig[4..4 + 3309]);
        let opk = oracle::PublicKey::try_from_bytes(mpk).unwrap();
        assert!(opk.verify(msg.as_bytes(), &msig, b""), "oracle rejects production ML-DSA half #{i}");
        assert!(!opk.verify(msg.as_bytes(), &msig, b"x"), "context must be bound #{i}");

        // Oracle-signed (deterministic) half verifies under the production
        // raw verifier.
        let osk_bytes: [u8; 4032] = arr(&sk[4..4 + 4032]);
        let osk = oracle::PrivateKey::try_from_bytes(osk_bytes).unwrap();
        let osig = osk.try_sign_with_seed(&[0u8; 32], msg.as_bytes(), b"").unwrap();
        assert!(bloch_crypto::crypto::verify_mldsa65_raw(&mpk, msg.as_bytes(), &osig));
    }
}
