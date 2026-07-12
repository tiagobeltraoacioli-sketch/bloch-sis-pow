// ─────────────────────────────────────────────────────────────────────────────
// Self-referential regression vectors generated from this repository's own
// implementation — NOT independent/external test vectors, and NOT an audit.
// They detect drift, not correctness.
// ─────────────────────────────────────────────────────────────────────────────
//
// KAT: Hybrid signer ML-DSA-65 ‖ Falcon-1024 (external-style, public-API only).
//
// Exercises `bloch::crypto` through its public surface:
//   generate_keypair_from_seed, sign, verify, MLDSA_{PUBKEY,SECRET,SIG}_LEN.
//
// What is pinned (see tests/vectors/kat_hybrid_signer.json):
//   - hybrid public-key length and secret-key length,
//   - the ML-DSA-65 public-key half SHA3-256 digest (deterministic from seed;
//     FIPS-204 keygen is platform-stable, so this is a portable anchor),
//   - the ML-DSA-65 secret-key half SHA3-256 digest,
//   - the fixed ML-DSA-65 signature-half length (3309),
//   - a deterministic ML-DSA-65 signature-half SHA3-256 digest over a fixed
//     message, produced under a seeded RNG (a REGRESSION-only deterministic
//     path — production signing is hedged/randomized),
//   - verify-accepts-a-valid-signature,
//   - a tampered byte ⇒ verify() returns false.
//
// The Falcon-1024 half is NOT byte-pinned: Falcon KEYGEN here shares the seeded
// byte stream and Falcon SIGNING uses floating-point Gaussian sampling, both of
// which carry the documented cross-platform caveat. The Falcon half is only
// length/behaviour-checked, never hashed into a portable golden value.
//
// Unaudited software; the coin has no value. These are regression vectors,
// not proofs of correctness or security.

use bloch::crypto::{self, MLDSA_PUBKEY_LEN, MLDSA_SECRET_LEN, MLDSA_SIG_LEN};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

fn load() -> Value {
    let path = format!("{}/tests/vectors/kat_hybrid_signer.json", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&raw).expect("kat_hybrid_signer.json must be valid JSON")
}

fn hexval(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("missing string field {key}")))
        .unwrap_or_else(|e| panic!("field {key} is not valid hex: {e}"))
}

fn digest_hex(b: &[u8]) -> String {
    hex::encode(Sha3_256::digest(b))
}

#[test]
fn deterministic_keygen_from_seed_is_byte_stable() {
    let v = load();
    let seed = hexval(&v, "seed_hex");
    let expected = &v["expected"];

    let (pk, sk) = crypto::generate_keypair_from_seed(&seed).expect("seeded keygen");

    // Full hybrid lengths.
    assert_eq!(pk.len(), expected["hybrid_pubkey_len"].as_u64().unwrap() as usize, "hybrid pk len");
    assert_eq!(sk.len(), expected["hybrid_secret_len"].as_u64().unwrap() as usize, "hybrid sk len");

    // Split offsets must be the documented fixed ML-DSA lengths.
    assert_eq!(MLDSA_PUBKEY_LEN, 1952);
    assert_eq!(MLDSA_SECRET_LEN, 4032);

    // Pinned ML-DSA halves (platform-stable golden anchors).
    assert_eq!(
        digest_hex(&pk[..MLDSA_PUBKEY_LEN]),
        expected["mldsa_pubkey_half_sha3_256"].as_str().unwrap(),
        "ML-DSA-65 public-key half drifted from the pinned vector"
    );
    assert_eq!(
        digest_hex(&sk[..MLDSA_SECRET_LEN]),
        expected["mldsa_secret_half_sha3_256"].as_str().unwrap(),
        "ML-DSA-65 secret-key half drifted from the pinned vector"
    );

    // Determinism: same seed → identical bytes on a second call.
    let (pk2, sk2) = crypto::generate_keypair_from_seed(&seed).unwrap();
    assert_eq!(pk, pk2, "same seed must reproduce identical pk");
    assert_eq!(sk, sk2, "same seed must reproduce identical sk");
}

#[test]
fn deterministic_mldsa_signature_half_is_byte_stable() {
    let v = load();
    let seed = hexval(&v, "seed_hex");
    let msg = hexval(&v, "message_hex");
    let expected = &v["expected"];

    let (_pk, sk) = crypto::generate_keypair_from_seed(&seed).unwrap();

    // Drive the RNG from the same seed so the (normally hedged) ML-DSA signature
    // becomes deterministic — a REGRESSION-ONLY path, not production signing.
    let guard = pqcrypto_internals::with_seeded_rng(
        <&[u8; 32]>::try_from(&seed[..32]).unwrap(),
    );
    let sig = crypto::sign(&sk, &msg).expect("hybrid sign");
    drop(guard);

    assert_eq!(
        MLDSA_SIG_LEN,
        expected["mldsa_sig_half_len"].as_u64().unwrap() as usize,
        "ML-DSA-65 signature-half length"
    );
    assert_eq!(
        digest_hex(&sig[..MLDSA_SIG_LEN]),
        expected["mldsa_sig_half_sha3_256"].as_str().unwrap(),
        "deterministic ML-DSA-65 signature half drifted from the pinned vector"
    );
}

#[test]
fn verify_accepts_valid_and_rejects_tampered() {
    let v = load();
    let seed = hexval(&v, "seed_hex");
    let msg = hexval(&v, "message_hex");

    let (pk, sk) = crypto::generate_keypair_from_seed(&seed).unwrap();

    // Production signing is hedged (randomized), so we cannot pin the whole-sig
    // bytes here — we assert acceptance and rejection behaviour instead.
    let sig = crypto::sign(&sk, &msg).expect("hybrid sign");
    assert!(crypto::verify(&pk, &msg, &sig), "valid hybrid signature must verify");

    // Tamper the ML-DSA half → must fail (AND-combiner).
    let mut t_mldsa = sig.clone();
    t_mldsa[0] ^= 0x01;
    assert!(!crypto::verify(&pk, &msg, &t_mldsa), "tampered ML-DSA half must fail");

    // Tamper the Falcon half → must fail (AND-combiner).
    let mut t_falcon = sig.clone();
    t_falcon[MLDSA_SIG_LEN + 1] ^= 0x01;
    assert!(!crypto::verify(&pk, &msg, &t_falcon), "tampered Falcon half must fail");

    // Wrong message → must fail.
    assert!(!crypto::verify(&pk, b"a-different-message", &sig), "wrong message must fail");

    // Truncated / falcon-less signature → parse failure ⇒ false.
    assert!(!crypto::verify(&pk, &msg, &sig[..MLDSA_SIG_LEN]), "falcon-less sig must fail");
}
