// ─────────────────────────────────────────────────────────────────────────────
// Self-referential regression + wrapper-equivalence vectors — NOT the official
// NIST FIPS-204 ML-DSA-65 `.rsp` known-answer tests, and NOT an audit. They
// detect drift and confirm Bloch's wrapper does not corrupt the underlying
// scheme; they do not prove standards conformance or security.
// ─────────────────────────────────────────────────────────────────────────────
//
// KAT: ML-DSA-65 (FIPS-204) as linked by the Bloch node.
//
// HONESTY (mirrors crates/bloch-crypto/src/crypto/mod.rs §"KAT SOURCE / HONESTY"):
// the official NIST ML-DSA-65 `.rsp` KAT files are NOT vendored in-tree. NIST
// reproduces its keypair from an AES-256-CTR DRBG, while Bloch's
// `generate_keypair_from_seed` drives keygen from a ChaCha20 stream via the
// `pqcrypto-internals` fork's `with_seeded_rng`. A signed NIST `.rsp` vector
// therefore does NOT reproduce a Bloch seeded keypair, so this file does NOT
// claim NIST-KAT equivalence. What it DOES pin, with no fabrication:
//   (1) FIPS-204 ML-DSA-65 parameter sizes (pk 1952 / sk 4032 / sig 3309),
//   (2) a byte-stable deterministic keypair from a fixed seed (regression
//       golden anchors, envelope-INVARIANT — they hash the raw ML-DSA body and
//       so are unaffected by any future suite-id envelope Dev-A prepends),
//   (3) detached sign→verify accepts; tamper / wrong-key / wrong-message reject,
//   (4) malformed parse inputs return Err (never panic).
//
// The pinned digests below are Dev-A's published golden ML-DSA body hashes
// (frozen handoff / tests/vectors/kat_hybrid_signer.json) for GOLDEN_SEED =
// [0x11; 32]. Because `generate_keypair_from_seed` calls `mldsa65::keypair()`
// FIRST from the seeded stream (crypto/mod.rs:78-86), a standalone seeded
// `mldsa65::keypair()` reproduces exactly the ML-DSA-65 half of the hybrid key,
// so hashing it here asserts-equal to the SAME published constant rather than
// inventing a new one (PMO R8: assert-equal, never independently re-bless).
//
// A-INDEPENDENT: exercises only the ML-DSA-65 primitive `pqcrypto_mldsa::mldsa65`
// that the node links today. It does NOT depend on Dev-A's suite-id/chain-id
// hard fork and stays valid across it (the golden digests are envelope-invariant).
//
// Unaudited software; the coin has no value. Regression vectors, not proofs.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use sha3::{Digest, Sha3_256};

// FIPS-204 ML-DSA-65 parameter sizes.
const ML_DSA_65_PUBKEY_LEN: usize = 1952;
const ML_DSA_65_SECRET_LEN: usize = 4032;
const ML_DSA_65_SIG_LEN: usize = 3309;

// GOLDEN_SEED = 32 bytes of 0x11 (Dev-A frozen handoff + kat_hybrid_signer.json).
const GOLDEN_SEED: [u8; 32] = [0x11; 32];

// Dev-A published, envelope-invariant golden hashes of the ML-DSA-65 body bytes
// for GOLDEN_SEED (assert-equal to these; do not re-bless — PMO R8).
const GOLDEN_MLDSA_PK_HASH: &str =
    "bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37";
const GOLDEN_MLDSA_SK_HASH: &str =
    "4ea56265a543928d9c4cf073fe8a6a85b9f7444b2012f2603b26b6a24f1255aa";

fn digest_hex(b: &[u8]) -> String {
    hex::encode(Sha3_256::digest(b))
}

#[test]
fn mldsa65_parameter_sizes_match_fips204() {
    assert_eq!(
        mldsa65::public_key_bytes(),
        ML_DSA_65_PUBKEY_LEN,
        "ML-DSA-65 public-key length must be the FIPS-204 value"
    );
    assert_eq!(
        mldsa65::secret_key_bytes(),
        ML_DSA_65_SECRET_LEN,
        "ML-DSA-65 secret-key length must be the FIPS-204 value"
    );
    assert_eq!(
        mldsa65::signature_bytes(),
        ML_DSA_65_SIG_LEN,
        "ML-DSA-65 detached-signature length must be the FIPS-204 value"
    );
    // The Bloch wrapper's public split-offset constants must equal the primitive.
    assert_eq!(bloch::crypto::MLDSA_PUBKEY_LEN, ML_DSA_65_PUBKEY_LEN);
    assert_eq!(bloch::crypto::MLDSA_SECRET_LEN, ML_DSA_65_SECRET_LEN);
    assert_eq!(bloch::crypto::MLDSA_SIG_LEN, ML_DSA_65_SIG_LEN);
}

#[test]
fn mldsa65_seeded_keygen_is_byte_stable_and_matches_golden() {
    // Drive keygen from the fixed seed; take only the FIRST draw so this equals
    // the ML-DSA-65 half of the Bloch hybrid keypair (crypto/mod.rs:78-86).
    let (pk1, sk1) = {
        let _g = pqcrypto_internals::with_seeded_rng(&GOLDEN_SEED);
        mldsa65::keypair()
    };
    let pk1 = pk1.as_bytes();
    let sk1 = sk1.as_bytes();

    assert_eq!(pk1.len(), ML_DSA_65_PUBKEY_LEN, "seeded pk length");
    assert_eq!(sk1.len(), ML_DSA_65_SECRET_LEN, "seeded sk length");

    // Assert-equal to Dev-A's published golden body hashes (never re-bless).
    assert_eq!(
        digest_hex(pk1),
        GOLDEN_MLDSA_PK_HASH,
        "ML-DSA-65 public key drifted from the published golden body hash"
    );
    assert_eq!(
        digest_hex(sk1),
        GOLDEN_MLDSA_SK_HASH,
        "ML-DSA-65 secret key drifted from the published golden body hash"
    );

    // Determinism: a second seeded keygen reproduces identical bytes.
    let (pk2, sk2) = {
        let _g = pqcrypto_internals::with_seeded_rng(&GOLDEN_SEED);
        mldsa65::keypair()
    };
    assert_eq!(pk1, pk2.as_bytes(), "same seed must reproduce identical ML-DSA pk");
    assert_eq!(sk1, sk2.as_bytes(), "same seed must reproduce identical ML-DSA sk");
}

#[test]
fn mldsa65_detached_sign_verify_roundtrip_and_rejections() {
    let (pk, sk) = mldsa65::keypair();
    let msg = b"BLOCH-KAT-MLDSA65-V1";

    let sig = mldsa65::detached_sign(msg, &sk);
    assert!(
        sig.as_bytes().len() <= ML_DSA_65_SIG_LEN,
        "ML-DSA-65 detached signature must not exceed the FIPS-204 length"
    );
    assert!(
        mldsa65::verify_detached_signature(&sig, msg, &pk).is_ok(),
        "a valid ML-DSA-65 detached signature must verify"
    );

    // Wrong message must fail.
    assert!(
        mldsa65::verify_detached_signature(&sig, b"a-different-message", &pk).is_err(),
        "wrong message must reject"
    );

    // Wrong (independent) key must fail.
    let (pk_other, _sk_other) = mldsa65::keypair();
    assert!(
        mldsa65::verify_detached_signature(&sig, msg, &pk_other).is_err(),
        "signature must not verify under an unrelated public key"
    );

    // Tampered signature bytes must fail (parse back through from_bytes first).
    let mut tampered = sig.as_bytes().to_vec();
    tampered[0] ^= 0x01;
    match mldsa65::DetachedSignature::from_bytes(&tampered) {
        Ok(bad_sig) => assert!(
            mldsa65::verify_detached_signature(&bad_sig, msg, &pk).is_err(),
            "a tampered but well-formed signature must reject"
        ),
        Err(_) => { /* parse rejection is also an acceptable rejection */ }
    }
}

#[test]
fn mldsa65_malformed_parse_returns_err_never_panics() {
    // Short / wrong-length inputs must return Err, never panic.
    for len in [0usize, 1, 31, ML_DSA_65_PUBKEY_LEN - 1, ML_DSA_65_PUBKEY_LEN + 1] {
        let buf = vec![0u8; len];
        if len != ML_DSA_65_PUBKEY_LEN {
            assert!(
                mldsa65::PublicKey::from_bytes(&buf).is_err(),
                "wrong-length ({len}) public key must not parse"
            );
        }
    }
    for len in [0usize, 1, ML_DSA_65_SIG_LEN - 1, ML_DSA_65_SIG_LEN + 1] {
        let buf = vec![0u8; len];
        assert!(
            mldsa65::DetachedSignature::from_bytes(&buf).is_err(),
            "wrong-length ({len}) detached signature must not parse"
        );
    }
    for len in [0usize, 1, ML_DSA_65_SECRET_LEN - 1, ML_DSA_65_SECRET_LEN + 1] {
        let buf = vec![0u8; len];
        assert!(
            mldsa65::SecretKey::from_bytes(&buf).is_err(),
            "wrong-length ({len}) secret key must not parse"
        );
    }
}
