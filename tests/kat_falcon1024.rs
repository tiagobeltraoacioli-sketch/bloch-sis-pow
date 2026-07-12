// ─────────────────────────────────────────────────────────────────────────────
// Self-referential regression + wrapper-behaviour vectors — NOT the official
// NIST Falcon-1024 known-answer tests, and NOT an audit. They detect drift and
// confirm behaviour; they do not prove standards conformance or security.
// ─────────────────────────────────────────────────────────────────────────────
//
// KAT: Falcon-1024 through Bloch's `bloch::crypto::falcon` wrapper.
//
// HONESTY: Falcon signing uses floating-point Gaussian sampling. Its signature
// bytes are NOT reproducible across platforms/toolchains, so — unlike the
// ML-DSA-65 half — the Falcon half is NEVER byte-pinned into a portable golden
// value (this mirrors the caveat in crates/bloch-crypto/src/crypto/mod.rs:79-81
// and tests/kat_hybrid_signer.rs). This file therefore pins only:
//   (1) the Falcon-1024 public-key length (1793, exposed via the wrapper),
//   (2) sizes reported by the linked `pqcrypto_falcon::falcon1024` primitive,
//   (3) sign→verify accepts; tamper / wrong-key / wrong-message reject,
//   (4) malformed / truncated inputs return false (never panic).
//
// A-INDEPENDENT: exercises only the Falcon-1024 primitive as wrapped today. It
// does NOT depend on Dev-A's suite-id/chain-id hard fork (the wrapper operates
// on raw Falcon bytes; any suite-id envelope is stripped before this layer is
// reached) and stays valid across it.
//
// Unaudited software; the coin has no value. Regression vectors, not proofs.

use bloch::crypto::falcon;
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

// Falcon-1024 public-key length (bytes) — matches FALCON_PUBKEY_LEN in
// crates/bloch-crypto/src/crypto/mod.rs and the design doc's envelope layout.
const FALCON_1024_PUBKEY_LEN: usize = 1793;

#[test]
fn falcon1024_sizes_are_stable() {
    // Through the Bloch wrapper.
    assert_eq!(
        falcon::pubkey_len(),
        FALCON_1024_PUBKEY_LEN,
        "Falcon-1024 public-key length drifted (wrapper)"
    );
    // Through the linked primitive (same value — the wrapper does not reshape).
    assert_eq!(
        falcon1024::public_key_bytes(),
        FALCON_1024_PUBKEY_LEN,
        "Falcon-1024 public-key length drifted (primitive)"
    );

    // A freshly generated keypair must report exactly these lengths.
    let (pk, sk) = falcon::keypair();
    assert_eq!(pk.len(), FALCON_1024_PUBKEY_LEN, "generated Falcon pk length");
    assert_eq!(
        sk.len(),
        falcon1024::secret_key_bytes(),
        "generated Falcon sk length must equal the primitive's secret_key_bytes()"
    );
}

#[test]
fn falcon1024_sign_verify_roundtrip_through_wrapper() {
    let (pk, sk) = falcon::keypair();
    let msg = b"BLOCH-KAT-FALCON1024-V1";

    let sig = falcon::sign(&sk, msg).expect("falcon sign");
    // Falcon signatures are variable-length but bounded by signature_bytes().
    assert!(
        sig.len() <= falcon1024::signature_bytes(),
        "Falcon-1024 signature must not exceed the primitive's max signature length"
    );
    assert!(
        falcon::verify(&pk, msg, &sig),
        "a valid Falcon-1024 signature must verify"
    );
}

#[test]
fn falcon1024_rejects_tamper_wrong_key_wrong_message() {
    let (pk, sk) = falcon::keypair();
    let msg = b"BLOCH-KAT-FALCON1024-V1";
    let sig = falcon::sign(&sk, msg).expect("falcon sign");

    // Wrong message.
    assert!(
        !falcon::verify(&pk, b"a-different-message", &sig),
        "wrong message must reject"
    );

    // Tampered signature byte.
    let mut tampered = sig.clone();
    tampered[0] ^= 0x01;
    assert!(
        !falcon::verify(&pk, msg, &tampered),
        "tampered Falcon signature must reject"
    );

    // Unrelated public key.
    let (pk_other, _sk_other) = falcon::keypair();
    assert!(
        !falcon::verify(&pk_other, msg, &sig),
        "signature must not verify under an unrelated public key"
    );
}

#[test]
fn falcon1024_malformed_inputs_return_false_never_panic() {
    let (pk, sk) = falcon::keypair();
    let msg = b"BLOCH-KAT-FALCON1024-V1";
    let sig = falcon::sign(&sk, msg).expect("falcon sign");

    // Empty and short public keys / signatures must be rejected, not panic.
    assert!(!falcon::verify(&[], msg, &sig), "empty pk must reject");
    assert!(!falcon::verify(&pk, msg, &[]), "empty sig must reject");
    assert!(
        !falcon::verify(&pk[..FALCON_1024_PUBKEY_LEN - 1], msg, &sig),
        "truncated pk must reject"
    );
    if !sig.is_empty() {
        assert!(
            !falcon::verify(&pk, msg, &sig[..sig.len() - 1]),
            "truncated sig must reject"
        );
    }
    // Garbage of the right pk length must reject (parse-fail ⇒ false).
    assert!(
        !falcon::verify(&vec![0u8; FALCON_1024_PUBKEY_LEN], msg, &sig),
        "all-zero pk must reject"
    );

    // The raw primitive's parsers must also return Err, never panic.
    assert!(falcon1024::PublicKey::from_bytes(&[]).is_err());
    assert!(falcon1024::DetachedSignature::from_bytes(&[]).is_err());
}
