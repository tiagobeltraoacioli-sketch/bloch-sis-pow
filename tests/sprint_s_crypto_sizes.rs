//! Sprint S / B6b — hybrid (Falcon-1024 ‖ ML-DSA-65) size-constant consistency.
//!
//! Locks `core::{PUBKEY_SIZE, PRIVKEY_SIZE, SIG_SIZE}` to the hybrid layout so
//! a future crate upgrade that changes sizes fails here rather than silently
//! regressing fee estimation. Public key / secret are fixed-length; the Falcon
//! signature is variable, so SIG_SIZE is an upper bound.
//!
//! Roadmap #1: every enveloped object now carries a 4-byte suite header
//! (`crypto::SUITE_HEADER_LEN`), so the size constants are `HDR + hybrid layout`.

use bloch::core::{PUBKEY_SIZE, PRIVKEY_SIZE, SIG_SIZE};
use bloch::crypto::{self, SUITE_HEADER_LEN};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_falcon::falcon1024;

#[test]
fn pubkey_size_is_hybrid_sum() {
    assert_eq!(
        PUBKEY_SIZE,
        SUITE_HEADER_LEN + mldsa65::public_key_bytes() + falcon1024::public_key_bytes(),
        "PUBKEY_SIZE must equal suite header + ML-DSA-65 ‖ Falcon-1024 public key lengths"
    );
}

#[test]
fn privkey_size_is_hybrid_sum() {
    assert_eq!(
        PRIVKEY_SIZE,
        SUITE_HEADER_LEN + mldsa65::secret_key_bytes() + falcon1024::secret_key_bytes(),
        "PRIVKEY_SIZE must equal suite header + ML-DSA-65 ‖ Falcon-1024 secret key lengths"
    );
}

#[test]
fn sig_size_is_upper_bound() {
    // Falcon signatures are variable-length; SIG_SIZE is an upper estimate used
    // only for fee sizing. It must cover the header + ML-DSA (fixed) + Falcon max.
    assert!(
        SIG_SIZE >= SUITE_HEADER_LEN + mldsa65::signature_bytes() + falcon1024::signature_bytes(),
        "SIG_SIZE ({}) must be >= header ({}) + ML-DSA ({}) + Falcon max ({})",
        SIG_SIZE, SUITE_HEADER_LEN, mldsa65::signature_bytes(), falcon1024::signature_bytes()
    );
}

#[test]
fn generated_hybrid_keypair_matches_constants() {
    // End-to-end: the hybrid keypair/signature produced by `crypto` match the
    // declared sizes (pk/sk exact; sig <= upper bound since Falcon is variable).
    let (pk, sk) = crypto::generate_keypair();
    let sig = crypto::sign(&sk, b"sprint-s hybrid regression").expect("sign");

    assert_eq!(pk.len(), PUBKEY_SIZE, "hybrid pubkey length");
    assert_eq!(sk.len(), PRIVKEY_SIZE, "hybrid secret length");
    assert!(sig.len() <= SIG_SIZE, "hybrid sig {} must be <= SIG_SIZE {}", sig.len(), SIG_SIZE);
    assert!(crypto::verify(&pk, b"sprint-s hybrid regression", &sig), "hybrid sig must verify");
}
