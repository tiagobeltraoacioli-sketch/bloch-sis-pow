// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signer-side hardening for hot validator hosts (p9e crypto audit finding 2,
//! "Falcon signing on hot hosts"; docs/CRYPTO-AUDIT-STATUS-20261020.md).
//!
//! NOTHING in this module changes what a valid signature is, how one is
//! encoded, or what any verifier accepts. It only adds checks that run on the
//! signing side before a signature leaves the process:
//!
//! * [`signing_platform_check`] — the constant-time argument for PQClean's
//!   integer-only `clean` Falcon signer rests on one hardware assumption:
//!   constant-time 32x32->64 integer multiplication. That holds on every
//!   x86_64 and ARMv8-A (aarch64) core a validator would run. Anything else is
//!   unvetted for online signing on a public schedule.
//! * [`falcon_signing_self_test`] — a power-on known-answer test of the Falcon
//!   signer (seeded keygen + sign pinned byte-for-byte). A miscompiled,
//!   mis-linked or faulty signer fails here before it touches a validator key.
//! * [`sign_verified`] — sign, then verify the result under the signer's own
//!   public key before releasing it. This is the standard countermeasure
//!   against fault attacks on lattice signers (a faulted Falcon/ML-DSA
//!   signature that does not verify can leak key material if published) and
//!   it also catches a keystore whose public and secret halves disagree.
//! * [`pairwise_consistency_test`] — FIPS 140-3 style pairwise check of a
//!   loaded keypair with a self-test message that can never collide with a
//!   32-byte consensus signing root.
//!
//! Seeded RNG use here is confined to the known-answer test, runs on a
//! dedicated short-lived thread (the seeded RNG in the vendored
//! `pqcrypto-internals` is thread-local and scoped), and never touches a real
//! key. Production signing stays randomized.

use super::{falcon, sign, verify, CryptoError};

/// Seed of the Falcon-1024 power-on known-answer test.
pub const FALCON_KAT_SEED: [u8; 32] = [0xB1; 32];
/// Message of the Falcon-1024 power-on known-answer test.
pub const FALCON_KAT_MSG: &[u8] = b"bloch-pos-falcon-clean-kat-v1";
/// SHA3-256 of the seeded Falcon-1024 public key (pqcrypto-falcon 0.4.1,
/// `clean`). Same pin as `falcon_clean_seeded_kat_is_byte_stable_and_verifies`.
pub const FALCON_KAT_PK_SHA3: &str =
    "afc79ea102992a5081b8172b55fb7c14e01ff2a74501a8577d1fe4df094c2375";
/// SHA3-256 of the seeded Falcon-1024 signature over [`FALCON_KAT_MSG`].
pub const FALCON_KAT_SIG_SHA3: &str =
    "645bf4db96650515c016aa1f615b78ad4dac5985363abdfbb8a3e0fc4a5d2e24";
/// Length of the seeded Falcon-1024 signature.
pub const FALCON_KAT_SIG_LEN: usize = 1271;

/// Domain of the pairwise-consistency self-test message. 40 bytes, so it can
/// never be mistaken for a 32-byte consensus signing root.
pub const PAIRWISE_SELF_TEST_MESSAGE: &[u8] = b"BLOCH/SIGNER-PAIRWISE-SELF-TEST/v1/never";

/// Target architectures on which the integer-only Falcon signer's
/// constant-time argument has been reviewed (constant-time 32x32->64 MUL).
pub const VETTED_SIGNING_ARCHES: &[&str] = &["x86_64", "aarch64"];

/// The architecture this binary was compiled for.
pub fn target_arch() -> &'static str {
    std::env::consts::ARCH
}

/// `Ok` when this build targets an architecture on which online Falcon signing
/// has been vetted; `Err` with an operator-facing explanation otherwise.
pub fn signing_platform_check() -> Result<(), String> {
    platform_check_for(target_arch())
}

fn platform_check_for(arch: &str) -> Result<(), String> {
    if VETTED_SIGNING_ARCHES.contains(&arch) {
        Ok(())
    } else {
        Err(format!(
            "online Falcon-1024 signing is vetted only on {VETTED_SIGNING_ARCHES:?}; this binary \
             targets `{arch}`, where constant-time 32x32->64 integer multiplication (the one \
             hardware assumption of the integer-only signer) has not been reviewed"
        ))
    }
}

/// Power-on known-answer test of the Falcon-1024 signer.
///
/// Runs seeded keygen + sign on a dedicated thread and compares SHA3-256 of
/// the produced key and signature with the pinned values, then checks that the
/// pinned signature verifies and that unseeded signing is still randomized.
pub fn falcon_signing_self_test() -> Result<(), String> {
    let handle = std::thread::Builder::new()
        .name("falcon-kat".into())
        .spawn(falcon_kat_on_this_thread)
        .map_err(|e| format!("falcon self-test: cannot spawn test thread: {e}"))?;
    handle
        .join()
        .map_err(|_| "falcon self-test: test thread panicked".to_string())?
}

fn falcon_kat_on_this_thread() -> Result<(), String> {
    use sha3::{Digest, Sha3_256};
    let seeded = pqcrypto_internals::with_seeded_rng_scope(&FALCON_KAT_SEED, || {
        let (pk, sk) = falcon::keypair();
        falcon::sign(&sk, FALCON_KAT_MSG).map(|sig| (pk, sk, sig))
    });
    let (pk, sk, sig) = seeded.map_err(|e| format!("falcon self-test: seeded sign failed: {e}"))?;
    let pk_hash = hex::encode(Sha3_256::digest(&pk));
    let sig_hash = hex::encode(Sha3_256::digest(&sig));
    if sig.len() != FALCON_KAT_SIG_LEN || pk_hash != FALCON_KAT_PK_SHA3 || sig_hash != FALCON_KAT_SIG_SHA3 {
        return Err(format!(
            "falcon self-test: known-answer mismatch (sig len {} want {FALCON_KAT_SIG_LEN}; pk sha3 \
             {pk_hash}; sig sha3 {sig_hash}). The linked Falcon signer is not the pinned \
             pqcrypto-falcon 0.4.1 `clean` implementation, or this machine computes it wrongly",
            sig.len()
        ));
    }
    if !falcon::verify(&pk, FALCON_KAT_MSG, &sig) {
        return Err("falcon self-test: pinned known-answer signature does not verify".into());
    }
    let fresh = falcon::sign(&sk, FALCON_KAT_MSG)
        .map_err(|e| format!("falcon self-test: randomized sign failed: {e}"))?;
    if fresh == sig {
        return Err("falcon self-test: signing outside the seeded scope reproduced the seeded \
                    signature; the RNG is not fresh per signature"
            .into());
    }
    if !falcon::verify(&pk, FALCON_KAT_MSG, &fresh) {
        return Err("falcon self-test: randomized signature does not verify".into());
    }
    Ok(())
}

/// Sign `message` and release the signature only if it verifies under
/// `public_key` with the consensus verifier.
///
/// The signature bytes are exactly what [`sign`] produced; nothing is
/// re-encoded. A verification failure returns `CryptoError::SignFailed` and the
/// faulty signature is dropped without being returned.
pub fn sign_verified(
    secret_key: &[u8],
    public_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    sign_verified_with(sign, verify, secret_key, public_key, message)
}

/// [`sign_verified`] with an explicit signer and verifier pair, for callers
/// that sign under a specific encoding / context policy and must check the
/// result with the verifier of that same policy.
pub fn sign_verified_with(
    sign_fn: impl FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError>,
    verify_fn: impl FnOnce(&[u8], &[u8], &[u8]) -> bool,
    secret_key: &[u8],
    public_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let signature = sign_fn(secret_key, message)?;
    if verify_fn(public_key, message, &signature) {
        Ok(signature)
    } else {
        Err(CryptoError::SignFailed(
            "produced signature does not verify under the signer's own public key \
             (fault, or mismatched keypair); signature withheld"
                .into(),
        ))
    }
}

/// Pairwise consistency test of a loaded keypair (sign + verify a fixed
/// self-test message that is not 32 bytes long).
pub fn pairwise_consistency_test(secret_key: &[u8], public_key: &[u8]) -> Result<(), String> {
    sign_verified(secret_key, public_key, PAIRWISE_SELF_TEST_MESSAGE)
        .map(|_| ())
        .map_err(|e| format!("pairwise consistency test failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[test]
    fn falcon_power_on_self_test_passes_on_this_build() {
        falcon_signing_self_test().expect("Falcon KAT self-test");
    }

    #[test]
    fn self_test_leaves_the_calling_thread_unseeded() {
        falcon_signing_self_test().expect("Falcon KAT self-test");
        let (_pk, sk) = falcon::keypair();
        let a = falcon::sign(&sk, b"after self-test").unwrap();
        let b = falcon::sign(&sk, b"after self-test").unwrap();
        assert_ne!(a, b, "signing after the self-test must stay randomized");
    }

    #[test]
    fn platform_check_accepts_the_vetted_arches_and_names_others() {
        assert!(platform_check_for("x86_64").is_ok());
        assert!(platform_check_for("aarch64").is_ok());
        for arch in ["x86", "arm", "riscv64", "wasm32", "powerpc64", "mips"] {
            let err = platform_check_for(arch).unwrap_err();
            assert!(err.contains(arch), "{err}");
        }
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(signing_platform_check().is_ok());
        }
    }

    #[test]
    fn pairwise_message_cannot_be_a_signing_root() {
        assert_ne!(PAIRWISE_SELF_TEST_MESSAGE.len(), 32);
    }

    #[test]
    fn sign_verified_returns_exactly_the_signed_bytes_that_verify() {
        let (pk, sk) = generate_keypair();
        let root = [0x5A; 32];
        let sig = sign_verified(&sk, &pk, &root).expect("matching keypair");
        assert!(verify(&pk, &root, &sig));
        assert!(pairwise_consistency_test(&sk, &pk).is_ok());
    }

    #[test]
    fn sign_verified_withholds_a_signature_under_a_mismatched_public_key() {
        let (_pk_a, sk_a) = generate_keypair();
        let (pk_b, _sk_b) = generate_keypair();
        let err = sign_verified(&sk_a, &pk_b, &[1u8; 32]).unwrap_err();
        assert!(matches!(err, CryptoError::SignFailed(_)), "{err:?}");
        assert!(pairwise_consistency_test(&sk_a, &pk_b).is_err());
    }

    #[test]
    fn sign_verified_with_uses_the_given_verifier() {
        let (pk, sk) = generate_keypair();
        let refusing = sign_verified_with(sign, |_, _, _| false, &sk, &pk, &[3u8; 32]);
        assert!(matches!(refusing, Err(CryptoError::SignFailed(_))));
        let canonical = sign_verified_with(
            sign,
            crate::crypto::verify_enveloped_canonical,
            &sk,
            &pk,
            &[3u8; 32],
        );
        assert!(canonical.is_ok(), "fresh signatures are canonical");
    }

    #[test]
    fn sign_verified_rejects_a_garbage_secret() {
        let (pk, _sk) = generate_keypair();
        assert!(sign_verified(&[0u8; 8], &pk, &[2u8; 32]).is_err());
    }
}
