// SPDX-License-Identifier: AGPL-3.0-or-later
//! `bloch-mldsa-clean` — ML-DSA-65 pinned to the FIPS 204 reference
//! behaviour (PQClean `clean`) on every platform (P9f / HF2 sigdet). Every
//! signer uses it; consensus verification uses it from
//! `MLDSA_PIN_ACTIVATION_EPOCH` (bloch-pos-committee) and for the canonical
//! signature policies. Before that epoch consensus keeps the historical
//! verification path unchanged, so adopting the pinned verifier is scheduled
//! as a coordinated upgrade.
//!
//! `pqcrypto-mldsa`'s safe wrappers (`mldsa65::verify_detached_signature`,
//! `mldsa65::detached_sign`) select an implementation by CPU: PQClean's AVX2
//! code on x86_64 with AVX2, the AArch64/NEON code on ARM, `clean` elsewhere —
//! when the `avx2`/`neon` features are on (they are the crate's defaults, and
//! Cargo features are additive across a workspace). Pinning one reference
//! implementation makes verification identical on every platform.
//!
//! This crate calls PQClean's portable `clean` implementation EXPLICITLY
//! through `pqcrypto_mldsa::ffi`, regardless of enabled features. `clean` is
//! always compiled (pqcrypto-mldsa's build.rs builds it unconditionally), is
//! the PQClean reference code, and is the only backend that exists on every
//! target. Its accept/reject behaviour is pinned against NIST ACVP and against
//! the AVX2/AArch64 backends and the independent pure-Rust `fips204` crate by
//! bloch-crypto's `tests/acvp_fips204_full.rs` and the `mldsa_backend_diff`
//! fuzz target.
//!
//! It exists as a separate crate only because `bloch-crypto` is
//! `#![forbid(unsafe_code)]` (I-4): the two FFI calls live here, behind
//! length-checked safe functions, mirroring how `pqcrypto-internals` hosts the
//! RNG FFI.
//!
//! Semantics are byte-identical to pqcrypto-mldsa's own wrappers: FIPS 204
//! pure mode with an EMPTY context string (`ctx = NULL, ctxlen = 0`), hedged
//! signing with `rnd` drawn through `PQCRYPTO_RUST_randombytes` (so
//! `pqcrypto-internals`' seeded-RNG scope behaves exactly as before).
#![no_std]
#![deny(unsafe_op_in_unsafe_fn, missing_docs)]

use pqcrypto_mldsa::ffi;

/// ML-DSA-65 public key length (FIPS 204).
pub const PUBLIC_KEY_BYTES: usize = ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
/// ML-DSA-65 secret key length (FIPS 204).
pub const SECRET_KEY_BYTES: usize = ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
/// ML-DSA-65 signature length (FIPS 204).
pub const SIGNATURE_BYTES: usize = ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
/// Longest FIPS 204 context string (one length byte).
pub const MAX_CONTEXT_BYTES: usize = 255;

/// Consensus verification: `true` iff `sig` is a valid ML-DSA-65 signature on
/// `message` (empty context) under `pk`, as decided by PQClean `clean`.
/// Exact lengths are required; anything else is `false`, never a panic.
pub fn verify(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    verify_ctx(pk, message, &[], sig)
}

/// [`verify`] with an explicit FIPS 204 context string (`ctx.len() <= 255`).
/// An empty `ctx` is passed to C as `(NULL, 0)`, exactly the call the empty-
/// context path has always made. Used by the v2 (suite-bound) signature
/// policy, which must not fall back to pqcrypto-mldsa's dispatching
/// `verify_detached_signature_ctx`.
pub fn verify_ctx(pk: &[u8], message: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != PUBLIC_KEY_BYTES || sig.len() != SIGNATURE_BYTES || ctx.len() > MAX_CONTEXT_BYTES {
        return false;
    }
    let ctx_ptr = if ctx.is_empty() { core::ptr::null() } else { ctx.as_ptr() };
    // SAFETY: every pointer is passed with its exact length; the C side reads
    // exactly PUBLIC_KEY_BYTES from `pk` (checked above), `siglen` bytes from
    // `sig`, `mlen` bytes from `message`, and `ctxlen` bytes from `ctx`
    // (nothing when ctxlen = 0, where ctx is NULL as in pqcrypto-mldsa's
    // wrapper).
    let rc = unsafe {
        ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
            sig.as_ptr(),
            sig.len(),
            message.as_ptr(),
            message.len(),
            ctx_ptr,
            ctx.len(),
            pk.as_ptr(),
        )
    };
    rc == 0
}

/// Sign `message` (empty context) with PQClean `clean`. `None` if `sk` has the
/// wrong length or the C signer reports failure / an unexpected length.
pub fn sign(sk: &[u8], message: &[u8]) -> Option<[u8; SIGNATURE_BYTES]> {
    sign_ctx(sk, message, &[])
}

/// [`sign`] with an explicit FIPS 204 context string (`ctx.len() <= 255`).
pub fn sign_ctx(sk: &[u8], message: &[u8], ctx: &[u8]) -> Option<[u8; SIGNATURE_BYTES]> {
    if sk.len() != SECRET_KEY_BYTES || ctx.len() > MAX_CONTEXT_BYTES {
        return None;
    }
    let ctx_ptr = if ctx.is_empty() { core::ptr::null() } else { ctx.as_ptr() };
    let mut sig = [0u8; SIGNATURE_BYTES];
    let mut siglen: usize = 0;
    // SAFETY: `sig` has SIGNATURE_BYTES capacity (the most the C side writes),
    // `sk` length is checked above, `siglen` is a valid out-pointer, `ctx` is
    // read for exactly `ctxlen` bytes (NULL with ctxlen = 0 for the empty
    // context, the same call pqcrypto-mldsa's `detached_sign` makes).
    let rc = unsafe {
        ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
            sig.as_mut_ptr(),
            &mut siglen,
            message.as_ptr(),
            message.len(),
            ctx_ptr,
            ctx.len(),
            sk.as_ptr(),
        )
    };
    if rc != 0 || siglen != SIGNATURE_BYTES {
        return None;
    }
    Some(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_mldsa::mldsa65;
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

    #[test]
    fn sizes_are_fips204_ml_dsa_65() {
        assert_eq!((PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES), (1952, 4032, 3309));
    }

    #[test]
    fn sign_verify_roundtrip_and_rejections() {
        let (pk, sk) = mldsa65::keypair();
        let (pk, sk) = (pk.as_bytes(), sk.as_bytes());
        let sig = sign(sk, b"m").expect("sign");
        assert!(verify(pk, b"m", &sig));
        assert!(!verify(pk, b"n", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(pk, b"m", &bad));
        assert!(!verify(pk, b"m", &sig[..SIGNATURE_BYTES - 1]));
        assert!(!verify(&pk[..PUBLIC_KEY_BYTES - 1], b"m", &sig));
        assert!(sign(&sk[..10], b"m").is_none());
    }

    #[test]
    fn context_variants_match_upstream_ctx_wrappers_and_bind_the_context() {
        use pqcrypto_traits::sign::DetachedSignature as _;
        let (pk, sk) = mldsa65::keypair();
        let ctx = b"BLOCH-SIG-v2\x01\x00";
        let sig = sign_ctx(sk.as_bytes(), b"m", ctx).expect("sign_ctx");
        assert!(verify_ctx(pk.as_bytes(), b"m", ctx, &sig));
        assert!(!verify_ctx(pk.as_bytes(), b"m", b"BLOCH-SIG-v2\x02\x00", &sig));
        assert!(!verify(pk.as_bytes(), b"m", &sig), "ctx signature must not verify with empty ctx");
        // Upstream (feature-dispatched) wrapper agrees in both directions.
        let up = mldsa65::DetachedSignature::from_bytes(&sig).unwrap();
        assert!(mldsa65::verify_detached_signature_ctx(&up, b"m", ctx, &pk).is_ok());
        let up_sig = mldsa65::detached_sign_ctx(b"m", ctx, &sk);
        assert!(verify_ctx(pk.as_bytes(), b"m", ctx, up_sig.as_bytes()));
        // Empty ctx slice is the empty-context call.
        let s0 = sign(sk.as_bytes(), b"m").unwrap();
        assert!(verify_ctx(pk.as_bytes(), b"m", &[], &s0));
        // Over-long context is refused, never passed to C.
        let long = [0u8; MAX_CONTEXT_BYTES + 1];
        assert!(sign_ctx(sk.as_bytes(), b"m", &long).is_none());
        assert!(!verify_ctx(pk.as_bytes(), b"m", &long, &sig));
        let max = [7u8; MAX_CONTEXT_BYTES];
        let smax = sign_ctx(sk.as_bytes(), b"m", &max).unwrap();
        assert!(verify_ctx(pk.as_bytes(), b"m", &max, &smax));
    }
}
