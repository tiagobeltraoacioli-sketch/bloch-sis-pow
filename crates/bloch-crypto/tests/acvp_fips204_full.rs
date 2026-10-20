// SPDX-License-Identifier: AGPL-3.0-or-later
//! P9e crypto audit: FIPS 204 (final) conformance of the pinned ML-DSA-65
//! implementation (`pqcrypto-mldsa =0.1.2`, PQClean `ml-dsa-65`), checked on
//! EVERY compiled backend explicitly, not only the one the runtime dispatcher
//! happens to pick on the test host.
//!
//! Why per-backend: `pqcrypto-mldsa` is built WITH its default features
//! (`avx2`, `neon`), so consensus verification runs PQClean's AVX2 code on
//! x86_64 hosts with AVX2, the AArch64 code on ARM hosts and `clean` elsewhere.
//! A verification divergence between backends is a chain-split bug (precedent:
//! RUSTSEC-2026-0125, an AVX2-only `use_hint` accept bug in another ML-DSA
//! crate). The pre-existing `acvp_mldsa.rs` only exercises the dispatched one.
//!
//! Vectors: NIST ACVP-Server `internalProjection.json` files (ML-DSA-65,
//! external interface, pure mode), see `vectors/ACVP-FIPS204-FULL-PROVENANCE.md`.
//! Expected answers come from NIST, never from Bloch's code.
//!
//! Scope boundary: PQClean's signer draws `rnd` (and keygen draws xi) through
//! `randombytes`, which Bloch routes through a ChaCha20 override; ACVP's exact
//! `rnd`/`seed` cannot be injected, so signing and keygen are checked by
//! interoperability (official keys sign/verify; official signatures verify),
//! not by byte-exact signature reproduction. The byte-exact keyGen/sigGen KAT
//! against an independent FIPS 204 implementation lives in
//! `audit/pq-conformance` (fips204 crate cross-check).
use pqcrypto_mldsa::{ffi, mldsa65};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};

const FIXTURE: &[u8] = include_bytes!("vectors/acvp-fips204-mldsa65-full.json");
const FIXTURE_SHA256: &str = "8289dd0ad1913e45b9150c95b7f6040ec169bec9d598ee438f7d731d5387c751";

fn fixture() -> Value {
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)), FIXTURE_SHA256, "fixture edited");
    let v: Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(v["parameterSet"], "ML-DSA-65");
    v
}

fn b(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap_or("")).unwrap()
}

type VerifyCtx = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *const u8) -> libc_int;
#[allow(non_camel_case_types)]
type libc_int = core::ffi::c_int;

/// Every ML-DSA-65 verification backend compiled into this binary that the
/// current CPU can execute, by name.
fn backends() -> Vec<(&'static str, VerifyCtx)> {
    let mut v: Vec<(&'static str, VerifyCtx)> =
        vec![("clean", ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx)];
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        v.push(("avx2", ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_verify_ctx));
    }
    #[cfg(target_arch = "aarch64")]
    v.push(("aarch64", ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_verify_ctx));
    v
}

fn verify_on(f: VerifyCtx, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    assert_eq!(pk.len(), mldsa65::public_key_bytes());
    // SAFETY: lengths are passed alongside every pointer; pk length asserted.
    unsafe { f(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), pk.as_ptr()) == 0 }
}

#[test]
fn fips204_final_sizes_not_round3_dilithium3() {
    // Round-3 Dilithium3: pk 1952, sk 4000, sig 3293. FIPS 204 ML-DSA-65:
    // pk 1952, sk 4032 (tr grew 32 -> 64 bytes), sig 3309 (c~ grew 32 -> 48).
    assert_eq!(mldsa65::public_key_bytes(), 1952);
    assert_eq!(mldsa65::secret_key_bytes(), 4032);
    assert_eq!(mldsa65::signature_bytes(), 3309);
    assert_eq!(bloch_crypto::crypto::MLDSA_SECRET_LEN, 4032);
    assert_eq!(bloch_crypto::crypto::MLDSA_SIG_LEN, 3309);
}

#[test]
fn acvp_keygen_all_25_keys_are_fips204_layout_and_interoperate() {
    let v = fixture();
    let cases = v["keyGen"].as_array().unwrap();
    assert_eq!(cases.len(), 25);
    for case in cases {
        let (pk, sk) = (b(case, "pk"), b(case, "sk"));
        // FIPS 204 Alg. 24/25: sk = rho(32) || K(32) || tr(64) || ...; tr = H(pk, 64).
        assert_eq!(&sk[..32], &pk[..32], "rho mismatch tcId {}", case["tcId"]);
        let mut tr = [0u8; 64];
        let mut h = sha3::Shake256::default();
        h.update(&pk);
        h.finalize_xof().read(&mut tr);
        assert_eq!(&sk[64..128], &tr[..], "tr != SHAKE256(pk,64) tcId {}", case["tcId"]);

        let spk = mldsa65::PublicKey::from_bytes(&pk).unwrap();
        let ssk = mldsa65::SecretKey::from_bytes(&sk).unwrap();
        let msg = format!("p9e keygen interop {}", case["tcId"]);
        let sig = mldsa65::detached_sign(msg.as_bytes(), &ssk);
        assert!(mldsa65::verify_detached_signature(&sig, msg.as_bytes(), &spk).is_ok());
        for (name, f) in backends() {
            assert!(verify_on(f, &pk, msg.as_bytes(), b"", sig.as_bytes()), "{name} tcId {}", case["tcId"]);
            assert!(!verify_on(f, &pk, b"other", b"", sig.as_bytes()), "{name} tcId {}", case["tcId"]);
        }
        assert!(bloch_crypto::crypto::verify_mldsa65_raw(&pk, msg.as_bytes(), sig.as_bytes()));
    }
}

#[test]
fn acvp_siggen_official_signatures_verify_on_every_backend() {
    let v = fixture();
    let cases = v["sigGen"].as_array().unwrap();
    assert_eq!(cases.len(), 30, "tg3 (deterministic) + tg15 (hedged), external/pure");
    let mut empty_ctx = 0;
    for case in cases {
        let (pk, msg, ctx, sig) = (b(case, "pk"), b(case, "message"), b(case, "context"), b(case, "signature"));
        assert_eq!(sig.len(), 3309);
        for (name, f) in backends() {
            assert!(verify_on(f, &pk, &msg, &ctx, &sig), "{name} rejects official sig tcId {}", case["tcId"]);
            let mut bad = sig.clone();
            bad[3309 - 1] ^= 0x80;
            assert!(!verify_on(f, &pk, &msg, &ctx, &bad), "{name} tcId {}", case["tcId"]);
        }
        // The production wrapper is the empty-context pure interface.
        let prod = bloch_crypto::crypto::verify_mldsa65_raw(&pk, &msg, &sig);
        assert_eq!(prod, ctx.is_empty(), "production wrapper ctx boundary tcId {}", case["tcId"]);
        empty_ctx += usize::from(ctx.is_empty());
        // Official secret keys are accepted by PQClean's signer and the result
        // verifies under the official public key (sk encoding interop).
        let ssk = mldsa65::SecretKey::from_bytes(&b(case, "sk")).unwrap();
        let ours = mldsa65::detached_sign_ctx(&msg, &ctx, &ssk);
        for (name, f) in backends() {
            assert!(verify_on(f, &pk, &msg, &ctx, ours.as_bytes()), "{name} tcId {}", case["tcId"]);
        }
    }
    assert!(empty_ctx >= 1, "need at least one positive KAT for the production empty-context path");
}

#[test]
fn acvp_sigver_all_outcomes_match_on_every_backend() {
    let v = fixture();
    let cases = v["sigVer"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let (pk, msg, ctx, sig) = (b(case, "pk"), b(case, "message"), b(case, "context"), b(case, "signature"));
        let want = case["testPassed"].as_bool().unwrap();
        for (name, f) in backends() {
            assert_eq!(verify_on(f, &pk, &msg, &ctx, &sig), want,
                "{name} tcId {} ({})", case["tcId"], case["reason"]);
        }
    }
}
