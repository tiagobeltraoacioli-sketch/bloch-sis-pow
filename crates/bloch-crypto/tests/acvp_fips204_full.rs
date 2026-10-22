// SPDX-License-Identifier: AGPL-3.0-or-later
//! P9e crypto audit: FIPS 204 (final) conformance of the pinned ML-DSA-65
//! implementation (`pqcrypto-mldsa =0.1.2`, PQClean `ml-dsa-65`), checked on
//! EVERY compiled backend explicitly, not only the one the runtime dispatcher
//! happens to pick on the test host.
//!
//! Why per-backend: `pqcrypto-mldsa` is built WITH its default features
//! (`avx2`, `neon`), so the historical verification path runs PQClean's AVX2
//! code on x86_64 hosts with AVX2, the AArch64 code on ARM hosts and `clean`
//! elsewhere; from MLDSA_PIN_ACTIVATION_EPOCH consensus uses `clean`
//! everywhere (bloch-mldsa-clean). This file checks every compiled backend
//! against NIST. The pre-existing `acvp_mldsa.rs` only exercises the
//! dispatched one.
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

// ── P9f: consensus verification is pinned to `clean` on every platform ──────
//
// `bloch_crypto::crypto` signs ML-DSA-65 through PQClean's `clean` FFI, and
// its pinned rule (`verify_mldsa65_raw_pinned`, `verify_pinned`, consensus
// from MLDSA_PIN_ACTIVATION_EPOCH) verifies through it too. These checks bind the consensus result to NIST's
// expected answer AND to every other compiled backend, for every ACVP sigVer
// case the production (empty-context, pure) interface can express, plus
// the boundary cases below.

#[test]
fn p9f_consensus_verify_matches_nist_and_every_backend_on_sigver() {
    let v = fixture();
    let mut checked = 0;
    for case in v["sigVer"].as_array().unwrap() {
        let (pk, msg, ctx, sig) = (b(case, "pk"), b(case, "message"), b(case, "context"), b(case, "signature"));
        let want = case["testPassed"].as_bool().unwrap();
        let prod = bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk, &msg, &sig);
        if ctx.is_empty() {
            assert_eq!(prod, want, "consensus vs NIST tcId {} ({})", case["tcId"], case["reason"]);
            checked += 1;
        }
        // Whatever the context, consensus == every backend run with EMPTY ctx.
        for (name, f) in backends() {
            assert_eq!(prod, verify_on(f, &pk, &msg, b"", &sig), "consensus vs {name} tcId {}", case["tcId"]);
        }
    }
    eprintln!("p9f: {checked} empty-context sigVer cases checked against NIST");
}

#[test]
fn p9f_consensus_verify_matches_every_backend_on_mutated_siggen() {
    let v = fixture();
    for case in v["sigGen"].as_array().unwrap() {
        let (pk, msg, ctx, sig) = (b(case, "pk"), b(case, "message"), b(case, "context"), b(case, "signature"));
        if !ctx.is_empty() {
            continue;
        }
        // Genuine + mutations over c~, z, hint region, hint counters, pk.
        let mut variants: Vec<(Vec<u8>, Vec<u8>)> = vec![(pk.clone(), sig.clone())];
        for &i in &[0usize, 47, 48, 1000, 3247, 3309 - 61, 3309 - 7, 3309 - 6, 3309 - 1] {
            for &x in &[0x01u8, 0x80, 0xff] {
                let mut s = sig.clone();
                s[i] ^= x;
                variants.push((pk.clone(), s));
            }
        }
        for &i in &[0usize, 31, 32, 1951] {
            let mut p = pk.clone();
            p[i] ^= 1;
            variants.push((p, sig.clone()));
        }
        for (p, s) in &variants {
            let prod = bloch_crypto::crypto::verify_mldsa65_raw_pinned(p, &msg, s);
            for (name, f) in backends() {
                assert_eq!(prod, verify_on(f, p, &msg, b"", s), "consensus vs {name} tcId {}", case["tcId"]);
            }
        }
        assert!(bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk, &msg, &sig));
        // Wrong lengths are rejected before any backend runs.
        assert!(!bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk, &msg, &sig[..3308]));
        let mut long = sig.clone();
        long.push(0);
        assert!(!bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk, &msg, &long));
        assert!(!bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk[..1951], &msg, &sig));
    }
}

#[test]
fn p9f_production_signatures_verify_on_every_backend() {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair();
    let (_, pk_body) = bloch_crypto::crypto::split_envelope(&pk).expect("pk envelope");
    let mpk = &pk_body[..1952];
    for i in 0..8u8 {
        let msg = [b"p9f clean signer ".as_slice(), &[i]].concat();
        let sig = bloch_crypto::crypto::sign(&sk, &msg).unwrap();
        assert!(bloch_crypto::crypto::verify(&pk, &msg, &sig));
        let (_, sig_body) = bloch_crypto::crypto::split_envelope(&sig).expect("sig envelope");
        let msig = &sig_body[..3309];
        for (name, f) in backends() {
            assert!(verify_on(f, mpk, &msg, b"", msig), "{name} rejects production signature");
        }
        let spk = mldsa65::PublicKey::from_bytes(mpk).unwrap();
        let ssig = mldsa65::DetachedSignature::from_bytes(msig).unwrap();
        assert!(mldsa65::verify_detached_signature(&ssig, &msg, &spk).is_ok());
    }
}
