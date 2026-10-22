// SPDX-License-Identifier: AGPL-3.0-or-later
//! HF2 signature determinism: ML-DSA-65 pinned to the FIPS 204 reference
//! behaviour (PQClean `clean`) on every platform.
//!
//! These tests check, on every backend the test host can execute:
//!
//! * keygen is the same function of the seed (FIPS 204 Alg. 6: wallets and
//!   validator keys derived from a seed do not rotate when the backend does);
//! * signing with the same `rnd` stream produces byte-identical signatures,
//!   with and without a FIPS 204 context (the v2 suite-bound context
//!   included), i.e. every intermediate value of Alg. 7 agrees;
//! * verification verdicts agree on genuine signatures and on structured
//!   mutations of c~, z, the hint vector and the per-row hint counters, under
//!   the empty context and under both v2 contexts;
//! * the pinned verifier enforces FIPS 204 Alg. 8's bound on z.
//!
//! NIST ACVP agreement for each backend is in `acvp_fips204_full.rs`; the
//! open-ended differential is the `mldsa_backend_diff` cargo-fuzz target.
use pqcrypto_mldsa::ffi;

const PK: usize = 1952;
const SK: usize = 4032;
const SIG: usize = 3309;

type Keypair = unsafe extern "C" fn(*mut u8, *mut u8) -> core::ffi::c_int;
type SignCtx =
    unsafe extern "C" fn(*mut u8, *mut usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;
type VerifyCtx =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;

struct Backend {
    name: &'static str,
    keypair: Keypair,
    sign: SignCtx,
    verify: VerifyCtx,
}

fn backends() -> Vec<Backend> {
    let mut v = vec![Backend {
        name: "clean",
        keypair: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
        sign: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx,
        verify: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx,
    }];
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        v.push(Backend {
            name: "avx2",
            keypair: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_keypair,
            sign: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_signature_ctx,
            verify: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_verify_ctx,
        });
    }
    #[cfg(target_arch = "aarch64")]
    v.push(Backend {
        name: "aarch64",
        keypair: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_keypair,
        sign: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_signature_ctx,
        verify: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_verify_ctx,
    });
    v
}

fn keypair_seeded(b: &Backend, seed: &[u8; 32]) -> ([u8; PK], [u8; SK]) {
    let (mut pk, mut sk) = ([0u8; PK], [0u8; SK]);
    // SAFETY: buffers have exactly the FIPS 204 ML-DSA-65 sizes.
    let rc = pqcrypto_internals::with_seeded_rng_scope(seed, || unsafe {
        (b.keypair)(pk.as_mut_ptr(), sk.as_mut_ptr())
    });
    assert_eq!(rc, 0, "{} keypair", b.name);
    (pk, sk)
}

fn sign_seeded(b: &Backend, sk: &[u8; SK], msg: &[u8], ctx: &[u8], rnd_seed: &[u8; 32]) -> Vec<u8> {
    let mut sig = vec![0u8; SIG];
    let mut len = 0usize;
    // SAFETY: sig has SIG capacity, every input pointer carries its length.
    let rc = pqcrypto_internals::with_seeded_rng_scope(rnd_seed, || unsafe {
        (b.sign)(sig.as_mut_ptr(), &mut len, msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), sk.as_ptr())
    });
    assert_eq!((rc, len), (0, SIG), "{} sign", b.name);
    sig
}

fn verify(b: &Backend, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    assert_eq!(pk.len(), PK);
    // SAFETY: every pointer is passed with its length; pk length asserted.
    unsafe { (b.verify)(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), pk.as_ptr()) == 0 }
}

/// Splitmix64, so the mutation schedule is reproducible without a dev-dep.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn v2_ctx(suite: u16) -> Vec<u8> {
    let mut c = bloch_crypto::crypto::SIG_V2_MLDSA_CONTEXT_PREFIX.to_vec();
    c.extend_from_slice(&suite.to_le_bytes());
    c
}

#[test]
fn seeded_keygen_is_backend_independent() {
    let bs = backends();
    eprintln!("backends: {:?}", bs.iter().map(|b| b.name).collect::<Vec<_>>());
    for i in 0..16u8 {
        let seed = [i.wrapping_mul(37).wrapping_add(1); 32];
        let reference = keypair_seeded(&bs[0], &seed);
        for b in &bs[1..] {
            assert_eq!(keypair_seeded(b, &seed), reference, "{} keygen differs from clean (seed {i})", b.name);
        }
    }
    // The production seeded keygen (which runs the dispatched keypair in this
    // test binary and `clean` in a release binary) yields the clean key.
    let seed = [0x42u8; 32];
    let (pk, _) = bloch_crypto::crypto::generate_keypair_from_seed(&seed).unwrap();
    let (_, body) = bloch_crypto::crypto::split_envelope(&pk).unwrap();
    assert_eq!(&body[..PK], &keypair_seeded(&bs[0], &seed).0[..]);
}

#[test]
fn same_rnd_gives_byte_identical_signatures_on_every_backend() {
    let bs = backends();
    let ctxs: [Vec<u8>; 4] = [Vec::new(), v2_ctx(0x0001), v2_ctx(0x0002), vec![0xA5; 255]];
    for i in 0..8u8 {
        let (pk, sk) = keypair_seeded(&bs[0], &[i ^ 0x5C; 32]);
        for ctx in &ctxs {
            for m in 0..4u8 {
                let msg: Vec<u8> = (0..(m as usize * 41)).map(|j| j as u8 ^ i).collect();
                let rnd = [m.wrapping_add(i).wrapping_mul(13); 32];
                let reference = sign_seeded(&bs[0], &sk, &msg, ctx, &rnd);
                for b in &bs {
                    let s = sign_seeded(b, &sk, &msg, ctx, &rnd);
                    assert_eq!(s, reference, "{} signature bytes differ from clean", b.name);
                    for v in &bs {
                        assert!(verify(v, &pk, &msg, ctx, &s), "{} rejects {} signature", v.name, b.name);
                    }
                }
            }
        }
    }
}

#[test]
fn verify_verdicts_agree_on_structured_mutations() {
    let bs = backends();
    let mut rng = Rng(0x4846_325f_5349_4744); // "HF2_SIGD"
    let ctxs: [Vec<u8>; 3] = [Vec::new(), v2_ctx(0x0001), v2_ctx(0x0002)];
    let (mut checked, mut accepted) = (0usize, 0usize);
    for k in 0..4u8 {
        let (pk, sk) = keypair_seeded(&bs[0], &[k.wrapping_add(0x77); 32]);
        for (ci, ctx) in ctxs.iter().enumerate() {
            let msg = [b"hf2 sigdet ".as_slice(), &[k, ci as u8]].concat();
            let sig = sign_seeded(&bs[0], &sk, &msg, ctx, &[k ^ ci as u8; 32]);
            for _ in 0..300 {
                let mut s = sig.clone();
                let mut p = pk.to_vec();
                let mut m = msg.clone();
                let mut c = ctx.clone();
                for _ in 0..=rng.below(3) {
                    match rng.below(9) {
                        0 => s[rng.below(48)] ^= 1 << rng.below(8),               // c~
                        1 => s[48 + rng.below(3200)] ^= 1 << rng.below(8),        // z
                        2 => { let i = SIG - 61 + rng.below(55); s[i] = rng.next() as u8; } // hint indices
                        3 => { let i = SIG - 6 + rng.below(6); s[i] = rng.next() as u8; }   // row counters
                        4 => { let i = SIG - 6 + rng.below(6); s[i] = s[i].wrapping_add(1); }
                        5 => p[rng.below(PK)] ^= 1 << rng.below(8),
                        6 => m.push(rng.next() as u8),
                        7 => c = ctxs[rng.below(3)].clone(),                     // cross-suite context
                        _ => {} // genuine
                    }
                }
                let reference = verify(&bs[0], &p, &m, &c, &s);
                for b in &bs[1..] {
                    assert_eq!(verify(b, &p, &m, &c, &s), reference, "{} vs clean verdict", b.name);
                }
                // Consensus wrapper = clean, empty context.
                if c.is_empty() {
                    assert_eq!(bloch_crypto::crypto::verify_mldsa65_raw(&p, &m, &s), reference);
                }
                checked += 1;
                accepted += usize::from(reference);
            }
        }
    }
    eprintln!("hf2 sigdet: {checked} cases, {accepted} accepted, all backends agree");
    assert!(accepted > 0 && accepted < checked);
}

/// The v2 suite-bound signer and verifier also run `clean`, and the v2
/// ML-DSA half is accepted by every backend under its suite context only.
#[test]
fn v2_bound_signatures_verify_on_every_backend_under_their_suite_context_only() {
    use bloch_crypto::crypto::{sign_bound, split_envelope, verify_bound, generate_keypair_from_seed};
    let bs = backends();
    let (pk, sk) = generate_keypair_from_seed(&[0x31u8; 32]).unwrap();
    let msg = b"hf2 v2 bound";
    let sig = sign_bound(&sk, msg).unwrap();
    assert!(verify_bound(&pk, msg, &sig));
    let (suite, pk_body) = split_envelope(&pk).unwrap();
    let (_, sig_body) = split_envelope(&sig).unwrap();
    assert_eq!(suite, 0x0001);
    for b in &bs {
        assert!(verify(b, &pk_body[..PK], msg, &v2_ctx(0x0001), &sig_body[..SIG]), "{}", b.name);
        assert!(!verify(b, &pk_body[..PK], msg, &v2_ctx(0x0002), &sig_body[..SIG]), "{}", b.name);
        assert!(!verify(b, &pk_body[..PK], msg, b"", &sig_body[..SIG]), "{}", b.name);
    }
}

// ── FIPS 204 Alg. 8 z bound, from NIST ACVP negative vectors ──────────────
//
// FIPS 204 Alg. 8 line 13 requires ||z||_inf < GAMMA1 - BETA. No signature is
// generated here: the NIST ACVP ML-DSA-65 sigVer set includes
// "modified signature - z" cases whose expected result is reject. The pinned
// verifier must match NIST on every empty-context sigVer case, and reject each
// modified-z case in particular.
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("vectors/acvp-fips204-mldsa65-full.json");
const FIXTURE_SHA256: &str = "8289dd0ad1913e45b9150c95b7f6040ec169bec9d598ee438f7d731d5387c751";

fn sigver_cases() -> Vec<Value> {
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)), FIXTURE_SHA256, "fixture edited");
    let v: Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(v["parameterSet"], "ML-DSA-65");
    v["sigVer"].as_array().unwrap().clone()
}

fn field(case: &Value, name: &str) -> Vec<u8> {
    hex::decode(case[name].as_str().unwrap_or("")).unwrap()
}

#[test]
fn pinned_verifier_matches_nist_on_every_sigver_case() {
    let mut empty = 0;
    for c in sigver_cases() {
        let (pk, msg, ctx, sig) = (field(&c, "pk"), field(&c, "message"), field(&c, "context"), field(&c, "signature"));
        let want = c["testPassed"].as_bool().unwrap();
        // The pinned backend (clean) with the case's FIPS 204 context.
        assert_eq!(
            bloch_mldsa_clean::verify_ctx(&pk, &msg, &ctx, &sig),
            want,
            "pinned clean verifier vs NIST tcId {} ({})",
            c["tcId"],
            c["reason"]
        );
        // The empty-context ones also go through the crypto entry point.
        if ctx.is_empty() {
            assert_eq!(bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk, &msg, &sig), want, "tcId {}", c["tcId"]);
            empty += 1;
        }
    }
    assert!(empty > 0);
}

#[test]
fn pinned_verifier_rejects_the_nist_modified_z_vectors() {
    let mut seen = 0;
    for c in sigver_cases() {
        if c["reason"].as_str() != Some("modified signature - z") {
            continue;
        }
        assert_eq!(c["testPassed"].as_bool(), Some(false));
        let (pk, msg, ctx, sig) = (field(&c, "pk"), field(&c, "message"), field(&c, "context"), field(&c, "signature"));
        assert!(
            !bloch_mldsa_clean::verify_ctx(&pk, &msg, &ctx, &sig),
            "pinned clean verifier accepted NIST modified-z vector tcId {}",
            c["tcId"]
        );
        seen += 1;
    }
    assert!(seen >= 1, "the ACVP fixture must carry a modified-z negative vector");
}
