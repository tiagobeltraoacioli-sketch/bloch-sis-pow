// SPDX-License-Identifier: AGPL-3.0-or-later
//! P9f: cost of pinning consensus ML-DSA-65 to PQClean `clean`.
//!
//! `#[ignore]`d measurement, not a pass/fail gate. Compares, on the SAME host
//! and keys, the pinned consensus path (`verify_mldsa65_raw_pinned`, `clean`), each other
//! compiled PQClean backend called directly (AVX2 / AArch64 — present only in
//! test builds via the dev-dependency), and the full hybrid verify/sign.
//!
//!   cargo test --release -p bloch-crypto --test p9f_mldsa_backend_perf \
//!       -- --ignored --nocapture --test-threads=1
use pqcrypto_mldsa::ffi;
use std::time::{Duration, Instant};

type VerifyCtx =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn time<F: FnMut()>(iters: u32, mut f: F) -> Duration {
    for _ in 0..16 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    t.elapsed() / iters
}

#[test]
#[ignore]
fn perf_mldsa65_consensus_clean_vs_simd() {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair();
    let msg = [0x51u8; 32];
    let sig = bloch_crypto::crypto::sign(&sk, &msg).unwrap();
    let (_, pk_body) = bloch_crypto::crypto::split_envelope(&pk).unwrap();
    let (_, sig_body) = bloch_crypto::crypto::split_envelope(&sig).unwrap();
    let mpk = &pk_body[..bloch_crypto::crypto::MLDSA_PUBKEY_LEN];
    let msig = &sig_body[..bloch_crypto::crypto::MLDSA_SIG_LEN];

    const N: u32 = 2000;
    let hybrid = time(N, || assert!(bloch_crypto::crypto::verify(&pk, &msg, &sig)));
    let consensus = time(N, || assert!(bloch_crypto::crypto::verify_mldsa65_raw_pinned(mpk, &msg, msig)));
    let mut others: Vec<(&str, VerifyCtx)> = Vec::new();
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        others.push(("avx2", ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_verify_ctx));
    }
    #[cfg(target_arch = "aarch64")]
    others.push(("aarch64", ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_verify_ctx));
    let sign = time(200, || {
        std::hint::black_box(bloch_crypto::crypto::sign(&sk, &msg).unwrap());
    });

    println!("\n=== P9f ML-DSA-65 backend cost (N={N}) ===");
    println!("  ML-DSA-65 verify, consensus (clean) : {:>8.4} ms", ms(consensus));
    for (name, f) in others {
        let d = time(N, || {
            // SAFETY: exact-length pk/sig, empty ctx.
            let rc = unsafe {
                f(msig.as_ptr(), msig.len(), msg.as_ptr(), msg.len(), core::ptr::null(), 0, mpk.as_ptr())
            };
            assert_eq!(rc, 0);
        });
        println!("  ML-DSA-65 verify, {name:<7} (ffi)     : {:>8.4} ms", ms(d));
    }
    println!("  hybrid verify (clean ML-DSA+Falcon) : {:>8.4} ms", ms(hybrid));
    println!("    Falcon-1024 share (by diff)       : {:>8.4} ms", ms(hybrid) - ms(consensus));
    println!("  hybrid sign (clean ML-DSA+Falcon)   : {:>8.4} ms", ms(sign));
}
