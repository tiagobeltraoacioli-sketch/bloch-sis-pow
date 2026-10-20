#![no_main]
//! Differential ML-DSA-65 verification across EVERY backend in the binary:
//! PQClean `clean`, PQClean `avx2` (x86_64 with AVX2), PQClean `aarch64` (ARM
//! hosts), and the independent pure-Rust FIPS 204 implementation `fips204`
//! (IntegrityChain). From MLDSA_PIN_ACTIVATION_EPOCH consensus is pinned to the
//! FIPS 204 reference behaviour (`clean`) on every platform (bloch-mldsa-clean).
//! This target keeps `clean` == AVX2 == AArch64 == fips204 == the pinned
//! production rule. Mutations target c~, z and the hint region, plus the
//! context string and the public key.
mod common;
use common::*;
use fips204::ml_dsa_65 as oracle;
use fips204::traits::{SerDes, Verifier};
use libfuzzer_sys::fuzz_target;
use pqcrypto_mldsa::ffi;

type V = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;

fn run(f: V, pk: &[u8; MLDSA_PK], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    unsafe { f(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), pk.as_ptr()) == 0 }
}

fuzz_target!(|data: &[u8]| {
    let fx = fixture();
    let mut cur = Cur(data);
    let sel = cur.u8();
    let k = sel as usize % fx.keys.len();
    let m = (sel as usize >> 2) % fx.msgs.len();
    let j = (sel as usize >> 3) % 2;
    let g = &fx.sigs[k][m][j];
    let mut pk: [u8; MLDSA_PK] = fx.keys[k].pk_body[..MLDSA_PK].try_into().unwrap();
    let mut sig: Vec<u8> = g[HDR..HDR + MLDSA_SIG].to_vec();
    let mut msg = fx.msgs[m].clone();
    let mut ctx: Vec<u8> = Vec::new();
    let mut mutated = false;
    let nops = cur.u8() % 8;
    for _ in 0..nops {
        let op = cur.u8();
        let off = cur.u16() as usize;
        let val = cur.u8();
        match op % 8 {
            // c~ (48 bytes), z (L*640 = 3200 bytes), hints (omega + k = 61 bytes)
            0 => { sig[off % 48] ^= val | 1; mutated = true; }
            1 => { sig[48 + off % 3200] ^= val | 1; mutated = true; }
            2 => { let i = MLDSA_SIG - 61 + off % 61; sig[i] = val; mutated = true; }
            3 => { let i = MLDSA_SIG - 6 + off % 6; sig[i] = val; mutated = true; } // per-row hint counters
            4 => { pk[off % MLDSA_PK] ^= val | 1; mutated = true; }
            5 => { ctx = cur.take((val as usize) % 300).to_vec(); mutated = true; }
            6 => { msg.push(val); mutated = true; }
            _ => { let n = off % 8; for _ in 0..n { sig.push(val) } mutated = true; }
        }
    }
    let clean = run(ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx, &pk, &msg, &ctx, &sig);
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        let avx2 = run(ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_verify_ctx, &pk, &msg, &ctx, &sig);
        assert_eq!(clean, avx2, "PQClean clean vs AVX2 disagree");
    }
    #[cfg(target_arch = "aarch64")]
    {
        let aarch64 = run(ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_verify_ctx, &pk, &msg, &ctx, &sig);
        assert_eq!(clean, aarch64, "PQClean clean vs AArch64 disagree");
    }
    let ora = match (oracle::PublicKey::try_from_bytes(pk), <[u8; MLDSA_SIG]>::try_from(sig.as_slice())) {
        (Ok(p), Ok(s)) => p.verify(&msg, &s, &ctx),
        _ => false,
    };
    assert_eq!(clean, ora, "PQClean vs fips204 disagree");
    // Pinned consensus rule = empty-context pure verify on `clean`.
    if ctx.is_empty() {
        assert_eq!(bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk, &msg, &sig), clean);
    }
    if !mutated { assert!(clean, "genuine signature rejected"); }
});
