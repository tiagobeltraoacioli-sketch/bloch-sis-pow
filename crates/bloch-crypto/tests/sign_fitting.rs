// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sign_fitting`: re-sign until the encoded hybrid signature fits a bound.
//!
//! The admission bound used by several transaction fields is
//! 4 (suite header) + 3309 (ML-DSA-65) + 1280 (Falcon-1024) = 4593 bytes,
//! while a valid compact Falcon-1024 signature can reach 1462 bytes. These
//! tests pin that the helper never returns an oversized signature, that its
//! output is an ordinary signature for every verifier, and that an
//! unreachable bound is a clear error rather than a loop.
use bloch_crypto::crypto::{self, CryptoError};

const ADMISSION_BUDGET: usize = crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1280;
const FALCON_BUDGET: usize = 1280;

#[test]
fn admission_budget_matches_the_documented_layout() {
    assert_eq!(ADMISSION_BUDGET, 4593);
    assert!(
        crypto::max_signature_len() > ADMISSION_BUDGET,
        "the helper exists because the maximum hybrid length exceeds the admission bound"
    );
}

#[test]
fn sign_fitting_always_returns_a_signature_within_the_bound() {
    let (pk, sk) = crypto::generate_keypair();
    for i in 0u32..64 {
        let message = i.to_le_bytes();
        let sig = crypto::sign_fitting(&sk, &message, ADMISSION_BUDGET).expect("fits");
        assert!(sig.len() <= ADMISSION_BUDGET, "attempt {i}: {} bytes", sig.len());
        assert!(crypto::verify(&pk, &message, &sig));
        assert!(crypto::verify_enveloped_canonical(&pk, &message, &sig));
        assert!(!crypto::verify(&pk, b"other", &sig));
    }
}

#[test]
fn sign_fitting_with_the_full_maximum_never_needs_a_retry() {
    let (pk, sk) = crypto::generate_keypair();
    let sig = crypto::sign_fitting(&sk, b"m", crypto::max_signature_len()).expect("fits");
    assert!(crypto::verify(&pk, b"m", &sig));
}

/// Find a seeded draw whose first plain signature overflows the admission
/// budget, then show that `sign_fitting` under the same seed discards that
/// draw and returns a different, fitting, verifying signature.
#[test]
fn sign_fitting_discards_an_oversized_draw() {
    // Seeded key and seeded signing randomness: the search is reproducible,
    // and FIRST_OVERSIZED_SEED only skips its prefix.
    const FIRST_OVERSIZED_SEED: u32 = 1024;
    let (pk, sk) = crypto::generate_keypair_from_seed(&[0x5F; 32]).unwrap();
    let message = b"bloch-sign-fitting-oversized-draw";
    let mut found = None;
    for s in FIRST_OVERSIZED_SEED..FIRST_OVERSIZED_SEED + 4096 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&s.to_le_bytes());
        let sig = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
            crypto::sign(&sk, message).expect("sign")
        });
        if sig.len() > ADMISSION_BUDGET {
            eprintln!("first oversized seed: {s}");
            found = Some((seed, sig));
            break;
        }
    }
    let (seed, oversized) = found.expect("an oversized Falcon draw within 4096 seeds");
    assert!(crypto::verify(&pk, message, &oversized), "oversized draws are still valid");
    let fitted = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
        crypto::sign_fitting(&sk, message, ADMISSION_BUDGET).expect("fits")
    });
    assert!(fitted.len() <= ADMISSION_BUDGET);
    assert_ne!(fitted, oversized);
    assert!(crypto::verify(&pk, message, &fitted));
    assert!(crypto::verify_enveloped_canonical(&pk, message, &fitted));
}

#[test]
fn sign_fitting_reports_an_unreachable_bound() {
    let (_pk, sk) = crypto::generate_keypair();
    // No room for any Falcon tail: no attempt can fit.
    let bound = crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN;
    match crypto::sign_fitting(&sk, b"m", bound) {
        Err(CryptoError::SignFailed(msg)) => {
            assert!(msg.contains(&bound.to_string()), "{msg}");
            assert!(msg.contains(&crypto::SIGN_FITTING_MAX_ATTEMPTS.to_string()), "{msg}");
        }
        other => panic!("expected SignFailed, got {other:?}"),
    }
}

#[test]
fn sign_fitting_propagates_a_malformed_key() {
    assert!(matches!(
        crypto::sign_fitting(&[0u8; 8], b"m", ADMISSION_BUDGET),
        Err(CryptoError::InvalidKey(_))
    ));
}

/// Empirical overflow rate of one compact Falcon-1024 signature over the
/// 1280-byte admission budget. Slow in debug builds; run with
/// `cargo test --release -p bloch-crypto --test sign_fitting -- --ignored --nocapture`.
/// `SIGN_FITTING_SAMPLES` overrides the default 20,000 samples.
#[test]
#[ignore = "statistical measurement; run explicitly in release mode"]
fn sign_fitting_falcon_overflow_rate() {
    let samples: usize = std::env::var("SIGN_FITTING_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let keys = 8usize;
    let pairs: Vec<_> = (0..keys).map(|_| crypto::generate_keypair()).collect();
    let mut over = 0usize;
    let mut max_seen = 0usize;
    let mut min_seen = usize::MAX;
    let mut sum = 0usize;
    for i in 0..samples {
        let (_, sk) = &pairs[i % keys];
        let sig = crypto::sign(sk, &(i as u64).to_le_bytes()).expect("sign");
        let falcon = sig.len() - crypto::SUITE_HEADER_LEN - crypto::MLDSA_SIG_LEN;
        sum += falcon;
        max_seen = max_seen.max(falcon);
        min_seen = min_seen.min(falcon);
        if falcon > FALCON_BUDGET {
            over += 1;
        }
    }
    let p = over as f64 / samples as f64;
    // P(all 64 attempts overflow) = p^64.
    println!(
        "falcon-1024 samples={samples} keys={keys} over_1280={over} p={p:.6} \
         mean={:.1} min={min_seen} max={max_seen} p^64={:e}",
        sum as f64 / samples as f64,
        p.powi(crypto::SIGN_FITTING_MAX_ATTEMPTS as i32)
    );
    assert!(p < 0.5, "the 1280-byte budget must be the common case");
}

/// The wallet keypair (used by the offline funding examples) exposes the
/// same helper for enveloped and legacy raw secret keys.
#[test]
fn wallet_keypair_sign_fitting_covers_enveloped_and_raw_secrets() {
    use bloch_crypto::wallet::{self, Keypair};
    let enveloped = wallet::generate_keypair(true);
    let raw = Keypair {
        private_key: enveloped.private_key[crypto::SUITE_HEADER_LEN..].to_vec(),
        public_key: enveloped.public_key.clone(),
        address: enveloped.address.clone(),
    };
    for key in [&enveloped, &raw] {
        for i in 0u8..8 {
            let sig = key.sign_fitting(&[i; 32], ADMISSION_BUDGET).expect("fits");
            assert!(sig.len() <= ADMISSION_BUDGET);
            assert!(Keypair::verify(&key.public_key, &[i; 32], &sig));
        }
        let err = key
            .sign_fitting(b"m", crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN)
            .unwrap_err();
        assert!(err.contains("attempts"), "{err}");
    }
}
