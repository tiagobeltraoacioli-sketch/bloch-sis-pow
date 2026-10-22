// SPDX-License-Identifier: AGPL-3.0-or-later
//! dudect-style timing leakage check of Falcon-1024 signing (p9e audit
//! finding 2: the `clean` signer is constant-time "by design", but no timing
//! test had ever been run on the built binary).
//!
//! Method (Reparaz-Balasch-Verbauwhede, "dude, is my code constant time?"):
//! two input classes are interleaved in random order, each signing call is
//! timed, and Welch's t statistic is computed on the raw samples and on
//! samples cropped at several pooled percentiles (dudect's outlier handling).
//! |t| > 4.5 is dudect's conventional "leakage detected" threshold.
//!
//! Classes measured:
//! * `secret-key`: key A vs key B over the same message. The interesting
//!   class: secret-dependent timing is what a remote observer of publication
//!   time could exploit.
//! * `message`: one key, a fixed message vs fresh random messages. PQClean
//!   hashes the (public) message with `hash_to_point_vartime`, so a
//!   message-dependent difference is expected and harmless; it is reported as
//!   the positive control that the harness can see a real dependency.
//!
//! Falcon's signing loop restarts when a sampled signature is too long; the
//! restart probability depends on the key's public Gram-Schmidt norms, so a
//! small key-vs-key mean shift from restarts is a known public-key effect, not
//! a secret leak. The test therefore reports, and only fails on
//! `BLOCH_FALCON_TIMING_ASSERT=1`.
//!
//! Run (release, takes minutes):
//!   cargo test -p bloch-crypto --release --test falcon_sign_timing -- --ignored --nocapture
//! Optional: BLOCH_FALCON_TIMING_SAMPLES=<per class, default 4000>.

use bloch_crypto::crypto::falcon;
use std::time::Instant;

#[derive(Default)]
struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    fn push(&mut self, class: usize, x: f64) {
        self.n[class] += 1.0;
        let d = x - self.mean[class];
        self.mean[class] += d / self.n[class];
        self.m2[class] += d * (x - self.mean[class]);
    }
    fn t(&self) -> f64 {
        if self.n[0] < 2.0 || self.n[1] < 2.0 {
            return 0.0;
        }
        let v0 = self.m2[0] / (self.n[0] - 1.0);
        let v1 = self.m2[1] / (self.n[1] - 1.0);
        let den = (v0 / self.n[0] + v1 / self.n[1]).sqrt();
        if den == 0.0 { 0.0 } else { (self.mean[0] - self.mean[1]) / den }
    }
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Returns (t on all samples, max |t| over cropped sets, mean ns per class).
fn analyse(samples: &[(usize, f64)]) -> (f64, f64, [f64; 2]) {
    let mut all = Welch::default();
    for &(c, x) in samples {
        all.push(c, x);
    }
    let mut sorted: Vec<f64> = samples.iter().map(|s| s.1).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut worst: f64 = 0.0;
    for pct in [0.5, 0.75, 0.9, 0.95, 0.99] {
        let cut = sorted[((sorted.len() as f64 - 1.0) * pct) as usize];
        let mut w = Welch::default();
        for &(c, x) in samples.iter().filter(|s| s.1 <= cut) {
            w.push(c, x);
        }
        worst = worst.max(w.t().abs());
    }
    (all.t(), worst, all.mean)
}

fn run_class(
    label: &str,
    samples_per_class: usize,
    mut sign_class: impl FnMut(usize, &mut u64),
) -> (f64, f64) {
    let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ (Instant::now().elapsed().as_nanos() as u64 | 1);
    // Warm-up.
    for i in 0..64 {
        sign_class(i & 1, &mut rng);
    }
    let mut samples = Vec::with_capacity(2 * samples_per_class);
    let mut left = [samples_per_class; 2];
    while left[0] + left[1] > 0 {
        let mut class = (xorshift(&mut rng) & 1) as usize;
        if left[class] == 0 {
            class ^= 1;
        }
        left[class] -= 1;
        let start = Instant::now();
        sign_class(class, &mut rng);
        samples.push((class, start.elapsed().as_nanos() as f64));
    }
    let (t_all, t_crop, mean) = analyse(&samples);
    println!(
        "falcon timing [{label}]: n={samples_per_class}/class mean0={:.0}ns mean1={:.0}ns \
         t(all)={t_all:.2} max|t|(cropped)={t_crop:.2}",
        mean[0], mean[1]
    );
    (t_all, t_crop)
}

#[test]
fn welch_t_is_zero_for_identical_classes_and_large_for_shifted_ones() {
    let mut same = Vec::new();
    let mut shifted = Vec::new();
    for i in 0..1000u32 {
        let x = f64::from(i % 17);
        same.push(((i & 1) as usize, x));
        shifted.push(((i & 1) as usize, x + if i & 1 == 1 { 50.0 } else { 0.0 }));
    }
    assert!(analyse(&same).0.abs() < 1.0);
    assert!(analyse(&shifted).0.abs() > 10.0);
}

#[test]
#[ignore = "timing measurement; run in --release with --ignored --nocapture"]
fn falcon_clean_signing_timing_dudect() {
    let n: usize = std::env::var("BLOCH_FALCON_TIMING_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4000);
    let enforce = std::env::var("BLOCH_FALCON_TIMING_ASSERT").as_deref() == Ok("1");

    let (_pk_a, sk_a) = falcon::keypair();
    let (_pk_b, sk_b) = falcon::keypair();
    let msg = [0x42u8; 32];
    let keys = [sk_a.clone(), sk_b];
    let (_, key_crop) = run_class("secret-key", n, |c, _| {
        std::hint::black_box(falcon::sign(&keys[c], &msg).unwrap());
    });

    let (_, msg_crop) = run_class("message (positive control)", n, |c, rng| {
        let mut m = [0x42u8; 32];
        if c == 1 {
            for chunk in m.chunks_mut(8) {
                chunk.copy_from_slice(&xorshift(rng).to_le_bytes());
            }
        }
        std::hint::black_box(falcon::sign(&sk_a, &m).unwrap());
    });
    println!("falcon timing summary: secret-key max|t|={key_crop:.2}, message max|t|={msg_crop:.2} (dudect threshold 4.5)");
    if enforce {
        assert!(key_crop < 4.5, "secret-key class shows timing leakage: max|t|={key_crop:.2}");
    }
}
