//! Robustness: the untrusted-input decode + verify paths must NEVER panic on
//! arbitrary bytes — only return `Err`/`Ok`. A malicious peer or RPC caller
//! controls these inputs, so a panic is a remote DoS.
//!
//! This runs a large deterministic corpus on stable Rust (no nightly needed).
//! The libfuzzer targets in `fuzz/fuzz_targets/` cover the SAME surface with
//! coverage-guided mutation on a fuzzing box; this test is the always-on floor
//! that keeps the invariant green in CI and locally.

use bloch_sis_pow::difficulty::Target;
use bloch_sis_pow::encode::decode_s;
use bloch_sis_pow::verify::verify;

/// Tiny deterministic xorshift64 PRNG — no dependency, reproducible corpus.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

/// Edge cases + many pseudo-random buffers of widely varying length.
fn corpus(seed: u64) -> Vec<Vec<u8>> {
    let mut v = vec![
        vec![],
        vec![0u8],
        vec![0xffu8],
        vec![0u8; 3],
        vec![0u8; 4096],
        vec![0xffu8; 4096],
        vec![0xffu8; 8193],
    ];
    let mut r = Rng(seed);
    for _ in 0..30_000 {
        let n = (r.next() % 6000) as usize;
        v.push(r.bytes(n));
    }
    v
}

#[test]
fn decode_s_never_panics_on_arbitrary_bytes() {
    for b in corpus(0x9E3779B97F4A7C15) {
        // Must return (Ok or Err) — never panic / overflow / index OOB.
        let _ = decode_s(&b);
    }
}

#[test]
fn verify_never_panics_on_decoded_solutions() {
    let header = b"fuzz-robustness-header";
    // Extremes of the difficulty target so the aux-filter branch is exercised.
    let targets = [Target::MIN, Target::MAX];
    for b in corpus(0xD1B54A32D192ED03) {
        if let Ok(sol) = decode_s(&b) {
            for t in &targets {
                let _ = verify(header, 0, &sol, t);
                let _ = verify(header, u64::MAX, &sol, t);
                let _ = verify(&[], 1, &sol, t); // empty header too
            }
        }
    }
}
