// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Deterministic expansion of seeds into uniformly-distributed matrices
// and vectors over Z_q.

//! Expand a seed into a public matrix `A ∈ Z_q^{m × n}` and a target
//! vector `t ∈ Z_q^m` deterministically, using rejection sampling to
//! ensure uniform distribution over `Z_q`.
//!
//! # Why rejection sampling?
//!
//! Naively reducing 24-bit chunks of SHAKE output modulo q would
//! introduce a small bias because `2^24` is not divisible by q. To
//! preserve uniformity (a property the worst-case-to-average-case
//! reduction relies on), we sample 24-bit chunks and reject those `≥ q`.
//!
//! The expected rejection rate is `(2^24 - q) / 2^24 ≈ 0.001` (i.e., we
//! discard about 1 chunk in 1000), so the overhead is negligible.

use alloc::vec;
use alloc::vec::Vec;

use crate::params::{M, N, Q};
use crate::shake::Shake256Stream;
use crate::{DOMAIN_LABEL_POW_SEED, DOMAIN_LABEL_TARGET};

/// Sample one element of `Z_q` from a streaming SHAKE reader using
/// rejection sampling on 24-bit chunks (3 bytes per attempt).
fn sample_uniform_zq(stream: &mut Shake256Stream) -> u32 {
    let mut buf = [0u8; 3];
    loop {
        stream.read(&mut buf);
        // Build a 24-bit unsigned integer.
        let candidate = (buf[0] as u32)
            | ((buf[1] as u32) << 8)
            | ((buf[2] as u32) << 16);
        // Mask to 23 bits (since q < 2^23, this slightly improves the
        // acceptance rate over a 24-bit candidate).
        let candidate23 = candidate & 0x007F_FFFF; // 23 bits
        if candidate23 < Q {
            return candidate23;
        }
        // Reject; loop. Expected very few iterations.
    }
}

/// Expand a 64-byte seed (derived from `(header || nonce)`) into a
/// public matrix `A ∈ Z_q^{m × n}` in row-major layout.
///
/// # Layout
/// - `A[i][j]` is at index `i * N + j` of the returned `Vec<u32>`.
/// - All entries are in the canonical range `[0, q-1]`.
///
/// # Determinism
/// For a given `seed`, the output is uniquely determined. This is the
/// public-coin requirement that allows verifiers to reconstruct the same
/// matrix from the same seed.
pub fn expand_matrix(seed: &[u8]) -> Vec<u32> {
    expand_matrix_rows(seed, M)
}

/// Expand only the first `rows` rows of `A` (row-major). Because the stream is
/// sampled sequentially, the first `rows` rows are byte-identical to those of
/// the full `expand_matrix`. Used to avoid materializing the whole matrix when
/// only a prefix of the residual is checked (relaxed testnet regime).
pub fn expand_matrix_rows(seed: &[u8], rows: usize) -> Vec<u32> {
    let rows = rows.min(M);
    let mut a = vec![0u32; rows * N];
    let mut stream = Shake256Stream::new(DOMAIN_LABEL_POW_SEED, &[seed, b"MATRIX-A"]);
    for entry in a.iter_mut() {
        *entry = sample_uniform_zq(&mut stream);
    }
    a
}

/// Expand a 64-byte seed into the target vector `t ∈ Z_q^m`.
///
/// `t` is independent of `A` because we use a different domain label
/// (`DOMAIN_LABEL_TARGET`) plus a different per-call discriminator
/// (`b"VECTOR-T"`).
pub fn expand_target(seed: &[u8]) -> Vec<u32> {
    expand_target_len(seed, M)
}

/// Expand only the first `len` entries of `t`. Sequential sampling means the
/// prefix is byte-identical to the full `expand_target`.
pub fn expand_target_len(seed: &[u8], len: usize) -> Vec<u32> {
    let len = len.min(M);
    let mut t = vec![0u32; len];
    let mut stream = Shake256Stream::new(DOMAIN_LABEL_TARGET, &[seed, b"VECTOR-T"]);
    for entry in t.iter_mut() {
        *entry = sample_uniform_zq(&mut stream);
    }
    t
}

/// Convenience: derive both `A` and `t` from a seed in one call.
/// Returns `(A, t)` where `A` is in row-major layout `[i*N + j]`
/// and `t.len() == M`.
pub fn expand_matrix_and_target(seed: &[u8]) -> (Vec<u32>, Vec<u32>) {
    (expand_matrix(seed), expand_target(seed))
}

/// Prefix variant: expand only the first `rows` rows of `A` and the first
/// `rows` entries of `t`. Identical to taking a `rows`-prefix of the full
/// expansion, but ~`M/rows`× cheaper — the win for the relaxed testnet regime
/// where only `rows` residual coefficients are checked. Consensus-neutral: the
/// checked coefficients are bit-for-bit the same as the full expansion.
pub fn expand_matrix_and_target_rows(seed: &[u8], rows: usize) -> (Vec<u32>, Vec<u32>) {
    (expand_matrix_rows(seed, rows), expand_target_len(seed, rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_has_correct_size() {
        let seed = [0u8; 64];
        let a = expand_matrix(&seed);
        assert_eq!(a.len(), M * N);
    }

    #[test]
    fn target_has_correct_size() {
        let seed = [0u8; 64];
        let t = expand_target(&seed);
        assert_eq!(t.len(), M);
    }

    #[test]
    fn all_entries_in_zq() {
        let seed = [0u8; 64];
        let (a, t) = expand_matrix_and_target(&seed);
        for &x in a.iter() {
            assert!(x < Q, "matrix entry {x} >= q={Q}");
        }
        for &x in t.iter() {
            assert!(x < Q, "target entry {x} >= q={Q}");
        }
    }

    #[test]
    fn matrix_and_target_independent() {
        // The first M elements of the matrix MUST differ from the
        // target vector, otherwise our domain separation is broken.
        let seed = [42u8; 64];
        let a = expand_matrix(&seed);
        let t = expand_target(&seed);
        // Take the first M entries of A and compare to t. With
        // independent samples, the probability of equality of all M
        // values is negligible.
        let first_row_a = &a[..M];
        assert_ne!(first_row_a, t.as_slice(), "A and t are not independent — domain separation broken");
    }

    #[test]
    fn determinism_across_calls() {
        let seed = [7u8; 64];
        let a1 = expand_matrix(&seed);
        let a2 = expand_matrix(&seed);
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_seeds_give_different_matrices() {
        let a1 = expand_matrix(&[0u8; 64]);
        let a2 = expand_matrix(&[1u8; 64]);
        assert_ne!(a1, a2);
    }

    #[test]
    fn empirical_uniformity_smoke_test() {
        // Smoke test for uniformity: bucket the output into 16 buckets
        // of approximately equal size, check the chi-squared isn't
        // wildly off. This is a rough sanity test, not a rigorous
        // statistical test.
        let seed = [123u8; 64];
        let a = expand_matrix(&seed);

        let buckets = 16;
        let bucket_size = Q / buckets as u32;
        let mut counts = vec![0u32; buckets];
        for &x in a.iter() {
            let idx = ((x / bucket_size) as usize).min(buckets - 1);
            counts[idx] += 1;
        }

        let expected = (M * N) as f64 / buckets as f64;
        let mut chi_sq = 0.0_f64;
        for &c in &counts {
            let diff = c as f64 - expected;
            chi_sq += diff * diff / expected;
        }

        // Chi-squared with 15 degrees of freedom: 99% upper tail ≈ 30.6.
        // We use a generous threshold (50) for this smoke test.
        assert!(chi_sq < 50.0, "matrix entries don't look uniform: chi^2 = {chi_sq:.2}");
    }
}
