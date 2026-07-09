// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Matrix-vector multiplication and residual computation.

//! Linear algebra primitives for Bloch-SIS-PoW.
//!
//! For the reference implementation we use a straightforward
//! O(m·n) matmul. Production deployments will replace this with an
//! NTT-accelerated path sharing implementation with ML-DSA-65.

use alloc::vec;
use alloc::vec::Vec;

use crate::field::center_mod_q;
use crate::params::{M, N};

/// Compute `A · s mod q` and return the result as a vector of length `m`
/// in *centered* representation, i.e., each coefficient lies in
/// `[-(q-1)/2, (q-1)/2]`.
///
/// # Inputs
/// - `a`: matrix in row-major layout, length `M*N`, entries in `[0, q)`
/// - `s`: solution vector, length `N`, entries in `{-B, …, B}` (small)
///
/// # Output
/// `Vec<i32>` of length `M`, each entry the centered representative of
/// the corresponding row's inner product with `s` modulo q.
///
/// # Performance note
/// Each row's inner product accumulates `n = 256` products of values
/// bounded by `q × B ≈ 2^25`. Accumulating in `i64` prevents overflow
/// even for the worst case (`n × q × B ≈ 2^33`).
pub fn mat_vec_mul_centered(a: &[u32], s: &[i32]) -> Vec<i32> {
    mat_vec_mul_centered_rows(a, s, M)
}

/// Row-limited `A·s`: compute only the first `rows` rows. `a` must hold at
/// least `rows * N` entries (row-major). Results are identical to the first
/// `rows` entries of `mat_vec_mul_centered`, so callers checking only a prefix
/// of the residual can pass a prefix-expanded `a` and skip the rest.
pub fn mat_vec_mul_centered_rows(a: &[u32], s: &[i32], rows: usize) -> Vec<i32> {
    debug_assert!(a.len() >= rows * N);
    debug_assert_eq!(s.len(), N);

    let mut out = vec![0i32; rows];
    for i in 0..rows {
        let row_start = i * N;
        let mut acc: i64 = 0;
        for j in 0..N {
            // a[i][j] in [0, q), s[j] in {-B, ..., B}
            // Accumulate as i64 to avoid overflow over n = 256 terms.
            acc += (a[row_start + j] as i64) * (s[j] as i64);
        }
        out[i] = center_mod_q(acc) as i32;
    }
    out
}

/// Compute the centered residual `(A·s - t) mod q` and return it.
///
/// Both `A·s` and `t` are reduced mod q before subtraction; the final
/// result is centered.
pub fn residual_centered(a: &[u32], s: &[i32], t: &[u32]) -> Vec<i32> {
    residual_centered_rows(a, s, t, M)
}

/// Row-limited residual `(A·s - t) mod q` over the first `rows` rows. `a` must
/// hold ≥ `rows * N` entries and `t` ≥ `rows`. Bit-for-bit identical to a
/// `rows`-prefix of `residual_centered`, so it is safe on the consensus path
/// when only `rows` coefficients are checked.
pub fn residual_centered_rows(a: &[u32], s: &[i32], t: &[u32], rows: usize) -> Vec<i32> {
    debug_assert!(t.len() >= rows);
    let mut as_ = mat_vec_mul_centered_rows(a, s, rows);
    for i in 0..rows {
        // Bring t_i into centered form before subtraction, then re-center.
        let t_centered = center_mod_q(t[i] as i64) as i32;
        let raw = as_[i] as i64 - t_centered as i64;
        as_[i] = center_mod_q(raw) as i32;
    }
    as_
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::infinity_norm;
    use crate::params::Q;

    #[test]
    fn matmul_zero_vector_gives_zero() {
        let a = vec![1u32; M * N];
        let s = vec![0i32; N];
        let result = mat_vec_mul_centered(&a, &s);
        assert_eq!(result.len(), M);
        for r in result {
            assert_eq!(r, 0);
        }
    }

    #[test]
    fn matmul_identity_like() {
        // If A is the all-ones matrix and s = (1, 0, 0, ..., 0),
        // then A·s should be (1, 1, ..., 1) mod q.
        let a = vec![1u32; M * N];
        let mut s = vec![0i32; N];
        s[0] = 1;
        let result = mat_vec_mul_centered(&a, &s);
        for r in result {
            assert_eq!(r, 1);
        }
    }

    #[test]
    fn residual_zero_when_target_equals_product() {
        // If t = A·s, residual is identically zero.
        let mut a = vec![0u32; M * N];
        for entry in a.iter_mut() {
            *entry = 7; // arbitrary fixed value < q
        }
        let mut s = vec![0i32; N];
        s[0] = 1;
        s[5] = -1;

        // Compute A·s manually then use as t.
        let as_ = mat_vec_mul_centered(&a, &s);
        // Convert to unsigned for use as t.
        let t: Vec<u32> = as_.iter().map(|&v| {
            if v >= 0 {
                v as u32
            } else {
                (Q as i64 + v as i64) as u32
            }
        }).collect();

        let r = residual_centered(&a, &s, &t);
        let norm = infinity_norm(&r);
        assert_eq!(norm, 0, "residual should be zero when t = A·s");
    }

    #[test]
    fn no_overflow_with_worst_case_accumulation() {
        // Worst-case row: all entries = q-1, all s_j = B, n = 256
        // sum = n * (q-1) * B ≈ 2^33, fits comfortably in i64.
        let a = vec![Q - 1; M * N];
        let s = vec![crate::params::B; N];
        let _ = mat_vec_mul_centered(&a, &s);
        // No panic ⇒ no overflow.
    }

    #[test]
    fn row_limited_residual_equals_full_prefix() {
        // Consensus-neutrality guard for the efficiency optimization: the
        // row-limited residual (from a prefix-expanded matrix) must be
        // bit-for-bit identical to the corresponding prefix of the full
        // residual, for every width k the regimes use.
        use crate::expand::{expand_matrix_and_target, expand_matrix_and_target_rows};
        let seed = [9u8; 64];
        let mut s = [0i32; N];
        for (i, v) in s.iter_mut().enumerate() {
            *v = (i as i32 % 5) - 2; // in {-2,...,2}
        }
        let (a_full, t_full) = expand_matrix_and_target(&seed);
        let full = residual_centered(&a_full, &s, &t_full);

        for k in [1usize, 4, 7, 64, M] {
            let (a_k, t_k) = expand_matrix_and_target_rows(&seed, k);
            let part = residual_centered_rows(&a_k, &s, &t_k, k);
            assert_eq!(part.as_slice(), &full[..k],
                "row-limited residual must equal the full prefix for k={k}");
        }
    }
}
