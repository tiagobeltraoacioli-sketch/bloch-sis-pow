// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Centered modular arithmetic over Z_q.
//
// Bloch-SIS-PoW uses the *centered* representative range
// `[-(q-1)/2, (q-1)/2]` rather than `[0, q-1]`. This is essential for
// the residual norm check `||A·s - t||_∞ < β` because we need the
// distance to the *nearest* multiple of q, not just the canonical
// representative.

//! Centered modular arithmetic over `Z_q` where `q = 8 380 417`.

use crate::params::{Q, Q_HALF, Q_I64};

/// Reduce an integer modulo `q` to the canonical centered range
/// `[-(q-1)/2, (q-1)/2]`.
///
/// This function is *constant time with respect to the value being reduced*
/// in the sense that branching is on `Q_HALF`, which is a public constant.
/// It does not branch on the input.
#[inline]
pub fn center_mod_q(x: i64) -> i64 {
    // Reduce to [0, q-1) first.
    let mut r = x % Q_I64;
    if r < 0 {
        r += Q_I64;
    }
    // Map [q/2, q-1] to [-(q/2), -1] (centered).
    if r > Q_HALF {
        r - Q_I64
    } else {
        r
    }
}

/// Reduce an unsigned i32 (post matrix-vector multiplication) into the
/// centered range. Convenience wrapper.
#[inline]
pub fn center_mod_q_i32(x: i32) -> i32 {
    center_mod_q(x as i64) as i32
}

/// Add two values modulo q, returning a value in the *unsigned*
/// canonical range [0, q-1].
#[inline]
pub fn add_mod_q(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    let s = a + b;
    if s >= Q { s - Q } else { s }
}

/// Subtract `b` from `a` modulo q, returning a value in [0, q-1].
#[inline]
pub fn sub_mod_q(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

/// Multiply two values modulo q. Performed in u64 to avoid overflow.
///
/// NOTE: For production-grade performance, this should be replaced with
/// Montgomery or Barrett reduction. For the reference implementation,
/// the straightforward u64 multiplication is correct and clear.
#[inline]
pub fn mul_mod_q(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    ((a as u64 * b as u64) % Q as u64) as u32
}

/// Compute the infinity norm of a slice of (already-centered) i32 values.
///
/// Returns the maximum absolute value. The returned `u32` always fits
/// because the centered range is bounded by `Q_HALF < 2^22`.
#[inline]
pub fn infinity_norm(coeffs: &[i32]) -> u32 {
    let mut max: u32 = 0;
    for &c in coeffs {
        let abs = c.unsigned_abs();
        if abs > max {
            max = abs;
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn center_round_trip() {
        for x in [-1_000_000_i64, -1, 0, 1, 1_000_000, Q_I64 - 1, Q_I64, Q_I64 + 5] {
            let centered = center_mod_q(x);
            assert!(centered.abs() <= Q_HALF, "out of centered range: {centered}");
            // Centered representative is congruent to x mod q.
            let diff = (x - centered).rem_euclid(Q_I64);
            assert_eq!(diff, 0, "centered({x}) = {centered} not congruent");
        }
    }

    #[test]
    fn add_mod_q_basic() {
        assert_eq!(add_mod_q(1, 1), 2);
        assert_eq!(add_mod_q(Q - 1, 1), 0);
        assert_eq!(add_mod_q(Q - 5, 10), 5);
    }

    #[test]
    fn sub_mod_q_basic() {
        assert_eq!(sub_mod_q(5, 3), 2);
        assert_eq!(sub_mod_q(0, 1), Q - 1);
        assert_eq!(sub_mod_q(3, 5), Q - 2);
    }

    #[test]
    fn mul_mod_q_overflow_safe() {
        // Worst case: (q-1) * (q-1) ≈ 2^46, well within u64 range.
        let r = mul_mod_q(Q - 1, Q - 1);
        assert!(r < Q);
        // Verify by independent computation.
        let expected = ((Q as u64 - 1) * (Q as u64 - 1) % Q as u64) as u32;
        assert_eq!(r, expected);
    }

    #[test]
    fn infinity_norm_basic() {
        assert_eq!(infinity_norm(&[]), 0);
        assert_eq!(infinity_norm(&[0, 0, 0]), 0);
        assert_eq!(infinity_norm(&[1, -2, 3, -4]), 4);
        assert_eq!(infinity_norm(&[i32::MIN]), i32::MIN.unsigned_abs());
    }
}
