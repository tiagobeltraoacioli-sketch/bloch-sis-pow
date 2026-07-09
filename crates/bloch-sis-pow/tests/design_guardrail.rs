//! Living guardrail for the small-k + leading-zeros PoW design (S1).
//!
//! Encodes the docs/specs/POW-HARDNESS.md finding in code: a small, non-trivial
//! residual width `k` is the secure shape; checking all `M` is broken. If anyone
//! sets `k` to full-`M` or otherwise into the trivial regime, this fails.

use bloch_sis_pow::params::{B, BETA, M, N, Q};
use bloch_sis_pow::{residual_regime_nontrivial, TESTNET_RESIDUAL_COEFFS};

/// Brute-force PoW work (bits) for checking `k` residual coords at bound `β`.
fn work_bits(k: usize) -> f64 {
    (k as f64) * ((Q as f64) / (2.0 * BETA as f64)).log2()
}
/// log2 size of the small-`s` search space (must exceed work for feasibility).
fn space_bits() -> f64 {
    (N as f64) * ((2 * B + 1) as f64).log2()
}

#[test]
fn active_k_is_non_trivial() {
    assert!(
        residual_regime_nontrivial(TESTNET_RESIDUAL_COEFFS, BETA, Q),
        "the active residual width must stay out of the trivial q-ary regime (√k·β < q)"
    );
}

#[test]
fn full_m_is_broken_and_thus_not_the_canonical_check() {
    // Trivial for lattice reduction: √M·β ≥ q.
    assert!(
        !residual_regime_nontrivial(M, BETA, Q),
        "full-M must be trivial — it is NOT a stronger canonical mode"
    );
    // ...and infeasible for honest mining: space cannot cover the work.
    assert!(
        space_bits() < work_bits(M),
        "full-M work must exceed the s-space (no small-s solution exists)"
    );
}

#[test]
fn small_k_window_is_non_trivial_and_feasible() {
    // The design window: small k stays non-trivial AND feasible (a solution
    // exists), leaving the leading-zeros target to tune difficulty.
    for k in [2usize, 4, 8, 16, 32, 44] {
        assert!(residual_regime_nontrivial(k, BETA, Q), "k={k} must be non-trivial");
        assert!(
            space_bits() >= work_bits(k),
            "k={k} must be feasible: space {:.0}b >= work {:.0}b",
            space_bits(),
            work_bits(k)
        );
    }
}
