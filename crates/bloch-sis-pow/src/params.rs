// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Compile-time parameters for Bloch-SIS-PoW.
//
// CHANGING ANY OF THESE CONSTANTS IS A HARD-FORK.

//! Bloch-SIS-PoW shipped (v0.1 reference) parameters.
//!
//! These values are derived from the alignment with NIST FIPS 204 (ML-DSA-65)
//! to maximize implementation reuse — most importantly, the prime modulus
//! `q = 2^23 - 2^13 + 1 = 8 380 417`, which permits sharing the
//! Number-Theoretic Transform (NTT) with the signature subsystem.
//!
//! **These are NOT security-validated parameters.** At `β = q/16` both shipped
//! residual regimes are insecure (see the crate header in `lib.rs` and
//! `residual_regime_nontrivial`); the secure parameter set awaits the
//! lattice-estimator run (`deploy/pow-estimator`) on the research track.

/// Solution vector dimension `n`.
///
/// `s ∈ Z^n` with `||s||_∞ ≤ B`. Final value subject to revision after
/// concrete-security analysis with the lattice estimator.
pub const N: usize = 256;

/// Number of rows in the public matrix `A` (sample / row dimension `m`).
///
/// `A ∈ Z_q^{m × n}`. The choice `m = 2n` is conventional in lattice
/// cryptography and gives a comfortable solution-density regime.
pub const M: usize = 512;

/// Prime modulus `q`.
///
/// `q = 2^23 - 2^13 + 1 = 8 380 417`. Identical to ML-DSA-65 (FIPS 204),
/// chosen so the NTT implementation can be shared between PoW and
/// signature subsystems.
pub const Q: u32 = 8_380_417;

/// `q` as i64 for centered-mod arithmetic without overflow on i32.
pub const Q_I64: i64 = Q as i64;

/// `(q - 1) / 2 = 4 190 208` — the boundary of the centered representative.
/// Used by `field::center_mod_q`.
pub const Q_HALF: i64 = (Q_I64 - 1) / 2;

/// Bound `B` on the infinity-norm of solution vectors.
///
/// `s_i ∈ {-B, …, -1, 0, 1, …, B}` with `B = 2`. Standard "short ternary
/// extended" choice from lattice cryptography literature; small enough to
/// preserve hardness margin, large enough to admit solutions reliably.
pub const B: i32 = 2;

/// Bound `β` on the residual infinity-norm: `||A·s − t||_∞ < β`.
///
/// `β = q / 16 = 523 776`. Sufficiently loose that solutions exist with
/// high probability, sufficiently tight that random `s` is unlikely to
/// satisfy the residual bound.
pub const BETA: u32 = Q / 16;

/// `β` as `i64` for centered-mod comparisons.
pub const BETA_I64: i64 = BETA as i64;

/// Length of the SHAKE-256-derived seed used to expand the matrix `A`
/// and the target vector `t`. Must be ≥ 32 to provide ≥ 128 bits of
/// effective seeding entropy.
pub const POW_SEED_LEN: usize = 64;

/// Output length, in bytes, of the auxiliary hash check.
/// `target` is interpreted as a 256-bit big-endian integer.
pub const AUX_HASH_LEN: usize = 32;

/// Number of bytes used to encode the solution vector `s` for hashing.
///
/// We pack `s` as `N` signed bytes (i8) — coefficients fit in `[-B, B]`
/// which is well within `i8` range.
pub const ENCODED_S_LEN: usize = N;

// ─────────────────────────────────────────────────────────────────────────────
// Runtime parameter struct
// ─────────────────────────────────────────────────────────────────────────────

/// Parameter bundle, runtime-accessible for callers that prefer values
/// over constants. The shipped instance is [`SHIPPED_PARAMS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Solution dimension n.
    pub n: usize,
    /// Matrix row dimension m.
    pub m: usize,
    /// Prime modulus q.
    pub q: u32,
    /// Solution norm bound B.
    pub b: i32,
    /// Residual norm bound beta.
    pub beta: u32,
}

/// The shipped Bloch-SIS-PoW parameter set (v0.1 reference).
///
/// NOT security-validated: at `β = q/16` both shipped residual regimes are
/// insecure (trivial q-ary regime at full-`M`; near-zero no-shortcut hardness
/// at the tiny testnet `k`). The "canonical secure" parameters are the
/// research track (`deploy/pow-estimator`), not what ships here.
pub const SHIPPED_PARAMS: Params = Params {
    n:    N,
    m:    M,
    q:    Q,
    b:    B,
    beta: BETA,
};

/// Deprecated alias for [`SHIPPED_PARAMS`].
///
/// The old name implied a vetted, "canonical secure" configuration. No such
/// configuration ships yet — see [`SHIPPED_PARAMS`] and the crate header.
#[deprecated(note = "renamed to SHIPPED_PARAMS — the shipped v0.1 set is not a \
                     vetted secure configuration; secure params are the research track")]
pub const CANONICAL_PARAMS: Params = SHIPPED_PARAMS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_matches_ml_dsa_65() {
        // q = 2^23 - 2^13 + 1
        assert_eq!(Q, (1u32 << 23) - (1u32 << 13) + 1);
        assert_eq!(Q, 8_380_417);
    }

    #[test]
    fn beta_is_sane_fraction_of_q() {
        // beta should be a small fraction of q; here exactly q/16
        assert_eq!(BETA, Q / 16);
        assert!(BETA < Q / 4, "beta too close to q/4 — hardness may degrade");
    }

    #[test]
    fn dimensions_consistent() {
        assert_eq!(M, 2 * N, "m = 2n is the conventional lattice-cryptography choice");
        assert!(N >= 256, "n < 256 likely insufficient for 2^120 classical security");
    }

    #[test]
    fn residual_regime_guardrail_matches_documented_status() {
        use crate::{residual_regime_nontrivial, TESTNET_RESIDUAL_COEFFS};
        // The tiny testnet width stays out of the trivial q-ary regime
        // (still ~zero security — k=4 has almost no no-shortcut hardness).
        assert!(residual_regime_nontrivial(TESTNET_RESIDUAL_COEFFS, BETA, Q));
        // Full-M at beta = q/16 IS the trivial q-ary regime — documenting that
        // the shipped full-M path is NOT a secure mode (see crate header).
        assert!(
            !residual_regime_nontrivial(M, BETA, Q),
            "full-M unexpectedly non-trivial — if beta/q changed, re-run the \
             estimator and update the honesty notes in lib.rs/verify.rs/solver.rs"
        );
    }
}
