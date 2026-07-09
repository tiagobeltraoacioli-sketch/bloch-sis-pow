// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Block verification — the cheap-CPU side of the protocol.

//! Bloch-SIS-PoW verifier.
//!
//! Verification is the operation every full node performs on every
//! incoming block. It must therefore be cheap — Bloch's reference
//! verifier completes in approximately 1 ms on contemporary CPUs,
//! dominated by the matrix-vector multiplication and the SHAKE-256
//! invocation for the auxiliary hash.
//!
//! Pseudocode:
//!
//! ```text
//! Verify(header, nu, s, target):
//!   1. seed := SHAKE(POW-SEED-V1, header || nu, 64 bytes)
//!   2. (A, t) := Expand(seed)
//!   3. assert ||s||_∞ ≤ B          // norm check
//!   4. r := A·s − t  (mod q, centered)
//!   5. assert ||r||_∞ < β           // residual check
//!   6. aux := SHAKE(POW-AUX-V1, encode(s) || nu || header, 32 bytes)
//!   7. assert aux < target          // difficulty filter
//!   8. accept
//! ```

use crate::difficulty::{hash_meets_target, Target};
use crate::encode::encode_s;
use crate::error::VerifyError;
use crate::expand::expand_matrix_and_target_rows;
use crate::field::infinity_norm;
use crate::matrix::residual_centered_rows;
use crate::params::{B, BETA, BETA_I64, M, N};
use crate::shake::shake256_dom;
use crate::solver::derive_pow_seed;
use crate::DOMAIN_LABEL_POW_AUX;

/// Verify a Bloch-SIS-PoW solution.
///
/// # Inputs
/// - `header`: serialized block header bytes (the same bytes that were
///   used during mining; everything *except* the nonce/solution).
/// - `nonce`: the nonce produced by the miner.
/// - `solution`: the solution vector `s ∈ {-B, …, B}^N`.
/// - `target`: the difficulty target encoded in the block header.
///
/// # Returns
/// - `Ok(())` if all three checks pass.
/// - `Err(VerifyError::SolutionTooLarge)` if `||s||_∞ > B`.
/// - `Err(VerifyError::ResidualTooLarge { actual, bound })` if the
///   residual exceeds `β`.
/// - `Err(VerifyError::AuxHashAboveTarget)` if the auxiliary hash
///   does not meet the target.
///
/// # Security honesty
/// This checks all `M` residual coefficients, but that is **not** a secure
/// mode: at `β = q/16`, full-`M` is in the trivial q-ary regime
/// (`√M·β ≥ q` — no lattice hardness) *and* is infeasible to honestly mine.
/// Both shipped regimes (full-`M` here, small-`k` testnet) are insecure; the
/// secure parameter set is the research track (see the crate header and
/// `residual_regime_nontrivial`). This function is retained for
/// wire-format compatibility and regime-separation testing.
pub fn verify(
    header: &[u8],
    nonce: u64,
    solution: &[i32; N],
    target: &Target,
) -> Result<(), VerifyError> {
    // Full-M verification. NOT "full-security" — see the doc comment above.
    verify_regime(header, nonce, solution, target, M)
}

/// Verify a Bloch-SIS-PoW solution under an explicit residual-check width.
///
/// Neither shipped width is secure at `β = q/16` (see the crate header):
/// - `residual_coeffs == M` is the full-`M` wire-compat check — trivial for
///   lattice reduction (`√M·β ≥ q`) and infeasible to honestly mine.
/// - A small value (e.g. `TESTNET_RESIDUAL_COEFFS = 4`) is the **relaxed
///   testnet regime** — brute-force mineable but essentially ZERO security.
///
/// Miner and verifier MUST agree on the same value. The secure `(k, β)` pair
/// awaits the lattice-estimator run (research track).
pub fn verify_regime(
    header: &[u8],
    nonce: u64,
    solution: &[i32; N],
    target: &Target,
    residual_coeffs: usize,
) -> Result<(), VerifyError> {
    // Design guardrail (S1), wired: a residual width in the trivial q-ary
    // regime (k·β² ≥ q²) yields no lattice hardness. The full-M width is
    // knowingly trivial (see crate header) and is kept only for wire-format
    // compatibility and regime-separation tests; any OTHER width must stay
    // non-trivial, so trip loudly in tests/debug builds if one does not.
    debug_assert!(
        residual_coeffs >= M
            || crate::residual_regime_nontrivial(residual_coeffs, BETA, crate::params::Q),
        "residual width k={residual_coeffs} is in the trivial q-ary regime \
         (k*beta^2 >= q^2): the residual check provides no lattice hardness"
    );

    // (1) Norm check on s.
    if solution.iter().any(|&v| v.abs() > B) {
        return Err(VerifyError::SolutionTooLarge);
    }

    // (2) Re-derive seed and expand only the first `k` rows of (A, t). Rows
    // beyond `k` are never inspected under the residual-width check, and the
    // prefix is bit-identical to a full expansion, so this is a pure speedup
    // (~M/k× under the relaxed testnet regime) with no consensus change.
    let k = residual_coeffs.min(M);
    let seed = derive_pow_seed(header, nonce);
    let (a, t) = expand_matrix_and_target_rows(&seed, k);

    // (3+4) Row-limited centered residual r = A·s - t (mod q), norm-checked.
    let r = residual_centered_rows(&a, solution, &t, k);
    let actual = infinity_norm(&r);
    if actual as i64 >= BETA_I64 {
        return Err(VerifyError::ResidualTooLarge {
            actual,
            bound: BETA,
        });
    }

    // (5) Auxiliary hash check.
    let s_bytes = encode_s(solution).map_err(VerifyError::from)?;
    let nonce_bytes = nonce.to_le_bytes();
    let aux = shake256_dom(
        DOMAIN_LABEL_POW_AUX,
        &[&s_bytes, &nonce_bytes, header],
        32,
    );
    let mut aux_arr = [0u8; 32];
    aux_arr.copy_from_slice(&aux);

    if !hash_meets_target(&aux_arr, target) {
        return Err(VerifyError::AuxHashAboveTarget);
    }

    Ok(())
}

/// Recompute the auxiliary hash for a (header, nonce, s) triple. Useful
/// for callers that want to attach the aux-hash as a block identifier
/// or pre-compute it before storing.
pub fn compute_aux_hash(header: &[u8], nonce: u64, solution: &[i32; N]) -> [u8; 32] {
    let s_bytes = encode_s(solution).expect("solution validity is the caller's responsibility");
    let nonce_bytes = nonce.to_le_bytes();
    let aux = shake256_dom(
        DOMAIN_LABEL_POW_AUX,
        &[&s_bytes, &nonce_bytes, header],
        32,
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&aux);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rejects_oversized_coefficient() {
        let header = b"verify-test";
        let nonce = 0u64;
        let mut s = [0i32; N];
        s[0] = 99; // way out of bound
        let target = Target::MAX;
        let result = verify(header, nonce, &s, &target);
        assert!(matches!(result, Err(VerifyError::SolutionTooLarge)));
    }

    #[test]
    fn verify_rejects_random_zero_solution_with_min_target() {
        // s = 0 yields A·0 = 0; residual = -t, which (with high prob)
        // has infinity norm ≈ q/2, way larger than β. So verification
        // should fail with ResidualTooLarge.
        let header = b"residual-test";
        let nonce = 17u64;
        let s = [0i32; N];
        let result = verify(header, nonce, &s, &Target::MAX);
        match result {
            Err(VerifyError::ResidualTooLarge { actual, bound }) => {
                assert!(actual >= bound);
            }
            other => panic!("expected ResidualTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn aux_hash_is_deterministic() {
        let header = b"hash-determinism";
        let mut s = [0i32; N];
        for i in 0..N {
            s[i] = (i as i32 % 5) - 2;
        }
        let h1 = compute_aux_hash(header, 1234, &s);
        let h2 = compute_aux_hash(header, 1234, &s);
        assert_eq!(h1, h2);
    }

    #[test]
    fn aux_hash_changes_with_nonce() {
        let header = b"hash-determinism";
        let s = [0i32; N];
        let h1 = compute_aux_hash(header, 1, &s);
        let h2 = compute_aux_hash(header, 2, &s);
        assert_ne!(h1, h2);
    }
}
