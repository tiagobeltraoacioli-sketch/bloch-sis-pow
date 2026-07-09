// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Bloch-SIS-PoW — Reference Implementation v0.1
// =============================================
//
// Lattice-based Proof-of-Work for the Bloch Protocol.
//
// This crate provides a reference implementation of Bloch-SIS-PoW, a
// proof-of-work algorithm whose hardness is conjectured to reduce to
// the Module Short Integer Solution (Module-SIS) problem on the
// algebraic structure shared with NIST FIPS 204 ML-DSA-65 signatures.
//
// Status
// ======
// THIS IS REFERENCE / RESEARCH CODE. It is correct in structure but has
// not been (a) audited, (b) cryptographically peer-reviewed, (c)
// optimized for production performance. Do NOT use in production.
//
// The accompanying academic document
// (Bloch_SIS_PoW_Academic_Foundations_v0.1.pdf) describes the intended
// formal hardness analysis, parameter selection process, and outstanding
// research questions. Bloch-SIS-PoW v1.0 will track that work.
//
// Crate layout
// ============
// - params      — Compile-time constants (n, m, q, B, beta, etc.)
// - field       — Centered modular arithmetic over Z_q
// - shake       — Domain-separated SHAKE-256 wrapper
// - expand      — Deterministic expansion of seeds into matrices/vectors
// - matrix      — Matrix-vector multiplication mod q
// - solver      — Mining algorithm (search for short s satisfying SIS + aux)
// - verify      — Block verification (cheap path)
// - difficulty  — Target encoding/decoding and ASERT adjustment
// - error       — Crate-wide error types
// - encode      — Canonical byte encoding of solution vectors
//
// Companion documents
// ===================
// - Bloch Protocol — Technical Specification v0.1 (system context)
// - Bloch-SIS-PoW: Academic Foundations v0.1 (research roadmap)

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! Bloch-SIS-PoW reference implementation.
//!
//! See the crate-level documentation comment in `src/lib.rs` for status
//! and scope notes.

extern crate alloc;

pub mod params;
pub mod field;
pub mod shake;
pub mod expand;
pub mod matrix;
pub mod encode;
pub mod difficulty;
pub mod error;
pub mod solver;
pub mod verify;

#[cfg(test)]
mod tests;

// ─────────────────────────────────────────────────────────────────────────────
// Public re-exports for the most common types and functions.
// ─────────────────────────────────────────────────────────────────────────────

pub use error::{PowError, MineError, VerifyError};
pub use params::{Params, SHIPPED_PARAMS};
#[allow(deprecated)]
pub use params::CANONICAL_PARAMS;
pub use solver::{mine, MineResult};
pub use verify::{verify, verify_regime};
pub use difficulty::{Target, bits_to_target, target_to_bits, hash_meets_target};

/// Crate version, derived from Cargo metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Number of residual coordinates checked — the small `k` of the **small-k +
/// leading-zeros** PoW design (`docs/specs/POW-HARDNESS.md`). Security comes from
/// a SMALL, non-trivial `k` (the SIS no-shortcut floor) plus the leading-zeros
/// difficulty target on the aux hash — NOT from `β` and NOT from checking all `M`
/// coefficients.
///
/// Checking all `M` is **not** a stronger "canonical" mode: at `β = q/16` it is
/// simultaneously TRIVIAL for lattice reduction (`√M·β ≥ q`) and INFEASIBLE for
/// honest small-`s` mining (the s-space is far too small) — broken in both
/// directions. The design must keep `√k·β < q` (see `residual_regime_nontrivial`).
///
/// This testnet value (4) is deliberately tiny — `k = 4` yields almost no
/// no-shortcut hardness — so **testnet is ZERO security**. The canonical secure
/// `k` (and `β`) await the lattice-estimator run (`deploy/pow-estimator`).
pub const TESTNET_RESIDUAL_COEFFS: usize = 4;

/// Design guardrail (S1): the residual check must stay OUT of the estimator's
/// trivial q-ary infinity-norm regime, i.e. `√k·β < q`  ⟺  `k·β² < q²`
/// (integer-safe). Full-`M` at `β = q/16` violates this; any usable `k` must
/// satisfy it. This is a *necessary* condition, not sufficient — the per-instance
/// BKZ core-SVP cost still gates the actual security (`deploy/pow-estimator`).
///
/// Wiring: enforced at compile time for [`TESTNET_RESIDUAL_COEFFS`] (below),
/// and via `debug_assert!` in `solver::mine` / `verify::verify_regime` for any
/// runtime-chosen width other than the documented-broken full-`M` compat path.
pub const fn residual_regime_nontrivial(k: usize, beta: u32, q: u32) -> bool {
    (k as u128) * (beta as u128) * (beta as u128) < (q as u128) * (q as u128)
}

// Compile-time wiring of the S1 guardrail: if a future edit bumps `k`, `β`, or
// `q` such that the testnet residual regime becomes trivial (`√k·β ≥ q`), the
// build fails here instead of shipping a silently-hollow check.
const _: () = assert!(
    residual_regime_nontrivial(TESTNET_RESIDUAL_COEFFS, params::BETA, params::Q),
    "TESTNET_RESIDUAL_COEFFS is in the trivial q-ary regime (k*beta^2 >= q^2): \
     the residual check would provide no lattice hardness at all"
);

/// Domain separation label written into every PoW seed expansion.
/// Changing this constant is a hard-fork.
pub const DOMAIN_LABEL_POW_SEED: &[u8] = b"BLOCH-POW-SEED-V1";

/// Domain separation label written into every auxiliary hash check.
/// Changing this constant is a hard-fork.
pub const DOMAIN_LABEL_POW_AUX:  &[u8] = b"BLOCH-POW-AUX-V1";

/// Domain separation label used when expanding the target vector `t`
/// from the seed.
/// Changing this constant is a hard-fork.
pub const DOMAIN_LABEL_TARGET:   &[u8] = b"BLOCH-POW-TARGET-V1";
