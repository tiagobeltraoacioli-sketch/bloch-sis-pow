// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Bloch-SIS-PoW — Reference Implementation v0.1
// =============================================
//
// Proof-of-Work for the Bloch Protocol: a SHAKE-256 (Keccak) hashcash
// with a Module-SIS structural gate.
//
// This crate provides a reference implementation of Bloch-SIS-PoW. A
// solution must (1) be a short vector `s`, (2) pass a Module Short
// Integer Solution (Module-SIS) residual check on the algebraic
// structure shared with NIST FIPS 204 ML-DSA-65 signatures, and
// (3) meet a SHAKE-256 aux-hash difficulty target.
//
// SECURITY MODEL — read this before quoting any number. The PoW's
// security is the CUMULATIVE HASHCASH WORK of condition (3), NOT
// lattice hardness: a trapdoorless PoW cannot be both lattice-hard and
// mineable — with no trapdoor, the lattice's core-SVP cost is
// simultaneously the attack cost and the honest mining cost, and the
// estimator frontier shows the two regimes are disjoint
// (docs/research/POW-CANONICAL-frontier.md). The Module-SIS residual
// (1)+(2) is a non-trivial structural gate (kept out of the trivial
// q-ary regime, `√k·β < q`) that binds the work to a lattice form; it
// is not the bit-security source, and no "N-bit lattice security"
// number attaches to this PoW. Its post-quantum property comes from
// SHAKE-256 (Grover: quadratic speedup only).
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

#[cfg(test)]
mod kat;

// ─────────────────────────────────────────────────────────────────────────────
// Public re-exports for the most common types and functions.
// ─────────────────────────────────────────────────────────────────────────────

pub use error::{PowError, MineError, VerifyError, BitsError};
pub use params::{Params, SHIPPED_PARAMS};
#[allow(deprecated)]
pub use params::CANONICAL_PARAMS;
pub use solver::{mine, MineResult};
pub use verify::{verify, verify_regime};
pub use difficulty::{Target, bits_to_target, try_bits_to_target, target_to_bits, hash_meets_target};

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
/// This testnet value (4) is deliberately tiny — `k = 4` adds only a ~12-bit
/// rejection floor — so **testnet is ZERO security**. The canonical `k` (and
/// `β`) await the no-shortcut / attacker-asymmetry analysis (candidate `k = 8`
/// = [`CANONICAL_RESIDUAL_COEFFS`], height-activated as soft fork SF-1;
/// `docs/research/POW-CANONICAL-frontier.md`). Note the gate is structural:
/// PoW security at any `k` is the hashcash target, not a lattice number.
pub const TESTNET_RESIDUAL_COEFFS: usize = 4;

/// Design guardrail (S1): the residual check must stay OUT of the estimator's
/// trivial q-ary infinity-norm regime, i.e. `√k·β < q`  ⟺  `k·β² < q²`
/// (integer-safe). Full-`M` at `β = q/16` violates this; any usable `k` must
/// satisfy it. This is a *structural* condition, not a security source: the
/// estimator declines the small-`k` substrate (solutions abundant → no
/// meaningful core-SVP number), so the PoW's security is the hashcash target,
/// with the gate contributing a fixed `k·log2(q/2β)`-bit rejection floor
/// (`docs/research/POW-CANONICAL-frontier.md`, `deploy/pow-estimator`).
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
     the residual gate would be structurally trivial (no rejection floor at all)"
);

/// Candidate **canonical** residual width `k = 8` — the target of the
/// height-activated soft fork that tightens the gate from
/// [`TESTNET_RESIDUAL_COEFFS`] (= 4). See `docs/research/POW-CANONICAL-frontier.md`.
///
/// HONESTY — what `k = 8` buys and what it does not. At `β = q/16` each
/// residual coefficient passes with probability `≈ 2β/q = 1/8`, so the gate's
/// structural rejection floor is `k·log2(q/2β) = 3k` bits: `k = 8` raises it
/// from ~2^12 (testnet `k = 4`) to ~2^24. That floor is **NOT** the security
/// source — the PoW's security remains the cumulative hashcash work of the
/// SHAKE-256 aux-hash target (see the crate header); no lattice bit-security
/// number attaches to any `k`. `k = 8` is the *candidate* canonical gate from
/// the frontier research, adopted **pending the no-shortcut /
/// attacker-asymmetry proof**; it is not the finalized secure parameter set.
///
/// SOFT-FORK PROPERTY: the residual check inspects the first `k` coefficients,
/// so any solution valid at `k = 8` is automatically valid at `k = 4` (prefix
/// subset). Raising `k` is therefore a pure *tightening* — old nodes accept
/// new-rule blocks (no partition), while old-rule blocks mined under `k = 4`
/// remain valid below the activation height. The reverse is NOT true: a
/// `k = 4` solution fails `k = 8` with probability ≈ 1 − 8^-4.
pub const CANONICAL_RESIDUAL_COEFFS: usize = 8;

// Compile-time wiring of the S1 guardrail for the canonical width, identical
// to the testnet wiring above. Hand-check: `8·(q/16)² = q²/32 < q²` — holds
// with a 32× margin at the shipped `β = q/16`, `q = 8380417`.
const _: () = assert!(
    residual_regime_nontrivial(CANONICAL_RESIDUAL_COEFFS, params::BETA, params::Q),
    "CANONICAL_RESIDUAL_COEFFS is in the trivial q-ary regime (k*beta^2 >= q^2): \
     the residual gate would be structurally trivial (no rejection floor at all)"
);

// Soft-fork direction guard: the canonical width must be a TIGHTENING of the
// testnet width (prefix-subset validity: k=8-valid ⟹ k=4-valid). If a future
// edit inverts this, the height-gated activation would be a chain-splitting
// LOOSENING (a hard fork), so fail the build instead.
const _: () = assert!(
    CANONICAL_RESIDUAL_COEFFS >= TESTNET_RESIDUAL_COEFFS,
    "CANONICAL_RESIDUAL_COEFFS < TESTNET_RESIDUAL_COEFFS would make the \
     height-gated activation a loosening (hard fork), not a soft fork"
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
