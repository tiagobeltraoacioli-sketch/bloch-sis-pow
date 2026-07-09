//! Module-SIS Proof-of-Work adapter.
//!
//! This is the seam between Bloch's block layer and the `bloch-sis-pow`
//! reference crate (Module-SIS lattice PoW, the identity of Bloch-SIS).
//! Since B5b, **Module-SIS is the live consensus PoW**: `Block::validate_pow`
//! verifies the block's solution vector under the relaxed testnet regime
//! (`verify_regime` with `TESTNET_RESIDUAL_COEFFS`); SHA-256d is gone.
//!
//! ## Honest status
//! The reference crate is research-grade and its full-`M` regime **cannot be
//! mined** (finding a short SIS vector needs BKZ + Babai, not yet implemented)
//! — nor is full-`M` secure at `β = q/16` (trivial q-ary regime; see the
//! crate header). Bloch therefore runs the relaxed testnet regime — **zero
//! security by design** — until the research track (lattice-estimator, BKZ
//! solver, ePrint, audit) produces a vetted secure parameter set. See
//! `BLOCH_DEVELOPMENT_PLAN.md` §3 and `crates/bloch-sis-pow`.

pub use bloch_sis_pow::{bits_to_target, target_to_bits, Target, VerifyError};

/// PoW solution-vector dimension (the witness a mined block carries).
/// Must equal the crate's Module-SIS dimension `N`.
pub const SOLUTION_LEN: usize = 256;
const _: () = assert!(SOLUTION_LEN == bloch_sis_pow::params::N);

/// Number of residual coefficients checked in the **relaxed testnet regime**
/// (re-exported from the crate). This small width makes brute-force mining
/// feasible but is **zero security**. (The full-`M`=512 width is NOT a secure
/// alternative — it is unmineable AND in the trivial q-ary regime at
/// `β = q/16`; the secure width awaits the lattice-estimator run.)
pub use bloch_sis_pow::TESTNET_RESIDUAL_COEFFS;

/// GhostDAG accumulated-work contribution of a block at compact difficulty
/// `bits`, computed from the **crate's** target semantics (consistent with
/// `validate_pow` and difficulty). Work = 2²⁵⁶ / target, approximated on the
/// top 16 target bytes into a u128 (matches the DAG's `work: u128` field).
#[inline]
pub fn work_from_bits(bits: u32) -> u128 {
    let target = bits_to_target(bits);
    let mut t_val: u128 = 0;
    for &b in target.as_bytes().iter().take(16) {
        t_val = (t_val << 8) | b as u128;
    }
    if t_val == 0 {
        u128::MAX
    } else {
        u128::MAX / t_val
    }
}

/// Next-block difficulty via ASERT-Lattice (the crate's 30 s-tuned ASERT),
/// anchored at genesis. `parent_timestamp` is the selected parent's timestamp;
/// `height` is the new block's height. Miner and validator MUST call this
/// identically so the expected `bits` match.
#[inline]
pub fn next_bits(
    anchor_bits: u32,
    anchor_timestamp: u64,
    parent_timestamp: u64,
    height: u64,
) -> u32 {
    bloch_sis_pow::difficulty::asert_next_bits(
        anchor_bits,
        anchor_timestamp as i64,
        0, // anchor height = genesis
        parent_timestamp as i64,
        height,
    )
}

/// Testnet-regime verify: relaxed residual width. **Zero security** — dev only.
#[inline]
pub fn verify_sis_pow_testnet(
    pow_preimage: &[u8],
    nonce: u64,
    solution: &[i32; SOLUTION_LEN],
    bits: u32,
) -> Result<(), VerifyError> {
    let target = bits_to_target(bits);
    bloch_sis_pow::verify_regime(pow_preimage, nonce, solution, &target, TESTNET_RESIDUAL_COEFFS)
}

/// Testnet-regime miner: brute-force search under the relaxed residual width.
/// Returns the found `(nonce, solution)` or `None` within the attempt budget.
/// **Zero security** — dev/testnet only.
pub fn mine_sis_pow_testnet(
    pow_preimage: &[u8],
    bits: u32,
    start_nonce: u64,
    max_attempts: u64,
) -> Option<(u64, [i32; SOLUTION_LEN])> {
    use bloch_sis_pow::solver::{mine, MineConfig};
    let target = bits_to_target(bits);
    let cfg = MineConfig {
        start_nonce,
        candidates_per_nonce: 4096,
        max_total_attempts: max_attempts,
        residual_coeffs: TESTNET_RESIDUAL_COEFFS,
    };
    mine(pow_preimage, &target, &cfg, None)
        .ok()
        .map(|r| (r.nonce, r.solution))
}

/// Verify a Module-SIS PoW witness at compact difficulty `bits`.
///
/// - `pow_preimage`: the block's canonical PoW header bytes. The crate derives
///   the seed as `SHAKE256(DOMAIN_SEED || pow_preimage || nonce)`, so the
///   preimage must commit to every consensus field **except** the nonce (which
///   the crate appends). The exact preimage bytes are fixed by B5b.
/// - `nonce`: the block nonce.
/// - `solution`: the short vector `s ∈ {-B,…,B}^N` found by the miner.
/// - `bits`: compact difficulty target.
///
/// Returns `Ok(())` iff the norm bound, SIS residual bound, and aux-hash
/// difficulty filter all hold (see `bloch_sis_pow::verify`).
#[inline]
pub fn verify_sis_pow(
    pow_preimage: &[u8],
    nonce: u64,
    solution: &[i32; SOLUTION_LEN],
    bits: u32,
) -> Result<(), VerifyError> {
    let target = bits_to_target(bits);
    bloch_sis_pow::verify(pow_preimage, nonce, solution, &target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solution_len_matches_crate_dimension() {
        assert_eq!(SOLUTION_LEN, bloch_sis_pow::params::N);
    }

    #[test]
    fn zero_solution_is_rejected() {
        // s = 0 → residual = -t, whose infinity norm is ~q/2 ≫ β, so even at
        // the easiest target the SIS residual check must reject it. Confirms
        // the adapter is wired to the crate's real verification path.
        let preimage = b"bloch-pow-adapter-test-preimage";
        let s = [0i32; SOLUTION_LEN];
        let err = verify_sis_pow(preimage, 0, &s, 0x207f_ffff).unwrap_err();
        assert!(matches!(err, VerifyError::ResidualTooLarge { .. }));
    }

    #[test]
    fn testnet_mine_then_verify_roundtrip() {
        // End-to-end: the relaxed testnet regime must be brute-force mineable,
        // its solution must verify under the testnet regime, be REJECTED by the
        // full-M verify (regime separation is real), and fail under a tampered
        // nonce.
        let preimage = b"bloch-testnet-e2e-preimage";
        // Easiest aux target so only the (relaxed) residual gates mining.
        let bits = target_to_bits(&Target::MAX);

        let (nonce, s) = mine_sis_pow_testnet(preimage, bits, 0, 20_000_000)
            .expect("relaxed testnet regime must be brute-force mineable");

        // Testnet verify accepts the mined solution.
        assert!(verify_sis_pow_testnet(preimage, nonce, &s, bits).is_ok());
        // Full-M verify must reject it — the relaxation is real.
        assert!(verify_sis_pow(preimage, nonce, &s, bits).is_err());
        // Tampering the nonce breaks it even under the testnet regime.
        assert!(verify_sis_pow_testnet(preimage, nonce.wrapping_add(1), &s, bits).is_err());
    }

    #[test]
    fn bits_roundtrip_through_target() {
        // Adapter exposes the crate's compact-bits <-> Target mapping intact.
        let bits = 0x1d00_ffff;
        let t = bits_to_target(bits);
        let back = target_to_bits(&t);
        // Round-trip is lossy in the low mantissa bits but must be stable
        // (idempotent) on re-encode.
        let t2 = bits_to_target(back);
        assert_eq!(t.as_bytes(), t2.as_bytes());
    }
}
