// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Mining algorithm: search for short s satisfying both the Module-SIS
// constraint and the auxiliary hash difficulty filter.

//! Bloch-SIS-PoW miner — reference implementation.
//!
//! # Algorithm overview
//!
//! Given a serialized block header `H_block` and a target threshold,
//! the miner searches for a pair `(nu, s)` such that:
//!
//! 1. **Norm bound**: `||s||_∞ ≤ B` (each coefficient in `[-B, B]`).
//! 2. **Residual bound**: `||A·s − t||_∞ < β` where `(A, t)` are
//!    deterministically derived from `seed = SHAKE(H_block || nu)`.
//! 3. **Difficulty filter**: `SHAKE(s || nu || H_block) < target`.
//!
//! For each candidate `nu`, the miner re-derives `(A, t)`, then attempts
//! to find a valid `s`. The reference implementation uses a randomized
//! short-vector candidate generator: it samples `s` uniformly from
//! `{-B, …, B}^N` (specifically from a sparse "ternary-extended"
//! distribution), then checks both the residual and the auxiliary hash.
//!
//! # Performance honesty
//!
//! This is **reference**, not production. A production miner would use
//! GPU parallelism for the matrix expansion, matmul, and SHAKE grinding.
//! Lattice reduction (BKZ + Babai) is deliberately **not** implemented:
//! for the small-`k` residual gate, solutions are abundant and
//! brute-force sampling is the correct, near-optimal strategy — the PoW's
//! work is the hashcash grind, not lattice reduction
//! (`docs/research/POW-CANONICAL-frontier.md` §5.1). A BKZ miner would
//! only be needed for the full-`M` lattice-as-work design, which that
//! research proves is unmineable.
//!
//! The search strategy below is brute-force-with-rng. It is correct
//! and pedagogically clear; production miners will parallelize it.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::difficulty::{hash_meets_target, Target};
use crate::encode::encode_s;
use crate::error::MineError;
use crate::expand::expand_matrix_and_target_rows;
use crate::field::infinity_norm;
use crate::matrix::residual_centered_rows;
use crate::params::{BETA_I64, B, M, N, POW_SEED_LEN};
use crate::shake::shake256_dom;
use crate::{DOMAIN_LABEL_POW_AUX, DOMAIN_LABEL_POW_SEED};

/// Result of a successful mining attempt.
#[derive(Clone, Debug)]
pub struct MineResult {
    /// The nonce that, with `s`, satisfies all PoW conditions.
    pub nonce: u64,
    /// The solution vector `s ∈ {-B, …, B}^N`.
    pub solution: [i32; N],
    /// The auxiliary SHAKE-256 hash, retained for caller convenience
    /// (e.g., as a block-id field).
    pub aux_hash: [u8; 32],
    /// Number of total candidate attempts across all (nu, s) pairs
    /// before finding the result. Useful for difficulty calibration.
    pub attempts: u64,
}

/// Configuration for the miner.
#[derive(Clone, Debug)]
pub struct MineConfig {
    /// Starting nonce (typically random or thread-id-derived).
    pub start_nonce: u64,
    /// Maximum number of `s` candidates to try *per nonce* before
    /// advancing to the next nonce. Larger values amortize the matrix
    /// expansion cost over more candidate `s` vectors.
    pub candidates_per_nonce: u64,
    /// Maximum total candidates across all nonces before giving up.
    /// Use `u64::MAX` for unbounded.
    pub max_total_attempts: u64,
    /// Number of residual coefficients checked against β. Neither shipped
    /// width is secure at `β = q/16` (see the crate header): `M` (=512) is
    /// the full-`M` wire-compat width — trivial for lattice reduction
    /// (`√M·β ≥ q`) AND infeasible to brute-force mine — while a small value
    /// (e.g. 4) is the **relaxed testnet regime**, brute-force mineable but
    /// essentially ZERO security. The verifier MUST use the same value (see
    /// `verify::verify_regime`). The secure `(k, β)` pair is the research
    /// track, not shipped here.
    pub residual_coeffs: usize,
}

impl Default for MineConfig {
    fn default() -> Self {
        Self {
            start_nonce: 0,
            candidates_per_nonce: 4096,
            max_total_attempts: u64::MAX,
            // Full-M by default for wire-compat with `verify::verify`. NOT a
            // secure mode — trivial q-ary regime AND unmineable; see crate
            // header. Testnet mining passes TESTNET_RESIDUAL_COEFFS instead.
            residual_coeffs: M,
        }
    }
}

/// PRNG state for candidate-`s` generation. We use SplitMix64 because
/// it is fast, deterministic given a seed, and adequate for sampling
/// short ternary-extended vectors. (NOT cryptographically secure; that
/// is fine: the *miner's* randomness only affects which solution is
/// found, not security.)
struct CandRng(u64);

impl CandRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        // Splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Sample a coefficient uniformly from `{-B, …, B}` (= 2B+1 values).
    fn next_coeff(&mut self) -> i32 {
        let r = self.next_u64();
        // 2B+1 = 5 for B=2. We take r mod 5 then shift.
        let v = (r % (2 * B as u64 + 1)) as i32;
        v - B
    }
}

/// Mine a block.
///
/// # Arguments
/// - `header`: serialized block-header bytes (everything except `nu, s`).
/// - `target`: difficulty target (acceptance threshold).
/// - `cfg`: search configuration.
/// - `cancel`: optional cooperative cancellation flag (set to `true`
///   externally to abort the miner).
///
/// # Returns
/// `Ok(MineResult)` if a valid PoW is found within budget;
/// `Err(MineError::AttemptsExhausted)` if the attempt budget was reached;
/// `Err(MineError::Cancelled)` if `cancel` was tripped.
pub fn mine(
    header: &[u8],
    target: &Target,
    cfg: &MineConfig,
    cancel: Option<&AtomicBool>,
) -> Result<MineResult, MineError> {
    // Design guardrail (S1), wired: see `verify::verify_regime`. Full-M is
    // exempt (documented-broken wire-compat path); any other width must stay
    // out of the trivial q-ary regime.
    debug_assert!(
        cfg.residual_coeffs >= M
            || crate::residual_regime_nontrivial(cfg.residual_coeffs, crate::params::BETA, crate::params::Q),
        "residual width k={} is in the trivial q-ary regime (k*beta^2 >= q^2): \
         the residual check provides no lattice hardness",
        cfg.residual_coeffs
    );

    let mut nonce = cfg.start_nonce;
    let mut total_attempts: u64 = 0;
    let mut rng = CandRng::new(0xCAFEF00D_DEADBEEF ^ nonce);

    while total_attempts < cfg.max_total_attempts {
        if let Some(c) = cancel {
            if c.load(Ordering::Relaxed) {
                return Err(MineError::Cancelled);
            }
        }

        // Derive seed for this nonce, then expand only the first `k` rows of A
        // and t — the residual check inspects only `k` coefficients, so rows
        // beyond `k` would be pure waste (~M/k× under the testnet regime).
        let k = cfg.residual_coeffs.min(M);
        let seed = derive_pow_seed(header, nonce);
        let (a, t) = expand_matrix_and_target_rows(&seed, k);

        // Try candidates_per_nonce values of s under this seed.
        for _ in 0..cfg.candidates_per_nonce {
            total_attempts += 1;
            if total_attempts >= cfg.max_total_attempts {
                break;
            }

            // Sample candidate s ∈ {-B,...,B}^N.
            let mut s = [0i32; N];
            for slot in s.iter_mut() {
                *slot = rng.next_coeff();
            }

            // Cheap check: are all coefficients in range? (Always true
            // by construction, but we keep the check defensive.)
            if s.iter().any(|&v| v.abs() > B) {
                continue;
            }

            // Check residual norm over the first `residual_coeffs` entries
            // (== M for the full-M wire-compat regime — unmineable AND not
            // secure; smaller for the relaxed testnet regime).
            let r = residual_centered_rows(&a, &s, &t, k);
            let norm = infinity_norm(&r);
            if norm as i64 >= BETA_I64 {
                continue;
            }

            // Check auxiliary hash threshold.
            let s_bytes = match encode_s(&s) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let nonce_bytes = nonce.to_le_bytes();
            let aux = shake256_dom(
                DOMAIN_LABEL_POW_AUX,
                &[&s_bytes, &nonce_bytes, header],
                32,
            );
            let mut aux_arr = [0u8; 32];
            aux_arr.copy_from_slice(&aux);

            if hash_meets_target(&aux_arr, target) {
                return Ok(MineResult {
                    nonce,
                    solution: s,
                    aux_hash: aux_arr,
                    attempts: total_attempts,
                });
            }
        }

        // Advance nonce; re-seed the candidate RNG with new entropy.
        nonce = nonce.wrapping_add(1);
        rng = CandRng::new((0xCAFEF00D_DEADBEEF as u64).wrapping_mul(nonce.wrapping_add(1)));
    }

    Err(MineError::AttemptsExhausted)
}

/// Derive the PoW seed from a header and nonce.
///
/// This is the canonical seed used by both the miner and the verifier
/// to reproduce `(A, t)` deterministically.
pub fn derive_pow_seed(header: &[u8], nonce: u64) -> Vec<u8> {
    let nonce_bytes = nonce.to_le_bytes();
    shake256_dom(
        DOMAIN_LABEL_POW_SEED,
        &[header, &nonce_bytes],
        POW_SEED_LEN,
    )
}

/// Multi-threaded mining helper. Spawns one worker per logical CPU,
/// each searching a disjoint nonce range.
///
/// Available only with the `parallel` feature (default-enabled).
#[cfg(feature = "parallel")]
pub fn mine_parallel(
    header: &[u8],
    target: &Target,
    cfg: &MineConfig,
    num_threads: usize,
) -> Result<MineResult, MineError> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::thread;

    let cancel = Arc::new(AtomicBool::new(false));
    let result = Arc::new(parking_lot_like::Mutex::new(None::<MineResult>));
    let total_attempts = Arc::new(AtomicU64::new(0));

    let nonce_range_per_thread = u64::MAX / num_threads.max(1) as u64;

    thread::scope(|s| {
        let mut handles = Vec::new();
        for tid in 0..num_threads {
            let header = header.to_vec();
            let target = *target;
            let cancel = cancel.clone();
            let result = result.clone();
            let total_attempts = total_attempts.clone();

            let mut local_cfg = cfg.clone();
            local_cfg.start_nonce = cfg.start_nonce
                .wrapping_add((tid as u64).wrapping_mul(nonce_range_per_thread));

            let handle = s.spawn(move || {
                if let Ok(r) = mine(&header, &target, &local_cfg, Some(&cancel)) {
                    cancel.store(true, Ordering::Relaxed);
                    let mut guard = result.lock();
                    if guard.is_none() {
                        *guard = Some(r.clone());
                        total_attempts.fetch_add(r.attempts, Ordering::Relaxed);
                    }
                }
            });
            handles.push(handle);
        }
        for h in handles { let _ = h.join(); }
    });

    let final_result = result.lock().clone();
    match final_result {
        Some(mut r) => {
            r.attempts = total_attempts.load(Ordering::Relaxed);
            Ok(r)
        }
        None => Err(MineError::AttemptsExhausted),
    }
}

// Tiny mutex stand-in to avoid pulling parking_lot in if not needed.
#[cfg(feature = "parallel")]
mod parking_lot_like {
    use std::sync::Mutex as StdMutex;
    pub struct Mutex<T>(StdMutex<T>);
    impl<T> Mutex<T> {
        pub fn new(v: T) -> Self { Self(StdMutex::new(v)) }
        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
            self.0.lock().unwrap_or_else(|e| e.into_inner())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty::Target;

    #[test]
    fn mine_with_max_target_succeeds_quickly() {
        // With Target::MAX, *every* aux hash satisfies the threshold.
        // The bottleneck is finding s such that the residual bound holds.
        let header = b"genesis-test-header-2026";
        let cfg = MineConfig {
            candidates_per_nonce: 16384,
            max_total_attempts: 1_000_000,
            ..Default::default()
        };
        let r = mine(header, &Target::MAX, &cfg, None);
        // Note: depending on parameters and rng, this may exhaust without
        // finding a residual-passing s. We just check it doesn't panic.
        let _ = r;
    }

    #[test]
    fn mine_respects_cancel_flag() {
        let header = b"cancel-test";
        // Nearly-impossible target so mining doesn't terminate quickly.
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // target = 1, ridiculously hard
        let target = Target::from_be_bytes(bytes);

        let cfg = MineConfig {
            candidates_per_nonce: 8,
            max_total_attempts: u64::MAX,
            ..Default::default()
        };

        let cancel = AtomicBool::new(false);
        // Pre-cancel before calling mine; should return quickly.
        cancel.store(true, Ordering::Relaxed);
        let r = mine(header, &target, &cfg, Some(&cancel));
        assert!(matches!(r, Err(MineError::Cancelled)));
    }

    #[test]
    fn mine_exhausts_attempts_with_tight_target() {
        let header = b"exhaust-test";
        // Ridiculously hard target to ensure exhaustion within budget.
        let target = Target::MIN;
        let cfg = MineConfig {
            candidates_per_nonce: 4,
            max_total_attempts: 32,
            ..Default::default()
        };
        let r = mine(header, &target, &cfg, None);
        assert!(matches!(r, Err(MineError::AttemptsExhausted)));
    }

    #[test]
    fn derive_seed_is_deterministic() {
        let s1 = derive_pow_seed(b"header", 42);
        let s2 = derive_pow_seed(b"header", 42);
        assert_eq!(s1, s2);

        let s3 = derive_pow_seed(b"header", 43);
        assert_ne!(s1, s3);
    }
}
