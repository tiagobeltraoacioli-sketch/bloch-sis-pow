// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Integration tests for Bloch-SIS-PoW.

//! Cross-module integration tests.

#[cfg(test)]
mod integration {
    use crate::expand::expand_matrix_and_target;
    use crate::solver::derive_pow_seed;

    #[test]
    fn seed_derivation_matches_between_miner_and_verifier() {
        let header = b"seed-roundtrip-test";
        let nonce = 42u64;
        let seed = derive_pow_seed(header, nonce);
        // Direct re-derivation in the verifier path produces the same
        // (A, t). We test only that subsequent calls match.
        let (a1, t1) = expand_matrix_and_target(&seed);
        let (a2, t2) = expand_matrix_and_target(&seed);
        assert_eq!(a1, a2);
        assert_eq!(t1, t2);
    }
}

/// Soft fork SF-1: canonical residual width k = 8 (height-activated at the
/// node layer). These tests pin the crate-level facts the fork relies on:
/// the prefix-subset property (k=8-valid ⟹ k=4-valid, NEVER the reverse)
/// and the S1 guardrail at k = 8.
#[cfg(test)]
mod soft_fork_sf1 {
    use crate::difficulty::Target;
    use crate::error::VerifyError;
    use crate::params::{BETA, M, Q};
    use crate::solver::{mine, MineConfig};
    use crate::verify::{verify, verify_regime};
    use crate::{
        residual_regime_nontrivial, CANONICAL_RESIDUAL_COEFFS, TESTNET_RESIDUAL_COEFFS,
    };

    /// Fixed header for the k=8 subset-property test.
    const K8_HEADER: &[u8] = b"bloch-sf1-k8-subset-property-test";

    /// Pre-searched start nonce whose FIRST 4096-candidate window contains a
    /// k=8-valid solution for `K8_HEADER` at `Target::MAX`. Mining at k = 8
    /// needs ~2^24 candidates in expectation (the gate's rejection floor), far
    /// too slow for a debug-mode unit test — but the solver is fully
    /// deterministic given (header, start_nonce), so we searched offline and
    /// pinned a lucky window. If solver internals (CandRng, sampling order,
    /// seeding) ever change, re-run `sf1_search_fast_k8_start_nonces`
    /// (`cargo test --release -p bloch-sis-pow -- --ignored --nocapture`)
    /// and update this constant.
    const K8_FAST_START_NONCE: u64 = 2175; // found at attempt 1864 of 4096

    fn k8_window_cfg(start_nonce: u64) -> MineConfig {
        MineConfig {
            start_nonce,
            candidates_per_nonce: 4096,
            max_total_attempts: 4096,
            residual_coeffs: CANONICAL_RESIDUAL_COEFFS,
        }
    }

    #[test]
    fn canonical_width_guardrails_hold() {
        // S1: k = 8 stays out of the trivial q-ary regime (8·(q/16)² = q²/32).
        assert!(residual_regime_nontrivial(CANONICAL_RESIDUAL_COEFFS, BETA, Q));
        // Soft-fork direction: canonical must tighten, not loosen.
        assert!(CANONICAL_RESIDUAL_COEFFS >= TESTNET_RESIDUAL_COEFFS);
        // Full-M remains trivial — k = 8 is NOT full-M.
        assert!(CANONICAL_RESIDUAL_COEFFS < M);
    }

    #[test]
    fn k8_solution_also_valid_at_k4_subset_property() {
        // Mine a real k=8 solution (pinned fast window; see the constant's
        // doc), then confirm the subset property end to end: valid at k = 8,
        // AUTOMATICALLY valid at k = 4, still rejected by full-M, and broken
        // by a tampered nonce.
        let target = Target::MAX;
        let r = mine(K8_HEADER, &target, &k8_window_cfg(K8_FAST_START_NONCE), None)
            .expect("pinned window must contain a k=8 solution — if solver \
                     internals changed, re-run sf1_search_fast_k8_start_nonces");

        // Valid at the canonical width.
        verify_regime(K8_HEADER, r.nonce, &r.solution, &target, CANONICAL_RESIDUAL_COEFFS)
            .expect("k=8-mined solution must verify at k=8");
        // Subset property: the first 4 residual coefficients are a prefix of
        // the first 8, so k=4 validity is automatic. This is what makes the
        // k: 4→8 activation a SOFT fork.
        verify_regime(K8_HEADER, r.nonce, &r.solution, &target, TESTNET_RESIDUAL_COEFFS)
            .expect("k=8-valid solution MUST also verify at k=4 (prefix subset)");
        // Regime separation vs full-M is still real.
        assert!(verify(K8_HEADER, r.nonce, &r.solution, &target).is_err());
        // Tampered nonce breaks it at the canonical width.
        assert!(verify_regime(
            K8_HEADER,
            r.nonce.wrapping_add(1),
            &r.solution,
            &target,
            CANONICAL_RESIDUAL_COEFFS
        )
        .is_err());
    }

    #[test]
    fn k4_solution_rejected_at_k8() {
        // The reverse of the subset property: a k=4 solution passes k=8 only
        // if residual coefficients 4..8 ALSO land under β — probability
        // ≈ 8^-4 = 1/4096 per solution. Mine k=4 solutions (cheap: ~2^12
        // candidates each) until one fails k=8; requiring more than 8 mines
        // has probability ≈ 4096^-8 (never), so the loop is deterministic in
        // practice.
        let target = Target::MAX;
        let header = b"bloch-sf1-k4-not-k8-test";
        let mut rejected = None;
        for i in 0..8u64 {
            let cfg = MineConfig {
                start_nonce: i * 1_000_003,
                candidates_per_nonce: 4096,
                max_total_attempts: 500_000,
                residual_coeffs: TESTNET_RESIDUAL_COEFFS,
            };
            let r = mine(header, &target, &cfg, None)
                .expect("k=4 testnet regime must be brute-force mineable");
            // Sanity: it verifies at the width it was mined for.
            verify_regime(header, r.nonce, &r.solution, &target, TESTNET_RESIDUAL_COEFFS)
                .expect("k=4-mined solution must verify at k=4");
            if verify_regime(header, r.nonce, &r.solution, &target, CANONICAL_RESIDUAL_COEFFS)
                .is_err()
            {
                rejected = Some(r);
                break;
            }
        }
        let r = rejected.expect(
            "8 consecutive k=4 solutions all passed k=8 (p ≈ 4096^-8) — \
             the k=8 gate is not actually checking coefficients 4..8",
        );
        // And the failure mode is the residual bound, not something else.
        match verify_regime(header, r.nonce, &r.solution, &target, CANONICAL_RESIDUAL_COEFFS) {
            Err(VerifyError::ResidualTooLarge { actual, bound }) => {
                assert!(actual >= bound);
            }
            other => panic!("expected ResidualTooLarge at k=8, got {other:?}"),
        }
    }

    /// Maintenance utility for the pinned fast-window constants (this module's
    /// `K8_FAST_START_NONCE` and the node-side k=8 test nonces). Scans start
    /// nonces whose first 4096-candidate window contains a k=8 solution and
    /// prints them. Run:
    ///
    /// ```text
    /// cargo test --release -p bloch-sis-pow -- --ignored --nocapture sf1_search
    /// ```
    #[test]
    #[ignore = "offline search utility — run in --release with --nocapture to (re)pin fast k=8 start nonces"]
    fn sf1_search_fast_k8_start_nonces() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        // (label, header, target) triples that need a pinned fast window.
        // The node-side entry mirrors src/pow tests: its miner derives the
        // target from compact bits, so search with the identical target.
        let max_bits_target = crate::bits_to_target(crate::target_to_bits(&Target::MAX));
        let searches: [(&str, &[u8], Target); 2] = [
            ("bloch-sis-pow::K8_FAST_START_NONCE", K8_HEADER, Target::MAX),
            (
                "src/pow tests K8_E2E_START_NONCE",
                b"bloch-sf1-k8-e2e-preimage",
                max_bits_target,
            ),
        ];

        for (label, header, target) in searches {
            let found = AtomicU64::new(u64::MAX);
            let stop = AtomicBool::new(false);
            let next = AtomicU64::new(0);
            std::thread::scope(|scope| {
                for _ in 0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) {
                    scope.spawn(|| loop {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let n = next.fetch_add(1, Ordering::Relaxed);
                        if mine(header, &target, &k8_window_cfg(n), None).is_ok() {
                            // Keep the smallest found start nonce for stability.
                            found.fetch_min(n, Ordering::Relaxed);
                            stop.store(true, Ordering::Relaxed);
                            return;
                        }
                    });
                }
            });
            let n = found.load(Ordering::Relaxed);
            assert_ne!(n, u64::MAX, "search aborted without a hit");
            let r = mine(header, &target, &k8_window_cfg(n), None)
                .expect("re-mining the found window must reproduce");
            println!(
                "SF-1 fast k=8 window [{label}]: start_nonce = {n} \
                 (nonce = {}, found at attempt {} of 4096)",
                r.nonce, r.attempts
            );
        }
    }
}
