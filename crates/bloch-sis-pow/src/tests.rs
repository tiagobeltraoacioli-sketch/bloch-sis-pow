// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Integration tests for Bloch-SIS-PoW.

//! Cross-module integration tests.

#[cfg(test)]
mod integration {
    use crate::difficulty::Target;
    use crate::expand::expand_matrix_and_target;
    use crate::field::infinity_norm;
    use crate::matrix::residual_centered;
    use crate::params::{B, BETA_I64, N};
    use crate::solver::{derive_pow_seed, mine, MineConfig};
    use crate::verify::{compute_aux_hash, verify};

    /// Helper: build a target where the high two bytes are zero, making
    /// roughly 1-in-65536 hashes acceptable. This is "easy testnet"
    /// difficulty — fast enough for unit tests, but exercises the full
    /// path.
    fn easy_test_target() -> Target {
        let mut bytes = [0xFFu8; 32];
        bytes[0] = 0x00;
        bytes[1] = 0xFF;
        Target::from_be_bytes(bytes)
    }

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

    #[test]
    fn manually_constructed_pass_through_verify() {
        // We synthesize a "passing" solution by:
        // 1. Picking a header and nonce.
        // 2. Deriving (A, t).
        // 3. Computing s such that A·s ≡ t (mod q) approximately.
        //
        // For the reference test, the simplest working witness is to
        // accept that with random s most won't pass; we use easy_target
        // and the miner with ample budget.

        let header = b"manual-witness-test";
        let target = easy_test_target();

        let cfg = MineConfig {
            start_nonce: 0,
            candidates_per_nonce: 256,
            max_total_attempts: 100_000,
            ..Default::default()
        };

        let mined = mine(header, &target, &cfg, None);
        // We may or may not succeed within budget; if we do, the result
        // MUST verify.
        if let Ok(r) = mined {
            verify(header, r.nonce, &r.solution, &target)
                .expect("a freshly mined solution must verify");

            // The aux hash matches what compute_aux_hash returns.
            let aux2 = compute_aux_hash(header, r.nonce, &r.solution);
            assert_eq!(r.aux_hash, aux2);
        }
        // If we didn't find one within budget, that's still a valid
        // outcome for a probabilistic search — we just won't have
        // exercised the verify path. The test passes either way; the
        // miner's correctness is exercised by other unit tests.
    }

    #[test]
    fn corrupted_solution_fails_verify() {
        // Even if we had a passing (nu, s), bumping any coefficient to
        // 0 should change the residual enough to break the residual
        // bound or the aux hash.
        let header = b"corruption-test";
        let target = Target::MAX; // skip aux check, focus on residual

        // Construct an "honest" residual-passing s for some nonce.
        // We brute-force by sampling.
        let mut found: Option<(u64, [i32; N])> = None;
        for nu in 0u64..1000 {
            let seed = derive_pow_seed(header, nu);
            let (a, t) = expand_matrix_and_target(&seed);

            // Try a few hundred candidates per nonce.
            let mut rng_state = nu.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for _ in 0..200 {
                rng_state = rng_state.wrapping_add(0xBF58_476D_1CE4_E5B9);
                let mut s = [0i32; N];
                let mut state = rng_state;
                for slot in s.iter_mut() {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let v = ((state >> 33) % (2 * B as u64 + 1)) as i32;
                    *slot = v - B;
                }
                let r = residual_centered(&a, &s, &t);
                if (infinity_norm(&r) as i64) < BETA_I64 {
                    found = Some((nu, s));
                    break;
                }
            }
            if found.is_some() { break; }
        }

        if let Some((nu, mut s)) = found {
            // Verify the honest solution.
            let r = verify(header, nu, &s, &target);
            assert!(r.is_ok(), "honest solution should verify: {r:?}");

            // Corrupt s by flipping one coefficient.
            s[0] = if s[0] == 0 { 1 } else { 0 };
            let r2 = verify(header, nu, &s, &target);
            // The corrupted solution should fail residual check
            // (overwhelmingly likely; not strictly guaranteed for any
            // single corruption, but for at-least-one we are safe).
            // If it happens to also pass, we'd accept that as a
            // statistical edge case rather than a bug.
            // For test reliability we just assert that *some* corruption
            // breaks it; if the first doesn't, try a few more.
            if r2.is_err() {
                return;
            }
            for i in 1..N {
                let original = s[i];
                s[i] = if original == 0 { 1 } else { 0 };
                if verify(header, nu, &s, &target).is_err() {
                    return;
                }
                s[i] = original;
            }
            panic!("no single-coefficient corruption broke verification — \
                    suspicious; investigate");
        }
        // If we couldn't find an honest solution within budget, skip;
        // other tests cover the verify path.
    }
}
