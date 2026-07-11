// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Known-Answer Tests (KATs) for the PoW/SIS layer.
// ════════════════════════════════════════════════════════════════════════════
// This module is the PoW analogue of `bloch-crypto`'s `crypto::kat`: fixed-input
// regression vectors that pin the SHAKE-256 hashcash and the Module-SIS
// structural gate at the exact documented parameters so neither can silently
// drift. It is `#[cfg(test)]`-only and adds NO runtime surface.
//
// Coverage (roadmap §3.1/§3.2, §4):
//   (A) Documented-parameter pins — N, M, q, B, β, seed/aux lengths and every
//       hard-fork domain label are exact-value asserted.
//   (B) SHAKE-256 hashcash golden vectors — `derive_pow_seed` and
//       `compute_aux_hash` produce byte-stable output for pinned inputs; the
//       seed also cross-checks against a hand-built `shake256_dom` call.
//   (C) SIS residual-gate golden vectors — the centered residual norm for a
//       pinned (seed, s) is stable, and the k=4 prefix of the k=8 expansion is
//       bit-identical (the soft-fork subset invariant, at the expansion level).
//   (D) Accept/reject KATs — the gate accepts a deterministically mined
//       candidate and rejects the three malformed classes: wrong residual,
//       insufficient work, and out-of-range s.
//   (E) End-to-end mined regression vector — a fixed (header, target, cfg)
//       mines a byte-stable winning (nonce, aux-hash).
//
// HONESTY: these are REGRESSION vectors captured from the current code, not
// standards KATs — there is no external Bloch-SIS-PoW reference to differ
// against (the crate IS the reference). They guarantee "no silent drift," not
// "matches an independent spec." See the `#[ignore]` gap marker at the bottom.

use crate::difficulty::{hash_meets_target, Target};
use crate::encode::encode_s;
use crate::error::VerifyError;
use crate::expand::{expand_matrix_and_target_rows, expand_target_len};
use crate::field::infinity_norm;
use crate::matrix::residual_centered_rows;
use crate::params::{AUX_HASH_LEN, B, BETA, BETA_I64, M, N, POW_SEED_LEN, Q};
use crate::shake::shake256_dom;
use crate::solver::{derive_pow_seed, mine, MineConfig};
use crate::verify::{compute_aux_hash, verify, verify_regime};
use crate::{
    CANONICAL_RESIDUAL_COEFFS, DOMAIN_LABEL_POW_AUX, DOMAIN_LABEL_POW_SEED,
    DOMAIN_LABEL_TARGET, TESTNET_RESIDUAL_COEFFS,
};

// ── Fixed KAT inputs ─────────────────────────────────────────────────────────
const KAT_HEADER: &[u8] = b"BLOCH-SIS-POW-KAT-HEADER-V1";
const KAT_NONCE: u64 = 0x0123_4567_89AB_CDEF;

/// A fixed, in-range patterned solution vector (coeffs cycle -2..=2).
fn kat_pattern_s() -> [i32; N] {
    let mut s = [0i32; N];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = (i as i32 % 5) - 2;
    }
    s
}

// ── Golden values (captured from the current code — see dump_goldens) ─────────
const GOLDEN_POW_SEED_HEX: &str =
    "38c9c357031746c073f3dfbd0d932c7d190d00b787a43fe00bd4190cfeafd4df\
     0d276b9340197848b0f15ba1c88081137413678667e79d5e28dba8e5bad2601f";
const GOLDEN_AUX_ZERO_S_HEX: &str =
    "f1f16282a24cc4337315f1ef42c4c801681b2d69385854bc7e228a666c48b00b";
const GOLDEN_AUX_PATTERN_S_HEX: &str =
    "b2fbfb8fc97fdade4f64e6e1157f387933690dead85b148a2a87d609bb325abb";
const GOLDEN_RESIDUAL_ZERO_S_K8: u32 = 4_023_573;
const GOLDEN_RESIDUAL_PATTERN_S_K8: u32 = 4_076_281;
// End-to-end mined regression vector (KAT_MINE_HEADER, Target::MAX, cfg below).
const KAT_MINE_HEADER: &[u8] = b"BLOCH-SIS-POW-KAT-MINE-V1";
const GOLDEN_MINE_NONCE: u64 = 5;
const GOLDEN_MINE_AUX_HEX: &str =
    "c10f84bff3a06705be456d658a1eee7290cb7ed04492683884fc70b664936d9a";

fn kat_mine_cfg() -> MineConfig {
    MineConfig {
        start_nonce: 0,
        candidates_per_nonce: 4096,
        max_total_attempts: 1_000_000,
        residual_coeffs: TESTNET_RESIDUAL_COEFFS,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// (A) Documented-parameter pins.
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn documented_params_are_pinned() {
    // The exact params quoted in the crate header / roadmap §1.3. A silent edit
    // to any of these is a hard fork and must break this test.
    assert_eq!(N, 256, "solution dimension N");
    assert_eq!(M, 512, "matrix rows M");
    assert_eq!(M, 2 * N, "m = 2n");
    assert_eq!(Q, 8_380_417, "modulus q = 2^23 - 2^13 + 1 (ML-DSA-65)");
    assert_eq!(Q, (1u32 << 23) - (1u32 << 13) + 1);
    assert_eq!(B, 2, "infinity-norm bound B");
    assert_eq!(BETA, Q / 16, "beta = q/16");
    assert_eq!(BETA, 523_776, "beta absolute value");
    assert_eq!(POW_SEED_LEN, 64, "pow seed length");
    assert_eq!(AUX_HASH_LEN, 32, "aux hash length");
    assert_eq!(TESTNET_RESIDUAL_COEFFS, 4, "testnet k");
    assert_eq!(CANONICAL_RESIDUAL_COEFFS, 8, "canonical k");
}

#[test]
fn domain_labels_are_pinned() {
    // Changing any of these constants is a hard fork; pin the exact bytes so a
    // typo/rename cannot ship silently (roadmap §1.3 domain-separation notes).
    assert_eq!(DOMAIN_LABEL_POW_SEED, b"BLOCH-POW-SEED-V1");
    assert_eq!(DOMAIN_LABEL_POW_AUX, b"BLOCH-POW-AUX-V1");
    assert_eq!(DOMAIN_LABEL_TARGET, b"BLOCH-POW-TARGET-V1");
}

// ═════════════════════════════════════════════════════════════════════════════
// (B) SHAKE-256 hashcash golden vectors.
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn pow_seed_derivation_is_byte_stable() {
    let seed = derive_pow_seed(KAT_HEADER, KAT_NONCE);
    assert_eq!(seed.len(), POW_SEED_LEN);
    assert_eq!(
        hex::encode(&seed),
        GOLDEN_POW_SEED_HEX,
        "derive_pow_seed drifted from the golden vector (hard-fork-visible change)"
    );
    // Cross-check: the seed is exactly the domain-separated SHAKE over
    // (header, nonce_le) under the POW-SEED label — no hidden transformation.
    let manual = shake256_dom(
        DOMAIN_LABEL_POW_SEED,
        &[KAT_HEADER, &KAT_NONCE.to_le_bytes()],
        POW_SEED_LEN,
    );
    assert_eq!(seed, manual, "derive_pow_seed must equal the raw shake256_dom call");
}

#[test]
fn aux_hash_golden_vectors_are_byte_stable() {
    let zero_s = [0i32; N];
    assert_eq!(
        hex::encode(compute_aux_hash(KAT_HEADER, KAT_NONCE, &zero_s)),
        GOLDEN_AUX_ZERO_S_HEX,
        "aux hash for zero s drifted"
    );
    assert_eq!(
        hex::encode(compute_aux_hash(KAT_HEADER, KAT_NONCE, &kat_pattern_s())),
        GOLDEN_AUX_PATTERN_S_HEX,
        "aux hash for patterned s drifted"
    );
    // The aux hash binds encode(s) ‖ nonce ‖ header under the AUX label; a
    // different nonce must move it (domain-separated, nonce-committed).
    assert_ne!(
        compute_aux_hash(KAT_HEADER, KAT_NONCE, &zero_s),
        compute_aux_hash(KAT_HEADER, KAT_NONCE.wrapping_add(1), &zero_s),
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// (C) SIS residual-gate golden vectors + prefix-subset invariant.
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn residual_norm_golden_vectors_are_stable() {
    let seed = derive_pow_seed(KAT_HEADER, KAT_NONCE);
    let (a8, t8) = expand_matrix_and_target_rows(&seed, CANONICAL_RESIDUAL_COEFFS);

    // Zero s ⇒ residual = A·0 - t = -t; its centered infinity-norm is pinned and
    // (with overwhelming probability, ≈ q/2) far above β, so zero s is rejected.
    let r_zero = residual_centered_rows(&a8, &[0i32; N], &t8, CANONICAL_RESIDUAL_COEFFS);
    let norm_zero = infinity_norm(&r_zero);
    assert_eq!(norm_zero, GOLDEN_RESIDUAL_ZERO_S_K8, "residual norm for zero s drifted");
    assert!(norm_zero as i64 >= BETA_I64, "zero s must exceed the residual bound");

    let r_pat = residual_centered_rows(&a8, &kat_pattern_s(), &t8, CANONICAL_RESIDUAL_COEFFS);
    assert_eq!(
        infinity_norm(&r_pat),
        GOLDEN_RESIDUAL_PATTERN_S_K8,
        "residual norm for patterned s drifted"
    );
}

#[test]
fn k4_expansion_is_a_prefix_of_k8_expansion() {
    // The soft-fork subset property (SF-1) at the expansion level: expanding the
    // first 4 rows yields bytes identical to the first 4 rows of the 8-row
    // expansion. This is *why* a k=8-valid solution is automatically k=4-valid.
    let seed = derive_pow_seed(KAT_HEADER, KAT_NONCE);
    let (a4, t4) = expand_matrix_and_target_rows(&seed, TESTNET_RESIDUAL_COEFFS);
    let (a8, t8) = expand_matrix_and_target_rows(&seed, CANONICAL_RESIDUAL_COEFFS);

    assert_eq!(a4.len(), TESTNET_RESIDUAL_COEFFS * N);
    assert_eq!(a8.len(), CANONICAL_RESIDUAL_COEFFS * N);
    assert_eq!(&a8[..TESTNET_RESIDUAL_COEFFS * N], &a4[..], "A rows are not prefix-consistent");
    assert_eq!(&t8[..TESTNET_RESIDUAL_COEFFS], &t4[..], "t is not prefix-consistent");
    // And the standalone target expander agrees on the prefix.
    let t_full = expand_target_len(&seed, CANONICAL_RESIDUAL_COEFFS);
    assert_eq!(t_full, t8, "expand_target_len disagrees with expand_matrix_and_target_rows");
}

// ═════════════════════════════════════════════════════════════════════════════
// (D) Accept / reject KATs at the documented params.
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn gate_accepts_known_valid_candidate() {
    // Deterministically mine a candidate in the (cheap, ~2^12) testnet k=4
    // regime at Target::MAX, then assert the verifier accepts it at the same
    // width — the positive end-to-end gate KAT.
    let r = mine(KAT_MINE_HEADER, &Target::MAX, &kat_mine_cfg(), None)
        .expect("k=4 testnet regime must be brute-force mineable within budget");
    verify_regime(KAT_MINE_HEADER, r.nonce, &r.solution, &Target::MAX, TESTNET_RESIDUAL_COEFFS)
        .expect("a freshly mined k=4 candidate must verify at k=4");
    // The reported aux hash matches an independent recomputation.
    assert_eq!(r.aux_hash, compute_aux_hash(KAT_MINE_HEADER, r.nonce, &r.solution));
    // Sanity: all coefficients are in range and the aux hash meets the target.
    assert!(r.solution.iter().all(|&c| c.abs() <= B));
    assert!(hash_meets_target(&r.aux_hash, &Target::MAX));
}

#[test]
fn gate_rejects_wrong_residual() {
    // Corrupt a valid candidate: flipping a coefficient perturbs A·s and (with
    // overwhelming probability) pushes the residual past β. Try coefficients
    // until one breaks it — statistically the first almost always does.
    let r = mine(KAT_MINE_HEADER, &Target::MAX, &kat_mine_cfg(), None)
        .expect("mine must succeed");
    let mut broke = false;
    for i in 0..N {
        let mut s = r.solution;
        s[i] = if s[i] == 0 { 1 } else { 0 };
        if let Err(VerifyError::ResidualTooLarge { actual, bound }) =
            verify_regime(KAT_MINE_HEADER, r.nonce, &s, &Target::MAX, TESTNET_RESIDUAL_COEFFS)
        {
            assert!(actual >= bound);
            broke = true;
            break;
        }
    }
    assert!(broke, "no single-coefficient corruption tripped ResidualTooLarge — suspicious");
}

#[test]
fn gate_rejects_insufficient_work() {
    // A residual-valid candidate whose aux hash does not meet an (impossible)
    // target must be rejected with AuxHashAboveTarget — the hashcash filter.
    let r = mine(KAT_MINE_HEADER, &Target::MAX, &kat_mine_cfg(), None)
        .expect("mine must succeed");
    let res = verify_regime(
        KAT_MINE_HEADER,
        r.nonce,
        &r.solution,
        &Target::MIN, // nothing can be < 0
        TESTNET_RESIDUAL_COEFFS,
    );
    assert!(
        matches!(res, Err(VerifyError::AuxHashAboveTarget)),
        "insufficient work must be AuxHashAboveTarget, got {res:?}"
    );
}

#[test]
fn gate_rejects_oversized_solution() {
    // Any coefficient beyond B must be rejected before the residual/aux checks.
    let mut s = [0i32; N];
    s[0] = 99;
    assert!(matches!(
        verify(KAT_HEADER, KAT_NONCE, &s, &Target::MAX),
        Err(VerifyError::SolutionTooLarge)
    ));
    // Full-M path rejects too (same norm gate).
    assert!(matches!(
        verify_regime(KAT_HEADER, KAT_NONCE, &s, &Target::MAX, M),
        Err(VerifyError::SolutionTooLarge)
    ));
    // Encoding rejects it as well (canonicality of s).
    assert!(encode_s(&s).is_err());
}

// ═════════════════════════════════════════════════════════════════════════════
// (E) End-to-end mined regression vector.
// ═════════════════════════════════════════════════════════════════════════════
#[test]
fn mined_solution_regression_vector_is_byte_stable() {
    // Fixed (header, target, cfg) ⇒ a byte-stable winning (nonce, aux-hash).
    // The solver is fully deterministic given these inputs; if any of CandRng,
    // sampling order, seed derivation, or the residual/aux math changes, this
    // pinned vector moves and the test flags it. Re-capture via dump_goldens.
    let r = mine(KAT_MINE_HEADER, &Target::MAX, &kat_mine_cfg(), None)
        .expect("mine must succeed");
    assert_eq!(r.nonce, GOLDEN_MINE_NONCE, "winning nonce drifted");
    assert_eq!(hex::encode(r.aux_hash), GOLDEN_MINE_AUX_HEX, "winning aux hash drifted");
    // And it verifies, closing the loop.
    verify_regime(KAT_MINE_HEADER, r.nonce, &r.solution, &Target::MAX, TESTNET_RESIDUAL_COEFFS)
        .expect("the pinned mined vector must verify");
}

// ── Golden-capture helper ─────────────────────────────────────────────────────
// Run with:
//   cargo test -p bloch-sis-pow kat::dump_goldens -- --ignored --nocapture
// then paste the printed constants above. Kept in-tree so the goldens are
// reproducible after any intentional (hard-fork) parameter change.
#[test]
#[ignore = "capture utility — prints the golden constants; run with --ignored --nocapture"]
fn dump_goldens() {
    let seed = derive_pow_seed(KAT_HEADER, KAT_NONCE);
    println!("GOLDEN_POW_SEED_HEX = \"{}\"", hex::encode(&seed));
    println!(
        "GOLDEN_AUX_ZERO_S_HEX = \"{}\"",
        hex::encode(compute_aux_hash(KAT_HEADER, KAT_NONCE, &[0i32; N]))
    );
    println!(
        "GOLDEN_AUX_PATTERN_S_HEX = \"{}\"",
        hex::encode(compute_aux_hash(KAT_HEADER, KAT_NONCE, &kat_pattern_s()))
    );
    let (a8, t8) = expand_matrix_and_target_rows(&seed, CANONICAL_RESIDUAL_COEFFS);
    let nz = infinity_norm(&residual_centered_rows(&a8, &[0i32; N], &t8, CANONICAL_RESIDUAL_COEFFS));
    let np = infinity_norm(&residual_centered_rows(&a8, &kat_pattern_s(), &t8, CANONICAL_RESIDUAL_COEFFS));
    println!("GOLDEN_RESIDUAL_ZERO_S_K8 = {nz}");
    println!("GOLDEN_RESIDUAL_PATTERN_S_K8 = {np}");
    let r = mine(KAT_MINE_HEADER, &Target::MAX, &kat_mine_cfg(), None).expect("mine");
    println!("GOLDEN_MINE_NONCE = {}", r.nonce);
    println!("GOLDEN_MINE_AUX_HEX = \"{}\"", hex::encode(r.aux_hash));
}

// ── Honest gap marker: standards-traceable / frozen-vector KAT ────────────────
#[test]
#[ignore = "regression vectors above pin the CURRENT code; a standards-traceable \
            Bloch-SIS-PoW KAT needs the frozen protocol spec + a second \
            implementation to differ against (roadmap P0.2/P0.3). Not sourceable \
            in-tree today — this crate IS the reference."]
fn frozen_spec_kat_todo() {
    // TODO(audit P0.3): once the protocol spec is frozen, vendor the published
    // Bloch-SIS-PoW test vectors and assert byte-equality here so the KATs
    // become spec-traceable rather than self-referential regression anchors.
}
