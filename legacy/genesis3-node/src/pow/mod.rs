//! Bloch-SIS Proof-of-Work adapter.
//!
//! This is the seam between Bloch's block layer and the `bloch-sis-pow`
//! reference crate (a SHAKE-256 hashcash PoW with a Module-SIS structural
//! gate — the identity of Bloch-SIS). Bloch-SIS was Genesis-3's consensus
//! PoW; Genesis-3 stopped at height 39,918 on 2026-08-13 and the live chain
//! is Genesis-4 proof of stake, so nothing here mines any more. This module is
//! retained because it is what an auditor replays the closed chain with.
//!
//! `Block::validate_pow` verifies the block's solution vector via
//! `verify_regime`, with the residual width `k` chosen by
//! [`canonical_residual_coeffs`]. That selector is DIFFICULTY-DRIVEN, not a
//! height jump: `k = 4` below `K_RULE_ACTIVATION_HEIGHT` at any difficulty,
//! then `k` rises 5 → 6 → 7 → 8 as the block's own ASERT `bits` cross the
//! `K_WORK_*` thresholds, and eases back if difficulty falls. The older
//! `CANONICAL_K_ACTIVATION_HEIGHT` (a flat k: 4 → 8 jump at height 40,320) was
//! RETIRED in 43ab5aa8; the constant still exists but no consensus path reads
//! it. SHA-256d is gone from the Mainnet/Testnet consensus — it returns
//! ONLY as the Genesis-2 devnet's chain-selected algorithm (see [`sha256d`]
//! and the pinned dispatcher [`mine_pow_parallel`], which route on
//! `bloch_crypto::core::pow_algorithm`, the same single mapping
//! `Block::validate_pow` dispatches on).
//!
//! ## Honest status
//! The reference crate is research-grade. Its full-`M` regime is **unmineable**
//! (no short `s` exists at these dimensions) and simultaneously insecure at
//! `β = q/16` (trivial q-ary regime) — the frontier research
//! (`docs/research/POW-CANONICAL-frontier.md`) proved lattice-hard mining is
//! structurally impossible for a trapdoorless PoW, so the PoW's security is
//! **hashcash cumulative work**, with the Module-SIS residual as a structural
//! gate. Bloch runs the relaxed testnet regime — **zero security by design** —
//! until the canonical gate params, the no-shortcut proof, the ePrint, and the
//! audit land. The k-ramp tightens the structural gate's rejection floor
//! (~8x per +1 to k, so ~2^12 at k = 4 up to ~2^24 at k = 8) but does NOT
//! change this security story: k is a structural/throughput filter, every
//! width in 4..=8 sits in the trivial q-ary regime at `β = q/16`, and the
//! security source remains hashcash cumulative work.
//! See `BLOCH_DEVELOPMENT_PLAN.md` §3 and `crates/bloch-sis-pow`.

pub use bloch_sis_pow::{bits_to_target, target_to_bits, Target, VerifyError};

// Genesis-2: SHA-256d miner over the 80-byte MiningHeader projection
// (chain-selectable PoW; the Module-SIS path below is unchanged and remains
// the Mainnet/Testnet consensus PoW).
pub mod sha256d;
pub use sha256d::{mine_sha256d, mine_sha256d_preimage};

use bloch_crypto::core::{node_chain_id, pow_algorithm, PowAlgorithm};

/// PoW solution-vector dimension (the witness a mined block carries).
/// Must equal the crate's Module-SIS dimension `N`.
pub const SOLUTION_LEN: usize = 256;
const _: () = assert!(SOLUTION_LEN == bloch_sis_pow::params::N);

/// Number of residual coefficients checked in the **relaxed testnet regime**
/// (re-exported from the crate). This small width makes brute-force mining
/// feasible but is **zero security**. (The full-`M`=512 width is NOT a secure
/// alternative — it is unmineable AND in the trivial q-ary regime at
/// `β = q/16`; the canonical gate width awaits the no-shortcut analysis,
/// `docs/research/POW-CANONICAL-frontier.md`.)
pub use bloch_sis_pow::TESTNET_RESIDUAL_COEFFS;

/// Candidate canonical residual width (k = 8), the post-activation gate of
/// soft fork SF-1 (re-exported from the crate — see its honesty docs: the
/// gate is structural, ~2^24 rejection floor; security stays the hashcash
/// target).
pub use bloch_sis_pow::CANONICAL_RESIDUAL_COEFFS;

/// The k-ramp's rule-activation height and its (height, bits) → k selector,
/// re-exported from `bloch_crypto::core` — the consensus module
/// `Block::validate_pow` lives in — so miner and validator provably share one
/// selector. Below [`K_RULE_ACTIVATION_HEIGHT`] k is 4 at every difficulty;
/// at or above it k rides the block's own `bits`.
///
/// The retired `CANONICAL_K_ACTIVATION_HEIGHT` is deliberately NOT re-exported
/// here: nothing in the validate/mine path reads it, and re-exporting it from
/// the PoW seam is what let three tests in this file keep treating it as the
/// live gate for six weeks after it stopped being one.
pub use bloch_crypto::core::{canonical_residual_coeffs, K_RULE_ACTIVATION_HEIGHT};

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
    // Height-switched ASERT re-anchor (CONSENSUS-CRITICAL). Below
    // ASERT_ANCHOR2_HEIGHT every node uses the genesis anchor the caller passed,
    // so all historical `expected_bits` replay byte-identically. At/above it the
    // schedule re-anchors to a fresh (height, timestamp, bits) reference: this
    // resets the ~62-day schedule debt the genesis anchor had accumulated (which,
    // with the ±4× cap, had pinned difficulty far below the real hashrate and let
    // block production run away) and — via the wide bound in `asert_next_bits`
    // for anchor_height > 0 — lets difficulty track hashrate freely from here.
    let (a_bits, a_ts, a_height) = if height >= bloch_crypto::core::ASERT_ANCHOR2_HEIGHT {
        (
            bloch_crypto::core::ASERT_ANCHOR2_BITS,
            bloch_crypto::core::ASERT_ANCHOR2_TIMESTAMP as i64,
            bloch_crypto::core::ASERT_ANCHOR2_HEIGHT,
        )
    } else {
        (anchor_bits, anchor_timestamp as i64, 0)
    };
    bloch_sis_pow::difficulty::asert_next_bits(
        a_bits,
        a_ts,
        a_height,
        parent_timestamp as i64,
        height,
    )
}

/// SHA-256d expected difficulty `bits` for the block at `height` — serves
/// BOTH SHA-256d chains (Genesis-2 devnet AND Genesis-3 mainnet; the name
/// keeps its historical `genesis2_` prefix).
///
/// SINGLE SOURCE OF TRUTH shared by `accept_block` (validation), the internal
/// solo miner, the stratum V1/V2 template builders, and the
/// `getblocktemplate` RPC so every producer serves EXACTLY the target the
/// validator enforces. Both chains run a Bitcoin-style windowed retarget:
/// `current_bits` (persisted in meta) holds the active target between
/// boundaries, recomputed every `GENESIS2_RETARGET_WINDOW` blocks from that
/// window's timespan. Genesis-3 shares the constants (`GENESIS3_BITS ==
/// GENESIS2_BITS`, `GENESIS3_RETARGET_WINDOW == GENESIS2_RETARGET_WINDOW` —
/// enforced by const asserts in core/mod.rs), so this one function is correct
/// for both; if G3 ever diverges, those asserts fire and this path must be
/// made chain-aware. It must NEVER be confused with the SIS ASERT path
/// anchored at `GENESIS_BITS` (0x2100ffff), which — on these chains — yields
/// a trivial diff-1 target that floods the DAG with same-height blocks.
pub fn genesis2_expected_bits(store: &crate::storage::Storage, height: u64) -> u32 {
    let cur = store.get_meta("current_bits").ok().flatten()
        .and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok())
        .map(u32::from_le_bytes)
        .unwrap_or(crate::core::GENESIS2_BITS);
    let window = crate::core::GENESIS2_RETARGET_WINDOW;
    if height >= window && height % window == 0 {
        let first = store.get_timestamp_at_height(height - window).ok().flatten();
        let last = store.get_timestamp_at_height(height - 1).ok().flatten();
        if let (Some(first), Some(last)) = (first, last) {
            return crate::core::retarget_bits_g2(cur, last.saturating_sub(first));
        }
    }
    cur
}

/// Testnet-regime verify: relaxed residual width (k = 4), height-blind.
/// **Zero security** — dev only. Consensus code must use the height-aware
/// [`verify_sis_pow`] instead (this is the pre-activation regime only).
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

/// Testnet-regime miner: brute-force search under the relaxed residual width
/// (k = 4), height-blind. Returns the found `(nonce, solution)` or `None`
/// within the attempt budget. **Zero security** — dev/testnet only. Consensus
/// mining must use the height-aware [`mine_sis_pow`] instead: a k=4-only
/// block is rejected by upgraded validators wherever the difficulty ramp has
/// lifted k above 4 (at or above [`K_RULE_ACTIVATION_HEIGHT`], once the
/// block's `bits` cross `K_WORK_5`).
pub fn mine_sis_pow_testnet(
    pow_preimage: &[u8],
    bits: u32,
    start_nonce: u64,
    max_attempts: u64,
) -> Option<(u64, [i32; SOLUTION_LEN])> {
    mine_sis_pow_regime(pow_preimage, bits, TESTNET_RESIDUAL_COEFFS, start_nonce, max_attempts)
}

/// Height- and difficulty-aware consensus verify. Verifies a Module-SIS PoW
/// witness at compact difficulty `bits` under the residual width selected by
/// `canonical_residual_coeffs(height, bits)` — the height and bits OF THE
/// BLOCK BEING VALIDATED (never the tip): k = 4 below
/// [`K_RULE_ACTIVATION_HEIGHT`], and at or above it k rises with the block's
/// own ASERT difficulty. Note that `bits` is therefore load-bearing twice
/// over: it is both the aux-hash target and an input to the gate width.
///
/// This mirrors `Block::validate_pow` exactly (both route k through
/// `bloch_crypto::core::canonical_residual_coeffs`).
///
/// `pow_preimage` is the block's canonical PoW header bytes: the crate derives
/// the seed as `SHAKE256(DOMAIN_SEED || pow_preimage || nonce)`, so the
/// preimage must commit to every consensus field **except** the nonce (which
/// the crate appends). The exact preimage bytes are fixed by B5b.
#[inline]
pub fn verify_sis_pow(
    pow_preimage: &[u8],
    nonce: u64,
    solution: &[i32; SOLUTION_LEN],
    bits: u32,
    height: u64,
) -> Result<(), VerifyError> {
    let target = bits_to_target(bits);
    bloch_sis_pow::verify_regime(
        pow_preimage,
        nonce,
        solution,
        &target,
        canonical_residual_coeffs(height, bits),
    )
}

/// Height-aware consensus miner (soft fork SF-1): brute-force search under
/// the residual width selected by `height` — the height of the block BEING
/// MINED (tip + 1 for a fresh template). Returns the found
/// `(nonce, solution)` or `None` within the attempt budget.
///
/// Cost honesty: at k = 8 the structural rejection floor is ~2^24, so a solve
/// needs on the order of 16M candidate vectors (vs ~2^12 at k = 4) even at
/// the easiest aux target.
pub fn mine_sis_pow(
    pow_preimage: &[u8],
    bits: u32,
    height: u64,
    start_nonce: u64,
    max_attempts: u64,
) -> Option<(u64, [i32; SOLUTION_LEN])> {
    mine_sis_pow_regime(
        pow_preimage,
        bits,
        canonical_residual_coeffs(height, bits),
        start_nonce,
        max_attempts,
    )
}

/// Shared miner body: brute-force search under an explicit residual width.
fn mine_sis_pow_regime(
    pow_preimage: &[u8],
    bits: u32,
    residual_coeffs: usize,
    start_nonce: u64,
    max_attempts: u64,
) -> Option<(u64, [i32; SOLUTION_LEN])> {
    use bloch_sis_pow::solver::{mine, MineConfig};
    let target = bits_to_target(bits);
    let cfg = MineConfig {
        start_nonce,
        candidates_per_nonce: 4096,
        max_total_attempts: max_attempts,
        residual_coeffs,
    };
    mine(pow_preimage, &target, &cfg, None)
        .ok()
        .map(|r| (r.nonce, r.solution))
}

/// Capacity: height-aware consensus miner that grinds across `num_threads`
/// CPU cores in parallel. Each worker searches a DISJOINT nonce range under
/// the *same* regime and target, so the returned `(nonce, solution)` is a
/// valid Bloch-SIS witness identical in kind to the single-threaded
/// [`mine_sis_pow`] — the first worker to find a solution wins, and
/// `verify_sis_pow` accepts it byte-for-byte the same way. This is a pure
/// scheduling/throughput change: no consensus, PoW-format, or verification
/// behavior is altered. `max_attempts` is the PER-WORKER attempt budget.
///
/// `num_threads <= 1` falls back to the single-threaded path so behavior is
/// unchanged on a single core.
pub fn mine_sis_pow_parallel(
    pow_preimage: &[u8],
    bits: u32,
    height: u64,
    start_nonce: u64,
    max_attempts: u64,
    num_threads: usize,
) -> Option<(u64, [i32; SOLUTION_LEN])> {
    if num_threads <= 1 {
        return mine_sis_pow(pow_preimage, bits, height, start_nonce, max_attempts);
    }
    use bloch_sis_pow::solver::{mine_parallel, MineConfig};
    let target = bits_to_target(bits);
    let cfg = MineConfig {
        start_nonce,
        candidates_per_nonce: 4096,
        max_total_attempts: max_attempts,
        residual_coeffs: canonical_residual_coeffs(height, bits),
    };
    mine_parallel(pow_preimage, &target, &cfg, num_threads)
        .ok()
        .map(|r| (r.nonce, r.solution))
}

/// Chain-dispatching parallel miner — the ONE entry point template builders
/// should call. Routes on `pow_algorithm(node_chain_id())`, the same single
/// mapping `Block::validate_pow` dispatches on, so what this returns is by
/// construction what the local validator accepts:
///
/// * `ModuleSis` (Mainnet/Testnet): [`mine_sis_pow_parallel`] — returns
///   `(nonce, witness)` with `witness.len() == 256` (`SOLUTION_LEN`), to be
///   stored in `Block.pow_solution`.
/// * `Sha256d` (Genesis2Devnet): [`mine_sha256d_preimage`] — returns
///   `(nonce, Vec::new())`: `Block.pow_solution` MUST stay empty on a
///   SHA-256d chain (validate_pow rejects any witness there). The nonce's
///   upper 32 bits are zero; `None` at 32-bit nonce exhaustion means the
///   caller must rebuild the template with a fresh timestamp (see
///   `sha256d` module docs).
///
/// `preimage` is `BlockHeader::pow_preimage()` (the 76-byte nonce-less
/// mining-header prefix) for BOTH arms; `max_attempts` is the per-worker
/// budget for both arms.
pub fn mine_pow_parallel(
    preimage: &[u8],
    bits: u32,
    height: u64,
    start_nonce: u64,
    max_attempts: u64,
    threads: usize,
) -> Option<(u64, Vec<i32>)> {
    match pow_algorithm(node_chain_id()) {
        PowAlgorithm::ModuleSis => {
            mine_sis_pow_parallel(preimage, bits, height, start_nonce, max_attempts, threads)
                .map(|(nonce, solution)| (nonce, solution.to_vec()))
        }
        PowAlgorithm::Sha256d => {
            // Per-chain endianness rule (single source of truth:
            // core::sha256d_le_fork_height_for — Genesis-2 flag-day at
            // SHA256D_LE_FORK_HEIGHT, Genesis-3 little-endian from height 0):
            // grind for exactly the comparison the validator will apply.
            let little_endian =
                height >= bloch_crypto::core::sha256d_le_fork_height_for(node_chain_id());
            mine_sha256d_preimage(preimage, bits, start_nonce, max_attempts, threads, little_endian)
                .map(|nonce| (nonce, Vec::new()))
        }
    }
}

/// Verify a Module-SIS PoW witness at the full-`M` residual width.
///
/// NOT a consensus path and NOT a secure mode: at `β = q/16`, full-`M` is in
/// the trivial q-ary regime (`√M·β ≥ q` — no lattice hardness) AND is
/// infeasible to honestly mine (see the bloch-sis-pow crate header). Retained
/// for wire-format compatibility and regime-separation testing only; the
/// consensus verify is the height-aware [`verify_sis_pow`].
#[inline]
pub fn verify_sis_pow_full_m(
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
        let err = verify_sis_pow_full_m(preimage, 0, &s, 0x207f_ffff).unwrap_err();
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
        assert!(verify_sis_pow_full_m(preimage, nonce, &s, bits).is_err());
        // Tampering the nonce breaks it even under the testnet regime.
        assert!(verify_sis_pow_testnet(preimage, nonce.wrapping_add(1), &s, bits).is_err());
    }

    #[test]
    fn next_bits_reanchors_at_asert_anchor2_height() {
        use bloch_crypto::core::{
            ASERT_ANCHOR2_HEIGHT, ASERT_ANCHOR2_TIMESTAMP, ASERT_ANCHOR2_BITS,
        };
        // At/above ASERT_ANCHOR2_HEIGHT the re-anchor governs and the passed
        // (genesis) anchor is ignored — two very different passed anchors yield
        // identical bits.
        let a = next_bits(0x2100ffff, 1_000, ASERT_ANCHOR2_TIMESTAMP, ASERT_ANCHOR2_HEIGHT);
        let b = next_bits(0x1c3a0000, 9_999, ASERT_ANCHOR2_TIMESTAMP, ASERT_ANCHOR2_HEIGHT);
        assert_eq!(a, b, "at ANCHOR2 the passed anchor must be ignored (re-anchored)");
        // On-schedule at the anchor (parent stamped at the anchor ts) → the
        // schedule deviation is zero, so the target is the anchor target and
        // bits round-trip to ASERT_ANCHOR2_BITS.
        assert_eq!(
            a, target_to_bits(&bits_to_target(ASERT_ANCHOR2_BITS)),
            "on-schedule at ANCHOR2 must reproduce ANCHOR2 bits"
        );
        // One block below, the switch is inactive: the passed genesis anchor
        // still governs, so the result is NOT the re-anchored bits.
        let below = next_bits(0x2100ffff, 1_000, ASERT_ANCHOR2_TIMESTAMP, ASERT_ANCHOR2_HEIGHT - 1);
        assert_ne!(below, a, "below ANCHOR2 must not use the re-anchor");
    }

    /// Soft fork SF-1: fixed preimage for the k=8 witness e2e test.
    const K8_E2E_PREIMAGE: &[u8] = b"bloch-sf1-k8-e2e-preimage";

    /// Pre-searched start nonce whose FIRST 4096-candidate window contains a
    /// k=8-valid solution for `K8_E2E_PREIMAGE` at the easiest compact-bits
    /// target. A cold k=8 mine needs ~2^24 candidates (the gate's rejection
    /// floor) — too slow for a debug unit test — but the solver is
    /// deterministic given (preimage, start_nonce), so the window was searched
    /// offline. If solver internals change, re-run the crate's search utility
    /// (`cargo test --release -p bloch-sis-pow -- --ignored --nocapture
    /// sf1_search`) and update this constant from the
    /// "src/pow tests K8_E2E_START_NONCE" line.
    const K8_E2E_START_NONCE: u64 = 4058; // found at attempt 2662 of 4096

    /// Compact difficulty that lands in the ramp's **k = 5** band, chosen so a
    /// unit test can actually exercise a k > 4 gate.
    ///
    /// Since the k-jump was retired for the difficulty-driven ramp
    /// (`canonical_residual_coeffs`), **no height alone can lift k** — k is a
    /// function of the block's own `bits`. A test that wants k > 4 must
    /// therefore supply bits the ramp reacts to, and those same bits are the
    /// aux-hash target the witness has to meet, so the two costs are coupled:
    ///
    /// | band | needs work ≥ | aux-hash pass rate | k=4 residual | joint     |
    /// |------|--------------|--------------------|--------------|-----------|
    /// | k=5  | 32           | ~1/63              | ~1/4096      | ~1/2^18   |
    /// | k=8  | 16_384       | ~1/16_384          | ~1/16.7M     | ~1/2^38   |
    ///
    /// k = 5 is the only band a debug-build brute force can reach. `0x20040000`
    /// decodes to a target of `04 00 …` → work 63, comfortably clear of
    /// `K_WORK_5` (32) without paying for a harder aux target than the test
    /// needs. The k > 4 precondition is asserted explicitly below, so retuning
    /// the `K_WORK_*` knobs fails loudly on the fixture rather than silently
    /// turning the gate test into a tautology.
    const RAMP_K5_BITS: u32 = 0x2004_0000;

    #[test]
    fn canonical_residual_coeffs_difficulty_driven_via_reexport() {
        // Pins the re-export the mining/verify seam uses. The selector (same fn
        // Block::validate_pow calls) is difficulty-driven: k=4 below the rule
        // activation at ANY bits; at/above it, k rides the block's ASERT
        // difficulty — low difficulty stays k=4, a hard target reaches k=8.
        let a = K_RULE_ACTIVATION_HEIGHT;
        assert_eq!(canonical_residual_coeffs(0, 0x0500ffff), TESTNET_RESIDUAL_COEFFS);
        assert_eq!(canonical_residual_coeffs(a - 1, 0x0500ffff), TESTNET_RESIDUAL_COEFFS);
        assert_eq!(canonical_residual_coeffs(a, 0x203fffc0), TESTNET_RESIDUAL_COEFFS);
        assert_eq!(canonical_residual_coeffs(a, 0x0500ffff), CANONICAL_RESIDUAL_COEFFS);
        assert_eq!(TESTNET_RESIDUAL_COEFFS, 4);
        assert_eq!(CANONICAL_RESIDUAL_COEFFS, 8);
    }

    #[test]
    fn k8_witness_verifies_under_every_k_the_ramp_selects() {
        // The soft-fork no-partition property, at the node seam: a witness
        // mined at the FULL canonical width (k = 8) also satisfies every
        // narrower gate, because the k = 4 residual check is a byte-prefix of
        // the k = 8 one. An un-upgraded peer therefore never rejects a block an
        // upgraded miner produced.
        //
        // WHAT THIS TEST CANNOT DO, and why it no longer claims to. Until the
        // k-ramp landed, k = 8 was selected by HEIGHT, so a test could mine at
        // k = 8 against the easiest possible aux target and then verify "at the
        // k=8 height". Under the difficulty-driven ramp k = 8 is reachable only
        // at work ≥ K_WORK_8 (16_384) — an aux target of ~1/16_384 on top of a
        // ~1/8^8 residual, i.e. ~2^38 expected candidates. That is not mineable
        // in a unit test at any height, so no test can mine a witness *at* the
        // difficulty where the ramp asks for k = 8. The subset direction below
        // is the part that is both testable and the part no-partition needs.
        let bits = target_to_bits(&Target::MAX);

        // Mine at the canonical width EXPLICITLY, through the regime miner.
        // Going through the height-aware `mine_sis_pow` would let the selector
        // choose k from (height, bits) — which, at the easiest target, is k = 4.
        // This test used to do exactly that: it asked for a "k=8 roundtrip" at
        // CANONICAL_K_ACTIVATION_HEIGHT, silently mined and verified at k = 4,
        // and passed without ever touching k = 8.
        let (nonce, s) = mine_sis_pow_regime(
            K8_E2E_PREIMAGE,
            bits,
            CANONICAL_RESIDUAL_COEFFS,
            K8_E2E_START_NONCE,
            4096,
        )
        .expect("pinned window must contain a k=8 solution — if solver \
                 internals changed, re-run the sf1_search utility");

        // The witness really is k=8-valid. This assertion is what keeps the
        // test honest: without it, a solver change that quietly narrowed the
        // mined width would leave every assertion below still passing.
        assert!(
            bloch_sis_pow::verify_regime(
                K8_E2E_PREIMAGE, nonce, &s, &bits_to_target(bits), CANONICAL_RESIDUAL_COEFFS,
            )
            .is_ok(),
            "pinned witness is not k=8-valid — the pinned start nonce is stale",
        );

        // ...and it therefore satisfies the narrower gate the ramp selects at
        // every position on the ramp.
        for h in [
            0u64,
            K_RULE_ACTIVATION_HEIGHT - 1,
            K_RULE_ACTIVATION_HEIGHT,
            K_RULE_ACTIVATION_HEIGHT + 1,
        ] {
            assert!(
                verify_sis_pow(K8_E2E_PREIMAGE, nonce, &s, bits, h).is_ok(),
                "k=8 witness must verify at height {h} (prefix-subset property)",
            );
        }
        assert!(verify_sis_pow_testnet(K8_E2E_PREIMAGE, nonce, &s, bits).is_ok());
        // Tampering the nonce breaks it wherever the ramp sits.
        assert!(verify_sis_pow(
            K8_E2E_PREIMAGE, nonce.wrapping_add(1), &s, bits, K_RULE_ACTIVATION_HEIGHT,
        )
        .is_err());
    }

    #[test]
    fn k4_mined_witness_rejected_where_the_ramp_lifts_k() {
        // At the node seam: a k=4-only witness must be rejected by the
        // height-aware verify wherever the difficulty ramp has lifted k above
        // 4, and must stay valid below the rule activation (where k = 4 for
        // every difficulty) — the soft fork tightens without invalidating
        // history.
        //
        // This test previously pinned `h = CANONICAL_K_ACTIVATION_HEIGHT` and
        // the easiest possible target, on the retired assumption that height
        // alone selects k = 8. Under the ramp those parameters select k = 4 on
        // both sides of the comparison, so every k=4 witness was accepted and
        // the loop fell through to a message ("gate broken") that named the one
        // thing that was NOT wrong.
        let preimage = b"bloch-sf1-k4-rejected-on-ramp";
        let bits = RAMP_K5_BITS;
        let h = K_RULE_ACTIVATION_HEIGHT;

        // Precondition, asserted before anything is mined: this test is only
        // meaningful if the ramp really selects k > 4 for these (height, bits).
        // If the K_WORK_* calibration moves, THIS is the assertion that should
        // fail — not the "gate broken" one at the bottom, which would be a lie.
        // Two distinguishable failures, deliberately: if the SELECTOR stops
        // lifting k, this precondition fires; if the ENFORCEMENT stops applying
        // the k it selected, the "gate broken" expect at the bottom fires. The
        // old test could only ever produce the second message, which is why it
        // spent six weeks reporting a broken gate that was not broken.
        let k_above = canonical_residual_coeffs(h, bits);
        assert!(
            k_above > TESTNET_RESIDUAL_COEFFS,
            "cannot exercise a k>4 gate: canonical_residual_coeffs({h}, {bits:#010x}) \
             returned k={k_above}. Either the K_WORK_* thresholds moved (re-pick \
             RAMP_K5_BITS to sit above K_WORK_5) or the ramp stopped rising with \
             difficulty (a consensus regression — do NOT just retune the fixture)",
        );
        assert_eq!(
            canonical_residual_coeffs(h - 1, bits),
            TESTNET_RESIDUAL_COEFFS,
            "below the rule activation k must be 4 at any difficulty",
        );

        // A k=4 witness passes the k=5 gate with probability ~1/8, so mine
        // until one fails it (16 consecutive passes has probability 8^-16).
        //
        // COST, measured on an idle 2-core box in a debug build: ~4.9 s when
        // the gate works (the first or second window fails k=5, as expected),
        // but ~64 s when it does NOT, because all 16 windows are mined before
        // the loop gives up. If this test ever appears to hang in CI rather
        // than to fail, that IS the failure — read it as a broken gate, and
        // give it a minute before killing the job.
        let mut rejected = None;
        for i in 0..16u64 {
            let (nonce, s) = mine_sis_pow_testnet(preimage, bits, i * 1_000_003, 8_000_000)
                .expect("k=4 testnet regime must be brute-force mineable");
            // Below activation the height-aware verify agrees with the testnet
            // verify: the witness is valid there.
            assert!(verify_sis_pow(preimage, nonce, &s, bits, h - 1).is_ok());
            assert!(verify_sis_pow(preimage, nonce, &s, bits, 0).is_ok());
            if verify_sis_pow(preimage, nonce, &s, bits, h).is_err() {
                rejected = Some((nonce, s));
                break;
            }
        }
        let (nonce, s) = rejected.expect(
            "16 consecutive k=4 witnesses all passed the ramp's k>4 gate — gate broken",
        );
        // Rejected at and above the activation, and for the RESIDUAL reason —
        // not because the aux hash happened to miss.
        assert!(matches!(
            verify_sis_pow(preimage, nonce, &s, bits, h).unwrap_err(),
            VerifyError::ResidualTooLarge { .. }
        ));
        assert!(matches!(
            verify_sis_pow(preimage, nonce, &s, bits, h + 1).unwrap_err(),
            VerifyError::ResidualTooLarge { .. }
        ));
    }

    #[test]
    fn height_aware_miner_below_activation_matches_testnet_regime() {
        // Below the rule activation the height-aware miner IS the testnet
        // regime: cheap to mine, and its output verifies under both the testnet
        // and the height-aware verify at pre-activation heights.
        let preimage = b"bloch-sf1-below-h-equivalence";
        let bits = target_to_bits(&Target::MAX);

        let (nonce, s) = mine_sis_pow(preimage, bits, 0, 0, 20_000_000)
            .expect("below the rule activation the height-aware miner must be k=4-cheap");
        assert!(verify_sis_pow(preimage, nonce, &s, bits, 0).is_ok());
        assert!(verify_sis_pow(preimage, nonce, &s, bits, K_RULE_ACTIVATION_HEIGHT - 1).is_ok());
        assert!(verify_sis_pow_testnet(preimage, nonce, &s, bits).is_ok());
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

/// Why the ancestry-incomplete cases below are ERRORS and not fallbacks.
///
/// The first version of the ancestry rule returned `Option<u32>` and both
/// callers did `unwrap_or_else(|| genesis2_expected_bits(...))` — a SILENT
/// fall-back to the legacy order-dependent value. That means one node can be
/// on the new rule while its peer is on the old one with no signal anywhere,
/// which is a consensus split by construction. It also silently DROPPED any
/// parent missing from the DAG (`filter_map`), so a node with a partial view
/// computed argmax over a SUBSET and confidently derived bits from the WRONG
/// selected parent. Fail-closed is deliberate: a loud reject/refusal on the
/// one node whose view is incomplete beats a quiet chain-wide fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedBitsError {
    /// Empty parents slice — only genesis has no parents and genesis is never
    /// validated through this path.
    NoParents,
    /// A listed parent has no GhostDAG data on this node. Selecting the parent
    /// from the remaining ones would silently pick the wrong selected parent,
    /// so this is an error, not a filter.
    ParentDataMissing(crate::consensus::BlockHash),
    /// The selected parent's block body (which carries its header bits) is not
    /// in local storage.
    SelectedParentBlockMissing(crate::consensus::BlockHash),
    /// The selected-parent walk could not reach `height - window` (pruned or
    /// mid-IBD ancestry, or the claimed height is inconsistent with the
    /// parents' heights).
    AncestryIncomplete { want: u64, reached: u64 },
}

impl std::fmt::Display for ExpectedBitsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoParents => write!(f, "no parents supplied"),
            Self::ParentDataMissing(h) =>
                write!(f, "parent {} has no DAG data on this node", hex::encode(&h[..8])),
            Self::SelectedParentBlockMissing(h) =>
                write!(f, "selected parent {} body not in local storage", hex::encode(&h[..8])),
            Self::AncestryIncomplete { want, reached } =>
                write!(f, "selected-parent walk stopped at h={} before reaching h={}", reached, want),
        }
    }
}

/// SHA-256d expected `bits` for a block at `height` carrying exactly
/// `parents` — the SINGLE choke point for every producer AND the validator.
///
/// ## Flag-day semantics
///
/// * `height <  DIFFICULTY_ANCESTRY_FORK_HEIGHT` — the legacy value
///   ([`genesis2_expected_bits`]: `current_bits` meta + height-keyed
///   timestamps), kept verbatim so settled history stays valid.
/// * `height >= DIFFICULTY_ANCESTRY_FORK_HEIGHT` — a PURE FUNCTION of the
///   block's own parent set and its selected-parent ancestry. No local
///   mutable state, no silent fallback: if the ancestry cannot be read the
///   caller gets an error and must fail closed (refuse to produce a template /
///   reject the block with an explicit reason).
///
/// ## Why the legacy split-brain existed (incident 2026-08-09, h=28080)
///
/// The legacy path derives bits from `current_bits` (rewritten on EVERY
/// accepted block) and `CF_TIMESTAMPS` (keyed by height alone — last-write-wins
/// when a height has siblings). At the h=28080 boundary with TWO tips at
/// 28079 the producer's own template flipped 0x1a0abb83 → 0x1a0abee4 the
/// moment the second 28079 block landed (journal, 04:42:23 vs 04:43:09),
/// while the ancestry rule — active in the validator via the flag-day, but
/// NOT in the stratum template builder — expected 0x1a0ac909 over the same
/// two-tip parent set. Every ASIC block was self-rejected and the chain sat
/// still. The fix is not "make the fallbacks agree": it is that everyone who
/// stamps or checks bits calls THIS function with THE SAME parents slice the
/// block header carries.
///
/// The producer MUST pass the exact slice it will stamp into
/// `header.parents`; the validator passes `block.header.parents`. Because the
/// result is a pure function of that slice, WHEN each side reads the tip set
/// no longer matters — a template built on a now-stale tip set still carries
/// bits consistent with its own parents, which is all the validator checks.
pub fn genesis2_expected_bits_for_parents(
    store: &crate::storage::Storage,
    dag: &crate::consensus::GhostDAG,
    parents: &[crate::consensus::BlockHash],
    height: u64,
) -> Result<u32, ExpectedBitsError> {
    genesis2_expected_bits_for_parents_gated(
        store, dag, parents, height,
        crate::core::DIFFICULTY_ANCESTRY_FORK_HEIGHT,
    )
}

/// Test seam for [`genesis2_expected_bits_for_parents`]: identical logic with
/// an explicit flag-day height, so the lab (tests/difficulty_ancestry_
/// boundary_lab.rs) can exercise the ancestry rule on a short chain without
/// building 30k blocks. Production code must call the un-suffixed wrapper.
pub fn genesis2_expected_bits_for_parents_gated(
    store: &crate::storage::Storage,
    dag: &crate::consensus::GhostDAG,
    parents: &[crate::consensus::BlockHash],
    height: u64,
    fork_height: u64,
) -> Result<u32, ExpectedBitsError> {
    if height < fork_height {
        return Ok(genesis2_expected_bits(store, height));
    }

    if parents.is_empty() {
        return Err(ExpectedBitsError::NoParents);
    }

    // Selected parent — EXACT mirror of `GhostDAG::select_parent`
    // (consensus/mod.rs): argmax over (blue_work, blue_score, hash). The
    // previous version compared (blue_work, hash) only, which can disagree
    // with GhostDAG when blue_work ties but blue_score does not — the walk
    // below follows GhostDAG's own `selected_parent` links, so the entry
    // point must use GhostDAG's own rule. Unlike `select_parent`, a missing
    // parent is an ERROR here (it treats missing as 0-work; we must not
    // guess).
    let mut best: Option<(crate::consensus::BlockHash, u128, u64)> = None;
    for p in parents {
        let d = dag.get_block_data(p)
            .ok_or(ExpectedBitsError::ParentDataMissing(*p))?;
        let cand = (*p, d.blue_work, d.blue_score);
        best = Some(match best {
            None => cand,
            Some(b) => {
                let ord = cand.1.cmp(&b.1)
                    .then(cand.2.cmp(&b.2))
                    .then(cand.0.cmp(&b.0));
                if ord == std::cmp::Ordering::Greater { cand } else { b }
            }
        });
    }
    let sp = best.expect("parents checked non-empty").0;

    // Bits in force = the selected parent's own header bits. Every block
    // carries its bits, so no extra storage is needed.
    let cur = store.get_block(&sp).ok().flatten()
        .ok_or(ExpectedBitsError::SelectedParentBlockMissing(sp))?
        .header.bits;

    let window = crate::core::GENESIS2_RETARGET_WINDOW;
    if height < window || height % window != 0 {
        return Ok(cur);
    }

    // Retarget boundary: walk this block's selected-parent chain for the two
    // window timestamps — never the height-keyed CF_TIMESTAMPS index, which
    // is last-write-wins when a height has siblings.
    let sp_data = dag.get_block_data(&sp)
        .ok_or(ExpectedBitsError::ParentDataMissing(sp))?;
    let last = sp_data.timestamp;

    let target_height = height - window;
    let mut data = sp_data;
    while data.height > target_height {
        let next = data.selected_parent.ok_or(
            ExpectedBitsError::AncestryIncomplete { want: target_height, reached: data.height })?;
        data = dag.get_block_data(&next).ok_or(
            ExpectedBitsError::AncestryIncomplete { want: target_height, reached: data.height })?;
    }
    if data.height != target_height {
        return Err(ExpectedBitsError::AncestryIncomplete {
            want: target_height, reached: data.height,
        });
    }
    let first = data.timestamp;

    Ok(crate::core::retarget_bits_g2(cur, last.saturating_sub(first)))
}
