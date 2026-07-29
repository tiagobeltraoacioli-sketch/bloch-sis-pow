//! Bloch-SIS Proof-of-Work adapter.
//!
//! This is the seam between Bloch's block layer and the `bloch-sis-pow`
//! reference crate (a SHAKE-256 hashcash PoW with a Module-SIS structural
//! gate — the identity of Bloch-SIS). Since B5b, **Bloch-SIS is the live
//! consensus PoW**: `Block::validate_pow` verifies the block's solution
//! vector via `verify_regime`, with the residual width selected by the
//! block's height (soft fork SF-1): `TESTNET_RESIDUAL_COEFFS` (= 4) below
//! `CANONICAL_K_ACTIVATION_HEIGHT`, `CANONICAL_RESIDUAL_COEFFS` (= 8) at or
//! above it. SHA-256d is gone from the Mainnet/Testnet consensus — it returns
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
//! audit land. Soft fork SF-1 (k: 4 → 8 at the activation height) tightens the
//! structural gate's rejection floor from ~2^12 to ~2^24 but does NOT change
//! this security story: k = 8 is the *candidate* canonical width, still
//! pending the no-shortcut proof, and the security source remains hashcash.
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

/// Soft fork SF-1 activation height + height→k selector (re-exported from
/// `bloch_crypto::core`, the consensus module `Block::validate_pow` lives in,
/// so miner and validator provably share one selector). The activation height
/// is a PLACEHOLDER the founder must set before the live deploy — see its doc.
pub use bloch_crypto::core::{canonical_residual_coeffs, CANONICAL_K_ACTIVATION_HEIGHT, K_RULE_ACTIVATION_HEIGHT};

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
/// block mined at/after `CANONICAL_K_ACTIVATION_HEIGHT` is rejected by
/// upgraded validators.
pub fn mine_sis_pow_testnet(
    pow_preimage: &[u8],
    bits: u32,
    start_nonce: u64,
    max_attempts: u64,
) -> Option<(u64, [i32; SOLUTION_LEN])> {
    mine_sis_pow_regime(pow_preimage, bits, TESTNET_RESIDUAL_COEFFS, start_nonce, max_attempts)
}

/// Height-aware consensus verify (soft fork SF-1). Verifies a Module-SIS PoW
/// witness at compact difficulty `bits` under the residual width selected by
/// `height` — the height OF THE BLOCK BEING VALIDATED (never the tip):
/// k = 4 below [`CANONICAL_K_ACTIVATION_HEIGHT`], k = 8 at/above it.
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

    /// Soft fork SF-1: fixed preimage for the height-aware k=8 e2e test.
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
    fn canonical_mine_verify_roundtrip_at_k8() {
        // (d) height-aware mine → verify roundtrip at a post-activation
        // height, plus the subset property through the node seam.
        let bits = target_to_bits(&Target::MAX);
        let h = CANONICAL_K_ACTIVATION_HEIGHT;

        let (nonce, s) = mine_sis_pow(K8_E2E_PREIMAGE, bits, h, K8_E2E_START_NONCE, 4096)
            .expect("pinned window must contain a k=8 solution — if solver \
                     internals changed, re-run the sf1_search utility");

        // Verifies at the height it was mined for (k = 8)...
        assert!(verify_sis_pow(K8_E2E_PREIMAGE, nonce, &s, bits, h).is_ok());
        assert!(verify_sis_pow(K8_E2E_PREIMAGE, nonce, &s, bits, h + 1).is_ok());
        // ...and below H too (k = 4 is a prefix subset of k = 8): un-upgraded
        // peers accept post-fork blocks — the soft-fork no-partition property.
        assert!(verify_sis_pow(K8_E2E_PREIMAGE, nonce, &s, bits, 0).is_ok());
        assert!(verify_sis_pow_testnet(K8_E2E_PREIMAGE, nonce, &s, bits).is_ok());
        // Tampering the nonce breaks it at the canonical height.
        assert!(verify_sis_pow(K8_E2E_PREIMAGE, nonce.wrapping_add(1), &s, bits, h).is_err());
    }

    #[test]
    fn k4_mined_block_rejected_at_canonical_height() {
        // (b) at the node seam: a k=4 (pre-fork style) witness must be
        // rejected by the height-aware verify at/above H. A k=4 solution
        // sneaks past k=8 with probability ≈ 1/4096, so mine until one fails
        // (more than 8 mines has probability ≈ 4096^-8 — never).
        let preimage = b"bloch-sf1-k4-rejected-at-h";
        let bits = target_to_bits(&Target::MAX);
        let h = CANONICAL_K_ACTIVATION_HEIGHT;

        let mut rejected = None;
        for i in 0..8u64 {
            let (nonce, s) = mine_sis_pow_testnet(preimage, bits, i * 1_000_003, 500_000)
                .expect("k=4 testnet regime must be brute-force mineable");
            // Height-aware verify agrees with the testnet verify below H.
            assert!(verify_sis_pow(preimage, nonce, &s, bits, h - 1).is_ok());
            if verify_sis_pow(preimage, nonce, &s, bits, h).is_err() {
                rejected = Some((nonce, s));
                break;
            }
        }
        let (nonce, s) = rejected
            .expect("8 consecutive k=4 solutions all passed k=8 — gate broken");
        assert!(matches!(
            verify_sis_pow(preimage, nonce, &s, bits, h).unwrap_err(),
            VerifyError::ResidualTooLarge { .. }
        ));
    }

    #[test]
    fn height_aware_miner_below_activation_matches_testnet_regime() {
        // (e) below H the height-aware miner IS the testnet regime: cheap to
        // mine, and its output verifies under both the testnet and the
        // height-aware verify at pre-fork heights.
        let preimage = b"bloch-sf1-below-h-equivalence";
        let bits = target_to_bits(&Target::MAX);

        let (nonce, s) = mine_sis_pow(preimage, bits, 0, 0, 20_000_000)
            .expect("below H the height-aware miner must be k=4-cheap");
        assert!(verify_sis_pow(preimage, nonce, &s, bits, 0).is_ok());
        assert!(verify_sis_pow(preimage, nonce, &s, bits, CANONICAL_K_ACTIVATION_HEIGHT - 1).is_ok());
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
