//! LOCAL TEST — "Dual AND" hybrid PoW (design probe, not yet consensus).
//!
//! Dual AND requires a block to satisfy BOTH proof-of-work schemes at once:
//!   valid(block) = sha256d_ok(header)  AND  sis_ok(header, pow_solution)
//!
//! This test does NOT modify consensus. It reconstructs the AND predicate out
//! of the crate's EXISTING, already-shipped public primitives, exactly as the
//! production patch would wire them, and proves the four required properties:
//!
//!   1. a block passes IFF BOTH schemes pass,
//!   2. fails if SHA-256d passes but SIS fails,
//!   3. fails if SIS passes but SHA-256d fails,
//!   4. pre-activation-height blocks ignore the SIS requirement (back-compat).
//!
//! Grounding (file:line at time of writing):
//!   * SHA-256d check      : bloch-crypto/src/core/mod.rs:2029 `sha256d_pow_valid`
//!   * SIS residual verify : bloch-sis-pow/src/verify.rs:83     `verify_regime`
//!                           (via src/pow/mod.rs:125 `verify_sis_pow_testnet`)
//!   * SIS seed preimage   : bloch-crypto/src/core/mod.rs:843   `pow_preimage()` (76B, nonce-less)
//!   * SHA-256d 80B header : bloch-crypto/src/core/mod.rs:834   `pow_hash()`
//!
//! The COUPLING that makes the AND non-cosmetic: both checks are fed the SAME
//! 80-byte MiningHeader projection. SHA-256d hashes the full 80 bytes; the SIS
//! seed is SHAKE(DOMAIN || pow_preimage[0..76] || nonce). Both therefore commit
//! to the same merkle_root, timestamp, bits and parents-commitment, and (with
//! the nonce constrained to 32 bits — see NOTE below) to the same nonce, so an
//! attacker cannot solve the two schemes over two different header inputs.

use bloch::core::{sha256d_pow_valid, Block, BlockHeader, MerkleRoot};
use bloch::pow;

/// Height at which the (hypothetical) Dual AND rule turns on. Mirrors the
/// existing height-gated `SHA256D_LE_FORK_HEIGHT = 2400` migration style: below
/// this height blocks validate byte-for-byte as before (SIS not required); at or
/// above it the SIS co-requirement is enforced.
const DUAL_AND_ACTIVATION_HEIGHT: u64 = 5_000;

/// All-0xFF target — every hash meets it (SHA-256d trivially passes).
const SHA_TARGET_ALWAYS: [u8; 32] = [0xFF; 32];
/// All-0x00 target — no realistic double-SHA256 (≈2^-256) can meet it, so
/// SHA-256d deterministically FAILS. Used to force the "SHA fails" quadrant.
const SHA_TARGET_NEVER: [u8; 32] = [0x00; 32];

fn test_header(nonce: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        parents: vec![],
        merkle_root: MerkleRoot::ZERO,
        timestamp: 1_777_000_000,
        // Easiest SIS aux target so mining is gated only by the (relaxed k=4)
        // residual — keeps the test a fast debug-build unit test.
        bits: pow::target_to_bits(&pow::Target::MAX),
        nonce,
    }
}

/// THE Dual AND validity predicate, assembled from existing public primitives.
/// This is the exact logic the production `validate_pow` `DualAnd` arm would run.
///
/// Verification ORDER is DoS-safe: the cheap SHA-256d gate runs FIRST and
/// short-circuits, so the expensive SIS residual/matrix-multiply only runs on
/// headers that already cost real SHA-256d work.
///
/// `sha_target` and `sis_bits` are PASSED SEPARATELY on purpose — this probe
/// demonstrates the recommended TWO-INDEPENDENT-DIFFICULTIES design (a SHA
/// target + a SIS target), which lets us drive each quadrant independently.
fn dual_and_valid(
    header: &BlockHeader,
    height: u64,
    pow_solution: &[i32],
    sha_target: &[u8; 32],
    sis_bits: u32,
) -> bool {
    // (1) Cheap gate: SHA-256d over the 80-byte MiningHeader (today's check).
    if !sha256d_pow_valid(&header.pow_hash(), sha_target, height) {
        return false;
    }

    // (3) Back-compat gate: before activation the SIS proof is NOT required,
    //     so a pre-fork block (empty pow_solution) validates exactly as it does
    //     on today's pure-SHA-256d Genesis-2 chain.
    if height < DUAL_AND_ACTIVATION_HEIGHT {
        return pow_solution.is_empty();
    }

    // (2) Expensive gate: the SIS witness must satisfy the Module-SIS instance
    //     derived from the SAME header (pow_preimage) and the SAME nonce.
    if pow_solution.len() != pow::SOLUTION_LEN {
        return false;
    }
    let mut s = [0i32; pow::SOLUTION_LEN];
    s.copy_from_slice(pow_solution);
    // NOTE: production uses the height-aware `verify_sis_pow(.., height)` so the
    // SF-1 residual ramp applies; this probe uses the k=4 testnet regime to keep
    // mining cheap. The AND wiring being proved is identical either way.
    pow::verify_sis_pow_testnet(&header.pow_preimage(), header.nonce, &s, sis_bits).is_ok()
}

/// Mine a real k=4 SIS witness for a header, returning the (nonce, solution)
/// and the header carrying that nonce. Cheap in the relaxed testnet regime.
fn mine_sis(sis_bits: u32) -> (BlockHeader, Vec<i32>) {
    let preimage = test_header(0).pow_preimage();
    let (nonce, solution) = pow::mine_sis_pow_testnet(&preimage, sis_bits, 0, 20_000_000)
        .expect("relaxed k=4 testnet regime must be brute-force mineable");
    // NOTE: solver starts at nonce 0, so `nonce < 2^32` here — SHA-256d (which
    // reads only the low 32 bits) and SIS (which reads the full u64) see the
    // SAME nonce, upholding the coupling. Production must ENFORCE nonce < 2^32
    // in the DualAnd arm so the high 32 bits can't be a free SIS-only grind.
    (test_header(nonce), solution.to_vec())
}

#[test]
fn dual_and_passes_iff_both_schemes_pass() {
    let sis_bits = pow::target_to_bits(&pow::Target::MAX);
    let (header, solution) = mine_sis(sis_bits);
    let h = DUAL_AND_ACTIVATION_HEIGHT; // post-activation: both required

    // Sanity: the two component checks individually agree with our fixtures.
    let mut s_arr = [0i32; pow::SOLUTION_LEN];
    s_arr.copy_from_slice(&solution);
    assert!(
        pow::verify_sis_pow_testnet(&header.pow_preimage(), header.nonce, &s_arr, sis_bits).is_ok(),
        "mined witness must verify under the SIS component check"
    );
    assert!(
        sha256d_pow_valid(&header.pow_hash(), &SHA_TARGET_ALWAYS, h),
        "SHA component must pass against the all-FF target"
    );

    // (1) BOTH pass -> Dual AND accepts.
    assert!(
        dual_and_valid(&header, h, &solution, &SHA_TARGET_ALWAYS, sis_bits),
        "block must pass when BOTH SHA-256d and SIS pass"
    );
}

#[test]
fn dual_and_fails_when_sha_passes_but_sis_fails() {
    let sis_bits = pow::target_to_bits(&pow::Target::MAX);
    let (header, solution) = mine_sis(sis_bits);
    let h = DUAL_AND_ACTIVATION_HEIGHT;

    // Corrupt the SIS witness (flip one coefficient) — SHA is untouched and
    // still passes (all-FF), but SIS must now reject.
    let mut bad = solution.clone();
    bad[0] = if bad[0] == 0 { 1 } else { 0 };
    assert!(
        sha256d_pow_valid(&header.pow_hash(), &SHA_TARGET_ALWAYS, h),
        "precondition: SHA still passes"
    );
    assert!(
        !dual_and_valid(&header, h, &bad, &SHA_TARGET_ALWAYS, sis_bits),
        "block must FAIL when SHA passes but the SIS witness is invalid"
    );

    // Also: tampering only the nonce (header) breaks the SIS seed binding while
    // SHA (all-FF) still passes.
    let mut tampered = header.clone();
    tampered.nonce = header.nonce.wrapping_add(1);
    assert!(
        !dual_and_valid(&tampered, h, &solution, &SHA_TARGET_ALWAYS, sis_bits),
        "block must FAIL when the nonce no longer binds the SIS witness"
    );
}

#[test]
fn dual_and_fails_when_sis_passes_but_sha_fails() {
    let sis_bits = pow::target_to_bits(&pow::Target::MAX);
    let (header, solution) = mine_sis(sis_bits);
    let h = DUAL_AND_ACTIVATION_HEIGHT;

    // SIS witness is valid, but the SHA target is unmeetable -> SHA fails.
    assert!(
        !sha256d_pow_valid(&header.pow_hash(), &SHA_TARGET_NEVER, h),
        "precondition: SHA must fail against the all-zero target"
    );
    assert!(
        !dual_and_valid(&header, h, &solution, &SHA_TARGET_NEVER, sis_bits),
        "block must FAIL when SIS passes but SHA-256d does not"
    );
}

#[test]
fn pre_activation_blocks_ignore_the_sis_requirement() {
    let sis_bits = pow::target_to_bits(&pow::Target::MAX);
    let (header, _solution) = mine_sis(sis_bits);

    // BELOW activation: a pure-SHA-256d block with an EMPTY pow_solution — i.e.
    // exactly what today's Genesis-2 chain produces — must still validate.
    let below = DUAL_AND_ACTIVATION_HEIGHT - 1;
    assert!(
        dual_and_valid(&header, below, &[], &SHA_TARGET_ALWAYS, sis_bits),
        "pre-activation: empty-witness SHA-256d block must remain valid (no reorg)"
    );

    // And the migration actually bites: AT activation, the same empty-witness
    // block is now rejected because the SIS co-requirement is enforced.
    assert!(
        !dual_and_valid(&header, DUAL_AND_ACTIVATION_HEIGHT, &[], &SHA_TARGET_ALWAYS, sis_bits),
        "post-activation: empty-witness block must be rejected (SIS now required)"
    );
}
