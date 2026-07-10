//! Demonstrates the **leading-zeros difficulty knob** of the small-k design — the
//! "the bar rises with mining" mechanic, Bitcoin-style, shown empirically.
//!
//! The PoW has two independent parts (the difficulty-knob split, already wired in
//! `verify::verify_regime`):
//!   1. a FIXED, non-trivial residual floor `β` (`√k·β < q`) — the Module-SIS
//!      structural gate; it does NOT change with difficulty and is not the
//!      security source;
//!   2. a TUNABLE `aux_hash < target` filter (SHAKE-256) — the mineable difficulty,
//!      raised/lowered by ASERT as hashrate rises/falls; this cumulative hash
//!      work is the PoW's security.
//!
//! This test freezes β and only moves the `aux` target: a harder target costs
//! strictly more mining work, and an impossible target yields no block. Mining is
//! deterministic here (fixed candidate RNG seed), so the attempt counts are exact.

use bloch_sis_pow::difficulty::{hash_meets_target, Target};
use bloch_sis_pow::solver::{mine, MineConfig};
use bloch_sis_pow::verify::verify_regime;
use bloch_sis_pow::TESTNET_RESIDUAL_COEFFS;

fn cfg(max_total_attempts: u64) -> MineConfig {
    MineConfig {
        start_nonce: 1,
        residual_coeffs: TESTNET_RESIDUAL_COEFFS, // small-k, non-trivial (√k·β < q)
        max_total_attempts,
        ..MineConfig::default()
    }
}

#[test]
fn leading_zeros_target_scales_mining_work() {
    let header = b"difficulty-scaling-demo";
    let k = TESTNET_RESIDUAL_COEFFS;

    // Easy: MAX target — every aux passes, so only the fixed β floor gates.
    let easy = mine(header, &Target::MAX, &cfg(20_000_000), None).expect("mine at easy target");
    verify_regime(header, easy.nonce, &easy.solution, &Target::MAX, k).expect("easy solution verifies");

    // Harder: require aux < 0x10.. (≈4 extra leading zero bits, ~16× more grind)
    // ON TOP of the same β. Only the leading-zeros knob moved; β is unchanged.
    let mut hard_bytes = [0xFFu8; 32];
    hard_bytes[0] = 0x10;
    let hard_target = Target::from_be_bytes(hard_bytes);
    let hard = mine(header, &hard_target, &cfg(50_000_000), None).expect("mine at harder target");
    verify_regime(header, hard.nonce, &hard.solution, &hard_target, k).expect("hard solution verifies");

    // The found aux genuinely meets the harder leading-zeros bar.
    assert!(hash_meets_target(&hard.aux_hash, &hard_target), "hard aux must be below the hard target");
    assert!(hard.aux_hash[0] <= 0x0F, "hard aux top byte shows the extra leading zeros");

    // The core claim: raising the leading-zeros bar costs strictly more work —
    // difficulty rises with mining, exactly like Bitcoin. β never moved.
    assert!(
        hard.attempts > easy.attempts,
        "harder aux-target must cost more work: easy={} hard={}",
        easy.attempts, hard.attempts
    );
}

#[test]
fn impossible_target_never_yields_a_block() {
    // Target::MIN — no hash is < 0, so the aux filter can never be met: the knob
    // genuinely gates acceptance (a real difficulty is unmineable without work).
    let header = b"impossible-target";
    let out = mine(header, &Target::MIN, &cfg(200_000), None);
    assert!(out.is_err(), "an impossible difficulty must exhaust the budget, never accept");
}
