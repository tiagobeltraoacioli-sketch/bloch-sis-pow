//! Property-based invariants for the ASERT-Lattice difficulty adjustment.
//!
//! Difficulty manipulation is a consensus attack vector (timestamp gaming,
//! oscillation). These assert the adjustment behaves monotonically, is bounded/
//! stable on schedule, deterministic, and always yields a valid target.

use bloch_sis_pow::difficulty::{
    asert_next_bits, bits_to_target, target_to_bits, ASERT_HALFLIFE, TARGET_BLOCK_TIME,
};

/// Canonical bits (bits→target→bits is idempotent for these).
fn norm(bits: u32) -> u32 {
    target_to_bits(&bits_to_target(bits))
}
fn tbytes(bits: u32) -> [u8; 32] {
    *bits_to_target(bits).as_bytes()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, n: u64) -> u64 { self.next() % n.max(1) }
}

#[test]
fn on_schedule_leaves_target_unchanged() {
    // exp_num = time_delta - TARGET_BLOCK_TIME*height_delta = 0 → factor 2^0 = 1.
    let anchor = norm(0x1e00_ffff);
    let h = 100u64;
    let anchor_ts = 1_000i64;
    let prev_ts = anchor_ts + TARGET_BLOCK_TIME * h as i64; // exactly on schedule
    let next = asert_next_bits(anchor, anchor_ts, 0, prev_ts, h);
    assert_eq!(tbytes(next), tbytes(anchor), "on-schedule must not move the target");
}

#[test]
fn slower_eases_and_faster_tightens_monotonically() {
    let anchor = norm(0x1e00_ffff);
    let anchor_ts = 1_000i64;
    let h = 50u64;
    let scheduled = anchor_ts + TARGET_BLOCK_TIME * h as i64;
    // ±one halflife → ~2x / ~0.5x, clearly separated.
    let fast = asert_next_bits(anchor, anchor_ts, 0, scheduled - ASERT_HALFLIFE, h);
    let on = asert_next_bits(anchor, anchor_ts, 0, scheduled, h);
    let slow = asert_next_bits(anchor, anchor_ts, 0, scheduled + ASERT_HALFLIFE, h);
    // higher target (bigger big-endian bytes) = easier.
    assert!(tbytes(fast) <= tbytes(on), "faster blocks must not ease difficulty");
    assert!(tbytes(on) <= tbytes(slow), "slower blocks must not tighten difficulty");
    assert!(tbytes(fast) < tbytes(slow), "a halflife swing must move the target");
}

#[test]
fn deterministic_and_yields_valid_canonical_target() {
    let mut r = Rng(0xD1FF_0001);
    for _ in 0..2000 {
        let anchor = norm(0x1d00_0000 | (r.range(0x00ff_ffff) as u32));
        let anchor_ts = r.range(1_000_000) as i64;
        let h = 1 + r.range(1000);
        // prev within a plausible window around schedule ± a few halflives.
        let jitter = r.range(4 * ASERT_HALFLIFE as u64) as i64 - 2 * ASERT_HALFLIFE;
        let prev_ts = anchor_ts + TARGET_BLOCK_TIME * h as i64 + jitter;

        let a = asert_next_bits(anchor, anchor_ts, 0, prev_ts, h);
        let b = asert_next_bits(anchor, anchor_ts, 0, prev_ts, h);
        assert_eq!(a, b, "adjustment must be deterministic");
        // output is a canonical bits value (round-trips through target).
        assert_eq!(target_to_bits(&bits_to_target(a)), a, "output must be a canonical target");
    }
}
