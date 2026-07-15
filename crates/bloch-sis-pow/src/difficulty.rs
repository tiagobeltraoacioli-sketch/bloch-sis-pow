// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Difficulty target representation and ASERT adjustment.

//! Difficulty target encoding (compact `u32` ⇄ 256-bit target) and the
//! ASERT (Absolutely Scheduled Exponentially Rising Targets) difficulty
//! adjustment algorithm.
//!
//! The "compact bits" representation is a u32 encoding of an
//! approximated 256-bit target value, identical in spirit to Bitcoin's
//! `nBits`. We carry it in block headers because it is dense and
//! human-readable.
//!
//! The ASERT adjustment is parameterized for Bloch's 30-second target
//! block time and uses a 2-day half-life. Both are protocol constants
//! and changing them is a hard fork.

use crate::error::BitsError;
use crate::params::AUX_HASH_LEN;

/// Target block time in seconds (= 30s). Hard-fork constant.
pub const TARGET_BLOCK_TIME: i64 = 30;

/// ASERT half-life in seconds (= 2 days). Hard-fork constant.
pub const ASERT_HALFLIFE: i64 = 2 * 24 * 60 * 60;

/// Maximum allowed adjustment factor per single retarget step
/// (relative to the previous target). Hard-fork constant.
///
/// `MAX_FACTOR = 4` means a single block's difficulty can increase
/// or decrease by at most 4×. This bounds attack potential from
/// timestamp manipulation without unduly limiting natural adjustment.
pub const MAX_FACTOR_NUMERATOR:   i64 = 4;
/// Denominator of the maximum factor (paired with the numerator).
pub const MAX_FACTOR_DENOMINATOR: i64 = 1;

/// A 256-bit target threshold against which the auxiliary hash is
/// compared. `aux_hash < target` is the acceptance condition.
///
/// Stored as 32 big-endian bytes for convenient comparison with the
/// SHAKE-256 output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Target(pub [u8; AUX_HASH_LEN]);

impl Target {
    /// The maximum possible target (everything passes — easiest difficulty).
    pub const MAX: Target = Target([0xFF; AUX_HASH_LEN]);

    /// The minimum possible target (nothing passes — impossible).
    pub const MIN: Target = Target([0x00; AUX_HASH_LEN]);

    /// Construct from a big-endian byte array.
    pub const fn from_be_bytes(bytes: [u8; AUX_HASH_LEN]) -> Self {
        Target(bytes)
    }

    /// Borrow the underlying bytes as a slice.
    pub fn as_bytes(&self) -> &[u8; AUX_HASH_LEN] {
        &self.0
    }
}

/// Decode a compact "bits" representation into a 256-bit target.
///
/// The compact format follows the convention used by Bitcoin and many
/// derivatives: the high byte is an exponent (number of bytes minus 3),
/// the low 24 bits are the mantissa. The target equals `mantissa <<
/// (8 * (exponent - 3))`.
///
/// # Returns
/// `Ok(target)` for a representable compact value, or a [`BitsError`]
/// describing why the value is invalid:
///
/// - [`BitsError::NegativeFlag`] — sign bit (0x0080_0000) set.
/// - [`BitsError::ZeroMantissa`] — mantissa is zero.
/// - [`BitsError::ExponentOutOfRange`] — the exponent shifts the mantissa
///   entirely above the 256-bit range (exponent ≥ 35).
/// - [`BitsError::MantissaOverflow`] — exponent 33/34 with high mantissa
///   bytes that would spill past the top of the target.
///
/// SECURITY (audit): this is the fail-hard decoder. The previous behavior
/// mapped an overflowing exponent to [`Target::MAX`] — the *easiest possible*
/// difficulty — so a block header carrying crafted bits (e.g. `0xFF00FFFF`)
/// would have every auxiliary hash pass the difficulty filter. Invalid bits
/// must be an error (or, in the infallible wrapper, the *impossible* target),
/// never a permissive default.
pub fn try_bits_to_target(bits: u32) -> Result<Target, BitsError> {
    let exponent = (bits >> 24) as i32;
    let mantissa = bits & 0x007F_FFFF; // mask out the negative-flag bit

    // Negative-target compact representations are invalid in this scheme.
    if (bits & 0x0080_0000) != 0 {
        return Err(BitsError::NegativeFlag);
    }
    if mantissa == 0 {
        return Err(BitsError::ZeroMantissa);
    }

    let mut out = [0u8; AUX_HASH_LEN];
    if exponent <= 3 {
        // Right-shift case: mantissa >> (8*(3-exponent)). Low bytes shifted
        // out are dropped — this rounds the target DOWN (harder), which is
        // the safe direction and matches the compact-format convention.
        let shift = 8 * (3 - exponent);
        let m = mantissa >> shift;
        // Place at end (low position).
        out[29] = ((m >> 16) & 0xFF) as u8;
        out[30] = ((m >> 8) & 0xFF) as u8;
        out[31] = (m & 0xFF) as u8;
    } else {
        // Left-shift case: mantissa << (8*(exponent-3))
        let shift = 8 * (exponent - 3);
        // Byte index (big-endian) where the LOWEST mantissa byte lands.
        let low_byte = AUX_HASH_LEN as i32 - 1 - shift / 8;
        if !(0..AUX_HASH_LEN as i32).contains(&low_byte) {
            // Even mantissa = 1 would sit above 2^255-ish; unrepresentable.
            return Err(BitsError::ExponentOutOfRange { exponent: exponent as u32 });
        }
        let pos = low_byte as usize;
        let m_bytes = mantissa.to_be_bytes(); // [_, b0, b1, b2]
        // High mantissa bytes that would land above byte 0 overflow the
        // 256-bit range. The old code silently DROPPED them (encoding a
        // different, smaller target); fail-hard instead.
        if (pos < 2 && m_bytes[1] != 0) || (pos < 1 && m_bytes[2] != 0) {
            return Err(BitsError::MantissaOverflow);
        }
        if pos >= 2 { out[pos - 2] = m_bytes[1]; }
        if pos >= 1 { out[pos - 1] = m_bytes[2]; }
        out[pos]                         = m_bytes[3];
    }
    Ok(Target(out))
}

/// Infallible compatibility wrapper around [`try_bits_to_target`].
///
/// # Returns
/// A 32-byte big-endian target. If the compact representation is invalid
/// (negative bit set, zero mantissa, or an exponent/mantissa that overflows
/// the 256-bit range), returns [`Target::MIN`] — the *impossible* target that
/// no hash can meet, so consensus fails CLOSED on malformed bits.
///
/// SECURITY (audit): overflowing exponents previously fell back to
/// [`Target::MAX`] (everything passes). New code should prefer
/// [`try_bits_to_target`] and reject the block explicitly.
pub fn bits_to_target(bits: u32) -> Target {
    try_bits_to_target(bits).unwrap_or(Target::MIN)
}

/// Encode a 256-bit target back into the compact `u32` bits form.
///
/// This is approximate: only the top three significant bytes of the
/// target are preserved in the compact form. Encoding then decoding
/// rounds the target *down* (toward harder) which is the safe direction.
pub fn target_to_bits(target: &Target) -> u32 {
    let bytes = &target.0;

    // Find the highest non-zero byte position.
    let mut idx = 0usize;
    while idx < AUX_HASH_LEN && bytes[idx] == 0 {
        idx += 1;
    }
    if idx == AUX_HASH_LEN {
        return 0; // target is zero
    }

    // Number of significant bytes is (AUX_HASH_LEN - idx).
    let total_bytes = AUX_HASH_LEN - idx;
    let exponent = total_bytes as u32;

    // Take up to three bytes of mantissa starting from idx.
    let m0 = bytes[idx] as u32;
    let m1 = if idx + 1 < AUX_HASH_LEN { bytes[idx + 1] as u32 } else { 0 };
    let m2 = if idx + 2 < AUX_HASH_LEN { bytes[idx + 2] as u32 } else { 0 };
    let mut mantissa = (m0 << 16) | (m1 << 8) | m2;

    // If the high bit of the mantissa is set, that would look like a
    // negative-target encoding. To avoid that, shift right one byte
    // and bump the exponent.
    let exponent = if (mantissa & 0x0080_0000) != 0 {
        mantissa >>= 8;
        exponent + 1
    } else {
        exponent
    };

    (exponent << 24) | (mantissa & 0x007F_FFFF)
}

/// Test whether a 32-byte hash satisfies `hash < target` (big-endian
/// lexicographic comparison).
pub fn hash_meets_target(hash: &[u8], target: &Target) -> bool {
    debug_assert_eq!(hash.len(), AUX_HASH_LEN);
    for i in 0..AUX_HASH_LEN {
        match hash[i].cmp(&target.0[i]) {
            core::cmp::Ordering::Less    => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal   => continue,
        }
    }
    // Equal across all bytes → not strictly less.
    false
}

/// ASERT difficulty adjustment.
///
/// Computes the new compact "bits" target for a block at `new_height`
/// given a fixed anchor block.
///
/// # Arguments
/// - `anchor_bits`: compact bits of the anchor block (a fixed reference).
/// - `anchor_timestamp`: timestamp of the anchor block.
/// - `anchor_height`: height of the anchor block.
/// - `prev_timestamp`: timestamp of the parent of the new block.
/// - `new_height`: height of the new block being mined.
///
/// # Returns
/// New compact bits for the block.
///
/// # Algorithm
/// ASERT corrects toward an absolute schedule: each block's expected
/// timestamp is `anchor_timestamp + TARGET_BLOCK_TIME * (height -
/// anchor_height)`. The deviation from this schedule, divided by the
/// half-life, becomes the exponent in `target *= 2^exponent`.
///
/// The factor is clamped to `[1/MAX_FACTOR, MAX_FACTOR]` per single
/// retarget to bound attack potential.
pub fn asert_next_bits(
    anchor_bits: u32,
    anchor_timestamp: i64,
    anchor_height: u64,
    prev_timestamp: i64,
    new_height: u64,
) -> u32 {
    let height_delta = (new_height - anchor_height) as i64;
    let time_delta   = prev_timestamp - anchor_timestamp;

    // Exponent numerator = time_delta - target_time * height_delta
    // If positive → blocks have been slower than scheduled → target eases.
    // If negative → blocks have been faster than scheduled → target tightens.
    let exp_num = time_delta - TARGET_BLOCK_TIME * height_delta;

    // Compute the adjustment factor 2^(exp_num / halflife).
    // We use a fixed-point shift approximation suitable for u32
    // bits-target arithmetic. For a reference implementation we use
    // an integer-shift approximation; production code may prefer a
    // higher-precision pow2 via lookup tables.
    let factor_log2_milli = (exp_num * 1000) / ASERT_HALFLIFE;

    let anchor_target = bits_to_target(anchor_bits);
    let new_target = scale_target_by_pow2_milli(&anchor_target, factor_log2_milli);

    target_to_bits(&new_target)
}

/// Multiply a 256-bit target by `2^(exponent_milli / 1000)` with
/// approximation suitable for difficulty adjustment.
///
/// Internally: the integer part becomes a true **bit** shift of the 256-bit
/// target (2^int_part), and the fractional part a small multiplicative
/// correction factor in 16-bit fixed point.
fn scale_target_by_pow2_milli(target: &Target, exponent_milli: i64) -> Target {
    // Clamp to avoid extreme adjustments per single retarget.
    let max_milli =  2_000; // 2.0 in milli units → factor 4
    let min_milli = -2_000; // -2.0 → factor 1/4
    let e_milli = exponent_milli.clamp(min_milli, max_milli);

    // Decompose into integer bits and fractional milli-bits.
    let int_part  = e_milli.div_euclid(1000) as i32;
    let frac_milli = e_milli.rem_euclid(1000) as u32; // 0..999

    // 2^(frac_milli/1000) approximated by 1 + (frac_milli/1000) * ln(2)
    // ≈ 1 + frac_milli * 0.000693, in 16-bit fixed point:
    // factor_q16 = 65536 + (frac_milli * 45) ≈ 1.0..1.999
    // (45 * 999 ≈ 44955 ≈ 0.685 in q16, close enough for milli precision.)
    let frac_factor_q16: u64 = 65_536 + (frac_milli as u64) * 45;

    // Integer part: a TRUE bit shift of the 256-bit target by 2^int_part —
    // NOT a byte shift. The old byte-shift multiplied by 256^int_part, so the
    // documented ±4× per-step clamp was really ±65536×, silently collapsing
    // difficulty once the chain drifted off schedule. int_part ∈ [-2, 2] after
    // the ±2000-milli clamp, i.e. at most two doublings/halvings.
    let mut t = target.0;
    if int_part > 0 {
        for _ in 0..int_part {
            // Left shift = larger target = easier; overflow saturates to MAX.
            if mul2_be(&mut t) { return Target([0xFFu8; AUX_HASH_LEN]); }
        }
    } else if int_part < 0 {
        for _ in 0..(-int_part) {
            // Right shift = smaller target = harder.
            div2_be(&mut t);
        }
    }

    // Fractional multiplier (16-bit fixed-point, ≈ 1.0..1.685) applied to the
    // bit-shifted target. Saturates to MAX on overflow (never wraps to a
    // spuriously harder target).
    let mut result = [0u8; AUX_HASH_LEN];
    let mut carry: u64 = 0;
    for i in (0..AUX_HASH_LEN).rev() {
        let prod = (t[i] as u64) * frac_factor_q16 + carry;
        let digit = prod >> 16;
        if i == 0 && digit > 0xFF {
            return Target([0xFFu8; AUX_HASH_LEN]);
        }
        result[i] = digit as u8;
        carry = prod & 0xFFFF;
    }
    Target(result)
}

/// Multiply a big-endian 256-bit integer by 2 in place; returns `true` on
/// overflow out of the top bit.
fn mul2_be(t: &mut [u8; AUX_HASH_LEN]) -> bool {
    let mut carry = 0u8;
    for i in (0..AUX_HASH_LEN).rev() {
        let v = ((t[i] as u16) << 1) | carry as u16;
        t[i] = v as u8;
        carry = (v >> 8) as u8;
    }
    carry != 0
}

/// Divide a big-endian 256-bit integer by 2 in place (floor).
fn div2_be(t: &mut [u8; AUX_HASH_LEN]) {
    let mut carry = 0u8;
    for i in 0..AUX_HASH_LEN {
        let v = ((carry as u16) << 8) | t[i] as u16;
        t[i] = (v >> 1) as u8;
        carry = (v & 1) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_integer_part_is_bit_shift_not_byte_shift() {
        // Regression for audit H3: the integer part of the pow2 exponent must be
        // a TRUE bit shift (×2^n), not a byte shift (×256^n) that amplified the
        // ±4× per-step clamp into ±65536×.
        let mut t = [0u8; 32];
        t[6] = 0x01;
        t[7] = 0x80;
        let target = Target(t);

        // +1000 milli = 2^1 → exactly one left bit-shift (frac factor is identity
        // at whole-bit exponents).
        let doubled = scale_target_by_pow2_milli(&target, 1000);
        let mut exp = t; mul2_be(&mut exp);
        assert_eq!(doubled.0, exp, "int_part=+1 must be ×2 (one bit), not ×256");

        // -1000 milli = 2^-1 → one right bit-shift.
        let halved = scale_target_by_pow2_milli(&target, -1000);
        let mut exph = t; div2_be(&mut exph);
        assert_eq!(halved.0, exph, "int_part=-1 must be ÷2 (one bit)");

        // Off-schedule blow-up clamps at ±2000 milli = ×4, NEVER ×65536.
        let quad = scale_target_by_pow2_milli(&target, 999_999);
        let mut exp4 = t; mul2_be(&mut exp4); mul2_be(&mut exp4);
        assert_eq!(quad.0, exp4, "single-step easing must cap at ×4");
    }

    /// Audit fix: invalid compact bits must be a hard error from the checked
    /// decoder — overflow exponent, mantissa spill, zero mantissa, sign bit.
    #[test]
    fn try_bits_to_target_rejects_invalid_bits() {
        // Overflow exponent: 0xFF puts even mantissa=1 far above 2^256.
        assert_eq!(
            try_bits_to_target(0xFF00_FFFF),
            Err(BitsError::ExponentOutOfRange { exponent: 0xFF }),
        );
        // Smallest overflowing exponent: 35 (shift of 32 bytes).
        assert_eq!(
            try_bits_to_target(0x2300_FFFF),
            Err(BitsError::ExponentOutOfRange { exponent: 0x23 }),
        );
        // Exponent 34 with a high mantissa byte spilling past byte 0.
        assert_eq!(try_bits_to_target(0x2201_0001), Err(BitsError::MantissaOverflow));
        // Zero mantissa encodes nothing.
        assert_eq!(try_bits_to_target(0x1D00_0000), Err(BitsError::ZeroMantissa));
        // Negative-target flag.
        assert_eq!(try_bits_to_target(0x1D80_0001), Err(BitsError::NegativeFlag));
    }

    /// Audit REGRESSION: the infallible wrapper must fail CLOSED. The old code
    /// returned Target::MAX (easiest difficulty — every hash passes) for an
    /// out-of-range exponent, letting crafted header bits neutralize PoW.
    #[test]
    fn bits_to_target_fails_closed_on_invalid_bits() {
        assert_eq!(bits_to_target(0xFF00_FFFF), Target::MIN,
            "overflow exponent must map to the impossible target, not MAX");
        assert_eq!(bits_to_target(0x2300_FFFF), Target::MIN);
        assert_eq!(bits_to_target(0x2201_0001), Target::MIN);
        // No hash can ever meet the fail-closed target.
        assert!(!hash_meets_target(&[0x00u8; 32], &bits_to_target(0xFF00_FFFF)));
    }

    /// Valid compact values decode and round-trip exactly.
    #[test]
    fn try_bits_to_target_valid_roundtrip() {
        // Bitcoin-mainnet-launch-style bits, also used by this chain's tooling.
        let t = try_bits_to_target(0x1D00_FFFF).expect("0x1d00ffff is valid");
        assert_eq!(target_to_bits(&t), 0x1D00_FFFF);
        // Checked and infallible decoders agree on valid input.
        assert_eq!(bits_to_target(0x1D00_FFFF), t);
        // Canonical encoding of Target::MAX (exponent 33) is valid too.
        let max_bits = target_to_bits(&Target::MAX);
        let rt = try_bits_to_target(max_bits).expect("canonical MAX bits are valid");
        assert_eq!(target_to_bits(&rt), max_bits);
    }

    #[test]
    fn target_max_min_constants() {
        assert_eq!(Target::MAX.0, [0xFFu8; 32]);
        assert_eq!(Target::MIN.0, [0x00u8; 32]);
    }

    #[test]
    fn hash_meets_target_basic() {
        let target = Target::from_be_bytes([0x10; 32]);
        let easy = [0x00; 32]; // < target
        let hard = [0xFF; 32]; // > target
        let edge = [0x10; 32]; // == target → not strictly less

        assert!(hash_meets_target(&easy, &target));
        assert!(!hash_meets_target(&hard, &target));
        assert!(!hash_meets_target(&edge, &target), "equal must NOT pass");
    }

    #[test]
    fn bits_round_trip() {
        // A reasonable test target.
        let mut target_bytes = [0u8; 32];
        target_bytes[2] = 0x12;
        target_bytes[3] = 0x34;
        target_bytes[4] = 0x56;
        let original = Target(target_bytes);

        let bits = target_to_bits(&original);
        let recovered = bits_to_target(bits);

        // Round-trip is approximate (by design); the recovered target
        // should be ≤ the original (rounding down / harder).
        assert!(!hash_meets_target(&original.0, &recovered) || original == recovered,
                "recovered target should be ≤ original");
    }

    #[test]
    fn asert_no_drift_when_on_schedule() {
        // If blocks land exactly on the schedule, target should stay
        // equal (within rounding) to the anchor.
        let anchor_bits = 0x1d_00_FF_FF; // arbitrary
        let anchor_height = 1000u64;
        let anchor_timestamp = 1_000_000i64;
        let new_height = 1100u64;
        let prev_timestamp = anchor_timestamp + TARGET_BLOCK_TIME * 100;

        let new_bits = asert_next_bits(
            anchor_bits, anchor_timestamp, anchor_height,
            prev_timestamp, new_height,
        );

        // Should be approximately equal; we permit ±1 byte difference.
        let a = bits_to_target(anchor_bits);
        let b = bits_to_target(new_bits);
        let diff = a.0.iter().zip(b.0.iter())
            .map(|(x, y)| (*x as i32 - *y as i32).abs())
            .sum::<i32>();
        assert!(diff < 256, "on-schedule ASERT drifted: diff={diff}");
    }
}
