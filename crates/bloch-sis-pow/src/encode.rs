// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Canonical byte encoding of solution vectors for hashing.

//! Canonical encoding of solution vectors `s ∈ {-B, …, B}^N` into bytes.
//!
//! With `B = 2`, each coefficient fits in `i8` range `{-2, -1, 0, 1, 2}`.
//! We encode each coefficient as a single signed byte for simplicity.
//! Compact encodings (3 bits per coefficient) are possible and may be
//! adopted later; for v0.1 we prioritize clarity over compactness.

use crate::error::PowError;
use crate::params::{B, ENCODED_S_LEN, N};

/// Encode a solution vector as `N` signed bytes.
///
/// # Errors
/// Returns [`PowError::SolutionTooLarge`] if any coefficient exceeds the
/// bound `B` (which would make the encoding invalid as a Bloch-SIS-PoW
/// solution).
pub fn encode_s(s: &[i32]) -> Result<[u8; ENCODED_S_LEN], PowError> {
    if s.len() != N {
        return Err(PowError::WrongLength {
            expected: N,
            got: s.len(),
        });
    }

    let mut out = [0u8; ENCODED_S_LEN];
    for (i, &coeff) in s.iter().enumerate() {
        if coeff.abs() > B {
            return Err(PowError::SolutionTooLarge {
                index: i,
                value: coeff,
                bound: B,
            });
        }
        // Cast i32 to i8 then to u8 reinterpretation. With |coeff| ≤ 2,
        // the cast is lossless.
        out[i] = (coeff as i8) as u8;
    }
    Ok(out)
}

/// Decode `N` signed bytes back into an `[i32; N]` solution vector.
///
/// # Errors
/// Returns [`PowError::SolutionTooLarge`] if the decoded value exceeds
/// the bound `B`.
pub fn decode_s(bytes: &[u8]) -> Result<[i32; N], PowError> {
    if bytes.len() != ENCODED_S_LEN {
        return Err(PowError::WrongLength {
            expected: ENCODED_S_LEN,
            got: bytes.len(),
        });
    }

    let mut out = [0i32; N];
    for (i, &b) in bytes.iter().enumerate() {
        let signed = b as i8 as i32;
        if signed.abs() > B {
            return Err(PowError::SolutionTooLarge {
                index: i,
                value: signed,
                bound: B,
            });
        }
        out[i] = signed;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_zero() {
        let s = [0i32; N];
        let bytes = encode_s(&s).unwrap();
        let decoded = decode_s(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn round_trip_full_range() {
        let mut s = [0i32; N];
        for i in 0..N {
            s[i] = match i % 5 {
                0 => -2,
                1 => -1,
                2 => 0,
                3 => 1,
                _ => 2,
            };
        }
        let bytes = encode_s(&s).unwrap();
        let decoded = decode_s(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn rejects_out_of_range_coefficient() {
        let mut s = [0i32; N];
        s[42] = 3; // exceeds B=2
        assert!(encode_s(&s).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        let s = [0i32; 100];
        assert!(encode_s(&s).is_err());
    }
}
