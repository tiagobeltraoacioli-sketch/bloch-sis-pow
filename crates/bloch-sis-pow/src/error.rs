// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Crate-wide error types.

//! Error types for Bloch-SIS-PoW.

use core::fmt;

/// General PoW error covering encoding and parameter validity issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowError {
    /// A solution coefficient exceeds the bound `B`.
    SolutionTooLarge {
        /// Index of the offending coefficient.
        index: usize,
        /// Actual value found.
        value: i32,
        /// Bound that was exceeded.
        bound: i32,
    },
    /// A vector or buffer had unexpected length.
    WrongLength {
        /// Required length.
        expected: usize,
        /// Length actually presented.
        got: usize,
    },
    /// An internal invariant was violated (should not happen).
    InternalInvariant(&'static str),
}

impl fmt::Display for PowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolutionTooLarge { index, value, bound } => {
                write!(f, "solution coefficient out of range: \
                          s[{index}] = {value}, |s[i]| ≤ {bound} required")
            }
            Self::WrongLength { expected, got } => {
                write!(f, "wrong vector length: expected {expected}, got {got}")
            }
            Self::InternalInvariant(msg) => {
                write!(f, "internal invariant violation: {msg}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PowError {}

/// Errors from decoding a compact difficulty "bits" value into a target.
///
/// Returned by [`crate::difficulty::try_bits_to_target`]. Every variant means
/// the compact value cannot represent a valid 256-bit target; consensus code
/// must treat blocks carrying such bits as invalid (fail-hard), never map them
/// to a permissive default target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitsError {
    /// The sign bit (0x0080_0000) is set — negative targets are invalid.
    NegativeFlag,
    /// The mantissa is zero — encodes no target at all.
    ZeroMantissa,
    /// The exponent shifts the mantissa entirely out of the 256-bit range.
    ExponentOutOfRange {
        /// Exponent byte found in the compact value.
        exponent: u32,
    },
    /// The exponent is in range but high mantissa bytes would overflow past
    /// the top of the 256-bit target.
    MantissaOverflow,
}

impl fmt::Display for BitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeFlag => f.write_str("compact bits has the negative-target flag set"),
            Self::ZeroMantissa => f.write_str("compact bits has a zero mantissa"),
            Self::ExponentOutOfRange { exponent } => {
                write!(f, "compact bits exponent {exponent} shifts the mantissa out of 256-bit range")
            }
            Self::MantissaOverflow => {
                f.write_str("compact bits mantissa overflows the 256-bit target range")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BitsError {}

/// Errors from the verifier (verify side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Solution coefficient exceeds the bound `B`.
    SolutionTooLarge,
    /// Residual `||A·s - t||_∞ ≥ β`.
    ResidualTooLarge {
        /// Actual maximum coefficient absolute value.
        actual: u32,
        /// Bound `β`.
        bound: u32,
    },
    /// Auxiliary hash check failed: `aux_hash ≥ target`.
    AuxHashAboveTarget,
    /// Underlying encoding/length error.
    PowError(PowError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolutionTooLarge => f.write_str("solution out of [-B, B]"),
            Self::ResidualTooLarge { actual, bound } => {
                write!(f, "residual norm {actual} ≥ β={bound}")
            }
            Self::AuxHashAboveTarget => f.write_str("auxiliary hash ≥ target"),
            Self::PowError(e) => write!(f, "pow error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyError {}

impl From<PowError> for VerifyError {
    fn from(value: PowError) -> Self {
        Self::PowError(value)
    }
}

/// Errors from the miner. Mostly these are non-fatal — search continues
/// with a different nonce — but some signal misuse of the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MineError {
    /// The maximum attempt budget was exhausted without finding a
    /// solution. Caller can retry with a higher budget.
    AttemptsExhausted,
    /// Mining was cancelled cooperatively (e.g., new tip arrived).
    Cancelled,
    /// Underlying error.
    PowError(PowError),
}

impl fmt::Display for MineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttemptsExhausted => f.write_str("attempts exhausted; retry with bigger budget"),
            Self::Cancelled         => f.write_str("mining cancelled"),
            Self::PowError(e)        => write!(f, "pow error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MineError {}

impl From<PowError> for MineError {
    fn from(value: PowError) -> Self {
        Self::PowError(value)
    }
}
