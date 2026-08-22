// SPDX-License-Identifier: AGPL-3.0-or-later
//! The house codec: fixed-width little-endian scalars, 4-byte length prefixes,
//! fields in declaration order — the shape `transition.rs` already uses.
//!
//! **Not RLP.** RLP admits non-minimal integer encodings, and this repo's rule
//! — from `DS_TXID` through the hybrid signature's fixed split point — is that
//! one object has exactly one encoding. Two encodings of one object is
//! malleability.
//!
//! Every reader is fail-closed and **returns `Err`, never panics**: a panic in
//! a decode path is a consensus rule violation, not a crash.

/// Why a decode failed. One variant per reason — "invalid" alone makes a
/// divergence undebuggable from logs (the `DepositReject` idiom).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The input ended before a field it promised.
    Truncated,
    /// Bytes remained after the last field. **A rejection, never ignored.**
    /// This chain has already paid for the other choice: nodes built before
    /// the AuxPoW merge froze at block 10802 on "trailing bytes in block
    /// body".
    TrailingBytes,
    /// A presence flag was neither `0` nor `1`. `2` is not "true".
    BadBool,
    /// The leading type byte is not one this crate knows.
    UnknownType,
    /// A length prefix, or the whole object, exceeds the caller-supplied
    /// payload budget. The budget is a parameter; the crate never assumes a
    /// constant for it.
    TooLarge,
    /// A batch declared `count == 0`. A batch that authorizes nothing is not
    /// a batch.
    EmptyBatch,
    /// A field is too large to be encoded canonically (a byte string longer
    /// than a `u32` length prefix can describe). Unreachable in practice;
    /// present so the encoder can fail closed instead of truncating.
    FieldTooLong,
}

/// A fail-closed reader over a byte slice.
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::Truncated)?;
        if end > self.bytes.len() {
            return Err(CodecError::Truncated);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// A presence flag. MUST be exactly `0` or `1`.
    pub(crate) fn bool(&mut self) -> Result<bool, CodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::BadBool),
        }
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub(crate) fn u128(&mut self) -> Result<u128, CodecError> {
        let b = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok(u128::from_le_bytes(a))
    }

    pub(crate) fn array20(&mut self) -> Result<[u8; 20], CodecError> {
        let b = self.take(20)?;
        let mut a = [0u8; 20];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// A `u32`-prefixed byte string. The prefix MUST match the bytes that
    /// follow — truncation is a rejection — and MUST fit the budget.
    pub(crate) fn bytes_u32(&mut self, budget: u64) -> Result<Vec<u8>, CodecError> {
        let len = self.u32()?;
        if u64::from(len) > budget {
            return Err(CodecError::TooLarge);
        }
        let len = usize::try_from(len).map_err(|_| CodecError::TooLarge)?;
        Ok(self.take(len)?.to_vec())
    }

    /// Finish. **Any remaining byte is a rejection.**
    pub(crate) fn finish(self) -> Result<(), CodecError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

/// Append a `u32`-prefixed byte string, failing closed if it cannot be
/// described canonically rather than truncating the prefix.
pub(crate) fn put_bytes_u32(out: &mut Vec<u8>, body: &[u8]) -> Result<(), CodecError> {
    let len = u32::try_from(body.len()).map_err(|_| CodecError::FieldTooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    Ok(())
}
