// SPDX-License-Identifier: AGPL-3.0-or-later
//! The call batch (§6) — encoding and decoding rules only.
//!
//! The dossier's throughput argument rests on one ≈ 4.6 KB signature
//! amortizing over many operations. Two ways to get there, and only one
//! preserves the sender:
//!
//! - A multicall **contract** needs no consensus surface at all — but then
//!   `msg.sender` for every sub-call is the multicall contract, not the user,
//!   which breaks token allowances and every `Ownable` check. It does not
//!   deliver what §6.1 claims.
//! - A contract **wallet** delivers it via account abstraction — which is
//!   §6.3, explicitly deferred to phase 2.
//!
//! So the batch is a transaction *kind*, and `data` carries the payload below.
//!
//! **Semantics are the execution layer's, and they are new consensus
//! surface:** every sub-call executing with `msg.sender` = the PQ account,
//! atomicity (any sub-call reverting reverts the whole transaction), gas
//! metered per sub-call against the one `gas_limit`, and `count` bounded by
//! the payload budget. Because those are consensus semantics rather than an
//! encoding, **`TX_TYPE_PQ_BATCH` is ratified by the founder at wiring time,
//! not by this crate.** It is specified now because it costs nothing while
//! inert, and because leaving it out would leave §6.1's amortization claim
//! without a mechanism.

use crate::codec::{put_bytes_u32, CodecError, Cursor};
use crate::ADDRESS_BYTES;

/// One sub-call of a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchCall {
    /// Destination, or `None` for contract creation.
    pub to: Option<[u8; ADDRESS_BYTES]>,
    /// Value in satoshi.
    pub value: u128,
    /// Calldata for this sub-call.
    pub calldata: Vec<u8>,
}

/// Encode a batch payload: `u32 count ‖ count × (u8 to_present ‖ [20]to? ‖
/// u128 value ‖ u32 len ‖ calldata)`.
///
/// The whole payload is covered by the signing root, because `data` is.
pub fn encode_batch(calls: &[BatchCall]) -> Result<Vec<u8>, CodecError> {
    if calls.is_empty() {
        return Err(CodecError::EmptyBatch);
    }
    let count = u32::try_from(calls.len()).map_err(|_| CodecError::FieldTooLong)?;
    let mut out = Vec::with_capacity(4 + calls.len() * 64);
    out.extend_from_slice(&count.to_le_bytes());
    for call in calls {
        match &call.to {
            Some(to) => {
                out.push(1);
                out.extend_from_slice(to);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&call.value.to_le_bytes());
        put_bytes_u32(&mut out, &call.calldata)?;
    }
    Ok(out)
}

/// Decode a batch payload. `count >= 1`; strict decode; trailing bytes
/// rejected; every length prefix must match the bytes that follow.
///
/// `max_bytes` is the caller's payload budget, the same parameter the
/// transaction decoder takes and for the same reason.
pub fn decode_batch(data: &[u8], max_bytes: u64) -> Result<Vec<BatchCall>, CodecError> {
    if data.len() as u64 > max_bytes {
        return Err(CodecError::TooLarge);
    }
    let mut c = Cursor::new(data);
    let count = c.u32()?;
    if count == 0 {
        return Err(CodecError::EmptyBatch);
    }
    // `count` is not trusted as a capacity hint: a 4-byte prefix can claim
    // four billion sub-calls. Each iteration's reads are bounded by the input,
    // and a short input fails on `Truncated` long before any allocation grows.
    let mut calls = Vec::new();
    for _ in 0..count {
        let to = if c.bool()? { Some(c.array20()?) } else { None };
        let value = c.u128()?;
        let calldata = c.bytes_u32(max_bytes)?;
        calls.push(BatchCall { to, value, calldata });
    }
    c.finish()?;
    Ok(calls)
}
