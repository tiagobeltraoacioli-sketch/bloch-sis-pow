// SPDX-License-Identifier: AGPL-3.0-or-later
//! The PQ-typed transaction (§3) and its one canonical encoding.

use crate::codec::{put_bytes_u32, CodecError, Cursor};
use crate::{ADDRESS_BYTES, TX_TYPE_PQ_BATCH, TX_TYPE_PQ_CALL};

/// A transaction authorized by `SUITE_MLDSA65_FALCON1024`, carrying
/// EVM-standard execution fields.
///
/// `sender` is **explicit**. Nothing is ever recovered: the hybrid suite is not
/// a recoverable signature scheme, so the verifier must be handed the
/// 3,745-byte public key or already know it. That is what `sender_pk` and the
/// account→pubkey directory are for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlochTx {
    /// [`TX_TYPE_PQ_CALL`] or [`TX_TYPE_PQ_BATCH`].
    pub type_byte: u8,
    /// Replay domain. Bound by the signing root.
    pub chain_id: u64,
    /// Account nonce. Checked by the execution layer, not here.
    pub nonce: u64,
    /// Gas limit for the whole transaction (the whole batch, for a batch).
    pub gas_limit: u64,
    /// Millisat per gas — `fee_market`'s unit, not a second one.
    pub max_fee: u128,
    /// Destination, or `None` for contract creation.
    pub to: Option<[u8; ADDRESS_BYTES]>,
    /// Value in satoshi.
    pub value: u128,
    /// Calldata; for [`TX_TYPE_PQ_BATCH`], the canonical batch payload (§6).
    pub data: Vec<u8>,
    /// The account being debited. A **claim**, made binding by the address
    /// consistency check in [`crate::verify`].
    pub sender: [u8; ADDRESS_BYTES],
    /// Enveloped hybrid public key. **REQUIRED on the account's first
    /// authorization, FORBIDDEN after** — see [`crate::verify`] for why the
    /// rule is presence and not equality.
    pub sender_pk: Option<Vec<u8>>,
    /// Enveloped hybrid signature over the signing root.
    pub signature: Vec<u8>,
}

impl BlochTx {
    /// Encode to the wire form `type_byte ‖ payload`.
    ///
    /// Errors only if a byte string is too long to carry a canonical `u32`
    /// length prefix — fail closed rather than truncate.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(160 + self.data.len() + self.signature.len());
        out.push(self.type_byte);
        self.encode_unsigned_into(&mut out)?;
        out.extend_from_slice(&self.sender);
        match &self.sender_pk {
            Some(pk) => {
                out.push(1);
                put_bytes_u32(&mut out, pk)?;
            }
            None => out.push(0),
        }
        put_bytes_u32(&mut out, &self.signature)?;
        Ok(out)
    }

    /// The execution fields, in declaration order. Shared by [`Self::encode`]
    /// and the signing root (§4.1) so the two can never describe different
    /// field sets — one derivation path, two readers.
    pub(crate) fn encode_unsigned_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.gas_limit.to_le_bytes());
        out.extend_from_slice(&self.max_fee.to_le_bytes());
        match &self.to {
            Some(to) => {
                out.push(1);
                out.extend_from_slice(to);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.value.to_le_bytes());
        put_bytes_u32(out, &self.data)?;
        Ok(())
    }

    /// Decode the wire form.
    ///
    /// `max_tx_bytes` is the caller's payload budget — in production
    /// `fee_market::max_block_tx_bytes(epoch)`. The crate takes it as a
    /// parameter and **never assumes a constant**, because the cap is itself
    /// epoch-gated and a constant here would be a second source of truth.
    ///
    /// Fail-closed on every path: presence flags must be exactly `0` or `1`,
    /// length prefixes must match the bytes that follow, and **trailing bytes
    /// are a rejection**. Malformed input returns `Err`; nothing panics.
    pub fn decode(bytes: &[u8], max_tx_bytes: u64) -> Result<Self, CodecError> {
        if bytes.len() as u64 > max_tx_bytes {
            return Err(CodecError::TooLarge);
        }
        let mut c = Cursor::new(bytes);
        let type_byte = c.u8()?;
        if type_byte != TX_TYPE_PQ_CALL && type_byte != TX_TYPE_PQ_BATCH {
            return Err(CodecError::UnknownType);
        }
        let chain_id = c.u64()?;
        let nonce = c.u64()?;
        let gas_limit = c.u64()?;
        let max_fee = c.u128()?;
        let to = if c.bool()? { Some(c.array20()?) } else { None };
        let value = c.u128()?;
        let data = c.bytes_u32(max_tx_bytes)?;
        let sender = c.array20()?;
        let sender_pk = if c.bool()? {
            Some(c.bytes_u32(max_tx_bytes)?)
        } else {
            None
        };
        let signature = c.bytes_u32(max_tx_bytes)?;
        c.finish()?;
        Ok(Self {
            type_byte,
            chain_id,
            nonce,
            gas_limit,
            max_fee,
            to,
            value,
            data,
            sender,
            sender_pk,
            signature,
        })
    }
}
