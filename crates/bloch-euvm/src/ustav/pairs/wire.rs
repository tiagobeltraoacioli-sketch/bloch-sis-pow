//! Bounded canonical pair transport. This is not a consensus activation or RPC server.
use super::{Error as PairError, PairReceipt, PairSwap};
use crate::ustav::native_wire::{check_native, encode_native, Reader};
use crate::ustav::{Ledger, Verifier, Witnesses, MAX_WITNESS_BYTES};

const MAGIC: &[u8; 8] = b"USTVPAIR";
pub const WIRE_VERSION: u16 = 1;
/// Covers two maximum native transactions, witnesses and bounded structural overhead.
pub const MAX_ENCODED_BYTES: usize = 5 * MAX_WITNESS_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Truncated,
    InvalidHeader,
    InvalidVersion,
    InvalidOperation,
    InvalidShape,
    TrailingBytes,
    WrongDomain,
    OutOfGas,
    Settlement(PairError),
}
impl From<PairError> for Error {
    fn from(error: PairError) -> Self {
        Self::Settlement(error)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPair {
    pub domain: [u8; 32],
    pub swap: PairSwap,
    pub witnesses: [Witnesses; 2],
}

fn shape(swap: &PairSwap, witnesses: &[Witnesses; 2], domain: &[u8; 32]) -> Result<(), Error> {
    swap.signing_hash(domain)?;
    for (leg, witness) in swap.legs.iter().zip(witnesses) {
        check_native(leg, witness, domain)?;
    }
    Ok(())
}
/// Encode the complete pair, including every owner, module and eligibility witness.
pub fn encode_pair(
    domain: &[u8; 32],
    swap: &PairSwap,
    witnesses: &[Witnesses; 2],
) -> Result<Vec<u8>, Error> {
    shape(swap, witnesses, domain)?;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    out.push(1); // The only admitted operation is atomic pair settlement.
    out.extend_from_slice(domain);
    for (tx, witness) in swap.legs.iter().zip(witnesses) {
        encode_native(&mut out, tx, witness)?;
    }
    if out.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Rejects oversized envelopes before allocation and unbounded counts before loops.
pub fn decode_pair(bytes: &[u8]) -> Result<DecodedPair, Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    let mut r = Reader { bytes, offset: 0 };
    if r.take(8)? != MAGIC {
        return Err(Error::InvalidHeader);
    }
    if u16::from_le_bytes(r.fixed()?) != WIRE_VERSION {
        return Err(Error::InvalidVersion);
    }
    if r.take(1)? != [1] {
        return Err(Error::InvalidOperation);
    }
    let domain = r.fixed()?;
    let (first, first_witness) = r.leg()?;
    let (second, second_witness) = r.leg()?;
    if r.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    let swap = PairSwap {
        legs: [first, second],
    };
    let witnesses = [first_witness, second_witness];
    shape(&swap, &witnesses, &domain)?;
    Ok(DecodedPair {
        domain,
        swap,
        witnesses,
    })
}

/// Decode and dispatch only the joint operation; no separately dispatchable legs.
/// The host supplies authenticated height, verifier and its transaction gas budget.
pub fn apply_encoded_pair(
    ledger: &mut Ledger,
    bytes: &[u8],
    height: u64,
    verifier: &dyn Verifier,
    gas_limit: u64,
) -> Result<PairReceipt, Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    let decoding_gas = 100u64.saturating_add((bytes.len() as u64).div_ceil(32));
    let remaining = gas_limit.checked_sub(decoding_gas).ok_or(Error::OutOfGas)?;
    let decoded = decode_pair(bytes)?;
    if decoded.domain != *ledger.domain() {
        return Err(Error::WrongDomain);
    }
    let mut receipt = ledger.settle_pair(
        &decoded.swap,
        &decoded.witnesses,
        height,
        verifier,
        remaining,
    )?;
    debug_assert!(receipt.gas_used <= remaining);
    receipt.gas_used = receipt.gas_used.saturating_add(decoding_gas);
    Ok(receipt)
}
