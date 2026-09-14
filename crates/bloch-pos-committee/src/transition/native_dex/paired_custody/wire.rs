//! Bounded creation-only transport. No RPC registration or reserve release.
pub use super::super::wire::Error;
use super::super::{
    wire::{preflight_base_shape, Reader},
    MAX_ENVELOPE_BYTES,
};
use super::{Receipt, Request, State};
use crate::{transition::PosTransaction, SignatureVerifier};
use bloch_euvm::ustav::{transfer_wire, Verifier};

pub fn encode(request: &Request, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
    request.canonical_bytes(domain).map_err(Error::Joint)
}

/// Authenticate the network externally. All sections and the complete tail are
/// bounded before payload decoders allocate; only one BLCH owner is supported.
pub fn decode(bytes: &[u8], expected_domain: &[u8; 32]) -> Result<Request, Error> {
    if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(8)? != b"BLCHPAIR" {
        return Err(Error::InvalidHeader);
    }
    if u16::from_le_bytes(reader.fixed()?) != 1 {
        return Err(Error::InvalidVersion);
    }
    let domain: [u8; 32] = reader.fixed()?;
    if domain == [0; 32] || domain != *expected_domain {
        return Err(Error::WrongDomain);
    }
    let valid_until = u64::from_le_bytes(reader.fixed()?);
    let native_gas = u64::from_le_bytes(reader.fixed()?);
    let base = reader.section(MAX_ENVELOPE_BYTES)?;
    preflight_base_shape(base, 1, true)?;
    let native_bytes = reader.section(transfer_wire::MAX_ENCODED_BYTES as u64)?;
    let seed = reader.fixed()?;
    let blch_amount = u64::from_le_bytes(reader.fixed()?);
    let native_amount = u64::from_le_bytes(reader.fixed()?);
    if reader.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    let blch = PosTransaction::from_canonical_bytes(base).map_err(Error::Base)?;
    if blch.canonical_bytes() != base {
        return Err(Error::NonCanonical);
    }
    let native = transfer_wire::decode(native_bytes).map_err(Error::Native)?;
    let request = Request {
        blch,
        native,
        seed,
        blch_amount,
        native_amount,
        valid_until,
        native_gas,
    };
    if encode(&request, expected_domain)? != bytes {
        return Err(Error::NonCanonical);
    }
    Ok(request)
}

/// Existing full-frame fee accounting is unchanged; requests cannot choose the
/// runtime domain, backend or verifier. Failures never publish partial custody.
pub fn apply_encoded(
    state: &mut State,
    bytes: &[u8],
    height: u64,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Receipt, Error> {
    let domain = *state.native().gateway().native().domain();
    let request = decode(bytes, &domain)?;
    state
        .execute_paired_custody(&request, height, base_verifier, native_verifier)
        .map_err(Error::Joint)
}

#[cfg(test)]
mod tests;
