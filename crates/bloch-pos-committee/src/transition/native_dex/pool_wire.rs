//! Bounded pool lifecycle transport, delegating all authorization to State.
//! No HTTP/RPC registration, consensus activation or alternate custody backend.
pub use super::wire::Error;
use super::wire::{preflight_base_shape, Reader};
use super::{
    add_liquidity, initial_liquidity, paired_custody, remove_liquidity, swap, swap_quote, State,
    MAX_BASE_WITNESS_BYTES, MAX_ENVELOPE_BYTES,
};
use crate::{fee_market, transition::PosTransaction, SignatureVerifier};
use bloch_euvm::ustav::{transfer_wire, Verifier};

#[derive(Clone, Debug)]
pub enum Request {
    CreatePair(paired_custody::Request),
    Initialize(initial_liquidity::Request),
    Add(add_liquidity::Request),
    Swap(swap::Request),
    Remove(remove_liquidity::Request),
    ClosePair(paired_custody::CloseRequest),
}
#[derive(Clone, Debug)]
pub enum Receipt {
    CreatePair(paired_custody::Receipt),
    Initialize(initial_liquidity::Receipt),
    Add(add_liquidity::Receipt),
    Swap(swap::Receipt),
    Remove(remove_liquidity::Receipt),
    ClosePair(paired_custody::CloseReceipt),
}
pub fn encode(request: &Request, domain: &[u8; 32]) -> Result<Vec<u8>, Error> {
    match request {
        Request::CreatePair(r) => r.canonical_bytes(domain),
        Request::Initialize(r) => r.canonical_bytes(domain),
        Request::Add(r) => r.canonical_bytes(domain),
        Request::Swap(r) => r.canonical_bytes(domain),
        Request::Remove(r) => r.canonical_bytes(domain),
        Request::ClosePair(r) => r.canonical_bytes(domain),
    }
    .map_err(Error::Joint)
}

// Only small fixed fields and borrowed, size-checked owner bytes exist before
// the complete frame passes structural validation. No witness tables are cloned.
enum Tail<'a> {
    Create {
        seed: [u8; 32],
        blch_amount: u64,
        native_amount: u64,
    },
    Add {
        pool: [u8; 32],
        root: [u8; 32],
        revision: u64,
        maximum: [u64; 2],
        minimum_lp: u64,
    },
    Swap {
        pool: [u8; 32],
        root: [u8; 32],
        revision: u64,
        input_asset: [u8; 32],
        amount: u64,
        minimum_out: u64,
    },
    Remove {
        pool: [u8; 32],
        owner: &'a [u8],
        root: [u8; 32],
        revision: u64,
        lp: u64,
        minimum: [u64; 2],
    },
    Close {
        reserve: [u8; 32],
        creation: [u8; 32],
    },
}
fn u64_field(reader: &mut Reader<'_>) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(reader.fixed()?))
}
fn base_decode(bytes: &[u8]) -> Result<PosTransaction, Error> {
    let tx = PosTransaction::from_canonical_bytes(bytes).map_err(Error::Base)?;
    if tx.canonical_bytes() != bytes {
        return Err(Error::NonCanonical);
    }
    Ok(tx)
}
fn finish(request: Request, bytes: &[u8], domain: &[u8; 32]) -> Result<Request, Error> {
    if encode(&request, domain)? != bytes {
        return Err(Error::NonCanonical);
    }
    Ok(request)
}
/// expected_domain must originate from authenticated host configuration.
/// Decoding accepts structurally canonical unsigned intents; execution still
/// requires funding, freshness, signatures and the current complete State.
pub fn decode(bytes: &[u8], expected_domain: &[u8; 32]) -> Result<Request, Error> {
    if bytes.len() as u64 > MAX_ENVELOPE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut reader = Reader { bytes, offset: 0 };
    let magic: [u8; 8] = reader.fixed()?;
    let version = match &magic {
        b"BLCHPAIR" | b"BLCHILIQ" | b"BLCHLPAD" | b"BLCHSWAP" | b"BLCHPCLS" => 1,
        b"BLCHLPRM" => 2,
        _ => return Err(Error::InvalidHeader),
    };
    if u16::from_le_bytes(reader.fixed()?) != version {
        return Err(Error::InvalidVersion);
    }
    let domain: [u8; 32] = reader.fixed()?;
    if domain == [0; 32] || domain != *expected_domain {
        return Err(Error::WrongDomain);
    }
    if &magic == b"BLCHILIQ" {
        let reserve = reader.fixed()?;
        let creation_authorization = reader.fixed()?;
        let fee_bps = u16::from_le_bytes(reader.fixed()?);
        let minimum_lp = u64_field(&mut reader)?;
        let valid_until = u64_field(&mut reader)?;
        let base = reader.section(MAX_ENVELOPE_BYTES)?;
        preflight_base_shape(base, 1, false)?;
        if reader.offset != bytes.len() {
            return Err(Error::TrailingBytes);
        }
        return finish(
            Request::Initialize(initial_liquidity::Request {
                reserve,
                creation_authorization,
                fee_bps,
                minimum_lp,
                valid_until,
                blch: base_decode(base)?,
            }),
            bytes,
            expected_domain,
        );
    }
    let valid_until = u64_field(&mut reader)?;
    let native_gas = u64_field(&mut reader)?;
    let base = reader.section(MAX_ENVELOPE_BYTES)?;
    preflight_base_shape(base, 1, true)?;
    let native_bytes = reader.section(transfer_wire::MAX_ENCODED_BYTES as u64)?;
    let tail = match &magic {
        b"BLCHPAIR" => Tail::Create {
            seed: reader.fixed()?,
            blch_amount: u64_field(&mut reader)?,
            native_amount: u64_field(&mut reader)?,
        },
        b"BLCHLPAD" => Tail::Add {
            pool: reader.fixed()?,
            root: reader.fixed()?,
            revision: u64_field(&mut reader)?,
            maximum: [u64_field(&mut reader)?, u64_field(&mut reader)?],
            minimum_lp: u64_field(&mut reader)?,
        },
        b"BLCHSWAP" => Tail::Swap {
            pool: reader.fixed()?,
            root: reader.fixed()?,
            revision: u64_field(&mut reader)?,
            input_asset: reader.fixed()?,
            amount: u64_field(&mut reader)?,
            minimum_out: u64_field(&mut reader)?,
        },
        b"BLCHLPRM" => {
            let pool = reader.fixed()?;
            let owner = reader.section(MAX_BASE_WITNESS_BYTES as u64)?;
            if owner.is_empty() {
                return Err(Error::TooLarge);
            }
            Tail::Remove {
                pool,
                owner,
                root: reader.fixed()?,
                revision: u64_field(&mut reader)?,
                lp: u64_field(&mut reader)?,
                minimum: [u64_field(&mut reader)?, u64_field(&mut reader)?],
            }
        }
        b"BLCHPCLS" => Tail::Close {
            reserve: reader.fixed()?,
            creation: reader.fixed()?,
        },
        _ => return Err(Error::InvalidHeader),
    };
    if reader.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    // Every section boundary and operation tail has now been validated.
    let blch = base_decode(base)?;
    let native = transfer_wire::decode(native_bytes).map_err(Error::Native)?;
    if native.domain != domain {
        return Err(Error::WrongDomain);
    }
    let request = match tail {
        Tail::Create {
            seed,
            blch_amount,
            native_amount,
        } => Request::CreatePair(paired_custody::Request {
            blch,
            native,
            seed,
            blch_amount,
            native_amount,
            valid_until,
            native_gas,
        }),
        Tail::Add {
            pool,
            root,
            revision,
            maximum,
            minimum_lp,
        } => Request::Add(add_liquidity::Request {
            quote: add_liquidity::QuoteRequest {
                domain,
                pool,
                revision,
                maximum,
                minimum_lp,
                valid_until,
            },
            pool_state_root: root,
            blch,
            native,
            native_gas,
        }),
        Tail::Swap {
            pool,
            root,
            revision,
            input_asset,
            amount,
            minimum_out,
        } => Request::Swap(swap::Request {
            quote: swap_quote::Request {
                domain,
                pool,
                revision,
                input_asset,
                amount,
                minimum_out,
                valid_until,
            },
            pool_state_root: root,
            blch,
            native,
            native_gas,
        }),
        Tail::Remove {
            pool,
            owner,
            root,
            revision,
            lp,
            minimum,
        } => Request::Remove(remove_liquidity::Request {
            quote: remove_liquidity::QuoteRequest {
                domain,
                pool,
                owner: owner.to_vec(),
                revision,
                lp,
                minimum,
                valid_until,
            },
            pool_state_root: root,
            blch,
            native,
            native_gas,
        }),
        Tail::Close { reserve, creation } => Request::ClosePair(paired_custody::CloseRequest {
            reserve,
            creation_authorization: creation,
            blch,
            native,
            valid_until,
            native_gas,
        }),
    };
    finish(request, bytes, expected_domain)
}
/// Full-frame network fee estimate only; does not authorize or reserve funding.
pub fn quote_encoded(state: &State, bytes: &[u8]) -> Result<fee_market::TxCharge, Error> {
    let request = decode(bytes, &state.domain)?;
    quote_request(state, &request)
}
pub(super) fn quote_request(
    state: &State,
    request: &Request,
) -> Result<fee_market::TxCharge, Error> {
    match request {
        Request::CreatePair(r) => state.quote_paired_custody(r),
        Request::Initialize(r) => state.quote_initial_liquidity(r),
        Request::Add(r) => state.quote_blch_add_fee(r),
        Request::Swap(r) => state.quote_blch_swap_fee(r),
        Request::Remove(r) => state.quote_blch_remove_fee(r),
        Request::ClosePair(r) => state.quote_paired_close(r),
    }
    .map_err(Error::Joint)
}
/// Dispatch only to the existing atomic State implementations. Runtime state,
/// network domain and verifiers cannot be supplied by the encoded request.
pub fn apply_encoded(
    state: &mut State,
    bytes: &[u8],
    height: u64,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Receipt, Error> {
    let request = decode(bytes, &state.domain)?;
    apply_request(state, &request, height, base_verifier, native_verifier)
}
pub(super) fn apply_request(
    state: &mut State,
    request: &Request,
    height: u64,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Receipt, Error> {
    match request {
        Request::CreatePair(r) => state
            .execute_paired_custody(r, height, base_verifier, native_verifier)
            .map(Receipt::CreatePair),
        Request::Initialize(r) => state
            .execute_initial_liquidity(r, height, base_verifier, native_verifier)
            .map(Receipt::Initialize),
        Request::Add(r) => state
            .execute_blch_add(r, height, base_verifier, native_verifier)
            .map(Receipt::Add),
        Request::Swap(r) => state
            .execute_blch_swap(r, height, base_verifier, native_verifier)
            .map(Receipt::Swap),
        Request::Remove(r) => state
            .execute_blch_remove(r, height, base_verifier, native_verifier)
            .map(Receipt::Remove),
        Request::ClosePair(r) => state
            .execute_paired_close(r, height, base_verifier, native_verifier)
            .map(Receipt::ClosePair),
    }
    .map_err(Error::Joint)
}

#[cfg(test)]
mod tests;
