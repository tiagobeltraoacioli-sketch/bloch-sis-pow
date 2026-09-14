//! Bounded native-pool action transport. No consensus activation or creation opcode.
use super::{PoolAction, PoolLedger, PoolReceipt};
use crate::kirpich::limits::MAX_KEY_BYTES;
use crate::ustav::amm::{Action, Request};
use crate::ustav::native_wire::Reader;
use crate::ustav::{OutPoint, Verifier, MAX_INPUTS, MAX_SIGNATURE_BYTES};
pub const WIRE_VERSION: u16 = 1;
pub const MAX_ENCODED_BYTES: usize = 32 * 1024;
const MAGIC: &[u8; 8] = b"USTVPOOL";
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Codec(crate::ustav::pairs::wire::Error),
    Pool(super::Error),
    TooLarge,
    InvalidHeader,
    InvalidVersion,
    InvalidOperation,
    InvalidShape,
    TrailingBytes,
    WrongDomain,
    OutOfGas,
}
impl From<crate::ustav::pairs::wire::Error> for Error {
    fn from(e: crate::ustav::pairs::wire::Error) -> Self {
        Self::Codec(e)
    }
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Pool(e)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub domain: [u8; 32],
    pub action: PoolAction,
    pub signature: Vec<u8>,
}
fn shape(e: &Envelope) -> Result<(), Error> {
    if e.domain == [0; 32]
        || e.action.owner.is_empty()
        || e.action.owner.len() > MAX_KEY_BYTES
        || e.signature.is_empty()
        || e.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(Error::InvalidShape);
    }
    for funding in &e.action.funding {
        if funding.len() > MAX_INPUTS || funding.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::InvalidShape);
        }
    }
    if matches!(e.action.request.action,Action::SwapExactInput{input_index,..} if input_index>1) {
        return Err(Error::InvalidShape);
    }
    Ok(())
}
fn blob(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}
pub fn encode(e: &Envelope) -> Result<Vec<u8>, Error> {
    shape(e)?;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    out.push(match e.action.request.action {
        Action::Add { .. } => 1,
        Action::SwapExactInput { .. } => 2,
        Action::Remove { .. } => 3,
    });
    out.extend_from_slice(&e.domain);
    out.extend_from_slice(&e.action.request.pool);
    out.extend_from_slice(&e.action.request.revision.to_le_bytes());
    out.extend_from_slice(&e.action.request.valid_until.to_le_bytes());
    match e.action.request.action {
        Action::Add {
            maximum,
            minimum_lp,
        } => {
            for value in [maximum[0], maximum[1], minimum_lp] {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        Action::SwapExactInput {
            input_index,
            amount,
            minimum_out,
        } => {
            out.push(input_index);
            out.extend_from_slice(&amount.to_le_bytes());
            out.extend_from_slice(&minimum_out.to_le_bytes());
        }
        Action::Remove { lp, minimum } => {
            for value in [lp, minimum[0], minimum[1]] {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    blob(&mut out, &e.action.owner);
    for funding in &e.action.funding {
        out.extend_from_slice(&(funding.len() as u32).to_le_bytes());
        for id in funding {
            out.extend_from_slice(&id.transaction);
            out.extend_from_slice(&id.index.to_le_bytes());
        }
    }
    blob(&mut out, &e.signature);
    if out.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(out)
}
pub fn decode(bytes: &[u8]) -> Result<Envelope, Error> {
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
    let op = r.take(1)?[0];
    if !(1..=3).contains(&op) {
        return Err(Error::InvalidOperation);
    }
    let domain = r.fixed()?;
    let pool = r.fixed()?;
    let revision = u64::from_le_bytes(r.fixed()?);
    let valid_until = u64::from_le_bytes(r.fixed()?);
    let action = match op {
        1 => Action::Add {
            maximum: [
                u64::from_le_bytes(r.fixed()?),
                u64::from_le_bytes(r.fixed()?),
            ],
            minimum_lp: u64::from_le_bytes(r.fixed()?),
        },
        2 => Action::SwapExactInput {
            input_index: r.take(1)?[0],
            amount: u64::from_le_bytes(r.fixed()?),
            minimum_out: u64::from_le_bytes(r.fixed()?),
        },
        _ => Action::Remove {
            lp: u64::from_le_bytes(r.fixed()?),
            minimum: [
                u64::from_le_bytes(r.fixed()?),
                u64::from_le_bytes(r.fixed()?),
            ],
        },
    };
    let owner = r.blob(MAX_KEY_BYTES)?;
    let mut funding = [Vec::new(), Vec::new()];
    for points in &mut funding {
        let count = r.count(MAX_INPUTS)?;
        // Check the entire bounded slice before allocating any outpoints.
        let raw = r.take(count * 36)?;
        for point in raw.chunks_exact(36) {
            points.push(OutPoint {
                transaction: point[..32].try_into().expect("fixed width"),
                index: u32::from_le_bytes(point[32..].try_into().expect("fixed width")),
            });
        }
    }
    let signature = r.blob(MAX_SIGNATURE_BYTES)?;
    if r.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    let e = Envelope {
        domain,
        action: PoolAction {
            request: Request {
                pool,
                revision,
                valid_until,
                action,
            },
            owner,
            funding,
        },
        signature,
    };
    shape(&e)?;
    Ok(e)
}
pub fn apply_encoded(
    ledger: &mut PoolLedger,
    bytes: &[u8],
    height: u64,
    verifier: &dyn Verifier,
    gas_limit: u64,
) -> Result<PoolReceipt, Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    let parse_gas = 100 + (bytes.len() as u64).div_ceil(32);
    let remaining = gas_limit.checked_sub(parse_gas).ok_or(Error::OutOfGas)?;
    let e = decode(bytes)?;
    if e.domain != *ledger.gateway().native().domain() {
        return Err(Error::WrongDomain);
    }
    let mut receipt = ledger.execute(&e.action, &e.signature, height, verifier, remaining)?;
    receipt.gas_used += parse_gas;
    Ok(receipt)
}
