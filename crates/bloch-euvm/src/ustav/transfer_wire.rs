//! Bounded single native transfer transport; no dispatch or consensus activation.
//! Decoding checks shape, not authorization, available inputs or conservation.
use super::native_wire::{check_native, encode_native, Reader};
use super::{Transaction, Witnesses, MAX_WITNESS_BYTES};

const MAGIC: &[u8; 8] = b"USTVTRAN";
pub const WIRE_VERSION: u16 = 1;
pub const MAX_ENCODED_BYTES: usize = 2 * MAX_WITNESS_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Codec(super::pairs::wire::Error),
    TooLarge,
    InvalidHeader,
    InvalidVersion,
    InvalidOperation,
    InvalidShape,
    TrailingBytes,
}
impl From<super::pairs::wire::Error> for Error {
    fn from(error: super::pairs::wire::Error) -> Self {
        Self::Codec(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub domain: [u8; 32],
    pub transaction: Transaction,
    pub witnesses: Witnesses,
}

fn shape(envelope: &Envelope) -> Result<(), Error> {
    if envelope.transaction.delta != 0
        || envelope.transaction.inputs.is_empty()
        || envelope.transaction.outputs.is_empty()
    {
        return Err(Error::InvalidShape);
    }
    check_native(&envelope.transaction, &envelope.witnesses, &envelope.domain)?;
    Ok(())
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    shape(envelope)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&envelope.domain);
    encode_native(&mut bytes, &envelope.transaction, &envelope.witnesses)?;
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Envelope, Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(8)? != MAGIC {
        return Err(Error::InvalidHeader);
    }
    if u16::from_le_bytes(reader.fixed()?) != WIRE_VERSION {
        return Err(Error::InvalidVersion);
    }
    if reader.take(1)? != [1] {
        return Err(Error::InvalidOperation);
    }
    let domain = reader.fixed()?;
    let (transaction, witnesses) = reader.leg()?;
    if reader.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    let envelope = Envelope {
        domain,
        transaction,
        witnesses,
    };
    shape(&envelope)?;
    Ok(envelope)
}
