//! Bounded import/redemption transport for the sealed gateway transition boundary.
//! Route setup remains explicit; this does not activate consensus or verify finality.
use super::{Deposit, GatewayLedger, ImportRequest, Release, WithdrawalRequest, MAX_COMMITTEE};
use crate::ustav::native_wire::{check_native, encode_native, Reader};
use crate::ustav::{
    Receipt, Transaction, Verifier, Witnesses, MAX_SIGNATURE_BYTES, MAX_WITNESS_BYTES,
};

pub const WIRE_VERSION: u16 = 1;
pub const MAX_ENCODED_BYTES: usize = 3 * MAX_WITNESS_BYTES;
const MAGIC: &[u8; 8] = b"USTVUSDT";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Codec(crate::ustav::pairs::wire::Error),
    Gateway(super::Error),
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
    fn from(value: crate::ustav::pairs::wire::Error) -> Self {
        Self::Codec(value)
    }
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Gateway(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Import(ImportRequest),
    Withdraw(WithdrawalRequest),
}
impl Operation {
    fn transaction(&self) -> &Transaction {
        match self {
            Self::Import(r) => &r.transaction,
            Self::Withdraw(r) => &r.transaction,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub domain: [u8; 32],
    pub operation: Operation,
    pub witnesses: Witnesses,
    /// Indexed by the configured committee; absent signers use empty slots.
    pub approvals: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    pub receipt: Receipt,
    pub release: Option<Release>,
}

fn shape(envelope: &Envelope) -> Result<(), Error> {
    check_native(
        envelope.operation.transaction(),
        &envelope.witnesses,
        &envelope.domain,
    )?;
    if envelope.approvals.len() < 2
        || envelope.approvals.len() > MAX_COMMITTEE
        || envelope
            .approvals
            .iter()
            .any(|s| s.len() > MAX_SIGNATURE_BYTES)
    {
        return Err(Error::InvalidShape);
    }
    // Cryptographic and route-specific checks belong to GatewayLedger, not decoding.
    match &envelope.operation {
        Operation::Import(r) => {
            r.signing_hash(&envelope.domain)?;
        }
        Operation::Withdraw(r) => {
            r.signing_hash(&envelope.domain)?;
        }
    }
    Ok(())
}

pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    shape(envelope)?;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    out.push(match &envelope.operation {
        Operation::Import(_) => 1,
        Operation::Withdraw(_) => 2,
    });
    out.extend_from_slice(&envelope.domain);
    match &envelope.operation {
        Operation::Import(r) => {
            out.extend_from_slice(&r.deposit.route);
            out.extend_from_slice(&r.deposit.nonce.to_le_bytes());
            out.extend_from_slice(&r.deposit.sender);
            out.extend_from_slice(&r.deposit.amount.to_le_bytes());
            out.extend_from_slice(&r.deposit.pq_recipient_hash);
            out.extend_from_slice(&r.source_transaction);
            out.extend_from_slice(&r.source_block);
            out.extend_from_slice(&r.event_index.to_le_bytes());
            out.extend_from_slice(&r.valid_until.to_le_bytes());
        }
        Operation::Withdraw(r) => {
            out.extend_from_slice(&r.route);
            out.extend_from_slice(&r.nonce.to_le_bytes());
            out.extend_from_slice(&r.recipient);
        }
    }
    encode_native(
        &mut out,
        envelope.operation.transaction(),
        &envelope.witnesses,
    )?;
    out.extend_from_slice(&(envelope.approvals.len() as u32).to_le_bytes());
    for approval in &envelope.approvals {
        out.extend_from_slice(&(approval.len() as u32).to_le_bytes());
        out.extend_from_slice(approval);
    }
    if out.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Checks envelope size before allocation and field counts before loops.
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
    let opcode = r.take(1)?[0];
    if opcode != 1 && opcode != 2 {
        return Err(Error::InvalidOperation);
    }
    let domain = r.fixed()?;
    let route = r.fixed()?;
    let nonce = u64::from_le_bytes(r.fixed()?);
    let account = r.fixed()?;
    let (operation, witnesses) = if opcode == 1 {
        let deposit = Deposit {
            route,
            nonce,
            sender: account,
            amount: u64::from_le_bytes(r.fixed()?),
            pq_recipient_hash: r.fixed()?,
        };
        let source_transaction = r.fixed()?;
        let source_block = r.fixed()?;
        let event_index = u32::from_le_bytes(r.fixed()?);
        let valid_until = u64::from_le_bytes(r.fixed()?);
        let (transaction, witnesses) = r.leg()?;
        (
            Operation::Import(ImportRequest {
                deposit,
                source_transaction,
                source_block,
                event_index,
                valid_until,
                transaction,
            }),
            witnesses,
        )
    } else {
        let (transaction, witnesses) = r.leg()?;
        (
            Operation::Withdraw(WithdrawalRequest {
                route,
                nonce,
                recipient: account,
                transaction,
            }),
            witnesses,
        )
    };
    let mut approvals = Vec::new();
    for _ in 0..r.count(MAX_COMMITTEE)? {
        approvals.push(r.blob(MAX_SIGNATURE_BYTES)?);
    }
    if r.offset != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    let envelope = Envelope {
        domain,
        operation,
        witnesses,
        approvals,
    };
    shape(&envelope)?;
    Ok(envelope)
}

/// Host-provided authenticated height and gas; all mutations use the sealed gateway.
pub fn apply_encoded(
    gateway: &mut GatewayLedger,
    bytes: &[u8],
    height: u64,
    verifier: &dyn Verifier,
    gas_limit: u64,
) -> Result<Applied, Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    let decoding_gas = 100 + (bytes.len() as u64).div_ceil(32);
    let remaining = gas_limit.checked_sub(decoding_gas).ok_or(Error::OutOfGas)?;
    let e = decode(bytes)?;
    if e.domain != *gateway.native().domain() {
        return Err(Error::WrongDomain);
    }
    let (mut receipt, release) = match &e.operation {
        Operation::Import(request) => (
            gateway.import(
                request,
                &e.witnesses,
                &e.approvals,
                height,
                verifier,
                remaining,
            )?,
            None,
        ),
        Operation::Withdraw(request) => {
            let (release, receipt) = gateway.withdraw(
                request,
                &e.witnesses,
                &e.approvals,
                height,
                verifier,
                remaining,
            )?;
            (receipt, Some(release))
        }
    };
    receipt.gas_used += decoding_gas;
    Ok(Applied { receipt, release })
}
