//! Parent-bound, all-or-nothing pool batches in the default-off rehearsal.
//! This is not a live block format, mempool, fee payout or consensus activation.
use super::{pool_wire, State};
use crate::{fee_market, SignatureVerifier};
use bloch_euvm::ustav::Verifier;
use sha3::{Digest, Sha3_256};

/// Fixed rehearsal limits, not caller-selected consensus parameters.
pub const MAX_OPERATIONS: usize = 128;
pub const MAX_BYTES: u64 = fee_market::MAX_BLOCK_TX_BYTES;
pub const MAX_GAS: u64 = fee_market::BLOCK_GAS_LIMIT;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Empty,
    TooManyOperations,
    BytesLimit,
    GasLimit,
    Arithmetic,
    WrongParent,
    Operation {
        index: usize,
        source: pool_wire::Error,
    },
    AccountingMismatch,
    CommitmentMismatch,
    PostStateMismatch,
}

/// A result is information, never a capability to install a previewed state.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub parent_root: [u8; 32],
    pub post_root: [u8; 32],
    pub commitment: [u8; 32],
    pub height: u64,
    pub wire_bytes: u64,
    pub charge: fee_market::TxCharge,
    pub receipts: Vec<pool_wire::Receipt>,
}

fn add_charge(total: &mut fee_market::TxCharge, next: &fee_market::TxCharge) -> Result<(), Error> {
    total.tx_bytes = total
        .tx_bytes
        .checked_add(next.tx_bytes)
        .ok_or(Error::Arithmetic)?;
    if total.tx_bytes > MAX_BYTES {
        return Err(Error::BytesLimit);
    }
    total.gas = total.gas.checked_add(next.gas).ok_or(Error::Arithmetic)?;
    if total.gas > MAX_GAS {
        return Err(Error::GasLimit);
    }
    total.base_fee_sat = total
        .base_fee_sat
        .checked_add(next.base_fee_sat)
        .ok_or(Error::Arithmetic)?;
    total.priority_fee_sat = total
        .priority_fee_sat
        .checked_add(next.priority_fee_sat)
        .ok_or(Error::Arithmetic)?;
    Ok(())
}
fn receipt_charge(receipt: &pool_wire::Receipt) -> fee_market::TxCharge {
    match receipt {
        pool_wire::Receipt::Gateway(r) => r.charge,
        pool_wire::Receipt::CreatePair(r) => r.charge,
        pool_wire::Receipt::Initialize(r) => r.charge,
        pool_wire::Receipt::Add(r) => r.charge,
        pool_wire::Receipt::Swap(r) => r.charge,
        pool_wire::Receipt::Remove(r) => r.charge,
        pool_wire::Receipt::ClosePair(r) => r.charge,
    }
}

fn stage(
    state: &State,
    parent_root: &[u8; 32],
    height: u64,
    frames: &[&[u8]],
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<(State, Outcome), Error> {
    if frames.is_empty() {
        return Err(Error::Empty);
    }
    if frames.len() > MAX_OPERATIONS {
        return Err(Error::TooManyOperations);
    }
    // Reject total wire size before any frame decoding, crypto or state cloning.
    let wire_bytes = frames.iter().try_fold(0u64, |total, frame| {
        total
            .checked_add(frame.len() as u64)
            .filter(|n| *n <= MAX_BYTES)
            .ok_or(Error::BytesLimit)
    })?;
    if state.state_root() != *parent_root {
        return Err(Error::WrongParent);
    }
    let mut charge = fee_market::TxCharge {
        gas: 0,
        tx_bytes: 0,
        base_fee_sat: 0,
        priority_fee_sat: 0,
    };
    let mut requests = Vec::with_capacity(frames.len());
    for (index, frame) in frames.iter().enumerate() {
        let request = pool_wire::decode(frame, &state.domain)
            .map_err(|source| Error::Operation { index, source })?;
        // Fee quoting depends on the fixed parent price and signed frame, not
        // whether an earlier operation has created its funding outputs yet.
        let fee = pool_wire::quote_request(state, &request)
            .map_err(|source| Error::Operation { index, source })?;
        add_charge(&mut charge, &fee)?;
        requests.push((request, fee));
    }
    // All declared bytes/gas and structural limits passed before cryptography.
    let mut staged = state.clone();
    let mut receipts = Vec::with_capacity(requests.len());
    for (index, (request, expected_fee)) in requests.iter().enumerate() {
        let receipt =
            pool_wire::apply_request(&mut staged, request, height, base_verifier, native_verifier)
                .map_err(|source| Error::Operation { index, source })?;
        if receipt_charge(&receipt) != *expected_fee {
            return Err(Error::AccountingMismatch);
        }
        receipts.push(receipt);
    }
    let old_fees = state.fee_escrow();
    let expected_fees = (
        old_fees
            .0
            .checked_add(charge.base_fee_sat)
            .ok_or(Error::Arithmetic)?,
        old_fees
            .1
            .checked_add(charge.priority_fee_sat)
            .ok_or(Error::Arithmetic)?,
    );
    if staged.fee_escrow() != expected_fees {
        return Err(Error::AccountingMismatch);
    }
    let outcome = Outcome {
        parent_root: *parent_root,
        post_root: staged.state_root(),
        commitment: commitment(&state.domain, parent_root, height, frames),
        height,
        wire_bytes,
        charge,
        receipts,
    };
    Ok((staged, outcome))
}

/// Fully verify an ordered candidate against a trusted parent and host height.
/// Does not reserve inputs, advance the chain or return executable inner state.
pub fn simulate(
    state: &State,
    parent_root: &[u8; 32],
    height: u64,
    frames: &[&[u8]],
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Outcome, Error> {
    stage(
        state,
        parent_root,
        height,
        frames,
        base_verifier,
        native_verifier,
    )
    .map(|(_, outcome)| outcome)
}

/// Revalidates every operation against the current parent; installs the entire
/// combined state only on success. Never trusts a caller's simulated outcome.
pub fn apply(
    state: &mut State,
    parent_root: &[u8; 32],
    height: u64,
    frames: &[&[u8]],
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<Outcome, Error> {
    let (staged, outcome) = stage(
        state,
        parent_root,
        height,
        frames,
        base_verifier,
        native_verifier,
    )?;
    *state = staged;
    Ok(outcome)
}

/// Exact candidate identity; no witness or frame ordering is omitted.
pub(super) fn commitment(
    domain: &[u8; 32],
    parent: &[u8; 32],
    height: u64,
    frames: &[&[u8]],
) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"BLOCH-POOL-BATCH-v1");
    hash.update(domain);
    hash.update(parent);
    hash.update(height.to_le_bytes());
    hash.update((frames.len() as u64).to_le_bytes());
    for frame in frames {
        hash.update((frame.len() as u64).to_le_bytes());
        hash.update(frame);
    }
    hash.finalize().into()
}

pub(super) struct Expected {
    pub parent: [u8; 32],
    pub post: [u8; 32],
    pub commitment: [u8; 32],
    pub height: u64,
}
/// Untrusted advertised roots are compared before installation, never after it.
pub(super) fn stage_expected(
    state: &State,
    expected: &Expected,
    frames: &[&[u8]],
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<(State, Outcome), Error> {
    let (staged, outcome) = stage(
        state,
        &expected.parent,
        expected.height,
        frames,
        base_verifier,
        native_verifier,
    )?;
    if outcome.commitment != expected.commitment {
        return Err(Error::CommitmentMismatch);
    }
    if outcome.post_root != expected.post {
        return Err(Error::PostStateMismatch);
    }
    Ok((staged, outcome))
}

#[cfg(test)]
pub(super) mod tests;
