//! Dormant canonical adapter for the existing BLCH/native pool lifecycle.
//! The host supplies candidate slot, price and activation. Gateway operations
//! are rejected here so pool admission cannot bypass import/withdrawal gates.
use super::{pool_wire, wire, CommittedState, NativeState, State};
use crate::{fee_market::TxCharge, SignatureVerifier};
use bloch_euvm::ustav::Verifier;
const OUTER_BYTES: u64 = crate::transition::NATIVE_TRANSFER_FRAME_BYTES as u64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::transition) enum Error {
    InvalidState,
    WrongOperation,
    Wire(wire::Error),
    Execution(super::Error),
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Execution(value)
    }
}
/// Stage both ledgers and publish them together only after successful execution.
/// `base_fee` is the candidate block's selected price, not the next-block quote.
/// Returned fees must enter the host's normal block fee accounting exactly once.
pub(in crate::transition) fn apply_pool(
    base: &mut CommittedState,
    payload: &[u8],
    slot: u64,
    base_fee: u128,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<TxCharge, Error> {
    let native = base.native_state.as_ref().ok_or(Error::InvalidState)?;
    if native.domain == [0; 32]
        || base.admission_network_domain != Some(native.domain)
        || native.native.gateway().native().domain() != &native.domain
        || native.base_fees != 0
        || native.priority_fees != 0
    {
        return Err(Error::InvalidState);
    }
    let request = pool_wire::decode(payload, &native.domain).map_err(Error::Wire)?;
    if matches!(&request, pool_wire::Request::Gateway(_)) {
        return Err(Error::WrongOperation);
    }
    let mut staged = base.clone();
    let native = staged.native_state.take().ok_or(Error::InvalidState)?;
    // Only an already-owned canonical component reaches this private adapter.
    // The temporary rehearsal executor sees a base with no embedded component.
    let mut state = State {
        base: staged,
        native: native.native,
        domain: native.domain,
        base_fees: 0,
        priority_fees: 0,
        base_reserves: native.base_reserves,
        base_locks: native.base_locks,
        paired_reserves: native.paired_reserves,
        paired_locks: native.paired_locks,
        initial_pools: native.initial_pools,
        reserve_pools: native.reserve_pools,
    };
    let charge = match &request {
        pool_wire::Request::CreatePair(r) => {
            state
                .execute_paired_custody_with_context(
                    r,
                    slot,
                    base_fee,
                    OUTER_BYTES,
                    base_verifier,
                    native_verifier,
                )?
                .charge
        }
        pool_wire::Request::Initialize(r) => {
            state
                .execute_initial_liquidity_with_context(
                    r,
                    slot,
                    base_fee,
                    OUTER_BYTES,
                    base_verifier,
                    native_verifier,
                )?
                .charge
        }
        pool_wire::Request::Add(r) => {
            state
                .execute_blch_add_with_context(
                    r,
                    slot,
                    base_fee,
                    OUTER_BYTES,
                    base_verifier,
                    native_verifier,
                )?
                .charge
        }
        pool_wire::Request::Swap(r) => {
            state
                .execute_blch_swap_with_context(
                    r,
                    slot,
                    base_fee,
                    OUTER_BYTES,
                    base_verifier,
                    native_verifier,
                )?
                .charge
        }
        pool_wire::Request::Remove(r) => {
            state
                .execute_blch_remove_with_context(
                    r,
                    slot,
                    base_fee,
                    OUTER_BYTES,
                    base_verifier,
                    native_verifier,
                )?
                .charge
        }
        pool_wire::Request::ClosePair(r) => {
            state
                .execute_paired_close_with_context(
                    r,
                    slot,
                    base_fee,
                    OUTER_BYTES,
                    base_verifier,
                    native_verifier,
                )?
                .charge
        }
        pool_wire::Request::Gateway(_) => return Err(Error::WrongOperation),
    };
    // Consensus settles the returned charge in its existing burn/reward path.
    // Never carry rehearsal escrow into canonical native state or double-charge it.
    let native = NativeState {
        native: state.native,
        domain: state.domain,
        base_fees: 0,
        priority_fees: 0,
        base_reserves: state.base_reserves,
        base_locks: state.base_locks,
        paired_reserves: state.paired_reserves,
        paired_locks: state.paired_locks,
        initial_pools: state.initial_pools,
        reserve_pools: state.reserve_pools,
    };
    state.base.native_state = Some(native);
    *base = state.base;
    Ok(charge)
}

#[cfg(test)]
#[path = "consensus_pool_tests.rs"]
pub(in crate::transition) mod tests;
