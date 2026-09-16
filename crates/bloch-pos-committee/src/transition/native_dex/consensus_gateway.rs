//! Atomic staging for dormant canonical federated imports and withdrawals.
//! Existing configured quorum attestations are not source-chain consensus proofs.
//! Expiry uses the candidate block's slot, inclusively: slot == valid_until is
//! valid. The block transition owns gate selection, admission, fee settlement
//! and publication; this module neither initializes nor imports native state.
use super::{gateway, wire, CommittedState, NativeState, State};
use crate::{fee_market::TxCharge, SignatureVerifier};
use bloch_euvm::ustav::gateway::wire::Operation;
use bloch_euvm::ustav::Verifier;

/// Outer PosTransaction tag (one byte) and payload length (four bytes).
const OUTER_BYTES: u64 = crate::transition::NATIVE_TRANSFER_FRAME_BYTES as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::transition) enum Error {
    InvalidState,
    WrongOperation,
    Wire(wire::Error),
    Execution(super::Error),
}

/// Stage both ledgers and publish them together only after successful execution.
/// `base_fee` is the candidate block's selected price, not the next-block quote.
/// Returned fees must enter the host's normal block fee accounting exactly once.
pub(in crate::transition) fn apply_gateway(
    base: &mut CommittedState,
    payload: &[u8],
    slot: u64,
    base_fee: u128,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
    import: bool,
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
    let request = gateway::decode(payload, &native.domain).map_err(Error::Wire)?;
    if matches!(&request.gateway.operation, Operation::Import(_)) != import {
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
    let execution = state
        .execute_gateway_with_context(
            &request,
            slot,
            base_fee,
            OUTER_BYTES,
            base_verifier,
            native_verifier,
        )
        .map_err(Error::Execution)?;
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
    Ok(execution.charge)
}

pub(in crate::transition) fn apply_import(
    base: &mut CommittedState,
    payload: &[u8],
    slot: u64,
    base_fee: u128,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<TxCharge, Error> {
    apply_gateway(
        base,
        payload,
        slot,
        base_fee,
        base_verifier,
        native_verifier,
        true,
    )
}

pub(in crate::transition) fn apply_withdrawal(
    base: &mut CommittedState,
    payload: &[u8],
    slot: u64,
    base_fee: u128,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<TxCharge, Error> {
    apply_gateway(
        base,
        payload,
        slot,
        base_fee,
        base_verifier,
        native_verifier,
        false,
    )
}

#[cfg(test)]
#[path = "consensus_gateway_tests.rs"]
pub(in crate::transition) mod tests;
