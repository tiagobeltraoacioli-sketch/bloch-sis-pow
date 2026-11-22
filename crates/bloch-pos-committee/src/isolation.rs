// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fault isolation between the L1 core and the L2 / bridge / settlement
//! handlers that share its state transition.
//!
//! The L2 settlement (0x12, 0x13), L2 deposit (0x14), L2 data availability
//! (0x15), L2 withdrawal claim (0x16) and, on the December L2 line, L2
//! forced transaction (0x1C, gated by `L2_FORCED_INCLUSION_EPOCH`) handlers run inside
//! `Transition::compute_post_state`, next to transfers and staking. A panic
//! in one of them (a slice out of range, an `unwrap`, an arithmetic overflow:
//! the release profile keeps `overflow-checks`) unwinds the thread that
//! judges blocks. Every node runs the same code on the same block, so every
//! node stops on it: a defect in code that serves the L2 halts the L1.
//!
//! [`contain`] is the boundary. It runs a closure and turns an unwind into
//! `None`, which the caller maps to the refusal it already has for an invalid
//! transaction. It is used in two places with different standing:
//!
//! * **Mempool / relay preflight (node-local, always on).** The preflight
//!   entry points the node calls at the mempool door and at proposer
//!   selection (`CommittedState::l2_deposit_refusal_at`,
//!   `l2_data_availability_refusal_at`, the `l2_withdraw_claim_refusal*`
//!   family, `l2_settlement::State::validate_async` and
//!   `pending_async_refusal`) run behind [`contain_refusal`]: a preflight that
//!   faults refuses the transaction. None of them is called by the block
//!   transition, so nothing about block validity changes. Without it, one
//!   gossiped transaction that faults a handler stops every node that
//!   receives it (the preflight runs on the consensus thread).
//! * **Block transition (consensus surface, gated by
//!   [`crate::params::L2_FAULT_ISOLATION_ACTIVATION_EPOCH`], inert).** A
//!   transaction of [`is_non_l1`] whose handler faults is refused like any
//!   other invalid transaction, which makes its block invalid
//!   (`TransitionError::Transaction(i)`); the working copy of the state is
//!   discarded with the error, as for every rejected block.
//!
//! What this does not cover, by construction: process aborts (allocation
//! failure, stack overflow, a double panic), non-termination, and the L2
//! bookkeeping that runs once per block outside any transaction
//! (`prepare_source`, `advance_height`, the checkpoint-root record and the L2
//! section of the state root). `consensus_invariant!` is not used by the
//! contained handlers; a contained fault is counted ([`contained_faults`])
//! and the panic hook still prints its message and location.

use crate::transition::PosTransaction;
use std::sync::atomic::{AtomicU64, Ordering};

static CONTAINED_FAULTS: AtomicU64 = AtomicU64::new(0);

/// Whether `tx` belongs to the L2 / bridge / settlement family: the
/// transaction types whose handlers serve the L2 rather than the L1 ledger
/// and validator set. The set the block-transition boundary applies to.
pub fn is_non_l1(tx: &PosTransaction) -> bool {
    // Exhaustive on purpose: a new transaction type does not compile until
    // it is put on one side of the boundary.
    match tx {
        PosTransaction::L2Settlement(_)
        | PosTransaction::L2SettlementAsync(_)
        | PosTransaction::L2Deposit(_)
        | PosTransaction::L2DataAvailability(_)
        | PosTransaction::L2WithdrawClaim(_)
        | PosTransaction::L2ForcedTransaction(_) => true,
        PosTransaction::Transfer { .. }
        | PosTransaction::TransferV2 { .. }
        | PosTransaction::Deposit { .. }
        | PosTransaction::Exit { .. }
        | PosTransaction::ExitV2 { .. }
        | PosTransaction::Withdraw { .. }
        | PosTransaction::Delegate { .. }
        | PosTransaction::RandaoRecommit { .. }
        | PosTransaction::KesRegister { .. }
        | PosTransaction::KesRotate { .. }
        | PosTransaction::SlashingEvidence(_)
        | PosTransaction::FundedDeposit(_)
        | PosTransaction::FundedDelegate(_)
        | PosTransaction::FundedUndelegate(_)
        | PosTransaction::FundedDelegationWithdraw(_)
        | PosTransaction::ValidatorCommissionUpdate(_)
        | PosTransaction::WithdrawalCredentialRotation(_)
        | PosTransaction::RescueCommit(_)
        | PosTransaction::RescueReveal(_) => false,
    }
}

/// Run `f`; `None` if it panicked. The fault is counted and its payload is
/// discarded (the panic hook has already reported it).
///
/// The caller must not keep using state `f` could have left half-written:
/// both callers in this workspace either pass `&` state (preflight) or drop
/// the working copy on the resulting error (block transition).
pub fn contain<T>(f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => Some(value),
        Err(payload) => {
            CONTAINED_FAULTS.fetch_add(1, Ordering::Relaxed);
            // A payload whose destructor panics must not escape either.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(payload)));
            None
        }
    }
}

/// The node-local preflight boundary: `f` answers why a transaction would be
/// refused (`None`: it would be taken); a fault in it is a refusal with the
/// reason `fault`. Only for functions that borrow the state immutably and are
/// not part of the block transition.
pub fn contain_refusal<R>(fault: R, f: impl FnOnce() -> Option<R>) -> Option<R> {
    contain(f).unwrap_or(Some(fault))
}

/// Faults contained by this process since it started. Any value above zero
/// is a defect in a contained handler and should be reported; for an
/// operator it is the signal that a transaction or block was refused because
/// code faulted, not because a rule said so.
pub fn contained_faults() -> u64 {
    CONTAINED_FAULTS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fault_is_contained_and_counted() {
        let before = contained_faults();
        assert_eq!(contain(|| 7u8), Some(7));
        let faulted: Option<u8> = contain(|| {
            let empty: [u8; 0] = [];
            let index = std::hint::black_box(3usize);
            empty[index]
        });
        assert_eq!(faulted, None);
        assert!(contained_faults() > before);
    }

    #[test]
    fn a_faulting_preflight_is_a_refusal() {
        #[derive(Debug, PartialEq)]
        enum Why {
            Rule,
            Fault,
        }
        assert_eq!(contain_refusal(Why::Fault, || None), None);
        assert_eq!(contain_refusal(Why::Fault, || Some(Why::Rule)), Some(Why::Rule));
        let before = contained_faults();
        let zero = std::hint::black_box(0u64);
        assert_eq!(contain_refusal(Why::Fault, || (1 / zero == 1).then_some(Why::Rule)), Some(Why::Fault));
        // Checked arithmetic is on in every profile (workspace `overflow-checks`).
        let top = std::hint::black_box(u64::MAX);
        assert_eq!(contain_refusal(Why::Fault, || (top + 1 == 0).then_some(Why::Rule)), Some(Why::Fault));
        assert!(contained_faults() >= before + 2);
    }
}
