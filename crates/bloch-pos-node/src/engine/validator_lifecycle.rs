// SPDX-License-Identifier: AGPL-3.0-or-later
//! State-aware relay and automatic lifecycle work for the node's own key.

use super::*;
use bloch_pos_committee::{interfaces::SlashingEvidence, params};

#[cfg(test)]
thread_local! { static WALL_SLOT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(super) fn test_wall_slot() -> Option<u64> {
    WALL_SLOT.with(|s| s.get())
}
#[cfg(test)]
pub(super) fn clock_at(slot: u64) -> impl Drop {
    struct Restore(Option<u64>);
    impl Drop for Restore {
        fn drop(&mut self) {
            WALL_SLOT.with(|s| s.set(self.0));
        }
    }
    Restore(WALL_SLOT.with(|s| s.replace(Some(slot))))
}

fn is_lifecycle(tx: &PosTransaction) -> bool {
    matches!(
        tx,
        PosTransaction::FundedDeposit(_)
            | PosTransaction::Withdraw { .. }
            | PosTransaction::ExitV2 { .. }
            | PosTransaction::RandaoRecommit { .. }
            | PosTransaction::SlashingEvidence(_)
    )
}

impl Engine {
    pub(super) fn validate_lifecycle_admission(&self, tx: &PosTransaction) -> Result<(), Refusal> {
        if !is_lifecycle(tx) {
            return Ok(());
        }
        self.state
            .validate_lifecycle_transaction(
                tx,
                self.state.total_active_stake_sat(),
                self.state.next_base_fee(),
                &self.verifier,
            )
            .map_err(|_| Refusal::Invalid("lifecycle transaction fails committed-state validation"))
    }

    /// Reserve funded inputs against every pending spend and reserve the
    /// joining key against duplicate registrations with different signatures.
    /// Conflicts are refused before capacity eviction or any broadcast.
    pub(super) fn funded_mempool_conflict(&self, tx: &PosTransaction) -> bool {
        let incoming = Self::spent_outpoints(tx).unwrap_or_default();
        self.mempool.values().any(|other| {
            let funded = matches!(tx, PosTransaction::FundedDeposit(_))
                || matches!(other, PosTransaction::FundedDeposit(_));
            if !funded {
                return false;
            }
            if let (PosTransaction::FundedDeposit(a), PosTransaction::FundedDeposit(b)) =
                (tx, other)
            {
                if a.validator_pubkey == b.validator_pubkey {
                    return true;
                }
            }
            Self::spent_outpoints(other)
                .is_some_and(|points| points.iter().any(|point| incoming.contains(point)))
        })
    }

    /// Recheck after every adopted head, including reorgs. Already-verified
    /// signatures are immutable; only their state-dependent rules need work.
    pub(super) fn revalidate_lifecycle_mempool(&mut self) {
        let state = &self.state;
        let total = state.total_active_stake_sat();
        let fee = state.next_base_fee();
        self.mempool.retain(|_, tx| {
            !is_lifecycle(tx)
                || state
                    .validate_lifecycle_transaction(tx, total, fee, &ProbeVerifier)
                    .is_ok()
        });
        self.mempool_admitted_at
            .retain(|key, _| self.mempool.contains_key(key));
        self.mempool_suspect
            .retain(|key| self.mempool.contains_key(key));
    }

    pub(super) fn report_equivocation(&mut self, evidence: SlashingEvidence) {
        let offender = match &evidence {
            SlashingEvidence::AttestationOffence { first, .. } => first.validator,
            SlashingEvidence::ProposerEquivocation { first, .. } => first.header.proposer_index,
        };
        crate::metrics::NodeMetrics::inc(&crate::metrics::NODE.equivocations_observed_total);
        match self.on_transaction(PosTransaction::SlashingEvidence(evidence)) {
            Ok(_) => eprintln!("slashing evidence against v{offender} admitted and broadcast"),
            Err(reason) => {
                eprintln!("slashing evidence against v{offender} not submitted: {reason:?}")
            }
        }
    }

    /// Called after proposer authentication. At most one header per slot/key
    /// in a bounded recent window; invalid signatures never allocate here.
    pub(super) fn observe_proposer_equivocation(&mut self, env: &BlockEnvelope) {
        if !params::epoch_gate_active(
            epoch_of(self.state.slot()),
            params::SLASHING_EVIDENCE_ACTIVATION_EPOCH,
        ) {
            return;
        }
        let key = (env.header.slot, env.header.proposer_index);
        let next = ProposalEnvelope {
            header: env.header.clone(),
            proposer_sig: env.proposer_sig.clone(),
        };
        if let Some(first) = self.observed_proposals.get(&key) {
            if first.header != next.header {
                self.report_equivocation(SlashingEvidence::ProposerEquivocation {
                    first: first.clone(),
                    second: next,
                });
            }
            return;
        }
        let floor = self
            .head_slot_now()
            .saturating_sub(SLOTS_PER_EPOCH.saturating_mul(2));
        self.observed_proposals
            .retain(|(slot, _), _| *slot >= floor);
        while self.observed_proposals.len() >= 4096 {
            self.observed_proposals.pop_first();
        }
        self.observed_proposals.insert(key, next);
    }

    pub(super) fn maintain_validator_lifecycle(&mut self, wall_epoch: u64) {
        // Avoid signing epoch-bound intents while replaying or behind the clock.
        if epoch_of(self.state.slot()) != wall_epoch {
            return;
        }
        let Some(keys) = self.keys.as_ref() else {
            return;
        };
        let Some(index) = self.duty_index(&self.state) else {
            return;
        };
        let Some(rec) = self.state.validator_record(index) else {
            return;
        };
        if self.mempool.values().any(|tx| {
            matches!(tx,
            PosTransaction::RandaoRecommit { validator, epoch, .. }
                if *validator == index && *epoch == wall_epoch)
        }) {
            return;
        }
        let tx = if params::epoch_gate_active(wall_epoch, params::WITHDRAWAL_ACTIVATION_EPOCH)
            && rec.withdrawable_epoch != u64::MAX
            && wall_epoch >= rec.withdrawable_epoch
            && rec.staked_sat > 0
        {
            Some(PosTransaction::Withdraw { validator: index })
        } else if params::epoch_gate_active(wall_epoch, params::RANDAO_RECOMMIT_ACTIVATION_EPOCH)
            && !rec.slashed
            // Exit schedules duties to stop later. Renew throughout that
            // delay, matching consensus, or an exhausted exiting key can
            // stop proposing while its stake still carries active weight.
            && rec.exit_epoch > wall_epoch
            && self.state.validator_reveals_used(index) == Some(params::RANDAO_CHAIN_LENGTH)
        {
            let Some(generation) = self.state.validator_randao_generation(index).checked_add(1)
            else {
                return;
            };
            let Some(network) = self.state.admission_network_domain() else {
                return;
            };
            let seed = keys.randao_seed_for(&network, generation);
            let new_commitment = RandaoChain::generate(seed).commitment();
            let signature = keys.sign(&bloch_pos_committee::beacon::recommit_signing_root(
                index,
                wall_epoch,
                &new_commitment,
            ));
            Some(PosTransaction::RandaoRecommit {
                validator: index,
                epoch: wall_epoch,
                new_commitment,
                signature,
            })
        } else {
            None
        };
        if let Some(tx) = tx {
            // Deduplication and all state checks use the ordinary RPC/gossip door.
            if let Err(reason) = self.on_transaction(tx) {
                eprintln!("validator lifecycle action for v{index} deferred: {reason:?}");
            }
        }
    }
}
