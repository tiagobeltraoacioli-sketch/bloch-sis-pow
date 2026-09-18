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

/// Delegates only cryptographic calls that survive consensus' cheap-first
/// lifecycle checks. The budget lives at this seam so random identities that
/// fail lookup do not consume it and valid messages do not clone state twice.
struct LifecycleAdmissionVerifier<'a, V> {
    inner: &'a verification::GossipVerifier<V>,
    mempool: std::cell::RefCell<&'a mut admission::Mempool>,
    source: Option<[u8; 32]>,
    wall_slot: u64,
    limited: std::cell::Cell<bool>,
}

impl<V: SignatureVerifier> SignatureVerifier for LifecycleAdmissionVerifier<'_, V> {
    fn verify_with_key(&self, public_key: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        // Exact immutable failures are already cheap and must not let a replay
        // consume the allowance that exists to bound actual cryptography.
        if self.inner.is_known_failure(public_key, message, signature) {
            return false;
        }
        if let Some(source) = self.source {
            if !self.mempool.borrow_mut().reserve_lifecycle_verification(source, self.wall_slot) {
                self.limited.set(true);
                return false;
            }
        }
        self.inner.verify_with_key(public_key, message, signature)
    }
}

#[cfg(test)]
mod verification_budget_tests {
    use super::*;

    struct Counting(std::rc::Rc<std::cell::Cell<usize>>);
    impl SignatureVerifier for Counting {
        fn verify_with_key(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> bool {
            self.0.set(self.0.get() + 1);
            false
        }
    }

    #[test]
    fn wrapper_stops_before_crypto_and_reopens_on_the_next_slot() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let inner = verification::GossipVerifier::new(Counting(calls.clone()));
        let mut mempool = admission::Mempool::default();
        let source = validator_lifecycle_source(3);
        {
            let verifier = LifecycleAdmissionVerifier {
                inner: &inner, mempool: std::cell::RefCell::new(&mut mempool),
                source: Some(source), wall_slot: 10, limited: std::cell::Cell::new(false),
            };
            assert!(!verifier.verify_with_key(&[], &[0; 32], &[1]));
            // An exact replay hits the failure cache and consumes no budget.
            assert!(!verifier.verify_with_key(&[], &[0; 32], &[1]));
            assert!(!verifier.verify_with_key(&[], &[0; 32], &[2]));
            assert!(!verifier.verify_with_key(&[], &[0; 32], &[3]));
            assert!(verifier.limited.get());
        }
        assert_eq!(calls.get(), LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT);
        let verifier = LifecycleAdmissionVerifier {
            inner: &inner, mempool: std::cell::RefCell::new(&mut mempool),
            source: Some(source), wall_slot: 11, limited: std::cell::Cell::new(false),
        };
        assert!(!verifier.verify_with_key(&[], &[0; 32], &[4]));
        assert_eq!(calls.get(), LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT + 1);
    }
}

impl Engine {
    pub(super) fn validate_lifecycle_admission(&mut self, tx: &PosTransaction) -> Result<(), Refusal> {
        if !is_lifecycle(tx) {
            return Ok(());
        }
        let total = self.state.active_validators().iter()
            .map(|v| u128::from(v.effective_stake)).sum();
        let fee = self.state.next_base_fee();
        let wall_slot = self.wall_slot();
        let source = self.lifecycle_verification_source(tx);
        let verifier = LifecycleAdmissionVerifier {
            inner: &self.gossip_verifier,
            mempool: std::cell::RefCell::new(&mut self.mempool),
            source, wall_slot, limited: std::cell::Cell::new(false),
        };
        let verdict = self.state.validate_lifecycle_transaction(tx, total, fee, &verifier);
        if verifier.limited.get() {
            return Err(Refusal::LifecycleVerificationLimited {
                until_slot: wall_slot.saturating_add(1),
            });
        }
        verdict.map_err(|_| Refusal::Invalid("lifecycle transaction fails committed-state validation"))
    }

    fn lifecycle_verification_source(&self, tx: &PosTransaction) -> Option<[u8; 32]> {
        match tx {
            PosTransaction::FundedDeposit(deposit) =>
                Some(lifecycle_source_hash(b"funding-key", &deposit.funding_pubkey)),
            PosTransaction::ExitV2 { pubkey_hash, .. } => self.state
                .validator_index_by_hash(pubkey_hash).map(validator_lifecycle_source),
            PosTransaction::RandaoRecommit { validator, .. } =>
                Some(validator_lifecycle_source(*validator)),
            PosTransaction::SlashingEvidence(evidence) => {
                let validator = match evidence {
                    SlashingEvidence::AttestationOffence { first, .. } => first.validator,
                    SlashingEvidence::ProposerEquivocation { first, .. } => first.header.proposer_index,
                };
                Some(validator_lifecycle_source(validator))
            }
            PosTransaction::Withdraw { .. } => None,
            _ => None,
        }
    }

    /// Reserve funded inputs against every pending spend and reserve the
    /// joining key against duplicate registrations with different signatures.
    /// Conflicts are refused before capacity eviction or any broadcast.
    pub(super) fn funded_mempool_conflict(&self, tx: &PosTransaction, evicted: &BTreeSet<Vec<u8>>) -> bool {
        let incoming = Self::spent_outpoints(tx).unwrap_or_default();
        self.mempool.iter().any(|(key, other)| {
            if evicted.contains(key) { return false; }
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
        let total = state.active_validators().iter().map(|v| u128::from(v.effective_stake)).sum();
        let fee = state.next_base_fee();
        let included = &self.tx_slot_index;
        self.mempool.retain(|_, tx| {
            // Also covers winning-branch transactions on the reorg path.
            !included.contains_key(&tx.txid())
                && (!is_lifecycle(tx)
                    || state
                        .validate_lifecycle_transaction(tx, total, fee, &ProbeVerifier)
                        .is_ok())
        });
        self.mempool_admitted_at
            .retain(|key, _| self.mempool.contains_key(key));
        self.mempool_suspect
            .retain(|key| self.mempool.contains_key(key));
    }

    fn evidence_admitted_log(offender: u32) -> String {
        format!(
            "slashing evidence against v{offender} admitted and broadcast; the observer earns no \
             protocol reward, and only the proposer of a block that includes the evidence may \
             receive the whistleblower credit"
        )
    }

    pub(super) fn report_equivocation(&mut self, evidence: SlashingEvidence) {
        let offender = match &evidence {
            SlashingEvidence::AttestationOffence { first, .. } => first.validator,
            SlashingEvidence::ProposerEquivocation { first, .. } => first.header.proposer_index,
        };
        crate::metrics::NodeMetrics::inc(&crate::metrics::NODE.equivocations_observed_total);
        match self.on_transaction(PosTransaction::SlashingEvidence(evidence)) {
            Ok(_) => eprintln!("{}", Self::evidence_admitted_log(offender)),
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
        if self.doppelganger_blocks_duties(self.wall_slot)
            || epoch_of(self.state.slot()) != wall_epoch {
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
            && rec.exit_epoch == u64::MAX
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
            let signing_root = bloch_pos_committee::beacon::recommit_signing_root(
                index,
                wall_epoch,
                &new_commitment,
            );
            let signature = match self.slashprot.guard_recommit(
                wall_epoch, generation, new_commitment, signing_root,
                || keys.sign(&signing_root),
            ) {
                Ok(signature) => signature,
                Err(reason) => {
                    eprintln!("validator lifecycle RANDAO signing for v{index} refused: {reason}");
                    return;
                }
            };
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

#[cfg(test)]
mod audit_reward_attribution_tests {
    use super::Engine;

    #[test]
    fn evidence_submission_log_does_not_promise_the_observer_a_reward() {
        let message = Engine::evidence_admitted_log(7);
        assert!(message.contains("v7 admitted and broadcast"));
        assert!(message.contains("observer earns no protocol reward"));
        assert!(message.contains("proposer of a block that includes the evidence"));
    }
}
