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

#[cfg(test)]
thread_local! { static NATIVE_SLASHING_FORCED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// Test-only: arm the P5a evidence-admission policy for this thread until
/// the guard drops (also on unwind).
#[cfg(test)]
pub(super) fn native_slashing_open() -> impl Drop {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            NATIVE_SLASHING_FORCED.with(|c| c.set(self.0));
        }
    }
    Restore(NATIVE_SLASHING_FORCED.with(|c| c.replace(true)))
}

/// Is the P5a evidence-admission policy armed at this WALL epoch? Node-local
/// relay policy: no block validity or state root depends on it.
pub(super) fn native_slashing_admission_active(wall_epoch: u64) -> bool {
    #[cfg(test)]
    if NATIVE_SLASHING_FORCED.with(|c| c.get()) {
        return true;
    }
    params::native_slashing_active(wall_epoch)
}

fn evidence_offender(evidence: &SlashingEvidence) -> u32 {
    match evidence {
        SlashingEvidence::AttestationOffence { first, .. } => first.validator,
        SlashingEvidence::ProposerEquivocation { first, .. } => first.header.proposer_index,
    }
}

fn is_lifecycle(tx: &PosTransaction) -> bool {
    matches!(
        tx,
        PosTransaction::FundedDeposit(_)
            | PosTransaction::FundedDelegate(_)
            | PosTransaction::FundedUndelegate(_)
            | PosTransaction::FundedDelegationWithdraw(_)
            | PosTransaction::ValidatorCommissionUpdate(_)
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
            PosTransaction::FundedDelegate(t) => Some(lifecycle_source_hash(b"funding-key", &t.funding_pubkey)),
            PosTransaction::FundedUndelegate(t) => Some(lifecycle_source_hash(b"funding-key", &t.funding_pubkey)),
            PosTransaction::FundedDelegationWithdraw(t) => Some(lifecycle_source_hash(b"funding-key", &t.funding_pubkey)),
            PosTransaction::ValidatorCommissionUpdate(t) => Some(validator_lifecycle_source(t.validator)),
            PosTransaction::ExitV2 { pubkey_hash, .. } => self.state
                .validator_index_by_hash(pubkey_hash).map(validator_lifecycle_source),
            PosTransaction::RandaoRecommit { validator, .. } =>
                Some(validator_lifecycle_source(*validator)),
            // P5a: once armed, `precheck_slashing_evidence` has already
            // charged both verifications to the DELIVERER; charging the
            // accused again would let forgers drain its allowance.
            PosTransaction::SlashingEvidence(_)
                if native_slashing_admission_active(epoch_of(self.wall_slot())) => None,
            PosTransaction::SlashingEvidence(evidence) =>
                Some(validator_lifecycle_source(evidence_offender(evidence))),
            PosTransaction::Withdraw { .. } => None,
            _ => None,
        }
    }

    /// P5a — evidence pre-admission (ObenBlock PoCI ingress port), armed by
    /// `NATIVE_SLASHING_ACTIVATION_EPOCH`. Before any state clone:
    ///
    /// 1. Context-free structure (two signers, no conflict) → `EvidenceFault`.
    /// 2. Chain context (unknown index, applied, already slashed) → state
    ///    dependent; never a peer fault, an honest peer may be on a branch
    ///    where it still applies.
    /// 3. Both signatures, under EXACTLY the consensus key resolution
    ///    (`CommittedState::verify_precheck_signatures`), charged to the
    ///    DELIVERING source's gossip allowance, never to the accused's
    ///    lifecycle allowance. Local observations (`None`) are this node's
    ///    own verified gossip and run unbudgeted, so `report_equivocation`
    ///    cannot be starved. A bad signature is a fault only when the
    ///    index→key binding is identical on every branch (genesis keys); a
    ///    key that does not resolve here is never a fault.
    /// 4. One pending evidence per offender: a re-signed (malleated) copy of
    ///    pending evidence is a different txid but the same offence. This
    ///    O(mempool) scan runs only after the budgeted verification, so
    ///    forged evidence is bounded by the allowance before it can cost a
    ///    scan.
    pub(super) fn precheck_slashing_evidence(
        &self,
        evidence: &SlashingEvidence,
        source: Option<[u8; 32]>,
    ) -> Result<(), Refusal> {
        use bloch_pos_committee::transition::EvidencePrecheckError as E;
        let pre = match self.state.precheck_slashing_evidence(evidence) {
            Ok(pre) => pre,
            Err(E::ContextFree(_)) => {
                return Err(Refusal::EvidenceFault(
                    "slashing evidence is malformed: the two messages do not name one \
                     signer in a double, surround or proposer conflict",
                ))
            }
            Err(E::Context(_)) => {
                return Err(Refusal::StateDependent(
                    "slashing evidence does not apply to this node's committed state \
                     (unknown validator, already applied, or already slashed)",
                ))
            }
        };
        let signed = match source {
            None => self.state.verify_precheck_signatures(&pre, &self.gossip_verifier),
            Some(_) => {
                let wall_slot = self.wall_slot();
                let verifier = self.gossip_verifier.budgeted_for_source(
                    wall_slot,
                    GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT,
                    source,
                    GOSSIP_VERIFICATIONS_PER_SOURCE_PER_SLOT,
                );
                let signed = self.state.verify_precheck_signatures(&pre, &verifier);
                if verifier.limited() {
                    return Err(Refusal::GossipVerificationLimited {
                        until_slot: wall_slot.saturating_add(1),
                    });
                }
                signed
            }
        };
        match signed {
            Some(true) => {}
            None => {
                return Err(Refusal::StateDependent(
                    "slashing evidence names a validator whose key does not resolve \
                     in this node's committed state",
                ))
            }
            Some(false) => {
                return Err(if pre.key_binding_final {
                    Refusal::EvidenceFault("slashing evidence carries a forged signature")
                } else {
                    Refusal::StateDependent(
                        "slashing evidence signature does not verify under this node's \
                         branch-dependent key binding",
                    )
                })
            }
        }
        let offender = pre.offender;
        if self.mempool.values().any(|tx| {
            matches!(tx, PosTransaction::SlashingEvidence(e) if evidence_offender(e) == offender)
        }) {
            return Err(Refusal::StateDependent(
                "slashing evidence against this validator is already pending",
            ));
        }
        Ok(())
    }

    /// Reserve funded inputs against every pending spend and reserve the
    /// joining key against duplicate registrations with different signatures.
    /// Conflicts are refused before capacity eviction or any broadcast.
    pub(super) fn funded_mempool_conflict(&self, tx: &PosTransaction, evicted: &BTreeSet<Vec<u8>>) -> bool {
        let incoming = Self::spent_outpoints(tx).unwrap_or_default();
        self.mempool.iter().any(|(key, other)| {
            if evicted.contains(key) { return false; }
            let funded = matches!(tx, PosTransaction::FundedDeposit(_) | PosTransaction::FundedDelegate(_))
                || matches!(other, PosTransaction::FundedDeposit(_) | PosTransaction::FundedDelegate(_));
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

#[cfg(test)]
mod p5a_evidence_admission_tests {
    use super::*;
    use bloch_pos_committee::{Attestation, AttestationData};

    const GATE_SLOT: u64 = params::SLASHING_EVIDENCE_ACTIVATION_EPOCH * SLOTS_PER_EPOCH + 1;

    fn att(engine: &Engine, v: u32, head: u8, sign: bool) -> Attestation {
        let data = AttestationData {
            // A post-activation offence: the 609070ee node policy refuses any
            // offence committed before SLASHING_EVIDENCE_ACTIVATION_EPOCH in
            // `admissible`, before P5a pre-admission is ever reached.
            slot: GATE_SLOT,
            head: [head; 32],
            source_epoch: 0,
            source_root: [1; 32],
            target_epoch: params::SLASHING_EVIDENCE_ACTIVATION_EPOCH,
            target_root: [head; 32],
        };
        let signature = if sign {
            engine.keys.as_ref().unwrap().sign(&data.signing_root())
        } else {
            let mut s = engine.keys.as_ref().unwrap().sign(&[head; 32]);
            s[7] ^= 1;
            s
        };
        Attestation { data, validator: v, signature }
    }

    fn ev(first: Attestation, second: Attestation) -> SlashingEvidence {
        SlashingEvidence::AttestationOffence { first, second }
    }

    fn src(n: u8) -> Option<[u8; 32]> {
        Some([n; 32])
    }

    #[test]
    fn closed_gate_keeps_the_legacy_refusal_shape() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let _clock = clock_at(GATE_SLOT);
        let malformed = ev(att(&engine, 0, 0xAA, true), att(&engine, 0, 0xAA, true));
        let refusal = engine
            .on_transaction_from(PosTransaction::SlashingEvidence(malformed), src(1))
            .unwrap_err();
        assert!(!matches!(refusal, Refusal::EvidenceFault(_)), "{refusal:?}");
    }

    #[test]
    fn malformed_evidence_is_the_deliverers_fault() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let _gate = native_slashing_open();
        let _clock = clock_at(GATE_SLOT);
        for bad in [
            ev(att(&engine, 0, 0xAA, true), att(&engine, 0, 0xAA, true)),
            ev(att(&engine, 0, 0xAA, true), att(&engine, 1, 0xBB, true)),
        ] {
            assert!(matches!(
                engine.on_transaction_from(PosTransaction::SlashingEvidence(bad), src(1)),
                Err(Refusal::EvidenceFault(_))
            ));
        }
        assert!(engine.mempool.is_empty());
    }

    #[test]
    fn forged_evidence_cannot_drain_the_accused_validators_allowance() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let _gate = native_slashing_open();
        let _clock = clock_at(GATE_SLOT);
        for n in 0..16u8 {
            let mut forged = ev(att(&engine, 0, 0xAA, false), att(&engine, 0, 0xBB, false));
            if let SlashingEvidence::AttestationOffence { first, .. } = &mut forged {
                first.signature[11] ^= n;
            }
            assert!(matches!(
                engine.on_transaction_from(PosTransaction::SlashingEvidence(forged), src(n)),
                Err(Refusal::EvidenceFault(_))
            ));
        }
        // Validator 0's own lifecycle allowance for this slot is intact.
        let accused = validator_lifecycle_source(0);
        for _ in 0..LIFECYCLE_VERIFICATIONS_PER_SOURCE_PER_SLOT {
            assert!(engine.mempool.reserve_lifecycle_verification(accused, GATE_SLOT));
        }
    }

    #[test]
    fn genuine_evidence_passes_and_unknown_or_pending_is_context_only() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let _gate = native_slashing_open();
        let _clock = clock_at(GATE_SLOT);
        let genuine = ev(att(&engine, 0, 0xAA, true), att(&engine, 0, 0xBB, true));
        engine.precheck_slashing_evidence(&genuine, src(1)).unwrap();
        engine.precheck_slashing_evidence(&genuine, None).unwrap();
        // An index this chain never registered: context, never a fault.
        let unknown = ev(att(&engine, 9, 0xAA, true), att(&engine, 9, 0xBB, true));
        assert!(matches!(
            engine.precheck_slashing_evidence(&unknown, src(1)),
            Err(Refusal::StateDependent(_))
        ));
        // One pending evidence per offender: a second pair (or a re-signed
        // copy) is refused once its signatures are judged.
        let tx = PosTransaction::SlashingEvidence(genuine);
        engine.mempool.insert(tx.canonical_bytes(), tx);
        let other = ev(att(&engine, 0, 0xCC, true), att(&engine, 0, 0xDD, true));
        assert!(matches!(
            engine.precheck_slashing_evidence(&other, src(2)),
            Err(Refusal::StateDependent(_))
        ));
    }

    /// HF2 review F-10: the O(mempool) pending-offender scan runs only after
    /// the budgeted verification, so forged evidence against an offender with
    /// pending evidence is still charged to (and judged against) the
    /// deliverer's allowance, and is refused as the fault it is.
    #[test]
    fn verification_budget_runs_before_the_pending_scan() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let _gate = native_slashing_open();
        let _clock = clock_at(GATE_SLOT);
        let genuine = ev(att(&engine, 0, 0xAA, true), att(&engine, 0, 0xBB, true));
        let tx = PosTransaction::SlashingEvidence(genuine);
        engine.mempool.insert(tx.canonical_bytes(), tx);
        let before = engine.gossip_verifier.budget_used_at(GATE_SLOT);
        let forged = ev(att(&engine, 0, 0xCC, false), att(&engine, 0, 0xDD, false));
        assert!(matches!(
            engine.precheck_slashing_evidence(&forged, src(3)),
            Err(Refusal::EvidenceFault(_))
        ));
        assert!(
            engine.gossip_verifier.budget_used_at(GATE_SLOT) > before,
            "the deliverer's allowance is charged before any mempool scan"
        );
    }
}
