// SPDX-License-Identifier: AGPL-3.0-or-later
//! P5a — clone-free evidence pre-admission (ObenBlock PoCI ingress port).
//!
//! Read-only. Nothing here mutates state or is consulted by
//! `compute_post_state`; block validity stays with `apply_slashing_evidence`.
//! The node uses these answers, behind
//! [`crate::params::NATIVE_SLASHING_ACTIVATION_EPOCH`], to (a) refuse garbage
//! evidence before it clones state or spends a hybrid verification, (b) tell a
//! peer's provable fault (penalise the deliverer) from a disagreement about
//! chain context (ignore), and (c) charge the two verifications to whoever
//! delivered the evidence instead of to the accused validator.

use super::*;
use crate::slashing::EvidenceError;

/// Why pre-admission refused evidence, split by who is at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidencePrecheckError {
    /// The bytes alone prove the evidence wrong, on every honest node and
    /// every branch: two signers, no conflict, identical messages. A peer
    /// that relays this is misbehaving.
    ContextFree(EvidenceError),
    /// The verdict depends on this node's chain (unknown index, already
    /// slashed, already applied, indeterminate write-off). An honest peer on
    /// another branch may disagree; never a peer fault.
    Context(EvidenceError),
}

/// Everything signature verification needs, resolved without a clone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidencePrecheck<'a> {
    pub offender: u32,
    /// Anti-replay identity — the same value consensus inserts in `applied`.
    pub id: [u8; 32],
    /// The two `(message epoch, signing root, signature)` triples, in
    /// submission order. The message epoch (vote target epoch, header slot
    /// epoch) is what consensus resolves the verification key for; there is
    /// deliberately no key here — verify with
    /// [`CommittedState::verify_precheck_signatures`], which uses the
    /// consensus rule [`slashing::verify_offender_signature`].
    pub signed: [SignedMessage<'a>; 2],
    /// True only when the index→key binding is the same on EVERY branch any
    /// honest peer can be on: a genesis validator (activation epoch 0). Only
    /// then is a bad signature a context-free fault of the deliverer. Local
    /// finality is not enough: during a chain split each side can carry its
    /// own finality, and a deposit- or funding-added index can map to
    /// different keys on the two sides, so an honest relay from the other
    /// side must not be penalised.
    pub key_binding_final: bool,
}

/// One signed message of an evidence pair.
pub type SignedMessage<'a> = (u64, [u8; 32], &'a [u8]);

/// Context-free structure of an evidence pair: the offender, the anti-replay
/// id and the two signed roots. Identical to the first step of
/// `SlashingState::process` / `process_proposer`, factored without state.
pub fn evidence_structure(
    evidence: &SlashingEvidence,
) -> Result<(u32, [u8; 32], [SignedMessage<'_>; 2]), EvidenceError> {
    match evidence {
        SlashingEvidence::AttestationOffence { first, second } => {
            let pair = slashing::SlashingEvidence { first: first.clone(), second: second.clone() };
            pair.offense()?;
            Ok((
                first.validator,
                pair.id(),
                [
                    (crate::epoch_of(first.data.slot), first.data.signing_root(), first.signature.as_slice()),
                    (crate::epoch_of(second.data.slot), second.data.signing_root(), second.signature.as_slice()),
                ],
            ))
        }
        SlashingEvidence::ProposerEquivocation { first, second } => {
            if first.header.proposer_index != second.header.proposer_index {
                return Err(EvidenceError::DifferentValidators);
            }
            if first.header.slot != second.header.slot
                || crate::header::BlockId::of(&first.header) == crate::header::BlockId::of(&second.header)
            {
                return Err(EvidenceError::NotConflicting);
            }
            let validator = first.header.proposer_index;
            Ok((
                validator,
                slashing::proposer_evidence_id(validator, &first.header, &second.header),
                [
                    (
                        crate::epoch_of(first.header.slot),
                        first.header.proposal_signing_root(),
                        first.proposer_sig.as_slice(),
                    ),
                    (
                        crate::epoch_of(second.header.slot),
                        second.header.proposal_signing_root(),
                        second.proposer_sig.as_slice(),
                    ),
                ],
            ))
        }
    }
}

impl CommittedState {
    /// Clone-free, signature-free pre-admission of slashing evidence.
    ///
    /// Same refusals, in the same cheapest-first order, as the transition's
    /// own path up to (not including) signature verification. A pass here is
    /// NOT validity: the caller still runs the full transition check.
    pub fn precheck_slashing_evidence<'a>(
        &'a self,
        evidence: &'a SlashingEvidence,
    ) -> Result<EvidencePrecheck<'a>, EvidencePrecheckError> {
        use EvidencePrecheckError::{Context, ContextFree};
        let (offender, id, signed) = evidence_structure(evidence).map_err(ContextFree)?;
        let Some(rec) = self.validators.get(&offender) else {
            return Err(Context(EvidenceError::UnknownValidator));
        };
        if self.slashing.is_applied(&id) {
            return Err(Context(EvidenceError::AlreadyApplied));
        }
        if rec.slashed || self.slashing.is_ejected(offender) {
            return Err(Context(EvidenceError::AlreadySlashed));
        }
        if self.is_write_off_indeterminate(offender) {
            return Err(Context(EvidenceError::AlreadySlashed));
        }
        let key_binding_final = rec.activation_epoch == 0;
        Ok(EvidencePrecheck { offender, id, signed, key_binding_final })
    }

    /// Verify both signatures of pre-admitted evidence with EXACTLY the key
    /// resolution consensus applies ([`slashing::verify_offender_signature`]
    /// against this state's registry), cheapest-first and short-circuiting
    /// like `SlashingState::process`. `None` = no key resolves here for the
    /// offender (never a peer fault); `Some(false)` = a signature fails.
    pub fn verify_precheck_signatures(
        &self,
        pre: &EvidencePrecheck<'_>,
        verifier: &dyn crate::attestation::SignatureVerifier,
    ) -> Option<bool> {
        for (epoch, root, sig) in pre.signed.iter() {
            if !slashing::verify_offender_signature(
                &self.validators,
                verifier,
                pre.offender,
                *epoch,
                root,
                sig,
            )? {
                return Some(false);
            }
        }
        Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::setup;
    use super::*;
    use crate::attestation::AttestationData;

    fn att(v: u32, target_epoch: u64, source_epoch: u64, head: u8) -> Attestation {
        Attestation {
            data: AttestationData {
                slot: target_epoch * SLOTS_PER_EPOCH,
                head: [head; 32],
                source_epoch,
                source_root: [1; 32],
                target_epoch,
                target_root: [head; 32],
            },
            validator: v,
            signature: vec![head; 8],
        }
    }

    fn pair(first: Attestation, second: Attestation) -> SlashingEvidence {
        SlashingEvidence::AttestationOffence { first, second }
    }

    #[test]
    fn malformed_evidence_is_a_context_free_fault() {
        let (_, g, _) = setup(4);
        for (ev, why) in [
            (pair(att(1, 1, 0, 0xAA), att(2, 1, 0, 0xBB)), EvidenceError::DifferentValidators),
            (pair(att(1, 1, 0, 0xAA), att(1, 1, 0, 0xAA)), EvidenceError::NotConflicting),
            (pair(att(1, 1, 0, 0xAA), att(1, 2, 1, 0xBB)), EvidenceError::NotConflicting),
        ] {
            assert_eq!(
                g.precheck_slashing_evidence(&ev).unwrap_err(),
                EvidencePrecheckError::ContextFree(why)
            );
        }
    }

    #[test]
    fn unknown_offender_is_context_not_fault() {
        let (_, g, _) = setup(4);
        let ev = pair(att(77, 1, 0, 0xAA), att(77, 1, 0, 0xBB));
        assert_eq!(
            g.precheck_slashing_evidence(&ev).unwrap_err(),
            EvidencePrecheckError::Context(EvidenceError::UnknownValidator)
        );
    }

    #[test]
    fn double_and_surround_pass_with_the_consensus_id_and_a_final_genesis_binding() {
        let (_, g, _) = setup(4);
        let double = pair(att(1, 1, 0, 0xAA), att(1, 1, 0, 0xBB));
        let p = g.precheck_slashing_evidence(&double).unwrap();
        assert_eq!(p.offender, 1);
        assert!(p.key_binding_final, "genesis keys are bound identically on every branch");
        let SlashingEvidence::AttestationOffence { first, second } = double.clone() else { unreachable!() };
        assert_eq!(p.id, slashing::SlashingEvidence { first, second }.id());
        // Surround: (0 -> 5) strictly surrounds (1 -> 4).
        let surround = pair(att(2, 5, 0, 0xAA), att(2, 4, 1, 0xBB));
        assert!(g.precheck_slashing_evidence(&surround).is_ok());
    }

    #[test]
    fn applied_and_slashed_offenders_are_refused_without_a_clone_or_a_signature() {
        let (_, mut g, _) = setup(4);
        let ev = pair(att(1, 1, 0, 0xAA), att(1, 1, 0, 0xBB));
        let roster = g.consensus_roster_at(g.epoch);
        // The slashing gate is consensus's question, not this one's: apply
        // directly, as the transition's own unit tests do.
        g.apply_slashing_evidence(&ev, 0, &roster, &super::super::tests::OkVerifier).unwrap();
        assert_eq!(
            g.precheck_slashing_evidence(&ev).unwrap_err(),
            EvidencePrecheckError::Context(EvidenceError::AlreadyApplied)
        );
        // Swapped order shares the id.
        let SlashingEvidence::AttestationOffence { first, second } = ev else { unreachable!() };
        let swapped = pair(second, first);
        assert_eq!(
            g.precheck_slashing_evidence(&swapped).unwrap_err(),
            EvidencePrecheckError::Context(EvidenceError::AlreadyApplied)
        );
        // A fresh pair against the same, already-slashed validator.
        let fresh = pair(att(1, 3, 0, 0xCC), att(1, 3, 0, 0xDD));
        assert_eq!(
            g.precheck_slashing_evidence(&fresh).unwrap_err(),
            EvidencePrecheckError::Context(EvidenceError::AlreadySlashed)
        );
    }

    /// Records every `(key, root, signature)` it is asked to verify and
    /// answers from a fixed script.
    struct Recording {
        calls: std::cell::RefCell<Vec<(Vec<u8>, [u8; 32], Vec<u8>)>>,
        answer: bool,
    }
    impl crate::attestation::SignatureVerifier for Recording {
        fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            self.calls.borrow_mut().push((pk.to_vec(), *root, sig.to_vec()));
            self.answer
        }
    }

    /// HF2 review F-3: pre-admission must judge signatures with the very key
    /// resolution consensus uses, never a separately chosen key, so the relay
    /// can never refuse evidence consensus would slash (for example once keys
    /// become per-epoch). Pinned by recording both paths' verifier calls.
    #[test]
    fn precheck_verifies_under_exactly_the_consensus_key_resolution() {
        let (_, g, _) = setup(4);
        for answer in [true, false] {
            let ev = pair(att(1, 3, 0, 0xAA), att(1, 3, 0, 0xBB));
            let node = Recording { calls: Default::default(), answer };
            let pre = g.precheck_slashing_evidence(&ev).unwrap();
            assert_eq!(g.verify_precheck_signatures(&pre, &node), Some(answer));
            let consensus = Recording { calls: Default::default(), answer };
            let SlashingEvidence::AttestationOffence { first, second } = ev.clone() else {
                unreachable!()
            };
            let dels: [crate::delegation::Delegation; 0] = [];
            let outcome = slashing::SlashingState::new().process(
                &slashing::SlashingEvidence { first, second },
                3,
                0,
                &dels,
                1_000_000,
                0,
                &consensus,
                &g.validators,
            );
            assert_eq!(outcome.is_ok(), answer);
            assert_eq!(*node.calls.borrow(), *consensus.calls.borrow(), "answer={answer}");
            assert_eq!(node.calls.borrow().len(), if answer { 2 } else { 1 });
        }
    }

    /// HF2 review F-6: only a binding shared by every branch (genesis keys)
    /// makes a bad signature the deliverer's provable fault. A validator added
    /// after genesis can map to different keys on two sides of a split, even
    /// when each side has finalized its own registration.
    #[test]
    fn post_genesis_binding_is_never_a_context_free_signature_fault() {
        let (_, mut g, _) = setup(4);
        g.validators.get_mut(&1).unwrap().activation_epoch = 1;
        let ev = pair(att(1, 3, 0, 0xAA), att(1, 3, 0, 0xBB));
        assert!(!g.precheck_slashing_evidence(&ev).unwrap().key_binding_final);
        let genesis = pair(att(2, 3, 0, 0xAA), att(2, 3, 0, 0xBB));
        assert!(g.precheck_slashing_evidence(&genesis).unwrap().key_binding_final);
    }

    /// A key that does not resolve here yields `None` (context), never a
    /// signature verdict.
    #[test]
    fn unresolvable_key_is_no_verdict() {
        let (_, mut g, _) = setup(4);
        let ev = pair(att(1, 3, 0, 0xAA), att(1, 3, 0, 0xBB));
        let pre = g.precheck_slashing_evidence(&ev).unwrap();
        let pre = EvidencePrecheck {
            offender: pre.offender,
            id: pre.id,
            signed: [
                (pre.signed[0].0, pre.signed[0].1, &[][..]),
                (pre.signed[1].0, pre.signed[1].1, &[][..]),
            ],
            key_binding_final: pre.key_binding_final,
        };
        g.validators.remove(&1);
        let v = Recording { calls: Default::default(), answer: true };
        assert_eq!(g.verify_precheck_signatures(&pre, &v), None);
        assert!(v.calls.borrow().is_empty());
    }
}
