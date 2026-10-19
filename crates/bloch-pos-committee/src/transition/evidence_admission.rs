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
    /// The offender's committed key at this state.
    pub pubkey: &'a [u8],
    /// The two `(signing root, signature)` pairs, in submission order.
    pub signed: [([u8; 32], &'a [u8]); 2],
    /// True when the index→key binding the evidence is judged against is
    /// itself finalized here (activation at or below the finalized epoch,
    /// which puts the registering block in finalized history). Only then is
    /// a bad signature a context-free fault: a deposit-added index can map to
    /// different keys on two unfinalized branches.
    pub key_binding_final: bool,
}

/// Context-free structure of an evidence pair: the offender, the anti-replay
/// id and the two signed roots. Identical to the first step of
/// `SlashingState::process` / `process_proposer`, factored without state.
pub fn evidence_structure(
    evidence: &SlashingEvidence,
) -> Result<(u32, [u8; 32], [([u8; 32], &[u8]); 2]), EvidenceError> {
    match evidence {
        SlashingEvidence::AttestationOffence { first, second } => {
            let pair = slashing::SlashingEvidence { first: first.clone(), second: second.clone() };
            pair.offense()?;
            Ok((
                first.validator,
                pair.id(),
                [
                    (first.data.signing_root(), first.signature.as_slice()),
                    (second.data.signing_root(), second.signature.as_slice()),
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
                    (first.header.proposal_signing_root(), first.proposer_sig.as_slice()),
                    (second.header.proposal_signing_root(), second.proposer_sig.as_slice()),
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
        let key_binding_final = rec.activation_epoch <= self.finality_engine.finalized().epoch;
        Ok(EvidencePrecheck {
            offender,
            id,
            pubkey: rec.pubkey.as_slice(),
            signed,
            key_binding_final,
        })
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
        assert!(p.key_binding_final, "genesis keys are bound in finalized history");
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
}
