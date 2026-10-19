// SPDX-License-Identifier: AGPL-3.0-or-later
//! OFFLINE rehearsal of the consensus evidence path (incident 2026-10-19).
//!
//! Runs the exact gate + `apply_slashing_evidence` the block transition runs
//! for a `PosTransaction::SlashingEvidence`, against a caller-held state, and
//! reports every intermediate verdict. Never used by consensus or by a node;
//! it exists so an operator can judge, against a copy of the committed state,
//! whether a given piece of evidence would be accepted today.

use super::*;
use crate::interfaces::SlashingEvidence;

/// Everything one rehearsal observed. All stake figures are satoshis.
#[derive(Clone, Debug)]
pub struct EvidenceRehearsal {
    pub validator: u32,
    pub state_epoch: u64,
    /// Both consensus guards at the inclusion epoch: the activation gate and
    /// (once armed) the pre-activation offence refusal.
    pub gate_open: bool,
    /// Structural offence (attestation pairs only).
    pub offence: Option<slashing::SlashableOffense>,
    /// Offence's own epoch: max target epoch of the pair, or header-slot epoch.
    pub offence_epoch: u64,
    pub record_present: bool,
    pub already_slashed: bool,
    pub write_off_indeterminate: bool,
    pub sig_first_ok: bool,
    pub sig_second_ok: bool,
    /// Detailed verdict of the slashing state machine (on a scratch copy).
    pub machine_verdict: Result<slashing::SlashableOffense, slashing::EvidenceError>,
    /// The real consensus call: `apply_slashing_evidence` on `self`.
    pub applied: bool,
    pub staked_before: u128,
    pub staked_after: u128,
    pub effective_before: u128,
    pub total_active: u128,
    pub exit_epoch_after: u64,
    pub penalty_bps: u128,
}

impl CommittedState {
    /// Rehearse inclusion of `evidence` in a block at this state's epoch,
    /// MUTATING `self` exactly as the transition would on success (so a
    /// caller can chain rehearsals to measure correlated amplification).
    /// Clone first for an isolated verdict.
    pub fn rehearse_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
        including_proposer: u32,
        verifier: &dyn SignatureVerifier,
    ) -> EvidenceRehearsal {
        let (validator, roots, sigs, offence, offence_epoch) = match evidence {
            SlashingEvidence::AttestationOffence { first, second } => {
                let pair = slashing::SlashingEvidence { first: first.clone(), second: second.clone() };
                (
                    first.validator,
                    [first.data.signing_root(), second.data.signing_root()],
                    [first.signature.clone(), second.signature.clone()],
                    pair.offense().ok(),
                    first.data.target_epoch.max(second.data.target_epoch),
                )
            }
            SlashingEvidence::ProposerEquivocation { first, second } => (
                first.header.proposer_index,
                [first.header.proposal_signing_root(), second.header.proposal_signing_root()],
                [first.proposer_sig.clone(), second.proposer_sig.clone()],
                None,
                first.header.slot / SLOTS_PER_EPOCH,
            ),
        };
        let rec = self.validators.get(&validator).cloned();
        let key = rec.as_ref().map(|r| r.pubkey.clone());
        let sig_ok = |i: usize| key.as_ref().is_some_and(|k| verifier.verify_with_key(k, &roots[i], &sigs[i]));
        let roster = self.consensus_roster_at(self.epoch);
        let total_active: u128 = roster.iter().map(|v| v.effective_stake as u128).sum();
        let effective_before = roster
            .iter()
            .find(|v| v.index == validator)
            .map(|v| v.effective_stake as u128)
            .unwrap_or(0);
        let machine_verdict = {
            let mut scratch = self.slashing.clone();
            let staked = rec.as_ref().map(|r| r.staked_sat).unwrap_or(0);
            match evidence {
                SlashingEvidence::AttestationOffence { first, second } => scratch
                    .process_with_effective_exposure(
                        &slashing::SlashingEvidence { first: first.clone(), second: second.clone() },
                        self.epoch, staked, &[], total_active, effective_before,
                        including_proposer, verifier, &self.validators,
                    ),
                SlashingEvidence::ProposerEquivocation { first, second } => scratch
                    .process_proposer_with_effective_exposure(
                        first, second, self.epoch, staked, &[], total_active, effective_before,
                        including_proposer, verifier, &self.validators,
                    ),
            }
            .map(|o| o.offense)
        };
        // Exactly the transition's two guards, in its order.
        let pre_activation_refused = crate::params::pre_activation_offence_refusal_active(self.epoch)
            && slashing::offence_predates_activation(evidence);
        let gate_open = Self::slashing_evidence_active(self.epoch) && !pre_activation_refused;
        let write_off_indeterminate = self.is_write_off_indeterminate(validator);
        let staked_before = rec.as_ref().map(|r| r.staked_sat).unwrap_or(0);
        let applied = gate_open
            && self
                .apply_slashing_evidence(evidence, including_proposer, &roster, verifier)
                .is_ok();
        let after = self.validators.get(&validator);
        let staked_after = after.map(|r| r.staked_sat).unwrap_or(0);
        let penalty_bps = if applied && staked_before > 0 {
            (staked_before - staked_after) * 10_000 / staked_before
        } else {
            0
        };
        EvidenceRehearsal {
            validator,
            state_epoch: self.epoch,
            gate_open,
            offence,
            offence_epoch,
            record_present: rec.is_some(),
            already_slashed: rec.as_ref().is_some_and(|r| r.slashed),
            write_off_indeterminate,
            sig_first_ok: sig_ok(0),
            sig_second_ok: sig_ok(1),
            machine_verdict,
            applied,
            staked_before,
            staked_after,
            effective_before,
            total_active,
            exit_epoch_after: after.map(|r| r.exit_epoch).unwrap_or(u64::MAX),
            penalty_bps,
        }
    }

    /// Read-only registry view for the rehearsal tool: (index, staked_sat,
    /// slashed, exit_epoch, sha3(pubkey)).
    pub fn rehearsal_registry(&self) -> Vec<(u32, u128, bool, u64, [u8; 32])> {
        use sha3::Digest;
        self.validators
            .values()
            .map(|r| (r.index, r.staked_sat, r.slashed, r.exit_epoch, sha3::Sha3_256::digest(&r.pubkey).into()))
            .collect()
    }

    /// Consensus roster at this state's epoch, as (index, effective_stake).
    pub fn rehearsal_roster(&self) -> Vec<(u32, u64)> {
        self.consensus_roster_at(self.epoch).iter().map(|v| (v.index, v.effective_stake)).collect()
    }

    pub fn rehearsal_epoch(&self) -> u64 {
        self.epoch
    }
}
