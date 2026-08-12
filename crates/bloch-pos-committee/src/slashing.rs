// SPDX-License-Identifier: AGPL-3.0-or-later

//! Slashing execution — the state machine behind §7.3.
//!
//! [`crate::attestation`] supplies *detection* (`surrounds`, `is_double_vote`)
//! and [`crate::delegation::apply_slash`] supplies the pro-rata *arithmetic*.
//! What neither supplies — and what this module adds — is the evidence
//! transaction and the state it mutates: verifying that two signed messages
//! really are one validator equivocating, pricing the offence, paying the
//! whistleblower, ejecting the validator, and refusing to do any of it twice.
//!
//! ## Correlated amplification is the load-bearing part
//!
//! A flat 5% penalty prices *accidents* correctly and *attacks* absurdly
//! cheaply. Reverting finality requires ≥ 1/3 of stake to equivocate; under a
//! flat penalty that attack costs the attacker 5% of a third of stake — a fee,
//! not a deterrent. So the penalty scales with how much stake was slashed in
//! the same window (Ethereum's proportional-slashing device): each offence
//! pays `base + 3 × (slashed_in_window / total_active)`, capped at 100%. The
//! multiplier is 3 because 1/3 is the finality-attack threshold — when a
//! third of stake equivocates together, the amplified term alone reaches
//! 100% and the attack costs the entire attacking stake. An unlucky solo
//! operator, alone in its window, still pays ≈ 5%.
//!
//! This is forward-looking: the Nth offender of a coordinated batch pays more
//! than the first, so the *marginal* price of adding one more validator to an
//! attack rises monotonically. Ethereum additionally reprices the early
//! offenders retroactively at withdrawal time; that needs deferred penalty
//! application, which belongs to the withdrawal path, not here. The honest
//! consequence: the first offenders of a batch are under-punished relative to
//! the retroactive scheme, but no ordering of the batch makes the batch cheap.
//!
//! ## Determinism (§5.5)
//!
//! [`SlashingState`] is consensus state: it must be derived from the chain
//! (evidence transactions in blocks), never from anything node-local. All
//! collections are B-trees so iteration and any future serialization are
//! canonical, and nothing here reads a clock — the epoch is an argument.

use crate::attestation::{Attestation, SignatureVerifier};
use crate::delegation::{apply_slash, Delegation};
use crate::interfaces::ProposalEnvelope;
use crate::params::DS_SLASH;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

/// Base penalty for equivocation, in basis points. Appendix A
/// (`SLASH_PROPOSER_EQUIV`): 5% + ejection. Two offences price off this one
/// constant because both *are* equivocation — a proposer signing two headers
/// for one slot, and an attester signing two votes for one target epoch — and
/// the spec assigns them the same row.
pub const SLASH_PROPOSER_EQUIV_BPS: u128 = 500;

/// Base penalty for a surround vote, in basis points. Appendix A: 5% +
/// ejection. Equal to the double-vote penalty today, but kept as a separate
/// constant because the two offences are distinct in the spec and a future
/// repricing of one must not silently reprice the other.
pub const SLASH_SURROUND_VOTE_BPS: u128 = 500;

/// The whistleblower (the proposer including the evidence) receives
/// `total_penalty / 32`. 1/32 per §7.3: large enough that including evidence
/// always beats ignoring it, small enough that slashing is a burn, not a
/// bounty market.
pub const WHISTLEBLOWER_QUOTIENT: u128 = 32;

/// Amplification multiplier: penalty grows by `3 × slashed_share` of the
/// stake. 3 because 1/3 of stake is what it takes to break a 2/3 finality
/// quorum — at exactly that much correlated equivocation the penalty reaches
/// 100%, so a finality attack forfeits the whole attacking stake.
pub const CORRELATION_MULTIPLIER: u128 = 3;

/// How long a slash keeps amplifying later slashes, in epochs.
///
/// Must be at least `WITHDRAWAL_DELAY_EPOCHS` (2,048, §7.2): a coordinated
/// attacker spreads its equivocations over time to look like unrelated
/// accidents, and the window only defeats that if every co-conspirator is
/// still bonded — hence still slashable at the amplified rate — when the
/// correlation becomes visible. Twice the withdrawal delay, next power of two.
pub const CORRELATION_WINDOW_EPOCHS: u64 = 4_096;

/// Which slashable offence the evidence proves. The offences are mutually
/// exclusive per evidence: a double vote requires equal target epochs, a
/// surround requires strictly nested (hence unequal) ones, and a proposer
/// equivocation is a pair of headers, not attestations. Mirrors the closed
/// [`crate::interfaces::Offence`] enum — an offence class is a consensus
/// rule, and adding one post-genesis is a hard fork, not an enum extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashableOffense {
    /// Two distinct signed headers for the same slot by the same proposer.
    /// This is exactly what [`crate::produce::ProducerRandao`]'s single-use
    /// reveal fence exists to make impossible by accident: the honest path to
    /// it is "call produce twice for one slot", and produce refuses.
    ProposerEquivocation,
    /// Two different attestations for the same target epoch.
    DoubleVote,
    /// One attestation's checkpoint span strictly surrounds the other's.
    SurroundVote,
}

impl SlashableOffense {
    /// Base penalty for this offence, before correlation amplification.
    pub const fn base_penalty_bps(self) -> u128 {
        match self {
            // Both are equivocation; the spec prices them on one row.
            SlashableOffense::ProposerEquivocation => SLASH_PROPOSER_EQUIV_BPS,
            SlashableOffense::DoubleVote => SLASH_PROPOSER_EQUIV_BPS,
            SlashableOffense::SurroundVote => SLASH_SURROUND_VOTE_BPS,
        }
    }
}

/// Why evidence was rejected. Distinct variants for the same reason
/// [`crate::attestation::RejectReason`] has them: "invalid" alone makes a
/// divergence between nodes impossible to debug from logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// The two messages are signed by different validators. Two validators
    /// disagreeing is consensus working, not an offence.
    DifferentValidators,
    /// The messages do not conflict — identical data, or merely different
    /// epochs with no double vote and no surround.
    NotConflicting,
    /// This evidence (or its swapped-order twin) was already applied.
    AlreadyApplied,
    /// The validator was already slashed and ejected; its stake was burned
    /// then, so there is nothing left to punish.
    AlreadySlashed,
    /// A signature failed verification — forged or corrupted evidence.
    BadSignature,
}

/// Two conflicting signed attestations from one validator — the attestation
/// half of the §7.3 evidence payload. The wire/transaction shape that carries
/// either this pair or a header pair is [`crate::interfaces::SlashingEvidence`];
/// the [`From`] impl below is the one conversion between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub first: Attestation,
    pub second: Attestation,
}

impl From<SlashingEvidence> for crate::interfaces::SlashingEvidence {
    fn from(ev: SlashingEvidence) -> Self {
        crate::interfaces::SlashingEvidence::AttestationOffence {
            first: ev.first,
            second: ev.second,
        }
    }
}

impl SlashingEvidence {
    /// Structural check: same signer, genuinely conflicting data.
    ///
    /// Deliberately does **not** touch signatures — this is the cheap gate.
    /// Note the identical-data case falls out of the predicates themselves:
    /// `is_double_vote` requires `self != other`, and nothing surrounds
    /// itself, so re-broadcasting one honest attestation twice can never be
    /// made to look like equivocation.
    pub fn offense(&self) -> Result<SlashableOffense, EvidenceError> {
        if self.first.validator != self.second.validator {
            return Err(EvidenceError::DifferentValidators);
        }
        let (a, b) = (&self.first.data, &self.second.data);
        if a.is_double_vote(b) {
            Ok(SlashableOffense::DoubleVote)
        } else if a.surrounds(b) || b.surrounds(a) {
            // Surround is checked both ways: the offence is the *pair*, and
            // which message the submitter listed first is not meaningful.
            Ok(SlashableOffense::SurroundVote)
        } else {
            Err(EvidenceError::NotConflicting)
        }
    }

    /// Canonical anti-replay identity of this evidence.
    ///
    /// Two deliberate choices:
    ///
    /// - **Order-independent.** The two signing roots are sorted before
    ///   hashing, so `(m1, m2)` and `(m2, m1)` share one identity — otherwise
    ///   every evidence could be replayed once for free by swapping the pair.
    /// - **Signatures excluded.** The identity covers what was signed, not
    ///   the signature bytes. Consensus must not assume the hybrid suite is
    ///   non-malleable; if a re-encoded signature changed the identity, one
    ///   offence could be "fresh evidence" arbitrarily many times.
    pub fn id(&self) -> [u8; 32] {
        let r1 = self.first.data.signing_root();
        let r2 = self.second.data.signing_root();
        let (lo, hi) = if r1 <= r2 { (r1, r2) } else { (r2, r1) };
        let mut h = Sha3_256::new();
        h.update(DS_SLASH);
        h.update(self.first.validator.to_le_bytes());
        h.update(lo);
        h.update(hi);
        h.finalize().into()
    }
}

/// Everything one applied slash produced. Balances live outside this crate,
/// so the outcome reports amounts and leaves crediting/debiting to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingOutcome {
    pub offense: SlashableOffense,
    /// Effective penalty after correlation amplification, in basis points.
    pub penalty_bps: u128,
    /// Loss per delegation, aligned with the `delegations` slice passed in —
    /// pro-rata via [`apply_slash`], because delegators sharing the downside
    /// is what makes delegation a security signal (delegation.rs rule 3).
    pub delegation_losses_sat: Vec<u128>,
    /// Sum of all losses — the amount burned plus the whistleblower cut.
    pub total_slashed_sat: u128,
    /// `total / 32`, owed to `including_proposer`. A validator reporting its
    /// own offence just nets 31/32 of the penalty — still a penalty — so
    /// self-reporting needs no special case.
    pub whistleblower_reward_sat: u128,
    /// The proposer that included the evidence, echoed back so the caller
    /// credits the right account.
    pub including_proposer: u32,
}

/// The slashing state machine: what has been applied, who is ejected, and how
/// much stake was slashed in each recent epoch (the amplification input).
/// `PartialEq` because this is a component of the transition's committed
/// state, and committed states are compared whole in the determinism tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlashingState {
    /// Identities of applied evidence. Successful applications only — failed
    /// evidence is not recorded, so a forged submission cannot squat an id
    /// and block the real evidence later.
    applied: BTreeSet<[u8; 32]>,
    /// Validators slashed and ejected. Ejection is permanent for the key:
    /// the operator can only return with a fresh deposit as a new record.
    ejected: BTreeSet<u32>,
    /// Slashed stake per epoch, pruned past the correlation window.
    window: BTreeMap<u64, u128>,
}

impl SlashingState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Has this validator already been slashed and ejected?
    pub fn is_ejected(&self, validator: u32) -> bool {
        self.ejected.contains(&validator)
    }

    /// Total stake slashed within the correlation window ending at `epoch`.
    pub fn slashed_in_window(&self, epoch: u64) -> u128 {
        let floor = epoch.saturating_sub(CORRELATION_WINDOW_EPOCHS - 1);
        self.window.range(floor..=epoch).map(|(_, s)| *s).sum()
    }

    /// Effective penalty for an offence judged at `epoch`, given the total
    /// active stake. `base + 3 × slashed_share`, capped at 100%.
    ///
    /// Computed from the window *before* the current offence is recorded:
    /// each offender is priced by how much correlated damage was already
    /// visible, which is what makes the marginal cost of a coordinated batch
    /// increase with every member added.
    pub fn penalty_bps(&self, base_bps: u128, epoch: u64, total_active_sat: u128) -> u128 {
        if total_active_sat == 0 {
            // No stake to measure correlation against; only the base applies.
            return base_bps.min(10_000);
        }
        let amplification =
            CORRELATION_MULTIPLIER * 10_000 * self.slashed_in_window(epoch) / total_active_sat;
        (base_bps + amplification).min(10_000)
    }

    /// Verify and apply one evidence transaction. This is the whole §7.3
    /// pipeline; on any error the state is untouched.
    ///
    /// Check order is cheapest-first, for the same DoS reason
    /// `attestation::validate` checks membership before signatures: the two
    /// hybrid signatures cost far more to verify than every structural check
    /// combined, so garbage must die before reaching them. Replay is checked
    /// before ejection so a resubmitted evidence is reported as the replay it
    /// is, not as a fresh offence against an ejected validator.
    pub fn process(
        &mut self,
        evidence: &SlashingEvidence,
        epoch: u64,
        delegations: &[Delegation],
        total_active_sat: u128,
        including_proposer: u32,
        verifier: &dyn SignatureVerifier,
    ) -> Result<SlashingOutcome, EvidenceError> {
        // 1. Structure: one signer, real conflict.
        let offense = evidence.offense()?;

        // 2. Anti-replay: the same pair (in either order) applies once, ever.
        let id = evidence.id();
        if self.applied.contains(&id) {
            return Err(EvidenceError::AlreadyApplied);
        }

        // 3. Ejection: a slashed validator's stake was already burned; a
        //    second evidence against it proves nothing new and must not
        //    touch delegators (or the window) again.
        let validator = evidence.first.validator;
        if self.ejected.contains(&validator) {
            return Err(EvidenceError::AlreadySlashed);
        }

        // 4. Signatures, last. Both messages, both verified under the same
        //    validator key — evidence is only evidence if the validator
        //    really signed both sides of the conflict.
        for att in [&evidence.first, &evidence.second] {
            if !verifier.verify(att.validator, &att.data.signing_root(), &att.signature) {
                return Err(EvidenceError::BadSignature);
            }
        }

        Ok(self.commit_offense(
            id,
            validator,
            offense,
            epoch,
            delegations,
            total_active_sat,
            including_proposer,
        ))
    }

    /// Verify and apply one proposer-equivocation evidence transaction: two
    /// distinct signed headers for the same slot by the same proposer. Same
    /// pipeline shape and error order as [`Self::process`]; the two share
    /// [`Self::commit_offense`] so the penalty arithmetic, replay set,
    /// ejection set and correlation window have exactly one definition.
    ///
    /// Deliberately does **not** check that the proposer was the slot's
    /// scheduled proposer. Signing two conflicting headers for one slot is
    /// provably hostile whether or not the schedule drew you — and checking
    /// the schedule would need the seed of an arbitrarily old epoch, which
    /// committed state does not retain (the 2-epoch mix window, §5.5).
    ///
    /// The identical-header case falls out structurally: one header equals
    /// itself, so `BlockId::of` matches and the pair is `NotConflicting` —
    /// re-gossiping your own block can never be made to look like
    /// equivocation, the same property `offense()` gives attestations.
    #[allow(clippy::too_many_arguments)]
    pub fn process_proposer(
        &mut self,
        first: &ProposalEnvelope,
        second: &ProposalEnvelope,
        epoch: u64,
        delegations: &[Delegation],
        total_active_sat: u128,
        including_proposer: u32,
        verifier: &dyn SignatureVerifier,
    ) -> Result<SlashingOutcome, EvidenceError> {
        // 1. Structure: one signer, one slot, two different blocks.
        if first.header.proposer_index != second.header.proposer_index {
            return Err(EvidenceError::DifferentValidators);
        }
        if first.header.slot != second.header.slot
            || crate::header::BlockId::of(&first.header) == crate::header::BlockId::of(&second.header)
        {
            return Err(EvidenceError::NotConflicting);
        }

        // 2. Anti-replay. Same construction as the attestation id: sorted
        //    signing roots, signatures excluded. The proposal signing root is
        //    under DS_PROPOSE while attestation roots are under DS_ATTEST, so
        //    a header-pair id can never collide with an attestation-pair id
        //    even though both live in one `applied` set.
        let r1 = first.header.proposal_signing_root();
        let r2 = second.header.proposal_signing_root();
        let (lo, hi) = if r1 <= r2 { (r1, r2) } else { (r2, r1) };
        let validator = first.header.proposer_index;
        let mut h = Sha3_256::new();
        h.update(DS_SLASH);
        h.update(validator.to_le_bytes());
        h.update(lo);
        h.update(hi);
        let id: [u8; 32] = h.finalize().into();
        if self.applied.contains(&id) {
            return Err(EvidenceError::AlreadyApplied);
        }

        // 3. Ejection: same rationale as `process` step 3.
        if self.ejected.contains(&validator) {
            return Err(EvidenceError::AlreadySlashed);
        }

        // 4. Signatures, last — the proposer really signed both headers.
        for env in [first, second] {
            if !verifier.verify(
                validator,
                &env.header.proposal_signing_root(),
                &env.proposer_sig,
            ) {
                return Err(EvidenceError::BadSignature);
            }
        }

        Ok(self.commit_offense(
            id,
            validator,
            SlashableOffense::ProposerEquivocation,
            epoch,
            delegations,
            total_active_sat,
            including_proposer,
        ))
    }

    /// Steps 5–7 of the pipeline, shared by both evidence forms: price the
    /// offence, burn pro-rata, and commit. Private, infallible, and only
    /// reachable after every check has passed — the checks stay with the
    /// evidence forms because they differ, the consequences live here because
    /// they must not.
    #[allow(clippy::too_many_arguments)]
    fn commit_offense(
        &mut self,
        id: [u8; 32],
        validator: u32,
        offense: SlashableOffense,
        epoch: u64,
        delegations: &[Delegation],
        total_active_sat: u128,
        including_proposer: u32,
    ) -> SlashingOutcome {
        // 5. Price the offence from the window as it stood before this slash.
        let penalty_bps = self.penalty_bps(offense.base_penalty_bps(), epoch, total_active_sat);

        // 6. Burn pro-rata across the operator's delegators.
        let delegation_losses_sat = apply_slash(delegations, validator, penalty_bps);
        let total_slashed_sat: u128 = delegation_losses_sat.iter().sum();
        let whistleblower_reward_sat = total_slashed_sat / WHISTLEBLOWER_QUOTIENT;

        // 7. Commit: mark the evidence spent, eject the validator, feed the
        //    window so the *next* correlated offence costs more, and prune
        //    entries the window can no longer see (bounded state).
        self.applied.insert(id);
        self.ejected.insert(validator);
        *self.window.entry(epoch).or_insert(0) += total_slashed_sat;
        let floor = epoch.saturating_sub(CORRELATION_WINDOW_EPOCHS - 1);
        self.window.retain(|e, _| *e >= floor);

        SlashingOutcome {
            offense,
            penalty_bps,
            delegation_losses_sat,
            total_slashed_sat,
            whistleblower_reward_sat,
            including_proposer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationData;

    /// A signature is "valid" iff it equals the signing root — enough to make
    /// forgery (any other bytes) detectable per-message in tests.
    struct RootEchoVerifier;
    impl SignatureVerifier for RootEchoVerifier {
        fn verify(&self, _v: u32, signing_root: &[u8; 32], signature: &[u8]) -> bool {
            signature == signing_root
        }
    }

    fn data(source_epoch: u64, target_epoch: u64, head: u8) -> AttestationData {
        AttestationData {
            slot: target_epoch * 32,
            head: [head; 32],
            source_epoch,
            source_root: [1; 32],
            target_epoch,
            target_root: [head; 32],
        }
    }

    fn signed(validator: u32, d: AttestationData) -> Attestation {
        Attestation { data: d, validator, signature: d.signing_root().to_vec() }
    }

    /// Two attestations for the same target epoch, different heads.
    fn double_vote(validator: u32) -> SlashingEvidence {
        SlashingEvidence {
            first: signed(validator, data(1, 2, 0xAA)),
            second: signed(validator, data(1, 2, 0xBB)),
        }
    }

    /// (source 1, target 6) surrounds (source 2, target 3).
    fn surround(validator: u32) -> SlashingEvidence {
        SlashingEvidence {
            first: signed(validator, data(1, 6, 0xAA)),
            second: signed(validator, data(2, 3, 0xBB)),
        }
    }

    fn delegation(delegator: u32, validator: u32, amount_sat: u128) -> Delegation {
        Delegation {
            delegator,
            validator,
            amount_sat,
            requested_epoch: 0,
            deactivate_epoch: None,
            eligible: true,
        }
    }

    const TOTAL_ACTIVE: u128 = 1_000_000;

    #[test]
    fn forged_evidence_is_rejected_and_leaves_state_untouched() {
        let mut ev = double_vote(7);
        ev.second.signature = vec![0u8; 32]; // not the signing root: forged
        let mut st = SlashingState::new();
        let dels = [delegation(1, 7, 100_000)];
        let r = st.process(&ev, 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::BadSignature);
        assert!(!st.is_ejected(7));
        assert_eq!(st.slashed_in_window(10), 0);
        // The forged submission must not have burned the id: the honest
        // version of the same evidence still applies.
        let ok = double_vote(7);
        assert!(st.process(&ok, 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).is_ok());
    }

    #[test]
    fn evidence_from_different_validators_is_rejected() {
        let ev = SlashingEvidence {
            first: signed(7, data(1, 2, 0xAA)),
            second: signed(8, data(1, 2, 0xBB)),
        };
        let mut st = SlashingState::new();
        let r = st.process(&ev, 10, &[], TOTAL_ACTIVE, 99, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::DifferentValidators);
    }

    #[test]
    fn identical_messages_are_not_a_conflict() {
        let d = data(1, 2, 0xAA);
        let ev = SlashingEvidence { first: signed(7, d), second: signed(7, d) };
        assert_eq!(ev.offense().unwrap_err(), EvidenceError::NotConflicting);
    }

    #[test]
    fn disjoint_epoch_spans_are_not_a_conflict() {
        // Different targets, no surround: normal honest voting across epochs.
        let ev = SlashingEvidence {
            first: signed(7, data(1, 2, 0xAA)),
            second: signed(7, data(2, 3, 0xBB)),
        };
        assert_eq!(ev.offense().unwrap_err(), EvidenceError::NotConflicting);
    }

    #[test]
    fn double_vote_slashes_delegators_pro_rata_and_ejects() {
        let dels = [
            delegation(1, 7, 100_000),
            delegation(2, 7, 300_000),
            delegation(3, 8, 600_000), // other validator: untouched
        ];
        let mut st = SlashingState::new();
        let out = st.process(&double_vote(7), 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).unwrap();
        assert_eq!(out.offense, SlashableOffense::DoubleVote);
        assert_eq!(out.penalty_bps, 500); // empty window: base only
        assert_eq!(out.delegation_losses_sat, vec![5_000, 15_000, 0]); // 5% each
        assert_eq!(out.total_slashed_sat, 20_000);
        assert!(st.is_ejected(7));
        assert!(!st.is_ejected(8));
    }

    #[test]
    fn surround_vote_is_slashable_in_either_pair_order() {
        for swap in [false, true] {
            let mut ev = surround(7);
            if swap {
                std::mem::swap(&mut ev.first, &mut ev.second);
            }
            assert_eq!(ev.offense().unwrap(), SlashableOffense::SurroundVote);
        }
    }

    #[test]
    fn whistleblower_gets_one_thirty_second() {
        let dels = [delegation(1, 7, 640_000)];
        let mut st = SlashingState::new();
        let out = st.process(&double_vote(7), 10, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier).unwrap();
        assert_eq!(out.total_slashed_sat, 32_000); // 5% of 640k
        assert_eq!(out.whistleblower_reward_sat, 1_000); // exactly 1/32
        assert_eq!(out.including_proposer, 42);
    }

    #[test]
    fn amplification_grows_with_stake_slashed_in_the_window() {
        // Validator 7 holds 30% of active stake; slashing it at 5% burns
        // 15,000 of 1,000,000 = 1.5%. The next offender in the same window
        // pays 500 + 3 × 10000 × 15000/1000000 = 950 bps, not 500.
        let dels = [delegation(1, 7, 300_000), delegation(2, 8, 100_000)];
        let mut st = SlashingState::new();
        let first = st.process(&double_vote(7), 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).unwrap();
        assert_eq!(first.penalty_bps, 500);
        assert_eq!(first.total_slashed_sat, 15_000);

        let second = st.process(&double_vote(8), 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).unwrap();
        assert_eq!(second.penalty_bps, 950);
        assert!(second.penalty_bps > first.penalty_bps);
        assert_eq!(second.total_slashed_sat, 9_500); // 9.5% of 100k
    }

    #[test]
    fn a_third_of_stake_slashed_saturates_the_penalty_at_100_percent() {
        // Force the window to hold ≥ 1/3 of stake: the amplified term alone
        // reaches 10,000 bps and the cap engages — a finality-scale attack
        // forfeits everything.
        let mut st = SlashingState::new();
        st.window.insert(10, TOTAL_ACTIVE / 3 + 1);
        assert_eq!(st.penalty_bps(500, 10, TOTAL_ACTIVE), 10_000);
    }

    #[test]
    fn slashes_outside_the_window_stop_amplifying() {
        let dels = [delegation(1, 7, 300_000), delegation(2, 8, 100_000)];
        let mut st = SlashingState::new();
        st.process(&double_vote(7), 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).unwrap();
        // Just inside the window: still amplified.
        let inside = 10 + CORRELATION_WINDOW_EPOCHS - 1;
        assert_eq!(st.penalty_bps(500, inside, TOTAL_ACTIVE), 950);
        // One epoch later the old slash has aged out: back to base.
        assert_eq!(st.penalty_bps(500, inside + 1, TOTAL_ACTIVE), 500);
    }

    #[test]
    fn replay_is_blocked_even_with_the_pair_swapped() {
        let dels = [delegation(1, 7, 100_000)];
        let mut st = SlashingState::new();
        let ev = double_vote(7);
        st.process(&ev, 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).unwrap();

        let replay = st.process(&ev, 11, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier);
        assert_eq!(replay.unwrap_err(), EvidenceError::AlreadyApplied);

        // Swapping first/second must not mint a fresh identity.
        let swapped = SlashingEvidence { first: ev.second.clone(), second: ev.first.clone() };
        let r = st.process(&swapped, 11, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::AlreadyApplied);

        // And the window recorded the slash exactly once.
        assert_eq!(st.slashed_in_window(11), 5_000);
    }

    #[test]
    fn an_ejected_validator_is_not_punished_again() {
        let dels = [delegation(1, 7, 100_000)];
        let mut st = SlashingState::new();
        st.process(&double_vote(7), 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).unwrap();

        // Genuinely different evidence (a surround, new messages) against the
        // same validator: rejected, and neither delegators nor the window are
        // touched a second time.
        let other = surround(7);
        let r = st.process(&other, 11, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::AlreadySlashed);
        assert_eq!(st.slashed_in_window(11), 5_000);
    }

    // ── proposer equivocation ───────────────────────────────────────────────

    fn header(slot: u64, proposer: u32, distinguisher: u8) -> crate::header::BlockHeaderV4 {
        crate::header::BlockHeaderV4 {
            version: crate::header::VERSION_G4,
            parent: [distinguisher; 32],
            state_root: [0; 32],
            body_root: [0; 32],
            slot,
            proposer_index: proposer,
            randao_reveal: [1; 32],
            randao_mix: [2; 32],
            justified_root: [3; 32],
            finalized_root: [4; 32],
            attestation_root: [5; 32],
            coherence_root: [6; 32],
        }
    }

    /// "Signed" under [`RootEchoVerifier`]: signature = proposal signing root.
    fn signed_header(slot: u64, proposer: u32, distinguisher: u8) -> ProposalEnvelope {
        let h = header(slot, proposer, distinguisher);
        ProposalEnvelope { proposer_sig: h.proposal_signing_root().to_vec(), header: h }
    }

    #[test]
    fn proposer_equivocation_slashes_and_ejects() {
        let dels = [delegation(1, 7, 100_000), delegation(2, 8, 100_000)];
        let (a, b) = (signed_header(5, 7, 0xAA), signed_header(5, 7, 0xBB));
        let mut st = SlashingState::new();
        let out = st
            .process_proposer(&a, &b, 10, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier)
            .unwrap();
        assert_eq!(out.offense, SlashableOffense::ProposerEquivocation);
        assert_eq!(out.penalty_bps, SLASH_PROPOSER_EQUIV_BPS); // empty window: base only
        assert_eq!(out.delegation_losses_sat, vec![5_000, 0]); // validator 8 untouched
        assert_eq!(out.whistleblower_reward_sat, out.total_slashed_sat / WHISTLEBLOWER_QUOTIENT);
        assert!(st.is_ejected(7));
        assert!(!st.is_ejected(8));
    }

    #[test]
    fn identical_headers_are_not_proposer_equivocation() {
        // Re-gossiping your own block must never be punishable.
        let a = signed_header(5, 7, 0xAA);
        let mut st = SlashingState::new();
        let r = st.process_proposer(&a, &a.clone(), 10, &[], TOTAL_ACTIVE, 42, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::NotConflicting);
    }

    #[test]
    fn different_slot_headers_are_not_proposer_equivocation() {
        // One proposer legitimately proposes in many slots over time.
        let (a, b) = (signed_header(5, 7, 0xAA), signed_header(6, 7, 0xBB));
        let mut st = SlashingState::new();
        let r = st.process_proposer(&a, &b, 10, &[], TOTAL_ACTIVE, 42, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::NotConflicting);
    }

    #[test]
    fn forged_proposer_evidence_is_rejected_and_id_not_burned() {
        let a = signed_header(5, 7, 0xAA);
        let mut b = signed_header(5, 7, 0xBB);
        b.proposer_sig = vec![0u8; 32]; // not the signing root: forged
        let dels = [delegation(1, 7, 100_000)];
        let mut st = SlashingState::new();
        let r = st.process_proposer(&a, &b, 10, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::BadSignature);
        assert!(!st.is_ejected(7));
        assert_eq!(st.slashed_in_window(10), 0);
        // The honest version of the same pair still applies.
        let b_ok = signed_header(5, 7, 0xBB);
        assert!(st.process_proposer(&a, &b_ok, 10, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier).is_ok());
    }

    #[test]
    fn proposer_evidence_replay_is_blocked_even_swapped() {
        let dels = [delegation(1, 7, 100_000)];
        let (a, b) = (signed_header(5, 7, 0xAA), signed_header(5, 7, 0xBB));
        let mut st = SlashingState::new();
        st.process_proposer(&a, &b, 10, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier).unwrap();
        let r = st.process_proposer(&b, &a, 11, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::AlreadyApplied);
        assert_eq!(st.slashed_in_window(11), 5_000); // recorded exactly once
    }

    #[test]
    fn header_and_attestation_evidence_share_one_ejection_set() {
        // A validator slashed for a double vote cannot be punished again by a
        // later proposer-equivocation evidence — the stake was already burned.
        let dels = [delegation(1, 7, 100_000)];
        let mut st = SlashingState::new();
        st.process(&double_vote(7), 10, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier).unwrap();
        let (a, b) = (signed_header(5, 7, 0xAA), signed_header(5, 7, 0xBB));
        let r = st.process_proposer(&a, &b, 11, &dels, TOTAL_ACTIVE, 42, &RootEchoVerifier);
        assert_eq!(r.unwrap_err(), EvidenceError::AlreadySlashed);
        assert_eq!(st.slashed_in_window(11), 5_000);
    }

    #[test]
    fn ineligible_delegations_do_not_burn() {
        // Tainted stake never contributed weight (delegation.rs rule 4), so
        // it must not absorb penalty either — otherwise taint would dilute
        // the loss of the stake that actually voted.
        let mut tainted = delegation(2, 7, 900_000);
        tainted.eligible = false;
        let dels = [delegation(1, 7, 100_000), tainted];
        let mut st = SlashingState::new();
        let out = st.process(&double_vote(7), 10, &dels, TOTAL_ACTIVE, 99, &RootEchoVerifier).unwrap();
        assert_eq!(out.delegation_losses_sat, vec![5_000, 0]);
    }
}
