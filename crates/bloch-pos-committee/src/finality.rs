// SPDX-License-Identifier: AGPL-3.0-or-later

//! Justification and finality — the Casper-style gadget (§5.1, §6.5.2).
//!
//! One checkpoint per epoch (`EPOCHS_PER_CHECKPOINT = 1`). The **full epoch
//! committee of 128** votes once at the epoch boundary; those votes — and only
//! those — drive justification and finality. The per-slot subcommittee of 8
//! exists purely to give LMD-GHOST intra-epoch fork-choice weight (§6.5.2) and
//! must never be fed into this module: its members are not in the epoch
//! committee for that epoch (different sortition role tag), so its votes are
//! rejected here by the membership check rather than by caller discipline.
//!
//! ## The rules
//!
//! - **Justification.** A checkpoint is justified when attestations carrying it
//!   as `target`, from epoch-committee members, whose `source` is the currently
//!   highest justified checkpoint, account for **≥ 2/3 of the committee's
//!   active stake**. The comparison is `3·attesting ≥ 2·total` in `u128` — no
//!   division, no rounding ambiguity, so "exactly 2/3" justifies and
//!   "2/3 − 1 satoshi" does not, identically on every node.
//! - **Finality.** Consecutive justification: when the supermajority link
//!   `source → target` has `target.epoch == source.epoch + 1`, the *source*
//!   checkpoint becomes finalized. A justified checkpoint whose next epoch also
//!   justifies (building on it) is final.
//! - **Inactivity leak.** After `INACTIVITY_LEAK_THRESHOLD_EPOCHS` (4) epochs
//!   without finality, committee members who fail to cast a valid vote bleed
//!   stake quadratically, until the remaining live stake is again ≥ 2/3 of the
//!   (shrunken) total and finality resumes.
//!
//! ## Why the source must be the highest justified checkpoint
//!
//! Casper FFG counts supermajority *links* `(s → t)`. If votes for the same
//! target were allowed to mix different justified sources, "2/3 voted for t"
//! would not name any single link, and the finalization predicate ("was the
//! link consecutive?") would depend on which mosaic of sources happened to add
//! up. Requiring one uniform source — the highest justified checkpoint as of
//! the start of the epoch, which is the source every honest validator uses
//! anyway — makes each justification a property of exactly one link, and the
//! consecutive-finality rule a one-line check against it.
//!
//! ## Why the state is a pure fold over the vote history
//!
//! This chain has already been split by consensus state living outside the
//! committed inputs: `expected_bits` was read from node-local mutable state and
//! froze every follower on 2026-08-08 (§5.5 of the migration design).
//! [`FinalityState`] therefore has no clock, no cache, and no channel to
//! anything but its inputs: `from_history(genesis, votes) == fold of
//! process_epoch`, and two nodes holding the same attestation history and the
//! same stake registry *cannot* disagree on what is justified or final. The
//! incremental [`FinalityState::process_epoch`] exists for the node's hot path,
//! but it is defined as — and tested to be — exactly the fold step of
//! [`FinalityState::from_history`].
//!
//! ## Safety argument, in one paragraph
//!
//! Each validator contributes at most once per epoch (duplicates are deduped;
//! *conflicting* votes mark the validator an equivocator and count for **no**
//! target — order-independent, unlike first-seen-wins). Two conflicting
//! checkpoints at the same epoch would therefore need two disjoint ≥ 2/3 stake
//! quorums out of one 3/3 total — impossible. At most one root is justified
//! per epoch, hence at most one can ever be finalized per epoch, on any input.

use crate::attestation::AttestationData;
use crate::params::{INACTIVITY_LEAK_QUOTIENT, INACTIVITY_LEAK_THRESHOLD_EPOCHS};
use crate::sample::Validator;
use std::collections::{BTreeMap, BTreeSet};

/// A checkpoint: the block root chosen at an epoch boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

/// Everything the gadget consumes for one epoch.
///
/// `attestations` are **epoch-boundary votes only**, already
/// signature-verified upstream (`attestation::validate`) — this module takes
/// bare `(validator, data)` pairs precisely so it cannot be handed an
/// unverified signature and mistake membership checking for authentication.
/// Per-slot subcommittee attestations belong to `forkchoice::Store::observe`,
/// never here; any that leak through are dropped by the committee-membership
/// check because slot and epoch committees are drawn under different sortition
/// role tags.
#[derive(Clone, Copy, Debug)]
pub struct EpochVotes<'a> {
    /// The epoch these votes justify (the checkpoint's own epoch).
    pub epoch: u64,
    /// **The whole active validator set** for this epoch, with effective stake
    /// as committed by the parent block's state.
    ///
    /// Not a sample. This field used to say "the caller draws it via
    /// `epoch_committee()`", which is the sampled k=128 draw, and that made the
    /// quorum two thirds of a *sample's* stake — finding F1 reading 2, where a
    /// ~30% adversary exceeds one third of the sample often enough to stall
    /// finality roughly one epoch in five. Worse, the partition that was
    /// written to fix exactly this had **no caller**: the fix existed as a
    /// module and changed nothing (adversarial review G1, 2026-08-11).
    ///
    /// Under [`crate::committees::epoch_committees`] the epoch's committees
    /// partition this set — every active validator lands in exactly one slot
    /// committee and votes exactly once — so the union of an epoch's committees
    /// *is* this field, the denominator is total active stake, and it is
    /// reachable by construction. The field is named for what it must be, and
    /// renaming it was deliberate: a compile error at every call site is
    /// cheaper than a silently wrong denominator.
    ///
    /// Stake comes in from committed state; the *leak* adjustment is applied
    /// internally, because the leak is itself a function of the vote history.
    pub active_set: &'a [Validator],
    /// Signature-verified epoch-boundary attestations.
    pub attestations: &'a [(u32, AttestationData)],
}

/// What processing one epoch produced. Returned so the caller can log, gossip
/// a finality update, or feed `equivocators` to the slashing pipeline (§7.3)
/// without re-deriving any of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochOutcome {
    /// Checkpoint justified by this epoch's votes, if the quorum was reached.
    pub justified: Option<Checkpoint>,
    /// Checkpoint finalized by the consecutive-justification rule, if any.
    pub finalized: Option<Checkpoint>,
    /// Committee members that signed conflicting attestations for this target
    /// epoch — slashable double votes (`AttestationData::is_double_vote`).
    pub equivocators: Vec<u32>,
}

/// Rejected input. Explicit rather than a panic because a malformed feed must
/// be attributable from logs, not reconstructed from a backtrace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityError {
    /// Epochs must be processed densely and in order (`expected` next). Dense,
    /// because the inactivity-leak clock ticks on *empty* epochs too — skipping
    /// one would silently change every later leak amount.
    OutOfOrderEpoch { got: u64, expected: u64 },
}

/// Justification/finality state. A pure function of `(genesis, vote history)`:
/// see the module docs for why this is load-bearing and not a platitude.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityState {
    /// Every justified checkpoint, keyed by epoch. At most one per epoch — the
    /// disjoint-quorums argument in the module docs. Kept whole (not pruned at
    /// finality) so the state remains bit-identical to a from-scratch replay.
    justified: BTreeMap<u64, [u8; 32]>,
    /// Highest justified checkpoint — the mandatory `source` for the next
    /// epoch's votes, and LMD-GHOST's walk root (§5.2).
    current_justified: Checkpoint,
    /// Highest finalized checkpoint.
    finalized: Checkpoint,
    /// Cumulative stake leaked per validator, in satoshis. Derived only from
    /// the vote history, so it lives inside the pure state rather than in the
    /// registry: the committed registry stake stays the input, and the leak is
    /// an adjustment this fold owns end to end.
    leaked: BTreeMap<u32, u64>,
    /// Next epoch this state will accept — makes "dense, in-order" checkable.
    next_epoch: u64,
}

impl FinalityState {
    /// Start from a trusted checkpoint (the transition block at genesis-4, or
    /// a weak-subjectivity checkpoint when syncing). It is justified *and*
    /// finalized by definition: finality needs a root of trust to link from.
    pub fn new(genesis: Checkpoint) -> Self {
        let mut justified = BTreeMap::new();
        justified.insert(genesis.epoch, genesis.root);
        FinalityState {
            justified,
            current_justified: genesis,
            finalized: genesis,
            leaked: BTreeMap::new(),
            next_epoch: genesis.epoch + 1,
        }
    }

    /// The canonical constructor: replay the whole history. `process_epoch` is
    /// the fold step; this exists so "state = pure function of history" is an
    /// API you can call, not a comment you must trust.
    pub fn from_history<'a, I>(genesis: Checkpoint, history: I) -> Result<Self, FinalityError>
    where
        I: IntoIterator<Item = EpochVotes<'a>>,
    {
        let mut state = FinalityState::new(genesis);
        for votes in history {
            state.process_epoch(&votes)?;
        }
        Ok(state)
    }

    /// Fold one epoch of votes into the state.
    ///
    /// Order inside this function matters and is part of consensus:
    /// 1. tally votes with **pre-epoch** leak-adjusted stakes (this epoch's
    ///    leak must not influence this epoch's own quorum),
    /// 2. justify / finalize,
    /// 3. tick the leak using the **post-vote** finalized epoch, so the epoch
    ///    that restores finality does not also punish its participants.
    pub fn process_epoch(&mut self, votes: &EpochVotes<'_>) -> Result<EpochOutcome, FinalityError> {
        if votes.epoch != self.next_epoch {
            return Err(FinalityError::OutOfOrderEpoch {
                got: votes.epoch,
                expected: self.next_epoch,
            });
        }
        self.next_epoch += 1;

        // Leak-adjusted stake per committee member. BTreeMap (not Hash) so
        // every iteration below is in fixed index order — determinism is not
        // allowed to depend on hasher seeds in a consensus path.
        let mut stake: BTreeMap<u32, u64> = BTreeMap::new();
        for v in votes.active_set {
            let leaked = *self.leaked.get(&v.index).unwrap_or(&0);
            stake.insert(v.index, v.effective_stake.saturating_sub(leaked));
        }
        // u128 accumulator: 128 members × u64::MAX stake overflows u64.
        let total_active: u128 = stake.values().map(|s| *s as u128).sum();

        // ── 1. Collect valid votes ─────────────────────────────────────────
        // A vote counts only if all of these hold; anything else makes the
        // validator "absent" for both quorum and leak purposes:
        //   - signer is in this epoch's committee (drops per-slot subcommittee
        //     votes and outsiders),
        //   - target epoch is this epoch (a stale or future target is not a
        //     vote for this checkpoint),
        //   - source is exactly the current highest justified checkpoint (the
        //     uniform-link rule from the module docs),
        //   - the validator did not equivocate.
        let mut first_vote: BTreeMap<u32, AttestationData> = BTreeMap::new();
        let mut equivocators: BTreeSet<u32> = BTreeSet::new();
        for (validator, data) in votes.attestations {
            if !stake.contains_key(validator) {
                continue;
            }
            if data.target_epoch != votes.epoch {
                continue;
            }
            match first_vote.get(validator) {
                None => {
                    first_vote.insert(*validator, *data);
                }
                // Same data twice is gossip duplication; *different* data for
                // the same target epoch is a slashable double vote. The
                // equivocator counts toward NO target: discarding both sides
                // is order-independent (first-seen-wins would let gossip
                // arrival order decide consensus) and removes the only way a
                // single validator could feed stake to two quorums.
                Some(prev) if prev != data => {
                    equivocators.insert(*validator);
                }
                Some(_) => {}
            }
        }
        for v in &equivocators {
            first_vote.remove(v);
        }

        // Keep only votes linking from the current justified checkpoint.
        let source = self.current_justified;
        let valid: BTreeMap<u32, AttestationData> = first_vote
            .into_iter()
            .filter(|(_, d)| {
                d.source_epoch == source.epoch
                    && d.source_root == source.root
                    // source < target is re-checked here even though
                    // attestation::validate enforces it, because this module
                    // must stay safe if a caller wires it up without the
                    // wire-level validation.
                    && d.source_epoch < d.target_epoch
            })
            .collect();

        // ── 2. Justify / finalize ──────────────────────────────────────────
        let mut tally: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        for (validator, data) in &valid {
            *tally.entry(data.target_root).or_insert(0) += stake[validator] as u128;
        }

        // ≥ 2/3 as 3·w ≥ 2·total: exact in integers, so the boundary case is
        // the same on every node. `total_active > 0` guards the degenerate
        // fully-leaked committee, where 0 ≥ 0 would "justify" an empty vote.
        let mut justified_now: Option<Checkpoint> = None;
        for (root, weight) in &tally {
            if total_active > 0 && weight * 3 >= total_active * 2 {
                // Two roots both reaching 2/3 is arithmetically impossible
                // (disjoint quorums out of one total); the loop shape just
                // makes the iteration order irrelevant.
                justified_now = Some(Checkpoint { epoch: votes.epoch, root: *root });
                break;
            }
        }

        let mut finalized_now: Option<Checkpoint> = None;
        if let Some(cp) = justified_now {
            self.justified.insert(cp.epoch, cp.root);
            if cp.epoch > self.current_justified.epoch {
                self.current_justified = cp;
            }
            // Consecutive justification, Casper k = 1: the supermajority link
            // was (source → cp). If they are adjacent epochs, the *source* —
            // already justified, now built on by a justified child — is final.
            // Strictly `>`: a link out of the already-finalized checkpoint
            // (e.g. genesis → epoch 1) re-derives a finality that exists;
            // reporting it as new would make "finalized this epoch" fire on
            // every first epoch. Same-epoch-different-root cannot occur: only
            // one root is ever justified per epoch.
            if cp.epoch == source.epoch + 1 && source.epoch > self.finalized.epoch {
                self.finalized = source;
                finalized_now = Some(source);
            }
        }

        // ── 3. Inactivity leak ─────────────────────────────────────────────
        // Uses the post-vote finalized epoch: if this epoch's votes restored
        // finality, its participants are not punished for the stall they just
        // ended. Strictly *after* the threshold — 4 epochs of non-finality is
        // tolerated intact (§5.1).
        let since_finality = votes.epoch.saturating_sub(self.finalized.epoch);
        if since_finality > INACTIVITY_LEAK_THRESHOLD_EPOCHS {
            // Linear-in-time per-epoch bite ⇒ quadratic cumulative loss, the
            // classic Casper shape: the longer the stall, the faster absent
            // stake evaporates, so recovery time is bounded instead of
            // drifting with the size of the absent fraction.
            let t = (since_finality - INACTIVITY_LEAK_THRESHOLD_EPOCHS) as u128;
            for v in votes.active_set {
                if valid.contains_key(&v.index) {
                    continue; // cast a valid vote — spared, even on a losing target's epoch
                }
                let remaining = stake[&v.index];
                if remaining == 0 {
                    continue;
                }
                // max(·, 1): integer division must not let a small stake sit
                // out the leak forever; min(·, remaining): never underflow.
                let bite = ((remaining as u128 * t) / INACTIVITY_LEAK_QUOTIENT).max(1) as u64;
                let bite = bite.min(remaining);
                *self.leaked.entry(v.index).or_insert(0) += bite;
            }
        }

        Ok(EpochOutcome {
            justified: justified_now,
            finalized: finalized_now,
            equivocators: equivocators.into_iter().collect(),
        })
    }

    /// Highest justified checkpoint — the required source for the next epoch's
    /// votes and the fork-choice walk root.
    pub fn current_justified(&self) -> Checkpoint {
        self.current_justified
    }

    /// Highest finalized checkpoint.
    pub fn finalized(&self) -> Checkpoint {
        self.finalized
    }

    /// Is exactly this checkpoint justified?
    pub fn is_justified(&self, cp: &Checkpoint) -> bool {
        self.justified.get(&cp.epoch) == Some(&cp.root)
    }

    /// Cumulative stake leaked from `validator`, in satoshis.
    pub fn leaked_of(&self, validator: u32) -> u64 {
        *self.leaked.get(&validator).unwrap_or(&0)
    }

    /// Next epoch this state will accept.
    pub fn next_epoch(&self) -> u64 {
        self.next_epoch
    }

    /// Every justified checkpoint this state holds, in epoch order.
    ///
    /// A read-only view for the state commitment (§5.5, 2026-08-11
    /// extension): the committed finality record must cover the *whole* fold
    /// state, and these fields are otherwise private by design. No hashing or
    /// serialization happens here — the committed byte format has exactly one
    /// definition, in `state_root`.
    pub fn justified_checkpoints(&self) -> impl Iterator<Item = Checkpoint> + '_ {
        self.justified.iter().map(|(epoch, root)| Checkpoint { epoch: *epoch, root: *root })
    }

    /// Cumulative inactivity leak per validator, in index order. Same purpose
    /// and same rules as [`FinalityState::justified_checkpoints`].
    pub fn leaked_stakes(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        self.leaked.iter().map(|(v, s)| (*v, *s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: [u8; 32] = [0xAA; 32];

    fn genesis() -> Checkpoint {
        Checkpoint { epoch: 0, root: G }
    }

    fn root(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn validator(index: u32, effective_stake: u64) -> Validator {
        Validator { index, effective_stake }
    }

    /// A well-formed epoch-boundary vote linking `source → (epoch, target)`.
    fn vote(v: u32, epoch: u64, target: [u8; 32], source: Checkpoint) -> (u32, AttestationData) {
        (
            v,
            AttestationData {
                slot: epoch * crate::params::SLOTS_PER_EPOCH,
                head: target,
                source_epoch: source.epoch,
                source_root: source.root,
                target_epoch: epoch,
                target_root: target,
            },
        )
    }

    #[test]
    fn exactly_two_thirds_justifies() {
        // total = 300; attesting = 200 = exactly 2/3 → 3·200 = 600 ≥ 2·300.
        let committee = [validator(0, 200), validator(1, 100)];
        let atts = [vote(0, 1, root(1), genesis())];
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, Some(Checkpoint { epoch: 1, root: root(1) }));
        assert!(st.is_justified(&Checkpoint { epoch: 1, root: root(1) }));
    }

    #[test]
    fn two_thirds_minus_one_does_not_justify() {
        // total = 300; attesting = 199 → 597 < 600. One satoshi short fails.
        let committee = [validator(0, 199), validator(1, 101)];
        let atts = [vote(0, 1, root(1), genesis())];
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, None);
        assert_eq!(st.current_justified(), genesis());
    }

    #[test]
    fn indivisible_total_needs_the_ceiling() {
        // total = 100: 2/3 is not an integer. 66 must fail (198 < 200),
        // 67 must pass (201 ≥ 200) — the integer form takes the ceiling.
        for (attesting, expect) in [(66u64, false), (67u64, true)] {
            let committee = [validator(0, attesting), validator(1, 100 - attesting)];
            let atts = [vote(0, 1, root(1), genesis())];
            let mut st = FinalityState::new(genesis());
            let out = st
                .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
                .unwrap();
            assert_eq!(out.justified.is_some(), expect, "attesting={attesting}");
        }
    }

    #[test]
    fn consecutive_justification_finalizes_the_source() {
        let committee = [validator(0, 2), validator(1, 1)];
        let mut st = FinalityState::new(genesis());

        // Epoch 1 justifies (link 0 → 1). Nothing final yet: a lone justified
        // checkpoint can still be abandoned.
        let a1 = [vote(0, 1, root(1), genesis())];
        let out1 = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &a1 })
            .unwrap();
        assert!(out1.justified.is_some());
        assert_eq!(out1.finalized, None);
        assert_eq!(st.finalized(), genesis());

        // Epoch 2 justifies with source = checkpoint 1 (link 1 → 2):
        // consecutive, so checkpoint 1 is finalized.
        let cp1 = st.current_justified();
        let a2 = [vote(0, 2, root(2), cp1)];
        let out2 = st
            .process_epoch(&EpochVotes { epoch: 2, active_set: &committee, attestations: &a2 })
            .unwrap();
        assert_eq!(out2.finalized, Some(cp1));
        assert_eq!(st.finalized(), cp1);
    }

    #[test]
    fn skipped_epoch_justifies_but_does_not_finalize() {
        let committee = [validator(0, 2), validator(1, 1)];
        let mut st = FinalityState::new(genesis());

        // Epoch 1: nobody votes.
        st.process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &[] })
            .unwrap();
        // Epoch 2 justifies with source = genesis (link 0 → 2): a valid
        // supermajority link, but NOT consecutive — nothing may finalize.
        let a2 = [vote(0, 2, root(2), genesis())];
        let out = st
            .process_epoch(&EpochVotes { epoch: 2, active_set: &committee, attestations: &a2 })
            .unwrap();
        assert!(out.justified.is_some());
        assert_eq!(out.finalized, None);
        assert_eq!(st.finalized(), genesis());
    }

    #[test]
    fn stale_source_does_not_count() {
        let committee = [validator(0, 2), validator(1, 1)];
        let mut st = FinalityState::new(genesis());
        let a1 = [vote(0, 1, root(1), genesis())];
        st.process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &a1 })
            .unwrap();

        // Epoch 2 votes still sourcing genesis, but checkpoint 1 is now the
        // highest justified checkpoint — the uniform-link rule rejects them.
        let a2 = [vote(0, 2, root(2), genesis())];
        let out = st
            .process_epoch(&EpochVotes { epoch: 2, active_set: &committee, attestations: &a2 })
            .unwrap();
        assert_eq!(out.justified, None);
    }

    #[test]
    fn unjustified_source_does_not_count() {
        let committee = [validator(0, 3)];
        let bogus = Checkpoint { epoch: 0, root: root(0xEE) }; // wrong root for epoch 0
        let atts = [vote(0, 1, root(1), bogus)];
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, None);
    }

    #[test]
    fn non_committee_vote_is_ignored() {
        // Validator 99 is not in the epoch committee — the shape of a per-slot
        // subcommittee vote reaching the finality gadget. Its stake must not
        // count even if it would complete the quorum.
        let committee = [validator(0, 1), validator(1, 2)];
        let atts = [vote(0, 1, root(1), genesis()), vote(99, 1, root(1), genesis())];
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, None);
    }

    #[test]
    fn equivocator_counts_for_no_target_and_is_reported() {
        // total = 300, quorum = 200. A(100)+B(100) vote X; C(100) double-votes
        // X and Y. C is discarded from BOTH tallies, so X stands at exactly
        // 200 from A+B alone (still justified) and Y gains nothing from C.
        let committee = [validator(0, 100), validator(1, 100), validator(2, 100)];
        let atts = [
            vote(0, 1, root(1), genesis()),
            vote(1, 1, root(1), genesis()),
            vote(2, 1, root(1), genesis()),
            vote(2, 1, root(2), genesis()), // conflicting: same target epoch, different root
        ];
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.equivocators, vec![2]);
        // Without C, X has 200/300 — still exactly 2/3, justified; but Y must
        // have gained nothing from C either.
        assert_eq!(out.justified, Some(Checkpoint { epoch: 1, root: root(1) }));
        assert!(!st.is_justified(&Checkpoint { epoch: 1, root: root(2) }));
    }

    #[test]
    fn no_two_conflicting_checkpoints_in_one_epoch() {
        // Adversarial shot at two quorums: 2/3 of the stake double-votes for
        // both X and Y. Dedup + equivocation discard means NEITHER justifies —
        // there is no input on which two roots reach 2/3 in the same epoch.
        let committee = [validator(0, 100), validator(1, 100), validator(2, 100)];
        let atts = [
            vote(0, 1, root(1), genesis()),
            vote(0, 1, root(2), genesis()),
            vote(1, 1, root(1), genesis()),
            vote(1, 1, root(2), genesis()),
            vote(2, 1, root(1), genesis()),
            vote(2, 1, root(2), genesis()),
        ];
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, None);
        assert_eq!(out.equivocators, vec![0, 1, 2]);
        assert!(!st.is_justified(&Checkpoint { epoch: 1, root: root(1) }));
        assert!(!st.is_justified(&Checkpoint { epoch: 1, root: root(2) }));
    }

    #[test]
    fn duplicate_identical_vote_is_not_equivocation_and_not_double_counted() {
        let committee = [validator(0, 200), validator(1, 100)];
        let v = vote(0, 1, root(1), genesis());
        let atts = [v, v]; // gossip duplication
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert!(out.equivocators.is_empty());
        assert_eq!(out.justified, Some(Checkpoint { epoch: 1, root: root(1) }));
    }

    #[test]
    fn inactivity_leak_starts_only_after_threshold() {
        // 60% present / 40% absent: stalled. For the first 4 epochs of
        // non-finality nobody leaks.
        let committee =
            [validator(0, 60_000_000), validator(1, 20_000_000), validator(2, 20_000_000)];
        let mut st = FinalityState::new(genesis());
        for e in 1..=INACTIVITY_LEAK_THRESHOLD_EPOCHS {
            let atts = [vote(0, e, root(e as u8), genesis())];
            st.process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &atts })
                .unwrap();
            assert_eq!(st.leaked_of(1), 0, "no leak within the threshold (epoch {e})");
        }
        // First epoch strictly beyond the threshold leaks the absentees only.
        let e = INACTIVITY_LEAK_THRESHOLD_EPOCHS + 1;
        let atts = [vote(0, e, root(0x77), genesis())];
        st.process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &atts })
            .unwrap();
        assert!(st.leaked_of(1) > 0);
        assert!(st.leaked_of(2) > 0);
        assert_eq!(st.leaked_of(0), 0, "a validly voting member never leaks");
    }

    #[test]
    fn inactivity_leak_recovers_finality() {
        // 60/40 stall: 60% can never reach 2/3 of the intact total. The
        // quadratic leak must shrink the absent 40% until 60% ≥ 2/3 of what
        // remains, then finality resumes via consecutive justification.
        let committee =
            [validator(0, 60_000_000), validator(1, 20_000_000), validator(2, 20_000_000)];
        let mut st = FinalityState::new(genesis());
        let mut recovered_at = None;
        for e in 1..=40u64 {
            let src = st.current_justified();
            let atts = [vote(0, e, root(e as u8), src)];
            let out = st
                .process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &atts })
                .unwrap();
            if out.finalized.is_some() {
                recovered_at = Some(e);
                break;
            }
        }
        let e = recovered_at.expect("leak must restore finality within 40 epochs");
        // Sanity on the shape of the recovery: it takes longer than the
        // threshold (the stall was real) and the finalized checkpoint is the
        // first post-recovery justified one.
        assert!(e > INACTIVITY_LEAK_THRESHOLD_EPOCHS);
        assert!(st.finalized().epoch > 0);
        assert!(st.leaked_of(1) > 0 && st.leaked_of(2) > 0);
        assert_eq!(st.leaked_of(0), 0);
        // And the absentees lost real stake: the leak is a cost, not a nudge.
        assert!(st.leaked_of(1) >= 20_000_000 / 4);
    }

    #[test]
    fn fully_leaked_committee_cannot_self_justify() {
        // Degenerate end state: everyone absent long enough that all stake has
        // leaked to zero. total = 0 must not satisfy 0 ≥ 0 and "justify" an
        // empty checkpoint.
        let committee = [validator(0, 10)];
        let mut st = FinalityState::new(genesis());
        for e in 1..=30u64 {
            st.process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &[] })
                .unwrap();
        }
        assert_eq!(st.leaked_of(0), 10);
        // Now a vote arrives from the fully-leaked validator: zero weight.
        let atts = [vote(0, 31, root(9), genesis())];
        let out = st
            .process_epoch(&EpochVotes { epoch: 31, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, None);
    }

    #[test]
    fn state_is_a_pure_function_of_history() {
        // Incremental processing and a from-scratch replay of the same history
        // must be bit-identical — the §5.5 rule as an executable assertion.
        let committee = [validator(0, 200), validator(1, 100)];
        let a1 = [vote(0, 1, root(1), genesis())];
        let cp1 = Checkpoint { epoch: 1, root: root(1) };
        let a2 = [vote(0, 2, root(2), cp1)];
        let history = [
            EpochVotes { epoch: 1, active_set: &committee, attestations: &a1 },
            EpochVotes { epoch: 2, active_set: &committee, attestations: &a2 },
            EpochVotes { epoch: 3, active_set: &committee, attestations: &[] },
        ];

        let mut incremental = FinalityState::new(genesis());
        for v in &history {
            incremental.process_epoch(v).unwrap();
        }
        let replayed = FinalityState::from_history(genesis(), history).unwrap();
        assert_eq!(incremental, replayed);
        assert_eq!(replayed.finalized(), cp1);
    }

    #[test]
    fn epochs_must_be_dense_and_in_order() {
        let committee = [validator(0, 1)];
        let mut st = FinalityState::new(genesis());
        assert_eq!(
            st.process_epoch(&EpochVotes { epoch: 3, active_set: &committee, attestations: &[] }),
            Err(FinalityError::OutOfOrderEpoch { got: 3, expected: 1 }),
        );
        st.process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &[] })
            .unwrap();
        assert_eq!(
            st.process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &[] }),
            Err(FinalityError::OutOfOrderEpoch { got: 1, expected: 2 }),
        );
    }

    #[test]
    fn u128_totals_survive_maximal_stakes() {
        // Two validators at u64::MAX would overflow a u64 accumulator; the
        // u128 path must tally and justify correctly.
        let committee = [validator(0, u64::MAX), validator(1, u64::MAX), validator(2, u64::MAX)];
        let atts = [vote(0, 1, root(1), genesis()), vote(1, 1, root(1), genesis())];
        let mut st = FinalityState::new(genesis());
        let out = st
            .process_epoch(&EpochVotes { epoch: 1, active_set: &committee, attestations: &atts })
            .unwrap();
        assert_eq!(out.justified, Some(Checkpoint { epoch: 1, root: root(1) }));
    }
}

// ── Wiring to the partition ─────────────────────────────────────────────────

/// Build [`EpochVotes`] from the epoch's **partition**, checking each attester
/// against the committee of *its own slot*.
///
/// This is the function that connects [`crate::committees`] to this gadget.
/// Without it the partition was a module with no caller: the fix for finding
/// F1 existed, was tested, was written up as done — and changed nothing,
/// because nothing invoked it (adversarial review G1, 2026-08-11). A
/// correction that is not wired is not a correction.
///
/// Two things it enforces that a flat committee list cannot:
///
/// 1. **The denominator is the whole active set.** Justification needs two
///    thirds of total active stake, not two thirds of a sample — the reading
///    under which a ~30% adversary stalls finality roughly one epoch in five.
/// 2. **Membership is slot-specific.** An attester must be in the committee of
///    the slot it attests for, not merely somewhere in the epoch. Accepting a
///    vote from the wrong slot's committee would let a validator vote in every
///    slot it can reach, which is the double-vote hazard partitioning exists to
///    remove.
///
/// Attestations failing either check are dropped here rather than passed on as
/// "absent": an out-of-slot vote is a protocol violation, not a missed duty,
/// and counting it as absence would leak stake from an honest validator whose
/// vote merely arrived mislabelled.
pub fn votes_from_partition<'a>(
    epoch: u64,
    active_set: &'a [Validator],
    attestations: &'a [(u32, AttestationData)],
    beacon_mix: &[u8; 32],
    accepted: &'a mut Vec<(u32, AttestationData)>,
) -> EpochVotes<'a> {
    let committees = crate::committees::epoch_committees(beacon_mix, epoch, active_set);
    let slots_per_epoch = crate::params::SLOTS_PER_EPOCH;

    accepted.clear();
    for (validator, data) in attestations {
        let idx = (data.slot % slots_per_epoch) as usize;
        let in_own_slot = committees
            .get(idx)
            .is_some_and(|c| c.binary_search(validator).is_ok());
        if in_own_slot {
            accepted.push((*validator, *data));
        }
    }

    EpochVotes { epoch, active_set, attestations: accepted }
}

// ── snapshot ─────────────────────────────────────────────────────────────────
//
// The encoding lives here rather than in `snapshot.rs` because these fields are
// private, and they should stay private: a state that anyone can construct
// field by field is a state nobody can reason about. Each type encodes itself.

impl FinalityState {
    pub fn snap_write(&self, w: &mut crate::snapshot::W) {
        w.len(self.justified.len());
        for (e, r) in &self.justified { w.u64(*e); w.h32(r); }
        w.u64(self.current_justified.epoch);
        w.h32(&self.current_justified.root);
        w.u64(self.finalized.epoch);
        w.h32(&self.finalized.root);
        w.len(self.leaked.len());
        for (v, s) in &self.leaked { w.u32(*v); w.u64(*s); }
        w.u64(self.next_epoch);
    }

    pub fn snap_read(r: &mut crate::snapshot::R) -> Result<Self, crate::snapshot::SnapErr> {
        let mut justified = std::collections::BTreeMap::new();
        for _ in 0..r.len()? { let e = r.u64()?; justified.insert(e, r.h32()?); }
        let current_justified = Checkpoint { epoch: r.u64()?, root: r.h32()? };
        let finalized = Checkpoint { epoch: r.u64()?, root: r.h32()? };
        let mut leaked = std::collections::BTreeMap::new();
        for _ in 0..r.len()? { let v = r.u32()?; leaked.insert(v, r.u64()?); }
        Ok(FinalityState { justified, current_justified, finalized, leaked, next_epoch: r.u64()? })
    }
}
