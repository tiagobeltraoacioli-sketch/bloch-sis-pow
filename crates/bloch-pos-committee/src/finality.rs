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
use crate::params::{
    INACTIVITY_LEAK_QUOTIENT, INACTIVITY_LEAK_RECOVERY_QUOTIENT,
    INACTIVITY_LEAK_THRESHOLD_EPOCHS, MIN_QUORUM_DENOMINATOR_DEN, MIN_QUORUM_DENOMINATOR_NUM,
};
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
    /// `true` only in a test build with the mutation switch on. Constant
    /// `false` everywhere else, so the branch above folds away in a release.
    #[inline]
    fn denominator_ignores_leak() -> bool {
        #[cfg(test)]
        {
            return tests_hook::IGNORE_LEAK_IN_DENOMINATOR.load(std::sync::atomic::Ordering::Relaxed);
        }
        #[cfg(not(test))]
        false
    }

    /// Mutation switch: reproduce the PRE-FIX denominator, with no floor. The
    /// two tests that document the 2026-08-24 false quorum set it, so the
    /// disease stays reproducible from this repository after the cure landed.
    /// Constant `false` in a release build.
    #[inline]
    fn denominator_floor_disabled() -> bool {
        #[cfg(test)]
        {
            return tests_hook::DISABLE_DENOMINATOR_FLOOR.load(std::sync::atomic::Ordering::Relaxed);
        }
        #[cfg(not(test))]
        false
    }

    /// Mutation switch: reproduce the PRE-FIX accumulator, which had exactly
    /// one write path and never came back down. Same purpose as
    /// [`Self::denominator_floor_disabled`]. Constant `false` in a release
    /// build.
    #[inline]
    fn leak_recovery_disabled() -> bool {
        #[cfg(test)]
        {
            return tests_hook::DISABLE_LEAK_RECOVERY.load(std::sync::atomic::Ordering::Relaxed);
        }
        #[cfg(not(test))]
        false
    }

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
        //
        // THE DENOMINATOR IS LEAK-ADJUSTED. That is what lets a partitioned
        // minority finalize its own branch: peers it cannot hear are absent,
        // absent stake leaks, and the leak comes straight out of the total
        // this quorum is measured against. See
        // `a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator`.
        //
        // THE FLOOR. There was a guard for `total_active == 0` and none for
        // "total_active is small", and small is where the chain broke: at
        // 6.25% of the original stake a 4-of-64 partition reaches two thirds
        // of what is left. The denominator may not fall below
        // `MIN_QUORUM_DENOMINATOR_NUM/DEN` of the UNLEAKED total, so the
        // smallest set the leak can ever rescue is a third of the original
        // stake — which is the set the leak exists for — and no set below
        // that can justify however long it waits. See the constant's docs for
        // what the floor does and does not guarantee.
        let unleaked_total: u128 =
            votes.active_set.iter().map(|v| v.effective_stake as u128).sum();
        let leak_adjusted: u128 = stake.values().map(|s| *s as u128).sum();
        let total_active: u128 = if Self::denominator_ignores_leak() {
            // Mutation hook, `cfg(test)` only: the counterfactual denominator,
            // unadjusted. The test above must FLIP to "never finalizes" when
            // this is on, or it is not measuring the mechanism it names.
            unleaked_total
        } else if Self::denominator_floor_disabled() {
            // Mutation hook, `cfg(test)` only: the arithmetic mainnet ran on
            // 2026-08-24, kept runnable so the incident stays reproducible.
            leak_adjusted
        } else {
            let floor = unleaked_total * MIN_QUORUM_DENOMINATOR_NUM / MIN_QUORUM_DENOMINATOR_DEN;
            leak_adjusted.max(floor)
        };

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
        let leaking = since_finality > INACTIVITY_LEAK_THRESHOLD_EPOCHS;
        if leaking {
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

        // ── 4. Leak recovery ───────────────────────────────────────────────
        if !Self::leak_recovery_disabled() {
            //
            // THIS IS THE ZEROING THE RELAUNCH NEEDS. `leaked` used to have a
            // single write path (`+= bite`) with no decay, no reset and no
            // removal, and the denominator subtracts it — so a partition's
            // collapsed quorum was permanent, and would have been inherited
            // by the relaunch, because the node's storage is a block log that
            // is REPLAYED (`bloch-pos-node/src/store.rs`) and `CommittedState`
            // has no constructor that reads a database. There is no stored
            // value for a migration to edit; the accumulator only exists as
            // the output of this fold, so this is the only place it can be
            // cleared identically on 64 machines.
            //
            // WHO recovers, and why it is NOT "everybody when finality is
            // healthy". That was the first shape of this rule and it
            // DEADLOCKS: recovery would be gated on finality, finality is
            // gated on a denominator the leak has collapsed, and a chain that
            // has not finalized in 110 epochs — which is what production
            // shows — could never begin to recover. The rule has to be able
            // to fire DURING a stall or it cannot end one.
            //
            // So the debt is discharged per validator, by participation:
            //   - while the chain is leaking, a validator that cast a valid
            //     vote this epoch recovers; one that did not, leaks (above).
            //     The two are exclusive by construction — same `valid` set,
            //     opposite branch — so no validator is charged and credited
            //     in one epoch.
            //   - once the chain is finalizing again, everyone recovers,
            //     including validators still returning.
            // This is the Altair shape (participate → score down, absent →
            // score up) and it is the shape that makes the accumulator a
            // debt rather than a ratchet.
            //
            // Rate: `max(leaked / QUOTIENT, 1)`. The `max(·, 1)` floor makes
            // it terminate rather than asymptote, exactly as `max(·, 1)` does
            // on the way up. Entries are REMOVED at zero, not left sitting at
            // zero, so a fully recovered state is bit-identical to one that
            // never leaked — §5.5 again: the state is a pure function of the
            // history, and "0" and "absent" must not be two spellings of one
            // fact.
            let mut drained: Vec<u32> = Vec::new();
            for v in votes.active_set {
                if leaking && !valid.contains_key(&v.index) {
                    continue; // absent during a stall: it leaked, it does not recover
                }
                if let Some(leaked) = self.leaked.get_mut(&v.index) {
                    let back = (*leaked / INACTIVITY_LEAK_RECOVERY_QUOTIENT).max(1).min(*leaked);
                    *leaked -= back;
                    if *leaked == 0 {
                        drained.push(v.index);
                    }
                }
            }
            for index in drained {
                self.leaked.remove(&index);
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
    /// **The false quorum, with numbers.**
    ///
    /// The quorum denominator is LEAK-ADJUSTED (`total_active` above). A node
    /// that can only hear `k` of the 64 validators counts the other `64 - k`
    /// as absent; absent stake leaks; the leak is subtracted from the very
    /// total the 2/3 test is measured against. So the denominator shrinks
    /// until it fits inside the minority the node can still hear, and that
    /// minority finalizes its own branch — with no bug in the finality code
    /// and no disagreement about any rule.
    ///
    /// This is why every partition in the 2026-08-24 incident finalized the
    /// same epoch on a different root. Divergent finality is a CONSEQUENCE of
    /// the partition, not an independent fault.
    ///
    /// The leak is also PERMANENT: `leaked` has exactly one write path in this
    /// file (`+= bite`), no decay and no reset, so a validator's stake never
    /// comes back. That is what makes this a relaunch question and not just an
    /// incident question.
    #[test]
    fn a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let (epoch, destroyed_pct) = run_partition(false);
        let epoch = epoch.expect(
            "a 4-of-64 partition must eventually self-finalize — if it never does, the \
             leak-adjusted denominator is not the mechanism and this analysis is wrong",
        );

        // 4 of 64 is 6.25% of the validators. It must NOT be able to justify
        // while the denominator is intact.
        assert!(
            epoch > INACTIVITY_LEAK_THRESHOLD_EPOCHS,
            "the minority justified at epoch {epoch}, at or before the leak threshold — \
             it would have to have done that WITHOUT the leak, which contradicts 4/64 < 2/3"
        );
        println!(
            "FALSE QUORUM: 4 of 64 validators (6.25%) first justified at epoch {epoch} of \
             non-finality, after the leak destroyed {destroyed_pct:.1}% of total network stake"
        );
    }

    /// **The mutation.** Take the leak back out of the denominator and rerun
    /// the identical scenario. The minority must now NEVER finalize. If it
    /// still does, the test above is passing for some other reason and proves
    /// nothing about the leak.
    #[test]
    fn without_the_leak_in_the_denominator_the_minority_never_finalizes() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        tests_hook::IGNORE_LEAK_IN_DENOMINATOR.store(true, std::sync::atomic::Ordering::Relaxed);
        let (epoch, _) = run_partition(true);
        tests_hook::IGNORE_LEAK_IN_DENOMINATOR.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            epoch, None,
            "MUTATION DID NOT BITE: with an unadjusted denominator a 4-of-64 minority still \
             justified at epoch {epoch:?}. Either the hook is not wired or the finalization \
             in the sibling test is not caused by the leak."
        );
        println!("MUTATION: with the leak removed from the denominator, 4 of 64 never justified");
    }

    /// The cumulative leak never decreases — there is no decay and no reset,
    /// which is the whole reason a relaunch inherits it.
    #[test]
    fn the_leak_only_ever_grows() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        // Pre-fix arithmetic on purpose — this test is the record of WHY the
        // relaunch needed a zeroing at all. The post-fix behaviour (the
        // accumulator comes back down) is
        // `the_leak_recovers_once_finality_is_healthy_again`.
        legacy_arithmetic(true);
        let committee: Vec<Validator> = (0..64u32).map(|i| validator(i, STAKE_EACH)).collect();
        let mut st = FinalityState::new(genesis());
        let mut prev = 0u64;
        for e in 1..=40u64 {
            let src = st.current_justified();
            let atts: Vec<(u32, AttestationData)> =
                (0..4u32).map(|v| vote(v, e, root(e as u8), src)).collect();
            st.process_epoch(&EpochVotes {
                epoch: e,
                active_set: &committee,
                attestations: &atts,
            })
            .unwrap();
            let now = st.leaked_of(40);
            assert!(
                now >= prev,
                "epoch {e}: leaked_of(40) went DOWN, {prev} -> {now}; if the leak can heal, \
                 the relaunch argument changes"
            );
            prev = now;
        }
        legacy_arithmetic(false);
        assert!(prev > 0, "validator 40 was absent for 40 epochs and leaked nothing");
        println!(
            "leak permanence: after 40 epochs an absent validator has lost {:.4}% of its stake, \
             and no code path gives any of it back",
            prev as f64 / STAKE_EACH as f64 * 100.0
        );
    }

    // ── THE FOURTH ENSAIO ───────────────────────────────────────────────
    // A clean devnet inherits NO leak, so every other scenario in this
    // repository can go green while mainnet comes back up broken. This one
    // starts from an accumulated leak, which is the state the relaunch
    // actually begins in.

    /// Replay the 2026-08-24 partition under the arithmetic mainnet ran, and
    /// hand back the leak accumulator it produced. This is not a fixture: it
    /// is the same fold, driven by the same votes, and it is how the node
    /// itself arrives at this state — `bloch-pos-node`'s storage is an
    /// append-only BLOCK LOG and `CommittedState` has no constructor that
    /// reads a database, so on every boot the leak is re-derived by replaying
    /// exactly this.
    fn mainnet_leak_after(epochs: u64) -> BTreeMap<u32, u64> {
        // Only the RECOVERY is switched off — that is the pre-fix accumulator,
        // the thing whose absence the relaunch inherits. The denominator floor
        // stays on deliberately, because it makes this replay a node with
        // CONTINUOUS non-finality: production reports 53-56 and 90-110 epoch
        // delays, and those are nodes that never reached quorum, not the one
        // node that self-justified. (With the floor off the 4-node partition
        // justifies at epoch 25, which resets the leak clock and turns the
        // schedule into a slower sawtooth — that node leaks less, so modelling
        // the stalled majority is both the common case and the conservative
        // one for the roster split.)
        tests_hook::DISABLE_LEAK_RECOVERY.store(true, std::sync::atomic::Ordering::Relaxed);
        let committee: Vec<Validator> = (0..64u32).map(|i| validator(i, STAKE_EACH)).collect();
        let mut st = FinalityState::new(genesis());
        for e in 1..=epochs {
            let src = st.current_justified();
            let atts: Vec<(u32, AttestationData)> =
                (0..4u32).map(|v| vote(v, e, root(e as u8), src)).collect();
            st.process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &atts })
                .unwrap();
        }
        assert_eq!(
            st.finalized().epoch,
            0,
            "the generator must model a node in CONTINUOUS non-finality; it finalized"
        );
        tests_hook::DISABLE_LEAK_RECOVERY.store(false, std::sync::atomic::Ordering::Relaxed);
        st.leaked.clone()
    }

    /// **The relaunch, with the disease already in the state.**
    ///
    /// Phase 1 — mainnet as it is: 60 of 64 validators unreachable for 56
    /// epochs, the delay production actually reports. Under the shipped
    /// arithmetic the 4-node partition finalizes alone and 60 validators are
    /// leaked to EXACTLY zero.
    ///
    /// Phase 2 — the relaunch as it was planned: all 64 nodes stop, take the
    /// same storage, take a fixed binary, restart together, and every one of
    /// the 64 validators comes back and votes honestly for the same root. It
    /// must be shown that this STILL does not finalize, because the leak came
    /// back with the storage. That is the whole point of this scenario.
    ///
    /// Phase 3 — the same relaunch with the accumulator able to recover.
    /// Finality must return, the accumulator must reach zero, and the
    /// denominator must be the full unleaked total again.
    #[test]
    fn the_fourth_ensaio_a_relaunch_that_inherits_the_leak() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let committee: Vec<Validator> = (0..64u32).map(|i| validator(i, STAKE_EACH)).collect();
        let unleaked_total = STAKE_EACH as u128 * 64;

        // ── Phase 1 ────────────────────────────────────────────────────────
        // 56 epochs: the middle of production's reported 53-56 band.
        let inherited = mainnet_leak_after(56);
        let zeroed: Vec<u32> =
            inherited.iter().filter(|(_, l)| **l == STAKE_EACH).map(|(v, _)| *v).collect();
        assert_eq!(
            zeroed.len(),
            60,
            "phase 1: after 56 epochs the 60 unreachable validators must be at EXACTLY zero, \
             which is the precondition the e1400 roster split needs"
        );
        let surviving: u128 =
            committee.iter().map(|v| (v.effective_stake - inherited.get(&v.index).copied().unwrap_or(0)) as u128).sum();
        println!(
            "PHASE 1 (mainnet today): 60 of 64 validators leaked to EXACTLY zero after 56 \
             epochs. The leak-adjusted denominator is {:.2}% of the unleaked total.",
            surviving as f64 / unleaked_total as f64 * 100.0
        );

        // ── Phase 2 ────────────────────────────────────────────────────────
        // The relaunch WITHOUT the zeroing: same accumulator, everyone back,
        // everyone honest, everyone voting for one root.
        let mut no_zeroing = FinalityState::new(genesis());
        no_zeroing.leaked = inherited.clone();
        tests_hook::DISABLE_LEAK_RECOVERY.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut ever_justified = None;
        for e in 1..=40u64 {
            let src = no_zeroing.current_justified();
            let atts: Vec<(u32, AttestationData)> =
                (0..64u32).map(|v| vote(v, e, root(e as u8), src)).collect();
            let out = no_zeroing
                .process_epoch(&EpochVotes {
                    epoch: e,
                    active_set: &committee,
                    attestations: &atts,
                })
                .unwrap();
            if out.justified.is_some() {
                ever_justified = Some(e);
                break;
            }
        }
        tests_hook::DISABLE_LEAK_RECOVERY.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            ever_justified, None,
            "phase 2: the relaunch finalized at epoch {ever_justified:?} WITHOUT the accumulator \
             being cleared — then the storage does not carry the disease and the zeroing is \
             not needed. Check this before believing the rest."
        );
        println!(
            "PHASE 2 (relaunch, accumulator NOT cleared): all 64 validators back, all honest, \
             all voting one root — and 40 epochs later the chain has justified NOTHING. The \
             storage brought the collapsed denominator back with it."
        );

        // ── Phase 3 ────────────────────────────────────────────────────────
        // Identical relaunch, accumulator now able to recover.
        let mut healed = FinalityState::new(genesis());
        healed.leaked = inherited.clone();
        let mut justified_at = None;
        let mut finalized_at = None;
        let mut drained_at = None;
        for e in 1..=400u64 {
            let src = healed.current_justified();
            let atts: Vec<(u32, AttestationData)> =
                (0..64u32).map(|v| vote(v, e, root(e as u8), src)).collect();
            let out = healed
                .process_epoch(&EpochVotes {
                    epoch: e,
                    active_set: &committee,
                    attestations: &atts,
                })
                .unwrap();
            if out.justified.is_some() && justified_at.is_none() {
                justified_at = Some(e);
            }
            if out.finalized.is_some() && finalized_at.is_none() {
                finalized_at = Some(e);
            }
            if healed.leaked.is_empty() && drained_at.is_none() {
                drained_at = Some(e);
                break;
            }
        }
        let j = justified_at.expect("phase 3: the relaunch must justify");
        let f = finalized_at.expect("phase 3: the relaunch must finalize");
        let d = drained_at.expect("phase 3: the accumulator must reach zero");
        assert!(healed.leaked.is_empty(), "the accumulator must be EMPTY, not merely small");
        // Bit-identical to a state that never leaked: entries removed, not
        // left sitting at zero (§5.5).
        assert_eq!(
            healed.leaked,
            BTreeMap::new(),
            "a fully recovered accumulator must be indistinguishable from one that never leaked"
        );
        for v in &committee {
            assert_eq!(
                healed.leaked_of(v.index),
                0,
                "validator {} still carries leak after the accumulator drained",
                v.index
            );
        }
        println!(
            "PHASE 3 (relaunch, accumulator recovers): justified at epoch {j}, finalized at \
             epoch {f}, accumulator fully drained at epoch {d} — denominator back to 100% of \
             the unleaked total, and every one of the 64 validators has its full weight and \
             its committee seat back."
        );

        // ── The property the relaunch is FOR ───────────────────────────────
        // With the accumulator healed and the floor in place, run the 2026-08-24
        // partition again from the recovered state. It must not self-justify.
        let mut post = healed.clone();
        let mut minority_justified = None;
        let start = post.next_epoch;
        for e in start..start + 120 {
            let src = post.current_justified();
            let atts: Vec<(u32, AttestationData)> =
                (0..4u32).map(|v| vote(v, e, root((e % 251) as u8), src)).collect();
            let out = post
                .process_epoch(&EpochVotes {
                    epoch: e,
                    active_set: &committee,
                    attestations: &atts,
                })
                .unwrap();
            if out.justified.is_some() {
                minority_justified = Some(e);
                break;
            }
        }
        assert_eq!(
            minority_justified, None,
            "THE RELAUNCH DOES NOT HOLD: a 4-of-64 partition justified alone at epoch \
             {minority_justified:?} on the healed chain. The floor is not doing its job."
        );
        println!(
            "AFTER: the identical 4-of-64 partition that justified at epoch 25 before the fix \
             cannot justify at all in 120 epochs. A minority no longer finalizes alone."
        );
    }

    /// The leak still WORKS. Two properties that must survive the fix, or the
    /// fix has quietly turned a liveness mechanism into a no-op.
    #[test]
    fn the_leak_still_buys_liveness_back_after_the_fix() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        // A 60/40 stall — a MAJORITY present, which is what the leak exists
        // for. It must still recover, and the absentees must still pay.
        let committee =
            [validator(0, 60_000_000), validator(1, 20_000_000), validator(2, 20_000_000)];
        let mut st = FinalityState::new(genesis());
        let mut recovered = None;
        for e in 1..=60u64 {
            let src = st.current_justified();
            let atts = [vote(0, e, root(e as u8), src)];
            let out = st
                .process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &atts })
                .unwrap();
            if out.finalized.is_some() {
                recovered = Some(e);
                break;
            }
        }
        let e = recovered.expect(
            "THE FIX BROKE THE LEAK: a 60/40 stall no longer recovers. The floor is above the \
             fraction the leak is supposed to rescue, and that is a founder decision, not a \
             side effect — report it as one.",
        );
        assert!(st.leaked_of(1) > 0 && st.leaked_of(2) > 0, "the absentees must still pay");
        assert_eq!(st.leaked_of(0), 0, "a validly voting member must never leak");
        println!(
            "LEAK STILL WORKS: 60/40 stall recovered at epoch {e}; the absent 40% paid \
             {} and {} satoshis.",
            st.leaked_of(1),
            st.leaked_of(2)
        );
    }

    /// The post-fix half of `the_leak_only_ever_grows`: the accumulator does
    /// come back down, and it comes down for the validator that PARTICIPATES,
    /// including while the chain is still stalled — which is the only reason
    /// a chain 110 epochs into non-finality can ever climb out.
    #[test]
    fn the_leak_recovers_once_the_validator_participates_even_during_a_stall() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        let committee: Vec<Validator> = (0..64u32).map(|i| validator(i, STAKE_EACH)).collect();
        let mut st = FinalityState::new(genesis());
        // 30 epochs with validator 40 absent: it accrues a leak, and the
        // chain does not finalize, so it is still leaking at the end.
        for e in 1..=30u64 {
            let src = st.current_justified();
            let atts: Vec<(u32, AttestationData)> =
                (0..4u32).map(|v| vote(v, e, root(e as u8), src)).collect();
            st.process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &atts })
                .unwrap();
        }
        let peak = st.leaked_of(40);
        assert!(peak > 0, "control: validator 40 must have accrued a leak to recover from");
        assert_eq!(st.finalized().epoch, 0, "control: the chain must still be stalled");

        // Validator 40 comes back. Nothing else changes — the chain is still
        // not finalizing. Its debt must start falling anyway.
        let mut prev = peak;
        for e in 31..=60u64 {
            let src = st.current_justified();
            let mut atts: Vec<(u32, AttestationData)> =
                (0..4u32).map(|v| vote(v, e, root(e as u8), src)).collect();
            atts.push(vote(40, e, root(e as u8), src));
            st.process_epoch(&EpochVotes { epoch: e, active_set: &committee, attestations: &atts })
                .unwrap();
            let now = st.leaked_of(40);
            assert!(
                now < prev || now == 0,
                "epoch {e}: validator 40 voted and its leak did not fall ({prev} -> {now}); \
                 recovery gated on finality would deadlock a stalled chain forever"
            );
            prev = now;
        }
        assert!(prev < peak, "validator 40's debt must be strictly smaller than its peak");
        println!(
            "RECOVERY DURING A STALL: validator 40's leak fell from {peak} to {prev} over 30 \
             epochs of participation, with the chain never finalizing once."
        );
        // Meanwhile a validator that stayed away kept paying.
        assert!(st.leaked_of(41) > st.leaked_of(40), "the still-absent validator must owe more");
    }

    const STAKE_EACH: u64 = 1_000_000_000;

    /// Serializes the tests that touch the process-global mutation switch.
    static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// **REGRESSION — this test used to prove the defect; it now pins the fix.**
    ///
    /// Until 2026-08-24 it asserted `assert_ne!` on the two partitions and
    /// `justified == None`, and it was right to: the leak did not only shrink
    /// the denominator, it re-shuffled the COMMITTEE, and the two call paths
    /// did not shuffle the same way.
    ///
    /// `transition.rs` holds two rosters for one epoch:
    ///
    /// - `compute_post_state` step 8 admits an attestation against
    ///   `committee_for_slot(&seed, slot, &roster)` where `roster =
    ///   st.consensus_roster_at(st.epoch)` — the **leaked** roster.
    /// - `close_epoch` tallies the epoch against `votes_from_partition(closing,
    ///   &roster, ...)` where `roster = st.duty_roster_at(closing)` — the
    ///   **unleaked** roster.
    ///
    /// `with_leak_applied` does not drop a fully-leaked validator, it sets
    /// `effective_stake = 0`. `committees::epoch_committees` then filtered
    /// `effective_stake > 0` **before** the Fisher-Yates shuffle, so the two
    /// rosters shuffled lists of different LENGTH — 64 vs 63 — and a
    /// Fisher-Yates over a different length is a different permutation
    /// everywhere, not a permutation with one element removed. Attestations the
    /// block admitted were dropped at the boundary tally, the numerator
    /// collapsed, and nothing finalized: 63 of 64 honest validators voting one
    /// root, the boundary keeping 4 of them, justification `None`.
    ///
    /// **The filter is gone.** Committee membership is now a pure function of
    /// (seed, epoch, index set); stake decides weight only. The two rosters
    /// carry the same index set and therefore partition identically, whatever
    /// the leak does — see `committees::epoch_committees`'s docs for why that
    /// was chosen over dropping the leaked validator on both paths. So every
    /// assertion below is the mirror of the one it replaces, and the
    /// measurement printout is kept so the number that used to be 6.3% is on
    /// the record next to the number that replaced it.
    ///
    /// The mutation that shows this can still go red lives in
    /// `committees::tests::rehearsal_restoring_the_filter_reopens_the_roster_split`.
    #[test]
    fn a_single_fully_leaked_validator_makes_the_two_rosters_partition_differently() {
        let _g = HOOK.lock().unwrap_or_else(|e| e.into_inner());
        // 64 validators. Task 2 shows every absent validator on a chain with
        // 49+ epochs of non-finality is at EXACTLY zero, so one is generous.
        let duty: Vec<Validator> = (0..64u32).map(|i| validator(i, STAKE_EACH)).collect();
        let consensus: Vec<Validator> = duty
            .iter()
            .map(|v| Validator {
                index: v.index,
                // exactly what transition::with_leak_applied produces
                effective_stake: if v.index == 7 { 0 } else { v.effective_stake },
            })
            .collect();

        let seed = [0x5Au8; 32];
        let epoch = 1u64;
        let step8 = crate::committees::epoch_committees(&seed, epoch, &consensus);
        let boundary = crate::committees::epoch_committees(&seed, epoch, &duty);
        assert_eq!(
            step8, boundary,
            "the leaked and unleaked rosters must now partition IDENTICALLY — this is the \
             assertion that used to be assert_ne!, and flipping it is the whole fix"
        );

        // Every validator attests honestly, in the slot STEP 8 admits it for.
        // Perfect participation: 64 of 64 voting — index 7 keeps its seat now,
        // it just carries no weight.
        let src = genesis();
        let target = root(1);
        let mut atts: Vec<(u32, AttestationData)> = Vec::new();
        for (slot_idx, members) in step8.iter().enumerate() {
            for v in members {
                atts.push((
                    *v,
                    AttestationData {
                        slot: epoch * crate::params::SLOTS_PER_EPOCH + slot_idx as u64,
                        head: target,
                        source_epoch: src.epoch,
                        source_root: src.root,
                        target_epoch: epoch,
                        target_root: target,
                    },
                ));
            }
        }
        let admitted = atts.len();
        assert_eq!(admitted, 64, "the fully-leaked validator must still hold a seat");

        // Now the boundary tally, against the UNLEAKED roster — the real
        // production function, the real seed, the real partition filter.
        let mut accepted = Vec::new();
        let ev = votes_from_partition(epoch, &duty, &atts, &seed, &mut accepted);
        let survived = ev.attestations.len();
        println!(
            "ROSTER UNIFIED: step 8 admitted {admitted} honest attestations; the boundary \
             kept {survived} ({:.1}%). Before 2026-08-24 this read 4 of 63 (6.3%).",
            survived as f64 / admitted as f64 * 100.0
        );
        assert_eq!(
            survived, admitted,
            "the boundary kept {survived} of {admitted} — the two partitions have diverged \
             again and the defect is back"
        );

        // And therefore: quorum, from a network in which every reachable
        // validator voted honestly for the same root.
        let mut st = FinalityState::new(genesis());
        let out = st.process_epoch(&ev).unwrap();
        assert_eq!(
            out.justified,
            Some(Checkpoint { epoch, root: target }),
            "all 64 validators voted for one root and it did NOT justify — the \
             roster split is back, or something else now blocks finality"
        );

        // The control: feed step 8's own roster to the boundary. It must give
        // the same answer, because the whole point is that there is no longer
        // a "step 8 roster" and a "boundary roster" as far as membership goes.
        let mut accepted2 = Vec::new();
        let ev2 = votes_from_partition(epoch, &consensus, &atts, &seed, &mut accepted2);
        assert_eq!(ev2.attestations.len(), admitted, "control: same roster keeps every vote");
        let mut st2 = FinalityState::new(genesis());
        let out2 = st2.process_epoch(&ev2).unwrap();
        assert_eq!(
            out2.justified,
            Some(Checkpoint { epoch, root: target }),
            "control: the leaked roster must justify the same checkpoint as the unleaked one"
        );
        println!(
            "CONTROL: the identical votes justify at epoch {epoch} against EITHER roster. \
             There is one partition now, not two."
        );
    }

    /// The guard that would have caught the above is a `debug_assert_eq!`, and
    /// the profile mainnet runs compiles it out. Pinned so nobody has to take
    /// the Cargo.toml on faith.
    #[test]
    fn the_only_guard_on_the_roster_split_is_absent_from_a_release_build() {
        assert!(
            cfg!(debug_assertions),
            "this test build has debug assertions off"
        );
        let manifest = include_str!("../../../Cargo.toml");
        let release = manifest
            .split("[profile.release]")
            .nth(1)
            .expect("workspace Cargo.toml must have [profile.release]")
            .split("\n[")
            .next()
            .unwrap();
        assert!(
            !release.contains("debug-assertions"),
            "[profile.release] now sets debug-assertions; if it is TRUE the guard is live \
             and this test should be replaced by the assertion itself"
        );
    }

    fn run_partition(mutated: bool) -> (Option<u64>, f64) {
        // The pre-fix arithmetic, deliberately: this function is the RECORD of
        // what mainnet ran on 2026-08-24, so it must keep running it after the
        // floor and the recovery landed. Both switches are `cfg(test)` and
        // both are reset before this returns.
        legacy_arithmetic(true);
        let out = run_partition_inner(mutated);
        legacy_arithmetic(false);
        out
    }

    /// Turn the two 2026-08-25 corrections off (`true`) or back on (`false`).
    fn legacy_arithmetic(on: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        tests_hook::DISABLE_DENOMINATOR_FLOOR.store(on, Relaxed);
        tests_hook::DISABLE_LEAK_RECOVERY.store(on, Relaxed);
    }

    fn run_partition_inner(mutated: bool) -> (Option<u64>, f64) {
        let committee: Vec<Validator> = (0..64u32).map(|i| validator(i, STAKE_EACH)).collect();
        let mut st = FinalityState::new(genesis());
        let horizon = if mutated { 120 } else { 60 };
        for e in 1..=horizon {
            let src = st.current_justified();
            let atts: Vec<(u32, AttestationData)> =
                (0..4u32).map(|v| vote(v, e, root(e as u8), src)).collect();
            let out = st
                .process_epoch(&EpochVotes {
                    epoch: e,
                    active_set: &committee,
                    attestations: &atts,
                })
                .unwrap();
            if out.justified.is_some() {
                let destroyed: u64 = (0..64u32).map(|v| st.leaked_of(v)).sum();
                let total = STAKE_EACH as u128 * 64;
                return (Some(e), destroyed as f64 / total as f64 * 100.0);
            }
        }
        (None, 0.0)
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

/// Mutation switch for the leak-denominator test. `cfg(test)`, so it cannot
/// exist in a shipped binary.
#[cfg(test)]
mod tests_hook {
    use std::sync::atomic::AtomicBool;
    /// Counterfactual: drop the leak out of the denominator entirely.
    pub(super) static IGNORE_LEAK_IN_DENOMINATOR: AtomicBool = AtomicBool::new(false);
    /// Reproduce the pre-fix denominator: leak-adjusted, no floor.
    pub(super) static DISABLE_DENOMINATOR_FLOOR: AtomicBool = AtomicBool::new(false);
    /// Reproduce the pre-fix accumulator: monotonic, never recovers.
    pub(super) static DISABLE_LEAK_RECOVERY: AtomicBool = AtomicBool::new(false);
}
