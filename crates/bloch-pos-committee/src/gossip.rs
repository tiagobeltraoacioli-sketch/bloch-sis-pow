// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attestation propagation policy — pure, no network.
//!
//! This module is the application half of `docs/specs/BLOCH-ATTESTATION-GOSSIP.md`
//! (§6.1–§6.3, §8.1), adapted to the partition model that superseded the
//! sampled 8+128 committees (see the seal at the top of that document and
//! `committees.rs`): there is now **one** attestation flow, and a validator's
//! duty is the single slot of each epoch its partition committee serves. The
//! transport half — topics, `TopicScoreParams`, token buckets, the ingest
//! channel — belongs to the node; nothing here touches a socket, a clock, or
//! gossipsub. The node feeds arrivals in and maps the returned decision onto
//! `report_message_validation_result`.
//!
//! ## The three-verb contract, and why Hold exists
//!
//! Every arriving attestation resolves to exactly one of:
//!
//! - **Reject** — a provable protocol violation (non-member, bad signature,
//!   malformed checkpoints). The node penalizes the forwarding peer.
//! - **Ignore** — true but useless (duplicate, outside the window, over the
//!   equivocation cap). Dropped silently, **never** penalized.
//! - **Hold** — references a block root we have not imported yet.
//!
//! Hold is the load-bearing verb. An attestation for slot `s` votes for the
//! head produced *in* slot `s`, so at every epoch boundary (and on every fast
//! block) the attestation racing ahead of its block is guaranteed ordinary
//! behavior, not an attack. This network's gossipsub mesh has collapsed twice
//! (2026-08-07) from scoring honest peers as offenders; classifying this race
//! as invalid would graylist honest peers at −100 per frame, every boundary.
//! Hence the hard rule, restated from the spec: **no honest-race path may
//! reach Reject.** Only Reject feeds peer penalties.
//!
//! ## Determinism
//!
//! All collections are B-trees and eviction is by insertion sequence number,
//! so pool state is a pure function of the inputs and the arrival history —
//! and, for honest traffic, the *final* state does not depend on arrival
//! order (an attestation held for a late block converges to the same Accept
//! it would have gotten had the block arrived first; the tests pin this).
//! Nothing here reads a clock: `current_slot` is always an argument.

use crate::attestation::{Attestation, KeyLookup, RejectReason, SignatureVerifier};
use crate::params::SLOTS_PER_EPOCH;
use crate::slashing::SlashingEvidence;
use std::collections::{BTreeMap, BTreeSet};

/// Acceptance window, in slots: two epochs, matching the seen-cache retention
/// and the participation records committed in state (spec §8.1). Outside the
/// window an attestation is stale-node replay — honest but useless — and the
/// correct response is silence, not a score war: the 2026-08-09 backfill
/// incident was one stale node dumping history, and the structural fix is
/// that such a dump is ignored at the edge, capped at "the last two epochs".
pub const ATTESTATION_WINDOW_SLOTS: u64 = 2 * SLOTS_PER_EPOCH;

/// Slots of forward clock-skew tolerance. One slot: a peer whose clock is
/// ahead by a few seconds publishes for a slot we have not entered yet, and
/// that must not count against it. Anything further ahead is ignored (not
/// rejected — clock skew is not provably hostile).
pub const CLOCK_SKEW_SLOTS: u64 = 1;

/// Capacity of the pending (unknown-head) pool, in attestations (spec §6.3:
/// 256 ≈ 1.2 MB of hybrid-signed attestations — a mirror of the block orphan
/// pool). Bounded because entries are held *before* signature verification
/// (see the pipeline order note below), so the pool must stay cheap to fill
/// and cheap to evict. Eviction is FIFO by insertion sequence: deterministic,
/// and under flood the newest — most likely still relevant — entries survive.
pub const MAX_PENDING_ATTESTATIONS: usize = 256;

/// Distinct attestations accepted per duty before further ones are ignored
/// (spec §6.2). Two, because slashing evidence needs exactly a conflicting
/// pair; a third message proves nothing new, and relaying it would let a
/// malicious validator use its own equivocation as an amplification
/// primitive. The cap turns "equivocate freely" into "double your own duty's
/// traffic once, then silence".
pub const MAX_EQUIVOCATIONS_PER_DUTY: usize = 2;

/// Why an attestation was dropped without penalty. Split from [`RejectReason`]
/// at the type level so the node *cannot* accidentally wire an Ignore into a
/// peer penalty — the two-incidents lesson, enforced by the compiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IgnoreReason {
    /// Outside `[current_slot − 64, current_slot + 1]`. Stale replay or clock
    /// skew; neither is provably hostile.
    OutsideWindow,
    /// Already accepted, or an identical copy is already held pending its
    /// block. Two copies of one attestation are one fact.
    Duplicate,
    /// This duty already produced its two distinct (slashable) attestations;
    /// further variants are noise.
    EquivocationLimit,
    /// The node cannot derive the committee for this attestation, because it
    /// cannot reach the branch the attestation names. Not a claim about the
    /// attestation — a statement about what this node holds.
    ///
    /// This is the honest verdict for a node that is behind or syncing, and it
    /// exists so that condition can never be mistaken for a violation. The
    /// `NotInCommittee` Reject below is justified by "both ends compute
    /// membership from the same finalized state"; a node that cannot reach the
    /// branch has no standing to make that claim about anyone.
    Unjudgeable,
    /// The signer is in the committee this node drew, but this node's registry
    /// projection has no key registered at that index — so the signature
    /// cannot be checked at all.
    ///
    /// The sibling of [`Self::Unjudgeable`], and Ignore for the same reason:
    /// it is a statement about what this node holds, not about the
    /// attestation. It is reachable exactly when a validator joined by deposit
    /// and this node has not yet applied the block that registered it. The
    /// peer that relayed the attestation may be perfectly honest and ahead of
    /// us; penalising it would graylist the best-informed peers precisely
    /// during a validator-set change.
    ///
    /// Note this cannot be caused by a *disagreement* about who holds an
    /// index — the registry is append-only with non-reusable indices and
    /// immutable pubkeys, so two states can differ only in whether an index is
    /// present, never in what key it holds. Absence means "behind", full stop.
    UnknownValidator,
    /// This duty already has [`MAX_EQUIVOCATIONS_PER_DUTY`] entries parked in
    /// the pending (unknown-head) pool.
    ///
    /// **R3 NEW-1.** Distinct from [`Self::EquivocationLimit`], which bounds
    /// *accepted* variants: this bounds *pending* ones, so a single duty
    /// cannot monopolise the shared FIFO pool with many differently-headed,
    /// validly-signed variants while its block is still missing. It is
    /// reachable only by a frame whose signature already verified (see the
    /// signature-before-hold ordering in [`AttestationPool::process`]), so —
    /// unlike the other cheap Ignore paths above — every occurrence already
    /// cost one hybrid verification; that is the intended trade (a bounded,
    /// self-funded cost, not a free one).
    PendingDutyLimit,
}

/// The decision on one arriving attestation. The node maps this onto
/// gossipsub's explicit validation verbs: `Accept` → relay + consume,
/// `Ignore`/`Hold` → drop silently (Hold also parks the message here),
/// `Reject` → drop + penalize the forwarding peer.
#[derive(Clone, Debug)]
pub enum GossipDecision {
    /// Valid: relay and feed consensus. If this is the duty's second distinct
    /// attestation, the conflicting pair rides along for the slashing pool —
    /// gossip only *captures* the pair; judging it (double vote? surround?)
    /// is `SlashingState::process`'s job. Boxed because the evidence carries
    /// two full hybrid-signed attestations (~9 KB) while the common case is
    /// `None` — the decision itself must stay cheap to move around.
    Accept { slashing_candidate: Option<Box<SlashingEvidence>> },
    /// Drop silently. Never penalize: every variant is reachable by honest
    /// peers under ordinary timing.
    Ignore(IgnoreReason),
    /// Provable violation. The only decision that may feed peer scoring.
    Reject(RejectReason),
    /// References `missing_root`, which we have not imported. Parked; the
    /// node re-runs it via [`AttestationPool::on_block`] when the block
    /// lands. Not relayed yet — we never relay what we cannot validate.
    Hold { missing_root: [u8; 32] },
}

/// Committee membership, injected. The committee for a slot MUST be derived
/// from committed state (`committees::committee_for_slot` over the finalized
/// parent's registry and beacon mix, §5.5) — never from node-local mutable
/// state; that rule exists because `expected_bits` read from local state
/// split consensus on 2026-08-08. Returned sorted ascending, as
/// `epoch_committees` already guarantees.
pub trait CommitteeLookup {
    fn committee(&self, slot: u64) -> Vec<u32>;
}

impl<F: Fn(u64) -> Vec<u32>> CommitteeLookup for F {
    fn committee(&self, slot: u64) -> Vec<u32> {
        self(slot)
    }
}

/// "Do we have this block?" — injected so the pool never owns a chain view.
pub trait BlockLookup {
    fn is_known(&self, root: &[u8; 32]) -> bool;
}

impl<F: Fn(&[u8; 32]) -> bool> BlockLookup for F {
    fn is_known(&self, root: &[u8; 32]) -> bool {
        self(root)
    }
}

/// A duty is one validator's single attestation obligation: under the
/// partition (committees.rs) each validator serves exactly one slot per
/// epoch, so `(slot, validator)` names the duty with no ambiguity.
type DutyKey = (u64, u32);

/// Data-hash key for exact-duplicate detection. The signing root is used as
/// the content hash: it is already domain-separated SHA3-256 over every field
/// of `AttestationData`, so distinct data cannot collide and no second hash
/// construction needs auditing.
type SeenKey = (u64, u32, [u8; 32]);

/// What we keep per duty: the distinct attestations accepted so far (at most
/// [`MAX_EQUIVOCATIONS_PER_DUTY`]), each with its data hash. Full messages,
/// not just hashes, because the *first* attestation must still be producible
/// as one half of a `SlashingEvidence` when the second arrives.
#[derive(Clone, Debug, Default)]
struct DutyRecord {
    accepted: Vec<([u8; 32], Attestation)>,
}

/// One parked attestation waiting for its block.
#[derive(Clone, Debug)]
struct PendingEntry {
    att: Attestation,
    missing_root: [u8; 32],
}

/// The attestation pool: dedup, equivocation capture, and the pending
/// (unknown-head) queue. Pure state machine — the node owns when to call it.
#[derive(Clone, Debug, Default)]
pub struct AttestationPool {
    /// Accepted attestations per duty. Bounded by pruning: retention is the
    /// acceptance window, so at most two epochs of the active set.
    seen: BTreeMap<DutyKey, DutyRecord>,
    /// Pending entries by insertion sequence — the FIFO eviction order.
    pending: BTreeMap<u64, PendingEntry>,
    /// Index: missing block root → pending sequence numbers, so a block
    /// arrival releases exactly its own waiters without a scan.
    pending_by_root: BTreeMap<[u8; 32], BTreeSet<u64>>,
    /// Exact-duplicate guard for parked entries: holding the same attestation
    /// twice would double-count it on release and waste pool capacity.
    pending_keys: BTreeSet<SeenKey>,
    /// Count of currently-parked entries per duty (R3 NEW-1). Bounds a single
    /// `(slot, validator)` duty's footprint in the shared pending pool to
    /// [`MAX_EQUIVOCATIONS_PER_DUTY`], independently of — and in addition to
    /// — the global FIFO cap ([`MAX_PENDING_ATTESTATIONS`]) and the
    /// accepted-side cap (`DutyRecord::accepted`, same limit). Entries are
    /// removed from this map the moment they leave `pending` (release or
    /// eviction), in [`AttestationPool::evict`], so it never drifts from
    /// `pending`'s actual contents.
    pending_by_duty: BTreeMap<DutyKey, usize>,
    /// Monotone insertion counter. Never reused, so FIFO order is total and
    /// deterministic across identical histories.
    next_seq: u64,
}

impl AttestationPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide on one arriving attestation.
    ///
    /// Pipeline order is cheapest test first, with ONE deliberate exception
    /// (R3 NEW-1, see below): everything before the signature is nanoseconds,
    /// the hybrid verify is the only expensive step, and for every outcome
    /// *other* than Hold the ordering is exactly the spec's — the only way to
    /// make this node burn a 4.6 KB hybrid verify is an in-window, novel,
    /// member-indexed attestation.
    ///
    ///   1. slot window          → outside: Ignore (stale/skewed ≠ hostile)
    ///   2. checkpoint sanity    → source ≥ target: Reject (provably malformed)
    ///   3. dedup + equivocation cap → Ignore
    ///   4. duty membership      → non-member: Reject (cannot be honest skew:
    ///      membership is a deterministic function of committed state both
    ///      sides can compute)
    ///   5. hybrid signature     → bad: Reject; unresolvable key: Ignore
    ///   6. head/target known?   → unknown: Hold (capped per duty)
    ///   7. Accept
    ///
    /// ## R3 NEW-1 — why signature verification moved *before* Hold
    ///
    /// The original spec order held first and verified only on release
    /// (`on_block`), because Hold is "free" for an honest race (the block is
    /// simply not here yet) and the hybrid verify is the expensive step to
    /// defer. That reasoning silently assumed a parked entry costs the
    /// *attacker* something too. It does not: `MAX_EQUIVOCATIONS_PER_DUTY`
    /// counted only *accepted* attestations, so an attacker who merely knows
    /// a real committee-member index (public via [`crate::schedule`]) could
    /// send [`MAX_PENDING_ATTESTATIONS`] frames with no signature at all, one
    /// per duty slot, and evict every honest boundary-race vote already
    /// parked — at zero cost to the attacker and zero peer-score cost
    /// (Hold → Ignore is, correctly, never a penalty).
    ///
    /// The fix verifies the signature first whenever the key is resolvable,
    /// which is always safe to do *before* knowing whether the referenced
    /// blocks are known: `keys` is a registry projection at a fixed epoch
    /// (`rolled_to(epoch)`, or the block's pre-state) that does not depend on
    /// `att.data.head` or `att.data.target_root` having been imported — i.e.
    /// key resolution and signature verification are head-independent. So
    /// this reordering cannot turn an honest race into a Reject: a bad
    /// signature was always going to be Reject once checked (step 6 in the
    /// old order), and a good signature was always going to reach Hold; only
    /// *which pool state* an unverifiable frame can occupy changes — from
    /// "parked, unverified" to "never parked". An unresolvable key (this
    /// node is behind — see [`IgnoreReason::UnknownValidator`]) still cannot
    /// be checked, so it still cannot be parked; it Ignores exactly as
    /// before, just one step earlier.
    ///
    /// This is *not* a consensus-relevant change and needs no activation
    /// gate: `AttestationPool` is node-local, ephemeral relay/scoring state
    /// (see the module doc — "a verdict here is a relay/scoring decision, not
    /// a validity verdict"). It is never part of `state_root`, never
    /// serialized into `blocks.log`, and no two honest nodes are required to
    /// agree on it. Replaying `blocks.log` is therefore byte-identical
    /// whether or not this fix is present; only in-flight gossip scoring
    /// changes, on every node simultaneously since the change is compiled in,
    /// not epoch-triggered.
    ///
    /// Independently, a per-duty cap on *pending* entries (also
    /// `MAX_EQUIVOCATIONS_PER_DUTY`, mirroring the accepted-side cap) stops a
    /// duty's own key — the only key that can now reach Hold for that duty —
    /// from flooding the pool with many distinct, differently-headed,
    /// validly-signed variants while genuinely undecided which one is real.
    pub fn process(
        &mut self,
        att: Attestation,
        current_slot: u64,
        committees: &impl CommitteeLookup,
        blocks: &impl BlockLookup,
        verifier: &dyn SignatureVerifier,
        keys: &dyn KeyLookup,
    ) -> GossipDecision {
        let slot = att.data.slot;

        // 1. Window. Both sides are Ignore, not Reject: behind is a stale
        //    node replaying its view, ahead is clock skew. Neither is
        //    provable hostility, and penalizing either graylists honest
        //    peers — the exact failure this module exists to prevent.
        //
        //    Saturating on purpose: these are window BOUNDS, and a bound that
        //    saturates at u64::MAX is still the same bound. `slot` is
        //    peer-supplied, so an attestation claiming a slot within
        //    ATTESTATION_WINDOW_SLOTS of u64::MAX used to trip overflow-checks
        //    here and abort the node; it is now Ignored like any other
        //    out-of-window slot (a saturated `slot + W` is >= current_slot,
        //    and such a slot exceeds `current_slot + skew` for every
        //    current_slot the chain can reach). For every non-overflowing
        //    input the decision is unchanged.
        if slot.saturating_add(ATTESTATION_WINDOW_SLOTS) < current_slot
            || slot > current_slot.saturating_add(CLOCK_SKEW_SLOTS)
        {
            return GossipDecision::Ignore(IgnoreReason::OutsideWindow);
        }

        // 2. Checkpoint sanity. A source at or past its target can never be
        //    produced by honest code operating on any chain view — it is
        //    malformed by construction, so it is safe to penalize.
        if att.data.source_epoch >= att.data.target_epoch {
            return GossipDecision::Reject(RejectReason::NonMonotonicCheckpoints);
        }

        let duty: DutyKey = (slot, att.validator);
        let data_hash = att.data.signing_root();

        // 3a. Exact duplicate — already accepted, or an identical copy is
        //     already parked. One fact, one copy: Ignore, never penalize.
        //     (Content-hash dedup is *correct* for attestations — they are
        //     data, not requests; the sync-topic nonce lesson cuts the other
        //     way here. No nonces, ever.)
        if let Some(rec) = self.seen.get(&duty) {
            if rec.accepted.iter().any(|(h, _)| *h == data_hash) {
                return GossipDecision::Ignore(IgnoreReason::Duplicate);
            }
            // 3b. Equivocation cap. Two distinct attestations are already
            //     accepted for this duty — a complete slashable pair. A
            //     third variant adds no evidence and relaying it would
            //     amplify the equivocator's own traffic. Checked before the
            //     signature so variants cannot burn verify budget either.
            if rec.accepted.len() >= MAX_EQUIVOCATIONS_PER_DUTY {
                return GossipDecision::Ignore(IgnoreReason::EquivocationLimit);
            }
        }
        if self.pending_keys.contains(&(slot, att.validator, data_hash)) {
            return GossipDecision::Ignore(IgnoreReason::Duplicate);
        }

        // 4. Duty membership, from committed state. Binary search: committees
        //    are sorted by construction (committees.rs sorts each committee).
        //    A non-member cannot be honest timing skew — both ends compute
        //    membership from the same finalized state — so this is a Reject.
        if committees.committee(slot).binary_search(&att.validator).is_err() {
            return GossipDecision::Reject(RejectReason::NotInCommittee);
        }

        // 5. Signature — moved before the head/target check (R3 NEW-1; see
        //    the long comment on this function for the replay-safety and
        //    ordering argument). Both halves of the hybrid suite, via the
        //    injected verifier. Only verified attestations are ever recorded
        //    or parked, so every equivocation pair we hand to slashing
        //    already carries two valid signatures — a forger cannot frame a
        //    validator here.
        //
        //    The key comes from the SAME state snapshot that drew the
        //    committee checked in step 4 — `rolled_to(epoch)` at the node.
        //    That is deliberate and it is the only defensible pairing: an
        //    attestation is authorised by (index in committee, key at index),
        //    and taking the two halves from different states is precisely the
        //    inconsistency this change removes. It reads node-local state, but
        //    it introduces no NEW node-local dependency: membership already
        //    came from that projection, and the old code took the key from a
        //    boot-time constant, which is worse — it could not follow the
        //    chain at all.
        //
        //    A verdict here is a relay/scoring decision, not a validity
        //    verdict: an attestation that arrives inside a block is re-judged
        //    by the transition against that block's pre-state. So a node whose
        //    projection lags and answers `UnknownValidator` loses propagation,
        //    never consensus. Reject-vs-Ignore matters for exactly that
        //    reason — see below.
        let Some(pubkey) = keys.pubkey(att.validator) else {
            // IGNORE, not Reject. A committee member this node cannot resolve
            // is a node that is BEHIND — its registry projection has not yet
            // caught up to the deposit that added the validator — and the
            // module's own rule is that "behind" is never provable hostility
            // (step 1 makes the same call for a stale slot). Rejecting here
            // would penalise the peer that relayed a perfectly valid
            // attestation and graylist honest peers during exactly the window
            // when a new validator joins: the mesh-collapse failure this
            // module exists to prevent. It also cannot be parked (R3 NEW-1):
            // an unresolvable key means this node cannot verify it, ever,
            // from this projection, so holding it would occupy a pending slot
            // that can never be cashed in by this node.
            return GossipDecision::Ignore(IgnoreReason::UnknownValidator);
        };
        if !verifier.verify_with_key(pubkey, &data_hash, &att.signature) {
            return GossipDecision::Reject(RejectReason::BadSignature);
        }

        // 6. Referenced blocks. The attestation votes for the head produced
        //    in its own slot, so arriving before that block is *guaranteed*
        //    ordinary propagation timing — milliseconds of race, every
        //    boundary. Hold, count nothing against anyone — but only up to
        //    the per-duty cap (R3 NEW-1): a frame reaching this point already
        //    carries a signature that verified for `duty`, so a further
        //    distinct variant beyond the cap can only come from `duty`'s own
        //    key, not from an outside attacker; it is bounded exactly like
        //    the accepted side to stop that key from monopolising shared pool
        //    capacity. The target root gets the same treatment as the head:
        //    at an epoch boundary the target IS the block just produced, and
        //    it races too.
        for root in [att.data.head, att.data.target_root] {
            if !blocks.is_known(&root) {
                let pending_for_duty = *self.pending_by_duty.get(&duty).unwrap_or(&0);
                if pending_for_duty >= MAX_EQUIVOCATIONS_PER_DUTY {
                    return GossipDecision::Ignore(IgnoreReason::PendingDutyLimit);
                }
                return self.hold(duty, att, root, data_hash);
            }
        }

        // 7. Record. Second distinct data for the duty = equivocation:
        //    capture the pair for the slashing pool but still Accept — both
        //    messages must propagate, because the rest of the network needs
        //    the same evidence (spec §6.2: "both are needed as slashing
        //    evidence").
        let rec = self.seen.entry(duty).or_default();
        let slashing_candidate = rec.accepted.first().map(|(_, first)| {
            Box::new(SlashingEvidence { first: first.clone(), second: att.clone() })
        });
        rec.accepted.push((data_hash, att));
        GossipDecision::Accept { slashing_candidate }
    }

    /// A block was imported: re-run every attestation that was waiting on it.
    ///
    /// Call *after* the block is queryable through the [`BlockLookup`], or
    /// the waiters will simply be re-held. Entries are replayed in insertion
    /// order (deterministic), and each goes through the full pipeline again —
    /// so an attestation still missing its *other* root is re-held under that
    /// root, and one whose signature turns out bad is rejected now. Returns
    /// each released attestation with its final decision; the node relays the
    /// Accepts (they were never relayed while parked).
    pub fn on_block(
        &mut self,
        root: &[u8; 32],
        current_slot: u64,
        committees: &impl CommitteeLookup,
        blocks: &impl BlockLookup,
        verifier: &dyn SignatureVerifier,
        keys: &dyn KeyLookup,
    ) -> Vec<(Attestation, GossipDecision)> {
        let seqs = match self.pending_by_root.remove(root) {
            Some(s) => s,
            None => return Vec::new(),
        };
        let mut out = Vec::with_capacity(seqs.len());
        for seq in seqs {
            // BTreeSet iterates ascending: FIFO replay.
            let entry = match self.pending.remove(&seq) {
                Some(e) => e,
                None => continue, // evicted after indexing; nothing to do
            };
            let key = (entry.att.data.slot, entry.att.validator, entry.att.data.signing_root());
            self.pending_keys.remove(&key);
            let att = entry.att;
            let decision =
                self.process(att.clone(), current_slot, committees, blocks, verifier, keys);
            out.push((att, decision));
        }
        out
    }

    /// Drop everything the acceptance window has moved past. Deterministic:
    /// the surviving state is a pure function of (state, `current_slot`).
    ///
    /// This is the *bound* on the seen-cache — retention mirrors the §8.1
    /// window, so `seen` holds at most two epochs of duties — and the expiry
    /// for parked entries whose block never came (a head that never arrives
    /// within two epochs lost fork choice anyway; the vote is moot).
    pub fn prune(&mut self, current_slot: u64) {
        let floor = current_slot.saturating_sub(ATTESTATION_WINDOW_SLOTS);
        self.seen.retain(|(slot, _), _| *slot >= floor);

        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, e)| e.att.data.slot < floor)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in expired {
            self.evict(seq);
        }
    }

    /// Number of attestations currently parked.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Data hashes accepted for a duty, in acceptance order. Exposed so the
    /// node (and the order-independence tests) can compare pool states
    /// without reaching into internals.
    pub fn accepted_hashes(&self, slot: u64, validator: u32) -> Vec<[u8; 32]> {
        self.seen
            .get(&(slot, validator))
            .map(|r| r.accepted.iter().map(|(h, _)| *h).collect())
            .unwrap_or_default()
    }

    /// Park an attestation under the root it is missing, evicting the oldest
    /// entry if the pool is full. FIFO eviction is a deliberate choice over
    /// "reject new": under a flood the newest entries are the ones most
    /// likely to still matter, and determinism requires the evictee to be a
    /// function of state, not of memory pressure or timing.
    ///
    /// Callers must have already (a) verified `att`'s signature and (b)
    /// checked the per-duty pending cap (R3 NEW-1) — this function only
    /// records the entry and its indexes, it does not re-check either,
    /// because both checks need the pre-hold state (the count *before* this
    /// insertion) that only the caller still has cheaply in hand.
    fn hold(
        &mut self,
        duty: DutyKey,
        att: Attestation,
        missing_root: [u8; 32],
        data_hash: [u8; 32],
    ) -> GossipDecision {
        while self.pending.len() >= MAX_PENDING_ATTESTATIONS {
            // Oldest first. `keys().next()` on a BTreeMap is the smallest
            // sequence number ever still present — insertion order, exactly.
            // The map is non-empty here (`len() >= cap > 0`), so the `else`
            // arm is unreachable; it is a `break` rather than a panic so that
            // the hold queue has no panic site — if the invariant were ever
            // broken the pool would simply stop evicting for this call.
            let Some(&oldest) = self.pending.keys().next() else { break };
            self.evict(oldest);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.pending_keys.insert((att.data.slot, att.validator, data_hash));
        self.pending_by_root.entry(missing_root).or_default().insert(seq);
        // Cannot overflow: this count is the number of pending entries for one
        // duty (incremented here, decremented in `evict` for the same entry),
        // so it is <= pending.len() < MAX_PENDING_ATTESTATIONS (256) after the
        // eviction loop above.
        #[allow(clippy::arithmetic_side_effects)]
        {
            *self.pending_by_duty.entry(duty).or_insert(0) += 1;
        }
        self.pending.insert(seq, PendingEntry { att, missing_root });
        GossipDecision::Hold { missing_root }
    }

    /// Remove one pending entry and every index pointing at it, including the
    /// per-duty pending count (R3 NEW-1) — recomputed from the entry itself
    /// rather than threaded through, so `evict` stays the single place that
    /// can never leave `pending_by_duty` out of sync with `pending`.
    fn evict(&mut self, seq: u64) {
        if let Some(entry) = self.pending.remove(&seq) {
            let duty: DutyKey = (entry.att.data.slot, entry.att.validator);
            if let Some(count) = self.pending_by_duty.get_mut(&duty) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.pending_by_duty.remove(&duty);
                }
            }
            self.pending_keys.remove(&(
                entry.att.data.slot,
                entry.att.validator,
                entry.att.data.signing_root(),
            ));
            if let Some(set) = self.pending_by_root.get_mut(&entry.missing_root) {
                set.remove(&seq);
                if set.is_empty() {
                    self.pending_by_root.remove(&entry.missing_root);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationData;
    use std::collections::BTreeSet;

    /// A signature is "valid" iff it equals the signing root — same device as
    /// slashing.rs: forgery (any other bytes) is detectable per-message
    /// without dragging the PQ stack into a policy test.
    struct RootEchoVerifier;
    /// Every index resolves to the same placeholder key. These tests are about
    /// window, dedup, membership and ordering — not about key binding — and
    /// their verifier doubles ignore the key bytes. The cases that DO care
    /// about resolution use `NoKeys` / a real registry instead.
    struct AnyKey;
    impl crate::attestation::KeyLookup for AnyKey {
        fn pubkey(&self, _v: u32) -> Option<&[u8]> {
            Some(b"placeholder-key")
        }
    }

    impl SignatureVerifier for RootEchoVerifier {
        fn verify_with_key(&self, _pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            sig == root
        }
    }

    const CURRENT_SLOT: u64 = 100;

    /// Committee for every slot in these tests: validators 1..=8, sorted, as
    /// `epoch_committees` would return them.
    fn committees() -> impl CommitteeLookup {
        |_slot: u64| vec![1u32, 2, 3, 4, 5, 6, 7, 8]
    }

    /// Known-block views. `head_of(n)` is the root pattern used by `att`.
    fn root(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn known(roots: &BTreeSet<[u8; 32]>) -> impl BlockLookup + '_ {
        move |r: &[u8; 32]| roots.contains(r)
    }

    /// Everything referenced by default test attestations: head 0xAA,
    /// target 0x22, plus head 0xBB for equivocation variants.
    fn default_known() -> BTreeSet<[u8; 32]> {
        [root(0xAA), root(0xBB), root(0x22)].into_iter().collect()
    }

    fn data(slot: u64, head: u8) -> AttestationData {
        AttestationData {
            slot,
            head: root(head),
            source_epoch: 1,
            source_root: root(0x11),
            target_epoch: 2,
            target_root: root(0x22),
        }
    }

    fn signed(validator: u32, d: AttestationData) -> Attestation {
        Attestation { data: d, validator, signature: d.signing_root().to_vec() }
    }

    fn att(validator: u32, slot: u64, head: u8) -> Attestation {
        signed(validator, data(slot, head))
    }

    fn is_accept(d: &GossipDecision) -> bool {
        matches!(d, GossipDecision::Accept { .. })
    }

    #[test]
    fn valid_attestation_is_accepted() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        let d = pool.process(att(1, CURRENT_SLOT, 0xAA), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(is_accept(&d));
        assert_eq!(pool.accepted_hashes(CURRENT_SLOT, 1).len(), 1);
    }

    #[test]
    fn duplicate_is_ignored_not_penalized() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        let a = att(1, CURRENT_SLOT, 0xAA);
        assert!(is_accept(&pool.process(a.clone(), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey)));
        // Same attestation again — e.g. after the transport duplicate cache
        // expired. One fact, one copy: Ignore, and specifically NOT Reject,
        // because Reject is the only decision wired to peer penalties.
        let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Ignore(IgnoreReason::Duplicate)));
        assert_eq!(pool.accepted_hashes(CURRENT_SLOT, 1).len(), 1);
    }

    #[test]
    fn non_member_is_rejected() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        // Validator 99 is not in any committee: membership is a deterministic
        // function of committed state, so this cannot be honest skew.
        let d = pool.process(att(99, CURRENT_SLOT, 0xAA), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Reject(RejectReason::NotInCommittee)));
    }

    #[test]
    fn bad_signature_is_rejected() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        let mut a = att(1, CURRENT_SLOT, 0xAA);
        a.signature = vec![0u8; 32]; // not the signing root: forged
        let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Reject(RejectReason::BadSignature)));
        // And nothing was recorded: a forgery cannot seed an equivocation
        // record against the validator it names.
        assert!(pool.accepted_hashes(CURRENT_SLOT, 1).is_empty());
    }

    #[test]
    fn non_monotonic_checkpoints_are_rejected() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        let mut d0 = data(CURRENT_SLOT, 0xAA);
        d0.source_epoch = 2; // == target_epoch: malformed by construction
        let d = pool.process(signed(1, d0), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Reject(RejectReason::NonMonotonicCheckpoints)));
    }

    #[test]
    fn outside_window_is_ignored_both_directions() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        let cs = 200u64;
        // Too old: a stale node replaying history — the 2026-08-09 shape.
        let old = att(1, cs - ATTESTATION_WINDOW_SLOTS - 1, 0xAA);
        let d = pool.process(old, cs, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Ignore(IgnoreReason::OutsideWindow)));
        // Too far ahead: more than one slot of clock skew.
        let fut = att(1, cs + CLOCK_SKEW_SLOTS + 1, 0xAA);
        let d = pool.process(fut, cs, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Ignore(IgnoreReason::OutsideWindow)));
        // Boundaries are inside: exactly −64 and +1 are accepted.
        assert!(is_accept(&pool.process(att(1, cs - ATTESTATION_WINDOW_SLOTS, 0xAA), cs, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey)));
        assert!(is_accept(&pool.process(att(2, cs + CLOCK_SKEW_SLOTS, 0xAA), cs, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey)));
    }

    #[test]
    fn unknown_head_is_held_then_released_when_the_block_arrives() {
        let mut pool = AttestationPool::new();
        // The guaranteed boundary race: the attestation beat its block.
        let mut blocks = [root(0x22)].into_iter().collect::<BTreeSet<_>>();
        let a = att(1, CURRENT_SLOT, 0xAA);
        let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Hold { missing_root } if missing_root == root(0xAA)));
        assert_eq!(pool.pending_len(), 1);
        assert!(pool.accepted_hashes(CURRENT_SLOT, 1).is_empty()); // not accepted yet

        // Block arrives, becomes queryable, waiters are replayed.
        blocks.insert(root(0xAA));
        let released = pool.on_block(&root(0xAA), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert_eq!(released.len(), 1);
        assert!(is_accept(&released[0].1));
        assert_eq!(pool.pending_len(), 0);
        assert_eq!(pool.accepted_hashes(CURRENT_SLOT, 1).len(), 1);
    }

    #[test]
    fn duplicate_of_a_held_attestation_is_ignored_and_held_once() {
        let mut pool = AttestationPool::new();
        let blocks = [root(0x22)].into_iter().collect::<BTreeSet<_>>();
        let a = att(1, CURRENT_SLOT, 0xAA);
        assert!(matches!(
            pool.process(a.clone(), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey),
            GossipDecision::Hold { .. }
        ));
        // The same frame again while parked: one copy is enough, and a
        // double-hold would double-release later.
        let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Ignore(IgnoreReason::Duplicate)));
        assert_eq!(pool.pending_len(), 1);
    }

    #[test]
    fn released_attestation_still_missing_its_target_is_reheld() {
        let mut pool = AttestationPool::new();
        // Neither head nor target known: hold is keyed by the head first.
        let mut blocks = BTreeSet::new();
        let a = att(1, CURRENT_SLOT, 0xAA);
        let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Hold { missing_root } if missing_root == root(0xAA)));

        // Head arrives but the target (an epoch-boundary block, racing too)
        // has not: the full pipeline re-runs and re-holds under the target.
        blocks.insert(root(0xAA));
        let released = pool.on_block(&root(0xAA), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert_eq!(released.len(), 1);
        assert!(matches!(released[0].1, GossipDecision::Hold { missing_root } if missing_root == root(0x22)));
        assert_eq!(pool.pending_len(), 1);

        blocks.insert(root(0x22));
        let released = pool.on_block(&root(0x22), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert_eq!(released.len(), 1);
        assert!(is_accept(&released[0].1));
    }

    #[test]
    fn forged_signature_is_rejected_before_parking_not_after() {
        // R3 NEW-1: signature verification now runs BEFORE the head/target
        // check, precisely so a forgery can never occupy a pending slot —
        // the opposite of this test's pre-fix name and premise. A forged
        // frame with an unknown head must Reject immediately, and the pool
        // must stay empty (nothing was ever parked to release later).
        let mut pool = AttestationPool::new();
        let blocks = [root(0x22)].into_iter().collect::<BTreeSet<_>>(); // head 0xAA unknown
        let mut a = att(1, CURRENT_SLOT, 0xAA);
        a.signature = vec![0u8; 32];
        let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Reject(RejectReason::BadSignature)));
        assert_eq!(pool.pending_len(), 0);
        assert!(pool.accepted_hashes(CURRENT_SLOT, 1).is_empty());
    }

    #[test]
    fn unsigned_frames_for_one_duty_never_park_and_evict_nothing() {
        // R3 NEW-1 core exploit, closed: 256 crafted frames for a SINGLE
        // duty, every one with an unknown head and a signature that fails
        // verification, must not occupy even one pending slot — because
        // signature verification now runs before Hold. Before the fix these
        // were free Holds that evicted the oldest 8 of a full FIFO pool
        // (see `pending_pool_is_bounded_with_deterministic_fifo_eviction`);
        // after the fix they cannot reach `hold` at all.
        let mut pool = AttestationPool::new();
        let blocks = BTreeSet::new(); // head/target both unknown either way

        // Fill the pool with 8 genuinely held, honestly-signed attestations
        // from OTHER duties first, so we can prove the attack evicts none of
        // them — not merely that the pool "stays small".
        for v in 1u32..=8 {
            let d0 = data(CURRENT_SLOT, 0xAA);
            let dec = pool.process(signed(v, d0), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
            assert!(matches!(dec, GossipDecision::Hold { .. }));
        }
        assert_eq!(pool.pending_len(), 8);
        let victim_seqs: Vec<u64> = pool.pending.keys().copied().collect();

        // Now the attack: 256 frames for one single duty (validator 1, this
        // same slot — already parked above, so use a validator NOT already
        // holding to isolate the per-duty accounting, and a fresh distinct
        // head per frame so none is an exact-duplicate Ignore either).
        for i in 0u64..256 {
            let mut d0 = data(CURRENT_SLOT, 0xAA);
            d0.head = {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            };
            let mut forged = signed(9, d0); // 9 is not in the test committee (1..=8)
            forged.signature = vec![0xEEu8; 32]; // never equals any signing_root
            let d = pool.process(forged, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
            // Validator 9 is rejected at the membership check (step 4), before
            // signature or hold are even reached — still proves the point:
            // nothing this loop sends ever becomes `Hold`.
            assert!(matches!(d, GossipDecision::Reject(RejectReason::NotInCommittee)));
        }
        assert_eq!(pool.pending_len(), 8, "the attack evicted nothing");
        assert_eq!(pool.pending.keys().copied().collect::<Vec<_>>(), victim_seqs);

        // Repeat with a real committee member (so membership passes) but a
        // signature that still fails verification under its own key: the
        // case the finding actually names ("a real committee-member index").
        for i in 0u64..256 {
            let mut d0 = data(CURRENT_SLOT, 0xBB); // distinct head from validator 1's other data
            d0.head = {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&(i + 1000).to_le_bytes());
                h
            };
            let mut forged = signed(2, d0); // validator 2: real committee member, no hold yet
            forged.signature = vec![0xEEu8; 32];
            let d = pool.process(forged, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
            assert!(matches!(d, GossipDecision::Reject(RejectReason::BadSignature)));
        }
        assert_eq!(pool.pending_len(), 8, "a real-index-but-forged flood evicted nothing either");
        assert_eq!(pool.pending.keys().copied().collect::<Vec<_>>(), victim_seqs);
    }

    #[test]
    fn signed_unknown_head_attestation_still_parks() {
        // The fix must not turn Hold into dead code: a properly signed
        // attestation for an unknown head is exactly the honest boundary
        // race the module exists to tolerate, and it must still park.
        let mut pool = AttestationPool::new();
        let blocks = [root(0x22)].into_iter().collect::<BTreeSet<_>>(); // head 0xAA unknown
        let a = att(1, CURRENT_SLOT, 0xAA);
        let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Hold { missing_root } if missing_root == root(0xAA)));
        assert_eq!(pool.pending_len(), 1);
    }

    #[test]
    fn pending_pool_caps_per_duty_footprint() {
        // R3 NEW-1: even with a valid signature, one duty cannot occupy more
        // than MAX_EQUIVOCATIONS_PER_DUTY pending slots — the complement of
        // the accepted-side cap, closing the "own validator floods the pool
        // with many distinct held variants" residual.
        let mut pool = AttestationPool::new();
        let blocks = BTreeSet::new(); // nothing known: every distinct variant would hold
        let heads = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut parked = 0usize;
        for &h in &heads {
            let a = att(1, CURRENT_SLOT, h);
            let d = pool.process(a, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
            if matches!(d, GossipDecision::Hold { .. }) {
                parked += 1;
            } else {
                assert!(matches!(d, GossipDecision::Ignore(IgnoreReason::PendingDutyLimit)), "unexpected: {d:?}");
            }
        }
        assert_eq!(parked, MAX_EQUIVOCATIONS_PER_DUTY);
        assert_eq!(pool.pending_len(), MAX_EQUIVOCATIONS_PER_DUTY);
        // A completely different duty is unaffected by validator 1's cap.
        let other = att(2, CURRENT_SLOT, 0xAA);
        assert!(matches!(
            pool.process(other, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey),
            GossipDecision::Hold { .. }
        ));
        assert_eq!(pool.pending_len(), MAX_EQUIVOCATIONS_PER_DUTY + 1);
    }

    #[test]
    fn equivocation_is_captured_as_evidence_and_capped_at_two() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        // First vote: plain accept, no evidence.
        let first = att(1, CURRENT_SLOT, 0xAA);
        match pool.process(first.clone(), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey) {
            GossipDecision::Accept { slashing_candidate: None } => {}
            other => panic!("expected clean accept, got {other:?}"),
        }
        // Second, distinct vote for the same duty: accepted (the network
        // needs both halves of the evidence) AND captured as a pair.
        let second = att(1, CURRENT_SLOT, 0xBB);
        match pool.process(second, CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey) {
            GossipDecision::Accept { slashing_candidate: Some(ev) } => {
                // The pair really is this validator conflicting with itself,
                // in a form the slashing pipeline recognizes as a double vote.
                assert_eq!(ev.first.validator, 1);
                assert_eq!(ev.second.validator, 1);
                assert_eq!(ev.first.data.signing_root(), first.data.signing_root());
                assert!(ev.offense().is_ok());
            }
            other => panic!("expected accept with evidence, got {other:?}"),
        }
        // Third distinct vote: proves nothing new, would only amplify the
        // equivocator's own traffic. Ignored — and not penalized, because a
        // peer that innocently relayed variant #3 is not the offender.
        let mut blocks3 = blocks.clone();
        blocks3.insert(root(0xCC));
        let third = att(1, CURRENT_SLOT, 0xCC);
        let d = pool.process(third, CURRENT_SLOT, &committees(), &known(&blocks3), &RootEchoVerifier, &AnyKey);
        assert!(matches!(d, GossipDecision::Ignore(IgnoreReason::EquivocationLimit)));
        assert_eq!(pool.accepted_hashes(CURRENT_SLOT, 1).len(), 2);
    }

    #[test]
    fn pending_pool_is_bounded_with_deterministic_fifo_eviction() {
        let mut pool = AttestationPool::new();
        let blocks = BTreeSet::new(); // nothing known: everything holds
        // Each entry must be a genuinely distinct DUTY (slot, validator), not
        // just a distinct signing root — since R3 NEW-1 caps pending entries
        // per duty at MAX_EQUIVOCATIONS_PER_DUTY, reusing a duty here would
        // test that cap instead of the FIFO one this test targets (that cap
        // has its own test, `pending_pool_caps_per_duty_footprint`). The
        // window admits `ATTESTATION_WINDOW_SLOTS + 1` distinct slots and the
        // test committee has 8 validators, so `slot` cycles fastest and
        // `validator` increments only once per full slot cycle: every i in
        // range yields a fresh (slot, validator) pair.
        let window = ATTESTATION_WINDOW_SLOTS + 1;
        for i in 0..(MAX_PENDING_ATTESTATIONS as u64 + 8) {
            let v = 1 + (i / window) as u32;
            assert!(v <= 8, "test committee only has 8 members");
            let slot = CURRENT_SLOT - (i % window);
            // Distinct head per i too, belt-and-suspenders against collapsing
            // any two entries into one dedup key.
            let mut d0 = data(slot, 0xAA);
            d0.head = {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            };
            let d = pool.process(signed(v, d0), CURRENT_SLOT, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey);
            assert!(matches!(d, GossipDecision::Hold { .. }));
        }
        // Never exceeds capacity, and the evictees are exactly the oldest 8.
        assert_eq!(pool.pending_len(), MAX_PENDING_ATTESTATIONS);
        let oldest_surviving = *pool.pending.keys().next().unwrap();
        assert_eq!(oldest_surviving, 8); // seqs 0..=7 evicted, in order
    }

    #[test]
    fn prune_drops_expired_state_deterministically() {
        let mut pool = AttestationPool::new();
        let blocks = default_known();
        assert!(is_accept(&pool.process(att(1, 10, 0xAA), 11, &committees(), &known(&blocks), &RootEchoVerifier, &AnyKey)));
        // Park one entry at the same old slot.
        let none = BTreeSet::new();
        assert!(matches!(
            pool.process(att(2, 10, 0x33), 11, &committees(), &known(&none), &RootEchoVerifier, &AnyKey),
            GossipDecision::Hold { .. }
        ));

        // Window has not moved past slot 10 yet: everything survives.
        pool.prune(10 + ATTESTATION_WINDOW_SLOTS);
        assert_eq!(pool.accepted_hashes(10, 1).len(), 1);
        assert_eq!(pool.pending_len(), 1);

        // One slot later it has: both records go, and the internal indexes
        // go with them (a re-send of the pruned duty is Ignored only by the
        // window now, not by a leaked dedup entry).
        pool.prune(10 + ATTESTATION_WINDOW_SLOTS + 1);
        assert!(pool.accepted_hashes(10, 1).is_empty());
        assert_eq!(pool.pending_len(), 0);
        assert!(pool.pending_by_root.is_empty());
        assert!(pool.pending_keys.is_empty());
    }

    #[test]
    fn final_state_does_not_depend_on_arrival_order() {
        // The property the Hold verb exists to provide: attestation-then-
        // block and block-then-attestation converge to identical pool state.
        let committee = committees();
        let all_known = default_known();
        let only_target = [root(0x22)].into_iter().collect::<BTreeSet<_>>();

        // Ordering A: attestation first (held), then the block.
        let mut pool_a = AttestationPool::new();
        let a = att(1, CURRENT_SLOT, 0xAA);
        assert!(matches!(
            pool_a.process(a.clone(), CURRENT_SLOT, &committee, &known(&only_target), &RootEchoVerifier, &AnyKey),
            GossipDecision::Hold { .. }
        ));
        let released = pool_a.on_block(&root(0xAA), CURRENT_SLOT, &committee, &known(&all_known), &RootEchoVerifier, &AnyKey);
        assert!(is_accept(&released[0].1));

        // Ordering B: block first, attestation second.
        let mut pool_b = AttestationPool::new();
        assert!(is_accept(&pool_b.process(a, CURRENT_SLOT, &committee, &known(&all_known), &RootEchoVerifier, &AnyKey)));

        // Identical observable state: same accepted set, same pending set.
        assert_eq!(pool_a.accepted_hashes(CURRENT_SLOT, 1), pool_b.accepted_hashes(CURRENT_SLOT, 1));
        assert_eq!(pool_a.pending_len(), 0);
        assert_eq!(pool_b.pending_len(), 0);
        // And a duplicate afterwards is judged identically by both.
        let dup = att(1, CURRENT_SLOT, 0xAA);
        assert!(matches!(
            pool_a.process(dup.clone(), CURRENT_SLOT, &committee, &known(&all_known), &RootEchoVerifier, &AnyKey),
            GossipDecision::Ignore(IgnoreReason::Duplicate)
        ));
        assert!(matches!(
            pool_b.process(dup, CURRENT_SLOT, &committee, &known(&all_known), &RootEchoVerifier, &AnyKey),
            GossipDecision::Ignore(IgnoreReason::Duplicate)
        ));
    }

    #[test]
    fn equivocation_capture_is_order_independent_too() {
        // Same two conflicting votes, opposite arrival orders: both pools
        // end with the same two hashes recorded and both emit evidence on
        // whichever message completed the pair.
        let committee = committees();
        let blocks = default_known();
        let x = att(1, CURRENT_SLOT, 0xAA);
        let y = att(1, CURRENT_SLOT, 0xBB);

        for (first, second) in [(x.clone(), y.clone()), (y, x)] {
            let mut pool = AttestationPool::new();
            match pool.process(first, CURRENT_SLOT, &committee, &known(&blocks), &RootEchoVerifier, &AnyKey) {
                GossipDecision::Accept { slashing_candidate: None } => {}
                other => panic!("expected clean accept, got {other:?}"),
            }
            match pool.process(second, CURRENT_SLOT, &committee, &known(&blocks), &RootEchoVerifier, &AnyKey) {
                GossipDecision::Accept { slashing_candidate: Some(ev) } => {
                    assert!(ev.offense().is_ok());
                    // The evidence identity is order-independent by
                    // construction (slashing.rs sorts the pair), so both
                    // orderings name one and the same offence.
                }
                other => panic!("expected accept with evidence, got {other:?}"),
            }
            let mut hashes = pool.accepted_hashes(CURRENT_SLOT, 1);
            hashes.sort_unstable();
            let mut expected = vec![
                data(CURRENT_SLOT, 0xAA).signing_root(),
                data(CURRENT_SLOT, 0xBB).signing_root(),
            ];
            expected.sort_unstable();
            assert_eq!(hashes, expected);
        }
    }
}
