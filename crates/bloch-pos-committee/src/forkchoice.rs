// SPDX-License-Identifier: AGPL-3.0-or-later

//! LMD-GHOST weight accumulation — what the per-slot subcommittee is *for*.
//!
//! Latest Message Driven: only a validator's most recent attestation counts,
//! so an equivocating or merely reorganising validator cannot vote twice for
//! weight purposes. Weight of a block = total effective stake of validators
//! whose latest message is that block or any of its descendants. The head is
//! found by walking from the justified root, always taking the heaviest child.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// DAG steps the fork choice has walked since the process started.
///
/// Not a metric anyone reads in production — it is the *asymptotics* test's
/// only deterministic handle. `head_step_count_is_linear_in_depth` doubles the
/// chain depth and asserts this counter roughly doubles; before the 2026-08-23
/// rewrite it roughly quadrupled, which is the whole claim in one number and
/// the reason the test could not have passed both before and after.
///
/// Batched: one relaxed add per fork-choice call, never one per step, so it
/// costs nothing on the consensus thread.
#[doc(hidden)]
pub static FORKCHOICE_STEPS: AtomicU64 = AtomicU64::new(0);

/// Per-validator latest vote, as the fork-choice store holds it.
#[derive(Clone, Copy, Debug)]
pub struct LatestMessage {
    pub slot: u64,
    pub root: [u8; 32],
}

/// Minimal block-tree view: every known block and its parent.
///
/// The caller owns the real store; this takes a borrowed view so the fork
/// choice cannot mutate anything, which keeps it a pure function of the inputs
/// (the §5.5 rule again).
pub struct BlockTree<'a> {
    /// child root → parent root.
    pub parents: &'a HashMap<[u8; 32], [u8; 32]>,
}

/// Fork-choice store: latest messages plus the stake behind each validator.
pub struct Store {
    latest: HashMap<u32, LatestMessage>,
    stake: HashMap<u32, u64>,
    /// Validators observed equivocating; excluded from weight forever.
    equivocators: std::collections::HashSet<u32>,
    /// Set-determined mode only: every `(validator, slot)` this fold has been
    /// shown, and the root it named. Empty and never read in legacy mode, so
    /// a legacy `Store` costs exactly what it did before.
    seen: HashMap<(u32, u64), [u8; 32]>,
    /// Which fold rule [`Store::observe`] applies. See
    /// [`Store::new_set_determined`].
    set_determined: bool,
}

impl Store {
    /// The fold as the live chain has run it since Genesis-4. Arrival-order
    /// dependent on message sets that contain a masked equivocation — see
    /// [`Store::observe`] — and kept bit-exact so a pre-flag-day state root
    /// stays reproducible.
    pub fn new() -> Self {
        Store {
            latest: HashMap::new(),
            stake: HashMap::new(),
            equivocators: std::collections::HashSet::new(),
            seen: HashMap::new(),
            set_determined: false,
        }
    }

    /// The fold that is actually what the doc comment on [`Store::observe`]
    /// has always claimed: a pure function of the message SET.
    ///
    /// It differs from [`Store::new`] on exactly one class of input — a set in
    /// which some validator named two different roots in one slot, and the
    /// legacy rule failed to notice because a higher-slot message from that
    /// validator was already stored. On every set with no such pair the two
    /// modes agree message-for-message and head-for-head; that equivalence is
    /// the fork-safety argument and it is asserted, not assumed, by
    /// `both_folds_agree_on_every_non_equivocating_set` in
    /// tests/probe_fold_order.rs.
    ///
    /// `seen` is bounded by the fold, not by history: both production callers
    /// build a fresh `Store` per call (`transition::accumulate_forkchoice`
    /// per block, `engine::forkchoice_store` per head computation), so it
    /// holds at most the messages of that one fold.
    pub fn new_set_determined() -> Self {
        Store {
            set_determined: true,
            ..Store::new()
        }
    }

    /// Bar a validator the CHAIN has already committed as an equivocator.
    ///
    /// This is not a second opinion about who equivocated — it is the verdict
    /// `transition::accumulate_forkchoice` already wrote into
    /// `CommittedState::fc_equivocators` and hashed into the state root, handed
    /// back to the fold that would otherwise re-derive it from scratch.
    ///
    /// ## Why the fold cannot be trusted to rediscover it
    ///
    /// The committed bar is a fold over *the canonical chain's blocks, in chain
    /// order, one block at a time, starting from the previous block's committed
    /// messages*. The node's bar is a fold over *every stored block body in
    /// block-root order, then the loose pool*. Those are different orders over
    /// different sets, and [`Store::observe`]'s legacy rule is order-dependent,
    /// so the node's re-derivation can come out weaker than the chain's. It can
    /// also come out weaker for reasons that have nothing to do with the fold:
    /// the block carrying one half of a pair may have been pruned, or never
    /// have reached this node at all. In every one of those cases the node
    /// counts, toward the head, the weight of a validator its own committed
    /// state says is barred forever.
    ///
    /// ## Why this needs no flag day
    ///
    /// Nothing here is committed. The transition builds its own `Store` and
    /// seeds it with nothing (`accumulate_forkchoice` re-applies the committed
    /// bar itself, by skipping barred attestations); this entry point is for
    /// the node's head computation, which is written to no root. The chain's
    /// definition of who is barred does not change — only whether the node
    /// bothers to read it.
    ///
    /// Monotone and idempotent: barring is permanent in this store as it is in
    /// committed state, and `equivocators` is a set.
    ///
    /// It clears `latest` as well as setting the bar, and those two halves
    /// belong together: clearing is what makes the call's POSITION relative to
    /// the fold irrelevant, so a caller cannot get a different head by seeding
    /// late. `engine::forkchoice_store` seeds early anyway, for cost — see the
    /// note there, which records that moving it after both fold phases changed
    /// no test.
    pub fn bar(&mut self, validator: u32) {
        self.latest.remove(&validator);
        self.equivocators.insert(validator);
    }

    /// Register a validator's effective stake (as committed by the parent
    /// block's state).
    pub fn set_stake(&mut self, validator: u32, effective_stake: u64) {
        self.stake.insert(validator, effective_stake);
    }

    /// Record a vote. Older messages are ignored, so replaying an old
    /// attestation cannot move the head backwards.
    ///
    /// A validator that signs two different heads in one slot is **equivocating**
    /// and is dropped from fork-choice weight entirely, permanently.
    ///
    /// An earlier version kept the first message seen and claimed that made head
    /// selection independent of arrival order. It did the opposite: with an
    /// equivocating validator, two honest nodes holding the identical message
    /// set each kept whichever arrived first and computed *different heads* —
    /// found by property test, 2026-08-11.
    ///
    /// Discarding the equivocator is order-independent by construction: the
    /// outcome depends on whether a conflicting pair exists in the set, never on
    /// which half arrived first. It also matches the finality gadget, which
    /// drops equivocators from both tallies, and it is the honest posture —
    /// equivocation is slashable (§7.3), so the validator is about to be ejected
    /// regardless. Its votes are evidence, not weight.
    /// ## The masking defect, and what `new_set_determined` does about it
    ///
    /// The rule below tests only the message it happens to be *storing*. A
    /// vote at a higher slot therefore hides an equivocating pair at a lower
    /// one: both halves fall to the `prev.slot >= msg.slot` arm before the
    /// equivocation arm is ever consulted, and the bar never fires. Fold the
    /// same three messages pair-first and the validator is barred forever.
    /// Two heads, one message set — which is precisely what the paragraph
    /// above says cannot happen. Witness:
    /// `fold_of_an_equivocating_pair_plus_a_later_vote_is_order_dependent`.
    ///
    /// [`Store::new_set_determined`] closes it by remembering the root named
    /// at every `(validator, slot)` this fold has seen, so the pair is
    /// compared against its own slot rather than against whatever is stored.
    /// It is off by default because the legacy answer is committed to the
    /// state root through `transition::accumulate_forkchoice`; see
    /// `params::FORKCHOICE_SET_DETERMINED_ACTIVATION_EPOCH`.
    pub fn observe(&mut self, validator: u32, msg: LatestMessage) -> bool {
        if self.equivocators.contains(&validator) {
            return false;
        }
        if self.set_determined {
            match self.seen.get(&(validator, msg.slot)) {
                // Two roots at one slot, wherever either half sits in the
                // fold: equivocation, and the bar no longer depends on what
                // else has arrived.
                Some(root) if *root != msg.root => {
                    self.latest.remove(&validator);
                    self.equivocators.insert(validator);
                    return false;
                }
                // Exact re-broadcast. Not an offence, and not news.
                Some(_) => return false,
                None => {
                    self.seen.insert((validator, msg.slot), msg.root);
                }
            }
        }
        match self.latest.get(&validator) {
            // Same slot, different head: equivocation. Drop the stored message
            // and bar the validator — both halves of the pair are refused, so
            // arrival order cannot matter.
            Some(prev) if prev.slot == msg.slot && prev.root != msg.root => {
                self.latest.remove(&validator);
                self.equivocators.insert(validator);
                false
            }
            Some(prev) if prev.slot >= msg.slot => false,
            _ => {
                self.latest.insert(validator, msg);
                true
            }
        }
    }

    /// Validators barred for equivocating. Feeds the slashing pipeline (§7.3).
    pub fn equivocators(&self) -> impl Iterator<Item = &u32> {
        self.equivocators.iter()
    }

    /// Total stake whose latest message is `root` or a descendant of it.
    pub fn weight(&self, tree: &BlockTree<'_>, root: &[u8; 32]) -> u128 {
        let mut total: u128 = 0;
        for (validator, msg) in &self.latest {
            if is_descendant_or_self(tree, &msg.root, root) {
                total += *self.stake.get(validator).unwrap_or(&0) as u128;
            }
        }
        total
    }

    /// Walk from `justified` to the head, taking the heaviest child at each
    /// step. Ties break on the larger block root — arbitrary, but *identical*
    /// on every node, which is the only property that matters.
    ///
    /// ## Why this is not `weight()` in a loop any more
    ///
    /// It was, until 2026-08-23, and that shape is O(V·D²): the descent visits
    /// D levels, each level called [`Store::weight`] once per sibling, and
    /// every one of those calls walked all V latest messages up their whole
    /// ancestor chain (O(V·D)). MEASURED on the old shape: 477 ms at depth
    /// 256, 2.4 s at 512, 8.8 s at 1024, 107 s at 4096 — a fork choice that
    /// costs more than a slot is a chain that stops.
    ///
    /// This computes the same numbers bottom-up instead. Each validator's
    /// stake is attributed once to the block it voted for, subtree weights
    /// accumulate in one pass from leaves toward the roots (Kahn's algorithm
    /// over child→parent edges), and the descent then reads a precomputed
    /// weight per sibling. O(V + N + D) for N known blocks.
    ///
    /// ## Why the selected head is bit-identical, not merely "equivalent"
    ///
    /// The head is consensus-relevant, so this is not a refactor that may be
    /// approximately right — the 2026-08-08 fork came from exactly that kind
    /// of confidence. Three obligations, and each is discharged here:
    ///
    /// 1. **The weights are the same numbers.** `weight(X)` counts a validator
    ///    iff `is_descendant_or_self(msg.root, X)`, i.e. iff the parent walk
    ///    from its vote reaches X. The walk gives up after `parents.len() + 1`
    ///    steps, and a functional graph (one parent per node) has at most that
    ///    many distinct nodes on any walk, so the cutoff never truncates a
    ///    reachable node: the predicate *is* plain reachability. Accumulating
    ///    `direct[R]` up the parent edges therefore lands the same stake on the
    ///    same blocks, and it does so for unknown roots too — a vote for a root
    ///    this node has never seen contributes to that root alone in both
    ///    implementations, which is why `weights` is seeded from every vote
    ///    root rather than from the known block set.
    ///
    /// 2. **The tie-break is byte-for-byte the one below it.** `best` starts at
    ///    `kids[0]` and a later sibling displaces it on `w > best_w ||
    ///    (w == best_w && *child > best)` — the lexicographic maximum of
    ///    (weight, root). The loop here is character-for-character that loop;
    ///    only the source of `w` changed. A different tie-break is a different
    ///    head is a hard fork, so it was not touched.
    ///
    /// 3. **Cycles cannot make the two disagree.** Kahn's leaves a node inside
    ///    a parent cycle unprocessed, where `weight()` would have credited it.
    ///    That gap is unreachable: a cycle node's parent is in the cycle, so it
    ///    can never be the child of an acyclic block, so the descent can only
    ///    query one after entering the cycle itself — and the descent below
    ///    (in both versions) never leaves a cycle. Whenever the old code
    ///    *terminated*, every block it weighed was acyclic-rooted, its whole
    ///    descendant set was acyclic (a cycle node's parent is in the cycle),
    ///    and Kahn's processed all of it. The step bound on the descent is new
    ///    and only fires where the old loop spun forever; block ids are hashes
    ///    over the header that names the parent, so it is unreachable on any
    ///    chain, not merely unlikely.
    ///
    /// `head_reference` keeps the old algorithm alive as the differential
    /// oracle: `forkchoice_head_matches_the_reference_implementation` in
    /// tests/properties.rs asserts the two agree over randomised DAGs, and
    /// `head_step_count_is_linear_in_depth_and_the_old_one_was_quadratic` in
    /// tests/forkchoice_asymptotics.rs is the test that could not pass before.
    pub fn head(
        &self,
        tree: &BlockTree<'_>,
        justified: [u8; 32],
        children: &HashMap<[u8; 32], Vec<[u8; 32]>>,
    ) -> [u8; 32] {
        let weights = self.subtree_weights(tree);
        let mut steps = 0u64;
        // Bounded for the same reason `is_descendant_or_self` is bounded: a
        // parent/children map with a cycle in it must terminate the node's
        // fork choice, not hang the consensus thread. The bound is a count of
        // LEVELS, and every level moves to a distinct block while the graph is
        // acyclic, so it cannot fire early on any real chain: there are at
        // most this many distinct blocks in the two maps put together.
        let limit = tree.parents.len() + children.len() + 1;
        let mut levels = 0usize;
        let mut current = justified;
        while levels <= limit {
            let kids = match children.get(&current) {
                Some(k) if !k.is_empty() => k,
                _ => break,
            };
            let w_of = |b: &[u8; 32]| weights.get(b).copied().unwrap_or(0);
            let mut best = kids[0];
            let mut best_w = w_of(&best);
            for child in &kids[1..] {
                let w = w_of(child);
                if w > best_w || (w == best_w && *child > best) {
                    best = *child;
                    best_w = w;
                }
            }
            steps += kids.len() as u64;
            levels += 1;
            current = best;
        }
        FORKCHOICE_STEPS.fetch_add(steps, Ordering::Relaxed);
        current
    }

    /// Total stake resting on each block's subtree, every block at once.
    ///
    /// `weights[b]` is exactly `self.weight(tree, &b)` — see the three
    /// obligations on [`Store::head`] — computed for all of them in one pass
    /// instead of one walk per query.
    ///
    /// The accumulation runs over `tree.parents`, never over the caller's
    /// `children` map, because `weight()` reads only `tree.parents`: if the
    /// two ever disagree, matching `weight()` is what keeps the head the same.
    fn subtree_weights(&self, tree: &BlockTree<'_>) -> HashMap<[u8; 32], u128> {
        // One validator, one vote, credited to the block it named. Roots this
        // node has never seen get an entry too: `weight()` counts a vote for
        // an unknown root toward that root itself.
        let mut weights: HashMap<[u8; 32], u128> =
            HashMap::with_capacity(tree.parents.len() + self.latest.len());
        for (validator, msg) in &self.latest {
            *weights.entry(msg.root).or_insert(0) +=
                *self.stake.get(validator).unwrap_or(&0) as u128;
        }
        for id in tree.parents.keys() {
            weights.entry(*id).or_insert(0);
        }

        // Kahn's over child→parent edges: a block's weight is final once every
        // known child has handed its subtree up.
        let mut pending: HashMap<[u8; 32], usize> = HashMap::with_capacity(tree.parents.len());
        for parent in tree.parents.values() {
            *pending.entry(*parent).or_insert(0) += 1;
        }
        let mut ready: Vec<[u8; 32]> = tree
            .parents
            .keys()
            .filter(|id| pending.get(*id).copied().unwrap_or(0) == 0)
            .copied()
            .collect();
        let mut steps = 0u64;
        while let Some(id) = ready.pop() {
            steps += 1;
            let w = weights.get(&id).copied().unwrap_or(0);
            let Some(parent) = tree.parents.get(&id) else {
                continue;
            };
            *weights.entry(*parent).or_insert(0) += w;
            // Only a KNOWN parent can itself be released: an unknown one has
            // no parent edge of its own, so nothing waits on it.
            if let Some(n) = pending.get_mut(parent) {
                *n -= 1;
                if *n == 0 && tree.parents.contains_key(parent) {
                    ready.push(*parent);
                }
            }
        }
        FORKCHOICE_STEPS.fetch_add(steps, Ordering::Relaxed);
        weights
    }

    /// The fork choice exactly as it was before the 2026-08-23 rewrite, kept
    /// as the differential oracle for [`Store::head`] and for nothing else.
    ///
    /// O(V·D²) and unusable on a real chain — it is here so a property test
    /// can assert the fast one agrees with it head-for-head over randomised
    /// DAGs, which is the only evidence that the rewrite was a performance
    /// change and not a consensus change.
    #[doc(hidden)]
    pub fn head_reference(
        &self,
        tree: &BlockTree<'_>,
        justified: [u8; 32],
        children: &HashMap<[u8; 32], Vec<[u8; 32]>>,
    ) -> [u8; 32] {
        let mut current = justified;
        loop {
            let kids = match children.get(&current) {
                Some(k) if !k.is_empty() => k,
                _ => return current,
            };
            let mut best = kids[0];
            let mut best_w = self.weight(tree, &best);
            for child in &kids[1..] {
                let w = self.weight(tree, child);
                if w > best_w || (w == best_w && *child > best) {
                    best = *child;
                    best_w = w;
                }
            }
            current = best;
        }
    }

    /// Number of validators with a recorded vote.
    pub fn voters(&self) -> usize {
        self.latest.len()
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

/// Is `node` equal to `ancestor`, or reachable from it by following parents?
///
/// Bounded by the number of known blocks: a corrupt parent map containing a
/// cycle must not hang the node, so the walk counts steps and gives up rather
/// than looping forever.
fn is_descendant_or_self(tree: &BlockTree<'_>, node: &[u8; 32], ancestor: &[u8; 32]) -> bool {
    let mut cur = *node;
    let mut steps = 0usize;
    let limit = tree.parents.len() + 1;
    let verdict = loop {
        if cur == *ancestor {
            break true;
        }
        match tree.parents.get(&cur) {
            Some(p) => {
                cur = *p;
                steps += 1;
                if steps > limit {
                    break false;
                }
            }
            None => break false,
        }
    };
    FORKCHOICE_STEPS.fetch_add(steps as u64, Ordering::Relaxed);
    verdict
}
