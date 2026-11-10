// SPDX-License-Identifier: AGPL-3.0-or-later
//! Derived fork-choice inputs owned by the same container as their envelopes.
//!
//! Every mutation updates the indexes. There is deliberately no mutable map
//! dereference: a caller cannot edit an envelope behind an index's back.
//! Historical votes retain the rebuild's exact block-ID/body ordering. In
//! particular, this does not change the legacy order-sensitive equivocation
//! fold into an arrival-order cache of latest messages.
//!
//! ## Which blocks vote (security review 2026-11-10, FC-1)
//!
//! Storing a block and counting its body votes are two separate steps.
//! [`BlockInventory::insert`] indexes the parent edge only. The body
//! attestations of a stored block are unverified at that point: admission
//! authenticates the proposer and the header's commitment to the body, but
//! the attestation signatures, committee membership and slots are judged by
//! the state transition, which runs only when the block is applied. Folding
//! them at insertion let any registered proposer mint fork-choice weight in
//! other validators' names, on a block that would never apply.
//!
//! [`BlockInventory::mark_validated`] is the second step. The engine calls it
//! for a block that passed the state transition: on canonical adoption, on a
//! branch replayed by a reorg, and on the boot paths that reload
//! already-validated history. A validated block keeps its votes when a later
//! reorg takes it off the canonical chain, exactly as before. A block that is
//! stored and not yet applied contributes its parent edge and nothing else;
//! its branch gains weight from the signature-checked attestation pool.

use super::{Attestation, BlockEnvelope, BlockTree, FcStore, LatestMessage};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Deref;

type Root = [u8; 32];
type Children = HashMap<Root, Vec<Root>>;
type Parents = HashMap<Root, Root>;

#[derive(Default)]
pub(super) struct BlockInventory {
    blocks: BTreeMap<Root, BlockEnvelope>,
    children: Children,
    /// Body votes of VALIDATED blocks only, keyed by block id and kept in
    /// body order (see the module docs). A block with no attestations has no
    /// entry, validated or not.
    votes: BTreeMap<Root, Vec<(u32, LatestMessage)>>,
    /// Bumped on every change to `votes`. Two equal readings mean the vote
    /// index did not change in between, which is what lets `advance` reuse a
    /// head across a turn that validated nothing.
    vote_generation: u64,
    /// Finalized canonical blocks whose body and proposer signature were
    /// released from memory (see [`BlockInventory::hollow`]). Their header,
    /// parent edge and vote index stay, so fork choice is unchanged; the full
    /// envelope is read back from the block log when something needs it.
    hollow: HashSet<Root>,
}

impl Deref for BlockInventory {
    type Target = BTreeMap<Root, BlockEnvelope>;
    fn deref(&self) -> &Self::Target {
        &self.blocks
    }
}

impl<'a> IntoIterator for &'a BlockInventory {
    type Item = (&'a Root, &'a BlockEnvelope);
    type IntoIter = std::collections::btree_map::Iter<'a, Root, BlockEnvelope>;
    fn into_iter(self) -> Self::IntoIter {
        self.blocks.iter()
    }
}

impl BlockInventory {
    /// Store `block` and index its parent edge. Its body votes are NOT
    /// counted until [`BlockInventory::mark_validated`] is called for it.
    ///
    /// Replacing an entry drops the previous entry's votes and released-body
    /// mark with it, so a caller that re-inserts validated history (the
    /// reorg path restoring released bodies) must mark it validated again.
    pub(super) fn insert(&mut self, id: Root, block: BlockEnvelope) -> Option<BlockEnvelope> {
        let previous = self.remove(&id);
        let children = self.children.entry(block.header.parent).or_default();
        let at = children
            .binary_search(&id)
            .expect_err("removed block must not remain indexed");
        children.insert(at, id);
        self.blocks.insert(id, block);
        previous
    }

    /// Count the body votes of a stored block that passed the state
    /// transition. Returns whether the vote index changed.
    ///
    /// The caller's obligation is the whole security property: `id` must name
    /// a block whose attestations the transition verified (signature,
    /// committee membership, slot) against that block's own pre-state. The
    /// votes enter the index in body order under the block's id, which is
    /// exactly the entry insertion used to create, so the fold order of
    /// validated history is unchanged.
    ///
    /// Idempotent. A released body is already validated and its index entry
    /// was retained, so it is left alone rather than rebuilt from the empty
    /// body that remains.
    pub(super) fn mark_validated(&mut self, id: &Root) -> bool {
        if self.hollow.contains(id) || self.votes.contains_key(id) {
            return false;
        }
        let Some(block) = self.blocks.get(id) else { return false };
        if block.body.attestations.is_empty() {
            return false;
        }
        let votes = block
            .body
            .attestations
            .iter()
            .map(|att| {
                (
                    att.validator,
                    LatestMessage {
                        slot: att.data.slot,
                        root: att.data.head,
                    },
                )
            })
            .collect();
        self.votes.insert(*id, votes);
        self.vote_generation = self.vote_generation.saturating_add(1);
        true
    }

    /// A counter that changes whenever the vote index does.
    pub(super) fn vote_generation(&self) -> u64 {
        self.vote_generation
    }

    /// Whether `id` currently contributes body votes to fork choice.
    #[cfg(test)]
    pub(super) fn has_indexed_votes(&self, id: &Root) -> bool {
        self.votes.contains_key(id)
    }

    /// Release a stored block's body and proposer signature, keeping its
    /// header, parent edge and vote index.
    ///
    /// Only for canonical blocks strictly below the finality latch: those can
    /// never be re-applied or cut by a reorg without the operator override
    /// (which rehydrates them first), and the block log on disk holds their
    /// exact bytes. Every PQ hybrid signature is ~4.6 KB, so the bodies are
    /// nearly all of a stored block; keeping them for the whole chain made a
    /// node's heap grow with the chain. The vote index was built from the full
    /// body when the block was validated and is untouched, so
    /// [`BlockInventory::head`] folds exactly the same votes in exactly the
    /// same order.
    ///
    /// A block that carries attestations and was never marked validated is
    /// refused: releasing it would discard votes that could never be indexed
    /// afterwards. Canonical blocks are always validated, so this only guards
    /// the contract against a future caller.
    pub(super) fn hollow(&mut self, id: &Root) -> bool {
        let Some(block) = self.blocks.get_mut(id) else { return false };
        if !block.body.attestations.is_empty() && !self.votes.contains_key(id) {
            return false;
        }
        if !self.hollow.insert(*id) {
            return false;
        }
        block.proposer_sig = Vec::new();
        block.body.transactions = Vec::new();
        block.body.attestations = Vec::new();
        true
    }

    /// Whether `id` is stored with its body released.
    pub(super) fn is_hollow(&self, id: &Root) -> bool {
        self.hollow.contains(id)
    }

    pub(super) fn remove(&mut self, id: &Root) -> Option<BlockEnvelope> {
        let block = self.blocks.remove(id)?;
        self.hollow.remove(id);
        let parent = block.header.parent;
        if let Some(children) = self.children.get_mut(&parent) {
            if let Ok(at) = children.binary_search(id) {
                children.remove(at);
            }
            if children.is_empty() {
                self.children.remove(&parent);
            }
        }
        if self.votes.remove(id).is_some() {
            self.vote_generation = self.vote_generation.saturating_add(1);
        }
        // Keep this block's children: removing a parent does not remove its
        // separately stored descendants in the authoritative map either.
        Some(block)
    }

    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        self.blocks.clear();
        self.children.clear();
        self.votes.clear();
        self.vote_generation = self.vote_generation.saturating_add(1);
        self.hollow.clear();
    }

    /// Only descendants of the walk's starting checkpoint can affect the
    /// weight of a candidate child. Parent edges have a single destination,
    /// so a vote outside this subtree cannot reach a child inside it. All
    /// historical votes are still folded below, including votes carried by
    /// blocks outside this subtree and votes for unknown roots.
    fn subtree(&self, justified: Root) -> Option<(Parents, Children)> {
        let mut parents = HashMap::new();
        let mut children = HashMap::new();
        let mut seen = HashSet::new();
        let mut pending = vec![justified];
        while let Some(parent) = pending.pop() {
            if !seen.insert(parent) {
                // Synthetic cyclic graphs must retain the old global step
                // bound exactly, even though hash-addressed blocks cannot
                // construct a parent cycle. Walk the whole map instead.
                return None;
            }
            if let Some(kids) = self.children.get(&parent) {
                children.insert(parent, kids.clone());
                for child in kids {
                    parents.insert(*child, parent);
                    pending.push(*child);
                }
            }
        }
        Some((parents, children))
    }

    /// Latest messages from the validated vote index and then the pool.
    ///
    /// BTreeMap block order and original body order are consensus-relevant
    /// inputs to the legacy fold. Do not sort by vote slot or insertion time.
    /// Only validated blocks have an entry in `votes` (see the module docs).
    fn vote_store<'a>(
        &self,
        pool: impl Iterator<Item = &'a Attestation>,
        validators: &[bloch_pos_committee::sample::Validator],
    ) -> FcStore {
        let mut fc = FcStore::new();
        for validator in validators {
            fc.set_stake(validator.index, validator.effective_stake);
        }
        for votes in self.votes.values() {
            for (validator, message) in votes {
                fc.observe(*validator, *message);
            }
        }
        for att in pool {
            fc.observe(
                att.validator,
                LatestMessage {
                    slot: att.data.slot,
                    root: att.data.head,
                },
            );
        }
        fc
    }

    /// The whole-map walk [`BlockInventory::subtree`] declines to shortcut
    /// (synthetic parent cycles). Same graph the full rebuild
    /// (`engine::lmd_ghost_head`) derives from the envelopes, and the same
    /// validated-only vote fold as the indexed path: the fallback must not be
    /// a way to count the body of a block that was never applied.
    fn head_over_all_blocks<'a>(
        &self,
        pool: impl Iterator<Item = &'a Attestation>,
        validators: &[bloch_pos_committee::sample::Validator],
        justified: Root,
        slot_tiebreak: bool,
    ) -> Root {
        let parents: Parents = self
            .blocks
            .iter()
            .map(|(id, block)| (*id, block.header.parent))
            .collect();
        let fc = self.vote_store(pool, validators);
        let tree = BlockTree { parents: &parents };
        if slot_tiebreak {
            let slots = self
                .blocks
                .iter()
                .map(|(id, block)| (*id, block.header.slot))
                .collect();
            fc.head_with_slot_tiebreak(&tree, justified, &self.children, &slots)
        } else {
            fc.head(&tree, justified, &self.children)
        }
    }

    pub(super) fn head<'a>(
        &self,
        pool: impl Iterator<Item = &'a Attestation>,
        validators: &[bloch_pos_committee::sample::Validator],
        justified: Root,
        slot_tiebreak: bool,
    ) -> Root {
        let Some((parents, children)) = self.subtree(justified) else {
            return self.head_over_all_blocks(pool, validators, justified, slot_tiebreak);
        };
        let fc = self.vote_store(pool, validators);
        let tree = BlockTree { parents: &parents };
        if slot_tiebreak {
            let slots = parents
                .keys()
                .map(|id| (*id, self.blocks[id].header.slot))
                .collect();
            fc.head_with_slot_tiebreak(&tree, justified, &children, &slots)
        } else {
            fc.head(&tree, justified, &children)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        forkchoice_tests::{attest, header, vals},
        Body,
    };
    use bloch_pos_committee::sample::Validator;

    fn root(n: u64) -> Root {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_be_bytes());
        bytes
    }

    fn block(parent: Root, slot: u64, attestations: Vec<Attestation>) -> BlockEnvelope {
        BlockEnvelope {
            header: header(parent, slot, slot as u8),
            proposer_sig: Vec::new(),
            body: Body {
                transactions: Vec::new(),
                attestations,
            },
        }
    }

    /// Store a block and count its body votes: what the engine does for a
    /// block that passed the state transition.
    fn insert_validated(inventory: &mut BlockInventory, id: Root, block: BlockEnvelope) {
        inventory.insert(id, block);
        inventory.mark_validated(&id);
    }

    /// The unchanged full rebuild over `view`, against the indexed head.
    ///
    /// `view` is what the rebuild is allowed to fold: the stored envelopes
    /// with the body votes of every block that was never validated removed.
    fn compare_view(
        inventory: &BlockInventory,
        view: &BTreeMap<Root, BlockEnvelope>,
        pool: &[Attestation],
        validators: &[Validator],
        justified: Root,
    ) {
        for slot_tiebreak in [false, true] {
            let expected = if slot_tiebreak {
                crate::engine::lmd_ghost_head_with_slot_tiebreak(
                    view,
                    pool.iter(),
                    validators,
                    justified,
                )
            } else {
                crate::engine::lmd_ghost_head(view, pool.iter(), validators, justified)
            };
            assert_eq!(
                inventory.head(pool.iter(), validators, justified, slot_tiebreak),
                expected,
                "indexed head differs at justified={justified:?}, slot_tiebreak={slot_tiebreak}"
            );
        }
    }

    /// For an inventory in which every stored block was validated, the
    /// envelopes themselves are the rebuild's input, as they always were.
    fn compare(
        inventory: &BlockInventory,
        pool: &[Attestation],
        validators: &[Validator],
        justified: Root,
    ) {
        compare_view(inventory, inventory, pool, validators, justified);
    }

    /// FC-1 (a): the body votes of a block that is stored but was never
    /// applied do not weigh on the head, whatever slot they claim.
    #[test]
    fn a_stored_unvalidated_block_contributes_its_edge_and_no_votes() {
        let mut inventory = BlockInventory::default();
        let g = root(0);
        // Two siblings; the larger id wins the zero-weight tie.
        inventory.insert(root(1), block(g, 1, Vec::new()));
        inventory.insert(root(2), block(g, 1, Vec::new()));
        let validators = vals(3);
        for tiebreak in [false, true] {
            assert_eq!(inventory.head([].iter(), &validators, g, tiebreak), root(2));
        }

        // A child of the losing sibling arrives carrying every validator's
        // vote for its own branch, at slots far beyond any honest vote.
        let carried = vec![
            attest(0, u64::MAX, root(1)),
            attest(1, u64::MAX, root(1)),
            attest(2, u64::MAX, root(1)),
        ];
        let generation = inventory.vote_generation();
        inventory.insert(root(3), block(root(1), 2, carried));
        assert!(!inventory.has_indexed_votes(&root(3)));
        assert_eq!(
            inventory.vote_generation(),
            generation,
            "storing a block must not change the vote index"
        );
        for tiebreak in [false, true] {
            assert_eq!(
                inventory.head([].iter(), &validators, g, tiebreak),
                root(2),
                "unverified body votes moved the head"
            );
        }
        // Its parent edge is indexed: the pool can still carry the branch.
        let pool = vec![attest(0, 2, root(3)), attest(1, 2, root(3))];
        for tiebreak in [false, true] {
            assert_eq!(inventory.head(pool.iter(), &validators, g, tiebreak), root(3));
        }
        // An honest later vote is not shadowed by the unvalidated body.
        let honest = vec![attest(0, 3, root(2)), attest(1, 3, root(2)), attest(2, 3, root(2))];
        for tiebreak in [false, true] {
            assert_eq!(inventory.head(honest.iter(), &validators, g, tiebreak), root(2));
        }
    }

    /// FC-1 (b): once the block is validated its votes count exactly as the
    /// full rebuild over the envelopes counts them, and they stop counting
    /// when the block is removed or replaced.
    #[test]
    fn validated_body_votes_count_exactly_as_the_full_rebuild() {
        let mut inventory = BlockInventory::default();
        let g = root(0);
        inventory.insert(root(1), block(g, 1, Vec::new()));
        inventory.insert(root(2), block(g, 1, Vec::new()));
        let carrier = block(root(1), 2, vec![attest(0, 1, root(1)), attest(1, 1, root(1))]);
        inventory.insert(root(3), carrier.clone());
        let validators = vals(3);
        assert_eq!(inventory.head([].iter(), &validators, g, false), root(2));

        let generation = inventory.vote_generation();
        assert!(inventory.mark_validated(&root(3)));
        assert!(inventory.has_indexed_votes(&root(3)));
        assert_ne!(inventory.vote_generation(), generation);
        assert_eq!(inventory.head([].iter(), &validators, g, false), root(3));
        // Blocks 1 and 2 carry no attestations, so the envelopes are now
        // exactly what the legacy rebuild folds.
        compare(&inventory, &[], &validators, g);
        compare(&inventory, &[attest(2, 5, root(2))], &validators, g);

        let generation = inventory.vote_generation();
        assert!(!inventory.mark_validated(&root(3)), "idempotent");
        assert!(!inventory.mark_validated(&root(1)), "nothing to index");
        assert!(!inventory.mark_validated(&root(77)), "unknown block");
        assert_eq!(inventory.vote_generation(), generation);

        // Replacing the entry forgets the validation with the old envelope.
        inventory.insert(root(3), carrier);
        assert!(!inventory.has_indexed_votes(&root(3)));
        assert_ne!(inventory.vote_generation(), generation);
        assert_eq!(inventory.head([].iter(), &validators, g, false), root(2));
        assert!(inventory.mark_validated(&root(3)));
        assert_eq!(inventory.head([].iter(), &validators, g, false), root(3));
        inventory.remove(&root(3));
        assert_eq!(inventory.head([].iter(), &validators, g, false), root(2));
    }

    #[test]
    fn released_bodies_keep_the_fork_choice_head() {
        let mut inventory = BlockInventory::default();
        let g = root(0);
        let outside = root(99);
        inventory.insert(root(1), block(g, 1, Vec::new()));
        inventory.insert(root(2), block(g, 1, Vec::new()));
        inventory.insert(root(30), block(outside, 8, vec![attest(0, 2, root(1))]));
        inventory.insert(root(20), block(outside, 7, vec![attest(0, 1, root(2))]));
        inventory.insert(root(10), block(outside, 6, vec![attest(1, 1, root(1))]));
        // A body whose votes were never indexed is not released: its votes
        // could not be recovered afterwards.
        assert!(!inventory.hollow(&root(30)));
        assert!(!inventory.is_hollow(&root(30)));
        assert!(!inventory.blocks[&root(30)].body.attestations.is_empty());
        for id in [root(10), root(20), root(30)] {
            assert!(inventory.mark_validated(&id));
        }
        let validators = vals(2);
        let before: Vec<_> = [false, true]
            .map(|tiebreak| inventory.head([].iter(), &validators, g, tiebreak))
            .to_vec();

        for id in [root(10), root(20), root(30)] {
            assert!(inventory.hollow(&id));
            assert!(!inventory.hollow(&id), "releasing twice is a no-op");
            assert!(inventory.blocks[&id].body.attestations.is_empty());
            assert!(!inventory.mark_validated(&id), "a released body is already indexed");
            assert!(inventory.has_indexed_votes(&id));
        }
        let after: Vec<_> = [false, true]
            .map(|tiebreak| inventory.head([].iter(), &validators, g, tiebreak))
            .to_vec();
        assert_eq!(after, before, "the vote index, not the body, feeds fork choice");

        let restored = block(outside, 8, vec![attest(0, 2, root(1))]);
        insert_validated(&mut inventory, root(30), restored);
        assert!(!inventory.is_hollow(&root(30)), "re-inserting a full block clears the mark");
        let restored_heads: Vec<_> = [false, true]
            .map(|tiebreak| inventory.head([].iter(), &validators, g, tiebreak))
            .to_vec();
        assert_eq!(restored_heads, before, "a restored, re-validated body votes as it did");
        inventory.remove(&root(20));
        assert!(!inventory.is_hollow(&root(20)));
    }

    #[test]
    fn historical_vote_order_and_removal_match_the_legacy_fold() {
        let mut inventory = BlockInventory::default();
        let g = root(0);
        let outside = root(99);
        inventory.insert(root(1), block(g, 1, Vec::new()));
        inventory.insert(root(2), block(g, 1, Vec::new()));
        // The carrier branch is disconnected from justified. Its votes must
        // still count, in ID order, not in this reverse insertion order.
        insert_validated(&mut inventory, root(30), block(outside, 8, vec![attest(0, 2, root(1))]));
        insert_validated(&mut inventory, root(20), block(outside, 7, vec![attest(0, 1, root(2))]));
        insert_validated(&mut inventory, root(10), block(outside, 6, vec![attest(0, 1, root(1))]));
        assert_eq!(
            inventory.head([].iter(), &vals(1), g, false),
            root(2),
            "A,B,C order bars the validator; an arrival-order fold would retain C"
        );
        compare(&inventory, &[], &vals(1), g);
        let conflicting = inventory.remove(&root(20)).unwrap();
        assert_eq!(
            inventory.head([].iter(), &vals(1), g, false),
            root(1),
            "removing a carrier must remove its equivocation effect too"
        );
        insert_validated(&mut inventory, root(20), conflicting);
        let first = inventory.remove(&root(10)).unwrap();
        insert_validated(&mut inventory, root(40), first);
        assert_eq!(
            inventory.head([].iter(), &vals(1), g, false),
            root(1),
            "B,C,A preserves the existing legacy fold's different answer"
        );
        compare(&inventory, &[], &vals(1), g);
        // Changing a loose pool or canonical stake must not leave a sticky
        // latest-message or effective-weight cache behind.
        let pool = vec![attest(0, 3, root(2))];
        compare(&inventory, &pool, &vals(1), g);
        compare(&inventory, &[], &[], g);
        compare(&inventory, &[], &vals(1), g);
    }

    /// The order in which blocks are validated must not matter either: the
    /// fold is by block id, whichever block was applied first.
    #[test]
    fn validation_order_does_not_change_the_fold_order() {
        let g = root(0);
        let outside = root(99);
        let carriers = [
            (root(10), block(outside, 6, vec![attest(0, 1, root(1))])),
            (root(20), block(outside, 7, vec![attest(0, 1, root(2))])),
            (root(30), block(outside, 8, vec![attest(0, 2, root(1))])),
        ];
        let mut heads = Vec::new();
        for order in [[0usize, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            let mut inventory = BlockInventory::default();
            inventory.insert(root(1), block(g, 1, Vec::new()));
            inventory.insert(root(2), block(g, 1, Vec::new()));
            for (id, carrier) in &carriers {
                inventory.insert(*id, carrier.clone());
            }
            for at in order {
                assert!(inventory.mark_validated(&carriers[at].0));
            }
            compare(&inventory, &[], &vals(1), g);
            heads.push(inventory.head([].iter(), &vals(1), g, false));
        }
        assert!(heads.iter().all(|head| *head == root(2)), "{heads:?}");
    }

    #[test]
    fn indexed_heads_match_rebuild_through_random_mutations_and_stakes() {
        let mut random = 0x1031_4669_A11C_E5EDu64;
        let mut next = || {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random
        };
        for _ in 0..16 {
            let mut inventory = BlockInventory::default();
            // The rebuild's input: every stored envelope, with the body votes
            // of blocks this test never validated removed. Maintained beside
            // the inventory, never derived from its index.
            let mut view: BTreeMap<Root, BlockEnvelope> = BTreeMap::new();
            let mut unvalidated_with_votes = 0usize;
            for step in 0..96 {
                let id = root(1 + next() % 48);
                if next() % 5 == 0 {
                    inventory.remove(&id);
                    view.remove(&id);
                } else {
                    // Replacements, missing parents and cycles are deliberate:
                    // correctness must not depend on map length or arrival order.
                    let parent = root(next() % 49);
                    let slot = next() % 12;
                    let votes: Vec<_> = (0..next() % 4)
                        .map(|_| attest((next() % 7) as u32, next() % 6, root(next() % 54)))
                        .collect();
                    let stored = block(parent, slot, votes);
                    inventory.insert(id, stored.clone());
                    if next() % 3 == 0 {
                        // Stored, never applied: an edge without votes.
                        if !stored.body.attestations.is_empty() {
                            unvalidated_with_votes += 1;
                        }
                        let mut bare = stored;
                        bare.body.attestations = Vec::new();
                        view.insert(id, bare);
                    } else {
                        inventory.mark_validated(&id);
                        view.insert(id, stored);
                    }
                }
                if next() % 6 == 0 {
                    // A block validated some time after it was stored.
                    let late = root(1 + next() % 48);
                    if let Some(stored) = inventory.blocks.get(&late).cloned() {
                        inventory.mark_validated(&late);
                        view.insert(late, stored);
                    }
                }
                let pool: Vec<_> = (0..next() % 5)
                    .map(|_| attest((next() % 7) as u32, next() % 7, root(next() % 54)))
                    .collect();
                let validators: Vec<_> = (0..next() % 7)
                    .map(|index| Validator {
                        index: index as u32,
                        effective_stake: next() % 500,
                    })
                    .collect();
                for justified in [root(0), root(next() % 49), root(77)] {
                    compare_view(&inventory, &view, &pool, &validators, justified);
                }
                if step == 48 {
                    inventory.clear();
                    view.clear();
                }
            }
            assert!(unvalidated_with_votes > 0, "the unvalidated case was exercised");
        }
    }

    #[test]
    fn checkpoint_subtree_excludes_history_without_discarding_historical_votes() {
        let mut inventory = BlockInventory::default();
        for slot in 1..=4096 {
            let votes = if slot % 32 == 0 {
                vec![attest(0, slot, root(slot - 1))]
            } else {
                Vec::new()
            };
            insert_validated(&mut inventory, root(slot), block(root(slot - 1), slot, votes));
        }
        let justified = root(4032);
        let (parents, children) = inventory.subtree(justified).unwrap();
        assert_eq!(parents.len(), 64);
        assert_eq!(children.len(), 64);
        assert_eq!(inventory.votes.len(), 128, "old vote carriers are retained");
        compare(&inventory, &[], &vals(1), justified);
        // Same-size replacement must update its parent edge and vote payload.
        insert_validated(
            &mut inventory,
            root(4096),
            block(root(4090), 4096, vec![attest(0, 8192, root(4091))]),
        );
        compare(&inventory, &[], &vals(1), justified);
        assert!(!inventory.children.contains_key(&root(4095)));
        inventory.remove(&root(4090));
        compare(&inventory, &[], &vals(1), justified);
        compare(&inventory, &[], &vals(1), root(4090));
    }

    #[test]
    #[ignore = "wall-clock measurement; equality is covered by ordinary differential regressions"]
    fn perf_indexed_forkchoice_by_history() {
        use std::time::Instant;
        for depth in [4096u64, 32768, 65536] {
            let mut inventory = BlockInventory::default();
            for slot in 1..=depth {
                let votes = if slot % 32 == 0 {
                    (0..3).map(|v| attest(v, slot, root(slot - 1))).collect()
                } else {
                    Vec::new()
                };
                insert_validated(&mut inventory, root(slot), block(root(slot - 1), slot, votes));
            }
            let justified = root(depth - 64);
            let validators = vals(3);
            let runs = 12;
            let started = Instant::now();
            let mut expected = root(0);
            for _ in 0..runs {
                expected =
                    crate::engine::lmd_ghost_head(&inventory, [].iter(), &validators, justified);
            }
            let rebuild_ms = started.elapsed().as_secs_f64() * 1000.0 / runs as f64;
            let started = Instant::now();
            for _ in 0..runs {
                assert_eq!(
                    inventory.head([].iter(), &validators, justified, false),
                    expected
                );
            }
            let indexed_ms = started.elapsed().as_secs_f64() * 1000.0 / runs as f64;
            println!("FORKCHOICE_BENCH blocks={depth} live_suffix=64 rebuild_ms={rebuild_ms:.3} indexed_ms={indexed_ms:.3} speedup={:.2}", rebuild_ms/indexed_ms);
        }
    }
}
