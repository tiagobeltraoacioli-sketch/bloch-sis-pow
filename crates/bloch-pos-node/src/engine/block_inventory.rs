// SPDX-License-Identifier: AGPL-3.0-or-later
//! Derived fork-choice inputs owned by the same container as their envelopes.
//!
//! Every mutation updates the indexes. There is deliberately no mutable map
//! dereference: a caller cannot edit an envelope behind an index's back.
//! Historical votes retain the rebuild's exact block-ID/body ordering. In
//! particular, this does not change the legacy order-sensitive equivocation
//! fold into an arrival-order cache of latest messages.

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
    votes: BTreeMap<Root, Vec<(u32, LatestMessage)>>,
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
    pub(super) fn insert(&mut self, id: Root, block: BlockEnvelope) -> Option<BlockEnvelope> {
        let previous = self.remove(&id);
        let children = self.children.entry(block.header.parent).or_default();
        let at = children
            .binary_search(&id)
            .expect_err("removed block must not remain indexed");
        children.insert(at, id);
        if !block.body.attestations.is_empty() {
            self.votes.insert(
                id,
                block
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
                    .collect(),
            );
        }
        self.blocks.insert(id, block);
        previous
    }

    pub(super) fn remove(&mut self, id: &Root) -> Option<BlockEnvelope> {
        let block = self.blocks.remove(id)?;
        let parent = block.header.parent;
        if let Some(children) = self.children.get_mut(&parent) {
            if let Ok(at) = children.binary_search(id) {
                children.remove(at);
            }
            if children.is_empty() {
                self.children.remove(&parent);
            }
        }
        self.votes.remove(id);
        // Keep this block's children: removing a parent does not remove its
        // separately stored descendants in the authoritative map either.
        Some(block)
    }

    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        self.blocks.clear();
        self.children.clear();
        self.votes.clear();
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
                // construct a parent cycle. Use the unchanged full oracle.
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

    pub(super) fn head<'a>(
        &self,
        pool: impl Iterator<Item = &'a Attestation>,
        validators: &[bloch_pos_committee::sample::Validator],
        justified: Root,
        slot_tiebreak: bool,
    ) -> Root {
        let Some((parents, children)) = self.subtree(justified) else {
            return if slot_tiebreak {
                super::lmd_ghost_head_with_slot_tiebreak(&self.blocks, pool, validators, justified)
            } else {
                super::lmd_ghost_head(&self.blocks, pool, validators, justified)
            };
        };
        let mut fc = FcStore::new();
        for validator in validators {
            fc.set_stake(validator.index, validator.effective_stake);
        }
        // BTreeMap block order and original body order are consensus-relevant
        // inputs to the legacy fold. Do not sort by vote slot or insertion time.
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

    fn compare(
        inventory: &BlockInventory,
        pool: &[Attestation],
        validators: &[Validator],
        justified: Root,
    ) {
        for slot_tiebreak in [false, true] {
            let expected = if slot_tiebreak {
                crate::engine::lmd_ghost_head_with_slot_tiebreak(
                    inventory,
                    pool.iter(),
                    validators,
                    justified,
                )
            } else {
                crate::engine::lmd_ghost_head(inventory, pool.iter(), validators, justified)
            };
            assert_eq!(
                inventory.head(pool.iter(), validators, justified, slot_tiebreak),
                expected,
                "indexed head differs at justified={justified:?}, slot_tiebreak={slot_tiebreak}"
            );
        }
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
        inventory.insert(root(30), block(outside, 8, vec![attest(0, 2, root(1))]));
        inventory.insert(root(20), block(outside, 7, vec![attest(0, 1, root(2))]));
        inventory.insert(root(10), block(outside, 6, vec![attest(0, 1, root(1))]));
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
        inventory.insert(root(20), conflicting);
        let first = inventory.remove(&root(10)).unwrap();
        inventory.insert(root(40), first);
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
            for step in 0..96 {
                let id = root(1 + next() % 48);
                if next() % 5 == 0 {
                    inventory.remove(&id);
                } else {
                    // Replacements, missing parents and cycles are deliberate:
                    // correctness must not depend on map length or arrival order.
                    let parent = root(next() % 49);
                    let slot = next() % 12;
                    let votes = (0..next() % 4)
                        .map(|_| attest((next() % 7) as u32, next() % 6, root(next() % 54)))
                        .collect();
                    inventory.insert(id, block(parent, slot, votes));
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
                    compare(&inventory, &pool, &validators, justified);
                }
                if step == 48 {
                    inventory.clear();
                }
            }
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
            inventory.insert(root(slot), block(root(slot - 1), slot, votes));
        }
        let justified = root(4032);
        let (parents, children) = inventory.subtree(justified).unwrap();
        assert_eq!(parents.len(), 64);
        assert_eq!(children.len(), 64);
        assert_eq!(inventory.votes.len(), 128, "old vote carriers are retained");
        compare(&inventory, &[], &vals(1), justified);
        // Same-size replacement must update its parent edge and vote payload.
        inventory.insert(
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
                inventory.insert(root(slot), block(root(slot - 1), slot, votes));
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
