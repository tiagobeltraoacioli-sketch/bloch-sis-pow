// SPDX-License-Identifier: MIT OR Apache-2.0

//! LMD-GHOST weight accumulation — what the per-slot subcommittee is *for*.
//!
//! Latest Message Driven: only a validator's most recent attestation counts,
//! so an equivocating or merely reorganising validator cannot vote twice for
//! weight purposes. Weight of a block = total effective stake of validators
//! whose latest message is that block or any of its descendants. The head is
//! found by walking from the justified root, always taking the heaviest child.

use std::collections::HashMap;

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
}

impl Store {
    pub fn new() -> Self {
        Store { latest: HashMap::new(), stake: HashMap::new() }
    }

    /// Register a validator's effective stake (as committed by the parent
    /// block's state).
    pub fn set_stake(&mut self, validator: u32, effective_stake: u64) {
        self.stake.insert(validator, effective_stake);
    }

    /// Record a vote. Older messages are ignored, so replaying an old
    /// attestation cannot move the head backwards.
    ///
    /// Equal slots are also ignored: a validator that signs two different heads
    /// in one slot is equivocating, and the first message seen is kept rather
    /// than letting the last one on the wire decide. That makes head selection
    /// independent of gossip arrival order, which is what stops two honest
    /// nodes from computing different heads from the same set of messages.
    pub fn observe(&mut self, validator: u32, msg: LatestMessage) -> bool {
        match self.latest.get(&validator) {
            Some(prev) if prev.slot >= msg.slot => false,
            _ => {
                self.latest.insert(validator, msg);
                true
            }
        }
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
    pub fn head(
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
    loop {
        if cur == *ancestor {
            return true;
        }
        match tree.parents.get(&cur) {
            Some(p) => {
                cur = *p;
                steps += 1;
                if steps > limit {
                    return false;
                }
            }
            None => return false,
        }
    }
}
