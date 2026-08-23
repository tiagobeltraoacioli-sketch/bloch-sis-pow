// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one test that could NOT pass before the 2026-08-23 fork-choice rewrite.
//!
//! `forkchoice_head_matches_the_reference_implementation` (tests/properties.rs)
//! proves the rewrite did not change the head. It passes before and after by
//! construction, so on its own it proves nothing about why the rewrite
//! happened. This file proves the other half: the *cost* changed shape.
//!
//! It reads `forkchoice::FORKCHOICE_STEPS`, a process-global counter of DAG
//! steps walked. **This file must hold exactly one test.** Cargo gives each
//! integration-test file its own process but runs the tests inside one file on
//! several threads, and a second test here would race the counter.

use bloch_pos_committee::forkchoice::FORKCHOICE_STEPS;
use bloch_pos_committee::{BlockTree, LatestMessage, Store};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

const GENESIS: [u8; 32] = [0xAAu8; 32];

fn block_id(depth: u32, branch: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = branch;
    id[1..5].copy_from_slice(&depth.to_be_bytes());
    id
}

/// A spine of `depth` blocks with a sibling hanging off every level — so the
/// descent has a real choice to make at each of the `depth` steps, which is
/// what made the old implementation quadratic.
fn chain(
    depth: u32,
) -> (
    HashMap<[u8; 32], [u8; 32]>,
    HashMap<[u8; 32], Vec<[u8; 32]>>,
) {
    let mut parents = HashMap::new();
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    let mut parent = GENESIS;
    for d in 0..depth {
        let spine = block_id(d, 0);
        let sibling = block_id(d, 1);
        parents.insert(spine, parent);
        parents.insert(sibling, parent);
        let kids = children.entry(parent).or_default();
        kids.push(spine);
        kids.push(sibling);
        kids.sort_unstable();
        parent = spine;
    }
    (parents, children)
}

/// `validators` votes spread down the spine, so weight really does accumulate
/// along the whole chain rather than sitting on one block.
fn store_for(depth: u32, validators: u32) -> Store {
    let mut s = Store::new();
    for v in 0..validators {
        s.set_stake(v, 100);
        // Every validator votes for a distinct depth on the spine, so weight
        // is spread the whole way down and the spine still wins every
        // comparison against its childless sibling.
        let d = (v as u64 * depth as u64 / validators.max(1) as u64) as u32;
        s.observe(
            v,
            LatestMessage {
                slot: 1,
                root: block_id(d.min(depth - 1), 0),
            },
        );
    }
    s
}

fn steps_of(f: impl FnOnce()) -> u64 {
    let before = FORKCHOICE_STEPS.load(Ordering::Relaxed);
    f();
    FORKCHOICE_STEPS.load(Ordering::Relaxed) - before
}

/// **Fails before this rewrite, passes after.** Double the chain depth and
/// count the DAG steps fork choice walks.
///
/// The implementation this replaced called `Store::weight` once per sibling
/// per level, and each of those calls walked all V latest messages up their
/// full ancestor chains: O(V·D²). Doubling D multiplied its work by about
/// four. MEASURED on that shape, one call: 477 ms at depth 256, 2,372 ms at
/// 512, 8,794 ms at 1,024, 107 s at 4,096 — well past a slot, which is a
/// chain that stops rather than a node that is slow.
///
/// The bottom-up version attributes each vote once and accumulates subtree
/// weights in a single pass, so doubling D roughly doubles the work.
///
/// Both ratios are asserted, on the same DAGs in the same run: the new one
/// must come in under 2.5, the old one must come in over 3.5. Asserting the
/// old one too is what makes the number meaningful — it shows the counter can
/// tell the two shapes apart rather than merely reporting a small number.
#[test]
fn head_step_count_is_linear_in_depth_and_the_old_one_was_quadratic() {
    const D: u32 = 64;
    const V: u32 = 32;

    let (p1, c1) = chain(D);
    let (p2, c2) = chain(D * 2);
    let s1 = store_for(D, V);
    let s2 = store_for(D * 2, V);
    let t1 = BlockTree { parents: &p1 };
    let t2 = BlockTree { parents: &p2 };

    // Sanity: the descent really does run the full depth, or the ratios below
    // would be measuring an early exit instead of the algorithm. Which of the
    // two blocks at the bottom level wins is not the point and is not asserted
    // — the deepest level carries no vote, so it is a zero-zero tie the
    // tie-break settles on the larger root. The DEPTH is the point.
    let head1 = s1.head(&t1, GENESIS, &c1);
    let reached = u32::from_be_bytes(head1[1..5].try_into().unwrap());
    assert_eq!(reached, D - 1, "the descent stopped short, at depth {reached}");
    assert_eq!(
        head1,
        s1.head_reference(&t1, GENESIS, &c1),
        "the two implementations must agree before their costs are compared"
    );

    let new_small = steps_of(|| {
        s1.head(&t1, GENESIS, &c1);
    });
    let new_big = steps_of(|| {
        s2.head(&t2, GENESIS, &c2);
    });
    let old_small = steps_of(|| {
        s1.head_reference(&t1, GENESIS, &c1);
    });
    let old_big = steps_of(|| {
        s2.head_reference(&t2, GENESIS, &c2);
    });

    let new_ratio = new_big as f64 / new_small as f64;
    let old_ratio = old_big as f64 / old_small as f64;
    println!(
        "depth {D}->{}: new {new_small}->{new_big} (x{new_ratio:.2}), \
         old {old_small}->{old_big} (x{old_ratio:.2})",
        D * 2
    );

    assert!(
        new_ratio < 2.5,
        "fork choice is not linear in depth: {new_small} steps at depth {D}, \
         {new_big} at depth {} (x{new_ratio:.2})",
        D * 2
    );
    assert!(
        old_ratio > 3.5,
        "the implementation this replaced was supposed to be quadratic in \
         depth, but doubling D only multiplied its work by {old_ratio:.2} — \
         the counter is not measuring what this test claims"
    );
    assert!(
        new_big * 8 < old_big,
        "at depth {} the new fork choice walks {new_big} steps and the old \
         one {old_big}; that is not the order-of-magnitude difference this \
         change exists for",
        D * 2
    );
}
