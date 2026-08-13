//! Sprint EE — DAG state convergence under differing block-arrival order.
//!
//! The pre-rebrand backlog listed a "two-node integration harness that wires
//! the gossipsub transports together and asserts state convergence" (Sprint
//! EE). The consensus bug class that harness is meant to catch is
//! *order-dependence*: two honest nodes that receive the same set of blocks in
//! different orders (which is the norm on a gossip network) must converge to an
//! identical selected chain, blue scores, and blue/red classification.
//!
//! The full libp2p transport harness needs a networking API affordance
//! (`NetworkNode::run` does not currently report its bound ephemeral listen
//! address, so two in-process nodes cannot be wired deterministically without
//! fixed ports and CI flakiness). That is tracked as its own change. This test
//! covers the consensus-layer convergence property directly and without
//! flakiness: it feeds the exact same DAG into two `GhostDAG` instances in two
//! different valid topological orders and asserts the resulting state is
//! byte-for-byte identical.

use bloch::consensus::GhostDAG;

type Id = u8;

fn h(n: Id) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// A block specification independent of arrival order: (id, parent ids, ts).
struct Spec {
    id:        Id,
    parents:   &'static [Id],
    timestamp: u64,
}

/// The reference DAG. Non-trivial: two diamonds and a late merge of two tips
/// that sit in each other's anticone, so blue/red classification is exercised.
///
/// ```text
///           G
///        /  |  \
///       A   B   F
///       |   |    \
///       C   D     \
///        \ /       \
///         E ------- H   (H merges E and F)
/// ```
const SPECS: &[Spec] = &[
    Spec { id: 1, parents: &[0],    timestamp: 1 }, // A
    Spec { id: 2, parents: &[0],    timestamp: 2 }, // B
    Spec { id: 6, parents: &[0],    timestamp: 6 }, // F
    Spec { id: 3, parents: &[1],    timestamp: 3 }, // C
    Spec { id: 4, parents: &[2],    timestamp: 4 }, // D
    Spec { id: 5, parents: &[3, 4], timestamp: 5 }, // E (merges C, D)
    Spec { id: 7, parents: &[5, 6], timestamp: 7 }, // H (merges E, F)
];

const GENESIS: Id = 0;
const K: usize = 3;

/// Build a DAG by inserting `SPECS` in the given order. `order` must be a
/// valid topological order (every parent inserted before its child); each
/// entry is an index into `SPECS`.
fn build_in_order(order: &[usize]) -> GhostDAG {
    let mut dag = GhostDAG::with_k(K);
    dag.add_genesis(h(GENESIS), 0);
    for &i in order {
        let s = &SPECS[i];
        let parents: Vec<[u8; 32]> = s.parents.iter().map(|&p| h(p)).collect();
        dag.add_block(h(s.id), parents, s.timestamp, 1000)
            .unwrap_or_else(|e| panic!("add_block for id={} failed: {}", s.id, e));
    }
    dag
}

fn all_ids() -> Vec<Id> {
    let mut ids = vec![GENESIS];
    ids.extend(SPECS.iter().map(|s| s.id));
    ids
}

/// Assert two DAGs have converged to identical consensus state.
fn assert_converged(a: &GhostDAG, b: &GhostDAG) {
    assert_eq!(a.block_count(), b.block_count(), "block_count diverged");
    assert_eq!(a.selected_tip(), b.selected_tip(), "selected_tip diverged");
    assert_eq!(a.tip_blue_score(), b.tip_blue_score(), "tip_blue_score diverged");
    assert_eq!(a.selected_chain(), b.selected_chain(), "selected_chain diverged");

    for id in all_ids() {
        let hash = h(id);
        let da = a.get_block_data(&hash).expect("block missing in DAG a");
        let db = b.get_block_data(&hash).expect("block missing in DAG b");
        assert_eq!(da.blue_score, db.blue_score, "blue_score diverged for id={}", id);
        assert_eq!(da.height, db.height, "height diverged for id={}", id);
        assert_eq!(
            a.is_blue(&hash), b.is_blue(&hash),
            "blue/red classification diverged for id={}", id
        );
    }
}

#[test]
fn same_dag_two_arrival_orders_converge() {
    // Order 1: a natural topological order.
    let order1 = [0, 1, 2, 3, 4, 5, 6]; // A B F C D E H
    // Order 2: a different but still-valid topological order (F early, the
    // two diamonds interleaved). Parents still precede children.
    let order2 = [2, 1, 0, 4, 3, 5, 6]; // F B A D C E H

    let dag1 = build_in_order(&order1);
    let dag2 = build_in_order(&order2);

    assert_converged(&dag1, &dag2);
}

#[test]
fn third_arrival_order_also_converges() {
    // A third permutation, to guard against the two chosen orders happening
    // to share an accidental symmetry.
    let order1 = [0, 1, 2, 3, 4, 5, 6];
    let order3 = [0, 2, 1, 3, 4, 5, 6]; // A F B C D E H

    let dag1 = build_in_order(&order1);
    let dag3 = build_in_order(&order3);

    assert_converged(&dag1, &dag3);
}

#[test]
fn convergence_reaches_the_expected_tip() {
    // Sanity anchor: H (id=7) merges the whole DAG and must be the selected
    // tip, and every block must be present.
    let dag = build_in_order(&[0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(dag.selected_tip(), Some(h(7)), "H should be the selected tip");
    assert_eq!(dag.block_count(), 8, "genesis + 7 blocks expected");
    for id in all_ids() {
        assert!(dag.has_block(&h(id)), "block id={} should be present", id);
    }
}
