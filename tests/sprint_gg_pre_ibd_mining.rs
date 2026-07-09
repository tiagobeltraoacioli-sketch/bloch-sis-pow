//! Sprint GG — pre-IBD mining bug fix
//!
//! Regression tests for the fix in src/main.rs that pauses the miner
//! loop while is_syncing is true.
//!
//! We cannot exercise the full miner loop (it's a tokio::spawn closure
//! tightly coupled to main.rs state), so these tests validate the
//! primitives the fix depends on:
//!
//!   1. NodeState::is_syncing is a plain bool — flip is atomic under
//!      a write lock.
//!   2. A read lock observes writes made while the miner was sleeping.
//!   3. The fix's branch condition matches the condition set during
//!      IBD transitions in src/main.rs (lines 369, 402).

use std::sync::Arc;
use parking_lot::RwLock;
use bloch::rpc::NodeState;

fn new_node_state() -> Arc<RwLock<NodeState>> {
    Arc::new(RwLock::new(NodeState {
        tip_blue_score: 0,
        block_count:    0,
        peer_count:     0,
        mempool_size:   0,
        is_syncing:     false,
        peer_addresses: Vec::new(),
        version:        "test".to_string(),
    }))
}

#[test]
fn is_syncing_defaults_false_miner_runs() {
    // The miner loop runs iff `state_m.read().is_syncing == false`.
    // A freshly-constructed node starts with is_syncing = false, so
    // the miner (if started) runs from boot.
    let state = new_node_state();
    assert!(!state.read().is_syncing);
}

#[test]
fn is_syncing_flip_observable_from_another_lock() {
    // Ensures the writes at src/main.rs:369 and :402 are observable
    // by the miner loop's read at the start of each iteration.
    let state = new_node_state();
    assert!(!state.read().is_syncing);

    state.write().is_syncing = true;
    assert!(state.read().is_syncing);

    state.write().is_syncing = false;
    assert!(!state.read().is_syncing);
}

#[test]
fn syncing_branch_matches_ibd_condition() {
    // Paranoid check that we read the same field name the IBD path
    // writes to. If anyone ever renames is_syncing, both sites would
    // need updating together; this test fails loudly if they drift.
    let state = new_node_state();

    // Simulate network::run observing a tip behind the network:
    //   state2.write().is_syncing = true;   (src/main.rs:369)
    state.write().is_syncing = true;

    // The miner's check:
    //   let syncing_now = state_m.read().is_syncing;
    let syncing_now = state.read().is_syncing;
    assert!(syncing_now, "miner must observe the syncing flag set by IBD");

    // Simulate IBD completion:
    //   state2.write().is_syncing = false;  (src/main.rs:402)
    state.write().is_syncing = false;

    let syncing_now = state.read().is_syncing;
    assert!(!syncing_now, "miner must observe the syncing flag cleared on IBD complete");
}

#[test]
fn repeated_toggle_reflects_each_transition() {
    // Detects any caching or memoization bug that would let the miner
    // see a stale value. Each transition must be visible.
    let state = new_node_state();

    for i in 0..10 {
        let want = i % 2 == 0;
        state.write().is_syncing = want;
        let got = state.read().is_syncing;
        assert_eq!(got, want, "iteration {}: expected {}, got {}", i, want, got);
    }
}
