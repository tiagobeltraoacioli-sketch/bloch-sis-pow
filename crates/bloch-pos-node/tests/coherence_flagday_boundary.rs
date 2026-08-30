// SPDX-License-Identifier: AGPL-3.0-or-later

//! DEV-15, Coherence wave — the flag-day boundary tests.
//!
//! The wave's derivation of the Coherence roots may only arrive as an
//! epochal flag day: the `params.rs` `*_ACTIVATION_EPOCH` idiom — shipped
//! `u64::MAX` (inert), lowered only with a coordinated fleet rebuild
//! (`LEAKED_ROSTER_ACTIVATION_EPOCH` and `BLOCK_BYTES_V2_ACTIVATION_EPOCH`
//! are the precedents).
//!
//! On this branch (HEAD of the wave base) **the gate does not exist yet**,
//! which is equivalent to an activation epoch of `u64::MAX`: the carried
//! binding is the rule at every reachable epoch. These tests therefore pin
//! three facts, each on the correct side of the seam:
//!
//! 1. **Below the gate** (today: everywhere) a block validates iff it
//!    carries the binding over the parent's CARRIED roots — asserted on
//!    both sides of a representative epoch boundary, because the boundary
//!    roll (`close_epoch`) is where an epoch-keyed gate will read its epoch
//!    and an off-by-one there is a network-wide fork at exactly one slot.
//! 2. **A new-rules block meets an old node**: rejected DETERMINISTICALLY
//!    (same named error on every application) and NOISILY (a distinct
//!    `CoherenceRootMismatch`, never a silent accept, never a generic
//!    error another subsystem could be blamed for).
//! 3. **The gate is closed at every epoch a test can reach** — the canary
//!    that fails the moment derivation activates anywhere without this file
//!    being consciously rewired.
//!
//! ## When the real gate constant lands (the wave's DEV that adds it)
//!
//! Wire it HERE, minimally:
//!   - point `GATE_EPOCH_UNDER_TEST` at the params constant (or at the
//!     test-override hook if the constant ships `u64::MAX`, like
//!     `params::hooks::gates_open_guard` does for the leak-recovery pair);
//!   - `expected_root_below_gate` stays exactly as it is — pre-gate bytes
//!     may not move (that is `coherence_replay_identity.rs`'s pin);
//!   - add the post-gate expectation (derived binding) for epochs
//!     `>= GATE_EPOCH_UNDER_TEST` and flip `gate_is_closed_at_every_
//!     reachable_epoch` into the pre/post pair it documents.

mod coherence_harness;

use bloch_pos_committee::derive::coherence_binding;
use bloch_pos_committee::interfaces::{StateReader, StateTransition, TransitionError};
use bloch_pos_committee::transition::CommittedState;
use bloch_pos_committee::{epoch_of, SLOTS_PER_EPOCH};
use coherence_harness as h;

/// The representative flag-day epoch these tests straddle: N = 2, so the
/// "old side" block sits in epoch 1 and the "new side" block in epoch 2.
/// Representative because nothing epoch-special happens at 2 — which is the
/// point: the gate logic must work at an arbitrary boundary, and 2 is cheap
/// to reach. When the real constant lands, see the module docs.
const GATE_EPOCH_UNDER_TEST: u64 = 2;

/// What a block must carry BELOW the gate: the binding over the parent's
/// carried roots — today the loaded zeros. One definition, used by every
/// test here, so the day it becomes epoch-dependent there is exactly one
/// place to teach that.
fn expected_root_below_gate(parent: &CommittedState) -> [u8; 32] {
    parent.coherence_root()
}

/// What an ungated (or post-gate) derivation would stamp while the pool is
/// empty: the binding over the REAL empty-tree roots, from the C1-frozen
/// `coherence-core` — not an arbitrary wrong value, but the exact bytes the
/// wave's derivation produces on the live (empty-pool) chain.
fn derived_root_for_an_empty_pool() -> [u8; 32] {
    coherence_binding(
        &coherence_core::CommitmentTree::new().root(),
        &coherence_core::NullifierSet::new().root(),
    )
}

/// Fixture: genesis plus an empty block early in epoch N−2, so the boundary
/// blocks below build on a state with some history behind it.
fn chain_to_the_seam() -> (
    bloch_pos_committee::transition::Transition<h::OkVerifier>,
    CommittedState,
    h::ChainSet,
) {
    let (t, genesis, mut chains) = h::genesis_fixture(4, &[]);
    let b1 = h::build_block(&t, &genesis, 1, &[], &mut chains);
    let s1 = h::apply(&t, &genesis, &b1, &[]);
    (t, s1, chains)
}

/// 1. Both sides of the boundary validate under the old behaviour, and both
/// accepted headers carry the carried binding — byte-equal across the seam.
#[test]
fn blocks_on_both_sides_of_the_epoch_boundary_validate_with_the_carried_binding() {
    let (t, pre, mut chains) = chain_to_the_seam();

    // Last slot of epoch N−1.
    let last_old = GATE_EPOCH_UNDER_TEST * SLOTS_PER_EPOCH - 1;
    assert_eq!(epoch_of(last_old), GATE_EPOCH_UNDER_TEST - 1, "fixture arithmetic");
    let old_side = h::build_block(&t, &pre, last_old, &[], &mut chains);
    assert_eq!(
        old_side.header.coherence_root,
        expected_root_below_gate(&pre),
        "the epoch N-1 block does not carry the carried binding"
    );
    let s_old = h::apply(&t, &pre, &old_side, &[]);

    // First slot of epoch N — the seam block. Crossing the boundary is
    // `close_epoch` territory: if a gate ever reads the wrong epoch here,
    // this is the block that forks.
    let first_new = GATE_EPOCH_UNDER_TEST * SLOTS_PER_EPOCH;
    assert_eq!(epoch_of(first_new), GATE_EPOCH_UNDER_TEST, "fixture arithmetic");
    let new_side = h::build_block(&t, &s_old, first_new, &[], &mut chains);
    let s_new = h::apply(&t, &s_old, &new_side, &[]);

    // On HEAD the rule is "carry" on BOTH sides, so the two headers agree
    // byte for byte on coherence_root. When the flag day lands with a gate
    // at this epoch, the second assertion is the one that legitimately
    // changes — under a conscious edit of this file, not silently.
    assert_eq!(
        old_side.header.coherence_root, new_side.header.coherence_root,
        "the two sides of the boundary disagree on coherence_root — a gate \
         activated without this file being rewired (see module docs)"
    );
    assert_eq!(s_new.slot(), first_new);
    assert_eq!(epoch_of(s_new.slot()), GATE_EPOCH_UNDER_TEST);
}

/// 2. The outdated-node scenario, exactly as it would happen on deploy day:
/// a block stamped under derivation semantics reaches a node running this
/// branch. The node must reject it — deterministically, with the named
/// error, on every retry — and must never silently accept it.
#[test]
fn an_outdated_node_rejects_a_new_rules_block_deterministically_and_noisily() {
    let (t, pre, mut chains) = chain_to_the_seam();
    let slot = GATE_EPOCH_UNDER_TEST * SLOTS_PER_EPOCH;

    // A block that is valid in every respect EXCEPT that its coherence_root
    // is the derived (empty-pool) binding — what a new-rules producer would
    // actually gossip. state_root is left as the old-rules builder computed
    // it, which matches the derived-header reality: the error must fire on
    // the coherence commitment, not be masked by a root mismatch later.
    // Speculative: this block exists to be rejected, so its reveal must not
    // be recorded as spent.
    let mut env = h::speculative_block(&t, &pre, slot, &[], &mut chains);
    env.header.coherence_root = derived_root_for_an_empty_pool();

    let first = t.apply_block(&pre, &env, &[], &[]);
    assert_eq!(
        first,
        Err(TransitionError::CoherenceRootMismatch),
        "an old node did not name the coherence commitment as the reason — \
         an operator reading logs on deploy day would be sent chasing the \
         wrong subsystem"
    );
    // Deterministic: byte-identical verdict on every application. A reject
    // that depends on iteration order or ambient state is a partition, not
    // a rule.
    for _ in 0..3 {
        assert_eq!(
            t.apply_block(&pre, &env, &[], &[]),
            first,
            "the verdict changed between applications of the same block"
        );
    }
    // Noisy: the variant's Debug form names Coherence, so the node's
    // `apply refused: {e}` log line is attributable at a glance.
    let msg = format!("{:?}", first.unwrap_err());
    assert!(
        msg.contains("Coherence"),
        "the reject does not name Coherence in its log form: {msg}"
    );

    // The same must hold for a garbage coherence_root — the reject is about
    // the commitment being wrong, not about recognising one specific rival.
    let mut garbage = h::speculative_block(&t, &pre, slot, &[], &mut chains);
    garbage.header.coherence_root = [0xAB; 32];
    assert_eq!(
        t.apply_block(&pre, &garbage, &[], &[]),
        Err(TransitionError::CoherenceRootMismatch),
    );
}

/// 3. The canary: at every epoch a test can reach on this branch, the rule
/// is still "carry", and the derived binding is still a reject. This test
/// is DESIGNED to fail the moment someone activates derivation anywhere —
/// including behind a gate whose default is not `u64::MAX` — without
/// consciously rewiring this file (module docs say how).
#[test]
fn the_gate_is_closed_at_every_reachable_epoch() {
    let (t, mut st, mut chains) = h::genesis_fixture(4, &[]);

    // Walk several epochs, one block per epoch (the rest of each epoch is
    // closed implicitly by the next block's boundary roll), asserting the
    // carried binding at each step. Six epochs is far past every
    // representative gate a test would place, and cheap.
    for e in 1..=6u64 {
        let slot = e * SLOTS_PER_EPOCH; // first slot of epoch e
        let env = h::build_block(&t, &st, slot, &[], &mut chains);
        assert_eq!(
            env.header.coherence_root,
            expected_root_below_gate(&st),
            "epoch {e}: the builder stamped something other than the carried \
             binding — derivation is live somewhere"
        );
        assert_ne!(
            env.header.coherence_root,
            derived_root_for_an_empty_pool(),
            "epoch {e}: the carried binding EQUALS the derived empty-pool \
             binding — the demonstration of the fork is vacuous, re-examine \
             the whole gate"
        );
        st = h::apply(&t, &st, &env, &[]);

        // And the derived header is still a named reject at this epoch —
        // built speculatively, so the rejected block burns no reveal.
        let mut rival = h::speculative_block(&t, &st, slot + 1, &[], &mut chains);
        rival.header.coherence_root = derived_root_for_an_empty_pool();
        assert_eq!(
            t.apply_block(&st, &rival, &[], &[]),
            Err(TransitionError::CoherenceRootMismatch),
            "epoch {e}: a derived-roots block was not rejected"
        );
    }
}
