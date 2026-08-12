// SPDX-License-Identifier: AGPL-3.0-or-later

//! The state root has one derivation path, and this file is what says so.
//!
//! # Why this file exists
//!
//! The crate's founding rule is that a consensus value is derived in exactly
//! one place. For *block identity* that rule is enforced by a source-scanning
//! property test (`header.rs::single_derivation_path`), which was written after
//! integration found two `BlockId` types, two `BlockHeaderV4` types and three
//! copies of the canonical header serialisation.
//!
//! Nothing enforced it for the **state root**, and the same thing happened. Two
//! seams grew in parallel — `transition` (the owned state machine the node
//! runs) and `derive`/`produce` (the stateless validator/producer pair) — each
//! deciding for itself which RANDAO mixes the root commits. `transition` kept
//! the retained boundaries *plus* the running mix; `derive` kept
//! `{epoch-1, epoch}`. From epoch 2 on that is three leaves against two: same
//! block, same parent, two different state roots. Two agents found it
//! independently on 2026-08-12, from opposite ends — one auditing which fields
//! were committed, one running a real devnet and noticing `produce.rs` was
//! effectively dead code because the node could not use it.
//!
//! A divergence of this shape does not announce itself. Both seams have green
//! tests, because each tests itself. It surfaces as two honest nodes rejecting
//! each other's blocks — the `expected_bits` failure of 2026-08-08 with a new
//! cause.
//!
//! # What is pinned here
//!
//! The window rule itself, at the boundaries where a length-off-by-one hides:
//! the genesis epoch, the first epoch that can retain anything, and the first
//! epoch where the two old rules disagreed. If someone reintroduces a private
//! retention rule in either seam, one of these fails.

use bloch_pos_committee::state_root::{randao_window, RandaoMix, RANDAO_BOUNDARIES_RETAINED};

fn mix(b: u8) -> [u8; 32] {
    [b; 32]
}

/// Epoch 0 commits exactly one entry: the running mix. There is no history to
/// retain, and an empty window would leave the genesis block's reveal
/// uncommitted.
#[test]
fn genesis_epoch_commits_only_the_running_mix() {
    let w = randao_window(&[], 0, mix(0xAA));
    assert_eq!(w.len(), 1);
    assert_eq!(w[0], RandaoMix { epoch: 0, mix: mix(0xAA) });
}

/// The retention count is a constant, and the window honours it: at epoch `E`
/// the committed set is the running entry plus at most
/// `RANDAO_BOUNDARIES_RETAINED` closed boundaries, and never a boundary older
/// than that.
#[test]
fn window_retains_exactly_the_declared_number_of_boundaries() {
    let history: Vec<RandaoMix> =
        (0..10u64).map(|e| RandaoMix { epoch: e, mix: mix(e as u8) }).collect();
    let epoch = 9;
    let w = randao_window(&history, epoch, mix(0xFF));

    assert_eq!(w.len() as u64, RANDAO_BOUNDARIES_RETAINED + 1);
    let oldest = epoch - RANDAO_BOUNDARIES_RETAINED;
    assert!(w.iter().all(|m| m.epoch >= oldest), "kept a boundary older than the rule allows");
    assert_eq!(w.last().unwrap(), &RandaoMix { epoch, mix: mix(0xFF) });
}

/// **The regression this file is named for.** At epoch 2 the two former rules
/// first disagreed: `transition` committed three entries, `derive` two. The
/// window is one rule now, so the count is whatever the constant says — and if
/// anyone shortens it back, this is the assertion that fires.
#[test]
fn epoch_two_is_where_the_two_old_rules_first_disagreed() {
    let history = vec![
        RandaoMix { epoch: 0, mix: mix(1) },
        RandaoMix { epoch: 1, mix: mix(2) },
    ];
    let w = randao_window(&history, 2, mix(3));

    // Three entries: {0, 1} retained, 2 running. The old `derive` rule produced
    // {1, 2} — two entries, a different leaf set, a different state root.
    assert_eq!(w.len(), 3, "the window lost an entry — the derive-side rule is back");
    assert_eq!(w.iter().map(|m| m.epoch).collect::<Vec<_>>(), vec![0, 1, 2]);
}

/// The running mix always wins over a stale entry for the same epoch. A parent
/// state carrying epoch `E` from an earlier block in that epoch must not shadow
/// the value this block just accumulated — that would commit a mix nobody
/// revealed to.
#[test]
fn running_mix_overrides_a_stale_entry_for_the_same_epoch() {
    let history = vec![
        RandaoMix { epoch: 4, mix: mix(0x11) },
        RandaoMix { epoch: 5, mix: mix(0x22) }, // stale value for the open epoch
    ];
    let w = randao_window(&history, 5, mix(0x99));

    let open = w.iter().find(|m| m.epoch == 5).expect("open epoch must be committed");
    assert_eq!(open.mix, mix(0x99), "a stale parent entry shadowed the accumulated mix");
    assert_eq!(w.iter().filter(|m| m.epoch == 5).count(), 1, "two leaves for one epoch");
}

/// Output cannot depend on how the caller happened to order its history. This
/// is the rule that the sampling path violated once already (the cumulative
/// stake array was built in slice order), so it is pinned wherever a committed
/// value is built from a collection.
#[test]
fn window_is_independent_of_history_order() {
    let mut history = vec![
        RandaoMix { epoch: 6, mix: mix(6) },
        RandaoMix { epoch: 7, mix: mix(7) },
        RandaoMix { epoch: 5, mix: mix(5) },
    ];
    let a = randao_window(&history, 8, mix(8));
    history.reverse();
    let b = randao_window(&history, 8, mix(8));
    assert_eq!(a, b);
}
