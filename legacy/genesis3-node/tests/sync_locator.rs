//! P6 — unit tests for the Phase-2 block-locator layer
//! (`bloch::sync::locator`).
//!
//! `build_locator` samples the selected chain with an exponential backoff
//! (dense head, then doubling gaps); `find_common_ancestor` resolves the
//! highest shared block from a received locator. Both are pure and untrusted-
//! input safe (the wire vec is bounded to MAX_WIRE_LOCATOR by P4 before it
//! reaches here). See legacy/design/CHAIN-SYNC-MODEL.md §2 Layer 3.

use bloch::sync::locator::{build_locator, find_common_ancestor, MAX_LOCATOR_LEN};
use std::collections::HashSet;

/// Deterministic 32-byte hash from an index (unique for indices < 2^32).
fn h(n: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    b
}

/// A tip-first → genesis-last selected chain of `len` distinct hashes.
fn chain(len: u32) -> Vec<[u8; 32]> {
    (0..len).map(h).collect()
}

// ── build_locator ─────────────────────────────────────────────────────────────

#[test]
fn build_locator_empty_input_yields_empty() {
    assert!(build_locator(&[]).is_empty());
}

#[test]
fn build_locator_single_element() {
    let out = build_locator(&chain(1));
    assert_eq!(out, vec![h(0)]);
}

#[test]
fn build_locator_dense_head_then_doubling_gaps() {
    let c = chain(200);
    let out = build_locator(&c);

    // Always pins the tip (first) and the oldest/genesis (last) block.
    assert_eq!(out.first().copied(), Some(c[0]));
    assert_eq!(out.last().copied(), Some(c[c.len() - 1]));

    // Dense head: the first 10 sampled hashes are chain indices 0..10.
    assert_eq!(&out[..10], &c[..10]);

    // After the dense head the gaps strictly widen (indices strictly increase,
    // and no gap is smaller than the previous once doubling starts).
    let idx: Vec<usize> = out
        .iter()
        .map(|hh| {
            c.iter()
                .position(|x| x == hh)
                .expect("locator hash in chain")
        })
        .collect();
    for w in idx.windows(2) {
        assert!(
            w[1] > w[0],
            "locator indices must strictly increase: {idx:?}"
        );
    }
    // Beyond the dense prefix, later gaps are >= earlier gaps (backoff).
    let gaps: Vec<usize> = idx.windows(2).map(|w| w[1] - w[0]).collect();
    // The last gap here is to the pinned genesis, which may shrink; check the
    // interior doubling region only (skip the first 9 unit gaps and the final
    // genesis pin).
    if gaps.len() > 11 {
        for w in gaps[9..gaps.len() - 1].windows(2) {
            assert!(w[1] >= w[0], "post-head gaps must not shrink: {gaps:?}");
        }
    }
}

#[test]
fn build_locator_never_exceeds_cap() {
    // A chain far longer than the cap must still produce <= MAX_LOCATOR_LEN.
    let out = build_locator(&chain(1_000_000));
    assert!(out.len() <= MAX_LOCATOR_LEN, "len {} > cap", out.len());
    // Genesis is still pinned as the backstop ancestor.
    assert_eq!(out.last().copied(), Some(h(1_000_000 - 1)));
}

#[test]
fn build_locator_no_duplicate_genesis_pin() {
    // A short chain where the walk already lands on the last element must not
    // append it twice.
    let c = chain(5);
    let out = build_locator(&c);
    assert_eq!(out.last().copied(), Some(c[4]));
    let genesis_count = out.iter().filter(|x| **x == c[4]).count();
    assert_eq!(genesis_count, 1);
}

// ── find_common_ancestor ──────────────────────────────────────────────────────

fn have(set: &HashSet<[u8; 32]>) -> impl Fn(&[u8; 32]) -> bool + '_ {
    move |x: &[u8; 32]| set.contains(x)
}

#[test]
fn find_common_ancestor_returns_first_owned_tip_closest() {
    // Locator is tip-first; we own h(2) and h(3) → the tip-closest (h(2)) wins.
    let locator = [h(0), h(1), h(2), h(3)];
    let owned: HashSet<[u8; 32]> = [h(2), h(3)].into_iter().collect();
    assert_eq!(find_common_ancestor(&locator, have(&owned)), Some(h(2)));
}

#[test]
fn find_common_ancestor_none_when_no_shared_history() {
    let locator = [h(0), h(1), h(2)];
    let owned: HashSet<[u8; 32]> = [h(99)].into_iter().collect();
    assert_eq!(find_common_ancestor(&locator, have(&owned)), None);
}

#[test]
fn find_common_ancestor_empty_locator_is_none() {
    let owned: HashSet<[u8; 32]> = [h(0)].into_iter().collect();
    assert_eq!(find_common_ancestor(&[], have(&owned)), None);
}
