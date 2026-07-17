//! P6 — unit tests for the Phase-2 per-peer chain-state table
//! (`bloch::sync::peer_state::PeerStateTable`).
//!
//! The table records UNTRUSTED wire hints (announced_*) and advertised tips per
//! `PeerId`, and answers the servable-frontier query used by the blue_work-
//! verified IBD latch. Announced scores are RPC hints only and never gate the
//! latch; `servable_blue_work` credits a tip only if the caller's resolver can
//! verify it against the local DAG. See CHAIN-SYNC-MODEL.md §2 Layer 4.

use bloch::sync::peer_state::PeerStateTable;
use libp2p::PeerId;
use std::collections::HashMap;
use std::time::Instant;

fn h(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

// ── connect / observe / disconnect lifecycle ──────────────────────────────────

#[test]
fn connect_and_disconnect_toggle_connected_count() {
    let t = PeerStateTable::new();
    let p = PeerId::random();
    assert_eq!(t.connected_count(), 0);

    t.on_connect(p, Instant::now());
    assert_eq!(t.connected_count(), 1);

    t.on_disconnect(&p);
    assert_eq!(t.connected_count(), 0);
    // Row is retained (snapshot still sees it), just marked disconnected.
    assert_eq!(t.snapshot().len(), 1);
    assert!(!t.snapshot()[0].1.connected);
}

#[test]
fn disconnect_unknown_peer_is_noop() {
    let t = PeerStateTable::new();
    t.on_disconnect(&PeerId::random());
    assert_eq!(t.connected_count(), 0);
    assert!(t.snapshot().is_empty());
}

#[test]
fn observe_creates_row_and_marks_connected() {
    let t = PeerStateTable::new();
    let p = PeerId::random();
    // A Tips observation for a peer we never saw ConnectionEstablished for.
    t.observe(p, 42, 7, &[h(1), h(2)], Instant::now());
    assert_eq!(t.connected_count(), 1);
    let snap = t.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].1.advertised_tips, vec![h(1), h(2)]);
    assert_eq!(snap[0].1.announced_blue_score, 42);
    assert_eq!(snap[0].1.announced_height, 7);
}

#[test]
fn observe_with_empty_tips_preserves_prior_tips_but_bumps_hints() {
    let t = PeerStateTable::new();
    let p = PeerId::random();
    // First a Tips frame carrying hashes.
    t.observe(p, 10, 1, &[h(3), h(4)], Instant::now());
    // Then a PeerTip/Version frame (no tip hashes) with higher scores.
    t.observe(p, 55, 9, &[], Instant::now());

    let snap = t.snapshot();
    // Tips untouched by the empty-tips observation.
    assert_eq!(snap[0].1.advertised_tips, vec![h(3), h(4)]);
    // Monotonic hints raised.
    assert_eq!(snap[0].1.announced_blue_score, 55);
    assert_eq!(snap[0].1.announced_height, 9);
}

#[test]
fn observe_hints_are_monotonic_never_regress() {
    let t = PeerStateTable::new();
    let p = PeerId::random();
    t.observe(p, 100, 50, &[], Instant::now());
    // A lower announced score must not lower the stored hint.
    t.observe(p, 10, 5, &[], Instant::now());
    let snap = t.snapshot();
    assert_eq!(snap[0].1.announced_blue_score, 100);
    assert_eq!(snap[0].1.announced_height, 50);
}

// ── connected_advertised_tips ─────────────────────────────────────────────────

#[test]
fn connected_advertised_tips_is_deduped_union_over_connected_peers_only() {
    let t = PeerStateTable::new();
    let a = PeerId::random();
    let b = PeerId::random();
    let c = PeerId::random();
    let now = Instant::now();
    t.observe(a, 1, 1, &[h(1), h(2)], now);
    t.observe(b, 1, 1, &[h(2), h(3)], now); // h(2) overlaps a
    t.observe(c, 1, 1, &[h(9)], now);
    t.on_disconnect(&c); // c's h(9) must drop out

    let mut got = t.connected_advertised_tips();
    got.sort_unstable();
    let mut want = vec![h(1), h(2), h(3)];
    want.sort_unstable();
    assert_eq!(got, want);
}

// ── servable_blue_work ────────────────────────────────────────────────────────

#[test]
fn servable_blue_work_takes_max_over_verifiable_connected_tips() {
    let t = PeerStateTable::new();
    let a = PeerId::random();
    let b = PeerId::random();
    let now = Instant::now();
    t.observe(a, 1, 1, &[h(1), h(2)], now);
    t.observe(b, 1, 1, &[h(3)], now);

    // Local DAG "knows" h(1)->50, h(3)->200; h(2) is unverifiable → contributes 0.
    let dag: HashMap<[u8; 32], u128> = [(h(1), 50u128), (h(3), 200u128)].into_iter().collect();
    let resolve = |x: &[u8; 32]| dag.get(x).copied();

    assert_eq!(t.servable_blue_work(resolve), 200);
}

#[test]
fn servable_blue_work_ignores_disconnected_peers() {
    let t = PeerStateTable::new();
    let a = PeerId::random();
    let b = PeerId::random();
    let now = Instant::now();
    t.observe(a, 1, 1, &[h(1)], now); // work 50
    t.observe(b, 1, 1, &[h(2)], now); // work 999
    t.on_disconnect(&b);

    let dag: HashMap<[u8; 32], u128> = [(h(1), 50u128), (h(2), 999u128)].into_iter().collect();
    let resolve = |x: &[u8; 32]| dag.get(x).copied();

    // b is disconnected, so its heavy tip must not count.
    assert_eq!(t.servable_blue_work(resolve), 50);
}

#[test]
fn servable_blue_work_zero_when_nothing_verifiable() {
    let t = PeerStateTable::new();
    let a = PeerId::random();
    t.observe(a, 1, 1, &[h(1), h(2)], Instant::now());
    // Resolver never verifies anything (announced work is never trusted).
    assert_eq!(t.servable_blue_work(|_h| None), 0);
}

// ── best_announced_blue_score (RPC hint only) ─────────────────────────────────

#[test]
fn best_announced_blue_score_is_max_over_connected() {
    let t = PeerStateTable::new();
    let a = PeerId::random();
    let b = PeerId::random();
    let now = Instant::now();
    t.observe(a, 30, 1, &[], now);
    t.observe(b, 90, 1, &[], now);
    assert_eq!(t.best_announced_blue_score(), 90);

    t.on_disconnect(&b);
    assert_eq!(t.best_announced_blue_score(), 30);
}

#[test]
fn best_announced_blue_score_zero_with_no_peers() {
    let t = PeerStateTable::new();
    assert_eq!(t.best_announced_blue_score(), 0);
}
