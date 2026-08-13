//! P6 — unit tests for the Phase-2 sync-negotiation frontier layer
//! (`bloch::sync::frontier`).
//!
//! Covers the pure diff/reconciliation predicates and the in-flight tip
//! tracker (`FrontierState`) that gates the blue_work-verified IBD latch. These
//! functions are deliberately closure-parameterized over the DAG membership
//! oracle (`has_block`), so they are exercised here against a plain in-memory
//! `HashSet` — no real `GhostDAG`/PoW needed, matching the pure-function design
//! in legacy/design/CHAIN-SYNC-MODEL.md §3 (Phase 2).

use bloch::sync::frontier::{advertise_tips, diff_missing, reconciled, FrontierState};
use bloch::sync::MAX_ADVERTISED_TIPS;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Deterministic 32-byte hash from a small tag byte.
fn h(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// A DAG membership oracle backed by a set of "present" hashes.
fn oracle(present: &HashSet<[u8; 32]>) -> impl Fn(&[u8; 32]) -> bool + '_ {
    move |x: &[u8; 32]| present.contains(x)
}

// ── advertise_tips ────────────────────────────────────────────────────────────

#[test]
fn advertise_tips_is_sorted_and_deterministic() {
    let unsorted = [h(9), h(1), h(5), h(3)];
    let out = advertise_tips(&unsorted);
    assert_eq!(out, vec![h(1), h(3), h(5), h(9)]);
    // Deterministic regardless of input order.
    let reordered = [h(3), h(9), h(5), h(1)];
    assert_eq!(advertise_tips(&reordered), out);
}

#[test]
fn advertise_tips_truncates_to_cap() {
    // More tips than the cap: result is capped, never longer.
    let many: Vec<[u8; 32]> = (0..300u32)
        .map(|i| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            b
        })
        .collect();
    let out = advertise_tips(&many);
    assert_eq!(out.len(), MAX_ADVERTISED_TIPS);
}

// ── diff_missing ──────────────────────────────────────────────────────────────

#[test]
fn diff_missing_returns_only_absent_tips() {
    let present: HashSet<[u8; 32]> = [h(1), h(2)].into_iter().collect();
    let advertised = [h(1), h(3), h(2), h(4)];
    let missing = diff_missing(&advertised, oracle(&present));
    // Only 3 and 4 are absent, order-preserving.
    assert_eq!(missing, vec![h(3), h(4)]);
}

#[test]
fn diff_missing_dedups_repeated_absent_tips() {
    let present: HashSet<[u8; 32]> = HashSet::new();
    let advertised = [h(7), h(7), h(8), h(7), h(8)];
    let missing = diff_missing(&advertised, oracle(&present));
    assert_eq!(missing, vec![h(7), h(8)]);
}

#[test]
fn diff_missing_empty_when_all_present() {
    let present: HashSet<[u8; 32]> = [h(1), h(2), h(3)].into_iter().collect();
    let advertised = [h(1), h(2), h(3)];
    assert!(diff_missing(&advertised, oracle(&present)).is_empty());
}

// ── FrontierState::to_request / outstanding ───────────────────────────────────

#[test]
fn to_request_records_in_flight_and_skips_on_repeat() {
    let mut fs = FrontierState::new();
    let present: HashSet<[u8; 32]> = [h(1)].into_iter().collect();
    let advertised = [h(1), h(2), h(3)];
    let now = Instant::now();

    // First call: 2 and 3 are missing and get requested + recorded.
    let first = fs.to_request(&advertised, oracle(&present), now);
    assert_eq!(first, vec![h(2), h(3)]);
    assert_eq!(fs.outstanding(), 2);

    // Second call with identical input: both already in flight → nothing new.
    let second = fs.to_request(&advertised, oracle(&present), now);
    assert!(second.is_empty());
    assert_eq!(fs.outstanding(), 2);
}

#[test]
fn to_request_ignores_already_present_tips() {
    let mut fs = FrontierState::new();
    let present: HashSet<[u8; 32]> = [h(1), h(2), h(3)].into_iter().collect();
    let advertised = [h(1), h(2), h(3)];
    assert!(fs
        .to_request(&advertised, oracle(&present), Instant::now())
        .is_empty());
    assert_eq!(fs.outstanding(), 0);
}

// ── FrontierState::note_received ──────────────────────────────────────────────

#[test]
fn note_received_drops_outstanding_by_one() {
    let mut fs = FrontierState::new();
    let present: HashSet<[u8; 32]> = HashSet::new();
    let advertised = [h(2), h(3)];
    fs.to_request(&advertised, oracle(&present), Instant::now());
    assert_eq!(fs.outstanding(), 2);

    fs.note_received(&h(2));
    assert_eq!(fs.outstanding(), 1);
}

#[test]
fn note_received_unknown_hash_is_noop() {
    let mut fs = FrontierState::new();
    let present: HashSet<[u8; 32]> = HashSet::new();
    fs.to_request(&[h(2)], oracle(&present), Instant::now());
    assert_eq!(fs.outstanding(), 1);

    fs.note_received(&h(99)); // never in flight
    assert_eq!(fs.outstanding(), 1);
}

// ── FrontierState::expired ────────────────────────────────────────────────────

#[test]
fn expired_returns_stale_and_restamps() {
    let mut fs = FrontierState::new();
    let present: HashSet<[u8; 32]> = HashSet::new();
    let t0 = Instant::now();
    fs.to_request(&[h(4), h(5)], oracle(&present), t0);

    let timeout = Duration::from_secs(30);
    // Nothing stale immediately after request.
    assert!(fs.expired(timeout, t0).is_empty());

    // Well past the timeout: both entries surface as re-requestable.
    let later = t0 + Duration::from_secs(31);
    let mut stale = fs.expired(timeout, later);
    stale.sort_unstable();
    assert_eq!(stale, vec![h(4), h(5)]);

    // They were re-stamped to `later`, so an immediate second sweep is empty
    // (still in flight, not yet expired again).
    assert!(fs.expired(timeout, later).is_empty());
    // And they remain outstanding — expiry re-requests, it does not clear.
    assert_eq!(fs.outstanding(), 2);
}

// ── reconciled ────────────────────────────────────────────────────────────────

#[test]
fn reconciled_false_when_a_tip_is_absent() {
    let present: HashSet<[u8; 32]> = [h(1)].into_iter().collect();
    let advertised = [h(1), h(2)];
    assert!(!reconciled(&advertised, oracle(&present), 0, |_| false));
}

#[test]
fn reconciled_false_when_outstanding_nonzero() {
    let present: HashSet<[u8; 32]> = [h(1), h(2)].into_iter().collect();
    let advertised = [h(1), h(2)];
    assert!(!reconciled(&advertised, oracle(&present), 1, |_| false));
}

#[test]
fn reconciled_true_only_when_all_present_and_nothing_in_flight() {
    let present: HashSet<[u8; 32]> = [h(1), h(2)].into_iter().collect();
    let advertised = [h(1), h(2)];
    assert!(reconciled(&advertised, oracle(&present), 0, |_| false));
}

#[test]
fn reconciled_trivially_true_on_empty_advertised_set() {
    let present: HashSet<[u8; 32]> = HashSet::new();
    assert!(reconciled(&[], oracle(&present), 0, |_| false));
}

// ── Fix #1 regression: phantom-tip give-up (abandonment) ────────────────────────
//
// Reviewer defect: `reconciled` required `has_block` for EVERY advertised tip and
// `expired` re-requested a timed-out tip forever, so one connected peer advertising
// a tip whose block is never served pinned the node in IBD (`is_syncing`) forever.
// Fix: after MAX_TIP_ATTEMPTS timed-out re-requests a tip is `abandoned`, drops out
// of `outstanding`, and `reconciled` treats it as resolved; receipt un-abandons it.

use bloch::sync::frontier::MAX_TIP_ATTEMPTS;

/// A phantom tip (never served) is abandoned after MAX_TIP_ATTEMPTS timeouts,
/// stops being outstanding, and lets `reconciled` complete — instead of pinning
/// the node in IBD forever. Receipt then un-abandons it.
#[test]
fn phantom_tip_is_abandoned_after_max_attempts_and_unblocks_reconciled() {
    let phantom = h(42);
    let present: HashSet<[u8; 32]> = HashSet::new(); // never served
    let advertised = [phantom];
    let mut state = FrontierState::new();
    let timeout = Duration::from_secs(30);
    let mut now = Instant::now();

    // First request records it in flight (attempt 1).
    let req = state.to_request(&advertised, oracle(&present), now);
    assert_eq!(req, vec![phantom]);
    assert_eq!(state.outstanding(), 1);
    assert!(!state.is_abandoned(&phantom));

    // Not reconciled while the phantom is in flight (has_block false, not abandoned).
    assert!(!reconciled(&advertised, oracle(&present), state.outstanding(), |x| state.is_abandoned(x)));

    // expired() bumps the attempt count each round. Attempts 2..MAX_TIP_ATTEMPTS-1
    // (the 1st in-flight insert already counts as attempt 1) still re-request it.
    for _ in 0..(MAX_TIP_ATTEMPTS - 2) {
        now += timeout;
        let retry = state.expired(timeout, now);
        assert_eq!(retry, vec![phantom], "still retrying below the give-up threshold");
        assert!(!state.is_abandoned(&phantom));
        assert_eq!(state.outstanding(), 1);
    }

    // The final timeout crosses MAX_TIP_ATTEMPTS: the tip is abandoned, NOT returned.
    now += timeout;
    let retry = state.expired(timeout, now);
    assert!(retry.is_empty(), "abandoned tip is not returned for re-request");
    assert!(state.is_abandoned(&phantom));
    assert_eq!(state.outstanding(), 0, "abandoned tip no longer counts as outstanding");

    // Now reconciled completes even though the phantom's block was never served.
    assert!(
        reconciled(&advertised, oracle(&present), state.outstanding(), |x| state.is_abandoned(x)),
        "an abandoned phantom tip must let reconciled complete (no permanent IBD pin)"
    );

    // Receipt heals: a fork tip that finally arrives is un-abandoned.
    state.note_received(&phantom);
    assert!(!state.is_abandoned(&phantom), "note_received un-abandons a tip");
}

/// A NORMAL tip received before hitting MAX_TIP_ATTEMPTS is never abandoned, and
/// `reconciled` flips true on receipt (has_block), not via the give-up path.
#[test]
fn normal_tip_received_before_giveup_is_never_abandoned() {
    let tip = h(7);
    let mut present: HashSet<[u8; 32]> = HashSet::new();
    let advertised = [tip];
    let mut state = FrontierState::new();
    let timeout = Duration::from_secs(30);
    let mut now = Instant::now();

    let req = state.to_request(&advertised, oracle(&present), now);
    assert_eq!(req, vec![tip]);

    // A couple of timeouts, well below the give-up threshold — still retrying.
    for _ in 0..2 {
        now += timeout;
        let retry = state.expired(timeout, now);
        assert_eq!(retry, vec![tip]);
        assert!(!state.is_abandoned(&tip));
    }
    // Not reconciled yet: still in flight and not present.
    assert!(!reconciled(&advertised, oracle(&present), state.outstanding(), |x| state.is_abandoned(x)));

    // Block arrives: clear in-flight and the DAG now has it.
    present.insert(tip);
    state.note_received(&tip);
    assert!(!state.is_abandoned(&tip));
    assert_eq!(state.outstanding(), 0);
    assert!(
        reconciled(&advertised, oracle(&present), state.outstanding(), |x| state.is_abandoned(x)),
        "reconciled flips true via has_block on normal receipt, not the give-up path"
    );
}

/// An abandoned tip is not re-requested by `to_request` (it stays out until a
/// genuine receipt un-abandons it), so we don't thrash on a known-unreachable tip.
#[test]
fn abandoned_tip_is_not_re_requested() {
    let phantom = h(99);
    let present: HashSet<[u8; 32]> = HashSet::new();
    let advertised = [phantom];
    let mut state = FrontierState::new();
    let timeout = Duration::from_secs(30);
    let mut now = Instant::now();

    state.to_request(&advertised, oracle(&present), now);
    for _ in 0..MAX_TIP_ATTEMPTS {
        now += timeout;
        state.expired(timeout, now);
    }
    assert!(state.is_abandoned(&phantom));

    // to_request must NOT re-add an abandoned tip.
    let req = state.to_request(&advertised, oracle(&present), now);
    assert!(req.is_empty(), "abandoned tip must not be re-requested");
    assert_eq!(state.outstanding(), 0);
}

// ── const wiring ──────────────────────────────────────────────────────────────

#[test]
fn advertised_tips_cap_is_sane() {
    // Guards the shared invariant that the frontier cap matches the wire cap
    // (see tests/sync_wire.rs for the network::MAX_WIRE_TIPS equality).
    assert_eq!(MAX_ADVERTISED_TIPS, 256);
}
