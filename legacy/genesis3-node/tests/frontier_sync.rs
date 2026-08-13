//! P6 — integration test for the Phase-2 sync-negotiation layer: end-to-end
//! frontier reconciliation + the blue_work-VERIFIED IBD release condition.
//!
//! This wires the three sync sub-modules together the way the P5 processor and
//! `maybe_release_ibd` do, but without a live libp2p swarm or a real
//! `GhostDAG`/PoW: node A's DAG is modelled as a `HashSet` of present hashes
//! plus a `blue_work` map, node B advertises its frontier through a
//! `PeerStateTable`, and delivery is simulated by inserting hashes into A.
//!
//! It asserts the two properties that motivated Phase 2
//! (legacy/design/CHAIN-SYNC-MODEL.md §2 Layer 3 / §3):
//!   1. A behind-node requests exactly the tips it lacks, converges, and its
//!      IBD-release condition (frontier reconciled AND local blue_work parity)
//!      flips true only after every advertised tip is present.
//!   2. Two divergent tips with IDENTICAL blue_score are BOTH requested — the
//!      set-difference (not scalar-cursor) fix the incident called out.

use bloch::sync::frontier::{reconciled, FrontierState};
use bloch::sync::peer_state::PeerStateTable;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

fn h(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// Minimal stand-in for a local DAG: membership + per-block blue_work.
#[derive(Default)]
struct FakeDag {
    present: HashSet<[u8; 32]>,
    work: HashMap<[u8; 32], u128>,
    selected_tip: Option<[u8; 32]>,
}

impl FakeDag {
    fn add(&mut self, hash: [u8; 32], work: u128) {
        self.present.insert(hash);
        self.work.insert(hash, work);
        // Heaviest present block is the selected tip.
        let is_heavier = self
            .selected_tip
            .and_then(|t| self.work.get(&t).copied())
            .map(|cur| work >= cur)
            .unwrap_or(true);
        if is_heavier {
            self.selected_tip = Some(hash);
        }
    }
    fn has_block(&self, x: &[u8; 32]) -> bool {
        self.present.contains(x)
    }
    fn blue_work(&self, x: &[u8; 32]) -> Option<u128> {
        self.work.get(x).copied()
    }
    fn selected_tip_work(&self) -> u128 {
        self.selected_tip
            .and_then(|t| self.blue_work(&t))
            .unwrap_or(0)
    }
}

/// The `maybe_release_ibd` predicate, replicated over the public sync APIs:
/// frontier reconciled against the connected peers' advertised tips AND our
/// locally-verified selected-tip blue_work is at least the servable frontier.
fn release_condition(dag: &FakeDag, peers: &PeerStateTable, frontier: &FrontierState) -> bool {
    let advertised = peers.connected_advertised_tips();
    let outstanding = frontier.outstanding();
    let done = reconciled(&advertised, |x| dag.has_block(x), outstanding, |x| frontier.is_abandoned(x));
    let servable = peers.servable_blue_work(|x| dag.blue_work(x));
    done && dag.selected_tip_work() >= servable
}

#[test]
fn behind_node_requests_gap_converges_and_then_releases_ibd() {
    // Node A has genesis + one block; node B is two blocks ahead.
    let mut a = FakeDag::default();
    a.add(h(0), 10); // genesis
    a.add(h(1), 20); // A's tip

    // B's advertised frontier: its two tips (which A lacks), with real work.
    // Delivering them into A would give A a heavier selected tip than B's
    // servable frontier claims.
    let b_tip_x = h(2);
    let b_tip_y = h(3);
    let b_work: HashMap<[u8; 32], u128> =
        [(b_tip_x, 30u128), (b_tip_y, 40u128)].into_iter().collect();

    let peers = PeerStateTable::new();
    let peer_b = PeerId::random();
    peers.observe(peer_b, 999, 3, &[b_tip_x, b_tip_y], Instant::now());

    let mut frontier = FrontierState::new();

    // --- Before reconciliation: A lacks both tips → NOT releasable. ---
    assert!(
        !release_condition(&a, &peers, &frontier),
        "must stay in IBD while advertised tips are missing"
    );

    // A computes the gap to request against its own DAG.
    let now = Instant::now();
    let advertised = peers.connected_advertised_tips();
    let to_req = frontier.to_request(&advertised, |x| a.has_block(x), now);
    let mut req_sorted = to_req.clone();
    req_sorted.sort_unstable();
    let mut want = vec![b_tip_x, b_tip_y];
    want.sort_unstable();
    assert_eq!(req_sorted, want, "A must request exactly the tips it lacks");
    assert_eq!(frontier.outstanding(), 2);

    // Outstanding requests alone keep the latch closed.
    assert!(!release_condition(&a, &peers, &frontier));

    // --- Simulate delivery of the missing blocks into A. ---
    for hh in &to_req {
        a.add(*hh, b_work[hh]);
        frontier.note_received(hh);
    }
    assert_eq!(frontier.outstanding(), 0);

    // A now has_block every advertised tip and its heaviest tip (work 40)
    // matches the servable frontier (max verifiable = 40) → releasable.
    assert!(
        release_condition(&a, &peers, &frontier),
        "IBD must release once frontier is reconciled and blue_work has parity"
    );
    assert!(a.has_block(&b_tip_x) && a.has_block(&b_tip_y));
}

#[test]
fn fabricated_high_announced_score_does_not_release_without_servable_blocks() {
    // The incident regression: a peer announces a huge blue_score but serves no
    // blocks A can verify. Release must NOT trigger (announced work is ignored).
    let mut a = FakeDag::default();
    a.add(h(0), 10);
    a.add(h(1), 20);

    let peers = PeerStateTable::new();
    let liar = PeerId::random();
    // Advertises a tip A cannot fetch/verify, with an absurd announced score.
    peers.observe(liar, u64::MAX, u64::MAX, &[h(200)], Instant::now());

    let frontier = FrontierState::new();

    // h(200) is not in A's DAG → reconciled() is false → no release, regardless
    // of the announced score. best_announced_blue_score is a hint only.
    assert_eq!(peers.best_announced_blue_score(), u64::MAX);
    assert!(
        !release_condition(&a, &peers, &frontier),
        "unverifiable advertised tips must never clear the IBD latch"
    );
}

#[test]
fn equal_blue_score_divergent_tips_are_both_requested() {
    // The scalar-cursor bug: two distinct tips share an identical blue_score.
    // A blue_score cursor would fetch only one; the DAG set-difference fetches
    // BOTH. Node B advertises two same-score, different-hash tips.
    let mut a = FakeDag::default();
    a.add(h(0), 10);

    let twin_a = h(11);
    let twin_b = h(12);

    let peers = PeerStateTable::new();
    let peer_b = PeerId::random();
    // Both tips carry the SAME announced blue_score (50); only the hash differs.
    peers.observe(peer_b, 50, 5, &[twin_a, twin_b], Instant::now());

    let mut frontier = FrontierState::new();
    let advertised = peers.connected_advertised_tips();
    let mut to_req = frontier.to_request(&advertised, |x| a.has_block(x), Instant::now());
    to_req.sort_unstable();

    let mut want = vec![twin_a, twin_b];
    want.sort_unstable();
    assert_eq!(
        to_req, want,
        "both equal-blue_score divergent tips must be requested"
    );
    assert_eq!(frontier.outstanding(), 2);
}
