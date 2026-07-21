//! Sprint EE (S3) — TRANSPORT-LEVEL two-node convergence + adversarial harness.
//!
//! ══════════════════════════════════════════════════════════════════════════
//! GATE (stated per the rule of engagement — nothing gated is claimed done):
//! this harness covers everything UP TO the live-net gate. What remains
//! LIVE-NET-GATED and is NOT claimed by this file:
//!   - deploying >= 3 real seed hosts and populating the (currently empty)
//!     `core::DEFAULT_SEEDS`;
//!   - running the equivocation / invalid-block / eclipse adversarial matrix
//!     across genuinely distributed hosts (real latency, real NAT, real
//!     multi-hop gossip);
//!   - any claim about eclipse resistance beyond the swarm-level inbound
//!     connection cap exercised here (outbound-peer diversity, addr-manager
//!     bucketing, and network-level sybil economics are untested until then).
//! ══════════════════════════════════════════════════════════════════════════
//!
//! What IS covered, in-process and deterministically wired:
//!   1. TWO real `NetworkNode`s — the full production stack (Kyber-secured TCP
//!      transport, gossipsub with peer scoring, identify, swarm-level
//!      connection limits) — on ephemeral loopback ports, wired via the new
//!      `listen_report` affordance (PART A of this change). This closes the
//!      exact blocker the sprint_ee_convergence.rs header names: "NetworkNode::run
//!      does not currently report its bound ephemeral listen address, so two
//!      in-process nodes cannot be wired deterministically without fixed ports
//!      and CI flakiness."
//!   2. A 7-block diamond-merge block DAG published through node A's real
//!      `outbound_tx` → gossipsub mesh → node B's `block_tx` → processor →
//!      `GhostDAG`, asserting both shared `Arc<RwLock<GhostDAG>>` converge to
//!      identical selected tip / blue score / selected chain / coloring. This
//!      exercises the LIVE transport path, unlike the consensus-only ordering
//!      test in sprint_ee_convergence.rs and the hand-written Tip model in
//!      dst_harness.rs.
//!   3. Equivocation over the live transport: two conflicting blocks at one
//!      height, applied to A in one order and gossiped to B in the OPPOSITE
//!      order — both nodes must reach identical fork choice.
//!   4. Eclipse (inbound-slot) pressure: a victim with `max_peers = 2` under
//!      dial-in pressure from four attacker nodes must hold established
//!      connections at the swarm-level cap.
//!
//! SCOPE HONESTY: the per-node "processor" here decodes a harness-local
//! `SimPayload` from `NewBlock.block_data` and feeds `GhostDAG::add_block`
//! directly. Full block validation (PoW verification, tx validation, coinbase
//! format) is main.rs's processor and is exercised by its own tests; this
//! harness proves the TRANSPORT + CONSENSUS convergence seam node-to-node.
//! The reaction to invalid/oversized frames is asserted deterministically (no
//! swarm) against the extracted `WirePenaltyTracker` unit in src/network/mod.rs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bloch::consensus::GhostDAG;
use bloch::network::{NetworkConfig, NetworkMessage, NetworkNode};
use bloch::sync::peer_state::PeerStateTable;
use parking_lot::RwLock;
use tokio::sync::mpsc;

/// Shared genesis for every harness node.
const GENESIS: [u8; 32] = [0xEE; 32];

/// GhostDAG k for the harness (same as sprint_ee_convergence.rs).
const K: usize = 3;

/// Distinct, deterministic block hash for the harness DAGs.
fn hb(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b[1] = 0xEE;
    b
}

/// Minimal consensus-relevant payload carried inside `NewBlock.block_data`.
/// (See SCOPE HONESTY in the file header: transport+consensus seam only.)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct SimPayload {
    hash:      [u8; 32],
    parents:   Vec<[u8; 32]>,
    timestamp: u64,
    work:      u128,
}

/// Everything the test needs to observe and drive one in-process node.
struct Harness {
    peer_id:     libp2p::PeerId,
    /// The bound TCP (non-websocket) listen addr, learned via `listen_report`.
    addr:        libp2p::Multiaddr,
    dag:         Arc<RwLock<GhostDAG>>,
    peer_state:  Arc<PeerStateTable>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    /// Count of gossip frames received from the mesh (mesh-liveness probe).
    /// Excludes the locally-generated heartbeat `PeerCount`.
    gossip_seen: Arc<AtomicU64>,
    /// Keep the per-node data dir (p2p identity, known_peers.json) alive.
    _dir:        tempfile::TempDir,
}

/// Full dialable multiaddr for a harness node.
fn full_addr(h: &Harness) -> String {
    format!("{}/p2p/{}", h.addr, h.peer_id)
}

/// Spin up one REAL NetworkNode: production `run()` loop, ephemeral loopback
/// port, plus a harness-side processor task on the `block_tx` seam (the same
/// seam main.rs owns in production).
async fn spawn_node(bootstrap_peers: Vec<String>, max_peers: usize) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = NetworkConfig {
        // Ephemeral port — the kernel picks it; PART A reports it back.
        listen_addr:         "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers,
        dns_seeds:           vec![],
        max_peers,
        data_dir:            dir.path().to_path_buf(),
        // Loopback harness: 127.0.0.1 must be dialable/persistable.
        allow_private_peers: true,
        // Every in-process node shares source IP 127.0.0.1; without this the
        // gossipsub ip-colocation penalty would graylist the whole harness
        // mesh (the exact failure mode the flag exists for).
        behind_proxy:        true,
        // Deterministic wiring ONLY via bootstrap_peers — no LAN discovery.
        enable_mdns:         false,
        // Announce-then-pull: harness nodes are not archival advertisers.
        archive:             false,
    };
    let node = NetworkNode::new(cfg).expect("NetworkNode::new");
    let peer_id = node.peer_id;

    let dag = Arc::new(RwLock::new(GhostDAG::with_k(K)));
    dag.write().add_genesis(GENESIS, 0);
    let peer_state = Arc::new(PeerStateTable::new());
    // Announce-then-pull: run() now serves inbound directed GetBlock pulls from
    // the block store. The harness exercises the gossip path, so an empty store
    // is fine (directed GetBlock would answer BlockNotFound).
    let store = Arc::new(
        bloch::storage::Storage::open(&dir.path().join("db")).expect("store"),
    );

    let (block_tx, mut block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    // PART A under test: the listen-addr report channel.
    let (addr_tx, mut addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();

    {
        let dag = dag.clone();
        let peer_state = peer_state.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let _ = node
                .run(block_tx, outbound_rx, dag, peer_state, store, Some(addr_tx))
                .await;
        });
    }

    // Harness processor: NewBlock → decode SimPayload → GhostDAG::add_block,
    // with an orphan buffer because gossip does not guarantee arrival order.
    let gossip_seen = Arc::new(AtomicU64::new(0));
    {
        let dag = dag.clone();
        let seen = gossip_seen.clone();
        tokio::spawn(async move {
            let mut orphans: Vec<SimPayload> = Vec::new();
            while let Some(msg) = block_rx.recv().await {
                // PeerCount is generated LOCALLY by run()'s heartbeat — it is
                // not evidence the gossip mesh delivers. Everything else on
                // this channel came from a peer through gossipsub.
                if !matches!(msg, NetworkMessage::PeerCount { .. }) {
                    seen.fetch_add(1, Ordering::Relaxed);
                }
                if let NetworkMessage::NewBlock { block_data, .. } = msg {
                    if let Ok((p, _)) = bincode::serde::decode_from_slice::<SimPayload, _>(
                        &block_data,
                        bincode::config::standard(),
                    ) {
                        orphans.push(p);
                        // Fixpoint: apply every buffered block whose parents
                        // are all present; repeat until no progress.
                        loop {
                            let before = orphans.len();
                            orphans.retain(|p| {
                                let mut d = dag.write();
                                if d.has_block(&p.hash) {
                                    return false; // duplicate delivery
                                }
                                if !p.parents.iter().all(|h| d.has_block(h)) {
                                    return true; // still an orphan
                                }
                                d.add_block(p.hash, p.parents.clone(), p.timestamp, p.work)
                                    .expect("harness add_block");
                                false
                            });
                            if orphans.len() == before {
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    // Learn the bound TCP (non-WS) listen addr through the PART-A channel.
    // Before PART A this information only existed in a log line — the exact
    // blocker the sprint_ee_convergence.rs header documents.
    let addr = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let a = addr_rx.recv().await.expect("listen_report channel closed");
            let s = a.to_string();
            if s.starts_with("/ip4/127.0.0.1/tcp/") && !s.contains("/ws") {
                return a;
            }
        }
    })
    .await
    .expect("no TCP listen addr reported within 15s");

    Harness { peer_id, addr, dag, peer_state, outbound_tx, gossip_seen, _dir: dir }
}

/// Poll `cond` until true or fail the test after `timeout`.
async fn wait_for<F: FnMut() -> bool>(mut cond: F, timeout: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout after {timeout:?} waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until the two nodes are connected AND the gossipsub mesh has proven it
/// delivers frames in both directions (Version/PeerTip/PeerRequest exchanged
/// on connect and on Subscribed).
async fn wait_for_mesh(a: &Harness, b: &Harness) {
    wait_for(
        || a.peer_state.connected_count() >= 1 && b.peer_state.connected_count() >= 1,
        Duration::from_secs(30),
        "TCP connection A<->B (ConnectionEstablished on both)",
    )
    .await;
    wait_for(
        || a.gossip_seen.load(Ordering::Relaxed) > 0 && b.gossip_seen.load(Ordering::Relaxed) > 0,
        Duration::from_secs(30),
        "gossipsub mesh delivery in both directions",
    )
    .await;
}

/// Producer-side block flow (the miner path): apply to the producer's DAG
/// directly, then gossip `NewBlock` through the producer's REAL outbound
/// channel until every receiver's DAG holds the block.
///
/// The retry loop is deliberate, not flakiness-papering: a publish that races
/// the receiver's topic subscription is lost by design in gossipsub, and a
/// byte-identical republish inside the 30s `duplicate_cache_time` window is
/// dropped LOCALLY (`PublishError::Duplicate` — the exact failure mode
/// documented at length in src/network/mod.rs). Retrying past cache expiry is
/// therefore guaranteed to make progress; the 90s deadline bounds the test.
async fn propagate_block(producer: &Harness, receivers: &[&Harness], p: &SimPayload) {
    {
        let mut d = producer.dag.write();
        if !d.has_block(&p.hash) {
            d.add_block(p.hash, p.parents.clone(), p.timestamp, p.work)
                .expect("producer add_block");
        }
    }
    let data = bincode::serde::encode_to_vec(p, bincode::config::standard()).expect("encode payload");
    let (blue_score, height) = {
        let d = producer.dag.read();
        (d.tip_blue_score(), d.block_count() as u64)
    };
    let msg = NetworkMessage::NewBlock { block_hash: p.hash, blue_score, height, block_data: data };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        if receivers.iter().all(|r| r.dag.read().has_block(&p.hash)) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "block {:02x}.. did not propagate through the gossipsub mesh in 90s",
            p.hash[0]
        );
        producer.outbound_tx.send(msg.clone()).await.expect("outbound_tx closed");
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}

/// The 7-block diamond-merge DAG (same shape as sprint_ee_convergence.rs):
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
fn diamond_specs() -> Vec<SimPayload> {
    let g = GENESIS;
    vec![
        SimPayload { hash: hb(1), parents: vec![g],              timestamp: 1, work: 1_000 }, // A
        SimPayload { hash: hb(2), parents: vec![g],              timestamp: 2, work: 1_000 }, // B
        SimPayload { hash: hb(6), parents: vec![g],              timestamp: 6, work: 1_000 }, // F
        SimPayload { hash: hb(3), parents: vec![hb(1)],          timestamp: 3, work: 1_000 }, // C
        SimPayload { hash: hb(4), parents: vec![hb(2)],          timestamp: 4, work: 1_000 }, // D
        SimPayload { hash: hb(5), parents: vec![hb(3), hb(4)],   timestamp: 5, work: 1_000 }, // E
        SimPayload { hash: hb(7), parents: vec![hb(5), hb(6)],   timestamp: 7, work: 1_000 }, // H
    ]
}

/// Assert two DAGs reached byte-identical consensus state.
fn assert_converged(a: &Harness, b: &Harness, blocks: &[SimPayload]) {
    let da = a.dag.read();
    let db = b.dag.read();
    assert_eq!(da.block_count(), db.block_count(), "block_count diverged");
    assert_eq!(da.selected_tip(), db.selected_tip(), "selected_tip diverged");
    assert_eq!(da.tip_blue_score(), db.tip_blue_score(), "tip_blue_score diverged");
    assert_eq!(da.selected_chain(), db.selected_chain(), "selected_chain diverged");
    let mut tips_a = da.tips();
    let mut tips_b = db.tips();
    tips_a.sort();
    tips_b.sort();
    assert_eq!(tips_a, tips_b, "DAG frontier diverged");
    for p in blocks {
        assert_eq!(
            da.is_blue(&p.hash),
            db.is_blue(&p.hash),
            "blue/red classification diverged for block {:02x}..",
            p.hash[0]
        );
    }
}

// ── 1+2: two-real-node convergence through the live gossipsub mesh ────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_convergence_two_real_nodes_diamond_merge() {
    let a = spawn_node(vec![], 8).await;
    let b = spawn_node(vec![full_addr(&a)], 8).await;
    wait_for_mesh(&a, &b).await;

    // Publish the whole DAG through node A's real outbound channel; node B
    // only ever learns the blocks via gossipsub → block_tx → processor.
    for p in diamond_specs() {
        propagate_block(&a, &[&b], &p).await;
    }

    assert_converged(&a, &b, &diamond_specs());

    // The transport really was the path: B holds every block yet never had
    // one applied directly by the test.
    assert_eq!(b.dag.read().block_count(), 8, "genesis + 7 gossiped blocks");
}

// ── 3: equivocation delivered through the live transport ─────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_equivocation_conflicting_blocks_converge() {
    let a = spawn_node(vec![], 8).await;
    let b = spawn_node(vec![full_addr(&a)], 8).await;
    wait_for_mesh(&a, &b).await;

    // The equivocation pair: two conflicting children of genesis at the same
    // height. A (the equivocator's local view) applies eq1 then eq2; B
    // receives them over the wire in the OPPOSITE order (eq2 gossiped first).
    let eq1 = SimPayload { hash: hb(0xA1), parents: vec![GENESIS], timestamp: 1, work: 1_000 };
    let eq2 = SimPayload { hash: hb(0xB1), parents: vec![GENESIS], timestamp: 1, work: 1_000 };
    {
        let mut d = a.dag.write();
        d.add_block(eq1.hash, eq1.parents.clone(), eq1.timestamp, eq1.work).expect("eq1 @ A");
        d.add_block(eq2.hash, eq2.parents.clone(), eq2.timestamp, eq2.work).expect("eq2 @ A");
    }
    propagate_block(&a, &[&b], &eq2).await; // B sees eq2 first…
    propagate_block(&a, &[&b], &eq1).await; // …then eq1: reversed arrival order.

    // An honest successor merges both equivocating tips, forcing blue/red
    // classification of the pair on both nodes.
    let merge = SimPayload {
        hash:      hb(0xC1),
        parents:   vec![eq1.hash, eq2.hash],
        timestamp: 2,
        work:      1_000,
    };
    propagate_block(&a, &[&b], &merge).await;

    // Identical fork choice despite opposite equivocation arrival order:
    // the equivocation bought the attacker nothing.
    assert_converged(&a, &b, &[eq1, eq2, merge]);
}

// ── 4: eclipse (inbound-slot) pressure against the swarm connection limits ────

/// A victim node with `max_peers = 2` is dialed by FOUR attacker nodes. The
/// swarm-level `connection_limits` behaviour (max_established_incoming =
/// max_peers) must hold established connections at the cap — an attacker
/// cannot fill unbounded inbound slots as eclipse setup.
///
/// GATE HONESTY: this proves the transport-level inbound bound ONLY. Real
/// eclipse resistance (outbound-peer diversity, addr-manager hygiene, sybil
/// economics across real hosts) is part of the LIVE-NET-GATED adversarial
/// matrix and is NOT claimed here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eclipse_inbound_slots_bounded_by_connection_limits() {
    const VICTIM_MAX_PEERS: usize = 2;
    let victim = spawn_node(vec![], VICTIM_MAX_PEERS).await;

    let mut attackers = Vec::new();
    for _ in 0..4 {
        attackers.push(spawn_node(vec![full_addr(&victim)], 8).await);
    }

    // Let the flood land: at least one attacker gets in…
    wait_for(
        || victim.peer_state.connected_count() >= 1,
        Duration::from_secs(30),
        "first attacker connection to the victim",
    )
    .await;
    // …then give every remaining dial ample time to complete or be denied.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // The victim never exceeds its swarm-level inbound cap.
    let connected = victim.peer_state.connected_count();
    assert!(
        connected <= VICTIM_MAX_PEERS,
        "inbound flood exceeded max_established_incoming: {connected} > {VICTIM_MAX_PEERS}"
    );

    // Attacker-side view: at most `VICTIM_MAX_PEERS` of the four attackers
    // hold a live connection to the victim — i.e. at least two dials were
    // refused at the transport layer.
    let attackers_connected_to_victim = attackers
        .iter()
        .filter(|h| {
            h.peer_state
                .snapshot()
                .iter()
                .any(|(pid, st)| *pid == victim.peer_id && st.connected)
        })
        .count();
    assert!(
        attackers_connected_to_victim <= VICTIM_MAX_PEERS,
        "{attackers_connected_to_victim} attackers connected; cap is {VICTIM_MAX_PEERS}"
    );
}
