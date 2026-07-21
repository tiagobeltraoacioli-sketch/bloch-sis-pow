//! Announce-then-pull — TWO-SWARM integration proof for the directed IBD PULL
//! path (`/bloch/sync/1` libp2p request-response).
//!
//! What this proves, over the REAL production transport (Kyber-secured TCP,
//! gossipsub, identify, the full `NetworkNode::run` loop):
//!
//!   1. Node A's IBD `GetBlock` — injected on A's real `outbound_tx`, exactly
//!      as `main.rs`'s message processor emits it — is delivered to node B as a
//!      **directed request-response** request and served by B's network loop
//!      straight from its block store; A receives the answer on its `block_tx`.
//!
//!   2. That fetch NEVER traverses the gossip mesh: B's `block_tx` (the seam
//!      the message-processor reads — i.e. the gossip path) never sees a
//!      `GetBlock`. In the pre-fix code the `_ => "sync"` router broadcast
//!      `GetBlock` to the whole mesh, so it WOULD have landed on B's `block_tx`.
//!      Its absence is the regression assertion for the O(peers) IBD-amplification
//!      fix.
//!
//! B's store is empty, so the served answer is `BlockNotFound` — which is all we
//! need: an empty store still exercises the entire directed path
//! (A.outbound → A.sync_rr.send_request → TCP → B.sync_rr inbound →
//! serve_sync_request(store miss) → BlockNotFound → A.block_tx) without having
//! to synthesise a valid PoW block body.
//!
//! GATE: in-process loopback only. Real-latency / multi-hop / NAT behaviour of
//! the pull path across distributed hosts remains live-net-gated and is NOT
//! claimed here.

use std::sync::Arc;
use std::time::Duration;

use bloch::consensus::GhostDAG;
use bloch::network::{NetworkConfig, NetworkMessage, NetworkNode};
use bloch::sync::peer_state::PeerStateTable;
use bloch::storage::Storage;
use parking_lot::RwLock;
use tokio::sync::mpsc;

const GENESIS: [u8; 32] = [0xEE; 32];
const K: usize = 3;

/// A live in-process node: its real `outbound_tx` (drive it like main.rs) and
/// its `block_rx` (observe exactly what the gossip path delivers upward).
struct Node {
    peer_id: libp2p::PeerId,
    addr: libp2p::Multiaddr,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    block_rx: mpsc::Receiver<NetworkMessage>,
    _dir: tempfile::TempDir,
}

async fn spawn(bootstrap_peers: Vec<String>, archive: bool) -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers,
        dns_seeds: vec![],
        max_peers: 16,
        data_dir: dir.path().to_path_buf(),
        allow_private_peers: true,
        behind_proxy: true,
        enable_mdns: false,
        archive,
    };
    let node = NetworkNode::new(cfg).expect("NetworkNode::new");
    let peer_id = node.peer_id;

    let dag = Arc::new(RwLock::new(GhostDAG::with_k(K)));
    dag.write().add_genesis(GENESIS, 0);
    let peer_state = Arc::new(PeerStateTable::new());
    let store = Arc::new(Storage::open(&dir.path().join("db")).expect("store"));

    let (block_tx, block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, mut addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();

    tokio::spawn(async move {
        let _ = node
            .run(block_tx, outbound_rx, dag, peer_state, store, Some(addr_tx))
            .await;
    });

    // Learn the bound ephemeral TCP (non-WS) addr.
    let addr = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let a = addr_rx.recv().await.expect("listen_report closed");
            let s = a.to_string();
            if s.starts_with("/ip4/127.0.0.1/tcp/") && !s.contains("/ws") {
                return a;
            }
        }
    })
    .await
    .expect("no TCP listen addr within 15s");

    Node { peer_id, addr, outbound_tx, block_rx, _dir: dir }
}

fn full_addr(n: &Node) -> String {
    format!("{}/p2p/{}", n.addr, n.peer_id)
}

/// Drain `rx` until a message matching `pred` arrives, or fail after `timeout`.
/// Returns the matching message.
async fn recv_until<F: Fn(&NetworkMessage) -> bool>(
    rx: &mut mpsc::Receiver<NetworkMessage>,
    pred: F,
    timeout: Duration,
    what: &str,
) -> NetworkMessage {
    tokio::time::timeout(timeout, async {
        loop {
            let m = rx.recv().await.expect("block_rx closed");
            if pred(&m) {
                return m;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout after {timeout:?} waiting for: {what}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directed_getblock_pull_bypasses_gossip() {
    let _ = env_logger::builder().is_test(true).try_init();

    // B is archival (advertised via identify agent-version) → A prefers it.
    let mut b = spawn(vec![], true).await;
    // A dials B.
    let mut a = spawn(vec![full_addr(&b)], false).await;

    // Wait until A has heard a gossip announce FROM B (Version/PeerTip). This
    // guarantees the mesh is up AND A's per-peer sync table now knows B, so the
    // outbound router will select B for a directed pull (not gossip-fallback).
    recv_until(
        &mut a.block_rx,
        |m| matches!(m, NetworkMessage::Version { .. } | NetworkMessage::PeerTip { .. }),
        Duration::from_secs(30),
        "A to receive a gossip announce from B (mesh up + peer known)",
    )
    .await;

    // Also drain B's channel up to now, and start counting: from here on, if a
    // GetBlock ever appears on B's gossip path, the fix regressed.
    // (Give identify a moment so B has learned A too; harmless either way.)
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Inject an IBD GetBlock exactly as main.rs's processor would. Retry a few
    // times: the very first send can still race peer-table population, in which
    // case the router gossip-falls-back and (with no gossip GetBlock responder
    // in this harness) no answer comes — so we re-inject until the DIRECTED
    // path answers.
    let want = [0xABu8; 32];
    let answer = {
        let mut got = None;
        for _ in 0..10 {
            a.outbound_tx
                .send(NetworkMessage::GetBlock { block_hash: want, nonce: 1 })
                .await
                .expect("send GetBlock");
            let r = tokio::time::timeout(
                Duration::from_secs(3),
                recv_until(
                    &mut a.block_rx,
                    |m| matches!(m, NetworkMessage::BlockNotFound { .. }),
                    Duration::from_secs(3),
                    "A to receive directed BlockNotFound",
                ),
            )
            .await;
            if let Ok(m) = r {
                got = Some(m);
                break;
            }
        }
        got.expect("A never received a directed BlockNotFound answer")
    };

    match answer {
        NetworkMessage::BlockNotFound { block_hash, .. } => {
            assert_eq!(block_hash, want, "answer must be for the requested hash");
        }
        other => panic!("unexpected answer: {}", other.kind_name()),
    }

    // The core regression assertion: B's gossip path (block_rx, what the message
    // processor reads) must NEVER have seen the GetBlock — it was served purely
    // over directed request-response inside B's network loop. We drain whatever
    // B buffered and assert no GetBlock is among it.
    let mut saw_getblock_on_gossip = false;
    while let Ok(m) = b.block_rx.try_recv() {
        if matches!(m, NetworkMessage::GetBlock { .. }) {
            saw_getblock_on_gossip = true;
        }
    }
    assert!(
        !saw_getblock_on_gossip,
        "IBD GetBlock leaked onto the gossip mesh (B's processor saw it) — the \
         O(peers) IBD-amplification fix regressed"
    );
}
