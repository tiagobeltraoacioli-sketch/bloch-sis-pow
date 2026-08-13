//! Per-peer chain-state table for the drop-in Kaspa sync-negotiation layer.
//!
//! Announced hints (`announced_blue_score` / `announced_height`) are UNTRUSTED
//! wire data and never gate the IBD latch; `advertised_tips` drive frontier
//! reconciliation; verified `blue_work` is resolved on demand against the local
//! DAG (see [`PeerStateTable::servable_blue_work`]).

use std::collections::HashMap;
use std::time::Instant;

use libp2p::PeerId;
use parking_lot::RwLock;

/// Per-peer chain-state. `announced_*` are UNTRUSTED wire hints (never gate the
/// latch); `advertised_tips` drive frontier reconciliation; verified blue_work is
/// resolved on demand against the local DAG (see `servable_blue_work`).
#[derive(Clone, Debug)]
pub struct PeerChainState {
    pub announced_blue_score: u64,
    pub announced_height:     u64,
    pub advertised_tips:      Vec<[u8; 32]>,
    pub last_seen:            Instant,
    pub connected:            bool,
}

/// Thread-safe `PeerId -> PeerChainState` table + servable-frontier query.
/// Shared as `Arc<PeerStateTable>`. Locking is internal (single `RwLock`).
pub struct PeerStateTable {
    inner: RwLock<HashMap<PeerId, PeerChainState>>,
}

impl PeerStateTable {
    pub fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()) }
    }

    /// P4: on `SwarmEvent::ConnectionEstablished`.
    pub fn on_connect(&self, peer: PeerId, now: Instant) {
        let mut g = self.inner.write();
        let e = g.entry(peer).or_insert_with(|| PeerChainState {
            announced_blue_score: 0,
            announced_height: 0,
            advertised_tips: Vec::new(),
            last_seen: now,
            connected: true,
        });
        e.connected = true;
        e.last_seen = now;
    }

    /// P4: on `SwarmEvent::ConnectionClosed`. Retains the row but marks it
    /// disconnected so it drops out of servable/connected queries.
    pub fn on_disconnect(&self, peer: &PeerId) {
        if let Some(e) = self.inner.write().get_mut(peer) {
            e.connected = false;
        }
    }

    /// P4: on decode of `Tips` / `PeerTip` / `Version`. For `PeerTip`/`Version`
    /// pass `tips = &[]` (they carry no tip hashes); for `Tips` pass the entry
    /// hashes. Updates hints + `last_seen` and (re)marks the peer connected.
    pub fn observe(
        &self,
        peer: PeerId,
        announced_blue_score: u64,
        announced_height: u64,
        tips: &[[u8; 32]],
        now: Instant,
    ) {
        let mut g = self.inner.write();
        let e = g.entry(peer).or_insert_with(|| PeerChainState {
            announced_blue_score: 0,
            announced_height: 0,
            advertised_tips: Vec::new(),
            last_seen: now,
            connected: true,
        });
        e.connected = true;
        e.last_seen = now;
        if announced_blue_score > e.announced_blue_score {
            e.announced_blue_score = announced_blue_score;
        }
        if announced_height > e.announced_height {
            e.announced_height = announced_height;
        }
        if !tips.is_empty() {
            e.advertised_tips = tips.to_vec();
            e.advertised_tips.truncate(crate::sync::MAX_ADVERTISED_TIPS);
        }
    }

    /// Union (deduped) of advertised tips over CONNECTED peers. P5 feeds this to
    /// `frontier::reconciled` and `frontier::to_request`.
    pub fn connected_advertised_tips(&self) -> Vec<[u8; 32]> {
        let g = self.inner.read();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for s in g.values().filter(|s| s.connected) {
            for h in &s.advertised_tips {
                if seen.insert(*h) {
                    out.push(*h);
                }
            }
        }
        out
    }

    /// Servable frontier: the greatest LOCALLY-VERIFIED blue_work reachable from
    /// a connected peer. `resolve(tip)` returns the tip's blue_work IFF it is in
    /// our DAG (P5 passes `|h| dag.get_node(h).map(|n| n.blue_work)`), else None.
    /// Tips we cannot verify contribute 0 — announced work is never trusted.
    pub fn servable_blue_work<F: Fn(&[u8; 32]) -> Option<u128>>(&self, resolve: F) -> u128 {
        let g = self.inner.read();
        let mut best = 0u128;
        for s in g.values().filter(|s| s.connected) {
            for h in &s.advertised_tips {
                if let Some(w) = resolve(h) {
                    best = best.max(w);
                }
            }
        }
        best
    }

    /// Highest announced blue_score among connected peers — RPC hint ONLY.
    pub fn best_announced_blue_score(&self) -> u64 {
        self.inner
            .read()
            .values()
            .filter(|s| s.connected)
            .map(|s| s.announced_blue_score)
            .max()
            .unwrap_or(0)
    }

    pub fn connected_count(&self) -> usize {
        self.inner.read().values().filter(|s| s.connected).count()
    }

    /// Debug/RPC snapshot.
    pub fn snapshot(&self) -> Vec<(PeerId, PeerChainState)> {
        self.inner.read().iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}

impl Default for PeerStateTable {
    fn default() -> Self {
        Self::new()
    }
}
