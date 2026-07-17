use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Pure: tips we should advertise, bounded to MAX_ADVERTISED_TIPS. Input is
/// `consensus::GhostDAG::tips()`. Deterministic order (sorted) for testability.
pub fn advertise_tips(dag_tips: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut t = dag_tips.to_vec();
    t.sort_unstable();
    t.truncate(crate::sync::MAX_ADVERTISED_TIPS);
    t
}

/// Pure: which advertised tips we lack. `has_block` is the DAG membership oracle
/// (`consensus::GhostDAG::has_block`). Result is deduped, order-preserving.
pub fn diff_missing<F: Fn(&[u8; 32]) -> bool>(
    advertised: &[[u8; 32]],
    has_block: F,
) -> Vec<[u8; 32]> {
    let mut seen = std::collections::HashSet::new();
    advertised
        .iter()
        .filter(|h| !has_block(h) && seen.insert(**h))
        .copied()
        .collect()
}

/// Pure sync-completion predicate. True iff every advertised tip is present and
/// nothing is in flight. `advertised` = union of connected peers' advertised
/// tips (from PeerStateTable::connected_advertised_tips).
pub fn reconciled<F: Fn(&[u8; 32]) -> bool>(
    advertised: &[[u8; 32]],
    has_block: F,
    outstanding: usize,
) -> bool {
    outstanding == 0 && advertised.iter().all(|h| has_block(h))
}

/// In-flight tip-request tracker. Shared as Arc<Mutex<FrontierState>>.
#[derive(Default)]
pub struct FrontierState {
    /// tip hash -> time we last (re)requested it via GetBlock.
    in_flight: HashMap<[u8; 32], Instant>,
}

impl FrontierState {
    pub fn new() -> Self {
        Self {
            in_flight: HashMap::new(),
        }
    }

    /// Number of tip GetBlocks awaiting delivery. Gates IBD release.
    pub fn outstanding(&self) -> usize {
        self.in_flight.len()
    }

    /// Compute newly-missing tips to GetBlock: diff_missing MINUS already
    /// in-flight, and record the ones returned as in-flight at `now`.
    /// P5 sends a GetBlock for each returned hash.
    pub fn to_request<F: Fn(&[u8; 32]) -> bool>(
        &mut self,
        advertised: &[[u8; 32]],
        has_block: F,
        now: Instant,
    ) -> Vec<[u8; 32]> {
        let missing = diff_missing(advertised, has_block);
        let mut out = Vec::new();
        for h in missing {
            if !self.in_flight.contains_key(&h) {
                self.in_flight.insert(h, now);
                out.push(h);
            }
        }
        out
    }

    /// Clear a tip once its block is accepted into the DAG. Call from the
    /// NewBlock-accepted path in P5. No-op if it was never in flight.
    pub fn note_received(&mut self, hash: &[u8; 32]) {
        self.in_flight.remove(hash);
    }

    /// Return in-flight tips older than `timeout` and refresh their timestamp to
    /// `now` (so they can be re-requested by the nudge). P5 re-sends GetBlock.
    pub fn expired(&mut self, timeout: Duration, now: Instant) -> Vec<[u8; 32]> {
        let stale: Vec<[u8; 32]> = self
            .in_flight
            .iter()
            .filter(|(_, t)| now.duration_since(**t) >= timeout)
            .map(|(h, _)| *h)
            .collect();
        for h in &stale {
            self.in_flight.insert(*h, now);
        }
        stale
    }
}
