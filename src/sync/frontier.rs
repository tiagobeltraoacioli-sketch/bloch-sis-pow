use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Give up fetching an advertised tip after this many timed-out re-requests and
/// mark it unreachable (`abandoned`). ~8 × TIP_REQUEST_TIMEOUT(30s) ≈ 4 min —
/// well past the 90s mine-through valve, so a tip that no reachable peer serves
/// (a fork we cannot reach, a partitioned holder, or a lying peer) stops
/// blocking `reconciled` instead of pinning the node in `is_syncing` forever.
pub const MAX_TIP_ATTEMPTS: u32 = 8;

/// Attempt-count jump applied on an EXPLICIT `BlockNotFound` (vs a silent
/// timeout, which adds 1). A tip a peer definitively cannot serve should be
/// abandoned in seconds, not after 4 min of timeouts: two NotFounds (2×4 past
/// the initial attempt of 1) cross `MAX_TIP_ATTEMPTS`. This is the H=3413
/// unstick — the orphan header chain whose bodies are gone network-wide gets
/// abandoned promptly so `maybe_release_ibd` can release `is_syncing`.
pub const NOT_FOUND_PENALTY: u32 = 4;

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

/// Pure sync-completion predicate. True iff every advertised tip is either
/// present (`has_block`) OR abandoned-as-unreachable (`is_abandoned`), and
/// nothing is in flight. An abandoned tip counts as "resolved" so a single
/// unreachable/phantom tip cannot pin the node in IBD forever — the blue_work
/// gate in maybe_release_ibd still guarantees we only release once our own
/// selected chain is at least the best VERIFIED reachable work.
pub fn reconciled<F: Fn(&[u8; 32]) -> bool, G: Fn(&[u8; 32]) -> bool>(
    advertised: &[[u8; 32]],
    has_block: F,
    outstanding: usize,
    is_abandoned: G,
) -> bool {
    outstanding == 0 && advertised.iter().all(|h| has_block(h) || is_abandoned(h))
}

/// In-flight tip-request tracker. Shared as Arc<Mutex<FrontierState>>.
#[derive(Default)]
pub struct FrontierState {
    /// tip hash -> (time we last (re)requested it via GetBlock, attempt count).
    in_flight: HashMap<[u8; 32], (Instant, u32)>,
    /// tips given up on after MAX_TIP_ATTEMPTS timed-out re-requests. They no
    /// longer count as outstanding and `reconciled` treats them as resolved.
    /// A tip leaves this set the instant its block actually arrives
    /// (`note_received`), so a fork that later becomes reachable heals.
    abandoned: HashSet<[u8; 32]>,
}

impl FrontierState {
    pub fn new() -> Self {
        Self { in_flight: HashMap::new(), abandoned: HashSet::new() }
    }

    /// In-flight tip GetBlocks awaiting delivery (excludes abandoned). Gates IBD.
    pub fn outstanding(&self) -> usize {
        self.in_flight.len()
    }

    /// True if we gave up fetching this tip (declared it unreachable).
    pub fn is_abandoned(&self, hash: &[u8; 32]) -> bool {
        self.abandoned.contains(hash)
    }

    /// Newly-missing tips to GetBlock: diff_missing MINUS in-flight MINUS
    /// abandoned; records returned ones as in-flight at `now`.
    pub fn to_request<F: Fn(&[u8; 32]) -> bool>(
        &mut self,
        advertised: &[[u8; 32]],
        has_block: F,
        now: Instant,
    ) -> Vec<[u8; 32]> {
        let missing = diff_missing(advertised, has_block);
        let mut out = Vec::new();
        for h in missing {
            if !self.in_flight.contains_key(&h) && !self.abandoned.contains(&h) {
                self.in_flight.insert(h, (now, 1));
                out.push(h);
            }
        }
        out
    }

    /// Clear a tip once its block is accepted. Also un-abandons it so a fork tip
    /// that finally arrives heals. No-op if neither in flight nor abandoned.
    pub fn note_received(&mut self, hash: &[u8; 32]) {
        self.in_flight.remove(hash);
        self.abandoned.remove(hash);
    }

    /// A peer answered GetBlock with an explicit `BlockNotFound` — a DEFINITIVE
    /// "I don't hold this body" (pruned/unknown), unlike a silent timeout. Count
    /// it toward abandonment AGGRESSIVELY: an unreachable tip that peers NotFound
    /// must not pin the node in IBD for 8×30s of timeouts (which was the H=3413
    /// symptom — the orphan header chain's bodies are gone network-wide, every
    /// peer NotFounds them, yet the node kept `is_syncing=true` forever). Adds
    /// `NOT_FOUND_PENALTY` to the attempt count; at `MAX_TIP_ATTEMPTS` the tip is
    /// abandoned (treated as resolved by `reconciled`, releasing IBD). No-op for
    /// a hash we are not currently chasing.
    pub fn note_not_found(&mut self, hash: &[u8; 32], now: Instant) {
        let attempts = match self.in_flight.get(hash) {
            Some((_, a)) => a.saturating_add(NOT_FOUND_PENALTY),
            None => return,
        };
        if attempts >= MAX_TIP_ATTEMPTS {
            self.in_flight.remove(hash);
            self.abandoned.insert(*hash);
        } else {
            self.in_flight.insert(*hash, (now, attempts));
        }
    }

    /// Timed-out in-flight tips for re-request. Each increments its attempt
    /// count; at MAX_TIP_ATTEMPTS it is moved to `abandoned` (dropped from
    /// in-flight, NOT returned). Otherwise its timestamp refreshes and it is
    /// returned so P5 re-sends GetBlock.
    pub fn expired(&mut self, timeout: Duration, now: Instant) -> Vec<[u8; 32]> {
        let stale: Vec<[u8; 32]> = self
            .in_flight
            .iter()
            .filter(|(_, (t, _))| now.duration_since(*t) >= timeout)
            .map(|(h, _)| *h)
            .collect();
        let mut retry = Vec::new();
        for h in stale {
            let attempts = self.in_flight.get(&h).map(|(_, a)| *a).unwrap_or(0) + 1;
            if attempts >= MAX_TIP_ATTEMPTS {
                self.in_flight.remove(&h);
                self.abandoned.insert(h);
            } else {
                self.in_flight.insert(h, (now, attempts));
                retry.push(h);
            }
        }
        retry
    }
}
