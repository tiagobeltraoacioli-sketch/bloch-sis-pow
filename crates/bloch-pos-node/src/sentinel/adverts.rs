// SPDX-License-Identifier: AGPL-3.0-or-later

//! `peer_finalized_ahead`: peers whose blocks advertise a finalized
//! checkpoint this node does not hold as its own.
//!
//! The mesh has no status message; what a peer "advertises" is the
//! `finalized_root` in the headers of the blocks it sends, which a valid
//! block sets to its branch's finalized checkpoint. The engine classifies
//! each advertised root against its own finality (see
//! `engine/sentinel_hooks.rs`) and the result lands here:
//!
//! - `ahead`: the root is a canonical block of ours ABOVE our finalized
//!   checkpoint — the peer finalized further along our own chain;
//! - `conflicting`: the root is a block we hold that is NOT canonical — the
//!   peer finalized a branch we are not on;
//! - `unknown_root`: we do not hold the block at all — the peer is ahead of
//!   us or on another branch, and we cannot yet tell which.
//!
//! The header is read before (and whatever the outcome of) validation, so an
//! entry is an observation, not a proof; each carries the engine's verdict on
//! the block that carried it. Memory is bounded: one entry per source, at
//! most [`MAX_ENTRIES`], and entries age out after [`ENTRY_TTL`].

use std::net::IpAddr;
use std::time::{Duration, Instant};

pub(crate) const MAX_ENTRIES: usize = 32;
pub(crate) const ENTRY_TTL: Duration = Duration::from_secs(1800);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdvertKind {
    Ahead,
    Conflicting,
    UnknownRoot,
}

impl AdvertKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AdvertKind::Ahead => "ahead",
            AdvertKind::Conflicting => "conflicting",
            AdvertKind::UnknownRoot => "unknown_root",
        }
    }
}

/// One observation, as handed over by the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub(crate) source: [u8; 32],
    pub(crate) kind: AdvertKind,
    pub(crate) advertised_finalized: [u8; 32],
    pub(crate) advertised_justified: [u8; 32],
    pub(crate) block_root: [u8; 32],
    pub(crate) block_slot: u64,
    /// Slot of the advertised finalized root's block, when this node holds it.
    pub(crate) root_slot: Option<u64>,
    /// Lowest epoch the advertised checkpoint can be for (`ceil(root_slot /
    /// SLOTS_PER_EPOCH)`), when known.
    pub(crate) epoch_hint: Option<u64>,
    /// Our finalized checkpoint at the time.
    pub(crate) our_finalized_epoch: u64,
    pub(crate) our_finalized_root: [u8; 32],
    pub(crate) verdict: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) obs: Observation,
    pub(crate) addr: Option<IpAddr>,
    pub(crate) first_seen_ms: u64,
    pub(crate) last_seen_ms: u64,
    pub(crate) last_seen: Instant,
    pub(crate) count: u64,
}

#[derive(Debug, Default)]
pub(crate) struct AdvertTable {
    entries: Vec<Entry>,
    pub(crate) evicted: u64,
}

impl AdvertTable {
    /// Record `obs`. Returns `true` when it is news for this source (a new
    /// entry, or a different kind or advertised root than last time) — the
    /// caller emits an event exactly then.
    pub(crate) fn record(&mut self, obs: Observation, addr: Option<IpAddr>, now: Instant, now_ms: u64) -> bool {
        self.expire(now);
        if let Some(e) = self.entries.iter_mut().find(|e| e.obs.source == obs.source) {
            let news = e.obs.kind != obs.kind || e.obs.advertised_finalized != obs.advertised_finalized;
            if news {
                e.first_seen_ms = now_ms;
                e.count = 0;
            }
            e.obs = obs;
            e.addr = addr.or(e.addr);
            e.last_seen = now;
            e.last_seen_ms = now_ms;
            e.count = e.count.saturating_add(1);
            return news;
        }
        if self.entries.len() >= MAX_ENTRIES {
            // Evict the oldest entry, preferring one whose block the engine
            // did not accept: many cheap sources sending unvalidatable blocks
            // must not push out a verified observation.
            let victim = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| (e.obs.verdict == "accept", e.last_seen))
                .map(|(i, _)| i);
            if let Some(oldest) = victim {
                self.entries.swap_remove(oldest);
                self.evicted = self.evicted.saturating_add(1);
            }
        }
        self.entries.push(Entry { obs, addr, first_seen_ms: now_ms, last_seen_ms: now_ms, last_seen: now, count: 1 });
        true
    }

    /// The source now agrees with us (or is behind): it is no longer ahead.
    pub(crate) fn clear(&mut self, source: &[u8; 32]) {
        self.entries.retain(|e| e.obs.source != *source);
    }

    pub(crate) fn expire(&mut self, now: Instant) {
        self.entries.retain(|e| now.saturating_duration_since(e.last_seen) < ENTRY_TTL);
    }

    /// Live entries, most recent first.
    pub(crate) fn live(&self, now: Instant) -> Vec<Entry> {
        let mut v: Vec<Entry> = self
            .entries
            .iter()
            .filter(|e| now.saturating_duration_since(e.last_seen) < ENTRY_TTL)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(source: u8, kind: AdvertKind, root: u8) -> Observation {
        Observation {
            source: [source; 32],
            kind,
            advertised_finalized: [root; 32],
            advertised_justified: [0; 32],
            block_root: [9; 32],
            block_slot: 1,
            root_slot: None,
            epoch_hint: None,
            our_finalized_epoch: 0,
            our_finalized_root: [0; 32],
            verdict: "accept",
        }
    }

    #[test]
    fn one_entry_per_source_and_news_only_on_change() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        assert!(t.record(obs(1, AdvertKind::Ahead, 5), None, now, 0));
        assert!(!t.record(obs(1, AdvertKind::Ahead, 5), None, now, 1));
        assert!(t.record(obs(1, AdvertKind::Conflicting, 5), None, now, 2));
        assert!(t.record(obs(1, AdvertKind::Conflicting, 6), None, now, 3));
        assert_eq!(t.live(now).len(), 1);
        t.clear(&[1; 32]);
        assert!(t.live(now).is_empty());
    }

    #[test]
    fn bounded_and_aging() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        for s in 0..=255u8 {
            t.record(obs(s, AdvertKind::UnknownRoot, 1), None, now + Duration::from_millis(u64::from(s)), 0);
        }
        assert_eq!(t.live(now + Duration::from_secs(1)).len(), MAX_ENTRIES);
        assert_eq!(t.evicted, 256 - MAX_ENTRIES as u64);
        // The newest survive.
        assert!(t.live(now + Duration::from_secs(1)).iter().all(|e| e.obs.source[0] as usize >= 256 - MAX_ENTRIES));
        assert!(t.live(now + ENTRY_TTL + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn accepted_observations_outlive_unverified_floods() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        t.record(obs(200, AdvertKind::Ahead, 7), None, now, 0);
        for s in 0..100u8 {
            let mut o = obs(s, AdvertKind::UnknownRoot, 1);
            o.verdict = "ignore";
            t.record(o, None, now + Duration::from_millis(1 + u64::from(s)), 0);
        }
        assert!(t.live(now + Duration::from_secs(1)).iter().any(|e| e.obs.source == [200; 32]));
    }
}
