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
//! ## Evidence levels (review R-01)
//!
//! The header is read before validation, and the engine can answer `Ignore`
//! before it has checked any signature. So an observation carries how much
//! it is worth:
//!
//! - `verified`: the engine ACCEPTED the block that carried the header —
//!   proposer signature, ancestry and state transition all checked;
//! - `corroborated`: not verified, but at least [`CORROBORATION_SOURCES`]
//!   sources in different /24 (IPv4) or /64 (IPv6) networks advertise the
//!   same finalized root;
//! - `unverified`: one unauthenticated claim. Listed, counted, never evented.
//!
//! Only `verified` and `corroborated` observations produce an event, and at
//! most one per source per [`EVENT_MIN_INTERVAL`]. An unverified claim never
//! replaces a verified entry of the same source.
//!
//! Memory is bounded: one entry per source, at most [`MAX_ENTRIES`], and
//! entries age out after [`ENTRY_TTL`].

use std::net::IpAddr;
use std::time::{Duration, Instant};

pub(crate) const MAX_ENTRIES: usize = 32;
pub(crate) const ENTRY_TTL: Duration = Duration::from_secs(1800);
/// Independent networks that must advertise the same root before an
/// unverified claim counts as corroborated.
pub(crate) const CORROBORATION_SOURCES: usize = 3;
/// At most one advert event per source in this interval.
pub(crate) const EVENT_MIN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Evidence {
    Unverified,
    Corroborated,
    Verified,
}

impl Evidence {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Evidence::Unverified => "unverified",
            Evidence::Corroborated => "corroborated",
            Evidence::Verified => "verified",
        }
    }
}

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
    /// The engine accepted the carrying block (signature, ancestry and
    /// transition verified). `false` for every other verdict.
    pub(crate) verified: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) obs: Observation,
    pub(crate) addr: Option<IpAddr>,
    /// Highest evidence level an event was emitted at for the current
    /// (kind, root) of this entry, and when.
    evented: Option<(Evidence, Instant)>,
    pub(crate) first_seen_ms: u64,
    pub(crate) last_seen_ms: u64,
    pub(crate) last_seen: Instant,
    pub(crate) count: u64,
}

#[derive(Debug, Default)]
pub(crate) struct AdvertTable {
    entries: Vec<Entry>,
    pub(crate) evicted: u64,
    /// Observations whose carrying block the engine did not accept.
    pub(crate) unverified_total: u64,
}

impl AdvertTable {
    /// Record `obs`. Returns the evidence level to emit an event at, if this
    /// observation warrants one: the level is `verified` or `corroborated`,
    /// it is news for this source at that level (new kind or root, or a
    /// higher level than last evented), and the per-source interval allows.
    pub(crate) fn record(&mut self, obs: Observation, addr: Option<IpAddr>, now: Instant, now_ms: u64) -> Option<Evidence> {
        self.expire(now);
        if !obs.verified {
            self.unverified_total = self.unverified_total.saturating_add(1);
        }
        let source = obs.source;
        match self.entries.iter_mut().find(|e| e.obs.source == source) {
            Some(e) => {
                if e.obs.verified && !obs.verified {
                    // An unauthenticated claim does not displace a verified
                    // observation of the same source.
                    return None;
                }
                let changed = e.obs.kind != obs.kind || e.obs.advertised_finalized != obs.advertised_finalized;
                if changed {
                    e.first_seen_ms = now_ms;
                    e.count = 0;
                    // Keep the timestamp: the per-source interval survives a
                    // change of claim, or alternating claims would defeat it.
                    e.evented = e.evented.map(|(_, at)| (Evidence::Unverified, at));
                }
                e.obs = obs;
                e.addr = addr.or(e.addr);
                e.last_seen = now;
                e.last_seen_ms = now_ms;
                e.count = e.count.saturating_add(1);
            }
            None => {
                if self.entries.len() >= MAX_ENTRIES {
                    // Evict the oldest entry, preferring an unverified one:
                    // many cheap sources sending unvalidatable blocks must
                    // not push out a verified observation.
                    let victim = self
                        .entries
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, e)| (e.obs.verified, e.last_seen))
                        .map(|(i, _)| i);
                    if let Some(oldest) = victim {
                        self.entries.swap_remove(oldest);
                        self.evicted = self.evicted.saturating_add(1);
                    }
                }
                self.entries.push(Entry { obs, addr, evented: None, first_seen_ms: now_ms, last_seen_ms: now_ms, last_seen: now, count: 1 });
            }
        }
        let at = self.entries.iter().position(|e| e.obs.source == source)?;
        let level = self.evidence_of(at);
        let e = self.entries.get_mut(at)?;
        if level == Evidence::Unverified {
            return None;
        }
        match e.evented {
            Some((prev, _)) if prev >= level => None,
            Some((_, last)) if now.saturating_duration_since(last) < EVENT_MIN_INTERVAL => None,
            _ => {
                e.evented = Some((level, now));
                Some(level)
            }
        }
    }

    /// Evidence level of entry `at`: verified, or corroborated by enough
    /// independent networks advertising the same root. At most
    /// [`MAX_ENTRIES`] comparisons.
    fn evidence_of(&self, at: usize) -> Evidence {
        let Some(e) = self.entries.get(at) else { return Evidence::Unverified };
        if e.obs.verified {
            return Evidence::Verified;
        }
        let mut networks: Vec<Option<super::cidr::Cidr>> = Vec::new();
        let mut verified_peer = false;
        for other in &self.entries {
            if other.obs.advertised_finalized != e.obs.advertised_finalized {
                continue;
            }
            verified_peer |= other.obs.verified;
            // A source with no known address is its own (unknown) network
            // and counts once in total.
            let net = other.addr.map(super::cidr::concentration_bucket);
            if !networks.contains(&net) {
                networks.push(net);
            }
        }
        if verified_peer || networks.len() >= CORROBORATION_SOURCES {
            Evidence::Corroborated
        } else {
            Evidence::Unverified
        }
    }

    /// Evidence level of `entry` (a clone handed out by [`Self::live`]).
    pub(crate) fn evidence(&self, entry: &Entry) -> Evidence {
        self.entries
            .iter()
            .position(|e| e.obs.source == entry.obs.source)
            .map_or(Evidence::Unverified, |at| self.evidence_of(at))
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

    fn obs(source: u8, kind: AdvertKind, root: u8, verified: bool) -> Observation {
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
            verdict: if verified { "accept" } else { "ignore" },
            verified,
        }
    }

    fn ip(net: u8, host: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, net, host)))
    }

    #[test]
    fn one_entry_per_source_and_an_event_only_on_verified_news() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        assert_eq!(t.record(obs(1, AdvertKind::Ahead, 5, true), None, now, 0), Some(Evidence::Verified));
        assert_eq!(t.record(obs(1, AdvertKind::Ahead, 5, true), None, now, 1), None);
        // A changed claim inside the per-source interval is recorded, not evented.
        assert_eq!(t.record(obs(1, AdvertKind::Conflicting, 6, true), None, now + Duration::from_secs(1), 2), None);
        assert_eq!(t.live(now)[0].obs.kind, AdvertKind::Conflicting);
        // After the interval the same claim is evented once.
        let later = now + EVENT_MIN_INTERVAL + Duration::from_secs(1);
        assert_eq!(t.record(obs(1, AdvertKind::Conflicting, 6, true), None, later, 3), Some(Evidence::Verified));
        assert_eq!(t.record(obs(1, AdvertKind::Conflicting, 6, true), None, later, 4), None);
        assert_eq!(t.live(later).len(), 1);
        t.clear(&[1; 32]);
        assert!(t.live(later).is_empty());
    }

    /// R-01: an unsigned header from one peer is listed as unverified and
    /// never produces an event, however often it is repeated or varied.
    #[test]
    fn a_single_unverified_claim_is_never_evented() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        for i in 0..200u64 {
            let kind = if i % 2 == 0 { AdvertKind::Conflicting } else { AdvertKind::Ahead };
            let at = now + Duration::from_secs(i * 61);
            assert_eq!(t.record(obs(1, kind, (i % 7) as u8, false), ip(1, 1), at, 0), None);
        }
        assert_eq!(t.unverified_total, 200);
        let live = t.live(now + Duration::from_secs(199 * 61));
        assert_eq!(live.len(), 1);
        assert_eq!(t.evidence(&live[0]), Evidence::Unverified);
    }

    #[test]
    fn independent_networks_corroborate_and_one_network_does_not() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        // Many hosts of one /24: still unverified.
        for h in 1..=10u8 {
            assert_eq!(t.record(obs(h, AdvertKind::Conflicting, 5, false), ip(1, h), now, 0), None);
        }
        // A second network: two networks, not enough.
        assert_eq!(t.record(obs(50, AdvertKind::Conflicting, 5, false), ip(2, 1), now, 0), None);
        // The third independent network corroborates.
        assert_eq!(t.record(obs(51, AdvertKind::Conflicting, 5, false), ip(3, 1), now, 0), Some(Evidence::Corroborated));
        let live = t.live(now);
        assert!(live.iter().all(|e| t.evidence(e) == Evidence::Corroborated));
        // A different root is not corroborated by those.
        assert_eq!(t.record(obs(52, AdvertKind::Conflicting, 6, false), ip(4, 1), now, 0), None);
    }

    #[test]
    fn an_unverified_claim_does_not_displace_a_verified_entry() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        t.record(obs(1, AdvertKind::Ahead, 5, true), None, now, 0);
        assert_eq!(t.record(obs(1, AdvertKind::Conflicting, 9, false), None, now, 0), None);
        let live = t.live(now);
        assert_eq!(live[0].obs.kind, AdvertKind::Ahead);
        assert!(live[0].obs.verified);
    }

    #[test]
    fn bounded_and_aging() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        for s in 0..=255u8 {
            t.record(obs(s, AdvertKind::UnknownRoot, 1, true), None, now + Duration::from_millis(u64::from(s)), 0);
        }
        assert_eq!(t.live(now + Duration::from_secs(1)).len(), MAX_ENTRIES);
        assert_eq!(t.evicted, 256 - MAX_ENTRIES as u64);
        // The newest survive.
        assert!(t.live(now + Duration::from_secs(1)).iter().all(|e| e.obs.source[0] as usize >= 256 - MAX_ENTRIES));
        assert!(t.live(now + ENTRY_TTL + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn verified_observations_outlive_unverified_floods() {
        let now = Instant::now();
        let mut t = AdvertTable::default();
        t.record(obs(200, AdvertKind::Ahead, 7, true), None, now, 0);
        for s in 0..100u8 {
            t.record(obs(s, AdvertKind::UnknownRoot, 1, false), None, now + Duration::from_millis(1 + u64::from(s)), 0);
        }
        assert!(t.live(now + Duration::from_secs(1)).iter().any(|e| e.obs.source == [200; 32]));
    }
}
