// SPDX-License-Identifier: AGPL-3.0-or-later
//! Accept-rate limit for the mesh's post-quantum handshake (audit L1-04).
//!
//! The inbound handshake runs before the dialer is authenticated, and every
//! accepted connection costs this node an ML-KEM encapsulation, an X25519
//! exchange and an ML-DSA-65 signature. The slot table bounds connections
//! held at once (per source and in total), not how fast they are opened: a
//! dialer that replays a precomputed first message, reads the answer and
//! hangs up buys that work as often as it can reconnect. This module bounds
//! the rate instead, with token buckets keyed like the slot table
//! (`connection_limit::limit_key`: an IPv4 address or an IPv6 /64) and one
//! global bucket, checked at accept before any thread, slot or handshake.
//!
//! Who is limited by what (review R-07: a single global bucket let a couple
//! of dozen reconnecting addresses keep it empty and so deny inbound
//! connections to every honest peer outside `--peers`):
//!
//! - **configured** sources (the operator's own `--peers`, granted by address
//!   at accept exactly as the slot table grants their standing) are never
//!   throttled and spend nothing;
//! - **vouched** sources (an address that recently delivered a block or vote
//!   the engine verified, or authenticated against a pin: the slot table's
//!   own notion) are bound by their per-source bucket only, never by a
//!   global one, so strangers cannot lock out validators this node already
//!   hears from;
//! - **strangers** are bound by their per-source bucket and by a global
//!   ceiling made of two buckets: the general one, and a reserve that only a
//!   source that has not tried to connect for `REST` (admitted or refused:
//!   an attempt is an attempt) may draw on. Sources
//!   that keep reconnecting therefore compete for the general bucket among
//!   themselves and cannot spend the reserve a first-time dialer uses; taking
//!   the reserve too needs a continuous supply of fresh /64s or IPv4
//!   addresses, which is a distributed flood the slot table already ranks.
//!
//! Node-local policy only: nothing here changes what a block or a vote is.
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Handshakes one non-configured source may start in a burst: exactly the
/// connections the slot table lets it hold (`MAX_INBOUND_PER_SOURCE`), so a
/// host running many nodes behind one address (sixteen co-hosted validators
/// on mainnet) can still open all its connections at once after a restart.
pub(super) const PER_SOURCE_BURST: f64 = super::MAX_INBOUND_PER_SOURCE as f64;
/// Sustained handshakes per second for one non-configured source.
pub(super) const PER_SOURCE_PER_SEC: f64 = 2.0;
/// Handshakes all strangers together may start in a burst (general bucket).
pub(super) const GLOBAL_BURST: f64 = 64.0;
/// Sustained handshakes per second across all strangers (general bucket):
/// about 30 ms of signing per second at the ML-DSA-65 cost.
pub(super) const GLOBAL_PER_SEC: f64 = 32.0;
/// The reserve only sources with a full bucket of their own may draw on.
pub(super) const RESERVE_BURST: f64 = 32.0;
/// Sustained refill of the reserve.
pub(super) const RESERVE_PER_SEC: f64 = 16.0;
/// How long a source must not have dialled to draw on the reserve.
pub(super) const REST: std::time::Duration = std::time::Duration::from_secs(4);
/// Bound on the per-source table; idle full buckets are dropped first.
const MAX_TRACKED_SOURCES: usize = 4096;

/// A dialer's standing at accept, as the slot table sees its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dialer {
    /// One of the operator's `--peers`.
    Configured,
    /// A source the slot table currently vouches for.
    Vouched,
    /// Anyone else.
    Stranger,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self { tokens: burst, at: now }
    }

    fn refill(&mut self, burst: f64, rate: f64, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.at = now;
    }

    fn take(&mut self) -> bool {
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[derive(Debug)]
pub(super) struct HandshakeRate {
    general: Bucket,
    reserve: Bucket,
    /// Per source: its bucket and when it last tried to connect.
    sources: HashMap<IpAddr, (Bucket, Option<Instant>)>,
}

impl HandshakeRate {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            general: Bucket::full(GLOBAL_BURST, now),
            reserve: Bucket::full(RESERVE_BURST, now),
            sources: HashMap::new(),
        }
    }

    /// May a connection from `ip` start a handshake now?
    pub(super) fn admit(&mut self, ip: IpAddr, dialer: Dialer, now: Instant) -> bool {
        if dialer == Dialer::Configured {
            return true;
        }
        let key = crate::connection_limit::limit_key(ip);
        self.general.refill(GLOBAL_BURST, GLOBAL_PER_SEC, now);
        self.reserve.refill(RESERVE_BURST, RESERVE_PER_SEC, now);
        if self.sources.len() >= MAX_TRACKED_SOURCES && !self.sources.contains_key(&key) {
            self.sources.retain(|_, (bucket, last)| {
                bucket.refill(PER_SOURCE_BURST, PER_SOURCE_PER_SEC, now);
                bucket.tokens < PER_SOURCE_BURST
                    || last.is_some_and(|at| now.saturating_duration_since(at) < REST)
            });
            if self.sources.len() >= MAX_TRACKED_SOURCES {
                // Every tracked source dialled recently; an untracked one
                // cannot be told from them, so it gets the general bucket.
                return dialer == Dialer::Vouched || self.general.take();
            }
        }
        let (source, last) = self.sources.entry(key).or_insert_with(|| (Bucket::full(PER_SOURCE_BURST, now), None));
        let rested = last.is_none_or(|at| now.saturating_duration_since(at) >= REST);
        *last = Some(now);
        source.refill(PER_SOURCE_BURST, PER_SOURCE_PER_SEC, now);
        if source.tokens < 1.0 {
            return false;
        }
        if dialer == Dialer::Stranger && !self.general.take() && !(rested && self.reserve.take()) {
            return false;
        }
        source.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn one_source_is_bounded_per_burst_and_refills() {
        let t0 = Instant::now();
        let mut rate = HandshakeRate::new(t0);
        let admitted = (0..100).filter(|_| rate.admit(ip("192.0.2.7"), Dialer::Stranger, t0)).count();
        assert_eq!(admitted, PER_SOURCE_BURST as usize);
        assert!(rate.admit(ip("192.0.2.8"), Dialer::Stranger, t0), "another source is unaffected");
        let later = t0 + Duration::from_secs(1);
        let refilled = (0..100).filter(|_| rate.admit(ip("192.0.2.7"), Dialer::Stranger, later)).count();
        assert_eq!(refilled, PER_SOURCE_PER_SEC as usize);
        // A vouched source is still bound by its own bucket.
        let vouched = (0..100).filter(|_| rate.admit(ip("192.0.2.9"), Dialer::Vouched, t0)).count();
        assert_eq!(vouched, PER_SOURCE_BURST as usize);
    }

    #[test]
    fn one_ipv6_64_is_one_source() {
        let t0 = Instant::now();
        let mut rate = HandshakeRate::new(t0);
        let admitted = (0..100u16)
            .filter(|n| rate.admit(ip(&format!("2001:db8:5:6::{n:x}")), Dialer::Stranger, t0))
            .count();
        assert_eq!(admitted, PER_SOURCE_BURST as usize);
    }

    /// Review R-07: a few dozen addresses reconnecting as fast as their own
    /// buckets allow, for a minute, never stop a first-time stranger, a
    /// vouched validator or a configured peer from being admitted.
    #[test]
    fn reconnecting_sources_cannot_lock_out_honest_dialers() {
        let t0 = Instant::now();
        let mut rate = HandshakeRate::new(t0);
        let mut flood_admitted = 0usize;
        let mut newcomers = 0usize;
        for tick in 0..600u64 {
            let now = t0 + Duration::from_millis(100 * tick);
            for a in 0..32u8 {
                for _ in 0..4 {
                    flood_admitted += usize::from(rate.admit(ip(&format!("198.51.100.{a}")), Dialer::Stranger, now));
                }
            }
            // Once per second, after the flood's turn: an address never seen.
            if tick % 10 == 9 {
                let fresh = IpAddr::V4(std::net::Ipv4Addr::from(0xCB00_7100 + (tick / 10) as u32));
                assert!(rate.admit(fresh, Dialer::Stranger, now), "a first-time dialer is admitted (tick {tick})");
                newcomers += 1;
                assert!(rate.admit(ip("203.0.113.200"), Dialer::Vouched, now), "a vouched validator reconnects");
                assert!(rate.admit(ip("203.0.113.201"), Dialer::Configured, now));
            }
        }
        assert_eq!(newcomers, 60);
        // The flood itself is held to the general bucket, not the reserve.
        let ceiling = GLOBAL_BURST + RESERVE_BURST + GLOBAL_PER_SEC * 60.0;
        assert!((flood_admitted as f64) <= ceiling, "{flood_admitted} > {ceiling}");
    }

    #[test]
    fn strangers_are_held_to_the_global_ceiling_and_configured_peers_are_exempt() {
        let t0 = Instant::now();
        let mut rate = HandshakeRate::new(t0);
        let admitted = (0..=255u8)
            .flat_map(|a| (0..4).map(move |_| a))
            .filter(|a| rate.admit(ip(&format!("198.51.100.{a}")), Dialer::Stranger, t0))
            .count();
        assert_eq!(admitted, (GLOBAL_BURST + RESERVE_BURST) as usize, "general bucket plus first-contact reserve");
        assert!(!rate.admit(ip("203.0.113.1"), Dialer::Stranger, t0), "both spent: a distributed flood");
        for _ in 0..1000 {
            assert!(rate.admit(ip("203.0.113.9"), Dialer::Configured, t0), "an operator-configured peer is never throttled");
        }
        assert!(rate.admit(ip("203.0.113.1"), Dialer::Stranger, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn the_source_table_stays_bounded() {
        let t0 = Instant::now();
        let mut rate = HandshakeRate::new(t0);
        for n in 0..(MAX_TRACKED_SOURCES as u32 * 2) {
            let a = std::net::Ipv4Addr::from(0x0a00_0000 + n);
            let _ = rate.admit(IpAddr::V4(a), Dialer::Stranger, t0 + Duration::from_millis(u64::from(n)));
        }
        assert!(rate.sources.len() <= MAX_TRACKED_SOURCES);
    }
}
