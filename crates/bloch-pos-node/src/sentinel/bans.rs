// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Sentinel's bounded, expiring peer ban table.
//!
//! Every bound the admin socket promises is enforced HERE, not at the socket,
//! so no future caller can skip one: TTL 1..=3600 s, at most
//! [`MAX_ACTIVE_BANS`] entries, ranges no wider than /16 (IPv4) or /48
//! (IPv6), and never a range that touches a protected address (the
//! operator's configured peers and loopback).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::cidr::Cidr;

pub(crate) const MAX_ACTIVE_BANS: usize = 256;
pub(crate) const MIN_TTL_SECS: u64 = 1;
pub(crate) const MAX_TTL_SECS: u64 = 3600;
pub(crate) const MAX_REASON_CHARS: usize = 160;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ban {
    pub(crate) range: Cidr,
    pub(crate) reason: String,
    pub(crate) ttl_secs: u64,
    pub(crate) created_ms: u64,
    pub(crate) expires: Instant,
}

impl Ban {
    pub(crate) fn remaining_secs(&self, now: Instant) -> u64 {
        let left = self.expires.saturating_duration_since(now);
        // Round up: a ban with 0.4 s left is still in force.
        left.as_secs() + u64::from(left.subsec_nanos() > 0)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BanError {
    Ttl(u64),
    TooWide(Cidr),
    Protected { range: Cidr, protected: Cidr },
    Full,
}

impl std::fmt::Display for BanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanError::Ttl(t) => write!(f, "ttl_secs must be {MIN_TTL_SECS}..={MAX_TTL_SECS} (got {t})"),
            BanError::TooWide(r) => write!(
                f,
                "{r} is wider than allowed (IPv4 at most /{}, IPv6 at most /{})",
                super::cidr::MIN_PREFIX_V4,
                super::cidr::MIN_PREFIX_V6
            ),
            BanError::Protected { range, protected } => {
                write!(f, "{range} covers protected address {protected} (configured peer or loopback); refused")
            }
            BanError::Full => write!(f, "ban table is full ({MAX_ACTIVE_BANS} active bans)"),
        }
    }
}

/// Keep a reason printable, single-line and short; it lands in logs and in
/// JSON events.
pub(crate) fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect()
}

/// Loopback can never be banned, whatever the configuration says.
pub(crate) fn always_protected() -> [Cidr; 2] {
    [
        Cidr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8).unwrap_or_else(|| Cidr::host(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))),
        Cidr::host(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ]
}

#[derive(Debug, Default)]
pub(crate) struct BanTable {
    bans: Vec<Ban>,
}

impl BanTable {
    /// Add (or renew) a ban. `protected` is every range that must never be
    /// covered; loopback is added here unconditionally.
    pub(crate) fn ban(
        &mut self,
        range: Cidr,
        ttl_secs: u64,
        reason: &str,
        protected: &[Cidr],
        now: Instant,
        now_ms: u64,
    ) -> Result<Ban, BanError> {
        if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_secs) {
            return Err(BanError::Ttl(ttl_secs));
        }
        if !range.within_ban_width() {
            return Err(BanError::TooWide(range));
        }
        for p in always_protected().iter().chain(protected.iter()) {
            if range.overlaps(p) {
                return Err(BanError::Protected { range, protected: *p });
            }
        }
        self.expire(now);
        let ban = Ban {
            range,
            reason: sanitize_reason(reason),
            ttl_secs,
            created_ms: now_ms,
            expires: now + Duration::from_secs(ttl_secs),
        };
        if let Some(existing) = self.bans.iter_mut().find(|b| b.range == range) {
            *existing = ban.clone();
            return Ok(ban);
        }
        if self.bans.len() >= MAX_ACTIVE_BANS {
            return Err(BanError::Full);
        }
        self.bans.push(ban.clone());
        Ok(ban)
    }

    /// Remove the ban on exactly `range`. Returns it if there was one.
    pub(crate) fn unban(&mut self, range: &Cidr) -> Option<Ban> {
        let at = self.bans.iter().position(|b| b.range == *range)?;
        Some(self.bans.swap_remove(at))
    }

    /// Drop expired bans and return them (for the `ban_expired` event).
    pub(crate) fn expire(&mut self, now: Instant) -> Vec<Ban> {
        let mut gone = Vec::new();
        self.bans.retain(|b| {
            if b.expires <= now {
                gone.push(b.clone());
                false
            } else {
                true
            }
        });
        gone
    }

    /// Whether `ip` is inside an unexpired ban. At most
    /// [`MAX_ACTIVE_BANS`] comparisons.
    pub(crate) fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        self.bans.iter().any(|b| b.expires > now && b.range.contains(ip))
    }

    pub(crate) fn active(&self, now: Instant) -> impl Iterator<Item = &Ban> {
        self.bans.iter().filter(move |b| b.expires > now)
    }

    pub(crate) fn len(&self) -> usize {
        self.bans.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn ttl_bounds_are_enforced() {
        let mut t = BanTable::default();
        let now = Instant::now();
        assert_eq!(t.ban(c("203.0.113.5"), 0, "x", &[], now, 0), Err(BanError::Ttl(0)));
        assert_eq!(t.ban(c("203.0.113.5"), 3601, "x", &[], now, 0), Err(BanError::Ttl(3601)));
        assert!(t.ban(c("203.0.113.5"), 1, "x", &[], now, 0).is_ok());
        assert!(t.ban(c("203.0.113.6"), 3600, "x", &[], now, 0).is_ok());
    }

    #[test]
    fn width_bounds_are_enforced() {
        let mut t = BanTable::default();
        let now = Instant::now();
        assert!(matches!(t.ban(c("10.0.0.0/15"), 60, "", &[], now, 0), Err(BanError::TooWide(_))));
        assert!(t.ban(c("10.0.0.0/16"), 60, "", &[], now, 0).is_ok());
        assert!(matches!(t.ban(c("2001:db8::/47"), 60, "", &[], now, 0), Err(BanError::TooWide(_))));
        assert!(t.ban(c("2001:db8::/48"), 60, "", &[], now, 0).is_ok());
    }

    #[test]
    fn protected_peers_and_loopback_can_never_be_banned() {
        let mut t = BanTable::default();
        let now = Instant::now();
        let configured = [c("198.51.100.7"), c("2001:db8:5:6::/64")];
        for range in ["198.51.100.7", "198.51.100.0/24", "198.51.0.0/16", "127.0.0.1", "127.5.0.0/16", "::1", "2001:db8:5::/48", "2001:db8:5:6::99"] {
            assert!(
                matches!(t.ban(c(range), 60, "", &configured, now, 0), Err(BanError::Protected { .. })),
                "{range} must be refused"
            );
        }
        assert!(t.ban(c("198.51.101.0/24"), 60, "", &configured, now, 0).is_ok());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn table_is_capped_and_renewal_does_not_grow_it() {
        let mut t = BanTable::default();
        let now = Instant::now();
        for i in 0..MAX_ACTIVE_BANS {
            let ip = format!("10.{}.{}.1", i / 256, i % 256);
            t.ban(c(&ip), 60, "", &[], now, 0).unwrap();
        }
        assert_eq!(t.ban(c("10.200.0.1"), 60, "", &[], now, 0), Err(BanError::Full));
        // Renewing an existing range is always possible.
        let renewed = t.ban(c("10.0.0.1"), 120, "again", &[], now, 0).unwrap();
        assert_eq!(renewed.ttl_secs, 120);
        assert_eq!(t.len(), MAX_ACTIVE_BANS);
    }

    #[test]
    fn bans_expire_and_stop_matching() {
        let mut t = BanTable::default();
        let now = Instant::now();
        t.ban(c("192.0.2.0/24"), 5, "flood", &[], now, 0).unwrap();
        let inside: IpAddr = "192.0.2.9".parse().unwrap();
        assert!(t.is_banned(inside, now));
        assert!(t.is_banned(inside, now + Duration::from_secs(4)));
        assert!(!t.is_banned(inside, now + Duration::from_secs(5)));
        assert!(t.expire(now + Duration::from_secs(4)).is_empty());
        let gone = t.expire(now + Duration::from_secs(6));
        assert_eq!(gone.len(), 1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn unban_removes_exact_range_only() {
        let mut t = BanTable::default();
        let now = Instant::now();
        t.ban(c("192.0.2.0/24"), 60, "", &[], now, 0).unwrap();
        assert!(t.unban(&c("192.0.2.1")).is_none());
        assert!(t.unban(&c("192.0.2.0/24")).is_some());
        assert!(!t.is_banned("192.0.2.1".parse().unwrap(), now));
    }

    #[test]
    fn reasons_are_sanitized() {
        let long = "a".repeat(500);
        assert_eq!(sanitize_reason(&long).len(), MAX_REASON_CHARS);
        assert_eq!(sanitize_reason("line\nbreak\u{7}"), "linebreak");
    }
}
