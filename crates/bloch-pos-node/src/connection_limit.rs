// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded per-address reservations, released on every worker exit path.
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
#[derive(Default)]
pub(crate) struct Limits(Mutex<BTreeMap<IpAddr, usize>>);
pub(crate) struct Permit {
    limits: Arc<Limits>,
    ip: IpAddr,
}
/// The source a limit is charged to: an IPv4 address, or an IPv6 /64.
///
/// A /64 is the smallest prefix a network hands to one subscriber or one
/// host, and whoever holds it can use any of its 2^64 addresses. Keyed by
/// full address, an IPv6 source therefore had no limit at all. IPv4-mapped
/// IPv6 (`::ffff:a.b.c.d`) is the same host as `a.b.c.d` and shares its key.
pub(crate) fn limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                for octet in octets.iter_mut().skip(8) {
                    *octet = 0;
                }
                IpAddr::V6(octets.into())
            }
        },
        ip => ip,
    }
}
impl Limits {
    pub(crate) fn reserve(self: &Arc<Self>, ip: IpAddr, maximum: usize) -> Option<Permit> {
        let ip = limit_key(ip);
        let mut counts = self.0.lock().ok()?;
        let count = counts.entry(ip).or_default();
        if *count >= maximum {
            return None;
        }
        *count = count.checked_add(1)?;
        Some(Permit {
            limits: self.clone(),
            ip,
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.limits.0.lock() {
            if let Some(count) = counts.get_mut(&self.ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&self.ip);
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_limits_release_and_do_not_block_other_addresses() {
        let limits = Arc::new(Limits::default());
        let ip = "127.0.0.1".parse().unwrap();
        let a = limits.reserve(ip, 1).unwrap();
        assert!(limits.reserve(ip, 1).is_none());
        assert!(limits
            .reserve("::ffff:127.0.0.1".parse().unwrap(), 1)
            .is_none());
        assert!(limits.reserve("127.0.0.2".parse().unwrap(), 1).is_some());
        drop(a);
        assert!(limits.reserve(ip, 1).is_some());
        assert!(limits.0.lock().unwrap().is_empty());
    }
    #[test]
    fn ipv6_limits_are_keyed_by_64_prefix() {
        let key = |text: &str| limit_key(text.parse().unwrap());
        assert_eq!(key("2001:db8:1:2:3:4:5:6"), key("2001:db8:1:2::"));
        assert_eq!(key("2001:db8:1:2:ffff:ffff:ffff:ffff"), key("2001:db8:1:2::1"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:192.0.2.7"), key("192.0.2.7"));
        assert_ne!(key("192.0.2.7"), key("192.0.2.8"));
        // Loopback and the unspecified address are not IPv4-mapped.
        assert_eq!(key("::1"), key("::"));

        let limits = Arc::new(Limits::default());
        let a = limits.reserve("2001:db8:1:2::1".parse().unwrap(), 2).unwrap();
        let _b = limits.reserve("2001:db8:1:2:aaaa::2".parse().unwrap(), 2).unwrap();
        assert!(limits.reserve("2001:db8:1:2:bbbb::3".parse().unwrap(), 2).is_none());
        assert!(limits.reserve("2001:db8:1:3::1".parse().unwrap(), 2).is_some());
        // A permit releases the prefix it was charged to, not its address.
        drop(a);
        assert!(limits.reserve("2001:db8:1:2:cccc::4".parse().unwrap(), 2).is_some());
    }
}
