// SPDX-License-Identifier: AGPL-3.0-or-later

//! Address ranges for the Sentinel ban table. Node-local; nothing here is
//! consensus input.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Narrowest range the admin socket may ban, per family: no wider than a /16
/// for IPv4 and a /48 for IPv6.
pub(crate) const MIN_PREFIX_V4: u8 = 16;
pub(crate) const MIN_PREFIX_V6: u8 = 48;

/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are the IPv4 address: a
/// dual-stack listener reports a v4 dialer that way, and a ban on one
/// spelling must hold against the other.
pub(crate) fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// One network: an address with its host bits cleared, and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// The single address `ip` (`/32` or `/128`).
    pub(crate) fn host(ip: IpAddr) -> Self {
        let ip = normalize(ip);
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        Cidr { net: ip, prefix }
    }

    /// `ip/prefix` with host bits cleared; `None` if the prefix is longer
    /// than the family allows.
    pub(crate) fn new(ip: IpAddr, prefix: u8) -> Option<Self> {
        let ip = normalize(ip);
        match ip {
            IpAddr::V4(v4) if prefix <= 32 => {
                Some(Cidr { net: IpAddr::V4(Ipv4Addr::from(mask_v4(u32::from(v4), prefix))), prefix })
            }
            IpAddr::V6(v6) if prefix <= 128 => {
                Some(Cidr { net: IpAddr::V6(Ipv6Addr::from(mask_v6(u128::from(v6), prefix))), prefix })
            }
            _ => None,
        }
    }

    /// Parse `a.b.c.d`, `a.b.c.d/n`, an IPv6 address, or `v6/n`.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() || text.len() > 64 {
            return Err("address must be 1..64 characters".into());
        }
        match text.split_once('/') {
            None => text
                .parse::<IpAddr>()
                .map(Cidr::host)
                .map_err(|_| format!("`{text}` is not an IP address")),
            Some((addr, len)) => {
                let ip = addr.parse::<IpAddr>().map_err(|_| format!("`{addr}` is not an IP address"))?;
                if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("`{len}` is not a prefix length"));
                }
                let prefix: u8 = len.parse().map_err(|_| format!("`{len}` is not a prefix length"))?;
                // A mapped v4 address with a v6 prefix: express it in v4 bits.
                let (ip, prefix) = match ip {
                    IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
                        if prefix < 96 {
                            return Err("an IPv4-mapped range must have a prefix of at least /96".into());
                        }
                        (ip, prefix - 96)
                    }
                    _ => (ip, prefix),
                };
                Cidr::new(ip, prefix).ok_or_else(|| format!("prefix /{prefix} is too long for that address family"))
            }
        }
    }

    pub(crate) fn is_v4(&self) -> bool {
        self.net.is_ipv4()
    }

    /// Whether this range is no wider than the admin socket allows.
    pub(crate) fn within_ban_width(&self) -> bool {
        if self.is_v4() { self.prefix >= MIN_PREFIX_V4 } else { self.prefix >= MIN_PREFIX_V6 }
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, normalize(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => mask_v4(u32::from(ip), self.prefix) == u32::from(net),
            (IpAddr::V6(net), IpAddr::V6(ip)) => mask_v6(u128::from(ip), self.prefix) == u128::from(net),
            _ => false,
        }
    }

    /// Two prefixes overlap exactly when the shorter contains the other's
    /// network address.
    pub(crate) fn overlaps(&self, other: &Cidr) -> bool {
        if self.is_v4() != other.is_v4() {
            return false;
        }
        if self.prefix <= other.prefix { self.contains(other.net) } else { other.contains(self.net) }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

fn mask_v4(bits: u32, prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { bits & (u32::MAX << (32 - u32::from(prefix.min(32)))) }
}

fn mask_v6(bits: u128, prefix: u8) -> u128 {
    if prefix == 0 { 0 } else { bits & (u128::MAX << (128 - u32::from(prefix.min(128)))) }
}

/// The /24 (IPv4) or /64 (IPv6) an address belongs to, for the concentration
/// report.
pub(crate) fn concentration_bucket(ip: IpAddr) -> Cidr {
    let ip = normalize(ip);
    let prefix = if ip.is_ipv4() { 24 } else { 64 };
    // Cannot fail: 24 <= 32 and 64 <= 128.
    Cidr::new(ip, prefix).unwrap_or_else(|| Cidr::host(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_and_ranges_and_clears_host_bits() {
        assert_eq!(Cidr::parse("10.1.2.3").unwrap().to_string(), "10.1.2.3/32");
        assert_eq!(Cidr::parse("10.1.2.3/16").unwrap().to_string(), "10.1.0.0/16");
        assert_eq!(Cidr::parse("2001:db8::1/48").unwrap().to_string(), "2001:db8::/48");
        assert_eq!(Cidr::parse("::ffff:10.1.2.3").unwrap().to_string(), "10.1.2.3/32");
        assert_eq!(Cidr::parse("::ffff:10.1.2.3/120").unwrap().to_string(), "10.1.2.0/24");
        for bad in ["", "10.1.2.3/33", "10.1.2.3/", "10.1.2.3/-1", "nope", "2001:db8::/129", "1.2.3.4/1x"] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn width_bounds_are_per_family() {
        assert!(Cidr::parse("10.0.0.0/16").unwrap().within_ban_width());
        assert!(!Cidr::parse("10.0.0.0/15").unwrap().within_ban_width());
        assert!(Cidr::parse("2001:db8::/48").unwrap().within_ban_width());
        assert!(!Cidr::parse("2001:db8::/47").unwrap().within_ban_width());
    }

    #[test]
    fn containment_and_overlap() {
        let net = Cidr::parse("192.0.2.0/24").unwrap();
        assert!(net.contains("192.0.2.77".parse().unwrap()));
        assert!(net.contains("::ffff:192.0.2.77".parse().unwrap()));
        assert!(!net.contains("192.0.3.1".parse().unwrap()));
        assert!(!net.contains("2001:db8::1".parse().unwrap()));
        assert!(net.overlaps(&Cidr::parse("192.0.2.9").unwrap()));
        assert!(net.overlaps(&Cidr::parse("192.0.0.0/16").unwrap()));
        assert!(!net.overlaps(&Cidr::parse("192.0.3.0/24").unwrap()));
        let v6 = Cidr::parse("2001:db8:1::/48").unwrap();
        assert!(v6.overlaps(&Cidr::parse("2001:db8:1:2::/64").unwrap()));
        assert!(!v6.overlaps(&net));
    }
}
