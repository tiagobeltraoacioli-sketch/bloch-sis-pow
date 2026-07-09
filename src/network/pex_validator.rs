//! Sprint P — PEX Protocol Hardening
//!
//! Validates and rate-limits Peer Exchange (PEX) messages to prevent
//! amplification attacks and private-network pivoting.
//!
//! ## Attacks this module prevents
//!
//! 1. **Amplification scan:** peer sends 10,000 arbitrary IPs, victim dials all
//!    of them. Sprint P caps per-message batch at 20.
//!
//! 2. **Sustained flooding:** peer sends PEX repeatedly to bypass batch limit.
//!    Sprint P applies a sliding rate limit of 100 addresses per 5 min per peer_id.
//!
//! 3. **Local-network pivoting:** peer sends 127.0.0.1, 10.x.x.x, 192.168.x.x,
//!    169.254.x.x. Sprint P rejects unless `--allow-private-peers` is set.
//!
//! 4. **known_peers.json pollution:** bad addresses persist forever. Sprint P
//!    filters on-load and caps at 1000 entries with FIFO eviction.

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

// ── Tunables ─────────────────────────────────────────────────────────────────

/// Max addresses processed per single PeerExchange message.
pub const PEX_BATCH_LIMIT: usize = 20;

/// Sliding window for PEX rate limit (per peer_id).
pub const PEX_RATE_WINDOW: Duration = Duration::from_secs(300);

/// Max addresses from a single peer within the sliding window.
pub const PEX_MAX_PER_WINDOW: usize = 100;

/// Max entries in known_peers.json.
pub const KNOWN_PEERS_CAP: usize = 1000;

/// How often aggregated stats are logged (see PexStats).
pub const PEX_STATS_LOG_INTERVAL: Duration = Duration::from_secs(60);

// ── Address validation ───────────────────────────────────────────────────────

/// Checks whether a string multiaddr is acceptable as a PEX suggestion
/// or a known_peers entry.
///
/// Rules:
/// - Must parse as a valid libp2p Multiaddr
/// - Must contain /tcp/ (we don't PEX QUIC/WebTransport yet)
/// - Must contain /p2p/<peer_id> (need to know who we're dialing)
/// - IP must not be loopback, link-local, or unspecified
/// - When `allow_private=false`: rejects RFC1918 (private networks)
pub fn is_valid_public_multiaddr(addr: &str, allow_private: bool) -> bool {
    let ma: Multiaddr = match addr.parse() {
        Ok(m) => m,
        Err(_) => return false,
    };

    let mut has_tcp = false;
    let mut has_p2p = false;
    let mut ip_ok = false;

    for proto in ma.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                ip_ok = is_acceptable_ipv4(&ip, allow_private);
                if !ip_ok { return false; }
            }
            Protocol::Ip6(ip) => {
                ip_ok = is_acceptable_ipv6(&ip, allow_private);
                if !ip_ok { return false; }
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => {
                // DNS names are opaque here — accept as IP-proxy.
                // Worst case, resolution fails at dial time.
                ip_ok = true;
            }
            Protocol::Tcp(_) => has_tcp = true,
            Protocol::P2p(_) => has_p2p = true,
            _ => {}
        }
    }

    ip_ok && has_tcp && has_p2p
}

/// Whether a multiaddr points at a LAN (private / loopback / link-local) IP.
/// mDNS auto-dial must accept ONLY LAN targets: an mDNS record that names a
/// public IP is a reflection / SSRF attempt (a rogue LAN responder making us
/// dial an arbitrary internet host), and must never be dialed.
pub fn is_lan_multiaddr(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                return ip.is_private() || ip.is_loopback() || ip.is_link_local();
            }
            Protocol::Ip6(ip) => {
                let seg = ip.segments();
                return ip.is_loopback()
                    || (seg[0] & 0xffc0) == 0xfe80   // link-local fe80::/10
                    || (seg[0] & 0xfe00) == 0xfc00;  // ULA fc00::/7
            }
            _ => {}
        }
    }
    false
}

fn is_acceptable_ipv4(ip: &Ipv4Addr, allow_private: bool) -> bool {
    // Always reject these, regardless of allow_private
    if ip.is_unspecified()      { return false; } // 0.0.0.0
    if ip.is_broadcast()        { return false; } // 255.255.255.255
    if ip.is_multicast()        { return false; } // 224.0.0.0/4
    if ip.is_documentation()    { return false; } // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if ip.is_link_local()       { return false; } // 169.254.0.0/16

    // Reject private networks unless explicitly allowed (dev/test mode)
    if !allow_private {
        if ip.is_loopback()     { return false; } // 127.0.0.0/8
        if ip.is_private()      { return false; } // 10.x, 172.16-31.x, 192.168.x
        // 100.64.0.0/10 (CGNAT) — stdlib doesn't have this
        let o = ip.octets();
        if o[0] == 100 && (o[1] & 0xc0) == 0x40 { return false; }
    }
    true
}

fn is_acceptable_ipv6(ip: &Ipv6Addr, allow_private: bool) -> bool {
    if ip.is_unspecified()   { return false; } // ::
    if ip.is_multicast()     { return false; } // ff00::/8

    if !allow_private {
        if ip.is_loopback()  { return false; } // ::1
        // ULA (Unique Local Address) fc00::/7
        let seg = ip.segments();
        if (seg[0] & 0xfe00) == 0xfc00 { return false; }
        // Link-local fe80::/10
        if (seg[0] & 0xffc0) == 0xfe80 { return false; }
    }
    true
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

/// Sliding-window rate limiter keyed by peer_id.
///
/// Each peer is allowed PEX_MAX_PER_WINDOW address suggestions per
/// PEX_RATE_WINDOW seconds. When a window expires, it resets.
#[derive(Default)]
pub struct PexRateLimiter {
    state: HashMap<PeerId, WindowState>,
}

#[derive(Clone, Copy)]
struct WindowState {
    window_start: Instant,
    count: usize,
}

impl PexRateLimiter {
    pub fn new() -> Self {
        Self { state: HashMap::new() }
    }

    /// Try to admit `n_addresses` from `sender`. Returns the number actually
    /// accepted after rate and batch limits. Rejected = n_addresses - accepted.
    pub fn admit(&mut self, sender: PeerId, n_addresses: usize) -> usize {
        // Apply batch limit first (independent of rate window).
        let capped_batch = n_addresses.min(PEX_BATCH_LIMIT);

        let now = Instant::now();
        let state = self.state.entry(sender).or_insert(WindowState {
            window_start: now,
            count: 0,
        });

        // If current window expired, reset
        if now.duration_since(state.window_start) >= PEX_RATE_WINDOW {
            state.window_start = now;
            state.count = 0;
        }

        // How much room left in the window
        let room = PEX_MAX_PER_WINDOW.saturating_sub(state.count);
        let admitted = capped_batch.min(room);
        state.count += admitted;
        admitted
    }

    /// Remove entries whose window has long expired (housekeeping).
    /// Call periodically to prevent unbounded growth.
    pub fn gc(&mut self) {
        let now = Instant::now();
        self.state.retain(|_, st| {
            now.duration_since(st.window_start) < PEX_RATE_WINDOW.saturating_mul(2)
        });
    }

    pub fn tracked_peer_count(&self) -> usize {
        self.state.len()
    }
}

// ── Aggregated stats (for logging) ───────────────────────────────────────────

/// Accumulates rejection/accept counts between periodic log emissions.
pub struct PexStats {
    last_log: Instant,
    accepted: usize,
    rejected_invalid: usize,
    rejected_batch:   usize,
    rejected_rate:    usize,
    rejected_private: usize,
    distinct_peers:   usize,
}

impl PexStats {
    pub fn new() -> Self {
        Self {
            last_log: Instant::now(),
            accepted: 0,
            rejected_invalid: 0,
            rejected_batch:   0,
            rejected_rate:    0,
            rejected_private: 0,
            distinct_peers:   0,
        }
    }

    pub fn record_accept(&mut self, n: usize) { self.accepted += n; }
    pub fn record_invalid(&mut self, n: usize) { self.rejected_invalid += n; }
    pub fn record_batch(&mut self, n: usize) { self.rejected_batch += n; }
    pub fn record_rate(&mut self, n: usize) { self.rejected_rate += n; }
    pub fn record_private(&mut self, n: usize) { self.rejected_private += n; }

    pub fn set_distinct_peers(&mut self, n: usize) { self.distinct_peers = n; }

    /// Returns a summary line if enough time has passed since the last log,
    /// resetting counters. Otherwise returns None.
    pub fn tick(&mut self) -> Option<String> {
        let now = Instant::now();
        if now.duration_since(self.last_log) < PEX_STATS_LOG_INTERVAL {
            return None;
        }
        let total_rej = self.rejected_invalid + self.rejected_batch
                      + self.rejected_rate + self.rejected_private;
        if self.accepted == 0 && total_rej == 0 {
            self.last_log = now;
            return None; // nothing to report
        }
        let msg = format!(
            "PEX stats: accepted {} | rejected {} (invalid {}, batch-limit {}, rate-limit {}, private {}) | tracked peers {}",
            self.accepted, total_rej,
            self.rejected_invalid, self.rejected_batch,
            self.rejected_rate, self.rejected_private,
            self.distinct_peers
        );
        // Reset
        self.last_log = now;
        self.accepted = 0;
        self.rejected_invalid = 0;
        self.rejected_batch = 0;
        self.rejected_rate = 0;
        self.rejected_private = 0;
        Some(msg)
    }
}

impl Default for PexStats {
    fn default() -> Self { Self::new() }
}

// ── known_peers.json hygiene ─────────────────────────────────────────────────

/// Apply known_peers cap and optionally evict oldest entries.
/// The input is a HashSet (unordered); we materialize to Vec, sort by a key we
/// don't have (insertion order is lost in a HashSet), so FIFO is best-effort.
///
/// For strict FIFO we'd need a VecDeque. Keeping HashSet for compatibility with
/// existing load/save; cap enforcement is soft — if we exceed cap, random entries
/// are removed until within bounds.
pub fn enforce_cap(peers: &mut std::collections::HashSet<String>) -> usize {
    let initial = peers.len();
    if initial <= KNOWN_PEERS_CAP {
        return 0;
    }
    let to_remove = initial - KNOWN_PEERS_CAP;
    let victims: Vec<String> = peers.iter().take(to_remove).cloned().collect();
    for v in &victims {
        peers.remove(v);
    }
    to_remove
}

/// One-time cleanup at startup: drop entries that fail the new validator.
/// Returns number of entries removed.
pub fn prune_invalid(
    peers: &mut std::collections::HashSet<String>,
    allow_private: bool,
) -> usize {
    let before = peers.len();
    peers.retain(|addr| is_valid_public_multiaddr(addr, allow_private));
    before - peers.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_filter_accepts_lan_rejects_public() {
        let lan = |s: &str| is_lan_multiaddr(&s.parse::<Multiaddr>().unwrap());
        // LAN / loopback / link-local — mDNS may auto-dial these.
        assert!(lan("/ip4/192.168.1.10/tcp/16110"));
        assert!(lan("/ip4/10.0.0.5/tcp/16110"));
        assert!(lan("/ip4/172.16.3.4/tcp/16110"));
        assert!(lan("/ip4/127.0.0.1/tcp/16110"));
        assert!(lan("/ip4/169.254.1.1/tcp/16110"));
        assert!(lan("/ip6/::1/tcp/16110"));
        assert!(lan("/ip6/fe80::1/tcp/16110"));
        // Public IPs — an mDNS record naming these is a reflection/SSRF attempt.
        assert!(!lan("/ip4/8.8.8.8/tcp/16110"));
        assert!(!lan("/ip4/1.1.1.1/tcp/443"));
        assert!(!lan("/ip6/2606:4700:4700::1111/tcp/443"));
    }
}
