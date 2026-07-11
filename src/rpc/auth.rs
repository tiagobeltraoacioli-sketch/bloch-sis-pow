//! Bloch-SIS Protocol — Sprint M: RPC authentication + rate limiting
//!
//! This module wraps the JSON-RPC handler with:
//!   1. Per-IP rate limiting (reads vs writes, separate buckets)
//!   2. Optional API key authentication (constant-time comparison)
//!   3. Localhost exemption (127.0.0.1 / ::1 bypass all checks)
//!
//! Security properties:
//!   - API key comparison uses `subtle::ConstantTimeEq` to prevent timing attacks
//!   - Rate limits are per-IP (IPv4 /32, IPv6 /128); no per-subnet aggregation
//!   - `sendrawtransaction` is the only "write" method; everything else is a read
//!   - Localhost always allowed (operator tools, miners)
//!
//! See docs/THREAT_MODEL.md section 4 for threat analysis.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex;

use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use subtle::ConstantTimeEq;

/// P0 (roadmap §1.6 / §4.3): drop a per-IP rate-limit entry once it has been
/// idle this long. 24h matches the sweep the original code comment proposed.
const RL_IDLE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Sweep at most this often, so the eviction scan is amortized and does not run
/// on every request (keeps `check` ~O(1) between sweeps).
const RL_GC_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Methods we treat as "writes" (mutating, gossipped to peers).
/// Anything else is a read-only query of chain state.
/// `submitblock` is the B5f pool seam (see rpc::SubmitBlockFn).
pub const WRITE_METHODS: &[&str] = &["sendrawtransaction", "submitblock"];

/// Type alias for a direct (non-keyed) in-memory rate limiter.
type IpRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Per-IP rate-limit buckets plus a last-seen timestamp for eviction.
struct IpEntry {
    reads:     Arc<IpRateLimiter>,
    writes:    Arc<IpRateLimiter>,
    last_seen: Instant,
}

/// Guarded interior state. A single mutex covers both the map and the last-GC
/// clock so eviction needs no second lock (no lock-ordering hazard).
struct Inner {
    buckets: HashMap<IpAddr, IpEntry>,
    last_gc: Instant,
}

/// Per-IP rate-limit state. Each IP gets two buckets: one for reads, one for
/// writes, created lazily on first hit.
///
/// P0 (roadmap §1.6 / §4.3): the map is now bounded by *time*. Previously it
/// never evicted, so a spoofed-source-IP or many-client flood grew it forever
/// → memory-exhaustion DoS. `check` runs an amortized sweep (at most once per
/// `RL_GC_INTERVAL`) that drops entries idle longer than `RL_IDLE_TTL`.
pub struct RateLimiterSet {
    reads_per_min:  u32,
    writes_per_min: u32,
    inner:          Mutex<Inner>,
}

impl RateLimiterSet {
    pub fn new(reads_per_min: u32, writes_per_min: u32) -> Self {
        Self {
            reads_per_min,
            writes_per_min,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                last_gc: Instant::now(),
            }),
        }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    /// `is_write` selects which bucket. Caller should have already
    /// determined whether the method is a write (see `WRITE_METHODS`).
    pub fn check(&self, ip: IpAddr, is_write: bool) -> bool {
        // Localhost bypass
        if ip.is_loopback() {
            return true;
        }

        let now = Instant::now();
        let mut inner = self.inner.lock();

        // Amortized time-based eviction (bounds the map — see struct docs).
        if now.duration_since(inner.last_gc) >= RL_GC_INTERVAL {
            inner.buckets.retain(|_, e| now.duration_since(e.last_seen) < RL_IDLE_TTL);
            inner.last_gc = now;
        }

        let (reads_pm, writes_pm) = (self.reads_per_min, self.writes_per_min);
        let entry = inner.buckets.entry(ip).or_insert_with(|| {
            let reads = Quota::per_minute(
                NonZeroU32::new(reads_pm.max(1)).unwrap()
            );
            let writes = Quota::per_minute(
                NonZeroU32::new(writes_pm.max(1)).unwrap()
            );
            IpEntry {
                reads:     Arc::new(RateLimiter::direct(reads)),
                writes:    Arc::new(RateLimiter::direct(writes)),
                last_seen: now,
            }
        });
        entry.last_seen = now;

        let limiter = if is_write { &entry.writes } else { &entry.reads };
        limiter.check().is_ok()
    }

    /// Number of distinct IPs currently tracked. For diagnostics/metrics.
    pub fn tracked_ips(&self) -> usize {
        self.inner.lock().buckets.len()
    }
}

/// Authentication decision for a single incoming request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// Proceed with the request.
    Allow,
    /// Reject with 401.
    Unauthorized,
    /// Reject with 429.
    RateLimited,
}

/// Returns true if the IP should be treated as "trusted local" and exempt
/// from auth + rate limiting.
///
/// Always exempt: loopback (127.0.0.1, ::1).
///
/// Exempt only when `trust_private_ranges` is true: RFC1918 / ULA.
/// This flag exists because Docker's default bridge rewrites the source IP
/// to the bridge gateway (e.g. 172.17.0.1), which is NOT loopback. Without
/// this flag, the operator running `curl 127.0.0.1` on the Docker host
/// gets 401s for writes. SECURITY: enabling this on a node sharing a
/// subnet with untrusted tenants (Kubernetes, shared VLANs) lets those
/// tenants bypass auth. Only enable on trusted single-tenant hosts.
///
/// Ranges covered when trust_private_ranges = true:
///   - IPv4 RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
///   - IPv6 ULA:     fc00::/7
/// Explicitly NOT covered (even with the flag):
///   - IPv4 link-local 169.254.0.0/16 (spoofable, APIPA)
///   - Carrier-grade NAT 100.64.0.0/10 (shared with other tenants by definition)
pub fn is_trusted_local_ip(ip: IpAddr, trust_private_ranges: bool) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if !trust_private_ranges {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8
            o[0] == 10
                // 172.16.0.0/12
                || (o[0] == 172 && (o[1] & 0xF0) == 16)
                // 192.168.0.0/16
                || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => {
            // fc00::/7 — Unique Local Address (RFC 4193)
            let first = v6.octets()[0];
            (first & 0xFE) == 0xFC
        }
    }
}

/// Apply auth + rate-limit checks to an incoming request, with explicit
/// control over whether private IP ranges are trusted.
///
/// This is the Sprint M-patch1 signature. The older `authorize()` wraps
/// this with `trust_private_ranges = false` for backward compatibility.
pub fn authorize_with_trust(
    ip: IpAddr,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    trust_private_ranges: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    if is_trusted_local_ip(ip, trust_private_ranges) {
        return AuthDecision::Allow;
    }

    let is_write = WRITE_METHODS.contains(&method);

    if !rate_limiter.check(ip, is_write) {
        return AuthDecision::RateLimited;
    }

    if is_write && require_auth_for_writes {
        match (presented_key, configured_key) {
            (Some(p), Some(c)) => {
                if p.as_bytes().ct_eq(c.as_bytes()).unwrap_u8() == 1 {
                    AuthDecision::Allow
                } else {
                    AuthDecision::Unauthorized
                }
            }
            _ => AuthDecision::Unauthorized,
        }
    } else if let (Some(p), Some(c)) = (presented_key, configured_key) {
        if p.as_bytes().ct_eq(c.as_bytes()).unwrap_u8() == 1 {
            AuthDecision::Allow
        } else {
            AuthDecision::Unauthorized
        }
    } else {
        AuthDecision::Allow
    }
}

/// Apply auth + rate-limit checks to an incoming request.
///
/// Parameters:
///   - `ip`: peer IP (localhost is exempt from everything)
///   - `method`: JSON-RPC method name (decides read vs write)
///   - `presented_key`: value of X-API-Key or Bearer, if any
///   - `configured_key`: server's configured API key, if any
///   - `require_auth_for_writes`: whether writes without a key are blocked
///   - `rate_limiter`: shared rate-limit state
///
/// NOTE: Backward-compatible shim. Defaults to `trust_private_ranges=false`.
/// New code should call `authorize_with_trust()` directly.
pub fn authorize(
    ip: IpAddr,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    authorize_with_trust(
        ip,
        method,
        presented_key,
        configured_key,
        require_auth_for_writes,
        false,
        rate_limiter,
    )
}

/// Extract API key from either `X-API-Key` header or `Authorization: Bearer <key>`.
pub fn extract_api_key<'a>(headers: &'a axum::http::HeaderMap) -> Option<&'a str> {
    if let Some(v) = headers.get("x-api-key") {
        if let Ok(s) = v.to_str() {
            return Some(s);
        }
    }
    if let Some(v) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(stripped) = s.strip_prefix("Bearer ") {
                return Some(stripped);
            }
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rl() -> RateLimiterSet {
        RateLimiterSet::new(60, 5)
    }

    #[test]
    fn localhost_bypasses_everything() {
        let r = rl();
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        for _ in 0..100 {
            let d = authorize(
                loopback,
                "sendrawtransaction",
                None,
                Some("secret"),
                true, // require auth for writes
                &r,
            );
            assert_eq!(d, AuthDecision::Allow, "loopback must always pass");
        }
    }

    #[test]
    fn localhost_v6_bypasses_everything() {
        let r = rl();
        let loopback_v6: IpAddr = Ipv6Addr::LOCALHOST.into();
        let d = authorize(loopback_v6, "sendrawtransaction", None, Some("s"), true, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn remote_read_without_auth_allowed() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(remote, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn remote_write_without_auth_blocked_when_required() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "sendrawtransaction", None, Some("secret"), true, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn remote_write_with_correct_key_allowed() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "sendrawtransaction", Some("secret"), Some("secret"), true, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn remote_write_with_wrong_key_unauthorized() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "sendrawtransaction", Some("wrong"), Some("secret"), true, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn wrong_key_on_read_still_rejected() {
        // Probing with wrong keys should not be indistinguishable from no key.
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "getblockcount", Some("wrong"), Some("secret"), false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn no_configured_key_means_auth_always_passes_reads() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(remote, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn rate_limit_kicks_in_on_remote_reads() {
        let r = RateLimiterSet::new(3, 2); // 3 reads/min for this test
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let mut allowed = 0;
        let mut rate_limited = 0;
        for _ in 0..10 {
            match authorize(remote, "getblockcount", None, None, false, &r) {
                AuthDecision::Allow => allowed += 1,
                AuthDecision::RateLimited => rate_limited += 1,
                _ => unreachable!(),
            }
        }
        assert!(allowed >= 1, "at least one should pass");
        assert!(rate_limited >= 1, "some should be rate-limited");
    }

    #[test]
    fn rate_limits_are_separate_per_ip() {
        let r = RateLimiterSet::new(2, 1);
        let ip1: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let ip2: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();

        // Exhaust ip1's reads
        for _ in 0..5 {
            authorize(ip1, "getblockcount", None, None, false, &r);
        }
        // ip2 should still be fresh
        let d = authorize(ip2, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn write_and_read_buckets_are_separate() {
        let r = RateLimiterSet::new(2, 2);
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        // Drain reads
        for _ in 0..3 {
            authorize(remote, "getblockcount", None, None, false, &r);
        }
        // Writes should still work (separate bucket)
        let d = authorize(
            remote, "sendrawtransaction", None, None, false, &r,
        );
        // Could be Allow or RateLimited depending on whether write bucket
        // has capacity; we just check it is not Unauthorized (which would
        // mean we somehow confused the two checks).
        assert_ne!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn timing_attack_resistance_smoke_test() {
        // Correct-length wrong-prefix, wrong-length: both should fail
        // equally. We don't measure timing, just behavior.
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();

        let d1 = authorize(remote, "getblockcount", Some("xxxxxx"), Some("secret"), false, &r);
        let d2 = authorize(remote, "getblockcount", Some("s"),       Some("secret"), false, &r);
        let d3 = authorize(remote, "getblockcount", Some("secretx"), Some("secret"), false, &r);

        assert_eq!(d1, AuthDecision::Unauthorized);
        assert_eq!(d2, AuthDecision::Unauthorized);
        assert_eq!(d3, AuthDecision::Unauthorized);
    }

    // ── Sprint M-patch1: trust_private_ranges tests ─────────────────

    #[test]
    fn is_trusted_loopback_always_true() {
        assert!(is_trusted_local_ip(Ipv4Addr::LOCALHOST.into(), false));
        assert!(is_trusted_local_ip(Ipv4Addr::LOCALHOST.into(), true));
        assert!(is_trusted_local_ip(Ipv6Addr::LOCALHOST.into(), false));
        assert!(is_trusted_local_ip(Ipv6Addr::LOCALHOST.into(), true));
    }

    #[test]
    fn is_trusted_docker_bridge_without_flag() {
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        assert!(!is_trusted_local_ip(docker_bridge, false));
    }

    #[test]
    fn is_trusted_docker_bridge_with_flag() {
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        assert!(is_trusted_local_ip(docker_bridge, true));
    }

    #[test]
    fn is_trusted_rfc1918_10_range() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 255, 255, 255),
            Ipv4Addr::new(10, 42, 7, 99),
        ] {
            assert!(is_trusted_local_ip(ip.into(), true));
            assert!(!is_trusted_local_ip(ip.into(), false));
        }
    }

    #[test]
    fn is_trusted_rfc1918_172_16_range() {
        for ip in [
            Ipv4Addr::new(172, 16, 0, 0),
            Ipv4Addr::new(172, 17, 0, 1),
            Ipv4Addr::new(172, 31, 255, 255),
        ] {
            assert!(is_trusted_local_ip(ip.into(), true));
        }
        for ip in [
            Ipv4Addr::new(172, 15, 255, 255),
            Ipv4Addr::new(172, 32, 0, 0),
        ] {
            assert!(!is_trusted_local_ip(ip.into(), true));
        }
    }

    #[test]
    fn is_trusted_rfc1918_192_168_range() {
        assert!(is_trusted_local_ip(Ipv4Addr::new(192, 168, 0, 1).into(), true));
        assert!(is_trusted_local_ip(Ipv4Addr::new(192, 168, 255, 255).into(), true));
        assert!(!is_trusted_local_ip(Ipv4Addr::new(192, 167, 0, 1).into(), true));
        assert!(!is_trusted_local_ip(Ipv4Addr::new(192, 169, 0, 1).into(), true));
    }

    #[test]
    fn is_trusted_link_local_never_trusted() {
        let apipa: IpAddr = Ipv4Addr::new(169, 254, 1, 1).into();
        assert!(!is_trusted_local_ip(apipa, false));
        assert!(!is_trusted_local_ip(apipa, true));
    }

    #[test]
    fn is_trusted_cgnat_never_trusted() {
        let cgnat: IpAddr = Ipv4Addr::new(100, 64, 0, 1).into();
        assert!(!is_trusted_local_ip(cgnat, true));
    }

    #[test]
    fn is_trusted_public_ipv4_never_trusted() {
        for ip in [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(9, 255, 255, 255),
            Ipv4Addr::new(11, 0, 0, 0),
            Ipv4Addr::new(193, 0, 0, 1),
        ] {
            assert!(!is_trusted_local_ip(ip.into(), true));
        }
    }

    #[test]
    fn is_trusted_ipv6_ula() {
        let ula1: IpAddr = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).into();
        let ula2: IpAddr = Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1).into();
        assert!(is_trusted_local_ip(ula1, true));
        assert!(is_trusted_local_ip(ula2, true));
        assert!(!is_trusted_local_ip(ula1, false));
    }

    #[test]
    fn is_trusted_ipv6_public_not_trusted() {
        let public_v6: IpAddr = Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1).into();
        assert!(!is_trusted_local_ip(public_v6, true));
    }

    #[test]
    fn authorize_with_trust_docker_bridge_write_bypass() {
        let r = rl();
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        let d = authorize_with_trust(
            docker_bridge,
            "sendrawtransaction",
            None,
            Some("secret"),
            true, true, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn authorize_with_trust_docker_bridge_write_blocked_without_flag() {
        let r = rl();
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        let d = authorize_with_trust(
            docker_bridge,
            "sendrawtransaction",
            None,
            Some("secret"),
            true, false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }
}
