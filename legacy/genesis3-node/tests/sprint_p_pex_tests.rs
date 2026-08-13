//! Sprint P — PEX Hardening Tests
//!
//! Unit tests for pex_validator module:
//!   - is_valid_public_multiaddr: address format + IP filtering
//!   - PexRateLimiter: batch + window limits
//!   - PexStats: aggregation + reset
//!   - enforce_cap: size bound
//!   - prune_invalid: legacy cleanup

#[cfg(test)]
mod sprint_p_tests {
    use bloch::network::pex_validator::*;
    use libp2p::PeerId;
    use std::collections::HashSet;

    fn sample_peer_id() -> String {
        PeerId::random().to_string()
    }

    fn addr_with_ip(ip: &str, port: u16) -> String {
        format!("/ip4/{}/tcp/{}/p2p/{}", ip, port, sample_peer_id())
    }

    // ─────────────────────────────────────────────────────────
    // is_valid_public_multiaddr — positive cases
    // ─────────────────────────────────────────────────────────

    #[test]
    fn accepts_valid_public_ipv4() {
        let addr = addr_with_ip("80.78.28.142", 16110);
        assert!(is_valid_public_multiaddr(&addr, false));
    }

    #[test]
    fn accepts_valid_public_ipv6() {
        let addr = format!("/ip6/2001:db8::1/tcp/16110/p2p/{}", sample_peer_id());
        // 2001:db8::/32 is actually documentation range in real RFC but stdlib
        // doesn't flag it — this test proves is_valid_public_multiaddr accepts it.
        assert!(is_valid_public_multiaddr(&addr, false));
    }

    #[test]
    fn accepts_dns_addresses() {
        let addr = format!("/dns4/seed.entanglementlayer.com/tcp/16110/p2p/{}", sample_peer_id());
        assert!(is_valid_public_multiaddr(&addr, false));
    }

    // ─────────────────────────────────────────────────────────
    // is_valid_public_multiaddr — format rejections
    // ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_garbage_string() {
        assert!(!is_valid_public_multiaddr("not a multiaddr", false));
        assert!(!is_valid_public_multiaddr("", false));
        assert!(!is_valid_public_multiaddr("/ip4/", false));
    }

    #[test]
    fn rejects_missing_tcp() {
        let addr = format!("/ip4/80.78.28.142/udp/16110/p2p/{}", sample_peer_id());
        assert!(!is_valid_public_multiaddr(&addr, false));
    }

    #[test]
    fn rejects_missing_p2p_peer_id() {
        let addr = "/ip4/80.78.28.142/tcp/16110";
        assert!(!is_valid_public_multiaddr(addr, false));
    }

    // ─────────────────────────────────────────────────────────
    // is_valid_public_multiaddr — IP filtering (allow_private=false)
    // ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_loopback_in_strict_mode() {
        assert!(!is_valid_public_multiaddr(&addr_with_ip("127.0.0.1", 16110), false));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("127.1.2.3", 16110), false));
    }

    #[test]
    fn rejects_rfc1918_in_strict_mode() {
        assert!(!is_valid_public_multiaddr(&addr_with_ip("10.0.0.1", 16110), false));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("172.16.0.1", 16110), false));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("172.31.255.254", 16110), false));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("192.168.1.1", 16110), false));
    }

    #[test]
    fn rejects_link_local_in_strict_mode() {
        assert!(!is_valid_public_multiaddr(&addr_with_ip("169.254.169.254", 16110), false));
    }

    #[test]
    fn rejects_cgnat_in_strict_mode() {
        // 100.64.0.0/10 — carrier-grade NAT
        assert!(!is_valid_public_multiaddr(&addr_with_ip("100.64.0.1", 16110), false));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("100.127.255.254", 16110), false));
    }

    #[test]
    fn rejects_reserved_ipv4() {
        assert!(!is_valid_public_multiaddr(&addr_with_ip("0.0.0.0", 16110), false));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("255.255.255.255", 16110), false));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("224.0.0.1", 16110), false)); // multicast
    }

    #[test]
    fn rejects_ipv6_loopback_and_link_local() {
        let lo = format!("/ip6/::1/tcp/16110/p2p/{}", sample_peer_id());
        let ll = format!("/ip6/fe80::1/tcp/16110/p2p/{}", sample_peer_id());
        let ula = format!("/ip6/fd00::1/tcp/16110/p2p/{}", sample_peer_id());
        assert!(!is_valid_public_multiaddr(&lo, false));
        assert!(!is_valid_public_multiaddr(&ll, false));
        assert!(!is_valid_public_multiaddr(&ula, false));
    }

    // ─────────────────────────────────────────────────────────
    // is_valid_public_multiaddr — allow_private mode (dev)
    // ─────────────────────────────────────────────────────────

    #[test]
    fn allow_private_lets_loopback_through() {
        assert!(is_valid_public_multiaddr(&addr_with_ip("127.0.0.1", 16110), true));
        assert!(is_valid_public_multiaddr(&addr_with_ip("10.0.0.1", 16110), true));
        assert!(is_valid_public_multiaddr(&addr_with_ip("192.168.1.1", 16110), true));
    }

    #[test]
    fn allow_private_still_rejects_reserved() {
        // Even in dev mode, 0.0.0.0 and multicast are rejected
        assert!(!is_valid_public_multiaddr(&addr_with_ip("0.0.0.0", 16110), true));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("224.0.0.1", 16110), true));
        assert!(!is_valid_public_multiaddr(&addr_with_ip("169.254.169.254", 16110), true));
    }

    // ─────────────────────────────────────────────────────────
    // PexRateLimiter
    // ─────────────────────────────────────────────────────────

    #[test]
    fn rate_limiter_admits_within_batch_limit() {
        let mut rl = PexRateLimiter::new();
        let peer = PeerId::random();
        // Ask for 10 (under both batch and window). Should admit all 10.
        let admitted = rl.admit(peer, 10);
        assert_eq!(admitted, 10);
    }

    #[test]
    fn rate_limiter_caps_at_batch_limit() {
        let mut rl = PexRateLimiter::new();
        let peer = PeerId::random();
        // Ask for 50. PEX_BATCH_LIMIT = 20.
        let admitted = rl.admit(peer, 50);
        assert_eq!(admitted, PEX_BATCH_LIMIT);
    }

    #[test]
    fn rate_limiter_accumulates_across_messages() {
        let mut rl = PexRateLimiter::new();
        let peer = PeerId::random();
        // Three messages of 20 each. Window allows 100 total.
        let a = rl.admit(peer, 20);
        let b = rl.admit(peer, 20);
        let c = rl.admit(peer, 20);
        let d = rl.admit(peer, 20);
        let e = rl.admit(peer, 20);
        // 100 total admitted.
        assert_eq!(a + b + c + d + e, 100);
        // 6th message should be rejected entirely (window full).
        let f = rl.admit(peer, 20);
        assert_eq!(f, 0);
    }

    #[test]
    fn rate_limiter_is_per_peer() {
        let mut rl = PexRateLimiter::new();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        // Peer A fills its window
        for _ in 0..5 { rl.admit(peer_a, 20); }
        assert_eq!(rl.admit(peer_a, 20), 0);
        // Peer B still has its full quota
        assert_eq!(rl.admit(peer_b, 20), 20);
    }

    // ─────────────────────────────────────────────────────────
    // PexStats
    // ─────────────────────────────────────────────────────────

    #[test]
    fn stats_records_without_crashing() {
        let mut s = PexStats::new();
        s.record_accept(10);
        s.record_invalid(5);
        s.record_batch(3);
        s.record_rate(2);
        s.record_private(1);
        s.set_distinct_peers(4);
        // tick() returns None because interval hasn't elapsed yet
        assert!(s.tick().is_none());
    }

    #[test]
    fn stats_tick_returns_none_when_nothing_recorded() {
        let mut s = PexStats::new();
        // Fresh stats, no activity — should return None even past interval
        // (hard to test real time elapsed without sleep, so just verify the
        //  zero-activity branch in current frame)
        assert!(s.tick().is_none());
    }

    // ─────────────────────────────────────────────────────────
    // enforce_cap
    // ─────────────────────────────────────────────────────────

    #[test]
    fn enforce_cap_noop_under_limit() {
        let mut set: HashSet<String> = (0..500).map(|i| format!("addr-{}", i)).collect();
        let removed = enforce_cap(&mut set);
        assert_eq!(removed, 0);
        assert_eq!(set.len(), 500);
    }

    #[test]
    fn enforce_cap_removes_excess() {
        let mut set: HashSet<String> = (0..KNOWN_PEERS_CAP + 100).map(|i| format!("addr-{}", i)).collect();
        let removed = enforce_cap(&mut set);
        assert_eq!(removed, 100);
        assert_eq!(set.len(), KNOWN_PEERS_CAP);
    }

    // ─────────────────────────────────────────────────────────
    // prune_invalid
    // ─────────────────────────────────────────────────────────

    #[test]
    fn prune_invalid_removes_polluted_entries() {
        let mut set: HashSet<String> = HashSet::new();
        set.insert(addr_with_ip("80.78.28.142", 16110));  // valid
        set.insert(addr_with_ip("10.0.0.1", 16110));       // private (invalid in strict)
        set.insert(addr_with_ip("127.0.0.1", 16110));      // loopback (invalid in strict)
        set.insert("garbage".into());                       // malformed
        set.insert("/ip4/80.78.28.143/tcp/16110".into());  // missing /p2p/

        let removed = prune_invalid(&mut set, false);
        assert_eq!(removed, 4);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn prune_invalid_with_allow_private_keeps_lan() {
        let mut set: HashSet<String> = HashSet::new();
        set.insert(addr_with_ip("80.78.28.142", 16110));
        set.insert(addr_with_ip("10.0.0.1", 16110));
        set.insert(addr_with_ip("127.0.0.1", 16110));
        set.insert("garbage".into());

        let removed = prune_invalid(&mut set, true);
        assert_eq!(removed, 1); // only "garbage"
        assert_eq!(set.len(), 3);
    }
}
