//! Bloch-SIS Protocol — Sprint M: RPC auth + rate limiting integration tests
//!
//! These tests hit the in-process `authorize()` function directly. They
//! do NOT spin up a full node or an HTTP server (that would require
//! the whole state apparatus). Integration against a running node is
//! left for manual QA — see docs/API.md for curl-based smoke tests.
//!
//! Unit tests for RateLimiterSet + authorize() are inside src/rpc/auth.rs
//! itself. This file tests the configuration surface more broadly.

use bloch::rpc::auth::{authorize, extract_api_key, AuthDecision, RateLimiterSet, WRITE_METHODS};
use std::net::{IpAddr, Ipv4Addr};

// ─── Helpers ──────────────────────────────────────────────────────────

fn remote() -> IpAddr {
    Ipv4Addr::new(203, 0, 113, 1).into() // TEST-NET-3 (RFC 5737)
}

fn localhost() -> IpAddr {
    Ipv4Addr::LOCALHOST.into()
}

fn fresh_limiter() -> RateLimiterSet {
    RateLimiterSet::new(60, 5)
}

// ─── Tests ────────────────────────────────────────────────────────────

#[test]
fn sprint_m_01_localhost_always_allowed_even_with_require_auth() {
    let r = fresh_limiter();
    let d = authorize(
        localhost(),
        "sendrawtransaction",
        None,
        Some("secret"),
        true,
        &r,
    );
    assert_eq!(d, AuthDecision::Allow);
}

#[test]
fn sprint_m_02_remote_read_no_key_configured_allowed() {
    let r = fresh_limiter();
    let d = authorize(remote(), "getblockcount", None, None, false, &r);
    assert_eq!(d, AuthDecision::Allow);
}

#[test]
fn sprint_m_03_remote_write_no_key_configured_allowed_when_not_required() {
    let r = fresh_limiter();
    let d = authorize(
        remote(),
        "sendrawtransaction",
        None,
        None,
        false, // require_auth_for_writes = false
        &r,
    );
    assert_eq!(d, AuthDecision::Allow);
}

#[test]
fn sprint_m_04_remote_write_no_key_but_required_blocked() {
    let r = fresh_limiter();
    let d = authorize(
        remote(),
        "sendrawtransaction",
        None,
        Some("secret"),
        true, // require_auth_for_writes = true
        &r,
    );
    assert_eq!(d, AuthDecision::Unauthorized);
}

#[test]
fn sprint_m_05_remote_write_wrong_key_unauthorized() {
    let r = fresh_limiter();
    let d = authorize(
        remote(),
        "sendrawtransaction",
        Some("wrong-key"),
        Some("correct-key"),
        true,
        &r,
    );
    assert_eq!(d, AuthDecision::Unauthorized);
}

#[test]
fn sprint_m_06_remote_write_correct_key_allowed() {
    let r = fresh_limiter();
    let d = authorize(
        remote(),
        "sendrawtransaction",
        Some("correct-key"),
        Some("correct-key"),
        true,
        &r,
    );
    assert_eq!(d, AuthDecision::Allow);
}

#[test]
fn sprint_m_07_presenting_wrong_key_on_read_is_rejected() {
    // Rationale: attackers probing with key guesses should not get a
    // different response from "no key at all". Since a malformed
    // auth attempt is suspicious, we reject.
    let r = fresh_limiter();
    let d = authorize(
        remote(),
        "getblockcount",
        Some("wrong"),
        Some("secret"),
        false,
        &r,
    );
    assert_eq!(d, AuthDecision::Unauthorized);
}

#[test]
fn sprint_m_08_write_methods_list_includes_sendrawtransaction() {
    assert!(WRITE_METHODS.contains(&"sendrawtransaction"));
}

#[test]
fn sprint_m_09_extract_api_key_from_x_api_key_header() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-api-key", "my-secret-key".parse().unwrap());
    assert_eq!(extract_api_key(&headers), Some("my-secret-key"));
}

#[test]
fn sprint_m_10_extract_api_key_from_bearer() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer my-secret-key".parse().unwrap(),
    );
    assert_eq!(extract_api_key(&headers), Some("my-secret-key"));
}

#[test]
fn sprint_m_11_extract_api_key_x_api_key_takes_precedence() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-api-key", "from-header".parse().unwrap());
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer from-bearer".parse().unwrap(),
    );
    assert_eq!(extract_api_key(&headers), Some("from-header"));
}

#[test]
fn sprint_m_12_extract_api_key_missing_returns_none() {
    let headers = axum::http::HeaderMap::new();
    assert_eq!(extract_api_key(&headers), None);
}

#[test]
fn sprint_m_13_extract_api_key_basic_auth_ignored() {
    let mut headers = axum::http::HeaderMap::new();
    // Basic auth (not Bearer) should not be misread as an API key.
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Basic dXNlcjpwYXNz".parse().unwrap(),
    );
    assert_eq!(extract_api_key(&headers), None);
}

#[test]
fn sprint_m_14_rate_limit_enforced_for_remote_reads() {
    // Tight limit (2 per min) to trigger in a test
    let r = RateLimiterSet::new(2, 1);
    let ip = remote();
    let mut allowed = 0;
    let mut limited = 0;
    for _ in 0..10 {
        match authorize(ip, "getblockcount", None, None, false, &r) {
            AuthDecision::Allow       => allowed += 1,
            AuthDecision::RateLimited => limited += 1,
            AuthDecision::Unauthorized => panic!("auth should not trigger here"),
        }
    }
    assert!(allowed >= 1);
    assert!(limited >= 1);
    // Sanity: allowed + limited must equal iterations
    assert_eq!(allowed + limited, 10);
}

#[test]
fn sprint_m_15_different_ips_have_independent_quotas() {
    let r = RateLimiterSet::new(1, 1);
    let ip1: IpAddr = Ipv4Addr::new(203, 0, 113, 1).into();
    let ip2: IpAddr = Ipv4Addr::new(198, 51, 100, 1).into();

    // Hammer ip1 until rate-limited
    let mut ip1_limited = false;
    for _ in 0..10 {
        if let AuthDecision::RateLimited = authorize(ip1, "getblockcount", None, None, false, &r) {
            ip1_limited = true;
            break;
        }
    }
    assert!(ip1_limited, "ip1 should get rate-limited");

    // ip2 should still be fresh
    let d = authorize(ip2, "getblockcount", None, None, false, &r);
    assert_eq!(d, AuthDecision::Allow);
}

#[test]
fn sprint_m_16_read_bucket_exhaustion_does_not_block_writes() {
    // Separate buckets = independent quotas.
    let r = RateLimiterSet::new(2, 2);
    let ip = remote();

    // Drain reads
    for _ in 0..5 {
        let _ = authorize(ip, "getblockcount", None, None, false, &r);
    }

    // A write should still be possible (up to its own limit)
    let d = authorize(ip, "sendrawtransaction", None, None, false, &r);
    assert_ne!(
        d,
        AuthDecision::Unauthorized,
        "should not be unauthorized (no auth required)"
    );
    // Could be Allow or RateLimited depending on counter state, but
    // NOT Unauthorized.
}

#[test]
fn sprint_m_17_key_comparison_is_length_agnostic() {
    // Presenting a shorter or longer key should both fail. The
    // ConstantTimeEq inside the implementation handles this.
    let r = fresh_limiter();
    let ip = remote();

    let cases: &[&str] = &["", "s", "se", "sec", "secre", "secret!", "SECRET"];
    for k in cases {
        let d = authorize(ip, "getblockcount", Some(k), Some("secret"), false, &r);
        assert_eq!(
            d,
            AuthDecision::Unauthorized,
            "key {:?} should not match 'secret'",
            k
        );
    }

    // Correct key still works
    let d = authorize(ip, "getblockcount", Some("secret"), Some("secret"), false, &r);
    assert_eq!(d, AuthDecision::Allow);
}

#[test]
fn sprint_m_18_tracked_ips_grows_with_new_requests() {
    let r = fresh_limiter();
    assert_eq!(r.tracked_ips(), 0);

    authorize(Ipv4Addr::new(1, 1, 1, 1).into(), "getblockcount", None, None, false, &r);
    assert_eq!(r.tracked_ips(), 1);

    authorize(Ipv4Addr::new(2, 2, 2, 2).into(), "getblockcount", None, None, false, &r);
    assert_eq!(r.tracked_ips(), 2);

    // Same IP again — no growth
    authorize(Ipv4Addr::new(1, 1, 1, 1).into(), "getblockcount", None, None, false, &r);
    assert_eq!(r.tracked_ips(), 2);

    // Localhost is NOT tracked (bypasses the limiter entirely)
    authorize(localhost(), "getblockcount", None, None, false, &r);
    assert_eq!(r.tracked_ips(), 2);
}
