// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn cfg_with_peers(peers: &[&str]) -> Config {
    Config { status: true, peers: peers.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

fn cmd(s: &Sentinel, line: &str) -> Json {
    admin::handle_line(s, line)
}

fn ok(j: &Json) -> bool {
    j.get("ok") == Some(&Json::Bool(true))
}

fn scratch(name: &str) -> PathBuf {
    // Short: macOS caps unix socket paths at 104 bytes.
    let dir = PathBuf::from(format!("/tmp/bs-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// A fake mesh: fixed inbound addresses, records disconnect requests.
struct FakeMesh {
    inbound: Vec<IpAddr>,
    configured: Vec<IpAddr>,
    closed: Arc<Mutex<Vec<IpAddr>>>,
}

impl MeshView for FakeMesh {
    fn inbound_addrs(&self) -> Vec<IpAddr> {
        self.inbound.clone()
    }
    fn configured_sources(&self) -> Vec<IpAddr> {
        self.configured.clone()
    }
    fn disconnect(&self, banned: &dyn Fn(IpAddr) -> bool) -> usize {
        let mut n = 0;
        for ip in &self.inbound {
            if banned(*ip) && !self.configured.contains(ip) {
                self.closed.lock().unwrap().push(*ip);
                n += 1;
            }
        }
        n
    }
}

#[test]
fn off_by_default() {
    assert!(!Config::default().enabled());
    assert!(start(Config::default()).is_ok(), "an empty config starts nothing");
    assert!(GLOBAL.get().is_none());
    assert!(current().is_none());
    assert!(status_rpc().is_none());
    // Hooks are no-ops.
    assert!(!refuse_inbound("192.0.2.1".parse().unwrap(), false));
    note_verdict(Some([1; 32]), crate::net::Verdict::Reject);
    note_kes_error("attest", 0, "x");
    for source in [None, Some("127.0.0.1".parse().unwrap()), Some("203.0.113.1".parse().unwrap())] {
        let err = crate::rpc::security_status_for(source).unwrap_err();
        assert_eq!(err, crate::rpc::RpcError::method_not_found("getsecuritystatus"));
    }
}

#[test]
fn admin_commands_respect_bounds_and_protected_peers() {
    let s = test_sentinel(cfg_with_peers(&["198.51.100.7:19100"]));
    let closed = Arc::new(Mutex::new(Vec::new()));
    s.register_mesh(Box::new(FakeMesh {
        inbound: vec!["203.0.113.9".parse().unwrap(), "203.0.113.10".parse().unwrap(), "198.51.100.7".parse().unwrap()],
        configured: vec!["198.51.100.7".parse().unwrap(), "2001:db8:9:9::".parse().unwrap()],
        closed: closed.clone(),
    }));

    let r = cmd(&s, r#"{"cmd":"peer.ban","cidr":"203.0.113.0/24","ttl_secs":600,"reason":"flood","id":7}"#);
    assert!(ok(&r), "{r:?}");
    assert_eq!(r.get("id").and_then(Json::as_u64), Some(7));
    assert_eq!(r.get("result").and_then(|x| x.get("disconnected")).and_then(Json::as_u64), Some(2));
    assert_eq!(closed.lock().unwrap().len(), 2);
    assert!(s.is_banned("203.0.113.200".parse().unwrap()));
    assert!(s.refuse_inbound("203.0.113.200".parse().unwrap(), false));
    assert!(!s.refuse_inbound("203.0.113.200".parse().unwrap(), true), "configured is never refused");

    for refused in [
        r#"{"cmd":"peer.ban","addr":"198.51.100.7","ttl_secs":60}"#,
        r#"{"cmd":"peer.ban","cidr":"198.51.0.0/16","ttl_secs":60}"#,
        r#"{"cmd":"peer.ban","addr":"127.0.0.1","ttl_secs":60}"#,
        r#"{"cmd":"peer.ban","addr":"::1","ttl_secs":60}"#,
        r#"{"cmd":"peer.ban","cidr":"2001:db8:9::/48","ttl_secs":60}"#,
        r#"{"cmd":"peer.ban","cidr":"10.0.0.0/8","ttl_secs":60}"#,
        r#"{"cmd":"peer.ban","cidr":"2001:db8::/32","ttl_secs":60}"#,
        r#"{"cmd":"peer.ban","addr":"192.0.2.1","ttl_secs":0}"#,
        r#"{"cmd":"peer.ban","addr":"192.0.2.1","ttl_secs":3601}"#,
        r#"{"cmd":"peer.ban","addr":"192.0.2.1"}"#,
        r#"{"cmd":"peer.ban","addr":"192.0.2.1","cidr":"192.0.2.0/24","ttl_secs":5}"#,
        r#"{"cmd":"peer.ban","addr":"192.0.2.0/24","ttl_secs":5}"#,
        r#"{"cmd":"node.restart"}"#,
        r#"{"cmd":"reject_root","root":"00"}"#,
        r#"{"cmd":"keys.export"}"#,
        r#"not json"#,
        r#"{}"#,
    ] {
        let r = cmd(&s, refused);
        assert!(!ok(&r), "must be refused: {refused} -> {r:?}");
        assert!(r.get("error").and_then(Json::as_str).is_some());
    }
    assert_eq!(s.bans_json(Instant::now()).get("active").and_then(Json::as_u64), Some(1));

    let r = cmd(&s, r#"{"cmd":"peer.bans"}"#);
    let entries = r.get("result").and_then(|x| x.get("entries")).unwrap();
    assert_eq!(entries.at(0).and_then(|e| e.get("range")).and_then(Json::as_str), Some("203.0.113.0/24"));

    let r = cmd(&s, r#"{"cmd":"peer.unban","cidr":"203.0.113.0/24"}"#);
    assert_eq!(r.get("result").and_then(|x| x.get("removed")), Some(&Json::Bool(true)));
    assert!(!s.is_banned("203.0.113.9".parse().unwrap()));

    // Every command was evented, refused ones included.
    let events = captured_events(&s);
    let admin = events.iter().filter(|e| e.contains("\"admin_command\"")).count();
    assert_eq!(admin, 20);
    assert!(events.iter().any(|e| e.contains("\"ban_applied\"")));
    assert!(events.iter().any(|e| e.contains("\"ban_removed\"")));
    // No unknown command name is echoed back into the event log verbatim.
    assert!(!events.iter().any(|e| e.contains("keys.export")));
}

#[test]
fn ban_ttl_expires_and_is_evented() {
    let s = test_sentinel(cfg_with_peers(&[]));
    assert!(ok(&cmd(&s, r#"{"cmd":"peer.ban","addr":"192.0.2.44","ttl_secs":1}"#)));
    assert!(s.is_banned("192.0.2.44".parse().unwrap()));
    s.sweep(Instant::now() + Duration::from_secs(2));
    assert!(!s.is_banned("192.0.2.44".parse().unwrap()));
    assert!(captured_events(&s).iter().any(|e| e.contains("\"ban_expired\"")));
}

#[test]
fn p2p_peer_multiaddrs_are_protected() {
    let s = test_sentinel(Config {
        status: true,
        p2p_peers: vec!["/ip4/198.51.100.20/tcp/19101/p2p/12D3KooWabc".into(), "/ip6/2001:db8::5/tcp/1".into()],
        ..Default::default()
    });
    assert!(!ok(&cmd(&s, r#"{"cmd":"peer.ban","addr":"198.51.100.20","ttl_secs":60}"#)));
    assert!(!ok(&cmd(&s, r#"{"cmd":"peer.ban","cidr":"2001:db8::/48","ttl_secs":60}"#)));
}

fn walk_keys(j: &Json, out: &mut Vec<String>, prefix: &str) {
    if let Json::Obj(fields) = j {
        for (k, v) in fields {
            let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
            out.push(path.clone());
            walk_keys(v, out, &path);
        }
    }
}

#[test]
fn status_has_the_documented_shape() {
    let s = test_sentinel(cfg_with_peers(&[]));
    s.publish_chain(ChainSnapshot { wall_slot: 64, wall_epoch: 2, live: true, transport: "devnet", ..Default::default() });
    let status = s.status_json();
    assert_eq!(status.get("schema").and_then(Json::as_str), Some(STATUS_SCHEMA));
    let mut keys = Vec::new();
    walk_keys(&status, &mut keys, "");
    for required in [
        "chain.head.root",
        "chain.head.epoch",
        "chain.justified.epoch",
        "chain.justified.root",
        "chain.finalized.epoch",
        "chain.finalized.root",
        "chain.finality_lag_epochs",
        "peer_finalized_ahead.count",
        "peer_finalized_ahead.strong_count",
        "peer_finalized_ahead.conflicting_strong_count",
        "peer_finalized_ahead.unverified_observations_total",
        "peer_finalized_ahead.entries",
        "gossip_verdicts.top",
        "gossip_verdicts.window_secs",
        "handshakes.top",
        "peers.mesh_inbound",
        "peers.inbound_by_v4_24",
        "peers.inbound_by_v6_64",
        "doppelganger.state",
        "kes.mode",
        "kes.bind_epoch",
        "bans.entries",
        "events.enabled",
    ] {
        assert!(keys.iter().any(|k| k == required), "missing {required} in {keys:?}");
    }
    // The schema in docs/SENTINEL-HOOKS.md names every top-level key.
    let doc = include_str!("../../../../docs/SENTINEL-HOOKS.md");
    if let Json::Obj(fields) = &status {
        for (k, _) in fields {
            assert!(doc.contains(&format!("`{k}`")), "docs/SENTINEL-HOOKS.md does not document `{k}`");
        }
    }
}

#[test]
fn status_stays_bounded_under_floods() {
    let s = test_sentinel(cfg_with_peers(&[]));
    let flood: Vec<IpAddr> = (0..2000u32).map(|i| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i))).collect();
    s.register_mesh(Box::new(FakeMesh { inbound: flood.clone(), configured: vec![], closed: Arc::default() }));
    for (i, ip) in flood.iter().enumerate() {
        s.note_handshake(*ip, 1, 1);
        let mut src = [0u8; 32];
        src[..4].copy_from_slice(&(i as u32).to_le_bytes());
        s.note_verdict(Some(src), crate::net::Verdict::Reject);
        s.observe_advert(Observation {
            source: src,
            kind: AdvertKind::UnknownRoot,
            advertised_finalized: [3; 32],
            advertised_justified: [0; 32],
            block_root: [4; 32],
            block_slot: 1,
            root_slot: None,
            epoch_hint: None,
            our_finalized_epoch: 0,
            our_finalized_root: [0; 32],
            verdict: "ignore",
            verified: false,
        });
    }
    let status = s.status_json();
    let len = |path: &[&str]| -> usize {
        let mut j = &status;
        for p in path {
            j = j.get(p).unwrap();
        }
        match j {
            Json::Arr(a) => a.len(),
            _ => panic!("not an array"),
        }
    };
    assert!(len(&["gossip_verdicts", "top"]) <= window::TOP_N);
    assert!(len(&["handshakes", "top"]) <= window::TOP_N);
    assert!(len(&["peer_finalized_ahead", "entries"]) <= adverts::MAX_ENTRIES);
    assert!(len(&["peers", "inbound_by_v4_24", "top"]) <= MAX_BUCKETS_REPORTED);
    assert_eq!(status.get("gossip_verdicts").and_then(|g| g.get("tracked_sources")).and_then(Json::as_u64), Some(window::MAX_SOURCES as u64));
    assert!(status.to_string().len() < 64 * 1024, "status answer must stay small");
}

#[test]
fn finality_lag_doppelganger_and_kes_transitions_are_evented() {
    let s = test_sentinel(cfg_with_peers(&[]));
    let mut c = ChainSnapshot { live: true, wall_epoch: 10, finalized_epoch: 8, transport: "devnet", ..Default::default() };
    c.kes.mode = "static";
    s.publish_chain(c.clone());
    c.wall_epoch = 13; // lag 5: crosses 4
    s.publish_chain(c.clone());
    c.wall_epoch = 14; // lag 6: same level, no event
    s.publish_chain(c.clone());
    c.finalized_epoch = 12; // lag 2: recovered
    s.publish_chain(c.clone());
    c.doppelganger.halted = true;
    c.kes.mode = "fail_closed";
    s.publish_chain(c.clone());
    let ev = captured_events(&s);
    assert_eq!(ev.iter().filter(|e| e.contains("\"finality_lag\"")).count(), 1, "{ev:?}");
    assert_eq!(ev.iter().filter(|e| e.contains("\"finality_recovered\"")).count(), 1);
    assert_eq!(ev.iter().filter(|e| e.contains("\"doppelganger_detected\"")).count(), 1);
    assert_eq!(ev.iter().filter(|e| e.contains("\"kes_mode_changed\"")).count(), 1);
    // Not live (replay/catch-up): no lag events.
    let quiet = test_sentinel(cfg_with_peers(&[]));
    quiet.publish_chain(ChainSnapshot { live: false, wall_epoch: 500, ..Default::default() });
    assert!(captured_events(&quiet).is_empty());
}

#[test]
fn kes_errors_are_classified_and_carry_no_raw_text() {
    let s = test_sentinel(cfg_with_peers(&[]));
    s.note_kes_error("attest", 4, "KES evolve to leaf 3 (period 9): permission denied: /secret/path/kes.key");
    s.note_kes_error("attest", 4, "KES enforcement state unknown");
    assert_eq!(classify_kes_error("no KES key is registered on chain for v4"), "not_registered");
    assert_eq!(classify_kes_error("KES is enforced from epoch 8620 and no kes.key is loaded"), "no_kes_key_loaded");
    let ev = captured_events(&s);
    assert_eq!(ev.len(), 2);
    assert!(ev[0].contains("\"evolution_failed\""));
    assert!(ev.iter().all(|e| !e.contains("/secret") && !e.contains("permission")));
    let status = s.status_json();
    assert_eq!(
        status.get("kes"),
        Some(&Json::Null),
        "no chain snapshot yet: the KES block is null, the error is kept for when it is published"
    );
}

#[test]
fn admin_socket_path_checks() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("perm");
    // World-writable directory: refused.
    let open = dir.join("ww");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let e = admin::check_path(&open.join("a.sock")).unwrap_err();
    assert!(e.contains("world-writable"), "{e}");
    // Existing non-socket: refused, and left alone.
    let file = dir.join("plain");
    std::fs::write(&file, b"keep me").unwrap();
    assert!(admin::check_path(&file).unwrap_err().contains("not a socket"));
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    // A directory at the path: refused.
    let sub = dir.join("sub");
    std::fs::create_dir(&sub).unwrap();
    assert!(admin::check_path(&sub).is_err());
    // A good path binds 0600.
    let sock = dir.join("a.sock");
    let listener = admin::bind(&sock).unwrap();
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
    // While someone listens, a second bind is refused.
    assert!(admin::bind(&sock).unwrap_err().contains("listening"));
    drop(listener);
    // A stale socket of ours is replaced.
    let again = admin::bind(&sock).unwrap();
    drop(again);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn admin_socket_end_to_end() {
    let dir = scratch("e2e");
    let sock = dir.join("a.sock");
    let listener = admin::bind(&sock).unwrap();
    let s = test_sentinel(cfg_with_peers(&[]));
    let server = s.clone();
    std::thread::spawn(move || admin::serve(listener, server));
    let mut stream = UnixStream::connect(&sock).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut ask = |line: &str| -> Json {
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut answer = String::new();
        reader.read_line(&mut answer).unwrap();
        crate::rpc::parse_json(answer.trim()).unwrap()
    };
    assert!(ok(&ask(r#"{"cmd":"peer.ban","addr":"192.0.2.77","ttl_secs":30,"reason":"test"}"#)));
    assert!(ok(&ask(r#"{"cmd":"peer.bans"}"#)));
    assert!(!ok(&ask(r#"{"cmd":"peer.ban","addr":"127.0.0.1","ttl_secs":30}"#)));
    assert!(s.is_banned("192.0.2.77".parse().unwrap()));
    // An oversized line is answered with an error and the connection closed.
    let big = format!("{{\"cmd\":\"peer.bans\",\"pad\":\"{}\"}}", "x".repeat(5000));
    let r = ask(&big);
    assert!(!ok(&r));
    let _ = std::fs::remove_dir_all(&dir);
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// R-02: only loopback (and in-process) callers read the status unless the
/// operator opted in, and a refused caller gets plain "method not found".
#[test]
fn status_is_served_to_loopback_callers_only() {
    let local = test_sentinel(cfg_with_peers(&[]));
    with_test_sentinel(local, || {
        assert!(crate::rpc::security_status_for(None).is_ok());
        assert!(crate::rpc::security_status_for(Some("127.0.0.1".parse().unwrap())).is_ok());
        assert!(crate::rpc::security_status_for(Some("::1".parse().unwrap())).is_ok());
        assert!(crate::rpc::security_status_for(Some("::ffff:127.0.0.1".parse().unwrap())).is_ok());
        for remote in ["203.0.113.9", "10.0.0.5", "2001:db8::1"] {
            let err = crate::rpc::security_status_for(Some(remote.parse().unwrap())).unwrap_err();
            assert_eq!(err, crate::rpc::RpcError::method_not_found("getsecuritystatus"), "{remote}");
        }
    });
    let remote = test_sentinel(Config { status: true, allow_remote_status: true, ..Default::default() });
    with_test_sentinel(remote, || {
        assert!(crate::rpc::security_status_for(Some("203.0.113.9".parse().unwrap())).is_ok());
    });
}

/// R-02 at the HTTP-facing backend: the request never reaches the engine
/// queue and the caller's address decides.
#[test]
fn the_rpc_backend_answers_status_before_the_queue_and_by_caller() {
    use crate::rpc::{RpcBackend, RpcRequest};
    let (tx, rx) = std::sync::mpsc::channel();
    let backend = crate::rpc::EngineBackend::new(tx);
    let s = test_sentinel(cfg_with_peers(&[]));
    with_test_sentinel(s, || {
        assert!(backend.call_from(RpcRequest::SecurityStatus, "127.0.0.1".parse().unwrap()).is_ok());
        let err = backend.call_from(RpcRequest::SecurityStatus, "198.51.100.3".parse().unwrap()).unwrap_err();
        assert_eq!(err, crate::rpc::RpcError::method_not_found("getsecuritystatus"));
    });
    assert!(rx.try_recv().is_err(), "nothing was queued for the consensus thread");
}

/// R-02 at boot, R-06 for the flag spellings.
#[test]
fn flags_are_parsed_strictly_and_a_routable_rpc_bind_is_refused() {
    let parse = |a: &[&str], bind: Option<&str>| Config::from_args(&argv(a), vec![], vec![], bind);
    assert_eq!(parse(&["run"], Some("0.0.0.0")).unwrap(), Config::default(), "off: any bind is fine");
    let c = parse(&["run", "--security-status"], Some("127.0.0.1")).unwrap();
    assert!(c.status && c.events.is_none() && c.admin_socket.is_none());
    // Both spellings of a path option.
    let c = parse(&["run", "--admin-socket", "/run/b/a.sock", "--security-events=/var/log/b/ev.jsonl"], Some("localhost")).unwrap();
    assert_eq!(c.admin_socket, Some(PathBuf::from("/run/b/a.sock")));
    assert_eq!(c.events, Some(PathBuf::from("/var/log/b/ev.jsonl")));
    let c = parse(&["run", "--admin-socket=/run/b/a.sock"], Some("::1")).unwrap();
    assert_eq!(c.admin_socket, Some(PathBuf::from("/run/b/a.sock")));
    // Malformed: an error, never a silent "off".
    for bad in [
        &["run", "--admin-socket"][..],
        &["run", "--admin-socket="][..],
        &["run", "--admin-socket", "--security-status"][..],
        &["run", "--security-events="][..],
        &["run", "--security-status=1"][..],
        &["run", "--admin-socket", "/a", "--admin-socket=/b"][..],
        &["run", "--security-status-remote"][..],
    ] {
        assert!(parse(bad, Some("127.0.0.1")).is_err(), "{bad:?}");
    }
    // A routable RPC bind with the Sentinel on needs the explicit flag.
    for bind in ["0.0.0.0", "10.1.2.3", "::", "node.example"] {
        let e = parse(&["run", "--security-status"], Some(bind)).unwrap_err();
        assert!(e.contains("not loopback"), "{e}");
        assert!(parse(&["run", "--security-events", "/x"], Some(bind)).is_err());
        assert!(parse(&["run", "--security-status", "--security-status-remote"], Some(bind)).unwrap().allow_remote_status);
    }
    // RPC off: nothing to expose.
    assert!(parse(&["run", "--security-status"], None).is_ok());
    // After `--`, tokens are not flags.
    assert_eq!(parse(&["run", "--", "--security-status"], Some("0.0.0.0")).unwrap(), Config::default());
}

/// R-04: handshake counters are keyed per IPv4 address / IPv6 /64.
#[test]
fn handshake_counters_are_keyed_by_the_mesh_source() {
    let s = test_sentinel(cfg_with_peers(&[]));
    for host in 0..3000u32 {
        let ip: IpAddr = format!("2001:db8:1:2::{host:x}").parse().unwrap();
        s.note_handshake(ip, 1, 1);
    }
    let status = s.status_json();
    let hs = status.get("handshakes").unwrap();
    assert_eq!(hs.get("tracked_sources").and_then(Json::as_u64), Some(1), "one /64 is one source");
    let top = hs.get("top").and_then(|t| t.at(0)).unwrap();
    assert_eq!(top.get("addr").and_then(Json::as_str), Some("2001:db8:1:2::"));
    assert_eq!(top.get("attempts").and_then(Json::as_u64), Some(3000));
    assert_eq!(hs.get("overflow").and_then(|o| o.get("attempts")).and_then(Json::as_u64), Some(0));
}

/// R-05: the connection lifetime is absolute; a client trickling bytes is
/// cut off at the deadline, not kept for as long as it keeps trickling.
#[test]
fn admin_connection_lifetime_is_absolute() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let s = test_sentinel(cfg_with_peers(&[]));
    let started = Instant::now();
    let handle = std::thread::spawn(move || admin::handle_connection_within(server, &s, Duration::from_millis(600)));
    // One byte every 100 ms, never a newline: each read succeeds.
    while started.elapsed() < Duration::from_secs(3) {
        if client.write_all(b"x").is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        if handle.is_finished() {
            break;
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    assert!(handle.is_finished(), "the handler outlived its lifetime");
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    handle.join().unwrap();
}

/// R-05: a group-writable directory is refused like a world-writable one.
#[test]
fn admin_socket_refuses_a_group_writable_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("grp");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let e = admin::check_path(&dir.join("a.sock")).unwrap_err();
    assert!(e.contains("group-writable"), "{e}");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(admin::check_path(&dir.join("a.sock")).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}
