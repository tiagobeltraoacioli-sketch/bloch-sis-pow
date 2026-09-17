// Reproduction for NET-03 — devnet inbound cap is GLOBAL, not per-IP: one host
// holding MAX_INBOUND_CONNECTIONS idle/junk connections locks every other peer
// out of a bootnode's onboarding path.
//
// PLACEMENT. `bloch-pos-node` is a `[[bin]]`-only crate (no lib target — see
// crates/bloch-pos-node/tests/rpc_method_registry.rs), so `net::start`,
// `DevnetMesh` and `MAX_INBOUND_CONNECTIONS` are only reachable from an
// in-file `#[cfg(test)] mod tests`. Drop this test INTO the `mod tests` block
// at the bottom of crates/bloch-pos-node/src/net.rs, right next to the
// existing `inbound_connections_are_capped`, which it extends. It reuses that
// test's free-port-probe idiom verbatim. DO NOT run it here / DO NOT commit it.
//
// What it proves, beyond the existing cap test:
//   1. All 128 slots can be filled from ONE source address (loopback) — there
//      is no per-IP bound (net.rs:963 checks only the global `inbound_live`).
//   2. A 5-byte junk frame (`len=1 ‖ 0xFF`) keeps a slot and costs the holder
//      nothing: `decode_event` returns `None` for the unknown type (net.rs:812)
//      and the reader loop continues (net.rs:1013-1028) — no disconnect, no
//      penalty. So the connections are held indefinitely for ~5 bytes/120 s.
//   3. While the attacker holds all 128, a fresh (honest) inbound connection is
//      accepted at TCP level and then CLOSED immediately by the server
//      (net.rs:963 `continue` -> `sock` dropped) — the victim is locked out.

#[test]
fn audit_net03_one_source_junk_flood_locks_out_new_inbound() {
    // Free-port probe, identical idiom to `inbound_connections_are_capped`.
    let probe = TcpListener::bind(("127.0.0.1", 0)).expect("probe a free port");
    let port = probe.local_addr().expect("local_addr").port();
    drop(probe);

    let (events, _rx) = mpsc::channel::<EngineEvent>();
    let head_slot = Arc::new(AtomicU64::new(0));
    let inflight = QueueBudget::new();
    let mesh = start(
        "127.0.0.1",
        port,
        Vec::new(),
        events,
        std::env::temp_dir(),
        head_slot,
        inflight,
    )
    .expect("bind the devnet transport");

    // The attacker: MAX_INBOUND_CONNECTIONS sockets, ALL from this one host,
    // held open. On each, send a single 5-byte junk frame (len=1, type 0xFF).
    // The server decodes it to `None` and keeps the connection — proving junk
    // frames carry no penalty and hold the slot.
    let junk_frame: [u8; 5] = [1, 0, 0, 0, 0xFF]; // u32 LE len=1, then one 0xFF byte
    let mut attacker = Vec::with_capacity(MAX_INBOUND_CONNECTIONS);
    for _ in 0..MAX_INBOUND_CONNECTIONS {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("attacker connect");
        s.write_all(&junk_frame).expect("write junk frame");
        attacker.push(s);
    }

    // Wait for the accept thread to register all 128.
    let deadline = Instant::now() + Duration::from_secs(5);
    while mesh.peer_count() < MAX_INBOUND_CONNECTIONS && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(200)); // let the count settle
    assert_eq!(
        mesh.peer_count(),
        MAX_INBOUND_CONNECTIONS,
        "one source filled every inbound slot with junk-frame connections"
    );

    // The victim: an honest third party dials the bootnode while the attacker
    // holds all 128. Its TCP connect succeeds (kernel handshake), but the
    // accept loop hits `inbound_live >= MAX_INBOUND_CONNECTIONS` and drops the
    // socket, so the server closes it: a read returns EOF (Ok(0)).
    let mut victim = TcpStream::connect(("127.0.0.1", port)).expect("victim TCP connect");
    victim
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buf = [0u8; 1];
    match victim.read(&mut buf) {
        Ok(0) => {} // server closed it: the victim is locked out (expected)
        Ok(n) => panic!("victim unexpectedly received {n} bytes; it was not refused"),
        Err(e) => panic!("victim was neither served nor promptly closed: {e}"),
    }

    // The attacker's connections were NOT evicted by their junk frames: the
    // count is still pinned at the cap, so the lockout is durable.
    assert_eq!(
        mesh.peer_count(),
        MAX_INBOUND_CONNECTIONS,
        "junk frames did not cost the attacker any slot; the lockout persists"
    );

    drop(attacker); // client-side close; proves nothing about the server side
}
