//! End-to-end pump integration test (D5).
//!
//! Drives the REAL [`router::run_worker`] pump — with its Sprint-2 five-arg
//! signature `(DownstreamConn, cfg, metrics, Arc<ExtranonceRegistry>,
//! Arc<PplnsLedger>)` — against a mock Stratum node, exercising:
//!
//!   * a full `subscribe` → `authorize` → `submit` handshake, asserting the
//!     accepted share lands in the POOL-WIDE [`PplnsLedger`] (G1) and bumps the
//!     shares-accepted metric;
//!   * hostile downstream input (a partial line, an oversize line, malformed
//!     JSON) fed through the real pump, asserting the worker terminates
//!     WITHOUT panicking (a protocol error is a clean exit, not a crash);
//!   * a FORCED extranonce1 collision across two workers (a mock node that
//!     hands every connection the SAME extranonce1), asserting the G2
//!     re-dial-until-unique guard records activity via
//!     `bloch_pool_extranonce1_redials_total` /
//!     `bloch_pool_extranonce1_unresolved_total`.
//!
//! The node side is a hand-rolled mock (no consensus code): it answers
//! `mining.subscribe` with a subscribe-result carrying a chosen extranonce1
//! plus a `set_difficulty` and a `notify`, and answers `mining.authorize` /
//! `mining.submit` with a matching `{id, result:true}`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use bloch_pool_proxy::downstream::DownstreamConn;
use bloch_pool_proxy::extranonce::ExtranonceRegistry;
use bloch_pool_proxy::pplns::PplnsLedger;
use bloch_pool_proxy::router::run_worker;
use bloch_pool_proxy::types::{Metrics, ProxyConfig, WorkerId};

// A `mining.notify` the mock node emits so the proxy has an active job to
// forward downstream. The proxy is a TRANSPARENT forwarder now (the NODE
// validates every submit), so the notify need not be a specific difficulty —
// the mock accepts whatever the proxy relays up. The job_id follows the node's
// real `"{sid:x}-{height}-{ctr:x}"` convention.
const NOTIFY_JOB_ID: &str = "1a-531000-8e";
const NOTIFY_NTIME: &str = "5f5e1000";
const NOTIFY_LINE: &str = "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"1a-531000-8e\",\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\",\"aabbccdd\",\"eeff\",[],\"20000000\",\"1d00ffff\",\"5f5e1000\",true]}";

/// Shared sink into which the mock node records every raw `mining.submit` line
/// it receives FROM the proxy — so a test can prove the proxy forwarded the
/// submit upstream verbatim (including any 6th version-rolling param).
type SubmitLog = Arc<Mutex<Vec<String>>>;

// ─────────────────────────────────────────────────────────────────────────
// Mock node
// ─────────────────────────────────────────────────────────────────────────

/// Spawn a mock Stratum node that hands EVERY accepted connection the same
/// fixed `extranonce1`. Accepts connections indefinitely (so the re-dial loop
/// has something to talk to), each handled on its own task. Returns a shared
/// [`SubmitLog`] capturing the raw `mining.submit` lines the proxy forwards up.
async fn spawn_mock_node(en1: &'static str) -> (String, tokio::task::JoinHandle<()>, SubmitLog) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let submits: SubmitLog = Arc::new(Mutex::new(Vec::new()));
    let submits_for_task = submits.clone();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    tokio::spawn(handle_node_conn(sock, en1.to_string(), submits_for_task.clone()));
                }
                Err(_) => break,
            }
        }
    });
    (addr, handle, submits)
}

/// One upstream connection from the proxy's point of view: reply to subscribe
/// with the fixed extranonce1 + a set_difficulty + a notify, and ack any
/// authorize/submit with a matching `{id, result:true}`.
async fn handle_node_conn(sock: TcpStream, en1: String, submits: SubmitLog) {
    let (rd, mut wr) = sock.into_split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        let n = match reader.read_line(&mut line).await {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        let v: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = v.get("id").cloned().unwrap_or(serde_json::Value::Null);
        if method == "mining.submit" {
            // Record the RAW forwarded submit line so the test can assert the
            // proxy relayed every param upstream (incl. the 6th version param).
            submits.lock().unwrap().push(line.trim().to_string());
        }
        match method {
            "mining.subscribe" => {
                let sub = format!(
                    "{{\"id\":{id},\"result\":[[[\"mining.set_difficulty\",\"{en1}\"],[\"mining.notify\",\"{en1}\"]],\"{en1}\",4],\"error\":null}}\n"
                );
                if wr.write_all(sub.as_bytes()).await.is_err() {
                    break;
                }
                let _ = wr
                    .write_all(b"{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[1024.0]}\n")
                    .await;
                let notify = format!("{NOTIFY_LINE}\n");
                let _ = wr.write_all(notify.as_bytes()).await;
                let _ = wr.flush().await;
            }
            "mining.authorize" | "mining.submit" => {
                let resp = format!("{{\"id\":{id},\"result\":true,\"error\":null}}\n");
                if wr.write_all(resp.as_bytes()).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Harness helpers
// ─────────────────────────────────────────────────────────────────────────

fn test_cfg(upstream_addr: String) -> Arc<ProxyConfig> {
    Arc::new(ProxyConfig {
        upstream_addr,
        connect_timeout: Duration::from_secs(2),
        handshake_timeout: Duration::from_secs(5),
        reconnect_backoff_min: Duration::from_millis(1),
        reconnect_backoff_max: Duration::from_millis(10),
        extranonce_redial_max: 3,
        pplns_window_shares: 1000,
        pplns_window_secs: 0,
        keepalive_idle: Duration::from_secs(30),
        // A tiny fixed vardiff share-target the proxy announces downstream.
        // Retarget window huge so vardiff never moves mid-test. The proxy no
        // longer validates submits locally — the NODE decides accept/reject —
        // so this value only shapes the announced `set_difficulty` and the
        // PPLNS credit weight, not whether a share is accepted.
        vardiff_initial: 1e-9,
        vardiff_min: 1e-9,
        vardiff_max: 1e-9,
        vardiff_retarget_shares: 1_000_000,
        ..ProxyConfig::default()
    })
}

/// A connected TCP pair wrapped as (miner-side stream, proxy-side
/// DownstreamConn). Writing to the returned stream drives the pump as if a
/// real miner were connected.
async fn connected_downstream(
    cfg: Arc<ProxyConfig>,
    metrics: Arc<Metrics>,
    id: WorkerId,
) -> (TcpStream, DownstreamConn) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let miner = TcpStream::connect(addr).await.unwrap();
    let (server_side, _) = listener.accept().await.unwrap();
    let down = DownstreamConn::new(server_side, id, cfg, metrics);
    (miner, down)
}

/// Continuously read and discard downstream bytes so the proxy's writes never
/// block on a full socket buffer.
fn spawn_drain(rd: tokio::net::tcp::OwnedReadHalf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(rd);
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn end_to_end_forwards_versionrolled_submit_and_relays_node_accept() {
    let (node_addr, _node, node_submits) = spawn_mock_node("aaaaaaaa").await;
    let cfg = test_cfg(node_addr);
    let metrics = Arc::new(Metrics::new());
    let registry = Arc::new(ExtranonceRegistry::new());
    let ledger = Arc::new(PplnsLedger::new(&cfg));

    let (miner, down) = connected_downstream(cfg.clone(), metrics.clone(), WorkerId(1)).await;
    let worker = tokio::spawn(run_worker(
        down,
        cfg.clone(),
        metrics.clone(),
        registry.clone(),
        ledger.clone(),
    ));

    let (rd, mut wr) = miner.into_split();
    let drain = spawn_drain(rd);

    // The proxy no longer validates locally: it forwards the submit to the NODE
    // and relays the node's verdict. So the submit need not clear any local
    // target — the mock node accepts whatever the proxy relays up. The submit
    // carries a 6th VERSION-ROLLING param ("1fffe000"); the proxy MUST forward
    // it upstream verbatim so the node reconstructs the header the ASIC hashed.
    let en2 = "00000000";
    let nonce_hex = "deadbeef";
    let rolled_version = "1fffe000";

    // Real subscribe → authorize sequence through the live pump.
    wr.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"itest/1.0\"]}\n")
        .await
        .unwrap();
    wr.write_all(b"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"bloch1qtest\",\"x\"]}\n")
        .await
        .unwrap();
    wr.flush().await.unwrap();

    // Let the buffered upstream prelude (subscribe-result → set_difficulty →
    // notify) drain so the pump is fully established before the submit.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let submit = format!(
        "{{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"w\",\"{NOTIFY_JOB_ID}\",\"{en2}\",\"{NOTIFY_NTIME}\",\"{nonce_hex}\",\"{rolled_version}\"]}}\n"
    );
    wr.write_all(submit.as_bytes()).await.unwrap();
    wr.flush().await.unwrap();

    // Wait until the pool-wide ledger reflects the accepted share (proves the
    // node's submit-result was correlated and folded into PPLNS accounting).
    let mut recorded = false;
    for _ in 0..250 {
        if !ledger.credit().is_empty() {
            recorded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(recorded, "node-accepted share should land in the pool-wide PPLNS ledger");
    assert!(
        metrics.snapshot().shares_accepted >= 1,
        "the submit should count once toward shares_accepted (authorize ack must NOT)"
    );
    // The authorize `true` ack must not have inflated the counter.
    assert_eq!(
        metrics.snapshot().shares_accepted,
        1,
        "only the real submit (node-accepted) should be counted"
    );

    // PROOF the submit reached the NODE with ALL params intact — crucially the
    // 6th version-rolling param the local-validator sprint would have dropped.
    let forwarded = node_submits.lock().unwrap().clone();
    assert_eq!(forwarded.len(), 1, "exactly one submit should reach the node");
    let up = &forwarded[0];
    assert!(up.contains("mining.submit"), "forwarded line is a submit: {up}");
    assert!(up.contains(NOTIFY_JOB_ID), "job_id preserved: {up}");
    assert!(up.contains(en2), "extranonce2 preserved: {up}");
    assert!(up.contains(NOTIFY_NTIME), "ntime preserved: {up}");
    assert!(up.contains(nonce_hex), "nonce preserved: {up}");
    assert!(
        up.contains(rolled_version),
        "6th version-rolling param MUST reach the node verbatim: {up}"
    );

    // Now push malformed / oversize / partial lines through the REAL pump. The
    // worker must terminate cleanly (a protocol error) — never panic.
    let _ = wr.write_all(b"partial-without-newline").await; // partial fragment...
    let _ = wr.write_all(b" then-more\n").await; // ...completes into malformed JSON
    let giant = vec![b'x'; 9000]; // > MAX_LINE_BYTES (8 KiB)
    let _ = wr.write_all(&giant).await;
    let _ = wr.write_all(b"\n").await;
    let _ = wr.write_all(b"{not valid json at all\n").await;
    let _ = wr.flush().await;
    drop(wr);

    let joined = tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("worker did not finish in time");
    assert!(joined.is_ok(), "worker task panicked on hostile input");

    drain.abort();
}

#[tokio::test]
async fn forced_extranonce_collision_triggers_redial_or_unresolved() {
    // Every upstream connection is handed the SAME extranonce1, so the second
    // worker cannot avoid the collision no matter how many times it re-dials.
    let (node_addr, _node, _submits) = spawn_mock_node("c0111de0").await;
    let cfg = test_cfg(node_addr);
    let metrics = Arc::new(Metrics::new());
    let registry = Arc::new(ExtranonceRegistry::new());
    let ledger = Arc::new(PplnsLedger::new(&cfg));

    // Worker A claims the fixed extranonce1 and stays connected (its RAII claim
    // must remain live while B tries to claim the same value).
    let (miner_a, down_a) = connected_downstream(cfg.clone(), metrics.clone(), WorkerId(1)).await;
    let worker_a = tokio::spawn(run_worker(
        down_a,
        cfg.clone(),
        metrics.clone(),
        registry.clone(),
        ledger.clone(),
    ));
    let (rd_a, mut wr_a) = miner_a.into_split();
    let drain_a = spawn_drain(rd_a);
    wr_a.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"A/1.0\"]}\n")
        .await
        .unwrap();
    wr_a.flush().await.unwrap();

    // Let A establish and register its extranonce1 before B collides.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Worker B is handed the SAME extranonce1 → collision → bounded re-dials →
    // unresolved (since the node keeps re-handing the in-use value).
    let (miner_b, down_b) = connected_downstream(cfg.clone(), metrics.clone(), WorkerId(2)).await;
    let worker_b = tokio::spawn(run_worker(
        down_b,
        cfg.clone(),
        metrics.clone(),
        registry.clone(),
        ledger.clone(),
    ));
    let (rd_b, mut wr_b) = miner_b.into_split();
    let drain_b = spawn_drain(rd_b);
    wr_b.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"B/1.0\"]}\n")
        .await
        .unwrap();
    wr_b.flush().await.unwrap();

    // The G2 guard must record activity: it re-dialed (redials_total) and/or
    // gave up after the budget (unresolved_total). Collisions are counted too.
    let mut moved = false;
    for _ in 0..200 {
        let s = metrics.snapshot();
        if s.extranonce1_redials > 0 || s.extranonce1_unresolved > 0 {
            moved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let snap = metrics.snapshot();
    assert!(
        moved,
        "a forced extranonce1 collision must trigger redial/unresolved metrics (redials={}, unresolved={}, collisions={})",
        snap.extranonce1_redials, snap.extranonce1_unresolved, snap.extranonce1_collisions
    );
    assert!(
        snap.extranonce1_collisions >= 1,
        "the collision itself must be counted"
    );

    worker_a.abort();
    worker_b.abort();
    drain_a.abort();
    drain_b.abort();
}
