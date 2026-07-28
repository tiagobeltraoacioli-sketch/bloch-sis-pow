//! extranonce — the process-wide extranonce1 collision guard and the
//! re-dial-until-unique loop that upgrades it from "observe" to "resolve".
//!
//! The node assigns an `extranonce1` to every upstream TCP session at
//! `mining.subscribe` time (see the node's
//! `src/stratum/session.rs::handle_subscribe`). That value is only 32 bits
//! and the node keeps NO uniqueness registry, so two upstreams can be handed
//! the SAME extranonce1 and then iterate the identical extranonce2/nonce
//! space — silently duplicating every scrap of work the pool exists to keep
//! disjoint. This module makes that observable AND, where the node can be
//! coaxed into it, fixable:
//!
//!   * [`ExtranonceRegistry`] — a process-wide set of the extranonce1 values
//!     currently held by live workers.
//!   * [`WorkerExtranonce`] — one worker's RAII claim on its current
//!     extranonce1. [`assign`](WorkerExtranonce::assign) reports whether the
//!     value was unique (claimed) or collided (already held by another live
//!     worker), counting a metric + WARN on the collision.
//!   * [`claim_unique`] — the bounded re-dial loop: on a colliding
//!     node-assigned extranonce1 it re-dials the upstream up to
//!     `cfg.extranonce_redial_max` times, hoping the node hands out a
//!     not-in-use value. If it never does, the proxy counts an
//!     `unresolved` metric, WARNs, and serves the overlapping space anyway —
//!     it NEVER spins forever.
//!
//! This module owns no wire framing and no consensus code; it only reads the
//! extranonce1 the node already assigned (`UpstreamConn::extranonce1`) and,
//! on collision, asks `upstream` to re-dial.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::types::{HandshakeReplay, Metrics, PoolError, ProxyConfig, WorkerId};
use crate::upstream::UpstreamConn;

// ─────────────────────────────────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────────────────────────────────

/// Process-wide registry of the `extranonce1` values currently assigned to
/// live workers.
///
/// The node's extranonce1 is a 32-bit value with NO uniqueness registry
/// (see the node's `session.rs::handle_subscribe`), so two upstreams can be
/// handed the same value and then duplicate ALL work silently. This registry
/// makes that observable: when a worker is assigned an extranonce1 already
/// held by another live worker, the proxy logs a WARN and bumps
/// `bloch_pool_extranonce1_collisions_total` — and the [`claim_unique`] loop
/// re-dials to try to escape the overlap.
#[derive(Debug, Default)]
pub struct ExtranonceRegistry {
    live: Mutex<HashSet<String>>,
}

impl ExtranonceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to claim `en1`. Returns `true` if it was unique (now registered),
    /// `false` if another live worker already holds it (a collision — the
    /// caller must NOT treat the search space as disjoint).
    fn try_claim(&self, en1: &str) -> bool {
        // A poisoned lock only means a previous holder panicked; the set is
        // still usable, so recover rather than propagate.
        let mut g = self.live.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(en1.to_string())
    }

    /// Release `en1` (called when the claiming worker drops it or exits).
    fn release(&self, en1: &str) {
        let mut g = self.live.lock().unwrap_or_else(|e| e.into_inner());
        g.remove(en1);
    }

    #[cfg(test)]
    fn contains(&self, en1: &str) -> bool {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(en1)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Per-worker RAII claim
// ─────────────────────────────────────────────────────────────────────────

/// RAII holder of ONE worker's current extranonce1 claim. Registers the
/// claim on [`assign`](WorkerExtranonce::assign) (logging + counting a
/// collision if the value is already live), moves the claim on reassignment
/// (reconnect / re-dial), and releases it on drop so a worker that exits —
/// normally, by error, or by panic — never leaks its extranonce1.
pub struct WorkerExtranonce {
    registry: Arc<ExtranonceRegistry>,
    /// The extranonce1 THIS worker currently owns a registry slot for, if
    /// any. `None` when the current value collided with another worker (we
    /// leave that other worker as the owner) or before the first assign.
    held: Option<String>,
}

impl WorkerExtranonce {
    pub fn new(registry: Arc<ExtranonceRegistry>) -> Self {
        Self {
            registry,
            held: None,
        }
    }

    /// Adopt `en1` as this worker's extranonce1. Releases any previously
    /// held value first.
    ///
    /// Returns `true` if the value was UNIQUE and is now claimed by this
    /// worker, `false` if it COLLIDED with another live worker (in which
    /// case the collision metric is bumped and a WARN logged, the other
    /// worker keeps ownership of the slot, and this worker holds nothing).
    /// The proxy stays transparent either way — it never drops the worker on
    /// a collision; the caller (see [`claim_unique`]) decides whether to
    /// re-dial for a fresh value.
    pub fn assign(&mut self, en1: &str, metrics: &Metrics, worker: WorkerId) -> bool {
        if self.held.as_deref() == Some(en1) {
            return true; // unchanged — already uniquely held by us
        }
        if let Some(prev) = self.held.take() {
            self.registry.release(&prev);
        }
        if self.registry.try_claim(en1) {
            self.held = Some(en1.to_string());
            true
        } else {
            metrics.extranonce1_collision();
            log::warn!(
                "{worker}: node assigned extranonce1 {en1} already in use by another live \
                 worker — search spaces OVERLAP; work will be duplicated"
            );
            // Leave `held` = None: the other worker owns the slot, so we must
            // not remove it on our drop.
            false
        }
    }
}

impl Drop for WorkerExtranonce {
    fn drop(&mut self) {
        if let Some(en1) = self.held.take() {
            self.registry.release(&en1);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Re-dial-until-unique
// ─────────────────────────────────────────────────────────────────────────

/// Claim a NOT-in-use extranonce1 for `worker`, re-dialing the upstream up
/// to `cfg.extranonce_redial_max` times if the node keeps handing out a
/// value another live worker already holds.
///
/// Flow:
///   1. [`assign`](WorkerExtranonce::assign) the upstream's current
///      `extranonce1`. If it was unique, return immediately (zero re-dials).
///   2. On a collision, loop up to `cfg.extranonce_redial_max` times:
///      re-dial the upstream (a fresh node session → a freshly-assigned
///      extranonce1), bump `extranonce1_redial`, and re-assign. As soon as a
///      unique value is claimed, return `Ok`.
///   3. If every attempt still collided, bump `extranonce1_unresolved`,
///      WARN, and return `Ok` ANYWAY — the proxy serves the overlapping
///      space rather than dropping the worker. It NEVER spins forever.
///
/// `preserve_prelude` is forwarded to [`UpstreamConn::redial`]: pass `true`
/// on the very first claim (the miner still expects to see its
/// subscribe-result buffered on the stream), `false` when the miner has
/// already subscribed and a changed extranonce1 is surfaced via
/// `mining.set_extranonce`.
///
/// Only a transport/handshake failure from the re-dial itself propagates as
/// `Err`; a mere inability to find a unique value is a resolved-to-overlap
/// success (`Ok`).
pub async fn claim_unique(
    upstream: &mut UpstreamConn,
    replay: &HandshakeReplay,
    wx: &mut WorkerExtranonce,
    cfg: &ProxyConfig,
    metrics: &Metrics,
    worker: WorkerId,
    preserve_prelude: bool,
) -> Result<(), PoolError> {
    // First try the value the node already handed this upstream.
    if wx.assign(&upstream.extranonce1, metrics, worker) {
        return Ok(());
    }

    // Collided: re-dial for a fresh node-assigned extranonce1, bounded.
    for attempt in 1..=cfg.extranonce_redial_max {
        upstream.redial(replay, preserve_prelude).await?;
        metrics.extranonce1_redial();
        if wx.assign(&upstream.extranonce1, metrics, worker) {
            log::info!(
                "{worker}: obtained unique extranonce1 {} after {attempt} re-dial(s)",
                upstream.extranonce1
            );
            return Ok(());
        }
    }

    // Exhausted the re-dial budget and every value still collided. Serve the
    // overlapping space rather than spin or drop the worker.
    metrics.extranonce1_unresolved();
    log::warn!(
        "{worker}: could not obtain a unique extranonce1 after {} re-dial(s) \
         (node kept assigning in-use values) — serving with OVERLAPPING search \
         space; some work will be duplicated",
        cfg.extranonce_redial_max
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Metrics, ProxyConfig, ServerMsg, WorkerId};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // ── registry / RAII claim ─────────────────────────────────────────────

    #[test]
    fn extranonce_registry_flags_collisions_and_counts_metric() {
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Metrics::new();

        // Worker A claims "aaaa" — unique.
        let mut a = WorkerExtranonce::new(reg.clone());
        assert!(a.assign("aaaa", &metrics, WorkerId(1)));
        assert!(reg.contains("aaaa"));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 0);

        // Worker B is handed the SAME "aaaa" — collision counted, A keeps slot.
        let mut b = WorkerExtranonce::new(reg.clone());
        assert!(!b.assign("aaaa", &metrics, WorkerId(2)));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 1);
        assert!(reg.contains("aaaa"));

        // B dropping must NOT evict A's still-live claim.
        drop(b);
        assert!(reg.contains("aaaa"), "B's drop wrongly released A's extranonce1");

        // A dropping releases it.
        drop(a);
        assert!(!reg.contains("aaaa"));
    }

    #[test]
    fn extranonce_reassign_moves_the_claim() {
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Metrics::new();
        let mut w = WorkerExtranonce::new(reg.clone());

        assert!(w.assign("1111", &metrics, WorkerId(1)));
        assert!(reg.contains("1111"));

        // Reconnect hands out a fresh extranonce1: old released, new claimed.
        assert!(w.assign("2222", &metrics, WorkerId(1)));
        assert!(!reg.contains("1111"));
        assert!(reg.contains("2222"));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 0);

        // Re-assigning the SAME value is a no-op (no self-collision).
        assert!(w.assign("2222", &metrics, WorkerId(1)));
        assert_eq!(metrics.snapshot().extranonce1_collisions, 0);
        assert!(reg.contains("2222"));
    }

    // ── claim_unique against a mock node ──────────────────────────────────

    /// Minimal mock node: for each expected connection, read until it sees a
    /// `mining.subscribe`, reply with a subscribe result carrying the given
    /// extranonce1, then push one `mining.notify`. Sockets are held alive
    /// until the task ends so the client can drain buffered bytes.
    async fn spawn_mock_node(
        extranonces: Vec<&'static str>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let mut keep = Vec::new();
            for en1 in extranonces {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let mut acc = String::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if acc.contains("mining.subscribe") {
                        break;
                    }
                }
                let result = format!(
                    "{{\"id\":1,\"result\":[[[\"mining.set_difficulty\",\"{en1}\"],[\"mining.notify\",\"{en1}\"]],\"{en1}\",4],\"error\":null}}\n"
                );
                let _ = sock.write_all(result.as_bytes()).await;
                let notify = "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job1\",\"ph\",\"c1\",\"c2\",[],\"20000000\",\"1a2b3c4d\",\"5f5e100\",true]}\n";
                let _ = sock.write_all(notify.as_bytes()).await;
                let _ = sock.flush().await;
                keep.push(sock);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(keep);
        });
        (addr, handle)
    }

    fn subscribe_replay() -> HandshakeReplay {
        HandshakeReplay {
            configure: None,
            subscribe: r#"{"id":1,"method":"mining.subscribe","params":["test-miner/1.0"]}"#
                .to_string(),
        }
    }

    fn test_cfg(upstream_addr: String, redial_max: u32) -> Arc<ProxyConfig> {
        Arc::new(ProxyConfig {
            upstream_addr,
            connect_timeout: Duration::from_secs(2),
            reconnect_backoff_min: Duration::from_millis(1),
            reconnect_backoff_max: Duration::from_millis(20),
            extranonce_redial_max: redial_max,
            ..ProxyConfig::default()
        })
    }

    #[tokio::test]
    async fn claim_unique_first_try_makes_zero_redials() {
        let (addr, _mock) = spawn_mock_node(vec!["cccc"]).await;
        let cfg = test_cfg(addr, 3);
        let metrics = Arc::new(Metrics::new());
        let reg = Arc::new(ExtranonceRegistry::new());

        let mut upstream =
            UpstreamConn::connect(cfg.clone(), metrics.clone(), WorkerId(1), subscribe_replay())
                .await
                .unwrap();
        let mut wx = WorkerExtranonce::new(reg.clone());

        claim_unique(
            &mut upstream,
            &subscribe_replay(),
            &mut wx,
            &cfg,
            &metrics,
            WorkerId(1),
            true,
        )
        .await
        .expect("claim_unique should resolve");

        assert!(reg.contains("cccc"));
        let snap = metrics.snapshot();
        assert_eq!(snap.extranonce1_redials, 0, "unique on first try → no redials");
        assert_eq!(snap.extranonce1_collisions, 0);
        assert_eq!(snap.extranonce1_unresolved, 0);
    }

    #[tokio::test]
    async fn claim_unique_collide_then_unique_resolves_within_budget() {
        // Pre-occupy "aaaa" with another live worker so the first assign
        // collides; the redial then lands on the free "bbbb".
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Arc::new(Metrics::new());
        let mut occupant = WorkerExtranonce::new(reg.clone());
        assert!(occupant.assign("aaaa", &metrics, WorkerId(99)));

        // Initial connect hands "aaaa" (collision), the redial hands "bbbb".
        let (addr, _mock) = spawn_mock_node(vec!["aaaa", "bbbb"]).await;
        let cfg = test_cfg(addr, 3);

        let mut upstream =
            UpstreamConn::connect(cfg.clone(), metrics.clone(), WorkerId(1), subscribe_replay())
                .await
                .unwrap();
        assert_eq!(upstream.extranonce1, "aaaa");
        let mut wx = WorkerExtranonce::new(reg.clone());

        claim_unique(
            &mut upstream,
            &subscribe_replay(),
            &mut wx,
            &cfg,
            &metrics,
            WorkerId(1),
            true,
        )
        .await
        .expect("claim_unique should resolve");

        assert_eq!(upstream.extranonce1, "bbbb");
        assert!(reg.contains("bbbb"));
        let snap = metrics.snapshot();
        assert_eq!(snap.extranonce1_redials, 1, "one redial to escape the collision");
        assert_eq!(snap.extranonce1_collisions, 1, "the initial assign collided once");
        assert_eq!(snap.extranonce1_unresolved, 0);
    }

    #[tokio::test]
    async fn claim_unique_permanent_collision_stops_after_n_and_serves_overlap() {
        const N: u32 = 3;
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Arc::new(Metrics::new());

        // Another worker permanently holds "dup"; the node keeps re-handing it.
        let mut occupant = WorkerExtranonce::new(reg.clone());
        assert!(occupant.assign("dup", &metrics, WorkerId(99)));

        // 1 initial connect + N redials, every one yielding the SAME "dup".
        let (addr, _mock) = spawn_mock_node(vec!["dup"; (N as usize) + 1]).await;
        let cfg = test_cfg(addr, N);

        let mut upstream =
            UpstreamConn::connect(cfg.clone(), metrics.clone(), WorkerId(1), subscribe_replay())
                .await
                .unwrap();
        let mut wx = WorkerExtranonce::new(reg.clone());

        // Never spins forever; resolves to overlap with Ok.
        claim_unique(
            &mut upstream,
            &subscribe_replay(),
            &mut wx,
            &cfg,
            &metrics,
            WorkerId(1),
            true,
        )
        .await
        .expect("claim_unique must return Ok even when it cannot resolve");

        let snap = metrics.snapshot();
        assert_eq!(
            snap.extranonce1_redials,
            u64::from(N),
            "stops after exactly N redials"
        );
        assert_eq!(snap.extranonce1_unresolved, 1, "unresolved counted once");
        // 1 initial collision + N per-redial collisions.
        assert_eq!(snap.extranonce1_collisions, u64::from(N) + 1);
    }

    #[tokio::test]
    async fn claim_unique_zero_budget_never_redials() {
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Arc::new(Metrics::new());
        let mut occupant = WorkerExtranonce::new(reg.clone());
        assert!(occupant.assign("busy", &metrics, WorkerId(99)));

        let (addr, _mock) = spawn_mock_node(vec!["busy"]).await;
        let cfg = test_cfg(addr, 0);

        let mut upstream =
            UpstreamConn::connect(cfg.clone(), metrics.clone(), WorkerId(1), subscribe_replay())
                .await
                .unwrap();
        let mut wx = WorkerExtranonce::new(reg.clone());

        claim_unique(
            &mut upstream,
            &subscribe_replay(),
            &mut wx,
            &cfg,
            &metrics,
            WorkerId(1),
            true,
        )
        .await
        .expect("claim_unique must return Ok");

        let snap = metrics.snapshot();
        assert_eq!(snap.extranonce1_redials, 0, "zero budget → no redials");
        assert_eq!(snap.extranonce1_unresolved, 1);
        assert_eq!(snap.extranonce1_collisions, 1);
    }

    #[tokio::test]
    async fn claim_unique_preserves_prelude_for_downstream_forwarding() {
        // With preserve_prelude = true and a resolving redial, the fresh
        // subscribe-result must still be buffered for the router to forward.
        let reg = Arc::new(ExtranonceRegistry::new());
        let metrics = Arc::new(Metrics::new());
        let mut occupant = WorkerExtranonce::new(reg.clone());
        assert!(occupant.assign("aaaa", &metrics, WorkerId(99)));

        let (addr, _mock) = spawn_mock_node(vec!["aaaa", "bbbb"]).await;
        let cfg = test_cfg(addr, 3);

        let mut upstream =
            UpstreamConn::connect(cfg.clone(), metrics.clone(), WorkerId(1), subscribe_replay())
                .await
                .unwrap();
        let mut wx = WorkerExtranonce::new(reg.clone());

        claim_unique(
            &mut upstream,
            &subscribe_replay(),
            &mut wx,
            &cfg,
            &metrics,
            WorkerId(1),
            true,
        )
        .await
        .unwrap();

        // The router's next read forwards the fresh subscribe-result downstream.
        match upstream.read().await.unwrap() {
            Some(f) => match f.parsed {
                ServerMsg::SubscribeResult(sr) => assert_eq!(sr.extranonce1, "bbbb"),
                other => panic!("expected buffered SubscribeResult, got {:?}", other),
            },
            None => panic!("expected a buffered subscribe result"),
        }
    }
}
