//! Module 5 — process entry + wiring.
//!
//! Loads [`ProxyConfig`] from the environment, builds the shared
//! `Arc<Metrics>`, binds the downstream listener and runs the accept-loop:
//! each accepted TCP connection gets a monotonic [`WorkerId`] and is handed
//! to `router::run_worker` on its own task, wrapped in a metrics guard so
//! `workers_active` is decremented even if the worker task unwinds. A tiny
//! HTTP metrics endpoint (see [`crate::metrics`]) runs alongside, and
//! SIGINT/SIGTERM stop the accept-loop cleanly.
//!
//! This module opens no upstream sockets and speaks no stratum itself — it
//! is pure wiring. All per-worker logic lives in `router` (module 4).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::downstream::DownstreamConn;
use crate::metrics;
use crate::router::{self, ExtranonceRegistry};
use crate::types::{Metrics, PoolError, ProxyConfig, WorkerId};

/// Owns the shared config + metrics and runs the whole proxy process.
pub struct ProxyServer {
    cfg: Arc<ProxyConfig>,
    metrics: Arc<Metrics>,
    /// Process-wide extranonce1 collision guard, shared by every worker.
    extranonce_registry: Arc<ExtranonceRegistry>,
}

/// RAII guard: increments `workers_active`/`workers_total` on construction
/// and decrements `workers_active` on drop. Because it drops on the worker
/// task's normal return, error return, OR panic, the active-worker gauge can
/// never leak a slot.
struct WorkerGuard {
    metrics: Arc<Metrics>,
}

impl WorkerGuard {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.worker_connected();
        WorkerGuard { metrics }
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.metrics.worker_disconnected();
    }
}

impl ProxyServer {
    pub fn new(cfg: ProxyConfig) -> Self {
        ProxyServer {
            cfg: Arc::new(cfg),
            metrics: Arc::new(Metrics::new()),
            extranonce_registry: Arc::new(ExtranonceRegistry::new()),
        }
    }

    /// Bind the downstream listener and the metrics endpoint, then run the
    /// accept-loop until a shutdown signal (SIGINT/SIGTERM) arrives. Returns
    /// `Ok(())` on clean shutdown; only a fatal bind error returns `Err`.
    pub async fn run(self) -> Result<(), PoolError> {
        let listener = TcpListener::bind(&self.cfg.listen_addr).await.map_err(|e| {
            PoolError::Config(format!(
                "cannot bind downstream listener {}: {}",
                self.cfg.listen_addr, e
            ))
        })?;
        log::info!(
            "bloch-pool-proxy listening for miners on {} -> upstream {} (max_workers={})",
            self.cfg.listen_addr,
            self.cfg.upstream_addr,
            self.cfg.max_workers
        );

        // Metrics endpoint on its own task. A bind failure there is logged but
        // must not take the proxy down — mining continues without metrics.
        {
            let m = self.metrics.clone();
            let addr = self.cfg.metrics_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = metrics::serve_metrics(&addr, m).await {
                    log::error!("metrics endpoint failed: {}", e);
                }
            });
        }

        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);

        let mut next_id: u64 = 1;

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    log::info!("shutdown signal received; stopping accept-loop");
                    break;
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            // Transient accept error (fd pressure, RST during
                            // handshake): log and keep serving.
                            log::warn!("downstream accept error: {}", e);
                            continue;
                        }
                    };

                    // fd guard: refuse when at capacity. The active count is a
                    // relaxed load; a small overshoot under a burst is harmless
                    // and self-corrects as workers finish.
                    let active = self.metrics.workers_active.load(Ordering::Relaxed);
                    if active >= 0 && (active as usize) >= self.cfg.max_workers {
                        log::warn!(
                            "at capacity ({} workers); rejecting {}",
                            self.cfg.max_workers, peer
                        );
                        // Drop the stream: closes the connection immediately.
                        drop(stream);
                        continue;
                    }

                    let id = WorkerId(next_id);
                    next_id = next_id.wrapping_add(1);

                    // TCP_NODELAY: stratum lines are tiny and latency-sensitive.
                    if let Err(e) = stream.set_nodelay(true) {
                        log::debug!("worker {} set_nodelay failed: {}", id, e);
                    }

                    log::info!("worker {} connected from {}", id, peer);

                    let cfg = self.cfg.clone();
                    let metrics = self.metrics.clone();
                    let registry = self.extranonce_registry.clone();
                    tokio::spawn(async move {
                        // Guard bumps workers_active now and releases on any exit.
                        let _guard = WorkerGuard::new(metrics.clone());
                        // Wrap the accepted stream; the router owns per-worker
                        // session state from here.
                        let down = DownstreamConn::new(stream, id, cfg.clone(), metrics.clone());
                        match router::run_worker(down, cfg, metrics, registry).await {
                            Ok(()) => log::info!("worker {} closed", id),
                            Err(e) => log::info!("worker {} closed: {}", id, e),
                        }
                    });
                }
            }
        }

        log::info!("bloch-pool-proxy stopped");
        Ok(())
    }
}

/// Resolve when the process should begin a graceful shutdown: SIGINT
/// (Ctrl-C) on all platforms, plus SIGTERM on unix (used by `fly` / systemd
/// / docker stop).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // If installing the SIGTERM handler fails, fall back to Ctrl-C alone.
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    r = tokio::signal::ctrl_c() => {
                        if let Err(e) = r {
                            log::warn!("ctrl_c listener error: {}", e);
                        }
                    }
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                log::warn!("cannot install SIGTERM handler: {}; using SIGINT only", e);
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Build a [`ProxyConfig`] from the environment, layered over
/// [`ProxyConfig::default`]. Recognised variables:
///
/// | var | field | example |
/// |-----|-------|---------|
/// | `BLOCH_POOL_LISTEN`        | `listen_addr`          | `0.0.0.0:3335` |
/// | `BLOCH_POOL_UPSTREAM`      | `upstream_addr`        | `127.0.0.1:3333` |
/// | `BLOCH_POOL_METRICS`       | `metrics_addr`         | `127.0.0.1:9333` |
/// | `BLOCH_POOL_KEEPALIVE_SECS`| `keepalive_idle` (s)   | `20` |
/// | `BLOCH_POOL_VARDIFF`       | `vardiff_override`     | `1`/`true`/`off` |
/// | `BLOCH_POOL_PPLNS_WINDOW`  | `pplns_window_shares`  | `100000` |
/// | `BLOCH_POOL_MAX_WORKERS`   | `max_workers`          | `4096` |
///
/// An unset variable keeps the default; a set-but-unparseable variable is a
/// hard [`PoolError::Config`] so a typo fails fast at startup instead of
/// silently mining with the wrong setting.
pub fn config_from_env() -> Result<ProxyConfig, PoolError> {
    config_from_getter(|k| std::env::var(k).ok())
}

/// Testable core of [`config_from_env`]: reads each variable through `get`
/// so tests can supply a map instead of mutating process-global env state.
fn config_from_getter<F>(get: F) -> Result<ProxyConfig, PoolError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut cfg = ProxyConfig::default();

    if let Some(v) = get("BLOCH_POOL_LISTEN") {
        cfg.listen_addr = v;
    }
    if let Some(v) = get("BLOCH_POOL_UPSTREAM") {
        cfg.upstream_addr = v;
    }
    if let Some(v) = get("BLOCH_POOL_METRICS") {
        cfg.metrics_addr = v;
    }
    if let Some(v) = get("BLOCH_POOL_KEEPALIVE_SECS") {
        let secs = parse_field::<u64>("BLOCH_POOL_KEEPALIVE_SECS", &v)?;
        cfg.keepalive_idle = std::time::Duration::from_secs(secs);
    }
    if let Some(v) = get("BLOCH_POOL_HANDSHAKE_SECS") {
        let secs = parse_field::<u64>("BLOCH_POOL_HANDSHAKE_SECS", &v)?;
        cfg.handshake_timeout = std::time::Duration::from_secs(secs);
    }
    if let Some(v) = get("BLOCH_POOL_VARDIFF") {
        cfg.vardiff_override = parse_bool("BLOCH_POOL_VARDIFF", &v)?;
    }
    if let Some(v) = get("BLOCH_POOL_PPLNS_WINDOW") {
        cfg.pplns_window_shares = parse_field::<usize>("BLOCH_POOL_PPLNS_WINDOW", &v)?;
    }
    if let Some(v) = get("BLOCH_POOL_MAX_WORKERS") {
        let n = parse_field::<usize>("BLOCH_POOL_MAX_WORKERS", &v)?;
        if n == 0 {
            return Err(PoolError::Config(
                "BLOCH_POOL_MAX_WORKERS must be >= 1".to_string(),
            ));
        }
        cfg.max_workers = n;
    }

    Ok(cfg)
}

fn parse_field<T>(name: &str, raw: &str) -> Result<T, PoolError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    raw.trim()
        .parse::<T>()
        .map_err(|e| PoolError::Config(format!("{}: invalid value {:?}: {}", name, raw, e)))
}

fn parse_bool(name: &str, raw: &str) -> Result<bool, PoolError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(PoolError::Config(format!(
            "{}: expected a boolean (1/0/true/false/on/off), got {:?}",
            name, other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    fn getter<'a>(
        map: &'a HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| map.get(k).map(|s| s.to_string())
    }

    #[test]
    fn empty_env_yields_defaults() {
        let map: HashMap<&str, &str> = HashMap::new();
        let cfg = config_from_getter(getter(&map)).unwrap();
        let def = ProxyConfig::default();
        assert_eq!(cfg.listen_addr, def.listen_addr);
        assert_eq!(cfg.upstream_addr, def.upstream_addr);
        assert_eq!(cfg.metrics_addr, def.metrics_addr);
        assert_eq!(cfg.keepalive_idle, def.keepalive_idle);
        assert_eq!(cfg.vardiff_override, def.vardiff_override);
        assert_eq!(cfg.pplns_window_shares, def.pplns_window_shares);
        assert_eq!(cfg.max_workers, def.max_workers);
    }

    #[test]
    fn overrides_are_applied() {
        let mut map = HashMap::new();
        map.insert("BLOCH_POOL_LISTEN", "0.0.0.0:4444");
        map.insert("BLOCH_POOL_UPSTREAM", "10.0.0.1:3333");
        map.insert("BLOCH_POOL_METRICS", "127.0.0.1:9999");
        map.insert("BLOCH_POOL_KEEPALIVE_SECS", "45");
        map.insert("BLOCH_POOL_VARDIFF", "true");
        map.insert("BLOCH_POOL_PPLNS_WINDOW", "250000");
        map.insert("BLOCH_POOL_MAX_WORKERS", "128");
        let cfg = config_from_getter(getter(&map)).unwrap();
        assert_eq!(cfg.listen_addr, "0.0.0.0:4444");
        assert_eq!(cfg.upstream_addr, "10.0.0.1:3333");
        assert_eq!(cfg.metrics_addr, "127.0.0.1:9999");
        assert_eq!(cfg.keepalive_idle, Duration::from_secs(45));
        assert!(cfg.vardiff_override);
        assert_eq!(cfg.pplns_window_shares, 250_000);
        assert_eq!(cfg.max_workers, 128);
    }

    #[test]
    fn bool_variants_parse() {
        for (s, want) in [
            ("1", true),
            ("on", true),
            ("YES", true),
            ("True", true),
            ("0", false),
            ("off", false),
            ("no", false),
            ("false", false),
        ] {
            assert_eq!(parse_bool("x", s).unwrap(), want, "for {s:?}");
        }
        assert!(parse_bool("x", "maybe").is_err());
    }

    #[test]
    fn bad_number_is_config_error() {
        let mut map = HashMap::new();
        map.insert("BLOCH_POOL_MAX_WORKERS", "lots");
        let err = config_from_getter(getter(&map)).unwrap_err();
        assert!(matches!(err, PoolError::Config(_)));
    }

    #[test]
    fn zero_max_workers_rejected() {
        let mut map = HashMap::new();
        map.insert("BLOCH_POOL_MAX_WORKERS", "0");
        let err = config_from_getter(getter(&map)).unwrap_err();
        assert!(matches!(err, PoolError::Config(_)));
    }

    #[test]
    fn new_stores_config_and_zeroed_metrics() {
        let mut cfg = ProxyConfig::default();
        cfg.max_workers = 7;
        let srv = ProxyServer::new(cfg);
        assert_eq!(srv.cfg.max_workers, 7);
        let snap = srv.metrics.snapshot();
        assert_eq!(snap.workers_active, 0);
        assert_eq!(snap.workers_total, 0);
    }

    #[test]
    fn worker_guard_balances_active_gauge() {
        let metrics = Arc::new(Metrics::new());
        {
            let _g = WorkerGuard::new(metrics.clone());
            assert_eq!(metrics.snapshot().workers_active, 1);
            assert_eq!(metrics.snapshot().workers_total, 1);
        }
        // Dropped: active back to zero, total remains (monotonic counter).
        assert_eq!(metrics.snapshot().workers_active, 0);
        assert_eq!(metrics.snapshot().workers_total, 1);
    }
}
