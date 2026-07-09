//! Per-connection session state + I/O loop.
//!
//! Owns the TcpStream split into read/write halves, maintains the
//! subscribe→authorize→authorized state machine, dispatches requests
//! to protocol handlers, and delivers server-initiated notifications.
//!
//! State transitions:
//!
//! ```text
//!   Fresh       -- mining.subscribe --> Subscribed
//!   Subscribed  -- mining.authorize --> Authorized
//!   Authorized  (submit/resubscribe)
//! ```
//!
//! Timeouts:
//! - auth_deadline: 30s from connection to reach Authorized, else close
//! - line read: 10min idle with no incoming line closes the session

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;
use std::time::Duration;
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use serde_json::{json, Value};
use log::{info, warn, debug};

use crate::address;
use super::jobs::Template;
use super::protocol::{
    methods, ErrorCode, StratumError, StratumRequest, StratumResponse, StratumNotification,
    MAX_LINE_BYTES,
};
use super::submit::{handle_submit, AcceptBlockFn};
use super::TemplateContext;

/// Sprint 2.d — Build a fresh Template from the current DAG + mempool
/// state with `session`'s authorized address in the coinbase output,
/// install it on the session, and dispatch `mining.notify`.
///
/// `clean_jobs=true` asks the miner to abandon any in-flight work
/// (used on tip changes where the old work can no longer win). False
/// is a mempool-driven refresh — miner may finish the current job.
///
/// Returns Err(&'static str) for diagnostic logging. Never panics.
pub fn install_fresh_template(
    session:    &std::sync::Arc<Session>,
    ctx:        &TemplateContext,
    clean_jobs: bool,
) -> Result<(), &'static str> {
    // 1. Extract authorized address. If the session is not yet
    //    authorized this is a bug in the caller — log and bail.
    let addr_str = match session.authorized_addr() {
        Some(a) => a,
        None    => return Err("install_fresh_template called on un-authorized session"),
    };

    let parsed_addr = match address::Address::parse(&addr_str) {
        Ok(a)  => a,
        Err(_) => return Err("stored address no longer parses — set_authorized_addr bypassed validation?"),
    };
    let miner_spk: Vec<u8> = parsed_addr.hash().to_vec();

    // 2. Snapshot DAG state: tip for height/blue_score, tips() for parents.
    //    Nested scope drops the read lock before we touch mempool/storage.
    let (parents, height, blue_score) = {
        let d = ctx.dag.read();
        let tip_hash = match d.selected_tip() {
            Some(h) => h,
            None    => return Err("DAG has no selected tip — node not ready?"),
        };
        let data = match d.get_block_data(&tip_hash) {
            Some(dd) => dd.clone(),
            None     => return Err("DAG selected_tip missing block data — inconsistent state"),
        };
        let parents_vec: Vec<[u8; 32]> = d.tips();
        // Next block extends the tip.
        (parents_vec, data.height + 1, data.blue_score + 1)
    };

    // 3. Current difficulty target.
    let bits = ctx.store.get_meta("current_bits").ok().flatten()
        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
        .unwrap_or(0x1d00ffff_u32);

    // 4. Pull top-fee transactions from mempool.
    //    Note: 2000 is an upper bound; Template::build will drop any
    //    that don't fit the block size budget.
    let other_txs = ctx.mempool.get_for_block(2000);
    let total_fees: u64 = other_txs.iter()
        .map(|tx| ctx.mempool.get_entry(&tx.txid())
            .map(|e| e.fee)
            .unwrap_or(0))
        .sum();

    // 5. Unique job id — timestamp + session id + atomic counter.
    //    Format is opaque to miners; only needs uniqueness per session.
    let job_id = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let c = CTR.fetch_add(1, Ordering::Relaxed);
        format!("{:x}-{}-{:x}", session.id, height, c)
    };

    // 6. Build the template.
    let template = Template::build(
        parents,
        height,
        blue_score,
        bits,
        &miner_spk,
        total_fees,
        other_txs,
        ctx.coinbase_tag.as_bytes(),
        job_id,
    );

    // 7. Install on session (either replace-all or append) and send notify.
    if clean_jobs {
        session.replace_templates(template.clone());
    } else {
        session.push_template(template.clone());
    }

    // Build the mining.notify JSON-RPC notification.
    // Template::to_notify_params renders the 9-element params array in
    // the canonical stratum order (job_id, prevhash, coinb1, coinb2,
    // merkle_branches, version, bits, ntime, clean_jobs).
    let notify = StratumNotification::new(
        methods::NOTIFY,
        template.to_notify_params(clean_jobs),
    );
    let _ = session.send_line(notify.to_line());

    info!(
        "stratum: session {} notified h={} bits=0x{:08x} job={} clean={} {} txs",
        session.id, template.height, template.bits, template.job_id, clean_jobs,
        template.other_txs.len(),
    );
    Ok(())
}

/// Session-level state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// TCP accept complete, no subscribe yet.
    Fresh,
    /// Received mining.subscribe, awaiting mining.authorize.
    Subscribed,
    /// Authorized; miner can receive jobs and submit shares.
    Authorized,
    /// Marked for removal; I/O loop will exit shortly.
    Dead,
}

/// How long a peer has to move Fresh → Authorized before we close them.
pub const AUTH_TIMEOUT_SECS: u64 = 30;

/// Idle close — no incoming messages for this long = drop.
pub const IDLE_TIMEOUT_SECS: u64 = 600;

/// Max submissions per minute per session. Anti-flood.
pub const SUBMIT_RATE_PER_MIN: u32 = 30;

/// Max number of templates retained per session. Miners may submit
/// against any of the last N jobs (stale but within retention window).
/// Older than this returns error-21 (JobNotFoundOrStale).
pub const MAX_TEMPLATES_PER_SESSION: usize = 16;

/// Soft cap on the duplicate-share cache. Keyed by (job_id, en2_hex,
/// nonce_hex). Cleared when a new template evicts old jobs.
pub const MAX_SUBMITTED_ENTRIES: usize = 4096;

/// A single stratum client session.
///
/// Shared via Arc between the server registry (for broadcasting
/// notifications) and the per-session task (for I/O). Interior
/// mutability via Mutex where needed.
pub struct Session {
    pub id:              u64,
    pub peer_addr:       SocketAddr,
    pub created_at:      Instant,

    /// Random 4-byte extranonce1 assigned at subscribe time.
    /// Unique per session (server guarantees no collision).
    pub extranonce1:     [u8; 4],

    /// Channel to the session writer task. Notifications and
    /// responses enter here and are serialized out in order.
    tx_out:              Mutex<Option<mpsc::UnboundedSender<String>>>,

    /// Current state. Atomic for cheap lock-free reads from the
    /// registry (snapshots, health checks) while the I/O task
    /// mutates it.
    state:               Mutex<SessionState>,

    /// The miner's bech32 address from mining.authorize.
    authorized_addr:     Mutex<Option<String>>,

    /// Rate-limit counter + window start for submission flood.
    submit_counter:      AtomicU32,
    submit_window_start: AtomicU64,  // secs since UNIX_EPOCH

    /// Recent job templates pushed to this session. Bounded by
    /// MAX_TEMPLATES_PER_SESSION (LRU, oldest first).
    templates:           Mutex<VecDeque<Template>>,

    /// Duplicate-share detection cache. Bounded; entries for a job_id
    /// are dropped when that template evicts from `templates`.
    submitted:           Mutex<HashSet<(String, String, String)>>,
}

impl Session {
    pub fn new(id: u64, peer_addr: SocketAddr) -> Self {
        let mut extranonce1 = [0u8; 4];
        // Seed with a mix of id + time so multiple sessions don't collide.
        // Cryptographic randomness isn't strictly required here; uniqueness is.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let seed = id.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(now);
        extranonce1.copy_from_slice(&seed.to_le_bytes()[..4]);

        Self {
            id,
            peer_addr,
            created_at:          Instant::now(),
            extranonce1,
            tx_out:              Mutex::new(None),
            state:               Mutex::new(SessionState::Fresh),
            authorized_addr:     Mutex::new(None),
            submit_counter:      AtomicU32::new(0),
            submit_window_start: AtomicU64::new(0),
            templates:           Mutex::new(VecDeque::with_capacity(MAX_TEMPLATES_PER_SESSION)),
            submitted:           Mutex::new(HashSet::new()),
        }
    }

    pub fn state(&self) -> SessionState { *self.state.lock() }
    pub fn is_authorized(&self) -> bool { self.state() == SessionState::Authorized }
    pub fn is_dead(&self) -> bool       { self.state() == SessionState::Dead }

    pub fn set_state(&self, s: SessionState) {
        *self.state.lock() = s;
    }

    pub fn authorized_addr(&self) -> Option<String> {
        self.authorized_addr.lock().clone()
    }

    /// Set authorized address — used by the authorize handler.
    pub(super) fn set_authorized_addr(&self, addr: String) {
        *self.authorized_addr.lock() = Some(addr);
    }

    /// Push a new template into the session's LRU buffer. When the
    /// buffer is full, the oldest template is evicted; submitted-share
    /// entries tied to that template are also dropped.
    pub fn push_template(&self, t: Template) {
        let mut templates = self.templates.lock();
        if templates.len() >= MAX_TEMPLATES_PER_SESSION {
            if let Some(evicted) = templates.pop_front() {
                // Drop submitted entries keyed by the evicted job_id.
                let mut submitted = self.submitted.lock();
                submitted.retain(|(jid, _, _)| jid != &evicted.job_id);
            }
        }
        templates.push_back(t);
    }

    /// Replace the entire template buffer — used on tip change with
    /// `clean_jobs=true`. Clears submitted cache too; old shares are
    /// no longer meaningful.
    pub fn replace_templates(&self, t: Template) {
        let mut templates = self.templates.lock();
        templates.clear();
        templates.push_back(t);

        let mut submitted = self.submitted.lock();
        submitted.clear();
    }

    /// Look up a template by job_id. Returns a clone to avoid holding
    /// the lock during block validation.
    pub fn find_template(&self, job_id: &str) -> Option<Template> {
        self.templates.lock().iter().rev().find(|t| t.job_id == job_id).cloned()
    }

    /// Mark a submission as seen. Returns Ok(()) if new, Err if duplicate.
    /// Automatically trims the cache if it grows too large.
    pub fn record_submission(
        &self,
        job_id:    &str,
        en2_hex:   &str,
        nonce_hex: &str,
    ) -> Result<(), ()> {
        let key = (job_id.to_string(), en2_hex.to_string(), nonce_hex.to_string());
        let mut submitted = self.submitted.lock();
        if submitted.contains(&key) {
            return Err(());
        }
        if submitted.len() >= MAX_SUBMITTED_ENTRIES {
            // Cap the cache size; drop a random entry to make room.
            // This is defensive — in practice the eviction path on
            // push_template keeps this well under the cap.
            if let Some(evict) = submitted.iter().next().cloned() {
                submitted.remove(&evict);
            }
        }
        submitted.insert(key);
        Ok(())
    }

    /// Register the outbound channel. Called once from `run`.
    fn install_writer(&self, tx: mpsc::UnboundedSender<String>) {
        *self.tx_out.lock() = Some(tx);
    }

    /// Send a fully-rendered line to this session's writer task.
    /// Returns Err if the writer has hung up.
    pub fn send_line(&self, line: String) -> Result<(), &'static str> {
        let g = self.tx_out.lock();
        match g.as_ref() {
            Some(tx) => tx.send(line).map_err(|_| "writer closed"),
            None     => Err("writer not installed"),
        }
    }

    /// Send a server-initiated notification (mining.notify, etc).
    pub fn notify(&self, method: &str, params: Value) -> Result<(), &'static str> {
        let n = StratumNotification::new(method, params);
        self.send_line(n.to_line())
    }

    /// Check-and-increment rate limiter. Returns Ok if the
    /// submission is allowed, Err with a diagnostic if not.
    pub fn check_submit_rate(&self) -> Result<(), StratumError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window_start = self.submit_window_start.load(Ordering::Relaxed);

        if now.saturating_sub(window_start) >= 60 {
            // New minute window
            self.submit_window_start.store(now, Ordering::Relaxed);
            self.submit_counter.store(1, Ordering::Relaxed);
            Ok(())
        } else {
            let count = self.submit_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if count > SUBMIT_RATE_PER_MIN {
                Err(StratumError::new(
                    ErrorCode::Other,
                    format!("submit rate exceeded ({}/min cap)", SUBMIT_RATE_PER_MIN),
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Per-session I/O task. Reads lines, dispatches, and handles
/// outbound notifications via an mpsc channel feeding the write half.
///
/// `accept_block` is the hook into the node's accept_block path. When
/// provided, submit validation produces real blocks and emits them
/// via this callback. When None, submit returns the legacy
/// placeholder error — useful for unit tests that don't need the DAG.
pub async fn run(
    session:       std::sync::Arc<Session>,
    socket:        TcpStream,
    accept_block:  Option<std::sync::Arc<AcceptBlockFn>>,
    // Sprint 2.d: template generation context. When None, handle_authorize
    // will not install a template (backward-compatible with protocol-only
    // smoke tests).
    node_ctx:      Option<std::sync::Arc<TemplateContext>>,
) -> std::io::Result<()> {
    // Disable Nagle for interactive JSON-RPC.
    let _ = socket.set_nodelay(true);

    let (rd, wr) = socket.into_split();

    // Outbound channel: session.send_line() enqueues here, writer
    // task flushes to the TCP socket.
    let (out_tx, out_rx) = mpsc::unbounded_channel::<String>();
    session.install_writer(out_tx);

    // Spawn writer half.
    let session_for_writer = session.clone();
    let writer_handle = tokio::spawn(async move {
        writer_loop(wr, out_rx, session_for_writer).await;
    });

    // Reader half: parse lines and dispatch.
    let mut reader = BufReader::with_capacity(MAX_LINE_BYTES + 256, rd);
    let mut line_buf = String::with_capacity(512);

    let auth_deadline = Instant::now() + Duration::from_secs(AUTH_TIMEOUT_SECS);

    loop {
        // Check auth timeout before each read.
        if !session.is_authorized() && Instant::now() > auth_deadline {
            warn!("stratum: session {} auth timeout ({}s)", session.id, AUTH_TIMEOUT_SECS);
            let err = StratumError::new(ErrorCode::Unauthorized, "authorization timeout");
            let _ = session.send_line(StratumResponse::error(None, err).to_line());
            break;
        }

        line_buf.clear();

        // Read a line with an idle timeout as the outer bound.
        let read_result = tokio::time::timeout(
            Duration::from_secs(IDLE_TIMEOUT_SECS),
            reader.read_line(&mut line_buf),
        ).await;

        match read_result {
            Ok(Ok(0)) => {
                // EOF — peer closed.
                debug!("stratum: session {} peer closed", session.id);
                break;
            }
            Ok(Ok(n)) if n > MAX_LINE_BYTES => {
                warn!("stratum: session {} sent oversize line ({}B)", session.id, n);
                break;
            }
            Ok(Ok(_)) => {
                // Dispatch the line.
                let cb_ref = accept_block.as_deref();
                let ctx_ref = node_ctx.as_deref();
                match dispatch(&session, &line_buf, cb_ref, ctx_ref).await {
                    Ok(Some(response)) => {
                        if session.send_line(response.to_line()).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        // Handler already sent (or the request was a notification).
                    }
                    Err(e) => {
                        warn!("stratum: session {} dispatch error: {}", session.id, e);
                        // Send a generic error-20 and keep session open.
                        let err = StratumError::new(ErrorCode::Other, "malformed request");
                        let _ = session.send_line(StratumResponse::error(None, err).to_line());
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("stratum: session {} read error: {}", session.id, e);
                break;
            }
            Err(_) => {
                info!("stratum: session {} idle timeout", session.id);
                break;
            }
        }
    }

    session.set_state(SessionState::Dead);

    // Dropping the tx in the session (via install_writer(None) would
    // be cleaner; the writer exits when the channel is empty-and-closed.
    // We can't easily mutate install_writer, so we let writer_handle
    // observe SessionState::Dead or simply timeout on its side.
    // Most commonly it exits because its mpsc::Receiver returns None
    // after all senders drop; our last sender reference was in the
    // session.tx_out Mutex, which outlives this task. Workaround:
    // wait for writer but bound it.
    let _ = tokio::time::timeout(Duration::from_secs(2), writer_handle).await;
    Ok(())
}

/// Writer task: drains the outbound channel into the TCP stream.
async fn writer_loop(
    mut wr: OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<String>,
    session: std::sync::Arc<Session>,
) {
    while let Some(line) = rx.recv().await {
        if session.is_dead() { break; }
        if wr.write_all(line.as_bytes()).await.is_err() {
            session.set_state(SessionState::Dead);
            break;
        }
        if wr.flush().await.is_err() {
            session.set_state(SessionState::Dead);
            break;
        }
    }
    // Half-close gracefully.
    let _ = wr.shutdown().await;
}

/// Request dispatcher. Parses a JSON line into a StratumRequest and
/// routes to the appropriate handler. Returns the response to send,
/// or None if the handler has already emitted output itself.
///
/// When `accept_block` is Some, mining.submit goes to the full
/// validation path in submit.rs. When None (e.g., in unit tests or
/// before the DAG wiring in main.rs is complete), submit returns
/// the legacy placeholder error.
async fn dispatch(
    session:       &std::sync::Arc<Session>,
    line:          &str,
    accept_block:  Option<&AcceptBlockFn>,
    node_ctx:      Option<&TemplateContext>,
) -> Result<Option<StratumResponse>, String> {
    let req = StratumRequest::parse(line)?;

    match req.method.as_str() {
        methods::SUBSCRIBE => Ok(Some(handle_subscribe(session, &req))),
        methods::AUTHORIZE => Ok(Some(handle_authorize(session, &req, node_ctx))),
        methods::SUBMIT    => Ok(Some(handle_submit_dispatch(session, &req, accept_block))),
        methods::EXTRANONCE_SUBSCRIBE => Ok(Some(StratumResponse::ok(req.id, Value::from(true)))),
        methods::SUGGEST_DIFFICULTY | methods::SUGGEST_TARGET => {
            Ok(Some(StratumResponse::ok(req.id, Value::from(true))))
        }
        other => {
            warn!("stratum: session {} unknown method: {}", session.id, other);
            Ok(Some(StratumResponse::error(
                req.id,
                StratumError::new(ErrorCode::Other, format!("unknown method: {}", other)),
            )))
        }
    }
}

/// mining.subscribe handler.
///
/// Returns: [[["mining.set_difficulty", sub_id], ["mining.notify", sub_id]],
///          extranonce1_hex, extranonce2_size]
fn handle_subscribe(session: &std::sync::Arc<Session>, req: &StratumRequest) -> StratumResponse {
    if session.state() != SessionState::Fresh {
        return StratumResponse::error(
            req.id.clone(),
            StratumError::new(ErrorCode::Other, "already subscribed"),
        );
    }

    session.set_state(SessionState::Subscribed);

    let extranonce1_hex = hex::encode(session.extranonce1);
    let subscriptions = json!([
        [methods::SET_DIFFICULTY, extranonce1_hex.clone()],
        [methods::NOTIFY,         extranonce1_hex.clone()],
    ]);

    info!("stratum: session {} subscribed (extranonce1={})", session.id, extranonce1_hex);

    StratumResponse::ok(req.id.clone(), json!([
        subscriptions,
        extranonce1_hex,
        4u32,  // extranonce2_size (bytes)
    ]))
}

/// mining.authorize handler.
///
/// Strict validation: the username must parse as a valid Bloch-SIS Protocol
/// bech32 address. Invalid addresses get a code-24 error and the
/// session stays in Subscribed (not Authorized).
fn handle_authorize(
    session:   &std::sync::Arc<Session>,
    req:       &StratumRequest,
    node_ctx:  Option<&TemplateContext>,
) -> StratumResponse {
    if session.state() == SessionState::Fresh {
        return StratumResponse::error(
            req.id.clone(),
            StratumError::new(ErrorCode::NotSubscribed, "must subscribe before authorizing"),
        );
    }

    // params: [username, password]
    let params = match req.params.as_array() {
        Some(a) if !a.is_empty() => a,
        _ => {
            return StratumResponse::error(
                req.id.clone(),
                StratumError::new(ErrorCode::Unauthorized, "authorize requires [username, password]"),
            );
        }
    };

    let username = match params[0].as_str() {
        Some(s) => s,
        None => {
            return StratumResponse::error(
                req.id.clone(),
                StratumError::new(ErrorCode::Unauthorized, "username must be a string"),
            );
        }
    };

    // Validate as a Bloch-SIS Protocol bech32 address.
    match address::Address::parse(username) {
        Ok(_) => {
            session.set_authorized_addr(username.to_string());
            session.set_state(SessionState::Authorized);
            info!("stratum: session {} authorized {}", session.id, username);

            // Sprint 2.d: immediately push a fresh template + mining.notify
            // so the miner can start work without waiting for the next
            // tip change or the 60s refresh tick.
            //
            // clean_jobs=true is semantically "fresh session, no prior
            // work to preserve". If node_ctx is None (protocol-only test
            // mode) this step is skipped silently.
            if let Some(ctx) = node_ctx {
                if let Err(reason) = install_fresh_template(session, ctx, true) {
                    warn!("stratum: session {} authorize OK but template install failed: {}",
                          session.id, reason);
                }
            }

            StratumResponse::ok(req.id.clone(), Value::from(true))
        }
        Err(e) => {
            warn!("stratum: session {} invalid address '{}': {}", session.id, username, e);
            StratumResponse::error(
                req.id.clone(),
                StratumError::new(ErrorCode::Unauthorized, format!("invalid address: {}", e)),
            )
        }
    }
}

/// Thin wrapper that delegates to the real submit handler in submit.rs
/// when an accept_block callback is available, otherwise returns the
/// AA.1-pt-1 placeholder error for unit tests that don't wire the
/// callback.
fn handle_submit_dispatch(
    session:        &std::sync::Arc<Session>,
    req:            &StratumRequest,
    accept_block:   Option<&AcceptBlockFn>,
) -> StratumResponse {
    match accept_block {
        Some(cb) => handle_submit(session, req, cb),
        None => handle_submit_placeholder(session, req),
    }
}

/// AA.1-pt-1 placeholder kept for standalone dispatch paths that don't
/// yet carry an accept_block callback (e.g., unit tests).
fn handle_submit_placeholder(session: &std::sync::Arc<Session>, req: &StratumRequest) -> StratumResponse {
    if !session.is_authorized() {
        return StratumResponse::error(
            req.id.clone(),
            StratumError::new(ErrorCode::Unauthorized, "unauthorized worker"),
        );
    }
    if let Err(e) = session.check_submit_rate() {
        return StratumResponse::error(req.id.clone(), e);
    }
    // Real handler lands next commit; for now, signal stale to any submission.
    StratumResponse::error(
        req.id.clone(),
        StratumError::new(
            ErrorCode::JobNotFoundOrStale,
            "submission path not yet implemented — expect error-21 until AA.1 pt 2 ships",
        ),
    )
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn mk_session() -> std::sync::Arc<Session> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        std::sync::Arc::new(Session::new(1, addr))
    }

    #[test]
    fn session_starts_fresh() {
        let s = mk_session();
        assert_eq!(s.state(), SessionState::Fresh);
        assert!(!s.is_authorized());
    }

    #[test]
    fn extranonce1_is_four_bytes() {
        let s = mk_session();
        assert_eq!(s.extranonce1.len(), 4);
    }

    #[test]
    fn extranonce1_differs_between_sessions() {
        // Session ids 1 and 2 → different extranonce1. Uses time+id,
        // so this can theoretically collide if two sessions
        // construct in the same microsecond with specific ids.
        // Extremely unlikely in practice.
        let a = std::sync::Arc::new(Session::new(1, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)));
        std::thread::sleep(std::time::Duration::from_micros(2));
        let b = std::sync::Arc::new(Session::new(2, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)));
        assert_ne!(a.extranonce1, b.extranonce1);
    }

    #[test]
    fn subscribe_advances_state_and_returns_extranonce() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(1)),
            method: methods::SUBSCRIBE.to_string(),
            params: json!(["cpuminer/2.5"]),
        };
        let resp = handle_subscribe(&s, &req);
        assert_eq!(s.state(), SessionState::Subscribed);
        // result is [subs_array, extranonce1_hex, 4]
        let result = &resp.result;
        assert!(result.is_array());
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[2].as_u64(), Some(4));
    }

    #[test]
    fn subscribe_twice_errors() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(1)),
            method: methods::SUBSCRIBE.to_string(),
            params: json!([]),
        };
        let _ = handle_subscribe(&s, &req);
        let resp = handle_subscribe(&s, &req);
        assert!(resp.error.is_some(), "second subscribe must error");
    }

    #[test]
    fn authorize_rejects_invalid_address() {
        let s = mk_session();
        // Put session in Subscribed first.
        s.set_state(SessionState::Subscribed);

        let req = StratumRequest {
            id:     Some(Value::from(2)),
            method: methods::AUTHORIZE.to_string(),
            params: json!(["not-a-valid-address", "x"]),
        };
        let resp = handle_authorize(&s, &req, None);
        assert!(resp.error.is_some(), "invalid address must error");
        assert_eq!(s.state(), SessionState::Subscribed, "session stays unauthorized on bad address");
    }

    #[test]
    fn authorize_before_subscribe_errors() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(1)),
            method: methods::AUTHORIZE.to_string(),
            params: json!(["bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45", "x"]),
        };
        let resp = handle_authorize(&s, &req, None);
        assert!(resp.error.is_some());
    }

    #[test]
    fn submit_while_unauthorized_errors_24() {
        let s = mk_session();
        let req = StratumRequest {
            id:     Some(Value::from(3)),
            method: methods::SUBMIT.to_string(),
            params: json!([]),
        };
        let resp = handle_submit_placeholder(&s, &req);
        let err_arr = resp.error.as_ref().and_then(|v| v.as_array()).unwrap();
        assert_eq!(err_arr[0].as_u64(), Some(24));
    }

    #[test]
    fn submit_rate_limiter_cuts_off_after_cap() {
        let s = mk_session();
        for _ in 0..SUBMIT_RATE_PER_MIN {
            assert!(s.check_submit_rate().is_ok());
        }
        // One more should trip.
        assert!(s.check_submit_rate().is_err());
    }
}
