//! Miner-facing stratum server — the SIS-native dialect.
//!
//! Keeps the node's Stratum V1 skeleton (src/stratum/session.rs):
//! newline-JSON over TCP, subscribe → authorize → submit state machine,
//! per-session writer task, auth/idle timeouts, per-minute submit rate
//! cap, Bitcoin-convention error codes. Params are SIS-native (see
//! protocol.rs) because classic V1 params cannot carry the Module-SIS
//! solution vector (node main.rs, B5f).
//!
//! Share validation is the real thing, not a mock:
//! `bloch_sis_pow::verify_regime(preimage, nonce, s, share_target,
//! canonical_residual_coeffs(job.height))` — the same verifier the node's
//! consensus uses in `Block::validate_pow` (height-aware: k=4 below the k=8
//! soft-fork activation height, k=8 at/above it), pointed at the softer share
//! target.
//! If the share's aux hash also meets the BLOCK target, the share IS a
//! block: it's assembled and pushed to the node via `submitblock`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use bloch_crypto::address::Address;
use bloch_sis_pow::verify::compute_aux_hash;
use bloch_sis_pow::{hash_meets_target, verify_regime, VerifyError};

use crate::job::Job;
use crate::protocol::{
    methods, ErrorCode, StratumError, StratumNotification, StratumRequest, StratumResponse,
    MAX_LINE_BYTES,
};
use crate::shares::work_from_bits;
use crate::state::{PoolState, Session, SessionState};

const AUTH_TIMEOUT_SECS: u64 = 30;
const IDLE_TIMEOUT_SECS: u64 = 600;
/// Global session ceiling: bounds memory, FDs, and aggregate verify
/// CPU (each session may spray SUBMIT_RATE_PER_MIN expensive verifies).
const MAX_SESSIONS: usize = 1024;
/// Per-IP session ceiling — addresses are free to mint, sockets from
/// one host should not be.
const MAX_SESSIONS_PER_IP: usize = 16;
/// Per-session writer queue depth. Bounded on purpose: a client that
/// cannot drain notify traffic is buffered nowhere and dropped instead
/// (an unbounded queue lets a stalled reader inflate pool memory).
const SEND_QUEUE_DEPTH: usize = 64;

/// Serve miners forever.
pub async fn run(pool: Arc<PoolState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&pool.cfg.listen).await?;
    info!("stratum: listening on {} (SIS-native dialect)", pool.cfg.listen);

    loop {
        let (socket, peer) = listener.accept().await?;

        // Connection caps BEFORE any per-session allocation.
        {
            let sessions = pool.sessions.lock();
            let peer_ip = peer.ip();
            let per_ip = sessions.values()
                .filter(|s| s.peer.parse::<std::net::SocketAddr>()
                    .map(|a| a.ip() == peer_ip).unwrap_or(false))
                .count();
            if sessions.len() >= MAX_SESSIONS || per_ip >= MAX_SESSIONS_PER_IP {
                drop(sessions);
                warn!("stratum: rejecting {} (session caps: {} global / {} per-IP)",
                    peer, MAX_SESSIONS, MAX_SESSIONS_PER_IP);
                continue; // socket drops → closed
            }
        }

        let id = pool.next_session_id();
        if id > 0xff_ffff {
            warn!("stratum: session ids exceeded 2^24 — nonce prefixes now \
                   reuse those of closed sessions (live ranges stay disjoint)");
        }
        let session = Arc::new(Session::new(id, peer.to_string()));
        pool.sessions.lock().insert(id, session.clone());
        info!("stratum: session {} accepted from {}", id, peer);

        let pool2 = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = session_loop(pool2.clone(), session, socket).await {
                debug!("stratum: session {} ended: {}", id, e);
            }
            pool2.sessions.lock().remove(&id);
            info!("stratum: session {} closed", id);
        });
    }
}

async fn session_loop(
    pool:    Arc<PoolState>,
    session: Arc<Session>,
    socket:  TcpStream,
) -> std::io::Result<()> {
    let _ = socket.set_nodelay(true);
    let (rd, mut wr) = socket.into_split();

    // Writer task: session.send_line() → bounded mpsc → socket.
    let (tx, mut rx) = mpsc::channel::<String>(SEND_QUEUE_DEPTH);
    *session.out.lock() = Some(tx);
    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if wr.write_all(line.as_bytes()).await.is_err() { break; }
            if wr.flush().await.is_err() { break; }
        }
        let _ = wr.shutdown().await;
    });

    // read_bounded_line enforces MAX_LINE_BYTES *during* accumulation, so a
    // slowloris peer that never sends '\n' cannot grow the buffer without
    // bound. `read_line` could not: it returns only on '\n' or EOF, so the
    // old `n > MAX_LINE_BYTES` check ran AFTER the whole line had already
    // been collected — multi-GB of heap per session, for free.
    let mut reader = BufReader::with_capacity(MAX_LINE_BYTES + 256, rd);
    let mut line_buf: Vec<u8> = Vec::with_capacity(1024);
    let auth_deadline = Instant::now() + Duration::from_secs(AUTH_TIMEOUT_SECS);

    loop {
        if !session.is_authorized() && Instant::now() > auth_deadline {
            warn!("stratum: session {} auth timeout", session.id);
            break;
        }
        line_buf.clear();
        // Bound every read. An unauthorized peer gets only what is left of
        // the auth window — otherwise a silent socket sits here for the full
        // idle window before the deadline above is ever re-checked.
        let read_timeout = if session.is_authorized() {
            Duration::from_secs(IDLE_TIMEOUT_SECS)
        } else {
            auth_deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(IDLE_TIMEOUT_SECS))
        };
        match tokio::time::timeout(
            read_timeout,
            read_bounded_line(&mut reader, &mut line_buf),
        ).await {
            Ok(Ok(0)) => break,                          // EOF
            Ok(Ok(_)) => {
                let line = match std::str::from_utf8(&line_buf) {
                    Ok(l)  => l,
                    Err(_) => break,                     // protocol violation
                };
                let resp = dispatch(&pool, &session, line).await;
                if let Some(resp) = resp {
                    if !session.send_line(resp.to_line()) { break; }
                }
                // Reclaim a large (but in-bound) line so a long-lived
                // session does not retain the capacity forever.
                if line_buf.capacity() > MAX_LINE_BYTES {
                    line_buf.shrink_to(1024);
                }
            }
            // Over-long line, read error, or idle timeout: all close.
            Ok(Err(_)) | Err(_) => break,
        }
    }

    *session.out.lock() = None; // closes the channel; writer drains + exits
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    Ok(())
}

/// Read one newline-terminated line, enforcing `MAX_LINE_BYTES` DURING
/// accumulation. Mirrors the node's `stratum::session::read_bounded_line`.
///
/// Returns the number of bytes in `buf` (including the trailing `\n`), `0`
/// on clean EOF, or `InvalidData` the instant an unterminated line crosses
/// the cap — before those bytes can be handed on or grown further.
async fn read_bounded_line<R>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize>
where
    R: AsyncBufReadExt + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(0); // EOF
        }
        if let Some(i) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=i]);
            let consumed = i + 1;
            reader.consume(consumed);
            if buf.len() > MAX_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stratum line exceeds MAX_LINE_BYTES",
                ));
            }
            return Ok(buf.len());
        }
        let n = available.len();
        buf.extend_from_slice(available);
        reader.consume(n);
        if buf.len() > MAX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stratum line exceeds MAX_LINE_BYTES",
            ));
        }
    }
}

async fn dispatch(
    pool:    &Arc<PoolState>,
    session: &Arc<Session>,
    line:    &str,
) -> Option<StratumResponse> {
    let req = match StratumRequest::parse(line) {
        Ok(r) => r,
        Err(e) => {
            debug!("stratum: session {} bad line: {}", session.id, e);
            return Some(StratumResponse::error(
                None, StratumError::new(ErrorCode::Other, "malformed request")));
        }
    };

    match req.method.as_str() {
        methods::SUBSCRIBE => Some(handle_subscribe(session, &req)),
        methods::AUTHORIZE => Some(handle_authorize(pool, session, &req)),
        methods::SUBMIT    => Some(handle_submit(pool, session, &req).await),
        other => Some(StratumResponse::error(
            req.id,
            StratumError::new(ErrorCode::Other, format!("unknown method: {}", other)),
        )),
    }
}

/// mining.subscribe → [[["mining.notify", sid]], nonce_base_hex, 0,
/// challenge_hex]
///
/// `nonce_base_hex` replaces Bitcoin's extranonce: the coinbase is fixed
/// per job (it pays the pool address), so miners get disjoint 2^40-wide
/// u64 nonce ranges instead. The trailing 0 sits where V1 clients expect
/// extranonce2_size ("no extranonce bytes"). `challenge_hex` is the
/// fresh 32-byte server nonce the ownership proof signs (protocol.rs).
fn handle_subscribe(session: &Arc<Session>, req: &StratumRequest) -> StratumResponse {
    let mut st = session.state.lock();
    if *st != SessionState::Fresh {
        return StratumResponse::error(
            req.id.clone(), StratumError::new(ErrorCode::Other, "already subscribed"));
    }
    *st = SessionState::Subscribed;
    drop(st);

    let nonce_base_hex = format!("{:016x}", session.nonce_base);
    info!("stratum: session {} subscribed (nonce_base={})", session.id, nonce_base_hex);
    StratumResponse::ok(req.id.clone(), json!([
        [[methods::NOTIFY, format!("{:x}", session.id)]],
        nonce_base_hex,
        0u32,
        hex::encode(session.challenge),
    ]))
}

/// Domain separator for the address-ownership proof: the miner signs
/// `AUTH_DOMAIN ‖ challenge` so a pool can never trick a wallet into
/// signing something that means anything on-chain.
pub const AUTH_DOMAIN: &[u8] = b"bloch-pool-authorize-v1";

/// mining.authorize [address, password, pubkey_hex?, signature_hex?] —
/// the username must be a valid Bloch bech32 address (bloch1q… /
/// bloch1t…), same rule as the node. When the pool requires the
/// ownership proof (default), the connection must also present the
/// hybrid public key hashing to that address and its signature over
/// `AUTH_DOMAIN ‖ challenge` — shares/credit are refused for an address
/// the connection cannot prove it controls (a hostile pool-side miner
/// could otherwise farm credit to an address it does not own, or squat
/// someone else's). On success the current job is pushed immediately.
fn handle_authorize(
    pool:    &Arc<PoolState>,
    session: &Arc<Session>,
    req:     &StratumRequest,
) -> StratumResponse {
    if *session.state.lock() == SessionState::Fresh {
        return StratumResponse::error(
            req.id.clone(),
            StratumError::new(ErrorCode::NotSubscribed, "must subscribe before authorizing"));
    }

    let username = match req.params.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return StratumResponse::error(
            req.id.clone(),
            StratumError::new(ErrorCode::Unauthorized, "authorize requires [address, password]")),
    };

    let addr = match Address::parse(username) {
        Ok(a) => a,
        Err(e) => {
            warn!("stratum: session {} invalid address '{}': {}", session.id, username, e);
            return StratumResponse::error(
                req.id.clone(),
                StratumError::new(ErrorCode::Unauthorized, format!("invalid address: {}", e)));
        }
    };

    if pool.cfg.require_auth_proof {
        let params = req.params.as_array().cloned().unwrap_or_default();
        let pubkey = params.get(2).and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok());
        let sig = params.get(3).and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok());
        let (Some(pubkey), Some(sig)) = (pubkey, sig) else {
            return StratumResponse::error(
                req.id.clone(),
                StratumError::new(ErrorCode::Unauthorized,
                    "this pool requires an address-ownership proof: \
                     authorize params [address, password, pubkey_hex, signature_hex] \
                     (signature over \"bloch-pool-authorize-v1\" || subscribe challenge)"));
        };
        // The presented key must BE the address (SHA3-256 → 20 bytes)…
        if Address::from_pubkey(&pubkey, addr.network()).hash() != addr.hash() {
            warn!("stratum: session {} pubkey does not hash to {}", session.id, username);
            return StratumResponse::error(
                req.id.clone(),
                StratumError::new(ErrorCode::Unauthorized, "pubkey does not match address"));
        }
        // …and the connection must hold its secret half: hybrid
        // ML-DSA-65 ‖ Falcon-1024 verify (the consensus signature
        // scheme, reused verbatim from bloch-crypto).
        let mut msg = AUTH_DOMAIN.to_vec();
        msg.extend_from_slice(&session.challenge);
        if !bloch_crypto::crypto::verify(&pubkey, &msg, &sig) {
            warn!("stratum: session {} ownership proof failed for {}", session.id, username);
            return StratumResponse::error(
                req.id.clone(),
                StratumError::new(ErrorCode::Unauthorized, "ownership proof failed"));
        }
        info!("stratum: session {} proved ownership of {}", session.id, username);
    }

    *session.address.lock() = Some(username.to_string());
    *session.state.lock() = SessionState::Authorized;
    info!("stratum: session {} authorized {}", session.id, username);

    // Push share difficulty + current work so mining starts immediately
    // — unless the node has been unreachable so long the retained job
    // is a likely-dead tip; new miners then wait for fresh work rather
    // than burning cycles on it.
    let share_bits = pool.ledger.lock().share_bits;
    let _ = session.send_line(
        StratumNotification::new(methods::SET_DIFFICULTY, json!([share_bits])).to_line());
    if pool.template_fresh() {
        if let Some(job) = pool.current_job() {
            let _ = session.send_line(notify_line(&job, true));
        }
    } else {
        warn!("stratum: session {} authorized but node is unreachable — \
               withholding stale job until a fresh template arrives", session.id);
    }

    StratumResponse::ok(req.id.clone(), Value::from(true))
}

/// Render mining.notify for a job (see protocol.rs for the param spec).
pub fn notify_line(job: &Job, clean: bool) -> String {
    StratumNotification::new(methods::NOTIFY, json!([
        job.id,
        hex::encode(&job.preimage),
        format!("{:08x}", job.bits),
        job.height,
        clean,
    ])).to_line()
}

/// mining.submit [address, job_id, nonce_hex(16), solution_hex(512)]
async fn handle_submit(
    pool:    &Arc<PoolState>,
    session: &Arc<Session>,
    req:     &StratumRequest,
) -> StratumResponse {
    let id = req.id.clone();

    if !session.check_submit_rate() {
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "submit rate exceeded"));
    }
    if !session.is_authorized() {
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::Unauthorized, "unauthorized worker"));
    }

    // ── Parse params ──────────────────────────────────────────────
    let params = match req.params.as_array() {
        Some(a) if a.len() >= 4 => a,
        _ => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other,
                "submit requires [address, job_id, nonce_hex, solution_hex]")),
    };
    let job_id = params[1].as_str().unwrap_or_default().to_string();
    let nonce = match params[2].as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    {
        Some(n) => n,
        None => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "nonce must be hex u64")),
    };
    // Enforce the session's assigned 2^40 range — the disjointness the
    // subscribe response promises is real, not advisory (prevents
    // honest cross-session duplicate work AND cross-session replay),
    // and it is a near-free pre-filter ahead of the expensive verify.
    if nonce >> 40 != session.nonce_base >> 40 {
        return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "nonce outside session's assigned range"));
    }
    let solution_bytes = match params[3].as_str().and_then(|s| hex::decode(s).ok()) {
        Some(b) => b,
        None => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, "solution not valid hex")),
    };
    let solution = match bloch_sis_pow::encode::decode_s(&solution_bytes) {
        Ok(s) => s,
        Err(e) => return StratumResponse::error(id,
            StratumError::new(ErrorCode::Other, format!("solution decode: {:?}", e))),
    };

    // Shares are credited to the AUTHORIZED address, not the (unauthenticated)
    // param — the param is informational, mirroring Bitcoin stratum.
    let address = session.address.lock().clone().unwrap_or_default();

    // ── Job lookup ────────────────────────────────────────────────
    let job = match pool.find_job(&job_id) {
        Some(j) => j,
        None => {
            pool.ledger.lock().record_stale();
            return StratumResponse::error(id,
                StratumError::new(ErrorCode::JobNotFoundOrStale,
                    format!("job '{}' not in retention window", job_id)));
        }
    };

    // ── Verify the share (real consensus verifier, share target) ─
    // Norm bound + Module-SIS residual gate + SHAKE-256 aux-hash vs the
    // share target — identical code path to Block::validate_pow, softer
    // target. CPU cost is a k-row expansion; fine for a reference pool.
    let share_target = pool.share_target;
    let preimage = job.preimage.clone();
    // Consensus gate width: identical selection to the node's `validate_pow`
    // (`canonical_residual_coeffs(block.height, block.header.bits)` — the
    // difficulty-driven k-ramp), so a share that clears the BLOCK target is
    // one the node will accept on `submitblock`. Height and bits are the
    // JOB's (the block being mined), never the tip's.
    let residual_coeffs = bloch_crypto::core::canonical_residual_coeffs(job.height, job.bits);
    let verdict = tokio::task::spawn_blocking(move || {
        verify_regime(&preimage, nonce, &solution, &share_target, residual_coeffs)
            .map(|_| (compute_aux_hash(&preimage, nonce, &solution), solution))
    }).await.unwrap_or_else(|_| Err(VerifyError::SolutionTooLarge));

    let (aux, solution) = match verdict {
        Ok(pair) => pair,
        Err(VerifyError::AuxHashAboveTarget) => {
            return StratumResponse::error(id,
                StratumError::new(ErrorCode::LowDifficulty, "share above share-target"));
        }
        Err(e) => {
            return StratumResponse::error(id,
                StratumError::new(ErrorCode::Other, format!("invalid share: {:?}", e)));
        }
    };

    // ── Duplicate + accounting ────────────────────────────────────
    // The block case snapshots the PPLNS window in the SAME ledger
    // lock that admits the winning share: correct PPLNS pays the last
    // N shares as of the winning share, so shares landing during the
    // submit round-trip must neither join nor evict this split.
    let is_block = hash_meets_target(&aux, &job.block_target);
    let contribs = {
        let mut ledger = pool.ledger.lock();
        let mut aux8 = [0u8; 8];
        aux8.copy_from_slice(&aux[..8]);
        if !ledger.record_submission(&job.preimage, nonce, aux8) {
            return StratumResponse::error(id,
                StratumError::new(ErrorCode::DuplicateShare, "duplicate share"));
        }
        let weight = work_from_bits(ledger.share_bits);
        ledger.record_share(&address, weight, job.bits);
        if is_block { Some(ledger.window_contributions()) } else { None }
    };
    debug!("stratum: session {} share accepted (job={} nonce={:x} miner={})",
        session.id, job_id, nonce, address);

    // ── Block? Same aux hash against the BLOCK target ─────────────
    if let Some(contribs) = contribs {
        info!("stratum: session {} share MEETS BLOCK TARGET h={} — submitting to node",
            session.id, job.height);
        submit_found_block(pool.clone(), job, nonce, solution, address.clone(), contribs).await;
    }

    StratumResponse::ok(id, Value::from(true))
}

/// Assemble the full block for a block-target share and push it to the
/// node. On acceptance the block is recorded PENDING with the PPLNS
/// split snapshotted at the find (`contribs`); credits are booked only
/// when the confirmation loop (main.rs) sees it canonical at
/// `confirm_depth`, and dropped if it is orphaned instead.
async fn submit_found_block(
    pool:     Arc<PoolState>,
    job:      Arc<Job>,
    nonce:    u64,
    solution: [i32; 256],
    finder:   String,
    contribs: Vec<(String, u128)>,
) {
    let block = job.assemble(nonce, &solution);
    let wire_hex = hex::encode(block.to_bitcoin_bytes());

    let pool2 = pool.clone();
    let result = tokio::task::spawn_blocking(move || {
        pool2.upstream.submit_block(&wire_hex)
    }).await.unwrap_or_else(|e| Err(format!("join: {}", e)));

    match result {
        Ok(hash_hex) => {
            let payout = pool.ledger.lock().record_block_pending(
                job.height, hash_hex.clone(), job.reward_sat, &finder, &contribs);
            info!(
                "BLOCK FOUND h={} hash={} reward={} sat — PENDING, PPLNS split \
                 snapshotted for {} miners (pool take {} sat), found by {}; \
                 credits book at depth {}",
                job.height,
                &hash_hex[..hash_hex.len().min(16)],
                job.reward_sat,
                payout.miners.len(),
                payout.pool_take,
                finder,
                pool.cfg.confirm_depth,
            );
        }
        Err(reason) => {
            // The share still counted; only the block was rejected
            // (usually a race with another block at the same height).
            // Counted + journaled so miners can audit conversion.
            pool.ledger.lock().record_block_rejected();
            warn!("node rejected our block at h={}: {}", job.height, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The authorize ownership proof end to end: a wallet keypair signs
    /// the domain-separated challenge and the pool-side checks (pubkey
    /// hashes to the address; hybrid signature verifies) accept it —
    /// and reject a signature over a different challenge (replay).
    #[test]
    fn ownership_proof_roundtrip() {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair();
        let addr_str = bloch_crypto::crypto::address_from_pubkey(&pk, false);
        let addr = Address::parse(&addr_str).expect("derived address parses");
        assert_eq!(Address::from_pubkey(&pk, addr.network()).hash(), addr.hash(),
            "pubkey must hash to its own address");

        let challenge = [7u8; 32];
        let mut msg = AUTH_DOMAIN.to_vec();
        msg.extend_from_slice(&challenge);
        let sig = bloch_crypto::crypto::sign(&sk, &msg).expect("sign");
        assert!(bloch_crypto::crypto::verify(&pk, &msg, &sig));

        // A different session's challenge must not verify (no replay).
        let mut other = AUTH_DOMAIN.to_vec();
        other.extend_from_slice(&[8u8; 32]);
        assert!(!bloch_crypto::crypto::verify(&pk, &other, &sig));
    }

    // ── Framing: an over-long line must die DURING accumulation ──────────
    //
    // `Endless` is a slowloris in one struct: an infinite stream of 'x'
    // with no '\n', ever. Against `read_line` this test never returns (the
    // process ODs on memory instead); against `read_bounded_line` it must
    // error after having pulled at most one BufReader refill past the cap.

    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    struct Endless(Arc<AtomicUsize>);

    impl AsyncRead for Endless {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let n = buf.remaining().min(4096);
            buf.put_slice(&vec![b'x'; n]);
            self.0.fetch_add(n, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    /// A never-terminated line is rejected before the bytes are collected:
    /// the error arrives, and the total served stays within one refill of
    /// MAX_LINE_BYTES instead of growing without bound.
    #[tokio::test]
    async fn unterminated_line_is_refused_during_accumulation() {
        let served = Arc::new(AtomicUsize::new(0));
        let mut reader =
            BufReader::with_capacity(MAX_LINE_BYTES + 256, Endless(served.clone()));
        let mut buf = Vec::with_capacity(1024);

        let err = tokio::time::timeout(
            Duration::from_secs(5),
            read_bounded_line(&mut reader, &mut buf),
        )
        .await
        .expect("bounded reader must return, not spin forever")
        .expect_err("an unterminated over-long line is a protocol violation");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let n = served.load(Ordering::Relaxed);
        assert!(
            n <= 2 * (MAX_LINE_BYTES + 256),
            "read {n} bytes for a {MAX_LINE_BYTES}-byte cap — not bounded"
        );
        assert!(buf.len() <= MAX_LINE_BYTES + 256 + 4096, "buffer grew past the cap");
    }

    /// A terminated line longer than the cap is refused too — the newline
    /// arriving does not buy the peer an unbounded line.
    #[tokio::test]
    async fn over_long_terminated_line_is_refused() {
        let mut src = vec![b'y'; MAX_LINE_BYTES + 1];
        src.push(b'\n');
        let mut reader = BufReader::with_capacity(MAX_LINE_BYTES + 256, &src[..]);
        let mut buf = Vec::new();
        let err = read_bounded_line(&mut reader, &mut buf).await.expect_err("over cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// And the happy path still frames normally: one line at a time, the
    /// trailing newline kept (dispatch trims it via serde/`parse`).
    #[tokio::test]
    async fn in_bound_lines_frame_one_at_a_time() {
        let src: &[u8] = b"{\"id\":1}\n{\"id\":2}\n";
        let mut reader = BufReader::new(src);
        let mut buf = Vec::new();

        let n = read_bounded_line(&mut reader, &mut buf).await.expect("first line");
        assert_eq!(n, 9);
        assert_eq!(&buf, b"{\"id\":1}\n");

        buf.clear();
        read_bounded_line(&mut reader, &mut buf).await.expect("second line");
        assert_eq!(&buf, b"{\"id\":2}\n");

        buf.clear();
        assert_eq!(read_bounded_line(&mut reader, &mut buf).await.expect("eof"), 0);
    }
}
