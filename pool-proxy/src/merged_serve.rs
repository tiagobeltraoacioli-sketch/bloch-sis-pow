//! Merged-mining Stratum SERVER handler — the socket wire that turns the
//! [`crate::merged_engine`] into a live service. Unlike the transparent-proxy
//! path (which forwards the node's jobs), a merged worker is served jobs the
//! proxy GENERATES from the two chains' templates, and its shares are checked
//! against BOTH targets.
//!
//! The protocol brain is [`MergedWorker`] — a PURE state machine over incoming
//! Stratum lines (subscribe / authorize / submit) that never does I/O, so it is
//! unit tested. [`serve_merged`] is the thin async loop: it owns the round
//! lifecycle (periodic [`create_round`] → set_difficulty + notify) and executes
//! the win a submit decides ([`submit_win`]).

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::codec::LineReader;
use crate::merged_engine::{create_round, decide_submit, submit_win, MergedConfig, SubmitAction};
use crate::mergedmining::{classify_merged_share, merged_job_to_notify, MergedJob};
use crate::rpc::{AuxBlockInfo, RpcClient};
use crate::btc_rpc::BtcRpcClient;
use crate::types::{Line, PoolError};
use crate::validator::difficulty_to_target;

/// Extranonce1 assigned to a merged worker (4 bytes), plus a 4-byte extranonce2
/// the miner rolls — 8 bytes total, matching the `extranonce_len` the round's
/// coinbase reserved (see [`crate::merged_engine::btc_coinbase_parts`]).
const EN1_LEN: usize = 4;
const EN2_SIZE: usize = 4;

/// Idle ceiling for one merged worker. Jobs are PUSHED to the miner, so a
/// socket that says nothing for this long is not waiting on us — it is a
/// parked fd. Matches the pool's `IDLE_TIMEOUT_SECS`.
const READ_IDLE_SECS: u64 = 600;

/// What a handled Stratum line asks the socket loop to do.
#[derive(Debug)]
pub enum WorkerReaction {
    /// Write these line(s) back to the miner.
    Send(Vec<String>),
    /// A winning share: write `reply`, then submit the AuxPoW for `aux_hash`.
    Win { reply: String, aux_hash: [u8; 32], action: SubmitAction },
    /// Nothing to do (unparseable / unknown method).
    None,
}

/// Pure Stratum-server state machine for one merged worker.
pub struct MergedWorker {
    extranonce1_hex: String,
    share_diff: f64,
    worker_target: [u8; 32],
    authorized: bool,
    round: Option<MergedJob>,
    aux_hash: Option<[u8; 32]>,
}

impl MergedWorker {
    pub fn new(extranonce1: [u8; EN1_LEN], share_diff: f64) -> Self {
        Self {
            extranonce1_hex: hex::encode(extranonce1),
            share_diff,
            worker_target: difficulty_to_target(share_diff),
            authorized: false,
            round: None,
            aux_hash: None,
        }
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
    pub fn has_round(&self) -> bool {
        self.round.is_some()
    }
    /// Total extranonce length (en1 + en2) the round's coinbase must reserve.
    pub fn extranonce_total_len() -> usize {
        EN1_LEN + EN2_SIZE
    }

    /// Install a fresh round (from [`create_round`]); the loop then serves
    /// [`Self::set_difficulty_line`] + [`Self::notify_line`].
    pub fn set_round(&mut self, aux: &AuxBlockInfo, job: MergedJob) {
        self.aux_hash = Some(aux.hash);
        self.round = Some(job);
    }

    /// `mining.set_difficulty` for this worker's share difficulty.
    pub fn set_difficulty_line(&self) -> String {
        format!(
            r#"{{"id":null,"method":"mining.set_difficulty","params":[{}]}}"#,
            self.share_diff
        )
    }

    /// `mining.notify` for the current round, or `None` if no round yet.
    pub fn notify_line(&self, clean_jobs: bool) -> Option<String> {
        self.round.as_ref().map(|j| merged_job_to_notify(j, clean_jobs))
    }

    /// Handle one incoming Stratum request line.
    pub fn handle_line(&mut self, raw: &str) -> WorkerReaction {
        let v: Value = match serde_json::from_str(raw.trim()) {
            Ok(v) => v,
            Err(_) => return WorkerReaction::None,
        };
        let id = v.get("id").cloned().unwrap_or(Value::Null);
        let method = v.get("method").and_then(Value::as_str).unwrap_or("");
        let params = v.get("params").and_then(Value::as_array).cloned().unwrap_or_default();

        match method {
            "mining.subscribe" => WorkerReaction::Send(vec![self.subscribe_reply(&id)]),
            "mining.authorize" => {
                // H-3 fix (audit finding): this used to accept ANY username
                // unconditionally. `addr::parse_worker_username` documents
                // its own contract — "the caller must then refuse
                // mining.authorize ... rather than serve jobs whose reward
                // has no owner" — but nothing here ever called it. Wiring the
                // full non-custodial payout redirect into the round builder
                // (L-10) is a separate, larger change; this fix closes the
                // narrower, concrete gap: an authorize with no parseable
                // `bloch1…` address is refused rather than silently accepted.
                let username = params.first().and_then(Value::as_str).unwrap_or("");
                match crate::addr::parse_worker_username(username) {
                    Some(_payout) => {
                        self.authorized = true;
                        WorkerReaction::Send(vec![ok_true(&id)])
                    }
                    None => WorkerReaction::Send(vec![err(
                        &id,
                        24,
                        "authorize requires a bloch1... payout address in the username",
                    )]),
                }
            }
            "mining.submit" => self.handle_submit(&id, &params),
            // Version-rolling negotiation: accept a permissive mask so ASICs proceed.
            "mining.configure" => WorkerReaction::Send(vec![format!(
                r#"{{"id":{},"result":{{"version-rolling":true,"version-rolling.mask":"1fffe000"}},"error":null}}"#,
                id
            )]),
            _ => WorkerReaction::Send(vec![ok_true(&id)]),
        }
    }

    fn subscribe_reply(&self, id: &Value) -> String {
        // [[["mining.set_difficulty",en1],["mining.notify",en1]], en1, en2_size]
        format!(
            r#"{{"id":{id},"result":[[["mining.set_difficulty","{en1}"],["mining.notify","{en1}"]],"{en1}",{en2}],"error":null}}"#,
            id = id,
            en1 = self.extranonce1_hex,
            en2 = EN2_SIZE,
        )
    }

    fn handle_submit(&mut self, id: &Value, params: &[Value]) -> WorkerReaction {
        if !self.authorized {
            return WorkerReaction::Send(vec![err(id, 24, "unauthorized worker")]);
        }
        let job = match &self.round {
            Some(j) => j,
            None => return WorkerReaction::Send(vec![err(id, 21, "no current job")]),
        };
        // params: [worker, job_id, extranonce2, ntime, nonce, (version?)]
        let get = |i: usize| params.get(i).and_then(Value::as_str).unwrap_or("");
        let en2 = get(2);
        let ntime = get(3);
        let nonce = get(4);

        // L-11 fix (audit finding): `classify_merged_share` splices `en1 ‖ en2`
        // into the coinbase with no length check against the extranonce size
        // the round's coinbase scriptSig actually reserved
        // (`MergedWorker::extranonce_total_len()`, see `btc_coinbase_parts`). A
        // short or long `en2` yields a structurally invalid coinbase that the
        // proxy would still hash and, on a lucky target hit, submit to the
        // node and to `bitcoind`. `self.extranonce1_hex` is always exactly
        // `EN1_LEN` bytes (derived from `worker_id`, never attacker input), so
        // only `en2` needs checking here.
        match hex::decode(en2) {
            Ok(b) if b.len() == EN2_SIZE => {}
            _ => {
                return WorkerReaction::Send(vec![err(
                    id,
                    20,
                    &format!("bad submit: extranonce2 must be exactly {EN2_SIZE} bytes"),
                )])
            }
        }
        let version = params
            .get(5)
            .and_then(Value::as_str)
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok());

        let c = match classify_merged_share(
            job,
            &self.extranonce1_hex,
            en2,
            ntime,
            nonce,
            version,
            &self.worker_target,
        ) {
            Ok(c) => c,
            Err(e) => return WorkerReaction::Send(vec![err(id, 20, &format!("bad submit: {e}"))]),
        };

        let action = decide_submit(&c);
        match &action {
            SubmitAction::Nothing => WorkerReaction::Send(vec![err(id, 23, "share above target")]),
            SubmitAction::Share => WorkerReaction::Send(vec![ok_true(id)]),
            SubmitAction::Bloch { .. } | SubmitAction::BtcAndBloch { .. } => WorkerReaction::Win {
                reply: ok_true(id),
                aux_hash: self.aux_hash.unwrap_or([0u8; 32]),
                action,
            },
        }
    }
}

fn ok_true(id: &Value) -> String {
    format!(r#"{{"id":{id},"result":true,"error":null}}"#)
}

/// H-3 fix (audit finding): `msg` used to be spliced into the JSON literal
/// verbatim (`"{msg}"`), and `msg` can carry client-controlled content (e.g.
/// `format!("bad submit: {e}")` where `e` is derived from attacker-supplied
/// hex/JSON). A `"` or embedded newline in that path produced malformed or
/// split output. `serde_json::Value::String`'s own `Display` escapes the
/// string exactly per JSON's grammar, so this is correct for any `msg`.
fn err(id: &Value, code: i64, msg: &str) -> String {
    format!(
        r#"{{"id":{id},"result":null,"error":[{code},{msg_json},null]}}"#,
        msg_json = Value::String(msg.to_string())
    )
}

/// The live async loop: serve one merged worker over `stream`. Owns the round
/// lifecycle (an initial round once authorized, refreshed on `refresh`) and
/// executes wins via [`submit_win`]. `worker_id` seeds the 4-byte extranonce1.
pub async fn serve_merged(
    stream: TcpStream,
    worker_id: u64,
    node: RpcClient,
    btc: BtcRpcClient,
    cfg: MergedConfig,
    share_diff: f64,
    refresh: Duration,
    cache: std::sync::Arc<crate::merged_engine::TemplateCache>,
) -> Result<(), PoolError> {
    let _ = stream.set_nodelay(true);
    let (rd, mut wr) = stream.into_split();
    // Bounded framing: `LineReader` enforces MAX_LINE_BYTES DURING
    // accumulation, so a worker that never sends '\n' cannot make us buffer
    // gigabytes (plain `read_line` returns only on '\n' or EOF).
    let mut reader = LineReader::new(BufReader::new(rd));
    let mut worker = MergedWorker::new((worker_id as u32).to_be_bytes(), share_diff);
    let mut round_ctr: u64 = 0;
    let mut ticker = tokio::time::interval(refresh);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut idle_deadline = tokio::time::Instant::now() + Duration::from_secs(READ_IDLE_SECS);
    loop {
        tokio::select! {
            // Refresh the round (new BTC template + Bloch candidate) and re-notify.
            _ = ticker.tick() => {
                if worker.is_authorized() {
                    if let Err(e) = start_round(&node, &btc, &cfg, &cache, refresh, &mut worker, &mut wr, &mut round_ctr).await {
                        log::warn!("merged: round refresh failed: {e}");
                    }
                }
            }
            // `next_line` is cancel-safe: a partial line survives losing
            // this select arm to the ticker above.
            r = read_worker_line(&mut reader, idle_deadline) => {
                let line = match r? {
                    Some(l) => l,
                    None    => break, // peer closed
                };
                idle_deadline = tokio::time::Instant::now() + Duration::from_secs(READ_IDLE_SECS);
                match worker.handle_line(&line) {
                    WorkerReaction::Send(lines) => {
                        for l in &lines { send_line(&mut wr, l).await?; }
                        // Kick the first round right after authorize.
                        if worker.is_authorized() && !worker.has_round() {
                            if let Err(e) = start_round(&node, &btc, &cfg, &cache, refresh, &mut worker, &mut wr, &mut round_ctr).await {
                                log::warn!("merged: initial round failed: {e}");
                            }
                        }
                    }
                    WorkerReaction::Win { reply, aux_hash, action } => {
                        send_line(&mut wr, &reply).await?;
                        match submit_win(&node, &btc, &aux_hash, &action).await {
                            Ok(Some(h)) => log::info!("merged: BLOCH BLOCK accepted by node: {h}"),
                            Ok(None)    => {}
                            Err(e)      => log::warn!("merged: submit_win failed: {e}"),
                        }
                    }
                    WorkerReaction::None => {}
                }
            }
        }
    }
    Ok(())
}

/// One bounded, deadline-capped read from a merged worker.
///
/// Both failure modes close the session, and both close it EARLY: an
/// over-long line is refused by [`LineReader`] the moment it crosses
/// `MAX_LINE_BYTES` — before the bytes are ever collected into a line —
/// and a peer silent past `deadline` is dropped instead of parked forever.
async fn read_worker_line<R: AsyncBufRead + Unpin>(
    reader: &mut LineReader<R>,
    deadline: tokio::time::Instant,
) -> Result<Option<Line>, PoolError> {
    match tokio::time::timeout_at(deadline, reader.next_line()).await {
        Ok(r)  => r,
        Err(_) => Err(PoolError::Protocol(format!(
            "merged worker idle for {READ_IDLE_SECS}s"
        ))),
    }
}

/// Pull a fresh round and serve set_difficulty + notify(clean).
async fn start_round(
    node: &RpcClient,
    btc: &BtcRpcClient,
    cfg: &MergedConfig,
    cache: &crate::merged_engine::TemplateCache,
    ttl: Duration,
    worker: &mut MergedWorker,
    wr: &mut (impl AsyncWriteExt + Unpin),
    round_ctr: &mut u64,
) -> Result<(), PoolError> {
    *round_ctr += 1;
    let job_id = format!("m{round_ctr:x}");
    let (aux, job) =
        create_round(node, btc, cfg, cache, ttl, job_id, MergedWorker::extranonce_total_len()).await?;
    worker.set_round(&aux, job);
    send_line(wr, &worker.set_difficulty_line()).await?;
    if let Some(n) = worker.notify_line(true) {
        send_line(wr, &n).await?;
    }
    Ok(())
}

async fn send_line(wr: &mut (impl AsyncWriteExt + Unpin), s: &str) -> Result<(), PoolError> {
    wr.write_all(s.as_bytes()).await.map_err(PoolError::Io)?;
    wr.write_all(b"\n").await.map_err(PoolError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merged_engine::build_round_job;
    use crate::rpc::AuxBlockInfo;

    fn worker_with_round(bloch_bits: u32, btc_bits: u32, diff: f64) -> MergedWorker {
        let mut w = MergedWorker::new([0, 0, 0, 1], diff);
        let aux = AuxBlockInfo { hash: [0x9A; 32], bits: bloch_bits, height: 5_600, active: true };
        let tmpl = crate::btc_rpc::BtcTemplate {
            previous_block_hash: [0x33; 32],
            version: 0x2000_0000,
            bits: btc_bits,
            cur_time: 1_700_000_000,
            height: 5_600,
            coinbase_value: 625_000_000,
            transactions: vec![],
            default_witness_commitment: None,
        };
        let job = build_round_job("m1".into(), &aux, &tmpl, &[0x51], b"tag", MergedWorker::extranonce_total_len());
        w.authorized = true;
        w.set_round(&aux, job);
        w
    }

    #[test]
    fn subscribe_advertises_extranonce() {
        let mut w = MergedWorker::new([0xde, 0xad, 0xbe, 0xef], 1.0);
        let r = w.handle_line(r#"{"id":1,"method":"mining.subscribe","params":["cpuminer"]}"#);
        match r {
            WorkerReaction::Send(lines) => {
                assert!(lines[0].contains("deadbeef"), "advertises extranonce1");
                assert!(lines[0].contains(",4]"), "advertises extranonce2 size 4");
            }
            _ => panic!("subscribe must Send"),
        }
    }

    #[test]
    fn authorize_marks_authorized_and_replies_true() {
        let mut w = MergedWorker::new([0; 4], 1.0);
        assert!(!w.is_authorized());
        let r = w.handle_line(
            r#"{"id":2,"method":"mining.authorize","params":["bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073","x"]}"#,
        );
        assert!(matches!(r, WorkerReaction::Send(l) if l[0].contains("\"result\":true")));
        assert!(w.is_authorized());
    }

    /// H-3 regression: red before the fix (`mining.authorize` accepted ANY
    /// username unconditionally), green after (a username with no parseable
    /// `bloch1…` payout address is refused, `is_authorized()` stays false).
    #[test]
    fn authorize_without_a_bloch_address_is_refused() {
        for bad_user in ["addr", "x", "", "bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk"] {
            let mut w = MergedWorker::new([0; 4], 1.0);
            let line = format!(r#"{{"id":2,"method":"mining.authorize","params":["{bad_user}"]}}"#);
            let r = w.handle_line(&line);
            assert!(
                matches!(&r, WorkerReaction::Send(l) if l[0].contains("\"result\":null")),
                "username {bad_user:?} without a bloch1 address must be refused, got {r:?}"
            );
            assert!(!w.is_authorized(), "must NOT be authorized for {bad_user:?}");
        }
    }

    #[test]
    fn submit_before_authorize_errors() {
        let mut w = MergedWorker::new([0; 4], 1.0);
        let r = w.handle_line(r#"{"id":3,"method":"mining.submit","params":["a","m1","00000000","66000000","00000000"]}"#);
        assert!(matches!(r, WorkerReaction::Send(l) if l[0].contains("unauthorized")));
    }

    #[test]
    fn submit_with_loose_bloch_target_is_a_win() {
        // Loose Bloch, impossible BTC → a Bloch-target win carrying an AuxPoW.
        let mut w = worker_with_round(0x20ff_ffff, 0x0300_0001, 1e-9);
        let r = w.handle_line(
            r#"{"id":7,"method":"mining.submit","params":["a","m1","deadbeef","66000000","00000000"]}"#,
        );
        match r {
            WorkerReaction::Win { reply, aux_hash, action } => {
                assert!(reply.contains("\"result\":true"));
                assert_eq!(aux_hash, [0x9A; 32]);
                assert!(matches!(action, SubmitAction::Bloch { .. } | SubmitAction::BtcAndBloch { .. }));
            }
            other => panic!("expected Win, got {other:?}"),
        }
    }

    #[test]
    fn submit_below_worker_target_is_rejected() {
        // Impossible everything (worker target 0 is unmeetable) → error, no win.
        let mut w = worker_with_round(0x0300_0001, 0x0300_0001, f64::MAX);
        // en2 is exactly EN2_SIZE (4) bytes so this exercises the target check,
        // not the L-11 extranonce2-length guard (covered separately below).
        let r = w.handle_line(
            r#"{"id":9,"method":"mining.submit","params":["a","m1","00000000","66000000","00000000"]}"#,
        );
        assert!(matches!(r, WorkerReaction::Send(l) if l[0].contains("above target")));
    }

    /// L-11 regression: red before the fix (a short/long/non-hex extranonce2
    /// reached `classify_merged_share`, which spliced it straight into the
    /// coinbase with no length check against what the round's coinbase
    /// scriptSig actually reserved), green after (rejected with a clear
    /// error before the coinbase is ever built).
    #[test]
    fn submit_with_wrong_length_extranonce2_is_rejected() {
        for bad_en2 in ["00", "0011223344", "not-hex", ""] {
            let mut w = worker_with_round(0x20ff_ffff, 0x0300_0001, 1e-9);
            let line = format!(
                r#"{{"id":9,"method":"mining.submit","params":["a","m1","{bad_en2}","66000000","00000000"]}}"#
            );
            let r = w.handle_line(&line);
            assert!(
                matches!(&r, WorkerReaction::Send(l) if l[0].contains("extranonce2")),
                "extranonce2={bad_en2:?} must be rejected with a length error, got {r:?}"
            );
        }
    }

    // ── Framing: the socket loop's read is bounded and deadlined ─────────
    //
    // `Endless` is a slowloris in one struct: an infinite stream of 'x'
    // with no '\n', ever. The old loop (`BufReader::read_line`) would grow
    // a String until the box died; `read_worker_line` must error after at
    // most one refill past MAX_LINE_BYTES.

    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
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

    /// Never-terminated line: refused before the bytes are collected, with
    /// the total pulled off the socket bounded by the cap.
    #[tokio::test]
    async fn worker_line_is_refused_during_accumulation() {
        let served = Arc::new(AtomicUsize::new(0));
        let mut reader = LineReader::new(BufReader::new(Endless(served.clone())));
        let far = tokio::time::Instant::now() + Duration::from_secs(600);

        let err = tokio::time::timeout(
            Duration::from_secs(5),
            read_worker_line(&mut reader, far),
        )
        .await
        .expect("bounded read must return, not spin forever")
        .expect_err("an unterminated over-long line is a protocol violation");
        assert!(matches!(err, crate::types::PoolError::Protocol(_)), "got {err:?}");

        let n = served.load(Ordering::Relaxed);
        assert!(
            n <= 2 * (crate::types::MAX_LINE_BYTES + 8192),
            "read {n} bytes for a {}-byte cap — not bounded",
            crate::types::MAX_LINE_BYTES
        );
    }

    /// A silent (never-readable) peer is dropped at the deadline instead of
    /// holding the fd forever.
    #[tokio::test]
    async fn silent_worker_hits_the_read_deadline() {
        struct Silent;
        impl AsyncRead for Silent {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }
        let mut reader = LineReader::new(BufReader::new(Silent));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let err = read_worker_line(&mut reader, deadline)
            .await
            .expect_err("a silent peer must time out");
        assert!(matches!(err, crate::types::PoolError::Protocol(_)), "got {err:?}");
    }

    /// The happy path still frames one stratum line at a time, EOF included.
    #[tokio::test]
    async fn worker_lines_frame_one_at_a_time() {
        let src: &[u8] = b"{\"id\":1}\n{\"id\":2}\n";
        let mut reader = LineReader::new(BufReader::new(src));
        let far = tokio::time::Instant::now() + Duration::from_secs(600);
        assert_eq!(read_worker_line(&mut reader, far).await.unwrap().as_deref(), Some("{\"id\":1}\n"));
        assert_eq!(read_worker_line(&mut reader, far).await.unwrap().as_deref(), Some("{\"id\":2}\n"));
        assert_eq!(read_worker_line(&mut reader, far).await.unwrap(), None);
    }
}
