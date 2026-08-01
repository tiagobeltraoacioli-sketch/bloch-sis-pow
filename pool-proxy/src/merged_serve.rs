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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::merged_engine::{create_round, decide_submit, submit_win, MergedConfig, SubmitAction};
use crate::mergedmining::{classify_merged_share, merged_job_to_notify, MergedJob};
use crate::rpc::{AuxBlockInfo, RpcClient};
use crate::btc_rpc::BtcRpcClient;
use crate::types::PoolError;
use crate::validator::difficulty_to_target;

/// Extranonce1 assigned to a merged worker (4 bytes), plus a 4-byte extranonce2
/// the miner rolls — 8 bytes total, matching the `extranonce_len` the round's
/// coinbase reserved (see [`crate::merged_engine::btc_coinbase_parts`]).
const EN1_LEN: usize = 4;
const EN2_SIZE: usize = 4;

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
                self.authorized = true; // solo/merged: node owns payout addr, any worker ok
                WorkerReaction::Send(vec![ok_true(&id)])
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

fn err(id: &Value, code: i64, msg: &str) -> String {
    format!(r#"{{"id":{id},"result":null,"error":[{code},"{msg}",null]}}"#)
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
) -> Result<(), PoolError> {
    let _ = stream.set_nodelay(true);
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut worker = MergedWorker::new((worker_id as u32).to_be_bytes(), share_diff);
    let mut round_ctr: u64 = 0;
    let mut ticker = tokio::time::interval(refresh);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut line = String::new();
    loop {
        tokio::select! {
            // Refresh the round (new BTC template + Bloch candidate) and re-notify.
            _ = ticker.tick() => {
                if worker.is_authorized() {
                    if let Err(e) = start_round(&node, &btc, &cfg, &mut worker, &mut wr, &mut round_ctr).await {
                        log::warn!("merged: round refresh failed: {e}");
                    }
                }
            }
            r = reader.read_line(&mut line) => {
                let n = r.map_err(PoolError::Io)?;
                if n == 0 { break; } // peer closed
                match worker.handle_line(&line) {
                    WorkerReaction::Send(lines) => {
                        for l in &lines { send_line(&mut wr, l).await?; }
                        // Kick the first round right after authorize.
                        if worker.is_authorized() && !worker.has_round() {
                            if let Err(e) = start_round(&node, &btc, &cfg, &mut worker, &mut wr, &mut round_ctr).await {
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
                line.clear();
            }
        }
    }
    Ok(())
}

/// Pull a fresh round and serve set_difficulty + notify(clean).
async fn start_round(
    node: &RpcClient,
    btc: &BtcRpcClient,
    cfg: &MergedConfig,
    worker: &mut MergedWorker,
    wr: &mut (impl AsyncWriteExt + Unpin),
    round_ctr: &mut u64,
) -> Result<(), PoolError> {
    *round_ctr += 1;
    let job_id = format!("m{round_ctr:x}");
    let (aux, job) =
        create_round(node, btc, cfg, job_id, MergedWorker::extranonce_total_len()).await?;
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
        let r = w.handle_line(r#"{"id":2,"method":"mining.authorize","params":["addr","x"]}"#);
        assert!(matches!(r, WorkerReaction::Send(l) if l[0].contains("\"result\":true")));
        assert!(w.is_authorized());
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
        let r = w.handle_line(
            r#"{"id":9,"method":"mining.submit","params":["a","m1","00","66000000","00000000"]}"#,
        );
        assert!(matches!(r, WorkerReaction::Send(l) if l[0].contains("above target")));
    }
}
