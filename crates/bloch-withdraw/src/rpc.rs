// SPDX-License-Identifier: AGPL-3.0-or-later

//! The node boundary: one trait, one blocking HTTP client, typed reads.
//!
//! ## Read from a node you validate yourself
//!
//! Every method here answers from ONE node's committed state. The public RPC
//! may be a pool of nodes on different branches, and two consecutive calls
//! answered by two branches will disagree about balances, spentness, and
//! finality. The whole crediting model of this crate ("the pinned inputs are
//! spent in finalized history") is a statement about a single validated
//! node's view — so point [`HttpNode`] at a node you run, or at an endpoint
//! that is one node, not a load balancer.
//!
//! ## Error taxonomy, mirrored from the node
//!
//! The Genesis-4 RPC promises one cause per error code
//! (`bloch-pos-node/src/rpc.rs`). This module keeps the codes a withdrawal
//! client must branch on as named constants and folds each into
//! [`SubmitOutcome`], so the state machine never parses English.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::json::Json;

/// The node's error codes this client branches on. Values are the node's
/// (`bloch-pos-node/src/rpc.rs`); the node's table is the authority.
pub const TX_DECODE_FAILED: i64 = -32002;
pub const MEMPOOL_FULL: i64 = -32003;
pub const NODE_UNAVAILABLE: i64 = -32004;
pub const TX_REFUSED: i64 = -32008;

/// Why a call produced no usable result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcFailure {
    /// Could not reach the node, or its reply was not a JSON-RPC response.
    /// Says nothing about the chain; retry against a healthy node.
    Transport(String),
    /// The node answered with a JSON-RPC error object.
    Rpc { code: i64, message: String },
}

impl std::fmt::Display for RpcFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcFailure::Transport(m) => write!(f, "transport: {m}"),
            RpcFailure::Rpc { code, message } => write!(f, "rpc {code}: {message}"),
        }
    }
}

/// Whatever can answer a Genesis-4 JSON-RPC call. Production is [`HttpNode`];
/// tests inject an in-process fake chain, which is what lets the double-spend
/// race be exercised deterministically.
pub trait Node {
    fn call(&self, method: &str, params: Json) -> Result<Json, RpcFailure>;
}

// ─── The blocking HTTP/1.1 client ───────────────────────────────────────────

/// `std::net` client for the node's HTTP/1.1 JSON-RPC endpoint.
///
/// Matches the server it talks to (`bloch-pos-node/src/rpc.rs`): POST with
/// `Content-Length`, no keep-alive, no TLS, no compression. One TCP
/// connection per call — the server closes after answering, so pooling would
/// buy nothing.
pub struct HttpNode {
    /// `host:port`. Accepts an `http://` prefix and strips it.
    addr: String,
    timeout: Duration,
}

impl HttpNode {
    pub fn new(addr: &str) -> Self {
        let addr = addr
            .trim()
            .strip_prefix("http://")
            .unwrap_or(addr.trim())
            .trim_end_matches('/')
            .to_string();
        HttpNode { addr, timeout: Duration::from_secs(30) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl Node for HttpNode {
    fn call(&self, method: &str, params: Json) -> Result<Json, RpcFailure> {
        let body = Json::Obj(vec![
            ("jsonrpc".into(), Json::s("2.0")),
            ("id".into(), Json::u(1)),
            ("method".into(), Json::s(method)),
            ("params".into(), params),
        ])
        .to_json();

        let t = |e: std::io::Error| RpcFailure::Transport(format!("{}: {e}", self.addr));
        let mut stream = TcpStream::connect(&self.addr).map_err(t)?;
        stream.set_read_timeout(Some(self.timeout)).map_err(t)?;
        stream.set_write_timeout(Some(self.timeout)).map_err(t)?;

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.addr,
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).map_err(t)?;

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(t)?;

        parse_http_response(&raw).and_then(|body| parse_envelope(&body))
    }
}

/// Split an HTTP/1.1 response into its body. Honors `Content-Length` when
/// present; otherwise takes everything to EOF (the server closes per request).
fn parse_http_response(raw: &[u8]) -> Result<String, RpcFailure> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| RpcFailure::Transport("no HTTP header terminator".into()))?;
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = head.lines();
    let status = lines.next().unwrap_or("");
    // JSON-RPC errors ride on 200; anything else is transport-level. 503 is
    // the node's own "at capacity, retry" answer and is reported as such.
    if !status.contains("200") {
        return Err(RpcFailure::Transport(format!("HTTP status: {status}")));
    }
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            }
        }
    }
    let body = &raw[header_end + 4..];
    let body = match content_length {
        Some(n) if n <= body.len() => &body[..n],
        Some(n) => {
            return Err(RpcFailure::Transport(format!(
                "truncated body: Content-Length {n}, got {}",
                body.len()
            )))
        }
        None => body,
    };
    String::from_utf8(body.to_vec())
        .map_err(|_| RpcFailure::Transport("response body is not UTF-8".into()))
}

/// Unpack the JSON-RPC 2.0 envelope: `result` or the `error` object.
fn parse_envelope(body: &str) -> Result<Json, RpcFailure> {
    let v = Json::parse(body)
        .map_err(|e| RpcFailure::Transport(format!("response is not JSON: {e}")))?;
    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(Json::as_i64).unwrap_or(0);
        let message =
            err.get("message").and_then(Json::as_str).unwrap_or("(no message)").to_string();
        return Err(RpcFailure::Rpc { code, message });
    }
    match v.get("result") {
        Some(result) => Ok(result.clone()),
        None => Err(RpcFailure::Transport("response has neither result nor error".into())),
    }
}

// ─── Typed reads ────────────────────────────────────────────────────────────

/// The `getchaininfo` fields this client acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInfo {
    pub slot: u64,
    pub epoch: u64,
    pub height: u64,
    pub finalized_height: Option<u64>,
    /// The finalized checkpoint's epoch — the line below which history is
    /// settled. [`ChainInfo::finalized_boundary_slot`] turns it into a slot.
    pub finalized_epoch: u64,
    /// The price THIS block was charged at (msat/gas).
    pub base_fee_msat_per_gas: u128,
    /// The price the NEXT block will charge — the one a transaction built
    /// now must commit to.
    pub next_base_fee_msat_per_gas: u128,
    /// Wall-clock slot minus head slot: this node's own staleness statement.
    pub behind_by_slots: u64,
}

impl ChainInfo {
    /// First slot of the finalized checkpoint's epoch. A block observed in
    /// committed state at `at_slot` is inside finalized history once
    /// `finalized_boundary_slot() > at_slot` — conservative by up to one
    /// epoch, never optimistic.
    pub fn finalized_boundary_slot(&self) -> u64 {
        self.finalized_epoch.saturating_mul(bloch_pos_committee::params::SLOTS_PER_EPOCH)
    }
}

fn want_u64(v: &Json, key: &str) -> Result<u64, RpcFailure> {
    v.get(key)
        .and_then(Json::as_u64)
        .ok_or_else(|| RpcFailure::Transport(format!("`{key}` missing or not a u64")))
}

fn want_sat_u128(v: &Json, key: &str) -> Result<u128, RpcFailure> {
    v.get(key)
        .and_then(Json::as_sat_u128)
        .ok_or_else(|| RpcFailure::Transport(format!("`{key}` missing or not an amount")))
}

fn want_hex32(v: &Json, key: &str) -> Result<[u8; 32], RpcFailure> {
    let s = v
        .get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| RpcFailure::Transport(format!("`{key}` missing or not a string")))?;
    crate::hex32(s).ok_or_else(|| RpcFailure::Transport(format!("`{key}` is not 32 bytes of hex")))
}

pub fn chain_info(node: &dyn Node) -> Result<ChainInfo, RpcFailure> {
    let v = node.call("getchaininfo", Json::Arr(vec![]))?;
    let finalized = v
        .get("finalized")
        .ok_or_else(|| RpcFailure::Transport("`finalized` missing".into()))?;
    Ok(ChainInfo {
        slot: want_u64(&v, "slot")?,
        epoch: want_u64(&v, "epoch")?,
        height: want_u64(&v, "height")?,
        finalized_height: v.get("finalized_height").and_then(Json::as_u64),
        finalized_epoch: want_u64(finalized, "epoch")?,
        base_fee_msat_per_gas: want_sat_u128(&v, "base_fee_millisat_per_gas")?,
        next_base_fee_msat_per_gas: want_sat_u128(&v, "next_base_fee_millisat_per_gas")?,
        behind_by_slots: want_u64(&v, "behind_by_slots")?,
    })
}

/// One outpoint's spentness, per `gettxout`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutStatus {
    pub unspent: bool,
    pub value_sat: Option<u64>,
    /// The head slot this answer was computed at — what pins the observation
    /// to a point on the chain instead of to a wall clock.
    pub at_slot: u64,
}

pub fn get_txout(node: &dyn Node, txid: &[u8; 32], vout: u32) -> Result<TxOutStatus, RpcFailure> {
    let v = node.call(
        "gettxout",
        Json::Arr(vec![Json::hex(txid), Json::u(u64::from(vout))]),
    )?;
    let unspent = v
        .get("unspent")
        .and_then(Json::as_bool)
        .ok_or_else(|| RpcFailure::Transport("`unspent` missing".into()))?;
    let value_sat = v.get("utxo").and_then(|u| u.get("value_sat")).and_then(Json::as_sat_u64);
    Ok(TxOutStatus { unspent, value_sat, at_slot: want_u64(&v, "at_slot")? })
}

/// One unspent output, per `listunspent`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
}

/// `listunspent` for one script hash. `truncated` is the node saying the page
/// was cut (its page caps at 1,000 with no cursor) — a hot wallet holding
/// more outputs than that should consolidate, not paginate.
pub fn list_unspent(
    node: &dyn Node,
    script_hash: &[u8; 32],
    limit: u64,
) -> Result<(Vec<Utxo>, bool), RpcFailure> {
    let v = node.call(
        "listunspent",
        Json::Arr(vec![Json::hex(script_hash), Json::u(limit)]),
    )?;
    let truncated = v.get("truncated").and_then(Json::as_bool).unwrap_or(false);
    let items = match v.get("utxos") {
        Some(Json::Arr(items)) => items,
        _ => return Err(RpcFailure::Transport("`utxos` missing or not an array".into())),
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(Utxo {
            txid: want_hex32(item, "txid")?,
            vout: u32::try_from(want_u64(item, "vout")?)
                .map_err(|_| RpcFailure::Transport("`vout` out of range".into()))?,
            value_sat: item
                .get("value_sat")
                .and_then(Json::as_sat_u64)
                .ok_or_else(|| RpcFailure::Transport("`value_sat` missing".into()))?,
        });
    }
    Ok((out, truncated))
}

/// `getbalance` for one script hash: `(balance_sat, utxo_count)`.
pub fn get_balance(node: &dyn Node, script_hash: &[u8; 32]) -> Result<(u128, u64), RpcFailure> {
    let v = node.call("getbalance", Json::Arr(vec![Json::hex(script_hash)]))?;
    Ok((want_sat_u128(&v, "balance_sat")?, want_u64(&v, "utxo_count")?))
}

/// What became of a `sendrawtransaction`, with every node verdict folded to
/// the action the state machine takes. No arm of this enum is an excuse to
/// rebuild with different inputs — see the crate docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// In the mempool (newly, or it already was — the intent is satisfied
    /// either way; `duplicate` only matters for logs).
    Accepted { duplicate: bool },
    /// `-32003`: turned away for capacity, not judged invalid. Submit the
    /// SAME bytes again later.
    MempoolFull,
    /// `-32008`: the node refused these bytes on their merits — its proposer
    /// watched them fail, or they are structurally inadmissible. Do not
    /// resubmit these bytes; the next tick rebuilds (same pinned inputs) at
    /// the then-current base fee.
    Refused { message: String },
    /// `-32004` or transport-level: the node could not be reached or did not
    /// answer. Nothing is known about the transaction; retry later.
    Unreachable { message: String },
}

pub fn send_raw(node: &dyn Node, canonical_bytes: &[u8]) -> Result<SubmitOutcome, RpcFailure> {
    match node.call("sendrawtransaction", Json::Arr(vec![Json::hex(canonical_bytes)])) {
        Ok(v) => {
            let duplicate = v.get("status").and_then(Json::as_str) == Some("duplicate");
            Ok(SubmitOutcome::Accepted { duplicate })
        }
        Err(RpcFailure::Rpc { code: MEMPOOL_FULL, .. }) => Ok(SubmitOutcome::MempoolFull),
        Err(RpcFailure::Rpc { code: TX_REFUSED, message }) => {
            Ok(SubmitOutcome::Refused { message })
        }
        Err(RpcFailure::Rpc { code: NODE_UNAVAILABLE, message }) => {
            Ok(SubmitOutcome::Unreachable { message })
        }
        Err(RpcFailure::Transport(message)) => Ok(SubmitOutcome::Unreachable { message }),
        // TX_DECODE_FAILED and everything else: a bug in this client (we
        // encoded the bytes we submit). Surface it, do not loop on it.
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_error_is_rpc_failure() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32008,"message":"refused"}}"#;
        match parse_envelope(body) {
            Err(RpcFailure::Rpc { code, message }) => {
                assert_eq!(code, TX_REFUSED);
                assert_eq!(message, "refused");
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn envelope_result_comes_through() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"height":7}}"#;
        let v = parse_envelope(body).unwrap();
        assert_eq!(v.get("height").and_then(Json::as_u64), Some(7));
    }

    #[test]
    fn http_response_honors_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra";
        assert_eq!(parse_http_response(raw).unwrap(), "{}");
    }

    #[test]
    fn http_non_200_is_transport() {
        let raw = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
        assert!(matches!(parse_http_response(raw), Err(RpcFailure::Transport(_))));
    }
}
