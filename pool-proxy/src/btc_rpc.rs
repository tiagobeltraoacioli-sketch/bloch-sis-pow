//! Minimal Bitcoin Core JSON-RPC client for merged mining (`getblocktemplate`,
//! `submitblock`). SCAFFOLD — the transport mirrors [`crate::rpc`]'s hand-rolled
//! HTTP/1.1 (tokio + serde_json, no reqwest), swapping the node's `X-API-Key`
//! for bitcoind's HTTP **Basic Auth**. The merge-mining pool uses this to pull a
//! parent Bitcoin template and to submit a found Bitcoin block; the Bloch side
//! stays on [`crate::rpc`]. Needs a live `bitcoind` (`-server -rpcuser -rpcpassword`).

use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::PoolError;

/// M-2 fix (audit finding): total per-call deadline (connect + write + read),
/// mirroring `crate::rpc::RPC_TIMEOUT`. Before this fix there was no timeout
/// anywhere in this file — a `bitcoind` that accepted the TCP connection and
/// then never responded parked the calling task forever, and since
/// `merged_engine.rs`'s `TemplateCache` holds its mutex across this call, that
/// permanently deadlocked every merged worker in the process.
const BTC_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// M-2 fix: largest response this client will buffer. `getblocktemplate` can
/// carry a couple thousand transactions; anything larger is treated as a
/// protocol error rather than read unbounded into memory. Mirrors
/// `crate::rpc::MAX_RESPONSE_BYTES`.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Minimal Bitcoin RPC client (`addr = host:port`, HTTP Basic Auth).
#[derive(Clone)]
pub struct BtcRpcClient {
    addr: String,
    user: String,
    pass: String,
}

/// The subset of `getblocktemplate` the pool needs to build merged work.
#[derive(Clone, Debug)]
pub struct BtcTemplate {
    pub previous_block_hash: [u8; 32],
    pub version: i32,
    pub bits: u32,
    pub cur_time: u32,
    pub height: u64,
    pub coinbase_value: u64,
    /// Non-coinbase transactions: (txid, raw_bytes), in template order.
    pub transactions: Vec<(String, Vec<u8>)>,
    /// The witness-commitment `default_witness_commitment` (hex), if segwit.
    pub default_witness_commitment: Option<String>,
}

impl BtcRpcClient {
    pub fn new(addr: String, user: String, pass: String) -> Self {
        Self { addr, user, pass }
    }

    /// `getblocktemplate` (segwit rules) → the fields the merged-mining pool
    /// needs. SCAFFOLD: parses the common fields; extend for full segwit.
    pub async fn get_block_template(&self) -> Result<BtcTemplate, PoolError> {
        let params = serde_json::json!([{ "rules": ["segwit"] }]);
        let r = self.call("getblocktemplate", params).await?;
        let hx32 = |v: &Value, k: &str| -> Result<[u8; 32], PoolError> {
            let s = v.get(k).and_then(Value::as_str).ok_or_else(|| miss(k))?;
            hex32(s).ok_or_else(|| PoolError::Protocol(format!("btc gbt: bad {k}")))
        };
        let txs = r
            .get("transactions")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|t| {
                        let txid = t.get("txid").and_then(Value::as_str)?.to_string();
                        let data = hex::decode(t.get("data").and_then(Value::as_str)?).ok()?;
                        Some((txid, data))
                    })
                    .collect::<Vec<(String, Vec<u8>)>>()
            })
            .unwrap_or_default();
        Ok(BtcTemplate {
            previous_block_hash: hx32(&r, "previousblockhash")?,
            version: r.get("version").and_then(Value::as_i64).unwrap_or(0x2000_0000) as i32,
            bits: u32::from_str_radix(
                r.get("bits").and_then(Value::as_str).ok_or_else(|| miss("bits"))?,
                16,
            )
            .map_err(|_| PoolError::Protocol("btc gbt: bad bits".into()))?,
            cur_time: r.get("curtime").and_then(Value::as_u64).unwrap_or(0) as u32,
            height: r.get("height").and_then(Value::as_u64).ok_or_else(|| miss("height"))?,
            coinbase_value: r.get("coinbasevalue").and_then(Value::as_u64).unwrap_or(0),
            transactions: txs,
            default_witness_commitment: r
                .get("default_witness_commitment")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    /// `submitblock(hex)` → `None` on accept, `Some(reason)` on reject
    /// (bitcoind returns a string reason or null).
    pub async fn submit_block(&self, block_hex: &str) -> Result<Option<String>, PoolError> {
        let r = self.call("submitblock", serde_json::json!([block_hex])).await?;
        Ok(r.as_str().map(str::to_string))
    }

    /// JSON-RPC-over-HTTP/1.1 with Basic Auth. Mirrors `crate::rpc` transport.
    ///
    /// M-2 fix: the whole call (connect + write + read) is now bounded by
    /// [`BTC_RPC_TIMEOUT`], mirroring `crate::rpc::RpcClient::call`. Before this
    /// fix a `bitcoind` that accepted the connection and never answered hung
    /// the calling task — and every merged worker with it, since the cache
    /// mutex is held across this call (see `merged_engine.rs`).
    async fn call(&self, method: &str, params: Value) -> Result<Value, PoolError> {
        match tokio::time::timeout(BTC_RPC_TIMEOUT, self.call_inner(method, params)).await {
            Ok(res) => res,
            Err(_) => Err(PoolError::Timeout(format!(
                "btc rpc {} to {} timed out after {:?}",
                method, self.addr, BTC_RPC_TIMEOUT
            ))),
        }
    }

    async fn call_inner(&self, method: &str, params: Value) -> Result<Value, PoolError> {
        let body = serde_json::json!({ "jsonrpc": "1.0", "id": "pool", "method": method, "params": params })
            .to_string();
        // M-10 fix (audit finding): `rpc.rs`'s API-key path already filters
        // CR/LF from a configured secret before splicing it into a header
        // ("cheap to be safe"); this file did the equivalent Basic-Auth splice
        // with no such guard. `user`/`pass` are operator configuration, not
        // request-derived, but a stray control character in either (a typo, a
        // misquoted env var) would otherwise corrupt the request line / inject
        // an extra header — reject rather than silently mis-send credentials.
        if self.user.contains(['\r', '\n']) || self.pass.contains(['\r', '\n']) {
            return Err(PoolError::Config(
                "btc rpc: user/pass must not contain CR or LF".into(),
            ));
        }
        let auth = base64(format!("{}:{}", self.user, self.pass).as_bytes());
        let head = format!(
            "POST / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\n\
             Content-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
            host = self.addr,
            len = body.len(),
        );
        let mut wire = Vec::with_capacity(head.len() + body.len());
        wire.extend_from_slice(head.as_bytes());
        wire.extend_from_slice(body.as_bytes());

        let mut s = TcpStream::connect(&self.addr).await?;
        s.write_all(&wire).await?;
        s.flush().await?;
        // M-2 fix: bounded read (was `read_to_end` with no cap at all).
        let raw = read_response_bounded(&mut s).await?;
        let _ = s.shutdown().await;

        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| {
            PoolError::Protocol("btc rpc: no header/body split".into())
        })?;
        let json: Value = serde_json::from_slice(&raw[split + 4..])
            .map_err(|e| PoolError::Protocol(format!("btc rpc: bad json: {e}")))?;
        if let Some(err) = json.get("error") {
            if !err.is_null() {
                return Err(PoolError::Protocol(format!("btc rpc error: {err}")));
            }
        }
        json.get("result").cloned().ok_or_else(|| PoolError::Protocol("btc rpc: no result".into()))
    }
}

/// M-2 fix: read the full response into a buffer capped at
/// [`MAX_RESPONSE_BYTES`] (peer sends `Connection: close`, so EOF terminates).
/// Mirrors `crate::rpc::read_response_bounded`. Replaces the previous
/// `read_to_end`, which had no cap — a slow-drip or malicious `bitcoind` (or a
/// misconfigured `BLOCH_POOL_BTC_RPC` pointed at an attacker-controlled host)
/// could otherwise grow this buffer without bound.
async fn read_response_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, PoolError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_RESPONSE_BYTES {
            return Err(PoolError::Protocol("btc rpc: response exceeds size cap".to_string()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

fn miss(k: &str) -> PoolError {
    PoolError::Protocol(format!("btc gbt: missing {k}"))
}

/// Parse a 32-byte hex string into internal (little-endian) byte order — the
/// order Bitcoin merkle/header fields use on the wire (hex is big-endian display,
/// so reverse).
fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    b.reverse();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Some(a)
}

/// Standard base64 (no line breaks) — small inline encoder to avoid a new dep.
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    }

    /// M-10 regression: a CR or LF in the configured RPC user/pass must be
    /// refused (a config error) rather than silently spliced into the raw
    /// HTTP request. Checked BEFORE any network I/O, so this never touches a
    /// real socket.
    #[tokio::test]
    async fn crlf_in_credentials_is_refused_before_any_network_io() {
        let bad_user = BtcRpcClient::new("127.0.0.1:1".into(), "user\r\nX-Evil: 1".into(), "pass".into());
        let err = bad_user.call_inner("ping", serde_json::json!([])).await.unwrap_err();
        assert!(matches!(err, PoolError::Config(_)), "expected Config error, got {err:?}");

        let bad_pass = BtcRpcClient::new("127.0.0.1:1".into(), "user".into(), "pa\nss".into());
        let err2 = bad_pass.call_inner("ping", serde_json::json!([])).await.unwrap_err();
        assert!(matches!(err2, PoolError::Config(_)), "expected Config error, got {err2:?}");

        // Sanity: an ordinary user/pass is not rejected by this guard (it
        // still fails, but for a DIFFERENT reason — the connect to port 1
        // fails — proving the CR/LF check itself does not false-positive).
        let ok = BtcRpcClient::new("127.0.0.1:1".into(), "user".into(), "pass".into());
        let err3 = ok.call_inner("ping", serde_json::json!([])).await.unwrap_err();
        assert!(!matches!(err3, PoolError::Config(_)), "clean credentials must pass the guard: {err3:?}");
    }

    #[test]
    fn hex32_reverses_to_internal_order() {
        // big-endian display "00..01" → internal little-endian [01,00,...,00]
        let s = "0000000000000000000000000000000000000000000000000000000000000001";
        let a = hex32(s).unwrap();
        assert_eq!(a[0], 1);
        assert!(a[1..].iter().all(|&b| b == 0));
    }
}
