//! Minimal Bitcoin Core JSON-RPC client for merged mining (`getblocktemplate`,
//! `submitblock`). SCAFFOLD — the transport mirrors [`crate::rpc`]'s hand-rolled
//! HTTP/1.1 (tokio + serde_json, no reqwest), swapping the node's `X-API-Key`
//! for bitcoind's HTTP **Basic Auth**. The merge-mining pool uses this to pull a
//! parent Bitcoin template and to submit a found Bitcoin block; the Bloch side
//! stays on [`crate::rpc`]. Needs a live `bitcoind` (`-server -rpcuser -rpcpassword`).

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::PoolError;

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
    async fn call(&self, method: &str, params: Value) -> Result<Value, PoolError> {
        let body = serde_json::json!({ "jsonrpc": "1.0", "id": "pool", "method": method, "params": params })
            .to_string();
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
        let mut raw = Vec::new();
        // SCAFFOLD: unbounded read for a scaffold; the live path should reuse
        // crate::rpc's bounded reader.
        s.read_to_end(&mut raw).await?;
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

    #[test]
    fn hex32_reverses_to_internal_order() {
        // big-endian display "00..01" → internal little-endian [01,00,...,00]
        let s = "0000000000000000000000000000000000000000000000000000000000000001";
        let a = hex32(s).unwrap();
        assert_eq!(a[0], 1);
        assert!(a[1..].iter().all(|&b| b == 0));
    }
}
