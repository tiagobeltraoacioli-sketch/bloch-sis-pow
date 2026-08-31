// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal JSON-RPC 2.0 over HTTP/1.1, std-only.
//!
//! The Genesis-4 node's RPC speaks exactly the HTTP a JSON-RPC client needs
//! (POST + `Content-Length`, no chunked encoding, no TLS on the node itself —
//! see `bloch-pos-node/src/rpc.rs`), so a `TcpStream` and two headers are the
//! whole client. No async runtime, no TLS stack, no connection pool: every
//! call is one connect, one request, one response, closed. A tool that moves
//! value wants the smallest possible amount of machinery between the operator
//! and the bytes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);

pub struct Client {
    host: String,
    port: u16,
    path: String,
}

impl Client {
    /// Accepts `http://host:port` or `http://host:port/path`. Refuses
    /// `https://` — this client does no TLS and must say so rather than
    /// silently speaking plaintext to a TLS port.
    pub fn new(url: &str) -> Result<Client, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| {
                format!(
                    "`{url}`: expected an http:// URL (this client is plaintext HTTP to a node \
                     or a local tunnel; it does not speak TLS)"
                )
            })?;
        let (hostport, path) = match rest.split_once('/') {
            None => (rest, String::from("/")),
            Some((hp, p)) => (hp, format!("/{p}")),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => {
                (h.to_string(), p.parse::<u16>().map_err(|_| format!("bad port in `{url}`"))?)
            }
            None => (hostport.to_string(), 80),
        };
        if host.is_empty() {
            return Err(format!("`{url}` has no host"));
        }
        Ok(Client { host, port, path })
    }

    /// One JSON-RPC call. A top-level `error` object becomes `Err` with its
    /// code and message; otherwise the `result` value is returned.
    pub fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        .to_string();
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.path,
            self.host,
            body.len(),
            body
        );

        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|e| format!("connect {}:{}: {e}", self.host, self.port))?;
        stream.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
        stream.write_all(request.as_bytes()).map_err(|e| format!("send: {e}"))?;

        // Read headers to the blank line, then exactly Content-Length body
        // bytes. Not read-to-EOF: the node may keep the connection open
        // regardless of `Connection: close`, and a client that waits for EOF
        // waits for the timeout instead of the answer.
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let header_end = loop {
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if raw.len() > 64 * 1024 {
                return Err("HTTP headers exceed 64 KiB".into());
            }
            let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed before the HTTP headers completed".into());
            }
            raw.extend_from_slice(&buf[..n]);
        };
        let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
        let status = head.lines().next().unwrap_or("").to_string();
        let content_length = head
            .lines()
            .find_map(|l| {
                let (name, v) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or_else(|| format!("response has no Content-Length ({status})"))?;
        if content_length > 64 * 1024 * 1024 {
            return Err("HTTP body exceeds 64 MiB".into());
        }
        let mut body_bytes = raw[header_end..].to_vec();
        while body_bytes.len() < content_length {
            let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("truncated HTTP body".into());
            }
            body_bytes.extend_from_slice(&buf[..n]);
        }
        body_bytes.truncate(content_length);
        let resp_body = String::from_utf8_lossy(&body_bytes).into_owned();
        if !status.contains(" 200 ") {
            return Err(format!("HTTP {status}: {}", resp_body.trim()));
        }
        let v: serde_json::Value = serde_json::from_str(resp_body.trim())
            .map_err(|e| format!("bad JSON-RPC body: {e}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("(no message)");
            return Err(format!("{method}: node error {code}: {msg}"));
        }
        v.get("result").cloned().ok_or_else(|| format!("{method}: response has no result"))
    }
}

/// Read a satoshi field that arrives as a decimal string (V4 wire rule R3) or,
/// tolerantly, as a JSON number.
pub fn sat_u128(v: &serde_json::Value) -> Option<u128> {
    if let Some(n) = v.as_u64() {
        return Some(n as u128);
    }
    v.as_str().and_then(|s| s.trim().parse::<u128>().ok())
}

/// `getutxos` for a script hash, as [`crate::Coin`]s.
pub fn get_coins(client: &Client, script_hash: &[u8; 32]) -> Result<Vec<crate::Coin>, String> {
    let result = client.call(
        "getutxos",
        serde_json::json!([hex::encode(script_hash), 1000]),
    )?;
    let utxos = result
        .get("utxos")
        .and_then(|u| u.as_array())
        .ok_or_else(|| "getutxos: no `utxos` array".to_string())?;
    if result.get("truncated").and_then(|t| t.as_bool()) == Some(true) {
        return Err("getutxos: the node truncated the UTXO listing (>1000 outputs); this \
                    source address is too fragmented for this tool"
            .into());
    }
    let mut coins = Vec::with_capacity(utxos.len());
    for u in utxos {
        let txid_hex =
            u.get("txid").and_then(|t| t.as_str()).ok_or_else(|| "utxo without txid".to_string())?;
        let txid_v = hex::decode(txid_hex).map_err(|e| format!("utxo txid: {e}"))?;
        let txid: [u8; 32] =
            txid_v.try_into().map_err(|_| "utxo txid is not 32 bytes".to_string())?;
        let vout = u
            .get("vout")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "utxo without vout".to_string())? as u32;
        let value = u
            .get("value_sat")
            .and_then(sat_u128)
            .ok_or_else(|| "utxo without value_sat".to_string())?;
        let value_sat =
            u64::try_from(value).map_err(|_| "utxo value exceeds u64".to_string())?;
        coins.push(crate::Coin { txid, vout, value_sat });
    }
    Ok(coins)
}

/// The base fee the NEXT block will charge — the price a transfer built now
/// must bake in. Prefer `getmempoolinfo.next_base_fee_millisat_per_gas`;
/// fall back to the same field on `getchaininfo`.
pub fn next_base_fee(client: &Client) -> Result<u128, String> {
    for method in ["getmempoolinfo", "getchaininfo"] {
        if let Ok(r) = client.call(method, serde_json::json!([])) {
            if let Some(v) = r.get("next_base_fee_millisat_per_gas").and_then(sat_u128) {
                return Ok(v);
            }
        }
    }
    Err("could not read next_base_fee_millisat_per_gas from the node".into())
}

/// (balance_sat, utxo_count) for a script hash.
pub fn get_balance(client: &Client, script_hash: &[u8; 32]) -> Result<(u128, u64), String> {
    let r = client.call("getbalance", serde_json::json!([hex::encode(script_hash)]))?;
    let bal = r
        .get("balance_sat")
        .and_then(sat_u128)
        .ok_or_else(|| "getbalance: no balance_sat".to_string())?;
    let count = r.get("utxo_count").and_then(|c| c.as_u64()).unwrap_or(0);
    Ok((bal, count))
}

/// Is this exact outpoint still unspent?
pub fn is_unspent(client: &Client, txid: &str, vout: u32) -> Result<bool, String> {
    let r = client.call("gettxout", serde_json::json!([txid, vout]))?;
    Ok(r.get("unspent").and_then(|u| u.as_bool()).unwrap_or(false))
}

/// Broadcast. Returns the node's `(accepted, txid)`.
pub fn send_raw(client: &Client, raw_hex: &str) -> Result<(bool, String), String> {
    let r = client.call("sendrawtransaction", serde_json::json!([raw_hex]))?;
    let accepted = r.get("accepted").and_then(|a| a.as_bool()).unwrap_or(false);
    let txid = r.get("txid").and_then(|t| t.as_str()).unwrap_or("").to_string();
    Ok((accepted, txid))
}
