// SPDX-License-Identifier: AGPL-3.0-or-later

//! A minimal JSON-RPC client, used ONLY to check the index against a live node.
//!
//! ## Read-only, low-rate, archival-only — by construction
//!
//! This is the one place the indexer talks to a node, and it exists for one
//! reason: to compare the index with a remote observation. It therefore does the
//! smallest thing that can prove it — a bounded sample of `getbalance` calls,
//! serialised, with a delay between them, against an **archival observer**.
//!
//! The historical endpoints use plaintext HTTP. The allowlist limits targets;
//! it does not authenticate an operator or prove an endpoint remains keyless.
//! Results are diagnostics, not independent balance or finality trust anchors.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use serde_json::Value;
use crate::io_deadline::DeadlineStream;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The two keyless archival observers. Nothing else is a legitimate target.
pub const ARCHIVALS: [&str; 2] = ["139.180.166.5:8080", "139.180.173.231:8080"];

pub struct Probe {
    addr: String,
    /// Minimum gap between calls. Not a throttle for the archival's sake alone
    /// — it is the honest admission that a tight loop against any node's RPC is
    /// the thing being designed out.
    gap: Duration,
    id: u64,
}

impl Probe {
    pub fn new(addr: &str, gap_ms: u64) -> Result<Probe, String> {
        if !ARCHIVALS.contains(&addr) {
            return Err(format!(
                "{addr} is not one of the archival observers ({}). This crate does not read \
                 from validators: their RPC has no auth and no rate limit and shares a thread \
                 with consensus.",
                ARCHIVALS.join(", ")
            ));
        }
        Ok(Probe { addr: addr.to_string(), gap: Duration::from_millis(gap_ms.max(120)), id: 0 })
    }

    fn call(&mut self, method: &str, params: &str) -> Result<Value, String> {
        std::thread::sleep(self.gap);
        self.id = self.id.checked_add(1).ok_or("RPC request identifier exhausted")?;
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"{method}","params":{params}}}"#,
            self.id
        );
        let sock = self
            .addr
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("no address")?;
        let socket = TcpStream::connect_timeout(&sock, Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        let mut s = DeadlineStream::new(&socket, Instant::now() + Duration::from_secs(20));
        let host = self.addr.clone();
        let req = format!(
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        s.take(MAX_RESPONSE_BYTES as u64 + 1).read_to_end(&mut response)
            .map_err(|_| "diagnostic response read failed or timed out")?;
        decode_response(&response, self.id)
    }

    /// `getbalance` for one `script_hash`, returning the satoshi as the node
    /// stated it.
    ///
    /// The value is read out of the raw response text rather than through a
    /// JSON number, deliberately: `balance_sat` is a decimal STRING on the wire
    /// precisely because the values exceed 2^53, and re-parsing it as a float
    /// somewhere in the middle of a correctness check would defeat the check.
    pub fn balance(&mut self, script_hash_hex: &str) -> Result<u128, String> {
        let hash = crate::hex32(&crate::parse_script_hash(script_hash_hex)?);
        let body = self.call("getbalance", &format!(r#"["{hash}"]"#))?;
        let decimal = body.get("balance_sat").and_then(Value::as_str).ok_or("missing balance_sat string")?;
        if decimal.is_empty() || !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid balance_sat decimal".into());
        }
        decimal.parse::<u128>().map_err(|_| "balance_sat exceeds integer range".into())
    }

    /// `getchaininfo`, returning `(height, slot, block_id, state_root)`.
    pub fn chaininfo(&mut self) -> Result<(u64, u64, String, String), String> {
        let body = self.call("getchaininfo", "[]")?;
        let h = body.get("height").and_then(Value::as_u64).ok_or("invalid height")?;
        let s = body.get("slot").and_then(Value::as_u64).ok_or("invalid slot")?;
        let digest = |key| -> Result<String, String> {
            let text = body.get(key).and_then(Value::as_str).ok_or("missing chain digest")?;
            Ok(crate::hex32(&crate::parse_script_hash(text)?))
        };
        Ok((h, s, digest("block_id")?, digest("state_root")?))
    }
}

/// Read an immediate string field from one complete JSON object.
pub fn extract_string_field(doc: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(doc).ok()?.get(key)?.as_str().map(str::to_owned)
}

pub fn extract_num_field(doc: &str, key: &str) -> Option<u128> {
    serde_json::from_str::<Value>(doc).ok()?.get(key)?.as_u64().map(u128::from)
}

/// Decode bounded diagnostic HTTP/JSON-RPC without echoing remote body text.
pub fn decode_response(response: &[u8], expected_id: u64) -> Result<Value, String> {
    if response.len() > MAX_RESPONSE_BYTES { return Err("diagnostic response exceeds byte budget".into()); }
    let boundary = response.windows(4).position(|part| part == b"\r\n\r\n").ok_or("missing HTTP header terminator")?;
    if boundary > MAX_HEADER_BYTES { return Err("diagnostic HTTP header exceeds byte budget".into()); }
    let head = std::str::from_utf8(&response[..boundary]).map_err(|_| "invalid HTTP header")?;
    let mut lines = head.split("\r\n");
    let status: Vec<_> = lines.next().unwrap_or("").split_whitespace().collect();
    if status.len() < 2 || !matches!(status[0], "HTTP/1.0" | "HTTP/1.1") || status[1] != "200" {
        return Err("diagnostic HTTP status is not successful".into());
    }
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid HTTP header field")?;
        if name.eq_ignore_ascii_case("transfer-encoding") { return Err("unsupported diagnostic transfer encoding".into()); }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if content_length.is_some() || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid HTTP content length".into());
            }
            content_length = Some(value.parse::<usize>().map_err(|_| "invalid HTTP content length")?);
        }
    }
    let body = &response[boundary + 4..];
    if content_length.is_some_and(|size| size != body.len()) { return Err("HTTP response length mismatch".into()); }
    let envelope: Value = serde_json::from_slice(body).map_err(|_| "invalid diagnostic JSON")?;
    if envelope.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || envelope.get("id").and_then(Value::as_u64) != Some(expected_id)
        || envelope.get("error").is_some_and(|error| !error.is_null()) {
        return Err("RPC response version, identifier or error mismatch".into());
    }
    envelope.get("result").filter(|value| value.is_object()).cloned().ok_or("missing RPC result object".into())
}
