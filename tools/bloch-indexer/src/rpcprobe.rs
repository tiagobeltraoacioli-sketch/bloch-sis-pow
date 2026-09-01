// SPDX-License-Identifier: AGPL-3.0-or-later

//! A minimal JSON-RPC client, used ONLY to check the index against a live node.
//!
//! ## Read-only, low-rate, archival-only — by construction
//!
//! This is the one place the indexer talks to a node, and it exists for one
//! reason: to prove the index agrees with the chain. It therefore does the
//! smallest thing that can prove it — a bounded sample of `getbalance` calls,
//! serialised, with a delay between them, against an **archival observer**.
//!
//! [`Probe::new`] refuses a port that is not an archival's, because the
//! difference between "a few hundred reads against a keyless observer" and "the
//! same reads against a validator" is the difference between a check and the
//! incident this whole crate exists to prevent. If you need to point it
//! somewhere else, you are pointing it somewhere it should not go.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

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
        Ok(Probe { addr: addr.to_string(), gap: Duration::from_millis(gap_ms), id: 0 })
    }

    fn call(&mut self, method: &str, params: &str) -> Result<String, String> {
        std::thread::sleep(self.gap);
        self.id += 1;
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
        let mut s = TcpStream::connect_timeout(&sock, Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(20))).ok();
        let host = self.addr.clone();
        let req = format!(
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut resp = String::new();
        s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
        let (_, b) = resp.split_once("\r\n\r\n").ok_or("no body in response")?;
        Ok(b.to_string())
    }

    /// `getbalance` for one `script_hash`, returning the satoshi as the node
    /// stated it.
    ///
    /// The value is read out of the raw response text rather than through a
    /// JSON number, deliberately: `balance_sat` is a decimal STRING on the wire
    /// precisely because the values exceed 2^53, and re-parsing it as a float
    /// somewhere in the middle of a correctness check would defeat the check.
    pub fn balance(&mut self, script_hash_hex: &str) -> Result<u128, String> {
        let body = self.call("getbalance", &format!(r#"["{script_hash_hex}"]"#))?;
        extract_string_field(&body, "balance_sat")
            .ok_or_else(|| format!("no balance_sat in response: {}", trim(&body)))?
            .parse::<u128>()
            .map_err(|e| e.to_string())
    }

    /// `getchaininfo`, returning `(height, slot, block_id, state_root)`.
    pub fn chaininfo(&mut self) -> Result<(u64, u64, String, String), String> {
        let body = self.call("getchaininfo", "[]")?;
        let h = extract_num_field(&body, "height").ok_or("no height")?;
        let s = extract_num_field(&body, "slot").ok_or("no slot")?;
        let id = extract_string_field(&body, "block_id").ok_or("no block_id")?;
        let sr = extract_string_field(&body, "state_root").ok_or("no state_root")?;
        Ok((h as u64, s as u64, id, sr))
    }
}

fn trim(s: &str) -> String {
    s.chars().take(200).collect()
}

/// Pull `"key":"value"` out of a JSON document by scanning.
///
/// A 40-line scanner rather than a JSON dependency, for the same reason the
/// rest of this crate has none. It is used only against this node's own
/// responses, whose shape is fixed by `BLOCH-RPC-V4.md`.
pub fn extract_string_field(doc: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let at = doc.find(&pat)? + pat.len();
    let rest = &doc[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub fn extract_num_field(doc: &str, key: &str) -> Option<u128> {
    let pat = format!("\"{key}\":");
    let at = doc.find(&pat)? + pat.len();
    let rest = &doc[at..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    rest[..end].parse().ok()
}
