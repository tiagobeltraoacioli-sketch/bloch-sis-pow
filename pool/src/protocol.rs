//! Stratum framing + error codes — a faithful mirror of the node's
//! `src/stratum/protocol.rs` (newline-delimited JSON, 8 KiB line cap,
//! Bitcoin-convention error codes), with the pool's SIS-native params
//! documented per method.
//!
//! Wire format (one JSON object per line):
//!
//! ```text
//! Request:    {"id": 1, "method": "mining.subscribe", "params": [...]}
//! Response:   {"id": 1, "result": ..., "error": null}
//! Error:      {"id": 1, "result": null, "error": [code, "msg", null]}
//! Notify:     {"id": null, "method": "mining.notify", "params": [...]}
//! ```
//!
//! SIS-native params (this is where we diverge from Bitcoin stratum —
//! the classic params cannot carry the Module-SIS witness, which is why
//! the node's own stratum server refuses to start; main.rs B5f):
//!
//! * `mining.subscribe`  → result `[[["mining.notify", sid]],
//!   nonce_base_hex, 0, challenge_hex]`. `nonce_base_hex` is a
//!   16-hex-char u64. Each session gets a disjoint 2^40-wide nonce
//!   range starting there (replaces extranonce: the coinbase is fixed
//!   by the pool, miners partition the u64 nonce space; submits outside
//!   the range are rejected). `challenge_hex` is a fresh 32-byte server
//!   nonce for the authorize ownership proof.
//! * `mining.authorize` → params `[address, password]`, or — when the
//!   pool requires the ownership proof (default) — `[address, password,
//!   pubkey_hex, signature_hex]`: the hybrid ML-DSA-65 ‖ Falcon-1024
//!   public key whose SHA3-256 hash is the address, and its signature
//!   over `"bloch-pool-authorize-v1" ‖ challenge` (the 32 raw challenge
//!   bytes from subscribe). Shares/credit are refused for an address
//!   the connection cannot prove it controls.
//! * `mining.set_difficulty` → params `[share_bits]` (compact-bits u32,
//!   decimal). Shares must meet `bits_to_target(share_bits)` on the
//!   SHAKE-256 aux hash.
//! * `mining.notify` → params `[job_id, preimage_hex, block_bits_hex,
//!   height, clean_jobs]`. `preimage_hex` is the 76-byte header preimage
//!   (`BlockHeader::pow_preimage()`): version ‖ parents-commitment ‖
//!   merkle_root ‖ timestamp ‖ bits. The miner greps for `(nonce, s)`
//!   with `bloch_sis_pow::solver::mine` against the share target.
//! * `mining.submit` → params `[address, job_id, nonce_hex(16),
//!   solution_hex(512)]`. `solution_hex` is the canonical encoding of
//!   `s` (`bloch_sis_pow::encode::encode_s`, one signed byte per
//!   coefficient, N = 256).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Max bytes per line. A submit line is ~620 bytes, but an authorize
/// line carrying the ownership proof is ~17 KiB of hex (hybrid pubkey
/// 3745 B + hybrid signature ~4.6 KiB), so the cap is 24 KiB — still a
/// hard bound per line, just PQ-sized.
pub const MAX_LINE_BYTES: usize = 24 * 1024;

// ── Incoming request ──────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
pub struct StratumRequest {
    #[serde(default)]
    pub id:     Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl StratumRequest {
    pub fn parse(line: &str) -> Result<Self, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err("empty line".to_string());
        }
        if trimmed.len() > MAX_LINE_BYTES {
            return Err(format!("line exceeds {}B limit", MAX_LINE_BYTES));
        }
        serde_json::from_str(trimmed).map_err(|e| format!("parse: {}", e))
    }
}

// ── Outgoing response ─────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct StratumResponse {
    pub id:     Option<Value>,
    pub result: Value,
    pub error:  Option<Value>,
}

impl StratumResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self { id, result, error: None }
    }

    pub fn error(id: Option<Value>, err: StratumError) -> Self {
        Self { id, result: Value::Null, error: Some(err.to_json()) }
    }

    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        line.push('\n');
        line
    }
}

// ── Server-initiated notification ─────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct StratumNotification {
    pub id:     Option<Value>,
    pub method: String,
    pub params: Value,
}

impl StratumNotification {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self { id: None, method: method.into(), params }
    }

    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        line.push('\n');
        line
    }
}

// ── Error codes (Bitcoin stratum convention, same as the node) ────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// 20 — Other / unknown method / malformed submission
    Other              = 20,
    /// 21 — Job not found (stale work)
    JobNotFoundOrStale = 21,
    /// 22 — Duplicate share
    DuplicateShare     = 22,
    /// 23 — Low difficulty share (aux hash above the share target)
    LowDifficulty      = 23,
    /// 24 — Unauthorized worker / invalid address
    Unauthorized       = 24,
    /// 25 — Not subscribed / protocol-state error
    NotSubscribed      = 25,
}

#[derive(Clone, Debug)]
pub struct StratumError {
    pub code:    ErrorCode,
    pub message: String,
}

impl StratumError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn to_json(&self) -> Value {
        Value::Array(vec![
            Value::Number(serde_json::Number::from(self.code as u32)),
            Value::String(self.message.clone()),
            Value::Null,
        ])
    }
}

// ── Method names (V1 names kept; params are SIS-native) ──────────

pub mod methods {
    // Client→server
    pub const SUBSCRIBE: &str = "mining.subscribe";
    pub const AUTHORIZE: &str = "mining.authorize";
    pub const SUBMIT:    &str = "mining.submit";

    // Server→client
    pub const NOTIFY:         &str = "mining.notify";
    pub const SET_DIFFICULTY: &str = "mining.set_difficulty";
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subscribe() {
        let line = r#"{"id": 1, "method": "mining.subscribe", "params": ["bloch-pool-miner/0.1"]}"#;
        let req = StratumRequest::parse(line).expect("should parse");
        assert_eq!(req.method, "mining.subscribe");
    }

    #[test]
    fn rejects_empty_and_oversize() {
        assert!(StratumRequest::parse("").is_err());
        assert!(StratumRequest::parse(&"x".repeat(MAX_LINE_BYTES + 1)).is_err());
    }

    #[test]
    fn error_codes_match_node_convention() {
        assert_eq!(ErrorCode::Other              as u32, 20);
        assert_eq!(ErrorCode::JobNotFoundOrStale as u32, 21);
        assert_eq!(ErrorCode::DuplicateShare     as u32, 22);
        assert_eq!(ErrorCode::LowDifficulty      as u32, 23);
        assert_eq!(ErrorCode::Unauthorized       as u32, 24);
        assert_eq!(ErrorCode::NotSubscribed      as u32, 25);
    }

    #[test]
    fn error_serializes_as_triple() {
        let resp = StratumResponse::error(
            Some(Value::from(2)),
            StratumError::new(ErrorCode::Unauthorized, "bad address"),
        );
        assert!(resp.to_line().contains("[24,\"bad address\",null]"));
    }
}
