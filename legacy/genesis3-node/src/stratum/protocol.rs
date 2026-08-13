//! Stratum V1 JSON-RPC protocol framing.
//!
//! Reads newline-delimited JSON requests off a TCP stream, emits
//! typed `StratumRequest` values, and serializes `StratumResponse`
//! / `StratumNotification` back to the wire.
//!
//! Wire format (newline-delimited JSON, one message per line):
//!
//! Request:    {"id": 1, "method": "mining.subscribe", "params": [...]}
//! Response:   {"id": 1, "result": ..., "error": null}
//! Error:      {"id": 1, "result": null, "error": [code, "msg", null]}
//! Notify:     {"id": null, "method": "mining.notify", "params": [...]}
//!
//! The 8 KiB line limit matches the de-facto Bitcoin stratum
//! convention — miners rarely need larger messages; exceeding it
//! closes the session as a protocol violation.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Max bytes per line before we treat the stream as malformed.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

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
    /// Parse a single JSON line. Returns an Err with a short diagnostic
    /// message suitable for logging; protocol violations are never
    /// echoed to the peer verbatim.
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

/// Successful response. `result` is arbitrary JSON.
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
        Self {
            id,
            result: Value::Null,
            error:  Some(err.to_json()),
        }
    }

    /// Serialize to a line-terminated JSON string ready for the wire.
    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        line.push('\n');
        line
    }
}

// ── Server-initiated notification ─────────────────────────────────

/// Server→client notification (mining.notify, mining.set_difficulty,
/// mining.set_extranonce). Has no `id` and no `result`.
#[derive(Clone, Debug, Serialize)]
pub struct StratumNotification {
    pub id:     Option<Value>, // always null, but serde demands the field
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

// ── Error codes (Bitcoin stratum convention) ──────────────────────

/// Standard stratum error codes. Values and meanings follow the
/// de-facto Bitcoin stratum convention used by Slush Pool, Braiins,
/// NiceHash, and every major mining client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// 20 — Other / unknown method
    Other              = 20,
    /// 21 — Job not found (stale work) or share above target
    JobNotFoundOrStale = 21,
    /// 22 — Duplicate share
    DuplicateShare     = 22,
    /// 23 — Low difficulty share (share below the declared target)
    LowDifficulty      = 23,
    /// 24 — Unauthorized worker / invalid address
    Unauthorized       = 24,
    /// 25 — Not subscribed / protocol-state error
    NotSubscribed      = 25,
}

/// An error response payload. Serializes as [code, message, null].
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

// ── Standard method names ─────────────────────────────────────────

pub mod methods {
    // Client→server
    pub const SUBSCRIBE:             &str = "mining.subscribe";
    pub const AUTHORIZE:             &str = "mining.authorize";
    pub const SUBMIT:                &str = "mining.submit";
    pub const CONFIGURE:             &str = "mining.configure";
    pub const EXTRANONCE_SUBSCRIBE:  &str = "mining.extranonce.subscribe";
    pub const SUGGEST_DIFFICULTY:    &str = "mining.suggest_difficulty";
    pub const SUGGEST_TARGET:        &str = "mining.suggest_target";

    // Server→client
    pub const NOTIFY:                &str = "mining.notify";
    pub const SET_DIFFICULTY:        &str = "mining.set_difficulty";
    pub const SET_EXTRANONCE:        &str = "mining.set_extranonce";
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_subscribe_request() {
        let line = r#"{"id": 1, "method": "mining.subscribe", "params": ["cpuminer/2.5"]}"#;
        let req = StratumRequest::parse(line).expect("should parse");
        assert_eq!(req.method, "mining.subscribe");
        assert_eq!(req.id, Some(Value::from(1)));
    }

    #[test]
    fn rejects_empty_line() {
        assert!(StratumRequest::parse("").is_err());
        assert!(StratumRequest::parse("   \n").is_err());
    }

    #[test]
    fn rejects_oversize_line() {
        let giant = "x".repeat(MAX_LINE_BYTES + 1);
        assert!(StratumRequest::parse(&giant).is_err());
    }

    #[test]
    fn ok_response_serializes_with_null_error() {
        let resp = StratumResponse::ok(Some(Value::from(1)), Value::from(true));
        let line = resp.to_line();
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"error\":null"));
        assert!(line.contains("\"result\":true"));
    }

    #[test]
    fn error_response_has_standard_error_shape() {
        let err = StratumError::new(ErrorCode::Unauthorized, "bad address");
        let resp = StratumResponse::error(Some(Value::from(2)), err);
        let line = resp.to_line();
        // Error is an array [code, message, null]
        assert!(line.contains("[24,\"bad address\",null]"));
        assert!(line.contains("\"result\":null"));
    }

    #[test]
    fn notification_has_null_id() {
        let notify = StratumNotification::new("mining.notify", Value::from(vec!["job1"]));
        let line = notify.to_line();
        assert!(line.contains("\"id\":null"));
        assert!(line.contains("\"method\":\"mining.notify\""));
    }

    #[test]
    fn error_codes_match_bitcoin_convention() {
        // Anyone pointing a cgminer at us must see the right numbers.
        assert_eq!(ErrorCode::Other              as u32, 20);
        assert_eq!(ErrorCode::JobNotFoundOrStale as u32, 21);
        assert_eq!(ErrorCode::DuplicateShare     as u32, 22);
        assert_eq!(ErrorCode::LowDifficulty      as u32, 23);
        assert_eq!(ErrorCode::Unauthorized       as u32, 24);
        assert_eq!(ErrorCode::NotSubscribed      as u32, 25);
    }
}
