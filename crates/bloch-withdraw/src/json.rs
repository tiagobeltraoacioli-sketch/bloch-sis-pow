// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal JSON — parse and emit, `std`-only.
//!
//! Exists for the same reason the node's own `rpc.rs` carries one: the V4 RPC
//! puts every satoshi amount on the wire as a **decimal string** (R3), and the
//! few numbers that are JSON numbers (slots, heights) must survive verbatim.
//! Numbers are therefore held as their raw source text and only converted at
//! the moment a caller asks for a `u64`/`u128` — nothing here ever routes a
//! value through an `f64`.
//!
//! This is a client of exactly one server (the Genesis-4 node), but it is
//! written as a general parser: escapes, nesting, whitespace, and a depth
//! bound so a hostile body cannot recurse the stack out.

use std::fmt::Write as _;

/// Maximum nesting depth accepted. The RPC's replies nest 3 deep; 64 is
/// paranoia, not a tuning knob.
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Invariant: valid JSON number literal, kept as source text.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    // ── Constructors ────────────────────────────────────────────────────────

    pub fn u(v: u64) -> Json {
        Json::Num(v.to_string())
    }
    pub fn s(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }
    pub fn hex(bytes: &[u8]) -> Json {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        Json::Str(s)
    }

    // ── Accessors ───────────────────────────────────────────────────────────

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn at(&self, idx: usize) -> Option<&Json> {
        match self {
            Json::Arr(items) => items.get(idx),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// `u64` from a JSON number. Strings are NOT accepted here — a field that
    /// is documented as a number must arrive as one.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(raw) => raw.parse().ok(),
            _ => None,
        }
    }

    /// Signed integer from a JSON number (JSON-RPC error codes are negative).
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Num(raw) => raw.parse().ok(),
            _ => None,
        }
    }

    /// A satoshi-denominated amount, per the V4 R3 rule: a **decimal string**.
    /// A bare JSON number is also accepted (defensively — the node does not
    /// emit them for amounts), because rejecting `10` where `"10"` was meant
    /// would fail closed on the wrong axis for a read.
    pub fn as_sat_u128(&self) -> Option<u128> {
        match self {
            Json::Str(s) => s.parse().ok(),
            Json::Num(raw) => raw.parse().ok(),
            _ => None,
        }
    }

    pub fn as_sat_u64(&self) -> Option<u64> {
        u64::try_from(self.as_sat_u128()?).ok()
    }

    // ── Emit ────────────────────────────────────────────────────────────────

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Num(raw) => out.push_str(raw),
            Json::Str(s) => write_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    // ── Parse ───────────────────────────────────────────────────────────────

    pub fn parse(text: &str) -> Result<Json, String> {
        let bytes = text.as_bytes();
        let mut pos = 0usize;
        let value = parse_value(bytes, &mut pos, 0)?;
        skip_ws(bytes, &mut pos);
        if pos != bytes.len() {
            return Err(format!("trailing bytes at offset {pos}"));
        }
        Ok(value)
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn skip_ws(b: &[u8], pos: &mut usize) {
    while *pos < b.len() && matches!(b[*pos], b' ' | b'\t' | b'\n' | b'\r') {
        *pos += 1;
    }
}

fn parse_value(b: &[u8], pos: &mut usize, depth: usize) -> Result<Json, String> {
    if depth > MAX_DEPTH {
        return Err("nesting too deep".into());
    }
    skip_ws(b, pos);
    let Some(&c) = b.get(*pos) else {
        return Err("unexpected end of input".into());
    };
    match c {
        b'{' => parse_object(b, pos, depth),
        b'[' => parse_array(b, pos, depth),
        b'"' => Ok(Json::Str(parse_string(b, pos)?)),
        b't' => parse_lit(b, pos, "true", Json::Bool(true)),
        b'f' => parse_lit(b, pos, "false", Json::Bool(false)),
        b'n' => parse_lit(b, pos, "null", Json::Null),
        b'-' | b'0'..=b'9' => parse_number(b, pos),
        other => Err(format!("unexpected byte {other:#04x} at offset {pos}", pos = *pos)),
    }
}

fn parse_lit(b: &[u8], pos: &mut usize, lit: &str, value: Json) -> Result<Json, String> {
    if b[*pos..].starts_with(lit.as_bytes()) {
        *pos += lit.len();
        Ok(value)
    } else {
        Err(format!("bad literal at offset {pos}", pos = *pos))
    }
}

fn parse_number(b: &[u8], pos: &mut usize) -> Result<Json, String> {
    let start = *pos;
    if b.get(*pos) == Some(&b'-') {
        *pos += 1;
    }
    let digits_from = *pos;
    while *pos < b.len() && b[*pos].is_ascii_digit() {
        *pos += 1;
    }
    if *pos == digits_from {
        return Err(format!("bad number at offset {start}"));
    }
    if b.get(*pos) == Some(&b'.') {
        *pos += 1;
        let frac_from = *pos;
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            *pos += 1;
        }
        if *pos == frac_from {
            return Err(format!("bad number at offset {start}"));
        }
    }
    if matches!(b.get(*pos), Some(b'e' | b'E')) {
        *pos += 1;
        if matches!(b.get(*pos), Some(b'+' | b'-')) {
            *pos += 1;
        }
        let exp_from = *pos;
        while *pos < b.len() && b[*pos].is_ascii_digit() {
            *pos += 1;
        }
        if *pos == exp_from {
            return Err(format!("bad number at offset {start}"));
        }
    }
    // The slice is ASCII by construction.
    Ok(Json::Num(String::from_utf8_lossy(&b[start..*pos]).into_owned()))
}

fn parse_string(b: &[u8], pos: &mut usize) -> Result<String, String> {
    debug_assert_eq!(b[*pos], b'"');
    *pos += 1;
    let mut out = String::new();
    loop {
        let Some(&c) = b.get(*pos) else {
            return Err("unterminated string".into());
        };
        *pos += 1;
        match c {
            b'"' => return Ok(out),
            b'\\' => {
                let Some(&esc) = b.get(*pos) else {
                    return Err("unterminated escape".into());
                };
                *pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hi = parse_hex4(b, pos)?;
                        let code = if (0xD800..0xDC00).contains(&hi) {
                            // Surrogate pair.
                            if b.get(*pos) != Some(&b'\\') || b.get(*pos + 1) != Some(&b'u') {
                                return Err("lone high surrogate".into());
                            }
                            *pos += 2;
                            let lo = parse_hex4(b, pos)?;
                            if !(0xDC00..0xE000).contains(&lo) {
                                return Err("bad low surrogate".into());
                            }
                            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                        } else {
                            hi
                        };
                        out.push(char::from_u32(code).ok_or("bad \\u escape")?);
                    }
                    other => return Err(format!("bad escape \\{}", other as char)),
                }
            }
            c if c < 0x20 => return Err("control byte in string".into()),
            c if c < 0x80 => out.push(c as char),
            _ => {
                // Multi-byte UTF-8: find the full sequence and validate it.
                let start = *pos - 1;
                let len = if c >= 0xF0 {
                    4
                } else if c >= 0xE0 {
                    3
                } else {
                    2
                };
                if start + len > b.len() {
                    return Err("truncated UTF-8 sequence".into());
                }
                let s = std::str::from_utf8(&b[start..start + len])
                    .map_err(|_| "bad UTF-8 in string")?;
                out.push_str(s);
                *pos = start + len;
            }
        }
    }
}

fn parse_hex4(b: &[u8], pos: &mut usize) -> Result<u32, String> {
    if *pos + 4 > b.len() {
        return Err("truncated \\u escape".into());
    }
    let mut v = 0u32;
    for i in 0..4 {
        let d = (b[*pos + i] as char).to_digit(16).ok_or("bad \\u escape")?;
        v = v * 16 + d;
    }
    *pos += 4;
    Ok(v)
}

fn parse_array(b: &[u8], pos: &mut usize, depth: usize) -> Result<Json, String> {
    *pos += 1; // '['
    let mut items = Vec::new();
    skip_ws(b, pos);
    if b.get(*pos) == Some(&b']') {
        *pos += 1;
        return Ok(Json::Arr(items));
    }
    loop {
        items.push(parse_value(b, pos, depth + 1)?);
        skip_ws(b, pos);
        match b.get(*pos) {
            Some(b',') => {
                *pos += 1;
            }
            Some(b']') => {
                *pos += 1;
                return Ok(Json::Arr(items));
            }
            _ => return Err(format!("expected ',' or ']' at offset {pos}", pos = *pos)),
        }
    }
}

fn parse_object(b: &[u8], pos: &mut usize, depth: usize) -> Result<Json, String> {
    *pos += 1; // '{'
    let mut fields = Vec::new();
    skip_ws(b, pos);
    if b.get(*pos) == Some(&b'}') {
        *pos += 1;
        return Ok(Json::Obj(fields));
    }
    loop {
        skip_ws(b, pos);
        if b.get(*pos) != Some(&b'"') {
            return Err(format!("expected object key at offset {pos}", pos = *pos));
        }
        let key = parse_string(b, pos)?;
        skip_ws(b, pos);
        if b.get(*pos) != Some(&b':') {
            return Err(format!("expected ':' at offset {pos}", pos = *pos));
        }
        *pos += 1;
        let value = parse_value(b, pos, depth + 1)?;
        fields.push((key, value));
        skip_ws(b, pos);
        match b.get(*pos) {
            Some(b',') => {
                *pos += 1;
            }
            Some(b'}') => {
                *pos += 1;
                return Ok(Json::Obj(fields));
            }
            _ => return Err(format!("expected ',' or '}}' at offset {pos}", pos = *pos)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_survive_as_text() {
        // 10^19 sat — past 2^53, the reason R3 exists. Must round-trip exactly.
        let v = Json::parse(r#"{"balance_sat":"10000000000000000000","slot":9007199254740993}"#)
            .unwrap();
        assert_eq!(v.get("balance_sat").unwrap().as_sat_u128(), Some(10_000_000_000_000_000_000));
        assert_eq!(v.get("slot").unwrap().as_u64(), Some(9007199254740993));
    }

    #[test]
    fn roundtrip() {
        let src = r#"{"a":[1,2.5,-3,"x\"y\\z\n"],"b":null,"c":true,"d":{"e":"café ⚡"}}"#;
        let v = Json::parse(src).unwrap();
        let emitted = v.to_json();
        assert_eq!(Json::parse(&emitted).unwrap(), v);
    }

    #[test]
    fn refuses_garbage() {
        for bad in ["", "{", "[1,", "\"abc", "{\"a\" 1}", "01x", "nul", "[1]2"] {
            assert!(Json::parse(bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn depth_bounded() {
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(Json::parse(&deep).is_err());
    }

    #[test]
    fn hex_helper() {
        assert_eq!(Json::hex(&[0x00, 0xff, 0x0a]), Json::Str("00ff0a".into()));
    }
}
