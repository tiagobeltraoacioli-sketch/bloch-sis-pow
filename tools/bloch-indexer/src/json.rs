// SPDX-License-Identifier: AGPL-3.0-or-later

//! A JSON writer, ~90 lines, because a value tree is all this needs.
//!
//! ## Every satoshi amount is a decimal string
//!
//! `BLOCH-RPC-V4.md` §0 R3, and the node's own RPC obeys it. Not for Rust's
//! benefit: `JSON.parse` turns every JSON number into an IEEE-754 double, exact
//! only to 2^53 - 1 = 9,007,199,254,740,991. The Genesis-4 cap is 10^19 sat —
//! 1,110× that — and the largest single carried address already holds
//! 354,617,540,000,000,000 sat, 39× past the limit. An index whose whole job is
//! to report balances cannot report them in a type that rounds them.
//!
//! So [`Json::sat`] takes a `u128` and emits `"354617540000000000"`. Heights,
//! slots, epochs, indices and counts stay numbers: they are small, and a
//! stringly-typed height helps nobody.

pub enum Json {
    Null,
    Bool(bool),
    Num(u64),
    /// A satoshi amount or other large integer, emitted as a decimal string.
    Sat(u128),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    pub fn u(v: u64) -> Json {
        Json::Num(v)
    }
    pub fn sat(v: u128) -> Json {
        Json::Sat(v)
    }
    pub fn s(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }
    pub fn hex32(v: &[u8; 32]) -> Json {
        Json::Str(crate::hex32(v))
    }

    pub fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Sat(n) => {
                out.push('"');
                out.push_str(&n.to_string());
                out.push('"');
            }
            Json::Str(s) => {
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
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
                    out.push('"');
                    out.push_str(k);
                    out.push_str("\":");
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    pub fn to_string(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }
}
