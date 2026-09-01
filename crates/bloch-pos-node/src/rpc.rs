// SPDX-License-Identifier: AGPL-3.0-or-later

//! JSON-RPC 2.0 over HTTP/1.1 — the Genesis-4 node's query and submission
//! surface.
//!
//! ## What this is a read layer over
//!
//! Everything answered here comes from the engine's committed state
//! (`CommittedState`) and its canonical chain. Nothing in this module decides
//! anything: it has no opinion about validity, it never writes state, and the
//! one method that *changes* anything (`sendrawtransaction`) does so by handing
//! bytes to the same `on_transaction` admission path a peer's gossip goes
//! through. That is deliberate, and it is the shape §5.5 asks for — a second
//! path into the mempool with its own checks would be the `expected_bits`
//! defect with a URL in front of it.
//!
//! ## Why there is no framework here
//!
//! The Genesis-3 node's RPC (`src/rpc/mod.rs` at the repo root) is axum + tower
//! + serde_json + tokio. This crate's dependency set is `bloch-pos-committee`,
//! `bloch-crypto` and `sha3` — it has no async runtime at all, and `net.rs` is
//! blocking `std::net` with one thread per connection. Pulling an async stack
//! in to serve nine read methods would add ~90 transitive crates and a runtime
//! to a node whose consensus loop is a single synchronous thread. So HTTP/1.1
//! and JSON are implemented here, in about 400 lines, against `std` only:
//! `serve` mirrors `net::start`'s accept-thread shape exactly.
//!
//! The cost is stated rather than hidden: this server speaks the subset of
//! HTTP/1.1 a JSON-RPC client needs (POST, `Content-Length`, no chunked
//! transfer-encoding, no keep-alive, no TLS, no compression). It is not a
//! general-purpose web server and must not become one.
//!
//! ## Conventions this obeys (`docs/specs/BLOCH-RPC-V4.md` §0)
//!
//! - **R3 — every satoshi-denominated field is a decimal string.** Not for
//!   Rust's benefit: the V4 cap is 10^19 sat, ~1110x JavaScript's 2^53 exact
//!   integer limit, so a JSON *number* is silently corrupted by every browser
//!   that reads it. [`Json::sat`] is the only way an amount leaves this module,
//!   and `amounts_are_decimal_strings_not_json_numbers` pins it.
//! - **R4 — failures are the top-level JSON-RPC `error` object**, never a
//!   `result.error` string under HTTP 200. The V3 convention forced a
//!   `ResultError` shim into both generated SDKs and the explorer; V4 is the
//!   one chance to not carry it forward.
//! - **R5 — `commission_bps` rides on every validator response.** Tokenomics
//!   V4 leaves commission uncapped on the explicit bet that clients surface the
//!   rate, which only works if the rate is always there to surface.
//!
//! ## Authentication: there is none
//!
//! No API key, no rate limit, no per-method authorisation — unlike the
//! Genesis-3 surface, which has all three (`src/rpc/auth.rs`). That is why
//! `--rpc-bind` defaults to `127.0.0.1` and why binding anything routable is an
//! explicit act that the help text pairs with a firewall instruction. The
//! bounds that *are* here are anti-exhaustion, not authorisation:
//! [`MAX_BODY_BYTES`], [`MAX_HEADER_BYTES`], [`MAX_CONNECTIONS`] and the socket
//! timeouts. They stop one client from consuming the node; they stop no one
//! from reading it.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bloch_pos_committee::header::{BlockEnvelope, BlockId};
use bloch_pos_committee::interfaces::{StateReader, ValidatorRecord};
use bloch_pos_committee::state_root::EutxoEntry;
use bloch_pos_committee::transition::{CommittedState, PosTransaction};
use bloch_pos_committee::{epoch_of, params::SLOTS_PER_EPOCH};

// ─── Limits (anti-exhaustion, not authorisation) ────────────────────────────

/// Largest request body accepted. A JSON-RPC call is a few hundred bytes; the
/// only method that can legitimately approach this is `sendrawtransaction`.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Largest request head (request line + headers) accepted before the body.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Connections served concurrently. Past this the listener answers 503 and
/// closes, rather than spawning threads until the process dies — the node's
/// consensus thread must survive its RPC port being hammered.
const MAX_CONNECTIONS: usize = 64;

/// Socket read/write timeout. A client that opens a connection and never
/// finishes a request must not hold a slot forever.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a request waits for the consensus thread to answer before giving
/// up. The engine services RPC between slot duties, so a request arriving while
/// a proposal is being signed waits for that signature; it should never wait
/// for a whole slot.
const ENGINE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default and maximum page size for [`RpcRequest::Utxos`].
const UTXO_PAGE_DEFAULT: usize = 100;
const UTXO_PAGE_MAX: usize = 1_000;

// ─── Errors ─────────────────────────────────────────────────────────────────
//
// # The error contract
//
// An integrator writes a client against these codes, so each one names **one
// cause**. A single generic "-32000: something went wrong" forces every caller
// to parse English to decide whether to retry, skip, or alert — which is the
// V3 defect R4 exists to end. The codes below are stable; the messages explain
// and may be reworded.
//
// | Code     | Name                     | Cause, and what a client should do |
// |----------|--------------------------|------------------------------------|
// | `-32700` | parse error              | Body was not JSON. Fix the client. |
// | `-32600` | invalid request          | JSON, but not a JSON-RPC 2.0 request object. |
// | `-32601` | method not found         | No such method in this build. |
// | `-32602` | invalid params           | Method exists, arguments do not fit (bad hex, missing field, out of range). |
// | `-32603` | internal error           | A bug in this node. Report it. |
// | `-32000` | `BLOCK_NOT_FOUND`        | No block with that id is known. Retry after syncing, or it never existed. |
// | `-32001` | `VALIDATOR_NOT_FOUND`    | Index is not in the committed registry. |
// | `-32002` | `TX_DECODE_FAILED`       | Bytes were valid hex but are not a canonical transaction. Do not retry unchanged. |
// | `-32003` | `MEMPOOL_FULL`           | Admission refused for capacity. Retry later — the transaction is not invalid. |
// | `-32004` | `NODE_UNAVAILABLE`       | Consensus thread did not answer, or is shutting down. Retry. |
// | `-32005` | `NO_TRANSACTION_INDEX`   | This build cannot look a transaction up by id — see [`RpcError::no_transaction_index`]. Not a transient failure. |
// | `-32006` | `NO_WALLET`              | This node holds no wallet and mints no addresses — see [`RpcError::no_wallet`]. Not a transient failure. |
// | `-32007` | `SLOT_EMPTY`             | The slot exists and carries no canonical block. **Normal under PoS** (a missed proposal); advance to the next slot. |

/// No block with that id is known to this node.
pub const BLOCK_NOT_FOUND: i64 = -32000;
/// The validator index is not in the committed registry.
pub const VALIDATOR_NOT_FOUND: i64 = -32001;
/// Valid hex, but not a canonical transaction encoding.
pub const TX_DECODE_FAILED: i64 = -32002;
/// The mempool is at capacity; the transaction itself was not judged invalid.
pub const MEMPOOL_FULL: i64 = -32003;
/// The consensus thread could not be reached.
pub const NODE_UNAVAILABLE: i64 = -32004;
/// There is no txid→block index (and, at this layer, no txid).
pub const NO_TRANSACTION_INDEX: i64 = -32005;
/// This node has no wallet and no frozen address format.
pub const NO_WALLET: i64 = -32006;
/// The slot carries no canonical block — a missed proposal, not an error state.
pub const SLOT_EMPTY: i64 = -32007;

/// The node refused a submitted transaction on its merits — it was judged
/// invalid, not deferred. Distinct from [`MEMPOOL_FULL`] because the client's
/// correct response is opposite: never resubmit these bytes.
pub const TX_REFUSED: i64 = -32008;

/// `getvalidatorstatus` on a node that holds no validator key. An observer
/// has no duties, so "is my validator working" has no referent — this code
/// says so instead of inventing an empty status a dashboard would render as
/// a broken validator.
pub const NO_VALIDATOR_KEY: i64 = -32009;

/// A JSON-RPC error object: a code a client can branch on and a message a human
/// can act on. Both halves are required — a bare code makes an operator read
/// this source file, and a bare message makes a client parse English.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError { code, message: message.into() }
    }

    /// -32700: the body was not JSON.
    pub fn parse_error(detail: &str) -> Self {
        Self::new(-32700, format!("parse error: {detail}"))
    }
    /// -32600: it was JSON, but not a JSON-RPC 2.0 request.
    pub fn invalid_request(detail: &str) -> Self {
        Self::new(-32600, format!("invalid request: {detail}"))
    }
    /// -32601: no such method on this node.
    pub fn method_not_found(method: &str) -> Self {
        Self::new(-32601, format!("method not found: {method}"))
    }
    /// -32602: the method exists, the arguments do not fit it.
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(-32602, format!("invalid params: {}", detail.into()))
    }
    /// [`NODE_UNAVAILABLE`]: the consensus thread could not be reached.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(NODE_UNAVAILABLE, detail.into())
    }

    /// [`NO_TRANSACTION_INDEX`] — `gettransaction`'s permanent answer in this
    /// build, and the reason is structural rather than a missing feature.
    ///
    /// A `PosTransaction` has **no transaction id at all** at this layer. The
    /// eUTXO value-transfer format is out of the migration's scope, so
    /// `Transfer` encodes `inputs`, `tx_bytes` and a tip — fee-market terms,
    /// with no sender, no recipient, no amount and no identity. Blocks commit
    /// to a `body_root` over the canonical *bytes*, and the store is an
    /// append-only block log with no secondary index.
    ///
    /// So there is nothing to hash into a txid and nothing to look one up in.
    /// Returning a synthesised digest of the canonical bytes would produce an
    /// identifier that no other node, block or client agrees on — an integrator
    /// would build deposit crediting on it and it would mean nothing. Saying
    /// the capability is absent is the only honest answer, and it is why this
    /// is a distinct code and not [`BLOCK_NOT_FOUND`].
    pub fn no_transaction_index() -> Self {
        Self::new(
            NO_TRANSACTION_INDEX,
            "this node cannot look up a transaction by id: at Genesis-4's current \
             layer a transaction carries no id (the transfer format is not yet \
             specified — `PosTransaction::Transfer` encodes only fee-market terms), \
             and the block store keeps no txid index. Track deposits by scanning \
             blocks via `getblockbyslot` and reading the eUTXO set via `getbalance` \
             / `listunspent`, both of which are exact. This is a permanent answer \
             for this build, not a transient failure — do not retry.",
        )
    }

    /// [`NO_WALLET`] — `getnewaddress` cannot be served, on two independent
    /// grounds, and neither is a scheduling accident.
    ///
    /// First: **a node RPC must never mint keys.** Key generation belongs in a
    /// wallet the operator controls; a node that mints a keypair on an
    /// unauthenticated port and hands back an address has generated key
    /// material in an observable session, with no record of who asked. Rule
    /// zero of `BLOCH-GENESIS-KEYS.md` puts production key generation on an
    /// air-gapped machine operated by a human, and this port is the opposite of
    /// that in every respect.
    ///
    /// Second, and it would block the method even if the first did not:
    /// Genesis-4 has **no frozen address format**. `withdrawal_credentials` is
    /// declared as opaque bytes precisely because the address format belongs to
    /// a transaction layer that does not exist yet (recorded as an open point in
    /// `BLOCH-POS-INTERFACES.md`). There is no string this method could return
    /// that a later build would still honour.
    pub fn no_wallet() -> Self {
        Self::new(
            NO_WALLET,
            "this node holds no wallet and does not generate addresses. Two reasons, \
             both permanent for this build: a node RPC must never mint key material \
             (production keys are generated by a human on an air-gapped machine, per \
             BLOCH-GENESIS-KEYS.md), and Genesis-4 has not frozen an address format \
             yet — `withdrawal_credentials` is opaque bytes by declaration, so any \
             address returned here could not be honoured later. Generate deposit \
             addresses in your own wallet and watch them with `getbalance` / \
             `listunspent`, which take a 32-byte script hash.",
        )
    }
}

pub type RpcResult = Result<Json, RpcError>;

// ─── Minimal JSON ───────────────────────────────────────────────────────────

/// A JSON value.
///
/// Numbers are held as their **raw source text** rather than as `f64`. That is
/// the whole R3 concern in the type system: an id of `9007199254740993` or a
/// satoshi amount must survive a round trip, and it cannot if it passes through
/// a double. This layer never does arithmetic on a parsed number, so the raw
/// token is not merely sufficient — it is strictly more faithful.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Invariant: always a valid JSON number literal.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// An unsigned integer, as a JSON number. For counts, slots, epochs and
    /// indexes — never for satoshis (see [`Json::sat`]).
    pub fn u(n: u64) -> Json {
        Json::Num(n.to_string())
    }

    /// A satoshi amount, as a decimal **string** (R3).
    ///
    /// `u128` in, string out, with no lossy step anywhere between: the
    /// consensus types carry `u128` because sums of balances wrap `u64`, and
    /// the wire carries a string because 10^19 does not fit a double. Every
    /// satoshi-denominated field in this module goes through here.
    pub fn sat(v: u128) -> Json {
        Json::Str(v.to_string())
    }

    pub fn s(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }

    pub fn hex(b: &[u8; 32]) -> Json {
        Json::Str(crate::codec::hex32(b))
    }

    pub fn obj(fields: Vec<(&str, Json)>) -> Json {
        Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The value as a `u64`, from either a JSON number or a decimal string.
    ///
    /// Strings are accepted because R3 makes every client string-minded about
    /// large integers; refusing `"41290"` for a slot would be gratuitous.
    /// Non-integers (`1.5`, `1e3`) are refused rather than truncated.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(raw) => raw.parse().ok(),
            Json::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Reads a boolean. Production code reads it too now — the GET /health
    /// endpoint branches its status code on `health.stalled` — so the old
    /// `#[cfg(test)]` gate is gone.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn at(&self, i: usize) -> Option<&Json> {
        match self {
            Json::Arr(items) => items.get(i),
            _ => None,
        }
    }

    /// Serialise. Total: every `Json` has a rendering, so this cannot fail.
    pub fn write(&self, out: &mut String) {
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

    pub fn to_string(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
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
            // Every other control character must be escaped or the output is
            // not JSON. Non-ASCII passes through as UTF-8, which is legal and
            // avoids a surrogate-encoding step nothing here needs.
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Nesting depth accepted while parsing.
///
/// This is a stack-overflow bound, not a taste judgement: the parser is
/// recursive, and `[[[[[…` repeated far enough aborts the *process* — which on
/// a validator means an unauthenticated request killing a node. A depth limit
/// is the fix; `deeply_nested_json_is_refused_not_fatal` pins it.
const MAX_DEPTH: u32 = 64;

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: u32,
}

/// Parse one JSON value from `text`, which must contain nothing else.
pub fn parse_json(text: &str) -> Result<Json, &'static str> {
    let mut p = Parser { b: text.as_bytes(), i: 0, depth: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err("trailing bytes after the top-level value");
    }
    Ok(v)
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Result<Json, &'static str> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("nesting too deep");
        }
        let v = match self.peek().ok_or("unexpected end of input")? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(Json::Str),
            b't' => {
                if self.eat(b"true") {
                    Ok(Json::Bool(true))
                } else {
                    Err("invalid literal")
                }
            }
            b'f' => {
                if self.eat(b"false") {
                    Ok(Json::Bool(false))
                } else {
                    Err("invalid literal")
                }
            }
            b'n' => {
                if self.eat(b"null") {
                    Ok(Json::Null)
                } else {
                    Err("invalid literal")
                }
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err("unexpected character"),
        };
        self.depth -= 1;
        v
    }

    fn object(&mut self) -> Result<Json, &'static str> {
        self.i += 1; // '{'
        let mut fields = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err("object key must be a string");
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err("expected ':' after object key");
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            fields.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err("expected ',' or '}' in object"),
            }
        }
    }

    fn array(&mut self) -> Result<Json, &'static str> {
        self.i += 1; // '['
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err("expected ',' or ']' in array"),
            }
        }
    }

    fn string(&mut self) -> Result<String, &'static str> {
        self.i += 1; // opening quote
        let mut s = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            // A lone surrogate is not a character. Pair it when
                            // the low half follows, and otherwise substitute
                            // U+FFFD — never fail, and never panic on a
                            // `char::from_u32` of a surrogate.
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b[self.i..].starts_with(b"\\u") {
                                    let save = self.i;
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                    } else {
                                        self.i = save;
                                        0xFFFD
                                    }
                                } else {
                                    0xFFFD
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                0xFFFD
                            } else {
                                hi
                            };
                            s.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err("invalid escape"),
                    }
                }
                // Raw control characters are illegal inside a JSON string.
                0x00..=0x1F => return Err("control character in string"),
                // UTF-8 continuation: copy the whole sequence verbatim. The
                // input is a `&str`, so it is already valid UTF-8 and the
                // boundary walk cannot land mid-character.
                _ => {
                    let start = self.i - 1;
                    while self.b.get(self.i).is_some_and(|b| b & 0xC0 == 0x80) {
                        self.i += 1;
                    }
                    match std::str::from_utf8(&self.b[start..self.i]) {
                        Ok(chunk) => s.push_str(chunk),
                        Err(_) => return Err("invalid utf-8 in string"),
                    }
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, &'static str> {
        let bytes = self.b.get(self.i..self.i + 4).ok_or("truncated \\u escape")?;
        let text = std::str::from_utf8(bytes).map_err(|_| "invalid \\u escape")?;
        let v = u32::from_str_radix(text, 16).map_err(|_| "invalid \\u escape")?;
        self.i += 4;
        Ok(v)
    }

    fn number(&mut self) -> Result<Json, &'static str> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        // The integer part is `0` or `[1-9][0-9]*` — JSON forbids leading
        // zeros, and accepting `01` would make this parser more permissive than
        // the grammar every client encodes against. That matters more here than
        // it looks: a number with two spellings is a value with two encodings,
        // and this module's whole reason for keeping numeric *text* is that a
        // request id and an amount must round-trip as written.
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err("number has a leading zero");
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err("number has no integer part"),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err("number has no fractional digits");
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err("number has no exponent digits");
            }
        }
        // Valid UTF-8 by construction: the slice is ASCII digits and signs.
        Ok(Json::Num(String::from_utf8_lossy(&self.b[start..self.i]).into_owned()))
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }
}

// ─── Hex ────────────────────────────────────────────────────────────────────

/// Decode a hex string (optionally `0x`-prefixed). `None` on any malformed
/// input — odd length, non-hex digit — rather than a partial decode.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn hex32_from(s: &str) -> Option<[u8; 32]> {
    let bytes = from_hex(s)?;
    bytes.try_into().ok()
}

// ─── The request surface ────────────────────────────────────────────────────

/// A decoded call, with its arguments already validated into node types.
///
/// The dispatcher turns JSON into one of these and the engine turns one of
/// these into JSON. Neither half handles the other's failure modes: by the time
/// a request reaches the engine, "the slot was not a number" has already been
/// answered, and by the time a reply reaches the dispatcher, "no such block"
/// has already been decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcRequest {
    ChainInfo,
    /// `getblockcount` — the polling method, carrying finality with it.
    BlockCount,
    BlockBySlot(u64),
    BlockById([u8; 32]),
    Validator(u32),
    ValidatorCount,
    Balance([u8; 32]),
    Utxos { script_hash: [u8; 32], limit: usize },
    /// `gettxout` — is this ONE output still unspent?
    ///
    /// Exists because `listunspent` cannot answer it. That method takes a
    /// script hash and a limit, has no cursor, and caps at `UTXO_PAGE_MAX`
    /// (1,000). The founder's script hash holds 425,568 outputs on the live
    /// chain, so 424,568 of them are unreachable through it: the same first
    /// page comes back every time.
    ///
    /// That gap has a consequence beyond convenience. The vesting-lock flag day
    /// has a go/no-go precondition — the founder and team allocation outpoints
    /// must still be unspent when the rule arms, or the lock seeds nothing and
    /// silently never exists for that bucket. The runbook asks an operator to
    /// confirm that by RPC, and until this method existed no such query was
    /// possible. A holder also could not audit their own position beyond an
    /// aggregate balance and an arbitrary first thousand outputs.
    ///
    /// **That precondition was measured on 2026-08-31, and it FAILED**: all
    /// five allocation outpoints answer `unspent: false` on three fleet nodes
    /// at a consistent head (slot 51,184, epoch 1,599), and the founder
    /// script's balance stood at ~37.94B BLOCH against the ~56.05B it opened
    /// with. The seeding machinery exists and ships inert
    /// (`params::VESTING_LOCK_ACTIVATION_EPOCH = u64::MAX`); arming it on
    /// this chain locks nothing unless the buckets are first returned to the
    /// pinned outpoints (`bloch_pos_committee::vesting::seed_targets`).
    ///
    /// Read-only: no consensus surface, no flag day.
    TxOut { txid: [u8; 32], vout: u32 },
    /// A transaction that **already decoded**.
    ///
    /// Decoding happens at this edge, not in the engine, for the same reason
    /// `net::decode_event` decodes at the network edge: bytes this build cannot
    /// read must never reach the mempool, because a proposer would then commit
    /// to a body it cannot reproduce. It also means "these bytes are not a
    /// transaction" is answered as `invalid params` by a pure function, which
    /// is what makes it testable without standing up a node.
    SendRawTransaction(PosTransaction),
    MempoolInfo,
    /// `getvalidatorstatus` — the status of THE validator key this node
    /// holds: registry state, duty-roster membership, next duty slots,
    /// whether recent attestations landed on chain, the signing-guard
    /// watermarks and the doppelganger watch. The first question a
    /// third-party operator asks — "is my validator working" — answered
    /// without SSH and without reading source. Node-local observability:
    /// nothing in consensus reads any of it.
    ValidatorStatus,
    /// `getmetrics` / `GET /metrics` — the same numbers as a Prometheus
    /// text exposition ([`MetricsSnapshot`]). One snapshot, taken on the
    /// engine thread, so every series in one scrape describes the same
    /// instant.
    Metrics,
}

/// Whatever can answer an [`RpcRequest`]. In production this is the channel to
/// the consensus thread; in tests it is a stub, which is the point — the HTTP
/// and JSON layers are exercised without standing up a node.
pub trait RpcBackend: Send + Sync + 'static {
    fn call(&self, req: RpcRequest) -> RpcResult;
}

/// One in-flight request handed to the consensus thread, with the channel it
/// must answer on.
pub struct RpcCall {
    pub req: RpcRequest,
    pub reply: Sender<RpcResult>,
}

/// The production backend: hand the request to the engine's event loop and wait.
///
/// Reads go through the consensus thread rather than through a shared snapshot
/// of state, and that is a deliberate cost. The engine's whole design is "one
/// thread owns all consensus state; nothing else mutates it"; a cached
/// state-shaped copy updated alongside is a second source of truth that can
/// drift, which is the `expected_bits` failure in miniature. Serialising queries
/// behind the loop means a query can never observe a half-applied block, and it
/// means no reader can be looking at last epoch's answer.
pub struct EngineBackend {
    /// `Mutex` because `mpsc::Sender` only became `Sync` in Rust 1.72 and this
    /// crate pins no MSRV. The lock is held exactly long enough to clone.
    engine: Mutex<Sender<crate::engine::EngineEvent>>,
}

impl EngineBackend {
    pub fn new(engine: Sender<crate::engine::EngineEvent>) -> Self {
        EngineBackend { engine: Mutex::new(engine) }
    }
}

impl RpcBackend for EngineBackend {
    fn call(&self, req: RpcRequest) -> RpcResult {
        let (tx, rx) = mpsc::channel::<RpcResult>();
        let sender = match self.engine.lock() {
            Ok(guard) => guard.clone(),
            // Poisoned only if a thread panicked while holding it. The channel
            // itself is still fine, but saying so honestly beats unwrapping.
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if sender.send(crate::engine::EngineEvent::Rpc(RpcCall { req, reply: tx })).is_err() {
            return Err(RpcError::unavailable("node is shutting down"));
        }
        match rx.recv_timeout(ENGINE_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(RpcError::unavailable(format!(
                "consensus thread did not answer within {}s",
                ENGINE_TIMEOUT.as_secs()
            ))),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(RpcError::unavailable("node is shutting down"))
            }
        }
    }
}

// ─── Dispatch ───────────────────────────────────────────────────────────────

/// Read argument `pos` (positional) or `name` (named). Supporting both costs
/// four lines and spares every client the guess.
fn pick<'a>(params: Option<&'a Json>, pos: usize, name: &str) -> Option<&'a Json> {
    match params? {
        arr @ Json::Arr(_) => arr.at(pos),
        obj @ Json::Obj(_) => obj.get(name),
        _ => None,
    }
}

fn want_u64(params: Option<&Json>, pos: usize, name: &str) -> Result<u64, RpcError> {
    pick(params, pos, name)
        .ok_or_else(|| RpcError::invalid_params(format!("missing `{name}`")))?
        .as_u64()
        .ok_or_else(|| {
            RpcError::invalid_params(format!("`{name}` must be a non-negative integer"))
        })
}

fn want_u32(params: Option<&Json>, pos: usize, name: &str) -> Result<u32, RpcError> {
    let v = want_u64(params, pos, name)?;
    u32::try_from(v).map_err(|_| {
        RpcError::invalid_params(format!("`{name}` must fit in 32 bits (got {v})"))
    })
}

fn want_hex32(params: Option<&Json>, pos: usize, name: &str) -> Result<[u8; 32], RpcError> {
    let raw = pick(params, pos, name)
        .ok_or_else(|| RpcError::invalid_params(format!("missing `{name}`")))?
        .as_str()
        .ok_or_else(|| RpcError::invalid_params(format!("`{name}` must be a hex string")))?;
    hex32_from(raw).ok_or_else(|| {
        RpcError::invalid_params(format!("`{name}` must be 32 bytes of hex (64 characters)"))
    })
}

/// Turn a method name and its params into a request, or say precisely why not.
///
/// # The exchange-integration surface
///
/// Six of these names are the ones a Genesis-3 integration already calls, kept
/// verbatim so a client ports by re-pointing its endpoint rather than by being
/// rewritten. Each is mapped to the PoS model without inventing semantics:
///
/// - `getbalance`, `listunspent` — read the eUTXO set out of `CommittedState`.
///   `listunspent` is the same request as `getutxos`; two names, one meaning,
///   because inventing a second semantics for the second name is how a client
///   ends up with two disagreeing balances.
/// - `getblockcount` — canonical height, plus the slot/epoch it sits at and the
///   finality that height is entitled to (see [`block_count_json`]).
/// - `sendrawtransaction` — canonical bytes in, mempool admission out.
/// - `gettransaction` — **refused**, with [`RpcError::no_transaction_index`].
///   There is no txid at this layer to look up, and approximating one would be
///   worse than the absence.
/// - `getnewaddress` — **refused**, with [`RpcError::no_wallet`]. A node RPC
///   does not mint key material, and no address format is frozen.
///
/// The refusals are routed here, as methods that exist and answer, rather than
/// left to fall through to `method not found`. The distinction is the whole
/// point: "this node cannot do that, here is why, do not retry" is actionable,
/// and "no such method" would send an integrator looking for a newer build.
pub fn route(method: &str, params: Option<&Json>) -> Result<RpcRequest, RpcError> {
    Ok(match method {
        "getchaininfo" => RpcRequest::ChainInfo,
        "getblockcount" => RpcRequest::BlockCount,
        "getblockbyslot" => RpcRequest::BlockBySlot(want_u64(params, 0, "slot")?),
        "getblockbyid" => RpcRequest::BlockById(want_hex32(params, 0, "block_id")?),
        "getvalidator" => RpcRequest::Validator(want_u32(params, 0, "index")?),
        "getvalidatorcount" => RpcRequest::ValidatorCount,
        "getbalance" => RpcRequest::Balance(want_hex32(params, 0, "script_hash")?),
        // Refused on purpose, and permanently for this build. See the doc
        // comments on the two constructors for the full reasoning.
        "gettransaction" => return Err(RpcError::no_transaction_index()),
        "getnewaddress" => return Err(RpcError::no_wallet()),
        "gettxout" => {
            let txid = want_hex32(params, 0, "txid")?;
            let vout = match pick(params, 1, "vout") {
                None | Some(Json::Null) => 0,
                Some(v) => {
                    let n = v.as_u64().ok_or_else(|| {
                        RpcError::invalid_params("`vout` must be a non-negative integer")
                    })?;
                    u32::try_from(n).map_err(|_| {
                        RpcError::invalid_params("`vout` does not fit in 32 bits")
                    })?
                }
            };
            RpcRequest::TxOut { txid, vout }
        }
        "getutxos" | "listunspent" => {
            let script_hash = want_hex32(params, 0, "script_hash")?;
            let limit = match pick(params, 1, "limit") {
                None | Some(Json::Null) => UTXO_PAGE_DEFAULT,
                Some(v) => {
                    let n = v.as_u64().ok_or_else(|| {
                        RpcError::invalid_params("`limit` must be a non-negative integer")
                    })?;
                    (n as usize).clamp(1, UTXO_PAGE_MAX)
                }
            };
            RpcRequest::Utxos { script_hash, limit }
        }
        "sendrawtransaction" => {
            let raw = pick(params, 0, "hex")
                .ok_or_else(|| RpcError::invalid_params("missing `hex`"))?
                .as_str()
                .ok_or_else(|| {
                    RpcError::invalid_params("`hex` must be a hex string of the canonical bytes")
                })?;
            let bytes = from_hex(raw)
                .ok_or_else(|| RpcError::invalid_params("`hex` is not valid hexadecimal"))?;
            if bytes.is_empty() {
                return Err(RpcError::invalid_params("`hex` decoded to zero bytes"));
            }
            // Two distinct causes, two distinct codes: bad hex above is a
            // client-side encoding mistake (-32602), while hex that decodes to
            // bytes which are not a canonical transaction is a different
            // failure the client must not retry unchanged (TX_DECODE_FAILED).
            let tx = PosTransaction::from_canonical_bytes(&bytes).map_err(|e| {
                RpcError::new(
                    TX_DECODE_FAILED,
                    format!("not a canonical Genesis-4 transaction: {e}"),
                )
            })?;
            RpcRequest::SendRawTransaction(tx)
        }
        "getmempoolinfo" => RpcRequest::MempoolInfo,
        "getvalidatorstatus" => RpcRequest::ValidatorStatus,
        // The JSON-RPC spelling of the scrape surface, for clients behind a
        // POST-only proxy (the public g4rpc forwards JSON-RPC bodies, not
        // arbitrary GETs). The result is the exposition text as one string.
        "getmetrics" => RpcRequest::Metrics,
        other => return Err(RpcError::method_not_found(other)),
    })
}

fn envelope(id: Json, outcome: RpcResult) -> String {
    let body = match outcome {
        Ok(result) => Json::Obj(vec![
            ("jsonrpc".into(), Json::s("2.0")),
            ("id".into(), id),
            ("result".into(), result),
        ]),
        // R4: failures are the top-level `error` object, never a string inside
        // `result` under HTTP 200.
        Err(e) => Json::Obj(vec![
            ("jsonrpc".into(), Json::s("2.0")),
            ("id".into(), id),
            (
                "error".into(),
                Json::obj(vec![
                    ("code", Json::Num(e.code.to_string())),
                    ("message", Json::s(e.message)),
                ]),
            ),
        ]),
    };
    body.to_string()
}

/// Handle one request body and return one response body.
///
/// Total on every input: any byte string produces a JSON-RPC response, and no
/// input path can panic. That is the property `malformed_input_never_panics`
/// exercises, and it is not a nicety — this is an unauthenticated port, so
/// "malformed input crashes the node" and "anyone can stop the validator" are
/// the same sentence.
pub fn handle_body(body: &str, backend: &dyn RpcBackend) -> String {
    let request = match parse_json(body) {
        Ok(v) => v,
        Err(why) => return envelope(Json::Null, Err(RpcError::parse_error(why))),
    };

    if matches!(request, Json::Arr(_)) {
        return envelope(
            Json::Null,
            Err(RpcError::invalid_request(
                "batch requests are not supported; send one call per request",
            )),
        );
    }
    if !matches!(request, Json::Obj(_)) {
        return envelope(
            Json::Null,
            Err(RpcError::invalid_request("a request must be a JSON object")),
        );
    }

    // Echo the id whatever it is, including absent (null). A client correlating
    // responses must get its id back even when the rest of the request was
    // nonsense — that is the only thing tying an error to the call that caused
    // it. Ids that are objects or arrays are out of spec but are echoed rather
    // than rewritten, because rewriting one breaks correlation silently.
    let id = request.get("id").cloned().unwrap_or(Json::Null);

    if let Some(v) = request.get("jsonrpc") {
        if v.as_str() != Some("2.0") {
            return envelope(id, Err(RpcError::invalid_request("`jsonrpc` must be \"2.0\"")));
        }
    }

    let Some(method) = request.get("method").and_then(Json::as_str) else {
        return envelope(id, Err(RpcError::invalid_request("`method` must be a string")));
    };

    let params = request.get("params").filter(|p| !matches!(p, Json::Null));
    let outcome = route(method, params).and_then(|req| backend.call(req));
    envelope(id, outcome)
}

// ─── HTTP/1.1, the subset a JSON-RPC client uses ────────────────────────────

/// Start the RPC server on `bind_addr:port` and return the address it actually
/// bound (which is how a test asks for port 0 and learns what it got).
///
/// # Exposure
///
/// This server authenticates nothing. `bind_addr` is `127.0.0.1` unless the
/// operator passed `--rpc-bind`, and a routable bind must be firewalled to the
/// clients that are meant to reach it. `sendrawtransaction` is a write, so an
/// open port is not merely a read leak.
pub fn serve(
    bind_addr: &str,
    port: u16,
    backend: Arc<dyn RpcBackend>,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind((bind_addr, port))?;
    let local = listener.local_addr()?;
    let live = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(sock) = conn else { continue };
            // Reserve a slot before spawning: incrementing inside the thread
            // would let an unbounded burst spawn first and count later.
            if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                live.fetch_sub(1, Ordering::SeqCst);
                let mut sock = sock;
                let _ = respond(&mut sock, 503, "{\"error\":\"too many connections\"}");
                continue;
            }
            let backend = backend.clone();
            let live = live.clone();
            thread::spawn(move || {
                let mut sock = sock;
                serve_connection(&mut sock, backend.as_ref());
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(local)
}

fn serve_connection(sock: &mut TcpStream, backend: &dyn RpcBackend) {
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
    match read_request(sock) {
        Ok(HttpRequest::Post(body)) => {
            // The body must be text before it can be JSON. Invalid UTF-8 is a
            // parse error with a JSON-RPC shape, not a dropped connection.
            let response = match std::str::from_utf8(&body) {
                Ok(text) => handle_body(text, backend),
                Err(_) => envelope(Json::Null, Err(RpcError::parse_error("body is not UTF-8"))),
            };
            let _ = respond(sock, 200, &response);
        }
        Ok(HttpRequest::Get(path)) => serve_get(sock, &path, backend),
        Err(HttpError { status, message }) => {
            let _ = respond(sock, status, &envelope(Json::Null, Err(RpcError::invalid_request(message))));
        }
    }
}

/// The two GET endpoints. Both are answered by the SAME engine thread that
/// answers JSON-RPC — deliberately, twice over: the numbers describe one
/// consistent instant, and the scrape doubles as a liveness probe of the
/// consensus loop itself. If the loop is wedged hard enough that it cannot
/// answer within [`ENGINE_TIMEOUT`], the scrape fails and the monitoring sees
/// a down target — which is the truth. (The measured 2026-08 stall was NOT
/// that shape: its loop kept running and will answer; the `stalled` flag it
/// serves is what says the node is broken.)
fn serve_get(sock: &mut TcpStream, path: &str, backend: &dyn RpcBackend) {
    match path {
        "/metrics" => match backend.call(RpcRequest::Metrics) {
            Ok(Json::Str(text)) => {
                let _ = respond_typed(sock, 200, PROM_CONTENT_TYPE, &text);
            }
            Ok(_) => {
                let _ = respond_typed(sock, 500, "text/plain", "metrics backend returned a non-text value\n");
            }
            Err(e) => {
                let _ = respond_typed(sock, 503, "text/plain", &format!("{}\n", e.message));
            }
        },
        "/health" => match backend.call(RpcRequest::ChainInfo) {
            Ok(info) => {
                let health = info.get("health").cloned().unwrap_or(Json::Null);
                let stalled = health.get("stalled").and_then(Json::as_bool).unwrap_or(false);
                // 503 when stalled: a load balancer or an exchange's deposit
                // gate takes the node out of rotation on status code alone,
                // no JSON parsing required. The body carries the health
                // object either way for the human who curls it.
                let status = if stalled { 503 } else { 200 };
                let _ = respond(sock, status, &health.to_string());
            }
            Err(e) => {
                let _ = respond(sock, 503, &envelope(Json::Null, Err(e)));
            }
        },
        _ => {
            let _ = respond_typed(
                sock,
                404,
                "text/plain",
                "not found; GET serves /metrics and /health, everything else is JSON-RPC over POST\n",
            );
        }
    }
}

struct HttpError {
    status: u16,
    message: &'static str,
}

fn http_err(status: u16, message: &'static str) -> HttpError {
    HttpError { status, message }
}

/// One parsed HTTP request: a JSON-RPC POST body, or a GET path.
///
/// GET exists for the two operational endpoints only — `/metrics`
/// (Prometheus text exposition) and `/health` (load-balancer / liveness
/// probe). Everything else on this server is JSON-RPC over POST, and GETs to
/// any other path are answered 404 rather than routed anywhere near the RPC
/// dispatch: a scrape surface must not become a second, unaudited query
/// surface by accident.
enum HttpRequest {
    Post(Vec<u8>),
    Get(String),
}

/// Read one HTTP request: the body of a POST, or the path of a GET.
fn read_request(sock: &mut TcpStream) -> Result<HttpRequest, HttpError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];

    // Head: read until CRLFCRLF, bounded.
    let head_end = loop {
        if let Some(p) = find_head_end(&buf) {
            break p;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(http_err(431, "request header too large"));
        }
        match sock.read(&mut chunk) {
            Ok(0) => return Err(http_err(400, "connection closed before the request head ended")),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(http_err(408, "timed out reading the request head")),
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let verb = parts.next().unwrap_or("");
    if verb.eq_ignore_ascii_case("GET") {
        // Strip any query string: a scraper that appends `?…` still means
        // the same endpoint, and the endpoints here take no parameters.
        let path = parts.next().unwrap_or("");
        let path = path.split('?').next().unwrap_or("").to_string();
        return Ok(HttpRequest::Get(path));
    }
    if !verb.eq_ignore_ascii_case("POST") {
        return Err(http_err(
            405,
            "this endpoint accepts POST (JSON-RPC) and GET /metrics or /health",
        ));
    }

    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            // Chunked bodies are not implemented. Saying so beats reading the
            // chunk headers as if they were JSON.
            return Err(http_err(411, "chunked transfer-encoding is not supported; send Content-Length"));
        }
    }
    let Some(len) = content_length else {
        return Err(http_err(411, "Content-Length is required"));
    };
    if len > MAX_BODY_BYTES {
        return Err(http_err(413, "request body too large"));
    }

    // Body: whatever already arrived with the head, plus the rest.
    let mut body = buf[head_end + 4..].to_vec();
    body.truncate(len);
    while body.len() < len {
        match sock.read(&mut chunk) {
            Ok(0) => return Err(http_err(400, "connection closed before the body was complete")),
            Ok(n) => {
                let want = len - body.len();
                body.extend_from_slice(&chunk[..n.min(want)]);
            }
            Err(_) => return Err(http_err(408, "timed out reading the request body")),
        }
    }
    Ok(HttpRequest::Post(body))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn respond(sock: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    respond_typed(sock, status, "application/json", body)
}

/// The Prometheus text exposition content type, version pinned — the same
/// string the pool proxy's exporter serves (`pool-proxy/src/metrics.rs`),
/// because two exporters in one project answering with two content types is
/// how a scraper config works against one of them by luck.
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

fn respond_typed(sock: &mut TcpStream, status: u16, content_type: &str, body: &str) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    // `Connection: close` because this server does not implement keep-alive:
    // one request per connection, and the client is told so instead of being
    // left waiting on a socket that will never answer again.
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes())?;
    sock.write_all(body.as_bytes())?;
    sock.flush()
}

// ─── Formatting: pure projections of committed state ────────────────────────
//
// Free functions of their arguments, not methods on the engine, for the reason
// §5.5 gives and `engine::lmd_ghost_head` follows: a value a client will read
// must be derivable from its inputs so it can be tested without standing up a
// node. Every one of them is exercised below against a real `CommittedState`.

/// Slots behind the wall clock beyond which a node counts as *behind* rather
/// than merely between blocks.
///
/// The number is chosen against this chain's measured cadence, not against an
/// ideal one. Genesis-4 fills roughly 13% of its slots (post-migration
/// measurement), so a healthy, fully-synced node routinely sits many slots
/// behind the wall clock simply because the slots in between are empty. At
/// 13% cadence an empty stretch of 64 slots (two epochs, 32 minutes) occurs
/// about once every three weeks; every shorter threshold fires weekly or
/// daily. And when the *chain itself* goes quiet for two epochs, "this node
/// is not making progress" is a true statement an operator wants to see —
/// the false-positive case is itself alert-worthy.
///
/// Against the incident this exists for: the stalled nodes were ~480 slots
/// behind (4 hours), and even the ones that recovered were 90–130 behind.
/// Both are far past this line.
pub const HEALTH_BEHIND_SLOTS: u64 = 64;

/// Apply-silence, in slots' worth of wall time, beyond which *behind*
/// hardens into *stalled*.
///
/// A node 480 slots behind that is actually syncing applies blocks
/// continuously — its silence is measured in milliseconds. One that has
/// applied nothing for eight slots (four minutes at the 30s cadence) while
/// two epochs behind is not slow, it is stuck: that is exactly the shape of
/// the post-replay stall this field exists to expose, which was previously
/// diagnosable only by shelling in and watching a log not grow.
pub const HEALTH_SILENCE_SLOTS: u64 = 8;

/// The node's own liveness verdict: is it keeping up with the wall clock,
/// and if not, is it at least making progress toward it?
///
/// # Why this exists
///
/// The post-replay sync stall (2026-08, production): a node finishes replay
/// far behind the live head and then stops — peers connected, RPC answering,
/// zero blocks applied, zero log lines. To a monitor reading `height` it
/// looks like an ordinary laggard; to `behind_by_slots` alone it looks like
/// a syncing node. The distinction that matters — *behind and advancing*
/// versus *behind and dead* — needs both the lag and the time since the last
/// applied block, judged together. This type is that judgement, made once,
/// as a pure function, so the RPC field, the periodic log line and the tests
/// all report the same verdict.
///
/// # What the verdict means
///
/// - `syncing`: behind the wall clock by at least [`HEALTH_BEHIND_SLOTS`]
///   but a block was applied within the last [`HEALTH_SILENCE_SLOTS`] slots'
///   worth of time — catching up, leave it alone.
/// - `stalled`: behind by at least [`HEALTH_BEHIND_SLOTS`] AND no block
///   applied for [`HEALTH_SILENCE_SLOTS`] slots' worth of time — **not
///   making progress**. This is the boolean an integrator should alert on,
///   and the one an exchange observer node should stop crediting deposits
///   on. It self-clears the moment a block is applied or the lag closes.
///
/// The two raw inputs are carried alongside the verdict so a consumer with a
/// different risk posture can apply its own thresholds.
///
/// # One honest limitation
///
/// A node cannot locally distinguish "I am deaf" from "the whole chain went
/// quiet": if no canonical block exists for two epochs anywhere, every
/// healthy node reports `stalled` too. That is accepted — a chain-wide
/// two-epoch outage deserves the same alert — and it is why this verdict
/// must never gate consensus behaviour by itself (see the proposal-lag gate
/// in `engine.rs`, which is separate, opt-in, and flag-day material).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Health {
    /// Wall-clock slot minus the head's slot.
    pub behind_by_slots: u64,
    /// Wall time since this node last applied a canonical block (or since
    /// boot, if it has applied none).
    pub ms_since_last_applied: u64,
    /// Behind, and recently applied a block: catching up.
    pub syncing: bool,
    /// Behind, and NOT applying blocks: not making progress. Alert on this.
    pub stalled: bool,
}

impl Health {
    /// The verdict, as a pure function of its inputs — no clock, no node —
    /// so `engine.rs` and the tests judge with the same code.
    ///
    /// `slot_ms` converts the silence threshold from slots to wall time;
    /// `.max(1)` for the same reason `Engine::wall_slot` guards its divisor —
    /// a hand-edited manifest must not turn a health check into an overflow.
    pub fn assess(wall_slot: u64, head_slot: u64, ms_since_last_applied: u64, slot_ms: u64) -> Health {
        let behind_by_slots = wall_slot.saturating_sub(head_slot);
        let behind = behind_by_slots >= HEALTH_BEHIND_SLOTS;
        let silent = ms_since_last_applied >= HEALTH_SILENCE_SLOTS.saturating_mul(slot_ms.max(1));
        Health {
            behind_by_slots,
            ms_since_last_applied,
            syncing: behind && !silent,
            stalled: behind && silent,
        }
    }

    /// The `getchaininfo` sub-object. `secs`, not `ms`, on the wire: the
    /// consumers poll at seconds granularity and every other duration on
    /// this surface is seconds.
    pub fn json(&self) -> Json {
        Json::obj(vec![
            ("behind_by_slots", Json::u(self.behind_by_slots)),
            ("secs_since_last_block", Json::u(self.ms_since_last_applied / 1000)),
            ("syncing", Json::Bool(self.syncing)),
            ("stalled", Json::Bool(self.stalled)),
        ])
    }
}


// ─── Operator observability: metrics and validator status ──────────────────
//
// Everything below is NODE-LOCAL REPORTING. No value here is read by any
// consensus rule, none is gossiped, and two nodes reporting differently
// cannot fork — the whole surface is a projection of state the node already
// holds, assembled on the engine thread so one response describes one
// instant. (The gates being REPORTED here — the signing guard, the
// doppelganger watch, the proposal-lag gate — live in `engine.rs` and
// `signing_history.rs`; none of them reads this module.)

/// The doppelganger watch, as an operator sees it. The engine reduces its
/// internal state to one of these; keeping the reduction a plain enum means
/// the metric encoding and the JSON string cannot drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoppelgangerView {
    /// `--doppelganger-epochs 0`, or a boot at the chain's slot 0: nothing
    /// is or will be watching for a twin this run.
    Disabled,
    /// Deliberately silent, listening for this key signing elsewhere, until
    /// the given slot.
    Watching { silent_until_slot: u64 },
    /// The watch ran its window and saw no twin; duties are enabled.
    Clear,
    /// A twin WAS seen. Reported for completeness: in practice the run loop
    /// exits the process on this state, so a scraper is far more likely to
    /// observe the target going down plus the DOPPELGANGER line in the log.
    Alarmed,
}

impl DoppelgangerView {
    /// The metric encoding (`bloch_pos_doppelganger_state`). Documented on
    /// the series' HELP line; keep the two in sync.
    pub fn as_gauge(self) -> u64 {
        match self {
            DoppelgangerView::Disabled => 0,
            DoppelgangerView::Watching { .. } => 1,
            DoppelgangerView::Clear => 2,
            DoppelgangerView::Alarmed => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DoppelgangerView::Disabled => "disabled",
            DoppelgangerView::Watching { .. } => "watching",
            DoppelgangerView::Clear => "clear",
            DoppelgangerView::Alarmed => "alarmed",
        }
    }
}

/// The validator-specific half of the observability surface: everything the
/// node knows about the ONE key it holds. Built by the engine, rendered
/// here, shared by `getvalidatorstatus` and the validator series of
/// `/metrics` so the two can never disagree.
#[derive(Clone, Debug)]
pub struct ValidatorStatusView {
    pub index: u32,
    /// Registry facts, when the index is in the committed registry at all.
    /// `None` is itself a finding: the node holds a key for an index the
    /// chain does not know, which the status must say rather than hide.
    pub registry: Option<ValidatorRegistryView>,
    /// Member of the CURRENT epoch's duty roster (the set duties are drawn
    /// from). False for a queued, exited or unknown validator.
    pub in_duty_roster: bool,
    /// Next slot at which this validator is in a committee and expected to
    /// attest, scanned from the wall clock to `projection_end_slot`. `None`
    /// means no duty inside that horizon — normal for proposals, surprising
    /// for attestation (every roster member attests once per epoch).
    pub next_attestation_slot: Option<u64>,
    /// Next slot at which this validator is the proposer, same horizon.
    pub next_proposal_slot: Option<u64>,
    /// The horizon the two scans covered (exclusive): end of the NEXT epoch.
    /// Further out the roster and seed can still change with reveals that
    /// have not happened, so the node stops rather than guess.
    pub projection_end_slot: u64,
    /// Whether an attestation by this validator is included on the canonical
    /// chain in the current / previous epoch. `None` when the participation
    /// map does not track this index (not in that epoch's roster). THIS is
    /// "did my duty actually land", as opposed to the signed-counters below,
    /// which are "did my node try".
    pub attested_in_current_epoch: Option<bool>,
    pub attested_in_previous_epoch: Option<bool>,
    /// Duties performed by THIS PROCESS since boot. Process-local by nature:
    /// they reset on restart, and they count signatures released, not
    /// inclusions. `attestations_signed` climbing while
    /// `attested_in_current_epoch` stays false is itself a diagnosis — the
    /// vote leaves this node and never lands (mesh problem), versus the vote
    /// never being produced (duty problem).
    pub attestations_signed: u64,
    pub proposals_signed: u64,
    /// Duties this process REFUSED via a protective gate — the signing
    /// guard, the doppelganger silence, or the proposal-lag gate. A value
    /// that keeps climbing is the cue to read the log lines those gates
    /// print.
    pub duties_refused: u64,
    /// Slashing-protection watermarks, when the store is open. `None` in the
    /// watermark fields means "nothing signed yet"; `guard_present: false`
    /// means the store itself is missing — a keyed node in that state
    /// performs no duties at all.
    pub guard_present: bool,
    pub guard_highest_proposed_slot: Option<u64>,
    /// `(source_epoch, target_epoch)` of the highest attestation recorded.
    pub guard_attestation_watermark: Option<(u64, u64)>,
    pub doppelganger: DoppelgangerView,
    /// Context the numbers above are judged against.
    pub wall_slot: u64,
    pub current_epoch: u64,
}

/// Registry facts for [`ValidatorStatusView`] — the same numbers
/// `getvalidator` serves, reduced to what the operator of THIS key acts on.
#[derive(Clone, Debug)]
pub struct ValidatorRegistryView {
    /// One of `validator_state`'s words: active / queued / exiting / exited
    /// / slashed.
    pub state: &'static str,
    pub slashed: bool,
    pub own_stake_sat: u128,
    /// Effective stake in the active set; `None` when not in it.
    pub effective_stake_sat: Option<u64>,
    /// Inactivity leak accrued against this validator, in satoshis. Nonzero
    /// means finality has been failing while this validator's votes were not
    /// in the counted set; it is the "penalty pending" an operator can still
    /// act on.
    pub leaked_sat: u64,
    pub activation_epoch: Option<u64>,
    pub exit_epoch: Option<u64>,
    pub withdrawable_epoch: Option<u64>,
}

impl ValidatorStatusView {
    /// The `getvalidatorstatus` result object.
    pub fn json(&self) -> Json {
        let opt_u = |v: Option<u64>| v.map_or(Json::Null, Json::u);
        let opt_b = |v: Option<bool>| v.map_or(Json::Null, Json::Bool);
        let registry = match &self.registry {
            None => Json::Null,
            Some(r) => Json::obj(vec![
                ("state", Json::s(r.state)),
                ("slashed", Json::Bool(r.slashed)),
                ("own_stake_sat", Json::sat(r.own_stake_sat)),
                (
                    "effective_stake_sat",
                    r.effective_stake_sat
                        .map_or(Json::Null, |v| Json::sat(u128::from(v))),
                ),
                ("leaked_sat", Json::sat(u128::from(r.leaked_sat))),
                ("activation_epoch", opt_u(r.activation_epoch)),
                ("exit_epoch", opt_u(r.exit_epoch)),
                ("withdrawable_epoch", opt_u(r.withdrawable_epoch)),
            ]),
        };
        let dopp = match self.doppelganger {
            DoppelgangerView::Watching { silent_until_slot } => Json::obj(vec![
                ("state", Json::s(self.doppelganger.as_str())),
                ("silent_until_slot", Json::u(silent_until_slot)),
            ]),
            other => Json::obj(vec![("state", Json::s(other.as_str()))]),
        };
        Json::obj(vec![
            ("validator_index", Json::u(u64::from(self.index))),
            ("registry", registry),
            ("in_duty_roster", Json::Bool(self.in_duty_roster)),
            ("next_attestation_slot", opt_u(self.next_attestation_slot)),
            ("next_proposal_slot", opt_u(self.next_proposal_slot)),
            ("projection_end_slot", Json::u(self.projection_end_slot)),
            ("attested_in_current_epoch", opt_b(self.attested_in_current_epoch)),
            ("attested_in_previous_epoch", opt_b(self.attested_in_previous_epoch)),
            ("attestations_signed_since_boot", Json::u(self.attestations_signed)),
            ("proposals_signed_since_boot", Json::u(self.proposals_signed)),
            ("duties_refused_since_boot", Json::u(self.duties_refused)),
            ("signing_guard", Json::obj(vec![
                ("present", Json::Bool(self.guard_present)),
                ("highest_proposed_slot", opt_u(self.guard_highest_proposed_slot)),
                (
                    "attestation_source_epoch",
                    opt_u(self.guard_attestation_watermark.map(|(s, _)| s)),
                ),
                (
                    "attestation_target_epoch",
                    opt_u(self.guard_attestation_watermark.map(|(_, t)| t)),
                ),
            ])),
            ("doppelganger", dopp),
            ("wall_slot", Json::u(self.wall_slot)),
            ("current_epoch", Json::u(self.current_epoch)),
        ])
    }
}

/// One consistent reading of every number `/metrics` exposes, taken on the
/// engine thread. The struct exists (rather than rendering inline in the
/// engine) so the exposition format is a pure function a test can pin
/// without standing up a node — the same rule every other projection in
/// this module follows.
#[derive(Clone, Debug)]
pub struct MetricsSnapshot {
    pub head_slot: u64,
    pub head_height: u64,
    pub wall_slot: u64,
    pub health: Health,
    pub finalized_height: Option<u64>,
    pub justified_epoch: u64,
    pub finalized_epoch: u64,
    pub current_epoch: u64,
    pub peers_connected: usize,
    pub peers_configured: usize,
    pub mempool_transactions: usize,
    pub mempool_capacity: usize,
    pub mempool_bytes: usize,
    pub blocks_known: usize,
    pub validators_total: usize,
    pub validators_active: usize,
    pub uptime_secs: u64,
    /// The validator series, absent on an observer. Absence is the honest
    /// encoding: an observer scraping 0 for "attested" would page someone
    /// about a validator that does not exist.
    pub validator: Option<ValidatorStatusView>,
}

impl MetricsSnapshot {
    /// Prometheus text exposition, version 0.0.4 — the format and naming
    /// conventions of the pool proxy's exporter, `bloch_pos_` prefix.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        fn series(out: &mut String, name: &str, kind: &str, help: &str, value: &str) {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push_str("\n# TYPE ");
            out.push_str(name);
            out.push(' ');
            out.push_str(kind);
            out.push('\n');
            out.push_str(name);
            out.push(' ');
            out.push_str(value);
            out.push('\n');
        }
        fn gauge(out: &mut String, name: &str, help: &str, value: String) {
            series(out, name, "gauge", help, &value);
        }
        let b = |v: bool| if v { "1" } else { "0" }.to_string();

        gauge(&mut out, "bloch_pos_head_slot", "Slot of the canonical head this node has applied.", self.head_slot.to_string());
        gauge(&mut out, "bloch_pos_head_height", "Height (canonical block count minus one) of the applied head.", self.head_height.to_string());
        gauge(&mut out, "bloch_pos_wall_slot", "Slot the wall clock says it is now.", self.wall_slot.to_string());
        gauge(&mut out, "bloch_pos_behind_slots", "wall_slot minus head slot. Routinely nonzero on this chain (most slots are empty); alert on bloch_pos_stalled, not on this alone.", self.health.behind_by_slots.to_string());
        gauge(&mut out, "bloch_pos_secs_since_last_block", "Seconds since this node last APPLIED a canonical block (or since boot). The number that was only visible as log-file growth during the 2026-08 stall.", (self.health.ms_since_last_applied / 1000).to_string());
        gauge(&mut out, "bloch_pos_syncing", "1 while behind the wall clock but still applying blocks (catching up; leave it alone).", b(self.health.syncing));
        gauge(&mut out, "bloch_pos_stalled", "1 while behind the wall clock AND applying nothing. THE alert signal: RPC answering and peers connected do not clear it.", b(self.health.stalled));
        match self.finalized_height {
            Some(h) => {
                gauge(&mut out, "bloch_pos_has_finality", "1 once any epoch has finalized in this node's view.", "1".to_string());
                gauge(&mut out, "bloch_pos_finalized_height", "Height of the last finalized block (series absent until finality exists).", h.to_string());
            }
            None => gauge(&mut out, "bloch_pos_has_finality", "1 once any epoch has finalized in this node's view.", "0".to_string()),
        }
        gauge(&mut out, "bloch_pos_justified_epoch", "Highest justified epoch in this node's view.", self.justified_epoch.to_string());
        gauge(&mut out, "bloch_pos_finalized_epoch", "Highest finalized epoch in this node's view.", self.finalized_epoch.to_string());
        gauge(&mut out, "bloch_pos_finality_distance_epochs", "Current epoch minus finalized epoch. 2 is the floor when finality is healthy; a climbing value means finality is failing and the inactivity leak is (or will be) active.", self.current_epoch.saturating_sub(self.finalized_epoch).to_string());
        gauge(&mut out, "bloch_pos_peers_connected", "Live P2P connections (libp2p: distinct peers; devnet transport: connections, which counts a two-way pair twice).", self.peers_connected.to_string());
        gauge(&mut out, "bloch_pos_peers_configured", "Peers this node was told to dial.", self.peers_configured.to_string());
        gauge(&mut out, "bloch_pos_mempool_transactions", "Transactions waiting in the mempool.", self.mempool_transactions.to_string());
        gauge(&mut out, "bloch_pos_mempool_capacity", "Mempool admission ceiling.", self.mempool_capacity.to_string());
        gauge(&mut out, "bloch_pos_mempool_bytes", "Canonical bytes held by the mempool.", self.mempool_bytes.to_string());
        gauge(&mut out, "bloch_pos_blocks_known", "Every structurally valid block this node stores, canonical or not (unpruned).", self.blocks_known.to_string());
        gauge(&mut out, "bloch_pos_validators_total", "Validator records in the committed registry.", self.validators_total.to_string());
        gauge(&mut out, "bloch_pos_validators_active", "Validators in the active set this epoch.", self.validators_active.to_string());
        gauge(&mut out, "bloch_pos_uptime_seconds", "Seconds since this process booted.", self.uptime_secs.to_string());

        if let Some(v) = &self.validator {
            gauge(&mut out, "bloch_pos_validator_index", "The validator index of the key this node holds.", v.index.to_string());
            gauge(&mut out, "bloch_pos_validator_in_registry", "1 when the held key's index exists in the committed registry.", b(v.registry.is_some()));
            gauge(&mut out, "bloch_pos_validator_in_duty_roster", "1 when this validator is in the current epoch's duty roster. THE validator-is-working precondition.", b(v.in_duty_roster));
            if let Some(r) = &v.registry {
                gauge(&mut out, "bloch_pos_validator_slashed", "1 when the registry marks this validator slashed.", b(r.slashed));
                gauge(&mut out, "bloch_pos_validator_exiting", "1 when an exit epoch is set (exiting or exited).", b(r.exit_epoch.is_some()));
                gauge(&mut out, "bloch_pos_validator_leaked_sat", "Inactivity leak accrued against this validator, satoshis. Nonzero = finality failing while this validator's votes were absent from the counted set.", r.leaked_sat.to_string());
            }
            // Absent-vs-false again: a validator outside an epoch's roster
            // has no participation entry, and a 0 would read as a missed
            // duty.
            if let Some(a) = v.attested_in_current_epoch {
                gauge(&mut out, "bloch_pos_validator_attested_current_epoch", "1 when an attestation by this validator is included on the canonical chain this epoch.", b(a));
            }
            if let Some(a) = v.attested_in_previous_epoch {
                gauge(&mut out, "bloch_pos_validator_attested_previous_epoch", "1 when an attestation by this validator was included in the previous epoch.", b(a));
            }
            series(&mut out, "bloch_pos_validator_attestations_signed_total", "counter", "Attestations signed by this process since boot (signatures released, not inclusions).", &v.attestations_signed.to_string());
            series(&mut out, "bloch_pos_validator_proposals_signed_total", "counter", "Blocks signed by this process since boot.", &v.proposals_signed.to_string());
            series(&mut out, "bloch_pos_validator_duties_refused_total", "counter", "Duties refused by a protective gate (signing guard, doppelganger silence, proposal-lag gate) since boot. Climbing = read the node log.", &v.duties_refused.to_string());
            series(&mut out, "bloch_pos_signing_guard_present", "gauge", "1 when the slashing-protection store is open. A keyed node without it performs NO duties.", &b(v.guard_present));
            if let Some(slot) = v.guard_highest_proposed_slot {
                series(&mut out, "bloch_pos_signing_guard_highest_proposed_slot", "gauge", "Highest slot this key ever signed a proposal for (durable watermark).", &slot.to_string());
            }
            if let Some((_, target)) = v.guard_attestation_watermark {
                series(&mut out, "bloch_pos_signing_guard_attestation_target_epoch", "gauge", "Target epoch of the highest attestation this key signed (durable watermark). current_epoch minus this = epochs since the key last voted.", &target.to_string());
            }
            series(&mut out, "bloch_pos_doppelganger_state", "gauge", "0 disabled/skipped, 1 watching (duties deliberately silent), 2 clear, 3 alarmed (the process exits on 3).", &v.doppelganger.as_gauge().to_string());
        }
        out
    }
}

/// `getchaininfo` — the method the finality-aware consumers read (V4 §2).
#[allow(clippy::too_many_arguments)]
pub fn chain_info_json(
    state: &CommittedState,
    head: &BlockId,
    // The committed root at `head`, HANDED IN rather than derived from
    // `state`. It used to be `state.state_root()` on this line, which is a
    // full walk of the committed state tree — 733 ms at Genesis-4's carryover
    // size — run on the consensus thread once per caller. See
    // `Engine::head_state_root` for why the head block's header already holds
    // exactly this value and what happens at genesis, where there is no header
    // to hold it. The value is unchanged for every input; only who computes it
    // is.
    state_root: [u8; 32],
    height: u64,
    finalized_height: Option<u64>,
    wall_slot: u64,
    // The node's own liveness verdict, judged by [`Health::assess`] from the
    // same wall clock as `wall_slot`. Handed in rather than derived here
    // because the silence measurement (`last_applied_ms`) lives on the
    // engine, and this function's rule is to stay a pure projection of its
    // arguments.
    health: &Health,
    validators_total: usize,
    mempool: usize,
    blocks_known: usize,
) -> Json {
    let fin = state.finality();
    let slot = state.slot();
    Json::obj(vec![
        ("block_id", Json::hex(head.as_bytes())),
        ("slot", Json::u(slot)),
        ("height", Json::u(height)),
        // The settled line, next to the head. See `Finality`: this is what
        // replaces a confirmation count, and an integrator reading only
        // `height` is reading the number that is *not* the guarantee.
        ("finalized_height", finalized_height.map_or(Json::Null, Json::u)),
        ("epoch", Json::u(epoch_of(slot))),
        ("slot_in_epoch", Json::u(slot % SLOTS_PER_EPOCH)),
        ("slots_per_epoch", Json::u(SLOTS_PER_EPOCH)),
        ("state_root", Json::hex(&state_root)),
        (
            "justified",
            Json::obj(vec![
                ("epoch", Json::u(fin.justified.epoch)),
                ("root", Json::hex(&fin.justified.root)),
            ]),
        ),
        (
            "finalized",
            Json::obj(vec![
                ("epoch", Json::u(fin.finalized.epoch)),
                ("root", Json::hex(&fin.finalized.root)),
            ]),
        ),
        (
            "previous_justified",
            Json::obj(vec![
                ("epoch", Json::u(fin.previous_justified.epoch)),
                ("root", Json::hex(&fin.previous_justified.root)),
            ]),
        ),
        (
            "validators",
            Json::obj(vec![
                ("total", Json::u(validators_total as u64)),
                ("active", Json::u(state.active_validators().len() as u64)),
            ]),
        ),
        ("total_active_stake_sat", Json::sat(state.total_active_stake_sat())),
        // The inactivity-leak accumulator, whole-fleet total. The direct
        // observable of the LEAK_RECOVERY flag day: a ratchet before the gate,
        // a debt trending to zero after it (runbook
        // docs/RELANCA-G4-DIAS-DE-BANDEIRA.md §3, debt 3 / §4.4).
        ("leaked_total_sat", Json::sat(state.leaked_total_sat())),
        ("base_fee_millisat_per_gas", Json::sat(state.base_fee_millisat_per_gas())),
        ("next_base_fee_millisat_per_gas", Json::sat(state.next_base_fee())),
        ("mempool", Json::u(mempool as u64)),
        ("blocks_known", Json::u(blocks_known as u64)),
        // Wall-clock slot and the gap to it: under PoS this is what "am I
        // synced" means. There is no depth and no difficulty to infer it from
        // (R1), so the node states it.
        ("wall_slot", Json::u(wall_slot)),
        ("behind_by_slots", Json::u(wall_slot.saturating_sub(slot))),
        // The liveness verdict — see [`Health`]. `behind_by_slots` above
        // says how far; `health.stalled` says whether the node is actually
        // moving toward closing the gap, which is the difference between a
        // node that is syncing and one that has silently stopped. The
        // post-replay stall (2026-08) looked identical to a laggard on every
        // field above this line; this object is what tells them apart.
        ("health", health.json()),
    ])
}

/// How a block stands relative to this node's own checkpoints.
///
/// # This is the field an exchange credits a deposit on
///
/// The integration question was "how many confirmations should we require, and
/// what does the guarantee rest on". Under PoS there is no answer in that
/// currency: depth is not security (R1), and a chain with no difficulty cannot
/// price a reorg in work. The guarantee rests on **Casper justification and
/// finalisation** — a finalised checkpoint cannot be reverted unless at least
/// one third of the total stake is slashed, which is a bonded, attributable,
/// on-chain cost rather than a probabilistic one.
///
/// So the honest replacement for "N confirmations" is exactly one boolean:
/// [`Finality::Finalized`]. A deposit in a finalised block is settled under the
/// protocol's strongest guarantee; a deposit in a merely justified or canonical
/// block can still be reorganised out. Nothing is gained by waiting a further
/// number of blocks past finalisation, and nothing else substitutes for it.
///
/// One caveat, stated because it bounds the guarantee: this is **this node's**
/// view, computed from the chain it has validated itself. That is the property
/// an integrator wants — it means the answer does not depend on trusting the
/// producer, and it is why running your own node and reading its RPC is the
/// correct deployment. It also means a node that is not synced reports its own
/// staleness, which `getchaininfo`'s `behind_by_slots` is there to expose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality {
    /// At or below the finalised checkpoint. Irreversible short of a
    /// one-third-of-stake slashing event. **Credit here.**
    Finalized,
    /// At or below the justified checkpoint but above the finalised one. One
    /// epoch away from finality in the normal case; still reversible.
    Justified,
    /// On this node's canonical chain, not yet justified. Reorganisable by
    /// ordinary fork choice.
    Canonical,
    /// Known to this node but not on its canonical chain.
    NotCanonical,
}

impl Finality {
    pub fn as_str(self) -> &'static str {
        match self {
            Finality::Finalized => "finalized",
            Finality::Justified => "justified",
            Finality::Canonical => "canonical",
            Finality::NotCanonical => "not_canonical",
        }
    }

    /// The single boolean a deposit decision should branch on.
    pub fn is_final(self) -> bool {
        matches!(self, Finality::Finalized)
    }
}

/// One block, in the V4 §3.2 shape.
///
/// `finality` is this node's own classification of the block against its own
/// justified/finalized checkpoints — R1's replacement for confirmations — and
/// `finalized` is the same judgement as the one boolean a client should branch
/// on. Both are emitted: the string carries the gradation for display, the
/// boolean removes any need to hardcode the string set.
///
/// `timestamp` is derived from the slot for display and is not a consensus
/// field: `BlockHeaderV4` carries no time.
pub fn block_json(
    env: &BlockEnvelope,
    height: Option<u64>,
    finality: Finality,
    timestamp_secs: u64,
) -> Json {
    let h = &env.header;
    Json::obj(vec![
        ("block_id", Json::hex(env.block_id().as_bytes())),
        // The header's `version` field VERBATIM — `VERSION_G4`, a 32-bit magic
        // (0xB10C0005), which renders as 2970353669 and looks wrong at a
        // glance. It is not. `BLOCH-RPC-V4.md` §3.2 sketches `"version": 4`,
        // but a client that recomputes `block_id` hashes the 304 header bytes
        // including this field, so emitting a friendlier `4` would hand it a
        // number it cannot verify anything with. Do not "fix" this to 4.
        ("version", Json::u(u64::from(h.version))),
        ("parent", Json::hex(&h.parent)),
        ("slot", Json::u(h.slot)),
        ("epoch", Json::u(epoch_of(h.slot))),
        ("height", height.map_or(Json::Null, Json::u)),
        ("proposer_index", Json::u(u64::from(h.proposer_index))),
        ("timestamp", Json::u(timestamp_secs)),
        ("state_root", Json::hex(&h.state_root)),
        ("body_root", Json::hex(&h.body_root)),
        ("randao_reveal", Json::hex(&h.randao_reveal)),
        ("randao_mix", Json::hex(&h.randao_mix)),
        ("justified_root", Json::hex(&h.justified_root)),
        ("finalized_root", Json::hex(&h.finalized_root)),
        ("attestation_root", Json::hex(&h.attestation_root)),
        ("coherence_root", Json::hex(&h.coherence_root)),
        ("finality", Json::s(finality.as_str())),
        ("finalized", Json::Bool(finality.is_final())),
        ("tx_count", Json::u(env.body.transactions.len() as u64)),
        ("attestation_count", Json::u(env.body.attestations.len() as u64)),
    ])
}

/// `getblockcount` — height first, finality alongside it.
///
/// A bare integer would match Genesis-3's shape, and it is the wrong shape for
/// a chain whose security is not depth. An integrator polling this method needs
/// the head *and* the line below which history is settled; returning only the
/// former is what makes someone reinvent "N confirmations" on top of it. So the
/// response carries the finalised height as a sibling field: `height` is what
/// exists, `finalized_height` is what is safe, and the gap between them is the
/// only lag that matters.
pub fn block_count_json(
    height: u64,
    slot: u64,
    finalized_height: Option<u64>,
    justified_epoch: u64,
    finalized_epoch: u64,
) -> Json {
    Json::obj(vec![
        ("height", Json::u(height)),
        ("slot", Json::u(slot)),
        ("epoch", Json::u(epoch_of(slot))),
        ("finalized_height", finalized_height.map_or(Json::Null, Json::u)),
        ("justified_epoch", Json::u(justified_epoch)),
        ("finalized_epoch", Json::u(finalized_epoch)),
    ])
}

/// What became of a submitted transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// Newly admitted to the mempool and gossiped to peers.
    New,
    /// Byte-identical to one already pending. The client's intent is satisfied,
    /// so this is a success and not an error — but it is reported distinctly,
    /// because a resubmission loop that cannot tell the two apart will keep
    /// resubmitting forever.
    Duplicate,
}

/// `sendrawtransaction` — what the node did with the bytes.
///
/// There is no txid here, and its absence is the same structural fact
/// [`RpcError::no_transaction_index`] documents: a `PosTransaction` has no
/// identity at this layer. `tx_hash` is SHA3-256 over the canonical bytes and
/// is labelled for what it is — a **local** handle for correlating this
/// submission with this response. It is not a consensus identifier, no block
/// commits to it, and no other node will agree it names anything. Building
/// deposit crediting on it would be building on a number this node invented.
pub fn submitted_json(tx: &PosTransaction, outcome: Admitted) -> Json {
    use sha3::{Digest, Sha3_256};
    let bytes = tx.canonical_bytes();
    let hash: [u8; 32] = Sha3_256::digest(&bytes).into();
    let kind = match tx {
        PosTransaction::Transfer { .. } => "transfer",
        PosTransaction::TransferV2 { .. } => "transfer_v2",
        PosTransaction::Deposit { .. } => "deposit",
        PosTransaction::DepositV2 { .. } => "deposit_v2",
        PosTransaction::Exit { .. } => "exit",
        PosTransaction::Withdraw { .. } => "withdraw",
        PosTransaction::Delegate { .. } => "delegate",
        PosTransaction::SlashingEvidence(_) => "slashing_evidence",
    };
    Json::obj(vec![
        ("accepted", Json::Bool(true)),
        (
            "status",
            Json::s(match outcome {
                Admitted::New => "accepted",
                Admitted::Duplicate => "duplicate",
            }),
        ),
        ("kind", Json::s(kind)),
        ("bytes", Json::u(bytes.len() as u64)),
        ("tx_hash", Json::hex(&hash)),
        (
            "tx_hash_note",
            Json::s(
                "local correlation handle only (SHA3-256 of the canonical bytes); \
                 not a consensus transaction id — no block commits to it",
            ),
        ),
        (
            "confirmation",
            Json::s(
                "this transport does not confirm: watch for the transaction in a \
                 block via `getblockbyslot`, and treat it as settled only once that \
                 block reports `finalized: true`",
            ),
        ),
    ])
}

/// Lifecycle of one validator as of `current_epoch`.
///
/// The order of the arms is the rule: `slashed` outranks everything, because a
/// slashed validator whose exit epoch has not arrived is not "exiting" in any
/// sense a client should display.
pub fn validator_state(rec: &ValidatorRecord, current_epoch: u64) -> &'static str {
    if rec.slashed {
        "slashed"
    } else if rec.exit_epoch != u64::MAX && current_epoch >= rec.exit_epoch {
        "exited"
    } else if rec.exit_epoch != u64::MAX {
        "exiting"
    } else if rec.activation_epoch == u64::MAX || current_epoch < rec.activation_epoch {
        "queued"
    } else {
        "active"
    }
}

/// One validator registry record (V4 §4.2).
///
/// `effective_stake_sat` is `None` for a validator the active set does not
/// carry — which is a different statement from zero, and is why it is not
/// defaulted: "not sampled this epoch" and "sampled with no weight" are
/// distinguishable states and a delegator cares which one it is looking at.
pub fn validator_json(
    rec: &ValidatorRecord,
    effective_stake_sat: Option<u64>,
    current_epoch: u64,
) -> Json {
    use sha3::{Digest, Sha3_256};
    let pubkey_hash: [u8; 32] = Sha3_256::digest(&rec.pubkey).into();
    let never = |e: u64| if e == u64::MAX { Json::Null } else { Json::u(e) };
    Json::obj(vec![
        ("index", Json::u(u64::from(rec.index))),
        ("pubkey_hash", Json::hex(&pubkey_hash)),
        ("pubkey_bytes", Json::u(rec.pubkey.len() as u64)),
        ("state", Json::s(validator_state(rec, current_epoch))),
        ("own_stake_sat", Json::sat(rec.staked_sat)),
        (
            "effective_stake_sat",
            effective_stake_sat.map_or(Json::Null, |v| Json::sat(u128::from(v))),
        ),
        // R5: the rate is on every validator response, not behind a detail
        // call. Consensus applies it capped at `rewards::MAX_COMMISSION_BPS`;
        // the committed value is reported verbatim so a rate someone set above
        // the cap is visible rather than laundered into the cap.
        ("commission_bps", Json::sat(rec.commission_bps)),
        ("randao_commitment", Json::hex(&rec.randao_commitment)),
        ("slashed", Json::Bool(rec.slashed)),
        ("activation_epoch", never(rec.activation_epoch)),
        ("exit_epoch", never(rec.exit_epoch)),
        ("withdrawable_epoch", never(rec.withdrawable_epoch)),
    ])
}

fn eutxo_json(e: &EutxoEntry) -> Json {
    Json::obj(vec![
        ("txid", Json::hex(&e.txid)),
        ("vout", Json::u(u64::from(e.vout))),
        ("value_sat", Json::sat(u128::from(e.value))),
        ("script_hash", Json::hex(&e.script_hash)),
        // The committed vesting lock: first epoch this output may be spent,
        // 0 = liquid. This is the §4.6 "vesting-lock visibility" answer —
        // extra field on the existing shapes rather than a new method, so a
        // wallet learns "spendable now, and if not, when" from the same call
        // it already makes before building a transaction.
        ("unlock_epoch", Json::u(e.unlock_epoch)),
    ])
}

/// `getbalance` — the summed value of every output locked to `script_hash`.
pub fn balance_json(state: &CommittedState, script_hash: &[u8; 32]) -> Json {
    let count = state.eutxos().filter(|e| &e.script_hash == script_hash).count();
    Json::obj(vec![
        ("script_hash", Json::hex(script_hash)),
        ("balance_sat", Json::sat(state.balance_sat(script_hash))),
        ("utxo_count", Json::u(count as u64)),
    ])
}

/// `getutxos` — the outputs themselves, paginated.
///
/// `truncated` rather than a cursor: the honest thing for a devnet-stage
/// surface is to say the page was cut, not to invent a pagination protocol the
/// OpenAPI V4 freeze has not decided on.
pub fn utxos_json(state: &CommittedState, script_hash: &[u8; 32], limit: usize) -> Json {
    let matching: Vec<&EutxoEntry> =
        state.eutxos().filter(|e| &e.script_hash == script_hash).collect();
    let total = matching.len();
    let page: Vec<Json> = matching.iter().take(limit).map(|e| eutxo_json(e)).collect();
    Json::obj(vec![
        ("script_hash", Json::hex(script_hash)),
        ("total", Json::u(total as u64)),
        ("returned", Json::u(page.len() as u64)),
        ("truncated", Json::Bool(total > page.len())),
        ("utxos", Json::Arr(page)),
    ])
}

/// `gettxout` — one outpoint, answered as present-or-absent.
///
/// `unspent` is stated as its own boolean rather than left implicit in whether
/// `utxo` is null. An integrator reading a null field has to decide whether it
/// means "spent", "never existed", or "this node does not know", and those are
/// three different facts to act on. Here the first two are both `unspent:
/// false` — this node's committed set does not contain it — and the third
/// cannot arise, because the set is committed state, not a cache: if the node
/// answered at all, it answered from the same eUTXO set its state root commits.
///
/// So a `false` is a real statement about the chain, and `at_slot` — the head
/// this node answered from — is returned either way, so the answer can be
/// pinned to a point on the chain rather than to the moment the call happened.
pub fn txout_json(state: &CommittedState, txid: &[u8; 32], vout: u32) -> Json {
    match state.utxo(txid, vout) {
        Some(e) => Json::obj(vec![
            ("txid", Json::hex(txid)),
            ("vout", Json::u(vout as u64)),
            ("unspent", Json::Bool(true)),
            ("utxo", eutxo_json(e)),
            ("at_slot", Json::u(state.slot())),
        ]),
        None => Json::obj(vec![
            ("txid", Json::hex(txid)),
            ("vout", Json::u(vout as u64)),
            ("unspent", Json::Bool(false)),
            ("utxo", Json::Null),
            ("at_slot", Json::u(state.slot())),
        ]),
    }
}

/// `getmempoolinfo`.
pub fn mempool_info_json(
    size: usize,
    max: usize,
    bytes: usize,
    next_base_fee_millisat_per_gas: u128,
) -> Json {
    Json::obj(vec![
        ("size", Json::u(size as u64)),
        ("max", Json::u(max as u64)),
        ("bytes", Json::u(bytes as u64)),
        ("next_base_fee_millisat_per_gas", Json::sat(next_base_fee_millisat_per_gas)),
    ])
}

#[cfg(test)]
mod tests;
