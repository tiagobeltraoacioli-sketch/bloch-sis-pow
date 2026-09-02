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
        Ok(body) => {
            // The body must be text before it can be JSON. Invalid UTF-8 is a
            // parse error with a JSON-RPC shape, not a dropped connection.
            let response = match std::str::from_utf8(&body) {
                Ok(text) => handle_body(text, backend),
                Err(_) => envelope(Json::Null, Err(RpcError::parse_error("body is not UTF-8"))),
            };
            let _ = respond(sock, 200, &response);
        }
        Err(HttpError { status, message }) => {
            let _ = respond(sock, status, &envelope(Json::Null, Err(RpcError::invalid_request(message))));
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

/// Read one HTTP request and return its body.
fn read_request(sock: &mut TcpStream) -> Result<Vec<u8>, HttpError> {
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
    if !verb.eq_ignore_ascii_case("POST") {
        return Err(http_err(405, "this endpoint accepts POST only"));
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
    Ok(body)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn respond(sock: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    // `Connection: close` because this server does not implement keep-alive:
    // one request per connection, and the client is told so instead of being
    // left waiting on a socket that will never answer again.
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
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
        // The finalised line, next to the head. See `Finality`: this is what
        // replaces a confirmation count, and an integrator reading only
        // `height` is reading a number that is weaker still. "Replaces" is not
        // "guarantees" — the retraction on `Finality` bounds what this line
        // buys, and it is less than an earlier revision of this file promised.
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
        ("base_fee_millisat_per_gas", Json::sat(state.base_fee_millisat_per_gas())),
        ("next_base_fee_millisat_per_gas", Json::sat(state.next_base_fee())),
        ("mempool", Json::u(mempool as u64)),
        ("blocks_known", Json::u(blocks_known as u64)),
        // Wall-clock slot and the gap to it: under PoS this is what "am I
        // synced" means. There is no depth and no difficulty to infer it from
        // (R1), so the node states it.
        ("wall_slot", Json::u(wall_slot)),
        ("behind_by_slots", Json::u(wall_slot.saturating_sub(slot))),
    ])
}

/// How a block stands relative to this node's own checkpoints.
///
/// # This is the field an exchange reads — and what it does NOT buy
///
/// The integration question was "how many confirmations should we require, and
/// what does the guarantee rest on". Under PoS there is no answer in that
/// currency: depth is not security (R1), and a chain with no difficulty cannot
/// price a reorg in work. [`Finality::Finalized`] is the right field to read.
/// What it rests on is far narrower than an earlier revision of this comment
/// claimed, and the difference is the one that decides customer money.
///
/// ## RETRACTION (2026-09-01): finality here is NOT backed by a slashing cost
///
/// This comment used to say that "a finalised checkpoint cannot be reverted
/// unless at least one third of the total stake is slashed, which is a bonded,
/// attributable, on-chain cost rather than a probabilistic one", and
/// [`Finality::Finalized`] used to be annotated "Credit here". That is
/// Casper's guarantee on paper. It is not this binary's. **No stake on
/// Genesis-4 can be slashed at all**, for four independent reasons, any one of
/// which is sufficient on its own:
///
/// 1. **Evidence cannot be decoded.**
///    `PosTransaction::from_canonical_bytes` returns
///    `TxDecodeError::EvidenceNotDecodable` for wire tag `0x05`
///    unconditionally, with no gate (`transition.rs:782`; the codec documents
///    the reason at `:713-729`). The encoder folds the nested messages in as
///    the signing roots they were signed over — hashes — so the envelopes are
///    unrecoverable by construction, not by omission.
/// 2. **That decoder is the only one on every ingress path**: block body
///    (`engine.rs:226`), gossip (`p2p.rs:1269`, `net.rs:293`) and
///    `sendrawtransaction` (this file, `:911`). A block carrying evidence is
///    therefore rejected by every peer, and a proposer that included it would
///    produce an unimportable block.
/// 3. **Nothing constructs the transaction outside tests.** The node captures
///    an equivocating pair and prints it; the log line itself reads "slashing
///    pipeline NOT wired — evidence is logged, not prosecuted"
///    (`engine.rs:2241`).
/// 4. **There is no activation constant to arm.**
///    `SLASHING_EVIDENCE_ACTIVATION_EPOCH` does not exist in this repository.
///    It is not set to `u64::MAX` — it is absent.
///
/// Read from the live chain on 2026-09-02 at height 34,665, epoch 1736, from
/// two keyless archival observers whose responses were byte-for-byte
/// identical: `getvalidatorcount` 64 total and 64 active; zero records with
/// `"slashed": true`; zero with a non-null `"exit_epoch"`; 64 of 64 in state
/// `active`. Equivocation on this fleet is *detected* — the node captures each
/// pair and logs it — and none of it has ever been prosecuted.
///
/// The scale of that is larger than the registry can show. Replay of
/// `blocks.log` puts **48 validators** with provable double-signing, derived
/// seven independent ways: two forensic pipelines written separately (one
/// producing the pair table with slot, both roots, and the blocks carrying
/// each half), the committed state reproduced, and six independently kept
/// logs deriving the same set in slot order. The two indices recorded in
/// `deploy/FLAG-DAY-EPOCH-800.md` (16 and 35) are *within* that set — an
/// earlier incident, not a competing count.
///
/// **Do not put that number in integrator-facing material.** Not because it is
/// doubtful, but because no RPC method exposes equivocation evidence, so the
/// recipient has no way to check it: every one of those 48 reads
/// `"slashed": false`, and the registry an exchange can query will agree with
/// the retraction while disagreeing with the forensics. A figure the reader
/// cannot verify does not belong in a document they are meant to act on.
/// Nothing above depends on it. `slashing.rs` is complete; nothing can reach
/// it.
///
/// So Genesis-4 finality today is **economic by intent and cryptographic by
/// nothing**. Reverting a finalised checkpoint costs an attacker no bonded
/// stake — only the coordination of the validators who would have to do it.
///
/// ## What an integrator can actually rely on
///
/// `Finalized` still carries real information: it is this node's own
/// judgement, computed from a chain it validated itself, and it is strictly
/// stronger than `Justified` or `Canonical`. It is not a settlement guarantee.
/// Three limits bound it, and they compound:
///
/// - **No slashing cost**, per the retraction above.
/// - **`finalized` is not a latch.** It has been measured *descending* across
///   reorgs that break no rule: fork choice walks from the *justified* root
///   and the state committed there finalises two epochs below the head, so the
///   deepest cut the algorithm may legitimately propose is itself a finality
///   rewind (finalized epoch 6 -> 4 -> 2 -> 0 in three in-rules cuts).
/// - **The quorum denominator has no floor.** It is leak-adjusted
///   unconditionally; the floor and the recovery rule are written but gated
///   behind `LEAK_RECOVERY_ACTIVATION_EPOCH`, which is `u64::MAX`
///   (`bloch-pos-committee/src/params.rs:610`). A partitioned minority holding
///   6.25% of stake has been shown to self-finalise once the absent majority
///   leaked away.
///
/// **Current honest guidance**, until this note is withdrawn: credit at
/// **`finalized` plus a margin of 3 epochs**, require **two independently
/// operated nodes to agree on the same finalized root AND epoch** — the epoch
/// alone is not enough — and **re-verify immediately before releasing funds**.
/// Two nodes agreeing does not mitigate the rewind, because both rewind
/// independently; it catches divergence, which is a different failure. The
/// margin of 3 bounds a single legal cut with one epoch to spare. It does not
/// bound a repeated ratchet: **no depth is provably safe today**, and saying
/// so is worth more than quoting a number that sounds like it is. This is the
/// same rule as `docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` §5,
/// and that document is the one an integrator should be handed.
///
/// There is no machine-readable form of this note on this release: the node
/// serves no `getcapabilities` method, so a client cannot branch on a
/// `slashing_enforced` flag and must be told in prose. Do not synthesise one.
///
/// This note is withdrawn when evidence has a wire shape that survives the
/// codec, the slashing path is reachable from the network and armed, the
/// finality latch ships, and the denominator floor is armed. The promise
/// returning and enforcement arriving are kept in step by
/// `tests/slashing_backed_finality_claims.rs`, which fails either way round.
///
/// One caveat, stated because it bounds the guarantee: this is **this node's**
/// view, computed from the chain it has validated itself. That is the property
/// an integrator wants — it means the answer does not depend on trusting the
/// producer, and it is why running your own node and reading its RPC is the
/// correct deployment. It also means a node that is not synced reports its own
/// staleness, which `getchaininfo`'s `behind_by_slots` is there to expose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality {
    /// At or below the finalised checkpoint. The strongest classification
    /// this node offers — and NOT irreversible: it is backed by no slashing
    /// cost (none can be applied on this network) and it is not a latch. Read
    /// the retraction on [`Finality`] before crediting anything on it.
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
        PosTransaction::Exit { .. } => "exit",
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
                 block via `getblockbyslot`. `finalized: true` on that block is \
                 the strongest signal this chain offers, but it is NOT a \
                 settlement guarantee — no slashing penalty backs it and it is \
                 not a latch; see `docs/integration/\
                 BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md` \u{a7}5",
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
    barred: usize,
    barred_hits: u64,
) -> Json {
    Json::obj(vec![
        ("size", Json::u(size as u64)),
        ("max", Json::u(max as u64)),
        ("bytes", Json::u(bytes as u64)),
        ("next_base_fee_millisat_per_gas", Json::sat(next_base_fee_millisat_per_gas)),
        // The rejection cache, from outside. Two numbers and they answer
        // different questions: `barred` is how many transactions this node is
        // currently refusing to re-admit, `barred_hits` is how many re-offers
        // it has actually turned away since boot. A cache with entries and
        // zero hits is barring nothing real — the distinction the mempool size
        // alone cannot make, and the reason measuring this needed an RPC
        // rather than a log line on a box someone has to hold a key for.
        ("barred", Json::u(barred as u64)),
        ("barred_hits", Json::u(barred_hits)),
    ])
}

#[cfg(test)]
mod tests;
