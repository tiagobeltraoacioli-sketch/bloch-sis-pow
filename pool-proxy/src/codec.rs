//! Stratum V1 line-protocol codec.
//!
//! Two responsibilities, cleanly split:
//!
//! 1. **Framing** (`LineReader` / `write_line`) — bounded, newline-delimited
//!    JSON over any tokio stream half. Mirrors the node's
//!    `read_bounded_line` semantics: `MAX_LINE_BYTES` is enforced DURING
//!    accumulation so a slowloris peer that never sends `\n` cannot grow a
//!    buffer without bound. The returned `Line` keeps its trailing `\n`, so
//!    the transparent proxy can forward the exact bytes it read.
//!
//! 2. **Classification** (`classify_client` / `classify_server` + helpers) —
//!    PURE, no-IO mapping of one raw line to the shared `ClientMsg` /
//!    `ServerMsg` enums. This is the ONLY module that pokes at
//!    `serde_json::Value` shapes; every other module consumes the typed
//!    enums. Nothing here rewrites the wire: `Framed::raw` is always the
//!    untouched input line and `Framed::parsed` is the classification.
//!
//! Wire shapes mirrored from the node (`src/stratum/{protocol,session}.rs`):
//!
//! ```text
//!   subscribe result : [[["mining.set_difficulty",en1],["mining.notify",en1]], en1_hex, 4]
//!   notify           : [job_id, prevhash, coinb1, coinb2, merkle[], version, bits, ntime, clean_jobs]
//!   set_difficulty   : [difficulty]
//!   set_extranonce   : [extranonce1_hex, extranonce2_size]
//!   submit           : [worker_name, job_id, extranonce2, ntime, nonce]
//!   error payload    : [code, "message", null]
//! ```
//!
//! Every function that touches untrusted bytes returns `Result` /
//! `Option` — there is no `unwrap`/`expect` on parsed network input.

use std::time::Instant;

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::types::{
    error_codes, methods, ClientMsg, Framed, Job, Line, PoolError, RawNotification, RawRequest,
    RawResponse, ServerMsg, Share, ShareOutcome, SubscribeResult, WorkerId, MAX_LINE_BYTES,
};

// ─────────────────────────────────────────────────────────────────────────
// Framing: bounded newline-delimited reader
// ─────────────────────────────────────────────────────────────────────────

/// Bounded, cancellation-friendly line reader over any buffered async
/// source (a `TcpStream` read half wrapped in `tokio::io::BufReader`, or
/// raw bytes in tests). Accumulates bytes until a `\n`, enforcing
/// `MAX_LINE_BYTES` as it goes.
pub struct LineReader<R: AsyncBufRead + Unpin> {
    inner: R,
    /// Partial-line accumulator. Retained across `next_line` calls so a
    /// short read (or, in the router, a cancelled poll) never loses bytes
    /// mid-line.
    buf: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(512),
        }
    }

    /// Read one newline-terminated line.
    ///
    /// * `Ok(Some(line))` — a full line INCLUDING its trailing `\n`. (On a
    ///   final line at EOF that lacked a newline, the bytes are still
    ///   delivered once, without a synthesized `\n`.)
    /// * `Ok(None)` — clean EOF with nothing buffered.
    /// * `Err(PoolError::Protocol)` — the line exceeded `MAX_LINE_BYTES`
    ///   (before a `\n` was seen) or was not valid UTF-8.
    /// * `Err(PoolError::Io)` — an underlying read failure.
    pub async fn next_line(&mut self) -> Result<Option<Line>, PoolError> {
        loop {
            let available = self.inner.fill_buf().await.map_err(PoolError::Io)?;

            if available.is_empty() {
                // EOF. Flush any trailing bytes that arrived without a
                // newline exactly once, then report EOF on the next call.
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let bytes = std::mem::take(&mut self.buf);
                return match String::from_utf8(bytes) {
                    Ok(line) => Ok(Some(line)),
                    Err(_) => Err(PoolError::Protocol("non-utf8 stratum line".to_string())),
                };
            }

            if let Some(i) = available.iter().position(|&b| b == b'\n') {
                // Copy up to and including the newline, then release the
                // borrow on `inner` before consuming.
                self.buf.extend_from_slice(&available[..=i]);
                let consumed = i + 1;
                self.inner.consume(consumed);

                if self.buf.len() > MAX_LINE_BYTES {
                    return Err(PoolError::Protocol(format!(
                        "stratum line exceeds {} bytes",
                        MAX_LINE_BYTES
                    )));
                }
                let bytes = std::mem::take(&mut self.buf);
                return match String::from_utf8(bytes) {
                    Ok(line) => Ok(Some(line)),
                    Err(_) => Err(PoolError::Protocol("non-utf8 stratum line".to_string())),
                };
            }

            // No newline in this chunk — accumulate all of it and keep
            // reading, but bail the instant we cross the cap so an endless
            // line cannot exhaust memory.
            let n = available.len();
            self.buf.extend_from_slice(available);
            self.inner.consume(n);
            if self.buf.len() > MAX_LINE_BYTES {
                return Err(PoolError::Protocol(format!(
                    "stratum line exceeds {} bytes",
                    MAX_LINE_BYTES
                )));
            }
        }
    }

    /// Consume the reader, returning the wrapped source. Handy for tests
    /// and for handing the socket half onward after the handshake.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Write a single stratum line, appending a trailing `\n` if the caller did
/// not include one, and flushing. Byte count written is left to the caller
/// to meter (via the shared `Metrics`) — this function only moves bytes.
pub async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, line: &str) -> Result<(), PoolError> {
    w.write_all(line.as_bytes()).await.map_err(PoolError::Io)?;
    if !line.ends_with('\n') {
        w.write_all(b"\n").await.map_err(PoolError::Io)?;
    }
    w.flush().await.map_err(PoolError::Io)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Classification: downstream (miner → proxy)
// ─────────────────────────────────────────────────────────────────────────

/// Classify a miner→proxy line into a `ClientMsg`, stamping `worker` onto
/// any `Share` produced. Malformed JSON is a protocol violation (`Err`); a
/// well-formed line with no `method`, or a recognized method we do not act
/// on specially, classifies as `Passthrough` so the router forwards it
/// verbatim.
pub fn classify_client(line: &str, worker: WorkerId) -> Result<Framed<ClientMsg>, PoolError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(framed(line, ClientMsg::Passthrough));
    }

    let v: Value = serde_json::from_str(trimmed)
        .map_err(|e| PoolError::Protocol(format!("client parse: {}", e)))?;

    let method = match v.get("method").and_then(Value::as_str) {
        Some(m) => m.to_string(),
        // A well-formed line with no method (e.g. a client-side response) is
        // not something this proxy interprets — forward it untouched.
        None => return Ok(framed(line, ClientMsg::Passthrough)),
    };

    let id = v.get("id").cloned();
    let params = v.get("params").cloned().unwrap_or(Value::Null);

    let parsed = match method.as_str() {
        methods::SUBSCRIBE => ClientMsg::Subscribe { id, params },
        methods::CONFIGURE => ClientMsg::Configure { id, params },
        methods::AUTHORIZE => {
            // params[0] = username (the bech32 address the node validates).
            let user = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            ClientMsg::Authorize { id, user, params }
        }
        methods::SUBMIT => {
            let req = RawRequest {
                id,
                method,
                params,
            };
            match parse_submit(&req, worker) {
                Some(share) => ClientMsg::Submit(share),
                // A submit with the wrong param shape: don't drop it, forward
                // it and let the node return the authoritative error.
                None => ClientMsg::Passthrough,
            }
        }
        methods::SUGGEST_DIFFICULTY | methods::SUGGEST_TARGET => {
            // suggest_difficulty carries a numeric difficulty in params[0];
            // suggest_target carries a hex target string (not an f64) — it
            // classifies with value 0.0 and the router treats it as an
            // untyped hint.
            let value = params
                .as_array()
                .and_then(|a| a.first())
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            ClientMsg::SuggestDifficulty { id, value }
        }
        _ => ClientMsg::Passthrough,
    };

    Ok(framed(line, parsed))
}

// ─────────────────────────────────────────────────────────────────────────
// Classification: upstream (node → proxy)
// ─────────────────────────────────────────────────────────────────────────

/// Classify a node→proxy line into a `ServerMsg`.
///
/// A line carrying a `method` is a server notification (`mining.notify`,
/// `mining.set_difficulty`, `mining.set_extranonce`); anything else with a
/// `result`/`error` is a response to a request the proxy forwarded upstream.
///
/// Note (per the interface contract): a `true`/`false` response cannot, by
/// itself, be distinguished as a submit-result vs. an authorize/configure/
/// suggest result — they all come back on the same upstream. This function
/// optimistically classifies every non-subscribe response as `SubmitResult`
/// and tags it with the request `id`; the ROUTER, which knows which ids it
/// sent as submits, is responsible for matching by `id` and ignoring the
/// rest. That keeps the codec pure and IO-free while matching the published
/// `classify_server(line)` signature (no id-map argument).
pub fn classify_server(line: &str) -> Result<Framed<ServerMsg>, PoolError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(framed(line, ServerMsg::Passthrough));
    }

    let v: Value = serde_json::from_str(trimmed)
        .map_err(|e| PoolError::Protocol(format!("server parse: {}", e)))?;

    // Server-initiated notification?
    if let Some(method) = v.get("method").and_then(Value::as_str) {
        let n = RawNotification {
            method: method.to_string(),
            params: v.get("params").cloned().unwrap_or(Value::Null),
        };
        let parsed = match method {
            methods::NOTIFY => match parse_notify(&n) {
                Some(job) => ServerMsg::Notify(job),
                None => ServerMsg::Passthrough,
            },
            methods::SET_DIFFICULTY => match parse_set_difficulty(&n) {
                Some(d) => ServerMsg::SetDifficulty(d),
                None => ServerMsg::Passthrough,
            },
            methods::SET_EXTRANONCE => match parse_set_extranonce(&n) {
                Some((extranonce1, extranonce2_size)) => ServerMsg::SetExtranonce {
                    extranonce1,
                    extranonce2_size,
                },
                None => ServerMsg::Passthrough,
            },
            _ => ServerMsg::Passthrough,
        };
        return Ok(framed(line, parsed));
    }

    // Response to a forwarded request?
    if v.get("result").is_some() || v.get("error").is_some() {
        let resp = RawResponse {
            id: v.get("id").cloned(),
            result: v.get("result").cloned().unwrap_or(Value::Null),
            error: v.get("error").cloned().unwrap_or(Value::Null),
        };
        let parsed = if let Some(sr) = parse_subscribe_result(&resp) {
            ServerMsg::SubscribeResult(sr)
        } else {
            ServerMsg::SubmitResult {
                id: resp.id.clone(),
                outcome: submit_outcome(&resp),
            }
        };
        return Ok(framed(line, parsed));
    }

    Ok(framed(line, ServerMsg::Passthrough))
}

// ─────────────────────────────────────────────────────────────────────────
// Narrow parse helpers (also called directly by router / upstream)
// ─────────────────────────────────────────────────────────────────────────

/// Parse a `mining.subscribe` result:
/// `[[["mining.set_difficulty",en1],["mining.notify",en1]], en1_hex, en2_size]`.
///
/// The leading element MUST be an array (the subscriptions list); this is
/// what distinguishes a subscribe-result from a plain boolean/`true`
/// response (authorize, configure, suggest) that shares the response shape.
pub fn parse_subscribe_result(resp: &RawResponse) -> Option<SubscribeResult> {
    let arr = resp.result.as_array()?;
    if arr.len() < 3 {
        return None;
    }
    // Discriminator: element 0 is the subscriptions array. A submit/authorize
    // "true" has no array here, so we won't misclassify it.
    if !arr[0].is_array() {
        return None;
    }
    let extranonce1 = arr[1].as_str()?.to_string();
    let extranonce2_size = arr[2].as_u64()? as usize;
    Some(SubscribeResult {
        extranonce1,
        extranonce2_size,
    })
}

/// Parse a `mining.notify` job. params[0] = job_id, params[8] = clean_jobs.
/// A missing/short `clean_jobs` defaults to `false` (do not abandon work).
pub fn parse_notify(n: &RawNotification) -> Option<Job> {
    let arr = n.params.as_array()?;
    let job_id = arr.first()?.as_str()?.to_string();
    let clean_jobs = arr.get(8).and_then(Value::as_bool).unwrap_or(false);
    Some(Job {
        job_id,
        clean_jobs,
        received_at: Instant::now(),
    })
}

/// Parse `mining.set_difficulty` — params[0] is the numeric difficulty.
pub fn parse_set_difficulty(n: &RawNotification) -> Option<f64> {
    n.params.as_array()?.first()?.as_f64()
}

/// Parse `mining.set_extranonce` — `[extranonce1_hex, extranonce2_size]`.
/// A missing size falls back to the node's default of 4 bytes.
pub fn parse_set_extranonce(n: &RawNotification) -> Option<(String, usize)> {
    let arr = n.params.as_array()?;
    let extranonce1 = arr.first()?.as_str()?.to_string();
    let extranonce2_size = arr.get(1).and_then(Value::as_u64).unwrap_or(4) as usize;
    Some((extranonce1, extranonce2_size))
}

/// Parse a `mining.submit`:
/// `[worker_name, job_id, extranonce2, ntime, nonce, version_bits?]`.
/// The wire `worker_name` (params[0]) is ignored — the proxy's own `WorkerId`
/// is authoritative. `difficulty` is left at `0.0` for the router to fill from
/// session state (it is not present on the wire).
///
/// The OPTIONAL 6th param is a version-rolling (ASICBoost / BIP310) miner's
/// rolled nVersion, hex. Antminer/Whatsminer firmware and MRR/NiceHash rig
/// proxies append it whenever they version-roll. Dropping it makes the pool
/// reconstruct every rolled share's header with the STATIC job version, so the
/// hash never matches and every share rejects as low-difficulty.
pub fn parse_submit(req: &RawRequest, worker: WorkerId) -> Option<Share> {
    let arr = req.params.as_array()?;
    if arr.len() < 5 {
        return None;
    }
    let job_id = arr[1].as_str()?.to_string();
    let extranonce2 = arr[2].as_str()?.to_string();
    let ntime = arr[3].as_str()?.to_string();
    let nonce = arr[4].as_str()?.to_string();
    // 6th param (version-rolling bits): present only for version-rolling miners.
    // Tolerate an optional 0x prefix; ignore a malformed value rather than
    // dropping the whole submit (fall back to the job version).
    let version = arr.get(5).and_then(Value::as_str).and_then(|s| {
        let t = s.trim();
        let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
        u32::from_str_radix(t, 16).ok()
    });
    Some(Share {
        worker,
        job_id,
        extranonce2,
        ntime,
        nonce,
        version,
        difficulty: 0.0,
        submitted_at: Instant::now(),
    })
}

/// Map a `mining.submit` response to a `ShareOutcome`.
///
/// `result: true` ⇒ `Accepted`. Otherwise, if an error array
/// `[code, msg, null]` is present, map the code via
/// `ShareOutcome::from_error_code`. A `false`/`null` result with no error
/// array is a generic rejection. (The proxy cannot tell a block from an
/// ordinary accepted share from `result:true` alone — that is the optional
/// `RouterHooks` block-detection concern, so this never returns `Block`.)
pub fn submit_outcome(resp: &RawResponse) -> ShareOutcome {
    if resp.result.as_bool() == Some(true) {
        return ShareOutcome::Accepted;
    }
    if let Some(err) = resp.error.as_array() {
        let code = err.first().and_then(Value::as_i64).unwrap_or(error_codes::OTHER);
        let message = err
            .get(1)
            .and_then(Value::as_str)
            .unwrap_or("share rejected")
            .to_string();
        return ShareOutcome::from_error_code(code, message);
    }
    ShareOutcome::Rejected {
        code: error_codes::OTHER,
        message: "share rejected".to_string(),
    }
}

/// Is this line a JSON-RPC *request* (has a `method` AND a non-null `id`)?
/// Server notifications (null id) and responses (no method) return `false`.
/// A line that does not parse returns `false`.
pub fn is_request(line: &str) -> bool {
    let v: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    v.get("method").and_then(Value::as_str).is_some()
        && v.get("id").map_or(false, |id| !id.is_null())
}

/// Extract the `method` field of a line, if present and a string.
pub fn method_of(line: &str) -> Option<String> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    v.get("method").and_then(Value::as_str).map(str::to_string)
}

// ─────────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────────

/// Bundle the untouched input line with its classification. Central so the
/// invariant "`raw` is always the verbatim input" holds in one place.
#[inline]
fn framed<T>(line: &str, parsed: T) -> Framed<T> {
    Framed {
        raw: line.to_string(),
        parsed,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    const W: WorkerId = WorkerId(7);

    fn reader(bytes: &'static [u8]) -> LineReader<BufReader<&'static [u8]>> {
        LineReader::new(BufReader::new(bytes))
    }

    // ── Framing ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn reads_multiple_newline_delimited_lines_with_trailing_newline() {
        let mut r = reader(b"{\"a\":1}\n{\"b\":2}\n");
        let l1 = r.next_line().await.unwrap().unwrap();
        let l2 = r.next_line().await.unwrap().unwrap();
        assert_eq!(l1, "{\"a\":1}\n");
        assert_eq!(l2, "{\"b\":2}\n");
        assert!(r.next_line().await.unwrap().is_none(), "clean EOF => None");
    }

    #[tokio::test]
    async fn delivers_final_unterminated_line_then_eof() {
        let mut r = reader(b"no-newline-here");
        let l = r.next_line().await.unwrap().unwrap();
        assert_eq!(l, "no-newline-here");
        assert!(r.next_line().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn empty_input_is_immediate_eof() {
        let mut r = reader(b"");
        assert!(r.next_line().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversize_line_without_newline_is_protocol_error() {
        // A line longer than the cap, no newline in sight.
        let giant: &'static [u8] = Box::leak(vec![b'x'; MAX_LINE_BYTES + 10].into_boxed_slice());
        let mut r = LineReader::new(BufReader::new(giant));
        match r.next_line().await {
            Err(PoolError::Protocol(_)) => {}
            other => panic!("expected Protocol error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn write_line_appends_newline_when_absent() {
        let mut out: Vec<u8> = Vec::new();
        write_line(&mut out, "{\"x\":1}").await.unwrap();
        assert_eq!(out, b"{\"x\":1}\n");
    }

    #[tokio::test]
    async fn write_line_keeps_existing_newline() {
        let mut out: Vec<u8> = Vec::new();
        write_line(&mut out, "{\"x\":1}\n").await.unwrap();
        assert_eq!(out, b"{\"x\":1}\n");
    }

    // ── Client classification ────────────────────────────────────────

    #[test]
    fn classifies_subscribe() {
        let f = classify_client(
            r#"{"id":1,"method":"mining.subscribe","params":["cpuminer/2.5"]}"#,
            W,
        )
        .unwrap();
        match f.parsed {
            ClientMsg::Subscribe { id, .. } => assert_eq!(id, Some(Value::from(1))),
            other => panic!("expected Subscribe, got {:?}", other),
        }
        // raw is forwarded verbatim.
        assert!(f.raw.contains("mining.subscribe"));
    }

    #[test]
    fn classifies_configure() {
        let f = classify_client(
            r#"{"id":0,"method":"mining.configure","params":[["version-rolling"],{}]}"#,
            W,
        )
        .unwrap();
        assert!(matches!(f.parsed, ClientMsg::Configure { .. }));
    }

    #[test]
    fn classifies_authorize_and_extracts_user() {
        let f = classify_client(
            r#"{"id":2,"method":"mining.authorize","params":["bloch1qexampleaddr","x"]}"#,
            W,
        )
        .unwrap();
        match f.parsed {
            ClientMsg::Authorize { user, .. } => assert_eq!(user, "bloch1qexampleaddr"),
            other => panic!("expected Authorize, got {:?}", other),
        }
    }

    #[test]
    fn classifies_submit_and_stamps_worker() {
        let f = classify_client(
            r#"{"id":9,"method":"mining.submit","params":["worker","job-1","deadbeef","5f5e1000","00c0ffee"]}"#,
            W,
        )
        .unwrap();
        match f.parsed {
            ClientMsg::Submit(share) => {
                assert_eq!(share.worker, W);
                assert_eq!(share.job_id, "job-1");
                assert_eq!(share.extranonce2, "deadbeef");
                assert_eq!(share.ntime, "5f5e1000");
                assert_eq!(share.nonce, "00c0ffee");
                assert_eq!(share.difficulty, 0.0);
            }
            other => panic!("expected Submit, got {:?}", other),
        }
    }

    #[test]
    fn malformed_submit_falls_through_to_passthrough() {
        // Only 3 params — cannot form a Share; must forward, not drop.
        let f = classify_client(
            r#"{"id":9,"method":"mining.submit","params":["worker","job-1","deadbeef"]}"#,
            W,
        )
        .unwrap();
        assert!(matches!(f.parsed, ClientMsg::Passthrough));
    }

    #[test]
    fn classifies_suggest_difficulty() {
        let f = classify_client(
            r#"{"id":3,"method":"mining.suggest_difficulty","params":[512.0]}"#,
            W,
        )
        .unwrap();
        match f.parsed {
            ClientMsg::SuggestDifficulty { value, .. } => assert_eq!(value, 512.0),
            other => panic!("expected SuggestDifficulty, got {:?}", other),
        }
    }

    #[test]
    fn suggest_target_hex_string_classifies_with_zero_value() {
        let f = classify_client(
            r#"{"id":3,"method":"mining.suggest_target","params":["00000000ffff0000"]}"#,
            W,
        )
        .unwrap();
        assert!(matches!(
            f.parsed,
            ClientMsg::SuggestDifficulty { value, .. } if value == 0.0
        ));
    }

    #[test]
    fn unknown_client_method_is_passthrough() {
        let f = classify_client(r#"{"id":5,"method":"mining.hello","params":[]}"#, W).unwrap();
        assert!(matches!(f.parsed, ClientMsg::Passthrough));
    }

    #[test]
    fn client_line_without_method_is_passthrough() {
        let f = classify_client(r#"{"id":5,"result":true,"error":null}"#, W).unwrap();
        assert!(matches!(f.parsed, ClientMsg::Passthrough));
    }

    #[test]
    fn malformed_json_is_protocol_error() {
        assert!(matches!(
            classify_client("{not json", W),
            Err(PoolError::Protocol(_))
        ));
        assert!(matches!(
            classify_server("not json at all"),
            Err(PoolError::Protocol(_))
        ));
    }

    #[test]
    fn empty_line_classifies_as_passthrough_both_directions() {
        assert!(matches!(
            classify_client("   \n", W).unwrap().parsed,
            ClientMsg::Passthrough
        ));
        assert!(matches!(
            classify_server("   \n").unwrap().parsed,
            ServerMsg::Passthrough
        ));
    }

    // ── Server classification ────────────────────────────────────────

    #[test]
    fn classifies_subscribe_result_and_extracts_extranonce1() {
        let line = r#"{"id":1,"result":[[["mining.set_difficulty","abcd1234"],["mining.notify","abcd1234"]],"abcd1234",4],"error":null}"#;
        let f = classify_server(line).unwrap();
        match f.parsed {
            ServerMsg::SubscribeResult(sr) => {
                assert_eq!(sr.extranonce1, "abcd1234");
                assert_eq!(sr.extranonce2_size, 4);
            }
            other => panic!("expected SubscribeResult, got {:?}", other),
        }
    }

    #[test]
    fn classifies_notify_job_id_and_clean_jobs() {
        let line = r#"{"id":null,"method":"mining.notify","params":["job-42","prev","c1","c2",[],"20000000","1a2b3c4d","5f5e1000",true]}"#;
        let f = classify_server(line).unwrap();
        match f.parsed {
            ServerMsg::Notify(job) => {
                assert_eq!(job.job_id, "job-42");
                assert!(job.clean_jobs);
            }
            other => panic!("expected Notify, got {:?}", other),
        }
    }

    #[test]
    fn notify_missing_clean_jobs_defaults_false() {
        let line = r#"{"id":null,"method":"mining.notify","params":["job-7"]}"#;
        let f = classify_server(line).unwrap();
        match f.parsed {
            ServerMsg::Notify(job) => {
                assert_eq!(job.job_id, "job-7");
                assert!(!job.clean_jobs);
            }
            other => panic!("expected Notify, got {:?}", other),
        }
    }

    #[test]
    fn classifies_set_difficulty() {
        let f = classify_server(r#"{"id":null,"method":"mining.set_difficulty","params":[16384.0]}"#)
            .unwrap();
        match f.parsed {
            ServerMsg::SetDifficulty(d) => assert_eq!(d, 16384.0),
            other => panic!("expected SetDifficulty, got {:?}", other),
        }
    }

    #[test]
    fn classifies_set_extranonce() {
        let f = classify_server(
            r#"{"id":null,"method":"mining.set_extranonce","params":["ff00ff00",4]}"#,
        )
        .unwrap();
        match f.parsed {
            ServerMsg::SetExtranonce {
                extranonce1,
                extranonce2_size,
            } => {
                assert_eq!(extranonce1, "ff00ff00");
                assert_eq!(extranonce2_size, 4);
            }
            other => panic!("expected SetExtranonce, got {:?}", other),
        }
    }

    #[test]
    fn accepted_submit_result() {
        let f = classify_server(r#"{"id":10,"result":true,"error":null}"#).unwrap();
        match f.parsed {
            ServerMsg::SubmitResult { id, outcome } => {
                assert_eq!(id, Some(Value::from(10)));
                assert_eq!(outcome, ShareOutcome::Accepted);
            }
            other => panic!("expected SubmitResult, got {:?}", other),
        }
    }

    #[test]
    fn rejected_submit_results_map_error_codes() {
        let cases = [
            (21, ShareOutcome::Stale),
            (22, ShareOutcome::Duplicate),
            (23, ShareOutcome::LowDifficulty),
        ];
        for (code, want) in cases {
            let line = format!(
                r#"{{"id":11,"result":null,"error":[{},"rejected",null]}}"#,
                code
            );
            let f = classify_server(&line).unwrap();
            match f.parsed {
                ServerMsg::SubmitResult { outcome, .. } => assert_eq!(outcome, want),
                other => panic!("expected SubmitResult, got {:?}", other),
            }
        }
    }

    #[test]
    fn other_error_code_maps_to_rejected() {
        let f = classify_server(r#"{"id":11,"result":null,"error":[24,"unauthorized",null]}"#)
            .unwrap();
        match f.parsed {
            ServerMsg::SubmitResult { outcome, .. } => {
                assert_eq!(
                    outcome,
                    ShareOutcome::Rejected {
                        code: 24,
                        message: "unauthorized".to_string()
                    }
                );
            }
            other => panic!("expected SubmitResult, got {:?}", other),
        }
    }

    #[test]
    fn boolean_true_response_is_not_a_subscribe_result() {
        // e.g. an authorize/configure/suggest true — reads as a SubmitResult
        // by shape; the router disambiguates by id.
        let f = classify_server(r#"{"id":2,"result":true,"error":null}"#).unwrap();
        assert!(matches!(f.parsed, ServerMsg::SubmitResult { .. }));
    }

    // ── Narrow helpers ───────────────────────────────────────────────

    #[test]
    fn is_request_distinguishes_requests_from_notifications_and_responses() {
        assert!(is_request(
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#
        ));
        // notification: null id
        assert!(!is_request(
            r#"{"id":null,"method":"mining.notify","params":[]}"#
        ));
        // response: no method
        assert!(!is_request(r#"{"id":1,"result":true,"error":null}"#));
        // garbage
        assert!(!is_request("garbage"));
    }

    #[test]
    fn method_of_extracts_method_or_none() {
        assert_eq!(
            method_of(r#"{"id":1,"method":"mining.submit","params":[]}"#),
            Some("mining.submit".to_string())
        );
        assert_eq!(method_of(r#"{"id":1,"result":true}"#), None);
        assert_eq!(method_of("not json"), None);
    }

    #[test]
    fn parse_submit_rejects_non_string_fields() {
        // job_id numeric instead of string => None (won't panic).
        let req = RawRequest {
            id: Some(Value::from(1)),
            method: methods::SUBMIT.to_string(),
            params: serde_json::json!(["w", 5, "en2", "ntime", "nonce"]),
        };
        assert!(parse_submit(&req, W).is_none());
    }

    #[test]
    fn parse_subscribe_result_requires_leading_array() {
        // A response whose result[0] is not an array must NOT be taken as a
        // subscribe-result (guards against misclassifying odd responses).
        let resp = RawResponse {
            id: Some(Value::from(1)),
            result: serde_json::json!(["notanarray", "abcd", 4]),
            error: Value::Null,
        };
        assert!(parse_subscribe_result(&resp).is_none());
    }
}
