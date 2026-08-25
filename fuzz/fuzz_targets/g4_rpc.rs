// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]
//! `rpc.rs` — the JSON-RPC parse + route surface. A PUBLIC network surface:
//! `g4rpc.posternpool.com` proxies this to the open internet, and the server
//! authenticates nothing (`rpc.rs::serve`, "# Exposure"). "Malformed input
//! crashes the node" and "anyone can stop the validator" are the same sentence.
//!
//! Covered:
//!   * `parse_json` — the hand-written JSON parser (recursive descent, numbers
//!     kept as raw source text).
//!   * `handle_body` — id echo, `jsonrpc` check, method extraction, and the
//!     full `route()` dispatch including `want_u64` / `want_u32` /
//!     `want_hex32` / `from_hex` and `PosTransaction::from_canonical_bytes`
//!     on `sendrawtransaction` (a real consensus-object decoder reached
//!     straight off the wire).
//!
//! NOT covered, deliberately and explicitly: the engine dispatch behind
//! `RpcBackend`. In production that is `EngineBackend`, which hands the request
//! to the consensus thread and blocks on a reply channel — it cannot be stood
//! up cheaply or deterministically in a fuzz iteration. The stub below answers
//! every request without touching node state, so everything from the socket
//! body down to `RpcRequest` is fuzzed and everything past `RpcRequest` is not.
//! Do not read a clean run here as coverage of the engine's query handlers.

use bloch_pos_node::rpc::{from_hex, handle_body, parse_json, Json, RpcBackend, RpcRequest, RpcResult};
use libfuzzer_sys::fuzz_target;

/// Answers without consensus state. Returning the discriminant rather than
/// `Ok(Json::Null)` keeps `route()`'s output observable to the fuzzer's
/// coverage feedback instead of collapsing every method onto one edge.
struct StubBackend;

impl RpcBackend for StubBackend {
    fn call(&self, req: RpcRequest) -> RpcResult {
        Ok(Json::s(match req {
            RpcRequest::ChainInfo => "chaininfo",
            RpcRequest::BlockCount => "blockcount",
            RpcRequest::BlockBySlot(_) => "blockbyslot",
            RpcRequest::BlockById(_) => "blockbyid",
            RpcRequest::Validator(_) => "validator",
            RpcRequest::ValidatorCount => "validatorcount",
            RpcRequest::Balance(_) => "balance",
            RpcRequest::Utxos { .. } => "utxos",
            RpcRequest::TxOut { .. } => "txout",
            RpcRequest::SendRawTransaction(_) => "sendraw",
            RpcRequest::MempoolInfo => "mempoolinfo",
        }))
    }
}

fuzz_target!(|data: &[u8]| {
    // The socket layer hands `handle_body` a `&str`. Feed lossy UTF-8 so every
    // input reaches the parser (bailing on invalid UTF-8 would let the fuzzer
    // spend its budget on byte strings the target then throws away), and feed
    // the strict decode too when it is available, so the real edge case of a
    // body that is exactly valid UTF-8 is also explored.
    let lossy = String::from_utf8_lossy(data);

    let _ = parse_json(&lossy);

    let backend = StubBackend;
    let reply = handle_body(&lossy, &backend);
    // Total function: every input produces a JSON-RPC response body, and that
    // body must itself be parseable — an unparseable reply is a client-side
    // hang, not a client-side error.
    assert!(
        parse_json(&reply).is_ok(),
        "rpc: handle_body emitted a body its own parser rejects"
    );

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = from_hex(s);
        let _ = handle_body(s, &backend);
    }
});
