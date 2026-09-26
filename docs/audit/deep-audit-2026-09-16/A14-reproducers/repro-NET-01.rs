// Repro for NET-01 — "Public bootnodes expose the full unauthenticated RPC
// (incl. sendrawtransaction) on :8080, and RPC executes on the consensus thread"
//
// DO NOT RUN, DO NOT COMMIT. This is a written repro only.
//
// Placement to compile: these tests reuse the helpers already defined in
// crates/bloch-pos-node/src/rpc/tests.rs (`Spy`, `call`, `request`,
// `test_server`, `post`, `state_with_balances`, `test_transfer`). Read them as
// if appended to that file's `mod tests` (which is `use super::*` of the rpc
// module, so `handle_body`, `route`, `RpcRequest`, `EngineBackend`,
// `RpcBackend`, `serve`, `parse_json` and `crate::engine::EngineEvent` are all
// in scope).
//
// What each test proves, mapped to the finding:
//   A: no credential of any kind is required to route `sendrawtransaction`
//      (a mempool-admit + network-broadcast write).           [claim 1: no auth]
//   B: every non-ledger RPC request is delivered to the engine event loop
//      (the consensus thread), while only Balance/Utxos are answered
//      off-thread from the published head.                    [claim 2: on-thread]
//   C: the same at the HTTP layer over a real socket: an unauthenticated POST
//      is accepted and dispatched.                            [claim 1, wire level]

use super::*;
use std::sync::mpsc;

fn hexlify(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── A. sendrawtransaction is routed with NO authentication ──────────────────
#[test]
fn net01_sendrawtransaction_is_dispatched_without_any_credential() {
    let spy = Spy::new();
    // A structurally valid transfer; canonical_bytes round-trips through
    // from_canonical_bytes (route's only decode gate — it verifies no
    // signature and asks for no key/token/apikey).
    let tx = test_transfer(1, 200, 5);
    let hex = hexlify(&tx.canonical_bytes());
    let body = request("sendrawtransaction", &format!("[\"{hex}\"]"));

    // No Authorization header, no api key, no session — handle_body is the
    // whole gate and it has none. The write route reaches the backend.
    let _ = call(spy.as_ref(), &body);
    assert!(
        matches!(spy.last(), Some(RpcRequest::SendRawTransaction(_))),
        "an unauthenticated body reached the network-broadcasting write route: {:?}",
        spy.last()
    );
}

// ── B. non-ledger requests run on the consensus thread; only ledger reads
//       are answered off-thread from the published head ──────────────────────
#[test]
fn net01_non_ledger_requests_go_to_the_engine_loop_ledger_reads_do_not() {
    // (1) A backend with a published head. Balance is answered off-thread:
    //     nothing is ever sent on the engine channel, so a dropped receiver
    //     is irrelevant and the call returns immediately.
    let (loop_tx, loop_rx) = mpsc::channel::<crate::engine::EngineEvent>();
    let head: crate::engine::SharedHead =
        std::sync::Arc::new(std::sync::Mutex::new(std::sync::Arc::new(state_with_balances())));
    let backend = EngineBackend::with_head(loop_tx, head);

    let script = [0u8; 32];
    let balance = backend.call(RpcRequest::Balance(script));
    assert!(balance.is_ok(), "getbalance must be answerable off the consensus thread");
    assert!(
        loop_rx.try_recv().is_err(),
        "a ledger read must NOT be posted to the engine loop"
    );

    // (2) A non-ledger request (getchaininfo) IS posted to the engine loop.
    //     Prove it by receiving the EngineEvent::Rpc the backend enqueues —
    //     the same channel the slot loop drains inline via serve_rpc, i.e. the
    //     consensus thread. sendrawtransaction takes the identical path.
    let (loop_tx2, loop_rx2) = mpsc::channel::<crate::engine::EngineEvent>();
    let head2: crate::engine::SharedHead =
        std::sync::Arc::new(std::sync::Mutex::new(std::sync::Arc::new(state_with_balances())));
    let backend2 = std::sync::Arc::new(EngineBackend::with_head(loop_tx2, head2));

    let b = backend2.clone();
    let caller = std::thread::spawn(move || b.call(RpcRequest::ChainInfo));

    match loop_rx2.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(crate::engine::EngineEvent::Rpc(call)) => {
            assert_eq!(
                call.req,
                RpcRequest::ChainInfo,
                "the request handed to the consensus thread is the client's request"
            );
            // Answer it so the caller thread unblocks.
            let _ = call.reply.send(Ok(Json::s("ok")));
        }
        other => panic!("getchaininfo was not routed to the engine loop: {other:?}"),
    }
    let _ = caller.join().expect("caller thread");

    // (3) With no consumer draining the loop, a non-ledger call cannot be
    //     answered at all: it depends on the consensus thread being free.
    //     (ENGINE_TIMEOUT is 10s; this documents the dependency — expect the
    //     test to sit for that long, or drop the receiver to force
    //     Disconnected immediately, as shown below.)
    let (loop_tx3, loop_rx3) = mpsc::channel::<crate::engine::EngineEvent>();
    let head3: crate::engine::SharedHead =
        std::sync::Arc::new(std::sync::Mutex::new(std::sync::Arc::new(state_with_balances())));
    let backend3 = EngineBackend::with_head(loop_tx3, head3);
    drop(loop_rx3); // no consensus thread => channel disconnected
    let outcome = backend3.call(RpcRequest::ChainInfo);
    assert!(
        outcome.is_err(),
        "a non-ledger request with no consensus thread to serve it cannot be answered"
    );
}

// ── C. HTTP layer: an unauthenticated POST is accepted and dispatched ───────
#[test]
fn net01_http_post_needs_no_credential() {
    let (addr, spy) = test_server();
    // `post` sends Host: localhost, Content-Type: application/json, and a body
    // — no Authorization, no cookie, no token. The gate (Host/Origin/CT) is
    // anti-CSRF, not authentication.
    let resp = post(addr, &request("getvalidators", "[]"));
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "unauthenticated POST refused: {resp}");
    assert_eq!(spy.last(), Some(RpcRequest::Validators));
}
