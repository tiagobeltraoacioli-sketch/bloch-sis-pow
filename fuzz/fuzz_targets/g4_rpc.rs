#![no_main]
//! Genesis-4 JSON-RPC parser and route dispatcher on bounded HTTP body input.

use bloch_pos_node::rpc::{self, RpcBackend, RpcError, RpcRequest, RpcResult};
use libfuzzer_sys::fuzz_target;

struct RefuseCalls;

impl RpcBackend for RefuseCalls {
    fn call(&self, _: RpcRequest) -> RpcResult {
        Err(RpcError::unavailable("fuzz backend"))
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > rpc::MAX_BODY_BYTES {
        return;
    }
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };

    let _ = rpc::parse_json(body);
    let _ = rpc::handle_body(body, &RefuseCalls);
});
