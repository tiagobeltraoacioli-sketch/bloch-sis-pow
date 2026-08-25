#![no_main]
//! Genesis-4 libp2p directed-sync request and response decoders.

use bloch_pos_node::p2p;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = p2p::decode_sync_request(data);
    let _ = p2p::decode_sync_response(data);
});
