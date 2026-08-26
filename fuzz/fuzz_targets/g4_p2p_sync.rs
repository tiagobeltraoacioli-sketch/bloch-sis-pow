// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]
//! `p2p.rs` — the directed-sync request/response frame codec.
//!
//! Surface: `crates/bloch-pos-node/src/p2p.rs`. A libp2p request-response
//! substream is delimited by EOF; `read_capped` slurps up to `MAX_SYNC_FRAME`
//! (8 MiB, p2p.rs:278) and hands the whole buffer to `decode_sync_request` /
//! `decode_sync_response`. Everything in that buffer is peer-controlled and
//! arrives before any signature or committee check.
//!
//! This target covers the FRAME DECODE path only. It does not touch
//! `read_capped` itself (p2p.rs:484 — dev WP2 owns the silent-truncation fix
//! there) and it does not touch the async I/O around it.
//!
//! Properties:
//!   P1 NO PANIC on arbitrary bytes, for both decoders.
//!   P2 INJECTIVITY: `encode(decode(x)) == x`. Sync-delivered block bytes are
//!      byte-identical to gossiped ones by design ("a synced block and a
//!      gossiped block are the same object, not two encodings that can
//!      disagree") — a non-injective frame decoder breaks exactly that.
//!   P3 The nested envelope path: each element of a decoded `Blocks` response
//!      is `codec::encode_envelope` output, so it is fed on to
//!      `decode_envelope`, which is where the sync path actually reaches
//!      consensus objects.

use bloch_pos_node::codec::decode_envelope;
use bloch_pos_node::p2p::{
    decode_sync_request, decode_sync_response, encode_sync_request, encode_sync_response,
    SyncResponse,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both decoders read the same tag byte (0x01) off the same buffer, so
    // feeding the whole input to each costs one extra pass and lets a single
    // corpus serve both frame shapes.
    if let Ok(req) = decode_sync_request(data) {
        assert!(
            encode_sync_request(&req) == data,
            "p2p: sync request encode(decode(x)) != x"
        );
    }

    if let Ok(resp) = decode_sync_response(data) {
        assert!(
            encode_sync_response(&resp) == data,
            "p2p: sync response encode(decode(x)) != x"
        );

        // P3 — the elements are block envelopes. This is the path a syncing
        // node walks for every page it pulls from a peer.
        let SyncResponse::Blocks { envelopes } = resp;
        for e in &envelopes {
            let _ = decode_envelope(e);
        }
    }
});
