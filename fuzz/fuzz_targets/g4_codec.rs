// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]
//! `codec.rs` — the Genesis-4 block-envelope / attestation wire decoders.
//!
//! Surface: `crates/bloch-pos-node/src/codec.rs`, reached from BOTH untrusted
//! ingest paths — gossiped blocks (`p2p.rs` → `decode_envelope`) and sync
//! response bodies (`decode_sync_response` → `decode_envelope` per element).
//! Every byte here comes from an unauthenticated peer.
//!
//! Properties asserted:
//!   P1 NO PANIC on arbitrary bytes. `Reader::take` does `self.buf.len() -
//!      self.at` (an unsigned subtraction) and every integer reader ends in
//!      `.try_into().unwrap()`; `MAX_FIELD_LEN` (8 MiB, codec.rs:24) is the
//!      only thing between a 4-byte length prefix and the allocator.
//!   P2 INJECTIVITY: `encode(decode(x)) == x` for every x that decodes. The
//!      log digest and the frame dedup both key on encoded bytes, so a decoder
//!      that maps two byte strings onto one envelope is a consensus bug, not a
//!      cosmetic one. This is the property `finish()`'s trailing-bytes check
//!      exists to hold.
//!
//! This links the REAL crate (`bloch_pos_node::codec`). Nothing is
//! reimplemented here — a fuzz target that re-derives the parser proves
//! something about the target, not about the node.

use bloch_pos_node::codec::{
    decode_attestation, decode_envelope, encode_attestation, encode_envelope, unhex, Reader,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // ── The envelope decoder: the whole gossip/sync block ingest. ──
    if let Ok(env) = decode_envelope(data) {
        let re = encode_envelope(&env);
        assert!(
            re == data,
            "codec: encode(decode(x)) != x — decoder is not injective \
             ({} bytes in, {} out)",
            data.len(),
            re.len()
        );
    }

    // ── The attestation decoder on its own, so the fuzzer can reach it ──
    // without first having to synthesise 304 valid header bytes.
    {
        let mut r = Reader::new(data);
        if let Ok(att) = decode_attestation(&mut r) {
            // `Reader` exposes no cursor, so the injectivity check is stated
            // as a prefix: re-encoding the attestation must reproduce exactly
            // the bytes the decoder consumed, which are a prefix of `data`.
            let mut re = Vec::new();
            encode_attestation(&mut re, &att);
            assert!(
                data.starts_with(&re),
                "codec: attestation encode(decode(x)) is not a prefix of x"
            );
        }
    }

    // ── `unhex` parses outpoints/keys/signatures off the RPC edge. Strict by ──
    // contract: odd length or a non-hex digit is an error, never a silently
    // truncated value. It indexes `pair[1]` inside a `chunks(2)` loop.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = unhex(s);
    }
});
