#![no_main]
//! Fuzz `codec::decode_attestation` — the highest-rate untrusted frame on the
//! Genesis-4 network. Every validator emits one per slot and every node
//! decodes all of them, so it is the widest attacker-reachable parser the
//! fleet runs.
//!
//! The property is strictness: for input the decoder consumes *entirely*
//! (`Reader::finish` — the check that rejects `encode(a) ‖ junk`),
//! `encode_attestation` must reproduce the input byte for byte. Attestations
//! are deduplicated and hashed by their wire bytes; a decoder with slack lets
//! one attestation wear two identities, which is a double-count in the quorum
//! that a re-encode check catches and a no-panic check does not.
//!
//! `bloch-pos-node` is a `[[bin]]`-only crate, so the module is pulled in by
//! `#[path]`: these bytes run the node's own source, not a copy of it.
use libfuzzer_sys::fuzz_target;

// The whole module compiles in, but a target drives one entry point, so the
// rest is dead code *here* — not in the node.
#[allow(dead_code)]
#[path = "../../crates/bloch-pos-node/src/codec.rs"]
mod codec;

fuzz_target!(|data: &[u8]| {
    let mut r = codec::Reader::new(data);
    let Ok(a) = codec::decode_attestation(&mut r) else { return };
    // Only frames the decoder consumed whole are round-trip candidates; a
    // decoded prefix is not claimed to re-encode to the full buffer.
    if r.finish().is_err() {
        return;
    }
    let mut out = Vec::new();
    codec::encode_attestation(&mut out, &a);
    assert_eq!(out, data, "attestation round-trip is not injective");
});
