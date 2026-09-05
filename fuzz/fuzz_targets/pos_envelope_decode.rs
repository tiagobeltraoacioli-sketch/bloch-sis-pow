#![no_main]
//! Fuzz `codec::decode_envelope` — the whole Genesis-4 block frame, exactly as
//! it arrives from an untrusted peer on the gossip topic. This is the first
//! thing a hostile peer can reach on the live chain, and it is where the
//! length-prefixed fields (`proposer_sig`, the attestation and transaction
//! counts, every transaction) are turned into allocations.
//!
//! Asserted, beyond absence of panic:
//!
//!   * **Round-trip.** `encode_envelope(decode_envelope(x)) == x` for every
//!     accepted `x`. The decoder ends in `Reader::finish`, so it already
//!     promises to reject `encode(e) ‖ junk`; this is that promise checked
//!     against the encoder rather than restated. Block frames are deduplicated
//!     by their bytes, so slack here is one block with two identities.
//!   * **Declared caps hold.** The `natt > 4096` / `ntx > 65_536` guards in
//!     the decoder are what stand between a four-byte count field and a
//!     multi-gigabyte `Vec::with_capacity`.
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
    let Ok(env) = codec::decode_envelope(data) else { return };
    assert!(env.body.attestations.len() <= 4096, "attestation cap did not hold");
    assert!(env.body.transactions.len() <= 65_536, "transaction cap did not hold");
    assert_eq!(codec::encode_envelope(&env), data, "envelope round-trip is not injective");
});
