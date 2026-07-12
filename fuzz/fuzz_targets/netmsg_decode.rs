#![no_main]
//! Fuzz the gossipsub ingest decoder. `NetworkMessage` is the untrusted wire
//! enum EVERY peer sends; the live ingest at `network/mod.rs:412` does exactly
//! this `bincode::serde::decode_from_slice::<NetworkMessage, _>` on attacker-
//! controlled bytes. A malformed buffer must only ever yield `Err` — never a
//! panic, an unbounded allocation, or a hang. This is the highest-value new
//! target: it is the first thing a hostile peer can reach.
use bloch::network::NetworkMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bincode::serde::decode_from_slice::<NetworkMessage, _>(
        data,
        bincode::config::standard(),
    );
});
