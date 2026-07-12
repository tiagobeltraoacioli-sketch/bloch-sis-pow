#![no_main]
//! Fuzz the PQ-transport handshake decoders. `HandshakeInit` / `HandshakeResp`
//! (`transport/mod.rs:128,138`) are decoded from bytes an unauthenticated peer
//! sends before any session key exists — the earliest untrusted-input surface
//! on the transport. Their `Vec<u8>` length fields (`kyber_pk`, `identity_pk`,
//! `signature`, `ciphertext`) are the classic over-alloc / panic risk. The
//! decode must only ever return `Err`, never panic or over-allocate.
use bloch::transport::{HandshakeInit, HandshakeResp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cfg = bincode::config::standard();
    let _ = bincode::serde::decode_from_slice::<HandshakeInit, _>(data, cfg);
    let _ = bincode::serde::decode_from_slice::<HandshakeResp, _>(data, cfg);
});
