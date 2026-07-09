#![no_main]
//! Fuzz the block wire parser. Blocks arrive as bytes from untrusted peers, and
//! the body now includes the Coherence shielded-tx suffix — the parser must
//! never panic, over-allocate, or loop on adversarial input (only Err).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bloch::core::Block::from_bitcoin_bytes(data);
});
