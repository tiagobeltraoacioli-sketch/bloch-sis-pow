#![no_main]
//! Fuzz the hybrid post-quantum signature verifier + crypto-agility envelope
//! parser on fully attacker-controlled bytes.
//!
//! `bloch::crypto::verify` is CONSENSUS-CRITICAL: every spend is authorized by
//! it. It parses a 4-byte suite envelope (or falls back to the legacy
//! pre-envelope carry-over encoding), splits the body into ML-DSA-65 ‖
//! Falcon-1024 halves at fixed lengths, and hands each half to a PQ verifier
//! (`mldsa65::{PublicKey,DetachedSignature}::from_bytes`, `falcon::verify`).
//! Public key, message, and signature all arrive from untrusted peers/RPC, so a
//! malformed triple must only ever yield `false` — never a panic, an
//! over-allocation on the `<=`-length splits, or a hang. This fills scanner
//! Part-A gap #4 (signature/attestation envelope parsing was previously
//! unfuzzed).
use bloch::crypto::{address_from_pubkey, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the fuzz buffer into pubkey / message / signature via two u16
    // length prefixes, so the fuzzer can vary all three independently and reach
    // the suite-mismatch, short-body, and from_bytes-parse-fail branches.
    if data.len() >= 4 {
        let pk_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let msg_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let rest = &data[4..];
        let (pk, r2) = rest.split_at(pk_len.min(rest.len()));
        let (msg, sig) = r2.split_at(msg_len.min(r2.len()));
        let _ = verify(pk, msg, sig);
    }

    // Also feed the whole buffer as both pubkey and signature: exercises the
    // envelope/legacy magic-byte split and the equal-suite path on maximal
    // input, plus the SHA3-256 address derivation over raw pubkey bytes.
    let _ = verify(data, b"", data);
    let _ = address_from_pubkey(data, false);
});
