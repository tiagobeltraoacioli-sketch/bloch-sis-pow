#![no_main]
//! Fuzz the transaction wire parser (untrusted peer / RPC input).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bloch::core::Transaction::from_stratum_bytes(data);
});
