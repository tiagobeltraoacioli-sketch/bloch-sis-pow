#![no_main]
//! Fuzz the Module-SIS solution decoder (untrusted peer/RPC bytes → [i32; N]).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bloch_sis_pow::encode::decode_s(data);
});
