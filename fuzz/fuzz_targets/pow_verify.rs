#![no_main]
//! Fuzz PoW verification end-to-end: decode an untrusted solution, then verify
//! it at both difficulty extremes. Neither must ever panic.
use bloch_sis_pow::difficulty::Target;
use bloch_sis_pow::encode::decode_s;
use bloch_sis_pow::verify::verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sol) = decode_s(data) {
        let _ = verify(b"fuzz", 0, &sol, &Target::MAX);
        let _ = verify(b"fuzz", u64::MAX, &sol, &Target::MIN);
    }
});
