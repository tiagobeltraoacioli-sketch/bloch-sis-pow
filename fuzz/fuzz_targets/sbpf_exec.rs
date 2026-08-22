#![no_main]
//! Differential-fuzz bloch-sbpf's execute() for panic-freedom under
//! verified-but-adversarial programs (BLOCH-SBPF-CORE.md §10): whatever
//! survives the verifier must run to a deterministic Outcome — every failure
//! mode is a Fault value, never a panic — and twice-run must be bit-identical
//! (the D1 property, asserted here under fuzz).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = bloch_sbpf::load(data) {
        let reg = bloch_sbpf::SyscallRegistry::v0();
        // Small budget keeps the fuzz loop fast; determinism is budget-
        // independent so nothing is lost.
        let a = bloch_sbpf::execute(&p, b"fuzz-input-16b!!", 4_096, &reg);
        let b = bloch_sbpf::execute(&p, b"fuzz-input-16b!!", 4_096, &reg);
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }
});
