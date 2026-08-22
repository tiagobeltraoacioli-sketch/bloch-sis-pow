#![no_main]
//! Fuzz bloch-sbpf's load() (BLOCH-SBPF-CORE.md §10): a hostile BSC-0
//! container must be rejected or verified — never a panic, never an unbounded
//! allocation (loader ceilings: 65 536 text slots / 512 KiB rodata / 65 536
//! function-table entries, all checked before allocation).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bloch_sbpf::load(data);
});
