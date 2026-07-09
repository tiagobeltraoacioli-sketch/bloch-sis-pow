#![no_main]
//! Fuzz the shielded Merkle path verifier. A spend carries an attacker-chosen
//! path + index; verify_path must return false, never panic.
use coherence_core::verify_path;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 72 {
        return;
    }
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&data[0..32]);
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[32..64]);
    let mut idx = [0u8; 8];
    idx.copy_from_slice(&data[64..72]);
    let index = u64::from_le_bytes(idx);
    let path: Vec<[u8; 32]> = data[72..]
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        })
        .collect();
    let _ = verify_path(&leaf, index, &path, &root);
});
