//! Robustness: the Merkle path verifier takes attacker-controlled input (a
//! shielded spend carries its own authentication path + index) and must NEVER
//! panic — any malformed path/index is just a `false`. A panic here is a remote
//! DoS on every node that validates the spend.
//!
//! Deterministic corpus on stable Rust; the libfuzzer target in `fuzz/` covers
//! the same surface with coverage-guided mutation on a fuzzing box.

use coherence_core::verify_path;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn arr32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for b in a.iter_mut() {
            *b = (self.next() & 0xff) as u8;
        }
        a
    }
}

#[test]
fn verify_path_never_panics_on_arbitrary_input() {
    let mut r = Rng(0x2545F4914F6CDD1D);
    for _ in 0..80_000 {
        let leaf = r.arr32();
        let root = r.arr32();
        // Path depth from empty to well past a realistic tree height, so any
        // index-shift / depth-indexing bug shows up.
        let plen = (r.next() % 70) as usize;
        let path: Vec<[u8; 32]> = (0..plen).map(|_| r.arr32()).collect();
        // Index across the full u64 range (extreme positions included).
        let index = r.next();
        let _ = verify_path(&leaf, index, &path, &root);
    }
    // A few explicit extremes.
    let z = [0u8; 32];
    let _ = verify_path(&z, u64::MAX, &[], &z);
    let _ = verify_path(&z, 0, &[z; 64], &z);
}
