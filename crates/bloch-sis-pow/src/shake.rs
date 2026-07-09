// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Domain-separated SHAKE-256 wrapper.

//! Canonical SHAKE-256 invocation with strict domain separation.
//!
//! Every Bloch-SIS-PoW use of SHAKE-256 routes through [`shake256_dom`].
//! This is critical for security: feeding the same input bytes into
//! SHAKE under different intended uses (matrix expansion vs auxiliary
//! hash, etc.) without domain separation would create cross-context
//! collisions that an attacker could exploit.

use alloc::vec;
use alloc::vec::Vec;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Length-prefix-and-feed helper. Writes the byte length as a little-endian
/// u64 followed by the bytes themselves. This prevents ambiguity in
/// concatenated inputs (Bloch never relies on natural unambiguity from
/// fixed-size inputs alone — every input is length-prefixed).
fn feed_with_len(hasher: &mut Shake256, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Domain-separated SHAKE-256.
///
/// # Inputs
/// - `label`: a short ASCII identifier (e.g. `b"BLOCH-POW-SEED-V1"`).
///   Includes the protocol name and a version tag.
/// - `inputs`: arbitrary number of byte slices, each independently
///   length-prefixed before being fed into SHAKE.
/// - `out_len`: number of output bytes desired.
///
/// # Output
/// A `Vec<u8>` of length `out_len` containing the SHAKE output.
///
/// # Security note
/// The label MUST be a unique per-context constant. Reusing the same
/// label across contexts defeats domain separation and may admit
/// cross-context attacks. See [`crate::DOMAIN_LABEL_POW_SEED`],
/// [`crate::DOMAIN_LABEL_POW_AUX`] and [`crate::DOMAIN_LABEL_TARGET`].
pub fn shake256_dom(label: &[u8], inputs: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();

    // Write the label first, length-prefixed.
    feed_with_len(&mut hasher, label);

    // Write each input, length-prefixed.
    for input in inputs {
        feed_with_len(&mut hasher, input);
    }

    let mut out = vec![0u8; out_len];
    let mut reader = hasher.finalize_xof();
    reader.read(&mut out);
    out
}

/// Streaming variant: returns an XOF reader so callers can pull arbitrary
/// numbers of bytes without re-hashing. Used by [`crate::expand`] for
/// matrix expansion where output sizes are very large.
///
/// (Provisional API — internal use only. Use [`Shake256Stream`] from
/// outside this module.)
fn _shake256_dom_reader_provisional() {
    // intentionally empty; the public streaming API is Shake256Stream below.
}

/// Streaming SHAKE-256 reader, length-prefixed and domain-separated.
///
/// Use this when expanding seeds into large outputs (the matrix `A`)
/// to avoid allocating the entire output at once.
pub struct Shake256Stream {
    reader: sha3::Shake256Reader,
}

impl Shake256Stream {
    /// Construct a new streaming reader. Inputs and label are written
    /// to the SHAKE absorption phase; subsequent reads pull from the
    /// squeeze phase.
    pub fn new(label: &[u8], inputs: &[&[u8]]) -> Self {
        let mut hasher = Shake256::default();
        feed_with_len(&mut hasher, label);
        for input in inputs {
            feed_with_len(&mut hasher, input);
        }
        Self { reader: hasher.finalize_xof() }
    }

    /// Read more bytes from the SHAKE squeeze phase into `buf`.
    pub fn read(&mut self, buf: &mut [u8]) {
        self.reader.read(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_length_correct() {
        let out = shake256_dom(b"TEST", &[b"hello"], 32);
        assert_eq!(out.len(), 32);

        let out2 = shake256_dom(b"TEST", &[b"hello"], 100);
        assert_eq!(out2.len(), 100);
    }

    #[test]
    fn determinism() {
        // Same inputs → same output.
        let a = shake256_dom(b"TEST", &[b"hello", b"world"], 64);
        let b = shake256_dom(b"TEST", &[b"hello", b"world"], 64);
        assert_eq!(a, b);
    }

    #[test]
    fn domain_separation_works() {
        // Different labels → different outputs even with same inputs.
        let a = shake256_dom(b"LABEL_A", &[b"data"], 32);
        let b = shake256_dom(b"LABEL_B", &[b"data"], 32);
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefixing_prevents_ambiguity() {
        // Concatenation ambiguity test: SHAKE("foo" || "bar") should NOT
        // equal SHAKE("foob" || "ar") under our length-prefixed scheme,
        // even though the raw concatenation would be the same.
        let a = shake256_dom(b"L", &[b"foo", b"bar"], 32);
        let b = shake256_dom(b"L", &[b"foob", b"ar"], 32);
        assert_ne!(a, b, "length prefixing must disambiguate split");
    }

    #[test]
    fn streaming_matches_one_shot() {
        // The streaming API on enough bytes should yield the same output
        // as the one-shot API.
        let label = b"STREAM-TEST";
        let inputs: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];

        let one_shot = shake256_dom(label, inputs, 1024);

        let mut stream = Shake256Stream::new(label, inputs);
        let mut streamed = vec![0u8; 1024];
        stream.read(&mut streamed);

        assert_eq!(one_shot, streamed);
    }
}
