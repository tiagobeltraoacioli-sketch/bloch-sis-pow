//! NIST CAVP-anchored known-answer tests for `Op::Sha256d`, run through the VM's
//! real `run()` path.
//!
//! CAVP has no double-SHA-256 file, so each KAT is two steps (full argument in
//! euvm-conformance/src/lib.rs):
//!   (1) assert `sha2::Sha256(Msg) == MD` — validates the primitive the VM links
//!       DIRECTLY against NIST, on this exact corpus;
//!   (2) run the opcode and compare against `Sha256(MD)` where MD is the
//!       NIST-GIVEN digest (read from the file, never recomputed from Msg). The
//!       outer application only ever hashes 32-byte inputs, a length step (1)
//!       covers via the corpus's own Len=256 vector.
//! What this proves about the OPCODE is exactly what only the opcode controls:
//! two applications (not one, not three), of the NIST-validated primitive, on the
//! popped operand, pushing all 32 bytes. It is deliberately NOT sold as a fully
//! independent double-SHA oracle — that oracle does not exist at NIST.
//!
//! Vector provenance: vectors/cavp/MANIFEST.toml (NIST CAVP shabytetestvectors.zip,
//! sha256 929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8).

use bloch_euvm::Op;
use euvm_conformance::{corrupt, parse_rsp, vm_hash_matches};
use sha2::{Digest, Sha256};

const SHORT: &str = include_str!("../vectors/cavp/SHA256ShortMsg.rsp");
const LONG: &str = include_str!("../vectors/cavp/SHA256LongMsg.rsp");

/// Counts measured from the NIST files at import time (2026-08-22) — the guard
/// against a parser mutation shrinking the corpus silently.
#[test]
fn corpus_counts_are_exactly_the_nist_counts() {
    assert_eq!(parse_rsp(SHORT).len(), 65, "SHA256ShortMsg must yield 65 vectors");
    assert_eq!(parse_rsp(LONG).len(), 64, "SHA256LongMsg must yield 64 vectors");
}

/// Step (1)'s anchor for the OUTER application: the corpus itself must contain a
/// 32-byte-message vector (Len = 256), the one length `Sha256(MD)` ever uses.
/// If NIST ever reshaped the file this assertion would flag the argument as void
/// instead of letting it rot silently.
#[test]
fn corpus_covers_the_32_byte_input_length() {
    assert!(
        parse_rsp(SHORT).iter().any(|v| v.len_bits == 256),
        "independence argument needs a Len=256 vector in the corpus"
    );
}

/// The Len=0 trap, pinned: empty message, and MD is the well-known SHA-256("")
/// digest.
#[test]
fn len_zero_vector_is_the_empty_message() {
    let vs = parse_rsp(SHORT);
    let v0 = vs.iter().find(|v| v.len_bits == 0).expect("Len=0 vector present");
    assert!(v0.msg.is_empty(), "Len=0 must parse to an EMPTY message, not [0x00]");
    assert_eq!(
        hex::encode(&v0.expected),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

/// Both steps for all 129 vectors, each with its CONTROL half (corrupted
/// expectation must be rejected — negative-test discipline rule 2).
#[test]
fn sha256d_opcode_matches_nist_anchored_double_hash_for_all_vectors() {
    let mut vectors = parse_rsp(SHORT);
    vectors.extend(parse_rsp(LONG));
    assert_eq!(vectors.len(), 129, "corpus must be 129 vectors");

    for v in &vectors {
        // (1) NIST anchor of the linked primitive on this exact input.
        assert_eq!(
            Sha256::digest(&v.msg).as_slice(),
            v.expected.as_slice(),
            "sha2 crate disagrees with NIST for Len={} bits — primitive, not opcode", v.len_bits
        );
        // (2) opcode == one more application of the NIST-validated primitive
        //     over the NIST-GIVEN digest.
        let expected_d = Sha256::digest(&v.expected).to_vec();
        assert!(
            vm_hash_matches(Op::Sha256d, &v.msg, &expected_d),
            "Sha256d KAT failed for Len={} bits", v.len_bits
        );
        assert!(
            !vm_hash_matches(Op::Sha256d, &v.msg, &corrupt(&expected_d)),
            "CONTROL failed (corrupted expectation accepted) for Len={} bits", v.len_bits
        );
    }
}
