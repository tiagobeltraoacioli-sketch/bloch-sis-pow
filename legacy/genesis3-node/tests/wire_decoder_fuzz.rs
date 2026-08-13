//! No-panic fuzz for the transaction / block / header WIRE DECODERS.
//!
//! These parsers (`Transaction::from_stratum_bytes`, `Block::from_bitcoin_bytes`,
//! `BlockHeader::from_bitcoin_bytes`) consume bytes straight off the P2P wire and
//! the RPC surface — fully attacker-controlled. The consensus rule is
//! "malformed ⇒ `Err`, never a panic": a panic on a crafted buffer is a remote
//! DoS. This is the always-on, stable-Rust floor for that invariant; the
//! coverage-guided `fuzz/fuzz_targets/{tx_parse,block_parse}.rs` libFuzzer
//! targets exercise the SAME entry points on a fuzzing box.
//!
//! Style matches `bloch-crypto`'s `crypto::kat` fuzz tests: a deterministic
//! SplitMix64 stream (reproducible failures) driven through
//! `std::panic::catch_unwind`, seeded with a handful of structured/adversarial
//! cases that land near the parser's length/count boundaries.
//!
//! `wire_roundtrip_props.rs` already checks that VALID values survive
//! serialize→parse; this file is its adversarial dual — arbitrary bytes must
//! only ever produce `Ok`/`Err`, never unwind.

use bloch::core::{Block, BlockHeader, Transaction};

/// Deterministic SplitMix64 — reproducible corpus, no external randomness.
struct SplitMix64(u64);
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() & 0xFF) as u8).collect()
    }
}

/// Feed one buffer through every decoder; assert none unwinds. The parsers are
/// `catch_unwind`-safe (they take `&[u8]` and return `Result`, holding no
/// cross-call state), so `AssertUnwindSafe` on the closure is sound.
fn assert_no_panic(data: &[u8]) {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let r = catch_unwind(AssertUnwindSafe(|| {
        let _ = Transaction::from_stratum_bytes(data);
        let _ = Block::from_bitcoin_bytes(data);
        let _ = BlockHeader::from_bitcoin_bytes(data);
    }));
    assert!(r.is_ok(), "a wire decoder panicked on {} bytes: {data:02x?}", data.len());
}

/// Structured seeds: boundary lengths and adversarial field values that steer
/// the parsers into their varint/count/length branches.
fn structured_cases() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        vec![],                    // empty
        vec![0x00],                // 1 byte
        vec![0xFF; 4],             // just a version field
        vec![0x00; 79],            // one byte short of the 80-byte header floor
        vec![0x00; 80],            // exactly the header floor, no extension
        vec![0xFF; 80],            // header floor, all-ones
        vec![0x00; 81],            // header + a lone varint byte
        vec![0xFF; 81],            // header + 0xFF varint (multi-byte length prefix)
        vec![0x00; 4096],          // large zero buffer
        vec![0xFF; 4096],          // large all-ones buffer
    ];
    // A 0xFD/0xFE/0xFF varint prefix right after the 80-byte header exercises
    // the multi-byte varint + huge-count rejection paths (audit M1 bound).
    for marker in [0xFDu8, 0xFE, 0xFF] {
        let mut b = vec![0u8; 80];
        b.push(marker);
        b.extend_from_slice(&[0xFFu8; 8]); // oversized length/count claim
        v.push(b);
    }
    // A tx claiming an enormous input count then truncating.
    v.push(vec![0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    v
}

#[test]
fn wire_decoders_never_panic_on_structured_input() {
    for c in structured_cases() {
        assert_no_panic(&c);
    }
}

#[test]
fn wire_decoders_never_panic_on_random_input() {
    let mut rng = SplitMix64(0xB10C_C0DE_F0F0_1234);
    for _ in 0..20_000 {
        // Bias lengths toward the small/around-header sizes where the field
        // walkers branch most, but keep a long tail.
        let len = match rng.next() % 4 {
            0 => (rng.next() % 96) as usize,          // around the 80-byte floor
            1 => (rng.next() % 512) as usize,
            2 => (rng.next() % 4096) as usize,
            _ => (rng.next() % 16_384) as usize,
        };
        let buf = rng.bytes(len);
        assert_no_panic(&buf);
    }
}

#[test]
fn wire_decoders_never_panic_on_valid_prefix_mutations() {
    // Start from a well-formed serialization and mutate single bytes: this keeps
    // the parser deep on the happy path where an OOB read is most likely.
    let tx = Transaction {
        version: 1,
        inputs: vec![bloch::core::TxInput {
            prev_txid: [7u8; 32],
            prev_index: 0,
            script_sig: vec![1, 2, 3, 4],
            sequence: 0xFFFF_FFFF,
        }],
        outputs: vec![bloch::core::TxOutput { value: 5_000, script_pubkey: vec![9u8; 20] }],
        locktime: 0,
    };
    let good = tx.to_stratum_bytes(true);
    for i in 0..good.len() {
        for xor in [0x01u8, 0xFF, 0x80] {
            let mut m = good.clone();
            m[i] ^= xor;
            assert_no_panic(&m);
        }
        // Truncations at every prefix length.
        assert_no_panic(&good[..i]);
    }
    // The pristine buffer must still parse (guards against a broken fixture).
    assert!(Transaction::from_stratum_bytes(&good).is_ok(), "valid tx fixture must parse");
}
