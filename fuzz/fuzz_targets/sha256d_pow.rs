#![no_main]
//! Fuzz the LIVE Genesis-2 SHA-256d PoW path on adversarial inputs.
//!
//! This is the verifier for the CHAIN THAT IS ACTUALLY LIVE: Genesis-2 uses
//! double-SHA256 over the 80-byte `MiningHeader` projection, height-gated by the
//! little-endian endianness hard fork (`SHA256D_LE_FORK_HEIGHT = 2400`). The
//! pre-existing `pow_verify` target fuzzes the OTHER (Mainnet/Testnet) chain's
//! Module-SIS lattice verifier — not this one — so the live PoW path was
//! previously unfuzzed. Two surfaces are exercised here, neither of which may
//! ever panic, over-allocate, or hang on attacker-controlled bytes:
//!
//!  1. `BlockHeader::from_bitcoin_bytes` — the untrusted wire header parse
//!     (varint parent count, parents-commitment consistency check, extension
//!     region) followed by the full consensus PoW computation
//!     (`pow_hash` → `sha256d_pow_valid`) at both endianness-fork arms.
//!  2. The raw 80-byte `MiningHeader` projection + double-SHA256 hash, taken
//!     straight from the first 80 fuzz bytes, independent of the extension
//!     parse.
use bloch::core::{bits_to_target, sha256d_pow_valid, BlockHeader, MiningHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // (1) Adversarial wire header → parse → live PoW check.
    if let Ok((header, _blue_score, height)) = BlockHeader::from_bitcoin_bytes(data) {
        let target = bits_to_target(header.bits);
        let h = header.pow_hash();
        // Exercise BOTH sides of the endianness hard fork plus the height the
        // attacker actually claimed in the extension region.
        let _ = sha256d_pow_valid(&h, &target, height);
        let _ = sha256d_pow_valid(&h, &target, 0); // legacy big-endian arm
        let _ = sha256d_pow_valid(&h, &target, u64::MAX); // post-fork LE arm
        // The projections the miner and stratum path reconstruct.
        let _ = header.to_mining_header();
        let _ = header.pow_preimage();
    }

    // (2) Raw 80-byte mining-header projection + double-SHA256, independent of
    //     the extension parse: the exact bytes an ASIC / stratum client hashes.
    if data.len() >= 80 {
        let mut buf = [0u8; 80];
        buf.copy_from_slice(&data[..80]);
        let mh = MiningHeader::from_bytes(&buf);
        let target = bits_to_target(mh.bits);
        let _ = sha256d_pow_valid(&mh.pow_hash(), &target, u64::from(mh.timestamp));
    }
});
