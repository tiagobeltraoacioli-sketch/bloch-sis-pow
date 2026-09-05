#![no_main]
//! Fuzz `BlockHeaderV4::canonical_deserialize` — Genesis-4's *only* header
//! decoder.
//!
//! Every block id on the live chain is `SHA3-256(DS_BLOCK ‖
//! canonical_serialize(header))`, so this function is the sole gate between
//! attacker bytes and block identity. Two properties, not just "no panic":
//!
//!   * **Length is exact.** Anything other than `ENCODED_LEN` must be `Err`.
//!     A decoder that accepts `encode(h) ‖ junk` gives one header two byte
//!     strings and breaks the injectivity `BlockId` promises — the same defect
//!     class as the "trailing bytes in block body" stall at height 10,802.
//!   * **Round-trip.** An accepted header must re-serialize to the exact bytes
//!     it was decoded from, or the id computed by the producer and the id
//!     computed by the validator are derived from different bytes.
use bloch_pos_committee::header::BlockHeaderV4;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match BlockHeaderV4::canonical_deserialize(data) {
        Ok(h) => {
            assert_eq!(data.len(), BlockHeaderV4::ENCODED_LEN, "accepted a wrong-length header");
            assert_eq!(h.canonical_serialize().as_slice(), data, "header round-trip is not injective");
        }
        Err(_) => {
            assert_ne!(data.len(), BlockHeaderV4::ENCODED_LEN, "rejected an exactly-sized header");
        }
    }
});
