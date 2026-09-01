// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one derivation of a Genesis-4 `script_hash`, and the one legacy shape
//! that is not a derivation at all.
//!
//! A Genesis-4 output is locked by 32 bytes. Those 32 bytes reach the eUTXO set
//! by exactly two routes, and only one of them is a function of a key:
//!
//! 1. **Native — [`from_pubkey`].** `SHA3-256(hybrid public key)`, all 32
//!    bytes. This is what `bloch-pos spendkey` prints, what a genesis
//!    allocation commits to, and what **every output a Genesis-4 transaction
//!    creates** uses ([`crate::transition::owns`] says so in those words).
//!    If you hold a key and need the hash its coins live under, this is the
//!    answer, and there is no other.
//!
//! 2. **Carried — [`carried_from_g3_hash160`].** The Genesis-3 carryover
//!    ingest writes a snapshot row's 20-byte hash160 into `script_hash[0..20]`
//!    and leaves the last twelve bytes zero. This is **not a derivation from a
//!    key**: it is a transcription of a file, performed once, at mainnet
//!    genesis, from `carryover.tsv`. Nothing computes it from a public key and
//!    nothing may.
//!
//! # The mistake this module exists to make impossible
//!
//! `Address::from_pubkey` truncates `SHA3-256(pubkey)` to 20 bytes, so
//! zero-extending an address's hash produces something that *looks* like the
//! carried shape:
//!
//! ```text
//!     SHA3-256(pubkey)[0..20] ‖ 0x00 × 12        <-- WRONG for a live key
//!     SHA3-256(pubkey)                            <-- what the key owns
//! ```
//!
//! Those are **different keys in the eUTXO set**. `getbalance` on one does not
//! see coins locked under the other. Six separate tools in this repository once
//! computed the first one — a faucet, a withdrawal client, a payout tool, a
//! receipt verifier, a runbook, and an integration guide — because the address
//! form is the one a human can read, and every one of them would have shown a
//! funded partner a zero balance.
//!
//! It is worse than a lookup mismatch, and worse in a way that is easy to miss:
//! [`crate::transition::owns`] accepts the truncated form (its second arm), so
//! the coins are not lost and nothing rejects the transaction. The mistake is
//! therefore **silent**, and it hands the recipient an output protected by 160
//! bits of preimage resistance instead of 256 — the Genesis-3 security tier,
//! applied to a key that never needed it, for no reason but that a 20-byte
//! number fits in an address and a 32-byte one does not.
//!
//! Carried outputs get that weaker tier because they had it on Genesis-3 and
//! taking it away would freeze the opening ledger. A native key has no such
//! excuse.
//!
//! # For integrators
//!
//! There is no address→`script_hash` conversion in this module, deliberately.
//! If you have an address and want the hash, the honest answer is that you are
//! holding the wrong identifier: ask for the `script_hash` instead.

use sha3::{Digest, Sha3_256};

/// Consensus's ownership rule, re-exported so that no tool has to restate it.
///
/// It used to be private to [`crate::transition`], which meant every client
/// that wanted to check "can this key open that output?" copied the two-line
/// body into its own crate — one of them verbatim, comment and all. A copied
/// consensus rule is a rule with a second implementation waiting to drift, so
/// the rule is exported and the copies are deleted.
pub use crate::transition::owns;

/// Width of a `script_hash`, in bytes.
pub const SCRIPT_HASH_BYTES: usize = 32;

/// Width of a Genesis-3 address hash (hash160), in bytes.
pub const G3_ADDRESS_BYTES: usize = 20;

/// **The** derivation: the 32-byte key under which a hybrid public key's coins
/// live on Genesis-4.
///
/// `pubkey` is the suite-framed hybrid ML-DSA-65 ‖ Falcon-1024 public key,
/// exactly the bytes that travel in a transfer's witness — not either half on
/// its own, and not a re-encoding of it. Hashing anything else produces a hash
/// nobody can spend from.
#[inline]
pub fn from_pubkey(pubkey: &[u8]) -> [u8; SCRIPT_HASH_BYTES] {
    Sha3_256::digest(pubkey).into()
}

/// The carried shape, for the Genesis-3 carryover ingest and nothing else.
///
/// `h160` comes from a `carryover.tsv` row. It is a Genesis-3 address hash that
/// already existed before this chain did; this function transcribes it into the
/// 32-byte field, zero-extending **to the right** (the direction is consensus —
/// padded on the left, every output has a different owner and this is a
/// different ledger).
///
/// # Never call this with a hash you just derived
///
/// If the 20 bytes you are about to pass came from `SHA3-256(pubkey)[..20]`, or
/// from an `Address` you built from a public key, stop: you want
/// [`from_pubkey`]. See the module docs.
#[inline]
pub fn carried_from_g3_hash160(h160: &[u8; G3_ADDRESS_BYTES]) -> [u8; SCRIPT_HASH_BYTES] {
    let mut out = [0u8; SCRIPT_HASH_BYTES];
    out[..G3_ADDRESS_BYTES].copy_from_slice(h160);
    out
}

/// Does this hash have the carried shape (last twelve bytes zero)?
///
/// A read-side predicate, for tools that want to tell a partner *why* a balance
/// query came back empty. It is not an ownership test — use
/// [`crate::transition::owns`] for that — and a native hash can land in this
/// shape by chance with probability 2^-96.
#[inline]
pub fn is_carried_shape(script_hash: &[u8; SCRIPT_HASH_BYTES]) -> bool {
    script_hash[G3_ADDRESS_BYTES..] == [0u8; SCRIPT_HASH_BYTES - G3_ADDRESS_BYTES]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two shapes are different values for the same key. If this ever
    /// passes with `assert_eq`, someone has "simplified" one into the other and
    /// silently moved every balance.
    #[test]
    fn the_native_and_carried_shapes_are_different_keys() {
        let pubkey = b"a suite-framed hybrid public key stands in for the real 8kB one";
        let native = from_pubkey(pubkey);
        let mut truncated = [0u8; 20];
        truncated.copy_from_slice(&native[..20]);
        let carried = carried_from_g3_hash160(&truncated);

        assert_ne!(
            native, carried,
            "the address-truncated shape must not equal the native hash — they are \
             different eUTXO-set keys and the whole zero-balance failure lives in the gap"
        );
        assert_eq!(&native[..20], &carried[..20], "they do share their first 20 bytes");
        assert!(is_carried_shape(&carried));
        // 2^-96 says this will not trip; if it does, the test key changed.
        assert!(!is_carried_shape(&native));
    }

    /// Consensus accepts BOTH, which is exactly why the mistake is silent. This
    /// pins that fact so nobody reads the module docs as "the truncated form is
    /// rejected" — it is not, and that is the problem.
    #[test]
    fn consensus_opens_both_shapes_with_the_same_key() {
        let pubkey = b"a suite-framed hybrid public key stands in for the real 8kB one";
        let key_hash = from_pubkey(pubkey);
        let mut truncated = [0u8; 20];
        truncated.copy_from_slice(&key_hash[..20]);
        let carried = carried_from_g3_hash160(&truncated);

        assert!(owns(&key_hash, &key_hash));
        assert!(owns(&key_hash, &carried));
    }

    /// Zero-extension goes RIGHT. Padded left, every carried output has a
    /// different owner and the opening ledger is a different ledger.
    #[test]
    fn the_carried_shape_pads_on_the_right() {
        let h = [0xABu8; G3_ADDRESS_BYTES];
        let out = carried_from_g3_hash160(&h);
        assert_eq!(&out[..20], &h[..], "the hash160 occupies the LOW 20 bytes");
        assert_eq!(&out[20..], &[0u8; 12], "and the tail is zero");
    }
}
