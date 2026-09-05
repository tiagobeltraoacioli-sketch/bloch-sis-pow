//! BIP39-style seed phrase handling.
//!
//! Bloch-SIS Protocol uses BIP39 wordlist (2048 words, English) to encode entropy
//! as human-readable mnemonics. This is the SAME standard used by Bitcoin,
//! Ethereum, and most other chains — seed phrases are portable with caveats
//! (different chains derive different keys from same seed, so phrases don't
//! interchange funds, only the backup format).
//!
//! Security properties:
//!   - 24-word phrase ≈ 256 bits entropy
//!   - 12-word phrase ≈ 128 bits entropy (still secure, shorter to write)
//!   - Built-in checksum catches ~99% of typos
//!   - PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" (the BIP39 seed) to
//!     derive the 64-byte seed from the phrase
//!
//! This implementation:
//!   - Generates 24-word phrases by default
//!   - Validates checksum on parse
//!   - Zeroes sensitive data on drop
//!
//! Not implemented (intentional):
//!   - BIP39 passphrase (25th word). User-facing complexity; no clear win.
//!   - Multi-language wordlists. English only for v0.5.4; consider for v0.6.

use super::errors::WalletError;
use zeroize::{Zeroize, ZeroizeOnDrop};
use sha2::Sha512;
use hmac::Hmac;
use pbkdf2::pbkdf2;

// English BIP39 wordlist — 2048 words
// In production, this should be loaded from a file; for simplicity we include
// a minimal subset here as an illustration. The real implementation should use
// the `bip39` crate or embed the full wordlist.
//
// For Sprint C MVP: use the `bip39` crate from crates.io.
// Cargo.toml addition:
//     bip39 = "2.0"

/// A BIP39 seed phrase. Sensitive — zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SeedPhrase {
    /// The raw phrase as a space-separated string.
    phrase: String,
}

impl SeedPhrase {
    /// Generate a new 24-word seed phrase using OS-level CSPRNG.
    pub fn generate() -> Result<Self, WalletError> {
        use rand::RngCore;
        let mut entropy = [0u8; 32];
        rand::rng().fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| WalletError::Crypto(format!("bip39 generate: {}", e)))?;
        Ok(SeedPhrase {
            phrase: mnemonic.to_string(),
        })
    }

    /// Parse a user-provided seed phrase, validating word list and checksum.
    pub fn parse(phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = bip39::Mnemonic::parse(phrase.trim())
            .map_err(|e| WalletError::InvalidSeedPhrase(e.to_string()))?;
        Ok(SeedPhrase {
            phrase: mnemonic.to_string(),
        })
    }

    /// The 64-byte BIP39 seed for this phrase.
    ///
    /// BIP39 fixes this exactly: `PBKDF2(HMAC-SHA512, mnemonic, "mnemonic" ||
    /// passphrase, 2048 iterations, 64 bytes)`. The PRF is **SHA-512**. Using
    /// SHA-256 here — as this function did until audit finding K-M3 — still
    /// returns 64 deterministic bytes, so nothing fails loudly; the seed is
    /// simply a different number, and the same mnemonic then yields a different
    /// key in every other BIP39 tool, including the two in this repo that are
    /// fed a canonical seed (`bloch_btc_wallet::derive_identity` and
    /// `bloch_pq_vault::derive_vault_keys`). Pinned to the official vectors in
    /// the tests below.
    ///
    /// The optional BIP39 passphrase ("25th word") is not implemented, so the
    /// salt is the bare `"mnemonic"`. The phrase is hashed as UTF-8 with no
    /// explicit NFKD pass: every phrase here comes from `bip39::Mnemonic` over
    /// the English wordlist, which is ASCII and hence already NFKD. Adding a
    /// non-ASCII wordlist (see the module header) would make normalization
    /// mandatory.
    ///
    /// These bytes are the starting material for key derivation. For ML-DSA-65,
    /// we use the first 32 bytes as the keygen seed.
    pub fn to_seed_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let _ = pbkdf2::<Hmac<Sha512>>(
            self.phrase.as_bytes(),
            b"mnemonic",
            2048,
            &mut out,
        );
        out
    }

    /// The pre-K-M3, non-BIP39 seed: PBKDF2-**HMAC-SHA256**, same salt and
    /// iteration count.
    ///
    /// Kept ONLY so migration/sweep tooling can re-derive a wallet that was
    /// created while `to_seed_bytes` used SHA-256 and move its funds to the
    /// corrected address. It is not BIP39 and must never seed a new wallet.
    ///
    /// NEEDS-FOUNDER-DECISION: whether any wallet in the wild was derived
    /// through the SHA-256 path, and if so whether the fix ships with an
    /// automatic sweep, a manual recovery tool, or an explicit refusal to
    /// support the old derivation. Until that is answered this function is the
    /// only code in the tree that can reach those keys, so it stays.
    #[deprecated(
        note = "not BIP39 (SHA-256 PRF); migration/sweep tooling only, never for new wallets"
    )]
    pub fn to_seed_bytes_legacy_sha256(&self) -> [u8; 64] {
        use sha2::Sha256;
        let mut out = [0u8; 64];
        let _ = pbkdf2::<Hmac<Sha256>>(
            self.phrase.as_bytes(),
            b"mnemonic",
            2048,
            &mut out,
        );
        out
    }

    /// Returns the phrase as words. For display purposes only.
    ///
    /// SECURITY: Do not log this. Do not persist unencrypted. Display only
    /// during wallet creation for the user to write down.
    pub fn words(&self) -> Vec<&str> {
        self.phrase.split_whitespace().collect()
    }

    /// Number of words.
    pub fn word_count(&self) -> usize {
        self.words().len()
    }
}

impl std::fmt::Debug for SeedPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the actual phrase in Debug output
        write!(f, "SeedPhrase({} words, <redacted>)", self.word_count())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_24_words() {
        let seed = SeedPhrase::generate().unwrap();
        assert_eq!(seed.word_count(), 24);
    }

    #[test]
    fn parse_rejects_invalid_word_count() {
        assert!(SeedPhrase::parse("abandon ability").is_err()); // 2 words
        assert!(SeedPhrase::parse("").is_err()); // 0 words

        // 13 words (not a valid BIP39 length)
        let invalid = (0..13).map(|_| "word").collect::<Vec<_>>().join(" ");
        assert!(SeedPhrase::parse(&invalid).is_err());
    }

    #[test]
    fn parse_accepts_valid_word_counts() {
        // Generate real BIP39 mnemonics at different lengths and verify parse accepts them.
        // bip39 crate generates 12 or 24 word mnemonics from entropy length.
        for entropy_bytes in [16usize, 32] {  // 16 bytes = 12 words, 32 bytes = 24 words
            let entropy = vec![0x42u8; entropy_bytes];
            let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
            let phrase = mnemonic.to_string();
            assert!(SeedPhrase::parse(&phrase).is_ok(), "failed for {}-word phrase", mnemonic.word_count());
        }
    }

    #[test]
    fn to_seed_bytes_is_deterministic() {
        // Generate a real BIP39 mnemonic, verify PBKDF2 is deterministic over it.
        let entropy = [0x42u8; 32];
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        let seed = SeedPhrase::parse(&mnemonic.to_string()).unwrap();
        let b1 = seed.to_seed_bytes();
        let b2 = seed.to_seed_bytes();
        assert_eq!(b1, b2);
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Join a line-continued literal back into a single-spaced phrase.
    fn phrase(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    const ABANDON_12: &str = "abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon about";

    /// The canonical BIP39 seed for [`ABANDON_12`] — byte-for-byte the constant
    /// `bloch-btc-wallet` and `bloch-pq-vault` test against.
    const ABANDON_12_SEED: &str =
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
         9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    /// Official BIP39 (Trezor) English vectors, empty passphrase:
    /// seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048) -> 64 bytes.
    ///
    /// This is the regression test for the SHA-256 PRF bug (K-M3): the broken
    /// code still returned 64 deterministic bytes, so only a known-answer
    /// vector catches it.
    #[test]
    fn to_seed_bytes_matches_bip39_official_vectors() {
        let cases: [(&str, &str); 4] = [
            (ABANDON_12, ABANDON_12_SEED),
            (
                "legal winner thank year wave sausage worth useful legal \
                 winner thank yellow",
                "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe\
                 5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
            ),
            (
                "letter advice cage absurd amount doctor acoustic avoid letter \
                 advice cage above",
                "77d6be9708c8218738934f84bbbb78a2e048ca007746cb764f0673e4b1812d17\
                 6bbb173e1a291f31cf633f1d0bad7d3cf071c30e98cd0688b5bcce65ecaceb36",
            ),
            (
                "abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon abandon art",
                "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70\
                 5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
            ),
        ];

        for (words, expected_hex) in cases {
            let words = phrase(words);
            let seed = SeedPhrase::parse(&words).unwrap();
            assert_eq!(
                seed.to_seed_bytes().to_vec(),
                hex(expected_hex),
                "BIP39 seed mismatch for {:?} — is the PRF SHA-512?",
                words
            );
        }
    }

    /// Cross-check against the `bip39` crate's own `to_seed`, an independent
    /// implementation of the same KDF, over freshly generated phrases so the
    /// property is not pinned to the hardcoded vectors above.
    #[test]
    fn to_seed_bytes_agrees_with_bip39_crate() {
        for _ in 0..4 {
            let seed = SeedPhrase::generate().unwrap();
            let mnemonic = bip39::Mnemonic::parse(&seed.phrase).unwrap();
            assert_eq!(seed.to_seed_bytes(), mnemonic.to_seed(""));
        }
    }

    /// The point of the fix: `Wallet::from_seed` and the BTC/vault side must
    /// land on the same PQ keypair for one mnemonic. Both take the first 32
    /// bytes of the canonical BIP39 seed, so agreeing on the seed is agreeing
    /// on the key.
    #[test]
    fn canonical_seed_drives_the_same_pq_key_as_external_tools() {
        let external_seed = hex(ABANDON_12_SEED);
        let ours = SeedPhrase::parse(&phrase(ABANDON_12)).unwrap().to_seed_bytes();
        assert_eq!(ours.to_vec(), external_seed);

        let (pk_ours, _) =
            crate::crypto::generate_keypair_from_seed(&ours[..32]).unwrap();
        let (pk_external, _) =
            crate::crypto::generate_keypair_from_seed(&external_seed[..32]).unwrap();
        assert_eq!(pk_ours, pk_external);
    }

    /// The legacy SHA-256 derivation is retained for migration/sweep tooling
    /// and pinned here so that path cannot silently drift. It must NOT equal
    /// the BIP39 seed — that inequality is exactly the bug K-M3 reported.
    #[test]
    fn legacy_sha256_seed_is_pinned_and_differs_from_bip39() {
        let seed = SeedPhrase::parse(&phrase(ABANDON_12)).unwrap();

        #[allow(deprecated)]
        let legacy = seed.to_seed_bytes_legacy_sha256();
        assert_ne!(legacy, seed.to_seed_bytes());
        assert_eq!(
            legacy.to_vec(),
            hex(
                "e37005eca9f1be2f3c6d86fd8d696f3c185ae3d36970d67c0588c6f75b209795\
                 53a4b1a2a3bad9c2ed253e597c9be55e8db153cce5add27f9940f1598c06adfe"
            ),
            "legacy derivation moved — wallets created before K-M3 would become unreachable"
        );
    }

    #[test]
    fn debug_does_not_leak_phrase() {
        let seed = SeedPhrase::generate().unwrap();
        let debug_str = format!("{:?}", seed);
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains(&seed.phrase));
    }
}
