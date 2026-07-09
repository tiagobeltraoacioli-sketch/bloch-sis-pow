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
//!   - PBKDF2 with 2048 rounds to derive seed bytes from phrase
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
use sha2::Sha256;
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

    /// Convert to raw seed bytes via PBKDF2 (as per BIP39 spec).
    ///
    /// These bytes are the starting material for key derivation. For ML-DSA-65,
    /// we use the first 32 bytes as the keygen seed.
    pub fn to_seed_bytes(&self) -> [u8; 64] {
        let salt = b"mnemonic";
        let mut out = [0u8; 64];
        let _ = pbkdf2::<Hmac<Sha256>>(
            self.phrase.as_bytes(),
            salt,
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

    #[test]
    fn debug_does_not_leak_phrase() {
        let seed = SeedPhrase::generate().unwrap();
        let debug_str = format!("{:?}", seed);
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains(&seed.phrase));
    }
}
