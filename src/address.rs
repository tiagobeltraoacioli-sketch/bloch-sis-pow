//! Bloch-SIS Protocol — Unified Address type
//!
//! Replaces scattered `[u8; 20]`, `Vec<u8>`, `String` address handling
//! with a single ergonomic type. Works in all three forms:
//!
//!   - On-chain: 20-byte hash (`&[u8; 20]`)
//!   - User-facing: "bloch1q..." / "bloch1t..." string with checksum
//!   - Raw bytes: 24-byte payload (20 hash + 4 checksum)
//!
//! All validation, parsing, and display logic lives here. Other modules
//! should take `&Address` instead of `&[u8]`.

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use thiserror::Error;

use crate::core::{MAINNET_PREFIX, TESTNET_PREFIX};

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn prefix(&self) -> &'static str {
        match self {
            Network::Mainnet => MAINNET_PREFIX,
            Network::Testnet => TESTNET_PREFIX,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    hash: [u8; 20],
    network: Network,
}

impl Address {
    /// Create an address from a known-good 20-byte pubkey hash.
    pub fn from_hash(hash: [u8; 20], network: Network) -> Self {
        Self { hash, network }
    }

    /// Borrow the 20-byte pubkey hash component of the address.
    pub fn hash_bytes(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Derive an address from a raw ML-DSA-65 public key.
    pub fn from_pubkey(pubkey: &[u8], network: Network) -> Self {
        let digest = Sha3_256::digest(pubkey);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&digest[..20]);
        Self { hash, network }
    }

    /// Parse a user-facing address string (bloch1q... or bloch1t...).
    /// Validates: prefix, hex format, length, and checksum.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let (network, payload) = if let Some(rest) = s.strip_prefix(MAINNET_PREFIX) {
            (Network::Mainnet, rest)
        } else if let Some(rest) = s.strip_prefix(TESTNET_PREFIX) {
            (Network::Testnet, rest)
        } else {
            return Err(AddressError::BadPrefix);
        };

        // Payload is hex of 20-byte hash + 4-byte checksum = 48 hex chars.
        if payload.len() != 48 {
            return Err(AddressError::BadLength { got: payload.len(), expected: 48 });
        }

        let bytes = hex::decode(payload).map_err(|_| AddressError::BadHex)?;
        if bytes.len() != 24 {
            return Err(AddressError::BadLength { got: bytes.len(), expected: 24 });
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[..20]);
        let expected_checksum = &bytes[20..24];

        // Verify checksum: SHA3-256(SHA3-256(hash))[0..4]
        let inner = Sha3_256::digest(&hash);
        let outer = Sha3_256::digest(&inner);
        let actual_checksum = &outer[..4];

        if expected_checksum != actual_checksum {
            return Err(AddressError::BadChecksum);
        }

        Ok(Self { hash, network })
    }

    /// The 20-byte pubkey hash (for storage, script_pubkey, etc.)
    pub fn hash(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Network enum.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Is this a mainnet address?
    pub fn is_mainnet(&self) -> bool {
        matches!(self.network, Network::Mainnet)
    }

    /// Is this a testnet address?
    pub fn is_testnet(&self) -> bool {
        matches!(self.network, Network::Testnet)
    }

    /// User-facing string form with checksum.
    pub fn to_string(&self) -> String {
        let inner = Sha3_256::digest(&self.hash);
        let outer = Sha3_256::digest(&inner);
        let checksum = &outer[..4];
        let mut payload = self.hash.to_vec();
        payload.extend_from_slice(checksum);
        format!("{}{}", self.network.prefix(), hex::encode(&payload))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::str::FromStr for Address {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid prefix (expected bloch1q or bloch1t)")]
    BadPrefix,
    #[error("invalid length: got {got} chars, expected {expected}")]
    BadLength { got: usize, expected: usize },
    #[error("invalid hex encoding")]
    BadHex,
    #[error("checksum mismatch")]
    BadChecksum,
}

// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn roundtrip_pubkey_address() {
        let (pk, _) = crypto::generate_keypair();
        let addr = Address::from_pubkey(&pk, Network::Mainnet);
        let as_str = addr.to_string();
        let parsed = Address::parse(&as_str).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn mainnet_address_starts_with_bloch1q() {
        let addr = Address::from_hash([0u8; 20], Network::Mainnet);
        assert!(addr.to_string().starts_with("bloch1q"));
    }

    #[test]
    fn testnet_address_starts_with_bloch1t() {
        let addr = Address::from_hash([0u8; 20], Network::Testnet);
        assert!(addr.to_string().starts_with("bloch1t"));
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        let result = Address::parse("bc1qabc123");
        assert!(matches!(result, Err(AddressError::BadPrefix)));
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let mut addr_str = Address::from_hash([0u8; 20], Network::Mainnet).to_string();
        // Flip one char of the checksum
        let last = addr_str.len() - 1;
        let new_char = if addr_str.as_bytes()[last] == b'0' { '1' } else { '0' };
        addr_str.replace_range(last..last+1, &new_char.to_string());
        let result = Address::parse(&addr_str);
        assert!(matches!(result, Err(AddressError::BadChecksum)));
    }

    #[test]
    fn parse_rejects_bad_length() {
        let result = Address::parse("bloch1qshort");
        assert!(matches!(result, Err(AddressError::BadLength { .. })));
    }

    #[test]
    fn treasury_address_parses() {
        // Treasury vault address (genesis-locked, see TOKENOMICS_V1.md §8)
        let s = "bloch1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31";
        let addr = Address::parse(s).unwrap();
        assert!(addr.is_mainnet());
        assert_eq!(addr.to_string(), s);
    }
}
