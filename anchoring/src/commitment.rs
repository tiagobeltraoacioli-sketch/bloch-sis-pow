// SPDX-License-Identifier: MIT OR Apache-2.0
//! The [`Commitment`] — a fixed-size digest an external system anchors to Bloch.
//!
//! A commitment is whatever compact fingerprint *your* system wants Bloch to
//! order + timestamp: an L2 state root, a rollup batch digest, a finality-gadget
//! checkpoint hash, an RWA attestation root. Bloch neither computes nor
//! validates it — it only anchors the 32 opaque bytes you hand it.
//!
//! > **Bloch settles nothing about what this digest means.** Its internal
//! > validity, data availability, and finality are yours (roadmap §2.2).

use crate::error::{AnchorError, Result};
use sha3::{Digest, Sha3_256};

/// Length in bytes of a Bloch anchor commitment.
pub const COMMITMENT_LEN: usize = 32;

/// Domain-separation tag mixed in when hashing arbitrary payloads into a
/// commitment, so an anchor digest can never collide with some other SHA3 use.
pub const COMMITMENT_DOMAIN: &[u8] = b"bloch-anchoring/commitment/v1";

/// A fixed-size (32-byte) commitment digest.
///
/// This is the ONLY thing that ever touches Bloch. Keep your real data (blocks,
/// batches, proofs) in your own data-availability layer and let this digest
/// reference it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Commitment([u8; COMMITMENT_LEN]);

impl Commitment {
    /// Wrap 32 raw bytes as a commitment (no hashing — you already have a digest).
    pub const fn from_bytes(bytes: [u8; COMMITMENT_LEN]) -> Self {
        Commitment(bytes)
    }

    /// Build a commitment from a byte slice of exactly [`COMMITMENT_LEN`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != COMMITMENT_LEN {
            return Err(AnchorError::BadLength {
                expected: COMMITMENT_LEN,
                got: bytes.len(),
            });
        }
        let mut out = [0u8; COMMITMENT_LEN];
        out.copy_from_slice(bytes);
        Ok(Commitment(out))
    }

    /// Domain-separated SHA3-256 of an arbitrary payload.
    ///
    /// Use this when you have raw bytes (a serialized checkpoint, a batch blob)
    /// and want a canonical 32-byte anchor for them.
    pub fn hash_payload(payload: &[u8]) -> Self {
        let mut h = Sha3_256::new();
        h.update(COMMITMENT_DOMAIN);
        h.update((payload.len() as u64).to_le_bytes());
        h.update(payload);
        let digest = h.finalize();
        let mut out = [0u8; COMMITMENT_LEN];
        out.copy_from_slice(&digest);
        Commitment(out)
    }

    /// Parse a 64-char hex string into a commitment.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim())?;
        Self::from_slice(&bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }

    /// Lowercase hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Commitment({})", self.to_hex())
    }
}

impl std::fmt::Display for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let c = Commitment::hash_payload(b"state root at height 42");
        let hex = c.to_hex();
        assert_eq!(hex.len(), 64);
        let back = Commitment::from_hex(&hex).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn hash_is_domain_separated_and_stable() {
        let a = Commitment::hash_payload(b"payload");
        let b = Commitment::hash_payload(b"payload");
        assert_eq!(a, b, "hashing must be deterministic");
        // A bare SHA3-256 of the same bytes must differ (domain + length prefix).
        let mut bare = Sha3_256::new();
        bare.update(b"payload");
        assert_ne!(a.as_bytes()[..], bare.finalize()[..]);
    }

    #[test]
    fn bad_length_rejected() {
        assert!(Commitment::from_slice(&[0u8; 31]).is_err());
        assert!(Commitment::from_slice(&[0u8; 33]).is_err());
    }
}
