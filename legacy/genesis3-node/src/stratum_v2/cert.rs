// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 Pool Authority Certificate.
//
// This module implements the SIGNATURE_NOISE_MESSAGE construction specified in
// Stratum V2 spec chapter 4 (Protocol Security). A pool operator maintains
// two keypairs:
//
//   - Authority keypair (long-lived, human-managed): the identity root of the
//     pool. Miners pin the authority pubkey in their config.
//   - Static keypair (rotatable, node-managed): performs the per-session ECDH
//     math during the NOISE_NX handshake. Bound to the authority identity via
//     a certificate (SignatureNoiseMessage) signed by the authority key.
//
// If the static key is compromised, the operator generates a new one, signs
// it with the still-safe authority key, and restarts. Miners reconnect with
// zero configuration change.
//
// Byte layout of the certificate (74 bytes on the wire):
//
//   version         u16  little-endian    2 bytes  (always 0x0000)
//   valid_from      u32  little-endian    4 bytes  (unix seconds inclusive)
//   not_valid_after u32  little-endian    4 bytes  (unix seconds exclusive)
//   signature       [u8; 64]              64 bytes (BIP-340 Schnorr)
//
// The Schnorr signature covers the concatenation:
//
//   version_bytes || valid_from_bytes || not_valid_after_bytes || static_pubkey_x
//
// where static_pubkey_x is the 32-byte x-coordinate of the Schnorr pubkey
// (XOnlyPublicKey) corresponding to the pool's static keypair.

use secp256k1::{
    schnorr::Signature,
    Keypair, Message, Secp256k1, XOnlyPublicKey,
};
use sha2::{Digest, Sha256};

use super::Sv2Error;

/// Byte length of the serialized certificate on the wire.
pub const CERT_LEN: usize = 2 + 4 + 4 + 64;

/// Current certificate version. Increment on incompatible format changes.
pub const CERT_VERSION: u16 = 0;

/// Pool authority certificate (Schnorr-signed attestation that a static
/// NOISE keypair is endorsed by the authority keypair for a time window).
#[derive(Debug, Clone, Copy)]
pub struct SignatureNoiseMessage {
    pub version:         u16,
    pub valid_from:      u32,
    pub not_valid_after: u32,
    pub signature:       [u8; 64],
}

impl SignatureNoiseMessage {
    /// Sign a new certificate binding `static_pubkey_x` to the authority
    /// identity for the window [valid_from, not_valid_after).
    ///
    /// Errors:
    ///   - Sv2Error::Config if valid_from >= not_valid_after
    pub fn new(
        authority_keypair: &Keypair,
        static_pubkey_x:   &XOnlyPublicKey,
        valid_from:        u32,
        not_valid_after:   u32,
    ) -> Result<Self, Sv2Error> {
        if valid_from >= not_valid_after {
            return Err(Sv2Error::Config(format!(
                "valid_from ({}) must be < not_valid_after ({})",
                valid_from, not_valid_after
            )));
        }

        let secp = Secp256k1::new();
        let digest = cert_digest(CERT_VERSION, valid_from, not_valid_after, static_pubkey_x);
        let message = Message::from_digest(digest);
        let sig = secp.sign_schnorr_no_aux_rand(&message, authority_keypair);

        Ok(Self {
            version:         CERT_VERSION,
            valid_from,
            not_valid_after,
            signature:       sig.as_ref().to_owned(),
        })
    }

    /// Verify a certificate claims to bind `static_pubkey_x` to the given
    /// authority identity, and the claim is cryptographically valid and
    /// within its validity window.
    ///
    /// `now_unix` is the current time. Pass 0 to skip the temporal check
    /// (useful only for tests).
    pub fn verify(
        &self,
        authority_pubkey: &XOnlyPublicKey,
        static_pubkey_x:  &XOnlyPublicKey,
        now_unix:         u32,
    ) -> Result<(), Sv2Error> {
        if self.version != CERT_VERSION {
            return Err(Sv2Error::Keypair(format!(
                "cert version {} unsupported (expected {})",
                self.version, CERT_VERSION
            )));
        }

        if now_unix != 0 {
            if now_unix < self.valid_from {
                return Err(Sv2Error::Keypair(format!(
                    "cert not valid yet: now={} valid_from={}",
                    now_unix, self.valid_from
                )));
            }
            if now_unix >= self.not_valid_after {
                return Err(Sv2Error::Keypair(format!(
                    "cert expired: now={} not_valid_after={}",
                    now_unix, self.not_valid_after
                )));
            }
        }

        let secp = Secp256k1::verification_only();
        let digest = cert_digest(self.version, self.valid_from, self.not_valid_after, static_pubkey_x);
        let message = Message::from_digest(digest);
        let sig = Signature::from_slice(&self.signature)
            .map_err(|e| Sv2Error::Keypair(format!("parse sig: {}", e)))?;

        secp.verify_schnorr(&sig, &message, authority_pubkey)
            .map_err(|e| Sv2Error::Keypair(format!("signature invalid: {}", e)))
    }

    /// Serialize to the 74-byte wire format.
    pub fn to_bytes(&self) -> [u8; CERT_LEN] {
        let mut out = [0u8; CERT_LEN];
        out[0..2].copy_from_slice(&self.version.to_le_bytes());
        out[2..6].copy_from_slice(&self.valid_from.to_le_bytes());
        out[6..10].copy_from_slice(&self.not_valid_after.to_le_bytes());
        out[10..74].copy_from_slice(&self.signature);
        out
    }

    /// Parse from the 74-byte wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Sv2Error> {
        if bytes.len() != CERT_LEN {
            return Err(Sv2Error::Keypair(format!(
                "cert length {} (expected {})",
                bytes.len(), CERT_LEN
            )));
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        let valid_from = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let not_valid_after = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[10..74]);

        Ok(Self { version, valid_from, not_valid_after, signature })
    }
}

/// Compute the SHA-256 digest that is signed by the authority keypair.
/// This is the canonical message construction for SV2 pool certificates.
fn cert_digest(
    version:         u16,
    valid_from:      u32,
    not_valid_after: u32,
    static_pubkey_x: &XOnlyPublicKey,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(version.to_le_bytes());
    h.update(valid_from.to_le_bytes());
    h.update(not_valid_after.to_le_bytes());
    h.update(static_pubkey_x.serialize());
    let out = h.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}
