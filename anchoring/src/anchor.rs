// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`Anchor`], [`Txid`], [`Finality`] and [`InclusionReference`] — the objects
//! Bloch hands back once your commitment is in the chain.
//!
//! Bloch's contribution is exactly three things: an **ordering**, a
//! **timestamp**, and an **anchor** (immutability under PoW depth). It is
//! nothing more — no statement about your system's validity (roadmap §2.2).

use crate::commitment::Commitment;

/// Length of a Bloch transaction id.
pub const TXID_LEN: usize = 32;

/// A 32-byte transaction id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Txid([u8; TXID_LEN]);

impl Txid {
    /// Wrap raw bytes.
    pub const fn from_bytes(b: [u8; TXID_LEN]) -> Self {
        Txid(b)
    }

    /// Parse a 64-char hex txid.
    pub fn from_hex(s: &str) -> crate::error::Result<Self> {
        let bytes = hex::decode(s.trim())?;
        if bytes.len() != TXID_LEN {
            return Err(crate::error::AnchorError::BadLength {
                expected: TXID_LEN,
                got: bytes.len(),
            });
        }
        let mut out = [0u8; TXID_LEN];
        out.copy_from_slice(&bytes);
        Ok(Txid(out))
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; TXID_LEN] {
        &self.0
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Txid({})", self.to_hex())
    }
}

impl std::fmt::Display for Txid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// PoW-depth finality, per roadmap §1.3. Bloch has **no BFT and no validator
/// set** — finality is purely burial depth.
///
/// * `0` confirmations           → [`Finality::Mempool`]
/// * `1..=99` confirmations      → [`Finality::Confirmed`]
/// * `100+` confirmations        → [`Finality::Final`] (coinbase maturity)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality {
    /// Seen but not yet in a block.
    Mempool,
    /// In a block, buried under `1..=99` blocks.
    Confirmed,
    /// Buried under `100+` blocks — treated as final.
    Final,
}

impl Finality {
    /// Number of blocks Bloch considers "final" (coinbase maturity).
    pub const FINAL_DEPTH: u64 = 100;

    /// Classify a confirmation count.
    pub const fn from_confirmations(confirmations: u64) -> Self {
        if confirmations == 0 {
            Finality::Mempool
        } else if confirmations >= Self::FINAL_DEPTH {
            Finality::Final
        } else {
            Finality::Confirmed
        }
    }
}

/// The receipt for a submitted commitment: where and how deeply it is anchored.
///
/// Note the honesty rail on the base chain. This crate anchors to **Genesis-3,
/// the proof-of-work chain, which stopped permanently at height 39,918 on
/// 2026-08-13**; while it ran, its k=4 relaxed-PoW low-hashrate regime made
/// work trivially forgeable and the chain 51%-attackable, so confirmations
/// were a *depth signal*, not a security guarantee. The live chain is
/// **Genesis-4, proof of stake**, where finality is Casper-style
/// justification/finalisation by epoch rather than depth, and where the
/// security question is concentration: all 64 validators are run by one
/// entity, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by the
/// founder and the Foundation. This type has not been ported to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The transaction that carries the commitment.
    pub txid: Txid,
    /// Block height the tx was mined at, if known (`None` while in mempool).
    pub height: Option<u64>,
    /// Confirmation depth (`0` = still in mempool).
    pub confirmations: u64,
}

impl Anchor {
    /// Classify this anchor's PoW-depth finality.
    pub fn finality(&self) -> Finality {
        Finality::from_confirmations(self.confirmations)
    }

    /// True once buried at least `n` blocks deep.
    pub fn has_confirmations(&self, n: u32) -> bool {
        self.confirmations >= n as u64
    }
}

/// The result of retrieving + verifying an anchored commitment by height/txid.
///
/// This is an **inclusion *reference*, not a full SPV/Merkle proof.** Today's
/// RPC surface (roadmap §1.2) lets you retrieve the transaction and confirm its
/// block + depth; it does not expose a Merkle branch. So this proves:
///
/// 1. a transaction with this `txid` exists and is mined at `height`,
/// 2. its outputs decode — via the documented convention — to *this* commitment,
/// 3. it is buried `confirmations` deep.
///
/// A compact Merkle-inclusion proof against the block's tx-root would be a
/// natural addition once a `getmerkleproof`-style RPC (or the data-carrier GIP)
/// lands — see the README.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionReference {
    /// The recovered commitment.
    pub commitment: Commitment,
    /// The anchoring transaction.
    pub anchor: Anchor,
    /// The raw output script_pubkeys (20 bytes each) that carried the
    /// commitment, so a verifier can independently re-decode them.
    pub carrier_scripts: Vec<Vec<u8>>,
}
