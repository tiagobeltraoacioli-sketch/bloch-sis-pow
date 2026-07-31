// SPDX-License-Identifier: MIT OR Apache-2.0
//! Merged-mining (AuxPoW) verification — dual-mine Bloch with Bitcoin.
//!
//! Bloch is SHA-256d, exactly like Bitcoin, so the SAME work can secure both:
//! a miner hashes a Bitcoin block whose **coinbase carries a commitment to a
//! Bloch block**. If that single hash meets Bloch's (own, lower) target, the
//! AuxPoW proof lets Bloch accept the block — no extra hashing, no new ASICs.
//!
//! This is the standard Bitcoin/Namecoin `CAuxPow` check, faithful to that
//! format so existing merge-mining pool tooling applies:
//!   1. the parent (BTC) header's double-SHA256 meets Bloch's `bits` target;
//!   2. the parent coinbase is proven in the parent header's merkle root
//!      (coinbase merkle branch), and is the FIRST tx (index 0);
//!   3. the coinbase script carries the merge-mining marker
//!      `fa be 6d 6d ‖ aux_root(32) ‖ merkle_size(4 LE) ‖ merkle_nonce(4 LE)`,
//!      appearing exactly once, whose `aux_root` folds from this Bloch block
//!      hash via the (single-chain) chain merkle branch.
//!
//! **NOT YET CONSENSUS-WIRED.** This is the verifier + its tests; accepting an
//! AuxPoW block into the chain is a flag-day consensus change (an activation
//! height), wired separately, exactly like the earlier SHA-256d-LE fork.
//!
//! Honest caveat: merged mining only secures Bloch with the FRACTION of BTC
//! hashrate that opts in, and lets a large BTC miner attack at ~zero marginal
//! cost — for a young chain this can worsen the 51% risk, not fix it. It is a
//! bootstrap lever, not a security guarantee.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{bits_to_target, hash_meets_target};

/// Bloch's merged-mining chain id (used in the anti-collision expected-index
/// formula, Namecoin semantics). Distinct constant, versioned with the format.
pub const AUXPOW_CHAIN_ID: u32 = 0x0B10; // "BL0CH"

/// The merge-mining marker that precedes the aux commitment in the coinbase.
const MERGED_MINING_MAGIC: [u8; 4] = [0xfa, 0xbe, 0x6d, 0x6d];

/// A parent-Bitcoin AuxPoW proof for one Bloch block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxPow {
    /// The parent (Bitcoin) block header carrying the actual PoW — MUST be 80
    /// bytes (`Vec` rather than `[u8; 80]` only so serde derives; length is
    /// checked in [`AuxPow::verify`]).
    pub parent_header: Vec<u8>,
    /// The parent block's coinbase transaction, serialized.
    pub coinbase_tx: Vec<u8>,
    /// Merkle branch (sibling hashes, bottom→top) proving the coinbase txid is
    /// in `parent_header`'s merkle root.
    pub coinbase_branch: Vec<[u8; 32]>,
    /// Index of the coinbase within the parent block — MUST be 0.
    pub coinbase_index: u32,
    /// Aux-chain merkle branch (empty for a single merge-mined chain).
    pub chain_branch: Vec<[u8; 32]>,
    /// Aux-chain slot index (0 for a single chain).
    pub chain_index: u32,
}

/// Why an AuxPoW proof is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuxPowError {
    /// The parent coinbase was not the first transaction (index != 0).
    CoinbaseNotFirst,
    /// The merge-mining marker `fabe6d6d` was not found in the coinbase.
    MissingMarker,
    /// The marker appears more than once (a smuggled second commitment).
    DuplicateMarker,
    /// The bytes after the marker are too short for the commitment.
    CommitmentTruncated,
    /// The committed aux root does not match this Bloch block's aux root.
    AuxRootMismatch,
    /// `merkle_size` in the coinbase != `2^len(chain_branch)`.
    BadMerkleSize,
    /// `chain_index` does not equal the nonce-derived expected slot.
    WrongChainIndex,
    /// The coinbase does not fold to the parent header's merkle root.
    MerkleRootMismatch,
    /// The parent header's PoW does not meet Bloch's target.
    InsufficientPow,
    /// `parent_header` is not exactly 80 bytes.
    BadParentHeaderLen,
}

/// SHA-256d (Bitcoin's double SHA-256), raw internal byte order.
fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Fold a leaf up a merkle branch (Bitcoin order: bit i of `index` selects
/// whether the running hash is the left or right child at level i).
fn merkle_fold(leaf: [u8; 32], branch: &[[u8; 32]], mut index: u32) -> [u8; 32] {
    let mut h = leaf;
    for sib in branch {
        let mut buf = [0u8; 64];
        if index & 1 == 0 {
            buf[..32].copy_from_slice(&h);
            buf[32..].copy_from_slice(sib);
        } else {
            buf[..32].copy_from_slice(sib);
            buf[32..].copy_from_slice(&h);
        }
        h = sha256d(&buf);
        index >>= 1;
    }
    h
}

/// The anti-collision expected slot for an aux chain (Namecoin `getExpectedIndex`):
/// a deterministic PRNG of `(nonce, chain_id, merkle_height)` prevents an
/// attacker from placing one commitment at a chosen slot for many chains.
fn expected_index(nonce: u32, chain_id: u32, merkle_height: u32) -> u32 {
    let mut rand = nonce as u64;
    rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    rand = rand.wrapping_add(chain_id as u64);
    rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    ((rand >> 16) as u32) & ((1u32 << merkle_height) - 1)
}

/// Find the single occurrence of `needle` in `hay`; error if absent or repeated.
fn find_unique(hay: &[u8], needle: &[u8; 4]) -> Result<usize, AuxPowError> {
    let mut found: Option<usize> = None;
    let mut i = 0;
    while i + 4 <= hay.len() {
        if &hay[i..i + 4] == needle {
            if found.is_some() {
                return Err(AuxPowError::DuplicateMarker);
            }
            found = Some(i);
        }
        i += 1;
    }
    found.ok_or(AuxPowError::MissingMarker)
}

/// Compare a raw double-SHA256 output to a big-endian `target` under Bitcoin's
/// little-endian convention (the hash is read reversed) — the same rule Bloch
/// uses post the SHA-256d-LE fork, so a BTC parent header validates natively.
fn pow_meets_target_le(pow: &[u8; 32], target: &[u8; 32]) -> bool {
    let mut le = *pow;
    le.reverse();
    hash_meets_target(&le, target)
}

impl AuxPow {
    /// Verify this proof commits to `aux_block_hash` (the Bloch block hash) and
    /// carries enough Bitcoin PoW to meet Bloch's `bits` target.
    pub fn verify(&self, aux_block_hash: [u8; 32], bits: u32) -> Result<(), AuxPowError> {
        if self.parent_header.len() != 80 {
            return Err(AuxPowError::BadParentHeaderLen);
        }
        // (2b) coinbase must be the first parent tx.
        if self.coinbase_index != 0 {
            return Err(AuxPowError::CoinbaseNotFirst);
        }

        // (3) locate + parse the merge-mining commitment in the coinbase.
        let pos = find_unique(&self.coinbase_tx, &MERGED_MINING_MAGIC)?;
        let c = &self.coinbase_tx[pos + 4..];
        if c.len() < 32 + 4 + 4 {
            return Err(AuxPowError::CommitmentTruncated);
        }
        let mut committed_root = [0u8; 32];
        committed_root.copy_from_slice(&c[0..32]);
        let merkle_size = u32::from_le_bytes([c[32], c[33], c[34], c[35]]);
        let merkle_nonce = u32::from_le_bytes([c[36], c[37], c[38], c[39]]);

        // The aux root this block folds to, and the size/slot binds.
        let aux_root = merkle_fold(aux_block_hash, &self.chain_branch, self.chain_index);
        if committed_root != aux_root {
            return Err(AuxPowError::AuxRootMismatch);
        }
        let height = self.chain_branch.len() as u32;
        if merkle_size != (1u32 << height) {
            return Err(AuxPowError::BadMerkleSize);
        }
        if self.chain_index != expected_index(merkle_nonce, AUXPOW_CHAIN_ID, height) {
            return Err(AuxPowError::WrongChainIndex);
        }

        // (2a) coinbase folds to the parent header's merkle root (bytes 36..68).
        let coinbase_txid = sha256d(&self.coinbase_tx);
        let root = merkle_fold(coinbase_txid, &self.coinbase_branch, self.coinbase_index);
        if root[..] != self.parent_header[36..68] {
            return Err(AuxPowError::MerkleRootMismatch);
        }

        // (1) the parent header carries enough PoW for Bloch's target.
        let parent_pow = sha256d(&self.parent_header);
        if !pow_meets_target_le(&parent_pow, &bits_to_target(bits)) {
            return Err(AuxPowError::InsufficientPow);
        }
        Ok(())
    }

    /// Canonical wire encoding (u32-LE length prefixes) for the block's optional
    /// AuxPoW trailer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&(self.parent_header.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.parent_header);
        o.extend_from_slice(&(self.coinbase_tx.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.coinbase_tx);
        o.extend_from_slice(&(self.coinbase_branch.len() as u32).to_le_bytes());
        for h in &self.coinbase_branch {
            o.extend_from_slice(h);
        }
        o.extend_from_slice(&self.coinbase_index.to_le_bytes());
        o.extend_from_slice(&(self.chain_branch.len() as u32).to_le_bytes());
        for h in &self.chain_branch {
            o.extend_from_slice(h);
        }
        o.extend_from_slice(&self.chain_index.to_le_bytes());
        o
    }

    /// Decode a trailer written by [`to_bytes`], returning the value and the
    /// number of bytes consumed. Sane caps guard against a malformed trailer.
    pub fn from_bytes(b: &[u8]) -> Result<(Self, usize), String> {
        const MAX_TX: usize = 1 << 20; // 1 MiB coinbase cap
        const MAX_BRANCH: usize = 64; // merkle depth cap
        let mut p = 0usize;
        fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], String> {
            if *p + n > b.len() {
                return Err("auxpow trailer: truncated".to_string());
            }
            let s = &b[*p..*p + n];
            *p += n;
            Ok(s)
        }
        fn r32(b: &[u8], p: &mut usize) -> Result<u32, String> {
            let s = take(b, p, 4)?;
            Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        }
        fn r32arr(b: &[u8], p: &mut usize) -> Result<[u8; 32], String> {
            let mut a = [0u8; 32];
            a.copy_from_slice(take(b, p, 32)?);
            Ok(a)
        }
        let phl = r32(b, &mut p)? as usize;
        if phl != 80 {
            return Err("auxpow trailer: parent_header must be 80 bytes".to_string());
        }
        let parent_header = take(b, &mut p, phl)?.to_vec();
        let cbl = r32(b, &mut p)? as usize;
        if cbl > MAX_TX {
            return Err("auxpow trailer: coinbase too large".to_string());
        }
        let coinbase_tx = take(b, &mut p, cbl)?.to_vec();
        let cbn = r32(b, &mut p)? as usize;
        if cbn > MAX_BRANCH {
            return Err("auxpow trailer: coinbase branch too deep".to_string());
        }
        let mut coinbase_branch = Vec::with_capacity(cbn);
        for _ in 0..cbn {
            coinbase_branch.push(r32arr(b, &mut p)?);
        }
        let coinbase_index = r32(b, &mut p)?;
        let chn = r32(b, &mut p)? as usize;
        if chn > MAX_BRANCH {
            return Err("auxpow trailer: chain branch too deep".to_string());
        }
        let mut chain_branch = Vec::with_capacity(chn);
        for _ in 0..chn {
            chain_branch.push(r32arr(b, &mut p)?);
        }
        let chain_index = r32(b, &mut p)?;
        Ok((
            AuxPow { parent_header, coinbase_tx, coinbase_branch, coinbase_index, chain_branch, chain_index },
            p,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a coinbase whose script carries the merge-mining commitment to
    /// `aux_root`, single-chain (size 1, index 0).
    fn coinbase_with_commitment(aux_root: [u8; 32], nonce: u32) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(b"coinbase-prefix-bytes"); // stand-in tx header/scriptSig start
        tx.extend_from_slice(&MERGED_MINING_MAGIC);
        tx.extend_from_slice(&aux_root);
        tx.extend_from_slice(&1u32.to_le_bytes()); // merkle_size = 2^0
        tx.extend_from_slice(&nonce.to_le_bytes());
        tx.extend_from_slice(b"coinbase-suffix"); // outputs etc.
        tx
    }

    /// A parent header with a chosen merkle_root and an easy target so its PoW
    /// validates without mining. `bits` 0x2100ffff is a near-maximal target.
    fn parent_header_with_merkle(merkle_root: [u8; 32]) -> Vec<u8> {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&2i32.to_le_bytes()); // version
        // prev_hash [4..36] left zero
        h[36..68].copy_from_slice(&merkle_root);
        h[68..72].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // time
        h[72..76].copy_from_slice(&0x20ff_ffffu32.to_le_bytes()); // bits (easy)
        // nonce [76..80] left zero
        h.to_vec()
    }

    #[test]
    fn valid_single_chain_auxpow_verifies() {
        let aux_hash = [0xABu8; 32]; // the Bloch block hash
        let nonce = 0;
        // single chain: chain_index 0, empty branch → aux_root == aux_hash.
        let coinbase = coinbase_with_commitment(aux_hash, nonce);
        let coinbase_txid = sha256d(&coinbase);
        // Two-tx parent: coinbase (idx 0) + one other tx; merkle branch = [other].
        let other_txid = [0x11u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&coinbase_txid);
        buf[32..].copy_from_slice(&other_txid);
        let merkle_root = sha256d(&buf);
        let header = parent_header_with_merkle(merkle_root);

        let aux = AuxPow {
            parent_header: header,
            coinbase_tx: coinbase,
            coinbase_branch: vec![other_txid],
            coinbase_index: 0,
            chain_branch: vec![],
            chain_index: 0,
        };
        assert_eq!(aux.verify(aux_hash, 0x20ff_ffff), Ok(()));
    }

    #[test]
    fn rejects_wrong_aux_hash() {
        let aux_hash = [0xABu8; 32];
        let coinbase = coinbase_with_commitment(aux_hash, 0);
        let coinbase_txid = sha256d(&coinbase);
        let header = parent_header_with_merkle(coinbase_txid); // single-tx block
        let aux = AuxPow {
            parent_header: header,
            coinbase_tx: coinbase,
            coinbase_branch: vec![],
            coinbase_index: 0,
            chain_branch: vec![],
            chain_index: 0,
        };
        // A DIFFERENT Bloch block hash must not verify against this commitment.
        assert_eq!(aux.verify([0xCDu8; 32], 0x20ff_ffff), Err(AuxPowError::AuxRootMismatch));
        // The correct one does.
        assert_eq!(aux.verify(aux_hash, 0x20ff_ffff), Ok(()));
    }

    #[test]
    fn rejects_missing_and_duplicate_marker() {
        let aux_hash = [0x01u8; 32];
        // No marker.
        let no_marker = AuxPow {
            parent_header: parent_header_with_merkle([0u8; 32]),
            coinbase_tx: b"no marker here".to_vec(),
            coinbase_branch: vec![],
            coinbase_index: 0,
            chain_branch: vec![],
            chain_index: 0,
        };
        assert_eq!(no_marker.verify(aux_hash, 0x20ff_ffff), Err(AuxPowError::MissingMarker));

        // Two markers.
        let mut dup = coinbase_with_commitment(aux_hash, 0);
        dup.extend_from_slice(&MERGED_MINING_MAGIC);
        let aux = AuxPow {
            parent_header: parent_header_with_merkle([0u8; 32]),
            coinbase_tx: dup,
            coinbase_branch: vec![],
            coinbase_index: 0,
            chain_branch: vec![],
            chain_index: 0,
        };
        assert_eq!(aux.verify(aux_hash, 0x20ff_ffff), Err(AuxPowError::DuplicateMarker));
    }

    #[test]
    fn to_bytes_from_bytes_round_trips() {
        let aux = AuxPow {
            parent_header: parent_header_with_merkle([0x22u8; 32]),
            coinbase_tx: coinbase_with_commitment([0x33u8; 32], 7),
            coinbase_branch: vec![[0x44u8; 32], [0x55u8; 32]],
            coinbase_index: 0,
            chain_branch: vec![[0x66u8; 32]],
            chain_index: 0,
        };
        let bytes = aux.to_bytes();
        let (back, used) = AuxPow::from_bytes(&bytes).expect("decodes");
        assert_eq!(used, bytes.len());
        assert_eq!(back, aux);
        // Extra trailing bytes: decode stops at `used` (caller enforces strictness).
        let mut extended = bytes.clone();
        extended.push(0xFF);
        let (b2, used2) = AuxPow::from_bytes(&extended).expect("decodes prefix");
        assert_eq!(b2, aux);
        assert_eq!(used2, bytes.len());
        // Truncated → error, never a panic.
        assert!(AuxPow::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rejects_coinbase_not_first_and_insufficient_pow() {
        let aux_hash = [0x02u8; 32];
        let coinbase = coinbase_with_commitment(aux_hash, 0);
        let coinbase_txid = sha256d(&coinbase);
        // not first
        let aux = AuxPow {
            parent_header: parent_header_with_merkle(coinbase_txid),
            coinbase_tx: coinbase.clone(),
            coinbase_branch: vec![],
            coinbase_index: 1,
            chain_branch: vec![],
            chain_index: 0,
        };
        assert_eq!(aux.verify(aux_hash, 0x20ff_ffff), Err(AuxPowError::CoinbaseNotFirst));

        // valid structure but an IMPOSSIBLE target (all-zero) → insufficient PoW.
        let ok = AuxPow {
            parent_header: parent_header_with_merkle(coinbase_txid),
            coinbase_tx: coinbase,
            coinbase_branch: vec![],
            coinbase_index: 0,
            chain_branch: vec![],
            chain_index: 0,
        };
        // bits 0x03000001 → target ~0x000001000...0 (astronomically hard).
        assert_eq!(ok.verify(aux_hash, 0x0300_0001), Err(AuxPowError::InsufficientPow));
    }
}
