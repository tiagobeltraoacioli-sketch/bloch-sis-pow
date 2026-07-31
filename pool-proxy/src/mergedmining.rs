//! Merged-mining producer for the pool proxy — build the parent-Bitcoin coinbase
//! commitment to a Bloch block and, on a win, the AuxPoW blob the Bloch node
//! accepts. SCAFFOLD: the format here MUST match `bloch-crypto::core::auxpow`
//! (the canonical verifier); it is re-implemented locally so the proxy keeps its
//! ZERO dependency on bloch-crypto (a design boundary). A test folds the coinbase
//! branch to a full merkle root; the node-side `verify` is the authority.
//!
//! End-to-end (see docs/MERGED-MINING.md):
//!   1. Bloch node `getblocktemplate` → the Bloch block identity `aux_block_hash`
//!      to commit + Bloch `bits` (SCAFFOLD: needs the node to expose the hash);
//!   2. BTC node `getblocktemplate` → the parent template ([`crate::btc_rpc`]);
//!   3. build a BTC coinbase carrying [`merge_mining_commitment`];
//!   4. serve the BTC work over Stratum (miners unchanged);
//!   5. a solution meeting Bloch's target → [`serialize_auxpow`] + submit to the
//!      Bloch node (SCAFFOLD: a `submitauxblock(aux_hash, auxpow_hex)` RPC);
//!      a solution meeting BTC's target → `submitblock` to bitcoind.

use sha2::{Digest, Sha256};

/// Merge-mining marker (Bitcoin/Namecoin `fabe6d6d`).
pub const MERGED_MINING_MAGIC: [u8; 4] = [0xfa, 0xbe, 0x6d, 0x6d];

/// SHA-256d.
fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// The bytes a pool embeds in the parent Bitcoin coinbase scriptSig:
/// `fabe6d6d ‖ aux_block_hash ‖ size(=1 LE) ‖ nonce(=0 LE)` (single aux chain).
/// MUST match `bloch_crypto::core::auxpow::merge_mining_commitment`.
pub fn merge_mining_commitment(aux_block_hash: [u8; 32]) -> Vec<u8> {
    let mut c = Vec::with_capacity(44);
    c.extend_from_slice(&MERGED_MINING_MAGIC);
    c.extend_from_slice(&aux_block_hash);
    c.extend_from_slice(&1u32.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c
}

/// Bitcoin merkle branch of the tx at `index` (coinbase = 0), duplicating the
/// last node on odd levels. Folding the tx txid up this branch reproduces the
/// parent header's merkle root (Bloch node checks this).
pub fn coinbase_merkle_branch(txids: &[[u8; 32]], index: u32) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    let mut idx = index as usize;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        branch.push(level[idx ^ 1]);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(sha256d(&buf));
        }
        level = next;
        idx >>= 1;
    }
    branch
}

/// Serialize an AuxPoW blob in the exact wire format
/// `bloch_crypto::core::auxpow::AuxPow::from_bytes` reads (single aux chain):
/// u32-LE length prefixes throughout. This is what the pool sends to the Bloch
/// node on a Bloch-target win.
pub fn serialize_auxpow(
    parent_header: &[u8; 80],
    coinbase_tx: &[u8],
    coinbase_branch: &[[u8; 32]],
    coinbase_index: u32,
) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&80u32.to_le_bytes());
    o.extend_from_slice(parent_header);
    o.extend_from_slice(&(coinbase_tx.len() as u32).to_le_bytes());
    o.extend_from_slice(coinbase_tx);
    o.extend_from_slice(&(coinbase_branch.len() as u32).to_le_bytes());
    for h in coinbase_branch {
        o.extend_from_slice(h);
    }
    o.extend_from_slice(&coinbase_index.to_le_bytes());
    // single aux chain: empty chain_branch + chain_index 0.
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o
}

/// Merged-mining configuration (BTC node + the pool's BTC payout).
#[derive(Clone, Debug)]
pub struct MergedMiningConfig {
    /// Enable merged mining (off by default — inert like the consensus side).
    pub enabled: bool,
    /// bitcoind RPC `host:port`.
    pub btc_rpc_addr: String,
    pub btc_rpc_user: String,
    pub btc_rpc_pass: String,
    /// The pool's BTC coinbase output script (where BTC rewards go).
    pub btc_payout_script: Vec<u8>,
}

impl Default for MergedMiningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            btc_rpc_addr: "127.0.0.1:8332".to_string(),
            btc_rpc_user: String::new(),
            btc_rpc_pass: String::new(),
            btc_payout_script: Vec::new(),
        }
    }
}

/// A merged-mining job: the parent-BTC work plus the Bloch commitment bound
/// into its coinbase. SCAFFOLD: field set for the Stratum job the proxy serves;
/// the coinbase split (`coinbase_prefix ‖ extranonce ‖ coinbase_suffix`) is the
/// standard Stratum `mining.notify` shape.
#[derive(Clone, Debug)]
pub struct MergedJob {
    pub job_id: String,
    /// The Bloch block this job merge-mines (committed in the coinbase).
    pub aux_block_hash: [u8; 32],
    /// Bloch's own compact target — a share meeting THIS is a Bloch block.
    pub bloch_bits: u32,
    /// Parent BTC header fields for the Stratum notify.
    pub btc_version: i32,
    pub btc_prev_hash: [u8; 32],
    pub btc_bits: u32,
    pub btc_ntime: u32,
    /// Coinbase split around the miner's extranonce (Stratum notify parts 2/3).
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_suffix: Vec<u8>,
    /// Merkle branch of the (other) BTC txs used to fold the coinbase to root.
    pub merkle_branch: Vec<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merkle_root_of(txids: &[[u8; 32]]) -> [u8; 32] {
        let mut level = txids.to_vec();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let mut b = [0u8; 64];
                b[..32].copy_from_slice(&pair[0]);
                b[32..].copy_from_slice(&pair[1]);
                next.push(sha256d(&b));
            }
            level = next;
        }
        level[0]
    }

    /// Fold the coinbase (index 0) up the pool's branch — must equal the full
    /// merkle root the parent header carries.
    fn fold(leaf: [u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
        let mut h = leaf;
        for sib in branch {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&h);
            b[32..].copy_from_slice(sib);
            h = sha256d(&b);
        }
        h
    }

    #[test]
    fn coinbase_branch_folds_to_merkle_root() {
        let coinbase = {
            let mut c = b"coinbase".to_vec();
            c.extend_from_slice(&merge_mining_commitment([0xAB; 32]));
            c
        };
        let cb_txid = sha256d(&coinbase);
        // odd tx count exercises the duplicate-last rule
        let txids = vec![cb_txid, [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let branch = coinbase_merkle_branch(&txids, 0);
        assert_eq!(fold(cb_txid, &branch), merkle_root_of(&txids));
    }

    #[test]
    fn commitment_layout_is_fixed() {
        let c = merge_mining_commitment([0x11; 32]);
        assert_eq!(c.len(), 44);
        assert_eq!(&c[0..4], &MERGED_MINING_MAGIC);
        assert_eq!(&c[4..36], &[0x11u8; 32]);
        assert_eq!(&c[36..40], &1u32.to_le_bytes()); // size
        assert_eq!(&c[40..44], &0u32.to_le_bytes()); // nonce
    }

    #[test]
    fn serialize_auxpow_length_is_deterministic() {
        let hdr = [7u8; 80];
        let cb = vec![9u8; 50];
        let branch = vec![[1u8; 32], [2u8; 32]];
        let blob = serialize_auxpow(&hdr, &cb, &branch, 0);
        // 4+80 + 4+50 + 4+64 + 4 + 4 + 4
        assert_eq!(blob.len(), 4 + 80 + 4 + 50 + 4 + 64 + 4 + 4 + 4);
    }
}
