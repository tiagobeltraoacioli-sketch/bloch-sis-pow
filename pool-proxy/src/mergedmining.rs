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

/// Assemble the Stratum job for a merged-mining round: bind the Bloch commitment
/// into the parent Bitcoin coinbase and pre-compute the (extranonce-independent)
/// merkle branch the node folds the winning coinbase up.
///
/// The merge-mining commitment is placed at the END of `coinbase_script_prefix`
/// (i.e. BEFORE the miner's extranonce), so it is FIXED for the whole job — the
/// extranonce the miner rolls only ever lands between prefix and suffix. Because
/// the coinbase is tx index 0, every sibling in its merkle branch belongs to the
/// OTHER txs' subtrees and is independent of whatever coinbase the extranonce
/// produces — so the branch computed here stays valid for every share.
#[allow(clippy::too_many_arguments)]
pub fn build_merged_job(
    job_id: String,
    aux_block_hash: [u8; 32],
    bloch_bits: u32,
    btc_version: i32,
    btc_prev_hash: [u8; 32],
    btc_bits: u32,
    btc_ntime: u32,
    coinbase_script_prefix: &[u8],
    coinbase_script_suffix: &[u8],
    other_txids: &[[u8; 32]],
) -> MergedJob {
    let mut coinbase_prefix = coinbase_script_prefix.to_vec();
    coinbase_prefix.extend_from_slice(&merge_mining_commitment(aux_block_hash));

    // Branch is over [coinbase_placeholder, other_txids...] at index 0. The
    // index-0 leaf never appears in a pushed sibling, so a zero placeholder
    // yields the same branch the real (extranonce-filled) coinbase folds up.
    let mut all = Vec::with_capacity(other_txids.len() + 1);
    all.push([0u8; 32]);
    all.extend_from_slice(other_txids);
    let merkle_branch = coinbase_merkle_branch(&all, 0);

    MergedJob {
        job_id,
        aux_block_hash,
        bloch_bits,
        btc_version,
        btc_prev_hash,
        btc_bits,
        btc_ntime,
        coinbase_prefix,
        coinbase_suffix: coinbase_script_suffix.to_vec(),
        merkle_branch,
    }
}

/// On a share that meets Bloch's target, package the AuxPoW blob the Bloch node
/// accepts: the solved 80-byte parent header, the full coinbase the miner built
/// (`coinbase_prefix ‖ extranonce ‖ coinbase_suffix`), and the job's coinbase
/// merkle branch. The result is byte-for-byte what
/// `bloch_crypto::core::auxpow::AuxPow::from_bytes` reads (single aux chain).
pub fn assemble_auxpow_for_win(
    solved_parent_header: &[u8; 80],
    full_coinbase: &[u8],
    merkle_branch: &[[u8; 32]],
) -> Vec<u8> {
    serialize_auxpow(solved_parent_header, full_coinbase, merkle_branch, 0)
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
    fn merged_job_win_produces_node_consistent_auxpow() {
        let aux_hash = [0x9Au8; 32];
        let other_txids = vec![[1u8; 32], [2u8; 32]]; // 3 txs total (odd → dup-last)

        // POOL builds the job (commitment fixed in the prefix).
        let job = build_merged_job(
            "job-1".into(),
            aux_hash,
            0x20ff_ffff,      // bloch bits
            0x2000_0000,      // btc version
            [0x22u8; 32],     // btc prev hash
            0x1a00_ffff,      // btc bits
            1_700_000_000,    // btc ntime
            b"btc-coinbase-prefix",
            b"btc-coinbase-suffix",
            &other_txids,
        );
        // The commitment binds THIS Bloch block, in the fixed (pre-extranonce) part.
        let pos = job
            .coinbase_prefix
            .windows(4)
            .position(|w| w == MERGED_MINING_MAGIC)
            .expect("commitment present in prefix");
        assert_eq!(&job.coinbase_prefix[pos + 4..pos + 36], &aux_hash);

        // MINER rolls an extranonce → the actual coinbase for this share.
        let mut full_coinbase = job.coinbase_prefix.clone();
        full_coinbase.extend_from_slice(b"EXTRANONCE-xyz");
        full_coinbase.extend_from_slice(&job.coinbase_suffix);
        let cb_txid = sha256d(&full_coinbase);

        // The job's branch (built from a PLACEHOLDER coinbase) folds the REAL
        // winning coinbase to the true parent merkle root — extranonce-independent.
        let real_root = merkle_root_of(&[cb_txid, other_txids[0], other_txids[1]]);
        assert_eq!(fold(cb_txid, &job.merkle_branch), real_root);

        // Solved parent header carries that root; assemble the AuxPoW blob.
        let mut solved_header = [0u8; 80];
        solved_header[0..4].copy_from_slice(&job.btc_version.to_le_bytes());
        solved_header[4..36].copy_from_slice(&job.btc_prev_hash);
        solved_header[36..68].copy_from_slice(&real_root);
        solved_header[68..72].copy_from_slice(&job.btc_ntime.to_le_bytes());
        solved_header[72..76].copy_from_slice(&job.btc_bits.to_le_bytes());
        let blob = assemble_auxpow_for_win(&solved_header, &full_coinbase, &job.merkle_branch);

        // The blob is exactly what the node parser expects: parent header at a
        // fixed offset, and the coinbase folds (via the embedded branch) to the
        // header's own merkle root — the node's two structural checks.
        assert_eq!(&blob[0..4], &80u32.to_le_bytes());
        assert_eq!(&blob[4..84], &solved_header); // parent_header round-trips
        assert_eq!(&solved_header[36..68], &real_root); // header commits to the root the coinbase folds to
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
