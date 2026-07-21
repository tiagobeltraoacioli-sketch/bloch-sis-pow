//! Stratum V1 job templates.
//!
//! A `Template` carries everything a miner needs to reconstruct the
//! 80-byte MiningHeader (see src/core/mod.rs MiningHeader), plus
//! enough extra state for the server to reassemble the full Block
//! when the miner submits a winning nonce.
//!
//! Pipeline:
//!
//! ```text
//!   Template::build()  — server reads tip + mempool + bits
//!      │
//!      ▼
//!   template.to_notify_params()  — rendered for mining.notify
//!      │
//!      ▼
//!   session.notify("mining.notify", ...)
//!      │
//!      ▼ miner computes coinbase_txid = sha256d(coinb1 || en1 || en2 || coinb2)
//!      ▼ walks merkle_branch → merkle_root
//!      ▼ assembles 80-byte MiningHeader, SHA-256d's it
//!      ▼ if hash < target: submit
//!      │
//!      ▼
//!   submit.rs (AA.1 pt 2b): reconstructs coinbase Transaction from
//!   the same bytes, assembles Block, routes to accept_block.
//! ```
//!
//! Critical invariant (tested below):
//!
//!   walk_merkle_branch(
//!     stratum_txid_of_bytes(coinb1 || en1 || en2 || coinb2),
//!     &template.merkle_branch,
//!   )  ==  Transaction::merkle_root(all_txs_including_coinbase)
//!
//! If this breaks, every share a miner submits is discarded as a
//! merkle mismatch and the server looks broken.

use sha2::{Digest, Sha256};
use serde_json::{json, Value};

use crate::core::{
    Transaction, TxInput, TxOutput,
    parents_commitment,
};

/// Extranonce size in bytes (4 en1 + 4 en2 = 8 bytes total injection).
pub const EXTRANONCE_TOTAL_BYTES: usize = 8;

/// A single job template delivered to one or more miners via mining.notify.
///
/// Immutable once built; the server stores these in a per-session
/// registry keyed by job_id so submissions can be matched back to
/// the originating template.
#[derive(Clone, Debug)]
pub struct Template {
    /// Unique job id. Sent to the miner; they echo it on submit.
    pub job_id: String,

    /// Original BlockDAG parents — kept so we can reconstruct the
    /// full BlockHeader when a submit arrives. Not visible to the
    /// miner; the miner only sees `prev_hash` below.
    pub parents: Vec<[u8; 32]>,

    /// 80-byte mining header's prev_hash field = parents_commitment(parents).
    /// Miner uses this directly as the 2nd 32-byte slot in the 80-byte header.
    pub prev_hash: [u8; 32],

    /// Merkle path from the coinbase_txid to the merkle_root. Ordered
    /// from leaf level up. Each entry is the sibling hash at that level.
    pub merkle_branch: Vec<[u8; 32]>,

    /// Coinbase bytes BEFORE the extranonce injection point.
    /// The miner forms: coinb1 || extranonce1 || extranonce2 || coinb2
    pub coinb1: Vec<u8>,

    /// Coinbase bytes AFTER the extranonce injection point.
    pub coinb2: Vec<u8>,

    /// Non-coinbase transactions from the mempool. Server reconstructs
    /// the full Block with these + the coinbase on submit.
    pub other_txs: Vec<Transaction>,

    /// Block header version field.
    pub version: u32,

    /// Block difficulty bits (target encoding).
    pub bits: u32,

    /// Suggested ntime. Miner may roll this within spec (currently
    /// no strict bounds; stratum clients cap rolling at a few minutes).
    pub ntime: u32,

    /// BlockDAG blue_score for the block-to-be.
    pub blue_score: u64,

    /// Block height (selected-chain index).
    pub height: u64,
}

impl Template {
    /// Build a template from concrete tip state.
    ///
    /// Parameters:
    /// - `parents`: BlockDAG parents selected for this block
    /// - `height`: the block's target height (tip.height + 1)
    /// - `blue_score`: the block's target blue_score
    /// - `bits`: current difficulty bits
    /// - `miner_spk`: miner's script_pubkey, from the authorized bech32 address
    /// - `total_fees`: sum of fees across `other_txs`, added to the coinbase value
    /// - `other_txs`: mempool-selected non-coinbase transactions
    /// - `coinbase_tag`: operator-chosen byte string for coinbase attribution
    /// - `job_id`: unique identifier for this template
    pub fn build(
        parents:      Vec<[u8; 32]>,
        height:       u64,
        blue_score:   u64,
        bits:         u32,
        miner_spk:    &[u8],
        total_fees:   u64,
        other_txs:    Vec<Transaction>,
        coinbase_tag: &[u8],
        job_id:       String,
    ) -> Self {
        // 1. Construct the coinbase with a placeholder extranonce.
        //
        //    script_sig = ascii("height:N|") || [0u8; 8] || coinbase_tag
        //                                       ^^^^^^^^^
        //                 extranonce1(4B)+extranonce2(4B) injection point
        //
        //    We then serialize the whole coinbase to stratum bytes and
        //    split coinb1/coinb2 at the location of the 8-byte zero run.
        let height_prefix = format!("height:{}|", height).into_bytes();

        let mut script_sig = Vec::with_capacity(height_prefix.len() + EXTRANONCE_TOTAL_BYTES + coinbase_tag.len());
        script_sig.extend_from_slice(&height_prefix);
        script_sig.extend_from_slice(&[0u8; EXTRANONCE_TOTAL_BYTES]);
        script_sig.extend_from_slice(coinbase_tag);

        // Bloch pure-PoW coinbase (B3):
        //   output[0] = miner   = full subsidy + total_fees
        //   output[1] = founder = vesting delta (if > 0)
        // Genesis-2 continues emission from the carried height: the coinbase must
        // pay the subsidy for the ABSOLUTE (emission) height, exactly as the
        // validator (validate_coinbase_value) computes it. `emission_height` is the
        // identity on every other chain, so this is a no-op there (Module-SIS, etc.).
        let emission_h = crate::core::emission_height(height);
        let subsidy = crate::core::tokenomics_v2::block_subsidy_sat(emission_h);
        let founder_vesting =
            crate::core::tokenomics_v2::founder_vesting_delta_sat(emission_h);

        let mut cb_outputs = vec![
            TxOutput {
                value:         subsidy.saturating_add(total_fees),
                script_pubkey: miner_spk.to_vec(),
            },
        ];
        if founder_vesting > 0 {
            cb_outputs.push(TxOutput {
                value:         founder_vesting,
                script_pubkey: crate::core::tokenomics_v2::founder_address_hash().to_vec(),
            });
        }

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig,
                sequence:   u32::MAX,
            }],
            outputs: cb_outputs,
            locktime: 0,
        };

        // 2. Serialize with script_sig (coinbase needs it for txid correctness).
        let coinbase_bytes = coinbase.to_stratum_bytes(true);

        // 3. Find the injection point. Our layout guarantees the height_prefix
        //    appears exactly once and is immediately followed by 8 zero bytes.
        //    That 8-byte run is what the miner replaces with their extranonce.
        let prefix_start = coinbase_bytes
            .windows(height_prefix.len())
            .position(|w| w == height_prefix.as_slice())
            .expect("placeholder height_prefix must appear in serialized coinbase");
        let injection_point = prefix_start + height_prefix.len();

        // 4. Split into coinb1 / coinb2. Miner fills the 8 bytes in the middle.
        let coinb1 = coinbase_bytes[..injection_point].to_vec();
        let coinb2 = coinbase_bytes[injection_point + EXTRANONCE_TOTAL_BYTES..].to_vec();

        // 5. Compute merkle_branch. Coinbase is at index 0; other_txs follow.
        let coinbase_txid = coinbase.txid();
        let other_txids:  Vec<[u8; 32]> = other_txs.iter().map(|t| t.txid()).collect();
        let all_txids:    Vec<[u8; 32]> = std::iter::once(coinbase_txid)
            .chain(other_txids.iter().copied())
            .collect();
        let merkle_branch = compute_merkle_branch(&all_txids);

        // 6. Derive the 80-byte mining header's prev_hash.
        let prev_hash = parents_commitment(&parents);

        // 7. ntime: current wall clock, low 32 bits. Miner may roll.
        let ntime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        Self {
            job_id,
            parents,
            prev_hash,
            merkle_branch,
            coinb1,
            coinb2,
            other_txs,
            version: 1,
            bits,
            ntime,
            blue_score,
            height,
        }
    }

    /// Render for mining.notify params.
    ///
    /// Stratum V1 notify shape:
    /// ```text
    /// [job_id,
    ///  prev_hash_hex,
    ///  coinb1_hex,
    ///  coinb2_hex,
    ///  [merkle_branch_hex, ...],
    ///  version_hex,
    ///  bits_hex,
    ///  ntime_hex,
    ///  clean_jobs_bool]
    /// ```
    ///
    /// All integer fields are big-endian hex per stratum convention
    /// (even though the underlying bytes are little-endian).
    pub fn to_notify_params(&self, clean_jobs: bool) -> Value {
        let branch: Vec<String> = self.merkle_branch.iter().map(hex::encode).collect();
        json!([
            self.job_id.clone(),
            // Stratum sends prev_hash with each 32-bit word byte-reversed; the
            // miner's le32dec UNDOES it to recover the raw consensus prev_hash.
            hex::encode(stratum_prevhash(&self.prev_hash)),
            hex::encode(&self.coinb1),
            hex::encode(&self.coinb2),
            branch,
            format!("{:08x}", self.version),
            format!("{:08x}", self.bits),
            format!("{:08x}", self.ntime),
            clean_jobs,
        ])
    }
}

/// Stratum V1 transmits the previous-block hash with each 32-bit word
/// byte-reversed. Standard SHA-256 miners (cpuminer, Antminer/BMMiner,
/// Whatsminer) run `le32dec` over each word when assembling the 80-byte
/// header, which UNDOES this swap and yields the raw consensus `prev_hash`
/// that `MiningHeader::to_bytes()` hashes. Sending the hash raw (no swap)
/// makes the miner hash a word-swapped prev_hash, so its PoW never matches
/// the node's reconstruction — every share/block is rejected as "invalid
/// PoW" (the long-standing ASIC/stratum rejection bug). This swap fixes it.
fn stratum_prevhash(prev: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4]     = prev[i * 4 + 3];
        out[i * 4 + 1] = prev[i * 4 + 2];
        out[i * 4 + 2] = prev[i * 4 + 1];
        out[i * 4 + 3] = prev[i * 4];
    }
    out
}

// ── Merkle branch primitives ───────────────────────────────────────

/// Compute the merkle branch for a list of txids where the coinbase
/// sits at index 0. Returns the sibling hashes from leaf level up.
///
/// For a tree of height h, returns a Vec of length h. If the input
/// has ≤ 1 txid, returns an empty Vec (coinbase_txid == merkle_root).
pub fn compute_merkle_branch(all_txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if all_txids.len() <= 1 {
        return Vec::new();
    }

    let mut level: Vec<[u8; 32]> = all_txids.to_vec();
    let mut branch: Vec<[u8; 32]> = Vec::new();

    while level.len() > 1 {
        // Bitcoin convention: duplicate last if odd.
        if level.len() % 2 != 0 {
            level.push(*level.last().expect("non-empty"));
        }

        // The coinbase (or its accumulated hash through this level)
        // is always at index 0. Its sibling is at index 1.
        branch.push(level[1]);

        // Collapse to next level.
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(Sha256::digest(Sha256::digest(buf)).into());
        }
        level = next;
    }

    branch
}

/// Walk a merkle branch from `coinbase_txid` up to the root.
///
/// The miner does this client-side to compute their merkle_root from
/// coinb1/coinb2-derived coinbase_txid + the branch from mining.notify.
///
/// Coinbase is always at position 0, so every concatenation is
/// (current || sibling), never (sibling || current).
pub fn walk_merkle_branch(coinbase_txid: [u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
    let mut h = coinbase_txid;
    for sibling in branch {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&h);
        buf[32..].copy_from_slice(sibling);
        h = Sha256::digest(Sha256::digest(buf)).into();
    }
    h
}

/// SHA-256d of arbitrary bytes. Used to hash reconstructed coinbase.
pub fn stratum_txid_of_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(bytes)).into()
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Transaction;

    fn mk_txid(tag: u8) -> [u8; 32] { [tag; 32] }

    // ── merkle_branch correctness (the consensus-critical invariant) ─

    /// The invariant that makes stratum work at all. Without this, every
    /// miner's submission gets rejected as a merkle-mismatch.
    fn assert_branch_reproduces_root(txids: &[[u8; 32]]) {
        if txids.is_empty() { return; }
        let branch = compute_merkle_branch(txids);
        let walked = walk_merkle_branch(txids[0], &branch);
        let canonical = bitcoin_style_merkle_root(txids);
        assert_eq!(walked, canonical,
            "walk(branch) disagrees with merkle_root for len={}", txids.len());
    }

    /// Canonical Bitcoin merkle root — used as the reference oracle
    /// against which `walk_merkle_branch` must agree.
    fn bitcoin_style_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() { return [0u8; 32]; }
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        while level.len() > 1 {
            if level.len() % 2 != 0 { level.push(*level.last().unwrap()); }
            level = level.chunks(2).map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                Sha256::digest(Sha256::digest(buf)).into()
            }).collect();
        }
        level[0]
    }

    #[test]
    fn branch_for_single_tx_is_empty() {
        let branch = compute_merkle_branch(&[mk_txid(0x01)]);
        assert!(branch.is_empty());
        // walk with empty branch returns coinbase_txid unchanged
        let walked = walk_merkle_branch(mk_txid(0x01), &branch);
        assert_eq!(walked, mk_txid(0x01));
    }

    #[test]
    fn branch_reproduces_root_for_2_txs() {
        let txids = vec![mk_txid(0x01), mk_txid(0x02)];
        assert_branch_reproduces_root(&txids);
    }

    #[test]
    fn branch_reproduces_root_for_3_txs() {
        // Odd count — triggers the "duplicate last" path.
        let txids = vec![mk_txid(0x01), mk_txid(0x02), mk_txid(0x03)];
        assert_branch_reproduces_root(&txids);
    }

    #[test]
    fn branch_reproduces_root_for_4_txs() {
        let txids = vec![mk_txid(0x01), mk_txid(0x02), mk_txid(0x03), mk_txid(0x04)];
        assert_branch_reproduces_root(&txids);
    }

    #[test]
    fn branch_reproduces_root_for_7_txs() {
        let txids: Vec<[u8; 32]> = (1..=7).map(|i| mk_txid(i as u8)).collect();
        assert_branch_reproduces_root(&txids);
    }

    #[test]
    fn branch_reproduces_root_for_8_txs() {
        let txids: Vec<[u8; 32]> = (1..=8).map(|i| mk_txid(i as u8)).collect();
        assert_branch_reproduces_root(&txids);
    }

    #[test]
    fn branch_reproduces_root_for_17_txs() {
        // Stress — 17 leaves, tree depth 5, lots of duplicate-last paths.
        let txids: Vec<[u8; 32]> = (1..=17).map(|i| mk_txid(i as u8)).collect();
        assert_branch_reproduces_root(&txids);
    }

    #[test]
    fn branch_length_matches_tree_depth() {
        // 2 leaves → depth 1 → 1 sibling
        assert_eq!(compute_merkle_branch(&vec![mk_txid(1); 2]).len(), 1);
        // 4 leaves → depth 2
        assert_eq!(compute_merkle_branch(&vec![mk_txid(1); 4]).len(), 2);
        // 5 leaves → depth 3 (pads to 6 → 3 → 2 → 1)
        assert_eq!(compute_merkle_branch(&vec![mk_txid(1); 5]).len(), 3);
        // 8 leaves → depth 3
        assert_eq!(compute_merkle_branch(&vec![mk_txid(1); 8]).len(), 3);
        // 9 leaves → depth 4
        assert_eq!(compute_merkle_branch(&vec![mk_txid(1); 9]).len(), 4);
    }

    // ── coinbase split correctness ─────────────────────────────────

    #[test]
    fn coinb1_plus_zeros_plus_coinb2_equals_full_coinbase_bytes() {
        // When we serialize a coinbase with placeholder zeros for extranonce,
        // splitting at the injection point and rejoining with zeros MUST
        // give us back the original byte string.
        let miner_spk = vec![0x11u8; 20];
        let tmpl = Template::build(
            vec![[0u8; 32]],
            100,
            99,
            0x1d00ffff,
            &miner_spk,
            0,
            Vec::new(),
            b"test-pool",
            "job-1".to_string(),
        );

        let injected_zeros = [0u8; EXTRANONCE_TOTAL_BYTES];
        let mut rejoined = Vec::new();
        rejoined.extend_from_slice(&tmpl.coinb1);
        rejoined.extend_from_slice(&injected_zeros);
        rejoined.extend_from_slice(&tmpl.coinb2);

        // Parse back to Transaction — must be equal to what we'd have built directly.
        let parsed = Transaction::from_stratum_bytes(&rejoined)
            .expect("rejoined bytes must deserialize");

        assert!(parsed.is_coinbase());
        // Bloch pure-PoW coinbase (B3): at this low height (outside the founder
        // vesting window) there is a single miner output paying 100% of the
        // subsidy. See src/core/mod.rs::Block::validate_coinbase_value.
        assert_eq!(parsed.outputs.len(), 1, "pure-PoW coinbase must have 1 output (miner)");
        assert_eq!(parsed.outputs[0].script_pubkey, miner_spk);
    }

    #[test]
    fn extranonce_injection_changes_coinbase_txid() {
        // Sanity: different extranonce bytes → different coinbase_txid.
        // If this fails, miners can't find unique solutions by varying
        // extranonce and the whole search-space expansion collapses.
        let miner_spk = vec![0x11u8; 20];
        let tmpl = Template::build(
            vec![[0u8; 32]], 100, 99, 0x1d00ffff,
            &miner_spk, 0, Vec::new(), b"test", "job".to_string(),
        );

        let mk_coinbase_bytes = |en: [u8; EXTRANONCE_TOTAL_BYTES]| {
            let mut b = Vec::new();
            b.extend_from_slice(&tmpl.coinb1);
            b.extend_from_slice(&en);
            b.extend_from_slice(&tmpl.coinb2);
            b
        };

        let bytes_a = mk_coinbase_bytes([0u8; 8]);
        let bytes_b = mk_coinbase_bytes([0xFFu8; 8]);
        let txid_a = stratum_txid_of_bytes(&bytes_a);
        let txid_b = stratum_txid_of_bytes(&bytes_b);

        assert_ne!(txid_a, txid_b, "extranonce must affect coinbase_txid");
    }

    // ── Template → notify shape ────────────────────────────────────

    #[test]
    fn notify_params_have_9_elements_in_correct_order() {
        let tmpl = Template::build(
            vec![[0u8; 32]], 1, 0, 0x1d00ffff,
            &vec![0u8; 20], 0, Vec::new(), b"t", "jobid".to_string(),
        );
        let params = tmpl.to_notify_params(true);
        let arr = params.as_array().expect("notify params must be array");
        assert_eq!(arr.len(), 9, "stratum notify has 9 positional params");
        assert_eq!(arr[0].as_str(), Some("jobid"));
        assert_eq!(arr[8].as_bool(), Some(true), "clean_jobs position");

        // Hex-encoded integer fields should be 8 hex chars (4 bytes).
        assert_eq!(arr[5].as_str().unwrap().len(), 8, "version hex is 8 chars");
        assert_eq!(arr[6].as_str().unwrap().len(), 8, "bits hex is 8 chars");
        assert_eq!(arr[7].as_str().unwrap().len(), 8, "ntime hex is 8 chars");
    }

    // ── Full end-to-end: reconstruct merkle_root from template ─────

    #[test]
    fn miner_can_reconstruct_merkle_root_from_template_alone() {
        // Simulate what a miner does after receiving mining.notify:
        //   1. Take coinb1 + pick extranonce1/extranonce2 + coinb2
        //   2. Hash to get coinbase_txid
        //   3. Walk the branch
        //   4. Compare against a merkle_root they'll put in the block header
        //
        // If this test passes for len=1, len=2, len=3 other_txs, stratum
        // miners can actually find blocks.

        for n_extra in [0usize, 1, 2, 3, 5] {
            let miner_spk = vec![0x77u8; 20];
            let other_txs: Vec<Transaction> = (0..n_extra).map(|i| {
                Transaction {
                    version: 1,
                    inputs: vec![TxInput {
                        prev_txid:  [i as u8; 32],
                        prev_index: 0,
                        script_sig: vec![0xAB, 0xCD],
                        sequence:   u32::MAX,
                    }],
                    outputs: vec![TxOutput {
                        value:         1000,
                        script_pubkey: vec![0x99; 20],
                    }],
                    locktime: 0,
                }
            }).collect();

            let tmpl = Template::build(
                vec![[0u8; 32]], 1, 0, 0x1d00ffff,
                &miner_spk, 0, other_txs.clone(), b"tag", format!("j{}", n_extra),
            );

            // Miner-side reconstruction:
            let miner_en = [0xCAu8, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
            let mut coinbase_bytes = Vec::new();
            coinbase_bytes.extend_from_slice(&tmpl.coinb1);
            coinbase_bytes.extend_from_slice(&miner_en);
            coinbase_bytes.extend_from_slice(&tmpl.coinb2);

            let miner_coinbase_txid = stratum_txid_of_bytes(&coinbase_bytes);
            let miner_merkle_root   = walk_merkle_branch(miner_coinbase_txid, &tmpl.merkle_branch);

            // Server-side verification: rebuild with same extranonce and
            // compute merkle_root directly. Must match miner's walk.
            let coinbase_tx = Transaction::from_stratum_bytes(&coinbase_bytes)
                .expect("coinbase must parse");
            assert!(coinbase_tx.is_coinbase());
            let all_txs: Vec<Transaction> = std::iter::once(coinbase_tx)
                .chain(other_txs.iter().cloned())
                .collect();
            let server_merkle_root = Transaction::merkle_root(&all_txs).into_inner();

            assert_eq!(
                miner_merkle_root, server_merkle_root,
                "miner's walk and server's direct compute disagree for n_extra={}", n_extra,
            );
        }
    }
}
