//! Merged-mining producer for the pool proxy — build the parent-Bitcoin coinbase
//! commitment to a Bloch block and, on a win, the AuxPoW blob the Bloch node
//! accepts. SCAFFOLD: the format here MUST match `bloch-crypto::core::auxpow`
//! (the canonical verifier); it is re-implemented locally so the proxy keeps its
//! ZERO dependency on bloch-crypto (a design boundary). A test folds the coinbase
//! branch to a full merkle root; the node-side `verify` is the authority.
//!
//! End-to-end (see legacy/MERGED-MINING.md):
//!   1. Bloch node `getblocktemplate` → the Bloch block identity `aux_block_hash`
//!      to commit + Bloch `bits` (SCAFFOLD: needs the node to expose the hash);
//!   2. BTC node `getblocktemplate` → the parent template ([`crate::btc_rpc`]);
//!   3. build a BTC coinbase carrying [`merge_mining_commitment`];
//!   4. serve the BTC work over Stratum (miners unchanged);
//!   5. a solution meeting Bloch's target → [`serialize_auxpow`] + submit to the
//!      Bloch node (SCAFFOLD: a `submitauxblock(aux_hash, auxpow_hex)` RPC);
//!      a solution meeting BTC's target → `submitblock` to bitcoind.

use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::jobstore::FullJob;
use crate::types::PoolError;
use crate::validator::{
    bits_to_target, effective_version, hex_to_bytes, meets, parse_hex_u32,
    undo_prevhash_word_swap, walk_merkle_branch,
};

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

// ── Stratum serve (the proxy generates + serves merged work) ─────────────────
//
// Unlike the transparent-proxy path (which forwards the node's own notify), a
// merged-mining round serves the PARENT BITCOIN work: the miner hashes a BTC
// block header whose coinbase carries the Bloch commitment. The wire is standard
// Stratum V1 — an ASIC needs no changes — so this reuses the exact notify shape
// (`jobstore::parse_notify_full`) and the exact share reconstruction/target math
// (`validator::validate`); merged mining only adds the SECOND target check.

/// Render a [`MergedJob`] as a Stratum `mining.notify` line for a downstream
/// miner. Serves the BTC parent work: `prevhash` is word-swapped for the wire
/// (the miner un-swaps it, exactly like the node's notify), the coinbase is
/// split `coinb1 = prefix (commitment already inside) ‖ <extranonce> ‖ coinb2 =
/// suffix`, and version/nbits/ntime are the parent Bitcoin header's, big-endian
/// per Stratum convention.
pub fn merged_job_to_notify(job: &MergedJob, clean_jobs: bool) -> String {
    let prevhash_wire = undo_prevhash_word_swap(&job.btc_prev_hash); // own inverse → wire form
    let merkle_json = job
        .merkle_branch
        .iter()
        .map(|h| format!("\"{}\"", hex::encode(h)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"id":null,"method":"mining.notify","params":["{id}","{prev}","{c1}","{c2}",[{mb}],"{ver:08x}","{bits:08x}","{ntime:08x}",{clean}]}}"#,
        id = job.job_id,
        prev = hex::encode(prevhash_wire),
        c1 = hex::encode(&job.coinbase_prefix),
        c2 = hex::encode(&job.coinbase_suffix),
        mb = merkle_json,
        ver = job.btc_version as u32,
        bits = job.btc_bits,
        ntime = job.btc_ntime,
        clean = clean_jobs,
    )
}

/// Adapt a [`MergedJob`] into a [`FullJob`] so the existing [`JobStore`] and
/// [`validator::validate`] handle merged work UNCHANGED (worker + BTC-block
/// checks). The Bloch-target check is layered on in [`classify_merged_share`].
/// `prevhash_raw` is the raw consensus prev-hash (validator un-word-swaps the
/// wire form; here we already hold raw). Height is `u64::MAX` — a BTC parent is
/// always Bitcoin little-endian, so the fork gate stays post-fork (`le = true`).
pub fn merged_job_to_fulljob(job: &MergedJob) -> FullJob {
    FullJob {
        job_id: job.job_id.clone(),
        version: job.btc_version as u32,
        prevhash_raw: job.btc_prev_hash,
        coinb1: job.coinbase_prefix.clone(),
        coinb2: job.coinbase_suffix.clone(),
        merkle_branch: job.merkle_branch.clone(),
        nbits: job.btc_bits,
        network_target: bits_to_target(job.btc_bits),
        height: u64::MAX,
        clean_jobs: true,
        received_at: Instant::now(),
    }
}

/// What a reconstructed merged share turned out to be. Ordered by strength: a
/// BTC-target hash is ALSO a Bloch block (Bloch's target is the looser one), so
/// it wins both; a Bloch-target hash that misses BTC is the common merged win.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergedWin {
    /// Meets Bitcoin's target: a real BTC block AND a Bloch block — submit the
    /// BTC block to bitcoind and the AuxPoW to the Bloch node.
    BtcAndBloch,
    /// Meets Bloch's (looser) target but not Bitcoin's: a Bloch block via AuxPoW.
    Bloch,
    /// Meets the worker's vardiff target only: a valid share (accounting).
    Share,
    /// Below the worker target — rejected.
    Reject,
}

/// A classified merged share: the reconstructed parent hash, the verdict, and —
/// on any Bloch-target win — the AuxPoW blob ready for the Bloch node.
#[derive(Clone, Debug)]
pub struct MergedClassification {
    pub win: MergedWin,
    /// Double-SHA256 of the reconstructed 80-byte parent Bitcoin header.
    pub hash: [u8; 32],
    /// The AuxPoW blob (`AuxPow::from_bytes` wire) — `Some` iff `win` is
    /// `Bloch` or `BtcAndBloch`.
    pub auxpow_blob: Option<Vec<u8>>,
}

/// Reconstruct a submitted merged share's parent Bitcoin header and classify it
/// against BOTH targets. The header reconstruction is byte-identical to
/// [`validator::validate`] (same coinbase splice, merkle walk, version-rolling,
/// LE compare) — merged mining only adds the Bloch-target check and, on a Bloch
/// win, packages the AuxPoW. `le = true` throughout: a BTC parent hash is
/// Bitcoin little-endian, matching the node's `auxpow::pow_meets_target_le`.
#[allow(clippy::too_many_arguments)]
pub fn classify_merged_share(
    job: &MergedJob,
    en1_hex: &str,
    en2_hex: &str,
    ntime_hex: &str,
    nonce_hex: &str,
    version_bits: Option<u32>,
    worker_target: &[u8; 32],
) -> Result<MergedClassification, PoolError> {
    // coinbase = prefix ‖ en1 ‖ en2 ‖ suffix (the commitment is inside prefix).
    let en1 = hex_to_bytes(en1_hex).ok_or_else(|| PoolError::Protocol("merged: en1 not hex".into()))?;
    let en2 = hex_to_bytes(en2_hex).ok_or_else(|| PoolError::Protocol("merged: en2 not hex".into()))?;
    let mut coinbase = Vec::with_capacity(
        job.coinbase_prefix.len() + en1.len() + en2.len() + job.coinbase_suffix.len(),
    );
    coinbase.extend_from_slice(&job.coinbase_prefix);
    coinbase.extend_from_slice(&en1);
    coinbase.extend_from_slice(&en2);
    coinbase.extend_from_slice(&job.coinbase_suffix);

    let txid = sha256d(&coinbase);
    let merkle_root = walk_merkle_branch(txid, &job.merkle_branch);

    let ntime = parse_hex_u32(ntime_hex)
        .ok_or_else(|| PoolError::Protocol("merged: ntime not a hex u32".into()))?;
    let nonce = parse_hex_u32(nonce_hex)
        .ok_or_else(|| PoolError::Protocol("merged: nonce not a hex u32".into()))?;
    let version = effective_version(job.btc_version as u32, version_bits);

    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&version.to_le_bytes());
    header[4..36].copy_from_slice(&job.btc_prev_hash);
    header[36..68].copy_from_slice(&merkle_root);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header[72..76].copy_from_slice(&job.btc_bits.to_le_bytes());
    header[76..80].copy_from_slice(&nonce.to_le_bytes());
    let hash = sha256d(&header);

    let meets_btc = meets(&hash, &bits_to_target(job.btc_bits), true);
    let meets_bloch = meets(&hash, &bits_to_target(job.bloch_bits), true);
    let meets_worker = meets(&hash, worker_target, true);

    let win = if meets_btc {
        MergedWin::BtcAndBloch
    } else if meets_bloch {
        MergedWin::Bloch
    } else if meets_worker {
        MergedWin::Share
    } else {
        MergedWin::Reject
    };

    // Any Bloch-target win yields the AuxPoW the node accepts: the solved parent
    // header + the exact coinbase the miner built + the job's coinbase branch.
    let auxpow_blob = matches!(win, MergedWin::BtcAndBloch | MergedWin::Bloch)
        .then(|| assemble_auxpow_for_win(&header, &coinbase, &job.merkle_branch));

    Ok(MergedClassification { win, hash, auxpow_blob })
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

    // Reconstruct the parent hash exactly as classify does — the test's own
    // oracle, so it can assert the tier logic without forcing a PoW solution.
    fn reconstruct_hash(job: &MergedJob, en2: &str, ntime: u32, nonce: u32) -> [u8; 32] {
        let mut coinbase = job.coinbase_prefix.clone();
        coinbase.extend_from_slice(&hex_to_bytes(en2).unwrap());
        coinbase.extend_from_slice(&job.coinbase_suffix);
        let root = walk_merkle_branch(sha256d(&coinbase), &job.merkle_branch);
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&(job.btc_version as u32).to_le_bytes());
        h[4..36].copy_from_slice(&job.btc_prev_hash);
        h[36..68].copy_from_slice(&root);
        h[68..72].copy_from_slice(&ntime.to_le_bytes());
        h[72..76].copy_from_slice(&job.btc_bits.to_le_bytes());
        h[76..80].copy_from_slice(&nonce.to_le_bytes());
        sha256d(&h)
    }

    fn sample_job(bloch_bits: u32, btc_bits: u32) -> MergedJob {
        build_merged_job(
            "7-5600-1a".into(),
            [0x9Au8; 32],
            bloch_bits,
            0x2000_0000,
            [0x22u8; 32],
            btc_bits,
            1_700_000_000,
            b"btc-cb-prefix",
            b"btc-cb-suffix",
            &[[1u8; 32], [2u8; 32]],
        )
    }

    #[test]
    fn notify_line_parses_back_to_the_same_job_fields() {
        let job = sample_job(0x20ff_ffff, 0x1a00_ffff);
        let line = merged_job_to_notify(&job, true);
        // The proxy's own notify parser round-trips it (same wire the node emits).
        let parsed = crate::jobstore::parse_notify_full(&line).expect("valid notify");
        assert_eq!(parsed.job_id, job.job_id);
        assert_eq!(parsed.version, job.btc_version as u32);
        assert_eq!(parsed.nbits, job.btc_bits);
        assert_eq!(parsed.coinb1, job.coinbase_prefix); // commitment carried in coinb1
        assert_eq!(parsed.coinb2, job.coinbase_suffix);
        assert_eq!(parsed.merkle_branch, job.merkle_branch);
        // prevhash: notify word-swaps for the wire; the parser un-swaps back.
        assert_eq!(parsed.prevhash_raw, job.btc_prev_hash);
        assert_eq!(parsed.height, 5600); // from the "sid-height-ctr" job_id
    }

    #[test]
    fn classify_agrees_with_primitive_meets_and_gates_the_blob() {
        // Bloch target loose, BTC target astronomically hard (never met here).
        let job = sample_job(0x20ff_ffff, 0x0300_0001);
        let (en1, en2, ntime_hex, nonce_hex) = ("", "deadbeef", "66000000", "00000000");
        let ntime = parse_hex_u32(ntime_hex).unwrap();
        let nonce = parse_hex_u32(nonce_hex).unwrap();
        let worker_target = bits_to_target(0x1d00_ffff); // diff-1

        let hash = reconstruct_hash(&job, en2, ntime, nonce);
        let exp_btc = meets(&hash, &bits_to_target(job.btc_bits), true);
        let exp_bloch = meets(&hash, &bits_to_target(job.bloch_bits), true);
        let exp_worker = meets(&hash, &worker_target, true);

        let c = classify_merged_share(&job, en1, en2, ntime_hex, nonce_hex, None, &worker_target)
            .expect("classifies");
        assert_eq!(c.hash, hash, "classify hashes the same header the oracle does");

        // The verdict is exactly the primitive ordering — no independent logic.
        let expected = if exp_btc {
            MergedWin::BtcAndBloch
        } else if exp_bloch {
            MergedWin::Bloch
        } else if exp_worker {
            MergedWin::Share
        } else {
            MergedWin::Reject
        };
        assert_eq!(c.win, expected);
        assert!(!exp_btc, "chosen BTC bits are unmeetable in this test");

        // The AuxPoW blob is present IFF a Bloch-target win, and when present it
        // carries the exact solved header (offset 4..84) — node-parseable.
        match c.win {
            MergedWin::Bloch | MergedWin::BtcAndBloch => {
                let blob = c.auxpow_blob.expect("bloch win → blob");
                // blob = 80u32(4) ‖ parent_header(80) ‖ … ; header = version(4) ‖ prev(32) …
                assert_eq!(&blob[0..4], &80u32.to_le_bytes());
                assert_eq!(&blob[4..8], &(job.btc_version as u32).to_le_bytes(), "parent version");
                assert_eq!(&blob[8..40], &job.btc_prev_hash[..], "parent header prev in blob");
            }
            _ => assert!(c.auxpow_blob.is_none(), "no win → no blob"),
        }
    }

    #[test]
    fn impossible_targets_reject_with_no_blob() {
        // Every target unmeetable (astronomically hard) + zero worker target →
        // Reject, no blob. sha256d is never all-zero, so this is deterministic.
        let job = sample_job(0x0300_0001, 0x0300_0001);
        let c = classify_merged_share(&job, "", "00", "66000000", "00000000", None, &[0u8; 32])
            .expect("classifies");
        assert_eq!(c.win, MergedWin::Reject);
        assert!(c.auxpow_blob.is_none());
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
