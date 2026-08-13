//! Merged-mining engine — ties the two chains' RPCs to the producers in
//! [`crate::mergedmining`], closing the pool→node loop:
//!
//!   1. [`RpcClient::create_aux_block`] → the candidate Bloch block to commit;
//!   2. [`BtcRpcClient::get_block_template`] → the parent Bitcoin template;
//!   3. [`build_round_job`] embeds the commitment in a parent BTC coinbase and
//!      returns a [`MergedJob`] the proxy serves over Stratum (the miner is
//!      unchanged — it hashes a normal Bitcoin header);
//!   4. on a share, [`crate::mergedmining::classify_merged_share`] +
//!      [`decide_submit`] pick the submit(s): a Bloch-target win →
//!      [`RpcClient::submit_aux_block`]; a BTC-target win ALSO → `bitcoind`
//!      `submitblock` (the full BTC-block assembly for that rarer path is a
//!      documented scaffold).
//!
//! The pure pieces (coinbase splice, job build, submit decision) are unit
//! tested; the async fns are thin orchestration over the two clients. The proxy
//! keeps its ZERO dependency on bloch-crypto — the AuxPoW format lives in
//! `mergedmining`, verbatim-matched to the node.

use crate::btc_rpc::{BtcRpcClient, BtcTemplate};
use crate::mergedmining::{build_merged_job, MergedClassification, MergedJob, MergedWin};
use crate::rpc::{AuxBlockInfo, RpcClient};
use crate::types::PoolError;

/// Operator config for a merged-mining round.
#[derive(Clone, Debug)]
pub struct MergedConfig {
    /// Bloch payout address — the node's coinbase pays this (via `createauxblock`).
    pub pool_bloch_addr: String,
    /// The pool's Bitcoin coinbase output scriptPubKey (where BTC rewards go).
    pub btc_payout_script: Vec<u8>,
    /// Arbitrary tag bytes placed in the BTC coinbase scriptSig (attribution).
    pub coinbase_tag: Vec<u8>,
}

/// Encode `height` as a BIP34 coinbase scriptSig prefix: a length-prefixed,
/// minimally-encoded little-endian script number. bitcoind requires the
/// coinbase scriptSig to begin with this.
fn bip34_height_push(height: u64) -> Vec<u8> {
    if height == 0 {
        return vec![0x00];
    }
    let mut le = Vec::new();
    let mut h = height;
    while h > 0 {
        le.push((h & 0xff) as u8);
        h >>= 8;
    }
    // If the MSB's high bit is set, append 0x00 so the value stays positive.
    if le.last().is_some_and(|b| b & 0x80 != 0) {
        le.push(0x00);
    }
    let mut out = Vec::with_capacity(le.len() + 1);
    out.push(le.len() as u8);
    out.extend_from_slice(&le);
    out
}

/// Bitcoin varint (CompactSize). Coinbase counts here are always < 0xfd, but
/// keep the full encoding so a large scriptSig/output count never mis-serializes.
fn varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// Build the parent-Bitcoin coinbase split around the miner's extranonce, ready
/// for [`build_merged_job`] (which appends the 44-byte merge-mining commitment
/// to the returned prefix). Layout of the full coinbase the miner assembles:
///
/// ```text
///   version(4) ‖ vin=1 ‖ prevout(null) ‖ scriptSig_len ‖
///     bip34_height ‖ tag ‖ [commitment(44)] ‖ [extranonce] ‖   ← scriptSig
///   sequence(4) ‖ vout=1 ‖ [value(8) ‖ spk_len ‖ payout_spk] ‖ locktime(4)
/// ```
///
/// `scriptSig_len` is pre-sized to include the commitment + extranonce, so the
/// tx stays well-formed once the miner fills the extranonce. Returns
/// `(prefix_without_commitment, suffix)`.
///
/// NOTE (scaffold): a single payout output, non-segwit serialization (the txid
/// the merkle tree uses). For the RARE BTC-target win that must be relayed to
/// bitcoind as a full block, the pool additionally needs the segwit witness
/// commitment output — see [`decide_submit`].
pub fn btc_coinbase_parts(
    height: u64,
    payout_script: &[u8],
    coinbase_value: u64,
    tag: &[u8],
    extranonce_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    const COMMITMENT_LEN: usize = 44; // fabe6d6d ‖ hash(32) ‖ size(4) ‖ nonce(4)
    let height_push = bip34_height_push(height);
    let script_sig_len = height_push.len() + tag.len() + COMMITMENT_LEN + extranonce_len;

    let mut prefix = Vec::new();
    prefix.extend_from_slice(&2i32.to_le_bytes()); // version 2
    prefix.extend_from_slice(&varint(1)); // vin count
    prefix.extend_from_slice(&[0u8; 32]); // prevout hash (null)
    prefix.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // prevout index
    prefix.extend_from_slice(&varint(script_sig_len as u64)); // scriptSig length
    prefix.extend_from_slice(&height_push); // BIP34 height
    prefix.extend_from_slice(tag); // attribution tag
    // build_merged_job appends the 44-byte commitment here; extranonce follows.

    let mut suffix = Vec::new();
    suffix.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    suffix.extend_from_slice(&varint(1)); // vout count
    suffix.extend_from_slice(&coinbase_value.to_le_bytes()); // output value
    suffix.extend_from_slice(&varint(payout_script.len() as u64)); // spk length
    suffix.extend_from_slice(payout_script); // payout scriptPubKey
    suffix.extend_from_slice(&0u32.to_le_bytes()); // locktime

    (prefix, suffix)
}

/// Decode a 32-byte hex txid in Bitcoin DISPLAY order (big-endian) into the
/// internal little-endian order the merkle tree uses.
fn hex32_reversed(s: &str) -> Option<[u8; 32]> {
    let mut b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    b.reverse();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Some(a)
}

/// Assemble the [`MergedJob`] for one round from the two templates.
pub fn build_round_job(
    job_id: String,
    aux: &AuxBlockInfo,
    tmpl: &BtcTemplate,
    payout_script: &[u8],
    tag: &[u8],
    extranonce_len: usize,
) -> MergedJob {
    let (prefix, suffix) =
        btc_coinbase_parts(tmpl.height, payout_script, tmpl.coinbase_value, tag, extranonce_len);
    let other_txids: Vec<[u8; 32]> = tmpl
        .transactions
        .iter()
        .filter_map(|(txid, _)| hex32_reversed(txid))
        .collect();
    build_merged_job(
        job_id,
        aux.hash,
        aux.bits,
        tmpl.version,
        tmpl.previous_block_hash,
        tmpl.bits,
        tmpl.cur_time,
        &prefix,
        &suffix,
        &other_txids,
    )
}

/// The submit(s) a classified share triggers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitAction {
    /// Below the worker target — nothing to do.
    Nothing,
    /// A valid share (worker target) — accounting only.
    Share,
    /// A Bloch-target win — submit the AuxPoW to the node.
    Bloch { auxpow_hex: String },
    /// A Bitcoin-target win — submit the AuxPoW to the node AND (scaffold) the
    /// full BTC block to bitcoind.
    BtcAndBloch { auxpow_hex: String },
}

/// Map a classification to the submit action, hex-encoding the AuxPoW blob for
/// any Bloch-target win.
pub fn decide_submit(c: &MergedClassification) -> SubmitAction {
    match c.win {
        MergedWin::Reject => SubmitAction::Nothing,
        MergedWin::Share => SubmitAction::Share,
        MergedWin::Bloch => match &c.auxpow_blob {
            Some(b) => SubmitAction::Bloch { auxpow_hex: hex::encode(b) },
            None => SubmitAction::Share, // defensive: no blob → treat as a share
        },
        MergedWin::BtcAndBloch => match &c.auxpow_blob {
            Some(b) => SubmitAction::BtcAndBloch { auxpow_hex: hex::encode(b) },
            None => SubmitAction::Share,
        },
        // RECONSTRUCTED 2026-08-13, and not the original. This arm existed
        // only in an uncommitted working tree that was destroyed; what it did
        // is not recoverable, so this is the most conservative reading of the
        // variant's own documentation: meets Bitcoin's target but NOT Bloch's.
        //
        // Counted as a share, and nothing is submitted to the Bloch node —
        // the safe direction, because a BTC-only win is by definition not a
        // Bloch block and submitting one would be wrong. Any BTC relay this
        // arm may once have performed is NOT wired here.
        //
        // Reachability bounds the cost: on mainnet Bitcoin's target is orders
        // of magnitude harder than Bloch's, so meeting it implies meeting
        // Bloch's and this arm is unreachable. On regtest it is the common
        // case, so rehearsals lose the BTC relay until this is rebuilt
        // deliberately.
        MergedWin::Btc => SubmitAction::Share,
    }
}


/// The two upstream templates, shared by every worker.
///
/// # Why this exists
///
/// The templates are a property of the chain tip, not of who is asking: at any
/// moment there is one candidate Bloch block and one Bitcoin template, and
/// every connected miner should be working on them. This serve path used to
/// pull both **per connection** — each worker owned an `RpcClient` and its own
/// refresh ticker — so N miners meant N independent `createauxblock` calls per
/// refresh interval, each opening a fresh TCP connection because the RPC
/// client sends `Connection: close`.
///
/// Fine with two miners, collapses with twenty. On 2026-08-13 the live pool
/// held 88 concurrent RPC connections against a two-core node, every call
/// timed out at 10 s, no worker received a job, and a 100+ TH/s ASIC sat idle
/// waiting for work the node was answering in 34 ms when asked once. The node
/// was never the problem; the fan-out was.
pub struct TemplateCache {
    inner: tokio::sync::Mutex<Option<(std::time::Instant, AuxBlockInfo, BtcTemplate)>>,
}

impl Default for TemplateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateCache {
    pub fn new() -> Self {
        Self { inner: tokio::sync::Mutex::new(None) }
    }

    /// Templates no older than `ttl`, fetching once if cold or stale.
    ///
    /// The freshness re-check after taking the lock is what does the work:
    /// callers queued behind an in-flight fetch find it already satisfied and
    /// return it, turning N simultaneous refreshes into one upstream call.
    pub async fn get(
        &self,
        node: &RpcClient,
        btc: &BtcRpcClient,
        cfg: &MergedConfig,
        ttl: std::time::Duration,
    ) -> Result<(AuxBlockInfo, BtcTemplate), PoolError> {
        let mut slot = self.inner.lock().await;
        if let Some((at, aux, tmpl)) = slot.as_ref() {
            if at.elapsed() < ttl {
                return Ok((aux.clone(), tmpl.clone()));
            }
        }
        // The lock is held across the fetch on purpose: serialising upstream
        // calls is the entire point. A failed fetch leaves the previous entry
        // in place, so a transient node error costs one stale round rather
        // than starting a stampede.
        let aux = node.create_aux_block(&cfg.pool_bloch_addr).await?;
        let tmpl = btc.get_block_template().await?;
        *slot = Some((std::time::Instant::now(), aux.clone(), tmpl.clone()));
        Ok((aux, tmpl))
    }
}

/// Start a merged round: take the shared templates and build this worker's job.
///
/// `job_id` and the extranonce stay per-worker — two miners must never search
/// the same space — while the templates under them are shared. That split is
/// the design: what is common to the tip is fetched once, what must differ per
/// miner is built per miner.
pub async fn create_round(
    node: &RpcClient,
    btc: &BtcRpcClient,
    cfg: &MergedConfig,
    cache: &TemplateCache,
    ttl: std::time::Duration,
    job_id: String,
    extranonce_len: usize,
) -> Result<(AuxBlockInfo, MergedJob), PoolError> {
    let (aux, tmpl) = cache.get(node, btc, cfg, ttl).await?;
    let job = build_round_job(job_id, &aux, &tmpl, &cfg.btc_payout_script, &cfg.coinbase_tag, extranonce_len);
    Ok((aux, job))
}

/// Perform the submit(s) for a classified win. Returns the node's accepted block
/// hash on a Bloch-target win, else `None`.
///
/// The Bloch side (`submitauxblock`) is the point and is authoritative. For a
/// `BtcAndBloch` win the parent header also met Bitcoin's target, so the block
/// is worth relaying to `bitcoind` — assembled from the SAME AuxPoW blob (parent
/// header + coinbase) via the vector-tested [`crate::btc_block`] and submitted
/// best-effort. A block carrying mempool txs needs those txs' raw bytes + the
/// segwit witness wrapper (a live-`bitcoind` sign-off item); the Bloch
/// acceptance never depends on the relay, so a rejected relay is only logged.
pub async fn submit_win(
    node: &RpcClient,
    btc: &BtcRpcClient,
    aux_hash: &[u8; 32],
    action: &SubmitAction,
) -> Result<Option<String>, PoolError> {
    match action {
        SubmitAction::Bloch { auxpow_hex } => Ok(Some(node.submit_aux_block(aux_hash, auxpow_hex).await?)),
        SubmitAction::BtcAndBloch { auxpow_hex } => {
            // Bloch side first (authoritative).
            let h = node.submit_aux_block(aux_hash, auxpow_hex).await?;
            // BTC side (best-effort relay) — reconstruct the block from the blob.
            if let Ok(blob) = hex::decode(auxpow_hex) {
                if let Some((_hash, header, coinbase)) =
                    crate::btc_block::header_and_coinbase_from_auxpow(&blob)
                {
                    // BIP144 segwit block: the coinbase carries its witness (the
                    // all-zero reserved value) so bitcoind can verify the witness
                    // commitment. Empty-block relay (no mempool txs); a non-empty
                    // relay would pass the template's raw txs as `other_txs`.
                    let block_hex = crate::btc_block::build_segwit_block_hex(&header, &coinbase, &[0u8; 32], &[])
                        .unwrap_or_else(|| crate::btc_block::build_block_hex(&header, &coinbase, &[]));
                    match btc.submit_block(&block_hex).await {
                        Ok(None) => log::info!("merged: BTC block relayed to bitcoind"),
                        Ok(Some(reason)) => log::warn!("merged: bitcoind rejected BTC block: {reason}"),
                        Err(e) => log::warn!("merged: submitblock failed: {e}"),
                    }
                }
            }
            Ok(Some(h))
        }
        SubmitAction::Share | SubmitAction::Nothing => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mergedmining::{classify_merged_share, MergedClassification, MergedWin};
    use crate::validator::bits_to_target;

    fn sample_template() -> BtcTemplate {
        BtcTemplate {
            previous_block_hash: [0x33u8; 32],
            version: 0x2000_0000,
            bits: 0x0300_0001,      // astronomically hard — no BTC win in tests
            cur_time: 1_700_000_000,
            height: 5_600,
            coinbase_value: 625_000_000,
            transactions: vec![],   // regtest empty block (common path)
            default_witness_commitment: None,
        }
    }

    #[test]
    fn coinbase_parts_form_a_wellformed_bitcoin_coinbase() {
        let payout = vec![0x76, 0xa9, 0x14]; // stub P2PKH prefix
        let tag = b"bloch/pool";
        let en_len = 8;
        let (prefix, suffix) = btc_coinbase_parts(5_600, &payout, 625_000_000, tag, en_len);

        // Reassemble the coinbase the miner would: prefix ‖ commitment(44) ‖ en ‖ suffix.
        let commitment = crate::mergedmining::merge_mining_commitment([0x9A; 32]);
        assert_eq!(commitment.len(), 44);
        let mut cb = prefix.clone();
        cb.extend_from_slice(&commitment);
        cb.extend_from_slice(&[0u8; 8]); // extranonce
        cb.extend_from_slice(&suffix);

        // version(4) ‖ vin(1)=01 ‖ prevout null(36) ‖ scriptSig_len(1) ‖ scriptSig …
        assert_eq!(&cb[0..4], &2i32.to_le_bytes());
        assert_eq!(cb[4], 0x01); // vin count
        assert_eq!(&cb[5..37], &[0u8; 32]); // prevout hash
        assert_eq!(&cb[37..41], &0xffff_ffffu32.to_le_bytes()); // prevout index
        let ss_len = cb[41] as usize; // single-byte varint (well under 0xfd)
        let ss_start = 42;
        // scriptSig actually spans height ‖ tag ‖ commitment ‖ extranonce.
        let height_push = bip34_height_push(5_600);
        let expect_ss_len = height_push.len() + tag.len() + 44 + en_len;
        assert_eq!(ss_len, expect_ss_len, "scriptSig length must cover commitment+extranonce");
        // BIP34: scriptSig begins with the height push.
        assert_eq!(&cb[ss_start..ss_start + height_push.len()], &height_push[..]);
        // The commitment appears exactly once in the coinbase.
        let occurrences = cb.windows(4).filter(|w| *w == [0xfa, 0xbe, 0x6d, 0x6d]).count();
        assert_eq!(occurrences, 1);
        // sequence ‖ vout=1 ‖ value ‖ spk_len ‖ spk ‖ locktime tail is intact.
        let tail = &cb[ss_start + ss_len..];
        assert_eq!(&tail[0..4], &0xffff_ffffu32.to_le_bytes()); // sequence
        assert_eq!(tail[4], 0x01); // vout count
        assert_eq!(&tail[tail.len() - 4..], &0u32.to_le_bytes()); // locktime
    }

    #[test]
    fn build_round_job_produces_a_serveable_committed_job() {
        let aux = AuxBlockInfo { hash: [0x9A; 32], bits: 0x20ff_ffff, height: 5_600, active: true };
        let tmpl = sample_template();
        let job = build_round_job("aux-5600".into(), &aux, &tmpl, &[0x51], b"tag", 8);

        // Commitment to the Bloch hash sits in the fixed (pre-extranonce) prefix.
        let pos = job.coinbase_prefix.windows(4).position(|w| w == [0xfa, 0xbe, 0x6d, 0x6d]).unwrap();
        assert_eq!(&job.coinbase_prefix[pos + 4..pos + 36], &aux.hash);
        // Parent fields carried from the BTC template.
        assert_eq!(job.btc_prev_hash, tmpl.previous_block_hash);
        assert_eq!(job.btc_bits, tmpl.bits);
        assert_eq!(job.bloch_bits, aux.bits);
        // Empty BTC block → no other txs → empty coinbase branch.
        assert!(job.merkle_branch.is_empty());
    }

    #[test]
    fn round_trip_engine_bloch_win_yields_node_ready_action() {
        // Loose Bloch target so the reconstructed share is a Bloch win; hard BTC.
        let aux = AuxBlockInfo { hash: [0x9A; 32], bits: 0x20ff_ffff, height: 5_600, active: true };
        let job = build_round_job("aux-5600".into(), &aux, &sample_template(), &[0x51], b"tag", 8);

        let c: MergedClassification =
            classify_merged_share(&job, "", "deadbeef", "66000000", "00000000", None, &bits_to_target(0x1d00_ffff))
                .expect("classifies");
        let action = decide_submit(&c);
        match c.win {
            MergedWin::Bloch | MergedWin::BtcAndBloch => {
                // A win → a node-ready AuxPoW hex the submit_win path forwards.
                let hex = match &action {
                    SubmitAction::Bloch { auxpow_hex } | SubmitAction::BtcAndBloch { auxpow_hex } => auxpow_hex.clone(),
                    other => panic!("win must map to a submit action, got {other:?}"),
                };
                assert!(!hex.is_empty());
                assert!(hex::decode(&hex).is_ok(), "auxpow hex decodes");
            }
            MergedWin::Share => assert_eq!(action, SubmitAction::Share),
            MergedWin::Reject => assert_eq!(action, SubmitAction::Nothing),
            // Matches the reconstructed arm in `decide_submit`: a BTC-only win
            // is counted as a share and nothing goes to the Bloch node. This
            // asserts the safe property rather than the original behaviour,
            // which was lost with the working tree it lived in.
            MergedWin::Btc => assert_eq!(action, SubmitAction::Share),
        }
    }

    #[test]
    fn decide_submit_maps_every_verdict() {
        let mk = |win, blob: Option<Vec<u8>>| MergedClassification { win, hash: [0; 32], auxpow_blob: blob };
        assert_eq!(decide_submit(&mk(MergedWin::Reject, None)), SubmitAction::Nothing);
        assert_eq!(decide_submit(&mk(MergedWin::Share, None)), SubmitAction::Share);
        assert_eq!(
            decide_submit(&mk(MergedWin::Bloch, Some(vec![1, 2, 3]))),
            SubmitAction::Bloch { auxpow_hex: "010203".into() }
        );
        assert_eq!(
            decide_submit(&mk(MergedWin::BtcAndBloch, Some(vec![0xaa]))),
            SubmitAction::BtcAndBloch { auxpow_hex: "aa".into() }
        );
    }
}
