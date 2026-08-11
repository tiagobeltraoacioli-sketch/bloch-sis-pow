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

/// Operator config for a merged-mining round. In an OPEN pool these two payout
/// fields are only the FALLBACK: a worker that declares its own addresses in the
/// Stratum username (see [`crate::addr::parse_worker_username`]) gets a round
/// built with [`MergedConfig::with_payout`], so its blocks pay itself and the
/// pool never custodies a reward.
#[derive(Clone, Debug)]
pub struct MergedConfig {
    /// Bloch payout address — the node's coinbase pays this (via `createauxblock`).
    pub pool_bloch_addr: String,
    /// The pool's Bitcoin coinbase output scriptPubKey (where BTC rewards go).
    pub btc_payout_script: Vec<u8>,
    /// Arbitrary tag bytes placed in the BTC coinbase scriptSig (attribution).
    pub coinbase_tag: Vec<u8>,
}

impl MergedConfig {
    /// This config with the payout targets replaced by one worker's own. A `None`
    /// BTC script keeps the operator's (the worker declared only a Bloch address).
    pub fn with_payout(&self, bloch_addr: &str, btc_script: Option<&[u8]>) -> Self {
        Self {
            pool_bloch_addr: bloch_addr.to_string(),
            btc_payout_script: btc_script
                .map(<[u8]>::to_vec)
                .unwrap_or_else(|| self.btc_payout_script.clone()),
            coinbase_tag: self.coinbase_tag.clone(),
        }
    }
}

/// One merged round: the two chains' work, plus the parent-BTC transactions the
/// header commits to (needed verbatim to relay a BTC-target win — the block body
/// must contain exactly the txs whose txids are in the job's merkle branch).
#[derive(Clone, Debug)]
pub struct MergedRound {
    pub aux: AuxBlockInfo,
    pub job: MergedJob,
    /// Raw (witness-carrying) serializations of the template's non-coinbase txs.
    pub btc_txs: Vec<Vec<u8>>,
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
/// `witness_commitment_spk` is the BIP141 `OP_RETURN aa21a9ed …` output script
/// (`default_witness_commitment` from `getblocktemplate`). It is REQUIRED on any
/// segwit-active chain: the relayed block carries the coinbase witness, and
/// bitcoind rejects a block with witness data whose coinbase does not commit to
/// it (`unexpected-witness`). Pass `None` only for a pre-segwit parent.
///
/// The serialization is the non-witness (txid) form — what the merkle tree and
/// the AuxPoW fold; [`crate::btc_block::build_segwit_block_hex`] adds the witness
/// to the relayed body only.
pub fn btc_coinbase_parts(
    height: u64,
    payout_script: &[u8],
    coinbase_value: u64,
    tag: &[u8],
    extranonce_len: usize,
    witness_commitment_spk: Option<&[u8]>,
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
    let vout_count = 1 + u64::from(witness_commitment_spk.is_some());
    suffix.extend_from_slice(&varint(vout_count)); // vout count
    suffix.extend_from_slice(&coinbase_value.to_le_bytes()); // output value
    suffix.extend_from_slice(&varint(payout_script.len() as u64)); // spk length
    suffix.extend_from_slice(payout_script); // payout scriptPubKey
    if let Some(wc) = witness_commitment_spk {
        // BIP141 commitment output — zero value, OP_RETURN.
        suffix.extend_from_slice(&0u64.to_le_bytes());
        suffix.extend_from_slice(&varint(wc.len() as u64));
        suffix.extend_from_slice(wc);
    }
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

/// Assemble the [`MergedJob`] for one round from the two templates. The coinbase
/// carries the template's `default_witness_commitment` when the parent is segwit
/// (bitcoind computes it over the template's tx set; the coinbase's own wtxid is
/// defined as all-zeros, so it does not depend on our coinbase bytes).
pub fn build_round_job(
    job_id: String,
    aux: &AuxBlockInfo,
    tmpl: &BtcTemplate,
    payout_script: &[u8],
    tag: &[u8],
    extranonce_len: usize,
) -> MergedJob {
    let wc = tmpl.default_witness_commitment.as_deref().and_then(|h| hex::decode(h).ok());
    let (prefix, suffix) = btc_coinbase_parts(
        tmpl.height,
        payout_script,
        tmpl.coinbase_value,
        tag,
        extranonce_len,
        wc.as_deref(),
    );
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
    /// A Bitcoin-target win that did NOT meet Bloch's target — relay the BTC
    /// block only. Sending this to `submitauxblock` would just earn an
    /// `InsufficientPow` (the common case on a regtest parent).
    Btc { auxpow_hex: String },
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
        MergedWin::Btc => match &c.auxpow_blob {
            Some(b) => SubmitAction::Btc { auxpow_hex: hex::encode(b) },
            None => SubmitAction::Share,
        },
        MergedWin::BtcAndBloch => match &c.auxpow_blob {
            Some(b) => SubmitAction::BtcAndBloch { auxpow_hex: hex::encode(b) },
            None => SubmitAction::Share,
        },
    }
}

/// Start a merged round: pull both templates and build the job to serve.
/// (Async orchestration; the pure build is [`build_round_job`].)
pub async fn create_round(
    node: &RpcClient,
    btc: &BtcRpcClient,
    cfg: &MergedConfig,
    job_id: String,
    extranonce_len: usize,
) -> Result<MergedRound, PoolError> {
    // `cfg` here is already the WORKER's effective config, so the node builds a
    // candidate whose coinbase pays that worker's Bloch address.
    let aux = node.create_aux_block(&cfg.pool_bloch_addr).await?;
    let tmpl = btc.get_block_template().await?;
    let job = build_round_job(job_id, &aux, &tmpl, &cfg.btc_payout_script, &cfg.coinbase_tag, extranonce_len);
    let btc_txs = tmpl.transactions.iter().map(|(_, raw)| raw.clone()).collect();
    Ok(MergedRound { aux, job, btc_txs })
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
    btc_txs: &[Vec<u8>],
) -> Result<Option<String>, PoolError> {
    match action {
        SubmitAction::Bloch { auxpow_hex } => Ok(Some(node.submit_aux_block(aux_hash, auxpow_hex).await?)),
        SubmitAction::Btc { auxpow_hex } => {
            relay_btc(btc, auxpow_hex, btc_txs).await;
            Ok(None)
        }
        SubmitAction::BtcAndBloch { auxpow_hex } => {
            // Bloch side first (authoritative), then the BTC relay regardless of
            // what the node said — the two chains' acceptances are independent.
            let bloch = node.submit_aux_block(aux_hash, auxpow_hex).await;
            relay_btc(btc, auxpow_hex, btc_txs).await;
            Ok(Some(bloch?))
        }
        SubmitAction::Share | SubmitAction::Nothing => Ok(None),
    }
}

/// Best-effort relay of a BTC-target win, rebuilt from the same blob handed to
/// the node: parent header + the exact coinbase the miner hashed + the template's
/// transactions (the header's merkle root commits to ALL of them, so the body
/// must carry them verbatim — relaying only the coinbase would be
/// `bad-txnmrklroot`).
async fn relay_btc(btc: &BtcRpcClient, auxpow_hex: &str, btc_txs: &[Vec<u8>]) {
    let Ok(blob) = hex::decode(auxpow_hex) else { return };
    let Some((_hash, header, coinbase)) = crate::btc_block::header_and_coinbase_from_auxpow(&blob)
    else {
        return;
    };
    // BIP144 segwit block: the coinbase carries its witness (the all-zero
    // reserved value), which bitcoind checks against the witness-commitment
    // output `btc_coinbase_parts` put in that same coinbase.
    let block_hex =
        crate::btc_block::build_segwit_block_hex(&header, &coinbase, &[0u8; 32], btc_txs)
            .unwrap_or_else(|| crate::btc_block::build_block_hex(&header, &coinbase, btc_txs));
    match btc.submit_block(&block_hex).await {
        Ok(None) => log::info!("merged: BTC block relayed to bitcoind ({} txs)", btc_txs.len() + 1),
        Ok(Some(reason)) => log::warn!("merged: bitcoind rejected BTC block: {reason}"),
        Err(e) => log::warn!("merged: submitblock failed: {e}"),
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
        let (prefix, suffix) = btc_coinbase_parts(5_600, &payout, 625_000_000, tag, en_len, None);

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

    /// The regression for `unexpected-witness`: on a segwit parent the coinbase
    /// MUST carry the BIP141 commitment output, because the relayed block body
    /// carries the coinbase witness. Two outputs, the second an OP_RETURN
    /// aa21a9ed of zero value.
    #[test]
    fn segwit_parent_coinbase_carries_the_witness_commitment_output() {
        let payout = crate::addr::btc_address_to_spk("bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk").unwrap();
        let wc = crate::btc_block::witness_commitment_spk(&[]); // empty block
        let (prefix, suffix) = btc_coinbase_parts(5_600, &payout, 625_000_000, b"tag", 8, Some(&wc));

        let mut cb = prefix;
        cb.extend_from_slice(&crate::mergedmining::merge_mining_commitment([0x9A; 32]));
        cb.extend_from_slice(&[0u8; 8]);
        cb.extend_from_slice(&suffix);

        let ss_len = cb[41] as usize;
        let tail = &cb[42 + ss_len..];
        assert_eq!(&tail[0..4], &0xffff_ffffu32.to_le_bytes()); // sequence
        assert_eq!(tail[4], 0x02, "two outputs: payout + witness commitment");
        // out0: value ‖ len ‖ payout spk
        assert_eq!(&tail[5..13], &625_000_000u64.to_le_bytes());
        assert_eq!(tail[13] as usize, payout.len());
        assert_eq!(&tail[14..14 + payout.len()], &payout[..]);
        // out1: zero value ‖ len ‖ OP_RETURN commitment
        let o1 = 14 + payout.len();
        assert_eq!(&tail[o1..o1 + 8], &0u64.to_le_bytes(), "commitment output pays nothing");
        assert_eq!(tail[o1 + 8] as usize, wc.len());
        assert_eq!(&tail[o1 + 9..o1 + 9 + wc.len()], &wc[..]);
        assert_eq!(&tail[tail.len() - 4..], &0u32.to_le_bytes()); // locktime
    }

    /// The template's `default_witness_commitment` must reach the coinbase — the
    /// live bug was a job built without it, so every relayed block was rejected.
    #[test]
    fn build_round_job_threads_the_template_witness_commitment() {
        let aux = AuxBlockInfo { hash: [0x9A; 32], bits: 0x20ff_ffff, height: 5_600, active: true };
        let wc = crate::btc_block::witness_commitment_spk(&[]);
        let mut tmpl = sample_template();
        tmpl.default_witness_commitment = Some(hex::encode(&wc));
        let job = build_round_job("m1".into(), &aux, &tmpl, &[0x51], b"tag", 8);
        assert!(
            job.coinbase_suffix.windows(wc.len()).any(|w| w == wc.as_slice()),
            "coinbase suffix must contain the template's witness commitment"
        );
        // Without it (pre-segwit parent) the coinbase stays single-output.
        let job2 = build_round_job("m2".into(), &aux, &sample_template(), &[0x51], b"tag", 8);
        assert!(!job2.coinbase_suffix.windows(6).any(|w| w == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]));
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
            MergedWin::Btc => assert!(matches!(action, SubmitAction::Btc { .. })),
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
        }
    }

    #[test]
    fn decide_submit_maps_every_verdict() {
        let mk = |win, blob: Option<Vec<u8>>| MergedClassification { win, hash: [0; 32], auxpow_blob: blob };
        assert_eq!(decide_submit(&mk(MergedWin::Reject, None)), SubmitAction::Nothing);
        assert_eq!(decide_submit(&mk(MergedWin::Share, None)), SubmitAction::Share);
        // A BTC-only win must NOT reach submitauxblock (that is InsufficientPow).
        assert_eq!(
            decide_submit(&mk(MergedWin::Btc, Some(vec![0xbb]))),
            SubmitAction::Btc { auxpow_hex: "bb".into() }
        );
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
