// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Sprint 10-delta Etapa 2: Template adapter for Stratum V2.
//
// V1 ships (coinb1, coinb2, merkle_branch) to the miner and lets the
// miner compute the merkle root locally. SV2 is different: the server
// must ship a *pre-computed* merkle root in NewMiningJob. So V2 has
// to perform locally what V1 offloaded to the miner.

use crate::core::Transaction;
use crate::stratum::{
    Template,
    TemplateContext,
    TipChanged,
    stratum_txid_of_bytes,
    walk_merkle_branch,
};

/// Compute the merkle root for a given channel's extranonce prefix,
/// exactly as a V1 miner would compute it from
/// `coinb1 || extranonce || coinb2` + `merkle_branch`.
pub fn compute_merkle_root_for_channel(
    template:          &Template,
    extranonce_prefix: &[u8; 8],
) -> [u8; 32] {
    let mut full = Vec::with_capacity(
        template.coinb1.len() + 8 + template.coinb2.len()
    );
    full.extend_from_slice(&template.coinb1);
    full.extend_from_slice(extranonce_prefix);
    full.extend_from_slice(&template.coinb2);

    let coinbase_txid = stratum_txid_of_bytes(&full);
    walk_merkle_branch(coinbase_txid, &template.merkle_branch)
}

/// Build a Template from a TipChanged event + TemplateContext,
/// for Stratum V2 session consumption.
pub fn build_template_for_sv2(
    tip:       &TipChanged,
    ctx:       &TemplateContext,
    miner_spk: &[u8],
    job_id:    String,
) -> Result<Template, TemplateBuildError> {
    let (height, blue_score) = {
        let d = ctx.dag.read();
        let data = d.get_block_data(&tip.hash)
            .ok_or(TemplateBuildError::TipDataMissing)?;
        (data.height + 1, data.blue_score + 1)
    };

    // Explicit `Vec<Transaction>` annotation + `for` loop removes any
    // closure-inference ambiguity that plagues the `.iter().map().sum()`
    // version in this module (works in V1 only because V1's session.rs
    // has a richer import environment).
    let other_txs: Vec<Transaction> = ctx.mempool.get_for_block(2000);
    let mut total_fees: u64 = 0;
    for tx in &other_txs {
        if let Some(entry) = ctx.mempool.get_entry(&tx.txid()) {
            total_fees = total_fees.saturating_add(entry.fee);
        }
    }

    // RETARGET-BOUNDARY FIX: `tip.bits` are the bits of the TIP block, but
    // the template is for the NEXT block (`height`). At a retarget boundary
    // the validator demands the retargeted bits — a template carrying the
    // stale tip bits is rejected ("invalid difficulty") on every window
    // boundary.
    //
    // FLAG-DAY core::DIFFICULTY_ANCESTRY_FORK_HEIGHT (gated inside the
    // function): expected bits are a pure function of the EXACT parent set
    // this template stamps (`tip.parents`) — the same slice, the same choke
    // point, accept_block uses on submit. Even if this TipChanged event is
    // stale by the time a share lands, the assembled block carries these
    // parents, so validator agreement is by construction. FAIL CLOSED when
    // the ancestry is unreadable: no template beats a doomed template.
    let bits = {
        let d = ctx.dag.read();
        crate::pow::genesis2_expected_bits_for_parents(&ctx.store, &d, &tip.parents, height)
            .map_err(|e| TemplateBuildError::BitsUnavailable(e.to_string()))?
    };

    Ok(Template::build(
        tip.parents.clone(),
        height,
        blue_score,
        bits,
        miner_spk,
        total_fees,
        other_txs,
        ctx.coinbase_tag.as_bytes(),
        job_id,
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateBuildError {
    #[error("tip block data missing from DAG — inconsistent state")]
    TipDataMissing,
    #[error("expected bits not derivable from parent ancestry (fail-closed): {0}")]
    BitsUnavailable(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_miner_spk(fill: u8) -> Vec<u8> {
        vec![fill; 20]
    }

    #[test]
    fn merkle_root_matches_v1_template_computation() {
        let miner_spk = dummy_miner_spk(0x42);
        let template = Template::build(
            vec![[1u8; 32], [2u8; 32]],
            100, 150, 0x1d00ffff,
            &miner_spk, 0, vec![],
            b"test-coinbase-tag", "job-1".to_string(),
        );
        let extranonce = [0xABu8; 8];

        let mut full = Vec::new();
        full.extend_from_slice(&template.coinb1);
        full.extend_from_slice(&extranonce);
        full.extend_from_slice(&template.coinb2);
        let cb_txid = stratum_txid_of_bytes(&full);
        let expected_root = walk_merkle_branch(cb_txid, &template.merkle_branch);

        let actual_root = compute_merkle_root_for_channel(&template, &extranonce);
        assert_eq!(actual_root, expected_root,
            "V2 adapter must produce byte-identical root to V1 computation");
    }

    #[test]
    fn different_extranonces_yield_different_roots() {
        let miner_spk = dummy_miner_spk(0x11);
        let template = Template::build(
            vec![[3u8; 32]],
            200, 250, 0x1d00ffff,
            &miner_spk, 0, vec![],
            b"tag", "job-2".to_string(),
        );
        let r1 = compute_merkle_root_for_channel(&template, &[0x00u8; 8]);
        let r2 = compute_merkle_root_for_channel(&template, &[0xFFu8; 8]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn empty_merkle_branch_returns_coinbase_txid() {
        let miner_spk = dummy_miner_spk(0x22);
        let template = Template::build(
            vec![[4u8; 32]],
            300, 350, 0x1d00ffff,
            &miner_spk, 0, vec![],
            b"tag", "job-3".to_string(),
        );
        assert!(template.merkle_branch.is_empty());

        let extranonce = [0x55u8; 8];
        let mut full = Vec::new();
        full.extend_from_slice(&template.coinb1);
        full.extend_from_slice(&extranonce);
        full.extend_from_slice(&template.coinb2);
        let expected_cb_txid = stratum_txid_of_bytes(&full);

        let actual_root = compute_merkle_root_for_channel(&template, &extranonce);
        assert_eq!(actual_root, expected_cb_txid);
    }
}
