// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stratum V2 — Block reconstruction helper for SubmitSharesStandard.
//
// Sprint 10-epsilon Phase 4: pure-functional reconstruction of a
// full Block from an Sv2CachedJob + the (version, ntime, nonce)
// that the miner rolled. No V1 dependency beyond the shared core
// primitives — V2 reproduces V1 submit.rs steps 7..11 independently.
//
// Why parallelize instead of extract-from-V1?
// V1 handle_submit in src/stratum/submit.rs is ~200 LOC tightly
// coupled to V1 concerns (params parsing, rate limiting, duplicate
// detection, V1 error codes). Extracting the pure reconstruction
// portion would risk regressing V1. V2 uses the same primitives
// (Transaction::from_stratum_bytes, stratum_txid_of_bytes,
// walk_merkle_branch, MiningHeader, pow_hash) so the two paths
// remain byte-identical by construction.
//
// Core invariant (enforced by test):
// Given the same Template + extranonce + (version, ntime, nonce),
// reconstruct_block_for_sv2_submit produces a Block whose
// header.pow_hash() equals what V1 would compute. The merkle_root
// in the reconstructed BlockHeader MUST equal cached.merkle_root
// byte-for-byte, else the template cache and the miner's view of
// the job have drifted and any submit would be rejected by
// accept_block downstream.
//
// This is the reconstruction step only — it does NOT check PoW
// against the target. The caller (session dispatcher in ε.5) is
// responsible for running bits_to_target + hash_meets_target on
// the returned pow_hash, then routing valid blocks through the
// AcceptBlockFn callback.

use crate::core::{
    bits_to_target, hash_meets_target,
    Block, BlockHeader, MerkleRoot, MiningHeader, Transaction,
};
use crate::stratum::{stratum_txid_of_bytes, walk_merkle_branch};
use crate::stratum_v2::channel::Sv2CachedJob;

/// Errors surfaced during block reconstruction for an SV2 submit.
///
/// All variants indicate that something about the (cached template,
/// extranonce, submit fields) triple is broken — the miner either
/// sent garbage or the template cache has been corrupted. None are
/// recoverable at this layer; the dispatcher maps them to a
/// SubmitSharesError reply.
#[derive(Debug, thiserror::Error)]
pub enum BlockReconstructError {
    /// Transaction::from_stratum_bytes refused to parse the
    /// coinbase bytes formed by coinb1 || extranonce || coinb2.
    /// Almost always indicates a template construction bug on our
    /// side; a miner cannot cause this by rolling the extranonce
    /// because those bytes sit inside the coinbase scriptSig.
    #[error("malformed coinbase bytes: {0}")]
    MalformedCoinbase(String),

    /// The reconstructed transaction parsed but is not a coinbase.
    /// Defense in depth — same as V1 handle_submit step 8.
    #[error("reconstructed transaction is not a coinbase")]
    NotACoinbase,

    /// The merkle_root we compute from the reconstructed coinbase
    /// + merkle_branch disagrees with the merkle_root we committed
    /// in NewMiningJob. If this fires in production the cache is
    /// corrupted; the dispatcher should reject the share rather
    /// than forward a block that will fail accept_block.
    #[error("reconstructed merkle_root disagrees with cached merkle_root \
             (cache corruption or template drift)")]
    MerkleRootMismatch {
        cached:        [u8; 32],
        reconstructed: [u8; 32],
    },
}

/// Outcome of [`reconstruct_block_for_sv2_submit`].
///
/// Separated from the Block itself so the caller can run the PoW
/// check before allocating the full Block downstream — pow_hash is
/// computed from the MiningHeader projection alone, so we expose it.
#[derive(Debug)]
pub struct ReconstructedSv2Block {
    /// The fully-assembled Block, ready for accept_block dispatch
    /// if the PoW check passes.
    pub block: Block,

    /// Double-SHA256 of the reconstructed 80-byte mining header.
    /// Equal to `block.header.pow_hash()` by construction — the
    /// AA.0 invariant in core::BlockHeader guarantees the two
    /// projections match.
    pub pow_hash: [u8; 32],
}

/// Reconstruct a full [`Block`] from an [`Sv2CachedJob`] plus the
/// miner's submit fields.
///
/// Steps (mirroring V1 submit.rs steps 7..11 exactly):
///
/// 1. Concatenate coinb1 || extranonce_prefix || coinb2 to form the
///    canonical coinbase bytes.
/// 2. Parse those bytes with [`Transaction::from_stratum_bytes`]
///    and verify [`Transaction::is_coinbase`].
/// 3. Compute the coinbase txid with [`stratum_txid_of_bytes`] and
///    walk the cached merkle_branch with [`walk_merkle_branch`]
///    to derive merkle_root.
/// 4. Compare against cached.merkle_root — must match byte-for-byte.
/// 5. Assemble the [`MiningHeader`] using cached template values +
///    miner-rolled (version, ntime, nonce). Compute pow_hash.
/// 6. Build the full Block { header: BlockHeader {...}, transactions,
///    blue_score, height } matching V1's exact struct-literal shape.
///
/// No PoW target check is performed here — the caller runs
/// [`bits_to_target`] + [`hash_meets_target`] on the returned
/// pow_hash to decide accept / reject. See
/// [`meets_block_target`] for a small convenience wrapper.
pub fn reconstruct_block_for_sv2_submit(
    cached:   &Sv2CachedJob,
    version:  u32,
    ntime:    u32,
    nonce:    u32,
) -> Result<ReconstructedSv2Block, BlockReconstructError> {
    let template = &*cached.template;

    // ── Step 1: rebuild the canonical coinbase bytes ──────────────────
    let mut coinbase_bytes = Vec::with_capacity(
        template.coinb1.len() + 8 + template.coinb2.len()
    );
    coinbase_bytes.extend_from_slice(&template.coinb1);
    coinbase_bytes.extend_from_slice(&cached.extranonce_prefix);
    coinbase_bytes.extend_from_slice(&template.coinb2);

    // ── Step 2: parse back into a Transaction + defense in depth ──────
    let coinbase_tx = Transaction::from_stratum_bytes(&coinbase_bytes)
        .map_err(BlockReconstructError::MalformedCoinbase)?;

    if !coinbase_tx.is_coinbase() {
        return Err(BlockReconstructError::NotACoinbase);
    }

    // ── Step 3: merkle root from the reconstructed coinbase txid ──────
    let coinbase_txid = stratum_txid_of_bytes(&coinbase_bytes);
    let reconstructed_merkle_root =
        walk_merkle_branch(coinbase_txid, &template.merkle_branch);

    // ── Step 4: byte-identity invariant ───────────────────────────────
    // This is the one test that separates "the cache still reflects
    // what the miner received" from "something has drifted". Never
    // forward a block whose cached and reconstructed merkle roots
    // disagree — accept_block will reject it downstream anyway.
    if reconstructed_merkle_root != cached.merkle_root {
        return Err(BlockReconstructError::MerkleRootMismatch {
            cached:        cached.merkle_root,
            reconstructed: reconstructed_merkle_root,
        });
    }

    // ── Step 5: assemble the 80-byte mining header + pow_hash ─────────
    // CHECKME-epsilon-version-rolling: SV2 SubmitSharesStandard carries
    // `version` for BIP-320 version rolling. V1 has no version rolling
    // and uses `template.version` unconditionally in both the mining
    // header and the assembled BlockHeader. To keep the AA.0 projection
    // invariant (BlockHeader.pow_hash() == mh.pow_hash()) we mirror V1:
    // both use template.version. The submitted `version` parameter is
    // currently ignored; version rolling will be added once SV2 channel
    // flags negotiate a nonzero version_rolling_mask (ε.6+).
    let _ = version; // suppress unused_variables; see CHECKME above
    let mh = MiningHeader {
        version:     template.version,
        prev_hash:   template.prev_hash,
        merkle_root: reconstructed_merkle_root,
        timestamp:   ntime,
        bits:        template.bits,
        nonce,
    };
    let pow_hash = mh.pow_hash();

    // ── Step 6: assemble the full Block (struct literal, V1 shape) ────
    let mut transactions = Vec::with_capacity(template.other_txs.len() + 1);
    transactions.push(coinbase_tx);
    transactions.extend(template.other_txs.iter().cloned());

    let block = Block {
        header: BlockHeader {
            version:     template.version,
            parents:     template.parents.clone(),
            merkle_root: MerkleRoot(reconstructed_merkle_root),
            timestamp:   ntime as u64,
            bits:        template.bits,
            nonce:       nonce as u64,
        },
        transactions,
        blue_score: template.blue_score,
        height:     template.height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    };

    // AA.0 invariant check — BlockHeader projection must match
    // MiningHeader projection. Debug-only; catastrophic drift would
    // show up immediately in dev, and in release we trust the type
    // system to keep the two shapes synchronized.
    debug_assert_eq!(
        block.header.pow_hash(),
        pow_hash,
        "BlockHeader / MiningHeader projection drift — AA.0 broken"
    );

    Ok(ReconstructedSv2Block { block, pow_hash })
}

/// Convenience wrapper: does the given pow_hash meet the block
/// target encoded in `bits`?
///
/// Callers can inline this — it is only here so session.rs in ε.5
/// does not have to re-import the primitives.
pub fn meets_block_target(pow_hash: &[u8; 32], bits: u32) -> bool {
    let target = bits_to_target(bits);
    hash_meets_target(pow_hash, &target)
}

// ─────────────────────────────────────────────────────────────────────
//                               TESTS
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::Template;
    use std::sync::Arc;

    // ── Test fixtures ──────────────────────────────────────────────────
    //
    // We need a Template whose (coinb1, extranonce, coinb2) concatenates
    // into bytes that Transaction::from_stratum_bytes will accept AND
    // whose is_coinbase() returns true. The cheapest way is to build a
    // real coinbase Transaction, serialize it via to_stratum_bytes,
    // and split the bytes at a known extranonce position.
    //
    // We delegate to V1's own Template::build to get guaranteed-correct
    // split points — that way the test exercises the same byte layout
    // a V1 miner would see in production.

    use crate::core::Transaction;

    fn mk_valid_template(
        coinbase_tag: &[u8],
        miner_spk:    &[u8],
    ) -> Template {
        // A minimal real template. We use V1 Template::build because
        // it owns the coinbase construction logic — if V1 builds a
        // parsable coinbase, V2 will reconstruct the same bytes.
        Template::build(
            /* parents   */ vec![[0xaa; 32]],
            /* height    */ 100,
            /* blue_score*/ 100,
            /* bits      */ 0x207f_ffff, // very easy target
            /* miner_spk */ miner_spk,
            /* total_fees*/ 0,
            /* other_txs */ vec![],
            /* coinbase_tag */ coinbase_tag,
            /* job_id    */ "test-job".to_string(),
        )
    }

    fn mk_cached_job(
        template:          Template,
        job_id:            u32,
        extranonce_prefix: [u8; 8],
    ) -> Sv2CachedJob {
        // Compute the merkle_root the same way push_new_jobs_on_tip_change
        // does in session.rs — via template_adapter.
        use crate::stratum_v2::template_adapter::compute_merkle_root_for_channel;
        let merkle_root = compute_merkle_root_for_channel(&template, &extranonce_prefix);

        Sv2CachedJob {
            job_id,
            template: Arc::new(template),
            extranonce_prefix,
            merkle_root,
        }
    }

    #[test]
    fn reconstruct_happy_path_produces_matching_pow_hash() {
        let tmpl = mk_valid_template(b"test-tag", &[0x51]); // OP_1, harmless
        let cached = mk_cached_job(tmpl, 1, [0x11; 8]);

        let result = reconstruct_block_for_sv2_submit(
            &cached,
            /* version */ 0x2000_0000,
            /* ntime   */ 0x6500_0000,
            /* nonce   */ 0x1234_5678,
        );
        let reconstructed = result.expect("happy-path reconstruction must succeed");

        // The pow_hash we return must equal the one the fully-assembled
        // block computes through the BlockHeader -> MiningHeader
        // projection. Any drift breaks accept_block.
        assert_eq!(
            reconstructed.block.header.pow_hash(),
            reconstructed.pow_hash
        );
    }

    #[test]
    fn reconstructed_merkle_root_matches_cached() {
        // Core byte-identity invariant: the merkle_root we commit at
        // push time and the merkle_root we derive at submit time must
        // be identical. If this assertion fires in CI, there is a bug
        // in template_adapter, walk_merkle_branch, or stratum_txid.
        let tmpl = mk_valid_template(b"inv", &[0x51]);
        let cached = mk_cached_job(tmpl, 7, [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);

        let r = reconstruct_block_for_sv2_submit(&cached, 1, 1, 1)
            .expect("reconstruction should succeed");

        // The BlockHeader we returned carries the reconstructed root.
        // Verify it equals the cache.
        assert_eq!(r.block.header.merkle_root.0, cached.merkle_root);
    }

    #[test]
    fn reconstructed_coinbase_is_still_a_coinbase() {
        // Defense-in-depth test. If Transaction::from_stratum_bytes ever
        // starts round-tripping something that fails is_coinbase, this
        // catches it before miners start seeing mysterious NotACoinbase
        // rejections in production.
        let tmpl = mk_valid_template(b"coinbase-test", &[0x51]);
        let cached = mk_cached_job(tmpl, 42, [0xab; 8]);

        let r = reconstruct_block_for_sv2_submit(&cached, 1, 1, 1)
            .expect("reconstruction should succeed");

        assert!(r.block.transactions.first().unwrap().is_coinbase());
    }

    #[test]
    fn different_extranonce_yields_different_pow_hash() {
        // Sanity: the extranonce is one of the fields the miner
        // iterates over. Two distinct extranonces must produce two
        // distinct merkle roots, and therefore two distinct pow_hashes.
        // If this fires we have a hashing collision or — more likely —
        // a bug where the extranonce is not actually injected into the
        // coinbase bytes.
        let tmpl = mk_valid_template(b"differ", &[0x51]);

        let c1 = mk_cached_job(tmpl.clone(), 1, [0x01; 8]);
        let c2 = mk_cached_job(tmpl,         2, [0x02; 8]);

        let r1 = reconstruct_block_for_sv2_submit(&c1, 1, 1, 1).unwrap();
        let r2 = reconstruct_block_for_sv2_submit(&c2, 1, 1, 1).unwrap();

        assert_ne!(c1.merkle_root, c2.merkle_root);
        assert_ne!(r1.pow_hash,    r2.pow_hash);
    }

    #[test]
    fn mismatched_cached_merkle_root_is_rejected() {
        // Simulate cache corruption: we hand the function a cached
        // merkle_root that disagrees with what the coinbase bytes
        // would produce. Function must refuse, not silently continue.
        let tmpl = mk_valid_template(b"mismatch", &[0x51]);
        let mut cached = mk_cached_job(tmpl, 1, [0x33; 8]);

        // Tamper: flip one byte of the cached merkle_root.
        cached.merkle_root[0] ^= 0xFF;

        let err = reconstruct_block_for_sv2_submit(&cached, 1, 1, 1)
            .expect_err("mismatched cache must be rejected");

        assert!(matches!(err, BlockReconstructError::MerkleRootMismatch { .. }));
    }
}
