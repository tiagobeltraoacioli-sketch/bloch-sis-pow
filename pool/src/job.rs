//! Job construction: node template → candidate Block → PoW preimage.
//!
//! The pool builds the coinbase itself, paying the POOL address (payouts
//! are then split off-chain per the PPLNS ledger — see payout.rs). The
//! coinbase mirrors the node's own miner loop (src/main.rs) and the
//! consensus rule `Block::validate_coinbase_value`:
//!
//!   output[0] = pool address, value = subsidy + total_fees
//!   output[1] = founder vesting delta (exact value + address, only
//!               when the template reports a non-zero delta)
//!
//! Every miner on a job shares ONE preimage (the coinbase is fixed), so
//! sessions partition the u64 nonce space instead of using extranonces
//! (see protocol.rs, `mining.subscribe`).

use bloch_crypto::core::{
    Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput,
};
use bloch_sis_pow::{bits_to_target, Target};

use crate::upstream::BlockTemplate;

/// One unit of work distributed to miners.
#[derive(Clone, Debug)]
pub struct Job {
    pub id:           String,
    pub height:       u64,
    /// Compact block difficulty — a share whose aux hash also meets
    /// THIS target is a valid block.
    pub bits:         u32,
    pub block_target: Target,
    /// 76-byte SIS PoW preimage (`BlockHeader::pow_preimage()`):
    /// version ‖ parents-commitment ‖ merkle_root ‖ timestamp ‖ bits.
    pub preimage:     Vec<u8>,
    /// What the block pays the pool if found (subsidy + fees) — the
    /// amount PPLNS splits across contributors.
    pub reward_sat:   u64,
    /// The full block skeleton (nonce = 0, empty pow_solution). On a
    /// block find we clone it, set nonce + solution, and submit.
    pub block:        Block,
}

impl Job {
    /// Build a job from a node template. `pool_spk` is the 20-byte
    /// pubkey-hash of the pool's payout address.
    pub fn build(tmpl: &BlockTemplate, pool_spk: &[u8], coinbase_tag: &str, id: String) -> Job {
        // Coinbase — same shape the node's solo miner and consensus
        // validation use. The height prefix keeps coinbase txids unique
        // across heights; the tag attributes blocks to this pool on
        // explorers.
        let mut cb_outputs = vec![TxOutput {
            value:         tmpl.subsidy_sat.saturating_add(tmpl.total_fees),
            script_pubkey: pool_spk.to_vec(),
        }];
        if tmpl.founder_vesting_sat > 0 {
            cb_outputs.push(TxOutput {
                value:         tmpl.founder_vesting_sat,
                script_pubkey: tmpl.founder_address_hash.to_vec(),
            });
        }

        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: format!("height:{}|{}", tmpl.height, coinbase_tag).into_bytes(),
                sequence:   u32::MAX,
            }],
            outputs:  cb_outputs,
            locktime: 0,
        };

        let all_txs: Vec<Transaction> = std::iter::once(coinbase)
            .chain(tmpl.transactions.iter().cloned())
            .collect();
        let merkle: MerkleRoot = Transaction::merkle_root(&all_txs);

        let block = Block {
            header: BlockHeader {
                version:     1,
                parents:     tmpl.parents.clone(),
                merkle_root: merkle,
                // Node clock, not pool clock — consensus requires
                // timestamp >= parent and this sidesteps pool/node skew.
                timestamp:   tmpl.cur_time,
                bits:        tmpl.bits,
                nonce:       0,
            },
            transactions: all_txs,
            blue_score:   tmpl.blue_score,
            height:       tmpl.height,
            pow_solution: Vec::new(),
            shielded_transactions: Vec::new(),
            // The pool mines Bloch natively (SIS PoW over the header
            // preimage) — merged-mining proofs are built by the AuxPoW
            // pool path, never here. Pre-activation blocks MUST be None
            // to stay byte-identical on the wire (genesis-preserving).
            auxpow: None,
        };

        let preimage = block.header.pow_preimage();

        Job {
            id,
            height: tmpl.height,
            bits: tmpl.bits,
            block_target: bits_to_target(tmpl.bits),
            preimage,
            reward_sat: tmpl.subsidy_sat.saturating_add(tmpl.total_fees),
            block,
        }
    }

    /// Materialize the found block for submission.
    pub fn assemble(&self, nonce: u64, solution: &[i32]) -> Block {
        let mut b = self.block.clone();
        b.header.nonce = nonce;
        b.pow_solution = solution.to_vec();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpl(founder_vesting_sat: u64) -> BlockTemplate {
        BlockTemplate {
            parents:              vec![[0x11u8; 32]],
            height:               42,
            emission_height:      42, // identity chain in tests (no carry-over)
            blue_score:           42,
            bits:                 0x2100ffff,
            cur_time:             1_777_686_999,
            subsidy_sat:          238_100_000_000,
            founder_vesting_sat,
            founder_address_hash: [0x77u8; 20],
            total_fees:           1_234,
            transactions:         Vec::new(),
        }
    }

    #[test]
    fn coinbase_satisfies_consensus_value_rule() {
        // validate_coinbase_value is THE consensus rule the block must
        // pass in accept_block — exercise it directly, both with and
        // without an active founder-vesting window.
        //
        // NOTE: the rule internally recomputes subsidy/vesting from the
        // block HEIGHT via tokenomics_v2, so the template values only
        // agree when they match tokenomics — here we build using the
        // real tokenomics numbers for height 42.
        let height = 42u64;
        let real_subsidy = bloch_crypto::core::tokenomics_v2::block_subsidy_sat(height);
        let real_vesting = bloch_crypto::core::tokenomics_v2::founder_vesting_delta_sat(height);
        let mut t = tmpl(real_vesting);
        t.subsidy_sat = real_subsidy;
        if real_vesting > 0 {
            t.founder_address_hash = bloch_crypto::core::tokenomics_v2::founder_address_hash();
        }

        let job = Job::build(&t, &[0x22u8; 20], "test-pool", "j1".into());
        assert!(job.block.validate_coinbase_format());
        job.block
            .validate_coinbase_value(t.total_fees)
            .expect("pool coinbase must satisfy consensus value rule");
    }

    /// End-to-end across the Emission V3 fork: a job cut from a
    /// consensus-correct template passes the REAL consensus rule
    /// (`validate_coinbase_value`) on both sides of the boundary, and a job
    /// carrying the stale pre-fork subsidy at the fork is rejected by it.
    ///
    /// NOTE on heights: this test process never calls `set_node_chain_id`,
    /// so `emission_height()` inside the validator is the identity — we
    /// place the block at its EMISSION height directly, which exercises the
    /// exact schedule the live G3 chain hits at local 40,000.
    #[test]
    fn coinbase_correct_across_emission_v3_fork() {
        use bloch_crypto::core::tokenomics_v2::{
            EMISSION_V3_FORK_EMISSION_HEIGHT, EMISSION_V3_INITIAL_REWARD_SAT,
            INITIAL_BLOCK_REWARD_SAT, block_subsidy_sat,
        };

        for eh in [EMISSION_V3_FORK_EMISSION_HEIGHT - 1, EMISSION_V3_FORK_EMISSION_HEIGHT] {
            let mut t = tmpl(0);
            t.height = eh;
            t.emission_height = eh;
            t.subsidy_sat = block_subsidy_sat(eh);
            let job = Job::build(&t, &[0x22u8; 20], "test-pool", "j1".into());
            job.block
                .validate_coinbase_value(t.total_fees)
                .unwrap_or_else(|e| panic!("consensus rejected correct coinbase at emission h{}: {}", eh, e));
        }

        // Sanity: the boundary really flips 8,400 → 2,600.
        assert_eq!(block_subsidy_sat(EMISSION_V3_FORK_EMISSION_HEIGHT - 1), INITIAL_BLOCK_REWARD_SAT);
        assert_eq!(block_subsidy_sat(EMISSION_V3_FORK_EMISSION_HEIGHT), EMISSION_V3_INITIAL_REWARD_SAT);

        // The failure mode this sprint exists to prevent: stale 8,400
        // subsidy in the coinbase AT the fork → consensus rejects the block.
        let mut stale = tmpl(0);
        stale.height = EMISSION_V3_FORK_EMISSION_HEIGHT;
        stale.emission_height = EMISSION_V3_FORK_EMISSION_HEIGHT;
        stale.subsidy_sat = INITIAL_BLOCK_REWARD_SAT;
        let job = Job::build(&stale, &[0x22u8; 20], "test-pool", "j1".into());
        job.block
            .validate_coinbase_value(stale.total_fees)
            .expect_err("consensus must reject an 8,400-BLOCH coinbase at the V3 fork");
    }

    #[test]
    fn merkle_commits_to_coinbase() {
        let t = tmpl(0);
        let job = Job::build(&t, &[0x22u8; 20], "test-pool", "j1".into());
        assert!(job.block.validate_merkle(), "header must commit to the body");
    }

    #[test]
    fn preimage_is_76_bytes_and_binds_bits() {
        let t = tmpl(0);
        let job = Job::build(&t, &[0x22u8; 20], "tag", "j1".into());
        assert_eq!(job.preimage.len(), 76);
        // Last 4 preimage bytes are bits (LE) — the share/block target is
        // committed inside the preimage; miners can't grind a softer one.
        assert_eq!(&job.preimage[72..76], &t.bits.to_le_bytes());
    }

    #[test]
    fn assemble_sets_witness() {
        let t = tmpl(0);
        let job = Job::build(&t, &[0x22u8; 20], "tag", "j1".into());
        let sol = vec![1i32; 256];
        let b = job.assemble(7, &sol);
        assert_eq!(b.header.nonce, 7);
        assert_eq!(b.pow_solution.len(), 256);
        // Assembly must not perturb the preimage (nonce is not part of it).
        assert_eq!(b.header.pow_preimage(), job.preimage);
    }
}
