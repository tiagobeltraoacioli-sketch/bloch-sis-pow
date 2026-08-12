//! Sprint U.3 — Audit finding C-1 (part 3 of 4): reorg detection & execution.
//!
//! These tests exercise the pure reorg primitives in isolation:
//!
//!   * `find_lca` / `compute_reorg_plan` are tested against hand-crafted
//!     mock DAGs — just enough `GhostdagData` to give each block a
//!     `selected_parent` pointer, which is the only field LCA cares about.
//!     We bypass `GhostDAG::add_block` entirely because it computes PHANTOM
//!     which is orthogonal to reorg-path logic and would make the tests
//!     fragile.
//!
//!   * `apply_block_utxo_mutations` and `execute_reorg` are tested against
//!     real `Storage` instances with fixture blocks, verifying that the
//!     UTXO set ends in the correct shape after rollback+apply and that
//!     mempool reinject discriminates correctly between still-valid and
//!     now-invalid transactions.
//!
//! Sprint U.4's harness will test the same primitives end-to-end through
//! `accept_block`; here we focus on correctness of the primitives alone.

use std::collections::HashMap;

use bloch::consensus::{BlockHash, GhostDAG, GhostdagData};
use bloch::core::{
    Block, BlockHeader, Transaction, TxInput, TxOutput,
};
use bloch::mempool::Mempool;
use bloch::reorg::{
    apply_block_utxo_mutations, compute_reorg_plan, execute_reorg, find_lca,
    ReorgPlan,
};
use bloch::storage::Storage;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn mk_storage() -> (TempDir, Storage) {
    let tmp = TempDir::new().unwrap();
    let s = Storage::open(tmp.path()).unwrap();
    (tmp, s)
}

/// Hand-built GhostdagData with only the fields `find_lca` / reorg planning
/// consult. Everything else gets defaults — we never run PHANTOM over these.
fn mk_dag_data(selected_parent: Option<BlockHash>, height: u64) -> GhostdagData {
    GhostdagData {
        blue_score: height,
        blue_work: height as u128,
        selected_parent,
        mergeset_blues: vec![],
        mergeset_reds: vec![],
        blues_anticone_sizes: HashMap::new(),
        parents: selected_parent.map(|p| vec![p]).unwrap_or_default(),
        height,
        timestamp: 1_700_000_000 + height,
    }
}

fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
    TxOutput {
        value,
        script_pubkey: vec![addr_byte; 20],
    }
}

fn mk_block(height: u64, transactions: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![],
            merkle_root: bloch::core::MerkleRoot::ZERO,
            timestamp:   1_700_000_000 + height,
            bits:        0x1d00ffff,
            nonce:       height,  // vary so block_hash() is distinct per height
        },
        transactions,
        blue_score: height,
        height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

fn mk_coinbase(addr_byte: u8, value: u64, height: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: 0xffffffff,
            script_sig: format!("cb:{}:{}", height, addr_byte).into_bytes(),
            sequence:   0xffffffff,
        }],
        outputs: vec![mk_output(addr_byte, value)],
        locktime: 0,
    }
}

fn mk_spend_tx(prev_txid: [u8; 32], prev_index: u32, to_addr: u8, value: u64, tag: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_index,
            script_sig: vec![0xde, 0xad, 0xbe, tag],
            sequence:   0xffffffff,
        }],
        outputs: vec![mk_output(to_addr, value)],
        locktime: 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// find_lca
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lca_of_same_block_is_that_block() {
    let mut dag = GhostDAG::with_default_k();
    let g = [0x00u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));
    assert_eq!(find_lca(&dag, &g, &g), Some(g));
}

#[test]
fn lca_of_two_tips_off_shared_fork_point_is_the_fork_point() {
    // Linear prefix, then fork:
    //   G → A → B (old tip)
    //         └→ C (new tip)
    // Expected: LCA(B, C) = A
    let mut dag = GhostDAG::with_default_k();
    let g = [0u8; 32];
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    dag.store.insert(g, mk_dag_data(None,      0));
    dag.store.insert(a, mk_dag_data(Some(g),   1));
    dag.store.insert(b, mk_dag_data(Some(a),   2));
    dag.store.insert(c, mk_dag_data(Some(a),   2));

    assert_eq!(find_lca(&dag, &b, &c), Some(a));
    assert_eq!(find_lca(&dag, &c, &b), Some(a), "LCA must be commutative");
}

#[test]
fn lca_when_one_is_ancestor_of_the_other_is_the_ancestor() {
    // Chain G → A → B: LCA(A, B) = A because A is on B's selected path.
    let mut dag = GhostDAG::with_default_k();
    let g = [0u8; 32];
    let a = [1u8; 32];
    let b = [2u8; 32];
    dag.store.insert(g, mk_dag_data(None,    0));
    dag.store.insert(a, mk_dag_data(Some(g), 1));
    dag.store.insert(b, mk_dag_data(Some(a), 2));

    assert_eq!(find_lca(&dag, &a, &b), Some(a));
    assert_eq!(find_lca(&dag, &b, &a), Some(a));
}

#[test]
fn lca_of_disjoint_chains_is_none() {
    // Two chains with different "genesis" — no intersection.
    let mut dag = GhostDAG::with_default_k();
    let g1 = [0xAAu8; 32];
    let a1 = [0xABu8; 32];
    let g2 = [0xBBu8; 32];
    let a2 = [0xBCu8; 32];
    dag.store.insert(g1, mk_dag_data(None,     0));
    dag.store.insert(a1, mk_dag_data(Some(g1), 1));
    dag.store.insert(g2, mk_dag_data(None,     0));
    dag.store.insert(a2, mk_dag_data(Some(g2), 1));

    assert!(find_lca(&dag, &a1, &a2).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// compute_reorg_plan
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn compute_reorg_plan_same_tip_returns_none() {
    let mut dag = GhostDAG::with_default_k();
    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));
    assert!(compute_reorg_plan(&dag, &g, &g).is_none());
}

#[test]
fn compute_reorg_plan_pure_extension_returns_none() {
    // G → A (old tip) → B (new tip): new tip descends from old tip on
    // the selected chain. That's an extension, not a reorg.
    let mut dag = GhostDAG::with_default_k();
    let g = [0u8; 32];
    let a = [1u8; 32];
    let b = [2u8; 32];
    dag.store.insert(g, mk_dag_data(None,    0));
    dag.store.insert(a, mk_dag_data(Some(g), 1));
    dag.store.insert(b, mk_dag_data(Some(a), 2));

    assert!(compute_reorg_plan(&dag, &a, &b).is_none(),
        "forward extension must not be reported as a reorg");
}

#[test]
fn compute_reorg_plan_backward_motion_returns_none() {
    // Going from B "back" to A (where A is ancestor of B) should be refused.
    let mut dag = GhostDAG::with_default_k();
    let g = [0u8; 32];
    let a = [1u8; 32];
    let b = [2u8; 32];
    dag.store.insert(g, mk_dag_data(None,    0));
    dag.store.insert(a, mk_dag_data(Some(g), 1));
    dag.store.insert(b, mk_dag_data(Some(a), 2));

    assert!(compute_reorg_plan(&dag, &b, &a).is_none(),
        "backward motion toward ancestor must not be reported as a reorg");
}

#[test]
fn compute_reorg_plan_simple_fork_has_correct_shape() {
    // G → A → B1 → B2   (old chain, depth 2 beyond A)
    //       └→ C1 → C2  (new chain, depth 2 beyond A)
    // Expected: LCA = A; rollback [B2, B1]; apply [C1, C2].
    let mut dag = GhostDAG::with_default_k();
    let g  = [0u8; 32];
    let a  = [1u8; 32];
    let b1 = [2u8; 32];
    let b2 = [3u8; 32];
    let c1 = [4u8; 32];
    let c2 = [5u8; 32];
    dag.store.insert(g,  mk_dag_data(None,     0));
    dag.store.insert(a,  mk_dag_data(Some(g),  1));
    dag.store.insert(b1, mk_dag_data(Some(a),  2));
    dag.store.insert(b2, mk_dag_data(Some(b1), 3));
    dag.store.insert(c1, mk_dag_data(Some(a),  2));
    dag.store.insert(c2, mk_dag_data(Some(c1), 3));

    let plan = compute_reorg_plan(&dag, &b2, &c2)
        .expect("plan must be produced for genuine fork");
    assert_eq!(plan.lca, a);
    assert_eq!(plan.to_rollback, vec![b2, b1], "rollback ordering: tip-first");
    assert_eq!(plan.to_apply,    vec![c1, c2], "apply ordering: LCA-first");
}

#[test]
fn compute_reorg_plan_asymmetric_depths() {
    // Old chain 1 deep past LCA, new chain 3 deep past LCA.
    let mut dag = GhostDAG::with_default_k();
    let g   = [0u8; 32];
    let lca = [1u8; 32];
    let b1  = [2u8; 32];
    let c1  = [3u8; 32];
    let c2  = [4u8; 32];
    let c3  = [5u8; 32];
    dag.store.insert(g,   mk_dag_data(None,       0));
    dag.store.insert(lca, mk_dag_data(Some(g),    1));
    dag.store.insert(b1,  mk_dag_data(Some(lca),  2));
    dag.store.insert(c1,  mk_dag_data(Some(lca),  2));
    dag.store.insert(c2,  mk_dag_data(Some(c1),   3));
    dag.store.insert(c3,  mk_dag_data(Some(c2),   4));

    let plan = compute_reorg_plan(&dag, &b1, &c3).unwrap();
    assert_eq!(plan.lca, lca);
    assert_eq!(plan.to_rollback, vec![b1]);
    assert_eq!(plan.to_apply,    vec![c1, c2, c3]);
}

#[test]
fn compute_reorg_plan_no_common_ancestor_returns_none() {
    let mut dag = GhostDAG::with_default_k();
    let g1 = [0xAAu8; 32];
    let a1 = [0xABu8; 32];
    let g2 = [0xBBu8; 32];
    let a2 = [0xBCu8; 32];
    dag.store.insert(g1, mk_dag_data(None,     0));
    dag.store.insert(a1, mk_dag_data(Some(g1), 1));
    dag.store.insert(g2, mk_dag_data(None,     0));
    dag.store.insert(a2, mk_dag_data(Some(g2), 1));

    assert!(compute_reorg_plan(&dag, &a1, &a2).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// apply_block_utxo_mutations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn apply_block_utxo_mutations_creates_utxos_and_undo_record() {
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA1, 500_000_000, 1);
    let cb_txid = cb.txid();
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    store.put_block(&block).unwrap();
    apply_block_utxo_mutations(&store, &block).expect("apply must succeed");

    assert!(store.get_utxo(&cb_txid, 0).unwrap().is_some(),
        "coinbase output must be in UTXO set");
    assert_eq!(store.get_coinbase_height(&cb_txid).unwrap(), Some(1),
        "coinbase info must record height");
    assert_eq!(store.get_tx_location(&cb_txid).unwrap().map(|(h, _)| h),
        Some(block_hash),
        "tx_index must point coinbase at its block");

    let undo = store.get_undo_data(&block_hash).unwrap().unwrap();
    assert_eq!(undo.block_height, 1);
    assert_eq!(undo.coinbase_txids, vec![cb_txid]);
    assert_eq!(undo.created_utxo_keys, vec![(cb_txid, 0)]);
}

#[test]
fn apply_then_rollback_via_public_primitive_round_trip() {
    // Sanity that apply_block_utxo_mutations + rollback_block compose cleanly,
    // mirroring U.2's apply_rollback_apply_rollback_is_stable but going
    // through the public reorg::apply primitive rather than the test helper.
    let (_tmp, store) = mk_storage();
    let cb = mk_coinbase(0xA2, 500_000_000, 1);
    let cb_txid = cb.txid();
    let block = mk_block(1, vec![cb]);
    let block_hash = block.block_hash();

    store.put_block(&block).unwrap();
    apply_block_utxo_mutations(&store, &block).unwrap();
    store.rollback_block(&block_hash).unwrap();

    assert!(store.get_utxo(&cb_txid, 0).unwrap().is_none(),
        "rollback must remove coinbase output");
    assert!(store.get_coinbase_height(&cb_txid).unwrap().is_none(),
        "rollback must remove coinbase info");
    assert!(store.get_undo_data(&block_hash).unwrap().is_none(),
        "rollback must consume undo record");
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_reorg
// ─────────────────────────────────────────────────────────────────────────────

/// Build the scenario used by execute_reorg tests. Produces two forks off a
/// shared genesis-like block, with distinct coinbase outputs so we can
/// verify which one "survives" the reorg.
///
/// Returns: (storage, mempool, plan_a_to_b) — plan rolls back fork A and
/// applies fork B.
fn setup_two_forks_storage_and_plan() -> (TempDir, Storage, Mempool, ReorgPlan) {
    let (tmp, store) = mk_storage();
    let mempool = Mempool::new();

    // Block A1 — coinbase paying addr 0xA1. Will be rolled back.
    let cb_a1 = mk_coinbase(0xA1, 500_000_000, 1);
    let block_a1 = mk_block(1, vec![cb_a1]);
    let a1_hash = block_a1.block_hash();
    store.put_block(&block_a1).unwrap();
    apply_block_utxo_mutations(&store, &block_a1).unwrap();

    // Block B1 — coinbase paying addr 0xB1. Will be applied. Uses a different
    // nonce via height+1 trick so block_hash differs from A1.
    let mut block_b1 = mk_block(1, vec![mk_coinbase(0xB1, 500_000_000, 1)]);
    block_b1.header.nonce = 999;  // force different block_hash from A1
    let b1_hash = block_b1.block_hash();
    store.put_block(&block_b1).unwrap();
    // Note: we do NOT apply B1 yet — it's a persisted-but-unapplied block
    // on the losing-to-winning chain, which is what execute_reorg expects.

    let plan = ReorgPlan {
        lca:         [0xFFu8; 32],  // synthetic LCA (storage doesn't consult it)
        to_rollback: vec![a1_hash],
        to_apply:    vec![b1_hash],
    };
    (tmp, store, mempool, plan)
}

#[test]
fn execute_reorg_updates_utxo_set_to_new_chain() {
    let (_tmp, store, mempool, plan) = setup_two_forks_storage_and_plan();

    // Compute expected txids via the same helpers the fixture used, so we
    // don't have to reconstruct Transaction bodies manually.
    let a1_cb_txid = mk_coinbase(0xA1, 500_000_000, 1).txid();
    let b1_cb_txid = mk_coinbase(0xB1, 500_000_000, 1).txid();

    assert!(store.get_utxo(&a1_cb_txid, 0).unwrap().is_some(),
        "sanity: A1 coinbase UTXO exists pre-reorg");

    let outcome = execute_reorg(&store, &mempool, &plan).expect("reorg must succeed");
    assert_eq!(outcome.rolled_back, 1);
    assert_eq!(outcome.applied,     1);

    assert!(store.get_utxo(&a1_cb_txid, 0).unwrap().is_none(),
        "rolled-back coinbase must be gone from UTXO set");
    assert!(store.get_utxo(&b1_cb_txid, 0).unwrap().is_some(),
        "applied coinbase must be in UTXO set");
}

#[test]
fn execute_reorg_reinjects_non_coinbase_tx_when_still_valid() {
    // Setup:
    //   Seed a UTXO U (address 0xAA) present BEFORE both forks.
    //   Fork A includes a coinbase + a tx spending U → addr 0xBB.
    //   Fork B includes only a coinbase (doesn't touch U).
    //   After reorg A→B, U is restored, so the spending tx is still valid
    //   (its prev_output U exists again). It should be reinjected.
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();

    // Seed U (pretend some earlier block created it).
    let u_txid = [0x77u8; 32];
    let u_out  = mk_output(0xAA, 10_000_000);
    store.put_utxo(&u_txid, 0, &u_out).unwrap();

    // Fork A: coinbase + spend-of-U.
    let cb_a    = mk_coinbase(0xA1, 500_000_000, 1);
    let spend_u = mk_spend_tx(u_txid, 0, 0xBB, 9_999_000, 0x01);
    let spend_u_txid = spend_u.txid();
    let block_a = mk_block(1, vec![cb_a, spend_u]);
    let a_hash = block_a.block_hash();
    store.put_block(&block_a).unwrap();
    apply_block_utxo_mutations(&store, &block_a).unwrap();

    // Sanity: U was consumed by fork A.
    assert!(store.get_utxo(&u_txid, 0).unwrap().is_none(),
        "sanity: U spent by fork A");

    // Fork B: coinbase only, does not touch U.
    let cb_b = mk_coinbase(0xB1, 500_000_000, 1);
    let mut block_b = mk_block(1, vec![cb_b]);
    block_b.header.nonce = 999;
    let b_hash = block_b.block_hash();
    store.put_block(&block_b).unwrap();

    let plan = ReorgPlan {
        lca:         [0xFFu8; 32],
        to_rollback: vec![a_hash],
        to_apply:    vec![b_hash],
    };

    let outcome = execute_reorg(&store, &mempool, &plan).unwrap();

    // U is back, and the spend-of-U tx is now in the mempool (fee was valid,
    // inputs resolvable).
    assert!(store.get_utxo(&u_txid, 0).unwrap().is_some(),
        "U must be restored by rollback");
    assert_eq!(outcome.txs_reinjected, 1,
        "the spend-of-U tx is still valid post-reorg, must be reinjected");
    assert_eq!(outcome.txs_discarded,  0);
    assert!(mempool.contains(&spend_u_txid),
        "mempool must hold the reinjected tx");
}

#[test]
fn execute_reorg_discards_tx_whose_inputs_are_gone() {
    // Setup:
    //   Fork A creates output X (coinbase C_A0, outputs addr 0xA1) and then
    //   has a second tx spending X in the same block (X is only known to A).
    //   Fork B is a coinbase that does NOT create X.
    //   After reorg A→B, X never exists, so A's spend-of-X tx has a missing
    //   input and must be discarded.
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();

    // Fork A with two txs: coinbase creates C_A0, second tx spends it.
    let cb_a = mk_coinbase(0xA1, 500_000_000, 1);
    let cb_a_txid = cb_a.txid();
    let spend_ca0 = mk_spend_tx(cb_a_txid, 0, 0xCC, 100_000_000, 0x02);
    let spend_ca0_txid = spend_ca0.txid();

    // NOTE: spending a coinbase in the same block it's created is NOT valid
    // under coinbase maturity rules (the real accept_block would reject), but
    // apply_block_utxo_mutations mirrors the mutation loop without those
    // validations — fine for this unit test whose point is the discard
    // decision in the reinject path. The "X doesn't exist in fork B" is what
    // we're actually verifying.
    let block_a = mk_block(1, vec![cb_a, spend_ca0]);
    let a_hash = block_a.block_hash();
    store.put_block(&block_a).unwrap();
    apply_block_utxo_mutations(&store, &block_a).unwrap();

    // Fork B: entirely different coinbase.
    let cb_b = mk_coinbase(0xB1, 500_000_000, 1);
    let mut block_b = mk_block(1, vec![cb_b]);
    block_b.header.nonce = 999;
    let b_hash = block_b.block_hash();
    store.put_block(&block_b).unwrap();

    let plan = ReorgPlan {
        lca:         [0xFFu8; 32],
        to_rollback: vec![a_hash],
        to_apply:    vec![b_hash],
    };
    let outcome = execute_reorg(&store, &mempool, &plan).unwrap();

    // The spend-of-C_A0 tx references C_A0 which never existed in fork B.
    // It must be discarded, not silently added to mempool with missing input.
    assert_eq!(outcome.txs_reinjected, 0);
    assert_eq!(outcome.txs_discarded,  1,
        "tx whose prev_output no longer exists must be discarded");
    assert!(!mempool.contains(&spend_ca0_txid),
        "mempool must not contain tx with missing inputs");
}

#[test]
fn execute_reorg_applied_blocks_become_reorg_capable() {
    // After execute_reorg applies the new chain, each applied block must
    // have its own UndoData recorded — otherwise a follow-up reorg couldn't
    // roll back from the new tip.
    let (_tmp, store, mempool, plan) = setup_two_forks_storage_and_plan();
    let b1_hash = plan.to_apply[0];

    execute_reorg(&store, &mempool, &plan).unwrap();

    assert!(store.get_undo_data(&b1_hash).unwrap().is_some(),
        "applied block must have fresh UndoData so it can be rolled back later");
}
