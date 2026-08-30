//! Sprint U.4 — reorg HARDENING harness (complements `sprint_u4_reorg_e2e.rs`).
//!
//! The end-to-end U.4 harness (`tests/sprint_u4_reorg_e2e.rs`) already covers
//! the disposition-classifier contract, fork-loser no-op, tip-flip convergence,
//! and back-and-forth stability. This file ADDS the properties that one does not
//! assert, driving the same real `Storage` + `GhostDAG` + `Mempool` fixtures:
//!   * audit-H1 abort-AND-restore — a fork block that double-spends, or spends a
//!     main-only output, must leave the UTXO set BYTE-EXACTLY at the pre-attempt
//!     state (the restore path in `execute_reorg_inner`);
//!   * byte-exact A→B→A symmetry via a full-outpoint-universe snapshot;
//!   * explicit mempool reinject/discard counts in `ReorgOutcome`;
//!   * the shielded `disconnect_block_self` order-guard (identity-keyed,
//!     `ReorgOrderMismatch` / `ReorgBeyondUndoHorizon`) and exact reversal.
//!
//! It is TEST-ONLY and additive: it drives the existing public API only and
//! never touches consensus/engine logic. Fixtures reuse the exact patterns from
//! `tests/sprint_u3_reorg.rs` / `tests/sprint_u4_reorg_e2e.rs` (temp `Storage`,
//! hand-built `GhostdagData` giving each block a `selected_parent`, coinbase +
//! spend `Transaction`s) so the blocks are REAL blocks the engine accepts, not
//! mocks that bypass the logic under test.
//!
//! # What each test asserts
//!
//!   1. `reorg_a_to_b_utxo_set_equals_fork_b`      — UTXO correctness after A→B.
//!   2. `reorg_b_to_a_restores_byte_exact_state`   — rollback/apply symmetry.
//!   3. `reorg_reinjects_valid_and_discards_orphan`— mempool reinject counts.
//!   4. `reorg_aborts_and_restores_on_fork_double_spend`      — audit H1.
//!   5. `reorg_aborts_and_restores_when_fork_spends_orphaned` — audit H1.
//!   6. `no_reorg_on_equal_forward_and_backward_tips` — `compute_reorg_plan` None.
//!   7. `shielded_disconnect_self_reverses_apply`  — shielded exact reversal.
//!   8. `shielded_disconnect_self_guards_order`     — shielded order guard.
//!
//! Both reorg + coherence live behind the default `node` feature, so this test
//! builds with a plain `cargo test --test reorg_e2e` (no extra `--features`).

use std::collections::HashMap;

use bloch::consensus::{BlockHash, GhostDAG, GhostdagData};
use bloch::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
use bloch::mempool::Mempool;
use bloch::reorg::{apply_block_utxo_mutations, compute_reorg_plan, execute_reorg};
use bloch::storage::Storage;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures — mirror sprint_u3_reorg.rs / sprint_u4_reorg_e2e.rs.
// ─────────────────────────────────────────────────────────────────────────────

fn mk_storage() -> (TempDir, Storage) {
    let tmp = TempDir::new().unwrap();
    let s = Storage::open(tmp.path()).unwrap();
    (tmp, s)
}

/// Only the fields `find_lca` / reorg planning consult; everything else default.
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
    TxOutput { value, script_pubkey: vec![addr_byte; 20] }
}

fn mk_block_at(height: u64, nonce_tag: u64, txs: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            parents: vec![],
            merkle_root: bloch::core::MerkleRoot::ZERO,
            timestamp: 1_700_000_000 + height,
            bits: 0x1d00ffff,
            nonce: nonce_tag,
        },
        transactions: txs,
        blue_score: height,
        height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),
        auxpow: None,
    }
}

fn mk_coinbase(addr_byte: u8, value: u64, height: u64, tag: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: 0xffffffff,
            script_sig: format!("cb:{}:{}:{}", height, addr_byte, tag).into_bytes(),
            sequence: 0xffffffff,
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
            sequence: 0xffffffff,
        }],
        outputs: vec![mk_output(to_addr, value)],
        locktime: 0,
    }
}

/// Byte-exact snapshot of the UTXO set over a KNOWN universe of outpoints.
///
/// `apply_block_utxo_mutations` only ever writes outputs of txs contained in the
/// blocks we build, so the set of outpoints that could possibly exist is exactly
/// the outputs of every tx across both forks (plus any seeded UTXOs). Enumerating
/// that universe and recording each outpoint's `(value, script_pubkey)` (or its
/// absence) is therefore a COMPLETE, byte-exact fingerprint of the UTXO set —
/// it catches a missing output, an A-only output that leaked through, a
/// double-count, or coins-from-nothing within the reachable universe. `TxOutput`
/// derives no `Eq`, so we compare the decomposed scalar fields.
fn utxo_snapshot(store: &Storage, outpoints: &[([u8; 32], u32)]) -> Vec<Option<(u64, Vec<u8>)>> {
    outpoints
        .iter()
        .map(|(txid, idx)| {
            store
                .get_utxo(txid, *idx)
                .unwrap()
                .map(|o| (o.value, o.script_pubkey))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// A shared two-fork world: G(LCA) → A1 → A2 (applied)  and  G → B1 → B2 → B3.
// All blocks are coinbase-only (500M each) with distinct addresses so we can
// track exactly which fork's coins survive. Returns everything a test needs to
// drive + inspect a reorg through the real engine.
// ─────────────────────────────────────────────────────────────────────────────

struct TwoForkWorld {
    _tmp: TempDir,
    store: Storage,
    dag: GhostDAG,
    a_tip: BlockHash,
    b_tip: BlockHash,
    /// Every outpoint that can ever exist in this world (universe for snapshots).
    universe: Vec<([u8; 32], u32)>,
    a_outpoints: Vec<([u8; 32], u32)>,
    b_outpoints: Vec<([u8; 32], u32)>,
}

fn build_two_fork_world() -> TwoForkWorld {
    let (_tmp, store) = mk_storage();
    let mut dag = GhostDAG::with_default_k();

    // LCA — genesis-like root. Stays put across every reorg (never in a plan),
    // so it needs no body / no applied state.
    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    // ── Fork A (the current selected tip): G → A1 → A2, applied forward ──
    let a1 = mk_block_at(1, 1001, vec![mk_coinbase(0xA1, 500_000_000, 1, 0x01)]);
    let a1h = a1.block_hash();
    dag.store.insert(a1h, mk_dag_data(Some(g), 1));
    store.put_block(&a1).unwrap();
    apply_block_utxo_mutations(&store, &a1).unwrap();

    let a2 = mk_block_at(2, 1002, vec![mk_coinbase(0xA2, 500_000_000, 2, 0x02)]);
    let a2h = a2.block_hash();
    dag.store.insert(a2h, mk_dag_data(Some(a1h), 2));
    store.put_block(&a2).unwrap();
    apply_block_utxo_mutations(&store, &a2).unwrap();

    // ── Fork B (the challenger): G → B1 → B2 → B3, persisted but NOT applied ──
    let b1 = mk_block_at(1, 2001, vec![mk_coinbase(0xB1, 500_000_000, 1, 0x11)]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    store.put_block(&b1).unwrap();

    let b2 = mk_block_at(2, 2002, vec![mk_coinbase(0xB2, 500_000_000, 2, 0x12)]);
    let b2h = b2.block_hash();
    dag.store.insert(b2h, mk_dag_data(Some(b1h), 2));
    store.put_block(&b2).unwrap();

    let b3 = mk_block_at(3, 2003, vec![mk_coinbase(0xB3, 500_000_000, 3, 0x13)]);
    let b3h = b3.block_hash();
    dag.store.insert(b3h, mk_dag_data(Some(b2h), 3));
    store.put_block(&b3).unwrap();

    let a_outpoints = vec![
        (mk_coinbase(0xA1, 500_000_000, 1, 0x01).txid(), 0u32),
        (mk_coinbase(0xA2, 500_000_000, 2, 0x02).txid(), 0u32),
    ];
    let b_outpoints = vec![
        (mk_coinbase(0xB1, 500_000_000, 1, 0x11).txid(), 0u32),
        (mk_coinbase(0xB2, 500_000_000, 2, 0x12).txid(), 0u32),
        (mk_coinbase(0xB3, 500_000_000, 3, 0x13).txid(), 0u32),
    ];
    let mut universe = a_outpoints.clone();
    universe.extend(b_outpoints.clone());

    TwoForkWorld { _tmp, store, dag, a_tip: a2h, b_tip: b3h, universe, a_outpoints, b_outpoints }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. UTXO correctness after reorg A→B.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn reorg_a_to_b_utxo_set_equals_fork_b() {
    let w = build_two_fork_world();
    let mempool = Mempool::new();

    // Sanity: pre-reorg the world is exactly fork A.
    for op in &w.a_outpoints {
        assert!(w.store.get_utxo(&op.0, op.1).unwrap().is_some(), "A output present pre-reorg");
    }
    for op in &w.b_outpoints {
        assert!(w.store.get_utxo(&op.0, op.1).unwrap().is_none(), "B output absent pre-reorg");
    }

    let plan = compute_reorg_plan(&w.dag, &w.a_tip, &w.b_tip)
        .expect("genuine fork must produce a plan");
    assert_eq!(plan.to_rollback.len(), 2, "roll back A2, A1");
    assert_eq!(plan.to_apply.len(), 3, "apply B1, B2, B3");

    let outcome = execute_reorg(&w.store, &mempool, &plan).expect("reorg A→B must succeed");
    assert_eq!(outcome.rolled_back, 2);
    assert_eq!(outcome.applied, 3);

    // Every B output present, every A-only output gone. No coins-from-nothing:
    // the universe snapshot has exactly the 3 B outpoints and nothing else.
    for op in &w.b_outpoints {
        let o = w.store.get_utxo(&op.0, op.1).unwrap().expect("B output must exist after reorg");
        assert_eq!(o.value, 500_000_000);
    }
    for op in &w.a_outpoints {
        assert!(w.store.get_utxo(&op.0, op.1).unwrap().is_none(), "A-only output must be gone after A→B");
    }

    // Applied B blocks must be reorg-capable (fresh undo) for the reverse trip.
    for h in &plan.to_apply {
        assert!(w.store.get_undo_data(h).unwrap().is_some(), "applied B block needs undo data");
    }
    // Rolled-back A undo records were consumed.
    for h in &plan.to_rollback {
        assert!(w.store.get_undo_data(h).unwrap().is_none(), "rolled-back A undo consumed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Rollback/apply symmetry — reorg B→A restores byte-exact original state.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn reorg_b_to_a_restores_byte_exact_state() {
    let w = build_two_fork_world();
    let mempool = Mempool::new();

    // Snapshot the pristine fork-A UTXO state over the full universe.
    let snap_before = utxo_snapshot(&w.store, &w.universe);

    // A → B.
    let plan_ab = compute_reorg_plan(&w.dag, &w.a_tip, &w.b_tip).unwrap();
    execute_reorg(&w.store, &mempool, &plan_ab).expect("A→B");

    let snap_on_b = utxo_snapshot(&w.store, &w.universe);
    assert_ne!(snap_before, snap_on_b, "sanity: the reorg actually changed the UTXO set");

    // B → A. Now B is the selected tip; roll it back and re-apply A.
    let plan_ba = compute_reorg_plan(&w.dag, &w.b_tip, &w.a_tip).unwrap();
    assert_eq!(plan_ba.to_rollback.len(), 3, "roll back B3, B2, B1");
    assert_eq!(plan_ba.to_apply.len(), 2, "apply A1, A2");
    execute_reorg(&w.store, &mempool, &plan_ba).expect("B→A");

    let snap_after = utxo_snapshot(&w.store, &w.universe);
    assert_eq!(
        snap_before, snap_after,
        "round-trip A→B→A must restore the byte-exact original UTXO state"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Mempool reinject — one A tx still valid under B is reinjected; one whose
//    input B never created is discarded. Assert the ReorgOutcome counts.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn reorg_reinjects_valid_and_discards_orphan() {
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();
    let mut dag = GhostDAG::with_default_k();

    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    // Seed a plain (non-coinbase) UTXO U that exists at the LCA. `txA` spends it.
    let u_txid = [0x77u8; 32];
    store.put_utxo(&u_txid, 0, &mk_output(0xAA, 10_000_000)).unwrap();

    // ── Fork A: A1 = [coinbase, txA(spend U)],  A2 = [coinbase, txD(spend A1 cb)] ──
    let cb_a1 = mk_coinbase(0xA1, 500_000_000, 1, 0x01);
    let cb_a1_txid = cb_a1.txid();
    let tx_a = mk_spend_tx(u_txid, 0, 0xBB, 9_990_000, 0x01); // spends U → still valid under B
    let tx_a_txid = tx_a.txid();
    let a1 = mk_block_at(1, 1001, vec![cb_a1, tx_a]);
    let a1h = a1.block_hash();
    dag.store.insert(a1h, mk_dag_data(Some(g), 1));
    store.put_block(&a1).unwrap();
    apply_block_utxo_mutations(&store, &a1).unwrap();

    // txD spends A1's coinbase output — an output that ONLY fork A ever creates.
    let cb_a2 = mk_coinbase(0xA2, 500_000_000, 2, 0x02);
    let tx_d = mk_spend_tx(cb_a1_txid, 0, 0xCC, 490_000_000, 0x02);
    let tx_d_txid = tx_d.txid();
    let a2 = mk_block_at(2, 1002, vec![cb_a2, tx_d]);
    let a2h = a2.block_hash();
    dag.store.insert(a2h, mk_dag_data(Some(a1h), 2));
    store.put_block(&a2).unwrap();
    apply_block_utxo_mutations(&store, &a2).unwrap();

    // ── Fork B: single coinbase-only block off the LCA (does not touch U). ──
    let b1 = mk_block_at(1, 2001, vec![mk_coinbase(0xB1, 500_000_000, 1, 0x11)]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    store.put_block(&b1).unwrap();

    let plan = compute_reorg_plan(&dag, &a2h, &b1h).unwrap();
    assert_eq!(plan.to_rollback, vec![a2h, a1h]);
    assert_eq!(plan.to_apply, vec![b1h]);

    let outcome = execute_reorg(&store, &mempool, &plan).expect("reorg must succeed");

    // txA (spends U, restored by rollback, untouched by B) → reinjected.
    // txD (spends A1's coinbase, which never exists in B's world) → discarded.
    assert_eq!(outcome.txs_reinjected, 1, "txA is still spendable under B → reinject");
    assert_eq!(outcome.txs_discarded, 1, "txD's input is orphaned under B → discard");
    assert!(mempool.contains(&tx_a_txid), "mempool holds the reinjected tx");
    assert!(!mempool.contains(&tx_d_txid), "mempool must not hold the orphaned tx");
    // Post-reorg U is restored (rollback un-spent it) and remains spendable.
    assert!(store.get_utxo(&u_txid, 0).unwrap().is_some(), "U restored by rollback");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4 & 5. Fork re-validation / abort-and-restore (audit H1). A B-fork block that
//    double-spends OR spends a main-A-only output must make execute_reorg return
//    Err, AND leave the UTXO set EXACTLY equal to the pre-attempt (A) state — the
//    restore path in execute_reorg_inner must run.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn reorg_aborts_and_restores_on_fork_double_spend() {
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();
    let mut dag = GhostDAG::with_default_k();

    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    // A mature, non-coinbase output U present at the LCA (survives rollback of A).
    let u_txid = [0x77u8; 32];
    store.put_utxo(&u_txid, 0, &mk_output(0xAA, 10_000_000)).unwrap();

    // Fork A: one coinbase block (the current tip).
    let a1 = mk_block_at(1, 1001, vec![mk_coinbase(0xA1, 500_000_000, 1, 0x01)]);
    let a1h = a1.block_hash();
    dag.store.insert(a1h, mk_dag_data(Some(g), 1));
    store.put_block(&a1).unwrap();
    apply_block_utxo_mutations(&store, &a1).unwrap();

    // Universe of outpoints for the byte-exact pre-attempt snapshot.
    let universe = vec![
        (u_txid, 0u32),
        (mk_coinbase(0xA1, 500_000_000, 1, 0x01).txid(), 0u32),
        (mk_coinbase(0xB1, 500_000_000, 1, 0x11).txid(), 0u32),
    ];
    let snap_before = utxo_snapshot(&store, &universe);

    // Fork B: coinbase + TWO txs that both spend U (intra-block double-spend).
    let cb_b1 = mk_coinbase(0xB1, 500_000_000, 1, 0x11);
    let spend1 = mk_spend_tx(u_txid, 0, 0xB2, 9_000_000, 0x01);
    let spend2 = mk_spend_tx(u_txid, 0, 0xB3, 9_000_000, 0x02); // double-spends U
    let b1 = mk_block_at(1, 2001, vec![cb_b1, spend1, spend2]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    store.put_block(&b1).unwrap();

    let plan = compute_reorg_plan(&dag, &a1h, &b1h).unwrap();
    let res = execute_reorg(&store, &mempool, &plan);

    assert!(res.is_err(), "reorg must abort on a fork block that double-spends");
    let msg = res.unwrap_err();
    assert!(msg.contains("double-spend"), "error must name the double-spend: {msg}");

    // Restore path ran: UTXO set is byte-exact equal to the pre-attempt A state.
    let snap_after = utxo_snapshot(&store, &universe);
    assert_eq!(snap_before, snap_after, "aborted reorg must restore the pre-attempt UTXO state");
    // Concretely: A1's coinbase is back, no B output leaked in.
    assert!(store.get_utxo(&mk_coinbase(0xA1, 500_000_000, 1, 0x01).txid(), 0).unwrap().is_some());
    assert!(store.get_utxo(&mk_coinbase(0xB1, 500_000_000, 1, 0x11).txid(), 0).unwrap().is_none());
    assert!(store.get_utxo(&u_txid, 0).unwrap().is_some(), "seeded U intact after abort");
}

#[test]
fn reorg_aborts_and_restores_when_fork_spends_orphaned_output() {
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();
    let mut dag = GhostDAG::with_default_k();

    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    // Fork A: coinbase cb_A1 (the current tip). cb_A1 exists ONLY on chain A.
    let cb_a1 = mk_coinbase(0xA1, 500_000_000, 1, 0x01);
    let cb_a1_txid = cb_a1.txid();
    let a1 = mk_block_at(1, 1001, vec![cb_a1]);
    let a1h = a1.block_hash();
    dag.store.insert(a1h, mk_dag_data(Some(g), 1));
    store.put_block(&a1).unwrap();
    apply_block_utxo_mutations(&store, &a1).unwrap();

    let universe = vec![
        (cb_a1_txid, 0u32),
        (mk_coinbase(0xB1, 500_000_000, 1, 0x11).txid(), 0u32),
    ];
    let snap_before = utxo_snapshot(&store, &universe);

    // Fork B: coinbase + a tx spending cb_A1 — an output that is rolled back
    // (orphaned) the moment fork A is disconnected, so it is absent from the
    // reorged UTXO set when B is re-validated.
    let cb_b1 = mk_coinbase(0xB1, 500_000_000, 1, 0x11);
    let spend_a_only = mk_spend_tx(cb_a1_txid, 0, 0xB2, 400_000_000, 0x01);
    let b1 = mk_block_at(1, 2001, vec![cb_b1, spend_a_only]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    store.put_block(&b1).unwrap();

    let plan = compute_reorg_plan(&dag, &a1h, &b1h).unwrap();
    let res = execute_reorg(&store, &mempool, &plan);

    assert!(res.is_err(), "reorg must abort: B spends an output that only existed on A");
    let msg = res.unwrap_err();
    assert!(msg.contains("absent"), "error must flag the orphaned input: {msg}");

    let snap_after = utxo_snapshot(&store, &universe);
    assert_eq!(snap_before, snap_after, "aborted reorg must restore the pre-attempt UTXO state");
    assert!(store.get_utxo(&cb_a1_txid, 0).unwrap().is_some(), "cb_A1 restored after abort");
    assert!(store.get_utxo(&mk_coinbase(0xB1, 500_000_000, 1, 0x11).txid(), 0).unwrap().is_none(),
        "no B coins-from-nothing after abort");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. No-reorg cases — compute_reorg_plan returns None for equal, forward, and
//    backward (ancestor) tips.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn no_reorg_on_equal_forward_and_backward_tips() {
    let mut dag = GhostDAG::with_default_k();
    let g = [0u8; 32];
    let a = [1u8; 32];
    let b = [2u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));
    dag.store.insert(a, mk_dag_data(Some(g), 1));
    dag.store.insert(b, mk_dag_data(Some(a), 2));

    // Equal tips → no-op.
    assert!(compute_reorg_plan(&dag, &b, &b).is_none(), "equal tips: no reorg");
    // Forward extension (old is ancestor of new) → not a reorg.
    assert!(compute_reorg_plan(&dag, &a, &b).is_none(), "forward extension: no reorg");
    // Backward motion (new is ancestor of old) → refused.
    assert!(compute_reorg_plan(&dag, &b, &a).is_none(), "backward to ancestor: no reorg");
    // A genuine sibling fork DOES produce a plan (contrast case).
    let c = [3u8; 32];
    dag.store.insert(c, mk_dag_data(Some(a), 2));
    assert!(compute_reorg_plan(&dag, &b, &c).is_some(), "genuine sibling fork: plan produced");
}

// ─────────────────────────────────────────────────────────────────────────────
// 7 & 8. Shielded order-guard (latent path). Drive the node-facing
//    ShieldedPool::apply_block_self / disconnect_block_self bookkeeping.
//
//    Shielded verification is RejectAll by default, so apply_block_self can only
//    commit an EMPTY shielded set (a real tx would be proof-rejected). We
//    therefore verify the exact-reversal property by applying a real (mocked-ok)
//    shielded block through the closure API and reversing it through the
//    node-facing disconnect_block_self, and verify the identity-keyed order
//    guard directly through the _self connect/disconnect pair.
// ─────────────────────────────────────────────────────────────────────────────

use bloch::coherence::{ShieldedPool, ShieldedTx, TxError};

fn shielded_tx(anchor: [u8; 32], nfs: Vec<[u8; 32]>, outs: Vec<[u8; 32]>) -> ShieldedTx {
    // One structurally well-formed (all-zero) note ciphertext per output —
    // validate() enforces ciphertexts_well_formed() as a precondition.
    let cts = outs.iter().map(|_| bloch::coherence::NoteCiphertext {
        kem_ct: vec![0u8; bloch::coherence::NOTE_KEM_CT_LEN],
        nonce: [0u8; bloch::coherence::NOTE_AEAD_NONCE_LEN],
        payload: vec![0u8; bloch::coherence::NOTE_PLAINTEXT_LEN + bloch::coherence::NOTE_AEAD_TAG_LEN],
    }).collect();
    ShieldedTx { anchor, nullifiers: nfs, outputs: outs, output_ciphertexts: cts, fee: 0, proof: vec![1], binding_sig: vec![] }
}

#[test]
fn shielded_disconnect_self_reverses_apply() {
    let ok = |_p: &bloch::coherence::SpendPublic, _pf: &[u8]| true;
    let mut pool = ShieldedPool::new();
    let root0 = pool.anchor();
    let id_a = [0xAAu8; 32];

    // Apply a real shielded block (spend a nullifier + append two commitments)
    // via the closure API (RejectAll would block apply_block_self here).
    pool.apply_block(id_a, &[shielded_tx(root0, vec![[1u8; 32]], vec![[10u8; 32], [11u8; 32]])], ok)
        .unwrap();
    let anchor_after = pool.anchor();
    assert_ne!(anchor_after, root0, "applying shielded outputs must advance the anchor");
    assert!(pool.engine.is_spent(&[1u8; 32]), "nullifier spent after apply");
    assert_eq!(pool.engine.undo_depth(), 1);

    // Reverse it through the node-facing _self disconnect (identity-keyed).
    pool.disconnect_block_self(id_a).expect("in-order disconnect must succeed");
    assert_eq!(pool.anchor(), root0, "disconnect_block_self reverts the commitment-tree root");
    assert!(!pool.engine.is_spent(&[1u8; 32]), "disconnect_block_self un-spends the nullifier");
    assert_eq!(pool.engine.undo_depth(), 0);

    // Bookkeeping through the true node path: apply_block_self commits an EMPTY
    // shielded set under RejectAll (no proof to reject) and records an undo
    // record that _self disconnect then reverses exactly.
    let id_empty = [0xEEu8; 32];
    assert_eq!(pool.apply_block_self(id_empty, &[]).unwrap(), 0);
    assert_eq!(pool.engine.undo_depth(), 1);
    assert_eq!(pool.anchor(), root0, "empty shielded set does not move the anchor");
    pool.disconnect_block_self(id_empty).expect("empty-block disconnect must succeed");
    assert_eq!(pool.engine.undo_depth(), 0);
}

#[test]
fn shielded_disconnect_self_guards_order() {
    let ok = |_p: &bloch::coherence::SpendPublic, _pf: &[u8]| true;
    let mut pool = ShieldedPool::new();
    let (id_a, id_b) = ([0xA1u8; 32], [0xB2u8; 32]);

    pool.apply_block(id_a, &[shielded_tx(pool.anchor(), vec![[1u8; 32]], vec![[10u8; 32]])], ok)
        .unwrap();
    let anchor_after_a = pool.anchor();
    pool.apply_block(id_b, &[shielded_tx(pool.anchor(), vec![[2u8; 32]], vec![[20u8; 32]])], ok)
        .unwrap();
    assert_eq!(pool.engine.undo_depth(), 2);

    // Out-of-order: ask to disconnect A while B is on top of the undo stack.
    // The engine is identity-keyed, so this is refused rather than silently
    // undoing the wrong block — nothing is popped, B's effect stays intact.
    match pool.disconnect_block_self(id_a) {
        Err(TxError::ReorgOrderMismatch { expected, found }) => {
            assert_eq!(expected, id_a);
            assert_eq!(found, id_b);
        }
        other => panic!("expected ReorgOrderMismatch, got {other:?}"),
    }
    assert_eq!(pool.engine.undo_depth(), 2, "nothing popped on order mismatch");
    assert!(pool.engine.is_spent(&[2u8; 32]), "B's nullifier still spent");

    // Correct tip-first order reverses cleanly.
    pool.disconnect_block_self(id_b).expect("tip-first disconnect of B");
    assert_eq!(pool.anchor(), anchor_after_a, "state returns to the post-A anchor");
    pool.disconnect_block_self(id_a).expect("then disconnect A");
    assert!(!pool.engine.is_spent(&[1u8; 32]), "A's nullifier un-spent");

    // Beyond the undo horizon → the caller must resync.
    assert_eq!(pool.disconnect_block_self(id_a), Err(TxError::ReorgBeyondUndoHorizon));
}
