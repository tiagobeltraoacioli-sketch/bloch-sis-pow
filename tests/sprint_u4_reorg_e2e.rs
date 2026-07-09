//! Sprint U.4 — End-to-end harness for audit finding C-1.
//!
//! U.4 wires the reorg primitives from U.1–U.3 into `accept_block` in the
//! bin crate (`src/main.rs`). Integration tests cannot link against the bin
//! crate directly, so instead of re-invoking `accept_block`, this harness
//! replays the **same disposition-based dispatch** that `accept_block` runs —
//! classify (old_tip, new_tip, selected_parent) into Extension / ForkLoser /
//! Reorg, then route through the public primitives.
//!
//! The classifier logic under test is intentionally duplicated from the
//! match expression in `accept_block` (src/main.rs, Sprint U.4). If either
//! copy is changed, the other must be updated in lockstep. The
//! `classify_matches_accept_block_contract` test documents the expected
//! truth table and serves as a canary.
//!
//! # Scenarios covered
//!
//!   * `multi_block_extension_sequence`: 3 blocks mined in order, each the
//!     selected tip's child. Exercises the Extension branch repeatedly and
//!     confirms every block produces a readable UndoData record.
//!
//!   * `fork_loser_preserves_main_chain_state`: after chain A is applied,
//!     a sibling block B1 is observed but does not win the tip. State must
//!     be byte-identical to the pre-B1 world — B1 exists in CF_BLOCKS only.
//!
//!   * `fork_then_reorg_flips_tip_and_converges_utxo`: chain A of depth 2
//!     is applied; chain B of depth 3 (with higher blue_work) triggers a
//!     reorg at accept of B3. Final UTXO set contains only B-chain outputs.
//!
//!   * `double_reorg_back_and_forth_is_stable`: A(2) → reorg → B(3) →
//!     reorg → A(4). After two reorgs, the UTXO set matches what a fresh
//!     node syncing only A(4) would have. Byte-for-byte invariance is the
//!     safety property; this is the test that would have caught a leak of
//!     B-chain UTXOs back into the A-chain view.
//!
//!   * `classify_matches_accept_block_contract`: pure logic test of the
//!     classifier, covering each arm of the match including the
//!     `None → Some` (post-genesis) path.

use std::collections::HashMap;

use bloch::consensus::{BlockHash, GhostDAG, GhostdagData};
use bloch::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
use bloch::mempool::Mempool;
use bloch::reorg::{
    apply_block_utxo_mutations, compute_reorg_plan, execute_reorg,
};
use bloch::storage::Storage;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────────────
// Disposition classifier — mirror of the one in src/main.rs accept_block.
//
// Keep this in sync with the match expression there. The contract is:
//
//   old == None, new == Some(block_hash)                 → Extension (first post-genesis)
//   old == Some(x), new == Some(x)                       → ForkLoser  (tip didn't move)
//   old == Some(x), new == Some(block_hash), parent == x → Extension
//   old == Some(x), new == Some(block_hash), parent != x → Reorg
//   anything else                                        → Unexpected
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    Extension,
    ForkLoser,
    Reorg,
    Unexpected,
}

fn classify(
    old_tip:         Option<BlockHash>,
    new_tip:         Option<BlockHash>,
    block_hash:      BlockHash,
    selected_parent: Option<BlockHash>,
) -> Disposition {
    match (old_tip, new_tip) {
        (None, Some(t)) if t == block_hash => Disposition::Extension,
        (Some(old), Some(new)) if new == old => Disposition::ForkLoser,
        (Some(old), Some(new)) if new == block_hash => {
            if selected_parent == Some(old) {
                Disposition::Extension
            } else {
                Disposition::Reorg
            }
        }
        _ => Disposition::Unexpected,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures — same shape as sprint_u3_reorg.rs so tests read similarly.
// ─────────────────────────────────────────────────────────────────────────────

fn mk_storage() -> (TempDir, Storage) {
    let tmp = TempDir::new().unwrap();
    let s = Storage::open(tmp.path()).unwrap();
    (tmp, s)
}

fn mk_dag_data(selected_parent: Option<BlockHash>, height: u64) -> GhostdagData {
    GhostdagData {
        blue_score:           height,
        blue_work:            height as u128,
        selected_parent,
        mergeset_blues:       vec![],
        mergeset_reds:        vec![],
        blues_anticone_sizes: HashMap::new(),
        parents:              selected_parent.map(|p| vec![p]).unwrap_or_default(),
        height,
        timestamp:             1_700_000_000 + height,
    }
}

fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
    TxOutput { value, script_pubkey: vec![addr_byte; 20] }
}

fn mk_block_at(height: u64, nonce_tag: u64, txs: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![],
            merkle_root: bloch::core::MerkleRoot::ZERO,
            timestamp:   1_700_000_000 + height,
            bits:        0x1d00ffff,
            nonce:       nonce_tag,
        },
        transactions: txs,
        blue_score:   height,
        height,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    }
}

fn mk_coinbase(addr_byte: u8, value: u64, height: u64, tag: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: 0xffffffff,
            // Include `tag` so two coinbases at the same height with different
            // addresses still hash to distinct txids even when value matches.
            script_sig: format!("cb:{}:{}:{}", height, addr_byte, tag).into_bytes(),
            sequence:   0xffffffff,
        }],
        outputs: vec![mk_output(addr_byte, value)],
        locktime: 0,
    }
}

/// Simulates the state-application phase of `accept_block` — given a block
/// plus the DAG state before and after its insertion, dispatch to the same
/// primitives main.rs dispatches to. Returns the final tip after the call.
fn simulate_accept(
    store:           &Storage,
    mempool:         &Mempool,
    dag:             &GhostDAG,
    old_tip:         Option<BlockHash>,
    new_tip:         Option<BlockHash>,
    block:           &Block,
) -> Result<Option<BlockHash>, String> {
    let block_hash = block.block_hash();
    let selected_parent = dag.store.get(&block_hash)
        .and_then(|d| d.selected_parent);

    // Persist block body unconditionally (matches main.rs:871).
    store.put_block(block).map_err(|e| e.to_string())?;

    match classify(old_tip, new_tip, block_hash, selected_parent) {
        Disposition::ForkLoser => {
            // No state change — mirrors main.rs ForkLoser arm.
            Ok(old_tip)
        }
        Disposition::Extension => {
            apply_block_utxo_mutations(store, block)?;
            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            Ok(Some(block_hash))
        }
        Disposition::Reorg => {
            let old = old_tip.expect("reorg implies Some(old)");
            let new = new_tip.expect("reorg implies Some(new)");
            let plan = compute_reorg_plan(dag, &old, &new)
                .ok_or_else(|| "compute_reorg_plan returned None in Reorg case".to_string())?;
            let _outcome = execute_reorg(store, mempool, &plan)?;
            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            Ok(Some(new))
        }
        Disposition::Unexpected => {
            // No-op, as in main.rs. Caller keeps the previous tip view.
            Ok(old_tip)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn classify_matches_accept_block_contract() {
    let block_hash   = [0x11u8; 32];
    let other        = [0x22u8; 32];
    let old_tip      = [0x33u8; 32];

    // Post-genesis first block: no old tip, new tip is this block.
    assert_eq!(
        classify(None, Some(block_hash), block_hash, Some(old_tip)),
        Disposition::Extension,
        "first block after genesis must be Extension"
    );

    // Tip didn't move: Same old/new value. This arm short-circuits regardless
    // of what block_hash or selected_parent are.
    assert_eq!(
        classify(Some(old_tip), Some(old_tip), block_hash, Some(old_tip)),
        Disposition::ForkLoser,
        "old==new must classify as ForkLoser"
    );

    // Normal extension: new tip IS this block AND its selected_parent IS old tip.
    assert_eq!(
        classify(Some(old_tip), Some(block_hash), block_hash, Some(old_tip)),
        Disposition::Extension,
        "new tip with selected_parent==old must be Extension"
    );

    // Reorg: new tip IS this block, but its selected_parent is NOT old tip.
    assert_eq!(
        classify(Some(old_tip), Some(block_hash), block_hash, Some(other)),
        Disposition::Reorg,
        "new tip with selected_parent!=old must be Reorg"
    );

    // Reorg with no selected_parent data (defensive path — classifier treats
    // as "not old", goes to Reorg; compute_reorg_plan will then safely refuse).
    assert_eq!(
        classify(Some(old_tip), Some(block_hash), block_hash, None),
        Disposition::Reorg,
        "missing selected_parent must fall to Reorg (safe-fail)"
    );

    // Unexpected: new tip is someone else entirely — not old, not this block.
    // Can't happen with a healthy GhostDAG, but classifier must route to the
    // no-op branch rather than corrupt state.
    assert_eq!(
        classify(Some(old_tip), Some(other), block_hash, Some(old_tip)),
        Disposition::Unexpected,
        "tip moved to a block other than the one we're accepting → Unexpected"
    );

    // Unexpected: None → None (DAG produced no tip after insert — shouldn't
    // happen, but must be safely a no-op).
    assert_eq!(
        classify(None, None, block_hash, None),
        Disposition::Unexpected,
    );
}

#[test]
fn multi_block_extension_sequence() {
    // Simulate a node mining/receiving 3 consecutive blocks on a single chain.
    // Each step: old_tip = previous block, new_tip = this block, parent = old_tip.
    // Every step must be an Extension; UTXO and undo data must be persisted per
    // block.
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();
    let mut dag = GhostDAG::with_default_k();

    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    // Block 1 — first post-genesis.
    let b1 = mk_block_at(1, 1001, vec![mk_coinbase(0xA1, 500_000_000, 1, 0x01)]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    let tip = simulate_accept(&store, &mempool, &dag, Some(g), Some(b1h), &b1).unwrap();
    assert_eq!(tip, Some(b1h), "after B1 tip must be B1");

    // Block 2.
    let b2 = mk_block_at(2, 1002, vec![mk_coinbase(0xA2, 500_000_000, 2, 0x02)]);
    let b2h = b2.block_hash();
    dag.store.insert(b2h, mk_dag_data(Some(b1h), 2));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(b2h), &b2).unwrap();
    assert_eq!(tip, Some(b2h));

    // Block 3.
    let b3 = mk_block_at(3, 1003, vec![mk_coinbase(0xA3, 500_000_000, 3, 0x03)]);
    let b3h = b3.block_hash();
    dag.store.insert(b3h, mk_dag_data(Some(b2h), 3));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(b3h), &b3).unwrap();
    assert_eq!(tip, Some(b3h));

    // Every block's coinbase must be a spendable UTXO.
    for (cb_idx, tag) in [(0xA1u8, 0x01u8), (0xA2, 0x02), (0xA3, 0x03)].iter().enumerate() {
        let h = (cb_idx + 1) as u64;
        let cb_txid = mk_coinbase(tag.0, 500_000_000, h, tag.1).txid();
        assert!(store.get_utxo(&cb_txid, 0).unwrap().is_some(),
            "coinbase for block h={} must be in UTXO set", h);
    }

    // Every block must have a persisted undo record (required for reorg).
    for h in [b1h, b2h, b3h] {
        assert!(store.get_undo_data(&h).unwrap().is_some(),
            "undo record must exist for every extended block");
    }
}

#[test]
fn fork_loser_preserves_main_chain_state() {
    // A1 extends genesis and becomes the tip. Then a sibling B1 (same height,
    // different hash, not selected) arrives. Disposition must be ForkLoser:
    //   - A1's coinbase UTXO stays.
    //   - B1's coinbase UTXO must NOT be created.
    //   - B1 is still persisted in CF_BLOCKS (so a future reorg can bring it in).
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();
    let mut dag = GhostDAG::with_default_k();

    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    let a1 = mk_block_at(1, 1001, vec![mk_coinbase(0xA1, 500_000_000, 1, 0x01)]);
    let a1h = a1.block_hash();
    dag.store.insert(a1h, mk_dag_data(Some(g), 1));
    let tip = simulate_accept(&store, &mempool, &dag, Some(g), Some(a1h), &a1).unwrap();
    assert_eq!(tip, Some(a1h));

    // B1 — same height, different address, different nonce → different hash.
    // GhostDAG doesn't actually select it (simulate by leaving new_tip == a1h).
    let b1 = mk_block_at(1, 9999, vec![mk_coinbase(0xB1, 500_000_000, 1, 0x01)]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    assert_ne!(a1h, b1h, "test fixture must produce distinct hashes");

    let tip_after = simulate_accept(&store, &mempool, &dag, Some(a1h), Some(a1h), &b1).unwrap();
    assert_eq!(tip_after, Some(a1h), "ForkLoser must leave tip unchanged");

    // A1 coinbase still exists.
    let a1_cb = mk_coinbase(0xA1, 500_000_000, 1, 0x01).txid();
    assert!(store.get_utxo(&a1_cb, 0).unwrap().is_some(),
        "A1 coinbase UTXO must survive fork-loser accept");

    // B1 coinbase must NOT exist — ForkLoser skipped apply_block_utxo_mutations.
    let b1_cb = mk_coinbase(0xB1, 500_000_000, 1, 0x01).txid();
    assert!(store.get_utxo(&b1_cb, 0).unwrap().is_none(),
        "B1 coinbase UTXO must NOT exist — fork loser is not applied");

    // B1 body IS persisted (required for future reorg).
    assert!(store.get_block(&b1h).unwrap().is_some(),
        "B1 body must be persisted even as fork-loser");

    // B1 must NOT have an undo record — undo is created only on apply.
    assert!(store.get_undo_data(&b1h).unwrap().is_none(),
        "fork-loser must not produce undo data");
}

#[test]
fn fork_then_reorg_flips_tip_and_converges_utxo() {
    // Scenario:
    //
    //   G → A1 → A2 (chain A, applied)
    //    \→ B1 → B2 → B3 (chain B, arrives in order, B3 triggers reorg)
    //
    // Expected after B3's accept:
    //   * A1, A2 coinbase UTXOs gone
    //   * B1, B2, B3 coinbase UTXOs present
    //   * Tip is B3
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();
    let mut dag = GhostDAG::with_default_k();

    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    // ── Chain A (applied) ─────────────────────────────────────────────
    let a1 = mk_block_at(1, 1001, vec![mk_coinbase(0xA1, 500_000_000, 1, 0x01)]);
    let a1h = a1.block_hash();
    dag.store.insert(a1h, mk_dag_data(Some(g), 1));
    let tip = simulate_accept(&store, &mempool, &dag, Some(g), Some(a1h), &a1).unwrap();

    let a2 = mk_block_at(2, 1002, vec![mk_coinbase(0xA2, 500_000_000, 2, 0x02)]);
    let a2h = a2.block_hash();
    dag.store.insert(a2h, mk_dag_data(Some(a1h), 2));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(a2h), &a2).unwrap();
    assert_eq!(tip, Some(a2h));

    // ── Chain B arrives: B1, B2 as fork-losers (tip stays at A2) ─────
    let b1 = mk_block_at(1, 2001, vec![mk_coinbase(0xB1, 500_000_000, 1, 0x11)]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(a2h), &b1).unwrap();
    assert_eq!(tip, Some(a2h), "B1 arriving does not dislodge A2");

    let b2 = mk_block_at(2, 2002, vec![mk_coinbase(0xB2, 500_000_000, 2, 0x12)]);
    let b2h = b2.block_hash();
    dag.store.insert(b2h, mk_dag_data(Some(b1h), 2));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(a2h), &b2).unwrap();
    assert_eq!(tip, Some(a2h), "B2 arriving does not dislodge A2 — still losing");

    // Sanity check: A-chain UTXOs still here, B-chain UTXOs absent.
    let a1_cb = mk_coinbase(0xA1, 500_000_000, 1, 0x01).txid();
    let b1_cb = mk_coinbase(0xB1, 500_000_000, 1, 0x11).txid();
    assert!(store.get_utxo(&a1_cb, 0).unwrap().is_some());
    assert!(store.get_utxo(&b1_cb, 0).unwrap().is_none());

    // ── B3 arrives — chain B now has more blue_work, tip flips ───────
    let b3 = mk_block_at(3, 2003, vec![mk_coinbase(0xB3, 500_000_000, 3, 0x13)]);
    let b3h = b3.block_hash();
    dag.store.insert(b3h, mk_dag_data(Some(b2h), 3));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(b3h), &b3).unwrap();
    assert_eq!(tip, Some(b3h), "B3 wins — tip flipped");

    // After reorg: A-chain coinbases gone, B-chain coinbases present.
    let a2_cb = mk_coinbase(0xA2, 500_000_000, 2, 0x02).txid();
    let b2_cb = mk_coinbase(0xB2, 500_000_000, 2, 0x12).txid();
    let b3_cb = mk_coinbase(0xB3, 500_000_000, 3, 0x13).txid();

    assert!(store.get_utxo(&a1_cb, 0).unwrap().is_none(), "A1 coinbase must be rolled back");
    assert!(store.get_utxo(&a2_cb, 0).unwrap().is_none(), "A2 coinbase must be rolled back");
    assert!(store.get_utxo(&b1_cb, 0).unwrap().is_some(), "B1 coinbase must be applied");
    assert!(store.get_utxo(&b2_cb, 0).unwrap().is_some(), "B2 coinbase must be applied");
    assert!(store.get_utxo(&b3_cb, 0).unwrap().is_some(), "B3 coinbase must be applied");

    // Undo records: A-chain gone (consumed by rollback), B-chain present.
    assert!(store.get_undo_data(&a1h).unwrap().is_none(), "A1 undo consumed by rollback");
    assert!(store.get_undo_data(&a2h).unwrap().is_none(), "A2 undo consumed by rollback");
    assert!(store.get_undo_data(&b1h).unwrap().is_some(), "B1 undo exists after apply");
    assert!(store.get_undo_data(&b2h).unwrap().is_some(), "B2 undo exists after apply");
    assert!(store.get_undo_data(&b3h).unwrap().is_some(), "B3 undo exists after apply");
}

#[test]
fn double_reorg_back_and_forth_is_stable() {
    // Scenario — worst-case flip-flop:
    //
    //   Phase 1: apply A1, A2.
    //   Phase 2: apply B1, B2, B3 → reorg flips to B.
    //   Phase 3: extend A side: A3, A4 arrive as losers, then A5 wins.
    //            Reorg flips back to A.
    //
    // Final UTXO state must match what a fresh node would have after
    // only ever seeing A1..A5 — no B-chain UTXOs must leak through.
    let (_tmp, store) = mk_storage();
    let mempool = Mempool::new();
    let mut dag = GhostDAG::with_default_k();

    let g = [0u8; 32];
    dag.store.insert(g, mk_dag_data(None, 0));

    // Build & apply A1, A2.
    let a1 = mk_block_at(1, 1001, vec![mk_coinbase(0xA1, 500_000_000, 1, 0x01)]);
    let a1h = a1.block_hash();
    dag.store.insert(a1h, mk_dag_data(Some(g), 1));
    let tip = simulate_accept(&store, &mempool, &dag, Some(g), Some(a1h), &a1).unwrap();

    let a2 = mk_block_at(2, 1002, vec![mk_coinbase(0xA2, 500_000_000, 2, 0x02)]);
    let a2h = a2.block_hash();
    dag.store.insert(a2h, mk_dag_data(Some(a1h), 2));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(a2h), &a2).unwrap();

    // Phase 2: B1..B3 arrive; B3 triggers first reorg A→B.
    let b1 = mk_block_at(1, 2001, vec![mk_coinbase(0xB1, 500_000_000, 1, 0x11)]);
    let b1h = b1.block_hash();
    dag.store.insert(b1h, mk_dag_data(Some(g), 1));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(a2h), &b1).unwrap();

    let b2 = mk_block_at(2, 2002, vec![mk_coinbase(0xB2, 500_000_000, 2, 0x12)]);
    let b2h = b2.block_hash();
    dag.store.insert(b2h, mk_dag_data(Some(b1h), 2));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(a2h), &b2).unwrap();

    let b3 = mk_block_at(3, 2003, vec![mk_coinbase(0xB3, 500_000_000, 3, 0x13)]);
    let b3h = b3.block_hash();
    dag.store.insert(b3h, mk_dag_data(Some(b2h), 3));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(b3h), &b3).unwrap();
    assert_eq!(tip, Some(b3h), "after first reorg tip is on chain B");

    // Phase 3: A3, A4 arrive (extending A2, still losing vs B3). Then A5
    // extends A4 and makes the A-chain's blue_work beat B3 → second reorg.
    let a3 = mk_block_at(3, 1003, vec![mk_coinbase(0xA3, 500_000_000, 3, 0x03)]);
    let a3h = a3.block_hash();
    dag.store.insert(a3h, mk_dag_data(Some(a2h), 3));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(b3h), &a3).unwrap();

    let a4 = mk_block_at(4, 1004, vec![mk_coinbase(0xA4, 500_000_000, 4, 0x04)]);
    let a4h = a4.block_hash();
    dag.store.insert(a4h, mk_dag_data(Some(a3h), 4));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(b3h), &a4).unwrap();
    assert_eq!(tip, Some(b3h), "A3/A4 still losing while B3 is tip");

    let a5 = mk_block_at(5, 1005, vec![mk_coinbase(0xA5, 500_000_000, 5, 0x05)]);
    let a5h = a5.block_hash();
    dag.store.insert(a5h, mk_dag_data(Some(a4h), 5));
    let tip = simulate_accept(&store, &mempool, &dag, tip, Some(a5h), &a5).unwrap();
    assert_eq!(tip, Some(a5h), "second reorg: tip flipped back to chain A");

    // Final state check — A-chain UTXOs present, B-chain UTXOs absent.
    for (addr, h, tag) in [(0xA1u8, 1u64, 0x01u8), (0xA2, 2, 0x02), (0xA3, 3, 0x03), (0xA4, 4, 0x04), (0xA5, 5, 0x05)] {
        let txid = mk_coinbase(addr, 500_000_000, h, tag).txid();
        assert!(store.get_utxo(&txid, 0).unwrap().is_some(),
            "A{} coinbase UTXO must be present after double reorg", h);
    }
    for (addr, h, tag) in [(0xB1u8, 1u64, 0x11u8), (0xB2, 2, 0x12), (0xB3, 3, 0x13)] {
        let txid = mk_coinbase(addr, 500_000_000, h, tag).txid();
        assert!(store.get_utxo(&txid, 0).unwrap().is_none(),
            "B{} coinbase UTXO must be absent after flip back to A", h);
    }

    // A-chain undo records should all exist (nothing has rolled back A).
    for h in [a1h, a2h, a3h, a4h, a5h] {
        assert!(store.get_undo_data(&h).unwrap().is_some(),
            "A-chain block must retain its undo record");
    }
    // B-chain undo records should NOT exist (consumed by the second reorg's
    // rollback phase).
    for h in [b1h, b2h, b3h] {
        assert!(store.get_undo_data(&h).unwrap().is_none(),
            "B-chain undo must be consumed by rollback");
    }
}
