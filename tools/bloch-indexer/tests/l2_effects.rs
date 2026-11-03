// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ledger effects of the native L2 kinds (0x12-0x16).
//!
//! The bookkeeping tests run in the default suite, without replay. The ignored
//! test replays a whole private chain with real signatures and real Groth16
//! settlements. Such a chain needs a build with forced gates, so its log and
//! manifest come from the environment.

use bloch_indexer::index::{ArchiveVerifier, Index};
use bloch_indexer::log::LogReader;
use bloch_indexer::model::*;
use bloch_pos_committee::attestation::SignatureVerifier;
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, BlockId, Body, VERSION_G4};
use bloch_pos_committee::transition::{
    FundingInput, L2DataAvailability, L2Deposit, L2WithdrawClaim, PosTransaction, TransferInput, TransferOutput,
};

/// The admission key length the L2 decoders insist on.
const ADMISSION_PQ_KEY_BYTES: usize = 3_749;

fn h32(n: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = n;
    a
}

/// The verifier the index replays with must judge proofs as the node does: the
/// bytes and the key of `keys.rs::both_proposal_and_validation_verify_real_l2_proofs`.
#[test]
fn replay_verifies_real_l2_settlement_proofs_like_the_node() {
    let values = include_bytes!("../../../crates/bloch-l2-proof/tests/fixtures/source-contract.values");
    let proof = include_bytes!("../../../crates/bloch-l2-proof/tests/fixtures/source-contract.proof");
    let key: [u8; 32] = values[22 + 6 * 32..22 + 7 * 32].try_into().unwrap();
    let policy = bloch_l2_proof::policy_commitment();
    assert!(ArchiveVerifier.verify_l2_settlement(&policy, &key, values, proof),
        "a real settlement proof must pass, or the first settlement halts the index");
    let mut corrupt = *proof;
    corrupt[12] ^= 1;
    assert!(!ArchiveVerifier.verify_l2_settlement(&policy, &key, values, &corrupt));
    assert!(!ArchiveVerifier.verify_l2_settlement(&[0u8; 32], &key, values, proof));
}

fn header(slot: u64, parent: [u8; 32], salt: u8) -> BlockHeaderV4 {
    BlockHeaderV4 {
        version: VERSION_G4,
        parent,
        state_root: h32(salt),
        body_root: [0u8; 32],
        slot,
        proposer_index: 0,
        randao_reveal: [0u8; 32],
        randao_mix: [0u8; 32],
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0u8; 32],
    }
}

fn envelope(h: BlockHeaderV4, txs: &[PosTransaction]) -> BlockEnvelope {
    BlockEnvelope {
        header: h,
        proposer_sig: vec![0u8; 16],
        body: Body { transactions: txs.iter().map(PosTransaction::canonical_bytes).collect(), attestations: vec![] },
    }
}

fn funding(op: OutPoint) -> Vec<FundingInput> {
    vec![FundingInput { txid: op.txid, vout: op.vout }]
}

fn deposit(from: OutPoint, amount_sat: u64, change: u64, to: [u8; 32]) -> PosTransaction {
    PosTransaction::L2Deposit(L2Deposit {
        network_domain: h32(0x91), funding_pubkey: vec![1; ADMISSION_PQ_KEY_BYTES], inputs: funding(from), amount_sat,
        recipient: [7; 20], change: TransferOutput { value: change, script_hash: to },
        tx_bytes: 1_000, tip_millisat_per_gas: 0, signature: vec![2; 4],
    })
}

fn data_availability(from: OutPoint, change: u64, to: [u8; 32]) -> PosTransaction {
    PosTransaction::L2DataAvailability(L2DataAvailability {
        network_domain: h32(0x91), funding_pubkey: vec![1; ADMISSION_PQ_KEY_BYTES], inputs: funding(from), l2_chain_id: 700770,
        l2_block_number: 1, payload: vec![0xc0], change: TransferOutput { value: change, script_hash: to },
        tx_bytes: 1_000, tip_millisat_per_gas: 0, signature: vec![2; 4],
    })
}

fn claim(from: OutPoint, sats: u64, recipient: [u8; 32], change: u64, to: [u8; 32]) -> PosTransaction {
    PosTransaction::L2WithdrawClaim(L2WithdrawClaim {
        network_domain: h32(0x91), funding_pubkey: vec![1; ADMISSION_PQ_KEY_BYTES], inputs: funding(from), l2_chain_id: 700770, index: 0,
        l1_recipient: recipient, sats, siblings: std::array::from_fn(|_| [0u8; 32]),
        release: TransferOutput { value: sats, script_hash: recipient },
        change: TransferOutput { value: change, script_hash: to },
        tx_bytes: 1_000, tip_millisat_per_gas: 0, attestation: None, signature: vec![2; 4],
    })
}

fn write_log(path: &std::path::Path, envs: &[BlockEnvelope]) {
    let mut out = Vec::new();
    for e in envs {
        let p = bloch_indexer::codec::encode_envelope(e);
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(&p);
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &out).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn net_history(ix: &Index, script: &[u8; 32]) -> i128 {
    ix.history.get(script).map_or(0, |rows| rows.iter().fold(0, |sum, row| match row.direction {
        Direction::In => sum + row.amount_sat as i128,
        Direction::Out => sum - row.amount_sat as i128,
    }))
}

const OPENING: u64 = 1_000;

/// Deposit, DA, claim, and then a spend of the claim's release, followed by a
/// reorg back across them. Balances, history, receipts and the rollback hold.
#[test]
fn deposit_da_claim_and_their_rollback_move_exactly_the_right_balances() {
    let genesis = h32(1);
    let (funder, recipient, payee) = (h32(0xF0), h32(0xE0), h32(0xD0));
    let coin = OutPoint { txid: h32(10), vout: 0 };
    let opening = vec![(coin, Utxo { value_sat: OPENING, script_hash: funder, created_height: 0 })];
    let mut ix = Index::new(genesis, opening, 64);

    // Deposit 700 with a fee of 10: 290 change, no output for the escrow.
    let d = deposit(coin, 700, 290, funder);
    let b1 = envelope(header(1, genesis, 1), std::slice::from_ref(&d));
    let d_change = OutPoint { txid: d.txid(), vout: 0 };
    // DA with a fee of 40: 250 change.
    let da = data_availability(d_change, 250, funder);
    let b2 = envelope(header(2, *BlockId::of(&b1.header).as_bytes(), 2), std::slice::from_ref(&da));
    let da_change = OutPoint { txid: da.txid(), vout: 0 };
    // Claim 300 from the escrow to the recipient, the relayer pays 50.
    let c = claim(da_change, 300, recipient, 200, funder);
    let b3 = envelope(header(3, *BlockId::of(&b2.header).as_bytes(), 3), std::slice::from_ref(&c));
    let release = OutPoint { txid: c.txid(), vout: 0 };
    let c_change = OutPoint { txid: c.txid(), vout: 1 };
    // The release is spendable like any other output.
    let spend = PosTransaction::Transfer {
        inputs: vec![TransferInput { txid: release.txid, vout: release.vout, pubkey: vec![0; 4], signature: vec![0; 4] }],
        outputs: vec![TransferOutput { value: 300, script_hash: payee }],
        tx_bytes: 1_000, tip_millisat_per_gas: 0,
    };
    let b4 = envelope(header(4, *BlockId::of(&b3.header).as_bytes(), 4), std::slice::from_ref(&spend));

    let dir = std::env::temp_dir().join(format!("bloch-indexer-l2-effects-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blocks.log");
    let all = [b1.clone(), b2.clone(), b3.clone(), b4.clone()];
    write_log(&path, &all);
    let mut reader = LogReader::open(&path).unwrap();
    ix.sync(&mut reader).unwrap();

    assert_eq!(ix.balance_of(&funder), 200);
    assert_eq!(ix.balance_of(&recipient), 0, "the recipient spent its release");
    assert_eq!(ix.balance_of(&payee), 300);
    assert_eq!(ix.eutxo_total_sat(), 500, "opening 1000 - escrow in 700 - fees 100 + escrow out 300");
    for script in [funder, recipient, payee] {
        assert_eq!(net_history(&ix, &script), ix.balance_of(&script) as i128);
    }
    let directions = |script: &[u8; 32]| ix.history[script].iter().map(|e| e.direction).collect::<Vec<_>>();
    assert_eq!(directions(&recipient), [Direction::In, Direction::Out]);

    let row = |kind: &str| ix.txs.iter().find(|t| t.kind.name() == kind).unwrap();
    let d_row = row("l2_deposit");
    assert_eq!((d_row.l2_escrow_in_sat, d_row.l2_escrow_out_sat, d_row.fee_sat), (700, 0, Some(10)));
    let da_row = row("l2_data_availability");
    assert_eq!((da_row.l2_escrow_in_sat, da_row.l2_escrow_out_sat, da_row.fee_sat), (0, 0, Some(40)));
    let c_row = row("l2_withdraw_claim");
    assert_eq!((c_row.l2_escrow_in_sat, c_row.l2_escrow_out_sat, c_row.fee_sat), (0, 300, Some(50)));
    assert_eq!(c_row.outputs, vec![(300, recipient), (200, funder)]);
    assert!(ix.utxo.contains_key(&c_change));

    // The public answers name the escrow movement on L2 kinds, and only there.
    let json = bloch_indexer::explorer::transaction(c_row).to_string();
    assert!(json.contains("\"l2_escrow_out_sat\":\"300\""), "{json}");
    let json = bloch_indexer::explorer::transaction(row("transfer")).to_string();
    assert!(!json.contains("l2_escrow"), "{json}");

    // A reorg that drops the claim and its spend restores what they consumed.
    write_log(&path, &all[..2]);
    assert!(reader.changed().unwrap());
    reader.reopen().unwrap();
    let (_, rolled) = ix.sync(&mut reader).unwrap();
    assert_eq!(rolled, 2);
    assert_eq!(ix.balance_of(&funder), 250);
    assert_eq!(ix.balance_of(&recipient), 0);
    assert_eq!(ix.balance_of(&payee), 0);
    assert!(ix.utxo.contains_key(&da_change) && !ix.utxo.contains_key(&release));
    assert_eq!(ix.eutxo_total_sat(), 250);
    for script in [funder, recipient, payee] {
        assert_eq!(net_history(&ix, &script), ix.balance_of(&script) as i128);
    }

    // And forward again onto the same chain.
    write_log(&path, &all);
    reader.reopen().unwrap();
    ix.sync(&mut reader).unwrap();
    assert_eq!((ix.balance_of(&funder), ix.balance_of(&payee), ix.eutxo_total_sat()), (200, 300, 500));
    std::fs::remove_dir_all(&dir).ok();
}

/// Every table a reader sees, for comparing an index that went through a reorg with one that did not.
fn assert_same_tables(ix: &Index, fresh: &Index, when: &str) {
    assert_eq!(ix.utxo, fresh.utxo, "{when}: utxo");
    assert_eq!(ix.all_outputs, fresh.all_outputs, "{when}: all_outputs");
    assert_eq!(ix.spent_at, fresh.spent_at, "{when}: spent_at");
    assert_eq!(ix.balance, fresh.balance, "{when}: balance");
    // A rollback leaves an empty set for a script it emptied; no answer reads it differently from an absent one.
    let non_empty = |i: &Index| i.by_script.iter().filter(|(_, set)| !set.is_empty()).map(|(k, v)| (*k, v.clone())).collect::<std::collections::HashMap<_, _>>();
    assert_eq!(non_empty(ix), non_empty(fresh), "{when}: by_script");
    assert_eq!(ix.history, fresh.history, "{when}: history");
    assert_eq!(ix.txs, fresh.txs, "{when}: txs");
    assert_eq!(ix.by_txid, fresh.by_txid, "{when}: by_txid");
    assert_eq!(ix.chain, fresh.chain, "{when}: chain");
    assert_eq!(ix.epochs, fresh.epochs, "{when}: epochs");
    assert_eq!(ix.participation, fresh.participation, "{when}: participation");
    assert_eq!(ix.eutxo_total_sat(), fresh.eutxo_total_sat(), "{when}: eutxo total");
    let escrow = |i: &Index, f: fn(&TxRow) -> u128| i.txs.iter().map(f).sum::<u128>();
    assert_eq!(escrow(ix, |t| t.l2_escrow_in_sat), escrow(fresh, |t| t.l2_escrow_in_sat), "{when}: escrow in");
    assert_eq!(escrow(ix, |t| t.l2_escrow_out_sat), escrow(fresh, |t| t.l2_escrow_out_sat), "{when}: escrow out");
}

/// An L1 reorg onto a competing branch at the same height and back, repeatedly. Same-slot replacement included: the
/// shape that a slot comparison misses. Nothing may count twice, compared table by table with a fresh index of the
/// branch. Bookkeeping only: no replay, these blocks carry no real signatures.
#[test]
fn switching_between_competing_branches_counts_nothing_twice() {
    let genesis = h32(1);
    let (funder, r1, r2) = (h32(0xF0), h32(0xE0), h32(0xE1));
    let coin = OutPoint { txid: h32(10), vout: 0 };
    let opening = vec![(coin, Utxo { value_sat: OPENING, script_hash: funder, created_height: 0 })];

    let d = deposit(coin, 700, 290, funder);
    let b1 = envelope(header(1, genesis, 1), std::slice::from_ref(&d));
    let shared = OutPoint { txid: d.txid(), vout: 0 };
    let id1 = *BlockId::of(&b1.header).as_bytes();

    // Branch A: a claim of 300 to r1, then more on top.
    let a_claim = claim(shared, 300, r1, 250, funder);
    let a2 = envelope(header(2, id1, 2), std::slice::from_ref(&a_claim));
    let a_da = data_availability(OutPoint { txid: a_claim.txid(), vout: 1 }, 200, funder);
    let a3 = envelope(header(3, *BlockId::of(&a2.header).as_bytes(), 3), std::slice::from_ref(&a_da));
    // Branch B: same slots, same height. The funder's coin pays a data record, and a smaller claim goes to r2.
    let b_da = data_availability(shared, 280, funder);
    let b2 = envelope(header(2, id1, 12), std::slice::from_ref(&b_da));
    let b_claim = claim(OutPoint { txid: b_da.txid(), vout: 0 }, 100, r2, 270, funder);
    let b3 = envelope(header(3, *BlockId::of(&b2.header).as_bytes(), 13), std::slice::from_ref(&b_claim));

    let dir = std::env::temp_dir().join(format!("bloch-indexer-l2-branches-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blocks.log");
    let fresh = |blocks: &[BlockEnvelope], name: &str| {
        let p = dir.join(name);
        write_log(&p, blocks);
        let mut ix = Index::new(genesis, opening.clone(), 64);
        ix.sync(&mut LogReader::open(&p).unwrap()).unwrap();
        ix
    };
    let branch_a = [b1.clone(), a2, a3];
    let branch_b = [b1, b2, b3];
    let fresh_a = fresh(&branch_a, "a.log");
    let fresh_b = fresh(&branch_b, "b.log");
    assert_eq!(fresh_a.balance_of(&r1), 300);
    assert_eq!(fresh_b.balance_of(&r2), 100);

    write_log(&path, &branch_a);
    let mut reader = LogReader::open(&path).unwrap();
    let mut ix = Index::new(genesis, opening.clone(), 64);
    ix.sync(&mut reader).unwrap();
    assert_same_tables(&ix, &fresh_a, "first A");
    for round in 0..5 {
        write_log(&path, &branch_b);
        reader.reopen().unwrap();
        assert_eq!(ix.sync(&mut reader).unwrap(), (2, 2));
        assert_same_tables(&ix, &fresh_b, &format!("round {round}, B"));
        assert_eq!(ix.balance_of(&r1), 0, "the orphaned claim is gone");
        write_log(&path, &branch_a);
        reader.reopen().unwrap();
        assert_eq!(ix.sync(&mut reader).unwrap(), (2, 2));
        assert_same_tables(&ix, &fresh_a, &format!("round {round}, A"));
        assert_eq!(ix.balance_of(&r2), 0, "the orphaned claim is gone");
    }
    assert_eq!(ix.stats.reorgs_handled, 10);
    std::fs::remove_dir_all(&dir).ok();
}

/// A zero change value creates no output (consensus: `change.value > 0`). A
/// settlement touches no eUTXO and has a fee of zero.
#[test]
fn zero_change_creates_no_output_and_a_claim_can_have_none() {
    let genesis = h32(1);
    let (funder, recipient) = (h32(0xF0), h32(0xE0));
    let a = OutPoint { txid: h32(10), vout: 0 };
    let b = OutPoint { txid: h32(11), vout: 0 };
    let mut ix = Index::new(genesis, vec![
        (a, Utxo { value_sat: 100, script_hash: funder, created_height: 0 }),
        (b, Utxo { value_sat: 5, script_hash: funder, created_height: 0 }),
    ], 64);
    let d = deposit(a, 99, 0, funder);
    let c = claim(b, 40, recipient, 0, funder);
    ix.apply(&envelope(header(1, genesis, 1), &[d.clone(), c.clone()]), 0);
    assert_eq!(ix.balance_of(&funder), 0);
    assert_eq!(ix.balance_of(&recipient), 40);
    assert!(!ix.all_outputs.contains_key(&OutPoint { txid: d.txid(), vout: 0 }));
    assert!(!ix.all_outputs.contains_key(&OutPoint { txid: c.txid(), vout: 1 }));
    assert_eq!(ix.txs[0].fee_sat, Some(1));
    assert_eq!(ix.txs[1].fee_sat, Some(5));
}

/// The whole private chain, replayed with real signatures and proofs. Needs an
/// indexer built with the private chain's forced gates:
/// `BLOCH_INDEXER_PRIVATE_LOG=… BLOCH_INDEXER_PRIVATE_MANIFEST=… cargo test -p
/// bloch-indexer --test l2_effects -- --ignored`
#[test]
#[ignore = "needs a private chain log and a build with its forced gates"]
fn a_private_chain_with_every_l2_kind_matches_the_utxo_set_after_every_block() {
    let log = std::env::var_os("BLOCH_INDEXER_PRIVATE_LOG").expect("BLOCH_INDEXER_PRIVATE_LOG");
    let manifest = std::env::var_os("BLOCH_INDEXER_PRIVATE_MANIFEST").expect("BLOCH_INDEXER_PRIVATE_MANIFEST");
    let report = bloch_indexer::audit::audit_log(log.as_ref(), manifest.as_ref(), std::path::Path::new("/nonexistent"), 1).unwrap();
    println!("{}", report.describe());
    report.require_all_l2_kinds().unwrap();
    assert_eq!(report.comparisons, report.blocks + 1, "compared at genesis and after every block");
}
