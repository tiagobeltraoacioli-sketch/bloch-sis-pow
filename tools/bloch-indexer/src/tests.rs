// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests, each written so it can fail.
//!
//! Every property here is checked by **violating** it as well as satisfying it:
//! a test that only ever sees the good case proves that the code runs, not that
//! the code is right.

use crate::index::Index;
use crate::log::{LogReader, ScanEnd};
use crate::model::*;

use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body, BlockId, VERSION_G4};
use bloch_pos_committee::transition::{
    PosTransaction, TransferInput, TransferOutput,
};

fn h32(n: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = n;
    a
}

fn header(slot: u64, parent: [u8; 32], proposer: u32, salt: u8) -> BlockHeaderV4 {
    BlockHeaderV4 {
        version: VERSION_G4,
        parent,
        // The salt is what makes two blocks at the same slot DIFFERENT blocks,
        // which is the reorg shape a slot-only comparison would miss.
        state_root: h32(salt),
        body_root: [0u8; 32],
        slot,
        proposer_index: proposer,
        randao_reveal: [0u8; 32],
        randao_mix: [0u8; 32],
        justified_root: [0u8; 32],
        finalized_root: [0u8; 32],
        attestation_root: [0u8; 32],
        coherence_root: [0u8; 32],
    }
}

fn att(validator: u32, slot: u64, target_epoch: u64) -> Attestation {
    Attestation {
        data: AttestationData {
            slot,
            head: [0u8; 32],
            source_epoch: target_epoch.saturating_sub(1),
            source_root: [0u8; 32],
            target_epoch,
            target_root: [0u8; 32],
        },
        validator,
        signature: vec![0u8; 8],
    }
}

fn transfer(inputs: Vec<(([u8; 32], u32))>, outputs: Vec<(u64, [u8; 32])>) -> PosTransaction {
    PosTransaction::Transfer {
        inputs: inputs
            .into_iter()
            .map(|(txid, vout)| TransferInput {
                txid,
                vout,
                pubkey: vec![0u8; 4],
                signature: vec![0u8; 4],
            })
            .collect(),
        outputs: outputs
            .into_iter()
            .map(|(value, script_hash)| TransferOutput { value, script_hash })
            .collect(),
        tx_bytes: 1_000,
        tip_millisat_per_gas: 0,
    }
}

fn envelope(h: BlockHeaderV4, txs: Vec<PosTransaction>, atts: Vec<Attestation>) -> BlockEnvelope {
    BlockEnvelope {
        header: h,
        proposer_sig: vec![0u8; 16],
        body: Body {
            transactions: txs.iter().map(PosTransaction::canonical_bytes).collect(),
            attestations: atts,
        },
    }
}

fn write_log(path: &std::path::Path, envs: &[BlockEnvelope]) {
    let mut out = Vec::new();
    for e in envs {
        let p = crate::codec::encode_envelope(e);
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(&p);
    }
    // A reorg replaces the file by rename, so the tests do too — an in-place
    // rewrite would let a reader miss the change and the test would pass for
    // the wrong reason.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &out).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bloch-indexer-test-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ── The frame table ─────────────────────────────────────────────────────────

/// The property `e904a6db` pins for the node's table, checked for this one: the
/// answer served from the frame table equals the answer from a walk, **on a log
/// whose slots do not increase**.
///
/// This is why neither implementation binary-searches. Slots are strictly
/// increasing when the engine writes the log, but that is an engine invariant
/// and not a property of the format, and the cost of assuming it is silently
/// wrong answers on any log that violates it.
#[test]
fn indexed_and_scanned_answers_are_identical_on_a_non_monotonic_log() {
    let d = tmpdir("nonmono");
    let p = d.join("blocks.log");
    let slots = [4u64, 1, 9, 9, 2, 40, 7];
    let envs: Vec<BlockEnvelope> = slots
        .iter()
        .enumerate()
        .map(|(i, s)| envelope(header(*s, h32(i as u8), 0, i as u8), vec![], vec![]))
        .collect();
    write_log(&p, &envs);

    let reader = LogReader::open(&p).unwrap();
    assert_eq!(reader.len(), slots.len());
    assert_eq!(reader.scan_end(), ScanEnd::Clean);

    for after in 0..12u64 {
        for limit in 1..8usize {
            let indexed: Vec<u64> =
                reader.frames_after(after, limit).iter().map(|f| f.slot).collect();
            let scanned: Vec<u64> =
                slots.iter().copied().filter(|s| *s > after).take(limit).collect();
            assert_eq!(indexed, scanned, "after={after} limit={limit}");
        }
    }

    // The control: the assumption the table refuses to make. If the lookup had
    // been written as skip_while/take_while over a "sorted" table, this is the
    // case it would get wrong — and it must actually differ, or the test above
    // proves nothing.
    let wrong: Vec<u64> = slots
        .iter()
        .copied()
        .skip_while(|s| *s <= 1)
        .take_while(|s| *s > 1)
        .take(3)
        .collect();
    let right: Vec<u64> = reader.frames_after(1, 3).iter().map(|f| f.slot).collect();
    assert_ne!(wrong, right, "the monotonicity assumption must be observably wrong here");
    let _ = std::fs::remove_dir_all(&d);
}

/// A frame whose declared length runs past EOF is a crash mid-append, not
/// corruption. Every frame before it must still be readable.
#[test]
fn a_torn_trailing_frame_is_dropped_and_the_rest_survives() {
    let d = tmpdir("torn");
    let p = d.join("blocks.log");
    let envs: Vec<BlockEnvelope> =
        (0..4u8).map(|i| envelope(header(i as u64 + 1, h32(i), 0, i), vec![], vec![])).collect();
    write_log(&p, &envs);
    let whole = std::fs::read(&p).unwrap();
    // Cut the last frame in half.
    let cut = whole.len() - 60;
    std::fs::write(&p, &whole[..cut]).unwrap();

    let reader = LogReader::open(&p).unwrap();
    assert_eq!(reader.len(), 3, "three whole frames survive");
    assert_eq!(reader.scan_end(), ScanEnd::TornTrailingFrame);
    let _ = std::fs::remove_dir_all(&d);
}

/// The one sentinel the format has. A length prefix that is wrong leaves
/// nothing to resync to, so the reader must say so rather than mis-parse.
#[test]
fn a_frame_that_does_not_start_with_version_g4_is_refused() {
    let d = tmpdir("badver");
    let p = d.join("blocks.log");
    let envs = vec![envelope(header(1, h32(0), 0, 0), vec![], vec![])];
    write_log(&p, &envs);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[4] ^= 0xFF; // corrupt the version's low byte
    std::fs::write(&p, &bytes).unwrap();
    let e = match LogReader::open(&p) {
        Err(e) => e,
        Ok(_) => panic!("a corrupted version field must be refused, not parsed"),
    };
    assert!(e.to_string().contains("VERSION_G4"), "{e}");
    let _ = std::fs::remove_dir_all(&d);
}

// ── Reorgs ──────────────────────────────────────────────────────────────────

/// The whole point. Build a chain that pays Carol, replace its last blocks with
/// a chain that pays Dave instead, and require that the index ends up holding
/// exactly what a fresh build of the new log holds — Carol at zero, with no
/// stale history, and Dave paid.
///
/// The replacement keeps the SAME SLOTS, which is the case a slot-only
/// comparison cannot see.
#[test]
fn a_reorg_that_reuses_the_same_slots_still_converges() {
    let d = tmpdir("reorg");
    let p = d.join("blocks.log");

    let alice = h32(0xA1);
    let carol = h32(0xC0);
    let dave = h32(0xDA);
    let coin = ([7u8; 32], 0u32);

    let genesis_id = h32(0x00);
    let opening = vec![(
        OutPoint { txid: coin.0, vout: coin.1 },
        Utxo { value_sat: 1_000_000, script_hash: alice, created_height: 0 },
    )];

    // Chain A: block 1 empty, block 2 pays Carol.
    let b1 = envelope(header(1, genesis_id, 0, 1), vec![], vec![att(3, 1, 0)]);
    let b1_id = *BlockId::of(&b1.header).as_bytes();
    let pay_carol = transfer(vec![coin], vec![(999_000, carol)]);
    let b2a = envelope(header(2, b1_id, 1, 2), vec![pay_carol], vec![att(4, 2, 0)]);

    // Chain B: same slot 2, different block, pays Dave.
    let pay_dave = transfer(vec![coin], vec![(998_000, dave)]);
    let b2b = envelope(header(2, b1_id, 1, 99), vec![pay_dave], vec![att(5, 2, 0)]);
    assert_ne!(
        *BlockId::of(&b2a.header).as_bytes(),
        *BlockId::of(&b2b.header).as_bytes(),
        "the two candidates must be different blocks at the same slot"
    );

    write_log(&p, &[b1.clone(), b2a]);
    let mut reader = LogReader::open(&p).unwrap();
    let mut ix = Index::new(genesis_id, opening.clone(), 64);
    ix.sync(&mut reader).unwrap();
    assert_eq!(ix.balance_of(&carol), 999_000);
    assert_eq!(ix.balance_of(&alice), 0);
    assert_eq!(ix.history.get(&carol).map(|v| v.len()), Some(1));

    // The reorg.
    write_log(&p, &[b1.clone(), b2b.clone()]);
    assert!(reader.changed().unwrap(), "the reader must notice the file was replaced");
    reader.reopen().unwrap();
    let (applied, rolled) = ix.sync(&mut reader).unwrap();
    assert_eq!((applied, rolled), (1, 1), "one block rolled back, one applied");

    assert_eq!(ix.balance_of(&carol), 0, "Carol's payment was orphaned");
    assert!(ix.history.get(&carol).is_none(), "and left no stale history");
    assert_eq!(ix.balance_of(&dave), 998_000, "Dave's payment is on the new chain");
    assert_eq!(ix.stats.reorgs_handled, 1);
    assert_eq!(ix.stats.deepest_reorg, 1);

    // Converging on the tip is not the same as converging on the state, so
    // compare against a build that never saw chain A at all.
    let mut fresh_reader = LogReader::open(&p).unwrap();
    let mut fresh = Index::new(genesis_id, opening, 64);
    fresh.sync(&mut fresh_reader).unwrap();
    assert_eq!(ix.utxo, fresh.utxo, "unspent set");
    assert_eq!(ix.balance, fresh.balance, "balances");
    assert_eq!(ix.chain, fresh.chain, "chain rows");
    assert_eq!(ix.txs.len(), fresh.txs.len(), "transactions");
    assert_eq!(ix.participation, fresh.participation, "participation");
    assert_eq!(ix.epochs, fresh.epochs, "epoch aggregates");

    let _ = std::fs::remove_dir_all(&d);
}

/// A reorg deeper than the undo journal must **refuse**, not half-roll-back.
///
/// This is the case `finalized`-as-a-watermark would have gotten wrong. The
/// index cannot repair itself from a journal that does not reach the fork, so
/// it says so and stays behind; a partial rollback would leave the set holding
/// outputs from blocks that are no longer on any chain, and nothing downstream
/// could tell.
#[test]
fn a_reorg_deeper_than_the_journal_refuses_rather_than_guessing() {
    let d = tmpdir("deep");
    let p = d.join("blocks.log");
    let genesis_id = h32(0x00);

    let mut envs = Vec::new();
    let mut parent = genesis_id;
    for i in 1..=10u64 {
        let e = envelope(header(i, parent, 0, i as u8), vec![], vec![]);
        parent = *BlockId::of(&e.header).as_bytes();
        envs.push(e);
    }
    write_log(&p, &envs);

    // Journal deep enough for 2 blocks only.
    let mut reader = LogReader::open(&p).unwrap();
    let mut ix = Index::new(genesis_id, vec![], 2);
    ix.sync(&mut reader).unwrap();
    assert_eq!(ix.height(), 10);

    // Shallow reorg: within the journal, must succeed.
    write_log(&p, &envs[..9]);
    reader.reopen().unwrap();
    let (_, rolled) = ix.sync(&mut reader).unwrap();
    assert_eq!(rolled, 1);

    // Deep reorg: past the journal, must refuse.
    write_log(&p, &envs[..3]);
    reader.reopen().unwrap();
    let e = ix.sync(&mut reader).unwrap_err();
    assert!(e.to_string().contains("rebuild required"), "{e}");
    // And it must not have half-applied anything.
    assert_eq!(ix.height(), 9, "the index is unchanged, not partially rolled back");

    let _ = std::fs::remove_dir_all(&d);
}

// ── Identifiers ─────────────────────────────────────────────────────────────

/// The two-derivation trap, closed at the door.
#[test]
fn an_address_is_refused_with_the_reason() {
    let e = crate::parse_script_hash("bloch1qxyz").unwrap_err();
    assert!(e.contains("script_hash"), "{e}");
    assert!(e.contains("silent"), "the reason must say WHY, not just refuse: {e}");
    assert!(crate::parse_script_hash(&"ab".repeat(32)).is_ok());
    assert!(crate::parse_script_hash(&"ab".repeat(31)).is_err(), "wrong length");
    assert!(crate::parse_script_hash(&"zz".repeat(32)).is_err(), "not hex");
}

/// `txid` is unique for transfers and NOT unique for the staking variants, so
/// the index keys transactions on `(block_id, tx_index)` and treats `txid` as a
/// list. If this ever stops being true the permalink scheme can be simplified;
/// until then, the test is what stops someone simplifying it wrongly.
#[test]
fn two_identical_exits_share_a_txid_which_is_why_txid_is_not_the_primary_key() {
    let a = PosTransaction::Exit { validator: 7 };
    let b = PosTransaction::Exit { validator: 7 };
    assert_eq!(a.txid(), b.txid(), "no nonce, so no distinct id");

    // Two transfers spending different coins cannot collide, which is why the
    // secondary index is still useful.
    let t1 = transfer(vec![([1u8; 32], 0)], vec![(10, h32(1))]);
    let t2 = transfer(vec![([2u8; 32], 0)], vec![(10, h32(1))]);
    assert_ne!(t1.txid(), t2.txid());
}

/// V1 and V2 encode the same logical transfer, and the index must record both
/// under the same `txid` — otherwise a payment would change its permalink when
/// the sender's wallet changed its encoding.
#[test]
fn the_two_transfer_encodings_share_one_txid() {
    use bloch_pos_committee::transition::{TransferInputV2, WitnessKey};
    let v1 = transfer(vec![([9u8; 32], 3)], vec![(500, h32(2))]);
    let v2 = PosTransaction::TransferV2 {
        keys: vec![WitnessKey { pubkey: vec![0u8; 4], signature: vec![0u8; 4] }],
        inputs: vec![TransferInputV2 { txid: [9u8; 32], vout: 3, key_index: 0 }],
        outputs: vec![TransferOutput { value: 500, script_hash: h32(2) }],
        tx_bytes: 1_000,
        tip_millisat_per_gas: 0,
    };
    assert_eq!(v1.txid(), v2.txid());
}

// ── Balances ────────────────────────────────────────────────────────────────

/// Satoshi arithmetic must not round. The largest carried holder is
/// 354,617,540,000,000,000 sat, 39× past the largest integer a double
/// represents exactly — and that value happens to BE exactly representable
/// (spacing at that magnitude is 64), so only a `+1` distinguishes correct
/// arithmetic from float arithmetic. The `+1` is deliberate.
#[test]
fn a_balance_past_2_to_the_53_is_exact() {
    let big: u64 = 354_617_540_000_000_001;
    let sh = h32(0xBB);
    let ix = Index::new(
        h32(0),
        vec![(
            OutPoint { txid: [1u8; 32], vout: 0 },
            Utxo { value_sat: big, script_hash: sh, created_height: 0 },
        )],
        16,
    );
    assert_eq!(ix.balance_of(&sh), big as u128);
    assert_eq!(ix.balance_of(&sh) as f64 as u128, 354_617_540_000_000_000);
    // The JSON wire form must be the exact decimal, not a number.
    let j = crate::json::Json::sat(ix.balance_of(&sh)).to_string();
    assert_eq!(j, "\"354617540000000001\"");
}

/// Participation is counted by an attestation's target epoch AND by the epoch
/// of the block that carried it, because those differ when inclusion is late
/// and consensus's own reward rule uses the second one.
#[test]
fn participation_records_both_the_target_and_the_inclusion_epoch() {
    let d = tmpdir("part");
    let p = d.join("blocks.log");
    let genesis_id = h32(0);
    // Slot 32 is epoch 1; the attestation targets epoch 0.
    let b = envelope(header(32, genesis_id, 5, 1), vec![], vec![att(11, 30, 0)]);
    write_log(&p, &[b]);
    let mut reader = LogReader::open(&p).unwrap();
    let mut ix = Index::new(genesis_id, vec![], 16);
    ix.sync(&mut reader).unwrap();

    assert_eq!(ix.participation[&(0, 11)].attested_target, 1, "targeted epoch 0");
    assert_eq!(ix.participation[&(0, 11)].included_here, 0);
    assert_eq!(ix.participation[&(1, 11)].included_here, 1, "but was included in epoch 1");
    assert_eq!(ix.participation[&(1, 5)].proposed, 1, "and validator 5 proposed it");
    let _ = std::fs::remove_dir_all(&d);
}
