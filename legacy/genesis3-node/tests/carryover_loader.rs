//! Fail-closed contract of the Genesis-2 carry-over loader.
//!
//! Until now this contract rested entirely on manual boots: a person built a bad
//! file, started a node, and read the exit code. That found real defects — the
//! duplicate-outpoint and zero-value holes were caught exactly that way — but it
//! protects nothing once the person stops looking. These tests pin the behaviour
//! so a later edit to the parser cannot quietly reopen a hole that was already
//! closed once.
//!
//! The property under test is that the three checks are INDEPENDENT. Each case
//! below defeats some of them and must still be refused by another:
//!
//!   * reordering        -> count and supply pass, only the root catches it
//!   * duplicate outpoint-> count and supply pass, only the uniqueness check does
//!   * zero-value row    -> supply passes, the parser rejects the row
//!   * one row removed   -> the root, the count AND the supply all fail
//!
//! If a future change makes any single check load-bearing on its own, one of
//! these regresses, which is the whole point of writing them down.

use std::io::Write;

/// Build a syntactically valid snapshot line. Values are the same shape
/// `bloch-snapshot-utxo` emits: `txid_hex \t vout \t value_sat \t spk_hex`.
fn line(txid_byte: u8, vout: u32, value: u64) -> String {
    format!("{}\t{}\t{}\t{}\n", hex::encode([txid_byte; 32]), vout, value, hex::encode([0x51u8; 1]))
}

fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bloch-carryover-test-{name}.tsv"));
    let mut f = std::fs::File::create(&p).expect("create temp snapshot");
    f.write_all(contents.as_bytes()).expect("write temp snapshot");
    p
}

/// A small, self-consistent snapshot: N rows, each a distinct outpoint.
fn good_snapshot(rows: u8) -> String {
    (0..rows).map(|i| line(i, 0, 8_400 * 100_000_000)).collect()
}

#[test]
fn accepts_a_well_formed_snapshot() {
    let p = write_temp("good", &good_snapshot(4));
    let snap = bloch::storage::parse_carryover_file(&p)
        .expect("a well-formed snapshot must parse");
    assert_eq!(snap.entry_count(), 4);
    assert_eq!(snap.total_sat, 4u128 * 8_400 * 100_000_000);
    let _ = std::fs::remove_file(p);
}

#[test]
fn rejects_duplicate_outpoints_even_when_count_and_supply_are_unchanged() {
    // The attack the manual drive found: duplicate one row over another of EQUAL
    // value. Line count is identical, summed supply is identical — both of those
    // checks pass. Ingest would collapse the two into one key and write fewer
    // UTXOs than it reported.
    let mut rows: Vec<String> = good_snapshot(4).lines().map(|l| format!("{l}\n")).collect();
    rows[1] = rows[0].clone();
    let p = write_temp("dup", &rows.concat());

    let err = bloch::storage::parse_carryover_file(&p)
        .expect_err("a duplicated outpoint must be refused");
    assert!(
        err.iter().any(|e| e.contains("duplicates outpoint")),
        "the failure must name the duplicate, got: {err:?}",
    );
    let _ = std::fs::remove_file(p);
}

#[test]
fn rejects_zero_value_outputs() {
    // Adds a row that changes the line count while contributing nothing to the
    // total, so the supply check cannot see it.
    let mut s = good_snapshot(4);
    s.push_str(&line(0xEE, 9, 0));
    let p = write_temp("zero", &s);

    let err = bloch::storage::parse_carryover_file(&p)
        .expect_err("a zero-value output must be refused");
    assert!(!err.is_empty(), "refusal must explain itself");
    let _ = std::fs::remove_file(p);
}

#[test]
fn reordering_changes_nothing_but_the_bytes_and_is_still_refused() {
    // Reordering preserves the set exactly: same rows, same count, same supply.
    // Only the byte-root can catch it — and it must, or two honest operators can
    // publish different roots for the same ledger and never learn why.
    let good = good_snapshot(4);
    let mut rows: Vec<&str> = good.lines().collect();
    rows.swap(0, 3);
    let reordered: String = rows.iter().map(|l| format!("{l}\n")).collect();

    let a = bloch::storage::parse_carryover_file(&write_temp("ord-a", &good))
        .expect("baseline parses");
    let b = bloch::storage::parse_carryover_file(&write_temp("ord-b", &reordered))
        .expect("reordered file is still well-formed");

    assert_eq!(a.entry_count(), b.entry_count(), "same number of rows");
    assert_eq!(a.total_sat, b.total_sat, "same supply");
    assert_ne!(a.root, b.root, "but the ROOT must differ — that is the only signal");
}

#[test]
fn a_removed_row_fails_root_count_and_supply_together() {
    // The one case where all three checks agree. Asserted so that a future change
    // which accidentally makes two of them equivalent shows up here.
    let good = good_snapshot(4);
    let short: String = good.lines().take(3).map(|l| format!("{l}\n")).collect();

    let a = bloch::storage::parse_carryover_file(&write_temp("full", &good)).unwrap();
    let b = bloch::storage::parse_carryover_file(&write_temp("short", &short)).unwrap();

    assert_ne!(a.root, b.root);
    assert_ne!(a.entry_count(), b.entry_count());
    assert_ne!(a.total_sat, b.total_sat);
}

#[test]
fn a_truncated_file_does_not_hash_like_the_intact_one() {
    // The defect this catches was real and shipped: an earlier version rebuilt
    // each line and re-appended "\n", so a file truncated before its final
    // newline hashed IDENTICALLY to the intact one — the single most likely
    // corruption of a large download was invisible to the commitment.
    let good = good_snapshot(4);
    let truncated = &good[..good.len() - 1]; // drop the trailing newline only

    let a = bloch::storage::parse_carryover_file(&write_temp("t-full", &good)).unwrap();
    let b = bloch::storage::parse_carryover_file(&write_temp("t-cut", truncated));

    match b {
        Ok(snap) => assert_ne!(
            a.root, snap.root,
            "a truncated file must not hash like the intact one",
        ),
        Err(_) => { /* refusing outright is also correct */ }
    }
}
