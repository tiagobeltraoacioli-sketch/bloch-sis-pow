//! UTXO-set snapshot tool — the carry-over artifact.
//!
//! Writes the complete UTXO set of a node data-dir to a deterministic file and
//! prints a commitment over it. Opens the data-dir READ-ONLY, so it is safe to
//! run against a live node without stopping it.
//!
//! # Why this exists
//!
//! `prune_blocks_below` deletes block BODIES below `tip - PRUNING_DEPTH` but keeps
//! the height→hash map, the DAG, the TX index and the UTXO set. On this fleet in
//! 2026-07 every node had pruned below ~394,913, so ~95% of the chain's bodies
//! exist nowhere and cannot be recovered — while every balance stayed intact and
//! queryable. The ledger survived; the history that produced it did not.
//!
//! That asymmetry is what this tool exploits. Two uses:
//!
//!   1. **Insurance.** A signed, hashed snapshot means balances are recoverable
//!      independently of the chain's ability to replay itself. Take it before any
//!      migration decision, not after.
//!   2. **Bootstrap.** A fresh node currently cannot sync: it asks for block 0, is
//!      promised 500 headers, and no peer can serve the bodies. An assumeutxo-style
//!      start from a published snapshot is the standard answer (Bitcoin assumeutxo,
//!      Ethereum snap sync) and needs exactly this artifact.
//!
//! # Honesty
//!
//! A snapshot is a TRUST ANCHOR, not a proof. Whoever starts from it trusts that
//! the set is the real one at that height. The commitment below lets independent
//! parties compare snapshots and detect disagreement — it does not, by itself,
//! prove correctness against a chain nobody can replay. Publish the root, let
//! several operators produce it separately, and treat agreement as the evidence.
//!
//! # Usage
//!
//! ```text
//! bloch-snapshot-utxo --data-dir ~/bloch-data --out utxo-snapshot.tsv
//! ```

use std::io::Write;
use std::path::Path;

/// Decode a UTXO key's 4-byte vout suffix. Legacy M-3: `canonical` selects
/// which of the two disagreeing conventions to use — see the long comment at
/// this function's call site for why BOTH exist and why the default
/// (`canonical = false`) is the historically-INCORRECT one.
fn decode_vout(bytes: [u8; 4], canonical: bool) -> u32 {
    if canonical {
        u32::from_le_bytes(bytes) // correct: matches storage::utxo_key's actual encoding
    } else {
        u32::from_be_bytes(bytes) // historical (incorrect) decode — kept for reproducibility
    }
}

#[cfg(test)]
mod decode_vout_tests {
    use super::*;

    /// Legacy M-3 regression: the historical (default) decode must reproduce
    /// the EXACT bug the published snapshot's root depends on — vout=1,
    /// written by `storage::utxo_key` as `1u32.to_le_bytes()` == `[1,0,0,0]`,
    /// must decode to 16_777_216 (`[1,0,0,0]` misread big-endian), not to 1.
    /// `--canonical-vout` must decode the SAME bytes to the real value, 1.
    #[test]
    fn default_decode_reproduces_the_published_bug_for_vout_1() {
        let bytes = 1u32.to_le_bytes(); // what storage::utxo_key actually writes for vout=1
        assert_eq!(decode_vout(bytes, false), 16_777_216, "default mode must keep reproducing the historical misread");
        assert_eq!(decode_vout(bytes, true), 1, "--canonical-vout must decode the true vout");
    }

    /// vout=0 is a byte-palindrome ([0,0,0,0]) — both decodes must agree,
    /// since it is unaffected by endianness either way.
    #[test]
    fn vout_zero_is_endianness_invariant() {
        let bytes = 0u32.to_le_bytes();
        assert_eq!(decode_vout(bytes, false), 0);
        assert_eq!(decode_vout(bytes, true), 0);
    }

    /// A round-trip sanity check across a spread of vout values: the
    /// canonical decode of `storage::utxo_key`'s own encoding must always
    /// recover the original value, while the default (historical) decode
    /// only coincidentally agrees when the bytes happen to be a palindrome.
    #[test]
    fn canonical_decode_round_trips_storage_utxo_key_encoding() {
        for vout in [0u32, 1, 2, 255, 256, 65_536, 16_777_216, u32::MAX] {
            let written = vout.to_le_bytes(); // storage::utxo_key's actual encoding
            assert_eq!(decode_vout(written, true), vout,
                "canonical decode must recover vout={vout} from its own LE encoding");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = String::from("./bloch-data");
    let mut out_path = String::from("utxo-snapshot.tsv");
    // Legacy M-3: see the long comment at the UTXO-iteration loop below for
    // the full story. Short version — `storage::utxo_key` writes the vout
    // suffix LITTLE-endian, but every reader of this column family (this
    // tool included, historically) parsed it BIG-endian, so any vout whose
    // LE and BE byte-swaps differ decodes to the WRONG number (38 live
    // outpoints on the published snapshot read back as vout=16,777,216,
    // which is vout=1's bytes misread as BE). The ALREADY-PUBLISHED
    // SHAKE-256 root was computed over that (buggy) BE reading, so this
    // tool's DEFAULT behaviour is UNCHANGED — reproducing the existing
    // artifact requires reproducing its bug. `--canonical-vout` switches to
    // the CORRECT (`from_le_bytes`) decode for a NEW export whose consumer
    // understands it is not byte-compatible with the historical artifact.
    let mut canonical_vout = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" if i + 1 < args.len() => { data_dir = args[i + 1].clone(); i += 2; }
            "--out"      if i + 1 < args.len() => { out_path = args[i + 1].clone(); i += 2; }
            "--canonical-vout" => { canonical_vout = true; i += 1; }
            "-h" | "--help" => {
                eprintln!("usage: bloch-snapshot-utxo --data-dir <dir> --out <file.tsv> [--canonical-vout]");
                eprintln!();
                eprintln!("  --canonical-vout   Decode the vout suffix of each UTXO key LITTLE-endian");
                eprintln!("                     (the encoding storage::utxo_key actually writes),");
                eprintln!("                     instead of the historical (incorrect) big-endian");
                eprintln!("                     decode this tool has always used. Changes the SHAKE-256");
                eprintln!("                     root and every non-zero, non-symmetric vout value in the");
                eprintln!("                     output — NOT byte-compatible with any snapshot published");
                eprintln!("                     before this flag existed. See legacy/README.md (Legacy M-3).");
                std::process::exit(0);
            }
            other => { eprintln!("unknown argument: {other}"); std::process::exit(2); }
        }
    }

    // Open RocksDB DIRECTLY, listing only the column families the DB actually has.
    //
    // Storage::open_read_only passes the CURRENT binary's full descriptor list, so it
    // refuses any data-dir created by an older node ("Column family not found:
    // reachability" against a node predating that CF). For a forensic/snapshot tool
    // that is backwards: it must read a database written by ANY version, precisely
    // because the reason to snapshot is usually that something is wrong with the
    // node. So: discover the CFs, open those, and touch only `utxo`.
    //
    // READ-ONLY acquires no write lock — a live node keeps mining while this runs.
    let existing = match rocksdb::DB::list_cf(&rocksdb::Options::default(), &data_dir) {
        Ok(v)  => v,
        Err(e) => { eprintln!("cannot list column families in {data_dir}: {e}"); std::process::exit(1); }
    };
    if !existing.iter().any(|c| c == "utxo") {
        eprintln!("no `utxo` column family in {data_dir} — is this a Bloch data-dir? \
                   (note: the RocksDB directory is <data-dir>/db)");
        std::process::exit(1);
    }
    let descriptors: Vec<_> = existing.iter()
        .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, rocksdb::Options::default()))
        .collect();
    let db = match rocksdb::DB::open_cf_descriptors_read_only(
        &rocksdb::Options::default(), &data_dir, descriptors, false,
    ) {
        Ok(d)  => d,
        Err(e) => { eprintln!("cannot open {data_dir} read-only: {e}"); std::process::exit(1); }
    };

    let read_u64_meta = |key: &str| -> Option<u64> {
        db.cf_handle("meta")
            .and_then(|cf| db.get_cf(&cf, key.as_bytes()).ok().flatten())
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
    };
    let height = read_u64_meta("tip_height");
    let pruned = read_u64_meta("pruned_height").unwrap_or(0);

    // DOC-DRIFT FIX (Legacy M-3): this comment used to say CF_UTXO keys are
    // `txid ‖ vout_be` — describing what a reader SHOULD do, not what
    // `storage::utxo_key` (legacy/genesis3-node/src/storage/mod.rs) actually
    // does. That function writes the vout suffix `index.to_le_bytes()` —
    // LITTLE-endian. Every UTXO-set reader in this codebase (this tool's
    // default path included) has always decoded that suffix BIG-endian
    // instead, so any vout whose LE and BE byte-swaps differ (any vout != 0
    // whose bytes aren't a palindrome) comes back as the WRONG number: the
    // published Genesis-2/3 carry-over snapshot carries 38 live outpoints
    // whose real vout is 1 but which this tool (and `iter_utxos_sorted`)
    // reports as vout = 16_777_216 (`0x01000000`, exactly `1u32.to_le_bytes()`
    // misread as big-endian).
    //
    // This does NOT corrupt anything CONSENSUS reads: `Storage::get_utxo`
    // and `Storage::delete_utxo` both build the SAME key via `utxo_key`
    // (write) and look it up via `utxo_key` again (read) — the LE encoding
    // round-trips correctly there, because both sides use the SAME (correct)
    // function. The mismatch is confined to code that tries to parse the
    // *raw key bytes* back into a vout number for DISPLAY/export, which only
    // this tool and `iter_utxos_sorted` do.
    //
    // The already-published SHAKE-256 root and TSV file for the carry-over
    // snapshot were produced by the (buggy) BE decode below — reproducing
    // that EXACT published artifact byte-for-byte requires reproducing the
    // bug, so it stays the DEFAULT. `--canonical-vout` switches to the
    // correct `from_le_bytes` decode for anyone taking a NEW export who
    // wants the real vout numbers and understands the root will differ from
    // the historical one. See `legacy/README.md`.
    let cf_utxo = db.cf_handle("utxo").expect("checked above");
    let mut utxos: Vec<(Vec<u8>, u32, u64, Vec<u8>)> = Vec::new();
    for item in db.iterator_cf(&cf_utxo, rocksdb::IteratorMode::Start) {
        let (key, val) = match item { Ok(kv) => kv, Err(e) => {
            eprintln!("read error while iterating the UTXO set: {e}"); std::process::exit(1); } };
        if key.len() < 36 { continue; }
        let txid = key[..key.len() - 4].to_vec();
        let vout_bytes = [key[key.len()-4], key[key.len()-3], key[key.len()-2], key[key.len()-1]];
        let vout = decode_vout(vout_bytes, canonical_vout);
        let output: bloch::core::TxOutput = match bloch::storage::decode(&val) {
            Ok(o) => o, Err(_) => continue,
        };
        utxos.push((txid, vout, output.value, output.script_pubkey));
    }
    // Sort by (txid, decoded vout) — numeric order on whichever decode mode
    // is active. In the default (historical) mode this is EXACTLY RocksDB's
    // own raw-key-byte order (a BE decode's numeric ordering is, by
    // construction, identical to lexicographic order on the same bytes),
    // matching `iter_utxos_sorted` and reproducing the historical artifact
    // unchanged. Under `--canonical-vout` this instead gives the sensible
    // ascending-vout order a fresh export should have — sorting by raw bytes
    // there would order by the WRONG (LE-of-the-correct-value) key instead.
    // Sorted explicitly so the commitment depends on this function rather
    // than on a RocksDB iteration detail.
    utxos.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Commitment: SHAKE-256 over the same bytes we write, in the same order. The
    // file and the root are therefore two views of one artifact — you can
    // recompute the root from the file and get the same answer, which is what
    // makes independent verification possible.
    use sha3::{Digest, Shake256};
    use sha3::digest::{Update, ExtendableOutput, XofReader};
    let mut hasher = Shake256::default();

    let mut f = match std::fs::File::create(&out_path) {
        Ok(f)  => f,
        Err(e) => { eprintln!("cannot write {out_path}: {e}"); std::process::exit(1); }
    };

    let mut total_sats: u128 = 0;
    for (txid, vout, value, spk) in &utxos {
        let line = format!("{}\t{}\t{}\t{}\n", hex::encode(txid), vout, value, hex::encode(spk));
        Update::update(&mut hasher, line.as_bytes());
        if let Err(e) = f.write_all(line.as_bytes()) {
            eprintln!("write failed: {e}"); std::process::exit(1);
        }
        total_sats += *value as u128;
    }

    let mut reader = hasher.finalize_xof();
    let mut root = [0u8; 32];
    reader.read(&mut root);

    eprintln!("UTXO snapshot written to {out_path}");
    eprintln!("  data-dir      : {data_dir}");
    eprintln!("  tip height    : {}", height.map(|h| h.to_string()).unwrap_or_else(|| "unknown".into()));
    eprintln!("  pruned below  : {pruned}  <- bodies deleted under this height; the SET below is still complete");
    eprintln!("  utxo count    : {}", utxos.len());
    eprintln!("  total value   : {total_sats} sats");
    eprintln!("  SHAKE-256 root: {}", hex::encode(root));
    eprintln!();
    eprintln!("Publish the root. Have other operators produce their own snapshot at the");
    eprintln!("same height and compare — agreement across independent nodes is the evidence,");
    eprintln!("not this tool's say-so. A snapshot is a trust anchor, not a proof.");
}
