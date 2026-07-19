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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = String::from("./bloch-data");
    let mut out_path = String::from("utxo-snapshot.tsv");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" if i + 1 < args.len() => { data_dir = args[i + 1].clone(); i += 2; }
            "--out"      if i + 1 < args.len() => { out_path = args[i + 1].clone(); i += 2; }
            "-h" | "--help" => {
                eprintln!("usage: bloch-snapshot-utxo --data-dir <dir> --out <file.tsv>");
                std::process::exit(0);
            }
            other => { eprintln!("unknown argument: {other}"); std::process::exit(2); }
        }
    }

    // READ-ONLY: no write lock, so a live node keeps serving while we snapshot.
    let store = match bloch::storage::Storage::open_read_only(Path::new(&data_dir)) {
        Ok(s)  => s,
        Err(e) => { eprintln!("cannot open {data_dir} read-only: {e}"); std::process::exit(1); }
    };

    let height = store
        .get_meta("tip_height").ok().flatten()
        .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes));
    let pruned = store.pruned_height();

    let utxos = match store.iter_utxos_sorted() {
        Ok(v)  => v,
        Err(e) => { eprintln!("failed to read the UTXO set: {e}"); std::process::exit(1); }
    };

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
