//! Bloch-SIS Protocol — Sprint F migration binary
//!
//! One-shot tool to populate CF_ADDR_TX_HISTORY from existing chain data.
//! Iterates all blocks in height order, calls index_tx_addresses for each tx.
//!
//! Usage: cargo run --release --bin bloch-migrate-addr-history -- <db_path>
//!
//! Idempotent: re-running produces the same index (same keys, same values).
//! Safe to run while daemon is stopped. ~2-3 minutes for a 1500-block chain.

use bloch::storage::Storage;
use std::env;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: bloch-migrate-addr-history <db_path>");
        eprintln!("example: bloch-migrate-addr-history /bloch-data/chain");
        std::process::exit(1);
    }
    let db_path = PathBuf::from(&args[1]);
    if !db_path.exists() {
        eprintln!("error: db path does not exist: {}", db_path.display());
        std::process::exit(1);
    }

    println!("Bloch-SIS Protocol Sprint F migration — address history indexer");
    println!("────────────────────────────────────────────────────────");
    println!("DB path:   {}", db_path.display());

    let t_start = Instant::now();

    let store = match Storage::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to open storage: {:?}", e);
            std::process::exit(1);
        }
    };

    // Find tip height
    let tip = match store.get_tip_height() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to read tip height: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("Tip height: {}", tip);
    println!();

    let mut blocks_indexed = 0u64;
    let mut txs_indexed = 0u64;
    let mut last_report = Instant::now();

    for h in 0..=tip {
        let hash = match store.get_block_hash_at_height(h) {
            Ok(Some(h)) => h,
            Ok(None) => continue, // gap in chain (shouldn't happen, but safe)
            Err(e) => {
                eprintln!("warn: could not fetch hash at height {}: {:?}", h, e);
                continue;
            }
        };
        let block = match store.get_block(&hash) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("warn: could not load block at height {}: {:?}", h, e);
                continue;
            }
        };

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            if let Err(e) = store.index_tx_addresses(tx, h, tx_idx as u32) {
                eprintln!("warn: index failed for tx in block {}: {:?}", h, e);
            } else {
                txs_indexed += 1;
            }
        }
        blocks_indexed += 1;

        // Progress report every 2 seconds or every 500 blocks
        if last_report.elapsed().as_secs() >= 2 || blocks_indexed % 500 == 0 {
            let pct = if tip > 0 { (h as f64 / tip as f64) * 100.0 } else { 100.0 };
            let elapsed = t_start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 { blocks_indexed as f64 / elapsed } else { 0.0 };
            println!("  [{:6.2}%] height {:7} / {}  ·  {} txs indexed  ·  {:.0} blocks/s",
                pct, h, tip, txs_indexed, rate);
            last_report = Instant::now();
        }
    }

    let elapsed = t_start.elapsed();
    println!();
    println!("────────────────────────────────────────────────────────");
    println!("Migration complete:");
    println!("  Blocks processed:   {}", blocks_indexed);
    println!("  Transactions indexed: {}", txs_indexed);
    println!("  Elapsed time:       {:.2}s", elapsed.as_secs_f64());
    println!();
    println!("The CF_ADDR_TX_HISTORY column family is now populated.");
    println!("Restart the daemon — new blocks will be indexed automatically.");
}
