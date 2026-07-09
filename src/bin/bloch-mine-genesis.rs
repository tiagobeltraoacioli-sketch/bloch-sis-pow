//! Genesis-block mining tool for Bloch-SIS Protocol chain resets (V2).
//!
//! V2 tokenomics (TOKENOMICS_V2.md, ADR-028) requires a 3-output genesis
//! coinbase split [miner 70% + 0 fees, validator_pool 25%, oracle_pool 5%]
//! from `block_subsidy_sat(0) = 1905 BLOCH`. No founder mint at genesis;
//! the 170M founder allocation vests block-by-block starting at CLIFF+1.
//!
//! Changing GENESIS_BITS, GENESIS_TIMESTAMP, the coinbase script_sig text,
//! or any of the three pool addresses invalidates the stored GENESIS_NONCE
//! and the node will refuse to start because `create_genesis_block().validate_pow()`
//! returns false.
//!
//! Usage
//! -----
//!
//! ```
//! bloch-mine-genesis \
//!     --bits 0x1d21af9e \
//!     --timestamp 1745280000 \
//!     --miner-addr           bloch1q4fbcd3b3fae5de3e2b4015ca132c8744b8af170a79e4eb45 \
//!     --validator-pool-addr  bloch1q<...> \
//!     --oracle-pool-addr     bloch1q<...> \
//!     --coinbase-text "BLOCH V2 mainnet genesis: 1B nominal supply, 70/25/5 split. 2026."
//! ```
//!
//! Output: a found `(nonce, hash)` pair you paste into
//! `src/core/mod.rs` and `src/core/tokenomics_v2.rs` (pool address constants).

use clap::Parser;
use bloch::core::{
    bits_to_target, hash_meets_target, tokenomics_v2,
    Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "bloch-mine-genesis")]
#[command(about = "Mine the GENESIS_NONCE for a V2 chain reset")]
struct Cli {
    /// Compact difficulty bits. Accept 0x-prefixed hex or decimal.
    #[arg(long, value_parser = parse_u32_hex_or_dec)]
    bits: u32,

    /// Unix timestamp for the genesis block (seconds since epoch).
    #[arg(long)]
    timestamp: u64,

    /// Miner address in bloch1q... bech32 form. Receives the 70% miner
    /// share at genesis (no fees collected for the genesis block).
    #[arg(long)]
    miner_addr: String,

    /// Validator pool address. Receives the 25% validator_pool share.
    #[arg(long)]
    validator_pool_addr: String,

    /// Oracle pool address. Receives the 5% oracle_pool share.
    #[arg(long)]
    oracle_pool_addr: String,

    /// Coinbase script_sig text. Becomes part of the genesis hash.
    /// Change this for every reset to produce a distinct genesis.
    #[arg(long)]
    coinbase_text: String,

    /// Number of mining threads. 0 = all available CPUs.
    #[arg(long, default_value = "0")]
    threads: usize,

    /// Starting nonce. Useful for resuming a search or splitting
    /// across machines. Each thread takes stride `threads * N` from
    /// its starting offset, so threads never collide.
    #[arg(long, default_value = "0")]
    start_nonce: u64,
}

fn parse_u32_hex_or_dec(s: &str) -> Result<u32, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("bad hex: {}", e))
    } else {
        s.parse().map_err(|e: std::num::ParseIntError| format!("bad decimal: {}", e))
    }
}

fn address_to_script_pubkey(addr: &str) -> Vec<u8> {
    let stripped = addr
        .trim_start_matches("bloch1q")
        .trim_start_matches("bloch1t");
    let hash_hex = &stripped[..40.min(stripped.len())];
    hex::decode(hash_hex).unwrap_or_else(|_| addr.as_bytes().to_vec())
}

fn main() {
    let cli = Cli::parse();

    println!("================================================");
    println!("  Bloch-SIS Protocol Genesis-Block Mining (V2)");
    println!("================================================");
    println!();
    println!("Parameters");
    println!("  bits:                0x{:08x}", cli.bits);
    println!("  timestamp:           {}", cli.timestamp);
    println!("  miner_addr:          {}", cli.miner_addr);
    println!("  validator_pool_addr: {}", cli.validator_pool_addr);
    println!("  oracle_pool_addr:    {}", cli.oracle_pool_addr);
    println!("  coinbase_text:       {:?}", cli.coinbase_text);
    println!();

    let miner_spk          = address_to_script_pubkey(&cli.miner_addr);
    let validator_pool_spk = address_to_script_pubkey(&cli.validator_pool_addr);
    let oracle_pool_spk    = address_to_script_pubkey(&cli.oracle_pool_addr);

    // V2 split for genesis (h=0): subsidy = 1905 BLOCH, no fees.
    let subsidy = tokenomics_v2::block_subsidy_sat(0);
    let (miner_value, validator_value, oracle_value) =
        tokenomics_v2::split_subsidy_sat(subsidy);

    println!("V2 genesis subsidy split (sat)");
    println!("  miner          (70%): {} ({} BLOCH)",
             miner_value, miner_value as f64 / 100_000_000.0);
    println!("  validator_pool (25%): {} ({} BLOCH)",
             validator_value, validator_value as f64 / 100_000_000.0);
    println!("  oracle_pool     (5%): {} ({} BLOCH)",
             oracle_value, oracle_value as f64 / 100_000_000.0);
    println!();

    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: cli.coinbase_text.clone().into_bytes(),
            sequence:   u32::MAX,
        }],
        outputs: vec![
            TxOutput {
                value:         miner_value,
                script_pubkey: miner_spk,
            },
            TxOutput {
                value:         validator_value,
                script_pubkey: validator_pool_spk,
            },
            TxOutput {
                value:         oracle_value,
                script_pubkey: oracle_pool_spk,
            },
        ],
        locktime: 0,
    };
    let merkle = Transaction::merkle_root(&[coinbase.clone()]);

    println!("Coinbase");
    println!("  txid:   {}", hex::encode(coinbase.txid()));
    println!("  merkle: {}", hex::encode(merkle.0));
    println!();

    let n_threads = if cli.threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        cli.threads
    };
    println!("Mining on {} threads starting from nonce {}…", n_threads, cli.start_nonce);
    println!();

    let target = bits_to_target(cli.bits);
    let target_arc = Arc::new(target);
    let found_nonce = Arc::new(AtomicU64::new(0));
    let found_flag  = Arc::new(AtomicBool::new(false));
    let hash_counter = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let mut handles = Vec::with_capacity(n_threads);
    for thread_id in 0..n_threads {
        let target   = target_arc.clone();
        let found_nonce = found_nonce.clone();
        let found_flag  = found_flag.clone();
        let hash_counter = hash_counter.clone();

        let start_n = cli.start_nonce + thread_id as u64;
        let stride  = n_threads as u64;

        let merkle_bytes = merkle.0;
        let bits         = cli.bits;
        let timestamp    = cli.timestamp;

        handles.push(std::thread::spawn(move || {
            let mut nonce = start_n;
            let mut local_count = 0u64;

            while !found_flag.load(Ordering::Relaxed) {
                let header = BlockHeader {
                    version:     1,
                    parents:     vec![],
                    merkle_root: MerkleRoot(merkle_bytes),
                    timestamp,
                    bits,
                    nonce,
                };
                let hash = header.pow_hash();

                if hash_meets_target(&hash, &target) {
                    found_nonce.store(nonce, Ordering::SeqCst);
                    found_flag.store(true,  Ordering::SeqCst);
                    hash_counter.fetch_add(local_count, Ordering::Relaxed);
                    return;
                }

                nonce = nonce.wrapping_add(stride);
                local_count += 1;

                if local_count & 0xFFFF == 0 {
                    hash_counter.fetch_add(0x10000, Ordering::Relaxed);
                    local_count = 0;
                }
            }
            hash_counter.fetch_add(local_count, Ordering::Relaxed);
        }));
    }

    let display_counter = hash_counter.clone();
    let display_flag    = found_flag.clone();
    let display_start   = start;
    let display_handle  = std::thread::spawn(move || {
        let mut last = 0u64;
        while !display_flag.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let now = display_counter.load(Ordering::Relaxed);
            let elapsed = display_start.elapsed().as_secs_f64();
            let instant = (now - last) as f64 / 2.0;
            last = now;
            let _avg = now as f64 / elapsed;
            print!("\r  [{:>4}s]  {:>10.0} H/s  total {:>13}  ",
                   elapsed as u64, instant, now);
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    });

    for h in handles {
        let _ = h.join();
    }
    let _ = display_handle.join();
    println!();

    let nonce = found_nonce.load(Ordering::SeqCst);
    let total_hashes = hash_counter.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();

    let final_block = Block {
        header: BlockHeader {
            version:     1,
            parents:     vec![],
            merkle_root: merkle,
            timestamp:   cli.timestamp,
            bits:        cli.bits,
            nonce,
        },
        transactions: vec![coinbase],
        blue_score: 0,
        height: 0,
        pow_solution: Vec::new(),
        shielded_transactions: Vec::new(),    };
    let block_hash = final_block.block_hash();

    let pow_ok = final_block.validate_pow();

    println!();
    println!("================================================");
    println!("  V2 Genesis Block Found");
    println!("================================================");
    println!();
    println!("  nonce:          {}", nonce);
    println!("  block_hash:     {}", hex::encode(block_hash));
    println!("  validate_pow:   {}", pow_ok);
    println!("  time:           {:.1} s", elapsed);
    println!("  hashes:         {}", total_hashes);
    println!("  avg rate:       {:.0} H/s", total_hashes as f64 / elapsed);
    println!();
    println!("Patch src/core/mod.rs with:");
    println!();
    println!("    pub const GENESIS_NONCE:     u64   = {};", nonce);
    println!("    pub const GENESIS_TIMESTAMP: u64   = {};", cli.timestamp);
    println!("    pub const GENESIS_BITS:      u32   = 0x{:08x};", cli.bits);
    println!();
    println!("And in src/core/tokenomics_v2.rs, set the address constants:");
    println!();
    println!("    pub const VALIDATOR_POOL_ADDRESS_HASH: Option<[u8; 20]> = Some(<...>);");
    println!("    pub const ORACLE_POOL_ADDRESS_HASH:    Option<[u8; 20]> = Some(<...>);");
    println!();
    println!("And in create_genesis_block_with_bits, update the coinbase");
    println!("script_sig to:");
    println!();
    println!("    {:?}.to_vec(),", cli.coinbase_text);
    println!();
    println!("Expected genesis hash for verification:");
    println!("    {}", hex::encode(block_hash));
    println!();

    if !pow_ok {
        eprintln!("WARNING: validate_pow returned false — something's wrong.");
        std::process::exit(1);
    }
}
