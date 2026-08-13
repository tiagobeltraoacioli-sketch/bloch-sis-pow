//! Genesis-block mining tool for the Genesis-2 (carry-over, SHA-256d) chain.
//!
//! Mirrors `bloch-mine-genesis`, but for the Genesis-2 chain:
//!
//!   * PoW is double SHA-256 over the 80-byte MiningHeader projection
//!     (the g2/T1 path — `pow::mine_sha256d` / `validate_pow`'s Sha256d arm),
//!     NOT Module-SIS.
//!   * The coinbase script_sig is NOT a free-text argument: it is the
//!     carry-over commitment derived from the `GENESIS2_CARRYOVER_*` constants
//!     baked in `core` (height, UTXO count, snapshot-root prefix), via the
//!     same `core::genesis2_coinbase_script_sig()` the node uses. The miner
//!     therefore CANNOT mine a genesis whose commitment differs from what the
//!     node will validate.
//!   * Construction goes through `core::create_genesis2_block_with_params`,
//!     the SINGLE path shared with the node's `create_genesis2_block` —
//!     miner and validator agree byte-for-byte by construction.
//!
//! The tool mines the nonce ONCE and prints the constants to bake into
//! `crates/bloch-crypto/src/core/mod.rs` (`GENESIS2_NONCE`,
//! `GENESIS2_TIMESTAMP`, `GENESIS2_BITS`, `GENESIS2_EXPECTED_HASH`). The node
//! then only VALIDATES — never mines — and must `exit(1)` if
//! `create_genesis2_block(..).validate_pow()` fails or the hash mismatches,
//! exactly as the existing genesis PoW check does.
//!
//! Before printing, the tool proves the constants on the REAL validation
//! path: it pins the process chain-id to Genesis2Devnet, checks
//! `validate_pow()` == true for the mined nonce, and checks that a tampered
//! nonce (mined+1) is REJECTED. It exits 1 unless both hold.
//!
//! Usage
//! -----
//!
//! ```
//! bloch-mine-genesis2 \
//!     --bits 0x1f00ffff \
//!     --timestamp 1784500000 \
//!     --miner-addr bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073
//! ```

use clap::Parser;
use bloch::core::{
    self, bits_to_target, hash_meets_target, node_chain_id, set_node_chain_id, ChainId,
    GENESIS2_CARRYOVER_SNAPSHOT_ROOT, GENESIS2_CARRYOVER_SOURCE_HEIGHT,
    GENESIS2_CARRYOVER_TOTAL_SAT, GENESIS2_CARRYOVER_UTXO_COUNT,
};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "bloch-mine-genesis2")]
#[command(about = "Mine the GENESIS2_NONCE for the Genesis-2 carry-over chain (SHA-256d)")]
struct Cli {
    /// Compact difficulty bits. Accept 0x-prefixed hex or decimal.
    #[arg(long, value_parser = parse_u32_hex_or_dec)]
    bits: u32,

    /// Unix timestamp for the genesis block (seconds since epoch).
    #[arg(long)]
    timestamp: u64,

    /// Miner address in bloch1q... bech32 form. Receives the genesis
    /// block subsidy (single-output coinbase, mirrors the V1 genesis).
    #[arg(long)]
    miner_addr: String,

    /// Number of mining threads. 0 = all available CPUs.
    #[arg(long, default_value = "0")]
    threads: usize,

    /// Starting nonce (< 2^32; the SHA-256d nonce space is 32-bit).
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

/// Same convention as bloch-mine-genesis / main.rs: hash-20 = first 40 hex
/// chars after the bech32 HRP. Fails closed on anything that does not decode.
fn address_to_script_pubkey(addr: &str) -> Result<Vec<u8>, String> {
    let stripped = addr
        .trim_start_matches("bloch1q")
        .trim_start_matches("bloch1t");
    if stripped.len() < 40 {
        return Err(format!("address too short for a hash-20: {}", addr));
    }
    hex::decode(&stripped[..40]).map_err(|e| format!("address hash not hex: {}", e))
}

fn main() {
    let cli = Cli::parse();

    // Pin THIS process to the Genesis-2 chain so validate_pow() below runs
    // the real Sha256d arm — the same dispatch the node will execute.
    set_node_chain_id(ChainId::Genesis2Devnet)
        .expect("chain-id already pinned to a different chain in this process");
    assert_eq!(node_chain_id(), ChainId::Genesis2Devnet);

    let miner_spk = match address_to_script_pubkey(&cli.miner_addr) {
        Ok(spk) => spk,
        Err(e) => {
            eprintln!("REFUSING: {}", e);
            std::process::exit(1);
        }
    };

    let script_sig = core::genesis2_coinbase_script_sig();
    let commitment_text = String::from_utf8_lossy(&script_sig).into_owned();

    println!("=====================================================");
    println!("  Bloch Genesis-2 Mining (carry-over chain, SHA-256d)");
    println!("=====================================================");
    println!();
    println!("Parameters");
    println!("  chain-id:    Genesis2Devnet (0x{:08X})", ChainId::Genesis2Devnet.to_u32());
    println!("  bits:        0x{:08x}", cli.bits);
    println!("  timestamp:   {}", cli.timestamp);
    println!("  miner_addr:  {}", cli.miner_addr);
    println!();
    println!("Carry-over commitment (baked constants, NOT arguments)");
    println!("  source height: {}", GENESIS2_CARRYOVER_SOURCE_HEIGHT);
    println!("  utxo count:    {}", GENESIS2_CARRYOVER_UTXO_COUNT);
    println!("  total sat:     {}", GENESIS2_CARRYOVER_TOTAL_SAT);
    println!("  snapshot root: {}", hex::encode(GENESIS2_CARRYOVER_SNAPSHOT_ROOT));
    println!("  coinbase script_sig: {:?}", commitment_text);
    println!();

    // Single shared construction path with the node (nonce filled in after
    // mining). Anything that changes these bytes invalidates the nonce.
    let template =
        core::create_genesis2_block_with_params(&miner_spk, cli.bits, cli.timestamp, 0);
    println!("Coinbase");
    println!("  txid:   {}", hex::encode(template.transactions[0].txid()));
    println!("  merkle: {}", hex::encode(template.header.merkle_root.0));
    println!();

    let n_threads = if cli.threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        cli.threads
    };
    println!("Mining SHA-256d on {} threads from nonce {}…", n_threads, cli.start_nonce);

    let start = Instant::now();
    // Budget: the full 32-bit space per worker (mine_sha256d stops at 2^32
    // regardless). Returns None on true nonce exhaustion — then the caller
    // must pick a new --timestamp; the space is NOT silently re-searched.
    let nonce = match bloch::pow::mine_sha256d(
        &template.header,
        cli.bits,
        cli.start_nonce,
        1u64 << 32,
        n_threads,
        // Genesis block is height 0 — pre-fork, legacy big-endian rule.
        false,
    ) {
        Some(n) => n,
        None => {
            eprintln!();
            eprintln!("Nonce space exhausted with no solution at bits 0x{:08x}.", cli.bits);
            eprintln!("Re-run with a different --timestamp (fresh 2^32 space).");
            std::process::exit(1);
        }
    };
    let elapsed = start.elapsed().as_secs_f64();

    // The candidate genesis: same construction path, mined nonce.
    let genesis =
        core::create_genesis2_block_with_params(&miner_spk, cli.bits, cli.timestamp, nonce);
    let block_hash = genesis.block_hash();
    let pow_hash = genesis.header.pow_hash();

    // Prove acceptance on the REAL validate path (Sha256d arm, chain pinned).
    let pow_ok = genesis.validate_pow();
    // Prove rejection of a tampered nonce on the same path.
    let tampered = core::create_genesis2_block_with_params(
        &miner_spk,
        cli.bits,
        cli.timestamp,
        nonce.wrapping_add(1),
    );
    // belt-and-braces: the raw target comparison must agree with the mined
    // verdict — if these ever disagree the dispatch is broken; refuse below.
    let raw_target_ok = hash_meets_target(&pow_hash, &bits_to_target(cli.bits));

    println!();
    println!("=====================================================");
    println!("  Genesis-2 Block Found");
    println!("=====================================================");
    println!();
    println!("  nonce:                    {}", nonce);
    println!("  pow_hash (SHA-256d):      {}", hex::encode(pow_hash));
    println!("  block_hash:               {}", hex::encode(block_hash));
    println!("  validate_pow (mined):     {}", pow_ok);
    println!("  validate_pow (nonce+1):   {} (must be false)", tampered.validate_pow());
    println!("  time:                     {:.1} s", elapsed);
    println!();
    println!("Bake into crates/bloch-crypto/src/core/mod.rs:");
    println!();
    println!("    pub const GENESIS2_TIMESTAMP: u64 = {};", cli.timestamp);
    println!("    pub const GENESIS2_BITS:      u32 = 0x{:08x};", cli.bits);
    println!("    pub const GENESIS2_NONCE:     u64 = {};", nonce);
    println!("    pub const GENESIS2_EXPECTED_HASH: [u8; 32] = [");
    for chunk in block_hash.chunks(8) {
        let row: Vec<String> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
        println!("        {},", row.join(", "));
    }
    println!("    ];");
    println!();
    println!("The node must then VALIDATE (never mine): create_genesis2_block(..)");
    println!(".validate_pow() AND block_hash == GENESIS2_EXPECTED_HASH, else exit(1) —");
    println!("fail closed, exactly like the existing genesis PoW check in main.rs.");

    if !pow_ok {
        eprintln!();
        eprintln!("REFUSING to emit: validate_pow rejected the mined genesis.");
        std::process::exit(1);
    }
    if tampered.validate_pow() {
        eprintln!();
        eprintln!("REFUSING to emit: a TAMPERED nonce also passed validate_pow —");
        eprintln!("the validation path is not discriminating (or nonce+1 is a real");
        eprintln!("solution — re-run with a different --start-nonce to disambiguate).");
        std::process::exit(1);
    }
    if !raw_target_ok {
        eprintln!();
        eprintln!("REFUSING to emit: validate_pow accepted but the raw hash/target");
        eprintln!("comparison disagrees — dispatch inconsistency. Do not bake these.");
        std::process::exit(1);
    }
}
