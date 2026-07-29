//! Genesis-block grinder for the Genesis-3 MAINNET (fresh SHA-256d chain,
//! carry-over ledger).
//!
//! Mirrors `bloch-mine-genesis2`, with Genesis-3's two deliberate differences:
//!
//!   * ALL header parameters are the BAKED constants (`GENESIS3_BITS`,
//!     `GENESIS3_TIMESTAMP`, `GENESIS3_MINER_SCRIPT_PUBKEY`) — not CLI
//!     arguments — so the ground nonce is DETERMINISTIC and reproducible:
//!     anyone re-running this tool against the same source tree searches the
//!     exact same header bytes. (`--timestamp` exists ONLY for the ~37%
//!     chance the 2^32 nonce space at diff-1 has no solution; if used, the
//!     printed GENESIS3_TIMESTAMP must be baked alongside the nonce.)
//!   * The grind is LITTLE-ENDIAN (Bitcoin/ASIC convention) — Genesis-3
//!     validates SHA-256d little-endian FROM HEIGHT 0
//!     (`core::sha256d_le_fork_height_for(Genesis3Mainnet) == 0`), and this
//!     tool derives the endianness from THAT function, so the grinder and the
//!     validator provably apply the same comparison.
//!
//! Construction goes through `core::create_genesis3_block_with_params`, the
//! SINGLE path shared with the node's `create_genesis3_block` — grinder and
//! validator agree byte-for-byte by construction. The coinbase script_sig is
//! the Genesis-3 banner derived from the carry-over constants
//! (`core::genesis3_coinbase_script_sig()`), never an argument.
//!
//! Before printing, the tool proves the constants on the REAL validation
//! path: it pins the process chain-id to Genesis3Mainnet, checks
//! `validate_pow()` == true for the ground nonce (the exact dispatch a
//! `--genesis3` node runs at height 0), and checks that a tampered nonce
//! (ground+1) is REJECTED. It exits 1 unless both hold.
//!
//! Determinism note: the default is SINGLE-THREADED, scanning nonces
//! sequentially from `--start-nonce` (default 0) — the result is the SMALLEST
//! valid nonce, bit-for-bit reproducible. `--threads N` (N > 1) grinds
//! faster; any nonce it finds is equally consensus-valid and is verified the
//! same way, but early-exit racing means it is not guaranteed to be the
//! smallest. For the canonical ceremony, run the default.
//!
//! Usage
//! -----
//!
//! ```
//! cargo run --release --bin grind_genesis3
//! # faster, non-canonical search order:
//! cargo run --release --bin grind_genesis3 -- --threads 8
//! ```
//!
//! Then bake the printed `GENESIS3_NONCE` / `GENESIS3_EXPECTED_HASH` (and
//! `GENESIS3_TIMESTAMP`, if overridden) into
//! `crates/bloch-crypto/src/core/mod.rs` and rebuild. From that point
//! `create_genesis3_block` ENFORCES them (fail closed).

use clap::Parser;
use bloch::core::{
    self, bits_to_target, node_chain_id, set_node_chain_id, sha256d_le_fork_height_for,
    sha256d_pow_valid_for_chain, ChainId,
    GENESIS3_BITS, GENESIS3_CARRYOVER_SNAPSHOT_ROOT, GENESIS3_CARRYOVER_SOURCE_HEIGHT,
    GENESIS3_CARRYOVER_TOTAL_SAT, GENESIS3_CARRYOVER_UTXO_COUNT,
    GENESIS3_MINER_SCRIPT_PUBKEY, GENESIS3_TIMESTAMP,
};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "grind_genesis3")]
#[command(about = "Grind GENESIS3_NONCE for the Genesis-3 mainnet (SHA-256d, little-endian from height 0)")]
struct Cli {
    /// Number of grinding threads. Default 1 == the canonical DETERMINISTIC
    /// search (smallest valid nonce). >1 is faster but the found nonce may
    /// not be the smallest (still consensus-valid and fully verified).
    #[arg(long, default_value = "1")]
    threads: usize,

    /// Starting nonce (< 2^32; the SHA-256d nonce space is 32-bit).
    #[arg(long, default_value = "0")]
    start_nonce: u64,

    /// Timestamp override. ONLY for the case where the full 2^32 nonce space
    /// at GENESIS3_BITS holds no solution (~37% per timestamp): re-run with
    /// GENESIS3_TIMESTAMP+1, +2, … and bake the printed timestamp TOO.
    /// Default: the baked GENESIS3_TIMESTAMP.
    #[arg(long)]
    timestamp: Option<u64>,
}

fn main() {
    let cli = Cli::parse();
    let timestamp = cli.timestamp.unwrap_or(GENESIS3_TIMESTAMP);

    // Pin THIS process to the Genesis-3 chain so validate_pow() below runs
    // the real Sha256d arm under the real per-chain endianness rule — the
    // same dispatch a --genesis3 node will execute at height 0.
    set_node_chain_id(ChainId::Genesis3Mainnet)
        .expect("chain-id already pinned to a different chain in this process");
    assert_eq!(node_chain_id(), ChainId::Genesis3Mainnet);

    // The endianness the validator applies at height 0, derived from the SAME
    // single source of truth (never hard-coded here): LE fork height 0 ⇒
    // little-endian from genesis.
    let le_fork_height = sha256d_le_fork_height_for(ChainId::Genesis3Mainnet);
    let little_endian = 0u64 >= le_fork_height;
    assert!(
        little_endian,
        "Genesis-3 must be little-endian from height 0 (sha256d_le_fork_height_for == {le_fork_height}); \
         the per-chain endianness rule changed — do not grind against the wrong rule",
    );

    let miner_spk: Vec<u8> = GENESIS3_MINER_SCRIPT_PUBKEY.to_vec();
    let script_sig = core::genesis3_coinbase_script_sig();
    let commitment_text = String::from_utf8_lossy(&script_sig).into_owned();

    println!("========================================================");
    println!("  Bloch Genesis-3 Grinder (MAINNET, SHA-256d, LE from h0)");
    println!("========================================================");
    println!();
    println!("Parameters (baked constants — NOT arguments)");
    println!("  chain-id:    Genesis3Mainnet (0x{:08X})", ChainId::Genesis3Mainnet.to_u32());
    println!("  bits:        0x{:08x}", GENESIS3_BITS);
    println!("  timestamp:   {}{}", timestamp,
             if cli.timestamp.is_some() { "  (OVERRIDE — bake this too!)" } else { "" });
    println!("  miner spk:   {} (founder hash-20)", hex::encode(GENESIS3_MINER_SCRIPT_PUBKEY));
    println!("  endianness:  little-endian from height 0 (ASIC-native)");
    println!();
    println!("Carry-over commitment (same ledger as Genesis-2)");
    println!("  source height: {}", GENESIS3_CARRYOVER_SOURCE_HEIGHT);
    println!("  utxo count:    {}", GENESIS3_CARRYOVER_UTXO_COUNT);
    println!("  total sat:     {}", GENESIS3_CARRYOVER_TOTAL_SAT);
    println!("  snapshot root: {}", hex::encode(GENESIS3_CARRYOVER_SNAPSHOT_ROOT));
    println!("  coinbase script_sig: {:?}", commitment_text);
    println!();

    // Single shared construction path with the node (nonce filled in after
    // grinding). Anything that changes these bytes invalidates the nonce.
    let template =
        core::create_genesis3_block_with_params(&miner_spk, GENESIS3_BITS, timestamp, 0);
    println!("Coinbase");
    println!("  txid:   {}", hex::encode(template.transactions[0].txid()));
    println!("  merkle: {}", hex::encode(template.header.merkle_root.0));
    println!();

    let n_threads = cli.threads.max(1);
    if n_threads == 1 {
        println!("Grinding SHA-256d (little-endian) SINGLE-THREADED from nonce {} — \
                  canonical deterministic search…", cli.start_nonce);
    } else {
        println!("Grinding SHA-256d (little-endian) on {} threads from nonce {} — \
                  NON-canonical search order (any found nonce is still valid)…",
                 n_threads, cli.start_nonce);
    }

    let start = Instant::now();
    // Budget: the full 32-bit space (mine_sha256d stops at 2^32 regardless).
    // The `little_endian` argument is the value derived from the per-chain
    // rule above — the same condition Block::validate_pow will re-check.
    let nonce = match bloch::pow::mine_sha256d(
        &template.header,
        GENESIS3_BITS,
        cli.start_nonce,
        1u64 << 32,
        n_threads,
        little_endian,
    ) {
        Some(n) => n,
        None => {
            eprintln!();
            eprintln!("Nonce space exhausted with no solution at bits 0x{:08x}.", GENESIS3_BITS);
            eprintln!("Re-run with `--timestamp {}` (fresh 2^32 space) and bake the", timestamp + 1);
            eprintln!("printed GENESIS3_TIMESTAMP alongside the nonce and hash.");
            std::process::exit(1);
        }
    };
    let elapsed = start.elapsed().as_secs_f64();

    // The candidate genesis: same construction path, ground nonce.
    let genesis =
        core::create_genesis3_block_with_params(&miner_spk, GENESIS3_BITS, timestamp, nonce);
    let block_hash = genesis.block_hash();
    let pow_hash = genesis.header.pow_hash();

    // Prove acceptance on the REAL validate path (Sha256d arm, chain pinned to
    // Genesis3Mainnet ⇒ little-endian at height 0).
    let pow_ok = genesis.validate_pow();
    // Prove rejection of a tampered nonce on the same path.
    let tampered = core::create_genesis3_block_with_params(
        &miner_spk, GENESIS3_BITS, timestamp, nonce.wrapping_add(1),
    );
    // Belt-and-braces: the chain-explicit check (what create_genesis3_block
    // enforces at every future node startup) must agree with validate_pow.
    let chain_explicit_ok = sha256d_pow_valid_for_chain(
        ChainId::Genesis3Mainnet, &pow_hash, &bits_to_target(GENESIS3_BITS), 0,
    );

    println!();
    println!("========================================================");
    println!("  Genesis-3 Block Found");
    println!("========================================================");
    println!();
    println!("  nonce:                       {}", nonce);
    println!("  pow_hash (raw SHA-256d):     {}", hex::encode(pow_hash));
    println!("  block_hash:                  {}", hex::encode(block_hash));
    println!("  validate_pow (ground):       {}", pow_ok);
    println!("  validate_pow (nonce+1):      {} (must be false)", tampered.validate_pow());
    println!("  chain-explicit LE check:     {}", chain_explicit_ok);
    println!("  time:                        {:.1} s", elapsed);
    println!();
    println!("Bake into crates/bloch-crypto/src/core/mod.rs:");
    println!();
    if cli.timestamp.is_some() {
        println!("    pub const GENESIS3_TIMESTAMP: u64 = {};", timestamp);
    }
    println!("    pub const GENESIS3_NONCE: u64 = {};", nonce);
    println!("    pub const GENESIS3_EXPECTED_HASH: [u8; 32] = [");
    for chunk in block_hash.chunks(8) {
        let row: Vec<String> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
        println!("        {},", row.join(", "));
    }
    println!("    ];");
    println!();
    println!("After baking, `create_genesis3_block` VERIFIES these at every node");
    println!("startup (PoW under the LE-from-h0 rule + exact block-hash pin) and");
    println!("panics on any drift — fail closed, never fail open.");

    if !pow_ok {
        eprintln!();
        eprintln!("REFUSING to emit: validate_pow rejected the ground genesis.");
        std::process::exit(1);
    }
    if tampered.validate_pow() {
        eprintln!();
        eprintln!("REFUSING to emit: a TAMPERED nonce also passed validate_pow —");
        eprintln!("the validation path is not discriminating (or nonce+1 is a real");
        eprintln!("solution — re-run with a different --start-nonce to disambiguate).");
        std::process::exit(1);
    }
    if !chain_explicit_ok {
        eprintln!();
        eprintln!("REFUSING to emit: validate_pow accepted but the chain-explicit");
        eprintln!("little-endian check disagrees — dispatch inconsistency. Do not");
        eprintln!("bake these.");
        std::process::exit(1);
    }
}
