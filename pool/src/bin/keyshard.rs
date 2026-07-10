//! bloch-pool-keyshard — procedural M-of-N seed recovery utility.
//!
//! Splits the pool operator's 32-byte wallet seed into 3 Shamir shares
//! (any 2 reconstruct) and recombines them. **Recovery only, not
//! threshold signing** — see `keyshard.rs` and README "Custody" for
//! the honest scope of what this does and does not protect.
//!
//! Run SPLIT and RECOVER on an isolated, offline machine: both handle
//! the raw seed. Shares travel on argv here (reference-grade) — clear
//! your shell history afterwards.

use clap::{Parser, Subcommand};

use bloch_pool::keyshard::{recover_seed, split_seed, SHARE_COUNT, THRESHOLD};

#[derive(Parser, Debug)]
#[command(
    name = "bloch-pool-keyshard",
    about = "Shamir 2-of-3 RECOVERY sharding for the pool wallet seed. \
             Procedural M-of-N: the seed still exists in one place at \
             recovery/signing time — this is disaster resilience, not \
             threshold signing.",
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Split a 32-byte seed (64 hex chars) into 3 shares (2-of-3).
    Split {
        /// The wallet seed, hex.
        #[arg(long)]
        seed_hex: String,
    },
    /// Recombine 2 or more shares back into the seed.
    Recover {
        /// A share (hex); pass --share at least twice.
        #[arg(long = "share", required = true)]
        shares: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    eprintln!("bloch-pool-keyshard: PROCEDURAL M-of-N — key RECOVERY, not \
               threshold signing. The seed is whole in this process's \
               memory; run this offline. On-chain multisig awaits GIP-008.");

    match cli.cmd {
        Cmd::Split { seed_hex } => {
            let bytes = match hex::decode(seed_hex.trim()) {
                Ok(b) => b,
                Err(e) => { eprintln!("seed is not valid hex: {}", e); std::process::exit(1); }
            };
            let seed: [u8; 32] = match bytes.try_into() {
                Ok(s) => s,
                Err(b) => {
                    eprintln!("seed must be exactly 32 bytes, got {}", b.len());
                    std::process::exit(1);
                }
            };
            let shares = split_seed(&seed);
            println!("{} shares, any {} reconstruct the seed.", SHARE_COUNT, THRESHOLD);
            println!("Give ONE to each custodian; never store two together:");
            for (i, s) in shares.iter().enumerate() {
                println!("share {}: {}", i + 1, hex::encode(s));
            }
        }
        Cmd::Recover { shares } => {
            let decoded: Vec<Vec<u8>> = shares.iter().enumerate().map(|(i, s)| {
                hex::decode(s.trim()).unwrap_or_else(|e| {
                    eprintln!("share {} is not valid hex: {}", i + 1, e);
                    std::process::exit(1);
                })
            }).collect();
            match recover_seed(&decoded) {
                Ok(seed) => {
                    println!("seed: {}", hex::encode(seed));
                    eprintln!("(reconstructed in THIS process — use it, then \
                               clear terminal scrollback and shell history)");
                }
                Err(e) => { eprintln!("{}", e); std::process::exit(1); }
            }
        }
    }
}
