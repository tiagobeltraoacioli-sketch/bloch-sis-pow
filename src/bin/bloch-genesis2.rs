//! Genesis-2 preparation — turn a UTXO snapshot into a carry-over commitment.
//!
//! Reads a snapshot produced by `bloch-snapshot-utxo`, VERIFIES it against the
//! emission schedule, and prints the constants a new chain would bake in so that
//! its genesis is cryptographically bound to the exact ledger it carries over.
//!
//! # What this does NOT do
//!
//! It does not mine a genesis block, choose a PoW algorithm, set a difficulty, or
//! launch anything. Those depend on decisions this tool has no business making.
//! It produces the one artifact that is independent of all of them: the commitment.
//!
//! # Why a commitment instead of 413,743 genesis outputs
//!
//! A genesis block could literally recreate every UTXO as an output. It would be
//! ~50 MB, self-contained, and verifiable by inspection. The alternative — commit
//! to the set's root and distribute the set as a file — is what Bitcoin's
//! `assumeutxo` and Ethereum's snap sync do, and it is the right call here for a
//! specific reason: this chain cannot serve its own history anyway (bodies below
//! ~394,913 were pruned everywhere and are unrecoverable), so a newcomer is going
//! to start from a distributed artifact regardless. Better to make that artifact
//! explicit and hash-bound than to pretend a 50 MB genesis changes the trust model.
//!
//! # The honest part
//!
//! Whoever starts from this trusts that the snapshot is the real ledger. The
//! commitment makes DISAGREEMENT detectable — several operators producing the same
//! root at the same height is meaningful evidence; one tool's output is not. Take
//! the snapshot at a stated, FROZEN height (stop the node), publish height + root
//! together, and have others reproduce it before anyone builds on it.
//!
//! # Usage
//!
//! ```text
//! bloch-genesis2 --snapshot utxo-snapshot.tsv --height 413743
//! ```

use std::io::{BufRead, BufReader};

/// Emission is flat at 8,400 BLCH/block until the first halving at 1,036,800, so
/// for any height this chain has reached, expected supply is a plain product.
/// Kept local and named rather than imported so the check is legible here — if it
/// ever disagrees with tokenomics_v2, that disagreement is the finding.
const REWARD_BLOCH_PER_BLOCK: u64 = 8_400;
const SAT_PER_BLOCH: u64 = 100_000_000;
const FIRST_HALVING_HEIGHT: u64 = 1_036_800;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut snapshot = String::new();
    let mut claimed_height: Option<u64> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--snapshot" if i + 1 < args.len() => { snapshot = args[i + 1].clone(); i += 2; }
            "--height"   if i + 1 < args.len() => {
                claimed_height = args[i + 1].parse().ok(); i += 2;
            }
            "-h" | "--help" => {
                eprintln!("usage: bloch-genesis2 --snapshot <file.tsv> --height <n>");
                std::process::exit(0);
            }
            other => { eprintln!("unknown argument: {other}"); std::process::exit(2); }
        }
    }
    if snapshot.is_empty() {
        eprintln!("--snapshot is required"); std::process::exit(2);
    }
    let height = match claimed_height {
        Some(h) => h,
        None => { eprintln!("--height is required: a snapshot without a stated height \
                             cannot be reproduced or compared"); std::process::exit(2); }
    };
    // A zero height passes every arithmetic check vacuously: 0 == 0 x 8,400 and an
    // empty file has 0 lines. The tool would emit a fully-formed commitment over
    // NOTHING, and a chain launched from it would carry no balances at all while
    // looking correctly verified. Found by adversarial review, not by testing.
    if height == 0 {
        eprintln!("height 0 is not a valid carry-over point: every check below would \
                   pass vacuously over an empty ledger");
        std::process::exit(2);
    }
    if height >= FIRST_HALVING_HEIGHT {
        eprintln!("height {height} is at or past the first halving ({FIRST_HALVING_HEIGHT}); \
                   the flat-emission check below no longer applies — extend this tool before \
                   trusting its arithmetic");
        std::process::exit(2);
    }

    let f = match std::fs::File::open(&snapshot) {
        Ok(f)  => f,
        Err(e) => { eprintln!("cannot read {snapshot}: {e}"); std::process::exit(1); }
    };

    // Recompute the root over the file exactly as written — same bytes, same order.
    use sha3::{Digest, Shake256};
    use sha3::digest::{Update, ExtendableOutput, XofReader};
    let mut hasher = Shake256::default();

    let mut count: u64 = 0;
    let mut total_sat: u128 = 0;
    let mut malformed: u64 = 0;
    for line in BufReader::new(f).lines() {
        let line = match line {
            Ok(l)  => l,
            Err(e) => { eprintln!("read error: {e}"); std::process::exit(1); }
        };
        let with_nl = format!("{line}\n");
        Update::update(&mut hasher, with_nl.as_bytes());
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 4 { malformed += 1; continue; }
        match parts[2].parse::<u64>() {
            Ok(v)  => { total_sat += v as u128; count += 1; }
            Err(_) => { malformed += 1; }
        }
    }

    let mut reader = hasher.finalize_xof();
    let mut root = [0u8; 32];
    reader.read(&mut root);
    let root_hex = hex::encode(root);

    // ── Verification ──────────────────────────────────────────────────────────
    // Supply must equal height × reward exactly. A snapshot missing even one UTXO
    // fails this, which is the point: the root proves the FILE is intact, this
    // proves the SET is complete.
    let expected_sat = (height as u128) * (REWARD_BLOCH_PER_BLOCK as u128) * (SAT_PER_BLOCH as u128);
    let supply_ok = total_sat == expected_sat;
    let count_ok  = count == height;

    println!("Genesis-2 carry-over commitment");
    println!("  snapshot file      : {snapshot}");
    println!("  stated height      : {height}");
    println!("  utxo count         : {count}");
    println!("  total supply       : {} BLCH", total_sat / SAT_PER_BLOCH as u128);
    println!("  SHAKE-256 root     : {root_hex}");
    if malformed > 0 {
        eprintln!("REFUSING: {malformed} malformed line(s) in {snapshot}.");
        eprintln!("A malformed line is skipped by the arithmetic but still hashed into the");
        eprintln!("root, so a corrupted file yields a DIFFERENT root that passes every check");
        eprintln!("below — a blessed commitment over a ledger nobody can reproduce. Earlier");
        eprintln!("this printed a warning and exited 0, which is the same defect this whole");
        eprintln!("migration exists to stop: a warning nobody reads is not a gate.");
        std::process::exit(1);
    }
    println!();
    println!("Verification");
    println!("  NOTE: these check the ledger's SHAPE, not its OWNERSHIP. A file with the");
    println!("  same count and the same total, but every script_pubkey reassigned, passes");
    println!("  both. The root binds THIS file; it does not prove the file reflects the");
    println!("  real chain. Only independent reproduction at the same frozen height does.");
    println!("  supply == height x {REWARD_BLOCH_PER_BLOCK} BLCH : {}",
             if supply_ok { "PASS" } else { "FAIL" });
    println!("  utxo count == height                : {}",
             if count_ok { "PASS" } else { "FAIL" });
    if !supply_ok {
        let d = total_sat as i128 - expected_sat as i128;
        println!("    expected {} BLCH, got {} BLCH (difference {} BLCH)",
                 expected_sat / SAT_PER_BLOCH as u128,
                 total_sat / SAT_PER_BLOCH as u128,
                 d / SAT_PER_BLOCH as i128);
        println!("    A mismatch usually means the snapshot was taken while the node kept");
        println!("    mining, so it does not correspond to the stated height. Stop the node");
        println!("    at an announced height and take it again — a migration snapshot must");
        println!("    be frozen, or two operators cannot produce the same root.");
    }
    println!();

    if !(supply_ok && count_ok) {
        eprintln!("REFUSING to emit genesis constants: the snapshot did not verify.");
        eprintln!("Fix the snapshot first. A commitment over an unverified set would bind");
        eprintln!("the new chain to a ledger nobody checked, which is worse than no commitment.");
        std::process::exit(1);
    }

    // ── The artifact ──────────────────────────────────────────────────────────
    println!("Bake these into the new chain (constants, like GENESIS_NONCE):");
    println!();
    println!("    pub const CARRYOVER_SNAPSHOT_ROOT:   [u8; 32] = hex!(\"{root_hex}\");");
    println!("    pub const CARRYOVER_SOURCE_HEIGHT:   u64      = {height};");
    println!("    pub const CARRYOVER_UTXO_COUNT:      u64      = {count};");
    println!("    pub const CARRYOVER_TOTAL_SAT:       u128     = {total_sat};");
    println!();
    println!("Suggested genesis coinbase script_sig (binds the chain's identity to the");
    println!("ledger it carries, and is human-readable in a block explorer):");
    println!();
    println!("    Bloch carry-over from height {height}: {count} UTXOs, root {}...",
             &root_hex[..16]);
    println!();
    println!("A node starting from this MUST refuse to run if the snapshot it loads does");
    println!("not hash to CARRYOVER_SNAPSHOT_ROOT — fail closed, exactly as the genesis PoW");
    println!("check does today. Publish the root and the height together, and have other");
    println!("operators reproduce both before anyone builds on it.");
}
