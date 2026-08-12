// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI for the Genesis-4 genesis ceremony. See lib.rs for what is built and
//! why; see README.md for the runbook.

use bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH;
use genesis4_ceremony::*;
use std::process::ExitCode;

const USAGE: &str = "\
genesis4-ceremony — assemble the Genesis-4 genesis block from the carryover
artifact and the genesis validator cohort

USAGE:
    genesis4-ceremony \\
        --carryover genesis4-carryover.tsv \\
        --carryover-shake256 <64-hex published digest> \\
        --cohort genesis4-cohort.tsv \\
        --founder <addr40> --vc <addr40> --team <addr40> \\
        --marketing <addr40> --liquidity <addr40> \\
        --out genesis4

Reads the plain-text carryover artifact (addr<TAB>value_sat, sorted — the file
build_carryover.py emits; gunzip it first if compressed), recomputes its
SHAKE-256, and refuses to proceed unless it matches the published digest.

Reads the genesis validator cohort (tokenomics §3.3): one line per validator,
index<TAB>pubkey<TAB>randao_c0<TAB>stake_sat<TAB>withdrawal, indices from 0,
raw ML-DSA-65 ‖ Falcon-1024 pubkeys (no suite envelope), at least 64 members,
funded from the liquidity bucket. The cohort is published in the block; the
one-year declining cap binds exactly this set.

Writes:
    <out>.tsv           canonical genesis allocation document (incl. cohort)
    <out>.tsv.shake256  its SHAKE-256 digest
    <out>.header.bin    canonical BlockHeaderV4 (little-endian, spec order)

Prints the genesis block_id and state_root. Several operators should run this
independently on the same artifact and compare block_ids — agreement between
independent parties is the evidence, not one party's output.";

fn arg(args: &[String], name: &str) -> Result<String, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it
                .next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"));
        }
    }
    Err(format!("missing required argument {name}"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") || args.is_empty() {
        println!("{USAGE}");
        return Ok(());
    }

    let carry_path = arg(&args, "--carryover")?;
    let digest_hex = arg(&args, "--carryover-shake256")?;
    let cohort_path = arg(&args, "--cohort")?;
    let out_base = arg(&args, "--out")?;
    let addrs = BucketAddrs {
        founder: arg(&args, "--founder")?,
        vc: arg(&args, "--vc")?,
        team: arg(&args, "--team")?,
        marketing: arg(&args, "--marketing")?,
        liquidity: arg(&args, "--liquidity")?,
    };

    let expected: [u8; 32] = hex::decode(digest_hex.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("--carryover-shake256 must be 64 hex chars (32 bytes)")?;

    if carry_path.ends_with(".gz") {
        return Err("gunzip the artifact first — the ceremony hashes the plain bytes".into());
    }
    let text = std::fs::read_to_string(&carry_path)
        .map_err(|e| format!("cannot read {carry_path}: {e}"))?;
    let cohort_text = std::fs::read_to_string(&cohort_path)
        .map_err(|e| format!("cannot read {cohort_path}: {e}"))?;

    let carry = read_carryover(&text)?;
    let cohort = read_cohort(&cohort_text)?;
    let genesis = build_genesis(&carry, &addrs, &cohort, &expected)?;
    let doc = render_document(&genesis);
    let doc_digest = document_digest(&doc);
    let header = genesis_header(&genesis);

    let doc_path = format!("{out_base}.tsv");
    let sum_path = format!("{out_base}.tsv.shake256");
    let hdr_path = format!("{out_base}.header.bin");
    std::fs::write(&doc_path, &doc).map_err(|e| format!("write {doc_path}: {e}"))?;
    std::fs::write(&sum_path, format!("{}  {}\n", hex::encode(doc_digest), doc_path))
        .map_err(|e| format!("write {sum_path}: {e}"))?;
    std::fs::write(&hdr_path, header.serialize())
        .map_err(|e| format!("write {hdr_path}: {e}"))?;

    // Display only; the divisor is the imported constant, not a restatement.
    let bloch = |sat: u128| format!("{}.{:08}", sat / SAT_PER_BLOCH, sat % SAT_PER_BLOCH);
    println!("carryover artifact   : {carry_path}");
    println!("  digest (verified)  : {}", hex::encode(carry.digest));
    println!("  holders            : {}", carry.rows.len());
    println!("  issued             : {} BLCH (the whole measured ledger — cap retired)", bloch(genesis.carryover_issued_sat));
    println!();
    println!("genesis cohort       : {cohort_path}");
    println!("  validators         : {}", genesis.validators.len());
    println!("  bonded stake       : {} BLCH (funded from liquidity, §3.3.1)", bloch(genesis.cohort_stake_sat));
    println!("  cohort_root        : {}", hex::encode(cohort_root(&genesis)));
    println!();
    for o in genesis.outputs.iter().filter(|o| o.bucket != "holder") {
        println!(
            "alloc {:<10} {} BLCH  tge {} bps, cliff {} slots, linear {} slots",
            o.bucket,
            bloch(o.value_sat),
            o.schedule.tge_bps,
            o.schedule.cliff_slots,
            o.schedule.linear_slots
        );
    }
    println!();
    println!("document             : {doc_path}");
    println!("  SHAKE-256          : {}", hex::encode(doc_digest));
    println!("header               : {hdr_path} ({} bytes)", HEADER_V4_LEN);
    println!("  state_root         : {}", hex::encode(header.state_root));
    println!("  block_id           : {}", hex::encode(header.block_id()));
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
