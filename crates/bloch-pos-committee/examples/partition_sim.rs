// SPDX-License-Identifier: AGPL-3.0-or-later

//! Partition simulator CLI (dev tooling). Prints a per-group timeline of
//! justified / finalized checkpoints and leak-adjusted weights, then a
//! summary with conflicting finality and claim double-payout detection.
//!
//! ```text
//! cargo run --release -p bloch-pos-committee --example partition_sim -- \
//!     [all|split2|split3|split50|offline|heal-both|solo3|votes-cross|delay]... \
//!     [--start-epoch N] [--max-epochs N] [--quiet]
//! ```
//!
//! `--start-epoch` (or `PARTITION_START_EPOCH`) chooses which activation
//! gates are live: the warm-up finalizes every epoch up to it. Default 5860.

#[path = "../tests/support/partition.rs"]
mod partition;

fn main() {
    let mut names: Vec<String> = vec![];
    let mut start = partition::default_start_epoch();
    let mut max = 4_000u64;
    let mut verbose = true;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--start-epoch" => start = args.next().and_then(|s| s.parse().ok()).expect("--start-epoch N"),
            "--max-epochs" => max = args.next().and_then(|s| s.parse().ok()).expect("--max-epochs N"),
            "--quiet" => verbose = false,
            "all" => names.extend(partition::SCENARIOS.iter().map(|s| s.to_string())),
            _ => names.push(a),
        }
    }
    if names.is_empty() {
        eprintln!("scenarios: {:?} (or all)", partition::SCENARIOS);
        std::process::exit(2);
    }
    for n in names {
        let Some(s) = partition::scenario(&n, start, max) else {
            eprintln!("unknown scenario {n}; known: {:?}", partition::SCENARIOS);
            std::process::exit(2);
        };
        let t = std::time::Instant::now();
        let r = partition::Sim::run(&s, verbose);
        println!("{}  wall time {:.1?}\n", r.summary(), t.elapsed());
    }
}
