// SPDX-License-Identifier: AGPL-3.0-or-later

//! Partition harness: deterministic multi-node scenarios over the real
//! transition. See `tests/support/partition.rs` for the model and for how to
//! point it at another branch's activation epochs.
//!
//! The fast tests below assert harness invariants only (determinism, every
//! block the producers built was accepted by the real transition), never a
//! verdict on the rules, so the same file runs unchanged on candidate
//! branches whose rules differ. The full scenarios are `#[ignore]`d (long);
//! run them, in release, with:
//!
//! ```text
//! cargo test --release -p bloch-pos-committee --test partition -- --ignored --nocapture
//! # or one scenario, with a timeline:
//! cargo run --release -p bloch-pos-committee --example partition_sim -- solo3
//! ```

#[path = "support/partition.rs"]
mod partition;

use partition::{default_start_epoch, scenario, Sim, SCENARIOS};

/// The fast tests warm up only to `PARTITION_TEST_START_EPOCH` (default 64)
/// so they stay cheap in a debug build; the ignored full run uses
/// `PARTITION_START_EPOCH` (default 5860, the live gates).
fn fast_start() -> u64 {
    std::env::var("PARTITION_TEST_START_EPOCH").ok().and_then(|s| s.parse().ok()).unwrap_or(64)
}

fn run_at(name: &str, start: u64, max: u64) -> partition::Report {
    let s = scenario(name, start, max).expect("known scenario");
    let r = Sim::run(&s, false);
    println!("{}", r.summary());
    assert!(!r.log.contains("could not build"), "a producer built a block the real transition refused:\n{}", r.log);
    r
}

/// Same inputs, same outcome, bit for bit: the harness has no clock, no
/// threads and no RNG.
#[test]
fn partition_harness_is_deterministic() {
    let a = run_at("votes-cross", fast_start(), 0);
    let b = run_at("votes-cross", fast_start(), 0);
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.final_heads, b.final_heads);
}

#[test]
fn partition_harness_delay_scenario_runs() {
    let r = run_at("delay", fast_start(), 0);
    assert!(r.stats.blocks > 0);
}

#[test]
#[ignore = "long: thousands of epochs under the ETH-paced leak; run in release"]
fn partition_harness_all_scenarios() {
    let max: u64 = std::env::var("PARTITION_MAX_EPOCHS").ok().and_then(|s| s.parse().ok()).unwrap_or(4_000);
    for name in SCENARIOS {
        run_at(name, default_start_epoch(), max);
    }
}
