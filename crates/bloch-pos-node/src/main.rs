// SPDX-License-Identifier: AGPL-3.0-or-later

//! # bloch-pos — the Genesis-4 node binary (skeleton)
//!
//! This binary exists so that the composition root of the PoS node has an
//! address in the tree before any consensus code is wired into it. Today it
//! does exactly three things: parse the two flags it recognises, run a
//! self-check over the frozen consensus parameters it links, and exit 0.
//! There is no consensus loop, no networking, no database.
//!
//! ## Why a new binary and not a feature in `bloch`
//!
//! The Genesis-3 validation path (repo-root `src/main.rs`) halts at height
//! 80,000 and is never modified by the PoS work — that rule is
//! non-negotiable (`docs/specs/BLOCH-POS-NODE-INTEGRATION.md` §0). A feature
//! flag inside `bloch` would put PoS code inside the binary whose only
//! remaining job is to stop correctly. A new binary makes the rule structural
//! rather than disciplinary.
//!
//! ## Ownership
//!
//! `main.rs` is the **composition root** and is change-controlled by the PMO
//! (§9.4 two-reviewer rule applies once real wiring begins). DEV-1/2/3 work
//! in their own module directories (`engine/`, `rules/`, `keys/`, `store/`,
//! `net/`, `rpc/`, `genesis/` — see the integration plan §2.2) and meet only
//! through the frozen traits in `bloch_pos_committee::interfaces`.

use bloch_pos_committee::genesis_cohort::{
    cohort_cap_bps, COHORT_CAP_FLOOR_BPS, COHORT_CAP_START_BPS, COHORT_TAPER_EPOCHS,
};
use bloch_pos_committee::params::{
    DS_ATTEST, DS_BLOCK, DS_BODY, DS_DEPOSIT, DS_EXIT, DS_PROPOSE, DS_RANDAO, DS_SLASH,
    DS_SORTITION, DS_STATE, RANDAO_CHAIN_LENGTH, SLOTS_PER_EPOCH, SLOT_DURATION_SECS,
};
use bloch_pos_committee::tokenomics_v4::{TOTAL_SUPPLY_SAT, VALIDATOR_EMISSION_BLOCH};

/// Genesis-4 block version (migration design §5.3). Lives here, not in the
/// pure crate: the network identity is the node's fact. Pinned by KAT once
/// A1's vector file covers headers.
const BLOCK_VERSION_V4: u32 = 0xB10C_0005;

const NAME: &str = env!("CARGO_PKG_NAME");
/// `pkg-version (git-commit[+dirty])`, stamped by build.rs. The commit is the
/// load-bearing part: the G8 release-integrity gate compares fleet, release
/// and source through it (deploy/RELEASE-INTEGRITY.md). Never fall back to
/// bare CARGO_PKG_VERSION — three identical "0.3.0-genesis2" strings on three
/// different binaries is the exact failure this replaces.
const VERSION: &str = env!("BLOCH_BUILD_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    for a in &args {
        match a.as_str() {
            "--version" | "-V" => {
                println!("{NAME} {VERSION} (Genesis-4 skeleton, block version {BLOCK_VERSION_V4:#010x})");
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => {
                eprintln!("{NAME}: unknown argument `{other}` (skeleton accepts only --version / --help)");
                std::process::exit(2);
            }
        }
    }

    println!("{NAME} {VERSION} — Bloch Genesis-4 PoS node (skeleton)");
    println!("block version {BLOCK_VERSION_V4:#010x}; slots {SLOT_DURATION_SECS}s x {SLOTS_PER_EPOCH}/epoch; randao chain {RANDAO_CHAIN_LENGTH}");

    self_check();

    println!("self-check passed; no consensus loop is wired yet — exiting.");
}

fn print_help() {
    println!(
        "{NAME} {VERSION} — Bloch Genesis-4 Proof-of-Stake node (skeleton)\n\
         \n\
         USAGE: bloch-pos [--version|--help]\n\
         \n\
         This skeleton boots, verifies the frozen consensus parameters it links\n\
         against the invariants below, and exits. It intentionally does nothing\n\
         else; the integration plan is docs/specs/BLOCH-POS-NODE-INTEGRATION.md."
    );
}

/// Sanity over the constants this binary will one day stake consensus on.
/// Each assert names the document that makes it an invariant. A failure here
/// means the linked `bloch-pos-committee` no longer matches the normative
/// specs and the binary must not proceed to do anything at all — which is
/// easy, because it can't.
fn self_check() {
    // §6.1 of the migration design: one hash, many uses, every use tagged,
    // and no two tags equal. A duplicated tag is a cross-protocol collision.
    let tags: [( &str, [u8; 16]); 10] = [
        ("DS_BLOCK", DS_BLOCK),
        ("DS_BODY", DS_BODY),
        ("DS_STATE", DS_STATE),
        ("DS_ATTEST", DS_ATTEST),
        ("DS_RANDAO", DS_RANDAO),
        ("DS_SORTITION", DS_SORTITION),
        ("DS_DEPOSIT", DS_DEPOSIT),
        ("DS_SLASH", DS_SLASH),
        ("DS_PROPOSE", DS_PROPOSE),
        ("DS_EXIT", DS_EXIT),
    ];
    for (i, (na, ta)) in tags.iter().enumerate() {
        assert!(ta.starts_with(b"BLCH4:"), "{na}: domain tag outside the BLCH4 namespace");
        for (nb, tb) in tags.iter().skip(i + 1) {
            assert_ne!(ta, tb, "domain tags {na} and {nb} collide");
        }
    }

    // BLOCH-TOKENOMICS-V4 §8.1: 21 B at 8 decimals must sit far below the
    // u64 wrap point (the 100 B draft did not). u128 carries it regardless;
    // this pins that the supply itself stayed in the safe zone.
    assert!(
        TOTAL_SUPPLY_SAT < (u64::MAX as u128) / 4,
        "total supply left the u64 headroom the V4 decision bought"
    );
    // §1 of the same document: validators get 43.03% — more than any single
    // insider bucket. The exact figure is tested in the pure crate; here we
    // only pin the ordering that made the 2026-08-11 reallocation meaningful.
    assert!(VALIDATOR_EMISSION_BLOCH > 9_000_000_000, "validator allocation shrank");

    // BLOCH-TOKENOMICS-V4 §3.3.1: the genesis-cohort cap starts at the whole
    // set, tapers linearly, and holds at one third from year one — the
    // "after year one the founder cannot halt Bloch alone" rule.
    assert_eq!(cohort_cap_bps(0), COHORT_CAP_START_BPS);
    assert_eq!(cohort_cap_bps(COHORT_TAPER_EPOCHS), COHORT_CAP_FLOOR_BPS);
    assert_eq!(cohort_cap_bps(10 * COHORT_TAPER_EPOCHS), COHORT_CAP_FLOOR_BPS);

    // Migration design §5.1: the slot cadence every other constant descends
    // from. If these move, every KAT and every capacity figure (G10) is stale.
    assert_eq!(SLOT_DURATION_SECS, 30);
    assert_eq!(SLOTS_PER_EPOCH, 32);
}
