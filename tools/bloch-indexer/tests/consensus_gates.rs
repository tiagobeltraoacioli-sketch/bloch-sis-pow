// SPDX-License-Identifier: AGPL-3.0-or-later

//! The indexer's gate table must list every activation gate the consensus
//! crate defines. A hard-fork branch that adds `FOO_ACTIVATION_EPOCH` (or any
//! other `pub const *_EPOCH: u64`) to
//! `params.rs` fails here until `src/consensus.rs` lists it — the moment to
//! work through the flag-day checklist in `docs/BLOCH-INDEXER.md`.

use std::collections::BTreeSet;

fn params_gate_names() -> BTreeSet<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/bloch-pos-committee/src/params.rs");
    let src = std::fs::read_to_string(&path).expect("read params.rs");
    let mut names = BTreeSet::new();
    for line in src.lines() {
        let Some(rest) = line.trim_start().strip_prefix("pub const ") else { continue };
        let name: String = rest.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect();
        // Every epoch-valued schedule constant, whatever its naming style
        // (`*_ACTIVATION_EPOCH`, `*_REGISTRATION_EPOCH`, `HF1_*_EPOCH`, ...).
        // Durations end in `_EPOCHS` and are not gates.
        if name.ends_with("_EPOCH") && name != "SLOTS_PER_EPOCH" && rest[name.len()..].trim_start().starts_with(": u64") {
            names.insert(name);
        }
    }
    names
}

#[test]
fn every_consensus_activation_gate_is_listed() {
    let listed: BTreeSet<String> =
        bloch_indexer::consensus::GATES.iter().map(|g| g.name.to_string()).collect();
    let defined = params_gate_names();
    assert!(defined.len() >= 20, "params.rs parse looks wrong: {defined:?}");
    let missing: Vec<_> = defined.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "activation gates defined in bloch-pos-committee but not listed in \
         tools/bloch-indexer/src/consensus.rs: {missing:?}. Add them, then work through \
         docs/BLOCH-INDEXER.md \"Flag days\" for any new transaction kind or ledger effect."
    );
    let stale: Vec<_> = listed.difference(&defined).collect();
    assert!(stale.is_empty(), "listed gates no longer defined: {stale:?}");
}

#[test]
fn the_gate_digest_moves_with_the_schedule() {
    use bloch_indexer::consensus::{gate_digest, highest_armed_epoch, table, GATES};
    assert_eq!(gate_digest(), gate_digest());
    let highest = highest_armed_epoch().expect("mainnet has armed gates");
    assert!(GATES.iter().any(|g| g.epoch == highest));
    assert!(highest >= bloch_pos_committee::params::L2_SETTLEMENT_ACTIVATION_EPOCH);
    let t = table();
    assert!(t.contains("gate digest") && t.contains("inert"));
}
