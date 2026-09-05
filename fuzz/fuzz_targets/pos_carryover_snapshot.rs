#![no_main]
//! Fuzz `genesis::read_carryover_snapshot` — the parser that reads Genesis-4's
//! opening ledger out of a 54 MB text file.
//!
//! It is a text parser (hex, decimal, tabs, line splitting) over a file the
//! node does not author, which is the shape that historically hides panics:
//! slicing, `unwrap` on `try_into`, and arithmetic that overflows on a value
//! nobody expected to see. It is also the one parser whose *output* is money —
//! every balance on the live chain descends from what it returns.
//!
//! So the assertions are the ledger's own invariants, checked on every
//! accepted input:
//!
//!   * **Conservation.** The returned entries sum to exactly `total_sat`. The
//!     dust rule hands the split remainder to a single output; if that hand-off
//!     ever drops or duplicates a satoshi, the opening supply silently differs
//!     from the total the commitment was checked against.
//!   * **`total_sat` is the split of the declared Genesis-3 total** — the sum
//!     of floors plus the gathered remainder, not an independently accumulated
//!     figure.
//!   * **Outpoints strictly ascend.** This is the only check that catches a
//!     duplicated outpoint, which `CommittedState::genesis` would otherwise
//!     absorb into its map — dropping one copy and leaving the ledger short of
//!     the total it just verified.
//!
//! `bloch-pos-node` is a `[[bin]]`-only crate, so the modules are pulled in by
//! `#[path]`: these bytes run the node's own source, not a copy of it.
//! `genesis` reaches `crate::codec`, so `codec` is declared here too.
use libfuzzer_sys::fuzz_target;

// The whole module compiles in, but a target drives one entry point, so the
// rest is dead code *here* — not in the node.
#[allow(dead_code)]
#[path = "../../crates/bloch-pos-node/src/codec.rs"]
mod codec;
#[allow(dead_code)]
#[path = "../../crates/bloch-pos-node/src/genesis.rs"]
mod genesis;

fuzz_target!(|data: &[u8]| {
    // `&[u8]` is a `BufRead`, which is the bound the reader takes — the same
    // trait the production `load_carryover` hands it a `BufReader<File>` for.
    let Ok(snap) = genesis::read_carryover_snapshot(data) else { return };

    let summed: u128 = snap.entries.iter().map(|e| u128::from(e.value)).sum();
    assert_eq!(summed, snap.total_sat, "entries do not sum to the declared opening total");

    assert_eq!(
        snap.total_sat,
        bloch_pos_committee::tokenomics_v4::split_g3_sat(snap.g3_total_sat),
        "opening total is not the split of the Genesis-3 total"
    );

    for w in snap.entries.windows(2) {
        assert!(
            (w[0].txid, w[0].vout) < (w[1].txid, w[1].vout),
            "outpoints are not strictly ascending"
        );
    }
});
