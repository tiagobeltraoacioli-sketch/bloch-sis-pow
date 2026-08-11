// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! TERMINAL-HEIGHT lab — the Genesis-3 chain stops at height 80,000.
//!
//! The unit tests in `bloch-crypto` pin `terminal_height(id)` by passing the
//! chain-id directly. That is not the path the node takes. At runtime the node
//! calls `is_past_terminal_height(h)`, which reads the process-wide chain-id
//! set once at startup from `--genesis3`.
//!
//! The dangerous failure is silent: if that wiring is wrong the predicate
//! returns `false` for every height, the guards never fire, the chain does not
//! stop, and nothing logs an error — the snapshot would simply be taken at a
//! height the chain sailed past. This lab exercises the runtime path.
//!
//! `set_node_chain_id` is one-shot per process, so this file deliberately
//! contains a single `#[test]`: a second one could observe an id set by
//! whichever test ran first.

use bloch::core;

#[test]
fn genesis3_runtime_path_halts_at_eighty_thousand() {
    core::set_node_chain_id(core::ChainId::Genesis3Mainnet)
        .expect("chain-id must be settable once");

    // The runtime predicate, not the by-id helper.
    assert_eq!(core::node_chain_id(), core::ChainId::Genesis3Mainnet);
    assert_eq!(
        core::terminal_height(core::node_chain_id()),
        Some(core::GENESIS3_TERMINAL_HEIGHT)
    );

    let t = core::GENESIS3_TERMINAL_HEIGHT;
    assert_eq!(t, 80_000);

    // The boundary. The terminal height is the LAST VALID block — it is the
    // height the snapshot is taken at. Off by one here and the artifact either
    // misses the final block or includes one the chain never agreed on.
    assert!(!core::is_past_terminal_height(0));
    assert!(!core::is_past_terminal_height(t - 1));
    assert!(!core::is_past_terminal_height(t), "a altura terminal e valida");
    assert!(core::is_past_terminal_height(t + 1));
    assert!(core::is_past_terminal_height(u64::MAX));

    // Ships inert. The live chain was at ~40,424 when this was written; a
    // constant at or below the tip would retroactively invalidate mined
    // history the moment the binary is deployed.
    assert!(t > 40_424, "altura terminal nao pode estar no passado da cadeia");
}
