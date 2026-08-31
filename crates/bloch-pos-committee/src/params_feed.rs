// SPDX-License-Identifier: AGPL-3.0-or-later

//! The consensus-parameter change schedule, as data — the integrator feed.
//!
//! # Why this exists
//!
//! On 2026-08-21/22 an exchange discovered **on their own** that the block
//! payload cap had doubled to 524,288 bytes at epoch 800
//! ([`crate::fee_market::MAX_BLOCK_TX_BYTES_V2`]). Their framing is the right
//! one: conservation is an equality, so a stale fee or size assumption is a
//! hard rejection, not a slow confirm. A silent consensus-parameter change is
//! a production outage for an integrator.
//!
//! This module turns every epoch-gated consensus change in this crate into a
//! machine-readable schedule that a node can serve over RPC
//! (`getconsensusschedule` in `bloch-pos-node`), so an integrator polls a
//! node instead of reading our commits.
//!
//! # Why it cannot drift from the code
//!
//! Two mechanisms, and both are needed:
//!
//! 1. **The values ARE the constants.** Every `activation_epoch`, `before`
//!    and `after` in [`SCHEDULE`] is the consensus constant itself
//!    (`crate::params::…`, `crate::fee_market::…`), not a copy. If the
//!    founder arms a gate or a value moves, the feed moves in the same
//!    commit, by construction. A hand-maintained changelog is exactly the
//!    failure this replaces.
//!
//! 2. **A tripwire against omission.** Construction cannot catch a NEW gate
//!    that never gets a `SCHEDULE` entry, so
//!    `tests::every_activation_gate_is_in_the_feed` scans this crate's
//!    sources for `pub const *_ACTIVATION_EPOCH` / `*_ACTIVATION_HEIGHT`
//!    declarations and for `_V<n>`-suffixed versioned constants, and fails
//!    the suite if any of them is absent from the feed. Adding a flag day
//!    without announcing it becomes a red build, which is the point.
//!
//! # What belongs here
//!
//! Everything gated on an epoch or height — active, armed-for-the-future, or
//! shipped inert (`u64::MAX`). Inert gates are published too, deliberately:
//! an integrator seeing `"status": "inert"` learns the shape of the next
//! change before it is armed, and arming then changes one number in a feed
//! they already parse. History stays forever — an integrator joining today
//! needs the past activations to understand the chain they are replaying.

/// One parameter affected by a gated change.
///
/// `before`/`after` are `None` when the change is a rule or wire-format
/// change with no single numeric value (the note then carries the meaning).
/// Numeric values are `u128` so any consensus constant in the tree fits.
#[derive(Clone, Copy, Debug)]
pub struct ParamDelta {
    /// The Rust constant (or rule) the delta is about, by its exact name —
    /// greppable in this crate.
    pub name: &'static str,
    /// Unit of `before`/`after`, or what the rule governs.
    pub unit: &'static str,
    /// Value in force BELOW the activation epoch. `None` = not numeric or
    /// the thing did not exist before the gate.
    pub before: Option<u128>,
    /// Value in force AT and ABOVE the activation epoch.
    pub after: Option<u128>,
    /// One sentence an integrator can act on.
    pub note: &'static str,
}

/// One epoch-gated consensus change: the gate constant, when it binds, and
/// every parameter it moves.
#[derive(Clone, Copy, Debug)]
pub struct GatedChange {
    /// The gate constant's exact name in `crate::params`.
    pub gate: &'static str,
    /// Where the gate constant is declared, workspace-relative.
    pub defined_in: &'static str,
    /// The gate constant itself. `u64::MAX` means shipped inert — the code
    /// is in every binary and none of it binds until this is lowered by a
    /// coordinated flag day.
    pub activation_epoch: u64,
    /// One sentence: what changes at the boundary.
    pub summary: &'static str,
    /// The parameters this gate moves.
    pub deltas: &'static [ParamDelta],
}

/// The sentinel meaning "shipped inert, not yet armed".
pub const INERT: u64 = u64::MAX;

/// Every epoch-gated consensus change in this crate, past and future, in
/// activation order (inert gates last).
///
/// **Do not copy values into this table.** Reference the constant. The
/// tripwire test below enforces presence, but only referencing enforces
/// correctness of the values themselves.
pub const SCHEDULE: &[GatedChange] = &[
    GatedChange {
        gate: "TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH",
        defined_in: "crates/bloch-pos-committee/src/params.rs",
        activation_epoch: crate::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
        summary: "The deduplicated transfer format TransferV2 (wire tag 0x06) becomes \
                  acceptable in blocks. The V1 format (tag 0x01) stays valid forever; \
                  this gate only adds an encoding. V2 carries one (pubkey, signature) \
                  witness per OWNER plus 40-byte inputs, instead of one full 8,560-byte \
                  witness per INPUT.",
        deltas: &[ParamDelta {
            name: "PosTransaction::TransferV2",
            unit: "wire format (tx tag 0x06)",
            before: None,
            after: None,
            note: "Below the gate every node rejects tag 0x06 (old binaries as a decode \
                   error, new ones as FormatNotActive); from the gate it is a valid \
                   transaction encoding. Gate is read from committed state, in \
                   transition.rs (apply path).",
        }],
    },
    GatedChange {
        gate: "BLOCK_BYTES_V2_ACTIVATION_EPOCH",
        defined_in: "crates/bloch-pos-committee/src/params.rs",
        activation_epoch: crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH,
        summary: "The block payload cap doubles to 512 KiB and the EIP-1559 byte target \
                  moves with it — one switch, never two, so the fee controller keeps \
                  pricing utilisation against the cap actually in force. A stale cap or \
                  target assumption in a client is a hard rejection.",
        deltas: &[
            ParamDelta {
                name: "MAX_BLOCK_TX_BYTES",
                unit: "bytes per block payload",
                before: Some(crate::fee_market::MAX_BLOCK_TX_BYTES as u128),
                after: Some(crate::fee_market::MAX_BLOCK_TX_BYTES_V2 as u128),
                note: "Hard cap on total transaction bytes in a block; a block over it \
                       is invalid regardless of gas. Ask through \
                       fee_market::max_block_tx_bytes(epoch), never the constant.",
            },
            ParamDelta {
                name: "BLOCK_TX_BYTES_TARGET",
                unit: "bytes per block payload",
                before: Some(crate::fee_market::BLOCK_TX_BYTES_TARGET as u128),
                after: Some(crate::fee_market::BLOCK_TX_BYTES_TARGET_V2 as u128),
                note: "EIP-1559 byte target (always half the cap); feeds next_base_fee. \
                       Ask through fee_market::block_tx_bytes_target(epoch).",
            },
        ],
    },
    GatedChange {
        gate: "LEAKED_ROSTER_ACTIVATION_EPOCH",
        defined_in: "crates/bloch-pos-committee/src/params.rs",
        activation_epoch: crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH,
        summary: "The inactivity leak starts reaching the DUTY ROSTER, not only the \
                  quorum denominator: leaked stake stops weighing in the proposer draw \
                  and in committee quorum weights. Membership (the partition) is \
                  unchanged; weights and the proposer schedule are not. Affects who \
                  produces blocks, not what a valid transaction is.",
        deltas: &[ParamDelta {
            name: "consensus_roster_at",
            unit: "consensus rule (roster weighting)",
            before: None,
            after: None,
            note: "Below the gate the roster ignores the leak; from the gate \
                   with_leak_applied subtracts each validator's leak from its \
                   effective stake (transition.rs). Armed by the runbook in \
                   docs/LEAKED-ROSTER-FLAG-DAY.md; the armed value is pinned by \
                   leaked_roster_armed_epoch_matches_the_runbook.",
        }],
    },
    GatedChange {
        gate: "ANCESTRY_SEED_ACTIVATION_EPOCH",
        defined_in: "crates/bloch-pos-committee/src/params.rs",
        activation_epoch: crate::params::ANCESTRY_SEED_ACTIVATION_EPOCH,
        summary: "SHIPPED INERT. When armed: the RANDAO seed for epoch E moves from the \
                  mix at the close of E-1 to the close of \
                  E-1-MIN_SEED_LOOKAHEAD_EPOCHS, closing the F6 proposer-grinding \
                  window. Changes committee partitions and proposer draws from the \
                  activation epoch onward.",
        deltas: &[ParamDelta {
            name: "MIN_SEED_LOOKAHEAD_EPOCHS",
            unit: "epochs of seed look-ahead",
            before: Some(0),
            after: Some(crate::committees::MIN_SEED_LOOKAHEAD_EPOCHS as u128),
            note: "Seed source for epoch E: close of E-1 (look-ahead 0) below the gate; \
                   close of E-1-lookahead at and above it (transition.rs, \
                   seed_for_epoch).",
        }],
    },
    GatedChange {
        gate: "LEAK_RECOVERY_ACTIVATION_EPOCH",
        defined_in: "crates/bloch-pos-committee/src/params.rs",
        activation_epoch: crate::params::LEAK_RECOVERY_ACTIVATION_EPOCH,
        summary: "SHIPPED INERT. When armed, two rules bind at once (finality.rs): the \
                  inactivity-leak accumulator starts RECOVERING in healthy epochs, and \
                  the quorum denominator gains a floor of 1/2 of unleaked active stake, \
                  so a small partition can never justify its own branch by waiting for \
                  everyone else to leak away.",
        deltas: &[
            ParamDelta {
                name: "INACTIVITY_LEAK_RECOVERY_QUOTIENT",
                unit: "1/quotient of outstanding leak returned per healthy epoch",
                before: None,
                after: Some(crate::params::INACTIVITY_LEAK_RECOVERY_QUOTIENT as u128),
                note: "No recovery exists below the gate (leak only accrues); from the \
                       gate a healthy epoch returns 1/16 of the outstanding leak.",
            },
            ParamDelta {
                name: "MIN_QUORUM_DENOMINATOR_NUM",
                unit: "numerator of the quorum-denominator floor fraction",
                before: None,
                after: Some(crate::params::MIN_QUORUM_DENOMINATOR_NUM),
                note: "No floor exists below the gate.",
            },
            ParamDelta {
                name: "MIN_QUORUM_DENOMINATOR_DEN",
                unit: "denominator of the quorum-denominator floor fraction",
                before: None,
                after: Some(crate::params::MIN_QUORUM_DENOMINATOR_DEN),
                note: "Together with the numerator: the denominator may never fall \
                       below 1/2 of unleaked active stake.",
            },
        ],
    },
];

/// Versioned (`_V<n>`) constants that are deliberately NOT in any
/// [`SCHEDULE`] entry's deltas, with the reason. The tripwire consults this
/// list; an empty reason is not accepted by the test, so nothing lands here
/// silently.
pub const VERSIONED_CONST_ALLOWLIST: &[(&str, &str)] = &[
    ("MAX_BLOCK_TX_BYTES_V2", "listed via its unversioned name MAX_BLOCK_TX_BYTES"),
    ("BLOCK_TX_BYTES_TARGET_V2", "listed via its unversioned name BLOCK_TX_BYTES_TARGET"),
];

/// Wall-clock instant (unix milliseconds) at which `epoch` begins, from the
/// chain's genesis manifest cadence. `None` for an inert gate.
///
/// Pure so the node's RPC and any offline tool derive the SAME date from the
/// same three numbers — the manifest is the single wall-clock authority; this
/// crate holds no dates.
pub fn activation_unix_ms(
    genesis_time_ms: u64,
    slot_ms: u64,
    slots_per_epoch: u64,
    activation_epoch: u64,
) -> Option<u64> {
    if activation_epoch == INERT {
        return None;
    }
    genesis_time_ms
        .checked_add(activation_epoch.checked_mul(slots_per_epoch)?.checked_mul(slot_ms)?)
}

/// `"active"`, `"scheduled"` or `"inert"` for a gate, judged against the
/// current wall-clock epoch. A gate binding exactly at the current epoch is
/// already `"active"` — the rule applies to this epoch's blocks.
pub fn status_at(activation_epoch: u64, wall_epoch: u64) -> &'static str {
    if activation_epoch == INERT {
        "inert"
    } else if wall_epoch >= activation_epoch {
        "active"
    } else {
        "scheduled"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `.rs` file in this crate's `src/`, read at test runtime so a NEW
    /// file is scanned automatically — an `include_str!` list would rot.
    fn crate_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("read source file");
                    out.push((path.display().to_string(), text));
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        walk(&src, &mut out);
        assert!(out.len() >= 20, "source scan found almost nothing; the walk is broken");
        out
    }

    /// `pub const NAME…` declarations in a source text whose name satisfies
    /// `pred`. Line-based on purpose: every gate in this repo is declared on
    /// one line, and a scanner that parses Rust is a scanner nobody audits.
    fn declared_consts(text: &str, pred: impl Fn(&str) -> bool) -> Vec<String> {
        let mut found = Vec::new();
        for line in text.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix("pub const ") else { continue };
            let Some(name) = rest.split(':').next() else { continue };
            let name = name.trim();
            if !name.is_empty() && pred(name) {
                found.push(name.to_string());
            }
        }
        found
    }

    /// THE TRIPWIRE. A new `*_ACTIVATION_EPOCH` / `*_ACTIVATION_HEIGHT`
    /// constant anywhere in this crate that has no [`SCHEDULE`] entry fails
    /// the suite. This is the test that makes "we changed a consensus
    /// parameter and told nobody" a red build instead of an integrator's
    /// production outage.
    #[test]
    fn every_activation_gate_is_in_the_feed() {
        let in_feed: Vec<&str> = SCHEDULE.iter().map(|c| c.gate).collect();
        let mut declared = Vec::new();
        for (path, text) in crate_sources() {
            for name in declared_consts(&text, |n| {
                n.ends_with("_ACTIVATION_EPOCH") || n.ends_with("_ACTIVATION_HEIGHT")
            }) {
                assert!(
                    in_feed.contains(&name.as_str()),
                    "{name} (declared in {path}) is an activation gate with NO entry in \
                     params_feed::SCHEDULE. A consensus flag day that integrators cannot \
                     see is a production outage for them — add the SCHEDULE entry (and its \
                     deltas) in the SAME commit that adds the gate.",
                );
                declared.push(name);
            }
        }
        // The reverse direction: a feed entry whose gate constant no longer
        // exists is a stale announcement — renames must reach the feed too.
        for change in SCHEDULE {
            assert!(
                declared.iter().any(|d| d == change.gate),
                "feed entry `{}` names a gate constant that is no longer declared \
                 anywhere in this crate; the feed is announcing a gate that does not \
                 exist",
                change.gate
            );
        }
    }

    /// A `_V<n>`-suffixed constant (the versioned-parameter idiom:
    /// `MAX_BLOCK_TX_BYTES_V2`) must appear in some entry's deltas or carry a
    /// reasoned allowlist line. Catches the NEXT `_V3` cap being added
    /// without a feed entry even if its gate reuses an existing constant.
    #[test]
    fn every_versioned_constant_is_announced_or_allowlisted() {
        fn is_versioned(name: &str) -> bool {
            let Some(pos) = name.rfind("_V") else { return false };
            let digits = &name[pos + 2..];
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
        let in_deltas: Vec<&str> =
            SCHEDULE.iter().flat_map(|c| c.deltas).map(|d| d.name).collect();
        for (path, text) in crate_sources() {
            for name in declared_consts(&text, is_versioned) {
                let allowed = VERSIONED_CONST_ALLOWLIST
                    .iter()
                    .any(|(n, reason)| *n == name && !reason.trim().is_empty());
                assert!(
                    in_deltas.contains(&name.as_str()) || allowed,
                    "{name} (declared in {path}) looks like a versioned consensus \
                     parameter and is neither in any params_feed::SCHEDULE delta nor in \
                     VERSIONED_CONST_ALLOWLIST with a reason. Announce it or allowlist \
                     it — in the same commit.",
                );
            }
        }
    }

    /// The feed is sorted by activation epoch, inert gates last, and no gate
    /// appears twice. Sorted output means an integrator diffing two polls
    /// sees an ARMED gate as one changed line, not a reshuffle.
    #[test]
    fn the_feed_is_sorted_and_unique() {
        let epochs: Vec<u64> = SCHEDULE.iter().map(|c| c.activation_epoch).collect();
        let mut sorted = epochs.clone();
        sorted.sort_unstable();
        assert_eq!(epochs, sorted, "SCHEDULE must stay in activation order");
        let mut gates: Vec<&str> = SCHEDULE.iter().map(|c| c.gate).collect();
        gates.sort_unstable();
        gates.dedup();
        assert_eq!(gates.len(), SCHEDULE.len(), "duplicate gate entry in SCHEDULE");
    }

    /// Wall-clock derivation pinned against the one date the repo records
    /// independently: params.rs documents LEAKED_ROSTER_ACTIVATION_EPOCH
    /// (1400) as 2026-08-29 10:51:19 UTC, and genesis/README.md records
    /// genesis at 2026-08-13 21:31:19 UTC (1,786,656,679,962 ms) with 30 s
    /// slots, 32 to an epoch. If the cadence arithmetic here ever bends, the
    /// feed would publish wrong dates — this pins it to the recorded ones.
    #[test]
    fn wall_clock_derivation_matches_the_recorded_flag_day() {
        const MAINNET_GENESIS_MS: u64 = 1_786_656_679_962;
        let t = activation_unix_ms(
            MAINNET_GENESIS_MS,
            30_000,
            crate::params::SLOTS_PER_EPOCH,
            crate::params::LEAKED_ROSTER_ACTIVATION_EPOCH,
        )
        .expect("armed gate must have a wall-clock instant");
        // 2026-08-29 10:51:19.962 UTC
        assert_eq!(t, 1_788_000_679_962);
        // And the epoch-800 pair (block bytes V2 + TransferV2):
        // 2026-08-22 18:51:19.962 UTC — NOT 21 August; the gate binds at the
        // first slot of epoch 800 by the manifest's cadence.
        let t800 = activation_unix_ms(
            MAINNET_GENESIS_MS,
            30_000,
            crate::params::SLOTS_PER_EPOCH,
            crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH,
        )
        .unwrap();
        assert_eq!(t800, 1_787_424_679_962);
        // Inert gates have no date, and must never invent one.
        assert_eq!(activation_unix_ms(MAINNET_GENESIS_MS, 30_000, 32, INERT), None);
    }

    /// The status projection an integrator will branch on.
    #[test]
    fn status_is_active_from_the_activation_epoch_itself() {
        assert_eq!(status_at(800, 799), "scheduled");
        assert_eq!(status_at(800, 800), "active");
        assert_eq!(status_at(800, 801), "active");
        assert_eq!(status_at(INERT, u64::MAX - 1), "inert");
    }

    /// The V2 deltas in the feed are the fee-market constants — by reference,
    /// so this cannot fail while the table references them; it exists to fail
    /// LOUDLY if someone "simplifies" the table into literals.
    #[test]
    fn the_block_bytes_entry_carries_the_fee_market_values() {
        let entry = SCHEDULE
            .iter()
            .find(|c| c.gate == "BLOCK_BYTES_V2_ACTIVATION_EPOCH")
            .expect("block-bytes entry");
        assert_eq!(entry.activation_epoch, crate::params::BLOCK_BYTES_V2_ACTIVATION_EPOCH);
        let cap = entry.deltas.iter().find(|d| d.name == "MAX_BLOCK_TX_BYTES").unwrap();
        assert_eq!(cap.before, Some(crate::fee_market::MAX_BLOCK_TX_BYTES as u128));
        assert_eq!(cap.after, Some(crate::fee_market::MAX_BLOCK_TX_BYTES_V2 as u128));
        let tgt = entry.deltas.iter().find(|d| d.name == "BLOCK_TX_BYTES_TARGET").unwrap();
        assert_eq!(tgt.before, Some(crate::fee_market::BLOCK_TX_BYTES_TARGET as u128));
        assert_eq!(tgt.after, Some(crate::fee_market::BLOCK_TX_BYTES_TARGET_V2 as u128));
    }
}
