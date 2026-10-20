// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which consensus rules this binary replays with, stated so an operator can
//! check them **before** a flag day instead of discovering them at one.
//!
//! ## Why this exists
//!
//! The index re-executes every block through `bloch_pos_committee`'s own
//! transition and compares the state root (see `index::Index::try_apply`).
//! That makes it exactly as old as the consensus code it was linked against.
//! At the native L2 activation (epoch 5850) the deployed indexer had been
//! built before the release that armed the L2 gate; from the first block of
//! epoch 5850 every replay ended in "replayed state root mismatch" and the
//! read API never came up. Nothing in the binary said which rules it knew.
//!
//! Every flag day repeats that risk: the indexer must be rebuilt from the
//! node release that arms the gate, and deployed before the gate's epoch. So
//! the binary now reports, at `/status`, `/consensus` and `bloch-indexer
//! gates`, every activation gate compiled into it, plus a digest of that
//! table that a release note can publish.
//!
//! ## Keeping the table complete
//!
//! `tests/consensus_gates.rs` reads `bloch-pos-committee/src/params.rs` and
//! fails if a `pub const *_EPOCH: u64` there (activation, registration or
//! hard-fork gates such as `HF1_OWN_TARGET_VOTES_EPOCH`) is missing here. A hard-fork branch that adds a gate therefore
//! cannot pass the indexer's tests until the gate is listed, which is the
//! moment someone has to read `docs/BLOCH-INDEXER.md` § "Flag days".

use sha3::{Digest, Sha3_256};

/// One consensus activation gate as compiled into this binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gate {
    pub name: &'static str,
    /// `u64::MAX` means inert (never activates in this build).
    pub epoch: u64,
}

impl Gate {
    pub fn armed(&self) -> bool {
        self.epoch != u64::MAX
    }
}

macro_rules! gates {
    ($($name:ident),* $(,)?) => {
        /// Every activation gate of `bloch_pos_committee::params`, in source
        /// order. Add new gates here; the test named above enforces it.
        pub const GATES: &[Gate] = &[
            $(Gate { name: stringify!($name), epoch: bloch_pos_committee::params::$name },)*
        ];
    };
}

gates!(
    ETH_PACED_LEAK_ACTIVATION_EPOCH,
    LEAKED_ROSTER_ACTIVATION_EPOCH,
    TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH,
    BLOCK_BYTES_V2_ACTIVATION_EPOCH,
    ANCESTRY_SEED_ACTIVATION_EPOCH,
    LEAK_RECOVERY_ACTIVATION_EPOCH,
    DEPOSIT_ACTIVATION_EPOCH,
    EXIT_AUTH_ACTIVATION_EPOCH,
    FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH,
    SLASHING_EVIDENCE_ACTIVATION_EPOCH,
    PRE_ACTIVATION_OFFENCE_REFUSAL_EPOCH,
    SLASHING_ECONOMICS_V2_ACTIVATION_EPOCH,
    DUST_RULE_ACTIVATION_EPOCH,
    RANDAO_RECOMMIT_ACTIVATION_EPOCH,
    TX_BYTES_BOUND_ACTIVATION_EPOCH,
    ATTESTATION_DEDUP_ACTIVATION_EPOCH,
    REWARDS_V2_ACTIVATION_EPOCH,
    FORKCHOICE_EQUIVOCATION_HORIZON_ACTIVATION_EPOCH,
    FORKCHOICE_SLOT_TIEBREAK_ACTIVATION_EPOCH,
    STAKING_TX_METERING_ACTIVATION_EPOCH,
    WITHDRAWAL_ACTIVATION_EPOCH,
    SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH,
    VALIDATOR_NETWORK_BINDING_ACTIVATION_EPOCH,
    FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH,
    FUNDED_DELEGATION_ACTIVATION_EPOCH,
    L2_SETTLEMENT_ACTIVATION_EPOCH,
    FUNDED_VALIDATOR_CANCELLATION_ACTIVATION_EPOCH,
    ACTIVATION_QUEUE_V2_ACTIVATION_EPOCH,
    DUTY_ROSTER_RECOVERY_ACTIVATION_EPOCH,
    // Hard forks 1-3 (crates/bloch-pos-committee/src/hard_forks.rs).
    HF1_CLAIM_FINALITY_EPOCH,
    HF1_FROZEN_FINALITY_SET_EPOCH,
    HF1_OWN_TARGET_VOTES_EPOCH,
    HF2_SLASHING_V2_EPOCH,
    NATIVE_SLASHING_ACTIVATION_EPOCH,
    HF2_GROWTH_CAP_EPOCH,
    SIG_CANONICAL_ACTIVATION_EPOCH,
    MLDSA_PIN_ACTIVATION_EPOCH,
    HF3_PQ_MIGRATION_EPOCH,
    LATTICE_EMERGENCY_ACTIVATION_EPOCH,
);

/// Source commit of this build, when the builder exported
/// `BLOCH_INDEXER_GIT_COMMIT` (release builds should:
/// `BLOCH_INDEXER_GIT_COMMIT=$(git rev-parse HEAD) cargo build ...`).
pub fn build_commit() -> &'static str {
    option_env!("BLOCH_INDEXER_GIT_COMMIT").unwrap_or("unknown")
}

/// SHA3-256 over `name=epoch\n` for every gate, in table order. Two binaries
/// with the same digest replay with the same activation schedule. A release
/// note can publish it next to the node's binary hash.
pub fn gate_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    for g in GATES {
        h.update(g.name.as_bytes());
        h.update(b"=");
        h.update(g.epoch.to_string().as_bytes());
        h.update(b"\n");
    }
    h.finalize().into()
}

/// The highest armed gate epoch in this build. A chain past every armed gate
/// this binary knows is where an unknown flag day would bite first.
pub fn highest_armed_epoch() -> Option<u64> {
    GATES.iter().filter(|g| g.armed()).map(|g| g.epoch).max()
}

/// Human-readable table for `bloch-indexer gates`.
pub fn table() -> String {
    let mut out = String::new();
    out.push_str(&format!("build commit   {}\n", build_commit()));
    out.push_str(&format!("gate digest    {}\n", crate::hex32(&gate_digest())));
    for g in GATES {
        let e = if g.armed() { g.epoch.to_string() } else { "inert".to_string() };
        out.push_str(&format!("  {:<52} {e}\n", g.name));
    }
    out
}
