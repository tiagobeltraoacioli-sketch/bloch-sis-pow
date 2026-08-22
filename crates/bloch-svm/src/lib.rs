// SPDX-License-Identifier: AGPL-3.0-or-later

//! # bloch-svm — Front 2: account model + deterministic parallel scheduler
//!
//! The implementation of `docs/specs/BLOCH-SVM-ACCOUNTS-SCHEDULER.md`:
//! an **SVM-shaped** (spec §0 — never "SVM-compatible") execution plane
//! consisting of the two things that make the SVM architecturally different
//! from the EVM:
//!
//! 1. an account model where state is partitioned into addressable entries a
//!    transaction must *declare* before touching ([`account`], [`tx`],
//!    [`runtime`]), and
//! 2. a scheduler that exploits those declarations to execute
//!    non-conflicting transactions in parallel with **byte-identical results
//!    to sequential execution in canonical order, on any thread count**
//!    ([`scheduler`]).
//!
//! ## STANDALONE SOFTWARE — NOT CONSENSUS-WIRED
//!
//! A live PoS chain with real validators runs from this repository. This
//! crate is therefore built to be UNREACHABLE from the node's state
//! transition, the same posture as `bloch-euvm`: neither `bloch-pos-node`
//! nor `bloch-pos-committee` depends on it (pinned by
//! [`the guard test`](#the-dependency-guard) below), and every
//! consensus-shaped integration point — `TAG_SVM_ROOT` in state_root.rs,
//! `TxClass::Svm` in fee_market.rs, `SVM_ACTIVATION_EPOCH` in params.rs, a
//! `PosTransaction` variant — is spec-§9 work for the single X1 re-freeze
//! round (BLOCH-L1-EXECUTION-PLAN SR-2) and is deliberately absent here.
//! The §10 overlap with ADR-040 (EVM-at-L1, Track E) is a pending
//! PMO/founder decision; this crate is written to be droppable into the X1
//! round if the answer is "joins" and shelvable if not — no KAT here pins
//! the consensus `state_root`, only the internal `svm_root`.
//!
//! ## Determinism posture (spec §2, D-0)
//!
//! The post-state of a block is a pure function of (parent committed state,
//! ordered block body). Enforced structurally: no clock, no I/O, no float
//! (`#![deny(clippy::float_arithmetic)]`), no `HashMap` anywhere a result is
//! derived from iteration (BTreeMap/BTreeSet only), no unchecked arithmetic
//! (checked/saturating with written arguments; sums in u128; the root
//! workspace's `overflow-checks = true` backstops every profile), no
//! `panic!`/`unwrap` in the execution path (typed errors —
//! [`errors`]), and the schedule is computed before any execution starts.
//! Production dependencies: `sha3`. That is the whole list.
//!
//! ## Module map (spec §12)
//!
//! [`params`] (separators, caps, PROVISIONAL economics) · [`errors`] ·
//! [`address`] (§3.1) · [`account`] (§3.2) · [`tree`] (§4) · [`tx`] (§5) ·
//! [`meter`] (§6.3) · [`runtime`] (§6 — the enforcement boundary and the
//! `ProgramExecutor` seam the sbpf front will plug into) · [`scheduler`]
//! (§7) · [`native`] (the v0 System-program subset; adversarial §8 programs
//! under `cfg(test)`).
//!
//! ## The dependency guard
//!
//! `consensus_crates_do_not_depend_on_bloch_svm` (below) reads the two
//! consensus crates' manifests at compile time and fails if either ever
//! names this crate. The reverse direction — this crate pulling consensus
//! code — exists only as a DEV dependency for the tree.rs cross-KAT, and
//! `cargo tree`/review guards that line.

#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
// `missing_docs` is deliberately NOT enabled: it fires on every field of
// every error payload, and "address: the address" comments would bury the
// comments that carry the actual argument. Module, type, and rule
// documentation is the standard this crate is held to instead — see any
// file for the density expected.

pub mod account;
pub mod address;
pub mod errors;
pub mod meter;
pub mod native;
pub mod params;
pub mod runtime;
pub mod scheduler;
pub mod tree;
pub mod tx;

#[cfg(test)]
pub(crate) mod testkit;

pub use account::Account;
pub use errors::{
    AbortCause, AccessError, BlockError, MeterError, ProgramError, RejectCause, TxStructError,
};
pub use meter::ComputeMeter;
pub use runtime::{
    AccountHandle, AccountMut, AccountView, ExecEnv, ProgramExecutor, SignatureVerifier,
    TxOutcome, TxResult,
};
pub use scheduler::{
    conflict, execute_block_parallel, execute_block_serial, schedule_waves, BlockOutcome,
};
pub use tree::SvmState;
pub use tx::{AccountMeta, DeclKind, Instruction, SvmTransaction, Witness};

#[cfg(test)]
mod guard {
    /// The structural version of "SOFTWARE, NOT CONSENSUS": if either
    /// consensus crate ever grows a dependency on bloch-svm, this test goes
    /// red before any reviewer has to notice. `include_str!` binds the check
    /// to the actual manifests, so it cannot rot into checking a stale copy.
    #[test]
    fn consensus_crates_do_not_depend_on_bloch_svm() {
        let node = include_str!("../../bloch-pos-node/Cargo.toml");
        let committee = include_str!("../../bloch-pos-committee/Cargo.toml");
        assert!(
            !node.contains("bloch-svm"),
            "bloch-pos-node must never depend on bloch-svm (spec §9: consensus \
             integration is X1-round work, and this crate is standalone until then)"
        );
        assert!(
            !committee.contains("bloch-svm"),
            "bloch-pos-committee must never depend on bloch-svm (same rule)"
        );
    }
}
