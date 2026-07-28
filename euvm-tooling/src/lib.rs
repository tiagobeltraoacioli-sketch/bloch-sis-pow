//! # euvm-tooling — developer tooling for the `bloch-euvm` eUTXO validator VM
//!
//! This crate is the parallel-build home for six dev-tooling components that wrap
//! the public API of the standalone `bloch-euvm` crate. Each component lives in its
//! own module file so six developers can build them in parallel without touching a
//! shared file:
//!
//! - [`asm`]     — an ergonomic assembler/DSL for building `Vec<bloch_euvm::Op>` programs.
//! - [`encode`]  — hex/JSON-ish encoders + decoders for Ops, Vals, programs and hashes.
//! - [`sim`]     — a thin, instrumented runner around `bloch_euvm::run`/`spend` with traces.
//! - [`tx`]      — a fluent `EuTx` builder that composes inputs/outputs/redeemers.
//! - [`examples`]— ready-made validator programs (P2PKH, multisig, hashlock, AMM …).
//! - `DOCS.md`   — the human-facing usage guide (no Rust module; a docs deliverable).
//!
//! The PMO owns `lib.rs` and `Cargo.toml`. Developers fill in ONLY their one module
//! file; the module declarations below are the fixed contract between components.

pub mod asm;
pub mod encode;
pub mod examples;
pub mod sim;
pub mod tx;

/// Crate-wide re-export of the underlying VM so downstream tooling and tests can
/// refer to a single canonical path (`euvm_tooling::euvm::Op`, etc.).
pub use bloch_euvm as euvm;
