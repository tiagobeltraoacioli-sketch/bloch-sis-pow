//! `bloch-crypto` — the lean crypto / wallet / transaction surface of the
//! Bloch protocol, extracted from the Genesis-3 node so downstream products
//! (mobile wallets, explorers, messengers) can depend on it WITHOUT pulling the
//! full node (rocksdb, libp2p, axum, …).
//!
//! # Which half of this crate is live, and which is history
//!
//! **Read this before quoting anything below as current.** This crate spans
//! both eras and the split runs straight through it:
//!
//! - [`crypto`] is **LIVE**. The hybrid ML-DSA-65 ‖ Falcon-1024 suite here is
//!   what every Genesis-4 consensus signature is produced and verified with:
//!   `bloch-pos-node` calls `crypto::{sign, verify}` on every block proposal,
//!   every attestation and every weak-subjectivity envelope. [`address`],
//!   [`hd_wallet`] and [`util`] are current with it.
//! - [`wallet`] is **split**: its key/identity half (generate, from_seed,
//!   encrypted keyfiles, address derivation) is current, but its transaction
//!   half (`Wallet::build_tx` / `Wallet::sign_tx`) emits the **Genesis-3**
//!   `core::Transaction`, which a Genesis-4 node does not accept. Genesis-4
//!   transactions are `bloch_pos_committee::transition::PosTransaction`. See
//!   that module's own doc.
//! - [`core`] is **HISTORICAL — Genesis-3.** It describes the proof-of-work
//!   chain that stopped permanently at height 39,918 on 2026-08-13: SHA-256d
//!   proof of work, ASERT difficulty retargeting, GhostDAG tip selection,
//!   merged mining ([`core::auxpow`]) and the 21 B tokenomics V2
//!   ([`core::tokenomics_v2`]). **None of it runs.** The live chain is
//!   **Genesis-4, proof of stake** — 30 s slots, 32-slot epochs, Casper-style
//!   finality by epoch, consensus in `crates/bloch-pos-committee`. `core` is
//!   kept buildable and readable because Genesis-4's opening ledger is derived
//!   from the chain it describes; an auditor tracing the carryover needs it.
//!   Read every present-tense sentence in `core` as describing Genesis-3.
//!
//! Genesis-4 does **not** depend on `core`: `bloch-pos-node` imports only
//! `bloch_crypto::crypto`.
//!
//! # The security caveat, current
//!
//! `core`'s disclaimers talk about hashrate and 51% attacks. Those were the
//! Genesis-3 risks and they are retired with that chain. The live risk is
//! **concentration**: all 64 Genesis-4 validators are operated by one entity,
//! 93.94% of the carryover sits at a single address, and 56.05 B of the
//! 57.15 B BLOCH issued at genesis is held by the founder and the Foundation.
//! One operator can halt the chain and one holder can outvote every other.
//!
//! # Provenance
//!
//! This crate is a pure code-move of the Genesis-3 node's non-`node`-feature
//! island: `types, crypto, core, address, wallet, hd_wallet, util`. That node
//! (now `legacy/genesis3-node`) re-exports these modules so every
//! `crate::core::…` / `crate::crypto::…` path in it keeps resolving unchanged.

pub mod types;
pub mod crypto;
pub mod core;
pub mod address;
pub mod wallet;
pub mod hd_wallet;
pub mod util;
