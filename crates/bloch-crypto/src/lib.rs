//! `bloch-crypto` — the lean crypto / wallet / transaction surface of the
//! Bloch-SIS Protocol, extracted from the `bloch` node so downstream products
//! (mobile wallets, explorers, messengers) can depend on it WITHOUT pulling the
//! full node (rocksdb, libp2p, axum, …).
//!
//! This crate is a pure code-move of the node's non-`node`-feature island:
//! `types, crypto, core, address, wallet, hd_wallet, util`. The node re-exports
//! these modules so every `crate::core::…` / `crate::crypto::…` path in the node
//! keeps resolving unchanged.

pub mod types;
pub mod crypto;
pub mod core;
pub mod address;
pub mod wallet;
pub mod hd_wallet;
pub mod util;
