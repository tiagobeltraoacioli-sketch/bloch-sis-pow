// SPDX-License-Identifier: AGPL-3.0-or-later

//! # bloch-withdraw — the reference withdrawal client for Bloch Genesis-4
//!
//! A library an exchange copies to send withdrawals on a chain whose
//! semantics defeat every habitual retry loop:
//!
//! - A transfer commits to **exactly one base fee** (conservation is an
//!   equality against `gas × price`); if the fee moves before inclusion the
//!   bytes are permanently invalid, and resubmitting them can never succeed.
//! - A transfer that misses its block is **dropped from the mempool without
//!   notice**.
//! - There are **no transaction ids** at the RPC layer — `gettransaction`
//!   refuses by design. Confirmation is a statement about the eUTXO set
//!   (`gettxout`, `getbalance`, `listunspent`), keyed by `script_hash`.
//! - `finalized` is the crediting line, not head. Depth is not security
//!   under PoS; one boolean is.
//!
//! Because a rebuilt transaction has different bytes and there is no txid,
//! **the transaction cannot be its own idempotency key**. The idempotency key
//! is the caller's withdrawal id, the payment identity is the **pinned input
//! set**, and the machine confirms-then-rebuilds, never the reverse. The
//! full race statement and the argument that closes it are in
//! `DOUBLE-PAYMENT-RACE.md`; the integration guide is `README.md`.
//!
//! ## Shape
//!
//! - [`withdraw::Withdrawer`] — `create` / `tick` / `cancel`, the whole API.
//! - [`store::Store`] — durability the caller owns ([`store::FileStore`] as
//!   the reference; implement the trait over your database).
//! - [`rpc::Node`] — the node boundary ([`rpc::HttpNode`] for a real node;
//!   tests inject a fake chain).
//! - [`build`] — attempt construction: exact conservation via the consensus
//!   crate's own `fee_market`, dust never emitted, size declared honestly.
//! - [`address`] — `bloch1q…` parsing and the two script-hash forms.
//!
//! ## Trust boundary
//!
//! Read from a node you validate yourself. The public RPC pool may answer
//! from nodes on different branches; this crate's guarantees are statements
//! about one honest node's committed state.

pub mod address;
pub mod build;
pub mod json;
pub mod rpc;
pub mod store;
pub mod withdraw;

pub use address::KeyMaterial;
pub use rpc::{HttpNode, Node};
pub use store::{FileStore, MemStore, Status, Store};
pub use withdraw::{Config, TickOutcome, WithdrawError, Withdrawer};

/// 32 bytes from 64 hex chars (an optional `0x` prefix is tolerated).
pub(crate) fn hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}
