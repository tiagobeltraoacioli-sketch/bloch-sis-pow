// SPDX-License-Identifier: MIT OR Apache-2.0
//! # bloch-anchoring — reference L2 / anchoring & commitment framework
//!
//! A **standalone, permissively-licensed (MIT OR Apache-2.0) scaffold** for the
//! anchoring pattern of the Bloch roadmap §2.2: an external system (an L2,
//! rollup, sidechain, state-channel hub, finality gadget, or notary) commits a
//! **compact commitment** — a state root, checkpoint hash, or batch digest —
//! into a Bloch transaction, paying in **BLCH**. Bloch's PoW gives that
//! commitment an **ordering + timestamp + anchor**, and nothing else.
//!
//! > **Bloch settles nothing about your system's internal validity.** Execution,
//! > validity rules, data availability, and finality are **yours**. Bloch stays
//! > agnostic underneath (Principle 0). **Bring your own architecture.**
//!
//! ## Status (binding honesty rails)
//!
//! This is a **SCAFFOLD / reference implementation — unaudited and
//! pre-production.** The base chain is **ownerless, neutral, and agnostic**:
//! anyone can build L2s, finality gadgets (FFGs), and RWA systems — **no
//! category is reserved and Postern Labs holds no privilege.** Base
//! mainnet-beta currently runs a **relaxed k=4 PoW regime → work is trivially
//! forgeable and the low-hashrate network is 51%-attackable**; treat everything
//! here as **experimental**. **BLCH is neutral gas — not a security, with no
//! value claim from anyone.** RWA builders own their **own legal and regulatory
//! responsibility**.
//!
//! ## Shape of the crate
//!
//! * [`commitment::Commitment`] — the fixed 32-byte digest you anchor.
//! * [`anchor::Anchor`] / [`anchor::Txid`] / [`anchor::Finality`] /
//!   [`anchor::InclusionReference`] — what Bloch hands back.
//! * [`convention`] — how a commitment is embedded using **only today's
//!   primitives** (P2PKH burn outputs; no data-carrier output exists yet).
//! * [`rpc`] — the [`rpc::RpcTransport`] seam, a typed [`rpc::BlochRpc`], and an
//!   offline [`rpc::MockTransport`].
//! * [`sdk`] — the [`sdk::Anchoring`] trait and [`sdk::AnchorClient`].
//! * [`http`] — a real `ureq` transport behind the `http` feature.
//!
//! See the crate README for the DA boundary and what a future data-carrier GIP
//! would add.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod commitment;
pub mod convention;
pub mod error;
pub mod rpc;
pub mod sdk;
pub mod tx;

#[cfg(feature = "http")]
pub mod http;

// Ergonomic top-level re-exports.
pub use anchor::{Anchor, Finality, InclusionReference, Txid};
pub use commitment::Commitment;
pub use error::{AnchorError, Result};
pub use sdk::{Anchoring, AnchorClient, MockSigner, TxSigner, WaitPolicy};
