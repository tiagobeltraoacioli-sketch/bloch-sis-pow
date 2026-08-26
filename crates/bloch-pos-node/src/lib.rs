// SPDX-License-Identifier: AGPL-3.0-or-later

//! # bloch-pos-node — the Genesis-4 node, as a library
//!
//! This crate is the node the live proof-of-stake mainnet runs. The `bloch-pos`
//! binary (`src/main.rs`) is a thin composition root on top of it: argument
//! parsing, key/genesis subcommands, process setup. Everything that decodes
//! bytes from a stranger, answers an RPC, or moves the chain forward lives
//! here.
//!
//! ## Why a library at all
//!
//! It was a binary-only crate until this split. That made the whole node
//! unreachable to anything but `main`, and in particular **unfuzzable**:
//! `cargo-fuzz` links a `[lib]`, and a bin target has none. An external audit
//! recorded the consequence plainly — *the live chain's remote surface has no
//! fuzzing*. Three targets (`g4_codec`, `g4_rpc`, `g4_p2p_sync`) are built
//! against this lib so they exercise the code the fleet actually runs, not a
//! transcription of it. A fuzz harness that reimplements the parser it is
//! testing finds bugs in the harness.
//!
//! The split is a pure refactor: no consensus logic, no constant and no wire
//! format was touched, and no module tree is compiled twice. The modules below
//! are declared **here and only here** — `main.rs` consumes them through
//! `use bloch_pos_node::…` like any other dependent, which is what keeps a
//! `codec::DecodeErr` in the fuzz target and a `codec::DecodeErr` in the node
//! the same type.
//!
//! ## The three remote surfaces
//!
//! Attacker-reachable entry points, and where a fuzzer should aim:
//!
//! - [`codec`] — the consensus wire format. [`codec::decode_envelope`] and
//!   [`codec::decode_attestation`] parse bytes straight off the mesh.
//! - [`rpc`] — the JSON-RPC server, which has **no authentication**.
//!   [`rpc::parse_json`], [`rpc::route`] and [`rpc::handle_body`] are the
//!   request parse/dispatch entry.
//! - [`p2p`] — the libp2p stack. [`p2p::decode_sync_request`] and
//!   [`p2p::decode_sync_response`] are the block-sync request/response codec,
//!   spoken to any peer that dials us.
//!
//! The remaining modules are the node itself: [`engine`] (production,
//! attestation, fork choice, finality), [`net`] (the devnet TCP mesh),
//! [`store`] (the append-only block log), [`genesis`] (manifest and carryover),
//! [`keys`] (the hybrid ML-DSA-65 ‖ Falcon-1024 keystore) and [`ws_boot`] (the
//! weak-subjectivity boot gate). Their own module docs carry the limitations
//! that apply at each site.
//!
//! ## Stability
//!
//! There is no API stability promise here. This is published as a library so
//! the node can be tested and fuzzed, not so third parties can build on it;
//! `pub` means "reachable from a test or a fuzz target", not "supported".

pub mod codec;
pub mod engine;
pub mod genesis;
pub mod keys;
pub mod net;
pub mod p2p;
pub mod rpc;
pub mod store;
pub mod ws_boot;
