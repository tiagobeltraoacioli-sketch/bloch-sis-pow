// SPDX-License-Identifier: AGPL-3.0-or-later
//! Public manifest and canonical envelope codecs for independent full replay.
pub mod codec;
pub mod genesis;
/// Offline half of `bloch-pos treasury-collect`, shared with the owner's
/// offline signer (`examples/sign-treasury-spend.rs`).
pub mod treasury_spend;

// The shared manifest tests exercise the actual pure runtime identity checks.
// Do not pull the network engine into the public codec library's test target.
#[cfg(test)]
#[path = "engine_identity.rs"]
mod engine;
