// SPDX-License-Identifier: AGPL-3.0-or-later

//! Release-baked weak-subjectivity checkpoint (cargo feature
//! `ws-release-anchor`; see `ws_boot::compiled_release_anchor`).
//!
//! The constant is the hex of the 154 canonical checkpoint bytes that
//! `bloch-pos ws-checkpoint --release-anchor` writes (`<prefix>.bin`), with
//! the reserved signer-set id `u32::MAX - 1`. Empty means "this release bakes
//! no checkpoint". The file is a `.rs` file on purpose: it is inside the
//! binary's source digest (build_source_digest.rs), so the reported
//! source-digest binds the anchor a release bakes.
//!
//! Re-baking at a release freeze: docs/WS-RELEASE-ANCHOR.md.

/// Hex of the canonical checkpoint bytes, or empty.
pub const RELEASE_ANCHOR_HEX: &str = "";
