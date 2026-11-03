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
///
/// Release A2 (agent 242, 2026-11-03 02:21 UTC): mainnet epoch 7306, boundary
/// slot 233791, block c2afdb5e523016b6c797ff509ae723d577dab182956fafe15ff4b9aa60fb55c3,
/// state 2905fe3fa97d31fc408f13c57b71e6e165b018cb5485bd22e5d3bb06b3ea44c2,
/// issued_at 1793672494, ws digest 80e8b1d55e73f28d789cb74159fec2b298c0093cfee5572810a19c6587126f20.
/// Minted with `ws-checkpoint --release-anchor` from 80.240.16.185:8080,
/// 199.247.22.8:8080 and 139.180.173.231:8080, which agreed (finalized 7306).
/// SHA-256 of the 154 bytes: 86f23350517773156318016bc06cf659e340b37de57692d2c39493efaee9f343.
/// Fresh installs refuse it from wall epoch 9322 (2026-11-25 11:23 UTC).
pub const RELEASE_ANCHOR_HEX: &str = "0100f47d3e499953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e4158a1c000000000000c2afdb5e523016b6c797ff509ae723d577dab182956fafe15ff4b9aa60fb55c32905fe3fa97d31fc408f13c57b71e6e165b018cb5485bd22e5d3bb06b3ea44c200000000000000000000000000000000000000000000000000000000000000002e45e96a00000000feffffff";
