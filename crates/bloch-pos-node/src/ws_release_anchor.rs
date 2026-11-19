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
/// KES-bind release candidate (2026-11-19 01:18 UTC): mainnet epoch 8742, boundary
/// slot 279743, block 7f13dd9b095e0574c67703feae3da23f0e55ea3127e6a51e725a5eaaf7e627ff,
/// state 3d7355dd56464a8903ee0d04b4b112aa28fb525980c9c3e78ceca2b71c98aa33,
/// issued_at 1795051114, ws digest 2ef30305353651887ae8a7b81b57d9f2428f13935126294709f8afda2919546c.
/// Minted with `ws-checkpoint --release-anchor` from 80.240.16.185:8080,
/// 199.247.22.8:8080 and 139.180.173.231:8080, which agreed (finalized 8742).
/// SHA-256 of the 154 bytes: 211345ae007638e1ebdb5fa980cb25b690d08d828837527703911e77fb8005b6.
/// Fresh installs refuse it from wall epoch 10758 (2026-12-11 10:19 UTC).
/// It replaces the release A2 anchor of epoch 7306, which fresh installs refuse
/// from wall epoch 9322 (2026-11-25 11:23 UTC).
pub const RELEASE_ANCHOR_HEX: &str = "0100f47d3e499953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e41526220000000000007f13dd9b095e0574c67703feae3da23f0e55ea3127e6a51e725a5eaaf7e627ff3d7355dd56464a8903ee0d04b4b112aa28fb525980c9c3e78ceca2b71c98aa3300000000000000000000000000000000000000000000000000000000000000006a4efe6a00000000feffffff";
