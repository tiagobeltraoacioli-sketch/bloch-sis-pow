// SPDX-License-Identifier: AGPL-3.0-or-later
//! Checkpoint claims become locally testable as canonical blocks arrive.
use super::*;
use bloch_pos_committee::ws::{WeakSubjectivityCheckpoint, WS_FORMAT_VERSION};

fn checkpoint(node: &Engine, block: &BlockEnvelope) -> WeakSubjectivityCheckpoint {
    WeakSubjectivityCheckpoint {
        version: WS_FORMAT_VERSION, network_id: 1,
        genesis_root: *node.manifest.genesis_id().as_bytes(), epoch: 64,
        block_root: *block.block_id().as_bytes(), state_root: block.header.state_root,
        validator_set_root: [0; 32], issued_at: 1, signer_set_id: 3,
    }
}

#[test]
fn ws_state_claim_is_pending_until_canonical_evidence_arrives() {
    let _clock = validator_lifecycle::clock_at(1);
    let (mut node, _dir) = perf_support::proposing_engine();
    node.propose(1);
    assert_eq!(node.state.slot(), 1);
    let block = node.blocks.get(node.head_id().as_bytes()).unwrap().clone();
    let mut anchor = checkpoint(&node, &block);
    node.ws_anchor = Some(anchor);
    assert!(node.ws_anchor_conflict().is_none());
    anchor.state_root = [0xa7; 32];
    node.ws_anchor = Some(anchor);
    node.canonical.remove(&anchor.block_root);
    assert!(node.ws_anchor_conflict().is_none(), "a known noncanonical block is not canonical evidence");
    node.canonical.insert(anchor.block_root);
    assert!(node.ws_anchor_conflict().unwrap().contains("WS_STATE_CONFLICT"));
    assert!(node.state.finality().finalized.epoch < anchor.epoch);
    let head = node.head_id();
    node.ws_anchor_hard = false;
    node.enforce_ws_anchor();
    assert!(node.ws_conflict_reported);
    assert_eq!(node.head_id(), head, "own-finality policy never reorganizes from a publication");
}

#[test]
fn ws_state_is_rechecked_on_canonical_apply_without_a_finality_advance() {
    let _clock = validator_lifecycle::clock_at(1);
    let (mut node, _dir) = perf_support::proposing_engine();
    let parent = node.state.arc();
    node.propose(1);
    let block = node.blocks.get(node.head_id().as_bytes()).unwrap().clone();
    let mut anchor = checkpoint(&node, &block);
    anchor.state_root = [0xa7; 32];
    // Re-run the real validated transition from its saved parent. The block
    // remains known but noncanonical until apply_canonical adopts it again.
    node.state.set((*parent).clone());
    node.chain.pop();
    node.canonical.remove(&anchor.block_root);
    node.ws_anchor = Some(anchor);
    node.ws_anchor_hard = false;
    assert!(node.ws_anchor_conflict().is_none());
    assert!(node.apply_canonical(&block));
    assert_eq!(node.state.finality().finalized.epoch, 0);
    assert!(node.ws_conflict_reported, "the apply hook must not wait for finality advancement");
}

#[test]
fn ws_runtime_preserves_reserved_and_published_genesis_conventions() {
    let (mut node, _dir) = perf_support::proposing_engine();
    let genesis = node.manifest.genesis_header();
    let root = *node.manifest.genesis_id().as_bytes();
    node.ws_anchor = Some(bloch_pos_committee::ws::genesis_anchor(1, root,
        node.manifest.genesis_state().state_root(), [0; 32], 1));
    assert!(node.ws_anchor_conflict().is_none());
    let mut published = node.ws_anchor.unwrap();
    published.epoch = 1;
    published.signer_set_id = 3;
    published.state_root = genesis.state_root;
    node.ws_anchor = Some(published);
    assert!(node.ws_anchor_conflict().is_none());
    published.state_root = [0xa7; 32];
    node.ws_anchor = Some(published);
    assert!(node.ws_anchor_conflict().unwrap().contains("WS_STATE_CONFLICT"));
}
