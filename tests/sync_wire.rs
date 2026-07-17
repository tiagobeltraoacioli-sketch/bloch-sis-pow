//! P6 — wire tests for the Phase-2 `GetTips` / `Tips` frames added to
//! `NetworkMessage` (P4), plus the shared-const equalities that keep the wire
//! bounds in lock-step with the sync-layer caps.
//!
//! Every `Tips`/`GetTips` frame is untrusted peer input: it must round-trip
//! through `decode_wire_message`, and over-length `tips`/`locator` vectors must
//! be rejected as protocol violations (bounded pre-allocation discipline, same
//! as the existing C1 decode path).

use bloch::network::{
    decode_wire_message, NetworkMessage, SyncEntry, WireDecodeError, MAX_WIRE_LOCATOR,
    MAX_WIRE_TIPS,
};
use bloch::sync::locator::MAX_LOCATOR_LEN;
use bloch::sync::MAX_ADVERTISED_TIPS;

/// Encode a message exactly as the network event loop does (see
/// `network::run` — `bincode::serde::encode_to_vec(&msg, standard())`).
fn encode(msg: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(msg, bincode::config::standard()).expect("encode NetworkMessage")
}

fn entry(tag: u8) -> SyncEntry {
    let mut hash = [0u8; 32];
    hash[0] = tag;
    SyncEntry {
        hash,
        blue_score: tag as u64,
        height: tag as u64,
    }
}

fn hash(tag: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = tag;
    h
}

// ── const equalities (compile-time + runtime backstop) ────────────────────────

// If P1/P2/P4 ever drift these apart, this fails to compile.
const _: () = assert!(MAX_WIRE_TIPS == MAX_ADVERTISED_TIPS);
const _: () = assert!(MAX_WIRE_LOCATOR == MAX_LOCATOR_LEN);

#[test]
fn wire_caps_match_sync_caps() {
    assert_eq!(MAX_WIRE_TIPS, MAX_ADVERTISED_TIPS);
    assert_eq!(MAX_WIRE_LOCATOR, MAX_LOCATOR_LEN);
}

// ── round-trip ────────────────────────────────────────────────────────────────

#[test]
fn get_tips_round_trips() {
    let bytes = encode(&NetworkMessage::GetTips);
    match decode_wire_message(&bytes).expect("decode GetTips") {
        NetworkMessage::GetTips => {}
        other => panic!("expected GetTips, got {other:?}"),
    }
}

#[test]
fn tips_round_trips_preserving_payload() {
    let tips = vec![entry(1), entry(2), entry(3)];
    let locator = vec![hash(9), hash(5), hash(1)];
    let bytes = encode(&NetworkMessage::Tips {
        tips: tips.clone(),
        locator: locator.clone(),
    });
    match decode_wire_message(&bytes).expect("decode Tips") {
        NetworkMessage::Tips {
            tips: got_tips,
            locator: got_locator,
        } => {
            assert_eq!(got_tips.len(), tips.len());
            for (a, b) in got_tips.iter().zip(&tips) {
                assert_eq!(a.hash, b.hash);
                assert_eq!(a.blue_score, b.blue_score);
                assert_eq!(a.height, b.height);
            }
            assert_eq!(got_locator, locator);
        }
        other => panic!("expected Tips, got {other:?}"),
    }
}

#[test]
fn empty_tips_frame_round_trips() {
    let bytes = encode(&NetworkMessage::Tips {
        tips: vec![],
        locator: vec![],
    });
    match decode_wire_message(&bytes).expect("decode empty Tips") {
        NetworkMessage::Tips { tips, locator } => {
            assert!(tips.is_empty());
            assert!(locator.is_empty());
        }
        other => panic!("expected Tips, got {other:?}"),
    }
}

// ── bounds enforcement (untrusted input) ──────────────────────────────────────

#[test]
fn tips_over_max_wire_tips_is_a_protocol_violation() {
    let tips: Vec<SyncEntry> = (0..(MAX_WIRE_TIPS + 1)).map(|i| entry(i as u8)).collect();
    let bytes = encode(&NetworkMessage::Tips {
        tips,
        locator: vec![],
    });
    let err = decode_wire_message(&bytes).expect_err("over-length tips must be rejected");
    assert!(matches!(err, WireDecodeError::Bounds(_)));
    assert!(err.is_protocol_violation());
}

#[test]
fn tips_locator_over_max_wire_locator_is_a_protocol_violation() {
    let locator: Vec<[u8; 32]> = (0..(MAX_WIRE_LOCATOR + 1)).map(|i| hash(i as u8)).collect();
    let bytes = encode(&NetworkMessage::Tips {
        tips: vec![],
        locator,
    });
    let err = decode_wire_message(&bytes).expect_err("over-length locator must be rejected");
    assert!(matches!(err, WireDecodeError::Bounds(_)));
    assert!(err.is_protocol_violation());
}

#[test]
fn tips_at_exactly_the_cap_is_accepted() {
    let tips: Vec<SyncEntry> = (0..MAX_WIRE_TIPS).map(|i| entry(i as u8)).collect();
    let locator: Vec<[u8; 32]> = (0..MAX_WIRE_LOCATOR).map(|i| hash(i as u8)).collect();
    let bytes = encode(&NetworkMessage::Tips { tips, locator });
    let decoded = decode_wire_message(&bytes).expect("frame at the cap must decode");
    match decoded {
        NetworkMessage::Tips { tips, locator } => {
            assert_eq!(tips.len(), MAX_WIRE_TIPS);
            assert_eq!(locator.len(), MAX_WIRE_LOCATOR);
        }
        other => panic!("expected Tips, got {other:?}"),
    }
}
