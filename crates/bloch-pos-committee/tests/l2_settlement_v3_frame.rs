// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cross-repository conformance for the native settlement V3 transaction frame.
//!
//! The SAME vector is built independently by bloch-l2-evm
//! (`tests/native_settlement_v3_frame.rs`) from its own codec, against an
//! identical copy of `fixtures/l2-settlement-v3/frame-async.hex`. Here it is
//! rebuilt from THIS crate's tags and V3 offsets and decoded by the canonical
//! transaction decoder. A drift on either side fails one of the two suites.
use bloch_pos_committee::l2_settlement::{
    v3, Transaction, ASYNC_WIRE_TAG, PROOF_BYTES, STATEMENT_V3_BYTES, STATEMENT_V3_TAG, TRANSACTION_V3_BYTES,
    WIRE_TAG,
};
use bloch_pos_committee::transition::PosTransaction;
use sha3::{Digest, Keccak256};

const FIXTURE: &str = include_str!("fixtures/l2-settlement-v3/frame-async.hex");
/// Shared with bloch-l2-evm `FRAME_ASYNC_KECCAK`.
const FRAME_ASYNC_KECCAK: &str = "b4a32832b08b2297693a9f6f1468d59301f13bdedd0af059d6054200147117d4";
const S: usize = 22;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// The golden V3 statement (bloch-l2-evm `settlement_v3_golden_vector`),
/// written through this crate's offsets.
fn golden_statement() -> Vec<u8> {
    let mut s = vec![0u8; STATEMENT_V3_BYTES];
    s[..S].copy_from_slice(STATEMENT_V3_TAG);
    let mut put_hash = |offset: usize, byte: u8| s[S + offset..S + offset + 32].fill(byte);
    for (i, offset) in [0, 32, 64, 96, 128, 160, 192, 224].into_iter().enumerate() {
        put_hash(offset, i as u8 + 1);
    }
    for (offset, byte) in [(272, 0x09), (304, 0x0a), (336, 0x0b), (368, 0x0c), (400, 0x0d), (448, 0x0e),
        (480, 0x0f), (536, 0x10), (v3::DEPOSITS_HASH, 0x11), (v3::TRANSACTIONS_ROOT, 0x12),
        (v3::RECEIPTS_ROOT, 0x13), (v3::WITHDRAWAL_ROOT, 0x14), (v3::DA_COMMITMENT, 0x15)] {
        put_hash(offset, byte);
    }
    let mut put_u64 = |offset: usize, hi: u8| {
        for k in 0..8 {
            s[S + offset + k] = hi + 1 + k as u8;
        }
    };
    for (offset, hi) in [(256, 0x00), (264, 0x10), (432, 0x20), (440, 0x30), (512, 0x40), (520, 0x50),
        (528, 0x60), (v3::USER_TX_COUNT, 0x70), (v3::WITHDRAWAL_COUNT, 0x80)] {
        put_u64(offset, hi);
    }
    s
}

fn golden() -> Transaction {
    Transaction {
        proof_policy: [0xa5; 32],
        statement: golden_statement(),
        proof: std::array::from_fn(|i| (i * 7 + 3) as u8),
    }
}

#[test]
fn v3_async_frame_matches_the_shared_l2_vector() {
    let bytes = golden().encode_async();
    assert_eq!((bytes.len(), TRANSACTION_V3_BYTES, PROOF_BYTES), (1155, 1155, 356));
    assert_eq!(bytes[0], 0x13);
    assert_eq!(bytes[0], ASYNC_WIRE_TAG);
    assert_eq!(bytes, unhex(FIXTURE), "frame differs from the shared fixture");
    assert_eq!(hex(&Keccak256::digest(&bytes)), FRAME_ASYNC_KECCAK);
    // The canonical decoder takes the shared bytes as an async settlement.
    match PosTransaction::from_canonical_bytes(&bytes).unwrap() {
        PosTransaction::L2SettlementAsync(tx) => assert_eq!(*tx, golden()),
        other => panic!("decoded as {other:?}"),
    }
    // The synchronous frame differs only in the first byte.
    let sync = golden().encode();
    assert_eq!(sync[0], WIRE_TAG);
    assert_eq!(sync[0], 0x12);
    assert_eq!(sync[1..], bytes[1..]);
    assert!(matches!(PosTransaction::from_canonical_bytes(&sync).unwrap(), PosTransaction::L2Settlement(_)));
}

#[test]
fn v3_frame_under_historical_tags_is_not_an_l2_settlement() {
    let bytes = golden().encode_async();
    for tag in [0x0e, 0x0f, 0x10] {
        let mut old = bytes.clone();
        old[0] = tag;
        assert!(Transaction::decode(&old).is_none(), "tag {tag:#x}");
        assert!(Transaction::decode_async(&old).is_none(), "tag {tag:#x}");
        // Whatever the canonical decoder does with these bytes, it is never an
        // L2 settlement (0x0E..=0x11 belong to mainnet funded delegation).
        if let Ok(decoded) = PosTransaction::from_canonical_bytes(&old) {
            assert!(
                !matches!(decoded, PosTransaction::L2Settlement(_) | PosTransaction::L2SettlementAsync(_)),
                "tag {tag:#x}"
            );
        }
    }
}
