// SPDX-License-Identifier: AGPL-3.0-or-later
//! §6 — the batch payload's encoding rules. Semantics are not tested here
//! because they are not decided here: `msg.sender`, atomicity and per-sub-call
//! metering are consensus surface awaiting the founder's ratification at
//! wiring time.

mod common;

use bloch_l1_evm_auth::batch::{decode_batch, encode_batch};
use bloch_l1_evm_auth::{BatchCall, CodecError};
use common::BUDGET;

fn calls() -> Vec<BatchCall> {
    vec![
        BatchCall {
            to: Some([0x11; 20]),
            value: 1,
            calldata: vec![0xa9, 0x05, 0x9c, 0xbb],
        },
        BatchCall {
            to: None,
            value: 0,
            calldata: vec![0x60; 64],
        },
        BatchCall {
            to: Some([0x33; 20]),
            value: u128::MAX,
            calldata: Vec::new(),
        },
    ]
}

#[test]
fn round_trip_is_exact() {
    let encoded = encode_batch(&calls()).unwrap();
    let decoded = decode_batch(&encoded, BUDGET).unwrap();
    assert_eq!(decoded, calls());
    assert_eq!(encode_batch(&decoded).unwrap(), encoded);
}

#[test]
fn an_empty_batch_is_rejected_control_one_call_decodes() {
    // NEGATIVE: `count = 0`. A batch that authorizes nothing is not a batch,
    // and an accepted zero-count batch is a signature spent on nothing.
    let zero = 0u32.to_le_bytes().to_vec();
    assert_eq!(decode_batch(&zero, BUDGET), Err(CodecError::EmptyBatch));
    assert_eq!(encode_batch(&[]), Err(CodecError::EmptyBatch));

    // CONTROL.
    let one = encode_batch(&calls()[..1]).unwrap();
    assert_eq!(decode_batch(&one, BUDGET).unwrap().len(), 1);
}

#[test]
fn trailing_bytes_after_a_batch_are_a_rejection() {
    let mut encoded = encode_batch(&calls()).unwrap();
    // CONTROL.
    assert!(decode_batch(&encoded, BUDGET).is_ok());
    // NEGATIVE.
    encoded.push(0);
    assert_eq!(
        decode_batch(&encoded, BUDGET),
        Err(CodecError::TrailingBytes)
    );
}

#[test]
fn a_truncated_sub_call_is_a_rejection() {
    let encoded = encode_batch(&calls()).unwrap();
    for cut in 0..encoded.len() {
        assert!(
            decode_batch(&encoded[..cut], BUDGET).is_err(),
            "prefix of {cut} bytes decoded"
        );
    }
    assert!(decode_batch(&encoded, BUDGET).is_ok());
}

#[test]
fn an_overstated_count_is_a_rejection_and_allocates_nothing() {
    // A 4-byte prefix can claim four billion sub-calls. The decoder must fail
    // on the input running out, not on memory running out.
    let mut hostile = u32::MAX.to_le_bytes().to_vec();
    hostile.extend_from_slice(&[0u8; 16]);
    assert_eq!(decode_batch(&hostile, BUDGET), Err(CodecError::Truncated));
}

#[test]
fn a_sub_call_presence_flag_must_be_zero_or_one() {
    let mut encoded = encode_batch(&calls()).unwrap();
    assert!(decode_batch(&encoded, BUDGET).is_ok());
    encoded[4] = 2;
    assert_eq!(decode_batch(&encoded, BUDGET), Err(CodecError::BadBool));
}

#[test]
fn the_budget_bounds_the_payload() {
    let encoded = encode_batch(&calls()).unwrap();
    let exact = encoded.len() as u64;
    assert!(decode_batch(&encoded, exact).is_ok());
    assert_eq!(
        decode_batch(&encoded, exact - 1),
        Err(CodecError::TooLarge)
    );
}
