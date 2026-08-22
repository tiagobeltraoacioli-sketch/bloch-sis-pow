// SPDX-License-Identifier: AGPL-3.0-or-later
//! §9.1 codec properties and §9.2's decoder pairs.
//!
//! Every negative below carries a **control half**: the same fixture with the
//! one field changed back, which must pass. A rejection test that would also
//! pass against a decoder returning `Err` unconditionally is not a test.

mod common;

use bloch_l1_evm_auth::{BlochTx, CodecError, TX_TYPE_PQ_BATCH, TX_TYPE_PQ_CALL};
use common::{first_use_tx, repeat_use_tx, Key, BUDGET};

#[test]
fn round_trip_is_exact_in_both_directions() {
    for tx in [
        first_use_tx(&Key::new(1)),
        repeat_use_tx(&Key::new(2)),
        {
            // Contract creation, empty data, zero value: the corners.
            let key = Key::new(3);
            let mut tx = common::base_tx(&key);
            tx.to = None;
            tx.data = Vec::new();
            tx.value = 0;
            tx.max_fee = u128::MAX;
            tx.nonce = u64::MAX;
            common::sign_with(tx, &key, Some(key.enveloped.clone()))
        },
        {
            let key = Key::new(4);
            let mut tx = common::base_tx(&key);
            tx.type_byte = TX_TYPE_PQ_BATCH;
            tx.data = vec![0xAB; 5_000];
            common::sign_with(tx, &key, None)
        },
    ] {
        let bytes = tx.encode().expect("encodes");
        let decoded = BlochTx::decode(&bytes, BUDGET).expect("decodes");
        assert_eq!(decoded, tx, "decode(encode(tx)) == tx");
        assert_eq!(
            decoded.encode().expect("re-encodes"),
            bytes,
            "encode(decode(bytes)) == bytes, byte for byte"
        );
    }
}

#[test]
fn trailing_bytes_are_a_rejection_control_without_them_decodes() {
    let tx = first_use_tx(&Key::new(9));
    let bytes = tx.encode().unwrap();

    // CONTROL: the exact encoding decodes.
    assert!(BlochTx::decode(&bytes, BUDGET).is_ok());

    // NEGATIVE: one byte more. Block 10802 froze the fleet over this.
    let mut extended = bytes.clone();
    extended.push(0x00);
    assert_eq!(
        BlochTx::decode(&extended, BUDGET),
        Err(CodecError::TrailingBytes)
    );
}

#[test]
fn presence_flags_must_be_zero_or_one_control_one_decodes() {
    let key = Key::new(10);
    let mut tx = common::base_tx(&key);
    tx.to = Some([0x22; 20]);
    let tx = common::sign_with(tx, &key, None);
    let bytes = tx.encode().unwrap();

    // The `to_present` flag sits after chain_id/nonce/gas_limit/max_fee:
    // 1 (type) + 8 + 8 + 8 + 16 = 41.
    let flag = 1 + 8 + 8 + 8 + 16;
    assert_eq!(bytes[flag], 1, "fixture points at the to_present flag");

    // CONTROL.
    assert!(BlochTx::decode(&bytes, BUDGET).is_ok());

    // NEGATIVE: `2` is not "true".
    let mut smuggled = bytes.clone();
    smuggled[flag] = 2;
    assert_eq!(
        BlochTx::decode(&smuggled, BUDGET),
        Err(CodecError::BadBool)
    );
}

#[test]
fn pk_presence_flag_must_be_zero_or_one() {
    let tx = repeat_use_tx(&Key::new(11));
    let bytes = tx.encode().unwrap();
    // pk_present is the byte right after the 20-byte sender, which is the
    // last field before it; find it by reconstructing the prefix length.
    let prefix = 1 + 8 + 8 + 8 + 16 + 1 + 20 + 16 + 4 + tx.data.len() + 20;
    assert_eq!(bytes[prefix], 0, "fixture points at the pk_present flag");

    assert!(BlochTx::decode(&bytes, BUDGET).is_ok());

    let mut smuggled = bytes;
    smuggled[prefix] = 7;
    assert_eq!(
        BlochTx::decode(&smuggled, BUDGET),
        Err(CodecError::BadBool)
    );
}

#[test]
fn truncation_at_every_prefix_is_a_rejection_never_a_panic() {
    let tx = first_use_tx(&Key::new(12));
    let bytes = tx.encode().unwrap();
    for cut in 0..bytes.len() {
        // Every proper prefix must fail. Nothing may panic.
        assert!(
            BlochTx::decode(&bytes[..cut], BUDGET).is_err(),
            "prefix of {cut} bytes decoded"
        );
    }
    // CONTROL: the whole thing decodes.
    assert!(BlochTx::decode(&bytes, BUDGET).is_ok());
}

#[test]
fn a_lying_length_prefix_is_a_rejection() {
    let tx = repeat_use_tx(&Key::new(13));
    let bytes = tx.encode().unwrap();
    // data_len sits after type/chain/nonce/gas/fee/to_present/to/value.
    let data_len_at = 1 + 8 + 8 + 8 + 16 + 1 + 20 + 16;
    let mut lying = bytes.clone();
    lying[data_len_at..data_len_at + 4].copy_from_slice(&99_999u32.to_le_bytes());
    assert_eq!(BlochTx::decode(&lying, BUDGET), Err(CodecError::Truncated));

    // CONTROL: the honest prefix decodes.
    assert!(BlochTx::decode(&bytes, BUDGET).is_ok());
}

#[test]
fn unknown_type_byte_is_a_rejection_control_both_known_types_decode() {
    let key = Key::new(14);
    for known in [TX_TYPE_PQ_CALL, TX_TYPE_PQ_BATCH] {
        let mut tx = common::base_tx(&key);
        tx.type_byte = known;
        let tx = common::sign_with(tx, &key, None);
        assert!(
            BlochTx::decode(&tx.encode().unwrap(), BUDGET).is_ok(),
            "known type {known:#04x} must decode"
        );
    }
    let tx = repeat_use_tx(&key);
    let mut bytes = tx.encode().unwrap();
    for unknown in [0x00u8, 0x02, 0x4f, 0x52, 0x7f, 0xff] {
        bytes[0] = unknown;
        assert_eq!(
            BlochTx::decode(&bytes, BUDGET),
            Err(CodecError::UnknownType),
            "type {unknown:#04x} must be rejected"
        );
    }
}

#[test]
fn the_budget_is_the_callers_and_is_enforced() {
    let tx = first_use_tx(&Key::new(15));
    let bytes = tx.encode().unwrap();
    let exact = bytes.len() as u64;

    // CONTROL: budget exactly the size of the object.
    assert!(BlochTx::decode(&bytes, exact).is_ok());

    // NEGATIVE: one byte less of budget.
    assert_eq!(BlochTx::decode(&bytes, exact - 1), Err(CodecError::TooLarge));
}

#[test]
fn arbitrary_bytes_never_panic() {
    // Totality, seeded and deterministic: the fuzz targets live outside the
    // everyday workspace, so the property also runs here on every CI pass.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for i in 0..4_000u32 {
        let len = (next() % 400) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
        // Half the corpus is steered at the real type bytes so the decoder
        // gets past its first branch rather than bouncing off it.
        if i % 2 == 0 && !buf.is_empty() {
            buf[0] = if i % 4 == 0 {
                TX_TYPE_PQ_CALL
            } else {
                TX_TYPE_PQ_BATCH
            };
        }
        let _ = BlochTx::decode(&buf, BUDGET);
        let _ = bloch_l1_evm_auth::batch::decode_batch(&buf, BUDGET);
    }
}
