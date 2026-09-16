//! Native outer transport is bounded and canonical in every feature build.
use bloch_pos_committee::transition::{
    NativeTransferPayload, PosTransaction, TxDecodeError,
    MAX_NATIVE_TRANSFER_PAYLOAD_BYTES, NATIVE_TRANSFER_TAG,
};

#[test]
fn native_outer_codec_is_injective_and_rejects_every_truncation() {
    let tx = PosTransaction::NativeTransfer(NativeTransferPayload::new(vec![1, 2, 3]).unwrap());
    let bytes = tx.canonical_bytes();
    assert_eq!(bytes, [NATIVE_TRANSFER_TAG, 3, 0, 0, 0, 1, 2, 3]);
    assert_eq!(PosTransaction::from_canonical_bytes(&bytes), Ok(tx));
    for length in 0..bytes.len() {
        assert!(PosTransaction::from_canonical_bytes(&bytes[..length]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(PosTransaction::from_canonical_bytes(&trailing), Err(TxDecodeError::TrailingBytes));
}

#[test]
fn native_payload_bound_precedes_allocation_and_infallible_encoding() {
    assert_eq!(NativeTransferPayload::new(Vec::new()), Err(TxDecodeError::InvalidNativePayload));
    assert_eq!(NativeTransferPayload::new(vec![0; MAX_NATIVE_TRANSFER_PAYLOAD_BYTES + 1]),
               Err(TxDecodeError::InvalidNativePayload));
    let mut oversized = vec![NATIVE_TRANSFER_TAG];
    oversized.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(PosTransaction::from_canonical_bytes(&oversized), Err(TxDecodeError::InvalidNativePayload));
    let tx = PosTransaction::NativeTransfer(
        NativeTransferPayload::new(vec![0; MAX_NATIVE_TRANSFER_PAYLOAD_BYTES]).unwrap());
    let bytes = tx.canonical_bytes();
    assert_eq!(bytes.len(), bloch_pos_committee::fee_market::MAX_BLOCK_TX_BYTES as usize);
    assert_eq!(PosTransaction::from_canonical_bytes(&bytes), Ok(tx));
}
