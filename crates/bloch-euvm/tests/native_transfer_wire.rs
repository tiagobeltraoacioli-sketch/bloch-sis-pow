//! Transport-only tests; dummy key/signature bytes never imply authorization.
use bloch_euvm::ustav::transfer_wire::{self as wire, Envelope, Error};
use bloch_euvm::ustav::{
    OutPoint, Output, Transaction, Witnesses, MAX_INPUTS, MAX_SIGNATURE_BYTES,
};
use bloch_euvm::Val;
fn fixture() -> Envelope {
    Envelope {
        domain: [1; 32],
        transaction: Transaction {
            asset: [2; 32],
            inputs: vec![OutPoint {
                transaction: [3; 32],
                index: 0,
            }],
            outputs: vec![Output {
                owner: vec![4; 32],
                amount: 50,
            }],
            delta: 0,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
        witnesses: Witnesses {
            owners: vec![vec![5; 32]],
            modules: vec![vec![Val::Bytes(vec![6; 32])]],
            ..Witnesses::default()
        },
    }
}
#[test]
fn canonical_roundtrip_and_every_truncated_prefix() {
    let e = fixture();
    let bytes = wire::encode(&e).unwrap();
    assert_eq!(&bytes[..11], b"USTVTRAN\x01\x00\x01");
    assert_eq!(wire::decode(&bytes).unwrap(), e);
    assert_eq!(wire::encode(&wire::decode(&bytes).unwrap()).unwrap(), bytes);
    for end in 0..bytes.len() {
        assert!(wire::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
}
#[test]
fn headers_versions_operations_trailing_and_size_fail_closed() {
    let bytes = wire::encode(&fixture()).unwrap();
    for (offset, error) in [
        (0, Error::InvalidHeader),
        (8, Error::InvalidVersion),
        (10, Error::InvalidOperation),
    ] {
        let mut bad = bytes.clone();
        bad[offset] ^= 0xff;
        assert_eq!(wire::decode(&bad), Err(error));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(wire::decode(&trailing), Err(Error::TrailingBytes));
    assert_eq!(
        wire::decode(&vec![0; wire::MAX_ENCODED_BYTES + 1]),
        Err(Error::TooLarge)
    );
    // Input count follows fixed header+domain+asset. Reject before allocating.
    let mut oversized = bytes;
    oversized[75..79].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(wire::decode(&oversized).is_err());
}
#[test]
fn mint_burn_nonzero_nonce_and_empty_transfer_rejected() {
    for delta in [-1, 1, i128::MAX, i128::MIN] {
        let mut e = fixture();
        e.transaction.delta = delta;
        assert_eq!(wire::encode(&e), Err(Error::InvalidShape));
        // The fixture's delta follows header, input, output count/key/amount.
        let mut encoded = wire::encode(&fixture()).unwrap();
        encoded[163..179].copy_from_slice(&delta.to_le_bytes());
        assert!(wire::decode(&encoded).is_err());
    }
    let mut e = fixture();
    e.transaction.mint_nonce = 1;
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.transaction.inputs.clear();
    e.witnesses.owners.clear();
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.transaction.outputs.clear();
    assert!(wire::encode(&e).is_err());
}
#[test]
fn sorted_inputs_witness_counts_and_blob_limits_enforced() {
    let mut e = fixture();
    e.transaction.inputs.push(e.transaction.inputs[0]);
    e.witnesses.owners.push(vec![1]);
    assert!(wire::encode(&e).is_err());
    e.transaction.inputs[0].index = 2;
    e.transaction.inputs[1].index = 1;
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.witnesses.owners.clear();
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.witnesses.owners[0] = vec![1; MAX_SIGNATURE_BYTES + 1];
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.transaction.outputs[0].owner = vec![1; bloch_euvm::kirpich::limits::MAX_KEY_BYTES + 1];
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.transaction.inputs = vec![e.transaction.inputs[0]; MAX_INPUTS + 1];
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.transaction.outputs[0].amount = 0;
    assert!(wire::encode(&e).is_err());
}

#[test]
fn eligibility_and_module_witnesses_are_canonical_and_bounded() {
    use bloch_euvm::state::{Proof, TREE_DEPTH};
    let mut e = fixture();
    e.witnesses.eligibility = vec![
        Proof {
            key: vec![1; 32],
            value: Some(vec![0; 8]),
            siblings: vec![[0; 32]; TREE_DEPTH],
        },
        Proof {
            key: vec![2; 32],
            value: Some(vec![0; 8]),
            siblings: vec![[0; 32]; TREE_DEPTH],
        },
    ];
    let encoded = wire::encode(&e).unwrap();
    assert_eq!(wire::decode(&encoded).unwrap(), e);
    e.witnesses.eligibility.reverse();
    assert!(wire::encode(&e).is_err());
    e.witnesses.eligibility.reverse();
    e.witnesses.eligibility[1].key = e.witnesses.eligibility[0].key.clone();
    assert!(wire::encode(&e).is_err());
    e.witnesses.eligibility.pop();
    e.witnesses.eligibility[0].value = None;
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.witnesses.modules[0] = vec![Val::Int(1)];
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.witnesses.modules[0] = vec![Val::Bytes(vec![]); 254];
    assert!(wire::encode(&e).is_err());
    let mut e = fixture();
    e.witnesses.modules = vec![vec![]; bloch_euvm::kirpich::limits::MAX_CHARTER_MODULES + 1];
    assert!(wire::encode(&e).is_err());
}
