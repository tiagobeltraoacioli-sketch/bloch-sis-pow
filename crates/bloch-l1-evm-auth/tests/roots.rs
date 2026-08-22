// SPDX-License-Identifier: AGPL-3.0-or-later
//! §9.1: every field is bound, and the domains are separated.

mod common;

use std::collections::BTreeSet;

use bloch_l1_evm_auth::root::{call_message, evm_txid, signing_root};
use bloch_l1_evm_auth::{DS_EVM_CALL, DS_EVM_TX, DS_EVM_TXID, TX_TYPE_PQ_BATCH};
use common::{base_tx, Key, CHAIN_ID};
use sha3::{Digest, Sha3_256};

#[test]
fn signing_root_binds_every_field_pairwise() {
    let key = Key::new(21);
    let base = base_tx(&key);
    let other = Key::new(22);

    let mut variants = vec![("base", base.clone())];
    variants.push(("type_byte", {
        let mut t = base.clone();
        t.type_byte = TX_TYPE_PQ_BATCH;
        t
    }));
    variants.push(("chain_id", {
        let mut t = base.clone();
        t.chain_id += 1;
        t
    }));
    variants.push(("nonce", {
        let mut t = base.clone();
        t.nonce += 1;
        t
    }));
    variants.push(("gas_limit", {
        let mut t = base.clone();
        t.gas_limit += 1;
        t
    }));
    variants.push(("max_fee", {
        let mut t = base.clone();
        t.max_fee += 1;
        t
    }));
    variants.push(("to_some_other", {
        let mut t = base.clone();
        t.to = Some([0x99; 20]);
        t
    }));
    variants.push(("to_none", {
        let mut t = base.clone();
        t.to = None;
        t
    }));
    variants.push(("value", {
        let mut t = base.clone();
        t.value += 1;
        t
    }));
    variants.push(("data_content", {
        let mut t = base.clone();
        t.data = vec![0x00, 0x00, 0x00, 0x00];
        t
    }));
    variants.push(("data_length", {
        let mut t = base.clone();
        t.data.push(0);
        t
    }));
    variants.push(("sender", {
        let mut t = base.clone();
        t.sender = other.address();
        t
    }));

    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (name, tx) in &variants {
        let root = signing_root(tx).expect("encodes");
        assert!(
            seen.insert(root),
            "{name} did not change the signing root — the field is not bound"
        );
    }
    assert_eq!(seen.len(), variants.len(), "all roots pairwise distinct");
}

#[test]
fn the_witness_is_not_in_the_root_so_the_id_cannot_be_rekeyed() {
    // `sender_pk` and `signature` are excluded (§4.1). Two encodings of one
    // authorization therefore share one id — which is what keeps the mempool
    // from holding two entries for one effect.
    let key = Key::new(23);
    let bare = base_tx(&key);
    let root = signing_root(&bare).unwrap();

    let with_pk = common::sign_with(bare.clone(), &key, Some(key.enveloped.clone()));
    let without_pk = common::sign_with(bare.clone(), &key, None);

    assert_eq!(signing_root(&with_pk).unwrap(), root);
    assert_eq!(signing_root(&without_pk).unwrap(), root);
    assert_eq!(
        evm_txid(&signing_root(&with_pk).unwrap()),
        evm_txid(&signing_root(&without_pk).unwrap()),
        "stripping or adding the pubkey must not change the transaction id"
    );

    // And a different signature over the same fields is the same id too.
    let mut resigned = with_pk.clone();
    resigned.signature = Key::new(24).sign(&root);
    assert_eq!(signing_root(&resigned).unwrap(), root);
}

#[test]
fn the_tags_are_fixed_width_and_that_is_what_makes_them_unambiguous() {
    // Worth stating carefully, because these two tags are a near miss:
    // "BLCH4:EVMTX" IS a textual prefix of "BLCH4:EVMTXID". Had the tags been
    // variable-length strings, `DS_EVM_TX ‖ "ID..."` and `DS_EVM_TXID ‖ "..."`
    // would be the same bytes, and a signing root would be reusable as a
    // transaction id preimage. The `params.rs` pattern — **exactly 16 bytes,
    // right-padded with zeros** — is what removes that: at equal width,
    // "prefix of" collapses to "equal to", and the padded forms differ at
    // byte 11 ('\0' against 'I').
    let tags = [DS_EVM_TX, DS_EVM_TXID, DS_EVM_CALL];
    for t in &tags {
        assert_eq!(t.len(), 16, "a variable-width tag reopens the ambiguity");
    }
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "tags {i} and {j} are equal");
                // At fixed width, distinct is exactly "neither prefixes the
                // other", so `tag_a ‖ anything != tag_b ‖ anything`.
                let mut left = a.to_vec();
                left.extend_from_slice(b"payload-one");
                let mut right = b.to_vec();
                right.extend_from_slice(b"payload-two");
                assert_ne!(left[..16], right[..16]);
            }
        }
    }

    // The near miss, demonstrated rather than asserted in prose.
    assert!(
        DS_EVM_TXID.starts_with(b"BLCH4:EVMTX"),
        "fixture assumes the textual overlap it is guarding"
    );
    let mut as_variable_width = b"BLCH4:EVMTX".to_vec();
    as_variable_width.extend_from_slice(b"ID\0\0\0");
    assert_eq!(
        as_variable_width.len(),
        16,
        "the collision only exists without padding"
    );
    assert_ne!(
        as_variable_width.as_slice(),
        DS_EVM_TX.as_slice(),
        "padding is load-bearing"
    );
}

#[test]
fn the_domains_do_not_collide() {
    // No DS_EVM_TX root equals a DS_EVM_TXID, DS_EVM_CALL, DS_DEPOSIT or
    // DS_SPEND digest of the same bytes.
    let key = Key::new(25);
    let tx = base_tx(&key);
    let root = signing_root(&tx).unwrap();

    // Compare the SAME bytes under different tags, so any difference is the
    // domain separation and nothing else.
    let fields = root.to_vec();

    let under = |tag: [u8; 16], bytes: &[u8]| -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(tag);
        h.update(bytes);
        h.finalize().into()
    };

    let ds_deposit: [u8; 16] = *b"BLCH4:DEPOSIT\0\0\0";
    let ds_spend: [u8; 16] = *b"BLCH4:SPEND\0\0\0\0\0";
    let ds_txid: [u8; 16] = *b"BLCH4:TXID\0\0\0\0\0\0";

    for tag in [DS_EVM_TXID, DS_EVM_CALL, ds_deposit, ds_spend, ds_txid] {
        assert_ne!(under(DS_EVM_TX, &fields), under(tag, &fields));
    }

    // The txid is not the root, and the call message is not either.
    assert_ne!(evm_txid(&root), root);
    let mut msg32 = [0u8; 32];
    msg32.copy_from_slice(&root);
    assert_ne!(call_message(CHAIN_ID, &msg32), root);
    assert_ne!(call_message(CHAIN_ID, &msg32), evm_txid(&root));
}

#[test]
fn the_call_message_binds_the_chain_id_and_the_digest() {
    let msg = [0x5a; 32];
    let other = [0x5b; 32];
    assert_ne!(call_message(1, &msg), call_message(2, &msg));
    assert_ne!(call_message(1, &msg), call_message(1, &other));

    // And it is not the bare digest: without the tag, a digest handed to a
    // user by a contract could be some transaction's signing root.
    let bare: [u8; 32] = Sha3_256::digest(msg).into();
    assert_ne!(call_message(1, &msg), msg);
    assert_ne!(call_message(1, &msg), bare);
}
