// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native payloads remain disabled. Their rejection must not publish a valid
//! competing prefix into canonical state, transaction status or persistent log.
use super::*;
use bloch_pos_committee::state_root::EutxoEntry;
use bloch_pos_committee::transition::{NativeTransferPayload, TransferInput, TransferOutput};

fn funded_prefix() -> (
    Engine,
    perf_support::TestDir,
    [u8; 32],
    BlockEnvelope,
    BlockEnvelope,
    PosTransaction,
) {
    let (public, secret) = bloch_crypto::crypto::generate_keypair_from_seed(&[49; 32]).unwrap();
    let opening = EutxoEntry {
        txid: [49; 32],
        vout: 0,
        value: 100_000_000,
        script_hash: Sha3_256::digest(&public).into(),
    };
    let (mut engine, directory) = perf_support::proposing_engine_funded(&[opening.clone()]);
    let genesis = *engine.head_id().as_bytes();
    // Historical V1 encoding is active at epoch zero. Its reserved size covers
    // the real hybrid signature; fees conserve the real opening UTXO exactly.
    let charge = fee_market::charge(
        fee_market::TxClass::Eutxo { inputs: 1 },
        10_000,
        engine.state.next_base_fee(),
        0,
    );
    let mut tx = PosTransaction::Transfer {
        inputs: vec![TransferInput {
            txid: opening.txid,
            vout: 0,
            pubkey: public,
            signature: vec![],
        }],
        outputs: vec![TransferOutput {
            value: opening.value - u64::try_from(charge.base_fee_sat).unwrap(),
            script_hash: [53; 32],
        }],
        tx_bytes: 10_000,
        tip_millisat_per_gas: 0,
    };
    let signature = bloch_crypto::crypto::sign(&secret, &tx.spend_signing_root()).unwrap();
    if let PosTransaction::Transfer { inputs, .. } = &mut tx {
        inputs[0].signature = signature;
    }
    assert!(tx.canonical_bytes().len() <= 10_000);
    engine.mempool.insert(tx.canonical_bytes(), tx.clone());
    engine.propose(1);
    let prefix = engine
        .blocks
        .get(engine.head_id().as_bytes())
        .unwrap()
        .clone();
    assert_eq!(
        body_transactions(&prefix).unwrap(),
        vec![tx.clone()],
        "fixture must execute its funded transaction"
    );
    engine.propose(2);
    let suffix = engine
        .blocks
        .get(engine.head_id().as_bytes())
        .unwrap()
        .clone();
    assert_eq!(suffix.header.slot, 2);
    assert!(engine.do_reorg(genesis, vec![]));
    assert!(!engine.tx_slot_index.contains_key(&tx.txid()));
    (engine, directory, genesis, prefix, suffix, tx)
}

#[test]
fn rejected_native_reorg_suffix_cannot_publish_prefix_state_or_transaction_status() {
    let (mut engine, dir, genesis, prefix, template, tx) = funded_prefix();
    let before = (*engine.state).clone();
    let chain = engine.chain.clone();
    let canonical = engine.canonical.clone();
    let recent = engine.recent_states.clone();
    let index = engine.tx_slot_index.clone();
    let order = engine.tx_slot_index_order.clone();
    let log = std::fs::read(dir.0.join("blocks.log")).unwrap();
    let disk_index = std::fs::read(dir.0.join("blocks.idx")).unwrap();
    let native = PosTransaction::NativeTransfer(NativeTransferPayload::new(vec![1]).unwrap());
    // Exercise both consensus rejection of a well-framed dormant operation and
    // an invalid body codec after the same valid, signed, funded prefix.
    for payload in [native.canonical_bytes(), vec![0x0e, 255, 255, 255, 255]] {
        let mut suffix = template.clone();
        suffix.body.transactions = vec![payload];
        suffix.header.body_root = derive::body_root(&suffix.body.transactions);
        suffix.proposer_sig = engine
            .keys
            .as_ref()
            .unwrap()
            .sign(&suffix.header.proposal_signing_root());
        assert!(!engine.do_reorg(genesis, vec![prefix.clone(), suffix]));
        assert_eq!(*engine.state, before);
        assert_eq!(engine.chain, chain);
        assert_eq!(engine.canonical, canonical);
        assert_eq!(engine.recent_states, recent);
        assert_eq!(
            engine.tx_slot_index, index,
            "a rejected branch must not expose its valid prefix through gettxstatus"
        );
        assert_eq!(
            engine.tx_slot_index_order, order,
            "rejected prefixes must not evict other indexed transactions"
        );
        assert_eq!(std::fs::read(dir.0.join("blocks.log")).unwrap(), log);
        assert_eq!(std::fs::read(dir.0.join("blocks.idx")).unwrap(), disk_index);
    }
    // Control: after rejecting the suffix, the identical valid prefix can win.
    assert!(engine.do_reorg(genesis, vec![prefix.clone()]));
    assert_eq!(engine.tx_slot_index.get(&tx.txid()), Some(&1));
    assert_eq!(engine.tx_status(&tx.txid()), "included");
    assert_eq!(
        *engine.state,
        engine.replay_to(*prefix.block_id().as_bytes())
    );
    // Re-adopting a validated prefix at the same slot must not let stale-tail
    // cleanup erase the winning transaction's just-published observation.
    assert!(engine.do_reorg(genesis, vec![prefix]));
    assert_eq!(engine.tx_slot_index.get(&tx.txid()), Some(&1));
    assert_eq!(engine.tx_status(&tx.txid()), "included");
}
