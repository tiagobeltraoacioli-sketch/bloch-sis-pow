use super::super::initial_liquidity::tests::funded;
use super::super::tests::{key, signature, BoundVerifier, DOMAIN};
use super::*;
use crate::transition::{TransferInputV2, TransferOutput};
use bloch_euvm::ustav::{Output, Transaction, Witnesses};

pub(in crate::transition::native_dex) fn fixture() -> (State, Request) {
    let (mut state, initial) = funded();
    let initialized = state
        .execute_initial_liquidity(&initial, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let record = &state.initial_pools[&initialized.pool];
    let b = &state.base_reserves[&record.reserve];
    let n = &state.paired_reserves[&record.reserve];
    let quote_request = QuoteRequest {
        domain: DOMAIN,
        pool: initialized.pool,
        revision: 1,
        maximum: [1_000_000, 30],
        minimum_lp: 1,
        valid_until: 100,
    };
    let quote = state.quote_blch_add(&quote_request, 1).unwrap();
    let mut blch = initial.blch;
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut blch
    {
        *inputs = vec![
            TransferInputV2 {
                txid: b.outpoint.0,
                vout: 0,
                key_index: RESERVE_KEY_INDEX,
            },
            TransferInputV2 {
                txid: initialized.blch_txid,
                vout: 0,
                key_index: 0,
            },
        ];
        *outputs = vec![
            TransferOutput {
                value: quote.reserves_after[0],
                script_hash: base_reserves::reserve_script(&DOMAIN, &record.reserve),
            },
            TransferOutput {
                value: 1,
                script_hash: Sha3_256::digest(key(1)).into(),
            },
        ];
    }
    let mut request = Request {
        quote: quote_request,
        pool_state_root: quote.pool_state_root,
        blch,
        native_gas: 100_000,
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                asset: n.asset,
                inputs: vec![
                    n.outpoint,
                    OutPoint {
                        transaction: n.outpoint.transaction,
                        index: 1,
                    },
                ],
                outputs: vec![
                    Output {
                        owner: key(1),
                        amount: quote.reserves_after[1],
                    },
                    Output {
                        owner: key(1),
                        amount: 40 - quote.amounts_in[1],
                    },
                ],
                delta: 0,
                mint_nonce: 0,
                policy_revision: 0,
                valid_until: 100,
            },
            witnesses: Witnesses {
                owners: vec![vec![], vec![0; 32]],
                modules: vec![vec![]],
                eligibility: vec![],
            },
        },
    };
    price(&state, &mut request);
    sign(&mut request);
    (state, request)
}
fn price(state: &State, r: &mut Request) {
    let len = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = len;
    }
    let fee = state.quote_blch_add_fee(r).unwrap();
    let quote = state.quote_blch_add(&r.quote, 1).unwrap();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut r.blch
    {
        outputs[1].value = state
            .base
            .utxo(&inputs[1].txid, inputs[1].vout)
            .unwrap()
            .value
            - quote.amounts_in[0]
            - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
}
fn sign(r: &mut Request) {
    let auth = r.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = signature(&auth, &key(1));
    }
    for witness in &mut r.native.witnesses.owners {
        if !witness.is_empty() {
            *witness = signature(&auth, &key(1));
        }
    }
}

#[test]
fn unbalanced_add_debits_only_required_amounts_and_rotates_both_reserves() {
    let (mut state, r) = fixture();
    let reserve = state.initial_pools[&r.quote.pool].reserve;
    let old_b = state.base_reserves[&reserve].outpoint;
    let old_n = state.paired_reserves[&reserve].outpoint;
    let quote = state.quote_blch_add(&r.quote, 1).unwrap();
    assert_eq!(quote.lp_minted, 3872);
    assert_eq!(quote.amounts_in, [499_936, 30]);
    assert_eq!(quote.unused_maximum, [500_064, 0]);
    let receipt = state
        .execute_blch_add(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(receipt.quote, quote);
    assert_eq!(state.blch_lp_position(&r.quote.pool, &key(1)), 6745 + 3872);
    assert_eq!(state.blch_lp_position(&r.quote.pool, &key(2)), 0);
    assert_eq!(
        state.blch_pool(&r.quote.pool).unwrap().lp_supply(),
        7745 + 3872
    );
    assert!(state.base.utxo(&old_b.0, old_b.1).is_none());
    assert!(state.native.gateway().native().output(&old_n).is_none());
    assert!(state.base_is_locked(&state.base_reserves[&reserve].outpoint));
    assert!(state
        .native()
        .is_locked(&state.paired_reserves[&reserve].outpoint));
    let root = state.state_root();
    assert!(state
        .execute_blch_add(&r, 1, &BoundVerifier, &BoundVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    let restored = State::restore(state.snapshot(), root, &BoundVerifier).unwrap();
    assert_eq!(restored.blch_lp_position(&r.quote.pool, &key(1)), 10617);
    let mut legacy = state.snapshot();
    legacy.version = 6;
    assert!(State::restore(legacy, root, &BoundVerifier).is_err());
}

#[test]
fn late_failures_never_publish_staged_lp_credit() {
    let (state, r) = fixture();
    for variant in 0..7 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => state.base_fees = u128::MAX,
            1 => state.priority_fees = u128::MAX,
            2 => {
                state.base.eutxos.insert(crate::state_root::EutxoEntry {
                    txid: r.output_txid(&DOMAIN).unwrap(),
                    vout: 0,
                    value: 1,
                    script_hash: [9; 32],
                });
            }
            3 => {
                if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
                    keys[0].signature[0] ^= 1;
                }
            }
            4 => bad.native.witnesses.owners[1][0] ^= 1,
            5 => {
                bad.native_gas = 100;
                price(&state, &mut bad);
                sign(&mut bad);
            }
            _ => bad.pool_state_root[0] ^= 1,
        }
        let root = state.state_root();
        assert!(
            state
                .execute_blch_add(&bad, 1, &BoundVerifier, &BoundVerifier)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(state.state_root(), root);
        assert_eq!(state.blch_lp_position(&r.quote.pool, &key(1)), 6745);
    }
}

#[test]
fn empty_funding_witness_and_foreign_locks_cannot_reuse_reserve_exception() {
    let (state, r) = fixture();
    for variant in 0..4 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => {
                bad.native.witnesses.owners[1].clear();
                price(&state, &mut bad);
                sign(&mut bad);
            }
            1 => {
                state
                    .paired_locks
                    .insert(bad.native.transaction.inputs[1], [9; 32]);
            }
            2 => {
                if let PosTransaction::TransferV2 { inputs, .. } = &bad.blch {
                    state
                        .base_locks
                        .insert((inputs[1].txid, inputs[1].vout), [9; 32]);
                }
            }
            _ => {
                bad.native.transaction.outputs[1].owner = key(2);
                sign(&mut bad);
            }
        }
        let root = state.state_root();
        assert!(state
            .execute_blch_add(&bad, 1, &BoundVerifier, &BoundVerifier)
            .is_err());
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn add_bounds_slippage_expiry_and_malformed_vectors_fail_without_mutation() {
    let (state, r) = fixture();
    for variant in 0..10 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => bad.quote.minimum_lp = 3873,
            1 => bad.quote.maximum[0] = 0,
            2 => bad.quote.maximum = [u64::MAX; 2],
            3 => bad.quote.valid_until = 0,
            4 => bad.quote.domain = [0; 32],
            5 => bad.native.transaction.outputs.clear(),
            6 => bad.native.witnesses.owners.clear(),
            7 => {
                if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
                    keys.clear();
                }
            }
            8 => {
                if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
                    outputs.clear();
                }
            }
            _ => bad.native_gas = u64::MAX,
        }
        let root = state.state_root();
        assert!(
            state
                .execute_blch_add(&bad, 1, &BoundVerifier, &BoundVerifier)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(state.state_root(), root);
    }
}
