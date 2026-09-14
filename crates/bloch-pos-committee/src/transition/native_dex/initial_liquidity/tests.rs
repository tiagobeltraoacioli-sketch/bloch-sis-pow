use super::super::paired_custody::tests::setup;
use super::super::tests::{key, signature, BoundVerifier, DOMAIN};
use super::*;
use crate::transition::{TransferInputV2, TransferOutput};
pub(in crate::transition::native_dex) fn funded() -> (State, Request) {
    let (mut state, pair) = setup();
    let receipt = state
        .execute_paired_custody(&pair, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let mut r = Request {
        reserve: receipt.reserve.id,
        creation_authorization: receipt.authorization,
        fee_bps: 30,
        minimum_lp: 1,
        valid_until: 100,
        blch: pair.blch,
    };
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut r.blch
    {
        *inputs = vec![TransferInputV2 {
            txid: receipt.blch_txid,
            vout: 1,
            key_index: 0,
        }];
        *outputs = vec![TransferOutput {
            value: 1,
            script_hash: Sha3_256::digest(key(1)).into(),
        }];
    }
    price(&state, &mut r);
    sign(&mut r);
    (state, r)
}
fn price(state: &State, r: &mut Request) {
    let len = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = len;
    }
    let fee = state.quote_initial_liquidity(r).unwrap();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut r.blch
    {
        outputs[0].value = state
            .base
            .utxo(&inputs[0].txid, inputs[0].vout)
            .unwrap()
            .value
            - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
}
fn sign(r: &mut Request) {
    let a = r.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = signature(&a, &key(1));
    }
}
#[test]
fn bootstrap_seals_lp_without_spending_reserves_and_snapshot_preserves_authority() {
    let (mut state, r) = funded();
    let base = state.base_reserves[&r.reserve].clone();
    let native = state.native.state_root();
    let before = state.native().snapshot();
    let out = state
        .execute_initial_liquidity(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(state.native.state_root(), native);
    assert_ne!(state.native().snapshot(), before);
    assert_eq!(state.base_reserves[&r.reserve], base);
    assert_eq!(
        state.blch_pool(&out.pool).unwrap().reserves(),
        [1_000_000, 60]
    );
    assert_eq!(out.lp_minted, 6745);
    assert_eq!(state.blch_lp_position(&out.pool, &key(1)), 6745);
    assert_eq!(state.blch_lp_position(&out.pool, &key(2)), 0);
    assert_eq!(state.blch_pool(&out.pool).unwrap().lp_supply(), 7745);
    let restored = State::restore(state.snapshot(), state.state_root(), &BoundVerifier).unwrap();
    assert_eq!(
        restored.blch_pool_for_reserve(&r.reserve),
        state.blch_pool(&out.pool)
    );
    assert_eq!(restored.blch_lp_position(&out.pool, &key(1)), 6745);
}
#[test]
fn bootstrap_snapshots_reject_forged_lp_owner_backing_duplicate_and_old_version() {
    let (mut state, r) = funded();
    state
        .execute_initial_liquidity(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let root = state.state_root();
    for variant in 0..7 {
        let mut bad = state.snapshot();
        match variant {
            0 => bad.initial_pools[0].lp_balance += 1,
            1 => bad.initial_pools[0].owner = key(2),
            2 => bad.initial_pools[0].reserve = [0; 32],
            3 => bad.initial_pools[0].creation_authorization = [0; 32],
            4 => bad.initial_pools.push(bad.initial_pools[0].clone()),
            5 => bad.version = 3,
            _ => bad.initial_pools.clear(),
        };
        assert!(State::restore(bad, root, &BoundVerifier).is_err());
    }
}
#[test]
fn locked_fee_inputs_and_postvalidation_failures_cannot_publish_lp() {
    let (state, r) = funded();
    for variant in 0..5 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => {
                if let PosTransaction::TransferV2 { inputs, .. } = &mut bad.blch {
                    inputs[0].vout = 0;
                }
            }
            1 => state.base_fees = u128::MAX,
            2 => bad.minimum_lp = u64::MAX,
            3 => bad.fee_bps = 10000,
            _ => {
                state.base.eutxos.insert(crate::state_root::EutxoEntry {
                    txid: bad.output_txid(&DOMAIN).unwrap(),
                    vout: 0,
                    value: 1,
                    script_hash: [7; 32],
                });
            }
        }
        sign(&mut bad);
        let root = state.state_root();
        assert!(state
            .execute_initial_liquidity(&bad, 1, &BoundVerifier, &BoundVerifier)
            .is_err());
        assert_eq!(state.state_root(), root);
        assert!(state.initial_pools.is_empty());
    }
}

fn initialized_quote() -> (State, super::super::swap_quote::Request) {
    let (mut state, r) = funded();
    let out = state
        .execute_initial_liquidity(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let request = super::super::swap_quote::Request {
        domain: DOMAIN,
        pool: out.pool,
        revision: 1,
        input_asset: bloch_euvm::BLCH,
        amount: 100_000,
        minimum_out: 5,
        valid_until: 100,
    };
    (state, request)
}

#[test]
fn backed_quotes_cover_both_directions_without_mutation_and_survive_restore() {
    let (state, mut r) = initialized_quote();
    let root = state.state_root();
    let before = state.native().snapshot();
    let q = state.quote_blch_swap(&r, 100).unwrap();
    assert_eq!(q.amount_out, 5);
    assert_eq!(q.reserves_before, [1_000_000, 60]);
    assert_eq!(q.reserves_after, [1_100_000, 55]);
    assert_eq!(q.fee_bps, 30);
    assert_eq!(q.request, r);
    assert_eq!(q.height, 100);
    assert_eq!(
        q.pool_state_root,
        state.blch_pool(&r.pool).unwrap().state_root()
    );
    r.input_asset = q.output_asset;
    r.amount = 6;
    r.minimum_out = 90_661;
    let reverse = state.quote_blch_swap(&r, 100).unwrap();
    assert_eq!(reverse.output_asset, bloch_euvm::BLCH);
    assert_eq!(reverse.amount_out, 90_661);
    assert_eq!(reverse.reserves_after, [909_339, 66]);
    assert_eq!(state.state_root(), root);
    assert_eq!(state.native().snapshot(), before);
    let restored = State::restore(state.snapshot(), root, &BoundVerifier).unwrap();
    assert_eq!(restored.quote_blch_swap(&r, 100).unwrap(), reverse);
}

#[test]
fn quote_rejects_wrong_domain_pool_asset_revision_expiry_dust_and_slippage() {
    let (state, r) = initialized_quote();
    let root = state.state_root();
    for variant in 0..9 {
        let mut bad = r.clone();
        match variant {
            0 => bad.domain = [0; 32],
            1 => bad.pool = [0; 32],
            2 => bad.input_asset = [255; 32],
            3 => bad.revision = 0,
            4 => bad.revision = 2,
            5 => bad.valid_until = 99,
            6 => bad.amount = 0,
            7 => bad.amount = 1,
            _ => bad.minimum_out = 6,
        }
        assert!(
            state.quote_blch_swap(&bad, 100).is_err(),
            "variant {variant}"
        );
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn quote_rechecks_backing_locks_creation_and_lp_authority() {
    let (state, r) = initialized_quote();
    let reserve = state.initial_pools[&r.pool].reserve;
    for variant in 0..8 {
        let mut bad = state.clone();
        match variant {
            0 => bad.base_reserves.get_mut(&reserve).unwrap().amount += 1,
            1 => bad.paired_reserves.get_mut(&reserve).unwrap().amount += 1,
            2 => bad.base_locks.clear(),
            3 => bad.paired_locks.clear(),
            4 => bad.reserve_pools.clear(),
            5 => bad.initial_pools.get_mut(&r.pool).unwrap().lp_balance += 1,
            6 => bad.initial_pools.get_mut(&r.pool).unwrap().owner = key(2),
            _ => {
                bad.initial_pools
                    .get_mut(&r.pool)
                    .unwrap()
                    .creation_authorization = [0; 32]
            }
        }
        let root = bad.state_root();
        assert!(bad.quote_blch_swap(&r, 100).is_err(), "variant {variant}");
        assert_eq!(bad.state_root(), root);
    }
}

fn swap_request(
    state: &State,
    pool: [u8; 32],
    base_point: ([u8; 32], u32),
    native_point: Option<bloch_euvm::ustav::OutPoint>,
    amount: u64,
    template: PosTransaction,
) -> super::super::swap::Request {
    use super::super::{base_reserves::RESERVE_KEY_INDEX, swap, swap_quote};
    use bloch_euvm::ustav::{Output, Transaction, Witnesses};
    let record = &state.initial_pools[&pool];
    let b = &state.base_reserves[&record.reserve];
    let n = &state.paired_reserves[&record.reserve];
    let quote_request = swap_quote::Request {
        domain: DOMAIN,
        pool,
        revision: record.pool.revision(),
        input_asset: if native_point.is_some() {
            n.asset
        } else {
            bloch_euvm::BLCH
        },
        amount,
        minimum_out: 1,
        valid_until: 100,
    };
    let quote = state.quote_blch_swap(&quote_request, 1).unwrap();
    let mut blch = template;
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut blch
    {
        *inputs = vec![
            TransferInputV2 {
                txid: b.outpoint.0,
                vout: b.outpoint.1,
                key_index: RESERVE_KEY_INDEX,
            },
            TransferInputV2 {
                txid: base_point.0,
                vout: base_point.1,
                key_index: 0,
            },
        ];
        *outputs = vec![TransferOutput {
            value: quote.reserves_after[0],
            script_hash: super::super::base_reserves::reserve_script(&DOMAIN, &record.reserve),
        }];
        if native_point.is_some() {
            outputs.push(TransferOutput {
                value: quote.amount_out,
                script_hash: Sha3_256::digest(key(1)).into(),
            });
        }
        outputs.push(TransferOutput {
            value: 1,
            script_hash: Sha3_256::digest(key(1)).into(),
        });
    }
    let mut inputs = vec![n.outpoint];
    let mut outputs = vec![Output {
        owner: n.owner.clone(),
        amount: quote.reserves_after[1],
    }];
    if let Some(point) = native_point {
        inputs.push(point);
        let funding = state.native.spendable_output(&point).unwrap().output.amount;
        if funding > amount {
            outputs.push(Output {
                owner: key(1),
                amount: funding - amount,
            });
        }
    } else {
        outputs.push(Output {
            owner: key(1),
            amount: quote.amount_out,
        });
    }
    inputs.sort();
    let witnesses = Witnesses {
        owners: inputs
            .iter()
            .map(|p| {
                if *p == n.outpoint {
                    vec![]
                } else {
                    vec![0; 32]
                }
            })
            .collect(),
        modules: vec![vec![]],
        eligibility: vec![],
    };
    let mut request = swap::Request {
        quote: quote_request,
        pool_state_root: quote.pool_state_root,
        blch,
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                asset: n.asset,
                inputs,
                outputs,
                delta: 0,
                mint_nonce: 0,
                policy_revision: 0,
                valid_until: 100,
            },
            witnesses,
        },
        native_gas: 100_000,
    };
    price_swap(state, &mut request);
    sign_swap(&mut request);
    request
}
fn price_swap(state: &State, r: &mut super::super::swap::Request) {
    let len = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = len;
    }
    let charge = state.quote_blch_swap_fee(r).unwrap();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut r.blch
    {
        let funding = state
            .base
            .utxo(&inputs[1].txid, inputs[1].vout)
            .unwrap()
            .value;
        let debit = if r.quote.input_asset == bloch_euvm::BLCH {
            r.quote.amount
        } else {
            0
        };
        outputs.last_mut().unwrap().value =
            funding - debit - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
}
fn sign_swap(r: &mut super::super::swap::Request) {
    let authorization = r.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = signature(&authorization, &key(1));
    }
    for sig in &mut r.native.witnesses.owners {
        if !sig.is_empty() {
            *sig = signature(&authorization, &key(1));
        }
    }
}
pub(in crate::transition::native_dex) fn swap_fixture() -> (State, super::super::swap::Request) {
    let (mut state, r) = funded();
    let receipt = state
        .execute_initial_liquidity(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let request = swap_request(
        &state,
        receipt.pool,
        (receipt.blch_txid, 0),
        None,
        100_000,
        r.blch,
    );
    (state, request)
}

#[test]
fn swaps_rotate_actual_reserves_preserve_lp_and_restore_then_swap_again() {
    let (mut state, r) = swap_fixture();
    let pool = r.quote.pool;
    let reserve = state.initial_pools[&pool].reserve;
    let old_base = state.base_reserves[&reserve].outpoint;
    let old_native = state.paired_reserves[&reserve].outpoint;
    let initial_lp = state.blch_lp_position(&pool, &key(1));
    let receipt = state
        .execute_blch_swap(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(receipt.quote.reserves_after, [1_100_000, 55]);
    assert!(state.base.utxo(&old_base.0, old_base.1).is_none());
    assert!(state
        .native
        .gateway()
        .native()
        .output(&old_native)
        .is_none());
    assert!(!state.base_is_locked(&old_base));
    assert!(!state.native().is_locked(&old_native));
    assert!(state.base_is_locked(&state.base_reserves[&reserve].outpoint));
    assert!(state
        .native()
        .is_locked(&state.paired_reserves[&reserve].outpoint));
    assert_eq!(state.base_reserves[&reserve].revision, 1);
    assert_eq!(state.blch_pool(&pool).unwrap().revision(), 2);
    assert_eq!(state.blch_lp_position(&pool, &key(1)), initial_lp);
    let mut state = State::restore(state.snapshot(), state.state_root(), &BoundVerifier).unwrap();
    let reverse = swap_request(
        &state,
        pool,
        (receipt.blch_txid, 1),
        Some(receipt.native.outputs[1]),
        3,
        r.blch,
    );
    state
        .execute_blch_swap(&reverse, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(state.blch_pool(&pool).unwrap().revision(), 3);
    assert_eq!(state.blch_lp_position(&pool, &key(1)), initial_lp);
    State::restore(state.snapshot(), state.state_root(), &BoundVerifier).unwrap();
}

#[test]
fn swap_invalid_reserve_fee_collision_and_authentication_are_atomic() {
    let (state, r) = swap_fixture();
    for variant in 0..10 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => bad.native.transaction.outputs[0].owner = key(2),
            1 => bad.native.transaction.outputs[0].amount += 1,
            2 => bad.native.witnesses.owners[0] = vec![0; 32],
            3 => {
                if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
                    outputs[0].value -= 1;
                    outputs[1].value += 1;
                }
            }
            4 => bad.pool_state_root[0] ^= 1,
            5 => state.base_fees = u128::MAX,
            6 => bad.native_gas = 1,
            7 => bad.quote.minimum_out = 6,
            8 => {
                if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
                    outputs[1].script_hash = Sha3_256::digest(key(2)).into();
                }
            }
            _ => {
                state.base.eutxos.insert(crate::state_root::EutxoEntry {
                    txid: bad.output_txid(&DOMAIN).unwrap(),
                    vout: 0,
                    value: 1,
                    script_hash: [7; 32],
                });
            }
        }
        sign_swap(&mut bad);
        let root = state.state_root();
        assert!(
            state
                .execute_blch_swap(&bad, 1, &BoundVerifier, &BoundVerifier)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn second_empty_witness_cannot_spend_even_the_reserve_owners_funding() {
    let (mut state, r) = swap_fixture();
    let receipt = state
        .execute_blch_swap(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let mut reverse = swap_request(
        &state,
        r.quote.pool,
        (receipt.blch_txid, 1),
        Some(receipt.native.outputs[1]),
        3,
        r.blch,
    );
    for sig in &mut reverse.native.witnesses.owners {
        sig.clear();
    }
    price_swap(&state, &mut reverse);
    sign_swap(&mut reverse);
    let root = state.state_root();
    assert!(state
        .execute_blch_swap(&reverse, 2, &BoundVerifier, &BoundVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
}

#[test]
fn evolved_pool_snapshots_reject_missing_pool_initial_funding_revision_and_v4() {
    let (mut state, r) = swap_fixture();
    state
        .execute_blch_swap(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let root = state.state_root();
    for variant in 0..5 {
        let mut bad = state.snapshot();
        match variant {
            0 => bad.initial_pools.clear(),
            1 => bad.initial_pools[0].initial_reserves[0] += 1,
            2 => bad.base_reserves[0].revision += 1,
            3 => bad.initial_pools[0].lp_balance += 1,
            _ => bad.version = 4,
        }
        assert!(State::restore(bad, root, &BoundVerifier).is_err());
    }
}

#[test]
fn malformed_swap_vectors_and_resource_limits_reject_without_panicking() {
    let (state, r) = swap_fixture();
    for variant in 0..8 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => bad.native.transaction.outputs.clear(),
            1 => bad.native.transaction.inputs.clear(),
            2 => bad.native.witnesses.owners.clear(),
            3 => bad.native.witnesses.owners.push(vec![]),
            4 => {
                if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
                    keys.clear();
                }
            }
            5 => {
                if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
                    outputs.clear();
                }
            }
            6 => bad.native_gas = u64::MAX,
            _ => bad.quote.domain = [0; 32],
        }
        let root = state.state_root();
        assert!(
            state
                .execute_blch_swap(&bad, 1, &BoundVerifier, &BoundVerifier)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn expired_swap_and_foreign_locked_funding_do_not_release_a_reserve() {
    let (mut state, r) = swap_fixture();
    let root = state.state_root();
    assert!(state
        .execute_blch_swap(&r, 101, &BoundVerifier, &BoundVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    let receipt = state
        .execute_blch_swap(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let reverse = swap_request(
        &state,
        r.quote.pool,
        (receipt.blch_txid, 1),
        Some(receipt.native.outputs[1]),
        3,
        r.blch,
    );
    let mut bad = state.clone();
    // Simulate an otherwise valid trader-owned funding output belonging to a
    // different paired lock. The exception must never authorize that input.
    bad.paired_locks.insert(receipt.native.outputs[1], [99; 32]);
    let root = bad.state_root();
    assert_eq!(
        bad.execute_blch_swap(&reverse, 2, &BoundVerifier, &BoundVerifier)
            .unwrap_err(),
        Error::LockedReserve
    );
    assert_eq!(bad.state_root(), root);
    let mut bad = state.clone();
    bad.base_locks.insert((receipt.blch_txid, 1), [99; 32]);
    let root = bad.state_root();
    assert_eq!(
        bad.execute_blch_swap(&reverse, 2, &BoundVerifier, &BoundVerifier)
            .unwrap_err(),
        Error::LockedReserve
    );
    assert_eq!(bad.state_root(), root);
}

fn remove_request(
    state: &State,
    pool: [u8; 32],
    fee_point: ([u8; 32], u32),
    lp: u64,
    template: PosTransaction,
) -> super::super::remove_liquidity::Request {
    use super::super::{base_reserves::RESERVE_KEY_INDEX, remove_liquidity};
    use bloch_euvm::ustav::{Output, Transaction, Witnesses};
    let record = &state.initial_pools[&pool];
    let b = &state.base_reserves[&record.reserve];
    let n = &state.paired_reserves[&record.reserve];
    let quote_request = remove_liquidity::QuoteRequest {
        owner: key(1),
        domain: DOMAIN,
        pool,
        revision: record.pool.revision(),
        lp,
        minimum: [1, 1],
        valid_until: 100,
    };
    let quote = state.quote_blch_remove(&quote_request, 1).unwrap();
    let mut blch = template;
    let owner_hash = Sha3_256::digest(key(1)).into();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut blch
    {
        *inputs = vec![
            TransferInputV2 {
                txid: b.outpoint.0,
                vout: b.outpoint.1,
                key_index: RESERVE_KEY_INDEX,
            },
            TransferInputV2 {
                txid: fee_point.0,
                vout: fee_point.1,
                key_index: 0,
            },
        ];
        *outputs = vec![
            TransferOutput {
                value: quote.reserves_after[0],
                script_hash: super::super::base_reserves::reserve_script(&DOMAIN, &record.reserve),
            },
            TransferOutput {
                value: quote.amounts_out[0],
                script_hash: owner_hash,
            },
            TransferOutput {
                value: 1,
                script_hash: owner_hash,
            },
        ];
    }
    let mut request = remove_liquidity::Request {
        quote: quote_request,
        pool_state_root: quote.pool_state_root,
        blch,
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                asset: n.asset,
                inputs: vec![n.outpoint],
                outputs: vec![
                    Output {
                        owner: key(1),
                        amount: quote.reserves_after[1],
                    },
                    Output {
                        owner: key(1),
                        amount: quote.amounts_out[1],
                    },
                ],
                delta: 0,
                mint_nonce: 0,
                policy_revision: 0,
                valid_until: 100,
            },
            witnesses: Witnesses {
                owners: vec![vec![0; 32]],
                modules: vec![vec![]],
                eligibility: vec![],
            },
        },
        native_gas: 100_000,
    };
    price_remove(state, &mut request);
    sign_remove(&mut request);
    request
}
fn price_remove(state: &State, r: &mut super::super::remove_liquidity::Request) {
    let len = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = len;
    }
    let charge = state.quote_blch_remove_fee(r).unwrap();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut r.blch
    {
        let funding = state
            .base
            .utxo(&inputs[1].txid, inputs[1].vout)
            .unwrap()
            .value;
        outputs[2].value = funding - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
}
fn sign_remove(r: &mut super::super::remove_liquidity::Request) {
    let authorization = r.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = signature(&authorization, &key(1));
    }
    r.native.witnesses.owners[0] = signature(&authorization, &key(1));
}
pub(in crate::transition::native_dex) fn remove_fixture(
) -> (State, super::super::remove_liquidity::Request) {
    let (mut state, initial) = funded();
    let receipt = state
        .execute_initial_liquidity(&initial, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let request = remove_request(
        &state,
        receipt.pool,
        (receipt.blch_txid, 0),
        3000,
        initial.blch,
    );
    (state, request)
}

#[test]
fn proportional_redemption_and_full_burn_leave_minimum_locked_and_close_disabled() {
    let (mut state, first) = remove_fixture();
    let pool = first.quote.pool;
    let reserve = state.initial_pools[&pool].reserve;
    let first_receipt = state
        .execute_blch_remove(&first, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(first_receipt.quote.amounts_out, [387_346, 23]);
    assert_eq!(first_receipt.quote.reserves_after, [612_654, 37]);
    assert_eq!(first_receipt.quote.lp_remaining, 3745);
    assert_eq!(state.blch_pool(&pool).unwrap().lp_supply(), 4745);
    let mut state = State::restore(state.snapshot(), state.state_root(), &BoundVerifier).unwrap();
    let last = remove_request(&state, pool, (first_receipt.blch_txid, 2), 3745, first.blch);
    let receipt = state
        .execute_blch_remove(&last, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(receipt.quote.amounts_out, [483_538, 29]);
    assert_eq!(receipt.quote.reserves_after, [129_116, 8]);
    assert_eq!(state.blch_lp_position(&pool, &key(1)), 0);
    assert_eq!(
        state.blch_pool(&pool).unwrap().lp_supply(),
        amm::MINIMUM_LIQUIDITY
    );
    assert!(state.base_is_locked(&state.base_reserves[&reserve].outpoint));
    assert!(state
        .native()
        .is_locked(&state.paired_reserves[&reserve].outpoint));
    let mut more = last.quote.clone();
    more.revision = state.blch_pool(&pool).unwrap().revision();
    more.lp = 1;
    assert!(state.quote_blch_remove(&more, 2).is_err());
    let close = super::super::paired_custody::CloseRequest {
        reserve,
        creation_authorization: state.paired_reserves[&reserve].authorization,
        blch: last.blch,
        native: last.native,
        valid_until: 100,
        native_gas: 100_000,
    };
    let root = state.state_root();
    assert_eq!(
        state
            .execute_paired_close(&close, 2, &BoundVerifier, &BoundVerifier)
            .unwrap_err(),
        Error::LockedReserve
    );
    assert_eq!(state.state_root(), root);
    State::restore(state.snapshot(), root, &BoundVerifier).unwrap();
}

#[test]
fn redemption_after_swap_uses_current_reserves_and_allows_another_swap() {
    let (mut state, trade) = swap_fixture();
    let traded = state
        .execute_blch_swap(&trade, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let remove = remove_request(
        &state,
        trade.quote.pool,
        (traded.blch_txid, 1),
        3000,
        trade.blch.clone(),
    );
    let reserves = state.blch_pool(&trade.quote.pool).unwrap().reserves();
    let supply = state.blch_pool(&trade.quote.pool).unwrap().lp_supply();
    let removed = state
        .execute_blch_remove(&remove, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    for i in 0..2 {
        assert_eq!(
            removed.quote.amounts_out[i],
            (u128::from(reserves[i]) * 3000 / u128::from(supply)) as u64
        );
    }
    let mut state = State::restore(state.snapshot(), state.state_root(), &BoundVerifier).unwrap();
    let next = swap_request(
        &state,
        trade.quote.pool,
        (removed.blch_txid, 2),
        None,
        100_000,
        trade.blch,
    );
    state
        .execute_blch_swap(&next, 3, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(state.blch_lp_position(&next.quote.pool, &key(1)), 3745);
    State::restore(state.snapshot(), state.state_root(), &BoundVerifier).unwrap();
}

#[test]
fn redemption_limits_signature_scope_and_late_collision_leave_lp_unchanged() {
    let (state, r) = remove_fixture();
    for variant in 0..10 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => bad.quote.lp = 0,
            1 => bad.quote.lp = 6746,
            2 => bad.quote.lp = u64::MAX,
            3 => bad.quote.minimum[0] = u64::MAX,
            4 => bad.quote.minimum[1] = u64::MAX,
            5 => bad.pool_state_root[0] ^= 1,
            6 => state.base_fees = u128::MAX,
            7 => bad.native_gas = 1,
            8 => bad.native.transaction.outputs[0].owner = key(2),
            _ => {
                state.base.eutxos.insert(crate::state_root::EutxoEntry {
                    txid: bad.output_txid(&DOMAIN).unwrap(),
                    vout: 0,
                    value: 1,
                    script_hash: [7; 32],
                });
            }
        }
        sign_remove(&mut bad);
        let root = state.state_root();
        assert!(
            state
                .execute_blch_remove(&bad, 1, &BoundVerifier, &BoundVerifier)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(state.state_root(), root);
        assert_eq!(state.blch_lp_position(&r.quote.pool, &key(1)), 6745);
    }
    let mut state = state;
    let root = state.state_root();
    assert!(state
        .execute_blch_remove(&r, 101, &BoundVerifier, &BoundVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
}

#[test]
fn redemption_cannot_use_empty_swap_witness_or_malformed_shapes() {
    let (state, r) = remove_fixture();
    for variant in 0..9 {
        let mut state = state.clone();
        let mut bad = r.clone();
        match variant {
            0 => {
                bad.native.witnesses.owners[0].clear();
                price_remove(&state, &mut bad);
            }
            1 => bad.native.transaction.outputs.clear(),
            2 => {
                bad.native.transaction.outputs.pop();
            }
            3 => bad.native.transaction.inputs.clear(),
            4 => bad.native.witnesses.owners.clear(),
            5 => bad.native.witnesses.owners.push(vec![]),
            6 => {
                if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
                    keys.clear();
                }
            }
            7 => {
                if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
                    outputs.clear();
                }
            }
            _ => bad.native_gas = u64::MAX,
        }
        let root = state.state_root();
        assert!(
            state
                .execute_blch_remove(&bad, 1, &BoundVerifier, &BoundVerifier)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn post_redemption_snapshots_reject_lp_inflation_supply_mismatch_and_old_version() {
    let (mut state, r) = remove_fixture();
    state
        .execute_blch_remove(&r, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let root = state.state_root();
    for variant in 0..5 {
        let mut bad = state.snapshot();
        match variant {
            0 => bad.initial_pools[0].lp_balance += 1,
            1 => bad.initial_pools[0].lp_balance = u64::MAX,
            2 => bad.initial_pools[0].owner = key(2),
            3 => bad.initial_pools[0].initial_reserves[0] += 1,
            _ => bad.version = 5,
        }
        assert!(State::restore(bad, root, &BoundVerifier).is_err());
    }
}

#[test]
fn provider_positions_bound_capacity_update_and_reclaim_empty_slots() {
    let (mut state, request) = funded();
    let receipt = state
        .execute_initial_liquidity(&request, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let record = state.initial_pools.get_mut(&receipt.pool).unwrap();
    for n in 2..=128 {
        record.set_position(&key(n), 1).unwrap();
    }
    let full = record.clone();
    assert!(record.set_position(&key(129), 1).is_err());
    assert_eq!(*record, full);
    record.set_position(&key(2), 2).unwrap();
    record.set_position(&key(2), 0).unwrap();
    assert_eq!(record.position(&key(2)), 0);
    assert!(!record.positions.contains_key(&key(2)));
    record.set_position(&key(129), 1).unwrap();
    record.set_position(&key(1), 0).unwrap();
    assert!(record.set_position(&key(130), 1).is_err());
    assert!(record.set_position(&[], 1).is_err());
    assert!(record
        .set_position(&vec![1; MAX_BASE_WITNESS_BYTES + 1], 1)
        .is_err());
}

#[test]
fn restored_positions_require_valid_keys_canonical_entries_and_total_supply() {
    // An evolved pool permits multiple providers; authority is still supplied
    // by the authenticated outer root, never by this structural fixture.
    let (mut state, request) = remove_fixture();
    state
        .execute_blch_remove(&request, 1, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let id = request.quote.pool;
    let record = state.initial_pools.get_mut(&id).unwrap();
    record.lp_balance -= 1;
    record.set_position(&key(2), 1).unwrap();
    let root = state.state_root();
    let restored = State::restore(state.snapshot(), root, &BoundVerifier).unwrap();
    assert_eq!(restored.blch_lp_position(&id, &key(2)), 1);
    for variant in 0..7 {
        let mut bad = state.clone();
        let record = bad.initial_pools.get_mut(&id).unwrap();
        match variant {
            0 => {
                record.positions.insert(key(3), 1);
            }
            1 => {
                record.positions.insert(key(3), 0);
            }
            2 => {
                record.positions.insert(key(1), 1);
            }
            3 => {
                record.positions.remove(&key(2));
                record.positions.insert(key(0), 1);
            }
            4 => {
                record.positions.remove(&key(2));
                record.positions.insert(vec![], 1);
            }
            5 => {
                record.positions.insert(key(3), u64::MAX);
            }
            _ => {
                for n in 3..=130 {
                    record.positions.insert(key(n), 1);
                }
            }
        }
        // Supply a matching root to exercise structural rejection independently.
        assert!(State::restore(bad.snapshot(), bad.state_root(), &BoundVerifier).is_err());
        assert_ne!(bad.state_root(), root);
    }
}
