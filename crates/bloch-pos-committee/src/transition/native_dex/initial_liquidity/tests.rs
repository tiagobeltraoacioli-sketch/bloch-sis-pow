use super::super::paired_custody::tests::setup;
use super::super::tests::{key, signature, BoundVerifier, DOMAIN};
use super::*;
use crate::transition::{TransferInputV2, TransferOutput};
fn funded() -> (State, Request) {
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
