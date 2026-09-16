use super::super::{
    pool_wire::Request,
    tests::{signature, BoundVerifier, DOMAIN},
    PosTransaction,
};
use super::*;
use crate::interfaces::StateReader;
fn base_mut(request: &mut Request) -> &mut PosTransaction {
    match request {
        Request::CreatePair(r) => &mut r.blch,
        Request::Initialize(r) => &mut r.blch,
        Request::Add(r) => &mut r.blch,
        Request::Swap(r) => &mut r.blch,
        Request::Remove(r) => &mut r.blch,
        Request::ClosePair(r) => &mut r.blch,
        _ => panic!("gateway"),
    }
}
fn auth(request: &Request) -> [u8; 32] {
    match request {
        Request::CreatePair(r) => r.authorization(&DOMAIN),
        Request::Initialize(r) => r.authorization(&DOMAIN),
        Request::Add(r) => r.authorization(&DOMAIN),
        Request::Swap(r) => r.authorization(&DOMAIN),
        Request::Remove(r) => r.authorization(&DOMAIN),
        Request::ClosePair(r) => r.authorization(&DOMAIN),
        _ => panic!("gateway"),
    }
    .unwrap()
}
fn quote(state: &State, request: &Request, fee: u128) -> crate::fee_market::TxCharge {
    match request {
        Request::CreatePair(r) => state.quote_paired_custody_with_context(r, fee, 5),
        Request::Initialize(r) => state.quote_initial_liquidity_with_context(r, fee, 5),
        Request::Add(r) => state.quote_blch_add_fee_with_context(r, fee, 5),
        Request::Swap(r) => state.quote_blch_swap_fee_with_context(r, fee, 5),
        Request::Remove(r) => state.quote_blch_remove_fee_with_context(r, fee, 5),
        Request::ClosePair(r) => state.quote_paired_close_with_context(r, fee, 5),
        _ => panic!("gateway"),
    }
    .unwrap()
}
pub(in crate::transition) fn fixtures(
    fee: u128,
) -> Vec<(CommittedState, Vec<u8>, crate::fee_market::TxCharge)> {
    super::super::pool_wire::tests::fixtures()
        .into_iter()
        .map(|(mut state, mut request)| {
            let old = pool_wire::quote_request(&state, &request).unwrap();
            let length = pool_wire::encode(&request, &DOMAIN).unwrap().len() as u64 + 5;
            if let PosTransaction::TransferV2 { tx_bytes, .. } = base_mut(&mut request) {
                *tx_bytes = length;
            }
            let charge = quote(&state, &request, fee);
            let old_total = old.base_fee_sat + old.priority_fee_sat;
            let new_total = charge.base_fee_sat + charge.priority_fee_sat;
            if let PosTransaction::TransferV2 { outputs, .. } = base_mut(&mut request) {
                let change = outputs.last_mut().unwrap();
                change.value =
                    u64::try_from(u128::from(change.value) + old_total - new_total).unwrap();
            }
            let hash = auth(&request);
            if let PosTransaction::TransferV2 { keys, .. } = base_mut(&mut request) {
                for key in keys {
                    key.signature = signature(&hash, &key.pubkey);
                }
            }
            let native = match &mut request {
                Request::CreatePair(r) => Some(&mut r.native),
                Request::Initialize(_) => None,
                Request::Add(r) => Some(&mut r.native),
                Request::Swap(r) => Some(&mut r.native),
                Request::Remove(r) => Some(&mut r.native),
                Request::ClosePair(r) => Some(&mut r.native),
                _ => None,
            };
            if let Some(native) = native {
                for (point, witness) in native
                    .transaction
                    .inputs
                    .iter()
                    .zip(native.witnesses.owners.iter_mut())
                {
                    if !witness.is_empty() {
                        let owner = &state
                            .native
                            .gateway()
                            .native()
                            .output(point)
                            .unwrap()
                            .output
                            .owner;
                        *witness = signature(&hash, owner);
                    }
                }
            }
            state.base_fees = 0;
            state.priority_fees = 0;
            let (base, pinned) = state.into_parts();
            let mut base = base;
            base.native_state = Some(pinned.state);
            (base, pool_wire::encode(&request, &DOMAIN).unwrap(), charge)
        })
        .collect()
}
#[test]
fn canonical_pool_all_operations_frame_fees_atomicity_and_restore() {
    let fee = crate::fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    for (mut base, bytes, charge) in fixtures(fee) {
        let before = base.clone();
        let actual = apply_pool(&mut base, &bytes, 1, fee, &BoundVerifier, &BoundVerifier).unwrap();
        assert_eq!(actual, charge);
        assert_ne!(base.native_state, before.native_state);
        let pinned = base.native_state.as_ref().unwrap();
        assert_eq!(pinned.base_fees, 0);
        assert_eq!(pinned.priority_fees, 0);
        let restored = NativeState::restore_snapshot(
            &pinned.encode_snapshot().unwrap(),
            &base,
            pinned.commitment(),
            &BoundVerifier,
        )
        .unwrap();
        assert_eq!(&restored, pinned);
        let post = base.clone();
        assert!(apply_pool(&mut base, &bytes, 1, fee, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(base, post);
        let mut corrupt = bytes.clone();
        corrupt.pop();
        let mut staged = before.clone();
        assert!(apply_pool(
            &mut staged,
            &corrupt,
            1,
            fee,
            &BoundVerifier,
            &BoundVerifier
        )
        .is_err());
        assert_eq!(staged, before);
    }
}
#[test]
fn canonical_pool_rejects_gateway_and_wrong_domain() {
    let fee = crate::fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let (mut base, request) = super::super::consensus_gateway::tests::funded_import(fee);
    let root = base.state_root();
    assert_eq!(
        apply_pool(
            &mut base,
            &request.canonical_bytes(&DOMAIN).unwrap(),
            1,
            fee,
            &BoundVerifier,
            &BoundVerifier
        ),
        Err(Error::WrongOperation)
    );
    assert_eq!(base.state_root(), root);
    for (mut base, mut bytes, _) in fixtures(fee) {
        bytes[10] ^= 1;
        let before = base.clone();
        assert!(apply_pool(&mut base, &bytes, 1, fee, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(base, before);
    }
}

pub(in crate::transition) fn imported_pool_start(fee: u128) -> (CommittedState, PosTransaction) {
    use super::super::tests::key;
    use bloch_euvm::ustav::gateway::{recipient_hash, wire::Operation};
    use sha3::{Digest, Sha3_256};
    let (base, mut request) = super::super::consensus_gateway::tests::funded_import(fee);
    let Operation::Import(import) = &mut request.gateway.operation else {
        unreachable!()
    };
    import.deposit.pq_recipient_hash = recipient_hash(&key(1));
    import.transaction.outputs[0].owner = key(1);
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[0].script_hash = Sha3_256::digest(key(1)).into();
    }
    let hash = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&hash, &keys[0].pubkey);
    }
    request.gateway.witnesses.modules[0] = vec![bloch_euvm::Val::Bytes(signature(&hash, &key(1)))];
    request.gateway.approvals = vec![signature(&hash, &key(2)), signature(&hash, &key(3))];
    (
        base,
        PosTransaction::NativeImport(
            crate::transition::NativeTransferPayload::new(
                request.canonical_bytes(&DOMAIN).unwrap(),
            )
            .unwrap(),
        ),
    )
}
fn state_view(base: &CommittedState) -> State {
    let mut projection = base.clone();
    let native = projection.native_state.take().unwrap();
    State {
        base: projection,
        native: native.native,
        domain: native.domain,
        base_fees: 0,
        priority_fees: 0,
        base_reserves: native.base_reserves,
        base_locks: native.base_locks,
        paired_reserves: native.paired_reserves,
        paired_locks: native.paired_locks,
        initial_pools: native.initial_pools,
        reserve_pools: native.reserve_pools,
    }
}
pub(in crate::transition) fn imported_pool_step(
    base: &CommittedState,
    step: usize,
    fee: u128,
) -> PosTransaction {
    use super::super::{initial_liquidity, paired_custody, tests::key};
    use crate::transition::{TransferInputV2, TransferOutput};
    use sha3::{Digest, Sha3_256};
    let state = state_view(base);
    let owner_hash = Sha3_256::digest(key(1)).into();
    let funding = base
        .utxos()
        .find(|entry| {
            entry.script_hash == owner_hash && !state.base_is_locked(&(entry.txid, entry.vout))
        })
        .unwrap();
    let mut template = paired_custody::tests::setup().1;
    if let PosTransaction::TransferV2 { inputs, .. } = &mut template.blch {
        *inputs = vec![TransferInputV2 {
            txid: funding.txid,
            vout: funding.vout,
            key_index: 0,
        }];
    }
    let mut request = match step {
        0 => {
            let native = state
                .native
                .gateway()
                .native()
                .snapshot()
                .outputs
                .into_iter()
                .find(|(_, o)| o.output.owner == key(1))
                .unwrap();
            template.native.transaction.asset = native.1.asset;
            template.native.transaction.inputs = vec![native.0];
            template.native.transaction.outputs[1].amount =
                native.1.output.amount - template.native_amount;
            Request::CreatePair(template)
        }
        1 => {
            let reserve = state.base_reserves.values().next().unwrap();
            if let PosTransaction::TransferV2 { outputs, .. } = &mut template.blch {
                *outputs = vec![TransferOutput {
                    value: 1,
                    script_hash: owner_hash,
                }];
            }
            Request::Initialize(initial_liquidity::Request {
                reserve: reserve.id,
                creation_authorization: state.paired_reserves[&reserve.id].authorization,
                fee_bps: 30,
                minimum_lp: 1,
                valid_until: 100,
                blch: template.blch,
            })
        }
        _ => {
            let pool = *state.initial_pools.keys().next().unwrap();
            Request::Swap(initial_liquidity::tests::swap_request(
                &state,
                pool,
                (funding.txid, funding.vout),
                None,
                100_000,
                template.blch,
            ))
        }
    };
    if let Request::Swap(r) = &mut request {
        r.quote.minimum_out = 5;
    }
    let length = pool_wire::encode(&request, &DOMAIN).unwrap().len() as u64 + 5;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = base_mut(&mut request) {
        *tx_bytes = length;
    }
    let charge = quote(&state, &request, fee);
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = base_mut(&mut request)
    {
        let total: u128 = inputs
            .iter()
            .map(|i| u128::from(base.utxo(&i.txid, i.vout).unwrap().value))
            .sum();
        let fixed: u128 = outputs[..outputs.len() - 1]
            .iter()
            .map(|o| u128::from(o.value))
            .sum();
        outputs.last_mut().unwrap().value =
            u64::try_from(total - fixed - charge.base_fee_sat - charge.priority_fee_sat).unwrap();
    }
    let hash = auth(&request);
    if let PosTransaction::TransferV2 { keys, .. } = base_mut(&mut request) {
        for k in keys {
            k.signature = signature(&hash, &k.pubkey);
        }
    }
    match &mut request {
        Request::CreatePair(r) => {
            for witness in &mut r.native.witnesses.owners {
                *witness = signature(&hash, &key(1));
            }
        }
        Request::Swap(r) => {
            for witness in &mut r.native.witnesses.owners {
                if !witness.is_empty() {
                    *witness = signature(&hash, &key(1));
                }
            }
        }
        _ => {}
    }
    PosTransaction::NativePool(
        crate::transition::NativeTransferPayload::new(
            pool_wire::encode(&request, &DOMAIN).unwrap(),
        )
        .unwrap(),
    )
}
pub(in crate::transition) fn assert_imported_pool(base: &CommittedState, swapped: bool) {
    use super::super::tests::key;
    let state = state_view(base);
    let pool = state.initial_pools.values().next().unwrap();
    // PoolState::new starts at revision 0. Initial Add advances it to 1;
    // the subsequent Swap advances it once more without minting/burning LP.
    assert_eq!(pool.pool.revision(), if swapped { 2 } else { 1 });
    assert_eq!(
        pool.pool.reserves(),
        if swapped {
            [1_100_000, 55]
        } else {
            [1_000_000, 60]
        }
    );
    assert_eq!(pool.pool.lp_supply(), 7745); // floor(sqrt(1_000_000 * 60))
    assert_eq!(state.blch_lp_position(&pool.pool.id(), &key(1)), 6745);
    assert_eq!(
        pool.pool.lp_supply() - state.blch_lp_position(&pool.pool.id(), &key(1)),
        bloch_euvm::ustav::amm::MINIMUM_LIQUIDITY
    );
    let asset = state.paired_reserves[&pool.reserve].asset;
    assert_eq!(state.native.gateway().native().supply(&asset), Some(100));
    let liabilities = state.native.gateway().liabilities(&asset).unwrap();
    assert_eq!(liabilities.native_supply, 100);
    assert_eq!(liabilities.imported, 100);
    assert_eq!(liabilities.burned, 0);
    let owned: u64 = state
        .native
        .gateway()
        .native()
        .snapshot()
        .outputs
        .iter()
        .filter(|(point, output)| output.asset == asset && output.output.owner == key(1) && !state.paired_locks.contains_key(point) && !state.native.is_locked(point))
        .map(|(_, output)| output.output.amount)
        .sum();
    assert_eq!(owned, if swapped { 45 } else { 40 }); // Exact output 5 satisfies signed minimum 5.
    assert_eq!(owned + pool.pool.reserves()[1], 100);
    assert!(
        u128::from(pool.pool.reserves()[0]) * u128::from(pool.pool.reserves()[1]) >= 60_000_000
    );
}
