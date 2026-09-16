use super::lifecycle::*;
use super::*;
use bloch_pos_committee::transition::native_dex::lab_quote::{Operation, Query};
#[test]
fn live_builder_create_initialize_swap_sign_with_real_hybrid() {
    let (mut state, bytes, _) = fixture();
    let PosTransaction::NativePool(p) = PosTransaction::from_canonical_bytes(&bytes).unwrap()
    else {
        panic!()
    };
    let pool_wire::Request::CreatePair(r) = pool_wire::decode(p.as_bytes(), &DOMAIN).unwrap()
    else {
        panic!()
    };
    let asset = r.native.transaction.asset;
    let seed = r.seed;
    let reserve = base_reserves::reserve_id(&DOMAIN, &seed, &key()).unwrap();
    let mut operations = vec![
        Operation::CreatePair {
            asset,
            seed,
            blch_amount: 1_000_000,
            native_amount: 60,
        },
        Operation::Initialize {
            reserve,
            fee_bps: 30,
            minimum_lp: 1,
        },
    ];
    for operation in operations.drain(..) {
        execute(&mut state, operation);
    }
    let pool = state.blch_pool_for_reserve(&reserve).unwrap().id();
    execute(
        &mut state,
        Operation::Swap {
            pool,
            input_asset: bloch_euvm::BLCH,
            amount: 100_000,
            minimum_out: 5,
        },
    );
    assert_eq!(state.blch_pool(&pool).unwrap().reserves(), [1_100_000, 55]);
    for (owner, valid_until) in [
        (vec![], 100),
        (vec![1; 8193], 100),
        (key(), 1),
        (key(), 130),
    ] {
        assert!(state
            .lab_build(
                &Query {
                    owner,
                    valid_until,
                    operation: Operation::Swap {
                        pool,
                        input_asset: bloch_euvm::BLCH,
                        amount: 100_000,
                        minimum_out: 1
                    }
                },
                1
            )
            .is_err());
    }
    let reverse = |amount, minimum_out| Query {
        owner: key(),
        valid_until: 100,
        operation: Operation::Swap {
            pool,
            input_asset: asset,
            amount,
            minimum_out,
        },
    };
    // The locked 55-unit reserve would cover 50, but the free coins (40 and 5)
    // cannot cover it individually. Never select the paired reserve as funding.
    assert_eq!(
        state.lab_build(&reverse(50, 1), 1).err(),
        Some("no sufficient spendable native output")
    );
    assert!(state.lab_build(&reverse(3, 56735), 1).is_err());
    let built = state.lab_build(&reverse(3, 56734), 1).unwrap();
    let PosTransaction::NativePool(p) =
        PosTransaction::from_canonical_bytes(&built.transaction).unwrap()
    else {
        panic!()
    };
    let pool_wire::Request::Swap(r) = pool_wire::decode(p.as_bytes(), &DOMAIN).unwrap() else {
        panic!()
    };
    let locked = state.paired_custody(&reserve).unwrap().outpoint;
    assert_eq!(r.native.transaction.inputs.len(), 2);
    assert!(r.native.transaction.inputs.windows(2).all(|p| p[0] < p[1]));
    for (point, witness) in r
        .native
        .transaction
        .inputs
        .iter()
        .zip(&r.native.witnesses.owners)
    {
        if *point == locked {
            assert!(witness.is_empty())
        } else {
            assert_eq!(
                state
                    .native()
                    .spendable_output(point)
                    .unwrap()
                    .output
                    .amount,
                5
            );
            assert_eq!(witness.len(), 4593);
        }
    }
    assert_eq!(
        r.native
            .transaction
            .outputs
            .iter()
            .map(|o| o.amount)
            .collect::<Vec<_>>(),
        vec![58, 2]
    );
    // Full consumption omits a zero-valued native change output.
    let exact = state.lab_build(&reverse(5, 91414), 1).unwrap();
    let PosTransaction::NativePool(p) =
        PosTransaction::from_canonical_bytes(&exact.transaction).unwrap()
    else {
        panic!()
    };
    let pool_wire::Request::Swap(r) = pool_wire::decode(p.as_bytes(), &DOMAIN).unwrap() else {
        panic!()
    };
    assert_eq!(r.native.transaction.outputs.len(), 1);
    let mut exact_state = state.clone();
    execute(&mut exact_state, reverse(5, 91414).operation);
    assert_eq!(
        exact_state.blch_pool(&pool).unwrap().reserves(),
        [1_008_586, 60]
    );
    let owner_script: [u8; 32] = Sha3_256::digest(key()).into();
    let wallet_balance = |s: &State| {
        s.base()
            .utxos()
            .filter(|u| u.script_hash == owner_script)
            .map(|u| u128::from(u.value))
            .sum::<u128>()
    };
    let before = wallet_balance(&state);
    let lp_before = state.blch_lp_position(&pool, &key());
    execute(&mut state, reverse(3, 56734).operation);
    assert_eq!(state.blch_pool(&pool).unwrap().reserves(), [1_043_266, 58]);
    assert_eq!(wallet_balance(&state), before + 56734 - built.fee_sat);
    assert_eq!(state.blch_lp_position(&pool, &key()), lp_before);
    assert_eq!(state.native().gateway().native().supply(&asset), Some(100));
}
fn execute(state: &mut State, operation: Operation) {
    let quote = state
        .lab_build(
            &Query {
                owner: key(),
                valid_until: 100,
                operation,
            },
            1,
        )
        .unwrap();
    let mut session = Session::open(&SEED, DOMAIN).unwrap();
    let review = session.prepare(state, &quote.transaction, 1).unwrap();
    assert_eq!(review.fee_sat, quote.fee_sat);
    let signed = session
        .sign(review.id, state, &quote.transaction, 1, true)
        .unwrap();
    let PosTransaction::NativePool(p) = PosTransaction::from_canonical_bytes(&signed).unwrap()
    else {
        panic!()
    };
    pool_wire::apply_encoded(state, p.as_bytes(), 1, &Hybrid, &Hybrid).unwrap();
    *state = state.clone().fixture_review_projection();
}
