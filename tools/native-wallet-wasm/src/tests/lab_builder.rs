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
    assert!(state
        .lab_build(
            &Query {
                owner: key(),
                valid_until: 100,
                operation: Operation::Swap {
                    pool,
                    input_asset: asset,
                    amount: 1,
                    minimum_out: 1
                }
            },
            1
        )
        .is_err());
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
