use super::super::tests::{BoundVerifier, DOMAIN};
use super::*;

fn fixtures() -> Vec<(State, Request)> {
    let (a, ar) = paired_custody::tests::setup();
    let (b, br) = initial_liquidity::tests::funded();
    let (c, cr) = add_liquidity::tests::fixture();
    let (d, dr) = initial_liquidity::tests::swap_fixture();
    let (e, er) = initial_liquidity::tests::remove_fixture();
    let (f, fr) = paired_custody::funded_close();
    vec![
        (a, Request::CreatePair(ar)),
        (b, Request::Initialize(br)),
        (c, Request::Add(cr)),
        (d, Request::Swap(dr)),
        (e, Request::Remove(er)),
        (f, Request::ClosePair(fr)),
    ]
}

#[test]
fn all_operations_preserve_direct_execution_fees_and_replay_protection() {
    for (mut state, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        assert_eq!(
            encode(&decode(&bytes, &DOMAIN).unwrap(), &DOMAIN).unwrap(),
            bytes
        );
        let charge = quote_encoded(&state, &bytes).unwrap();
        assert_eq!(charge.tx_bytes, bytes.len() as u64);
        let mut direct = state.clone();
        let fee = match &r {
            Request::Gateway(r) => {
                direct
                    .execute_gateway(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::CreatePair(r) => {
                direct
                    .execute_paired_custody(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Initialize(r) => {
                direct
                    .execute_initial_liquidity(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Add(r) => {
                direct
                    .execute_blch_add(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Swap(r) => {
                direct
                    .execute_blch_swap(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::Remove(r) => {
                direct
                    .execute_blch_remove(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
            Request::ClosePair(r) => {
                direct
                    .execute_paired_close(r, 1, &BoundVerifier, &BoundVerifier)
                    .unwrap()
                    .charge
            }
        };
        assert_eq!(charge.gas, fee.gas);
        assert_eq!(charge.base_fee_sat, fee.base_fee_sat);
        apply_encoded(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).unwrap();
        assert_eq!(state.state_root(), direct.state_root());
        assert_eq!(state.fee_escrow(), direct.fee_escrow());
        let root = state.state_root();
        assert!(apply_encoded(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn every_truncated_prefix_and_trailing_byte_rejects_atomically() {
    for (mut state, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        let root = state.state_root();
        for end in 0..bytes.len() {
            assert!(
                apply_encoded(&mut state, &bytes[..end], 1, &BoundVerifier, &BoundVerifier)
                    .is_err(),
                "prefix {end}"
            );
            assert_eq!(state.state_root(), root);
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode(&trailing, &DOMAIN),
            Err(Error::TrailingBytes)
        ));
    }
}

#[test]
fn hostile_headers_domains_and_lengths_are_bounded() {
    for (_, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        let length_offset = if matches!(r, Request::Initialize(_)) {
            124
        } else {
            58
        };
        for (offset, data) in [
            (0, b"UNKNOWN!".to_vec()),
            (8, 0u16.to_le_bytes().to_vec()),
            (10, vec![0; 32]),
            (length_offset, u64::MAX.to_le_bytes().to_vec()),
            (length_offset + 9, u32::MAX.to_le_bytes().to_vec()),
            (length_offset + 13, u32::MAX.to_le_bytes().to_vec()),
        ] {
            let mut bad = bytes.clone();
            bad[offset..offset + data.len()].copy_from_slice(&data);
            assert!(decode(&bad, &DOMAIN).is_err());
        }
        assert!(matches!(decode(&bytes, &[99; 32]), Err(Error::WrongDomain)));
        if length_offset == 58 {
            let base_len = u64::from_le_bytes(bytes[58..66].try_into().unwrap()) as usize;
            let native_offset = 66 + base_len;
            let mut bad = bytes.clone();
            bad[native_offset..native_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(matches!(decode(&bad, &DOMAIN), Err(Error::TooLarge)));
            let mut bad = bytes.clone();
            bad[native_offset + 8 + 11] ^= 1;
            assert!(decode(&bad, &DOMAIN).is_err());
            if matches!(r, Request::Remove(_)) {
                let native_len =
                    u64::from_le_bytes(bytes[native_offset..native_offset + 8].try_into().unwrap())
                        as usize;
                let owner_offset = native_offset + 8 + native_len + 32;
                for length in [0, MAX_BASE_WITNESS_BYTES as u64 + 1, u64::MAX] {
                    let mut bad = bytes.clone();
                    bad[owner_offset..owner_offset + 8].copy_from_slice(&length.to_le_bytes());
                    assert!(decode(&bad, &DOMAIN).is_err());
                }
                let mut old = bytes.clone();
                old[8..10].copy_from_slice(&1u16.to_le_bytes());
                assert!(matches!(decode(&old, &DOMAIN), Err(Error::InvalidVersion)));
            }
        }
    }
}

#[test]
fn canonical_intent_tampering_and_expiry_never_change_state() {
    for (mut state, r) in fixtures() {
        let bytes = encode(&r, &DOMAIN).unwrap();
        let root = state.state_root();
        assert!(apply_encoded(&mut state, &bytes, 101, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
        let offset = if matches!(r, Request::Initialize(_)) {
            106
        } else {
            42
        };
        let mut tampered = bytes.clone();
        tampered[offset] ^= 1;
        assert!(decode(&tampered, &DOMAIN).is_ok());
        assert!(apply_encoded(&mut state, &tampered, 1, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn creation_frame_stays_compatible_with_existing_transport() {
    let (_, request) = paired_custody::tests::setup();
    let old = paired_custody::wire::encode(&request, &DOMAIN).unwrap();
    assert_eq!(encode(&Request::CreatePair(request), &DOMAIN).unwrap(), old);
    assert!(matches!(decode(&old, &DOMAIN), Ok(Request::CreatePair(_))));
}

#[test]
fn unsigned_intents_can_decode_but_cannot_execute() {
    for (mut state, mut request) in fixtures() {
        let blch = match &mut request {
            Request::CreatePair(r) => &mut r.blch,
            Request::Initialize(r) => &mut r.blch,
            Request::Add(r) => &mut r.blch,
            Request::Swap(r) => &mut r.blch,
            Request::Remove(r) => &mut r.blch,
            Request::ClosePair(r) => &mut r.blch,
            Request::Gateway(r) => &mut r.blch,
        };
        let PosTransaction::TransferV2 { keys, .. } = blch else {
            panic!("fixture must use TransferV2");
        };
        keys[0].signature.clear();
        let bytes = encode(&request, &DOMAIN).unwrap();
        assert!(decode(&bytes, &DOMAIN).is_ok());
        let root = state.state_root();
        assert!(apply_encoded(&mut state, &bytes, 1, &BoundVerifier, &BoundVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
}

#[test]
fn decoded_intent_preserves_all_lifecycle_fields_and_executor_authorizations() {
    use super::super::pool_intent::{DecodedIntent, Operation};
    let operations = [
        Operation::CreatePair,
        Operation::Initialize,
        Operation::Add,
        Operation::Swap,
        Operation::Remove,
        Operation::ClosePair,
    ];
    for ((_, request), operation) in fixtures().into_iter().zip(operations) {
        let mut bytes = encode(&request, &DOMAIN).unwrap();
        let intent = DecodedIntent::decode(&bytes, &DOMAIN).unwrap();
        assert_eq!(intent.operation(), operation);
        assert_eq!(intent.domain(), DOMAIN);
        assert_eq!(encode(intent.request(), &DOMAIN).unwrap(), bytes);
        let hash = match request {
            Request::Gateway(r) => r.authorization(&DOMAIN),
            Request::CreatePair(r) => r.authorization(&DOMAIN),
            Request::Initialize(r) => r.authorization(&DOMAIN),
            Request::Add(r) => r.authorization(&DOMAIN),
            Request::Swap(r) => r.authorization(&DOMAIN),
            Request::Remove(r) => r.authorization(&DOMAIN),
            Request::ClosePair(r) => r.authorization(&DOMAIN),
        }
        .unwrap();
        assert_eq!(intent.authorization(), hash);
        assert!(intent.matches_packet(&bytes));
        let retained = bytes.clone();
        bytes[0] ^= 1;
        assert!(!intent.matches_packet(&bytes));
        assert_eq!(intent.canonical_bytes(), retained);
        assert_eq!(
            intent.packet_hash(),
            DecodedIntent::decode(&retained, &DOMAIN)
                .unwrap()
                .packet_hash()
        );
    }
}

#[test]
fn decoded_intent_refuses_wrong_domain_truncation_trailing_and_oversized_packets() {
    use super::super::pool_intent::DecodedIntent;
    for (_, request) in fixtures() {
        let bytes = encode(&request, &DOMAIN).unwrap();
        assert!(DecodedIntent::decode(&bytes, &[0; 32]).is_err());
        assert!(DecodedIntent::decode(&bytes, &[99; 32]).is_err());
        for end in 0..bytes.len() {
            assert!(DecodedIntent::decode(&bytes[..end], &DOMAIN).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(DecodedIntent::decode(&trailing, &DOMAIN).is_err());
    }
    assert!(DecodedIntent::decode(&vec![0; MAX_ENVELOPE_BYTES as usize + 1], &DOMAIN).is_err());
}

#[test]
fn decoded_intent_distinguishes_signed_intent_from_witness_packet_identity() {
    use super::super::pool_intent::DecodedIntent;
    let (_, request) = initial_liquidity::tests::swap_fixture();
    let original = encode(&Request::Swap(request.clone()), &DOMAIN).unwrap();
    let intent = DecodedIntent::decode(&original, &DOMAIN).unwrap();
    let mut changed = request.clone();
    if let PosTransaction::TransferV2 { keys, .. } = &mut changed.blch {
        keys[0].signature[0] ^= 1;
    }
    let altered = encode(&Request::Swap(changed), &DOMAIN).unwrap();
    let forged = DecodedIntent::decode(&altered, &DOMAIN).unwrap();
    // Decode accepts a structurally valid forged witness, never blesses it.
    assert_eq!(intent.authorization(), forged.authorization());
    assert_ne!(intent.packet_hash(), forged.packet_hash());
    assert!(!intent.matches_packet(&altered));
    let mut changed = request;
    changed.quote.minimum_out += 1;
    let altered = encode(&Request::Swap(changed), &DOMAIN).unwrap();
    let different_trade = DecodedIntent::decode(&altered, &DOMAIN).unwrap();
    assert_ne!(intent.authorization(), different_trade.authorization());
    assert_ne!(intent.packet_hash(), different_trade.packet_hash());
}

fn review_payer(request: &Request) -> Vec<u8> {
    let base = match request {
        Request::Gateway(r) => &r.blch,
        Request::CreatePair(r) => &r.blch,
        Request::Initialize(r) => &r.blch,
        Request::Add(r) => &r.blch,
        Request::Swap(r) => &r.blch,
        Request::Remove(r) => &r.blch,
        Request::ClosePair(r) => &r.blch,
    };
    let PosTransaction::TransferV2 { keys, .. } = base else {
        unreachable!()
    };
    keys[0].pubkey.clone()
}

#[test]
fn funding_review_matches_execution_charge_and_preserves_state_for_all_pool_operations() {
    use super::super::pool_review::FundingReview;
    for (state, request) in fixtures() {
        let payer = review_payer(&request);
        let bytes = encode(&request, &DOMAIN).unwrap();
        let root = state.state_root();
        let review = FundingReview::prepare(&state, &bytes, &payer, 1).unwrap();
        assert_eq!(review.state_root(), root);
        assert_eq!(review.height(), 1);
        assert_eq!(review.payer(), payer);
        assert!(review.funding_sats() > 0);
        let expected = quote_encoded(&state, &bytes).unwrap();
        assert_eq!(review.charge().gas, expected.gas);
        assert_eq!(review.charge().base_fee_sat, expected.base_fee_sat);
        assert_eq!(review.charge().priority_fee_sat, expected.priority_fee_sat);
        let deadline = review.valid_until();
        // Expiry is an inclusive chain height, not a wall-clock deadline.
        let intent = review.finish(&state, &payer, deadline, &bytes).unwrap();
        assert!(intent.matches_packet(&bytes));
        assert_eq!(state.state_root(), root);
        let mut executed = state.clone();
        apply_encoded(&mut executed, &bytes, 1, &BoundVerifier, &BoundVerifier).unwrap();
        assert_eq!(
            executed.fee_escrow().0 - state.fee_escrow().0,
            expected.base_fee_sat
        );
        assert_eq!(
            executed.fee_escrow().1 - state.fee_escrow().1,
            expected.priority_fee_sat
        );
    }
}

#[test]
fn funding_review_refuses_changed_context_expiry_and_height_regression() {
    use super::super::pool_review::{Error as ReviewError, FundingReview};
    for (state, request) in fixtures() {
        let payer = review_payer(&request);
        let bytes = encode(&request, &DOMAIN).unwrap();
        let prepare = || FundingReview::prepare(&state, &bytes, &payer, 2).unwrap();
        assert!(matches!(
            prepare().finish(&state, &[99; 32], 2, &bytes),
            Err(ReviewError::AccountChanged)
        ));
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert!(matches!(
            prepare().finish(&state, &payer, 2, &changed),
            Err(ReviewError::PacketChanged)
        ));
        assert!(matches!(
            prepare().finish(&state, &payer, 1, &bytes),
            Err(ReviewError::HeightRegressed)
        ));
        let deadline = prepare().valid_until();
        assert!(matches!(
            prepare().finish(&state, &payer, deadline + 1, &bytes),
            Err(ReviewError::Expired)
        ));
        assert!(matches!(
            FundingReview::prepare(&state, &bytes, &payer, deadline + 1),
            Err(ReviewError::Expired)
        ));
        let mut advanced = state.clone();
        apply_encoded(&mut advanced, &bytes, 2, &BoundVerifier, &BoundVerifier).unwrap();
        assert!(matches!(
            prepare().finish(&advanced, &payer, 2, &bytes),
            Err(ReviewError::StateChanged)
        ));
    }
}

#[test]
fn funding_review_binds_actual_payer_coins_and_excludes_locked_reserve_value() {
    use super::super::pool_review::{Error as ReviewError, FundingReview};
    let (state, request) = initial_liquidity::tests::swap_fixture();
    let bytes = encode(&Request::Swap(request.clone()), &DOMAIN).unwrap();
    let payer = review_payer(&Request::Swap(request.clone()));
    assert!(matches!(
        FundingReview::prepare(&state, &bytes, &[99; 32], 1),
        Err(ReviewError::UnsupportedPayer)
    ));
    let review = FundingReview::prepare(&state, &bytes, &payer, 1).unwrap();
    let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &request.blch
    else {
        unreachable!()
    };
    let mut own = 0u128;
    let mut reserves = 0u128;
    for input in inputs {
        let value = u128::from(state.base().utxo(&input.txid, input.vout).unwrap().value);
        if state.base_is_locked(&(input.txid, input.vout)) {
            reserves += value;
        } else {
            own += value;
        }
    }
    assert!(reserves > 0);
    assert_eq!(review.funding_sats(), own);
    assert!(review.funding_sats() < own + reserves);
    assert_eq!(
        review.wallet_outputs_sats(),
        outputs[1..]
            .iter()
            .map(|o| u128::from(o.value))
            .sum::<u128>()
    );
    let mut unaffordable = request.clone();
    if let PosTransaction::TransferV2 {
        tip_millisat_per_gas,
        ..
    } = &mut unaffordable.blch
    {
        *tip_millisat_per_gas = fee_market::MAX_TIP_MILLISAT_PER_GAS;
    }
    let expensive = encode(&Request::Swap(unaffordable), &DOMAIN).unwrap();
    assert!(matches!(
        FundingReview::prepare(&state, &expensive, &payer, 1),
        Err(ReviewError::InvalidFunding)
    ));
    let mut wrong_pool = request.clone();
    wrong_pool.quote.pool = [255; 32];
    let unknown = encode(&Request::Swap(wrong_pool), &DOMAIN).unwrap();
    assert!(matches!(
        FundingReview::prepare(&state, &unknown, &payer, 1),
        Err(ReviewError::InvalidFunding)
    ));
    for mode in 0..5 {
        let mut bad = request.clone();
        let PosTransaction::TransferV2 { keys, inputs, .. } = &mut bad.blch else {
            unreachable!()
        };
        let i = inputs.iter().position(|i| i.key_index == 0).unwrap();
        match mode {
            0 => inputs.push(inputs[i].clone()),
            1 => inputs[i].txid = [255; 32],
            2 => inputs[i].key_index = super::super::base_reserves::RESERVE_KEY_INDEX,
            3 => keys[0].pubkey = vec![99; payer.len()],
            _ => inputs.retain(|i| i.key_index != 0),
        }
        let bad_payer = keys[0].pubkey.clone();
        let bytes = encode(&Request::Swap(bad), &DOMAIN).unwrap();
        assert!(
            matches!(
                FundingReview::prepare(&state, &bytes, &bad_payer, 1),
                Err(ReviewError::InvalidFunding)
            ),
            "mode {mode}"
        );
    }
}

#[test]
fn funding_review_honors_inner_deadline_and_refuses_conflicting_expiry() {
    use super::super::pool_review::{Error as ReviewError, FundingReview};
    let (state, mut request) = initial_liquidity::tests::swap_fixture();
    let payer = review_payer(&Request::Swap(request.clone()));
    request.native.transaction.valid_until = 3;
    let bytes = encode(&Request::Swap(request.clone()), &DOMAIN).unwrap();
    let review = FundingReview::prepare(&state, &bytes, &payer, 3).unwrap();
    assert_eq!(review.valid_until(), 3);
    assert!(matches!(
        review.finish(&state, &payer, 4, &bytes),
        Err(ReviewError::Expired)
    ));
    request.native.transaction.valid_until = request.quote.valid_until + 1;
    let bytes = encode(&Request::Swap(request), &DOMAIN).unwrap();
    assert!(matches!(
        FundingReview::prepare(&state, &bytes, &payer, 1),
        Err(ReviewError::InvalidExpiry)
    ));
}
