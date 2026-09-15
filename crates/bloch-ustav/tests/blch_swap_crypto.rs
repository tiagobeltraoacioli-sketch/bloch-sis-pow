//! Real PQ atomic swaps against sealed BLCH/native reserves; local rehearsal only.
//! No block activation, mainnet funds or real external USDT backing.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::{
    gateway::pools::PoolLedger, transfer_wire, Output, Registration, Transaction, Verifier,
    Witnesses,
};
use bloch_euvm::Val;
use bloch_pos_committee::header::BlockHeaderV4;
use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
use bloch_pos_committee::transition::native_dex::pool_wire;
use bloch_pos_committee::transition::native_dex::State;
use bloch_pos_committee::transition::{
    CommittedState, PosTransaction, TransferInputV2, TransferOutput, WitnessKey,
};
use bloch_pos_committee::{BlockId, SignatureVerifier, StateReader};
use bloch_ustav::BlochVerifier;
use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;
const DOMAIN: [u8; 32] = [121; 32];
const GAS: u64 = 1_000_000;
const COIN: u64 = 100_000_000;
type Keys = (Vec<u8>, Vec<u8>);
fn identities() -> &'static [Keys; 3] {
    static KEYS: OnceLock<[Keys; 3]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            crypto::generate_keypair_from_seed(&[122; 32]).unwrap(),
            crypto::generate_keypair_from_seed(&[123; 32]).unwrap(),
            crypto::generate_keypair_from_seed(&[124; 32]).unwrap(),
        ]
    })
}
fn signature(message: &[u8], secret: &[u8]) -> Vec<u8> {
    crypto::sign(secret, message).unwrap()
}
struct BaseVerifier;
impl SignatureVerifier for BaseVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        BlochVerifier.verify_pq(root, key, sig)
    }
}
fn base_state() -> CommittedState {
    let id = BlockId::of(&BlockHeaderV4 {
        version: bloch_pos_committee::transition::BLOCK_VERSION_V4,
        parent: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0; 32],
        randao_mix: [7; 32],
        justified_root: [0; 32],
        finalized_root: [0; 32],
        attestation_root: [0; 32],
        coherence_root: [0; 32],
    });
    CommittedState::genesis_with_network_domain(
        DOMAIN,
        id,
        [7; 32],
        &[],
        &[],
        [0; 32],
        [0; 32],
        [0; 32],
        EvmCommitment {
            account_root: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            base_fee_per_gas: 0,
        },
        &[
            EutxoEntry {
                txid: [9; 32],
                vout: 0,
                value: COIN,
                script_hash: Sha3_256::digest(&identities()[2].0).into(),
            },
            EutxoEntry {
                txid: [8; 32],
                vout: 0,
                value: COIN,
                script_hash: Sha3_256::digest(identities()[0].0.clone()).into(),
            },
        ],
    )
}

fn funded_state() -> (State, transfer_wire::Envelope, bloch_euvm::ustav::OutPoint) {
    let base = base_state();
    let mut native = PoolLedger::new(DOMAIN);
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"PAIRED-CUSTODY-TEST".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1_000_000,
                issuer_pubkey: identities()[1].0.clone(),
            })],
        },
        nonce: [31; 32],
        initial_kyc_root: None,
    };
    let sig = signature(
        &registration.signing_hash(&DOMAIN).unwrap(),
        &identities()[1].1,
    );
    let asset = native
        .register(registration, &sig, &BlochVerifier, GAS)
        .unwrap();
    let mint = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![
            Output {
                owner: identities()[2].0.clone(),
                amount: 100_000,
            },
            Output {
                owner: identities()[0].0.clone(),
                amount: 100_000,
            },
        ],
        delta: 200_000,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let w = Witnesses {
        modules: vec![vec![Val::Bytes(signature(
            &mint.signing_hash(&DOMAIN).unwrap(),
            &identities()[1].1,
        ))]],
        ..Witnesses::default()
    };
    let receipt = native.apply(&mint, &w, 1, &BlochVerifier, GAS).unwrap();
    let envelope = transfer_wire::Envelope {
        domain: DOMAIN,
        transaction: Transaction {
            inputs: vec![receipt.outputs[1]],
            outputs: vec![
                Output {
                    owner: identities()[0].0.clone(),
                    amount: 60_000,
                },
                Output {
                    owner: identities()[0].0.clone(),
                    amount: 40_000,
                },
            ],
            delta: 0,
            ..mint
        },
        witnesses: Witnesses {
            owners: vec![vec![0; 5500]],
            modules: vec![vec![]],
            eligibility: vec![],
        },
    };
    let state = State::from_parts(
        base.clone(),
        native.clone(),
        base.state_root(),
        native.state_root(),
    )
    .unwrap();
    (state, envelope, receipt.outputs[0])
}

use bloch_pos_committee::transition::native_dex::base_reserves::{reserve_id, reserve_script};
use bloch_pos_committee::transition::native_dex::paired_custody::Request;
const SEED: [u8; 32] = [32; 32];
const BASE_RESERVE: u64 = 10_000_000;

fn fixture() -> (State, Request, bloch_euvm::ustav::OutPoint) {
    let (state, native, trader_native) = funded_state();
    let owner = identities()[0].0.clone();
    let id = reserve_id(&DOMAIN, &SEED, &owner).unwrap();
    let mut request = Request {
        seed: SEED,
        blch_amount: BASE_RESERVE,
        native_amount: 60_000,
        valid_until: 100,
        native_gas: 100_000,
        native,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: owner.clone(),
                signature: vec![0; 5500],
            }],
            inputs: vec![TransferInputV2 {
                txid: [8; 32],
                vout: 0,
                key_index: 0,
            }],
            outputs: vec![
                TransferOutput {
                    value: BASE_RESERVE,
                    script_hash: reserve_script(&DOMAIN, &id),
                },
                TransferOutput {
                    value: 1,
                    script_hash: Sha3_256::digest(&owner).into(),
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
    };
    let length = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = length + 256;
    }
    let charge = state.quote_paired_custody(&request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[1].value =
            COIN - BASE_RESERVE - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    resign(&mut request);
    (state, request, trader_native)
}
fn resign(request: &mut Request) {
    let message = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&message, &identities()[0].1);
    }
    request.native.witnesses.owners[0] = signature(&message, &identities()[0].1);
}

use bloch_euvm::ustav::OutPoint;
use bloch_pos_committee::transition::native_dex::base_reserves::RESERVE_KEY_INDEX;
use bloch_pos_committee::transition::native_dex::{initial_liquidity, swap, swap_quote};

fn initialized() -> (State, [u8; 32], [u8; 32], OutPoint) {
    let (mut state, creation, funding) = fixture();
    let created = state
        .execute_paired_custody(&creation, 2, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let mut init = initial_liquidity::Request {
        reserve: created.reserve.id,
        creation_authorization: created.authorization,
        fee_bps: 30,
        minimum_lp: 1,
        valid_until: 100,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: identities()[0].0.clone(),
                signature: vec![0; 5500],
            }],
            inputs: vec![TransferInputV2 {
                txid: created.blch_txid,
                vout: 1,
                key_index: 0,
            }],
            outputs: vec![TransferOutput {
                value: 1,
                script_hash: Sha3_256::digest(&identities()[0].0).into(),
            }],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
    };
    let len = init.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut init.blch {
        *tx_bytes = len + 256;
    }
    let fee = state.quote_initial_liquidity(&init).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut init.blch {
        outputs[0].value = state.base().utxo(&created.blch_txid, 1).unwrap().value
            - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
    let auth = init.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut init.blch {
        keys[0].signature = signature(&auth, &identities()[0].1);
    }
    let initialized = state
        .execute_initial_liquidity(&init, 3, &BaseVerifier, &BlochVerifier)
        .unwrap();
    (state, initialized.pool, created.reserve.id, funding)
}

fn swap_request(
    state: &State,
    pool: [u8; 32],
    reserve: [u8; 32],
    base_funding: ([u8; 32], u32),
    native_funding: Option<OutPoint>,
) -> swap::Request {
    let base = state.base_reserve(&reserve).unwrap();
    let native = state.paired_custody(&reserve).unwrap();
    let pool_state = state.blch_pool(&pool).unwrap();
    let native_input = native_funding.is_some();
    let quote_request = swap_quote::Request {
        domain: DOMAIN,
        pool,
        revision: pool_state.revision(),
        input_asset: if native_input {
            native.asset
        } else {
            bloch_euvm::BLCH
        },
        amount: if native_input { 1_000 } else { 100_000 },
        minimum_out: 1,
        valid_until: 100,
    };
    let quote = state.quote_blch_swap(&quote_request, 4).unwrap();
    let trader = identities()[2].0.clone();
    let trader_hash = Sha3_256::digest(&trader).into();
    let mut base_outputs = vec![TransferOutput {
        value: if native_input {
            base.amount - quote.amount_out
        } else {
            base.amount + quote_request.amount
        },
        script_hash: reserve_script(&DOMAIN, &reserve),
    }];
    if native_input {
        base_outputs.push(TransferOutput {
            value: quote.amount_out,
            script_hash: trader_hash,
        });
    }
    base_outputs.push(TransferOutput {
        value: 1,
        script_hash: trader_hash,
    });
    let mut inputs = vec![native.outpoint];
    let mut outputs = vec![Output {
        owner: identities()[0].0.clone(),
        amount: if native_input {
            native.amount + quote_request.amount
        } else {
            native.amount - quote.amount_out
        },
    }];
    if let Some(point) = native_funding {
        inputs.push(point);
        outputs.push(Output {
            owner: trader.clone(),
            amount: state
                .native()
                .gateway()
                .native()
                .output(&point)
                .unwrap()
                .output
                .amount
                - quote_request.amount,
        });
    } else {
        outputs.push(Output {
            owner: trader.clone(),
            amount: quote.amount_out,
        });
    }
    inputs.sort();
    let owners = inputs
        .iter()
        .map(|point| {
            if *point == native.outpoint {
                vec![]
            } else {
                vec![0; 5500]
            }
        })
        .collect();
    let mut request = swap::Request {
        quote: quote_request,
        pool_state_root: quote.pool_state_root,
        native_gas: 100_000,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: trader,
                signature: vec![0; 5500],
            }],
            inputs: vec![
                TransferInputV2 {
                    txid: base.outpoint.0,
                    vout: base.outpoint.1,
                    key_index: RESERVE_KEY_INDEX,
                },
                TransferInputV2 {
                    txid: base_funding.0,
                    vout: base_funding.1,
                    key_index: 0,
                },
            ],
            outputs: base_outputs,
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                asset: native.asset,
                inputs,
                outputs,
                delta: 0,
                mint_nonce: 0,
                policy_revision: 0,
                valid_until: 100,
            },
            witnesses: Witnesses {
                owners,
                modules: vec![vec![]],
                eligibility: vec![],
            },
        },
    };
    let len = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = len + 256;
    }
    let charge = state.quote_blch_swap_fee(&request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs.last_mut().unwrap().value = state
            .base()
            .utxo(&base_funding.0, base_funding.1)
            .unwrap()
            .value
            - (charge.base_fee_sat + charge.priority_fee_sat) as u64
            - if native_input {
                0
            } else {
                request.quote.amount
            };
    }
    sign_swap(&mut request);
    request
}
fn sign_swap(request: &mut swap::Request) {
    // Exercise the future wallet's immutable decoding path with real PQ signing.
    use bloch_pos_committee::transition::native_dex::{pool_intent, pool_wire};
    let bytes = pool_wire::encode(&pool_wire::Request::Swap(request.clone()), &DOMAIN).unwrap();
    let intent = pool_intent::DecodedIntent::decode(&bytes, &DOMAIN).unwrap();
    assert_eq!(intent.operation(), pool_intent::Operation::Swap);
    let hash = intent.authorization();
    assert_eq!(hash, request.authorization(&DOMAIN).unwrap());
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&hash, &identities()[2].1);
    }
    for witness in &mut request.native.witnesses.owners {
        if !witness.is_empty() {
            *witness = signature(&hash, &identities()[2].1);
        }
    }
}
fn reject_swap(state: &mut State, request: &swap::Request) {
    let root = state.state_root();
    let base = state.base().clone();
    let native = state.native().snapshot();
    let fees = state.fee_escrow();
    assert!(state
        .execute_blch_swap(request, 4, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.base(), &base);
    assert_eq!(state.native().snapshot(), native);
    assert_eq!(state.fee_escrow(), fees);
}

#[test]
fn stranger_trader_swaps_both_directions_without_pool_owner_signature() {
    let (mut state, pool, reserve, native_funding) = initialized();
    let lp = state.blch_lp_position(&pool, &identities()[0].0);
    let supply = state
        .native()
        .gateway()
        .native()
        .supply(&state.paired_custody(&reserve).unwrap().asset);
    let first = swap_request(&state, pool, reserve, ([9; 32], 0), None);
    assert!(first.native.witnesses.owners[0].is_empty());
    let expected = state.quote_blch_swap(&first.quote, 4).unwrap();
    let mut encoded_state = state.clone();
    let frame = pool_wire::encode(&pool_wire::Request::Swap(first.clone()), &DOMAIN).unwrap();
    pool_wire::apply_encoded(&mut encoded_state, &frame, 4, &BaseVerifier, &BlochVerifier).unwrap();
    let receipt = state
        .execute_blch_swap(&first, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(encoded_state.state_root(), state.state_root());
    assert_eq!(encoded_state.fee_escrow(), state.fee_escrow());
    assert_eq!(receipt.quote, expected);
    assert_eq!(
        state.blch_pool(&pool).unwrap().reserves(),
        expected.reserves_after
    );
    assert_eq!(state.blch_pool(&pool).unwrap().revision(), 2);
    assert!(state.base().utxo(&[9; 32], 0).is_none());
    reject_swap(&mut state, &first);
    let second = swap_request(
        &state,
        pool,
        reserve,
        (receipt.blch_txid, 1),
        Some(native_funding),
    );
    let expected = state.quote_blch_swap(&second.quote, 4).unwrap();
    let second_receipt = state
        .execute_blch_swap(&second, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(second_receipt.quote, expected);
    assert_eq!(
        state
            .base()
            .utxo(&second_receipt.blch_txid, 1)
            .unwrap()
            .value,
        expected.amount_out
    );
    assert_eq!(state.blch_pool(&pool).unwrap().revision(), 3);
    assert_eq!(
        state.blch_pool(&pool).unwrap().reserves(),
        expected.reserves_after
    );
    assert_eq!(state.blch_lp_position(&pool, &identities()[0].0), lp);
    assert_eq!(state.blch_lp_position(&pool, &identities()[2].0), 0);
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .supply(&second.native.transaction.asset),
        supply
    );
    let base_reserve = state.base_reserve(&reserve).unwrap();
    let native_reserve = state.paired_custody(&reserve).unwrap();
    assert!(state
        .spendable_base_output(&base_reserve.outpoint)
        .is_none());
    assert!(state.native().is_locked(&native_reserve.outpoint));
    assert!(state
        .native()
        .spendable_output(&native_reserve.outpoint)
        .is_none());
    let base_value: u128 = state
        .base()
        .utxos()
        .map(|entry| u128::from(entry.value))
        .sum();
    let (base_fees, tips) = state.fee_escrow();
    assert_eq!(base_value + base_fees + tips, 2 * u128::from(COIN));
    let restored = State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    assert_eq!(restored.state_root(), state.state_root());
    assert_eq!(restored.blch_pool(&pool), state.blch_pool(&pool));
    reject_swap(&mut state, &second);
}

#[test]
fn forged_signatures_theft_slippage_and_stale_roots_reject_atomically() {
    let (mut state, pool, reserve, funding) = initialized();
    let valid = swap_request(&state, pool, reserve, ([9; 32], 0), Some(funding));
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = valid.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
            keys[0].signature[offset] ^= 1;
        }
        reject_swap(&mut state, &bad);
        let mut bad = valid.clone();
        bad.native
            .witnesses
            .owners
            .iter_mut()
            .find(|w| !w.is_empty())
            .unwrap()[offset] ^= 1;
        reject_swap(&mut state, &bad);
    }
    let mut bad = valid.clone();
    let standalone = bad.blch.spend_signing_root();
    if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
        keys[0].signature = signature(&standalone, &identities()[2].1);
    }
    reject_swap(&mut state, &bad);
    let mut bad = valid.clone();
    let standalone = bad.native.transaction.signing_hash(&DOMAIN).unwrap();
    *bad.native
        .witnesses
        .owners
        .iter_mut()
        .find(|w| !w.is_empty())
        .unwrap() = signature(&standalone, &identities()[2].1);
    reject_swap(&mut state, &bad);
    let mut bad = valid.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
        outputs[1].script_hash = Sha3_256::digest(&identities()[1].0).into();
    }
    sign_swap(&mut bad);
    reject_swap(&mut state, &bad);
    let mut bad = valid.clone();
    bad.native.transaction.outputs[0].owner = identities()[2].0.clone();
    sign_swap(&mut bad);
    reject_swap(&mut state, &bad);
    let mut bad = valid.clone();
    bad.quote.minimum_out = u64::MAX;
    sign_swap(&mut bad);
    reject_swap(&mut state, &bad);
    let mut bad = valid.clone();
    bad.pool_state_root[0] ^= 1;
    sign_swap(&mut bad);
    reject_swap(&mut state, &bad);
    state
        .execute_blch_swap(&valid, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
}

#[test]
fn swap_funding_review_binds_real_trader_and_rejects_post_execution_state() {
    use bloch_pos_committee::transition::native_dex::pool_review::{Error, FundingReview};
    let (mut state, pool, reserve, funding) = initialized();
    let request = swap_request(&state, pool, reserve, ([9; 32], 0), Some(funding));
    let payer = &identities()[2].0;
    let bytes = request.canonical_bytes(&DOMAIN).unwrap();
    let review = FundingReview::prepare(&state, &bytes, payer, 4).unwrap();
    let outstanding = FundingReview::prepare(&state, &bytes, payer, 4).unwrap();
    let fee = *review.charge();
    let checked = review.finish(&state, payer, 4, &bytes).unwrap();
    assert_eq!(
        checked.authorization(),
        request.authorization(&DOMAIN).unwrap()
    );
    let receipt = state
        .execute_blch_swap(&request, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(receipt.charge, fee);
    assert!(matches!(
        outstanding.finish(&state, payer, 4, &bytes),
        Err(Error::StateChanged)
    ));
}

#[test]
fn signed_swap_preflight_predicts_execution_without_mutating_state() {
    use bloch_pos_committee::transition::native_dex::pool_submission::SubmissionReview;
    let (mut state, pool, reserve, funding) = initialized();
    let request = swap_request(&state, pool, reserve, ([9; 32], 0), Some(funding));
    let bytes = request.canonical_bytes(&DOMAIN).unwrap();
    let payer = &identities()[2].0;
    let before = state.state_root();
    let review =
        SubmissionReview::prepare(&state, &bytes, payer, 4, &BaseVerifier, &BlochVerifier).unwrap();
    assert_eq!(state.state_root(), before);
    let predicted = review.predicted_root();
    assert_ne!(predicted, before);
    let pool_wire::Receipt::Swap(simulated) = review.receipt() else {
        panic!("wrong receipt")
    };
    let simulated_fee = simulated.charge;
    assert_eq!(simulated_fee, *review.funding().charge());
    let checked = review.finish(&state, payer, 4, &bytes).unwrap();
    assert!(checked.matches_packet(&bytes));
    let actual = state
        .execute_blch_swap(&request, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(actual.charge, simulated_fee);
    assert_eq!(state.state_root(), predicted);
}

#[test]
fn signed_swap_preflight_rejects_bad_signatures_and_execution_constraints() {
    use bloch_pos_committee::transition::native_dex::pool_review::FundingReview;
    use bloch_pos_committee::transition::native_dex::pool_submission::{Error, SubmissionReview};
    let (state, pool, reserve, funding) = initialized();
    let request = swap_request(&state, pool, reserve, ([9; 32], 0), Some(funding));
    let payer = &identities()[2].0;
    let before = state.state_root();
    let mut invalid = Vec::new();
    let mut bad = request.clone();
    if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
        keys[0].signature[0] ^= 1;
    }
    invalid.push(bad);
    let mut bad = request.clone();
    bad.native
        .witnesses
        .owners
        .iter_mut()
        .find(|w| !w.is_empty())
        .unwrap()[0] ^= 1;
    invalid.push(bad);
    let mut bad = request.clone();
    bad.quote.minimum_out = u64::MAX;
    sign_swap(&mut bad);
    invalid.push(bad);
    let mut bad = request;
    bad.pool_state_root[0] ^= 1;
    sign_swap(&mut bad);
    invalid.push(bad);
    for bad in invalid {
        let bytes = bad.canonical_bytes(&DOMAIN).unwrap();
        // Funding inspection alone deliberately accepts these signed envelopes.
        FundingReview::prepare(&state, &bytes, payer, 4).unwrap();
        assert!(matches!(
            SubmissionReview::prepare(&state, &bytes, payer, 4, &BaseVerifier, &BlochVerifier),
            Err(Error::Execution(_))
        ));
        assert_eq!(state.state_root(), before);
    }
}

#[test]
fn signed_swap_preflight_requires_exact_submission_context() {
    use bloch_pos_committee::transition::native_dex::pool_review;
    use bloch_pos_committee::transition::native_dex::pool_submission::{Error, SubmissionReview};
    let (mut state, pool, reserve, funding) = initialized();
    let request = swap_request(&state, pool, reserve, ([9; 32], 0), Some(funding));
    let bytes = request.canonical_bytes(&DOMAIN).unwrap();
    let payer = &identities()[2].0;
    let prepare = || {
        SubmissionReview::prepare(&state, &bytes, payer, 4, &BaseVerifier, &BlochVerifier).unwrap()
    };
    for height in [3, 5, 101] {
        assert!(matches!(
            prepare().finish(&state, payer, height, &bytes),
            Err(Error::HeightChanged)
        ));
    }
    assert!(matches!(
        prepare().finish(&state, &identities()[1].0, 4, &bytes),
        Err(Error::Review(pool_review::Error::AccountChanged))
    ));
    let mut altered = bytes.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert!(matches!(
        prepare().finish(&state, payer, 4, &altered),
        Err(Error::Review(pool_review::Error::PacketChanged))
    ));
    let outstanding = prepare();
    state
        .execute_blch_swap(&request, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert!(matches!(
        outstanding.finish(&state, payer, 4, &bytes),
        Err(Error::Review(pool_review::Error::StateChanged))
    ));
}
