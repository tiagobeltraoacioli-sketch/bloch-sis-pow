//! Real PQ multi-provider liquidity deposits against sealed BLCH/native reserves; local rehearsal only.
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
use bloch_pos_committee::transition::native_dex::{
    add_liquidity, initial_liquidity, remove_liquidity,
};

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

fn remove_request(
    state: &State,
    pool: [u8; 32],
    reserve: [u8; 32],
    funding: ([u8; 32], u32),
    lp: u64,
) -> remove_liquidity::Request {
    let base = state.base_reserve(&reserve).unwrap();
    let native = state.paired_custody(&reserve).unwrap();
    let quote_request = remove_liquidity::QuoteRequest {
        domain: DOMAIN,
        pool,
        revision: state.blch_pool(&pool).unwrap().revision(),
        owner: identities()[2].0.clone(),
        lp,
        minimum: [1, 1],
        valid_until: 100,
    };
    let quote = state.quote_blch_remove(&quote_request, 4).unwrap();
    let owner = identities()[2].0.clone();
    let owner_hash = Sha3_256::digest(&owner).into();
    let mut request = remove_liquidity::Request {
        quote: quote_request,
        pool_state_root: quote.pool_state_root,
        native_gas: 100_000,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: owner.clone(),
                signature: vec![0; 5500],
            }],
            inputs: vec![
                TransferInputV2 {
                    txid: base.outpoint.0,
                    vout: base.outpoint.1,
                    key_index: RESERVE_KEY_INDEX,
                },
                TransferInputV2 {
                    txid: funding.0,
                    vout: funding.1,
                    key_index: 0,
                },
            ],
            outputs: vec![
                TransferOutput {
                    value: quote.reserves_after[0],
                    script_hash: reserve_script(&DOMAIN, &reserve),
                },
                TransferOutput {
                    value: quote.amounts_out[0],
                    script_hash: owner_hash,
                },
                TransferOutput {
                    value: 1,
                    script_hash: owner_hash,
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                asset: native.asset,
                inputs: vec![native.outpoint],
                outputs: vec![
                    Output {
                        owner: identities()[0].0.clone(),
                        amount: quote.reserves_after[1],
                    },
                    Output {
                        owner,
                        amount: quote.amounts_out[1],
                    },
                ],
                delta: 0,
                mint_nonce: 0,
                policy_revision: 0,
                valid_until: 100,
            },
            witnesses: Witnesses {
                owners: vec![vec![0; 5500]],
                modules: vec![vec![]],
                eligibility: vec![],
            },
        },
    };
    let len = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = len + 256;
    }
    let fee = state.quote_blch_remove_fee(&request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[2].value = state.base().utxo(&funding.0, funding.1).unwrap().value
            - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
    sign_remove(&mut request);
    request
}
fn sign_remove(request: &mut remove_liquidity::Request) {
    let auth = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&auth, &identities()[2].1);
    }
    request.native.witnesses.owners[0] = signature(&auth, &identities()[2].1);
}
fn reject_remove(state: &mut State, request: &remove_liquidity::Request) {
    let root = state.state_root();
    let base = state.base().clone();
    let native = state.native().snapshot();
    let fees = state.fee_escrow();
    assert!(state
        .execute_blch_remove(request, 4, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.base(), &base);
    assert_eq!(state.native().snapshot(), native);
    assert_eq!(state.fee_escrow(), fees);
}

fn add_request(
    state: &State,
    pool: [u8; 32],
    reserve: [u8; 32],
    base_funding: ([u8; 32], u32),
    native_funding: OutPoint,
    maximum: [u64; 2],
) -> add_liquidity::Request {
    let base = state.base_reserve(&reserve).unwrap();
    let native = state.paired_custody(&reserve).unwrap();
    let q = add_liquidity::QuoteRequest {
        domain: DOMAIN,
        pool,
        revision: state.blch_pool(&pool).unwrap().revision(),
        maximum,
        minimum_lp: 1,
        valid_until: 100,
    };
    let quote = state.quote_blch_add(&q, 4).unwrap();
    let mut inputs = vec![native.outpoint, native_funding];
    inputs.sort();
    let owners = inputs
        .iter()
        .map(|p| {
            if *p == native.outpoint {
                vec![]
            } else {
                vec![0; 5500]
            }
        })
        .collect();
    let mut request = add_liquidity::Request {
        quote: q,
        pool_state_root: quote.pool_state_root,
        native_gas: 100_000,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: identities()[2].0.clone(),
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
            outputs: vec![
                TransferOutput {
                    value: quote.reserves_after[0],
                    script_hash: reserve_script(&DOMAIN, &reserve),
                },
                TransferOutput {
                    value: 1,
                    script_hash: Sha3_256::digest(&identities()[2].0).into(),
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                asset: native.asset,
                inputs,
                outputs: vec![
                    Output {
                        owner: identities()[0].0.clone(),
                        amount: quote.reserves_after[1],
                    },
                    Output {
                        owner: identities()[2].0.clone(),
                        amount: state
                            .native()
                            .gateway()
                            .native()
                            .output(&native_funding)
                            .unwrap()
                            .output
                            .amount
                            - quote.amounts_in[1],
                    },
                ],
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
    let charge = state.quote_blch_add_fee(&request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[1].value = state
            .base()
            .utxo(&base_funding.0, base_funding.1)
            .unwrap()
            .value
            - quote.amounts_in[0]
            - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    sign_add(&mut request);
    request
}
fn sign_add(request: &mut add_liquidity::Request) {
    let auth = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&auth, &identities()[2].1);
    }
    for witness in &mut request.native.witnesses.owners {
        if !witness.is_empty() {
            *witness = signature(&auth, &identities()[2].1);
        }
    }
}
fn reject_add(state: &mut State, request: &add_liquidity::Request) {
    let root = state.state_root();
    let base = state.base().clone();
    let native = state.native().snapshot();
    let fees = state.fee_escrow();
    assert!(state
        .execute_blch_add(request, 4, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.base(), &base);
    assert_eq!(state.native().snapshot(), native);
    assert_eq!(state.fee_escrow(), fees);
}

#[test]
fn independent_provider_adds_balanced_and_unbalanced_then_redeems_only_own_lp() {
    let (mut state, pool, reserve, native_funding) = initialized();
    let creator_lp = state.blch_lp_position(&pool, &identities()[0].0);
    let supply = state
        .native()
        .gateway()
        .native()
        .supply(&state.paired_custody(&reserve).unwrap().asset);
    let first = add_request(
        &state,
        pool,
        reserve,
        ([9; 32], 0),
        native_funding,
        [1_000_000, 6_000],
    );
    let expected = state.quote_blch_add(&first.quote, 4).unwrap();
    assert_eq!(expected.amounts_in, [999_993, 6_000]);
    assert_eq!(expected.unused_maximum, [7, 0]);
    assert_eq!(expected.lp_minted, 77_459);
    let first_receipt = state
        .execute_blch_add(&first, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(first_receipt.quote, expected);
    assert_eq!(
        state.blch_lp_position(&pool, &identities()[2].0),
        expected.lp_minted
    );
    reject_add(&mut state, &first);
    let second = add_request(
        &state,
        pool,
        reserve,
        (first_receipt.blch_txid, 1),
        first_receipt.native.outputs[1],
        [1_000_000, 12_000],
    );
    let second_quote = state.quote_blch_add(&second.quote, 4).unwrap();
    let total_lp = state.blch_pool(&pool).unwrap().lp_supply();
    for index in 0..2 {
        let debit = (u128::from(second_quote.lp_minted)
            * u128::from(second_quote.reserves_before[index]))
        .div_ceil(u128::from(total_lp)) as u64;
        assert_eq!(second_quote.amounts_in[index], debit);
        assert_eq!(
            second_quote.unused_maximum[index],
            second.quote.maximum[index] - debit
        );
    }
    assert_eq!(second_quote.amounts_in[1], 6_000);
    let second_receipt = state
        .execute_blch_add(&second, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .output(&second_receipt.native.outputs[1])
            .unwrap()
            .output
            .amount,
        88_000
    );
    let provider_lp = expected.lp_minted + second_quote.lp_minted;
    assert_eq!(
        state.blch_lp_position(&pool, &identities()[2].0),
        provider_lp
    );
    assert_eq!(
        state.blch_lp_position(&pool, &identities()[0].0),
        creator_lp
    );
    assert_eq!(
        state.blch_pool(&pool).unwrap().lp_supply(),
        creator_lp + provider_lp + 1_000
    );
    let restored = State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    assert_eq!(
        restored.blch_lp_position(&pool, &identities()[2].0),
        provider_lp
    );
    state = restored;
    let redeem = remove_request(
        &state,
        pool,
        reserve,
        (second_receipt.blch_txid, 1),
        provider_lp,
    );
    // The reserve creator cannot authorize burning another provider's position.
    let mut stolen = redeem.clone();
    let auth = stolen.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut stolen.blch {
        keys[0].signature = signature(&auth, &identities()[0].1);
    }
    stolen.native.witnesses.owners[0] = signature(&auth, &identities()[0].1);
    reject_remove(&mut state, &stolen);
    let redeemed = state
        .execute_blch_remove(&redeem, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(state.blch_lp_position(&pool, &identities()[2].0), 0);
    assert_eq!(
        state.blch_lp_position(&pool, &identities()[0].0),
        creator_lp
    );
    assert_eq!(
        state.blch_pool(&pool).unwrap().lp_supply(),
        creator_lp + 1_000
    );
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .output(&redeemed.native.outputs[1])
            .unwrap()
            .output
            .owner,
        identities()[2].0
    );
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .supply(&redeem.native.transaction.asset),
        supply
    );
    let sum: u128 = state.base().utxos().map(|e| u128::from(e.value)).sum();
    let (fees, tips) = state.fee_escrow();
    assert_eq!(sum + fees + tips, 2 * u128::from(COIN));
    assert!(state
        .native()
        .is_locked(&state.paired_custody(&reserve).unwrap().outpoint));
    let restored = State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    assert_eq!(restored.state_root(), state.state_root());
    reject_remove(&mut state, &redeem);
}

#[test]
fn forged_pq_signatures_redirects_slippage_and_stale_quotes_reject_atomically() {
    let (mut state, pool, reserve, funding) = initialized();
    let valid = add_request(
        &state,
        pool,
        reserve,
        ([9; 32], 0),
        funding,
        [1_000_000, 12_000],
    );
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = valid.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
            keys[0].signature[offset] ^= 1;
        }
        reject_add(&mut state, &bad);
        let mut bad = valid.clone();
        bad.native
            .witnesses
            .owners
            .iter_mut()
            .find(|w| !w.is_empty())
            .unwrap()[offset] ^= 1;
        reject_add(&mut state, &bad);
    }
    let mut bad = valid.clone();
    let hash = bad.blch.spend_signing_root();
    if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
        keys[0].signature = signature(&hash, &identities()[2].1);
    }
    reject_add(&mut state, &bad);
    let mut bad = valid.clone();
    let hash = bad.native.transaction.signing_hash(&DOMAIN).unwrap();
    *bad.native
        .witnesses
        .owners
        .iter_mut()
        .find(|w| !w.is_empty())
        .unwrap() = signature(&hash, &identities()[2].1);
    reject_add(&mut state, &bad);
    let mut bad = valid.clone();
    bad.quote.minimum_lp = u64::MAX;
    sign_add(&mut bad);
    reject_add(&mut state, &bad);
    let mut bad = valid.clone();
    bad.pool_state_root[0] ^= 1;
    sign_add(&mut bad);
    reject_add(&mut state, &bad);
    for index in 0..2 {
        let mut bad = valid.clone();
        bad.native.transaction.outputs[index].owner = identities()[1].0.clone();
        sign_add(&mut bad);
        reject_add(&mut state, &bad);
    }
    let mut bad = valid.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
        outputs[1].script_hash = Sha3_256::digest(&identities()[1].0).into();
    }
    sign_add(&mut bad);
    reject_add(&mut state, &bad);
    let mut bad = valid.clone();
    bad.native.transaction.outputs[0].amount -= 1;
    bad.native.transaction.outputs[1].amount += 1;
    sign_add(&mut bad);
    reject_add(&mut state, &bad);
    state
        .execute_blch_add(&valid, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    reject_add(&mut state, &valid);
}
