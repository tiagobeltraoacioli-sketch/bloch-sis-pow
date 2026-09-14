//! Real PQ signatures for paired BLCH/native custody; local rehearsal only.
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
        &[EutxoEntry {
            txid: [8; 32],
            vout: 0,
            value: COIN,
            script_hash: Sha3_256::digest(identities()[0].0.clone()).into(),
        }],
    )
}

fn funded_state() -> (State, transfer_wire::Envelope) {
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
        outputs: vec![Output {
            owner: identities()[0].0.clone(),
            amount: 100_000,
        }],
        delta: 100_000,
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
            inputs: receipt.outputs,
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
    (state, envelope)
}

use bloch_pos_committee::transition::native_dex::base_reserves::{reserve_id, reserve_script};
use bloch_pos_committee::transition::native_dex::paired_custody::Request;
const SEED: [u8; 32] = [32; 32];
const BASE_RESERVE: u64 = 10_000_000;

fn fixture() -> (State, Request) {
    let (state, native) = funded_state();
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
    (state, request)
}
fn resign(request: &mut Request) {
    let message = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&message, &identities()[0].1);
    }
    request.native.witnesses.owners[0] = signature(&message, &identities()[0].1);
}
fn reject_unchanged(state: &mut State, request: &Request) {
    let root = state.state_root();
    let base = state.base().clone();
    let native = state.native().snapshot();
    let fees = state.fee_escrow();
    assert!(state
        .execute_paired_custody(request, 2, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.base(), &base);
    assert_eq!(state.native().snapshot(), native);
    assert_eq!(state.fee_escrow(), fees);
}

#[test]
fn paired_custody_rejects_standalone_and_forged_hybrid_signatures_atomically() {
    let (mut state, request) = fixture();
    let mut standalone = request.clone();
    let message = standalone.blch.spend_signing_root();
    if let PosTransaction::TransferV2 { keys, .. } = &mut standalone.blch {
        keys[0].signature = signature(&message, &identities()[0].1);
    }
    reject_unchanged(&mut state, &standalone);
    standalone = request.clone();
    standalone.native.witnesses.owners[0] = signature(
        &standalone.native.transaction.signing_hash(&DOMAIN).unwrap(),
        &identities()[0].1,
    );
    reject_unchanged(&mut state, &standalone);
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = request.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
            keys[0].signature[offset] ^= 1;
        }
        reject_unchanged(&mut state, &bad);
        let mut bad = request.clone();
        bad.native.witnesses.owners[0][offset] ^= 1;
        reject_unchanged(&mut state, &bad);
    }
    // A valid token leg must not commit when real BLCH conservation fails.
    let mut unbalanced = request.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut unbalanced.blch {
        outputs[1].value += 1;
    }
    resign(&mut unbalanced);
    reject_unchanged(&mut state, &unbalanced);
    // Both owners authorize this malformed token debit, but conservation still rejects it.
    let mut unbalanced = request.clone();
    unbalanced.native.transaction.outputs[1].amount += 1;
    resign(&mut unbalanced);
    reject_unchanged(&mut state, &unbalanced);
    // Custody metadata must not be detached from a signed reserve destination.
    let mut redirected = request.clone();
    redirected.native.transaction.outputs[0].owner = identities()[2].0.clone();
    resign(&mut redirected);
    reject_unchanged(&mut state, &redirected);
    let mut redirected = request.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut redirected.blch {
        outputs[0].script_hash = Sha3_256::digest(&identities()[2].0).into();
    }
    resign(&mut redirected);
    reject_unchanged(&mut state, &redirected);
    state
        .execute_paired_custody(&request, 2, &BaseVerifier, &BlochVerifier)
        .unwrap();
    reject_unchanged(&mut state, &request);
}

#[test]
fn paired_custody_preserves_supply_locks_both_assets_and_restores_joint_state() {
    let (mut state, request) = fixture();
    let id = reserve_id(&DOMAIN, &SEED, &identities()[0].0).unwrap();
    let asset = request.native.transaction.asset;
    let native_hash = request.native.transaction.signing_hash(&DOMAIN).unwrap();
    let native_reserve = bloch_euvm::ustav::OutPoint {
        transaction: native_hash,
        index: 0,
    };
    let supply = state.native().gateway().native().supply(&asset);
    let quote = state.quote_paired_custody(&request).unwrap();
    state
        .execute_paired_custody(&request, 2, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let reserve = state.base_reserve(&id).unwrap();
    assert_eq!(reserve.amount, BASE_RESERVE);
    assert!(state.spendable_base_output(&reserve.outpoint).is_none());
    assert!(state.paired_custody(&id).is_some());
    assert!(state.native().is_locked(&native_reserve));
    assert!(state.native().spendable_output(&native_reserve).is_none());
    let output = state
        .native()
        .gateway()
        .native()
        .output(&native_reserve)
        .unwrap();
    assert_eq!(output.output.amount, 60_000);
    assert_eq!(output.output.owner, identities()[0].0);
    assert_eq!(state.native().gateway().native().supply(&asset), supply);
    assert_eq!(
        state.fee_escrow(),
        (quote.base_fee_sat, quote.priority_fee_sat)
    );
    let coins: u128 = state
        .base()
        .utxos()
        .map(|entry| u128::from(entry.value))
        .sum();
    assert_eq!(
        coins + quote.base_fee_sat + quote.priority_fee_sat,
        u128::from(COIN)
    );
    let restored = State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    assert_eq!(restored.state_root(), state.state_root());
    assert!(restored.native().is_locked(&native_reserve));
    assert!(restored.spendable_base_output(&reserve.outpoint).is_none());
    // The real PQ owner must dispatch through the complete state; there is no
    // clonable inner ledger to extract and spend independently of the BLCH leg.
    let mut restored = restored;
    let mut joint = bloch_pos_committee::transition::native_dex::Request {
        blch: request.blch.clone(),
        native: request.native.clone(),
        valid_until: request.valid_until,
        native_gas: request.native_gas,
    };
    joint.native.transaction.inputs = vec![native_reserve];
    joint.native.transaction.outputs = vec![Output {
        owner: identities()[0].0.clone(),
        amount: 60_000,
    }];
    let hash = joint.authorization(&DOMAIN).unwrap();
    joint.native.witnesses.owners[0] = signature(&hash, &identities()[0].1);
    if let PosTransaction::TransferV2 { keys, .. } = &mut joint.blch {
        keys[0].signature = signature(&hash, &identities()[0].1);
    }
    let before = restored.state_root();
    assert!(matches!(
        restored.execute(&joint, 3, &BaseVerifier, &BlochVerifier),
        Err(bloch_pos_committee::transition::native_dex::Error::LockedReserve)
    ));
    assert_eq!(restored.state_root(), before);
}

#[test]
fn paired_wire_real_pq_matches_typed_execution_and_rejects_replay_and_tampering() {
    use bloch_pos_committee::transition::native_dex::paired_custody::wire;
    let (mut state, request) = fixture();
    let bytes = wire::encode(&request, &DOMAIN).unwrap();
    let decoded = wire::decode(&bytes, &DOMAIN).unwrap();
    assert_eq!(
        decoded.authorization(&DOMAIN).unwrap(),
        request.authorization(&DOMAIN).unwrap()
    );
    assert_eq!(wire::encode(&decoded, &DOMAIN).unwrap(), bytes);
    let root = state.state_root();
    let base = state.base().clone();
    let native = state.native().snapshot();
    let fees = state.fee_escrow();
    let mut wrong_domain = bytes.clone();
    wrong_domain[10] ^= 1;
    let mut bad_tail = bytes.clone();
    *bad_tail.last_mut().unwrap() ^= 1;
    let mut trailing = bytes.clone();
    trailing.push(0);
    for malformed in [
        wrong_domain,
        bad_tail,
        trailing,
        bytes[..bytes.len() - 1].to_vec(),
    ] {
        assert!(
            wire::apply_encoded(&mut state, &malformed, 2, &BaseVerifier, &BlochVerifier).is_err()
        );
        assert_eq!(state.state_root(), root);
        assert_eq!(state.base(), &base);
        assert_eq!(state.native().snapshot(), native);
        assert_eq!(state.fee_escrow(), fees);
    }
    // A canonical encoding is not evidence that its real PQ witnesses are valid.
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut forged = request.clone();
        forged.native.witnesses.owners[0][offset] ^= 1;
        let bad = wire::encode(&forged, &DOMAIN).unwrap();
        assert!(wire::decode(&bad, &DOMAIN).is_ok());
        assert!(wire::apply_encoded(&mut state, &bad, 2, &BaseVerifier, &BlochVerifier).is_err());
        assert_eq!(state.state_root(), root);
    }
    let mut direct = state.clone();
    let expected = direct
        .execute_paired_custody(&request, 2, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let actual = wire::apply_encoded(&mut state, &bytes, 2, &BaseVerifier, &BlochVerifier).unwrap();
    assert_eq!(actual.charge, expected.charge);
    assert_eq!(actual.authorization, expected.authorization);
    assert_eq!(actual.blch_txid, expected.blch_txid);
    assert_eq!(actual.reserve, expected.reserve);
    assert_eq!(actual.native, expected.native);
    assert_eq!(state.state_root(), direct.state_root());
    assert_eq!(state.fee_escrow(), direct.fee_escrow());
    let root = state.state_root();
    let mut restored = State::restore(state.snapshot(), root, &BlochVerifier).unwrap();
    assert!(wire::apply_encoded(&mut restored, &bytes, 2, &BaseVerifier, &BlochVerifier).is_err());
    assert_eq!(restored.state_root(), root);
}

use bloch_pos_committee::transition::native_dex::paired_custody::CloseRequest;

fn close_fixture() -> (State, CloseRequest) {
    use bloch_pos_committee::transition::native_dex::base_reserves::RESERVE_KEY_INDEX;
    let (mut state, creation) = fixture();
    let receipt = state
        .execute_paired_custody(&creation, 2, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let fee_funding = state.base().utxo(&receipt.blch_txid, 1).unwrap().value;
    let owner = identities()[0].0.clone();
    let mut request = CloseRequest {
        reserve: receipt.reserve.id,
        creation_authorization: receipt.authorization,
        valid_until: 100,
        native_gas: 100_000,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: owner.clone(),
                signature: vec![0; 5500],
            }],
            inputs: vec![
                TransferInputV2 {
                    txid: receipt.blch_txid,
                    vout: 0,
                    key_index: RESERVE_KEY_INDEX,
                },
                TransferInputV2 {
                    txid: receipt.blch_txid,
                    vout: 1,
                    key_index: 0,
                },
            ],
            outputs: vec![
                TransferOutput {
                    value: BASE_RESERVE,
                    script_hash: Sha3_256::digest(&owner).into(),
                },
                TransferOutput {
                    value: 1,
                    script_hash: Sha3_256::digest(&owner).into(),
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                inputs: vec![receipt.native.outputs[0]],
                outputs: vec![Output {
                    owner,
                    amount: creation.native_amount,
                }],
                ..creation.native.transaction.clone()
            },
            witnesses: Witnesses {
                owners: vec![vec![0; 5500]],
                modules: vec![vec![]],
                eligibility: vec![],
            },
        },
    };
    let length = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = length + 256;
    }
    let quote = state.quote_paired_close(&request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[1].value = fee_funding - (quote.base_fee_sat + quote.priority_fee_sat) as u64;
    }
    sign_close(&mut request);
    (state, request)
}
fn sign_close(request: &mut CloseRequest) {
    let hash = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&hash, &identities()[0].1);
    }
    request.native.witnesses.owners[0] = signature(&hash, &identities()[0].1);
}
fn reject_close_unchanged(state: &mut State, request: &CloseRequest) {
    let root = state.state_root();
    let base = state.base().clone();
    let native = state.native().snapshot();
    let fees = state.fee_escrow();
    assert!(state
        .execute_paired_close(request, 3, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.base(), &base);
    assert_eq!(state.native().snapshot(), native);
    assert_eq!(state.fee_escrow(), fees);
}
#[test]
fn real_pq_close_rejects_forgery_redirected_reserves_and_fee_subsidy_atomically() {
    let (mut state, request) = close_fixture();
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = request.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
            keys[0].signature[offset] ^= 1;
        }
        reject_close_unchanged(&mut state, &bad);
        let mut bad = request.clone();
        bad.native.witnesses.owners[0][offset] ^= 1;
        reject_close_unchanged(&mut state, &bad);
    }
    let mut bad = request.clone();
    bad.creation_authorization[0] ^= 1;
    sign_close(&mut bad);
    reject_close_unchanged(&mut state, &bad);
    // Total BLCH conservation still holds, but reserve value cannot fund fees/change.
    let mut bad = request.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
        outputs[0].value -= 1;
        outputs[1].value += 1;
    }
    sign_close(&mut bad);
    reject_close_unchanged(&mut state, &bad);
    let mut bad = request.clone();
    bad.native.transaction.outputs[0].owner = identities()[2].0.clone();
    sign_close(&mut bad);
    reject_close_unchanged(&mut state, &bad);
    let mut bad = request.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
        outputs[0].script_hash = Sha3_256::digest(&identities()[2].0).into();
    }
    sign_close(&mut bad);
    reject_close_unchanged(&mut state, &bad);
    // Correct ordinary owner signatures cannot substitute for joint-close consent.
    let mut bad = request.clone();
    let hash = bad.native.transaction.signing_hash(&DOMAIN).unwrap();
    bad.native.witnesses.owners[0] = signature(&hash, &identities()[0].1);
    reject_close_unchanged(&mut state, &bad);
    state
        .execute_paired_close(&request, 3, &BaseVerifier, &BlochVerifier)
        .unwrap();
}
#[test]
fn real_pq_close_returns_both_assets_and_restored_state_rejects_replay() {
    let (mut state, request) = close_fixture();
    let before_fees = state.fee_escrow();
    let native_input = request.native.transaction.inputs[0];
    let base_input = state.base_reserve(&request.reserve).unwrap().outpoint;
    let asset = request.native.transaction.asset;
    let supply = state.native().gateway().native().supply(&asset);
    let quote = state.quote_paired_close(&request).unwrap();
    let mut encoded_state = state.clone();
    let frame =
        pool_wire::encode(&pool_wire::Request::ClosePair(request.clone()), &DOMAIN).unwrap();
    pool_wire::apply_encoded(&mut encoded_state, &frame, 3, &BaseVerifier, &BlochVerifier).unwrap();
    let receipt = state
        .execute_paired_close(&request, 3, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(encoded_state.state_root(), state.state_root());
    assert_eq!(encoded_state.fee_escrow(), state.fee_escrow());
    assert_eq!(receipt.charge, quote);
    assert!(state.paired_custody(&request.reserve).is_none());
    assert!(state.base_reserve(&request.reserve).is_none());
    assert!(state.base().utxo(&base_input.0, base_input.1).is_none());
    assert!(state
        .native()
        .gateway()
        .native()
        .output(&native_input)
        .is_none());
    assert!(!state.native().is_locked(&native_input));
    assert!(!state.base_is_locked(&base_input));
    let returned = state
        .spendable_base_output(&(receipt.blch_txid, 0))
        .unwrap();
    assert_eq!(returned.value, BASE_RESERVE);
    assert_eq!(
        returned.script_hash,
        <[u8; 32]>::from(Sha3_256::digest(&identities()[0].0))
    );
    let native = state
        .native()
        .spendable_output(&receipt.native.outputs[0])
        .unwrap();
    assert_eq!(native.output.amount, 60_000);
    assert_eq!(native.output.owner, identities()[0].0);
    assert_eq!(state.native().gateway().native().supply(&asset), supply);
    let fees = state.fee_escrow();
    assert_eq!(
        fees,
        (
            before_fees.0 + quote.base_fee_sat,
            before_fees.1 + quote.priority_fee_sat
        )
    );
    let coins: u128 = state
        .base()
        .utxos()
        .map(|entry| u128::from(entry.value))
        .sum();
    assert_eq!(coins + fees.0 + fees.1, u128::from(COIN));
    let root = state.state_root();
    let mut restored = State::restore(state.snapshot(), root, &BlochVerifier).unwrap();
    reject_close_unchanged(&mut restored, &request);
    assert_eq!(restored.state_root(), root);
    assert!(restored
        .native()
        .spendable_output(&receipt.native.outputs[0])
        .is_some());
}

use bloch_pos_committee::transition::native_dex::initial_liquidity::Request as LiquidityRequest;

fn liquidity_fixture() -> (State, LiquidityRequest, CloseRequest) {
    let (state, close) = close_fixture();
    let fee_input = match &close.blch {
        PosTransaction::TransferV2 { inputs, .. } => inputs[1].clone(),
        _ => unreachable!(),
    };
    let mut request = LiquidityRequest {
        reserve: close.reserve,
        creation_authorization: close.creation_authorization,
        fee_bps: 30,
        minimum_lp: 1,
        valid_until: 100,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: identities()[0].0.clone(),
                signature: vec![0; 5500],
            }],
            inputs: vec![fee_input],
            outputs: vec![TransferOutput {
                value: 1,
                script_hash: Sha3_256::digest(&identities()[0].0).into(),
            }],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
    };
    finalize_liquidity(&state, &mut request);
    (state, request, close)
}
fn finalize_liquidity(state: &State, request: &mut LiquidityRequest) {
    let len = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = len + 256;
    }
    let quote = state.quote_initial_liquidity(request).unwrap();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut request.blch
    {
        let funding = state
            .base()
            .utxo(&inputs[0].txid, inputs[0].vout)
            .unwrap()
            .value;
        outputs[0].value = funding - (quote.base_fee_sat + quote.priority_fee_sat) as u64;
    }
    sign_liquidity(request, 0);
}
fn sign_liquidity(request: &mut LiquidityRequest, key_index: usize) {
    let hash = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&hash, &identities()[key_index].1);
    }
}
fn reject_liquidity_unchanged(state: &mut State, request: &LiquidityRequest) {
    let root = state.state_root();
    let native = state.native().snapshot();
    let base = state.base().clone();
    let fees = state.fee_escrow();
    assert!(state
        .execute_initial_liquidity(request, 3, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.native().snapshot(), native);
    assert_eq!(state.base(), &base);
    assert_eq!(state.fee_escrow(), fees);
}
#[test]
fn real_pq_initial_liquidity_conserves_reserves_and_locks_minimum_lp() {
    let (mut state, request, mut close) = liquidity_fixture();
    let base_reserve = state.base_reserve(&request.reserve).unwrap().clone();
    let native_reserve = state.paired_custody(&request.reserve).unwrap().clone();
    let native_before = state.native().snapshot();
    let supply_before = state
        .native()
        .gateway()
        .native()
        .supply(&native_reserve.asset);
    let native_output_before = state
        .native()
        .gateway()
        .native()
        .output(&native_reserve.outpoint)
        .unwrap()
        .clone();
    let quote = state.quote_initial_liquidity(&request).unwrap();
    let fees_before = state.fee_escrow();
    let receipt = state
        .execute_initial_liquidity(&request, 3, &BaseVerifier, &BlochVerifier)
        .unwrap();
    // Independent integer expectation: floor(sqrt(10_000_000 * 60_000)) = 774596.
    assert_eq!(receipt.lp_minted, 773_596);
    let pool = state.blch_pool(&receipt.pool).unwrap();
    assert_eq!(pool.assets(), [bloch_euvm::BLCH, native_reserve.asset]);
    assert_eq!(pool.reserves(), [BASE_RESERVE, 60_000]);
    assert_eq!(pool.lp_supply(), 774_596);
    assert_eq!(pool.revision(), 1);
    assert_eq!(pool.fee_bps(), 30);
    assert_eq!(
        state.blch_lp_position(&receipt.pool, &identities()[0].0),
        773_596
    );
    assert_eq!(state.blch_lp_position(&receipt.pool, &identities()[2].0), 0);
    assert_eq!(state.blch_lp_position(&receipt.pool, &[]), 0);
    assert_eq!(state.base_reserve(&request.reserve), Some(&base_reserve));
    assert_eq!(
        state.paired_custody(&request.reserve),
        Some(&native_reserve)
    );
    // Owned native diagnostics now also commit LP authority, even though token
    // supply and the actual reserved token output remain unchanged.
    assert_ne!(state.native().snapshot(), native_before);
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .supply(&native_reserve.asset),
        supply_before
    );
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .output(&native_reserve.outpoint),
        Some(&native_output_before)
    );
    assert_eq!(receipt.charge, quote);
    assert_eq!(
        state.fee_escrow(),
        (
            fees_before.0 + quote.base_fee_sat,
            fees_before.1 + quote.priority_fee_sat
        )
    );
    let mut restored =
        State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    assert_eq!(
        restored.blch_lp_position(&receipt.pool, &identities()[0].0),
        receipt.lp_minted
    );
    assert_eq!(
        restored.blch_pool(&receipt.pool),
        state.blch_pool(&receipt.pool)
    );
    // Refresh actual fee funding: this otherwise-valid close must not bypass LP custody.
    if let PosTransaction::TransferV2 { inputs, .. } = &mut close.blch {
        inputs[1].txid = receipt.blch_txid;
        inputs[1].vout = 0;
    }
    let quote = restored.quote_paired_close(&close).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut close.blch {
        outputs[1].value = restored.base().utxo(&receipt.blch_txid, 0).unwrap().value
            - (quote.base_fee_sat + quote.priority_fee_sat) as u64;
    }
    sign_close(&mut close);
    let root = restored.state_root();
    assert!(matches!(
        restored.execute_paired_close(&close, 4, &BaseVerifier, &BlochVerifier),
        Err(bloch_pos_committee::transition::native_dex::Error::LockedReserve)
    ));
    assert_eq!(restored.state_root(), root);
    // A fresh fee input does not permit a second issuance for the same reserve.
    let mut duplicate = request.clone();
    if let PosTransaction::TransferV2 { inputs, .. } = &mut duplicate.blch {
        inputs[0].txid = receipt.blch_txid;
        inputs[0].vout = 0;
    }
    finalize_liquidity(&restored, &mut duplicate);
    reject_liquidity_unchanged(&mut restored, &duplicate);
    assert_eq!(
        restored.blch_lp_position(&receipt.pool, &identities()[0].0),
        773_596
    );
}
#[test]
fn real_pq_initial_liquidity_rejects_forgery_theft_and_minimum_lp_violation() {
    let (mut state, request, _) = liquidity_fixture();
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = request.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
            keys[0].signature[offset] ^= 1;
        }
        reject_liquidity_unchanged(&mut state, &bad);
    }
    let mut bad = request.clone();
    bad.minimum_lp = 773_597;
    sign_liquidity(&mut bad, 0);
    reject_liquidity_unchanged(&mut state, &bad);
    let mut bad = request.clone();
    bad.creation_authorization[0] ^= 1;
    sign_liquidity(&mut bad, 0);
    reject_liquidity_unchanged(&mut state, &bad);
    let mut bad = request.clone();
    if let PosTransaction::TransferV2 { keys, outputs, .. } = &mut bad.blch {
        keys[0].pubkey = identities()[2].0.clone();
        outputs[0].script_hash = Sha3_256::digest(&identities()[2].0).into();
    }
    sign_liquidity(&mut bad, 2);
    reject_liquidity_unchanged(&mut state, &bad);
    let mut bad = request.clone();
    bad.fee_bps = 31; // The original owner did not sign this fee schedule.
    reject_liquidity_unchanged(&mut state, &bad);
    state
        .execute_initial_liquidity(&request, 3, &BaseVerifier, &BlochVerifier)
        .unwrap();
}
