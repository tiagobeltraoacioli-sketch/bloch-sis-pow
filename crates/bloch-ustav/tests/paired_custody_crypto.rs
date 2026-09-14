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
    // Even the actual PQ owner cannot spend a locked native reserve.
    let mut ledger = restored.native().clone();
    let mut tx = request.native.transaction.clone();
    tx.inputs = vec![native_reserve];
    tx.outputs = vec![Output {
        owner: identities()[0].0.clone(),
        amount: 60_000,
    }];
    let witnesses = Witnesses {
        owners: vec![signature(
            &tx.signing_hash(&DOMAIN).unwrap(),
            &identities()[0].1,
        )],
        modules: vec![vec![]],
        eligibility: vec![],
    };
    let before = ledger.state_root();
    assert!(ledger
        .apply(&tx, &witnesses, 3, &BlochVerifier, GAS)
        .is_err());
    assert_eq!(ledger.state_root(), before);
    assert!(ledger
        .plan_transfer(&tx, &witnesses, 3, &BlochVerifier, GAS)
        .is_err());
    assert_eq!(ledger.state_root(), before);
}
