//! Real hybrid owner signatures for the explicitly opt-in joint rehearsal.
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
use bloch_pos_committee::transition::native_dex::{Request, State};
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
fn fixture() -> (State, Request) {
    let base = base_state();
    let mut native = PoolLedger::new(DOMAIN);
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"Quote".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: identities()[1].0.clone(),
            })],
        },
        nonce: [1; 32],
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
            owner: identities()[2].0.clone(),
            amount: 100,
        }],
        delta: 100,
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
    let tx = Transaction {
        inputs: receipt.outputs,
        outputs: vec![Output {
            owner: identities()[0].0.clone(),
            amount: 100,
        }],
        delta: 0,
        ..mint
    };
    let state = State::from_parts(
        base.clone(),
        native.clone(),
        base.state_root(),
        native.state_root(),
    )
    .unwrap();
    let mut request = Request {
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: identities()[0].0.clone(),
                signature: vec![0; 5500],
            }],
            inputs: vec![TransferInputV2 {
                txid: [8; 32],
                vout: 0,
                key_index: 0,
            }],
            outputs: vec![TransferOutput {
                value: 1,
                script_hash: Sha3_256::digest(identities()[2].0.clone()).into(),
            }],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: tx,
            witnesses: Witnesses {
                owners: vec![vec![0; 5500]],
                modules: vec![vec![]],
                eligibility: vec![],
            },
        },
        valid_until: 100,
        native_gas: 100_000,
    };
    reprice(&state, &mut request);
    resign(&mut request);
    (state, request)
}
fn reprice(state: &State, request: &mut Request) {
    let length = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = length + 256;
    }
    let charge = state.quote(request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[0].value = COIN - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
}
fn resign(request: &mut Request) {
    let message = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&message, &identities()[0].1);
    }
    request.native.witnesses.owners[0] = signature(&message, &identities()[2].1);
}
fn unchanged_after_rejection(state: &mut State, request: &Request) {
    let root = state.state_root();
    let base = state.base().clone();
    let native = state.native().snapshot();
    let fees = state.fee_escrow();
    assert!(state
        .execute(request, 2, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.base(), &base);
    assert_eq!(state.native().snapshot(), native);
    assert_eq!(state.fee_escrow(), fees);
}

#[test]
fn hybrid_real_blch_reserve_continuation_preserves_custody_and_owner_authority() {
    use bloch_pos_committee::transition::native_dex::base_reserves::{
        reserve_id, reserve_script, Action, Request as ReserveRequest, RESERVE_KEY_INDEX,
    };
    let (mut state, mut joint) = fixture();
    let owner = identities()[0].0.clone();
    let id = reserve_id(&DOMAIN, &[19; 32], &owner).unwrap();
    let amount = 10_000_000;
    let mut request = ReserveRequest {
        action: Action::Create {
            seed: [19; 32],
            amount,
        },
        valid_until: 100,
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
                    value: amount,
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
    let finalize = |state: &State, request: &mut ReserveRequest, funding: u64, deposit: u64| {
        let length = request.canonical_bytes(&DOMAIN).unwrap().len() as u64;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
            *tx_bytes = length + 256;
        }
        let charge = state.quote_base_reserve(request).unwrap();
        if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
            outputs[1].value =
                funding - deposit - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
        }
        let digest = request.authorization(&DOMAIN).unwrap();
        if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
            keys[0].signature = signature(&digest, &identities()[0].1);
        }
    };
    finalize(&state, &mut request, COIN, amount);
    let native_before = state.native().state_root();
    let first = state
        .execute_base_reserve(&request, 2, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert!(state
        .spendable_base_output(&first.reserve.outpoint)
        .is_none());
    let funding = state.base().utxo(&first.blch_txid, 1).unwrap().value;
    request.action = Action::Continue {
        reserve: id,
        revision: 0,
    };
    if let PosTransaction::TransferV2 { inputs, keys, .. } = &mut request.blch {
        *inputs = vec![
            TransferInputV2 {
                txid: first.blch_txid,
                vout: 0,
                key_index: RESERVE_KEY_INDEX,
            },
            TransferInputV2 {
                txid: first.blch_txid,
                vout: 1,
                key_index: 0,
            },
        ];
        keys[0].signature = vec![0; 5500];
    }
    finalize(&state, &mut request, funding, 0);
    let before = state.state_root();
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut forged = request.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut forged.blch {
            keys[0].signature[offset] ^= 1;
        }
        assert!(state
            .execute_base_reserve(&forged, 3, &BaseVerifier, &BlochVerifier)
            .is_err());
        assert_eq!(state.state_root(), before);
    }
    joint.blch = request.blch.clone();
    assert!(state
        .execute(&joint, 3, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(state.state_root(), before);
    let next = state
        .execute_base_reserve(&request, 3, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(next.reserve.amount, amount);
    assert_eq!(next.reserve.revision, 1);
    assert!(state.base().utxo(&first.blch_txid, 0).is_none());
    assert_eq!(state.native().state_root(), native_before);
    let coins: u128 = state.base().utxos().map(|entry| entry.value as u128).sum();
    let fees = state.fee_escrow();
    assert_eq!(coins + fees.0 + fees.1, COIN as u128);
    let restored = State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    assert_eq!(restored.base_reserve(&id), Some(&next.reserve));
    assert!(restored
        .spendable_base_output(&next.reserve.outpoint)
        .is_none());
}
#[test]
fn hybrid_joint_blch_native_atomicity_cross_binding_and_fee_restore() {
    let (mut state, request) = fixture();
    // Each owner separately signing their ordinary leg does not authorize the exchange.
    let mut standalone = request.clone();
    let base_hash = standalone.blch.spend_signing_root();
    if let PosTransaction::TransferV2 { keys, .. } = &mut standalone.blch {
        keys[0].signature = signature(&base_hash, &identities()[0].1);
    }
    unchanged_after_rejection(&mut state, &standalone);
    standalone = request.clone();
    standalone.native.witnesses.owners[0] = signature(
        &standalone.native.transaction.signing_hash(&DOMAIN).unwrap(),
        &identities()[2].1,
    );
    unchanged_after_rejection(&mut state, &standalone);
    // Modifying either counterparty's payout invalidates the jointly signed intent.
    let mut tampered = request.clone();
    tampered.native.transaction.outputs[0].owner = identities()[2].0.clone();
    unchanged_after_rejection(&mut state, &tampered);
    tampered = request.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut tampered.blch {
        outputs[0].script_hash = Sha3_256::digest(&identities()[0].0).into();
    }
    unchanged_after_rejection(&mut state, &tampered);
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = request.clone();
        bad.native.witnesses.owners[0][offset] ^= 1;
        unchanged_after_rejection(&mut state, &bad);
        let mut bad = request.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
            keys[0].signature[offset] ^= 1;
        }
        unchanged_after_rejection(&mut state, &bad);
    }
    let native_input = request.native.transaction.inputs[0];
    let expected = state.quote(&request).unwrap();
    let receipt = state
        .execute(&request, 2, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(receipt.charge, expected);
    assert!(state.base().utxo(&[8; 32], 0).is_none());
    let received = state.base().utxo(&receipt.blch_txid, 0).unwrap();
    assert_eq!(
        received.script_hash,
        <[u8; 32]>::from(Sha3_256::digest(&identities()[2].0))
    );
    assert_eq!(
        u128::from(received.value) + expected.base_fee_sat + expected.priority_fee_sat,
        u128::from(COIN)
    );
    assert!(state
        .native()
        .gateway()
        .native()
        .output(&native_input)
        .is_none());
    let native_received = state
        .native()
        .gateway()
        .native()
        .output(&receipt.native.outputs[0])
        .unwrap();
    assert_eq!(native_received.output.owner, identities()[0].0);
    assert_eq!(native_received.output.amount, 100);
    assert_eq!(
        state.fee_escrow(),
        (expected.base_fee_sat, expected.priority_fee_sat)
    );
    let mut restored =
        State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    assert_eq!(restored.state_root(), state.state_root());
    assert_eq!(restored.fee_escrow(), state.fee_escrow());
    unchanged_after_rejection(&mut restored, &request);
    let mut forged = state.snapshot();
    forged.base_fees += 1;
    assert!(State::restore(forged, state.state_root(), &BlochVerifier).is_err());
}
