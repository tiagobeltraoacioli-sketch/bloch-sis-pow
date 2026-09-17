use super::*;
use crate::header::BlockHeaderV4;
use crate::state_root::{EutxoEntry, EvmCommitment};
use crate::transition::{TransferInputV2, TransferOutput, WitnessKey};
use crate::BlockId;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::{Output, Registration, Transaction, Witnesses};
use bloch_euvm::Val;
pub(super) const DOMAIN: [u8; 32] = [42; 32];
const GAS: u64 = 1_000_000;
pub(super) const COIN: u64 = 100_000_000;
pub(super) struct BoundVerifier;
pub(super) fn key(n: u8) -> Vec<u8> {
    vec![n; 32]
}
pub(super) fn signature(message: &[u8], key: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(key);
    h.update(message);
    h.finalize().to_vec()
}
impl SignatureVerifier for BoundVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        key.len() == 32 && key[0] != 0 && sig == signature(root, key)
    }
}
impl Verifier for BoundVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        key.len() == 32 && key[0] != 0
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], sig: &[u8]) -> bool {
        self.valid_pq_key(key) && sig == signature(message, key)
    }
}
fn base_state() -> CommittedState {
    let id = BlockId::of(&BlockHeaderV4 {
        version: crate::transition::BLOCK_VERSION_V4,
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
            script_hash: Sha3_256::digest(key(1)).into(),
        }],
    )
}
pub(super) fn fixture() -> (State, Request) {
    let base = base_state();
    let mut native = PoolLedger::new(DOMAIN);
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"Quote".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: key(2),
            })],
        },
        nonce: [1; 32],
        initial_kyc_root: None,
    };
    let sig = signature(&registration.signing_hash(&DOMAIN).unwrap(), &key(2));
    let asset = native
        .register(registration, &sig, &BoundVerifier, GAS)
        .unwrap();
    let mint = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: key(3),
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
            &key(2),
        ))]],
        ..Witnesses::default()
    };
    let receipt = native.apply(&mint, &w, 1, &BoundVerifier, GAS).unwrap();
    let tx = Transaction {
        inputs: receipt.outputs,
        outputs: vec![Output {
            owner: key(1),
            amount: 100,
        }],
        delta: 0,
        ..mint
    };
    let state = State::from_parts(
        base.clone(),
        native.clone(),
        base.compute_root(),
        native.state_root(),
    )
    .unwrap();
    let mut request = Request {
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: key(1),
                signature: vec![0; 32],
            }],
            inputs: vec![TransferInputV2 {
                txid: [8; 32],
                vout: 0,
                key_index: 0,
            }],
            outputs: vec![TransferOutput {
                value: 1,
                script_hash: Sha3_256::digest(key(3)).into(),
            }],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: tx,
            witnesses: Witnesses {
                owners: vec![vec![0; 32]],
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
        *tx_bytes = length;
    }
    let charge = state.quote(request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[0].value = COIN - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
}
fn resign(request: &mut Request) {
    let message = request.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&message, &key(1));
    }
    request.native.witnesses.owners[0] = signature(&message, &key(3));
}
fn reject(state: &mut State, request: &Request, height: u64) {
    let root = state.state_root();
    let base = state.base.clone();
    let native = state.native.state_root();
    let escrow = state.fee_escrow();
    assert!(state
        .execute(request, height, &BoundVerifier, &BoundVerifier)
        .is_err());
    assert_eq!(state.state_root(), root);
    assert_eq!(state.base, base);
    assert_eq!(state.native.state_root(), native);
    assert_eq!(state.fee_escrow(), escrow);
}

#[test]
fn joint_spends_real_base_and_native_conserves_combined_fee_and_replays_fail() {
    let (mut state, request) = fixture();
    let charge = state.quote(&request).unwrap();
    let base_bytes = request.blch.canonical_bytes().len() as u64;
    assert!(charge.tx_bytes > base_bytes);
    assert_eq!(
        charge.gas,
        request.native_gas * NATIVE_GAS_MULTIPLIER
            + fee_market::intrinsic_gas(fee_market::TxClass::Eutxo { inputs: 1 }, charge.tx_bytes)
    );
    let result = state
        .execute(&request, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(result.charge, charge);
    assert_eq!(result.blch_txid, request.output_txid(&DOMAIN).unwrap());
    assert_ne!(result.blch_txid, request.blch.txid());
    assert!(state.base.utxo(&[8; 32], 0).is_none());
    let paid = state.base.utxo(&result.blch_txid, 0).unwrap().value;
    assert_eq!(
        u128::from(COIN),
        u128::from(paid) + charge.base_fee_sat + charge.priority_fee_sat
    );
    assert_eq!(
        state.fee_escrow(),
        (charge.base_fee_sat, charge.priority_fee_sat)
    );
    let output = state
        .native
        .gateway()
        .native()
        .output(&result.native.outputs[0])
        .unwrap();
    assert_eq!(output.output.owner, key(1));
    assert_eq!(output.output.amount, 100);
    reject(&mut state, &request, 2);
}

#[test]
fn counterparty_native_asset_domain_and_expiry_tampering_cannot_settle() {
    for case in 0..5 {
        let (mut state, mut request) = fixture();
        match case {
            0 => request.native.transaction.outputs[0].owner = key(99),
            1 => request.native.transaction.asset = [99; 32],
            2 => request.native.domain = [99; 32],
            3 => request.valid_until = 101,
            _ => {
                if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
                    outputs[0].script_hash = [99; 32];
                }
            }
        }
        reject(&mut state, &request, 2);
    }
    let (mut state, request) = fixture();
    reject(&mut state, &request, 101);
}

#[test]
fn standalone_and_joint_signatures_are_not_interchangeable() {
    let (mut state, mut request) = fixture();
    let mut native = state.native.clone();
    let native_root = native.state_root();
    assert!(native
        .apply(
            &request.native.transaction,
            &request.native.witnesses,
            2,
            &BoundVerifier,
            GAS
        )
        .is_err());
    assert_eq!(native.state_root(), native_root);
    let root = request.blch.checked_signing_root(state.base.epoch);
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature = signature(&root, &key(1));
    }
    request.native.witnesses.owners[0] = signature(
        &request.native.transaction.signing_hash(&DOMAIN).unwrap(),
        &key(3),
    );
    reject(&mut state, &request, 2);
}

#[test]
fn bad_base_after_valid_native_staging_leaves_everything_untouched() {
    let (mut state, mut request) = fixture();
    if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
        keys[0].signature[0] ^= 1;
    }
    reject(&mut state, &request, 2);
    let (mut state, mut request) = fixture();
    if let PosTransaction::TransferV2 { inputs, .. } = &mut request.blch {
        inputs.push(inputs[0].clone());
    }
    reprice(&state, &mut request);
    resign(&mut request);
    reject(&mut state, &request, 2);
}

#[test]
fn scoped_output_collision_is_rejected_before_commit() {
    let (mut state, request) = fixture();
    let txid = request.output_txid(&DOMAIN).unwrap();
    state.base.eutxos.insert(EutxoEntry {
        txid,
        vout: 0,
        value: 1,
        script_hash: [99; 32],
    });
    reject(&mut state, &request, 2);
}

#[test]
fn native_budget_and_declared_full_envelope_size_are_enforced_atomically() {
    let (mut state, mut request) = fixture();
    request.native_gas = 1;
    reprice(&state, &mut request);
    resign(&mut request);
    reject(&mut state, &request, 2);
    let (mut state, mut request) = fixture();
    let standalone_size = request.blch.canonical_bytes().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = standalone_size;
    }
    resign(&mut request);
    reject(&mut state, &request, 2);
}

#[test]
fn part_roots_and_network_identity_must_match() {
    let (state, _) = fixture();
    assert!(State::from_parts(
        state.base.clone(),
        state.native.clone(),
        [0; 32],
        state.native.state_root()
    )
    .is_err());
    let foreign = PoolLedger::new([99; 32]);
    assert!(State::from_parts(
        state.base.clone(),
        foreign.clone(),
        state.base.compute_root(),
        foreign.state_root()
    )
    .is_err());
}

#[test]
fn native_unit_conversion_cannot_exceed_total_gas_ceiling() {
    let (mut state, mut request) = fixture();
    request.native_gas = fee_market::MAX_TX_GAS;
    assert!(state.quote(&request).is_err());
    reject(&mut state, &request, 2);
    request.native_gas = u64::MAX;
    assert!(state.quote(&request).is_err());
    reject(&mut state, &request, 2);
}

#[test]
fn complete_snapshot_restores_fee_escrow_and_replay_protection() {
    let (mut state, request) = fixture();
    state
        .execute(&request, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    let root = state.state_root();
    let mut restored = State::restore(state.snapshot(), root, &BoundVerifier).unwrap();
    assert_eq!(restored.state_root(), root);
    assert_eq!(restored.fee_escrow(), state.fee_escrow());
    assert_eq!(restored.base, state.base);
    reject(&mut restored, &request, 2);
    let mut changed = state.snapshot();
    changed.base_fees += 1;
    assert!(State::restore(changed, root, &BoundVerifier).is_err());
    let mut changed = state.snapshot();
    changed.priority_fees = 0;
    assert!(State::restore(changed, root, &BoundVerifier).is_err());
    assert!(State::restore(state.snapshot(), [0; 32], &BoundVerifier).is_err());
}

#[test]
fn joint_signature_cannot_authorize_a_conserving_standalone_base_transfer() {
    let (state, request) = fixture();
    let mut base = state.base.clone();
    let mut standalone = request.blch.clone();
    let length = standalone.canonical_bytes().len() as u64;
    if let PosTransaction::TransferV2 {
        tx_bytes,
        outputs,
        tip_millisat_per_gas,
        ..
    } = &mut standalone
    {
        *tx_bytes = length;
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 1 },
            length,
            base.next_base_fee(),
            *tip_millisat_per_gas,
        );
        outputs[0].value = COIN - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    let before = base.clone();
    assert_eq!(
        base.apply_transfer_v2(&standalone, base.next_base_fee(), &BoundVerifier),
        Err(TransferReject::BadSignature)
    );
    assert_eq!(base, before);
}

#[test]
fn congested_parent_uses_derived_next_block_price() {
    let (mut state, mut request) = fixture();
    state.base.base_fee_millisat_per_gas = 1000;
    state.base.block_gas_used = fee_market::BLOCK_GAS_LIMIT;
    state.base.block_tx_bytes = fee_market::MAX_BLOCK_TX_BYTES;
    let next_price = state.base.next_base_fee();
    assert!(next_price > state.base.base_fee_millisat_per_gas);
    reprice(&state, &mut request);
    resign(&mut request);
    let charge = state.quote(&request).unwrap();
    let expected = fee_market::fee_parts_sat(charge.gas, next_price, 2);
    let old_price = fee_market::fee_parts_sat(charge.gas, state.base.base_fee_millisat_per_gas, 2);
    assert_ne!(expected.0, old_price.0);
    assert_eq!((charge.base_fee_sat, charge.priority_fee_sat), expected);
    let execution = state
        .execute(&request, 2, &BoundVerifier, &BoundVerifier)
        .unwrap();
    assert_eq!(execution.charge, charge);
    assert_eq!(state.fee_escrow(), expected);
}
