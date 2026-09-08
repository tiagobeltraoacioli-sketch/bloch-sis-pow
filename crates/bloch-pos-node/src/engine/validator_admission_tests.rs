// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::keys::{Unlock, AUTO_VALIDATOR_INDEX};
use bloch_pos_committee::{
    staking,
    transition::{funded::*, FundedDeposit, FundingInput, TransferOutput},
};

fn authorize(tx: &mut FundedDeposit, funding: &Keystore, joining: &Keystore) {
    tx.tx_bytes = tx.reserved_tx_bytes();
    tx.funding_signature = funding.sign(&tx.funding_root());
    tx.proof_of_possession = joining.sign(&tx.possession_root());
}

fn fixture() -> (
    Engine,
    perf_support::TestDir,
    Keystore,
    Keystore,
    FundedDeposit,
) {
    let (mut engine, dir) = perf_support::proposing_engine();
    let funding =
        Keystore::generate_with(&dir.0.join("funding"), 0, &Unlock::PlaintextOptIn).unwrap();
    let joining = Keystore::generate_with(
        &dir.0.join("joining"),
        AUTO_VALIDATOR_INDEX,
        &Unlock::PlaintextOptIn,
    )
    .unwrap();
    let mut tx = FundedDeposit {
        network_domain: [0; 32],
        valid_until_epoch: 100,
        funding_pubkey: funding.pubkey.clone(),
        inputs: vec![FundingInput {
            txid: [0; 32],
            vout: 0,
        }],
        validator_pubkey: joining.pubkey.clone(),
        amount_sat: staking::MIN_DEPOSIT_SAT,
        randao_commitment: RandaoChain::generate(joining.randao_seed).commitment(),
        withdrawal_credentials: [0x81; 32],
        commission_bps: 500,
        change: TransferOutput {
            value: 50_000,
            script_hash: [0x82; 32],
        },
        max_base_fee_millisat_per_gas: 100,
        tip_millisat_per_gas: 5,
        tx_bytes: 0,
        funding_signature: Vec::new(),
        proof_of_possession: Vec::new(),
    };
    tx.tx_bytes = tx.reserved_tx_bytes();
    // This is a real, encoded genesis allocation; no state injection or
    // fabricated client input value funds the positive node rehearsal.
    engine.manifest.genesis_time_ms = now_ms().saturating_sub(500_000);
    engine
        .manifest
        .allocations
        .push(crate::genesis::GenesisAllocation {
            purpose: crate::genesis::alloc_purpose::LIQUIDITY,
            script_hash: Sha3_256::digest(&funding.pubkey).into(),
            amount_sat: tx.required_funding_sat().unwrap(),
            unlock_epoch: 0,
        });
    let opening = engine.manifest.opening_balances();
    tx.inputs[0] = FundingInput {
        txid: opening[0].txid,
        vout: opening[0].vout,
    };
    engine.state = StateCell::new(engine.manifest.genesis_state());
    tx.network_domain = engine.state.admission_network_domain().unwrap();
    authorize(&mut tx, &funding, &joining);
    (engine, dir, funding, joining, tx)
}

#[test]
fn real_pq_admission_requires_both_algorithms_for_both_roles() {
    let (_engine, _dir, funding, joining, tx) = fixture();
    assert_eq!(funding.pubkey.len(), ADMISSION_PQ_KEY_BYTES);
    assert_eq!(joining.pubkey.len(), ADMISSION_PQ_KEY_BYTES);
    assert!(tx.funding_signature.len() <= ADMISSION_PQ_SIGNATURE_MAX);
    assert!(tx.proof_of_possession.len() <= ADMISSION_PQ_SIGNATURE_MAX);
    tx.verify_authorizations(&HybridVerifier::new()).unwrap();
    for role in [false, true] {
        for offset in [14, 4 + 3309 + 10] {
            let mut attack = tx.clone();
            let sig = if role {
                &mut attack.funding_signature
            } else {
                &mut attack.proof_of_possession
            };
            sig[offset] ^= 1;
            assert!(attack
                .verify_authorizations(&HybridVerifier::new())
                .is_err());
        }
    }
    let mut single = tx.clone();
    single.validator_pubkey[2] = 2;
    assert!(single
        .verify_authorizations(&HybridVerifier::new())
        .is_err());
    let mut substituted = tx.clone();
    substituted.withdrawal_credentials[0] ^= 1;
    // Re-signing one role does not authorize a change for the other role.
    substituted.proof_of_possession = joining.sign(&substituted.possession_root());
    assert!(substituted
        .verify_authorizations(&HybridVerifier::new())
        .is_err());
    assert_eq!(
        PosTransaction::from_canonical_bytes(&tx.canonical_bytes()),
        Ok(PosTransaction::FundedDeposit(tx))
    );
}

#[test]
fn funded_mempool_gate_source_outpoints_and_budget_are_wired() {
    let (mut engine, _dir, _funding, _joining, tx) = fixture();
    let wire = PosTransaction::FundedDeposit(tx.clone());
    assert_eq!(tx_tip_rate(&wire), tx.tip_millisat_per_gas);
    assert_eq!(
        tx_source_hash(&wire),
        Some(Sha3_256::digest(&tx.funding_pubkey).into())
    );
    assert_eq!(
        Engine::spent_outpoints(&wire),
        Some(vec![(tx.inputs[0].txid, tx.inputs[0].vout)])
    );
    assert!(admissible(&wire, 0)
        .unwrap_err()
        .contains("FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH"));
    let result = engine.on_transaction(wire);
    assert!(matches!(result, Err(Refusal::Invalid(_))));
    assert!(engine.mempool.is_empty());
    let terms = engine
        .serve_rpc(RpcRequest::ValidatorAdmission)
        .unwrap()
        .to_string();
    assert!(terms.contains("\"active\":false"));
    assert!(terms.contains("\"activation_epoch\":null"));
    assert!(terms.contains(&crate::codec::hex(&tx.network_domain)));
}

#[test]
fn admission_domain_distinguishes_legacy_geneses_with_different_clocks() {
    let (engine, _dir, _funding, _joining, _) = fixture();
    let mut other = Manifest::decode(&engine.manifest.encode()).unwrap();
    other.slot_ms += 1;
    assert_eq!(
        other.genesis_id(),
        engine.manifest.genesis_id(),
        "v1 historically shared a block id"
    );
    assert_ne!(
        other.genesis_state().admission_network_domain(),
        engine.state.admission_network_domain()
    );
    let st = engine.manifest.genesis_state();
    assert_eq!(
        st.state_root(),
        engine.state.state_root(),
        "network context does not change historical roots"
    );
}

/// Compiled and executed by scripts/rehearse-validator-admission.py in an
/// isolated source copy with only the new activation constant set to epoch 0.
/// The shipping binary has no runtime switch that could enable this path.
#[test]
#[ignore = "requires isolated compile-time activation rehearsal"]
fn funded_validator_two_nodes_rehearsal() {
    assert!(bloch_pos_committee::params::funded_validator_admission_active(0));
    let (mut founder, _founder_dir, funding, joining, tx) = fixture();
    let (mut joiner, joiner_dir) = perf_support::proposing_engine();
    joiner.manifest = Manifest::decode(&founder.manifest.encode()).unwrap();
    joiner.state = StateCell::new(joiner.manifest.genesis_state());
    joiner.chain = vec![(0, joiner.manifest.genesis_id())];
    joiner.canonical = BTreeSet::from([*joiner.manifest.genesis_id().as_bytes()]);
    joiner.keys = Some(joining);
    let binding = crate::slashprot::Binding {
        validator_pubkey_sha3: Sha3_256::digest(&tx.validator_pubkey).into(),
        genesis_digest: tx.network_domain,
    };
    joiner.slashprot = SlashingProtection::open_bound(&joiner_dir.0, binding).unwrap();
    assert_eq!(joiner.duty_index(&joiner.state), None);
    let mut invalid = tx.clone();
    invalid.proof_of_possession[100] ^= 1;
    assert!(founder
        .on_transaction(PosTransaction::FundedDeposit(invalid))
        .is_err());
    let mut wrong_network = tx.clone();
    wrong_network.network_domain[0] ^= 1;
    authorize(&mut wrong_network, &funding, joiner.keys.as_ref().unwrap());
    assert!(founder
        .on_transaction(PosTransaction::FundedDeposit(wrong_network))
        .is_err());
    assert!(founder
        .on_transaction(PosTransaction::FundedDeposit(tx.clone()))
        .is_ok());
    let mut saw_joiner_propose = false;
    let mut saw_joiner_attest = false;
    let mut history = Vec::new();
    for slot in 1..=410u64 {
        founder.wall_slot = slot;
        joiner.wall_slot = slot;
        let before = founder.head_id();
        founder.propose(slot);
        if founder.head_id() != before {
            let env = founder.blocks[founder.head_id().as_bytes()].clone();
            history.push(env.clone());
            joiner.ingest(env);
        } else {
            joiner.propose(slot);
            if joiner.head_id() != before {
                let env = joiner.blocks[joiner.head_id().as_bytes()].clone();
                saw_joiner_propose |= env.header.proposer_index == 1;
                history.push(env.clone());
                founder.ingest(env);
            }
        }
        assert_eq!(
            founder.head_id(),
            joiner.head_id(),
            "node heads diverged at {slot}"
        );
        assert_eq!(founder.state.state_root(), joiner.state.state_root());
        if slot < 8 * SLOTS_PER_EPOCH {
            assert!(!saw_joiner_propose);
            assert!(!joiner
                .state
                .active_validators()
                .iter()
                .any(|v| v.index == 1));
        }
        if slot >= 8 * SLOTS_PER_EPOCH {
            joiner.attest(slot);
            saw_joiner_attest |= joiner.pool.values().any(|a| a.validator == 1);
        }
    }
    assert!(saw_joiner_propose && saw_joiner_attest);
    assert_eq!(joiner.duty_index(&joiner.state), Some(1));
    let hash: [u8; 32] = Sha3_256::digest(&tx.validator_pubkey).into();
    let by_key = joiner
        .serve_rpc(RpcRequest::ValidatorByKey(hash))
        .unwrap()
        .to_string();
    assert!(by_key.contains("\"index\":1"));
    assert!(by_key.contains("\"state\":\"active\""));
    let (mut replay, _replay_dir) = perf_support::proposing_engine();
    replay.manifest = Manifest::decode(&founder.manifest.encode()).unwrap();
    replay.state = StateCell::new(replay.manifest.genesis_state());
    replay.chain = vec![(0, replay.manifest.genesis_id())];
    replay.canonical = BTreeSet::from([*replay.manifest.genesis_id().as_bytes()]);
    replay.keys = None;
    for env in history {
        replay.ingest_replay(env);
    }
    assert_eq!(replay.state.state_root(), joiner.state.state_root());
    let keys = joiner.keys.as_ref().unwrap();
    assert_eq!(
        check_joining_registry_identity(&replay.state, 1, &keys.pubkey, keys.randao_seed),
        RegistryIdentity::Active
    );
    let wm = joiner.slashprot.watermarks();
    let mut restored = SlashingProtection::open_bound(&joiner_dir.0, binding).unwrap();
    assert!(restored
        .guard_proposal(wm.proposal_slot.unwrap(), || panic!("must not sign twice"))
        .is_err());
    assert_eq!(restored.watermarks(), wm);
    let mut other_binding = binding;
    other_binding.validator_pubkey_sha3[0] ^= 1;
    assert!(SlashingProtection::open_bound(&joiner_dir.0, other_binding).is_err());
}
