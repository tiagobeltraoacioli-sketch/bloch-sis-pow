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
        withdrawal_credentials: Sha3_256::digest(&funding.pubkey).into(),
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
/// isolated source copy with the five lifecycle constants set to epoch 0.
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
    let mut exit_slot = None;
    // Selection is stake-weighted and uses fresh keys. Wait for an actual
    // joining proposer instead of assuming one appears in a fixed 154-slot
    // window. The bound remains below one full RANDAO chain.
    for slot in 1..=4096u64 {
        let _clock = super::validator_lifecycle::clock_at(slot);
        founder.wall_slot = slot;
        joiner.wall_slot = slot;
        // Exchange real signed attestations so funding becomes finalized
        // before the new key is permitted to join the active roster.
        founder.attest(slot);
        joiner.attest(slot);
        let votes: Vec<_> = founder.pool.values().chain(joiner.pool.values()).cloned().collect();
        saw_joiner_attest |= votes.iter().any(|att| att.validator == 1);
        for att in votes {
            founder.on_attestation(att.clone(), Origin::none(), epoch_of(slot));
            joiner.on_attestation(att, Origin::none(), epoch_of(slot));
        }
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
        if slot >= 410
            && slot % SLOTS_PER_EPOCH < SLOTS_PER_EPOCH - 2
            && history.last().is_some_and(|env| env.header.slot == slot && env.header.proposer_index == 1)
            && history.iter().any(|env| env.body.attestations.iter().any(|att| att.validator == 1))
        {
            exit_slot = Some(slot + 1);
            break;
        }
    }
    let exit_slot = exit_slot.expect("joining validator must propose and have an included attestation");
    assert!(saw_joiner_propose && saw_joiner_attest);
    assert!(history.iter().any(|env| env.body.attestations.iter().any(|att| att.validator == 1)),
        "a new validator's real PQ attestation must be included, not merely produced");
    assert_eq!(joiner.duty_index(&joiner.state), Some(1));
    let hash: [u8; 32] = Sha3_256::digest(&tx.validator_pubkey).into();
    let by_key = joiner
        .serve_rpc(RpcRequest::ValidatorByKey(hash))
        .unwrap()
        .to_string();
    assert!(by_key.contains("\"index\":1"));
    assert!(by_key.contains("\"state\":\"active\""));
    // Exit is authorized by both PQ algorithms and is valid only for the
    // current inclusion epoch. Funding authority cannot sign a validator exit.
    let _clock = super::validator_lifecycle::clock_at(exit_slot);
    let exit_epoch = epoch_of(exit_slot);
    let root = staking::ExitTx { pubkey_hash: hash, epoch: exit_epoch, signature: Vec::new() }.signing_root();
    let exit = PosTransaction::ExitV2 { pubkey_hash: hash, epoch: exit_epoch,
        signature: joiner.keys.as_ref().unwrap().sign(&root) };
    for offset in [14, 4 + 3309 + 10] {
        let mut forged = exit.clone();
        if let PosTransaction::ExitV2 { signature, .. } = &mut forged { signature[offset] ^= 1; }
        assert!(founder.on_transaction(forged).is_err());
    }
    founder.on_transaction(exit.clone()).unwrap();
    joiner.on_transaction(exit).unwrap();
    drive_pair(&mut founder, &mut joiner, exit_slot, &mut history);
    let rec = founder.state.validator_record(1).unwrap();
    assert_eq!(rec.exit_epoch, exit_epoch + staking::EXIT_DELAY_EPOCHS);
    let maturity = rec.withdrawable_epoch;
    let stake_before_slash = rec.staked_sat;
    // Observe a genuine proposer equivocation through the network handler.
    // The second header is signed by the offender but has a conflicting
    // state root; its invalid block must still expose the signed offence.
    let mut conflicting = history.iter().rev().find(|env| env.header.proposer_index == 1).unwrap().clone();
    conflicting.header.state_root[0] ^= 1;
    conflicting.proposer_sig = joiner.keys.as_ref().unwrap().sign(&conflicting.header.proposal_signing_root());
    let _ = founder.ingest_judged(conflicting);
    assert!(founder.mempool.values().any(|tx| matches!(tx, PosTransaction::SlashingEvidence(_))));
    drive_pair(&mut founder, &mut joiner, exit_slot + 1, &mut history);
    let rec = founder.state.validator_record(1).unwrap();
    assert!(rec.slashed);
    assert!(rec.staked_sat < stake_before_slash);
    assert_eq!(rec.withdrawable_epoch, maturity, "slashing cannot shorten the voluntary-exit lock");
    let bonded_residue = rec.staked_sat;
    drive_pair(&mut founder, &mut joiner, rec.exit_epoch * SLOTS_PER_EPOCH, &mut history);
    assert!(!founder.state.active_validators().iter().any(|v| v.index == 1));
    let withdrawal = PosTransaction::Withdraw { validator: 1 };
    // Keep finality progressing through the real 2,048-epoch withdrawal
    // delay. Skipping the entire interval without votes would deliberately
    // leak the only remaining validator to zero under the existing rules.
    for epoch in (rec.exit_epoch + 1)..maturity {
        drive_pair(&mut founder, &mut joiner, epoch * SLOTS_PER_EPOCH, &mut history);
    }
    drive_pair(&mut founder, &mut joiner, maturity * SLOTS_PER_EPOCH - 1, &mut history);
    assert!(founder.on_transaction(withdrawal.clone()).is_err());
    drive_pair(&mut founder, &mut joiner, maturity * SLOTS_PER_EPOCH, &mut history);
    // The operator's node creates the crank automatically once its adopted
    // head reaches maturity; the ordinary transaction path relays it.
    drive_pair(&mut founder, &mut joiner, maturity * SLOTS_PER_EPOCH + 1, &mut history);
    let paid = founder.state.utxo(&withdrawal.txid(), 0).expect("funded bond paid").clone();
    assert!(u128::from(paid.value) >= bonded_residue);
    assert_eq!(paid.script_hash, tx.withdrawal_credentials);
    assert_eq!(founder.state.validator_record(1).unwrap().staked_sat, 0);
    assert!(founder.on_transaction(withdrawal.clone()).is_err());
    let mut spend = PosTransaction::TransferV2 {
        keys: vec![bloch_pos_committee::transition::WitnessKey {
            pubkey: funding.pubkey.clone(), signature: vec![0; ADMISSION_PQ_SIGNATURE_MAX],
        }],
        inputs: vec![bloch_pos_committee::transition::TransferInputV2 { txid: withdrawal.txid(), vout: 0, key_index: 0 }],
        outputs: vec![TransferOutput { value: paid.value, script_hash: [0x94; 32] }],
        tx_bytes: 0, tip_millisat_per_gas: 5,
    };
    let reserved = spend.canonical_bytes().len() as u64;
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, reserved, founder.state.next_base_fee(), 5);
    if let PosTransaction::TransferV2 { tx_bytes, outputs, .. } = &mut spend {
        *tx_bytes = reserved;
        outputs[0].value -= u64::try_from(charge.base_fee_sat + charge.priority_fee_sat).unwrap();
    }
    let root = spend.spend_signing_root();
    if let PosTransaction::TransferV2 { keys, .. } = &mut spend { keys[0].signature = funding.sign(&root); }
    let _clock = super::validator_lifecycle::clock_at(maturity * SLOTS_PER_EPOCH + 2);
    founder.on_transaction(spend.clone()).unwrap();
    drive_pair(&mut founder, &mut joiner, maturity * SLOTS_PER_EPOCH + 2, &mut history);
    assert!(founder.state.utxo(&withdrawal.txid(), 0).is_none());
    assert!(founder.state.utxo(&spend.txid(), 0).is_some());
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
        RegistryIdentity::Inactive
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

/// Advance two separate engine states through actual encoded blocks, signed
/// attestations and the same admission/automatic-action paths as the runtime.
fn drive_pair(a: &mut Engine, b: &mut Engine, slot: u64, history: &mut Vec<BlockEnvelope>) {
    assert!(try_drive_pair(a, b, slot, history), "a proposer must remain live at {slot}");
}

fn try_drive_pair(a: &mut Engine, b: &mut Engine, slot: u64, history: &mut Vec<BlockEnvelope>) -> bool {
    let _clock = super::validator_lifecycle::clock_at(slot);
    a.wall_slot = slot;
    b.wall_slot = slot;
    a.maintain_validator_lifecycle(epoch_of(slot));
    b.maintain_validator_lifecycle(epoch_of(slot));
    a.attest(slot);
    b.attest(slot);
    let votes: Vec<_> = a.pool.values().chain(b.pool.values()).cloned().collect();
    for att in votes {
        a.on_attestation(att.clone(), Origin::none(), epoch_of(slot));
        b.on_attestation(att, Origin::none(), epoch_of(slot));
    }
    let txs: Vec<_> = a.mempool.values().chain(b.mempool.values()).cloned().collect();
    for tx in txs { let _ = a.on_transaction(tx.clone()); let _ = b.on_transaction(tx); }
    let before = a.head_id();
    a.propose(slot);
    if a.head_id() != before {
        let env = a.blocks[a.head_id().as_bytes()].clone();
        history.push(env.clone());
        b.ingest(env);
    } else {
        b.propose(slot);
        if b.head_id() == before { return false; }
        let env = b.blocks[b.head_id().as_bytes()].clone();
        history.push(env.clone());
        a.ingest(env);
    }
    assert_eq!(a.state.slot(), slot);
    assert_eq!(a.head_id(), b.head_id());
    assert_eq!(a.state.state_root(), b.state.state_root());
    true
}

#[test]
#[ignore = "requires isolated compile-time activation rehearsal"]
fn funded_mempool_rejects_invalid_state_rehearsal() {
    let (mut engine, _dir, funding, joining, tx) = fixture();
    for change in 0..3 {
        let mut attack = tx.clone();
        match change {
            0 => attack.inputs[0].txid[0] ^= 1,
            1 => attack.change.value += 1,
            _ => attack.max_base_fee_millisat_per_gas = 0,
        }
        authorize(&mut attack, &funding, &joining);
        assert!(engine.on_transaction(PosTransaction::FundedDeposit(attack)).is_err());
        assert!(engine.mempool.is_empty());
    }
    // Capacity sentinels are never proposed: this isolates whether a signed
    // but unfunded high-tip intent can evict entries before state validation.
    for validator in 0..MEMPOOL_MAX as u32 {
        let held = PosTransaction::Exit { validator };
        engine.mempool.insert(held.canonical_bytes(), held);
    }
    let held: Vec<_> = engine.mempool.keys().cloned().collect();
    let mut missing = tx.clone();
    missing.inputs[0].txid[0] ^= 1;
    authorize(&mut missing, &funding, &joining);
    assert!(engine.on_transaction(PosTransaction::FundedDeposit(missing)).is_err());
    assert_eq!(held, engine.mempool.keys().cloned().collect::<Vec<_>>());
    assert_eq!(engine.mempool_evicted_low_fee, 0);
    engine.mempool.clear();
    engine.on_transaction(PosTransaction::FundedDeposit(tx.clone())).unwrap();
    let mut rival = tx.clone();
    rival.withdrawal_credentials[0] ^= 1;
    authorize(&mut rival, &funding, &joining);
    assert!(engine.on_transaction(PosTransaction::FundedDeposit(rival)).is_err());
    assert_eq!(engine.mempool.len(), 1);
    // Revalidation drops previously valid intents after their UTXO is consumed.
    let _clock = super::validator_lifecycle::clock_at(1);
    engine.wall_slot = 1;
    engine.propose(1);
    assert_eq!(engine.state.validator_count(), 2);
    engine.mempool.insert(tx.canonical_bytes(), PosTransaction::FundedDeposit(tx));
    engine.revalidate_lifecycle_mempool();
    assert!(engine.mempool.is_empty());
}

#[test]
#[ignore = "requires isolated compile-time activation and short RANDAO chains"]
fn randao_automatic_recommit_rehearsal() {
    for exiting in [false, true] {
        rehearse_randao_rotation(exiting);
    }
}

fn rehearse_randao_rotation(exiting: bool) {
    assert_eq!(bloch_pos_committee::params::RANDAO_CHAIN_LENGTH, 16);
    let (mut first, _dir, _funding, joining, _) = fixture();
    let mut record = first.manifest.validators[0].clone();
    record.index = 1;
    record.pubkey = joining.pubkey.clone();
    record.randao_commitment = RandaoChain::generate(joining.randao_seed).commitment();
    first.manifest.validators.push(record);
    first.genesis_validator_count = 2;
    first.state = StateCell::new(first.manifest.genesis_state());
    first.chain = vec![(0, first.manifest.genesis_id())];
    first.canonical = BTreeSet::from([*first.manifest.genesis_id().as_bytes()]);
    let (mut second, _second_dir) = perf_support::proposing_engine();
    second.manifest = Manifest::decode(&first.manifest.encode()).unwrap();
    second.genesis_validator_count = 2;
    second.state = StateCell::new(second.manifest.genesis_state());
    second.chain = first.chain.clone();
    second.canonical = first.canonical.clone();
    second.keys = Some(joining);
    if exiting {
        // A voluntary exit leaves duties active for 32 epochs. Exhausting a
        // chain during that delay must not disable renewal while still active.
        let _clock = super::validator_lifecycle::clock_at(1);
        let keys = first.keys.as_ref().unwrap();
        let mut exit = staking::ExitTx {
            pubkey_hash: Sha3_256::digest(&keys.pubkey).into(),
            epoch: 0,
            signature: Vec::new(),
        };
        exit.signature = keys.sign(&exit.signing_root());
        first.on_transaction(PosTransaction::ExitV2 {
            pubkey_hash: exit.pubkey_hash,
            epoch: exit.epoch,
            signature: exit.signature,
        }).unwrap();
    }
    let mut history = Vec::new();
    let mut produced = 0;
    for slot in 1..=160 { produced += usize::from(try_drive_pair(&mut first, &mut second, slot, &mut history)); }
    // An exhausted validator can miss its draw while another proposer
    // includes its renewal. The network must recover and keep producing.
    assert!(produced >= 120, "renewal must preserve sustained block production");
    assert!(first.state.slot() >= 150);
    for index in [0, 1] {
        assert!(first.state.validator_randao_generation(index) >= 2, "multiple rotations required");
    }
    let mut replay = first.manifest.genesis_state();
    let transition = Transition::new(HybridVerifier::new());
    for env in &history {
        let proposal = ProposalEnvelope { header: env.header.clone(), proposer_sig: env.proposer_sig.clone() };
        replay = transition.apply_block(&replay, &proposal, &env.body.attestations, &body_transactions(env).unwrap()).unwrap();
    }
    assert_eq!(replay.state_root(), first.state.state_root());
    for engine in [&first, &second] {
        let keys = engine.keys.as_ref().unwrap();
        let index = replay.validator_index_by_pubkey(&keys.pubkey).unwrap();
        let seed = keys.randao_seed_for(&replay.admission_network_domain().unwrap(), replay.validator_randao_generation(index));
        assert_eq!(check_joining_registry_identity(&replay, index, &keys.pubkey, seed), RegistryIdentity::Active);
        assert_eq!(check_joining_registry_identity(&replay, index, &keys.pubkey, keys.randao_seed), RegistryIdentity::RandaoMismatch);
    }
}
