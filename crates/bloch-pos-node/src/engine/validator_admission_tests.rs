// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::codec;
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


/// Exercise the separately built CLI against the payout created by this rehearsal.
/// All private material is freshly generated disposable devnet material.
fn payout_from_cli(dir: &std::path::Path, funding: &Keystore,
    paid: &bloch_pos_committee::state_root::EutxoEntry, base_fee: u128, epoch: u64) -> PosTransaction {
    use std::io::Write;
    let binary = std::env::var_os("BLOCH_PAYOUT_TEST_BIN")
        .expect("run through scripts/rehearse-validator-admission.py to build the matching CLI");
    let work = dir.join("payout-cli");
    std::fs::create_dir(&work).unwrap();
    let keystore = work.join("sealed-withdrawal");
    let pass = "disposable lifecycle payout rehearsal passphrase";
    funding.save_with(&keystore, &Unlock::passphrase(pass)).unwrap();
    let passfile = work.join("passphrase");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    options.open(&passfile).unwrap().write_all(pass.as_bytes()).unwrap();
    let public = work.join("withdrawal.pub.hex");
    std::fs::write(&public, codec::hex(&funding.pubkey)).unwrap();
    let draft = work.join("draft.hex");
    let ready = work.join("ready.hex");
    let common = vec!["--validator".to_owned(), "1".into(), "--input-value".into(), paid.value.to_string(),
        "--withdrawal-script".into(), codec::hex(&paid.script_hash), "--destination".into(), codec::hex(&[0x94;32]),
        "--base-fee".into(), base_fee.to_string(), "--epoch".into(), epoch.to_string(),
        "--max-fee".into(), (paid.value - 1).to_string()];
    let path = |p: &std::path::Path| p.to_str().unwrap().to_owned();
    let invoke = |command: &str, extra: Vec<String>| {
        let result = std::process::Command::new(&binary).arg("validator-payout").arg(command)
            .args(&common).args(extra)
            .env_remove("BLOCH_KEYSTORE_PASSPHRASE").env_remove("BLOCH_KEYSTORE_ALLOW_PLAINTEXT")
            .env("BLOCH_KEYSTORE_PASSPHRASE_FILE", &passfile).output().unwrap();
        assert!(result.status.success(), "CLI {command}: {}", String::from_utf8_lossy(&result.stderr));
    };
    let read = |p: &std::path::Path| PosTransaction::from_canonical_bytes(
        &codec::unhex(std::fs::read_to_string(p).unwrap().trim()).unwrap()).unwrap();
    invoke("prepare", vec!["--pubkey".into(), path(&public), "--tip".into(), "5".into(), "--out".into(), path(&draft)]);
    invoke("inspect", vec!["--tx".into(), path(&draft)]);
    let unsigned = read(&draft);
    invoke("sign", vec!["--tx".into(), path(&draft), "--dir".into(), path(&keystore),
        "--expected-root".into(), codec::hex(&unsigned.checked_signing_root(epoch)), "--out".into(), path(&ready)]);
    invoke("inspect", vec!["--tx".into(), path(&ready)]);
    let signed = read(&ready);
    assert_eq!(unsigned.txid(), signed.txid());
    assert_eq!(signed.canonical_bytes()[0], 0x06);
    signed
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
#[ignore = "exports fresh throwaway identities for the isolated joining network rehearsal"]
fn funded_joining_network_fixture() {
    let activation = bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH;
    assert!((2..=16).contains(&activation), "use an isolated finite-gate build");
    let out = std::path::PathBuf::from(std::env::var_os("BLOCH_JOINING_NETWORK_FIXTURE").unwrap());
    std::fs::create_dir(&out).unwrap();
    let (mut founder, _dir, funding, joining, mut deposit) = fixture();
    founder.manifest.genesis_time_ms = now_ms() + 20_000;
    founder.manifest.slot_ms = 500;
    founder.manifest.pre_state_root = std::sync::OnceLock::new();
    let state = founder.manifest.genesis_state();
    deposit.network_domain = state.admission_network_domain().unwrap();
    let opening = founder.manifest.opening_balances();
    deposit.inputs[0] = FundingInput { txid: opening[0].txid, vout: opening[0].vout };
    authorize(&mut deposit, &funding, &joining);
    for name in ["founder", "joining"] { std::fs::create_dir(out.join(name)).unwrap(); }
    founder.keys.as_ref().unwrap().save_with(&out.join("founder"), &Unlock::PlaintextOptIn).unwrap();
    joining.save_with(&out.join("joining"), &Unlock::PlaintextOptIn).unwrap();
    std::fs::write(out.join("genesis.bin"), founder.manifest.encode()).unwrap();
    std::fs::write(out.join("deposit.bin"), PosTransaction::FundedDeposit(deposit).canonical_bytes()).unwrap();
}

#[test]
#[ignore = "checks committed public logs from the isolated joining network rehearsal"]
fn funded_joining_network_evidence() {
    let out = std::path::PathBuf::from(std::env::var_os("BLOCH_JOINING_NETWORK_FIXTURE").unwrap());
    let (_manifest, digest) = Manifest::load(&out.join("genesis.bin")).unwrap();
    for name in ["founder", "joining"] {
        let store = Store::open(&out.join(name), &digest).unwrap();
        let blocks = store.read_all().unwrap();
        assert!(blocks.iter().any(|b| b.header.proposer_index == 1),
                "the new identity's proposal must be committed by {name}");
        assert!(blocks.iter().any(|b| b.body.attestations.iter().any(|a| a.validator == 1)),
                "the new identity's attestation must be included in {name}'s committed history");
    }
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
    assert!(terms.contains(&format!("\"activation_epoch\":{}", bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH)));
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
    {
        let _clock = super::validator_lifecycle::clock_at(1);
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
        assert!(matches!(
            founder.on_transaction(PosTransaction::FundedDeposit(tx.clone())),
            Err(Refusal::LifecycleVerificationLimited { until_slot: 2 })
        ));
    }
    {
        let _clock = super::validator_lifecycle::clock_at(2);
        assert!(founder
            .on_transaction(PosTransaction::FundedDeposit(tx.clone()))
            .is_ok());
    }
    let mut saw_joiner_propose = false;
    let mut saw_joiner_attest = false;
    let mut history = Vec::new();
    let mut exit_slot = None;
    // Selection is stake-weighted and uses fresh keys. Wait for an actual
    // joining proposer instead of assuming one appears in a fixed 154-slot
    // window. The bound remains below one full RANDAO chain.
    for slot in 2..=4096u64 {
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
    let exit_epoch = epoch_of(exit_slot);
    let root = staking::ExitTx { pubkey_hash: hash, epoch: exit_epoch, signature: Vec::new() }.signing_root();
    let exit = PosTransaction::ExitV2 { pubkey_hash: hash, epoch: exit_epoch,
        signature: joiner.keys.as_ref().unwrap().sign(&root) };
    {
        let _clock = super::validator_lifecycle::clock_at(exit_slot);
        for offset in [14, 4 + 3309 + 10] {
            let mut forged = exit.clone();
            if let PosTransaction::ExitV2 { signature, .. } = &mut forged { signature[offset] ^= 1; }
            assert!(founder.on_transaction(forged).is_err());
        }
        assert!(matches!(
            founder.on_transaction(exit.clone()),
            Err(Refusal::LifecycleVerificationLimited { until_slot }) if until_slot == exit_slot + 1
        ));
    }
    let exit_admission_slot = exit_slot + 1;
    {
        let _clock = super::validator_lifecycle::clock_at(exit_admission_slot);
        founder.on_transaction(exit.clone()).unwrap();
        joiner.on_transaction(exit).unwrap();
    }
    drive_pair(&mut founder, &mut joiner, exit_admission_slot, &mut history);
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
    {
        let _clock = super::validator_lifecycle::clock_at(exit_admission_slot + 1);
        let _ = founder.ingest_judged(conflicting);
        assert!(founder.mempool.values().any(|tx| matches!(tx, PosTransaction::SlashingEvidence(_))));
    }
    drive_pair(&mut founder, &mut joiner, exit_admission_slot + 1, &mut history);
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
    assert_eq!(
        founder.on_transaction(withdrawal.clone()),
        Ok(Admitted::Duplicate),
        "included withdrawal is classified as an already-committed duplicate"
    );
    assert!(
        !founder.mempool.has_txid(&withdrawal.txid()),
        "included withdrawal is not reinserted into the pending pool"
    );
    let spend_slot = maturity * SLOTS_PER_EPOCH + 2;
    let _payout_clock = super::validator_lifecycle::clock_at(spend_slot);
    let spend = payout_from_cli(&_founder_dir.0, &funding, &paid, founder.state.next_base_fee(), epoch_of(spend_slot));
    // Alterations of the signed CLI intent must fail at the real mempool door.
    for case in 0..3 {
        let mut altered = spend.clone();
        if let PosTransaction::TransferV2 { keys, outputs, .. } = &mut altered {
            match case {
                0 => outputs[0].script_hash[0] ^= 1,
                1 => outputs[0].value -= 1,
                _ => keys[0].signature[20] ^= 1,
            }
        }
        let refusal = founder.on_transaction(altered).unwrap_err();
        let expected = if case == 1 {
            "transfer value is not conserved at the current base fee"
        } else {
            "signature that does not verify"
        };
        assert!(format!("{refusal:?}").contains(expected), "{refusal:?}");
    }
    let _clock = super::validator_lifecycle::clock_at(maturity * SLOTS_PER_EPOCH + 2);
    founder.on_transaction(spend.clone()).unwrap();
    drive_pair(&mut founder, &mut joiner, maturity * SLOTS_PER_EPOCH + 2, &mut history);
    assert!(founder.state.utxo(&withdrawal.txid(), 0).is_none());
    assert!(founder.state.utxo(&spend.txid(), 0).is_some());
    let spend_block = founder.head_id();
    for epoch in maturity + 1..=maturity + 4 {
        drive_pair(&mut founder, &mut joiner, epoch * SLOTS_PER_EPOCH, &mut history);
    }
    assert!(founder.state.finality().finalized.epoch > epoch_of(spend_slot), "payout spend must finalize");
    assert!(founder.chain.iter().any(|(_, id)| *id == spend_block));
    println!("PAYOUT_CLI_EVIDENCE {{\"deposit_txid\":\"{}\",\"withdrawal_txid\":\"{}\",\"spend_txid\":\"{}\",\"spend_slot\":{},\"spend_block\":\"{}\",\"head_block\":\"{}\",\"state_root\":\"{}\",\"finalized_epoch\":{},\"finalized_root\":\"{}\"}}",
        codec::hex(&PosTransaction::FundedDeposit(tx.clone()).txid()), codec::hex(&withdrawal.txid()), codec::hex(&spend.txid()),
        spend_slot, codec::hex(spend_block.as_bytes()), codec::hex(founder.head_id().as_bytes()), codec::hex(&founder.state.state_root()),
        founder.state.finality().finalized.epoch, codec::hex(&founder.state.finality().finalized.root));
    let (mut replay, _replay_dir) = perf_support::proposing_engine();
    replay.manifest = Manifest::decode(&founder.manifest.encode()).unwrap();
    replay.state = StateCell::new(replay.manifest.genesis_state());
    replay.chain = vec![(0, replay.manifest.genesis_id())];
    replay.canonical = BTreeSet::from([*replay.manifest.genesis_id().as_bytes()]);
    replay.keys = None;
    for env in history {
        assert!(replay.ingest_replay(env));
    }
    assert_eq!(replay.state.state_root(), joiner.state.state_root());
    println!("PAYOUT_CLI_REPLAY_VERIFIED {}", codec::hex(&replay.state.state_root()));
    let keys = joiner.keys.as_ref().unwrap();
    assert_eq!(
        check_registry_identity(&replay.state, 1, &keys.pubkey, keys.randao_seed),
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

/// Exercise a finite flag day under the already-active consensus regime.
#[test]
#[ignore = "requires isolated finite-epoch activation rehearsal"]
fn funded_activation_boundary_rehearsal() {
    let activation = bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH;
    assert!((1..=16).contains(&activation), "use the isolated activation script");
    let boundary = activation * SLOTS_PER_EPOCH;
    let (mut founder, _dir, _funding, _joining, deposit) = fixture();
    let (mut observer, _observer_dir) = perf_support::proposing_engine();
    observer.manifest = Manifest::decode(&founder.manifest.encode()).unwrap();
    observer.state = StateCell::new(observer.manifest.genesis_state());
    observer.chain = vec![(0, observer.manifest.genesis_id())];
    observer.canonical = BTreeSet::from([*observer.manifest.genesis_id().as_bytes()]);
    observer.keys = None;
    let tx = PosTransaction::FundedDeposit(deposit);
    let mut history = Vec::new();
    for slot in 1..boundary {
        assert!(founder.on_transaction(tx.clone()).is_err());
        drive_pair(&mut founder, &mut observer, slot, &mut history);
    }
    // Advancing a local clock must not open admission before the committed
    // head crosses L. State-aware validation shares the consensus gate.
    let _clock = super::validator_lifecycle::clock_at(boundary);
    founder.wall_slot = boundary;
    let before = founder.state.state_root();
    assert!(founder.on_transaction(tx.clone()).is_err());
    assert!(founder.state.validate_lifecycle_transaction(
        &tx, founder.state.total_active_stake_sat(), founder.state.next_base_fee(),
        &HybridVerifier::new(),
    ).is_err());
    assert_eq!(founder.state.state_root(), before);
    assert!(founder.state.validator_record(1).is_none());
    drive_pair(&mut founder, &mut observer, boundary, &mut history);
    assert!(founder.state.validate_lifecycle_transaction(
        &tx, founder.state.total_active_stake_sat(), founder.state.next_base_fee(),
        &HybridVerifier::new(),
    ).is_ok());
    founder.on_transaction(tx.clone()).unwrap();
    drive_pair(&mut founder, &mut observer, boundary + 1, &mut history);
    assert!(history.last().unwrap().body.transactions.contains(&tx.canonical_bytes()));
    assert!(founder.state.is_funded_validator(1));
    assert_eq!(founder.state.validator_record(1).unwrap().activation_epoch, u64::MAX);
    assert_eq!(
        founder.on_transaction(tx.clone()),
        Ok(Admitted::Duplicate),
        "included funding is classified as an already-committed duplicate"
    );
    assert!(
        !founder.mempool.has_txid(&tx.txid()),
        "included funding is not reinserted into the pending pool"
    );
    let (mut replay, _replay_dir) = perf_support::proposing_engine();
    replay.manifest = Manifest::decode(&founder.manifest.encode()).unwrap();
    replay.state = StateCell::new(replay.manifest.genesis_state());
    replay.chain = vec![(0, replay.manifest.genesis_id())];
    replay.canonical = BTreeSet::from([*replay.manifest.genesis_id().as_bytes()]);
    replay.keys = None;
    if let Some(path) = std::env::var_os("BLOCH_ACTIVATION_FIXTURE") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("genesis.bin"), founder.manifest.encode()).unwrap();
        for envelope in history.iter().filter(|e| e.header.slot < boundary) {
            std::fs::write(path.join(format!("{:016}.block", envelope.header.slot)),
                           crate::codec::encode_envelope(envelope)).unwrap();
        }
    }
    for envelope in history { assert!(replay.ingest_replay(envelope)); }
    assert_eq!(replay.head_id(), founder.head_id());
    assert_eq!(replay.state.state_root(), founder.state.state_root());
    assert!(replay.state.is_funded_validator(1));
}

#[test]
#[ignore = "requires public blocks exported by the finite activation rehearsal"]
fn funded_pre_activation_compatibility_rehearsal() {
    assert_eq!(bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH, u64::MAX);
    let path = std::path::PathBuf::from(std::env::var_os("BLOCH_ACTIVATION_FIXTURE").unwrap());
    let activation: u64 = std::env::var("BLOCH_ACTIVATION_TEST_EPOCH").unwrap().parse().unwrap();
    assert!((2..=16).contains(&activation));
    let (mut replay, _dir) = perf_support::proposing_engine();
    replay.manifest = Manifest::decode(&std::fs::read(path.join("genesis.bin")).unwrap()).unwrap();
    replay.state = StateCell::new(replay.manifest.genesis_state());
    replay.chain = vec![(0, replay.manifest.genesis_id())];
    replay.canonical = BTreeSet::from([*replay.manifest.genesis_id().as_bytes()]);
    replay.keys = None;
    let mut blocks: Vec<_> = std::fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "block")).collect();
    blocks.sort();
    assert_eq!(blocks.len() as u64, activation * SLOTS_PER_EPOCH - 1);
    for path in blocks {
        let envelope = crate::codec::decode_envelope(&std::fs::read(path).unwrap()).unwrap();
        assert!(epoch_of(envelope.header.slot) < activation);
        let root = envelope.header.state_root;
        let slot = envelope.header.slot;
        assert!(replay.ingest_replay(envelope));
        assert_eq!(replay.state.slot(), slot);
        assert_eq!(replay.state.state_root(), root,
                   "unarmed and armed builds must agree below L at slot {slot}");
    }
    assert!(replay.state.validator_record(1).is_none());
}

/// Advance separate engines through signed blocks and runtime admission paths.
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
    assert_eq!(bloch_pos_committee::params::RANDAO_CHAIN_LENGTH, 16);
    let (mut first, _dir, _funding, joining, _) = fixture();
    let mut record = first.manifest.validators[0].clone();
    record.index = 1;
    record.pubkey = joining.pubkey.clone();
    record.randao_commitment = RandaoChain::generate(joining.randao_seed).commitment();
    first.manifest.validators.push(record);
    // audit LD-05, 2026-09-17: the fixture seeds `genesis_time_ms` from the
    // wall clock, and under `V2Bound` the genesis mix folds it, so every run
    // drew a different proposer schedule. Some schedules spend both 16-reveal
    // chains in the same slot, and a renewal can only be submitted once a
    // chain is fully spent and only be included by a proposer that still has
    // a reveal — nobody is left, and the rehearsal failed at random (CI,
    // 2026-09-17). A pinned genesis time makes the schedule a fixture, not a
    // lottery; the simultaneous-exhaustion corner itself is a consensus
    // precondition (`transition.rs` `apply_randao_recommit`) and is tracked
    // as LD-05 in docs/audit/deep-audit-2026-09-16/A12-dynamic.md. The wall
    // slot is injected by `clock_at`, so the manifest's clock is inert here.
    first.manifest.genesis_time_ms = 1_700_000_000_000;
    first.genesis_validator_indices = BTreeSet::from([0, 1]);
    first.state = StateCell::new(first.manifest.genesis_state());
    first.chain = vec![(0, first.manifest.genesis_id())];
    first.canonical = BTreeSet::from([*first.manifest.genesis_id().as_bytes()]);
    let (mut second, _second_dir) = perf_support::proposing_engine();
    second.manifest = Manifest::decode(&first.manifest.encode()).unwrap();
    second.genesis_validator_indices = BTreeSet::from([0, 1]);
    second.state = StateCell::new(second.manifest.genesis_state());
    second.chain = first.chain.clone();
    second.canonical = first.canonical.clone();
    second.keys = Some(joining);
    // Match production's identity-bound durable signer initialization.
    for (engine, directory) in [(&mut first, &_dir.0), (&mut second, &_second_dir.0)] {
        let keys = engine.keys.as_ref().unwrap();
        engine.slashprot = SlashingProtection::open_bound(directory, crate::slashprot::Binding {
            validator_pubkey_sha3: <sha3::Sha3_256 as sha3::Digest>::digest(&keys.pubkey).into(),
            genesis_digest: <sha3::Sha3_256 as sha3::Digest>::digest(engine.manifest.encode()).into(),
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
        assert_eq!(check_registry_identity(&replay, index, &keys.pubkey, seed), RegistryIdentity::Active);
        assert_eq!(check_registry_identity(&replay, index, &keys.pubkey, keys.randao_seed), RegistryIdentity::RandaoMismatch);
    }
}

#[test]
fn proposal_selection_keeps_inactive_funded_candidates_out_without_mutation() {
    assert!(10 < bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH);
    let (mut engine, _dir, _funding, _joining, tx) = fixture();
    for expiry in [100, 101, 102] {
        let mut candidate = tx.clone();
        candidate.valid_until_epoch = expiry;
        let candidate = PosTransaction::FundedDeposit(candidate);
        engine.mempool.insert(candidate.canonical_bytes(), candidate);
    }
    let root = engine.state.state_root();
    assert!(engine.select_transactions(10).is_empty());
    assert_eq!(engine.mempool.len(), 3);
    assert_eq!(engine.state.state_root(), root);
    assert!(engine.rejected.is_empty());
}

#[test]
fn active_funded_proposal_selection_uses_actual_gate_and_filters_conflicting_intents() {
    let activation = bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH;
    assert_eq!(activation, 2_884);
    let (mut engine, _dir, funding, joining, mut first) = fixture();
    first.valid_until_epoch = activation.saturating_add(100);
    authorize(&mut first, &funding, &joining);
    let mut alternative = first.clone();
    alternative.valid_until_epoch = alternative.valid_until_epoch.saturating_add(1);
    authorize(&mut alternative, &funding, &joining);
    let first = PosTransaction::FundedDeposit(first);
    let alternative = PosTransaction::FundedDeposit(alternative);
    let rolled = engine.rolled_to(activation);
    let total = rolled.active_validators().iter().map(|v| u128::from(v.effective_stake)).sum();
    let price = engine.state.next_base_fee_at(activation);
    for candidate in [&first, &alternative] {
        assert!(rolled.validate_lifecycle_transaction(candidate, total, price, &engine.verifier).is_ok(),
            "each real signed funded candidate must be independently valid at the actual activation epoch");
        engine.mempool.insert(candidate.canonical_bytes(), candidate.clone());
    }
    let selected = engine.select_transactions(activation);
    assert_eq!(selected.len(), 1, "shared inputs cannot be spent by both independently valid intents");
    assert!(selected.contains(&first) || selected.contains(&alternative));
    assert_eq!(engine.select_transactions(activation), selected, "reusing the cached epoch view must preserve selection");
    assert_eq!(engine.mempool.len(), 2, "conflicting intent selection is not eviction");
    assert!(engine.rejected.is_empty());
}

#[test]
fn admission_negative_cache_funded_authorization_remains_retryable_at_actual_gate() {
    let activation = bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH;
    assert_eq!(activation, 2_884);
    let (engine, _dir, funding, joining, mut deposit) = fixture();
    deposit.valid_until_epoch = activation + 100;
    authorize(&mut deposit, &funding, &joining);
    let valid = PosTransaction::FundedDeposit(deposit.clone());
    let (verifier, calls) = verification::counted_hybrid();
    assert!(admissible_with_verifier(&valid, activation - 1, &verifier).is_err());
    assert!(admissible_with_verifier(&valid, deposit.valid_until_epoch + 1, &verifier).is_err());
    assert_eq!(calls.get(), 0, "epoch/expiry refusals must not become cached crypto failures");
    let rolled = engine.rolled_to(activation);
    let total = rolled.active_validators().iter().map(|v| u128::from(v.effective_stake)).sum();
    let base_fee = engine.state.next_base_fee_at(activation);
    let stateful = |tx: &PosTransaction| {
        rolled.validate_lifecycle_transaction(tx, total, base_fee, &verifier)
    };
    let mut forged = deposit.clone();
    let last = forged.funding_signature.last_mut().unwrap();
    *last ^= 1;
    let forged = PosTransaction::FundedDeposit(forged);
    for _ in 0..16 { assert!(stateful(&forged).is_err()); }
    assert_eq!(calls.get(), 1);
    assert!(stateful(&valid).is_ok());
    assert_eq!(calls.get(), 3, "corrected funding signature and joining proof must both run");
    let mut changed = deposit.clone();
    changed.valid_until_epoch += 1;
    assert!(stateful(&PosTransaction::FundedDeposit(changed.clone())).is_err());
    assert_eq!(calls.get(), 4, "a changed funding root must not reuse old verification");
    authorize(&mut changed, &funding, &joining);
    let changed = PosTransaction::FundedDeposit(changed);
    assert!(stateful(&changed).is_ok());
    assert_eq!(calls.get(), 6);
    assert!(stateful(&changed).is_ok(),
        "the corrected real funded candidate must still pass state validation at epoch2884");
    assert_eq!(admissible(&changed, activation), admissible_with_verifier(&changed, activation, &verifier));
    let next_joining = Keystore::generate_with(&_dir.0.join("next-joining"), AUTO_VALIDATOR_INDEX, &Unlock::PlaintextOptIn).unwrap();
    let mut other_key = deposit;
    other_key.validator_pubkey = next_joining.pubkey.clone();
    other_key.randao_commitment = RandaoChain::generate(next_joining.randao_seed).commitment();
    let before = calls.get();
    assert!(stateful(&PosTransaction::FundedDeposit(other_key.clone())).is_err());
    assert!(calls.get() > before, "a different joining key/root must receive its own crypto check");
    authorize(&mut other_key, &funding, &next_joining);
    let other_key = PosTransaction::FundedDeposit(other_key);
    assert!(admissible_with_verifier(&other_key, activation, &verifier).is_ok());
    assert!(stateful(&other_key).is_ok());
}
