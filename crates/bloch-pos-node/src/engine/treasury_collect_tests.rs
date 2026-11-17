// SPDX-License-Identifier: AGPL-3.0-or-later
//! `treasury-collect` against a real `Engine` (private, in-process chain;
//! real hybrid keys and verifier, the real mempool door, the real committee
//! transition inside blocks this node produces).
//!
//! The treasury here is a stand-in of the mainnet one's exact shape: the
//! carried form (20 bytes of SHA3-256 of a THROWAWAY raw legacy key, twelve
//! zero bytes), holding outputs shaped like a crossing fee (150,000 sat at
//! vout 2), a forced-inclusion surcharge (1,000 sat at vout 2), a carryover
//! balance, a dust output, and a genesis allocation bucket; plus a foreign
//! output of another carried key. The owner's key is never used (it cannot
//! be); this shows the rule and the tool, not possession — the same limit
//! agent 335 stated for `r335_a_treasury_output_in_the_carried_form_…`.

use super::*;
use crate::genesis::{alloc_purpose, GenesisAllocation};
use crate::treasury_collect::{agree, parse_chain_info, parse_utxo_page, EndpointSnapshot};
use crate::treasury_spend::{
    build_plan, inspect, protected_outpoints, Exclusion, Intent, Observation,
};
use bloch_crypto::wallet::Keypair;
use bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH as V2_FLAG_DAY;
use bloch_pos_committee::state_root::EutxoEntry;
use bloch_pos_committee::transition::{
    funded::ADMISSION_PQ_SIGNATURE_MAX, TransferInputV2, TransferOutput,
};

/// A legacy (pre-envelope) wallet key, exactly as the founder's wallet holds
/// one: raw public and private halves (`sign-deposit-funding.rs` fixture).
fn legacy(seed: u8) -> Keypair {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[seed; 32]).unwrap();
    let raw = pk[4..].to_vec();
    Keypair {
        private_key: sk[4..].to_vec(),
        public_key: raw.clone(),
        address: bloch_crypto::crypto::address_from_pubkey(&raw, false),
    }
}
fn carried(raw: &[u8]) -> [u8; 32] {
    let h: [u8; 32] = Sha3_256::digest(raw).into();
    let mut s = [0u8; 32];
    s[..20].copy_from_slice(&h[..20]);
    s
}
fn entry(t: u8, vout: u32, value: u64, script: [u8; 32]) -> EutxoEntry {
    EutxoEntry { txid: [t; 32], vout, value, script_hash: script }
}

/// Two reads of this node's RPC answers, under two endpoint names. (One
/// process: the agreement rules themselves are tested with disagreeing
/// snapshots in `treasury_collect::tests`.)
fn observe(engine: &mut Engine, treasury: &[u8; 32]) -> Observation {
    let info = engine.serve_rpc(RpcRequest::ChainInfo).unwrap();
    let page = engine
        .serve_rpc(RpcRequest::Utxos { script_hash: *treasury, limit: 1_000 })
        .unwrap();
    let mempool = engine.serve_rpc(RpcRequest::MempoolInfo).unwrap();
    let base_fee: u128 = mempool
        .get("next_base_fee_millisat_per_gas")
        .and_then(Json::as_str)
        .unwrap()
        .parse()
        .unwrap();
    let snap = |addr: &str| {
        let (read, epoch) = parse_chain_info(addr, &info).unwrap();
        let (total, utxos) = parse_utxo_page(&page, treasury).unwrap();
        EndpointSnapshot { read, epoch, base_fee, total, utxos }
    };
    let digest: [u8; 32] = Sha3_256::digest(engine.manifest.encode()).into();
    let (obs, notes) = agree(*treasury, digest, snap("node-a:16400"), snap("node-b:16400")).unwrap();
    assert!(notes.is_empty());
    // The file round-trips exactly (what the signer reads is what was written).
    assert_eq!(Observation::parse(&obs.encode()).unwrap(), obs);
    obs
}

fn sign(tx: &mut PosTransaction, key: &Keypair, root: &[u8; 32]) {
    let PosTransaction::TransferV2 { keys, .. } = tx else { unreachable!() };
    keys[0].signature = key.sign_fitting(root, ADMISSION_PQ_SIGNATURE_MAX).unwrap();
}

#[test]
fn treasury_collection_spends_carried_outputs_by_the_raw_key_and_refuses_the_rest() {
    let owner = legacy(0x51);
    let stranger = legacy(0x52);
    let t = carried(&owner.public_key);
    let foreign = carried(&stranger.public_key);
    let opening = vec![
        entry(0xa1, 2, 150_000, t),
        entry(0xa2, 2, 1_000, t),
        entry(0xa3, 0, 50_000_000, t),
        entry(0xa4, 0, 5, t),
        entry(0xb1, 0, 70_000, foreign),
    ];
    let (mut engine, _dir) = perf_support::proposing_engine_funded(&opening);
    engine.manifest.allocations.push(GenesisAllocation {
        purpose: alloc_purpose::FOUNDER,
        script_hash: t,
        amount_sat: 3_000_000,
        unlock_epoch: 0,
    });
    engine.state = StateCell::new(engine.manifest.genesis_state());
    let protected = protected_outpoints(&engine.manifest, &t);
    assert_eq!(protected.len(), 1);
    let allocation = *protected.iter().next().unwrap();
    assert!(engine.state.utxo(&allocation.0, allocation.1).is_some());

    super::devnet_tools_tests::drive_to_epoch(&mut engine, V2_FLAG_DAY);
    let slot = V2_FLAG_DAY * SLOTS_PER_EPOCH;
    let _clock = super::validator_lifecycle::clock_at(slot);
    engine.wall_slot = slot;

    let obs = observe(&mut engine, &t);
    assert_eq!(obs.utxos.len(), 5, "four carried outputs and the allocation, nothing foreign");
    assert_eq!(obs.page_total, 5);
    let balance_before = engine.state.balance_sat(&t);
    let consolidate = Intent { pay: vec![], change_to: t, tip: 0, max_fee_sat: 50_000, max_inputs: 1_000 };

    // ── Refusals before anything is signed ──────────────────────────────
    let wrong = build_plan(&obs, &protected, &stranger.public_key, &consolidate).unwrap_err();
    assert!(wrong.contains("wrong key"), "{wrong}");
    let mut enveloped = vec![0xb1, 0x0c, 1, 0];
    enveloped.extend_from_slice(&owner.public_key);
    let env = build_plan(&obs, &protected, &enveloped, &consolidate).unwrap_err();
    assert!(env.contains("suite-enveloped form"), "{env}");
    let mut edited = obs.clone();
    edited.utxos.push(entry(0xb1, 0, 70_000, foreign));
    let f = build_plan(&edited, &protected, &owner.public_key, &consolidate).unwrap_err();
    assert!(f.contains("foreign output"), "{f}");
    let dust = Intent { pay: vec![TransferOutput { value: 999, script_hash: [0x94; 32] }], ..consolidate.clone() };
    assert!(build_plan(&obs, &protected, &owner.public_key, &dust).unwrap_err().contains("dust"));
    let capped = Intent { max_fee_sat: 100, ..consolidate.clone() };
    assert!(build_plan(&obs, &protected, &owner.public_key, &capped).unwrap_err().contains("--max-fee"));

    // ── The consolidation draft ─────────────────────────────────────────
    let plan = build_plan(&obs, &protected, &owner.public_key, &consolidate).unwrap();
    assert_eq!(plan.inputs.len(), 3, "allocation and dust left out");
    assert!(plan.excluded.iter().any(|(u, why)| (u.txid, u.vout) == allocation && *why == Exclusion::GenesisAllocation));
    assert!(plan.excluded.iter().any(|(u, why)| u.value == 5 && matches!(why, Exclusion::Uneconomic { .. })));
    assert_eq!(plan.input_sum_sat, 150_000 + 1_000 + 50_000_000);
    assert_eq!(plan.signing_root, plan.tx.checked_signing_root(V2_FLAG_DAY));
    // An allocation outpoint put into a draft by hand: refused by inspection.
    let mut with_alloc = plan.tx.clone();
    if let PosTransaction::TransferV2 { inputs, .. } = &mut with_alloc {
        inputs.push(TransferInputV2 { txid: allocation.0, vout: allocation.1, key_index: 0 });
    }
    assert!(inspect(&obs, &protected, &with_alloc, 50_000).unwrap_err().contains("genesis allocation"));

    // ── Signatures: the stranger cannot, the raw key can ────────────────
    let mut by_stranger = plan.tx.clone();
    sign(&mut by_stranger, &stranger, &plan.signing_root);
    assert!(inspect(&obs, &protected, &by_stranger, 50_000).is_err());
    let refusal = engine.on_transaction(by_stranger).unwrap_err();
    assert!(format!("{refusal:?}").contains("signature that does not verify"), "{refusal:?}");
    let mut stranger_key = plan.tx.clone();
    if let PosTransaction::TransferV2 { keys, .. } = &mut stranger_key {
        keys[0].pubkey = stranger.public_key.clone();
    }
    sign(&mut stranger_key, &stranger, &plan.signing_root);
    assert!(engine.on_transaction(stranger_key).is_err(), "a stranger's own key opens nothing of the treasury");

    let mut tx = plan.tx.clone();
    sign(&mut tx, &owner, &plan.signing_root);
    let shown = inspect(&obs, &protected, &tx, 50_000).unwrap();
    assert!(shown.signed);
    assert_eq!(shown.txid, plan.txid, "the signature does not move the txid");
    let mut tampered = tx.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut tampered {
        outputs[0].value -= 1;
    }
    let refusal = engine.on_transaction(tampered).unwrap_err();
    assert!(format!("{refusal:?}").contains("not conserved"), "{refusal:?}");

    assert!(admissible(&tx, V2_FLAG_DAY).is_ok());
    assert_eq!(engine.on_transaction(tx.clone()), Ok(Admitted::New));
    let before = engine.head_id();
    engine.propose(slot);
    assert_ne!(engine.head_id(), before, "the block must be adopted");
    assert_eq!(engine.blocks[engine.head_id().as_bytes()].body.transactions, vec![tx.canonical_bytes()]);
    for u in &plan.inputs {
        assert!(engine.state.utxo(&u.txid, u.vout).is_none(), "spent input must leave the set");
    }
    let merged = engine.state.utxo(&tx.txid(), 0).expect("the consolidation output").clone();
    assert_eq!(merged.script_hash, t, "a consolidation stays at the treasury script");
    assert_eq!(u128::from(merged.value), plan.input_sum_sat - u128::from(plan.fee_sat));
    assert!(engine.state.utxo(&allocation.0, allocation.1).is_some(), "the allocation is untouched");
    assert!(engine.state.utxo(&[0xa4; 32], 0).is_some(), "the dust output is untouched");
    assert!(engine.state.utxo(&[0xb1; 32], 0).is_some(), "the foreign output is untouched");
    assert_eq!(engine.state.balance_sat(&t), balance_before - u128::from(plan.fee_sat), "only the fee left the treasury");
    println!(
        "TREASURY_COLLECT_EVIDENCE consolidation txid {} inputs {} fee {} sat merged {} sat",
        crate::codec::hex32(&tx.txid()),
        plan.inputs.len(),
        plan.fee_sat,
        merged.value
    );

    // ── Second draft: a payment with change, from the merged output ─────
    let slot2 = slot + 1;
    let _clock2 = super::validator_lifecycle::clock_at(slot2);
    engine.wall_slot = slot2;
    let obs2 = observe(&mut engine, &t);
    let dest = [0x94u8; 32];
    let pay = Intent {
        pay: vec![TransferOutput { value: 10_000_000, script_hash: dest }],
        change_to: t,
        tip: 5,
        max_fee_sat: 50_000,
        max_inputs: 1_000,
    };
    let plan2 = build_plan(&obs2, &protected, &owner.public_key, &pay).unwrap();
    assert_eq!(plan2.inputs.len(), 1, "only the merged output is eligible");
    let mut tx2 = plan2.tx.clone();
    sign(&mut tx2, &owner, &plan2.signing_root);
    inspect(&obs2, &protected, &tx2, 50_000).unwrap();
    assert_eq!(engine.on_transaction(tx2.clone()), Ok(Admitted::New));
    let before = engine.head_id();
    engine.propose(slot2);
    assert_ne!(engine.head_id(), before);
    let paid = engine.state.utxo(&tx2.txid(), 0).expect("payment").clone();
    assert_eq!((paid.script_hash, paid.value), (dest, 10_000_000));
    let change = engine.state.utxo(&tx2.txid(), 1).expect("change").clone();
    assert_eq!(change.script_hash, t);
    assert_eq!(
        u128::from(change.value),
        u128::from(merged.value) - 10_000_000 - u128::from(plan2.fee_sat)
    );
    assert!(engine.state.utxo(&merged.txid, 0).is_none());
}
