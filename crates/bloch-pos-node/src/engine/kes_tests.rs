// SPDX-License-Identifier: AGPL-3.0-or-later
//! KES on the node, mainnet line: the registration gate at the mempool door,
//! the pending-registration dedupe, and the duty signer producing real hybrid
//! leaf signatures over the bound message that the consensus verifier
//! accepts — and nothing else. Every key here is a disposable test key.
use super::*;
use crate::keys::{HybridVerifier, KdfParams, Unlock};
use bloch_pos_committee::kes::{self, KesPublic};

fn registration(engine: &Engine, validator: u32, root_byte: u8) -> PosTransaction {
    let public = KesPublic::new(kes::MIN_DEPTH, [root_byte; 32], 0);
    let domain = engine.state.admission_network_domain().unwrap_or([0; 32]);
    let signature = engine
        .keys
        .as_ref()
        .expect("the proposing engine holds validator 0's key")
        .sign(&kes::register_signing_root(&domain, validator, &public));
    PosTransaction::KesRegister { validator, depth: public.depth, root: public.root, signature }
}

/// Mainnet as shipped: the registration window is unarmed, so a correctly
/// signed registration is refused at the door with the flag-day reason, is
/// not relayed, and leaves the mempool and committed state untouched.
#[test]
fn registration_is_refused_before_its_window() {
    assert_eq!(bloch_pos_committee::params::KES_REGISTRATION_EPOCH, 7360);
    let (mut engine, _dir) = perf_support::proposing_engine();
    let tx = registration(&engine, 0, 0x11);
    for epoch in [0, 4_669, 7_359] {
        let why = admissible(&tx, epoch).expect_err("unarmed");
        assert!(why.contains("KES_REGISTRATION_EPOCH"), "{why}");
    }
    match engine.on_transaction(tx) {
        Err(Refusal::Invalid(why)) => assert!(why.contains("KES_REGISTRATION_EPOCH"), "{why}"),
        other => panic!("expected the flag-day refusal, got {other:?}"),
    }
    assert!(engine.mempool.is_empty());
    assert!(engine.state.kes_roots().is_empty());
}

/// The relay dedupe (devnet 7606f74f): one pending registration per
/// validator, first come first kept; another validator's is judged on its
/// own; non-registrations are untouched.
#[test]
fn a_second_pending_registration_for_the_same_validator_is_refused() {
    let (engine, _dir) = perf_support::proposing_engine();
    let first = registration(&engine, 0, 0x11);
    let mut pending: BTreeMap<Vec<u8>, PosTransaction> = BTreeMap::new();
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &pending, &first), Ok(()));
    pending.insert(first.canonical_bytes(), first.clone());
    let second = registration(&engine, 0, 0x22);
    match validator_lifecycle::kes_register_conflict(&engine.state, &pending, &second) {
        Err(Refusal::Invalid(why)) => assert!(why.contains("already pending"), "{why}"),
        other => panic!("expected the pending refusal, got {other:?}"),
    }
    let other_validator = registration(&engine, 7, 0x33);
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &pending, &other_validator), Ok(()));
    let withdraw = PosTransaction::Withdraw { validator: 0 };
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &pending, &withdraw), Ok(()));
}

/// A static key whose registry entry is `pk`, with a KES key and a domain:
/// the lookup committed state answers with after a registration.
struct Registered {
    pk: Vec<u8>,
    kes: KesPublic,
    domain: Option<[u8; 32]>,
}

impl KeyLookup for Registered {
    fn pubkey(&self, validator: u32) -> Option<&[u8]> {
        (validator == 4).then_some(self.pk.as_slice())
    }
    fn kes_public(&self, validator: u32, _period: u64) -> Option<KesPublic> {
        (validator == 4).then_some(self.kes)
    }
    fn kes_network_domain(&self) -> Option<[u8; 32]> {
        self.domain
    }
}

/// The duty signer with real ML-DSA-65 + Falcon-1024 leaves: before
/// enforcement it is the static key, unchanged; after it, the evolved leaf
/// over `kes::leaf_message`, which the consensus check accepts for exactly
/// that validator, period and network.
#[test]
fn the_duty_signer_produces_bound_leaf_signatures_consensus_accepts() {
    let dir = std::env::temp_dir().join(format!("bloch-kes-duty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let unlock = Unlock::passphrase_with("kes-duty-test-passphrase", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
    let keys = Keystore::generate_with(&dir, 4, &Unlock::PlaintextOptIn).unwrap();
    let mut key = crate::kes_key::KesKey::generate(4, 2, |_| {}).unwrap();
    key.save(&dir, &unlock).unwrap();
    let public = key.public();
    let domain = Some([0xD7; 32]);
    let lookup = Registered { pk: keys.pubkey.clone(), kes: public, domain };
    let verifier = HybridVerifier::new();
    let root = [0x42; 32];

    // Before enforcement: the static signature, byte-for-byte keys.sign.
    let signer = KesSigner::new(key, dir.clone(), unlock);
    let static_sig = sign_duty(&keys, Some(&signer), None, domain, 4, 0, &root);
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, None, &root, &static_sig), Some(true));

    // Period 2, as `prepare_kes` would leave it.
    let mut signer = signer;
    signer.key.evolve_to(&signer.dir, &signer.unlock, 2).unwrap();
    let sig = sign_duty(&keys, Some(&signer), Some((2, public)), domain, 4, 0, &root);
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(2), &root, &sig), Some(true));
    // Not another period, message, network, or the bare root.
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(1), &root, &sig), Some(false));
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(2), &[0x43; 32], &sig), Some(false));
    let elsewhere = Registered { pk: keys.pubkey.clone(), kes: public, domain: Some([0xD8; 32]) };
    assert_eq!(kes::verify_validator_in(&elsewhere, &verifier, 4, Some(2), &root, &sig), Some(false));
    let bare = signer.key.sign(&root).unwrap();
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(2), &root, &bare), Some(false));
    // The static key no longer signs a duty once KES is enforced.
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(2), &root, &static_sig), Some(false));
    // Without a KES key or a domain the signer refuses (empty signature).
    assert!(sign_duty(&keys, None, Some((2, public)), domain, 4, 0, &root).is_empty());
    assert!(sign_duty(&keys, Some(&signer), Some((2, public)), None, 4, 0, &root).is_empty());
    // The producer's probe verifier accepts the empty probe signature.
    assert!(ProbeVerifier.verify_kes(&public, 2, &root, &[]));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The block-admission proof cache is keyed by the same authority before
/// enforcement as it always was: SHA3 of the static key. From the static-key
/// network binding (epoch 10010, docs/FLAG-DAY-E10010.md) the static
/// authority also names the network, so no verdict cached under the bare-root
/// rule is reused across that gate.
#[test]
fn the_block_admission_authority_is_the_static_key_hash_while_unarmed() {
    let (engine, _dir) = perf_support::proposing_engine();
    let pk = KeyLookup::pubkey(&*engine.state, 0).unwrap().to_vec();
    let expected: [u8; 32] = Sha3_256::digest(&pk).into();
    let gate = bloch_pos_committee::params::STATIC_KEY_NETWORK_BINDING_ACTIVATION_EPOCH;
    if gate > 1 {
        for epoch in [0, 1, gate - 1] {
            assert_eq!(kes::authority_fingerprint(&*engine.state, 0, epoch), Some(expected));
        }
    }
    for epoch in [gate, 1 << 40] {
        let bound = kes::authority_fingerprint(&*engine.state, 0, epoch);
        assert!(bound.is_some() && bound != Some(expected), "{epoch}");
        assert_eq!(bound, kes::authority_fingerprint(&*engine.state, 0, gate));
    }
    assert_eq!(kes::authority_fingerprint(&*engine.state, 99, 0), None);
}

/// `getkes` while unarmed: no schedule, no period, nothing registered.
#[test]
fn getkes_reports_the_unarmed_schedule() {
    let (engine, _dir) = perf_support::proposing_engine();
    let mut json = String::new();
    rpc::kes_json(&engine.state).write(&mut json);
    for field in [
        "\"registration_epoch\":7360",
        "\"activation_epoch\":8620",
        "\"period_epochs\":90",
        "\"registration_open\":false",
        "\"period\":null",
        "\"registered\":[]",
        "\"enforced_from\":null",
        "\"min_registered_stake_bps\":9000",
    ] {
        assert!(json.contains(field), "{field} missing from {json}");
    }
}

// ── HF3: per-key start period, rotation policy, rotation dedupe ──────────

fn rotation(validator: u32, period: u64, root_byte: u8) -> PosTransaction {
    PosTransaction::KesRotate { validator, period, depth: kes::MIN_DEPTH, root: [root_byte; 32], signature: vec![0; 8] }
}

/// The relay dedupe for 0x17 still holds with rotation in the code: one
/// pending registration per validator, and a registration is never confused
/// with a pending rotation (or the reverse).
#[test]
fn registration_dedupe_is_unchanged_and_independent_of_rotations() {
    let (engine, _dir) = perf_support::proposing_engine();
    let mut pending: BTreeMap<Vec<u8>, PosTransaction> = BTreeMap::new();
    let first = registration(&engine, 0, 0x11);
    pending.insert(first.canonical_bytes(), first);
    match validator_lifecycle::kes_register_conflict(&engine.state, &pending, &registration(&engine, 0, 0x22)) {
        Err(Refusal::Invalid(why)) => assert!(why.contains("already pending"), "{why}"),
        other => panic!("expected the pending refusal, got {other:?}"),
    }
    // A pending registration does not block a rotation, nor the reverse.
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &pending, &rotation(0, 3, 0x33)), Ok(()));
    let mut rotations: BTreeMap<Vec<u8>, PosTransaction> = BTreeMap::new();
    let r = rotation(0, 3, 0x33);
    rotations.insert(r.canonical_bytes(), r);
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &rotations, &registration(&engine, 0, 0x11)), Ok(()));
}

/// One pending rotation per validator (first come, first kept), applied
/// from day one; other validators and other transactions are untouched.
#[test]
fn a_second_pending_rotation_for_the_same_validator_is_refused() {
    let (engine, _dir) = perf_support::proposing_engine();
    let mut pending: BTreeMap<Vec<u8>, PosTransaction> = BTreeMap::new();
    let first = rotation(0, 3, 0x11);
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &pending, &first), Ok(()));
    pending.insert(first.canonical_bytes(), first);
    for second in [rotation(0, 3, 0x22), rotation(0, 4, 0x11)] {
        match validator_lifecycle::kes_register_conflict(&engine.state, &pending, &second) {
            Err(Refusal::Invalid(why)) => assert!(why.contains("rotation") && why.contains("already pending"), "{why}"),
            other => panic!("expected the pending-rotation refusal, got {other:?}"),
        }
    }
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &pending, &rotation(7, 3, 0x22)), Ok(()));
}

/// Mainnet as shipped: a rotation is refused at the door with the HF3
/// flag-day reason (and a malformed one is refused even structurally).
#[test]
fn rotation_is_refused_at_the_door_while_hf3_is_unarmed() {
    assert_eq!(bloch_pos_committee::params::HF3_KES_EPOCH, 7360);
    let (mut engine, _dir) = perf_support::proposing_engine();
    for epoch in [0, 4_669, 7_359] {
        let why = admissible(&rotation(0, 0, 0x11), epoch).expect_err("unarmed");
        assert!(why.contains("HF3_KES_EPOCH"), "{why}");
    }
    match engine.on_transaction(rotation(0, 0, 0x11)) {
        Err(Refusal::Invalid(why)) => assert!(why.contains("HF3_KES_EPOCH"), "{why}"),
        other => panic!("expected the flag-day refusal, got {other:?}"),
    }
    assert!(engine.mempool.is_empty());
}

fn entry(current: KesPublic, next: Option<KesPublic>) -> kes::KesEntry {
    kes::KesEntry { current, next, retired: Vec::new() }
}

/// The node's rotation policy, period by period: idle far from expiry,
/// keygen inside the (staggered) horizon, submit once per period, wait for
/// the handover once committed, and never act on a key it does not hold.
#[test]
fn the_rotation_policy_generates_submits_and_hands_over() {
    use bloch_pos_committee::params::{KES_ROTATE_REMAINING_PERIODS as R, KES_ROTATION_STAGGER_PERIODS as S};
    let depth = 12;
    let key = KesPublic::new(depth, [1; 32], 100);
    let succ = KesPublic::new(depth, [2; 32], 0);
    let e = entry(key, None);
    let end = key.end_period();
    let index = 5u32;
    let horizon = R + u64::from(index) % S;
    let step = |period, next: Option<KesPublic>, generating, submitted| {
        kes_rotation_step(&e, period, index, &key, next, generating, submitted)
    };
    assert_eq!(step(100, None, false, false), KesRotationStep::Idle, "fresh key");
    assert_eq!(step(end - horizon - 1, None, false, false), KesRotationStep::Idle, "one period outside the horizon");
    assert_eq!(step(end - horizon, None, false, false), KesRotationStep::Generate { depth }, "inside the horizon");
    assert_eq!(step(end - horizon, None, true, false), KesRotationStep::Idle, "keygen already running");
    assert_eq!(step(end - horizon, Some(succ), false, false), KesRotationStep::Submit);
    assert_eq!(step(end - horizon, Some(succ), false, true), KesRotationStep::Idle, "once per period");
    assert_eq!(step(end - horizon + 1, Some(succ), false, false), KesRotationStep::Submit, "resubmitted next period");
    assert_eq!(step(end - 1, Some(succ), false, false), KesRotationStep::Submit, "the last period still can");
    assert_eq!(step(end, Some(succ), false, false), KesRotationStep::Idle, "expired: no leaf can rotate");
    // A successor equal to the key in force is useless: generate a fresh one.
    assert_eq!(step(end - 2, Some(KesPublic::new(depth, [1; 32], 0)), false, false), KesRotationStep::Generate { depth });
    // An early successor (incident response) is submitted at once.
    assert_eq!(step(200, Some(succ), false, false), KesRotationStep::Submit);
    // Committed: wait for the handover; a foreign pending successor is flagged.
    let committed = entry(key, Some(KesPublic::new(depth, [2; 32], 3000)));
    assert_eq!(kes_rotation_step(&committed, 2999, index, &key, Some(succ), false, true), KesRotationStep::AwaitHandover);
    assert_eq!(kes_rotation_step(&committed, 2999, index, &key, None, false, false), KesRotationStep::Foreign);
    // Not this node's key in force (another file): never rotate with it.
    let other = KesPublic::new(depth, [9; 32], 0);
    assert_eq!(kes_rotation_step(&e, end - 2, index, &other, None, false, false), KesRotationStep::Idle);
    // The stagger spreads co-hosted validators over S different periods.
    let firsts: std::collections::BTreeSet<u64> = (0..S as u32)
        .map(|i| (100..end).find(|&p| kes_rotation_step(&e, p, i, &key, None, false, false) != KesRotationStep::Idle).unwrap())
        .collect();
    assert_eq!(firsts.len() as u64, S);
}

/// With real hybrid leaves: a key registered late (on-chain start period 7)
/// signs period 9 with leaf 2 — the leaf index is the period minus the key's
/// start, not the global period — and the successor's leaf 0 signs the first
/// period after the rotation, while the old key does not.
#[test]
fn the_duty_signer_signs_with_the_leaf_of_the_keys_own_start() {
    let dir = std::env::temp_dir().join(format!("bloch-kes-start-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let unlock_for = || Unlock::passphrase_with("kes-start-test-passphrase", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
    let unlock = unlock_for();
    let keys = Keystore::generate_with(&dir, 4, &Unlock::PlaintextOptIn).unwrap();
    let key = crate::kes_key::KesKey::generate(4, 2, |_| {}).unwrap();
    key.save(&dir, &unlock).unwrap();
    let tree = key.public();
    let on_chain = KesPublic::new(tree.depth, tree.root, 7);
    let domain = Some([0xD7; 32]);
    let lookup = Registered { pk: keys.pubkey.clone(), kes: on_chain, domain };
    let verifier = HybridVerifier::new();
    let root = [0x42; 32];
    let mut signer = KesSigner::new(key, dir.clone(), unlock_for());
    signer.key.evolve_to(&signer.dir, &signer.unlock, on_chain.leaf_index(9).unwrap()).unwrap();
    assert_eq!(signer.key.period(), 2);
    let sig = sign_duty(&keys, Some(&signer), Some((9, on_chain)), domain, 4, 0, &root);
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(9), &root, &sig), Some(true));
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(2), &root, &sig), Some(false), "not the global period 2");

    // Rotation in period 9 to a fresh tree: start period 10.
    let successor = crate::kes_key::KesKey::generate(4, 2, |_| {}).unwrap();
    successor.save_next(&dir, &unlock).unwrap();
    let next_tree = successor.public();
    signer.next = Some(successor);
    let rotate_root = kes::rotate_signing_root(&domain.unwrap(), 4, 9, next_tree.depth, &next_tree.root);
    let rotate_sig = signer.key.sign(&kes::leaf_message(domain, 4, &on_chain, 9, &rotate_root).unwrap()).unwrap();
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(9), &rotate_root, &rotate_sig), Some(true), "the rotation's leaf signature");
    let new_chain = KesPublic::new(next_tree.depth, next_tree.root, 10);
    signer.adopt_successor(&new_chain).unwrap();
    assert_eq!(signer.key.public().root, next_tree.root, "swapped in memory");
    assert_eq!(crate::kes_key::KesKey::load_optional(&dir, &unlock).unwrap().unwrap().public().root, next_tree.root, "and on disk");
    assert!(!crate::kes_key::KesKey::next_path(&dir).exists());
    let after = Registered { pk: keys.pubkey.clone(), kes: new_chain, domain };
    let new_sig = sign_duty(&keys, Some(&signer), Some((10, new_chain)), domain, 4, 0, &root);
    assert_eq!(kes::verify_validator_in(&after, &verifier, 4, Some(10), &root, &new_sig), Some(true));
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(10), &root, &new_sig), Some(false), "not under the old key");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review PER-1: the successor is promoted on unfinalized head state, so the
/// replaced key must survive until the handover is final. With real hybrid
/// leaves: after the swap the old key is kept and evolved (no seed of a past
/// period); when a reorg removes the rotation and the chain names the old
/// tree again, the node swaps back, signs a duty the old tree verifies, and
/// can sign a new `KesRotate`; once the finalized checkpoint reaches the
/// successor's first epoch the old key is shredded.
#[test]
fn a_replaced_kes_key_survives_a_reorg_across_the_handover_and_is_shredded_at_finality() {
    let dir = std::env::temp_dir().join(format!("bloch-kes-per1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let unlock_for = || Unlock::passphrase_with("kes-per1-test-passphrase", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
    let unlock = unlock_for();
    let keys = Keystore::generate_with(&dir, 4, &Unlock::PlaintextOptIn).unwrap();
    let key = crate::kes_key::KesKey::generate(4, 3, |_| {}).unwrap();
    key.save(&dir, &unlock).unwrap();
    let tree = key.public();
    let old_chain = KesPublic::new(tree.depth, tree.root, 7);
    let domain = Some([0xD7; 32]);
    let verifier = HybridVerifier::new();
    let root = [0x42; 32];
    let retired_path = dir.join(crate::kes_key::RETIRED_FILE_NAME);
    let schedule = bloch_pos_committee::params::kes_schedule();
    let first_epoch = |period: u64| schedule.activation_epoch + period * schedule.period_epochs;

    let mut signer = KesSigner::new(key, dir.clone(), unlock_for());
    signer.key.evolve_to(&signer.dir, &signer.unlock, old_chain.leaf_index(9).unwrap()).unwrap();
    let successor = crate::kes_key::KesKey::generate(4, 2, |_| {}).unwrap();
    successor.save_next(&dir, &unlock).unwrap();
    let next_tree = successor.public();
    signer.next = Some(successor);

    // Branch A: the rotation was included in period 9; period 10 begins.
    let new_chain = KesPublic::new(next_tree.depth, next_tree.root, 10);
    let branch_a = entry(old_chain, Some(new_chain));
    signer.adopt_successor(&branch_a.in_force(10)).unwrap();
    assert_eq!(signer.key.public().root, next_tree.root);
    assert!(retired_path.exists(), "the replaced key is kept, not shredded");
    assert_eq!(signer.retired.as_ref().unwrap().period(), 2, "still at its last leaf (period 9)");

    // Not final yet: kept, and evolved to the old tree's leaf for period 10
    // so the seed of period 9 is erased like any past period.
    signer.settle_replaced(&branch_a, 10, Some(10), first_epoch(10) - 1);
    assert_eq!(signer.retired.as_ref().unwrap().period(), 3);
    assert_eq!(crate::kes_key::KesKey::load_retired(&dir, &unlock).unwrap().unwrap().period(), 3);
    // A clock far ahead of the head does not erase further (review F-5).
    signer.settle_replaced(&branch_a, 13, Some(10), first_epoch(10) - 1);
    assert_eq!(signer.retired.as_ref().unwrap().period(), 3);

    // Reorg to branch B, which forks below the including block: no rotation
    // on chain, the old tree is the key in force for period 10.
    let branch_b = entry(old_chain, None);
    signer.adopt_successor(&branch_b.in_force(10)).unwrap();
    assert_eq!(signer.key.public().root, tree.root, "the old key signs again");
    assert_eq!(signer.next.as_ref().unwrap().public().root, next_tree.root, "the successor is sealed again");
    assert!(signer.retired.is_none() && !retired_path.exists());
    assert_eq!(crate::kes_key::KesKey::load_optional(&dir, &unlock).unwrap().unwrap().public().root, tree.root);
    assert_eq!(crate::kes_key::KesKey::load_next(&dir, &unlock).unwrap().unwrap().public().root, next_tree.root);
    let lookup = Registered { pk: keys.pubkey.clone(), kes: old_chain, domain };
    let sig = sign_duty(&keys, Some(&signer), Some((10, old_chain)), domain, 4, 0, &root);
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(10), &root, &sig), Some(true), "a duty under the old tree");
    // And it can rotate again: the policy submits, the old leaf signs it.
    assert_eq!(
        kes_rotation_step(&branch_b, 10, 4, &signer.key.public(), signer.next.as_ref().map(|n| n.public()), false, false),
        KesRotationStep::Submit
    );
    let rotate_root = kes::rotate_signing_root(&domain.unwrap(), 4, 10, next_tree.depth, &next_tree.root);
    let rotate_sig = signer.key.sign(&kes::leaf_message(domain, 4, &old_chain, 10, &rotate_root).unwrap()).unwrap();
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, Some(10), &rotate_root, &rotate_sig), Some(true));

    // The new rotation is included in period 10; the handover is period 11.
    let new_chain = KesPublic::new(next_tree.depth, next_tree.root, 11);
    let branch_b = entry(old_chain, Some(new_chain));
    signer.adopt_successor(&branch_b.in_force(11)).unwrap();
    assert_eq!(signer.key.public().root, next_tree.root);
    signer.settle_replaced(&branch_b, 11, Some(11), first_epoch(11) - 1);
    assert_eq!(signer.retired.as_ref().unwrap().period(), 4, "kept and evolved while unfinalized");
    // A restart in this window loads the kept key.
    assert_eq!(crate::kes_key::KesKey::load_retired(&dir, &unlock).unwrap().unwrap().public().root, tree.root);
    // Final: destroyed.
    signer.settle_replaced(&branch_b, 11, Some(11), first_epoch(11));
    assert!(signer.retired.is_none() && !retired_path.exists(), "shredded once the handover is final");
    // The chain can no longer name the old tree; nothing to swap back to.
    signer.adopt_successor(&old_chain).unwrap();
    assert_eq!(signer.key.public().root, next_tree.root);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review W2-4: the replaced key is destroyed on the chain's finalized epoch
/// only. A duty or wall period far past the old tree's last period (a clock
/// that jumped forward) while the handover is not final keeps it, so a
/// reorg of that handover can still swap back; it goes once the finalized
/// checkpoint is past the old tree's last period.
#[test]
fn a_clock_jump_does_not_destroy_the_replaced_kes_key() {
    let dir = std::env::temp_dir().join(format!("bloch-kes-w24-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let unlock_for = || Unlock::passphrase_with("kes-w24-test-passphrase", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
    let unlock = unlock_for();
    let key = crate::kes_key::KesKey::generate(4, 2, |_| {}).unwrap();
    key.save(&dir, &unlock).unwrap();
    let tree = key.public();
    let old_chain = KesPublic::new(tree.depth, tree.root, 7);
    let end = old_chain.end_period();
    let retired_path = dir.join(crate::kes_key::RETIRED_FILE_NAME);
    let schedule = bloch_pos_committee::params::kes_schedule();
    let first_epoch = |period: u64| schedule.activation_epoch + period * schedule.period_epochs;

    let mut signer = KesSigner::new(key, dir.clone(), unlock_for());
    let successor = crate::kes_key::KesKey::generate(4, 1, |_| {}).unwrap();
    successor.save_next(&dir, &unlock).unwrap();
    let next_tree = successor.public();
    signer.next = Some(successor);

    // The successor takes over in the period after the old tree's last one,
    // so only the expiry rule can destroy the old key before that handover
    // is final.
    let handover = end + 1;
    let branch = entry(old_chain, Some(KesPublic::new(next_tree.depth, next_tree.root, handover)));
    signer.adopt_successor(&branch.in_force(handover)).unwrap();
    assert!(retired_path.exists());

    // The wall clock says a period far past the old tree's end; the chain
    // has finalized nothing past it.
    signer.settle_replaced(&branch, end + 40, Some(handover), first_epoch(end) - 1);
    assert!(signer.retired.is_some() && retired_path.exists(), "kept: the chain has not finalized past the old tree");
    signer.adopt_successor(&old_chain).unwrap();
    assert_eq!(signer.key.public().root, tree.root, "so a reorg of the handover can still swap back");
    signer.adopt_successor(&branch.in_force(handover)).unwrap();

    // Finalized past the old tree's last period (the handover itself is not
    // final yet): destroyed.
    signer.settle_replaced(&branch, handover, Some(handover), first_epoch(end));
    assert!(signer.retired.is_none() && !retired_path.exists(), "shredded on the finalized epoch");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review F-1: KES leaves are signed and verified in the canonical,
/// suite-bound v2 form from the first KES signature, so the
/// `SIG_CANONICAL` flag day cannot silence them. The plain (v1) check refuses
/// a leaf signature, the leaf hook accepts it, refuses a v1 leaf signature,
/// and every node wrapper forwards the hook.
#[test]
fn kes_leaves_are_bound_v2_signatures_through_every_verifier_wrapper() {
    let key = crate::kes_key::KesKey::generate(9, 1, |_| {}).unwrap();
    let public = key.public();
    let message = [0x5B; 32];
    let sig = key.sign(&message).unwrap();
    let leaf = kes::KesSignature::decode(&sig).unwrap();
    let hybrid = HybridVerifier::new();
    assert!(!hybrid.verify_with_key(&leaf.leaf_pk, &message, &leaf.sig), "not a v1 signature");
    assert!(hybrid.verify_kes_leaf(&leaf.leaf_pk, &message, &leaf.sig));
    assert!(kes::verify(&hybrid, &public, 0, &message, &sig));
    // A v1 leaf signature (what the devnet line produced) is refused.
    let leaf_seed = kes::leaf_seed(&[0u8; 32]);
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&leaf_seed[..]).unwrap();
    let v1 = bloch_crypto::crypto::sign(&sk, &message).unwrap();
    assert!(hybrid.verify_with_key(&pk, &message, &v1));
    assert!(!hybrid.verify_kes_leaf(&pk, &message, &v1));
    // The gossip cache forwards the hook, and a cached plain failure of the
    // same triple does not poison the leaf check.
    let gossip = verification::GossipVerifier::new(HybridVerifier::new());
    assert!(!gossip.verify_with_key(&leaf.leaf_pk, &message, &leaf.sig));
    assert!(gossip.verify_kes_leaf(&leaf.leaf_pk, &message, &leaf.sig));
    assert!(kes::verify(&gossip, &public, 0, &message, &sig));
    let budgeted = gossip.budgeted(1, 8);
    assert!(kes::verify(&budgeted, &public, 0, &message, &sig));
}

/// Review F-5: a forward clock jump does not erase periods the chain has not
/// reached unless the operator confirms the exact target period.
#[test]
fn kes_evolution_refuses_multi_period_jumps_without_confirmation() {
    assert!(kes_evolution_allowed(10, Some(10), 11, None), "the next period");
    assert!(kes_evolution_allowed(10, Some(30), 31, None), "following the head");
    assert!(!kes_evolution_allowed(10, Some(10), 12, None), "a jump past both");
    assert!(!kes_evolution_allowed(10, None, 40, None));
    assert!(kes_evolution_allowed(10, Some(10), 40, Some(40)), "confirmed");
    assert!(!kes_evolution_allowed(10, Some(10), 40, Some(39)), "confirmation names the exact period");
}

/// Rehearsal kes-1 (2): the hybrid signature bound is the true maximum
/// envelope (compact Falcon up to 1,462 bytes), so a long-Falcon static
/// registration signature is not refused at the door; the decoder bound for
/// KES leaves is the same number.
#[test]
fn the_kes_signature_bounds_are_the_true_hybrid_maximum() {
    assert_eq!(kes::HYBRID_SIGNATURE_MAX, bloch_crypto::crypto::max_signature_len());
    assert_eq!(kes::MAX_LEAF_SIG_LEN, bloch_crypto::crypto::max_signature_len());
    assert!(bloch_pos_committee::transition::funded::ADMISSION_PQ_SIGNATURE_MAX < kes::HYBRID_SIGNATURE_MAX);
    let with_sig = |len: usize| PosTransaction::KesRegister { validator: 0, depth: 12, root: [1; 32], signature: vec![7; len] };
    // Structural door only (the flag-day gate is checked first, so call the
    // bound through a window that is open: compare the two refusals).
    let gate = admissible(&with_sig(16), 0).unwrap_err();
    for len in [4_593, 4_596, kes::HYBRID_SIGNATURE_MAX] {
        assert_eq!(admissible(&with_sig(len), 0).unwrap_err(), gate, "{len} bytes fail only on the gate");
    }
    assert!(admissible_kes_register_shape(12, &vec![7; kes::HYBRID_SIGNATURE_MAX]));
    assert!(admissible_kes_register_shape(12, &vec![7; 4_596]));
    assert!(!admissible_kes_register_shape(12, &vec![7; kes::HYBRID_SIGNATURE_MAX + 1]));
    assert!(!admissible_kes_register_shape(12, &[]));
}

/// Rehearsal kes-1 (1): the mempool's registration dedupe reads the same
/// rescue rule consensus applies (`CommittedState::kes_rescue_open`), so an
/// expired key's static-key rescue is not refused at the door. Under the
/// compiled schedule no rescue can be open; the armed cases are in the
/// committee (`an_expired_key_can_be_rescued_by_the_static_key_and_a_live_one_cannot`).
#[test]
fn the_registration_dedupe_defers_to_the_consensus_rescue_rule() {
    let (engine, _dir) = perf_support::proposing_engine();
    for v in 0..4 {
        assert!(!engine.state.kes_rescue_open(v));
    }
    let pending: BTreeMap<Vec<u8>, PosTransaction> = BTreeMap::new();
    assert_eq!(validator_lifecycle::kes_register_conflict(&engine.state, &pending, &registration(&engine, 0, 0x11)), Ok(()));
    let source = include_str!("validator_lifecycle.rs");
    assert!(
        source.contains("state.kes_public(*validator).is_some() && !state.kes_rescue_open(*validator)"),
        "the already-registered refusal must exempt an open rescue"
    );
}

/// Agent 83, net K: a registration sent in the first slot of the opening
/// epoch, before that epoch's first block exists, passes the wall-clock door
/// and is then judged against a committed head still before the flag day.
/// That refusal lifts with the next block, so it must reach the client as
/// `TX_REFUSED_RETRYABLE` (-32009) with a deadline, never as the terminal
/// -32008 "retrying the same bytes will not help". On a head that has not
/// reached the gate and a wall clock that has not either, the door refusal
/// is unchanged.
#[test]
fn a_registration_ahead_of_the_head_is_retryable_not_terminal() {
    let gate = bloch_pos_committee::params::KES_REGISTRATION_EPOCH;
    let (mut engine, _dir) = perf_support::proposing_engine();
    assert!(epoch_of(engine.state.slot()) < gate, "the fixture head must be before the gate");
    let tx = registration(&engine, 0, 0x11);

    // First slot of the opening epoch: open by the wall clock, not by the head.
    let first = first_slot_of_epoch(gate).expect("the gate epoch has a first slot");
    {
        let _clock = validator_lifecycle::clock_at(first);
        match engine.on_transaction(tx.clone()) {
            Err(Refusal::StateDependent(why)) => {
                assert_eq!(why, validator_lifecycle::FLAG_DAY_AHEAD_OF_HEAD);
                assert!(!why.contains("will not help"), "{why}");
            }
            other => panic!("expected the retryable flag-day refusal, got {other:?}"),
        }
        let RpcResult::Err(e) = engine.serve_rpc(RpcRequest::SendRawTransaction(tx.clone())) else {
            panic!("a registration ahead of the head must produce an RPC error");
        };
        assert_eq!(e.code, rpc::TX_REFUSED_RETRYABLE, "{e:?}");
        assert!(!e.message.contains("will not help"), "{}", e.message);
        assert!(e.message.contains("resubmit the same bytes"), "{}", e.message);
        let data = e.data.as_ref().expect("-32009 carries error.data");
        assert_eq!(data.get("retryable"), Some(&rpc::Json::Bool(true)));
        assert_eq!(data.get("until_slot").and_then(rpc::Json::as_u64), Some(first + 1));
        assert!(engine.mempool.is_empty());
        assert!(engine.state.kes_roots().is_empty());
    }

    // Last slot before the gate: the door refuses on the flag day, terminal
    // as before (the wall clock has not reached the gate).
    {
        let _clock = validator_lifecycle::clock_at(first - 1);
        match engine.on_transaction(tx.clone()) {
            Err(Refusal::Invalid(why)) => assert!(why.contains("KES_REGISTRATION_EPOCH"), "{why}"),
            other => panic!("expected the door's flag-day refusal, got {other:?}"),
        }
    }
}

/// The classifier itself: only the gated lifecycle formats, only while the
/// gate lies strictly between the head's epoch and the wall clock's.
#[test]
fn the_flag_day_classifier_names_only_a_gate_between_head_and_wall() {
    use validator_lifecycle::flag_day_opened_after_head as ahead;
    let gate = bloch_pos_committee::params::KES_REGISTRATION_EPOCH;
    let register = PosTransaction::KesRegister { validator: 0, depth: 12, root: [1; 32], signature: vec![7; 40] };
    assert!(ahead(&register, gate - 1, gate));
    assert!(ahead(&register, 0, gate + 5));
    // Head already at or past the gate: a refusal there is on the bytes.
    assert!(!ahead(&register, gate, gate));
    assert!(!ahead(&register, gate, gate + 1));
    // Wall clock not at the gate yet: the door's flag-day refusal applies.
    assert!(!ahead(&register, gate - 2, gate - 1));
    // Head ahead of the wall clock (clock skew): never retryable on this path.
    assert!(!ahead(&register, gate, gate - 1));
    // A format without a wall/head gate split is never reclassified.
    assert!(!ahead(&PosTransaction::Withdraw { validator: 0 }, gate - 1, gate));
    // HF3 PQ migration shares the epoch and the split.
    assert_eq!(bloch_pos_committee::params::HF3_PQ_MIGRATION_EPOCH, gate);
}

/// What the head state rolled to a duty epoch answers with once the bind
/// boundary has been crossed: validator 0's static key, its committed KES
/// entry and the bind epoch.
struct RolledView {
    pk: Vec<u8>,
    entry: kes::KesEntry,
    enforced_from: Option<u64>,
    domain: [u8; 32],
}

impl KeyLookup for RolledView {
    fn pubkey(&self, validator: u32) -> Option<&[u8]> {
        (validator == 0).then_some(self.pk.as_slice())
    }
    fn kes_public(&self, validator: u32, period: u64) -> Option<KesPublic> {
        (validator == 0).then(|| self.entry.resolve(period)).flatten()
    }
    fn kes_network_domain(&self) -> Option<[u8; 32]> {
        Some(self.domain)
    }
    fn kes_enforced_from(&self) -> Option<Option<u64>> {
        Some(self.enforced_from)
    }
}

/// **Audit L1-01: a duty past a KES bind its head has not crossed signs
/// under the rule every verifier applies.**
///
/// Mainnet numbers. The bind is decided at the boundary into the gate epoch
/// X = 8620 and governs from X + `KES_BIND_DELAY_EPOCHS`; no block is applied
/// in X and X+1, so the HEAD state still reads `kes_enforced_from = None`
/// while the state every verifier rolls to the duty epoch X+2 binds KES.
/// The signer used to decide on the unrolled head: it signed statically and
/// every verifier refused the vote and the block, so no block could cross
/// the bind. It now decides on the rolled view: the same engine, with the
/// same lagging head, prepares the leaf, and what it signs verifies.
#[test]
fn a_duty_past_an_unseen_kes_bind_signs_the_leaf_verifiers_require() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let (mut engine, dir) = perf_support::proposing_engine();
    let kes_dir = dir.0.join("kes");
    std::fs::create_dir_all(&kes_dir).unwrap();
    let unlock_for = || Unlock::passphrase_with("kes-l1-01-test-passphrase", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
    let key = crate::kes_key::KesKey::generate(0, 2, |_| {}).unwrap();
    key.save(&kes_dir, &unlock_for()).unwrap();
    let on_chain = KesPublic::new(key.public().depth, key.public().root, 0);
    engine.kes = Some(KesSigner::new(key, kes_dir, unlock_for()));

    let duty_epoch = KES_ACTIVATION_EPOCH + KES_BIND_DELAY_EPOCHS;
    let domain = [0xD7; 32];
    let pk = engine.keys.as_ref().unwrap().pubkey.clone();
    // The head: registered, but the deciding boundary was never applied.
    let head = RolledView { pk: pk.clone(), entry: on_chain.into(), enforced_from: None, domain };
    // The same state rolled across X and X+1 into the duty epoch.
    let rolled = RolledView { pk, entry: on_chain.into(), enforced_from: Some(duty_epoch), domain };
    assert_eq!(engine.state.kes_enforced_from(), None, "the engine's own head predates the bind too");
    assert_eq!(kes::signing_mode(&head, 0, duty_epoch), kes::SigningMode::Static);
    assert_eq!(kes::signing_mode(&rolled, 0, duty_epoch), kes::SigningMode::Kes(0));

    let verifier = HybridVerifier::new();
    let root = [0x42; 32];
    let verifies = |signature: &[u8]| kes::verify_validator(&rolled, &verifier, 0, duty_epoch, &root, signature);

    // The old decision (the unrolled head): static, refused by every verifier.
    let stale = engine.prepare_kes_in(&head, Some(&head.entry), duty_epoch, 0).unwrap();
    assert_eq!(stale, None);
    let static_sig = sign_duty(engine.keys.as_ref().unwrap(), engine.kes.as_ref(), stale, Some(domain), 0, duty_epoch, &root);
    assert_eq!(verifies(&static_sig), Some(false), "the halt: a static signature in a KES-governed epoch");

    // The fixed decision (the rolled view): the leaf, accepted.
    let prepared = engine.prepare_kes_in(&rolled, Some(&rolled.entry), duty_epoch, 0).unwrap();
    assert_eq!(prepared, Some((0, on_chain)));
    let leaf_sig = sign_duty(engine.keys.as_ref().unwrap(), engine.kes.as_ref(), prepared, Some(domain), 0, duty_epoch, &root);
    assert_eq!(verifies(&leaf_sig), Some(true), "the duty signed under the rolled rule verifies");
    // One epoch earlier the static key still signs, on both views.
    assert_eq!(engine.prepare_kes_in(&rolled, Some(&rolled.entry), duty_epoch - 1, 0).unwrap(), None);
}

/// Reviews RC-01 and RC2-04: the block door rolls nothing, and derives
/// nothing, for a header no key of its proposer signed.
///
/// The probe path itself, not an early exit: the parent is a stored block
/// in epoch 8600 that no held state describes (so `governed` holds for every
/// epoch from 8622 on, and the door skips the "no KES key" exit that the
/// head path takes on this unregistered fixture), and every header is less
/// than `MAX_EPOCH_ADVANCE` epochs past it, so without the probe the door
/// would spend the slot's long roll and run the parent through the
/// transition. Garbage, empty and leaf-shaped forged signatures, each from
/// its own source (no failure quota is reached): every one is judged
/// `false` on `fallback` itself, the long roll is untouched, nothing is
/// rolled or cached. Control: a header the proposer really signed (its
/// static key) passes the probe, takes the long roll and runs the parent
/// through the transition, which refuses it, so the parent is remembered as
/// failed (RC2-07) and a re-offer is dropped without taking anything.
///
/// A KES entry cannot be planted in a `CommittedState` from this crate (the
/// fields are private and the local-cache decoder checks the state root),
/// so the leaf half of the probe on a registered key is covered by the
/// `#[ignore]` end-to-end test `sibling_heads_cross_the_bind_and_unsigned_headers_roll_nothing`.
#[test]
fn an_unsigned_header_far_past_the_gate_rolls_nothing() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let (mut engine, _dir) = perf_support::proposing_engine();
    engine.propose(1);
    let head = *engine.head_id().as_bytes();
    let template = engine.blocks.get(&head).expect("the block just proposed").clone();
    let bind = KES_ACTIVATION_EPOCH + KES_BIND_DELAY_EPOCHS;

    // The stored parent: on the head, 22 epochs before the first governed one.
    let mut parent_env = template.clone();
    parent_env.header.parent = head;
    parent_env.header.slot = first_slot_of_epoch(bind - 22).unwrap() + 1;
    let parent = *parent_env.block_id().as_bytes();
    engine.blocks.insert(parent, parent_env);
    assert!(engine.exact_parent_state(&parent).is_none(), "no held state describes it");
    let fallback = engine.proposer_authority_state(&parent);
    assert!(Arc::ptr_eq(&fallback, &engine.state.arc()), "fallback is the head");

    let wall = first_slot_of_epoch(bind + 40).unwrap();
    let mut leaf_shaped = kes::SIGNATURE_MAGIC.to_vec();
    leaf_shaped.extend_from_slice(&[0; 64]);
    let header = |epoch: u64, k: u64, signature: Vec<u8>| {
        let mut env = template.clone();
        env.header.parent = parent;
        env.header.slot = first_slot_of_epoch(epoch).unwrap() + 1 + k;
        env.proposer_sig = signature;
        env
    };
    {
        let _w = wall_at(&mut engine, wall);
        let mut source = 0u8;
        for signature in [vec![0xEE; 64], Vec::new(), leaf_shaped] {
            for k in 0..8u64 {
                source += 1;
                let env = header(bind + k * 4, k, signature.clone());
                assert!(epoch_of(env.header.slot) - (bind - 22) < MAX_EPOCH_ADVANCE, "within reach of a roll");
                match engine.door_kes_state(&env, Source::Gossip(Some([source; 32])), None, Arc::clone(&fallback)) {
                    DoorKes::Judge { state, known } => {
                        assert!(Arc::ptr_eq(&state, &fallback), "judged on fallback");
                        assert_eq!(known, Some(false), "and refused by the probe");
                    }
                    _ => panic!("an unsigned header is judged (false), not deferred or dropped"),
                }
            }
        }
        assert_eq!(engine.state.door_rolled_epochs(), 0, "no epoch was rolled");
        assert_eq!(engine.state.memo_len(), 0, "and no roll was memoized");
        assert!((bind..bind + 40).all(|e| engine.state.door_cached(&parent, e).is_none()), "nor cached");
        assert!(engine.state.try_spend_door_long_roll(wall), "the slot's long roll was never taken");
    }

    // Control: really signed by the proposer, in the next wall slot.
    let signed = |epoch: u64, engine: &Engine| {
        let mut env = header(epoch, 0, Vec::new());
        env.proposer_sig = engine.keys.as_ref().unwrap().sign_for_epoch(epoch, &env.header.proposal_signing_root());
        env
    };
    {
        let _w = wall_at(&mut engine, wall + 1);
        let env = signed(bind, &engine);
        let verdict = engine.door_kes_state(&env, Source::Gossip(Some([0xA1; 32])), None, Arc::clone(&fallback));
        assert!(matches!(verdict, DoorKes::DropFailedParent(p) if p == parent), "past the probe, through the transition");
        assert!(!engine.state.try_spend_door_long_roll(wall + 1), "the long roll was taken for it");
        engine.reorg_anchors.side.remember_failed(parent);
    }
    {
        let _w = wall_at(&mut engine, wall + 2);
        let env = signed(bind + 1, &engine);
        let verdict = engine.door_kes_state(&env, Source::Gossip(Some([0xA2; 32])), None, Arc::clone(&fallback));
        assert!(matches!(verdict, DoorKes::Drop), "a remembered failed parent is not run again");
        assert!(engine.state.try_spend_door_long_roll(wall + 2), "and takes no long roll");
    }
    assert_eq!(engine.state.door_rolled_epochs(), 0);
    assert_eq!(epoch_of(engine.state.slot()), 0, "the head did not move");
}

/// Reviews RC2-07, RC3-04 and RC3-06, through the whole door
/// (`ingest_one`): a stored parent that fails the transition on its own
/// parent's exact post-state, found while judging a really signed child, is
/// remembered as failed and removed from the store, as the side-branch fold
/// does with a block that fails; the child is ignored. When a peer offers
/// the parent again and admission stores it again, a further child is
/// dropped without running the parent through the transition again.
#[test]
fn a_parent_failing_the_transition_in_the_door_is_remembered_and_removed() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let (mut engine, _dir) = perf_support::proposing_engine();
    engine.propose(1);
    let head = *engine.head_id().as_bytes();
    let template = engine.blocks.get(&head).expect("the block just proposed").clone();
    let bind = KES_ACTIVATION_EPOCH + KES_BIND_DELAY_EPOCHS;
    let mut parent_env = template.clone();
    parent_env.header.parent = head;
    parent_env.header.slot = first_slot_of_epoch(bind - 22).unwrap() + 1;
    let parent = *parent_env.block_id().as_bytes();
    engine.blocks.insert(parent, parent_env.clone());
    let signed = |epoch: u64, engine: &Engine| {
        let mut env = template.clone();
        env.header.parent = parent;
        env.header.slot = first_slot_of_epoch(epoch).unwrap() + 1;
        env.proposer_sig = engine.keys.as_ref().unwrap().sign_for_epoch(epoch, &env.header.proposal_signing_root());
        env
    };
    let wall = first_slot_of_epoch(bind + 4).unwrap();
    {
        let _w = wall_at(&mut engine, wall);
        let child = signed(bind, &engine);
        let (verdict, landed) = engine.ingest_one(child, Source::Gossip(Some([0xB1; 32])));
        assert_eq!(verdict, Verdict::Ignore);
        assert!(landed.is_none());
        assert!(engine.reorg_anchors.side.failed_index.contains(&parent), "the parent is remembered as failed");
        assert!(!engine.blocks.contains_key(&parent), "and removed from the store");
        assert!(!engine.state.try_spend_door_long_roll(wall), "the long roll was taken for the transition");
    }
    engine.blocks.insert(parent, parent_env);
    {
        let _w = wall_at(&mut engine, wall + 1);
        let child = signed(bind + 1, &engine);
        let fallback = engine.proposer_authority_state(&parent);
        let verdict = engine.door_kes_state(&child, Source::Gossip(Some([0xB2; 32])), None, fallback);
        assert!(matches!(verdict, DoorKes::Drop), "a child of a remembered failed parent is dropped");
        assert!(engine.state.try_spend_door_long_roll(wall + 1), "without taking the long roll");
    }
    assert_eq!(engine.state.door_rolled_epochs(), 0);
}

/// Review RC-01: the door's roll is exact, bounded, rationed and cached.
/// Within `DOOR_FREE_ROLL_EPOCHS` it is free; a longer one takes the wall
/// slot's single door long roll and the next is deferred until the slot
/// changes; a repeat is served from the cache; past `MAX_EPOCH_ADVANCE` it
/// is never run. For a parent that is not the head the roll is cached by
/// (parent id, epoch). In every case it equals the uncached reference fold.
#[test]
fn the_door_roll_is_exact_bounded_rationed_and_cached() {
    let (engine, _dir) = perf_support::proposing_engine();
    let head = *engine.head_id().as_bytes();
    let base = engine.state.arc();
    let roll = |parent: [u8; 32], is_head: bool, epoch: u64, local: bool| {
        engine.door_roll(parent, is_head, Arc::clone(&base), epoch, local, false)
    };
    {
        let _clock = validator_lifecycle::clock_at(100);
        assert!(roll(head, true, DOOR_FREE_ROLL_EPOCHS, false).is_ok(), "free");
        assert_eq!(engine.state.door_rolled_epochs(), DOOR_FREE_ROLL_EPOCHS);
        let far = roll(head, true, 400, false).ok().expect("the slot's long roll");
        assert_eq!(*far, engine.rolled_to_uncached(400), "exactly the transition's fold");
        let spent = engine.state.door_rolled_epochs();
        assert_eq!(spent, 400);
        assert!(matches!(roll(head, true, 500, false), Err(DoorKes::Defer)), "one long roll per slot");
        assert!(roll(head, true, 400, false).is_ok(), "a repeat is a memo hit");
        assert!(roll(head, true, 500, true).is_ok(), "this node's own block is not rationed");
        assert_eq!(engine.state.door_rolled_epochs(), spent + 100);
    }
    let before = engine.state.door_rolled_epochs();
    {
        let _clock = validator_lifecycle::clock_at(101);
        assert!(matches!(roll(head, true, MAX_EPOCH_ADVANCE + 1, false), Err(DoorKes::Drop)), "never past the ceiling");
        assert_eq!(engine.state.door_rolled_epochs(), before, "and nothing rolled for it");
        let side = [0xAB; 32];
        let rolled = roll(side, false, 450, false).ok().expect("a fresh slot's long roll");
        assert_eq!(*rolled, engine.rolled_to_uncached(450));
        assert!(Arc::ptr_eq(&engine.door_rolled_cached(&side, false, 450).unwrap(), &rolled), "cached by (parent, epoch)");
        let again = roll(side, false, 450, false).ok().expect("served from the cache, not rationed");
        assert!(Arc::ptr_eq(&again, &rolled));
        assert!(engine.door_rolled_cached(&[0xAC; 32], false, 450).is_none(), "another parent is another key");
    }
}

/// Review RC2-01: short door rolls are rationed per wall slot, and a short
/// roll of the head is remembered beside the memo.
///
/// After a long roll the memo holds only the highest epochs, and it evicts
/// the lowest first, so a short roll of the head (head + 3) used to leave
/// the memo as it was computed and was paid again by every header. Now it
/// is kept in the door's cache (keyed by the head's block id) and a repeat
/// rolls nothing; and short rolls together take at most
/// `DOOR_SHORT_ROLL_EPOCHS_PER_SLOT` epochs per wall slot, the next one is
/// deferred until the slot changes.
#[test]
fn the_door_short_rolls_are_rationed_per_slot_and_cached_for_the_head() {
    let (engine, _dir) = perf_support::proposing_engine();
    let head = *engine.head_id().as_bytes();
    let base = engine.state.arc();
    let roll = |parent: [u8; 32], is_head: bool, epoch: u64| {
        engine.door_roll(parent, is_head, Arc::clone(&base), epoch, false, false)
    };
    {
        let _clock = validator_lifecycle::clock_at(200);
        assert!(roll(head, true, 400).is_ok(), "the slot's long roll");
        assert_eq!(engine.state.roll_distance(DOOR_FREE_ROLL_EPOCHS), DOOR_FREE_ROLL_EPOCHS, "the memo kept only the far epochs");
        let before = engine.state.door_rolled_epochs();
        let short = roll(head, true, DOOR_FREE_ROLL_EPOCHS).ok().expect("a short roll");
        assert_eq!(*short, engine.rolled_to_uncached(DOOR_FREE_ROLL_EPOCHS), "exact");
        assert_eq!(engine.state.door_rolled_epochs(), before + DOOR_FREE_ROLL_EPOCHS);
        assert_eq!(engine.state.roll_distance(DOOR_FREE_ROLL_EPOCHS), DOOR_FREE_ROLL_EPOCHS, "the memo forgot it again");
        let again = roll(head, true, DOOR_FREE_ROLL_EPOCHS).ok().expect("served from the door's cache");
        assert!(Arc::ptr_eq(&again, &short));
        assert_eq!(engine.state.door_rolled_epochs(), before + DOOR_FREE_ROLL_EPOCHS, "a repeat rolls nothing");

        // The rest of the slot's short-roll epochs, then a deferral.
        let mut spent = DOOR_FREE_ROLL_EPOCHS;
        let mut side = 0u8;
        while spent + DOOR_FREE_ROLL_EPOCHS <= DOOR_SHORT_ROLL_EPOCHS_PER_SLOT {
            side += 1;
            assert!(roll([side; 32], false, DOOR_FREE_ROLL_EPOCHS).is_ok());
            spent += DOOR_FREE_ROLL_EPOCHS;
        }
        let rolled = engine.state.door_rolled_epochs();
        assert!(matches!(roll([0xF0; 32], false, DOOR_FREE_ROLL_EPOCHS), Err(DoorKes::Defer)), "the slot's short rolls are spent");
        assert!(engine.door_roll([0xF0; 32], false, Arc::clone(&base), DOOR_FREE_ROLL_EPOCHS, true, false).is_ok(), "this node's own block is not rationed");
        assert_eq!(engine.state.door_rolled_epochs(), rolled + DOOR_FREE_ROLL_EPOCHS);
    }
    {
        let _clock = validator_lifecycle::clock_at(201);
        assert!(roll([0xF1; 32], false, DOOR_FREE_ROLL_EPOCHS).is_ok(), "a new slot, a new allowance");
    }
}

/// Drive a one-validator engine through each epoch of `epochs` (ascending):
/// the validator votes at its duty slot and proposes right after it, in the
/// same epoch, so the vote is included and the epoch is justified. Returns
/// the last block's slot.
fn live_epochs(engine: &mut Engine, epochs: impl IntoIterator<Item = u64>) -> u64 {
    let mut last = engine.state.slot();
    for e in epochs {
        let duty = engine.attestation_duty_slot(e).unwrap_or_else(|| panic!("epoch {e}: no duty"));
        let next = first_slot_of_epoch(e + 1).expect("a next epoch");
        let block = if duty + 1 < next { duty + 1 } else { duty };
        let _clock = validator_lifecycle::clock_at(block);
        engine.wall_slot = duty;
        engine.attest(duty);
        engine.wall_slot = block;
        engine.propose(block);
        assert_eq!(engine.state.slot(), block, "epoch {e}: the block is applied");
        last = block;
    }
    last
}

/// **Audit L1-01, end to end at mainnet numbers** (review R-11): a real
/// chain, a real registration, the real `rolled_to`, and this node's own
/// transition as the verifier.
///
/// One validator (all the stake) registers a depth-8 hybrid tree in the
/// window and the head stops in epoch 8619, the last before the gate. The
/// boundary into 8620 decides the bind (in force from 8622), but no block is
/// applied in 8620 or 8621, so the head state never learns it. The duty of
/// epoch 8622 is then signed from that lagging head: the vote must verify
/// under the state rolled to its epoch, and the proposal must be applied by
/// the transition, which rolls the parent into 8622 and requires the leaf.
/// With the signer deciding on the unrolled head (906336fd) both are signed
/// statically: the vote fails `attestation::validate` and the block is
/// refused, i.e. the chain cannot cross the bind.
///
/// Ignored by default only for its run time (thousands of real hybrid
/// signatures and state roots, several minutes in release):
/// `cargo test --release -p bloch-pos-node --bin bloch-pos -- --ignored two_empty_epochs`.
///
/// The chain is kept live cheaply: two consecutive voted epochs out of
/// every three until the Ethereum-paced leak (5700), then two out of
/// sixteen, which keeps finality close enough that the validator's weight
/// is never leaked away and uses fewer blocks than its RANDAO chain holds.
#[test]
#[ignore = "several minutes: drives a real chain to epoch 8622"]
fn two_empty_epochs_after_the_bind_decision_do_not_halt_the_chain() {
    use bloch_pos_committee::params::{
        ETH_PACED_LEAK_ACTIVATION_EPOCH, KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS, KES_MIN_REGISTERED_DEPTH,
        KES_REGISTRATION_EPOCH,
    };
    let (mut engine, dir) = perf_support::proposing_engine();
    let kes_dir = dir.0.join("kes");
    std::fs::create_dir_all(&kes_dir).unwrap();
    let unlock_for = || Unlock::passphrase_with("kes-l1-01-e2e-passphrase", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
    let key = crate::kes_key::KesKey::generate(0, KES_MIN_REGISTERED_DEPTH, |_| {}).unwrap();
    key.save(&kes_dir, &unlock_for()).unwrap();
    let tree = key.public();
    engine.kes = Some(KesSigner::new(key, kes_dir, unlock_for()));

    let gate = KES_ACTIVATION_EPOCH;
    let mut schedule: BTreeSet<u64> = BTreeSet::new();
    let mut e = 1;
    while e < ETH_PACED_LEAK_ACTIVATION_EPOCH {
        schedule.extend([e, e + 1]);
        e += 3;
    }
    while e < gate - 1 {
        schedule.extend([e, e + 1]);
        e += 16;
    }
    schedule.extend([KES_REGISTRATION_EPOCH, KES_REGISTRATION_EPOCH + 1, gate - 2, gate - 1]);
    schedule.retain(|e| *e < gate);
    assert!(schedule.len() < 8_000, "fewer blocks than one RANDAO chain holds");

    // Up to the registration window, then the registration, then on to the
    // last epoch before the gate.
    let window = live_epochs(&mut engine, schedule.range(..=KES_REGISTRATION_EPOCH).copied());
    assert_eq!(epoch_of(window), KES_REGISTRATION_EPOCH);
    let domain = engine.state.admission_network_domain().unwrap_or([0; 32]);
    let public = KesPublic::new(tree.depth, tree.root, 0);
    let signature = engine.keys.as_ref().unwrap().sign(&kes::register_signing_root(&domain, 0, &public));
    {
        let _clock = validator_lifecycle::clock_at(window);
        engine.wall_slot = window;
        engine
            .on_transaction(PosTransaction::KesRegister { validator: 0, depth: tree.depth, root: tree.root, signature })
            .expect("the registration is admitted");
    }
    let before = live_epochs(&mut engine, schedule.range(KES_REGISTRATION_EPOCH + 1..).copied());
    assert!(engine.state.kes_roots().contains_key(&0), "the registration is included");
    assert_eq!(epoch_of(before), gate - 1, "the head stops in the last epoch before the gate");
    assert_eq!(engine.state.kes_enforced_from(), None, "the head has not crossed the deciding boundary");

    // Epochs X and X+1 stay empty; the duty is in X+2, the first governed.
    let duty_epoch = gate + KES_BIND_DELAY_EPOCHS;
    let rolled = engine.rolled_to(duty_epoch);
    assert_eq!(rolled.kes_enforced_from(), Some(duty_epoch), "the real roll decides the bind at the gate boundary");
    assert_eq!(kes::signing_mode(&*rolled, 0, duty_epoch), kes::SigningMode::Kes(0));
    assert_eq!(kes::signing_mode(&*engine.state, 0, duty_epoch), kes::SigningMode::Static, "what the head alone says");
    drop(rolled);

    // The vote, signed from the lagging head, judged as gossip and block
    // validation judge it: against the state rolled to its epoch.
    let vote_slot = engine.attestation_duty_slot(duty_epoch).expect("the only validator has a duty");
    let _clock = validator_lifecycle::clock_at(vote_slot);
    engine.wall_slot = vote_slot;
    // The Sentinel's `kes` status reads the same duty state and the same
    // mode call as the signer (`duty_state` + `duty_signing_mode`), so on
    // the lagging head it reports the leaf the vote is about to be signed
    // with, not the head's static mode.
    let was_live = std::mem::replace(&mut engine.live, true);
    let status = engine.sentinel_snapshot().kes;
    engine.live = was_live;
    assert_eq!((status.mode, status.period), ("kes", Some(0)), "the status agrees with the signer");
    assert_eq!(status.bind_epoch, Some(Some(duty_epoch)));
    assert_eq!(status.head_state_epoch, duty_epoch, "read on the state rolled to the duty epoch");
    engine.attest(vote_slot);
    assert_eq!(engine.state.slot(), before, "voting does not move the head");
    let vote = engine
        .pool
        .values()
        .find(|a| a.validator == 0 && a.data.target_epoch == duty_epoch)
        .cloned()
        .expect("the vote is signed and pooled");
    let rolled = engine.rolled_to(duty_epoch);
    assert_eq!(
        bloch_pos_committee::attestation::validate(&vote, &[0], vote.data.slot, &HybridVerifier::new(), &*rolled),
        Ok(()),
        "the vote verifies under the rule of the state rolled to its epoch"
    );
    drop(rolled);

    // The proposal: applied by this node's own transition, which rolls the
    // parent across the two empty epochs and requires the KES leaf.
    engine.propose(vote_slot);
    assert_eq!(engine.state.slot(), vote_slot, "the KES-signed proposal crosses the bind");
    assert_eq!(engine.state.kes_enforced_from(), Some(duty_epoch));
}

/// The chain of the L1-01 end-to-end test, stopped after `last` (a live
/// epoch before the gate): one validator, a depth-8 hybrid KES tree
/// registered in the window, two of every three (then sixteen) epochs voted.
fn registered_chain(last: u64) -> (Engine, perf_support::TestDir) {
    use bloch_pos_committee::params::{ETH_PACED_LEAK_ACTIVATION_EPOCH, KES_ACTIVATION_EPOCH, KES_MIN_REGISTERED_DEPTH, KES_REGISTRATION_EPOCH};
    let (mut engine, dir) = perf_support::proposing_engine();
    let kes_dir = dir.0.join("kes");
    std::fs::create_dir_all(&kes_dir).unwrap();
    let unlock_for = || Unlock::passphrase_with("kes-rc-02-e2e-passphrase", KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 });
    let key = crate::kes_key::KesKey::generate(0, KES_MIN_REGISTERED_DEPTH, |_| {}).unwrap();
    key.save(&kes_dir, &unlock_for()).unwrap();
    let tree = key.public();
    engine.kes = Some(KesSigner::new(key, kes_dir, unlock_for()));
    assert!(last < KES_ACTIVATION_EPOCH && last > KES_REGISTRATION_EPOCH + 1);
    let mut schedule: BTreeSet<u64> = BTreeSet::new();
    let mut e = 1;
    while e < ETH_PACED_LEAK_ACTIVATION_EPOCH {
        schedule.extend([e, e + 1]);
        e += 3;
    }
    while e < last {
        schedule.extend([e, e + 1]);
        e += 16;
    }
    schedule.extend([KES_REGISTRATION_EPOCH, KES_REGISTRATION_EPOCH + 1, last - 1, last]);
    schedule.retain(|e| *e <= last);
    let window = live_epochs(&mut engine, schedule.range(..=KES_REGISTRATION_EPOCH).copied());
    let domain = engine.state.admission_network_domain().unwrap_or([0; 32]);
    let public = KesPublic::new(tree.depth, tree.root, 0);
    let signature = engine.keys.as_ref().unwrap().sign(&kes::register_signing_root(&domain, 0, &public));
    {
        let _clock = validator_lifecycle::clock_at(window);
        engine.wall_slot = window;
        engine
            .on_transaction(PosTransaction::KesRegister { validator: 0, depth: tree.depth, root: tree.root, signature })
            .expect("the registration is admitted");
    }
    let head = live_epochs(&mut engine, schedule.range(KES_REGISTRATION_EPOCH + 1..).copied());
    assert_eq!(epoch_of(head), last);
    assert!(engine.state.kes_roots().contains_key(&0), "the registration is included");
    (engine, dir)
}

/// Make `slot` the wall slot of both clocks the engine reads.
fn wall_at(engine: &mut Engine, slot: u64) -> impl Drop {
    engine.wall_slot = slot;
    validator_lifecycle::clock_at(slot)
}

/// **Reviews RC-02 and RC-01, end to end at mainnet numbers.**
///
/// RC-02: the stall of L1-01 with two sibling heads. H1 and H2 are children
/// of P in epoch 8619; epochs 8620 and 8621 stay empty; the first block of
/// 8622, B, is built on H1 and signed with the KES leaf (the bind decided at
/// the boundary into 8620 governs it). On a node whose head is H2 neither
/// the head nor the ring holds H1's post-state, so the door of 179251c4
/// judged B on the unrolled head H2 (static key), failed it and parked it:
/// each side kept only the bind-crossing blocks built on its own head. B must
/// now be admitted, judged on H1's own post-state rolled into 8622 (derived
/// here by running H1 through the transition from P's post-state, which the
/// ring holds), and the transition applies it on that parent.
///
/// RC-01, on the same lagging head (registered KES key, no bind known,
/// thousands of epochs behind the wall clock): a header with a garbage
/// signature, and one carrying B's real leaf signature over another header,
/// roll nothing; a header this proposer really signed (static key) takes the
/// wall slot's single long roll and a second one in the same slot is
/// deferred without rolling; a header beyond `MAX_EPOCH_ADVANCE` is dropped
/// without rolling.
///
/// Ignored by default only for its run time, like the L1-01 test:
/// `cargo test --release -p bloch-pos-node --bin bloch-pos -- --ignored sibling_heads`.
#[test]
#[ignore = "several minutes: drives a real chain to epoch 8622"]
fn sibling_heads_cross_the_bind_and_unsigned_headers_roll_nothing() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let gate = KES_ACTIVATION_EPOCH;
    let bind = gate + KES_BIND_DELAY_EPOCHS;
    let (mut engine, _dir) = registered_chain(gate - 2);
    let p = *engine.head_id().as_bytes();
    assert_eq!(engine.state.kes_enforced_from(), None);

    // H1 and H2, siblings on P in 8619 (proposed in increasing slots, the
    // rival taken out of the store while each is built so fork choice cannot
    // flip between two weightless siblings), then B on H1 in 8622, with
    // 8620 and 8621 empty.
    let s1 = first_slot_of_epoch(gate - 1).unwrap() + 1;
    {
        let _w = wall_at(&mut engine, s1);
        engine.propose(s1);
    }
    let h1 = *engine.head_id().as_bytes();
    assert_ne!(h1, p, "H1 is applied");
    let env_h1 = engine.blocks.get(&h1).unwrap().clone();
    assert!(engine.do_reorg(p, Vec::new()), "hand H1 back");
    engine.blocks.remove(&h1);
    let s2 = s1 + 1;
    {
        let _w = wall_at(&mut engine, s2);
        engine.propose(s2);
    }
    let h2 = *engine.head_id().as_bytes();
    assert!(h2 != h1 && h2 != p, "H2 is applied");
    let env_h2 = engine.blocks.get(&h2).unwrap().clone();
    engine.blocks.remove(&h2);
    engine.blocks.insert(h1, env_h1.clone());
    assert!(engine.do_reorg(p, vec![env_h1.clone()]), "onto H1 to build B");
    assert_eq!(*engine.head_id().as_bytes(), h1);
    let sb = first_slot_of_epoch(bind).unwrap() + 1;
    {
        let _w = wall_at(&mut engine, sb);
        engine.propose(sb);
    }
    let b = *engine.head_id().as_bytes();
    assert_eq!(engine.state.slot(), sb, "the transition applies B on H1 across the bind");
    assert_eq!(engine.state.kes_enforced_from(), Some(bind));
    let env_b = engine.blocks.get(&b).unwrap().clone();
    assert_eq!(env_b.header.parent, h1);

    // The node of RC-02: head H2, H1 stored beside it, B not yet seen.
    engine.blocks.insert(h2, env_h2.clone());
    assert!(engine.do_reorg(p, vec![env_h2.clone()]), "onto H2");
    engine.blocks.remove(&b);
    assert_eq!(*engine.head_id().as_bytes(), h2);
    assert!(engine.blocks.get(&h1).is_some(), "H1 is stored");
    engine.recent_states.retain(|(id, _)| *id != h1);
    assert!(engine.exact_parent_state(&h1).is_none(), "nothing holds H1's post-state");
    assert!(engine.exact_parent_state(&p).is_some(), "the ring holds P's");
    assert_eq!(engine.state.kes_enforced_from(), None, "the head H2 has not seen the bind");

    // What the 179251c4 door judged B on: the unrolled head, static key.
    let fallback = engine.proposer_authority_state(&h1);
    assert!(Arc::ptr_eq(&fallback, &engine.state.arc()));
    assert_eq!(kes::signing_mode(&*fallback, 0, bind), kes::SigningMode::Static);
    assert_eq!(
        kes::verify_validator(&*fallback, &HybridVerifier::new(), 0, bind, &env_b.header.proposal_signing_root(), &env_b.proposer_sig),
        Some(false),
        "under the head alone B's leaf signature fails: the partition"
    );

    // RC-02: B arrives by gossip and is admitted.
    let rolled_before = engine.state.door_rolled_epochs();
    {
        let _w = wall_at(&mut engine, sb);
        engine.live = true;
        let (verdict, landed) = engine.ingest_one(env_b.clone(), Source::Gossip(Some([0x52; 32])));
        assert_eq!(verdict, Verdict::Accept, "B is admitted on its own parent's rolled state");
        assert_eq!(landed.map(|(id, _)| id), Some(b));
    }
    assert!(engine.blocks.get(&b).is_some() || engine.canonical.contains(&b));
    assert!(!engine.orphans.iter().any(|(id, ..)| *id == b), "not parked");
    assert_eq!(engine.state.door_rolled_epochs() - rolled_before, bind - (gate - 1), "one roll, H1's epoch to B's");
    let cached = engine.state.door_cached(&h1, bind).expect("the roll is cached by (H1, 8622)");
    assert_eq!(cached.kes_enforced_from(), Some(bind));

    // RC-01 on a head that lags by thousands of epochs: H2 again, alone in
    // the store above P, as a syncing node (wide horizon).
    if *engine.head_id().as_bytes() != h2 {
        assert!(engine.do_reorg(p, vec![env_h2.clone()]), "back onto H2");
    }
    engine.blocks.remove(&b);
    engine.blocks.remove(&h1);
    assert_eq!(*engine.head_id().as_bytes(), h2);
    assert_eq!(engine.state.kes_enforced_from(), None);
    engine.live = false;
    let far_epoch = bind + 3_000;
    let far = first_slot_of_epoch(far_epoch).unwrap();
    let header_at = |slot: u64, signature: Vec<u8>, engine: &Engine| {
        let mut env = env_b.clone();
        env.header.parent = *engine.head_id().as_bytes();
        env.header.slot = slot;
        env.proposer_sig = signature;
        env
    };
    let signed_at = |slot: u64, engine: &Engine| {
        let mut env = header_at(slot, Vec::new(), engine);
        env.proposer_sig = engine.keys.as_ref().unwrap().sign_for_epoch(epoch_of(slot), &env.header.proposal_signing_root());
        env
    };
    let rolled = engine.state.door_rolled_epochs();
    {
        let _w = wall_at(&mut engine, far);
        // Garbage, far ahead; and B's real leaf signature (period 0) on
        // another header of B's epoch: leaf-shaped, but not over this root.
        for (slot, signature) in [(far - 1, vec![0xEE; 96]), (sb + 1, env_b.proposer_sig.clone())] {
            let env = header_at(slot, signature, &engine);
            assert_eq!(engine.ingest_one(env, Source::Gossip(Some([0x53; 32]))).0, Verdict::Ignore);
        }
        assert_eq!(engine.state.door_rolled_epochs(), rolled, "no key signed them: nothing rolled");
        assert_eq!(engine.state.memo_len(), 0);

        // Really signed by the proposer (its static key): one long roll ...
        let first = signed_at(far - 3, &engine);
        assert_eq!(engine.ingest_one(first, Source::Gossip(Some([0x56; 32]))).0, Verdict::Ignore, "static key in a KES epoch: refused like the transition");
        let after_one = engine.state.door_rolled_epochs();
        assert_eq!(after_one - rolled, epoch_of(far - 3) - (gate - 1), "the slot's one long roll, from H2's epoch");
        // ... and the second, at an epoch the memo does not hold, in the
        // same slot, waits.
        let second = signed_at(far - 3 - 100 * SLOTS_PER_EPOCH, &engine);
        let second_id = *second.block_id().as_bytes();
        assert_eq!(engine.ingest_one(second, Source::Gossip(Some([0x54; 32]))).0, Verdict::Ignore);
        assert_eq!(engine.state.door_rolled_epochs(), after_one, "deferred, not rolled");
        assert!(engine.orphans.iter().any(|(id, ..)| *id == second_id), "held for the next slot");
    }
    {
        let beyond = first_slot_of_epoch(epoch_of(engine.state.slot()) + MAX_EPOCH_ADVANCE + 1).unwrap() + 1;
        let _w = wall_at(&mut engine, beyond);
        let before = engine.state.door_rolled_epochs();
        let env = signed_at(beyond, &engine);
        assert_eq!(engine.ingest_one(env, Source::Gossip(Some([0x55; 32]))).0, Verdict::Ignore);
        assert_eq!(engine.state.door_rolled_epochs(), before, "past MAX_EPOCH_ADVANCE nothing is rolled");
    }
}

/// **Review RC2-03, end to end at mainnet numbers.**
///
/// The RC-02 stall with sibling branches two blocks deep: P in 8618, A1 and
/// H1 on it, A2 and H2 on it, all in 8619; 8620 and 8621 empty; B, the
/// first block of 8622, on H1 and signed with the KES leaf. The node's head
/// is H2 (held there by a vote, so validating A1 and H1 does not move it).
/// B arrives before the side-branch fold reaches H1: neither H1's nor A1's
/// post-state is held, so the door judges B on `fallback` (the head H2,
/// static key), fails it and parks it for its proposer's authority, and the
/// head never changes, so `authority_parked_due` never re-judges it. In
/// 32adb56d B stayed parked until evicted. Now the fold, on validating H1,
/// queues B for the door again and keeps H1's post-state, and B is admitted
/// on it, rolled into 8622, while the head stays H2.
///
/// Ignored by default only for its run time, like the L1-01 test:
/// `cargo test --release -p bloch-pos-node --bin bloch-pos -- --ignored deeper_side_branch`.
#[test]
#[ignore = "several minutes: drives a real chain to epoch 8622"]
fn a_bind_crossing_block_on_a_deeper_side_branch_is_admitted_once_the_fold_reaches_its_parent() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let gate = KES_ACTIVATION_EPOCH;
    let bind = gate + KES_BIND_DELAY_EPOCHS;
    let (mut engine, _dir, [a1, h1, h2, b], env_b, sb) = deeper_siblings_fixture();

    // B by gossip: judged on the head H2 (static), failed, parked.
    engine.live = true;
    {
        let _w = wall_at(&mut engine, sb);
        let (verdict, landed) = engine.ingest_one(env_b.clone(), Source::Gossip(Some([0x57; 32])));
        assert_eq!(verdict, Verdict::Ignore);
        assert!(landed.is_none());
    }
    assert!(engine.orphans.iter().any(|(id, ..)| *id == b), "B is parked");
    assert!(engine.authority_parked.judged.contains_key(&b), "for its proposer's authority");
    assert!(engine.authority_parked_due().is_empty(), "the head did not change: the old trigger never fires");

    // The fold validates A1 and H1; the head stays H2; B is queued again.
    let mut slot = sb;
    while !(engine.blocks.is_validated(&a1) && engine.blocks.is_validated(&h1)) {
        assert!(slot < sb + 32, "the fold validates the branch within a few slots");
        let _w = wall_at(&mut engine, slot);
        for _ in 0..4 {
            engine.validate_side_branch_turn(slot);
        }
        slot += 1;
    }
    assert_eq!(*engine.head_id().as_bytes(), h2, "a stalled head: validation adopted nothing");
    assert!(engine.deferred_orphans.iter().any(|(id, ..)| *id == b), "B is queued for the door again");
    assert!(engine.exact_parent_state(&h1).is_some(), "H1's post-state is held for it");

    // The promotion runs the whole door again, now on H1's own state.
    let rolled_before = engine.state.door_rolled_epochs();
    {
        let _w = wall_at(&mut engine, slot);
        while engine.deferred_orphans.iter().any(|(id, ..)| *id == b) {
            engine.release_orphan_turn();
        }
    }
    assert!(engine.blocks.contains_key(&b) || engine.canonical.contains(&b), "B is admitted and stored");
    assert!(!engine.orphans.iter().any(|(id, ..)| *id == b), "not parked again");
    assert_eq!(engine.state.door_rolled_epochs() - rolled_before, bind - (gate - 1), "H1's epoch to B's");
    assert_eq!(engine.state.door_cached(&h1, bind).expect("cached by (H1, 8622)").kes_enforced_from(), Some(bind));
}

/// The fixture of the RC2-03 and RC3-01 end-to-end tests: on a registered
/// chain stopped in 8618 at P, the sibling branches P→A1→H1 and P→A2→H2 in
/// 8619, and B on H1 in 8622 (the first epoch the bind governs, signed with
/// the KES leaf, applied by the transition). The node is left with its head
/// on H2, held there by a vote, A1 and H1 stored as admission stores them
/// (not validated), no post-state of A1 or H1 held, and B not yet seen.
/// Returns the engine, its directory, the ids (a1, h1, h2, b), B and B's
/// slot.
fn deeper_siblings_fixture() -> (Engine, perf_support::TestDir, [[u8; 32]; 4], BlockEnvelope, u64) {
    let (engine, dir, ids, env_b, sb, forks) = deeper_siblings_fixture_with(0);
    assert!(forks.is_empty());
    (engine, dir, ids, env_b, sb)
}

/// [`deeper_siblings_fixture`], plus `forks` one-block side forks on P in
/// the slots after H2 (8619), stored as admission stores them (not
/// validated). Their ids are returned last.
fn deeper_siblings_fixture_with(
    forks: usize,
) -> (Engine, perf_support::TestDir, [[u8; 32]; 4], BlockEnvelope, u64, Vec<[u8; 32]>) {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let gate = KES_ACTIVATION_EPOCH;
    let bind = gate + KES_BIND_DELAY_EPOCHS;
    let (mut engine, dir) = registered_chain(gate - 2);
    let p = *engine.head_id().as_bytes();
    assert_eq!(engine.state.kes_enforced_from(), None);
    let propose_at = |engine: &mut Engine, slot: u64| {
        let _w = wall_at(engine, slot);
        engine.propose(slot);
        assert_eq!(engine.state.slot(), slot, "applied");
        let id = *engine.head_id().as_bytes();
        (id, engine.blocks.get(&id).unwrap().clone())
    };

    // A1, H1 on P; handed back; A2, H2 on P; then onto H1 again for B.
    let s0 = first_slot_of_epoch(gate - 1).unwrap() + 1;
    let (a1, env_a1) = propose_at(&mut engine, s0);
    let (h1, env_h1) = propose_at(&mut engine, s0 + 1);
    assert_eq!((env_a1.header.parent, env_h1.header.parent), (p, a1));
    assert!(engine.do_reorg(p, Vec::new()), "hand A1, H1 back");
    engine.blocks.remove(&h1);
    engine.blocks.remove(&a1);
    let (a2, env_a2) = propose_at(&mut engine, s0 + 2);
    let (h2, env_h2) = propose_at(&mut engine, s0 + 3);
    assert_eq!((env_a2.header.parent, env_h2.header.parent), (p, a2));
    assert!(engine.do_reorg(p, Vec::new()), "hand A2, H2 back");
    engine.blocks.remove(&h2);
    engine.blocks.remove(&a2);
    let mut fork_envs = Vec::new();
    for k in 0..forks as u64 {
        let (f, env_f) = propose_at(&mut engine, s0 + 4 + k);
        assert_eq!(env_f.header.parent, p);
        assert_eq!(epoch_of(env_f.header.slot), gate - 1, "fixture: the forks are in H2's epoch");
        assert!(engine.do_reorg(p, Vec::new()), "hand the fork back");
        engine.blocks.remove(&f);
        fork_envs.push((f, env_f));
    }
    engine.blocks.insert(a1, env_a1.clone());
    engine.blocks.insert(h1, env_h1.clone());
    assert!(engine.do_reorg(p, vec![env_a1.clone(), env_h1.clone()]), "onto H1 to build B");
    let sb = first_slot_of_epoch(bind).unwrap() + 1;
    let (b, env_b) = propose_at(&mut engine, sb);
    assert_eq!(env_b.header.parent, h1);
    assert_eq!(engine.state.kes_enforced_from(), Some(bind), "B crosses the bind on H1");

    // The node: head H2, held by a vote; A1 and H1 stored as admission
    // stores them (not validated); B not yet seen; no post-state of A1/H1.
    engine.blocks.insert(a2, env_a2.clone());
    engine.blocks.insert(h2, env_h2.clone());
    assert!(engine.do_reorg(p, vec![env_a2.clone(), env_h2.clone()]), "onto H2");
    engine.blocks.remove(&b);
    for (id, env) in [(a1, &env_a1), (h1, &env_h1)] {
        engine.blocks.remove(&id);
        engine.blocks.insert(id, env.clone());
    }
    for (f, env_f) in &fork_envs {
        engine.blocks.insert(*f, env_f.clone());
    }
    let fork_ids: Vec<[u8; 32]> = fork_envs.iter().map(|(f, _)| *f).collect();
    engine.recent_states.retain(|(id, _)| *id != a1 && *id != h1 && !fork_ids.contains(id));
    engine.reorg_anchors.side.cursor = None;
    let vote = forkchoice_tests::attest(0, s0 + 3, h2);
    engine.pool.insert((vote.validator, vote.data.signing_root()), vote);
    assert_eq!(*engine.head_id().as_bytes(), h2);
    assert_eq!(engine.forkchoice_head(), h2, "fixture: the vote holds the head");
    assert!(engine.exact_parent_state(&h1).is_none() && engine.exact_parent_state(&a1).is_none());
    assert!(!engine.blocks.is_validated(&a1) && !engine.blocks.is_validated(&h1));
    assert!(fork_ids.iter().all(|f| !engine.blocks.is_validated(f) && !engine.canonical.contains(f)));

    (engine, dir, [a1, h1, h2, b], env_b, sb, fork_ids)
}

/// **Review RC3-01, end to end at mainnet numbers: the natural order.**
///
/// The fixture of the RC2-03 test, but the side-branch fold validates A1
/// and H1, and drops its cursor, BEFORE B arrives (in the network B comes
/// two empty epochs after H1). Nothing waited on H1 when it was validated,
/// so in 8a33e939 nothing kept its post-state: B was judged on `fallback`,
/// parked, and never judged again (H1 is no longer a fold candidate and the
/// head does not move). Now the fold keeps the exact post-states of the
/// side blocks it validated, and B is admitted on H1's own state, rolled
/// into 8622, as it arrives, while the head stays H2.
///
/// `cargo test --release -p bloch-pos-node --bin bloch-pos -- --ignored natural_order`.
#[test]
#[ignore = "several minutes: drives a real chain to epoch 8622"]
fn a_bind_crossing_block_arriving_after_the_fold_validated_its_side_parent_is_admitted_natural_order() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let gate = KES_ACTIVATION_EPOCH;
    let bind = gate + KES_BIND_DELAY_EPOCHS;
    let (mut engine, _dir, [a1, h1, h2, b], env_b, sb) = deeper_siblings_fixture();
    engine.live = true;

    // The fold first: A1 and H1 validated, then a turn with nothing left
    // drops the cursor. The head stays H2.
    let mut slot = sb;
    while !(engine.blocks.is_validated(&a1) && engine.blocks.is_validated(&h1)) {
        assert!(slot < sb + 32, "the fold validates the branch within a few slots");
        let _w = wall_at(&mut engine, slot);
        for _ in 0..4 {
            engine.validate_side_branch_turn(slot);
        }
        slot += 1;
    }
    {
        let _w = wall_at(&mut engine, slot);
        engine.validate_side_branch_turn(slot);
        engine.validate_side_branch_turn(slot);
    }
    assert!(engine.reorg_anchors.side.cursor.is_none(), "the cursor is dropped");
    assert_eq!(*engine.head_id().as_bytes(), h2, "a stalled head: validation adopted nothing");
    assert!(
        !engine.orphans.iter().chain(engine.deferred_orphans.iter()).any(|(_, env, ..)| env.header.parent == h1),
        "nothing waited on H1"
    );
    assert!(engine.exact_parent_state(&h1).is_some(), "H1's exact post-state is still held");

    // Then B, by gossip: admitted at once, on H1's own state.
    let rolled_before = engine.state.door_rolled_epochs();
    {
        let _w = wall_at(&mut engine, slot);
        let (verdict, landed) = engine.ingest_one(env_b.clone(), Source::Gossip(Some([0x58; 32])));
        assert_eq!(verdict, Verdict::Accept, "B is admitted on its own parent's rolled state");
        assert_eq!(landed.map(|(id, _)| id), Some(b));
    }
    assert!(!engine.orphans.iter().any(|(id, ..)| *id == b), "not parked");
    assert_eq!(engine.state.door_rolled_epochs() - rolled_before, bind - (gate - 1), "H1's epoch to B's");
    assert_eq!(engine.state.door_cached(&h1, bind).expect("cached by (H1, 8622)").kes_enforced_from(), Some(bind));
}

/// Audit L1-06 (node-local half): past the gate and before the bind a first
/// key starts at period 0, so a tree too shallow to reach the current period
/// is refused at the door; a deep enough tree, and any registration before
/// the gate, are not.
#[test]
fn a_registration_born_expired_is_refused_at_the_door() {
    let (engine, _dir) = perf_support::proposing_engine();
    assert!(!validator_lifecycle::kes_registration_born_expired(&engine.state, 0, 1), "before the gate");
    let gate = bloch_pos_committee::params::KES_ACTIVATION_EPOCH;
    let epoch = gate + 2 * bloch_pos_committee::params::KES_PERIOD_EPOCHS;
    assert_eq!(bloch_pos_committee::params::kes_period(epoch), Some(2));
    let rolled = engine.rolled_to(epoch);
    assert_eq!(rolled.kes_enforced_from(), None, "nobody registered: KES has not bound");
    assert!(validator_lifecycle::kes_registration_born_expired(&rolled, epoch, 1), "two periods of life, period 2");
    assert!(!validator_lifecycle::kes_registration_born_expired(&rolled, epoch, 2), "four periods of life");
    assert!(!validator_lifecycle::kes_registration_born_expired(&rolled, epoch, 8));
    assert!(!validator_lifecycle::kes_registration_born_expired(&rolled, gate - 1, 1), "the epoch before the gate");
}

/// **Review RC4-01, end to end at mainnet numbers.**
///
/// The natural order of the RC3-01 test, but before B arrives the fold also
/// validates [`SIDE_TIP_STATES`] newer side blocks (one-block forks on P in
/// 8619, as further proposers' variants or short forks of a stalled network
/// produce), each of which keeps its state in the ring: H1's and A1's
/// exact post-states are evicted. In 84040ce0 B was then judged on
/// `fallback`, parked, and never judged again: H1 is validated, so no
/// longer a fold candidate, and the head does not move. Now the door asks
/// for H1's state, the fold recomputes it from the nearest exact ancestor
/// within its budgets, B is queued again and admitted on H1's own state,
/// rolled into 8622, while the head stays H2.
///
/// `cargo test --release -p bloch-pos-node --bin bloch-pos -- --ignored left_the_ring`.
#[test]
#[ignore = "several minutes: drives a real chain to epoch 8622"]
fn a_bind_crossing_block_whose_validated_side_parent_left_the_ring_is_admitted_after_recomputation() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let bind = KES_ACTIVATION_EPOCH + KES_BIND_DELAY_EPOCHS;
    let (mut engine, _dir, [a1, h1, h2, b], env_b, sb, forks) = deeper_siblings_fixture_with(SIDE_TIP_STATES);
    engine.live = true;

    // The fold: A1 and H1 first (the longer branch), then every fork.
    let mut slot = sb;
    let all_validated =
        |e: &Engine| [a1, h1].iter().chain(forks.iter()).all(|id| e.blocks.is_validated(id));
    while !all_validated(&engine) {
        assert!(slot < sb + 64, "the fold validates every side block within a few slots");
        let _w = wall_at(&mut engine, slot);
        for _ in 0..4 {
            engine.validate_side_branch_turn(slot);
        }
        slot += 1;
    }
    {
        let _w = wall_at(&mut engine, slot);
        engine.validate_side_branch_turn(slot);
        engine.validate_side_branch_turn(slot);
    }
    assert!(engine.reorg_anchors.side.cursor.is_none(), "the cursor is dropped");
    assert_eq!(*engine.head_id().as_bytes(), h2, "a stalled head: validation adopted nothing");
    assert!(
        engine.exact_parent_state(&h1).is_none() && engine.exact_parent_state(&a1).is_none(),
        "RC4-01: newer side states evicted H1's and A1's"
    );

    // B by gossip: judged on `fallback`, parked, and H1's state is asked for.
    {
        let _w = wall_at(&mut engine, slot);
        let (verdict, landed) = engine.ingest_one(env_b.clone(), Source::Gossip(Some([0x59; 32])));
        assert_eq!(verdict, Verdict::Ignore);
        assert!(landed.is_none());
    }
    assert!(engine.orphans.iter().any(|(id, ..)| *id == b), "B is parked");
    assert!(engine.authority_parked.judged.contains_key(&b), "for its proposer's authority");
    assert!(engine.authority_parked_due().is_empty(), "the head did not change: the old trigger never fires");
    assert!(engine.reorg_anchors.side.wanting.contains(&b), "the door asked for H1's state");

    // The fold recomputes it; B is queued again and admitted on it.
    let mut admitted = false;
    for _ in 0..32 {
        slot += 1;
        let _w = wall_at(&mut engine, slot);
        engine.requeue_budget_parked_blocks(slot);
        for _ in 0..4 {
            engine.validate_side_branch_turn(slot);
        }
        while engine.deferred_orphans.iter().any(|(id, ..)| *id == b) {
            engine.release_orphan_turn();
        }
        if engine.blocks.contains_key(&b) || engine.canonical.contains(&b) {
            admitted = true;
            break;
        }
    }
    assert!(admitted, "B is admitted once H1's state is recomputed");
    assert!(!engine.orphans.iter().any(|(id, ..)| *id == b), "not parked again");
    assert_eq!(engine.state.door_cached(&h1, bind).expect("cached by (H1, 8622)").kes_enforced_from(), Some(bind));
    {
        let _w = wall_at(&mut engine, slot + 1);
        engine.validate_side_branch_turn(slot + 1);
    }
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "served, and the request is gone");
}

/// **Reviews RC5-07 and RC5-08, through the whole door (`ingest_one`), at
/// a cheap height.** A stored, validated side-branch parent P2 whose state
/// and whose parent's state (P1) this node does not hold, and children of
/// it in an epoch a KES bind can govern:
///
/// - a header no key of the proposer signed is refused by the probe and
///   never asks for P2's state (no recomputation for an unauthenticated
///   header);
/// - a header the proposer really signed passes the probe, the door asks
///   for P2's state (`JudgeWantingParentState`), and since the static
///   signature verifies on `fallback` the block is not parked: nothing is
///   recorded either (RC5-07: only a block parked for its authority is);
/// - this node's own block (no probe) whose signature does not verify on
///   `fallback` is parked for its proposer's authority and is wanted.
///   Serving it runs P1 through the transition, which refuses it: P1 is
///   removed and remembered and the request is given up.
#[test]
fn the_door_asks_for_a_side_parent_state_only_for_a_block_it_parked_past_the_probe() {
    use bloch_pos_committee::params::{KES_ACTIVATION_EPOCH, KES_BIND_DELAY_EPOCHS};
    let (mut engine, _dir) = perf_support::proposing_engine();
    engine.propose(1);
    let head = *engine.head_id().as_bytes();
    let template = engine.blocks.get(&head).expect("the block just proposed").clone();
    let bind = KES_ACTIVATION_EPOCH + KES_BIND_DELAY_EPOCHS;
    let mut p1_env = template.clone();
    p1_env.header.parent = head;
    p1_env.header.slot = first_slot_of_epoch(bind - 22).unwrap() + 1;
    let p1 = *p1_env.block_id().as_bytes();
    engine.blocks.insert(p1, p1_env);
    let mut p2_env = template.clone();
    p2_env.header.parent = p1;
    p2_env.header.slot = first_slot_of_epoch(bind - 22).unwrap() + 2;
    let p2 = *p2_env.block_id().as_bytes();
    engine.blocks.insert(p2, p2_env);
    engine.blocks.mark_validated(&p2);
    assert!(engine.exact_parent_state(&p2).is_none() && engine.exact_parent_state(&p1).is_none());
    let child = |k: u64, signature: Option<&Engine>| {
        let mut env = template.clone();
        env.header.parent = p2;
        env.header.slot = first_slot_of_epoch(bind).unwrap() + 1 + k;
        env.proposer_sig = match signature {
            Some(engine) => engine.keys.as_ref().unwrap().sign_for_epoch(bind, &env.header.proposal_signing_root()),
            None => vec![0xEE; 64],
        };
        env
    };
    let wall = first_slot_of_epoch(bind).unwrap() + 4;
    let _w = wall_at(&mut engine, wall);

    let unsigned = child(0, None);
    let unsigned_id = *unsigned.block_id().as_bytes();
    let (verdict, _) = engine.ingest_one(unsigned, Source::Gossip(Some([0xC1; 32])));
    assert_ne!(verdict, Verdict::Accept);
    assert!(!engine.reorg_anchors.side.wanting.contains(&unsigned_id), "no request for an unsigned header");
    assert!(engine.reorg_anchors.side.wanting.is_empty());

    let own = child(2, None);
    let own_id = *own.block_id().as_bytes();
    let (verdict, _) = engine.ingest_one(own, Source::Local);
    assert_eq!(verdict, Verdict::Ignore);
    assert!(engine.authority_parked.judged.contains_key(&own_id), "fixture: parked for its authority");
    assert!(engine.reorg_anchors.side.wanting.contains(&own_id), "and wanted");

    assert!(engine.blocks.contains_key(&p1), "fixture: P1 is stored");
    assert_eq!(engine.serve_wanted_side_state_turn(), Some(false));
    assert!(!engine.blocks.contains_key(&p1), "P1 failed the transition: removed");
    assert!(engine.reorg_anchors.side.failed_index.contains(&p1), "and remembered");
    assert!(engine.reorg_anchors.side.wanting.is_empty(), "the request is given up");

    // Last: an authenticated child may be stored and weighed by fork choice.
    let signed = child(1, Some(&engine));
    let signed_id = *signed.block_id().as_bytes();
    let fallback = engine.proposer_authority_state(&p2);
    assert!(
        matches!(
            engine.door_kes_state(&signed, Source::Gossip(Some([0xC2; 32])), None, fallback),
            DoorKes::JudgeWantingParentState { .. }
        ),
        "past the probe, the door asks"
    );
    let _ = engine.ingest_one(signed, Source::Gossip(Some([0xC3; 32])));
    assert!(!engine.authority_parked.judged.contains_key(&signed_id), "fixture: authenticated, not parked");
    assert!(!engine.reorg_anchors.side.wanting.contains(&signed_id), "RC5-07: so not wanted");

    assert_eq!(*engine.head_id().as_bytes(), head, "the head did not move");
}
