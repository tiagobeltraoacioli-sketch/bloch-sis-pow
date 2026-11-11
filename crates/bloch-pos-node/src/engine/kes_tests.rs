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
/// enforcement as it always was: SHA3 of the static key.
#[test]
fn the_block_admission_authority_is_the_static_key_hash_while_unarmed() {
    let (engine, _dir) = perf_support::proposing_engine();
    let pk = KeyLookup::pubkey(&*engine.state, 0).unwrap().to_vec();
    let expected: [u8; 32] = Sha3_256::digest(&pk).into();
    for epoch in [0, 1, 1 << 40] {
        assert_eq!(kes::authority_fingerprint(&*engine.state, 0, epoch), Some(expected));
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
