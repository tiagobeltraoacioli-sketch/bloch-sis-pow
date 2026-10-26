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
