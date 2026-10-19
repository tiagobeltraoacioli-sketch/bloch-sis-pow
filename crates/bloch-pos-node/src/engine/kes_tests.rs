// SPDX-License-Identifier: AGPL-3.0-or-later
//! KES on the node, mainnet line: the registration gate at the mempool door,
//! the pending-registration dedupe, and the duty signer producing real hybrid
//! leaf signatures over the bound message that the consensus verifier
//! accepts — and nothing else. Every key here is a disposable test key.
use super::*;
use crate::keys::{HybridVerifier, KdfParams, Unlock};
use bloch_pos_committee::kes::{self, KesPublic};

fn registration(engine: &Engine, validator: u32, root_byte: u8) -> PosTransaction {
    let public = KesPublic { depth: kes::MIN_DEPTH, root: [root_byte; 32] };
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
    assert_eq!(bloch_pos_committee::params::KES_REGISTRATION_EPOCH, u64::MAX);
    let (mut engine, _dir) = perf_support::proposing_engine();
    let tx = registration(&engine, 0, 0x11);
    for epoch in [0, 4_669, 1 << 40] {
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
    fn kes_public(&self, validator: u32) -> Option<KesPublic> {
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
    let signer = KesSigner { key, dir: dir.clone(), unlock };
    let static_sig = sign_duty(&keys, Some(&signer), None, domain, 4, &root);
    assert_eq!(kes::verify_validator_in(&lookup, &verifier, 4, None, &root, &static_sig), Some(true));

    // Period 2, as `prepare_kes` would leave it.
    let mut signer = signer;
    signer.key.evolve_to(&signer.dir, &signer.unlock, 2).unwrap();
    let sig = sign_duty(&keys, Some(&signer), Some(2), domain, 4, &root);
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
    assert!(sign_duty(&keys, None, Some(2), domain, 4, &root).is_empty());
    assert!(sign_duty(&keys, Some(&signer), Some(2), None, 4, &root).is_empty());
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
        "\"registration_epoch\":null",
        "\"activation_epoch\":null",
        "\"period_epochs\":90",
        "\"registration_open\":false",
        "\"period\":null",
        "\"registered\":[]",
    ] {
        assert!(json.contains(field), "{field} missing from {json}");
    }
}
