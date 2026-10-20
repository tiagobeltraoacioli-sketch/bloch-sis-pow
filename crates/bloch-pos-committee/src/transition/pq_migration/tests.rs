// Included into `transition::tests::pq_migration` (see transition.rs).
use crate::params::{
    pq_migration_rehearsal, RESCUE_COMMIT_MIN_DELAY_EPOCHS, RESCUE_COMMIT_TTL_EPOCHS,
};
use crate::transition::pq_migration::*;

const NET: [u8; 32] = [0x91; 32];

/// Lattice hybrid key in the live enveloped shape (suite 0x0001).
fn lattice_key(tag: u8) -> Vec<u8> {
    let mut k = vec![tag; crate::transition::funded::ADMISSION_PQ_KEY_BYTES];
    k[..4].copy_from_slice(&[0xb1, 0x0c, 0x01, 0x00]);
    k
}

/// Hash-based suite key (suite 0x0003): envelope ‖ SLH pk ‖ Falcon pk.
fn slh_key(tag: u8) -> Vec<u8> {
    let mut k = vec![tag; SLH_SUITE_PUBKEY_BYTES];
    k[..4].copy_from_slice(&[0xb1, 0x0c, 0x03, 0x00]);
    k
}

fn entry(txid: u8, vout: u32, value_bloch: u128, script: [u8; 32]) -> crate::state_root::EutxoEntry {
    crate::state_root::EutxoEntry {
        txid: [txid; 32],
        vout,
        value: u64::try_from(sat(value_bloch)).unwrap(),
        script_hash: script,
    }
}

fn state_with(opening: &[crate::state_root::EutxoEntry]) -> CommittedState {
    let (_, mut st, _) = setup_with(4, ToyVerifier, opening);
    st.admission_network_domain = Some(NET);
    st
}

/// Pretend epochs passed and `finalized_epoch` finalized, without running
/// the chain: the rules under test read only these two committed values.
fn at_epoch(st: &mut CommittedState, epoch: u64, finalized_epoch: u64) {
    st.epoch = epoch;
    st.finality_engine = finality::FinalityState::new(finality::Checkpoint {
        epoch: finalized_epoch,
        root: [0xF1; 32],
    });
}

// ─── gates ──────────────────────────────────────────────────────────────────

/// TRIPWIRE. Both flag days ship inert; arming either is a founder decision
/// with a replay, a mixed-fleet qualification and a coordinated epoch.
#[test]
fn pq_migration_gates_ship_inert() {
    assert_eq!(crate::params::HF3_PQ_MIGRATION_EPOCH, u64::MAX);
    assert_eq!(crate::params::LATTICE_EMERGENCY_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::hf3_pq_migration_active(u64::MAX - 1));
    assert!(!crate::params::lattice_emergency_active(u64::MAX - 1));
}

#[test]
fn suite_classifier_fails_closed() {
    assert_eq!(key_suite(&lattice_key(1)), Some(SUITE_MLDSA65_FALCON1024));
    assert_eq!(key_suite(&vec![7u8; crate::staking::HYBRID_PK_BYTES]), Some(SUITE_MLDSA65_FALCON1024));
    assert_eq!(key_suite(&slh_key(1)), Some(SUITE_SLHDSA128S_FALCON1024));
    assert!(is_hash_based_key(&slh_key(1)));
    assert!(!is_hash_based_key(&lattice_key(1)));
    // Right tag, wrong length; unknown suite; garbage: never hash-based.
    let mut short = slh_key(1);
    short.pop();
    assert!(!is_hash_based_key(&short));
    assert!(!is_hash_based_key(&[0xb1, 0x0c, 0x09, 0x00, 1, 2]));
    assert!(!is_hash_based_key(&[]));
}

/// The address already commits to (suite, key): the same key bytes under a
/// different suite header hash to a different script.
#[test]
fn address_commits_to_the_suite() {
    let mut a = slh_key(5);
    let b = a.clone();
    a[2] = 0x01;
    assert_ne!(native_script(&a), native_script(&b));
}

// ─── withdrawal-credential rotation ─────────────────────────────────────────

fn rotation(st: &CommittedState, auth: &[u8], new_key: &[u8]) -> WithdrawalCredentialRotation {
    let mut tx = WithdrawalCredentialRotation {
        network_domain: NET,
        epoch: st.epoch,
        validator: 0,
        authorizing_pubkey: auth.to_vec(),
        new_pubkey: new_key.to_vec(),
        authorizing_signature: Vec::new(),
        new_key_signature: Vec::new(),
    };
    let root = tx.signing_root();
    tx.authorizing_signature = toy_sign(auth, &root);
    tx.new_key_signature = toy_sign(new_key, &root);
    tx
}

fn rotation_fixture() -> (CommittedState, Vec<u8>) {
    let owner = lattice_key(0x21);
    let mut st = state_with(&[]);
    st.validators.get_mut(&0).unwrap().withdrawal_credentials = native_script(&owner).to_vec();
    (st, owner)
}

#[test]
fn rotation_is_inert_and_atomic_without_the_gate() {
    let (mut st, owner) = rotation_fixture();
    let tx = rotation(&st, &owner, &slh_key(0x31));
    let before = st.clone();
    let root = st.compute_root();
    assert_eq!(
        st.apply_transaction(&PosTransaction::WithdrawalCredentialRotation(tx), 0, 0, &ToyVerifier),
        Err(TxReject::PqMigration(PqMigrationReject::NotActive))
    );
    assert_eq!(st, before);
    assert_eq!(st.compute_root(), root);
}

#[test]
fn rotation_moves_the_bond_destination_to_the_hash_based_key() {
    let _gate = pq_migration_rehearsal::open_slh();
    let (mut st, owner) = rotation_fixture();
    let new_key = slh_key(0x31);
    let root_before = st.compute_root();
    let tx = rotation(&st, &owner, &new_key);
    // Wire round-trip through the real decoder.
    let wire = PosTransaction::WithdrawalCredentialRotation(tx.clone());
    assert_eq!(PosTransaction::from_canonical_bytes(&wire.canonical_bytes()), Ok(wire.clone()));
    st.apply_transaction(&wire, 0, 0, &ToyVerifier).unwrap();
    assert_eq!(st.validators[&0].withdrawal_credentials, native_script(&new_key).to_vec());
    assert_ne!(st.compute_root(), root_before);
    // Replay of the same message: the old key no longer opens the credential.
    assert_eq!(
        st.apply_transaction(&wire, 0, 0, &ToyVerifier),
        Err(TxReject::PqMigration(PqMigrationReject::Credential))
    );
    // The hash-based key can rotate again (key hygiene), to another SLH key.
    let again = rotation(&st, &new_key, &slh_key(0x32));
    st.apply_transaction(&PosTransaction::WithdrawalCredentialRotation(again), 0, 0, &ToyVerifier)
        .unwrap();
    assert_eq!(st.validators[&0].withdrawal_credentials, native_script(&slh_key(0x32)).to_vec());
}

#[test]
fn rotation_accepts_a_carried_credential() {
    let _gate = pq_migration_rehearsal::open_slh();
    let (mut st, owner) = rotation_fixture();
    st.validators.get_mut(&0).unwrap().withdrawal_credentials = carried_script(&owner).to_vec();
    let tx = rotation(&st, &owner, &slh_key(0x31));
    st.apply_withdrawal_credential_rotation(&tx, &ToyVerifier).unwrap();
}

#[test]
fn rotation_rejects_every_wrong_shape_atomically() {
    let _gate = pq_migration_rehearsal::open_slh();
    let (st, owner) = rotation_fixture();
    let new_key = slh_key(0x31);
    let check = |tx: WithdrawalCredentialRotation, want: PqMigrationReject| {
        let mut s = st.clone();
        assert_eq!(s.apply_withdrawal_credential_rotation(&tx, &ToyVerifier), Err(want));
        assert_eq!(s, st, "a refused rotation must leave state untouched");
    };
    // The validator's consensus key is not the credential owner.
    let consensus_key = st.validators[&0].pubkey.clone();
    check(rotation(&st, &consensus_key, &new_key), PqMigrationReject::Credential);
    check(rotation(&st, &lattice_key(0x22), &new_key), PqMigrationReject::Credential);
    // Rotation only ever moves TO the hash-based suite.
    check(rotation(&st, &owner, &lattice_key(0x23)), PqMigrationReject::NotHashBased);
    let mut tx = rotation(&st, &owner, &new_key);
    tx.authorizing_signature[0] ^= 1;
    check(tx, PqMigrationReject::Signature);
    let mut tx = rotation(&st, &owner, &new_key);
    tx.new_key_signature[0] ^= 1;
    check(tx, PqMigrationReject::NewKeySignature);
    let mut tx = rotation(&st, &owner, &new_key);
    tx.epoch += 1;
    check(tx, PqMigrationReject::Epoch);
    let mut tx = rotation(&st, &owner, &new_key);
    tx.network_domain = [0; 32];
    check(tx, PqMigrationReject::Network);
    let mut tx = rotation(&st, &owner, &new_key);
    tx.validator = 99;
    check(tx, PqMigrationReject::Validator);
    // Paid-out bonds have nothing left to protect.
    let mut paid = st.clone();
    paid.validators.get_mut(&0).unwrap().staked_sat = 0;
    let tx = rotation(&paid, &owner, &new_key);
    assert_eq!(
        paid.apply_withdrawal_credential_rotation(&tx, &ToyVerifier),
        Err(PqMigrationReject::Validator)
    );
}

#[test]
fn after_the_break_a_lattice_rotation_needs_a_matured_commitment() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let (mut st, owner) = rotation_fixture();
    let new_key = slh_key(0x31);
    let tx = rotation(&st, &owner, &new_key);
    // A valid lattice signature alone is worthless after the break.
    assert_eq!(
        st.clone().apply_withdrawal_credential_rotation(&tx, &ToyVerifier),
        Err(PqMigrationReject::CommitmentUnknown)
    );
    let c = rescue_credential_commitment(0, &owner, &native_script(&new_key));
    st.apply_rescue_commit(&RescueCommit { network_domain: NET, commitment: c }).unwrap();
    let committed_at = st.epoch;
    at_epoch(&mut st, committed_at + RESCUE_COMMIT_MIN_DELAY_EPOCHS, committed_at + 2);
    let tx = rotation(&st, &owner, &new_key);
    st.apply_withdrawal_credential_rotation(&tx, &ToyVerifier).unwrap();
    assert_eq!(st.validators[&0].withdrawal_credentials, native_script(&new_key).to_vec());
    assert_eq!(st.pq_rescue_commitment_epoch(&c), None, "commitment consumed");
}

#[test]
fn after_the_break_a_hash_based_credential_still_rotates_directly() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let owner = slh_key(0x41);
    let mut st = state_with(&[]);
    st.validators.get_mut(&0).unwrap().withdrawal_credentials = native_script(&owner).to_vec();
    let tx = rotation(&st, &owner, &slh_key(0x42));
    st.apply_withdrawal_credential_rotation(&tx, &ToyVerifier).unwrap();
}

// ─── funds: the emergency freeze ────────────────────────────────────────────

fn transfer_by(pubkey: &[u8]) -> PosTransaction {
    PosTransaction::Transfer {
        inputs: vec![TransferInput { txid: [1; 32], vout: 0, pubkey: pubkey.to_vec(), signature: vec![] }],
        outputs: vec![],
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    }
}

#[test]
fn lattice_spend_freeze_is_inert_below_the_gate() {
    let st = state_with(&[]);
    assert_eq!(st.check_lattice_spend_freeze(&transfer_by(&lattice_key(1))), Ok(()));
    let _slh_only = pq_migration_rehearsal::open_slh();
    assert_eq!(st.check_lattice_spend_freeze(&transfer_by(&lattice_key(1))), Ok(()));
}

#[test]
fn after_the_break_only_hash_based_keys_spend_directly() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let st = state_with(&[]);
    assert_eq!(
        st.check_lattice_spend_freeze(&transfer_by(&lattice_key(1))),
        Err(TxReject::PqMigration(PqMigrationReject::LatticeSpendFrozen))
    );
    // Legacy raw hybrid keys and unknown suites are frozen too.
    assert!(st.check_lattice_spend_freeze(&transfer_by(&vec![9; crate::staking::HYBRID_PK_BYTES])).is_err());
    assert!(st.check_lattice_spend_freeze(&transfer_by(&[0xb1, 0x0c, 0x02, 0x00, 1])).is_err());
    assert_eq!(st.check_lattice_spend_freeze(&transfer_by(&slh_key(1))), Ok(()));
    let v2 = PosTransaction::TransferV2 {
        keys: vec![
            WitnessKey { pubkey: slh_key(1), signature: vec![] },
            WitnessKey { pubkey: lattice_key(2), signature: vec![] },
        ],
        inputs: vec![],
        outputs: vec![],
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    };
    assert!(st.check_lattice_spend_freeze(&v2).is_err(), "one lattice owner freezes the whole transfer");
    // And through the real dispatch, before any other rule runs.
    let mut s = st.clone();
    assert_eq!(
        s.apply_transaction(&transfer_by(&lattice_key(1)), 0, 0, &ToyVerifier),
        Err(TxReject::PqMigration(PqMigrationReject::LatticeSpendFrozen))
    );
}

// ─── funds: commit-reveal rescue ────────────────────────────────────────────

struct Rescue {
    st: CommittedState,
    key: Vec<u8>,
    dest: [u8; 32],
    committed_at: u64,
}

/// A lattice key owning two native outputs and one carried output, a
/// commitment to sweep them to an SLH address, and the clock moved to the
/// first epoch the commitment is usable.
fn rescue_fixture() -> Rescue {
    let key = lattice_key(0x51);
    let other = lattice_key(0x52);
    let mut st = state_with(&[
        entry(0xA1, 0, 10, native_script(&key)),
        entry(0xA2, 3, 20, native_script(&key)),
        entry(0xA3, 1, 5, carried_script(&key)),
        entry(0xA4, 0, 7, native_script(&other)),
    ]);
    let dest = native_script(&slh_key(0x61));
    let committed_at = st.epoch;
    st.apply_rescue_commit(&RescueCommit {
        network_domain: NET,
        commitment: rescue_spend_commitment(&key, &dest, 0),
    })
    .unwrap();
    at_epoch(&mut st, committed_at + RESCUE_COMMIT_MIN_DELAY_EPOCHS, committed_at + 1);
    Rescue { st, key, dest, committed_at }
}

fn reveal(key: &[u8], inputs: &[(u8, u32)], dest: [u8; 32], tip: u128) -> RescueReveal {
    let mut inputs: Vec<FundingInput> =
        inputs.iter().map(|(t, v)| FundingInput { txid: [*t; 32], vout: *v }).collect();
    inputs.sort_by_key(|i| (i.txid, i.vout));
    let mut tx = RescueReveal {
        network_domain: NET,
        pubkey: key.to_vec(),
        inputs,
        destination_script_hash: dest,
        tip_millisat_per_gas: tip,
        tx_bytes: 0,
        signature: toy_sign(key, &[0; 32]), // placeholder of final length
    };
    tx.tx_bytes = tx.exact_tx_bytes();
    tx.signature = toy_sign(key, &tx.signing_root());
    tx
}

const ALL: &[(u8, u32)] = &[(0xA1, 0), (0xA2, 3), (0xA3, 1)];

#[test]
fn rescue_messages_are_inert_without_the_emergency() {
    let _slh_only = pq_migration_rehearsal::open_slh();
    let mut st = state_with(&[]);
    let before = st.clone();
    let commit = PosTransaction::RescueCommit(RescueCommit { network_domain: NET, commitment: [3; 32] });
    assert_eq!(
        st.apply_transaction(&commit, 0, 0, &ToyVerifier),
        Err(TxReject::PqMigration(PqMigrationReject::NotActive))
    );
    let r = PosTransaction::RescueReveal(reveal(&lattice_key(1), &[(1, 0)], [0; 32], 0));
    assert_eq!(
        st.apply_transaction(&r, 0, 0, &ToyVerifier),
        Err(TxReject::PqMigration(PqMigrationReject::NotActive))
    );
    assert_eq!(st, before);
}

#[test]
fn rescue_wire_round_trips() {
    let c = PosTransaction::RescueCommit(RescueCommit { network_domain: NET, commitment: [3; 32] });
    assert_eq!(PosTransaction::from_canonical_bytes(&c.canonical_bytes()), Ok(c.clone()));
    let r = PosTransaction::RescueReveal(reveal(&lattice_key(1), ALL, [4; 32], 7));
    assert_eq!(PosTransaction::from_canonical_bytes(&r.canonical_bytes()), Ok(r.clone()));
    assert_ne!(c.txid(), r.txid());
}

/// An empty commitment map adds nothing to the state root; a non-empty one
/// is committed. This is what keeps every pre-emergency root identical.
#[test]
fn commitments_are_root_neutral_until_present() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let mut st = state_with(&[]);
    let empty_root = st.compute_root();
    st.apply_rescue_commit(&RescueCommit { network_domain: NET, commitment: [3; 32] }).unwrap();
    assert_ne!(st.compute_root(), empty_root);
    st.pq_rescue_commits.clear();
    assert_eq!(st.compute_root(), empty_root);
}

#[test]
fn a_commitment_keeps_its_first_epoch() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let mut st = state_with(&[]);
    let c = RescueCommit { network_domain: NET, commitment: [3; 32] };
    st.apply_rescue_commit(&c).unwrap();
    let first = st.pq_rescue_commitment_epoch(&[3; 32]).unwrap();
    st.epoch += 5;
    assert_eq!(st.apply_rescue_commit(&c), Err(PqMigrationReject::CommitmentExists));
    assert_eq!(st.pq_rescue_commitment_epoch(&[3; 32]), Some(first));
    let charge = st.clone().apply_rescue_commit(&RescueCommit { network_domain: NET, commitment: [4; 32] }).unwrap();
    assert_eq!(charge.base_fee_sat + charge.priority_fee_sat, 0, "commits are fee-free");
    assert_eq!(charge.gas, fee_market::BLOCK_GAS_LIMIT / crate::params::RESCUE_COMMITS_PER_BLOCK);
}

#[test]
fn rescue_sweeps_every_output_of_the_key_to_the_committed_destination() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let Rescue { mut st, key, dest, .. } = rescue_fixture();
    let tx = reveal(&key, ALL, dest, 0);
    let base_fee = st.base_fee_millisat_per_gas;
    let charge = st.apply_rescue_reveal(&tx, base_fee, &ToyVerifier).unwrap();
    let fee = charge.base_fee_sat + charge.priority_fee_sat;
    let txid = PosTransaction::RescueReveal(tx.clone()).txid();
    let out = st.eutxos.get(&(txid, 0)).expect("rescued output");
    assert_eq!(out.script_hash, dest);
    assert_eq!(u128::from(out.value) + fee, sat(35));
    for (t, v) in ALL {
        assert!(st.eutxos.get(&([*t; 32], *v)).is_none());
    }
    assert!(st.eutxos.get(&([0xA4; 32], 0)).is_some(), "another owner's coin is untouched");
    assert_eq!(st.pq_rescue_commitment_epoch(&tx.commitment()), None, "commitment consumed");
    // A second reveal finds nothing to sweep.
    assert_eq!(
        st.apply_rescue_reveal(&tx, base_fee, &ToyVerifier),
        Err(PqMigrationReject::MissingInput)
    );
}

#[test]
fn rescue_rejects_atomically() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let Rescue { st, key, dest, committed_at } = rescue_fixture();
    let base_fee = st.base_fee_millisat_per_gas;
    let check = |s: &CommittedState, tx: RescueReveal, want: PqMigrationReject| {
        let mut s2 = s.clone();
        assert_eq!(s2.apply_rescue_reveal(&tx, base_fee, &ToyVerifier), Err(want));
        assert_eq!(&s2, s, "a refused reveal must leave state untouched");
    };
    // Leaving the carried output behind would expose it to any forger.
    check(&st, reveal(&key, &[(0xA1, 0), (0xA2, 3)], dest, 0), PqMigrationReject::IncompleteSweep);
    // Someone else's coin.
    check(&st, reveal(&key, &[(0xA1, 0), (0xA2, 3), (0xA3, 1), (0xA4, 0)], dest, 0), PqMigrationReject::Ownership);
    // Destination or tip differ from the commitment: a relay or forger cannot
    // redirect or re-price an honest reveal.
    check(&st, reveal(&key, ALL, [0xEE; 32], 0), PqMigrationReject::CommitmentUnknown);
    check(&st, reveal(&key, ALL, dest, 1_000), PqMigrationReject::CommitmentUnknown);
    let mut tx = reveal(&key, ALL, dest, 0);
    tx.tx_bytes += 1;
    check(&st, tx, PqMigrationReject::Size);
    let mut tx = reveal(&key, ALL, dest, 0);
    tx.inputs.swap(0, 1);
    check(&st, tx, PqMigrationReject::DuplicateInput);
    let mut tx = reveal(&key, ALL, dest, 0);
    tx.signature[0] ^= 1;
    check(&st, tx, PqMigrationReject::Signature);
    // A hash-based key never needs the rescue.
    check(&st, reveal(&slh_key(1), ALL, dest, 0), PqMigrationReject::NotLatticeKey);
    // Timing: too young, not yet finalized, expired.
    let mut young = st.clone();
    at_epoch(&mut young, committed_at + RESCUE_COMMIT_MIN_DELAY_EPOCHS - 1, committed_at + 1);
    check(&young, reveal(&key, ALL, dest, 0), PqMigrationReject::CommitmentImmature);
    let mut unfinal = st.clone();
    at_epoch(&mut unfinal, committed_at + RESCUE_COMMIT_MIN_DELAY_EPOCHS, committed_at);
    check(&unfinal, reveal(&key, ALL, dest, 0), PqMigrationReject::CommitmentNotFinal);
    let mut old = st.clone();
    at_epoch(&mut old, committed_at + RESCUE_COMMIT_TTL_EPOCHS + 1, committed_at + 1);
    check(&old, reveal(&key, ALL, dest, 0), PqMigrationReject::CommitmentExpired);
}

/// The front-running scenario the design exists for: an attacker who can
/// forge lattice signatures learns the key from the owner's pending reveal
/// and races it. Its own commitment is necessarily younger than the owner's,
/// so it cannot be cited until the owner's reveal has long been includable;
/// once that lands, there is nothing left to steal.
#[test]
fn a_forger_who_learns_the_key_from_the_mempool_cannot_front_run() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let Rescue { mut st, key, dest, committed_at } = rescue_fixture();
    let thief = native_script(&slh_key(0x66));
    st.apply_rescue_commit(&RescueCommit {
        network_domain: NET,
        commitment: rescue_spend_commitment(&key, &thief, 0),
    })
    .unwrap();
    let base_fee = st.base_fee_millisat_per_gas;
    // Same epoch, everything forged perfectly (the toy verifier accepts the
    // thief's signature because the key is the owner's): still immature.
    assert_eq!(
        st.clone().apply_rescue_reveal(&reveal(&key, ALL, thief, 0), base_fee, &ToyVerifier),
        Err(PqMigrationReject::CommitmentImmature)
    );
    // A plain transfer with a forged lattice signature is frozen outright.
    assert!(st.check_lattice_spend_freeze(&transfer_by(&key)).is_err());
    st.apply_rescue_reveal(&reveal(&key, ALL, dest, 0), base_fee, &ToyVerifier).unwrap();
    // Even once the thief's commitment matures, the coins are gone.
    let thief_epoch = st.epoch;
    at_epoch(&mut st, thief_epoch + RESCUE_COMMIT_MIN_DELAY_EPOCHS, thief_epoch + 1);
    assert_eq!(
        st.apply_rescue_reveal(&reveal(&key, ALL, thief, 0), base_fee, &ToyVerifier),
        Err(PqMigrationReject::MissingInput)
    );
    let _ = committed_at;
}

#[test]
fn expired_commitments_are_pruned_at_the_boundary() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let mut st = state_with(&[]);
    st.apply_rescue_commit(&RescueCommit { network_domain: NET, commitment: [1; 32] }).unwrap();
    let at = st.epoch;
    st.epoch = at + 10;
    st.apply_rescue_commit(&RescueCommit { network_domain: NET, commitment: [2; 32] }).unwrap();
    st.prune_pq_rescue_commits(at + RESCUE_COMMIT_TTL_EPOCHS);
    assert_eq!(st.pq_rescue_commits.len(), 2);
    st.prune_pq_rescue_commits(at + RESCUE_COMMIT_TTL_EPOCHS + 1);
    assert_eq!(st.pq_rescue_commitment_epoch(&[1; 32]), None);
    assert_eq!(st.pq_rescue_commitment_epoch(&[2; 32]), Some(at + 10));
}

#[test]
#[cfg(feature = "local-state-cache")]
fn local_cache_round_trips_rescue_commitments() {
    let _gate = pq_migration_rehearsal::open_emergency();
    let mut st = state_with(&[]);
    let empty = st.encode_local_cache().unwrap();
    assert_eq!(empty, st.encode_local_cache_owned_reference().unwrap(), "no section while empty");
    st.apply_rescue_commit(&RescueCommit { network_domain: NET, commitment: [1; 32] }).unwrap();
    let header = crate::header::BlockHeaderV4 {
        version: crate::transition::BLOCK_VERSION_V4, parent: [0; 32], state_root: st.compute_root(),
        body_root: [0; 32], slot: st.slot, proposer_index: 0,
        randao_reveal: [0; 32], randao_mix: st.randao_mix,
        justified_root: [0; 32], finalized_root: [0; 32],
        attestation_root: [0; 32], coherence_root: [0; 32],
    };
    st.head = header.id();
    let bytes = st.encode_local_cache().unwrap();
    assert_eq!(CommittedState::decode_local_cache(&bytes, &header).unwrap(), st);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CommittedState::decode_local_cache(&trailing, &header).is_err());
}

/// The PQ bytes come from the HF3 allocation table and nowhere else: 0x17
/// (KesRegister) and 0x1B (KesRotate) sit on either side, 0x24 is the
/// rescue-commitment state tag, and this tree decodes neither KES byte.
#[test]
fn pq_wire_bytes_follow_the_hf3_allocation() {
    use crate::wire_alloc::{state, tx};
    assert_eq!(
        [WITHDRAWAL_CREDENTIAL_ROTATION_TAG, RESCUE_COMMIT_TAG, RESCUE_REVEAL_TAG],
        [0x18, 0x19, 0x1A]
    );
    assert_eq!(state::PQ_RESCUE_COMMIT, 0x24);
    for kes in [tx::KES_REGISTER, tx::KES_ROTATE] {
        assert_eq!(PosTransaction::from_canonical_bytes(&[kes]), Err(TxDecodeError::UnknownTag(kes)));
    }
    // Every PQ tag decodes to its own variant on this tree (round trip).
    let tx = PosTransaction::RescueCommit(RescueCommit {
        network_domain: NET,
        commitment: rescue_spend_commitment(&lattice_key(0x51), &native_script(&slh_key(0x61)), 0),
    });
    let bytes = tx.canonical_bytes();
    assert_eq!(bytes[0], RESCUE_COMMIT_TAG);
    assert_eq!(PosTransaction::from_canonical_bytes(&bytes), Ok(tx));
}
