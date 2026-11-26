// AUDIT-L1L2-20261123 L1S-02. A withdrawal-credential rotation (wire 0x18)
// pays no fee, could be repeated without limit (A -> B -> A ...), and its gas
// and bytes fed the base-fee controller. Two gated rules, both inert as
// shipped: only paid usage moves the base fee
// (`FEE_CONTROLLER_PAID_USAGE_ACTIVATION_EPOCH`) and one rotation per
// validator per epoch (`CREDENTIAL_ROTATION_LIMIT_ACTIVATION_EPOCH`).

/// Accepts a signature whose first 32 bytes are the toy signature; the rest
/// is padding, so the transactions have the size real suite-0x0003
/// signatures have (4 + 7,856 + about 1,280 bytes).
struct FixL1s02PaddedVerifier;
impl SignatureVerifier for FixL1s02PaddedVerifier {
    fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        sig.len() >= 32 && sig[..32] == toy_sign(pk, root)[..]
    }
}

/// Past HF3 (7360): every gate but the two under test is read from the real
/// epoch constants.
const FIX_L1S02_EPOCH: u64 = 9_000;

fn fix_l1s02_rotation(epoch: u64, validator: u32, auth: &[u8], new_key: &[u8]) -> PosTransaction {
    let mut tx = WithdrawalCredentialRotation {
        network_domain: NET,
        epoch,
        validator,
        authorizing_pubkey: auth.to_vec(),
        new_pubkey: new_key.to_vec(),
        authorizing_signature: Vec::new(),
        new_key_signature: Vec::new(),
    };
    let root = tx.signing_root();
    for (key, sig) in [(auth, &mut tx.authorizing_signature), (new_key, &mut tx.new_key_signature)] {
        *sig = toy_sign(key, &root);
        sig.resize(4 + 7_856 + 1_280, 0x5a);
    }
    PosTransaction::WithdrawalCredentialRotation(tx)
}

fn fix_l1s02_key(v: u32, side: u8) -> Vec<u8> {
    let mut k = slh_key(side);
    k[4..8].copy_from_slice(&v.to_le_bytes());
    k
}

struct FixL1s02Run {
    start_fee: u128,
    state: CommittedState,
    t: Transition<FixL1s02PaddedVerifier>,
    chains: Vec<RandaoChain>,
    coin: crate::state_root::EutxoEntry,
    owner: Vec<u8>,
}

/// The finding's attack: `blocks` consecutive blocks, each carrying one
/// rotation for each of the first `identities` validators (A -> B, B -> A).
fn fix_l1s02_run(identities: u32, blocks: u64) -> FixL1s02Run {
    let owner = owner_key(0x37);
    let coin = opening(0x74, 0, 21_000_000_000_000_000, &owner);
    let (t, mut st, mut chains) = setup_with(24, FixL1s02PaddedVerifier, std::slice::from_ref(&coin));
    st.admission_network_domain = Some(NET);
    st.epoch = FIX_L1S02_EPOCH;
    st.slot = FIX_L1S02_EPOCH * SLOTS_PER_EPOCH;
    for v in 0..identities {
        st.validators.get_mut(&v).unwrap().withdrawal_credentials = native_script(&fix_l1s02_key(v, 0xA1)).to_vec();
    }
    let start_fee = st.next_base_fee();
    for n in 0..blocks {
        let slot = st.slot + 1;
        let (from, to) = if n % 2 == 0 { (0xA1, 0xB2) } else { (0xB2, 0xA1) };
        let body: Vec<PosTransaction> = (0..identities)
            .map(|v| fix_l1s02_rotation(crate::epoch_of(slot), v, &fix_l1s02_key(v, from), &fix_l1s02_key(v, to)))
            .collect();
        let env = build_block(&t, &st, slot, &[], &body, &mut chains);
        st = t.apply_block(&st, &env, &[], &body).unwrap();
    }
    FixL1s02Run { start_fee, state: st, t, chains, coin, owner }
}

#[test]
fn l1s02_fee_gates_are_inert() {
    assert_eq!(crate::params::FEE_CONTROLLER_PAID_USAGE_ACTIVATION_EPOCH, u64::MAX);
    assert_eq!(crate::params::CREDENTIAL_ROTATION_LIMIT_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::fee_controller_paid_usage_active(u64::MAX - 1));
    assert!(!crate::params::credential_rotation_limit_active(u64::MAX - 1));
}

/// The finding's 23-rotation blocks: inert, the base fee ratchets; behind the
/// paid-usage gate it stays where it was, and a paying transfer above the
/// byte target still raises it.
#[test]
fn l1s02_free_usage_does_not_move_the_base_fee_behind_the_gate() {
    let inert = fix_l1s02_run(23, 8);
    assert!(inert.state.next_base_fee() > inert.start_fee, "as shipped the free rotations raise the price");

    let _fix = crate::params::fee_controller_paid_usage_rehearsal::open();
    let FixL1s02Run { start_fee, state: st, t, mut chains, coin, owner } = fix_l1s02_run(23, 8);
    assert_eq!(st.next_base_fee(), start_fee, "free transactions no longer price paying ones out");
    assert_eq!((st.block_gas_used, st.block_tx_bytes), (0, 0));

    let to = script_of(&owner_key(0x38));
    let declared = fee_market::block_tx_bytes_target(FIX_L1S02_EPOCH) + 20_000;
    let paying = transfer_spending(std::slice::from_ref(&coin), &owner, to, declared, 0, st.next_base_fee());
    let slot = st.slot + 1;
    let env = build_block(&t, &st, slot, &[], std::slice::from_ref(&paying), &mut chains);
    let post = t.apply_block(&st, &env, &[], std::slice::from_ref(&paying)).unwrap();
    assert_eq!(post.block_tx_bytes, declared);
    assert!(post.next_base_fee() > start_fee, "paid usage above target still moves the price");
}

/// One rotation per validator per epoch behind the limit gate: the reverse
/// rotation is refused in the same epoch and accepted in the next one; the
/// record is committed, emptied at the boundary, and absent while inert.
#[test]
fn l1s02_one_rotation_per_validator_per_epoch_behind_the_gate() {
    let _gate = pq_migration_rehearsal::open_slh();
    let (base, owner) = rotation_fixture();
    let (a, b) = (slh_key(0x31), slh_key(0x32));
    let wire = |st: &CommittedState, auth: &[u8], new_key: &[u8]| {
        PosTransaction::WithdrawalCredentialRotation(rotation(st, auth, new_key))
    };

    // Inert (as shipped): A -> B -> A in one epoch, nothing recorded.
    let mut inert = base.clone();
    inert.apply_transaction(&wire(&inert, &owner, &a), 0, 0, &ToyVerifier).unwrap();
    inert.apply_transaction(&wire(&inert, &a, &b), 0, 0, &ToyVerifier).unwrap();
    inert.apply_transaction(&wire(&inert, &b, &a), 0, 0, &ToyVerifier).unwrap();
    assert!(inert.credential_rotation_epochs.is_empty());

    let _limit = crate::params::credential_rotation_limit_rehearsal::open();
    let mut st = base.clone();
    let unrecorded_root = {
        let mut same = base.clone();
        same.validators.get_mut(&0).unwrap().withdrawal_credentials = native_script(&a).to_vec();
        same.compute_root()
    };
    st.apply_transaction(&wire(&st, &owner, &a), 0, 0, &ToyVerifier).unwrap();
    assert_eq!(st.credential_rotation_epochs.get(&0), Some(&st.epoch));
    assert_ne!(st.compute_root(), unrecorded_root, "the record is committed");
    let before = st.clone();
    assert_eq!(
        st.apply_transaction(&wire(&st, &a, &b), 0, 0, &ToyVerifier),
        Err(TxReject::PqMigration(PqMigrationReject::AlreadyRotated))
    );
    assert_eq!(st, before, "a refused rotation changes nothing");
    // Another validator is not affected.
    st.validators.get_mut(&1).unwrap().withdrawal_credentials = native_script(&owner).to_vec();
    let mut other = rotation(&st, &owner, &a);
    other.validator = 1;
    let root = other.signing_root();
    other.authorizing_signature = toy_sign(&owner, &root);
    other.new_key_signature = toy_sign(&a, &root);
    st.apply_transaction(&PosTransaction::WithdrawalCredentialRotation(other), 0, 0, &ToyVerifier).unwrap();

    // The restart cache carries the record in its own section.
    #[cfg(feature = "local-state-cache")]
    {
        let bytes = st.encode_local_cache().unwrap();
        assert!(bytes.windows(16).any(|w| w == b"BPOSST01:CROT:v1"));
        assert!(!base.encode_local_cache().unwrap().windows(16).any(|w| w == b"BPOSST01:CROT:v1"));
    }

    // Next epoch: emptied at the boundary, the next rotation is accepted.
    let mut next = st.close_epoch();
    assert!(next.credential_rotation_epochs.is_empty());
    next.apply_transaction(&wire(&next, &a, &b), 0, 0, &ToyVerifier).unwrap();
    assert_eq!(next.validators[&0].withdrawal_credentials, native_script(&b).to_vec());
}
