//! Adversarial transition tests. The deterministic test verifier binds both key
//! and message; real ML-DSA/Falcon/ECDSA coverage lives in bloch-ustav.
use bloch_euvm::modules::*;
use bloch_euvm::state::{self, SparseMerkleTree};
use bloch_euvm::ustav::*;
use bloch_euvm::{SigVerifier, Val};
use sha2::{Digest, Sha256};

const DOMAIN: [u8; 32] = [42; 32];
const GAS: u64 = 10_000_000;
struct TestVerifier;
fn key(id: u8) -> Vec<u8> {
    vec![id; 32]
}
fn sign(message: &[u8], key: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(key);
    hash.update(message);
    hash.finalize().to_vec()
}
impl SigVerifier for TestVerifier {
    fn verify(&self, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
        self.valid_pq_key(pk) && sig == sign(msg, pk)
    }
    fn verify_ecdsa(&self, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
        self.valid_ecdsa_key(pk) && sig == sign(msg, pk)
    }
}
impl Verifier for TestVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        key.len() == 32 && key[0] != 0
    }
    fn valid_ecdsa_key(&self, key: &[u8]) -> bool {
        key.len() == 33 && key[0] == 2
    }
}
fn basic() -> Registration {
    Registration {
        charter: TokenCharter {
            token_name: b"USTV".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 100,
                issuer_pubkey: key(1),
            })],
        },
        nonce: [9; 32],
        initial_kyc_root: None,
    }
}
fn full() -> Registration {
    let mut r = basic();
    r.charter.modules.extend([
        ModuleKind::TransferPolicy(TransferPolicyConfig {
            authority_pubkey: key(2),
        }),
        ModuleKind::ComplianceKycGate(KycConfig {}),
        ModuleKind::Vesting(VestingConfig {
            unlock_height: 10,
            beneficiary_pubkey: key(3),
        }),
        ModuleKind::Governance(GovernanceConfig {
            threshold: 2,
            signers: vec![key(4), key(5), key(6)],
        }),
        ModuleKind::Custody(CustodyConfig {
            btc_pubkey: vec![2; 33],
            pq_pubkey: key(7),
        }),
    ]);
    r.initial_kyc_root = Some(state::empty_root());
    r
}
fn registered(r: &Registration) -> (Ledger, [u8; 32]) {
    let mut ledger = Ledger::new(DOMAIN);
    let signature = sign(&r.signing_hash(&DOMAIN).unwrap(), &key(1));
    let asset = ledger
        .register(r.clone(), &signature, &TestVerifier, GAS)
        .unwrap();
    (ledger, asset)
}
fn mint(asset: [u8; 32], amount: u64) -> Transaction {
    Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: key(8),
            amount,
        }],
        delta: i128::from(amount),
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    }
}
fn module_witnesses(
    r: &Registration,
    message: &[u8; 32],
    delta: i128,
    spends: bool,
    admin: bool,
) -> Witnesses {
    let bytes = |key: &[u8]| Val::Bytes(sign(message, key));
    Witnesses {
        modules: r
            .charter
            .modules
            .iter()
            .map(|m| match m {
                ModuleKind::Supply(c) if delta != 0 && !admin => vec![bytes(&c.issuer_pubkey)],
                ModuleKind::Supply(_) | ModuleKind::ComplianceKycGate(_) => vec![],
                ModuleKind::TransferPolicy(c) => vec![if admin {
                    bytes(&c.authority_pubkey)
                } else {
                    Val::Bytes(vec![])
                }],
                ModuleKind::Vesting(c) if spends && !admin => vec![bytes(&c.beneficiary_pubkey)],
                ModuleKind::Vesting(_) => vec![],
                ModuleKind::Governance(c) => c.signers.iter().map(|k| bytes(k)).collect(),
                ModuleKind::Custody(c) => vec![bytes(&c.btc_pubkey), bytes(&c.pq_pubkey)],
            })
            .collect(),
        ..Witnesses::default()
    }
}
fn witnesses(ledger: &Ledger, tx: &Transaction) -> Witnesses {
    let message = tx.signing_hash(&DOMAIN).unwrap();
    let mut w = module_witnesses(
        ledger.registration(&tx.asset).unwrap(),
        &message,
        tx.delta,
        !tx.inputs.is_empty(),
        false,
    );
    w.owners = tx
        .inputs
        .iter()
        .map(|id| sign(&message, &ledger.output(id).unwrap().output.owner))
        .collect();
    w
}
fn membership(asset: &[u8; 32], owners: &[Vec<u8>], expiry: u64) -> SparseMerkleTree {
    let mut tree = SparseMerkleTree::new();
    for owner in owners {
        tree.insert(
            &eligibility_key(&DOMAIN, asset, owner),
            &expiry.to_le_bytes(),
        );
    }
    tree
}
fn add_proofs(w: &mut Witnesses, tree: &SparseMerkleTree, asset: &[u8; 32], owners: &[Vec<u8>]) {
    let subjects: std::collections::BTreeSet<_> = owners
        .iter()
        .map(|k| eligibility_key(&DOMAIN, asset, k))
        .collect();
    w.eligibility = subjects.iter().map(|key| tree.prove(key)).collect();
}
fn reject(ledger: &mut Ledger, tx: &Transaction, w: &Witnesses, height: u64) -> Error {
    let before = ledger.snapshot();
    let err = ledger.apply(tx, w, height, &TestVerifier, GAS).unwrap_err();
    assert_eq!(
        ledger.snapshot(),
        before,
        "rejection must be atomic: {err:?}"
    );
    err
}
fn funded() -> (Ledger, Transaction, Receipt) {
    let (mut ledger, asset) = registered(&basic());
    let tx = mint(asset, 60);
    let receipt = ledger
        .apply(&tx, &witnesses(&ledger, &tx), 1, &TestVerifier, GAS)
        .unwrap();
    (ledger, tx, receipt)
}

#[test]
fn mint_transfer_burn_conserves_supply_and_enforces_owner() {
    let (mut ledger, mint, receipt) = funded();
    let tx = Transaction {
        inputs: receipt.outputs,
        outputs: vec![Output {
            owner: key(10),
            amount: 60,
        }],
        delta: 0,
        ..mint
    };
    let w = witnesses(&ledger, &tx);
    let mut bad = w.clone();
    bad.owners[0] = sign(&tx.signing_hash(&DOMAIN).unwrap(), &key(11));
    assert_eq!(reject(&mut ledger, &tx, &bad, 2), Error::InvalidSignature);
    let spent = ledger.apply(&tx, &w, 2, &TestVerifier, GAS).unwrap();
    assert_eq!(ledger.supply(&tx.asset), Some(60));
    assert_eq!(reject(&mut ledger, &tx, &w, 2), Error::MissingInput);
    let burn = Transaction {
        inputs: spent.outputs,
        outputs: vec![],
        delta: -60,
        ..tx
    };
    let w = witnesses(&ledger, &burn);
    let mut no_issuer = w.clone();
    no_issuer.modules[0] = vec![Val::Bytes(vec![])];
    assert!(matches!(
        reject(&mut ledger, &burn, &no_issuer, 2),
        Error::ModuleRejected(0)
    ));
    ledger.apply(&burn, &w, 2, &TestVerifier, GAS).unwrap();
    assert_eq!(ledger.supply(&burn.asset), Some(0));
    assert!(ledger.snapshot().outputs.is_empty());
}

#[test]
fn emission_nonce_and_cumulative_cap_are_state_owned() {
    let (mut ledger, asset) = registered(&basic());
    let mut tx = mint(asset, 40);
    let w = witnesses(&ledger, &tx);
    ledger.apply(&tx, &w, 1, &TestVerifier, GAS).unwrap();
    assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::InvalidMintNonce);
    tx.mint_nonce = 1;
    tx.outputs[0].amount = 61;
    tx.delta = 61;
    let w = witnesses(&ledger, &tx);
    assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::SupplyOutOfRange);
    tx.outputs[0].amount = 60;
    tx.delta = 60;
    ledger
        .apply(&tx, &witnesses(&ledger, &tx), 1, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(ledger.supply(&tx.asset), Some(100));
    assert_eq!(ledger.next_mint_nonce(&tx.asset), Some(2));
}

#[test]
fn signatures_bind_outputs_expiry_nonce_and_network() {
    let (mut ledger, asset) = registered(&basic());
    let tx = mint(asset, 10);
    let w = witnesses(&ledger, &tx);
    let mut changed = tx.clone();
    changed.outputs[0].owner = key(11);
    assert!(matches!(
        reject(&mut ledger, &changed, &w, 1),
        Error::ModuleRejected(0)
    ));
    changed = tx.clone();
    changed.valid_until -= 1;
    assert!(matches!(
        reject(&mut ledger, &changed, &w, 1),
        Error::ModuleRejected(0)
    ));
    let mut wrong_domain = w.clone();
    wrong_domain.modules[0] = vec![Val::Bytes(sign(
        &tx.signing_hash(&[43; 32]).unwrap(),
        &key(1),
    ))];
    assert!(matches!(
        reject(&mut ledger, &tx, &wrong_domain, 1),
        Error::ModuleRejected(0)
    ));
    assert_eq!(reject(&mut ledger, &tx, &w, 101), Error::Expired);
}

#[test]
fn callers_cannot_omit_or_pad_registered_policies() {
    let (mut ledger, asset) = registered(&basic());
    let tx = mint(asset, 10);
    let original = witnesses(&ledger, &tx);
    for modules in [
        vec![],
        vec![vec![]],
        vec![vec![Val::Int(1)]],
        vec![vec![Val::Bytes(vec![]), Val::Bytes(vec![])]],
        vec![vec![], vec![]],
    ] {
        let mut w = original.clone();
        w.modules = modules;
        assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::InvalidWitness);
    }
}

#[test]
fn all_six_modules_use_authenticated_context_and_subject_proofs() {
    let mut r = full();
    let asset = r.asset_id(&DOMAIN).unwrap();
    let tree = membership(&asset, &[key(8), key(10)], 100);
    r.initial_kyc_root = Some(tree.root());
    // Asset is computable before constructing its subject-bound initial KYC root.
    assert_eq!(asset, r.asset_id(&DOMAIN).unwrap());
    let (mut ledger, asset) = registered(&r);
    let mint = mint(asset, 60);
    let mut w = witnesses(&ledger, &mint);
    add_proofs(&mut w, &tree, &asset, &[key(8)]);
    for (module, slot) in [(0, 0), (4, 0), (5, 0), (5, 1)] {
        let mut bad = w.clone();
        bad.modules[module][slot] = Val::Bytes(vec![]);
        // Governance is 2-of-3: remove two distinct signatures to miss quorum.
        if module == 4 {
            bad.modules[module][1] = Val::Bytes(vec![]);
        }
        assert!(
            matches!(reject(&mut ledger, &mint, &bad, 1), Error::ModuleRejected(i) | Error::ModuleVm(i, _) if i == module)
        );
    }
    // Vesting gates spends, allowing a pre-unlock initial distribution.
    let receipt = ledger.apply(&mint, &w, 1, &TestVerifier, GAS).unwrap();
    let transfer = Transaction {
        inputs: receipt.outputs,
        outputs: vec![Output {
            owner: key(10),
            amount: 60,
        }],
        delta: 0,
        ..mint
    };
    let mut w = witnesses(&ledger, &transfer);
    add_proofs(&mut w, &tree, &asset, &[key(8), key(10)]);
    assert!(matches!(
        reject(&mut ledger, &transfer, &w, 9),
        Error::ModuleVm(3, _)
    ));
    let mut bad = w.clone();
    bad.modules[3] = vec![Val::Bytes(vec![])];
    assert!(matches!(
        reject(&mut ledger, &transfer, &bad, 10),
        Error::ModuleRejected(3)
    ));
    bad = w.clone();
    bad.eligibility.pop();
    assert_eq!(
        reject(&mut ledger, &transfer, &bad, 10),
        Error::InvalidEligibility
    );
    bad = w.clone();
    bad.eligibility.reverse();
    assert_eq!(
        reject(&mut ledger, &transfer, &bad, 10),
        Error::InvalidEligibility
    );
    ledger.apply(&transfer, &w, 10, &TestVerifier, GAS).unwrap();
}

#[test]
fn kyc_proofs_bind_asset_recipient_expiry_and_current_root() {
    let mut r = full();
    let asset = r.asset_id(&DOMAIN).unwrap();
    let tree = membership(&asset, &[key(8)], 9);
    r.initial_kyc_root = Some(tree.root());
    let (mut ledger, _) = registered(&r);
    let tx = mint(asset, 10);
    let mut w = witnesses(&ledger, &tx);
    add_proofs(&mut w, &tree, &asset, &[key(8)]);
    assert_eq!(reject(&mut ledger, &tx, &w, 10), Error::InvalidEligibility);
    let mut other = tx.clone();
    other.outputs[0].owner = key(10);
    let mut other_w = witnesses(&ledger, &other);
    other_w.eligibility = w.eligibility.clone();
    assert_eq!(
        reject(&mut ledger, &other, &other_w, 1),
        Error::InvalidEligibility
    );
    let another_tree = membership(&[99; 32], &[key(8)], 9);
    other_w = witnesses(&ledger, &tx);
    add_proofs(&mut other_w, &another_tree, &[99; 32], &[key(8)]);
    assert_eq!(
        reject(&mut ledger, &tx, &other_w, 1),
        Error::InvalidEligibility
    );
    let update = PolicyUpdate {
        asset,
        revision: 0,
        valid_until: 100,
        action: PolicyAction::SetKycRoot(state::empty_root()),
    };
    let uw = module_witnesses(&r, &update.signing_hash(&DOMAIN), 0, false, true);
    ledger
        .update_policy(&update, &uw, 1, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::StalePolicy);
    other = tx;
    other.policy_revision = 1;
    other_w = witnesses(&ledger, &other);
    other_w.eligibility = w.eligibility;
    assert_eq!(
        reject(&mut ledger, &other, &other_w, 1),
        Error::InvalidEligibility
    );
}

#[test]
fn policy_updates_require_authority_governance_custody_and_fresh_revision() {
    let r = full();
    let (mut ledger, asset) = registered(&r);
    let update = PolicyUpdate {
        asset,
        revision: 0,
        valid_until: 100,
        action: PolicyAction::SetFrozen(true),
    };
    let w = module_witnesses(&r, &update.signing_hash(&DOMAIN), 0, false, true);
    for module in [1, 4, 5] {
        let mut bad = w.clone();
        bad.modules[module].fill(Val::Bytes(vec![]));
        let before = ledger.snapshot();
        assert!(ledger
            .update_policy(&update, &bad, 1, &TestVerifier, GAS)
            .is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    assert_eq!(
        ledger.update_policy(&update, &w, 101, &TestVerifier, GAS),
        Err(Error::Expired)
    );
    ledger
        .update_policy(&update, &w, 1, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(
        ledger.update_policy(&update, &w, 1, &TestVerifier, GAS),
        Err(Error::StalePolicy)
    );
    let mut changed = update;
    changed.revision = 1;
    changed.action = PolicyAction::SetFrozen(false);
    assert!(ledger
        .update_policy(&changed, &w, 1, &TestVerifier, GAS)
        .is_err());
    let w = module_witnesses(&r, &changed.signing_hash(&DOMAIN), 0, false, true);
    ledger
        .update_policy(&changed, &w, 1, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(ledger.policy_revision(&asset), Some(2));
}

#[test]
fn freeze_is_registry_state_and_authority_is_additional_to_owner() {
    let mut r = basic();
    r.charter
        .modules
        .push(ModuleKind::TransferPolicy(TransferPolicyConfig {
            authority_pubkey: key(2),
        }));
    let (mut ledger, asset) = registered(&r);
    let tx = mint(asset, 10);
    let receipt = ledger
        .apply(&tx, &witnesses(&ledger, &tx), 1, &TestVerifier, GAS)
        .unwrap();
    let update = PolicyUpdate {
        asset,
        revision: 0,
        valid_until: 100,
        action: PolicyAction::SetFrozen(true),
    };
    let w = module_witnesses(&r, &update.signing_hash(&DOMAIN), 0, false, true);
    ledger
        .update_policy(&update, &w, 1, &TestVerifier, GAS)
        .unwrap();
    let tx = Transaction {
        inputs: receipt.outputs,
        delta: 0,
        policy_revision: 1,
        ..tx
    };
    let mut w = witnesses(&ledger, &tx);
    assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::ModuleRejected(1));
    w.modules[1] = vec![Val::Bytes(sign(
        &tx.signing_hash(&DOMAIN).unwrap(),
        &key(2),
    ))];
    let mut missing_owner = w.clone();
    missing_owner.owners[0].clear();
    assert_eq!(
        reject(&mut ledger, &tx, &missing_owner, 1),
        Error::InvalidSignature
    );
    ledger.apply(&tx, &w, 1, &TestVerifier, GAS).unwrap();
}

#[test]
fn registration_is_authorized_bounded_and_immutable() {
    let r = basic();
    let mut ledger = Ledger::new(DOMAIN);
    let sig = sign(&r.signing_hash(&DOMAIN).unwrap(), &key(1));
    assert_eq!(
        ledger.register(r.clone(), b"forged", &TestVerifier, GAS),
        Err(Error::InvalidSignature)
    );
    assert!(ledger.snapshot().tokens.is_empty());
    ledger
        .register(r.clone(), &sig, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(
        ledger.register(r.clone(), &sig, &TestVerifier, GAS),
        Err(Error::AlreadyRegistered)
    );
    let mut altered = r.clone();
    altered.nonce[0] ^= 1;
    assert_eq!(
        ledger.register(altered, &sig, &TestVerifier, GAS),
        Err(Error::InvalidSignature)
    );
    let mut altered = r.clone();
    altered.charter.modules.push(r.charter.modules[0].clone());
    assert!(matches!(
        ledger.register(altered, &sig, &TestVerifier, GAS),
        Err(Error::InvalidCharter(_))
    ));
    let mut altered = r.clone();
    if let ModuleKind::Supply(c) = &mut altered.charter.modules[0] {
        c.issuer_pubkey = vec![1];
    }
    assert_eq!(
        ledger.register(altered, &sig, &TestVerifier, GAS),
        Err(Error::InvalidKey)
    );
    let mut altered = r;
    altered.charter.token_name = vec![b'x'; 257];
    assert!(matches!(
        ledger.register(altered, &sig, &TestVerifier, GAS),
        Err(Error::ResourceLimit(_))
    ));
}

#[test]
fn registry_identity_is_distinct_from_legacy_compiler_and_raw_minting_ids() {
    let r = basic();
    let (mut ledger, asset) = registered(&r);
    let compiled = compile_charter(&r.charter);
    for other in [
        compiled.policy_id().unwrap(),
        compiled.validators[0].validator_hash,
    ] {
        assert_ne!(asset, other);
        let tx = mint(other, 10);
        assert_eq!(
            reject(&mut ledger, &tx, &Witnesses::default(), 1),
            Error::UnknownAsset
        );
    }
    let mut other = r.clone();
    other.nonce[0] ^= 1;
    assert_ne!(asset, other.asset_id(&DOMAIN).unwrap());
    other = r;
    other.charter.token_name.push(b'2');
    assert_ne!(asset, other.asset_id(&DOMAIN).unwrap());
    assert_ne!(asset, other.asset_id(&[43; 32]).unwrap());
}

#[test]
fn initial_root_is_signed_and_committed_without_circular_asset_identity() {
    let r = full();
    let mut changed = r.clone();
    changed.initial_kyc_root = Some([1; 32]);
    assert_eq!(r.asset_id(&DOMAIN), changed.asset_id(&DOMAIN));
    assert_ne!(r.signing_hash(&DOMAIN), changed.signing_hash(&DOMAIN));
    let mut ledger = Ledger::new(DOMAIN);
    let sig = sign(&r.signing_hash(&DOMAIN).unwrap(), &key(1));
    assert_eq!(
        ledger.register(changed.clone(), &sig, &TestVerifier, GAS),
        Err(Error::InvalidSignature)
    );
    let (first, _) = registered(&r);
    let (second, _) = registered(&changed);
    assert_ne!(first.state_root(), second.state_root());
}

#[test]
fn snapshot_requires_trusted_root_and_conserved_canonical_state() {
    let (ledger, _, _) = funded();
    let root = ledger.state_root();
    let snapshot = ledger.snapshot();
    let restored = Ledger::restore(snapshot.clone(), root, &TestVerifier).unwrap();
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.state_root(), root);
    assert!(matches!(
        Ledger::restore(snapshot.clone(), [0; 32], &TestVerifier),
        Err(Error::SnapshotRootMismatch)
    ));
    let mut bad = snapshot.clone();
    bad.outputs[0].1.output.amount += 1;
    assert!(matches!(
        Ledger::restore(bad, root, &TestVerifier),
        Err(Error::InvalidSnapshot)
    ));
    let mut bad = snapshot.clone();
    bad.tokens[0].1.mint_nonce += 1;
    assert!(matches!(
        Ledger::restore(bad, root, &TestVerifier),
        Err(Error::SnapshotRootMismatch)
    ));
    let mut bad = snapshot.clone();
    bad.outputs.push(bad.outputs[0].clone());
    assert!(matches!(
        Ledger::restore(bad, root, &TestVerifier),
        Err(Error::InvalidSnapshot)
    ));
    let mut bad = snapshot;
    bad.version += 1;
    assert!(matches!(
        Ledger::restore(bad, root, &TestVerifier),
        Err(Error::InvalidSnapshot)
    ));
}

#[test]
fn gas_exhaustion_and_malformed_shapes_never_commit() {
    let (mut ledger, asset) = registered(&basic());
    let tx = mint(asset, 10);
    let w = witnesses(&ledger, &tx);
    let before = ledger.snapshot();
    let mut probe = ledger.clone();
    let used = probe
        .apply(&tx, &w, 1, &TestVerifier, GAS)
        .unwrap()
        .gas_used;
    for gas in [0, 100, used - 1] {
        assert_eq!(
            ledger.apply(&tx, &w, 1, &TestVerifier, gas),
            Err(Error::OutOfGas)
        );
        assert_eq!(ledger.snapshot(), before);
    }
    ledger.apply(&tx, &w, 1, &TestVerifier, used).unwrap();
    let mut bad = tx.clone();
    bad.outputs[0].amount = 11;
    assert_eq!(reject(&mut ledger, &bad, &w, 1), Error::ValueNotConserved);
    bad = tx.clone();
    bad.outputs[0].amount = 0;
    assert_eq!(reject(&mut ledger, &bad, &w, 1), Error::InvalidAmount);
    bad = tx.clone();
    bad.outputs = vec![tx.outputs[0].clone(); MAX_OUTPUTS + 1];
    assert!(matches!(
        reject(&mut ledger, &bad, &w, 1),
        Error::ResourceLimit(_)
    ));
    bad = tx;
    bad.delta = i128::MAX;
    assert_eq!(reject(&mut ledger, &bad, &w, 1), Error::SupplyOutOfRange);
}

#[test]
fn duplicate_inputs_wrong_asset_and_unregistered_outpoints_are_rejected() {
    let (mut ledger, mint, receipt) = funded();
    let mut tx = Transaction {
        inputs: receipt.outputs,
        delta: 0,
        ..mint
    };
    let w = witnesses(&ledger, &tx);
    tx.inputs.push(tx.inputs[0]);
    assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::NonCanonicalInputs);
    tx.inputs.pop();
    let mut second = basic();
    second.nonce[0] ^= 1;
    let sig = sign(&second.signing_hash(&DOMAIN).unwrap(), &key(1));
    tx.asset = ledger.register(second, &sig, &TestVerifier, GAS).unwrap();
    let w = witnesses(&ledger, &tx);
    assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::WrongAsset);
    tx.inputs[0].index = 99;
    assert_eq!(reject(&mut ledger, &tx, &w, 1), Error::MissingInput);
}

#[test]
fn oversized_witness_is_denied_before_crypto() {
    let (mut ledger, asset) = registered(&basic());
    let tx = mint(asset, 10);
    let mut w = witnesses(&ledger, &tx);
    w.modules[0][0] = Val::Bytes(vec![0; MAX_SIGNATURE_BYTES + 1]);
    assert!(matches!(
        reject(&mut ledger, &tx, &w, 1),
        Error::ResourceLimit(_)
    ));
}

#[test]
fn kirpich_preflight_bounds_names_modules_signer_lists_and_keys() {
    use bloch_euvm::kirpich::{kirpich_audit, limits};
    let r = basic();
    let mut cases = vec![];
    let mut c = r.charter.clone();
    c.token_name.resize(limits::MAX_TOKEN_NAME_BYTES + 1, 0);
    cases.push((c, "KRP-047"));
    let mut c = r.charter.clone();
    c.modules = vec![ModuleKind::ComplianceKycGate(KycConfig {}); limits::MAX_CHARTER_MODULES + 1];
    cases.push((c, "KRP-047"));
    let mut c = r.charter.clone();
    c.modules.push(ModuleKind::Governance(GovernanceConfig {
        threshold: 1,
        signers: vec![vec![]; 1025],
    }));
    cases.push((c, "KRP-047"));
    let mut c = r.charter;
    if let ModuleKind::Supply(s) = &mut c.modules[0] {
        s.issuer_pubkey.resize(limits::MAX_KEY_BYTES + 1, 0);
    }
    cases.push((c, "KRP-046"));
    for (charter, code) in cases {
        let report = kirpich_audit(&charter);
        assert!(report.denied);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].code, code);
    }
}

#[test]
fn successful_registration_retains_kirpich_advisories() {
    let mut r = basic();
    r.charter
        .modules
        .push(ModuleKind::TransferPolicy(TransferPolicyConfig {
            authority_pubkey: key(1),
        }));
    let (ledger, asset) = registered(&r);
    let audit = ledger.audit(&asset).unwrap();
    assert!(!audit.denied);
    assert!(audit.findings.iter().any(|f| f.code == "KRP-004"));
    let (compiled, report) = compile_charter_with_report(&r.charter).unwrap();
    assert_eq!(&report, audit);
    assert_eq!(compiled.charter_id, compile_charter(&r.charter).charter_id);
}

#[test]
fn signing_vectors_pin_the_independent_canonical_encoding() {
    // Computed separately with Python struct.pack / hashlib, from the format in
    // docs/ustav-kernel.md. Do not regenerate these from Rust to accept a drift.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    let r = basic();
    let asset = r.asset_id(&DOMAIN).unwrap();
    let tx = mint(asset, 60);
    let update = PolicyUpdate {
        asset,
        revision: 0,
        valid_until: 100,
        action: PolicyAction::SetFrozen(true),
    };
    assert_eq!(
        hex(&asset),
        "a224ab5ed1ed42cd4501c30a49ff049e30225b13b83a5f1b6bfacf7322d1e299"
    );
    assert_eq!(
        hex(&r.signing_hash(&DOMAIN).unwrap()),
        "2a2e8346c79916ba0b092d318ba0fbb2b3f3ac22c3821f89dcb35d1f88ca10ab"
    );
    assert_eq!(
        hex(&tx.signing_hash(&DOMAIN).unwrap()),
        "b144919303a8486658de648f6149bfa1e5ebf136d865fe5d02d401d4946088e1"
    );
    assert_eq!(
        hex(&update.signing_hash(&DOMAIN)),
        "f05031709c50427edf39af2bc35cd788dfbc1128ef084aa3703396b456b154c0"
    );
}

#[test]
fn unreachable_vesting_and_kyc_without_authority_cannot_register() {
    let mut r = basic();
    r.charter.modules.push(ModuleKind::Vesting(VestingConfig {
        unlock_height: i128::from(u64::MAX) + 1,
        beneficiary_pubkey: key(3),
    }));
    let mut ledger = Ledger::new(DOMAIN);
    let signature = sign(&r.signing_hash(&DOMAIN).unwrap(), &key(1));
    assert!(matches!(
        ledger.register(r, &signature, &TestVerifier, GAS),
        Err(Error::InvalidCharter(_))
    ));
    let mut r = basic();
    r.charter
        .modules
        .push(ModuleKind::ComplianceKycGate(KycConfig {}));
    r.initial_kyc_root = Some(state::empty_root());
    let signature = sign(&r.signing_hash(&DOMAIN).unwrap(), &key(1));
    assert!(matches!(
        ledger.register(r, &signature, &TestVerifier, GAS),
        Err(Error::InvalidCharter(_))
    ));
    assert!(ledger.snapshot().tokens.is_empty());
}
