//! State-machine adversarial tests. TestVerifier is deliberately NOT cryptography;
//! real hybrid signatures are exercised by bloch-ustav's Chameleon tests.
use bloch_euvm::kirpich::chameleon::audit_erc20;
use bloch_euvm::modules::*;
use bloch_euvm::ustav::chameleon::{wire, *};
use bloch_euvm::ustav::{
    Error as NativeError, OutPoint, Output, Registration, Transaction, Verifier, Witnesses,
};
use bloch_euvm::Val;

const DOMAIN: [u8; 32] = [42; 32];
const GAS: u64 = 10_000_000;
struct TestVerifier;
fn key(n: u8) -> Vec<u8> {
    vec![n; 32]
}
fn sign(message: &[u8], owner: &[u8]) -> Vec<u8> {
    wire::sha256(&[owner, message].concat()).to_vec()
}
impl Verifier for TestVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        key.len() == 32 && key[0] != 0
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], sig: &[u8]) -> bool {
        self.valid_pq_key(key) && sign(message, key) == sig
    }
}
fn registration() -> Registration {
    Registration {
        charter: TokenCharter {
            token_name: b"CHAMELEON-TEST".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: key(1),
            })],
        },
        nonce: [7; 32],
        initial_kyc_root: None,
    }
}
fn registered() -> (ChameleonLedger, EvmRoute) {
    let mut ledger = ChameleonLedger::new(DOMAIN);
    let reg = registration();
    let asset = ledger
        .register(
            reg.clone(),
            &sign(&reg.signing_hash(&DOMAIN).unwrap(), &key(1)),
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let route = EvmRoute {
        origin_domain: DOMAIN,
        asset,
        chain_id: 1,
        adapter: [3; 20],
        decimals: 8,
        cap: 1000,
        adapter_code_hash: [4; 32],
    };
    (ledger, route)
}
fn mint(ledger: &mut ChameleonLedger, asset: [u8; 32]) -> Transaction {
    let mut tx = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: key(1),
            amount: 100,
        }],
        delta: 100,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let w = Witnesses {
        modules: vec![vec![Val::Bytes(sign(
            &tx.signing_hash(&DOMAIN).unwrap(),
            &key(1),
        ))]],
        ..Witnesses::default()
    };
    tx.inputs = ledger
        .apply(&tx, &w, 1, &TestVerifier, GAS)
        .unwrap()
        .outputs;
    tx.delta = 0;
    tx.outputs = vec![
        Output {
            owner: key(1),
            amount: 60,
        },
        Output {
            owner: key(1),
            amount: 40,
        },
    ];
    tx
}
fn ready() -> (ChameleonLedger, EvmRoute, ExportRequest) {
    let (mut ledger, route) = registered();
    ledger
        .enable(
            route.clone(),
            &sign(&route.enable_hash(), &key(1)),
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let transaction = mint(&mut ledger, route.asset);
    let req = ExportRequest {
        route: route.id(),
        expected_nonce: 0,
        recipient: [5; 20],
        lock_output: 0,
        transaction,
    };
    (ledger, route, req)
}
fn export_witness(req: &ExportRequest) -> Witnesses {
    Witnesses {
        owners: vec![sign(&req.signing_hash(&DOMAIN).unwrap(), &key(1))],
        modules: vec![vec![]],
        ..Witnesses::default()
    }
}
fn exported() -> (ChameleonLedger, EvmRoute, Export) {
    let (mut ledger, route, req) = ready();
    let (record, _) = ledger
        .export(&req, &export_witness(&req), 2, &TestVerifier, GAS)
        .unwrap();
    (ledger, route, record)
}
fn claim_for(
    ledger: &ChameleonLedger,
    route: &EvmRoute,
    amount: u64,
) -> (ReturnClaim, InclusionProof, TrustedBurnCheckpoint) {
    let burn = Burn {
        route: route.id(),
        nonce: 0,
        sender: [8; 20],
        amount,
        pq_recipient_hash: wire::sha256(&key(9)),
    };
    let (root, proof) = wire::root_and_proof(&[burn.id()], Some(0)).unwrap();
    (
        ReturnClaim {
            burn,
            pq_recipient: key(9),
            escrow_inputs: ledger.escrow_inputs(&route.id()),
            valid_until: 100,
        },
        proof.unwrap(),
        TrustedBurnCheckpoint {
            route: route.id(),
            adapter_code_hash: route.adapter_code_hash,
            block_hash: [10; 32],
            root,
            leaf_count: 1,
        },
    )
}
fn claim_signature(claim: &ReturnClaim) -> Vec<u8> {
    sign(&claim.signing_hash(&DOMAIN).unwrap(), &key(9))
}

#[test]
fn kirpich_refuses_each_unpreserved_policy_and_keeps_native_rules_separate() {
    let mut reg = registration();
    assert!(!audit_erc20(&reg.charter, false).denied);
    assert!(audit_erc20(&reg.charter, true).denied);
    let extras = [
        ModuleKind::TransferPolicy(TransferPolicyConfig {
            authority_pubkey: key(2),
        }),
        ModuleKind::ComplianceKycGate(KycConfig {}),
        ModuleKind::Vesting(VestingConfig {
            unlock_height: 10,
            beneficiary_pubkey: key(3),
        }),
        ModuleKind::Governance(GovernanceConfig {
            threshold: 1,
            signers: vec![key(4)],
        }),
        ModuleKind::Custody(CustodyConfig {
            btc_pubkey: key(5),
            pq_pubkey: key(6),
        }),
    ];
    for extra in extras {
        reg.charter.modules.push(extra);
        let a = audit_erc20(&reg.charter, false);
        assert!(a.denied && a.findings.iter().any(|f| f.code == "KRP-080"));
        assert_eq!(a, audit_erc20(&reg.charter, false));
        assert_eq!(inspect_erc20_policy(&reg), Err(Error::UnsupportedPolicy));
        reg.charter.modules.pop();
    }
    reg.charter.modules.clear();
    assert!(audit_erc20(&reg.charter, false).denied);
    reg = registration();
    reg.charter.modules.push(reg.charter.modules[0].clone());
    assert!(audit_erc20(&reg.charter, false).denied);
    assert_eq!(bloch_euvm::kirpich::RULESET_VERSION, 2);
}

#[test]
fn enabling_requires_issuer_authorization_of_exact_deployment_before_issuance() {
    let (mut ledger, route) = registered();
    let before = ledger.snapshot();
    let sig = sign(&route.enable_hash(), &key(1));
    assert_eq!(
        ledger.enable(
            route.clone(),
            &sign(&route.enable_hash(), &key(2)),
            &TestVerifier,
            GAS
        ),
        Err(Error::Native(NativeError::InvalidSignature))
    );
    assert_eq!(
        ledger.enable(route.clone(), &sig, &TestVerifier, 1000),
        Err(Error::Native(NativeError::OutOfGas))
    );
    let mut changed = route.clone();
    changed.adapter_code_hash[0] ^= 1;
    assert_eq!(changed.id(), route.id());
    assert_ne!(changed.enable_hash(), route.enable_hash());
    assert_eq!(
        ledger.enable(changed, &sig, &TestVerifier, GAS),
        Err(Error::Native(NativeError::InvalidSignature))
    );
    for case in 0..7 {
        let mut bad = route.clone();
        match case {
            0 => bad.origin_domain = [0; 32],
            1 => bad.chain_id = 0,
            2 => bad.adapter = [0; 20],
            3 => bad.decimals = 19,
            4 => bad.cap += 1,
            5 => bad.asset = [0; 32],
            _ => bad.adapter_code_hash = [0; 32],
        }
        assert_eq!(
            ledger.enable(bad, &sig, &TestVerifier, GAS),
            Err(Error::InvalidRoute)
        );
        assert_eq!(ledger.snapshot(), before);
    }
    mint(&mut ledger, route.asset);
    let before = ledger.snapshot();
    assert_eq!(
        ledger.enable(route, &sig, &TestVerifier, GAS),
        Err(Error::EnableBeforeIssuance)
    );
    assert_eq!(ledger.snapshot(), before);
}

#[test]
fn duplicate_route_and_issuer_reconfiguration_are_refused() {
    let (mut ledger, mut route, _) = ready();
    let before = ledger.snapshot();
    route.adapter[0] ^= 1;
    assert_eq!(
        ledger.enable(
            route.clone(),
            &sign(&route.enable_hash(), &key(1)),
            &TestVerifier,
            GAS
        ),
        Err(Error::AlreadyEnabled)
    );
    assert_eq!(ledger.snapshot(), before);
}

#[test]
fn export_signature_binds_destination_nonce_transaction_and_lock_selection() {
    let (mut ledger, route, req) = ready();
    let before = ledger.snapshot();
    let mut ordinary = export_witness(&req);
    ordinary.owners[0] = sign(&req.transaction.signing_hash(&DOMAIN).unwrap(), &key(1));
    assert_eq!(
        ledger.export(&req, &ordinary, 2, &TestVerifier, GAS),
        Err(Error::Native(NativeError::InvalidSignature))
    );
    let signed = export_witness(&req);
    for case in 0..9 {
        let mut bad = req.clone();
        match case {
            0 => bad.recipient[0] ^= 1,
            1 => bad.expected_nonce += 1,
            2 => bad.lock_output = 1,
            3 => bad.transaction.valid_until += 1,
            4 => bad.route[0] ^= 1,
            5 => bad.recipient = route.adapter,
            6 => bad.recipient = [0; 20],
            7 => bad.transaction.delta = 1,
            _ => bad.transaction.mint_nonce = 1,
        }
        assert!(ledger.export(&bad, &signed, 2, &TestVerifier, GAS).is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    assert!(ledger.export(&req, &signed, 2, &TestVerifier, 100).is_err());
    assert_eq!(ledger.snapshot(), before);
    let (record, receipt) = ledger.export(&req, &signed, 2, &TestVerifier, GAS).unwrap();
    assert_eq!(record.amount, 60);
    assert!(ledger.is_locked(&receipt.outputs[0]));
    assert!(!ledger.is_locked(&receipt.outputs[1]));
    assert_eq!(ledger.native().supply(&route.asset), Some(100));
    let (root, count) = ledger.export_root().unwrap();
    assert!(wire::verify_inclusion(
        &record.id(),
        &ledger.export_proof(0).unwrap(),
        &root,
        count
    ));
}

#[test]
fn escrow_cannot_be_spent_burned_or_exported_by_its_former_owner() {
    let (mut ledger, route, _) = exported();
    let mut tx = Transaction {
        asset: route.asset,
        inputs: ledger.escrow_inputs(&route.id()),
        outputs: vec![Output {
            owner: key(1),
            amount: 60,
        }],
        delta: 0,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let before = ledger.snapshot();
    for burn in [false, true] {
        if burn {
            tx.outputs.clear();
            tx.delta = -60;
        }
        let w = Witnesses {
            owners: vec![sign(&tx.signing_hash(&DOMAIN).unwrap(), &key(1))],
            modules: vec![vec![]],
            ..Witnesses::default()
        };
        assert_eq!(
            ledger.apply(&tx, &w, 3, &TestVerifier, GAS),
            Err(Error::LockedInput)
        );
        assert_eq!(ledger.snapshot(), before);
    }
    tx.delta = 0;
    tx.outputs = vec![Output {
        owner: key(1),
        amount: 60,
    }];
    let req = ExportRequest {
        transaction: tx,
        route: route.id(),
        expected_nonce: 1,
        recipient: [5; 20],
        lock_output: 0,
    };
    assert_eq!(
        ledger.export(&req, &export_witness(&req), 3, &TestVerifier, GAS),
        Err(Error::LockedInput)
    );
    assert_eq!(ledger.snapshot(), before);
}

#[test]
fn partial_return_conserves_supply_and_keeps_change_locked() {
    let (mut ledger, route, _) = exported();
    let (claim, proof, cp) = claim_for(&ledger, &route, 25);
    let sig = claim_signature(&claim);
    let released = ledger
        .claim(&claim, &proof, &cp, &sig, 3, &TestVerifier, GAS)
        .unwrap();
    assert!(!ledger.is_locked(&released));
    assert_eq!(
        ledger.native().output(&released).unwrap().output,
        Output {
            owner: key(9),
            amount: 25
        }
    );
    assert_eq!(ledger.native().supply(&route.asset), Some(100));
    let state = ledger.route(&route.id()).unwrap();
    assert_eq!((state.locked, state.returned), (35, 25));
    let change = ledger.escrow_inputs(&route.id());
    assert_eq!(
        ledger.native().output(&change[0]).unwrap().output.amount,
        35
    );
    let before = ledger.snapshot();
    assert_eq!(
        ledger.claim(&claim, &proof, &cp, &sig, 3, &TestVerifier, GAS),
        Err(Error::AlreadyClaimed)
    );
    assert_eq!(ledger.snapshot(), before);
    // The claimant may spend only the released output; PQ ownership of escrow
    // change does not grant permission to bypass the remaining backing lock.
    for (input, amount, locked) in [(change[0], 35, true), (released, 25, false)] {
        let tx = Transaction {
            asset: route.asset,
            inputs: vec![input],
            outputs: vec![Output {
                owner: key(10),
                amount,
            }],
            delta: 0,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let w = Witnesses {
            owners: vec![sign(&tx.signing_hash(&DOMAIN).unwrap(), &key(9))],
            modules: vec![vec![]],
            ..Witnesses::default()
        };
        let result = ledger.apply(&tx, &w, 4, &TestVerifier, GAS);
        if locked {
            assert_eq!(result, Err(Error::LockedInput));
        } else {
            assert!(result.is_ok());
        }
    }
}

#[test]
fn failed_claims_are_atomic_across_proof_authorization_and_accounting_checks() {
    let (ledger, route, _) = exported();
    let (claim, proof, cp) = claim_for(&ledger, &route, 25);
    let sig = claim_signature(&claim);
    let before = ledger.snapshot();
    for case in 0..19 {
        let mut l = ledger.clone();
        let mut c = claim.clone();
        let mut p = proof.clone();
        let mut checkpoint = cp.clone();
        let mut signature = sig.clone();
        let mut gas = GAS;
        let mut height = 3;
        match case {
            0 => p.siblings[0][0] ^= 1,
            1 => p.index = 1,
            2 => checkpoint.root[0] ^= 1,
            3 => checkpoint.leaf_count = 0,
            4 => checkpoint.leaf_count = wire::MAX_LEAVES + 1,
            5 => checkpoint.adapter_code_hash[0] ^= 1,
            6 => checkpoint.route[0] ^= 1,
            7 => checkpoint.block_hash = [0; 32],
            8 => c.pq_recipient = key(8),
            9 => c.burn.amount += 1,
            10 => c.valid_until += 1,
            11 => signature[0] ^= 1,
            12 => height = 101,
            13 => gas = 1000,
            14 => c.escrow_inputs.clear(),
            15 => c.escrow_inputs.push(c.escrow_inputs[0]),
            16 => c.escrow_inputs[0].index = 99,
            17 => c.pq_recipient = vec![0; 4097],
            _ => signature = vec![0; 8193],
        }
        assert!(
            l.claim(&c, &p, &checkpoint, &signature, height, &TestVerifier, gas)
                .is_err(),
            "case {case}"
        );
        assert_eq!(l.snapshot(), before, "case {case}");
    }
    let (too_much, proof, cp) = claim_for(&ledger, &route, 61);
    let mut l = ledger.clone();
    assert_eq!(
        l.claim(
            &too_much,
            &proof,
            &cp,
            &claim_signature(&too_much),
            3,
            &TestVerifier,
            GAS
        ),
        Err(Error::InsufficientBacking)
    );
    assert_eq!(l.snapshot(), before);
}

#[test]
fn multiple_returns_and_reexports_preserve_cumulative_backing() {
    let (mut ledger, route, _) = exported();
    let (first, proof, cp) = claim_for(&ledger, &route, 25);
    ledger
        .claim(
            &first,
            &proof,
            &cp,
            &claim_signature(&first),
            3,
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let mut second = first.clone();
    second.burn.nonce = 1;
    second.burn.amount = 35;
    second.escrow_inputs = ledger.escrow_inputs(&route.id());
    let (root, proof) =
        wire::root_and_proof(&[first.burn.id(), second.burn.id()], Some(1)).unwrap();
    let cp = TrustedBurnCheckpoint {
        root,
        leaf_count: 2,
        ..cp
    };
    let released = ledger
        .claim(
            &second,
            &proof.unwrap(),
            &cp,
            &claim_signature(&second),
            4,
            &TestVerifier,
            GAS,
        )
        .unwrap();
    assert!(ledger.escrow_inputs(&route.id()).is_empty());
    let tx = Transaction {
        asset: route.asset,
        inputs: vec![released],
        outputs: vec![Output {
            owner: key(9),
            amount: 35,
        }],
        delta: 0,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let req = ExportRequest {
        route: route.id(),
        expected_nonce: 1,
        recipient: [5; 20],
        lock_output: 0,
        transaction: tx,
    };
    let w = Witnesses {
        owners: vec![sign(&req.signing_hash(&DOMAIN).unwrap(), &key(9))],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    ledger.export(&req, &w, 5, &TestVerifier, GAS).unwrap();
    assert_eq!(ledger.route(&route.id()).unwrap().locked, 35);
    assert_eq!(ledger.native().supply(&route.asset), Some(100));
    ChameleonLedger::restore(ledger.snapshot(), ledger.state_root(), &TestVerifier).unwrap();
}

#[test]
fn restoration_authenticates_locks_routes_exports_and_return_nullifiers_together() {
    let (mut ledger, route, _) = exported();
    let (claim, proof, cp) = claim_for(&ledger, &route, 25);
    ledger
        .claim(
            &claim,
            &proof,
            &cp,
            &claim_signature(&claim),
            3,
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let root = ledger.state_root();
    let snapshot = ledger.snapshot();
    assert_eq!(
        ChameleonLedger::restore(snapshot.clone(), root, &TestVerifier)
            .unwrap()
            .snapshot(),
        snapshot
    );
    assert!(ChameleonLedger::restore(
        snapshot.clone(),
        ledger.native().state_root(),
        &TestVerifier
    )
    .is_err());
    for case in 0..11 {
        let mut bad = snapshot.clone();
        match case {
            0 => bad.locks.clear(),
            1 => bad.claimed.clear(),
            2 => bad.routes.clear(),
            3 => bad.exports.clear(),
            4 => bad.routes[0].1.returned += 1,
            5 => bad.routes[0].1.config.adapter_code_hash[0] ^= 1,
            6 => bad.exports[0].recipient[0] ^= 1,
            7 => bad.native_root[0] ^= 1,
            8 => bad.claimed.push(bad.claimed[0]),
            9 => bad.version += 1,
            _ => {
                bad.locks[0].0 = OutPoint {
                    transaction: [0; 32],
                    index: 0,
                }
            }
        }
        assert!(
            ChameleonLedger::restore(bad, root, &TestVerifier).is_err(),
            "case {case}"
        );
    }
    let mut restored = ChameleonLedger::restore(snapshot, root, &TestVerifier).unwrap();
    assert_eq!(
        restored.claim(
            &claim,
            &proof,
            &cp,
            &claim_signature(&claim),
            4,
            &TestVerifier,
            GAS
        ),
        Err(Error::AlreadyClaimed)
    );
}

#[test]
fn ordered_typed_merkle_proofs_reject_wrong_counts_and_siblings() {
    for count in [1, 2, 3, 7, 8, 9, 31, 32, 33] {
        let ids: Vec<_> = (0u64..count)
            .map(|i| wire::sha256(&i.to_be_bytes()))
            .collect();
        for index in 0..count as usize {
            let (root, proof) = wire::root_and_proof(&ids, Some(index)).unwrap();
            let mut proof = proof.unwrap();
            assert!(wire::verify_inclusion(&ids[index], &proof, &root, count));
            assert!(!wire::verify_inclusion(
                &ids[index],
                &proof,
                &root,
                index as u64
            ));
            proof.siblings[31][0] ^= 1;
            assert!(!wire::verify_inclusion(&ids[index], &proof, &root, count));
        }
    }
    assert!(wire::root_and_proof(&[], Some(0)).is_none());
    assert!(wire::root_and_proof(&[[0; 32]], Some(1)).is_none());
}

#[test]
fn rust_matches_independent_python_and_solidity_wire_vectors() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/chameleon-v1.json")).unwrap();
    let hex = |bytes: &[u8]| {
        format!(
            "0x{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    let route = EvmRoute {
        origin_domain: [0x11; 32],
        asset: [0x22; 32],
        chain_id: 1,
        adapter: [0x33; 20],
        decimals: 8,
        cap: 1000,
        adapter_code_hash: [0x66; 32],
    };
    let export = Export {
        route: route.id(),
        nonce: 0,
        recipient: [0x55; 20],
        amount: 60,
        native_transaction: [0x44; 32],
    };
    let pq_hash = wire::sha256(b"non-production-pq-vector");
    let burns: Vec<_> = (0..33)
        .map(|nonce| {
            Burn {
                route: route.id(),
                nonce,
                sender: [0x55; 20],
                amount: nonce + 1,
                pq_recipient_hash: pq_hash,
            }
            .id()
        })
        .collect();
    assert_eq!(expected["route_id"], hex(&route.id()));
    assert_eq!(expected["enable_hash"], hex(&route.enable_hash()));
    assert_eq!(expected["export_id"], hex(&export.id()));
    assert_eq!(expected["burn_id"], hex(&burns[0]));
    assert_eq!(expected["pq_recipient_hash"], hex(&pq_hash));
    let (root, proof) = wire::root_and_proof(&[export.id()], Some(0)).unwrap();
    assert_eq!(expected["export_root"], hex(&root));
    for (i, sibling) in proof.unwrap().siblings.iter().enumerate() {
        assert_eq!(expected["export_branch"][i], hex(sibling));
    }
    assert_eq!(
        expected["empty_root"],
        hex(&wire::root_and_proof(&[], None).unwrap().0)
    );
    for n in [1, 2, 3, 7, 8, 9, 17, 32, 33] {
        assert_eq!(
            expected["burn_roots"][n.to_string()],
            hex(&wire::root_and_proof(&burns[..n], None).unwrap().0)
        );
    }
}

#[test]
fn an_authenticated_burn_cannot_consume_another_assets_escrow() {
    let (mut ledger, first_route, _) = exported();
    let mut registration = registration();
    registration.nonce = [8; 32];
    let asset = ledger
        .register(
            registration.clone(),
            &sign(&registration.signing_hash(&DOMAIN).unwrap(), &key(1)),
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let second_route = EvmRoute {
        asset,
        adapter: [7; 20],
        ..first_route.clone()
    };
    ledger
        .enable(
            second_route.clone(),
            &sign(&second_route.enable_hash(), &key(1)),
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let request = ExportRequest {
        route: second_route.id(),
        expected_nonce: 0,
        recipient: [5; 20],
        lock_output: 0,
        transaction: mint(&mut ledger, second_route.asset),
    };
    ledger
        .export(&request, &export_witness(&request), 2, &TestVerifier, GAS)
        .unwrap();
    let (mut claim, proof, checkpoint) = claim_for(&ledger, &first_route, 25);
    claim.escrow_inputs = ledger.escrow_inputs(&second_route.id());
    let before = ledger.snapshot();
    assert_eq!(
        ledger.claim(
            &claim,
            &proof,
            &checkpoint,
            &claim_signature(&claim),
            3,
            &TestVerifier,
            GAS
        ),
        Err(Error::InvalidClaim)
    );
    assert_eq!(ledger.snapshot(), before);
}
