//! Real hybrid PQ authentication around ATTESTED, simulated external deposits.
//! Deterministic seeds are test fixtures only. No source finality proof or funds.
#[path = "../examples/usdt_gateway.rs"]
mod simulation;
use bloch_crypto::crypto;
use bloch_ustav::gateway::{Error, WithdrawalRequest};
use bloch_ustav::{BlochVerifier, Transaction, Witnesses};
use simulation::{Scenario, DOMAIN, GAS};

fn fixture() -> Scenario {
    Scenario::new(
        (170..176)
            .map(|seed| crypto::generate_keypair_from_seed(&[seed; 32]).unwrap())
            .collect(),
    )
}

#[test]
fn liability_reports_separate_assets_and_do_not_mutate_accounting() {
    let mut scenario = fixture();
    scenario.enable_all();
    let first_asset = scenario.configs[0].route.native_asset;
    let mut registration = scenario
        .ledger
        .native()
        .registration(&first_asset)
        .unwrap()
        .clone();
    registration.nonce = [199; 32];
    registration.charter.token_name = b"SECOND-BRIDGED-ASSET-SIMULATION".to_vec();
    let signature = crypto::sign(
        &scenario.issuer.1,
        &registration.signing_hash(&DOMAIN).unwrap(),
    )
    .unwrap();
    let second_asset = scenario
        .ledger
        .register(registration, &signature, &BlochVerifier, GAS)
        .unwrap();
    let mut config = scenario.configs[0].clone();
    config.route.native_asset = second_asset;
    config.route.token = [201; 20];
    config.route.vault = [202; 20];
    let message = config.signing_hash();
    let signature = crypto::sign(&scenario.issuer.1, &message).unwrap();
    let approvals = scenario.approvals(&message);
    scenario
        .ledger
        .enable(config, &signature, &approvals, &BlochVerifier, GAS)
        .unwrap();
    let request = scenario.deposit(0, 0);
    let message = request.signing_hash(&DOMAIN).unwrap();
    let witnesses = scenario.issuer_witness(&message);
    let approvals = scenario.approvals(&message);
    scenario
        .ledger
        .import(&request, &witnesses, &approvals, 1, &BlochVerifier, GAS)
        .unwrap();
    let before = scenario.ledger.snapshot();
    let first = scenario.ledger.liabilities(&first_asset).unwrap();
    let second = scenario.ledger.liabilities(&second_asset).unwrap();
    assert_eq!(
        (first.native_supply, first.imported, first.burned),
        (100_000_000, 100_000_000, 0)
    );
    assert_eq!(
        (second.native_supply, second.imported, second.burned),
        (0, 0, 0)
    );
    assert_eq!((first.routes.len(), second.routes.len()), (2, 1));
    assert!(first
        .routes
        .iter()
        .all(|r| r.route != second.routes[0].route));
    assert_eq!(scenario.ledger.snapshot(), before);
}

#[test]
fn real_hybrid_wire_import_transfer_cross_origin_burn_and_snapshot_roundtrip() {
    let scenario = fixture();
    let asset = scenario.configs[0].route.native_asset;
    let first_route = scenario.configs[0].route.id();
    let second_route = scenario.configs[1].route.id();
    let ledger = simulation::complete(scenario);
    let before = ledger.snapshot();
    let report = ledger.liabilities(&asset).unwrap();
    assert_eq!(report.native_domain, DOMAIN);
    assert_eq!(report.native_asset, asset);
    assert_eq!(report.imported, 200_000_000);
    assert_eq!(report.burned, 100_000_000);
    assert_eq!(report.native_supply, 100_000_000);
    assert_eq!(report.routes.len(), 2);
    let first = report
        .routes
        .iter()
        .find(|r| r.route == first_route)
        .unwrap();
    let second = report
        .routes
        .iter()
        .find(|r| r.route == second_route)
        .unwrap();
    assert_eq!(
        (first.outstanding, first.burned, first.release_count),
        (100_000_000, 0, 0)
    );
    assert_eq!(
        (second.outstanding, second.burned, second.release_count),
        (0, 100_000_000, 1)
    );
    assert_eq!(ledger.liabilities(&[0; 32]), Err(Error::UnknownRoute));
    assert_eq!(ledger.snapshot(), before);
    let restored =
        bloch_ustav::gateway::GatewayLedger::restore(before, ledger.state_root(), &BlochVerifier)
            .unwrap();
    assert_eq!(restored.liabilities(&asset).unwrap(), report);
}

#[test]
fn issuer_and_independent_hybrid_quorum_are_required_with_atomic_rollback() {
    let mut scenario = fixture();
    let config = scenario.configs[0].clone();
    let message = config.signing_hash();
    let signature = crypto::sign(&scenario.issuer.1, &message).unwrap();
    let approvals = scenario.approvals(&message);
    let before = scenario.ledger.snapshot();
    let mut below_quorum = approvals.clone();
    below_quorum[1].clear();
    assert_eq!(
        scenario.ledger.enable(
            config.clone(),
            &signature,
            &below_quorum,
            &BlochVerifier,
            GAS
        ),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        scenario
            .ledger
            .enable(config.clone(), &[], &approvals, &BlochVerifier, GAS),
        Err(Error::Unauthorized)
    );
    assert_eq!(scenario.ledger.snapshot(), before);
    scenario.enable_all();
    let request = scenario.deposit(0, 0);
    let message = request.signing_hash(&DOMAIN).unwrap();
    let approvals = scenario.approvals(&message);
    let witness = scenario.issuer_witness(&message);
    let before = scenario.ledger.snapshot();
    // Independently corrupt the ML-DSA and Falcon components of the committee certificate.
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut tampered = approvals.clone();
        tampered[0][offset] ^= 1;
        assert_eq!(
            scenario
                .ledger
                .import(&request, &witness, &tampered, 1, &BlochVerifier, GAS),
            Err(Error::Unauthorized)
        );
        assert_eq!(scenario.ledger.snapshot(), before);
    }
    // Native mint signatures cannot substitute for route-bound issuer certificates.
    let unscoped = scenario.issuer_witness(&request.transaction.signing_hash(&DOMAIN).unwrap());
    assert!(scenario
        .ledger
        .import(&request, &unscoped, &approvals, 1, &BlochVerifier, GAS)
        .is_err());
    assert!(scenario
        .ledger
        .import(
            &request,
            &Witnesses::default(),
            &approvals,
            1,
            &BlochVerifier,
            GAS
        )
        .is_err());
    assert_eq!(scenario.ledger.snapshot(), before);
    let receipt = scenario
        .ledger
        .import(&request, &witness, &approvals, 1, &BlochVerifier, GAS)
        .unwrap();
    let withdrawal = WithdrawalRequest {
        route: config.route.id(),
        nonce: 0,
        recipient: [190; 20],
        transaction: Transaction {
            inputs: receipt.outputs,
            outputs: vec![],
            delta: -100_000_000,
            ..request.transaction
        },
    };
    let message = withdrawal.signing_hash(&DOMAIN).unwrap();
    let mut witness = scenario.issuer_witness(&message);
    witness.owners = vec![crypto::sign(&scenario.alice.1, &message).unwrap()];
    let approvals = scenario.approvals(&message);
    let before = scenario.ledger.snapshot();
    let mut missing_issuer = witness.clone();
    missing_issuer.modules = vec![vec![]];
    assert!(scenario
        .ledger
        .withdraw(
            &withdrawal,
            &missing_issuer,
            &approvals,
            2,
            &BlochVerifier,
            GAS
        )
        .is_err());
    let mut missing_owner = witness.clone();
    missing_owner.owners.clear();
    assert!(scenario
        .ledger
        .withdraw(
            &withdrawal,
            &missing_owner,
            &approvals,
            2,
            &BlochVerifier,
            GAS
        )
        .is_err());
    let mut below_quorum = approvals.clone();
    below_quorum[1].clear();
    assert_eq!(
        scenario
            .ledger
            .withdraw(&withdrawal, &witness, &below_quorum, 2, &BlochVerifier, GAS),
        Err(Error::Unauthorized)
    );
    assert_eq!(scenario.ledger.snapshot(), before);
    scenario
        .ledger
        .withdraw(&withdrawal, &witness, &approvals, 2, &BlochVerifier, GAS)
        .unwrap();
    assert_eq!(
        scenario
            .ledger
            .native()
            .supply(&withdrawal.transaction.asset),
        Some(0)
    );
}

#[test]
fn encoded_real_hybrid_certificate_tampering_rolls_back() {
    let mut scenario = fixture();
    scenario.enable_all();
    let request = scenario.deposit(0, 0);
    let message = request.signing_hash(&DOMAIN).unwrap();
    let envelope = bloch_ustav::gateway::wire::Envelope {
        domain: DOMAIN,
        operation: bloch_ustav::gateway::wire::Operation::Import(request),
        witnesses: scenario.issuer_witness(&message),
        approvals: scenario.approvals(&message),
    };
    let before = scenario.ledger.snapshot();
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut tampered = envelope.clone();
        tampered.approvals[0][offset] ^= 1;
        let encoded = bloch_ustav::gateway::wire::encode(&tampered).unwrap();
        assert_eq!(
            bloch_ustav::gateway::wire::decode(&encoded).unwrap(),
            tampered
        );
        assert_eq!(
            bloch_ustav::gateway::wire::apply_encoded(
                &mut scenario.ledger,
                &encoded,
                1,
                &BlochVerifier,
                GAS
            ),
            Err(bloch_ustav::gateway::wire::Error::Gateway(
                Error::Unauthorized
            ))
        );
        assert_eq!(scenario.ledger.snapshot(), before);
    }
    let encoded = bloch_ustav::gateway::wire::encode(&envelope).unwrap();
    bloch_ustav::gateway::wire::apply_encoded(
        &mut scenario.ledger,
        &encoded,
        1,
        &BlochVerifier,
        GAS,
    )
    .unwrap();
}
