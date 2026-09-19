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
fn real_hybrid_wire_import_transfer_cross_origin_burn_and_snapshot_roundtrip() {
    simulation::complete(fixture());
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
