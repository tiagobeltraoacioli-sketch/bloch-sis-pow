//! Real ML-DSA-65 AND Falcon-1024 authorization at every native Chameleon edge.
//! Burn records here are trusted test inputs. The executable roundtrip additionally
//! obtains its burn root from the actual Solidity adapter running in a local EVM.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::Val;
use bloch_ustav::chameleon::{wire, *};
use bloch_ustav::{BlochVerifier, Output, Registration, Transaction, Witnesses};

#[test]
fn hybrid_authorization_is_required_for_enable_export_and_return() {
    let domain = [81; 32];
    let gas = 10_000_000;
    let (issuer, secret) = crypto::generate_keypair_from_seed(&[82; 32]).unwrap();
    let (recipient, recipient_secret) = crypto::generate_keypair_from_seed(&[83; 32]).unwrap();
    let sign = |message: &[u8]| crypto::sign(&secret, message).unwrap();
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"CHAMELEON-PQ-TEST".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: issuer.clone(),
            })],
        },
        nonce: [1; 32],
        initial_kyc_root: None,
    };
    let mut ledger = ChameleonLedger::new(domain);
    let asset = ledger
        .register(
            registration.clone(),
            &sign(&registration.signing_hash(&domain).unwrap()),
            &BlochVerifier,
            gas,
        )
        .unwrap();
    let route = EvmRoute {
        origin_domain: domain,
        asset,
        chain_id: 1,
        adapter: [3; 20],
        decimals: 8,
        cap: 1000,
        adapter_code_hash: [4; 32],
    };
    let enable_signature = sign(&route.enable_hash());
    let offsets = [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ];
    let before = ledger.snapshot();
    for offset in offsets {
        let mut bad = enable_signature.clone();
        bad[offset] ^= 1;
        assert!(ledger
            .enable(route.clone(), &bad, &BlochVerifier, gas)
            .is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    ledger
        .enable(route.clone(), &enable_signature, &BlochVerifier, gas)
        .unwrap();
    let mut tx = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: issuer,
            amount: 100,
        }],
        delta: 100,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let w = Witnesses {
        modules: vec![vec![Val::Bytes(sign(&tx.signing_hash(&domain).unwrap()))]],
        ..Witnesses::default()
    };
    tx.inputs = ledger
        .apply(&tx, &w, 1, &BlochVerifier, gas)
        .unwrap()
        .outputs;
    tx.delta = 0;
    let request = ExportRequest {
        route: route.id(),
        expected_nonce: 0,
        recipient: [5; 20],
        lock_output: 0,
        transaction: tx,
    };
    let w = Witnesses {
        owners: vec![sign(&request.signing_hash(&domain).unwrap())],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    let before = ledger.snapshot();
    for offset in offsets {
        let mut bad = w.clone();
        bad.owners[0][offset] ^= 1;
        assert!(ledger
            .export(&request, &bad, 2, &BlochVerifier, gas)
            .is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    let mut ordinary = w.clone();
    ordinary.owners[0] = sign(&request.transaction.signing_hash(&domain).unwrap());
    assert!(ledger
        .export(&request, &ordinary, 2, &BlochVerifier, gas)
        .is_err());
    ledger.export(&request, &w, 2, &BlochVerifier, gas).unwrap();
    let burn = Burn {
        route: route.id(),
        nonce: 0,
        sender: [6; 20],
        amount: 25,
        pq_recipient_hash: wire::sha256(&recipient),
    };
    let (root, proof) = wire::root_and_proof(&[burn.id()], Some(0)).unwrap();
    let proof = proof.unwrap();
    let checkpoint = TrustedBurnCheckpoint {
        route: route.id(),
        adapter_code_hash: route.adapter_code_hash,
        block_hash: [7; 32],
        root,
        leaf_count: 1,
    };
    let claim = ReturnClaim {
        burn,
        pq_recipient: recipient,
        escrow_inputs: ledger.escrow_inputs(&route.id()),
        valid_until: 100,
    };
    let message = claim.signing_hash(&domain).unwrap();
    let signature = crypto::sign(&recipient_secret, &message).unwrap();
    let before = ledger.snapshot();
    // Neither one valid PQ leg nor a classical-looking key/signature is accepted.
    for offset in offsets {
        let mut bad = signature.clone();
        bad[offset] ^= 1;
        assert!(ledger
            .claim(&claim, &proof, &checkpoint, &bad, 3, &BlochVerifier, gas)
            .is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    assert!(ledger
        .claim(
            &claim,
            &proof,
            &checkpoint,
            &sign(&message),
            3,
            &BlochVerifier,
            gas
        )
        .is_err());
    let mut classical = claim.clone();
    classical.pq_recipient = vec![2; 33];
    assert!(ledger
        .claim(
            &classical,
            &proof,
            &checkpoint,
            &[0; 65],
            3,
            &BlochVerifier,
            gas
        )
        .is_err());
    assert_eq!(ledger.snapshot(), before);
    let released = ledger
        .claim(
            &claim,
            &proof,
            &checkpoint,
            &signature,
            3,
            &BlochVerifier,
            gas,
        )
        .unwrap();
    assert_eq!(ledger.native().output(&released).unwrap().output.amount, 25);
    assert_eq!(ledger.native().supply(&asset), Some(100));
    assert_eq!(ledger.route(&route.id()).unwrap().locked, 75);
    let mut restored =
        ChameleonLedger::restore(ledger.snapshot(), ledger.state_root(), &BlochVerifier).unwrap();
    assert_eq!(
        restored.claim(
            &claim,
            &proof,
            &checkpoint,
            &signature,
            4,
            &BlochVerifier,
            gas
        ),
        Err(Error::AlreadyClaimed)
    );
}
