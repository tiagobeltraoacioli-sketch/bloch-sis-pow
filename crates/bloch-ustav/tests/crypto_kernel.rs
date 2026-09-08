use bloch_crypto::crypto;
use bloch_euvm::modules::*;
use bloch_euvm::{SigVerifier, Val};
use bloch_ustav::*;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use std::sync::OnceLock;

const DOMAIN: [u8; 32] = [31; 32];
const GAS: u64 = 10_000_000;
fn keys() -> &'static (Vec<u8>, Vec<u8>) {
    static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEYS.get_or_init(|| crypto::generate_keypair_from_seed(&[17; 32]).unwrap())
}
fn registration() -> Registration {
    Registration {
        charter: TokenCharter {
            token_name: b"REAL-PQ".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 100,
                issuer_pubkey: keys().0.clone(),
            })],
        },
        nonce: [7; 32],
        initial_kyc_root: None,
    }
}
fn signed(message: &[u8]) -> Vec<u8> {
    crypto::sign(&keys().1, message).unwrap()
}

#[test]
fn real_hybrid_registration_mint_transfer_and_burn() {
    let verifier = BlochVerifier;
    let r = registration();
    let mut ledger = Ledger::new(DOMAIN);
    let asset = ledger
        .register(
            r.clone(),
            &signed(&r.signing_hash(&DOMAIN).unwrap()),
            &verifier,
            GAS,
        )
        .unwrap();
    let tx = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: keys().0.clone(),
            amount: 100,
        }],
        delta: 100,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let w = Witnesses {
        modules: vec![vec![Val::Bytes(signed(&tx.signing_hash(&DOMAIN).unwrap()))]],
        ..Witnesses::default()
    };
    let receipt = ledger.apply(&tx, &w, 1, &verifier, GAS).unwrap();
    let tx = Transaction {
        inputs: receipt.outputs,
        delta: 0,
        ..tx
    };
    let w = Witnesses {
        owners: vec![signed(&tx.signing_hash(&DOMAIN).unwrap())],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    let before = ledger.snapshot();
    let mut forged = w.clone();
    forged.owners[0][crypto::SUITE_HEADER_LEN] ^= 1;
    assert_eq!(
        ledger.apply(&tx, &forged, 1, &verifier, GAS),
        Err(Error::InvalidSignature)
    );
    assert_eq!(ledger.snapshot(), before);
    let receipt = ledger.apply(&tx, &w, 1, &verifier, GAS).unwrap();
    let tx = Transaction {
        inputs: receipt.outputs,
        outputs: vec![],
        delta: -100,
        ..tx
    };
    let sig = signed(&tx.signing_hash(&DOMAIN).unwrap());
    let w = Witnesses {
        owners: vec![sig.clone()],
        modules: vec![vec![Val::Bytes(sig)]],
        ..Witnesses::default()
    };
    ledger.apply(&tx, &w, 1, &verifier, GAS).unwrap();
    assert_eq!(ledger.supply(&asset), Some(0));
    let root = ledger.state_root();
    Ledger::restore(ledger.snapshot(), root, &verifier).unwrap();
}

#[test]
fn malformed_keys_suites_and_each_tampered_signature_leg_fail() {
    let verifier = BlochVerifier;
    let (pk, _) = keys();
    let message = [22; 32];
    let sig = signed(&message);
    assert!(verifier.valid_pq_key(pk));
    assert!(verifier.verify(&message, pk, &sig));
    for len in [0, 1, 4, 1952, pk.len() - 1, pk.len() + 1] {
        assert!(!verifier.valid_pq_key(&vec![0; len]));
    }
    let mut bad_key = pk.clone();
    bad_key[2] = 2;
    assert!(!verifier.valid_pq_key(&bad_key));
    bad_key = pk.clone();
    bad_key[crypto::SUITE_HEADER_LEN + crypto::MLDSA_PUBKEY_LEN] = 9;
    assert!(!verifier.valid_pq_key(&bad_key));
    bad_key = pk.clone();
    let start = crypto::SUITE_HEADER_LEN + crypto::MLDSA_PUBKEY_LEN + 1;
    bad_key[start] = 0xff;
    bad_key[start + 1] = 0xff;
    assert!(!verifier.valid_pq_key(&bad_key));
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = sig.clone();
        bad[offset] ^= 1;
        assert!(!verifier.verify(&message, pk, &bad));
    }
    let mut bad = sig.clone();
    bad[2] = 2;
    assert!(!verifier.verify(&message, pk, &bad));
    assert!(!verifier.verify(&[23; 32], pk, &sig));
    assert!(!verifier.verify(b"short", pk, &sig));
}

#[test]
fn custody_requires_both_real_ecdsa_and_pq_signatures() {
    let ecdsa = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let pk = ecdsa
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let mut r = registration();
    r.charter.modules.push(ModuleKind::Custody(CustodyConfig {
        btc_pubkey: pk,
        pq_pubkey: keys().0.clone(),
    }));
    let mut ledger = Ledger::new(DOMAIN);
    let asset = ledger
        .register(
            r.clone(),
            &signed(&r.signing_hash(&DOMAIN).unwrap()),
            &BlochVerifier,
            GAS,
        )
        .unwrap();
    let tx = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: keys().0.clone(),
            amount: 10,
        }],
        delta: 10,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 10,
    };
    let message = tx.signing_hash(&DOMAIN).unwrap();
    let pq = signed(&message);
    let ec: Signature = ecdsa.sign_prehash(&message).unwrap();
    let w = Witnesses {
        modules: vec![
            vec![Val::Bytes(pq.clone())],
            vec![Val::Bytes(ec.to_bytes().to_vec()), Val::Bytes(pq)],
        ],
        ..Witnesses::default()
    };
    for slot in [0, 1] {
        let mut bad = w.clone();
        bad.modules[1][slot] = Val::Bytes(vec![]);
        let before = ledger.snapshot();
        assert!(ledger.apply(&tx, &bad, 1, &BlochVerifier, GAS).is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    ledger.apply(&tx, &w, 1, &BlochVerifier, GAS).unwrap();
}

#[test]
fn ecdsa_rejects_high_s_uncompressed_keys_and_wrong_messages() {
    let ecdsa = SigningKey::from_bytes((&[5; 32]).into()).unwrap();
    let message = [6; 32];
    let pk = ecdsa.verifying_key().to_encoded_point(true);
    let sig: Signature = ecdsa.sign_prehash(&message).unwrap();
    assert!(BlochVerifier.verify_ecdsa(&message, pk.as_bytes(), &sig.to_bytes()));
    assert!(!BlochVerifier.verify_ecdsa(&[7; 32], pk.as_bytes(), &sig.to_bytes()));
    assert!(
        !BlochVerifier.valid_ecdsa_key(ecdsa.verifying_key().to_encoded_point(false).as_bytes())
    );
    let mut invalid = [0xff; 33];
    invalid[0] = 2;
    assert!(!BlochVerifier.valid_ecdsa_key(&invalid));
    let high = Signature::from_scalars(sig.r().to_bytes(), (-sig.s()).to_bytes()).unwrap();
    assert!(high.normalize_s().is_some());
    assert!(!BlochVerifier.verify_ecdsa(&message, pk.as_bytes(), &high.to_bytes()));
}
