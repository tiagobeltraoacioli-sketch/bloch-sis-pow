//! Native pair adversarial coverage with deterministic message/key-bound signatures.
use bloch_euvm::modules::*;
use bloch_euvm::ustav::pairs::wire::Error;
use bloch_euvm::ustav::pairs::wire::*;
use bloch_euvm::ustav::pairs::PairSwap;
use bloch_euvm::ustav::*;
use bloch_euvm::Val;
use sha2::{Digest, Sha256};

const DOMAIN: [u8; 32] = [42; 32];
const GAS: u64 = 10_000_000;
struct TestVerifier;
fn key(id: u8) -> Vec<u8> {
    vec![id; 32]
}
fn sign(message: &[u8], owner: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(owner);
    hash.update(message);
    hash.finalize().to_vec()
}
impl Verifier for TestVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        key.len() == 32 && key[0] != 0
    }
    fn verify_pq(&self, message: &[u8], owner: &[u8], signature: &[u8]) -> bool {
        self.valid_pq_key(owner) && signature == sign(message, owner)
    }
}
fn fixture() -> (Ledger, PairSwap) {
    let mut ledger = Ledger::new(DOMAIN);
    let mut legs = Vec::new();
    for n in 1..=2 {
        let registration = Registration {
            charter: TokenCharter {
                token_name: format!("Native{n}").into_bytes(),
                modules: vec![
                    ModuleKind::Supply(SupplyConfig {
                        cap: 1000,
                        issuer_pubkey: key(1),
                    }),
                    ModuleKind::TransferPolicy(TransferPolicyConfig {
                        authority_pubkey: key(2),
                    }),
                ],
            },
            nonce: [n; 32],
            initial_kyc_root: None,
        };
        let signature = sign(&registration.signing_hash(&DOMAIN).unwrap(), &key(1));
        let asset = ledger
            .register(registration, &signature, &TestVerifier, GAS)
            .unwrap();
        let mint = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![Output {
                owner: key(n + 10),
                amount: 100,
            }],
            delta: 100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let witness = Witnesses {
            modules: vec![
                vec![Val::Bytes(sign(
                    &mint.signing_hash(&DOMAIN).unwrap(),
                    &key(1),
                ))],
                vec![Val::Bytes(vec![])],
            ],
            ..Witnesses::default()
        };
        let receipt = ledger
            .apply(&mint, &witness, 1, &TestVerifier, GAS)
            .unwrap();
        legs.push(Transaction {
            inputs: receipt.outputs,
            outputs: vec![Output {
                owner: key(13 - n),
                amount: 100,
            }],
            delta: 0,
            ..mint
        });
    }
    legs.sort_by_key(|leg| leg.asset);
    (
        ledger,
        PairSwap {
            legs: legs.try_into().unwrap(),
        },
    )
}
fn witnesses(ledger: &Ledger, swap: &PairSwap, domain: &[u8; 32]) -> [Witnesses; 2] {
    let message = swap.signing_hash(domain).unwrap();
    std::array::from_fn(|n| Witnesses {
        owners: swap.legs[n]
            .inputs
            .iter()
            .map(|id| sign(&message, &ledger.output(id).unwrap().output.owner))
            .collect(),
        modules: vec![vec![], vec![Val::Bytes(vec![])]],
        eligibility: vec![],
    })
}
#[test]
fn canonical_roundtrip_and_dispatch() {
    let (mut ledger, swap) = fixture();
    let w = witnesses(&ledger, &swap, &DOMAIN);
    let bytes = encode_pair(&DOMAIN, &swap, &w).unwrap();
    let decoded = decode_pair(&bytes).unwrap();
    assert_eq!(decoded.domain, DOMAIN);
    assert_eq!(decoded.swap, swap);
    assert_eq!(decoded.witnesses, w);
    assert_eq!(
        encode_pair(&decoded.domain, &decoded.swap, &decoded.witnesses).unwrap(),
        bytes
    );
    let receipt = apply_encoded_pair(&mut ledger, &bytes, 2, &TestVerifier, GAS).unwrap();
    assert_eq!(receipt.authorization, swap.signing_hash(&DOMAIN).unwrap());
    assert!(receipt.gas_used <= GAS);
    for leg in &swap.legs {
        assert!(ledger.output(&leg.inputs[0]).is_none());
    }
}

#[test]
fn all_truncations_and_header_length_malleability_fail() {
    let (ledger, swap) = fixture();
    let w = witnesses(&ledger, &swap, &DOMAIN);
    let bytes = encode_pair(&DOMAIN, &swap, &w).unwrap();
    for n in 0..bytes.len() {
        assert!(decode_pair(&bytes[..n]).is_err(), "accepted prefix {n}");
    }
    for (offset, value) in [(0, 0), (8, 2), (10, 2)] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        assert!(decode_pair(&bad).is_err());
    }
    let mut count_overflow = bytes.clone();
    count_overflow[75..79].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_pair(&count_overflow).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(decode_pair(&trailing), Err(Error::TrailingBytes));
    assert_eq!(
        decode_pair(&vec![0; MAX_ENCODED_BYTES + 1]),
        Err(Error::TooLarge)
    );
}

#[test]
fn forged_signatures_wrong_domain_and_gas_preserve_state() {
    let (mut ledger, swap) = fixture();
    let w = witnesses(&ledger, &swap, &DOMAIN);
    let before = ledger.snapshot();
    let mut forged = w.clone();
    forged[1].owners[0][0] ^= 1;
    let bytes = encode_pair(&DOMAIN, &swap, &forged).unwrap();
    assert!(apply_encoded_pair(&mut ledger, &bytes, 2, &TestVerifier, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    let foreign = encode_pair(&[9; 32], &swap, &w).unwrap();
    assert_eq!(
        apply_encoded_pair(&mut ledger, &foreign, 2, &TestVerifier, GAS),
        Err(Error::WrongDomain)
    );
    assert_eq!(ledger.snapshot(), before);
    let bytes = encode_pair(&DOMAIN, &swap, &w).unwrap();
    let mut preview = ledger.clone();
    let exact = apply_encoded_pair(&mut preview, &bytes, 2, &TestVerifier, GAS)
        .unwrap()
        .gas_used;
    assert!(apply_encoded_pair(&mut ledger, &bytes, 2, &TestVerifier, exact - 1).is_err());
    assert_eq!(ledger.snapshot(), before);
    apply_encoded_pair(&mut ledger, &bytes, 2, &TestVerifier, exact).unwrap();
}

#[test]
fn complete_module_and_kyc_witnesses_roundtrip_without_loss() {
    let (ledger, swap) = fixture();
    let mut w = witnesses(&ledger, &swap, &DOMAIN);
    w[0].modules
        .push(vec![Val::Bytes(vec![]), Val::Bytes(vec![99; 8192])]);
    let mut tree = bloch_euvm::state::SparseMerkleTree::new();
    tree.insert(&[7; 32], &100u64.to_le_bytes());
    w[0].eligibility.push(tree.prove(&[7; 32]));
    let bytes = encode_pair(&DOMAIN, &swap, &w).unwrap();
    assert_eq!(decode_pair(&bytes).unwrap().witnesses, w);
    w[0].modules[2][0] = Val::Int(1);
    assert!(encode_pair(&DOMAIN, &swap, &w).is_err());
    w[0].modules[2][0] = Val::Bytes(vec![]);
    w[0].eligibility[0].value = None;
    assert!(encode_pair(&DOMAIN, &swap, &w).is_err());
}
