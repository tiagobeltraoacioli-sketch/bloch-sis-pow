//! Native pair adversarial coverage with deterministic message/key-bound signatures.
use bloch_euvm::modules::*;
use bloch_euvm::ustav::pairs::{Pair, PairSwap};
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
fn reject(ledger: &mut Ledger, swap: &PairSwap, witness: &[Witnesses; 2], height: u64, gas: u64) {
    let before = ledger.snapshot();
    let root = ledger.state_root();
    assert!(ledger
        .settle_pair(swap, witness, height, &TestVerifier, gas)
        .is_err());
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(ledger.state_root(), root);
}

#[test]
fn pair_identity_is_canonical_and_domain_bound() {
    let a = [1; 32];
    let b = [2; 32];
    let pair = Pair::new(DOMAIN, a, b).unwrap();
    assert_eq!(pair.assets(), [a, b]);
    assert_eq!(pair.id(), Pair::new(DOMAIN, b, a).unwrap().id());
    assert_ne!(pair.id(), Pair::new([7; 32], a, b).unwrap().id());
    assert!(Pair::new(DOMAIN, a, a).is_err());
    assert!(Pair::new(DOMAIN, [0; 32], a).is_err());
}

#[test]
fn signing_vectors_match_independent_sha256d_encoding() {
    // Expected values were independently computed with Python hashlib/struct,
    // including little-endian length prefixes and integer widths.
    let hex = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(Pair::new(DOMAIN, [1; 32], [2; 32]).unwrap().id()),
        "6195c723761367575b63733ec24c191b56aa8a1ee41d32fee25655cfeff5b45f"
    );
    let swap = PairSwap {
        legs: std::array::from_fn(|n| Transaction {
            asset: [n as u8 + 1; 32],
            inputs: vec![OutPoint {
                transaction: [3 + 2 * n as u8; 32],
                index: n as u32,
            }],
            outputs: vec![Output {
                owner: key(4 + 2 * n as u8),
                amount: 10 * (n as u64 + 1),
            }],
            delta: 0,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        }),
    };
    assert_eq!(
        hex(swap.legs[0].signing_hash(&DOMAIN).unwrap()),
        "1832a189471019593543c63582f926e4c547e4535a8c9e552715ca2864b0dc42"
    );
    assert_eq!(
        hex(swap.legs[1].signing_hash(&DOMAIN).unwrap()),
        "7b409366ace827e94ebf3c64c6517c39ac3800bacbee0c7022365c197360bcd3"
    );
    assert_eq!(
        hex(swap.signing_hash(&DOMAIN).unwrap()),
        "85cf5bc4207077ab88dd412b06dba89fdca53ef948f395450bf638e72b1d740a"
    );
}

#[test]
fn both_legs_settle_conserving_supply_and_replay_fails() {
    let (mut ledger, swap) = fixture();
    let witness = witnesses(&ledger, &swap, &DOMAIN);
    let receipt = ledger
        .settle_pair(&swap, &witness, 2, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(receipt.authorization, swap.signing_hash(&DOMAIN).unwrap());
    assert_eq!(
        receipt.pair,
        Pair::new(DOMAIN, swap.legs[0].asset, swap.legs[1].asset)
            .unwrap()
            .id()
    );
    assert!(receipt.gas_used >= receipt.legs.iter().map(|r| r.gas_used).sum());
    for (leg, result) in swap.legs.iter().zip(&receipt.legs) {
        assert_eq!(ledger.supply(&leg.asset), Some(100));
        assert!(ledger.output(&leg.inputs[0]).is_none());
        assert_eq!(
            ledger.output(&result.outputs[0]).unwrap().output,
            leg.outputs[0]
        );
    }
    reject(&mut ledger, &swap, &witness, 2, GAS);
}

#[test]
fn wrong_second_signature_rolls_back_first_leg() {
    let (mut ledger, swap) = fixture();
    let mut witness = witnesses(&ledger, &swap, &DOMAIN);
    witness[1].owners[0][0] ^= 1;
    reject(&mut ledger, &swap, &witness, 2, GAS);
}

#[test]
fn changing_opposite_recipient_invalidates_joint_authorization() {
    let (mut ledger, mut swap) = fixture();
    let witness = witnesses(&ledger, &swap, &DOMAIN);
    swap.legs[1].outputs[0].owner = key(99);
    reject(&mut ledger, &swap, &witness, 2, GAS);
}

#[test]
fn signatures_cannot_cross_domains_or_standalone_boundaries() {
    let (mut ledger, swap) = fixture();
    let foreign = witnesses(&ledger, &swap, &[9; 32]);
    reject(&mut ledger, &swap, &foreign, 2, GAS);
    let joint = witnesses(&ledger, &swap, &DOMAIN);
    let before = ledger.snapshot();
    assert!(ledger
        .apply(&swap.legs[0], &joint[0], 2, &TestVerifier, GAS)
        .is_err());
    assert_eq!(ledger.snapshot(), before);
    let mut standalone = joint;
    for (leg, w) in swap.legs.iter().zip(&mut standalone) {
        w.owners[0] = sign(
            &leg.signing_hash(&DOMAIN).unwrap(),
            &ledger.output(&leg.inputs[0]).unwrap().output.owner,
        );
    }
    reject(&mut ledger, &swap, &standalone, 2, GAS);
}

#[test]
fn second_leg_expiry_revision_and_gas_fail_atomically() {
    let (mut ledger, swap) = fixture();
    for stale_revision in [false, true] {
        let mut invalid = swap.clone();
        if stale_revision {
            invalid.legs[1].policy_revision = 1;
        } else {
            invalid.legs[1].valid_until = 1;
        }
        let witness = witnesses(&ledger, &invalid, &DOMAIN);
        reject(&mut ledger, &invalid, &witness, 2, GAS);
    }
    let witness = witnesses(&ledger, &swap, &DOMAIN);
    let mut preview = ledger.clone();
    let used = preview
        .settle_pair(&swap, &witness, 2, &TestVerifier, GAS)
        .unwrap()
        .gas_used;
    reject(&mut ledger, &swap, &witness, 2, used - 1);
    ledger
        .settle_pair(&swap, &witness, 2, &TestVerifier, used)
        .unwrap();
}

#[test]
fn malformed_pairs_mint_burn_and_unknown_assets_reject() {
    let (mut ledger, swap) = fixture();
    let witness = witnesses(&ledger, &swap, &DOMAIN);
    for case in 0..8 {
        let mut invalid = swap.clone();
        match case {
            0 => invalid.legs[1].asset = invalid.legs[0].asset,
            1 => invalid.legs[0].asset = [0; 32],
            2 => invalid.legs.swap(0, 1),
            3 => {
                invalid.legs[0].delta = 1;
                invalid.legs[0].outputs[0].amount += 1;
            }
            4 => {
                invalid.legs[0].delta = -1;
                invalid.legs[0].outputs[0].amount -= 1;
            }
            5 => invalid.legs[0].mint_nonce = 1,
            6 => invalid.legs[0].inputs.clear(),
            _ => invalid.legs[0].outputs.clear(),
        }
        assert!(invalid.signing_hash(&DOMAIN).is_err());
        reject(&mut ledger, &invalid, &witness, 2, GAS);
    }
    let mut unknown = swap.clone();
    unknown.legs[1].asset = [255; 32];
    let unknown_witness = witnesses(&ledger, &unknown, &DOMAIN);
    reject(&mut ledger, &unknown, &unknown_witness, 2, GAS);
}

#[test]
fn frozen_second_asset_requires_authority_on_joint_digest() {
    let (mut ledger, mut swap) = fixture();
    let update = PolicyUpdate {
        asset: swap.legs[1].asset,
        revision: 0,
        valid_until: 100,
        action: PolicyAction::SetFrozen(true),
    };
    let update_witness = Witnesses {
        modules: vec![
            vec![],
            vec![Val::Bytes(sign(&update.signing_hash(&DOMAIN), &key(2)))],
        ],
        ..Witnesses::default()
    };
    ledger
        .update_policy(&update, &update_witness, 2, &TestVerifier, GAS)
        .unwrap();
    swap.legs[1].policy_revision = 1;
    let mut witness = witnesses(&ledger, &swap, &DOMAIN);
    reject(&mut ledger, &swap, &witness, 2, GAS);
    witness[1].modules[1] = vec![Val::Bytes(sign(
        &swap.legs[1].signing_hash(&DOMAIN).unwrap(),
        &key(2),
    ))];
    reject(&mut ledger, &swap, &witness, 2, GAS);
    witness[1].modules[1] = vec![Val::Bytes(sign(
        &swap.signing_hash(&DOMAIN).unwrap(),
        &key(2),
    ))];
    ledger
        .settle_pair(&swap, &witness, 2, &TestVerifier, GAS)
        .unwrap();
}

#[test]
fn unrelated_utxos_and_prior_supply_survive_staged_settlement() {
    let (mut ledger, swap) = fixture();
    let mint = Transaction {
        asset: swap.legs[0].asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: key(88),
            amount: 7,
        }],
        delta: 7,
        mint_nonce: 1,
        policy_revision: 0,
        valid_until: 100,
    };
    let mint_witness = Witnesses {
        modules: vec![
            vec![Val::Bytes(sign(
                &mint.signing_hash(&DOMAIN).unwrap(),
                &key(1),
            ))],
            vec![Val::Bytes(vec![])],
        ],
        ..Witnesses::default()
    };
    let minted = ledger
        .apply(&mint, &mint_witness, 2, &TestVerifier, GAS)
        .unwrap();
    let untouched = ledger.output(&minted.outputs[0]).unwrap().clone();
    let witness = witnesses(&ledger, &swap, &DOMAIN);
    ledger
        .settle_pair(&swap, &witness, 2, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(ledger.output(&minted.outputs[0]), Some(&untouched));
    assert_eq!(ledger.supply(&mint.asset), Some(107));
    assert_eq!(ledger.next_mint_nonce(&mint.asset), Some(2));
}

#[test]
fn signed_second_leg_inflation_and_wrong_asset_inputs_reject_atomically() {
    let (mut ledger, swap) = fixture();
    let mut inflation = swap.clone();
    inflation.legs[1].outputs[0].amount += 1;
    let witness = witnesses(&ledger, &inflation, &DOMAIN);
    reject(&mut ledger, &inflation, &witness, 2, GAS);
    let mut wrong_asset = swap.clone();
    wrong_asset.legs[1].inputs = wrong_asset.legs[0].inputs.clone();
    let witness = witnesses(&ledger, &wrong_asset, &DOMAIN);
    reject(&mut ledger, &wrong_asset, &witness, 2, GAS);
}
