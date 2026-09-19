//! Native reference settlement with the actual ML-DSA-65 AND Falcon-1024 host.
use bloch_crypto::crypto;
use bloch_euvm::modules::{GovernanceConfig, ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::pairs::PairSwap;
use bloch_euvm::Val;
use bloch_ustav::*;
use std::sync::OnceLock;

const DOMAIN: [u8; 32] = [91; 32];
const GAS: u64 = 10_000_000;
type Keys = (Vec<u8>, Vec<u8>);
fn keys() -> &'static [Keys; 2] {
    static KEYS: OnceLock<[Keys; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            crypto::generate_keypair_from_seed(&[81; 32]).unwrap(),
            crypto::generate_keypair_from_seed(&[82; 32]).unwrap(),
        ]
    })
}
fn sign(owner: usize, hash: &[u8]) -> Vec<u8> {
    crypto::sign(&keys()[owner].1, hash).unwrap()
}
fn fixture() -> (Ledger, PairSwap, [usize; 2]) {
    let mut ledger = Ledger::new(DOMAIN);
    let mut legs = Vec::new();
    for owner in 0..2 {
        let registration = Registration {
            charter: TokenCharter {
                token_name: format!("NATIVE-PAIR-{owner}").into_bytes(),
                modules: vec![
                    ModuleKind::Supply(SupplyConfig {
                        cap: 100,
                        issuer_pubkey: keys()[owner].0.clone(),
                    }),
                    ModuleKind::Governance(GovernanceConfig {
                        threshold: 1,
                        signers: vec![keys()[owner].0.clone()],
                    }),
                ],
            },
            nonce: [owner as u8; 32],
            initial_kyc_root: None,
        };
        let asset = ledger
            .register(
                registration.clone(),
                &sign(owner, &registration.signing_hash(&DOMAIN).unwrap()),
                &BlochVerifier,
                GAS,
            )
            .unwrap();
        let mint = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![Output {
                owner: keys()[owner].0.clone(),
                amount: 100,
            }],
            delta: 100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let signature = sign(owner, &mint.signing_hash(&DOMAIN).unwrap());
        let minted = ledger
            .apply(
                &mint,
                &Witnesses {
                    modules: vec![
                        vec![Val::Bytes(signature.clone())],
                        vec![Val::Bytes(signature)],
                    ],
                    ..Witnesses::default()
                },
                1,
                &BlochVerifier,
                GAS,
            )
            .unwrap();
        let transfer = Transaction {
            inputs: minted.outputs,
            outputs: vec![Output {
                owner: keys()[1 - owner].0.clone(),
                amount: 100,
            }],
            delta: 0,
            ..mint
        };
        legs.push((transfer, owner));
    }
    legs.sort_by_key(|(leg, _)| leg.asset);
    let [(a, a_owner), (b, b_owner)]: [(Transaction, usize); 2] = legs.try_into().unwrap();
    (ledger, PairSwap { legs: [a, b] }, [a_owner, b_owner])
}
fn witnesses(swap: &PairSwap, owners: [usize; 2]) -> [Witnesses; 2] {
    let hash = swap.signing_hash(&DOMAIN).unwrap();
    owners.map(|owner| {
        let signature = sign(owner, &hash);
        Witnesses {
            owners: vec![signature.clone()],
            modules: vec![vec![], vec![Val::Bytes(signature)]],
            ..Witnesses::default()
        }
    })
}

#[test]
fn hybrid_joint_authorization_exchanges_both_native_assets() {
    let (mut ledger, swap, owners) = fixture();
    let w = witnesses(&swap, owners);
    let receipt = ledger
        .settle_pair(&swap, &w, 2, &BlochVerifier, GAS)
        .unwrap();
    for (i, leg) in swap.legs.iter().enumerate() {
        assert!(ledger.output(&leg.inputs[0]).is_none());
        let received = ledger.output(&receipt.legs[i].outputs[0]).unwrap();
        assert_eq!(received.asset, leg.asset);
        assert_eq!(received.output, leg.outputs[0]);
        assert_eq!(ledger.supply(&leg.asset), Some(100));
    }
    let settled = ledger.snapshot();
    assert!(ledger
        .settle_pair(&swap, &w, 2, &BlochVerifier, GAS)
        .is_err());
    assert_eq!(ledger.snapshot(), settled);
    Ledger::restore(settled, ledger.state_root(), &BlochVerifier).unwrap();
}

#[test]
fn either_tampered_hybrid_component_in_second_leg_rolls_back_first() {
    let (mut ledger, swap, owners) = fixture();
    let w = witnesses(&swap, owners);
    let before = ledger.snapshot();
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut forged = w.clone();
        forged[1].owners[0][offset] ^= 1;
        assert!(ledger
            .settle_pair(&swap, &forged, 2, &BlochVerifier, GAS)
            .is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    ledger
        .settle_pair(&swap, &w, 2, &BlochVerifier, GAS)
        .unwrap();
}

#[test]
fn ordinary_leg_signatures_cannot_authorize_pair_owners_or_governance() {
    let (mut ledger, swap, owners) = fixture();
    let w = witnesses(&swap, owners);
    let before = ledger.snapshot();
    for i in 0..2 {
        let single_signature = sign(owners[i], &swap.legs[i].signing_hash(&DOMAIN).unwrap());
        let mut ordinary_owner = w.clone();
        ordinary_owner[i].owners[0] = single_signature.clone();
        assert!(ledger
            .settle_pair(&swap, &ordinary_owner, 2, &BlochVerifier, GAS)
            .is_err());
        assert_eq!(ledger.snapshot(), before);
        let mut ordinary_module = w.clone();
        ordinary_module[i].modules[1][0] = Val::Bytes(single_signature);
        assert!(ledger
            .settle_pair(&swap, &ordinary_module, 2, &BlochVerifier, GAS)
            .is_err());
        assert_eq!(ledger.snapshot(), before);
    }
}
