//! Local reference settlement only: no network, consensus activation or persisted keys.
//! The illustrative stablecoin has no backing, peg or redemption implementation.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::pairs::PairSwap;
use bloch_euvm::Val;
use bloch_ustav::*;

fn main() {
    let domain = [93; 32]; // Demo only; a host must authenticate its network domain.
    let gas = 10_000_000;
    let owners = [crypto::generate_keypair(), crypto::generate_keypair()];
    let mut ledger = Ledger::new(domain);
    let mut transfers = Vec::new();
    for (i, name) in [b"ILLUSTRATIVE-STABLECOIN".as_slice(), b"NATIVE-DEMO-ASSET"]
        .iter()
        .enumerate()
    {
        let registration = Registration {
            charter: TokenCharter {
                token_name: name.to_vec(),
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 1_000,
                    issuer_pubkey: owners[i].0.clone(),
                })],
            },
            nonce: [i as u8; 32],
            initial_kyc_root: None,
        };
        let registration_signature = crypto::sign(
            &owners[i].1,
            &registration
                .signing_hash(&domain)
                .expect("registration hash"),
        )
        .expect("registration signature");
        let asset = ledger
            .register(registration, &registration_signature, &BlochVerifier, gas)
            .expect("register native asset");
        let mint = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![Output {
                owner: owners[i].0.clone(),
                amount: 100,
            }],
            delta: 100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let mint_signature = crypto::sign(
            &owners[i].1,
            &mint.signing_hash(&domain).expect("mint hash"),
        )
        .expect("mint signature");
        let minted = ledger
            .apply(
                &mint,
                &Witnesses {
                    modules: vec![vec![Val::Bytes(mint_signature)]],
                    ..Witnesses::default()
                },
                1,
                &BlochVerifier,
                gas,
            )
            .expect("mint illustrative units");
        transfers.push((
            Transaction {
                inputs: minted.outputs,
                outputs: vec![Output {
                    owner: owners[1 - i].0.clone(),
                    amount: 100,
                }],
                delta: 0,
                ..mint
            },
            i,
        ));
    }
    transfers.sort_by_key(|(leg, _)| leg.asset);
    let [(first, first_owner), (second, second_owner)]: [(Transaction, usize); 2] =
        transfers.try_into().expect("two assets");
    let swap = PairSwap {
        legs: [first, second],
    };
    // Each owner approves both legs together, including recipients and amounts.
    let joint_hash = swap
        .signing_hash(&domain)
        .expect("joint authorization hash");
    let witnesses = [first_owner, second_owner].map(|owner| Witnesses {
        owners: vec![crypto::sign(&owners[owner].1, &joint_hash).expect("joint hybrid signature")],
        modules: vec![vec![]],
        ..Witnesses::default()
    });
    let receipt = ledger
        .settle_pair(&swap, &witnesses, 2, &BlochVerifier, gas)
        .expect("atomic pair settlement");
    for (i, leg) in swap.legs.iter().enumerate() {
        assert!(ledger.output(&leg.inputs[0]).is_none());
        assert_eq!(
            ledger.output(&receipt.legs[i].outputs[0]).unwrap().output,
            leg.outputs[0]
        );
        assert_eq!(ledger.supply(&leg.asset), Some(100));
    }
    let before_replay = ledger.snapshot();
    assert!(ledger
        .settle_pair(&swap, &witnesses, 2, &BlochVerifier, gas)
        .is_err());
    assert_eq!(ledger.snapshot(), before_replay);
    println!("Reference native pair: both independently owned assets exchanged atomically.");
    println!("Owners authorized both legs using ML-DSA-65 AND Falcon-1024; replay rejected.");
    println!(
        "Illustrative stablecoin only: no backing, peg, redemption or live network activation."
    );
}
