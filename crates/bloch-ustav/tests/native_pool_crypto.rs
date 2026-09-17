//! Real hybrid signatures over native-token custody; no base BLCH or network activation.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::amm::{Action, PoolState, Request};
use bloch_euvm::ustav::gateway::pools::{
    creation_hash, Error as PoolError, PoolAction, PoolLedger,
};
use bloch_euvm::Val;
use bloch_ustav::{BlochVerifier, Output, Registration, Transaction, Witnesses};
const DOMAIN: [u8; 32] = [101; 32];
const GAS: u64 = 10_000_000;
fn signed(secret: &[u8], hash: &[u8]) -> Vec<u8> {
    crypto::sign(secret, hash).unwrap()
}
#[test]
fn real_pq_pool_custody_add_swap_lp_theft_rejection_remove_and_restore() {
    let owner = crypto::generate_keypair_from_seed(&[102; 32]).unwrap();
    let trader = crypto::generate_keypair_from_seed(&[103; 32]).unwrap();
    let mut ledger = PoolLedger::new(DOMAIN);
    let mut assets = Vec::new();
    for i in 0..2 {
        let registration = Registration {
            charter: TokenCharter {
                token_name: format!("POOL-TEST-{i}").into_bytes(),
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 10_000_000,
                    issuer_pubkey: owner.0.clone(),
                })],
            },
            nonce: [i; 32],
            initial_kyc_root: None,
        };
        let signature = signed(&owner.1, &registration.signing_hash(&DOMAIN).unwrap());
        let asset = ledger
            .register(registration, &signature, &BlochVerifier, GAS)
            .unwrap();
        let tx = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![
                Output {
                    owner: owner.0.clone(),
                    amount: 2_000_000,
                },
                Output {
                    owner: trader.0.clone(),
                    amount: 100_000,
                },
            ],
            delta: 2_100_000,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let w = Witnesses {
            modules: vec![vec![Val::Bytes(signed(
                &owner.1,
                &tx.signing_hash(&DOMAIN).unwrap(),
            ))]],
            ..Witnesses::default()
        };
        let minted = ledger.apply(&tx, &w, 1, &BlochVerifier, GAS).unwrap();
        assets.push((asset, minted.outputs[0], minted.outputs[1]));
    }
    assets.sort_by_key(|a| a.0);
    let pool = PoolState::new(DOMAIN, assets[0].0, assets[1].0, 30, [104; 32]).unwrap();
    let create = signed(&owner.1, &creation_hash(&pool, &owner.0).unwrap());
    let id = ledger
        .create(pool, &owner.0, &create, &BlochVerifier, GAS)
        .unwrap();
    let add = PoolAction {
        request: Request {
            pool: id,
            revision: 0,
            valid_until: 100,
            action: Action::Add {
                maximum: [1_000_000, 1_500_000],
                minimum_lp: 1,
            },
        },
        owner: owner.0.clone(),
        funding: [vec![assets[0].1], vec![assets[1].1]],
    };
    let signature = signed(&owner.1, &ledger.signing_hash(&add).unwrap());
    let added = ledger
        .execute(&add, &signature, 2, &BlochVerifier, GAS)
        .unwrap();
    assert!(added.lp_balance > 0);
    assert!(added.reserves.iter().all(|id| ledger.is_locked(id)));
    let before = ledger.snapshot();
    assert!(ledger
        .execute(&add, &signature, 2, &BlochVerifier, GAS)
        .is_err());
    assert_eq!(before, ledger.snapshot());
    let swap = PoolAction {
        request: Request {
            pool: id,
            revision: 1,
            valid_until: 100,
            action: Action::SwapExactInput {
                input_index: 0,
                amount: 10_000,
                minimum_out: 1,
            },
        },
        owner: trader.0.clone(),
        funding: [vec![assets[0].2], vec![]],
    };
    let signature = signed(&trader.1, &ledger.signing_hash(&swap).unwrap());
    let swapped = ledger
        .execute(&swap, &signature, 3, &BlochVerifier, GAS)
        .unwrap();
    let payout = ledger
        .gateway()
        .native()
        .output(&swapped.payouts[1].unwrap())
        .unwrap();
    assert_eq!(payout.output.owner, trader.0);
    assert!(payout.output.amount > 0);
    assert_eq!(ledger.position(&id, &trader.0), 0);
    let remove = PoolAction {
        request: Request {
            pool: id,
            revision: 2,
            valid_until: 100,
            action: Action::Remove {
                lp: added.lp_balance,
                minimum: [1, 1],
            },
        },
        owner: owner.0.clone(),
        funding: [vec![], vec![]],
    };
    let hash = ledger.signing_hash(&remove).unwrap();
    let before = ledger.snapshot();
    assert_eq!(
        ledger.execute(&remove, &signed(&trader.1, &hash), 4, &BlochVerifier, GAS),
        Err(PoolError::Unauthorized)
    );
    assert_eq!(before, ledger.snapshot());
    let mut impersonation = remove.clone();
    impersonation.owner = trader.0.clone();
    let hash = ledger.signing_hash(&impersonation).unwrap();
    assert_eq!(
        ledger.execute(
            &impersonation,
            &signed(&trader.1, &hash),
            4,
            &BlochVerifier,
            GAS
        ),
        Err(PoolError::InsufficientPosition)
    );
    assert_eq!(before, ledger.snapshot());
    // Restoration must retain both PQ position ownership and reserve locks.
    let mut restored = PoolLedger::restore(before, ledger.state_root(), &BlochVerifier).unwrap();
    assert!(swapped.reserves.iter().all(|id| restored.is_locked(id)));
    assert_eq!(restored.position(&id, &owner.0), added.lp_balance);
    let hash = restored.signing_hash(&remove).unwrap();
    let mut forged = signed(&owner.1, &hash);
    forged[crypto::SUITE_HEADER_LEN] ^= 1;
    let before = restored.snapshot();
    assert_eq!(
        restored.execute(&remove, &forged, 4, &BlochVerifier, GAS),
        Err(PoolError::Unauthorized)
    );
    assert_eq!(restored.snapshot(), before);
    let removed = restored
        .execute(&remove, &signed(&owner.1, &hash), 4, &BlochVerifier, GAS)
        .unwrap();
    assert_eq!(removed.lp_balance, 0);
    assert_eq!(restored.position(&id, &owner.0), 0);
    assert_eq!(restored.pool(&id).unwrap().lp_supply(), 1000);
    for (i, asset) in assets.iter().enumerate() {
        assert_eq!(
            restored.gateway().native().supply(&asset.0),
            Some(2_100_000)
        );
        assert_eq!(
            restored
                .gateway()
                .native()
                .output(&removed.payouts[i].unwrap())
                .unwrap()
                .output
                .owner,
            owner.0
        );
        assert!(restored.is_locked(&removed.reserves[i]));
    }
    PoolLedger::restore(restored.snapshot(), restored.state_root(), &BlochVerifier).unwrap();
}
