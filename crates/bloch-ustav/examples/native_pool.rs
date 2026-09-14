//! Native-token custody rehearsal using fresh ephemeral hybrid PQ keys.
//! No base BLCH, real USDT backing, consensus activation or network transactions.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::amm::{Action, PoolState, Request};
use bloch_euvm::ustav::gateway::pools::{creation_hash, PoolAction, PoolLedger};
use bloch_euvm::Val;
use bloch_ustav::{BlochVerifier, Output, Registration, Transaction, Witnesses};
fn main() {
    let domain = [111; 32];
    let gas = 10_000_000;
    let owner = crypto::generate_keypair();
    let trader = crypto::generate_keypair();
    let mut ledger = PoolLedger::new(domain);
    let mut minted_assets = Vec::new();
    for i in 0..2 {
        let registration = Registration {
            charter: TokenCharter {
                token_name: format!("LOCAL-POOL-ASSET-{i}").into_bytes(),
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 10_000_000,
                    issuer_pubkey: owner.0.clone(),
                })],
            },
            nonce: [i; 32],
            initial_kyc_root: None,
        };
        let signature =
            crypto::sign(&owner.1, &registration.signing_hash(&domain).unwrap()).unwrap();
        let asset = ledger
            .register(registration, &signature, &BlochVerifier, gas)
            .unwrap();
        let mint = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![
                Output {
                    owner: owner.0.clone(),
                    amount: 2_000_000,
                },
                Output {
                    owner: trader.0.clone(),
                    amount: 50_000,
                },
            ],
            delta: 2_050_000,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let signature = crypto::sign(&owner.1, &mint.signing_hash(&domain).unwrap()).unwrap();
        let receipt = ledger
            .apply(
                &mint,
                &Witnesses {
                    modules: vec![vec![Val::Bytes(signature)]],
                    ..Witnesses::default()
                },
                1,
                &BlochVerifier,
                gas,
            )
            .unwrap();
        minted_assets.push((asset, receipt.outputs));
    }
    minted_assets.sort_by_key(|a| a.0);
    let state = PoolState::new(
        domain,
        minted_assets[0].0,
        minted_assets[1].0,
        30,
        [112; 32],
    )
    .unwrap();
    let signature = crypto::sign(&owner.1, &creation_hash(&state, &owner.0).unwrap()).unwrap();
    let pool = ledger
        .create(state, &owner.0, &signature, &BlochVerifier, gas)
        .unwrap();
    let add = PoolAction {
        request: Request {
            pool,
            revision: 0,
            valid_until: 100,
            action: Action::Add {
                maximum: [1_000_000, 1_500_000],
                minimum_lp: 1,
            },
        },
        owner: owner.0.clone(),
        funding: [vec![minted_assets[0].1[0]], vec![minted_assets[1].1[0]]],
    };
    let signature = crypto::sign(&owner.1, &ledger.signing_hash(&add).unwrap()).unwrap();
    let added = ledger
        .execute(&add, &signature, 2, &BlochVerifier, gas)
        .unwrap();
    let swap = PoolAction {
        request: Request {
            pool,
            revision: 1,
            valid_until: 100,
            action: Action::SwapExactInput {
                input_index: 0,
                amount: 10_000,
                minimum_out: 1,
            },
        },
        owner: trader.0.clone(),
        funding: [vec![minted_assets[0].1[1]], vec![]],
    };
    let signature = crypto::sign(&trader.1, &ledger.signing_hash(&swap).unwrap()).unwrap();
    let swapped = ledger
        .execute(&swap, &signature, 3, &BlochVerifier, gas)
        .unwrap();
    let received = ledger
        .gateway()
        .native()
        .output(&swapped.payouts[1].unwrap())
        .unwrap()
        .output
        .amount;
    let mut restored =
        PoolLedger::restore(ledger.snapshot(), ledger.state_root(), &BlochVerifier).unwrap();
    let remove = PoolAction {
        request: Request {
            pool,
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
    let signature = crypto::sign(&owner.1, &restored.signing_hash(&remove).unwrap()).unwrap();
    restored
        .execute(&remove, &signature, 4, &BlochVerifier, gas)
        .unwrap();
    assert_eq!(restored.position(&pool, &owner.0), 0);
    assert_eq!(restored.pool(&pool).unwrap().lp_supply(), 1000);
    println!("Native-token custody rehearsal: real ML-DSA-65 AND Falcon-1024 signatures.");
    println!("Added liquidity; second owner swapped 10000 units for {received}; restored sealed state and removed user LP.");
    println!("Two local Supply-only assets; no base BLCH, actual USDT, mainnet funds or consensus activation.");
}
