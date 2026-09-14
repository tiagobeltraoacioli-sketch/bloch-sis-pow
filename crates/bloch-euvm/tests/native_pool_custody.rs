//! Adversarial sealed pool custody tests. Key-bound deterministic test verifier;
//! simulated gateway attestations are not real source-chain deposits or PQ crypto.
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter, TransferPolicyConfig};
use bloch_euvm::ustav::amm::{self, Action, PoolState, Request};
use bloch_euvm::ustav::gateway::{
    self, pools::*, Deposit, ImportRequest, Route, RouteConfig, WithdrawalRequest,
};
use bloch_euvm::ustav::pairs::PairSwap;
use bloch_euvm::ustav::{OutPoint, Output, Registration, Transaction, Verifier, Witnesses};
use bloch_euvm::{AssetId, Val, BLCH};
use sha2::{Digest, Sha256};
const DOMAIN: [u8; 32] = [31; 32];
const GAS: u64 = 10_000_000;
const TOTAL: u64 = 1_000_000;
struct V;
fn key(n: u8) -> Vec<u8> {
    vec![n; 32]
}
fn sign(message: &[u8], owner: &[u8]) -> Vec<u8> {
    Sha256::digest([owner, message].concat()).to_vec()
}
impl Verifier for V {
    fn valid_pq_key(&self, k: &[u8]) -> bool {
        k.len() == 32 && k[0] > 0
    }
    fn verify_pq(&self, m: &[u8], k: &[u8], s: &[u8]) -> bool {
        self.valid_pq_key(k) && sign(m, k) == s
    }
}
fn approvals(m: &[u8]) -> Vec<Vec<u8>> {
    vec![sign(m, &key(2)), sign(m, &key(3)), vec![]]
}
fn issuer(m: &[u8]) -> Witnesses {
    Witnesses {
        modules: vec![vec![Val::Bytes(sign(m, &key(1)))]],
        ..Witnesses::default()
    }
}
fn register(ledger: &mut PoolLedger, n: u8, restricted: bool) -> AssetId {
    let mut modules = vec![ModuleKind::Supply(SupplyConfig {
        cap: 10_000_000,
        issuer_pubkey: key(1),
    })];
    if restricted {
        modules.push(ModuleKind::TransferPolicy(TransferPolicyConfig {
            authority_pubkey: key(5),
        }));
    }
    let r = Registration {
        charter: TokenCharter {
            token_name: vec![b'A', n],
            modules,
        },
        nonce: [n; 32],
        initial_kyc_root: None,
    };
    let s = sign(&r.signing_hash(&DOMAIN).unwrap(), &key(1));
    ledger.register(r, &s, &V, GAS).unwrap()
}
fn tx(asset: AssetId, inputs: Vec<OutPoint>, amount: u64, owner: Vec<u8>) -> Transaction {
    Transaction {
        asset,
        inputs,
        outputs: vec![Output { owner, amount }],
        delta: 0,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    }
}
struct Fixture {
    ledger: PoolLedger,
    pool: [u8; 32],
    assets: [AssetId; 2],
    funding: [Vec<OutPoint>; 2],
    import: ImportRequest,
    route: RouteConfig,
}
impl Fixture {
    fn new() -> Self {
        let mut ledger = PoolLedger::new(DOMAIN);
        let a = register(&mut ledger, 11, false);
        let b = register(&mut ledger, 12, false);
        let route = RouteConfig {
            route: Route {
                source_domain: [41; 32],
                native_domain: DOMAIN,
                native_asset: b,
                token: [42; 20],
                vault: [43; 20],
                decimals: 6,
                cap: 10_000_000,
                vault_code_hash: [44; 32],
            },
            committee: vec![key(2), key(3), key(4)],
            threshold: 2,
        };
        let m = route.signing_hash();
        ledger
            .enable(route.clone(), &sign(&m, &key(1)), &approvals(&m), &V, GAS)
            .unwrap();
        let mut mint = tx(a, vec![], TOTAL, key(10));
        mint.delta = i128::from(TOTAL);
        let minted = ledger
            .apply(
                &mint,
                &issuer(&mint.signing_hash(&DOMAIN).unwrap()),
                1,
                &V,
                GAS,
            )
            .unwrap();
        let mut mint_b = tx(b, vec![], TOTAL, key(10));
        mint_b.delta = i128::from(TOTAL);
        let import = ImportRequest {
            deposit: Deposit {
                route: route.route.id(),
                nonce: 0,
                sender: [45; 20],
                amount: TOTAL,
                pq_recipient_hash: gateway::recipient_hash(&key(10)),
            },
            source_transaction: [46; 32],
            source_block: [47; 32],
            event_index: 0,
            valid_until: 100,
            transaction: mint_b,
        };
        let m = import.signing_hash(&DOMAIN).unwrap();
        let envelope = gateway::wire::Envelope {
            domain: DOMAIN,
            operation: gateway::wire::Operation::Import(import.clone()),
            witnesses: issuer(&m),
            approvals: approvals(&m),
        };
        let bytes = gateway::wire::encode(&envelope).unwrap();
        assert_eq!(gateway::wire::decode(&bytes).unwrap(), envelope);
        let mut direct = ledger.clone();
        let direct_receipt = direct
            .import(&import, &issuer(&m), &approvals(&m), 1, &V, GAS)
            .unwrap();
        let applied = ledger.apply_encoded_gateway(&bytes, 1, &V, GAS).unwrap();
        assert!(applied.release.is_none());
        let imported = applied.receipt;
        assert_eq!(imported.outputs, direct_receipt.outputs);
        assert_eq!(
            imported.gas_used,
            direct_receipt.gas_used + 100 + (bytes.len() as u64).div_ceil(32)
        );
        assert_eq!(ledger.snapshot(), direct.snapshot());
        let state = PoolState::new(DOMAIN, a, b, 30, [48; 32]).unwrap();
        let assets = state.assets();
        let s = sign(&creation_hash(&state, &key(10)).unwrap(), &key(10));
        let pool = ledger.create(state, &key(10), &s, &V, GAS).unwrap();
        let funding = if assets[0] == a {
            [minted.outputs, imported.outputs]
        } else {
            [imported.outputs, minted.outputs]
        };
        Self {
            ledger,
            pool,
            assets,
            funding,
            import,
            route,
        }
    }
    fn action(&self, action: Action, owner: u8, funding: [Vec<OutPoint>; 2]) -> PoolAction {
        PoolAction {
            request: Request {
                pool: self.pool,
                revision: self.ledger.pool(&self.pool).unwrap().revision(),
                valid_until: 100,
                action,
            },
            owner: key(owner),
            funding,
        }
    }
    fn execute(&mut self, a: &PoolAction) -> PoolReceipt {
        let s = sign(&self.ledger.signing_hash(a).unwrap(), &a.owner);
        self.ledger.execute(a, &s, 2, &V, GAS).unwrap()
    }
    fn initial(&mut self) -> PoolReceipt {
        let a = self.action(
            Action::Add {
                maximum: [100_000; 2],
                minimum_lp: 1,
            },
            10,
            self.funding.clone(),
        );
        self.execute(&a)
    }
    fn transfer(&mut self, id: OutPoint, recipient: u8) -> OutPoint {
        let output = self.ledger.gateway().native().output(&id).unwrap().clone();
        let t = tx(output.asset, vec![id], output.output.amount, key(recipient));
        let w = Witnesses {
            owners: vec![sign(
                &t.signing_hash(&DOMAIN).unwrap(),
                &output.output.owner,
            )],
            modules: vec![vec![]],
            ..Witnesses::default()
        };
        self.ledger.apply(&t, &w, 2, &V, GAS).unwrap().outputs[0]
    }
}

#[test]
fn actual_funding_add_swap_remove_preserves_native_and_bridge_supply() {
    let mut f = Fixture::new();
    let first = f.initial();
    assert_eq!(first.lp_balance, 100_000 - amm::MINIMUM_LIQUIDITY);
    assert_eq!(f.ledger.pool(&f.pool).unwrap().reserves(), [100_000; 2]);
    for i in 0..2 {
        assert!(f
            .ledger
            .gateway()
            .native()
            .output(&f.funding[i][0])
            .is_none());
        assert!(f.ledger.is_locked(&first.reserves[i]));
        assert_eq!(
            f.ledger
                .gateway()
                .native()
                .output(&first.payouts[i].unwrap())
                .unwrap()
                .output
                .amount,
            900_000
        );
    }
    // Owner transfers of route-enabled USDT remain usable outside reserves.
    let second_owner = [
        f.transfer(first.payouts[0].unwrap(), 11),
        f.transfer(first.payouts[1].unwrap(), 11),
    ];
    let add = f.action(
        Action::Add {
            maximum: [10_000; 2],
            minimum_lp: 1,
        },
        11,
        [vec![second_owner[0]], vec![second_owner[1]]],
    );
    let added = f.execute(&add);
    assert_eq!(added.lp_balance, 10_000);
    let swap = f.action(
        Action::SwapExactInput {
            input_index: 0,
            amount: 1_000,
            minimum_out: 1,
        },
        11,
        [vec![added.payouts[0].unwrap()], vec![]],
    );
    let swapped = f.execute(&swap);
    assert!(swapped.payouts[1].is_some());
    assert_eq!(f.ledger.position(&f.pool, &key(11)), 10_000);
    let remove = f.action(
        Action::Remove {
            lp: 10_000,
            minimum: [1; 2],
        },
        11,
        [vec![], vec![]],
    );
    let removed = f.execute(&remove);
    assert_eq!(removed.lp_balance, 0);
    assert_eq!(f.ledger.position(&f.pool, &key(10)), 99_000);
    for asset in f.assets {
        assert_eq!(f.ledger.gateway().native().supply(&asset), Some(TOTAL));
    }
    let route = f.ledger.gateway().route(&f.route.route.id()).unwrap();
    assert_eq!((route.imported, route.burned), (u128::from(TOTAL), 0));
    let root = f.ledger.state_root();
    let restored = PoolLedger::restore(f.ledger.snapshot(), root, &V).unwrap();
    assert_eq!(restored.snapshot(), f.ledger.snapshot());
    assert!(removed.reserves.iter().all(|id| restored.is_locked(id)));
}

#[test]
fn reserve_locks_reject_every_public_escape_and_pool_funding_path() {
    let mut f = Fixture::new();
    let initial = f.initial();
    for i in 0..2 {
        assert!(f.ledger.spendable_output(&initial.reserves[i]).is_none());
        assert!(f
            .ledger
            .spendable_output(&initial.payouts[i].unwrap())
            .is_some());
    }
    assert_eq!(
        f.ledger.position(
            &f.pool,
            &vec![10; bloch_euvm::kirpich::limits::MAX_KEY_BYTES + 1]
        ),
        0
    );

    let before = f.ledger.snapshot();
    let t = tx(f.assets[0], vec![initial.reserves[0]], 100_000, key(10));
    let w = Witnesses {
        owners: vec![sign(&t.signing_hash(&DOMAIN).unwrap(), &key(10))],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    assert_eq!(f.ledger.apply(&t, &w, 2, &V, GAS), Err(Error::LockedInput));
    let b = usize::from(f.assets[1] == f.route.route.native_asset);
    let mut withdrawal_tx = tx(f.assets[b], vec![initial.reserves[b]], 100_000, key(10));
    withdrawal_tx.outputs.clear();
    withdrawal_tx.delta = -100_000;
    let withdrawal = WithdrawalRequest {
        route: f.route.route.id(),
        nonce: 0,
        recipient: [60; 20],
        transaction: withdrawal_tx,
    };
    assert_eq!(
        f.ledger.withdraw(&withdrawal, &w, &[], 2, &V, GAS),
        Err(Error::LockedInput)
    );
    let message = withdrawal.signing_hash(&DOMAIN).unwrap();
    let mut witnesses = issuer(&message);
    witnesses.owners = vec![sign(&message, &key(10))];
    let envelope = gateway::wire::Envelope {
        domain: DOMAIN,
        operation: gateway::wire::Operation::Withdraw(withdrawal.clone()),
        witnesses,
        approvals: approvals(&message),
    };
    let encoded = gateway::wire::encode(&envelope).unwrap();
    assert_eq!(
        f.ledger.apply_encoded_gateway(&encoded, 2, &V, GAS),
        Err(Error::LockedInput)
    );
    let pair = PairSwap {
        legs: [
            t,
            tx(f.assets[1], vec![initial.reserves[1]], 100_000, key(10)),
        ],
    };
    assert_eq!(
        f.ledger
            .settle_pair(&pair, &[w.clone(), w.clone()], 2, &V, GAS),
        Err(Error::LockedInput)
    );
    let mut import = f.import.clone();
    import.transaction.inputs = vec![initial.reserves[b]];
    assert_eq!(
        f.ledger.import(&import, &w, &[], 2, &V, GAS),
        Err(Error::LockedInput)
    );
    let action = f.action(
        Action::Add {
            maximum: [1_000; 2],
            minimum_lp: 1,
        },
        10,
        [vec![initial.reserves[0]], vec![initial.reserves[1]]],
    );
    let s = sign(&f.ledger.signing_hash(&action).unwrap(), &key(10));
    assert_eq!(
        f.ledger.execute(&action, &s, 2, &V, GAS),
        Err(Error::LockedInput)
    );
    assert_eq!(f.ledger.snapshot(), before);
}

#[test]
fn theft_tampering_and_low_gas_cannot_change_balances_or_positions() {
    let mut f = Fixture::new();
    let initial = f.initial();
    let before = f.ledger.snapshot();
    let theft = f.action(
        Action::Remove {
            lp: 1_000,
            minimum: [0; 2],
        },
        11,
        [vec![], vec![]],
    );
    let s = sign(&f.ledger.signing_hash(&theft).unwrap(), &key(11));
    assert_eq!(
        f.ledger.execute(&theft, &s, 2, &V, GAS),
        Err(Error::InsufficientPosition)
    );
    let add = f.action(
        Action::Add {
            maximum: [10_000; 2],
            minimum_lp: 1,
        },
        10,
        [
            vec![initial.payouts[0].unwrap()],
            vec![initial.payouts[1].unwrap()],
        ],
    );
    let s = sign(&f.ledger.signing_hash(&add).unwrap(), &key(10));
    for gas in [0, 1, 1_600, 1_850] {
        assert!(f.ledger.execute(&add, &s, 2, &V, gas).is_err());
        assert_eq!(f.ledger.snapshot(), before);
    }
    let mut changed = add.clone();
    changed.owner = key(11);
    assert_eq!(
        f.ledger.execute(&changed, &s, 2, &V, GAS),
        Err(Error::Unauthorized)
    );
    let foreign = sign(&f.ledger.signing_hash(&changed).unwrap(), &key(11));
    assert_eq!(
        f.ledger.execute(&changed, &foreign, 2, &V, GAS),
        Err(Error::InvalidFunding)
    );
    changed = add.clone();
    changed.funding[0].clear();
    assert_eq!(
        f.ledger.execute(&changed, &s, 2, &V, GAS),
        Err(Error::Unauthorized)
    );
    changed = add.clone();
    changed.request.valid_until = 99;
    assert_eq!(
        f.ledger.execute(&changed, &s, 2, &V, GAS),
        Err(Error::Unauthorized)
    );
    assert_eq!(f.ledger.snapshot(), before);
    f.execute(&add);
    let settled = f.ledger.snapshot();
    assert!(f.ledger.execute(&add, &s, 2, &V, GAS).is_err());
    assert_eq!(f.ledger.snapshot(), settled);
}

#[test]
fn restore_rejects_missing_backing_lp_and_nested_root_tampering() {
    let mut f = Fixture::new();
    let initial = f.initial();
    let snap = f.ledger.snapshot();
    let root = f.ledger.state_root();
    let mut bad = snap.clone();
    bad.positions[0].2 += 1;
    assert!(PoolLedger::restore(bad, root, &V).is_err());
    let mut bad = snap.clone();
    bad.positions[0].1 = key(11);
    assert!(PoolLedger::restore(bad, root, &V).is_err());
    let mut bad = snap.clone();
    bad.pools[0].reserves = None;
    assert!(PoolLedger::restore(bad, root, &V).is_err());
    let mut bad = snap.clone();
    bad.pools[0].reserves = Some([initial.payouts[0].unwrap(), initial.reserves[1]]);
    assert!(PoolLedger::restore(bad, root, &V).is_err());
    let mut bad = snap.clone();
    bad.pools[0].state.reserves[0] += 1;
    bad.pools[0].root = bad.pools[0].state.state_root();
    assert!(PoolLedger::restore(bad, root, &V).is_err());
    let mut bad = snap.clone();
    bad.gateway
        .native
        .outputs
        .retain(|(id, _)| *id != initial.reserves[0]);
    assert!(PoolLedger::restore(bad, root, &V).is_err());
    assert!(PoolLedger::restore(snap.clone(), snap.gateway_root, &V).is_err());
    let mut restored = PoolLedger::restore(snap, root, &V).unwrap();
    let t = tx(f.assets[0], vec![initial.reserves[0]], 100_000, key(10));
    assert_eq!(
        restored.apply(&t, &Witnesses::default(), 3, &V, GAS),
        Err(Error::LockedInput)
    );
}

#[test]
fn unsupported_assets_and_invalid_pool_creation_fail_closed() {
    let mut f = Fixture::new();
    let restricted = register(&mut f.ledger, 13, true);
    for asset in [BLCH, [0; 32], restricted, [88; 32]] {
        let state = PoolState::new(DOMAIN, f.assets[0], asset, 30, [70; 32]).unwrap();
        let s = sign(&creation_hash(&state, &key(10)).unwrap(), &key(10));
        let before = f.ledger.snapshot();
        assert_eq!(
            f.ledger.create(state, &key(10), &s, &V, GAS),
            Err(Error::UnsupportedAsset)
        );
        assert_eq!(f.ledger.snapshot(), before);
    }
    let state = PoolState::new([90; 32], f.assets[0], f.assets[1], 30, [70; 32]).unwrap();
    let s = sign(&creation_hash(&state, &key(10)).unwrap(), &key(10));
    assert_eq!(
        f.ledger.create(state, &key(10), &s, &V, GAS),
        Err(Error::InvalidPool)
    );
}

#[test]
fn foreign_pool_and_second_pair_leg_cannot_consume_reserves() {
    let mut f = Fixture::new();
    let initial = f.initial();
    let state = PoolState::new(DOMAIN, f.assets[0], f.assets[1], 30, [91; 32]).unwrap();
    let signature = sign(&creation_hash(&state, &key(10)).unwrap(), &key(10));
    let other = f
        .ledger
        .create(state, &key(10), &signature, &V, GAS)
        .unwrap();
    let action = PoolAction {
        request: Request {
            pool: other,
            revision: 0,
            valid_until: 100,
            action: Action::Add {
                maximum: [10_000; 2],
                minimum_lp: 1,
            },
        },
        owner: key(10),
        funding: [vec![initial.reserves[0]], vec![initial.reserves[1]]],
    };
    let signature = sign(&f.ledger.signing_hash(&action).unwrap(), &key(10));
    let before = f.ledger.snapshot();
    assert_eq!(
        f.ledger.execute(&action, &signature, 2, &V, GAS),
        Err(Error::LockedInput)
    );
    let pair = PairSwap {
        legs: [
            tx(
                f.assets[0],
                vec![initial.payouts[0].unwrap()],
                900_000,
                key(10),
            ),
            tx(f.assets[1], vec![initial.reserves[1]], 100_000, key(10)),
        ],
    };
    assert_eq!(
        f.ledger.settle_pair(
            &pair,
            &[Witnesses::default(), Witnesses::default()],
            2,
            &V,
            GAS
        ),
        Err(Error::LockedInput)
    );
    assert_eq!(f.ledger.snapshot(), before);
}

#[test]
fn malformed_funding_expiry_and_full_lp_removal_preserve_minimum_reserves() {
    let mut f = Fixture::new();
    // Empty, registered pools also survive full sealed persistence.
    PoolLedger::restore(f.ledger.snapshot(), f.ledger.state_root(), &V).unwrap();
    let initial = f.initial();
    let mut action = f.action(
        Action::Add {
            maximum: [10_000; 2],
            minimum_lp: 1,
        },
        10,
        [
            vec![initial.payouts[0].unwrap()],
            vec![initial.payouts[1].unwrap()],
        ],
    );
    let before = f.ledger.snapshot();
    action.funding[0].push(initial.payouts[0].unwrap());
    assert_eq!(f.ledger.signing_hash(&action), Err(Error::InvalidFunding));
    action.funding[0] = vec![initial.payouts[1].unwrap()];
    let signature = sign(&f.ledger.signing_hash(&action).unwrap(), &key(10));
    assert_eq!(
        f.ledger.execute(&action, &signature, 2, &V, GAS),
        Err(Error::InvalidFunding)
    );
    action.funding = [vec![], vec![]];
    let signature = sign(&f.ledger.signing_hash(&action).unwrap(), &key(10));
    assert_eq!(
        f.ledger.execute(&action, &signature, 2, &V, GAS),
        Err(Error::InvalidFunding)
    );
    assert_eq!(f.ledger.snapshot(), before);
    let remove = f.action(
        Action::Remove {
            lp: initial.lp_balance,
            minimum: [0; 2],
        },
        10,
        [vec![], vec![]],
    );
    let signature = sign(&f.ledger.signing_hash(&remove).unwrap(), &key(10));
    assert_eq!(
        f.ledger.execute(&remove, &signature, 101, &V, GAS),
        Err(Error::Amm(amm::Error::Expired))
    );
    assert_eq!(f.ledger.snapshot(), before);
    let receipt = f.execute(&remove);
    assert_eq!(receipt.lp_balance, 0);
    assert_eq!(
        f.ledger.pool(&f.pool).unwrap().lp_supply(),
        amm::MINIMUM_LIQUIDITY
    );
    assert_eq!(
        f.ledger.pool(&f.pool).unwrap().reserves(),
        [amm::MINIMUM_LIQUIDITY; 2]
    );
    let restored = PoolLedger::restore(f.ledger.snapshot(), f.ledger.state_root(), &V).unwrap();
    assert_eq!(restored.position(&f.pool, &key(10)), 0);
    assert!(receipt.reserves.iter().all(|id| restored.is_locked(id)));
}

#[test]
fn encoded_gateway_domain_gas_and_valid_withdrawal_preserve_outer_pool_state() {
    let mut f = Fixture::new();
    let initial = f.initial();
    let b = usize::from(f.assets[1] == f.route.route.native_asset);
    let mut transaction = tx(
        f.assets[b],
        vec![initial.payouts[b].unwrap()],
        900_000,
        key(10),
    );
    transaction.outputs.clear();
    transaction.delta = -900_000;
    let request = WithdrawalRequest {
        route: f.route.route.id(),
        nonce: 0,
        recipient: [80; 20],
        transaction,
    };
    let message = request.signing_hash(&DOMAIN).unwrap();
    let mut witnesses = issuer(&message);
    witnesses.owners = vec![sign(&message, &key(10))];
    let envelope = gateway::wire::Envelope {
        domain: DOMAIN,
        operation: gateway::wire::Operation::Withdraw(request.clone()),
        witnesses: witnesses.clone(),
        approvals: approvals(&message),
    };
    let encoded = gateway::wire::encode(&envelope).unwrap();
    let before = f.ledger.snapshot();
    let decoding_gas = 100 + (encoded.len() as u64).div_ceil(32);
    assert_eq!(
        f.ledger
            .apply_encoded_gateway(&encoded, 2, &V, decoding_gas - 1),
        Err(Error::Wire(gateway::wire::Error::OutOfGas))
    );
    assert_eq!(f.ledger.snapshot(), before);
    let mut wrong_domain = envelope.clone();
    wrong_domain.domain = [81; 32];
    let wrong = gateway::wire::encode(&wrong_domain).unwrap();
    assert_eq!(
        f.ledger.apply_encoded_gateway(&wrong, 2, &V, GAS),
        Err(Error::Wire(gateway::wire::Error::WrongDomain))
    );
    assert_eq!(f.ledger.snapshot(), before);
    let mut direct = f.ledger.clone();
    let (release, direct_receipt) = direct
        .withdraw(&request, &witnesses, &approvals(&message), 2, &V, GAS)
        .unwrap();
    let applied = f
        .ledger
        .apply_encoded_gateway(&encoded, 2, &V, GAS)
        .unwrap();
    assert_eq!(applied.release, Some(release));
    assert_eq!(
        applied.receipt.gas_used,
        direct_receipt.gas_used + decoding_gas
    );
    assert_eq!(f.ledger.snapshot(), direct.snapshot());
    assert_eq!(
        f.ledger.gateway().native().supply(&f.assets[b]),
        Some(100_000)
    );
    assert_eq!(f.ledger.pool(&f.pool).unwrap().reserves(), [100_000; 2]);
    let root = f.ledger.state_root();
    let restored = PoolLedger::restore(f.ledger.snapshot(), root, &V).unwrap();
    assert!(initial.reserves.iter().all(|id| restored.is_locked(id)));
}
