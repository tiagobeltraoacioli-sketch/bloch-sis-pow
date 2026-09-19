//! Deterministic key-bound test verifier; actual hybrid crypto is tested in bloch-ustav.
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::ustav::amm::{Action, PoolState, Request};
use bloch_euvm::ustav::gateway::pools::wire::Envelope;
use bloch_euvm::ustav::gateway::pools::{creation_hash, PoolAction, PoolLedger};
use bloch_euvm::ustav::{Output, Registration, Transaction, Verifier, Witnesses};
use bloch_euvm::Val;
use sha2::{Digest, Sha256};
const DOMAIN: [u8; 32] = [51; 32];
const GAS: u64 = 10_000_000;
struct V;
fn sign(hash: &[u8], key: &[u8]) -> Vec<u8> {
    Sha256::digest([key, hash].concat()).to_vec()
}
impl Verifier for V {
    fn valid_pq_key(&self, k: &[u8]) -> bool {
        k.len() == 32 && k[0] > 0
    }
    fn verify_pq(&self, m: &[u8], k: &[u8], s: &[u8]) -> bool {
        self.valid_pq_key(k) && sign(m, k) == s
    }
}
fn fixture() -> (PoolLedger, Envelope) {
    let mut ledger = PoolLedger::new(DOMAIN);
    let owner = vec![8; 32];
    let mut minted = Vec::new();
    for i in 0..2 {
        let r = Registration {
            charter: TokenCharter {
                token_name: vec![65, i],
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 10_000_000,
                    issuer_pubkey: owner.clone(),
                })],
            },
            nonce: [i; 32],
            initial_kyc_root: None,
        };
        let sig = sign(&r.signing_hash(&DOMAIN).unwrap(), &owner);
        let asset = ledger.register(r, &sig, &V, GAS).unwrap();
        let tx = Transaction {
            asset,
            inputs: vec![],
            outputs: vec![Output {
                owner: owner.clone(),
                amount: 1_000_000,
            }],
            delta: 1_000_000,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        };
        let w = Witnesses {
            modules: vec![vec![Val::Bytes(sign(
                &tx.signing_hash(&DOMAIN).unwrap(),
                &owner,
            ))]],
            ..Witnesses::default()
        };
        let receipt = ledger.apply(&tx, &w, 1, &V, GAS).unwrap();
        minted.push((asset, receipt.outputs[0]));
    }
    minted.sort_by_key(|a| a.0);
    let pool = PoolState::new(DOMAIN, minted[0].0, minted[1].0, 30, [12; 32]).unwrap();
    let sig = sign(&creation_hash(&pool, &owner).unwrap(), &owner);
    let id = ledger.create(pool, &owner, &sig, &V, GAS).unwrap();
    let action = PoolAction {
        request: Request {
            pool: id,
            revision: 0,
            valid_until: 100,
            action: Action::Add {
                maximum: [100_000, 200_000],
                minimum_lp: 1,
            },
        },
        owner: owner.clone(),
        funding: [vec![minted[0].1], vec![minted[1].1]],
    };
    let signature = sign(&ledger.signing_hash(&action).unwrap(), &owner);
    (
        ledger,
        Envelope {
            domain: DOMAIN,
            action,
            signature,
        },
    )
}
fn transfer(ledger: &PoolLedger, e: &Envelope) -> (Transaction, Witnesses) {
    let input = e.action.funding[0][0];
    let old = ledger.gateway().native().output(&input).unwrap();
    let tx = Transaction {
        asset: old.asset,
        inputs: vec![input],
        outputs: vec![Output {
            owner: vec![9; 32],
            amount: old.output.amount,
        }],
        delta: 0,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let w = Witnesses {
        owners: vec![sign(&tx.signing_hash(&DOMAIN).unwrap(), &e.action.owner)],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    (tx, w)
}
#[test]
fn dropping_plan_preserves_full_state_and_commit_matches_direct_apply() {
    let (mut ledger, e) = fixture();
    let (tx, w) = transfer(&ledger, &e);
    let before = ledger.snapshot();
    let root = ledger.state_root();
    let receipt = {
        let plan = ledger.plan_transfer(&tx, &w, 2, &V, GAS).unwrap();
        plan.receipt().clone()
    };
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(ledger.state_root(), root);
    let mut direct = ledger.clone();
    let direct_receipt = direct.apply(&tx, &w, 2, &V, GAS).unwrap();
    assert!(receipt.gas_used > direct_receipt.gas_used);
    assert_eq!(receipt.transaction, direct_receipt.transaction);
    assert_eq!(receipt.outputs, direct_receipt.outputs);
    assert_eq!(receipt.supply, direct_receipt.supply);
    let committed = ledger
        .plan_transfer(&tx, &w, 2, &V, receipt.gas_used)
        .unwrap()
        .commit();
    assert_eq!(committed, receipt);
    assert_eq!(ledger.snapshot(), direct.snapshot());
    assert_eq!(ledger.state_root(), direct.state_root());
    assert!(ledger.plan_transfer(&tx, &w, 2, &V, GAS).is_err());
}
#[test]
fn signature_expiry_stale_policy_supply_delta_and_gas_fail_without_changes() {
    let (mut ledger, e) = fixture();
    let (tx, w) = transfer(&ledger, &e);
    let before = ledger.snapshot();
    let needed = ledger
        .plan_transfer(&tx, &w, 2, &V, GAS)
        .unwrap()
        .receipt()
        .gas_used;
    for gas in [0, 100, needed - 1] {
        assert!(ledger.plan_transfer(&tx, &w, 2, &V, gas).is_err());
        assert_eq!(ledger.snapshot(), before);
    }
    let mut wrong = w.clone();
    wrong.owners[0][0] ^= 1;
    assert!(ledger.plan_transfer(&tx, &wrong, 2, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    assert!(ledger.plan_transfer(&tx, &w, 101, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    let mut stale = tx.clone();
    stale.policy_revision = 1;
    assert!(ledger.plan_transfer(&stale, &w, 2, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    for delta in [-1, 1] {
        let mut bad = tx.clone();
        bad.delta = delta;
        assert!(ledger.plan_transfer(&bad, &w, 2, &V, GAS).is_err());
        assert_eq!(ledger.snapshot(), before);
    }
}
#[test]
fn pool_reserve_locks_remain_authoritative_for_staged_transfers() {
    let (mut ledger, e) = fixture();
    let receipt = ledger.execute(&e.action, &e.signature, 2, &V, GAS).unwrap();
    let reserve = ledger
        .gateway()
        .native()
        .output(&receipt.reserves[0])
        .unwrap();
    let tx = Transaction {
        asset: reserve.asset,
        inputs: vec![receipt.reserves[0]],
        outputs: vec![Output {
            owner: e.action.owner.clone(),
            amount: reserve.output.amount,
        }],
        delta: 0,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let w = Witnesses {
        owners: vec![sign(&tx.signing_hash(&DOMAIN).unwrap(), &e.action.owner)],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    let before = ledger.snapshot();
    assert!(ledger.plan_transfer(&tx, &w, 3, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    assert!(ledger.is_locked(&receipt.reserves[0]));
}
#[test]
fn late_transfer_policy_rejection_does_not_commit_valid_owner_spend() {
    use bloch_euvm::modules::GovernanceConfig;
    let owner = vec![8; 32];
    let authority = vec![9; 32];
    let mut ledger = PoolLedger::new(DOMAIN);
    let r = Registration {
        charter: TokenCharter {
            token_name: b"PLAN-POLICY".to_vec(),
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 1000,
                    issuer_pubkey: owner.clone(),
                }),
                ModuleKind::Governance(GovernanceConfig {
                    threshold: 1,
                    signers: vec![authority.clone()],
                }),
            ],
        },
        nonce: [88; 32],
        initial_kyc_root: None,
    };
    let sig = sign(&r.signing_hash(&DOMAIN).unwrap(), &owner);
    let asset = ledger.register(r, &sig, &V, GAS).unwrap();
    let mint = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: owner.clone(),
            amount: 100,
        }],
        delta: 100,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let hash = mint.signing_hash(&DOMAIN).unwrap();
    let w = Witnesses {
        modules: vec![
            vec![Val::Bytes(sign(&hash, &owner))],
            vec![Val::Bytes(sign(&hash, &authority))],
        ],
        ..Witnesses::default()
    };
    let receipt = ledger.apply(&mint, &w, 1, &V, GAS).unwrap();
    let tx = Transaction {
        inputs: receipt.outputs,
        outputs: vec![Output {
            owner: authority.clone(),
            amount: 100,
        }],
        delta: 0,
        ..mint
    };
    let hash = tx.signing_hash(&DOMAIN).unwrap();
    let mut w = Witnesses {
        owners: vec![sign(&hash, &owner)],
        modules: vec![vec![], vec![Val::Bytes(sign(&hash, &owner))]],
        ..Witnesses::default()
    };
    let before = ledger.snapshot();
    assert!(ledger.plan_transfer(&tx, &w, 2, &V, GAS).is_err());
    assert_eq!(ledger.snapshot(), before);
    w.modules[1][0] = Val::Bytes(sign(&hash, &authority));
    ledger.plan_transfer(&tx, &w, 2, &V, GAS).unwrap().commit();
    assert!(ledger.gateway().native().output(&tx.inputs[0]).is_none());
}
