//! Local ATTESTED external-deposit simulation with real hybrid PQ signatures.
//! No source-chain proof, real USDT, network calls, consensus activation or funds.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::Val;
use bloch_ustav::gateway::*;
use bloch_ustav::{BlochVerifier, Output, Registration, Transaction, Witnesses};

pub(crate) const GAS: u64 = 10_000_000;
pub(crate) const DOMAIN: [u8; 32] = [101; 32];
pub(crate) type Keypair = (Vec<u8>, Vec<u8>);

// Shared with the integration test, which supplies deterministic test-only keys.
// The executable always generates fresh ephemeral keys and never prints secrets.
pub(crate) struct Scenario {
    pub ledger: GatewayLedger,
    pub issuer: Keypair,
    pub alice: Keypair,
    pub bob: Keypair,
    pub committee: Vec<Keypair>,
    pub configs: Vec<RouteConfig>,
}
impl Scenario {
    pub fn new(mut keys: Vec<Keypair>) -> Self {
        assert_eq!(keys.len(), 6);
        let issuer = keys.remove(0);
        let alice = keys.remove(0);
        let bob = keys.remove(0);
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        let committee = keys;
        let registration = Registration {
            charter: TokenCharter {
                token_name: b"ATTESTED-USDT-SIMULATION".to_vec(),
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 1_000_000_000,
                    issuer_pubkey: issuer.0.clone(),
                })],
            },
            nonce: [102; 32],
            initial_kyc_root: None,
        };
        let mut ledger = GatewayLedger::new(DOMAIN);
        let asset = ledger
            .register(
                registration.clone(),
                &crypto::sign(&issuer.1, &registration.signing_hash(&DOMAIN).unwrap()).unwrap(),
                &BlochVerifier,
                GAS,
            )
            .unwrap();
        // All domains, vaults and code hashes are simulation fixtures, not deployments.
        let configs = [103u8, 104]
            .into_iter()
            .map(|origin| RouteConfig {
                route: Route {
                    source_domain: [origin; 32],
                    native_domain: DOMAIN,
                    native_asset: asset,
                    token: [origin; 20],
                    vault: [origin + 10; 20],
                    decimals: 6,
                    cap: 500_000_000,
                    vault_code_hash: [origin + 20; 32],
                },
                committee: committee.iter().map(|key| key.0.clone()).collect(),
                threshold: 2,
            })
            .collect();
        Self {
            ledger,
            issuer,
            alice,
            bob,
            committee,
            configs,
        }
    }
    pub fn approvals(&self, message: &[u8]) -> Vec<Vec<u8>> {
        self.committee
            .iter()
            .enumerate()
            .map(|(index, key)| {
                if index < 2 {
                    crypto::sign(&key.1, message).unwrap()
                } else {
                    vec![]
                }
            })
            .collect()
    }
    pub fn enable_all(&mut self) {
        // All routes are fixed before first import; both back one native asset.
        for config in self.configs.clone() {
            let message = config.signing_hash();
            self.ledger
                .enable(
                    config,
                    &crypto::sign(&self.issuer.1, &message).unwrap(),
                    &self.approvals(&message),
                    &BlochVerifier,
                    GAS,
                )
                .unwrap();
        }
    }
    pub fn deposit(&self, route_index: usize, mint_nonce: u64) -> ImportRequest {
        ImportRequest {
            deposit: Deposit {
                route: self.configs[route_index].route.id(),
                nonce: 0,
                sender: [130; 20],
                amount: 100_000_000,
                pq_recipient_hash: recipient_hash(&self.alice.0),
            },
            source_transaction: [140 + route_index as u8; 32],
            source_block: [150 + route_index as u8; 32],
            event_index: 0,
            valid_until: 100,
            transaction: Transaction {
                asset: self.configs[route_index].route.native_asset,
                inputs: vec![],
                outputs: vec![Output {
                    owner: self.alice.0.clone(),
                    amount: 100_000_000,
                }],
                delta: 100_000_000,
                mint_nonce,
                policy_revision: 0,
                valid_until: 100,
            },
        }
    }
    pub fn issuer_witness(&self, message: &[u8]) -> Witnesses {
        Witnesses {
            modules: vec![vec![Val::Bytes(
                crypto::sign(&self.issuer.1, message).unwrap(),
            )]],
            ..Witnesses::default()
        }
    }
}

pub(crate) fn complete(mut scenario: Scenario) -> GatewayLedger {
    scenario.enable_all();
    let initial = scenario
        .ledger
        .liabilities(&scenario.configs[0].route.native_asset)
        .unwrap();
    assert_eq!(
        (initial.native_supply, initial.imported, initial.burned),
        (0, 0, 0)
    );
    assert_eq!(initial.routes.len(), 2);
    let first = scenario.deposit(0, 0);
    let second = scenario.deposit(1, 1);
    let mut receipts = Vec::new();
    let mut encoded_imports = Vec::new();
    for request in [&first, &second] {
        let message = request.signing_hash(&DOMAIN).unwrap();
        let envelope = wire::Envelope {
            domain: DOMAIN,
            operation: wire::Operation::Import(request.clone()),
            witnesses: scenario.issuer_witness(&message),
            approvals: scenario.approvals(&message),
        };
        let encoded = wire::encode(&envelope).unwrap();
        assert_eq!(wire::decode(&encoded).unwrap(), envelope);
        let applied =
            wire::apply_encoded(&mut scenario.ledger, &encoded, 1, &BlochVerifier, GAS).unwrap();
        assert!(applied.release.is_none());
        receipts.push(applied.receipt);
        encoded_imports.push(encoded);
    }
    let transfer = Transaction {
        inputs: receipts[0].outputs.clone(),
        outputs: vec![Output {
            owner: scenario.bob.0.clone(),
            amount: 100_000_000,
        }],
        delta: 0,
        ..first.transaction.clone()
    };
    // A normal holder transfer has no issuer signature and no committee approval.
    let witness = Witnesses {
        owners: vec![
            crypto::sign(&scenario.alice.1, &transfer.signing_hash(&DOMAIN).unwrap()).unwrap(),
        ],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    let transferred = scenario
        .ledger
        .apply(&transfer, &witness, 2, &BlochVerifier, GAS)
        .unwrap();
    // Bob exits via the other origin, which has its own 100-USDT inventory.
    let withdrawal = WithdrawalRequest {
        route: scenario.configs[1].route.id(),
        nonce: 0,
        recipient: [160; 20],
        transaction: Transaction {
            inputs: transferred.outputs,
            outputs: vec![],
            delta: -100_000_000,
            ..transfer
        },
    };
    let message = withdrawal.signing_hash(&DOMAIN).unwrap();
    let mut witness = scenario.issuer_witness(&message);
    witness.owners = vec![crypto::sign(&scenario.bob.1, &message).unwrap()];
    let envelope = wire::Envelope {
        domain: DOMAIN,
        operation: wire::Operation::Withdraw(withdrawal.clone()),
        witnesses: witness,
        approvals: scenario.approvals(&message),
    };
    let encoded_withdrawal = wire::encode(&envelope).unwrap();
    assert_eq!(wire::decode(&encoded_withdrawal).unwrap(), envelope);
    let applied = wire::apply_encoded(
        &mut scenario.ledger,
        &encoded_withdrawal,
        3,
        &BlochVerifier,
        GAS,
    )
    .unwrap();
    let release = applied.release.expect("withdrawal release record");
    assert_eq!(release.amount, 100_000_000);
    assert_eq!(
        scenario
            .ledger
            .route(&scenario.configs[0].route.id())
            .unwrap()
            .burned,
        0
    );
    assert_eq!(
        scenario
            .ledger
            .route(&scenario.configs[1].route.id())
            .unwrap()
            .burned,
        100_000_000
    );
    assert_eq!(
        scenario.ledger.native().supply(&first.transaction.asset),
        Some(100_000_000)
    );
    let root = scenario.ledger.state_root();
    let mut restored =
        GatewayLedger::restore(scenario.ledger.snapshot(), root, &BlochVerifier).unwrap();
    assert_eq!(restored.snapshot(), scenario.ledger.snapshot());
    assert!(
        wire::apply_encoded(&mut restored, &encoded_withdrawal, 4, &BlochVerifier, GAS).is_err()
    );
    assert_eq!(
        wire::apply_encoded(&mut restored, &encoded_imports[0], 4, &BlochVerifier, GAS),
        Err(wire::Error::Gateway(Error::Replay))
    );
    assert_eq!(restored.state_root(), root);
    restored
}

#[cfg(not(test))]
fn main() {
    let ledger = complete(Scenario::new(
        (0..6).map(|_| crypto::generate_keypair()).collect(),
    ));
    println!("ATTESTED SIMULATION ONLY: no real source proof, USDT or funds");
    println!("Real ML-DSA-65 AND Falcon-1024 issuer + independent 2-of-3 committee authorization");
    println!("Two simulated origins imported 200 USDT units; owner-only transfer succeeded");
    println!("Cross-origin burn reserved 100 USDT units; remaining native supply is 100");
    println!("Release is an authorization record, not an executed external payment");
    println!("Gateway wire encode/decode/apply succeeded; full snapshot restored and wire replays rejected");
    println!("state_root={:02x?}", ledger.state_root());
}
