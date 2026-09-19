//! Federated gateway authorization, replay and accounting regression tests.
use bloch_euvm::modules::*;
use bloch_euvm::ustav::gateway::*;
use bloch_euvm::ustav::{Output, Receipt, Registration, Transaction, Verifier, Witnesses};
use bloch_euvm::Val;
use sha2::{Digest, Sha256};
const DOMAIN: [u8; 32] = [42; 32];
const GAS: u64 = 100_000_000;
struct TestVerifier;
fn key(id: u8) -> Vec<u8> {
    vec![id; 32]
}
fn sign(message: &[u8], key: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(key);
    h.update(message);
    h.finalize().to_vec()
}
impl Verifier for TestVerifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        key.len() == 32 && key[0] != 0
    }
    fn verify_pq(&self, msg: &[u8], key: &[u8], sig: &[u8]) -> bool {
        self.valid_pq_key(key) && sign(msg, key) == sig
    }
}
fn config(asset: [u8; 32]) -> RouteConfig {
    RouteConfig {
        route: Route {
            source_domain: [7; 32],
            native_domain: DOMAIN,
            native_asset: asset,
            token: [8; 20],
            vault: [9; 20],
            decimals: 6,
            cap: 1_000_000,
            vault_code_hash: [10; 32],
        },
        committee: vec![key(2), key(3), key(4)],
        threshold: 2,
    }
}
fn approvals(message: &[u8; 32]) -> Vec<Vec<u8>> {
    vec![sign(message, &key(2)), sign(message, &key(3)), vec![]]
}
fn registered() -> (GatewayLedger, [u8; 32]) {
    let mut gateway = GatewayLedger::new(DOMAIN);
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"Federated USDT".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1_000_000,
                issuer_pubkey: key(1),
            })],
        },
        nonce: [1; 32],
        initial_kyc_root: None,
    };
    let sig = sign(&registration.signing_hash(&DOMAIN).unwrap(), &key(1));
    let asset = gateway
        .register(registration, &sig, &TestVerifier, GAS)
        .unwrap();
    (gateway, asset)
}
fn fixture() -> (GatewayLedger, RouteConfig) {
    let (mut gateway, asset) = registered();
    let cfg = config(asset);
    let msg = cfg.signing_hash();
    gateway
        .enable(
            cfg.clone(),
            &sign(&msg, &key(1)),
            &approvals(&msg),
            &TestVerifier,
            GAS,
        )
        .unwrap();
    (gateway, cfg)
}
fn request(cfg: &RouteConfig) -> ImportRequest {
    ImportRequest {
        deposit: Deposit {
            route: cfg.route.id(),
            nonce: 1,
            sender: [11; 20],
            amount: 100,
            pq_recipient_hash: recipient_hash(&key(12)),
        },
        source_transaction: [13; 32],
        source_block: [14; 32],
        event_index: 0,
        valid_until: 100,
        transaction: Transaction {
            asset: cfg.route.native_asset,
            inputs: vec![],
            outputs: vec![Output {
                owner: key(12),
                amount: 100,
            }],
            delta: 100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
    }
}
fn import_witness(req: &ImportRequest) -> Witnesses {
    Witnesses {
        owners: vec![],
        modules: vec![vec![Val::Bytes(sign(
            &req.signing_hash(&DOMAIN).unwrap(),
            &key(1),
        ))]],
        eligibility: vec![],
    }
}
fn fund(gateway: &mut GatewayLedger, cfg: &RouteConfig) -> Receipt {
    let req = request(cfg);
    let msg = req.signing_hash(&DOMAIN).unwrap();
    gateway
        .import(
            &req,
            &import_witness(&req),
            &approvals(&msg),
            1,
            &TestVerifier,
            GAS,
        )
        .unwrap()
}
fn withdrawal(cfg: &RouteConfig, receipt: &Receipt) -> WithdrawalRequest {
    WithdrawalRequest {
        route: cfg.route.id(),
        nonce: 0,
        recipient: [15; 20],
        transaction: Transaction {
            asset: cfg.route.native_asset,
            inputs: receipt.outputs.clone(),
            outputs: vec![],
            delta: -100,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
    }
}
fn burn_witness(req: &WithdrawalRequest) -> Witnesses {
    let msg = req.signing_hash(&DOMAIN).unwrap();
    Witnesses {
        owners: vec![sign(&msg, &key(12))],
        modules: vec![vec![Val::Bytes(sign(&msg, &key(1)))]],
        eligibility: vec![],
    }
}

#[test]
fn complete_import_withdraw_and_restore_preserve_accounting_and_replay() {
    let (mut gateway, cfg) = fixture();
    let minted = fund(&mut gateway, &cfg);
    assert_eq!(gateway.native().supply(&cfg.route.native_asset), Some(100));
    assert_eq!(gateway.route(&cfg.route.id()).unwrap().imported, 100);
    let root = gateway.state_root();
    let mut gateway = GatewayLedger::restore(gateway.snapshot(), root, &TestVerifier).unwrap();
    let req = request(&cfg);
    let msg = req.signing_hash(&DOMAIN).unwrap();
    assert!(gateway
        .import(
            &req,
            &import_witness(&req),
            &approvals(&msg),
            1,
            &TestVerifier,
            GAS
        )
        .is_err());
    assert_eq!(gateway.state_root(), root);
    let burn = withdrawal(&cfg, &minted);
    let msg = burn.signing_hash(&DOMAIN).unwrap();
    let (release, _) = gateway
        .withdraw(
            &burn,
            &burn_witness(&burn),
            &approvals(&msg),
            2,
            &TestVerifier,
            GAS,
        )
        .unwrap();
    assert_eq!(release.amount, 100);
    assert_eq!(release.recipient, [15; 20]);
    assert_eq!(release.route, cfg.route.id());
    assert_eq!(gateway.native().supply(&cfg.route.native_asset), Some(0));
    let state = gateway.route(&cfg.route.id()).unwrap();
    assert_eq!(state.burned, 100);
    assert_eq!(state.next_release_nonce, 1);
    let root = gateway.state_root();
    let mut restored = GatewayLedger::restore(gateway.snapshot(), root, &TestVerifier).unwrap();
    assert!(restored
        .withdraw(
            &burn,
            &burn_witness(&burn),
            &approvals(&msg),
            2,
            &TestVerifier,
            GAS
        )
        .is_err());
    assert_eq!(restored.state_root(), root);
    assert!(GatewayLedger::restore(gateway.snapshot(), [0; 32], &TestVerifier).is_err());
}

#[test]
fn issuer_and_committee_are_required_and_rejection_is_atomic() {
    let (mut gateway, cfg) = fixture();
    let req = request(&cfg);
    let msg = req.signing_hash(&DOMAIN).unwrap();
    let root = gateway.state_root();
    let mut wrong = approvals(&msg);
    wrong[1].clear();
    assert!(gateway
        .import(&req, &import_witness(&req), &wrong, 1, &TestVerifier, GAS)
        .is_err());
    assert_eq!(gateway.state_root(), root);
    let mut bad_issuer = import_witness(&req);
    bad_issuer.modules[0][0] = Val::Bytes(vec![]);
    assert!(gateway
        .import(&req, &bad_issuer, &approvals(&msg), 1, &TestVerifier, GAS)
        .is_err());
    assert_eq!(gateway.state_root(), root);
    let mut foreign = req.clone();
    foreign.source_block = [99; 32];
    assert!(gateway
        .import(
            &foreign,
            &import_witness(&req),
            &approvals(&msg),
            1,
            &TestVerifier,
            GAS
        )
        .is_err());
    assert_eq!(gateway.state_root(), root);
}

#[test]
fn naked_supply_changes_are_denied_but_owner_only_transfers_work() {
    let (mut gateway, cfg) = fixture();
    let req = request(&cfg);
    let naked = Witnesses {
        modules: vec![vec![Val::Bytes(sign(
            &req.transaction.signing_hash(&DOMAIN).unwrap(),
            &key(1),
        ))]],
        ..Witnesses::default()
    };
    assert!(gateway
        .apply(&req.transaction, &naked, 1, &TestVerifier, GAS)
        .is_err());
    let minted = fund(&mut gateway, &cfg);
    let tx = Transaction {
        inputs: minted.outputs,
        outputs: vec![Output {
            owner: key(16),
            amount: 100,
        }],
        delta: 0,
        ..req.transaction
    };
    let w = Witnesses {
        owners: vec![sign(&tx.signing_hash(&DOMAIN).unwrap(), &key(12))],
        modules: vec![vec![]],
        eligibility: vec![],
    };
    let receipt = gateway.apply(&tx, &w, 2, &TestVerifier, GAS).unwrap();
    assert_eq!(
        gateway
            .native()
            .output(&receipt.outputs[0])
            .unwrap()
            .output
            .owner,
        key(16)
    );
    let burn = Transaction {
        inputs: receipt.outputs,
        outputs: vec![],
        delta: -100,
        ..tx
    };
    let msg = burn.signing_hash(&DOMAIN).unwrap();
    let w = Witnesses {
        owners: vec![sign(&msg, &key(16))],
        modules: vec![vec![Val::Bytes(sign(&msg, &key(1)))]],
        eligibility: vec![],
    };
    assert!(gateway.apply(&burn, &w, 2, &TestVerifier, GAS).is_err());
}

#[test]
fn same_event_with_new_nonce_and_same_nonce_with_new_event_cannot_recredit() {
    let (mut gateway, cfg) = fixture();
    fund(&mut gateway, &cfg);
    let root = gateway.state_root();
    for new_nonce in [false, true] {
        let mut req = request(&cfg);
        req.transaction.mint_nonce = 1;
        if new_nonce {
            req.deposit.nonce = 2;
        } else {
            req.source_transaction = [99; 32];
            req.event_index = 1;
        }
        let msg = req.signing_hash(&DOMAIN).unwrap();
        assert!(gateway
            .import(
                &req,
                &import_witness(&req),
                &approvals(&msg),
                2,
                &TestVerifier,
                GAS
            )
            .is_err());
        assert_eq!(gateway.state_root(), root);
    }
}

#[test]
fn withdrawal_requires_owner_issuer_quorum_and_binds_external_recipient() {
    let (mut gateway, cfg) = fixture();
    let minted = fund(&mut gateway, &cfg);
    let req = withdrawal(&cfg, &minted);
    let msg = req.signing_hash(&DOMAIN).unwrap();
    let root = gateway.state_root();
    for missing in 0..3 {
        let mut w = burn_witness(&req);
        let mut committee = approvals(&msg);
        match missing {
            0 => w.owners[0].clear(),
            1 => w.modules[0][0] = Val::Bytes(vec![]),
            _ => committee[1].clear(),
        }
        assert!(gateway
            .withdraw(&req, &w, &committee, 2, &TestVerifier, GAS)
            .is_err());
        assert_eq!(gateway.state_root(), root);
    }
    let mut altered = req.clone();
    altered.recipient = [99; 20];
    assert!(gateway
        .withdraw(
            &altered,
            &burn_witness(&req),
            &approvals(&msg),
            2,
            &TestVerifier,
            GAS
        )
        .is_err());
    assert_eq!(gateway.state_root(), root);
}

#[test]
fn route_configuration_requires_distinct_quorum_and_matching_domain() {
    for case in 0..4 {
        let (mut gateway, asset) = registered();
        let mut cfg = config(asset);
        match case {
            0 => cfg.threshold = 1,
            1 => cfg.committee[1] = cfg.committee[0].clone(),
            2 => cfg.route.native_domain = [99; 32],
            _ => cfg.route.cap = 2_000_000,
        }
        let msg = cfg.signing_hash();
        let root = gateway.state_root();
        assert!(gateway
            .enable(
                cfg,
                &sign(&msg, &key(1)),
                &approvals(&msg),
                &TestVerifier,
                GAS
            )
            .is_err());
        assert_eq!(gateway.state_root(), root);
    }
}

#[test]
fn malformed_imports_and_low_gas_do_not_change_balances_or_replay_state() {
    let (mut gateway, cfg) = fixture();
    let good = request(&cfg);
    let root = gateway.state_root();
    for case in 0..5 {
        let mut req = good.clone();
        match case {
            0 => req.transaction.outputs[0].owner = key(99),
            1 => {
                req.transaction.outputs[0].amount = 101;
                req.transaction.delta = 101;
            }
            2 => req.valid_until = 0,
            3 => req.deposit.amount = 0,
            _ => req.transaction.asset = [99; 32],
        }
        let (w, a) = match req.signing_hash(&DOMAIN) {
            Ok(msg) => (
                Witnesses {
                    modules: vec![vec![Val::Bytes(sign(&msg, &key(1)))]],
                    ..Witnesses::default()
                },
                approvals(&msg),
            ),
            Err(_) => (
                import_witness(&good),
                approvals(&good.signing_hash(&DOMAIN).unwrap()),
            ),
        };
        assert!(gateway.import(&req, &w, &a, 1, &TestVerifier, GAS).is_err());
        assert_eq!(gateway.state_root(), root);
    }
    let msg = good.signing_hash(&DOMAIN).unwrap();
    assert!(gateway
        .import(
            &good,
            &import_witness(&good),
            &approvals(&msg),
            1,
            &TestVerifier,
            1
        )
        .is_err());
    assert_eq!(gateway.state_root(), root);
    fund(&mut gateway, &cfg);
}

#[test]
fn duplicate_source_vault_route_cannot_change_asset_binding() {
    let (mut gateway, cfg) = fixture();
    let mut altered = cfg.clone();
    altered.route.token = [44; 20];
    let msg = altered.signing_hash();
    let root = gateway.state_root();
    assert!(gateway
        .enable(
            altered,
            &sign(&msg, &key(1)),
            &approvals(&msg),
            &TestVerifier,
            GAS
        )
        .is_err());
    assert_eq!(gateway.state_root(), root);
}

#[test]
fn route_deposit_and_request_hashes_bind_source_and_destination() {
    let cfg = config([5; 32]);
    let req = request(&cfg);
    let mut other = cfg.clone();
    other.route.source_domain = [6; 32];
    assert_ne!(cfg.route.id(), other.route.id());
    assert_ne!(cfg.signing_hash(), other.signing_hash());
    other = cfg.clone();
    other.route.vault_code_hash = [6; 32];
    // External route ABI excludes code hash; native enabling still authenticates it.
    assert_eq!(cfg.route.id(), other.route.id());
    assert_ne!(cfg.signing_hash(), other.signing_hash());
    let mut deposit = req.deposit.clone();
    deposit.pq_recipient_hash = [55; 32];
    assert_ne!(req.deposit.id(), deposit.id());
    assert_ne!(
        req.signing_hash(&DOMAIN).unwrap(),
        req.signing_hash(&[55; 32]).unwrap()
    );
    let mut alternate_event = req.clone();
    alternate_event.event_index = 2;
    assert_ne!(
        req.signing_hash(&DOMAIN).unwrap(),
        alternate_event.signing_hash(&DOMAIN).unwrap()
    );
}

#[test]
fn fungible_cross_origin_exit_requires_that_routes_reserve_inventory() {
    let (mut gateway, first) = fixture();
    let mut second = first.clone();
    second.route.source_domain = [77; 32];
    second.route.vault = [78; 20];
    let msg = second.signing_hash();
    gateway
        .enable(
            second.clone(),
            &sign(&msg, &key(1)),
            &approvals(&msg),
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let minted = fund(&mut gateway, &first);
    let burn = withdrawal(&second, &minted);
    let msg = burn.signing_hash(&DOMAIN).unwrap();
    let before = gateway.state_root();
    assert!(gateway
        .withdraw(
            &burn,
            &burn_witness(&burn),
            &approvals(&msg),
            2,
            &TestVerifier,
            GAS
        )
        .is_err());
    assert_eq!(gateway.state_root(), before);
    let mut req = request(&second);
    req.transaction.mint_nonce = 1;
    let msg = req.signing_hash(&DOMAIN).unwrap();
    gateway
        .import(
            &req,
            &import_witness(&req),
            &approvals(&msg),
            2,
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let msg = burn.signing_hash(&DOMAIN).unwrap();
    gateway
        .withdraw(
            &burn,
            &burn_witness(&burn),
            &approvals(&msg),
            3,
            &TestVerifier,
            GAS,
        )
        .unwrap();
    assert_eq!(
        gateway.native().supply(&first.route.native_asset),
        Some(100)
    );
    assert_eq!(gateway.route(&first.route.id()).unwrap().imported, 100);
    assert_eq!(gateway.route(&first.route.id()).unwrap().burned, 0);
    assert_eq!(gateway.route(&second.route.id()).unwrap().imported, 100);
    assert_eq!(gateway.route(&second.route.id()).unwrap().burned, 100);
    GatewayLedger::restore(gateway.snapshot(), gateway.state_root(), &TestVerifier).unwrap();
}

#[test]
fn gateway_pairs_trade_bridge_assets_with_owner_signatures_only() {
    let (mut gateway, cfg) = fixture();
    let bridge_receipt = fund(&mut gateway, &cfg);
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"Native quote asset".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: key(1),
            })],
        },
        nonce: [2; 32],
        initial_kyc_root: None,
    };
    let msg = registration.signing_hash(&DOMAIN).unwrap();
    let asset = gateway
        .register(registration, &sign(&msg, &key(1)), &TestVerifier, GAS)
        .unwrap();
    let mint = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: key(18),
            amount: 50,
        }],
        delta: 50,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let w = Witnesses {
        modules: vec![vec![Val::Bytes(sign(
            &mint.signing_hash(&DOMAIN).unwrap(),
            &key(1),
        ))]],
        ..Witnesses::default()
    };
    let quote_receipt = gateway.apply(&mint, &w, 1, &TestVerifier, GAS).unwrap();
    let mut legs = [
        Transaction {
            asset: cfg.route.native_asset,
            inputs: bridge_receipt.outputs,
            outputs: vec![Output {
                owner: key(18),
                amount: 100,
            }],
            delta: 0,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
        Transaction {
            inputs: quote_receipt.outputs,
            outputs: vec![Output {
                owner: key(12),
                amount: 50,
            }],
            delta: 0,
            ..mint
        },
    ];
    legs.sort_by_key(|leg| leg.asset);
    let swap = bloch_euvm::ustav::pairs::PairSwap { legs };
    let msg = swap.signing_hash(&DOMAIN).unwrap();
    let w = std::array::from_fn(|n| Witnesses {
        owners: vec![sign(
            &msg,
            &gateway
                .native()
                .output(&swap.legs[n].inputs[0])
                .unwrap()
                .output
                .owner,
        )],
        modules: vec![vec![]],
        eligibility: vec![],
    });
    gateway
        .settle_pair(&swap, &w, 2, &TestVerifier, GAS)
        .unwrap();
    assert_eq!(gateway.native().supply(&cfg.route.native_asset), Some(100));
    assert_eq!(gateway.route(&cfg.route.id()).unwrap().imported, 100);
    GatewayLedger::restore(gateway.snapshot(), gateway.state_root(), &TestVerifier).unwrap();
}

#[test]
fn snapshots_reject_tampered_route_counters_events_and_release_nonces() {
    let (mut gateway, cfg) = fixture();
    let minted = fund(&mut gateway, &cfg);
    let burn = withdrawal(&cfg, &minted);
    let msg = burn.signing_hash(&DOMAIN).unwrap();
    gateway
        .withdraw(
            &burn,
            &burn_witness(&burn),
            &approvals(&msg),
            2,
            &TestVerifier,
            GAS,
        )
        .unwrap();
    let root = gateway.state_root();
    for case in 0..6 {
        let mut snapshot = gateway.snapshot();
        match case {
            0 => snapshot.routes[0].imported += 1,
            1 => snapshot.routes[0].burned -= 1,
            2 => snapshot.routes[0].next_release_nonce += 1,
            3 => snapshot.imports.clear(),
            4 => snapshot.releases[0].nonce = 9,
            _ => snapshot.imports[0].source_transaction = [0; 32],
        }
        assert!(GatewayLedger::restore(snapshot, root, &TestVerifier).is_err());
    }
}

mod transport {
    use super::*;
    use bloch_euvm::ustav::gateway::wire::{self, Envelope, Operation};

    fn import_envelope(cfg: &RouteConfig) -> Envelope {
        let req = request(cfg);
        Envelope {
            domain: DOMAIN,
            witnesses: import_witness(&req),
            approvals: approvals(&req.signing_hash(&DOMAIN).unwrap()),
            operation: Operation::Import(req),
        }
    }

    #[test]
    fn encoded_import_and_burn_match_direct_state_and_release() {
        let (mut gateway, cfg) = fixture();
        let mut direct = gateway.clone();
        let envelope = import_envelope(&cfg);
        let bytes = wire::encode(&envelope).unwrap();
        assert_eq!(wire::decode(&bytes).unwrap(), envelope);
        assert_eq!(wire::encode(&wire::decode(&bytes).unwrap()).unwrap(), bytes);
        let imported = wire::apply_encoded(&mut gateway, &bytes, 1, &TestVerifier, GAS).unwrap();
        let direct_import = fund(&mut direct, &cfg);
        assert_eq!(gateway.snapshot(), direct.snapshot());
        assert!(imported.release.is_none());
        assert!(imported.receipt.gas_used > direct_import.gas_used);
        let req = withdrawal(&cfg, &imported.receipt);
        let envelope = Envelope {
            domain: DOMAIN,
            witnesses: burn_witness(&req),
            approvals: approvals(&req.signing_hash(&DOMAIN).unwrap()),
            operation: Operation::Withdraw(req.clone()),
        };
        let bytes = wire::encode(&envelope).unwrap();
        assert_eq!(wire::decode(&bytes).unwrap(), envelope);
        let burned = wire::apply_encoded(&mut gateway, &bytes, 2, &TestVerifier, GAS).unwrap();
        let (release, _) = direct
            .withdraw(
                &req,
                &envelope.witnesses,
                &envelope.approvals,
                2,
                &TestVerifier,
                GAS,
            )
            .unwrap();
        assert_eq!(burned.release, Some(release));
        assert_eq!(gateway.snapshot(), direct.snapshot());
        let before = gateway.snapshot();
        assert!(wire::apply_encoded(&mut gateway, &bytes, 2, &TestVerifier, GAS).is_err());
        assert_eq!(gateway.snapshot(), before);
    }

    #[test]
    fn all_prefixes_counts_headers_and_trailing_bytes_fail_closed() {
        let (mut gateway, cfg) = fixture();
        let before = gateway.snapshot();
        let bytes = wire::encode(&import_envelope(&cfg)).unwrap();
        for n in 0..bytes.len() {
            assert!(
                wire::apply_encoded(&mut gateway, &bytes[..n], 1, &TestVerifier, GAS).is_err(),
                "accepted prefix {n}"
            );
        }
        assert_eq!(gateway.snapshot(), before);
        for (offset, value) in [(0, 0), (8, 2), (10, 3)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(wire::decode(&bad).is_err());
        }
        // Header43 + import metadata176 + asset32 precede native input count.
        let mut bad_count = bytes.clone();
        bad_count[251..255].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(wire::decode(&bad_count).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(wire::decode(&trailing), Err(wire::Error::TrailingBytes));
        assert_eq!(
            wire::decode(&vec![0; wire::MAX_ENCODED_BYTES + 1]),
            Err(wire::Error::TooLarge)
        );
        // Three 32/32/empty signature slots: count4 + length fields12 + signatures64.
        let mut bad_committee_count = bytes;
        let offset = bad_committee_count.len() - 80;
        bad_committee_count[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(wire::decode(&bad_committee_count).is_err());
    }

    #[test]
    fn tampering_domain_expiry_and_exact_gas_preserve_state() {
        let (mut gateway, cfg) = fixture();
        let before = gateway.snapshot();
        let envelope = import_envelope(&cfg);
        let bytes = wire::encode(&envelope).unwrap();
        let mut preview = gateway.clone();
        let exact = wire::apply_encoded(&mut preview, &bytes, 1, &TestVerifier, GAS)
            .unwrap()
            .receipt
            .gas_used;
        assert!(wire::apply_encoded(&mut gateway, &bytes, 1, &TestVerifier, exact - 1).is_err());
        assert_eq!(gateway.snapshot(), before);
        let mut wrong_domain = envelope.clone();
        wrong_domain.domain = [99; 32];
        assert_eq!(
            wire::apply_encoded(
                &mut gateway,
                &wire::encode(&wrong_domain).unwrap(),
                1,
                &TestVerifier,
                GAS
            ),
            Err(wire::Error::WrongDomain)
        );
        let mut forged = envelope;
        forged.approvals[0][0] ^= 1;
        assert!(wire::apply_encoded(
            &mut gateway,
            &wire::encode(&forged).unwrap(),
            1,
            &TestVerifier,
            GAS
        )
        .is_err());
        assert!(wire::apply_encoded(&mut gateway, &bytes, 101, &TestVerifier, GAS).is_err());
        assert_eq!(gateway.snapshot(), before);
        wire::apply_encoded(&mut gateway, &bytes, 1, &TestVerifier, exact).unwrap();
        let imported = gateway.snapshot();
        assert!(wire::apply_encoded(&mut gateway, &bytes, 1, &TestVerifier, GAS).is_err());
        assert_eq!(gateway.snapshot(), imported);
    }

    #[test]
    fn malformed_witnesses_and_unbounded_committee_cannot_encode() {
        let (_, cfg) = fixture();
        let mut e = import_envelope(&cfg);
        e.approvals.resize(MAX_COMMITTEE + 1, vec![]);
        assert_eq!(wire::encode(&e), Err(wire::Error::InvalidShape));
        let mut e = import_envelope(&cfg);
        e.approvals[0] = vec![0; bloch_euvm::ustav::MAX_SIGNATURE_BYTES + 1];
        assert_eq!(wire::encode(&e), Err(wire::Error::InvalidShape));
        let mut e = import_envelope(&cfg);
        e.witnesses.modules[0] = vec![Val::Int(0)];
        assert!(wire::encode(&e).is_err());
    }
}
