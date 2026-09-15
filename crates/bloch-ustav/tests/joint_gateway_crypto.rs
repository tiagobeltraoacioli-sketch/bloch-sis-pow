//! Real hybrid-PQ sponsored bridge operations. External events are test fixtures,
//! not source-finality proofs, deployed vaults or actual USDT payments.
use bloch_crypto::crypto;
use bloch_euvm::ustav::{
    gateway::{
        self,
        pools::PoolLedger,
        wire::{Envelope, Operation},
    },
    Output, Registration, Transaction, Verifier, Witnesses,
};
use bloch_euvm::{
    modules::{ModuleKind, SupplyConfig, TokenCharter},
    Val,
};
use bloch_pos_committee::{
    header::BlockHeaderV4,
    state_root::{EutxoEntry, EvmCommitment},
    transition::{
        native_dex::{gateway as joint, pool_batch, pool_candidate, pool_wire, State},
        CommittedState, PosTransaction, TransferInputV2, TransferOutput, WitnessKey,
    },
    BlockId, SignatureVerifier, StateReader,
};
use bloch_ustav::BlochVerifier;
use sha3::{Digest, Sha3_256};
use std::sync::OnceLock;
const DOMAIN: [u8; 32] = [201; 32];
const COIN: u64 = 100_000_000;
const AMOUNT: u64 = 100_000_000;
type Key = (Vec<u8>, Vec<u8>);
fn keys() -> &'static Vec<Key> {
    static KEYS: OnceLock<Vec<Key>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut keys: Vec<_> = (202..207)
            .map(|n| crypto::generate_keypair_from_seed(&[n; 32]).unwrap())
            .collect();
        keys[3..].sort_by(|a, b| a.0.cmp(&b.0));
        keys
    })
}
struct BaseVerifier;
impl SignatureVerifier for BaseVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        BlochVerifier.verify_pq(root, key, sig)
    }
}
fn sign(index: usize, message: &[u8]) -> Vec<u8> {
    crypto::sign(&keys()[index].1, message).unwrap()
}
fn base() -> CommittedState {
    let id = BlockId::of(&BlockHeaderV4 {
        version: 4,
        parent: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0; 32],
        randao_mix: [7; 32],
        justified_root: [0; 32],
        finalized_root: [0; 32],
        attestation_root: [0; 32],
        coherence_root: [0; 32],
    });
    CommittedState::genesis_with_network_domain(
        DOMAIN,
        id,
        [7; 32],
        &[],
        &[],
        [0; 32],
        [0; 32],
        [0; 32],
        EvmCommitment {
            account_root: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            base_fee_per_gas: 0,
        },
        &[
            EutxoEntry {
                txid: [8; 32],
                vout: 0,
                value: COIN,
                script_hash: Sha3_256::digest(&keys()[0].0).into(),
            },
            EutxoEntry {
                txid: [19; 32],
                vout: 0,
                value: COIN,
                script_hash: Sha3_256::digest(&keys()[2].0).into(),
            },
        ],
    )
}
fn sponsor() -> PosTransaction {
    PosTransaction::TransferV2 {
        keys: vec![WitnessKey {
            pubkey: keys()[0].0.clone(),
            signature: vec![0; 5500],
        }],
        inputs: vec![TransferInputV2 {
            txid: [8; 32],
            vout: 0,
            key_index: 0,
        }],
        outputs: vec![TransferOutput {
            value: 1,
            script_hash: Sha3_256::digest(&keys()[0].0).into(),
        }],
        tx_bytes: 0,
        tip_millisat_per_gas: 2,
    }
}
fn fixture() -> (State, joint::Request) {
    let mut native = PoolLedger::new(DOMAIN);
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"SPONSORED-USDT-SIMULATION".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: AMOUNT * 10,
                issuer_pubkey: keys()[1].0.clone(),
            })],
        },
        nonce: [9; 32],
        initial_kyc_root: None,
    };
    let message = registration.signing_hash(&DOMAIN).unwrap();
    let asset = native
        .register(registration, &sign(1, &message), &BlochVerifier, 1_000_000)
        .unwrap();
    let config = gateway::RouteConfig {
        route: gateway::Route {
            source_domain: [10; 32],
            native_domain: DOMAIN,
            native_asset: asset,
            token: [11; 20],
            vault: [12; 20],
            decimals: 6,
            cap: AMOUNT * 10,
            vault_code_hash: [13; 32],
        },
        committee: keys()[3..].iter().map(|k| k.0.clone()).collect(),
        threshold: 2,
    };
    let message = config.signing_hash();
    let route = native
        .enable(
            config,
            &sign(1, &message),
            &[sign(3, &message), sign(4, &message)],
            &BlochVerifier,
            1_000_000,
        )
        .unwrap();
    let base = base();
    let state = State::from_parts(
        base.clone(),
        native.clone(),
        base.state_root(),
        native.state_root(),
    )
    .unwrap();
    let mut request = joint::Request {
        blch: sponsor(),
        gateway: Envelope {
            domain: DOMAIN,
            operation: Operation::Import(gateway::ImportRequest {
                deposit: gateway::Deposit {
                    route,
                    nonce: 0,
                    sender: [14; 20],
                    amount: AMOUNT,
                    pq_recipient_hash: gateway::recipient_hash(&keys()[2].0),
                },
                source_transaction: [15; 32],
                source_block: [16; 32],
                event_index: 0,
                valid_until: 100,
                transaction: Transaction {
                    asset,
                    inputs: vec![],
                    outputs: vec![Output {
                        owner: keys()[2].0.clone(),
                        amount: AMOUNT,
                    }],
                    delta: AMOUNT.into(),
                    mint_nonce: 0,
                    policy_revision: 0,
                    valid_until: 100,
                },
            }),
            witnesses: Witnesses {
                modules: vec![vec![Val::Bytes(vec![0; 5500])]],
                ..Witnesses::default()
            },
            approvals: vec![vec![0; 5500]; 2],
        },
        valid_until: 100,
        native_gas: 100_000,
    };
    fund_and_sign(&state, &mut request, COIN);
    (state, request)
}
fn fund_and_sign(state: &State, r: &mut joint::Request, funds: u64) {
    fund_and_sign_with(state, r, funds, 0);
}
fn fund_and_sign_with(state: &State, r: &mut joint::Request, funds: u64, sponsor: usize) {
    // Measure real hybrid witnesses before pricing; re-sign the final fee intent.
    resign_with(r, sponsor);
    let size = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = size + 512;
    }
    let charge = state.quote_gateway(r).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut r.blch {
        outputs[0].value = funds - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    resign_with(r, sponsor);
}
fn resign(r: &mut joint::Request) {
    resign_with(r, 0);
}
fn resign_with(r: &mut joint::Request, sponsor: usize) {
    use bloch_pos_committee::transition::native_dex::pool_intent;
    let bytes = pool_wire::encode(&pool_wire::Request::Gateway(r.clone()), &DOMAIN).unwrap();
    let intent = pool_intent::DecodedIntent::decode(&bytes, &DOMAIN).unwrap();
    let expected = match &r.gateway.operation {
        Operation::Import(_) => pool_intent::Operation::Import,
        Operation::Withdraw(_) => pool_intent::Operation::Withdraw,
    };
    assert_eq!(intent.operation(), expected);
    assert_eq!(pool_wire::encode(intent.request(), &DOMAIN).unwrap(), bytes);
    let message = intent.authorization();
    assert_eq!(message, r.authorization(&DOMAIN).unwrap());
    if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
        keys[0].signature = sign(sponsor, &message);
    }
    r.gateway.witnesses.modules = vec![vec![Val::Bytes(sign(1, &message))]];
    if matches!(&r.gateway.operation, Operation::Withdraw(_)) {
        r.gateway.witnesses.owners = vec![sign(2, &message)];
    }
    r.gateway.approvals = vec![sign(3, &message), sign(4, &message)];
}
fn withdrawal(state: &State, import: &joint::Request, receipt: &joint::Receipt) -> joint::Request {
    let Operation::Import(original) = &import.gateway.operation else {
        unreachable!()
    };
    let mut request = joint::Request {
        blch: sponsor(),
        gateway: Envelope {
            domain: DOMAIN,
            operation: Operation::Withdraw(gateway::WithdrawalRequest {
                route: original.deposit.route,
                nonce: 0,
                recipient: [17; 20],
                transaction: Transaction {
                    inputs: receipt.gateway.receipt.outputs.clone(),
                    outputs: vec![],
                    delta: -(AMOUNT as i128),
                    ..original.transaction.clone()
                },
            }),
            witnesses: Witnesses {
                owners: vec![vec![0; 5500]],
                modules: vec![vec![Val::Bytes(vec![0; 5500])]],
                ..Witnesses::default()
            },
            approvals: vec![vec![0; 5500]; 2],
        },
        valid_until: 100,
        native_gas: 100_000,
    };
    if let PosTransaction::TransferV2 { inputs, .. } = &mut request.blch {
        inputs[0].txid = receipt.blch_txid;
    }
    let PosTransaction::TransferV2 { outputs, .. } = &import.blch else {
        unreachable!()
    };
    fund_and_sign(state, &mut request, outputs[0].value);
    request
}
fn reject_unchanged(state: &mut State, request: &joint::Request, height: u64) {
    let before = (
        state.state_root(),
        state.base().clone(),
        state.native().snapshot(),
        state.fee_escrow(),
    );
    assert!(state
        .execute_gateway(request, height, &BaseVerifier, &BlochVerifier)
        .is_err());
    assert_eq!(
        (
            state.state_root(),
            state.base().clone(),
            state.native().snapshot(),
            state.fee_escrow()
        ),
        before
    );
}

#[test]
fn sponsored_import_and_burn_share_atomic_batch_and_restore() {
    let (anchor, import) = fixture();
    let mut state = anchor.clone();
    let receipt = state
        .execute_gateway(&import, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert!(receipt.gateway.release.is_none());
    let Operation::Import(r) = &import.gateway.operation else {
        unreachable!()
    };
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .supply(&r.transaction.asset),
        Some(AMOUNT)
    );
    assert_eq!(
        state
            .native()
            .gateway()
            .route(&r.deposit.route)
            .unwrap()
            .imported,
        AMOUNT as u128
    );
    let burn = withdrawal(&state, &import, &receipt);
    // Fresh sponsor funding must not bypass the source-event replay record.
    let mut replay = import.clone();
    if let PosTransaction::TransferV2 { inputs, .. } = &mut replay.blch {
        inputs[0].txid = receipt.blch_txid;
    }
    let PosTransaction::TransferV2 { outputs, .. } = &import.blch else {
        unreachable!()
    };
    fund_and_sign(&state, &mut replay, outputs[0].value);
    assert!(matches!(
        state.execute_gateway(&replay, 4, &BaseVerifier, &BlochVerifier),
        Err(bloch_pos_committee::transition::native_dex::Error::Native(
            gateway::pools::Error::Gateway(gateway::Error::Replay)
        ))
    ));
    let burned = state
        .execute_gateway(&burn, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(burned.gateway.release.as_ref().unwrap().amount, AMOUNT);
    assert_eq!(
        state
            .native()
            .gateway()
            .native()
            .supply(&r.transaction.asset),
        Some(0)
    );
    let frames = [
        import.canonical_bytes(&DOMAIN).unwrap(),
        burn.canonical_bytes(&DOMAIN).unwrap(),
    ];
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    let candidate =
        pool_candidate::build(&anchor, 4, &refs, &BaseVerifier, &BlochVerifier).unwrap();
    let mut batched = anchor.clone();
    let result =
        pool_candidate::apply(&mut batched, &candidate, 4, &BaseVerifier, &BlochVerifier).unwrap();
    assert_eq!(result.post_root, state.state_root());
    assert_eq!(
        result.charge.base_fee_sat,
        receipt.charge.base_fee_sat + burned.charge.base_fee_sat
    );
    assert_eq!(
        state.fee_escrow(),
        (result.charge.base_fee_sat, result.charge.priority_fee_sat)
    );
    let mut restored =
        State::restore(state.snapshot(), state.state_root(), &BlochVerifier).unwrap();
    reject_unchanged(&mut restored, &import, 4);
    reject_unchanged(&mut restored, &burn, 4);
    let mut replay_burn = burn.clone();
    if let PosTransaction::TransferV2 { inputs, .. } = &mut replay_burn.blch {
        inputs[0].txid = burned.blch_txid;
    }
    let PosTransaction::TransferV2 { outputs, .. } = &burn.blch else {
        unreachable!()
    };
    fund_and_sign(&restored, &mut replay_burn, outputs[0].value);
    reject_unchanged(&mut restored, &replay_burn, 4);
    // A bad second operation rolls back even the first import and its BLCH fees.
    let mut forged = burn.clone();
    forged.gateway.approvals[0][crypto::SUITE_HEADER_LEN] ^= 1;
    let bad = forged.canonical_bytes(&DOMAIN).unwrap();
    let mut rollback = anchor.clone();
    assert!(pool_batch::apply(
        &mut rollback,
        &anchor.state_root(),
        4,
        &[&frames[0], &bad],
        &BaseVerifier,
        &BlochVerifier
    )
    .is_err());
    assert_eq!(rollback.state_root(), anchor.state_root());
    #[cfg(feature = "native-dex-host")]
    durable_roundtrip(anchor, &frames, state.state_root());
}

#[test]
fn malformed_transport_and_each_authority_failure_preserve_both_ledgers() {
    let (mut state, request) = fixture();
    let frame = request.canonical_bytes(&DOMAIN).unwrap();
    assert_eq!(
        pool_wire::encode(&pool_wire::decode(&frame, &DOMAIN).unwrap(), &DOMAIN).unwrap(),
        frame
    );
    for end in 0..frame.len() {
        assert!(joint::decode(&frame[..end], &DOMAIN).is_err());
    }
    for offset in [0, 8, 10, 58] {
        let mut bad = frame.clone();
        bad[offset] ^= 255;
        assert!(joint::decode(&bad, &DOMAIN).is_err());
    }
    let mut extra = frame.clone();
    extra.push(0);
    assert!(joint::decode(&extra, &DOMAIN).is_err());
    for index in 0..4 {
        let mut bad = request.clone();
        match index {
            0 => {
                if let PosTransaction::TransferV2 { keys, .. } = &mut bad.blch {
                    keys[0].signature[crypto::SUITE_HEADER_LEN] ^= 1;
                }
            }
            1 => bad.gateway.witnesses.modules = vec![vec![Val::Bytes(vec![0; 5500])]],
            2 => bad.gateway.approvals[0][crypto::SUITE_HEADER_LEN] ^= 1,
            _ => {
                bad.gateway.approvals[1][crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1] ^= 1
            }
        }
        reject_unchanged(&mut state, &bad, 4);
    }
    reject_unchanged(&mut state, &request, 101);
    let mut bad = request.clone();
    bad.native_gas = 1;
    fund_and_sign(&state, &mut bad, COIN);
    reject_unchanged(&mut state, &bad, 4);
    let mut bad = request.clone();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut bad.blch {
        outputs[0].value += 1;
    }
    resign(&mut bad);
    reject_unchanged(&mut state, &bad, 4);
    // A valid standalone certificate is not a joint sponsor authorization.
    let Operation::Import(r) = &request.gateway.operation else {
        unreachable!()
    };
    let standalone = r.signing_hash(&DOMAIN).unwrap();
    let mut bad = request.clone();
    bad.gateway.witnesses.modules = vec![vec![Val::Bytes(sign(1, &standalone))]];
    bad.gateway.approvals = vec![sign(3, &standalone), sign(4, &standalone)];
    reject_unchanged(&mut state, &bad, 4);
    let receipt = state
        .execute_gateway(&request, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let burn = withdrawal(&state, &request, &receipt);
    let mut bad = burn.clone();
    bad.gateway.witnesses.owners[0][crypto::SUITE_HEADER_LEN] ^= 1;
    reject_unchanged(&mut state, &bad, 4);
    let mut bad = burn.clone();
    if let Operation::Withdraw(r) = &mut bad.gateway.operation {
        r.recipient[0] ^= 1;
    }
    reject_unchanged(&mut state, &bad, 4);
    state
        .execute_gateway(&burn, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
}

#[cfg(feature = "native-dex-host")]
fn durable_roundtrip(anchor: State, frames: &[Vec<u8>], expected: [u8; 32]) {
    use bloch_ustav::{
        dex_admission::PendingBatch,
        dex_journal::{Checkpoint, Error as JournalError, Journal, TailRecovery},
    };
    let path = std::env::temp_dir().join(format!(
        "bloch-joint-gateway-{}-{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut journal = Journal::create(&path, anchor.clone(), 3).unwrap();
    let mut pending = PendingBatch::new(&journal, 4).unwrap();
    let request = joint::decode(&frames[0], &DOMAIN).unwrap();
    let Operation::Import(import) = &request.gateway.operation else {
        unreachable!()
    };
    let route = import.deposit.route;
    let original_head = journal.checkpoint();
    for frame in frames {
        pending.admit(&journal, frame, 4).unwrap();
    }
    // An admitted preview must not appear among locally committed records.
    let view = journal.state().native().gateway();
    assert!(view.import_record(&route, 0).is_none());
    assert!(view.release_record(&route, 0).is_none());
    assert!(view.releases_after(&route, None, 1).unwrap().is_empty());
    assert!(journal
        .release_page(original_head, &route, None, 1)
        .unwrap()
        .records()
        .is_empty());
    assert_eq!(journal.state().state_root(), anchor.state_root());
    assert_eq!(pending.commit(&mut journal, 4).unwrap().post_root, expected);
    let view = journal.state().native().gateway();
    let deposit = view.import_record(&route, 0).unwrap().clone();
    assert_eq!(deposit.deposit, import.deposit);
    assert_eq!(deposit.source_transaction, import.source_transaction);
    let release = view.release_record(&route, 0).unwrap().clone();
    assert_eq!(release.amount, AMOUNT);
    assert_eq!(
        view.releases_after(&route, None, 1).unwrap(),
        vec![&release]
    );
    assert!(view.releases_after(&route, Some(0), 1).unwrap().is_empty());
    let head = journal.checkpoint();
    let bytes_before_queries = std::fs::read(&path).unwrap();
    for stale in [
        original_head,
        Checkpoint {
            height: head.height - 1,
            ..head
        },
        Checkpoint {
            root: [0; 32],
            ..head
        },
    ] {
        assert!(matches!(
            journal.release_page(stale, &route, None, 1),
            Err(JournalError::WrongHead)
        ));
    }
    let page = journal.release_page(head, &route, None, 1).unwrap();
    assert_eq!(page.checkpoint(), head);
    assert_eq!(page.route(), &route);
    assert_eq!(page.records(), &[&release]);
    assert_eq!(page.next_after(), Some(0));
    let next = journal
        .release_page(head, &route, page.next_after(), 1)
        .unwrap();
    assert!(next.records().is_empty());
    assert_eq!(next.next_after(), None);
    assert!(journal
        .release_page(head, &route, Some(u64::MAX), 1)
        .unwrap()
        .records()
        .is_empty());
    for limit in [0, 129, usize::MAX] {
        assert!(matches!(
            journal.release_page(head, &route, None, limit),
            Err(JournalError::Gateway(gateway::Error::ResourceLimit))
        ));
    }
    assert!(matches!(
        journal.release_page(head, &[0; 32], None, 1),
        Err(JournalError::Gateway(gateway::Error::UnknownRoute))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before_queries);
    drop(journal);
    let reopened = Journal::open(&path, anchor, 3, head, TailRecovery::Reject).unwrap();
    assert_eq!(reopened.state().state_root(), expected);
    let view = reopened.state().native().gateway();
    assert_eq!(view.import_record(&route, 0), Some(&deposit));
    assert_eq!(view.release_record(&route, 0), Some(&release));
    assert_eq!(
        view.releases_after(&route, None, 128).unwrap(),
        vec![&release]
    );
    assert!(view.import_record(&route, 1).is_none());
    assert!(view.release_record(&route, 1).is_none());
    assert_eq!(reopened.checkpoint(), head);
    let page = reopened.release_page(head, &route, None, 1).unwrap();
    assert_eq!(page.records(), &[&release]);
    assert_eq!(page.checkpoint(), head);
    assert_eq!(page.next_after(), Some(0));
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn bridge_import_liquidity_independent_trade_and_redemption_survive_restart() {
    use bloch_euvm::ustav::transfer_wire;
    use bloch_pos_committee::transition::native_dex::{base_reserves, paired_custody, Error};
    let (mut state, mut import) = fixture();
    if let Operation::Import(r) = &mut import.gateway.operation {
        r.transaction.outputs[0].owner = keys()[0].0.clone();
        r.deposit.pq_recipient_hash = gateway::recipient_hash(&keys()[0].0);
    }
    fund_and_sign(&state, &mut import, COIN);
    let anchor = state.clone();
    let imported = state
        .execute_gateway(&import, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let Operation::Import(r) = &import.gateway.operation else {
        unreachable!()
    };
    let id = base_reserves::reserve_id(&DOMAIN, &[18; 32], &keys()[0].0).unwrap();
    let mut pair = paired_custody::Request {
        blch: sponsor(),
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                inputs: imported.gateway.receipt.outputs.clone(),
                delta: 0,
                ..r.transaction.clone()
            },
            witnesses: Witnesses {
                owners: vec![vec![0; 5500]],
                modules: vec![vec![]],
                ..Witnesses::default()
            },
        },
        seed: [18; 32],
        blch_amount: 1_000_000,
        native_amount: AMOUNT,
        valid_until: 100,
        native_gas: 100_000,
    };
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = &mut pair.blch
    {
        inputs[0].txid = imported.blch_txid;
        outputs.insert(
            0,
            TransferOutput {
                value: pair.blch_amount,
                script_hash: base_reserves::reserve_script(&DOMAIN, &id),
            },
        );
    }
    let size = pair.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut pair.blch {
        *tx_bytes = size + 256;
    }
    let charge = state.quote_paired_custody(&pair).unwrap();
    let PosTransaction::TransferV2 { outputs, .. } = &import.blch else {
        unreachable!()
    };
    let funds = outputs[0].value;
    if let PosTransaction::TransferV2 { outputs, .. } = &mut pair.blch {
        outputs[1].value =
            funds - pair.blch_amount - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
    }
    let message = pair.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut pair.blch {
        keys[0].signature = sign(0, &message);
    }
    pair.native.witnesses.owners[0] = sign(0, &message);
    let created = state
        .execute_paired_custody(&pair, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let frames = [
        import.canonical_bytes(&DOMAIN).unwrap(),
        pair.canonical_bytes(&DOMAIN).unwrap(),
    ];
    let mut batched = anchor.clone();
    pool_batch::apply(
        &mut batched,
        &anchor.state_root(),
        4,
        &[&frames[0], &frames[1]],
        &BaseVerifier,
        &BlochVerifier,
    )
    .unwrap();
    assert_eq!(batched.state_root(), state.state_root());
    let mut burn = withdrawal(&state, &import, &imported);
    if let Operation::Withdraw(r) = &mut burn.gateway.operation {
        r.transaction.inputs = created.native.outputs.clone();
    }
    if let PosTransaction::TransferV2 { inputs, .. } = &mut burn.blch {
        inputs[0].txid = created.blch_txid;
        inputs[0].vout = 1;
    }
    let PosTransaction::TransferV2 { outputs, .. } = &pair.blch else {
        unreachable!()
    };
    fund_and_sign(&state, &mut burn, outputs[1].value);
    let message = burn.authorization(&DOMAIN).unwrap();
    burn.gateway.witnesses.owners[0] = sign(0, &message);
    let root = state.state_root();
    assert!(matches!(
        state.execute_gateway(&burn, 4, &BaseVerifier, &BlochVerifier),
        Err(Error::LockedReserve)
    ));
    assert_eq!(state.state_root(), root);
    let mut restored = State::restore(state.snapshot(), root, &BlochVerifier).unwrap();
    assert!(matches!(
        restored.execute_gateway(&burn, 4, &BaseVerifier, &BlochVerifier),
        Err(Error::LockedReserve)
    ));
    assert_eq!(restored.state_root(), root);
    complete_market_roundtrip(anchor, state, import, pair, created);
}

#[path = "support/bridge_market_roundtrip.rs"]
mod market_roundtrip;
use market_roundtrip::complete_market_roundtrip;

#[test]
fn gateway_funding_review_binds_real_sponsor_and_import_certificate_deadline() {
    use bloch_pos_committee::transition::native_dex::pool_review::{Error, FundingReview};
    let (mut state, import) = fixture();
    let payer = &keys()[0].0;
    let bytes = import.canonical_bytes(&DOMAIN).unwrap();
    let before = state.state_root();
    assert!(matches!(
        FundingReview::prepare(&state, &bytes, &keys()[1].0, 4),
        Err(Error::UnsupportedPayer)
    ));
    let review = FundingReview::prepare(&state, &bytes, payer, 4).unwrap();
    assert_eq!(review.funding_sats(), u128::from(COIN));
    let fee = *review.charge();
    let checked = review.finish(&state, payer, 4, &bytes).unwrap();
    assert_eq!(
        checked.authorization(),
        import.authorization(&DOMAIN).unwrap()
    );
    assert_eq!(state.state_root(), before);
    let receipt = state
        .execute_gateway(&import, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(receipt.charge, fee);
    let burn = withdrawal(&state, &import, &receipt);
    let bytes = burn.canonical_bytes(&DOMAIN).unwrap();
    let review = FundingReview::prepare(&state, &bytes, payer, 5).unwrap();
    let fee = *review.charge();
    review.finish(&state, payer, 5, &bytes).unwrap();
    let receipt = state
        .execute_gateway(&burn, 5, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(receipt.charge, fee);

    let (state, mut import) = fixture();
    let Operation::Import(r) = &mut import.gateway.operation else {
        unreachable!()
    };
    r.valid_until = 3;
    let bytes = import.canonical_bytes(&DOMAIN).unwrap();
    assert_eq!(
        FundingReview::prepare(&state, &bytes, payer, 3)
            .unwrap()
            .valid_until(),
        3
    );
    assert!(matches!(
        FundingReview::prepare(&state, &bytes, payer, 4),
        Err(Error::Expired)
    ));
    let Operation::Import(r) = &mut import.gateway.operation else {
        unreachable!()
    };
    r.valid_until = import.valid_until + 1;
    let bytes = import.canonical_bytes(&DOMAIN).unwrap();
    assert!(matches!(
        FundingReview::prepare(&state, &bytes, payer, 1),
        Err(Error::InvalidExpiry)
    ));
}
