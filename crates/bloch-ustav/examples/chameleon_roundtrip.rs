//! Local Rust -> EVM -> Rust interoperability regression with real PQ signatures.
//! All keys are fresh and ephemeral. No RPC, live deployment, or real funds.
//! The frozen export root and EVM burn checkpoint are explicitly trusted test
//! inputs; this example is NOT a finality verifier or a production bridge CLI.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::Val;
use bloch_ustav::chameleon::{wire, *};
use bloch_ustav::{BlochVerifier, OutPoint, Output, Registration, Transaction, Witnesses};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{env, fs, path::Path, process::Command};

const DOMAIN: [u8; 32] = [42; 32];
const GAS: u64 = 10_000_000;
fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn hash(value: &Value) -> [u8; 32] {
    let text = value
        .as_str()
        .expect("hex string")
        .strip_prefix("0x")
        .expect("hex prefix");
    assert_eq!(text.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex byte"))
}
fn evm(bridge: &Path, input: &Path, output: &Path, fixture: &Value) -> Value {
    fs::write(input, serde_json::to_string_pretty(fixture).unwrap()).unwrap();
    if output.exists() {
        fs::remove_file(output).unwrap();
    } // Never accept stale output.
    let result = Command::new(env::var("FORGE").unwrap_or_else(|_| "forge".into()))
        .current_dir(bridge)
        .args([
            "test",
            "--use",
            &env::var("SOLC").unwrap_or_else(|_| "0.8.24".into()),
            "--match-contract",
            "ChameleonRoundTripTest",
            "--match-test",
            "testNativeRoundTripFixture",
            "-vv",
        ])
        .env("CHAMELEON_ROUNDTRIP_INPUT", input)
        .env("CHAMELEON_ROUNDTRIP_OUTPUT", output)
        .output()
        .expect("execute Forge; set FORGE and SOLC to pinned executable paths");
    print!("{}", String::from_utf8_lossy(&result.stdout));
    assert!(
        result.status.success(),
        "EVM test failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_str(&fs::read_to_string(output).expect("fresh EVM result")).unwrap()
}

fn main() {
    let bridge = env::args()
        .nth(1)
        .expect("Usage: chameleon_roundtrip /path/to/bloch-l2-bridge");
    let bridge = fs::canonicalize(bridge).expect("bridge checkout");
    let (issuer, issuer_secret) = crypto::generate_keypair();
    let (recipient, recipient_secret) = crypto::generate_keypair();
    let sign = |message: &[u8]| crypto::sign(&issuer_secret, message).unwrap();
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"CHAMELEON-LOCAL-TEST".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: issuer.clone(),
            })],
        },
        nonce: [7; 32],
        initial_kyc_root: None,
    };
    let mut ledger = ChameleonLedger::new(DOMAIN);
    let asset = ledger
        .register(
            registration.clone(),
            &sign(&registration.signing_hash(&DOMAIN).unwrap()),
            &BlochVerifier,
            GAS,
        )
        .unwrap();
    // CREATE address depends on deployer/nonce, not constructor bytes. This
    // avoids a circular dependency between export root and token deployment.
    let mut rlp = vec![0xd6, 0x94];
    rlp.extend_from_slice(&[0x11; 20]);
    rlp.push(1);
    let address_hash = Keccak256::digest(&rlp);
    let mut adapter = [0; 20];
    adapter.copy_from_slice(&address_hash[12..]);
    let mut route = EvmRoute {
        origin_domain: DOMAIN,
        asset,
        chain_id: 31337,
        adapter,
        decimals: 8,
        cap: 1000,
        adapter_code_hash: [1; 32],
    };
    let mint = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: issuer,
            amount: 100,
        }],
        delta: 100,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let request = ExportRequest {
        route: route.id(),
        expected_nonce: 0,
        recipient: [0xaa; 20],
        lock_output: 0,
        transaction: Transaction {
            inputs: vec![OutPoint {
                transaction: mint.signing_hash(&DOMAIN).unwrap(),
                index: 0,
            }],
            delta: 0,
            ..mint.clone()
        },
    };
    let prepared = Export {
        route: route.id(),
        nonce: 0,
        recipient: request.recipient,
        amount: 100,
        native_transaction: request.transaction.signing_hash(&DOMAIN).unwrap(),
    };
    let (prepared_root, prepared_proof) = wire::root_and_proof(&[prepared.id()], Some(0)).unwrap();
    let directory = bridge.join("out/chameleon-roundtrip").join(hex(&asset));
    fs::create_dir_all(&directory).unwrap();
    let input = directory.join("input.json");
    let output = directory.join("output.json");
    let mut fixture = json!({"phase": 0, "origin": hex(&DOMAIN), "asset": hex(&asset),
        "route_id": hex(&route.id()), "export_id": hex(&prepared.id()), "export_root": hex(&prepared_root),
        "export_branch": prepared_proof.unwrap().siblings.iter().map(|b| hex(b)).collect::<Vec<_>>(),
        "native_transaction": hex(&prepared.native_transaction), "pq_recipient_hash": hex(&wire::sha256(&recipient))});
    // Stage 0 deploys only, obtaining actual immutable runtime identity before
    // native route enablement and issuance. It cannot mint a representation.
    let deployment = evm(&bridge, &input, &output, &fixture);
    route.adapter_code_hash = hash(&deployment["adapter_code_hash"]);
    assert_eq!(hash(&deployment["route_id"]), route.id());
    ledger
        .enable(
            route.clone(),
            &sign(&route.enable_hash()),
            &BlochVerifier,
            GAS,
        )
        .unwrap();
    let mint_w = Witnesses {
        modules: vec![vec![Val::Bytes(sign(&mint.signing_hash(&DOMAIN).unwrap()))]],
        ..Witnesses::default()
    };
    ledger
        .apply(&mint, &mint_w, 1, &BlochVerifier, GAS)
        .unwrap();
    let export_w = Witnesses {
        owners: vec![sign(&request.signing_hash(&DOMAIN).unwrap())],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    // A native-transfer signature cannot authorize an export.
    let mut ordinary = export_w.clone();
    ordinary.owners[0] = sign(&request.transaction.signing_hash(&DOMAIN).unwrap());
    let before = ledger.state_root();
    assert!(ledger
        .export(&request, &ordinary, 2, &BlochVerifier, GAS)
        .is_err());
    assert_eq!(before, ledger.state_root());
    let (record, _) = ledger
        .export(&request, &export_w, 2, &BlochVerifier, GAS)
        .unwrap();
    assert_eq!(record, prepared);
    assert_eq!(ledger.export_root(), (prepared_root, 1));
    fixture["phase"] = json!(1);
    fixture["adapter_code_hash"] = json!(hex(&route.adapter_code_hash));
    let destination = evm(&bridge, &input, &output, &fixture);
    assert_eq!(
        hash(&destination["adapter_code_hash"]),
        route.adapter_code_hash
    );
    assert_eq!(hash(&destination["route_id"]), route.id());
    let burn = Burn {
        route: route.id(),
        nonce: 0,
        sender: [0xbb; 20],
        amount: 25,
        pq_recipient_hash: wire::sha256(&recipient),
    };
    assert_eq!(hash(&destination["burn_id"]), burn.id());
    assert_eq!(destination["burn_count"], 1);
    let (_, proof) = wire::root_and_proof(&[burn.id()], Some(0)).unwrap();
    let proof = proof.unwrap();
    let checkpoint = TrustedBurnCheckpoint {
        route: route.id(),
        adapter_code_hash: route.adapter_code_hash,
        // Explicit local test marker, NOT a real or finalized Ethereum block.
        block_hash: wire::sha256(b"LOCAL-EVM-FIXTURE-NOT-FINALITY"),
        root: hash(&destination["burn_root"]),
        leaf_count: 1,
    };
    assert!(wire::verify_inclusion(
        &burn.id(),
        &proof,
        &checkpoint.root,
        1
    ));
    let claim = ReturnClaim {
        burn,
        pq_recipient: recipient,
        escrow_inputs: ledger.escrow_inputs(&route.id()),
        valid_until: 100,
    };
    let message = claim.signing_hash(&DOMAIN).unwrap();
    let sig = crypto::sign(&recipient_secret, &message).unwrap();
    let before = ledger.state_root();
    for offset in [
        crypto::SUITE_HEADER_LEN,
        crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + 1,
    ] {
        let mut bad = sig.clone();
        bad[offset] ^= 1;
        assert!(ledger
            .claim(&claim, &proof, &checkpoint, &bad, 3, &BlochVerifier, GAS)
            .is_err());
        assert_eq!(ledger.state_root(), before);
    }
    let released = ledger
        .claim(&claim, &proof, &checkpoint, &sig, 3, &BlochVerifier, GAS)
        .unwrap();
    assert_eq!(ledger.native().output(&released).unwrap().output.amount, 25);
    assert_eq!(ledger.route(&route.id()).unwrap().locked, 75);
    assert_eq!(destination["evm_supply"], 75);
    assert_eq!(ledger.native().supply(&asset), Some(100));
    let mut restored =
        ChameleonLedger::restore(ledger.snapshot(), ledger.state_root(), &BlochVerifier).unwrap();
    assert_eq!(
        restored.claim(&claim, &proof, &checkpoint, &sig, 4, &BlochVerifier, GAS),
        Err(Error::AlreadyClaimed)
    );
    println!("PQ native export -> ERC-20 mint/allowance/transfer/burn -> PQ native claim: PASS");
    println!("Native supply=100, native released=25, locked backing=75, EVM supply=75");
    println!("Both PQ signature legs and replay after authenticated restore: PASS");
    println!(
        "LOCAL ONLY: checkpoint authentication is trusted; no live bridge or finality verification"
    );
    println!("Public test fixtures: {}", directory.display());
}
