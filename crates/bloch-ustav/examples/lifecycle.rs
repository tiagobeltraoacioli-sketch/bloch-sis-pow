//! Local reference flow with fresh ephemeral keys. No network or disk writes.
use bloch_crypto::crypto;
use bloch_euvm::modules::{ModuleKind, SupplyConfig, TokenCharter};
use bloch_euvm::Val;
use bloch_ustav::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let domain = [42; 32]; // Demo only: the host must use its authenticated network domain.
    let gas = 10_000_000;
    let (issuer, issuer_secret) = crypto::generate_keypair();
    let (recipient, recipient_secret) = crypto::generate_keypair();
    let sign_issuer = |hash: &[u8]| crypto::sign(&issuer_secret, hash).expect("issuer signature");
    let registration = Registration {
        charter: TokenCharter {
            token_name: b"USTAV-DEMO".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: issuer.clone(),
            })],
        },
        nonce: [1; 32],
        initial_kyc_root: None,
    };
    let mut ledger = Ledger::new(domain);
    let asset = ledger
        .register(
            registration.clone(),
            &sign_issuer(&registration.signing_hash(&domain).unwrap()),
            &BlochVerifier,
            gas,
        )
        .expect("register");
    let mint = Transaction {
        asset,
        inputs: vec![],
        outputs: vec![Output {
            owner: issuer,
            amount: 60,
        }],
        delta: 60,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let mint_w = Witnesses {
        modules: vec![vec![Val::Bytes(sign_issuer(
            &mint.signing_hash(&domain).unwrap(),
        ))]],
        ..Witnesses::default()
    };
    let minted = ledger
        .apply(&mint, &mint_w, 1, &BlochVerifier, gas)
        .expect("mint");
    let transfer = Transaction {
        inputs: minted.outputs,
        outputs: vec![Output {
            owner: recipient,
            amount: 60,
        }],
        delta: 0,
        ..mint
    };
    let transfer_w = Witnesses {
        owners: vec![sign_issuer(&transfer.signing_hash(&domain).unwrap())],
        modules: vec![vec![]],
        ..Witnesses::default()
    };
    let transferred = ledger
        .apply(&transfer, &transfer_w, 2, &BlochVerifier, gas)
        .expect("transfer");
    assert_eq!(
        ledger.apply(&transfer, &transfer_w, 2, &BlochVerifier, gas),
        Err(Error::MissingInput)
    );
    let root = ledger.state_root();
    // In a node, this root must come from independently authenticated consensus.
    let mut restored = Ledger::restore(ledger.snapshot(), root, &BlochVerifier).expect("restore");
    let burn = Transaction {
        inputs: transferred.outputs,
        outputs: vec![],
        delta: -60,
        ..transfer
    };
    let message = burn.signing_hash(&domain).unwrap();
    let burn_w = Witnesses {
        owners: vec![crypto::sign(&recipient_secret, &message).unwrap()],
        modules: vec![vec![Val::Bytes(sign_issuer(&message))]],
        ..Witnesses::default()
    };
    let burned = restored
        .apply(&burn, &burn_w, 3, &BlochVerifier, gas)
        .expect("burn");
    println!("asset={}", hex(&asset));
    println!(
        "mint_supply={} transfer_supply={} final_supply={}",
        minted.supply, transferred.supply, burned.supply
    );
    println!("spent-input replay rejected; authenticated snapshot restored");
    println!("final_state_root={}", hex(&restored.state_root()));
}
