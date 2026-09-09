// SPDX-License-Identifier: AGPL-3.0-or-later
//! The public offline workflow, through the actual binary with sealed keys.
use bloch_pos_committee::transition::PosTransaction;
use std::{
    path::Path,
    process::{Command, Output},
};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .args(args)
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FILE")
        .env_remove("BLOCH_KEYSTORE_ALLOW_PLAINTEXT")
        .env(
            "BLOCH_KEYSTORE_PASSPHRASE",
            "ephemeral admission test passphrase",
        )
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    s.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn sealed_offline_roles_prepare_sign_inspect_and_refuse_overwrite() {
    let dir =
        Temp(std::env::temp_dir().join(format!("bloch-admission-cli-{}", std::process::id())));
    std::fs::create_dir(&dir.0).unwrap();
    let funding = dir.0.join("funding");
    let joining = dir.0.join("joining");
    ok(&["keygen", "--dir", path(&funding), "--index", "0"]);
    ok(&["keygen", "--dir", path(&joining), "--index", "auto"]);
    assert!(std::fs::read(joining.join("validator.key"))
        .unwrap()
        .starts_with(b"BPOSKEY2"));
    let public = |dir: &Path| -> Vec<String> {
        ok(&["keygen-public", "--dir", path(dir)])
            .trim()
            .split('\t')
            .map(String::from)
            .collect()
    };
    let f = public(&funding);
    let j = public(&joining);
    assert_eq!(j[0], u32::MAX.to_string());
    let fpk = dir.0.join("funding.pub");
    let jpk = dir.0.join("joining.pub");
    std::fs::write(&fpk, &f[1]).unwrap();
    std::fs::write(&jpk, &j[1]).unwrap();
    let genesis = dir.0.join("genesis.bin");
    ok(&["genesis", "--keys", path(&funding), "--out", path(&genesis)]);
    let draft = dir.0.join("draft.hex");
    let input = format!("{}:0:3000000000000", hex(&[0x73; 32]));
    let withdrawal = hex(&[0x81; 32]);
    let change = hex(&[0x82; 32]);
    ok(&[
        "validator-deposit",
        "prepare",
        "--genesis",
        path(&genesis),
        "--funding-pubkey",
        path(&fpk),
        "--validator-pubkey",
        path(&jpk),
        "--randao",
        &j[2],
        "--withdrawal",
        &withdrawal,
        "--change",
        &change,
        "--stake",
        "2500000000000",
        "--input",
        &input,
        "--max-base-fee",
        "100",
        "--tip",
        "5",
        "--expiry",
        "20",
        "--commission",
        "500",
        "--out",
        path(&draft),
    ]);
    let inspect = ok(&["validator-deposit", "inspect", "--tx", path(&draft)]);
    assert!(inspect.contains(&withdrawal));
    assert!(inspect.contains(&change));
    assert!(inspect.contains("Stake (sat): 2500000000000"));
    let signed = dir.0.join("funded.hex");
    let ready = dir.0.join("ready.hex");
    assert!(!invoke(&[
        "validator-deposit",
        "sign",
        "--genesis",
        path(&genesis),
        "--tx",
        path(&draft),
        "--role",
        "validator",
        "--dir",
        path(&funding),
        "--out",
        path(&signed)
    ])
    .status
    .success());
    assert!(!signed.exists());
    ok(&[
        "validator-deposit",
        "sign",
        "--genesis",
        path(&genesis),
        "--tx",
        path(&draft),
        "--role",
        "funding",
        "--dir",
        path(&funding),
        "--out",
        path(&signed),
    ]);
    ok(&[
        "validator-deposit",
        "sign",
        "--genesis",
        path(&genesis),
        "--tx",
        path(&signed),
        "--role",
        "validator",
        "--dir",
        path(&joining),
        "--out",
        path(&ready),
    ]);
    let decode = |file: &Path| {
        PosTransaction::from_canonical_bytes(&unhex(&std::fs::read_to_string(file).unwrap()))
            .unwrap()
    };
    let unsigned = decode(&draft);
    let complete = decode(&ready);
    assert_eq!(unsigned.txid(), complete.txid());
    let PosTransaction::FundedDeposit(tx) = complete else {
        panic!("wrong transaction kind")
    };
    assert!(bloch_crypto::crypto::verify(
        &tx.funding_pubkey,
        &tx.funding_root(),
        &tx.funding_signature
    ));
    assert!(bloch_crypto::crypto::verify(
        &tx.validator_pubkey,
        &tx.possession_root(),
        &tx.proof_of_possession
    ));
    // A signer's own manifest is checked before its keystore is opened.
    let other_genesis = dir.0.join("other-genesis.bin");
    ok(&["genesis", "--keys", path(&funding), "--out", path(&other_genesis), "--slot-ms", "1234"]);
    let refused = invoke(&["validator-deposit", "sign", "--genesis", path(&other_genesis),
        "--tx", path(&draft), "--role", "funding", "--dir", "missing-keystore",
        "--out", path(&dir.0.join("wrong-network.hex"))]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("trusted genesis manifest"));

    let exit_file = dir.0.join("exit.hex");
    ok(&["validator-lifecycle", "exit", "--dir", path(&joining), "--epoch", "7", "--out", path(&exit_file)]);
    let PosTransaction::ExitV2 { pubkey_hash, epoch, signature } = decode(&exit_file) else { panic!("expected ExitV2"); };
    assert_eq!(epoch, 7);
    let root = bloch_pos_committee::staking::ExitTx { pubkey_hash, epoch, signature: Vec::new() }.signing_root();
    assert!(bloch_crypto::crypto::verify(&unhex(&j[1]), &root, &signature));
    let withdraw_file = dir.0.join("withdraw.hex");
    ok(&["validator-lifecycle", "withdraw", "--validator", "71", "--out", path(&withdraw_file)]);
    assert_eq!(decode(&withdraw_file), PosTransaction::Withdraw { validator: 71 });
    assert!(!invoke(&["validator-lifecycle", "withdraw", "--validator", "71", "--out", path(&withdraw_file)]).status.success());

    let saved = std::fs::read(&ready).unwrap();
    assert!(!invoke(&[
        "validator-deposit",
        "sign",
        "--genesis",
        path(&genesis),
        "--tx",
        path(&signed),
        "--role",
        "validator",
        "--dir",
        path(&joining),
        "--out",
        path(&ready)
    ])
    .status
    .success());
    assert_eq!(saved, std::fs::read(&ready).unwrap());
}
