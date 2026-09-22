// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real CLI, disposable sealed keys and consensus wire/crypto verification.
//! No node or production identity is contacted by these tests.
use bloch_pos_committee::{
    fee_market::{self, TxClass},
    transition::PosTransaction,
};
use sha3::{Digest, Sha3_256};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    s.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn path(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}
fn invoke(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .args(args)
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FILE")
        .env_remove("BLOCH_KEYSTORE_ALLOW_PLAINTEXT")
        .env(
            "BLOCH_KEYSTORE_PASSPHRASE",
            "disposable payout CLI test passphrase",
        )
        .output()
        .unwrap()
}
fn ok(args: &[String]) -> String {
    let r = invoke(args);
    assert!(
        r.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    String::from_utf8(r.stdout).unwrap()
}
fn decode(p: &Path) -> PosTransaction {
    PosTransaction::from_canonical_bytes(&unhex(&std::fs::read_to_string(p).unwrap())).unwrap()
}
struct Fixture {
    root: PathBuf,
    keys: PathBuf,
    pubkey: Vec<u8>,
    common: Vec<String>,
    draft: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "bloch-payout-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let keys = root.join("withdrawal");
        ok(&[
            "keygen".into(),
            "--dir".into(),
            path(&keys),
            "--index".into(),
            "auto".into(),
        ]);
        assert!(std::fs::read(keys.join("validator.key"))
            .unwrap()
            .starts_with(b"BPOSKEY2"));
        let public = ok(&["keygen-public".into(), "--dir".into(), path(&keys)]);
        let pubkey = unhex(public.split('\t').nth(1).unwrap());
        std::fs::write(root.join("public.hex"), hex(&pubkey)).unwrap();
        let common = vec![
            "--validator".into(),
            "71".into(),
            "--input-value".into(),
            "2500000000000".into(),
            "--withdrawal-script".into(),
            hex(&Sha3_256::digest(&pubkey)),
            "--destination".into(),
            hex(&[0x82; 32]),
            "--base-fee".into(),
            "10".into(),
            "--epoch".into(),
            "5000".into(),
            "--max-fee".into(),
            "1000000".into(),
        ];
        let draft = root.join("draft.hex");
        let f = Self {
            root,
            keys,
            pubkey,
            common,
            draft,
        };
        ok(&f.args(
            "prepare",
            &[
                "--pubkey".into(),
                path(&f.root.join("public.hex")),
                "--tip".into(),
                "5".into(),
                "--out".into(),
                path(&f.draft),
            ],
        ));
        f
    }
    fn args(&self, command: &str, extra: &[String]) -> Vec<String> {
        let mut args = vec!["validator-payout".into(), command.into()];
        args.extend(self.common.clone());
        args.extend_from_slice(extra);
        args
    }
    fn signing(&self, file: &Path, keydir: &Path, output: &Path) -> Vec<String> {
        self.args(
            "sign",
            &[
                "--tx".into(),
                path(file),
                "--dir".into(),
                path(keydir),
                "--expected-root".into(),
                hex(&decode(file).checked_signing_root(5000)),
                "--out".into(),
                path(output),
            ],
        )
    }
}
fn replace(args: &mut [String], flag: &str, value: String) {
    let i = args.iter().position(|a| a == flag).unwrap();
    args[i + 1] = value;
}

#[test]
fn sealed_payout_round_trip_matches_consensus_wire_and_fee_rules() {
    let f = Fixture::new();
    let before = std::fs::read(f.keys.join("validator.key")).unwrap();
    let unsigned = decode(&f.draft);
    let ready = f.root.join("ready.hex");
    let inspection = ok(&f.args("inspect", &["--tx".into(), path(&f.draft)]));
    assert!(inspection.contains("Signature present: false"));
    ok(&f.signing(&f.draft, &f.keys, &ready));
    let tx = decode(&ready);
    assert_eq!(tx.canonical_bytes()[0], 0x06);
    assert_eq!(tx.txid(), unsigned.txid());
    assert_eq!(
        tx.checked_signing_root(5000),
        unsigned.checked_signing_root(5000)
    );
    let PosTransaction::TransferV2 {
        keys,
        inputs,
        outputs,
        tx_bytes,
        tip_millisat_per_gas,
    } = &tx
    else {
        panic!("expected TransferV2");
    };
    assert_eq!(
        inputs[0].txid,
        PosTransaction::Withdraw { validator: 71 }.txid()
    );
    assert_eq!((inputs[0].vout, inputs[0].key_index), (0, 0));
    assert_eq!(keys[0].pubkey, f.pubkey);
    assert!(bloch_crypto::crypto::verify(
        &keys[0].pubkey,
        &tx.checked_signing_root(5000),
        &keys[0].signature
    ));
    let charge = fee_market::charge(
        TxClass::Eutxo { inputs: 1 },
        *tx_bytes,
        10,
        *tip_millisat_per_gas,
    );
    assert_eq!(
        u128::from(outputs[0].value) + charge.base_fee_sat + charge.priority_fee_sat,
        2_500_000_000_000
    );
    assert!(tx.canonical_bytes().len() as u64 <= *tx_bytes);
    assert!(*tx_bytes - tx.canonical_bytes().len() as u64 <= fee_market::HYBRID_SIG_BYTES);
    assert!(
        ok(&f.args("inspect", &["--tx".into(), path(&ready)])).contains("Signature present: true")
    );
    assert_eq!(before, std::fs::read(f.keys.join("validator.key")).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&ready).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn substituted_intent_and_invalid_fees_are_refused_before_unlock() {
    let f = Fixture::new();
    let missing = f.root.join("nonexistent-keystore");
    let output = f.root.join("must-not-exist.hex");
    for (flag, value, expected) in [
        ("--destination", hex(&[0x90; 32]), "destination"),
        (
            "--withdrawal-script",
            hex(&[0x90; 32]),
            "withdrawal credential",
        ),
        ("--validator", "72".into(), "withdrawal output"),
        ("--input-value", "2500000000001".into(), "conserve"),
        ("--base-fee", "11".into(), "conserve"),
        ("--base-fee", "0".into(), "consensus range"),
        ("--max-fee", "1".into(), "--max-fee"),
        ("--epoch", "0".into(), "must be active"),
        ("--expected-root", hex(&[0; 32]), "approved intent"),
    ] {
        let mut args = f.signing(&f.draft, &missing, &output);
        replace(&mut args, flag, value);
        let result = invoke(&args);
        assert!(!result.status.success(), "{flag}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!output.exists());
    }
    // Malformed witness tables, reservations and signatures cannot cause unlock.
    for case in 0..9 {
        let mut tx = decode(&f.draft);
        let PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            tx_bytes,
            ..
        } = &mut tx
        else {
            unreachable!()
        };
        match case {
            0 => inputs[0].key_index = 1,
            1 => inputs[0].vout = 1,
            2 => *tx_bytes += 1,
            3 => keys[0].signature = vec![0; 4593],
            4 => outputs.push(outputs[0].clone()),
            5 => keys[0].pubkey.truncate(4),
            6 => keys.clear(),
            7 => inputs.clear(),
            8 => outputs.clear(),
            _ => unreachable!(),
        }
        let file = f.root.join(format!("mutation-{case}.hex"));
        std::fs::write(&file, hex(&tx.canonical_bytes())).unwrap();
        let r = invoke(&f.signing(&file, &missing, &output));
        assert!(!r.status.success());
        assert!(!String::from_utf8_lossy(&r.stderr).contains("No such file"));
        assert!(!output.exists());
    }
}

#[test]
fn output_and_signed_artifacts_are_preserved_and_wrong_keys_refused() {
    let f = Fixture::new();
    let ready = f.root.join("ready.hex");
    ok(&f.signing(&f.draft, &f.keys, &ready));
    let original = std::fs::read(&ready).unwrap();
    assert!(
        !invoke(&f.signing(&f.draft, &f.root.join("missing"), &ready))
            .status
            .success()
    );
    assert_eq!(std::fs::read(&ready).unwrap(), original);
    let output = f.root.join("new.hex");
    let signed = invoke(&f.signing(&ready, &f.root.join("missing"), &output));
    assert!(!signed.status.success());
    assert!(String::from_utf8_lossy(&signed.stderr).contains("already signed"));
    let wrong = f.root.join("wrong-key");
    ok(&[
        "keygen".into(),
        "--dir".into(),
        path(&wrong),
        "--index".into(),
        "auto".into(),
    ]);
    let r = invoke(&f.signing(&f.draft, &wrong, &output));
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("keystore does not own"));
    assert!(!output.exists());
    let oversized = f.root.join("oversized.hex");
    std::fs::write(&oversized, "0".repeat(32769)).unwrap();
    let r = invoke(&f.args("inspect", &["--tx".into(), path(&oversized)]));
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("32768"));
    #[cfg(unix)]
    {
        let link = f.root.join("dangling-output.hex");
        std::os::unix::fs::symlink(f.root.join("absent-target"), &link).unwrap();
        assert!(!invoke(&f.signing(&f.draft, &f.keys, &link))
            .status
            .success());
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[test]
fn plaintext_opt_in_cannot_downgrade_payout_signing() {
    let f = Fixture::new();
    let output = f.root.join("no-plaintext.hex");
    let r = Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .args(f.signing(&f.draft, &f.keys, &output))
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FILE")
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE")
        .env("BLOCH_KEYSTORE_ALLOW_PLAINTEXT", "1")
        .output()
        .unwrap();
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("requires a sealed keystore"));
    assert!(!output.exists());
}

#[test]
fn malformed_arguments_formats_and_extreme_fees_fail_closed() {
    let f = Fixture::new();
    let mut duplicate = f.args("inspect", &["--tx".into(), path(&f.draft)]);
    duplicate.extend(["--validator".into(), "71".into()]);
    assert!(!invoke(&duplicate).status.success());
    let mut unknown = f.args("inspect", &["--tx".into(), path(&f.draft)]);
    unknown.extend(["--broadcast".into(), "yes".into()]);
    assert!(!invoke(&unknown).status.success());
    let output = f.root.join("extreme.hex");
    for tip in [u128::MAX, fee_market::MAX_TIP_MILLISAT_PER_GAS] {
        let r = invoke(&f.args(
            "prepare",
            &[
                "--pubkey".into(),
                path(&f.root.join("public.hex")),
                "--tip".into(),
                tip.to_string(),
                "--out".into(),
                path(&output),
            ],
        ));
        assert!(!r.status.success());
        assert!(!output.exists());
    }
    let other = f.root.join("withdraw.hex");
    std::fs::write(
        &other,
        hex(&PosTransaction::Withdraw { validator: 71 }.canonical_bytes()),
    )
    .unwrap();
    let r = invoke(&f.args("inspect", &["--tx".into(), path(&other)]));
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("wire 0x06"));
    let mut trailing = std::fs::read_to_string(&f.draft).unwrap().trim().to_owned();
    trailing.push_str("00");
    std::fs::write(&other, trailing).unwrap();
    assert!(!invoke(&f.args("inspect", &["--tx".into(), path(&other)]))
        .status
        .success());
}

#[test]
fn output_at_relay_minimum_is_allowed_but_one_satoshi_less_is_refused() {
    let f = Fixture::new();
    let original = decode(&f.draft);
    let PosTransaction::TransferV2 {
        tx_bytes,
        tip_millisat_per_gas,
        ..
    } = original
    else {
        unreachable!()
    };
    let charge = fee_market::charge(
        TxClass::Eutxo { inputs: 1 },
        tx_bytes,
        10,
        tip_millisat_per_gas,
    );
    let fee = u64::try_from(charge.base_fee_sat + charge.priority_fee_sat).unwrap();
    for remainder in [999u64, 1000] {
        let out = f.root.join(format!("minimum-{remainder}.hex"));
        let mut args = f.args(
            "prepare",
            &[
                "--pubkey".into(),
                path(&f.root.join("public.hex")),
                "--tip".into(),
                "5".into(),
                "--out".into(),
                path(&out),
            ],
        );
        replace(&mut args, "--input-value", (fee + remainder).to_string());
        let response = invoke(&args);
        if remainder == 999 {
            assert!(!response.status.success());
            assert!(String::from_utf8_lossy(&response.stderr).contains("minimum of 1000"));
            assert!(!out.exists());
        } else {
            assert!(
                response.status.success(),
                "{}",
                String::from_utf8_lossy(&response.stderr)
            );
            let PosTransaction::TransferV2 { outputs, .. } = decode(&out) else {
                unreachable!()
            };
            assert_eq!(outputs[0].value, 1000);
        }
    }
    let mut modified = decode(&f.draft);
    if let PosTransaction::TransferV2 { outputs, .. } = &mut modified {
        outputs[0].value = 999;
    }
    let dusty = f.root.join("dusty-draft.hex");
    std::fs::write(&dusty, hex(&modified.canonical_bytes())).unwrap();
    let out = f.root.join("must-not-sign.hex");
    let mut args = f.signing(&dusty, &f.root.join("missing-keystore"), &out);
    replace(&mut args, "--input-value", (fee + 999).to_string());
    let response = invoke(&args);
    assert!(!response.status.success());
    assert!(String::from_utf8_lossy(&response.stderr).contains("minimum of 1000"));
    assert!(!out.exists());
}
