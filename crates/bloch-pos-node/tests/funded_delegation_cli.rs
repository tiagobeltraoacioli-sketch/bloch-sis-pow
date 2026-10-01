// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exercise offline delegation through the real binary and sealed, disposable keys.
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
            "disposable offline delegation test",
        )
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> String {
    let result = invoke(args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn refused(args: &[&str], reason: &str) {
    let result = invoke(args);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains(reason),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
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
fn decode(p: &Path) -> PosTransaction {
    PosTransaction::from_canonical_bytes(&unhex(&std::fs::read_to_string(p).unwrap())).unwrap()
}
fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}
struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sealed_review_bound_delegation_intents_and_negative_cases() {
    let dir =
        Temp(std::env::temp_dir().join(format!("bloch-delegation-cli-{}", std::process::id())));
    std::fs::create_dir(&dir.0).unwrap();
    let owner = dir.0.join("owner");
    let stranger = dir.0.join("stranger");
    for key in [&owner, &stranger] {
        ok(&["keygen", "--dir", path(key), "--index", "0"]);
        assert!(std::fs::read(key.join("validator.key"))
            .unwrap()
            .starts_with(b"BPOSKEY2"));
    }
    let public = |key: &Path| {
        ok(&["keygen-public", "--dir", path(key)])
            .trim()
            .split('\t')
            .nth(1)
            .unwrap()
            .to_owned()
    };
    let pk = public(&owner);
    let wrong_pk = public(&stranger);
    let pubfile = dir.0.join("owner.pub");
    let wrong_pubfile = dir.0.join("wrong.pub");
    std::fs::write(&pubfile, &pk).unwrap();
    std::fs::write(&wrong_pubfile, &wrong_pk).unwrap();
    let genesis = dir.0.join("genesis");
    let other = dir.0.join("other-genesis");
    ok(&["genesis", "--keys", path(&owner), "--out", path(&genesis)]);
    ok(&[
        "genesis",
        "--keys",
        path(&owner),
        "--slot-ms",
        "1234",
        "--out",
        path(&other),
    ]);
    let hash = hex(&[71; 32]);
    let input = format!("{hash}:0:2000000000");
    let root_zero = hex(&[0; 32]);
    for kind in ["delegate", "commission", "undelegate", "withdraw"] {
        let draft = dir.0.join(format!("{kind}.draft"));
        let signed = dir.0.join(format!("{kind}.signed"));
        let bad = dir.0.join(format!("{kind}.bad"));
        let command = format!("prepare-{kind}");
        let mut args = vec![
            "funded-delegation",
            &command,
            "--genesis",
            path(&genesis),
            "--out",
            path(&draft),
        ];
        match kind {
            "delegate" => args.extend([
                "--pubkey",
                path(&pubfile),
                "--validator-hash",
                &hash,
                "--amount",
                "1000000000",
                "--input",
                &input,
                "--change",
                &hash,
                "--max-base-fee",
                "100",
                "--tip",
                "5",
                "--expiry",
                "20",
            ]),
            "commission" => {
                args.extend(["--validator", "0", "--commission", "500", "--epoch", "12"])
            }
            "undelegate" => args.extend([
                "--pubkey",
                path(&pubfile),
                "--delegator",
                "0",
                "--position",
                "0",
                "--epoch",
                "12",
            ]),
            "withdraw" => args.extend([
                "--pubkey",
                path(&pubfile),
                "--delegator",
                "0",
                "--position",
                "0",
                "--epoch",
                "12",
                "--destination",
                &hash,
                "--max-base-fee",
                "100",
            ]),
            _ => unreachable!(),
        }
        let review = ok(&args);
        assert!(review.contains("\"signed\":false"));
        refused(&args, "exists");
        let mut duplicate = args.clone();
        duplicate.extend(["--out", path(&bad)]);
        refused(&duplicate, "duplicate option");
        if kind == "delegate" {
            let mut dup = args.clone();
            dup.extend(["--input", &input]);
            refused(&dup, "invalid intent");
            let mut poor = args.clone();
            let i = poor.iter().position(|v| *v == "--amount").unwrap();
            poor[i + 1] = "9000000000";
            refused(&poor, "insufficient funding");
        }
        let unsigned = decode(&draft);
        let root = hex(&match &unsigned {
            PosTransaction::FundedDelegate(t) => t.signing_root(),
            PosTransaction::FundedUndelegate(t) => t.signing_root(),
            PosTransaction::FundedDelegationWithdraw(t) => t.signing_root(),
            PosTransaction::ValidatorCommissionUpdate(t) => t.signing_root(),
            _ => unreachable!(),
        });
        let sign = |gen: &Path, key: &Path, expected: &str, src: &Path, dst: &Path| {
            invoke(&[
                "funded-delegation",
                "sign",
                "--genesis",
                path(gen),
                "--dir",
                path(key),
                "--tx",
                path(src),
                "--expected-root",
                expected,
                "--out",
                path(dst),
            ])
        };
        let failed = sign(&genesis, Path::new("missing-key"), &root_zero, &draft, &bad);
        assert!(String::from_utf8_lossy(&failed.stderr).contains("reviewed signing root"));
        assert!(!bad.exists());
        let failed = sign(&other, Path::new("missing-key"), &root, &draft, &bad);
        assert!(String::from_utf8_lossy(&failed.stderr).contains("another genesis"));
        assert!(!bad.exists());
        if kind != "commission" {
            let failed = sign(&genesis, &stranger, &root, &draft, &bad);
            assert!(String::from_utf8_lossy(&failed.stderr).contains("not the intent owner"));
            assert!(!bad.exists());
        }
        let result = sign(&genesis, &owner, &root, &draft, &signed);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut inspect = vec!["funded-delegation", "inspect", "--tx", path(&signed)];
        if kind == "commission" {
            refused(&inspect, "requires --pubkey");
            let mut wrong = inspect.clone();
            wrong.extend(["--pubkey", path(&wrong_pubfile)]);
            refused(&wrong, "invalid commission authorization");
            inspect.extend(["--pubkey", path(&pubfile)]);
        }
        assert!(ok(&inspect).contains("\"signed\":true"));
        let original = std::fs::read(&signed).unwrap();
        assert!(!sign(&genesis, &owner, &root, &draft, &signed)
            .status
            .success());
        assert_eq!(original, std::fs::read(&signed).unwrap());
        assert!(!sign(&genesis, &owner, &root, &signed, &bad)
            .status
            .success());
        assert!(!bad.exists());
        let mut complete = decode(&signed);
        assert_eq!(unsigned.txid(), complete.txid());
        let sig = match &mut complete {
            PosTransaction::FundedDelegate(t) => {
                t.amount_sat += 1;
                &t.funding_signature
            }
            PosTransaction::FundedUndelegate(t) => {
                t.position += 1;
                &t.signature
            }
            PosTransaction::FundedDelegationWithdraw(t) => {
                t.destination_script_hash[0] ^= 1;
                &t.signature
            }
            PosTransaction::ValidatorCommissionUpdate(t) => {
                t.commission_bps += 1;
                &t.signature
            }
            _ => unreachable!(),
        };
        assert!(bloch_crypto::crypto::verify(
            &unhex(&pk),
            &unhex(&root),
            sig
        ));
        std::fs::write(&bad, hex(&complete.canonical_bytes())).unwrap();
        let mut tampered = vec!["funded-delegation", "inspect", "--tx", path(&bad)];
        if kind == "commission" {
            tampered.extend(["--pubkey", path(&pubfile)]);
        }
        refused(&tampered, "authorization");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&signed).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
