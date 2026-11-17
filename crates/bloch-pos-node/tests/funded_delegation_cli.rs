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
        let signature_len = match decode(&signed) {
            PosTransaction::FundedDelegate(t) => t.funding_signature.len(),
            PosTransaction::FundedUndelegate(t) => t.signature.len(),
            PosTransaction::FundedDelegationWithdraw(t) => t.signature.len(),
            PosTransaction::ValidatorCommissionUpdate(t) => t.signature.len(),
            _ => unreachable!(),
        };
        assert!(
            signature_len > 0
                && signature_len
                    <= bloch_pos_committee::transition::funded::ADMISSION_PQ_SIGNATURE_MAX
        );
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

/// GIP-0002 (WT-04): `--max-commission` writes the capped request (tag
/// 0x1C), shows the cap for review and signs its own root; without the flag
/// the tool still writes the capless request (tag 0x0E) byte for byte.
#[test]
fn prepare_delegate_writes_the_capped_form_only_when_asked() {
    let dir = Temp(std::env::temp_dir().join(format!("bloch-delegation-cap-cli-{}", std::process::id())));
    std::fs::create_dir(&dir.0).unwrap();
    let owner = dir.0.join("owner");
    ok(&["keygen", "--dir", path(&owner), "--index", "0"]);
    let pk = ok(&["keygen-public", "--dir", path(&owner)]).trim().split('\t').nth(1).unwrap().to_owned();
    let pubfile = dir.0.join("owner.pub");
    std::fs::write(&pubfile, &pk).unwrap();
    let genesis = dir.0.join("genesis");
    ok(&["genesis", "--keys", path(&owner), "--out", path(&genesis)]);
    let hash = hex(&[71; 32]);
    let input = format!("{hash}:0:2000000000");
    let prepare = |out: &Path, cap: Option<&str>| {
        let mut args = vec![
            "funded-delegation", "prepare-delegate", "--genesis", path(&genesis), "--out", path(out),
            "--pubkey", path(&pubfile), "--validator-hash", &hash, "--amount", "1000000000",
            "--input", &input, "--change", &hash, "--max-base-fee", "100", "--tip", "5", "--expiry", "20",
        ];
        if let Some(cap) = cap {
            args.extend(["--max-commission", cap]);
        }
        invoke(&args)
    };

    let capless = dir.0.join("capless.draft");
    let review = prepare(&capless, None);
    assert!(review.status.success(), "{}", String::from_utf8_lossy(&review.stderr));
    assert!(!String::from_utf8_lossy(&review.stdout).contains("max_commission_bps"));
    let PosTransaction::FundedDelegate(v1) = decode(&capless) else { panic!("capless request expected") };
    assert_eq!(unhex(&std::fs::read_to_string(&capless).unwrap())[0], 0x0e);

    let capped = dir.0.join("capped.draft");
    let review = prepare(&capped, Some("500"));
    assert!(review.status.success(), "{}", String::from_utf8_lossy(&review.stderr));
    assert!(String::from_utf8_lossy(&review.stdout).contains("\"max_commission_bps\":\"500\""));
    let PosTransaction::FundedDelegateV2(v2) = decode(&capped) else { panic!("capped request expected") };
    assert_eq!(unhex(&std::fs::read_to_string(&capped).unwrap())[0], 0x1c);
    assert_eq!(v2.max_commission_bps, 500);
    assert_eq!(v2.request.tx_bytes, v1.tx_bytes + 16);
    assert!(v2.validate_shape().is_ok());
    // The 16 extra bytes are paid for out of the change, nothing else moves.
    assert!(v2.request.change.value < v1.change.value);
    assert_eq!((v2.request.amount_sat, &v2.request.inputs), (v1.amount_sat, &v1.inputs));
    assert_ne!(v2.signing_root(), v1.signing_root());

    // A cap above 100% is refused before anything is written.
    let absurd = dir.0.join("absurd.draft");
    let refused_cap = prepare(&absurd, Some("10001"));
    assert!(!refused_cap.status.success());
    assert!(String::from_utf8_lossy(&refused_cap.stderr).contains("invalid intent"));
    assert!(!absurd.exists());

    // Signing binds the reviewed V2 root; the capless root does not sign it.
    let signed = dir.0.join("capped.signed");
    let sign = |expected: &str| {
        invoke(&[
            "funded-delegation", "sign", "--genesis", path(&genesis), "--dir", path(&owner),
            "--tx", path(&capped), "--expected-root", expected, "--out", path(&signed),
        ])
    };
    let wrong = sign(&hex(&v1.signing_root()));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("reviewed signing root"));
    assert!(!signed.exists());
    let done = sign(&hex(&v2.signing_root()));
    assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
    let PosTransaction::FundedDelegateV2(complete) = decode(&signed) else { panic!("capped request expected") };
    assert_eq!(complete.max_commission_bps, 500);
    assert!(bloch_crypto::crypto::verify(&unhex(&pk), &v2.signing_root(), &complete.request.funding_signature));
    assert!(!bloch_crypto::crypto::verify(&unhex(&pk), &v1.signing_root(), &complete.request.funding_signature));
    let inspected = ok(&["funded-delegation", "inspect", "--tx", path(&signed)]);
    assert!(inspected.contains("\"signed\":true") && inspected.contains("\"max_commission_bps\":\"500\""));
}
