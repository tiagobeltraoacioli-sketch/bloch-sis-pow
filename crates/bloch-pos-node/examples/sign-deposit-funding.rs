// SPDX-License-Identifier: AGPL-3.0-or-later
//! Human-operated offline funding authorization from an encrypted legacy wallet.
//! The wallet is never converted or exported. No network or broadcast support.
use bloch_pos_committee::transition::{FundedDeposit, PosTransaction};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
};
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err("Invalid hex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).map_err(|_| "Invalid hex")?, 16)
                .map_err(|_| "Invalid hex".into())
        })
        .collect()
}
fn read_bounded(path: &str, limit: u64) -> Result<String, String> {
    let mut s = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_string(&mut s)
        .map_err(|_| "Invalid text file")?;
    if s.len() as u64 > limit {
        return Err("File exceeds offline size limit".into());
    }
    Ok(s)
}
fn unlock_wallet(wallet: &str, passfile: &str) -> Result<bloch_crypto::wallet::Keypair, String> {
    use zeroize::Zeroizing;
    let meta =
        std::fs::symlink_metadata(passfile).map_err(|_| "Cannot read password file metadata")?;
    if !meta.file_type().is_file() {
        return Err("Password file must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("Password file must have owner-only permissions".into());
        }
    }
    let password = Zeroizing::new(read_bounded(passfile, 4096)?);
    if password.is_empty() {
        return Err("Empty password file".into());
    }
    let wallet_meta = std::fs::metadata(wallet).map_err(|_| "Cannot read wallet metadata")?;
    if !wallet_meta.is_file() || wallet_meta.len() > 131072 {
        return Err("Wallet must be a regular file of at most 128 KiB".into());
    }
    bloch_crypto::wallet::Keypair::load_encrypted(std::path::Path::new(wallet), &password).map_err(
        |_| "Wallet unlock failed: wrong password, unsupported format or damaged wallet".into(),
    )
}

fn read_tx(path: &str) -> Result<FundedDeposit, String> {
    let bytes = unhex(read_bounded(path, 65536)?.trim())?;
    let tx = PosTransaction::from_canonical_bytes(&bytes)
        .map_err(|_| "Invalid canonical transaction")?;
    if tx.canonical_bytes() != bytes {
        return Err("Noncanonical transaction".into());
    }
    match tx {
        PosTransaction::FundedDeposit(tx) => Ok(tx),
        _ => Err("Expected funded deposit".into()),
    }
}
fn check(
    tx: &FundedDeposit,
    approved: &FundedDeposit,
    expected: &[u8],
    complete: bool,
) -> Result<(), String> {
    tx.validate_shape().map_err(|_| "Invalid deposit shape")?;
    if !approved.funding_signature.is_empty() || !approved.proof_of_possession.is_empty() {
        return Err("Approved draft must be unsigned".into());
    }
    let mut intent = tx.clone();
    intent.funding_signature.clear();
    intent.proof_of_possession.clear();
    if &intent != approved || tx.funding_root().as_slice() != expected {
        return Err("Intent differs from approved draft or funding root".into());
    }
    if tx.proof_of_possession.is_empty()
        || !bloch_crypto::crypto::verify(
            &tx.validator_pubkey,
            &tx.possession_root(),
            &tx.proof_of_possession,
        )
    {
        return Err("Invalid validator possession signature".into());
    }
    if complete {
        if tx.funding_signature.is_empty()
            || !bloch_crypto::crypto::verify(
                &tx.funding_pubkey,
                &tx.funding_root(),
                &tx.funding_signature,
            )
        {
            return Err("Invalid funding signature".into());
        }
    } else if !tx.funding_signature.is_empty() {
        return Err("Funding role already signed".into());
    }
    Ok(())
}
fn sign_checked<F>(
    tx: &mut FundedDeposit,
    approved: &FundedDeposit,
    expected: &[u8],
    unlock: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<bloch_crypto::wallet::Keypair, String>,
{
    check(tx, approved, expected, false)?;
    let key = unlock()?;
    let mut native = vec![0xb1, 0x0c, 1, 0];
    native.extend_from_slice(&key.public_key);
    if native != tx.funding_pubkey {
        return Err("Wallet does not own funding authority".into());
    }
    tx.funding_signature = key.sign(&tx.funding_root())?;
    check(tx, approved, expected, true)
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("Offline only. --tx FILE --approved UNSIGNED --expected-root HEX32 --mode verify-partial|verify-complete|sign. For sign also --wallet ENCRYPTED_JSON --passphrase-file OWNER_ONLY_FILE --out NEW_FILE. No broadcast.");
        return Ok(());
    }
    if args.len() % 2 != 0 {
        return Err("Expected option/value pairs".into());
    }
    let mut a = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if ![
            "--tx",
            "--approved",
            "--expected-root",
            "--mode",
            "--wallet",
            "--passphrase-file",
            "--out",
        ]
        .contains(&pair[0].as_str())
            || a.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("Unknown or duplicate option".into());
        }
    }
    let get = |name| {
        a.get(name)
            .copied()
            .ok_or_else(|| format!("Missing {name}"))
    };
    let mut tx = read_tx(get("--tx")?)?;
    let approved = read_tx(get("--approved")?)?;
    let expected = unhex(get("--expected-root")?)?;
    if expected.len() != 32 {
        return Err("Expected hex32 root".into());
    }
    let mode = get("--mode")?;
    match mode {
        "verify-partial" | "verify-complete" => {
            if a.len() != 4 {
                return Err("Unexpected verification options".into());
            }
            check(&tx, &approved, &expected, mode == "verify-complete")?;
        }
        "sign" => {
            if a.len() != 7 {
                return Err("Missing signing options".into());
            }
            let out = get("--out")?;
            if std::fs::symlink_metadata(out).is_ok() {
                return Err("Output exists".into());
            }
            sign_checked(&mut tx, &approved, &expected, || {
                unlock_wallet(get("--wallet")?, get("--passphrase-file")?)
            })?;
            let bytes = PosTransaction::FundedDeposit(tx.clone()).canonical_bytes();
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(out).map_err(|_| "Cannot create new output")?;
            writeln!(file, "{}", hex(&bytes)).map_err(|_| "Cannot write output")?;
            file.sync_all().map_err(|_| "Cannot sync output")?;
        }
        _ => return Err("Unknown mode".into()),
    }
    println!(
        "Approved intent matched; validator signature verified; funding signature verified: {}",
        !tx.funding_signature.is_empty()
    );
    println!(
        "Transaction id: {}",
        hex(&PosTransaction::FundedDeposit(tx).txid())
    );
    println!(
        "Nothing broadcast. Check current epoch, input ownership and finality before submission."
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Refused: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_crypto::{crypto, wallet::Keypair};
    use bloch_pos_committee::transition::{FundingInput, TransferOutput};
    fn fixture() -> (FundedDeposit, FundedDeposit, Keypair) {
        let (pubkey, secret) = crypto::generate_keypair();
        let raw = pubkey[4..].to_vec();
        let key = Keypair {
            private_key: secret[4..].to_vec(),
            public_key: raw.clone(),
            address: crypto::address_from_pubkey(&raw, false),
        };
        let (vpub, vsecret) = crypto::generate_keypair();
        let mut tx = FundedDeposit {
            network_domain: [1; 32],
            valid_until_epoch: 3016,
            funding_pubkey: pubkey,
            inputs: vec![FundingInput {
                txid: [2; 32],
                vout: 0,
            }],
            validator_pubkey: vpub,
            amount_sat: 2_500_000_000_000,
            randao_commitment: [3; 32],
            withdrawal_credentials: [4; 32],
            commission_bps: 0,
            change: TransferOutput {
                value: 955709,
                script_hash: [4; 32],
            },
            max_base_fee_millisat_per_gas: 100,
            tip_millisat_per_gas: 5,
            tx_bytes: 0,
            funding_signature: vec![],
            proof_of_possession: vec![],
        };
        tx.tx_bytes = tx.reserved_tx_bytes();
        let approved = tx.clone();
        tx.proof_of_possession = crypto::sign(&vsecret, &tx.possession_root()).unwrap();
        (tx, approved, key)
    }
    #[test]
    fn rejects_changes_and_bad_possession_before_wallet_unlock() {
        let (tx, approved, _) = fixture();
        let root = tx.funding_root();
        for n in 0..5 {
            let mut bad = tx.clone();
            match n {
                0 => bad.amount_sat += 1,
                1 => bad.withdrawal_credentials = [9; 32],
                2 => bad.network_domain = [9; 32],
                3 => bad.valid_until_epoch += 1,
                _ => bad.proof_of_possession[10] ^= 1,
            }
            assert!(
                sign_checked(&mut bad, &approved, &root, || panic!("must not unlock")).is_err()
            );
        }
        let mut bad = tx.clone();
        assert!(sign_checked(&mut bad, &approved, &[0; 32], || panic!("must not unlock")).is_err());
    }
    #[test]
    fn signs_both_roles_preserving_approved_intent_and_rejects_wrong_owner() {
        let (mut tx, approved, key) = fixture();
        let root = tx.funding_root();
        let pop = tx.proof_of_possession.clone();
        let (_, _, wrong) = fixture();
        assert!(sign_checked(&mut tx, &approved, &root, || Ok(wrong)).is_err());
        sign_checked(&mut tx, &approved, &root, || Ok(key)).unwrap();
        assert_eq!(pop, tx.proof_of_possession);
        check(&tx, &approved, &root, true).unwrap();
        assert!(sign_checked(&mut tx, &approved, &root, || panic!("must not unlock")).is_err());
        tx.funding_signature[10] ^= 1;
        assert!(check(&tx, &approved, &root, true).is_err());
    }
    #[test]
    #[ignore = "requires DEPOSIT_FUNDING_BIN pointing to the built example"]
    fn encrypted_wallet_real_cli_roundtrip() {
        let bin =
            std::env::var("DEPOSIT_FUNDING_BIN").expect("Set DEPOSIT_FUNDING_BIN to built example");
        let (tx, approved, key) = fixture();
        let root = hex(&tx.funding_root());
        let dir =
            std::env::temp_dir().join(format!("bloch-deposit-funding-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let wallet = dir.join("wallet.json");
        let pass = dir.join("password");
        let partial = dir.join("partial.hex");
        let draft = dir.join("draft.hex");
        let output = dir.join("signed.hex");
        key.save_encrypted(&wallet, "Disposable test password only 2026!")
            .unwrap();
        std::fs::write(&pass, "Disposable test password only 2026!").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(
            &partial,
            hex(&PosTransaction::FundedDeposit(tx).canonical_bytes()),
        )
        .unwrap();
        std::fs::write(
            &draft,
            hex(&PosTransaction::FundedDeposit(approved).canonical_bytes()),
        )
        .unwrap();
        let before = std::fs::read(&wallet).unwrap();
        let common = vec![
            "--tx",
            partial.to_str().unwrap(),
            "--approved",
            draft.to_str().unwrap(),
            "--expected-root",
            &root,
            "--mode",
            "sign",
            "--wallet",
            wallet.to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
            "--out",
            output.to_str().unwrap(),
        ];
        std::fs::write(&pass, "wrong password").unwrap();
        assert!(!std::process::Command::new(&bin)
            .args(&common)
            .output()
            .unwrap()
            .status
            .success());
        assert!(!output.exists());
        std::fs::write(&pass, "Disposable test password only 2026!").unwrap();
        let r = std::process::Command::new(&bin)
            .args(&common)
            .output()
            .unwrap();
        assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
        assert_eq!(before, std::fs::read(&wallet).unwrap());
        let out_before = std::fs::read(&output).unwrap();
        assert!(!std::process::Command::new(&bin)
            .args(&common)
            .output()
            .unwrap()
            .status
            .success());
        assert_eq!(out_before, std::fs::read(&output).unwrap());
        let r = std::process::Command::new(&bin)
            .args([
                "--tx",
                output.to_str().unwrap(),
                "--approved",
                draft.to_str().unwrap(),
                "--expected-root",
                &root,
                "--mode",
                "verify-complete",
            ])
            .output()
            .unwrap();
        assert!(r.status.success());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(unlock_wallet(wallet.to_str().unwrap(), pass.to_str().unwrap()).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
