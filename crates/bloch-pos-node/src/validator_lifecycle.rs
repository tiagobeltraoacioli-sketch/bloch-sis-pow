// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline exit signing and permissionless withdrawal encoding (ADR-041).

use crate::{codec, keys::Keystore};
use bloch_pos_committee::{staking::ExitTx, transition::PosTransaction};
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, fs::OpenOptions, io::Write, path::Path};

const HELP: &str = "Validator lifecycle (offline; does not broadcast)

exit --dir KEYSTORE_DIR --epoch INCLUSION_EPOCH --out NEW_FILE
withdraw --validator INDEX --out NEW_FILE

Exit signs the exact inclusion epoch and the keystore's public-key hash.
Confirm the epoch with your node before signing; an expired exit must be
signed again. Use a distinct validator key per network: the ADR-041 exit
signature does not contain a network domain. No command changes your keys.
Withdrawal needs no signature and always pays the registered credential.
Transaction files contain hex. Submit using sendrawtransaction only after
reviewing getvalidatorbykey/getvalidator and the lifecycle activation epoch.";

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        println!("{HELP}");
        return Ok(());
    };
    if command == "--help" || command == "help" {
        println!("{HELP}");
        return Ok(());
    }
    let allowed: &[&str] = match command.as_str() {
        "exit" => &["--dir", "--epoch", "--out"],
        "withdraw" => &["--validator", "--out"],
        _ => return Err("expected exit, withdraw or --help".into()),
    };
    let mut flags = BTreeMap::new();
    let mut iter = rest.iter();
    while let Some(flag) = iter.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err(format!("unknown option {flag}"));
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if flags.insert(flag.as_str(), value.as_str()).is_some() {
            return Err(format!("duplicate option {flag}"));
        }
    }
    let get = |flag| {
        flags
            .get(flag)
            .copied()
            .ok_or_else(|| format!("missing {flag}"))
    };
    let tx = if command == "exit" {
        let epoch = get("--epoch")?
            .parse()
            .map_err(|_| "invalid inclusion epoch")?;
        let keys = Keystore::load(Path::new(get("--dir")?)).map_err(|e| e.to_string())?;
        let pubkey_hash = Sha3_256::digest(&keys.pubkey).into();
        let root = ExitTx {
            pubkey_hash,
            epoch,
            signature: Vec::new(),
        }
        .signing_root();
        println!(
            "Exit public-key hash: {}\nInclusion epoch: {epoch}",
            codec::hex(&pubkey_hash)
        );
        PosTransaction::ExitV2 {
            pubkey_hash,
            epoch,
            signature: keys.sign(&root),
        }
    } else {
        let validator = get("--validator")?
            .parse()
            .map_err(|_| "invalid validator index")?;
        PosTransaction::Withdraw { validator }
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(get("--out")?).map_err(|e| e.to_string())?;
    writeln!(file, "{}", codec::hex(&tx.canonical_bytes())).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    println!("Transaction id: {}", codec::hex(&tx.txid()));
    Ok(())
}
