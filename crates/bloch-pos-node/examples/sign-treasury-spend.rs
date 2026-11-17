// SPDX-License-Identifier: AGPL-3.0-or-later
//! Human-operated OFFLINE signer for a treasury spend drafted by
//! `bloch-pos treasury-collect prepare`, with the treasury key's encrypted
//! legacy wallet. The same family and the same wallet discipline as
//! `sign-deposit-funding.rs` (the founder's existing offline signer): the
//! wallet is never converted or exported, the passphrase comes from an
//! owner-only file, nothing touches the network, nothing is broadcast.
//!
//! Order of operations, each a refusal point:
//! 1. the draft is canonical, unsigned, and passes the full treasury
//!    inspection against the observation and the trusted manifest
//!    (every input observed and owned by the treasury, no genesis
//!    allocation, no dust, exact conservation, fee within --max-fee);
//! 2. its signing root equals the root the owner approved (--expected-root);
//! 3. only then is the wallet unlocked; its RAW public key must be the
//!    draft's witness key;
//! 4. the signature is checked again by the same inspection (consensus spend
//!    verifier) before the signed file is written (new file, mode 0600).
use bloch_pos_committee::transition::{funded::ADMISSION_PQ_SIGNATURE_MAX, PosTransaction};
use bloch_pos_node::{
    codec,
    genesis::Manifest,
    treasury_spend::{inspect, protected_outpoints, render, Observation, MAX_OBSERVATION_BYTES},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{Read, Write},
};

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

/// Verbatim the unlock discipline of `sign-deposit-funding.rs`.
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

fn read_tx(path: &str) -> Result<PosTransaction, String> {
    let bytes = codec::unhex(read_bounded(path, 4 * 1024 * 1024)?.trim())?;
    let tx = PosTransaction::from_canonical_bytes(&bytes)
        .map_err(|_| "Invalid canonical transaction")?;
    if tx.canonical_bytes() != bytes {
        return Err("Noncanonical transaction".into());
    }
    Ok(tx)
}

/// Steps 1 to 4 above; `unlock` runs only after steps 1 and 2 pass.
fn sign_checked<F>(
    tx: &mut PosTransaction,
    obs: &Observation,
    protected: &BTreeSet<([u8; 32], u32)>,
    expected_root: &[u8; 32],
    max_fee_sat: u64,
    unlock: F,
) -> Result<String, String>
where
    F: FnOnce() -> Result<bloch_crypto::wallet::Keypair, String>,
{
    let before = inspect(obs, protected, tx, max_fee_sat)?;
    if before.signed {
        return Err("Draft is already signed".into());
    }
    if &before.signing_root != expected_root {
        return Err("Signing root differs from the approved --expected-root".into());
    }
    let key = unlock()?;
    let PosTransaction::TransferV2 { keys, .. } = tx else {
        return Err("Expected a TransferV2".into());
    };
    if key.public_key != keys[0].pubkey {
        return Err("Wallet does not own this draft's witness key (raw public key differs)".into());
    }
    keys[0].signature = key.sign_fitting(&before.signing_root, ADMISSION_PQ_SIGNATURE_MAX)?;
    let after = inspect(obs, protected, tx, max_fee_sat)?;
    if !after.signed || after.txid != before.txid || after.signing_root != before.signing_root {
        return Err("Signed transaction does not match the approved draft".into());
    }
    Ok(render(obs, &after))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("Offline only. --observation FILE --genesis TRUSTED_MANIFEST --tx UNSIGNED_DRAFT --expected-root HEX32 --max-fee SAT --wallet ENCRYPTED_JSON --passphrase-file OWNER_ONLY_FILE --out NEW_FILE. Runs the treasury inspection before and after signing. No network, no broadcast.");
        return Ok(());
    }
    if args.len() % 2 != 0 {
        return Err("Expected option/value pairs".into());
    }
    let allowed = [
        "--observation",
        "--genesis",
        "--tx",
        "--expected-root",
        "--max-fee",
        "--wallet",
        "--passphrase-file",
        "--out",
    ];
    let mut a = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str()) || a.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err("Unknown or duplicate option".into());
        }
    }
    if a.len() != allowed.len() {
        return Err("Missing options (all eight are required)".into());
    }
    let get = |name: &str| a.get(name).copied().ok_or_else(|| format!("Missing {name}"));
    let out = get("--out")?;
    if std::fs::symlink_metadata(out).is_ok() {
        return Err("Output exists".into());
    }
    let obs = Observation::parse(&read_bounded(get("--observation")?, MAX_OBSERVATION_BYTES)?)?;
    let (manifest, digest) =
        Manifest::load(std::path::Path::new(get("--genesis")?)).map_err(|e| e.to_string())?;
    if digest != obs.genesis_sha3 {
        return Err("Genesis manifest is not the one the observation names".into());
    }
    let protected = protected_outpoints(&manifest, &obs.treasury);
    let expected: [u8; 32] = codec::unhex(get("--expected-root")?)?
        .try_into()
        .map_err(|_| "Expected hex32 root")?;
    let max_fee: u64 = get("--max-fee")?.parse().map_err(|_| "Invalid --max-fee")?;
    let mut tx = read_tx(get("--tx")?)?;
    let shown = sign_checked(&mut tx, &obs, &protected, &expected, max_fee, || {
        unlock_wallet(get("--wallet")?, get("--passphrase-file")?)
    })?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(out).map_err(|_| "Cannot create new output")?;
    writeln!(file, "{}", codec::hex(&tx.canonical_bytes())).map_err(|_| "Cannot write output")?;
    file.sync_all().map_err(|_| "Cannot sync output")?;
    print!("{shown}");
    println!("Signed. Nothing broadcast. Submit with sendrawtransaction from an online machine.");
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
    use bloch_pos_committee::state_root::EutxoEntry;
    use bloch_pos_node::treasury_spend::{build_plan, EndpointRead, Intent};
    use sha3::{Digest, Sha3_256};

    fn legacy(seed: u8) -> Keypair {
        let (pk, sk) = crypto::generate_keypair_from_seed(&[seed; 32]).unwrap();
        let raw = pk[4..].to_vec();
        Keypair { private_key: sk[4..].to_vec(), public_key: raw.clone(), address: crypto::address_from_pubkey(&raw, false) }
    }
    fn carried(raw: &[u8]) -> [u8; 32] {
        let h: [u8; 32] = Sha3_256::digest(raw).into();
        let mut s = [0u8; 32];
        s[..20].copy_from_slice(&h[..20]);
        s
    }
    fn fixture(key: &Keypair) -> (Observation, PosTransaction, [u8; 32]) {
        let t = carried(&key.public_key);
        let obs = Observation {
            treasury: t,
            genesis_sha3: [0; 32],
            epoch: 9_000,
            base_fee: 10,
            endpoints: vec![
                EndpointRead { addr: "a:1".into(), head_slot: 288_000, head_block: [1; 32], finalized_epoch: 8_998, finalized_root: [2; 32] },
                EndpointRead { addr: "b:1".into(), head_slot: 288_000, head_block: [1; 32], finalized_epoch: 8_998, finalized_root: [2; 32] },
            ],
            page_total: 2,
            utxos: vec![
                EutxoEntry { txid: [5; 32], vout: 2, value: 150_000, script_hash: t },
                EutxoEntry { txid: [6; 32], vout: 2, value: 25_000, script_hash: t },
            ],
        };
        let intent = Intent { pay: vec![], change_to: t, tip: 0, max_fee_sat: 10_000, max_inputs: 1_000 };
        let plan = build_plan(&obs, &BTreeSet::new(), &key.public_key, &intent).unwrap();
        (obs, plan.tx, plan.signing_root)
    }

    #[test]
    fn refuses_before_unlock_on_a_changed_draft_or_root() {
        let key = legacy(0x71);
        let (obs, tx, root) = fixture(&key);
        let none = BTreeSet::new();
        for n in 0..4 {
            let mut bad = tx.clone();
            if let PosTransaction::TransferV2 { outputs, tip_millisat_per_gas, inputs, .. } = &mut bad {
                match n {
                    0 => outputs[0].value -= 1,
                    1 => outputs[0].script_hash[0] ^= 1,
                    2 => *tip_millisat_per_gas += 1,
                    _ => inputs[0].vout = 3,
                }
            }
            assert!(sign_checked(&mut bad, &obs, &none, &root, 10_000, || panic!("must not unlock")).is_err(), "case {n}");
        }
        let mut same = tx.clone();
        assert!(sign_checked(&mut same, &obs, &none, &[0; 32], 10_000, || panic!("must not unlock")).is_err());
        // A fee cap below the exact fee: refused before unlock.
        let mut same = tx.clone();
        assert!(sign_checked(&mut same, &obs, &none, &root, 1, || panic!("must not unlock")).is_err());
    }

    #[test]
    fn signs_with_the_raw_legacy_key_and_refuses_another_wallet() {
        let key = legacy(0x72);
        let (obs, tx, root) = fixture(&key);
        let none = BTreeSet::new();
        let mut wrong = tx.clone();
        assert!(sign_checked(&mut wrong, &obs, &none, &root, 10_000, || Ok(legacy(0x73))).is_err());
        let mut good = tx.clone();
        let shown = sign_checked(&mut good, &obs, &none, &root, 10_000, || Ok(key)).unwrap();
        assert!(shown.contains("Signature present: true"));
        assert_eq!(good.txid(), tx.txid());
        // Already signed: refused before unlock.
        assert!(sign_checked(&mut good.clone(), &obs, &none, &root, 10_000, || panic!("must not unlock")).is_err());
        // A flipped signature byte fails the post-signature inspection.
        if let PosTransaction::TransferV2 { keys, .. } = &mut good {
            keys[0].signature[40] ^= 1;
        }
        assert!(inspect(&obs, &none, &good, 10_000).is_err());
    }

    #[test]
    fn end_to_end_with_an_encrypted_wallet_file() {
        let key = legacy(0x74);
        let (obs, tx, root) = fixture(&key);
        let dir = std::env::temp_dir().join(format!("sign-treasury-spend-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let wallet = dir.join("wallet.json");
        key.save_encrypted(&wallet, "disposable test wallet passphrase").unwrap();
        let pass = dir.join("pass");
        std::fs::write(&pass, "disposable test wallet passphrase").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut t1 = tx.clone();
        let p = |x: &std::path::Path| x.to_str().unwrap().to_owned();
        let r = sign_checked(&mut t1, &obs, &BTreeSet::new(), &root, 10_000, || unlock_wallet(&p(&wallet), &p(&pass)));
        #[cfg(unix)]
        assert!(r.unwrap_err().contains("owner-only"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut t2 = tx.clone();
        sign_checked(&mut t2, &obs, &BTreeSet::new(), &root, 10_000, || unlock_wallet(&p(&wallet), &p(&pass))).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
