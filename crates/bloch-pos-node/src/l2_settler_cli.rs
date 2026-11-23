// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline L2 settler authorization workflow (audit AUDIT-L1L2-20261123,
//! L2N-01 stop-gap). Behind
//! `params::L2_SETTLER_AUTHORIZATION_ACTIVATION_EPOCH` a V3 settlement (wire
//! 0x13) is accepted only with a trailer signed by a registered settler key
//! (`l2_settlement::settler`). This tool writes the set text the release
//! pins, and signs a settlement with a sealed keystore; it never broadcasts
//! and decides no consensus rule: digest, trailer encoding and the bounds are
//! the committee's.
//!
//! The settler key is an ordinary sealed keystore (`bloch-pos keygen`,
//! BPOSKEY2), opened only by this process with the passphrase policy every
//! keystore command follows.

use crate::{
    codec,
    keys::{HybridVerifier, Keystore},
    l2_deposit_cli::{domain, get, options, read_text},
};
use bloch_pos_committee::{
    attestation::SignatureVerifier,
    l2_settlement::{mainnet, settler, Transaction},
    transition::funded::ADMISSION_PQ_SIGNATURE_MAX,
};
use sha3::{Digest, Sha3_256};
use std::{fs::OpenOptions, io::Write, path::Path};

const HELP: &str = "Native L2 settler authorization (audit L2N-01): the registered settler set and the settlement trailer (offline; does not broadcast)

pubkey --dir KEYSTORE_DIR --out FILE
set --pubkey HEX_FILE [--pubkey ...] --out SET_FILE
inspect --set SET_FILE
inspect --tx FILE
check --set SET_FILE --dir KEYSTORE_DIR
authorize --genesis TRUSTED_FILE --chain-id N --tx FILE --set SET_FILE --dir KEYSTORE_DIR
          [--next-set SET_FILE] --out NEW_FILE
verify --genesis TRUSTED_FILE --chain-id N --tx FILE --set SET_FILE

The settler key is a sealed keystore made by `bloch-pos keygen --dir DIR --index 0`;
`pubkey` writes its public half (hex), the only part that leaves the host.
A set is 1 to 3 distinct keys, the settler's first, standby keys after it; SET_FILE
is the text the native release pins in l2_settlement::mainnet::SETTLER_SET.
`check` opens the keystore, requires its key in the set and signs and verifies a
self-test value under a domain no consensus rule reads.
`authorize` takes an unsigned asynchronous V3 settlement (hex, wire 0x13) and
writes it with the trailer `signer || signature || next set`: the signature is
over this exact settlement (policy, statement, proof) and the next set, on the
network of the trusted genesis and the chain the statement names. --next-set
replaces the registered set when the settlement is accepted (rotation; any
registered key may do it). Before the gate's epoch the network refuses a
settlement that carries a trailer: submit the unsigned bytes until then.";

/// Domain of the `check` self-test signature: not a consensus domain.
const SELF_TEST_DOMAIN: &[u8] = b"BLOCH:L2:SETTLER-SELF-TEST:1";
/// Offset of the L2 chain id in a statement (after the 22-byte tag).
const STATEMENT_CHAIN_ID: usize = 22 + 256;

fn read_set(path: &str) -> Result<Vec<Vec<u8>>, String> {
    mainnet::settler_keys(&read_text(path)?)
        .ok_or_else(|| format!("{path}: not a settler set (1 to {} distinct enveloped hybrid keys in hex, one per line)", settler::MAX_KEYS))
}

fn set_text(keys: &[Vec<u8>]) -> String {
    keys.iter().map(|key| codec::hex(key) + "\n").collect()
}

fn write_new(path: &str, text: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| format!("{path}: {e}"))?;
    file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

fn key_id(key: &[u8]) -> String {
    codec::hex32(&Sha3_256::digest(key).into())
}

fn describe_set(label: &str, keys: &[Vec<u8>]) {
    println!("{label} of {} key(s), set hash {}", keys.len(), codec::hex32(&settler::set_hash(keys)));
    for (i, key) in keys.iter().enumerate() {
        println!("  {i}: sha3 {}", key_id(key));
    }
}

/// An asynchronous V3 settlement from its hex file.
fn read_settlement(path: &str) -> Result<Transaction, String> {
    let bytes = codec::unhex(read_text(path)?.trim())?;
    let tx = Transaction::decode_async_with_authorization(&bytes).ok_or("not an asynchronous L2 settlement (wire 0x13)")?;
    if tx.statement.len() != bloch_pos_committee::l2_settlement::STATEMENT_V3_BYTES {
        return Err("only a V3 settlement carries a settler authorization".into());
    }
    Ok(tx)
}

fn statement_chain_id(tx: &Transaction) -> u64 {
    u64::from_be_bytes(tx.statement[STATEMENT_CHAIN_ID..STATEMENT_CHAIN_ID + 8].try_into().expect("8 bytes"))
}

fn chain_id(o: &[(String, String)], tx: &Transaction) -> Result<u64, String> {
    let chain_id: u64 = get(o, "--chain-id")?.parse().map_err(|_| "bad --chain-id")?;
    if statement_chain_id(tx) != chain_id {
        return Err(format!("the statement is for chain {}, not --chain-id {chain_id}", statement_chain_id(tx)));
    }
    Ok(chain_id)
}

/// The authorization of `tx` by `keys` (a member of `set`), naming
/// `next_set`. The signature is released by the keystore only after it
/// verifies, and is checked once more here exactly as consensus checks it.
pub(crate) fn authorize_with(
    keys: &Keystore,
    network_domain: &[u8; 32],
    chain_id: u64,
    tx: &Transaction,
    set: &[Vec<u8>],
    next_set: Option<Vec<Vec<u8>>>,
) -> Result<settler::Authorization, String> {
    if tx.authorization.is_some() {
        return Err("the settlement already carries an authorization".into());
    }
    let signer = set.iter().position(|k| *k == keys.pubkey).ok_or("this keystore's key is not in the settler set")?;
    if next_set.as_deref() == Some(set) {
        return Err("--next-set is the registered set: nothing to rotate".into());
    }
    let digest = settler::digest(network_domain, chain_id, &tx.commitment(), next_set.as_deref());
    let signature = keys.sign_fitting(&digest, ADMISSION_PQ_SIGNATURE_MAX)?;
    let authorization = settler::Authorization { signer: signer as u8, signature, next_set };
    check_authorization(network_domain, chain_id, tx, &authorization, set)?;
    Ok(authorization)
}

/// What `State::check_authorization` requires of a trailer, against `set`.
pub(crate) fn check_authorization(
    network_domain: &[u8; 32],
    chain_id: u64,
    tx: &Transaction,
    authorization: &settler::Authorization,
    set: &[Vec<u8>],
) -> Result<(), String> {
    let key = set.get(usize::from(authorization.signer)).ok_or("the signer index is outside the set")?;
    if authorization.next_set.as_ref().is_some_and(|keys| !settler::valid_set(keys)) {
        return Err("the next set is not a valid settler set".into());
    }
    let digest = settler::digest(network_domain, chain_id, &tx.commitment(), authorization.next_set.as_deref());
    if !HybridVerifier::new().verify_with_key(key, &digest, &authorization.signature) {
        return Err("the signature does not verify under the set's key at the signer index".into());
    }
    // One encoding, within the wire bounds: what the network will decode.
    let mut signed = tx.clone();
    signed.authorization = Some(authorization.clone());
    if Transaction::decode_async_with_authorization(&signed.encode_async()).as_ref() != Some(&signed) {
        return Err("the authorized settlement does not decode (signature or set out of bounds)".into());
    }
    Ok(())
}

fn pubkey(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--dir", "--out"])?;
    let keys = Keystore::load(Path::new(get(&o, "--dir")?)).map_err(|e| e.to_string())?;
    if !settler::valid_set(std::slice::from_ref(&keys.pubkey)) {
        return Err("the keystore's key is not an enveloped hybrid key of the settler size".into());
    }
    write_new(get(&o, "--out")?, &(codec::hex(&keys.pubkey) + "\n"))?;
    println!("settler public key sha3 {}", key_id(&keys.pubkey));
    Ok(())
}

fn set(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--pubkey", "--out"])?;
    let keys = o
        .iter()
        .filter(|(f, _)| f == "--pubkey")
        .map(|(_, path)| codec::unhex(read_text(path)?.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    if !settler::valid_set(&keys) {
        return Err(format!("a settler set is 1 to {} distinct enveloped hybrid keys", settler::MAX_KEYS));
    }
    let text = set_text(&keys);
    if mainnet::settler_keys(&text).as_deref() != Some(keys.as_slice()) {
        return Err("the set text does not read back".into());
    }
    write_new(get(&o, "--out")?, &text)?;
    describe_set("settler set", &keys);
    Ok(())
}

fn inspect(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--set", "--tx"])?;
    if let Ok(path) = get(&o, "--set") {
        describe_set("settler set", &read_set(path)?);
    }
    if let Ok(path) = get(&o, "--tx") {
        let tx = read_settlement(path)?;
        println!("asynchronous V3 settlement");
        println!("  chain id       : {}", statement_chain_id(&tx));
        println!("  proof policy   : {}", codec::hex32(&tx.proof_policy));
        println!("  commitment     : {}", codec::hex32(&tx.commitment()));
        println!("  wire bytes     : {}", tx.wire_len());
        match &tx.authorization {
            None => println!("  authorization  : none (the form accepted before the settler gate)"),
            Some(a) => {
                println!("  authorization  : signer {} ({} signature bytes)", a.signer, a.signature.len());
                match &a.next_set {
                    None => println!("  next set       : none (the registered set stays)"),
                    Some(keys) => describe_set("  next set", keys),
                }
            }
        }
    }
    if o.is_empty() {
        return Err("inspect needs --set and/or --tx".into());
    }
    Ok(())
}

fn check(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--set", "--dir"])?;
    let set = read_set(get(&o, "--set")?)?;
    let keys = Keystore::load(Path::new(get(&o, "--dir")?)).map_err(|e| e.to_string())?;
    let signer = set.iter().position(|k| *k == keys.pubkey).ok_or("this keystore's key is not in the settler set")?;
    let digest: [u8; 32] = Sha3_256::new().chain_update(SELF_TEST_DOMAIN).chain_update(settler::set_hash(&set)).finalize().into();
    let signature = keys.sign_fitting(&digest, ADMISSION_PQ_SIGNATURE_MAX)?;
    if !HybridVerifier::new().verify_with_key(&keys.pubkey, &digest, &signature) {
        return Err("the self-test signature does not verify".into());
    }
    println!("settler key ready: signer {signer} of {} (sha3 {}), set hash {}", set.len(), key_id(&keys.pubkey), codec::hex32(&settler::set_hash(&set)));
    Ok(())
}

fn authorize(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--genesis", "--chain-id", "--tx", "--set", "--dir", "--next-set", "--out"])?;
    let mut tx = read_settlement(get(&o, "--tx")?)?;
    let chain_id = chain_id(&o, &tx)?;
    let network_domain = domain(get(&o, "--genesis")?)?;
    let set = read_set(get(&o, "--set")?)?;
    let next_set = get(&o, "--next-set").ok().map(read_set).transpose()?;
    let keys = Keystore::load(Path::new(get(&o, "--dir")?)).map_err(|e| e.to_string())?;
    let authorization = authorize_with(&keys, &network_domain, chain_id, &tx, &set, next_set)?;
    println!("settlement {} of chain {chain_id}", codec::hex32(&tx.commitment()));
    println!("  signer         : {} of {} (sha3 {})", authorization.signer, set.len(), key_id(&keys.pubkey));
    println!("  set hash       : {}", codec::hex32(&settler::set_hash(&set)));
    // Public: what was signed. A caller that derives the digest itself compares it with this line.
    println!(
        "  digest         : {}",
        codec::hex32(&settler::digest(&network_domain, chain_id, &tx.commitment(), authorization.next_set.as_deref()))
    );
    match &authorization.next_set {
        None => println!("  next set       : none (the registered set stays)"),
        Some(keys) => println!("  next set       : {} key(s), set hash {} (REPLACES the registered set on acceptance)", keys.len(), codec::hex32(&settler::set_hash(keys))),
    }
    tx.authorization = Some(authorization);
    write_new(get(&o, "--out")?, &(codec::hex(&tx.encode_async()) + "\n"))
}

fn verify(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--genesis", "--chain-id", "--tx", "--set"])?;
    let tx = read_settlement(get(&o, "--tx")?)?;
    let chain_id = chain_id(&o, &tx)?;
    let set = read_set(get(&o, "--set")?)?;
    let authorization = tx.authorization.clone().ok_or("the settlement carries no authorization")?;
    let mut unsigned = tx.clone();
    unsigned.authorization = None;
    check_authorization(&domain(get(&o, "--genesis")?)?, chain_id, &unsigned, &authorization, &set)?;
    println!("authorized by signer {} of {} (sha3 {})", authorization.signer, set.len(), key_id(&set[usize::from(authorization.signer)]));
    match &authorization.next_set {
        None => println!("next set: none"),
        Some(keys) => println!("next set: {} key(s), set hash {}", keys.len(), codec::hex32(&settler::set_hash(keys))),
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        println!("{HELP}");
        return Ok(());
    };
    match command.as_str() {
        "--help" | "help" => {
            println!("{HELP}");
            Ok(())
        }
        "pubkey" => pubkey(rest),
        "set" => set(rest),
        "inspect" => inspect(rest),
        "check" => check(rest),
        "authorize" => authorize(rest),
        "verify" => verify(rest),
        _ => Err("expected pubkey, set, inspect, check, authorize, verify or --help".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KdfParams, Unlock};
    use bloch_pos_committee::l2_settlement::{PROOF_BYTES, STATEMENT_V3_BYTES, TRANSACTION_V3_BYTES};

    /// The cross-repository vector: one authorized settlement with a real
    /// hybrid signature. The same file is `deployment/mainnet/testdata/
    /// settler-authorization-vector.json` in bloch-l2-evm, where the settler's
    /// own codec is tested against it (`test_settler_authorization.py`).
    const VECTOR: &str = include_str!("../tests/fixtures/l2-settler-authorization-vector.json");

    fn unlock() -> Unlock {
        // The smallest parameters a new keystore may be sealed with.
        Unlock::passphrase_with("settler-test-passphrase-2026", KdfParams { m_cost: 65_536, t_cost: 3, p_cost: 1 })
    }

    /// A sealed keystore from a fixed seed, in a directory removed on drop.
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn keystore(seed: u8) -> (Dir, Keystore) {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = Dir(std::env::temp_dir().join(format!("bloch-l2-settler-{}-{n}-{seed}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).unwrap();
        let keys = Keystore::generate_seeded_for_test(&dir.0, 0, [seed; 32], &unlock()).unwrap();
        // What the tool does: open the sealed file. Without the passphrase it does not open.
        let loaded = Keystore::load_with(&dir.0, &unlock()).unwrap();
        assert_eq!(loaded.pubkey, keys.pubkey);
        let wrong = Unlock::passphrase_with("another-passphrase-2026", KdfParams { m_cost: 65_536, t_cost: 3, p_cost: 1 });
        assert!(Keystore::load_with(&dir.0, &wrong).is_err());
        (dir, loaded)
    }

    /// A well-formed V3 settlement of `chain_id` (the statement is not a
    /// provable one: the authorization does not read it beyond its bytes).
    fn settlement(chain_id: u64, fill: u8) -> Transaction {
        let mut statement = vec![fill; STATEMENT_V3_BYTES];
        statement[..22].copy_from_slice(b"BLOCH:EVM:SETTLEMENT:3");
        statement[STATEMENT_CHAIN_ID..STATEMENT_CHAIN_ID + 8].copy_from_slice(&chain_id.to_be_bytes());
        let tx = Transaction { proof_policy: [0x15; 32], statement, proof: [fill ^ 0x5a; PROOF_BYTES], authorization: None };
        assert_eq!(Transaction::decode_async_with_authorization(&tx.encode_async()), Some(tx.clone()));
        tx
    }

    fn field<'a>(vector: &'a str, name: &str) -> &'a str {
        let at = vector.find(&format!("\"{name}\"")).unwrap_or_else(|| panic!("vector field {name}"));
        let rest = &vector[at + name.len() + 2..];
        let start = rest.find('"').unwrap() + 1;
        &rest[start..start + rest[start..].find('"').unwrap()]
    }

    fn bytes(vector: &str, name: &str) -> Vec<u8> {
        codec::unhex(field(vector, name)).unwrap()
    }

    #[test]
    fn a_registered_keystore_authorizes_a_settlement_the_committee_decodes_and_verifies() {
        let (_a, settler_key) = keystore(1);
        let (_b, standby) = keystore(2);
        let (_c, outsider) = keystore(3);
        let set = vec![settler_key.pubkey.clone(), standby.pubkey.clone()];
        assert!(settler::valid_set(&set));
        let (domain, chain) = ([7u8; 32], 700_770);
        let tx = settlement(chain, 0x11);

        let authorization = authorize_with(&settler_key, &domain, chain, &tx, &set, None).unwrap();
        assert_eq!(authorization.signer, 0);
        assert!(authorization.signature.len() <= ADMISSION_PQ_SIGNATURE_MAX);
        let mut signed = tx.clone();
        signed.authorization = Some(authorization.clone());
        let wire = signed.encode_async();
        // The unsigned bytes are a prefix: the form deployed today plus the trailer.
        assert_eq!(&wire[..TRANSACTION_V3_BYTES], tx.encode_async().as_slice());
        assert_eq!(Transaction::decode_async_with_authorization(&wire), Some(signed.clone()));
        assert_eq!(signed.commitment(), tx.commitment(), "the head commitment does not cover the trailer");
        // Exactly the three steps of State::check_authorization.
        let digest = settler::digest(&domain, chain, &tx.commitment(), None);
        assert!(HybridVerifier::new().verify_with_key(&set[0], &digest, &authorization.signature));

        // The standby key signs under its own index; an outsider cannot.
        assert_eq!(authorize_with(&standby, &domain, chain, &tx, &set, None).unwrap().signer, 1);
        assert!(authorize_with(&outsider, &domain, chain, &tx, &set, None).is_err());
        // Bound to the network, the chain, the settlement and the signer.
        assert!(check_authorization(&[8u8; 32], chain, &tx, &authorization, &set).is_err());
        assert!(check_authorization(&domain, chain + 1, &tx, &authorization, &set).is_err());
        assert!(check_authorization(&domain, chain, &settlement(chain, 0x12), &authorization, &set).is_err());
        let mut reproven = tx.clone();
        reproven.proof[0] ^= 1;
        assert!(check_authorization(&domain, chain, &reproven, &authorization, &set).is_err());
        let moved = settler::Authorization { signer: 1, ..authorization.clone() };
        assert!(check_authorization(&domain, chain, &tx, &moved, &set).is_err());
        // A settlement is authorized once.
        assert!(authorize_with(&settler_key, &domain, chain, &signed, &set, None).is_err());
    }

    #[test]
    fn a_rotation_is_covered_by_the_signature() {
        let (_a, settler_key) = keystore(1);
        let (_b, standby) = keystore(2);
        let (_c, replacement) = keystore(4);
        let set = vec![settler_key.pubkey.clone(), standby.pubkey.clone()];
        let next = vec![replacement.pubkey.clone(), standby.pubkey.clone()];
        let (domain, chain) = ([7u8; 32], 700_770);
        let tx = settlement(chain, 0x21);
        let rotating = authorize_with(&standby, &domain, chain, &tx, &set, Some(next.clone())).unwrap();
        assert_eq!((rotating.signer, rotating.next_set.as_ref()), (1, Some(&next)));
        check_authorization(&domain, chain, &tx, &rotating, &set).unwrap();
        // The next set cannot be dropped, added or changed afterwards.
        let dropped = settler::Authorization { next_set: None, ..rotating.clone() };
        assert!(check_authorization(&domain, chain, &tx, &dropped, &set).is_err());
        let changed = settler::Authorization { next_set: Some(vec![replacement.pubkey.clone()]), ..rotating.clone() };
        assert!(check_authorization(&domain, chain, &tx, &changed, &set).is_err());
        let plain = authorize_with(&standby, &domain, chain, &tx, &set, None).unwrap();
        let grafted = settler::Authorization { next_set: Some(next), ..plain };
        assert!(check_authorization(&domain, chain, &tx, &grafted, &set).is_err());
        // Rotating to the registered set is refused before anything is signed.
        assert!(authorize_with(&standby, &domain, chain, &tx, &set, Some(set.clone())).is_err());
    }

    #[test]
    fn the_set_text_is_the_text_the_release_pins() {
        let (_a, one) = keystore(1);
        let (_b, two) = keystore(2);
        let set = vec![one.pubkey.clone(), two.pubkey.clone()];
        assert_eq!(mainnet::settler_keys(&set_text(&set)), Some(set.clone()));
        assert_ne!(settler::set_hash(&set), settler::set_hash(&[two.pubkey.clone(), one.pubkey.clone()]), "order is part of the set");
    }

    /// The committed vector, checked with the committee's decoder and digest
    /// and the node's real hybrid verifier. The L2 repository checks the same
    /// file with its own codec, so both sides agree on every byte.
    #[test]
    fn the_cross_repository_vector_is_what_consensus_accepts() {
        let domain: [u8; 32] = bytes(VECTOR, "network_domain").try_into().unwrap();
        let chain: u64 = field(VECTOR, "chain_id").parse().unwrap();
        let set = mainnet::settler_keys(&field(VECTOR, "set").replace(',', "\n")).expect("set");
        assert_eq!(codec::hex32(&settler::set_hash(&set)), field(VECTOR, "set_hash"));
        for case in ["plain", "rotation"] {
            let unsigned = Transaction::decode_async_with_authorization(&bytes(VECTOR, "unsigned_tx")).expect("unsigned settlement");
            assert!(unsigned.authorization.is_none());
            assert_eq!(codec::hex32(&unsigned.commitment()), field(VECTOR, "commitment"));
            let wire = bytes(VECTOR, &format!("{case}_authorized_tx"));
            let signed = Transaction::decode_async_with_authorization(&wire).expect("authorized settlement");
            assert_eq!(signed.encode_async(), wire, "one encoding");
            assert_eq!(&wire[..TRANSACTION_V3_BYTES], unsigned.encode_async().as_slice());
            let authorization = signed.authorization.clone().expect("trailer");
            assert_eq!(authorization.signer.to_string(), field(VECTOR, &format!("{case}_signer")));
            let next_hash = authorization.next_set.as_deref().map_or([0; 32], settler::set_hash);
            assert_eq!(codec::hex32(&next_hash), field(VECTOR, &format!("{case}_next_set_hash")));
            let digest = settler::digest(&domain, chain, &unsigned.commitment(), authorization.next_set.as_deref());
            assert_eq!(codec::hex32(&digest), field(VECTOR, &format!("{case}_digest")));
            assert!(HybridVerifier::new().verify_with_key(&set[usize::from(authorization.signer)], &digest, &authorization.signature));
            check_authorization(&domain, chain, &unsigned, &authorization, &set).unwrap();
        }
    }

    /// Writes the vector (run once, by hand, when the format changes):
    /// `BLOCH_WRITE_SETTLER_VECTOR=<path> cargo test … write_the_cross_repository_vector -- --ignored`.
    #[test]
    #[ignore = "writes the cross-repository vector file"]
    fn write_the_cross_repository_vector() {
        let Some(path) = std::env::var_os("BLOCH_WRITE_SETTLER_VECTOR") else { return };
        let (_a, settler_key) = keystore(0x51);
        let (_b, standby) = keystore(0x52);
        let (_c, replacement) = keystore(0x53);
        let set = vec![settler_key.pubkey.clone(), standby.pubkey.clone()];
        let next = vec![replacement.pubkey.clone(), standby.pubkey.clone()];
        let domain: [u8; 32] = codec::unhex("f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966").unwrap().try_into().unwrap();
        let chain = 700_770u64;
        let tx = settlement(chain, 0x33);
        let plain = authorize_with(&settler_key, &domain, chain, &tx, &set, None).unwrap();
        let rotation = authorize_with(&standby, &domain, chain, &tx, &set, Some(next.clone())).unwrap();
        let wire = |a: &settler::Authorization| {
            let mut signed = tx.clone();
            signed.authorization = Some(a.clone());
            codec::hex(&signed.encode_async())
        };
        let hexes = |keys: &[Vec<u8>]| keys.iter().map(|k| codec::hex(k)).collect::<Vec<_>>().join(",");
        let text = format!(
            "{{\n \"note\": \"L2 settler authorization vector (audit L2N-01): test keys from fixed seeds, never used on a network\",\n \"network_domain\": \"{}\",\n \"chain_id\": \"{chain}\",\n \"set\": \"{}\",\n \"set_hash\": \"{}\",\n \"next_set\": \"{}\",\n \"unsigned_tx\": \"{}\",\n \"commitment\": \"{}\",\n \"plain_signer\": \"{}\",\n \"plain_next_set_hash\": \"{}\",\n \"plain_digest\": \"{}\",\n \"plain_authorized_tx\": \"{}\",\n \"rotation_signer\": \"{}\",\n \"rotation_next_set_hash\": \"{}\",\n \"rotation_digest\": \"{}\",\n \"rotation_authorized_tx\": \"{}\"\n}}\n",
            codec::hex32(&domain),
            hexes(&set),
            codec::hex32(&settler::set_hash(&set)),
            hexes(&next),
            codec::hex(&tx.encode_async()),
            codec::hex32(&tx.commitment()),
            plain.signer,
            codec::hex32(&[0; 32]),
            codec::hex32(&settler::digest(&domain, chain, &tx.commitment(), None)),
            wire(&plain),
            rotation.signer,
            codec::hex32(&settler::set_hash(&next)),
            codec::hex32(&settler::digest(&domain, chain, &tx.commitment(), Some(&next))),
            wire(&rotation),
        );
        std::fs::write(path, text).unwrap();
    }
}
