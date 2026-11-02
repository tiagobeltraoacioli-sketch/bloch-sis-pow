// SPDX-License-Identifier: AGPL-3.0-or-later
//! REHEARSAL TOOLING ONLY (scripts/hf-rehearsal/inert). Compiled into the
//! tooling copy of the node, never into a node that runs on a network, and
//! refuses any manifest that is not devnet-shaped. Throwaway keys only.
//!
//! Builds the transactions, blocks and votes a gate must refuse or accept:
//!   slh-keystore  --dir D --index N
//!   slh-transfer  --dir D --input T:V:S --to H --base-fee F --tip T --epoch E [--price-epoch P] --out F
//!   rotate        --genesis G --auth-dir A --new-dir N --validator V --epoch E --out F
//!   forge-block   --genesis G --dir D --data-dir N --slot S --form v1|v2|leaf [--kes-dir K] --to ADDR
//!   forge-vote    --genesis G --dir D --data-dir N --after-slot A --validator V --form v1|v2|leaf [--kes-dir K] --to ADDR
//!   bad-evidence  --genesis G --data-dir N --slot S --slot2 S2 --kind forged-sig|no-conflict|two-signers --tag T --out F
//!   marker-transfer --dir D --genesis G --input T:V:S --to H --base-fee F --tip T --out F
//!   sig-forms     --genesis G --data-dir N --from-epoch A --to-epoch B
use crate::{codec, devnet_tools, genesis::Manifest, kes_key::KesKey, keys::{Keystore, Unlock}, net, store};
use bloch_crypto::crypto;
use bloch_pos_committee::{
    attestation::{Attestation, SignaturePolicy},
    epoch_of, fee_market,
    header::BlockEnvelope,
    interfaces::{ProposalEnvelope, SlashingEvidence},
    params::{MIN_TRANSFER_OUTPUT_SAT, SLHDSA_FALCON_MAX_ENVELOPED_SIG_LEN},
    transition::{PosTransaction, TransferInputV2, TransferOutput, WitnessKey, WithdrawalCredentialRotation},
};
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, path::Path};

type R<T> = Result<T, String>;
const MAGIC_V1: &[u8; 8] = b"BPOSKEY1";

fn flags(a: &[String]) -> R<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    for p in a.chunks(2) {
        if p.len() != 2 || !p[0].starts_with("--") { return Err("options are --name value pairs".into()); }
        m.insert(p[0].clone(), p[1].clone());
    }
    Ok(m)
}
fn get<'a>(m: &'a BTreeMap<String, String>, k: &str) -> R<&'a str> {
    m.get(k).map(String::as_str).ok_or_else(|| format!("missing {k}"))
}
fn num<T: std::str::FromStr>(m: &BTreeMap<String, String>, k: &str) -> R<T> {
    get(m, k)?.parse().map_err(|_| format!("{k} must be a number"))
}
fn h32(s: &str) -> R<[u8; 32]> {
    codec::unhex(s)?.try_into().map_err(|_| format!("{s} is not 32 bytes"))
}
fn write_hex(path: &str, b: &[u8]) -> R<()> {
    std::fs::write(path, codec::hex(b) + "\n").map_err(|e| e.to_string())
}
fn load_plain(dir: &str) -> R<(Vec<u8>, Vec<u8>)> {
    let b = std::fs::read(Path::new(dir).join("validator.key")).map_err(|e| e.to_string())?;
    if b.len() < 12 || &b[..8] != MAGIC_V1 { return Err(format!("{dir}: not plaintext BPOSKEY1")); }
    let mut at = 12;
    let mut field = || { let n = u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize; let v = b[at + 4..at + 4 + n].to_vec(); at += 4 + n; v };
    let pk = field(); let sk = field();
    Ok((pk, sk))
}
fn devnet(genesis: &str) -> R<(Manifest, [u8; 32])> {
    let (m, d) = Manifest::load(Path::new(genesis)).map_err(|e| e.to_string())?;
    devnet_tools::require_devnet_shape(&m)?;
    let domain: [u8; 32] = Sha3_256::digest(m.encode()).into();
    let _ = d;
    Ok((m, domain))
}

fn slh_keystore(m: &BTreeMap<String, String>) -> R<()> {
    let dir = Path::new(get(m, "--dir")?);
    let index: u32 = num(m, "--index")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let (pk, sk) = crypto::slhdsa_suite::generate_keypair();
    let mut randao = [0u8; 32];
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut randao)).map_err(|e| e.to_string())?;
    let mut out = MAGIC_V1.to_vec();
    out.extend_from_slice(&index.to_le_bytes());
    for v in [&pk, &sk] { out.extend_from_slice(&(v.len() as u32).to_le_bytes()); out.extend_from_slice(v); }
    out.extend_from_slice(&randao);
    std::fs::write(dir.join("validator.key"), &out).map_err(|e| e.to_string())?;
    let script: [u8; 32] = Sha3_256::digest(&pk).into();
    println!("script {}", codec::hex(&script));
    Ok(())
}

/// One witness TransferV2. `class_epoch` prices the witness; the tx is signed
/// by `sign`. `sign` may be retried by the caller's closure.
fn one_key_transfer(pubkey: &[u8], sig_room: usize, m: &BTreeMap<String, String>, class_epoch: u64, epoch: u64,
                    sign: impl Fn(&[u8; 32]) -> R<Vec<u8>>) -> R<PosTransaction> {
    let input = get(m, "--input")?;
    let parts: Vec<&str> = input.split(':').collect();
    let [txid, vout, sat] = parts[..] else { return Err("--input needs TXID:VOUT:SAT".into()) };
    let (txid, vout, value): ([u8; 32], u32, u64) = (h32(txid)?, vout.parse().map_err(|_| "vout")?, sat.parse().map_err(|_| "sat")?);
    let to = h32(get(m, "--to")?)?;
    let base_fee: u128 = num(m, "--base-fee")?;
    let tip: u128 = num(m, "--tip")?;
    let mut tx = PosTransaction::TransferV2 {
        keys: vec![WitnessKey { pubkey: pubkey.to_vec(), signature: vec![0u8; sig_room] }],
        inputs: vec![TransferInputV2 { txid, vout, key_index: 0 }],
        outputs: vec![TransferOutput { value: 0, script_hash: to }],
        tx_bytes: 0, tip_millisat_per_gas: tip,
    };
    let reserved = tx.canonical_bytes().len() as u64;
    let class = fee_market::eutxo_class_for_keys(class_epoch, [pubkey]);
    let c = fee_market::charge(class, reserved, base_fee, tip);
    let fee = c.base_fee_sat + c.priority_fee_sat;
    let paid = u64::try_from(u128::from(value).checked_sub(fee).ok_or("fee above input")?).map_err(|_| "overflow")?;
    if paid < MIN_TRANSFER_OUTPUT_SAT { return Err("output below minimum".into()); }
    if let PosTransaction::TransferV2 { tx_bytes, outputs, .. } = &mut tx { *tx_bytes = reserved; outputs[0].value = paid; }
    let root = tx.checked_signing_root(epoch);
    let sig = sign(&root)?;
    if let PosTransaction::TransferV2 { keys, .. } = &mut tx { keys[0].signature = sig; }
    let enc = tx.canonical_bytes().len() as u64;
    if enc > reserved || reserved - enc > fee_market::TX_BYTES_DECLARE_SLACK { return Err(format!("encoding {enc} vs reserved {reserved}")); }
    println!("gas {} fee_sat {fee} paid_sat {paid} class {class:?}", c.gas);
    Ok(tx)
}

fn slh_transfer(m: &BTreeMap<String, String>) -> R<()> {
    let (pk, sk) = load_plain(get(m, "--dir")?)?;
    let epoch: u64 = num(m, "--epoch")?;
    let price: u64 = if m.contains_key("--price-epoch") { num(m, "--price-epoch")? } else { epoch };
    let tx = one_key_transfer(&pk, SLHDSA_FALCON_MAX_ENVELOPED_SIG_LEN, m, price, epoch, |root| {
        for _ in 0..16 {
            if let Ok(s) = crypto::sign(&sk, root) { if s.len() <= SLHDSA_FALCON_MAX_ENVELOPED_SIG_LEN { return Ok(s); } }
        }
        Err("no signature within the bound".into())
    })?;
    write_hex(get(m, "--out")?, &tx.canonical_bytes())?;
    println!("Transaction id: {}", codec::hex(&tx.txid()));
    Ok(())
}

/// A valid hybrid transfer whose ML-DSA half starts with the marker byte the
/// fault-injected pinned verifier of the pin nets refuses, and which every
/// other verifier accepts. Without the fault injection the pinned and legacy
/// verifiers agree on every valid signature, so nothing else can tell them apart.
fn marker_transfer(m: &BTreeMap<String, String>) -> R<()> {
    let (pk, sk) = load_plain(get(m, "--dir")?)?;
    let epoch: u64 = if m.contains_key("--epoch") { num(m, "--epoch")? } else { 0 };
    let room = 4 + 3309 + 1462;
    let tx = one_key_transfer(&pk, room, m, epoch, epoch, |root| {
        for _ in 0..200_000 {
            let s = crypto::sign(&sk, root).map_err(|e| format!("{e:?}"))?;
            if s.len() > 4 && s[4] == 0xA5 && crypto::verify(&pk, root, &s) { return Ok(s); }
        }
        Err("no marker signature".into())
    })?;
    write_hex(get(m, "--out")?, &tx.canonical_bytes())?;
    println!("Transaction id: {}", codec::hex(&tx.txid()));
    Ok(())
}

fn rotate(m: &BTreeMap<String, String>) -> R<()> {
    let (_, domain) = devnet(get(m, "--genesis")?)?;
    let (apk, ask) = load_plain(get(m, "--auth-dir")?)?;
    let (npk, nsk) = load_plain(get(m, "--new-dir")?)?;
    let mut tx = WithdrawalCredentialRotation {
        network_domain: domain, epoch: num(m, "--epoch")?, validator: num(m, "--validator")?,
        authorizing_pubkey: apk, new_pubkey: npk, authorizing_signature: Vec::new(), new_key_signature: Vec::new(),
    };
    let root = tx.signing_root();
    tx.authorizing_signature = crypto::sign(&ask, &root).map_err(|e| format!("{e:?}"))?;
    tx.new_key_signature = crypto::sign(&nsk, &root).map_err(|e| format!("{e:?}"))?;
    let wire = PosTransaction::WithdrawalCredentialRotation(tx.clone());
    write_hex(get(m, "--out")?, &wire.canonical_bytes())?;
    println!("new_credential {}", codec::hex(&tx.new_credential()));
    println!("Transaction id: {}", codec::hex(&wire.txid()));
    Ok(())
}

fn sign_form(m: &BTreeMap<String, String>, domain: [u8; 32], validator: u32, root: &[u8; 32]) -> R<Vec<u8>> {
    match get(m, "--form")? {
        "v1" => Ok(Keystore::load(Path::new(get(m, "--dir")?)).map_err(|e| e.to_string())?.sign(root)),
        "v2" => Ok(Keystore::load(Path::new(get(m, "--dir")?)).map_err(|e| e.to_string())?.sign_under(SignaturePolicy::Bound, root)),
        "leaf" => {
            let unlock = Unlock::from_env().map_err(|e| e.to_string())?;
            let kes = KesKey::load_optional(Path::new(get(m, "--kes-dir")?), &unlock).map_err(|e| e.to_string())?
                .ok_or("no validator.kes in --kes-dir")?;
            let msg = bloch_pos_committee::kes::leaf_message(Some(domain), validator, &kes.public(), kes.period(), root)
                .ok_or("no leaf message")?;
            kes.sign(&msg).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown form {other}")),
    }
}

fn forge_block(m: &BTreeMap<String, String>) -> R<()> {
    let (_, domain) = devnet(get(m, "--genesis")?)?;
    let original = devnet_tools::read_block_at_slot(Path::new(get(m, "--data-dir")?), num(m, "--slot")?)?;
    let mut forged = original.clone();
    forged.header.state_root[0] ^= 1;
    let root = forged.header.proposal_signing_root();
    forged.proposer_sig = sign_form(m, domain, forged.header.proposer_index, &root)?;
    net::send_block(get(m, "--to")?, &forged).map_err(|e| e.to_string())?;
    println!("slot {} proposer {} forged_id {} id8 {}", forged.header.slot, forged.header.proposer_index,
             codec::hex32(forged.block_id().as_bytes()), codec::hex8(forged.block_id().as_bytes()));
    Ok(())
}

/// Every block after `after`, paging through the store (one call is byte-capped).
fn blocks_from(dir: &Path, after: u64) -> R<Vec<BlockEnvelope>> {
    let mut out: Vec<BlockEnvelope> = Vec::new();
    let mut cursor = after;
    loop {
        let page = store::Store::blocks_after(dir, cursor, 256).map_err(|e| e.to_string())?;
        if page.is_empty() { return Ok(out); }
        for f in &page {
            let e = codec::decode_envelope(f).map_err(|x| x.to_string())?;
            cursor = cursor.max(e.header.slot);
            out.push(e);
        }
    }
}

fn forge_vote(m: &BTreeMap<String, String>) -> R<()> {
    let (_, domain) = devnet(get(m, "--genesis")?)?;
    let validator: u32 = num(m, "--validator")?;
    let dir = Path::new(get(m, "--data-dir")?);
    let mut blocks = blocks_from(dir, num(m, "--after-slot")?)?;
    blocks.reverse();
    let att = blocks.iter().flat_map(|b| b.body.attestations.iter()).filter(|a| a.validator == validator)
        .max_by_key(|a| a.data.slot).ok_or("no recent attestation by that validator")?;
    let mut data = att.data.clone();
    let head = blocks.iter().find(|b| b.block_id().as_bytes() == &data.head).ok_or("head not in tail")?;
    data.head = head.header.parent;
    let root = data.signing_root();
    let signature = sign_form(m, domain, validator, &root)?;
    let forged = Attestation { data, validator, signature };
    net::send_attestation(get(m, "--to")?, &forged).map_err(|e| e.to_string())?;
    println!("vote validator {validator} slot {} target_epoch {} root {}", forged.data.slot, forged.data.target_epoch, codec::hex(&root));
    Ok(())
}

fn proposal(e: &BlockEnvelope) -> ProposalEnvelope {
    ProposalEnvelope { header: e.header.clone(), proposer_sig: e.proposer_sig.clone() }
}

fn bad_evidence(m: &BTreeMap<String, String>) -> R<()> {
    devnet(get(m, "--genesis")?)?;
    let dir = Path::new(get(m, "--data-dir")?);
    let a = devnet_tools::read_block_at_slot(dir, num(m, "--slot")?)?;
    let tag: u32 = num(m, "--tag")?;
    let ev = match get(m, "--kind")? {
        "no-conflict" => SlashingEvidence::ProposerEquivocation { first: proposal(&a), second: proposal(&a) },
        "two-signers" => {
            let b = devnet_tools::read_block_at_slot(dir, num(m, "--slot2")?)?;
            SlashingEvidence::ProposerEquivocation { first: proposal(&a), second: proposal(&b) }
        }
        "forged-sig" => {
            let mut b = a.clone();
            b.header.state_root[0] ^= 1;
            b.header.state_root[1] = tag as u8;
            b.header.state_root[2] = (tag >> 8) as u8;
            b.proposer_sig = a.proposer_sig.clone();
            let n = b.proposer_sig.len();
            b.proposer_sig[n - 1] ^= 0x5a;
            SlashingEvidence::ProposerEquivocation { first: proposal(&a), second: proposal(&b) }
        }
        other => return Err(format!("unknown kind {other}")),
    };
    write_hex(get(m, "--out")?, &PosTransaction::SlashingEvidence(ev).canonical_bytes())?;
    println!("offender {}", a.header.proposer_index);
    Ok(())
}

/// Per epoch: how many proposer and vote signatures verify under the v1 rule,
/// under the canonical bound rule, and decode as KES signatures. Read-only.
fn sig_forms(m: &BTreeMap<String, String>) -> R<()> {
    let (man, _) = devnet(get(m, "--genesis")?)?;
    let dir = Path::new(get(m, "--data-dir")?);
    let (lo, hi): (u64, u64) = (num(m, "--from-epoch")?, num(m, "--to-epoch")?);
    let key = |i: u32| man.validators.iter().find(|v| v.index == i).map(|v| v.pubkey.clone());
    let form = |pk: &[u8], root: &[u8; 32], sig: &[u8]| -> (u64, u64, u64) {
        use crypto::SignaturePolicy as P;
        (u64::from(crypto::verify_with_policy(P::Compatible, pk, root, sig)),
         u64::from(crypto::verify_with_policy(P::Bound, pk, root, sig)),
         u64::from(bloch_pos_committee::kes::KesSignature::decode(sig).is_some()))
    };
    let mut rows: BTreeMap<u64, [u64; 8]> = BTreeMap::new();
    for e in blocks_from(dir, lo.saturating_mul(32).saturating_sub(1))? {
        let ep = epoch_of(e.header.slot);
        if ep < lo || ep > hi { continue; }
        let r = rows.entry(ep).or_default();
        if let Some(pk) = key(e.header.proposer_index) {
            let (a, b, c) = form(&pk, &e.header.proposal_signing_root(), &e.proposer_sig);
            r[0] += 1; r[1] += a; r[2] += b; r[3] += c;
        }
        for at in &e.body.attestations {
            if epoch_of(at.data.slot) != ep { continue; }
            if let Some(pk) = key(at.validator) {
                let (a, b, c) = form(&pk, &at.data.signing_root(), &at.signature);
                r[4] += 1; r[5] += a; r[6] += b; r[7] += c;
            }
        }
    }
    for (ep, r) in rows {
        println!("{{\"epoch\":{ep},\"blocks\":{},\"block_v1\":{},\"block_v2\":{},\"block_kes\":{},\"votes\":{},\"vote_v1\":{},\"vote_v2\":{},\"vote_kes\":{}}}",
                 r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    }
    Ok(())
}

pub fn main(args: &[String]) -> R<()> {
    let Some(cmd) = args.first() else { return Err("see the source header".into()) };
    let m = flags(&args[1..])?;
    match cmd.as_str() {
        "slh-keystore" => slh_keystore(&m),
        "slh-transfer" => slh_transfer(&m),
        "marker-transfer" => marker_transfer(&m),
        "rotate" => rotate(&m),
        "forge-block" => forge_block(&m),
        "forge-vote" => forge_vote(&m),
        "bad-evidence" => bad_evidence(&m),
        "sig-forms" => sig_forms(&m),
        other => Err(format!("unknown command {other}")),
    }
}
