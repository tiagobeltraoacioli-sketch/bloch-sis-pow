//! Offline, explicit laboratory authority step. No network or broadcast code.
use super::*;
use bloch_pos_committee::{
    state_root::EutxoEntry,
    transition::native_dex::{lab_withdrawal, wallet_projection},
};
use std::str::FromStr;
struct Verifier;
impl n::Verifier for Verifier {
    fn valid_pq_key(&self, key: &[u8]) -> bool {
        bloch_crypto::crypto::valid_native_hybrid_key(key)
    }
    fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
        self.valid_pq_key(key) && bloch_crypto::crypto::verify(key, message, signature)
    }
}
fn unique_fields(value: &Json) -> Result<(), String> {
    match value {
        Json::Obj(fields) => {
            let mut seen = std::collections::BTreeSet::new();
            for (name, child) in fields {
                if !seen.insert(name) {
                    return Err("duplicate JSON field".into());
                }
                unique_fields(child)?;
            }
        }
        Json::Arr(items) => {
            for child in items {
                unique_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn read(path: &str) -> Result<Json, String> {
    use std::io::Read;
    const MAX: u64 = 12 * 1024 * 1024;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX {
        return Err("laboratory JSON exceeds limit".into());
    }
    let value =
        crate::rpc::parse_json(std::str::from_utf8(&bytes).map_err(|_| "invalid UTF-8 JSON")?)
            .map_err(str::to_string)?;
    unique_fields(&value)?;
    Ok(value)
}
fn text<'a>(value: &'a Json, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("missing string {name}"))
}
fn num<T: FromStr>(value: &Json, name: &str) -> Result<T, String> {
    let raw = text(value, name)?;
    if raw.is_empty()
        || !raw.bytes().all(|b| b.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(format!("invalid decimal {name}"));
    }
    raw.parse().map_err(|_| format!("invalid integer {name}"))
}
fn bytes(value: &Json, name: &str, max: usize) -> Result<Vec<u8>, String> {
    let raw = text(value, name)?;
    if raw.len() > max * 2 {
        return Err(format!("{name} exceeds limit"));
    }
    codec::unhex(raw)
}
fn hash<const N: usize>(value: &Json, name: &str) -> Result<[u8; N], String> {
    bytes(value, name, N)?
        .try_into()
        .map_err(|_| format!("invalid {name} length"))
}
pub(super) fn run(
    flags: &BTreeMap<&str, &str>,
    manifest: &Manifest,
    domain: [u8; 32],
    issuer: &Keystore,
    member: &Keystore,
) -> Result<Json, String> {
    let request_file = *flags.get("--request").ok_or("missing --request")?;
    let trusted_file = *flags
        .get("--trusted-view")
        .ok_or("missing independently obtained --trusted-view")?;
    if request_file == trusted_file {
        return Err(
            "request and independently obtained trusted view must be separate files".into(),
        );
    }
    let exported = read(request_file)?;
    if text(&exported, "schema")? != "postern.native-lab-withdrawal-request.v1" {
        return Err("wrong request schema".into());
    }
    let original = exported.get("quote").ok_or("missing quote")?;
    let trusted = read(trusted_file)?;
    for view in [original, &trusted] {
        if text(view, "format")? != "BPOSLAB1"
            || hash::<32>(view, "domain")? != domain
            || hash::<32>(view, "genesis")? != *manifest.genesis_id().as_bytes()
        {
            return Err("laboratory identity mismatch".into());
        }
    }
    if original.get("certificateRequired") != Some(&Json::Bool(true))
        || original.get("signingAvailable") != Some(&Json::Bool(false))
    {
        return Err("request is not awaiting a certificate".into());
    }
    if text(original, "operation")? != "withdraw" {
        return Err("wrong certificate operation".into());
    }
    let request = original.get("request").ok_or("missing typed request")?;
    if hash::<32>(request, "expectedHead")? != hash::<32>(original, "head")? {
        return Err("request head mismatch".into());
    }
    let query = lab_withdrawal::Query {
        owner: bytes(request, "ownerPublicKeyHex", 8192)?,
        route: hash(request, "route")?,
        amount: num(request, "amount")?,
        recipient: hash(request, "recipientHex20")?,
        nonce: num(request, "nonce")?,
        valid_until: num(request, "validUntil")?,
    };
    let state = project(&trusted, manifest, domain)?;
    let height = num(&trusted, "height")?;
    let prepared = state
        .lab_build_withdrawal(&query, height)
        .map_err(str::to_string)?;
    let auth = hash(original, "authorizationHex")?;
    if prepared.transaction != bytes(original, "transactionHex", 262144)?
        || prepared.authorization != auth
        || prepared.issuer_pubkey != issuer.pubkey
        || bytes(original, "issuerPublicKeyHex", 8192)? != prepared.issuer_pubkey
        || num::<u16>(original, "threshold")? != prepared.threshold
        || num::<u128>(original, "feeSat")? != prepared.fee_sat
    {
        return Err("request changed or issuer does not match current trusted state".into());
    }
    let Some(Json::Arr(authorities)) = original.get("committeePublicKeysHex") else {
        return Err("missing committee identities".into());
    };
    let public_keys = authorities
        .iter()
        .map(|k| {
            k.as_str()
                .ok_or("invalid committee key".into())
                .and_then(|s| {
                    if s.len() > 16384 {
                        Err("committee key exceeds limit".into())
                    } else {
                        codec::unhex(s)
                    }
                })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if public_keys != prepared.committee {
        return Err("committee identities do not match current state".into());
    }
    let mut approvals = Vec::with_capacity(prepared.committee.len());
    for public in &prepared.committee {
        approvals.push(if *public == issuer.pubkey {
            issuer.sign(&auth)
        } else if *public == member.pubkey {
            member.sign(&auth)
        } else {
            return Err(
                "a configured committee key is not available in this laboratory command".into(),
            );
        });
    }
    let certified = state
        .lab_certify_withdrawal(
            &query,
            height,
            auth,
            issuer.sign(&auth),
            approvals,
            &Verifier,
        )
        .map_err(str::to_string)?;
    Ok(Json::obj(vec![
        (
            "schema",
            Json::s("postern.native-lab-withdrawal-certificate.v1"),
        ),
        ("domain", Json::hex(&domain)),
        ("authorizationHex", Json::hex(&auth)),
        (
            "transactionHex",
            Json::s(codec::hex(&certified.transaction)),
        ),
    ]))
}

fn project(trusted: &Json, manifest: &Manifest, domain: [u8; 32]) -> Result<State, String> {
    if text(trusted, "format")? != "BPOSLAB1"
        || hash::<32>(trusted, "domain")? != domain
        || hash::<32>(trusted, "genesis")? != *manifest.genesis_id().as_bytes()
    {
        return Err("laboratory identity mismatch".into());
    }
    let context = trusted.get("context").ok_or("missing trusted context")?;
    let Some(Json::Arr(rows)) = context.get("utxos") else {
        return Err("missing UTXO projection".into());
    };
    if rows.len() > 4096 {
        return Err("UTXO projection exceeds limit".into());
    }
    let utxos = rows
        .iter()
        .map(|u| {
            Ok(EutxoEntry {
                txid: hash(u, "txid")?,
                vout: num(u, "vout")?,
                value: num(u, "value")?,
                script_hash: hash(u, "scriptHash")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let base = wallet_projection::base(
        domain,
        &utxos,
        num(context, "baseFeeMillisatPerGas")?,
        num(context, "blockGasUsed")?,
        num(context, "blockTxBytes")?,
        num(context, "epoch")?,
    )
    .map_err(|_| "invalid trusted base projection")?;
    let state = State::wallet_review_projection(
        base,
        &bytes(context, "nativeSnapshotHex", 4 * 1024 * 1024)?,
        hash(context, "nativeCommitmentHex")?,
        &Verifier,
    )
    .map_err(|_| "invalid trusted native snapshot")?;
    Ok(state)
}

pub(super) fn inspect(
    flags: &BTreeMap<&str, &str>,
    manifest: &Manifest,
    domain: [u8; 32],
) -> Result<Json, String> {
    let packet = read(flags.get("--request").ok_or("missing --request")?)?;
    let trusted = read(
        flags
            .get("--trusted-view")
            .ok_or("missing --trusted-view")?,
    )?;
    let state = project(&trusted, manifest, domain)?;
    let transaction =
        PosTransaction::from_canonical_bytes(&bytes(&packet, "transactionHex", 262144)?)
            .map_err(|_| "invalid canonical transaction")?;
    let PosTransaction::NativeWithdrawal(ref payload) = transaction else {
        return Err("expected NativeWithdrawal".into());
    };
    let request =
        gateway::decode(payload.as_bytes(), &domain).map_err(|_| "invalid withdrawal packet")?;
    let g::wire::Operation::Withdraw(ref withdrawal) = request.gateway.operation else {
        return Err("expected gateway withdrawal".into());
    };
    if withdrawal.transaction.delta >= 0 {
        return Err("withdrawal does not burn".into());
    }
    let amount = u64::try_from(withdrawal.transaction.delta.unsigned_abs())
        .map_err(|_| "invalid burn amount")?;
    let burn = withdrawal
        .transaction
        .signing_hash(&domain)
        .map_err(|_| "invalid native burn")?;
    let record = state
        .native()
        .gateway()
        .release_record(&withdrawal.route, withdrawal.nonce)
        .ok_or("release record not present in trusted state")?;
    if record.native_burn != burn
        || record.amount != amount
        || record.recipient != withdrawal.recipient
        || record.route != withdrawal.route
        || record.nonce != withdrawal.nonce
    {
        return Err("release record does not match decoded native burn".into());
    }
    let prefixed = |value: &[u8]| Json::s(format!("0x{}", codec::hex(value)));
    Ok(Json::obj(vec![
        ("native_domain", prefixed(&domain)),
        ("route_id", prefixed(&withdrawal.route)),
        ("native_burn", prefixed(&burn)),
        ("nonce", Json::sat(withdrawal.nonce as u128)),
        ("recipient", prefixed(&withdrawal.recipient)),
        ("amount", Json::sat(amount as u128)),
        ("transaction_id", Json::hex(&transaction.txid())),
        ("observed_head", Json::s(text(&trusted, "head")?)),
        ("observed_slot", Json::s(text(&trusted, "height")?)),
        (
            "trust",
            Json::s("decoded-transaction-and-trusted-release-record-not-finality-proof"),
        ),
    ]))
}
