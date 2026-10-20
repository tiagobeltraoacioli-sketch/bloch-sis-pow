// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline, review-bound funded delegation intents. Never opens a network socket.
use crate::{
    codec,
    genesis::Manifest,
    keys::{HybridVerifier, Keystore},
    rpc::Json,
};
use bloch_pos_committee::attestation::SignatureVerifier;
use bloch_pos_committee::transition::{
    funded, FundedDelegate, FundedDelegationWithdraw, FundedUndelegate, FundingInput, PosTransaction,
    TransferOutput, ValidatorCommissionUpdate,
};
use sha3::{Digest, Sha3_256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

const HELP: &str = "Offline funded delegation; never broadcasts.
prepare-delegate --genesis FILE --pubkey FILE --validator-hash HEX32 --amount SAT
  --input TXID:VOUT:SAT [--input ...] --change HEX32 --max-base-fee RATE --tip RATE --expiry EPOCH --out NEW_FILE
prepare-commission --genesis FILE --validator INDEX --commission BPS --epoch EPOCH --out NEW_FILE
prepare-undelegate --genesis FILE --pubkey FILE --delegator ID --position INDEX --epoch EPOCH --out NEW_FILE
prepare-withdraw --genesis FILE --pubkey FILE --delegator ID --position INDEX --epoch EPOCH
  --destination HEX32 --max-base-fee RATE --out NEW_FILE
inspect --tx FILE [--pubkey FILE]
sign --genesis TRUSTED_FILE --tx FILE --dir KEYSTORE --expected-root HEX32 --out NEW_FILE

Files contain canonical transaction hex; public-key files contain suite-enveloped key hex.
Inspect the complete intent and independently check the validator index/key before signing.
Signing requires the exact inspected root and trusted genesis. A signed commission inspection
requires the validator public key. Funding values are estimates, checked against actual UTXOs
by consensus. Keep passphrases out of command arguments; use the existing sealed-keystore workflow.
Activation and submission are separate. This command neither arms a gate nor submits a transaction.";

struct Args(BTreeMap<String, Vec<String>>);
impl Args {
    fn parse(args: &[String], allowed: &[&str]) -> Result<Self, String> {
        let mut map = BTreeMap::<String, Vec<String>>::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            if !allowed.contains(&flag.as_str()) {
                return Err(format!("unknown option {flag}"));
            }
            let value = iter
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?;
            let values = map.entry(flag.clone()).or_default();
            if flag != "--input" && !values.is_empty() {
                return Err(format!("duplicate option {flag}"));
            }
            values.push(value.clone());
        }
        Ok(Self(map))
    }
    fn get(&self, flag: &str) -> Result<&str, String> {
        self.0
            .get(flag)
            .and_then(|v| v.first())
            .map(String::as_str)
            .ok_or_else(|| format!("missing {flag}"))
    }
    fn number<T: std::str::FromStr>(&self, flag: &str) -> Result<T, String> {
        self.get(flag)?
            .parse()
            .map_err(|_| format!("invalid integer for {flag}"))
    }
    fn hash(&self, flag: &str) -> Result<[u8; 32], String> {
        hash(self.get(flag)?)
    }
}
fn hash(s: &str) -> Result<[u8; 32], String> {
    codec::unhex(s)?
        .try_into()
        .map_err(|_| "expected a 32-byte hex value".into())
}
fn hex_file(path: &str) -> Result<Vec<u8>, String> {
    let mut s = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(100_001)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    if s.len() > 100_000 {
        return Err("offline file exceeds limit".into());
    }
    codec::unhex(s.trim())
}
fn domain(path: &str) -> Result<[u8; 32], String> {
    let (manifest, _) = Manifest::load(Path::new(path)).map_err(|e| e.to_string())?;
    Ok(Sha3_256::digest(manifest.encode()).into())
}
fn read_tx(path: &str) -> Result<PosTransaction, String> {
    let tx = PosTransaction::from_canonical_bytes(&hex_file(path)?).map_err(|e| e.to_string())?;
    shape(&tx)?;
    Ok(tx)
}
fn shape(tx: &PosTransaction) -> Result<(), String> {
    let result = match tx {
        PosTransaction::FundedDelegate(t) => t.validate_shape(),
        PosTransaction::FundedUndelegate(t) => t.validate_shape(),
        PosTransaction::FundedDelegationWithdraw(t) => t.validate_shape(),
        PosTransaction::ValidatorCommissionUpdate(t) => t.validate_shape(),
        _ => {
            return Err("expected funded delegation, undelegation, withdrawal or commission".into())
        }
    };
    result.map_err(|e| format!("invalid intent: {e:?}"))
}
fn identity(tx: &PosTransaction) -> ([u8; 32], [u8; 32], &[u8]) {
    match tx {
        PosTransaction::FundedDelegate(t) => {
            (t.network_domain, t.signing_root(), &t.funding_signature)
        }
        PosTransaction::FundedUndelegate(t) => (t.network_domain, t.signing_root(), &t.signature),
        PosTransaction::FundedDelegationWithdraw(t) => {
            (t.network_domain, t.signing_root(), &t.signature)
        }
        PosTransaction::ValidatorCommissionUpdate(t) => {
            (t.network_domain, t.signing_root(), &t.signature)
        }
        _ => unreachable!("shape was checked"),
    }
}
fn authorization(tx: &PosTransaction, commission_key: Option<&[u8]>) -> Result<(), String> {
    if identity(tx).2.is_empty() {
        return Ok(());
    }
    let verifier = HybridVerifier::new();
    match tx {
        PosTransaction::FundedDelegate(t) => t
            .verify_authorization(&verifier)
            .map_err(|e| format!("authorization: {e:?}")),
        PosTransaction::FundedUndelegate(t) => t
            .verify_authorization(&verifier)
            .map_err(|e| format!("authorization: {e:?}")),
        PosTransaction::FundedDelegationWithdraw(t) => t
            .verify_authorization(&verifier)
            .map_err(|e| format!("authorization: {e:?}")),
        PosTransaction::ValidatorCommissionUpdate(t) => {
            let key = commission_key.ok_or("signed commission inspection requires --pubkey")?;
            if !verifier.verify_with_key(key, &t.signing_root(), &t.signature) {
                return Err("invalid commission authorization".into());
            }
            Ok(())
        }
        _ => unreachable!("shape was checked"),
    }
}
fn inspect(tx: &PosTransaction, commission_key: Option<&[u8]>) -> Result<Json, String> {
    shape(tx)?;
    authorization(tx, commission_key)?;
    let (network, root, sig) = identity(tx);
    let mut fields = vec![
        ("network_domain", Json::hex(&network)),
        ("signing_root", Json::hex(&root)),
        ("txid", Json::hex(&tx.txid())),
        ("signed", Json::Bool(!sig.is_empty())),
    ];
    match tx {
        PosTransaction::FundedDelegate(t) => fields.extend(vec![
            ("kind", Json::s("delegate")),
            (
                "funding_pubkey_hash",
                Json::hex(&Sha3_256::digest(&t.funding_pubkey).into()),
            ),
            ("validator_pubkey_hash", Json::hex(&t.validator_pubkey_hash)),
            ("amount_sat", Json::sat(t.amount_sat)),
            ("change_script_hash", Json::hex(&t.change.script_hash)),
            ("minimum_change_sat", Json::sat(t.change.value.into())),
            (
                "max_base_fee_millisat_per_gas",
                Json::sat(t.max_base_fee_millisat_per_gas),
            ),
            ("tip_millisat_per_gas", Json::sat(t.tip_millisat_per_gas)),
            ("valid_until_epoch", Json::u(t.valid_until_epoch)),
            ("reserved_tx_bytes", Json::u(t.tx_bytes)),
            (
                "required_funding_sat",
                Json::sat(t.required_funding_sat().ok_or("funding overflow")?),
            ),
            (
                "inputs",
                Json::Arr(
                    t.inputs
                        .iter()
                        .map(|i| {
                            Json::obj(vec![
                                ("txid", Json::hex(&i.txid)),
                                ("vout", Json::u(i.vout.into())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        PosTransaction::ValidatorCommissionUpdate(t) => fields.extend(vec![
            ("kind", Json::s("commission")),
            ("validator", Json::u(t.validator.into())),
            ("commission_bps", Json::sat(t.commission_bps)),
            ("epoch", Json::u(t.epoch)),
        ]),
        PosTransaction::FundedUndelegate(t) => fields.extend(vec![
            ("kind", Json::s("undelegate")),
            ("delegator", Json::u(t.delegator_id.into())),
            ("position", Json::u(t.position.into())),
            ("epoch", Json::u(t.epoch)),
            (
                "funding_pubkey_hash",
                Json::hex(&Sha3_256::digest(&t.funding_pubkey).into()),
            ),
        ]),
        PosTransaction::FundedDelegationWithdraw(t) => fields.extend(vec![
            ("kind", Json::s("withdraw")),
            ("delegator", Json::u(t.delegator_id.into())),
            ("position", Json::u(t.position.into())),
            ("epoch", Json::u(t.epoch)),
            (
                "funding_pubkey_hash",
                Json::hex(&Sha3_256::digest(&t.funding_pubkey).into()),
            ),
            (
                "destination_script_hash",
                Json::hex(&t.destination_script_hash),
            ),
            (
                "max_base_fee_millisat_per_gas",
                Json::sat(t.max_base_fee_millisat_per_gas),
            ),
        ]),
        _ => unreachable!("shape was checked"),
    }
    Ok(Json::obj(fields))
}
fn write_tx(path: &str, tx: &PosTransaction) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(|e| e.to_string())?;
    writeln!(f, "{}", codec::hex(&tx.canonical_bytes())).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
fn prepare(command: &str, args: &[String]) -> Result<(), String> {
    let allowed: &[&str] = match command {
        "prepare-delegate" => &[
            "--genesis",
            "--pubkey",
            "--validator-hash",
            "--amount",
            "--input",
            "--change",
            "--max-base-fee",
            "--tip",
            "--expiry",
            "--out",
        ],
        "prepare-commission" => &[
            "--genesis",
            "--validator",
            "--commission",
            "--epoch",
            "--out",
        ],
        "prepare-undelegate" => &[
            "--genesis",
            "--pubkey",
            "--delegator",
            "--position",
            "--epoch",
            "--out",
        ],
        "prepare-withdraw" => &[
            "--genesis",
            "--pubkey",
            "--delegator",
            "--position",
            "--epoch",
            "--destination",
            "--max-base-fee",
            "--out",
        ],
        _ => return Err("unknown preparation command".into()),
    };
    let a = Args::parse(args, allowed)?;
    let network_domain = domain(a.get("--genesis")?)?;
    let tx = match command {
        "prepare-delegate" => {
            let mut inputs = Vec::new();
            let mut total = 0u128;
            for value in
                a.0.get("--input")
                    .ok_or("at least one --input is required")?
            {
                let fields: Vec<_> = value.split(':').collect();
                if fields.len() != 3 {
                    return Err("input needs TXID:VOUT:SAT".into());
                }
                let amount: u64 = fields[2].parse().map_err(|_| "invalid input value")?;
                total = total
                    .checked_add(amount.into())
                    .ok_or("input sum overflow")?;
                inputs.push(FundingInput {
                    txid: hash(fields[0])?,
                    vout: fields[1].parse().map_err(|_| "invalid vout")?,
                });
            }
            inputs.sort();
            let mut t = FundedDelegate {
                network_domain,
                valid_until_epoch: a.number("--expiry")?,
                funding_pubkey: hex_file(a.get("--pubkey")?)?,
                inputs,
                validator_pubkey_hash: a.hash("--validator-hash")?,
                amount_sat: a.number("--amount")?,
                change: TransferOutput {
                    value: 0,
                    script_hash: a.hash("--change")?,
                },
                max_base_fee_millisat_per_gas: a.number("--max-base-fee")?,
                tip_millisat_per_gas: a.number("--tip")?,
                tx_bytes: 0,
                funding_signature: Vec::new(),
            };
            t.tx_bytes = t.reserved_tx_bytes();
            let budget = t.charge(t.max_base_fee_millisat_per_gas);
            t.change.value = total
                .checked_sub(t.amount_sat)
                .and_then(|n| n.checked_sub(budget.base_fee_sat))
                .and_then(|n| n.checked_sub(budget.priority_fee_sat))
                .ok_or("insufficient funding")?
                .try_into()
                .map_err(|_| "change exceeds u64")?;
            PosTransaction::FundedDelegate(t)
        }
        "prepare-commission" => {
            PosTransaction::ValidatorCommissionUpdate(ValidatorCommissionUpdate {
                network_domain,
                epoch: a.number("--epoch")?,
                validator: a.number("--validator")?,
                commission_bps: a.number("--commission")?,
                signature: Vec::new(),
            })
        }
        "prepare-undelegate" => PosTransaction::FundedUndelegate(FundedUndelegate {
            network_domain,
            epoch: a.number("--epoch")?,
            delegator_id: a.number("--delegator")?,
            position: a.number("--position")?,
            funding_pubkey: hex_file(a.get("--pubkey")?)?,
            signature: Vec::new(),
        }),
        "prepare-withdraw" => PosTransaction::FundedDelegationWithdraw(FundedDelegationWithdraw {
            network_domain,
            epoch: a.number("--epoch")?,
            delegator_id: a.number("--delegator")?,
            position: a.number("--position")?,
            funding_pubkey: hex_file(a.get("--pubkey")?)?,
            destination_script_hash: a.hash("--destination")?,
            max_base_fee_millisat_per_gas: a.number("--max-base-fee")?,
            signature: Vec::new(),
        }),
        _ => unreachable!(),
    };
    let info = inspect(&tx, None)?;
    write_tx(a.get("--out")?, &tx)?;
    println!("{}", info.to_string());
    Ok(())
}
pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        println!("{HELP}");
        return Ok(());
    };
    match command.as_str(){
        "help"|"--help"=>{println!("{HELP}");Ok(())},
        "prepare-delegate"|"prepare-commission"|"prepare-undelegate"|"prepare-withdraw"=>prepare(command,rest),
        "inspect"=>{let a=Args::parse(rest,&["--tx","--pubkey"])?;
            let key=a.0.get("--pubkey").map(|values|hex_file(&values[0])).transpose()?;
            println!("{}",inspect(&read_tx(a.get("--tx")?)?,key.as_deref())?.to_string());Ok(())},
        "sign"=>{
            let a=Args::parse(rest,&["--genesis","--tx","--dir","--expected-root","--out"])?;
            let mut tx=read_tx(a.get("--tx")?)?;let (network,root,sig)=identity(&tx);
            if !sig.is_empty(){return Err("refusing to replace an existing signature".into());}
            if network!=domain(a.get("--genesis")?)? {return Err("intent belongs to another genesis manifest".into());}
            if root!=a.hash("--expected-root")? {return Err("intent differs from the reviewed signing root".into());}
            let keys=Keystore::load(Path::new(a.get("--dir")?)).map_err(|e|e.to_string())?;
            let expected=match &tx {PosTransaction::FundedDelegate(t)=>Some(&t.funding_pubkey),PosTransaction::FundedUndelegate(t)=>Some(&t.funding_pubkey),PosTransaction::FundedDelegationWithdraw(t)=>Some(&t.funding_pubkey),_=>None};
            if expected.is_some_and(|key|key!=&keys.pubkey){return Err("keystore is not the intent owner".into());}
            let signed=keys.sign_fitting(&root,funded::ADMISSION_PQ_SIGNATURE_MAX)?;
            match &mut tx {PosTransaction::FundedDelegate(t)=>t.funding_signature=signed,PosTransaction::FundedUndelegate(t)=>t.signature=signed,PosTransaction::FundedDelegationWithdraw(t)=>t.signature=signed,PosTransaction::ValidatorCommissionUpdate(t)=>t.signature=signed,_=>unreachable!()}
            let info=inspect(&tx,Some(&keys.pubkey))?;write_tx(a.get("--out")?,&tx)?;println!("{}", info.to_string());Ok(())
        },
        _=>Err("expected prepare-delegate, prepare-commission, prepare-undelegate, prepare-withdraw, inspect or sign".into()),
    }
}
