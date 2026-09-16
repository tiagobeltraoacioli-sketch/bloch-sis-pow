//! Offline disposable laboratory transaction builder. Never broadcasts.
use crate::{
    codec,
    genesis::{Manifest, ManifestFormat},
    keys::Keystore,
    rpc::Json,
};
use bloch_euvm::{
    modules::{ModuleKind, SupplyConfig, TokenCharter},
    ustav::{self as n, gateway as g},
};
use bloch_pos_committee::interfaces::StateReader;
use bloch_pos_committee::transition::{
    native_dex::{bootstrap, gateway, State},
    NativeTransferPayload, PosTransaction, TransferInputV2, TransferOutput, WitnessKey,
};
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, path::Path};

pub fn run(args: &[String]) -> Result<(), String> {
    let allowed = [
        "--kind",
        "--genesis",
        "--sponsor",
        "--committee",
        "--base-fee",
        "--input-txid",
        "--input-value",
        "--source-domain",
        "--token",
        "--vault",
        "--vault-code-hash",
        "--source-tx",
        "--source-block",
        "--event-index",
        "--deposit-nonce",
        "--deposit-sender",
        "--native-recipient-public-key",
        "--mint-nonce",
        "--valid-until",
        "--fund-amount",
    ];
    let mut flags = BTreeMap::new();
    for pair in args.chunks(2) {
        if pair.len() != 2 {
            return Err("missing option value".into());
        }
        if !allowed.contains(&pair[0].as_str()) {
            return Err(format!("unknown option {}", pair[0]));
        }
        if flags.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(format!("duplicate option {}", pair[0]));
        }
    }
    let get = |key| {
        flags
            .get(key)
            .copied()
            .ok_or_else(|| format!("missing {key}"))
    };
    let kind = get("--kind")?;
    if !["info", "bootstrap", "import", "withdraw", "fund-wallet"].contains(&kind) {
        return Err("expected info/bootstrap/import/withdraw/fund-wallet".into());
    }
    let (manifest, domain) =
        Manifest::load(Path::new(get("--genesis")?)).map_err(|e| e.to_string())?;
    if manifest.format != ManifestFormat::NativeLab
        || manifest.carryover.is_some()
        || !manifest.cohort.is_empty()
    {
        return Err("requires isolated BPOSLAB1 genesis".into());
    }
    let sponsor = Keystore::load(Path::new(get("--sponsor")?)).map_err(|e| e.to_string())?;
    let committee = Keystore::load(Path::new(get("--committee")?)).map_err(|e| e.to_string())?;
    if sponsor.pubkey == committee.pubkey {
        return Err("committee keys must differ".into());
    }
    let fee: u128 = flags
        .get("--base-fee")
        .copied()
        .unwrap_or("1")
        .parse()
        .map_err(|_| "invalid base fee")?;
    let base = manifest.genesis_state();
    let script: [u8; 32] = Sha3_256::digest(&sponsor.pubkey).into();
    let (input, value) = if kind == "bootstrap" || kind == "info" {
        let o = base
            .utxos()
            .find(|o| o.script_hash == script)
            .ok_or("sponsor not funded in lab genesis")?;
        (
            TransferInputV2 {
                txid: o.txid,
                vout: o.vout,
                key_index: 0,
            },
            o.value,
        )
    } else {
        let raw = get("--input-txid")?.trim_start_matches("0x");
        if raw.len() != 64 || !raw.is_ascii() {
            return Err("invalid input txid".into());
        }
        let mut id = [0; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b =
                u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| "invalid input txid")?;
        }
        (
            TransferInputV2 {
                txid: id,
                vout: 0,
                key_index: 0,
            },
            get("--input-value")?
                .parse::<u64>()
                .map_err(|_| "invalid input value")?,
        )
    };
    let recipient = match flags.get("--native-recipient-public-key") {
        Some(raw) if raw.len() <= 16384 => codec::unhex(raw)?,
        Some(_) => return Err("recipient key exceeds limit".into()),
        None => sponsor.pubkey.clone(),
    };
    if !bloch_crypto::crypto::valid_native_hybrid_key(&recipient) {
        return Err("invalid native recipient key".into());
    }
    let valid_until: u64 = flags
        .get("--valid-until")
        .copied()
        .unwrap_or("10000")
        .parse()
        .map_err(|_| "invalid validity")?;
    let mint_nonce: u64 = flags
        .get("--mint-nonce")
        .copied()
        .unwrap_or("0")
        .parse()
        .map_err(|_| "invalid mint nonce")?;
    if kind == "withdraw" && recipient != sponsor.pubkey {
        return Err("operator withdrawal cannot sign a different owner".into());
    }
    if kind == "fund-wallet" {
        use bloch_pos_committee::{fee_market, transition::TransferInput};
        let amount = get("--fund-amount")?
            .parse::<u64>()
            .map_err(|_| "invalid funding amount")?;
        if amount == 0 {
            return Err("funding amount must be positive".into());
        }
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, 10000, fee, 0);
        let change = remaining(value, charge)?
            .checked_sub(amount)
            .filter(|n| *n > 0)
            .ok_or("insufficient funding")?;
        let mut tx = PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid: input.txid,
                vout: input.vout,
                pubkey: sponsor.pubkey.clone(),
                signature: vec![],
            }],
            outputs: vec![
                TransferOutput {
                    value: change,
                    script_hash: script,
                },
                TransferOutput {
                    value: amount,
                    script_hash: Sha3_256::digest(&recipient).into(),
                },
            ],
            tx_bytes: 10000,
            tip_millisat_per_gas: 0,
        };
        let sig = sponsor.sign(&tx.spend_signing_root());
        if let PosTransaction::Transfer { inputs, .. } = &mut tx {
            inputs[0].signature = sig;
        }
        println!(
            "{}",
            Json::obj(vec![
                ("hex", Json::s(codec::hex(&tx.canonical_bytes()))),
                ("txid", Json::hex(&tx.txid())),
                ("output_txid", Json::hex(&tx.txid())),
                ("output_value", Json::s(change.to_string())),
                ("wallet_value", Json::s(amount.to_string())),
                ("wallet_vout", Json::s("1")),
                ("recipient_hash", Json::hex(&g::recipient_hash(&recipient)))
            ])
            .to_string()
        );
        return Ok(());
    }
    let sample = sponsor.sign(&[0; 32]);
    let blch = PosTransaction::TransferV2 {
        keys: vec![WitnessKey {
            pubkey: sponsor.pubkey.clone(),
            signature: sample.clone(),
        }],
        inputs: vec![input],
        outputs: vec![TransferOutput {
            value: 1,
            script_hash: script,
        }],
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    };
    let registration = n::Registration {
        charter: TokenCharter {
            token_name: b"Synthetic laboratory asset".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: sponsor.pubkey.clone(),
            })],
        },
        nonce: [7; 32],
        initial_kyc_root: None,
    };
    let asset = registration
        .asset_id(&domain)
        .map_err(|e| format!("{e:?}"))?;
    let mut config = g::RouteConfig {
        route: g::Route {
            source_domain: Sha3_256::digest(b"isolated-synthetic-source-v1").into(),
            native_domain: domain,
            native_asset: asset,
            token: [3; 20],
            vault: [4; 20],
            decimals: 6,
            cap: 1000,
            vault_code_hash: [5; 32],
        },
        committee: vec![sponsor.pubkey.clone(), committee.pubkey.clone()],
        threshold: 2,
    };
    config.committee.sort();
    if let Some(v) = flags.get("--source-domain") {
        config.route.source_domain = fixed(v)?;
    }
    if let Some(v) = flags.get("--token") {
        config.route.token = fixed(v)?;
    }
    if let Some(v) = flags.get("--vault") {
        config.route.vault = fixed(v)?;
    }
    if let Some(v) = flags.get("--vault-code-hash") {
        config.route.vault_code_hash = fixed(v)?;
    }
    if kind == "info" {
        println!(
            "{}",
            Json::obj(vec![
                ("native_domain", Json::hex(&domain)),
                ("native_asset", Json::hex(&asset)),
                (
                    "pq_recipient_hash",
                    Json::hex(&g::recipient_hash(&recipient))
                )
            ])
            .to_string()
        );
        return Ok(());
    }

    let approvals = |hash: &[u8; 32]| {
        config
            .committee
            .iter()
            .map(|pk| {
                if *pk == sponsor.pubkey {
                    sponsor.sign(hash)
                } else {
                    committee.sign(hash)
                }
            })
            .collect::<Vec<_>>()
    };
    let native = n::Transaction {
        asset,
        inputs: vec![],
        outputs: vec![n::Output {
            owner: recipient.clone(),
            amount: 100,
        }],
        delta: 100,
        mint_nonce,
        policy_revision: 0,
        valid_until,
    };
    let mint_id = native.signing_hash(&domain).map_err(|e| format!("{e:?}"))?;
    let mut burn = [0; 32];
    let (tx, output_id, remaining) = if kind == "bootstrap" {
        let mut r = bootstrap::Request {
            domain,
            blch,
            registration,
            route: config.clone(),
            valid_until,
            native_gas: 100_000,
            issuer_signature: sample.clone(),
            approvals: approvals(&[0; 32]),
        };
        let size = r.canonical_bytes().map_err(|e| format!("{e:?}"))?.len() as u64 + 5 + 64;
        set_size(&mut r.blch, size);
        let charge = r.quote(fee).map_err(|e| format!("{e:?}"))?;
        let remaining = remaining(value, charge)?;
        set_value(&mut r.blch, remaining);
        let hash = r.authorization().map_err(|e| format!("{e:?}"))?;
        sign_base(&mut r.blch, &sponsor, &hash);
        r.issuer_signature = sponsor.sign(&hash);
        r.approvals = approvals(&hash);
        let output = r.output_txid().map_err(|e| format!("{e:?}"))?;
        (
            PosTransaction::NativeBootstrap(
                NativeTransferPayload::new(r.canonical_bytes().map_err(|e| format!("{e:?}"))?)
                    .map_err(|e| e.to_string())?,
            ),
            output,
            remaining,
        )
    } else {
        let operation = if kind == "import" {
            g::wire::Operation::Import(g::ImportRequest {
                deposit: g::Deposit {
                    route: config.route.id(),
                    nonce: flags
                        .get("--deposit-nonce")
                        .copied()
                        .unwrap_or("1")
                        .parse()
                        .map_err(|_| "invalid deposit nonce")?,
                    sender: flags
                        .get("--deposit-sender")
                        .map(|v| fixed(v))
                        .transpose()?
                        .unwrap_or([11; 20]),
                    amount: 100,
                    pq_recipient_hash: g::recipient_hash(&recipient),
                },
                source_transaction: flags
                    .get("--source-tx")
                    .map(|v| fixed(v))
                    .transpose()?
                    .unwrap_or([13; 32]),
                source_block: flags
                    .get("--source-block")
                    .map(|v| fixed(v))
                    .transpose()?
                    .unwrap_or([14; 32]),
                event_index: flags
                    .get("--event-index")
                    .copied()
                    .unwrap_or("0")
                    .parse()
                    .map_err(|_| "invalid event index")?,
                valid_until,
                transaction: native,
            })
        } else {
            let tx = n::Transaction {
                inputs: vec![n::OutPoint {
                    transaction: mint_id,
                    index: 0,
                }],
                outputs: vec![],
                delta: -100,
                mint_nonce: 0,
                ..native
            };
            burn = tx.signing_hash(&domain).map_err(|e| format!("{e:?}"))?;
            g::wire::Operation::Withdraw(g::WithdrawalRequest {
                route: config.route.id(),
                nonce: 0,
                recipient: [15; 20],
                transaction: tx,
            })
        };
        let mut r = gateway::Request {
            blch,
            gateway: g::wire::Envelope {
                domain,
                operation,
                witnesses: n::Witnesses {
                    owners: if kind == "withdraw" {
                        vec![sample.clone()]
                    } else {
                        vec![]
                    },
                    modules: vec![vec![bloch_euvm::Val::Bytes(sample)]],
                    eligibility: vec![],
                },
                approvals: approvals(&[0; 32]),
            },
            valid_until,
            native_gas: 100_000,
        };
        let size = r
            .canonical_bytes(&domain)
            .map_err(|e| format!("{e:?}"))?
            .len() as u64
            + 5
            + 64;
        set_size(&mut r.blch, size);
        let ledger = g::pools::PoolLedger::new(domain);
        let root = ledger.state_root();
        let st = State::from_parts(base.clone(), ledger, base.state_root(), root)
            .map_err(|e| format!("{e:?}"))?;
        let charge = st
            .quote_gateway_with_context(&r, fee, 5)
            .map_err(|e| format!("{e:?}"))?;
        let remaining = remaining(value, charge)?;
        set_value(&mut r.blch, remaining);
        let hash = r.authorization(&domain).map_err(|e| format!("{e:?}"))?;
        sign_base(&mut r.blch, &sponsor, &hash);
        r.gateway.witnesses.modules[0] = vec![bloch_euvm::Val::Bytes(sponsor.sign(&hash))];
        r.gateway.approvals = approvals(&hash);
        if kind == "withdraw" {
            r.gateway.witnesses.owners = vec![sponsor.sign(&hash)];
        }
        let output = r.output_txid(&domain).map_err(|e| format!("{e:?}"))?;
        let payload =
            NativeTransferPayload::new(r.canonical_bytes(&domain).map_err(|e| format!("{e:?}"))?)
                .map_err(|e| e.to_string())?;
        (
            if kind == "import" {
                PosTransaction::NativeImport(payload)
            } else {
                PosTransaction::NativeWithdrawal(payload)
            },
            output,
            remaining,
        )
    };
    println!(
        "{}",
        Json::obj(vec![
            ("hex", Json::s(codec::hex(&tx.canonical_bytes()))),
            ("txid", Json::hex(&tx.txid())),
            ("output_txid", Json::hex(&output_id)),
            ("output_value", Json::s(remaining.to_string())),
            ("native_domain", Json::hex(&domain)),
            ("native_asset", Json::hex(&asset)),
            ("route", Json::hex(&config.route.id())),
            ("recipient_hash", Json::hex(&g::recipient_hash(&recipient))),
            ("native_burn", Json::hex(&burn)),
            ("synthetic_assets", Json::Bool(true)),
            (
                "source_evidence",
                Json::s(if flags.contains_key("--source-domain") {
                    "provided-local-records"
                } else {
                    "synthetic-placeholder"
                })
            )
        ])
        .to_string()
    );
    Ok(())
}
fn remaining(value: u64, charge: bloch_pos_committee::fee_market::TxCharge) -> Result<u64, String> {
    value
        .checked_sub(
            u64::try_from(charge.base_fee_sat + charge.priority_fee_sat)
                .map_err(|_| "fee overflow")?,
        )
        .ok_or("insufficient synthetic funds".into())
}
fn set_size(tx: &mut PosTransaction, n: u64) {
    if let PosTransaction::TransferV2 { tx_bytes, .. } = tx {
        *tx_bytes = n;
    }
}
fn set_value(tx: &mut PosTransaction, n: u64) {
    if let PosTransaction::TransferV2 { outputs, .. } = tx {
        outputs[0].value = n;
    }
}
fn sign_base(tx: &mut PosTransaction, key: &Keystore, hash: &[u8; 32]) {
    if let PosTransaction::TransferV2 { keys, .. } = tx {
        keys[0].signature = key.sign(hash);
    }
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let raw = text.strip_prefix("0x").unwrap_or(text);
    if raw.len() != 2 * N || !raw.is_ascii() {
        return Err("invalid fixed hex value".into());
    }
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16)
            .map_err(|_| "invalid fixed hex value")?;
    }
    Ok(out)
}
