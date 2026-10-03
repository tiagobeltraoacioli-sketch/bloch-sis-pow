//! Typed, local delegation signer. No networking, generic digest signing,
//! external recipients, key export or consensus activation.
use bloch_crypto::crypto;
use bloch_pos_committee::{
    delegation, fee_market, params, staking,
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX,
        funded_delegation::MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT, FundedDelegate,
        FundedDelegationWithdraw, FundedUndelegate, FundingInput, PosTransaction, TransferOutput,
    },
};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{cell::RefCell, collections::BTreeMap};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &str = "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966";
const MAX: usize = 2 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or("missing string")
}
fn number<T: std::str::FromStr>(v: &Value, key: &str) -> Result<T> {
    let s = string(v, key)?;
    if s.is_empty()
        || s.len() > 39
        || s.len() > 1 && s.starts_with('0')
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical integer");
    }
    s.parse().map_err(|_| "integer overflow")
}
fn bytes(v: &Value, key: &str, max: usize) -> Result<Vec<u8>> {
    let s = string(v, key)?;
    if s.len() > max * 2
        || s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid hex");
    }
    hex::decode(s).map_err(|_| "invalid hex")
}
fn hash(v: &Value, key: &str) -> Result<[u8; 32]> {
    bytes(v, key, 32)?.try_into().map_err(|_| "invalid hash")
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}
fn nullable_epoch(v: &Value, key: &str) -> Result<Option<u64>> {
    if v.get(key) == Some(&Value::Null) {
        Ok(None)
    } else {
        number(v, key).map(Some)
    }
}

struct Session {
    public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
    pending: Option<[u8; 32]>,
}
impl Session {
    fn open(public: Vec<u8>, secret: Vec<u8>) -> Result<Self> {
        let secret = Zeroizing::new(secret);
        if !(public.len() == 3749 && public.starts_with(&[0xb1, 0x0c, 1, 0]))
            || secret.len() > 16384
        {
            return Err("invalid account");
        }
        let challenge =
            digest(&[b"BLOCH:WALLET:DELEGATION:ACCOUNT:V1".as_slice(), &public].concat());
        let proof = crypto::sign(&secret, &challenge).map_err(|_| "invalid secret")?;
        if !crypto::verify(&public, &challenge, &proof) {
            return Err("account mismatch");
        }
        Ok(Self {
            public,
            secret,
            pending: None,
        })
    }
    fn build(&self, args: &Value) -> Result<(PosTransaction, Value)> {
        let c = &args["context"];
        let epoch: u64 = number(c, "epoch")?;
        if string(c, "domain")? != DOMAIN
            || c["active"] != true
            || !params::epoch_gate_active(epoch, params::FUNDED_DELEGATION_ACTIVATION_EPOCH)
            || number::<u64>(c, "activationEpoch")? != params::FUNDED_DELEGATION_ACTIVATION_EPOCH
            || number::<u64>(c, "withdrawalDelayEpochs")? != staking::WITHDRAWAL_DELAY_EPOCHS
            || number::<u64>(c, "cooldownEpochs")? != delegation::COOLDOWN_EPOCHS
        {
            return Err("inactive or incompatible network");
        }
        let owner = digest(&self.public);
        if hash(c, "ownerHash")? != owner {
            return Err("wrong owner");
        }
        let network_domain = hex::decode(DOMAIN).unwrap().try_into().unwrap();
        let base: u128 = number(c, "baseFee")?;
        if !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
            .contains(&base)
        {
            return Err("invalid fee");
        }
        let cap = base
            .checked_add(base.div_ceil(4))
            .ok_or("fee overflow")?
            .min(fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS);
        let operation = string(args, "operation")?;
        let mut review = json!({"operation": operation, "ownerHash": hex::encode(owner), "epoch": epoch.to_string(),
            "baseFee": base.to_string(), "maxBaseFee": cap.to_string(), "destination": hex::encode(owner),
            "cooldownEpochs": delegation::COOLDOWN_EPOCHS.to_string(), "withdrawalDelayEpochs": staking::WITHDRAWAL_DELAY_EPOCHS.to_string()});
        let tx = if operation == "delegate" {
            let validator = &c["validator"];
            let key_hash = hash(validator, "keyHash")?;
            if string(validator, "status")? != "active" || key_hash == [0; 32] {
                return Err("validator is not active");
            }
            let commission: u128 = number(validator, "commissionBps")?;
            if commission > 10000 {
                return Err("invalid commission");
            }
            let amount: u128 = number(args, "amountSat")?;
            let reserved: u128 = number(validator, "reservedSat")?;
            if amount < delegation::MIN_DELEGATION_SAT
                || reserved.checked_add(amount).ok_or("amount overflow")?
                    > MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT
            {
                return Err("amount or validator capacity");
            }
            let rows = c["utxos"].as_array().ok_or("missing funding")?;
            if rows.is_empty() || rows.len() > 128 {
                return Err("funding bound");
            }
            let mut total = 0u128;
            let mut inputs = Vec::new();
            for row in rows {
                if hash(row, "scriptHash")? != owner {
                    return Err("funding owner mismatch");
                }
                let value: u64 = number(row, "value")?;
                total = total.checked_add(value.into()).ok_or("funding overflow")?;
                inputs.push(FundingInput {
                    txid: hash(row, "txid")?,
                    vout: number(row, "vout")?,
                });
            }
            inputs.sort();
            let mut t = FundedDelegate {
                network_domain,
                valid_until_epoch: epoch.checked_add(1).ok_or("epoch overflow")?,
                funding_pubkey: self.public.clone(),
                inputs,
                validator_pubkey_hash: key_hash,
                amount_sat: amount,
                change: TransferOutput {
                    value: 0,
                    script_hash: owner,
                },
                max_base_fee_millisat_per_gas: cap,
                tip_millisat_per_gas: 0,
                tx_bytes: 0,
                funding_signature: Vec::new(),
            };
            t.tx_bytes = t.reserved_tx_bytes();
            let fee = t.charge(cap).base_fee_sat;
            t.change.value = total
                .checked_sub(amount)
                .and_then(|v| v.checked_sub(fee))
                .ok_or("insufficient native funding")?
                .try_into()
                .map_err(|_| "change overflow")?;
            t.validate_shape().map_err(|_| "invalid delegation")?;
            review["validatorHash"] = hex::encode(key_hash).into();
            review["validatorIndex"] = string(validator, "index")?.into();
            review["commissionBps"] = commission.to_string().into();
            review["amountSat"] = amount.to_string().into();
            review["fundingSat"] = total.to_string().into();
            review["minimumChangeSat"] = t.change.value.to_string().into();
            review["maximumFeeSat"] = fee.to_string().into();
            review["validUntilEpoch"] = t.valid_until_epoch.to_string().into();
            PosTransaction::FundedDelegate(t)
        } else {
            let p = &c["position"];
            let position: u32 = number(p, "position")?;
            if number::<u32>(args, "position")? != position
                || hash(p, "ownerHash")? != owner
                || p["withdrawn"] != false
            {
                return Err("position ownership or state");
            }
            let delegator_id: u32 = number(p, "delegator")?;
            review["position"] = position.to_string().into();
            review["delegator"] = delegator_id.to_string().into();
            if operation == "undelegate" {
                if nullable_epoch(p, "deactivateEpoch")?.is_some() {
                    return Err("exit already requested");
                }
                let t = FundedUndelegate {
                    network_domain,
                    epoch,
                    delegator_id,
                    position,
                    funding_pubkey: self.public.clone(),
                    signature: Vec::new(),
                };
                t.validate_shape().map_err(|_| "invalid exit")?;
                review["amountSat"] = string(p, "principalSat")?.into();
                review["maximumFeeSat"] = "0".into();
                PosTransaction::FundedUndelegate(t)
            } else if operation == "withdraw" {
                let inactive = nullable_epoch(p, "inactiveSince")?.ok_or("not inactive")?;
                let deactivate = nullable_epoch(p, "deactivateEpoch")?.ok_or("no exit request")?;
                let maturity = inactive
                    .checked_add(staking::WITHDRAWAL_DELAY_EPOCHS)
                    .ok_or("epoch overflow")?;
                if deactivate
                    .checked_add(delegation::COOLDOWN_EPOCHS)
                    .ok_or("epoch overflow")?
                    > inactive
                    || nullable_epoch(p, "withdrawableEpoch")? != Some(maturity)
                    || number::<u128>(p, "activatedSat")? != 0
                    || p["mature"] != true
                    || epoch < maturity
                    || number::<u64>(c, "finalizedEpoch")? < maturity
                {
                    return Err("withdrawal not mature and finalized");
                }
                let principal: u128 = number(p, "principalSat")?;
                let loss: u128 = number(p, "slashLossesSat")?;
                let fees: u128 = number(p, "feeRewardsSat")?;
                let issuance: u128 = number(p, "issuanceRewardsSat")?;
                let gross = principal
                    .checked_sub(loss)
                    .and_then(|v| v.checked_add(fees))
                    .and_then(|v| v.checked_add(issuance))
                    .ok_or("payout overflow")?;
                let mut t = FundedDelegationWithdraw {
                    network_domain,
                    epoch,
                    delegator_id,
                    position,
                    funding_pubkey: self.public.clone(),
                    destination_script_hash: owner,
                    max_base_fee_millisat_per_gas: cap,
                    signature: vec![0; ADMISSION_PQ_SIGNATURE_MAX],
                };
                let max_fee = t.charge(cap).base_fee_sat;
                let minimum: u64 = gross
                    .checked_sub(max_fee)
                    .ok_or("insufficient payout")?
                    .try_into()
                    .map_err(|_| "payout overflow")?;
                if minimum < params::MIN_TRANSFER_OUTPUT_SAT {
                    return Err("payout below minimum");
                }
                t.signature.clear();
                t.validate_shape().map_err(|_| "invalid withdrawal")?;
                review["amountSat"] = principal.to_string().into();
                review["rewardsSat"] = fees
                    .checked_add(issuance)
                    .ok_or("reward overflow")?
                    .to_string()
                    .into();
                review["slashLossesSat"] = loss.to_string().into();
                review["estimatedPayoutSat"] = minimum.to_string().into();
                review["maximumFeeSat"] = max_fee.to_string().into();
                review["withdrawableEpoch"] = maturity.to_string().into();
                PosTransaction::FundedDelegationWithdraw(t)
            } else {
                return Err("unsupported operation");
            }
        };
        review["transactionHex"] = hex::encode(tx.canonical_bytes()).into();
        let id = digest(&serde_json::to_vec(&review).map_err(|_| "review encoding")?);
        review["id"] = hex::encode(id).into();
        Ok((tx, review))
    }
    fn review(&mut self, args: &Value) -> Result<Value> {
        self.pending = None;
        let (_, review) = self.build(args)?;
        self.pending = Some(hash(&review, "id")?);
        Ok(review)
    }
    fn sign(&mut self, args: &Value) -> Result<Value> {
        let expected = self.pending.take().ok_or("review required")?;
        let (mut tx, review) = self.build(args)?;
        if args["confirmed"] != true
            || hash(args, "reviewId")? != expected
            || hash(&review, "id")? != expected
        {
            return Err("review changed");
        }
        let root = match &tx {
            PosTransaction::FundedDelegate(t) => t.signing_root(),
            PosTransaction::FundedUndelegate(t) => t.signing_root(),
            PosTransaction::FundedDelegationWithdraw(t) => t.signing_root(),
            _ => return Err("unsupported operation"),
        };
        let signature = crypto::sign(&self.secret, &root).map_err(|_| "signature failed")?;
        if !crypto::verify(&self.public, &root, &signature) {
            return Err("signature verification failed");
        }
        match &mut tx {
            PosTransaction::FundedDelegate(t) => t.funding_signature = signature,
            PosTransaction::FundedUndelegate(t) => t.signature = signature,
            PosTransaction::FundedDelegationWithdraw(t) => t.signature = signature,
            _ => unreachable!(),
        }
        Ok(
            json!({"transactionHex": hex::encode(tx.canonical_bytes()), "txid": hex::encode(tx.txid()), "review": review}),
        )
    }
}

thread_local! {
    static SESSION: RefCell<Option<Session>> = const {RefCell::new(None)};
    static BUFFERS: RefCell<BTreeMap<usize,Box<[u8]>>> = const {RefCell::new(BTreeMap::new())};
}
fn dispatch(mut request: Value) -> Result<Value> {
    let result = dispatch_inner(&mut request);
    for name in ["secretKeyHex", "mnemonic"] {
        if let Some(Value::String(s)) = request.get_mut("args").and_then(|a| a.get_mut(name)) {
            s.zeroize();
        }
    }
    if result.is_err() {
        SESSION.with(|s| {
            if let Some(s) = s.borrow_mut().as_mut() {
                s.pending = None;
            }
        });
    }
    result
}
fn dispatch_inner(request: &mut Value) -> Result<Value> {
    let method = string(request, "method")?.to_owned();
    let args = request.get_mut("args").ok_or("missing args")?;
    if method == "open_keypair" || method == "open_mnemonic" {
        SESSION.with(|s| *s.borrow_mut() = None);
        if string(args, "domainHex")? != DOMAIN {
            return Err("wrong network");
        }
        let public = bytes(args, "publicKeyHex", 8192)?;
        let session = if method == "open_keypair" {
            Session::open(public, bytes(args, "secretKeyHex", 16384)?)?
        } else {
            use bloch_crypto::wallet::seed::{SeedPhrase, SeedVersion};
            let phrase = Zeroizing::new(string(args, "mnemonic")?.to_owned());
            if phrase.len() > 1024 {
                return Err("phrase bound");
            }
            let parsed = SeedPhrase::parse(&phrase).map_err(|_| "invalid phrase")?;
            let mut found = None;
            for version in [
                SeedVersion::V1LegacyPbkdf2Sha256,
                SeedVersion::V2Bip39Sha512,
            ] {
                let seed = Zeroizing::new(
                    parsed
                        .to_seed_bytes_versioned(version, "")
                        .map_err(|_| "derivation failed")?,
                );
                let (pk, sk) = crypto::generate_keypair_from_seed(&seed[..32])
                    .map_err(|_| "key derivation failed")?;
                let secret = Zeroizing::new(sk);
                if pk == public {
                    found = Some(Session::open(pk, secret.to_vec())?);
                    break;
                }
            }
            found.ok_or("phrase account mismatch")?
        };
        let result = json!({"publicKeyHex": hex::encode(&session.public), "domainHex": DOMAIN});
        SESSION.with(|s| *s.borrow_mut() = Some(session));
        return Ok(result);
    }
    SESSION.with(|cell| {
        let mut slot = cell.borrow_mut();
        if method == "lock" {
            *slot = None;
            return Ok(json!({"locked":true}));
        }
        let s = slot.as_mut().ok_or("locked")?;
        match method.as_str() {
            "cancel" => {
                s.pending = None;
                Ok(json!({"cancelled":true}))
            }
            "review" => s.review(args),
            "sign" => s.sign(args),
            _ => Err("unsupported method"),
        }
    })
}

#[no_mangle]
pub extern "C" fn nw_alloc(len: u32) -> usize {
    if len == 0 || len as usize > MAX {
        return 0;
    }
    BUFFERS.with(|b| {
        let mut map = b.borrow_mut();
        if map.len() >= 4 || map.values().map(|v| v.len()).sum::<usize>() + len as usize > MAX * 2 {
            return 0;
        }
        let mut bytes = vec![0; len as usize].into_boxed_slice();
        let ptr = bytes.as_mut_ptr() as usize;
        map.insert(ptr, bytes);
        ptr
    })
}
#[no_mangle]
pub extern "C" fn nw_free(ptr: usize, len: u32) {
    BUFFERS.with(|b| {
        let mut m = b.borrow_mut();
        if m.get(&ptr).is_some_and(|v| v.len() == len as usize) {
            if let Some(mut v) = m.remove(&ptr) {
                v.zeroize();
            }
        }
    });
}
#[no_mangle]
pub extern "C" fn nw_call(ptr: usize, len: u32) -> u64 {
    let request = BUFFERS.with(|b| {
        let map = b.borrow();
        let bytes = map
            .get(&ptr)
            .filter(|v| v.len() == len as usize)
            .ok_or("invalid buffer")?;
        serde_json::from_slice(bytes).map_err(|_| "invalid JSON")
    });
    let result = request.and_then(dispatch);
    if result.is_err() {
        SESSION.with(|s| {
            if let Some(s) = s.borrow_mut().as_mut() {
                s.pending = None;
            }
        });
    }
    let response = match result {
        Ok(v) => json!({"ok":true,"result":v}),
        Err(e) => json!({"ok":false,"error":e}),
    };
    let bytes = serde_json::to_vec(&response).unwrap();
    let ptr = nw_alloc(bytes.len() as u32);
    if ptr == 0 {
        return 0;
    }
    BUFFERS.with(|b| {
        b.borrow_mut()
            .get_mut(&ptr)
            .unwrap()
            .copy_from_slice(&bytes)
    });
    ((ptr as u64) << 32) | bytes.len() as u64
}

#[cfg(test)]
mod tests;
