// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed, local signer for the native L1 -> L2 deposit (wire tag 0x14).
//!
//! The wallet page hands this module typed arguments; the module builds the
//! transaction with the node's own consensus types (`L2Deposit`,
//! `fee_market::charge`), shows what it built (`review`) and signs exactly
//! that (`sign`). It has no networking, signs no caller-supplied digest,
//! never exports a key, and pays change only to the session's own key.
//!
//! Modelled on `tools/delegation-wallet-wasm` (commit 46e2f4d2): the same
//! `nw_alloc` / `nw_free` / `nw_call` ABI, the same account opening rules
//! (V1 legacy PBKDF2 seed first, then V2; the expected public key decides)
//! and the same single-use review fingerprint.
use bloch_crypto::crypto;
use bloch_pos_committee::{
    fee_market,
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX,
        l2_deposit::{MAX_DEPOSIT_INPUTS, MAX_L2_DEPOSIT_SAT, MIN_L2_DEPOSIT_SAT},
        FundingInput, L2Deposit, PosTransaction, TransferOutput,
    },
};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{cell::RefCell, collections::BTreeMap};
use zeroize::{Zeroize, Zeroizing};

/// The Genesis-4 mainnet admission domain: SHA3-256 of `genesis/mainnet.manifest`
/// (what `l2_deposit_cli::domain` computes and `getl2settlement.network` reports).
/// A test recomputes it from the manifest in this repository.
pub const DOMAIN: &str = "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966";
const MAX: usize = 2 * 1024 * 1024;
/// Hybrid ML-DSA-65 + Falcon-1024 public key (suite 0x0001), enveloped.
const PUBLIC_KEY_BYTES: usize = 3749;
const PUBLIC_KEY_PREFIX: [u8; 4] = [0xb1, 0x0c, 1, 0];
const ACCOUNT_CHALLENGE: &[u8] = b"BLOCH:WALLET:L2-DEPOSIT:ACCOUNT:V1";
const REVIEW_FINGERPRINT: &[u8] = b"BLOCH:WALLET:L2-DEPOSIT:REVIEW:V1";
const REVIEW_KEYS: &[&str] =
    &["recipientHex", "amountSat", "inputs", "baseFeeMillisatPerGas", "tipMillisatPerGas"];
/// `sign` takes the review fields, the fingerprint, and optionally the
/// reviewed fee and change, which must then equal the rebuilt ones.
const SIGN_ONLY_KEYS: &[&str] = &["reviewId", "feeSat", "changeSat"];
const INPUT_KEYS: &[&str] = &["txidHex", "vout", "valueSat", "scriptHashHex"];

/// Signer-side fee ceilings (review R503-1). The fee is the one value of a
/// deposit that goes to neither the owner nor the recipient, and the tip is
/// the one price the page alone decides, so the signer bounds both itself.
///
/// 1. The tip may not exceed the base fee. The base fee the page reports is
///    checked by the network (consensus requires exact conservation at the
///    including block's base fee), the tip is not; with this rule the fee is
///    at most twice what the network itself charges.
pub const MAX_TIP_PER_BASE_FEE: u128 = 1;
/// 2. The whole fee (base + priority, at the worst-case size) may not exceed
///    0.1 BLCH, whatever prices the page reports. At the floor price a
///    2-input deposit pays 2,874 sat and the largest one (128 inputs) 95,262
///    sat; with no tip the ceiling is first reached by the largest deposit
///    above 104 times the floor price (at least 44 consecutive full blocks
///    from the floor, the base fee moving 1/8 per block) and by a 2-input
///    one above 3,480 times (`the_fee_ceiling_leaves_room_for_congestion`
///    computes the table). Past that the signer refuses, nothing is signed,
///    and the owner can deposit from fewer outputs or wait.
pub const MAX_FEE_SAT: u128 = 10_000_000;

type Result<T> = std::result::Result<T, &'static str>;

fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or("missing string")
}
/// Canonical decimal string: digits only, no sign, no leading zero.
fn decimal<T: std::str::FromStr>(s: &str) -> Result<T> {
    if s.is_empty()
        || s.len() > 39
        || s.len() > 1 && s.starts_with('0')
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical integer");
    }
    s.parse().map_err(|_| "integer overflow")
}
fn number<T: std::str::FromStr>(v: &Value, key: &str) -> Result<T> {
    decimal(string(v, key)?)
}
/// A canonical decimal string or a JSON unsigned integer (input rows only).
fn number_or_integer<T: std::str::FromStr + TryFrom<u64>>(v: &Value, key: &str) -> Result<T> {
    match &v[key] {
        Value::String(s) => decimal(s),
        Value::Number(n) => {
            T::try_from(n.as_u64().ok_or("noncanonical integer")?).map_err(|_| "integer overflow")
        }
        _ => Err("missing integer"),
    }
}
fn lower_hex(s: &str, max: usize) -> Result<Vec<u8>> {
    if s.len() > max * 2
        || s.len() % 2 != 0
        || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid hex");
    }
    hex::decode(s).map_err(|_| "invalid hex")
}
fn bytes(v: &Value, key: &str, max: usize) -> Result<Vec<u8>> {
    lower_hex(string(v, key)?, max)
}
fn hash(v: &Value, key: &str) -> Result<[u8; 32]> {
    bytes(v, key, 32)?.try_into().map_err(|_| "invalid hash")
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}
/// Refuse fields this module does not understand: a page must never believe
/// an argument (a change address, a different key) was honoured.
fn only_keys(v: &Value, allowed: &[&[&str]]) -> Result<()> {
    let map = v.as_object().ok_or("missing args")?;
    if map.keys().all(|k| allowed.iter().any(|set| set.contains(&k.as_str()))) {
        Ok(())
    } else {
        Err("unsupported field")
    }
}
/// The node's ownership rule (`transition::owns`): the full key hash, or the
/// carried form (its first 20 bytes followed by twelve zero bytes).
fn owns(key_hash: &[u8; 32], script_hash: &[u8; 32]) -> bool {
    key_hash == script_hash || script_hash[20..] == [0u8; 12] && key_hash[..20] == script_hash[..20]
}

struct Built {
    tx: L2Deposit,
    review: Value,
    id: [u8; 32],
    fee: u128,
}

struct Session {
    public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
    pending: Option<[u8; 32]>,
}
impl Session {
    fn open(public: Vec<u8>, secret: Vec<u8>) -> Result<Self> {
        let secret = Zeroizing::new(secret);
        if !(public.len() == PUBLIC_KEY_BYTES && public.starts_with(&PUBLIC_KEY_PREFIX))
            || secret.len() > 16384
        {
            return Err("invalid account");
        }
        // The secret must sign for this public key; the message is a fixed,
        // domain-separated challenge, never caller data.
        let challenge = digest(&[ACCOUNT_CHALLENGE, &public].concat());
        let proof = crypto::sign(&secret, &challenge).map_err(|_| "invalid secret")?;
        if !crypto::verify(&public, &challenge, &proof) {
            return Err("account mismatch");
        }
        Ok(Self { public, secret, pending: None })
    }

    /// Build the unsigned deposit from typed arguments, exactly as
    /// `bloch-pos l2-deposit prepare` does, and describe it.
    fn build(&self, args: &Value, signing: bool) -> Result<Built> {
        only_keys(args, if signing { &[REVIEW_KEYS, SIGN_ONLY_KEYS] } else { &[REVIEW_KEYS] })?;
        let owner = digest(&self.public);
        let network_domain: [u8; 32] = hex::decode(DOMAIN).unwrap().try_into().unwrap();

        // Recipient: 20 bytes, either hex case (EIP-55 is the page's check), not zero.
        let recipient_text = string(args, "recipientHex")?;
        if recipient_text.len() != 40 {
            return Err("invalid recipient");
        }
        let recipient: [u8; 20] = lower_hex(&recipient_text.to_ascii_lowercase(), 20)
            .map_err(|_| "invalid recipient")?
            .try_into()
            .map_err(|_| "invalid recipient")?;
        if recipient == [0; 20] {
            return Err("zero recipient");
        }

        let amount_sat: u64 = number(args, "amountSat")?;
        if !(MIN_L2_DEPOSIT_SAT..=MAX_L2_DEPOSIT_SAT).contains(&amount_sat) {
            return Err("amount out of range");
        }

        let rows = args["inputs"].as_array().ok_or("missing funding")?;
        if rows.is_empty() || rows.len() > MAX_DEPOSIT_INPUTS {
            return Err("funding bound");
        }
        let mut funding = Vec::with_capacity(rows.len());
        let mut total = 0u128;
        for row in rows {
            only_keys(row, &[INPUT_KEYS])?;
            let value: u64 = number_or_integer(row, "valueSat")?;
            if value == 0 {
                return Err("empty input");
            }
            // Optional: when the page passes the output's script hash, it
            // must be one this key opens under the node's rule.
            if row.get("scriptHashHex").is_some() && !owns(&owner, &hash(row, "scriptHashHex")?) {
                return Err("funding owner mismatch");
            }
            total = total.checked_add(value.into()).ok_or("funding overflow")?;
            funding.push((
                FundingInput { txid: hash(row, "txidHex")?, vout: number_or_integer(row, "vout")? },
                value,
            ));
        }
        // Consensus order: strictly increasing (txid, vout), no duplicates.
        funding.sort();
        if !funding.windows(2).all(|w| w[0].0 < w[1].0) {
            return Err("duplicate input");
        }

        let base_fee: u128 = number(args, "baseFeeMillisatPerGas")?;
        if !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
            .contains(&base_fee)
        {
            return Err("invalid fee");
        }
        let tip: u128 = number(args, "tipMillisatPerGas")?;
        if tip > fee_market::MAX_TIP_MILLISAT_PER_GAS {
            return Err("tip above ceiling");
        }
        if tip > base_fee.saturating_mul(MAX_TIP_PER_BASE_FEE) {
            return Err("tip above base fee");
        }

        let mut tx = L2Deposit {
            network_domain,
            funding_pubkey: self.public.clone(),
            inputs: funding.iter().map(|(input, _)| input.clone()).collect(),
            amount_sat,
            recipient,
            // Change returns to the session's own key hash; no argument can move it.
            change: TransferOutput { value: 0, script_hash: owner },
            tx_bytes: 0,
            tip_millisat_per_gas: tip,
            signature: Vec::new(),
        };
        // Reserve the worst-case signature so the declared size never under-runs.
        tx.tx_bytes = (tx.canonical_bytes().len() + ADMISSION_PQ_SIGNATURE_MAX) as u64;
        let class = fee_market::TxClass::Eutxo { inputs: tx.inputs.len() as u32 };
        if fee_market::intrinsic_gas(class, tx.tx_bytes) > fee_market::MAX_TX_GAS {
            return Err("gas ceiling");
        }
        let charge = fee_market::charge(class, tx.tx_bytes, base_fee, tip);
        let fee =
            charge.base_fee_sat.checked_add(charge.priority_fee_sat).ok_or("fee overflow")?;
        if fee > MAX_FEE_SAT {
            return Err("fee above signer ceiling");
        }
        // Exact conservation: inputs = amount + change + fee.
        let change = total
            .checked_sub(u128::from(amount_sat))
            .and_then(|v| v.checked_sub(fee))
            .ok_or("inputs do not cover the amount plus fee")?;
        tx.change.value = u64::try_from(change).map_err(|_| "change overflow")?;

        let unsigned = PosTransaction::L2Deposit(tx.clone());
        let unsigned_bytes = unsigned.canonical_bytes();
        // Fingerprint of the complete typed review: the whole witness-free
        // transaction (domain, key, inputs, amount, recipient, change, size,
        // tip) and the context it was priced with.
        let mut h = Sha3_256::new();
        h.update(REVIEW_FINGERPRINT);
        h.update((unsigned_bytes.len() as u64).to_le_bytes());
        h.update(&unsigned_bytes);
        h.update(base_fee.to_le_bytes());
        h.update(fee.to_le_bytes());
        h.update(total.to_le_bytes());
        for (_, value) in &funding {
            h.update(value.to_le_bytes());
        }
        let id: [u8; 32] = h.finalize().into();
        let review = json!({
            "recipientHex": hex::encode(recipient),
            "amountSat": amount_sat.to_string(),
            "feeSat": fee.to_string(),
            "baseFeeSat": charge.base_fee_sat.to_string(),
            "priorityFeeSat": charge.priority_fee_sat.to_string(),
            "changeSat": tx.change.value.to_string(),
            "totalInputSat": total.to_string(),
            "txBytes": tx.tx_bytes.to_string(),
            "inputCount": tx.inputs.len(),
            "baseFeeMillisatPerGas": base_fee.to_string(),
            "tipMillisatPerGas": tip.to_string(),
            "ownerHashHex": hex::encode(owner),
            "changeScriptHashHex": hex::encode(tx.change.script_hash),
            "domainHex": DOMAIN,
            // The txid is witness-free, so it is already final here.
            "txid": hex::encode(unsigned.txid()),
            "reviewId": hex::encode(id),
        });
        Ok(Built { tx, review, id, fee })
    }

    fn review(&mut self, args: &Value) -> Result<Value> {
        self.pending = None;
        let built = self.build(args, false)?;
        self.pending = Some(built.id);
        Ok(built.review)
    }

    fn sign(&mut self, args: &Value) -> Result<Value> {
        // Consumed before anything else: one review authorises one attempt.
        let expected = self.pending.take().ok_or("review required")?;
        let Built { mut tx, id, fee, .. } = self.build(args, true)?;
        if hash(args, "reviewId")? != expected || id != expected {
            return Err("review changed");
        }
        if args.get("feeSat").is_some() && number::<u128>(args, "feeSat")? != fee
            || args.get("changeSat").is_some() && number::<u64>(args, "changeSat")? != tx.change.value
        {
            return Err("review changed");
        }
        let root = tx.intent_root();
        let signature = crypto::sign_fitting(&self.secret, &root, ADMISSION_PQ_SIGNATURE_MAX)
            .map_err(|_| "signature failed")?;
        if !crypto::verify(&self.public, &root, &signature) {
            return Err("signature verification failed");
        }
        tx.signature = signature;
        let fee_sat = fee.to_string();
        let change_sat = tx.change.value.to_string();
        let declared = tx.tx_bytes;
        let wire = PosTransaction::L2Deposit(tx);
        let encoded = wire.canonical_bytes();
        // The node's own decoder must return this very transaction, and the
        // declared size must cover the signed encoding.
        if PosTransaction::from_canonical_bytes(&encoded).ok().as_ref() != Some(&wire)
            || declared < encoded.len() as u64
        {
            return Err("invalid deposit");
        }
        Ok(json!({
            "transactionHex": hex::encode(&encoded),
            "txid": hex::encode(wire.txid()),
            "feeSat": fee_sat,
            "changeSat": change_sat,
        }))
    }
}

/// Freed heap memory is wiped before it returns to the allocator (review
/// R503-2): the shared crypto crates free copies of key material (the seeded
/// RNG state, temporary key encodings) without clearing them. `realloc` is
/// deliberately the default (allocate, copy, free), so the old block of a
/// grown buffer is wiped too. WASM artifact only.
#[cfg(target_arch = "wasm32")]
mod wiping {
    use std::alloc::{GlobalAlloc, Layout, System};
    pub struct Wiping;
    // SAFETY: every call is forwarded to `System` with the caller's own
    // layout; `dealloc` first writes zeros over exactly `layout.size()`
    // bytes of the block the caller owns and is giving up.
    unsafe impl GlobalAlloc for Wiping {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            System.alloc(layout)
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            System.alloc_zeroed(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            for i in 0..layout.size() {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
            System.dealloc(ptr, layout)
        }
    }
    #[global_allocator]
    static ALLOCATOR: Wiping = Wiping;
}

/// Bytes of stack overwritten after every call. The module's stack is 1 MiB
/// (the linker default for this target) and `nw_call` is entered by the host
/// near its top; the signature schemes keep key-dependent temporaries up to
/// a few hundred KiB below that.
#[cfg(target_arch = "wasm32")]
const STACK_SCRUB_BYTES: usize = 896 * 1024;

/// Overwrite the stack region the finished call used (review R503-2): the
/// signature code leaves parts of the secret key in dead stack frames.
#[cfg(target_arch = "wasm32")]
#[inline(never)]
fn scrub_stack() {
    let mut frame = [0u8; STACK_SCRUB_BYTES];
    frame.zeroize();
    core::hint::black_box(&frame);
}
#[cfg(not(target_arch = "wasm32"))]
fn scrub_stack() {}

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
            // The production web wallet derives with the V1 legacy PBKDF2
            // seed; V2 is tried second. The expected public key decides:
            // resolution never selects a different account.
            for version in [SeedVersion::V1LegacyPbkdf2Sha256, SeedVersion::V2Bip39Sha512] {
                let seed = Zeroizing::new(
                    parsed.to_seed_bytes_versioned(version, "").map_err(|_| "derivation failed")?,
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
        let result = json!({
            "publicKeyHex": hex::encode(&session.public),
            "ownerHashHex": hex::encode(digest(&session.public)),
            "domainHex": DOMAIN,
        });
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
    let packed = call(ptr, len);
    // Seeded key derivation leaves its ChaCha20 state (keyed with the account
    // seed) in the spare capacity of the shared crate's RNG stack. Entering
    // one scope with a public all-zero seed writes a fresh state over that
    // slot; nothing draws from it.
    pqcrypto_internals::with_seeded_rng_scope(&[0u8; 32], || ());
    // After the call's own frames are gone, and after every call: an open,
    // a signature and a refusal all leave key-dependent stack behind.
    scrub_stack();
    packed
}
#[inline(never)]
fn call(ptr: usize, len: u32) -> u64 {
    let request = BUFFERS.with(|b| {
        let map = b.borrow();
        let bytes = map.get(&ptr).filter(|v| v.len() == len as usize).ok_or("invalid buffer")?;
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
    BUFFERS.with(|b| b.borrow_mut().get_mut(&ptr).unwrap().copy_from_slice(&bytes));
    ((ptr as u64) << 32) | bytes.len() as u64
}

#[cfg(test)]
mod tests;
