// SPDX-License-Identifier: AGPL-3.0-or-later

//! Devnet-only, NON-CONSENSUS tooling for the multi-process validator
//! lifecycle harness (VAD-04, 2026-09-11).
//!
//! Three things a fresh devnet needs that the node had no command for:
//!
//! 1. `genesis --alloc <script_hash_hex64>:<amount_sat>` — a spendable
//!    opening balance, so a funded deposit has an outpoint to name. Parsed
//!    here ([`parse_allocs`]) and reported ([`allocation_report`]) through
//!    `Manifest::allocation_outputs`, the same function `genesis_state`
//!    materialises the outputs with, so the harness never re-derives an
//!    allocation txid by hand.
//! 2. `transfer-v2` — an offline `TransferV2` builder and signer
//!    ([`build_transfer_v2`]): one witness key, one output, priced with the
//!    same `fee_market::charge` consensus applies at inclusion, signed over
//!    the same `checked_signing_root` consensus verifies.
//! 3. `devnet-equivocate` — a proposer-equivocation injector: re-signs a
//!    block THIS keystore already signed, with one `state_root` byte
//!    flipped, and hands it to a running devnet node so the slashing
//!    pipeline can be exercised end to end. Refuses any manifest that is not
//!    devnet-shaped ([`require_devnet_shape`]).
//!
//! Nothing here is consensus. Every rule this module mirrors is enforced
//! again by `bloch-pos-committee` and by the node's mempool door
//! (`engine::admissible`); the mirrors exist so a refusal happens on the
//! operator's machine, with a reason, instead of silently on the mesh. The
//! conventions are the offline CLIs' (`validator_deposit.rs`,
//! `validator_lifecycle.rs`): allow-listed `--flag value` pairs, hex files,
//! output files `create_new` at mode 0600, no secret or passphrase on argv,
//! `Keystore::load` honouring `BLOCH_KEYSTORE_ALLOW_PLAINTEXT` and
//! `BLOCH_KEYSTORE_PASSPHRASE_FILE`.

use crate::{
    codec,
    genesis::{alloc_purpose, GenesisAllocation, Manifest},
    keys::Keystore,
    net, store,
};
use bloch_pos_committee::{
    fee_market,
    header::BlockEnvelope,
    params::{MIN_TRANSFER_OUTPUT_SAT, TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH},
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX, PosTransaction, TransferInputV2, TransferOutput,
        WitnessKey,
    },
};
use sha3::{Digest, Sha3_256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Write,
    path::Path,
};

/// The most allocations a manifest may carry. Mirrors the cap
/// `Manifest::decode` enforces (`allocation count over cap`); pinned by
/// `tests::documented_constants_are_what_the_docs_say`, which encodes one
/// more than this and watches the decoder refuse it.
pub const MANIFEST_ALLOCATION_CAP: usize = 64;

pub const TRANSFER_V2_HELP: &str = "Offline TransferV2 builder and signer (devnet tooling; does not broadcast)

transfer-v2 --dir KEYSTORE_DIR --input TXID:VOUT:SAT [--input ...]
            --to SCRIPT_HASH_HEX64 --base-fee MILLISAT_PER_GAS
            --tip MILLISAT_PER_GAS [--genesis FILE] [--epoch EPOCH]
            --out NEW_FILE

Builds one TransferV2 (wire tag 0x06): ONE witness key (the keystore's
suite-enveloped public key), every --input spent through it (key_index 0),
and ONE output paying (sum of inputs - fee) to --to. The fee is
fee_market::charge at --base-fee and --tip over the canonical size, which is
exactly the charge consensus applies at inclusion. Consensus requires
spent == created + fee with the fee priced at the INCLUDING block's base fee
(next_base_fee_at the block's epoch), so pass the base fee the next block
will use — getvalidatoradmission.next_base_fee_millisat_per_gas — and
submit at once: a base-fee move between build and inclusion invalidates the
transaction (ValueNotConserved), and it must then be rebuilt.
--epoch is the epoch of the including block and feeds checked_signing_root:
it changes the signing root only once SIGHASH_NETWORK_BINDING arms
(inert at u64::MAX in this build). Default 0.
--genesis is optional: when given, every --input that is one of the
manifest's genesis allocations is checked against it (value and owner).
Outputs below the mempool dust floor are refused. Transaction files contain
hex of the canonical bytes; submit with sendrawtransaction. Consensus and
the mempool accept the format only from
TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH onward.";

pub const EQUIVOCATE_HELP: &str = "Proposer-equivocation injector (DEVNET ONLY; never point it at a real network)

devnet-equivocate --genesis FILE --dir KEYSTORE_DIR --data-dir NODE_DATA_DIR
                  --slot S --to HOST:PORT

Reads the committed block at slot S from the node's block log (blocks.log
and blocks.idx, read-only: the running node's LOCK is not taken, so
--data-dir may be the live directory or a copy of it), checks that the
block's own proposer signature verifies under the keystore at --dir — this
tool makes a devnet validator equivocate against ITSELF and refuses any
block it did not sign — flips header.state_root[0], re-signs proposer_sig
over the new proposal signing root, and sends the envelope to --to as a
devnet FRAME_BLOCK frame, the way submit-tx sends a transaction. Both block
ids are printed. Send it while the original is still recent: a node keeps
observed proposals for about two epochs and needs the block's parent.
Refused unless the manifest is devnet-shaped (empty cohort, no carryover).";

fn error(message: impl ToString) -> String {
    message.to_string()
}

/// Allow-listed `--flag value` pairs, the `validator_deposit.rs` shape.
/// Flags in `repeatable` may appear more than once; every other flag at most
/// once.
struct Flags(BTreeMap<String, Vec<String>>);

impl Flags {
    fn parse(args: &[String], allowed: &[&str], repeatable: &[&str]) -> Result<Self, String> {
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
            if !repeatable.contains(&flag.as_str()) && !values.is_empty() {
                return Err(format!("duplicate option {flag}"));
            }
            values.push(value.clone());
        }
        Ok(Self(map))
    }

    fn get(&self, flag: &str) -> Result<&str, String> {
        self.optional(flag).ok_or_else(|| format!("missing {flag}"))
    }

    fn optional(&self, flag: &str) -> Option<&str> {
        self.0.get(flag).and_then(|v| v.first()).map(String::as_str)
    }

    fn all(&self, flag: &str) -> &[String] {
        self.0.get(flag).map_or(&[], Vec::as_slice)
    }

    fn number<T: std::str::FromStr>(&self, flag: &str) -> Result<T, String> {
        self.get(flag)?
            .parse()
            .map_err(|_| format!("invalid integer for {flag}"))
    }

    fn hash(&self, flag: &str) -> Result<[u8; 32], String> {
        hash32(self.get(flag)?).map_err(|e| format!("{flag}: {e}"))
    }
}

fn hash32(hex: &str) -> Result<[u8; 32], String> {
    codec::unhex(hex)?
        .try_into()
        .map_err(|_| "needs exactly 32 bytes (64 hex digits)".to_string())
}

/// Hex of the canonical bytes, into a NEW file at mode 0600 — the same
/// contract as the deposit and lifecycle tools, so a stale file is never
/// silently overwritten.
fn write_hex_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(error)?;
    writeln!(file, "{}", codec::hex(bytes)).map_err(error)?;
    file.sync_all().map_err(error)
}

// ── genesis --alloc ─────────────────────────────────────────────────────────

/// One `--alloc <script_hash_hex64>:<amount_sat>` as a liquid genesis
/// allocation: purpose LIQUIDITY, `unlock_epoch` 0 (the field is not
/// enforced anyway — see `GenesisAllocation`). The amount must fit `u64`:
/// that is the value width of a committed eUTXO, and `Manifest::decode`
/// refuses anything wider, so it is refused here first, with a reason.
pub fn parse_alloc_spec(spec: &str) -> Result<GenesisAllocation, String> {
    let Some((hash_hex, amount)) = spec.rsplit_once(':') else {
        return Err(format!("--alloc {spec}: expected <script_hash_hex64>:<amount_sat>"));
    };
    let script_hash = hash32(hash_hex).map_err(|e| format!("--alloc script hash: {e}"))?;
    let amount_sat: u64 = amount
        .parse()
        .map_err(|_| format!("--alloc {spec}: amount_sat must be an integer that fits u64"))?;
    if amount_sat == 0 {
        return Err(format!("--alloc {spec}: a zero-value allocation funds nothing"));
    }
    Ok(GenesisAllocation {
        purpose: alloc_purpose::LIQUIDITY,
        script_hash,
        amount_sat: u128::from(amount_sat),
        unlock_epoch: 0,
    })
}

/// Every `--alloc` on the `genesis` command line, in order. Refuses more
/// than [`MANIFEST_ALLOCATION_CAP`] — the manifest would not decode.
pub fn parse_allocs(args: &[String]) -> Result<Vec<GenesisAllocation>, String> {
    let mut out = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg != "--alloc" {
            continue;
        }
        let Some(spec) = iter.next() else {
            return Err("--alloc needs <script_hash_hex64>:<amount_sat>".into());
        };
        out.push(parse_alloc_spec(spec)?);
        if out.len() > MANIFEST_ALLOCATION_CAP {
            return Err(format!(
                "more than {MANIFEST_ALLOCATION_CAP} --alloc entries: a manifest carrying \
                 more would be refused by every node that loads it"
            ));
        }
    }
    Ok(out)
}

/// One line per allocation, naming the outpoint genesis materialises for
/// it — `allocation <n>: txid=<hex64> vout=0 value_sat=<n>
/// script_hash=<hex64>`, `<n>` being the position in the manifest's list
/// (`--alloc` order, from 0). The outpoints come from
/// `Manifest::allocation_outputs`, the function `genesis_state` builds the
/// ledger with, so what is printed is what `gettxout` will answer.
pub fn allocation_report(manifest: &Manifest) -> Vec<String> {
    manifest
        .allocation_outputs()
        .iter()
        .enumerate()
        .map(|(n, e)| {
            format!(
                "allocation {n}: txid={} vout={} value_sat={} script_hash={}",
                codec::hex32(&e.txid),
                e.vout,
                e.value,
                codec::hex32(&e.script_hash)
            )
        })
        .collect()
}

// ── transfer-v2 ─────────────────────────────────────────────────────────────

/// One `--input TXID:VOUT:SAT`: the outpoint and the value the sender says
/// it holds. The value is the sender's claim; consensus resolves the real
/// output and refuses the transfer if the sum does not conserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sat: u64,
}

impl SpendInput {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut fields = text.split(':');
        let txid = hash32(fields.next().ok_or("input needs TXID:VOUT:SAT")?)
            .map_err(|e| format!("input TXID: {e}"))?;
        let vout = fields
            .next()
            .ok_or("input needs VOUT")?
            .parse()
            .map_err(|_| "invalid VOUT")?;
        let value_sat = fields
            .next()
            .ok_or("input needs SAT")?
            .parse()
            .map_err(|_| "invalid SAT")?;
        if fields.next().is_some() {
            return Err("input needs exactly TXID:VOUT:SAT".into());
        }
        Ok(SpendInput { txid, vout, value_sat })
    }
}

/// A built, signed transfer and the arithmetic behind it, so the CLI can
/// print what it did and a test can check it against `fee_market::charge`.
#[derive(Debug)]
pub struct TransferV2Plan {
    pub tx: PosTransaction,
    pub charge: fee_market::TxCharge,
    pub spent_sat: u128,
    pub fee_sat: u128,
    pub paid_sat: u64,
    pub signing_root: [u8; 32],
}

/// Build and sign a one-owner, one-output `TransferV2`.
///
/// `tx_bytes` is reserved the way the in-process rehearsal does it
/// (`validator_admission_tests.rs`): the witness slot is filled with a
/// signature-sized placeholder (`ADMISSION_PQ_SIGNATURE_MAX` bytes), the
/// canonical length of THAT is declared, and the real signature — never
/// longer — is dropped in afterwards. The declaration sits inside the signing
/// root, so it has to be fixed before signing and cannot move after.
///
/// `epoch` is the including block's epoch, handed to
/// `PosTransaction::checked_signing_root` exactly as consensus hands its own
/// committed epoch: below `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` the
/// root is the plain `spend_signing_root`.
pub fn build_transfer_v2(
    keys: &Keystore,
    inputs: &[SpendInput],
    to: [u8; 32],
    base_fee_millisat_per_gas: u128,
    tip_millisat_per_gas: u128,
    epoch: u64,
) -> Result<TransferV2Plan, String> {
    if inputs.is_empty() {
        return Err("at least one --input is required".into());
    }
    let mut seen = BTreeSet::new();
    let mut spent_sat = 0u128;
    for i in inputs {
        if !seen.insert((i.txid, i.vout)) {
            return Err(format!(
                "input {}:{} is named twice — consensus refuses a duplicate spend point",
                codec::hex32(&i.txid),
                i.vout
            ));
        }
        spent_sat = spent_sat
            .checked_add(u128::from(i.value_sat))
            .ok_or("input sum overflow")?;
    }
    if base_fee_millisat_per_gas < fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS {
        return Err(format!(
            "--base-fee {base_fee_millisat_per_gas} is below the protocol floor {}: no block \
             can ever price a transfer at it",
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS
        ));
    }
    if base_fee_millisat_per_gas > fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS {
        return Err("--base-fee is above the protocol ceiling".into());
    }
    if tip_millisat_per_gas > fee_market::MAX_TIP_MILLISAT_PER_GAS {
        return Err("--tip is above the consensus ceiling — no block could carry it".into());
    }

    // The reservation: the encoding with a maximal signature in the witness
    // slot and a zero-value output (fixed width — the value does not change
    // the length) is exactly as long as the signed transaction can be.
    let mut tx = PosTransaction::TransferV2 {
        keys: vec![WitnessKey {
            pubkey: keys.pubkey.clone(),
            signature: vec![0u8; ADMISSION_PQ_SIGNATURE_MAX],
        }],
        inputs: inputs
            .iter()
            .map(|i| TransferInputV2 { txid: i.txid, vout: i.vout, key_index: 0 })
            .collect(),
        outputs: vec![TransferOutput { value: 0, script_hash: to }],
        tx_bytes: 0,
        tip_millisat_per_gas,
    };
    let reserved = tx.canonical_bytes().len() as u64;
    // One verification per witness-table entry, and the table has one
    // entry: the class term consensus prices `apply_transfer_v2` with.
    let class = fee_market::TxClass::Eutxo { inputs: 1 };
    if fee_market::intrinsic_gas(class, reserved) > fee_market::MAX_TX_GAS {
        return Err("the transfer declares more gas than a block may spend".into());
    }
    let charge = fee_market::charge(class, reserved, base_fee_millisat_per_gas, tip_millisat_per_gas);
    let fee_sat = charge
        .base_fee_sat
        .checked_add(charge.priority_fee_sat)
        .ok_or("fee overflow")?;
    let paid = spent_sat.checked_sub(fee_sat).ok_or_else(|| {
        format!("inputs hold {spent_sat} sat, below the {fee_sat} sat fee at this base fee and tip")
    })?;
    let paid_sat = u64::try_from(paid).map_err(|_| "the output exceeds a u64 UTXO")?;
    if paid_sat < MIN_TRANSFER_OUTPUT_SAT {
        return Err(format!(
            "the output would be {paid_sat} sat, below the {MIN_TRANSFER_OUTPUT_SAT} sat \
             minimum output value the mempool relays (inputs {spent_sat} sat, fee {fee_sat} sat)"
        ));
    }
    if let PosTransaction::TransferV2 { tx_bytes, outputs, .. } = &mut tx {
        *tx_bytes = reserved;
        outputs[0].value = paid_sat;
    }
    let signing_root = tx.checked_signing_root(epoch);
    let signature = keys.sign(&signing_root);
    if let PosTransaction::TransferV2 { keys, .. } = &mut tx {
        keys[0].signature = signature;
    }
    // The declaration must cover the encoding (consensus: UnderdeclaredSize)
    // and not exceed it by more than the slack (mempool policy today,
    // consensus once TX_BYTES_BOUND arms). Both hold by construction; they
    // are checked rather than assumed because the signature length is the
    // PQ library's, not this tool's.
    let encoded = tx.canonical_bytes().len() as u64;
    if reserved < encoded {
        return Err(format!(
            "the signature made the encoding {encoded} bytes, past the {reserved} reserved"
        ));
    }
    if reserved.saturating_sub(encoded) > fee_market::TX_BYTES_DECLARE_SLACK {
        return Err("the reservation over-declares the encoding past the slack".into());
    }
    // The node's own mempool door, at the flag-day epoch: dust, table
    // discipline, price bounds, declared size and the signature, judged by
    // the code a node runs — not a re-statement of it.
    crate::engine::admissible(&tx, TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH)
        .map_err(|reason| format!("a node's mempool would refuse this transfer: {reason}"))?;
    Ok(TransferV2Plan { tx, charge, spent_sat, fee_sat, paid_sat, signing_root })
}

/// When a manifest is at hand, an input that names one of its genesis
/// allocations must agree with it: same value, and owned by this keystore.
/// Inputs that are not allocations (payouts, change, earlier transfers) are
/// not checkable offline and pass through.
fn check_inputs_against_manifest(
    manifest: &Manifest,
    inputs: &[SpendInput],
    keys: &Keystore,
) -> Result<(), String> {
    let owner: [u8; 32] = Sha3_256::digest(&keys.pubkey).into();
    let allocations = manifest.allocation_outputs();
    for i in inputs {
        let Some(a) = allocations.iter().find(|a| a.txid == i.txid && a.vout == i.vout) else {
            continue;
        };
        if a.value != i.value_sat {
            return Err(format!(
                "input {}:{} is a genesis allocation of {} sat, not {} sat",
                codec::hex32(&i.txid),
                i.vout,
                a.value,
                i.value_sat
            ));
        }
        if a.script_hash != owner {
            return Err(format!(
                "input {}:{} is a genesis allocation owned by {}, not by this keystore ({})",
                codec::hex32(&i.txid),
                i.vout,
                codec::hex32(&a.script_hash),
                codec::hex32(&owner)
            ));
        }
    }
    Ok(())
}

/// `transfer-v2 ...` — see [`TRANSFER_V2_HELP`].
pub fn transfer_v2(args: &[String]) -> Result<(), String> {
    if matches!(args.first().map(String::as_str), None | Some("--help" | "help")) {
        println!("{TRANSFER_V2_HELP}");
        return Ok(());
    }
    let a = Flags::parse(
        args,
        &["--genesis", "--dir", "--input", "--to", "--base-fee", "--tip", "--epoch", "--out"],
        &["--input"],
    )?;
    let out = a.get("--out")?;
    let inputs = a
        .all("--input")
        .iter()
        .map(|s| SpendInput::parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    let to = a.hash("--to")?;
    let base_fee: u128 = a.number("--base-fee")?;
    let tip: u128 = a.number("--tip")?;
    let epoch: u64 = match a.optional("--epoch") {
        Some(_) => a.number("--epoch")?,
        None => 0,
    };
    let keys = Keystore::load(Path::new(a.get("--dir")?)).map_err(error)?;
    if let Some(path) = a.optional("--genesis") {
        let (manifest, _) = Manifest::load(Path::new(path)).map_err(error)?;
        check_inputs_against_manifest(&manifest, &inputs, &keys)?;
    }
    let plan = build_transfer_v2(&keys, &inputs, to, base_fee, tip, epoch)?;
    let owner: [u8; 32] = Sha3_256::digest(&keys.pubkey).into();
    println!("Witness key hash: {}", codec::hex32(&owner));
    for i in &inputs {
        println!("Input: {}:{} ({} sat claimed)", codec::hex32(&i.txid), i.vout, i.value_sat);
    }
    println!(
        "Output: {} sat to {}\nBase fee (millisat/gas): {base_fee}\nTip (millisat/gas): {tip}\n\
         Gas: {}\nReserved bytes: {}\nBase fee (sat): {}\nPriority fee (sat): {}\n\
         Fee (sat): {}\nInputs (sat): {}\nSigning epoch: {epoch}\nSigning root: {}",
        plan.paid_sat,
        codec::hex32(&to),
        plan.charge.gas,
        plan.charge.tx_bytes,
        plan.charge.base_fee_sat,
        plan.charge.priority_fee_sat,
        plan.fee_sat,
        plan.spent_sat,
        codec::hex32(&plan.signing_root),
    );
    write_hex_file(out, &plan.tx.canonical_bytes())?;
    println!("Transaction id: {}", codec::hex32(&plan.tx.txid()));
    Ok(())
}

// ── devnet-equivocate ───────────────────────────────────────────────────────

/// The safety rail. A devnet manifest bonds throwaway keys and commits to no
/// carried balances: `cohort` empty and `carryover` `None`. The mainnet
/// manifest has both, and so has anything derived from it.
pub fn require_devnet_shape(manifest: &Manifest) -> Result<(), String> {
    if !manifest.cohort.is_empty() || manifest.carryover.is_some() {
        return Err(format!(
            "REFUSED: the manifest is not devnet-shaped ({} cohort members, carryover {}). \
             devnet-equivocate exists to make a DEVNET validator equivocate against itself \
             so the slashing pipeline can be rehearsed; it must never touch a real network. \
             Equivocating on a live chain is a slashable offence against your own stake.",
            manifest.cohort.len(),
            if manifest.carryover.is_some() { "committed" } else { "none" }
        ));
    }
    Ok(())
}

/// The data dir must belong to the network the manifest describes:
/// `meta.bin` is `magic ‖ version ‖ genesis digest`, written by `Store::open`
/// on first boot, and the digest is the one `Manifest::load` returns.
pub fn check_data_dir_network(data_dir: &Path, genesis_digest: &[u8; 32]) -> Result<(), String> {
    let meta = std::fs::read(data_dir.join("meta.bin"))
        .map_err(|e| format!("{} is not a bloch-pos data dir (meta.bin: {e})", data_dir.display()))?;
    match meta.get(12..44) {
        Some(recorded) if meta.len() == 44 && recorded == genesis_digest => Ok(()),
        _ => Err(format!(
            "data dir {} was initialised for a different genesis than --genesis",
            data_dir.display()
        )),
    }
}

/// The committed block at exactly `slot`, read from the node's block log the
/// way a sync answer is served (`Store::blocks_after`): read-only, no
/// data-dir lock, so a running node's directory can be read in place.
pub fn read_block_at_slot(data_dir: &Path, slot: u64) -> Result<BlockEnvelope, String> {
    if slot == 0 {
        return Err("slot 0 is the synthesized genesis block; it is never in the log".into());
    }
    let frames = store::Store::blocks_after(data_dir, slot.saturating_sub(1), 1)
        .map_err(|e| format!("cannot read the block log in {}: {e}", data_dir.display()))?;
    let Some(frame) = frames.first() else {
        return Err(format!(
            "no block at or after slot {slot} in {}",
            data_dir.display()
        ));
    };
    let env = codec::decode_envelope(frame).map_err(error)?;
    if env.header.slot != slot {
        return Err(format!(
            "no block at slot {slot}: the log's next block is at slot {}",
            env.header.slot
        ));
    }
    Ok(env)
}

/// Whether THIS keystore produced the block: its proposer signature must
/// verify under the keystore's public key over the proposal signing root.
/// That is the whole identity check — no registry replay, no operator-typed
/// index to trust.
pub fn check_signed_by(env: &BlockEnvelope, keys: &Keystore) -> Result<(), String> {
    if bloch_crypto::crypto::verify(
        &keys.pubkey,
        &env.header.proposal_signing_root(),
        &env.proposer_sig,
    ) {
        Ok(())
    } else {
        Err(format!(
            "the keystore at --dir did not sign the block at slot {} (proposer_index {}); \
             this tool only makes a validator equivocate against ITSELF",
            env.header.slot, env.header.proposer_index
        ))
    }
}

/// The conflicting block: same slot, same proposer, same body, one bit of
/// `state_root` different, re-signed by the same key over the new
/// `proposal_signing_root` — the mutation `validator_admission_tests.rs`
/// performs in process. Its id differs (the id is over the header), its
/// state root is wrong (every node rejects the block), and its signature is
/// genuine (every node that holds the original sees an equivocation).
pub fn forge_conflicting(env: &BlockEnvelope, keys: &Keystore) -> BlockEnvelope {
    let mut conflicting = env.clone();
    conflicting.header.state_root[0] ^= 1;
    conflicting.proposer_sig = keys.sign(&conflicting.header.proposal_signing_root());
    conflicting
}

/// `devnet-equivocate ...` — see [`EQUIVOCATE_HELP`].
pub fn equivocate(args: &[String]) -> Result<(), String> {
    if matches!(args.first().map(String::as_str), None | Some("--help" | "help")) {
        println!("{EQUIVOCATE_HELP}");
        return Ok(());
    }
    let a = Flags::parse(args, &["--genesis", "--dir", "--data-dir", "--slot", "--to"], &[])?;
    let (manifest, digest) = Manifest::load(Path::new(a.get("--genesis")?)).map_err(error)?;
    require_devnet_shape(&manifest)?;
    let data_dir = Path::new(a.get("--data-dir")?);
    check_data_dir_network(data_dir, &digest)?;
    let slot: u64 = a.number("--slot")?;
    let to = a.get("--to")?;
    let keys = Keystore::load(Path::new(a.get("--dir")?)).map_err(error)?;
    let original = read_block_at_slot(data_dir, slot)?;
    check_signed_by(&original, &keys)?;
    let conflicting = forge_conflicting(&original, &keys);
    net::send_block(to, &conflicting).map_err(|e| format!("cannot send to {to}: {e}"))?;
    println!(
        "slot {slot}, proposer_index {}\noriginal block id:    {}\nconflicting block id: {}\n\
         sent to {to} as FRAME_BLOCK; this transport does not acknowledge — watch the receiving \
         node for `slashing evidence against v{} admitted and broadcast`",
        original.header.proposer_index,
        codec::hex32(original.block_id().as_bytes()),
        codec::hex32(conflicting.block_id().as_bytes()),
        original.header.proposer_index,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{CarryoverCommitment, ManifestFormat, ManifestValidator};
    use crate::keys::Unlock;
    use bloch_pos_committee::beacon::RandaoChain;
    use bloch_pos_committee::derive;
    use bloch_pos_committee::header::{BlockHeaderV4, Body, VERSION_G4};
    use bloch_pos_committee::params::{
        SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH, TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH as V2_FLAG_DAY,
    };
    use bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Throwaway directory, removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "bloch-pos-devnet-tools-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create the test dir");
            TempDir(dir)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn keystore(dir: &Path, index: u32) -> Keystore {
        Keystore::generate_with(dir, index, &Unlock::PlaintextOptIn).expect("generate keys")
    }

    /// The shape `genesis_cmd` writes: one genesis validator, no cohort, no
    /// carryover, the given allocations.
    fn devnet_manifest(validator: &Keystore, allocations: Vec<GenesisAllocation>) -> Manifest {
        Manifest {
            genesis_time_ms: 1_700_000_000_000,
            slot_ms: 500,
            validators: vec![ManifestValidator {
                index: 0,
                stake_sat: 200_000 * SAT_PER_BLOCH,
                randao_commitment: RandaoChain::generate(validator.randao_seed).commitment(),
                pubkey: validator.pubkey.clone(),
                withdrawal_credentials: Vec::new(),
                commission_bps: 0,
            }],
            cohort: Vec::new(),
            carryover: None,
            allocations,
            carryover_entries: Vec::new(),
            format: ManifestFormat::V1Unbound,
            pre_state_root: std::sync::OnceLock::new(),
        }
    }

    fn alloc_spec(script_hash: &[u8; 32], amount_sat: u64) -> String {
        format!("{}:{amount_sat}", codec::hex32(script_hash))
    }

    /// Every constant the docs and messages in this module quote by value.
    #[test]
    fn documented_constants_are_what_the_docs_say() {
        assert_eq!(MANIFEST_ALLOCATION_CAP, 64);
        assert_eq!(MIN_TRANSFER_OUTPUT_SAT, 1_000);
        assert_eq!(V2_FLAG_DAY, 800);
        assert_eq!(SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH, u64::MAX);
        // The cap mirrors `Manifest::decode`: one over it does not decode.
        let dir = TempDir::new();
        let ks = keystore(&dir.path("v0"), 0);
        let alloc = |i: u64| GenesisAllocation {
            purpose: alloc_purpose::LIQUIDITY,
            script_hash: [0x51; 32],
            amount_sat: 1_000 + u128::from(i),
            unlock_epoch: 0,
        };
        let at_cap = devnet_manifest(&ks, (0..64).map(alloc).collect());
        assert!(Manifest::decode(&at_cap.encode()).is_ok());
        let over = devnet_manifest(&ks, (0..65).map(alloc).collect());
        assert!(Manifest::decode(&over.encode()).is_err());
        // The reservation's premise: a real hybrid signature never exceeds the
        // placeholder it is measured against.
        assert!(ks.sign(&[7u8; 32]).len() <= ADMISSION_PQ_SIGNATURE_MAX);
    }

    #[test]
    fn genesis_alloc_manifest_round_trips_and_genesis_state_holds_the_reported_outpoints() {
        let dir = TempDir::new();
        let ks = keystore(&dir.path("v0"), 0);
        let funder = keystore(&dir.path("funder"), crate::keys::AUTO_VALIDATOR_INDEX);
        let funder_script: [u8; 32] = Sha3_256::digest(&funder.pubkey).into();
        let args: Vec<String> = [
            "--keys", "v0", "--alloc", &alloc_spec(&funder_script, 2_500_100_000_000),
            "--out", "x", "--alloc", &alloc_spec(&[0x42; 32], 1_000_000),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let allocations = parse_allocs(&args).unwrap();
        assert_eq!(allocations.len(), 2);
        assert_eq!(allocations[0].purpose, alloc_purpose::LIQUIDITY);
        assert_eq!(allocations[0].script_hash, funder_script);
        assert_eq!(allocations[0].amount_sat, 2_500_100_000_000);
        assert_eq!(allocations[0].unlock_epoch, 0);
        assert_eq!(allocations[1].amount_sat, 1_000_000);

        let manifest = devnet_manifest(&ks, allocations.clone());
        manifest.check_supply().unwrap();
        let out = dir.path("genesis.blg");
        std::fs::write(&out, manifest.encode()).unwrap();
        let (back, _digest) = Manifest::load(&out).unwrap();
        assert_eq!(back.allocations, allocations, "both allocations must survive the file");

        // What the CLI prints is what the committed genesis ledger holds.
        let report = allocation_report(&back);
        assert_eq!(report.len(), 2);
        let state = back.genesis_state();
        for (n, line) in report.iter().enumerate() {
            let field = |key: &str| -> String {
                line.split(' ')
                    .find_map(|w| w.strip_prefix(key).map(str::to_string))
                    .unwrap_or_else(|| panic!("{key} missing in {line}"))
            };
            assert!(line.starts_with(&format!("allocation {n}: ")));
            let txid = hash32(&field("txid=")).unwrap();
            assert_eq!(field("vout="), "0");
            let value: u64 = field("value_sat=").parse().unwrap();
            let script_hash = hash32(&field("script_hash=")).unwrap();
            let entry = state.utxo(&txid, 0).expect("the printed outpoint must exist");
            assert_eq!(entry.value, value);
            assert_eq!(entry.script_hash, script_hash);
            assert_eq!(u128::from(value), allocations[n].amount_sat);
            assert_eq!(script_hash, allocations[n].script_hash);
        }
    }

    #[test]
    fn alloc_parser_refuses_malformed_specs_and_the_cap() {
        let good = alloc_spec(&[0x11; 32], 5);
        assert!(parse_alloc_spec(&good).is_ok());
        assert!(parse_alloc_spec("deadbeef:5").is_err(), "short hash");
        assert!(parse_alloc_spec(&format!("{}:0", codec::hex32(&[1; 32]))).is_err(), "zero");
        assert!(parse_alloc_spec(&format!("{}:x", codec::hex32(&[1; 32]))).is_err(), "not a number");
        assert!(
            parse_alloc_spec(&format!("{}:18446744073709551616", codec::hex32(&[1; 32]))).is_err(),
            "u64::MAX + 1 does not fit a UTXO value"
        );
        assert!(parse_alloc_spec("nocolon").is_err());
        let args = |n: usize| -> Vec<String> {
            (0..n).flat_map(|_| ["--alloc".to_string(), good.clone()]).collect()
        };
        assert_eq!(parse_allocs(&args(64)).unwrap().len(), 64);
        assert!(parse_allocs(&args(65)).is_err());
        assert!(parse_allocs(&["--alloc".to_string()]).is_err(), "dangling flag");
        assert!(parse_allocs(&["--keys".to_string(), "a".to_string()]).unwrap().is_empty());
    }

    #[test]
    fn transfer_v2_builder_prices_like_consensus_and_passes_the_mempool_door() {
        let dir = TempDir::new();
        let funder = keystore(&dir.path("funder"), crate::keys::AUTO_VALIDATOR_INDEX);
        let input = SpendInput::parse(&format!("{}:3:{}", codec::hex32(&[0x33; 32]), 50_000_000)).unwrap();
        assert_eq!(input, SpendInput { txid: [0x33; 32], vout: 3, value_sat: 50_000_000 });
        let dest = [0x77u8; 32];
        let plan = build_transfer_v2(&funder, &[input.clone()], dest, 10, 5, 0).unwrap();
        let PosTransaction::TransferV2 { keys, inputs, outputs, tx_bytes, tip_millisat_per_gas } =
            &plan.tx
        else {
            panic!("not a TransferV2");
        };
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].pubkey, funder.pubkey);
        assert_eq!(inputs, &[TransferInputV2 { txid: [0x33; 32], vout: 3, key_index: 0 }]);
        assert_eq!(*tip_millisat_per_gas, 5);
        // The charge is `fee_market::charge` over the declared size, one
        // verification: exactly what `apply_transfer_v2` will compute.
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, *tx_bytes, 10, 5);
        assert_eq!(plan.charge, charge);
        assert_eq!(plan.fee_sat, charge.base_fee_sat + charge.priority_fee_sat);
        assert_eq!(outputs, &[TransferOutput { value: plan.paid_sat, script_hash: dest }]);
        assert_eq!(u128::from(plan.paid_sat) + plan.fee_sat, 50_000_000);
        // Declared size covers the encoding and does not over-declare.
        let encoded = plan.tx.canonical_bytes().len() as u64;
        assert!(*tx_bytes >= encoded);
        assert!(*tx_bytes - encoded <= fee_market::TX_BYTES_DECLARE_SLACK);
        // Signed over the root consensus checks at this epoch.
        assert_eq!(plan.signing_root, plan.tx.checked_signing_root(0));
        assert_eq!(plan.signing_root, plan.tx.spend_signing_root());
        assert!(bloch_crypto::crypto::verify(&funder.pubkey, &plan.signing_root, &keys[0].signature));
        // The node's door: refused before the flag day, admitted from it on.
        assert!(crate::engine::admissible(&plan.tx, V2_FLAG_DAY - 1).is_err());
        assert!(crate::engine::admissible(&plan.tx, V2_FLAG_DAY).is_ok());
        // Round trip through the wire encoding the file carries.
        assert_eq!(
            PosTransaction::from_canonical_bytes(&plan.tx.canonical_bytes()).unwrap(),
            plan.tx
        );
        // Duplicate spend points are refused before any signing.
        assert!(build_transfer_v2(&funder, &[input.clone(), input], dest, 10, 5, 0).is_err());
    }

    #[test]
    fn transfer_v2_builder_refuses_dust_and_underfunded_inputs() {
        let dir = TempDir::new();
        let funder = keystore(&dir.path("funder"), crate::keys::AUTO_VALIDATOR_INDEX);
        let rich = SpendInput { txid: [0x33; 32], vout: 0, value_sat: 50_000_000 };
        let fee = build_transfer_v2(&funder, &[rich], [1; 32], 10, 5, 0).unwrap().fee_sat;
        let fee = u64::try_from(fee).unwrap();
        // One satoshi under the floor: refused, naming the floor.
        let dusty = SpendInput { txid: [0x33; 32], vout: 0, value_sat: fee + MIN_TRANSFER_OUTPUT_SAT - 1 };
        let err = build_transfer_v2(&funder, &[dusty], [1; 32], 10, 5, 0).unwrap_err();
        assert!(err.contains(&MIN_TRANSFER_OUTPUT_SAT.to_string()), "{err}");
        // Exactly the floor: accepted.
        let floor = SpendInput { txid: [0x33; 32], vout: 0, value_sat: fee + MIN_TRANSFER_OUTPUT_SAT };
        assert_eq!(build_transfer_v2(&funder, &[floor], [1; 32], 10, 5, 0).unwrap().paid_sat, MIN_TRANSFER_OUTPUT_SAT);
        // Not even the fee.
        let broke = SpendInput { txid: [0x33; 32], vout: 0, value_sat: fee - 1 };
        assert!(build_transfer_v2(&funder, &[broke], [1; 32], 10, 5, 0).is_err());
        // A base fee below the protocol floor can never be a block's.
        assert!(build_transfer_v2(&funder, &[rich], [1; 32], 9, 5, 0).is_err());
        assert!(build_transfer_v2(&funder, &[], [1; 32], 10, 5, 0).is_err());
    }

    #[test]
    fn devnet_shape_check_refuses_a_cohort_and_a_carryover() {
        let dir = TempDir::new();
        let ks = keystore(&dir.path("v0"), 0);
        let devnet = devnet_manifest(&ks, Vec::new());
        require_devnet_shape(&devnet).unwrap();
        let mut with_cohort = devnet_manifest(&ks, Vec::new());
        with_cohort.cohort = vec![0];
        let err = require_devnet_shape(&with_cohort).unwrap_err();
        assert!(err.contains("REFUSED") && err.contains("never touch a real network"), "{err}");
        let mut with_carryover = devnet_manifest(&ks, Vec::new());
        with_carryover.carryover = Some(CarryoverCommitment {
            digest: [1; 32],
            set_root: [2; 32],
            entry_count: 1,
            total_sat: 1,
        });
        assert!(require_devnet_shape(&with_carryover).is_err());
    }

    #[test]
    fn forged_block_is_signed_by_the_keystore_and_has_a_different_id() {
        let dir = TempDir::new();
        let proposer = keystore(&dir.path("proposer"), 0);
        let other = keystore(&dir.path("other"), 1);
        let header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0xa1; 32],
            state_root: [0xb2; 32],
            body_root: derive::body_root(&[]),
            slot: 7,
            proposer_index: 0,
            randao_reveal: [0xc3; 32],
            randao_mix: [0xd4; 32],
            justified_root: [0; 32],
            finalized_root: [0; 32],
            attestation_root: derive::attestation_root(&[]),
            coherence_root: [0; 32],
        };
        let original = BlockEnvelope {
            header,
            proposer_sig: proposer.sign(&header.proposal_signing_root()),
            body: Body { transactions: Vec::new(), attestations: Vec::new() },
        };
        // Into a real block log, read back while the store still holds the
        // data-dir lock — what a live node's directory looks like.
        let node_dir = dir.path("node");
        let digest = [0x5a; 32];
        let mut store_handle = store::Store::open(&node_dir, &digest).unwrap();
        store_handle.append(&original).unwrap();
        check_data_dir_network(&node_dir, &digest).unwrap();
        assert!(check_data_dir_network(&node_dir, &[0x5b; 32]).is_err());
        assert!(read_block_at_slot(&node_dir, 0).is_err(), "genesis is never in the log");
        assert!(read_block_at_slot(&node_dir, 6).unwrap_err().contains("slot 7"), "gap names the next block");
        assert!(read_block_at_slot(&node_dir, 8).is_err(), "past the tip");
        let read = read_block_at_slot(&node_dir, 7).unwrap();
        assert_eq!(read.header, original.header);
        assert_eq!(read.proposer_sig, original.proposer_sig);
        drop(store_handle);

        check_signed_by(&read, &proposer).unwrap();
        assert!(check_signed_by(&read, &other).is_err(), "someone else's block is refused");

        let forged = forge_conflicting(&read, &proposer);
        assert_ne!(forged.block_id(), original.block_id());
        assert_eq!(forged.header.slot, original.header.slot);
        assert_eq!(forged.header.proposer_index, original.header.proposer_index);
        assert_eq!(forged.header.state_root[0], original.header.state_root[0] ^ 1);
        assert_eq!(forged.header.state_root[1..], original.header.state_root[1..]);
        assert_eq!(forged.body.transactions, original.body.transactions);
        assert!(bloch_crypto::crypto::verify(
            &proposer.pubkey,
            &forged.header.proposal_signing_root(),
            &forged.proposer_sig
        ));
        assert!(
            !bloch_crypto::crypto::verify(
                &proposer.pubkey,
                &original.header.proposal_signing_root(),
                &forged.proposer_sig
            ),
            "the new signature is over the new header, not a copy of the old one"
        );
        // The frame a node receives decodes to the forged envelope.
        let frame = net::block_frame(&forged);
        assert_eq!(frame[0], net::FRAME_BLOCK);
        let decoded = codec::decode_envelope(&frame[1..]).unwrap();
        assert_eq!(decoded.header, forged.header);
        assert_eq!(decoded.proposer_sig, forged.proposer_sig);
    }
}
