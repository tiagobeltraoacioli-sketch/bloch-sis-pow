// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! spend-runbook — the executable companion to
//! `docs/integration/BLOCH-SPEND-RUNBOOK.md`.
//!
//! One binary, four subcommands, in the order the runbook runs them:
//!
//! 1. `keygen`     — a throwaway hybrid ML-DSA-65 ‖ Falcon-1024 spending
//!                   keypair, written to plain hex files. NON-PRODUCTION.
//! 2. `genesis`    — a devnet genesis manifest that includes a LIQUID
//!                   allocation to a script hash of your choosing, so a
//!                   devnet chain opens with a coin that can actually be
//!                   spent (the stock `bloch-pos genesis` opens with none).
//! 3. `build-tx`   — coin values in, signed canonical transfer hex out:
//!                   sizing, fee arithmetic against the committed base fee,
//!                   exact-conservation change, signing-root derivation,
//!                   hybrid signing, local AND-verification, decode
//!                   round-trip. Everything except broadcasting.
//! 4. `decode`     — the reverse direction, for auditing any transfer hex.
//!
//! Broadcasting is `sendrawtransaction` over the node's JSON-RPC and is left
//! to curl on purpose: that is the surface an integrator actually holds, and
//! this tool must not accumulate a private transport of its own.
//!
//! ## Why this compiles the node's own files
//!
//! The `#[path]` modules below mount `bloch-pos-node`'s `codec.rs`, `keys.rs`
//! and `genesis.rs` directly. The alternative — re-implementing the keystore,
//! manifest and hex formats here — is a second copy of a wire format, free to
//! drift, which is the exact defect family (`pow_hash`/`block_hash`,
//! `expected_bits`) this repository keeps paying for. If the node's formats
//! change, this tool follows automatically or fails to compile — both are
//! correct outcomes.
//!
//! ## Key hygiene (binding)
//!
//! This tool generates keys into plain files and prints addresses. That is
//! only acceptable because the keys are THROWAWAY: devnet coins, or dust-level
//! mainnet rehearsal amounts. It must never be pointed at treasury or
//! production key material, and it refuses to be useful for that: it cannot
//! read the node's `validator.key` keystore for signing, only its own hex
//! files.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::exit;

use sha3::{Digest, Sha3_256};

// The node's own source files — see the module comment above.
#[path = "../../../crates/bloch-pos-node/src/codec.rs"]
mod codec;
#[path = "../../../crates/bloch-pos-node/src/keys.rs"]
mod keys;
#[path = "../../../crates/bloch-pos-node/src/genesis.rs"]
mod genesis;

use bloch_pos_committee::fee_market;
use bloch_pos_committee::transition::{PosTransaction, TransferInput, TransferOutput};

/// Upper bound on one enveloped hybrid signature: 4-byte suite envelope +
/// ML-DSA-65 (3309) + Falcon-1024 (≤ 1330, variable). Used only to SIZE the
/// declared `tx_bytes` before the real signature exists — `tx_bytes` is
/// inside the signing root, so it must be fixed first, and consensus only
/// refuses a declaration BELOW the encoding (`UnderdeclaredSize`), never
/// above it.
const SIG_LEN_UPPER_BOUND: usize = 4 + 3309 + 1330;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("genesis") => genesis_cmd(&args[1..]),
        Some("build-tx") => build_tx(&args[1..]),
        Some("decode") => decode_cmd(&args[1..]),
        _ => {
            eprintln!(
                "spend-runbook — executable companion to docs/integration/BLOCH-SPEND-RUNBOOK.md\n\
                 \n\
                 USAGE:\n\
                   spend-runbook keygen --out <dir>\n\
                       Throwaway hybrid spending keypair -> <dir>/spend.pk.hex,\n\
                       <dir>/spend.sk.hex (0600). Prints both script-hash forms\n\
                       and the bloch1q/bloch1t address. NON-PRODUCTION KEYS ONLY.\n\
                   spend-runbook genesis --keys <d0,d1,...> --alloc <sh32-hex>:<sat> [--alloc ...]\n\
                                         --out <file> [--slot-ms n] [--start-in secs]\n\
                       Devnet genesis manifest with liquid allocations. Prints the\n\
                       allocation outpoints (txid:vout) the coins live at.\n\
                   spend-runbook build-tx --sk <file> --pk <file>\n\
                                          --spend <txid-hex>:<vout>:<value-sat> [--spend ...]\n\
                                          --pay <sh32-hex|address>:<sat> [--pay ...]\n\
                                          [--change <sh32-hex|address>] [--base-fee <msat/gas>]\n\
                                          [--tip <msat/gas>] [--out-hex <file>]\n\
                       Build, size, fee, sign, verify, encode. Prints the signed\n\
                       canonical hex for sendrawtransaction. Sends nothing.\n\
                   spend-runbook decode --hex <hex|@file>\n\
                       Decode canonical transfer bytes and re-verify every signature."
            );
            exit(2);
        }
    }
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if a == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        }
    }
    out
}

fn bail(msg: &str) -> ! {
    eprintln!("spend-runbook: {msg}");
    exit(1)
}

fn unhex32(s: &str, what: &str) -> [u8; 32] {
    match codec::unhex(s) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        }
        Ok(b) => bail(&format!("{what}: {} bytes, expected 32", b.len())),
        Err(e) => bail(&format!("{what}: {e}")),
    }
}

/// A destination: either a 64-hex-char script hash (used verbatim) or a
/// `bloch1q…`/`bloch1t…` address (20-byte hash, zero-extended to 32 — the
/// same `owns` convention the node applies, rpc.rs / transition.rs).
fn dest_script_hash(s: &str) -> [u8; 32] {
    if s.starts_with("bloch1") {
        match bloch_crypto::address::Address::parse(s) {
            Ok(a) => {
                let mut sh = [0u8; 32];
                sh[..20].copy_from_slice(a.hash());
                sh
            }
            Err(e) => bail(&format!("address {s}: {e:?}")),
        }
    } else {
        unhex32(s, "script hash")
    }
}

// ─── keygen ─────────────────────────────────────────────────────────────────

fn keygen(args: &[String]) {
    let Some(dir) = arg_value(args, "--out") else {
        bail("keygen: --out <dir> is required");
    };
    let dir = PathBuf::from(dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        bail(&format!("keygen: cannot create {}: {e}", dir.display()));
    }
    let (pk, sk) = bloch_crypto::crypto::generate_keypair();

    let pk_path = dir.join("spend.pk.hex");
    let sk_path = dir.join("spend.sk.hex");
    if sk_path.exists() {
        bail(&format!(
            "keygen: {} already exists — refusing to overwrite a key",
            sk_path.display()
        ));
    }
    std::fs::write(&pk_path, codec::hex(&pk)).unwrap_or_else(|e| bail(&format!("{e}")));
    std::fs::write(&sk_path, codec::hex(&sk)).unwrap_or_else(|e| bail(&format!("{e}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600));
    }

    let full: [u8; 32] = Sha3_256::digest(&pk).into();
    let mut addr_form = [0u8; 32];
    addr_form[..20].copy_from_slice(&full[..20]);
    let mainnet =
        bloch_crypto::address::Address::from_pubkey(&pk, bloch_crypto::address::Network::Mainnet);
    let testnet =
        bloch_crypto::address::Address::from_pubkey(&pk, bloch_crypto::address::Network::Testnet);

    println!("wrote {}", pk_path.display());
    println!("wrote {} (mode 0600)", sk_path.display());
    println!("pubkey_len            : {} bytes (suite-enveloped hybrid)", pk.len());
    println!("script_hash (full 32) : {}", codec::hex32(&full));
    println!("script_hash (addr20+0): {}", codec::hex32(&addr_form));
    println!("address (mainnet)     : {mainnet}");
    println!("address (testnet)     : {testnet}");
    println!();
    println!("Either script_hash form is spendable by this key (`owns`, rpc.rs).");
    println!("Outputs paid to the ADDRESS use the addr20+0 form; getbalance and");
    println!("getutxos take whichever form the output was created under.");
    eprintln!("\nTHROWAWAY KEY. Do not fund it with more than a rehearsal amount.");
}

// ─── genesis ────────────────────────────────────────────────────────────────

fn genesis_cmd(args: &[String]) {
    let Some(keys_csv) = arg_value(args, "--keys") else {
        bail("genesis: --keys <dir1,dir2,...> is required");
    };
    let Some(out) = arg_value(args, "--out") else {
        bail("genesis: --out <file> is required");
    };
    let slot_ms: u64 = arg_value(args, "--slot-ms").and_then(|s| s.parse().ok()).unwrap_or(2_000);
    let start_in: u64 = arg_value(args, "--start-in").and_then(|s| s.parse().ok()).unwrap_or(5);

    let mut validators = Vec::new();
    for (i, dir) in keys_csv.split(',').enumerate() {
        let ks = match keys::Keystore::load(Path::new(dir)) {
            Ok(k) => k,
            Err(e) => bail(&format!("genesis: cannot load keystore {dir}: {e}")),
        };
        if ks.index != i as u32 {
            bail(&format!(
                "genesis: keystore {dir} carries index {} but sits at position {i}",
                ks.index
            ));
        }
        // Same uneven-stake pattern as `bloch-pos genesis`, so nothing about
        // the consensus run differs from the stock devnet.
        let stake_sat: u128 =
            (i as u128 % 3 + 1) * 200_000 * bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH;
        validators.push(genesis::ManifestValidator {
            index: ks.index,
            stake_sat,
            randao_commitment: bloch_pos_committee::beacon::RandaoChain::generate(ks.randao_seed)
                .commitment(),
            pubkey: ks.pubkey.clone(),
            withdrawal_credentials: Vec::new(),
            commission_bps: 0,
        });
    }

    let mut allocations = Vec::new();
    for spec in arg_values(args, "--alloc") {
        let Some((sh_hex, sat)) = spec.rsplit_once(':') else {
            bail(&format!("--alloc {spec}: expected <script-hash-hex>:<sat>"));
        };
        let script_hash = dest_script_hash(sh_hex);
        let Ok(amount_sat) = sat.parse::<u128>() else {
            bail(&format!("--alloc: bad satoshi amount {sat}"));
        };
        allocations.push(genesis::GenesisAllocation {
            // LIQUIDITY is the one bucket whose function is to be liquid at
            // genesis; a devnet rehearsal coin is exactly that.
            purpose: genesis::alloc_purpose::LIQUIDITY,
            script_hash,
            amount_sat,
            unlock_epoch: 0,
        });
    }
    if allocations.is_empty() {
        bail("genesis: at least one --alloc is required — a devnet with no allocation opens with nothing to spend");
    }

    let manifest = genesis::Manifest {
        genesis_time_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + start_in * 1000,
        slot_ms,
        validators,
        cohort: Vec::new(),
        carryover: None,
        allocations,
        carryover_entries: Vec::new(),
    };
    if let Err(e) = manifest.check_supply() {
        bail(&format!("genesis: {e}"));
    }
    let bytes = manifest.encode();
    // Round-trip through the node's own decoder before writing: a manifest
    // this tool encodes but the node cannot decode must die here, not at
    // `bloch-pos run`.
    if let Err(e) = genesis::Manifest::decode(&bytes) {
        bail(&format!("genesis: encode/decode round-trip failed: {e:?}"));
    }
    std::fs::write(&out, &bytes).unwrap_or_else(|e| bail(&format!("cannot write {out}: {e}")));

    println!(
        "wrote {out}: {} validators, slot {slot_ms} ms, genesis block {}",
        manifest.validators.len(),
        codec::hex8(manifest.genesis_id().as_bytes()),
    );
    for e in manifest.allocation_outputs() {
        println!(
            "allocation outpoint  : {}:{}  value {} sat  script_hash {}",
            codec::hex32(&e.txid),
            e.vout,
            e.value,
            codec::hex32(&e.script_hash),
        );
    }
}

// ─── build-tx ───────────────────────────────────────────────────────────────

struct Spend {
    txid: [u8; 32],
    vout: u32,
    value: u64,
}

fn build_tx(args: &[String]) {
    let sk = read_key_file(&arg_value(args, "--sk").unwrap_or_else(|| bail("--sk <file> is required")));
    let pk = read_key_file(&arg_value(args, "--pk").unwrap_or_else(|| bail("--pk <file> is required")));

    // What the key can spend, checked before anything is built: catching a
    // key/coin mismatch here beats a ScriptMismatch after inclusion fails.
    let key_hash: [u8; 32] = Sha3_256::digest(&pk).into();

    let mut spends: Vec<Spend> = Vec::new();
    for spec in arg_values(args, "--spend") {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() != 3 {
            bail(&format!("--spend {spec}: expected <txid-hex>:<vout>:<value-sat>"));
        }
        spends.push(Spend {
            txid: unhex32(parts[0], "--spend txid"),
            vout: parts[1].parse().unwrap_or_else(|_| bail(&format!("--spend: bad vout {}", parts[1]))),
            value: parts[2].parse().unwrap_or_else(|_| bail(&format!("--spend: bad value {}", parts[2]))),
        });
    }
    if spends.is_empty() {
        bail("at least one --spend <txid-hex>:<vout>:<value-sat> is required");
    }

    let mut pays: Vec<TransferOutput> = Vec::new();
    for spec in arg_values(args, "--pay") {
        let Some((dest, sat)) = spec.rsplit_once(':') else {
            bail(&format!("--pay {spec}: expected <script-hash-hex|address>:<sat>"));
        };
        pays.push(TransferOutput {
            value: sat.parse().unwrap_or_else(|_| bail(&format!("--pay: bad value {sat}"))),
            script_hash: dest_script_hash(dest),
        });
    }
    if pays.is_empty() {
        bail("at least one --pay is required");
    }

    let change_sh = arg_value(args, "--change").map(|s| dest_script_hash(&s));
    let base_fee: u128 = arg_value(args, "--base-fee")
        .and_then(|s| s.parse().ok())
        .unwrap_or(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS);
    let tip: u128 = arg_value(args, "--tip").and_then(|s| s.parse().ok()).unwrap_or(0);

    let sum_in: u128 = spends.iter().map(|s| s.value as u128).sum();
    let sum_pay: u128 = pays.iter().map(|o| o.value as u128).sum();
    let n_inputs = spends.len() as u32;

    // ── Sizing and the exact-conservation change ────────────────────────────
    //
    // `tx_bytes` sits INSIDE the signing root, so it must be final before
    // signing; the Falcon half of the signature is variable-length, so the
    // exact encoding cannot be known before signing. The resolution is the
    // one consensus permits: declare an UPPER BOUND (a dummy signature of
    // maximal length), which satisfies `UnderdeclaredSize` for any real
    // signature and costs a few hundred sat of over-declared gas.
    //
    // Conservation is EXACT (`spent == created + fee`, transition.rs), so the
    // change output is derived, not chosen — and if the change would be zero
    // the output is dropped and the fee recomputed over the smaller shape.
    let dummy_sig = vec![0u8; SIG_LEN_UPPER_BOUND];
    let build = |outputs: Vec<TransferOutput>, tx_bytes: u64| -> PosTransaction {
        PosTransaction::Transfer {
            inputs: spends
                .iter()
                .map(|s| TransferInput {
                    txid: s.txid,
                    vout: s.vout,
                    pubkey: pk.clone(),
                    signature: dummy_sig.clone(),
                })
                .collect(),
            outputs,
            tx_bytes,
            tip_millisat_per_gas: tip,
        }
    };

    let shape = |with_change: bool| -> (Vec<TransferOutput>, u64, fee_market::TxCharge) {
        let mut outs = pays.clone();
        if with_change {
            outs.push(TransferOutput { value: 0, script_hash: change_sh.unwrap_or([0u8; 32]) });
        }
        let sized = build(outs.clone(), 0);
        let tx_bytes = sized.canonical_bytes().len() as u64;
        let charge =
            fee_market::charge(fee_market::TxClass::Eutxo { inputs: n_inputs }, tx_bytes, base_fee, tip);
        (outs, tx_bytes, charge)
    };

    // First assume a change output exists, then correct if it comes out zero.
    let (mut outputs, mut tx_bytes, mut charge) = shape(change_sh.is_some());
    let mut fee = charge.base_fee_sat + charge.priority_fee_sat;
    if change_sh.is_some() {
        if sum_in < sum_pay + fee {
            bail(&format!(
                "insufficient funds: inputs {sum_in} sat < pays {sum_pay} + fee {fee}"
            ));
        }
        let change = sum_in - sum_pay - fee;
        if change == 0 {
            let (o, t, c) = shape(false);
            outputs = o;
            tx_bytes = t;
            charge = c;
            fee = charge.base_fee_sat + charge.priority_fee_sat;
            if sum_in != sum_pay + fee {
                bail(&format!(
                    "conservation cannot be met without change: inputs {sum_in} != pays {sum_pay} + fee {fee}; \
                     adjust the paid amount"
                ));
            }
        } else {
            let last = outputs.last_mut().unwrap();
            last.value = u64::try_from(change).unwrap_or_else(|_| bail("change exceeds u64"));
        }
    } else if sum_in != sum_pay + fee {
        bail(&format!(
            "no --change given and conservation is exact: inputs {sum_in} != pays {sum_pay} + fee {fee} \
             (difference {}). Add --change <dest> or adjust --pay.",
            sum_in.abs_diff(sum_pay + fee)
        ));
    }

    // ── Root, signature, witness fill ───────────────────────────────────────
    let mut tx = build(outputs, tx_bytes);
    let signing_root = tx.spend_signing_root();
    let signature = bloch_crypto::crypto::sign(&sk, &signing_root)
        .unwrap_or_else(|e| bail(&format!("hybrid signing failed: {e:?}")));
    if let PosTransaction::Transfer { inputs, .. } = &mut tx {
        for i in inputs.iter_mut() {
            i.signature = signature.clone();
        }
    }

    // ── Local validation: everything a node will check that we can check ────
    // 1. Both signature halves verify (AND) over the signing root.
    if !bloch_crypto::crypto::verify(&pk, &signing_root, &signature) {
        bail("self-check failed: the signature does not verify over the signing root");
    }
    // 2. The key actually owns each spent script hash form we were told about
    //    (only checkable against the chain; here we at least print the hash).
    // 3. Declared size covers the real encoding (UnderdeclaredSize).
    let encoded = tx.canonical_bytes();
    if (encoded.len() as u64) > tx_bytes {
        bail(&format!(
            "self-check failed: encoded {} bytes exceeds declared tx_bytes {tx_bytes}",
            encoded.len()
        ));
    }
    // 4. Decode round-trip through the node's own decoder.
    match PosTransaction::from_canonical_bytes(&encoded) {
        Ok(back) if back == tx => {}
        Ok(_) => bail("self-check failed: decode round-trip returned a different transaction"),
        Err(e) => bail(&format!("self-check failed: canonical bytes do not decode: {e:?}")),
    }
    // 5. Conservation restated, from the final shape.
    let created: u128 = match &tx {
        PosTransaction::Transfer { outputs, .. } => outputs.iter().map(|o| o.value as u128).sum(),
        _ => unreachable!(),
    };
    assert_eq!(sum_in, created + fee, "internal: conservation drifted during sizing");

    println!("signing_root      : {}", codec::hex32(&signing_root));
    println!("txid              : {}", codec::hex32(&tx.txid()));
    println!("inputs            : {n_inputs} ({} sat)", sum_in);
    match &tx {
        PosTransaction::Transfer { outputs, .. } => {
            for (vout, o) in outputs.iter().enumerate() {
                println!(
                    "output {vout}          : {} sat -> {}",
                    o.value,
                    codec::hex32(&o.script_hash)
                );
            }
        }
        _ => unreachable!(),
    }
    println!("spender key hash  : {}", codec::hex32(&key_hash));
    println!("declared tx_bytes : {tx_bytes} (encoded {} bytes)", encoded.len());
    println!("gas               : {}", charge.gas);
    println!(
        "fee               : {fee} sat (base {} @ {base_fee} msat/gas + tip {} @ {tip} msat/gas)",
        charge.base_fee_sat, charge.priority_fee_sat
    );
    println!("signature_len     : {} bytes per input", signature.len());
    println!();
    println!("BASE FEE WARNING: this transfer conserves value ONLY at base fee {base_fee} msat/gas.");
    println!("If the network's base fee moves before inclusion, this transaction is");
    println!("permanently invalid (ValueNotConserved) and must be REBUILT and RE-SIGNED.");

    let hex = codec::hex(&encoded);
    if let Some(out) = arg_value(args, "--out-hex") {
        std::fs::write(&out, &hex).unwrap_or_else(|e| bail(&format!("cannot write {out}: {e}")));
        println!("\nwrote signed canonical hex to {out} ({} bytes encoded)", encoded.len());
    } else {
        println!("\ncanonical hex (sendrawtransaction param):\n{hex}");
    }
}

fn read_key_file(path: &str) -> Vec<u8> {
    let s = std::fs::read_to_string(path)
        .unwrap_or_else(|e| bail(&format!("cannot read {path}: {e}")));
    codec::unhex(s.trim()).unwrap_or_else(|e| bail(&format!("{path}: {e}")))
}

// ─── decode ─────────────────────────────────────────────────────────────────

fn decode_cmd(args: &[String]) {
    let Some(arg) = arg_value(args, "--hex") else {
        bail("decode: --hex <hex|@file> is required");
    };
    let hex_str = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).unwrap_or_else(|e| bail(&format!("cannot read {path}: {e}")))
    } else {
        arg
    };
    let bytes = codec::unhex(hex_str.trim()).unwrap_or_else(|e| bail(&e));
    let tx = PosTransaction::from_canonical_bytes(&bytes)
        .unwrap_or_else(|e| bail(&format!("not a canonical Genesis-4 transaction: {e:?}")));
    let root = tx.spend_signing_root();
    println!("decoded           : {} bytes", bytes.len());
    println!("txid              : {}", codec::hex32(&tx.txid()));
    println!("signing_root      : {}", codec::hex32(&root));
    match &tx {
        PosTransaction::Transfer { inputs, outputs, tx_bytes, tip_millisat_per_gas } => {
            println!("kind              : Transfer (tag 0x01)");
            println!("declared tx_bytes : {tx_bytes}   tip: {tip_millisat_per_gas} msat/gas");
            for (n, i) in inputs.iter().enumerate() {
                let ok = bloch_crypto::crypto::verify(&i.pubkey, &root, &i.signature);
                let kh: [u8; 32] = Sha3_256::digest(&i.pubkey).into();
                println!(
                    "input {n}           : {}:{}  key_hash {}  signature {}",
                    codec::hex32(&i.txid),
                    i.vout,
                    codec::hex32(&kh),
                    if ok { "VERIFIES" } else { "DOES NOT VERIFY" }
                );
            }
            for (vout, o) in outputs.iter().enumerate() {
                println!(
                    "output {vout}          : {} sat -> {}",
                    o.value,
                    codec::hex32(&o.script_hash)
                );
            }
        }
        other => println!("kind              : {other:?}"),
    }
    // Flush deliberately: this output is what people paste into tickets.
    let _ = std::io::stdout().flush();
}
