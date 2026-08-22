//! bloch-wallet — Bloch-SIS Protocol CLI Wallet
//! Colors: amber accent · green success · red error · muted gray

use clap::{Parser, Subcommand};
use std::path::PathBuf;

// ── ANSI colors ───────────────────────────────────────────────────────────────
const AMBER:   &str = "\x1b[38;5;214m";   // #EF9F27 equivalent
const GREEN:   &str = "\x1b[38;5;71m";    // #639922 equivalent
const RED:     &str = "\x1b[38;5;167m";   // #E24B4A equivalent
const MUTED:   &str = "\x1b[38;5;245m";   // gray secondary
const BOLD:    &str = "\x1b[1m";
const DIM:     &str = "\x1b[2m";
const RESET:   &str = "\x1b[0m";

fn amber(s: &str)  -> String { format!("{}{}{}", AMBER, s, RESET) }
fn green(s: &str)  -> String { format!("{}{}{}", GREEN, s, RESET) }
fn red(s: &str)    -> String { format!("{}{}{}", RED, s, RESET) }
fn muted(s: &str)  -> String { format!("{}{}{}", MUTED, s, RESET) }
fn bold(s: &str)   -> String { format!("{}{}{}", BOLD, s, RESET) }
fn dim(s: &str)    -> String { format!("{}{}{}", DIM, s, RESET) }

fn banner() {
    println!();
    println!("  {}◆{}  {} B L O C H   W A L L E T {}  {}◆{}",
        AMBER, RESET, BOLD, RESET, AMBER, RESET);
    // The suite line must name what is actually generated. It said "ML-DSA-65"
    // while `generate_keypair` was producing an enveloped
    // SUITE_MLDSA65_FALCON1024 pair — and the sizes printed two lines later
    // (3,749 / 6,341 = PUBKEY_SIZE / PRIVKEY_SIZE, both hybrid) contradicted
    // it in the same screen. Understating the suite is the wrong direction to
    // be wrong in: the hybrid IS the security claim.
    println!("  {}ML-DSA-65 ‖ Falcon-1024 (hybrid) · AES-256-GCM · Argon2id{}",
        MUTED, RESET);
    println!();
}

fn ok(msg: &str) {
    println!("  {} {}", green("✓"), msg);
}

fn err(msg: &str) {
    println!("  {} {}", red("✗"), msg);
    std::process::exit(1);
}

fn label(k: &str, v: &str) {
    println!("  {:<14} {}", muted(k), v);
}

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "bloch-wallet")]
#[command(about = "Bloch-SIS Protocol Wallet — hybrid ML-DSA-65 ‖ Falcon-1024 keypairs")]
#[command(version)]
#[command(disable_help_flag = false)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long, global = true)]
    testnet: bool,
    #[arg(long, global = true, default_value = "http://127.0.0.1:16210")]
    rpc: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new keypair and encrypted keystore
    New {
        #[arg(long, default_value = "./bloch-wallet.json")]
        output: PathBuf,
    },
    /// Show address of a keystore
    Address { keystore: PathBuf },
    /// Show public key (hex)
    Pubkey { keystore: PathBuf },
    /// Check balance via RPC
    Balance { address: String },
    /// Build, sign, and broadcast a transaction
    Send {
        keystore: PathBuf,
        to:       String,
        amount:   f64,
        #[arg(long, default_value_t = 0.0001)]
        fee:      f64,
    },
    /// Sign arbitrary message
    Sign { keystore: PathBuf, message: String },
    /// P4.3 — Create a signed selective-disclosure bundle (view/audit key).
    /// Prompts for the BIP39 seed phrase; discloses ONLY the given receive
    /// indices (0 = base address). The bundle contains public data + signatures
    /// only — never the seed or any secret key.
    Disclose {
        /// Comma-separated receive indices, e.g. "0,2,5"
        indices: String,
        /// What this disclosure is for (bound into the signatures)
        #[arg(long)]
        purpose: String,
        /// Who this disclosure is addressed to (bound in; verifiers must check it)
        #[arg(long)]
        audience: String,
        #[arg(long, default_value = "./bloch-disclosure.json")]
        output: PathBuf,
    },
    /// Verify a disclosure bundle OFFLINE (no node needed)
    VerifyBundle { bundle: PathBuf },
    /// Watch-only audit: verify a bundle, then sum balances over its addresses
    Watch { bundle: PathBuf },
}

pub fn main() {
    let cli = Cli::parse();
    banner();

    match cli.cmd {

        Cmd::New { output } => {
            println!("  {}Generating hybrid ML-DSA-65 ‖ Falcon-1024 keypair...{}", MUTED, RESET);
            println!("  {}(this takes a moment — 4000-byte key generation){}",
                DIM, RESET);
            println!();

            let kp = crate::wallet::generate_keypair(cli.testnet);

            println!("  {} {}", amber("address"), bold(&kp.address));
            println!();
            label("pubkey size",  &format!("{} bytes", kp.public_key.len()));
            label("privkey size", &format!("{} bytes (never share!)", kp.private_key.len()));
            label("algorithm",    "ML-DSA-65 (FIPS 204) ‖ Falcon-1024 — hybrid, both verified");
            label("network",      if cli.testnet { "testnet" } else { "mainnet" });
            println!();

            let pw = prompt_new_password();
            println!();
            match kp.save_encrypted(&output, &pw) {
                Ok(()) => {
                    ok(&format!("Keystore saved: {}", amber(&output.display().to_string())));
                    println!();
                    println!("  {}Keep your password safe — it cannot be recovered.{}",
                        MUTED, RESET);
                }
                Err(e) => err(&format!("Save failed: {}", e)),
            }
        }

        Cmd::Address { keystore } => {
            let kp = load_kp(&keystore);
            println!("  {}", amber(&kp.address));
        }

        Cmd::Pubkey { keystore } => {
            let kp = load_kp(&keystore);
            let hex = hex::encode(&kp.public_key);
            println!("  {}", muted(&hex[..32]));
            println!("  {}", muted(&hex[32..64]));
            println!("  {}... ({} bytes total){}", DIM, kp.public_key.len(), RESET);
        }

        Cmd::Balance { address } => {
            print!("  {}querying node...{}\r", MUTED, RESET);
            let resp = rpc_call(&cli.rpc, "getbalance",
                serde_json::json!([address]));

            match resp.get("error") {
                Some(e) => err(&format!("RPC error: {}", e)),
                None => {
                    // R3: satoshi amounts are decimal strings on the V4 wire,
                    // numbers on the G3 wire — `sat_u64` reads both.
                    let sats = crate::wallet::sat_u64(&resp["satoshis"]).unwrap_or(0);
                    let bloch = sats as f64 / 1e8;
                    let utxos = resp["utxo_count"].as_u64().unwrap_or(0);

                    println!();
                    println!("  {} {}", amber("balance"),
                        bold(&format!("{:.8} BLOCH", bloch)));
                    println!();
                    label("satoshis",   &format!("{}", sats));
                    label("utxos",      &format!("{}", utxos));
                    label("address",    &dim(&address));
                }
            }
        }

        Cmd::Send { keystore, to, amount, fee } => {
            let kp          = load_kp(&keystore);
            let amount_sats = (amount * 1e8).round() as u64;
            let fee_sats    = (fee * 1e8).round() as u64;

            println!("  {}transaction preview{}", BOLD, RESET);
            println!();
            label("from",   &kp.address);
            label("to",     &to);
            label("amount", &format!("{:.8} BLOCH  {}({} sats){}",
                amount, MUTED, amount_sats, RESET));
            label("fee",    &format!("{:.8} BLOCH", fee));
            println!();

            // 1. Fetch UTXOs via getutxos (returns full UTXO list for coin selection)
            print!("  {}fetching UTXOs...{}\r", MUTED, RESET);
            let resp = rpc_call(&cli.rpc, "getutxos",
                serde_json::json!([kp.address]));

            if let Some(e) = resp.get("error") {
                if !e.is_null() {
                    err(&format!("RPC error: {}", e));
                }
            }

            let avail = crate::wallet::sat_u64(&resp["satoshis"]).unwrap_or(0);
            let utxo_count = resp["utxo_count"].as_u64().unwrap_or(0);
            if avail < amount_sats + fee_sats {
                err(&format!("Insufficient funds: have {:.8} BLOCH ({} UTXOs), need {:.8} BLOCH",
                    avail as f64 / 1e8, utxo_count,
                    (amount_sats + fee_sats) as f64 / 1e8));
            }

            // 2. Parse UTXOs from getutxos response
            let utxos_raw = resp["utxos"].as_array().cloned().unwrap_or_default();
            let available_utxos: Vec<(Vec<u8>, u32, crate::core::TxOutput)> = utxos_raw
                .iter()
                .filter_map(|u| {
                    let txid_hex = u["txid"].as_str()?;
                    let txid = hex::decode(txid_hex).ok()?;
                    let idx  = u["index"].as_u64()? as u32;
                    let val  = crate::wallet::sat_u64(&u["value"])?;
                    let spk  = hex::decode(u["script_pubkey"].as_str()?).ok()?;
                    Some((txid, idx, crate::core::TxOutput { value: val, script_pubkey: spk }))
                })
                .collect();

            if available_utxos.is_empty() {
                err("No UTXOs returned by node — cannot build transaction");
            }

            ok(&format!("{} UTXOs available ({:.8} BLOCH)",
                available_utxos.len(), avail as f64 / 1e8));

            // Sprint K: Parse and validate destination address (checksum-enforced)
            let to_hex = match crate::address::Address::parse(&to) {
                Ok(a) => hex::encode(a.hash()),
                Err(e) => { err(&format!("Invalid destination address: {}\n  Hint: addresses must be 55 chars (bloch1q + 40 hex hash + 8 hex checksum)", e)); unreachable!() }
            };

            // 4. Build and sign transaction
            print!("  {}building transaction...{}\r", MUTED, RESET);
            let tx = match crate::wallet::TxBuilder::build(&kp, &available_utxos, &to_hex, amount_sats, fee_sats) {
                Ok(t)  => t,
                Err(e) => { err(&format!("Build failed: {}", e)); unreachable!() }
            };

            let txid = tx.txid();
            ok(&format!("Transaction built — txid: {}", amber(&hex::encode(txid))));
            label("inputs",  &format!("{}", tx.inputs.len()));
            label("outputs", &format!("{}", tx.outputs.len()));
            label("sig size",&format!("{} bytes (ML-DSA-65 ‖ Falcon-1024)", tx.inputs[0].script_sig.len()));
            println!();

            // 5. Serialize and broadcast via sendrawtransaction
            // Sprint 1.d: Bitcoin-format wire (replaces bincode).
            // include_script_sig=true — the signature bytes must travel
            // with the tx so the node can verify.
            let raw = tx.to_stratum_bytes(true);

            print!("  {}broadcasting via sendrawtransaction...{}\r", MUTED, RESET);
            let resp2 = rpc_call(&cli.rpc, "sendrawtransaction",
                serde_json::json!([hex::encode(&raw)]));

            match resp2.get("error") {
                Some(e) if !e.is_null() => err(&format!("Broadcast failed: {}", e)),
                _ => {
                    ok("Broadcast accepted by node");
                    println!();
                    println!("  {} {}", amber("txid"), bold(&hex::encode(txid)));
                }
            }
        }

        Cmd::Disclose { indices, purpose, audience, output } => {
            let idx: Vec<u32> = match indices.split(',')
                .map(|s| s.trim().parse::<u32>())
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(v) if !v.is_empty() => v,
                _ => { err("indices must be a comma-separated list of numbers, e.g. 0,2,5"); unreachable!() }
            };

            println!("  {}Selective disclosure — reveals ONLY the listed indices.{}", MUTED, RESET);
            println!("  {}The bundle proves control of those addresses; it cannot and{}", DIM, RESET);
            println!("  {}does not prove they are ALL of your addresses (by design).{}", DIM, RESET);
            println!();

            let phrase = prompt_password(&format!("  {}seed phrase:{} ", MUTED, RESET));
            let seed = match crate::wallet::SeedPhrase::parse(&phrase) {
                Ok(s) => s,
                Err(e) => { err(&format!("Invalid seed phrase: {}", e)); unreachable!() }
            };
            let network = if cli.testnet { crate::address::Network::Testnet }
                          else { crate::address::Network::Mainnet };

            print!("  {}deriving {} keypair(s) + signing (slow: hybrid PQ keygen)...{}\r",
                MUTED, idx.len(), RESET);
            let seed_bytes = seed.to_seed_bytes();
            let bundle = match crate::wallet::DisclosureBundle::create(
                &seed_bytes, &idx, network, &purpose, &audience)
            {
                Ok(b) => b,
                Err(e) => { err(&format!("Disclosure failed: {}", e)); unreachable!() }
            };

            let json = serde_json::to_string_pretty(&bundle).unwrap();
            match crate::util::atomic_write(&output, json.as_bytes()) {
                Ok(()) => {
                    ok(&format!("Disclosure bundle saved: {}", amber(&output.display().to_string())));
                    println!();
                    for e in &bundle.entries {
                        label(&format!("index {}", e.index), &e.address);
                    }
                    println!();
                    println!("  {}Share this file with '{}' only — anyone holding it can see{}",
                        MUTED, audience, RESET);
                    println!("  {}these addresses' full on-chain history, forever.{}", MUTED, RESET);
                }
                Err(e) => err(&format!("Save failed: {}", e)),
            }
        }

        Cmd::VerifyBundle { bundle } => {
            let verified = load_and_verify_bundle(&bundle);
            ok("bundle signatures + address bindings verified");
            println!();
            label("network",  &format!("{:?}", verified.network));
            label("purpose",  &verified.purpose);
            label("audience", &verified.audience);
            label("created",  &verified.created_at);
            println!();
            for (index, addr) in &verified.addresses {
                label(&format!("index {}", index), &addr.to_string());
            }
            println!();
            println!("  {}Proven: the discloser controls these addresses.{}", MUTED, RESET);
            println!("  {}NOT proven: that these are all of their addresses (selective).{}", DIM, RESET);
            println!("  {}Check the audience field names YOU before trusting the bundle.{}", DIM, RESET);
        }

        Cmd::Watch { bundle } => {
            let verified = load_and_verify_bundle(&bundle);
            ok(&format!("bundle verified — {} address(es)", verified.addresses.len()));
            println!();

            let mut total: u64 = 0;
            for (index, addr) in &verified.addresses {
                let addr_str = addr.to_string();
                let resp = rpc_call(&cli.rpc, "getbalance", serde_json::json!([addr_str]));
                match resp.get("error") {
                    Some(e) if !e.is_null() =>
                        label(&format!("index {}", index), &red(&format!("RPC error: {}", e))),
                    _ => {
                        let sats = crate::wallet::sat_u64(&resp["satoshis"]).unwrap_or(0);
                        total = total.saturating_add(sats);
                        label(&format!("index {}", index),
                            &format!("{:.8} BLOCH  {}{}{}", sats as f64 / 1e8, DIM, addr_str, RESET));
                    }
                }
            }
            println!();
            println!("  {} {}", amber("disclosed total"),
                bold(&format!("{:.8} BLOCH", total as f64 / 1e8)));
            println!("  {}(total over the DISCLOSED subset only — not a whole-wallet total){}",
                MUTED, RESET);
        }

        Cmd::Sign { keystore, message } => {
            let kp  = load_kp(&keystore);
            let msg = hex::decode(&message)
                .unwrap_or_else(|_| message.into_bytes());

            print!("  {}signing {} bytes...{}\r", MUTED, msg.len(), RESET);
            match kp.sign(&msg) {
                Ok(sig) => {
                    ok(&format!("Signature ({} bytes)", sig.len()));
                    println!();
                    let h = hex::encode(&sig);
                    println!("  {}", muted(&h[..64]));
                    println!("  {}...{}", DIM, RESET);
                }
                Err(e) => err(&format!("Sign failed: {}", e)),
            }
        }
    }

    println!();
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn load_and_verify_bundle(path: &PathBuf) -> crate::wallet::VerifiedDisclosure {
    let json = match std::fs::read_to_string(path) {
        Ok(j) => j,
        Err(e) => { err(&format!("Cannot read bundle: {}", e)); unreachable!() }
    };
    let bundle: crate::wallet::DisclosureBundle = match serde_json::from_str(&json) {
        Ok(b) => b,
        Err(e) => { err(&format!("Bundle parse failed: {}", e)); unreachable!() }
    };
    match bundle.verify() {
        Ok(v) => v,
        Err(e) => { err(&format!("Bundle verification FAILED: {}", e)); unreachable!() }
    }
}

fn load_kp(path: &PathBuf) -> crate::wallet::Keypair {
    let pw = prompt_password(&format!("  {}password:{} ", MUTED, RESET));
    match crate::wallet::Keypair::load_encrypted(path, &pw) {
        Ok(kp) => { ok("keystore decrypted"); println!(); kp }
        Err(e) => { err(&format!("Load failed: {}", e)); unreachable!() }
    }
}

fn prompt_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_default()
}

fn prompt_new_password() -> String {
    loop {
        let pw  = rpassword::prompt_password(
            &format!("  {}new password:{} ", MUTED, RESET)
        ).unwrap_or_default();
        if let Err(e) = crate::wallet::validate_password(&pw) {
            println!("  {} {}", red("✗"), muted(&format!("weak password: {}", e)));
            continue;
        }
        let pw2 = rpassword::prompt_password(
            &format!("  {}confirm:     {} ", MUTED, RESET)
        ).unwrap_or_default();
        if pw == pw2 { return pw; }
        println!("  {} {}", red("✗"), muted("passwords do not match"));
    }
}

fn rpc_call(endpoint: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
    })).unwrap();
    let url  = endpoint.trim_start_matches("http://");
    let (host, _) = url.split_once('/').unwrap_or((url, ""));
    match std::net::TcpStream::connect(host) {
        Err(_) => serde_json::json!({ "error": "node not reachable" }),
        Ok(mut s) => {
            use std::io::{Write, Read};
            let req = format!(
                "POST / HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                host, body.len(), body
            );
            let _ = s.write_all(req.as_bytes());
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            if let Some(p) = buf.find("\r\n\r\n") {
                serde_json::from_str(&buf[p+4..])
                    .ok()
                    .and_then(|v: serde_json::Value|
                        v.get("result").cloned())
                    .unwrap_or(serde_json::json!({}))
            } else {
                serde_json::json!({ "error": "invalid response" })
            }
        }
    }
}
