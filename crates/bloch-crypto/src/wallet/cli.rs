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
    println!("  {}◆{}  {} B L O C H {}  {}◆{}",
        AMBER, RESET, BOLD, RESET, AMBER, RESET);
    println!("  {}Hybrid signatures: ML-DSA-65 + Falcon-1024 · SHA3-256{}",
        MUTED, RESET);
    println!("  {}Keystore encryption: AES-256-GCM · Argon2id{}", MUTED, RESET);
    println!();
}

fn ok(msg: &str) {
    println!("  {} {}", green("✓"), msg);
}

fn err(msg: &str) -> ! {
    println!("  {} {}", red("✗"), msg);
    std::process::exit(1);
}

fn label(k: &str, v: &str) {
    println!("  {:<14} {}", muted(k), v);
}

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "bloch-wallet")]
#[command(about = "Bloch Protocol Wallet — hybrid ML-DSA-65 + Falcon-1024 signatures")]
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
        amount:   String,
        #[arg(long, default_value = "0.0001")]
        fee:      String,
    },
    /// Sign a message (domain-separated digest — see `verify-message`)
    Sign { keystore: PathBuf, message: String },
    /// Verify a signature produced by `sign` against a public key
    VerifyMessage {
        /// Signer's public key, hex-encoded (see the `pubkey` command).
        pubkey: String,
        /// The exact message text that was signed.
        message: String,
        /// The signature, hex-encoded.
        signature: String,
    },
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
            println!("  {}Generating hybrid ML-DSA-65 + Falcon-1024 keypair...{}", MUTED, RESET);
            println!("  {}(post-quantum key generation may take a moment){}",
                DIM, RESET);
            println!();

            let kp = crate::wallet::generate_keypair(cli.testnet);

            println!("  {} {}", amber("address"), bold(&kp.address));
            println!();
            label("pubkey size",  &format!("{} bytes", kp.public_key.len()));
            label("privkey size", &format!("{} bytes (never share!)", kp.private_key.len()));
            label("algorithm",    "ML-DSA-65 + Falcon-1024 (hybrid)");
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
            // Public-key export must include every byte for native script hashing.
            println!("{hex}");
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
            let amount_sats = checked_cli_satoshis(&amount, false).unwrap_or_else(|message| err(message));
            let fee_sats = checked_cli_satoshis(&fee, true).unwrap_or_else(|message| err(message));
            let total_needed = amount_sats.checked_add(fee_sats)
                .unwrap_or_else(|| err("amount plus fee exceeds u64"));
            let to_hex = checked_destination(&to, &kp.address).unwrap_or_else(|message| err(&message));

            println!("  {}transaction preview{}", BOLD, RESET);
            println!();
            label("from",   &kp.address);
            label("to",     &to);
            label("amount", &format!("{} BLOCH  {}({} sats){}",
                amount, MUTED, amount_sats, RESET));
            label("fee",    &format!("{} BLOCH", fee));
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
            if avail < total_needed {
                err(&format!("Insufficient funds: have {:.8} BLOCH ({} UTXOs), need {:.8} BLOCH",
                    avail as f64 / 1e8, utxo_count,
                    total_needed as f64 / 1e8));
            }

            // 2. Parse UTXOs from getutxos response
            let available_utxos = parse_send_utxos(&resp)
                .unwrap_or_else(|message| err(message));

            if available_utxos.is_empty() {
                err("No UTXOs returned by node — cannot build transaction");
            }

            ok(&format!("{} UTXOs available ({:.8} BLOCH)",
                available_utxos.len(), avail as f64 / 1e8));


            let tx = match crate::wallet::TxBuilder::build(&kp, &available_utxos, &to_hex, amount_sats, fee_sats) {
                Ok(t)  => t,
                Err(e) => { err(&format!("Build failed: {}", e)) }
            };

            let txid = tx.txid();
            ok(&format!("Transaction built — txid: {}", amber(&hex::encode(txid))));
            label("inputs",  &format!("{}", tx.inputs.len()));
            label("outputs", &format!("{}", tx.outputs.len()));
            label("sig size",&format!("{} bytes", tx.inputs[0].script_sig.len()));
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
                _ => { err("indices must be a comma-separated list of numbers, e.g. 0,2,5") }
            };

            println!("  {}Selective disclosure — reveals ONLY the listed indices.{}", MUTED, RESET);
            println!("  {}The bundle proves control of those addresses; it cannot and{}", DIM, RESET);
            println!("  {}does not prove they are ALL of your addresses (by design).{}", DIM, RESET);
            println!();

            let phrase = prompt_password(&format!("  {}seed phrase:{} ", MUTED, RESET));
            let seed = match crate::wallet::SeedPhrase::parse(&phrase) {
                Ok(s) => s,
                Err(e) => { err(&format!("Invalid seed phrase: {}", e)) }
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
                Err(e) => { err(&format!("Disclosure failed: {}", e)) }
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
            let kp = load_kp(&keystore);
            // A4-M-4 FIX: sign a DOMAIN-SEPARATED digest of the message's raw
            // bytes — NEVER hex-decode user-supplied text first. The old
            // code's `hex::decode(&message).unwrap_or_else(|_| message.into_bytes())`
            // meant a 64-hex-character "message" signed the raw 32 decoded
            // bytes directly: indistinguishable at the signature layer from a
            // tx sighash / disclosure digest / PoS signing root. A "prove you
            // own this address by signing this challenge" phishing prompt
            // could then harvest a valid transaction signature.
            print!("  {}signing message ({} bytes)...{}\r", MUTED, message.len(), RESET);
            match kp.sign_message(message.as_bytes()) {
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

        Cmd::VerifyMessage { pubkey, message, signature } => {
            let pk = match hex::decode(&pubkey) {
                Ok(b) => b,
                Err(e) => { err(&format!("Invalid pubkey hex: {}", e)) }
            };
            let sig = match hex::decode(&signature) {
                Ok(b) => b,
                Err(e) => { err(&format!("Invalid signature hex: {}", e)) }
            };
            // Same domain-separated digest `sign` uses — never hex-decode
            // `message` either; verification must mirror signing exactly.
            if crate::wallet::Keypair::verify_message(&pk, message.as_bytes(), &sig) {
                ok("signature verifies for this message and public key");
            } else {
                err("signature does NOT verify for this message and public key");
            }
        }
    }

    println!();
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn load_and_verify_bundle(path: &PathBuf) -> crate::wallet::VerifiedDisclosure {
    let json = match std::fs::read_to_string(path) {
        Ok(j) => j,
        Err(e) => { err(&format!("Cannot read bundle: {}", e)) }
    };
    let bundle: crate::wallet::DisclosureBundle = match serde_json::from_str(&json) {
        Ok(b) => b,
        Err(e) => { err(&format!("Bundle parse failed: {}", e)) }
    };
    match bundle.verify() {
        Ok(v) => v,
        Err(e) => { err(&format!("Bundle verification FAILED: {}", e)) }
    }
}

fn load_kp(path: &PathBuf) -> crate::wallet::Keypair {
    let pw = prompt_password(&format!("  {}password:{} ", MUTED, RESET));
    match crate::wallet::Keypair::load_encrypted(path, &pw) {
        Ok(kp) => { ok("keystore decrypted"); println!(); kp }
        Err(e) => { err(&format!("Load failed: {}", e)) }
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
        // `save_encrypted` also enforces `encryption::validate_password_strength`
        // (length + breach denylist) — check it here too so a rejected
        // password re-prompts instead of failing the whole `New` command.
        if let Err(e) = crate::wallet::encryption::validate_password_strength(&pw) {
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
    let authority = endpoint.strip_prefix("http://").unwrap_or(endpoint).trim_end_matches('/');
    crate::wallet::http_rpc::call(authority, method, &params, None)
        .unwrap_or_else(|error| serde_json::json!({"error":error}))
}

// Parse once from the original CLI token: no float may choose the spend amount.
fn checked_cli_satoshis(value: &str, allow_zero: bool) -> Result<u64, &'static str> {
    let satoshis = crate::wallet::parse_bloch_satoshis(value)?;
    if !allow_zero && satoshis == 0 { return Err("payment must contain at least one satoshi"); }
    Ok(satoshis)
}

fn checked_destination(destination: &str, source: &str) -> Result<String, String> {
    let destination = crate::address::Address::parse(destination).map_err(|_| "invalid destination address".to_string())?;
    let source = crate::address::Address::parse(source).map_err(|_| "invalid wallet address".to_string())?;
    if destination.network() != source.network() { return Err("destination address network differs from wallet".into()); }
    Ok(hex::encode(destination.hash()))
}

fn parse_send_utxos(response: &serde_json::Value) -> Result<Vec<(Vec<u8>, u32, crate::core::TxOutput)>, &'static str> {
    let rows = response["utxos"].as_array().ok_or("RPC response missing UTXO array")?;
    rows.iter().map(|row| {
        let txid = hex::decode(row["txid"].as_str().ok_or("UTXO missing transaction ID")?)
            .map_err(|_| "invalid UTXO transaction ID hex")?;
        if txid.len() != 32 { return Err("UTXO transaction ID must contain 32 bytes"); }
        let index = row["index"].as_u64().and_then(|value| u32::try_from(value).ok())
            .ok_or("UTXO index must fit u32")?;
        let value = crate::wallet::sat_u64(&row["value"]).ok_or("invalid UTXO value")?;
        let script_pubkey = hex::decode(row["script_pubkey"].as_str().ok_or("UTXO missing script")?)
            .map_err(|_| "invalid UTXO script hex")?;
        Ok((txid, index, crate::core::TxOutput { value, script_pubkey }))
    }).collect()
}

#[cfg(test)]
mod audit_cli_input_tests {
    use super::*;
    use crate::address::{Address, Network};

    #[test]
    fn cli_amount_refuses_nonfinite_negative_saturating_and_zero_payment() {
        for value in ["NaN", "inf", "-inf", "-1", "1e30"] {
            assert!(checked_cli_satoshis(value, true).is_err());
        }
        assert!(checked_cli_satoshis("0", false).is_err());
        assert!(checked_cli_satoshis("0.000000001", false).is_err());
        assert_eq!(checked_cli_satoshis("0", true), Ok(0));
        assert_eq!(checked_cli_satoshis("1.25", false), Ok(125_000_000));
        assert_eq!(checked_cli_satoshis("0.00000001", false), Ok(1));
    }

    #[test]
    fn clap_preserves_exact_amount_and_fee_tokens() {
        let cli = Cli::try_parse_from(["postern-wallet", "send", "wallet.json", "recipient",
            "90071992.54740993", "--fee", "0.00000001"]).unwrap();
        match cli.cmd {
            Cmd::Send { amount, fee, .. } => {
                assert_eq!(checked_cli_satoshis(&amount, false).unwrap(), 9_007_199_254_740_993);
                assert_eq!(checked_cli_satoshis(&fee, true).unwrap(), 1);
            }
            _ => panic!("expected send command"),
        }
    }

    #[test]
    fn cli_destination_preserves_network_before_converting_to_hash() {
        let main = Address::from_hash([1; 20], Network::Mainnet).to_string();
        let test = Address::from_hash([1; 20], Network::Testnet).to_string();
        assert!(checked_destination(&main, &test).is_err());
        assert!(checked_destination(&test, &main).is_err());
        assert_eq!(checked_destination(&main, &main).unwrap(), "01".repeat(20));
        assert!(checked_destination("invalid", &main).is_err());
    }

    #[test]
    fn cli_utxo_parser_refuses_invalid_rows_without_silent_filtering() {
        let row = serde_json::json!({"txid": "ab".repeat(32), "index": u32::MAX,
            "value": "9007199254740993", "script_pubkey": "cd".repeat(20)});
        let parsed = parse_send_utxos(&serde_json::json!({"utxos": [row.clone()]})).unwrap();
        assert_eq!(parsed[0].1, u32::MAX);
        assert_eq!(parsed[0].2.value, 9_007_199_254_740_993);
        for invalid in [serde_json::json!(4294967296u64), serde_json::json!(-1), serde_json::json!(1.5)] {
            let mut bad = row.clone(); bad["index"] = invalid;
            assert!(parse_send_utxos(&serde_json::json!({"utxos": [row.clone(), bad]})).is_err());
        }
        let mut bad = row; bad["txid"] = serde_json::json!("ab");
        assert!(parse_send_utxos(&serde_json::json!({"utxos": [bad]})).is_err());
        assert!(parse_send_utxos(&serde_json::json!({})).is_err());
    }
}
