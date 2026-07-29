//! bloch-cli — Bloch-SIS Protocol RPC client (like bitcoin-cli)
//!
//! Usage:
//!   bloch-cli getnetworkinfo
//!   bloch-cli getbalance bloch1q...
//!   bloch-cli send &lt;wallet.json&gt; &lt;to_address&gt; &lt;amount_bloch&gt; [--fee 0.001]
//!   bloch-cli --help

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    // Parse --rpc-url flag (default: 127.0.0.1:16210)
    let mut rpc_host = "127.0.0.1".to_string();
    let mut rpc_port = 16210u16;
    let mut cmd_args: Vec<&str> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc-host" => { i += 1; if i < args.len() { rpc_host = args[i].clone(); } }
            "--rpc-port" => { i += 1; if i < args.len() { rpc_port = args[i].parse().unwrap_or(16210); } }
            _ => { cmd_args.push(&args[i]); }
        }
        i += 1;
    }

    if cmd_args.is_empty() {
        print_usage();
        return;
    }

    let method = cmd_args[0];
    let params = &cmd_args[1..];

    let (rpc_method, rpc_params) = match method {

        // ── Network ────────────────────────────────────────────────
        "getnetworkinfo" | "info" => ("getnetworkinfo", serde_json::Value::Null),
        "getblockcount"  | "height" => ("getblockcount", serde_json::Value::Null),
        "getmempoolinfo" | "mempool" => ("getmempoolinfo", serde_json::Value::Null),

        // ── Blocks ─────────────────────────────────────────────────
        "getblockhash" => {
            require_params(params, 1, "getblockhash <height>");
            let h: u64 = params[0].parse().unwrap_or_else(|_| die("height must be a number"));
            ("getblockhash", serde_json::json!([h]))
        }

        "getblock" => {
            require_params(params, 1, "getblock <hash> [verbose]");
            let verbose = params.get(1).map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getblock", serde_json::json!([params[0], verbose]))
        }

        "getblockbyheight" | "block" => {
            require_params(params, 1, "getblockbyheight <height> [verbose]");
            let h: u64 = params[0].parse().unwrap_or_else(|_| die("height must be a number"));
            let verbose = params.get(1).map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getblockbyheight", serde_json::json!([h, verbose]))
        }

        "getrecentblocks" | "recent" => {
            let count: u64 = params.first().and_then(|s| s.parse().ok()).unwrap_or(10);
            ("getrecentblocks", serde_json::json!([count]))
        }

        // ── Transactions ───────────────────────────────────────────
        "gettransaction" | "tx" => {
            require_params(params, 1, "gettransaction <txid>");
            ("gettransaction", serde_json::json!([params[0]]))
        }

        "sendrawtransaction" | "sendraw" => {
            require_params(params, 1, "sendrawtransaction <hex>");
            ("sendrawtransaction", serde_json::json!([params[0]]))
        }

        // ── Wallet ─────────────────────────────────────────────────
        "getbalance" | "balance" => {
            require_params(params, 1, "getbalance <address>");
            ("getbalance", serde_json::json!([params[0]]))
        }

        "getutxos" | "utxos" | "listunspent" => {
            require_params(params, 1, "getutxos <address>");
            ("getutxos", serde_json::json!([params[0]]))
        }

        // ── Phase 2: new commands ──────────────────────────────────
        "validateaddress" | "validate" => {
            require_params(params, 1, "validateaddress <address>");
            ("validateaddress", serde_json::json!([params[0]]))
        }

        "estimatefee" | "fee" => {
            ("estimatefee", serde_json::Value::Null)
        }

        "getrawmempool" | "rawmempool" => {
            let verbose = params.first().map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getrawmempool", serde_json::json!([verbose]))
        }

        "decoderawtransaction" | "decode" => {
            require_params(params, 1, "decoderawtransaction <hex>");
            ("decoderawtransaction", serde_json::json!([params[0]]))
        }

        "getdaginfo" | "dag" => {
            ("getdaginfo", serde_json::Value::Null)
        }

        "listtransactions" | "txlist" => {
            require_params(params, 1, "listtransactions <address> [count]");
            let count: u64 = params.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
            ("listtransactions", serde_json::json!([params[0], count]))
        }

        "getpeerinfo" | "peers" => {
            ("getpeerinfo", serde_json::Value::Null)
        }

        // ── Wallet: send (builds + signs + broadcasts) ─────────────
        "send" => {
            require_params(params, 3, "send <wallet.json> <to_address> <amount_bloch> [--fee 0.001] [--chain genesis3|genesis2|mainnet|testnet]");
            do_send(params, &rpc_host, rpc_port);
            return;
        }

        // ── Diagnostic: key format (no secret leaked — lengths/suite only) ─────
        "keyinfo" => {
            require_params(params, 1, "keyinfo <wallet.json>");
            let pw = read_password("Wallet password: ");
            let path = std::path::Path::new(params[0]);
            match bloch::wallet::Keypair::load_encrypted(path, &pw) {
                Ok(kp) => {
                    let pk = &kp.public_key; let sk = &kp.private_key;
                    let suite = |b: &[u8]| -> String {
                        if b.len() >= 4 && b[0]==0xB1 && b[1]==0x0C {
                            format!("enveloped suite 0x{:04x}", u16::from_le_bytes([b[2],b[3]]))
                        } else { "RAW (no envelope)".into() }
                    };
                    println!("address:      {}", kp.address);
                    println!("pubkey  len:  {}  ({})", pk.len(), suite(pk));
                    println!("privkey len:  {}  ({})", sk.len(), suite(sk));
                    println!("expected: hybrid pk=3749 sk=4032+falcon(~2300); mldsa-only pk=1956 sk=4036");
                }
                Err(e) => { eprintln!("load failed: {}", e); process::exit(1); }
            }
            return;
        }

        // ── Wallet: generate ───────────────────────────────────────
        "newwallet" | "createwallet" => {
            require_params(params, 1, "newwallet <output_path.json>");
            do_new_wallet(params[0]);
            return;
        }

        // ── Phase 3: HD Wallet commands ────────────────────────────
        "newseed" => {
            require_params(params, 1, "newseed <output_path.json>");
            do_newseed(params[0]);
            return;
        }

        "newaddress" => {
            require_params(params, 1, "newaddress <wallet-hd.json> [label]");
            let label = params.get(1).copied().unwrap_or("new");
            do_newaddress(params[0], label);
            return;
        }

        "addresses" => {
            require_params(params, 1, "addresses <wallet-hd.json>");
            do_list_addresses(params[0]);
            return;
        }

        "importfounder" | "import-founder" => {
            require_params(params, 2, "importfounder <wallet-hd.json> <founder.json>");
            do_import_founder(params[0], params[1]);
            return;
        }

        // ── PoI: Proof-of-Improvement ──────────────────────────────
        "pools" | "getpools" | "treasury" | "gettreasury" => {
            // V2: aliases preserved for UX; routes to V2 multi-pool endpoint.
            ("getpools", serde_json::Value::Null)
        }

        "poiclaims" | "claims" => {
            ("getpoiclaims", serde_json::Value::Null)
        }

        "poiclaim" | "claim" => {
            require_params(params, 1, "poiclaim <claim_id_hex>");
            ("getpoiclaim", serde_json::json!([params[0]]))
        }

        "poisubmit" | "submitclaim" => {
            require_params(params, 4, "poisubmit <commit_hash> <category:0-3> <description> <address> [ci_attestation]");
            let ci = params.get(4).copied().unwrap_or("");
            ("submitpoiclaim", serde_json::json!([params[0], params[1].parse::<u64>().unwrap_or(3), params[2], params[3], ci]))
        }

        "poivote" | "vote" => {
            require_params(params, 3, "poivote <claim_id> <voter_address> <yes|no|abstain>");
            ("submitpoivote", serde_json::json!([params[0], params[1], params[2]]))
        }

        // ── eUTXO VM (node must run with --features euvm) ──────────
        // Thin passthroughs to the D5 euvm_* RPC methods; on a node built
        // without the feature they return "unknown method".
        "euvm_utxos" | "euvm_listutxos" => {
            // [validator_hash|null] [limit] [offset]
            let vh = params.get(0)
                .filter(|s| **s != "null" && !s.is_empty())
                .map(|s| serde_json::json!(s))
                .unwrap_or(serde_json::Value::Null);
            let limit: u64 = params.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            let offset: u64 = params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            ("euvm_listutxos", serde_json::json!([vh, limit, offset]))
        }

        "euvm_getutxo" => {
            require_params(params, 2, "euvm_getutxo <txid_hex> <index>");
            let idx: u64 = params[1].parse().unwrap_or_else(|_| die("index must be a number"));
            ("euvm_getutxo", serde_json::json!([params[0], idx]))
        }

        "euvm_buildtx" => {
            // Takes the full build-request object as ONE JSON argument:
            //   bloch-cli euvm_buildtx '{"inputs":[...],"outputs":[...]}'
            // (May carry secret keys — the node treats it as an auth-gated
            // write; set BLOCH_RPC_API_KEY if the node requires auth.)
            require_params(params, 1, "euvm_buildtx '<build-request-json>'");
            let obj: serde_json::Value = serde_json::from_str(params[0])
                .unwrap_or_else(|e| die(&format!("argument must be valid JSON: {}", e)));
            ("euvm_buildtx", serde_json::json!([obj]))
        }

        // ── Help ───────────────────────────────────────────────────
        "help" => { print_usage(); return; }

        _ => {
            eprintln!("Unknown command: {}", method);
            eprintln!("Run 'bloch-cli help' for usage.");
            process::exit(1);
        }
    };

    // Make RPC call
    match rpc_call(&rpc_host, rpc_port, rpc_method, &rpc_params) {
        Ok(result) => {
            let pretty = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
            println!("{}", pretty);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

// ── RPC client ──────────────────────────────────────────────────────────────

fn rpc_call(
    host: &str,
    port: u16,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let body_str = body.to_string();

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("cannot connect to {} — is the node running? ({})", addr, e))?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;

    // Optional API key for auth-required writes (sendrawtransaction): set
    // BLOCH_RPC_API_KEY. Sent as the x-api-key header the node expects.
    let api_key_hdr = std::env::var("BLOCH_RPC_API_KEY")
        .map(|k| format!("x-api-key: {}\r\n", k))
        .unwrap_or_default();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        addr, api_key_hdr, body_str.len(), body_str
    );

    stream.write_all(request.as_bytes()).map_err(|e| format!("write failed: {}", e))?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|e| format!("read failed: {}", e))?;

    let response_str = String::from_utf8_lossy(&response);

    // Find JSON body (after \r\n\r\n)
    let json_start = response_str.find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let json_body = &response_str[json_start..];

    // Handle chunked transfer encoding
    let json_clean = if response_str.contains("Transfer-Encoding: chunked") {
        parse_chunked(json_body)
    } else {
        json_body.trim().to_string()
    };

    let resp: serde_json::Value = serde_json::from_str(&json_clean)
        .map_err(|e| format!("invalid JSON response: {} — raw: {}", e, &json_clean[..200.min(json_clean.len())]))?;

    if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }

    Ok(resp.get("result").cloned().unwrap_or(resp))
}

/// Parse HTTP chunked transfer encoding
fn parse_chunked(body: &str) -> String {
    let mut result = String::new();
    let mut remaining = body.trim();

    loop {
        // Read chunk size (hex)
        let nl = match remaining.find("\r\n") {
            Some(i) => i,
            None => break,
        };
        let size_str = remaining[..nl].trim();
        let size = match usize::from_str_radix(size_str, 16) {
            Ok(0) => break, // terminal chunk
            Ok(s) => s,
            Err(_) => {
                // Not chunked, return as-is
                return body.trim().to_string();
            }
        };
        remaining = &remaining[nl + 2..];
        if remaining.len() < size { break; }
        result.push_str(&remaining[..size]);
        remaining = &remaining[size..];
        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
        }
    }

    if result.is_empty() { body.trim().to_string() } else { result }
}

// ── Send command ────────────────────────────────────────────────────────────

fn do_send(params: &[&str], rpc_host: &str, rpc_port: u16) {
    let wallet_path = params[0];
    let to_address = params[1];
    let amount_str = params[2];

    // Parse fee (default 0.001 BLOCH)
    let mut fee_bloch: f64 = 0.001;
    // Chain-id to sign for. The sighash folds in the chain-id, so signing for
    // the wrong one yields a SILENTLY-rejected tx ("invalid signature"). The
    // LIVE network is Genesis-2, so default to it (previously the wallet fell
    // back to Mainnet/Testnet by address prefix and required BLOCH_GENESIS2=1).
    // Override with `--chain genesis3|genesis2|mainnet|testnet`.
    let mut chain: String = "genesis2".to_string();
    let mut i = 3;
    while i < params.len() {
        if params[i] == "--fee" && i + 1 < params.len() {
            fee_bloch = params[i + 1].parse().unwrap_or_else(|_| die("invalid fee"));
            i += 2;
        } else if params[i] == "--chain" && i + 1 < params.len() {
            chain = params[i + 1].to_lowercase();
            i += 2;
        } else {
            i += 1;
        }
    }
    // The wallet's TxBuilder derives the sighash chain-id from BLOCH_GENESIS3 /
    // BLOCH_GENESIS2 (set => Genesis3Mainnet / Genesis2Devnet; unset =>
    // Testnet/Mainnet by address prefix). Fold the --chain choice into it, and
    // always print it so the choice is visible.
    match chain.as_str() {
        "genesis3" | "g3" => {
            std::env::remove_var("BLOCH_GENESIS2");
            std::env::set_var("BLOCH_GENESIS3", "1");
        }
        "genesis2" | "g2" => {
            std::env::remove_var("BLOCH_GENESIS3");
            std::env::set_var("BLOCH_GENESIS2", "1");
        }
        "mainnet" | "testnet" => {
            std::env::remove_var("BLOCH_GENESIS2");
            std::env::remove_var("BLOCH_GENESIS3");
        }
        other => die(&format!(
            "unknown --chain '{}': use genesis3 | genesis2 | mainnet | testnet", other)),
    }
    println!("Signing for chain: {}", chain);

    let amount_sats = bloch_to_sats(amount_str);
    let fee_sats = (fee_bloch * 1e8) as u64;

    // Load wallet
    let password = read_password("Wallet password: ");
    let path = std::path::Path::new(wallet_path);
    let keypair = match bloch::wallet::Keypair::load_encrypted(path, &password) {
        Ok(kp) => kp,
        Err(e) => { eprintln!("Failed to load wallet: {}", e); process::exit(1); }
    };

    println!("From: {}", keypair.address);
    println!("To:   {}", to_address);
    println!("Amount: {} BLOCH", amount_str);
    println!("Fee:    {} BLOCH", fee_bloch);

    // Get UTXOs via RPC
    // Pass a UTXO limit: a huge wallet (e.g. the carry-over founder set with
    // hundreds of thousands of UTXOs) otherwise returns a multi-MB response that
    // times out the client. A handful of UTXOs is plenty to cover any single spend.
    let utxos_result = match rpc_call(rpc_host, rpc_port, "getutxos", &serde_json::json!([keypair.address, 50])) {
        Ok(r) => r,
        Err(e) => { eprintln!("RPC error: {}", e); process::exit(1); }
    };

    let utxos_json = utxos_result.get("utxos").and_then(|u| u.as_array()).cloned().unwrap_or_default();
    if utxos_json.is_empty() {
        eprintln!("No UTXOs found for {}", keypair.address);
        process::exit(1);
    }

    // Convert to TxBuilder format
    let mut available_utxos: Vec<(Vec<u8>, u32, bloch::core::TxOutput)> = Vec::new();
    for u in &utxos_json {
        let txid = hex::decode(u["txid"].as_str().unwrap_or("")).unwrap_or_default();
        let idx = u["index"].as_u64().unwrap_or(0) as u32;
        let value = u["value"].as_u64().unwrap_or(0);
        let spk = hex::decode(u["script_pubkey"].as_str().unwrap_or("")).unwrap_or_default();
        available_utxos.push((txid, idx, bloch::core::TxOutput { value, script_pubkey: spk }));
    }

    let total_available: u64 = available_utxos.iter().map(|(_, _, o)| o.value).sum();
    println!("Available: {} BLOCH ({} UTXOs)", total_available as f64 / 1e8, available_utxos.len());

    // Sprint K: Parse and validate destination address (checksum-enforced)
    let to_addr = match bloch::address::Address::parse(to_address) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid destination address: {}", e);
            eprintln!("Hint: addresses must be 55 chars total (bloch1q + 40 hex hash + 8 hex checksum)");
            process::exit(1);
        }
    };
    let to_addr_hex = hex::encode(to_addr.hash());

    // Build and sign TX
    let tx = match bloch::wallet::TxBuilder::build(
        &keypair, &available_utxos, &to_addr_hex, amount_sats, fee_sats,
    ) {
        Ok(tx) => tx,
        Err(e) => { eprintln!("TX build failed: {}", e); process::exit(1); }
    };

    let txid = hex::encode(tx.txid());
    println!("TXID: {}", txid);

    // Serialize and broadcast
    // Sprint 1.d: Bitcoin-format wire (replaces bincode). Infallible.
    let raw = tx.to_stratum_bytes(true);
    let raw_hex = hex::encode(&raw);

    match rpc_call(rpc_host, rpc_port, "sendrawtransaction", &serde_json::json!([raw_hex])) {
        Ok(result) => {
            if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
                eprintln!("Broadcast rejected: {}", err);
                process::exit(1);
            }
            println!("Broadcast OK");
        }
        Err(e) => { eprintln!("Broadcast failed: {}", e); process::exit(1); }
    }
}

// ── New wallet command ──────────────────────────────────────────────────────

// ── Phase 3: HD Wallet functions ────────────────────────────────────────────

fn do_newseed(output_path: &str) {
    println!("Generating HD wallet with 24-word mnemonic...");
    println!();

    let password = loop {
        let p1 = read_password("Set password (min 12 chars, 3 of: upper/lower/digit/special): ");
        if let Err(e) = bloch::wallet::validate_password(&p1) {
            eprintln!("Weak password: {}", e);
            continue;
        }
        let p2 = read_password("Confirm password: ");
        if p1 != p2 {
            eprintln!("Passwords don't match.");
            continue;
        }
        break p1;
    };

    let use_passphrase = read_password("Optional passphrase (press Enter to skip): ");
    let passphrase = if use_passphrase.is_empty() { None } else { Some(use_passphrase.as_str()) };

    let testnet = output_path.contains("testnet");
    let wallet = match bloch::hd_wallet::HdWallet::create(&password, passphrase, testnet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Failed to create wallet: {}", e); process::exit(1); }
    };

    let mnemonic_str = wallet.mnemonic.to_string();
    let first_addr = wallet.addresses[0].1.address.clone();

    let path = std::path::Path::new(output_path);
    if let Err(e) = wallet.save(path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!("  BACKUP YOUR MNEMONIC PHRASE (24 words)");
    println!("══════════════════════════════════════════════════════════════");
    println!();
    let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
    for (i, chunk) in words.chunks(4).enumerate() {
        let line: Vec<String> = chunk.iter().enumerate().map(|(j, w)| {
            format!("{:2}. {:<10}", i * 4 + j + 1, w)
        }).collect();
        println!("  {}", line.join(" "));
    }
    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!();
    println!("Write these 24 words on paper. Store offline.");
    println!("Without BOTH the mnemonic AND {}, the wallet is inaccessible.", output_path);
    if passphrase.is_some() {
        println!("Passphrase is ALSO required to unlock.");
    }
    println!();
    println!("First address: {}", first_addr);
    println!("Wallet file:   {}", output_path);
}

fn do_newaddress(wallet_path: &str, label: &str) {
    let password = read_password("Wallet password: ");
    let passphrase_input = read_password("Passphrase (Enter to skip): ");
    let passphrase = if passphrase_input.is_empty() { None } else { Some(passphrase_input.as_str()) };
    let mnemonic = read_password("Mnemonic (24 words): ");

    let path = std::path::Path::new(wallet_path);
    let mut wallet = match bloch::hd_wallet::HdWallet::load(path, &mnemonic, passphrase, &password) {
        Ok(w) => w,
        Err(e) => { eprintln!("Load failed: {}", e); process::exit(1); }
    };

    let new_kp = wallet.new_address(label);
    let new_addr = new_kp.address.clone();

    if let Err(e) = wallet.save(path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("New address: {}", new_addr);
    println!("Label:       {}", label);
}

fn do_list_addresses(wallet_path: &str) {
    // For listing we just show what's in the file (no decryption needed for public data)
    let json = match std::fs::read_to_string(wallet_path) {
        Ok(s) => s,
        Err(e) => { eprintln!("Cannot read {}: {}", wallet_path, e); process::exit(1); }
    };
    let wallet: bloch::hd_wallet::HdWalletFile = match serde_json::from_str(&json) {
        Ok(w) => w,
        Err(e) => { eprintln!("Invalid wallet file: {}", e); process::exit(1); }
    };
    println!();
    println!("HD Wallet — {} ({})", wallet_path, wallet.network);
    println!("Created: {}", wallet.created_at);
    println!();
    println!("  {:<4} {:<56} {}", "idx", "address", "label");
    println!("  {}", "-".repeat(80));
    for addr in &wallet.addresses {
        println!("  {:<4} {:<56} {}", addr.index, addr.address, addr.label);
    }
    println!();
    println!("Total: {} address(es)", wallet.addresses.len());
}

fn do_import_founder(hd_wallet_path: &str, founder_path: &str) {
    println!("Importing founder.json into HD wallet...");
    println!();

    let founder_password = read_password("founder.json password: ");
    let founder_path_p = std::path::Path::new(founder_path);
    let founder_kp = match bloch::wallet::Keypair::load_encrypted(founder_path_p, &founder_password) {
        Ok(kp) => kp,
        Err(e) => { eprintln!("Failed to load founder.json: {}", e); process::exit(1); }
    };

    println!("Founder address: {}", founder_kp.address);
    println!();

    let hd_password = read_password("HD wallet password: ");
    let hd_passphrase_input = read_password("HD wallet passphrase (Enter to skip): ");
    let hd_passphrase = if hd_passphrase_input.is_empty() { None } else { Some(hd_passphrase_input.as_str()) };
    let mnemonic = read_password("HD wallet mnemonic (24 words): ");

    let hd_path = std::path::Path::new(hd_wallet_path);
    let mut wallet = match bloch::hd_wallet::HdWallet::load(hd_path, &mnemonic, hd_passphrase, &hd_password) {
        Ok(w) => w,
        Err(e) => { eprintln!("Failed to load HD wallet: {}", e); process::exit(1); }
    };

    let addr = founder_kp.address.clone();
    wallet.import_keypair(founder_kp, "founder");

    if let Err(e) = wallet.save(hd_path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("Imported: {}", addr);
    println!("Label:    founder");
}

// ── Original wallet function ────────────────────────────────────────────────

fn do_new_wallet(output_path: &str) {
    println!("Generating ML-DSA-65 keypair...");

    let password = loop {
        let p1 = read_password("Set password (min 12 chars, 3 of: upper/lower/digit/special): ");
        if let Err(e) = bloch::wallet::validate_password(&p1) {
            eprintln!("Weak password: {}", e);
            continue;
        }
        let p2 = read_password("Confirm password: ");
        if p1 != p2 {
            eprintln!("Passwords don't match.");
            continue;
        }
        break p1;
    };

    let testnet = output_path.contains("testnet");
    let keypair = bloch::wallet::generate_keypair(testnet);
    let path = std::path::Path::new(output_path);

    match keypair.save_encrypted(path, &password) {
        Ok(_) => {
            println!("Wallet saved: {}", output_path);
            println!("Address:      {}", keypair.address);
            println!("Network:      {}", if testnet { "testnet" } else { "mainnet" });
            println!();
            println!("BACKUP THIS FILE. If lost, your BLOCH is gone forever.");
        }
        Err(e) => {
            eprintln!("Failed to save wallet: {}", e);
            process::exit(1);
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn read_password(prompt: &str) -> String {
    eprint!("{}", prompt);
    rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("Failed to read password: {}", e);
        process::exit(1);
    })
}

fn bloch_to_sats(s: &str) -> u64 {
    let f: f64 = s.parse().unwrap_or_else(|_| die("invalid amount"));
    (f * 1e8) as u64
}

fn require_params(params: &[&str], min: usize, usage: &str) {
    if params.len() < min {
        eprintln!("Usage: bloch-cli {}", usage);
        process::exit(1);
    }
}

fn die(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    process::exit(1);
}

fn print_usage() {
    println!(r#"
  bloch-cli — Bloch-SIS Protocol RPC client

  NETWORK
    bloch-cli info                          Network info
    bloch-cli height                        Current block count
    bloch-cli mempool                       Mempool info
    bloch-cli peers                         Peer info
    bloch-cli dag                           DAG info (tips, chain, scores)

  BLOCKS
    bloch-cli block <height> [verbose]      Get block by height
    bloch-cli getblock <hash> [verbose]     Get block by hash
    bloch-cli getblockhash <height>         Get block hash at height
    bloch-cli recent [count]                Recent blocks (default: 10)

  TRANSACTIONS
    bloch-cli tx <txid>                     Get transaction
    bloch-cli sendraw <hex>                 Broadcast raw transaction
    bloch-cli decode <hex>                  Decode raw TX (without broadcast)
    bloch-cli rawmempool [verbose]          List mempool transactions
    bloch-cli fee                           Estimate fee

  WALLET (simple)
    bloch-cli balance <address>             Get balance
    bloch-cli utxos <address>               List unspent outputs
    bloch-cli txlist <address> [count]      Transaction history
    bloch-cli validate <address>            Validate address format
    bloch-cli newwallet <path.json>         Generate simple wallet (1 keypair)
    bloch-cli send <wallet.json> <to> <amount> [--fee 0.001]

  HD WALLET (BIP39, multi-address)
    bloch-cli newseed <wallet-hd.json>      Generate 24-word mnemonic + wallet
    bloch-cli newaddress <wallet-hd.json> [label]    Add new address
    bloch-cli addresses <wallet-hd.json>    List all addresses
    bloch-cli importfounder <wallet-hd.json> <founder.json>    Import simple wallet

  eUTXO VM (node built with --features euvm)
    bloch-cli euvm_utxos [validator_hash] [limit] [offset]   List eUTXO contract UTXOs
    bloch-cli euvm_getutxo <txid> <index>   Inspect one UTXO (legacy or eUTXO, decoded)
    bloch-cli euvm_buildtx '<json>'         Build (and pre-validate) an eUTXO raw tx
                                            from a JSON build-request; broadcast the
                                            returned raw_tx with 'sendraw'

  PROOF-OF-IMPROVEMENT (PoI)
    bloch-cli treasury                      Treasury balance and stats
    bloch-cli claims                        List all PoI claims
    bloch-cli claim <claim_id>              Get claim details + vote tally
    bloch-cli submitclaim <commit> <cat:0-3> <desc> <addr> [ci_hex]    Submit improvement
    bloch-cli vote <claim_id> <voter_addr> <yes|no|abstain>            Vote on claim

  OPTIONS
    --rpc-host <host>                      RPC host (default: 127.0.0.1)
    --rpc-port <port>                      RPC port (default: 16210)
    --help                                 This message
"#);
}
