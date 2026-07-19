//! tkv0_inject — throwaway local-testnet driver for the bloch-tokens
//! reference indexer end-to-end test. NOT part of the node; lives in
//! examples/ only to reuse the compiled `bloch` lib. Envelope bytes are
//! hand-encoded here to match the TKV0 SPEC so the injector shares NO code
//! with the indexer under test.

use bloch::core::{ChainId, Transaction, TxInput, TxOutput};
use bloch::wallet::{generate_keypair, Keypair};
use std::io::{Read, Write};
use std::net::TcpStream;

fn rpc(port: u16, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let addr = format!("127.0.0.1:{}", port);
    let mut s = TcpStream::connect(&addr).expect("connect node rpc");
    s.set_read_timeout(Some(std::time::Duration::from_secs(30))).unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        addr, body.len(), body);
    s.write_all(req.as_bytes()).unwrap();
    s.flush().unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let text = String::from_utf8_lossy(&resp);
    let start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let bodytext = &text[start..];
    let clean = if text.contains("Transfer-Encoding: chunked") { dechunk(bodytext) } else { bodytext.trim().to_string() };
    let v: serde_json::Value = serde_json::from_str(&clean)
        .unwrap_or_else(|e| panic!("bad json: {} raw={}", e, &clean[..clean.len().min(300)]));
    v.get("result").cloned().unwrap_or(v)
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rem = body.trim();
    loop {
        let nl = match rem.find("\r\n") { Some(i) => i, None => break };
        let size = match usize::from_str_radix(rem[..nl].trim(), 16) { Ok(0) => break, Ok(s) => s, Err(_) => return body.trim().to_string() };
        rem = &rem[nl + 2..];
        if rem.len() < size { break; }
        out.push_str(&rem[..size]);
        rem = &rem[size..];
        if rem.starts_with("\r\n") { rem = &rem[2..]; }
    }
    if out.is_empty() { body.trim().to_string() } else { out }
}

fn issue_env(decimals: u8, supply: u64, symbol: &str, name: &str) -> Vec<u8> {
    let mut v = vec![0x54, 0x4B, 0x56, 0x30, 0x00, 0x01, decimals, 0x01];
    v.extend_from_slice(&supply.to_le_bytes());
    v.push(symbol.len() as u8);
    v.extend_from_slice(symbol.as_bytes());
    v.push(name.len() as u8);
    v.extend_from_slice(name.as_bytes());
    v
}

fn transfer_env(token_id: [u8; 32], assigns: &[(u32, u64)]) -> Vec<u8> {
    let mut v = vec![0x54, 0x4B, 0x56, 0x30, 0x00, 0x02];
    v.extend_from_slice(&token_id);
    v.push(assigns.len() as u8);
    for (vout, amt) in assigns { v.extend_from_slice(&vout.to_le_bytes()); v.extend_from_slice(&amt.to_le_bytes()); }
    v
}

fn load_wallet(path: &str) -> Keypair {
    let txt = std::fs::read_to_string(path).expect("read wallet");
    let j: serde_json::Value = serde_json::from_str(&txt).unwrap();
    Keypair {
        private_key: hex::decode(j["private_key_hex"].as_str().unwrap()).unwrap(),
        public_key: hex::decode(j["public_key_hex"].as_str().unwrap()).unwrap(),
        address: j["address"].as_str().unwrap().to_string(),
    }
}

fn sign_tx(mut tx: Transaction, kp: &Keypair) -> Transaction {
    for i in 0..tx.inputs.len() {
        let sighash = tx.sighash(i, ChainId::Testnet);
        let sig = kp.sign(&sighash).expect("sign");
        tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &kp.public_key);
    }
    tx
}

fn pick_mature_utxo(port: u16, addr: &str, need: u64) -> ([u8; 32], u32, u64) {
    let r = rpc(port, "getutxos", serde_json::json!([addr]));
    let utxos = r["utxos"].as_array().cloned().unwrap_or_default();
    for u in &utxos {
        let value = u["value"].as_u64().unwrap_or(0);
        if value < need { continue; }
        let txid_hex = u["txid"].as_str().unwrap_or("");
        let idx = u["index"].as_u64().unwrap_or(0) as u32;
        let tx = rpc(port, "gettransaction", serde_json::json!([txid_hex]));
        let conf = tx["confirmations"].as_u64().unwrap_or(0);
        let coinbase = tx["transaction"]["coinbase"].as_bool().unwrap_or(false);
        if coinbase && conf < 100 { continue; }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hex::decode(txid_hex).unwrap());
        return (txid, idx, value);
    }
    panic!("no mature utxo with value >= {} found ({} utxos)", need, utxos.len());
}

fn send(port: u16, tx: &Transaction) -> String {
    let raw = hex::encode(tx.to_stratum_bytes(true));
    let r = rpc(port, "sendrawtransaction", serde_json::json!([raw]));
    if let Some(e) = r.get("error").and_then(|e| e.as_str()) { panic!("sendrawtransaction rejected: {}", e); }
    hex::encode(tx.txid())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("genwallet") => {
            let kp = generate_keypair(true);
            let j = serde_json::json!({
                "private_key_hex": hex::encode(&kp.private_key),
                "public_key_hex": hex::encode(&kp.public_key),
                "address": kp.address,
            });
            std::fs::write(&args[2], serde_json::to_string_pretty(&j).unwrap()).unwrap();
            println!("{}", kp.address);
        }
        Some("issue") => {
            let kp = load_wallet(&args[2]);
            let port: u16 = args[3].parse().unwrap();
            let symbol = &args[4];
            let supply: u64 = args[5].parse().unwrap();
            let colored_val = 1_000_000u64;
            let fee = 50_000u64;
            let (txid, idx, val) = pick_mature_utxo(port, &kp.address, colored_val + fee);
            let mut outputs = vec![
                TxOutput { value: colored_val, script_pubkey: kp.address_bytes() },
                TxOutput { value: 0, script_pubkey: issue_env(0, supply, symbol, "Acme") },
            ];
            let change = val - colored_val - fee;
            if change > 546 { outputs.push(TxOutput { value: change, script_pubkey: kp.address_bytes() }); }
            let tx = Transaction { version: 1, inputs: vec![TxInput { prev_txid: txid, prev_index: idx, script_sig: vec![], sequence: u32::MAX }], outputs, locktime: 0 };
            println!("{}", send(port, &sign_tx(tx, &kp)));
        }
        Some("transfer") => {
            let kp = load_wallet(&args[2]);
            let port: u16 = args[3].parse().unwrap();
            let mut token_id = [0u8; 32];
            token_id.copy_from_slice(&hex::decode(&args[4]).unwrap());
            let amount: u64 = args[5].parse().unwrap();
            let recipient = [0xBBu8; 20].to_vec();
            let out_val = 500_000u64;
            let fee = 50_000u64;
            let mut outputs = vec![
                TxOutput { value: out_val, script_pubkey: recipient },
                TxOutput { value: 0, script_pubkey: transfer_env(token_id, &[(0, amount)]) },
            ];
            let change = 1_000_000u64 - out_val - fee;
            if change > 546 { outputs.push(TxOutput { value: change, script_pubkey: kp.address_bytes() }); }
            let tx = Transaction { version: 1, inputs: vec![TxInput { prev_txid: token_id, prev_index: 0, script_sig: vec![], sequence: u32::MAX }], outputs, locktime: 0 };
            println!("{}", send(port, &sign_tx(tx, &kp)));
        }
        Some("malformed") => {
            let kp = load_wallet(&args[2]);
            let port: u16 = args[3].parse().unwrap();
            let mut token_id = [0u8; 32];
            token_id.copy_from_slice(&hex::decode(&args[4]).unwrap());
            let mut bad = transfer_env(token_id, &[(0, 1)]);
            bad[0] = 0x58; // corrupt magic: "XKV0"
            let (utxo, idx, val) = pick_mature_utxo(port, &kp.address, 60_000);
            let mut outputs = vec![
                TxOutput { value: 546, script_pubkey: kp.address_bytes() },
                TxOutput { value: 0, script_pubkey: bad },
            ];
            let change = val - 546 - 50_000;
            if change > 546 { outputs.push(TxOutput { value: change, script_pubkey: kp.address_bytes() }); }
            let tx = Transaction { version: 1, inputs: vec![TxInput { prev_txid: utxo, prev_index: idx, script_sig: vec![], sequence: u32::MAX }], outputs, locktime: 0 };
            println!("{}", send(port, &sign_tx(tx, &kp)));
        }
        _ => { eprintln!("usage: tkv0_inject genwallet|issue|transfer|malformed ..."); std::process::exit(1); }
    }
}
