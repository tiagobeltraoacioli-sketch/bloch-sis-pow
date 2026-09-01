// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Run the reference withdrawal client, for real, on a Genesis-4 testnet.
//!
//! This exists because the integration book's §7.9 says the spend path has
//! never been executed with production key material, and an exchange will not
//! let a customer withdrawal be its first execution. The answer to that is not
//! a paragraph; it is this program, run against a chain.
//!
//! ```text
//!   cargo run --release -p bloch-withdraw --example testnet_rehearsal -- \
//!       <rpc host:port> <recipient script_hash hex> <amount_sat> [seed-hex]
//! ```
//!
//! It prints the hot wallet's `script_hash` and exits if that wallet is empty,
//! so the operator can drip to it first. THROWAWAY KEYS ONLY: the seed is a
//! command-line argument, which is the wrong place for anything that guards
//! real money.

use bloch_withdraw::{FileStore, HttpNode, KeyMaterial, Status, Withdrawer};
use bloch_withdraw::rpc::{chain_info, get_balance};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(rpc), Some(to), Some(amount)) = (a.first(), a.get(1), a.get(2)) else {
        eprintln!(
            "usage: testnet_rehearsal <host:port> <recipient-script-hash-hex> <amount_sat> [seed-hex]"
        );
        std::process::exit(2);
    };
    let amount: u64 = amount.parse().expect("amount_sat is a u64");
    let seed_hex = a.get(3).cloned().unwrap_or_else(|| "11".repeat(32));
    let seed: Vec<u8> = (0..seed_hex.len() / 2)
        .map(|i| u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).expect("seed is hex"))
        .collect();

    let node = HttpNode::new(rpc);
    let key = KeyMaterial::from_seed(&seed).expect("keypair from seed");
    let sh = key.script_hash();
    let sh_hex: String = sh.iter().map(|b| format!("{b:02x}")).collect();
    println!("hot wallet script_hash : {sh_hex}");
    println!("  (this is SHA3-256(pubkey) — the one derivation; drip to THIS)");

    match chain_info(&node) {
        Ok(i) => println!("node                   : height {} behind {} slots", i.height, i.behind_by_slots),
        Err(e) => {
            eprintln!("getchaininfo failed: {e}");
            std::process::exit(1);
        }
    }
    let (bal, n) = get_balance(&node, &sh).expect("getbalance");
    println!("hot wallet balance     : {bal} sat across {n} outputs");
    if bal == 0 {
        eprintln!("\nhot wallet is empty — drip to the script_hash above, then re-run.");
        std::process::exit(3);
    }

    let store = FileStore::open(
        std::env::var("WITHDRAW_STORE").unwrap_or_else(|_| "/tmp/bloch-withdraw-rehearsal".into()),
    )
    .expect("store");
    let mut w = Withdrawer::new(&node, &store, &key);
    // THE FIX UNDER TEST: the client is told which chain it is on. Mainnet
    // stays the default everywhere else; this is the explicit opt-in.
    w.cfg.network = bloch_crypto::address::Network::Testnet;

    let id = std::env::var("WITHDRAW_ID").unwrap_or_else(|_| "rehearsal-1".into());
    let rec = w.create(&id, to, amount).expect("create");
    println!("\ncreated {id}: {} sat -> {}", rec.amount_sat, hex(&rec.recipient_script_hash));

    for round in 1..=200 {
        match w.tick(&id) {
            Ok(o) => {
                println!("tick {round:>3}: status {:?}{}", o.status, match &o.submit {
                    Some(s) => format!("  submit {s:?}"),
                    None => String::new(),
                });
                if o.status.is_terminal() {
                    println!("\nTERMINAL: {:?}", o.status);
                    std::process::exit(match o.status {
                        Status::Paid { .. } => 0,
                        _ => 4,
                    });
                }
            }
            Err(e) => {
                eprintln!("tick {round}: {e}");
                std::process::exit(1);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    eprintln!("gave up waiting");
    std::process::exit(5);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
