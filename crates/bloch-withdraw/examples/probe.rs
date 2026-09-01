// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only smoke test against a real node.
//!
//! ```sh
//! cargo run -p bloch-withdraw --example probe -- 139.84.201.52:16400 [bloch1q-address]
//! ```
//!
//! Prints the chain info a withdrawal decision reads (head vs finalized, the
//! two base fees, staleness), and — given an address — its balance and first
//! unspent outputs. Sends nothing.

use bloch_withdraw::address::parse_payee;
use bloch_withdraw::rpc::{chain_info, get_balance, list_unspent};
use bloch_withdraw::HttpNode;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(addr) = args.next() else {
        eprintln!("usage: probe <host:port> [bloch1q-address]");
        std::process::exit(2);
    };
    let node = HttpNode::new(&addr);

    match chain_info(&node) {
        Ok(info) => {
            println!("slot                {}", info.slot);
            println!("epoch               {}", info.epoch);
            println!("height              {}", info.height);
            println!("finalized_height    {:?}", info.finalized_height);
            println!("finalized_epoch     {}", info.finalized_epoch);
            println!("finalized_boundary  slot {}", info.finalized_boundary_slot());
            println!("base_fee            {} msat/gas", info.base_fee_msat_per_gas);
            println!("next_base_fee       {} msat/gas  <- build against THIS", info.next_base_fee_msat_per_gas);
            println!("behind_by_slots     {}", info.behind_by_slots);
        }
        Err(e) => {
            eprintln!("getchaininfo failed: {e}");
            std::process::exit(1);
        }
    }

    // Takes a 64-hex script_hash (what `bloch-pos spendkey` prints). A probe is
    // read-only, so it accepts either network and the carryover address form
    // too — it moves no coins and refusing here would only make it useless for
    // looking at a carried balance.
    if let Some(address) = args.next() {
        let net = if address.starts_with("bloch1t") {
            bloch_crypto::address::Network::Testnet
        } else {
            bloch_crypto::address::Network::Mainnet
        };
        let script_hash = match parse_payee(&address, net, true) {
            Ok((h, _form)) => h,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
        match get_balance(&node, &script_hash) {
            Ok((balance, count)) => {
                println!("\naddress             {address}");
                println!("balance_sat         {balance}");
                println!("utxo_count          {count}");
            }
            Err(e) => eprintln!("getbalance failed: {e}"),
        }
        match list_unspent(&node, &script_hash, 5) {
            Ok((utxos, truncated)) => {
                for u in &utxos {
                    let txid_hex: String =
                        u.txid.iter().map(|b| format!("{b:02x}")).collect();
                    println!("utxo  {}:{}  {} sat", txid_hex, u.vout, u.value_sat);
                }
                if truncated {
                    println!("(listing truncated by the node)");
                }
            }
            Err(e) => eprintln!("listunspent failed: {e}"),
        }
    }
}
