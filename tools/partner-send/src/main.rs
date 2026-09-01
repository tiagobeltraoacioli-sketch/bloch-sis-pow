// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-partner-send` — one small, attended BLCH transfer at a time.
//!
//! Four subcommands, three of which exist so the key never has to touch the
//! connected machine:
//!
//! - `plan`      read-only: select coins, price the transfer, write plan.json,
//!               show the full preview and the signing root. Touches no key.
//! - `sign`      offline-capable: load a key (seed phrase / encrypted keyfile /
//!               node keystore), re-check the plan, show the preview, demand
//!               the typed confirmation, sign, write signed.json.
//! - `broadcast` re-check everything in signed.json (root, signature, input
//!               spendability), show the preview again, confirm, send.
//! - `send`      the three above in one interactive run, for when the key is
//!               on this machine anyway. Same preview, same typed phrase.
//!
//! Every value-moving path runs through `confirm_or_abort`, which refuses to
//! proceed when stdin/stdout are not a terminal. There is no `--yes`, no
//! environment override, and no way to pipe the phrase in.

use std::io::{BufRead, IsTerminal, Write};
use std::process::exit;

use bloch_crypto::address::Address;
use bloch_partner_send::{
    build_plan, check_plan_integrity, check_signed_plan, confirmation_phrase, format_blch,
    keypair_from_seed_phrase, parse_blch, parse_node_keystore, preview, rpc, script_hash32, Plan,
    SignedPlan, DEFAULT_TIP_MILLISAT_PER_GAS, MAX_PARTNER_SEND_SAT,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("plan") => plan_cmd(&args[1..]),
        Some("sign") => sign_cmd(&args[1..]),
        Some("broadcast") => broadcast_cmd(&args[1..]),
        Some("send") => send_cmd(&args[1..]),
        Some("--help") | Some("-h") | None => help(),
        Some(other) => {
            eprintln!("bloch-partner-send: unknown command `{other}` (see --help)");
            exit(2);
        }
    }
}

fn help() {
    println!(
        "bloch-partner-send — one small, attended BLCH transfer at a time (Genesis-4)\n\
         \n\
         Hard rails, none overridable by flag:\n\
           * amount and destination are REQUIRED — no defaults, no batch mode\n\
           * per-run cap: {} BLCH (MAX_PARTNER_SEND_SAT; changing it means editing source)\n\
           * refuses to create any output below 546 sat (the dust floor)\n\
           * confirmation is a typed phrase at a real terminal — no --yes, no pipe\n\
         \n\
         USAGE:\n\
           bloch-partner-send plan --rpc <http://host:16400> --from <bloch1q…>\n\
                                   --to <bloch1q…> --amount <BLCH>\n\
                                   [--tip <millisat-per-gas>] --out plan.json\n\
               Read-only. Selects coins, prices the transfer at the node's next\n\
               base fee, prints the full preview + signing root, writes the plan.\n\
           bloch-partner-send sign --plan plan.json --out signed.json\n\
                                   (--seed | --keyfile <file> | --keystore-dir <dir>)\n\
               Prompts for the key material (hidden input), re-checks the plan,\n\
               shows the preview, demands the typed confirmation, signs.\n\
               Runs offline — no --rpc.\n\
           bloch-partner-send broadcast --rpc <url> --signed signed.json\n\
               Re-verifies plan + signature, re-checks the inputs are still\n\
               unspent, shows the preview, confirms again, broadcasts.\n\
           bloch-partner-send send --rpc <url> --from <addr> --to <addr>\n\
                                   --amount <BLCH> [--tip <n>]\n\
                                   (--seed | --keyfile <file> | --keystore-dir <dir>)\n\
               plan + sign + broadcast in one attended run.\n\
         \n\
         The partner confirms receipt with tools/partner-send/verify_receipt.py —\n\
         Genesis-4 has no transaction ids at the wallet layer; the address balance\n\
         and its UTXO set ARE the receipt.",
        format_blch(MAX_PARTNER_SEND_SAT)
    );
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn required(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("bloch-partner-send: {name} is required (no defaults for anything that moves value)");
        exit(2);
    })
}

fn parse_addr(s: &str, what: &str) -> Address {
    Address::parse(s).unwrap_or_else(|e| {
        eprintln!("bloch-partner-send: {what} `{s}`: {e}");
        exit(2);
    })
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("bloch-partner-send: {msg}");
    exit(1);
}

// ── The attended gate ───────────────────────────────────────────────────────

/// Show the preview and demand the typed phrase. Aborts the process unless a
/// human at a real terminal types it exactly (three attempts for typos).
///
/// Fails closed on every non-interactive path: piped stdin, redirected
/// stdout, EOF, mismatch. This is the property that makes the tool incapable
/// of unattended operation, so nothing may call the RPC broadcast or a
/// signing key before it returns.
fn confirm_or_abort(plan: &Plan, action: &str) {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        die(format!(
            "refusing to {action}: stdin/stdout is not a terminal. This tool has no unattended \
             mode — run it interactively."
        ));
    }
    print!("{}", preview(plan));
    let phrase = confirmation_phrase(plan);
    println!("To {action}, type exactly:  {phrase}");
    let stdin = std::io::stdin();
    for attempt in 1..=3 {
        print!("> ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => die(format!("no confirmation (EOF); nothing was {action}ed")),
            Ok(_) => {}
        }
        if line.trim_end_matches(['\r', '\n']) == phrase {
            return;
        }
        if attempt < 3 {
            eprintln!("that did not match; type the phrase exactly, or Ctrl-C to abort");
        }
    }
    die(format!("confirmation did not match after 3 attempts; nothing was {action}ed"));
}

// ── Key loading (sign paths only) ───────────────────────────────────────────

/// Load the hybrid keypair from exactly one explicitly chosen source. Every
/// prompt is hidden input; no secret is echoed, logged, or written.
fn load_key(args: &[String]) -> (Vec<u8>, Vec<u8>) {
    let sources = [has_flag(args, "--seed"), arg(args, "--keyfile").is_some(),
        arg(args, "--keystore-dir").is_some()];
    match sources.iter().filter(|s| **s).count() {
        0 => die("choose a key source: --seed, --keyfile <file>, or --keystore-dir <dir>"),
        1 => {}
        _ => die("choose exactly ONE key source"),
    }
    if !std::io::stdin().is_terminal() {
        die("refusing to read key material without a terminal");
    }
    if has_flag(args, "--seed") {
        let phrase = rpassword::prompt_password("BIP39 seed phrase (input hidden): ")
            .unwrap_or_else(|e| die(format!("reading seed phrase: {e}")));
        return keypair_from_seed_phrase(phrase.trim()).unwrap_or_else(|e| die(e));
    }
    if let Some(path) = arg(args, "--keyfile") {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| die(format!("{path}: {e}")));
        let ef: bloch_crypto::wallet::encryption::EncryptedKeyfile =
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| die(format!("{path}: not an encrypted keyfile: {e}")));
        let password = rpassword::prompt_password("keyfile password (input hidden): ")
            .unwrap_or_else(|e| die(format!("reading password: {e}")));
        let (secret, public, _net) =
            ef.decrypt(&password).unwrap_or_else(|e| die(format!("{path}: {e}")));
        return (public, secret);
    }
    let dir = arg(args, "--keystore-dir").expect("checked above");
    let path = std::path::Path::new(&dir).join("validator.key");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
    parse_node_keystore(&bytes).unwrap_or_else(|e| die(format!("{}: {e}", path.display())))
}

// ── Subcommands ─────────────────────────────────────────────────────────────

fn build_plan_from_chain(args: &[String]) -> (rpc::Client, Plan) {
    let url = required(args, "--rpc");
    let from = parse_addr(&required(args, "--from"), "--from");
    let to = parse_addr(&required(args, "--to"), "--to");
    let amount_sat = parse_blch(&required(args, "--amount")).unwrap_or_else(|e| die(e));
    let tip = match arg(args, "--tip") {
        None => DEFAULT_TIP_MILLISAT_PER_GAS,
        Some(t) => t.parse::<u128>().unwrap_or_else(|_| die(format!("--tip `{t}` is not a number"))),
    };

    let client = rpc::Client::new(&url).unwrap_or_else(|e| die(e));
    let base = rpc::next_base_fee(&client).unwrap_or_else(|e| die(e));
    let coins = rpc::get_coins(&client, &script_hash32(&from)).unwrap_or_else(|e| die(e));
    println!(
        "source holds {} coin(s); pricing at base fee {} millisat/gas (tip {})",
        coins.len(),
        base,
        tip
    );
    let plan = build_plan(&from, &to, amount_sat, &coins, base, tip).unwrap_or_else(|e| die(e));
    (client, plan)
}

fn plan_cmd(args: &[String]) {
    let out = required(args, "--out");
    let (_client, plan) = build_plan_from_chain(args);
    print!("{}", preview(&plan));
    let json = serde_json::to_string_pretty(&plan).expect("plan serializes");
    std::fs::write(&out, json).unwrap_or_else(|e| die(format!("{out}: {e}")));
    println!(
        "plan written to {out}. Nothing was signed and nothing was sent.\n\
         Next: bloch-partner-send sign --plan {out} --out signed.json \
         (--seed | --keyfile … | --keystore-dir …)"
    );
}

fn read_plan(path: &str) -> Plan {
    let bytes = std::fs::read(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    let plan: Plan =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| die(format!("{path}: {e}")));
    check_plan_integrity(&plan).unwrap_or_else(|e| die(format!("{path}: {e}")));
    plan
}

fn sign_cmd(args: &[String]) {
    let plan_path = required(args, "--plan");
    let out = required(args, "--out");
    let plan = read_plan(&plan_path);
    confirm_or_abort(&plan, "sign");
    let (public, secret) = load_key(args);
    let signed = bloch_partner_send::sign_plan(&plan, &public, &secret).unwrap_or_else(|e| die(e));
    let json = serde_json::to_string_pretty(&signed).expect("signed plan serializes");
    std::fs::write(&out, json).unwrap_or_else(|e| die(format!("{out}: {e}")));
    println!(
        "signed transfer written to {out} (txid {}). Not broadcast yet.\n\
         Next: bloch-partner-send broadcast --rpc <url> --signed {out}",
        signed.plan.txid
    );
}

fn read_signed(path: &str) -> (SignedPlan, Vec<u8>) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    let sp: SignedPlan =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| die(format!("{path}: {e}")));
    let raw = check_signed_plan(&sp).unwrap_or_else(|e| die(format!("{path}: {e}")));
    (sp, raw)
}

fn broadcast_cmd(args: &[String]) {
    let url = required(args, "--rpc");
    let signed_path = required(args, "--signed");
    let (sp, raw) = read_signed(&signed_path);
    let client = rpc::Client::new(&url).unwrap_or_else(|e| die(e));
    preflight_inputs(&client, &sp.plan);
    confirm_or_abort(&sp.plan, "broadcast");
    do_broadcast(&client, &sp, &raw);
}

/// The chain moved on since the plan: check the base fee still matches (a
/// transfer is valid at exactly one price point) and every input is still
/// unspent. Better a refusal here than a silent mempool rejection.
fn preflight_inputs(client: &rpc::Client, plan: &Plan) {
    match rpc::next_base_fee(client) {
        Ok(base) if base != plan.base_fee_millisat_per_gas => die(format!(
            "the chain's next base fee is now {base} millisat/gas but this transfer was priced \
             at {}; conservation is exact, so it would be refused. Re-plan at the current fee.",
            plan.base_fee_millisat_per_gas
        )),
        Ok(_) => {}
        Err(e) => die(format!("cannot read the current base fee: {e}")),
    }
    for i in &plan.inputs {
        match rpc::is_unspent(client, &i.txid, i.vout) {
            Ok(true) => {}
            Ok(false) => die(format!(
                "input {}:{} is no longer unspent — something else moved the source's coins. \
                 Re-plan from the current UTXO set.",
                &i.txid[..16],
                i.vout
            )),
            Err(e) => die(format!("checking input {}:{}: {e}", &i.txid[..16], i.vout)),
        }
    }
}

fn do_broadcast(client: &rpc::Client, sp: &SignedPlan, raw: &[u8]) {
    let (accepted, txid) =
        rpc::send_raw(client, &hex::encode(raw)).unwrap_or_else(|e| die(e));
    if !accepted {
        die("the node did not accept the transaction into its mempool");
    }
    println!(
        "accepted into the mempool (txid {txid}).\n\
         Confirmation is the destination's balance, not this txid: have the partner run\n\
           python3 tools/partner-send/verify_receipt.py {} --rpc <their-node> --expect {}\n\
         Funds are settled when the receiving block's epoch is finalized (16–32 min).",
        sp.plan.to_address,
        format_blch(sp.plan.amount_sat),
    );
}

fn send_cmd(args: &[String]) {
    let (client, plan) = build_plan_from_chain(args);
    preflight_inputs(&client, &plan); // cheap; also proves gettxout agrees
    confirm_or_abort(&plan, "sign-and-broadcast");
    let (public, secret) = load_key(args);
    let signed = bloch_partner_send::sign_plan(&plan, &public, &secret).unwrap_or_else(|e| die(e));
    let raw = check_signed_plan(&signed).unwrap_or_else(|e| die(e));
    do_broadcast(&client, &signed, &raw);
}
