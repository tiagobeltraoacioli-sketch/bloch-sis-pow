// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-stake` — attended Genesis-4 staking transactions, one at a time.
//!
//! Four operator actions (`deposit`, `exit`, `delegate`, `withdraw`), each
//! split `plan` / `sign` / `broadcast` so the key never has to touch the
//! connected machine. Every value-moving path shows the full plan — inputs,
//! outputs, change, fee, signing roots, txid — and demands a typed
//! confirmation phrase at a real terminal. No `--yes`, no environment
//! override, no unattended mode.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::exit;

use bloch_crypto::address::Address;
use bloch_staking_cli::{
    build_deposit_plan, build_exit_plan, build_withdraw_plan, check_deposit_plan,
    check_signed_deposit, check_withdraw_plan, delegate_refusal, deposit_confirmation_phrase,
    deposit_preview, exit_broadcast_refusal, exit_confirmation_phrase, exit_preview,
    format_blch, keypair_from_seed_phrase, parse_blch, parse_node_keystore,
    randao_commitment_from_seed, rpc, script_hash32, sign_deposit_funding, sign_deposit_pop,
    sign_exit, withdraw_confirmation_phrase, withdraw_preview, Coin, DepositPlan, ExitPlan,
    SignedDeposit, SignedExit, WithdrawPlan, DEFAULT_TIP_MILLISAT_PER_GAS,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match (args.first().map(String::as_str), args.get(1).map(String::as_str)) {
        (Some("deposit"), Some("plan")) => deposit_plan_cmd(&args[2..]),
        (Some("deposit"), Some("sign")) => deposit_sign_cmd(&args[2..]),
        (Some("deposit"), Some("broadcast")) => deposit_broadcast_cmd(&args[2..]),
        (Some("exit"), Some("plan")) => exit_plan_cmd(&args[2..]),
        (Some("exit"), Some("sign")) => exit_sign_cmd(&args[2..]),
        (Some("exit"), Some("broadcast")) => {
            eprintln!("bloch-stake: {}", exit_broadcast_refusal());
            exit(1);
        }
        (Some("delegate"), _) => {
            eprintln!("bloch-stake: {}", delegate_refusal());
            exit(1);
        }
        (Some("withdraw"), Some("plan")) => withdraw_plan_cmd(&args[2..]),
        (Some("withdraw"), Some("broadcast")) => withdraw_broadcast_cmd(&args[2..]),
        (Some("--help"), _) | (Some("-h"), _) | (None, _) => help(),
        _ => {
            eprintln!("bloch-stake: unknown command (see --help)");
            exit(2);
        }
    }
}

fn help() {
    println!(
        "bloch-stake — attended Genesis-4 validator staking transactions\n\
         \n\
         Hard rails, none overridable by flag:\n\
           * every consensus quantity (roots, txid, fees, caps) comes from the\n\
             consensus crate — this tool re-derives nothing\n\
           * refuses at build time anything the chain would refuse: an inactive\n\
             format (naming its activation epoch), a bond below {} BLCH or above\n\
             the per-validator cap, sub-dust change, a withdrawal before\n\
             withdrawable_epoch, an exit this key does not control\n\
           * confirmation is a typed phrase at a real terminal — no --yes, no pipe\n\
           * --rehearsal lifts ONLY the activation-epoch gate and marks the\n\
             artifact; broadcast refuses rehearsal artifacts unconditionally\n\
         \n\
         DEPOSIT (funded validator registration, DepositV2):\n\
           bloch-stake deposit plan --rpc <http://host:16400> --funding <bloch1q…>\n\
                --amount <BLCH> --withdrawal <bloch1q…>\n\
                (--keystore-dir <dir> | --public-line <file>)\n\
                [--commission-bps <n>] [--tip <millisat/gas>] [--rehearsal]\n\
                --out deposit-plan.json\n\
             Read-only. --keystore-dir reads the validator pubkey + RANDAO seed\n\
             locally; --public-line takes the `bloch-pos keygen-public` output\n\
             line instead, so the planning box never sees key material.\n\
           bloch-stake deposit sign --plan deposit-plan.json --out signed.json\n\
                [--only funding|pop] [--signed <partially-signed.json>]\n\
                funding key: --seed | --keyfile <file> | --funding-keystore-dir <dir>\n\
                validator key (PoP): --keystore-dir <dir>\n\
             Offline. The coin owner and the validator key may sign on different\n\
             machines: run once with --only funding, carry the file, run again\n\
             with --only pop --signed <file>.\n\
           bloch-stake deposit broadcast --rpc <url> --signed signed.json\n\
         \n\
         EXIT (signed voluntary exit):\n\
           bloch-stake exit plan --rpc <url> --validator <index> [--rehearsal]\n\
                --out exit-plan.json\n\
           bloch-stake exit sign --plan exit-plan.json --keystore-dir <dir>\n\
                --out signed-exit.json\n\
           bloch-stake exit broadcast\n\
             Refuses today: the signed-exit format has no wire carrier yet.\n\
         \n\
         DELEGATE (funded delegation):\n\
           bloch-stake delegate …\n\
             Refuses today with the full reason: the funded delegation wire\n\
             format does not exist yet; this tool does not invent one.\n\
         \n\
         WITHDRAW (unauthenticated crank; payout goes to the credentials fixed\n\
         at deposit — nothing to sign):\n\
           bloch-stake withdraw plan --rpc <url> --validator <index> [--rehearsal]\n\
                --out withdraw-plan.json\n\
           bloch-stake withdraw broadcast --rpc <url> --plan withdraw-plan.json",
        format_blch(bloch_pos_committee::staking::MIN_DEPOSIT_SAT)
    );
}

// ── Small argument helpers (partner-send's, verbatim discipline) ────────────

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn required(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("bloch-stake: {name} is required (no defaults for anything that moves value)");
        exit(2);
    })
}

fn parse_addr(s: &str, what: &str) -> Address {
    Address::parse(s).unwrap_or_else(|e| {
        eprintln!("bloch-stake: {what} `{s}`: {e}");
        exit(2);
    })
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("bloch-stake: {msg}");
    exit(1);
}

fn write_json<T: serde::Serialize>(path: &str, value: &T) {
    let json = serde_json::to_string_pretty(value).expect("artifact serializes");
    std::fs::write(path, json).unwrap_or_else(|e| die(format!("{path}: {e}")));
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> T {
    let bytes = std::fs::read(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| die(format!("{path}: {e}")))
}

// ── The attended gate ───────────────────────────────────────────────────────

/// Show the preview and demand the typed phrase. Aborts unless a human at a
/// real terminal types it exactly (three attempts for typos). Fails closed
/// on every non-interactive path: piped stdin, redirected stdout, EOF,
/// mismatch. Nothing may call a signing key or the RPC broadcast before this
/// returns.
fn confirm_or_abort(preview_text: &str, phrase: &str, action: &str) {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        die(format!(
            "refusing to {action}: stdin/stdout is not a terminal. This tool has no unattended \
             mode — run it interactively."
        ));
    }
    print!("{preview_text}");
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

// ── Key loading ─────────────────────────────────────────────────────────────

/// Load the FUNDING hybrid keypair from exactly one explicitly chosen
/// source. Every prompt is hidden input; no secret is echoed or written.
fn load_funding_key(args: &[String]) -> (Vec<u8>, Vec<u8>) {
    let sources = [
        has_flag(args, "--seed"),
        arg(args, "--keyfile").is_some(),
        arg(args, "--funding-keystore-dir").is_some(),
    ];
    match sources.iter().filter(|s| **s).count() {
        0 => die("choose a funding key source: --seed, --keyfile <file>, or \
                  --funding-keystore-dir <dir>"),
        1 => {}
        _ => die("choose exactly ONE funding key source"),
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
    let dir = arg(args, "--funding-keystore-dir").expect("checked above");
    let (_, pubkey, secret, _) = read_keystore(&dir);
    (pubkey, secret)
}

/// Read a node keystore (`<dir>/validator.key`).
fn read_keystore(dir: &str) -> (u32, Vec<u8>, Vec<u8>, [u8; 32]) {
    let path = PathBuf::from(dir).join("validator.key");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
    parse_node_keystore(&bytes).unwrap_or_else(|e| die(format!("{}: {e}", path.display())))
}

// ── Chain reads shared by the plan/broadcast paths ──────────────────────────

fn client_for(args: &[String]) -> rpc::Client {
    rpc::Client::new(&required(args, "--rpc")).unwrap_or_else(|e| die(e))
}

fn registered_hashes(client: &rpc::Client) -> Vec<(u32, [u8; 32])> {
    let count = rpc::validator_count(client).unwrap_or_else(|e| die(e));
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        match rpc::get_validator(client, i as u32) {
            Ok(v) => out.push((v.index, v.pubkey_hash)),
            Err(e) => die(format!("getvalidator {i}: {e}")),
        }
    }
    out
}

// ═════════════════════════════════════════════════════════════ DEPOSIT ═════

fn deposit_plan_cmd(args: &[String]) {
    let out = required(args, "--out");
    let funding = parse_addr(&required(args, "--funding"), "--funding");
    let withdrawal = parse_addr(&required(args, "--withdrawal"), "--withdrawal");
    let amount_sat = parse_blch(&required(args, "--amount")).unwrap_or_else(|e| die(e)) as u128;
    let commission_bps = match arg(args, "--commission-bps") {
        None => 0u128,
        Some(c) => c.parse().unwrap_or_else(|_| die(format!("--commission-bps `{c}` is not a number"))),
    };
    let tip = match arg(args, "--tip") {
        None => DEFAULT_TIP_MILLISAT_PER_GAS,
        Some(t) => t.parse().unwrap_or_else(|_| die(format!("--tip `{t}` is not a number"))),
    };
    let rehearsal = has_flag(args, "--rehearsal");

    // The validator's PUBLIC material: from a local keystore, or from the
    // `bloch-pos keygen-public` TSV line so the planning box never holds
    // key material.
    let (validator_pubkey, randao_commitment): (Vec<u8>, [u8; 32]) =
        match (arg(args, "--keystore-dir"), arg(args, "--public-line")) {
            (Some(_), Some(_)) => die("choose ONE of --keystore-dir and --public-line"),
            (Some(dir), None) => {
                let (_, pubkey, _, seed) = read_keystore(&dir);
                (pubkey, randao_commitment_from_seed(seed))
            }
            (None, Some(path)) => {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| die(format!("{path}: {e}")));
                parse_public_line(&text).unwrap_or_else(|e| die(format!("{path}: {e}")))
            }
            (None, None) => die(
                "the validator's public material is required: --keystore-dir <dir> (reads \
                 validator.key locally) or --public-line <file> (the `bloch-pos \
                 keygen-public` output line — no key material needed on this machine)",
            ),
        };

    let client = client_for(args);
    let chain = rpc::chain_status(&client).unwrap_or_else(|e| die(e));
    let coins_raw = rpc::get_coins(&client, &script_hash32(&funding)).unwrap_or_else(|e| die(e));
    let coins: Vec<Coin> = coins_raw;
    println!(
        "chain at epoch {}; funding address holds {} coin(s); pricing at base fee {} \
         millisat/gas (tip {})",
        chain.epoch,
        coins.len(),
        chain.next_base_fee_millisat_per_gas,
        tip
    );
    let registered = registered_hashes(&client);
    let plan = build_deposit_plan(
        &funding,
        &withdrawal,
        &validator_pubkey,
        randao_commitment,
        commission_bps,
        amount_sat,
        &coins,
        chain.epoch,
        chain.total_active_stake_sat,
        chain.next_base_fee_millisat_per_gas,
        tip,
        &registered,
        rehearsal,
    )
    .unwrap_or_else(|e| die(e));
    print!("{}", deposit_preview(&plan));
    write_json(&out, &plan);
    println!(
        "plan written to {out}. Nothing was signed and nothing was sent.\n\
         Next: bloch-stake deposit sign --plan {out} --out signed.json \\\n\
               --keystore-dir <validator keystore> \\\n\
               (--seed | --keyfile … | --funding-keystore-dir …)"
    );
}

/// Parse one `bloch-pos keygen-public` line: `index \t pubkey-hex \t
/// commitment-hex` (trailing fields ignored).
fn parse_public_line(text: &str) -> Result<(Vec<u8>, [u8; 32]), String> {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| "file is empty".to_string())?;
    let mut fields = line.split('\t');
    let _index = fields.next().ok_or_else(|| "missing index field".to_string())?;
    let pk_hex = fields.next().ok_or_else(|| "missing pubkey field".to_string())?;
    let c_hex = fields.next().ok_or_else(|| "missing commitment field".to_string())?;
    let pubkey = hex::decode(pk_hex.trim()).map_err(|e| format!("pubkey hex: {e}"))?;
    let c = hex::decode(c_hex.trim()).map_err(|e| format!("commitment hex: {e}"))?;
    let commitment: [u8; 32] =
        c.try_into().map_err(|_| "commitment is not 32 bytes".to_string())?;
    Ok((pubkey, commitment))
}

fn deposit_sign_cmd(args: &[String]) {
    let out = required(args, "--out");
    let mut sd: SignedDeposit = if let Some(signed_path) = arg(args, "--signed") {
        read_json(&signed_path)
    } else {
        let plan_path = required(args, "--plan");
        let plan: DepositPlan = read_json(&plan_path);
        SignedDeposit { plan, funding_pubkey: None, funding_signature: None, proof_of_possession: None }
    };
    check_deposit_plan(&sd.plan).unwrap_or_else(|e| die(e));

    let only = arg(args, "--only");
    let (do_funding, do_pop) = match only.as_deref() {
        None => (true, true),
        Some("funding") => (true, false),
        Some("pop") => (false, true),
        Some(other) => die(format!("--only `{other}`: expected `funding` or `pop`")),
    };

    confirm_or_abort(
        &deposit_preview(&sd.plan),
        &deposit_confirmation_phrase(&sd.plan),
        "sign",
    );

    if do_funding {
        let (public, secret) = load_funding_key(args);
        sign_deposit_funding(&mut sd, &public, &secret).unwrap_or_else(|e| die(e));
        println!("funding witness signed (DS_DEPOSIT_FUND root).");
    }
    if do_pop {
        let dir = arg(args, "--keystore-dir").unwrap_or_else(|| {
            die("--keystore-dir <dir> is required for the proof of possession (the \
                 validator key itself must sign the §7.1 root)")
        });
        let (_, vpk, vsk, _) = read_keystore(&dir);
        sign_deposit_pop(&mut sd, &vpk, &vsk).unwrap_or_else(|e| die(e));
        println!("proof of possession signed (DS_DEPOSIT root).");
    }

    let complete = sd.funding_pubkey.is_some() && sd.proof_of_possession.is_some();
    write_json(&out, &sd);
    if complete {
        // Prove the artifact broadcastable NOW (or say why not) — but do not
        // broadcast. Rehearsal artifacts fail this check by design.
        match check_signed_deposit(&sd) {
            Ok(raw) => println!(
                "signed deposit written to {out} ({} canonical bytes, txid {}). Not broadcast \
                 yet.\nNext: bloch-stake deposit broadcast --rpc <url> --signed {out}",
                raw.len(),
                sd.plan.txid
            ),
            Err(e) if sd.plan.rehearsal => println!(
                "signed REHEARSAL deposit written to {out}. As planned, it can never be \
                 broadcast ({e})"
            ),
            Err(e) => die(format!("the signed artifact fails its own broadcast checks: {e}")),
        }
    } else {
        println!(
            "partially signed deposit written to {out} (funding witness: {}, proof of \
             possession: {}).\nComplete it with: bloch-stake deposit sign --signed {out} \
             --out {out} --only {}",
            if sd.funding_pubkey.is_some() { "present" } else { "MISSING" },
            if sd.proof_of_possession.is_some() { "present" } else { "MISSING" },
            if sd.funding_pubkey.is_some() { "pop" } else { "funding" },
        );
    }
}

fn deposit_broadcast_cmd(args: &[String]) {
    let signed_path = required(args, "--signed");
    let sd: SignedDeposit = read_json(&signed_path);
    let raw = check_signed_deposit(&sd).unwrap_or_else(|e| die(e));

    let client = client_for(args);
    let chain = rpc::chain_status(&client).unwrap_or_else(|e| die(e));
    // The chain moved on since the plan: the flag day must (still) have
    // arrived, the base fee must still match (conservation is exact — a
    // moved base fee means a refused deposit), every input must still be
    // unspent, and the key must not have been registered meanwhile.
    bloch_staking_cli::check_format_active(
        bloch_staking_cli::StakingFormat::DepositV2,
        chain.epoch,
        false,
    )
    .unwrap_or_else(|e| die(e));
    if chain.next_base_fee_millisat_per_gas != sd.plan.base_fee_millisat_per_gas {
        die(format!(
            "the chain's next base fee is now {} millisat/gas but this deposit was priced at \
             {}; conservation is exact, so it would be refused. Re-plan at the current fee.",
            chain.next_base_fee_millisat_per_gas, sd.plan.base_fee_millisat_per_gas
        ));
    }
    for i in &sd.plan.inputs {
        match rpc::is_unspent(&client, &i.txid, i.vout) {
            Ok(true) => {}
            Ok(false) => die(format!(
                "input {}:{} is no longer unspent — something else moved the funding coins. \
                 Re-plan from the current UTXO set.",
                &i.txid[..16],
                i.vout
            )),
            Err(e) => die(format!("checking input {}:{}: {e}", &i.txid[..16], i.vout)),
        }
    }
    let registered = registered_hashes(&client);
    let ph = hex::decode(&sd.plan.validator_pubkey_hash).expect("checked");
    if let Some((idx, _)) = registered.iter().find(|(_, h)| h[..] == ph[..]) {
        die(format!(
            "this validator key registered meanwhile (validator index {idx}); consensus \
             refuses a second deposit of a registered key"
        ));
    }

    confirm_or_abort(
        &deposit_preview(&sd.plan),
        &deposit_confirmation_phrase(&sd.plan),
        "broadcast",
    );
    let (accepted, txid) =
        rpc::send_raw(&client, &hex::encode(&raw)).unwrap_or_else(|e| die(e));
    if !accepted {
        die("the node did not accept the deposit into its mempool");
    }
    println!(
        "accepted into the mempool (txid {txid}).\n\
         The bond leaves the spendable set when the deposit lands in a block; the validator \
         then waits the activation queue ({} epochs minimum, {} activations per epoch). \
         Watch it with getvalidatorcount / getvalidator.",
        bloch_pos_committee::staking::ACTIVATION_DELAY_EPOCHS,
        bloch_pos_committee::staking::MAX_ACTIVATIONS_PER_EPOCH,
    );
}

// ════════════════════════════════════════════════════════════════ EXIT ═════

fn exit_plan_cmd(args: &[String]) {
    let out = required(args, "--out");
    let index: u32 = required(args, "--validator")
        .parse()
        .unwrap_or_else(|_| die("--validator must be a validator index (u32)"));
    let rehearsal = has_flag(args, "--rehearsal");
    let client = client_for(args);
    let chain = rpc::chain_status(&client).unwrap_or_else(|e| die(e));
    let v = rpc::get_validator(&client, index).unwrap_or_else(|e| die(e));
    let plan = build_exit_plan(&v, chain.epoch, rehearsal).unwrap_or_else(|e| die(e));
    print!("{}", exit_preview(&plan));
    write_json(&out, &plan);
    println!(
        "exit plan written to {out}. Nothing was signed.\n\
         Next: bloch-stake exit sign --plan {out} --keystore-dir <dir> --out signed-exit.json\n\
         NOTE: the exit's epoch ({}) is inside its signing root and must match the epoch of \
         inclusion — sign and submit promptly. (Submission is not possible yet; see \
         `bloch-stake exit broadcast`.)",
        plan.epoch
    );
}

fn exit_sign_cmd(args: &[String]) {
    let out = required(args, "--out");
    let plan_path = required(args, "--plan");
    let plan: ExitPlan = read_json(&plan_path);
    let dir = required(args, "--keystore-dir");
    confirm_or_abort(&exit_preview(&plan), &exit_confirmation_phrase(&plan), "sign");
    let (_, pubkey, secret, _) = read_keystore(&dir);
    let signed: SignedExit = sign_exit(&plan, &pubkey, &secret).unwrap_or_else(|e| die(e));
    write_json(&out, &signed);
    println!(
        "signed exit written to {out}.\n{}",
        exit_broadcast_refusal()
    );
}

// ════════════════════════════════════════════════════════════ WITHDRAW ═════

fn withdraw_plan_cmd(args: &[String]) {
    let out = required(args, "--out");
    let index: u32 = required(args, "--validator")
        .parse()
        .unwrap_or_else(|_| die("--validator must be a validator index (u32)"));
    let rehearsal = has_flag(args, "--rehearsal");
    let client = client_for(args);
    let chain = rpc::chain_status(&client).unwrap_or_else(|e| die(e));
    let v = rpc::get_validator(&client, index).unwrap_or_else(|e| die(e));
    let plan = build_withdraw_plan(&v, chain.epoch, rehearsal).unwrap_or_else(|e| die(e));
    print!("{}", withdraw_preview(&plan));
    write_json(&out, &plan);
    println!(
        "withdrawal plan written to {out}. Nothing was sent. This crank carries no \
         signature — the payout can only go to the credentials fixed at deposit time.\n\
         Next: bloch-stake withdraw broadcast --rpc <url> --plan {out}"
    );
}

fn withdraw_broadcast_cmd(args: &[String]) {
    let plan_path = required(args, "--plan");
    let plan: WithdrawPlan = read_json(&plan_path);
    let raw = check_withdraw_plan(&plan).unwrap_or_else(|e| die(e));

    let client = client_for(args);
    let chain = rpc::chain_status(&client).unwrap_or_else(|e| die(e));
    // Re-derive the whole verdict from the chain's current state: the flag
    // day, and the record's committed clocks (a slashing included since the
    // plan extends withdrawable_epoch).
    let v = rpc::get_validator(&client, plan.validator_index).unwrap_or_else(|e| die(e));
    let fresh = build_withdraw_plan(&v, chain.epoch, false).unwrap_or_else(|e| die(e));
    if fresh.txid != plan.txid {
        die("the re-derived crank does not match the plan file — the file was altered");
    }

    confirm_or_abort(
        &withdraw_preview(&fresh),
        &withdraw_confirmation_phrase(&fresh),
        "broadcast",
    );
    let (accepted, txid) =
        rpc::send_raw(&client, &hex::encode(&raw)).unwrap_or_else(|e| die(e));
    if !accepted {
        die("the node did not accept the withdrawal into its mempool");
    }
    println!(
        "accepted into the mempool (txid {txid}).\n\
         The residue pays out as a normal spendable output at `(txid, 0)`, locked to the \
         withdrawal credentials fixed at deposit time. Confirmation is that address's \
         balance."
    );
}
