// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forward-secure validator keys (`bloch_pos_committee::kes`): generate the
//! key beside `validator.key`, and prepare the one-time registration (wire
//! 0x17) signed by the validator's static key. Offline; broadcasting stays an
//! explicit `sendrawtransaction`.

use crate::l2_deposit_cli::{domain, get, options};
use crate::{codec, kes_key::KesKey, keys::{Keystore, Unlock, AUTO_VALIDATOR_INDEX}};
use bloch_pos_committee::{kes, transition::PosTransaction};
use std::{fs::OpenOptions, io::Write, path::Path};

const HELP: &str = "Forward-secure (KES) validator keys

keygen   --dir DATA_DIR [--depth N]        new validator.kes (2^N periods, default 12: about 11 years
                                           of one-day periods), sealed like validator.key
keygen-next --dir DATA_DIR [--depth N]     validator.kes.next: an early successor the node rotates to
                                           (KesRotate, signed by its current leaf) after a restart;
                                           incident response only, the node renews on its own
inspect  --dir DATA_DIR                    depth, root and the current period
register --dir DATA_DIR --genesis FILE --out FILE [--validator INDEX]
                                           the once-only registration tx (wire 0x17), signed by
                                           validator.key; send its hex with sendrawtransaction.
                                           Consensus refuses it before HF3_KES_EPOCH

The key evolves inside the node: before signing in a new period it rewrites
validator.kes with only that period's seed. Never keep copies of older files.
Renewal is automatic (HF3): about a year before the key expires the node
generates validator.kes.next, rotates to it with a KesRotate signed by the
current leaf, and swaps the files once the chain makes it the key in force.";

pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..], false),
        Some("keygen-next") => keygen(&args[1..], true),
        Some("inspect") => inspect(&args[1..]),
        Some("register") => register(&args[1..]),
        _ => {
            println!("{HELP}");
            Ok(())
        }
    }
}

fn keygen(args: &[String], next: bool) -> Result<(), String> {
    let o = options(args, &["--dir", "--depth"])?;
    let dir = Path::new(get(&o, "--dir")?);
    let depth: u8 = match get(&o, "--depth") {
        Ok(text) => text.parse().map_err(|_| "--depth must be a small integer")?,
        Err(_) => bloch_pos_committee::params::KES_DEFAULT_DEPTH,
    };
    if depth < bloch_pos_committee::params::KES_MIN_REGISTERED_DEPTH || depth > kes::MAX_DEPTH {
        return Err(format!(
            "--depth must be {}..={} (consensus refuses shallower trees)",
            bloch_pos_committee::params::KES_MIN_REGISTERED_DEPTH,
            kes::MAX_DEPTH
        ));
    }
    let target = if next { KesKey::next_path(dir) } else { KesKey::path(dir) };
    if target.exists() {
        return Err(format!("{} already exists; never overwrite KES key material", target.display()));
    }
    if next && !KesKey::path(dir).exists() {
        return Err("--next needs the current validator.kes beside it".into());
    }
    let unlock = Unlock::from_env().map_err(|e| e.to_string())?;
    let index = Keystore::load_with(dir, &unlock).map_err(|e| format!("validator.key: {e}"))?.index;
    let total = 1u64 << depth.min(kes::MAX_DEPTH);
    let started = std::time::Instant::now();
    let key = KesKey::generate(index, depth, |done| {
        if done % 64 == 0 || done == total {
            eprintln!("kes keygen: {done}/{total} leaves ({:.0}s)", started.elapsed().as_secs_f64());
        }
    })
    .map_err(|e| e.to_string())?;
    if next {
        key.save_next(dir, &unlock).map_err(|e| e.to_string())?;
    } else {
        key.save(dir, &unlock).map_err(|e| e.to_string())?;
    }
    println!("{}", inspect_json(&key));
    Ok(())
}

fn inspect_json(key: &KesKey) -> String {
    format!(
        "{{\"index\":{},\"depth\":{},\"periods\":{},\"period\":{},\"root\":\"{}\"}}",
        key.index(),
        key.public().depth,
        key.public().periods(),
        key.period(),
        codec::hex(&key.public().root)
    )
}

fn inspect(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--dir"])?;
    let dir = Path::new(get(&o, "--dir")?);
    let unlock = Unlock::from_env().map_err(|e| e.to_string())?;
    let key = KesKey::load_optional(dir, &unlock).map_err(|e| e.to_string())?.ok_or("no validator.kes in --dir")?;
    println!("{}", inspect_json(&key));
    Ok(())
}

fn register(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--dir", "--genesis", "--out", "--validator"])?;
    let dir = Path::new(get(&o, "--dir")?);
    let unlock = Unlock::from_env().map_err(|e| e.to_string())?;
    let keys = Keystore::load_with(dir, &unlock).map_err(|e| format!("validator.key: {e}"))?;
    let key = KesKey::load_optional(dir, &unlock).map_err(|e| e.to_string())?.ok_or("no validator.kes in --dir")?;
    let validator = match get(&o, "--validator") {
        Ok(text) => text.parse::<u32>().map_err(|_| "--validator must be an index")?,
        Err(_) if keys.index != AUTO_VALIDATOR_INDEX => keys.index,
        Err(_) => return Err("this keystore joined with an automatic index: pass --validator".into()),
    };
    let public = key.public();
    let network = domain(get(&o, "--genesis")?)?;
    let signature = keys.sign(&kes::register_signing_root(&network, validator, &public));
    let tx = PosTransaction::KesRegister { validator, depth: public.depth, root: public.root, signature };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(get(&o, "--out")?).map_err(|e| e.to_string())?;
    writeln!(file, "{}", codec::hex(&tx.canonical_bytes())).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let opens = bloch_pos_committee::params::KES_REGISTRATION_EPOCH;
    println!(
        "{{\"validator\":{validator},\"depth\":{},\"root\":\"{}\",\"network_domain\":\"{}\",\"registration_epoch\":{}}}",
        public.depth,
        codec::hex(&public.root),
        codec::hex(&network),
        if opens == u64::MAX { "null".to_string() } else { opens.to_string() }
    );
    Ok(())
}
