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
register --dir DATA_DIR --genesis FILE --out FILE [--validator INDEX] [--epoch EPOCH]
                                           the once-only registration tx (wire 0x17), signed by
                                           validator.key; send its hex with sendrawtransaction.
                                           Consensus refuses it before HF3_KES_EPOCH.
                                           --epoch is the epoch of the block that will include it.
                                           From KES_REGISTER_EPOCH_BINDING_EPOCH on it is required
                                           and the transaction is valid in that epoch only (16
                                           minutes): sign for the current epoch, or the next one
                                           near a boundary, send it at once, and sign again with a
                                           new --out if the epoch passes before inclusion

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
    let o = options(args, &["--dir", "--genesis", "--out", "--validator", "--epoch"])?;
    let epoch = match get(&o, "--epoch") {
        Ok(text) => Some(text.parse::<u64>().map_err(|_| "--epoch must be the inclusion epoch")?),
        Err(_) => None,
    };
    let binding = bloch_pos_committee::params::KES_REGISTER_EPOCH_BINDING_EPOCH;
    let form = registration_form(epoch, binding)?;
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
    // The message consensus verifies in a block of the target epoch: the
    // legacy one before the flag day, the epoch-bound one from it on.
    let message = match form {
        RegistrationForm::Legacy => kes::register_signing_root(&network, validator, &public),
        RegistrationForm::EpochBound(epoch) => kes::register_signing_root_at(&network, validator, &public, epoch),
    };
    let signature = keys.sign(&message);
    let tx = PosTransaction::KesRegister { validator, depth: public.depth, root: public.root, signature };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(get(&o, "--out")?).map_err(|e| e.to_string())?;
    writeln!(file, "{}", codec::hex(&tx.canonical_bytes())).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let opens = bloch_pos_committee::params::KES_REGISTRATION_EPOCH;
    println!(
        "{{\"validator\":{validator},\"depth\":{},\"root\":\"{}\",\"network_domain\":\"{}\",\"registration_epoch\":{},\"valid_only_in_epoch\":{}}}",
        public.depth,
        codec::hex(&public.root),
        codec::hex(&network),
        if opens == u64::MAX { "null".to_string() } else { opens.to_string() },
        match form {
            RegistrationForm::Legacy => "null".to_string(),
            RegistrationForm::EpochBound(epoch) => epoch.to_string(),
        }
    );
    Ok(())
}

/// Which registration message `register` signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistrationForm {
    /// `kes::register_signing_root`: valid at any epoch before the flag day.
    Legacy,
    /// `kes::register_signing_root_v2` for this inclusion epoch only.
    EpochBound(u64),
}

/// The form for a registration meant for `epoch`, under a build whose
/// `KES_REGISTER_EPOCH_BINDING_EPOCH` is `binding`. While the flag day is
/// unarmed, or the target epoch is before it, the legacy form (as before this
/// flag existed). With the flag day armed the target epoch must be stated: a
/// signature without it could only be the legacy one, which consensus refuses
/// from the flag day on.
fn registration_form(epoch: Option<u64>, binding: u64) -> Result<RegistrationForm, String> {
    match epoch {
        _ if binding == u64::MAX => Ok(RegistrationForm::Legacy),
        Some(epoch) if epoch >= binding => Ok(RegistrationForm::EpochBound(epoch)),
        Some(_) => Ok(RegistrationForm::Legacy),
        None => Err(format!(
            "pass --epoch (the epoch of the block that will include the registration): from epoch \
             {binding} on the signature binds it and is valid in that epoch only"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registration_form_follows_the_flag_day_and_the_target_epoch() {
        // Unarmed (as shipped): the legacy form, with or without --epoch.
        assert_eq!(bloch_pos_committee::params::KES_REGISTER_EPOCH_BINDING_EPOCH, u64::MAX);
        assert_eq!(registration_form(None, u64::MAX), Ok(RegistrationForm::Legacy));
        assert_eq!(registration_form(Some(7_360), u64::MAX), Ok(RegistrationForm::Legacy));
        assert_eq!(registration_form(Some(u64::MAX), u64::MAX), Ok(RegistrationForm::Legacy));
        // Armed: --epoch is required and selects the form of that epoch.
        assert!(registration_form(None, 7_360).is_err());
        assert_eq!(registration_form(Some(7_359), 7_360), Ok(RegistrationForm::Legacy));
        assert_eq!(registration_form(Some(7_360), 7_360), Ok(RegistrationForm::EpochBound(7_360)));
        assert_eq!(registration_form(Some(9_000), 7_360), Ok(RegistrationForm::EpochBound(9_000)));
    }

    #[test]
    fn the_epoch_bound_form_signs_the_message_consensus_verifies() {
        // While the flag day is unarmed the shared selector is the legacy
        // message at every epoch, so the two arms of `register` agree.
        let public = kes::KesPublic::new(12, [0x22; 32], 0);
        for epoch in [0, 7_360, u64::MAX] {
            assert_eq!(
                kes::register_signing_root_at(&[0x11; 32], 7, &public, epoch),
                kes::register_signing_root(&[0x11; 32], 7, &public)
            );
        }
    }
}
