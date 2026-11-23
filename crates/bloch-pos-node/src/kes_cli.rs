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
         [--rpc HOST:PORT] [--mode register|rescue|correct]
                                           the once-only registration tx (wire 0x17), signed by
                                           validator.key; send its hex with sendrawtransaction.
                                           Consensus refuses it before HF3_KES_EPOCH.
                                           --epoch is the epoch of the block that will include it.
                                           From KES_REGISTER_EPOCH_BINDING_EPOCH on it is required
                                           and the transaction is valid in that epoch only (16
                                           minutes): sign for the current epoch, or the next one
                                           near a boundary, send it at once, and sign again with a
                                           new --out if the epoch passes before inclusion.
                                           --rpc asks a synced node (getkes) what is registered for
                                           the validator first, and REFUSES to sign when a tree is
                                           already registered: registration is once-only, and a
                                           registered tree this node does not hold leaves the
                                           validator unable to sign from the KES bind on. Always
                                           pass it. --mode rescue signs the replacement of an
                                           EXPIRED tree (after the bind); --mode correct signs the
                                           one pre-bind correction of a wrong tree (needs --rpc and
                                           --epoch; consensus refuses it until
                                           KES_PREBIND_CORRECTION_ACTIVATION_EPOCH is armed)

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
    let o = options(args, &["--dir", "--genesis", "--out", "--validator", "--epoch", "--rpc", "--mode"])?;
    let mode = match get(&o, "--mode") {
        Ok("register") | Err(_) => RegisterMode::First,
        Ok("rescue") => RegisterMode::Rescue,
        Ok("correct") => RegisterMode::Correct,
        Ok(_) => return Err("--mode must be register, rescue or correct".into()),
    };
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
    // Audit L1C-61: what the chain already has for this validator, before
    // anything is signed.
    let chain = match get(&o, "--rpc") {
        Ok(addr) => registered_on_chain(&crate::equivocation_watch::rpc_query(addr, "getkes")?, validator)?,
        Err(_) => ChainRegistration::NotChecked,
    };
    if let Some(warning) = registration_guard(&chain, &public, mode)? {
        eprintln!("WARNING: {warning}");
    }
    let network = domain(get(&o, "--genesis")?)?;
    // The message consensus verifies in a block of the target epoch: the
    // legacy one before the flag day, the epoch-bound one from it on; for a
    // correction, its own message, bound to the epoch and the replaced tree.
    let message = match (mode, &chain) {
        (RegisterMode::Correct, ChainRegistration::Registered { depth, root }) => {
            let epoch = epoch.ok_or("--mode correct needs --epoch (the epoch of the block that will include it)")?;
            kes::correct_signing_root(&network, validator, epoch, &kes::KesPublic::new(*depth, *root, 0), &public)
        }
        (RegisterMode::Correct, _) => return Err("--mode correct needs --rpc: the correction is signed against the registered tree".into()),
        _ => match form {
            RegistrationForm::Legacy => kes::register_signing_root(&network, validator, &public),
            RegistrationForm::EpochBound(epoch) => kes::register_signing_root_at(&network, validator, &public, epoch),
        },
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

/// What `register` is asked to produce (audit L1C-61).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegisterMode {
    /// The validator's first, once-only registration.
    First,
    /// The static-key replacement of an expired tree (after the bind).
    Rescue,
    /// The one pre-bind correction of a registered tree
    /// (`params::KES_PREBIND_CORRECTION_ACTIVATION_EPOCH`).
    Correct,
}

/// What a node's `getkes` says is registered for the validator.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ChainRegistration {
    /// No `--rpc`: the chain was not asked.
    NotChecked,
    /// The node knows no KES tree for this validator.
    Unregistered,
    /// The tree in force for this validator.
    Registered { depth: u8, root: [u8; 32] },
}

/// The validator's entry in a `getkes` reply.
fn registered_on_chain(getkes: &crate::rpc::Json, validator: u32) -> Result<ChainRegistration, String> {
    let crate::rpc::Json::Arr(registered) = getkes.get("registered").ok_or("getkes: no `registered` list in the reply")? else {
        return Err("getkes: `registered` is not a list".into());
    };
    for entry in registered {
        if entry.get("validator").and_then(crate::rpc::Json::as_u64) != Some(u64::from(validator)) {
            continue;
        }
        let depth = entry
            .get("depth")
            .and_then(crate::rpc::Json::as_u64)
            .and_then(|depth| u8::try_from(depth).ok())
            .ok_or("getkes: registered entry without a depth")?;
        let root = entry
            .get("root")
            .and_then(crate::rpc::Json::as_str)
            .and_then(|hex| codec::unhex(hex).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or("getkes: registered entry without a 32-byte root")?;
        return Ok(ChainRegistration::Registered { depth, root });
    }
    Ok(ChainRegistration::Unregistered)
}

/// May `register` sign for the local tree `public`, given what the chain
/// has? `Ok(Some(_))` is a warning to print; `Err` refuses before anything
/// is signed or written.
///
/// A first registration is refused whenever a tree is already registered:
/// with another root, signing would only produce a transaction consensus
/// refuses while hiding that this node does not hold the registered key
/// (from the KES bind on it could not sign); with the same root there is
/// nothing left to do.
fn registration_guard(chain: &ChainRegistration, public: &kes::KesPublic, mode: RegisterMode) -> Result<Option<String>, String> {
    match (chain, mode) {
        (ChainRegistration::NotChecked, RegisterMode::Correct) => {
            Err("--mode correct needs --rpc: the correction is signed against the registered tree".into())
        }
        (ChainRegistration::NotChecked, _) => Ok(Some(
            "the chain was NOT checked (no --rpc). Registration is once-only: if another KES tree is already \
             registered for this validator, this node cannot sign from the KES bind on. Pass --rpc HOST:PORT of a \
             synced node."
                .into(),
        )),
        (ChainRegistration::Unregistered, RegisterMode::First) => Ok(None),
        (ChainRegistration::Unregistered, _) => {
            Err("no KES tree is registered for this validator: use the plain registration (no --mode)".into())
        }
        (ChainRegistration::Registered { depth, root }, _) if *root == public.root && *depth == public.depth => Err(format!(
            "this validator already has this very tree registered (root {}): nothing to sign",
            codec::hex(root)
        )),
        (ChainRegistration::Registered { root, .. }, RegisterMode::First) => Err(format!(
            "REFUSED: a DIFFERENT KES tree is already registered for this validator (chain root {}, this node's \
             validator.kes root {}). Registration is once-only and consensus would refuse this one; from the KES \
             bind on only the registered tree can sign. Find and restore the validator.kes that was registered. \
             (An expired registered tree is replaced with --mode rescue; a wrong one, before the bind and once \
             the correction gate is armed, with --mode correct.)",
            codec::hex(root),
            codec::hex(&public.root)
        )),
        (ChainRegistration::Registered { root, .. }, RegisterMode::Rescue) => Ok(Some(format!(
            "replacing the registered tree (root {}): consensus admits this only after the KES bind, once that \
             tree has EXPIRED with no rotation pending",
            codec::hex(root)
        ))),
        (ChainRegistration::Registered { root, .. }, RegisterMode::Correct) => Ok(Some(format!(
            "correcting the registered tree (root {}): consensus admits this once per validator, only before the \
             KES bind is decided, only in the epoch given by --epoch, and only once \
             KES_PREBIND_CORRECTION_ACTIVATION_EPOCH is armed (unarmed in this build: {})",
            codec::hex(root),
            bloch_pos_committee::params::KES_PREBIND_CORRECTION_ACTIVATION_EPOCH == u64::MAX
        ))),
    }
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

    /// Audit L1C-61: `register` refuses to sign a first registration when
    /// the chain already has a tree for the validator.
    #[test]
    fn register_refuses_when_another_tree_is_already_registered() {
        let local = kes::KesPublic::new(12, [0x22; 32], 0);
        let other = ChainRegistration::Registered { depth: 12, root: [0xBB; 32] };
        let same = ChainRegistration::Registered { depth: 12, root: [0x22; 32] };
        // Nothing registered: the plain registration, silently.
        assert_eq!(registration_guard(&ChainRegistration::Unregistered, &local, RegisterMode::First), Ok(None));
        // A different tree: refused, naming both roots.
        let refused = registration_guard(&other, &local, RegisterMode::First).unwrap_err();
        assert!(refused.starts_with("REFUSED: a DIFFERENT KES tree is already registered"), "{refused}");
        assert!(refused.contains(&codec::hex(&[0xBB; 32])) && refused.contains(&codec::hex(&[0x22; 32])), "{refused}");
        // The same tree: nothing to do, in every mode.
        for mode in [RegisterMode::First, RegisterMode::Rescue, RegisterMode::Correct] {
            assert!(registration_guard(&same, &local, mode).unwrap_err().contains("already has this very tree"));
        }
        // The chain not asked: as before this check existed, with a warning.
        let unchecked = registration_guard(&ChainRegistration::NotChecked, &local, RegisterMode::First);
        assert!(unchecked.unwrap().unwrap().contains("NOT checked"));
        assert!(registration_guard(&ChainRegistration::NotChecked, &local, RegisterMode::Rescue).unwrap().is_some());
        assert!(registration_guard(&ChainRegistration::NotChecked, &local, RegisterMode::Correct).is_err());
        // The explicit replacement modes need a registered tree.
        for mode in [RegisterMode::Rescue, RegisterMode::Correct] {
            assert!(registration_guard(&ChainRegistration::Unregistered, &local, mode).is_err());
            assert!(registration_guard(&other, &local, mode).unwrap().is_some(), "{mode:?} warns and proceeds");
        }
    }

    #[test]
    fn the_registered_tree_is_read_from_a_getkes_reply() {
        let reply = |registered: &str| {
            crate::rpc::parse_json(&format!("{{\"epoch\":8800,\"registered\":[{registered}]}}")).unwrap()
        };
        let root = codec::hex(&[0xBB; 32]);
        let entry = format!("{{\"validator\":13,\"depth\":12,\"periods\":4096,\"root\":\"{root}\",\"start_period\":0}}");
        let other = format!("{{\"validator\":7,\"depth\":8,\"root\":\"{}\"}}", codec::hex(&[0x07; 32]));
        assert_eq!(
            registered_on_chain(&reply(&format!("{other},{entry}")), 13),
            Ok(ChainRegistration::Registered { depth: 12, root: [0xBB; 32] })
        );
        assert_eq!(registered_on_chain(&reply(&other), 13), Ok(ChainRegistration::Unregistered));
        assert_eq!(registered_on_chain(&reply(""), 13), Ok(ChainRegistration::Unregistered));
        // A reply that cannot be read is an error, never "unregistered".
        assert!(registered_on_chain(&crate::rpc::parse_json("{\"epoch\":1}").unwrap(), 13).is_err());
        assert!(registered_on_chain(&reply("{\"validator\":13,\"depth\":12,\"root\":\"abcd\"}"), 13).is_err());
        assert!(registered_on_chain(&reply("{\"validator\":13,\"root\":\"00\"}"), 13).is_err());
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
