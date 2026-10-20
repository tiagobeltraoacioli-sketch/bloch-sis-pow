// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline, identity-bound movement of signing watermarks and RANDAO intents. Never fences a host.
use crate::{
    codec, signer_anchor,
    slashprot::{self, Binding},
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
};

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("expected export, import, set-floor or retire")?;
    let extra = match action {
        "export" => "--out",
        "import" => "--in",
        "set-floor" => "--min-slot",
        "retire" => "--note",
        _ => return Err("expected export, import, set-floor or retire".into()),
    };
    let mut options = BTreeMap::new();
    let mut rest = args[1..].chunks_exact(2);
    for pair in &mut rest {
        if ![
            "--data-dir",
            "--validator-pubkey-sha3",
            "--genesis-digest",
            "--signer-anchor-dir",
            extra,
        ]
        .contains(&pair[0].as_str())
        {
            return Err(format!("unknown option: {}", pair[0]));
        }
        if options.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(format!("duplicate option: {}", pair[0]));
        }
    }
    if !rest.remainder().is_empty() {
        return Err("every option requires a value".into());
    }
    let required = |name| {
        options
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is required"))
    };
    let hash = |name| -> Result<[u8; 32], String> {
        codec::unhex(required(name)?)
            .map_err(|e| format!("{name}: {e}"))?
            .try_into()
            .map_err(|_| format!("{name} must contain exactly 32 bytes"))
    };
    let directory = Path::new(required("--data-dir")?);
    let binding = Binding {
        validator_pubkey_sha3: hash("--validator-pubkey-sha3")?,
        genesis_digest: hash("--genesis-digest")?,
    };
    // The host-level anchor (signer_anchor.rs), when this host has one for the
    // key: export merges it (it can be ahead of a restored data dir), and
    // retire marks it. Taking its lock also proves no node of this key runs.
    let anchor_root = options
        .get("--signer-anchor-dir")
        .map(|value| signer_anchor::RootSource::Explicit(std::path::PathBuf::from(*value)))
        .or_else(signer_anchor::resolve_root);
    let held_anchor = match &anchor_root {
        Some(source)
            if signer_anchor::key_dir(source.path(), &binding).is_dir() || action == "retire" =>
        {
            match signer_anchor::SignerAnchor::acquire_for_tool(source.path(), &binding) {
                Ok(anchor) => Some(anchor),
                // A default root this user cannot write (and that holds no
                // anchor for the key) is not an error for `retire`: the data
                // dir marker is still written below.
                Err(e)
                    if matches!(source, signer_anchor::RootSource::Default(_))
                        && e.kind() != std::io::ErrorKind::AddrInUse
                        && signer_anchor::is_unreachable_root_error(&e)
                        && !signer_anchor::key_dir(source.path(), &binding).is_dir() =>
                {
                    eprintln!(
                        "Signer anchor {} is not writable here; skipping it. Pass \
                         --signer-anchor-dir if this host's nodes use another anchor root.",
                        source.path().display()
                    );
                    None
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        _ => None,
    };
    match action {
        "export" => {
            let out = Path::new(required(extra)?);
            let mut bytes = slashprot::export_bound(directory, binding).map_err(|e| e.to_string())?;
            if let Some(anchor) = &held_anchor {
                match fs::read(anchor.record_path()) {
                    Ok(other) => {
                        bytes = slashprot::merge_records(binding, &bytes, &other)
                            .map_err(|e| format!("signer anchor {}: {e}", anchor.dir().display()))?;
                        println!("Merged the host signer anchor {} into the export.", anchor.dir().display());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(out)
                .map_err(|e| format!("cannot create export: {e}"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| format!("cannot persist export: {e}"))?;
            let parent = out
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            crate::store::fsync_dir(parent).map_err(|e| e.to_string())?;
            println!(
                "Exported identity-bound signing protection (including any RANDAO intent). This file contains no private key."
            );
        }
        "import" => {
            let mut bytes = Vec::new();
            fs::File::open(required(extra)?)
                .map_err(|e| e.to_string())?
                .take(slashprot::MAX_RECORD_LEN.saturating_add(1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            let marks =
                slashprot::import_bound(directory, binding, &bytes).map_err(|e| e.to_string())?;
            println!("Imported monotone signing protection; proposal/attestation watermarks: {marks:?}");
            println!("The previous host must remain fenced; importing a file cannot stop another signer.");
        }
        "set-floor" => {
            let slot = required(extra)?
                .parse::<u64>()
                .map_err(|_| "--min-slot must be an unsigned integer")?;
            let marks =
                slashprot::initialize_floor(directory, binding, slot).map_err(|e| e.to_string())?;
            println!("Persisted signing floor: {marks:?}");
            println!("Attestations may remain blocked until their source epoch reaches the conservative floor. This does not fence a previous host or replace its signing history.");
        }
        "retire" => {
            let note = required(extra)?;
            if note.contains('\n') {
                return Err("--note must be one line".into());
            }
            crate::keys::ensure_mutation_ownership(directory).map_err(|e| e.to_string())?;
            let _lock = crate::store::DirLock::acquire(directory).map_err(|e| e.to_string())?;
            signer_anchor::write_retired(directory, note).map_err(|e| e.to_string())?;
            if let Some(anchor) = &held_anchor {
                signer_anchor::write_retired(anchor.dir(), note).map_err(|e| e.to_string())?;
            }
            println!(
                "Retired this validator key on this host (data dir{}). A node started here \
                 with this key now refuses to boot. Export the record BEFORE retiring.",
                if held_anchor.is_some() { " and signer anchor" } else { "" }
            );
        }
        _ => return Err("unsupported action".into()),
    }
    Ok(())
}
