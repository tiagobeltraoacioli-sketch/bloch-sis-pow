// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline, identity-bound movement of signing watermarks. Never fences a host.
use crate::{
    codec,
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
        .ok_or("expected export, import or set-floor")?;
    let extra = match action {
        "export" => "--out",
        "import" => "--in",
        "set-floor" => "--min-slot",
        _ => return Err("expected export, import or set-floor".into()),
    };
    let mut options = BTreeMap::new();
    let mut rest = args[1..].chunks_exact(2);
    for pair in &mut rest {
        if ![
            "--data-dir",
            "--validator-pubkey-sha3",
            "--genesis-digest",
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
    match action {
        "export" => {
            let out = Path::new(required(extra)?);
            let bytes = slashprot::export_bound(directory, binding).map_err(|e| e.to_string())?;
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
                "Exported identity-bound signing watermarks. This file contains no private key."
            );
        }
        "import" => {
            let mut bytes = Vec::new();
            fs::File::open(required(extra)?)
                .map_err(|e| e.to_string())?
                .take(141)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            let marks =
                slashprot::import_bound(directory, binding, &bytes).map_err(|e| e.to_string())?;
            println!("Imported monotone signing watermarks: {marks:?}");
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
        _ => return Err("unsupported action".into()),
    }
    Ok(())
}
