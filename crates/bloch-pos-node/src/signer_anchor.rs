// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host-level signer anchor: one exclusive lock and one record copy per
//! validator key, OUTSIDE the data dir. Node-local only; nothing here touches
//! consensus or state.
//!
//! `slashprot` keeps the last-signed watermarks inside the data dir, and
//! `store::DirLock` stops two processes sharing ONE data dir. Neither stops:
//!
//! - two data dirs on one host that both hold the same `validator.key`
//!   (a copied directory "as a spare", a half-finished migration) — each
//!   takes its own data-dir lock and both sign;
//! - a data dir restored from an older backup — its record is restored
//!   with it, so it is internally consistent and silently lower than what the
//!   key has already signed.
//!
//! The anchor closes both on one host. `<root>/<pubkey-sha3>-<network>/`
//! holds a `LOCK` (the same flock discipline as the data-dir lock, so a
//! second instance of the key on this host refuses to start, whatever data
//! dir it uses) and `signing_record.bin`, a copy of the data-dir record that
//! every signature write updates before the signature is released. At boot a
//! data-dir record older than the anchor is a rollback and is refused unless
//! the operator passes `--accept-signing-rollback`.
//!
//! `SIGNER-RETIRED` (written by `slashing-protection retire` after a migration
//! export) makes the anchor refuse every later boot of this key on this host.
//!
//! Defaults: root = `$BLOCH_SIGNER_ANCHOR_DIR`, else `$HOME/.bloch-signer`.
//! `BLOCH_NO_SIGNER_ANCHOR=1` (`--no-signer-anchor`) disables it, loudly.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::slashprot::Binding;

pub const ENV_DIR: &str = "BLOCH_SIGNER_ANCHOR_DIR";
pub const ENV_DISABLE: &str = "BLOCH_NO_SIGNER_ANCHOR";
pub const ENV_ACCEPT_ROLLBACK: &str = "BLOCH_ACCEPT_SIGNING_ROLLBACK";
pub const RECORD_FILE: &str = "signing_record.bin";
pub const RETIRED_FILE: &str = "SIGNER-RETIRED";

/// The anchor root this process would use, or `None` when none can be named.
pub fn default_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_DIR).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(|home| PathBuf::from(home).join(".bloch-signer"))
}

/// Per-key directory under `root`.
pub fn key_dir(root: &Path, binding: &Binding) -> PathBuf {
    root.join(format!(
        "{}-{}",
        crate::codec::hex(&binding.validator_pubkey_sha3),
        crate::codec::hex(&binding.genesis_digest)
    ))
}

/// Refuse when either directory carries a retirement marker.
pub fn check_not_retired(dirs: &[&Path]) -> io::Result<()> {
    for dir in dirs {
        let marker = dir.join(RETIRED_FILE);
        match fs::read_to_string(&marker) {
            Ok(note) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "this validator key was RETIRED on this host ({}: {}). Its signing \
                         record was exported for a migration; running it here again is how one \
                         key ends up signing on two hosts. Remove the marker only after \
                         proving the other host is stopped for good.",
                        marker.display(),
                        note.trim()
                    ),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The held anchor. Dropping it releases the key lock.
pub struct SignerAnchor {
    dir: PathBuf,
    _lock: crate::store::DirLock,
}

impl std::fmt::Debug for SignerAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerAnchor").field("dir", &self.dir).finish()
    }
}

impl SignerAnchor {
    /// Create `<root>/<key>` (0700) and take its exclusive lock, or refuse.
    pub fn acquire(root: &Path, binding: &Binding) -> io::Result<SignerAnchor> {
        let dir = key_dir(root, binding);
        create_private_dir(&dir)?;
        let lock = crate::store::DirLock::acquire(&dir).map_err(|e| {
            if e.kind() == io::ErrorKind::AddrInUse {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "SECOND SIGNER REFUSED: validator key {} is already held by another \
                         bloch-pos process on this host (signer lock {}). Two instances of \
                         one key sign the same duties twice, whatever data dirs they use. \
                         Stop the other instance first.",
                        crate::codec::hex8(&binding.validator_pubkey_sha3),
                        dir.join("LOCK").display()
                    ),
                )
            } else {
                e
            }
        })?;
        check_not_retired(&[&dir])?;
        Ok(SignerAnchor { dir, _lock: lock })
    }

    /// For offline tools: take the lock (proving no node of this key runs on
    /// this host) without the retirement check, so a retired anchor can still
    /// be exported or re-marked.
    pub fn acquire_for_tool(root: &Path, binding: &Binding) -> io::Result<SignerAnchor> {
        let dir = key_dir(root, binding);
        create_private_dir(&dir)?;
        let lock = crate::store::DirLock::acquire(&dir).map_err(|e| {
            io::Error::new(e.kind(), format!("signer anchor {}: {e}", dir.display()))
        })?;
        Ok(SignerAnchor { dir, _lock: lock })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn record_path(&self) -> PathBuf {
        self.dir.join(RECORD_FILE)
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Write the retirement marker durably.
pub fn write_retired(dir: &Path, note: &str) -> io::Result<()> {
    crate::store::atomic_private_write(&dir.join(RETIRED_FILE), format!("{note}\n").as_bytes())
}
