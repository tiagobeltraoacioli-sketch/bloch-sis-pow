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
//! Root resolution:
//!
//! - `--signer-anchor-dir` / `$BLOCH_SIGNER_ANCHOR_DIR` (explicit): strict.
//!   If it cannot be created or locked the node refuses to boot.
//! - otherwise `$HOME/.bloch-signer` (default): best effort. Hardened systemd
//!   units (`ProtectHome=`, `ProtectSystem=strict` with `ReadWritePaths=`
//!   limited to the data dir) make `$HOME` read-only or invisible, and some
//!   units run without `HOME` at all. In those cases the default anchor is
//!   reported UNAVAILABLE, loudly, and the node boots exactly as it did
//!   before the anchor existed (data-dir record + data-dir lock only).
//!   A held lock (second signer), a retirement marker, a corrupt or foreign
//!   record, or a rolled-back data dir stay fatal in both modes.
//!
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

/// Directory name of the default anchor root under `$HOME`.
pub const DEFAULT_DIR_NAME: &str = ".bloch-signer";

/// Where the anchor root came from; decides how an unusable root is handled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootSource {
    /// `--signer-anchor-dir` / `$BLOCH_SIGNER_ANCHOR_DIR`: failures are fatal.
    Explicit(PathBuf),
    /// `$HOME/.bloch-signer`: a sandboxed or missing home degrades loudly.
    Default(PathBuf),
}

impl RootSource {
    pub fn path(&self) -> &Path {
        match self {
            RootSource::Explicit(p) | RootSource::Default(p) => p,
        }
    }
}

/// The explicitly configured anchor root, if any.
pub fn explicit_root() -> Option<PathBuf> {
    std::env::var_os(ENV_DIR).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// The anchor root this process would use, or `None` when none can be named.
pub fn resolve_root() -> Option<RootSource> {
    if let Some(dir) = explicit_root() {
        return Some(RootSource::Explicit(dir));
    }
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(|home| RootSource::Default(PathBuf::from(home).join(DEFAULT_DIR_NAME)))
}

/// The anchor root path this process would use (explicit or default).
pub fn default_root() -> Option<PathBuf> {
    resolve_root().map(|r| r.path().to_path_buf())
}

/// True for the errors a service sandbox produces on a path outside its
/// writable set (`ProtectHome=`, `ProtectSystem=strict`, a missing or
/// foreign-owned home): read-only file system, permission denied, missing
/// parent. Never true for a held lock (`AddrInUse`) or bad data.
pub fn is_unreachable_root_error(e: &io::Error) -> bool {
    const EROFS: i32 = 30; // identical on Linux and the BSDs/macOS
    matches!(e.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound)
        || e.raw_os_error() == Some(EROFS)
        || e.kind() == io::ErrorKind::ReadOnlyFilesystem
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
        let anchor = Self::lock_only(root, binding)?;
        check_not_retired(&[&anchor.dir])?;
        Ok(anchor)
    }

    /// [`Self::acquire`] for the DEFAULT root (`$HOME/.bloch-signer`):
    /// `Ok(None)` when the root is unreachable from this process (service
    /// sandbox, missing or foreign home; see [`is_unreachable_root_error`]),
    /// so the node can boot without the anchor. Every other failure (a held
    /// key lock, a retirement marker) is returned unchanged.
    pub fn acquire_default(root: &Path, binding: &Binding) -> io::Result<Option<SignerAnchor>> {
        let anchor = match Self::lock_only(root, binding) {
            Ok(anchor) => anchor,
            Err(e) if e.kind() != io::ErrorKind::AddrInUse && is_unreachable_root_error(&e) => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        check_not_retired(&[&anchor.dir])?;
        Ok(Some(anchor))
    }

    fn lock_only(root: &Path, binding: &Binding) -> io::Result<SignerAnchor> {
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
