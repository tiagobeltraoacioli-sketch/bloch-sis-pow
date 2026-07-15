//! Bloch-SIS Protocol — Shared utility functions.
//!
//! Small helpers that don't fit cleanly into any subsystem module.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Atomically write `contents` to `path`.
///
/// Sprint T.5 — Audit L-4 fix.
///
/// `std::fs::write()` is NOT atomic — it opens the file, writes some bytes,
/// closes. A crash/power loss midway leaves a truncated or partial file on
/// disk. For wallet keystores this is catastrophic: the old working file
/// gets mangled and the user loses access to their keys with no way back.
///
/// This helper implements the canonical safe-write dance:
///   1. Write the full contents to a sibling temp file (`path.tmp.NNNN`).
///   2. fsync the temp file so bytes reach disk.
///   3. Atomically rename temp → target. On POSIX, rename(2) is atomic for
///      paths on the same filesystem, so either the old file or the new file
///      is observable, never a partial blend.
///   4. Best-effort fsync the parent directory so the rename itself is
///      durable (otherwise a crash right after rename might lose the new
///      name even though the temp bytes are safe).
///
/// # Portability
///
/// - On Unix, rename(2) is guaranteed atomic within one filesystem.
/// - On Windows, `std::fs::rename` maps to `MoveFileExW` with
///   `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` since Rust 1.74,
///   which provides the equivalent guarantee.
/// - If `path` is on a different filesystem from the directory's temp file,
///   the rename may fall back to copy+unlink, which is NOT atomic. In
///   practice wallet paths are single-filesystem, so this edge case does
///   not arise.
///
/// # Errors
///
/// Returns any I/O error from the sequence. On failure, the temp file may
/// remain on disk; callers typically do not need to clean up since a second
/// save attempt overwrites it.
///
/// # Example
///
/// ```ignore
/// use bloch::util::atomic_write;
/// atomic_write(Path::new("/path/to/wallet.json"), b"...json bytes...")?;
/// ```
pub fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    // Temp filename: sibling of target. Using PID + time as uniqueness source
    // avoids collisions if multiple Bloch-SIS Protocol processes touch the same path.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no file name")
    })?;

    let pid = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let tmp_name = format!("{}.tmp.{}.{}", file_name.to_string_lossy(), pid, nonce);
    let tmp_path = parent.join(&tmp_name);

    // Write + fsync the temp file.
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true)
            .create_new(true);  // explicit: fail if collision
        // SECURITY (audit M): every current caller writes wallet keystore
        // material through this helper. Create the file with owner-only
        // permissions (0600) BEFORE the first secret byte is written, so
        // there is never a window where the keystore is group/world-readable
        // under a permissive umask. rename(2) preserves the temp file's mode,
        // so the final file ends up 0600 as well (including when it replaces
        // an older, more permissive keystore).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        f.write_all(contents)?;
        f.sync_all()?; // fsync the data before rename
    }

    // Atomic rename into place.
    if let Err(e) = fs::rename(&tmp_path, path) {
        // Best-effort cleanup of orphan temp file on failure.
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    // Best-effort: fsync the parent directory so the rename itself is durable.
    // Some filesystems (ext4 with default options, APFS) order rename-with-
    // previous-fsync conservatively already, so failure here is not fatal.
    #[cfg(unix)]
    {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn atomic_write_creates_new_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        atomic_write(&path, b"hello world").unwrap();

        let read = fs::read(&path).unwrap();
        assert_eq!(read, b"hello world");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.txt");

        fs::write(&path, b"old contents").unwrap();
        atomic_write(&path, b"new contents").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new contents");
    }

    /// Audit REGRESSION: keystore files must be created owner-only (0600).
    /// Before the fix the temp file inherited the process umask (typically
    /// 0644), leaving the encrypted keystore world-readable.
    #[cfg(unix)]
    #[test]
    fn atomic_write_creates_owner_only_keystore_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wallet.json");
        atomic_write(&path, b"{\"cipher\":\"secret keystore bytes\"}").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600,
            "keystore file must be 0600, got {:o}", mode & 0o777);
    }

    /// Overwriting an older, more permissive keystore must also end at 0600
    /// (rename replaces the target with the 0600 temp file).
    #[cfg(unix)]
    #[test]
    fn atomic_write_overwrite_tightens_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wallet.json");

        fs::write(&path, b"old keystore").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write(&path, b"new keystore").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600,
            "replaced keystore must be 0600, got {:o}", mode & 0o777);
    }

    #[test]
    fn atomic_write_leaves_no_temp_files_on_success() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wallet.json");
        atomic_write(&path, b"{}").unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();

        // Only wallet.json should remain — no .tmp.* siblings.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "wallet.json");
    }
}
