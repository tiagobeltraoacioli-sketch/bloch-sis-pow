//! bloch-pool-keyshard — procedural M-of-N seed recovery utility.
//!
//! Splits the pool operator's 32-byte wallet seed into 3 Shamir shares
//! (any 2 reconstruct) and recombines them. **Recovery only, not
//! threshold signing** — see `keyshard.rs` and README "Custody" for
//! the honest scope of what this does and does not protect.
//!
//! Run SPLIT and RECOVER on an isolated, offline machine: both handle
//! the raw seed.
//!
//! ## M-8 fix (audit finding)
//!
//! This used to take the raw seed and every Shamir share on **argv**
//! (`--seed-hex`, `--share`) and print the recovered seed to **stdout**.
//! On any multi-user or containerised host, `/proc/<pid>/cmdline` and `ps`
//! expose argv to every local user for the process's lifetime — shell
//! history is not the exposure the old doc comment warned about, the
//! process table is. And the seed was never zeroized: it moved through
//! `Vec<u8>` → `[u8; 32]` and back with no `Zeroize`, so it could sit in
//! freed heap memory after the process exits or after a later
//! allocation is served from the same page.
//!
//! Now: the seed / shares are read from **stdin** (default, one value
//! per line for `recover`) or from a **file** whose permissions are
//! checked to be `0600` (owner-only) before it is opened —
//! `--seed-file` / `--share-file`, repeatable for shares. The `--seed-hex`
//! / `--share` argv flags still exist for scripted/CI use, but each use
//! now prints a loud stderr warning naming the exposure. The recovered
//! seed is written to a file descriptor (`--out <path>`, created `0600`)
//! instead of stdout by default; printing to stdout requires the explicit
//! `--allow-stdout` opt-out, which also warns. Every secret buffer
//! (`Vec<u8>` seed bytes, decoded shares, the final `[u8; 32]`) is
//! zeroized before it goes out of scope.

use std::io::{BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use bloch_pool::keyshard::{recover_seed, split_seed, SHARE_COUNT, THRESHOLD};

#[derive(Parser, Debug)]
#[command(
    name = "bloch-pool-keyshard",
    about = "Shamir 2-of-3 RECOVERY sharding for the pool wallet seed. \
             Procedural M-of-N: the seed still exists in one place at \
             recovery/signing time — this is disaster resilience, not \
             threshold signing.",
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Split a 32-byte seed into 3 shares (2-of-3). Reads the seed from
    /// stdin by default; `--seed-file`/`--seed-hex` are alternatives.
    Split {
        /// DEPRECATED (M-8): the seed on argv, visible in `ps`/`/proc` for
        /// the process's lifetime. Prefer stdin or `--seed-file`.
        #[arg(long)]
        seed_hex: Option<String>,
        /// Read the seed (hex) from this file. Refused unless its
        /// permissions are exactly `0600` (owner read/write only).
        #[arg(long)]
        seed_file: Option<PathBuf>,
    },
    /// Recombine 2 or more shares back into the seed. Reads shares from
    /// stdin (one hex value per line) by default; `--share-file`
    /// (repeatable) and `--share` (argv, deprecated) are alternatives.
    Recover {
        /// DEPRECATED (M-8): a share on argv, visible in `ps`/`/proc` for
        /// the process's lifetime. Prefer stdin or `--share-file`.
        #[arg(long = "share")]
        shares: Vec<String>,
        /// Read one share (hex) from this file; repeat for each share.
        /// Refused unless permissions are exactly `0600`.
        #[arg(long = "share-file")]
        share_files: Vec<PathBuf>,
        /// Write the recovered seed (hex) to this file, created `0600`.
        /// One of `--out` or `--allow-stdout` is required.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print the recovered seed to stdout instead of a file. Opt-in
        /// and loud: stdout can be captured by a terminal scrollback,
        /// a logging supervisor, or a `tee`d pipeline far more easily
        /// than a file this process itself created with `0600`.
        #[arg(long)]
        allow_stdout: bool,
    },
}

/// M-8 fix: refuse to read a secret-bearing file unless its permission
/// bits are exactly owner-read/write (`0600`) — group/other must have
/// zero access. Fails closed (a permission-check error is treated the
/// same as "too permissive") rather than silently reading a
/// world-readable share off disk.
fn check_0600(path: &std::path::Path) -> Result<(), String> {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "{} has mode {mode:o}, refusing to read a secret from it \
             (must be exactly 0600 — 'chmod 600 {}')",
            path.display(),
            path.display()
        ));
    }
    Ok(())
}

/// Read and zeroize-friendly-decode one hex value from a `0600`-checked file.
/// The file's raw text is zeroized before returning (it briefly holds the
/// same hex the caller will decode and zeroize again after use).
fn read_hex_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    check_0600(path)?;
    let mut text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let decoded = hex::decode(text.trim())
        .map_err(|e| format!("{} is not valid hex: {e}", path.display()));
    text.zeroize();
    decoded
}

/// Read one line of hex from stdin (trimmed), zeroizing the raw line buffer
/// before returning the decoded bytes.
fn read_hex_line(prompt: &str) -> Result<Vec<u8>, String> {
    eprint!("{prompt} (hex, from stdin): ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("stdin read failed: {e}"))?;
    let decoded = hex::decode(line.trim())
        .map_err(|e| format!("stdin input is not valid hex: {e}"));
    line.zeroize();
    decoded
}

/// Write `hex_text` to `path`, creating it `0600` from the start (no window
/// where the file exists world-readable before the permission is applied).
#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, hex_text: &str) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(hex_text.as_bytes())
        .and_then(|_| f.write_all(b"\n"))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();

    eprintln!("bloch-pool-keyshard: PROCEDURAL M-of-N — key RECOVERY, not \
               threshold signing. The seed is whole in this process's \
               memory; run this offline. On-chain multisig awaits GIP-008.");

    match cli.cmd {
        Cmd::Split { seed_hex, seed_file } => {
            let mut bytes = match (seed_hex, seed_file) {
                (Some(_), Some(_)) => fail("pass only one of --seed-hex / --seed-file"),
                (Some(hex_str), None) => {
                    eprintln!(
                        "WARNING (M-8): --seed-hex places the seed on argv — visible to \
                         every local user via `ps`/`/proc/<pid>/cmdline` for this \
                         process's lifetime. Prefer stdin or --seed-file."
                    );
                    hex::decode(hex_str.trim()).unwrap_or_else(|e| fail(format!("seed is not valid hex: {e}")))
                }
                (None, Some(path)) => read_hex_file(&path).unwrap_or_else(|e| fail(e)),
                (None, None) => read_hex_line("wallet seed").unwrap_or_else(|e| fail(e)),
            };
            let mut seed: [u8; 32] = match bytes.as_slice().try_into() {
                Ok(s) => s,
                Err(_) => {
                    let got = bytes.len();
                    bytes.zeroize();
                    fail(format!("seed must be exactly 32 bytes, got {got}"));
                }
            };
            bytes.zeroize();

            let mut shares = split_seed(&seed);
            // `seed` has done its job; clear it before any further work.
            seed.zeroize();

            println!("{} shares, any {} reconstruct the seed.", SHARE_COUNT, THRESHOLD);
            println!("Give ONE to each custodian; never store two together:");
            for (i, s) in shares.iter().enumerate() {
                println!("share {}: {}", i + 1, hex::encode(s));
            }
            for s in shares.iter_mut() {
                s.zeroize();
            }
        }
        Cmd::Recover { shares, share_files, out, allow_stdout } => {
            if out.is_none() && !allow_stdout {
                fail(
                    "refusing to run: pass --out <path> (recommended) or the explicit \
                     --allow-stdout opt-out (M-8: the recovered seed is not printed to \
                     stdout by default)",
                );
            }
            if !shares.is_empty() {
                eprintln!(
                    "WARNING (M-8): --share places a share on argv — visible to every \
                     local user via `ps`/`/proc/<pid>/cmdline` for this process's \
                     lifetime. Prefer stdin or --share-file."
                );
            }

            let mut decoded: Vec<Vec<u8>> = Vec::new();
            for (i, s) in shares.iter().enumerate() {
                match hex::decode(s.trim()) {
                    Ok(b) => decoded.push(b),
                    Err(e) => fail(format!("share {} is not valid hex: {e}", i + 1)),
                }
            }
            for path in &share_files {
                match read_hex_file(path) {
                    Ok(b) => decoded.push(b),
                    Err(e) => fail(e),
                }
            }
            if decoded.is_empty() {
                // Neither argv nor file shares given: fall back to stdin,
                // prompting for THRESHOLD lines.
                for i in 0..THRESHOLD {
                    match read_hex_line(&format!("share {}/{THRESHOLD}", i + 1)) {
                        Ok(b) => decoded.push(b),
                        Err(e) => fail(e),
                    }
                }
            }

            let result = recover_seed(&decoded);
            for s in decoded.iter_mut() {
                s.zeroize();
            }

            match result {
                Ok(mut seed) => {
                    let hex_seed = hex::encode(seed);
                    seed.zeroize();
                    if let Some(path) = out {
                        match write_secret_file(&path, &hex_seed) {
                            Ok(()) => eprintln!(
                                "seed written to {} (0600) — clear it when you are done",
                                path.display()
                            ),
                            Err(e) => {
                                let mut hex_seed = hex_seed;
                                hex_seed.zeroize();
                                fail(e);
                            }
                        }
                    } else {
                        // --allow-stdout was required to reach here.
                        println!("seed: {hex_seed}");
                        eprintln!(
                            "(printed to stdout by explicit --allow-stdout — clear your \
                             terminal scrollback and shell history)"
                        );
                    }
                    let mut hex_seed = hex_seed;
                    hex_seed.zeroize();
                }
                Err(e) => fail(e),
            }
        }
    }
}
