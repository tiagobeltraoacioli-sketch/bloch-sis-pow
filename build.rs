// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stamps the git commit into the binary.
//
// Why this exists: on 2026-08-11 a fleet survey found three boxes running three
// different binaries, all reporting `bloch 0.3.0-genesis2`, with no way to tell
// what any of them was built from. One had no source tree at all. Identifying
// what is running had to be done by md5 and guesswork.
//
// A version string without a commit is not a version string. This makes the
// question answerable with `bloch --version`, forever.

use std::process::Command;

fn main() {
    let pkg = env!("CARGO_PKG_VERSION");

    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    };

    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());

    // A dirty build is the thing that made the fleet unidentifiable in the
    // first place, so it is marked loudly rather than hidden.
    let dirty = match git(&["status", "--porcelain"]) {
        Some(s) if !s.is_empty() => "+dirty",
        Some(_) => "",
        None => "+nogit",
    };

    println!("cargo:rustc-env=BLOCH_BUILD_VERSION={pkg} ({commit}{dirty})");

    // Rebuild when HEAD moves, so the stamp cannot go stale in an incremental
    // build — a stale stamp is worse than no stamp: it is a confident lie.
    for p in [".git/HEAD", ".git/index"] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}
