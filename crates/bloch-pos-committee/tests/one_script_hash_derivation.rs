// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The guard.** A Genesis-4 `script_hash` may be built in exactly two places,
//! and this test fails the moment a third appears.
//!
//! # Why a source scan and not a type
//!
//! The obvious fix — a newtype that only the canonical module can construct —
//! does not hold here. The dangerous shape is four lines of ordinary Rust
//! (`let mut out = [0u8; 32]; out[..20].copy_from_slice(&h);`) written against
//! a plain `[u8; 32]` that crosses the RPC boundary as hex and comes back as
//! hex. It costs nothing to write and it compiles anywhere, in any crate, in
//! any language in this repository. Three tools wrote it independently, none of
//! them wrong-looking, because the address form is the one a human can read.
//!
//! So the guard is a scan with an explicit allowlist, in the spirit of
//! `published_checksums.rs`. It cannot prove a fourth derivation is impossible.
//! It makes writing one a **build failure with an explanation attached**, which
//! is the property that was actually missing: every one of the six sites this
//! replaced was written by someone who did not know the other five existed.
//!
//! # What trips it
//!
//! Constructing the 20-bytes-then-zeroes shape, in Rust, TypeScript or Python,
//! outside the allowlist below. That shape is legitimate in exactly one
//! situation — transcribing a Genesis-3 `carryover.tsv` row at mainnet genesis
//! — and every other use of it is the silent zero-balance bug.
//!
//! # If this test fails
//!
//! Do not add your file to the allowlist to make it pass. Ask which hash you
//! actually want:
//!
//! * You have a **public key** and want the hash its coins live under →
//!   `bloch_pos_committee::script_hash::from_pubkey`. This is almost always it.
//! * You have an **address** → you are holding the wrong identifier. Genesis-4
//!   names payees by `script_hash`; ask for that instead. There is deliberately
//!   no conversion.
//! * You are **ingesting the carryover file** → you are `genesis.rs`, you are
//!   already on the list, and there will not be a second one of you.

use std::path::{Path, PathBuf};

/// Files permitted to build the carried (20 + 12 zero-byte) shape, each with
/// the reason it is allowed to.
const ALLOWED: &[(&str, &str)] = &[
    (
        "crates/bloch-pos-committee/src/script_hash.rs",
        "THE canonical module: `carried_from_g3_hash160` is the one implementation",
    ),
    (
        "crates/bloch-pos-node/src/genesis.rs",
        "the Genesis-3 carryover ingest — transcribes a snapshot row, does not derive from a key",
    ),
    (
        "crates/bloch-pos-node/src/main.rs",
        "`genesis-mainnet` places the founder allocation at a real Genesis-3 hash160 \
         (FOUNDER_WITHDRAWAL_H160), under the same ingest rule",
    ),
    (
        "crates/bloch-pos-committee/tests/one_script_hash_derivation.rs",
        "this guard, which has to spell the pattern in order to look for it",
    ),
];

/// Source markers for "someone is building the carried shape here".
///
/// Deliberately narrow: each one is the *construction* of the shape, not a
/// mention of it. Prose about the rule is fine and there is a lot of it.
const RUST_MARKERS: &[&str] = &[
    "[..20].copy_from_slice(",
    "[..G3_ADDRESS_BYTES].copy_from_slice(",
    "[0..20].copy_from_slice(",
];
const SCRIPT_MARKERS: &[&str] = &[
    "\"00\".repeat(12)",
    "'00'.repeat(12)",
    "b\"\\x00\" * 12",
    "bytes(12)",
];

fn repo_root() -> PathBuf {
    // tests/ -> bloch-pos-committee/ -> crates/ -> repo
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the committee crate sits two levels below the repo root")
        .to_path_buf()
}

/// Directories with no bearing on how a live `script_hash` is derived.
fn skip_dir(name: &str) -> bool {
    matches!(
        name,
        "target"
            | "node_modules"
            | ".git"
            | "legacy"        // Genesis-3, closed; its 20-byte world is its own
            | "sdk"           // Genesis-3 clients; they return 20-byte script_pubkeys
            | "docs"
            | "audit"
            | "spikes"
            | "fuzz"
            | "bench"
            | "os"
            | "apps"
            | "gips"
            | ".claude"
    )
}

fn is_source(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("rs") | Some("ts") | Some("py")
    )
}

/// Strip whole-line comments so that *describing* the rule never trips it.
/// Trailing comments are left in place on purpose — a marker sitting after code
/// on the same line is worth a second look either way.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().filter_map(|(i, l)| {
        let t = l.trim_start();
        if t.starts_with("//") || t.starts_with("#") || t.starts_with("*") {
            None
        } else {
            Some((i + 1, l))
        }
    })
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !skip_dir(&name) && !name.starts_with('.') {
                walk(&p, out);
            }
        } else if is_source(&p) {
            out.push(p);
        }
    }
}

#[test]
fn the_carried_script_hash_shape_is_built_in_exactly_the_allowed_places() {
    let root = repo_root();
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 50,
        "the scan found only {} source files under {} — it is not looking where it thinks it is, \
         and a guard that scans nothing passes for the wrong reason",
        files.len(),
        root.display()
    );

    let mut offenders: Vec<String> = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.iter().any(|(a, _)| *a == rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        let markers: &[&str] = if f.extension().and_then(|e| e.to_str()) == Some("rs") {
            RUST_MARKERS
        } else {
            SCRIPT_MARKERS
        };
        for (n, line) in code_lines(&text) {
            for m in markers {
                if line.contains(m) {
                    offenders.push(format!("  {rel}:{n}  contains `{m}`\n      {}", line.trim()));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nA SECOND `script_hash` DERIVATION HAS APPEARED.\n\n\
         These sites build the carried shape — 20 bytes then twelve zeroes — outside the two \n\
         places allowed to. If the 20 bytes came from a public key or an address, this is the \n\
         silent zero-balance bug: `SHA3-256(pubkey)[..20] ‖ 0x00*12` is a DIFFERENT eUTXO-set \n\
         key from `SHA3-256(pubkey)`, consensus accepts both, and the partner you funded sees \n\
         nothing.\n\n{}\n\n\
         Use `bloch_pos_committee::script_hash::from_pubkey`. Read that module's docs before \n\
         adding anything to ALLOWED in {}.\n",
        offenders.join("\n"),
        file!(),
    );
}

/// The allowlist must not rot into a list of paths that no longer exist — an
/// entry for a deleted file silently widens nothing but hides that the guard's
/// picture of the tree is stale.
#[test]
fn every_allowlist_entry_names_a_file_that_exists() {
    let root = repo_root();
    for (path, why) in ALLOWED {
        assert!(
            root.join(path).exists(),
            "allowlist entry `{path}` ({why}) does not exist under {}",
            root.display()
        );
    }
}

/// The canonical module is the only thing that may be the answer, so it has to
/// still be there and still say what the rest of the tree relies on.
#[test]
fn the_canonical_derivation_is_where_everything_points() {
    let src = std::fs::read_to_string(
        repo_root().join("crates/bloch-pos-committee/src/script_hash.rs"),
    )
    .expect("the canonical script_hash module must exist");
    assert!(
        src.contains("pub fn from_pubkey"),
        "`from_pubkey` is the derivation every tool in this repository is pointed at"
    );
    assert!(
        src.contains("pub fn carried_from_g3_hash160"),
        "the carryover ingest's transcription must stay named and documented, not inlined"
    );
}
