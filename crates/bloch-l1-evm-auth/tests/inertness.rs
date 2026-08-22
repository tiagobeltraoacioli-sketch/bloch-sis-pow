// SPDX-License-Identifier: AGPL-3.0-or-later
//! §9.4 — inertness as a mechanical acceptance criterion, not an opinion.
//!
//! Mainnet finality has been stalled for 27 epochs and blocks arrive roughly
//! one per 40 slots. A line of this crate reaching consensus by accident is
//! not a red test — it is an incident. So the claim "this is inert" is
//! asserted here, in CI, by reading the repository rather than by asking a
//! reviewer to believe it.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // crates/bloch-l1-evm-auth -> crates -> root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate sits two levels under the repo root")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

#[test]
fn the_flag_day_is_still_the_end_of_time() {
    assert_eq!(
        bloch_l1_evm_auth::ACTIVATION_EPOCH,
        u64::MAX,
        "someone lowered the flag day. That is a founder decision, taken after \
         G10 gets its second line and with the fleet rebuilt first."
    );
}

#[test]
fn no_consensus_crate_declares_a_dependency_on_this_one() {
    for crate_dir in ["bloch-pos-node", "bloch-pos-committee", "bloch-crypto", "bloch-euvm"] {
        let manifest = repo_root().join("crates").join(crate_dir).join("Cargo.toml");
        let text = read(&manifest);
        assert!(
            !text.contains("bloch-l1-evm-auth"),
            "{crate_dir}/Cargo.toml names bloch-l1-evm-auth — wiring is X2, after X1, after the founder"
        );
    }
}

#[test]
fn no_consensus_source_file_mentions_this_crate() {
    let mut offenders = Vec::new();
    for crate_dir in ["bloch-pos-node", "bloch-pos-committee", "bloch-crypto", "bloch-euvm"] {
        let src = repo_root().join("crates").join(crate_dir).join("src");
        walk(&src, &mut |path, text| {
            if text.contains("bloch_l1_evm_auth") {
                offenders.push(path.display().to_string());
            }
        });
    }
    assert!(
        offenders.is_empty(),
        "these consensus sources reference the crate: {offenders:?}"
    );
}

#[test]
fn the_crate_is_a_root_workspace_member_and_carries_no_private_workspace() {
    let root = read(&repo_root().join("Cargo.toml"));
    assert!(
        root.contains("\"crates/bloch-l1-evm-auth\""),
        "a crate outside `members` is invisible to `cargo test --workspace` — \
         that is how the entire PoS consensus once went untested"
    );
    let own = read(&repo_root()
        .join("crates")
        .join("bloch-l1-evm-auth")
        .join("Cargo.toml"));
    assert!(
        !own.contains("[workspace]"),
        "a private [workspace] table would hide this crate from the root build"
    );
}

#[test]
fn the_runtime_dependency_list_is_sha3_and_nothing_else() {
    let own = read(&repo_root()
        .join("crates")
        .join("bloch-l1-evm-auth")
        .join("Cargo.toml"));
    // Comment lines name the forbidden crates on purpose (the manifest
    // explains WHY they are absent); only declarations count.
    let runtime: String = own
        .split("[dev-dependencies]")
        .next()
        .expect("manifest has a body")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "revm", "alloy", "k256", "secp256k1", "serde", "bloch-crypto", "bloch-pos-node", "rand",
        "tokio",
    ] {
        assert!(
            !runtime.contains(forbidden),
            "{forbidden} appeared in the runtime dependencies"
        );
    }
    assert!(runtime.contains("sha3"));
}

#[test]
fn no_secp256k1_verifier_exists_anywhere_in_this_crate() {
    // D-AUTH is option 2. Not one line, in any file, under any name.
    let src = repo_root().join("crates").join("bloch-l1-evm-auth").join("src");
    let mut offenders = Vec::new();
    walk(&src, &mut |path, text| {
        for needle in ["ecrecover", "secp256k1", "k256::", "Secp256k1"] {
            // The module docs name the rejected options on purpose; only code
            // would be a problem, and code would not be inside a `//!`/`///`
            // line. Check non-comment lines only.
            for line in text.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if line.contains(needle) {
                    offenders.push(format!("{}: {line}", path.display()));
                }
            }
        }
    });
    assert!(offenders.is_empty(), "secp256k1 crept in: {offenders:?}");
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path, &str)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            let text = read(&path);
            f(&path, &text);
        }
    }
}
