// SPDX-License-Identifier: AGPL-3.0-or-later

//! The keystore is sealed at rest, **through the binary** (audit I-H1).
//!
//! `src/keys.rs` has unit tests for the format itself. They prove the module
//! is right; they do not prove the shipped `bloch-pos` uses it, or that the
//! policy an operator actually types — an environment variable, a command-line
//! flag — reaches it. That gap is where this defect lived: the code that wrote
//! the plaintext file was reachable, correct, and tested.
//!
//! So this drives the real executable and reads the real bytes off disk.
//!
//! Fast on purpose: `keygen` and `keygen-public`, no chain, no clock, no
//! network. The consensus cold start lives in `cold_start.rs` and is left
//! alone — it is timing-sensitive, and adding a memory-hard KDF to every node
//! boot made a known-flaky test flakier without proving anything more.
//!
//! Every key here is generated in-process into a temp dir and deleted. No
//! fleet host, no real keystore and no real passphrase is touched.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");
const PASSPHRASE: &str = "throwaway test passphrase";

/// Sealed format. The plaintext one this replaced is `BPOSKEY1`.
const SEALED_MAGIC: &[u8] = b"BPOSKEY2";
const PLAINTEXT_MAGIC: &[u8] = b"BPOSKEY1";

fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bloch-pos-keystore-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create the test dir");
    d
}

/// Run `bloch-pos` with an explicit environment. `env` is applied on top of a
/// cleared keystore policy, so a passphrase or opt-in that happens to be set
/// in the developer's own shell cannot make a refusal look like a success.
fn run(args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut c = Command::new(BIN);
    c.env_remove("BLOCH_KEYSTORE_PASSPHRASE")
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FILE")
        .env_remove("BLOCH_KEYSTORE_ALLOW_PLAINTEXT");
    for (k, v) in env {
        c.env(k, v);
    }
    c.args(args).output().expect("spawn bloch-pos")
}

fn keygen(dir: &PathBuf, env: &[(&str, &str)]) -> std::process::Output {
    run(&["keygen", "--dir", dir.to_str().unwrap(), "--index", "0"], env)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The binary, given a passphrase, writes a sealed file — and the RANDAO
/// commitment it prints (public, derived from the secret seed) does not appear
/// in that file, because the seed it comes from is inside the ciphertext.
///
/// Against the pre-fix binary this fails on the magic: `keygen` wrote
/// `BPOSKEY1` with the hybrid secret key and the RANDAO seed in the clear.
#[test]
fn keygen_under_a_passphrase_writes_a_sealed_file() {
    let dir = tmp_dir("sealed");
    let out = keygen(&dir, &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE)]);
    assert!(out.status.success(), "keygen failed: {}", stderr(&out));

    let raw = std::fs::read(dir.join("validator.key")).expect("read the keystore");
    assert_eq!(
        &raw[..8],
        SEALED_MAGIC,
        "keygen wrote {:?}, not a sealed keystore",
        String::from_utf8_lossy(&raw[..8])
    );
    assert!(
        !contains(&raw, PLAINTEXT_MAGIC),
        "a plaintext keystore body is embedded in the file"
    );

    // Mode 0600, as before — necessary, and never sufficient, which is the
    // whole finding.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("validator.key"))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "keystore mode is {mode:o}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The sealed file opens again through the binary — `keygen-public` reads the
/// keystore and prints the cohort row — and refuses to open without the
/// passphrase. Both halves through the real executable, because the second is
/// the property an operator depends on and the first is the one that stops it
/// from being useless.
#[test]
fn the_binary_reopens_a_sealed_keystore_only_with_the_passphrase() {
    let dir = tmp_dir("reopen");
    let out = keygen(&dir, &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE)]);
    assert!(out.status.success(), "keygen failed: {}", stderr(&out));

    let ok = run(
        &["keygen-public", "--dir", dir.to_str().unwrap()],
        &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE)],
    );
    assert!(
        ok.status.success(),
        "keygen-public could not reopen a keystore it just sealed: {}",
        stderr(&ok)
    );
    let row = String::from_utf8_lossy(&ok.stdout);
    assert!(row.starts_with("0\t"), "unexpected cohort row: {row:?}");

    for env in [
        vec![],
        vec![("BLOCH_KEYSTORE_PASSPHRASE", "the wrong one")],
        vec![("BLOCH_KEYSTORE_ALLOW_PLAINTEXT", "1")],
    ] {
        let bad = run(&["keygen-public", "--dir", dir.to_str().unwrap()], &env);
        assert!(
            !bad.status.success(),
            "a sealed keystore opened with {env:?}; stdout was {:?}",
            String::from_utf8_lossy(&bad.stdout)
        );
        assert!(
            bad.stdout.is_empty(),
            "a refused open still printed something: {:?}",
            String::from_utf8_lossy(&bad.stdout)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// No passphrase and no opt-in is a refusal that writes nothing. The default
/// is not "plaintext because nobody configured anything" — that default is the
/// defect.
#[test]
fn keygen_with_no_policy_at_all_refuses_and_writes_nothing() {
    let dir = tmp_dir("nopolicy");
    let out = keygen(&dir, &[]);
    assert!(
        !out.status.success(),
        "keygen wrote a keystore with no passphrase and no opt-in"
    );
    assert!(
        !dir.join("validator.key").exists(),
        "a refused keygen still left a validator.key behind"
    );
    // The message has to name a way forward; a refusal an operator cannot act
    // on is an outage.
    let e = stderr(&out);
    assert!(
        e.contains("BLOCH_KEYSTORE_PASSPHRASE") && e.contains("--allow-plaintext-keystore"),
        "the refusal does not tell the operator what to do: {e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The opt-in still works, is the only thing that makes a plaintext file, and
/// is reachable from the command line as well as the environment — a flag an
/// operator can see in `ps` and in a unit file, not only an inherited variable.
#[test]
fn the_plaintext_opt_in_is_the_only_route_to_a_plaintext_file() {
    for (tag, args, env) in [
        (
            "env",
            vec!["keygen", "--dir", "", "--index", "0"],
            vec![("BLOCH_KEYSTORE_ALLOW_PLAINTEXT", "1")],
        ),
        (
            "flag",
            vec![
                "keygen",
                "--allow-plaintext-keystore",
                "--dir",
                "",
                "--index",
                "0",
            ],
            vec![],
        ),
    ] {
        let dir = tmp_dir(tag);
        let args: Vec<&str> = args
            .into_iter()
            .map(|a| if a.is_empty() { dir.to_str().unwrap() } else { a })
            .collect();
        let out = run(&args, &env);
        assert!(out.status.success(), "keygen ({tag}) failed: {}", stderr(&out));
        let raw = std::fs::read(dir.join("validator.key")).expect("read");
        assert_eq!(
            &raw[..8],
            PLAINTEXT_MAGIC,
            "the {tag} opt-in did not produce a plaintext keystore"
        );

        // ...and that file is refused by a node configured for a sealed one.
        let refused = run(
            &["keygen-public", "--dir", dir.to_str().unwrap()],
            &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE)],
        );
        assert!(
            !refused.status.success(),
            "a plaintext keystore loaded under a passphrase policy ({tag})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
