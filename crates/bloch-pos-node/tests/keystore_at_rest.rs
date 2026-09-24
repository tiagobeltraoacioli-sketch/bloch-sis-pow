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
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FD")
        .env_remove("BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF")
        .env_remove("BLOCH_KEYSTORE_EXPECT_KDF")
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
    let recovery = run(&["keygen-public", "--dir", dir.to_str().unwrap()],
        &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE),
          ("BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF", "1"),
          ("BLOCH_KEYSTORE_EXPECT_KDF", "65536,3,1")]);
    assert!(recovery.status.success(), "explicit bounded recovery must preserve ordinary decoding");
    assert_eq!(recovery.stdout, ok.stdout);
    let missing_expectation = run(&["keygen-public", "--dir", dir.to_str().unwrap()],
        &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE), ("BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF", "1")]);
    assert!(!missing_expectation.status.success());
    assert!(stderr(&missing_expectation).contains("expensive KDF recovery requires BLOCH_KEYSTORE_EXPECT_KDF"));
    let wrong_expectation = run(&["keygen-public", "--dir", dir.to_str().unwrap()],
        &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE),
          ("BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF", "1"),
          ("BLOCH_KEYSTORE_EXPECT_KDF", "65536,4,1")]);
    assert!(!wrong_expectation.status.success());
    assert!(stderr(&wrong_expectation).contains("does not match BLOCH_KEYSTORE_EXPECT_KDF"));
    let expectation_without_opt_in = run(&["keygen-public", "--dir", dir.to_str().unwrap()],
        &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE),
          ("BLOCH_KEYSTORE_EXPECT_KDF", "65536,3,1")]);
    assert!(!expectation_without_opt_in.status.success());
    assert!(stderr(&expectation_without_opt_in).contains("requires BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1"));
    let invalid = run(&["keygen-public", "--dir", dir.to_str().unwrap()],
        &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE), ("BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF", "2")]);
    assert!(!invalid.status.success());
    assert!(stderr(&invalid).contains("BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF must be 0 or 1"));

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

// ----- deep audit 2026-09-16: KS-01, KS-02, KS-03 through the binary -----

fn write_pass_file(dir: &PathBuf, contents: &str, mode: u32) -> PathBuf {
    let p = dir.join("pass");
    std::fs::write(&p, format!("{contents}\n")).expect("write pass file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    let _ = mode;
    p
}

/// Temp files left in `dir`. The keystore is installed through a staging
/// file with a per-process unique name, so look for the suffix rather than
/// one fixed path.
fn leftover_temp_files(dir: &PathBuf) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect()
}

/// audit KS-01 (2026-09-16). `keygen` pointed at a directory that already
/// holds a `validator.key` is a refusal, not a replacement: the bytes on
/// disk are untouched under every policy, the message says why, and the
/// exit code is the binary's failure code (1), not a usage error.
#[test]
fn keygen_refuses_to_overwrite_an_existing_keystore() {
    let dir = tmp_dir("overwrite");
    let out = keygen(&dir, &[("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE)]);
    assert!(out.status.success(), "first keygen failed: {}", stderr(&out));
    let before = std::fs::read(dir.join("validator.key")).expect("read");

    for env in [
        vec![("BLOCH_KEYSTORE_PASSPHRASE", PASSPHRASE)],
        vec![("BLOCH_KEYSTORE_PASSPHRASE", "a different throwaway passphrase")],
        vec![("BLOCH_KEYSTORE_ALLOW_PLAINTEXT", "1")],
    ] {
        let again = keygen(&dir, &env);
        assert_eq!(again.status.code(), Some(1), "keygen over a live key ({env:?}): {}", stderr(&again));
        let e = stderr(&again);
        assert!(e.contains("refusing to replace"), "the refusal does not say why: {e}");
        assert!(again.stdout.is_empty(), "a refused keygen printed a success line");
    }
    assert_eq!(std::fs::read(dir.join("validator.key")).expect("read"), before, "the key was touched");
    let leftover = leftover_temp_files(&dir);
    assert!(leftover.is_empty(), "temp file left behind: {leftover:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// audit KS-02 (2026-09-16). The node's `BLOCH_KEYSTORE_PASSPHRASE_FILE`
/// path, the one `run` and every keystore-reading verb take, refuses a
/// group- or world-readable passphrase file, the way `keys seal
/// --passphrase-file` always did, and opens the keystore once the file is
/// 0600. Driven through `keygen-public`, which reads the keystore through
/// exactly the loader `run` uses.
#[cfg(unix)]
#[test]
fn the_node_passphrase_file_path_refuses_a_world_readable_file() {
    let dir = tmp_dir("passfile-mode");
    let pass = write_pass_file(&dir, PASSPHRASE, 0o600);
    let out = keygen(&dir, &[("BLOCH_KEYSTORE_PASSPHRASE_FILE", pass.to_str().unwrap())]);
    assert!(out.status.success(), "keygen from a 0600 passphrase file failed: {}", stderr(&out));

    for mode in [0o644u32, 0o640, 0o604] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(mode)).expect("chmod");
        let refused = run(
            &["keygen-public", "--dir", dir.to_str().unwrap()],
            &[("BLOCH_KEYSTORE_PASSPHRASE_FILE", pass.to_str().unwrap())],
        );
        assert!(!refused.status.success(), "a {mode:04o} passphrase file opened the keystore");
        assert!(refused.stdout.is_empty(), "a refused open still printed a cohort row");
        let e = stderr(&refused);
        assert!(
            e.contains("readable by group or others") && e.contains("passphrase file"),
            "the refusal does not name the cause: {e}"
        );
    }
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let ok = run(
        &["keygen-public", "--dir", dir.to_str().unwrap()],
        &[("BLOCH_KEYSTORE_PASSPHRASE_FILE", pass.to_str().unwrap())],
    );
    assert!(ok.status.success(), "a 0600 passphrase file must open the keystore: {}", stderr(&ok));
    assert!(String::from_utf8_lossy(&ok.stdout).starts_with("0\t"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// audit KS-03 (2026-09-16). `keygen` under a passphrase shorter than the
/// floor `keys seal` already enforces, from the environment variable and
/// from a passphrase file alike, is refused, names the floor, and writes
/// nothing. The floor applies when SEALING only: resolving the unlock policy
/// never enforces it (unit-tested in `keys.rs`), so a keystore sealed under
/// a short passphrase by an earlier binary keeps opening.
#[test]
fn keygen_refuses_a_short_passphrase_and_writes_nothing() {
    let dir = tmp_dir("short-pass");
    let short = "elevenchars";
    let pass = write_pass_file(&dir, short, 0o600);
    for env in [
        vec![("BLOCH_KEYSTORE_PASSPHRASE", short)],
        vec![("BLOCH_KEYSTORE_PASSPHRASE_FILE", pass.to_str().unwrap())],
    ] {
        let out = keygen(&dir, &env);
        assert_eq!(out.status.code(), Some(1), "keygen under a short passphrase ({env:?})");
        let e = stderr(&out);
        assert!(e.contains("at least 12 characters"), "the refusal does not name the floor: {e}");
        assert!(!dir.join("validator.key").exists(), "a refused keygen wrote a keystore");
        let leftover = leftover_temp_files(&dir);
        assert!(leftover.is_empty(), "a refused keygen left a temp file: {leftover:?}");
    }
    // Twelve characters is the floor, and the floor seals.
    let out = keygen(&dir, &[("BLOCH_KEYSTORE_PASSPHRASE", "twelve chars")]);
    assert!(out.status.success(), "a passphrase at the floor must seal: {}", stderr(&out));
    assert_eq!(&std::fs::read(dir.join("validator.key")).unwrap()[..8], SEALED_MAGIC);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn inherited_pipe_credentials_seal_and_reopen_without_secret_environment() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = tmp_dir("inherited-pipe");
    let invoke = |arguments: &[&str], conflict: bool| {
        let mut command = Command::new(BIN);
        command.args(arguments).env_remove("BLOCH_KEYSTORE_PASSPHRASE")
            .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FILE")
            .env_remove("BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF")
            .env_remove("BLOCH_KEYSTORE_EXPECT_KDF")
            .env_remove("BLOCH_KEYSTORE_ALLOW_PLAINTEXT")
            .env("BLOCH_KEYSTORE_PASSPHRASE_FD", "0")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if conflict { command.env("BLOCH_KEYSTORE_PASSPHRASE", "unused-conflicting-value"); }
        let mut child = command.spawn().unwrap();
        if !conflict {
            child.stdin.take().unwrap().write_all(PASSPHRASE.as_bytes()).unwrap();
        } else { drop(child.stdin.take()); }
        let output = child.wait_with_output().unwrap();
        assert!(!contains(&output.stdout, PASSPHRASE.as_bytes()));
        assert!(!contains(&output.stderr, PASSPHRASE.as_bytes()));
        output
    };
    let path = dir.to_str().unwrap();
    let generated = invoke(&["keygen", "--dir", path, "--index", "0"], false);
    assert!(generated.status.success(), "{}", String::from_utf8_lossy(&generated.stderr));
    assert_eq!(&std::fs::read(dir.join("validator.key")).unwrap()[..8], SEALED_MAGIC);
    let opened = invoke(&["keygen-public", "--dir", path], false);
    assert!(opened.status.success(), "{}", String::from_utf8_lossy(&opened.stderr));
    let refused = invoke(&["keygen-public", "--dir", path], true);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("cannot be combined"));
    std::fs::remove_dir_all(dir).unwrap();
}
