// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-pos keys seal` / `keys inspect`, **through the binary** (audit
//! round 3: the flag-day prerequisite).
//!
//! `src/keys.rs` unit-tests `Keystore::seal_in_place` and `Keystore::inspect`.
//! This drives the shipped executable the way the runbook will: a plaintext
//! `BPOSKEY1` keystore written by `keygen`, sealed in place from a 0600
//! passphrase file, inspected before and after, and opened afterwards by
//! `keygen-public` under the sealed policy only.
//!
//! Every key here is generated in-process into a temp dir and deleted. No
//! fleet host, no real keystore and no real passphrase is touched.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");
const PASSPHRASE: &str = "throwaway test passphrase, long enough";

const SEALED_MAGIC: &[u8] = b"BPOSKEY2";
const PLAINTEXT_MAGIC: &[u8] = b"BPOSKEY1";

fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bloch-pos-keys-seal-{}-{}-{}",
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

/// Run `bloch-pos` over a cleared keystore policy, so nothing in the
/// developer's shell can turn a refusal into a success.
fn run(args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut c = Command::new(BIN);
    c.env_remove("BLOCH_KEYSTORE_PASSPHRASE")
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FILE")
        .env_remove("BLOCH_KEYSTORE_ALLOW_PLAINTEXT");
    for (k, v) in env {
        c.env(k, v);
    }
    // `output()` connects stdin to /dev/null: NOT a tty, which is exactly the
    // condition the interactive path must refuse under.
    c.args(args).output().expect("spawn bloch-pos")
}

fn text(o: &std::process::Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn write_pass_file(dir: &Path, mode: u32) -> PathBuf {
    let p = dir.join("pass");
    std::fs::write(&p, format!("{PASSPHRASE}\n")).expect("write pass file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    let _ = mode;
    p
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// The migration, end to end, exactly as the runbook will run it.
#[test]
fn a_plaintext_keystore_is_sealed_in_place_and_opens_only_under_the_passphrase() {
    let dir = tmp_dir("migrate");
    let d = dir.to_str().unwrap();

    // 1. A fleet-shaped plaintext keystore.
    let g = run(&["keygen", "--dir", d, "--index", "9"], &[("BLOCH_KEYSTORE_ALLOW_PLAINTEXT", "1")]);
    assert!(g.status.success(), "keygen (plaintext opt-in) failed: {}", text(&g));
    let plain = std::fs::read(dir.join("validator.key")).expect("read plaintext keystore");
    assert_eq!(&plain[..8], PLAINTEXT_MAGIC);

    // 2. Inspect says plaintext, prints no secret, and reports the lock free.
    let i = run(&["keys", "inspect", "--dir", d], &[]);
    assert!(i.status.success(), "{}", text(&i));
    let shown = text(&i);
    assert!(shown.contains("plaintext"), "{shown}");
    assert!(shown.contains("index     : 9"), "{shown}");
    assert!(shown.contains("lock free"), "{shown}");
    // The RANDAO seed is the last 32 bytes of the plaintext file; the secret
    // key sits before it. Neither may appear in anything inspect prints.
    let seed = &plain[plain.len() - 32..];
    assert!(!contains(&i.stdout, seed) && !contains(&i.stderr, seed));

    // 3. Seal from a 0600 passphrase file.
    let pass = write_pass_file(&dir, 0o600);
    let s = run(&["keys", "seal", "--dir", d, "--passphrase-file", pass.to_str().unwrap()], &[]);
    assert!(s.status.success(), "keys seal failed: {}", text(&s));
    let out = text(&s);
    assert!(out.contains("sealed"), "{out}");
    assert!(!out.contains(PASSPHRASE), "the passphrase must never be echoed");
    assert!(!contains(&s.stdout, seed), "no secret byte on stdout");
    let sealed = std::fs::read(dir.join("validator.key")).expect("read sealed keystore");
    assert_eq!(&sealed[..8], SEALED_MAGIC, "the file is now sealed");
    assert!(!contains(&sealed, seed), "the RANDAO seed left the disk");
    assert!(!dir.join("validator.key.sealed.tmp").exists(), "no temp file left behind");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("validator.key")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // 4. Inspect now says sealed.
    let i = run(&["keys", "inspect", "--dir", d], &[]);
    assert!(i.status.success(), "{}", text(&i));
    assert!(text(&i).contains("sealed"), "{}", text(&i));

    // 5. The sealed file opens under the passphrase file and NOT under the
    //    plaintext opt-in: the migration is real, not cosmetic.
    let ok = run(
        &["keygen-public", "--dir", d],
        &[("BLOCH_KEYSTORE_PASSPHRASE_FILE", pass.to_str().unwrap())],
    );
    assert!(ok.status.success(), "sealed keystore must open under its passphrase: {}", text(&ok));
    assert!(String::from_utf8_lossy(&ok.stdout).starts_with("9\t"), "{}", text(&ok));
    let no = run(&["keygen-public", "--dir", d], &[("BLOCH_KEYSTORE_ALLOW_PLAINTEXT", "1")]);
    assert!(!no.status.success(), "the plaintext opt-in must not open a sealed keystore");

    // 6. Sealing twice is a refusal, not a silent re-seal.
    let again = run(&["keys", "seal", "--dir", d, "--passphrase-file", pass.to_str().unwrap()], &[]);
    assert!(!again.status.success());
    assert!(text(&again).contains("already sealed"), "{}", text(&again));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The passphrase never comes from argv, never from a world-readable file,
/// and never from a stdin that is not a terminal.
#[test]
fn keys_seal_refuses_every_unsafe_passphrase_source() {
    let dir = tmp_dir("sources");
    let d = dir.to_str().unwrap();
    let g = run(&["keygen", "--dir", d, "--index", "1"], &[("BLOCH_KEYSTORE_ALLOW_PLAINTEXT", "1")]);
    assert!(g.status.success(), "{}", text(&g));
    let before = std::fs::read(dir.join("validator.key")).unwrap();

    // argv
    let a = run(&["keys", "seal", "--dir", d, "--passphrase", PASSPHRASE], &[]);
    assert_eq!(a.status.code(), Some(2), "{}", text(&a));
    assert!(text(&a).contains("not accepted"), "{}", text(&a));

    // world-readable file
    #[cfg(unix)]
    {
        let loose = write_pass_file(&dir, 0o644);
        let w = run(&["keys", "seal", "--dir", d, "--passphrase-file", loose.to_str().unwrap()], &[]);
        assert!(!w.status.success());
        assert!(text(&w).contains("readable by group or others"), "{}", text(&w));
    }

    // no file, stdin is /dev/null
    let t = run(&["keys", "seal", "--dir", d], &[]);
    assert!(!t.status.success());
    assert!(text(&t).contains("not a terminal"), "{}", text(&t));

    // Nothing above touched the keystore.
    assert_eq!(std::fs::read(dir.join("validator.key")).unwrap(), before);
    assert_eq!(&before[..8], PLAINTEXT_MAGIC);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `keys inspect` on a directory with no keystore is an error, not a crash,
/// and `keys` with no verb prints usage and exits 2.
#[test]
fn keys_inspect_without_a_keystore_is_a_clean_error() {
    let dir = tmp_dir("empty");
    let d = dir.to_str().unwrap();
    let i = run(&["keys", "inspect", "--dir", d], &[]);
    assert_eq!(i.status.code(), Some(1), "{}", text(&i));
    assert!(text(&i).contains("cannot read"), "{}", text(&i));
    let k = run(&["keys"], &[]);
    assert_eq!(k.status.code(), Some(2), "{}", text(&k));
    let _ = std::fs::remove_dir_all(&dir);
}
