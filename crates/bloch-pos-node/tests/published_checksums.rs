//! The published checksum file must describe the files it ships beside.
//!
//! # Why this test exists
//!
//! On 2026-09-01 `carryover.tsv.gz.sha256` on public `main` still carried the
//! retired **Genesis-1** digests. The data files were correct; the checksum
//! was not. So an operator who followed our own published instructions and
//! verified the download got a mismatch on a **good** file, and the diligent
//! conclusion from a mismatch is tampering.
//!
//! That is the worst shape a trust defect can take: it penalises exactly the
//! careful operator and waves the careless one through.
//!
//! Nothing failed in between. The digests were prose in a text file, and prose
//! cannot go red. This test is the fix — not the corrected digits, which would
//! rot again the next time the snapshot is rebuilt.
//!
//! # The rule
//!
//! A fact the build system can check must never live only in a file nobody
//! executes. Strongest mechanism the fact allows: compile error > test > CI
//! gate > dated fact with a re-check recipe. A checksum is squarely "test".

use std::process::Command;

/// Repository root, from this test's own location.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn sha256_of(path: &std::path::Path) -> String {
    let out = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .expect("shasum runs");
    assert!(out.status.success(), "shasum failed on {}", path.display());
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("a digest")
        .to_string()
}

/// Parse `<digest>  <name>` lines, ignoring trailing annotations such as
/// "(uncompressed)" and any `#` comment lines.
fn published(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.to_string(), it.next()?.to_string()))
        })
        .collect()
}

#[test]
fn the_published_carryover_digests_describe_the_shipped_files() {
    let root = repo_root();
    let sums = root.join("carryover.tsv.gz.sha256");
    let text = std::fs::read_to_string(&sums).expect("the checksum file ships");
    let rows = published(&text);
    assert!(!rows.is_empty(), "{} lists no digests", sums.display());

    let gz = root.join("carryover.tsv.gz");
    assert!(gz.exists(), "carryover.tsv.gz must ship beside its checksum");

    // The compressed file we can hash directly.
    let gz_row = rows
        .iter()
        .find(|(_, name)| name.ends_with("carryover.tsv.gz"))
        .expect("the checksum file must name carryover.tsv.gz");
    assert_eq!(
        gz_row.0,
        sha256_of(&gz),
        "\ncarryover.tsv.gz.sha256 does not describe carryover.tsv.gz.\n\
         An operator who verifies the download as we instruct will get a\n\
         mismatch on a GOOD file and correctly conclude tampering.\n\
         Regenerate the checksum file in THIS commit; do not ship them\n\
         disagreeing.\n"
    );

    // The uncompressed digest is checked by streaming through gunzip, so the
    // 17 MB plaintext never has to exist on disk.
    let un = rows
        .iter()
        .find(|(_, name)| name.ends_with("carryover.tsv"));
    if let Some((claimed, _)) = un {
        let sh = format!(
            "gzip -dc {} | shasum -a 256",
            shell_quote(&gz.to_string_lossy())
        );
        let out = Command::new("sh").arg("-c").arg(&sh).output().expect("pipeline runs");
        let got = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .expect("a digest")
            .to_string();
        assert_eq!(
            *claimed, got,
            "\nthe uncompressed digest in carryover.tsv.gz.sha256 does not match\n\
             what carryover.tsv.gz decompresses to. Same rule: regenerate in\n\
             this commit.\n"
        );
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
