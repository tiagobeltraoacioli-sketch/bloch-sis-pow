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

#[test]
fn the_terminal_carryover_facts_match_ledger_documentation() {
    use bloch_pos_committee::tokenomics_v4::{
        split_g3_sat, CARRYOVER_MEASURED_UTXOS, CARRYOVER_TOTAL_BLOCH, SAT_PER_BLOCH,
    };

    let gz = repo_root().join("carryover.tsv.gz");
    let output = Command::new("gzip")
        .arg("-dc")
        .arg(&gz)
        .output()
        .expect("gzip runs");
    assert!(output.status.success(), "gzip failed on {}", gz.display());
    let text = std::str::from_utf8(&output.stdout).expect("snapshot is UTF-8 TSV");

    let mut rows = 0u64;
    let mut g3_total = 0u128;
    let mut split_rows = 0u128;
    let mut remainder_rows = 0u64;
    let mut zero_rows = 0u64;
    let mut largest: Option<(u64, &str, u32, &str)> = None;
    for line in text.lines() {
        let mut fields = line.split('\t');
        let txid = fields.next().expect("txid");
        let vout: u32 = fields.next().expect("vout").parse().expect("canonical vout");
        let value: u64 = fields.next().expect("value").parse().expect("canonical value");
        let address = fields.next().expect("address");
        assert!(fields.next().is_none(), "snapshot row has more than four fields");

        rows += 1;
        g3_total += u128::from(value);
        split_rows += split_g3_sat(u128::from(value));
        remainder_rows += u64::from((u128::from(value) * 100) % 21 != 0);
        zero_rows += u64::from(value == 0);
        let candidate = (value, txid, vout, address);
        if largest.is_none_or(|current| {
            value > current.0 || (value == current.0 && (txid, vout) < (current.1, current.2))
        }) {
            largest = Some(candidate);
        }
    }

    let exact = split_g3_sat(g3_total);
    assert_eq!(rows, CARRYOVER_MEASURED_UTXOS);
    assert_eq!(g3_total, 381_074_400_000_000_000);
    assert_eq!(exact, CARRYOVER_TOTAL_BLOCH * SAT_PER_BLOCH);
    assert_eq!(remainder_rows, 111);
    assert_eq!(exact - split_rows, 57);
    assert_eq!(zero_rows, 1, "the historical anchor is the only zero-value row");
    assert_eq!(
        largest.expect("snapshot is non-empty").3,
        "cb339d2ef2e502d36864689192891567ba87f91c",
        "the deterministic dust recipient is the owner of the largest output"
    );
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
