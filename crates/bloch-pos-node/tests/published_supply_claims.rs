// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The published supply figures, and the gate that makes them expire.**
//!
//! On 2026-09-01 an audit measured the founder script hash on two archival
//! nodes and found 37,918,473,235.78565979 BLCH. `docs/PROJECT-STATUS.md` and
//! `SECURITY.md` both published 56,046,829,380 — in the present tense, as
//! "sitting at a single script hash". The gap was 18,128,356,145.07452011
//! BLCH, moved on chain across 1,051 transactions between epochs 184 and 1618,
//! and **nothing in this repository could detect it**.
//!
//! The published number was not wrong when it was written. It was the genesis
//! holding, and the genesis holding is still exactly that. What was wrong was
//! the tense. That is the whole defect class this file exists for: a
//! *measurement* published as if it were a *constant*.
//!
//! ## Why `integration_book_claims.rs` could not have caught it
//!
//! That file works — beautifully — because every number it guards is decided
//! by a constant in this workspace, so a parameter change and the assertion
//! move together in one commit. There is no constant that decides what an
//! address holds. Live state drifts with no commit at all, so no
//! assert-against-a-constant test can ever see it.
//!
//! So this file asserts two different things:
//!
//! 1. **Genesis figures against the shipped artefacts** (`genesis_*` tests) —
//!    hermetic, always on. `carryover.tsv.gz` is in the repository and the five
//!    allocation buckets are constants, so the opening ledger is fully
//!    derivable here. This catches a *wrong* genesis number.
//!
//! 2. **Live figures against a clock** (`live_*` tests) — every figure that
//!    describes current state lives in exactly one place,
//!    `docs/LIVE-SUPPLY.md`, carrying a `measured_at` date, and this file fails
//!    once that date ages past [`MAX_MEASUREMENT_AGE_DAYS`]. Nobody has to
//!    remember to look; the calendar turns it red. When `BLOCH_ARCHIVAL_RPC`
//!    is set it additionally re-measures every row against two archivals and
//!    demands exact agreement.
//!
//! The second gate is the one that would have caught this. It is deliberately
//! annoying: a stale figure in a published document is a defect, and the cost
//! of clearing it is one re-measurement.
//!
//! ## Discipline
//!
//! A failure in `live_*` is not a bug in this file. Re-measure (the recipe is
//! in `docs/LIVE-SUPPLY.md`), update the table and `measured_at` in the same
//! commit. Do **not** raise `MAX_MEASUREMENT_AGE_DAYS` to make it pass — that
//! converts a known-stale number back into an unknown-stale one, which is the
//! state this file was written to end.

use std::path::{Path, PathBuf};
use std::process::Command;

/// How long a live measurement stays publishable. Chosen because the sweep
/// that motivated this file moved 90% of its value inside 26 days: a window
/// wider than that can hide the whole event between two green runs.
const MAX_MEASUREMENT_AGE_DAYS: i64 = 30;

/// The founder script hash, as `getbalance` takes it: the 20-byte hash160
/// zero-extended to the right, per `read_carryover_snapshot`.
const FOUNDER_H160: &str = "e986db5149cff7499b282a048272a09aff0af4ff";

/// Repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn ledger_path() -> PathBuf {
    repo_root().join("docs/LIVE-SUPPLY.md")
}

fn ledger() -> String {
    std::fs::read_to_string(ledger_path())
        .expect("docs/LIVE-SUPPLY.md must exist — it is the only place a live figure may be published")
}

/// One `script_hash  balance_sat  utxos  share%` row of the ledger table.
#[derive(Debug, PartialEq, Eq)]
struct Row {
    h160: String,
    balance_sat: u128,
    utxos: u64,
}

fn ledger_rows(text: &str) -> Vec<Row> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 4 || f[0].len() != 40 || !f[0].chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let (Ok(balance_sat), Ok(utxos)) = (f[1].parse::<u128>(), f[2].parse::<u64>()) else {
            continue;
        };
        out.push(Row { h160: f[0].to_string(), balance_sat, utxos });
    }
    assert!(!out.is_empty(), "the ledger table in docs/LIVE-SUPPLY.md parsed to zero rows");
    out
}

/// `measured_at YYYY-MM-DD` as days since the Unix epoch.
fn measured_at_day(text: &str) -> i64 {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("measured_at"))
        .expect("docs/LIVE-SUPPLY.md must carry a `measured_at YYYY-MM-DD` line");
    let d = line.split_whitespace().nth(1).expect("measured_at has no date");
    let p: Vec<i64> = d.split('-').map(|x| x.parse().expect("measured_at is not YYYY-MM-DD")).collect();
    assert_eq!(p.len(), 3, "measured_at is not YYYY-MM-DD: {d:?}");
    days_from_civil(p[0], p[1], p[2])
}

/// Howard Hinnant's `days_from_civil`. Written out rather than pulled in: this
/// test must not acquire a dependency to check a date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn today_day() -> i64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400) as i64
}

// ───────────────────────── genesis: hermetic ─────────────────────────

/// The opening ledger, rebuilt from `carryover.tsv.gz` exactly as
/// `genesis::read_carryover_snapshot` builds it: per-row `x100/21` floor, then
/// the whole remainder onto the highest-value entry (ties to lowest outpoint).
///
/// Returns `(total_sat, founder_sat, founder_outputs, rows)`.
fn rebuild_carryover() -> (u128, u128, u64, u64) {
    let gz = repo_root().join("carryover.tsv.gz");
    let out = Command::new("gzip")
        .arg("-dc")
        .arg(&gz)
        .output()
        .expect("`gzip -dc` — the same command CARRYOVER-SNAPSHOT.md tells a reader to run");
    assert!(out.status.success(), "gzip -dc {} failed", gz.display());
    let text = String::from_utf8(out.stdout).expect("carryover.tsv is UTF-8");

    let mut split_total: u128 = 0;
    let mut g3_total: u128 = 0;
    let mut founder: u128 = 0;
    let mut founder_n: u64 = 0;
    let mut rows: u64 = 0;
    // The dust lands on the highest-value entry; we only need to know whether
    // that entry is the founder's, so we track the running maximum's owner.
    let mut best: Option<(u128, bool)> = None;

    for line in text.lines() {
        let c: Vec<&str> = line.split('\t').collect();
        assert_eq!(c.len(), 4, "carryover row is not 4 tab-separated columns");
        let g3: u128 = c[2].parse().expect("value_sat is not a u128");
        let split = bloch_pos_committee::tokenomics_v4::split_g3_sat(g3);
        let is_founder = c[3] == FOUNDER_H160;
        g3_total += g3;
        split_total += split;
        rows += 1;
        if is_founder {
            founder += split;
            founder_n += 1;
        }
        if best.is_none_or(|(v, _)| split > v) {
            best = Some((split, is_founder));
        }
    }

    let exact = bloch_pos_committee::tokenomics_v4::split_g3_sat(g3_total);
    let dust = exact - split_total;
    if best.expect("carryover is empty").1 {
        founder += dust;
    }
    (exact, founder, founder_n, rows)
}

fn allocation_total_sat() -> u128 {
    use bloch_pos_committee::tokenomics_v4 as t;
    (t::FOUNDER_BLOCH + t::VC_BLOCH + t::TEAM_BLOCH + t::MARKETING_BLOCH + t::LIQUIDITY_BLOCH)
        * t::SAT_PER_BLOCH
}

#[test]
fn genesis_carryover_matches_the_shipped_snapshot() {
    let (total, _, _, rows) = rebuild_carryover();
    assert_eq!(rows, 452_726, "CARRYOVER-SNAPSHOT.md publishes 452,726 rows");
    assert_eq!(
        total,
        bloch_pos_committee::tokenomics_v4::CARRYOVER_TOTAL_BLOCH
            * bloch_pos_committee::tokenomics_v4::SAT_PER_BLOCH,
        "the shipped carryover.tsv.gz no longer sums to CARRYOVER_TOTAL_BLOCH",
    );
}

#[test]
fn genesis_issuance_is_carryover_plus_the_five_buckets() {
    let (carry, _, _, _) = rebuild_carryover();
    assert_eq!(
        carry + allocation_total_sat(),
        bloch_pos_committee::tokenomics_v4::GENESIS_ISSUED_SAT,
        "carryover + allocations no longer equals GENESIS_ISSUED_SAT",
    );
}

/// The genesis holding of the founder script hash — 56,046,829,380.86018372
/// BLCH across 426,199 outputs — is fixed forever and derivable here. It is
/// the number the two documents published; the defect was never this figure,
/// it was publishing it in the present tense.
#[test]
fn genesis_founder_holding_is_what_the_documents_used_to_call_current() {
    let (_, founder_carry, founder_n, _) = rebuild_carryover();
    let founder = founder_carry + allocation_total_sat();
    assert_eq!(founder_carry, 1_704_682_938_086_017_913, "founder carryover share moved");
    assert_eq!(founder_n, 426_194, "founder carryover output count moved");
    assert_eq!(founder, 5_604_682_938_086_017_913, "founder genesis holding moved");
    assert_eq!(founder_n + 5, 426_199, "founder genesis output count moved");

    let text = ledger();
    assert!(
        text.contains("5604682938086017913") && text.contains("56,046,829,380.86018372"),
        "docs/LIVE-SUPPLY.md must state the genesis holding, in satoshis and in BLCH",
    );
}

/// **`FOUNDER_TOTAL_BLOCH` omits four of the five allocation buckets.**
///
/// This test is green while the defect stands and goes red the moment somebody
/// fixes the constant — at which point the fixer updates this test and the
/// eleven published figures listed in `docs/LIVE-SUPPLY.md` in the same commit.
/// That is the point: today the wrong number is invisible, and after this test
/// exists it cannot be changed quietly in either direction.
///
/// The constant reads `LARGEST_CARRYOVER_ADDRESS_BLOCH + FOUNDER_BLOCH`, but
/// `main.rs:605-622` writes **all five** buckets to one script hash — the
/// founder's — under a single `script_hash` expression. The four it drops
/// (`VC`, `TEAM`, `MARKETING`, `LIQUIDITY`) are 29,000,000,000 BLCH.
///
/// It is a reporting constant: no consumer in `bloch-pos-committee` or
/// `bloch-pos-node` outside `tokenomics_v4.rs`, so correcting it moves no
/// consensus behaviour and no state root.
#[test]
fn founder_total_bloch_omits_four_of_the_five_buckets() {
    use bloch_pos_committee::tokenomics_v4 as t;

    let omitted = t::VC_BLOCH + t::TEAM_BLOCH + t::MARKETING_BLOCH + t::LIQUIDITY_BLOCH;
    assert_eq!(omitted, 29_000_000_000, "the four dropped buckets changed size");

    let correct = t::LARGEST_CARRYOVER_ADDRESS_BLOCH
        + t::FOUNDER_BLOCH
        + t::VC_BLOCH
        + t::TEAM_BLOCH
        + t::MARKETING_BLOCH
        + t::LIQUIDITY_BLOCH;
    assert_eq!(correct, 56_046_829_380, "the corrected founder total moved");
    assert_eq!(correct * 10_000 / t::TOTAL_SUPPLY_BLOCH, 5604, "corrected pin is 5604 bps");

    // The corrected constant is the chain's own genesis measurement, truncated
    // to whole BLOCH. Two independent derivations, one number.
    let (_, founder_carry, _, _) = rebuild_carryover();
    let measured_genesis = founder_carry + allocation_total_sat();
    assert_eq!(
        correct,
        measured_genesis / t::SAT_PER_BLOCH,
        "the corrected constant must equal the replayed genesis holding",
    );

    assert_eq!(
        t::FOUNDER_TOTAL_BLOCH,
        27_046_829_380,
        "FOUNDER_TOTAL_BLOCH is no longer the known-wrong value. If it was just \
         corrected to {correct} (5604 bps, 56.05% of the cap): good — now delete \
         this test and update every figure listed under \"Where the wrong number \
         is published\" in docs/LIVE-SUPPLY.md, including apps/site/supply.html \
         and the two docs/audit/CERTIK-* files. If it changed to something else, \
         it is wrong in a new way.",
    );
    assert_eq!(
        t::FOUNDER_TOTAL_BLOCH + omitted,
        correct,
        "the shortfall is exactly the four omitted buckets",
    );

    // The ledger must name the corrected value, so doc and test cannot drift.
    let text = ledger();
    assert!(
        text.contains("56,046,829,380") && text.contains("29,000,000,000"),
        "docs/LIVE-SUPPLY.md must state the corrected total and the shortfall",
    );
}

// ───────────────────────── live: expires ─────────────────────────

/// **The gate that would have caught the drift.** A live measurement is
/// publishable for [`MAX_MEASUREMENT_AGE_DAYS`] days. After that this fails on
/// its own, with no reviewer involved.
#[test]
fn live_measurement_has_not_expired() {
    let text = ledger();
    let age = today_day() - measured_at_day(&text);
    assert!(age >= 0, "docs/LIVE-SUPPLY.md is measured in the future");
    assert!(
        age <= MAX_MEASUREMENT_AGE_DAYS,
        "the live supply figures in docs/LIVE-SUPPLY.md are {age} days old (limit \
         {MAX_MEASUREMENT_AGE_DAYS}). Re-measure per that file's \"How to re-derive it\" \
         and update the table and `measured_at` together. Do not raise the limit.",
    );
}

/// No live figure may be published anywhere but the ledger. The two documents
/// that carried the stale number are checked by name, because they are the two
/// that were wrong.
#[test]
fn no_document_republishes_a_live_balance() {
    // The genesis figure, in the grouped form the prose used. Any document
    // other than the ledger printing it is republishing a measurement.
    const GENESIS_FIGURE: &str = "56,046,829,380";
    // Prose wraps, so the qualifier has to be *adjacent*, not on the same
    // line. A window is what a reader actually takes in; a line is not.
    const WINDOW: usize = 4;
    let root = repo_root();
    for rel in ["docs/PROJECT-STATUS.md", "SECURITY.md", "README.md"] {
        let p = root.join(rel);
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(GENESIS_FIGURE) {
                continue;
            }
            let lo = i.saturating_sub(WINDOW);
            let hi = (i + WINDOW + 1).min(lines.len());
            let window = lines[lo..hi].join("\n");
            assert!(
                window.contains("at genesis")
                    || window.contains("right at genesis")
                    || window.contains("docs/LIVE-SUPPLY.md")
                    || window.contains("LIVE-SUPPLY.md"),
                "{rel}:{} republishes {GENESIS_FIGURE} with nothing within {WINDOW} lines \
                 saying it is a genesis figure or pointing at docs/LIVE-SUPPLY.md. That \
                 number has been wrong as a statement of current holdings since epoch \
                 ~1050.\n{window}",
                i + 1,
            );
        }
    }
}

/// Opt-in re-measurement. Set `BLOCH_ARCHIVAL_RPC` to two comma-separated
/// `host:port` archivals (never a validator — the RPC shares a thread with
/// consensus there) and every row of the ledger is re-measured, on both, and
/// must agree exactly.
#[test]
fn live_ledger_still_holds_on_two_archivals() {
    let Ok(spec) = std::env::var("BLOCH_ARCHIVAL_RPC") else {
        eprintln!("BLOCH_ARCHIVAL_RPC unset — skipping the online re-measurement");
        return;
    };
    let hosts: Vec<&str> = spec.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    assert_eq!(hosts.len(), 2, "BLOCH_ARCHIVAL_RPC needs exactly two hosts: one node is not a corroboration");

    let text = ledger();
    let mut checked = 0usize;
    for row in ledger_rows(&text) {
        let script_hash = format!("{}{}", row.h160, "0".repeat(24));
        let mut seen: Vec<(u128, u64)> = Vec::new();
        for h in &hosts {
            seen.push(getbalance(h, &script_hash));
        }
        assert_eq!(seen[0], seen[1], "the two archivals disagree about {}", row.h160);
        assert_eq!(
            (row.balance_sat, row.utxos),
            seen[0],
            "docs/LIVE-SUPPLY.md is stale for {}: published {} sat / {} utxos, the chain says \
             {} sat / {} utxos",
            row.h160, row.balance_sat, row.utxos, seen[0].0, seen[0].1,
        );
        checked += 1;
    }
    assert!(checked > 0, "no rows were re-measured");
    eprintln!("re-measured {checked} script hashes against {hosts:?} — ledger holds");
}

/// A single JSON-RPC `getbalance`, over a raw socket. No HTTP client is worth a
/// dependency for one POST, and this test must not add one to the node crate.
fn getbalance(host: &str, script_hash: &str) -> (u128, u64) {
    use std::io::{Read, Write};
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getbalance","params":["{script_hash}"]}}"#
    );
    let mut s = std::net::TcpStream::connect(host).unwrap_or_else(|e| panic!("connect {host}: {e}"));
    s.set_read_timeout(Some(std::time::Duration::from_secs(60))).unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    (field(&resp, "\"balance_sat\":\""), field(&resp, "\"utxo_count\":"))
}

fn field<T: std::str::FromStr>(resp: &str, key: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    let at = resp.find(key).unwrap_or_else(|| panic!("no {key} in RPC response: {resp}"));
    let rest = &resp[at + key.len()..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().expect("RPC field is not a number")
}
