// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The consensus surface may not move without an announcement.**
//!
//! # Why this test exists
//!
//! On 2026-08-22, at epoch 800, the block payload cap doubled from 262,144 to
//! 524,288 bytes and the EIP-1559 byte target doubled with it. No integrator
//! was told. An exchange found it by watching the chain and dated it a day
//! early, because reverse-engineering an activation from block contents is the
//! only tool we left them.
//!
//! Their diagnosis was exact, and it is why this is not cosmetic:
//!
//! > *Conservation is an equality, so a stale fee assumption is a hard
//! > rejection rather than a slow confirm.*
//!
//! `apply_transfer` requires `sum(inputs) == sum(outputs) + fee` exactly. An
//! integrator on a stale parameter does not get slow confirmations. They get a
//! transaction that can never be valid, at any future moment, no matter how
//! long they wait or how often they rebroadcast.
//!
//! # What this test is for, and what it is not for
//!
//! It does NOT verify that the parameters are correct — that is what the
//! consensus suites in `bloch-pos-committee` do. It verifies that
//! `docs/integration/CONSENSUS-PARAMETER-REGISTER.md`, the document an
//! integrator is handed, still describes the binary we ship.
//!
//! The register is prose, and prose cannot go red. That is the whole defect —
//! the same one `published_checksums.rs` was written for one layer down, and
//! it states the rule this test obeys:
//!
//! > *A fact the build system can check must never live only in a file nobody
//! > executes.*
//!
//! # The property being enforced
//!
//! **Shipping a consensus parameter change without an announcement must be
//! difficult, not merely frowned upon.** Concretely, all five of these are red:
//!
//! 1. a constant, wire tag or RPC method in the source with no register row;
//! 2. a register row naming something that is no longer in the source;
//! 3. a register value that disagrees with the linked constant;
//! 4. a row whose gate is FINITE — armed or already passed — carrying the
//!    `N-000` "pre-dates the register" sentinel instead of a notice id;
//! 5. a notice id that does not resolve to a real notice in
//!    `CONSENSUS-CHANGE-NOTICES.md`.
//!
//! Rule 4 is the load-bearing one. Arming a gate flips its value away from
//! `u64::MAX`, which trips rule 3; correcting the register to match then trips
//! rule 4, because the gate is now finite; and satisfying rule 4 requires a
//! notice id that rule 5 forces to exist. There is no ordering of those edits
//! that arms a flag day and leaves the tree green without a written notice.
//!
//! # Deliberate non-goals
//!
//! Values are compared against the **linked** constants, not re-parsed from
//! the source text, so `BLOCK_GAS_TARGET = BLOCK_GAS_LIMIT / 2` is caught when
//! `BLOCK_GAS_LIMIT` moves even though its own expression never changed. The
//! source expression is checked too, as text, so a change from `/ 2` to `/ 4`
//! is named at the site rather than only in the resolved number.
//!
//! This test reads other files and never itself, so the self-match trap
//! documented at `finality.rs:1594` does not apply. It does strip `//` lines
//! from every source it scans, because the prose in those files quotes the
//! identifiers it defines.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ── Locating the tree ───────────────────────────────────────────────────────

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    crate_dir().join("../..").canonicalize().expect("repository root")
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

fn committee_src(file: &str) -> String {
    read(&crate_dir().join("../bloch-pos-committee/src").join(file))
}

fn node_src(file: &str) -> String {
    read(&crate_dir().join("src").join(file))
}

fn register() -> String {
    read(&repo_root().join("docs/integration/CONSENSUS-PARAMETER-REGISTER.md"))
}

fn notices() -> String {
    read(&repo_root().join("docs/integration/CONSENSUS-CHANGE-NOTICES.md"))
}

/// Drop `//` comment lines. Every file scanned here documents its own
/// constants in prose directly above them, so an uncommented scan finds each
/// name several times and a "removed" constant would still appear to exist.
fn code_only(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Reading the register's machine tables ───────────────────────────────────

/// One row of a `<!-- MACHINE-TABLE: name -->` block, cells trimmed and
/// stripped of the backticks the Markdown uses for code spans.
type Row = Vec<String>;

fn table(md: &str, name: &str) -> Vec<Row> {
    let open = format!("<!-- MACHINE-TABLE: {name} -->");
    let start = md
        .find(&open)
        .unwrap_or_else(|| panic!("register has no machine table `{name}`"))
        + open.len();
    let rest = &md[start..];
    let end = rest
        .find("<!-- END-MACHINE-TABLE -->")
        .unwrap_or_else(|| panic!("machine table `{name}` is not closed"));

    rest[..end]
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('|'))
        // Drop the header row and the `|---|---|` separator.
        .filter(|l| !l.contains("---"))
        .skip(1)
        .map(|l| {
            l.trim_matches('|')
                .split('|')
                .map(|c| c.trim().trim_matches('`').to_string())
                .collect::<Row>()
        })
        .collect()
}

// ── The linked values ───────────────────────────────────────────────────────

/// The register's `Value` column, checked against the constant the binary
/// actually compiles. Every constant in the register must appear here; a name
/// that does not resolve is itself a failure, so adding a constant to the
/// source and the register while skipping this table is still red.
fn linked(name: &str) -> Option<u128> {
    use bloch_pos_committee::{fee_market as f, params as p, rewards as r, slashing as sl, staking as st};
    Some(match name {
        // params.rs
        "COMMITTEE_SIZE" => p::COMMITTEE_SIZE as u128,
        "SLOT_SUBCOMMITTEE_SIZE" => p::SLOT_SUBCOMMITTEE_SIZE as u128,
        "SLOTS_PER_EPOCH" => p::SLOTS_PER_EPOCH as u128,
        "SLOT_DURATION_SECS" => p::SLOT_DURATION_SECS as u128,
        "MAX_DRAWS_PER_SLOT" => p::MAX_DRAWS_PER_SLOT as u128,
        "RANDAO_CHAIN_LENGTH" => p::RANDAO_CHAIN_LENGTH as u128,
        "INACTIVITY_LEAK_THRESHOLD_EPOCHS" => p::INACTIVITY_LEAK_THRESHOLD_EPOCHS as u128,
        "INACTIVITY_LEAK_QUOTIENT" => p::INACTIVITY_LEAK_QUOTIENT,
        "INACTIVITY_LEAK_RECOVERY_QUOTIENT" => p::INACTIVITY_LEAK_RECOVERY_QUOTIENT as u128,
        "MIN_QUORUM_DENOMINATOR_NUM" => p::MIN_QUORUM_DENOMINATOR_NUM,
        "MIN_QUORUM_DENOMINATOR_DEN" => p::MIN_QUORUM_DENOMINATOR_DEN,
        "LEAKED_ROSTER_ACTIVATION_EPOCH" => p::LEAKED_ROSTER_ACTIVATION_EPOCH as u128,
        "TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH" => {
            p::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH as u128
        }
        "BLOCK_BYTES_V2_ACTIVATION_EPOCH" => p::BLOCK_BYTES_V2_ACTIVATION_EPOCH as u128,
        "ANCESTRY_SEED_ACTIVATION_EPOCH" => p::ANCESTRY_SEED_ACTIVATION_EPOCH as u128,
        "LEAK_RECOVERY_ACTIVATION_EPOCH" => p::LEAK_RECOVERY_ACTIVATION_EPOCH as u128,

        // fee_market.rs
        "MAX_BLOCK_TX_BYTES" => f::MAX_BLOCK_TX_BYTES as u128,
        "BLOCK_TX_BYTES_TARGET" => f::BLOCK_TX_BYTES_TARGET as u128,
        "MAX_BLOCK_TX_BYTES_V2" => f::MAX_BLOCK_TX_BYTES_V2 as u128,
        "BLOCK_TX_BYTES_TARGET_V2" => f::BLOCK_TX_BYTES_TARGET_V2 as u128,
        "BLOCK_GAS_LIMIT" => f::BLOCK_GAS_LIMIT as u128,
        "BLOCK_GAS_TARGET" => f::BLOCK_GAS_TARGET as u128,
        "GAS_PER_BYTE" => f::GAS_PER_BYTE as u128,
        "TX_FLAT_GAS" => f::TX_FLAT_GAS as u128,
        "HYBRID_SIG_BYTES" => f::HYBRID_SIG_BYTES as u128,
        "HYBRID_VERIFY_INSTRUCTIONS" => f::HYBRID_VERIFY_INSTRUCTIONS as u128,
        "INSTRUCTIONS_PER_GAS" => f::INSTRUCTIONS_PER_GAS as u128,
        "HYBRID_VERIFY_GAS" => f::HYBRID_VERIFY_GAS as u128,
        "SECP256K1_VERIFY_GAS" => f::SECP256K1_VERIFY_GAS as u128,
        "SHIELDED_VERIFY_GAS_PROVISIONAL" => f::SHIELDED_VERIFY_GAS_PROVISIONAL as u128,
        "MILLISAT_PER_SAT" => f::MILLISAT_PER_SAT,
        "MIN_BASE_FEE_MILLISAT_PER_GAS" => f::MIN_BASE_FEE_MILLISAT_PER_GAS,
        "MAX_BASE_FEE_MILLISAT_PER_GAS" => f::MAX_BASE_FEE_MILLISAT_PER_GAS,
        "BASE_FEE_CHANGE_DENOMINATOR" => f::BASE_FEE_CHANGE_DENOMINATOR,

        // staking.rs
        "SUITE_MLDSA65_FALCON1024" => st::SUITE_MLDSA65_FALCON1024 as u128,
        "MLDSA65_PK_BYTES" => st::MLDSA65_PK_BYTES as u128,
        "FALCON1024_PK_BYTES" => st::FALCON1024_PK_BYTES as u128,
        "HYBRID_PK_BYTES" => st::HYBRID_PK_BYTES as u128,
        "MLDSA65_SIG_BYTES" => st::MLDSA65_SIG_BYTES as u128,
        "MIN_DEPOSIT_SAT" => st::MIN_DEPOSIT_SAT,
        "ACTIVATION_DELAY_EPOCHS" => st::ACTIVATION_DELAY_EPOCHS as u128,
        "MAX_ACTIVATIONS_PER_EPOCH" => st::MAX_ACTIVATIONS_PER_EPOCH as u128,
        "EXIT_DELAY_EPOCHS" => st::EXIT_DELAY_EPOCHS as u128,
        "WITHDRAWAL_DELAY_EPOCHS" => st::WITHDRAWAL_DELAY_EPOCHS as u128,

        // slashing.rs
        "SLASH_PROPOSER_EQUIV_BPS" => sl::SLASH_PROPOSER_EQUIV_BPS,
        "SLASH_SURROUND_VOTE_BPS" => sl::SLASH_SURROUND_VOTE_BPS,
        "WHISTLEBLOWER_QUOTIENT" => sl::WHISTLEBLOWER_QUOTIENT,
        "CORRELATION_MULTIPLIER" => sl::CORRELATION_MULTIPLIER,
        "CORRELATION_WINDOW_EPOCHS" => sl::CORRELATION_WINDOW_EPOCHS as u128,

        // rewards.rs
        "BPS" => r::BPS,
        "BASE_FEE_BURN_BPS" => r::BASE_FEE_BURN_BPS,
        "PRIORITY_FEE_PRODUCER_BPS" => r::PRIORITY_FEE_PRODUCER_BPS,
        "MAX_COMMISSION_BPS" => r::MAX_COMMISSION_BPS,
        "MIN_DELEGATION_SAT" => r::MIN_DELEGATION_SAT,

        _ => return None,
    })
}

// ── Scanning the source for `pub const` items ───────────────────────────────

/// Every top-level `pub const NAME: <scalar> = <expr>;` in `src`, as
/// `name -> expression`. Byte-array constants (the `DS_*` tags) are handled
/// separately because their values are not integers.
fn scalar_consts(src: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in code_only(src).lines() {
        let Some(rest) = line.strip_prefix("pub const ") else { continue };
        let Some((name, tail)) = rest.split_once(':') else { continue };
        let Some((ty, expr)) = tail.split_once('=') else { continue };
        let ty = ty.trim();
        // Scalars only. `[u8; 16]` and anything structured is not this table.
        if !matches!(ty, "u16" | "u32" | "u64" | "u128" | "usize") {
            continue;
        }
        let Some(expr) = expr.trim().strip_suffix(';') else { continue };
        out.insert(name.trim().to_string(), expr.trim().to_string());
    }
    out
}

/// Every top-level `pub const NAME: [u8; 16] = <expr>;` — the domain tags.
fn ds_consts(src: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in code_only(src).lines() {
        let Some(rest) = line.strip_prefix("pub const ") else { continue };
        let Some((name, tail)) = rest.split_once(':') else { continue };
        let Some((ty, expr)) = tail.split_once('=') else { continue };
        if ty.trim() != "[u8; 16]" {
            continue;
        }
        let Some(expr) = expr.trim().strip_suffix(';') else { continue };
        out.insert(name.trim().to_string(), expr.trim().to_string());
    }
    out
}

/// The body of a `fn`, by brace matching from its signature.
fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let at = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found — did it move or get renamed?"));
    let rest = &src[at..];
    let open = rest.find('{').expect("a function body");
    let mut depth = 0usize;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[open..open + i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after `{signature}`");
}

// ── Shared assertion helpers ────────────────────────────────────────────────

/// The two-direction set diff. `found` is what the source says, `declared` is
/// what the register says. Either asymmetry is a failure, and the message
/// names the specific items rather than the counts.
fn both_directions(what: &str, found: &BTreeMap<String, String>, declared: &BTreeMap<String, String>) {
    let undeclared: Vec<&String> = found.keys().filter(|k| !declared.contains_key(*k)).collect();
    let phantom: Vec<&String> = declared.keys().filter(|k| !found.contains_key(*k)).collect();

    assert!(
        undeclared.is_empty(),
        "{what}: {} item(s) exist in the source with NO row in \
         docs/integration/CONSENSUS-PARAMETER-REGISTER.md:\n{}\n\n\
         Add a row. If this is a consensus-visible change, it also needs a notice in \
         CONSENSUS-CHANGE-NOTICES.md and the notice's id in the row's Notice column.",
        undeclared.len(),
        undeclared.iter().map(|n| format!("  + {n}")).collect::<Vec<_>>().join("\n"),
    );

    assert!(
        phantom.is_empty(),
        "{what}: {} row(s) in the register name something that is NOT in the source \
         any more:\n{}\n\n\
         If it was removed or renamed, that is a breaking change for every integrator \
         who reads it. Write the notice first, then update the register.",
        phantom.len(),
        phantom.iter().map(|n| format!("  - {n}")).collect::<Vec<_>>().join("\n"),
    );

    for (name, expr) in found {
        let want = &declared[name];
        assert_eq!(
            expr, want,
            "{what}: the source expression for `{name}` changed.\n  \
             register says: {want}\n  source says:   {expr}\n\n\
             Update the register, and issue a notice if this moves a value.",
        );
    }
}

/// Every referenced notice id must resolve to a heading in the notices file,
/// and `N-000` is the sentinel that resolves to the "pre-dates the register"
/// entry.
fn assert_notice_exists(id: &str, notices: &str, context: &str) {
    assert!(
        notices.contains(&format!("## {id}")),
        "{context} cites notice `{id}`, which has no `## {id}` entry in \
         docs/integration/CONSENSUS-CHANGE-NOTICES.md.\n\n\
         A register row may not point at a notice that was never written.",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// The tests
// ═══════════════════════════════════════════════════════════════════════════

/// `params.rs` and the register agree on every scalar consensus constant.
#[test]
fn params_match_the_register() {
    let src = committee_src("params.rs");
    let found = scalar_consts(&src);

    // Anti-vacuity: a moved or renamed file must FAIL, not pass by finding
    // nothing. This is the idiom `vesting_is_not_enforced` uses and the reason
    // it cannot be defeated by relocating the crate.
    assert!(
        found.len() >= 16,
        "scanned params.rs and found only {} scalar constants — this test cannot \
         pass by looking at nothing",
        found.len(),
    );

    let declared: BTreeMap<String, String> = table(&register(), "params")
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone()))
        .collect();

    both_directions("params.rs", &found, &declared);
}

/// The same, for the fee-market and capacity constants — the ones the
/// 2026-08-22 incident actually moved.
#[test]
fn fee_market_matches_the_register() {
    let src = committee_src("fee_market.rs");
    let found = scalar_consts(&src);
    assert!(
        found.len() >= 18,
        "scanned fee_market.rs and found only {} constants — refusing to pass vacuously",
        found.len(),
    );

    let declared: BTreeMap<String, String> = table(&register(), "fee_market")
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone()))
        .collect();

    both_directions("fee_market.rs", &found, &declared);
}

/// Staking, slashing and reward constants, which bind anyone who credits a
/// customer's stake.
#[test]
fn validator_economics_match_the_register() {
    let mut found = BTreeMap::new();
    for (module, src) in [
        ("staking", committee_src("staking.rs")),
        ("slashing", committee_src("slashing.rs")),
        ("rewards", committee_src("rewards.rs")),
    ] {
        for (name, expr) in scalar_consts(&src) {
            // `SAT_PER_BLOCH` is re-exported into staking from tokenomics_v4;
            // it is registered there, not here.
            if name == "SAT_PER_BLOCH" {
                continue;
            }
            found.insert(name, format!("{module}\u{1}{expr}"));
        }
    }
    assert!(
        found.len() >= 20,
        "scanned staking/slashing/rewards and found only {} constants — refusing to \
         pass vacuously",
        found.len(),
    );

    let declared: BTreeMap<String, String> = table(&register(), "staking")
        .into_iter()
        .map(|r| (r[0].clone(), format!("{}\u{1}{}", r[1], r[2])))
        .collect();

    both_directions("staking/slashing/rewards", &found, &declared);
}

/// **The register's numbers are the binary's numbers.**
///
/// The text checks above catch a renamed or re-expressed constant. This
/// catches the case they cannot: a value that moved without its expression
/// changing, because the expression names another constant that moved
/// (`BLOCK_GAS_TARGET = BLOCK_GAS_LIMIT / 2`).
#[test]
fn every_registered_value_equals_the_compiled_constant() {
    let md = register();
    let mut checked = 0usize;

    for (which, value_col) in [("params", 2), ("fee_market", 2), ("staking", 3)] {
        for row in table(&md, which) {
            let name = &row[0];
            let want: u128 = row[value_col].parse().unwrap_or_else(|e| {
                panic!("register row `{name}` has an unparseable Value `{}`: {e}", row[value_col])
            });
            let got = linked(name).unwrap_or_else(|| {
                panic!(
                    "register row `{name}` has no entry in this test's `linked()` table.\n\n\
                     Every registered constant must be linked so its VALUE is checked, not \
                     only its name. Add an arm to `linked()`.",
                )
            });
            assert_eq!(
                got, want,
                "\n\n*** `{name}` HAS CHANGED VALUE ***\n  \
                 register (what integrators were told): {want}\n  \
                 binary   (what the chain enforces):    {got}\n\n\
                 This is a consensus-visible change. Before updating the register:\n  \
                 1. write the notice in docs/integration/CONSENSUS-CHANGE-NOTICES.md\n  \
                 2. put its id in this row's Notice column\n  \
                 3. send it to integrators with the lead time in that file's section 2\n\n\
                 Conservation is an equality: an integrator on the old value does not get \
                 slow confirmations, they get transactions that can never be valid.",
            );
            checked += 1;
        }
    }

    assert!(checked >= 50, "only {checked} values checked — refusing to pass vacuously");
}

/// The domain-separation tags, which enter signing roots. A change here
/// invalidates every signature an integrator can produce.
#[test]
fn domain_tags_match_the_register() {
    let found = ds_consts(&committee_src("params.rs"));
    assert!(
        found.len() >= 14,
        "found only {} DS_* tags — refusing to pass vacuously",
        found.len(),
    );

    let declared: BTreeMap<String, String> = table(&register(), "ds_tags")
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone()))
        .collect();

    both_directions("domain-separation tags", &found, &declared);
}

/// Transaction wire tags: the first byte of `canonical_bytes`.
#[test]
fn transaction_wire_tags_match_the_register() {
    let src = committee_src("transition.rs");
    let body = fn_body(&src, "pub fn canonical_bytes(&self)");

    // `b.push(0xNN);` at the head of each variant's arm. The nested pushes
    // inside the 0x05 evidence encoding are sub-tags of an already-tagged
    // transaction, not top-level discriminants, so the set — not the
    // multiset — is what is pinned.
    let mut found = BTreeMap::new();
    for line in code_only(body).lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("b.push(0x") {
            if let Some(hex) = rest.strip_suffix(");") {
                found.insert(format!("0x{}", hex.to_lowercase()), String::new());
            }
        }
    }
    assert!(
        found.len() >= 6,
        "found only {} transaction wire tags in canonical_bytes — refusing to pass \
         vacuously",
        found.len(),
    );

    let declared: BTreeMap<String, String> = table(&register(), "wire_tags")
        .into_iter()
        .map(|r| (r[0].to_lowercase(), String::new()))
        .collect();

    both_directions("transaction wire tags", &found, &declared);
}

/// Network frame tags. The compiler cannot help here — every dispatch is a
/// `match` on a plain `u8` with a `_ =>` arm — so this is the only thing that
/// notices a tag appearing, disappearing, or changing value.
#[test]
fn frame_tags_match_the_register() {
    let src = code_only(&node_src("net.rs"));
    let mut found = BTreeMap::new();
    for line in src.lines() {
        let Some(rest) = line.strip_prefix("pub const FRAME_") else { continue };
        let Some((name, tail)) = rest.split_once(':') else { continue };
        let Some((_, expr)) = tail.split_once('=') else { continue };
        let Some(expr) = expr.trim().strip_suffix(';') else { continue };
        found.insert(format!("FRAME_{}", name.trim()), expr.trim().to_lowercase());
    }
    assert!(found.len() >= 4, "found only {} FRAME_* tags — refusing to pass vacuously", found.len());

    let declared: BTreeMap<String, String> = table(&register(), "frame_tags")
        .into_iter()
        .map(|r| (r[0].clone(), r[1].to_lowercase()))
        .collect();

    both_directions("network frame tags", &found, &declared);
}

/// **The frozen RPC namespace.** Every method the node answers, in both
/// directions: nothing served that is undocumented, nothing documented that is
/// no longer served.
///
/// Scoped to the body of `route` on purpose. `rpc.rs` also contains a
/// hand-rolled JSON parser full of `"…" =>` arms, and a file-wide scan would
/// swallow them.
#[test]
fn rpc_namespace_matches_the_register() {
    let src = node_src("rpc.rs");
    let body = fn_body(&src, "pub fn route(method: &str");

    let mut found = BTreeMap::new();
    for line in code_only(body).lines() {
        let t = line.trim();
        // Method arms are the only place a quoted lowercase name is followed
        // by `=>` or by `|` (the getutxos/listunspent or-pattern). Argument
        // names like `want_u64(params, 0, "slot")` are followed by `)`.
        if !t.starts_with('"') {
            continue;
        }
        for piece in t.split("=>").next().unwrap_or("").split('|') {
            let p = piece.trim();
            if let Some(inner) = p.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_lowercase()) {
                    found.insert(inner.to_string(), String::new());
                }
            }
        }
    }
    assert!(
        found.len() >= 13,
        "found only {} RPC methods in `route` — refusing to pass vacuously",
        found.len(),
    );

    let declared: BTreeMap<String, String> = table(&register(), "rpc")
        .into_iter()
        .map(|r| (r[0].clone(), String::new()))
        .collect();

    both_directions("RPC namespace", &found, &declared);
}

/// RPC error codes. A client branches on these; a code appearing without
/// warning forces it to guess whether a failure is retryable.
#[test]
fn rpc_error_codes_match_the_register() {
    let src = code_only(&node_src("rpc.rs"));
    let mut found = BTreeMap::new();
    for line in src.lines() {
        let Some(rest) = line.strip_prefix("pub const ") else { continue };
        let Some((name, tail)) = rest.split_once(':') else { continue };
        let Some((ty, expr)) = tail.split_once('=') else { continue };
        if ty.trim() != "i64" {
            continue;
        }
        let Some(expr) = expr.trim().strip_suffix(';') else { continue };
        found.insert(name.trim().to_string(), expr.trim().to_string());
    }
    assert!(
        found.len() >= 9,
        "found only {} RPC error codes — refusing to pass vacuously",
        found.len(),
    );

    let declared: BTreeMap<String, String> = table(&register(), "rpc_errors")
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone()))
        .collect();

    both_directions("RPC error codes", &found, &declared);
}

/// **A gate that is armed must carry a notice.**
///
/// This is the rule that makes the register more than documentation. A gate is
/// ARMED the moment its epoch constant stops being `u64::MAX`, whether that
/// epoch is in the future or already past. From that moment the row may not
/// carry `N-000`, the "pre-dates this register, never announced" sentinel.
///
/// There is no edit order that arms a flag day and leaves the tree green
/// without a written notice: changing the constant breaks
/// `every_registered_value_equals_the_compiled_constant`, and repairing that
/// breaks this.
#[test]
fn an_armed_gate_must_cite_a_notice() {
    let md = register();
    let notices = notices();
    let mut armed_rows = 0usize;

    for (which, gate_col, notice_col) in [("params", 3, 5), ("fee_market", 3, 5)] {
        for row in table(&md, which) {
            let name = &row[0];
            let gate = &row[gate_col];
            let notice = &row[notice_col];

            assert_notice_exists(notice, &notices, &format!("register row `{name}`"));

            // Which activation constant governs this row? `self` means the row
            // IS an activation constant; `—` means it is ungated.
            let gate_value = match gate.as_str() {
                "—" | "-" | "" => continue,
                "self" => linked(name),
                other => linked(other),
            };
            let Some(gate_value) = gate_value else {
                panic!(
                    "register row `{name}` names gate `{gate}`, which is not a constant \
                     this test can link. Gates must be real activation constants.",
                )
            };

            if gate_value == u128::from(u64::MAX) {
                continue; // inert; N-000 is honest here
            }
            armed_rows += 1;

            assert_ne!(
                notice, "N-000",
                "\n\n*** `{name}` IS GATED ON AN ARMED FLAG DAY WITH NO NOTICE ***\n  \
                 gate:  {gate} = {gate_value}\n  \
                 notice: N-000 (the \"pre-dates this register, never announced\" sentinel)\n\n\
                 `N-000` is only honest for the genesis surface and for gates still at \
                 u64::MAX. An armed or already-passed gate is a consensus change that \
                 integrators must be told about.\n\n\
                 Write the notice in docs/integration/CONSENSUS-CHANGE-NOTICES.md and put \
                 its id here. Arming a constant is the founder's decision; announcing it \
                 is not optional.",
            );
        }
    }

    assert!(
        armed_rows >= 7,
        "only {armed_rows} armed-gate rows found — the epoch-800 and epoch-1400 flag days \
         should account for at least seven. Refusing to pass vacuously.",
    );
}

/// Every notice id cited anywhere in the register resolves to a real notice,
/// including in the tables the test above does not walk.
#[test]
fn every_cited_notice_exists() {
    let md = register();
    let notices = notices();
    let mut cited = 0usize;

    for which in
        ["params", "fee_market", "staking", "ds_tags", "wire_tags", "frame_tags", "rpc", "rpc_errors"]
    {
        for row in table(&md, which) {
            let id = row.last().expect("a Notice column");
            assert!(
                id.starts_with("N-"),
                "table `{which}`, row `{}`: last column should be a notice id, got `{id}`",
                row[0],
            );
            assert_notice_exists(id, &notices, &format!("table `{which}` row `{}`", row[0]));
            cited += 1;
        }
    }

    assert!(cited >= 90, "only {cited} notice citations checked — refusing to pass vacuously");
}
