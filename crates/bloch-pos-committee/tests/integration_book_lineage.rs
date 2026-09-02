//! **The Exchange Integration Book's claims, bound to the tree the fleet
//! actually runs — not to whatever branch the book was written on.**
//!
//! `integration_book_claims.rs` pins the book's *numbers* against the
//! constants in this crate. This file pins something that file structurally
//! cannot: **which tree those constants were read from.**
//!
//! ## Why this file exists
//!
//! On 2026-09-01 a check of `REJECTION_TTL_SLOTS` against `main` concluded the
//! mempool rejection cache "is not in the released binary" and that there is
//! "no bar at all". Both statements went into partner-facing text. Both are
//! false: the constant is at `engine.rs:178` on the fleet commit
//! `46133196` *and* on the published tag `g4-node-20260901` (`7a83ca89`). It
//! is absent only on `main`.
//!
//! That was not a careless reading. It was a correct reading of the wrong
//! tree, and nothing in the repository objected, because:
//!
//! - `main` does **not** descend from the fleet commit. Six commits are
//!   missing from it, including `47f7644b`, which carries four consensus
//!   corrections.
//! - The book *and* `integration_book_claims.rs` both live on a branch that
//!   contains neither the fleet commit nor the release tag. A source-reading
//!   test added there reads an `engine.rs` with no rejection cache in it and
//!   cheerfully confirms the false claim.
//!
//! So the pinning harness could not have caught this, and adding more
//! assertions to it in place would not have helped. The missing assertion is
//! about **provenance**: every claim the book makes about "the released
//! binary" has to be checked against the commit that was actually released.
//!
//! ## What this file asserts
//!
//! Each test reads a blob out of the **release tag** by object id, using git,
//! rather than trusting the working tree it happens to be compiled in. That is
//! the whole point: the working tree is the thing under suspicion.
//!
//! `vesting_is_not_enforced` (`bloch-pos-node/src/genesis.rs`) is the
//! precedent for a test that reads source text and fails when a published
//! claim stops being true. This extends the idea one level out, to the
//! question of *which* source text.
//!
//! ## Reading a failure here
//!
//! A failure is not a bug in this file. It means the Integration Book is
//! currently telling an exchange something the released binary does not
//! support. The fix is to correct the book — and, where a test names a source
//! line, to correct that too — in the same commit, per
//! `docs/integration/CONSENSUS-CHANGELOG-DISCIPLINE.md`.
//!
//! Several of these are **red on the branch this file was written on**, by
//! construction. That is the finding, not a broken test.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The published release: tag `g4-node-20260901`. This is the binary an
/// integrator downloads, and the only tree the book may describe as "released".
const RELEASE_TAG: &str = "7a83ca8984266f4937e380d06de2afb984de96ff";

/// The commit the fleet actually runs. The release tag is a descendant of it
/// (via the merge `65608807`, "os documentos corrigidos do main SOBRE a
/// linhagem da frota"). Any tree that does not contain this commit is missing
/// four consensus corrections and is not what the network is running.
const FLEET_COMMIT: &str = "46133196fe481f41ce52881a276e28b8eda18f4b";

const BOOK: &str = "docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md";

fn repo_root() -> PathBuf {
    // .../crates/bloch-pos-committee -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is two levels below the repository root")
        .to_path_buf()
}

/// Run git in the repository, returning stdout. Panics with the stderr on
/// failure — a test that cannot reach history must fail loudly, never quietly
/// pass, because "I could not check" is exactly the state that produced the
/// error this file exists to catch.
fn git(args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("could not run git {args:?}: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("git emitted non-UTF-8")
}

/// True when `ancestor` is reachable from `descendant`.
fn contains(descendant: &str, ancestor: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .status()
        .expect("git merge-base is runnable")
        .success()
}

/// A file as it exists **in the release**, not as it exists here.
fn released_file(path: &str) -> String {
    git(&["show", &format!("{RELEASE_TAG}:{path}")])
}

fn book_text() -> String {
    std::fs::read_to_string(repo_root().join(BOOK))
        .unwrap_or_else(|e| panic!("{BOOK} is unreadable: {e}"))
}

/// Every line of the book carrying a commit anchor of the form `@ <sha>`,
/// returned as (1-based line number, the anchor).
fn book_anchors() -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (i, line) in book_text().lines().enumerate() {
        // Anchors appear as "main @ e4083f9" and "`main` @ `e4083f9`".
        for (pos, _) in line.match_indices('@') {
            let rest: String = line[pos + 1..]
                .chars()
                .skip_while(|c| c.is_whitespace() || *c == '`')
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if rest.len() >= 7 {
                found.push((i + 1, rest));
            }
        }
    }
    found
}

/// **The book may only claim to describe a tree that contains what the fleet
/// runs.**
///
/// This is the assertion whose absence let a check against `main` be written
/// up as a statement about the released binary. `main` does not descend from
/// the fleet commit, so a claim anchored there is a claim about a tree the
/// network is not running — regardless of how carefully the claim itself was
/// verified.
#[test]
fn book_anchors_name_a_tree_that_contains_what_the_fleet_runs() {
    let anchors = book_anchors();
    assert!(
        !anchors.is_empty(),
        "{BOOK} states no commit anchor at all. An integration document that \
         does not say which commit it describes cannot be audited, and an \
         unauditable claim is how the rejection-cache error shipped."
    );

    let mut bad = Vec::new();
    let lines: Vec<&str> = book_text().lines().map(|l| l.to_string().leak() as &str).collect();
    for (line, anchor) in &anchors {
        // A commit may be named as history — "the revision that was wrong was
        // checked against X" — provided the text says so on the same line. The
        // escape hatch is deliberate: naming a non-release commit is allowed,
        // naming one *silently* is not.
        let l = lines[line - 1].to_ascii_lowercase();
        if l.contains("not the released lineage") || l.contains("superseded") {
            continue;
        }
        if !contains(anchor, FLEET_COMMIT) {
            bad.push(format!(
                "  {BOOK}:{line} anchors on {anchor}, which does NOT contain \
                 the fleet commit {}",
                &FLEET_COMMIT[..8]
            ));
        }
    }

    assert!(
        bad.is_empty(),
        "The Integration Book describes itself as covering \"the RELEASED \
         binary\", but anchors on a commit that is not the released lineage:\n\
         {}\n\n\
         The released tree is g4-node-20260901 ({}), which contains the fleet \
         commit {} via the merge 65608807. Re-anchor every line above on the \
         tag, and re-verify the claims that were checked against the old \
         anchor — at least the rejection cache (§6.5, §10) was wrong because \
         of this.",
        bad.join("\n"),
        &RELEASE_TAG[..8],
        &FLEET_COMMIT[..8],
    );
}

/// **The rejection cache is in the released binary.** The book says it is not.
///
/// This is the error, in an assertion. It reads `engine.rs` out of the release
/// tag rather than out of the working tree, because on the branch the book
/// lives on the working tree's `engine.rs` genuinely has no rejection cache —
/// which is precisely how the false claim survived review.
#[test]
fn the_rejection_cache_is_in_the_released_binary() {
    let engine = released_file("crates/bloch-pos-node/src/engine.rs");
    assert!(
        engine.contains("const REJECTION_TTL_SLOTS"),
        "REJECTION_TTL_SLOTS is absent from engine.rs at the release tag {}. \
         If this constant was genuinely removed from the release, this test \
         and the Integration Book must both be rewritten — but check the tag \
         is right before believing it.",
        &RELEASE_TAG[..8]
    );

    let book = book_text();
    let mut offending = Vec::new();
    for (i, line) in book.lines().enumerate() {
        let l = line.to_ascii_lowercase();
        let denies_release = l.contains("not in the released binary")
            || l.contains("[unreleased]")
            || (l.contains("rejection cache") && l.contains("absent"))
            || l.contains("| absent |");
        let about_the_cache = l.contains("rejection cache")
            || l.contains("rejection_ttl_slots")
            || l.contains("cache-recusa");
        if denies_release && about_the_cache {
            offending.push(format!("  {BOOK}:{} {}", i + 1, line.trim()));
        }
    }

    assert!(
        offending.is_empty(),
        "The Integration Book tells an exchange the mempool rejection cache is \
         not in the released binary. It is: `const REJECTION_TTL_SLOTS: u64 = \
         128` at crates/bloch-pos-node/src/engine.rs:178, on the release tag \
         {} AND on the fleet commit {}. It is absent only on `main`, which is \
         not the fleet lineage.\n\n\
         Offending lines:\n{}\n\n\
         Telling an integrator there is \"no bar at all\" would be materially \
         false: a refused transaction is barred from re-entering the mempool \
         for 128 slots (~64 minutes), and a client that resubmits immediately \
         will be silently dropped for an hour.",
        &RELEASE_TAG[..8],
        &FLEET_COMMIT[..8],
        offending.join("\n"),
    );
}

/// **The released RPC source must not still promise a slashing cost.**
///
/// Casper's guarantee is that reverting a finalised checkpoint burns at least
/// a third of the stake. On Genesis-4 nothing can be slashed: wire tag `0x05`
/// is refused unconditionally by `PosTransaction::from_canonical_bytes`, and
/// there is no activation constant to arm. The doc comment an integrator reads
/// in the released source still asserts the guarantee anyway.
#[test]
fn the_released_rpc_source_does_not_promise_a_slashing_backed_finality() {
    let rpc = released_file("crates/bloch-pos-node/src/rpc.rs");

    let mut still_promised = Vec::new();
    for (i, line) in rpc.lines().enumerate() {
        if line.contains("one third of the total stake is slashed")
            || line.contains("Credit here")
        {
            still_promised.push(format!("  rpc.rs:{} {}", i + 1, line.trim()));
        }
    }

    assert!(
        still_promised.is_empty(),
        "The released binary's own source ({}) still tells a reader that a \
         finalised checkpoint is backed by a slashing cost, and still says \
         \"Credit here\":\n{}\n\n\
         No stake on Genesis-4 can be slashed. Slashing evidence rides on wire \
         tag 0x05, and crates/bloch-pos-committee/src/transition.rs:782 returns \
         TxDecodeError::EvidenceNotDecodable for that tag unconditionally, with \
         no gate — there is no SLASHING_EVIDENCE_ACTIVATION_EPOCH to arm. A \
         retraction exists in the working tree but is not in anything \
         published, so this text is what an integrator reading the release \
         actually sees.",
        &RELEASE_TAG[..8],
        still_promised.join("\n"),
    );
}

/// **The checklist must not contradict the settlement section it summarises.**
///
/// The settlement guarantee was retracted twice — `de1a1056` took out the
/// prose, `b354453c` took out the table row that still said *credit*. The
/// checklist bullet was missed both times, so the last thing an integrator
/// reads is the instruction the rest of the page spends two sections
/// withdrawing.
#[test]
fn the_checklist_does_not_reinstate_the_retracted_credit_rule() {
    let book = book_text();

    // Only look inside the checklist; §5 is allowed — required, in fact — to
    // discuss crediting on `finalized` at length.
    let checklist: Vec<(usize, &str)> = book
        .lines()
        .enumerate()
        .skip_while(|(_, l)| !l.to_ascii_lowercase().contains("integration checklist"))
        .map(|(i, l)| (i + 1, l))
        .collect();
    assert!(
        !checklist.is_empty(),
        "{BOOK} has no integration checklist section to check"
    );

    let mut bare = Vec::new();
    for (line_no, line) in &checklist {
        let l = line.to_ascii_lowercase();
        if !l.trim_start().starts_with("- [ ]") || !l.contains("credit on") {
            continue;
        }
        // A compliant bullet has to carry the margin or the two-node rule with
        // it; "credit on finalized" on its own is the retracted instruction.
        let carries_the_caveat = l.contains("margin")
            || l.contains("two independent")
            || l.contains("past")
            || l.contains("not sufficient");
        if !carries_the_caveat {
            bare.push(format!("  {BOOK}:{line_no} {}", line.trim()));
        }
    }

    assert!(
        bare.is_empty(),
        "The checklist still instructs an integrator to credit on `finalized`, \
         which §5 of the same document retracts:\n{}\n\n\
         §5 says finality here is economic, not cryptographic; that `finalized` \
         is not network-unique; and that it is not a latch and can move \
         backwards. The checklist is the part an integrator implements from. \
         Either carry the margin and the two-node rule into the bullet, or \
         remove it.",
        bare.join("\n"),
    );
}

/// **The harness that the book says pins it must exist in the released tree.**
///
/// The book tells an exchange that "every number in this document is now
/// pinned by a test" and that moving a published constant "is a CI failure".
/// That assurance is only worth anything if the test is in the tree that CI
/// builds and that the release was cut from.
#[test]
fn the_pinning_harness_the_book_cites_exists_in_the_release() {
    let cited = "crates/bloch-pos-committee/tests/integration_book_claims.rs";
    let book = book_text();

    // The test only bites while the book actually makes the promise. There are
    // therefore two honest ways to go green: land the harness on the release
    // lineage, or stop telling an exchange that CI guards these numbers.
    let promises_ci = book.contains("integration_book_claims.rs")
        && (book.contains("CI failure") || book.contains("is now pinned by a test"));
    if !promises_ci {
        return;
    }

    let present = Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .args(["cat-file", "-e", &format!("{RELEASE_TAG}:{cited}")])
        .status()
        .expect("git cat-file is runnable")
        .success();

    assert!(
        present,
        "{BOOK} promises an exchange that every published number is pinned by \
         {cited} and that moving a constant is a CI failure. That file does \
         not exist at the release tag {}, nor on `main`. It exists only on the \
         branch the book was written on — which is also the branch that does \
         not contain the fleet commit. So the assurance covers no released \
         tree, and the one class of error it was created to prevent (a \
         constant read from the wrong lineage) is the one it cannot see.\n\n\
         Two ways to fix this, both honest: land the harness on the release \
         lineage and cut a tag that carries it, or withdraw the CI promise \
         from the book. Do not leave the promise standing unbacked.",
        &RELEASE_TAG[..8]
    );
}

/// **No provisional wire tag may appear in partner-facing text.**
///
/// The released tag space is `0x01`–`0x06`. `0x07` and `0x08` exist only in
/// worktrees, behind `FUNDED_STAKE_ACTIVATION_EPOCH`, and their numbering is
/// contested. A tag number printed in a partner document is a number an
/// integrator will encode, and renumbering it later is a silent wire break.
///
/// This one is **green today**, and is here to keep it that way.
#[test]
fn no_provisional_wire_tag_reaches_partner_facing_text() {
    let codec = released_file("crates/bloch-pos-committee/src/transition.rs");

    // The released decoder's arms, as they appear in `from_canonical_bytes`.
    for tag in ["0x01 =>", "0x02 =>", "0x03 =>", "0x04 =>", "0x05 =>", "0x06 =>"] {
        assert!(
            codec.contains(tag),
            "the released decoder has no arm `{tag}`; the wire tag space this \
             test freezes has changed and the Integration Book §6.1 must be \
             re-read before this test is edited"
        );
    }
    for tag in ["0x07 =>", "0x08 =>"] {
        assert!(
            !codec.contains(tag),
            "wire tag `{tag}` is now in the released decoder. Until its \
             numbering is settled it must still not appear in partner-facing \
             text; if it has shipped, say so deliberately rather than by \
             letting this test lapse."
        );
    }

    let partner_facing = [
        BOOK,
        "docs/integration/BLOCH-EXCHANGE-INTEGRATION.md",
        "docs/integration/CONSENSUS-CHANGELOG-DISCIPLINE.md",
    ];
    let mut leaked = Vec::new();
    for doc in partner_facing {
        let path = repo_root().join(doc);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if line.contains("0x07") || line.contains("0x08") {
                leaked.push(format!("  {doc}:{} {}", i + 1, line.trim()));
            }
        }
    }

    assert!(
        leaked.is_empty(),
        "A provisional wire tag appears in partner-facing text:\n{}\n\n\
         The released space is 0x01-0x06 (transition.rs::from_canonical_bytes). \
         0x07 and 0x08 exist only on unreleased branches and are contested. An \
         integrator who encodes a tag number we later renumber gets a silent \
         wire break, not an error.",
        leaked.join("\n"),
    );
}

/// **`-32008` is not one verdict, and the book presents it as one.**
///
/// The released engine returns `TX_REFUSED` from two arms that ask the client
/// for opposite behaviour:
///
/// - `Refusal::Invalid` — terminal. *"retrying the same bytes will not help"*.
/// - `Refusal::PreviouslyRefused { until_slot }` — **retryable**. *"barred
///   until slot N … If the parent is still pending, resubmit after it
///   confirms."*
///
/// The second is the rejection cache the book calls unreleased. A client that
/// implements the book's `-32008` row — "never resubmit these bytes" — drops
/// forever a transaction that was only barred for 64 minutes, typically one
/// whose parent had not landed yet. Nothing but the English message
/// distinguishes the two.
#[test]
fn the_two_meanings_of_32008_are_disclosed() {
    let engine = released_file("crates/bloch-pos-node/src/engine.rs");

    assert!(
        engine.contains("Err(Refusal::PreviouslyRefused { until_slot }) => Err(RpcError::new("),
        "the retryable arm of TX_REFUSED is gone from the released engine; if \
         -32008 now has a single meaning, simplify the book's §3.9 row and \
         retire this test deliberately"
    );
    assert!(
        engine.contains("Err(Refusal::Invalid(why)) => Err(RpcError::new("),
        "the terminal arm of TX_REFUSED is gone from the released engine"
    );

    // Both arms carry the same code. That is the hazard.
    let refused_arms = engine.matches("rpc::TX_REFUSED").count();
    assert!(
        refused_arms >= 2,
        "expected at least two TX_REFUSED emission sites in the released \
         engine, found {refused_arms}"
    );

    let book = book_text();
    let row = book
        .lines()
        .find(|l| l.contains("-32008") && l.contains('|'))
        .unwrap_or_else(|| panic!("{BOOK} has no -32008 row in its error table"));

    let admits_retry = row.to_ascii_lowercase().contains("two meanings")
        || row.to_ascii_lowercase().contains("read the message")
        || row.to_ascii_lowercase().contains("barred");
    assert!(
        admits_retry,
        "{BOOK} presents -32008 as a single terminal verdict:\n  {}\n\n\
         The released engine emits it from two arms with opposite remedies \
         (engine.rs, Refusal::Invalid vs Refusal::PreviouslyRefused). Only the \
         message text separates them. A client that follows this row will \
         permanently drop transactions that were barred for 128 slots because \
         their parent had not confirmed yet.",
        row.trim()
    );
}

/// **The fifth gate is inert, not dead — and the book said dead.**
///
/// `ANCESTRY_SEED_ACTIVATION_EPOCH` is `u64::MAX`, and a previous revision
/// concluded from that, plus a stale doc comment, that it was unreferenced.
/// It is read on two live consensus paths, and being closed is exactly what
/// pins the committee-seed look-ahead to 0 today.
#[test]
fn the_ancestry_seed_gate_is_inert_but_not_dead() {
    let transition = released_file("crates/bloch-pos-committee/src/transition.rs");
    let engine = released_file("crates/bloch-pos-node/src/engine.rs");

    let live_sites = [
        ("transition.rs", &transition, "epoch < crate::params::ANCESTRY_SEED_ACTIVATION_EPOCH"),
        (
            "engine.rs",
            &engine,
            "epoch < bloch_pos_committee::params::ANCESTRY_SEED_ACTIVATION_EPOCH",
        ),
    ];
    for (name, text, needle) in live_sites {
        assert!(
            text.contains(needle),
            "{name} in the release no longer reads ANCESTRY_SEED_ACTIVATION_EPOCH. \
             If the look-ahead really was made unconditional, the book's §1.2 \
             correction should be revisited — but check the tag, not `main`."
        );
    }

    // Paragraph-scoped, not line-scoped. The claim that caught us out spread
    // the constant's name and the word "dead" across three lines, and a
    // line-local check walked straight past it.
    let book = book_text();
    let mut wrong = Vec::new();
    let mut para_start = 1usize;
    let mut para: Vec<&str> = Vec::new();
    let mut paragraphs: Vec<(usize, String)> = Vec::new();
    for (i, line) in book.lines().enumerate() {
        if line.trim().is_empty() {
            if !para.is_empty() {
                paragraphs.push((para_start, para.join("\n")));
                para.clear();
            }
            para_start = i + 2;
        } else {
            if para.is_empty() {
                para_start = i + 1;
            }
            para.push(line);
        }
    }
    if !para.is_empty() {
        paragraphs.push((para_start, para.join("\n")));
    }

    for (start, text) in &paragraphs {
        let l = text.to_ascii_lowercase();
        if !l.contains("ancestry_seed") {
            continue;
        }
        // A correction is allowed to quote the wording it withdraws.
        if l.contains("revision said") || l.contains("correction") {
            continue;
        }
        if l.contains("gates nothing") || l.contains("unreferenced") || l.contains("is dead") {
            wrong.push(format!("  {BOOK}:{start} (paragraph) {}", text.trim()));
        }
    }
    assert!(
        wrong.is_empty(),
        "{BOOK} describes ANCESTRY_SEED_ACTIVATION_EPOCH as dead or \
         unreferenced:\n{}\n\n\
         In the release it is read at transition.rs:1608 and engine.rs:946. \
         Because it is u64::MAX both pin the seed look-ahead to 0, so the \
         constant is load-bearing by being closed. Two source doc comments \
         (params.rs:323-334, transition.rs:1569-1572) claim it was removed; \
         they are stale and the code above them is authoritative.",
        wrong.join("\n"),
    );
}

/// **`getcapabilities` is not in the release, and the book tells integrators to
/// build on it.**
///
/// This is the rejection-cache error with the sign flipped. There, a released
/// feature was described as unreleased. Here, an **unreleased** method is
/// described as the first call a client should make — §3.1 says "Call this
/// first" and "branch your client on `getcapabilities`, not on the tables in
/// this document", and the checklist repeats it.
///
/// The method exists only on the branch this document is maintained on. It is
/// absent from the release tag, from the fleet commit and from `main`, and
/// both public archivals answer `-32601` (probed 2026-09-01). A client written
/// to the checklist fails on its first call to every node that exists.
#[test]
fn getcapabilities_is_not_promised_as_live_while_it_is_unreleased() {
    let rpc = released_file("crates/bloch-pos-node/src/rpc.rs");
    let in_release = rpc.contains("\"getcapabilities\" =>");

    let book = book_text();
    let mut promises = Vec::new();
    for (i, line) in book.lines().enumerate() {
        if !line.contains("getcapabilities") {
            continue;
        }
        let l = line.to_ascii_lowercase();
        // A line that marks it unreleased, or that explains its absence, is
        // fine. A line that instructs the reader to call it is not.
        if l.contains("[unreleased]") || l.contains("-32601") || l.contains("not in the release") {
            continue;
        }
        // A correction is allowed to quote the instruction it withdraws.
        if l.contains("revision") || l.contains("correction") || l.contains("told you") {
            continue;
        }
        if l.contains("call this first")
            || l.contains("call `getcapabilities` at connect")
            || l.contains("branch your client on")
        {
            promises.push(format!("  {BOOK}:{} {}", i + 1, line.trim()));
        }
    }

    if in_release {
        // It shipped; the instruction is then correct and there is nothing to
        // police here.
        return;
    }

    assert!(
        promises.is_empty(),
        "{BOOK} instructs an integrator to call `getcapabilities` and to branch \
         on it, but the method is NOT in the released binary:\n{}\n\n\
         `\"getcapabilities\" =>` is absent from rpc.rs at the release tag {}, at \
         the fleet commit {} and on `main`. It exists only on the branch this \
         document is maintained on. Both public archivals answer -32601 \
         (probed 2026-09-01), which is exactly what the released dispatch does \
         for an unknown method.\n\n\
         This is the rejection-cache mistake inverted: there a released feature \
         was called unreleased; here an unreleased method is presented as the \
         first call a client should make. Mark it [UNRELEASED] and tell the \
         reader to build against §3's tables until it ships.",
        promises.join("\n"),
        &RELEASE_TAG[..8],
        &FLEET_COMMIT[..8],
    );
}
