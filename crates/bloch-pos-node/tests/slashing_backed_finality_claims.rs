// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The lock between "we promise a slashing penalty" and "a penalty can be
//! applied".**
//!
//! On 2026-09-01 this node's own RPC documentation told integrators that a
//! finalised checkpoint *"cannot be reverted unless at least one third of the
//! total stake is slashed, which is a bonded, attributable, on-chain cost
//! rather than a probabilistic one"*, and annotated `Finality::Finalized`
//! with **"Credit here."** The public block explorer said reversing a
//! finalised block *"would require burning a third of the bonded stake"*.
//!
//! No stake on Genesis-4 can be slashed. Four independent breaks, any one of
//! them sufficient:
//!
//! 1. `PosTransaction::from_canonical_bytes` returns
//!    `TxDecodeError::EvidenceNotDecodable` for wire tag `0x05`
//!    **unconditionally, with no gate**. The encoder folds the two nested
//!    messages in as the *signing roots* they were signed over — hashes — so
//!    the envelopes are unrecoverable by construction, not by omission.
//! 2. That decoder is the only one on every ingress path: block body
//!    (`engine::body_transactions`), gossip (`p2p.rs`, `net.rs`) and
//!    `sendrawtransaction` (`rpc.rs`). A block carrying evidence is rejected
//!    by every peer; a proposer that included it would produce an unimportable
//!    block.
//! 3. Nothing constructs the transaction outside tests. The node captures an
//!    equivocating pair and prints that the pipeline is not wired.
//! 4. `SLASHING_EVIDENCE_ACTIVATION_EPOCH` does not exist — it is absent, not
//!    set to `u64::MAX`.
//!
//! # Why a test, and why this shape
//!
//! The claim survived in four places at once — a doc comment, a
//! specification, an audit dossier and a web page — because prose does not
//! fail. `vesting_is_not_enforced` (`genesis.rs`) is the precedent: it reads
//! the crate that authorises spends and goes red if the identifier appears.
//!
//! # No machine-readable half on this lineage
//!
//! The retraction as first written also set `slashing_enforced: false` and
//! `finalized_is_a_latch: false` in a `getcapabilities` response. **That
//! release does not exist here.** `g4-node-20260901` serves no
//! `getcapabilities` method — both public archival nodes answer `-32601` — so
//! there is no capability object to guard and none is faked. Every retraction
//! site below is prose, and this test is the only machine-readable thing
//! standing behind it.
//!
//! This file locks the pair **in both directions**, which is the part that
//! matters. Getting them out of step is bad either way round:
//!
//! - **Enforcement absent, promise present** → [`no_text_promises_a_slashing_backed_finality`]
//!   fails. That is today's defect, and the direction it can regress in.
//! - **Enforcement arrives, retraction still standing** → the same test and
//!   [`the_retraction_is_published_wherever_the_promise_was`] both fail, and
//!   say so: once evidence can travel, every retraction here *understates*
//!   the guarantee, which is its own kind of wrong document.
//!
//! So the reachability of the slashing path is measured — by **calling the
//! decoder**, not by grepping for it — and the text is judged against that
//! measurement rather than against a hardcoded expectation.
//!
//! # The contract for writing about slashing
//!
//! A [`PROMISE_PATTERNS`] phrase may appear only inside a **retraction
//! window**: one of [`RETRACTION_MARKERS`] within the preceding
//! [`RETRACTION_WINDOW`] characters (whitespace-normalised). Quoting the old
//! claim in order to withdraw it is fine and expected; asserting it is not.
//! If you are adding a genuine new statement about slashing that trips this,
//! the answer is not to widen the patterns — it is that the sentence needs a
//! marker saying which way it cuts.
//!
//! # Discipline
//!
//! A failure here is not a bug in this file. Either the text regressed, or
//! enforcement landed and the text has to catch up. Do not delete a pattern
//! to get green.

use std::path::{Path, PathBuf};

use bloch_pos_committee::transition::{PosTransaction, TxDecodeError};

/// Phrases that assert a slashing-backed finality guarantee. Whitespace is
/// normalised before matching, so line wrapping cannot hide one.
const PROMISE_PATTERNS: &[&str] = &[
    "one third of the total stake is slashed",
    "one-third of the total stake is slashed",
    "one third of the stake is slashed",
    "one-third-of-stake slashing",
    "third of the bonded stake",
    "burning a third of the bonded stake",
    "credit here",
    "slashing is real",
    "slashing pipeline is live",
    "evidence is a transaction any node can include",
    // The same promise in the passive voice, which is how it survived the
    // first sweep: not "a third is slashed" but "reverting it would require
    // slashing a third".
    "slashing at least a third",
    "detectable and slashable",
    // Irreversibility asserted without naming the penalty. It is the same
    // claim: nothing else on this chain could make a block irreversible.
    "may be treated as irreversible",
    "finalized epoch is irreversible",
    "finalised history can never be reorganised out",
    "finalized history can never be reorganized out",
    "settlement is the finalized: true boolean",
    // "slashing" listed as a shipped, live property of the running chain.
    "staking and slashing",
    // The gap recorded as closed when only its transition half was closed.
    "gap-3 is fixed",
];

/// A promise phrase is permitted within this many normalised characters of one
/// of [`RETRACTION_MARKERS`], on **either** side. Wide enough for a quoted
/// sentence plus its lead-in; far too narrow to launder a fresh assertion
/// several paragraphs from an unrelated retraction.
///
/// Both directions, because a markdown table row cannot put the marker first
/// without mangling the row: the CertiK dossier's check-15 cell states the
/// control and corrects it in the same sentence. Prose should still lead with
/// the withdrawal — a reader who stops early must not stop on the claim.
const RETRACTION_WINDOW: usize = 600;

/// What makes a quotation a withdrawal rather than a claim.
const RETRACTION_MARKERS: &[&str] = &[
    "retraction",
    "retracted",
    "used to read",
    "used to say",
    "used to open",
    "used to be annotated",
    "used to call",
    "corrected 2026-09-01",
    "this section used to",
    "an earlier revision",
];

/// The surfaces that carried the claim, and must therefore carry the
/// withdrawal while the penalty cannot be applied. Each is checked to exist:
/// a renamed file must fail loudly, not silently stop being guarded.
///
/// Every entry is a file that exists at `g4-node-20260901`. Sites that the
/// retraction originally also covered — `docs/VALIDATOR-RUNBOOK.md`,
/// `docs/specs/BLOCH-RPC-STABILITY-V4.md`,
/// `apps/explorer/src/components/corroboration.tsx` and the
/// `tools/validator-ops/` scripts — **do not exist on this lineage** and are
/// deliberately not listed: a site that cannot be checked must not be
/// pretended into this table. Add them here in the same commit that brings
/// those files onto the release lineage.
const RETRACTION_SITES: &[(&str, &str)] = &[
    // The doc comment an integrator reads programmatically, via rustdoc.
    ("crates/bloch-pos-node/src/rpc.rs", "economic by intent and cryptographic by nothing"),
    // The book the exchange integrates from — the document a partner is handed.
    (
        "docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md",
        "no stake can be slashed at all",
    ),
    // Its predecessor, still in the tree and still linked.
    (
        "docs/integration/BLOCH-EXCHANGE-INTEGRATION.md",
        "the equivocation is indeed detectable",
    ),
    // The public block explorer's block page.
    ("apps/explorer/src/pages/G4Block.tsx", "not backed by any slashing penalty"),
    // The website copy source.
    ("docs/site/COPY.md", "cannot be applied"),
    // The V4 RPC specification's own status enum.
    ("docs/specs/BLOCH-RPC-V4.md", "retracted 2026-09-01"),
    // The module every reviewer opens when they hear "slashing".
    ("crates/bloch-pos-committee/src/slashing.rs", "not reachable from the network"),
    // The crate description, which is what `cargo metadata` and any package
    // index would republish.
    ("crates/bloch-pos-committee/Cargo.toml", "unreachable from the network"),
    // The fork-choice doc that claimed finalised history is unreorganisable.
    ("crates/bloch-pos-node/src/engine.rs", "finalized is not a latch"),
    // The security-tooling overview, which listed slashing as shipped.
    ("SECURITY_TOOLING.md", "cannot be applied on the live chain"),
    // The dossier an external auditor reads.
    ("docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md", "reopened 2026-09-01"),
    // The whitepaper chapter that called finality "accountable, slashable".
    ("docs/whitepaper/ED2-CONSENSUS.md", "still with no cost in it"),
    // The plan that recorded GAP-3 as closed on the transition half alone.
    ("docs/PMO-GENESIS4-INTEGRATION-PLAN.md", "gap-3 is not fixed"),
];

/// Extensions worth reading. Everything else in the tree is data or build
/// output and cannot address a reader.
const PROSE_EXTENSIONS: &[&str] = &["rs", "md", "tsx", "ts", "js", "html", "toml", "sh"];

/// Directories that are not this repository's own published word: build
/// output, git internals, vendored packages, and the agent worktrees, which
/// hold whole parallel copies of the tree and would report every finding
/// dozens of times.
const SKIPPED_DIRS: &[&str] = &[".git", ".claude", "target", "node_modules", "dist", "build"];

/// Below this, the walk is broken and this file would pass by reading nothing
/// — the failure mode it exists to prevent. The tree held well over three
/// thousand matching files when this was written.
const MIN_FILES_SCANNED: usize = 400;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root resolves")
}

/// Lowercase, and collapse every whitespace run to a single space, so a
/// sentence broken across lines — or across a `///` prefix, or a markdown
/// blockquote `>` — still matches as one string.
fn normalise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_ws = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            in_ws = true;
            continue;
        }
        // `///`, `//!`, `//`, `*` and `>` are comment and quote furniture, not
        // words. Dropping them means a claim cannot be hidden by rewrapping a
        // doc comment or turning a paragraph into a blockquote.
        if in_ws {
            out.push(' ');
            in_ws = false;
        }
        out.push(ch.to_ascii_lowercase());
    }
    let mut cleaned = String::with_capacity(out.len());
    for token in out.split(' ') {
        let t = token.trim_matches(|c| {
            c == '/' || c == '*' || c == '>' || c == '#' || c == '|' || c == '`'
        });
        if t.is_empty() {
            continue;
        }
        if !cleaned.is_empty() {
            cleaned.push(' ');
        }
        cleaned.push_str(t);
    }
    cleaned
}

/// Every prose file in the tree, as (path relative to root, normalised text).
fn prose_files() -> Vec<(String, String)> {
    let root = repo_root();
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            if path.is_dir() {
                if !SKIPPED_DIRS.contains(&name.as_str()) {
                    stack.push(path);
                }
                continue;
            }
            // This file quotes every pattern it hunts for. Guarding itself
            // would make it permanently red for the wrong reason.
            if name == "slashing_backed_finality_claims.rs" {
                continue;
            }
            let ext = path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
            if !PROSE_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let rel = path
                .strip_prefix(&root)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.display().to_string());
            out.push((rel, normalise(&text)));
        }
    }
    out.sort();
    out
}

/// Whether the slashing path can be reached from the network at all, measured
/// by running the codec rather than by reading it.
#[derive(Debug, PartialEq, Eq)]
enum Reachability {
    /// Tag `0x05` is refused by construction: no evidence can arrive.
    RefusedByConstruction,
    /// Tag `0x05` decodes. Evidence has a wire shape now.
    EvidenceDecodes,
    /// Neither — the codec changed in a way this test cannot interpret.
    Changed(String),
}

fn reachability() -> Reachability {
    // A minimally well-formed attestation-offence body, so a refusal cannot be
    // mistaken for `Truncated`: tag, sub-tag, then two (validator, root,
    // signature) triples with empty signatures.
    let mut bytes = vec![0x05u8, 0x02];
    for _ in 0..2 {
        bytes.extend_from_slice(&0u32.to_le_bytes()); // validator
        bytes.extend_from_slice(&[0u8; 32]); // signing root
        bytes.extend_from_slice(&0u32.to_le_bytes()); // signature length
    }
    match PosTransaction::from_canonical_bytes(&bytes) {
        Err(TxDecodeError::EvidenceNotDecodable) => Reachability::RefusedByConstruction,
        Ok(PosTransaction::SlashingEvidence(_)) => Reachability::EvidenceDecodes,
        other => Reachability::Changed(format!("{other:?}")),
    }
}

/// Break 1, measured: the decoder refuses tag `0x05` unconditionally.
///
/// This is the fact every other assertion in this file is judged against, so
/// it is established by *calling* the codec. It is deliberately separate from
/// the text tests: if the codec changes, this is the test that says so first.
#[test]
fn evidence_cannot_reach_a_verifier_from_the_network() {
    match reachability() {
        Reachability::RefusedByConstruction => {}
        Reachability::EvidenceDecodes => panic!(
            "tag 0x05 now DECODES. Slashing evidence can travel on the wire.\n\n\
             That is good news and this test is the wrong place to celebrate it: \
             every retraction listed in RETRACTION_SITES now understates the \
             guarantee, and the sibling tests in this file will say the same. \
             Update the text and this file together — that pairing is the whole \
             point of the file."
        ),
        Reachability::Changed(what) => panic!(
            "the tag-0x05 codec changed in a way this test does not understand: \
             {what}\n\nDecide what it means for the published guarantee before \
             adjusting this test, not after."
        ),
    }
}

/// Break 4, measured: there is no activation constant to arm.
///
/// A gated-but-present constant would be a different (and much better) world:
/// a flag day exists, it is simply not scheduled. There is not one here, and
/// the difference is exactly what an integrator would want to know.
#[test]
fn there_is_no_slashing_activation_constant_to_arm() {
    let files = prose_files();
    assert!(
        files.len() >= MIN_FILES_SCANNED,
        "scanned only {} files — the walk is broken and this test would pass by \
         reading nothing",
        files.len(),
    );
    // A *declaration*, not a mention: the retractions in this repo name the
    // constant in order to say it is absent, and a bare substring search would
    // fire on the very text it is guarding.
    let hits: Vec<&String> = files
        .iter()
        .filter(|(path, text)| {
            path.ends_with(".rs")
                && (text.contains("const slashing_evidence_activation_epoch")
                    || text.contains("static slashing_evidence_activation_epoch"))
        })
        .map(|(path, _)| path)
        .collect();
    if reachability() == Reachability::RefusedByConstruction {
        assert!(
            hits.is_empty(),
            "`SLASHING_EVIDENCE_ACTIVATION_EPOCH` now appears in:\n  {}\n\n\
             The published retractions say it does not exist — that it is absent \
             rather than set to `u64::MAX`, which is a claim about how far the \
             work has got. If a flag day now exists, say so in the retraction \
             sites before changing this test.",
            hits.iter().map(|p| p.as_str()).collect::<Vec<_>>().join("\n  "),
        );
    }
}

/// Break 3, measured: the node still says out loud that it does not prosecute.
///
/// This is the line an operator sees when a validator equivocates, and it is
/// the only thing standing between "captured" and "silently dropped".
#[test]
fn the_node_still_admits_it_does_not_prosecute() {
    if reachability() != Reachability::RefusedByConstruction {
        return; // covered, and interpreted, by the reachability test above
    }
    let engine = repo_root().join("crates/bloch-pos-node/src/engine.rs");
    let text = normalise(&std::fs::read_to_string(&engine).expect("engine.rs is readable"));
    assert!(
        text.contains("slashing pipeline not wired"),
        "engine.rs no longer prints that the slashing pipeline is unwired, but \
         tag 0x05 is still undecodable. Either the log line was removed while \
         the gap remained — which turns a captured equivocation back into a \
         silent drop — or prosecution landed and every retraction in this repo \
         needs revisiting."
    );
}

/// **The lock.** No text in this tree may assert a slashing-backed finality
/// while no stake can be slashed.
#[test]
fn no_text_promises_a_slashing_backed_finality() {
    let files = prose_files();
    assert!(
        files.len() >= MIN_FILES_SCANNED,
        "scanned only {} files — the walk is broken and this test would pass by \
         reading nothing",
        files.len(),
    );

    let mut violations: Vec<String> = Vec::new();
    for (path, text) in &files {
        for pattern in PROMISE_PATTERNS {
            let mut from = 0usize;
            while let Some(offset) = text[from..].find(pattern) {
                let at = from + offset;
                let window_start = at.saturating_sub(RETRACTION_WINDOW);
                let window_end = (at + pattern.len() + RETRACTION_WINDOW).min(text.len());
                let around = &text[window_start..window_end];
                let withdrawn = RETRACTION_MARKERS.iter().any(|m| around.contains(m));
                if !withdrawn {
                    let end = (at + pattern.len() + 90).min(text.len());
                    violations.push(format!(
                        "  {path}\n    matched: {pattern:?}\n    context: …{}…",
                        &text[window_start.max(at.saturating_sub(90))..end],
                    ));
                }
                from = at + pattern.len();
            }
        }
    }

    match reachability() {
        Reachability::RefusedByConstruction => assert!(
            violations.is_empty(),
            "Text promises a slashing penalty that CANNOT BE APPLIED. Tag 0x05 is \
             still refused by `PosTransaction::from_canonical_bytes`, so no evidence \
             can reach a verifier through any ingress path, nothing constructs the \
             transaction outside tests, and no activation constant exists.\n\n{}\n\n\
             This is the claim retracted on 2026-09-01 across rpc.rs, the \
             exchange integration book, the CertiK dossier, the whitepaper and \
             the block explorer. If it is genuinely true again, the retractions \
             in RETRACTION_SITES have to go first — this test is the thing that \
             keeps the two in step. If the sentence is a legitimate description of \
             the *designed* mechanism, mark it: a RETRACTION_MARKERS phrase within \
             {RETRACTION_WINDOW} characters is what tells a reader which way it cuts.",
            violations.join("\n\n"),
        ),
        Reachability::EvidenceDecodes => panic!(
            "Tag 0x05 decodes: evidence can travel. Every retraction this repo \
             published is now an understatement, and the guidance built on it \
             (credit at finalized + 3 epochs, no depth provably safe) was written \
             for a chain where the penalty did not exist.\n\n\
             Revisit RETRACTION_SITES, then this test. {} promise phrase(s) are \
             currently un-marked, which may be correct now.",
            violations.len(),
        ),
        Reachability::Changed(what) => {
            panic!("codec changed in an uninterpretable way ({what}); see the reachability test")
        }
    }
}

/// The other half of the lock: while the penalty cannot be applied, every
/// surface that carried the promise must carry the withdrawal. Deleting a
/// retraction is as much a regression as re-asserting the claim, and it is the
/// quieter of the two.
#[test]
fn the_retraction_is_published_wherever_the_promise_was() {
    let root = repo_root();
    let reach = reachability();
    let mut missing: Vec<String> = Vec::new();
    let mut lingering: Vec<String> = Vec::new();

    for (rel, marker) in RETRACTION_SITES {
        let path = root.join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{rel} is a guarded retraction site and must exist: {e}"));
        let text = normalise(&raw);
        let present = text.contains(&normalise(marker));
        match reach {
            Reachability::RefusedByConstruction if !present => {
                missing.push(format!("  {rel}\n    lost: {marker:?}"));
            }
            Reachability::EvidenceDecodes if present => {
                lingering.push(format!("  {rel}\n    stale: {marker:?}"));
            }
            _ => {}
        }
    }

    assert!(
        missing.is_empty(),
        "A published retraction disappeared while the penalty is still \
         unappliable (tag 0x05 refused):\n\n{}\n\nAn integrator reads these. \
         Removing the withdrawal restores the promise by silence, which is how \
         the claim survived in four places at once the first time.",
        missing.join("\n\n"),
    );
    assert!(
        lingering.is_empty(),
        "Tag 0x05 decodes now, but these retractions still tell readers no stake \
         can be slashed:\n\n{}\n\nThat is the reverse regression this file exists \
         to catch — enforcement arriving and the documents staying behind.",
        lingering.join("\n\n"),
    );
}
