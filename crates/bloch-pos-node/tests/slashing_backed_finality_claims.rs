// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keep finality claims aligned with the scheduled source and its limits.
//!
//! A finite activation epoch is a release schedule, not proof of deployed
//! readiness or an already applied penalty. Preserve the prohibition on
//! unqualified settlement promises even after a date is selected. Each guarded
//! publication must identify the lifecycle schedule; historical retractions
//! may remain when explicitly scoped to the earlier unarmed release.
//! The decoder, unique constant declaration, co-activation and publication
//! checks remain independent so none can hide a regression in another.

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
    // The marker moved on 2026-09-05 when finding F-03 landed the finality
    // latch: "finalized is not a latch" stopped being true of the local node
    // (the engine now refuses to rewind below its own finalized checkpoint),
    // but the slashing-cost half of the retraction stands and the doc still
    // carries it — as the phrase guarded here.
    ("crates/bloch-pos-node/src/engine.rs", "not an economic guarantee across nodes"),
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
    // A well-formed attestation-offence pair, encoded by the codec's own
    // encoder so this probe measures the DECODER and not a hand-kept byte
    // layout. (The first revision of this probe hand-rolled the retired
    // signing-root layout, which would have answered `Changed(Truncated)`
    // forever once the envelope format landed.)
    let attest = |head: u8| bloch_pos_committee::Attestation {
        data: bloch_pos_committee::AttestationData {
            slot: 32,
            head: [head; 32],
            source_epoch: 0,
            source_root: [1; 32],
            target_epoch: 1,
            target_root: [head; 32],
        },
        validator: 2,
        signature: vec![0u8; 8],
    };
    let bytes = PosTransaction::SlashingEvidence(
        bloch_pos_committee::interfaces::SlashingEvidence::AttestationOffence {
            first: attest(0xAA),
            second: attest(0xBB),
        },
    )
    .canonical_bytes();
    match PosTransaction::from_canonical_bytes(&bytes) {
        Err(TxDecodeError::EvidenceNotDecodable) => Reachability::RefusedByConstruction,
        Ok(PosTransaction::SlashingEvidence(_)) => Reachability::EvidenceDecodes,
        other => Reachability::Changed(format!("{other:?}")),
    }
}

/// Whether this source schedules reachable evidence inclusion. This is not
/// a measurement of deployed binary versions or the live network epoch.
fn penalty_scheduled() -> bool {
    reachability() == Reachability::EvidenceDecodes
        && bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH != u64::MAX
}

/// Break 1, measured — and since 2026-09-05 (F-02) measured the other way
/// round: tag `0x05` DECODES, and the flag day is what stands between the
/// wire and the penalty.
///
/// This is the fact every other assertion in this file is judged against, so
/// it is established by *calling* the codec. It is deliberately separate from
/// the text tests: if the codec changes, this is the test that says so first.
#[test]
fn evidence_decodes_and_the_release_schedule_is_explicit() {
    match reachability() {
        Reachability::EvidenceDecodes => {}
        Reachability::RefusedByConstruction => panic!(
            "tag 0x05 stopped decoding — F-02 has REGRESSED. §7.3 slashing is \
             structurally unreachable again (equivocation with no economic \
             cost), every document corrected on 2026-09-05 overstates the \
             mechanism, and the retractions of 2026-09-01 are the accurate \
             text once more. Restore the envelope codec, or update text and \
             this file together — that pairing is the whole point of the file."
        ),
        Reachability::Changed(what) => panic!(
            "the tag-0x05 codec changed in a way this test does not understand: \
             {what}\n\nDecide what it means for the published guarantee before \
             adjusting this test, not after."
        ),
    }
    assert!(penalty_scheduled(), "the coordinated release must schedule evidence inclusion");
    assert_eq!(bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH, 2_884);
}

/// Break 4, measured — in its post-2026-09-05 shape: the activation constant
/// EXISTS on this lineage (the "different and much better world" the first
/// revision of this test described: a flag day exists, it is simply not
/// scheduled), it is declared in exactly one place, and it is not armed.
///
/// The declaration scan is UNCONDITIONAL, for the reason the first revision
/// learned the hard way: a guard that disables itself when its subject
/// changes is worse than no guard, because a passing run reads as evidence.
#[test]
fn the_activation_constant_is_unique_and_matches_the_schedule() {
    // The value, read from the crate rather than from text: arming is a
    // founder decision with a fleet-rollout precondition, and this file is
    // one of the tripwires in front of it (transition.rs has another,
    // `slashing_evidence_gate_is_inert`).
    assert_eq!(
        bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH,
        2_884,
        "changing the selected epoch requires another coordinated release",
    );

    let files = prose_files();
    assert!(
        files.len() >= MIN_FILES_SCANNED,
        "scanned only {} files — the walk is broken and this test would pass by \
         reading nothing",
        files.len(),
    );
    // A *declaration*, not a mention: the corrected retractions name the
    // constant in order to say it is unarmed, and a bare substring search
    // would fire on the very text it is guarding.
    let hits: Vec<&String> = files
        .iter()
        .filter(|(path, text)| {
            path.ends_with(".rs")
                && (text.contains("const slashing_evidence_activation_epoch")
                    || text.contains("static slashing_evidence_activation_epoch"))
        })
        .map(|(path, _)| path)
        .collect();
    assert_eq!(
        hits,
        vec!["crates/bloch-pos-committee/src/params.rs"],
        "`SLASHING_EVIDENCE_ACTIVATION_EPOCH` must be declared in params.rs and \
         ONLY there — a second declaration is the two-spellings hazard the \
         wire-namespace registry records (`_ACTIVATION_SPELLINGS`), and zero \
         declarations means the flag day vanished while the decoder stayed, \
         which would make evidence consensus-valid nowhere or everywhere \
         depending on who still compiles the gate. Codec reachability right \
         now: {:?}. Text sites to keep in step: rpc.rs break 4, the CertiK \
         dossier, BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md.",
        reachability(),
    );
}

// SCOPE, stated because getting it wrong is what produced the defect this
// file's break 4 had to be corrected for on 2026-09-02.
//
// This test walks the CHECKED-OUT WORKING TREE. It can therefore only ever
// support a claim about the tree that is built — never a claim about "this
// repository", which is 1,300+ refs, most of which no released binary contains.
// Historical scope example: `d21c3370` declared the gate as `u64::MAX` on a
// different release lineage, while this tree schedules epoch 2884. A test over
// the checked-out tree cannot establish which lineage a fleet runs. It was the
// old retraction prose that overreached by turning a tree measurement into a
// repository/deployment claim; the current text requires binary inventory.

/// The observation hook must submit evidence and report a gated refusal;
/// silently dropping an observed pair must not return during integration.
#[test]
fn observed_evidence_is_submitted_with_an_explicit_gated_outcome() {
    let root = repo_root();
    let engine = normalise(&std::fs::read_to_string(root.join("crates/bloch-pos-node/src/engine.rs")).expect("engine source"));
    let lifecycle = normalise(&std::fs::read_to_string(root.join("crates/bloch-pos-node/src/engine/validator_lifecycle.rs")).expect("lifecycle source"));
    assert!(engine.contains("self.report_equivocation((*ev).into())"), "attestation observation hook was disconnected");
    assert!(engine.contains("self.observe_proposer_equivocation(&env)"), "proposer observation hook was disconnected");
    assert!(lifecycle.contains("self.on_transaction(postransaction::slashingevidence(evidence))"), "evidence bypasses ordinary admission or is only logged");
    assert!(lifecycle.contains("not submitted:"), "a gate refusal must be visible to the operator");
    assert_eq!(bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH, 2_884);
    assert_eq!(bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH,
        bloch_pos_committee::params::FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH);
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

    if let Reachability::Changed(what) = reachability() {
        panic!("codec changed in an uninterpretable way ({what}); see the reachability test");
    }
    assert!(
        violations.is_empty(),
        "A scheduled penalty is not proof of deployment, application, or a \
         universal cross-node settlement guarantee. Unqualified promises:\n{}",
        violations.join("\n\n"),
    );
}

/// Every previously guarded publication must distinguish the scheduled
/// release from deployed behavior. Retained historical retractions are valid
/// history, not a reason to assert that penalties are already live.
#[test]
fn every_published_surface_identifies_the_candidate_schedule() {
    let root = repo_root();
    assert!(penalty_scheduled());
    let mut missing = Vec::new();
    for (rel, _) in RETRACTION_SITES {
        let raw = std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("guarded publication {rel} must exist: {e}"));
        let text = normalise(&raw);
        if !text.contains("lifecycle epoch 2884") || !text.contains("2026-09-14") {
            missing.push(*rel);
        }
    }
    assert!(missing.is_empty(), "Publications missing the selected schedule: {missing:?}");
}
