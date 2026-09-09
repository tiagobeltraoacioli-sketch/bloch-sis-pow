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
//! No stake on Genesis-4 can be slashed. Four independent breaks when first
//! written; on 2026-09-05 (Round-2 finding F-02) break 1 was closed and break
//! 4 changed shape, and the verdict — no stake can be slashed on the live
//! chain — did not move:
//!
//! 1. ~~Evidence cannot be decoded~~ **closed 2026-09-05**:
//!    `PosTransaction::from_canonical_bytes` used to return
//!    `TxDecodeError::EvidenceNotDecodable` for wire tag `0x05`
//!    unconditionally, because the encoder folded the two nested messages in
//!    as the *signing roots* they were signed over — hashes, unrecoverable by
//!    construction. The codec now carries both envelopes whole and decodes
//!    them, and [`reachability`] measures exactly that.
//! 2. That decoder is the only one on every ingress path: block body
//!    (`engine::body_transactions`), gossip (`p2p.rs`, `net.rs`) and
//!    `sendrawtransaction` (`rpc.rs`). Every path therefore reaches the same
//!    transition gate (break 4), and the released fleet binaries — which
//!    predate the format — still refuse the tag at decode.
//! 3. Closed by ADR-041 implementation: observed equivocations now enter
//!    state-aware admission and report whether submission succeeded. The
//!    activation gate remains closed, so the live-chain retraction stands.
//! 4. `SLASHING_EVIDENCE_ACTIVATION_EPOCH` **is now defined on this lineage,
//!    inert at `u64::MAX`** — the same change that made the tag decodable
//!    introduced it, and gates the evidence transaction on it in the state
//!    transition (`TxReject::EvidenceNotActive` below the flag day). An
//!    earlier revision of this break said the constant existed only
//!    off-lineage (`d21c3370:params.rs:638`); that was true when written.
//!    Unarmed, no flag day is scheduled, and THIS break alone now carries the
//!    verdict: evidence can travel in format and still no block may carry it.
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

/// Whether the penalty can actually land on the live chain: evidence must
/// BOTH decode and be consensus-valid in some reachable epoch. The flag day
/// (`SLASHING_EVIDENCE_ACTIVATION_EPOCH`) is inert at `u64::MAX`, so today
/// this is false, and every retraction in this file is judged against THIS —
/// not against decodability alone, which since 2026-09-05 is necessary but
/// not sufficient.
fn penalty_appliable() -> bool {
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
fn evidence_decodes_and_only_the_inert_flag_day_stands_in_the_way() {
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
    assert!(
        !penalty_appliable(),
        "SLASHING_EVIDENCE_ACTIVATION_EPOCH is no longer u64::MAX: the flag \
         day is ARMED. If the founder scheduled it, every retraction in \
         RETRACTION_SITES is now an understatement and the sibling tests will \
         say so — update the text first, then this file. If the founder did \
         not schedule it, revert the constant NOW: arming activates §7.3 \
         network-wide and forks every node that cannot decode tag 0x05."
    );
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
fn the_activation_constant_exists_in_one_place_and_is_not_armed() {
    // The value, read from the crate rather than from text: arming is a
    // founder decision with a fleet-rollout precondition, and this file is
    // one of the tripwires in front of it (transition.rs has another,
    // `slashing_evidence_gate_is_inert`).
    assert_eq!(
        bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH,
        u64::MAX,
        "the slashing flag day is ARMED. If the founder scheduled it, the \
         retraction sites understate the guarantee and must move first; if \
         not, revert now — arming forks every node that cannot decode 0x05.",
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
// `SLASHING_EVIDENCE_ACTIVATION_EPOCH` is declared today on `d21c3370`
// (`params.rs:638`, `u64::MAX`), a direct child of fleet commit `46133196`
// pushed to a public remote, and this test was green the whole time — correctly,
// because that commit is not in this tree. It was the retraction PROSE that
// overreached, by saying "does not exist in this repository" about a measurement
// that only covered one lineage. No test in a tree can close that gap; only a
// narrower sentence can, which is why the sentences now say "release lineage".

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
    assert_eq!(bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH, u64::MAX,
        "implemented observation does not authorize mainnet activation");
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
    if !penalty_appliable() {
        assert!(
            violations.is_empty(),
            "Text promises a slashing penalty that CANNOT BE APPLIED. Since \
             2026-09-05 tag 0x05 decodes, but the evidence transaction is \
             consensus-refused at every epoch below \
             SLASHING_EVIDENCE_ACTIVATION_EPOCH, which is inert at u64::MAX — \
             and nothing constructs the transaction outside tests. (Before \
             2026-09-05 the decoder itself refused the tag; either way the \
             penalty cannot land.)\n\n{}\n\n\
             This is the claim retracted on 2026-09-01 across rpc.rs, the \
             exchange integration book, the CertiK dossier, the whitepaper and \
             the block explorer. If it is genuinely true again, the retractions \
             in RETRACTION_SITES have to go first — this test is the thing that \
             keeps the two in step. If the sentence is a legitimate description of \
             the *designed* mechanism, mark it: a RETRACTION_MARKERS phrase within \
             {RETRACTION_WINDOW} characters is what tells a reader which way it cuts.",
            violations.join("\n\n"),
        )
    } else {
        panic!(
            "The slashing flag day is ARMED and evidence decodes: the penalty \
             can land. Every retraction this repo published is now an \
             understatement, and the guidance built on it (credit at \
             finalized + 3 epochs, no depth provably safe) was written for a \
             chain where the penalty did not exist.\n\n\
             Revisit RETRACTION_SITES, then this test. {} promise phrase(s) are \
             currently un-marked, which may be correct now.",
            violations.len(),
        )
    }
}

/// The other half of the lock: while the penalty cannot be applied, every
/// surface that carried the promise must carry the withdrawal. Deleting a
/// retraction is as much a regression as re-asserting the claim, and it is the
/// quieter of the two.
#[test]
fn the_retraction_is_published_wherever_the_promise_was() {
    let root = repo_root();
    // Keyed on the penalty being appliable — NOT on decodability. Since
    // 2026-09-05 evidence decodes while the flag day stays inert, and in that
    // world the retractions are still the accurate text: no stake can be
    // slashed on the live chain. They become stale only when the penalty can
    // actually land.
    let appliable = penalty_appliable();
    let mut missing: Vec<String> = Vec::new();
    let mut lingering: Vec<String> = Vec::new();

    for (rel, marker) in RETRACTION_SITES {
        let path = root.join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{rel} is a guarded retraction site and must exist: {e}"));
        let text = normalise(&raw);
        let present = text.contains(&normalise(marker));
        if !appliable && !present {
            missing.push(format!("  {rel}\n    lost: {marker:?}"));
        }
        if appliable && present {
            lingering.push(format!("  {rel}\n    stale: {marker:?}"));
        }
    }

    assert!(
        missing.is_empty(),
        "A published retraction disappeared while the penalty is still \
         unappliable (the flag day is inert):\n\n{}\n\nAn integrator reads \
         these. Removing the withdrawal restores the promise by silence, which \
         is how the claim survived in four places at once the first time.",
        missing.join("\n\n"),
    );
    assert!(
        lingering.is_empty(),
        "The penalty can land now (evidence decodes AND the flag day is \
         armed), but these retractions still tell readers no stake can be \
         slashed:\n\n{}\n\nThat is the reverse regression this file exists \
         to catch — enforcement arriving and the documents staying behind.",
        lingering.join("\n\n"),
    );
}
