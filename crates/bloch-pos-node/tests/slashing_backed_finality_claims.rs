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
//! No stake on Genesis-4 can be slashed **below epoch 2700**. Four
//! independent breaks when first written; on 2026-09-05 (Round-2 finding
//! F-02) break 1 was closed and break 4 changed shape; on 2026-09-09 the
//! founder ARMED break 4 at epoch 2700 (`docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md`).
//! The verdict for every block the chain had produced at that decision
//! (~epoch 2413) — no stake can be slashed — did not move; from 2700 on it
//! does, and this file's job changed shape with it (see "After arming"):
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
//!    state-aware admission and report whether submission succeeded. Below
//!    the flag day the gate refuses them, so the live-chain retraction stands
//!    for every epoch below 2700.
//! 4. `SLASHING_EVIDENCE_ACTIVATION_EPOCH` **is defined on this lineage and
//!    ARMED at epoch 2700** — it was introduced at `u64::MAX` by the same
//!    change that made the tag decodable, and gates the evidence transaction
//!    in the state transition (`TxReject::EvidenceNotActive` below the flag
//!    day). An earlier revision of this break said the constant existed only
//!    off-lineage (`d21c3370:params.rs:638`); that was true when written.
//!    Between 2026-09-05 and 2026-09-09 it was unarmed and this break alone
//!    carried the verdict. Since 2026-09-09 it carries a DATE instead: below
//!    2700 evidence can travel in format and still no block may carry it; at
//!    and after 2700 a block may, and `apply_slashing_evidence` runs.
//!
//! # After arming (2026-09-09): what this file locks now
//!
//! The constant being a real epoch does not make the promise true. Three
//! things stand between "armed" and "a slashing-backed finality":
//!
//! - **the chain has to get there** — every block below 2700 has no penalty,
//!   and at the decision the head was ~2413;
//! - **the penalty has never landed** — no prosecution has been observed on
//!   mainnet, no mainnet withdrawal has settled, and no third party has
//!   audited §7.3 (the runbook's "still open" list records all three);
//! - **the mechanism is narrower than the ADR** — ADR-041 T-6 is NOT
//!   reconciled with `SlashingState`'s one-prosecution rule; the
//!   implementation keeps the one-prosecution rule.
//!
//! So the lock keeps BOTH halves in force in the armed state: no text may
//! assert an unqualified slashing-backed finality, and every retraction site
//! must still carry its withdrawal. What changes is a third check: a
//! retraction site that describes the constant as unarmed / inert /
//! `u64::MAX` is now a false statement, and it must name the armed epoch in
//! the same breath (`the_retraction_sites_do_not_call_the_armed_gate_inert`).
//! The human step this test cannot take — deciding, once the chain is past
//! 2700 and a prosecution has landed, that the retractions may be withdrawn
//! and the promise restated — is recorded in the runbook, and whoever takes
//! it edits RETRACTION_SITES and this file together.
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
//!   fails. That was the 2026-09-01 defect, and the direction it can regress
//!   in at any epoch.
//! - **Enforcement scheduled, retraction claims it is not** →
//!   [`the_retraction_sites_do_not_call_the_armed_gate_inert`] fails: a
//!   withdrawal that says "unarmed" after 2026-09-09 misleads in the other
//!   direction.
//! - **Retraction deleted while the penalty has not landed** →
//!   [`the_retraction_is_published_wherever_the_promise_was`] fails.
//!
//! So the reachability of the slashing path is measured — by **calling the
//! decoder**, not by grepping for it — the constant is read from the crate,
//! and the text is judged against both rather than against a hardcoded
//! expectation.
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

/// The epoch the founder armed the flag day at (2026-09-09), as recorded in
/// `docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md`. `transition.rs`'s
/// `slashing_evidence_armed_epoch_matches_the_runbook` pins the same value
/// from the committee side; this is the node side of the same tripwire.
const ARMED_EPOCH: u64 = 2_700;

/// From which epoch the penalty can actually land on the live chain, if any:
/// evidence must BOTH decode and be consensus-valid from some epoch. `None`
/// means "at no epoch" — the state this file was written in (decoder refused
/// the tag) and the state it was in from 2026-09-05 to 2026-09-09 (decodes,
/// gate at `u64::MAX`). `Some(2700)` is the armed state. Every retraction in
/// this file is judged against THIS — not against decodability alone, which
/// since 2026-09-05 is necessary but not sufficient, and not against the
/// constant alone, which without a decoder would gate nothing.
fn penalty_scheduled_at() -> Option<u64> {
    if reachability() != Reachability::EvidenceDecodes {
        return None;
    }
    let epoch = bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH;
    (epoch != u64::MAX).then_some(epoch)
}

/// Words that describe the constant as not in force. A retraction site may
/// use them only while also naming the armed epoch in the same window — the
/// sentence "was inert at `u64::MAX` until armed at 2700" is a correct
/// history; the sentence "is inert at `u64::MAX`" is a false present.
const UNARMED_WORDS: &[&str] = &["u64::max", "unarmed", "not armed", "inert", "no flag day is scheduled"];

/// Break 1, measured — and since 2026-09-05 (F-02) measured the other way
/// round: tag `0x05` DECODES, and the flag day is what stands between the
/// wire and the penalty. Since 2026-09-09 that flag day is a date.
///
/// This is the fact every other assertion in this file is judged against, so
/// it is established by *calling* the codec. It is deliberately separate from
/// the text tests: if the codec changes, this is the test that says so first.
#[test]
fn evidence_decodes_and_the_flag_day_is_armed_at_the_runbook_epoch() {
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
    assert_eq!(
        penalty_scheduled_at(),
        Some(ARMED_EPOCH),
        "SLASHING_EVIDENCE_ACTIVATION_EPOCH moved away from the armed epoch 2700 \
         (2026-09-09). If it was DISARMED (u64::MAX): the retractions become the \
         whole truth again at every epoch, and this file's armed-state prose has \
         to say so — revert to the 2026-09-05..09 wording. If it was MOVED: that \
         is a new flag day, needing its own fleet rollout, announcement and \
         runbook; update docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md, transition.rs's \
         slashing_evidence_armed_epoch_matches_the_runbook and this constant in \
         ONE commit. Either way: arming activates §7.3 network-wide and forks \
         every node that cannot decode tag 0x05, so the fleet must be on the new \
         binary BEFORE the epoch."
    );
}

/// Break 4, measured — in its post-2026-09-09 shape: the activation constant
/// EXISTS on this lineage, it is declared in exactly one place, and it is
/// armed at the epoch the runbook records.
///
/// The declaration scan is UNCONDITIONAL, for the reason the first revision
/// learned the hard way: a guard that disables itself when its subject
/// changes is worse than no guard, because a passing run reads as evidence.
#[test]
fn the_activation_constant_exists_in_one_place_and_is_armed_at_the_runbook_epoch() {
    // The value, read from the crate rather than from text: arming was a
    // founder decision with a fleet-rollout precondition, and this file is
    // one of the tripwires behind it (transition.rs has another,
    // `slashing_evidence_armed_epoch_matches_the_runbook`).
    assert_eq!(
        bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH,
        ARMED_EPOCH,
        "the slashing flag day moved from 2700. A second change is a new flag \
         day (own rollout, announcement, runbook) or a disarm (retractions \
         become the whole truth again); update the runbook, transition.rs and \
         this file in one commit.",
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
    // Implementing the observation hook never authorised activation; the
    // epoch is the founder's, and it must be the one the runbook records.
    assert_eq!(bloch_pos_committee::params::SLASHING_EVIDENCE_ACTIVATION_EPOCH, ARMED_EPOCH,
        "the observation hook's gate must be the runbook's armed epoch (docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md)");
}

/// **The lock.** No text in this tree may assert an unqualified
/// slashing-backed finality — while no stake can be slashed (every epoch
/// below 2700), and while the armed penalty has not landed, been audited, or
/// had ADR-041 T-6 reconciled with the one-prosecution rule. A sentence
/// about slashing has to say which way it cuts (a RETRACTION_MARKERS phrase
/// within RETRACTION_WINDOW), in every state this file knows.
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
    match penalty_scheduled_at() {
        None => assert!(
            violations.is_empty(),
            "Text promises a slashing penalty that CANNOT BE APPLIED at any epoch: \
             either tag 0x05 does not decode, or SLASHING_EVIDENCE_ACTIVATION_EPOCH \
             is back at u64::MAX.\n\n{}\n\n\
             This is the claim retracted on 2026-09-01 across rpc.rs, the \
             exchange integration book, the CertiK dossier, the whitepaper and \
             the block explorer. If the sentence is a legitimate description of \
             the *designed* mechanism, mark it: a RETRACTION_MARKERS phrase within \
             {RETRACTION_WINDOW} characters is what tells a reader which way it cuts.",
            violations.join("\n\n"),
        ),
        Some(epoch) => assert!(
            violations.is_empty(),
            "Text asserts an UNQUALIFIED slashing-backed finality. The flag day is \
             armed at epoch {epoch} (2026-09-09), and that is not the same thing: \
             every block below {epoch} has no penalty in it; no prosecution has \
             landed on mainnet and none has been audited; ADR-041 T-6 is not \
             reconciled with the one-prosecution rule. The guidance built on the \
             2026-09-01 retraction (credit at finalized + 3 epochs, no depth \
             provably safe) still stands until a human withdraws it in \
             RETRACTION_SITES and this file together, after the chain is past \
             {epoch} and a prosecution has been observed.\n\n{}\n\n\
             Until then a sentence about slashing must say which way it cuts: a \
             RETRACTION_MARKERS phrase within {RETRACTION_WINDOW} characters. \
             Naming the armed epoch is not a marker on its own.",
            violations.join("\n\n"),
        ),
    }
}

/// The other half of the lock: every surface that carried the promise must
/// carry the withdrawal — while the penalty cannot be applied at any epoch,
/// AND while it is armed but has not landed (below 2700 the retraction is
/// the literal truth of every block; from 2700 it stays until a human
/// withdraws it, see the module docs). Deleting a retraction is as much a
/// regression as re-asserting the claim, and it is the quieter of the two.
///
/// The first revision of this test had a "lingering" branch that failed the
/// moment the constant left `u64::MAX`, on the theory that arming makes every
/// retraction an understatement. Arming at a FUTURE epoch does not: at the
/// decision the chain was ~290 epochs short of it. That branch was replaced
/// by `the_retraction_sites_do_not_call_the_armed_gate_inert`, which catches
/// the actual staleness arming introduces.
#[test]
fn the_retraction_is_published_wherever_the_promise_was() {
    let root = repo_root();
    let mut missing: Vec<String> = Vec::new();

    for (rel, marker) in RETRACTION_SITES {
        let path = root.join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{rel} is a guarded retraction site and must exist: {e}"));
        let text = normalise(&raw);
        if !text.contains(&normalise(marker)) {
            missing.push(format!("  {rel}\n    lost: {marker:?}"));
        }
    }

    assert!(
        missing.is_empty(),
        "A published retraction disappeared while the penalty has not landed \
         (scheduled at: {:?}):\n\n{}\n\nAn integrator reads these. Removing \
         the withdrawal restores the promise by silence, which is how the claim \
         survived in four places at once the first time. Withdrawing a \
         retraction is a decision taken after the chain is past the armed epoch \
         and a prosecution has been observed, and it edits RETRACTION_SITES and \
         this file together.",
        penalty_scheduled_at(),
        missing.join("\n\n"),
    );
}

/// The staleness arming DOES introduce: a retraction site that still says
/// the constant is unarmed / inert / `u64::MAX` is a false statement after
/// 2026-09-09, and it is false in the direction that hides a consensus
/// change from the people who most need to know about it (a fleet operator
/// reading `slashing.rs`, an exchange reading the integration book). Every
/// occurrence of the constant's name in a retraction site whose window also
/// contains an UNARMED_WORDS phrase must name the armed epoch in that same
/// window — history ("was inert until armed at 2700") passes, a stale present
/// ("is inert at u64::MAX") fails.
///
/// Scoped to RETRACTION_SITES on purpose: dated audit reports elsewhere in
/// `docs/audit/` record what was true at their base commit and are not
/// rewritten.
#[test]
fn the_retraction_sites_do_not_call_the_armed_gate_inert() {
    let Some(epoch) = penalty_scheduled_at() else {
        // Not armed: "unarmed" is the truth, and the sibling tests carry the lock.
        return;
    };
    let root = repo_root();
    let needle = "slashing_evidence_activation_epoch";
    let epoch_text = epoch.to_string();
    let mut stale: Vec<String> = Vec::new();
    for (rel, _) in RETRACTION_SITES {
        let raw = std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("{rel} is a guarded retraction site and must exist: {e}"));
        let text = normalise(&raw);
        let mut from = 0usize;
        while let Some(offset) = text[from..].find(needle) {
            let at = from + offset;
            let window_start = at.saturating_sub(RETRACTION_WINDOW);
            let window_end = (at + needle.len() + RETRACTION_WINDOW).min(text.len());
            let around = &text[window_start..window_end];
            let says_unarmed = UNARMED_WORDS.iter().any(|w| around.contains(w));
            // `2_700` in a Rust literal and `2700` in prose are the same epoch.
            let names_epoch = around.replace('_', "").contains(&epoch_text);
            if says_unarmed && !names_epoch {
                let end = (at + needle.len() + 120).min(text.len());
                stale.push(format!(
                    "  {rel}\n    context: …{}…",
                    &text[at.saturating_sub(120)..end]
                ));
            }
            from = at + needle.len();
        }
    }
    assert!(
        stale.is_empty(),
        "These retraction sites describe SLASHING_EVIDENCE_ACTIVATION_EPOCH as \
         unarmed / inert / u64::MAX without naming the armed epoch ({epoch}) in \
         the same window. That was true until 2026-09-09 and is false now; say \
         'was … until armed at {epoch}' or drop the word.\n\n{}",
        stale.join("\n\n"),
    );
}
