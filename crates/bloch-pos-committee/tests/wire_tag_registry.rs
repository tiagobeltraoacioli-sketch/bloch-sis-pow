//! # The frozen wire-tag registry, and why it is a separate file
//!
//! Every other tag test in this workspace reads ONE tree and pins that tree's
//! internal agreement — `transition.rs`'s own
//! `every_wire_tag_is_claimed_exactly_once` builds one witness per variant and
//! checks no two share a byte. That is a real invariant and it catches nothing
//! here, for two reasons:
//!
//! 1. **It cannot see other branches.** Two branches assigning the same byte to
//!    different variants never coexist in a single `match`, so no arm is ever
//!    unreachable, no compiler warns, and git merges them cleanly. Each tree is
//!    self-consistent; each passes its own test; every one of those decoders
//!    SUCCEEDS on the same block body and yields a different transaction, a
//!    different post-state and a different state root. No `UnknownTag`, no
//!    error, nothing in a log.
//! 2. **It lives in the file it guards.** A merge that brings a rival
//!    `transition.rs` brings that file's copy of the guard with it, so the
//!    guard moves to whatever the merge decided. A test cannot police a file
//!    it rides inside.
//!
//! This file addresses (2) by sitting outside the file it guards. A merge that
//! brings a rival `transition.rs` lands that branch's code and leaves this
//! table untouched — the code changes, the frozen table does not, and the
//! assertions below go red naming both claimants. That is the whole mechanism.
//! It bites at MERGE time, which is the moment that matters, not on the branch
//! where each tree looks fine.
//!
//! ## The limit of that mechanism, stated because an earlier draft denied it
//!
//! Until 2026-09-02 these lines claimed the mechanism was airtight because
//! **"no branch in this repository has a file at this path (re-verified across
//! 528 ref and worktree tips)."** That was false when it was written, and the
//! branch that falsifies it is the same `70991742` this file cites nine lines
//! below as the executed hazard.
//!
//! Measured 2026-09-02 over all 1,320 ref tips, the following carry a file at
//! `crates/bloch-pos-committee/tests/wire_tag_registry.rs`:
//!
//! * `demo/final-writeoff-ruled` (`70991742`) — local, **and pushed to both
//!   `origin` and `github`**. A 507-line rival of this 966-line file. Its table
//!   records `0x07 = DepositFunded` and `0x08 = ExitV2`; its own
//!   `transition.rs` decoder produces `FundedDeposit` (`:1158`) and
//!   `SignedExit` (`:1189`). Two bytes, table against code, on one tree. The
//!   branch is 17 ahead / 87 behind tag `g4-node-20260901` and its copy of this
//!   test is red on its own tree.
//! * `guard/wire-tag-registry` (`61e9342d`) — local + both remotes; this
//!   file's own pre-release sibling, not a rival.
//!
//! So the honest statement of the guarantee is narrower, and it is a
//! guarantee about *code*, not about *this file*:
//!
//! > A merge that brings a rival `transition.rs` **and no rival copy of this
//! > path** trips these assertions. A merge that brings BOTH replaces the
//! > guard with the rival's own guard, and nothing here fires.
//!
//! A plain `git merge` of `demo/final-writeoff-ruled` conflicts loudly on this
//! path, so the default is safe. What is NOT safe is `-X theirs`, or any
//! scripted resolution that prefers the incoming side: it silently substitutes
//! the rival table and the substitution appears in no test output. The file
//! this mechanism cannot police is itself, and one branch already holds the
//! copy that would replace it.
//!
//! The durable fix is not in this file. It is to remove the rival copy from
//! `demo/final-writeoff-ruled` on both remotes, which needs the founder's
//! word because it rewrites a published branch. Until that happens this
//! paragraph is the guard, and it only guards a reader.
//!
//! ## The hazard, executed and dated
//!
//! `8f727d4b` (2026-09-02 01:36:36) recorded `0x07 = DepositFunded`,
//! `0x08 = ExitV2`, `0x09 = Withdraw` as released. Its own **conflict-free
//! merge** `70991742`, nine minutes later, left `0x07 = FundedDeposit` and
//! `0x08 = SignedExit`. Two of three bytes silently re-pointed, no conflict
//! marker, nothing logged. On `dev1/transition-merge`, tag `0x08` meant
//! `Withdraw` at `429edb22`, `SignedExit` at `648ac16c`, `ExitV2` at
//! `50447839`, and `SignedExit` again after merge `a5c20a90` — four meanings on
//! one line of development.
//!
//! ## Two defences, deliberately layered
//!
//! * `frozen_variant_space` below is an **exhaustive `match` with no wildcard
//!   arm**. A merge that adds a variant to `PosTransaction` makes it
//!   non-exhaustive and this target FAILS TO COMPILE (`error[E0004]`), naming
//!   the variant. That is stronger than a red test: it cannot be `#[ignore]`d,
//!   and `error[E0004]` is a `^error` line, which is the only thing the
//!   `clippy-hardened` CI ratchet counts. A warning-level lint is structurally
//!   uncountable by that ratchet, and there is no `[workspace.lints]` anywhere
//!   in this workspace to raise one.
//! * The runtime assertions then produce the readable report — which rivals
//!   claim the byte, on how many refs, and where to look.
//!
//! Neither is redundant: the match freezes the *variant space*, the tables
//! freeze the *byte assignment*. A merge can break either one alone.
//!
//! ## What this file does NOT decide
//!
//! Choosing which of `Withdraw` / `SignedExit` / `ExitV2` owns `0x08` is a
//! consensus decision and belongs to the founder, not to a test. So the table
//! below records the **released** space (`0x01`–`0x06`, verifiable against tag
//! `g4-node-20260901`) as canonical, and every unreleased number as
//! **claimed-but-unassigned, with its rival claimants named**. Landing one of
//! them requires editing this table, and the diff makes the choice visible
//! instead of silent.
//!
//! ## Per-namespace, never global
//!
//! `docs/WIRE-NAMESPACE-REGISTRY.md` records deliberate same-value pairs that
//! are CORRECT across namespaces — `SYNC_TAG_GET_BLOCKS` = `SYNC_TAG_BLOCKS` =
//! `0x01`, `TAG_EUTXO` = `FRAME_BLOCK` = `0x01`. A test that checked global
//! distinctness would fail on correct code and be "fixed" by exactly the
//! renumbering it exists to prevent. Every check below is scoped to one
//! namespace.

use bloch_pos_committee::transition::{PosTransaction, TxDecodeError};

// ===========================================================================
//                    THE FROZEN TABLE — EDIT DELIBERATELY
// ===========================================================================
// Anything landing a reserved number MUST edit this table. That edit is the
// visible record of a consensus choice. Do not "fix" a red test by widening
// the table without the founder's ruling on the tag.

/// One branch family's claim on a byte.
///
/// ## The counting unit, stated because an unstated one rots
///
/// Swept 2026-09-02 by blob object id across **528 distinct tip commits**
/// (1,474 ref entries + 167 worktree HEADs; 317 of those tips carry
/// `transition.rs` at all, across 101 distinct blobs — the remaining 211 are
/// Genesis-3 PoW trees with no `bloch-pos-committee`).
///
/// * `tips` — distinct **commit ids** carrying this meaning. This is the
///   honest unit: it counts distinct lines of work and is immune to the
///   ×3 inflation from the `github`/`origin`/`upstream-gitlab` mirrors.
/// * `heads` — distinct `refs/heads/` names. This is the unit that matters
///   when asking "how many branches could merge this into me".
///
/// The two disagree in both directions (a branch family sharing one tree
/// inflates `heads`; a detached worktree inflates `tips`), which is why both
/// are recorded rather than one being called "refs".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Claim {
    /// The name the claimant gives this byte.
    name: &'static str,
    tips: usize,
    heads: usize,
    /// A representative ref, so a failure can be traced without a re-sweep.
    example: &'static str,
}

/// Status of one byte in a wire namespace. There is deliberately no `Free`
/// variant: a byte absent from the table is free, and giving "free" a spelling
/// invites an editor to mark a contested byte free instead of ruling on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Shipped in tag `g4-node-20260901` and on the live chain. Canonical.
    ///
    /// `rivals` names branches that give this SAME released byte a DIFFERENT
    /// meaning. A released byte with a live rival is the most dangerous row in
    /// the table — it is a collision inside the space the network has already
    /// finalised — so it is recorded, not silently omitted for being released.
    Released { name: &'static str, rivals: &'static [Claim] },
    /// Claimed by two or more unmerged branches that do not agree. NOT
    /// assigned. The decoder must refuse it until the founder rules.
    Contested(&'static [Claim]),
}

const NO_RIVALS: &[Claim] = &[];

/// Released tags whose decoder is deliberately **one-way**: the encoder emits
/// them, the decoder refuses them.
///
/// This list exists to close a blind spot that was live in the first draft of
/// this file. `0x05`'s registered name is `SlashingEvidence` — the name the
/// ENCODER gives the variant. Six tips make `0x05` *decode* to a
/// `PosTransaction::SlashingEvidence`, and the decoded variant name would then
/// EQUAL the registered name, so the released-tag check would pass on exactly
/// the re-pointing it exists to catch. Naming the one-way tags explicitly makes
/// the refusal itself the pinned property.
const ONE_WAY_TX_TAGS: &[u8] = &[0x05];

// ---------------------------------------------------------------------------
// §1 — PosTransaction wire tags. First byte of `canonical_bytes`.
// ---------------------------------------------------------------------------
const TX_TAGS: &[(u8, Status)] = &[
    (0x01, Status::Released { name: "Transfer", rivals: NO_RIVALS }),
    (0x02, Status::Released { name: "Deposit", rivals: NO_RIVALS }),
    (0x03, Status::Released { name: "Exit", rivals: NO_RIVALS }),
    (0x04, Status::Released { name: "Delegate", rivals: NO_RIVALS }),
    // Released and ONE-WAY: the decoder returns `EvidenceNotDecodable`
    // unconditionally (see ONE_WAY_TX_TAGS). `SlashingEvidence` is the
    // encoder-side name. Six tips make it decodable — that is a released-space
    // re-pointing, listed as a rival, not as a separate byte.
    (
        0x05,
        Status::Released {
            name: "SlashingEvidence",
            rivals: &[Claim {
                name: "SlashingEvidence (DECODABLE — released tree refuses it)",
                tips: 6,
                heads: 6,
                example: "refs/heads/pmo/wire-namespace-registry",
            }],
        },
    ),
    // A COLLISION IN THE RELEASED SPACE. `TransferV2` took 0x06 on the
    // mainline; a branch whose tip is 87 minutes older gives 0x06 to
    // `FundedDeposit`. The loser was never deleted and still sits on two
    // remotes, so it is still merge-reachable.
    (
        0x06,
        Status::Released {
            name: "TransferV2",
            rivals: &[Claim {
                name: "FundedDeposit",
                tips: 1,
                heads: 1,
                example: "refs/heads/worktree-wf_a64751d6-225-3 \
                          (= github/wip/funded-stake-a7, upstream-gitlab/wip/funded-stake-a7)",
            }],
        },
    ),
    // -------- unreleased, contested --------
    (
        0x07,
        Status::Contested(&[
            Claim {
                name: "FundedDeposit",
                tips: 10,
                heads: 13,
                example: "refs/heads/demo/final-writeoff-ruled",
            },
            Claim {
                name: "DepositV2",
                tips: 10,
                heads: 8,
                example: "refs/heads/integ/exit-carrier-land",
            },
            Claim {
                name: "DepositFunded",
                tips: 4,
                heads: 8,
                example: "refs/heads/dev4/writeoff-memo",
            },
            Claim {
                name: "Withdraw",
                tips: 2,
                heads: 2,
                example: "refs/heads/worktree-agent-a1d31358b1c038bdf",
            },
            Claim {
                name: "SignedExit",
                tips: 1,
                heads: 1,
                example: "refs/heads/worktree-wf_a64751d6-225-3",
            },
        ]),
    ),
    (
        0x08,
        Status::Contested(&[
            Claim {
                name: "SignedExit",
                tips: 10,
                heads: 13,
                example: "refs/heads/demo/final-writeoff-ruled",
            },
            Claim {
                name: "Withdraw",
                tips: 10,
                heads: 8,
                example: "refs/heads/integ/exit-carrier-land",
            },
            Claim {
                name: "ExitV2",
                tips: 4,
                heads: 8,
                example: "refs/heads/dev4/writeoff-memo",
            },
        ]),
    ),
    (
        0x09,
        Status::Contested(&[
            Claim {
                name: "Withdraw",
                tips: 14,
                heads: 21,
                example: "refs/heads/demo/final-writeoff-ruled",
            },
            Claim {
                name: "ExitV2",
                tips: 4,
                heads: 2,
                example: "refs/heads/integ/exit-carrier-land",
            },
        ]),
    ),
];

/// Three lineages that all intend the SAME flag day disagree on all three
/// unreleased bytes. `0x07` is only a naming split — `FundedDeposit` and
/// `DepositV2` carry the same semantics — but `0x08` and `0x09` are
/// semantically INCOMPATIBLE, and whichever lands second splits the chain at
/// decode. Verified 2026-09-02 by reading each branch's `transition.rs` blob:
///
/// | byte | `funded/eutxo-merge-a7` | `wt/signed-exit-wire` | `wt/exit-churn-limit` |
/// |------|-------------------------|-----------------------|-----------------------|
/// | 0x07 | `FundedDeposit`         | `DepositV2`           | `DepositV2`           |
/// | 0x08 | `SignedExit`            | `Withdraw`            | `Withdraw`            |
/// | 0x09 | `Withdraw`              | `ExitV2`              | *(no `0x09` arm)*     |
///
/// The last cell is a correction to the collision report this table was built
/// from, which listed `wt/exit-churn-limit` as claiming `0x09 = ExitV2`. It
/// does not: its decoder stops at `0x08`.
///
/// The only thing standing between these two meanings is the decoder's final
/// `UnknownTag` arm — so the failure is SILENT on the side that decodes and
/// refusing on the side that does not. That asymmetry is why this must be
/// caught before the merge, not after.
const _FLAG_DAY_COLLISION_NOTE: () = ();

/// The funded-staking activation constant has two spellings across the fleet:
/// `FUNDED_STAKE_ACTIVATION_EPOCH` (30 heads, incl. `funded/eutxo-merge-a7`)
/// and `FUNDED_STAKING_ACTIVATION_EPOCH` (9 heads, incl. `wt/signed-exit-wire`
/// and `wt/exit-churn-limit`).
///
/// On the fleet lineage `46133196`, at tag `g4-node-20260901` and on `main`,
/// **neither spelling exists at all**. That is a different fact from being
/// present-and-unarmed, and is stated that way deliberately: there is nothing
/// to disarm here, and a merge that introduces either spelling is introducing
/// the constant, not changing its value. This file arms nothing and asserts
/// nothing about its value — it records the two spellings so a future sweep
/// for one of them does not conclude the other is absent.
const _ACTIVATION_SPELLINGS: [&str; 2] =
    ["FUNDED_STAKE_ACTIVATION_EPOCH", "FUNDED_STAKING_ACTIVATION_EPOCH"];

// ---------------------------------------------------------------------------
// §1a — the sub-namespace NESTED INSIDE tag 0x05.
//
// `0x05`'s payload opens with a second discriminant selecting the offence
// family. Both are **bare literals bound to no constant**, so a `const NAME: u8`
// sweep — the sweep every other namespace here is audited by — cannot see them.
// They are registered by source position instead. This is not "lifting" them
// into constants: that would edit consensus code, which this file may not do.
// ---------------------------------------------------------------------------
const EVIDENCE_SUBTAGS: &[(&str, u8)] =
    &[("ProposerEquivocation", 0x01), ("AttestationOffence", 0x02)];

// ---------------------------------------------------------------------------
// §2 — Frame bytes, `crates/bloch-pos-node/src/net.rs`.
// The namespace with NO diagnostic: `net.rs` matches `&FRAME_BLOCK` as a
// binding by reference and compares with `==` at runtime, so two consts with
// different names and the same value are invisible to `unreachable_patterns`.
//
// A sibling guard, `net::tests::frame_bytes_are_claimed_exactly_once`, does
// pairwise distinctness over a hard-coded array of 8 names. It is NOT on this
// lineage — it exists on exactly one `net.rs` blob (`862b5c41`), carried by 10
// heads including `integ/validator-opening` and `integ/exit-carrier-land`, and
// is absent from the fleet commit, tag `g4-node-20260901` and `main`. So there
// is nothing to duplicate here today.
//
// When it does merge, the two are consistent by containment, not by accident:
// check (c) below is that same pairwise-distinctness test, scanned from source
// instead of hard-coded, so it holds wherever the sibling holds. The sibling
// would PASS the very merge this file is built to stop — its 8 names are
// pairwise distinct on that branch — because it can only ask "does this tree
// contradict itself", never "does this tree contradict what shipped". Check
// (b) is the half it cannot express.
// ---------------------------------------------------------------------------
const FRAME_TAGS: &[(u8, Status)] = &[
    (0x01, Status::Released { name: "FRAME_BLOCK", rivals: NO_RIVALS }),
    (0x02, Status::Released { name: "FRAME_ATT", rivals: NO_RIVALS }),
    (0x03, Status::Released { name: "FRAME_GET_BLOCKS", rivals: NO_RIVALS }),
    (0x04, Status::Released { name: "FRAME_TX", rivals: NO_RIVALS }),
    (
        0x05,
        Status::Contested(&[
            Claim {
                name: "FRAME_GET_TIME",
                tips: 15,
                heads: 10,
                example: "refs/heads/agent/testnet-deliver",
            },
            Claim {
                name: "FRAME_GET_STATE",
                tips: 2,
                heads: 2,
                example: "refs/heads/worktree-agent-a58dfe6cc066ef5b3",
            },
        ]),
    ),
    (
        0x06,
        Status::Contested(&[
            Claim {
                name: "FRAME_TIME",
                tips: 15,
                heads: 10,
                example: "refs/heads/agent/testnet-deliver",
            },
            Claim {
                name: "FRAME_STATE",
                tips: 2,
                heads: 2,
                example: "refs/heads/worktree-agent-a58dfe6cc066ef5b3",
            },
        ]),
    ),
    // Single-claimant but unreleased: still not assigned, still must not
    // appear in a merged `net.rs` without a table edit.
    (
        0x07,
        Status::Contested(&[Claim {
            name: "FRAME_GET_STATE",
            tips: 12,
            heads: 7,
            example: "refs/heads/agent/testnet-deliver",
        }]),
    ),
    (
        0x08,
        Status::Contested(&[Claim {
            name: "FRAME_STATE",
            tips: 12,
            heads: 7,
            example: "refs/heads/agent/testnet-deliver",
        }]),
    ),
];

// ---------------------------------------------------------------------------
// §3 — `DS_*` domain separators in `params.rs`. Names, not numbers: a
// collision here is two names sharing one 16-byte string (one hash domain
// doing two jobs), or one name bound to two different strings (one job
// hashed two ways on two branches).
//
// Swept 2026-09-02: no name is bound to two different strings anywhere, and no
// string is shared by two names. Three unreleased additions exist and collide
// with nothing — `DS_FUND` (5 tips), `DS_DEPOSIT_FUND` (11 tips), `DS_NFSET`
// (1 tip). This namespace is, today, the only clean one of the three.
// ---------------------------------------------------------------------------
const RELEASED_DS: &[(&str, &str)] = &[
    ("DS_ATTEST", r"BLCH4:ATTEST\0\0\0\0"),
    ("DS_BLOCK", r"BLCH4:BLOCK\0\0\0\0\0"),
    ("DS_BODY", r"BLCH4:BODY\0\0\0\0\0\0"),
    ("DS_COHERENCE", r"BLCH4:COHERE\0\0\0\0"),
    ("DS_DEPOSIT", r"BLCH4:DEPOSIT\0\0\0"),
    ("DS_EXIT", r"BLCH4:EXIT\0\0\0\0\0\0"),
    ("DS_PROPOSE", r"BLCH4:PROPOSE\0\0\0"),
    ("DS_RANDAO", r"BLCH4:RANDAO\0\0\0\0"),
    ("DS_SLASH", r"BLCH4:SLASH\0\0\0\0\0"),
    ("DS_SORTITION", r"BLCH4:SORTIT\0\0\0\0"),
    ("DS_SPEND", r"BLCH4:SPEND\0\0\0\0\0"),
    ("DS_STATE", r"BLCH4:STATE\0\0\0\0\0"),
    ("DS_TXID", r"BLCH4:TXID\0\0\0\0\0\0"),
    ("DS_WSCKPT", r"BLCH4:WSCKPT\0\0\0\0"),
];

// ===========================================================================
//              THE COMPILE-TIME FREEZE — no wildcard arm, ever
// ===========================================================================

/// Maps every `PosTransaction` variant to the byte this registry assigns it.
///
/// **This match has no `_` arm and must never grow one.** A merge that adds a
/// variant — `Withdraw`, `SignedExit`, `ExitV2`, `DepositV2`, `FundedDeposit`,
/// `DepositFunded` — makes it non-exhaustive, and this test target stops
/// compiling with `error[E0004]` naming the uncovered variant. That failure
/// happens at the merge, before any test runs, and cannot be silenced by
/// `#[ignore]`.
///
/// Verified by re-colliding (2026-09-02): adding a `Withdraw` variant to
/// `PosTransaction` produced
/// `error[E0004]: non-exhaustive patterns: '&PosTransaction::Withdraw { .. }' not covered`
/// pointing at this function. A freeze that has never been violated on purpose
/// is a freeze nobody has tested.
fn frozen_variant_space(tx: &PosTransaction) -> u8 {
    match tx {
        PosTransaction::Transfer { .. } => 0x01,
        PosTransaction::Deposit { .. } => 0x02,
        PosTransaction::Exit { .. } => 0x03,
        PosTransaction::Delegate { .. } => 0x04,
        PosTransaction::SlashingEvidence(_) => 0x05,
        PosTransaction::TransferV2 { .. } => 0x06,
        // NO wildcard arm. Adding one defeats the entire freeze.
    }
}

// ===========================================================================
//                              THE ASSERTIONS
// ===========================================================================

fn render_claims(claims: &[Claim]) -> String {
    let mut s = String::new();
    for c in claims {
        s.push_str(&format!(
            "      {:<48} {:>3} tip(s) / {:>3} head(s)   e.g. {}\n",
            c.name, c.tips, c.heads, c.example
        ));
    }
    s
}

fn contested_msg(space: &str, tag: u8, claims: &[Claim]) -> String {
    let mut s = format!(
        "\n\n  WIRE TAG COLLISION — {space} {tag:#04x} is CLAIMED BUT UNASSIGNED.\n\n  \
         Something in this tree has landed a meaning for {tag:#04x}. The frozen\n  \
         registry does not assign it, because these branches disagree:\n\n"
    );
    s.push_str(&render_claims(claims));
    s.push_str(
        "\n  Each of those decoders SUCCEEDS on the same block body and yields a\n  \
         different transaction and a different state root. Picking one is a\n  \
         CONSENSUS decision and belongs to the founder, not to this test.\n\n  \
         If the founder has ruled: edit TX_TAGS/FRAME_TAGS in\n  \
         crates/bloch-pos-committee/tests/wire_tag_registry.rs, move this byte\n  \
         from Contested to Released, and let the diff record the choice.\n  \
         Do NOT widen the table to make this test go quiet.\n",
    );
    s
}

/// Decode `tag` with every payload length up to 320 bytes and return the
/// variant name of the first shape that decodes. Debug's leading identifier is
/// the variant name, so this reads the tree's ACTUAL tag->variant binding
/// without naming any unreleased variant in code.
///
/// `None` means no payload of that length decoded (a one-way tag; a released
/// format may also need structured bytes rather than zeros).
fn decoded_variant_name(tag: u8) -> Option<String> {
    for pad in 0..=320usize {
        let mut bytes = vec![tag];
        bytes.extend(std::iter::repeat(0u8).take(pad));
        if let Ok(tx) = PosTransaction::from_canonical_bytes(&bytes) {
            let dbg = format!("{tx:?}");
            let name: String =
                dbg.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            return Some(name);
        }
    }
    None
}

/// The released space is exactly `0x01`-`0x06`. Verified against tag
/// `g4-node-20260901` by object id: no `0x07`/`0x08`/`0x09` has ever shipped.
///
/// Three ways a merge can break a released tag, and all three are checked:
///   * it stops being recognised (renumbered or dropped) — this build could
///     then not read blocks the network has already finalised;
///   * it still decodes, but to a DIFFERENT variant. That is the silent one;
///   * a ONE-WAY tag starts decoding. Silent in the same way, and invisible to
///     the name comparison, because the tree decodes it to exactly the name
///     the encoder gave it. Checked explicitly against `ONE_WAY_TX_TAGS`.
#[test]
fn released_transaction_tags_keep_their_meaning() {
    let mut unrecognised: Vec<String> = Vec::new();
    let mut repointed: Vec<String> = Vec::new();
    let mut newly_decodable: Vec<String> = Vec::new();

    for (tag, status) in TX_TAGS {
        let Status::Released { name, .. } = status else { continue };
        let one_way = ONE_WAY_TX_TAGS.contains(tag);

        if PosTransaction::from_canonical_bytes(&[*tag]) == Err(TxDecodeError::UnknownTag(*tag)) {
            unrecognised.push(format!("      {tag:#04x} ({name}) is no longer recognised at all"));
            continue;
        }
        match (one_way, decoded_variant_name(*tag)) {
            (true, Some(actual)) => newly_decodable.push(format!(
                "      {tag:#04x}  registered ONE-WAY (encoder name {name}) but this tree \
                 decodes it to {actual}"
            )),
            (true, None) => {}
            (false, Some(actual)) if &actual != name => repointed.push(format!(
                "      {tag:#04x}  registered as {name:<16} but this tree decodes {actual}"
            )),
            (false, _) => {}
        }
    }

    if unrecognised.is_empty() && repointed.is_empty() && newly_decodable.is_empty() {
        return;
    }

    let mut msg = String::from("\n\n  RELEASED WIRE TAGS CHANGED MEANING IN THIS TREE\n\n");
    if !repointed.is_empty() {
        msg.push_str("  Re-pointed (the silent kind — both decoders SUCCEED):\n");
        for l in &repointed {
            msg.push_str(l);
            msg.push('\n');
        }
    }
    if !newly_decodable.is_empty() {
        msg.push_str("\n  A one-way tag became decodable (equally silent):\n");
        for l in &newly_decodable {
            msg.push_str(l);
            msg.push('\n');
        }
    }
    if !repointed.is_empty() || !newly_decodable.is_empty() {
        msg.push_str(
            "\n  Each of these decodes the same block body into a different\n  \
             transaction, with a different post-state and a different state\n  \
             root. Nothing reports it: no UnknownTag, no error, no log line.\n  \
             A node on each side of this change finalises a different chain.\n",
        );
    }
    if !unrecognised.is_empty() {
        msg.push_str("\n  No longer recognised (this build cannot read finalised blocks):\n");
        for l in &unrecognised {
            msg.push_str(l);
            msg.push('\n');
        }
    }
    msg.push_str(
        "\n  If these changes are intended they are CONSENSUS changes: they need\n  \
         the founder's ruling and an edit to TX_TAGS recording it, not a silent\n  \
         merge. Do NOT edit the table merely to make this test go quiet.\n",
    );
    panic!("{msg}");
}

/// A released byte that a live branch gives a different meaning is the most
/// dangerous row in the table, because "it shipped" reads as "it is safe".
/// This test does not fail on the rivals existing — they are recorded facts —
/// it fails if the tree has adopted one.
#[test]
fn released_tags_with_live_rivals_still_hold_the_released_meaning() {
    let mut adopted: Vec<String> = Vec::new();
    for (tag, status) in TX_TAGS {
        let Status::Released { name, rivals } = status else { continue };
        if rivals.is_empty() {
            continue;
        }
        let one_way = ONE_WAY_TX_TAGS.contains(tag);
        let actual = decoded_variant_name(*tag);
        let broken = match (one_way, &actual) {
            (true, Some(_)) => true,
            (false, Some(a)) => a != name,
            _ => false,
        };
        if broken {
            adopted.push(format!(
                "\n\n  RELEASED BYTE {tag:#04x} HAS BEEN RE-POINTED TO A RIVAL MEANING.\n\n  \
                 Released as {name}; this tree answers {actual:?}.\n  \
                 Known rival claimants on live branches:\n\n{}\n  \
                 This byte is on the live chain. Changing it is not a rename —\n  \
                 it re-reads every block already finalised under the old meaning.\n",
                render_claims(rivals)
            ));
        }
    }
    if !adopted.is_empty() {
        panic!("{}", adopted.join(""));
    }
}

/// Tag `0x05` is the special case: a recognised tag that never produces a
/// transaction. Pinned separately so a merge cannot quietly turn the
/// one-way evidence tag into a decodable format.
#[test]
fn evidence_tag_stays_one_way() {
    for pad in [0usize, 1, 4, 8, 32] {
        let mut bytes = vec![0x05u8];
        bytes.extend(std::iter::repeat(0u8).take(pad));
        assert_eq!(
            PosTransaction::from_canonical_bytes(&bytes),
            Err(TxDecodeError::EvidenceNotDecodable),
            "\n\n  Wire tag 0x05 must be one-way (EvidenceNotDecodable) for every\n  \
             payload. Six tips already decode it (see the 0x05 rival in TX_TAGS);\n  \
             a tree that does has adopted the nested sub-namespace inside 0x05,\n  \
             whose two sub-discriminants are bare literals bound to no constant\n  \
             and therefore invisible to any `const NAME: u8` sweep. Register it\n  \
             (EVIDENCE_SUBTAGS) before merging.\n"
        );
    }
}

/// **The merge-time assertion.** Every contested byte must be REFUSED by this
/// tree's decoder, under every payload shape. A branch that lands a meaning
/// for one stops refusing it, and this test names every rival claimant.
#[test]
fn contested_transaction_tags_are_refused() {
    let mut landed: Vec<(u8, &[Claim], String)> = Vec::new();
    for (tag, status) in TX_TAGS {
        let Status::Contested(claims) = status else { continue };
        // Several payload shapes, deliberately: a variant with one `u32`
        // field decodes happily from a 5-byte input while a bare tag byte
        // still fails as `Truncated`, and a zero-field variant decodes from
        // the bare byte alone. Requiring `UnknownTag` for ALL of them leaves
        // no shape that slips through.
        for pad in [0usize, 1, 4, 5, 8, 16, 32, 64, 256] {
            let mut bytes = vec![*tag];
            bytes.extend(std::iter::repeat(0u8).take(pad));
            let got = PosTransaction::from_canonical_bytes(&bytes);
            if got != Err(TxDecodeError::UnknownTag(*tag)) {
                landed.push((*tag, claims, format!("{got:?} for a {pad}-byte payload")));
                break;
            }
        }
    }
    if landed.is_empty() {
        return;
    }
    let mut msg = String::new();
    for (tag, claims, evidence) in &landed {
        msg.push_str(&contested_msg("PosTransaction tag", *tag, claims));
        msg.push_str(&format!("  (this tree's decoder answered {evidence})\n"));
    }
    panic!("{msg}");
}

/// The exhaustive match and the byte table must agree.
///
/// The match freezes the variant space; the table freezes the byte assignment.
/// This ties them together, so a merge that re-points an EXISTING variant to a
/// different byte — which keeps the match exhaustive and so compiles fine — is
/// still caught.
///
/// `SlashingEvidence` is absent: constructing one needs signed proposal
/// envelopes, and a hand-rolled fake would pin this test to the envelope
/// layout rather than to the tag. It is covered by `evidence_tag_stays_one_way`
/// and by the `0x05` arm of the match above.
#[test]
fn the_exhaustive_match_agrees_with_the_table() {
    let samples: Vec<PosTransaction> = vec![
        PosTransaction::Transfer {
            inputs: Vec::new(),
            outputs: Vec::new(),
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        },
        PosTransaction::Deposit {
            pubkey: vec![7u8; 4],
            amount_sat: 1,
            randao_commitment: [0u8; 32],
            withdrawal_credentials: vec![9u8; 4],
            commission_bps: 0,
        },
        PosTransaction::Exit { validator: 3 },
        PosTransaction::Delegate {
            delegator: 1,
            validator: 2,
            amount_sat: 5,
            eligible: true,
        },
        PosTransaction::TransferV2 {
            keys: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        },
    ];

    for tx in &samples {
        let want = frozen_variant_space(tx);
        let bytes = tx.canonical_bytes();
        assert_eq!(
            bytes[0], want,
            "\n\n  {tx:?} is frozen at {want:#04x} but this tree ENCODES it as {:#04x}.\n  \
             The variant space still compiles (the match is exhaustive), so nothing\n  \
             else catches this: the byte moved under a variant that already existed.\n",
            bytes[0]
        );

        let registered = TX_TAGS.iter().find(|(t, _)| *t == want).map(|(_, s)| s);
        match registered {
            Some(Status::Released { name, .. }) => {
                let dbg = format!("{tx:?}");
                let actual: String =
                    dbg.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                assert_eq!(
                    &actual, name,
                    "\n\n  Byte {want:#04x} is registered to {name} but the exhaustive match \
                     maps {actual} to it.\n"
                );
            }
            other => panic!(
                "\n\n  The exhaustive match maps {tx:?} to {want:#04x}, which the table \
                 records as {other:?}.\n  A variant encoding into unreleased space is a \
                 consensus change.\n"
            ),
        }
    }
}

/// No byte may be Released twice, and no byte may be both Released and
/// Contested. This guards the TABLE itself against a careless edit.
#[test]
fn the_table_is_internally_consistent() {
    let mut seen: Vec<u8> = Vec::new();
    for (tag, _) in TX_TAGS {
        assert!(!seen.contains(tag), "wire tag {tag:#04x} appears twice in TX_TAGS");
        seen.push(*tag);
    }
    let mut names: Vec<&str> = Vec::new();
    for (_, status) in TX_TAGS {
        if let Status::Released { name, .. } = status {
            assert!(!names.contains(name), "variant {name} is Released at two different tags");
            names.push(name);
        }
    }
    for tag in ONE_WAY_TX_TAGS {
        assert!(
            TX_TAGS
                .iter()
                .any(|(t, s)| t == tag && matches!(s, Status::Released { .. })),
            "one-way tag {tag:#04x} is not Released in TX_TAGS"
        );
    }
    let mut seen: Vec<u8> = Vec::new();
    for (tag, _) in FRAME_TAGS {
        assert!(!seen.contains(tag), "frame byte {tag:#04x} appears twice in FRAME_TAGS");
        seen.push(*tag);
    }
    let mut subs: Vec<u8> = Vec::new();
    for (name, v) in EVIDENCE_SUBTAGS {
        assert!(!subs.contains(v), "evidence subtag {v:#04x} ({name}) appears twice");
        subs.push(*v);
    }
}

// --- source-text checks for the namespaces that are consts, not behaviour ---

/// `net.rs` is read at COMPILE time out of the tree being tested, so this
/// check follows whatever a merge put there.
const NET_RS: &str = include_str!("../../bloch-pos-node/src/net.rs");
const PARAMS_RS: &str = include_str!("../src/params.rs");
const TRANSITION_RS: &str = include_str!("../src/transition.rs");

/// Parse `pub const NAME: u8 = 0xNN;` lines.
fn scan_u8_consts(src: &str, prefix: &str) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        let Some(idx) = line.find("const ") else { continue };
        let rest = &line[idx + 6..];
        let Some((name, tail)) = rest.split_once(':') else { continue };
        let name = name.trim();
        if !name.starts_with(prefix) {
            continue;
        }
        let Some((ty, val)) = tail.split_once('=') else { continue };
        if ty.trim() != "u8" {
            continue;
        }
        let val = val.trim().trim_end_matches(';').trim();
        let parsed = if let Some(h) = val.strip_prefix("0x") {
            u8::from_str_radix(h, 16).ok()
        } else {
            val.parse::<u8>().ok()
        };
        if let Some(v) = parsed {
            out.push((name.to_string(), v));
        }
    }
    out
}

/// The frame namespace has no compiler diagnostic of any kind, and its sibling
/// in-file guard is not on this lineage. This is the only thing standing
/// between it and a silent two-meanings-one-byte merge.
#[test]
fn frame_bytes_match_the_frozen_registry() {
    let found = scan_u8_consts(NET_RS, "FRAME_");
    assert!(!found.is_empty(), "no FRAME_* consts found in net.rs — did the path move?");

    // (a) a released byte must keep its released name
    for (tag, status) in FRAME_TAGS {
        let Status::Released { name, .. } = status else { continue };
        let actual: Vec<&String> = found.iter().filter(|(_, v)| v == tag).map(|(n, _)| n).collect();
        assert_eq!(
            actual.len(),
            1,
            "\n\n  Frame byte {tag:#04x} is released as {name} but this tree binds it to \
             {actual:?}.\n  Two names on one frame byte is invisible to rustc: net.rs matches\n  \
             `&FRAME_BLOCK` as a binding by reference, never as a literal.\n"
        );
        assert_eq!(
            actual[0], name,
            "\n\n  Frame byte {tag:#04x} is released as {name}; this tree calls it {}.\n",
            actual[0]
        );
    }

    // (b) a contested byte must not be bound at all. This is the half the
    //     sibling in-file guard cannot express.
    for (tag, status) in FRAME_TAGS {
        let Status::Contested(claims) = status else { continue };
        let actual: Vec<&String> = found.iter().filter(|(_, v)| v == tag).map(|(n, _)| n).collect();
        assert!(
            actual.is_empty(),
            "{}\n  (net.rs in this tree binds it to {:?})\n",
            contested_msg("frame byte", *tag, claims),
            actual
        );
    }

    // (c) within this ONE namespace, no value may carry two names. Same
    //     property the sibling guard checks, scanned rather than hard-coded.
    for i in 0..found.len() {
        for j in (i + 1)..found.len() {
            assert_ne!(
                found[i].1, found[j].1,
                "\n\n  Frame bytes {} and {} share the value {:#04x} in one namespace.\n  \
                 No diagnostic fires for this; the two become one frame on the wire.\n",
                found[i].0, found[j].0, found[i].1
            );
        }
    }
}

/// The two sub-discriminants nested inside tag `0x05`, which no `const` sweep
/// can see because they are bare literals. Read by source position: find the
/// `SlashingEvidence` encoder arm, then the `b.push(0xNN)` that follows each
/// offence family.
#[test]
fn evidence_subtags_match_the_frozen_registry() {
    let Some(start) = TRANSITION_RS.find("PosTransaction::SlashingEvidence(ev)") else {
        panic!("the SlashingEvidence encoder arm moved — re-anchor this check");
    };
    let arm = &TRANSITION_RS[start..(start + 2000).min(TRANSITION_RS.len())];

    for (family, want) in EVIDENCE_SUBTAGS {
        let needle = format!("SlashingEvidence::{family}");
        let Some(at) = arm.find(&needle) else {
            panic!(
                "\n\n  Evidence offence family {family} is registered at sub-tag {want:#04x}\n  \
                 inside wire tag 0x05, but it is not in the encoder arm any more.\n  \
                 This sub-namespace is bare literals bound to no constant, so nothing\n  \
                 else in this workspace can see it change.\n"
            );
        };
        let after = &arm[at..];
        let Some(p) = after.find("b.push(0x") else {
            panic!("no sub-tag push found after {family}");
        };
        let hex = &after[p + 9..p + 11];
        let got = u8::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("bad sub-tag hex {hex:?}"));
        assert_eq!(
            got, *want,
            "\n\n  EVIDENCE SUB-TAG RE-POINTED inside wire tag 0x05.\n\n  \
             {family} is registered at {want:#04x}; this tree emits {got:#04x}.\n\n  \
             Both sub-discriminants are bare literals bound to no constant, so a\n  \
             `const NAME: u8` sweep — the sweep every other namespace here is\n  \
             audited by — cannot see this. Two nodes disagreeing on this byte\n  \
             attribute an equivocation to the wrong offence family.\n"
        );
    }
}

/// Parse `pub const DS_NAME: [u8; 16] = *b"...";`
fn scan_ds(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(idx) = line.find("const DS_") else { continue };
        let rest = &line[idx + 6..];
        let Some((name, tail)) = rest.split_once(':') else { continue };
        let Some(open) = tail.find("*b\"") else { continue };
        let after = &tail[open + 3..];
        let Some(close) = after.find('"') else { continue };
        out.push((name.trim().to_string(), after[..close].to_string()));
    }
    out
}

/// Domain separators: one name, one string, and no string doing two jobs.
#[test]
fn domain_separators_match_the_frozen_registry() {
    let found = scan_ds(PARAMS_RS);
    assert!(!found.is_empty(), "no DS_* consts found in params.rs — did the path move?");

    for (name, value) in RELEASED_DS {
        let actual: Vec<&(String, String)> = found.iter().filter(|(n, _)| n == name).collect();
        assert_eq!(
            actual.len(),
            1,
            "\n\n  Released domain separator {name} is defined {} times in params.rs.\n",
            actual.len()
        );
        assert_eq!(
            &actual[0].1, value,
            "\n\n  Released domain separator {name} is bound to a DIFFERENT string in this\n  \
             tree.\n  released: {value}\n  here:     {}\n  \
             One name hashed two ways is a silent state-root split between nodes\n  \
             that ran different subsets of the work.\n",
            actual[0].1
        );
    }

    // No two separators may share a string — that is one hash domain doing
    // two jobs, which is the DS_ namespace's version of a tag collision.
    for i in 0..found.len() {
        for j in (i + 1)..found.len() {
            assert_ne!(
                found[i].1, found[j].1,
                "\n\n  Domain separators {} and {} share the byte string {:?}.\n",
                found[i].0, found[j].0, found[i].1
            );
        }
    }
}
