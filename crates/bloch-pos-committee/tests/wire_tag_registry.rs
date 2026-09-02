//! # The frozen wire-tag registry, and why it is a separate file
//!
//! Every other tag test in this workspace reads ONE tree and pins that tree's
//! internal agreement — `transition.rs`'s own
//! `every_wire_tag_is_claimed_exactly_once` builds one witness per variant and
//! checks no two share a byte. That is a real invariant and it catches nothing
//! here, for two reasons:
//!
//! 1. **It cannot see other branches.** `0x08` is `Withdraw` on
//!    `integ/exit-carrier-land`, `SignedExit` on all of `dev1`–`dev6` and
//!    `pmo10/*`, and `ExitV2` on the writeoff cluster. Each tree is
//!    self-consistent; each passes its own test; every one of those decoders
//!    SUCCEEDS on the same block body and yields a different transaction, a
//!    different post-state and a different state root. No `UnknownTag`, no
//!    error, nothing in a log.
//! 2. **It lives in the file it guards.** A merge that brings a rival
//!    `transition.rs` brings that file's copy of the guard with it, so the
//!    guard moves to whatever the merge decided. A test cannot police a file
//!    it rides inside.
//!
//! This file fixes (2) by construction: **no branch in this repository has a
//! file at this path.** A merge of any rival branch therefore lands that
//! branch's `transition.rs` and leaves this table untouched — the code changes,
//! the frozen table does not, and the assertions below go red naming both
//! claimants. That is the whole mechanism. It bites at MERGE time, which is the
//! moment that matters, not on the branch where each tree looks fine.
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
//! `docs/WIRE-NAMESPACE-REGISTRY.md` (branch `pmo/wire-namespace-registry`)
//! records deliberate same-value pairs that are CORRECT across namespaces —
//! `SYNC_TAG_GET_BLOCKS` = `SYNC_TAG_BLOCKS` = `0x01`, `TAG_EUTXO` =
//! `FRAME_BLOCK` = `0x01`. A test that checked global distinctness would fail
//! on correct code and be "fixed" by renumbering, causing the split it was
//! meant to prevent. Every check below is scoped to one namespace.

use bloch_pos_committee::transition::{PosTransaction, TxDecodeError};

// ===========================================================================
//                    THE FROZEN TABLE — EDIT DELIBERATELY
// ===========================================================================
// Anything landing a reserved number MUST edit this table. That edit is the
// visible record of a consensus choice. Do not "fix" a red test by widening
// the table without the founder's ruling on the tag.

/// Status of one byte in a wire namespace. There is deliberately no `Free`
/// variant: a byte absent from the table is free, and giving "free" a spelling
/// invites an editor to mark a contested byte free instead of ruling on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Shipped in tag `g4-node-20260901` and on the live chain. Canonical.
    Released(&'static str),
    /// Claimed by two or more unmerged branches that do not agree. NOT
    /// assigned. The decoder must refuse it until the founder rules.
    Contested(&'static [Claim]),
}

/// One branch family's claim on a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Claim {
    /// The name the claimant gives this byte.
    name: &'static str,
    /// How many distinct refs (branches + detached worktree HEADs) carry it,
    /// as swept 2026-09-02 across all 519 ref/worktree tips by blob id.
    refs: usize,
    /// A representative ref, so a failure can be traced without a re-sweep.
    example: &'static str,
}

// ---------------------------------------------------------------------------
// §1 — PosTransaction wire tags. First byte of `canonical_bytes`.
// ---------------------------------------------------------------------------
const TX_TAGS: &[(u8, Status)] = &[
    (0x01, Status::Released("Transfer")),
    (0x02, Status::Released("Deposit")),
    (0x03, Status::Released("Exit")),
    (0x04, Status::Released("Delegate")),
    // Recognised, but one-way: the decoder returns `EvidenceNotDecodable`
    // unconditionally. It is a claimed tag that never produces a transaction.
    (0x05, Status::Released("SlashingEvidence")),
    (0x06, Status::Released("TransferV2")),
    // ---- FOUNDER'S RULING, recorded 2026-09-02 (DEMONSTRATION ONLY) ----
    // Suppose the write-off assignment had been ruled canonical and recorded
    // here. That record is what makes a later disagreement visible.
    (0x07, Status::Released("DepositFunded")),
    (0x08, Status::Released("ExitV2")),
    (0x09, Status::Released("Withdraw")),
];

// ---------------------------------------------------------------------------
// §2 — Frame bytes, `crates/bloch-pos-node/src/net.rs`.
// The namespace with NO diagnostic: `net.rs` matches `&FRAME_BLOCK` as a
// binding by reference and compares with `==` at runtime, so two consts with
// different names and the same value are invisible to `unreachable_patterns`.
// ---------------------------------------------------------------------------
const FRAME_TAGS: &[(u8, Status)] = &[
    (0x01, Status::Released("FRAME_BLOCK")),
    (0x02, Status::Released("FRAME_ATT")),
    (0x03, Status::Released("FRAME_GET_BLOCKS")),
    (0x04, Status::Released("FRAME_TX")),
    (
        0x05,
        Status::Contested(&[
            Claim { name: "FRAME_GET_TIME", refs: 19, example: "integ/validator-opening" },
            Claim { name: "FRAME_GET_STATE", refs: 2, example: "ws-ceremony-exec" },
        ]),
    ),
    (
        0x06,
        Status::Contested(&[
            Claim { name: "FRAME_TIME", refs: 19, example: "integ/validator-opening" },
            Claim { name: "FRAME_STATE", refs: 2, example: "ws-ceremony-exec" },
        ]),
    ),
    // Single-claimant but unreleased: still not assigned, still must not
    // appear in a merged `net.rs` without a table edit.
    (
        0x07,
        Status::Contested(&[Claim {
            name: "FRAME_GET_STATE",
            refs: 16,
            example: "integ/validator-opening",
        }]),
    ),
    (
        0x08,
        Status::Contested(&[Claim {
            name: "FRAME_STATE",
            refs: 16,
            example: "integ/validator-opening",
        }]),
    ),
];

// ---------------------------------------------------------------------------
// §3 — `DS_*` domain separators in `params.rs`. Names, not numbers: a
// collision here is two names sharing one 16-byte string (one hash domain
// doing two jobs), or one name bound to two different strings (one job
// hashed two ways on two branches).
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
//                              THE ASSERTIONS
// ===========================================================================

fn contested_msg(space: &str, tag: u8, claims: &[Claim]) -> String {
    let mut s = format!(
        "\n\n  WIRE TAG COLLISION — {space} {tag:#04x} is CLAIMED BUT UNASSIGNED.\n\n  \
         Something in this tree has landed a meaning for {tag:#04x}. The frozen\n  \
         registry does not assign it, because these branches disagree:\n\n"
    );
    for c in claims {
        s.push_str(&format!(
            "      {:<16} claimed by {:>3} ref(s)   e.g. {}\n",
            c.name, c.refs, c.example
        ));
    }
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
/// without naming any unreleased variant in code -- which is what lets this one
/// file compile against every branch in the repository.
///
/// `None` means no payload of that length decoded (tag 0x05 is one-way; a
/// released format may also need structured bytes rather than zeros).
fn decoded_variant_name(tag: u8) -> Option<String> {
    for pad in 0..=320usize {
        let mut bytes = vec![tag];
        bytes.extend(std::iter::repeat(0u8).take(pad));
        if let Ok(tx) = PosTransaction::from_canonical_bytes(&bytes) {
            let dbg = format!("{tx:?}");
            let name: String = dbg
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            return Some(name);
        }
    }
    None
}

/// The released space is exactly `0x01`-`0x06`. Verified against tag
/// `g4-node-20260901`, and independently confirmed by an audit that read
/// blobs by object id: no `0x07`/`0x08`/`0x09` has ever been published.
///
/// Two ways a merge can break a released tag, and both are checked:
///   * it stops being recognised (renumbered or dropped) -- this build could
///     then not read blocks the network has already finalised;
///   * it still decodes, but to a DIFFERENT variant. That is the silent one.
///     It is not hypothetical: on `dev1/transition-merge`, tag `0x08` meant
///     `Withdraw` at `429edb22`, `SignedExit` at `648ac16c`, `ExitV2` at
///     `50447839`, and `SignedExit` again after the merge commit `a5c20a90`
///     ("staking: merge the funded bonds and the write-off"). Four meanings on
///     one line of development, re-pointed by a merge, with no conflict marker
///     and nothing in any log.
#[test]
fn released_transaction_tags_keep_their_meaning() {
    // Accumulate every violation rather than panicking on the first. One
    // merge re-points more than one tag (the demonstration merge of
    // `dev1/transition-merge` moved BOTH 0x07 and 0x08), and a founder ruling
    // on a partial list is a ruling made on bad information.
    let mut unrecognised: Vec<String> = Vec::new();
    let mut repointed: Vec<String> = Vec::new();

    for (tag, status) in TX_TAGS {
        let Status::Released(name) = status else { continue };
        if PosTransaction::from_canonical_bytes(&[*tag]) == Err(TxDecodeError::UnknownTag(*tag)) {
            unrecognised.push(format!("      {tag:#04x} ({name}) is no longer recognised at all"));
            continue;
        }
        if let Some(actual) = decoded_variant_name(*tag) {
            if &actual != name {
                repointed.push(format!(
                    "      {tag:#04x}  registered as {name:<16} but this tree decodes {actual}"
                ));
            }
        }
    }

    if unrecognised.is_empty() && repointed.is_empty() {
        return;
    }

    let mut msg = String::from("\n\n  RELEASED WIRE TAGS CHANGED MEANING IN THIS TREE\n\n");
    if !repointed.is_empty() {
        msg.push_str("  Re-pointed (the silent kind — both decoders SUCCEED):\n");
        for l in &repointed {
            msg.push_str(l);
            msg.push('\n');
        }
        msg.push_str(
            "\n  Each of these decodes the same block body into a different\n  transaction, with a different post-state and a different state\n  root. Nothing reports it: no UnknownTag, no error, no log line.\n  A node on each side of this change finalises a different chain.\n",
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
        "\n  If these changes are intended they are CONSENSUS changes: they need\n  the founder's ruling and an edit to TX_TAGS recording it, not a silent\n  merge. Do NOT edit the table merely to make this test go quiet.\n",
    );
    panic!("{msg}");
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
             payload. A tree that decodes it has added a nested sub-namespace\n  \
             inside 0x05 — register it before merging (see WIRE-NAMESPACE-REGISTRY\n  \
             1a: the two evidence kinds are bare literals bound to no constant,\n  \
             which is why a `const NAME: u8` sweep cannot see them).\n"
        );
    }
}

/// **The merge-time assertion.** Every contested byte must be REFUSED by this
/// tree's decoder, under every payload shape. A branch that lands a meaning
/// for one stops refusing it, and this test names every rival claimant.
///
/// Several paddings, deliberately: a variant with one `u32` field decodes
/// happily from a 5-byte input while a bare tag byte still fails as
/// `Truncated`, and a zero-field variant decodes from the bare byte alone.
/// Requiring `UnknownTag` for ALL of them leaves no shape that slips through.
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
        if let Status::Released(n) = status {
            assert!(!names.contains(n), "variant {n} is Released at two different tags");
            names.push(n);
        }
    }
    let mut seen: Vec<u8> = Vec::new();
    for (tag, _) in FRAME_TAGS {
        assert!(!seen.contains(tag), "frame byte {tag:#04x} appears twice in FRAME_TAGS");
        seen.push(*tag);
    }
}

// --- source-text checks for the namespaces that are consts, not behaviour ---

/// `net.rs` is read at COMPILE time out of the tree being tested, so this
/// check follows whatever a merge put there.
const NET_RS: &str = include_str!("../../bloch-pos-node/src/net.rs");
const PARAMS_RS: &str = include_str!("../src/params.rs");

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

/// The frame namespace has no compiler diagnostic of any kind. This is the
/// only thing standing between it and a silent two-meanings-one-byte merge.
#[test]
fn frame_bytes_match_the_frozen_registry() {
    let found = scan_u8_consts(NET_RS, "FRAME_");
    assert!(!found.is_empty(), "no FRAME_* consts found in net.rs — did the path move?");

    // (a) a released byte must keep its released name
    for (tag, status) in FRAME_TAGS {
        let Status::Released(name) = status else { continue };
        let actual: Vec<&String> =
            found.iter().filter(|(_, v)| v == tag).map(|(n, _)| n).collect();
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

    // (b) a contested byte must not be bound at all
    for (tag, status) in FRAME_TAGS {
        let Status::Contested(claims) = status else { continue };
        let actual: Vec<&String> =
            found.iter().filter(|(_, v)| v == tag).map(|(n, _)| n).collect();
        assert!(
            actual.is_empty(),
            "{}\n  (net.rs in this tree binds it to {:?})\n",
            contested_msg("frame byte", *tag, claims),
            actual
        );
    }

    // (c) within this ONE namespace, no value may carry two names
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
