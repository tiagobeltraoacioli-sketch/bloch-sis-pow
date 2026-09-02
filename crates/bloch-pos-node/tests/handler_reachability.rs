//! Guard tests for handlers that no production path can reach.
//!
//! # Why these exist
//!
//! Three times in a row the same defect shipped and was found from outside:
//! a handler that is complete, tested and documented as a consensus rule,
//! which nothing in production ever calls.
//!
//!   * `unlock_epoch` — committed by genesis, never read by the crate that
//!     authorises spends. Found by an exchange, not by us; the doc comment
//!     asserted the opposite for weeks. Pinned by
//!     `bloch_pos_node::genesis::tests::vesting_is_not_enforced`.
//!   * `apply_exit` — complete and tested with zero production callers,
//!     while the live tag-`0x03` arm retired validators from a bare index
//!     with no signature at all. Wired up only on 2026-09-01, by the same
//!     commit that gave the signed exit a wire tag; before it, nothing would
//!     have failed if the wiring had never landed.
//!   * `apply_slashing_evidence` — one production call site, reachable only
//!     through a decoder that returns `EvidenceNotDecodable` unconditionally
//!     and by design. Live code nothing can reach.
//!
//! A comment cannot fail, and `cargo build` cannot fail either: every one of
//! these compiles, and `pub` suppresses the dead-code lint that would
//! otherwise have said so. So the claim has to be *checked* rather than
//! remembered, and it has to be checked in BOTH directions — a handler
//! becoming unreachable is a defect, and a handler declared unreachable
//! quietly becoming reachable is a consensus change that must not arrive
//! silently.
//!
//! These tests read the source at test time, exactly like
//! `vesting_is_not_enforced` and the frozen-RPC-namespace test. They are
//! deliberately not written against the compiled crate: the property is about
//! what the code *says*, and a call site that exists only inside `#[cfg(test)]`
//! is precisely the thing being caught.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// ─── source loading ─────────────────────────────────────────────────────────

fn crate_src(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn rust_files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap_or_else(|_| panic!("{} is readable", d.display())) {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let s = std::fs::read_to_string(&p).expect("utf-8 source");
                out.push((p, s));
            }
        }
    }
    out.sort();
    out
}

/// Every `.rs` file of the two crates that make a block apply: the consensus
/// crate and the node that drives it.
fn workspace_src() -> Vec<(PathBuf, String)> {
    let mut v = rust_files(&crate_src("../bloch-pos-committee/src"));
    let n = v.len();
    v.extend(rust_files(&crate_src("src")));
    // If either crate is moved or renamed, this test must not pass by looking
    // at nothing — the exact failure mode it exists to prevent.
    assert!(n > 5, "found only {n} files under bloch-pos-committee/src");
    assert!(
        v.len() - n > 5,
        "found only {} files under bloch-pos-node/src",
        v.len() - n
    );
    v
}

fn transition_rs() -> String {
    std::fs::read_to_string(crate_src("../bloch-pos-committee/src/transition.rs"))
        .expect("bloch-pos-committee/src/transition.rs is readable")
}

/// The line indices that live inside a `#[cfg(test)]` item, found by brace
/// matching from each COLUMN-ZERO `#[cfg(test)]` to the close of the item it
/// annotates.
///
/// # Why not "the first `#[cfg(test)]` and everything after"
///
/// Because it is wrong, and wrong in the direction that makes this whole test
/// lie. `bloch-pos-node/src/engine.rs` has TEN column-zero `#[cfg(test)]`
/// blocks interleaved with production code; taking the first at line 519 as a
/// boundary reclassifies four thousand lines of live consensus plumbing as
/// tests, and a first pass of this audit did exactly that and reported
/// `resolve_activations` and `deposit_pop_signing_root` as dead when both are
/// called from the transition. A reachability test that reads the source has
/// to get the source right; "found nothing, therefore nothing is there" is
/// the failure mode, not the answer.
///
/// Column zero on purpose too: an indented `#[cfg(test)]` annotates a
/// test-only item nested inside production code (`params::rehearsal`), and
/// the brace walk below handles it the same way — but anchoring on column
/// zero keeps the walk from starting inside a string or a doc example.
fn test_lines(src: &str) -> Vec<bool> {
    let lines: Vec<&str> = src.lines().collect();
    let mut mark = vec![false; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].starts_with("#[cfg(test)]") {
            i += 1;
            continue;
        }
        let (mut depth, mut j, mut opened) = (0i32, i, false);
        while j < lines.len() {
            for c in lines[j].chars() {
                match c {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            mark[j] = true;
            // A `#[cfg(test)]` on a `use` or a `const` has no body; it ends at
            // the first `;` before any brace opens.
            if opened && depth <= 0 {
                break;
            }
            if !opened && lines[j].trim_end().ends_with(';') && j > i {
                break;
            }
            j += 1;
        }
        i = j + 1;
    }
    mark
}

fn is_comment(l: &str) -> bool {
    let t = l.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

/// Body of the first item whose declaration line contains `header`, by brace
/// matching. Panics if the anchor is gone — a renamed function must break
/// this test loudly rather than make it vacuous.
fn body_of<'a>(src: &'a str, header: &str) -> &'a str {
    let at = src
        .find(header)
        .unwrap_or_else(|| panic!("anchor `{header}` no longer exists in transition.rs"));
    let open = at + src[at..].find('{').expect("an item body");
    let b = src.as_bytes();
    let (mut depth, mut i) = (0i32, open);
    while i < b.len() {
        match b[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open + 1..i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced braces after `{header}`")
}

// ─── the wire ───────────────────────────────────────────────────────────────

/// Every variant of `PosTransaction`, in declaration order.
fn variants(src: &str) -> Vec<String> {
    body_of(src, "pub enum PosTransaction")
        .lines()
        .filter(|l| !is_comment(l))
        .filter_map(|l| {
            let t = l.trim_end();
            // A variant is indented exactly four spaces at the top level of
            // the enum body; its payload opens with `{` or `(`, or it is a
            // unit variant ending in `,`.
            let name = t.strip_prefix("    ")?;
            if name.starts_with(' ') || name.starts_with('#') {
                return None;
            }
            let id: String = name
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let rest = &name[id.len()..];
            let looks_like_variant = rest.starts_with(" {")
                || rest.starts_with('(')
                || rest.starts_with('{')
                || rest == ",";
            (!id.is_empty() && id.starts_with(char::is_uppercase) && looks_like_variant)
                .then_some(id)
        })
        .collect()
}

fn hex_tag(s: &str) -> Option<u8> {
    s.strip_prefix("0x")
        .and_then(|h| u8::from_str_radix(h, 16).ok())
}

/// variant → the tag byte `canonical_bytes` writes for it: the first
/// `b.push(0x..)` after that variant's arm. (The nested pushes inside the
/// evidence arm are later, so taking the *first* is what makes this correct.)
fn encoder_tags(src: &str) -> BTreeMap<String, u8> {
    let enc = body_of(src, "pub fn canonical_bytes(&self)");
    let mut out = BTreeMap::new();
    for v in variants(src) {
        let pat = format!("PosTransaction::{v}");
        let at = enc
            .find(&pat)
            .unwrap_or_else(|| panic!("`{v}` has no arm in canonical_bytes — it cannot be sent"));
        let push = enc[at..]
            .find("b.push(0x")
            .unwrap_or_else(|| panic!("`{v}`'s encoder arm writes no tag byte"));
        let s = &enc[at + push + "b.push(".len()..];
        let tag = hex_tag(&s[..4]).unwrap_or_else(|| panic!("`{v}`: unreadable tag `{}`", &s[..4]));
        assert!(out.insert(v.clone(), tag).is_none(), "two arms for `{v}`");
    }
    out
}

/// The decoder's top-level arms: tag → whether the arm yields a transaction
/// (`true`) or refuses outright (`false`).
fn decoder_arms(src: &str) -> BTreeMap<u8, bool> {
    let dec = body_of(src, "pub fn from_canonical_bytes(bytes: &[u8])");
    let mut out = BTreeMap::new();
    for l in dec.lines() {
        if is_comment(l) {
            continue;
        }
        // Arms of the tag match sit at exactly twelve spaces of indent.
        let Some(t) = l.strip_prefix("            ") else {
            continue;
        };
        if t.starts_with(' ') {
            continue;
        }
        let Some((lhs, rhs)) = t.split_once("=>") else {
            continue;
        };
        let Some(tag) = hex_tag(lhs.trim()) else {
            continue;
        };
        out.insert(tag, !rhs.contains("return Err("));
    }
    out
}

/// Variants that `apply_transaction` has an arm for.
fn handled(src: &str) -> BTreeSet<String> {
    let app = body_of(src, "fn apply_transaction(");
    variants(src)
        .into_iter()
        .filter(|v| app.contains(&format!("PosTransaction::{v}")))
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Encoder, decoder and transition must agree about every wire tag.
// ────────────────────────────────────────────────────────────────────────────

/// A tag that `canonical_bytes` writes but `from_canonical_bytes` cannot
/// return is **write-only**: a proposer can put it in a block body and no
/// node — including the proposer replaying its own block — can ever recover
/// it. Any handler behind such a tag is unreachable code however complete it
/// is, which is exactly the `apply_slashing_evidence` defect.
///
/// Today there is exactly one, `0x05`, and it is deliberate: the evidence
/// encoder folds its nested messages in as the signing roots they were signed
/// over, and nothing recovers an envelope from a hash. That decision is
/// allowed to stand — it is not allowed to be *joined*, and it is not allowed
/// to be quietly reversed either. Both directions fail here.
const WRITE_ONLY_TAGS: &[(u8, &str)] = &[(
    0x05,
    "SlashingEvidence: the encoder folds the nested header/attestation in as \
     their signing roots, so evidence cannot be recovered from a block body. \
     §7.3 is therefore unreachable from the network however complete \
     slashing.rs is; it needs its own wire shape carrying both envelopes whole.",
)];

#[test]
fn every_wire_tag_decodes_to_the_variant_that_encodes_it() {
    let src = transition_rs();
    let enc = encoder_tags(&src);
    let dec = decoder_arms(&src);
    let handled = handled(&src);

    assert!(
        enc.len() >= 6,
        "only {} encoder arms found — this test is looking at nothing",
        enc.len()
    );

    let write_only: BTreeMap<u8, &str> = WRITE_ONLY_TAGS.iter().copied().collect();

    for (variant, tag) in &enc {
        // (a) Something can construct it and something can handle it.
        assert!(
            handled.contains(variant),
            "wire tag {tag:#04x} (`{variant}`) is encodable but `apply_transaction` has no arm \
             for it: a block carrying it would take an unwritten path.",
        );
        // (b) The decoder knows the tag at all. A tag with no arm falls to
        //     `UnknownTag`, which is a different and much quieter bug than a
        //     declared refusal.
        let Some(&yields) = dec.get(tag) else {
            panic!(
                "wire tag {tag:#04x} (`{variant}`) is written by `canonical_bytes` but \
                 `from_canonical_bytes` has no arm for it. Every node — the proposer \
                 included — will reject its own block body with `UnknownTag({tag:#04x})`.",
            );
        };
        // (c) And the two agree about whether the tag is supported.
        match (yields, write_only.get(tag)) {
            (true, None) | (false, Some(_)) => {}
            (false, None) => panic!(
                "wire tag {tag:#04x} (`{variant}`) is WRITE-ONLY: `canonical_bytes` emits it and \
                 `from_canonical_bytes` refuses it outright, so no node can recover it from a \
                 block body and `{variant}`'s handler is unreachable code. If this is deliberate \
                 — as {:#04x} is — add it to WRITE_ONLY_TAGS with the reason, and say so in the \
                 integration guide, because it bounds what the feature can be built on.",
                WRITE_ONLY_TAGS[0].0,
            ),
            (true, Some(why)) => panic!(
                "wire tag {tag:#04x} (`{variant}`) is listed in WRITE_ONLY_TAGS but the decoder \
                 now returns it. That is good news and it must not arrive silently: the reason \
                 recorded here says\n\n    {why}\n\nGo and correct that text — and the exchange \
                 integration guide, which repeats it — then drop the entry.",
            ),
        }
    }

    // No decoder arm for a tag nothing can produce: it would be an admission
    // path with no encoder to pin its shape, and `canonical_bytes_round_trips`
    // could not cover it.
    let encoded: BTreeSet<u8> = enc.values().copied().collect();
    for tag in dec.keys() {
        assert!(
            encoded.contains(tag),
            "`from_canonical_bytes` accepts tag {tag:#04x} but `canonical_bytes` never writes it: \
             the decoder is the only statement of that format's shape and nothing pins it.",
        );
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 2. Every consensus handler is reachable — or is declared unreachable here.
// ────────────────────────────────────────────────────────────────────────────

/// `l` mentions `sym` as a WHOLE identifier.
///
/// Substring matching is not good enough here and the difference is not
/// cosmetic: `validate_deposit_fields` contains `validate_deposit`, and the
/// two have opposite reachability — the fields half is what the transition
/// actually calls, the whole is the reference spec nothing calls. A
/// `contains()` here reports the dead function as live, which is the precise
/// error this file is written to prevent.
fn mentions(l: &str, sym: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(rel) = l[from..].find(sym) {
        let at = from + rel;
        let before_ok = at == 0 || !l[..at].chars().next_back().is_some_and(ident);
        let after = at + sym.len();
        let after_ok = !l[after..].chars().next().is_some_and(ident);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// How many production (non-`#[cfg(test)]`) references a symbol has across
/// the consensus crate and the node.
fn production_refs(sym: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut defined = false;
    for (p, s) in workspace_src() {
        let marks = test_lines(&s);
        // Whether we are inside a `use` item. Tracked across lines, not
        // matched on the opening line: the consensus crate re-exports the
        // staking rules through a multi-line `pub use staking::{ ... }`, and
        // a per-line match credits `validate_deposit` with a "call site" that
        // is a re-export — which is exactly how a dead rule looks alive, and
        // is the mistake this whole file exists to stop making.
        let mut in_use = false;
        for (i, l) in s.lines().enumerate() {
            let head = l.trim_start();
            let opens_use = head.starts_with("use ") || head.starts_with("pub use ");
            let was_in_use = in_use || opens_use;
            in_use = was_in_use && !l.trim_end().ends_with(';');

            if was_in_use || is_comment(l) || !mentions(l, sym) || marks[i] {
                continue;
            }
            // The definition is not a call site.
            if mentions(head, sym)
                && (head.starts_with("fn ")
                    || head.starts_with("pub fn ")
                    || head.starts_with("pub(crate) fn ")
                    || head.starts_with("pub(super) fn "))
            {
                defined = true;
                continue;
            }
            hits.push(format!("  {}:{}: {}", p.display(), i + 1, l.trim()));
        }
        // A trait method declaration counts as a definition too, so a symbol
        // that exists ONLY as an unimplemented trait method still satisfies
        // the "cannot pass by looking at nothing" guard rather than panicking.
        if !defined && s.contains(&format!("fn {sym}(")) {
            defined = true;
        }
    }
    assert!(
        defined,
        "`{sym}` is not defined anywhere under bloch-pos-committee/src or bloch-pos-node/src — \
         this test cannot pass by looking at nothing. If it was renamed, rename it here too.",
    );
    hits
}

/// The reachability ledger. `true` = a production path reaches it today and
/// must keep doing so; `false` = nothing production reaches it, and the
/// second column says why that is tolerable and what it costs.
///
/// **Both columns are load-bearing.** A `true` that goes to zero callers is
/// the `apply_exit` defect coming back. A `false` that gains one is a
/// consensus rule going live — which may be entirely correct, and still must
/// not happen without the prose that describes the chain being corrected in
/// the same commit.
const REACHABILITY: &[(&str, bool, &str)] = &[
    // ── reachable, and must stay so ─────────────────────────────────────────
    (
        "apply_transfer",
        true,
        "tag 0x01, the only unconditionally live transaction",
    ),
    (
        "apply_transfer_v2",
        true,
        "tag 0x06, behind TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH",
    ),
    (
        "apply_deposit_v2",
        true,
        "tag 0x07, behind FUNDED_STAKING_ACTIVATION_EPOCH",
    ),
    (
        "apply_exit",
        true,
        "tag 0x09, behind SIGNED_EXIT_ACTIVATION_EPOCH",
    ),
    (
        "validate_exit",
        true,
        "the exit rule, reached through apply_exit",
    ),
    (
        "validate_deposit_fields",
        true,
        "the deposit field rules, reached through apply_deposit_v2",
    ),
    (
        "apply_slashing_evidence",
        true,
        "one call site — see WRITE_ONLY_TAGS for what it is worth",
    ),
    // ── unreachable, deliberately, and it costs something ───────────────────
    (
        "validate_deposit",
        false,
        "REFERENCE SPEC ONLY. It is `validate_deposit_fields` + the proof of possession, and the \
         transition takes only the first half: `apply_deposit_v2` runs the PoP through its own \
         injected verifier. So the *rule* is enforced, but not by this function, and a reader who \
         greps for the deposit check finds a function no block ever executes. If a production \
         caller appears, say so in staking.rs's docs first.",
    ),
    (
        "validate_withdrawal",
        false,
        "REFERENCE SPEC ONLY, and stated as such in its own doc comment. It recomputes ripeness \
         from `exit_epoch + WITHDRAWAL_DELAY_EPOCHS`; the paying arm gates on the COMMITTED \
         `withdrawable_epoch`, which slashing extends. The two disagree exactly on the slashed \
         path, so wiring this in would be a consensus change, not a cleanup.",
    ),
    (
        "apply_delegation",
        false,
        "NO WIRE TAG REACHES IT. It carries the funded-delegation rules and sits behind \
         FUNDED_STAKING_ACTIVATION_EPOCH, but no `PosTransaction` variant carries a funded \
         delegation, so arming that gate would open funded deposits and leave delegation exactly \
         as dead as it is now. The gate is not the missing piece; the format is.",
    ),
];

#[test]
fn declared_reachability_matches_the_source() {
    let mut broke = Vec::new();
    for (sym, expect_reachable, why) in REACHABILITY {
        let hits = production_refs(sym);
        match (*expect_reachable, hits.is_empty()) {
            (true, true) => broke.push(format!(
                "`{sym}` HAS BECOME UNREACHABLE — zero production call sites. It is declared \
                 reachable here as: {why}.\nThis is the `apply_exit` defect: complete, tested, \
                 documented as a rule, and executed by nothing. Restore the call site, or move \
                 the entry to the unreachable half WITH the prose that says what stopped working.",
            )),
            (false, false) => broke.push(format!(
                "`{sym}` IS NOW REACHED FROM PRODUCTION:\n{}\n\nIt is declared unreachable here \
                 as:\n    {why}\n\nThat text, and the exchange integration guide that repeats it, \
                 are now wrong. Correct them, then flip this entry — enforcement arriving is good \
                 news that must not arrive silently.",
                hits.join("\n"),
            )),
            _ => {}
        }
    }
    assert!(broke.is_empty(), "\n\n{}\n", broke.join("\n\n"));
}

// ────────────────────────────────────────────────────────────────────────────
// 3. A gate that does not exist is not a gate at u64::MAX.
// ────────────────────────────────────────────────────────────────────────────

/// Each wire tag's flag-day gate and its value in `params.rs`. `None` means
/// the arm is gated by nothing at all — which for the legacy staking tags is
/// the point (no flag day reopens them; they are refused at every epoch), and
/// for `0x01` is that transfers are live.
///
/// The distinction this pins is the one a sibling audit got wrong: a gate at
/// `u64::MAX` is armed by editing one constant, while a gate that DOES NOT
/// EXIST cannot be armed at all, and reporting the second as the first tells
/// an exchange that a feature is one flag-day away when it is not.
const GATES: &[(u8, Option<(&str, &str)>)] = &[
    (0x01, None),
    (0x02, None),
    (0x03, None),
    (0x04, None),
    (0x05, None),
    (
        0x06,
        Some(("TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH", "800")),
    ),
    (0x07, Some(("FUNDED_STAKING_ACTIVATION_EPOCH", "u64::MAX"))),
    (0x08, Some(("WITHDRAWAL_ACTIVATION_EPOCH", "u64::MAX"))),
    (0x09, Some(("SIGNED_EXIT_ACTIVATION_EPOCH", "u64::MAX"))),
];

#[test]
fn every_declared_gate_exists_and_is_still_where_it_was_left() {
    let params = std::fs::read_to_string(crate_src("../bloch-pos-committee/src/params.rs"))
        .expect("params.rs is readable");
    let src = transition_rs();
    let tags: BTreeSet<u8> = encoder_tags(&src).values().copied().collect();

    for (tag, gate) in GATES {
        assert!(
            tags.contains(tag),
            "GATES still lists tag {tag:#04x}, which the encoder no longer writes.",
        );
        let Some((name, value)) = gate else { continue };
        let decl = format!("pub const {name}: u64 = {value};");
        assert!(
            params.contains(&format!("pub const {name}: u64 =")),
            "tag {tag:#04x}'s gate `{name}` is NOT DECLARED in params.rs. A missing gate is not \
             an unarmed gate: nothing can arm it, and the format behind it is unreachable by \
             construction rather than by a pending flag day.",
        );
        assert!(
            params.contains(&decl),
            "tag {tag:#04x}'s gate has moved: `{decl}` is no longer in params.rs.\nIf this is a \
             deliberate flag day, that is a consensus change — update this line in the SAME \
             commit, and check the exchange integration guide, which states these values.",
        );
    }

    // Every gate the transition actually reads must be one this table knows
    // about, so a new format cannot ship with an unrecorded flag day.
    let app = body_of(&src, "fn apply_transaction(");
    let known: BTreeSet<&str> = GATES
        .iter()
        .filter_map(|(_, g)| g.map(|(n, _)| n))
        .collect();
    for l in app.lines().filter(|l| !is_comment(l)) {
        for w in l.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if w.ends_with("_ACTIVATION_EPOCH") && !known.contains(w) {
                panic!(
                    "`apply_transaction` reads the flag day `{w}`, which is not in GATES. Add it \
                     with its tag and its value: an unrecorded gate is one nobody checks before \
                     telling an integrator what is live.",
                );
            }
        }
    }
}
