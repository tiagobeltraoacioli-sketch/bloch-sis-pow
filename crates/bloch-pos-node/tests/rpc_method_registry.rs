// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The frozen RPC method-NAME registry — layer 2
//!
//! ## Why a second file, and why it reads source instead of calling code
//!
//! `bloch-pos-node` is a `[[bin]]`-only crate: there is no lib target, so an
//! integration test cannot `use bloch_pos_node::rpc`. That is a constraint, and
//! it turns out to be the right shape anyway. The compile-time freeze needs the
//! `RpcRequest` type, so it lives INSIDE the crate at
//! `src/rpc/method_registry.rs`, attached by one `#[cfg(test)] mod` line in
//! `rpc.rs` — and a merge can delete a line. This file is auto-discovered by
//! cargo from `tests/`, needs no declaration anywhere, and therefore cannot be
//! detached by a merge that only edits `rpc.rs`. So it polices the attachment
//! as well as the names.
//!
//! No branch in this repository carries a file at this path (swept 2026-09-02
//! across every local and remote ref). A merge of any rival lands that branch's
//! `rpc.rs` and leaves this table untouched: the code changes, the frozen table
//! does not, and the assertions below go red naming the new name. It bites at
//! MERGE time, which is the moment that matters, not on the branch where each
//! tree looks fine.
//!
//! ## The hazard, executed and dated
//!
//! 2026-09-02. `rpc/build-identity-release` (998d1121) added `getbuildinfo`.
//! `dev/refusal-split-release-20260901` (5e39d7f6) added `getnodeversion`. Both
//! descend from tag `g4-node-20260901`, both answer *which binary is
//! answering?*, and merging them conflicted only in `build.rs` and
//! `rpc/tests.rs`. `rpc.rs` and `engine.rs` **auto-merged with zero conflict
//! markers**: both names routed, both variants dispatched, two implementations
//! of one answer shipped in one binary. Reproduced before this file was
//! written; the merged `route()` opened
//!
//! ```text
//!     "getnodeversion" => RpcRequest::NodeVersion,
//!     "getchaininfo"   => RpcRequest::ChainInfo,
//!     "getbuildinfo"   => RpcRequest::BuildInfo,
//! ```
//!
//! ## Aliases are allowed. Second implementations are not.
//!
//! `getutxos` and `listunspent` are one match arm, one variant, one
//! implementation — a Bitcoin-Core-compatible spelling for an integrator, not a
//! second answer. That shape is fine and is registered in `ALIAS_PAIRS`. What
//! is refused is a second VARIANT, which means a second body of code that can
//! drift from the first and report different fields for the same question.
//!
//! ## What this file cannot catch — read this before trusting it
//!
//! Stated plainly, because a guard whose limits are unstated gets trusted past
//! them, and three guards audited in this repo on 2026-09-01 were green while
//! the thing they guarded was broken:
//!
//! * **It cannot tell whether two DIFFERENT questions are really different.**
//!   `getchaininfo` and `getblockcount` both carry finality. A registry that
//!   tried to prove "one question, one method" in general would need a
//!   semantic taxonomy, would be wrong at the edges, and would be "fixed" by
//!   widening it. So the general property is enforced structurally (a new
//!   question needs a new variant, which fails to COMPILE against
//!   `src/rpc/method_registry.rs`), and only the identity question — the one
//!   with a live rival — is pinned by name.
//! * **It is a text scan of `route()`.** A method reachable by some other path
//!   — a second dispatcher, a proxy rewriting names, an `if` before the match —
//!   is invisible to it. It pins the match arms in `pub fn route`, nothing else.
//! * **It says nothing about behaviour.** Equal names do not mean equal
//!   answers. It cannot see a method that keeps its name and changes what it
//!   reports; that is what
//!   `the_surviving_identity_method_still_carries_the_field_it_was_chosen_for`
//!   in the sibling file is for, and even that only checks field presence.
//! * **It cannot police the fleet.** It proves what this SOURCE routes. Whether
//!   a running archival routes it is exactly the question `getbuildinfo`
//!   exists to answer, and the answer needs the node, not the test.
//! * **It counts nothing.** Deliberately: no line counts, no arm counts, no
//!   "the table has N entries". A count is satisfied by the wrong content.
//!   Every assertion below is set equality against named strings.

use std::path::PathBuf;

// ===========================================================================
//                    THE FROZEN TABLE — EDIT DELIBERATELY
// ===========================================================================
// Anything landing a new routed method MUST edit this table. That edit is the
// visible record of the choice. Do not "fix" a red test by widening the table
// without deciding, in the diff, that the new name is not a second answer to a
// question already answered.

/// `(method name, the `RpcRequest` variant it constructs)`.
///
/// The variant is recorded as the bare identifier as it appears in `route`,
/// because that is what a merge changes and what a source scan can read
/// without compiling anything.
const ROUTED: &[(&str, &str)] = &[
    ("getchaininfo", "ChainInfo"),
    ("getbuildinfo", "BuildInfo"),
    ("getblockcount", "BlockCount"),
    ("getblockbyslot", "BlockBySlot"),
    ("getblockbyid", "BlockById"),
    ("getvalidator", "Validator"),
    ("getvalidatorcount", "ValidatorCount"),
    ("getbalance", "Balance"),
    ("gettxout", "TxOut"),
    ("getutxos", "Utxos"),
    ("listunspent", "Utxos"),
    ("sendrawtransaction", "SendRawTransaction"),
    ("getmempoolinfo", "MempoolInfo"),
];

/// Names that are routed and answer with a REFUSAL rather than a variant.
///
/// They are methods that exist and say why they cannot help, deliberately —
/// "no such method" would send an integrator looking for a newer build. They
/// have no variant, so the scan below must expect them or trip on them.
const ROUTED_REFUSALS: &[&str] = &["gettransaction", "getnewaddress"];

/// Registered aliases: two names, ONE variant, one implementation.
///
/// This is the shape a second name is allowed to take. `listunspent` is the
/// Bitcoin-Core spelling of `getutxos`; they share a match arm, so there is
/// nothing that can drift between them.
const ALIAS_PAIRS: &[(&str, &str)] = &[("listunspent", "getutxos")];

/// The one method that answers *which binary is answering this port?*, and the
/// spellings that must NOT.
///
/// `getnodeversion` is measured, not hypothetical: it is on
/// `dev/refusal-split-release-20260901` (5e39d7f6), which still sits on
/// `origin` and `github` and is therefore still merge-reachable today.
const IDENTITY_METHOD: &str = "getbuildinfo";
const RIVAL_IDENTITY_SPELLINGS: &[&str] =
    &["getnodeversion", "getversion", "getidentity", "getbuild", "getnodeinfo"];

// ===========================================================================
//                              THE SCAN
// ===========================================================================

fn rpc_source() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/rpc.rs");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Extract the body of `pub fn route(...)` by brace balance.
fn route_body(src: &str) -> String {
    let start = src
        .find("pub fn route(method: &str")
        .expect("`pub fn route` has moved or been renamed — the scan is blind, fix it");
    let open = src[start..].find('{').expect("route has a body") + start;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open..open + i + 1].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in `route`");
}

/// Every `(name, variant-or-REFUSAL)` the match arms in `route` bind.
///
/// Arms sit at eight spaces of indent inside `Ok(match method {`. Each arm may
/// carry several `"name"` literals before its `=>` (that is an alias).
fn scan_arms(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('"') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent != 8 {
            continue;
        }
        let Some(arrow) = trimmed.find("=>") else { continue };
        let (head, tail) = trimmed.split_at(arrow);

        // Names: every string literal left of the `=>`.
        let mut names = Vec::new();
        let bytes: Vec<char> = head.chars().collect();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == '"' {
                let mut j = i + 1;
                let mut s = String::new();
                while j < bytes.len() && bytes[j] != '"' {
                    s.push(bytes[j]);
                    j += 1;
                }
                names.push(s);
                i = j + 1;
            } else {
                i += 1;
            }
        }

        // The variant, or the marker for a deliberate refusal.
        let target = if tail.contains("return Err(") {
            "REFUSAL".to_string()
        } else if let Some(k) = tail.find("RpcRequest::") {
            tail[k + "RpcRequest::".len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        } else {
            // A block arm: the variant is constructed further down. Find the
            // first `RpcRequest::` after this line, within the body.
            let after = body.split(trimmed).nth(1).unwrap_or("");
            match after.find("RpcRequest::") {
                Some(k) => after[k + "RpcRequest::".len()..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect(),
                None => "UNRESOLVED".to_string(),
            }
        };
        for n in names {
            out.push((n, target.clone()));
        }
    }
    out
}

// ===========================================================================
//                              THE ASSERTIONS
// ===========================================================================

/// **The merge-time assertion.** The routed method-name set is exactly the
/// frozen table — no name added, none removed, none re-pointed.
///
/// This is the half the compile-time freeze cannot express. A second name wired
/// to an EXISTING variant keeps the match exhaustive and compiles fine; only a
/// name table catches it.
#[test]
fn the_routed_method_set_is_frozen() {
    let arms = scan_arms(&route_body(&rpc_source()));

    let mut expected: Vec<(String, String)> = ROUTED
        .iter()
        .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
        .chain(
            ROUTED_REFUSALS
                .iter()
                .map(|n| ((*n).to_string(), "REFUSAL".to_string())),
        )
        .collect();
    let mut got = arms.clone();
    expected.sort();
    got.sort();

    if got == expected {
        return;
    }

    let added: Vec<_> = got.iter().filter(|x| !expected.contains(x)).collect();
    let gone: Vec<_> = expected.iter().filter(|x| !got.contains(x)).collect();

    let mut msg = String::from("\n\n  THE ROUTED RPC METHOD SET CHANGED.\n\n");
    if !added.is_empty() {
        msg.push_str("  Newly routed in this tree (not in the frozen table):\n");
        for (n, v) in &added {
            msg.push_str(&format!("      {n:<24} -> RpcRequest::{v}\n"));
        }
        msg.push_str(
            "\n  Before widening the table, answer one question: does this name\n  \
             answer a question an existing method already answers? On 2026-09-02\n  \
             two branches off tag g4-node-20260901 each added a method for\n  \
             \"which binary is answering?\" — `getbuildinfo` and `getnodeversion` —\n  \
             and they MERGED WITH NO CONFLICT MARKER in rpc.rs or engine.rs.\n  \
             Both routed, both dispatched, two implementations of one answer.\n\n  \
             If the answer is yes, make it an ALIAS: a second `\"name\" =>` on the\n  \
             SAME match arm, one implementation behind it, the way `listunspent`\n  \
             aliases `getutxos`. Then register it in ALIAS_PAIRS below.\n  \
             If it is genuinely a new question, add it to ROUTED and let the diff\n  \
             record that decision.\n",
        );
    }
    if !gone.is_empty() {
        msg.push_str("\n  Registered but no longer routed (integrators lose a method):\n");
        for (n, v) in &gone {
            msg.push_str(&format!("      {n:<24} -> RpcRequest::{v}\n"));
        }
    }
    msg.push_str("\n  Do NOT edit the table merely to make this test go quiet.\n");
    panic!("{msg}");
}

/// Exactly one routed name answers the identity question.
///
/// Separate from the set check on purpose: the set check goes red for any
/// change at all, and this one says WHY the change is dangerous when the change
/// is the identity method. It also survives someone "fixing" the set check by
/// pasting the new name into `ROUTED`.
#[test]
fn exactly_one_routed_name_answers_the_identity_question() {
    let arms = scan_arms(&route_body(&rpc_source()));
    let names: Vec<&str> = arms.iter().map(|(n, _)| n.as_str()).collect();

    assert!(
        names.contains(&IDENTITY_METHOD),
        "\n\n  `{IDENTITY_METHOD}` is no longer routed. It is the only method that\n  \
         answers \"which binary is answering?\", and the rule we published to a\n  \
         partner exchange — trust a read only when two nodes agree — is\n  \
         unfalsifiable without it.\n"
    );

    let landed: Vec<&&str> = RIVAL_IDENTITY_SPELLINGS
        .iter()
        .filter(|r| names.contains(&**r))
        .collect();
    if landed.is_empty() {
        return;
    }
    panic!(
        "\n\n  A SECOND METHOD ANSWERS THE IDENTITY QUESTION: {landed:?}\n\n  \
         `{IDENTITY_METHOD}` already answers it. Two spellings means the\n  \
         two-nodes-agree check has two answers on the day it first matters, and\n  \
         these two do not report the same fields: the survivor reports\n  \
         `source_digest`, computed from the bytes that were compiled, which no\n  \
         environment variable can move. `getnodeversion` reported `commit`,\n  \
         which BLOCH_BUILD_COMMIT lets any builder assert.\n\n  \
         Alias it onto the same arm, or drop it. Do not ship both.\n"
    );
}

/// Registered aliases really are aliases: same variant, therefore one
/// implementation.
///
/// If someone "aliases" a name by giving it its own variant, this catches it —
/// that is a second implementation wearing an alias's clothes.
#[test]
fn registered_aliases_share_one_implementation() {
    let arms = scan_arms(&route_body(&rpc_source()));
    for (alias, canonical) in ALIAS_PAIRS {
        let a = arms.iter().find(|(n, _)| n == alias).map(|(_, v)| v.clone());
        let c = arms.iter().find(|(n, _)| n == canonical).map(|(_, v)| v.clone());
        assert_eq!(
            a, c,
            "\n\n  `{alias}` is registered as an alias of `{canonical}` but they build\n  \
             DIFFERENT variants ({a:?} vs {c:?}). That is a second implementation,\n  \
             not an alias: the two can drift and report different answers to one\n  \
             question. Put both names on the same match arm.\n"
        );
        assert!(a.is_some(), "`{alias}` is registered as an alias but is not routed");
    }
}

/// **Layer 1 must still be attached.**
///
/// The compile-time freeze lives inside the crate and is attached by a single
/// `#[cfg(test)] mod method_registry;` line in `rpc.rs`. A merge that rewrites
/// the bottom of `rpc.rs` could drop that line, and the freeze would vanish
/// silently — a guard that can be detached by the merge it guards against is
/// not a guard. This file cannot be detached (cargo discovers `tests/`), so it
/// holds the other one on.
#[test]
fn the_compile_time_freeze_is_still_attached() {
    let src = rpc_source();
    assert!(
        src.contains("mod method_registry;"),
        "\n\n  `rpc.rs` no longer declares `mod method_registry;`.\n  \
         The compile-time freeze over the RpcRequest variant space is DETACHED:\n  \
         a merge can now add a variant — a second method answering an existing\n  \
         question — and nothing will fail to compile. Restore the declaration at\n  \
         the bottom of rpc.rs.\n"
    );
    let f = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/rpc/method_registry.rs");
    assert!(
        f.is_file(),
        "\n\n  {} is missing. The exhaustive `frozen_method_space` match — the\n  \
         layer that makes adding a variant an error[E0004] rather than a quiet\n  \
         merge — does not exist in this tree.\n",
        f.display()
    );
    let reg = std::fs::read_to_string(&f).unwrap();
    // The freeze is the ABSENCE of a wildcard arm. If someone adds one to make
    // a merge compile, the whole layer is inert and nothing else would notice.
    let body_start = reg.find("fn frozen_method_space").expect("the freeze function is gone");
    let body_end = reg[body_start..].find("\n}").expect("unterminated") + body_start;
    let body = &reg[body_start..body_end];
    assert!(
        !body.contains("_ =>"),
        "\n\n  `frozen_method_space` has grown a wildcard arm. That defeats the\n  \
         entire compile-time freeze: a merge can add an RpcRequest variant and\n  \
         it will compile silently. Remove the `_ =>` arm and add the variant\n  \
         explicitly, which is the visible act the registry exists to force.\n"
    );
}
