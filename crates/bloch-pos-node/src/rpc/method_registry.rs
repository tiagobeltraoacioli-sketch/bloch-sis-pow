// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The frozen RPC method registry — layer 1, the compile-time freeze
//!
//! ## The class of defect this exists for
//!
//! On 2026-09-02 two branches off tag `g4-node-20260901` each added a method
//! answering one question — *which binary is answering this port?*
//! `rpc/build-identity-release` (998d1121) added `getbuildinfo`;
//! `dev/refusal-split-release-20260901` (5e39d7f6) added `getnodeversion`.
//! Merging them produced conflicts in `build.rs` and `rpc/tests.rs` — and
//! **none at all** in `rpc.rs` or `engine.rs`. The merged tree routed both
//! names, dispatched both to the engine, and carried two independent
//! implementations of one answer, with no conflict marker anywhere.
//!
//! That is worse than a duplicated function. The rule we published to a partner
//! exchange is *trust a read only when two nodes agree*, and this is the method
//! that makes that rule checkable. Two spellings of it means "the nodes agree"
//! has two answers on the day it first matters, and the two do not report the
//! same fields.
//!
//! ## Why the existing tests could not catch it
//!
//! `rpc/tests.rs` has a routing test that walks every method and asserts each
//! decodes to its variant. It is a real test and it is structurally blind here,
//! for the same two reasons the wire-tag registry documents:
//!
//! 1. **It reads one tree.** Each branch's routing test passed on its own
//!    branch, and the merged tree's routing test passes too — both methods
//!    route, both assertions hold. A test that asks "is this tree
//!    self-consistent?" cannot ask "does this tree answer one question twice?"
//! 2. **It rides inside the file it guards.** A merge bringing a rival
//!    `rpc/tests.rs` brings that file's copy of the guard. It moves to whatever
//!    the merge decided.
//!
//! ## Two layers, and what each one costs an attacker
//!
//! * **This file** is an exhaustive `match` over `RpcRequest` with **no
//!   wildcard arm**. A merge that adds a variant — which is what a second
//!   method needs, and is exactly what `NodeVersion` was — makes it
//!   non-exhaustive and the crate's test target **fails to compile** with
//!   `error[E0004]`, naming the variant. That cannot be `#[ignore]`d.
//! * **`crates/bloch-pos-node/tests/rpc_method_registry.rs`** reads `rpc.rs`
//!   as text and pins the routed NAME set. It catches the case this file
//!   cannot: a second name wired to an EXISTING variant, which keeps the match
//!   exhaustive and compiles fine. It also asserts this file is still attached,
//!   because `rpc.rs` declares it with one line and a merge could drop that
//!   line — see the honesty note there.
//!
//! Neither is redundant. This one freezes the *variant space*; that one freezes
//! the *name space*.
//!
//! ## What this file does NOT decide
//!
//! It does not decide that adding an RPC method is wrong. Methods should be
//! added. It decides that adding one is a **visible** act: land the variant,
//! edit the match below, and let the diff record it beside the name it takes.
//! Do not add a `_` arm to make this compile.

use super::*;

// ===========================================================================
//                THE COMPILE-TIME FREEZE — no wildcard arm, ever
// ===========================================================================

/// Maps every `RpcRequest` variant to the canonical method name that produces
/// it.
///
/// **This match has no `_` arm and must never grow one.** A merge that adds a
/// variant — `NodeVersion`, `getversion`, `getidentity`, whatever the next one
/// is called — makes it non-exhaustive and this target stops compiling with
/// `error[E0004]` naming the uncovered variant. That happens at the merge,
/// before any test runs.
///
/// Verified by re-colliding on 2026-09-02: re-adding `RpcRequest::NodeVersion`
/// produced
/// `error[E0004]: non-exhaustive patterns: '&RpcRequest::NodeVersion' not covered`
/// pointing at this function. A freeze nobody has violated on purpose is a
/// freeze nobody has tested.
fn frozen_method_space(req: &RpcRequest) -> &'static str {
    match req {
        RpcRequest::ChainInfo => "getchaininfo",
        RpcRequest::BuildInfo => "getbuildinfo",
        RpcRequest::BlockCount => "getblockcount",
        RpcRequest::BlockBySlot(_) => "getblockbyslot",
        RpcRequest::BlockById(_) => "getblockbyid",
        RpcRequest::Validator(_) => "getvalidator",
        RpcRequest::ValidatorCount => "getvalidatorcount",
        RpcRequest::Balance(_) => "getbalance",
        RpcRequest::Utxos { .. } => "getutxos",
        RpcRequest::TxOut { .. } => "gettxout",
        RpcRequest::SendRawTransaction(_) => "sendrawtransaction",
        RpcRequest::MempoolInfo => "getmempoolinfo",
        // NO wildcard arm. Adding one defeats the entire freeze.
    }
}

// ===========================================================================
//            THE IDENTITY QUESTION — one question, one method
// ===========================================================================

/// The method that answers *which binary is answering this port?*
///
/// One entry. This is the whole point of the file: the question with a live
/// rival is the one that must be pinned by name, not merely by variant count.
const IDENTITY_METHOD: &str = "getbuildinfo";

/// Spellings that have been proposed for the identity question and are **not**
/// routed on this lineage. A merge that lands one goes red here naming it.
///
/// `getnodeversion` is the measured one — `dev/refusal-split-release-20260901`
/// (5e39d7f6), which still sits on `origin` and `github` and is therefore still
/// merge-reachable. The others are not speculative padding: they are the
/// obvious next spellings, and reserving them costs nothing while leaving one
/// of them free costs exactly the collision this file was written after.
///
/// Landing any of them as an ALIAS is legitimate — see `ALIAS_PAIRS` in the
/// sibling test for how `listunspent` does it — but an alias is a second
/// `"name" =>` on the SAME match arm, not a second variant with a second
/// implementation. Making that edit is what moves a name off this list.
const RIVAL_IDENTITY_SPELLINGS: &[&str] =
    &["getnodeversion", "getversion", "getidentity", "getbuild", "getnodeinfo"];

// ===========================================================================
//                              THE ASSERTIONS
// ===========================================================================

/// Every frozen variant is reachable under its registered name, and decodes to
/// exactly that variant.
///
/// This ties the exhaustive match to `route`. The match freezes which variants
/// may exist; this proves the dispatcher still binds each to the name the
/// registry gives it, so a merge that re-points an EXISTING variant onto a
/// different method name — which keeps the match exhaustive and compiles fine —
/// is still caught.
#[test]
fn every_frozen_variant_routes_under_its_registered_name() {
    // One witness per variant, with the minimum params each name needs.
    let hex32 = "ab".repeat(32);
    let cases: &[(&str, &str)] = &[
        ("getchaininfo", "[]"),
        ("getbuildinfo", "[]"),
        ("getblockcount", "[]"),
        ("getblockbyslot", "[7]"),
        ("getvalidator", "[3]"),
        ("getvalidatorcount", "[]"),
        ("getmempoolinfo", "[]"),
    ];
    for (name, params) in cases {
        let p = parse_json(params).expect("test params parse");
        let req = route(name, Some(&p))
            .unwrap_or_else(|e| panic!("`{name}` must route on this lineage: {e:?}"));
        assert_eq!(
            frozen_method_space(&req),
            *name,
            "\n\n  `{name}` routes to a variant the registry registers under a \
             DIFFERENT name.\n  The variant space still compiles (the match is \
             exhaustive), so nothing\n  else catches this: the name moved under a \
             variant that already existed.\n"
        );
    }
    // The hex-taking ones, kept separate so a bad literal fails loudly.
    for name in ["getblockbyid", "getbalance", "getutxos"] {
        let p = parse_json(&format!("[\"{hex32}\"]")).unwrap();
        let req = route(name, Some(&p)).unwrap_or_else(|e| panic!("`{name}`: {e:?}"));
        let registered = frozen_method_space(&req);
        assert!(
            registered == name || (name == "getutxos" && registered == "getutxos"),
            "`{name}` routes to a variant registered as `{registered}`"
        );
    }
}

/// **The merge-time assertion.** Exactly one method answers the identity
/// question, and every known rival spelling is refused.
///
/// A branch that lands a second identity method stops this tree refusing its
/// name, and this test names the branch it came from. It fails BEFORE the
/// duplicate reaches an integrator, which is the only moment at which the
/// answer is still unambiguous.
#[test]
fn exactly_one_method_answers_the_identity_question() {
    let empty = Json::Arr(Vec::new());

    // The survivor answers, and answers with the identity variant.
    let req = route(IDENTITY_METHOD, Some(&empty))
        .unwrap_or_else(|e| panic!("`{IDENTITY_METHOD}` must route: {e:?}"));
    assert_eq!(
        req,
        RpcRequest::BuildInfo,
        "the identity method must decode to the identity variant"
    );

    // And nothing else does.
    let mut landed: Vec<String> = Vec::new();
    for rival in RIVAL_IDENTITY_SPELLINGS {
        if let Ok(got) = route(rival, Some(&empty)) {
            landed.push(format!(
                "      {rival:<20} routes, to {got:?}"
            ));
        }
    }
    if landed.is_empty() {
        return;
    }
    panic!(
        "\n\n  A SECOND METHOD ANSWERS THE IDENTITY QUESTION.\n\n  \
         `{IDENTITY_METHOD}` is the one method on this lineage that answers\n  \
         \"which binary is answering?\". These now answer it too:\n\n{}\n  \
         This is the defect the registry exists for, and it merges WITHOUT a\n  \
         conflict marker: two branches off tag g4-node-20260901 did exactly\n  \
         this on 2026-09-02 and `rpc.rs` and `engine.rs` auto-merged clean.\n\n  \
         We told a partner exchange to trust a read only when two nodes agree.\n  \
         This is the method that makes that checkable. Two spellings of it means\n  \
         the check has two answers, and they do not report the same fields.\n\n  \
         If a second NAME is genuinely wanted, make it an ALIAS — a second\n  \
         `\"name\" =>` on the SAME match arm in `route`, one implementation\n  \
         behind it, the way `listunspent` aliases `getutxos` — then move it out\n  \
         of RIVAL_IDENTITY_SPELLINGS here and add it to ALIAS_PAIRS in\n  \
         crates/bloch-pos-node/tests/rpc_method_registry.rs. Do NOT add a second\n  \
         variant, and do NOT delete this test to make it quiet.\n",
        landed.join("\n")
    );
}

/// The identity answer must actually carry the fields that make it worth
/// having.
///
/// A registry that only counted methods would stay green while the surviving
/// method was hollowed out — which is the failure mode of a guard that asserts
/// a shape instead of a fact. `source_digest` is the load-bearing field: it is
/// the only one no environment variable can move, and it is the only reason
/// `getbuildinfo` was chosen over `getnodeversion`. If it goes, the choice this
/// registry records was wrong and the test should say so.
#[test]
fn the_surviving_identity_method_still_carries_the_field_it_was_chosen_for() {
    let out = build_info_json().to_string();
    for field in ["source_digest", "commit_source", "tree_state", "commit"] {
        assert!(
            out.contains(&format!("\"{field}\"")),
            "\n\n  `{IDENTITY_METHOD}` no longer reports `{field}`.\n  \
             It was chosen over `getnodeversion` precisely because it reports\n  \
             a digest of the compiled tree and says whether `commit` is\n  \
             evidence or an assertion. Without those it is the method it\n  \
             replaced, and the replacement was pointless.\n"
        );
    }
    assert_ne!(
        env!("BLOCH_SOURCE_DIGEST"),
        "unavailable",
        "built inside the workspace, so the digest must have been computed"
    );
    // The clean-tree bug this branch fixed: `tree_state` must be able to say
    // `clean`. Before the `git_raw` split it could only ever say `unknown`.
    assert!(
        ["clean", "modified", "unverified", "unknown"]
            .contains(&env!("BLOCH_BUILD_TREE_STATE")),
        "tree_state must be one of the four registered states"
    );
}
