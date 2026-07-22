//! # Kirpich — Lane A: **module-conflict** rules
//!
//! Kirpich (кирпич, "brick") is the deterministic static audit that inspects an Ustav
//! [`TokenCharter`] *before* it is laid into the contract (compiled by
//! [`crate::modules::compile_charter`]) and **fails closed** on a real defect. This file
//! is one of four dev lanes; it owns the *composition/conflict* rules — contradictions
//! that live in how a charter's modules are put together, independent of the emitted
//! bytecode.
//!
//! ## Rules in this lane
//!
//! | Code    | Severity | What it catches |
//! |---------|----------|-----------------|
//! | KRP-001 | Deny     | More than one `Supply` module — the token's minting policy / asset id is ambiguous. |
//! | KRP-002 | Deny     | A `Governance` signer set with a duplicate pubkey — one signature counts twice, silently halving quorum. |
//! | KRP-003 | Deny     | A `Custody` module whose `btc_pubkey == pq_pubkey` — the hybrid 2-of-2 collapses to one key/algorithm. |
//! | KRP-004 | Warn     | The same pubkey reused across two *different* modules/roles — a separation-of-duties smell. |
//! | KRP-005 | Warn     | A duplicated non-`Supply` module kind — redundant/contradictory composition. |
//!
//! (`Supply` duplication is owned exclusively by KRP-001; a within-module duplicate — a
//! repeated governance signer, or `btc == pq` in one custody module — is owned by KRP-002
//! / KRP-003 respectively and is deliberately *not* re-reported as KRP-004 cross-role
//! reuse.)
//!
//! ## Integration contract (what the Integrate phase, `src/kirpich.rs`, provides)
//!
//! This file is compiled as `mod conflicts;` inside `src/kirpich.rs`, so it reaches the
//! shared audit types through `super::`:
//!
//! ```ignore
//! pub enum Severity { Deny = 0, Warn = 1, Info = 2 }   // Copy + Ord, most-severe first
//! pub struct Finding {
//!     pub code: &'static str,          // stable "KRP-NNN"
//!     pub severity: Severity,
//!     pub module: Option<&'static str>,// offending ModuleKind::tag(), or None (charter-level)
//!     pub index: Option<usize>,        // position in charter.modules, when module-specific
//!     pub message: String,             // deterministically formatted
//! }
//! ```
//!
//! The single entry point is [`audit`], which **appends** findings (never reorders — the
//! dispatcher sorts canonically once, over all lanes). Pure, deterministic, no
//! IO/clock/float/HashMap; every rule tolerates a malformed charter by emitting a Finding
//! (or nothing) rather than panicking.

use super::{Finding, Severity};
use crate::modules::{ModuleKind, TokenCharter};
use std::collections::{BTreeMap, BTreeSet};

/// Lane A entry point. Runs every module-conflict rule and **appends** their findings to
/// `out` in rule order (the caller sorts canonically across all lanes). Never panics.
pub(super) fn audit(charter: &TokenCharter, out: &mut Vec<Finding>) {
    krp001_multiple_supply(charter, out);
    krp002_duplicate_governance_signer(charter, out);
    krp003_custody_btc_eq_pq(charter, out);
    krp004_key_reuse_across_roles(charter, out);
    krp005_duplicate_module_kind(charter, out);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A deterministic, panic-free, non-UTF8-safe label for a pubkey: its length plus a
/// hex prefix of at most the first `MAX` bytes. Used in messages so byte blobs never
/// leak raw/invalid UTF-8 and the output stays byte-stable for a given charter.
fn key_label(b: &[u8]) -> String {
    const MAX: usize = 8;
    let mut s = String::new();
    s.push_str("len=");
    s.push_str(&b.len().to_string());
    s.push_str(" 0x");
    for byte in b.iter().take(MAX) {
        s.push_str(&format!("{byte:02x}"));
    }
    if b.len() > MAX {
        s.push_str("..");
    }
    s
}

/// The pubkey-bearing (role, key) pairs of a module, in a stable order. `KycConfig`
/// carries no key. This is the basis for cross-role reuse detection (KRP-004).
fn role_keys(m: &ModuleKind) -> Vec<(&'static str, &[u8])> {
    match m {
        ModuleKind::Supply(c) => vec![("issuer", c.issuer_pubkey.as_slice())],
        ModuleKind::TransferPolicy(c) => vec![("authority", c.authority_pubkey.as_slice())],
        ModuleKind::ComplianceKycGate(_) => Vec::new(),
        ModuleKind::Vesting(c) => vec![("beneficiary", c.beneficiary_pubkey.as_slice())],
        ModuleKind::Governance(c) => c
            .signers
            .iter()
            .map(|s| ("governance-signer", s.as_slice()))
            .collect(),
        ModuleKind::Custody(c) => vec![
            ("custody-btc", c.btc_pubkey.as_slice()),
            ("custody-pq", c.pq_pubkey.as_slice()),
        ],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-001 — multiple Supply modules (Deny)
// ─────────────────────────────────────────────────────────────────────────────

/// A token's identity *is* its minting policy: `CompiledToken::policy_id()` returns the
/// hash of the FIRST `Supply` module. A charter with two or more `Supply` modules is
/// therefore ambiguous — the asset id silently derives from whichever Supply happens to
/// be first. One Deny finding per Supply beyond the first.
fn krp001_multiple_supply(charter: &TokenCharter, out: &mut Vec<Finding>) {
    let idxs: Vec<usize> = charter
        .modules
        .iter()
        .enumerate()
        .filter(|(_, m)| matches!(m, ModuleKind::Supply(_)))
        .map(|(i, _)| i)
        .collect();
    if idxs.len() > 1 {
        for &i in idxs.iter().skip(1) {
            out.push(Finding {
                code: "KRP-001",
                severity: Severity::Deny,
                module: Some("supply"),
                index: Some(i),
                message: format!(
                    "charter declares {} Supply modules; a token has exactly one minting \
                     policy (its asset id) — Supply at index {i} is ambiguous",
                    idxs.len()
                ),
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-002 — duplicate Governance signer (Deny)
// ─────────────────────────────────────────────────────────────────────────────

/// `compile_governance` does NOT deduplicate `signers`; a pubkey listed twice lets one
/// real signature — reused across both of that key's redeemer slots — count twice toward
/// the threshold, silently halving the distinct keys required for quorum (see the
/// `governance_duplicate_signer_pubkey_lets_one_key_satisfy_two_slots` regression in
/// `modules.rs`). One Deny per distinct duplicated key, reported at first re-sighting so
/// the count of findings equals the number of over-listed keys.
fn krp002_duplicate_governance_signer(charter: &TokenCharter, out: &mut Vec<Finding>) {
    for (i, m) in charter.modules.iter().enumerate() {
        if let ModuleKind::Governance(g) = m {
            let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
            let mut reported: BTreeSet<&[u8]> = BTreeSet::new();
            for pk in &g.signers {
                let key = pk.as_slice();
                // `seen.insert` false => already present; `reported.insert` true => not
                // yet flagged. Together: flag each duplicated key exactly once.
                if !seen.insert(key) && reported.insert(key) {
                    out.push(Finding {
                        code: "KRP-002",
                        severity: Severity::Deny,
                        module: Some("governance"),
                        index: Some(i),
                        message: format!(
                            "Governance signer set contains a duplicate key ({}); one \
                             signature reused across both slots counts twice, silently \
                             halving quorum",
                            key_label(key)
                        ),
                    });
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-003 — Custody btc_pubkey == pq_pubkey (Deny)
// ─────────────────────────────────────────────────────────────────────────────

/// The Custody module is the hybrid-PQ 2-of-2: a Bitcoin (ECDSA) key AND a
/// post-quantum key must BOTH sign. If the two configured keys are byte-identical the
/// composition collapses to a single key/algorithm — the whole point (defence in depth
/// against a break of either curve) is defeated. Deny.
fn krp003_custody_btc_eq_pq(charter: &TokenCharter, out: &mut Vec<Finding>) {
    for (i, m) in charter.modules.iter().enumerate() {
        if let ModuleKind::Custody(c) = m {
            if c.btc_pubkey == c.pq_pubkey {
                out.push(Finding {
                    code: "KRP-003",
                    severity: Severity::Deny,
                    module: Some("custody"),
                    index: Some(i),
                    message: format!(
                        "Custody btc_pubkey == pq_pubkey ({}); the hybrid 2-of-2 collapses \
                         to a single key/algorithm, defeating post-quantum defence in depth",
                        key_label(&c.btc_pubkey)
                    ),
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-004 — key reuse across roles (Warn)
// ─────────────────────────────────────────────────────────────────────────────

/// The same pubkey serving two *different* module roles (e.g. the Supply issuer key is
/// also the TransferPolicy authority, or a Governance signer doubles as the Custody BTC
/// key) collapses controls that separation of duties assumes are independent. Advisory
/// (Warn), not fail-closed: it can be intentional.
///
/// Scoped to CROSS-module reuse only: a duplicate *within* one module — a repeated
/// governance signer, or `btc == pq` in one custody module — is owned by KRP-002 /
/// KRP-003 and is deliberately not double-reported here (the per-key map keys on the
/// module index, so a key appearing twice at the same index counts as one occurrence).
fn krp004_key_reuse_across_roles(charter: &TokenCharter, out: &mut Vec<Finding>) {
    // pubkey -> (module_index -> first role seen at that index). BTreeMaps keep both the
    // outer scan (by pubkey bytes) and the inner report (by index) deterministic.
    let mut map: BTreeMap<Vec<u8>, BTreeMap<usize, &'static str>> = BTreeMap::new();
    for (i, m) in charter.modules.iter().enumerate() {
        for (role, pk) in role_keys(m) {
            map.entry(pk.to_vec()).or_default().entry(i).or_insert(role);
        }
    }
    for (pk, occ) in &map {
        if occ.len() > 1 {
            if let Some(&last_idx) = occ.keys().last() {
                let where_: Vec<String> =
                    occ.iter().map(|(idx, role)| format!("{role}#{idx}")).collect();
                out.push(Finding {
                    code: "KRP-004",
                    severity: Severity::Warn,
                    module: None, // cross-cutting: spans >1 module
                    index: Some(last_idx),
                    message: format!(
                        "key {} is reused across {} roles [{}]; distinct roles should use \
                         distinct keys (separation of duties)",
                        key_label(pk),
                        occ.len(),
                        where_.join(", ")
                    ),
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRP-005 — duplicate (non-Supply) module kind (Warn)
// ─────────────────────────────────────────────────────────────────────────────

/// Two modules of the same kind rarely compose meaningfully: two TransferPolicies with
/// different authorities (which one governs?), two Vestings with different unlock heights
/// (contradictory), a second KYC gate, etc. Advisory (Warn) — the compiler will emit both
/// validators, so it is a composition smell rather than a hard defect. `Supply`
/// duplication is skipped here because KRP-001 owns it (as a Deny).
fn krp005_duplicate_module_kind(charter: &TokenCharter, out: &mut Vec<Finding>) {
    let mut first_seen: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (i, m) in charter.modules.iter().enumerate() {
        let tag = m.tag();
        if tag == "supply" {
            continue; // KRP-001 owns Supply duplication
        }
        if let Some(&first) = first_seen.get(tag) {
            out.push(Finding {
                code: "KRP-005",
                severity: Severity::Warn,
                module: Some(tag),
                index: Some(i),
                message: format!(
                    "duplicate {tag} module (first at index {first}, again at index {i}); \
                     redundant/contradictory composition — a token needs at most one {tag} guard"
                ),
            });
        } else {
            first_seen.insert(tag, i);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::{
        CustodyConfig, GovernanceConfig, SupplyConfig, TransferPolicyConfig, VestingConfig,
    };

    // ── construction helpers ──
    fn run(c: &TokenCharter) -> Vec<Finding> {
        let mut v = Vec::new();
        audit(c, &mut v);
        v
    }
    fn count(f: &[Finding], code: &str) -> usize {
        f.iter().filter(|x| x.code == code).count()
    }
    fn charter(mods: Vec<ModuleKind>) -> TokenCharter {
        TokenCharter { token_name: b"T".to_vec(), modules: mods }
    }
    fn supply(k: &[u8]) -> ModuleKind {
        ModuleKind::Supply(SupplyConfig { cap: 100, issuer_pubkey: k.to_vec() })
    }
    fn transfer(k: &[u8]) -> ModuleKind {
        ModuleKind::TransferPolicy(TransferPolicyConfig { authority_pubkey: k.to_vec() })
    }
    fn vesting(k: &[u8]) -> ModuleKind {
        ModuleKind::Vesting(VestingConfig { unlock_height: 10, beneficiary_pubkey: k.to_vec() })
    }
    fn gov(sigs: &[&[u8]], t: u32) -> ModuleKind {
        ModuleKind::Governance(GovernanceConfig {
            signers: sigs.iter().map(|s| s.to_vec()).collect(),
            threshold: t,
        })
    }
    fn custody(b: &[u8], p: &[u8]) -> ModuleKind {
        ModuleKind::Custody(CustodyConfig { btc_pubkey: b.to_vec(), pq_pubkey: p.to_vec() })
    }

    // ── KRP-001 ──
    #[test]
    fn krp001_multiple_supply_denies() {
        let f = run(&charter(vec![supply(b"a"), transfer(b"x"), supply(b"b")]));
        assert_eq!(count(&f, "KRP-001"), 1);
        assert!(f
            .iter()
            .any(|x| x.code == "KRP-001" && x.severity == Severity::Deny && x.index == Some(2)));
    }
    #[test]
    fn krp001_single_supply_passes() {
        assert_eq!(count(&run(&charter(vec![supply(b"a"), transfer(b"x")])), "KRP-001"), 0);
    }
    #[test]
    fn krp001_three_supply_flags_two() {
        // N supplies => N-1 findings (each beyond the first)
        assert_eq!(count(&run(&charter(vec![supply(b"a"), supply(b"b"), supply(b"c")])), "KRP-001"), 2);
    }

    // ── KRP-002 ──
    #[test]
    fn krp002_duplicate_governance_signer_denies() {
        let f = run(&charter(vec![gov(&[b"k", b"k", b"o"], 2)]));
        assert_eq!(count(&f, "KRP-002"), 1);
        assert!(f
            .iter()
            .any(|x| x.code == "KRP-002" && x.severity == Severity::Deny && x.index == Some(0)));
    }
    #[test]
    fn krp002_distinct_signers_pass() {
        assert_eq!(count(&run(&charter(vec![gov(&[b"a", b"b", b"c"], 2)])), "KRP-002"), 0);
    }
    #[test]
    fn krp002_reports_each_duplicated_key_once() {
        // k appears 3x, m appears 2x => 2 findings (one per distinct duplicated key)
        assert_eq!(count(&run(&charter(vec![gov(&[b"k", b"k", b"k", b"m", b"m"], 2)])), "KRP-002"), 2);
    }

    // ── KRP-003 ──
    #[test]
    fn krp003_custody_btc_eq_pq_denies() {
        let f = run(&charter(vec![custody(b"same", b"same")]));
        assert_eq!(count(&f, "KRP-003"), 1);
        assert!(f.iter().any(|x| x.code == "KRP-003" && x.severity == Severity::Deny));
    }
    #[test]
    fn krp003_distinct_custody_keys_pass() {
        assert_eq!(count(&run(&charter(vec![custody(b"btc", b"pq")])), "KRP-003"), 0);
    }

    // ── KRP-004 ──
    #[test]
    fn krp004_cross_role_reuse_warns() {
        // Supply issuer key == TransferPolicy authority key: reuse across two modules.
        let f = run(&charter(vec![supply(b"shared"), transfer(b"shared")]));
        assert_eq!(count(&f, "KRP-004"), 1);
        assert!(f
            .iter()
            .any(|x| x.code == "KRP-004" && x.severity == Severity::Warn && x.module.is_none()));
    }
    #[test]
    fn krp004_distinct_keys_pass() {
        assert_eq!(
            count(&run(&charter(vec![supply(b"a"), transfer(b"b"), vesting(b"c")])), "KRP-004"),
            0
        );
    }
    #[test]
    fn krp004_within_module_custody_dup_not_flagged_as_reuse() {
        // btc == pq is KRP-003's job (same module index) — must NOT raise KRP-004.
        assert_eq!(count(&run(&charter(vec![custody(b"same", b"same")])), "KRP-004"), 0);
    }
    #[test]
    fn krp004_within_governance_dup_not_flagged_as_reuse() {
        // duplicate signer within one gov module is KRP-002, not cross-role reuse.
        assert_eq!(count(&run(&charter(vec![gov(&[b"k", b"k"], 1)])), "KRP-004"), 0);
    }
    #[test]
    fn krp004_governance_signer_reused_in_custody_warns() {
        // a governance signer key doubling as the custody BTC key: cross-module reuse.
        let f = run(&charter(vec![gov(&[b"g1", b"dual"], 1), custody(b"dual", b"pq")]));
        assert_eq!(count(&f, "KRP-004"), 1);
    }

    // ── KRP-005 ──
    #[test]
    fn krp005_duplicate_kind_warns() {
        let f = run(&charter(vec![transfer(b"a"), transfer(b"b")]));
        assert_eq!(count(&f, "KRP-005"), 1);
        assert!(f
            .iter()
            .any(|x| x.code == "KRP-005" && x.severity == Severity::Warn && x.index == Some(1)));
    }
    #[test]
    fn krp005_supply_dup_not_double_counted() {
        // two Supply modules => KRP-001 only, never KRP-005.
        let f = run(&charter(vec![supply(b"a"), supply(b"b")]));
        assert_eq!(count(&f, "KRP-005"), 0);
        assert_eq!(count(&f, "KRP-001"), 1);
    }
    #[test]
    fn krp005_distinct_kinds_pass() {
        assert_eq!(
            count(&run(&charter(vec![transfer(b"a"), vesting(b"b"), custody(b"c", b"d")])), "KRP-005"),
            0
        );
    }

    // ── robustness / determinism ──
    #[test]
    fn empty_charter_no_panic_no_findings() {
        assert!(run(&charter(vec![])).is_empty());
    }
    #[test]
    fn empty_pubkeys_no_panic() {
        // degenerate empty keys must not panic; empty btc == empty pq fires KRP-003,
        // two empty signers fire KRP-002.
        let f = run(&charter(vec![custody(b"", b""), gov(&[b"", b""], 1)]));
        assert_eq!(count(&f, "KRP-003"), 1);
        assert_eq!(count(&f, "KRP-002"), 1);
    }
    #[test]
    fn determinism_same_charter_identical_after_canonical_sort() {
        let c = charter(vec![
            supply(b"s"),
            transfer(b"s"),
            transfer(b"t"),
            custody(b"x", b"x"),
            gov(&[b"g", b"g"], 2),
        ]);
        let sort = |mut v: Vec<Finding>| {
            v.sort_by(|a, b| {
                a.code
                    .cmp(b.code)
                    .then(a.index.cmp(&b.index))
                    .then_with(|| a.message.cmp(&b.message))
            });
            v
        };
        assert_eq!(sort(run(&c)), sort(run(&c)));
    }

    // ── adversarial / edge-case additions ──

    fn kyc() -> ModuleKind {
        ModuleKind::ComplianceKycGate(crate::modules::KycConfig {})
    }

    /// A charter using every one of the six module kinds exactly once, all pubkeys
    /// pairwise-distinct, must pass with zero findings of any severity — the audit
    /// must not manufacture a Deny/Warn out of thin air on a well-formed charter.
    #[test]
    fn adv_full_composite_charter_passes_completely_clean() {
        let f = run(&charter(vec![
            supply(b"issuer-key"),
            transfer(b"authority-key"),
            kyc(),
            vesting(b"beneficiary-key"),
            gov(&[b"signer-1", b"signer-2", b"signer-3"], 2),
            custody(b"btc-key", b"pq-key"),
        ]));
        assert!(f.is_empty(), "expected zero findings on a clean composite charter, got {f:?}");
    }

    /// `KycConfig` is the one module kind that carries no pubkey (`role_keys` returns an
    /// empty Vec for it). Multiple KYC gates must still be caught by KRP-005 (duplicate
    /// module kind) but must never be miscounted as KRP-004 key reuse, and must not panic
    /// on the empty per-module key list.
    #[test]
    fn adv_duplicate_kyc_gate_warns_without_key_reuse_or_panic() {
        let f = run(&charter(vec![kyc(), kyc(), kyc()]));
        assert_eq!(count(&f, "KRP-005"), 2, "3 kyc-gates => 2 findings (each beyond the first)");
        assert_eq!(count(&f, "KRP-004"), 0);
        assert!(f.iter().all(|x| x.severity == Severity::Warn));
    }

    /// Numeric fields the conflict rules do not themselves inspect (`cap`, `threshold`,
    /// `unlock_height`) are pushed to their type-level extremes — including negative
    /// `i128` (the signed field) and the `0`/`MAX` boundary for the unsigned ones (which
    /// is where a `negative as unsigned` wraparound bug would also land). None of this
    /// may panic, and — since these fields are conflict-irrelevant — the finding set must
    /// be identical to the same charter shape built with harmless placeholder values.
    #[test]
    fn adv_numeric_boundary_params_no_panic_and_conflict_irrelevant() {
        let extreme = charter(vec![
            ModuleKind::Supply(SupplyConfig { cap: 0, issuer_pubkey: b"i1".to_vec() }),
            ModuleKind::Supply(SupplyConfig {
                cap: u64::MAX,
                issuer_pubkey: b"i2".to_vec(),
            }),
            ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g1".to_vec(), b"g2".to_vec()],
                threshold: 0,
            }),
            ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g3".to_vec(), b"g4".to_vec()],
                threshold: u32::MAX,
            }),
            ModuleKind::Vesting(VestingConfig {
                unlock_height: i128::MIN,
                beneficiary_pubkey: b"v1".to_vec(),
            }),
            ModuleKind::Vesting(VestingConfig {
                unlock_height: i128::MAX,
                beneficiary_pubkey: b"v2".to_vec(),
            }),
        ]);
        let baseline = charter(vec![
            ModuleKind::Supply(SupplyConfig { cap: 1, issuer_pubkey: b"i1".to_vec() }),
            ModuleKind::Supply(SupplyConfig { cap: 1, issuer_pubkey: b"i2".to_vec() }),
            ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g1".to_vec(), b"g2".to_vec()],
                threshold: 1,
            }),
            ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g3".to_vec(), b"g4".to_vec()],
                threshold: 1,
            }),
            ModuleKind::Vesting(VestingConfig { unlock_height: 0, beneficiary_pubkey: b"v1".to_vec() }),
            ModuleKind::Vesting(VestingConfig { unlock_height: 0, beneficiary_pubkey: b"v2".to_vec() }),
        ]);
        assert_eq!(run(&extreme), run(&baseline));
    }

    /// Degenerate/malformed inputs that are *not* the already-covered empty-charter case:
    /// an empty `token_name`, a `Governance` module with zero signers, and a `Custody`
    /// module with one empty key and one non-empty key (must NOT trip KRP-003). None of
    /// this may panic and none of it should produce a false-positive Deny.
    #[test]
    fn adv_malformed_charter_empty_name_zero_signers_no_false_positive() {
        let c = TokenCharter {
            token_name: Vec::new(),
            modules: vec![
                ModuleKind::Governance(GovernanceConfig { signers: Vec::new(), threshold: 0 }),
                custody(b"", b"nonempty"),
            ],
        };
        let f = run(&c);
        assert!(
            f.iter().all(|x| x.severity != Severity::Deny),
            "expected no false-positive Deny, got {f:?}"
        );
        assert_eq!(count(&f, "KRP-002"), 0);
        assert_eq!(count(&f, "KRP-003"), 0);
    }

    /// A charter with many modules (stress/boundary on count, not just value) must still
    /// terminate promptly, never panic, and produce exactly the counts the rules promise:
    /// N Supply modules => N-1 KRP-001 findings; N identical Governance signers => N-1
    /// KRP-002 findings.
    #[test]
    fn adv_large_module_count_no_panic_correct_counts() {
        const N: usize = 500;
        let mut mods: Vec<ModuleKind> = (0..N).map(|i| supply(format!("s{i}").as_bytes())).collect();
        mods.push(gov(&vec![b"dup".as_slice(); N], 1));
        let f = run(&charter(mods));
        assert_eq!(count(&f, "KRP-001"), N - 1);
        assert_eq!(count(&f, "KRP-002"), 1, "N identical signers => 1 distinct duplicated key");
    }

    /// Stronger determinism check than the canonical-sort variant above: for a charter
    /// that triggers every rule at least once, two independent `audit()` runs over the
    /// *same* charter must be identical **before any sorting** — the dispatcher relies on
    /// this file emitting rule-internally-stable order, not merely a stable order after
    /// its own final sort.
    #[test]
    fn adv_determinism_raw_output_order_stable_across_runs_all_rules_firing() {
        let c = charter(vec![
            supply(b"s1"),
            supply(b"s2"),
            transfer(b"s1"), // KRP-004: reused across Supply/TransferPolicy
            transfer(b"t2"),
            gov(&[b"g1", b"g1", b"g2"], 2), // KRP-002
            custody(b"same", b"same"),      // KRP-003
            custody(b"c1", b"c2"),
            custody(b"c1", b"c3"), // KRP-005: duplicate custody kind
        ]);
        let a = run(&c);
        let b = run(&c);
        assert_eq!(a, b, "raw (pre-sort) finding order must be identical across repeated runs");
        // Sanity: this charter really does exercise every rule, so the determinism check
        // is not vacuous.
        for code in ["KRP-001", "KRP-002", "KRP-003", "KRP-004", "KRP-005"] {
            assert!(count(&a, code) >= 1, "expected {code} to fire at least once in this fixture");
        }
    }
}
