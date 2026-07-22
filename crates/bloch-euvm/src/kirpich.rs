//! # Kirpich — the Ustav charter internal-audit gate (unified dispatcher)
//!
//! Kirpich (кирпич, "brick": the block you inspect *before* you lay it into the wall)
//! is the deterministic, fail-closed static audit that inspects a
//! [`TokenCharter`](crate::modules::TokenCharter) **before** it is compiled into an
//! eUTXO validator set by [`crate::modules::compile_charter`]. It is the internal-audit
//! gate over the Ustav charter compile path: a charter that carries a `Deny`-severity
//! defect must never reach the compiler on the audited build path
//! ([`crate::modules::compile_charter_audited`]).
//!
//! ## Isolation / honesty
//!
//! Like the rest of `bloch-euvm`, Kirpich is **FOUNDATION, tests-only, NOT
//! consensus-wired**. It lives behind the off-by-default `euvm` feature and is not
//! compiled into the node binary. It never mutates a charter, never runs consensus, and
//! never blocks the un-audited [`crate::modules::compile_charter`] (which is preserved
//! as-is). The audited path is opt-in.
//!
//! ## Determinism (sacred, shared by every lane)
//!
//! The audit is a **pure function of the charter**: same charter ⇒ byte-identical
//! [`AuditReport`]. No clock, no float, no `HashMap` iteration, no IO; all arithmetic in
//! the lanes is checked / saturating. No rule panics on any charter — a malformed
//! charter yields [`Finding`]s, never a crash. The dispatcher imposes a single
//! **canonical ordering** over every lane's findings so the report is reproducible
//! regardless of the order lanes ran or appended.
//!
//! ## The four rule lanes
//!
//! Each lane is a self-contained module with a `pub(super) fn audit(charter, out)` sink
//! that *appends* findings (never sorts — the dispatcher sorts once, over all lanes):
//!
//! | lane | file | codes | catches |
//! |------|------|-------|---------|
//! | A — module conflicts       | [`conflicts`]    | KRP-001..=KRP-005 | composition contradictions (multiple Supply, duplicate governance signer, custody btc==pq, cross-role key reuse, duplicate module kind) |
//! | B — compliance completeness| [`completeness`] | KRP-020..=KRP-026 | structurally unfinishable modules (empty charter, empty authority keys, KYC gate with no transfer control, empty token name) |
//! | C — unsafe params          | [`params`]       | KRP-040..=KRP-045 | scalar foot-guns (0-of-m / unsatisfiable / >253-signer governance, non-positive vesting height, zero supply cap, empty signer key) |
//! | D — emitted programs       | [`emitted`]      | KRP-060..=KRP-064 | defects in the *compiled bytes* (non-deterministic recompile, incomplete emit, gas/size budget, Supply hash==BLCH, always-true / neutered guard) |
//!
//! ## Public API
//!
//! - [`Severity`] — `Deny < Warn < Info` (`Ord`, most-severe first).
//! - [`Finding`] — one defect: stable `code`, `severity`, offending `module` tag +
//!   `index` (when module-specific), and a deterministically formatted `message`.
//! - [`AuditReport`] — the sorted findings plus a `denied` verdict, with
//!   [`AuditReport::has_deny`] / [`AuditReport::by_severity`] helpers.
//! - [`kirpich_audit`] — run every lane and return the canonical report.

use crate::modules::TokenCharter;

// The four rule lanes. Private: reached only through this dispatcher. Each reaches the
// shared `Finding` / `Severity` types below via `super::`.
mod completeness;
mod conflicts;
mod emitted;
mod params;

/// Severity of a [`Finding`]. Ordered **most-severe first** (`Deny < Warn < Info`), so a
/// canonical ascending sort surfaces the blocking findings at the top and the derived
/// `Ord` doubles as the primary sort key.
///
/// Only `Deny` blocks the audited compile path ([`AuditReport::denied`]); `Warn` and
/// `Info` are advisory. (`Info` is part of the vocabulary but no current lane emits it.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Fail-closed: the audited build path refuses to compile the charter.
    Deny = 0,
    /// Advisory: a smell / hazard that does not block compilation.
    Warn = 1,
    /// Informational only.
    Info = 2,
}

/// A single audit finding — one defect discovered in a charter by one rule.
///
/// The shape is shared verbatim by all four lanes (they import it via `super::Finding`),
/// so no per-lane adaptation is needed. `message` is always formatted from charter
/// scalars / byte-lengths only, never from clocks or addresses, keeping it byte-stable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule identifier, e.g. `"KRP-001"`.
    pub code: &'static str,
    /// How serious the finding is (and whether it blocks the audited compile).
    pub severity: Severity,
    /// The offending module's [`crate::modules::ModuleKind::tag`], or `None` for a
    /// charter-level finding that is not tied to one module.
    pub module: Option<&'static str>,
    /// The offending module's position in `charter.modules`, when module-specific.
    pub index: Option<usize>,
    /// Deterministically formatted human-readable description.
    pub message: String,
}

/// The result of a full Kirpich audit: every lane's [`Finding`]s in a single
/// **canonical order**, plus the fail-closed `denied` verdict.
///
/// `findings` is sorted by `(severity, code, index, message)` — a total, deterministic
/// order with no `HashMap` anywhere — so the same charter always yields a byte-identical
/// report. `denied` is `true` iff any finding is [`Severity::Deny`].
#[derive(Clone, Debug)]
pub struct AuditReport {
    /// All findings, in canonical `(severity, code, index, message)` order.
    pub findings: Vec<Finding>,
    /// `true` iff at least one finding is [`Severity::Deny`] — the audited compile path
    /// fails closed on this.
    pub denied: bool,
}

impl AuditReport {
    /// Whether the report carries at least one [`Severity::Deny`] finding. Equivalent to
    /// [`AuditReport::denied`]; provided as a method for call-site readability.
    pub fn has_deny(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Deny)
    }

    /// The findings of exactly `severity`, borrowed in canonical order.
    pub fn by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// Count of findings of exactly `severity`.
    pub fn count(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }
}

/// Run the full Kirpich internal audit over `charter` and return its canonical
/// [`AuditReport`]. Pure, deterministic, and panic-free for any charter.
///
/// Every lane is invoked and its findings collected into one sink, then sorted into the
/// canonical `(severity, code, index, message)` order. `denied` is set iff any finding
/// is [`Severity::Deny`]. This is the audit half of
/// [`crate::modules::compile_charter_audited`].
pub fn kirpich_audit(charter: &TokenCharter) -> AuditReport {
    let mut findings: Vec<Finding> = Vec::new();

    // Every lane appends in its own rule order; ordering is imposed once, below.
    conflicts::audit(charter, &mut findings); // Lane A — KRP-001..=KRP-005
    completeness::audit(charter, &mut findings); // Lane B — KRP-020..=KRP-026
    params::audit(charter, &mut findings); // Lane C — KRP-040..=KRP-045
    emitted::audit(charter, &mut findings); // Lane D — KRP-060..=KRP-064

    // Canonical, deterministic ordering: primarily by (severity, code, index) as the
    // integration contract requires; `message` is the final tiebreak so two findings
    // sharing a (severity, code, index) — e.g. both empty Custody legs (KRP-024) — still
    // have a stable, total order. `Option<usize>` sorts `None` before `Some`.
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.code.cmp(b.code))
            .then_with(|| a.index.cmp(&b.index))
            .then_with(|| a.message.cmp(&b.message))
    });

    let denied = findings.iter().any(|f| f.severity == Severity::Deny);
    AuditReport { findings, denied }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::{
        CustodyConfig, GovernanceConfig, KycConfig, ModuleKind, SupplyConfig,
        TransferPolicyConfig, VestingConfig,
    };

    /// A well-formed charter using every module kind exactly once, all keys distinct.
    /// It must audit completely clean (no findings of any severity).
    fn clean_charter() -> TokenCharter {
        TokenCharter {
            token_name: b"USTV".to_vec(),
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 1_000_000,
                    issuer_pubkey: b"issuer-pk".to_vec(),
                }),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"authority-pk".to_vec(),
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: 2_400,
                    beneficiary_pubkey: b"benef-pk".to_vec(),
                }),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"g1".to_vec(), b"g2".to_vec(), b"g3".to_vec()],
                    threshold: 2,
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: b"btc-pk".to_vec(),
                    pq_pubkey: b"pq-pk".to_vec(),
                }),
            ],
        }
    }

    #[test]
    fn clean_charter_audits_clean_and_not_denied() {
        let report = kirpich_audit(&clean_charter());
        assert!(report.findings.is_empty(), "expected zero findings, got {:?}", report.findings);
        assert!(!report.denied);
        assert!(!report.has_deny());
    }

    #[test]
    fn empty_charter_is_denied_no_panic() {
        let report = kirpich_audit(&TokenCharter { token_name: vec![], modules: vec![] });
        assert!(report.denied);
        assert!(report.has_deny());
        // KRP-020 (empty charter, Deny) and KRP-026 (empty name, Warn) at minimum.
        assert!(report.findings.iter().any(|f| f.code == "KRP-020"));
        assert!(report.findings.iter().any(|f| f.code == "KRP-026"));
    }

    #[test]
    fn every_lane_is_wired_and_reachable() {
        // One charter that trips at least one rule in each of the four lanes.
        let charter = TokenCharter {
            token_name: b"MIX".to_vec(),
            modules: vec![
                // Lane A: two Supply modules => KRP-001. Second supply has cap 0 (Lane C
                // KRP-044) and empty issuer (Lane B KRP-021).
                ModuleKind::Supply(SupplyConfig { cap: 100, issuer_pubkey: b"iss".to_vec() }),
                ModuleKind::Supply(SupplyConfig { cap: 0, issuer_pubkey: vec![] }),
                // Lane C: 0-of-2 governance => KRP-040 (and Lane D KRP-064 always-true).
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"a".to_vec(), b"b".to_vec()],
                    threshold: 0,
                }),
            ],
        };
        let report = kirpich_audit(&charter);
        for code in ["KRP-001", "KRP-021", "KRP-040", "KRP-044", "KRP-064"] {
            assert!(
                report.findings.iter().any(|f| f.code == code),
                "expected {code} to be present; got {:?}",
                report.findings.iter().map(|f| f.code).collect::<Vec<_>>()
            );
        }
        assert!(report.denied);
    }

    #[test]
    fn findings_are_canonically_sorted_deny_first() {
        let charter = TokenCharter {
            token_name: vec![], // KRP-026 Warn
            modules: vec![
                ModuleKind::Custody(CustodyConfig { btc_pubkey: vec![], pq_pubkey: vec![] }), // KRP-024 Deny x2
            ],
        };
        let report = kirpich_audit(&charter);
        // Severity is non-decreasing across the sorted list (all Deny before any Warn).
        for w in report.findings.windows(2) {
            assert!(w[0].severity <= w[1].severity, "severity not sorted: {:?}", report.findings);
        }
        // Within equal (severity, code), the message tiebreak gives a total order.
        assert!(report.findings.windows(2).all(|w| {
            (w[0].severity, w[0].code, w[0].index, &w[0].message)
                <= (w[1].severity, w[1].code, w[1].index, &w[1].message)
        }));
    }

    #[test]
    fn audit_is_deterministic_byte_identical() {
        let charter = clean_charter();
        let a = kirpich_audit(&charter);
        let mut dirty = charter;
        dirty.modules.push(ModuleKind::Governance(GovernanceConfig {
            signers: vec![b"x".to_vec(), b"x".to_vec()], // dup signer => KRP-002
            threshold: 1,
        }));
        let b1 = kirpich_audit(&dirty);
        let b2 = kirpich_audit(&dirty);
        assert_eq!(b1.findings, b2.findings, "same charter must yield identical findings");
        assert_eq!(b1.denied, b2.denied);
        // sanity: the clean run really is clean and the dirty run really differs
        assert!(a.findings.is_empty());
        assert!(!b1.findings.is_empty());
    }

    #[test]
    fn by_severity_and_count_partition_the_findings() {
        let charter = TokenCharter {
            token_name: vec![], // KRP-026 Warn
            modules: vec![ModuleKind::Supply(SupplyConfig { cap: 0, issuer_pubkey: vec![] })],
        };
        let report = kirpich_audit(&charter);
        let denies = report.by_severity(Severity::Deny);
        let warns = report.by_severity(Severity::Warn);
        assert!(!denies.is_empty());
        assert!(denies.iter().all(|f| f.severity == Severity::Deny));
        assert!(warns.iter().all(|f| f.severity == Severity::Warn));
        assert_eq!(report.count(Severity::Deny), denies.len());
        assert_eq!(report.count(Severity::Warn), warns.len());
        assert_eq!(denies.len() + warns.len() + report.count(Severity::Info), report.findings.len());
    }
}
