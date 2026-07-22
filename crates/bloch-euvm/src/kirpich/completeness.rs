//! # Kirpich — Lane B: **Compliance completeness** (`src/kirpich/completeness.rs`)
//!
//! Part of the **Kirpich** static charter auditor (кирпич = "brick" — the building
//! block you inspect before laying it into the contract). This lane is a deterministic,
//! fail-closed pass that inspects a [`TokenCharter`](crate::modules::TokenCharter)
//! *before* it compiles and flags **completeness / presence** defects: a charter that
//! declares a module but leaves it structurally *unfinishable* — an authority key that
//! is empty (so the guard can never be satisfied and the funds it protects are locked
//! forever), a compliance gate with no transfer control behind it, or a charter with no
//! modules / no name at all.
//!
//! ## Rules implemented in this lane
//!
//! | code | severity | trigger |
//! |------|----------|---------|
//! | `KRP-020` | **Deny** | empty charter — `modules.is_empty()`; the compiled token would guard nothing |
//! | `KRP-021` | **Deny** | `Supply.issuer_pubkey` empty — mints can never be authorized (authority unenforceable) |
//! | `KRP-022` | **Deny** | `TransferPolicy.authority_pubkey` empty — a freeze can never be lifted (funds lock) |
//! | `KRP-023` | **Deny** | `Vesting.beneficiary_pubkey` empty — matured funds can never be claimed |
//! | `KRP-024` | **Deny** | `Custody` leg (`btc_pubkey` and/or `pq_pubkey`) empty — the 2-of-2 can never be satisfied |
//! | `KRP-025` | **Warn** | a `ComplianceKycGate` present but the charter has **no** `TransferPolicy` — membership is checked but transfers are not restricted (incomplete compliance) |
//! | `KRP-026` | **Warn** | `token_name` empty — no ticker / domain separation for the charter |
//!
//! `Deny` findings make the audited build path fail closed; `Warn` findings are
//! advisory and never block. The "transfer control" that `KRP-025` looks for is
//! specifically a [`ModuleKind::TransferPolicy`](crate::modules::ModuleKind::TransferPolicy)
//! — that is the module whose *purpose* is to gate/freeze transfers. `Custody` and
//! `Governance` are spend-authorization guards, not transfer-restriction policy, so
//! their presence does not satisfy this rule.
//!
//! ## Determinism / safety contract (shared by every Kirpich lane)
//!
//! - **Pure & deterministic:** the only inputs are the charter's scalars/byte-lengths
//!   and its module ordering; no clock, no float, no `HashMap` iteration, no IO.
//! - **No panics on any input:** every check is an `.is_empty()` / iteration; there is
//!   no arithmetic and nothing to unwrap, so a malformed charter yields findings, never
//!   a crash.
//! - **Append-only sink:** findings are *pushed* onto `out` in charter order. The
//!   Integrate phase's `kirpich_audit` performs the final canonical
//!   `(code, index, message)` sort, so this lane does not sort.
//!
//! ## Finding / Severity shape (what the integrator must provide)
//!
//! This file expects the parent module `crate::kirpich` (owned by the Integrate phase,
//! `src/kirpich.rs`) to define exactly these two types, which we pull in via `super::`:
//!
//! ```ignore
//! pub enum Severity { Deny = 0, Warn = 1, Info = 2 }   // most-severe first
//! pub struct Finding {
//!     pub code: &'static str,          // stable "KRP-NNN"
//!     pub severity: Severity,
//!     pub module: Option<&'static str>,// ModuleKind::tag(), or None for charter-level
//!     pub index: Option<usize>,        // position in charter.modules, or None
//!     pub message: String,             // deterministically formatted
//! }
//! ```
//!
//! Integration is therefore a no-op on this file: the integrator only needs
//! `mod completeness;` inside `src/kirpich.rs` with those two types in scope.

use super::{Finding, Severity};
use crate::modules::{ModuleKind, TokenCharter};

/// Lane B entry point. Appends every completeness finding for `charter` onto `out` in
/// charter order (the dispatcher sorts canonically afterward). Pure, deterministic,
/// never panics.
pub(super) fn audit(charter: &TokenCharter, out: &mut Vec<Finding>) {
    // ── KRP-020: an empty charter compiles to a token with zero validators. ──
    // Nothing would guard the token's outputs; refuse to compile it (fail closed).
    if charter.modules.is_empty() {
        out.push(Finding {
            code: "KRP-020",
            severity: Severity::Deny,
            module: None,
            index: None,
            message:
                "charter declares no modules: the compiled token would guard nothing"
                    .to_string(),
        });
    }

    // ── KRP-026: an empty token_name gives the charter no ticker / domain tag. ──
    // The charter still compiles deterministically, so this is advisory (Warn).
    if charter.token_name.is_empty() {
        out.push(Finding {
            code: "KRP-026",
            severity: Severity::Warn,
            module: None,
            index: None,
            message: "token_name is empty: charter has no ticker / domain separation"
                .to_string(),
        });
    }

    // Single pass over the modules: emit per-module emptiness findings and, in the
    // same walk, record whether any TransferPolicy exists and where the KYC gates sit
    // (both needed for the KRP-025 completeness cross-check below).
    let mut has_transfer_control = false;
    let mut kyc_gate_indices: Vec<usize> = Vec::new();

    for (i, m) in charter.modules.iter().enumerate() {
        match m {
            // ── KRP-021: Supply with an empty issuer key. ──
            // The Supply guard requires the issuer to sign every mint; an empty
            // pubkey can never verify, so no mint can ever be authorized. The
            // "mintable-by-authority but no authority" defect, in its starkest form.
            ModuleKind::Supply(c) => {
                if c.issuer_pubkey.is_empty() {
                    out.push(Finding {
                        code: "KRP-021",
                        severity: Severity::Deny,
                        module: Some(m.tag()),
                        index: Some(i),
                        message: format!(
                            "Supply module #{i} has an empty issuer_pubkey: mints can \
                             never be authorized (mint authority is unenforceable)"
                        ),
                    });
                }
            }

            // ── KRP-022: TransferPolicy with an empty authority key. ──
            // A frozen output is unfrozen only by the authority's signature; an empty
            // authority key can never sign, so any freeze is permanent — funds lock.
            ModuleKind::TransferPolicy(c) => {
                has_transfer_control = true;
                if c.authority_pubkey.is_empty() {
                    out.push(Finding {
                        code: "KRP-022",
                        severity: Severity::Deny,
                        module: Some(m.tag()),
                        index: Some(i),
                        message: format!(
                            "TransferPolicy module #{i} has an empty authority_pubkey: a \
                             freeze can never be lifted (frozen funds lock permanently)"
                        ),
                    });
                }
            }

            // ── KRP-023: Vesting with an empty beneficiary key. ──
            // Matured funds require the beneficiary's signature; an empty key means the
            // vested output can never be claimed by anyone.
            ModuleKind::Vesting(c) => {
                if c.beneficiary_pubkey.is_empty() {
                    out.push(Finding {
                        code: "KRP-023",
                        severity: Severity::Deny,
                        module: Some(m.tag()),
                        index: Some(i),
                        message: format!(
                            "Vesting module #{i} has an empty beneficiary_pubkey: matured \
                             funds can never be claimed (permanently unspendable)"
                        ),
                    });
                }
            }

            // ── KRP-024: Custody with an empty leg. ──
            // The hybrid-PQ guard is a 2-of-2 (BOTH the BTC/ECDSA key and the PQ key
            // must sign). An empty key on either leg can never verify, so the 2-of-2 is
            // permanently unsatisfiable. Emit one finding per empty leg (distinct
            // messages keep the canonical sort stable).
            ModuleKind::Custody(c) => {
                if c.btc_pubkey.is_empty() {
                    out.push(Finding {
                        code: "KRP-024",
                        severity: Severity::Deny,
                        module: Some(m.tag()),
                        index: Some(i),
                        message: format!(
                            "Custody module #{i} has an empty btc_pubkey (ECDSA leg): the \
                             hybrid 2-of-2 can never be satisfied"
                        ),
                    });
                }
                if c.pq_pubkey.is_empty() {
                    out.push(Finding {
                        code: "KRP-024",
                        severity: Severity::Deny,
                        module: Some(m.tag()),
                        index: Some(i),
                        message: format!(
                            "Custody module #{i} has an empty pq_pubkey (PQ leg): the \
                             hybrid 2-of-2 can never be satisfied"
                        ),
                    });
                }
            }

            // Record KYC gates for the post-loop completeness cross-check (KRP-025).
            ModuleKind::ComplianceKycGate(_) => {
                kyc_gate_indices.push(i);
            }

            // Governance carries no key-presence completeness rule in this lane
            // (n-of-m / quorum sanity belongs to Lane C, params.rs).
            ModuleKind::Governance(_) => {}
        }
    }

    // ── KRP-025: a compliance (KYC) gate with no transfer control behind it. ──
    // A security-style token that checks membership but has no TransferPolicy has an
    // incomplete compliance layer: nothing restricts/freezes transfers once a holder is
    // admitted. Advisory (Warn) — the KYC gate itself still enforces membership.
    if !has_transfer_control {
        for i in kyc_gate_indices {
            out.push(Finding {
                code: "KRP-025",
                severity: Severity::Warn,
                module: Some("kyc-gate"),
                index: Some(i),
                message: format!(
                    "ComplianceKycGate module #{i} present but the charter has no \
                     TransferPolicy: membership is checked yet transfers are \
                     unrestricted (incomplete compliance)"
                ),
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::{
        CustodyConfig, GovernanceConfig, KycConfig, SupplyConfig, TransferPolicyConfig,
        VestingConfig,
    };

    // ── tiny helpers ──────────────────────────────────────────────────────────

    fn run(charter: &TokenCharter) -> Vec<Finding> {
        let mut out = Vec::new();
        audit(charter, &mut out);
        out
    }
    fn codes(fs: &[Finding]) -> Vec<&'static str> {
        fs.iter().map(|f| f.code).collect()
    }
    fn find<'a>(fs: &'a [Finding], code: &str) -> Vec<&'a Finding> {
        fs.iter().filter(|f| f.code == code).collect()
    }
    fn has(fs: &[Finding], code: &str) -> bool {
        fs.iter().any(|f| f.code == code)
    }

    // A well-formed "everything present" charter that triggers NONE of this lane's
    // rules — the baseline every "passes" assertion builds from.
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
                    signers: vec![b"g1".to_vec(), b"g2".to_vec()],
                    threshold: 2,
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: b"btc-pk".to_vec(),
                    pq_pubkey: b"pq-pk".to_vec(),
                }),
            ],
        }
    }

    /// The clean baseline produces zero findings from this lane.
    #[test]
    fn clean_charter_has_no_completeness_findings() {
        assert!(run(&clean_charter()).is_empty());
    }

    // ── KRP-020: empty charter ────────────────────────────────────────────────

    #[test]
    fn krp020_empty_charter_denies() {
        let charter = TokenCharter {
            token_name: b"NAME".to_vec(),
            modules: vec![],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-020");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Deny);
        assert_eq!(hits[0].module, None);
        assert_eq!(hits[0].index, None);
    }

    #[test]
    fn krp020_passes_when_any_module_present() {
        let charter = TokenCharter {
            token_name: b"NAME".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g1".to_vec()],
                threshold: 1,
            })],
        };
        assert!(!has(&run(&charter), "KRP-020"));
    }

    // ── KRP-021: Supply issuer empty ──────────────────────────────────────────

    #[test]
    fn krp021_empty_issuer_denies() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 100,
                issuer_pubkey: vec![], // empty
            })],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-021");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Deny);
        assert_eq!(hits[0].module, Some("supply"));
        assert_eq!(hits[0].index, Some(0));
    }

    #[test]
    fn krp021_passes_with_nonempty_issuer() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 100,
                issuer_pubkey: b"iss".to_vec(),
            })],
        };
        assert!(!has(&run(&charter), "KRP-021"));
    }

    // ── KRP-022: TransferPolicy authority empty ───────────────────────────────

    #[test]
    fn krp022_empty_authority_denies() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::TransferPolicy(TransferPolicyConfig {
                authority_pubkey: vec![],
            })],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-022");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Deny);
        assert_eq!(hits[0].module, Some("transfer-policy"));
        assert_eq!(hits[0].index, Some(0));
    }

    #[test]
    fn krp022_passes_with_nonempty_authority() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::TransferPolicy(TransferPolicyConfig {
                authority_pubkey: b"auth".to_vec(),
            })],
        };
        assert!(!has(&run(&charter), "KRP-022"));
    }

    // ── KRP-023: Vesting beneficiary empty ────────────────────────────────────

    #[test]
    fn krp023_empty_beneficiary_denies() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Vesting(VestingConfig {
                unlock_height: 10,
                beneficiary_pubkey: vec![],
            })],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-023");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Deny);
        assert_eq!(hits[0].module, Some("vesting"));
        assert_eq!(hits[0].index, Some(0));
    }

    #[test]
    fn krp023_passes_with_nonempty_beneficiary() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Vesting(VestingConfig {
                unlock_height: 10,
                beneficiary_pubkey: b"ben".to_vec(),
            })],
        };
        assert!(!has(&run(&charter), "KRP-023"));
    }

    // ── KRP-024: Custody leg empty ────────────────────────────────────────────

    #[test]
    fn krp024_empty_btc_leg_denies() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Custody(CustodyConfig {
                btc_pubkey: vec![],
                pq_pubkey: b"pq".to_vec(),
            })],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-024");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Deny);
        assert_eq!(hits[0].module, Some("custody"));
        assert_eq!(hits[0].index, Some(0));
    }

    #[test]
    fn krp024_empty_pq_leg_denies() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Custody(CustodyConfig {
                btc_pubkey: b"btc".to_vec(),
                pq_pubkey: vec![],
            })],
        };
        assert!(has(&run(&charter), "KRP-024"));
    }

    /// Both legs empty ⇒ two distinct KRP-024 findings (one per leg), both Deny.
    #[test]
    fn krp024_both_legs_empty_yields_two_findings() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Custody(CustodyConfig {
                btc_pubkey: vec![],
                pq_pubkey: vec![],
            })],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-024");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|f| f.severity == Severity::Deny));
        // distinct messages so the canonical (code,index,message) sort is stable
        assert_ne!(hits[0].message, hits[1].message);
    }

    #[test]
    fn krp024_passes_with_both_legs_present() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Custody(CustodyConfig {
                btc_pubkey: b"btc".to_vec(),
                pq_pubkey: b"pq".to_vec(),
            })],
        };
        assert!(!has(&run(&charter), "KRP-024"));
    }

    // ── KRP-025: KYC gate without transfer control ────────────────────────────

    #[test]
    fn krp025_kyc_without_transfer_policy_warns() {
        let charter = TokenCharter {
            token_name: b"SEC".to_vec(),
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 1,
                    issuer_pubkey: b"iss".to_vec(),
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
            ],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-025");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].module, Some("kyc-gate"));
        assert_eq!(hits[0].index, Some(1)); // the KYC gate's position
    }

    /// A TransferPolicy anywhere in the charter satisfies the rule (no KRP-025).
    #[test]
    fn krp025_passes_when_transfer_policy_present() {
        let charter = TokenCharter {
            token_name: b"SEC".to_vec(),
            modules: vec![
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"auth".to_vec(),
                }),
            ],
        };
        assert!(!has(&run(&charter), "KRP-025"));
    }

    /// Custody / Governance are NOT transfer control: a KYC gate alongside only those
    /// still trips KRP-025.
    #[test]
    fn krp025_custody_and_governance_do_not_count_as_transfer_control() {
        let charter = TokenCharter {
            token_name: b"SEC".to_vec(),
            modules: vec![
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: b"btc".to_vec(),
                    pq_pubkey: b"pq".to_vec(),
                }),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"g".to_vec()],
                    threshold: 1,
                }),
            ],
        };
        assert!(has(&run(&charter), "KRP-025"));
    }

    /// Two KYC gates with no transfer control ⇒ one KRP-025 per gate, each carrying its
    /// own module index.
    #[test]
    fn krp025_one_finding_per_kyc_gate() {
        let charter = TokenCharter {
            token_name: b"SEC".to_vec(),
            modules: vec![
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
            ],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-025");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].index, Some(0));
        assert_eq!(hits[1].index, Some(1));
    }

    #[test]
    fn krp025_no_kyc_gate_no_finding() {
        // No KYC gate at all: nothing to complete, no KRP-025 even without a policy.
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g".to_vec()],
                threshold: 1,
            })],
        };
        assert!(!has(&run(&charter), "KRP-025"));
    }

    // ── KRP-026: empty token_name ─────────────────────────────────────────────

    #[test]
    fn krp026_empty_name_warns() {
        let charter = TokenCharter {
            token_name: vec![],
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g".to_vec()],
                threshold: 1,
            })],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-026");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Warn);
        assert_eq!(hits[0].module, None);
        assert_eq!(hits[0].index, None);
    }

    #[test]
    fn krp026_passes_with_nonempty_name() {
        let charter = TokenCharter {
            token_name: b"HASNAME".to_vec(),
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g".to_vec()],
                threshold: 1,
            })],
        };
        assert!(!has(&run(&charter), "KRP-026"));
    }

    // ── determinism / no-panic / cross-rule ───────────────────────────────────

    /// Same charter ⇒ byte-identical finding list (codes, severities, indices,
    /// messages), every time. This lane pushes in charter order; the dispatcher sorts.
    #[test]
    fn deterministic_same_charter_identical_findings() {
        // A charter that trips several rules at once.
        let charter = TokenCharter {
            token_name: vec![], // KRP-026
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 1,
                    issuer_pubkey: vec![], // KRP-021
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()), // KRP-025 (no TP)
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: vec![], // KRP-024 x2
                    pq_pubkey: vec![],
                }),
            ],
        };
        let a = run(&charter);
        let b = run(&charter);
        assert_eq!(codes(&a), codes(&b));
        assert_eq!(a, b); // Finding derives PartialEq/Eq — full structural equality
        // sanity: all expected codes present
        for c in ["KRP-021", "KRP-024", "KRP-025", "KRP-026"] {
            assert!(has(&a, c), "expected {c}");
        }
    }

    /// The empty charter trips KRP-020 (Deny) and KRP-026 (Warn) together — and nothing
    /// panics on the zero-module / zero-name degenerate input.
    #[test]
    fn empty_charter_no_name_trips_020_and_026_no_panic() {
        let charter = TokenCharter {
            token_name: vec![],
            modules: vec![],
        };
        let fs = run(&charter);
        assert!(has(&fs, "KRP-020"));
        assert!(has(&fs, "KRP-026"));
        // no module-level rules can fire with zero modules
        for c in ["KRP-021", "KRP-022", "KRP-023", "KRP-024", "KRP-025"] {
            assert!(!has(&fs, c));
        }
    }

    /// A fully broken charter (every Deny rule tripped) never panics and yields a
    /// finding for each rule with the right severity split.
    #[test]
    fn everything_empty_no_panic_and_full_severity_split() {
        let charter = TokenCharter {
            token_name: vec![],
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 0,
                    issuer_pubkey: vec![],
                }),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: vec![],
                }),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: 0,
                    beneficiary_pubkey: vec![],
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: vec![],
                    pq_pubkey: vec![],
                }),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
            ],
        };
        let fs = run(&charter);
        // Deny rules present (note: TransferPolicy IS present here, so KRP-025 does NOT fire)
        for c in ["KRP-021", "KRP-022", "KRP-023", "KRP-024"] {
            assert!(has(&fs, c), "expected {c}");
        }
        assert!(!has(&fs, "KRP-025")); // a TransferPolicy exists → KYC completeness OK
        assert!(has(&fs, "KRP-026")); // Warn
        // KRP-020 must NOT fire (modules are present)
        assert!(!has(&fs, "KRP-020"));
        // every KRP-021..024 finding is Deny
        for f in &fs {
            if matches!(f.code, "KRP-021" | "KRP-022" | "KRP-023" | "KRP-024") {
                assert_eq!(f.severity, Severity::Deny, "{} should be Deny", f.code);
            }
        }
    }

    /// Indices are the true `charter.modules` positions even when earlier modules are
    /// clean (regression guard against off-by-one / mis-indexed findings).
    #[test]
    fn module_indices_track_real_positions() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"g".to_vec()],
                    threshold: 1,
                }), // idx 0, clean
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"a".to_vec(),
                }), // idx 1, clean (also satisfies KRP-025)
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: 5,
                    beneficiary_pubkey: vec![], // idx 2, KRP-023
                }),
            ],
        };
        let fs = run(&charter);
        let hits = find(&fs, "KRP-023");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].index, Some(2));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ADVERSARIAL / EDGE-CASE (appended) — malformed charters, numeric
    // boundaries (0 / MAX / negative), reserved-but-empty capacity, KYC/
    // transfer-control interaction gaps, and determinism/no-panic at scale.
    // ═══════════════════════════════════════════════════════════════════════

    // ── KRP-020 / KRP-026 independence + reserved-capacity trap ───────────────

    /// KRP-020 and KRP-026 are independent triggers: a non-empty name with zero
    /// modules trips only 020; a non-empty module set with an empty name trips
    /// only 026. Guards against the two checks being accidentally coupled.
    #[test]
    fn krp020_and_krp026_are_independent_triggers() {
        let no_modules_named = TokenCharter {
            token_name: b"NAME".to_vec(),
            modules: vec![],
        };
        let fs = run(&no_modules_named);
        assert!(has(&fs, "KRP-020"));
        assert!(!has(&fs, "KRP-026"));

        let unnamed_with_module = TokenCharter {
            token_name: vec![],
            modules: vec![ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g".to_vec()],
                threshold: 1,
            })],
        };
        let fs = run(&unnamed_with_module);
        assert!(!has(&fs, "KRP-020"));
        assert!(has(&fs, "KRP-026"));
    }

    /// A `Vec` that reserves capacity but holds zero elements must still read as
    /// empty: `is_empty()` is length-based, never capacity-based. Adversarial
    /// guard against a hypothetical capacity/len mix-up regression.
    #[test]
    fn reserved_capacity_does_not_fool_emptiness_checks() {
        let mut name: Vec<u8> = Vec::with_capacity(4096);
        assert!(name.is_empty());
        name.clear(); // no-op, still empty, capacity retained
        let mut modules: Vec<ModuleKind> = Vec::with_capacity(4096);
        modules.clear();

        let charter = TokenCharter {
            token_name: name,
            modules,
        };
        let fs = run(&charter);
        assert!(has(&fs, "KRP-020"));
        assert!(has(&fs, "KRP-026"));
        assert_eq!(fs.len(), 2);
    }

    // ── byte-content edge cases: emptiness is length, not content ──────────────

    /// A single all-zero byte is a *non-empty* pubkey/name: emptiness is defined
    /// by byte length, not by the byte values. Every Deny rule in this lane must
    /// NOT fire when the "key" is one or more `0x00` bytes — false positive guard.
    #[test]
    fn all_zero_byte_fields_are_not_treated_as_empty() {
        let charter = TokenCharter {
            token_name: vec![0u8], // non-empty
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 1,
                    issuer_pubkey: vec![0u8; 3],
                }),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: vec![0u8],
                }),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: 1,
                    beneficiary_pubkey: vec![0u8; 32],
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: vec![0u8],
                    pq_pubkey: vec![0u8],
                }),
            ],
        };
        assert!(run(&charter).is_empty());
    }

    /// The inverse: a truly zero-length key (not zero-valued) must still Deny even
    /// when every other field on the same module is at a numeric extreme — the
    /// emptiness check must not be short-circuited by unrelated scalar values.
    #[test]
    fn zero_length_leg_denies_even_with_extreme_sibling_fields() {
        let charter = TokenCharter {
            token_name: b"T".to_vec(),
            modules: vec![ModuleKind::Custody(CustodyConfig {
                btc_pubkey: vec![],
                pq_pubkey: b"pq".to_vec(),
            })],
        };
        let fs = run(&charter);
        assert_eq!(find(&fs, "KRP-024").len(), 1);
    }

    // ── numeric-field boundaries (0 / MAX / negative i128) do not leak in ──────
    //
    // This lane checks ONLY pubkey/name byte-emptiness; `cap`, `unlock_height`,
    // and `threshold` are Lane C's concern. These tests pin that non-coupling at
    // the numeric extremes so a future edit that accidentally reads those fields
    // here cannot silently change this lane's behavior.

    /// Every numeric field at its extreme (u64::MAX cap, i128::MIN unlock_height —
    /// the "negative" boundary for the one signed field in scope —, u32::MAX
    /// threshold, an empty signer list) with all *keys* present must still yield
    /// zero findings: no false positive tied to scalar magnitude.
    #[test]
    fn numeric_extremes_do_not_cause_false_positive_when_keys_present() {
        let charter = TokenCharter {
            token_name: b"EXT".to_vec(),
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: u64::MAX,
                    issuer_pubkey: b"iss".to_vec(),
                }),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: i128::MIN, // negative boundary
                    beneficiary_pubkey: b"ben".to_vec(),
                }),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![], // zero-length, but Governance has no rule here
                    threshold: u32::MAX,
                }),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"auth".to_vec(),
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: b"btc".to_vec(),
                    pq_pubkey: b"pq".to_vec(),
                }),
            ],
        };
        assert!(run(&charter).is_empty());
    }

    /// The mirror image: the same numeric extremes (including i128::MAX and a
    /// `cap`/`unlock_height`/`threshold` of exactly 0) paired with EMPTY keys must
    /// still Deny every rule — the extremes must not mask a missing key either.
    #[test]
    fn numeric_extremes_do_not_mask_missing_keys() {
        let charter = TokenCharter {
            token_name: vec![],
            modules: vec![
                ModuleKind::Supply(SupplyConfig {
                    cap: 0, // zero boundary
                    issuer_pubkey: vec![],
                }),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: vec![],
                }),
                ModuleKind::Vesting(VestingConfig {
                    unlock_height: i128::MAX, // positive boundary
                    beneficiary_pubkey: vec![],
                }),
                ModuleKind::Custody(CustodyConfig {
                    btc_pubkey: vec![],
                    pq_pubkey: vec![],
                }),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"g".to_vec(); 64], // large-but-finite, not a rule here
                    threshold: 0,                      // zero boundary
                }),
            ],
        };
        let fs = run(&charter);
        for c in ["KRP-021", "KRP-022", "KRP-023", "KRP-024", "KRP-026"] {
            assert!(has(&fs, c), "expected {c}");
        }
        assert_eq!(find(&fs, "KRP-024").len(), 2); // both legs empty
    }

    /// Governance's own internal consistency (empty signer list with a non-zero
    /// threshold, or threshold > signers.len(), or threshold == 0) is explicitly
    /// out of scope for this lane (per the `ModuleKind::Governance(_) => {}` arm) —
    /// pin that no combination of degenerate Governance values is ever flagged
    /// here, at either numeric boundary.
    #[test]
    fn governance_degenerate_values_never_flagged_by_this_lane() {
        let charter = TokenCharter {
            token_name: b"G".to_vec(),
            modules: vec![
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![],
                    threshold: 0,
                }),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"only-one".to_vec()],
                    threshold: u32::MAX, // threshold >> signers.len()
                }),
            ],
        };
        assert!(run(&charter).is_empty());
    }

    // ── KRP-025 / transfer-control gap: presence vs. functioning policy ────────
    //
    // KRP-025's rule is "a TransferPolicy module is present somewhere in the
    // charter", not "a *working* TransferPolicy is present". These tests pin
    // that distinction exactly as coded (no rule-logic change), because it is a
    // real completeness gap worth flagging: a TransferPolicy with an empty
    // authority (itself KRP-022 Deny — permanently unusable) still suppresses
    // the KRP-025 Warn for any co-existing KYC gate.

    /// A broken (empty-authority) TransferPolicy still counts as "transfer
    /// control" for KRP-025's purposes: KRP-022 fires (the policy itself is
    /// unusable) but KRP-025 does NOT — the KYC gate's Warn is suppressed even
    /// though nothing can ever actually gate a transfer. Documents a real
    /// presence-vs-functional gap in the rule as specified/coded.
    #[test]
    fn krp025_is_suppressed_by_a_broken_transfer_policy() {
        let charter = TokenCharter {
            token_name: b"SEC".to_vec(),
            modules: vec![
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: vec![], // empty -> KRP-022, but still "present"
                }),
            ],
        };
        let fs = run(&charter);
        assert!(has(&fs, "KRP-022")); // the policy itself is flagged unusable
        assert!(!has(&fs, "KRP-025")); // yet it still suppresses the KYC warning
    }

    /// KRP-025's transfer-control check is order-independent: a TransferPolicy
    /// declared AFTER the KYC gate(s) in module order still suppresses the warn
    /// (the two-pass logic — collect during the loop, decide after — must not be
    /// sensitive to declaration order).
    #[test]
    fn krp025_transfer_control_check_is_order_independent() {
        let charter = TokenCharter {
            token_name: b"SEC".to_vec(),
            modules: vec![
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::ComplianceKycGate(KycConfig::default()),
                ModuleKind::Governance(GovernanceConfig {
                    signers: vec![b"g".to_vec()],
                    threshold: 1,
                }),
                ModuleKind::TransferPolicy(TransferPolicyConfig {
                    authority_pubkey: b"auth".to_vec(),
                }), // declared last
            ],
        };
        assert!(!has(&run(&charter), "KRP-025"));
    }

    // ── malformed / degenerate charters: no panic ──────────────────────────────

    /// A charter whose only module is a Custody leg with a large-but-plausible
    /// key (not empty) alongside a totally empty leg, repeated as the sole
    /// module, plus an empty name and non-empty modules list: multiple
    /// simultaneously-degenerate fields on one module, still no panic and exactly
    /// the expected findings.
    #[test]
    fn multiple_simultaneous_defects_on_one_module_no_panic() {
        let charter = TokenCharter {
            token_name: vec![],
            modules: vec![ModuleKind::Custody(CustodyConfig {
                btc_pubkey: vec![],
                pq_pubkey: vec![],
            })],
        };
        let fs = run(&charter);
        assert_eq!(find(&fs, "KRP-024").len(), 2);
        assert!(has(&fs, "KRP-026"));
        assert!(!has(&fs, "KRP-020")); // one module is present
    }

    // ── stress: large charter — no panic, correct counts, determinism ─────────

    /// A charter with thousands of modules (alternating a clean Supply and a
    /// both-legs-empty Custody) must not panic, must produce exactly the
    /// arithmetic-predicted finding count, and must keep true positional indices
    /// even at the far end of the vector (regression guard against any
    /// accidental O(1)-lookback / truncation at scale).
    #[test]
    fn large_charter_no_panic_correct_counts_and_indices() {
        const N: usize = 4000; // N Supply (clean) + N Custody (both legs empty)
        let mut modules = Vec::with_capacity(2 * N);
        for _ in 0..N {
            modules.push(ModuleKind::Supply(SupplyConfig {
                cap: 1,
                issuer_pubkey: b"iss".to_vec(),
            }));
            modules.push(ModuleKind::Custody(CustodyConfig {
                btc_pubkey: vec![],
                pq_pubkey: vec![],
            }));
        }
        let charter = TokenCharter {
            token_name: b"BIG".to_vec(),
            modules,
        };
        let fs = run(&charter);
        // 2 KRP-024 findings per Custody module, none from the clean Supply modules.
        assert_eq!(fs.len(), 2 * N);
        assert!(fs.iter().all(|f| f.code == "KRP-024"));
        assert!(fs.iter().all(|f| f.severity == Severity::Deny));
        // last Custody module sits at index 2*N - 1; both its findings must carry it.
        let last_index = 2 * N - 1;
        let last_hits: Vec<_> = fs.iter().filter(|f| f.index == Some(last_index)).collect();
        assert_eq!(last_hits.len(), 2);
    }

    /// Determinism must hold under stress, not just on hand-written small
    /// charters: running the same large, multi-defect charter twice must yield
    /// byte-identical finding vectors (same order, since this lane doesn't sort).
    #[test]
    fn deterministic_under_stress_large_mixed_charter() {
        const N: usize = 1500;
        let mut modules = Vec::with_capacity(N + 2);
        modules.push(ModuleKind::ComplianceKycGate(KycConfig::default()));
        for i in 0..N {
            // alternate empty/non-empty issuer so both branches interleave heavily
            let issuer = if i % 2 == 0 { vec![] } else { b"iss".to_vec() };
            modules.push(ModuleKind::Supply(SupplyConfig {
                cap: i as u64,
                issuer_pubkey: issuer,
            }));
        }
        let charter = TokenCharter {
            token_name: vec![],
            modules,
        };
        let a = run(&charter);
        let b = run(&charter);
        assert_eq!(a, b);
        assert_eq!(codes(&a), codes(&b));
        // sanity: half the Supply modules (even i) are empty-issuer => N/2 KRP-021s,
        // plus 1 KRP-025 (KYC with no TransferPolicy) and 1 KRP-026 (empty name).
        assert_eq!(find(&a, "KRP-021").len(), N / 2);
        assert_eq!(find(&a, "KRP-025").len(), 1);
        assert_eq!(find(&a, "KRP-026").len(), 1);
    }
}
