//! Integration test: the Kirpich audit gate over the Ustav charter compile path.
//!
//! Proves the two ends of the fail-closed contract through the crate's PUBLIC API:
//!   * a charter carrying a `Deny` finding makes `compile_charter_audited` return
//!     `Err(report)` (with `report.denied` set) — it never reaches the compiler;
//!   * a clean charter compiles successfully and its result is byte-identical to the
//!     un-audited `compile_charter` (the gate is transparent when it passes);
//!   * the audit is deterministic across repeated runs.

use bloch_euvm::kirpich_audit;
use bloch_euvm::modules::{
    compile_charter, compile_charter_audited, CustodyConfig, GovernanceConfig, KycConfig,
    ModuleKind, SupplyConfig, TokenCharter, TransferPolicyConfig, VestingConfig,
};
use bloch_euvm::Severity;

/// A well-formed charter using every module kind once; audits completely clean.
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
fn deny_charter_is_rejected_fail_closed() {
    // Two Supply modules (KRP-001, Deny) + a 0-of-2 governance (KRP-040, Deny). The audit
    // must deny, so the audited compile must return Err and never produce a CompiledToken.
    let charter = TokenCharter {
        token_name: b"BAD".to_vec(),
        modules: vec![
            ModuleKind::Supply(SupplyConfig { cap: 10, issuer_pubkey: b"a".to_vec() }),
            ModuleKind::Supply(SupplyConfig { cap: 20, issuer_pubkey: b"b".to_vec() }),
            ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"g1".to_vec(), b"g2".to_vec()],
                threshold: 0,
            }),
        ],
    };

    let result = compile_charter_audited(&charter);
    let report = result.expect_err("a Deny-carrying charter must fail closed (Err)");
    assert!(report.denied, "report.denied must be set on the error path");
    assert!(report.has_deny());
    assert!(report.count(Severity::Deny) >= 1);
    // The offending rules are present in the report.
    assert!(report.findings.iter().any(|f| f.code == "KRP-001"));
    assert!(report.findings.iter().any(|f| f.code == "KRP-040"));
    // Fail-closed also means "no compiled output leaks out" — Err carries a report, not a
    // CompiledToken, which the type system already guarantees here.
}

#[test]
fn clean_charter_compiles_and_matches_unaudited() {
    let charter = clean_charter();

    // The audited path succeeds…
    let audited = compile_charter_audited(&charter).expect("clean charter must compile");
    // …and is transparent: identical charter id + validator set to the un-audited compile.
    let direct = compile_charter(&charter);
    assert_eq!(audited.charter_id, direct.charter_id);
    assert_eq!(audited.validators.len(), direct.validators.len());
    for (a, d) in audited.validators.iter().zip(direct.validators.iter()) {
        assert_eq!(a.kind, d.kind);
        assert_eq!(a.validator_hash, d.validator_hash);
    }

    // And the report itself is clean.
    let report = kirpich_audit(&charter);
    assert!(!report.denied);
    assert!(report.findings.is_empty(), "clean charter must have zero findings: {:?}", report.findings);
}

#[test]
fn audit_is_deterministic_across_runs() {
    let charter = TokenCharter {
        token_name: vec![], // KRP-026 (Warn) among others
        modules: vec![
            ModuleKind::Custody(CustodyConfig { btc_pubkey: vec![], pq_pubkey: vec![] }),
            ModuleKind::Governance(GovernanceConfig {
                signers: vec![b"dup".to_vec(), b"dup".to_vec()],
                threshold: 0,
            }),
        ],
    };
    let a = kirpich_audit(&charter);
    let b = kirpich_audit(&charter);
    assert_eq!(a.findings, b.findings, "same charter must yield byte-identical findings");
    assert_eq!(a.denied, b.denied);
    assert!(a.denied);
}
