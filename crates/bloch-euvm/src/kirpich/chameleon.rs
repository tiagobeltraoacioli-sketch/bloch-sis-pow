//! Separate export compatibility profile. It does not change native v3 rules
//! or identities and is not an audit of bridge finality or deployed EVM code.
use super::{kirpich_audit, limits, AuditReport, Finding, Severity};
use crate::modules::{ModuleKind, TokenCharter};

pub const ERC20_PROFILE_VERSION: u32 = 1;

/// Native audit plus the v1 unrestricted ERC-20 preservation requirement.
/// Unsupported restrictions are denied; the adapter never silently drops them.
pub fn audit_erc20(charter: &TokenCharter, has_kyc_root: bool) -> AuditReport {
    let mut report = kirpich_audit(charter);
    // The native preflight already emitted its bounded resource finding.
    if limits::resource_error(charter).is_some() {
        return report;
    }
    if !matches!(charter.modules.as_slice(), [ModuleKind::Supply(_)]) || has_kyc_root {
        report.findings.push(Finding {
            code: "KRP-080",
            severity: Severity::Deny,
            module: None,
            index: None,
            message: "Chameleon ERC-20 profile v1 requires exactly one Supply module and no KYC root; additional policies need a preserving adapter".to_owned(),
        });
    }
    report.findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.code.cmp(b.code))
            .then_with(|| a.index.cmp(&b.index))
            .then_with(|| a.message.cmp(&b.message))
    });
    report.denied = report.has_deny();
    report
}
