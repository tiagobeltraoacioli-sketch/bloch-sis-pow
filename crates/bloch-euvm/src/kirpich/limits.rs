//! Allocation-free admission checks, before conflict maps or compilation.
use crate::modules::{ModuleKind, TokenCharter};

pub const MAX_TOKEN_NAME_BYTES: usize = 256;
pub const MAX_CHARTER_MODULES: usize = 64;
pub const MAX_CHARTER_BYTES: usize = 270_336;
pub const MAX_KEY_BYTES: usize = 8192;
pub const MAX_KEY_BYTES_TOTAL: usize = 262_144;
// Structural ceiling only; the semantic quorum ceiling remains 253 (KRP-042).
const MAX_SIGNER_ENTRIES: usize = 1024;

/// Visit borrowed keys without constructing an intermediate vector. The caller
/// can stop at the first error, including in a hostile governance signer list.
pub(crate) fn visit_keys<E>(
    module: &ModuleKind,
    mut f: impl FnMut(bool, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    match module {
        ModuleKind::Supply(c) => f(false, &c.issuer_pubkey),
        ModuleKind::TransferPolicy(c) => f(false, &c.authority_pubkey),
        ModuleKind::ComplianceKycGate(_) => Ok(()),
        ModuleKind::Vesting(c) => f(false, &c.beneficiary_pubkey),
        ModuleKind::Governance(c) => c.signers.iter().try_for_each(|pk| f(false, pk)),
        ModuleKind::Custody(c) => {
            f(true, &c.btc_pubkey)?;
            f(false, &c.pq_pubkey)
        }
    }
}

pub(crate) fn resource_error(charter: &TokenCharter) -> Option<(&'static str, &'static str)> {
    if charter.token_name.len() > MAX_TOKEN_NAME_BYTES {
        return Some(("KRP-047", "token name exceeds 256 bytes"));
    }
    if charter.modules.len() > MAX_CHARTER_MODULES {
        return Some(("KRP-047", "charter exceeds 64 modules"));
    }
    let mut total_keys = 0usize;
    // Upper bound including tags, scalar fields and all length prefixes.
    let mut encoded = 16usize.saturating_add(charter.token_name.len());
    for module in &charter.modules {
        if let ModuleKind::Governance(c) = module {
            if c.signers.len() > MAX_SIGNER_ENTRIES {
                return Some(("KRP-047", "governance input exceeds 1024 signer entries"));
            }
        }
        encoded = encoded.saturating_add(32);
        let result = visit_keys(module, |_, key| {
            total_keys = total_keys.saturating_add(key.len());
            encoded = encoded.saturating_add(8).saturating_add(key.len());
            if key.len() > MAX_KEY_BYTES || total_keys > MAX_KEY_BYTES_TOTAL {
                return Err((
                    "KRP-046",
                    "charter exceeds the individual or total public-key byte budget",
                ));
            }
            if encoded > MAX_CHARTER_BYTES {
                return Err(("KRP-047", "charter encoding exceeds its byte budget"));
            }
            Ok(())
        });
        if let Err(error) = result {
            return Some(error);
        }
    }
    None
}
