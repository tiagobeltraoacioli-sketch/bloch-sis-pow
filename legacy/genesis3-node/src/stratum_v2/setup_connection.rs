//! SV2 `SetupConnection` policy layer (Sprint 8c-beta scaffold; Sprint 9-beta flag mask).

#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupConnectionProtocol {
    Mining = 0,
    JobDeclaration = 1,
    TemplateDistribution = 2,
}

impl SetupConnectionProtocol {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Mining),
            1 => Some(Self::JobDeclaration),
            2 => Some(Self::TemplateDistribution),
            _ => None,
        }
    }

    pub fn is_supported_on_bloch(self) -> bool {
        matches!(self, Self::Mining | Self::TemplateDistribution)
    }
}

pub const MIN_SUPPORTED_VERSION: u16 = 2;
pub const MAX_SUPPORTED_VERSION: u16 = 2;

/// Flags Bloch-SIS Protocol recognises at `SetupConnection` time.
///
/// Current recognised bits:
/// - `0x0000_0001` — REQUIRES_STANDARD_JOB / ALLOW_FULL_TEMPLATE_MODE
///
/// NOT yet recognised (future sprints):
/// - `0x2000_0000` — REQUIRES_WORK_SELECTION
/// - `0x4000_0000` — REQUIRES_VERSION_ROLLING
pub const KNOWN_FLAG_MASK: u32 = 0x0000_0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupConnectionError {
    UnknownProtocol(u8),
    UnsupportedProtocol(SetupConnectionProtocol),
    VersionMismatch { min: u16, max: u16 },
    UnknownFlags(u32),
}

impl std::fmt::Display for SetupConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProtocol(b) => write!(f, "unknown SV2 protocol byte: {b}"),
            Self::UnsupportedProtocol(p) => write!(f, "unsupported SV2 protocol: {p:?}"),
            Self::VersionMismatch { min, max } => write!(
                f,
                "version range {}..={} does not overlap local {}..={}",
                min, max, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION
            ),
            Self::UnknownFlags(bits) => write!(f, "unknown SV2 flag bits: 0x{bits:08x}"),
        }
    }
}

impl std::error::Error for SetupConnectionError {}

#[derive(Debug, Clone)]
pub struct SetupConnectionRequest {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupConnectionOutcome {
    Success { used_version: u16, used_flags: u32 },
    Error(SetupConnectionError),
}

impl SetupConnectionRequest {
    pub fn validate(&self, known_flag_mask: u32) -> SetupConnectionOutcome {
        let proto = match SetupConnectionProtocol::from_u8(self.protocol) {
            Some(p) => p,
            None => {
                return SetupConnectionOutcome::Error(
                    SetupConnectionError::UnknownProtocol(self.protocol),
                );
            }
        };

        if !proto.is_supported_on_bloch() {
            return SetupConnectionOutcome::Error(
                SetupConnectionError::UnsupportedProtocol(proto),
            );
        }

        if self.max_version < MIN_SUPPORTED_VERSION
            || self.min_version > MAX_SUPPORTED_VERSION
        {
            return SetupConnectionOutcome::Error(
                SetupConnectionError::VersionMismatch {
                    min: self.min_version,
                    max: self.max_version,
                },
            );
        }

        let unknown = self.flags & !known_flag_mask;
        if unknown != 0 {
            return SetupConnectionOutcome::Error(
                SetupConnectionError::UnknownFlags(unknown),
            );
        }

        let used_version = self.max_version.min(MAX_SUPPORTED_VERSION);
        SetupConnectionOutcome::Success {
            used_version,
            used_flags: self.flags,
        }
    }
}

#[cfg(test)]
mod tests_flag_mask {
    use super::*;

    #[test]
    fn known_flag_mask_accepts_requires_standard_job() {
        let req = SetupConnectionRequest {
            protocol: 0,
            min_version: 2,
            max_version: 2,
            flags: 0x0000_0001,
        };
        let outcome = req.validate(KNOWN_FLAG_MASK);
        assert!(matches!(
            outcome,
            SetupConnectionOutcome::Success {
                used_version: 2,
                used_flags: 0x0000_0001
            }
        ));
    }

    #[test]
    fn known_flag_mask_rejects_work_selection() {
        let req = SetupConnectionRequest {
            protocol: 0,
            min_version: 2,
            max_version: 2,
            flags: 0x2000_0000,
        };
        let outcome = req.validate(KNOWN_FLAG_MASK);
        assert!(matches!(
            outcome,
            SetupConnectionOutcome::Error(SetupConnectionError::UnknownFlags(0x2000_0000))
        ));
    }

    #[test]
    fn known_flag_mask_rejects_combined_known_and_unknown() {
        let req = SetupConnectionRequest {
            protocol: 0,
            min_version: 2,
            max_version: 2,
            flags: 0x0000_0001 | 0x4000_0000,
        };
        let outcome = req.validate(KNOWN_FLAG_MASK);
        assert!(matches!(
            outcome,
            SetupConnectionOutcome::Error(SetupConnectionError::UnknownFlags(0x4000_0000))
        ));
    }
}
