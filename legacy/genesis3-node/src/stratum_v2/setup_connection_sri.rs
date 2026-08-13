//! SV2 interop layer for `SetupConnection` (Sprint 8c-gamma).
//!
//! Maps Bloch-SIS Protocol's policy-layer types from
//! [`super::setup_connection`] onto the names and strings that the
//! Stratum V2 reference implementation (SRI) expects on the wire.
//!
//! The actual construction of SRI structs
//! (`stratum_core::common_messages_sv2::SetupConnectionSuccess`,
//! `SetupConnectionError`, etc.) is deferred to Sprint 8d, where
//! `session::run_loop` will build them from the descriptors this
//! module produces. Keeping that step separate lets us iterate on
//! the exact SRI type paths against the compiler instead of in an
//! offline-generated module.

#![allow(dead_code)]

use super::setup_connection::{
    SetupConnectionError, SetupConnectionOutcome, SetupConnectionProtocol,
};

/// Canonical subprotocol name as used in the SV2 reference.
///
/// These match the variant names of
/// `stratum_core::common_messages_sv2::Protocol` exactly, so they
/// can be used to build log lines or error strings that match
/// upstream SRI output byte-for-byte.
pub fn sv2_protocol_name(proto: SetupConnectionProtocol) -> &'static str {
    match proto {
        SetupConnectionProtocol::Mining => "MiningProtocol",
        SetupConnectionProtocol::JobDeclaration => "JobDeclarationProtocol",
        SetupConnectionProtocol::TemplateDistribution => "TemplateDistributionProtocol",
    }
}

/// SV2-spec error-code string for a given Bloch-SIS Protocol error.
///
/// The codes below match the Stratum V2 specification v2.0
/// ("Setup Connection -> Error") and are the exact strings the SRI
/// implementation compares against when rejecting a handshake.
pub fn sv2_error_code(err: &SetupConnectionError) -> &'static str {
    match err {
        SetupConnectionError::UnknownProtocol(_) => "unsupported-protocol",
        SetupConnectionError::UnsupportedProtocol(_) => "unsupported-protocol",
        SetupConnectionError::VersionMismatch { .. } => "protocol-version-mismatch",
        SetupConnectionError::UnknownFlags(_) => "unsupported-feature-flags",
    }
}

/// Intermediate representation produced from a
/// [`SetupConnectionOutcome`] by [`outcome_to_response_descriptor`].
///
/// Session code (Sprint 8d) consumes this to build the actual SRI
/// `SetupConnectionSuccess` or `SetupConnectionError` frame.
/// Keeping the descriptor stringly-typed for `error_code` matches
/// what the SRI type expects in its `error_code: Str0255<'a>` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupConnectionResponseDescriptor {
    Success {
        used_version: u16,
        used_flags: u32,
    },
    Error {
        error_code: &'static str,
    },
}

/// Translate a policy-layer outcome into a session-layer response descriptor.
pub fn outcome_to_response_descriptor(
    outcome: &SetupConnectionOutcome,
) -> SetupConnectionResponseDescriptor {
    match outcome {
        SetupConnectionOutcome::Success {
            used_version,
            used_flags,
        } => SetupConnectionResponseDescriptor::Success {
            used_version: *used_version,
            used_flags: *used_flags,
        },
        SetupConnectionOutcome::Error(err) => SetupConnectionResponseDescriptor::Error {
            error_code: sv2_error_code(err),
        },
    }
}
