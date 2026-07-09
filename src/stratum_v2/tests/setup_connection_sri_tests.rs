use crate::stratum_v2::setup_connection::{
    SetupConnectionError, SetupConnectionProtocol, SetupConnectionRequest,
    MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION,
};
use crate::stratum_v2::setup_connection_sri::{
    outcome_to_response_descriptor, sv2_error_code, sv2_protocol_name,
    SetupConnectionResponseDescriptor,
};

#[test]
fn sv2_name_matches_sri_reference_for_each_protocol() {
    assert_eq!(
        sv2_protocol_name(SetupConnectionProtocol::Mining),
        "MiningProtocol"
    );
    assert_eq!(
        sv2_protocol_name(SetupConnectionProtocol::JobDeclaration),
        "JobDeclarationProtocol"
    );
    assert_eq!(
        sv2_protocol_name(SetupConnectionProtocol::TemplateDistribution),
        "TemplateDistributionProtocol"
    );
}

#[test]
fn sv2_error_code_maps_unsupported_protocol() {
    let err = SetupConnectionError::UnsupportedProtocol(
        SetupConnectionProtocol::JobDeclaration,
    );
    assert_eq!(sv2_error_code(&err), "unsupported-protocol");
    let err_unknown = SetupConnectionError::UnknownProtocol(99);
    assert_eq!(sv2_error_code(&err_unknown), "unsupported-protocol");
}

#[test]
fn sv2_error_code_maps_version_mismatch() {
    let err = SetupConnectionError::VersionMismatch { min: 0, max: 1 };
    assert_eq!(sv2_error_code(&err), "protocol-version-mismatch");
}

#[test]
fn sv2_error_code_maps_unknown_flags() {
    let err = SetupConnectionError::UnknownFlags(0xDEAD_BEEF);
    assert_eq!(sv2_error_code(&err), "unsupported-feature-flags");
}

#[test]
fn descriptor_preserves_success_fields() {
    let happy = SetupConnectionRequest {
        protocol: SetupConnectionProtocol::Mining as u8,
        min_version: MIN_SUPPORTED_VERSION,
        max_version: MAX_SUPPORTED_VERSION,
        flags: 0,
    };
    let outcome = happy.validate(0);
    let descriptor = outcome_to_response_descriptor(&outcome);
    assert_eq!(
        descriptor,
        SetupConnectionResponseDescriptor::Success {
            used_version: MAX_SUPPORTED_VERSION,
            used_flags: 0,
        }
    );
}

#[test]
fn descriptor_preserves_error_code_for_job_declaration() {
    let bad = SetupConnectionRequest {
        protocol: SetupConnectionProtocol::JobDeclaration as u8,
        min_version: MIN_SUPPORTED_VERSION,
        max_version: MAX_SUPPORTED_VERSION,
        flags: 0,
    };
    let outcome = bad.validate(0);
    let descriptor = outcome_to_response_descriptor(&outcome);
    assert_eq!(
        descriptor,
        SetupConnectionResponseDescriptor::Error {
            error_code: "unsupported-protocol",
        }
    );
}
