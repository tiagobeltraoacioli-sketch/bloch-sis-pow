use crate::stratum_v2::setup_connection::{
    SetupConnectionError, SetupConnectionOutcome, SetupConnectionProtocol,
    SetupConnectionRequest, MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION,
};

const NO_FLAGS: u32 = 0;

#[test]
fn setup_accepts_mining_protocol_happy_path() {
    let req = SetupConnectionRequest {
        protocol: SetupConnectionProtocol::Mining as u8,
        min_version: MIN_SUPPORTED_VERSION,
        max_version: MAX_SUPPORTED_VERSION,
        flags: 0,
    };
    match req.validate(NO_FLAGS) {
        SetupConnectionOutcome::Success { used_version, used_flags } => {
            assert_eq!(used_version, MAX_SUPPORTED_VERSION);
            assert_eq!(used_flags, 0);
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn setup_rejects_job_declaration_protocol() {
    let req = SetupConnectionRequest {
        protocol: SetupConnectionProtocol::JobDeclaration as u8,
        min_version: MIN_SUPPORTED_VERSION,
        max_version: MAX_SUPPORTED_VERSION,
        flags: 0,
    };
    assert!(matches!(
        req.validate(NO_FLAGS),
        SetupConnectionOutcome::Error(SetupConnectionError::UnsupportedProtocol(
            SetupConnectionProtocol::JobDeclaration
        ))
    ));
}

#[test]
fn setup_rejects_unknown_protocol_byte() {
    let req = SetupConnectionRequest {
        protocol: 99,
        min_version: MIN_SUPPORTED_VERSION,
        max_version: MAX_SUPPORTED_VERSION,
        flags: 0,
    };
    assert!(matches!(
        req.validate(NO_FLAGS),
        SetupConnectionOutcome::Error(SetupConnectionError::UnknownProtocol(99))
    ));
}

#[test]
fn setup_rejects_version_window_below_local_min() {
    let req = SetupConnectionRequest {
        protocol: SetupConnectionProtocol::Mining as u8,
        min_version: 0,
        max_version: MIN_SUPPORTED_VERSION.saturating_sub(1),
        flags: 0,
    };
    assert!(matches!(
        req.validate(NO_FLAGS),
        SetupConnectionOutcome::Error(SetupConnectionError::VersionMismatch { .. })
    ));
}

#[test]
fn setup_rejects_unknown_flag_bits() {
    let req = SetupConnectionRequest {
        protocol: SetupConnectionProtocol::Mining as u8,
        min_version: MIN_SUPPORTED_VERSION,
        max_version: MAX_SUPPORTED_VERSION,
        flags: 0b1010,
    };
    match req.validate(0b0010) {
        SetupConnectionOutcome::Error(SetupConnectionError::UnknownFlags(bits)) => {
            assert_eq!(bits, 0b1000);
        }
        other => panic!("expected UnknownFlags error, got {other:?}"),
    }
}
