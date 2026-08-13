use crate::stratum_v2::{Sv2Config, Sv2Error};
use std::path::PathBuf;

#[test]
fn config_new_happy_path() {
    let cfg = Sv2Config::new(
        "0.0.0.0:3334".parse().unwrap(),
        500,
        PathBuf::from("/tmp/key.json"),
    )
    .expect("valid config");
    assert_eq!(cfg.max_sessions, 500);
    assert_eq!(cfg.bind_addr.port(), 3334);
}

#[test]
fn config_rejects_zero_sessions() {
    let result = Sv2Config::new(
        "0.0.0.0:3334".parse().unwrap(),
        0,
        PathBuf::from("/tmp/key.json"),
    );
    assert!(matches!(result, Err(Sv2Error::Config(_))));
}

#[test]
fn config_rejects_excessive_sessions() {
    let result = Sv2Config::new(
        "0.0.0.0:3334".parse().unwrap(),
        20_000,
        PathBuf::from("/tmp/key.json"),
    );
    assert!(matches!(result, Err(Sv2Error::Config(_))));
}
