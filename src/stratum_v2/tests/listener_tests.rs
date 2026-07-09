use crate::stratum_v2::{Sv2Config, Sv2StaticKeypair};
use tempfile::TempDir;

#[tokio::test]
async fn listener_can_bind_ephemeral() {
    let dir = TempDir::new().expect("tempdir");
    let key_path = dir.path().join("key.json");
    let kp = Sv2StaticKeypair::load_or_generate(&key_path).unwrap();

    let cfg = Sv2Config::new(
        "127.0.0.1:0".parse().unwrap(),
        10,
        key_path.clone(),
    )
    .unwrap();

    let tcp = tokio::net::TcpListener::bind(cfg.bind_addr).await;
    assert!(tcp.is_ok());

    let reloaded = Sv2StaticKeypair::load_or_generate(&cfg.cert_path).unwrap();
    assert_eq!(kp.fingerprint_hex(), reloaded.fingerprint_hex());
}

#[test]
fn stratum_core_linked() {
    // Smoke test: stratum_core is importable and re-exports work.
    use crate::stratum_v2::binary_sv2;
    use crate::stratum_v2::framing_sv2;
    let _ = std::any::type_name::<binary_sv2::U256>();
    let _ = std::any::type_name::<framing_sv2::header::Header>();
}
