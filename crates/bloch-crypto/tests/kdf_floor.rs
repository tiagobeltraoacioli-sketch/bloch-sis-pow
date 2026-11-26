//! A new keyfile cannot be written below the Argon2id floor (review F12).
//! This is an integration test on purpose: the crate's own unit tests encrypt
//! with tiny parameters and are exempt, every other build is not.
use bloch_crypto::address::Network;
use bloch_crypto::wallet::encryption::{EncryptedKeyfile, KdfParams};

const PASSWORD: &str = "correct horse battery staple 42";

fn floor() -> KdfParams {
    KdfParams {
        m_cost: KdfParams::MIN_M_COST_KIB,
        t_cost: KdfParams::MIN_T_COST,
        p_cost: KdfParams::MIN_P_COST,
    }
}

#[test]
fn encrypt_refuses_kdf_params_below_the_floor() {
    let weak = [
        KdfParams { m_cost: KdfParams::MIN_M_COST_KIB - 1, ..floor() },
        KdfParams { t_cost: KdfParams::MIN_T_COST - 1, ..floor() },
        KdfParams { p_cost: 0, ..floor() },
        KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 },
    ];
    for params in weak {
        assert!(params.check_floor().is_err());
        assert!(
            EncryptedKeyfile::encrypt_with_params(&[7u8; 64], &[9u8; 64], Network::Mainnet, PASSWORD, params).is_err(),
            "v1 keyfile written with m={} t={} p={}", params.m_cost, params.t_cost, params.p_cost
        );
        assert!(
            EncryptedKeyfile::encrypt_seed_v2_with_params(
                &[3u8; 64], &[7u8; 64], &[9u8; 64], Network::Mainnet, PASSWORD, params
            ).is_err(),
            "v2 keyfile written with m={} t={} p={}", params.m_cost, params.t_cost, params.p_cost
        );
    }
}

#[test]
fn the_floor_itself_and_the_default_are_accepted() {
    assert!(floor().check_floor().is_ok());
    assert!(KdfParams::default().check_floor().is_ok());
    let keyfile = EncryptedKeyfile::encrypt_with_params(&[7u8; 64], &[9u8; 64], Network::Mainnet, PASSWORD, floor())
        .expect("the floor is a usable setting");
    assert_eq!(keyfile.kdf.m_cost, KdfParams::MIN_M_COST_KIB);
}
