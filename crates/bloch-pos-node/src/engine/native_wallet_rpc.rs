//! Official RPC identity and canonical activation policy; no runtime gate override.
use super::*;
use bloch_pos_committee::{transition::native_wallet::WalletOperation, SignatureVerifier};
pub(super) fn format<V: SignatureVerifier>(
    manifest: &Manifest,
    state: &CommittedState,
    transition: &Transition<V>,
    operation: WalletOperation,
) -> Result<&'static str, rpc::RpcError> {
    let domain: [u8; 32] = Sha3_256::digest(manifest.encode()).into();
    if state.admission_network_domain() != Some(domain) {
        return Err(rpc::RpcError::new(
            -32000,
            "canonical network domain does not match manifest",
        ));
    }
    match manifest.format {
        #[cfg(feature = "native-lab")]
        crate::genesis::ManifestFormat::NativeLab => {
            if !transition.native_lab_matches(&state) {
                return Err(rpc::RpcError::new(
                    -32601,
                    "native laboratory is not selected",
                ));
            }
            Ok("BPOSLAB1")
        }
        format => {
            if transition.native_lab_matches(&state) {
                return Err(rpc::RpcError::new(
                    -32000,
                    "laboratory transition cannot serve official wallet state",
                ));
            }
            state
                .authorize_native_wallet(domain, operation)
                .map_err(|e| rpc::RpcError::new(-32000, e))?;
            Ok(match format {
                crate::genesis::ManifestFormat::V1Unbound => "BPOSMAN1",
                crate::genesis::ManifestFormat::V2Bound => "BPOSMAN2",
                #[cfg(feature = "native-lab")]
                crate::genesis::ManifestFormat::NativeLab => unreachable!(),
            })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_wallet_identity_is_manifest_bound_and_disabled_before_activation() {
        let raw = include_bytes!("../../../../genesis/mainnet.manifest");
        let manifest = Manifest::decode(raw).unwrap();
        assert_eq!(manifest.encode(), raw);
        let domain: [u8; 32] = Sha3_256::digest(raw).into();
        assert_eq!(
            crate::codec::hex(&domain),
            "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966"
        );
        let state = bloch_pos_committee::transition::native_dex::wallet_projection::base(
            Sha3_256::digest(manifest.encode()).into(),
            &[],
            10,
            0,
            0,
            0,
        )
        .unwrap();
        assert_eq!(state.admission_network_domain(), Some(domain));
        assert_eq!(crate::codec::hex(manifest.genesis_id().as_bytes()), "9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415");
        let transition = Transition::new(HybridVerifier::new());
        for operation in [
            WalletOperation::View,
            WalletOperation::Pool,
            WalletOperation::Withdrawal,
        ] {
            assert!(format(&manifest, &state, &transition, operation).is_err());
        }
        let mut wrong_manifest = Manifest::decode(raw).unwrap();
        wrong_manifest.genesis_time_ms += 1;
        let failure =
            format(&wrong_manifest, &state, &transition, WalletOperation::View).unwrap_err();
        assert!(failure.message.contains("domain"));
    }
    #[cfg(feature = "native-lab")]
    #[test]
    fn laboratory_transition_cannot_serve_official_manifest() {
        let manifest =
            Manifest::decode(include_bytes!("../../../../genesis/mainnet.manifest")).unwrap();
        let state = bloch_pos_committee::transition::native_dex::wallet_projection::base(
            Sha3_256::digest(manifest.encode()).into(),
            &[],
            10,
            0,
            0,
            0,
        )
        .unwrap();
        let transition = Transition::native_laboratory(
            HybridVerifier::new(),
            state.admission_network_domain().unwrap(),
        )
        .unwrap();
        assert!(
            format(&manifest, &state, &transition, WalletOperation::View)
                .unwrap_err()
                .message
                .contains("laboratory transition")
        );
    }
}
