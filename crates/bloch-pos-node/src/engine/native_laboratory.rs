//! Explicit laboratory identity and loopback-only transport policy.
use super::*;

pub(super) fn check_config(cfg: &Config, manifest: &Manifest) -> io::Result<()> {
    let lab_format = {
        #[cfg(feature = "native-lab")]
        {
            manifest.format == crate::genesis::ManifestFormat::NativeLab
        }
        #[cfg(not(feature = "native-lab"))]
        {
            false
        }
    };
    if cfg.native_lab != lab_format {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--native-lab and a BPOSLAB1 manifest must be selected together",
        ));
    }
    if !lab_format {
        return Ok(());
    }
    check_transport(cfg)?;
    if manifest.carryover.is_some() || !manifest.cohort.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native laboratory refuses official carryover/cohort",
        ));
    }
    Ok(())
}

pub(super) fn check_transport(cfg: &Config) -> io::Result<()> {
    if !cfg.native_lab {
        return Ok(());
    }
    let loopback = |address: &str| {
        address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    };
    if !matches!(cfg.transport, Transport::Devnet)
        || !loopback(&cfg.listen_addr)
        || !loopback(&cfg.rpc_bind)
        || !loopback(&cfg.metrics_bind)
        || !cfg.p2p_peers.is_empty()
        || cfg.peers.iter().any(|p| {
            !p.parse::<std::net::SocketAddr>()
                .is_ok_and(|a| a.ip().is_loopback())
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native laboratory requires loopback devnet transport",
        ));
    }
    Ok(())
}

pub(super) fn transition<V: bloch_pos_committee::SignatureVerifier>(
    verifier: V,
    enabled: bool,
    domain: [u8; 32],
) -> io::Result<Transition<V>> {
    if enabled {
        #[cfg(feature = "native-lab")]
        {
            return Transition::native_laboratory(verifier, domain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e));
        }
        #[cfg(not(feature = "native-lab"))]
        {
            let _ = domain;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native-lab feature is absent",
            ));
        }
    }
    Ok(Transition::new(verifier))
}

#[cfg(all(test, feature = "native-lab"))]
mod tests {
    use super::*;
    use bloch_euvm::{
        modules::{ModuleKind, SupplyConfig, TokenCharter},
        ustav::{
            gateway::{Route, RouteConfig},
            Registration,
        },
    };
    use bloch_pos_committee::transition::{
        native_dex::bootstrap, NativeTransferPayload, TransferInputV2, TransferOutput, WitnessKey,
    };
    fn config() -> Config {
        Config {
            native_lab: true,
            data_dir: PathBuf::new(),
            genesis_path: PathBuf::new(),
            transport: Transport::Devnet,
            listen: 0,
            listen_addr: "127.0.0.1".into(),
            peers: vec!["127.0.0.1:19310".into()],
            p2p_listen: vec![],
            p2p_peers: vec![],
            max_peers: 4,
            behind_proxy: false,
            stop_at_slot: Some(4),
            ws: crate::ws_boot::WsConfig {
                checkpoint: None,
                signer_set: None,
            },
            carryover_path: None,
            rpc_bind: "127.0.0.1".into(),
            rpc_port: None,
            metrics_bind: "127.0.0.1".into(),
            metrics_port: None,
        }
    }
    #[test]
    fn native_lab_config_refuses_official_manifest_and_remote_transport() {
        let mut m =
            Manifest::decode(include_bytes!("../../../../genesis/mainnet.manifest")).unwrap();
        let mut c = config();
        assert!(check_config(&c, &m).is_err());
        m.format = crate::genesis::ManifestFormat::NativeLab;
        assert!(check_config(&c, &m).is_err());
        m.carryover = None;
        m.cohort.clear();
        m.allocations.clear();
        assert!(check_config(&c, &m).is_ok());
        c.native_lab = false;
        assert!(check_config(&c, &m).is_err());
        c.native_lab = true;
        c.peers = vec!["192.0.2.1:19310".into()];
        assert!(check_config(&c, &m).is_err());
        c.peers.clear();
        c.rpc_bind = "0.0.0.0".into();
        assert!(check_config(&c, &m).is_err());
    }
    #[test]
    fn native_lab_real_signatures_admit_bootstrap_produce_and_replay() {
        let (mut e, dir) = perf_support::proposing_engine();
        let second = Keystore::generate_with(
            &dir.0.join("committee2"),
            1,
            &crate::keys::Unlock::PlaintextOptIn,
        )
        .unwrap();
        e.manifest.format = crate::genesis::ManifestFormat::NativeLab;
        let owner = e.keys.as_ref().unwrap();
        let pk = owner.pubkey.clone();
        let script: [u8; 32] = Sha3_256::digest(&pk).into();
        e.manifest.allocations = vec![crate::genesis::GenesisAllocation {
            purpose: crate::genesis::alloc_purpose::LIQUIDITY,
            script_hash: script,
            amount_sat: 100_000_000_000,
            unlock_epoch: 0,
        }];
        e.manifest.pre_state_root = std::sync::OnceLock::new();
        let pre = e.manifest.genesis_state();
        let domain = pre.admission_network_domain().unwrap();
        let opening = pre.utxos().next().unwrap().clone();
        e.chain = vec![(0, e.manifest.genesis_id())];
        e.canonical = BTreeSet::from([*e.manifest.genesis_id().as_bytes()]);
        e.state.set(pre.clone());
        e.tr = Transition::native_laboratory(HybridVerifier::new(), domain).unwrap();
        e.tr_probe = Transition::native_laboratory(ProbeVerifier, domain).unwrap();
        let registration = Registration {
            charter: TokenCharter {
                token_name: b"Synthetic lab".to_vec(),
                modules: vec![ModuleKind::Supply(SupplyConfig {
                    cap: 1000,
                    issuer_pubkey: pk.clone(),
                })],
            },
            nonce: [7; 32],
            initial_kyc_root: None,
        };
        let asset = registration.asset_id(&domain).unwrap();
        let sample = owner.sign(&[0; 32]);
        let mut r = bootstrap::Request {
            domain,
            blch: PosTransaction::TransferV2 {
                keys: vec![WitnessKey {
                    pubkey: pk.clone(),
                    signature: sample.clone(),
                }],
                inputs: vec![TransferInputV2 {
                    txid: opening.txid,
                    vout: opening.vout,
                    key_index: 0,
                }],
                outputs: vec![TransferOutput {
                    value: 1,
                    script_hash: script,
                }],
                tx_bytes: 0,
                tip_millisat_per_gas: 0,
            },
            registration,
            route: RouteConfig {
                route: Route {
                    source_domain: [9; 32],
                    native_domain: domain,
                    native_asset: asset,
                    token: [3; 20],
                    vault: [4; 20],
                    decimals: 6,
                    cap: 1000,
                    vault_code_hash: [5; 32],
                },
                committee: vec![pk, second.pubkey.clone()],
                threshold: 2,
            },
            valid_until: 1000,
            native_gas: 100_000,
            issuer_signature: sample.clone(),
            approvals: vec![sample, second.sign(&[0; 32])],
        };
        r.route.committee.sort();
        let declared = r.canonical_bytes().unwrap().len() as u64 + 5 + 64;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
            *tx_bytes = declared;
        }
        let charge = r.quote(pre.next_base_fee()).unwrap();
        if let PosTransaction::TransferV2 { outputs, .. } = &mut r.blch {
            outputs[0].value =
                opening.value - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
        }
        let hash = r.authorization().unwrap();
        if let PosTransaction::TransferV2 { keys, .. } = &mut r.blch {
            keys[0].signature = owner.sign(&hash);
        }
        r.issuer_signature = owner.sign(&hash);
        r.approvals = r
            .route
            .committee
            .iter()
            .map(|pk| {
                if *pk == owner.pubkey {
                    owner.sign(&hash)
                } else {
                    second.sign(&hash)
                }
            })
            .collect();
        let tx = PosTransaction::NativeBootstrap(
            NativeTransferPayload::new(r.canonical_bytes().unwrap()).unwrap(),
        );
        assert_eq!(tx_tip_rate(&tx), 0);
        assert_eq!(tx_source_hash(&tx), Some(script));
        assert_eq!(
            Engine::spent_outpoints(&tx),
            Some(vec![(opening.txid, opening.vout)])
        );
        assert!(e.on_transaction(tx.clone()).is_ok());
        assert_eq!(e.mempool.len(), 1);
        e.propose(1);
        assert_eq!(e.state.slot(), 1);
        assert!(e.mempool.is_empty());
        assert!(e.on_transaction(tx).is_err());
        let log = e.store.read_all().unwrap();
        assert_eq!(log.len(), 1);
        let env = &log[0];
        let replay =
            e.tr.apply_block(
                &pre,
                &ProposalEnvelope {
                    header: env.header.clone(),
                    proposer_sig: env.proposer_sig.clone(),
                },
                &env.body.attestations,
                &body_transactions(env).unwrap(),
            )
            .unwrap();
        assert_eq!(replay.state_root(), e.state.state_root());
        let view = e.state.native_lab_wallet_view().unwrap();
        assert_eq!(view.utxos, e.state.utxos().cloned().collect::<Vec<_>>());
        assert!(view.snapshot.len() <= 4 * 1024 * 1024);
        let reply = e.serve_rpc(RpcRequest::NativeWalletView { owner: None }).unwrap();
        assert!(format!("{reply:?}").contains("trusted-host-projection-not-finality-proof"));
        e.tr = Transition::new(HybridVerifier::new());
        assert!(e.serve_rpc(RpcRequest::NativeWalletView { owner: None }).is_err());
        e.tr = Transition::native_laboratory(HybridVerifier::new(), domain).unwrap();
        let bytes = e.state.native_component_snapshot_bytes().unwrap().unwrap();
        assert_eq!(
            replay
                .with_restored_native_component(&bytes, &HybridVerifier::new())
                .unwrap()
                .state_root(),
            replay.state_root()
        );
    }
}
