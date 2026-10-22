// SPDX-License-Identifier: AGPL-3.0-or-later

//! `getfinalitycertificate` end to end on a real chain: N genesis validators
//! with real hybrid ML-DSA-65 ‖ Falcon-1024 keystores, every block proposed
//! and every vote signed through the production `attest`/`propose` paths and
//! applied by the production transition. The certificates the RPC returns are
//! then checked by the standalone verifier crate.
//!
//! `BLOCH_FINCERT_VALIDATORS` (default 106 — the mainnet-scale set) sizes the
//! chain; `BLOCH_FINCERT_VECTORS=<dir>` writes the certificates and anchor as
//! test vectors for `crates/bloch-finality-cert/tests/`.

use super::*;
use bloch_finality_cert::{size_report, verify, verify_chain, Certificate, HybridSigCheck, Refusal, TrustAnchors};

fn cert_of(engine: &mut Engine, epoch: Option<u64>, block: Option<[u8; 32]>, src: Option<u64>) -> (Json, Certificate) {
    let j = engine
        .serve_rpc(RpcRequest::FinalityCertificate { epoch, block, set_source_epoch: src })
        .unwrap_or_else(|e| panic!("certificate e{epoch:?}: {e:?}"));
    let hex = j.get("certificate").and_then(|c| c.as_str()).expect("certificate hex").to_string();
    let bytes = bloch_finality_cert::from_hex(&hex).expect("hex");
    let cert = Certificate::decode(&bytes).expect("decodes");
    assert_eq!(cert.encode(), bytes, "canonical round trip");
    (j, cert)
}

#[test]
fn real_chain_certificates_verify_chain_and_refuse_forgeries() {
    let n: u32 = std::env::var("BLOCH_FINCERT_VALIDATORS").ok().and_then(|v| v.parse().ok()).unwrap_or(106);
    let (mut engine, _dir, others) = perf_support::proposing_engine_n(&[], n);
    // Every validator as (keystore, its own slashing-protection db).
    let mut vals: Vec<(Option<Keystore>, SlashingProtection)> = Vec::new();
    let first = engine.keys.take();
    for (i, k) in std::iter::once(first.expect("validator 0")).chain(others).enumerate() {
        let d = _dir.0.join(format!("sp{i}"));
        std::fs::create_dir_all(&d).unwrap();
        vals.push((Some(k), SlashingProtection::open(&d).expect("slashprot")));
    }
    let as_each = |engine: &mut Engine, vals: &mut Vec<(Option<Keystore>, SlashingProtection)>, f: &dyn Fn(&mut Engine)| {
        for v in vals.iter_mut() {
            std::mem::swap(&mut engine.keys, &mut v.0);
            std::mem::swap(&mut engine.slashprot, &mut v.1);
            f(engine);
            std::mem::swap(&mut engine.keys, &mut v.0);
            std::mem::swap(&mut engine.slashprot, &mut v.1);
        }
    };
    let target_final = 4;
    for slot in 1..=(8 * SLOTS_PER_EPOCH) {
        as_each(&mut engine, &mut vals, &|e: &mut Engine| e.attest(slot));
        as_each(&mut engine, &mut vals, &|e: &mut Engine| e.propose(slot));
        assert_eq!(engine.head_slot_now(), slot, "slot {slot} must get a block");
        if engine.state.finality().finalized.epoch >= target_final {
            break;
        }
    }
    let fin = engine.state.finality().finalized.epoch;
    assert!(fin >= target_final, "finalized only e{fin}");

    // e1's set source would be genesis, whose unbound (V1) header commits no
    // state root — exactly why a verifier needs a later anchor.
    let err = engine
        .serve_rpc(RpcRequest::FinalityCertificate { epoch: Some(1), block: None, set_source_epoch: None })
        .unwrap_err();
    assert_eq!(err.code, rpc::NODE_UNAVAILABLE, "{err:?}");

    // Anchor: the epoch-1 checkpoint, trusted out of band (a WS checkpoint).
    let anchor = engine.checkpoint_root(1);
    let block_in_e2 = *engine.chain.iter().find(|(s, _)| epoch_of(*s) == 2).unwrap().1.as_bytes();
    let (j2, c2) = cert_of(&mut engine, Some(2), None, None);
    let (_, c3) = cert_of(&mut engine, Some(3), None, None);
    let (jl, c4) = cert_of(&mut engine, None, Some(block_in_e2), None);
    // A long hop: e4 proven against the e1 registry directly.
    let (_, c4_hop) = cert_of(&mut engine, Some(4), None, Some(1));
    assert_eq!(c4.epoch(), fin, "latest = the finalized checkpoint");
    assert!(!c4.ancestry.is_empty());

    let mut anchors = TrustAnchors::new([anchor]);
    let ok = verify_chain(&[c2.clone(), c3.clone(), c4.clone()], &mut anchors, &HybridSigCheck)
        .unwrap_or_else(|(i, e)| panic!("cert {i}: {e:?}"));
    assert_eq!(ok[2].ancestry_tip.map(|t| t.1), Some(block_in_e2));
    for v in &ok {
        assert_eq!(v.votes, [n as usize, n as usize], "full participation, every vote listed");
    }
    verify(&c4_hop, &TrustAnchors::new([anchor]), &HybridSigCheck).expect("hop certificate");
    // Without the chain, e3's set source (e2) is not trusted.
    assert!(matches!(
        verify(&c3, &TrustAnchors::new([anchor]), &HybridSigCheck),
        Err(Refusal::UntrustedSetSource { .. })
    ));

    // Size, measured on this chain.
    let full = size_report(&c2);
    let mut minimal = c2.clone();
    let need = (2 * n as usize).div_ceil(3);
    for l in minimal.links.iter_mut() {
        l.votes.truncate(need);
    }
    verify(&minimal, &TrustAnchors::new([anchor]), &HybridSigCheck).expect("2/3 subset verifies");
    let min = size_report(&minimal);
    eprintln!(
        "FINCERT n={n}: full={} B (registry {} B, votes {:?} B), minimal(2/3)={} B, json reply bytes field={}",
        full.total,
        full.registry,
        full.votes,
        min.total,
        j2.get("bytes").map(|b| b.to_string()).unwrap_or_default()
    );
    let _ = jl;

    if let Ok(dir) = std::env::var("BLOCH_FINCERT_VECTORS") {
        let d = std::path::Path::new(&dir);
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("anchor.hex"), bloch_finality_cert::to_hex(&anchor)).unwrap();
        std::fs::write(d.join("cert_e2.bin"), c2.encode()).unwrap();
        std::fs::write(d.join("cert_e3.bin"), c3.encode()).unwrap();
        std::fs::write(d.join("cert_e4_ancestry.bin"), c4.encode()).unwrap();
        std::fs::write(d.join("ancestry_block.hex"), bloch_finality_cert::to_hex(&block_in_e2)).unwrap();
    }
}
