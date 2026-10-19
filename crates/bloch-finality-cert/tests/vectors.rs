// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test vectors from a real test chain (106 genesis validators, real hybrid
//! ML-DSA-65 ‖ Falcon-1024 keys, blocks produced and applied by the
//! production engine; see `bloch-pos-node/src/engine/finality_cert_tests.rs`),
//! and the refusal cases an integrator must see fail.

use bloch_finality_cert::*;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn cert(name: &str) -> Certificate {
    let b = std::fs::read(dir().join(name)).expect("vector present");
    let c = Certificate::decode(&b).expect("vector decodes");
    assert_eq!(c.encode(), b, "{name}: encoding is canonical");
    c
}

fn hex32(name: &str) -> [u8; 32] {
    let s = std::fs::read_to_string(dir().join(name)).unwrap();
    from_hex(&s).unwrap().try_into().unwrap()
}

fn anchors() -> TrustAnchors {
    TrustAnchors::new([hex32("anchor.hex")])
}

fn ok(c: &Certificate) -> Verified {
    verify(c, &anchors(), &HybridSigCheck).expect("vector verifies")
}

#[test]
fn vectors_verify_as_a_chain_from_the_anchor() {
    let chain = [cert("cert_e2.bin"), cert("cert_e3.bin"), cert("cert_e4_ancestry.bin")];
    let mut a = anchors();
    let v = verify_chain(&chain, &mut a, &HybridSigCheck).unwrap_or_else(|(i, e)| panic!("cert {i}: {e:?}"));
    assert_eq!(v.iter().map(|x| x.epoch).collect::<Vec<_>>(), vec![2, 3, 4]);
    assert_eq!(v[2].ancestry_tip.map(|t| t.1), Some(hex32("ancestry_block.hex")));
    for x in &v {
        assert_eq!(x.votes, [106, 106]);
        assert_eq!(x.stake[0].0, x.stake[0].1, "full participation");
    }
    let s = size_report(&chain[0]);
    eprintln!("cert_e2: {s:?}");
}

#[test]
fn refuses_a_forged_signature() {
    let mut c = cert("cert_e2.bin");
    let last = c.links[1].votes[5].signature.len() - 1;
    c.links[1].votes[5].signature[last / 2] ^= 0x01;
    let who = c.links[1].votes[5].validator;
    assert_eq!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::BadSignature { link: 1, validator: who }));
    // A valid signature moved to another validator's slot is also forged.
    let mut c = cert("cert_e2.bin");
    let sig = c.links[0].votes[0].signature.clone();
    c.links[0].votes[1].signature = sig;
    assert!(matches!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::BadSignature { link: 0, .. })));
}

#[test]
fn refuses_insufficient_stake() {
    let mut c = cert("cert_e2.bin");
    // Exactly 2/3 of 106 equal bonds needs 71 votes; 70 must fail.
    c.links[0].votes.truncate(71);
    ok(&c);
    c.links[0].votes.truncate(70);
    assert!(matches!(
        verify(&c, &anchors(), &HybridSigCheck),
        Err(Refusal::InsufficientStake { link: 0, .. })
    ));
    let mut c = cert("cert_e2.bin");
    c.links[1].votes.clear();
    assert!(matches!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::InsufficientStake { link: 1, .. })));
    // Duplicating votes cannot manufacture stake.
    let mut c = cert("cert_e2.bin");
    c.links[0].votes.truncate(70);
    let dup = c.links[0].votes[0].clone();
    c.links[0].votes.push(dup);
    assert!(matches!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::DuplicateOrUnsortedVote { .. })));
}

#[test]
fn refuses_a_wrong_or_shrunk_validator_set() {
    // Untrusted set source (no anchor / another chain's anchor).
    let c = cert("cert_e2.bin");
    assert!(matches!(
        verify(&c, &TrustAnchors::new([[0x42; 32]]), &HybridSigCheck),
        Err(Refusal::UntrustedSetSource { .. })
    ));
    // A record whose stake was inflated no longer matches the state root.
    let mut c = cert("cert_e2.bin");
    let mut rec = bloch_pos_committee::state_root::ValidatorRecord::from_canonical_bytes(&c.registry.records[3].0).unwrap();
    rec.stake *= 1000;
    c.registry.records[3].0 = rec.canonical_bytes();
    assert_eq!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::RegistryProof { index: 3 }));
    // A swapped key: same.
    let mut c = cert("cert_e2.bin");
    let mut rec = bloch_pos_committee::state_root::ValidatorRecord::from_canonical_bytes(&c.registry.records[4].0).unwrap();
    rec.pubkey = bloch_pos_committee::state_root::ValidatorRecord::from_canonical_bytes(&c.registry.records[5].0).unwrap().pubkey;
    c.registry.records[4].0 = rec.canonical_bytes();
    assert_eq!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::RegistryProof { index: 4 }));
    // Omitting members (to shrink the denominator) is caught by the absence
    // proofs: dropping the last 40 records leaves index 66 unproven-absent.
    let mut c = cert("cert_e2.bin");
    c.registry.records.truncate(66);
    assert!(matches!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::RegistryIncomplete { .. })));
    // ...and by the gap rule when a middle record goes.
    let mut c = cert("cert_e2.bin");
    c.registry.records.remove(10);
    assert!(matches!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::RegistryIncomplete { index: 10 })));
    // A set source from later than the certified epoch is refused.
    let c4 = cert("cert_e4_ancestry.bin");
    let mut c = cert("cert_e2.bin");
    c.registry = c4.registry.clone();
    let mut a = anchors();
    a.roots.insert(c4.links[0].source_root);
    assert!(matches!(verify(&c, &a, &HybridSigCheck), Err(Refusal::SetSourceDistance { .. })));
}

#[test]
fn refuses_a_foreign_root() {
    // Claim another root for epoch 2: header no longer hashes to it.
    let mut c = cert("cert_e2.bin");
    let other = cert("cert_e3.bin").root();
    c.links[0].target_root = other;
    c.links[1].source_root = other;
    assert_eq!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::CheckpointMismatch));
    // Swap in the matching header too: then the votes do not sign that root.
    let mut c = cert("cert_e2.bin");
    let c3 = cert("cert_e3.bin");
    c.checkpoint_header = c3.checkpoint_header;
    c.links[0].target_root = other;
    c.links[1].source_root = other;
    assert!(verify(&c, &anchors(), &HybridSigCheck).is_err());
    // Votes from another epoch's certificate do not certify this one.
    let mut c = cert("cert_e2.bin");
    c.links[1] = cert("cert_e3.bin").links[1].clone();
    assert!(matches!(verify(&c, &anchors(), &HybridSigCheck), Err(Refusal::LinkShape(_))));
    // A broken ancestry is refused.
    let mut c = cert("cert_e4_ancestry.bin");
    c.ancestry.remove(1);
    let mut a = anchors();
    for r in [cert("cert_e2.bin").root(), cert("cert_e3.bin").root()] {
        a.roots.insert(r);
    }
    assert_eq!(verify(&c, &a, &HybridSigCheck), Err(Refusal::AncestryBroken { at: 1 }));
}

#[test]
fn malformed_bytes_never_panic() {
    let b = std::fs::read(dir().join("cert_e2.bin")).unwrap();
    for cut in [0, 7, 10, 400, 900, b.len() / 2, b.len() - 1] {
        assert!(Certificate::decode(&b[..cut]).is_err());
    }
    let mut t = b.clone();
    t.push(0);
    assert_eq!(Certificate::decode(&t), Err(Refusal::Malformed("trailing bytes")));
}
