// SPDX-License-Identifier: AGPL-3.0-or-later
//! Audit L1N-03 (red team W3-4): the certificate assembly budget is shared
//! out per caller, and a request naming another `block` is not a new scan.
//!
//! Eight unauthenticated requests per slot, each naming a different `block`
//! of one finalized epoch, used to be eight assemblies (sixteen epoch scans
//! on the consensus thread) and to refuse every other caller of
//! `getfinalitycertificate` and `getlcproof` until the next slot.
use super::finality_cert::{
    BuildShares, CertLinks, FinalityCertStore, CERT_BUILDS_PER_SLOT, CERT_BUILDS_PER_SOURCE_PER_SLOT,
    CERT_LOCAL_BUILDS_PER_SLOT, LINKS_CACHE,
};
use super::*;
use bloch_finality_cert::Link;

fn remote(n: u8) -> Option<[u8; 32]> {
    Some(crate::net::verification_source_for_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, n))))
}

fn loopback() -> Option<[u8; 32]> {
    Some(crate::net::verification_source_for_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
}

/// One remote caller has a share, remote callers together have a ceiling,
/// and neither touches what local callers keep.
#[test]
fn the_assembly_budget_is_shared_out_per_caller() {
    let mut shares = BuildShares::default();
    for n in 0..CERT_BUILDS_PER_SOURCE_PER_SLOT {
        assert!(shares.reserve(7, remote(1)).is_ok(), "unit {n} of one caller's share");
    }
    let refused = shares.reserve(7, remote(1)).unwrap_err();
    assert!(refused.contains("per slot") && refused.contains("one caller"), "{refused}");
    // A second caller spends the rest of the remote ceiling.
    for _ in CERT_BUILDS_PER_SOURCE_PER_SLOT..CERT_BUILDS_PER_SLOT {
        assert!(shares.reserve(7, remote(2)).is_ok());
    }
    let refused = shares.reserve(7, remote(3)).unwrap_err();
    assert!(refused.contains("per slot") && !refused.contains("one caller"), "{refused}");
    // Local callers are untouched: in-process, loopback IPv4 and IPv6.
    let loopback6 = Some(crate::net::verification_source_for_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    for n in 0..CERT_LOCAL_BUILDS_PER_SLOT {
        let caller = [None, loopback(), loopback6][n as usize % 3];
        assert!(shares.reserve(7, caller).is_ok(), "local unit {n}");
    }
    let refused = shares.reserve(7, None).unwrap_err();
    assert!(refused.contains("per slot") && refused.contains("local"), "{refused}");
    assert!(shares.reserve(7, loopback()).is_err(), "loopback draws on the local share, not a remote one");
    // The next slot renews every share.
    assert!(shares.reserve(8, remote(1)).is_ok());
    assert!(shares.reserve(8, remote(3)).is_ok());
    assert!(shares.reserve(8, None).is_ok());
}

/// Requests cycling through old epochs never displace the links of the
/// newest ones, which is what clients at the head ask for.
#[test]
fn the_links_of_the_newest_epochs_are_kept() {
    let links = |epoch: u64| {
        let link = |source_epoch, target_epoch| Link {
            source_epoch,
            source_root: [0; 32],
            target_epoch,
            target_root: [0; 32],
            votes: Vec::new(),
        };
        Arc::new(CertLinks { source: (epoch - 1, [0; 32]), links: [link(epoch - 1, epoch), link(epoch, epoch + 1)] })
    };
    let key = |epoch: u64| (epoch, [epoch as u8; 32], [epoch as u8 + 1; 32]);
    let mut store = FinalityCertStore::default();
    let newest: Vec<u64> = (10..10 + LINKS_CACHE as u64).collect();
    for epoch in newest.iter().rev() {
        store.remember_links(key(*epoch), links(*epoch));
    }
    assert_eq!(store.held_link_epochs(), newest, "ascending by epoch");
    for old in 1..=5 {
        store.remember_links(key(old), links(old));
    }
    assert_eq!(store.held_link_epochs(), newest, "old epochs displaced nothing");
    store.remember_links(key(18), links(18));
    assert_eq!(store.held_link_epochs(), (11..=18).collect::<Vec<_>>(), "a newer epoch displaces the oldest");
    // Links scanned again for an epoch replace the ones held for it.
    store.remember_links((18, [0xEE; 32], [0xEF; 32]), links(18));
    assert_eq!(store.held_link_epochs(), (11..=18).collect::<Vec<_>>());
}

/// The finding's own scenario on a real four-validator chain, then the
/// shares at the RPC entry.
#[test]
fn another_block_of_one_epoch_is_not_a_new_assembly_and_callers_have_shares() {
    let n = 4;
    let (mut engine, _dir, others) = perf_support::proposing_engine_n(&[], n);
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
    for slot in 1..=(9 * SLOTS_PER_EPOCH) {
        as_each(&mut engine, &mut vals, &|e: &mut Engine| e.attest(slot));
        as_each(&mut engine, &mut vals, &|e: &mut Engine| e.propose(slot));
        if engine.state.finality().finalized.epoch >= 5 {
            break;
        }
    }
    assert!(engine.state.finality().finalized.epoch >= 5);
    let slot = engine.wall_slot();
    let clock = validator_lifecycle::clock_at(slot);
    let certificate = |engine: &mut Engine, caller: Option<[u8; 32]>, epoch: u64, block: Option<[u8; 32]>| {
        engine.serve_rpc_from(
            RpcRequest::FinalityCertificate { epoch: Some(epoch), block, set_source_epoch: None },
            caller,
        )
    };

    // Eight requests in one slot from one remote address, each naming a
    // different canonical ancestor of the checkpoint of epoch 4.
    let root = engine.checkpoint_root(4);
    let top = engine.height_of(&root).expect("the checkpoint is canonical") as usize;
    let scans_before = engine.finality_certs.vote_scans;
    let mut replies = Vec::new();
    for back in 1..=8usize {
        let ancestor = *engine.chain[top - back].1.as_bytes();
        let reply = certificate(&mut engine, remote(9), 4, Some(ancestor)).unwrap_or_else(|e| panic!("request {back}: {e:?}"));
        assert_eq!(reply.get("ancestry").and_then(Json::as_u64), Some(back as u64), "it carries the ancestry asked for");
        replies.push(reply);
    }
    assert_eq!(engine.finality_certs.vote_scans - scans_before, 2, "one assembly: two epoch scans, not sixteen");
    assert_eq!(engine.finality_certs.builds, (slot, 1), "and one unit of the budget");
    assert!(replies.windows(2).all(|pair| pair[0] != pair[1]), "eight different certificates");

    // Everybody else, same slot: the newest finalized epoch, by either
    // method, from another address and from this host.
    certificate(&mut engine, remote(10), 5, None).expect("an honest getfinalitycertificate in the same slot");
    engine
        .serve_rpc_from(RpcRequest::LcProof { epoch: Some(5), set_source_epoch: None, block: None }, loopback())
        .expect("an honest getlcproof in the same slot");
    assert_eq!(engine.finality_certs.builds, (slot, 2), "epoch 5 was assembled once for both");

    // The shares at the RPC entry. Nothing is held, so each request below
    // needs an assembly; the remote callers' units are taken by hand.
    drop(clock);
    let slot = slot + 1;
    let _clock = validator_lifecycle::clock_at(slot);
    let forget = |engine: &mut Engine| {
        engine.finality_certs.forget_links();
        engine.finality_certs.cache.clear();
        engine.finality_certs.default_source.clear();
    };
    forget(&mut engine);
    for _ in 0..CERT_BUILDS_PER_SOURCE_PER_SLOT {
        engine.finality_certs.shares.reserve(slot, remote(9)).unwrap();
    }
    let scans = engine.finality_certs.vote_scans;
    let spent = certificate(&mut engine, remote(9), 4, None).unwrap_err();
    assert_eq!(spent.code, rpc::NODE_UNAVAILABLE);
    assert!(spent.message.contains("per slot") && spent.message.contains("one caller"), "{spent:?}");
    assert_eq!(engine.finality_certs.vote_scans, scans, "refused before any block is read");
    certificate(&mut engine, remote(10), 4, None).expect("another address still has its share");

    // The remote ceiling spent by other addresses: a new address is told to
    // retry, a local caller is served.
    forget(&mut engine);
    for n in 0..(CERT_BUILDS_PER_SLOT - CERT_BUILDS_PER_SOURCE_PER_SLOT - 1) {
        engine.finality_certs.shares.reserve(slot, remote(20 + n as u8)).unwrap();
    }
    let full = certificate(&mut engine, remote(40), 5, None).unwrap_err();
    assert_eq!(full.code, rpc::NODE_UNAVAILABLE);
    assert!(full.message.contains("per slot"), "{full:?}");
    certificate(&mut engine, loopback(), 5, None).expect("the loopback caller's share is its own");
    forget(&mut engine);
    certificate(&mut engine, None, 4, None).expect("and so is an in-process caller's");
}
