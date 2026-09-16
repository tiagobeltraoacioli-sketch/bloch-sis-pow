//! Real block production, durable log reopening and authoritative replay with
//! the optional native sidecar. Native activation remains disabled throughout.
use super::*;

#[test]
fn durable_checkpoint_follows_live_blocks_and_reopens_only_after_replay() {
    let (mut engine, directory) = perf_support::proposing_engine();
    engine.propose(1);
    engine.propose(2);
    assert_eq!(engine.state.slot(), 2);
    let root = engine.state.state_root();
    let head = engine.head_id();
    let checkpoint = std::fs::read(directory.0.join("native-component.bin")).unwrap();
    assert_eq!(&checkpoint[44..76], head.as_bytes());
    assert_eq!(&checkpoint[76..108], &root);
    let manifest_bytes = engine.manifest.encode();
    drop(engine);
    let store = Store::open(&directory.0, &[0; 32]).unwrap();
    let logged = store.read_all().unwrap();
    assert_eq!(logged.len(), 2);
    let mut replayed = Manifest::decode(&manifest_bytes).unwrap().genesis_state();
    let transition = Transition::new(HybridVerifier::new());
    for env in logged {
        replayed = transition
            .apply_block(
                &replayed,
                &ProposalEnvelope {
                    header: env.header.clone(),
                    proposer_sig: env.proposer_sig.clone(),
                },
                &env.body.attestations,
                &body_transactions(&env).unwrap(),
            )
            .unwrap();
    }
    assert_eq!(replayed.state_root(), root);
    assert_eq!(replayed.head(), head);
    assert!(store
        .restore_native_component(&replayed, &HybridVerifier::new())
        .unwrap()
        .is_none());
    assert_eq!(replayed.native_component_snapshot_bytes().unwrap(), None);
    assert_eq!(
        bloch_pos_committee::params::NATIVE_STATE_ACTIVATION_EPOCH,
        u64::MAX
    );
    assert_eq!(
        bloch_pos_committee::params::NATIVE_TRANSFER_ACTIVATION_EPOCH,
        u64::MAX
    );
}

#[test]
fn canonical_reorg_rewrites_checkpoint_after_durable_log_and_corruption_is_refused() {
    let (mut engine, directory) = perf_support::proposing_engine();
    engine.propose(1);
    let ancestor = *engine.head_id().as_bytes();
    engine.propose(2);
    assert!(engine.do_reorg(ancestor, vec![]));
    assert_eq!(engine.state.slot(), 1);
    assert_eq!(engine.store.read_all().unwrap().len(), 1);
    let path = directory.0.join("native-component.bin");
    let mut checkpoint = std::fs::read(&path).unwrap();
    assert_eq!(&checkpoint[44..76], &ancestor);
    assert_eq!(&checkpoint[76..108], &engine.state.state_root());
    assert!(engine
        .store
        .restore_native_component(&engine.state, &HybridVerifier::new())
        .unwrap()
        .is_none());
    checkpoint[76] ^= 1;
    std::fs::write(path, checkpoint).unwrap();
    assert!(engine
        .store
        .restore_native_component(&engine.state, &HybridVerifier::new())
        .is_err());
    assert_eq!(engine.head_id().as_bytes(), &ancestor);
}
