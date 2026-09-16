use super::*;
use bloch_pos_committee::{
    header::{BlockHeaderV4, BlockId},
    state_root::EvmCommitment,
};

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bloch-native-sidecar-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn state() -> CommittedState {
    let header = BlockHeaderV4 {
        version: 4,
        parent: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
        slot: 0,
        proposer_index: 0,
        randao_reveal: [0; 32],
        randao_mix: [7; 32],
        justified_root: [0; 32],
        finalized_root: [0; 32],
        attestation_root: [0; 32],
        coherence_root: [0; 32],
    };
    CommittedState::genesis_with_network_domain(
        [9; 32],
        BlockId::of(&header),
        [7; 32],
        &[],
        &[],
        [0; 32],
        [0; 32],
        [0; 32],
        EvmCommitment {
            account_root: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            base_fee_per_gas: 0,
        },
        &[],
    )
}

#[test]
fn durable_sidecar_roundtrips_binding_and_payload_with_atomic_replacement() {
    let directory = Directory::new();
    let binding = Binding::from_state([9; 32], &state());
    write_record(&directory.0, binding, b"first component bytes").unwrap();
    assert_eq!(
        read_record(&directory.0).unwrap(),
        Some((binding, b"first component bytes".to_vec()))
    );
    write_record(&directory.0, binding, b"replacement").unwrap();
    assert_eq!(
        read_record(&directory.0).unwrap(),
        Some((binding, b"replacement".to_vec()))
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[test]
fn restart_preserves_absence_and_untrusted_sidecar_cannot_bootstrap_native_state() {
    let directory = Directory::new();
    let replayed = state();
    let root = replayed.state_root();
    let store = Store::open(&directory.0, &[9; 32]).unwrap();
    store.save_native_component(&replayed).unwrap();
    drop(store);
    let reopened = Store::open(&directory.0, &[9; 32]).unwrap();
    assert!(reopened
        .restore_native_component(&replayed, &crate::keys::HybridVerifier::new())
        .unwrap()
        .is_none());
    write_record(
        &directory.0,
        Binding::from_state([9; 32], &replayed),
        b"fabricated populated snapshot",
    )
    .unwrap();
    assert!(reopened
        .restore_native_component(&replayed, &crate::keys::HybridVerifier::new())
        .is_err());
    assert_eq!(replayed.state_root(), root);
    assert_eq!(replayed.native_component_snapshot_bytes().unwrap(), None);
}

#[test]
fn stale_head_is_a_cache_miss_but_same_head_root_and_genesis_mismatch_fail() {
    let directory = Directory::new();
    let replayed = state();
    let store = Store::open(&directory.0, &[9; 32]).unwrap();
    let expected = Binding::from_state([9; 32], &replayed);
    let verifier = crate::keys::HybridVerifier::new();
    assert!(store
        .restore_native_component(&replayed, &verifier)
        .unwrap()
        .is_none());
    for binding in [Binding {
        head: [5; 32],
        ..expected
    }] {
        write_record(&directory.0, binding, b"older snapshot").unwrap();
        assert!(store
            .restore_native_component(&replayed, &verifier)
            .unwrap()
            .is_none());
    }
    for binding in [
        Binding {
            slot: 1,
            ..expected
        },
        Binding {
            root: [6; 32],
            ..expected
        },
        Binding {
            genesis: [7; 32],
            ..expected
        },
    ] {
        write_record(&directory.0, binding, &[]).unwrap();
        assert!(store
            .restore_native_component(&replayed, &verifier)
            .is_err());
    }
}

#[test]
fn corrupt_truncated_trailing_and_forged_length_files_are_refused() {
    let directory = Directory::new();
    let binding = Binding::from_state([9; 32], &state());
    write_record(&directory.0, binding, b"payload").unwrap();
    let good = fs::read(directory.0.join(FILE_NAME)).unwrap();
    for length in [0, 8, HEADER_BYTES - 1, HEADER_BYTES, good.len() - 1] {
        fs::write(directory.0.join(FILE_NAME), &good[..length]).unwrap();
        assert!(read_record(&directory.0).is_err());
    }
    for offset in [0, 8, 12, 44, 76, 108, 116, 120, HEADER_BYTES] {
        let mut bad = good.clone();
        bad[offset] ^= 0xff;
        fs::write(directory.0.join(FILE_NAME), bad).unwrap();
        assert!(read_record(&directory.0).is_err());
    }
    let mut trailing = good;
    trailing.push(0);
    fs::write(directory.0.join(FILE_NAME), trailing).unwrap();
    assert!(read_record(&directory.0).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_and_hardlinks_are_not_followed_for_snapshot_reads() {
    use std::os::unix::fs::symlink;
    let directory = Directory::new();
    let other = Directory::new();
    write_record(&other.0, Binding::from_state([9; 32], &state()), &[]).unwrap();
    let target = other.0.join(FILE_NAME);
    let path = directory.0.join(FILE_NAME);
    symlink(&target, &path).unwrap();
    assert!(read_record(&directory.0).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(read_record(&directory.0).is_err());
}

#[test]
fn torn_temporary_file_does_not_replace_last_durable_checkpoint() {
    let directory = Directory::new();
    let binding = Binding::from_state([9; 32], &state());
    write_record(&directory.0, binding, b"durable").unwrap();
    fs::write(
        directory.0.join(".native-component.interrupted.tmp"),
        b"partial",
    )
    .unwrap();
    assert_eq!(
        read_record(&directory.0).unwrap(),
        Some((binding, b"durable".to_vec()))
    );
}
