//! Durable reachability index — end-to-end persistence + migration tests
//! (Phases 1 & 2).
//!
//! Exercises the real storage path a Fast/armed node uses:
//!   * per-block atomic writes via `put_dag_with_integrity_and_reach` (the same
//!     WriteBatch as CF_DAG), plus the genesis snapshot + version tag;
//!   * reload from CF_REACHABILITY (fast path) and a from-CF_DAG rebuild
//!     (migration path), both validated against the brute-force oracle;
//!   * the torn-write / version-mismatch cases fall back to a rebuild that still
//!     self-checks clean.
//!
//! These run WITHOUT any live node and on a throwaway tempdir — the durable
//! index is a rebuildable cache, never consensus state.

use std::collections::HashMap;

use bloch::consensus::{BlockHash, GhostDAG, GhostdagData};
use bloch::storage::Storage;

type Spec = (BlockHash, Vec<BlockHash>, u64, u128);

fn hh(a: u8, b: u16) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = a;
    h[1] = (b >> 8) as u8;
    h[2] = (b & 0xff) as u8;
    h
}

/// Repeated diamond merges — non-empty mergesets so the reachability FCS and at
/// least one reindex are exercised.
fn merging(genesis: BlockHash, iters: u16) -> Vec<Spec> {
    let mut specs = Vec::new();
    let mut prev = genesis;
    let mut ts = 1u64;
    for i in 1..=iters {
        let l = hh(b'A', i);
        let r = hh(b'B', i);
        let m = hh(b'M', i);
        specs.push((l, vec![prev], ts, 1000)); ts += 1;
        specs.push((r, vec![prev], ts, 1000)); ts += 1;
        specs.push((m, vec![l, r], ts, 1000)); ts += 1;
        prev = m;
    }
    specs
}

/// Build a Fast DAG in memory AND persist every block through the real durable
/// write path into `store`, exactly as the node does. Returns the source DAG.
fn build_and_persist(store: &Storage, genesis: BlockHash, specs: &[Spec], k: usize) -> GhostDAG {
    let mut dag = GhostDAG::with_k_fast(k);

    // Genesis: add, drain tracking, snapshot (sets version + root + record).
    dag.add_genesis(genesis, 0);
    let _ = dag.reach_take_delta();
    let gdata = dag.get_block_data(&genesis).cloned().unwrap();
    store.put_dag_with_integrity(&genesis, &gdata).expect("persist genesis dag");
    store
        .store_reachability_snapshot(&dag.reach_export_all(), dag.reach_root())
        .expect("persist genesis reachability snapshot");

    // Each block: add, drain the delta, fold it into the atomic DAG write.
    for (hash, parents, ts, work) in specs {
        dag.add_block(*hash, parents.clone(), *ts, *work)
            .unwrap_or_else(|e| panic!("add_block {}: {e:?}", hex::encode(&hash[..4])));
        let ddata = dag.get_block_data(hash).cloned().unwrap();
        let (upserts, removals) = dag.reach_take_delta();
        store
            .put_dag_with_integrity_and_reach(hash, &ddata, &upserts, &removals)
            .expect("atomic dag + reach write");
    }
    dag
}

fn all_hashes(genesis: BlockHash, specs: &[Spec]) -> Vec<BlockHash> {
    let mut v = vec![genesis];
    v.extend(specs.iter().map(|(h, ..)| *h));
    v
}

/// Reconstruct the in-memory DAG store from CF_DAG (no reach), so a loaded /
/// rebuilt index has a parent graph to self-check against.
fn load_dag_only(store: &Storage, k: usize) -> GhostDAG {
    let mut dag = GhostDAG::with_k_fast(k);
    let entries = store.load_all_dag_data().expect("load CF_DAG");
    dag.load_persisted(entries);
    dag
}

#[test]
fn persist_then_reload_matches_and_self_checks() {
    let dir = tempfile::tempdir().unwrap();
    let g = hh(0, 0);
    let specs = merging(g, 40);
    let k = 10;

    let source = {
        let store = Storage::open(dir.path()).expect("open");
        let src = build_and_persist(&store, g, &specs, k);

        // The atomic path persisted a record for every block.
        let recs = store.load_all_reachability().expect("load reach");
        assert_eq!(recs.len(), src.block_count(), "one reach record per block");
        assert_eq!(
            store.get_reachability_version().unwrap(),
            Some(Storage::REACHABILITY_SCHEMA_VERSION),
            "version tag persisted",
        );
        assert_eq!(store.get_reachability_root().unwrap(), Some(g), "root persisted");
        src
    };

    // Reopen: reload DAG + reach index from disk, self-check, and compare every
    // ancestry query to the freshly-built source DAG.
    let store = Storage::open(dir.path()).expect("reopen");
    let mut dag = load_dag_only(&store, k);
    let records = store.load_all_reachability().unwrap();
    let root = store.get_reachability_root().unwrap();
    dag.reach_load_records(&records, root).expect("reach_load_records");

    let checked = dag.reach_self_check_sample(5000, 0x1234_5678).expect("self-check clean");
    assert!(checked > 0, "self-check actually sampled pairs");

    let hashes = all_hashes(g, &specs);
    for a in &hashes {
        for b in &hashes {
            assert_eq!(
                dag.reachability().is_dag_ancestor(a, b),
                source.reachability().is_dag_ancestor(a, b),
                "reloaded index disagrees with source",
            );
        }
    }
}

#[test]
fn migration_rebuild_from_cf_dag_only() {
    let dir = tempfile::tempdir().unwrap();
    let g = hh(0, 0);
    let specs = merging(g, 50);
    let k = 10;

    // Persist a full Fast history, then WIPE the reachability records + version
    // tag to simulate a pre-durable-index (or torn) datadir. CF_DAG is intact.
    let source = {
        let store = Storage::open(dir.path()).expect("open");
        let src = build_and_persist(&store, g, &specs, k);
        // Clear the reachability CF + meta by storing an empty snapshot with a
        // bogus version, then deleting the version so boot sees "absent".
        store.store_reachability_snapshot(&[], None).unwrap();
        store.put_meta("reachability/meta/version", &[]).unwrap(); // corrupt/absent
        src
    };

    let store = Storage::open(dir.path()).expect("reopen");
    // Boot would see version != expected ⇒ rebuild from CF_DAG.
    assert_ne!(
        store.get_reachability_version().unwrap(),
        Some(Storage::REACHABILITY_SCHEMA_VERSION),
        "version must look absent/mismatched to trigger rebuild",
    );

    let mut dag = load_dag_only(&store, k);
    let n = dag.rebuild_reachability_from_store().expect("rebuild");
    assert_eq!(n, dag.block_count(), "rebuild indexed every block");

    // Self-check + query-equivalence to the source.
    dag.reach_self_check_sample(5000, 0x9abc_def0).expect("rebuilt index self-checks");
    let hashes = all_hashes(g, &specs);
    for a in &hashes {
        for b in &hashes {
            assert_eq!(
                dag.reachability().is_dag_ancestor(a, b),
                source.reachability().is_dag_ancestor(a, b),
                "rebuilt index disagrees with source",
            );
        }
    }

    // Persisting the rebuilt snapshot restores the version + full coverage.
    let snap = dag.reach_export_all();
    let root = dag.reach_root();
    store.store_reachability_snapshot(&snap, root).unwrap();
    assert_eq!(
        store.get_reachability_version().unwrap(),
        Some(Storage::REACHABILITY_SCHEMA_VERSION),
    );
    assert_eq!(store.load_all_reachability().unwrap().len(), dag.block_count());
}

#[test]
fn reload_equals_rebuild_bit_for_bit() {
    // The fast reload path and the migration rebuild path must agree on the
    // ancestry answers (records may be laid out differently but queries can't).
    let dir = tempfile::tempdir().unwrap();
    let g = hh(0, 0);
    let specs = merging(g, 30);
    let k = 10;

    let store = Storage::open(dir.path()).expect("open");
    let _src = build_and_persist(&store, g, &specs, k);

    let mut reloaded = load_dag_only(&store, k);
    let records = store.load_all_reachability().unwrap();
    let root = store.get_reachability_root().unwrap();
    reloaded.reach_load_records(&records, root).unwrap();

    let mut rebuilt = load_dag_only(&store, k);
    rebuilt.rebuild_reachability_from_store().unwrap();

    let hashes = all_hashes(g, &specs);
    let mut differences = 0usize;
    for a in &hashes {
        for b in &hashes {
            if reloaded.reachability().is_dag_ancestor(a, b)
                != rebuilt.reachability().is_dag_ancestor(a, b)
            {
                differences += 1;
            }
        }
    }
    assert_eq!(differences, 0, "reload and rebuild must answer identically");
    let _ : HashMap<BlockHash, GhostdagData> = HashMap::new(); // keep imports used
}
