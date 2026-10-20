// SPDX-License-Identifier: AGPL-3.0-or-later

//! **"Gates off is byte-identical" guard for hard-fork ports.**
//! Instrumentation only: every test here is `#[ignore]`d and driven by
//! environment variables from `scripts/hf-replay-guard/check.sh`. Nothing here
//! asserts a consensus property on its own; it DUMPS what the code under test
//! computes, and the script diffs that dump against the dump the reference
//! release (b4a21fb6) produced from the same input bytes.
//!
//! Three dumps, each a pure function of its input file:
//!
//! * `hf_guard_generate_fixtures` — run ONCE, on the reference release only.
//!   Builds deterministic-shape chains with the replay benchmark's generator
//!   (real hybrid keys, real proposer signatures, real committee attestations,
//!   real transfers) and writes their exact bytes to disk. Every block has
//!   already passed the reference `Transition::apply_block`.
//! * `hf_guard_replay_fixtures` — feeds those bytes through
//!   `Engine::ingest_replay`, the entry point boot replay uses, and prints one
//!   line per block: slot, block id, verdict, post-state root and both
//!   checkpoints. Because every header commits to its post-state root, a
//!   branch that computes a different state refuses the block, so the first
//!   differing line is the first divergent slot.
//! * `hf_guard_mainnet_headers` — re-encodes a sample of finalized mainnet
//!   headers (fetched read-only over public RPC) with the code under test and
//!   prints the recomputed id, the proposal signing root and the serialize /
//!   deserialize round trip. A branch that changes header encoding, id hashing
//!   or the version it accepts at a sampled slot shows up as a differing line.
//!
//! Why a child of `engine`: `bloch-pos-node` has no `[lib]`, and
//! `ingest_replay` is private to `engine`. This mirrors `replay_bench.rs`,
//! whose `boot_engine` it reuses so that it keeps compiling on any branch
//! that keeps the benchmark compiling.

use std::io::Write;
use std::path::{Path, PathBuf};

use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4};
use bloch_pos_committee::interfaces::StateReader;
use bloch_pos_committee::schedule::first_slot_of_epoch;
use bloch_pos_committee::state_root::EutxoEntry;
use bloch_pos_committee::epoch_of;

use super::replay_bench::{boot_engine, Generator};
use crate::codec::{hex, hex32, unhex};
use crate::genesis::Manifest;

const EUTXO_LEN: usize = 32 + 4 + 8 + 32;

fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set")))
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "hf-replay-guard-{tag}-{}-{}",
        std::process::id(),
        super::now_ms()
    ));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

// ── fixture file format ─────────────────────────────────────────────────────
//
//   manifest.bin   Manifest::encode()
//   carryover.bin  N × (txid 32 | vout u32le | value u64le | script_hash 32)
//   blocks.bin     N × (len u32le | codec::encode_envelope)

fn write_fixture(dir: &Path, manifest: &Manifest, chain: &[BlockEnvelope]) {
    std::fs::create_dir_all(dir).expect("fixture dir");
    std::fs::write(dir.join("manifest.bin"), manifest.encode()).expect("manifest");
    let mut co = Vec::with_capacity(manifest.carryover_entries.len() * EUTXO_LEN);
    for e in &manifest.carryover_entries {
        co.extend_from_slice(&e.txid);
        co.extend_from_slice(&e.vout.to_le_bytes());
        co.extend_from_slice(&e.value.to_le_bytes());
        co.extend_from_slice(&e.script_hash);
    }
    std::fs::write(dir.join("carryover.bin"), co).expect("carryover");
    let mut blocks = Vec::new();
    for env in chain {
        let b = crate::codec::encode_envelope(env);
        blocks.extend_from_slice(&(b.len() as u32).to_le_bytes());
        blocks.extend_from_slice(&b);
    }
    std::fs::write(dir.join("blocks.bin"), blocks).expect("blocks");
}

fn read_fixture(dir: &Path) -> (Manifest, Vec<BlockEnvelope>) {
    let mbytes = std::fs::read(dir.join("manifest.bin")).expect("manifest.bin");
    let mut manifest = Manifest::decode(&mbytes).expect("manifest decodes");
    let co = std::fs::read(dir.join("carryover.bin")).expect("carryover.bin");
    assert_eq!(co.len() % EUTXO_LEN, 0, "carryover.bin length");
    manifest.carryover_entries = co
        .chunks(EUTXO_LEN)
        .map(|c| EutxoEntry {
            txid: c[0..32].try_into().unwrap(),
            vout: u32::from_le_bytes(c[32..36].try_into().unwrap()),
            value: u64::from_le_bytes(c[36..44].try_into().unwrap()),
            script_hash: c[44..76].try_into().unwrap(),
        })
        .collect();
    let raw = std::fs::read(dir.join("blocks.bin")).expect("blocks.bin");
    let mut chain = Vec::new();
    let mut at = 0usize;
    while at < raw.len() {
        let n = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        chain.push(crate::codec::decode_envelope(&raw[at..at + n]).expect("frame decodes"));
        at += n;
    }
    (manifest, chain)
}

// ── scenarios ───────────────────────────────────────────────────────────────

/// (name, carryover outputs, participation %, slot plan). Each slot plan is a
/// list of half-open slot ranges; a slot whose proposer the generator cannot
/// find is simply empty, exactly as on a live chain.
fn scenarios() -> Vec<(&'static str, u32, u32, Vec<(u64, u64)>)> {
    let e = |ep: u64| first_slot_of_epoch(ep).expect("epoch slot");
    vec![
        // Genesis onwards, full participation: justification and finality
        // advance; epoch boundaries 1..=6; a transfer in every block.
        ("early-finalizing", 4_096, 100, vec![(1, e(6) + 8)]),
        // Below the 2/3 threshold: nothing justifies, the leak regime.
        ("early-unjustified", 4_096, 50, vec![(1, e(4) + 4)]),
        // Sparse proposals with skipped slots across boundaries.
        ("early-gappy", 1_024, 100, vec![(1, 20), (40, 41), (e(2) - 1, e(2) + 2), (e(3) + 5, e(4) + 3)]),
        // A six-epoch silence past the inactivity-leak threshold, then the set
        // returns: leak accrual, then recovery, on a live registry.
        ("early-leak-recovery", 1_024, 100, vec![(1, e(2) + 4), (e(8) + 1, e(10) + 6)]),
        // NOT here, on purpose: a chain under the current rule set (epoch
        // >= 5850). The generator cannot jump there — 5,849 empty epochs leak
        // every validator to zero (quotient 64, quadratic) — and building the
        // 180k intervening blocks is hours per run. The live rule set is covered
        // at header level by `hf_guard_mainnet_headers` instead.
    ]
}

#[test]
#[ignore]
fn hf_guard_generate_fixtures() {
    let root = env_path("HF_GUARD_FIXTURE_DIR");
    let only = std::env::var("HF_GUARD_SCENARIO").ok();
    for (name, carry, part, plan) in scenarios() {
        if only.as_deref().is_some_and(|o| o != name) {
            continue;
        }
        let keys_dir = scratch(&format!("gen-{name}"));
        let name_s = name.to_string();
        let (manifest, chain) = std::thread::spawn(move || {
            let mut g = Generator::new(&keys_dir, carry, part);
            let mut chain = Vec::new();
            for (a, b) in plan {
                for slot in a..b {
                    if let Some(env) = g.block_at(slot) {
                        chain.push(env);
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&keys_dir);
            (super::replay_bench::clone_manifest(&g.manifest), chain)
        })
        .join()
        .unwrap_or_else(|_| panic!("generator panicked for {name_s}"));
        assert!(!chain.is_empty(), "{name}: generator produced no block");
        write_fixture(&root.join(name), &manifest, &chain);
        println!(
            "fixture {name}: {} blocks, slots {}..={}",
            chain.len(),
            chain.first().unwrap().header.slot,
            chain.last().unwrap().header.slot
        );
    }
}

#[test]
#[ignore]
fn hf_guard_replay_fixtures() {
    let root = env_path("HF_GUARD_FIXTURE_DIR");
    let out_path = env_path("HF_GUARD_OUT");
    let mut names: Vec<String> = std::fs::read_dir(&root)
        .expect("fixture root")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("blocks.bin").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no fixture under {}", root.display());
    let mut out = std::fs::File::create(&out_path).expect("out file");
    for name in names {
        let (manifest, chain) = read_fixture(&root.join(&name));
        let dir = scratch(&format!("replay-{name}"));
        let name_t = name.clone();
        // Fresh thread: the state-root memo is thread-local (see replay_bench).
        let lines = std::thread::spawn(move || {
            let mut lines = Vec::with_capacity(chain.len() + 1);
            let mut engine = boot_engine(manifest, &dir);
            lines.push(format!(
                "{name_t} genesis - - {} - -",
                hex32(&engine.state.state_root())
            ));
            for (i, env) in chain.into_iter().enumerate() {
                let slot = env.header.slot;
                let id = env.block_id();
                let ok = engine.ingest_replay(env) && engine.head_id() == id;
                let fin = engine.state.finality();
                lines.push(format!(
                    "{name_t} {i} {slot} {} {} {} j{}:{} f{}:{}",
                    hex32(id.as_bytes()),
                    if ok { "ACCEPT" } else { "REJECT" },
                    hex32(&engine.state.state_root()),
                    fin.justified.epoch,
                    hex32(&fin.justified.root),
                    fin.finalized.epoch,
                    hex32(&fin.finalized.root),
                ));
                if !ok {
                    break;
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
            lines
        })
        .join()
        .unwrap_or_else(|_| vec![format!("{name} PANIC - - - - -")]);
        for l in lines {
            writeln!(out, "{l}").expect("write");
        }
    }
}

fn h32(v: &serde_json_lite::Value, k: &str) -> [u8; 32] {
    let s = v.str(k);
    unhex(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .unwrap_or_else(|| panic!("field {k} is not 32-byte hex: {s}"))
}

#[test]
#[ignore]
fn hf_guard_mainnet_headers() {
    let sample = std::fs::read_to_string(env_path("HF_GUARD_MAINNET_SAMPLE")).expect("sample");
    let mut out = std::fs::File::create(env_path("HF_GUARD_OUT")).expect("out file");
    let mut n = 0usize;
    for line in sample.lines().filter(|l| !l.trim().is_empty()) {
        let v = serde_json_lite::Value::parse(line);
        let h = BlockHeaderV4 {
            version: v.u64("version") as u32,
            parent: h32(&v, "parent"),
            state_root: h32(&v, "state_root"),
            body_root: h32(&v, "body_root"),
            slot: v.u64("slot"),
            proposer_index: v.u64("proposer_index") as u32,
            randao_reveal: h32(&v, "randao_reveal"),
            randao_mix: h32(&v, "randao_mix"),
            justified_root: h32(&v, "justified_root"),
            finalized_root: h32(&v, "finalized_root"),
            attestation_root: h32(&v, "attestation_root"),
            coherence_root: h32(&v, "coherence_root"),
        };
        let reported = h32(&v, "block_id");
        let bytes = h.canonical_serialize();
        let round = BlockHeaderV4::canonical_deserialize(&bytes)
            .map(|d| d == h)
            .unwrap_or(false);
        let id = h.id();
        writeln!(
            out,
            "{} e{} id={} {} sigroot={} roundtrip={} enc={}",
            h.slot,
            epoch_of(h.slot),
            hex32(id.as_bytes()),
            if *id.as_bytes() == reported { "ID-MATCH" } else { "ID-MISMATCH" },
            hex32(&h.proposal_signing_root()),
            round,
            hex(&bytes[..8]),
        )
        .expect("write");
        n += 1;
    }
    assert!(n > 0, "empty mainnet sample");
}

/// The node crate carries no JSON parser for arbitrary input, and the sample
/// is flat `{"k": "hex" | int}` produced by our own fetcher, so a 30-line
/// reader is enough and keeps this test free of a new dependency.
mod serde_json_lite {
    pub struct Value(Vec<(String, String)>);
    impl Value {
        pub fn parse(s: &str) -> Value {
            let s = s.trim().trim_start_matches('{').trim_end_matches('}');
            let mut kv = Vec::new();
            for part in s.split(',') {
                let (k, v) = part.split_once(':').expect("k:v");
                kv.push((
                    k.trim().trim_matches('"').to_string(),
                    v.trim().trim_matches('"').to_string(),
                ));
            }
            Value(kv)
        }
        pub fn str(&self, k: &str) -> &str {
            &self.0.iter().find(|(kk, _)| kk == k).unwrap_or_else(|| panic!("missing {k}")).1
        }
        pub fn u64(&self, k: &str) -> u64 {
            self.str(k).parse().unwrap_or_else(|_| panic!("{k} not an integer"))
        }
    }
}
