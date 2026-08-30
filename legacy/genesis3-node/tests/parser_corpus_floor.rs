//! Stable-Rust, always-on "floor" for the untrusted-input parsers (roadmap §1c).
//!
//! cargo-fuzz needs nightly + libFuzzer and is NOT part of the node build, so on
//! stable CI *none* of the parser hardening runs. This file:
//!
//!   1. GENERATES a committed seed corpus under `fuzz/corpus/<target>/` (valid
//!      encodings + near-miss / truncated mutations) — the same corpus the
//!      libFuzzer targets start from, pinned as a tested asset.
//!   2. REPLAYS every corpus file through the SAME parse entry points the
//!      libFuzzer targets exercise, asserting no panic (only `Ok`/`Err`).
//!
//! This gives every stable PR a regression floor without the nightly toolchain.
//! It covers the node-owned decoders reachable via the `bloch` public API:
//! `Block::from_bitcoin_bytes`, `Transaction::from_stratum_bytes`, the
//! `NetworkMessage` bincode decode, the handshake decode, and the stateful
//! mempool op-stream. The `pow_decode` / `pow_verify` / `merkle_path` corpora
//! are also generated here for the libFuzzer box, but their replay lives with
//! the crypto crate (their parsers are not in this crate's direct dep graph).
//!
//! Style mirrors `tests/wire_decoder_fuzz.rs`: a deterministic SplitMix64 stream
//! (reproducible corpus) driven through `catch_unwind`.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use bloch::coherence::{
    NoteCiphertext, ShieldedTx,
    NOTE_AEAD_NONCE_LEN, NOTE_AEAD_TAG_LEN, NOTE_KEM_CT_LEN, NOTE_PLAINTEXT_LEN,
};
use bloch::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
use bloch::mempool::Mempool;
use bloch::network::{NetworkMessage, SyncEntry};
use bloch::transport::{HandshakeInit, HandshakeResp};

// ── deterministic PRNG ────────────────────────────────────────────────────────

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() as usize) % n.max(1)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// `bytes(min + range(max))` in a single call so it can be used inside a
    /// struct literal without two simultaneous `&mut self` borrows (E0499:
    /// `r.bytes(r.range(n))` borrows `*r` mutably twice in one expression).
    fn bytes_rand(&mut self, min: usize, max: usize) -> Vec<u8> {
        let n = min + self.range(max);
        self.bytes(n)
    }
    fn arr32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for b in a.iter_mut() {
            *b = self.next() as u8;
        }
        a
    }
}

fn corpus_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the workspace/crate root that owns `fuzz/`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus")
}

fn bincfg() -> bincode::config::Configuration {
    bincode::config::standard()
}

// ── fixture builders ──────────────────────────────────────────────────────────

fn rand_tx(r: &mut Rng) -> Transaction {
    let n_in = 1 + r.range(3);
    let n_out = 1 + r.range(3);
    Transaction {
        version: 1,
        inputs: (0..n_in)
            .map(|_| TxInput {
                prev_txid: r.arr32(),
                prev_index: r.next() as u32,
                script_sig: r.bytes_rand(0, 40),
                sequence: r.next() as u32,
            })
            .collect(),
        outputs: (0..n_out)
            .map(|_| TxOutput {
                value: r.next() % 21_000_000_00000000,
                script_pubkey: r.bytes(20),
            })
            .collect(),
        locktime: r.next() as u32,
    }
}

fn rand_shielded(r: &mut Rng) -> ShieldedTx {
    let outputs: Vec<[u8; 32]> = (0..r.range(3)).map(|_| r.arr32()).collect();
    // Length-exact per-output note ciphertexts: read_shielded_tx enforces the
    // ML-KEM-1024 / AEAD component lengths, so the VALID corpus must use them
    // (malformed lengths are exercised by the mutation pass over these bytes).
    let output_ciphertexts: Vec<NoteCiphertext> = outputs.iter().map(|_| {
        let mut nonce = [0u8; NOTE_AEAD_NONCE_LEN];
        for b in nonce.iter_mut() { *b = r.next() as u8; }
        NoteCiphertext {
            kem_ct: r.bytes(NOTE_KEM_CT_LEN),
            nonce,
            payload: r.bytes(NOTE_PLAINTEXT_LEN + NOTE_AEAD_TAG_LEN),
        }
    }).collect();
    ShieldedTx {
        anchor: r.arr32(),
        nullifiers: (0..r.range(3)).map(|_| r.arr32()).collect(),
        outputs,
        output_ciphertexts,
        fee: r.next() % 1_000_000,
        proof: r.bytes_rand(0, 120),
        binding_sig: r.bytes_rand(0, 64),
    }
}

fn rand_block(r: &mut Rng) -> Vec<u8> {
    let cb = rand_tx(r);
    let shielded: Vec<ShieldedTx> = (0..r.range(3)).map(|_| rand_shielded(r)).collect();
    let block = Block {
        header: BlockHeader {
            version: 1,
            parents: vec![],
            merkle_root: Transaction::merkle_root(&[cb.clone()]),
            timestamp: r.next(),
            bits: 0x2100_ffff,
            nonce: r.next(),
        },
        transactions: vec![cb],
        blue_score: r.next(),
        height: r.next(),
        pow_solution: vec![],
        shielded_transactions: shielded,
        auxpow: None,
    };
    block.to_bitcoin_bytes()
}

fn rand_netmsg(r: &mut Rng) -> Vec<u8> {
    let msg = match r.range(6) {
        0 => NetworkMessage::NewBlock {
            block_hash: r.arr32(),
            blue_score: r.next(),
            height: r.next(),
            block_data: rand_block(r),
        },
        1 => NetworkMessage::NewTransaction {
            txid: r.arr32(),
            tx_data: rand_tx(r).to_stratum_bytes(true),
        },
        2 => NetworkMessage::PeerTip {
            peer_id: hex::encode(r.arr32()),
            blue_score: r.next(),
            height: r.next(),
        },
        3 => NetworkMessage::Headers {
            entries: (0..r.range(5))
                .map(|_| SyncEntry {
                    hash: r.arr32(),
                    blue_score: r.next(),
                    height: r.next(),
                })
                .collect(),
        },
        4 => NetworkMessage::GetBlock { block_hash: r.arr32(), nonce: r.next() },
        _ => NetworkMessage::Version {
            version: r.next() as u32,
            user_agent: "bloch/floor".into(),
            blue_score: r.next(),
            height: r.next(),
            timestamp: r.next(),
        },
    };
    bincode::serde::encode_to_vec(&msg, bincfg()).expect("encode NetworkMessage")
}

fn rand_handshake_init(r: &mut Rng) -> Vec<u8> {
    let init = HandshakeInit {
        version: 1,
        kyber_pk: r.bytes_rand(0, 64),
        identity_pk: r.bytes_rand(0, 64),
        nonce: r.arr32(),
        signature: r.bytes_rand(0, 64),
    };
    bincode::serde::encode_to_vec(&init, bincfg()).expect("encode HandshakeInit")
}

fn rand_handshake_resp(r: &mut Rng) -> Vec<u8> {
    let resp = HandshakeResp {
        ciphertext: r.bytes_rand(0, 64),
        identity_pk: r.bytes_rand(0, 64),
        signature: r.bytes_rand(0, 64),
    };
    bincode::serde::encode_to_vec(&resp, bincfg()).expect("encode HandshakeResp")
}

/// A valid `pow_decode` seed: exactly `N = 256` signed bytes in [-2, 2].
fn rand_pow(r: &mut Rng) -> Vec<u8> {
    (0..256).map(|_| (r.next() % 5) as i8 as u8).collect()
}

/// A `merkle_path` seed: 32-byte leaf ‖ 32-byte root ‖ 8-byte index ‖ path.
fn rand_merkle(r: &mut Rng) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&r.arr32());
    v.extend_from_slice(&r.arr32());
    v.extend_from_slice(&r.next().to_le_bytes());
    for _ in 0..r.range(6) {
        v.extend_from_slice(&r.arr32());
    }
    v
}

/// A `mempool_ops` seed: an op-stream byte string (the target's own VM decodes
/// it). Random bytes are a fine seed; the near-miss set below adds structure.
fn rand_mempool_ops(r: &mut Rng) -> Vec<u8> {
    r.bytes_rand(1, 160)
}

/// Truncations / bit-flips of a valid encoding — the near-miss corpus.
fn near_misses(r: &mut Rng, valid: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if !valid.is_empty() {
        out.push(valid[..valid.len() / 2].to_vec()); // truncated
        out.push(valid[..valid.len().saturating_sub(1)].to_vec()); // one short
        let mut flipped = valid.to_vec();
        let i = r.range(flipped.len());
        flipped[i] ^= 0xFF; // single-byte corruption
        out.push(flipped);
    }
    out.push(vec![]); // empty
    out.push(vec![0xFF; 4]);
    out
}

// ── corpus generation ─────────────────────────────────────────────────────────

fn write_corpus(target: &str, samples: &[Vec<u8>]) {
    let dir = corpus_root().join(target);
    fs::create_dir_all(&dir).expect("create corpus dir");
    for (i, s) in samples.iter().enumerate() {
        // Content-addressed-ish name keyed by index+len so regenerations are
        // stable and don't accumulate junk.
        let path = dir.join(format!("seed_{i:04}_{}", s.len()));
        fs::write(&path, s).expect("write corpus seed");
    }
}

fn gen_target(r: &mut Rng, valids: usize, mk: impl Fn(&mut Rng) -> Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for _ in 0..valids {
        let v = mk(r);
        let nm = near_misses(r, &v);
        out.push(v);
        out.extend(nm);
    }
    out
}

/// Regenerate the whole seed corpus. Runs as a normal test so `cargo test`
/// materializes the committed corpus; idempotent (stable filenames).
#[test]
fn generate_seed_corpus() {
    let mut r = Rng(0xB10C_C025_0001);
    write_corpus("block_parse", &gen_target(&mut r, 8, rand_block));
    write_corpus("tx_parse", &gen_target(&mut r, 8, |r| rand_tx(r).to_stratum_bytes(true)));
    write_corpus("netmsg_decode", &gen_target(&mut r, 12, rand_netmsg));
    write_corpus("handshake_decode", &{
        let mut v = gen_target(&mut r, 6, rand_handshake_init);
        v.extend(gen_target(&mut r, 6, rand_handshake_resp));
        v
    });
    write_corpus("pow_decode", &gen_target(&mut r, 8, rand_pow));
    write_corpus("pow_verify", &gen_target(&mut r, 8, rand_pow));
    write_corpus("merkle_path", &gen_target(&mut r, 8, rand_merkle));
    write_corpus("mempool_ops", &gen_target(&mut r, 12, rand_mempool_ops));

    // Sanity: the highest-value target has a non-empty corpus on disk.
    let n = fs::read_dir(corpus_root().join("netmsg_decode"))
        .expect("netmsg corpus dir")
        .count();
    assert!(n > 0, "netmsg_decode corpus must be populated");
}

// ── replay (the actual floor) ─────────────────────────────────────────────────

/// Read every file under `fuzz/corpus/<target>/`. Also returns freshly-generated
/// in-memory samples so the floor holds even if the on-disk corpus was cleaned.
fn corpus_and_seeds(target: &str, mk: impl Fn(&mut Rng) -> Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let dir = corpus_root().join(target);
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            if let Ok(b) = fs::read(e.path()) {
                out.push(b);
            }
        }
    }
    // Always-present in-memory floor, independent of on-disk state.
    let mut r = Rng(0xF100_0000_0001);
    out.extend(gen_target(&mut r, 6, mk));
    out
}

fn assert_no_panic<F: Fn(&[u8]) + std::panic::RefUnwindSafe>(target: &str, mk: impl Fn(&mut Rng) -> Vec<u8>, run: F) {
    for data in corpus_and_seeds(target, &mk) {
        let res = catch_unwind(AssertUnwindSafe(|| run(&data)));
        assert!(
            res.is_ok(),
            "{target} parser panicked on {} bytes: {:02x?}",
            data.len(),
            &data[..data.len().min(64)]
        );
    }
}

#[test]
fn floor_block_parse_no_panic() {
    assert_no_panic("block_parse", rand_block, |d| {
        let _ = Block::from_bitcoin_bytes(d);
    });
}

#[test]
fn floor_tx_parse_no_panic() {
    assert_no_panic("tx_parse", |r| rand_tx(r).to_stratum_bytes(true), |d| {
        let _ = Transaction::from_stratum_bytes(d);
    });
}

#[test]
fn floor_netmsg_decode_no_panic() {
    assert_no_panic("netmsg_decode", rand_netmsg, |d| {
        let _ = bincode::serde::decode_from_slice::<NetworkMessage, _>(d, bincfg());
    });
}

#[test]
fn floor_handshake_decode_no_panic() {
    assert_no_panic("handshake_decode", rand_handshake_init, |d| {
        let _ = bincode::serde::decode_from_slice::<HandshakeInit, _>(d, bincfg());
        let _ = bincode::serde::decode_from_slice::<HandshakeResp, _>(d, bincfg());
    });
}

/// Replay the mempool op-stream corpus through a real `Mempool`, asserting the
/// three-way invariant holds after each op (the stable-Rust mirror of the
/// `mempool_ops` libFuzzer target). Reuses the target's own VM shape.
#[test]
fn floor_mempool_ops_no_panic() {
    for data in corpus_and_seeds("mempool_ops", rand_mempool_ops) {
        let res = catch_unwind(AssertUnwindSafe(|| drive_mempool(&data)));
        assert!(res.is_ok(), "mempool_ops panicked on {} bytes", data.len());
    }
}

fn drive_mempool(data: &[u8]) {
    let mp = Mempool::new();
    let mut i = 0usize;
    let mut live: Vec<[u8; 32]> = Vec::new();
    let u8 = |i: &mut usize| {
        let b = data.get(*i).copied().unwrap_or(0);
        *i += 1;
        b
    };
    let mut ops = 0;
    while i < data.len() && ops < 2048 {
        ops += 1;
        match u8(&mut i) % 3 {
            0 => {
                let n_in = 1 + (u8(&mut i) % 3) as usize;
                let inputs = (0..n_in)
                    .map(|_| {
                        let mut txid = [0u8; 32];
                        for b in txid.iter_mut() {
                            *b = u8(&mut i);
                        }
                        TxInput {
                            prev_txid: txid,
                            prev_index: u8(&mut i) as u32,
                            script_sig: vec![0u8; 8],
                            sequence: 0xffff_ffff,
                        }
                    })
                    .collect();
                let tx = Transaction {
                    version: 1,
                    inputs,
                    outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![1u8; 20] }],
                    locktime: 0,
                };
                if let Ok(txid) = mp.add(tx, 100_000 + u8(&mut i) as u64) {
                    live.push(txid);
                }
            }
            1 => {
                if !live.is_empty() {
                    let idx = (u8(&mut i) as usize) % live.len();
                    let txid = live.swap_remove(idx);
                    mp.remove(&txid);
                }
            }
            _ => {
                let n = (u8(&mut i) % 4) as usize;
                let mut batch = Vec::new();
                for _ in 0..n {
                    if live.is_empty() {
                        break;
                    }
                    let idx = (u8(&mut i) as usize) % live.len();
                    batch.push(live.swap_remove(idx));
                }
                mp.remove_confirmed(&batch);
            }
        }
        mp.debug_check_invariants().expect("mempool invariant");
    }
}
