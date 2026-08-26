// SPDX-License-Identifier: AGPL-3.0-or-later
//! Seeds `fuzz/corpus/g4_{codec,rpc,p2p_sync}/` from the REAL encoders.
//!
//! Its own package, on purpose. Declared as a `[[bin]]` in ../Cargo.toml it
//! would show up in `cargo fuzz list` and in the `fuzz-smoke` loop as a fuzz
//! target that it is not; declared as an `[[example]]` there it would still
//! drag the whole `bloch-fuzz` dependency graph in, which means `bloch` and so
//! `librocksdb-sys` — a ~35-minute C++ build for a two-minute job. Standing
//! alone it depends on the Genesis-4 crates and nothing else.
//!
//! Run:  cd fuzz/seedgen && cargo run --release   (stable toolchain is fine)
//! Output paths are resolved from CARGO_MANIFEST_DIR, so cwd does not matter.
//!
//! Every block/sync seed is produced by calling `encode_envelope`,
//! `encode_sync_request` and `encode_sync_response` themselves. Hand-written
//! seed bytes drift from the encoder silently; these cannot.

use std::fs;
use std::path::Path;

use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body, VERSION_G4};
use bloch_pos_node::codec::encode_envelope;
use bloch_pos_node::p2p::{encode_sync_request, encode_sync_response, SyncRequest, SyncResponse};

/// Real ML-DSA-65 ‖ Falcon-1024 signatures are 4589 bytes on this chain (see
/// the codec's own round-trip test), so seeds carry that length rather than a
/// toy one — the fuzzer should start from the shape the live wire has.
const SIG_LEN: usize = 4589;

/// codec.rs:24 `MAX_FIELD_LEN` == p2p.rs:278 `MAX_SYNC_FRAME` == 8 MiB. One
/// codec field may legally be as large as an entire sync frame; the boundary
/// is worth a seed on both sides of it.
const MAX_FIELD_LEN: usize = 8 * 1024 * 1024;

fn header(slot: u64) -> BlockHeaderV4 {
    BlockHeaderV4 {
        version: VERSION_G4,
        parent: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
        slot,
        proposer_index: 7,
        randao_reveal: [0x44; 32],
        randao_mix: [0x55; 32],
        justified_root: [0x66; 32],
        finalized_root: [0x77; 32],
        attestation_root: [0x88; 32],
        coherence_root: [0x99; 32],
    }
}

fn attestation(validator: u32, slot: u64) -> Attestation {
    Attestation {
        data: AttestationData {
            slot,
            head: [0xA1; 32],
            source_epoch: slot / 32,
            source_root: [0xA2; 32],
            target_epoch: slot / 32 + 1,
            target_root: [0xA3; 32],
        },
        validator,
        signature: vec![0xC0; SIG_LEN],
    }
}

fn write(dir: &str, name: &str, bytes: &[u8]) {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("../corpus").join(dir);
    fs::create_dir_all(&d).expect("corpus dir");
    fs::write(d.join(name), bytes).expect("write seed");
    println!("{dir}/{name}: {} bytes", bytes.len());
}

fn main() {
    // ── g4_codec ────────────────────────────────────────────────────────────
    // 1. Empty body — the minimum legal envelope.
    let empty = BlockEnvelope {
        header: header(1),
        proposer_sig: vec![0xDD; SIG_LEN],
        body: Body { transactions: vec![], attestations: vec![] },
    };
    write("g4_codec", "envelope_empty_body", &encode_envelope(&empty));

    // 2. A realistic devnet block: 12 validators' attestations + a few txs.
    let full = BlockEnvelope {
        header: header(4242),
        proposer_sig: vec![0xDD; SIG_LEN],
        body: Body {
            transactions: vec![vec![0xEE; 220], vec![], vec![0x01, 0x02, 0x03]],
            attestations: (0..12u32).map(|v| attestation(v, 4241)).collect(),
        },
    };
    write("g4_codec", "envelope_12_att_3_tx", &encode_envelope(&full));

    // 3. The MAX_FIELD_LEN boundary, as LENGTH PREFIXES rather than as 8 MiB of
    //    payload. `Reader::bytes` checks `n > MAX_FIELD_LEN` on the decoded u32
    //    BEFORE it allocates, so both sides of that comparison are reachable in
    //    ~308 bytes. Seeding an actual 8 MiB file would instead push libFuzzer's
    //    inferred `-max_len` to 8 MiB and collapse exec/s for every run.
    for (name, n) in [
        ("envelope_len_prefix_at_cap", MAX_FIELD_LEN as u32),
        ("envelope_len_prefix_over_cap", MAX_FIELD_LEN as u32 + 1),
    ] {
        let mut b = header(9).canonical_serialize().to_vec();
        b.extend_from_slice(&n.to_le_bytes());
        write("g4_codec", name, &b);
    }

    // 4. A bare attestation, for the standalone `decode_attestation` arm.
    let mut bare = Vec::new();
    bloch_pos_node::codec::encode_attestation(&mut bare, &attestation(3, 77));
    write("g4_codec", "attestation_bare", &bare);

    // ── g4_p2p_sync ─────────────────────────────────────────────────────────
    write(
        "g4_p2p_sync",
        "req_getblocks",
        &encode_sync_request(&SyncRequest::GetBlocks { after_slot: 4242, limit: 128 }),
    );
    write(
        "g4_p2p_sync",
        "req_getblocks_zero",
        &encode_sync_request(&SyncRequest::GetBlocks { after_slot: 0, limit: 0 }),
    );
    write(
        "g4_p2p_sync",
        "resp_empty",
        &encode_sync_response(&SyncResponse::Blocks { envelopes: vec![] }),
    );
    // A response carrying real envelopes, so the nested `decode_envelope` arm
    // has somewhere to start from.
    write(
        "g4_p2p_sync",
        "resp_two_envelopes",
        &encode_sync_response(&SyncResponse::Blocks {
            envelopes: vec![encode_envelope(&empty), encode_envelope(&full)],
        }),
    );
    // MAX_SYNC_BLOCKS is 128, and `decode_sync_response` rejects n > 128. This
    // seed sits at exactly the largest accepted count, which is the edge that
    // comparison turns on. The elements are empty rather than 128 copies of a
    // real envelope: the frame decoder only length-prefixes them, so the count
    // boundary is reached either way, and the realistic version was 628 KB —
    // large enough to drag libFuzzer's inferred `-max_len` up and cost exec/s
    // on every run for no extra reach. `resp_two_envelopes` above carries the
    // real nested-envelope shape.
    write(
        "g4_p2p_sync",
        "resp_count_at_max_sync_blocks",
        &encode_sync_response(&SyncResponse::Blocks { envelopes: vec![Vec::new(); 128] }),
    );

    // ── g4_rpc ──────────────────────────────────────────────────────────────
    // Text, so these are written literally rather than encoder-derived; each
    // one is a method `route()` actually accepts, so the fuzzer starts inside
    // the dispatch rather than outside the JSON parser.
    for (name, body) in [
        ("getchaininfo", r#"{"jsonrpc":"2.0","id":1,"method":"getchaininfo"}"#),
        ("getblockcount", r#"{"jsonrpc":"2.0","id":2,"method":"getblockcount"}"#),
        ("getblockbyslot", r#"{"jsonrpc":"2.0","id":3,"method":"getblockbyslot","params":[4242]}"#),
        (
            "getblockbyid",
            r#"{"jsonrpc":"2.0","id":4,"method":"getblockbyid","params":["1111111111111111111111111111111111111111111111111111111111111111"]}"#,
        ),
        (
            "getbalance",
            r#"{"jsonrpc":"2.0","id":5,"method":"getbalance","params":["00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"]}"#,
        ),
        (
            "listunspent",
            r#"{"jsonrpc":"2.0","id":6,"method":"listunspent","params":["00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",1000]}"#,
        ),
        (
            "gettxout",
            r#"{"jsonrpc":"2.0","id":7,"method":"gettxout","params":["abababababababababababababababababababababababababababababababab",0]}"#,
        ),
        ("getvalidator", r#"{"jsonrpc":"2.0","id":8,"method":"getvalidator","params":[0]}"#),
        ("getmempoolinfo", r#"{"jsonrpc":"2.0","id":9,"method":"getmempoolinfo"}"#),
        ("sendrawtransaction", r#"{"jsonrpc":"2.0","id":10,"method":"sendrawtransaction","params":["00"]}"#),
        // Shapes the dispatcher must survive: a batch, a non-object, a huge id.
        ("batch_rejected", r#"[{"jsonrpc":"2.0","id":1,"method":"getchaininfo"}]"#),
        ("bignum_id", r#"{"jsonrpc":"2.0","id":9007199254740993,"method":"getblockcount"}"#),
        ("nested", r#"{"jsonrpc":"2.0","id":{"a":[1,2,{"b":null}]},"method":"getchaininfo","params":{"slot":1}}"#),
    ] {
        write("g4_rpc", name, body.as_bytes());
    }
}
