# Fuzz seed corpora

One subdirectory per libFuzzer target (`fuzz/corpus/<target>/`). Each file is one
input. libFuzzer starts from these instead of an empty corpus, so it reaches
interesting states faster, and each file doubles as a committed regression seed.

**Provenance (honesty note):** these are *seed* inputs derived from the actual
wire formats read out of the source, not a saved fuzzing run and not a proof of
anything. They are hand-derived to be byte-accurate to:

| target | format the seeds encode | source of truth |
|---|---|---|
| `netmsg_decode` | `NetworkMessage`, bincode 2 `config::standard()` | live ingest `src/network/mod.rs:412` |
| `handshake_decode` | `HandshakeInit` / `HandshakeResp`, bincode 2 `standard()` | `src/transport/mod.rs:128,138` |
| `mempool_ops` | the target's own op-script (op=`u8%3`; add/remove/remove_confirmed) | `fuzz/fuzz_targets/mempool_ops.rs` |
| `tx_parse` | `Transaction::from_stratum_bytes` (bitcoin-varint) | `crates/bloch-crypto/src/core/mod.rs` |
| `pow_decode` / `pow_verify` | 256 signed bytes, each `abs <= B` (B=2) | `crates/bloch-sis-pow` (`ENCODED_S_LEN=256`) |
| `merkle_path` | `leaf[32] ‖ root[32] ‖ index_le[8] ‖ path(32·k)` | `fuzz/fuzz_targets/merkle_path.rs` |
| `block_parse` | 80-byte `MiningHeader` prefix ‖ varint parents ‖ tail | `Block::from_bitcoin_bytes` |

Each dir mixes valid encodings with a few near-miss / truncated / over-alloc
probes (`nm_*`) so the fuzzer has both a deep starting point and boundary seeds.

`block_parse` seeds reach the parser but are not full consensus-valid blocks
(`prev_hash` does not match `parents_commitment`); libFuzzer mutates from there.

To regenerate/expand from the node's real serializers (round-trip fixtures)
requires the nightly + `cargo-fuzz` toolchain that the fuzz crate is gated on
(it is `exclude`d from the workspace). That is a follow-up, not a claim made here.

## Genesis-4 targets (`g4_codec`, `g4_rpc`, `g4_p2p_sync`) — encoder-derived

Unlike the Genesis-3 seeds above, these are **not hand-derived**. They are
written by `fuzz/seedgen`, a small standalone package that calls the node's own
`encode_envelope`, `encode_attestation`, `encode_sync_request` and
`encode_sync_response`, so a change to the wire format changes the seeds the
next time they are regenerated instead of silently invalidating them:

    cd fuzz/seedgen && cargo run --release

The `g4_rpc` seeds are the exception, and are literal request bodies — that
surface is text, so there is no encoder to call. Each one is a method `route()`
actually accepts, so the fuzzer starts inside the dispatcher rather than outside
the JSON parser, plus a few shapes the dispatcher must survive (a batch, an
id larger than 2^53, a deeply nested id).

These directories hold seeds only. libFuzzer writes newly discovered inputs back
into the corpus directory it is given, so after a campaign this tree will have
grown; what is committed is the small seed set, deliberately.
