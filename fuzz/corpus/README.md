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
