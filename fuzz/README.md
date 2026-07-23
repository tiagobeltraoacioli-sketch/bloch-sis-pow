# Fuzzing — untrusted-input attack surface

Coverage-guided fuzzers (cargo-fuzz / libFuzzer) for the consensus-critical
parsers that consume bytes from untrusted peers. A parse must only ever return
`Err` — never panic, over-allocate, or hang.

Targets (11 total):

Wire / P2P ingest (untrusted remote bytes — primary attack surface):
- `block_parse`     — `Block::from_bitcoin_bytes` (incl. the shielded-tx suffix).
- `tx_parse`        — `Transaction::from_stratum_bytes`.
- `netmsg_decode`   — gossipsub `NetworkMessage` bincode2 decode.
- `handshake_decode`— PQ-transport `HandshakeInit` / `HandshakeResp` decode.
- `merkle_path`     — shielded-pool `verify_path` (attacker path + index).
- `mempool_ops`     — stateful mempool invariant guard.

PoW:
- `sha256d_pow`     — **LIVE Genesis-2** SHA-256d verifier: header wire parse
                      → `pow_hash` → `sha256d_pow_valid` at both endianness-fork
                      arms, plus the raw 80-byte `MiningHeader` projection.
- `pow_verify`      — the OTHER (Mainnet/Testnet) chain's Module-SIS lattice
                      verifier (`decode_s` + `verify` at Target extremes).
- `pow_decode`      — Module-SIS solution decoder.

Consensus ordering:
- `ghostdag_order`  — stateful GhostDAG under adversarial DAG topologies
                      (coloring + `ordered_hashes_from` / `tip` queries).

Crypto:
- `sig_verify`      — hybrid ML-DSA-65 ‖ Falcon-1024 `crypto::verify` + the
                      crypto-agility suite-envelope / legacy-fallback parser.

Run (nightly toolchain + cargo-fuzz):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run sha256d_pow                       # or any target above
cargo +nightly fuzz run ghostdag_order -- -max_total_time=300
cargo +nightly fuzz run sig_verify   -- -max_total_time=300
```

Reproduce a crash: `cargo +nightly fuzz run <target> fuzz/artifacts/...`.

Status of the three new scanner-priority targets (`sha256d_pow`,
`ghostdag_order`, `sig_verify`): their API usage is compile-verified against the
built `bloch` crate, but they were NOT executed in the dev sandbox — libFuzzer
needs the nightly toolchain + sanitizer runtime, which is not installed here.
Run them on a capable runner / in CI (see `oss-fuzz/`) with the commands above.

This crate is **not** part of the node build (not a path-dep). Not run in the
dev sandbox (needs the nightly + libFuzzer toolchain) — it is a ready harness;
wire `cargo fuzz run` into CI/nightly on a capable runner. New parsers of
untrusted bytes should get a target here.
