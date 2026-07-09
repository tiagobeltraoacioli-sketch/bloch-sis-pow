# Fuzzing — untrusted-input attack surface

Coverage-guided fuzzers (cargo-fuzz / libFuzzer) for the consensus-critical
parsers that consume bytes from untrusted peers. A parse must only ever return
`Err` — never panic, over-allocate, or hang.

Targets:
- `block_parse` — `Block::from_bitcoin_bytes` (incl. the shielded-tx suffix).
- `tx_parse` — `Transaction::from_stratum_bytes`.

Run (nightly toolchain + cargo-fuzz):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run block_parse            # or tx_parse
cargo +nightly fuzz run block_parse -- -max_total_time=300
```

Reproduce a crash: `cargo +nightly fuzz run block_parse fuzz/artifacts/...`.

This crate is **not** part of the node build (not a path-dep). Not run in the
dev sandbox (needs the nightly + libFuzzer toolchain) — it is a ready harness;
wire `cargo fuzz run` into CI/nightly on a capable runner. New parsers of
untrusted bytes should get a target here.
