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

## Harness repair, 2026-08-25 — this harness was DEAD for the whole Genesis-4 era

Everything below the repair note was, until this date, describing a program that
could not build.

`fuzz/Cargo.toml` took the node by `bloch = { path = ".." }`. When Genesis-4
became the trunk the repo root turned into a **virtual manifest** and the
`bloch` package moved to `legacy/genesis3-node`, so that path stopped naming a
package. `cargo metadata` on this crate then failed outright:

```
error: failed to get `bloch` as a dependency of package `bloch-fuzz v0.0.0`
Caused by: found a virtual manifest at `.../Cargo.toml` instead of a package manifest
```

That is a resolution failure, which means **no target in this file could be
built** — not the five `fuzz-smoke` names, not the other six. Two things hid it:
`.gitlab-ci.yml`'s `fuzz-smoke` job is `allow_failure: true`, so the pipeline
stayed green; and `fuzz/corpus/` holds eleven populated directories, so the tree
kept looking like a running fuzzing program on disk.

Fix: `bloch = { path = "../legacy/genesis3-node" }`. That package still declares
`[lib] name = "bloch"`, so every `bloch::...` import in the existing targets
resolves unchanged. `fuzz-smoke` now runs `cargo +nightly fuzz build` (all
targets) *before* it runs anything, because a link failure is not a fuzzing
result and must never again be reported as one.

## Execution status (last local run: 2026-07-22, nightly + cargo-fuzz 0.12.0, macOS x86_64, AddressSanitizer)

The four scanner-priority surfaces were **built and executed** locally — no
crash, panic, over-allocation, or hang was observed in short smoke runs:

| Target           | Surface                                   | Result (ASan)              |
|------------------|-------------------------------------------|----------------------------|
| `block_parse`    | Block wire deser (primary remote surface) | 167 326 runs, ~7 967 exec/s, clean |
| `tx_parse`       | Transaction wire deser                    | 257 762 runs, ~8 314 exec/s, clean |
| `sha256d_pow`    | LIVE Genesis-2 SHA-256d PoW path          | 174 420 runs, ~8 305 exec/s, clean |
| `ghostdag_order` | GhostDAG ordering (stateful)              |  41 067 runs, ~1 955 exec/s, clean |
| `sig_verify`     | Hybrid ML-DSA-65 ‖ Falcon-1024 verify     | 172 169 runs, ~8 198 exec/s, clean |

Smoke runs (20–30 s) prove the harness links against the real `bloch` API and
does not fault on shallow inputs; they are **not** a coverage-exhausting
campaign. Run a real campaign (minutes–hours, or continuously in OSS-Fuzz)
before drawing any assurance conclusion. The remaining targets
(`netmsg_decode`, `handshake_decode`, `merkle_path`, `mempool_ops`,
`pow_verify`, `pow_decode`) build from the same crate and toolchain but were not
individually smoke-run in this pass.

This crate is **not** part of the node build (not a path-dep of `bloch`); it is
its own workspace root (empty `[workspace]` table) so `cargo fuzz build` does not
walk up into the node workspace. Wire `cargo fuzz run` into CI/nightly on a
capable runner (see `oss-fuzz/`). New parsers of untrusted bytes should get a
target here.
