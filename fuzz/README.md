# Fuzzing — untrusted-input attack surface

Coverage-guided fuzzers (cargo-fuzz / libFuzzer) for the consensus-critical
parsers that consume bytes from untrusted peers. A parse must only ever return
`Err` — never panic, over-allocate, or hang.

Targets (15 total).

## Genesis-4 — THE LIVE CHAIN

Untrusted bytes reaching the running fleet. Each asserts a **property**, not
merely the absence of a panic — a decoder can be perfectly panic-free and still
accept `encode(x) ‖ junk`, which is the block-10802 defect class.

- `pos_envelope_decode`    — `codec::decode_envelope`: the whole block frame off
                             gossipsub. Round-trips to the exact input bytes;
                             the attestation/transaction caps hold.
- `pos_attestation_decode` — `codec::decode_attestation`: the highest-rate frame
                             on the network. Round-trips, for input consumed whole.
- `pos_header_decode`      — `BlockHeaderV4::canonical_deserialize`: the single
                             derivation path `BlockId` rests on. Length is exact
                             in both directions; round-trips.
- `pos_carryover_snapshot` — `genesis::read_carryover_snapshot`: the text parser
                             that reads the opening ledger. Entries sum to
                             `total_sat`, `total_sat` is the split of the
                             Genesis-3 total, outpoints strictly ascend.

`bloch-pos-node` is a `[[bin]]`-only crate, so these targets reach `src/codec.rs`
and `src/genesis.rs` through `#[path]` includes: the fuzzed bytes run the node's
own source rather than a copy of it.

## Genesis-3 — CLOSED (stopped at height 39,918)

Kept because Genesis-4's opening ledger is Genesis-3's output, and the parsers
below still run in the `bloch` binary an auditor uses to re-derive it. They are
**not** coverage of the live chain.

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

Does it still build? (stable, seconds, no libFuzzer needed):

```bash
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Run (nightly toolchain + cargo-fuzz):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run pos_envelope_decode               # or any target above
cargo +nightly fuzz run pos_carryover_snapshot -- -max_total_time=300
cargo +nightly fuzz run sha256d_pow           -- -max_total_time=300
```

Reproduce a crash: `cargo +nightly fuzz run <target> fuzz/artifacts/...`.

## Execution status

**The whole harness stopped building when Genesis-4 landed, and nobody noticed
for weeks.** `fuzz/Cargo.toml` declared `bloch = { path = ".." }`, from when the
repository root was the `bloch` package; Genesis-4 made the root a virtual
manifest and moved the PoW node to `legacy/genesis3-node/`, and cargo answers a
path-dep on a virtual manifest with a hard error. Every target failed to resolve.
Nothing went red, because the only CI job that touched `fuzz/` skips itself
without nightly and was `allow_failure`.

Two things now fail closed instead:
`crates/bloch-pos-node/tests/fuzz_harness_resolves.rs` (runs in `cargo test
--workspace`; no nightly, no libFuzzer, no C++ toolchain) and the `fuzz-build`
job in `.gitlab-ci.yml` (`cargo check --manifest-path fuzz/Cargo.toml --bins`,
blocking).

**Nothing below has been re-run since.** The table is the Genesis-3 tree as it
stood on 2026-07-22, and it describes a chain that has since stopped. Treat it
as history, not as assurance about anything running today; the four `pos_*`
targets have no campaign behind them at all yet.

### Genesis-3 tree, 2026-07-22 (nightly + cargo-fuzz 0.12.0, macOS x86_64, AddressSanitizer)

The four scanner-priority surfaces were built and executed locally — no
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

This crate is **not** a member of the node workspace; it is its own workspace
root (empty `[workspace]` table) so `cargo fuzz build` does not walk up into the
node workspace. That isolation is exactly why its breakage was invisible to
`cargo build --workspace`, and why the resolve check had to be written as a test
inside a workspace member. New parsers of untrusted bytes should get a target
here, an entry in `oss-fuzz/build.sh`, and a line in the list above — the first
two are enforced, the third is not.
