# Fuzzing — untrusted-input attack surface

Coverage-guided fuzzers (cargo-fuzz / libFuzzer) for the consensus-critical
parsers that consume bytes from untrusted peers. A parse must only ever return
`Err` — never panic, over-allocate, or hang.

> **Scope gap, stated rather than left to be discovered: every target below
> fuzzes Genesis-3.** All eleven link against `bloch` (the proof-of-work node in
> `legacy/genesis3-node/`) and `bloch-sis-pow`. Genesis-3 stopped permanently at
> height 39,918 on 2026-08-13. The live chain is **Genesis-4, proof of stake**,
> and **no target here fuzzes it** — not `bloch-pos-committee`'s transition or
> state root, not `bloch-pos-node`'s block/attestation wire codec, not its
> genesis-manifest or carryover parser, each of which consumes bytes from a
> remote peer or an operator-supplied file today.
>
> This is the same defect class as a lint gate scoped to a retired crate: the
> control exists, its report is clean, and it is aimed at software that no
> longer runs. Read the results below as assurance about the chain that
> produced Genesis-4's opening ledger, and as **no assurance at all** about the
> chain now producing blocks. Genesis-4 targets are outstanding work.
>
> **Worse, and verified 2026-08-14: this crate does not currently resolve, so
> none of it runs at all.** `Cargo.toml` declares `bloch = { path = ".." }`,
> but the repository root became a *virtual* manifest when the proof-of-work
> node moved to `legacy/genesis3-node/`. `cargo metadata` from this directory
> fails with:
>
> ```
> found a virtual manifest at `<repo>/Cargo.toml` instead of a package manifest
> ```
>
> The CI `fuzz-smoke` job is `allow_failure: true`, so this has been failing
> silently rather than reporting. **Treat the execution table below as a record
> of a 2026-07-22 run against the then-current layout, not as a claim that
> anything fuzzes today.** The fix is one line — repoint the dependency at
> `legacy/genesis3-node` — plus one real run to confirm the harness still
> links; it is left undone here deliberately, because changing what a CI job
> builds is a behaviour change and belongs in its own reviewed commit.

Targets (11 total, all against the retired Genesis-3 code):

Wire / P2P ingest (untrusted remote bytes — primary attack surface):
- `block_parse`     — `Block::from_bitcoin_bytes` (incl. the shielded-tx suffix).
- `tx_parse`        — `Transaction::from_stratum_bytes`.
- `netmsg_decode`   — gossipsub `NetworkMessage` bincode2 decode.
- `handshake_decode`— PQ-transport `HandshakeInit` / `HandshakeResp` decode.
- `merkle_path`     — shielded-pool `verify_path` (attacker path + index).
- `mempool_ops`     — stateful mempool invariant guard.

PoW (retired — Genesis-3 stopped at height 39,918; nothing verifies these paths
on a live chain any more):
- `sha256d_pow`     — the SHA-256d verifier: header wire parse
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

## Execution status (last local run: 2026-07-22, nightly + cargo-fuzz 0.12.0, macOS x86_64, AddressSanitizer)

The four scanner-priority surfaces were **built and executed** locally — no
crash, panic, over-allocation, or hang was observed in short smoke runs:

| Target           | Surface                                   | Result (ASan)              |
|------------------|-------------------------------------------|----------------------------|
| `block_parse`    | Block wire deser (primary remote surface) | 167 326 runs, ~7 967 exec/s, clean |
| `tx_parse`       | Transaction wire deser                    | 257 762 runs, ~8 314 exec/s, clean |
| `sha256d_pow`    | SHA-256d PoW path (retired with Genesis-3)| 174 420 runs, ~8 305 exec/s, clean |
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

## Outstanding: Genesis-4 has no targets

Named so the gap is a work item and not a silence. The untrusted-input surfaces
of the live chain are, at minimum:

- `bloch-pos-node/src/codec.rs` — block and attestation wire decode, and the
  genesis-manifest and keystore file formats. This is the direct remote-peer
  surface, the exact analogue of `block_parse` and `netmsg_decode`.
- `bloch-pos-node/src/genesis.rs` — the carryover snapshot parser, which reads a
  54 MB operator-supplied file with 452,726 entries.
- `bloch-pos-committee/src/transition.rs` — `PosTransaction` decode and apply,
  the analogue of `tx_parse` and `mempool_ops`.
- `bloch-pos-committee/src/state_root.rs` and `committees.rs` — the analogues of
  `ghostdag_order`, now that sortition and not DAG colouring decides ordering.

`sig_verify` is the one target whose primitive still applies: Genesis-4 uses the
same hybrid ML-DSA-65 ‖ Falcon-1024 construction on every consensus path. It
still reaches it through the retired crate's wrapper rather than the path the
live node calls, so it is evidence about the primitive and not about the live
call site.
