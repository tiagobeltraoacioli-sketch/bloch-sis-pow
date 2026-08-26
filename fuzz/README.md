# Fuzzing — untrusted-input attack surface

Coverage-guided fuzzers (cargo-fuzz / libFuzzer) for the consensus-critical
parsers that consume bytes from untrusted peers. A parse must only ever return
`Err` — never panic, over-allocate, or hang.

Targets (14 total):

**Genesis-4 — THE LIVE CHAIN.** These three are the remote surface an external
audit found unfuzzed. They link `bloch_pos_node` (the crate the fleet runs), not
a transcription of it:
- `g4_codec`       — `codec::decode_envelope` / `decode_attestation`: the block
                     and attestation wire form, reached from BOTH gossip and
                     sync ingest. Also asserts `encode(decode(x)) == x`.
- `g4_rpc`         — `rpc::parse_json` / `route` / `handle_body`: the
                     **unauthenticated public** JSON-RPC surface `g4rpc` serves
                     to the internet. Parse + dispatch-to-`RpcRequest` only; the
                     engine backend is stubbed (see below).
- `g4_p2p_sync`    — `p2p::decode_sync_request` / `decode_sync_response`: the
                     directed-sync frame codec, plus the nested envelope decode
                     each response element goes through.

**Genesis-3 — the retired proof-of-work node, kept buildable for audit.**

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
resolves unchanged. CI is now two jobs, because they answer two different
questions. **`fuzz-build` blocks**: "does the harness link against the real
node?" has a yes/no answer, and the answer being NO is exactly what went
unnoticed here — a harness that does not link is a broken build, not a weak
fuzzing result. **`fuzz-smoke` stays `allow_failure: true`**: a 20-second search
that finds nothing has not proved anything, so a red there is a signal to read
rather than a merge gate. The asymmetry is the point; `allow_failure` is
defensible for a bounded search and indefensible for a link check, and one job
could not be both.

## Execution status — 2026-08-25, after the harness repair

Toolchain: nightly-x86_64-apple-darwin + cargo-fuzz 0.12.0, macOS x86_64,
AddressSanitizer, `-C debug-assertions`.

### Build: 14 / 14 targets link

`cargo +nightly fuzz build` — 390 crates, **0 errors**, 35m14s cold for the
eleven Genesis-3 targets (the long pole is `librocksdb-sys`, a C++ build pulled
in by the Genesis-3 storage layer), 3m16s more for the three Genesis-4 ones.

| Target | Era | Build |
|---|---|---|
| `g4_codec` | G4 | BUILT |
| `g4_rpc` | G4 | BUILT |
| `g4_p2p_sync` | G4 | BUILT |
| `block_parse` | G3 | BUILT |
| `tx_parse` | G3 | BUILT |
| `pow_decode` | G3 | BUILT |
| `pow_verify` | G3 | BUILT |
| `merkle_path` | G3 | BUILT |
| `netmsg_decode` | G3 | BUILT |
| `handshake_decode` | G3 | BUILT |
| `mempool_ops` | G3 | BUILT |
| `sha256d_pow` | G3 | BUILT |
| `ghostdag_order` | G3 | BUILT |
| `sig_verify` | G3 | BUILT |

No target had to be rewritten or dropped to get there; the repair was one path.

### Campaign: the three Genesis-4 targets, 20 s each

| Target | runs | `cov:` | `ft:` | `exec/s` | crashes |
|---|---|---|---|---|---|
| `g4_codec`    | 65 909 | **300** | 624 | ~3 138 | none |
| `g4_rpc`      | 45 195 | **833** | 2 437 | ~2 152 | none |
| `g4_p2p_sync` | 64 670 | **249** | 586 | ~3 079 | none |

**Zero crashes, zero panics, zero OOM. `fuzz/artifacts/` is empty.**

Coverage is real, not nominal — the point of quoting `cov:` at all. `g4_rpc`
was still finding new edges at the moment it stopped (`cov:` 832 -> 833 with
`ft:` climbing through the final second), and the dictionary libFuzzer inferred
from it contains `"method"`, `"getbalance"`, `"1.0"` and `"true"` — tokens that
only appear if the input is reaching the JSON parser and the method router
rather than being rejected at the edge.

**Honest caveats, in order of how much they should temper the above:**

1. **20 s per target is a smoke run, not assurance.** It was 20 s and not longer
   because the machine was shared with a priority mainnet-consensus build; the
   numbers are CPU-limited by contention. A real campaign is minutes to hours,
   or continuous in OSS-Fuzz (`oss-fuzz/`). Nothing here licenses "the RPC
   surface is safe".
2. **`g4_rpc` does not cover engine dispatch.** Everything from the request body
   down to an `RpcRequest` is fuzzed — `parse_json`, the id/`jsonrpc`/`method`
   handling, `route`, `want_u64` / `want_u32` / `want_hex32`, `from_hex`, and
   `PosTransaction::from_canonical_bytes` on `sendrawtransaction`. Everything
   *past* `RpcRequest` is not: production `EngineBackend` hands the request to
   the consensus thread and blocks on a reply channel, which cannot be stood up
   per fuzz iteration, so the target uses a stub backend. A clean run says
   nothing about the engine's query handlers.
3. **`g4_rpc` does not cover the HTTP layer.** `read_request` / `find_head_end`
   parse the request head off a `TcpStream`; they are private and socket-bound.
   Not fuzzed.
4. **`g4_p2p_sync` covers frame DECODE only.** `read_capped` (p2p.rs:484) and
   the async I/O around it are outside the target.
5. **The eleven Genesis-3 targets were built but not re-run** in this pass. They
   link and load their corpora; the last campaign numbers for them predate the
   trunk switch and are not reproduced here, because a number obtained from a
   harness that could not build is not a number.

### Seed corpora for the Genesis-4 targets

`fuzz/corpus/g4_*` are produced by `fuzz/seedgen` calling the node's OWN
encoders — `encode_envelope`, `encode_attestation`, `encode_sync_request`,
`encode_sync_response` — so they cannot drift from the wire format the way
hand-written seed bytes do. Regenerate with `cd fuzz/seedgen && cargo run
--release`. Five, thirteen and five files respectively: seeds, not a saved
campaign.

Two boundary seeds are worth naming. `MAX_FIELD_LEN` (codec.rs:24) and
`MAX_SYNC_FRAME` (p2p.rs:278) are the same 8 MiB, so one codec field may legally
be as large as an entire sync frame. That edge is seeded as length *prefixes* at
cap and cap+1 (`envelope_len_prefix_{at,over}_cap`, 308 bytes each) rather than
as 8 MiB of payload: `Reader::bytes` tests `n > MAX_FIELD_LEN` on the decoded
u32 before it allocates, so both sides of the comparison are reachable cheaply,
and an 8 MiB seed would instead raise libFuzzer's inferred `-max_len` to 8 MiB
and collapse `exec/s` on every future run. Likewise
`resp_count_at_max_sync_blocks` sits at exactly `MAX_SYNC_BLOCKS` (128), the
largest count `decode_sync_response` accepts.

This crate is **not** part of the node build (not a path-dep of `bloch`); it is
its own workspace root (empty `[workspace]` table) so `cargo fuzz build` does not
walk up into the node workspace. Wire `cargo fuzz run` into CI/nightly on a
capable runner (see `oss-fuzz/`). New parsers of untrusted bytes should get a
target here.
