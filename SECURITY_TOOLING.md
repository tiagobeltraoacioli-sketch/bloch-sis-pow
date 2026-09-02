# Security Tooling — Bloch Protocol

> **Genesis-3-era document — sealed 2026-08-12, scope table corrected
> 2026-08-13.** Genesis-4 (proof of stake) went live on 2026-08-13 and
> Genesis-3 (proof of work) stopped at height 39,918; the ownerless thesis was
> retracted (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
>
> The scanner inventory and the tracked open-advisory set (hickory-proto,
> yamux GHSA-vxx9-2994-q338) are current and consensus-independent. The scope
> table below now names the live PoS crates; the PoW fuzz targets and the
> description of the EVM as an L2 scaffold are superseded
> (`docs/adr/ADR-040-evm-and-ustav-at-l1.md`).

*How the code is scanned, what each tool catches, what it cannot, and how to run everything locally. As of 2026-07-22. Unaudited by a third party — automated scanning + an internal adversarial audit reduce but do not remove risk; consensus logic and cryptographic parameter choices require human + external review.*

## Scope — two codebases, different threat models

| Layer | What | Where |
|---|---|---|
| **L1 core (Rust) — LIVE** | Genesis-4, **proof of stake**: slots and epochs, LMD-GHOST fork choice, Casper-style FFG finality, RANDAO beacon, staking, slashing rules that are written and unit-tested but **cannot be applied on the live chain** (evidence is undecodable on every ingress path — see the retraction on `Finality` in `crates/bloch-pos-node/src/rpc.rs`), SHA-3/SHAKE-256 state root, hybrid **ML-DSA-65 ‖ Falcon-1024** signatures on every consensus path (no BLS), libp2p networking. Consensus-critical infrastructure, not smart contracts. | `crates/bloch-pos-committee`, `crates/bloch-pos-node` |
| **L1 core (Rust) — CLOSED** | Genesis-3, **proof of work**: SHA-256d, AuxPoW merged mining, **GhostDAG** (blue_score) ordering, the **bloch-euvm** eUTXO contract VM. Stopped at height 39,918; scanned because Genesis-4's opening ledger is derived from it, not because it runs. | `legacy/genesis3-node`, `crates/bloch-euvm`, `crates/bloch-ffg` |
| **Shared crypto (Rust)** | Signature suite, addresses, hashing, the Module-SIS reference PoW puzzle. On the Genesis-4 consensus path via `bloch-crypto`; `bloch-sis-pow` is pulled in by it and is not a live consensus rule. | `crates/bloch-crypto`, `crates/bloch-sis-pow`, `crates/coherence-core` |
| **EVM / L2** | **Not deployed Solidity.** The L2 is a Rust **revm-based scaffold** (design-only, testnet/zero-value): `l2/bloch-l2-{evm,sequencer,prover,anchor,bridge}` in the **products repo** (`bloch-protocol`). Scanned as Rust; the Solidity toolchain is configured for *when* real contracts exist. | `bloch-protocol/l2/*` |

> **Correction to earlier design notes, twice over.** The first correction said the live chain was **SHA-256d** rather than the Module-SIS lattice PoW, and that **Casper FFG was dropped** in favour of PoW depth. Both statements were true of Genesis-3 and neither is true now: the live chain is Genesis-4, there is no proof of work in it at all, and finality is Casper-style FFG over an epoch committee — the gadget that was dropped came back as the whole finality mechanism. Read the crate, not this paragraph.

## L1 Rust scanners

| Tool | Catches | Cannot catch | Local run |
|---|---|---|---|
| **cargo-audit** | Known RustSec advisories in `Cargo.lock` (CVEs, DoS, unsound) | Logic bugs, novel vulns | `cargo audit` (see advisory posture below for the tracked `--ignore` set) |
| **cargo-deny** | Advisories + **license policy** (permissive only; AGPL allowed for the six first-party crates, copyleft denied for third-party deps) + banned/duplicate crates + untrusted registries | Same as audit for logic | `cargo deny check` |
| **osv-scanner** | Same `Cargo.lock`, but the **OSV.dev** DB (RustSec **+ GHSA**) — catches GHSA-only advisories cargo-audit's RustSec-only feed misses | Logic bugs, novel vulns | `osv-scanner --lockfile=Cargo.lock` (install: `go install github.com/google/osv-scanner/cmd/osv-scanner@latest`; needs network for the DB — supplementary, not a blocking CI gate) |
| **cargo-geiger** | `unsafe` usage across the dependency tree; flags increases | Whether the unsafe is *correct* | `cargo geiger` |
| **Clippy (hardened)** | Panics in consensus paths (`unwrap`/`expect`), arithmetic side-effects, pedantic smells. Covers the LIVE Genesis-4 crates (`bloch-pos-committee`, `bloch-pos-node`) and the closed Genesis-3 ones (`bloch`, `bloch-crypto`, `bloch-euvm`). A per-crate **ratchet**: baselines are recorded and the run fails when a count goes up | Semantic/consensus correctness | `./scripts/hardened-clippy.sh` (the script is the definition of the scope and the baselines; do not hand-roll the crate list) |
| **Miri** | Undefined behaviour in the consensus + serialization test suites | Anything not exercised by a test | `cargo +nightly miri test` (consensus/serialization crates) |
| **cargo-fuzz / libFuzzer** | Panics/UB/DoS on adversarial input to the P2P wire, PoW verifier, DAG ordering, signature parsing | Deep logic bugs, consensus splits | `cargo +nightly fuzz run <target>` (targets below) |
| **proptest** | Property invariants (deterministic ordering, blue-score monotonicity, emission conservation) | Invariants nobody wrote | `cargo test` (property tests run in-suite) |

**Fuzz targets** (`fuzz/fuzz_targets/`): `block_parse`, `netmsg_decode`, `handshake_decode`, `pow_decode`, `pow_verify`, `sha256d_pow`, `merkle_path`, `ghostdag_order`, `mempool_ops`, `sig_verify` — priority order: P2P deserialization (primary remote surface) → SHA-256d PoW verify → GhostDAG ordering → signature/attestation parsing. An **OSS-Fuzz** application (`fuzz/oss-fuzz/{project.yaml,build.sh,Dockerfile}`) reuses these so Google runs them continuously for free.

> **Every one of those targets is a Genesis-3 surface, and Genesis-3 has stopped.** The Genesis-4 node's parsers and P2P surfaces (`crates/bloch-pos-node`) have **no fuzz targets at all**. The live chain's remote attack surface is, today, unfuzzed. Writing that harness is the work that closes the gap; relabelling the existing targets would not.

### The hardened-clippy gate, measured (2026-08-13)

The `clippy-hardened` job is described in both pipelines as BLOCKING. Until 2026-08-13 its scope was Genesis-3 only: it had never linted `bloch-pos-committee`, the consensus producing blocks. Pointing it at the live crates also established that it could not have passed on the retired ones either. Counts at commit `8167ceb`, on the pinned toolchain:

| Crate | Findings | Era |
|---|---|---|
| `bloch` | 59 | Genesis-3 |
| `bloch-crypto` | 22 | shared; on the Genesis-4 signature path |
| `bloch-pos-node` | 27 | **Genesis-4, live** |
| `bloch-pos-committee` | 9 | **Genesis-4, live consensus** |
| `bloch-euvm` | 0 | Genesis-3 |

None of the nine in the live consensus crate is a reachable crash: each is a `try_into()` after a length-checked `take(n)`, a slice of a header whose length was validated first, or a `keys().next()` under `len() >= cap > 0`. They are hand-proofs where the lint wants a type-level guarantee, which is exactly why they stay counted. The job is now a **per-crate ratchet** — the recorded number may fall, never rise — rather than a pass/fail gate that was red on every commit and therefore read by nobody.

## EVM / L2 scanners (configured for future Solidity)

No Solidity is deployed yet (the L2 is a Rust revm scaffold). The Solidity toolchain — **Slither**, **Aderyn**, **Mythril**, **Echidna/Medusa**, **Foundry** (`forge test`/`coverage`), **Halmos**, **Semgrep**, **solhint** — is documented + config-scaffolded for when real contracts land. The L2 Rust crates are scanned with the same L1 Rust suite. See the bridge threat model for the highest-risk component.

## Advisory posture — the honest disposition

`cargo-audit` / `cargo-deny` are green with a **documented ignore set** (full rationale in `deny.toml` + `audit.toml`). Two classes:

1. **Unmaintained-notice** (no runtime vuln): the vendored `pqcrypto-*` PQ crates (PQClean archived — frozen under Cargo.lock by design), and SP1/zk host-side toolchain crates (backoff, ansi_term, instant, derivative, lru, …) that never touch the consensus/P2P runtime.

2. **⚠️ OPEN real vulnerabilities — tracked, not dismissed:**
   - **RUSTSEC-2026-0118** — hickory-proto NSEC3 closest-encloser proof: **unbounded loop (DoS)**.
   - **RUSTSEC-2026-0119** — hickory-proto **O(n²) name-compression CPU exhaustion (DoS)**.
   - **Why not fixed:** the fix is in hickory 0.26.x (DNSSEC code moved to `hickory-net`); **libp2p 0.56.0 pins hickory-proto 0.25.2** via `libp2p-dns` + `libp2p-mdns`. We cannot bump hickory without a libp2p release that repins it.
   - **Reachability / mitigation:** the DNS surface is `/dns4/` multiaddr resolution and LAN-only mDNS discovery. The node's canonical peering uses `/ip4/` addresses (no DNS resolution), and DNSSEC validation is not enabled — practical exposure is a self-inflicted malicious resolver or a hostile LAN.
   - **Action:** remove both `--ignore` entries the moment a libp2p release pins hickory ≥ 0.26.
   - **⚠️ GHSA-vxx9-2994-q338 — yamux 0.12.1 (CVSS 8.7):** stream-multiplexer DoS. Surfaced by **osv-scanner** (GHSA-only — cargo-audit's RustSec feed does not carry it). Same upstream block as hickory: `libp2p-yamux 0.47.0` (libp2p 0.56.0) pins yamux 0.12.1; the fix (yamux 0.13/0.14) is unreachable until libp2p repins. Reachability is any connected peer over the yamux muxer — **the most exposed of the open residuals**; noise/`/ip4/` peering does not mitigate it. **Action:** bump the moment libp2p repins yamux; until then this is an accepted-but-tracked P2P DoS risk.
   - **GHSA-vj64-rjf3-w3v7 — p3-challenger 0.2.2-succinct (CVSS 8.9)** and **GHSA-3g92-f9ch-qjcm — p3-symmetric (2.9):** plonky3 crates pinned by the SP1 4.2.1 prover stack — **host-side proof generation only, never the node consensus/P2P runtime.** Not bumpable without moving off pinned SP1. Tracked; low practical exposure.

   **Fixes applied this pass (real bumps, in-semver, staged in `Cargo.lock`):**
   - **`spin` 0.9.8 → 0.9.9** — 0.9.8 was **yanked** (would fail `cargo audit --deny warnings` and `deny yanked="deny"`).
   - **`rpassword` 7.4.0 → 7.5.4** — clears **GHSA-2p6r-x3vv-xqm2**; `rpassword` is a **direct** node dependency (CLI passphrase entry), so this is a first-party surface, not transitive.

## bloch-euvm — internally audited + remediated

The native eUTXO contract VM had a dedicated internal adversarial audit (`crates/bloch-euvm/audit/INTERNAL-AUDIT-2026-07.md`). Verdict: proceed to consensus-wiring engineering, **hard block on activation** until the blockers close. **0 critical** (the crate is inert/feature-off), **2 HIGH** integration blockers + **1 MEDIUM** — **all remediated**, each with a passing regression test:
- **F1** — the block commitment now binds `SparseMerkleTree::root()` over the eUTXO set (was a 36-byte scalar summary).
- **F2** — gas now scales with operand byte length + hard memory/size ceilings (was flat: an 8 MB hash cost the same as 1 byte).
- **F3** — checked arithmetic + `overflow-checks = true` mandated in `[profile.release]` (closes the release-wraps-vs-debug-panics validator split).
330 tests pass (debug **and** release parity). Kirpich (the Ustav charter-audit gate) adds 23 fail-closed KRP rules on top.

## What automated tooling CANNOT catch (needs human + third-party review)

- **Consensus logic** — GhostDAG ordering correctness, reorg-depth safety, the height-gated fork mechanics.
- **Cryptographic parameter choices** — the ML-DSA-65/Falcon-1024 hybrid construction, SHAKE-256 domain separation, the PoW difficulty regime.
- **The Rust↔EVM bridge** — the highest-risk component (message replay, cross-side signature verification, finality inheritance). See the bridge threat model.
- **Economic/game-theoretic** properties at low hashrate (the chain is 51%-attackable today).

**A third-party audit is required before any consensus activation of the native-contract features.** Automated scanning is a floor, not a ceiling.

---
*© 2026 Tiago Beltrão de Azevedo Tenório Acioli · licensed AGPL-3.0-or-later. Unaudited mainnet beta — BLCH is not a security and carries no value claim. This document reflects the real code, not aspiration.*
