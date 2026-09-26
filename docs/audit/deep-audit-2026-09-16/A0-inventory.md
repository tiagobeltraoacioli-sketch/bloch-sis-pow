# Annex A0 — Repository inventory and static metrics

*Deep audit of `tiagobeltraoacioli-sketch/bloch-sis-pow`, tree at commit `562e220` (2026-09-11), audited 2026-09-16.*

## A0.1 Workspace map (what is live, what is not)

| Area | Path | Role | Lines of Rust (src, excl. test dirs) | `#[test]` count | Live on Genesis-4? |
|---|---|---|---|---|---|
| Consensus core | `crates/bloch-pos-committee` | frozen PoS math (sha3 only dependency) | 38,719 | 613 | **yes — the consensus** |
| Node | `crates/bloch-pos-node` | the `bloch-pos` binary the fleet runs | 35,667 | 421 | **yes — mainnet binary** |
| Signatures | `crates/bloch-crypto` | hybrid ML-DSA-65 ‖ Falcon-1024, wallet, address, tx types | 11,470 | 175 | **yes — consensus path** |
| PQ FFI fork | `crates/pqcrypto-internals` | vendored pqcrypto-internals 0.2.11 + seeded-RNG override | 833 (+ C sources) | 16 | **yes — everything signs through it** |
| PoW reference | `crates/bloch-sis-pow` | Module-SIS gated SHAKE-256 hashcash | 3,915 | 81 | pulled by bloch-crypto (types), no PoW verified live |
| Shielded pool | `crates/coherence-core` | SHAKE-256 commitments/nullifiers | 859 | 13 | pulled by bloch-crypto; pool is empty |
| Genesis tool | `tools/genesis4-ceremony` | assembled the live genesis block | — | 28 | ran once |
| Vault | `crates/bloch-pq-vault` | BTC P2WSH commit-delay-reveal + PQ clawback | 1,778 | 22 | product, not consensus |
| Token kernel | `crates/bloch-ustav` | PQ-only native-token kernel | 860 | 5 | not wired |
| BTC wallet | `crates/bloch-btc-wallet` | — | 320 | 7 | product |
| yamux fork | `crates/libp2p-yamux` | removes yamux 0.12 backend (GHSA-vxx9-2994-q338) | 446 | 4 | only under `--transport libp2p` |
| Legacy PoW node | `legacy/genesis3-node` | the `bloch` binary, stopped at h39,918 | 41,234 | 865 | **no** — closed chain; source of the carried ledger |
| eUTXO VM | `crates/bloch-euvm` | Genesis-3 contract VM | 13,805 | 381 | **no** (feature-gated, never wired to G4) |
| FFG (G3) | `crates/bloch-ffg` | Genesis-3 finality committee | 652 | 13 | **no** |
| SP1 prover | `crates/coherence-prover` | excluded from workspace | 609 | 6 | no |
| Pool / proxy | `pool/`, `pool-proxy/` | Stratum mining pool + merged-mining proxy | own workspaces | — | idle (PoW ended) |
| Apps / SDKs | `apps/`, `sdk/`, `tools/{indexer,faucet}` | TS/Go/Python | — | — | web-facing products |

Total Rust in tree: 212,561 lines across 389 files. 2,449 tracked files. 876 packages in the root `Cargo.lock`, 0 git-sourced.

## A0.2 Build and toolchain

| Check | Result |
|---|---|
| `cargo check --workspace --all-targets` | **0 errors**, exit 0, 4m44s wall on 4 vCPU |
| Toolchain | rustc/cargo 1.94.1 — matches `crates/bloch-pos-node/rust-toolchain.toml` pin (`1.94.1`) |
| `overflow-checks` in `[profile.release]` | `true` (root `Cargo.toml`) — consensus-critical, present |
| `cargo audit` / `cargo deny` | not installed in this environment; policy files reviewed statically (Annex A10) |

Compiler warnings in the **live** crates (all `dead_code` / unused-import class — none affect behaviour, but each is an unreferenced symbol in a consensus binary):

| Crate | Warning | Location |
|---|---|---|
| bloch-pos-committee | unused import `consensus_invariant` | `src/lib.rs:108` |
| bloch-pos-committee | fn `subtree_root` never used | `src/state_root.rs:355` |
| bloch-pos-committee (tests) | unused doc comments, unused `AtomicBool`, `MockRpc` never constructed | `finality.rs:1977-1992`, `params.rs:530-786` |
| bloch-pos-node | `NO_TXS` never used | `engine.rs:199` |
| bloch-pos-node | fn `check_registry_identity` never used | `engine.rs:4390` |
| bloch-pos-node | method `ingest` never used | `engine.rs:2095` |
| bloch-pos-node | method `reason` never used | `engine.rs:1248` |
| bloch-pos-node | `VALIDATOR_EMISSION` never used | `genesis.rs:265` |
| bloch-pos-node | methods `bonds_are_fully_funded`, `pubkeys` never used | `genesis.rs:1126` |
| bloch-pos-node | fn `load_optional_with` never used | `keys.rs:550` |
| bloch-pos-node | method `tracked` never used | `p2p.rs:527` |
| bloch-pos-node | fn `new` never used | `rpc.rs:946` |
| bloch-pos-node | method `binding` never used | `slashprot.rs:280` |
| bloch-pos-node | fns `sync_body_bytes_read`, `sync_frames_scanned` never used | `store.rs:48,60` |

## A0.3 Consensus flag-day gates (`crates/bloch-pos-committee/src/params.rs`)

Mainnet epoch at audit time ≈ **3,065** (genesis 2026-08-13 21:31:19 UTC, 30 s slots, 32 slots/epoch). A gate at `u64::MAX` means the code ships in every binary but **no node applies the rule**.

| Constant | Value | State on mainnet |
|---|---|---|
| `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | 800 | bound |
| `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | 800 | bound |
| `LEAKED_ROSTER_ACTIVATION_EPOCH` | 1,400 | bound |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | 2,700 | bound since 2026-09-12 21:31 UTC (denominator-ratchet fix) |
| `ANCESTRY_SEED_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `DEPOSIT_ACTIVATION_EPOCH` | `u64::MAX` | **inert** — no new validator can deposit |
| `EXIT_AUTH_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `SLASHING_EVIDENCE_ACTIVATION_EPOCH` | `u64::MAX` | **inert** — equivocation is not punished on chain |
| `DUST_RULE_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `RANDAO_RECOMMIT_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `TX_BYTES_BOUND_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `ATTESTATION_DEDUP_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `REWARDS_V2_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `FORKCHOICE_EQUIVOCATION_HORIZON_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `STAKING_TX_METERING_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `WITHDRAWAL_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |
| `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` | `u64::MAX` | **inert** — transaction signatures not bound to the network id |
| `FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH` | `u64::MAX` | **inert** |

4 gates bound, **15 inert**. Every "fixed in code" claim for a rule behind an inert gate is a claim about a future flag day, not about blocks produced today.

## A0.4 Determinism and panic surface (static counts)

| Metric | Value | Note |
|---|---|---|
| Runtime dependencies of `bloch-pos-committee` | 1 (`sha3`) | verified in `Cargo.toml` |
| `HashMap`/`HashSet` in consensus non-test code | `forkchoice.rs` (latest messages, stake, equivocators, subtree weights), `state_root.rs` (singleton cache), `header.rs` (test-only) | reviewed in Annex A2/A4 for iteration-order dependence |
| Floating point in consensus non-test code | none (all `f64` uses are inside `#[cfg(test)]` reporting) | ok |
| Clock / RNG / env reads in consensus crate | none outside `perf.rs` (feature-gated instrumentation) and test timing | ok |
| `consensus_invariant!` call sites | 9 in `transition.rs`, 1 in `params.rs` | each must be unreachable from peer input (Annex A1/A2) |
| `unwrap()`/`expect()` in `transition.rs` (all, incl. tests) | 242 | classified in Annex A1 |
| `panic!/assert!/expect/unreachable` in node `engine.rs` (incl. tests) | 413 | classified in Annex A5 |
| Narrowing `as` casts in `transition.rs` non-test | 45 | reviewed in Annex A1 |
| `unsafe` in live crates | `keys.rs` (termios), `store.rs` (flock), `metrics.rs:615`, `main.rs` (`set_var`), `rpc/tests.rs`; `bloch-crypto` forbids unsafe | see Annexes A5–A8 |

Environment variables read by the node binary: `BLOCH_KEYSTORE_PASSPHRASE`, `BLOCH_KEYSTORE_PASSPHRASE_FILE`, `BLOCH_KEYSTORE_ALLOW_PLAINTEXT`, `BLOCH_NO_DOPPELGANGER`, `BLOCH_ALLOW_FINALITY_REWIND` (the last two are also set by CLI flags via `std::env::set_var` in `main.rs:1460-1465`).

## A0.5 Prior audits already in the tree (baseline this audit was diffed against)

`docs/audit/groundstate_audit.md`, `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`, `docs/audit/CERTIK-CENTRALIZATION.md`, `docs/audit/CERTIK-MARKET-TRANSPARENCY.md`, `docs/audit/AUDIT-2026-04-20_ERA1.md`, `docs/audit/VALIDATOR-ADMISSION-REVIEW-2026-09-08.md`, `docs/audit/VAD-04-LIFECYCLE-SOAK-2026-09-11.md`, `audit/CONSOLIDATED-SECURITY-REPORT.md` (2026-07-22, Genesis-3 era), `docs/specs/BLOCH-POS-GAPS.md`, `docs/post-mortems/2026-08-24-finality-divergence.md`, `docs/post-mortems/2026-04-21-ibd-reorg.md`.
