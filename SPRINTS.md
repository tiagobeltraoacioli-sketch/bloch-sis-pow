# Bloch-SIS Protocol — Sprint History & Development Effort Log (Era 1: GroundState)

> **Historical — Era 1 and Genesis-3.** This is an effort log. The
> proof-of-work chain it documents stopped permanently at height **39,918**
> on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots,
> 32-slot epochs, finality by epoch), live since 21:31:19 UTC that day. Kept
> because Genesis-4's opening ledger is derived from Genesis-3, and because
> an effort log is a record. It is not what runs. The ownerless thesis was
> also retracted (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
>
> Parts I–III are an Era-1 effort record and stand as history. Part IV
> (remaining sprints) and Part VIII (the Stratum V2 sprint series) plan
> mining work that will not happen. Nothing in this file — hashrate figures,
> difficulty regimes, block times, supply allocations — describes the live
> network; for that, read [`README.md`](./README.md) and
> [`SECURITY.md`](./SECURITY.md).

**Repository (current):** `gitlab.com/Entanglementlayer/bloch-layer`  
**Repository (predecessor, Era 1):** `github.com/Groundstate100/groundstate` (suspended)
**Document version:** 2.1 · Effort-based edition
**Purpose:** Authoritative log of completed development work, broken down by sprint, with effort estimates (person-hours), lines-of-code touched, files modified, and technical scope. This document is a development-effort reference, not a transcript.
**Supersedes:** Prior `sprints.md` and `SPRINTS.md v2.0` (time-based).

---

## Project continuity note (April 2026 rebrand)

Sprints **S through 10-zeta** documented below were completed under the
**GroundState (GRND)** project name, on the chain that operated as
GroundState mainnet from Sprint 6 onward. In **April 2026** the codebase
was rebranded to **Bloch-SIS Protocol (BLOCH)** and the chain was reset
for genesis regeneration (Phase 6 of the rebrand). The codebase,
architecture, sprint history, and effort log are continuous; only the
project identity changed.

Where this document references **immutable artifacts of the GroundState
era** — Docker image tags such as `groundstate77/groundstate:v0.6.0`,
volume names such as `grnd-data-v0.5.13-snapshot-20260422`, deployed
URLs such as `scan.groundstate.network`, the audit document at
`docs/audit/AUDIT-2026-04-20.md`, or published filenames such as
`groundstate-whitepaper-v0.6.0.pdf` — those references are preserved
unchanged because they identify real historical artifacts, not the
current Bloch-SIS Protocol project.

Sprint numbering continues forward under Bloch-SIS Protocol starting at
**Sprint 11 — Compliance-First** (see [`ROADMAP.md`](./ROADMAP.md)).
Sprints in this document with letter suffixes (Sprint AA, Z, EE, FF) or
sub-letter suffixes (10-alpha through 10-zeta) belong to Era 1.

---

## How to read this document

Each sprint entry follows the same structure:

- **Scope** — the technical problem solved
- **Effort (est.)** — person-hours of equivalent senior-engineer work, including design, implementation, tests, code review cycles, debugging
- **Code delta** — approximate lines added/modified, files touched
- **Tests** — regression tests added, total passing after sprint
- **Why it mattered** — the consequence of not doing this work, or the capability unlocked
- **Status** — ✅ merged/deployed · 🚧 in progress · ⬜ planned

Effort estimates represent equivalent senior-engineer person-hours. They reflect the work-product value — design decisions, code production, test authorship, review iteration, and debugging — as if performed by a human engineer working independently.

---

## Executive summary

| Metric | Value |
|---|---:|
| Sprints completed (letter series) | 13 |
| Sprints completed (v0.6.0 series) | 6 |
| Sprints in flight | 2 |
| Sprints planned (roadmap) | 9 |
| **Total effort delivered in window** | **~529 person-hours** |
| Releases cut | 5 (v0.5.10 → v0.6.0) |
| Hard forks executed | 1 |
| Audit findings closed | 22 / 25 (88%) + 2 post-release |
| Test suite growth | 170 → 209 passing |
| Production deployments | 7 (5 node versions + 2 Akash config revisions) |
| Docker images published | 5 node images + 1 miner image |
| New binaries | 2 (`grnd-mine-genesis`, `grnd-wallet`) |

**Scope shift during window:** The codebase moved from a static-audit-remediated v0.5.x chain (custom 264-byte block header, CPU-only mining) to a v0.6.0 hard fork with a Bitcoin-compatible 80-byte wire format, enabling existing SHA-256 ASICs to mine without firmware changes, while retaining ML-DSA-65 for post-quantum transaction signatures.

---

## Part I · Audit remediation sprint series

Prior to this development window, an external audit of the GroundState codebase produced 25 findings across severity tiers (CRITICAL / HIGH / MEDIUM / LOW). The audit tracker lives at `docs/audit/AUDIT-2026-04-20.md`. The sprint series below systematically closed these findings.

### Sprint S · Audit quick-wins

- **Scope:** Low-risk surgical fixes for LOW-tier documentation and code-hygiene findings. Restored `Cargo.lock` commit (previously `.gitignore`d — a HIGH finding), clarified consensus comments, README cross-references to the audit doc.
- **Effort (est.):** **8 h**
- **Code delta:** ~80 LOC across 5 files (`Cargo.lock` restored, `README.md`, `src/consensus/ghostdag.rs`, 2 doc files)
- **Tests:** +2 regression (170 → 172)
- **Why it mattered:** Restoring `Cargo.lock` eliminated a reproducible-build gap that the audit flagged as HIGH; without this, Docker builds produced different binaries across days as dependency resolution drifted.
- **Status:** ✅

### Sprint T.1 · Seed-based ML-DSA-65 keygen

- **Scope:** Replace the library's internal RNG-keygen path with deterministic seed-based keygen, enabling wallet recovery from a 32-byte seed phrase. Required establishing a fork of `pqcrypto-internals` to expose the seed constructor not surfaced upstream.
- **Effort (est.):** **16 h** (majority in fork maintenance design — vendoring vs. forking, patch carry strategy, branch naming conventions)
- **Code delta:** ~150 LOC in new `src/crypto/seed_kdf.rs` + `Cargo.toml` pinning the fork via git dependency
- **Tests:** +1 deterministic-keygen regression (172 → 173)
- **Why it mattered:** Without deterministic keygen, users had no recovery path. A lost hardware device meant permanently lost funds. This is table-stakes wallet UX.
- **Status:** ✅

### Sprint T.2 – T.5 · Wallet hygiene

- **Scope:** Complete the wallet CLI: `generate`, `restore`, `inspect`, secure-delete operations. Argon2id key-derivation for keystore encryption. JSON keystore file format with version pinning for future migration.
- **Effort (est.):** **24 h** across four sub-sprints
- **Code delta:** ~450 LOC, primarily in `src/bin/grnd-wallet.rs` + new `src/wallet/keystore.rs` module
- **Tests:** +4 covering encrypt/decrypt round-trip, key-derivation determinism, argon2 parameters (173 → 177)
- **Why it mattered:** A reference wallet binary that a user can trust is the minimum viable cryptocurrency UX. Without it, the chain is unusable outside the test environment.
- **Status:** ✅

### Sprint U.1 – U.4 · UTXO reorg handling (CRITICAL finding C-1)

- **Scope:** The single highest-severity audit finding. Pre-Sprint-U, the reorg path did not correctly revert spent UTXOs when a competing branch became canonical — a consensus-level bug that would have produced chain state divergence between honest nodes during any non-trivial reorg. Architecture: per-block `UndoData` records in a new RocksDB column family `CF_UNDO`, replayed in reverse during rollback.
- **Effort (est.):** **60 h** across four sub-sprints (design 12 h, U.1 storage schema 12 h, U.2 rollback routine 14 h, U.3 reorg integration 14 h, U.4 accept-block integration 8 h)
- **Code delta:** ~800 LOC across `src/storage/rocks_db.rs` (+250 for CF definition, `put_undo_data`, `get_undo_data`, `delete_undo_data`, `rollback_block`), `src/consensus/ghostdag.rs::reorganize_to` (+180 logic rewrite), `src/core/mod.rs` (+120 for `UndoData` type), and `src/consensus/accept.rs` (+250 for UTXO-set tracking during block application)
- **Tests:** +6 covering single-block rollback, multi-block reorg, reorg to deeper fork, concurrent-mutation safety, undo-data-missing error path, and idempotency (177 → 183)
- **Why it mattered:** A reorg bug in a PoW chain is not "a bug" — it is "the chain forks silently and operators cannot agree on state." Closing this finding was a prerequisite to any public deployment.
- **Status:** ✅

### Sprint V.1 · Audit batch fix-up

- **Scope:** Seven findings in a single sprint: H-5 (input validation on RPC endpoint), M-9 (off-by-one in hash slicing), M-10 (unbounded vec allocation on malformed message), M-3 (missing timeout on handshake), L-1/L-3/L-5 (code-hygiene LOWs).
- **Effort (est.):** **20 h**
- **Code delta:** ~200 LOC across 9 files
- **Tests:** +4 (183 → 187)
- **Why it mattered:** Batch sprint to drain the backlog of small-to-medium findings in a single review cycle, rather than seven separate review cycles.
- **Status:** ✅

### Sprint W · Docs bundle (3 HIGHs)

- **Scope:** Three HIGH-severity findings that were documentation-only (audit flagged _missing documentation_, not missing code): genesis immutability specification, threat model publication, rewrite of address-format doc with reproducible test vectors.
- **Effort (est.):** **14 h** (mostly writing, with research on the exact threat model vocabulary)
- **Code delta:** ~0 code LOC, ~600 documentation lines (`docs/THREAT_MODEL.md` new, `docs/ADDRESS_FORMAT.md` rewritten, `docs/audit/AUDIT-2026-04-20.md` tracker updates)
- **Tests:** 0
- **Why it mattered:** An undocumented threat model means independent reviewers cannot assess whether the code meets its design goals. Closing these required writing the goals down.
- **Status:** ✅

### Sprint X · Async DNS (M-11)

- **Scope:** Convert `resolve_multiaddr` from synchronous to async. The synchronous version blocked the tokio runtime during DNS resolution — in pathological cases (slow recursor), this stalled block gossip for seconds at a time across the entire node.
- **Effort (est.):** **6 h**
- **Code delta:** ~50 LOC in `src/network/mod.rs` (line 129), 1 compile-time regression test
- **Tests:** +1 (187 → 188)
- **Why it mattered:** A single DNS lookup stalling the entire runtime is a latent DoS. Fixing it is a 50-line change; not fixing it is a production outage waiting for a slow recursor.
- **Status:** ✅

### Sprint BB · MerkleRoot newtype (L-2)

- **Scope:** Introduce `MerkleRoot([u8; 32])` newtype to prevent accidental mixups between three structurally identical `[u8; 32]` types in use: block hashes, transaction hashes, and merkle roots. Audit found at least two code paths passing these interchangeably.
- **Effort (est.):** **10 h** (mechanical but must touch every call site)
- **Code delta:** ~220 LOC across 14 files (mostly signature changes — `fn foo(h: [u8; 32])` → `fn foo(h: MerkleRoot)`)
- **Tests:** +1 compilation test (wrong type fails to compile) (188 → 189)
- **Why it mattered:** A type system that distinguishes semantically-different values prevents entire bug classes at compile time. The cost of retrofitting is one sprint; the cost of shipping a bug in this class would be hours of production debugging.
- **Status:** ✅

### Sprint CC · Post-release IBD bug (PR-1 / post-release finding)

- **Scope:** Discovered minutes after the v0.5.11 seed redeployment. The seed, at real height 2655, was broadcasting a stale `PeerTip { height: 1 }` to every new peer forever, because `NetworkNode::run` captured `our_blue_score` and `our_height` as value parameters at startup and baked them into a single `my_tip` message reused for the lifetime of the process. New peers saw height parity with the seed, never triggered IBD, and mined isolated chains.
- **Effort (est.):** **36 h** (bug discovery and root-cause analysis 10 h, refactor of `network::run` signature 12 h, three regression tests including the canary test 8 h, two fixup callsites found on second pass 6 h)
- **Code delta:** ~320 LOC across 3 files — commit `a1af484` (3 files, 299 insertions(+), 9 deletions(-)) + fixup commit `6bfd1d9` (1 file, 18 insertions(+), 4 deletions(-)). Primary change: `NetworkNode::run` takes `Arc<RwLock<GhostDAG>>` instead of two scalar values; new free function `build_current_tip` reads tip fresh on each call under a short read lock; new 60-second `tip_announce` tokio interval re-publishes tip to peers that connected before new blocks were accepted.
- **Tests:** +3 in `src/network/mod.rs::tests` — the canary `build_current_tip_reads_fresh_dag_state_each_call` advances the DAG mid-test and asserts the second tip read reflects the new state (189 → 192)
- **Why it mattered:** This bug was invisible to the original audit because it was a runtime multi-node bug. Every unit and integration test uses a single in-memory DAG; they never exercise a live PeerTip exchange between two nodes. Shipping this bug meant shipping a chain where Akash workers would never sync against the seed — the public network would have remained a one-node network indefinitely.
- **Status:** ✅

### Sprint DD · Reorg-from-genesis bug (PR-2 / post-release finding)

- **Scope:** After Sprint CC unblocked IBD, the worker started receiving blocks but every block was logged as `accepted into fork (not selected tip)`. Root cause: when IBD delivers blocks sequentially from genesis, each block triggers a reorg attempt from current tip (genesis) to new tip (h=1, then h=2, ...). The reorg code unconditionally calls `rollback_block` on the source tip before extending forward. Genesis has no undo data — it was never "applied", it is an immutable foundational fact — so rollback fails with `no undo data for block`, aborting the reorg and leaving `selected_tip` frozen at genesis.
- **Effort (est.):** **20 h** (diagnosis 6 h — requires reading production logs across two separate nodes — fix 10 h, tests 4 h)
- **Code delta:** ~90 LOC in `src/consensus/ghostdag.rs::reorganize_to` (genesis short-circuit branch)
- **Tests:** +2 — a five-block chain is built and the first reorg from genesis is asserted to complete; a separate test asserts that a reorg _not_ rooted at genesis still performs the rollback (regression guard for the special case) (192 → 194)
- **Why it mattered:** Second bug hiding behind the first. Without Sprint CC we would not have seen DD; without DD the worker would have synced but never caught up. Both required to unblock the mining network.
- **Status:** ✅

### Sprint Y · Integrity chain (M-2)

- **Scope:** Last of the three remaining MEDIUM findings. Adds a block-by-block integrity hash chain detecting silent storage corruption: each block's commitment is `blake3(prev_commit || block_hash)`, stored in a dedicated column family. An operator can run a scan that verifies every block's commitment matches its computed value.
- **Effort (est.):** **18 h**
- **Code delta:** ~250 LOC across `src/storage/rocks_db.rs` (new column family + API) and a new `src/bin/grnd-verify-integrity.rs` binary
- **Tests:** +3 (194 → 197)
- **Why it mattered:** RocksDB silent corruption is rare but not hypothetical. An on-disk corruption that matches block hashes but mutates other fields (e.g., flips a coinbase output) is catastrophic. The integrity chain makes this detectable in seconds.
- **Status:** ✅

### Sprint GG · Pre-IBD mining lockout

- **Scope:** The mining loop was running immediately on node startup, producing blocks against whatever tip existed locally (usually genesis) before IBD completed. Those blocks would be orphaned the instant real headers arrived from peers, wasting hashpower and polluting the block store.
- **Effort (est.):** **12 h**
- **Code delta:** ~70 LOC adding an `ibd_complete: AtomicBool` gate in `src/main.rs` and gating the miner task on it, plus its integration with the network IBD state machine
- **Tests:** +2 (197 → 199)
- **Why it mattered:** Without this gate, a worker joining the network would produce ~50 orphan blocks in its first 10 minutes — noise for peers and wasted energy for the operator. Resolved before v0.5.13 release.
- **Status:** ✅

---

**Part I subtotal: ~244 person-hours across 13 sprints. Audit scoreboard: 22/25 (88%) + 2 post-release findings closed. Test suite: 170 → 199 passing.**

---

## Part II · v0.6.0 hard fork sprint series

### Strategic context

After Sprint GG, the v0.5.x chain was stable but architecturally limited: its custom 264-byte block header (which carried ML-DSA-65 signature material inline) was incompatible with Bitcoin's Stratum V1 protocol and with existing SHA-256 ASIC firmware. Every SHA-256 ASIC in the world — billions of dollars of deployed hashing capacity — was inaccessible to the GroundState network.

The v0.6.0 hard fork migrates the block header wire format to Bitcoin's canonical 80-byte layout (version 4B + prev_block_hash 32B + merkle_root 32B + timestamp 4B + bits 4B + nonce 4B). ML-DSA-65 signatures are relocated to the transaction body, committed via the merkle root. Existing ASICs become compatible with zero firmware changes — only a pool endpoint change. This required a hard fork because pre-v0.6.0 blocks fail v0.6.0 validation rules.

### Sprint 1 · Bitcoin-format wire migration

- **Scope:** Replace the 264-byte header with an 80-byte `MiningHeader` across four code paths: block wire format, storage schema, network messages, transaction wire format.
- **Effort (est.):** **56 h** across four sub-slices (block wire 16 h, storage 12 h, network 14 h, transaction wire 14 h)
- **Code delta:** ~1,100 LOC across 11 files. Primary changes:
  - `src/core/block.rs` — new `MiningHeader` struct with exact Bitcoin byte layout, `pow_hash()` method computing `SHA-256(SHA-256(header_bytes))` Bitcoin-identical
  - `src/storage/rocks_db.rs` — serialization path updated for new header size
  - `src/network/mod.rs` — gossipsub `NewBlock` and `GetHeaders` schemas updated; protocol version bumped 1 → 2
  - `src/core/transaction.rs` — signature material moved from header to coinbase transaction, committed via merkle root
- **Tests:** +4 covering header serialization round-trip, pow_hash determinism against Bitcoin test vectors, mixed-version rejection, merkle-root commitment invariant (199 → 203)
- **Why it mattered:** This is the sprint that unlocked the entire ASIC mining ecosystem. Without it, GroundState competes with other alt-coins for CPU miners. With it, GroundState is the only post-quantum cryptocurrency that inherits Bitcoin's hashpower supply chain.
- **Status:** ✅

### Sprint 2 · Stratum V1 scaffolding

- **Scope:** Implement a standards-compliant Stratum V1 pool server inside the node, allowing external miners (cpuminer, bfgminer, ASIC firmware) to connect over TCP and submit shares.
- **Effort (est.):** **44 h** across sub-slices (2.a CLI flags & spawn 10 h, 2.b accept_block callback 18 h, 2.c bech32 authorization 10 h, session state machine 6 h)
- **Code delta:** ~850 LOC in new module `src/stratum/` with three files:
  - `mod.rs` — orchestration, listener task, session lifecycle
  - `session.rs` — per-connection state machine (subscribe → authorize → notify → submit)
  - `wire.rs` — JSON-RPC 1.0 message encoding/decoding
  - Plus `main.rs` additions for CLI flags `--stratum`, `--stratum-addr`, `--stratum-max-sessions`, `--stratum-coinbase-tag`
- **Tests:** +3 covering stratum message parsing, share target vs. block target validation, bech32 authorization with malformed inputs rejected (203 → 206)
- **Why it mattered:** Stratum V1 is the lingua franca of ASIC pools. Without an in-node Stratum V1 server, operators would have to run a separate pool software stack and figure out its integration themselves. Shipping this reduces miner onboarding from a multi-hour project to a one-line Docker command.
- **Status:** ✅

### Sprint 3 · Difficulty recalibration

- **Scope:** Compute the `GENESIS_BITS` constant targeting the initial hashrate envelope (single CPU, ~1 MH/s). Bits `0x1d21af9e` chosen after offline calibration simulations. Target block time confirmed at 10 seconds; retarget every 2016 blocks with ±4× clamp (Bitcoin-identical parameters).
- **Effort (est.):** **8 h** (the calibration itself is arithmetic, but validating it against expected-hashrate scenarios requires writing throwaway simulations)
- **Code delta:** ~40 LOC — new constants in `src/consensus/difficulty.rs` and one config table in `docs/parameters.md`
- **Tests:** +1 asserting that `GENESIS_BITS` decodes to the target difficulty (206 → 207)
- **Why it mattered:** Setting `GENESIS_BITS` too low means the chain stalls at launch because nobody can hit the target. Setting it too high means the chain immediately races through hundreds of blocks until the first retarget catches up, which looks broken to observers. Calibration has to be right on the first attempt because a hard fork is already being cut.
- **Status:** ✅

### Sprint 4 · Founder keypair generation

- **Scope:** Generate the founder ML-DSA-65 keypair holding the 5% genesis allocation (1,050,000 GRND). Keystore encrypted with argon2id-derived KEK. Founder address: `grnd1q473d5eda954fb0af025c926e8ead886cb86302b7952d5c2b`. Redundant backups to `~/Documents/grnd-backups/` and external storage.
- **Effort (est.):** **6 h** (the keygen is fast; the careful backup procedure takes most of the time)
- **Code delta:** ~0 production LOC (uses existing Sprint T.1 tooling)
- **Tests:** 0 (operational sprint, not a code sprint)
- **Why it mattered:** The founder key is cryptographically unique — if it is lost, the 5% allocation is permanently inaccessible and cannot be re-minted. The key ceremony has to be right on the first attempt.
- **Status:** ✅

### Sprint 5 · Genesis-mining tooling

- **Scope:** The `grnd-mine-genesis` binary. Given `--bits`, `--timestamp`, `--founder`, `--coinbase-text`, it searches for a nonce producing a block hash below target and writes the genesis block to disk. Used 2026-04-22 to produce the v0.6.0 genesis block with nonce `70242105` and hash `000000028f16c3710ba25825ad2cef2afcd30d806ca86b9e6a3d8ef0e95b2f67`.
- **Effort (est.):** **20 h**
- **Code delta:** ~320 LOC in new `src/bin/grnd-mine-genesis.rs` + shared genesis-construction logic in `src/core/genesis.rs`
- **Tests:** +2 asserting determinism (same inputs always produce the same nonce + hash) and PoW validity of the output (207 → 209)
- **Why it mattered:** A reproducible genesis is an audit requirement. Any third party must be able to take the published inputs and verify that our published nonce and block hash are the minimum valid values. Without this tool, "genesis is reproducible" is a claim; with it, it is a theorem.
- **Status:** ✅

### Sprint 6 · Reset runbook + mainnet launch

- **Scope:** Coordinated chain reset. Genesis mined with Sprint 5 tool; source patched with concrete genesis constants; Docker images built (`groundstate77/groundstate:v0.6.0` digest `sha256:fcc7172789950a40429f704e7eae536cab1a18d2141177f45ecec572141b63df`, 34 MB runtime; `groundstate77/cpuminer-multi:latest` digest `sha256:abd22c1c35a76d9bcf8f643bca1a64c6ea4671bb8b1ce1cbc388b86f4bf1f985`); old chain volume preserved as rollback path (`grnd-data-v0.5.13-snapshot-20260422`); seed redeployed with `--metrics --metrics-public --rpc-bind 0.0.0.0 --stratum`; UFW port 3333 opened; Prometheus connected to monitoring network.
- **Effort (est.):** **32 h** (most of it in the Docker build troubleshooting for the miner image — zlib1g missing from build stage causing `-lz` linker errors, multi-stage Debian bookworm adjustments)
- **Code delta:** ~60 LOC in patches to `Cargo.toml`, `Dockerfile`, `Dockerfile.cpuminer`, plus the concrete genesis constants
- **Tests:** +0 direct code tests; launch validated by chain progression to height 14+ within minutes of deployment, with founder balance and treasury accumulation confirmed via RPC
- **Why it mattered:** A hard fork that fails at launch is a hard fork that does not happen. Every detail — RPC binding, metrics exposure, stratum authentication format (bech32 address only, no worker tag), volume naming — has to be right before the first block is mined. Operational sprint with zero margin for error.
- **Status:** ✅

---

**Part II subtotal: ~166 person-hours across 6 sprints. One hard fork cleanly executed. Test suite: 199 → 209 passing.**

---

## Part III · Launch assets (publication work)

Work product that is not code but was necessary for the v0.6.0 launch to be credible to the outside world.

### Whitepaper (v0.6.0)

- **Scope:** 16-page technical document covering abstract, design philosophy, protocol specification (§3.1–3.5), economic model (§4), network architecture (§5), security analysis (§6), reproducible genesis (§7), roadmap (§8), references, appendices. Published as `docs/whitepaper/groundstate-whitepaper-v0.6.0.{md,pdf}` (~85 KB PDF).
- **Effort (est.):** **30 h** (research + writing + typography + review cycles)
- **Code delta:** ~0 code; ~2,400 words of technical prose; EB Garamond serif body + Inter headings + JetBrains Mono code

### Apex site update

- **Scope:** `groundstate.network` homepage migrated from v0.5.14-sprintr to v0.6.0. New hard-fork callout above the existing milestone; new fourth pillar `00 · PROOF OF WORK · 80-byte header`; Unique Position claim box; dual-pane Mine/Run-a-Node section with `groundstate77/cpuminer-multi` integration; updated genesis hash in footer; whitepaper links in nav/hero/footer; RPC script updated for v0.6.0 methods.
- **Effort (est.):** **14 h** (design-system preservation required careful extraction of the existing tokens — Fraunces serif, Bitcoin orange `#f7931a`, italic-orange emphasis pattern — before making any structural edits)
- **Code delta:** ~370 LOC of HTML/CSS/JS added to `apex/index.html`; zero existing design tokens changed

### Shared design tokens

- **Scope:** `grnd-tokens.css` — standalone stylesheet with all CSS variables (colors, fonts, spacing), component classes (`.grnd-nav`, `.grnd-callout`, `.grnd-eyebrow`, `.grnd-btn`, `.grnd-code`, `.grnd-led`, `.grnd-table`) intended for cross-site import. Enables unified visual identity across apex, scan, and docs sites without duplicating token definitions.
- **Effort (est.):** **8 h**
- **Code delta:** ~340 LOC of CSS in one file

### Scan overview dashboard

- **Scope:** `scan.groundstate.network/overview.html` — live chain dashboard with hashrate hero panel, halving countdown with progress bar and ETA, block-time percentiles (min/p50/target/p90/p99), treasury balance with UTXO count, supply distribution tier chart (all 8 tiers), circulating supply with % of cap, genesis info tiles. All data via node JSON-RPC (`getblockcount`, `getchainstats`, `gettreasury`, `getsupplydistribution`, `getblocktimepercentiles`). 15-second auto-refresh.
- **Effort (est.):** **18 h**
- **Code delta:** ~720 LOC HTML/CSS/JS in one standalone page

### Recent blocks live feed

- **Scope:** `scan.groundstate.network/blocks.html` — paginated live table (20/50/100 block windows). Columns: height, age (ticking every 1s), UTC time, hash with link, tx count, block size. New-block animation (orange flash + fade). Live/paused toggle with green LED. Row click navigates to `/block/<hash>`. Coinbase-only badge for blocks with single transaction.
- **Effort (est.):** **16 h**
- **Code delta:** ~680 LOC HTML/CSS/JS in one standalone page

---

**Part III subtotal: ~86 person-hours across 5 deliverables.**

---

## Part IV · Roadmap — remaining sprints

### Near-term (v0.7 – v0.9)

#### Stratum V2 migration ⬜

- **Scope:** Migrate from Stratum V1 (currently deployed) to Stratum V2 (BIP 301 / SRI). Binary framing instead of JSON-over-TCP; NOISE_NX encryption handshake; three SV2 sub-protocols (Mining, Template Distribution, Job Distribution/Negotiation); parallel listener on port 3334 alongside the existing V1 listener on 3333 for backward compatibility.
- **Effort (est.):** **120 h** across 4–6 sprints (binary framing 30 h, NOISE encryption 25 h, three sub-protocols 50 h, integration tests against SRI vectors 15 h)
- **Why it matters:** V1 has no authentication of pool → worker job messages (malicious pool can steal work), higher bandwidth than necessary, no native merged-mining support, no job-selection-by-miner. A post-quantum Bitcoin alternative should ship with the best mining protocol available.

#### Pruned nodes ⬜

- **Scope:** Bitcoin-style block pruning. Retain UTXO set + rolling window of recent blocks (e.g., last 10,000); discard archival block bodies. Reduces non-archival full-node disk footprint from ~12 GB/year to under 5 GB steady-state. Protocol-level signaling so other nodes don't request archival data from pruned nodes.
- **Effort (est.):** **50 h** across 2 sprints (storage refactor 30 h, network signaling 20 h)
- **Why it matters:** ML-DSA-65 signatures are ~3.3 KB each. Without pruning, disk growth is dominated by transaction signatures, making full-node operation progressively more expensive.

#### SPV proof compaction ⬜

- **Scope:** Sparse Merkle tree with blake3 commitments in a new column family. O(log n) inclusion proofs for mobile / browser light clients instead of full header-chain fetches.
- **Effort (est.):** **70 h** across 3 sprints (spec 15 h, implementation 40 h, proof-verification test suite 15 h)
- **Why it matters:** Light clients are the path to consumer-grade wallets. Without compact proofs, every mobile wallet must sync O(n) headers.

#### Difficulty adjustment smoothing (ASERT / LWMA) ⬜

- **Scope:** Replace the 2016-block ±4× retarget with a moving-window DAA (ASERT or LWMA). With 10-second blocks, the current retarget window is ~5.6 hours — short enough that a moving-window DAA becomes feasible without sacrificing stability and eliminates the "timewarp"-style attacks that affect Bitcoin's DAA.
- **Effort (est.):** **40 h** across 2 sprints (implementation 20 h, testnet validation 20 h)
- **Why it matters:** At 10-second blocks, hashrate volatility produces visible oscillation in the current DAA. A moving window produces stable confirmation times for users.

#### CSIP-014 · Zero-knowledge rollup L2 ⬜

- **Scope:** ZK rollup layer 2 for high-frequency transactions (micro-payments, inter-exchange settlement). Candidate proof system: PLONK with BLS12-381 pairings (classical-secure, though not itself post-quantum).
- **Effort (est.):** **280 h** across 6–10 sprints. Largest single item on the roadmap; will likely span multiple hard forks.
- **Why it matters:** L1 throughput with ML-DSA-65 signatures tops out around 100 TPS per 4 MB block. High-frequency use cases need L2.

### Medium-term (v1.0)

#### Treasury decentralization ⬜

- **Scope:** Replace the multisig treasury with a governance contract; vote weight proportional to stake-age-weighted UTXO holdings. The 2% on-chain tax remains; what changes is who can authorize spending.
- **Effort (est.):** **80 h**

#### Adaptive block size ⬜

- **Scope:** Miner-voted block size within hard bounds (4 MB min, 32 MB max) via coinbase-transaction signals.
- **Effort (est.):** **40 h**

#### Soft-fork versioning framework ⬜

- **Scope:** Bitcoin BIP9 / BIP341-style deployment mechanism using block-version-field signals. Framework for future non-hard-fork upgrades.
- **Effort (est.):** **60 h**

### Long-term research (v2.0+)

#### Post-post-quantum signature scheme research ⬜

- **Scope:** ML-DSA-65 is our current PQ signature choice (NIST FIPS 204). If FIPS 204 is deprecated (structural weakness in Module-LWE), we need a replacement: candidates are SLH-DSA (FIPS 205, stateless hash-based, much larger signatures) or a future lattice scheme. This is research, not engineering.
- **Effort (est.):** **200 h+** (research and spec work, pre-implementation)

#### Accumulator-based UTXO commitments ⬜

- **Scope:** Replace the rolling UTXO set with a cryptographic accumulator (Utreexo adapted for post-quantum). Reduces full-node storage to O(log |UTXO|); transactions carry inclusion proofs.
- **Effort (est.):** **150 h**

#### STARK-based SPV ⬜

- **Scope:** Replace Merkle inclusion proofs with STARKs. O(log n) proofs without trusted setup, compatible with post-quantum assumptions. Requires FRI-based polynomial commitment scheme.
- **Effort (est.):** **200 h**

---

**Part IV subtotal: ~1,290 person-hours of planned work across 9 roadmap items.**

---

## Part V · Open operational items

Tracked here because they are owed for completeness, not as code sprints:

| Item | Effort (est.) | Status |
|---|---:|---|
| Akash workers v0.6.0 SDL redeploy | 4 h | 🚧 |
| GitHub release v0.6.0 tag + notes | 3 h | ⬜ |
| `README.md` sync to v0.6.0 | 2 h | ⬜ |
| `docs.groundstate.network` v0.6.0 theming | 8 h | ⬜ |
| `scan.groundstate.network` Next.js unification with tokens | 16 h | ⬜ |

**Operational subtotal: ~33 person-hours.**

---

## Part VI · Testing baseline

| Milestone | Unit tests passing | Delta |
|---|---:|---:|
| Pre-window baseline | 170 | — |
| Post-Sprint S | 172 | +2 |
| Post-Sprint T.1 – T.5 | 177 | +5 |
| Post-Sprint U.1 – U.4 | 183 | +6 |
| Post-Sprint V.1 | 187 | +4 |
| Post-Sprint X | 188 | +1 |
| Post-Sprint BB | 189 | +1 |
| Post-Sprint CC | 192 | +3 |
| Post-Sprint DD | 194 | +2 |
| Post-Sprint Y | 197 | +3 |
| Post-Sprint GG | 199 | +2 |
| Post-Sprint 1 (Bitcoin wire) | 203 | +4 |
| Post-Sprint 2 (Stratum V1) | 206 | +3 |
| Post-Sprint 3 | 207 | +1 |
| Post-Sprint 5 | 209 | +2 |
| **Post-v0.6.0 launch** | **209** | (+39 cumulative) |
| Post-Sprint 10-delta (V2 per-channel jobs) | 222 | +13 (post-v0.6.0 cumulative) |

All run via `cargo test --lib` on `main`. Integration tests in `tests/` add ~30 additional; coverage was not measured quantitatively during the window. A future operational sprint should add `cargo-llvm-cov` to CI.

---

## Part VII · Notable commits

High-value commits preserved for bisection reference:

| Commit | Sprint | Delta | Notes |
|---|---|---|---|
| `a1af484` | CC | 3 files, +299 / -9 | Dynamic tip refresh; the commit that unblocked public mining |
| `6bfd1d9` | CC fixup | 1 file, +18 / -4 | Version handshake + heartbeat log use fresh DAG state |
| `cbc6994` | Pre-CC | n/a | Last known-bad revision; useful bisection anchor |
| `d9995fa` | S | Dockerfile + `.gitignore` | Reproducible builds restored |
| `5227a2b` | v0.5.11 ops | deploy/ | First Akash worker SDL |

v0.6.0 sprint commit series (Sprints 1–6) is approximately 20 commits in `main` history, to be referenced by the `v0.6.0` git tag once created.

---

---

## Part VIII · Stratum V2 sprint series (post-v0.6.0)

Stratum V2 implementation as a parallel listener on port 3334, coexisting with Stratum V1 on port 3333. Uses SRI umbrella crate `stratum-core` (re-exports `binary_sv2`, `codec_sv2`, `noise_sv2`, `mining_sv2`, `template_distribution_sv2`). Each V2 session holds its own `NoiseCodec` after NOISE_NX handshake completion; there is no central session registry unlike V1, so per-session state is truly independent.

> **Backfill note.** Sprints 7 through 10-gamma are present in commit history (`git log --grep="Sprint [7-9]"` and `git log --grep="Sprint 10-"`) but have not yet been expanded into full SPRINTS.md entries. A documentation sprint to backfill effort estimates and scope is tracked as **CHECKME-doc-v2-foundation**. The entry below covers Sprint 10-delta in full; earlier V2 sprints are summarized only.

### Sprints 7 through 10-gamma (summary)

- **Sprint 7:** wire skeleton — empty listener binds port 3334 and drops connections
- **Sprint 8 (c/d sub-variants):** NOISE_NX handshake end-to-end, authority keypair persistence, handshake timeout (`4ecf340`)
- **Sprint 9 (alpha/beta/gamma):** SetupConnection decode via SRI `codec_sv2`, policy evaluation against `KNOWN_FLAG_MASK`, SetupConnectionSuccess/Error encode plus encrypted write (`b90ba58`, `6868f79`, `d4bf7cd`)
- **Sprint 10-alpha (`4ecf340`):** wire SV2 listener into `main.rs` runtime
- **Sprint 10-beta (`83db9b2`):** `OpenStandardMiningChannel` dispatch, `ChannelRegistry`, `derive_extranonce_prefix`, `OpenStandardMiningChannelSuccess` wire encode
- **Sprint 10-gamma (`3c0d1f7`):** job broadcasting infrastructure. `NewMiningJob` (0x15) and `MiningSetNewPrevHash` (0x20) encoders. `SubmitSharesStandard` (0x1a) decoder. `tip_rx` and `node_ctx` plumbed as `_`-prefixed parameters in `drive_session_io`. Tests went 55 to 70 in `stratum_v2::*`.

### Sprint 10-delta · Template adapter + per-channel NewMiningJob push

- **Scope:** Wire V2 sessions to push NewMiningJob on every TipChanged and route SubmitSharesStandard back to the session. The Phase-2 post-setup loop in `drive_session_io` is converted from a blocking `timeout(read)` into a `tokio::select!` multiplexing socket reads and tip events. Work split into five phases:
  - **Phase 1 (`fa319e4`)** — node_ctx plumbing. `Option<Arc<TemplateContext>>` threaded `main.rs` -> `Sv2Config` -> `listener::run` -> `Sv2Session::new` -> `drive_session_io`. Each session gets its own `Arc` clone of the V1/V2-shared DAG/store/mempool handle. Runtime no-op; consumption arrives in Phase 4.
  - **Phase 2 (`6ce4fc7`)** — new `src/stratum_v2/template_adapter.rs`. Two pure-library functions: `compute_merkle_root_for_channel(template, extranonce_prefix) -> [u8; 32]` is the choke point for the byte-identical-header invariant (V2 root must match V1 root or shares get rejected by `accept_block`); `build_template_for_sv2(tip, ctx, miner_spk, job_id) -> Result<Template>` deliberately diverges from V1 by reading `tip.parents` from the event rather than re-reading `d.tips()` — V2 cannot centralize dispatch the way V1 `SessionRegistry` does, so per-session DAG reads would produce N-way lock contention.
  - **Phase 3** — verified no-op. `ChannelState.extranonce_prefix`, `ChannelRegistry`, `derive_extranonce_prefix`, and `OpenStandardMiningChannelSuccess` wire encoding were already implemented in Sprint 10-beta. No commit.
  - **Phase 4a (`7bf805c`)** — `tokio::select!` skeleton. Two arms: socket read with idle timeout, and `TipChanged` recv. `tip_rx` is `Option<Receiver>`; `None` disables the arm via `std::future::pending()` (idiomatic select disable). On `RecvError::Closed`, `tip_rx` is set to `None` so subsequent iterations fall through rather than spinning on a permanently-closed channel.
  - **Phase 4b (`ad6ab5e`)** — real push. On each tip event, build Template once, iterate `ChannelRegistry`, compute per-channel merkle_root via the Phase 2 adapter, allocate fresh `job_id` from monotonic session counter, encode NewMiningJob (0x15), encrypt via `NoiseCodec`, write to socket. `ChannelState.last_job_id` updated for Phase 4c match. Two CHECKMEs: `CHECKME-4b-spk` (placeholder `miner_spk` via SHA-256 of session tag; real bech32 parsing from `user_identity` is Epsilon) and `CHECKME-4b-extranonce` (8-byte pad/truncate of up-to-32-byte prefix; revisit when SV2 channels negotiate full-length extranonces distinct from V1).
  - **Phase 4c (`6ed2eca`)** — SubmitSharesStandard (0x1a) dispatch. Pure-function `validate_share_against_channel` returns `Accepted { job_id }`, `UnknownChannel`, or `StaleJob { channel_last, submitted }`. No PoW check, no wire response — both deferred to Epsilon.

- **Effort (est.):** **6 h** across five phases (P1 ~1 h, P2 ~1.5 h, P3 ~0.25 h verify, P4a ~1 h, P4b ~1.5 h, P4c ~0.75 h)
- **Code delta:** ~560 insertions / ~44 deletions across 8 files — `src/stratum_v2/{session.rs, template_adapter.rs (new), listener.rs, mod.rs, config.rs}`, `src/stratum_v2/tests/session_tests.rs`, `src/stratum/mod.rs`, `src/main.rs`
- **Tests:** +7 covering merkle root (3 golden round-trip vs V1-style computation) and share validation (4 cases: accept, unknown channel, stale job, no-last-job). `stratum_v2::*` went 70 -> 77.
- **Why it mattered:** Before 10-delta, V2 miners connecting to port 3334 after completing NOISE handshake sat idle forever — no work was ever pushed. After 10-delta, every TipChanged produces a fresh NewMiningJob per channel, and submitted shares route back to the originating job. All framing, routing, and crypto wire are in place. The only remaining gap for end-to-end block acceptance is PoW validation + `accept_block` wiring — Sprint 10-epsilon.
- **Out of scope (Epsilon):** PoW validation (reconstruct 80-byte header from job merkle_root plus submitted `(version, ntime, nonce)`, double-SHA256, compare against share and block targets); block reconstruction; `accept_block` callback threading; SubmitSharesSuccess (0x1c) / SubmitSharesError (0x1d) wire responses; real `miner_spk` derivation from `user_identity`.
- **Status:** ✅ merged to `main`, not yet deployed. Deployment planned on Sprint 10-epsilon completion as `v0.7.0-alpha.2`.

---

## Effort totals

| Category | Person-hours |
|---|---:|
| Part I — Audit remediation (13 sprints) | 244 |
| Part II — v0.6.0 hard fork (6 sprints) | 166 |
| Part III — Launch assets (5 deliverables) | 86 |
| Part V — Open operational (5 items) | 33 |
| **Delivered in window (subtotal)** | **529** |
| Part IV — Roadmap planned (9 items) | 1,290 |
| **Roadmap total (planned + delivered)** | **1,819** |

---

*Effort figures are senior-engineer person-hours, independent of calendar time or wall-clock session length. Figures are estimates reflecting the cost of producing equivalent work-product under normal human engineering conditions — design + implementation + tests + review iteration + debugging.*
