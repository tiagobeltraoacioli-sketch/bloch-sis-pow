# Mainnet Development Checklist

| Field | Value |
|---|---|
| **Status** | Working draft |
| **Date** | 2026-05-01 |
| **Author** | Founder (custodial) |
| **Scope** | Engineering work required before mainnet activation under founder custodial stewardship per ADR-023 Phase 1 |
| **Out of scope** | Foundation work (ADR-023, 024, 026), external audit (Phase 3), CEX listing |
| **Companion docs** | `docs/STRESS-TEST-PLAN.md`, `docs/INTERNAL-AUDIT-PLAN.md` |

---

## 1. Purpose

This document enumerates the engineering deliverables that must close before mainnet activation. It is not a roadmap (see `ROADMAP.md`); it is a state-of-the-build snapshot pinning what is implemented, what is partial, and what is unstarted as of 2026-05-01.

Mainnet activation per ADR-023 happens under temporary administrative custody by the founder, with no Foundation in legal existence and no CEX listing. The founder is therefore solely accountable for code quality at activation. External audit (Kudelski / NCC / Trail of Bits / Certik / Halborn) is contracted by the Foundation post-Phase-3, not pre-mainnet. Phase 1 miners accept residual risk that audit-driven corrections occur post-Foundation.

The corollary is that this checklist must be exhaustively closed before activation. There is no external audit to catch what we miss.

---

## 2. Status legend

- ✅ **Done** — implemented, tested, documented
- 🟡 **Partial** — implemented but with known gaps (CHECKMEs, missing tests, missing docs)
- ⬜ **Not started** — design exists or doesn't, no code

---

## 3. Consensus & cryptography

### 3.1 Core consensus

- ✅ GhostDAG-Q with blue/red scoring
- ✅ SHA-256d Proof of Work
- ✅ ML-DSA-65 (FIPS 204) transaction signatures
- ✅ Hybrid PoW+PoS architecture (FFG activates at block 210k per ADR-011)
- ⏳ Tokenomics 70/25/5 reward split — V1 (93/5/2) was implemented in commits `825e0a1`/`ac14295`; V2 spec locked in tag `v0.2.2-tokenomics-v2-spec` (ADR-028); code migration sequenced in `docs/MIGRATION-TOKENOMICS-V1-TO-V2.md` and lands in Sprint 2.1.D
- ✅ ADR-005 era + Phragmén committee rotation (integer NUM=40 / DEN=100, no float in consensus)
- ✅ Block time 150s, dual finality (soft 1 epoch / hard 2 epochs) per ADR-006
- ✅ Bonding contract + slashing 5%/equivocation, 40%/inactivity per ADR-007
- ✅ Halving with tail floor 25 BLOCH/block perpetual (ADR-010)
- ✅ Founder premine 17% / 30y linear vesting (ADR-010-A)

### 3.2 DKG (Distributed Key Generation)

- ✅ Sprint 2.1.C-rev1 closed, 10/10 Phase γ days complete (tag `v0.2.1.c-gamma-day10`)
- ✅ Pedersen VSS, Gennaro fork v0.9.0-bloch-1
- ✅ Lagrange reconstruction cross-validation (3 integration tests)
- ✅ RFC 9380 Appendix J vectors (14 integration tests, tag `v0.2.1.c-rfc9380-vectors`)
- ✅ Hash-to-curve BLS12-381 G1+G2 with BLOCH DSTs per ADR-022

### 3.3 Pending crypto work

- ⬜ ADR-028 — Sprint 2.1.C-rev1 closure document (separate commit, planned)
- ⬜ Post-quantum hybridization roadmap activation per ADR-020 (deferred until ML-DSA matures further in standards bodies)

---

## 4. Storage & networking

### 4.1 Storage

- ✅ RocksDB with column families
- ✅ Address history migration tool (`bloch-migrate-addr-history` binary)
- ⬜ M-2 hash-chain integrity check over persisted GhostDAG data (inherited audit finding, deferred to Sprint 12)
- ⬜ M-3 `MAX_REACHABILITY_DEPTH = 1024` silent cutoff (add `warn!` log when bound is hit; re-evaluate value)

### 4.2 Networking

- ✅ libp2p gossipsub for block + tx propagation
- ✅ axum RPC (JSON-RPC over HTTP, port 16210)
- ✅ Sprint A1/A2 transport, stream, upgrade tests passing
- ✅ ADR-021 transport layer continuity preserved through rebrand

### 4.3 Pending networking work

- ⬜ Two-node integration test harness (Sprint EE carryover) — in-process two-`NetworkNode` test that wires gossipsub transports together and asserts state convergence. Catches consensus bugs that current integration coverage misses.

---

## 5. Mining — Stratum V1

- ✅ Sprint AA.1 pt 1, 2a, 2b complete (TCP accept loop, session state machine, subscribe/authorize)
- ✅ Sprint AA.1 pt 3 integration done (CLI flags, accept_block callback, per-session template, tip detection)
- ✅ Bitcoin-format tx serialization + merkle branch
- ✅ Full submit pipeline → `accept_block` callback
- ✅ 9 integration tests in `tests/sprint_aa1_stratum_tx.rs`

### 5.1 Pending V1 work

- 🟡 `docs/operations/stratum.md` outdated — still labelled `v0.6.0-alpha2` with `v0.6.0-final` TBD. Limitations section lists items that are addressed. Needs rewrite reflecting current state.
- ⬜ Variable-difficulty share targets (Sprint AA.2 — pool mode) — out of mainnet activation scope; documented in `sprint-aa1-plan.md`
- ⬜ extranonce.subscribe support — currently silently accepted but not honored. Acceptable for short-running miners; not a mainnet blocker.

---

## 6. Mining — Stratum V2 (the gap)

This is the largest open work item before mainnet activation.

### 6.1 What's implemented

- ✅ Sprint 7 wire skeleton (commit `c20d889`)
- ✅ Sprint 8a — `cert.rs` Schnorr signatures (178 lines)
- ✅ Sprint 8b — `handshake.rs` NOISE_NX (111 lines)
- ✅ Sprint 8c — `setup_connection.rs` + `session.rs` initial state machine
- ✅ Sprint 8d — `main.rs` wiring (lines 1080–1141)
- ✅ Sprint 9 (Mining Protocol) implementation — `mining_job.rs`, `submit_shares.rs`, `submit_responses.rs`, `channel.rs`, `open_channel_*.rs` files all present (~1700 lines combined)
- ✅ Sprint 10-delta TemplateContext shared V1↔V2 (visible in main.rs L1118)
- ✅ Sprint 10-epsilon Phase 5.a `accept_block_cb` shared V1↔V2 (main.rs L1126)

Total: ~4,470 lines of SV2 code in `src/stratum_v2/`.

### 6.2 What's missing — CHECKMEs (BLOCKERS for ASIC interop)

Four `CHECKME` markers in code that must resolve before any real ASIC connects without misbehavior:

#### CHECKME-epsilon-version-rolling
- **Location:** `src/stratum_v2/session.rs:919`, `src/stratum_v2/block_reconstruct.rs:158–166`
- **Problem:** SV2 `SubmitSharesStandard` carries `version` for BIP-320 version rolling (AsicBoost). Code currently uses `template.version` unconditionally; the submitted `version` is ignored (`let _ = version;`).
- **Why blocker:** Antminer S19 / S21 stock firmware uses version rolling by default. Without this fix, every share from an Antminer is reconstructed against the wrong header version, fails PoW check, and gets rejected.
- **Fix scope:** ~50 LoC + 2 unit tests + 1 integration test. Need to decide: accept any version_mask (permissive), or negotiate via channel flags (spec-correct). The CHECKME comment says "ε.6+" — this is now ε.6.

#### CHECKME-epsilon-shares-sum
- **Location:** `src/stratum_v2/session.rs:820`, `:1000`
- **Problem:** `new_shares_sum` always passed as 0 in `SubmitSharesSuccess` response. Real downstream consumers (pool aggregators, share statistics) need cumulative count.
- **Why blocker:** Solo mining doesn't strictly need it (every share is a block submission). But Bitaxe and ASIC firmware both display "shares accepted" counters that pull from this field. Wrong value confuses operators.
- **Fix scope:** ~20 LoC. Track per-channel cumulative counter, increment on each successful submit, return in response.

#### CHECKME-4b-extranonce
- **Location:** `src/stratum_v2/session.rs:724`, `src/stratum_v2/channel.rs:45`
- **Problem:** Extranonce truncation strategy is fixed at 4 bytes. SV2 channels can negotiate larger extranonce_prefix sizes; we don't honor the negotiation.
- **Why blocker:** Standard channels typically use 8-byte extranonce. Truncating to 4 reduces the search space and increases extranonce2 exhaustion risk on high-hashrate ASICs.
- **Fix scope:** ~80 LoC. Honor `min_extranonce_size` and `max_extranonce_size` from `OpenStandardMiningChannel`. Update `channel.rs` to track per-channel extranonce_prefix length.

#### CHECKME-epsilon-multichannel-spk
- **Location:** `src/stratum_v2/session.rs:655`
- **Problem:** Solo mining edge case where one session opens multiple mining channels — each channel needs its own coinbase script_pubkey if the miner authorizes different addresses per channel.
- **Why blocker:** Lower priority. Standard ASIC firmware opens one channel per session. Becomes blocker if we want multi-worker SV2 support.
- **Fix scope:** ~40 LoC + test. Decide: support multi-channel multi-spk, or reject at OpenChannel time with explicit error.

### 6.3 Tests missing (BLOCKERS for confidence)

- ⬜ `tests/sprint_sv2_handshake.rs` — NOISE_NX handshake end-to-end (initiator + responder pair)
- ⬜ `tests/sprint_sv2_setup_connection.rs` — SetupConnection success + 4 error variants
- ⬜ `tests/sprint_sv2_mining.rs` — OpenChannel → NewMiningJob → SubmitSharesStandard → SubmitSharesSuccess full round-trip
- ⬜ `tests/sprint_sv2_block_acceptance.rs` — share that meets block target → accept_block call → broadcast
- ⬜ `tests/vectors/sv2/handshake_act1.bin`, `handshake_act2.bin`, `setup_connection_*.bin` — placeholder paths in GIP-0003 v0.3, files don't exist

Estimated effort: 12–16h focused work for the test suite plus CHECKME fixes combined.

### 6.4 Observability missing

- ⬜ Prometheus metrics for SV2: `sv2_sessions_total`, `sv2_sessions_active`, `sv2_handshake_duration_seconds`, `sv2_shares_submitted_total{result=ok|stale|low_diff|invalid}`, `sv2_blocks_found_total`, `sv2_certificate_validity_remaining_days`
- ⬜ Per-IP rate limit before NOISE handshake (DoS mitigation, mentioned in GIP-0003 §Security Considerations as Sprint 11 deliverable)
- ⬜ Operator alert when certificate validity window <48h (mentioned in GIP-0003)

### 6.5 Documentation missing

- ⬜ `docs/operations/stratum-v2.md` — operator guide (parallel to V1 stratum.md), how to enable, how to configure ASIC firmware, troubleshooting common errors, certificate management, key rotation procedure
- 🟡 `docs/gips/GIP-0003-stratum-v2.md` — currently v0.3 covering through Sprint 8 only. Sprint 9 (Mining) and Sprint 10 (TDP) marked TBD but code is implemented. Needs v0.4 update documenting what's actually implemented + Sprint 11 Interop scope.
- ⬜ Antminer S19/S21 quickstart card — single-page walkthrough for Bitmain stock firmware operator

### 6.6 Sprint 10-epsilon (V2 block acceptance — partially done)

Per ROADMAP.md "Carryover from pre-rebrand backlog":
- 🟡 PoW validation — present but with version rolling bug (CHECKME-epsilon-version-rolling)
- 🟡 Block reconstruction — present, needs verification against real ASIC traffic
- ✅ accept_block wiring — done (main.rs L1126)
- ⬜ `SubmitSharesSuccess` (0x1c) encoder — verify against SV2 spec wire format
- ⬜ `SubmitSharesError` (0x1d) encoder — verify against SV2 spec wire format

---

## 7. Compliance — Sprint 11 (gating mainnet per ROADMAP.md)

This entire sprint is unstarted. ROADMAP.md says mainnet does not launch until Sprint 11 lands.

- ⬜ **11.1 Entity structure** — BLOCH Labs Delaware C-Corp incorporation. Coordinate with US corporate counsel. Treasury vault custody, trademark holder, public-good infrastructure operator.
- ⬜ **11.2 Sanctions compliance smart contract** — On-chain blacklist/freeze/wipe primitives + sanctionsListRoot anchor (OFAC, UN, Interpol). Multi-sig + on-chain timelock. Sanctioned blocks do not finalize.
- ⬜ **11.3 KYC/KYB + KYP** — Miner identity attestation. Blocks proposed by un-attested miners enter chain but do not reach finality. KYP for template declarers (deferred to Sprint 14).
- ⬜ **11.4 AML monitoring + sovereign jurisdictional freeze** — Per-jurisdiction freeze without protocol consensus on underlying judgment.
- ⬜ **11.5 PCI DSS 4.0.1 + proof-of-reserves** — Operational security baseline + on-chain proof-of-reserves spec for treasury and oracle pool.

Each sub-sprint is consensus-touching work and requires its own GIP before implementation. No GIPs exist yet for any of these (current GIPs: GIP-0001 process, GIP-0002 stratum V1, GIP-0003 stratum V2).

Estimated effort: difficult to size without sub-sprint design work. Likely 200–400 person-hours of coding plus legal coordination.

---

## 8. Tooling, build, deploy

### 8.1 Build & CI

- ✅ Cargo workspace with 6 binaries (bloch, bloch-cli, bloch-wallet, bloch-mine-genesis, bloch-calibrate, bloch-migrate-addr-history, bloch-oracle)
- ✅ `cargo test` passes (excluding pre-existing `vuln05_coinbase_with_fees_fixed` flake)
- ✅ Dockerfile (multi-stage rust:1.94-slim-bookworm → debian:bookworm-slim)
- ⬜ Dockerfile updates: expose ports 3333 (SV1) + 3334 (SV2), add other binaries beyond `bloch` + `bloch-migrate-addr-history`, document volume mounts for SV2 keystores
- ⬜ docker-compose.yml for dev environment (node + Prometheus + Grafana)
- ⬜ Reproducible build verification (build twice from clean checkout, diff binaries)

### 8.2 CLI tooling

- ✅ bloch-cli — basic CLI present
- ✅ bloch-wallet — wallet operations
- ✅ bloch-mine-genesis — genesis block generation
- ✅ bloch-calibrate — difficulty calibration
- ✅ bloch-oracle — oracle node operation
- ✅ bloch-migrate-addr-history — address history migration
- ⬜ bloch-cli `stratum-v2-keygen` subcommand — generate authority + static keypairs for SV2 deployment
- ⬜ bloch-cli `health-check` subcommand — operator quick diagnostics (RPC reachable, peers connected, tip recent, mempool not stuck)

### 8.3 Pre-existing test failure to investigate

- 🟡 `security_tests::vuln05_coinbase_with_fees_fixed` fails in `cargo test --test security_audit`. Pre-existing, unrelated to DKG/FFG/SV2 work. Could be a flake or genuine regression. Must be investigated before mainnet — either fix or document as known issue with explanation.

---

## 9. Genesis configuration

- ⬜ `GENESIS_BITS` calibration based on expected initial hashrate (current placeholder `0x1d00ffff` is too easy if real hashrate is low)
  - Per `sprint-aa1-pt3-plan.md` §7, calibrate so target ≈ 2^256 / (hashrate × block_time)
  - For 30 Mhash/s seed + 60s blocks: target ≈ 2^225, bits exponent ~29
  - Re-derive precisely with measured seed hashrate before genesis mining
- ⬜ Genesis coinbase tag finalization — currently `bloch-stratum/v0.6` placeholder per AA.1 plan; choose final byte sequence
- ⬜ Founder premine address generation, ML-DSA-65 keystore stored 3-2-1 (server + Mac + pendrive APFS encrypted, per memory entry of 2026-04-26)
- ⬜ Treasury and oracle pool vault address generation, multi-sig setup
- ⬜ Genesis block ceremony — generate, sign, verify, publish

---

## 10. Documentation gaps (operator-facing)

- ⬜ `docs/operations/getting-started.md` — minimum viable node deployment
- ⬜ `docs/operations/stratum.md` — V1 operator guide refresh
- ⬜ `docs/operations/stratum-v2.md` — V2 operator guide (does not exist)
- ⬜ `docs/operations/observability.md` — Prometheus + Grafana setup, alert rules
- ⬜ `docs/operations/troubleshooting.md` — common failure modes, log signatures, recovery procedures
- ⬜ `docs/operator-quickstart.md` — single-page card for someone bringing up first node, target ≤30 minutes from binary download to live mining

---

## 11. Summary — work units before mainnet activation

| Work item | Estimated effort | Blocker? |
|---|---|---|
| 4× SV2 CHECKMEs | 8–12h | YES |
| SV2 integration test suite | 12–16h | YES |
| SV2 Prometheus metrics | 4–6h | NO (operator quality of life) |
| docs/operations/stratum-v2.md | 4h | YES (operator can't deploy without docs) |
| GIP-0003 v0.3 → v0.4 update | 3h | NO (docs hygiene) |
| Sprint 10-epsilon encoders verification | 4–6h | YES |
| Two-node integration harness (Sprint EE) | 8–10h | NO (carryover, post-mainnet OK) |
| Sprint 11.1 — BLOCH Labs incorporation | non-engineering | YES |
| Sprint 11.2 — Sanctions contract | 60–80h | YES |
| Sprint 11.3 — KYC/KYB + KYP | 40–60h | YES |
| Sprint 11.4 — AML + sovereign freeze | 40–60h | YES |
| Sprint 11.5 — PCI DSS + proof-of-reserves | 30–50h | YES |
| Stress test execution (per STRESS-TEST-PLAN.md) | 16–24h | YES |
| Internal audit (per INTERNAL-AUDIT-PLAN.md) | 24–40h | YES |
| Genesis configuration finalization | 8h | YES |
| Genesis block ceremony | 4h | YES |
| Investigate `vuln05_coinbase_with_fees_fixed` failure | 2–8h | YES |

**Total engineering effort: approximately 270–410 person-hours**, dominated by Sprint 11 sub-sprints. SV2 work is approximately 30–45 hours if no surprises.

At 6h/day focused output, that is 8–12 weeks of work for a single developer. With external counsel for Sprint 11.1 and 11.2 happening in parallel, calendar timeline 12–16 weeks is realistic, putting feasible mainnet activation in late Q3 2026 or Q4 2026 — not earlier.

---

## 12. Next actions

This week:
1. Order 2× Bitaxe Gamma 601 (per `BLOCH-ASIC-Hardware-Recommendation.pdf` §8.1)
2. Begin SV2 CHECKME work — start with `epsilon-version-rolling` since it blocks Antminer interop
3. Draft GIP-0004 outline for Sprint 11.2 Sanctions Contract — required design artifact before any sanctions code is written

Next 30 days:
4. Resolve all 4 SV2 CHECKMEs against real Bitaxe traffic
5. Write SV2 integration test suite
6. Update `docs/operations/stratum.md` and create `docs/operations/stratum-v2.md`
7. Update GIP-0003 to v0.4

Next 60 days:
8. Begin Sprint 11.1 corporate work in parallel with technical sprints
9. Begin Sprint 11.2 design (GIP first, code second)
10. Engage external counsel — US securities, EU MiCA (if EU exposure), Brazilian, Swiss/Singapore (per ADR-026 §6 Open questions)

---

## 13. Document control

- **Version:** 1.0 — initial draft
- **Last updated:** 2026-05-01
- **Update cadence:** Whenever a checkbox changes state
- **Owner:** Founder (custodial) until Phase 3, Foundation thereafter
- **License:** Same as repository
