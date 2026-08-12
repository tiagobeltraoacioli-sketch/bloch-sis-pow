# Stress Test Plan — Pre-Mainnet Validation

| Field | Value |
|---|---|
| **Status** | Working draft |
| **Date** | 2026-05-01 |
| **Author** | Founder (custodial) |
| **Scope** | Stress test execution before mainnet activation |
| **Position in lifecycle** | Phase 0 → Phase 1 transition; runs after `MAINNET-DEV-CHECKLIST.md` items close, before `INTERNAL-AUDIT-PLAN.md` execution |
| **Companion docs** | `legacy/MAINNET-DEV-CHECKLIST.md`, `legacy/INTERNAL-AUDIT-PLAN.md` |

---

## 1. Purpose

Stress testing exists to find failure modes that unit tests and integration tests cannot. Specifically:

- Behavior under load that exceeds typical operating ranges
- Interaction between subsystems under contention
- Resource exhaustion paths (memory, file descriptors, network buffers, RocksDB write amplification)
- Recovery behavior when the node is killed mid-write, mid-handshake, mid-DKG ceremony
- Adversarial behavior from peers and miners

The goal is not to prove correctness — that is what `INTERNAL-AUDIT-PLAN.md` does. The goal is to **provoke failure** under controlled conditions so we can fix what breaks before real users hit it.

If this plan executes and zero issues are found, the plan is wrong. The plan is right when it surfaces 5–20 actionable findings.

---

## 2. Scope and exclusions

**In scope:**
- Consensus engine (GhostDAG-Q, FFG)
- Storage (RocksDB)
- P2P networking (libp2p gossipsub)
- RPC (axum)
- Stratum V1 (port 3333)
- Stratum V2 (port 3334)
- DKG ceremony resilience
- Mempool behavior under load

**Out of scope:**
- External cryptographic primitives (BLS12-381, ML-DSA-65, SHA-256d) — already covered by RFC 9380 vectors and FIPS 204 reference. Not stress-tested directly; trusted via primitive correctness.
- Sprint 11 compliance contracts — those are unstarted; will require their own stress test plan when they exist.
- Real ASIC hardware — physical hardware cannot be reliably stress-tested by us. We trust Bitmain / Bitaxe quality and validate via integration testing only.

---

## 3. Test environment

### 3.1 Hardware

Stress testing requires multiple machines simulating a network. Minimum setup:

| Role | Specs | Count |
|---|---|---|
| Node-under-test | 16 GB RAM, 8 cores, NVMe SSD, 1 Gbps net | 1 |
| Peer simulator | 8 GB RAM, 4 cores, SSD | 3 |
| Miner simulator (CPU mining) | 4 GB RAM, 4 cores | 5 |
| Adversary node | 8 GB RAM, 4 cores | 1 |
| Real Bitaxe Gamma 601 | — | 1–2 (per `BLOCH-ASIC-Hardware-Recommendation.pdf`) |

Cloud equivalent: AWS or Hetzner, ~USD 200 for a 1-week test campaign.

### 3.2 Software

- `bloch` binary built from `cargo build --release` of the latest pre-mainnet branch
- Custom load-generation harness (Rust or Python) for scenarios that can't be expressed as standalone binaries
- Prometheus + Grafana for time-series capture during runs
- Wireshark / tcpdump captures of stratum and P2P traffic
- `flamegraph` and `tokio-console` for performance profiling

### 3.3 Network setup

- All test machines on a private VLAN to avoid leaking testnet traffic to public internet
- Synthetic latency injection via `tc` (Linux traffic control) for cross-region simulation
- Synthetic packet loss via `tc` for unreliable-network scenarios

---

## 4. Test scenarios

### 4.1 Consensus stress

#### S1.1 — High block rate
- **Goal:** Verify GhostDAG-Q handles 10× normal block rate without state corruption
- **Method:** 5 miner simulators running concurrently, all on local network with near-zero latency
- **Duration:** 6 hours
- **Pass criteria:** No DAG inconsistency detected by `bloch-cli verify-dag`. No panics. Memory stable (no growth >2 GB over 6 hours).
- **Expected difficulty:** Low difficulty target so blocks are produced rapidly even with CPU mining.

#### S1.2 — Reorg storms
- **Goal:** Verify reorg handling under repeated reorgs at varying depth
- **Method:** Two equal-hashrate miner clusters, each unaware of the other. Network partition for 30 minutes, then heal. Repeat 20 times.
- **Duration:** 24 hours
- **Pass criteria:** Final state convergent. UTXO set matches between all nodes (`bloch-cli compare-utxo-set`). No double-spend accepted.
- **Carryover:** Sprint FF in ROADMAP.md mentions reorg observability — this test populates initial data for those metrics.

#### S1.3 — Equivocation
- **Goal:** Verify slashing fires per ADR-007 when validator equivocates
- **Method:** Modified validator that signs two different blocks at same height
- **Duration:** Single ceremony
- **Pass criteria:** Slashing transaction emitted. Equivocator's stake reduced 5%. Network continues without halt.

### 4.2 Storage stress

#### S2.1 — RocksDB write amplification
- **Goal:** Detect write amplification issues under sustained writes
- **Method:** Synthetic block generation at peak rate for 48 hours
- **Duration:** 48 hours
- **Pass criteria:** Write amplification factor (WAF) ≤ 10x. Disk space growth linear (no compaction explosions). Read latency p99 < 100ms throughout.
- **Tools:** RocksDB built-in metrics + Prometheus

#### S2.2 — Crash recovery
- **Goal:** Verify storage integrity after kill -9 mid-write
- **Method:** Run node under sustained mining load. Every 5 minutes, kill -9. Restart. Verify state.
- **Iterations:** 100
- **Pass criteria:** All 100 restarts succeed. No state corruption. No DAG hash mismatch with peer nodes.

#### S2.3 — Address history migration
- **Goal:** Verify `bloch-migrate-addr-history` handles 1M addresses with 100M transactions
- **Method:** Synthetic dataset generation, run migration, time it, verify output
- **Pass criteria:** Migration completes in <2 hours. Output queryable via RPC. Memory peak <8 GB.

### 4.3 Networking stress

#### S3.1 — Peer churn
- **Goal:** Verify gossipsub stability with peers connecting/disconnecting rapidly
- **Method:** 50 peer simulators connecting and disconnecting at random intervals (mean 30s)
- **Duration:** 12 hours
- **Pass criteria:** Block propagation latency p99 < 5 seconds despite churn. No file descriptor leak.

#### S3.2 — High peer count
- **Goal:** Verify performance with 200 simultaneous peers
- **Method:** 200 peer simulators all connected to one node
- **Duration:** 6 hours
- **Pass criteria:** CPU usage <80%. Memory <8 GB. Block propagation working. No starvation of any peer.

#### S3.3 — Latency injection
- **Goal:** Verify FFG finality gracefully degrades under cross-region latency
- **Method:** Network partitions with 50ms, 100ms, 250ms, 500ms latency added between groups
- **Duration:** 4 hours per latency tier
- **Pass criteria:** FFG soft finality achieved within 2 epochs at all latencies up to 250ms. At 500ms, finality may take 3–4 epochs but must eventually achieve.

### 4.4 Stratum V1 stress

#### S4.1 — Session count
- **Goal:** Verify V1 server handles configured `--stratum-max-sessions` without degradation
- **Method:** 256 concurrent SV1 client simulators (or 500, whichever the config allows)
- **Duration:** 24 hours
- **Pass criteria:** All sessions remain authenticated and receive jobs. p99 mining.notify latency <500ms. No FD leak.

#### S4.2 — Submission flood
- **Goal:** Verify rate limiting per session works
- **Method:** Single client submits 10,000 shares per minute (well above 30/min cap)
- **Duration:** 1 hour
- **Pass criteria:** Server rate-limits client (error 23). Other clients on same server unaffected.

#### S4.3 — Malformed input
- **Goal:** Verify V1 server rejects malformed JSON without crashing
- **Method:** Fuzz client sending random bytes, malformed JSON, oversized lines (>8 KiB), nested JSON
- **Duration:** 4 hours
- **Pass criteria:** No panics. No memory blowup. Sessions get cleanly closed on protocol violation.

### 4.5 Stratum V2 stress

This is the highest-priority stress section because SV2 has the least production exposure.

#### S5.1 — NOISE handshake under load
- **Goal:** Verify handshake completes successfully under 100 concurrent connection attempts
- **Method:** 100 SV2 client simulators all initiating handshake simultaneously
- **Pass criteria:** All 100 handshakes complete within 30 seconds. No mutex contention deadlock.

#### S5.2 — Pre-handshake DoS
- **Goal:** Verify server handles connection flood that doesn't complete handshake
- **Method:** 1000 TCP connections opened, never sending Act 1 message
- **Duration:** 1 hour
- **Pass criteria:** Server times out idle connections. Memory stable. Other (legitimate) handshakes continue working.
- **Notes:** This test will surface the per-IP rate limit gap mentioned in GIP-0003 §Security Considerations.

#### S5.3 — Mining channel flood
- **Goal:** Verify channel opening at scale
- **Method:** 100 sessions, each opening 10 mining channels
- **Pass criteria:** All 1000 channels accepted. Per-channel state isolation verified (one session disconnecting doesn't affect another's channels).

#### S5.4 — Real Bitaxe end-to-end
- **Goal:** Verify all 4 CHECKME fixes actually work with real Bitmain silicon
- **Method:** Bitaxe Gamma 601 connected to node, running for 24 hours
- **Pass criteria:**
  - Handshake completes
  - Channel opens with negotiated extranonce_prefix size (CHECKME-4b-extranonce)
  - Version rolling shares accepted (CHECKME-epsilon-version-rolling)
  - Cumulative shares_sum reported correctly (CHECKME-epsilon-shares-sum)
  - At least one share that meets block target is accepted
  - No protocol-level errors logged
- **Notes:** This is the validation that the entire SV2 sprint is meaningful.

#### S5.5 — Certificate expiry
- **Goal:** Verify cert auto-renewal works
- **Method:** Set cert validity to 1 hour. Run for 8 hours.
- **Pass criteria:** Cert renews automatically before expiry. No mining downtime.

### 4.6 DKG stress

#### S6.1 — Ceremony participation churn
- **Goal:** Verify DKG ceremony tolerates participants joining/leaving mid-ceremony
- **Method:** 7-of-12 ceremony where 3 participants drop and rejoin during rounds 2-4
- **Pass criteria:** Ceremony completes successfully or fails cleanly with diagnostic. No partial state corruption.

#### S6.2 — Adversarial participant
- **Goal:** Verify Pedersen VSS catches malformed shares
- **Method:** Modified participant sending invalid commitments
- **Pass criteria:** Complaints fired. Adversarial participant excluded. Ceremony completes among remaining honest participants.

### 4.7 Mempool stress

#### S7.1 — Mempool flood
- **Goal:** Verify mempool eviction policy under flood
- **Method:** 100,000 transactions submitted in 5 minutes
- **Pass criteria:** Mempool size capped per configuration. Lowest-fee transactions evicted first. RPC remains responsive.

#### S7.2 — Replace-by-fee storms
- **Goal:** Verify RBF doesn't degrade performance
- **Method:** 1000 transactions each replaced 10 times
- **Pass criteria:** Replacement cost (CPU + storage) bounded. Latest version always serves into next block template.

---

## 5. Adversarial scenarios

These tests assume an attacker, not a buggy peer.

### A1 — Eclipse attack
Attacker controls all peer connections to victim. Verify victim detects and recovers (peer diversity heuristics, fallback DNS seeds).

### A2 — Sybil flood
Attacker creates 10,000 nodes with fresh identities. Verify gossipsub mesh formation isn't dominated.

### A3 — Block withholding
Adversarial miner solves blocks but doesn't broadcast. Verify network still progresses (no liveness halt).

### A4 — Long-range attack
Attacker builds parallel chain from 1000 blocks ago. Verify checkpointing prevents acceptance even if attacker has more cumulative work.

### A5 — Stratum hijack
Attacker MITMs a SV1 connection (cleartext). Verify the new SV2 path provides protection that V1 cannot. Document the V1 attack as known limitation in `legacy/operations/stratum.md`.

---

## 6. Tooling

### 6.1 Build the harness

A test harness lives in `tests/stress/` (does not exist yet, must be created). Components:

- `stress_runner` binary — orchestrates scenarios, collects logs and metrics
- `peer_simulator` — minimal libp2p peer that participates in gossipsub
- `miner_simulator` — CPU miner that submits via SV1 or SV2
- `adversary_simulator` — implements adversarial behaviors A1–A5
- `chaos_monkey` — random kill -9, network partition, latency injection
- `metrics_capture` — Prometheus scraper writing to JSON for offline analysis

Estimated effort to build: 40–60h of dedicated work. Significant investment but reusable across all future versions of the protocol.

### 6.2 Reuse existing tools

- `cargo bench` for microbenchmarks of consensus + crypto primitives
- `tokio-console` for async runtime visibility
- `flamegraph` for CPU profiling
- `pprof` for memory profiling
- `cargo-fuzz` for fuzzing — already part of Sprint 12 plan, can leverage same infrastructure
- `polkadot-fuzz` patterns applicable to consensus engine fuzzing

---

## 7. Schedule

| Week | Activity |
|---|---|
| Week 1 | Build stress harness skeleton (peer_simulator, miner_simulator, runner) |
| Week 2 | Build adversary_simulator + chaos_monkey + metrics_capture |
| Week 3 | Execute consensus stress (S1.x) and storage stress (S2.x) — 6+ days continuous |
| Week 4 | Execute networking stress (S3.x) and stratum V1 stress (S4.x) |
| Week 5 | Execute stratum V2 stress (S5.x) including real Bitaxe runs |
| Week 6 | Execute DKG stress (S6.x), mempool stress (S7.x), adversarial scenarios (A1-A5) |
| Week 7 | Triage findings, fix critical issues, retest |
| Week 8 | Final regression run + documentation of findings |

Total: 8 weeks. Can compress to 4 weeks with two engineers.

---

## 8. Pass / fail criteria for the campaign

The stress test campaign passes if:

1. All scenarios run to completion (none aborted due to test infrastructure failure)
2. No critical findings remain unfixed (critical = data loss, consensus break, or remote crash)
3. All high findings are fixed or have explicit deferral with risk acceptance signed by founder
4. Real Bitaxe end-to-end test (S5.4) passes — this is the SV2 go/no-go gate
5. Reproducible results — campaign can be rerun and produce qualitatively similar findings

The campaign **does not** pass if any of:

- Any scenario produces unexpected node panic that wasn't reproduced and root-caused
- Any scenario produces consensus inconsistency between nodes
- Any scenario produces UTXO state divergence
- The real Bitaxe cannot mine successfully against the SV2 listener for 24 hours

A failure of any of these conditions means more development work and another campaign.

---

## 9. Reporting

Each finding gets logged in `docs/findings/STRESS-2026-XXXX.md` with:

- **Severity** — critical / high / medium / low / informational
- **Reproduction** — exact steps and configuration
- **Logs / traces** — captured Prometheus snapshots, log excerpts, packet captures
- **Root cause** — what's actually wrong
- **Fix** — code change that addresses it (or deferral rationale)
- **Regression test** — how we know we won't regress

Final campaign report at `docs/findings/STRESS-CAMPAIGN-2026-MAINNET.md` summarizing all findings, fixes, and residual risks. This document is also a deliverable for the eventual Foundation-contracted external audit (gives them a head start).

---

## 10. Document control

- **Version:** 1.0 — initial draft
- **Last updated:** 2026-05-01
- **Update cadence:** Each scenario expanded in detail as it's executed; scenarios added or deleted as discoveries warrant
- **Owner:** Founder (custodial) until Phase 3, Foundation thereafter
- **License:** Same as repository
