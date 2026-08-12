# Internal Audit Plan — Final Pre-Mainnet Review

| Field | Value |
|---|---|
| **Status** | Working draft |
| **Date** | 2026-05-01 |
| **Author** | Founder (custodial) |
| **Scope** | Final internal audit of the BLOCH codebase before mainnet activation under founder custodial stewardship per ADR-023 Phase 1 |
| **Position in lifecycle** | Runs after `STRESS-TEST-PLAN.md` campaign closes. Last engineering gate before genesis ceremony and mainnet activation. |
| **Companion docs** | `legacy/MAINNET-DEV-CHECKLIST.md`, `legacy/STRESS-TEST-PLAN.md` |

---

## 1. Purpose and scope

This is the founder's final internal review of the codebase before mainnet activation. It is **not** a substitute for the external audit that the Foundation will contract per ADR-026 — Kudelski, NCC Group, Trail of Bits, Certik, or Halborn (or a combination thereof) — once the Foundation incorporates after Phase 2.

This internal audit serves three distinct functions:

1. **Catch what stress testing missed.** Stress testing finds dynamic failures; static review finds subtler issues — incorrect bounds, missing guards, dead code paths that masked bugs, copy-paste errors that compile and pass tests but are wrong.

2. **Document the codebase for the eventual external audit firm.** Auditors charge by the hour. A well-organized codebase with clear documentation, threat model, and known-issues list reduces the audit cost substantially and improves audit depth (auditors spend their time on hard problems, not on understanding our basics).

3. **Surface residual risks for explicit founder acceptance.** Anything the founder ships with known issues must be acknowledged in writing. Phase 1 mainnet activation under founder custodial stewardship means the founder cannot point at an external auditor as having signed off — the founder takes the risk personally.

### 1.1 What is in scope

- All Rust code in `src/`
- All integration tests in `tests/`
- All ADRs and GIPs (cross-reference: code matches documented design)
- Build configuration (`Cargo.toml`, `Dockerfile`, CI configuration)
- Operator documentation (`docs/operations/*`)
- Genesis configuration

### 1.2 What is out of scope

- External crates and their transitive dependencies (we trust upstream's audit posture; we list dependencies explicitly in the threat model and pin versions)
- The Sprint 11 compliance contracts (those are unstarted at the time of this document; they get their own audit plan when they exist)
- Hardware-level concerns (ASIC firmware, BMC, hardware random number generators)
- Operating system security (operator's responsibility per `docs/operations/*`)

---

## 2. Audit methodology

The audit is structured in five passes, each with a specific lens:

### 2.1 Pass 1 — Boundaries

Examine every place where untrusted input enters the system. For each entry point, verify input validation, error handling, and resource bounds.

Entry points to examine:
- RPC endpoints (axum routes in `src/rpc/`)
- P2P protocol messages (libp2p gossipsub in `src/network/`)
- Stratum V1 JSON-RPC parsing (`src/stratum/protocol.rs`)
- Stratum V2 binary frame decoding (`src/stratum_v2/setup_connection_decode.rs`, `open_channel_decode.rs`, `submit_shares.rs`)
- DKG message handling (`src/ffg/dkg/*`)
- CLI argument parsing (`src/main.rs`, `src/bin/*`)
- File reads (config files, keystore files, RocksDB column family reads with corrupted data)

For each entry point, the auditor verifies:
- Maximum size bound on input
- Type validation before use
- Error propagation (no `.unwrap()` on user-supplied values)
- Resource bounds (no unbounded allocation, no infinite loops on bad input)
- Logging of validation failures (so operators can detect attack patterns)

### 2.2 Pass 2 — State machines

The protocol has many state machines. Each one must be examined for unreachable states, illegal transitions, and missing transitions.

State machines to audit:
- Block validation pipeline (`src/consensus/`)
- DAG state (block → tip, blue/red, finality)
- DKG ceremony rounds (R1 through R5)
- FFG voting (epoch transitions, justification, finalization)
- Stratum V1 session (`Fresh → Subscribed → Authorized → Dead`)
- Stratum V2 session (`Handshake → SetupDone → Live → Closed`)
- SV2 mining channel state
- Mempool transaction state (pending → confirmed → conflicted → expired)

For each state machine, the auditor verifies:
- All states are reachable from the initial state via the transition function
- All terminal states are reachable
- No transition introduces inconsistent state (i.e., post-condition holds in all branches)
- Concurrent transitions are properly synchronized (mutex / atomic ordering)

### 2.3 Pass 3 — Cryptographic correctness

The cryptographic primitives are externally verified (RFC 9380 vectors, FIPS 204 reference) but their *use* in our code requires verification.

Items to audit:
- DST (domain separation tag) used at every hash-to-curve site (cross-context confusion is a real risk)
- Nonce reuse in any signature scheme (MUST NOT happen — would catastrophically leak keys)
- Constant-time comparisons for all secret-comparison operations
- Memory zeroization of secret material (zeroize crate usage)
- Random number generator sourcing (must be `OsRng` or equivalent CSPRNG; never test RNG in production code)
- Key derivation paths for premine, treasury, oracle pool, founder, and protocol fees
- Signature verification ordering (verify before commit; never the reverse)

### 2.4 Pass 4 — Consensus invariants

Consensus correctness is the highest-stakes section. A bug here is a chain split or worse.

Invariants to verify:
- Block reward calculation matches ADR-010 emission curve
- 70/25/5 reward split implemented per ADR-010-Addendum-1 (as activated by ADR-028) across miner / validator / oracle pool
- Coinbase tx structure matches Bitcoin format (compatible with stratum reconstruction)
- Merkle root reconstruction matches what stratum miners assemble from coinb1/extranonce/coinb2/branch
- Difficulty retargeting matches ADR-006 specification
- FFG soft finality / hard finality timing matches ADR-006 (1 epoch / 2 epochs)
- Validator inactivity threshold uses integer (NUM=40, DEN=100) not f32 per ADR-005 §4.1
- Slashing math correct: 5% per equivocation, 40% per inactivity event per ADR-007
- Premine vesting schedule: 17% supply, 12-month cliff, 348-month linear, total 30 years per ADR-010-A
- Total supply hard cap of 1,000,000,000 BLOCH nominal (170M founder premine + 800M mining + 30M validator/oracle pool, per TOKENOMICS_V2.md) never exceeded by any code path; tail emission of 25 BLOCH/block is perpetual and intentional, not a cap violation
- Genesis block validates under the same rules as subsequent blocks (no special-case bypass)

For each invariant, the audit must:
- Cite the source ADR
- Cite the source code location implementing it
- Identify any unit test that exercises the invariant
- Note any path that could violate the invariant if a bug existed elsewhere

### 2.5 Pass 5 — Adversarial code review

Read the code with the question: "if I wanted to attack this, where would I look?"

Areas to examine adversarially:
- Block validation rejection criteria — does any malformed block get accepted?
- Mempool eviction — can attacker get free transaction inclusion by exploiting eviction policy?
- Difficulty retargeting — can attacker manipulate difficulty by withholding/releasing blocks at boundaries?
- Stratum extranonce — can a stratum miner manipulate extranonce to claim more reward than entitled?
- DKG complaint mechanism — can adversarial participant cause honest participants to be slashed?
- Transaction signature verification — any path where a malformed signature is treated as valid?
- Network layer — any messages that bypass consensus rules?

---

## 3. Specific high-risk areas

These warrant individual sections because their bug surface is non-obvious.

### 3.1 Concurrency

Rust's borrow checker prevents data races but does not prevent logic races. We use:

- `Arc<RwLock<GhostDAG>>` — write locks on tip changes
- `Arc<Mutex<...>>` for various mutable state
- `tokio::sync::broadcast` for tip notifications
- `tokio::sync::mpsc` for network message routing

Audit checklist:
- Lock ordering — every code path that acquires multiple locks must do so in the same order. Use `clippy::missing_const_for_thread_local` and similar lints.
- Lock duration — write locks held briefly. No I/O under a write lock.
- Read locks across `await` — read lock held during `await` is a deadlock risk if any code path on the awaited future tries to write.
- Channel backpressure — bounded channels must have explicit overflow handling. Unbounded channels can OOM.

### 3.2 Storage

RocksDB is correctness-critical. Audit:

- Column family separation correct (no accidental cross-CF reads/writes)
- Write atomicity for related rows (use `WriteBatch`)
- Read-modify-write sequences are not racy (use snapshots or transactions)
- Deletion semantics — does deletion actually free space? RocksDB tombstones can grow.
- Schema versioning — migration tool exists for known migrations; what about unknown future ones?

### 3.3 Stratum V2 specifically

SV2 is the youngest code in the codebase and has the lowest test coverage. Pay special attention.

Audit checklist:
- All 4 CHECKMEs resolved (per `MAINNET-DEV-CHECKLIST.md` §6.2)
- NOISE handshake state machine handles all error paths cleanly
- Per-session memory bounded (an attacker opening many sessions cannot OOM the server)
- Authority key never logged or leaked
- Cert validity checked correctly (clock skew handling, NTP dependency documented)
- Mining job IDs unique across channels and sessions
- Share validation cannot be bypassed via crafted SubmitSharesStandard

### 3.4 DKG

DKG is the most cryptographically subtle code in the codebase.

Audit checklist:
- Pedersen VSS commitments verified before use
- Lagrange interpolation correct (we have RFC 9380 + Day 10 cross-validation tests; verify they exercise the path that production uses)
- Participant indices unique and bounded
- Round transitions cannot occur out of order
- Partial state cannot leak between sessions (one ceremony abandoned, another started)
- Adversarial participant exclusion deterministic and tied to verifiable evidence

### 3.5 Genesis

Genesis is the highest-stakes single code path because it cannot be reverted.

Audit checklist:
- Genesis difficulty calibrated per measured seed hashrate (re-verified at ceremony time)
- Genesis coinbase tag chosen and committed
- Premine address generated, ML-DSA-65 keystore secured per 3-2-1 backup
- Treasury and oracle pool addresses generated, multi-sig set up per ADR-018
- Genesis timestamp signed by founder
- Genesis block validated against the same rules as subsequent blocks
- Genesis block accepted by a clean fresh node sync (no special bootstrap path that could mask a bug)

---

## 4. Tooling

### 4.1 Static analysis

Run all of these in CI for the audit branch:

- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo audit` — known vulnerabilities in dependency tree
- `cargo deny check` — license compliance and dependency policy
- `cargo geiger` — unsafe code report (any `unsafe` in our code requires explicit justification)
- `cargo udeps` — unused dependencies
- `cargo outdated` — out-of-date dependencies, prioritize security-critical updates

### 4.2 Dynamic analysis

- `cargo-fuzz` — fuzz harnesses for input parsing (RPC, stratum decoders, P2P messages)
- `miri` — undefined behavior detection in safe Rust (slow but catches real issues)
- Sanitizers (ASan, TSan, MSan) — built with `RUSTFLAGS="-Z sanitizer=..."` on nightly

### 4.3 Custom checks

Some checks are specific to BLOCH:

- Verify all hash-to-curve invocations use a defined DST constant from `src/ffg/dkg/hash_to_curve.rs`
- Verify no f32/f64 arithmetic in consensus code paths (per ADR-005 §4.1)
- Verify all `expect()` and `panic!()` calls in non-test code have justifying comments
- Verify all `TODO`, `FIXME`, `CHECKME` markers are tracked in the issue tracker

---

## 5. Cross-referencing ADRs

Every architectural decision recorded in `docs/adr/` must be verified against code.

| ADR | Subject | Verification |
|---|---|---|
| ADR-002-rev2 | DKG protocol family | `src/ffg/dkg/` |
| ADR-003 | Minimum committee policy | Committee selection code |
| ADR-004 | DKG epoch overlap | DKG scheduling |
| ADR-005 | Committee era + Phragmén | Era rotation, integer threshold |
| ADR-006 | Block time + dual finality | Consensus timing |
| ADR-007 | Bonding contract + slashing | Slashing math |
| ADR-010 | Tokenomics emission | Reward calculation |
| ADR-010-A | Founder premine | Vesting schedule |
| ADR-010-Add-1 | Oracle pool | 70/25/5 split (activated by ADR-028) |
| ADR-011 | FFG activation height | Block 210k transition |
| ADR-018 | Oracle network | Oracle bonding, query API |
| ADR-019 | Fork governance | Fork policy |
| ADR-020 | PQ hybridization | Reserved roadmap |
| ADR-021 | Transport continuity | libp2p preserved |
| ADR-022 | Hash-to-curve + BLS | DSTs, group choice |
| ADR-023 | Foundation Genesis Model | (Phase 3 work, not Phase 1 code) |
| ADR-024 | Steward Council bootstrap | (Phase 3 work) |
| ADR-025 | Decentralization metrics | Metrics computation code (Phase 2 deliverable) |
| ADR-026 | Custody handover | (Phase 3 work) |
| ADR-027 | Founder commitments | (binding instrument, not code) |

For each ADR with code: the audit produces a 1-page summary of what was decided and where it's implemented. This becomes input to the eventual external audit.

---

## 6. Threat model documentation

Update `docs/THREAT_MODEL.md` to reflect current code. Areas to expand:

- Stratum V2 attack surface (handshake DoS, share forgery, certificate trust assumptions)
- Foundation incorporation period — what attacks become possible during the founder-custodial Phase 1?
- Sprint 11 compliance contracts when they exist — they introduce new attack surface
- Supply chain attacks on the dependency tree (cargo dependency confusion, malicious crate updates)

---

## 7. Output deliverables

The audit produces:

1. **`docs/findings/AUDIT-2026-INTERNAL.md`** — full findings report with severity, reproduction, root cause, fix
2. **Updated `docs/THREAT_MODEL.md`** with current state
3. **`docs/PRE-MAINNET-AUDIT-SUMMARY.md`** — executive summary safe to share with potential external audit firms
4. **Code patches** for all critical and high findings
5. **Risk acceptance memos** signed by founder for any deferred medium / low findings
6. **Updated `MAINNET-DEV-CHECKLIST.md`** with remaining items

---

## 8. Severity classification

| Severity | Definition | Action |
|---|---|---|
| **Critical** | Consensus break, data loss, remote arbitrary code execution, key compromise | Mainnet blocker. Fix immediately. Re-run stress test for affected area. |
| **High** | Denial of service, partial state corruption, privacy leak | Mainnet blocker absent compelling justification. Fix in current audit cycle. |
| **Medium** | Performance degradation, partial functionality, configuration footguns | Document, fix if budget allows, otherwise defer to post-mainnet patch release. |
| **Low** | Code quality, test coverage gap, documentation issue | Document. Fix opportunistically. Not a blocker. |
| **Informational** | Suggestions, refactoring opportunities | Document only. |

---

## 9. Schedule

| Day | Activity |
|---|---|
| 1–2 | Pass 1 (boundaries) — RPC, P2P, stratum decoders |
| 3–4 | Pass 2 (state machines) — consensus, DKG, sessions |
| 5 | Pass 3 (cryptographic correctness) |
| 6–7 | Pass 4 (consensus invariants) |
| 8 | Pass 5 (adversarial review) |
| 9 | Storage section deep dive |
| 10 | Stratum V2 specific section |
| 11 | DKG specific section |
| 12 | Genesis section |
| 13 | Static + dynamic analysis runs |
| 14 | Cross-referencing ADRs |
| 15 | Threat model update |
| 16 | Findings triage and severity assignment |
| 17–19 | Critical/high fixes |
| 20 | Re-verification of fixes |
| 21 | Final summary report |

Total: ~21 days for one auditor working full time. Compressible to 14 days with two auditors and parallelizable work streams (Pass 1, Pass 2, Pass 3 can run in parallel).

---

## 10. Success criteria

The internal audit is complete when:

1. All 5 passes have been executed and documented
2. Every ADR has a code-cross-reference page
3. All critical and high findings are fixed
4. All medium findings are documented with explicit accept/defer decision
5. Static + dynamic analysis runs produce no new errors
6. Threat model is updated and reflects current code
7. Founder reviews and signs the executive summary

The internal audit **does not** complete if:

- Any critical finding remains unfixed
- Any cryptographic invariant is unverified
- The genesis ceremony cannot proceed because of an unresolved finding

---

## 11. Position vis-à-vis external audit

Per ADR-026 (Custody Handover Protocol) and the founder's prior commitments, external audit is contracted by the Foundation post-Phase-3, not by the founder pre-mainnet.

Candidate external audit firms (per `BLOCH-ASIC-Hardware-Recommendation.pdf` §1 and ROADMAP.md alignment):

- Kudelski Security (familiar with zkcrypto stack)
- NCC Group (broad blockchain coverage)
- Trail of Bits (deep Rust expertise)
- Certik (formal verification capability)
- Halborn (mining and consensus specialty)

The Steward Council elected per ADR-024 will receive this internal audit's executive summary as a starting point. The external audit firm chosen will benefit from:

- Threat model already documented
- Findings already triaged
- ADR-to-code mapping already done
- Stress test campaign report already published

This reduces external audit cost (firms charge by hour) and increases external audit depth (auditors spend their time on hard problems, not on understanding our codebase basics).

---

## 12. Document control

- **Version:** 1.0 — initial draft
- **Last updated:** 2026-05-01
- **Update cadence:** Each pass section detailed as the audit progresses. Findings logged in real time.
- **Owner:** Founder (custodial) for Phase 1 audit. Foundation thereafter for Phase 3 audit oversight.
- **License:** Same as repository
