# Bloch-SIS Protocol — Threat Model (audit-scoping draft)

**Status: advisory / design-only. This is a PLAN and an honest self-assessment,
NOT a claim of security.** No external cryptographic or security audit has been
performed on any part of this codebase. Nothing here is "secure," "proven,"
"audited," or "quantum-safe." This document is not legal or financial advice.

Companion to `docs/SPEC.md` (the frozen protocol description). Its purpose is to
tell an external auditor **what to protect, against whom, and — critically —
what the security goal actually is**, so the engagement is scoped correctly and
the auditor does not mis-model the system. Grounded in the code; citations are
`file:line`.

> This is the audit-scoping threat model, the companion to `docs/SPEC.md`. It
> complements — does not replace — the two pre-existing threat docs, which are
> retained: `docs/THREAT-MODEL.md` (a shorter security/privacy matrix) and
> `docs/THREAT_MODEL.md` (a fuller STRIDE-per-subsystem model). Where any of the
> three disagree, the code (cited `file:line`) is authoritative.

---

## 0. The unusual security goal — READ THIS FIRST

**Bloch-SIS protects chain-ordering integrity and liveness, NOT asset value.**

- **The coin is worthless by design.** It is **not a security**, confers no
  claim, and no revenue ever touches the token (`roadmap-crypto-core.md` §0;
  emission params `core/mod.rs:8-28` exist for ordering, not value). Personal
  Postern products are free; corporate/service lines — never the token — are the
  revenue model.
- **Consequence for scoping:** the thing worth stealing in a normal cryptocurrency
  (spendable value) **is not the asset here.** An auditor who models Bloch as
  "protect user funds" will mis-prioritise. The assets that matter are the
  *integrity of the ordered history* (no silent rewrite of accepted, final
  history) and *the ability of honest nodes to keep making progress* (liveness),
  plus the *soundness of the crypto primitives as reusable building blocks* (the
  same hybrid signer is consumed by the Postern products, where context does
  matter).
- **What this is NOT:** it is not a custody system, there is no privileged party
  that can freeze/seize/deanonymize, and there is no "protect the money" claim to
  audit. There is also **no live network today** — the chain runs a
  **zero-security testnet** PoW regime (§2, k=4).

State this to any auditor up front. Everything below is the *intended* posture
and its current status; **no security guarantee holds today.**

---

## 1. Assets and trust boundaries

### 1.1 Assets (in priority order for this system's goal)

| Asset | Why it matters here | Not the asset |
|---|---|---|
| **Ordering integrity of finalized history** | the core promise: accepted history below `CHECKPOINT_DEPTH` (1000, `core/mod.rs:79`) is not silently rewritten | — |
| **Liveness / progress** of honest nodes | a valueless chain still fails if it can be stalled/desynced | — |
| **Soundness of the hybrid signer + PoW verifier** as primitives | reused by Postern (auth, attestation) where a break has real blast radius | — |
| **Node/host integrity** (runs the intended code) | attestation story (stubbed here) | — |
| Spending keys / "funds" | *low priority by design* — the coin is valueless | value protection is **explicitly not a goal** |

### 1.2 Trust boundaries

1. **Untrusted network ↔ node:** every inbound block/tx/P2P message is adversarial
   input. Parsing is bounded/EOF-safe (`core/mod.rs:804-844, 1073+`; "audit M1"),
   and consensus-invalid input must yield rejection, never a panic or a non-`false`
   verify (`crypto/mod.rs:102-131`).
2. **Consensus rule boundary:** miner and validator must apply *identical* rules.
   Single-sourced where it counts: the k-selector
   (`core/mod.rs:151-158`, mirrored `src/pow/mod.rs:134-149`) and difficulty
   (`src/pow/mod.rs:77-90`).
3. **RPC ↔ operator/clients:** `src/rpc/` is a privileged-ish surface (mempool
   admission mirrors block validation, `rpc/mod.rs:1290-1299`).
4. **Supply chain:** the **vendored `pqcrypto-internals` fork** (the
   `randombytes` override, `crates/pqcrypto-internals/`) and the pinned PQClean C
   for ML-DSA/Falcon/Kyber are inside the TCB; a committed `Cargo.lock` and
   `[patch.crates-io]` define what actually builds.
5. **Host / OS:** below the (currently stubbed) attestation layer, the node trusts
   its host.

---

## 2. Adversary classes and findings

### 2.1 Miner / 51% adversary

- **Cheap-PoW forgery / the k=4 regime.** Today the live regime is
  `TESTNET_RESIDUAL_COEFFS = 4` — **explicitly ZERO security**
  (`lib.rs:109-115`, `src/pow/mod.rs:34-40`). Solutions are brute-force cheap;
  the structural gate contributes only a ~2¹² rejection floor. SF-1 (k→8) raises
  the floor to ~2²⁴ but **does not change the security story: security is
  cumulative SHAKE-256 hashcash work, not lattice hardness** (`lib.rs:16-26`).
  There is no lattice bit-security number at any parameter set.
- **51% / majority-hashrate.** Fork choice is GhostDAG on accumulated work
  (`consensus/mod.rs:32-58`, §7.2 of the spec). A majority-work adversary can
  reorg up to `CHECKPOINT_DEPTH = 1000` blocks (`core/mod.rs:79`); deeper reorgs
  are rejected (finality gate). **Mainnet-beta is 51%-attackable** — stated
  plainly; on a valueless coin the impact is ordering disruption/liveness, not
  theft, but it is real and in-scope.
- **Selfish mining / withholding / equivocation.** Standard PoW-DAG concerns;
  the reorg re-validation path (`src/reorg.rs`) re-checks input existence,
  double-spend, value conservation and coinbase maturity.
- **Activation-height footgun.** `CANONICAL_K_ACTIVATION_HEIGHT = 1_000_000` is a
  placeholder (`core/mod.rs:120-141`). Shipping it to mainnet, or setting it at/
  below the tip, forces a chain reset or a partition. Must be set + CI-guarded
  before deploy (roadmap P0.5).

### 2.2 Network / P2P adversary (MITM, eclipse, partition, spam, replay)

- **Cross-chain / replay at the signature level — OPEN.** The tx sighash has
  **no chain-id / network tag** (`core/mod.rs:869-891`; SPEC §4.4). A signed tx is
  structurally replayable testnet↔mainnet / across any fork if outpoints coincide.
  This is the single most important *protocol-level* weakness to record. Fix is
  roadmap P0.4 (a hard fork).
- **DoS / resource exhaustion (maps to `roadmap-rust-systems.md`).** The node
  roadmap flags concrete, currently-open DoS vectors that an auditor of the wire
  layer will hit:
  - *Silent-death on panic:* the message-processor/swarm/RPC tasks are
    `tokio::spawn`ed with no supervision — a panic on an untrusted-input path =
    permanent silent desync (rust roadmap §2.5, P0). Audit `unwrap`/`expect`/
    `try_into().unwrap()` on parse paths.
    (Bloch's stated rule — malformed consensus input ⇒ `false`/reject, never
    panic — must be verified by fuzzing: `verify`, `Address::parse`, keyfile
    decrypt, tx deserialization; roadmap P0.7.)
  - *Unbounded GhostDAG nodes at zero PoW cost*, PEX/rate-limiter maps growing
    unbounded → memory-exhaustion (rust roadmap §1.6, §4.2–4.3).
  - *Mempool quadratic scan under flood* (50k linear scan per accepted tx; rust
    roadmap §1.6) and mempool bounded by count not bytes (§4.3).
  - *Expensive RPC (`getchainstats`/`getsupplydistribution`) with no concurrency
    cap* — slow-loris/flood (rust roadmap §2.5).
  These are liveness/availability threats — directly on the protected axis for a
  valueless chain. Swarm-level connection limits now exist
  (`network/mod.rs:120-126`), partially closing eclipse-setup floods.
- **Eclipse.** libp2p gossipsub + mDNS + identify, "every node is a seed"
  (`network/mod.rs:107-126`); `DEFAULT_SEEDS` is empty (`core/mod.rs:73-77`) — no
  seed infra yet, so bootstrap is `--peer`-driven and eclipse-relevant.
- **Handshake replay / MITM.** The PQ transport handshake (`src/transport/mod.rs`)
  is Kyber768 + hybrid-sig authenticated, transcript-bound (t1/t2), nonce'd — but
  **self-labelled: no formal proof, no audit** (`transport/mod.rs:63`). Two
  parallel handshake variants exist (`transport/mod.rs` and `transport/upgrade.rs`)
  and should be consolidated/scoped before symbolic analysis (roadmap §4.4).
  Application-layer gossip messages (`NetworkMessage`) are unsigned at the app
  layer; integrity rests on full re-validation of the re-parsed block/tx.

### 2.3 RPC / operator-adjacent adversary

Mempool admission runs the same validation core as block acceptance
(`rpc/mod.rs:1290-1299` mirrors `main.rs:1750-1807`). Risks: the DoS items in
§2.2; and any divergence between the mempool and block-validation paths (they
share `validate_tx_inputs`-style logic but should be diffed by the auditor).

### 2.4 Supply-chain adversary

- The **vendored `pqcrypto-internals` fork** is the highest-leverage unreviewed
  code: a thread-local that silently swaps the RNG for **all** PQClean crates on
  the thread (`crates/pqcrypto-internals/`, used at `crypto/mod.rs:78`). Invariant
  to verify: no seeded guard is ever alive across a `sign()` call (keygen only).
- Pinned PQClean C for ML-DSA-65 / Falcon-1024 / Kyber768 — integration is
  bespoke and unreviewed; the underlying schemes are NIST-selected but the
  wrappers are not KAT-verified against the standards yet (roadmap P0.3).
- Committed `Cargo.lock` + `[patch.crates-io]` define the real build; reproducible
  build + signed releases/SLSA are a later gate.

### 2.5 Quantum / harvest-now-decrypt-later (HNDL)

- Signatures are PQ (hybrid lattice); hashing is SHA3/SHAKE (Grover-only).
- **But `postern-messenger` transport is classical Curve25519 (Olm/Megolm)** —
  **HNDL applies to messaging transport** (roadmap §1.6, App.B). Only at-rest is
  PQ there. This is outside the blockchain node but inside the wider product TCB
  an auditor may be asked about.

### 2.6 Side-channel adversary (signing)

All PoW inputs are public, so PoW has no constant-time requirement. **All
side-channel risk is in signing**, concentrated in **Falcon-1024's
floating-point Gaussian sampler** (not constant-time; documented EM/timing key
recovery on vulnerable impls). Bloch inherits whatever `pqcrypto-falcon 0.4`
(PQClean C) does. Mitigations (pin the commit, make Falcon the removable half,
threat-model per environment) are roadmap §2.2 — **not done**.

---

## 3. Known weaknesses (stated plainly)

1. **51%-attackable mainnet-beta.** Majority work can reorg up to 1000 blocks.
   No audit changes this; it is inherent to a low-hashrate PoW chain.
2. **k=4 regime = zero security.** The live testnet residual width is forgeable
   by design (`lib.rs:109-115`).
3. **No audit has been performed.** Anywhere. Nothing is "secure/proven/audited."
4. **No chain-id replay guard** in the tx sighash (§2.2) — testnet↔mainnet /
   cross-fork replay is not prevented at the signature level.
5. **Bespoke, load-bearing trust root with wide blast radius.** One hybrid signer
   (`bloch-crypto::crypto`) and one seeded-RNG fork underpin the chain **and**
   every Postern consumer (consiglio-auth login, seal-companion attestation). A
   bug here is systemic, not local.
6. **Classical Curve25519 still in `postern-messenger`** → HNDL on messaging
   transport (§2.5).
7. **Crypto-agility gap:** algorithm identity is implicit in fixed 1952/3309
   offsets; no suite-id; migration requires a hard fork (SPEC §10).
8. **PoW canonical `(k, β)` unproven and `β = q/16` loose;** the no-shortcut /
   attacker-asymmetry analysis is unfinished (research track).
9. **Attestation hooks in the blockchain repo are stubs** — no hardware quote
   signature is verified here (the real SEV-SNP path lives in
   `postern-seal-companion`, TDX still stubbed).
10. **Node DoS surface** (silent-death-on-panic, unbounded maps, mempool
    quadratic scan) per `roadmap-rust-systems.md` — availability threats on the
    protected liveness axis.

---

## 4. Scope for a first external audit

### 4.1 In scope (recommended)

- The **hybrid signature construction** (AND-combiner, parse-failure⇒false,
  seeded keygen) and the **seeded-RNG fork** (`crypto/mod.rs`,
  `pqcrypto-internals`).
- The **tx sighash + verification path**, including the chain-id gap
  (`core/mod.rs:869-891`, `main.rs:1750-1807`).
- The **PoW verifier** and the k-regime / SF-1 machinery (`crates/bloch-sis-pow`,
  `core/mod.rs:141-158`), audited *as hashcash* (not as a lattice-hardness claim).
- **Wire (de)serialization robustness** — no panics, no OOM, malformed⇒reject
  (block/tx/header/P2P parsers).
- **Consensus rules** — validity + GhostDAG fork choice + reorg/finality.
- **Malformed-input KATs / fuzzing** of `verify`, `Address::parse`, keyfile
  decrypt, tx deserialization (roadmap P0.7).

### 4.2 Out of scope for the first audit

- Lattice hardness of the PoW (there is no such claim to audit; it is hashcash).
- The Postern product crates (courier, messenger, vault, keys, telephony) — each
  is separately auditable later.
- The attestation/TEE quote-verification path (stubs here; real path is in
  Postern; audit after it is de-stubbed).
- The shielded/Coherence pool (formats present, verifier not turned on).
- Token economics / value assumptions (the coin is valueless — nothing to audit
  there).

### 4.3 What MUST be frozen/done before the audit starts

An audit of a moving target wastes money. Before commissioning:

1. **Freeze the wire formats** (SPEC §9): hybrid pk/sig layout, tx sighash,
   address, block/header, PoW structure. (Roadmap P0.1.)
2. **This spec + threat model** delivered (roadmap P0.2 — this pair).
3. **KATs / test vectors** for every primitive, plus official ML-DSA-65 +
   Falcon-1024 KATs run *through Bloch's wrappers* (roadmap P0.3).
4. **Decide the chain-id sighash fix** (P0.4) and either land it or explicitly
   defer it with the auditor's knowledge — it is a hard fork.
5. **Set `CANONICAL_K_ACTIVATION_HEIGHT` off the placeholder** + CI guard
   (P0.5); fix the ML-DSA/Falcon ordering comments (P0.6, SPEC §11).
6. **Fuzz corpora** checked in (P0.7).

Only after a scoped audit of the *frozen* spec+impl could Bloch honestly say
"the hybrid signature construction and PoW verifier were reviewed by <firm>
against <spec> at <commit>, findings in <report>." **Never** "secure" or
"unbreakable," and the *coin has no value* rail always stands.

---

## 5. Reporting

Security issues: private advisory flow (`SECURITY.md`) — do not open a public
issue for sensitive findings. Design/privacy concerns are in-scope and welcome.

---

*End of THREAT-MODEL-AUDIT.md. Companion: `docs/SPEC.md`.*
