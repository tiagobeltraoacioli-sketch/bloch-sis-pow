# Bloch-SIS Protocol — Threat Model (audit-scoping draft)

> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by
> epoch), live since 21:31:19 UTC on 2026-08-13. Kept because Genesis-4's
> opening ledger is derived from it. It is not what runs. The ownerless
> thesis was retracted
> (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
>
> §0 (Bloch protects chain-ordering integrity and liveness, not asset value)
> and the trust-boundary/parsing analysis stand. The k=4 PoW regime, the
> difficulty citations and the PoW-framed adversary classes do not.
>
> **The current threat models are `docs/specs/BLOCH-POS-THREAT-MODEL.md` and
> `docs/specs/BLOCH-POS-THREAT-MODEL-2.md`.** An auditor scoping work on the
> live chain should start there, not here. This document remains useful for
> the parts that outlived proof of work: the trust boundaries, the
> parsing/robustness posture, the vendored `pqcrypto-internals` fork, the
> Falcon side-channel question and the crypto-agility gap.

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

- **The coin is worthless by design.** *(Premise recorded as written in the
  Genesis-3 framing. ADR-036 retracted the ownerless thesis, and Genesis-4
  allocates 10 B BLOCH to VC and 5 B to liquidity, so whether this framing
  still holds is an open question for the founder to settle — it is not settled
  here, and an auditor should ask rather than assume.)* It is **not a security**, confers no
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
- **What this is NOT:** it is not a custody system, no consensus *rule* grants
  any party a freeze/seize/deanonymize power, and there is no "protect the
  money" claim to audit. **But note who runs it** — see the disclosure below;
  "no privileged party in the rules" is not the same as "no privileged party".
- **On liveness of the network itself:** when this was written there was no live
  network — the chain ran a zero-security testnet PoW regime (§2, k=4). That is
  no longer the situation in either direction: proof of work is retired, and
  Genesis-4 has been live under proof of stake since 21:31:19 UTC on
  2026-08-13, with a public read RPC at <https://posternlabs.com/g4rpc>.

**The disclosure to state to any auditor up front.** The security question
under Genesis-4 is not hashrate, it is concentration: all 64 validators are run
by one entity, 93.94% of the carryover sits at a single address, and 56.05 B of
the 57.15 B BLOCH issued at genesis is held by the founder and the Foundation.
One operator can halt the chain and one holder can outvote every other. On top
of that, the live transport is a point-to-point TCP full mesh with a fixed peer
list, no discovery and no authentication, which is why a third party cannot yet
join the network; and Deposit/Delegate transactions are refused at every node's
mempool (`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is not
yet funded from the UTXO set, so there is no permissionless path to becoming a
validator. Everything below is the *intended* Genesis-3 posture and its status
at the seal date; **no security guarantee holds today, and no audit has been
performed on either chain.**

---

## 1. Assets and trust boundaries

### 1.1 Assets (in priority order for this system's goal)

| Asset | Why it matters here | Not the asset |
|---|---|---|
| **Ordering integrity of finalized history** | the core promise. *Genesis-3 drew the line at depth:* accepted history below `CHECKPOINT_DEPTH` (1000, `core/mod.rs:79`) was not silently rewritten. **On the live chain the line is not depth at all** — Genesis-4 settles by Casper-style justification and finalisation **at epoch boundaries** (32 slots × 30 s = 16 min per epoch; ~32 min typical to finality, ~48 min worst case). An auditor who models Bloch settlement as "N blocks deep" is modelling the retired chain | — |
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

### 2.1 Block producer adversary

**Live (Genesis-4): the concentrated operator / holder.** This is the class
that replaces everything in this section. All 64 genesis validators are run by
one entity, so proposal and attestation are a single party's decision; 93.94%
of the carryover (17,046,829,380 of 18,146,400,000 BLOCH) sits at one address,
and carried balances are stakeable, so if that balance stakes the Nakamoto
coefficient is 1. There is no permissionless entry to dilute this: Deposit and
Delegate are refused at every node's mempool
(`crates/bloch-pos-node/src/engine.rs:1900-1906`). An auditor should model
censorship, halting and unilateral finalisation as *available to the operator
by construction*, and should ask what would detect it — not whether cryptography
prevents it, because it does not.

**Genesis-3 (retired — kept as the record):**

- **Cheap-PoW forgery / the k=4 regime.** At the seal date the live regime was
  `TESTNET_RESIDUAL_COEFFS = 4` — **explicitly ZERO security**
  (`lib.rs:109-115`, `src/pow/mod.rs:34-40`). Solutions were brute-force cheap;
  the structural gate contributed only a ~2¹² rejection floor. SF-1 (k→8) raised
  the floor to ~2²⁴ but **did not change the security story: security was
  cumulative SHAKE-256 hashcash work, not lattice hardness** (`lib.rs:16-26`).
  There was no lattice bit-security number at any parameter set. Moot now: there
  is no proof of work to forge.
- **51% / majority-hashrate.** Fork choice was GhostDAG on accumulated work
  (`consensus/mod.rs:32-58`, §7.2 of the spec). A majority-work adversary could
  reorg up to `CHECKPOINT_DEPTH = 1000` blocks (`core/mod.rs:79`); deeper reorgs
  were rejected. This was stated plainly at the time as "mainnet-beta is
  51%-attackable". It no longer applies — not because it was fixed, but because
  hashrate stopped being what secures the chain. The replacement risk is
  concentration, above.
- **Selfish mining / withholding / equivocation.** Standard PoW-DAG concerns;
  the reorg re-validation path (`src/reorg.rs`) re-checked input existence,
  double-spend, value conservation and coinbase maturity. Withholding and
  equivocation have proof-of-stake analogues; see
  `docs/specs/BLOCH-POS-THREAT-MODEL.md` and `-2.md`.
- **Activation-height footgun.** `CANONICAL_K_ACTIVATION_HEIGHT = 1_000_000` was a
  placeholder (`core/mod.rs:120-141`). Shipping it to mainnet, or setting it at/
  below the tip, would force a chain reset or a partition. The chain stopped at
  39,918, well below it, so this never fired.

### 2.2 Network / P2P adversary (MITM, eclipse, partition, spam, replay)

> **Scope.** The libp2p/gossipsub/mDNS and Kyber-handshake items below describe
> the Genesis-3 stack. **The live Genesis-4 transport is a point-to-point TCP
> full mesh with a fixed peer list, no discovery and no authentication, which
> is why a third party cannot yet join the network.** A libp2p module exists
> in-tree but is not what the fleet runs. So on the live chain: eclipse is moot
> (the peer set is fixed), and MITM is *unmitigated* rather than mitigated —
> there is no handshake to attack because there is no handshake. The
> resource-exhaustion and parse-robustness reasoning below is the part that
> transfers.

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

1. **One entity holds and runs everything.** The security question under
   Genesis-4 is not hashrate, it is concentration: all 64 validators are run by
   one entity, 93.94% of the carryover sits at a single address, and 56.05 B of
   the 57.15 B BLOCH issued at genesis is held by the founder and the
   Foundation. One operator can halt the chain and one holder can outvote every
   other. Carried balances are stakeable, so if the largest carryover address
   (17,046,829,380 of 18,146,400,000 BLOCH) stakes, the Nakamoto coefficient is
   1. No audit changes this; it is a distribution and operations fact, not a
   code defect. *(This slot previously read "51%-attackable mainnet-beta —
   majority work can reorg up to 1000 blocks; inherent to a low-hashrate PoW
   chain." That risk retired with proof of work at height 39,918; this is the
   one that replaced it.)*
2. **No permissionless entry, and a closed unauthenticated network.** Deposit
   and Delegate transactions are refused at every node's mempool
   (`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is not yet
   funded from the UTXO set, so there is no path for a third party to become a
   validator today. The transport is a point-to-point TCP full mesh with a fixed
   peer list, no discovery and no authentication, so a third party cannot even
   join as a peer, and on-path tampering is unaddressed by cryptography.
   Weakness 1 cannot be diluted from outside until both are changed. *(This slot
   previously read "k=4 regime = zero security — the live testnet residual width
   is forgeable by design." That regime ended with proof of work; the forgeable
   PoW is gone, and this is the structural openness gap that stands in its
   place.)*
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
   attacker-asymmetry analysis was unfinished. *Retired with proof of work —
   there is no PoW parameter set in the live system to prove anything about.*
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
- ~~The **PoW verifier** and the k-regime / SF-1 machinery
  (`crates/bloch-sis-pow`, `core/mod.rs:141-158`), audited *as hashcash*.~~
  **Retired.** In its place, for the live chain: the **proof-of-stake engine and
  the epoch finality gadget** (`crates/bloch-pos-node`,
  `crates/bloch-pos-committee`) — proposer selection, attestation weighting, and
  the justification/finalisation rule — audited under the honest assumption that
  the whole validator set is currently one operator.
- **Wire (de)serialization robustness** — no panics, no OOM, malformed⇒reject
  (block/tx/header/P2P parsers).
- **Consensus rules** — validity + fork choice + reorg/finality. *(The GhostDAG
  fork choice named in the original text is Genesis-3; the live rule is
  proposer-per-slot with Casper-style epoch justification/finalisation.)*
- **Malformed-input KATs / fuzzing** of `verify`, `Address::parse`, keyfile
  decrypt, tx deserialization (roadmap P0.7).

### 4.2 Out of scope for the first audit

- Lattice hardness of the PoW (there was no such claim to audit; it was
  hashcash — and there is no PoW at all on the live chain).
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
5. ~~**Set `CANONICAL_K_ACTIVATION_HEIGHT` off the placeholder** + CI guard
   (P0.5)~~ — moot, the PoW chain stopped at 39,918 and never reached it. Fix
   the ML-DSA/Falcon ordering comments (P0.6, SPEC §11) — still relevant, since
   the hybrid signer is on every live consensus path.
6. **Fuzz corpora** checked in (P0.7).

Only after a scoped audit of the *frozen* spec+impl could Bloch honestly say
"the hybrid signature construction and the consensus engine were reviewed by
<firm> against <spec> at <commit>, findings in <report>." **Never** "secure" or
"unbreakable," and never without the concentration disclosure alongside it: an
audit of the code says nothing about who runs the validators or who holds the
supply.

---

## 5. Reporting

Security issues: private advisory flow (`SECURITY.md`) — do not open a public
issue for sensitive findings. Design/privacy concerns are in-scope and welcome.

---

*End of THREAT-MODEL-AUDIT.md. Companion: `docs/SPEC.md`.*
