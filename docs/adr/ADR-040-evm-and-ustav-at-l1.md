<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ADR-040 — EVM at L1 with no L2, and Ustav at L1

- **Status:** Accepted in direction (founder decision, 2026-08-11) —
  **design and consequences under development**; the execution vehicle is
  `docs/specs/BLOCH-L1-EXECUTION-PLAN.md`.
  **Not built (2026-08-14).** Genesis-4 launched on 2026-08-13 **without an
  EVM and without Ustav at L1**. `crates/bloch-pos-node` references `euvm`
  zero times and neither PoS crate has an euvm dependency; the header carries
  an `EvmCommitment` that is **carried, never recomputed**
  (`interfaces.rs` `StateRoots::evm`), i.e. a reserved slot, not an
  execution layer. Nothing in this ADR is running.
- **Relates to:** `docs/FLEET-BRIEF-2026-08-11.md` (the framing of record),
  `crates/bloch-euvm` (Ustav/Kirpich as they exist today),
  `bloch-l2-evm` (chainId 8400 — the service being replaced),
  `BLOCH-POS-NODE-INTEGRATION.md`

## Context

Two arrangements stood before this decision:

- **EVM execution lived beside the chain, not on it.** `bloch-l2-evm`
  (chainId 8400) is a separate always-on service; the L1's execution layer
  is the eUTXO VM (`bloch-euvm`), consensus-wired at Genesis-3 height 0.
- **Ustav and Kirpich were tooling, not consensus.** Ustav is the PSTRN-1
  token-charter standard; Kirpich is its fail-closed charter-audit gate.
  Both are publicly described as Postern reference tooling built on
  `bloch-euvm` — "reference/tooling, not consensus rules".

The founder's instruction of 2026-08-11 changes both: Bloch runs EVM **at
the base layer**, not as a rollup — `bloch-l2-evm` is the thing being
replaced, not extended — and the Ustav charter is **promoted to a consensus
object**, validated by every node rather than enforced by convention.

**Premise correction, recorded so it is not repeated.** The instruction came
with "Solana is natively EVM". It is not: Solana runs the SVM over SBF
bytecode, and EVM on Solana exists only through Neon EVM, a separately
deployed program. What Solana *does* have — and what the instruction
actually means — is **one global state machine at L1 with no rollups**:
everything native, one fee market, one state. That is the design target.
Solana must not be cited as EVM precedent in any document.

## Decision

1. **EVM at L1.** Genesis-4 executes EVM at the base layer. There is no
   rollup, no separate sequencer, no second fee market. `bloch-l2-evm` is
   sunset by replacement.
2. **Ustav at L1.** The PSTRN-1 charter becomes a consensus object: charter
   rules are validated by every node, and charter state is
   fork-choice-relevant. Kirpich's gate semantics become the model for that
   validation rather than remaining an off-chain audit step.

## What is decided, and what deliberately is not

The decision is **direction only**. The following are explicitly *not*
decided, and nobody is authorised to pick them silently:

- **The authorization model — the hard problem.** All EVM tooling signs
  secp256k1 and recovers the sender from the signature; Bloch's base
  signature suite is ML-DSA-65 ‖ Falcon-1024 — not recoverable, ~4.6 KB per
  signature, no hardware-wallet support. "EVM at L1" therefore forces one
  of three choices, each with a real cost: (a) accept secp256k1 accounts at
  L1 — cheapest adoption, but it installs a quantum-vulnerable
  authorisation path in the chain whose reason to exist is not having one;
  (b) PQ-only accounts with EVM semantics — keeps the thesis, forfeits
  MetaMask and every unported tool; (c) both, with the dual-authorisation
  consequences made explicit, including what a quantum adversary can take
  from the secp256k1 side and whether that contaminates the PQ side. All
  three must be priced, one recommended, and **the founder decides**
  (gate E0 of the execution plan).
- **State coexistence**: how an account-model state lives beside the eUTXO
  base and the C1-frozen Coherence pool.
- **The closed `StateRoots` list**: what the EVM and charter state add to
  the committed component list, coordinated with the already-pending
  extension flagged in `transition.rs` (see the execution plan's single
  re-freeze rule).
- **Gas versus the V4 fee model** (fees burn during emission, then flow to
  validators — one fee market is the point of L1-native execution).
- **The fate of `bloch-euvm`**: survives beside the EVM, is absorbed, or
  dies. This also bounds what "Ustav at L1" binds to — a charter that
  governs only eUTXO assets while EVM tokens exist unbound would be
  bypassable, which defeats the promotion's purpose.
- **For Ustav specifically**: the exchange being made must be stated in the
  spec that lands — what is gained (a charter that cannot be bypassed by
  talking to the contract directly) against what is bought (consensus
  surface, upgrade rigidity, and the fact that a token issuer's charter
  mistake becomes every node's validation cost — a charter bug is a chain
  bug). An explicit charter upgrade story is a precondition for consensus
  wiring, not an afterthought.

## Consequences

**Being designed, not invented here.** The sequencing, ownership and
dependency structure live in `docs/specs/BLOCH-L1-EXECUTION-PLAN.md`; the
open questions above are its decision gates. This ADR should be amended in
place (repo convention — cf. ADR-035's amendment note) when the
authorization decision (E0) lands, since that decision determines the
security posture of the whole direction.
