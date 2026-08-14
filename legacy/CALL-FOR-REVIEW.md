# Reviewers & testers wanted: run a node, break the PoW, review the design

> **Historical — Genesis-3. Do not repost.** This describes the proof-of-work
> chain that stopped permanently at height **39,918** on **2026-08-13**. The
> live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs,
> finality by epoch), live since 21:31:19 UTC that day. Kept because Genesis-4's
> opening ledger is derived from Genesis-3. It is not what runs, and nothing
> below is a live call for anything: there is no PoW to break, no mining to
> test, and no node a third party can currently join (the transport has a fixed
> peer list and no discovery).
>
> Two further corrections to the text below. The **ownerless thesis was
> retracted** (ADR-036 — Bloch has an issuer and a two-entity foundation
> structure, `docs/specs/BLOCH-ENTITY-STRUCTURE.md`). And the halt height cited
> in the earlier version of this banner (80,000) was never reached; the
> terminal-height rule was later lowered to 50,000 and the chain in fact stopped
> at 39,918.

> This is the canonical, repo-persistent version of the "reviewers wanted"
> call. Post it verbatim as a GitLab issue / Discussion (and to the external
> channels: Bitcointalk Dev board, r/cryptography, an IACR ePrint) — keeping
> every caveat intact.

Bloch-SIS-PoW is an ownerless, open-source, post-quantum pure-PoW BlockDAG:
SHAKE-256 hashcash coupled to a Module-SIS structural gate, ASERT-Lattice
per-block difficulty (~30 s), PHANTOM/GhostDAG-Q ordering, and Falcon‖ML-DSA
hybrid signatures. We are looking for people to test it and try to break it.

**This is a request for review and testing — not for mining-for-profit and
not for buying anything.**

## ⚠️ Honest status first

*(Written for Genesis-3. The unaudited / not-a-security / no-value statements
still hold. The network claims do not: under Genesis-4 the security question is
not hashrate but concentration — all 64 validators are run by one entity, 93.94%
of the carryover sits at a single address, and 56.05 B of the 57.15 B BLOCH
issued at genesis is held by the founder and the Foundation. One operator can
halt the chain and one holder can outvote every other. The "17% founder premine"
below is tokenomics V2; under Genesis-4 the founder holds 27.04% of the 100 B
cap.)*

This is **mainnet-beta, unaudited, experimental research software**. The coin
is **worth nothing by design** — no token sale, no listing, no price, ever;
it is not a security or an asset. The network is small and **51%-attackable**,
and the current **relaxed k=4** regime of the Module-SIS gate is **cheaply
forgeable** (a k=8 hardening was reverted because raising k without a matched
hashcash-difficulty drop made mining ~4096× harder and stalled the chain; it
will re-activate with a coupled difficulty fix). There is a fully disclosed
**17% founder premine** (10-year cliff, 40-year on-chain vesting, structurally
passive — no governance or protocol power, zero sale/listing). Full mainnet
security is gated on a concrete-security analysis of the canonical PoW
parameters (lattice-estimator class), an IACR ePrint for open review, and a
third-party audit — **none of which exist yet**. Nothing here is financial or
legal advice.

That is exactly why we are posting this: the design needs adversarial eyes
before those gates can be passed honestly.

## What we are asking for

### 1. Node operators — run it and report what breaks

Follow the quickstart in the [README](../README.md): build from the repo and
run `bloch --mine` (solo mining is the default; no pool needed). Report
stability, sync, and peering issues — crashes, stalls, forks your node
disagrees about, reorg weirdness, resource blowups. The explorer
(https://posternlabs.com/explorer) and the public demo node's JSON-RPC
(https://blochv-node.fly.dev) are useful for cross-checking what your node
sees.

### 2. Cryptographers — does the Module-SIS gate add anything?

The PoW is SHAKE-256 hashcash plus a Module-SIS structural gate: `k` residual
coefficients, acceptance ≈ `(2β/q)^k`, currently at the relaxed k=4. The
questions we most want answered:

- Does the gate add real hardness **on top of** hashcash, or is it (at any
  parameterization) just a constant-factor acceptance filter an attacker can
  route around?
- What **canonical parameters** (k, β, q, module rank) would make forging the
  gate reduce to a genuinely hard SIS instance — and what does a
  lattice-estimator-class concrete-security analysis say about them?
- How should k and the hashcash difficulty be **coupled** so hardening the
  gate doesn't stall the chain (the failure mode that forced the k=8 revert)?

### 3. Attackers — please try to break it

- Cheaply forge blocks under the current relaxed regime (we believe you can —
  show us how cheaply, and whether it survives hardening).
- Find **amortization or precompute** attacks on the derived SIS instance:
  reusable structure across blocks, batching, trapdoors in the derivation.
- Attempt **51% and selfish-mining** strategies against the
  PHANTOM/GhostDAG-Q DAG ordering and the ASERT-Lattice per-block difficulty.

Write-ups, PoCs, and even half-finished attack sketches are all welcome —
open an issue or reply here. There is no bug bounty (there is no treasury and
the coin has no price); the payoff is a broken-or-hardened design in public.

### What this is not

Not an invitation to mine for profit, buy anything, or speculate. If you want
to point hashrate at it for testing, solo (`bloch --mine`) is preferred; the
one independent reference pool (https://posternpool.com, stratum
`posternpool.com:3335`, 0% fee) exists for convenience, but pools centralize
and a >51% pool is itself an attack vector.

**Links:** repo https://gitlab.com/blochsispow-group/BlochSISPoW-project ·
site https://posternlabs.com · explorer https://posternlabs.com/explorer ·
demo RPC https://blochv-node.fly.dev
