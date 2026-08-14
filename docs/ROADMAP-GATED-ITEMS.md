# Roadmap — gated items register

> **Historical — Genesis-3.** This register was written for the proof-of-work
> chain that stopped permanently at height 39,918 on 2026-08-13. The live
> chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality
> by epoch). Kept because Genesis-4's opening ledger is derived from it. It is
> not what runs.
>
> Three decisions retire whole entries below rather than their gates:
>
> - **The ownerless thesis is retracted** (ADR-036; two-entity foundation,
>   `docs/specs/BLOCH-ENTITY-STRUCTURE.md`). Every "anchors to the ownerless
>   base" framing below is stale.
> - **Genesis-3 stopped at height 39,918** — not the 80,000 this register
>   previously named, and not the 50,000 that appears in branch names; both
>   were planned ceilings the chain never reached. Genesis-4 relaunched as
>   PoS, so the k=8 PoW reactivation item loses its object entirely and the
>   FFG-BFT overlay item is **superseded by shipped Casper finality**.
> - **EVM runs at L1, no rollup** (2026-08-11): the "EVM L2 + wBLCH bridge"
>   item is superseded — there is no separate EVM chain to bridge to.
>   Downstream items that depended on it (PosternDex) re-gate on the L1 EVM.
>
> Entries whose *factual* claims about the live network were wrong have been
> corrected in place and marked; the rest is kept unrewritten on purpose. Read
> against the fleet brief and the Genesis-4 specs.

**What this is.** The honest "cannot be fleet-finished" list. Every item here is
blocked on something engineering *alone* cannot produce: a third-party audit,
real confidential-compute hardware, an *open* network, legal/custody sign-off, or
a research artifact (proof / ePrint). Engineering advances each item **up to**
its gate and stops; the gate is external. Nothing below may be marked "done"
until its specific gate clears.

**One gate has changed shape and must not be misread.** "A live network does not
exist" was true when this was written and is **false now**: Genesis-4 is live
under proof of stake, 64 validators finalising by epoch. What does not exist is
an **open** network — the live transport is a point-to-point TCP full mesh with a
fixed peer list, no discovery and no authentication, which is why a third party
cannot yet join, and Deposit/Delegate are refused at every node's mempool
(`crates/bloch-pos-node/src/engine.rs:1900-1906`) so no third party can become a
validator. Items below that were gated on "a live net" are re-gated on that.

Format: **name — gate — unblock action** (the concrete external step that lifts
the gate). Cross-refs point at `ROADMAP.md` tracks (S/P/M) and `docs/`.

---

## Security / consensus

- **k=8 PoW reactivation (S1, canonical PoW security claim)** — **RETIRED, not
  gated.** Proof of work ended with Genesis-3 at height 39,918; there is no PoW
  in the live consensus, so this item has no object. **What replaced its risk:**
  the security question under Genesis-4 is not hashrate, it is concentration —
  all 64 validators are run by one entity, 93.94 % of the carryover sits at a
  single address, and 56.05 B of the 57.15 B BLOCH issued at genesis is held by
  the founder and the Foundation. One operator can halt the chain and one holder
  can outvote every other. That is not gated on an external artifact; it is
  gated on distribution decisions. The original entry follows as a record.
  *(Historical)* GATE: the relaxed
  testnet difficulty regime cannot be flipped to canonical without (a) a
  no-shortcut / attacker-asymmetry proof for the chosen small-`k` gate and (b)
  independent cryptographic review of it — neither is producible by coding alone.
  UNBLOCK: freeze the canonical `k=8`, β=q/16 leading-zeros gate parameters;
  produce the no-shortcut / rejection-floor proof for `k=8`; calibrate the
  matched difficulty cut (leading-zeros target) so honest mineability is
  preserved; publish the ePrint restating the reframed claim (hashcash cumulative
  work on the aux SHAKE-256 target + Module-SIS residual as a structural gate,
  NOT a lattice bit-security number); obtain third-party audit of the reframed
  claim. Refs: `legacy/specs/POW-HARDNESS.md`, `deploy/pow-estimator/`,
  `legacy/research/POW-CANONICAL-frontier.md`.

- **Independent audit + fuzzing (S2)** — GATE: **no external security review has
  been completed**; the audit gap has been open since day one and the consensus
  mechanism changed underneath it. UNBLOCK: engage a third-party auditor for
  hybrid ML-DSA-65 ‖ Falcon-1024 signing, the Genesis-4 slot/epoch consensus
  (justification, finalisation, LMD-GHOST fork choice, committee sampling), the
  unauthenticated live transport, PoS mempool admission, and serialization;
  remediate inherited findings M-2/M-3; stand up continuous differential
  fuzzing. External auditor engagement is the gate. *(The Genesis-3 scope — PoW
  verify, GhostDAG-Q consensus + reorg — is retired with the chain.)*

- **Open multi-operator network (S3)** — **the gate moved; do not read this as
  "there is no network".** Genesis-4 **is live**: 64 validators, 30 s slots,
  32-slot epochs, finalising by epoch since 2026-08-13 21:31:19 UTC. What does
  not exist is a network anyone else can join or a set anyone else can validate
  in: the live transport is a point-to-point TCP full mesh with a fixed peer
  list, no discovery and no authentication, and Deposit/Delegate are refused at
  every node's mempool because bonding is not funded from the UTXO set. So the
  adversarial matrix that matters cannot be run — every node in it would still
  be ours. UNBLOCK: (a) an authenticated, discoverable transport a stranger can
  dial; (b) UTXO-funded bonding so deposits and delegations are accepted (a
  wire-format change needing a flag day); (c) ≥3 **independent operators**
  running validators; (d) then the convergence + adversarial (equivocation /
  invalid-block / eclipse) matrix across them. (Also unblocks the Dandelion++
  unicast-stem-transport piece in P3.)

- **Attestation on real hardware (S4 / Node ISO + Seal + Chiostro first boot)** —
  GATE: the attestation chain (L1 image digest → OS dm-verity `os_roothash` →
  L3 TEE) is code + docs only; a real quote requires booting the reproducible
  image on genuine **SEV-SNP / TDX** confidential-compute hardware, which is not
  available in the fleet. UNBLOCK: boot the reproducible image in a real
  SEV-SNP/TDX confidential VM (Graviton/host with the silicon), generate a real
  attestation quote, and verify the full L1→OS→L3 chain end-to-end against it.
  Hardware access is the gate.

- **Supply-chain + key hygiene (S5)** — GATE: signed-release provenance and
  custody hardening need out-of-band key material and operator action, not just
  code. UNBLOCK: rotate the leaked founder PAT; move the founder wallet to
  offline/HSM custody; stand up SLSA/signed releases + `cargo-audit` in CI.
  (Founder/operator action + HSM procurement are the gate.)

- **On-chain k-of-n multisig custody (S6 / GIP-008, M-8)** — GATE: consensus
  change (new descriptor-hash output type verifying k-of-n hybrid
  Falcon‖ML-DSA); GIP-008 is APPROVED but activation rides node-operator
  signaling, and every node on the live network is operated by the same entity,
  so "signaling" would be one party agreeing with itself — the mechanism cannot
  mean anything until S3's *open* gate clears. UNBLOCK: implement the
  descriptor-hash output type + consensus verification, then activate via the
  standard GIP activation-signaling path once independent operators exist (S3).
  Threshold-signing (threshold Falcon) drop-in stays gated on an *audited*
  implementation (2026 preprint only today). Ref:
  `docs/research/MOFN-CUSTODY-DECISION.md`.

## Privacy (Coherence)

- **Coherence P1 — turn shielded transactions ON (node-side FRI verifier)** —
  GATE: the node ships a reject-all `verify=false` stub; flipping it to a real
  FRI verifier requires the SP1 prover deployed on GPU infrastructure and the
  verifier wired into the reorg/verification path — a deploy + integration gate
  beyond writing the verifier. UNBLOCK: deploy the SP1 prover
  (`deploy/sp1-prover`, Fly GPU), wire the node-side FRI verifier replacing the
  stub, and connect it into the block-verify / reorg wiring. (Any "private"
  *claim* additionally waits on P2 below.)

- **Coherence P2 — external review + audit (C3/C4)** — GATE: no "private" claim
  is adopted until the note/commitment/nullifier formats, spend circuit, and FRI
  verification path clear third-party audit. UNBLOCK: external cryptographic
  audit of the Coherence spend path.

- **Coherence P3 — network-layer metadata privacy (Dandelion++ stem transport)**
  — GATE: the routing core is done and unit-tested, but a **unicast stem
  transport** can only be validated on a net with independent peers. Note the
  premise has changed: the live Genesis-4 transport is **not** gossipsub — it is
  a fixed-peer TCP full mesh where every node sends to every node, which is the
  worst possible substrate for stem privacy and admits no outside relay at all.
  (The gossipsub/libp2p stack exists in-tree but is not what the fleet runs.)
  UNBLOCK: build the unicast stem transport and test it against the open,
  multi-operator net from S3 (optional Tor/I2P stem hops follow).

- **Coherence P5 — post-audit lattice upgrade** — GATE: the lattice-RingCT
  successor (MatRiCT+/Gao) is adopted only after its **own** audit. UNBLOCK:
  independent audit of the chosen lattice-RingCT construction.

## Finality

- **Casper-style epoch finality — SHIPPED AND LIVE. This entry is no longer
  gated.** It is not an overlay on proof of work; it is the Genesis-4 consensus
  itself. 30 s slots, 32 slots per epoch, `COMMITTEE_SIZE = 128` voting at each
  epoch boundary for justification and finalisation, `SLOT_SUBCOMMITTEE_SIZE = 8`
  per slot for LMD-GHOST fork-choice weight, hybrid **ML-DSA-65 ‖ Falcon-1024**
  (no BLS) on every consensus path
  (`crates/bloch-pos-committee/src/params.rs`). Typical finality ~32 minutes,
  ~48 minutes worst case. The chain has finalised on this since 2026-08-13
  21:31:19 UTC.

  **Honest caveat — this is the substitution for the old hashrate caveat.**
  Finality is only as decentralized as the *stake*, and the stake is
  concentrated: all 64 validators are run by one entity, 93.94 % of the
  carryover sits at a single address (17,046,829,380 of 18,146,400,000 BLOCH,
  `LARGEST_CARRYOVER_ADDRESS_BLOCH`), and 56.05 B of the 57.15 B BLOCH issued at
  genesis is held by the founder and the Foundation. Carried balances are
  stakeable, so a Nakamoto coefficient of 1 is reachable. **One operator can
  halt the chain and one holder can outvote every other** — a >1/3 stake absence
  stops finality and >2/3 decides it outright, and both thresholds sit inside
  one entity today. What remains genuinely gated: **independent audit (S2)**, a
  **slashing-evidence pipeline** (equivocation is defined but nothing live
  collects, proves or punishes it), and independent operators (S3) without which
  "committee" and "operator" are the same word.

  *(Historical: the FFG-BFT checkpoint overlay
  `bft/postern-bft-finality` / `docs/specs/POSTERN-FFG-BFT-FINALITY.md` was
  designed as a PQ finality layer on top of proof of work, chained behind k=8
  reactivation. Proof of work is retired; the design was superseded by native
  PoS finality rather than deployed.)*

## Postern L2 / product surface (anchors to the base chain; not base protocol)

*The "ownerless base" framing here is retracted (ADR-036): Genesis-4 has an
issuer and a two-entity foundation structure. Read "ownerless base" below as
"the base chain".*

- **EVM L2 + wBLCH bridge** — GATE: a wrapped-BLCH bridge needs a security audit
  of the bridge/lock contracts and a custody model for the locked base-chain
  BLCH; neither is an engineering-only deliverable. UNBLOCK: bridge + settlement
  contract audit; defined custody (multisig/HSM/threshold) for locked BLCH; an
  **open** base net (S3) to anchor to — the base chain is live, but a bridge
  whose counterparty set is a single operator is a custody arrangement, not a
  bridge. **Superseded in shape anyway:** the EVM runs at L1, so there is no
  separate EVM chain to bridge to (2026-08-11).

- **PosternDex** — GATE: DEX contracts require an independent smart-contract
  audit before handling value; depends on the EVM L2 + wBLCH bridge above.
  UNBLOCK: smart-contract audit + the audited bridge/custody prerequisites. Ref:
  `docs/specs/POSTERNDEX-BRIDGE-DESIGN.md`.

- **RWA / BaaS product lines** — GATE: real-world-asset and
  bank/business-as-a-service offerings are gated on **legal + regulatory**
  sign-off (securities, licensing, KYC/AML at the edge) and custody
  arrangements — outside engineering entirely. UNBLOCK: legal/regulatory review
  and licensing per jurisdiction; audited custody; then integration.

- **Kalinov Bridge** — GATE: cross-chain bridge — audit + custody + legal, same
  class of external sign-off as the wBLCH bridge. UNBLOCK: bridge contract audit,
  defined custody for bridged assets, and legal review of the cross-chain flow.

---

**Rule of engagement.** For every item above, engineering builds and lands
everything *before* the gate (specs, scaffolds, verifiers, contracts, harnesses)
and STATES the gate. The gate — audit, hardware, an **open** net, legal, or a
research proof/ePrint — is cleared off-fleet. This register exists so no gated
item is ever silently reported as finished; the same rule forbids reporting a
gate as un-cleared when it has in fact cleared, which is why the finality entry
above now reads SHIPPED and the "no live network" premise has been corrected.
