# Roadmap — gated items register

> **PARTIALLY SUPERSEDED — 2026-08-11.** This register was written for the
> Genesis-3 PoW chain and pre-dates three founder decisions that retire whole
> entries rather than their gates:
>
> - **The ownerless thesis is retracted** (ADR-036; two-entity foundation,
>   `docs/specs/BLOCH-ENTITY-STRUCTURE.md`). Every "anchors to the ownerless
>   base" framing below is stale.
> - **Genesis-3 halts at height 80,000** and Genesis-4 relaunches as PoS —
>   the k=8 PoW reactivation and FFG-BFT overlay items lose their object.
> - **EVM runs at L1, no rollup** (2026-08-11): the "EVM L2 + wBLCH bridge"
>   item is superseded — there is no separate EVM chain to bridge to.
>   Downstream items that depended on it (PosternDex) re-gate on the L1 EVM.
>
> Text kept unrewritten on purpose; read entries against the fleet brief and
> the Genesis-4 specs.

**What this is.** The honest "cannot be fleet-finished" list. Every item here is
blocked on something engineering *alone* cannot produce: a third-party audit,
real confidential-compute hardware, a live network, legal/custody sign-off, or a
research artifact (proof / ePrint). Engineering advances each item **up to** its
gate and stops; the gate is external. Nothing below may be marked "done" until
its specific gate clears.

Format: **name — gate — unblock action** (the concrete external step that lifts
the gate). Cross-refs point at `ROADMAP.md` tracks (S/P/M) and `docs/`.

---

## Security / consensus

- **k=8 PoW reactivation (S1, canonical PoW security claim)** — GATE: the relaxed
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

- **Independent audit + fuzzing (S2)** — GATE: no external security review has
  been done; the audit gap has been open since day one. UNBLOCK: engage a
  third-party auditor for hybrid Falcon‖ML-DSA signing, PoW verify, GhostDAG-Q
  consensus + reorg, and serialization; remediate inherited findings M-2/M-3;
  stand up continuous differential fuzzing. External auditor engagement is the
  gate.

- **Live multi-node network (S3)** — GATE: today it is effectively a solo-node
  demo; proving consensus/reorg/gossip needs real deployed seed infrastructure
  and an adversarial-node matrix that only runs on a live net. UNBLOCK: deploy
  ≥3 seed nodes, wire `DEFAULT_SEEDS`, run the convergence + adversarial
  (equivocation / invalid-block / eclipse) matrix across them. (Also unblocks the
  Dandelion++ unicast-stem-transport piece in P3.)

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
  signaling on a live network, which does not exist yet. UNBLOCK: implement the
  descriptor-hash output type + consensus verification, then activate via the
  standard GIP activation-signaling path once a live multi-node net (S3) exists.
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
  transport** can only be validated on a live multi-node net (gossipsub is
  broadcast-only). UNBLOCK: build the unicast stem transport and test it against
  the live net from S3 (optional Tor/I2P stem hops follow).

- **Coherence P5 — post-audit lattice upgrade** — GATE: the lattice-RingCT
  successor (MatRiCT+/Gao) is adopted only after its **own** audit. UNBLOCK:
  independent audit of the chosen lattice-RingCT construction.

## Finality overlay

- **FFG-BFT checkpoint finality overlay (S7)** — GATE: reference scaffold only
  (`bft/postern-bft-finality`, design `docs/specs/POSTERN-FFG-BFT-FINALITY.md`) —
  not built, not deployed, no live committee; a PQ (ML-DSA, no BLS)
  finality overlay anchored to the ownerless base. Chained gate: stable ownerless
  base *(architecture frozen — done)* → **k=8 PoW reactivation (S1)** →
  **independent audit (S2)**. UNBLOCK: clear S1 and S2, then land the
  consensus-touching pieces via a GIP with node-operator signaling and stand up a
  live work-weighted committee. Honest caveat: hashrate-weighted finality is only
  as decentralized as the (today concentrated) hashrate — a >2/3-hashrate entity
  still breaks it.

## Postern L2 / product surface (anchors to the ownerless base; not base protocol)

- **EVM L2 + wBLCH bridge** — GATE: a wrapped-BLCH bridge needs a security audit
  of the bridge/lock contracts and a custody model for the locked base-chain
  BLCH; neither is an engineering-only deliverable. UNBLOCK: bridge + settlement
  contract audit; defined custody (multisig/HSM/threshold) for locked BLCH; live
  base net (S3) to anchor to.

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
and STATES the gate. The gate — audit, hardware, live net, legal, or a research
proof/ePrint — is cleared off-fleet. This register exists so no gated item is
ever silently reported as finished.
