# Bloch-SIS — roadmap

**North star: maximize security and privacy.** Everything below is ordered by how
much it moves those two axes — not by how much new surface it adds. The project
already has broad surface (node, the SIS-gated hashcash PoW, hybrid PQ signatures, attestation
L1–L3, the Coherence privacy layer, an SP1 prover, four clients, two OSes). What
it lacks is **depth**: proven hardness, a live network, audits, and privacy that
actually runs. This roadmap closes that. No dates — priorities shift with audit
findings and research.

## Positioning — privacy-first, compliance opt-in

Bloch-SIS is a **privacy-first** chain. The protocol does **not** surveil, freeze,
blacklist, or KYC. Compliance is **opt-in at the edge**: a user can *selectively
disclose* their own activity to an auditor via view keys / selective-disclosure
proofs (MatRiCT-Au-style) — the protocol itself stays blind. This reverses the
inherited "compliance-first" plan (on-chain freeze/wipe, KYC miners, AML,
sovereign freeze), which is technically incompatible with a shielded pool: a chain
either sees-and-controls (surveillance) or it does not (privacy). We choose
privacy, and put the disclosure switch in the user's hands, not the protocol's.

> **Honest baseline.** The chain is a **zero-security testnet** (relaxed PoW
> regime, unaudited, no real network). No privacy or security claim is adopted
> until its specific gate below is cleared. See `docs/PROJECT-STATUS.md`.

---

## 🔐 Security track

### S1 — Canonical PoW security claim *(the central gate)*
The default runs a relaxed testnet regime; the canonical verifier already exists
(`bloch-sis-pow::verify`). **The hardness research is done** — three independent
analyses (`docs/specs/POW-HARDNESS.md`, `deploy/pow-estimator/SCREEN-RESULTS.md`,
`docs/research/POW-CANONICAL-frontier.md`) converge on one result: **a
trapdoorless PoW cannot be both lattice-hard and mineable.** With no trapdoor,
the core-SVP cost is simultaneously the attack cost and the honest mining cost;
the estimator sweep shows every ≥100-bit point is unmineable (no short `s`
exists) and every mineable point is in the trivial q-ary regime — the regimes
are disjoint. So the honest security claim is **hashcash cumulative work on the
aux SHAKE-256 target**, with the Module-SIS residual as a **non-trivial
structural gate** (`√k·β < q`, enforced at compile time) — not a lattice
bit-security number. **Next, concrete:** (1) freeze the canonical small-`k` +
leading-zeros gate parameters (candidate `k=8`, β=q/16); (2) prove the
no-shortcut / attacker-asymmetry bound for the chosen `k` (the gate adds a
fixed rejection floor and no lattice shortcut); (3) calibrate leading-zeros
difficulty, flip the default, and write the ePrint rationale stating the
reframed claim. *Without S1, everything rides on unproven work.*

### S2 — Independent audit + fuzzing
Third-party review of: hybrid Falcon‖ML-DSA signing, the PoW, GhostDAG-Q
consensus + reorg, and serialization. Differential/continuous fuzzing of the
consensus engine, tx/block deserialization, PoW verify, and PEX. *(Carries the
inherited Sprint 12 intent — the audit gap open since day one — and remediation
of inherited findings M-2/M-3.)* Then Coherence (P2).

### S3 — Live multi-node network
Deploy ≥3 seed nodes, wire `DEFAULT_SEEDS`, and prove consensus/reorg/gossip
across nodes (today it's effectively a solo-node demo). Ship the in-process
two-`NetworkNode` convergence harness (inherited Sprint EE) and add adversarial
nodes (equivocation, invalid blocks, eclipse) to the matrix.

### S4 — Attestation on real hardware
Run the reproducible image in a real SEV-SNP/TDX confidential VM; produce a real
quote; verify the full **L1 (image digest) → OS (dm-verity `os_roothash`) → L3
(TEE)** chain end-to-end. Validates what is today code + docs.

### S5 — Supply-chain + key hygiene
`cargo-audit`, SLSA/signed releases, the vendored-dep provenance, reorg
observability metrics (`bloch_reorg_*`, inherited Sprint FF). Rotate the leaked
founder PAT; move the founder wallet to offline/HSM custody.

### S6 — On-chain k-of-n multisig custody (GIP-008)
Bloch is strictly single-signature P2PKH today — no script system, and the
~10 KB `script_sig` cap can't even hold a second ~8.5 KB hybrid co-signer — so
treasury/enterprise **M-of-N custody has no on-chain option without a consensus
change** (full analysis: `docs/research/MOFN-CUSTODY-DECISION.md`). Target
end-state: a new **descriptor-hash output type** that consensus verifies as
**k-of-n full hybrid Falcon‖ML-DSA signatures** (a 2-of-3 spend ≈ 21 KB, ~2.1%
of a 1 MB block; uses only already-audited primitives — no new crypto). This is
the roadmapped **M-8** treasury multisig, landed via **GIP-008** before any code.
Until then, custody is **procedural M-of-N** — Shamir 2-of-3 seed recovery +
dual-control disbursement, shipped in the reference mining pool. MPC **threshold**
signing (threshold ML-DSA; threshold Falcon is only a 2026 preprint, unaudited)
is a **2027+ drop-in** — its outputs verify as standard signatures, so it needs
no further consensus change — adopt only with an audited implementation.
*(Supersedes the earlier "threshold ML-DSA" framing of M-8: on-chain
multiple-signature multisig is the nearer, buildable path; MPC threshold is the
later upgrade.)* **Status: GIP-008 APPROVED (founder, 2026-07-10)** for the
on-chain k-of-n hybrid-signature descriptor-hash direction; consensus code
lands via the standard GIP activation-signaling path.

### S7 — FFG-BFT checkpoint finality overlay *(gated protocol item)*
A post-quantum BFT finality gadget that anchors **reorg-proof checkpoints** to the
base as **ordinary transactions** — an **overlay, not a base-consensus change**
(the base stays **pure PoW**). Committee = the **miners weighted by hashrate**
(work-weighted, ~120-block rotation, >2/3 quorum, co-signing with **ML-DSA** —
post-quantum, no BLS). Raises the 51%-attack safety bar to **67%** and adds
no-deep-reorg finality below that. Reclassified **into** the protocol from the
Postern product roadmap: a finality overlay has no operator, so it belongs to the
ownerless commons, not to a company. Reference scaffold exists
(`bft/postern-bft-finality` + design `docs/specs/POSTERN-FFG-BFT-FINALITY.md`) —
**not built, not deployed, no live committee.** **Honest caveat:**
hashrate-weighted finality is only as decentralized as the hashrate — concentrated
today, so effectively centralized until miners decentralize, and a >2/3-hashrate
entity still breaks it. **Gated on:** a stable ownerless base *(architecture
frozen — done)* → **k=8 PoW reactivation (S1)** → **independent audit (S2)**;
consensus-touching pieces land via a GIP with node-operator signaling.

---

## 🕵️ Privacy track (Coherence)

### P1 — Turn shielded transactions ON *(biggest privacy win available now)*
Deploy the SP1 prover (`deploy/sp1-prover`, Fly GPU) and wire the **node-side FRI
verifier**, replacing the reject-all `verify=false` stub. Flips Coherence from
tested scaffold to a **working private transaction**. Cheap, high-impact.

### P2 — Coherence external review + audit (C3/C4)
Review the note/commitment/nullifier formats, the spend circuit, and the FRI
verification path. No "private" claim until this clears.

### P3 — Network-layer metadata privacy
Even with shielded amounts, tx propagation leaks the originating IP and timing.
**Dandelion++ routing core + integration adapter done** (`src/dandelion.rs`:
stem/fluff decision, per-epoch stem successor, anti-blackhole embargo, and a
`DandelionRelay` producing `RelayAction`s for the network loop; unit-tested).
Remaining: a **unicast stem transport** (gossipsub is broadcast-only — the one
external-gated piece, best tested on a live multi-node net / S3), wire the relay
into the tx path (Fluff = gossipsub publish, works today), and an optional
**Tor/I2P** transport for the stem hops. Privacy of *amounts* without privacy of
*origin* is
half a promise.

### P4 — Wallet-level privacy + opt-in disclosure
**Diversified addresses done + wired into the wallet core**
(`crypto::diversified_{seed,keypair,address}` + `WalletCore::address_at(i)` /
`sign_at(i)`: index 0 is the base address, 1,2,… are independent, unlinkable,
spendable rotation addresses; unit-tested). Remaining: surface rotation in the
client UIs (desktop/mobile), encrypted-at-rest keystores everywhere, and
**view keys / selective disclosure** — the user's opt-in compliance switch
(MatRiCT-Au-style auditability), never a protocol backdoor. Make the private path
the default path.

### P5 — Post-audit lattice upgrade
Track the lattice-RingCT lineage (MatRiCT+/Gao) as the smaller-proof, ring-privacy
successor to the SP1/FRI spend path — adopt only after its own audit.

---

## 🧩 Enablers (serve S/P adoption, not new surface)

- **Build the OS images for real** — `nix build .#iso` / `.#attested-image` /
  `.#mobile-image` on a Nix host → bootable reproducible artifacts. The attested
  image is a *security* deliverable (S4).
- **Mobile wallet UI** — UniFFI + a native shell over `WalletCore` so the private
  wallet is usable, not just buildable.
- **Blochscan** — host the explorer against a live node (frontend exists;
  `explorer/blochscan.html`).
- **Whitepaper + threat model** — the **threat model is written**
  (`docs/THREAT-MODEL.md`: assets, adversaries, security/privacy threats →
  mitigations → gates, and what is *not* protected). Whitepaper (consolidated
  design) still pending.

## Governance & economics (unchanged principles)

- **GIP process** for any consensus-touching change (`gips/`); soft-forks
  preferred; consensus breaks need explicit activation signaling.
- **No inflation, no extra premine.** `MAX_SUPPLY` consensus-enforced from genesis;
  the 17% founder allocation (10-yr lock + 40-yr vesting) is all that exists.
- Governance lives with node operators/miners, not a discretionary foundation.

## What we will NOT do

- **No protocol-level freeze, blacklist, wipe, KYC, AML, or sovereign address
  quarantine.** These are incompatible with the shielded pool and with a
  privacy-first chain. Compliance is opt-in disclosure by the user, at the edge —
  never enforced by consensus. *(This explicitly reverses the inherited Sprint 11
  compliance-first plan.)*
- **No inflation / no premine** beyond the genesis 17%.
- **No hard-fork feature** without a GIP + node-operator signaling.
- **No misleading claims** — no "100% private", no "phone mining", no security
  claim before its gate (S1/S2/P2) clears.

## The next three moves

1. **S1 — PoW hardness** *(research in flight)* → real security foundation.
2. **P1 — node-side FRI verifier** → privacy that actually runs.
3. **S3 — multi-node network** → consensus proven beyond a single node.

Deliberately *not* next: more clients / more surface. Breadth is done; the work
now is **depth in security and privacy**.
