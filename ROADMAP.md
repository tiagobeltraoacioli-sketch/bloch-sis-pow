# Bloch-SIS — roadmap

**North star: maximize security and privacy.** Everything below is ordered by how
much it moves those two axes — not by how much new surface it adds. The project
already has broad surface (node, Module-SIS PoW, hybrid PQ signatures, attestation
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

### S1 — Canonical PoW hardness *(the central gate)*
The default runs a relaxed testnet regime; the canonical verifier already exists
(`bloch-sis-pow::verify`). **A hardness study is done** (`docs/specs/POW-HARDNESS.md`):
the PoW is Inhomogeneous-SIS (BDD/CVP), and **the current `β = q/16` is very
likely broken** — with `m=512`, `√m·β ≈ 1.41q ≥ q` puts it in the estimator's
*trivial q-ary regime* (a valid `s` is found by lattice reduction, no PoW work).
The `256×512` dimension is also too small (ML-DSA's security is from ~1024–2048
dim, not the ±2 bound). **Next, concrete:** (1) run the lattice-estimator (its
∞-norm Module-SIS example is at the same q=8380417) to pick `(n, m, β)` with
`log2(rop) ≥ 128` + a feasibility check; (2) separate difficulty (leading-zeros
knob) from the security bound β; (3) flip the default + write the ePrint rationale.
*Without S1, everything rides on unproven work.*

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
