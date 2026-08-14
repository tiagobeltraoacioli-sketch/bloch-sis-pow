# Bloch-SIS — security & privacy threat model

> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by
> epoch), live since 21:31:19 UTC on 2026-08-13. Kept because Genesis-4's
> opening ledger is derived from it. It is not what runs. The ownerless
> thesis was retracted
> (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
>
> The privacy table, the signature-forgery and hash-break rows, and the
> "what is NOT protected" discipline stand. The cheap-PoW-forgery row, the
> GhostDAG-Q reorg row and the malicious-miner adversary describe a chain
> that no longer produces blocks. The current threat models are
> `docs/specs/BLOCH-POS-THREAT-MODEL.md` and `-2.md`.

What Bloch-SIS protects, against whom, and — just as important — **what it does
not protect**. Organized around the two motto axes: **security** and **privacy**.
This is an honest, adversary-oriented companion to `ROADMAP.md` and
`docs/PROJECT-STATUS.md`; each row links a threat to its mitigation and the gate
that closes it.

> ## 🔴 Baseline — read first
> **At the time this was written**, the chain ran a **zero-security testnet**
> regime of the Module-SIS PoW (relaxed residual) — trivially forgeable and
> unaudited. That regime is gone: the proof-of-work chain stopped at height
> 39,918 and nothing below describes a live PoW network.
>
> **The live disclosure, for a reader today:** the security question under
> Genesis-4 is not hashrate, it is concentration: all 64 validators are run by
> one entity, 93.94% of the carryover sits at a single address, and 56.05 B of
> the 57.15 B BLOCH issued at genesis is held by the founder and the
> Foundation. One operator can halt the chain and one holder can outvote every
> other. The live transport is a point-to-point TCP full mesh with a fixed peer
> list, no discovery and no authentication, which is why a third party cannot
> yet join the network. Nothing here is audited. Everything below describes the
> *intended* posture of the Genesis-3 design and its status at the seal date.

## Positioning

Bloch-SIS is **privacy-first**: the protocol does not surveil, freeze, blacklist,
or KYC. Compliance is **opt-in at the edge** (view keys / selective disclosure),
never enforced by consensus. So "the operator" is *not* in the trust base for
privacy — there is no privileged party that can deanonymize or freeze users.

**Scope note for the live chain.** That statement is about *consensus rules*,
and it still holds: no rule grants anyone a freeze or disclosure power. It is
not a statement about *operators*. Under Genesis-4 all 64 validators are run by
one entity, so that entity today decides which transactions are proposed and
can stop the chain by stopping its machines. Censorship-resistance and
liveness are, right now, an operational promise from one party — not a
protocol guarantee.

## Assets (what we protect)

| Asset | Axis |
|---|---|
| Spending keys / funds | security |
| Consensus integrity (no double-spend, no forgery, no reorg theft) | security |
| Node & OS integrity (runs the audited code) | security |
| Transaction **amounts** | privacy |
| Transaction **sender/receiver linkage** | privacy |
| **Metadata** (originating IP, timing) | privacy |
| Long-term confidentiality vs a **quantum** adversary | both |

## Adversaries

- **Network attacker** — MITM, eclipse, partition, spam, replay.
- **Malicious miner** *(Genesis-3 only — there is no mining under Genesis-4)* —
  withhold, selfish-mine, attempt cheap PoW forgery.
- **Malicious / Byzantine node** — invalid blocks, equivocation, bad gossip.
- **Concentrated operator / holder** *(the live Genesis-4 adversary)* — the one
  entity that runs all 64 validators, and the addresses that hold the great
  majority of stakeable supply. See the baseline box: this is the adversary
  that actually matters today, and no cryptography in this document constrains
  it.
- **Chain analyst / passive surveillant** — links txs, amounts, IPs.
- **Quantum adversary** — Shor/Grover against signatures + hashes (future).
- **Supply-chain attacker** — tampered dependency, build, or release.
- **Host / infrastructure attacker** — compromises the machine the node runs on.

---

## 🔐 Security threats

*The rows below are the Genesis-3 posture. Rows marked **G3 only** describe
mechanisms — proof of work, GhostDAG-Q, the libp2p gossip layer — that the live
chain no longer runs; they are kept as the record of the chain whose ledger
Genesis-4 inherited. The live threats are stake concentration, single-operator
liveness and an unauthenticated fixed-mesh transport (see the baseline box).*

| Threat | Mitigation | Status / gate |
|---|---|---|
| **Cheap PoW forgery** (find solutions faster than intended work) — **G3 only** | SHAKE-256 hashcash target (cumulative work) + non-trivial Module-SIS structural gate (`√k·β < q`, compile-time enforced) | ⚠️ the testnet regime **was** forgeable; hardness research concluded PoW security is hash work, not lattice hardness (`legacy/research/POW-CANONICAL-frontier.md`). Retired with proof of work — there is no PoW to forge on the live chain |
| **Signature forgery** (incl. quantum) | Hybrid **Falcon-1024 ‖ ML-DSA-65** — both must verify (two lattice families) | ✅ implemented; **S2** audit pending |
| **Hash break** (incl. quantum) | SHAKE-256 / SHA3 throughout (Grover-resistant margins) | ✅ implemented |
| **Double-spend / reorg theft** — **G3 only** | GhostDAG-Q + reorg re-validation (input existence, no double-spend, value conservation, coinbase maturity) | ✅ H1 fix + tests at the seal date. Superseded: the live chain settles by Casper-style justification/finalisation **by epoch** (32 slots of 30 s = 16 min; ~32 min typical to finality, ~48 min worst case), not by accumulated work depth |
| **Block/tx malleability** | block identity binds the merkle (incl. shielded via `os`-style body root) into the PoW preimage | ✅ H2 fix + merkle-binding |
| **Eclipse / bad peers / spam** — **G3 only** | PEX hygiene, min relay fee, bounded deser, gossip block-id binding | ✅ L2/L3/M1 fixes against the G3 libp2p/PEX stack. Not the live posture: Genesis-4 runs a point-to-point TCP full mesh with a fixed peer list, no discovery and no authentication, which is why a third party cannot yet join the network. Eclipse is moot while the peer list is fixed; the cost is that the network is closed and unauthenticated |
| **Stake concentration** *(live, Genesis-4)* | none — no protocol mechanism caps a holder or an operator | ❌ **open, and the dominant risk.** All 64 validators are run by one entity; 93.94% of the carryover sits at one address (17,046,829,380 of 18,146,400,000 BLOCH); carried balances are stakeable, so if that balance stakes the Nakamoto coefficient is 1 |
| **Validator signature forgery** *(live, Genesis-4)* | hybrid **ML-DSA-65 ‖ Falcon-1024** on every consensus path — both halves verified | ✅ implemented; unaudited |
| **Malicious deser inputs** | bounded, EOF-safe parsing (capacity clamps) | ✅ M1 fix + fuzzing planned (**S2**) |
| **Supply-chain tamper** | vendored deps, committed `Cargo.lock`, reproducible build (L1, verified digest) | ✅ L1; signed releases/SLSA = **S5** |
| **Host compromise** | container hardening (L2) + attestation (L3): TEE + dm-verity `os_roothash` + image digest, checked by `verify()` | ✅ code+tests; real-hardware end-to-end = **S4** |
| **Key theft** | encrypted keystore (Argon2 + AEAD/AAD), founder wallet offline/HSM | ✅ M2/L1 fixes; founder HSM + PAT rotation = **S5** |

## 🕵️ Privacy threats

| Threat | Mitigation | Status / gate |
|---|---|---|
| **Amounts visible** | Coherence shielded pool — SHAKE-256 commitments, hidden values, ZK spend proof | ⚙️ formats + consensus done; **turn ON = P1** (node FRI verifier), audit = **P2** |
| **Sender/receiver linkage** | nullifiers + note commitments + Merkle accumulator (no on-chain link) | ⚙️ same as above (P1/P2) |
| **Metadata leak** (origin IP, timing) even when amounts are shielded | Dandelion++ (stem/fluff) + optional Tor/I2P relay | ❌ **not yet** — **P3** (a real gap: private amounts ≠ private origin) |
| **Address reuse / clustering** | diversified addresses, no reuse | ⚙️ **P4** |
| **Keys readable at rest** | encrypted-at-rest keystores in every client | ✅ node; clients = **P4** |
| **Forced disclosure / protocol backdoor** | none — disclosure is **opt-in** (view keys / selective disclosure), user-held | ✅ by design; view keys = **P4** |
| **Quantum de-anonymization** (future) | hash-based + lattice constructions only; **no elliptic-curve ZK** | ✅ by design (C1 rule) |

---

## What is NOT protected (explicit)

- **At the seal date: nothing.** Zero-security testnet — forgeable PoW,
  unaudited, no network; coins were described as worthless by design.
- **Today, on the live chain: not decentralisation, and not
  censorship-resistance.** The security question under Genesis-4 is not
  hashrate, it is concentration: all 64 validators are run by one entity,
  93.94% of the carryover sits at a single address, and 56.05 B of the 57.15 B
  BLOCH issued at genesis is held by the founder and the Foundation. One
  operator can halt the chain and one holder can outvote every other. The
  transport is an unauthenticated fixed-mesh, so a third party cannot even
  join to observe as a peer. None of this is a bug being fixed on a deadline;
  it is the current state, stated plainly.
- **Metadata**, even after P1: origin IP + timing leak until **P3** ships. Shielded
  amounts without network privacy is **half a promise** — stated plainly.
- **Unaudited paths**: consensus/crypto (S2), the shielded pool (P2), and the
  attestation chain on real hardware (S4) are all **claim-gated** — no
  guarantee until each clears. (PoW parameter hardness, S1, is moot: proof of
  work is retired.)
- **The node operator's own OS/host** below the attested image, unless run in a
  TEE (S4).
- **No "100% private" claim, ever, before C4.** No "phone mining" claim.

## Reporting

Security issues: use the private advisory flow (see `SECURITY.md`) — do **not**
open a public issue for sensitive findings. Privacy-relevant design concerns are
in-scope and welcome.
