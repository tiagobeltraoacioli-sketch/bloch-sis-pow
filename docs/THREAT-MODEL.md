# Bloch-SIS — security & privacy threat model

What Bloch-SIS protects, against whom, and — just as important — **what it does
not protect**. Organized around the two motto axes: **security** and **privacy**.
This is an honest, adversary-oriented companion to `ROADMAP.md` and
`docs/PROJECT-STATUS.md`; each row links a threat to its mitigation and the gate
that closes it.

> ## 🔴 Baseline — read first
> The chain runs a **zero-security testnet** regime of the Module-SIS PoW
> (relaxed residual). It is **trivially forgeable** and **unaudited**, with **no
> live network**. Everything below describes the *intended* posture and its
> current status; **no security or privacy guarantee holds today**. Do not attach
> value.

## Positioning

Bloch-SIS is **privacy-first**: the protocol does not surveil, freeze, blacklist,
or KYC. Compliance is **opt-in at the edge** (view keys / selective disclosure),
never enforced by consensus. So "the operator" is *not* in the trust base for
privacy — there is no privileged party that can deanonymize or freeze users.

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
- **Malicious miner** — withhold, selfish-mine, attempt cheap PoW forgery.
- **Malicious / Byzantine node** — invalid blocks, equivocation, bad gossip.
- **Chain analyst / passive surveillant** — links txs, amounts, IPs.
- **Quantum adversary** — Shor/Grover against signatures + hashes (future).
- **Supply-chain attacker** — tampered dependency, build, or release.
- **Host / infrastructure attacker** — compromises the machine the node runs on.

---

## 🔐 Security threats

| Threat | Mitigation | Status / gate |
|---|---|---|
| **Cheap PoW forgery** (find solutions faster than intended work) | SHAKE-256 hashcash target (cumulative work) + non-trivial Module-SIS structural gate (`√k·β < q`, compile-time enforced) | ⚠️ **testnet regime is forgeable**; hardness research concluded PoW security is hash work, not lattice hardness (`docs/research/POW-CANONICAL-frontier.md`) — canonical gate params + no-shortcut proof = **S1** |
| **Signature forgery** (incl. quantum) | Hybrid **Falcon-1024 ‖ ML-DSA-65** — both must verify (two lattice families) | ✅ implemented; **S2** audit pending |
| **Hash break** (incl. quantum) | SHAKE-256 / SHA3 throughout (Grover-resistant margins) | ✅ implemented |
| **Double-spend / reorg theft** | GhostDAG-Q + reorg re-validation (input existence, no double-spend, value conservation, coinbase maturity) | ✅ H1 fix + tests; **S2/S3** (audit + live multi-node) |
| **Block/tx malleability** | block identity binds the merkle (incl. shielded via `os`-style body root) into the PoW preimage | ✅ H2 fix + merkle-binding |
| **Eclipse / bad peers / spam** | PEX hygiene, min relay fee, bounded deser, gossip block-id binding | ✅ L2/L3/M1 fixes; **S3** adversarial-node matrix |
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

- **Today: nothing.** Zero-security testnet — forgeable PoW, unaudited, no
  network. Coins are worthless by design.
- **Metadata**, even after P1: origin IP + timing leak until **P3** ships. Shielded
  amounts without network privacy is **half a promise** — stated plainly.
- **Unaudited paths**: PoW parameter hardness (S1), consensus/crypto (S2), the
  shielded pool (P2), and the attestation chain on real hardware (S4) are all
  **claim-gated** — no guarantee until each clears.
- **The node operator's own OS/host** below the attested image, unless run in a
  TEE (S4).
- **No "100% private" claim, ever, before C4.** No "phone mining" claim.

## Reporting

Security issues: use the private advisory flow (see `SECURITY.md`) — do **not**
open a public issue for sensitive findings. Privacy-relevant design concerns are
in-scope and welcome.
