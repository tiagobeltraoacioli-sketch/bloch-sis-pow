# Decision memo — M-of-N custody for Bloch-SIS-PoW

> **Historical — written against the proof-of-work chain.** This memo is dated
> **2026-07-10** and its §2 ("What Bloch's code actually supports **today**")
> describes **Genesis-3**, the proof-of-work chain, which stopped permanently
> at height **39,918 on 2026-08-13**. The live chain is **Genesis-4, proof of
> stake** (30 s slots, 32-slot epochs, finality by epoch), whose transaction
> set, script model and node are different code
> (`crates/bloch-pos-committee`, `crates/bloch-pos-node`). **Do not read §2 as
> a description of what the live chain supports** — in particular, the
> Genesis-3 `script_sig` layout, the 10,000-byte cap, the `parse_script_sig`
> path and the `src/main.rs` validation sites it cites are Genesis-3 code, and
> the reference mining pool it plans for no longer has a chain to serve.
>
> What survives the transition intact, and is why the memo is kept: the
> **cryptographic** argument. Bloch still requires **both** ML-DSA-65 and
> Falcon-1024 to verify on every signature, so threshold/MPC signing remains
> blocked on threshold Falcon; the seed-derived keygen that makes Shamir
> sharing of a 32-byte seed the right shape is unchanged; and the conclusion —
> that production PQ threshold signing does not exist in audited form and
> anyone selling it as settled is overclaiming — stands. The **implementation
> path** (a new output type, a raised script_sig cap, GIP-008) would have to be
> re-derived against the Genesis-4 transaction set, not against the code cited
> below. Custody of the founder and Foundation genesis keys is a separate,
> currently unresolved question — see `docs/specs/BLOCH-GENESIS-KEYS.md`
> (DRAFT) and `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md` §4 item 3.

**To:** Founder
**From:** Cryptography-architecture advisor
**Date:** 2026-07-10
**Decision:** How to do M-of-N custody on a chain whose signatures are hybrid **Falcon-1024 ‖ ML-DSA-65** (both must verify)
**Scope:** (a) the reference mining pool, (b) enterprise / escrow custody (Chiave dual-control context)

---

## TL;DR recommendation

**For the reference pool, ship now:** no cryptographic threshold at all — keep the daemon keyless (it already is), minimize the custodied balance with frequent disbursement, put the single operator wallet seed behind an **operational M-of-N**: 2-of-3 Shamir shards of the 32-byte wallet seed for recovery, plus a dual-control payout procedure (two humans to unlock the signing box). **For enterprise/escrow, the target end-state is consensus-level on-chain k-of-n multisig of full hybrid signatures** — a new output type (fits the already-roadmapped M-8 / GIP-008 treasury multisig) where spending requires M independent Falcon‖ML-DSA signatures verified by the existing verifier. This is the only M-of-N that removes the single point of compromise at signing using **only primitives Bloch already trusts**, at a cost of ~8.5 KB per co-signer per input — affordable at Bloch's block size and volume. Threshold-MPC lattice signing (Quorus/Mithril-style threshold ML-DSA, and the brand-new threshold-Falcon work) is real research but has **zero audited production implementations in 2026**; treat it as a future drop-in optimization, not a dependency.

---

## 1. Why the PQ constraint changes the answer

On a classical chain, this memo would be one line: "use FROST (Schnorr threshold) or MuSig2; output is a standard single signature; done." None of that transfers:

- **FROST / MuSig2 / ROAST** exploit the linear structure of Schnorr over an elliptic-curve group. Falcon and ML-DSA have no such clean linearity: ML-DSA (Dilithium) is Fiat–Shamir-with-aborts over module lattices, and naive Shamir-style interpolation blows up the short-vector norms the scheme depends on — the classic obstacle documented across the threshold-lattice literature. **Not applicable.**
- **ECDSA-MPC (GG18/GG20/CMP, Lindell)** is bespoke machinery for ECDSA's multiplicative nonce structure. **Not applicable.**
- **Falcon is the hard half.** Falcon signing is high-dimensional Gaussian sampling over an NTRU lattice via fast-Fourier orthogonalization on double-precision floats — ~72% of signing time, per-coefficient variable means/variances, and notoriously side-channel-sensitive. Distributing that sampler among mutually distrusting parties is the open problem of the field; nearly every "threshold lattice signature" paper sidesteps it by inventing a *new* threshold-friendly scheme instead. The first serious attempt to thresholdize *standardized* Falcon (Garg & Escudero, ePrint 2026/1300) appeared **this year** as a preprint.
- **The hybrid doubles the difficulty.** Bloch requires *both* signatures on every spend (`crates/bloch-crypto/src/crypto/mod.rs:102-131` — verify splits the blob and returns false unless ML-DSA *and* Falcon verify). A threshold-ML-DSA breakthrough alone is not enough; you need threshold Falcon **on the same message, in the same ceremony**, or you have no threshold signing at all. This is the price of defence-in-depth across two lattice families, and it is worth stating plainly: *the hybrid that protects the consensus path is exactly what makes MPC custody bleeding-edge.*

Consequence: in 2026, "cryptographic threshold signing" is not a shippable answer for Bloch. M-of-N must come from either **multiple independent full signatures** (on-chain multisig) or **operational/procedural M-of-N around whole keys**.

---

## 2. What Bloch's code actually supports today

**On-chain multisig: NO. The chain is strictly single-signature P2PKH-style.** Evidence:

| Fact | Evidence |
|---|---|
| One `(sig, pubkey)` pair per input, nothing else | `crates/bloch-crypto/src/core/mod.rs:577` ("script_sig encoding: [4B sig_len][sig][4B pubkey_len][pubkey]") and `parse_script_sig` at `core/mod.rs:858-870` — parses exactly one pair, returns `None` otherwise |
| No script interpreter, no opcodes, no threshold logic | grep for `OP_`/script evaluation across `src/` and `crates/` finds nothing; `script_pubkey` is a bare 20-byte hash (`core/mod.rs:586-590`, `address.rs:100`) |
| Consensus validation is hash-match + single hybrid verify | `src/main.rs:1720-1736` (`validate_tx_inputs`): parse one pair → `SHA3-256(pk)[..20] == script_pubkey` → `crypto::verify(pk, sighash, sig)`. That's the entire authorization model |
| Wire format caps `script_sig` at **10,000 bytes** | `core/mod.rs:771` (`from_stratum_bytes`). One hybrid pair is ~8,524 B (sig ≤4,771 + pk 3,745 + 8 B lengths, per `core/mod.rs:91-93`), so a second co-signer **cannot even be encoded** today |
| Sighash excludes all script_sigs | `core/mod.rs:819-823` — good news: every co-signer would sign the *same* digest, so k-of-n is structurally clean to add |
| Multisig is already on the roadmap, unbuilt | `docs/releases/v0.5.11.md:296-298` — "M-8 — treasury multisig with M-of-N threshold ML-DSA and timelock… Requires GIP-008 before code lands" |

**Pool custody today:** the pool daemon is deliberately keyless — credits are ledger entries and "disbursing credits is a wallet transaction the pool operator makes… This reference implements the accounting, not custody automation" (`pool/src/payout.rs:20-23`; `pool/README.md:125-126`; the daemon takes only a `pool_address` string, `pool/src/main.rs:33`). So the single point of theft/loss is the **operator's wallet key**, outside the daemon. The tokenomics advisor already flagged this custody exposure and the direct-coinbase-payout alternative (`pool/docs/advisor-tokenomics.md:293-298`).

**One codebase gift:** keygen is deterministic from a 32-byte seed (`crypto/mod.rs:62-87`). That means Shamir sharing should target the **seed**, not the ~7 KB of raw lattice secret keys — shard 32 bytes, re-derive the hybrid keypair on reconstruction. (Respect the caveat at `crypto/mod.rs:49-55`: pin the `pqcrypto-mldsa`/`pqcrypto-falcon` versions in the shard metadata, since an upstream keygen change breaks seed→key reproducibility.)

**Bottom line:** on-chain M-of-N requires a consensus + wire-format change (new output type, raised script_sig cap). Everything shippable *today* is off-chain.

---

## 3. Options table

| Technique | PQ-compatible? | Maturity / audit (2026) | On/off-chain | Single point of compromise at signing? | Cost to Bloch | Tx-size / perf impact |
|---|---|---|---|---|---|---|
| **1. On-chain k-of-n multisig** (M independent hybrid sigs, new output type) | **Yes** — just M runs of the existing verifier | Primitives already audited in-tree; only the *composition* is new. Needs GIP-008, consensus fork | On-chain | **No** — M keys on M machines/people; compromise of <M keys yields nothing | Medium: new script_pubkey type (hash of sorted-pubkey descriptor + m,n), raise 10 KB script_sig cap (`core/mod.rs:771`), mempool/fee sizing, wallet ceremony UX | ~8.5 KB per co-signer per input; a 2-of-3 spend reveals 3 pks + 2 sigs ≈ **21 KB ≈ 2.1% of the 1 MB block** (`core/mod.rs:27`). Verify cost: M hybrid verifies, sub-millisecond — negligible |
| **2. Shamir SSS of the seed**, reconstruct to sign | Yes (shards 32-B seed; scheme-agnostic) | Very mature primitive (SLIP-39-class); trivial to implement correctly for a 32-B secret | Off-chain | **Yes** — at signing, the full key exists in one place. Acceptable for *recovery* and for low-frequency ceremonies on an air-gapped box; not acceptable as the steady-state defense for a hot service | Low: wallet-side only, no consensus change | None on-chain |
| **3a. Threshold ML-DSA (MPC)** — Quorus (ePrint 2025/1163), Mithril (USENIX Sec '26), TALUS; also non-FIPS-output schemes (Threshold Raccoon EC'24, Ringtail, Hermine) | Yes, **but covers only the ML-DSA half of Bloch's hybrid** | Research code at best. Quorus/Mithril outputs verify as standard FIPS 204 sigs (no consensus change!) — Mithril ≤6 parties, ~1 MB comms/party; **no audited production library exists**. Raccoon itself did not advance in NIST's additional-signatures process | Off-chain signing, standard sig on-chain | No (that's the point) | High: integrate/harden research MPC code; useless alone for Bloch (Falcon half still single-key) | None on-chain (standard sig) |
| **3b. Threshold Falcon** | The blocker. FP/FFT Gaussian sampling resists distribution; first thresholdization of *standardized* Falcon is Garg–Escudero **ePrint 2026/1300, a months-old preprint** | Preprint. No implementation ecosystem, no audit, unknown constants in practice | Off-chain signing, standard sig on-chain | No | Not realistically buildable by this project in 2026 | None on-chain |
| **4. Policy/HSM + operational M-of-N** (M-of-N human approvals gate a single isolated signer; what real custodians ship) | Yes — key handling is scheme-agnostic. Caveat: **FIPS-validated HSM support for the pair is thin** — ML-DSA (FIPS 204) is arriving in HSM lines; Falcon/FN-DSA (FIPS 206) was still unfinalized as of early 2026, so "HSM" here realistically means an air-gapped or TEE-isolated signer, not a certified appliance | Mature *pattern* (it is how most production custody actually works), but it is procedure, not cryptography | Off-chain | **Yes, cryptographically** — one key signs. Mitigated (not eliminated) by isolation + quorum policy + audit log | Low–medium: Chiave dual-control workflow + signing box | None |
| **5. NIST threshold-crypto program** (IR 8214C) | The final Call was published **2026-01-20**; submissions are in the "Previews" phase mid-2026 (preview writeups due July 31, 2026) | **Nothing is standardized or even standards-track yet.** Realistic horizon for NIST-blessed PQ threshold schemes: years | — | — | Watch; do not depend on | — |

---

## 4. Recommendation and migration path

### Phase 0 — Reference pool, ship now (weeks, no consensus change)

The pool must stay honest reference-grade, and by project rule the daemon never custodies the token (`pool/README.md:125-126`). Do **not** put threshold cryptography in it. Instead:

1. **Shrink the target.** Disburse on a short cadence once coinbase matures; the custodied balance should be days of rewards, not months. (Direct-coinbase payout — splitting the coinbase across miner addresses — remains the custody-eliminating end-state the tokenomics advisor flagged; it costs coinbase size and is a separate decision.)
2. **Operational M-of-N around the operator wallet (option 4 + 2):** signing key lives only on an isolated (ideally air-gapped) machine; payouts require dual control (two people: one prepares the batch from the ledger, one authorizes/signs — the Chiave pattern applied to the pool); **2-of-3 Shamir shards of the 32-byte wallet seed** (`crypto/mod.rs:62-87` makes this clean) held by distinct parties/locations as the recovery layer, with the pqcrypto crate version pinned in shard metadata per the `crypto/mod.rs:49-55` warning.
3. **Document it as what it is:** procedural M-of-N. A single machine compromise at signing time can still steal the (deliberately small) balance. Don't overclaim.

### Phase 1 — GIP-008: consensus-level k-of-n hybrid multisig (the real decision; 1–2 quarters)

This is the recommended **end-state for enterprise/escrow custody**, and it upgrades the pool too:

- New output type: `script_pubkey` = 20-byte hash of a canonical multisig descriptor `(m, n, sorted hybrid pubkey hashes)`; spend reveals the descriptor plus **m full Falcon‖ML-DSA signatures** over the existing sighash (`core/mod.rs:819-823` already gives all co-signers the same digest). Consensus change: descriptor-hash match + m distinct-key runs of the existing `crypto::verify` — no new cryptography, no new verifier, no new assumptions.
- Wire/consensus deltas: raise the 10,000-byte `script_sig` cap (`core/mod.rs:771`), update `estimate_size`/fee logic (`core/mod.rs:882-890`), mempool sizing. A 2-of-3 spend ≈ 21 KB ≈ 2.1% of a 1 MB block — fine at Bloch's volumes; fee-priced, so it pays its way. Verification cost is m sub-millisecond verifies — negligible next to SIS-PoW validation.
- Why this beats waiting for MPC: it is the **only** design available in 2026 that (a) removes the single point of compromise at the moment of signing, (b) uses only the two audited primitives already in consensus, and (c) is reviewable by any auditor without trusting a research artifact. Bitcoin ran on exactly this model (CHECKMULTISIG) for a decade; the PQ tax is bytes, not risk.
- This also lands the roadmapped **M-8 treasury multisig + timelock** (`docs/releases/v0.5.11.md:296-298`) with the same machinery. Enterprise escrow = 2-of-3 (client, Chiave, neutral/notary) on-chain, with SSS shards of each participant key as the recovery layer underneath.

### Phase 2 — Threshold MPC as a drop-in optimization (watch, don't build; 2027+)

Track Quorus/Mithril-class threshold ML-DSA (FIPS-204-compatible output means it needs **no further consensus change** — an MPC quorum simply becomes one "co-signer" inside the Phase-1 multisig or eventually replaces it) and the nascent threshold-Falcon line (ePrint 2026/1300), plus the NIST IR 8214C process. Adopt only when: standard-verifying output for **both** halves of the hybrid, a maintained implementation, and an independent audit. Honest caveat for any enterprise conversation: **production PQ threshold signing does not exist in audited form in 2026, and anyone selling it as settled is overclaiming.** Bloch's hybrid makes it strictly harder than for ML-DSA-only chains — that is a deliberate trade, and the on-chain multisig path is how we get real M-of-N without betting custody on preprints.

Ethos check: everything above is protocol and product hardening; nothing here creates a revenue line that touches the token — enterprise custody revenue is Chiave service work, per the standing rule.

---

## Sources

- [Quorus: Efficient, Scalable Threshold ML-DSA Signatures from MPC (ePrint 2025/1163)](https://eprint.iacr.org/2025/1163)
- [Efficient Threshold ML-DSA up to 6 parties — Mithril, NIST 6th PQC Conf](https://csrc.nist.gov/csrc/media/events/2025/sixth-pqc-standardization-conference/efficient%20threshold%20ml-dsa%20up%20to%206%20parties.pdf) and [ePrint 2026/013](https://eprint.iacr.org/2026/013)
- [Threshold Signatures Reloaded: ML-DSA and Enhanced Raccoon with Identifiable Aborts (ePrint 2025/1166)](https://eprint.iacr.org/2025/1166)
- [TALUS: Threshold ML-DSA with One-Round Online Signing (arXiv 2603.22109)](https://arxiv.org/html/2603.22109v1)
- [Threshold Raccoon: Practical Threshold Signatures from Standard Lattice Assumptions (ePrint 2024/184, EUROCRYPT 2024)](https://eprint.iacr.org/2024/184)
- [Thresholdizing Standardized FALCON Signatures — Garg & Escudero (ePrint 2026/1300)](https://eprint.iacr.org/2026/1300.pdf)
- [Falcon specification / design (falcon-sign.info)](https://falcon-sign.info/) and [Bi-SamplerZ: Gaussian sampler cost in Falcon (arXiv 2505.24509)](https://arxiv.org/pdf/2505.24509)
- [NIST IR 8214C (final, Jan 2026): First Call for Multi-Party Threshold Schemes](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8214C.pdf) and [project page / submission phases](https://csrc.nist.gov/projects/threshold-cryptography)
- [NIST IR 8610: Status Report on Round 2 of Additional Digital Signatures (Raccoon not advanced; Round-3 = FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, UOV)](https://csrc.nist.gov/pubs/ir/8610/final)
